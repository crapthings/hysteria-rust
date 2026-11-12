//! Opt-in bounded TCP diagnostics. Targets are memory-only; each close owns one stream.
use crate::{CliError, Result, routing::Action};
use hysteria_transport::ProxyStream;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
};
const CAPACITY: usize = 4096;
const MAX_PAGE: usize = 200;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpInbound {
    Socks5,
    HttpConnect,
    HttpForwarding,
    TcpForwarding,
    Tun,
    Redirect,
    Tproxy,
    Embedded,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpState {
    Connecting,
    Active,
}
#[derive(Clone, Debug, Serialize)]
pub struct TcpConnection {
    pub id: String,
    pub inbound: TcpInbound,
    pub target: String,
    pub outbound: Action,
    pub routing_revision: Option<u64>,
    pub matched_rule: Option<usize>,
    pub started_at: String,
    pub state: TcpState,
}
#[derive(Debug, Serialize)]
pub struct TrackingStatus {
    pub enabled: bool,
    pub tracked: usize,
    pub control_handles: usize,
    pub capacity: usize,
    pub skipped: u64,
}
#[derive(Debug, Serialize)]
pub struct ConnectionPage {
    pub schema_version: u8,
    pub tracking: TrackingStatus,
    pub connections: Vec<TcpConnection>,
    pub next_cursor: Option<String>,
}
struct Entry {
    info: TcpConnection,
    socket: Arc<Socket>,
}
struct State {
    enabled: bool,
    stopped: bool,
    next: u64,
    skipped: u64,
    entries: BTreeMap<u64, Entry>,
    sockets: BTreeMap<u64, Weak<Socket>>,
}
pub(crate) struct Connections {
    namespace: String,
    state: Mutex<State>,
}
impl Connections {
    pub(crate) fn new(namespace: String) -> Self {
        Self {
            namespace,
            state: Mutex::new(State {
                enabled: false,
                stopped: false,
                next: 0,
                skipped: 0,
                entries: BTreeMap::new(),
                sockets: BTreeMap::new(),
            }),
        }
    }
    fn status(s: &State) -> TrackingStatus {
        TrackingStatus {
            enabled: s.enabled,
            tracked: s.entries.len(),
            control_handles: s.sockets.len(),
            capacity: CAPACITY,
            skipped: s.skipped,
        }
    }
    pub(crate) fn enable(&self, enabled: bool) -> Result<TrackingStatus> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stopped {
            return Err(CliError::new("client connection tracking has stopped"));
        }
        state.enabled = enabled;
        if !enabled {
            state.entries.clear();
        }
        Ok(Self::status(&state))
    }
    fn id(&self, n: u64) -> String {
        format!("{}-{n:016x}", self.namespace)
    }
    fn parse(&self, id: &str) -> Result<u64> {
        let suffix = id
            .strip_prefix(&format!("{}-", self.namespace))
            .ok_or_else(|| CliError::new("connection ID belongs to another runtime"))?;
        if suffix.len() != 16
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CliError::new("invalid connection ID"));
        }
        u64::from_str_radix(suffix, 16).map_err(|_| CliError::new("invalid connection ID"))
    }
    pub(crate) fn list(&self, after: Option<&str>, limit: usize) -> Result<ConnectionPage> {
        if !(1..=MAX_PAGE).contains(&limit) {
            return Err(CliError::new("connection page limit must be 1 through 200"));
        }
        let after = after.map(|id| self.parse(id)).transpose()?.unwrap_or(0);
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut entries = state
            .entries
            .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded));
        let connections: Vec<_> = entries
            .by_ref()
            .take(limit)
            .map(|(_, e)| e.info.clone())
            .collect();
        let next_cursor = if entries.next().is_some() {
            connections.last().map(|c| c.id.clone())
        } else {
            None
        };
        Ok(ConnectionPage {
            schema_version: 1,
            tracking: Self::status(&state),
            connections,
            next_cursor,
        })
    }
    pub(crate) fn close(&self, id: &str) -> Result<bool> {
        let key = self.parse(id)?;
        let removed = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let removed = state.entries.remove(&key);
            if removed.is_some() {
                state.sockets.remove(&key);
            }
            removed
        };
        if let Some(entry) = removed {
            entry.socket.close();
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub(crate) fn shutdown(&self) {
        let sockets = {
            let mut s = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.stopped = true;
            s.enabled = false;
            s.entries.clear();
            std::mem::take(&mut s.sockets)
        };
        for socket in sockets.into_values().filter_map(|s| s.upgrade()) {
            socket.close();
        }
    }
    pub(crate) fn register(
        self: &Arc<Self>,
        inbound: TcpInbound,
        target: &str,
        selection: &crate::client_routing::RouteSelection,
    ) -> Option<Registration> {
        let mut s = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !s.enabled || s.stopped {
            return None;
        }
        if s.sockets.len() >= CAPACITY || target.len() > 1024 || s.next == u64::MAX {
            s.skipped = s.skipped.saturating_add(1);
            return None;
        }
        s.next += 1;
        let key = s.next;
        let socket = Arc::new(Socket::new());
        s.sockets.insert(key, Arc::downgrade(&socket));
        s.entries.insert(
            key,
            Entry {
                info: TcpConnection {
                    id: self.id(key),
                    inbound,
                    target: target.into(),
                    outbound: selection.decision.outbound,
                    routing_revision: selection.revision,
                    matched_rule: selection.decision.matched_rule,
                    started_at: chrono::Utc::now().to_rfc3339(),
                    state: TcpState::Connecting,
                },
                socket: Arc::clone(&socket),
            },
        );
        Some(Registration {
            registry: Arc::clone(self),
            key,
            socket,
        })
    }
}
struct SocketState {
    stream: Option<Box<dyn ProxyStream>>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    eof: bool,
    write_closed: bool,
}
struct Socket {
    cancel: watch::Sender<bool>,
    state: Mutex<SocketState>,
}
impl Socket {
    fn new() -> Self {
        Self {
            cancel: watch::channel(false).0,
            state: Mutex::new(SocketState {
                stream: None,
                reader: None,
                writer: None,
                eof: false,
                write_closed: false,
            }),
        }
    }
    fn close(&self) {
        self.cancel.send_replace(true);
        let (stream, reader, writer) = {
            let mut s = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (s.stream.take(), s.reader.take(), s.writer.take())
        };
        drop(stream);
        if let Some(w) = reader {
            w.wake();
        }
        if let Some(w) = writer {
            w.wake();
        }
    }
}
pub(crate) struct Registration {
    registry: Arc<Connections>,
    key: u64,
    socket: Arc<Socket>,
}
impl Registration {
    pub(crate) async fn cancelled(&self) {
        let mut rx = self.socket.cancel.subscribe();
        let _ = rx.wait_for(|c| *c).await;
    }
    fn finish(&self) {
        {
            let mut state = self
                .registry
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.entries.remove(&self.key);
            state.sockets.remove(&self.key);
        }
        self.socket.close();
    }
    pub(crate) fn attach(self, stream: Box<dyn ProxyStream>) -> Box<dyn ProxyStream> {
        {
            let mut s = self
                .socket
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !*self.socket.cancel.borrow() {
                s.stream = Some(stream);
            }
        }
        {
            let mut s = self
                .registry
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(entry) = s.entries.get_mut(&self.key) {
                entry.info.state = TcpState::Active;
            }
        }
        Box::new(TrackedStream { registration: self })
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.finish();
    }
}
struct TrackedStream {
    registration: Registration,
}
fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "TCP connection closed by client control",
    )
}
impl TrackedStream {
    fn poll_write_op(
        &self,
        cx: &mut Context<'_>,
        op: impl FnOnce(Pin<&mut dyn ProxyStream>, &mut Context<'_>) -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        let result = {
            let mut s = self
                .registration
                .socket
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.writer = Some(cx.waker().clone());
            match s.stream.as_mut() {
                Some(stream) => op(Pin::new(&mut **stream), cx),
                None => Poll::Ready(Err(closed())),
            }
        };
        if matches!(result, Poll::Ready(Err(_))) {
            self.registration.finish();
        }
        result
    }
}
impl AsyncRead for TrackedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let (result, finished) = {
            let mut s = self
                .registration
                .socket
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.reader = Some(cx.waker().clone());
            let before = buf.filled().len();
            let available = buf.remaining();
            let result = match s.stream.as_mut() {
                Some(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
                None => Poll::Ready(Err(closed())),
            };
            if matches!(result, Poll::Ready(Ok(())))
                && available > 0
                && before == buf.filled().len()
            {
                s.eof = true;
            }
            (result, s.eof && s.write_closed)
        };
        if finished || matches!(result, Poll::Ready(Err(_))) {
            self.registration.finish();
        }
        result
    }
}
impl AsyncWrite for TrackedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_op(cx, |s, cx| s.poll_write(cx, buf))
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_op(cx, |s, cx| s.poll_write_vectored(cx, buf))
    }
    fn is_write_vectored(&self) -> bool {
        self.registration
            .socket
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stream
            .as_ref()
            .is_some_and(AsyncWrite::is_write_vectored)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_op(cx, |s, cx| s.poll_flush(cx).map_ok(|()| 0))
            .map_ok(|_| ())
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = self
            .poll_write_op(cx, |s, cx| s.poll_shutdown(cx).map_ok(|()| 0))
            .map_ok(|_| ());
        if matches!(result, Poll::Ready(Ok(()))) {
            let finished = {
                let mut s = self
                    .registration
                    .socket
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.write_closed = true;
                s.eof
            };
            if finished {
                self.registration.finish();
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn fixture() -> (Arc<Connections>, crate::client_routing::RouteSelection) {
        let registry = Arc::new(Connections::new("0123456789abcdef0123456789abcdef".into()));
        let config = crate::routing::RoutingConfig::default();
        let router = crate::routing::Router::compile(&config).unwrap();
        (
            registry,
            crate::client_routing::RouteSelection::uncounted(
                router
                    .decide("example.com:443", crate::routing::Protocol::Tcp)
                    .unwrap(),
            ),
        )
    }
    #[tokio::test]
    async fn close_drops_idle_stream_without_waiting_for_consumer_poll() {
        let (registry, selection) = fixture();
        registry.enable(true).unwrap();
        let registration = registry
            .register(TcpInbound::Embedded, "example.com:443", &selection)
            .unwrap();
        let (stream, mut peer) = tokio::io::duplex(16);
        let _held = registration.attach(Box::new(stream));
        let page = registry.list(None, 1).unwrap();
        let id = &page.connections[0].id;
        assert!(registry.close(id).unwrap());
        assert!(!registry.close(id).unwrap());
        let mut bytes = [0; 1];
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), peer.read(&mut bytes))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(registry.list(None, 1).unwrap().connections.is_empty());
        assert!(registry.close("another-runtime-0000000000000001").is_err());
    }
    #[tokio::test]
    async fn half_closed_stream_remains_until_both_directions_finish() {
        let (registry, selection) = fixture();
        registry.enable(true).unwrap();
        let registration = registry
            .register(TcpInbound::Embedded, "example.com:443", &selection)
            .unwrap();
        let (stream, mut peer) = tokio::io::duplex(16);
        let mut stream = registration.attach(Box::new(stream));
        peer.shutdown().await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(registry.list(None, 1).unwrap().connections.len(), 1);
        stream.write_all(b"x").await.unwrap();
        peer.read_exact(&mut [0; 1]).await.unwrap();
        stream.shutdown().await.unwrap();
        assert!(registry.list(None, 1).unwrap().connections.is_empty());
    }
    #[tokio::test]
    async fn disabling_forgets_targets_but_shutdown_still_closes_idle_streams() {
        let (registry, selection) = fixture();
        registry.enable(true).unwrap();
        let registration = registry
            .register(TcpInbound::Embedded, "private.example:443", &selection)
            .unwrap();
        let (stream, mut peer) = tokio::io::duplex(16);
        let mut held = registration.attach(Box::new(stream));
        let status = registry.enable(false).unwrap();
        assert_eq!(status.tracked, 0);
        assert_eq!(status.control_handles, 1);
        held.write_all(b"x").await.unwrap();
        peer.read_exact(&mut [0; 1]).await.unwrap();
        assert!(
            !serde_json::to_string(&registry.list(None, 1).unwrap())
                .unwrap()
                .contains("private.example")
        );
        registry.shutdown();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
    #[test]
    fn privacy_capacity_pagination_and_ids_are_bounded() {
        let (registry, selection) = fixture();
        assert!(
            registry
                .register(TcpInbound::Embedded, "secret.example:443", &selection)
                .is_none()
        );
        registry.enable(true).unwrap();
        let mut guards = Vec::new();
        for _ in 0..CAPACITY {
            guards.push(
                registry
                    .register(TcpInbound::Embedded, "example.com:443", &selection)
                    .unwrap(),
            );
        }
        assert!(
            registry
                .register(TcpInbound::Embedded, "overflow:443", &selection)
                .is_none()
        );
        let first = registry.list(None, 200).unwrap();
        assert_eq!(first.tracking.skipped, 1);
        assert_eq!(first.connections.len(), 200);
        let second = registry.list(first.next_cursor.as_deref(), 200).unwrap();
        assert!(second.connections[0].id > first.connections[199].id);
        assert!(registry.list(None, 201).is_err());
        registry.enable(false).unwrap();
        assert!(registry.list(None, 200).unwrap().connections.is_empty());
        registry.enable(true).unwrap();
        drop(guards.pop());
        let new = registry
            .register(TcpInbound::Embedded, "new:443", &selection)
            .unwrap();
        assert_ne!(
            registry.list(None, 1).unwrap().connections[0].id,
            first.connections[0].id
        );
        drop(guards);
        assert_eq!(registry.list(None, 1).unwrap().connections.len(), 1);
        drop(new);
        registry.shutdown();
        assert!(registry.enable(true).is_err());
    }
}
