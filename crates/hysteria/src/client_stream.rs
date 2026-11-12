//! Stop-aware direct streams without an extra userspace forwarding buffer.
use hysteria_transport::ProxyStream;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
};

type Stop = Pin<Box<dyn Future<Output = ()> + Send>>;
pub(crate) struct DirectStream {
    closed: bool,
    inner: Box<dyn ProxyStream>,
    read_stop: Stop,
    write_stop: Stop,
}
impl DirectStream {
    pub(crate) fn new(inner: Box<dyn ProxyStream>, stop: watch::Receiver<bool>) -> Self {
        Self {
            closed: false,
            inner,
            read_stop: Box::pin(stopped(stop.clone())),
            write_stop: Box::pin(stopped(stop)),
        }
    }
}
pub(crate) async fn stopped(mut stop: watch::Receiver<bool>) {
    let _ = stop.wait_for(|closed| *closed).await;
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "client stopped")
}
impl AsyncRead for DirectStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed || self.read_stop.as_mut().poll(cx).is_ready() {
            self.closed = true;
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut *self.inner).poll_read(cx, buffer)
    }
}
impl AsyncWrite for DirectStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || self.write_stop.as_mut().poll(cx).is_ready() {
            self.closed = true;
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut *self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed || self.write_stop.as_mut().poll(cx).is_ready() {
            self.closed = true;
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed || self.write_stop.as_mut().poll(cx).is_ready() {
            self.closed = true;
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

/// Counts successful payload I/O at the outbound stream boundary.
pub(crate) struct MeteredStream {
    inner: Box<dyn ProxyStream>,
    counter: std::sync::Arc<crate::client_traffic::PayloadCounter>,
}
impl MeteredStream {
    pub(crate) fn wrap(
        inner: Box<dyn ProxyStream>,
        counter: Option<std::sync::Arc<crate::client_traffic::PayloadCounter>>,
    ) -> Box<dyn ProxyStream> {
        match counter {
            Some(counter) => Box::new(Self { inner, counter }),
            None => inner,
        }
    }
}
impl AsyncRead for MeteredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.counter.download(buffer.filled().len() - before);
        }
        result
    }
}
impl AsyncWrite for MeteredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = result {
            self.counter.upload(n);
        }
        result
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write_vectored(cx, buffers);
        if let Poll::Ready(Ok(n)) = result {
            self.counter.upload(n);
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod metering_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn partial_writes_and_reads_count_only_transferred_payload() {
        let meter = crate::client_traffic::TrafficMeter::new().unwrap();
        let (local, mut peer) = tokio::io::duplex(4);
        let mut stream =
            MeteredStream::wrap(Box::new(local), Some(std::sync::Arc::clone(&meter.direct)));
        assert_eq!(stream.write(b"abcdefgh").await.unwrap(), 4);
        assert_eq!(meter.sample().traffic.direct.upload_bytes, 4);
        let mut buffer = [0; 4];
        peer.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"abcd");
        peer.write_all(b"repl").await.unwrap();
        let mut small = [0; 2];
        stream.read_exact(&mut small).await.unwrap();
        assert_eq!(meter.sample().traffic.direct.download_bytes, 2);
        drop(peer);
        assert!(stream.write(b"fail").await.is_err());
        assert_eq!(meter.sample().traffic.direct.upload_bytes, 4);
    }
}
