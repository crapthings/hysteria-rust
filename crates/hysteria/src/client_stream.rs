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
