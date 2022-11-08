use std::{
    collections::VecDeque,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, FutureExt, Stream};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_native_tls::TlsStream;

use crate::tls::TlsAcceptor;

///
pub struct Bindings {
    bindings: VecDeque<Binding>,
}

impl Bindings {
    ///
    pub fn new() -> Self {
        Self {
            bindings: VecDeque::new(),
        }
    }

    ///
    pub async fn add_tcp_bindings<T>(&mut self, addresses: T) -> io::Result<()>
    where
        T: IntoIterator<Item = SocketAddr>,
    {
        for addr in addresses {
            let listener = Binding::tcp(addr).await?;

            self.bindings.push_back(listener);
        }

        Ok(())
    }

    ///
    pub async fn add_tls_bindings<T>(
        &mut self,
        acceptor: TlsAcceptor,
        addresses: T,
    ) -> io::Result<()>
    where
        T: IntoIterator<Item = SocketAddr>,
    {
        for addr in addresses {
            let listener = Binding::tls(addr, acceptor.clone()).await?;

            self.bindings.push_back(listener);
        }

        Ok(())
    }
}

impl Stream for Bindings {
    type Item = io::Result<Connection>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        for _ in 0..self.bindings.len() {
            if let Some(binding) = self.bindings.pop_front() {
                let poll = binding.poll_accept(cx);

                let res = match poll {
                    Poll::Ready(Ok(c)) => Poll::Ready(c),
                    Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                    Poll::Pending => Poll::Pending,
                };

                self.bindings.push_back(binding);

                if let Poll::Ready(c) = res {
                    return Poll::Ready(Some(Ok(c)));
                }
            }
        }

        Poll::Pending
    }
}

///
pub struct Binding {
    local_addr: SocketAddr,
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
}

impl Binding {
    ///
    pub async fn tcp(bind_address: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(bind_address).await?;

        let local_addr = listener.local_addr()?;

        let res = Self {
            local_addr,
            listener,
            acceptor: None,
        };

        Ok(res)
    }

    ///
    pub async fn tls(bind_address: SocketAddr, acceptor: TlsAcceptor) -> io::Result<Self> {
        let listener = TcpListener::bind(bind_address).await?;

        let local_addr = listener.local_addr()?;

        let res = Self {
            local_addr,
            listener,
            acceptor: Some(acceptor),
        };

        Ok(res)
    }

    ///
    fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<Connection>> {
        let (stream, remote_addr) = ready!(self.listener.poll_accept(cx))?;

        let connection = if let Some(acceptor) = self.acceptor.as_ref() {
            InnerConnection::PendingTls(Box::pin(acceptor.accept(stream)))
        } else {
            InnerConnection::Tcp(stream)
        };

        let info = ConnectionInfo {
            local_addr: self.local_addr,
            remote_addr,
            is_https: self.acceptor.is_some(),
        };

        Poll::Ready(Ok(Connection::new(connection, info)))
    }
}

///
type TlsAcceptResult = io::Result<TlsStream<TcpStream>>;

///
type PendingTlsConnection = Pin<Box<dyn Future<Output = TlsAcceptResult> + Send>>;

///
pub struct Connection {
    inner: InnerConnection,
    info: ConnectionInfo,
}

impl Connection {
    ///
    fn new(inner: InnerConnection, info: ConnectionInfo) -> Self {
        Self { inner, info }
    }

    ///
    pub fn info(&self) -> ConnectionInfo {
        self.info
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.inner), cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write_vectored(Pin::new(&mut self.inner), cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.inner), cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

///
#[derive(Debug, Copy, Clone)]
pub struct ConnectionInfo {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    is_https: bool,
}

impl ConnectionInfo {
    ///
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    ///
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    ///
    pub fn is_https(&self) -> bool {
        self.is_https
    }
}

///
enum InnerConnection {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
    PendingTls(PendingTlsConnection),
}

impl AsyncRead for InnerConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        match this {
            Self::Tcp(c) => AsyncRead::poll_read(Pin::new(c), cx, buf),
            Self::Tls(c) => AsyncRead::poll_read(Pin::new(c), cx, buf),
            Self::PendingTls(pending) => {
                let stream = ready!(pending.poll_unpin(cx))?;

                *this = Self::Tls(stream);

                AsyncRead::poll_read(Pin::new(this), cx, buf)
            }
        }
    }
}

impl AsyncWrite for InnerConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        match this {
            Self::Tcp(c) => AsyncWrite::poll_write(Pin::new(c), cx, buf),
            Self::Tls(c) => AsyncWrite::poll_write(Pin::new(c), cx, buf),
            Self::PendingTls(pending) => {
                let stream = ready!(pending.poll_unpin(cx))?;

                *this = Self::Tls(stream);

                AsyncWrite::poll_write(Pin::new(this), cx, buf)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        match this {
            Self::Tcp(c) => AsyncWrite::poll_flush(Pin::new(c), cx),
            Self::Tls(c) => AsyncWrite::poll_flush(Pin::new(c), cx),
            Self::PendingTls(pending) => {
                let stream = ready!(pending.poll_unpin(cx))?;

                *this = Self::Tls(stream);

                AsyncWrite::poll_flush(Pin::new(this), cx)
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;

        match this {
            Self::Tcp(c) => AsyncWrite::poll_shutdown(Pin::new(c), cx),
            Self::Tls(c) => AsyncWrite::poll_shutdown(Pin::new(c), cx),
            Self::PendingTls(pending) => {
                let stream = ready!(pending.poll_unpin(cx))?;

                *this = Self::Tls(stream);

                AsyncWrite::poll_shutdown(Pin::new(this), cx)
            }
        }
    }
}
