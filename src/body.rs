use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{ready, Stream, TryStreamExt};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full, StreamBody};
use hyper::body::{Frame, Incoming};

/// HTTP message body.
pub struct Body {
    inner: BoxBody<Bytes, io::Error>,
}

impl Body {
    /// Create a new body from a given stream.
    pub fn from_stream<S>(stream: S) -> Self
    where
        S: Stream<Item = io::Result<Bytes>> + Send + Sync + 'static,
    {
        Self {
            inner: BoxBody::new(StreamBody::new(stream.map_ok(Frame::data))),
        }
    }

    /// Create a new empty body.
    pub fn empty() -> Self {
        let inner = Empty::new()
            .map_err(|_| io::Error::from(io::ErrorKind::Other))
            .boxed();

        Self { inner }
    }
}

impl hyper::body::Body for Body {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        hyper::body::Body::poll_frame(Pin::new(&mut self.inner), cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Stream for Body {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(hyper::body::Body::poll_frame(Pin::new(&mut self.inner), cx)) {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        return Poll::Ready(Some(Ok(data)));
                    }
                }
                Some(Err(err)) => return Poll::Ready(Some(Err(err))),
                None => return Poll::Ready(None),
            }
        }
    }
}

impl From<Bytes> for Body {
    fn from(data: Bytes) -> Self {
        let inner = Full::new(data)
            .map_err(|_| io::Error::from(io::ErrorKind::Other))
            .boxed();

        Self { inner }
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Self::from(Bytes::from(s))
    }
}

impl From<Incoming> for Body {
    fn from(body: Incoming) -> Self {
        let inner = body
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
            .boxed();

        Self { inner }
    }
}
