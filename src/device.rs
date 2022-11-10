use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    future::{AbortHandle, Abortable},
    ready, FutureExt, SinkExt, Stream, StreamExt,
};
use h2::{
    client::{Connection, SendRequest},
    RecvStream, SendStream,
};
use hyper::{upgrade::Upgraded, Body, Request, Response};

use crate::{response, Error};

///
#[derive(Clone)]
pub struct DeviceManager {
    devices: Arc<Mutex<HashMap<String, DeviceHandle>>>,
}

impl DeviceManager {
    ///
    pub fn new() -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    ///
    pub fn add(&self, device_id: &str, handle: DeviceHandle) -> Option<DeviceHandle> {
        self.devices
            .lock()
            .unwrap()
            .insert(device_id.to_string(), handle)
    }

    ///
    pub fn remove(&self, device_id: &str) -> Option<DeviceHandle> {
        self.devices.lock().unwrap().remove(device_id)
    }

    ///
    pub fn get(&self, device_id: &str) -> Option<DeviceHandle> {
        self.devices.lock().unwrap().get(device_id).cloned()
    }
}

/// Future representing a device connection.
///
/// The future will be resolved when the corresponding connection gets closed.
pub struct DeviceConnection {
    connection: Abortable<Connection<Upgraded, Bytes>>,
}

impl DeviceConnection {
    /// Create a new device connection.
    pub async fn new(connection: Upgraded) -> Result<(Self, DeviceHandle), Error> {
        let (h2, connection) = h2::client::handshake(connection).await?;

        // TODO: ping pong

        let (connection, abort) = futures::future::abortable(connection);

        let (request_tx, mut request_rx) = mpsc::channel::<DeviceRequest>(4);

        tokio::spawn(async move {
            while let Some(request) = request_rx.next().await {
                request.spawn_send(h2.clone());
            }
        });

        let connection = Self { connection };

        let handle = DeviceHandle { request_tx, abort };

        Ok((connection, handle))
    }
}

impl Future for DeviceConnection {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let res = match ready!(self.connection.poll_unpin(cx)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err.into()),
            Err(_) => Ok(()),
        };

        Poll::Ready(res)
    }
}

/// Device handle.
#[derive(Clone)]
pub struct DeviceHandle {
    request_tx: mpsc::Sender<DeviceRequest>,
    abort: AbortHandle,
}

impl DeviceHandle {
    /// Send a given request to the connected device and return a device
    /// response.
    pub async fn send_request(&mut self, request: Request<Body>) -> Response<Body> {
        let (request, response_rx) = DeviceRequest::new(request);

        self.request_tx.send(request).await.unwrap_or_default();

        response_rx.await
    }

    /// Close the connection.
    pub fn close(&self) {
        self.abort.abort();
    }
}

/// Request wrapper for requests that shall be sent to a device.
struct DeviceRequest {
    request: Request<Body>,
    response_tx: DeviceResponseTx,
}

impl DeviceRequest {
    /// Create a new device request and an associated response future.
    fn new(request: Request<Body>) -> (Self, DeviceResponseRx) {
        let (response_tx, response_rx) = oneshot::channel();

        let response_tx = DeviceResponseTx { inner: response_tx };
        let response_rx = DeviceResponseRx { inner: response_rx };

        let request = Self {
            request,
            response_tx,
        };

        (request, response_rx)
    }

    /// Send the request into a given device channel in a background task.
    fn spawn_send(self, channel: SendRequest<Bytes>) {
        tokio::spawn(self.send(channel));
    }

    /// Send the request into a given device channel.
    async fn send(self, channel: SendRequest<Bytes>) {
        let response = Self::send_internal(self.request, channel)
            .await
            .unwrap_or_else(|_| response::bad_gateway());

        self.response_tx.send(response);
    }

    /// Helper function for sending a given HTTP request into a given device
    /// channel.
    async fn send_internal(
        request: Request<Body>,
        channel: SendRequest<Bytes>,
    ) -> Result<Response<Body>, Error> {
        let (parts, body) = request.into_parts();

        let (response, body_tx) = channel
            .ready()
            .await?
            .send_request(Request::from_parts(parts, ()), false)?;

        tokio::spawn(async move {
            if let Err(err) = SendBody::new(body, body_tx).await {
                eprintln!("unable to send request body: {}", err);
            }
        });

        let (parts, body) = response.await?.into_parts();

        let body = Body::wrap_stream(ReceiveBody::new(body));

        Ok(Response::from_parts(parts, body))
    }
}

/// Future that will be resolved into a device response.
struct DeviceResponseRx {
    inner: oneshot::Receiver<Response<Body>>,
}

impl Future for DeviceResponseRx {
    type Output = Response<Body>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(self.inner.poll_unpin(cx)) {
            Ok(res) => Poll::Ready(res),
            Err(_) => Poll::Ready(response::bad_gateway()),
        }
    }
}

/// Resolver for the device response future.
struct DeviceResponseTx {
    inner: oneshot::Sender<Response<Body>>,
}

impl DeviceResponseTx {
    /// Resolve the device response future.
    fn send(self, response: Response<Body>) {
        self.inner.send(response).unwrap_or_default();
    }
}

/// Stream that will handle receiving of an HTTP2 body.
struct ReceiveBody {
    inner: RecvStream,
}

impl ReceiveBody {
    /// Create a new body stream.
    fn new(h2: RecvStream) -> Self {
        Self { inner: h2 }
    }
}

impl Stream for ReceiveBody {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(item) = ready!(self.inner.poll_data(cx)) {
            let data = item.map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

            self.inner
                .flow_control()
                .release_capacity(data.len())
                .unwrap();

            Poll::Ready(Some(Ok(data)))
        } else {
            Poll::Ready(None)
        }
    }
}

/// Future that will drive sending of a request/response body into an HTTP2
/// channel.
struct SendBody<B> {
    channel: SendStream<Bytes>,
    body: B,
    chunk: Option<Bytes>,
}

impl<B> SendBody<B> {
    /// Create a new body sender.
    fn new(body: B, channel: SendStream<Bytes>) -> Self {
        Self {
            channel,
            body,
            chunk: None,
        }
    }

    /// Poll channel send capacity.
    fn poll_capacity(
        &mut self,
        cx: &mut Context<'_>,
        required: usize,
    ) -> Poll<Result<usize, Error>> {
        let mut capacity = self.channel.capacity();

        while capacity == 0 {
            // ask the channel for additional send capacity
            self.channel.reserve_capacity(required);

            capacity = ready!(self.channel.poll_capacity(cx)).ok_or_else(|| {
                Error::from_static_msg("unable to allocate HTTP2 channel capacity")
            })??;
        }

        Poll::Ready(Ok(capacity))
    }
}

impl<B, E> SendBody<B>
where
    B: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Into<Error>,
{
    /// Poll the next chunk to be sent.
    fn poll_next_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, Error>> {
        if let Some(chunk) = self.chunk.take() {
            return Poll::Ready(Ok(Some(chunk)));
        }

        match ready!(self.body.poll_next_unpin(cx)) {
            Some(Ok(chunk)) => Poll::Ready(Ok(Some(chunk))),
            Some(Err(err)) => Poll::Ready(Err(err.into())),
            None => Poll::Ready(Ok(None)),
        }
    }
}

impl<B, E> Future for SendBody<B>
where
    B: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Into<Error>,
{
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Some(mut chunk) = ready!(self.poll_next_chunk(cx))? {
            if let Poll::Ready(capacity) = self.poll_capacity(cx, chunk.len()) {
                let take = capacity?.min(chunk.len());

                self.channel.send_data(chunk.split_to(take), false)?;

                if !chunk.is_empty() {
                    self.chunk = Some(chunk);
                }
            } else {
                // we'll use the chunk next time
                self.chunk = Some(chunk);

                return Poll::Pending;
            }
        }

        self.channel.send_data(Bytes::new(), true)?;

        Poll::Ready(Ok(()))
    }
}