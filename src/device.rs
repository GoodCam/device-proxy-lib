use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    future::{AbortHandle, Abortable, Either},
    ready, FutureExt, SinkExt, Stream, StreamExt,
};
use h2::{client::SendRequest, Ping, PingPong, RecvStream, SendStream};
use hyper::{upgrade::Upgraded, Body, Request, Response};
use uuid::Uuid;

use crate::{response, Error};

/// Device manager.
#[derive(Clone)]
pub struct DeviceManager {
    devices: Arc<Mutex<HashMap<String, DeviceEntry>>>,
}

impl DeviceManager {
    /// Create a new device manager.
    pub fn new() -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Add a given device.
    pub fn add(
        &self,
        device_id: &str,
        session_id: Uuid,
        handle: DeviceHandle,
    ) -> Option<DeviceHandle> {
        self.devices
            .lock()
            .unwrap()
            .insert(device_id.to_string(), DeviceEntry::new(session_id, handle))
            .map(|old| old.into_handle())
    }

    /// Remove device with a given ID.
    pub fn remove(&self, device_id: &str, session_id: Option<Uuid>) -> Option<DeviceHandle> {
        let mut devices = self.devices.lock().unwrap();

        let entry = devices.get(device_id)?;

        if let Some(session_id) = session_id {
            if session_id != entry.session_id {
                return None;
            }
        }

        devices.remove(device_id).map(|entry| entry.into_handle())
    }

    /// Get device with a given ID.
    pub fn get(&self, device_id: &str) -> Option<DeviceHandle> {
        self.devices
            .lock()
            .unwrap()
            .get(device_id)
            .map(|entry| entry.handle())
            .cloned()
    }
}

/// Device manager entry.
struct DeviceEntry {
    session_id: Uuid,
    handle: DeviceHandle,
}

impl DeviceEntry {
    /// Create a new device manager entry.
    fn new(session_id: Uuid, handle: DeviceHandle) -> Self {
        Self { session_id, handle }
    }

    /// Get the device handle.
    fn handle(&self) -> &DeviceHandle {
        &self.handle
    }

    /// Get the device handle.
    fn into_handle(self) -> DeviceHandle {
        self.handle
    }
}

const PING_INTERVAL: Duration = Duration::from_secs(10);
const PONG_TIMEOUT: Duration = Duration::from_secs(20);

/// Typle alias.
type Connection = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

/// Future representing a device connection.
///
/// The future will be resolved when the corresponding connection gets closed.
pub struct DeviceConnection {
    connection: Abortable<Connection>,
}

impl DeviceConnection {
    /// Create a new device connection.
    pub async fn new(connection: Upgraded) -> Result<(Self, DeviceHandle), Error> {
        let (h2, mut connection) = h2::client::handshake(connection).await?;

        let ping_pong = connection
            .ping_pong()
            .expect("unable to get connection ping-pong");

        let keep_alive = KeepAlive::new(ping_pong, PING_INTERVAL, PONG_TIMEOUT);

        let connection: Connection = Box::pin(async move {
            let keep_alive = keep_alive.run();

            futures::pin_mut!(connection);
            futures::pin_mut!(keep_alive);

            let select = futures::future::select(connection, keep_alive);

            match select.await {
                Either::Left((res, _)) => res.map_err(Error::from),
                Either::Right((res, connection)) => {
                    if res.is_err() {
                        res
                    } else {
                        connection.await.map_err(Error::from)
                    }
                }
            }
        });

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
            Ok(Err(err)) => Err(err),
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

/// Keep-alive handler.
struct KeepAlive {
    inner: PingPong,
    interval: Duration,
    timeout: Duration,
}

impl KeepAlive {
    /// Create a new keep-alive handler.
    fn new(ping_pong: PingPong, interval: Duration, timeout: Duration) -> Self {
        Self {
            inner: ping_pong,
            interval,
            timeout,
        }
    }

    /// Run the handler.
    async fn run(mut self) -> Result<(), Error> {
        let mut next_ping = Instant::now() + self.interval;

        loop {
            tokio::time::sleep_until(next_ping.into()).await;

            next_ping = Instant::now() + self.interval;

            let pong = tokio::time::timeout(self.timeout, self.inner.ping(Ping::opaque()));

            match pong.await {
                Ok(Ok(_)) => (),
                Ok(Err(err)) => {
                    // do not return any error if the connection was normally
                    // closed by the remote peer
                    if let Some(err) = err.get_io() {
                        if err.kind() == io::ErrorKind::BrokenPipe {
                            return Ok(());
                        }
                    }

                    return Err(err.into());
                }
                Err(_) => return Err(Error::from_static_msg("connection timeout")),
            }
        }
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
                warn!("unable to send request body: {err}");
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
