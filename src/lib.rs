//! # GoodCam Device Proxy
//!
//! This library simplifies creating HTTP proxies that can be used to communicate
//! with GoodCam devices in various networks. GoodCam devices contain a
//! [built-in client](https://goodcam.github.io/goodcam-api/#tag/cloud>) that
//! can be configured to connect automatically to a given proxy. Once
//! connected, the devices will wait for incoming HTTP requests. The proxy
//! simply forwards incoming HTTP requests to the connected devices.
//!
//! ## Usage example
//!
//! See the `examples` directory in the root of this repository for a
//! ready-to-use example.
//!
//! ```ignore
//! use gcdevproxy::{
//!     async_trait::async_trait,
//!     auth::BasicAuthorization,
//!     http::{Body, Request},
//!     ClientHandlerResult, DeviceHandlerResult, Error, RequestHandler,
//! };
//!
//! struct MyRequestHandler;
//!
//! #[async_trait]
//! impl RequestHandler for MyRequestHandler {
//!     async fn handle_device_request(
//!         &self,
//!         authorization: BasicAuthorization,
//!     ) -> Result<DeviceHandlerResult, Error> {
//!         ...
//!     }
//!
//!     async fn handle_client_request(
//!         &self,
//!         request: Request<Body>,
//!     ) -> Result<ClientHandlerResult, Error> {
//!         ...
//!     }
//! }
//!
//! let mut builder = ProxyBuilder::new();
//!
//! builder
//!     .hostname(hostname)
//!     .http_bind_address(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)));
//!
//! builder
//!     .build(MyRequestHandler)
//!     .await
//!     .unwrap()
//!     .await
//!     .unwrap();
//! ```

#[macro_use]
extern crate log;

mod acme;
mod binding;
mod device;
mod error;
mod response;
mod tls;
mod utils;

#[cfg(feature = "c-api")]
mod exports;

pub mod auth;

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures::{
    channel::mpsc::{self, UnboundedSender},
    future::AbortHandle,
    FutureExt, StreamExt,
};
use hyper::{Body, HeaderMap, Method, Request, Response, Server, Version};
use native_tls::Identity;

pub use async_trait;
pub use hyper;
pub use hyper::http;

use self::{
    auth::BasicAuthorization,
    binding::{Bindings, Connection},
    device::{DeviceConnection, DeviceManager},
    error::{BadGateway, HttpError, Unauthorized},
    tls::TlsMode,
    utils::AbortOnDrop,
};

pub use self::{binding::ConnectionInfo, error::Error};

/// Possible results of a device connection handler.
pub enum DeviceHandlerResult {
    /// Accept the corresponding device connection.
    Accept,

    /// Reject the corresponding device connection.
    Unauthorized,

    /// Redirect the corresponding device to a given location.
    Redirect(String),
}

impl DeviceHandlerResult {
    /// Accept the corresponding device connection.
    pub fn accept() -> Self {
        Self::Accept
    }

    /// Reject the corresponding device connection.
    pub fn unauthorized() -> Self {
        Self::Unauthorized
    }

    /// Redirect the corresponding device to a given location.
    ///
    /// This can be used for example to implement load balancing by redirecting
    /// incoming devices to another service if the capacity of the current
    /// service is reached.
    pub fn redirect<T>(location: T) -> Self
    where
        T: ToString,
    {
        Self::Redirect(location.to_string())
    }
}

/// Possible results of a client handler.
pub enum ClientHandlerResult {
    /// Forward the request to a given device.
    Forward(String, Request<Body>),

    /// Block the corresponding request and return a given response back to the
    /// client.
    Block(Response<Body>),
}

impl ClientHandlerResult {
    /// Forward the request to a given device.
    pub fn forward<T>(device_id: T, request: Request<Body>) -> Self
    where
        T: ToString,
    {
        Self::Forward(device_id.to_string(), request)
    }

    /// Block the corresponding request and return a given response back to the
    /// client.
    pub fn block(response: Response<Body>) -> Self {
        Self::Block(response)
    }
}

/// Common trait for proxy request handlers.
#[async_trait::async_trait]
pub trait RequestHandler {
    /// Handle a given device request.
    ///
    /// The method is responsible for device authentication and (optionally)
    /// load balancing. It is called every time a GoodCam device connects to
    /// the proxy. The implementation should check the device ID and key in the
    /// authorization object.
    async fn handle_device_request(
        &self,
        authorization: BasicAuthorization,
    ) -> Result<DeviceHandlerResult, Error>;

    /// Handle a given client request.
    ///
    /// The method is responsible for authentication of a given client request.
    /// It is called every time a client is attempting to send an HTTP request
    /// to a GoodCam device. The implementation should verify the client
    /// identity and permission to access a given device. It is also
    /// responsible for extracting the target device ID from the request.
    async fn handle_client_request(
        &self,
        request: Request<Body>,
    ) -> Result<ClientHandlerResult, Error>;
}

/// Blocking version of the request handler trait.
///
/// See [`RequestHandler`] for more info.
pub trait BlockingRequestHandler {
    /// Handle a given device request.
    fn handle_device_request(
        &self,
        authorization: BasicAuthorization,
    ) -> Result<DeviceHandlerResult, Error>;

    /// Handle a given client request.
    fn handle_client_request(&self, request: Request<Body>) -> Result<ClientHandlerResult, Error>;
}

/// Adapter to make a [`RequestHandler`] from a given
/// [`BlockingRequestHandler`].
pub struct RequestHandlerAdapter<T> {
    inner: Arc<T>,
}

#[async_trait::async_trait]
impl<T> RequestHandler for RequestHandlerAdapter<T>
where
    T: BlockingRequestHandler + Send + Sync + 'static,
{
    async fn handle_device_request(
        &self,
        authorization: BasicAuthorization,
    ) -> Result<DeviceHandlerResult, Error> {
        let inner = self.inner.clone();

        let blocking =
            tokio::task::spawn_blocking(move || inner.handle_device_request(authorization));

        blocking
            .await
            .map_err(|_| Error::from_static_msg("terminating"))?
    }

    async fn handle_client_request(
        &self,
        request: Request<Body>,
    ) -> Result<ClientHandlerResult, Error> {
        let inner = self.inner.clone();

        let blocking = tokio::task::spawn_blocking(move || inner.handle_client_request(request));

        blocking
            .await
            .map_err(|_| Error::from_static_msg("terminating"))?
    }
}

impl<T> From<T> for RequestHandlerAdapter<T> {
    fn from(handler: T) -> Self {
        Self {
            inner: Arc::new(handler),
        }
    }
}

/// Proxy builder.
pub struct ProxyBuilder {
    hostname: String,
    http_bind_addresses: Vec<SocketAddr>,
    https_bind_addresses: Vec<SocketAddr>,
    tls_mode: TlsMode,
}

impl ProxyBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            hostname: String::from("localhost"),
            http_bind_addresses: Vec::new(),
            https_bind_addresses: Vec::new(),
            tls_mode: TlsMode::None,
        }
    }

    /// Set the hostname where the proxy will be available.
    pub fn hostname<T>(&mut self, hostname: T) -> &mut Self
    where
        T: ToString,
    {
        self.hostname = hostname.to_string();
        self
    }

    /// Add a given HTTP binding.
    pub fn http_bind_address(&mut self, addr: SocketAddr) -> &mut Self {
        self.http_bind_addresses.push(addr);
        self
    }

    /// Add a given HTTPS binding.
    pub fn https_bind_address(&mut self, addr: SocketAddr) -> &mut Self {
        self.https_bind_addresses.push(addr);
        self
    }

    /// Set TLS identity (used for HTTPS).
    ///
    /// # Arguments
    /// * `key` - key in PEM format
    /// * `cert` - certificate chain in PEM format
    pub fn tls_identity(&mut self, key: &[u8], cert: &[u8]) -> Result<&mut Self, Error> {
        let identity = Identity::from_pkcs8(cert, key)?;

        self.tls_mode = TlsMode::Simple(identity);

        Ok(self)
    }

    /// Use Let's Encrypt to generate the TLS key and certificate chain
    /// automatically.
    ///
    /// Please note that Let's encrypt requires HTTP services to be available
    /// on a public domain name on TCP port 80 in order to issue a TLS
    /// certificate. Make sure that you set the proxy hostname and that you
    /// add at least the `0.0.0.0:80` HTTP binding.
    pub fn lets_encrypt(&mut self) -> &mut Self {
        self.tls_mode = TlsMode::LetsEncrypt;
        self
    }

    /// Build the proxy and use a given request handler to handle incoming
    /// connections.
    pub async fn build<T>(self, request_handler: T) -> Result<Proxy, Error>
    where
        T: RequestHandler + Send + Sync + 'static,
    {
        info!("Starting GoodCam device proxy");
        info!("HTTP bindings: {:?}", self.http_bind_addresses);
        info!("HTTPS bindings: {:?}", self.https_bind_addresses);
        info!("hostname: {}", self.hostname);

        let acme_challenges = acme::ChallengeRegistrations::new();

        let acme_account = self.tls_mode.create_acme_account().await?;
        let tls_acceptor = self.tls_mode.create_tls_acceptor()?;

        let mut acme_watchdog = None;

        if let Some(tls_acceptor) = tls_acceptor.as_ref() {
            if let Some(acme_account) = acme_account {
                let watchdog = acme::Watchdog::new(
                    acme_account,
                    acme_challenges.clone(),
                    tls_acceptor.clone(),
                    &self.hostname,
                );

                acme_watchdog = Some(watchdog.await?);
            }
        }

        let handler = InternalRequestHandler {
            acme_challenges,
            devices: DeviceManager::new(),
            handler: request_handler.into(),
        };

        let mut bindings = Bindings::new();

        bindings.add_tcp_bindings(self.http_bind_addresses).await?;

        if let Some(acceptor) = tls_acceptor {
            bindings
                .add_tls_bindings(acceptor, self.https_bind_addresses)
                .await?;
        }

        let incoming = hyper::server::accept::poll_fn(move |cx| bindings.poll_next_unpin(cx));

        let make_service = hyper::service::make_service_fn(move |connection: &Connection| {
            let connection_info = connection.info();

            let handler = handler.clone();

            let service = hyper::service::service_fn(move |mut request| {
                request.extensions_mut().insert(connection_info);

                let handler = handler.clone();

                async move {
                    let response = handler.handle_request(request).await;

                    Ok(response) as Result<_, hyper::Error>
                }
            });

            futures::future::ok::<_, hyper::Error>(service)
        });

        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded();

        let server = Server::builder(incoming)
            .http1_keepalive(true)
            .http2_keep_alive_interval(Some(Duration::from_secs(120)))
            .http2_keep_alive_timeout(Duration::from_secs(20))
            .serve(make_service)
            .with_graceful_shutdown(async move {
                if shutdown_rx.next().await.is_none() {
                    futures::future::pending().await
                }
            });

        let (server, server_handle) = futures::future::abortable(server);

        let server = AbortOnDrop::from(tokio::spawn(server));

        let watchdog = if let Some(watchdog) = acme_watchdog {
            AbortOnDrop::from(tokio::spawn(watchdog.watch()))
        } else {
            AbortOnDrop::from(tokio::spawn(futures::future::pending()))
        };

        let join = async move {
            let res = match server.await {
                Ok(Ok(Ok(()))) => Ok(()),
                Ok(Ok(Err(err))) => Err(err.into()),
                Ok(Err(_)) => Ok(()),
                Err(_) => Ok(()),
            };

            watchdog.abort();

            let _ = watchdog.await;

            res
        };

        let handle = ProxyHandle {
            shutdown: shutdown_tx,
            abort: server_handle,
        };

        let proxy = Proxy {
            join: Box::pin(join),
            handle,
        };

        info!("Proxy started");

        Ok(proxy)
    }
}

impl Default for ProxyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// GoodCam device proxy.
///
/// The proxy itself is a future that will be resolved when the proxy stops.
/// The proxy runs in a background task, so the future does not have to be
/// polled in order to run the proxy. However, dropping the future will also
/// abort the background task.
pub struct Proxy {
    join: Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>,
    handle: ProxyHandle,
}

impl Proxy {
    /// Get a proxy builder.
    pub fn builder() -> ProxyBuilder {
        ProxyBuilder::new()
    }

    /// Get a proxy handle.
    pub fn handle(&self) -> ProxyHandle {
        self.handle.clone()
    }
}

impl Future for Proxy {
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.join.poll_unpin(cx)
    }
}

/// Proxy handle.
#[derive(Clone)]
pub struct ProxyHandle {
    shutdown: UnboundedSender<()>,
    abort: AbortHandle,
}

impl ProxyHandle {
    /// Gracefully stop the proxy.
    pub fn stop(&self) {
        let _ = self.shutdown.unbounded_send(());
    }

    /// Abort the proxy execution.
    pub fn abort(&self) {
        self.abort.abort();
    }
}

/// Internal request handler.
struct InternalRequestHandler<T> {
    acme_challenges: acme::ChallengeRegistrations,
    devices: DeviceManager,
    handler: Arc<T>,
}

impl<T> InternalRequestHandler<T>
where
    T: RequestHandler + Send + Sync + 'static,
{
    /// Handle a given request.
    async fn handle_request(&self, request: Request<Body>) -> Response<Body> {
        self.handle_request_inner(request)
            .await
            .unwrap_or_else(|err| {
                if let Some(response) = err.to_response() {
                    return response;
                }

                eprintln!("internal server error: {}", err);

                response::internal_server_error()
            })
    }

    /// Handle a given request.
    async fn handle_request_inner(
        &self,
        request: Request<Body>,
    ) -> Result<Response<Body>, HttpError> {
        if let Some(token) = request.get_acme_challenge_token() {
            if let Some(response) = self.acme_challenges.create_response(token) {
                return Ok(response);
            }
        }

        if request.is_device_request() {
            self.handle_device_request(request).await
        } else {
            self.handle_client_request(request).await
        }
    }

    /// Handle a given device request.
    async fn handle_device_request(
        &self,
        request: Request<Body>,
    ) -> Result<Response<Body>, HttpError> {
        let authorization = request
            .headers()
            .get("authorization")
            .ok_or(Unauthorized)?
            .to_str()
            .ok()
            .map(BasicAuthorization::from_str)
            .and_then(|res| res.ok())
            .ok_or(Unauthorized)?;

        let device_id = String::from(authorization.username());

        let ret = self.handler.handle_device_request(authorization).await?;

        match ret {
            DeviceHandlerResult::Accept => {
                let this = self.clone();

                tokio::spawn(async move {
                    if let Err(err) = this.handle_device_connection(&device_id, request).await {
                        eprintln!("unable to upgrade device connection: {}", err);
                    }
                });

                let res = Response::builder()
                    .status(101)
                    .header("Upgrade", "goodcam-device-proxy")
                    .body(Body::empty())
                    .unwrap();

                Ok(res)
            }
            DeviceHandlerResult::Unauthorized => Err(HttpError::from(Unauthorized)),
            DeviceHandlerResult::Redirect(location) => Ok(response::temporary_redirect(location)),
        }
    }

    /// Handle a new device connection.
    async fn handle_device_connection(
        &self,
        device_id: &str,
        request: Request<Body>,
    ) -> Result<(), Error> {
        let upgraded = hyper::upgrade::on(request).await?;

        let (connection, handle) = DeviceConnection::new(upgraded).await?;

        if let Some(old) = self.devices.add(device_id, handle) {
            old.close();
        }

        eprintln!("device connected");

        if let Err(err) = connection.await {
            eprintln!("device connection error: {}", err);
        } else {
            eprintln!("device disconnected");
        }

        self.devices.remove(device_id);

        Ok(())
    }

    /// Handle a given client request.
    async fn handle_client_request(
        &self,
        request: Request<Body>,
    ) -> Result<Response<Body>, HttpError> {
        let ret = self.handler.handle_client_request(request).await?;

        match ret {
            ClientHandlerResult::Block(response) => Ok(response),
            ClientHandlerResult::Forward(device_id, request) => {
                let response = self
                    .devices
                    .get(&device_id)
                    .ok_or(BadGateway)?
                    .send_request(request)
                    .await;

                Ok(response)
            }
        }
    }
}

impl<T> Clone for InternalRequestHandler<T> {
    fn clone(&self) -> Self {
        Self {
            acme_challenges: self.acme_challenges.clone(),
            devices: self.devices.clone(),
            handler: self.handler.clone(),
        }
    }
}

/// Request extensions/helpers.
trait RequestExt {
    /// Check if this is a device request.
    fn is_device_request(&self) -> bool;

    /// Get ACME challenge token (if this is an AMC challenge request).
    fn get_acme_challenge_token(&self) -> Option<&str>;
}

impl RequestExt for Request<Body> {
    fn is_device_request(&self) -> bool {
        let uri = self.uri();
        let headers = self.headers();

        let path = uri.path();

        let is_upgrade = headers
            .as_ext()
            .get_all_tokens("connection")
            .any(|token| token.eq_ignore_ascii_case("upgrade"));

        let is_gc_device_upgrade = headers
            .as_ext()
            .get_all_tokens("upgrade")
            .any(|token| token.eq_ignore_ascii_case("goodcam-device-proxy"));

        self.version() == Version::HTTP_11
            && self.method() == Method::GET
            && path == "/"
            && is_upgrade
            && is_gc_device_upgrade
    }

    fn get_acme_challenge_token(&self) -> Option<&str> {
        let uri = self.uri();

        let path = uri.path();

        path.strip_prefix("/.well-known/acme-challenge/")
    }
}

/// Helper for extending the `HeaderMap`.
trait AsHeaderMapExt {
    /// Get the extended header map.
    fn as_ext(&self) -> HeaderMapExt;
}

impl AsHeaderMapExt for HeaderMap {
    fn as_ext(&self) -> HeaderMapExt {
        HeaderMapExt { inner: self }
    }
}

/// Private helpers/extensions of the `HeaderMap`.
struct HeaderMapExt<'a> {
    inner: &'a HeaderMap,
}

impl<'a> HeaderMapExt<'a> {
    ///
    fn get_all_tokens(&self, name: &str) -> impl Iterator<Item = &str> {
        // TODO: handle correctly quoted tokens

        self.inner.get_all(name).into_iter().flat_map(|header| {
            header
                .to_str()
                .unwrap_or("")
                .split(',')
                .map(|token| token.trim())
                .filter(|token| !token.is_empty())
        })
    }
}
