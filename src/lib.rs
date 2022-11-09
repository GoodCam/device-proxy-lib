mod acme;
mod binding;
mod device;
mod error;
mod response;
mod tls;

#[cfg(feature = "c-api")]
mod exports;

pub mod auth;

use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::{
    channel::oneshot::{self, Sender},
    future::Either,
    StreamExt,
};
use hyper::{Body, HeaderMap, Method, Request, Response, Server, Version};
use native_tls::Identity;
use tokio::task::JoinHandle;

pub use hyper;

use self::{
    auth::BasicAuthorization,
    binding::{Bindings, Connection},
    device::{DeviceConnection, DeviceManager},
    error::{BadGateway, HttpError, Unauthorized},
    tls::TlsMode,
};

pub use self::{binding::ConnectionInfo, error::Error};

///
pub enum DeviceHandlerResult {
    Accept,
    Unauthorized,
    Redirect(String),
}

impl DeviceHandlerResult {
    /// Accept the device connection.
    pub fn accept() -> Self {
        Self::Accept
    }

    /// Reject the client connection.
    pub fn unauthorized() -> Self {
        Self::Unauthorized
    }

    /// Redirect the client to another service.
    pub fn redirect<T>(location: T) -> Self
    where
        T: ToString,
    {
        Self::Redirect(location.to_string())
    }
}

///
pub enum ClientHandlerResult {
    Forward(String, Request<Body>),
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

    /// Block the request and return a given response back to the client.
    pub fn block(response: Response<Body>) -> Self {
        Self::Block(response)
    }
}

///
#[async_trait]
pub trait RequestHandler {
    ///
    async fn handle_device_request(
        &self,
        authorization: BasicAuthorization,
    ) -> Result<DeviceHandlerResult, Error>;

    ///
    async fn handle_client_request(
        &self,
        request: Request<Body>,
    ) -> Result<ClientHandlerResult, Error>;
}

///
pub trait BlockingRequestHandler {
    ///
    fn handle_device_request(
        &self,
        authorization: BasicAuthorization,
    ) -> Result<DeviceHandlerResult, Error>;

    ///
    fn handle_client_request(&self, request: Request<Body>) -> Result<ClientHandlerResult, Error>;
}

///
pub struct RequestHandlerAdapter<T> {
    inner: Arc<T>,
}

#[async_trait]
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

///
pub struct ProxyBuilder {
    hostname: String,
    http_bind_addresses: Vec<SocketAddr>,
    https_bind_addresses: Vec<SocketAddr>,
    tls_mode: TlsMode,
}

impl ProxyBuilder {
    ///
    pub fn new() -> Self {
        Self {
            hostname: String::from("localhost"),
            http_bind_addresses: Vec::new(),
            https_bind_addresses: Vec::new(),
            tls_mode: TlsMode::None,
        }
    }

    ///
    pub fn hostname<T>(&mut self, hostname: T) -> &mut Self
    where
        T: ToString,
    {
        self.hostname = hostname.to_string();
        self
    }

    ///
    pub fn http_bind_address(&mut self, addr: SocketAddr) -> &mut Self {
        self.http_bind_addresses.push(addr);
        self
    }

    ///
    pub fn https_bind_address(&mut self, addr: SocketAddr) -> &mut Self {
        self.https_bind_addresses.push(addr);
        self
    }

    ///
    pub fn tls_identity(&mut self, key: &[u8], cert: &[u8]) -> Result<&mut Self, Error> {
        let identity = Identity::from_pkcs8(cert, key)?;

        self.tls_mode = TlsMode::Simple(identity);

        Ok(self)
    }

    ///
    pub fn lets_encrypt(&mut self) -> &mut Self {
        self.tls_mode = TlsMode::LetsEncrypt;
        self
    }

    ///
    pub fn build<T>(self, request_handler: T) -> Proxy<RequestHandlerAdapter<T>>
    where
        T: BlockingRequestHandler + Send + Sync + 'static,
    {
        self.build_async(RequestHandlerAdapter::from(request_handler))
    }

    ///
    pub fn build_async<T>(self, request_handler: T) -> Proxy<T>
    where
        T: RequestHandler + Send + Sync + 'static,
    {
        Proxy {
            hostname: self.hostname,
            http_bind_addresses: self.http_bind_addresses,
            https_bind_addresses: self.https_bind_addresses,
            tls_mode: self.tls_mode,
            handler: request_handler,
        }
    }
}

impl Default for ProxyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

///
pub struct Proxy<T> {
    hostname: String,
    http_bind_addresses: Vec<SocketAddr>,
    https_bind_addresses: Vec<SocketAddr>,
    tls_mode: TlsMode,
    handler: T,
}

impl<T> Proxy<T>
where
    T: RequestHandler + Send + Sync + 'static,
{
    ///
    pub fn builder() -> ProxyBuilder {
        ProxyBuilder::new()
    }

    ///
    pub async fn serve(self) -> Result<ProxyHandle, Error> {
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
            handler: self.handler.into(),
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

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server = Server::builder(incoming)
            .http1_keepalive(true)
            .http2_keep_alive_interval(Some(Duration::from_secs(120)))
            .http2_keep_alive_timeout(Duration::from_secs(20))
            .serve(make_service)
            .with_graceful_shutdown(async move {
                if shutdown_rx.await.is_err() {
                    futures::future::pending().await
                }
            });

        let server = tokio::spawn(server);

        let watchdog = if let Some(watchdog) = acme_watchdog {
            tokio::spawn(watchdog.watch())
        } else {
            tokio::spawn(futures::future::pending())
        };

        // TODO: aborting this task won't abort the proxy and the watchdog
        let task = tokio::spawn(async move {
            let res = server.await;

            watchdog.abort();

            let _ = watchdog.await;

            match res {
                Ok(res) => res,
                Err(_) => Ok(()),
            }
        });

        let handle = ProxyHandle { shutdown_tx, task };

        Ok(handle)
    }
}

///
pub struct ProxyHandle {
    shutdown_tx: Sender<()>,
    task: JoinHandle<Result<(), hyper::Error>>,
}

impl ProxyHandle {
    ///
    pub async fn stop(self, timeout: Duration) -> Result<(), Error> {
        let _ = self.shutdown_tx.send(());

        let delay = tokio::time::sleep(timeout);

        let task = self.task;

        futures::pin_mut!(delay);
        futures::pin_mut!(task);

        let select = futures::future::select(delay, task);

        match select.await {
            Either::Left((_, task)) => {
                // abort the task
                task.abort();

                // and wait until it stops
                let _ = task.await;

                Err(Error::from_static_msg("timeout"))
            }
            Either::Right((res, _)) => match res {
                Ok(res) => res.map_err(Error::from),
                Err(_) => Err(Error::from_static_msg("terminating")),
            },
        }
    }

    ///
    pub async fn abort(self) {
        // abort the task
        self.task.abort();

        // and wait until it stops
        let _ = self.task.await;
    }
}

///
struct InternalRequestHandler<T> {
    acme_challenges: acme::ChallengeRegistrations,
    devices: DeviceManager,
    handler: Arc<T>,
}

impl<T> InternalRequestHandler<T>
where
    T: RequestHandler + Send + Sync + 'static,
{
    ///
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

    ///
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

    ///
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

    ///
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

    ///
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

///
trait RequestExt {
    ///
    fn is_device_request(&self) -> bool;

    ///
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

///
trait AsHeaderMapExt {
    ///
    fn as_ext(&self) -> HeaderMapExt;
}

impl AsHeaderMapExt for HeaderMap {
    fn as_ext(&self) -> HeaderMapExt {
        HeaderMapExt { inner: self }
    }
}

///
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
