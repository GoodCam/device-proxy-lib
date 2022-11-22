use std::{
    borrow::Cow,
    ffi::c_void,
    net::{IpAddr, SocketAddr},
    os::raw::{c_char, c_int},
    ptr,
    sync::Mutex,
    time::Duration,
};

use async_trait::async_trait;
use futures::{
    channel::oneshot::{self, Sender},
    future::Either,
};
use hyper::{Body, Request, Response};
use libc::{EINVAL, EIO};
use tokio::{
    runtime::{self, Runtime},
    task::JoinHandle,
};

use crate::{
    auth::BasicAuthorization, exports::RawContextWrapper, ClientHandlerResult, DeviceHandlerResult,
    Error, ProxyBuilder, ProxyHandle, RequestHandler,
};

/// Foreign callback for asynchronous proxy construction.
type NewProxyCallback = unsafe extern "C" fn(context: *mut c_void, proxy: *mut RawProxyHandle);

/// Foreign callback for joining the proxy runtime.
type ProxyJoinCallback = unsafe extern "C" fn(context: *mut c_void, res: c_int);

/// Foreign device request handler.
type RawDeviceHandlerFn = unsafe extern "C" fn(
    context: *mut c_void,
    authorization: *const BasicAuthorization,
    result: *mut Sender<Result<DeviceHandlerResult, Error>>,
);

/// Foreign client request handler.
type RawClientHandlerFn = unsafe extern "C" fn(
    context: *mut c_void,
    request: *mut Request<Body>,
    result: *mut Sender<Result<ClientHandlerResult, Error>>,
);

/// TLS mode.
enum TlsMode {
    None,
    LetsEncrypt,
    Simple(Vec<u8>, Vec<u8>),
}

/// Foreign request handler.
#[derive(Copy, Clone)]
struct RawRequestHandler {
    handle_device: RawDeviceHandlerFn,
    handle_client: RawClientHandlerFn,
    device_context: *mut c_void,
    client_context: *mut c_void,
}

impl RawRequestHandler {
    /// Create a new request handler.
    fn new() -> Self {
        Self {
            handle_device: dummy_device_request_handler,
            handle_client: dummy_client_request_handler,
            device_context: ptr::null_mut(),
            client_context: ptr::null_mut(),
        }
    }
}

#[async_trait]
impl RequestHandler for RawRequestHandler {
    async fn handle_device_request(
        &self,
        authorization: BasicAuthorization,
    ) -> Result<DeviceHandlerResult, Error> {
        let (tx, rx) = oneshot::channel();

        let this = *self;

        tokio::task::spawn_blocking(move || {
            // we need to capture the whole request handler
            let this = this;

            let tx = Box::into_raw(Box::new(tx));

            unsafe { (this.handle_device)(this.device_context, &authorization, tx) }
        });

        rx.await
            .map_err(|_| Error::from_static_msg("device handler failure"))?
    }

    async fn handle_client_request(
        &self,
        request: Request<Body>,
    ) -> Result<ClientHandlerResult, Error> {
        let (tx, rx) = oneshot::channel();

        let this = *self;

        tokio::task::spawn_blocking(move || {
            // we need to capture the whole request handler
            let this = this;

            let request = Box::into_raw(Box::new(request));

            let tx = Box::into_raw(Box::new(tx));

            unsafe { (this.handle_client)(this.client_context, request, tx) }
        });

        rx.await
            .map_err(|_| Error::from_static_msg("client handler failure"))?
    }
}

unsafe impl Send for RawRequestHandler {}
unsafe impl Sync for RawRequestHandler {}

/// Default device request handler that will reject all incoming connections.
unsafe extern "C" fn dummy_device_request_handler(
    _: *mut c_void,
    _: *const BasicAuthorization,
    tx: *mut Sender<Result<DeviceHandlerResult, Error>>,
) {
    let tx = Box::from_raw(tx);

    let _ = tx.send(Ok(DeviceHandlerResult::Unauthorized));
}

/// Default client request handler that will block all incoming requests.
unsafe extern "C" fn dummy_client_request_handler(
    _: *mut c_void,
    request: *mut Request<Body>,
    tx: *mut Sender<Result<ClientHandlerResult, Error>>,
) {
    Box::from_raw(request);

    let tx = Box::from_raw(tx);

    let response = Response::builder().status(501).body(Body::empty()).unwrap();

    let _ = tx.send(Ok(ClientHandlerResult::block(response)));
}

/// Proxy configuration.
struct ProxyConfig {
    handler: RawRequestHandler,
    hostname: String,
    http_bind_addresses: Vec<SocketAddr>,
    https_bind_addresses: Vec<SocketAddr>,
    tls_mode: TlsMode,
}

impl ProxyConfig {
    /// Create a new proxy configuration.
    fn new() -> Self {
        Self {
            handler: RawRequestHandler::new(),
            hostname: String::from("localhost"),
            http_bind_addresses: Vec::new(),
            https_bind_addresses: Vec::new(),
            tls_mode: TlsMode::None,
        }
    }

    /// Create and populate a proxy builder.
    fn to_builder(&self) -> Result<ProxyBuilder, Error> {
        let mut builder = ProxyBuilder::new();

        builder.hostname(&self.hostname);

        for addr in &self.http_bind_addresses {
            builder.http_bind_address(*addr);
        }

        for addr in &self.https_bind_addresses {
            builder.https_bind_address(*addr);
        }

        match &self.tls_mode {
            TlsMode::None => (),
            TlsMode::LetsEncrypt => {
                builder.lets_encrypt();
            }
            TlsMode::Simple(key, cert) => {
                builder.tls_identity(key, cert)?;
            }
        }

        Ok(builder)
    }
}

/// Proxy context.
struct RawProxyContext {
    runtime: Runtime,
    handle: ProxyHandle,
    task: Option<JoinHandle<Result<(), Error>>>,
}

impl RawProxyContext {
    /// Start a new proxy asynchronously and call a given callback when the
    /// proxy has started.
    fn start<T, F>(builder: ProxyBuilder, request_handler: T, cb: F)
    where
        T: RequestHandler + Send + Sync + 'static,
        F: FnOnce(Result<RawProxyContext, Error>) + Send + 'static,
    {
        let res = runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .build();

        let runtime = match res {
            Ok(r) => r,
            Err(err) => return cb(Err(err.into())),
        };

        runtime.handle().clone().spawn(async move {
            let proxy = match builder.build(request_handler).await {
                Ok(p) => p,
                Err(err) => return cb(Err(err)),
            };

            let handle = proxy.handle();

            let task = tokio::spawn(proxy);

            let res = Self {
                runtime,
                handle,
                task: Some(task),
            };

            cb(Ok(res));
        });
    }

    /// Stop the proxy asynchronously.
    fn stop(&mut self, timeout: Duration) {
        if let Some(task) = self.task.take() {
            let handle = self.handle.clone();

            let task = self.runtime.spawn(async move {
                handle.stop();

                let delay = tokio::time::sleep(timeout);

                futures::pin_mut!(delay);
                futures::pin_mut!(task);

                let select = futures::future::select(delay, task);

                match select.await {
                    Either::Left((_, task)) => {
                        // abort the task
                        handle.abort();

                        // and wait until it stops
                        let _ = task.await;

                        Err(Error::from_static_msg("timeout"))
                    }
                    Either::Right((res, _)) => match res {
                        Ok(res) => res.map_err(Error::from),
                        Err(_) => Ok(()),
                    },
                }
            });

            self.task = Some(task);
        }
    }

    /// Abort the proxy.
    fn abort(&self) {
        self.handle.abort();
    }

    /// Join the proxy runtime asynchronously.
    fn join<F>(&mut self, cb: F)
    where
        F: FnOnce(Result<(), Error>) + Send + 'static,
    {
        if let Some(task) = self.task.take() {
            let task = self.runtime.spawn(async move {
                let res = match task.await {
                    Ok(res) => res,
                    Err(_) => Ok(()),
                };

                cb(res);

                Ok(())
            });

            self.task = Some(task);
        } else {
            cb(Ok(()));
        }
    }
}

impl Drop for RawProxyContext {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Proxy handle.
struct RawProxyHandle {
    context: Mutex<RawProxyContext>,
}

impl RawProxyHandle {
    /// Start the proxy.
    ///
    /// This method will block the thread until the proxy is initialized.
    fn start<T>(builder: ProxyBuilder, request_handler: T) -> Result<Self, Error>
    where
        T: RequestHandler + Send + Sync + 'static,
    {
        let (tx, rx) = std::sync::mpsc::channel();

        Self::start_async(builder, request_handler, move |res| {
            let _ = tx.send(res);
        });

        rx.recv().unwrap()
    }

    /// Start the proxy.
    ///
    /// This method will return immediately and call a given callback when the
    /// proxy is ready.
    fn start_async<T, F>(builder: ProxyBuilder, request_handler: T, cb: F)
    where
        T: RequestHandler + Send + Sync + 'static,
        F: FnOnce(Result<RawProxyHandle, Error>) + Send + 'static,
    {
        RawProxyContext::start(builder, request_handler, move |res| match res {
            Ok(ctx) => {
                let res = Self {
                    context: Mutex::new(ctx),
                };

                cb(Ok(res));
            }
            Err(err) => cb(Err(err)),
        })
    }

    /// Stop the proxy asynchronously.
    fn stop(&self, timeout: Duration) {
        self.context.lock().unwrap().stop(timeout);
    }

    /// Abort the proxy.
    fn abort(&self) {
        self.context.lock().unwrap().abort();
    }

    /// Block the current thread until the proxy has stopped.
    fn join(&self) -> Result<(), Error> {
        let (tx, rx) = std::sync::mpsc::channel();

        self.context.lock().unwrap().join(move |res| {
            let _ = tx.send(res);
        });

        match rx.recv() {
            Ok(res) => res,
            Err(_) => Ok(()),
        }
    }

    /// Call a given callback when the proxy has stopped.
    fn join_async<F>(&self, cb: F)
    where
        F: FnOnce(Result<(), Error>) + Send + 'static,
    {
        self.context.lock().unwrap().join(cb);
    }
}

/// Create a new proxy configuration.
#[no_mangle]
extern "C" fn gcdp__proxy_config__new() -> *mut ProxyConfig {
    Box::into_raw(Box::new(ProxyConfig::new()))
}

/// Set proxy hostname.
#[no_mangle]
unsafe extern "C" fn gcdp__proxy_config__set_hostname(
    config: *mut ProxyConfig,
    hostname: *const c_char,
) -> c_int {
    let config = &mut *config;

    if let Some(hostname) = try_result!(EINVAL, super::cstr_to_str(hostname)) {
        config.hostname = hostname.to_string();
    } else {
        throw!(EINVAL, "hostname cannot be null");
    }

    0
}

/// Add HTTP binding.
///
/// The addr should be a C-string representing an IPv4/IPv6 address.
#[no_mangle]
unsafe extern "C" fn gcdp__proxy_config__add_http_bind_addr(
    config: *mut ProxyConfig,
    addr: *const c_char,
    port: u16,
) -> c_int {
    let config = &mut *config;

    config
        .http_bind_addresses
        .push(try_result!(EINVAL, raw_addr_to_socket_addr(addr, port)));

    0
}

/// Add HTTPS binding.
///
/// The addr should be a C-string representing an IPv4/IPv6 address.
#[no_mangle]
unsafe extern "C" fn gcdp__proxy_config__add_https_bind_addr(
    config: *mut ProxyConfig,
    addr: *const c_char,
    port: u16,
) -> c_int {
    let config = &mut *config;

    config
        .https_bind_addresses
        .push(try_result!(EINVAL, raw_addr_to_socket_addr(addr, port)));

    0
}

/// Use Let's encrypt to generate a TLS key and a certificate.
#[no_mangle]
extern "C" fn gcdp__proxy_config__use_lets_encrypt(config: *mut ProxyConfig) {
    let config = unsafe { &mut *config };

    config.tls_mode = TlsMode::LetsEncrypt;
}

/// Use a given TLS identity.
///
/// The key and certificate chain must be in PEM format.
#[no_mangle]
unsafe extern "C" fn gcdp__proxy_config__set_tls_identity(
    config: *mut ProxyConfig,
    key: *const u8,
    key_size: usize,
    cert: *const u8,
    cert_size: usize,
) {
    let config = &mut *config;

    let key = std::slice::from_raw_parts(key, key_size);
    let cert = std::slice::from_raw_parts(cert, cert_size);

    config.tls_mode = TlsMode::Simple(key.to_vec(), cert.to_vec());
}

/// Use a given device request handler.
///
/// The handler and the context must be thread-safe and they must remain valid
/// for the whole lifetime of the proxy.
#[no_mangle]
extern "C" fn gcdp__proxy_config__set_device_handler(
    config: *mut ProxyConfig,
    handler: RawDeviceHandlerFn,
    context: *mut c_void,
) {
    let config = unsafe { &mut *config };

    config.handler.device_context = context;
    config.handler.handle_device = handler;
}

/// Use a given client request handler.
///
/// The handler and the context must be thread-safe and they must remain valid
/// for the whole lifetime of the proxy.
#[no_mangle]
extern "C" fn gcdp__proxy_config__set_client_handler(
    config: *mut ProxyConfig,
    handler: RawClientHandlerFn,
    context: *mut c_void,
) {
    let config = unsafe { &mut *config };

    config.handler.client_context = context;
    config.handler.handle_client = handler;
}

/// Free the configuration.
#[no_mangle]
extern "C" fn gcdp__proxy_config__free(config: *mut ProxyConfig) {
    unsafe { super::free(config) }
}

/// Create a new proxy form a given configuration.
///
/// The function will block the current thread until the proxy is available.
#[no_mangle]
extern "C" fn gcdp__proxy__new(config: *const ProxyConfig) -> *mut RawProxyHandle {
    let config = unsafe { &*config };

    let builder = try_result!(EINVAL, ptr::null_mut(), config.to_builder());

    let handle = try_result!(
        EIO,
        ptr::null_mut(),
        RawProxyHandle::start(builder, config.handler)
    );

    Box::into_raw(Box::new(handle))
}

/// Create a new proxy from a given configuration.
///
/// The function will return immediately and notify a given callback once the
/// proxy is available.
#[no_mangle]
extern "C" fn gcdp__proxy__new_async(
    config: *const ProxyConfig,
    cb: NewProxyCallback,
    context: *mut c_void,
) {
    let config = unsafe { &*config };

    let context = RawContextWrapper(context);

    let cb = move |proxy| unsafe { cb(context.unwrap(), proxy) };

    let builder = match config.to_builder() {
        Ok(b) => b,
        Err(err) => {
            // set the error
            super::set_last_error(EIO, Cow::Owned(err.to_string()));

            // and return NULL
            return cb(ptr::null_mut());
        }
    };

    RawProxyHandle::start_async(builder, config.handler, move |res| match res {
        Ok(handle) => cb(Box::into_raw(Box::new(handle))),
        Err(err) => {
            // set the error
            super::set_last_error(EIO, Cow::Owned(err.to_string()));

            // and return NULL
            cb(ptr::null_mut());
        }
    });
}

/// Stop the proxy.
///
/// This function is asynchronous.
#[no_mangle]
extern "C" fn gcdp__proxy__stop(proxy: *mut RawProxyHandle, timeout: u32) {
    let handle = unsafe { &*proxy };

    handle.stop(Duration::from_millis(timeout as u64));
}

/// Abort the proxy.
///
/// This function is asynchronous.
#[no_mangle]
extern "C" fn gcdp__proxy__abort(proxy: *mut RawProxyHandle) {
    let handle = unsafe { &*proxy };

    handle.abort();
}

/// Block the current thread until the proxy has stopped.
#[no_mangle]
unsafe extern "C" fn gcdp__proxy__join(proxy: *mut RawProxyHandle) -> c_int {
    let handle = &*proxy;

    try_result!(EIO, handle.join());

    0
}

/// Notify a given callback when the proxy stops.
#[no_mangle]
unsafe extern "C" fn gcdp__proxy__join_async(
    proxy: *mut RawProxyHandle,
    cb: ProxyJoinCallback,
    context: *mut c_void,
) {
    let handle = &*proxy;

    let context = RawContextWrapper(context);

    handle.join_async(move |res| match res {
        Ok(()) => cb(context.unwrap(), 0),
        Err(err) => {
            // set the error
            super::set_last_error(EIO, Cow::Owned(err.to_string()));

            // and return the error code
            cb(context.unwrap(), EIO);
        }
    });
}

/// Free the proxy.
#[no_mangle]
extern "C" fn gcdp__proxy__free(proxy: *mut RawProxyHandle) {
    unsafe { super::free(proxy) }
}

/// Set the device handler result to "accept" indicating that the proxy should
/// accept the device connection.
///
/// The function takes ownership of the sender.
#[no_mangle]
extern "C" fn gcdp__device_handler_result__accept(
    tx: *mut Sender<Result<DeviceHandlerResult, Error>>,
) {
    let tx = unsafe { Box::from_raw(tx) };

    let _ = tx.send(Ok(DeviceHandlerResult::Accept));
}

/// Set the device handler result to "unauthorized" indicating that the proxy
/// should reject the device connection.
///
/// The function takes ownership of the sender.
#[no_mangle]
extern "C" fn gcdp__device_handler_result__unauthorized(
    tx: *mut Sender<Result<DeviceHandlerResult, Error>>,
) {
    let tx = unsafe { Box::from_raw(tx) };

    let _ = tx.send(Ok(DeviceHandlerResult::Unauthorized));
}

/// Set the device handler result to "redirect" indicating that the proxy
/// should redirect the device to a given location.
///
/// The function takes ownership of the sender.
#[no_mangle]
unsafe extern "C" fn gcdp__device_handler_result__redirect(
    tx: *mut Sender<Result<DeviceHandlerResult, Error>>,
    location: *const c_char,
) -> c_int {
    let location = if let Some(location) = try_result!(EINVAL, super::cstr_to_str(location)) {
        location
    } else {
        throw!(EINVAL, "location cannot be null");
    };

    let tx = Box::from_raw(tx);

    let _ = tx.send(Ok(DeviceHandlerResult::redirect(location)));

    0
}

/// Set the device handler result to "error" indicating that the handler is not
/// able to handle the request.
///
/// The function takes ownership of the sender.
#[no_mangle]
unsafe extern "C" fn gcdp__device_handler_result__error(
    tx: *mut Sender<Result<DeviceHandlerResult, Error>>,
    error: *const c_char,
) -> c_int {
    let error = try_result!(EINVAL, super::cstr_to_error(error));

    let tx = Box::from_raw(tx);

    let _ = tx.send(Err(error));

    0
}

/// Set the client handler result to "forward" indicating that the proxy should
/// forward the client request to device with a given ID.
///
/// The function takes ownership of the request and the sender.
#[no_mangle]
unsafe extern "C" fn gcdp__client_handler_result__forward(
    tx: *mut Sender<Result<ClientHandlerResult, Error>>,
    device_id: *const c_char,
    request: *mut Request<Body>,
) -> c_int {
    if request.is_null() {
        throw!(EINVAL, "request cannot be null");
    }

    let device_id = if let Some(device_id) = try_result!(EINVAL, super::cstr_to_str(device_id)) {
        device_id
    } else {
        throw!(EINVAL, "device ID cannot be null");
    };

    let request = Box::from_raw(request);

    let tx = Box::from_raw(tx);

    let _ = tx.send(Ok(ClientHandlerResult::forward(device_id, *request)));

    0
}

/// Set the client handler result to "block" indicating that the proxy should
/// block the client request and return a given response instead.
///
/// The function takes ownership of the response and the sender.
#[no_mangle]
unsafe extern "C" fn gcdp__client_handler_result__block(
    tx: *mut Sender<Result<ClientHandlerResult, Error>>,
    response: *mut Response<Body>,
) -> c_int {
    if response.is_null() {
        throw!(EINVAL, "response cannot be null");
    }

    let response = Box::from_raw(response);

    let tx = Box::from_raw(tx);

    let _ = tx.send(Ok(ClientHandlerResult::block(*response)));

    0
}

/// Set the client handler result to "error" indicating that the handler is not
/// able to handle the request.
///
/// The function takes ownership of the sender.
#[no_mangle]
unsafe extern "C" fn gcdp__client_handler_result__error(
    tx: *mut Sender<Result<ClientHandlerResult, Error>>,
    error: *const c_char,
) -> c_int {
    let error = try_result!(EINVAL, super::cstr_to_error(error));

    let tx = Box::from_raw(tx);

    let _ = tx.send(Err(error));

    0
}

/// Get device ID from a given authorization object.
///
/// The device ID will be copied into a given buffer (unless it is NULL).
/// The size parameter is expected to contain the buffer capacity and after the
/// function returns, it will contain the original length of the device ID.
/// The size cannot be NULL.
///
/// The string copied into the buffer may be truncated but it will be always
/// null-terminated.
#[no_mangle]
unsafe extern "C" fn gcdp__authorization__get_device_id(
    authorization: *const BasicAuthorization,
    buffer: *mut c_char,
    size: *mut usize,
) {
    let authorization = &*authorization;

    *size = super::str_to_cstr(authorization.username(), buffer, *size);
}

/// Get device key from a given authorization object.
///
/// The device key will be copied into a given buffer (unless it is NULL).
/// The size parameter is expected to contain the buffer capacity and after the
/// function returns, it will contain the original length of the device key.
/// The size cannot be NULL.
///
/// The string copied into the buffer may be truncated but it will be always
/// null-terminated.
#[no_mangle]
unsafe extern "C" fn gcdp__authorization__get_device_key(
    authorization: *const BasicAuthorization,
    buffer: *mut c_char,
    size: *mut usize,
) {
    let authorization = &*authorization;

    *size = super::str_to_cstr(authorization.password(), buffer, *size);
}

/// Helper function for constructing a socket address from a given C-string and
/// port.
unsafe fn raw_addr_to_socket_addr(addr: *const c_char, port: u16) -> Result<SocketAddr, Error> {
    let addr: IpAddr = super::cstr_to_str(addr)
        .transpose()
        .ok_or_else(|| Error::from_static_msg("address cannot be null"))?
        .ok()
        .map(|addr| addr.parse())
        .and_then(|res| res.ok())
        .ok_or_else(|| Error::from_static_msg("invalid address"))?;

    Ok(SocketAddr::from((addr, port)))
}
