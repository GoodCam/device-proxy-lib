use std::{
    ffi::c_void,
    net::{IpAddr, SocketAddr},
    os::raw::{c_char, c_int},
    ptr,
    time::Duration,
};

use futures::future::Either;
use hyper::{Body, Request, Response};
use libc::{EINVAL, EIO};
use tokio::{
    runtime::{self, Runtime},
    task::JoinHandle,
};

use crate::{
    auth::BasicAuthorization, BlockingRequestHandler, ClientHandlerResult, DeviceHandlerResult,
    Error, ProxyBuilder, ProxyHandle, RequestHandler, RequestHandlerAdapter,
};

///
type RawDeviceHandlerFn = unsafe extern "C" fn(
    context: *mut c_void,
    authorization: *const BasicAuthorization,
    result: *mut Result<DeviceHandlerResult, Error>,
);

///
type RawClientHandlerFn = unsafe extern "C" fn(
    context: *mut c_void,
    request: *mut Request<Body>,
    result: *mut Result<ClientHandlerResult, Error>,
);

///
#[derive(Copy, Clone)]
struct RawRequestHandler {
    handle_device: RawDeviceHandlerFn,
    handle_client: RawClientHandlerFn,
    device_context: *mut c_void,
    client_context: *mut c_void,
}

impl RawRequestHandler {
    ///
    fn new() -> Self {
        Self {
            handle_device: dummy_device_request_handler,
            handle_client: dummy_client_request_handler,
            device_context: ptr::null_mut(),
            client_context: ptr::null_mut(),
        }
    }
}

impl BlockingRequestHandler for RawRequestHandler {
    fn handle_device_request(
        &self,
        authorization: BasicAuthorization,
    ) -> Result<DeviceHandlerResult, Error> {
        let mut result = Ok(DeviceHandlerResult::Unauthorized);

        unsafe {
            (self.handle_device)(self.device_context, &authorization, &mut result);
        }

        result
    }

    fn handle_client_request(&self, request: Request<Body>) -> Result<ClientHandlerResult, Error> {
        let request = Box::into_raw(Box::new(request));

        let response = Response::builder().status(501).body(Body::empty()).unwrap();

        let mut result = Ok(ClientHandlerResult::block(response));

        unsafe {
            (self.handle_client)(self.client_context, request, &mut result);
        }

        result
    }
}

unsafe impl Send for RawRequestHandler {}
unsafe impl Sync for RawRequestHandler {}

///
extern "C" fn dummy_device_request_handler(
    _: *mut c_void,
    _: *const BasicAuthorization,
    _: *mut Result<DeviceHandlerResult, Error>,
) {
}

///
extern "C" fn dummy_client_request_handler(
    _: *mut c_void,
    request: *mut Request<Body>,
    _: *mut Result<ClientHandlerResult, Error>,
) {
    unsafe {
        Box::from_raw(request);
    }
}

///
enum TlsMode {
    None,
    LetsEncrypt,
    Simple(Vec<u8>, Vec<u8>),
}

///
struct ProxyConfig {
    handler: RawRequestHandler,
    hostname: String,
    http_bind_addresses: Vec<SocketAddr>,
    https_bind_addresses: Vec<SocketAddr>,
    tls_mode: TlsMode,
}

impl ProxyConfig {
    ///
    fn new() -> Self {
        Self {
            handler: RawRequestHandler::new(),
            hostname: String::from("localhost"),
            http_bind_addresses: Vec::new(),
            https_bind_addresses: Vec::new(),
            tls_mode: TlsMode::None,
        }
    }
}

///
struct RawProxyHandle {
    runtime: Runtime,
    handle: ProxyHandle,
    task: JoinHandle<Result<(), Error>>,
}

impl RawProxyHandle {
    ///
    fn start<T>(builder: ProxyBuilder, request_handler: T) -> Result<Self, Error>
    where
        T: RequestHandler + Send + Sync + 'static,
    {
        let runtime = runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .build()?;

        let proxy = runtime.block_on(builder.build(request_handler))?;

        let handle = proxy.handle();

        let task = runtime.spawn(proxy);

        let res = Self {
            runtime,
            handle,
            task,
        };

        Ok(res)
    }

    ///
    fn stop(self, timeout: Duration) -> Result<(), Error> {
        self.runtime.block_on(async move {
            self.handle.stop();

            let delay = tokio::time::sleep(timeout);

            let task = self.task;

            futures::pin_mut!(delay);
            futures::pin_mut!(task);

            let select = futures::future::select(delay, task);

            match select.await {
                Either::Left((_, task)) => {
                    // abort the task
                    self.handle.abort();

                    // and wait until it stops
                    let _ = task.await;

                    Err(Error::from_static_msg("timeout"))
                }
                Either::Right((res, _)) => match res {
                    Ok(res) => res.map_err(Error::from),
                    Err(_) => Ok(()),
                },
            }
        })
    }

    ///
    fn abort(self) {
        // abort the task
        self.handle.abort();

        // and wait until it stops
        let _ = self.runtime.block_on(self.task);
    }
}

///
#[no_mangle]
extern "C" fn gcdp__proxy_config__new() -> *mut ProxyConfig {
    Box::into_raw(Box::new(ProxyConfig::new()))
}

///
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

///
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

///
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

///
#[no_mangle]
extern "C" fn gcdp__proxy_config__use_lets_encrypt(config: *mut ProxyConfig) {
    let config = unsafe { &mut *config };

    config.tls_mode = TlsMode::LetsEncrypt;
}

///
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

///
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

///
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

///
#[no_mangle]
extern "C" fn gcdp__proxy_config__free(config: *mut ProxyConfig) {
    unsafe { super::free(config) }
}

///
#[no_mangle]
extern "C" fn gcdp__proxy__new(config: *const ProxyConfig) -> *mut RawProxyHandle {
    let config = unsafe { &*config };

    let mut builder = ProxyBuilder::new();

    builder.hostname(&config.hostname);

    for addr in &config.http_bind_addresses {
        builder.http_bind_address(*addr);
    }

    for addr in &config.https_bind_addresses {
        builder.https_bind_address(*addr);
    }

    match &config.tls_mode {
        TlsMode::None => (),
        TlsMode::LetsEncrypt => {
            builder.lets_encrypt();
        }
        TlsMode::Simple(key, cert) => {
            try_result!(EINVAL, ptr::null_mut(), builder.tls_identity(key, cert));
        }
    }

    let handler = RequestHandlerAdapter::from(config.handler);

    let handle = try_result!(
        EIO,
        ptr::null_mut(),
        RawProxyHandle::start(builder, handler)
    );

    Box::into_raw(Box::new(handle))
}

///
#[no_mangle]
extern "C" fn gcdp__proxy__stop(proxy: *mut RawProxyHandle, timeout: u32) -> c_int {
    let handle = unsafe { Box::from_raw(proxy) };

    try_result!(EIO, handle.stop(Duration::from_millis(timeout as u64)));

    0
}

///
#[no_mangle]
extern "C" fn gcdp__proxy__abort(proxy: *mut RawProxyHandle) {
    let handle = unsafe { Box::from_raw(proxy) };

    handle.abort();
}

///
#[no_mangle]
extern "C" fn gcdp__device_handler_result__accept(result: *mut Result<DeviceHandlerResult, Error>) {
    let result = unsafe { &mut *result };

    *result = Ok(DeviceHandlerResult::Accept)
}

///
#[no_mangle]
extern "C" fn gcdp__device_handler_result__unauthorized(
    result: *mut Result<DeviceHandlerResult, Error>,
) {
    let result = unsafe { &mut *result };

    *result = Ok(DeviceHandlerResult::Unauthorized)
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__device_handler_result__redirect(
    result: *mut Result<DeviceHandlerResult, Error>,
    location: *const c_char,
) -> c_int {
    let result = &mut *result;

    if let Some(location) = try_result!(EINVAL, super::cstr_to_str(location)) {
        *result = Ok(DeviceHandlerResult::Redirect(location.to_string()));
    } else {
        throw!(EINVAL, "location cannot be null");
    }

    0
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__device_handler_result__error(
    result: *mut Result<DeviceHandlerResult, Error>,
    error: *const c_char,
) -> c_int {
    let result = &mut *result;

    *result = Err(try_result!(EINVAL, super::cstr_to_error(error)));

    0
}

///
///
/// The function takes ownership of the request.
#[no_mangle]
unsafe extern "C" fn gcdp__client_handler_result__forward(
    result: *mut Result<ClientHandlerResult, Error>,
    device_id: *const c_char,
    request: *mut Request<Body>,
) -> c_int {
    let result = &mut *result;

    if request.is_null() {
        throw!(EINVAL, "request cannot be null");
    }

    if let Some(device_id) = try_result!(EINVAL, super::cstr_to_str(device_id)) {
        let request = Box::from_raw(request);

        *result = Ok(ClientHandlerResult::forward(device_id, *request));
    } else {
        throw!(EINVAL, "device ID cannot be null");
    }

    0
}

///
///
/// The function takes ownership of the response.
#[no_mangle]
unsafe extern "C" fn gcdp__client_handler_result__block(
    result: *mut Result<ClientHandlerResult, Error>,
    response: *mut Response<Body>,
) -> c_int {
    let result = &mut *result;

    if response.is_null() {
        throw!(EINVAL, "response cannot be null");
    }

    let response = Box::from_raw(response);

    *result = Ok(ClientHandlerResult::block(*response));

    0
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__client_handler_result__error(
    result: *mut Result<ClientHandlerResult, Error>,
    error: *const c_char,
) -> c_int {
    let result = &mut *result;

    *result = Err(try_result!(EINVAL, super::cstr_to_error(error)));

    0
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__authorization__get_device_id(
    authorization: *const BasicAuthorization,
    buffer: *mut c_char,
    size: *mut usize,
) {
    let authorization = &*authorization;

    *size = super::str_to_cstr(authorization.username(), buffer, *size);
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__authorization__get_device_key(
    authorization: *const BasicAuthorization,
    buffer: *mut c_char,
    size: *mut usize,
) {
    let authorization = &*authorization;

    *size = super::str_to_cstr(authorization.password(), buffer, *size);
}

///
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
