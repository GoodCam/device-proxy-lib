use std::{
    borrow::Cow,
    ffi::{c_void, CStr},
    iter::Peekable,
    net::{IpAddr, SocketAddr},
    os::raw::{c_char, c_int},
    ptr,
    str::Utf8Error,
    sync::Mutex,
};

use hyper::{
    http::header::{HeaderValue, Iter as HeaderIter},
    Body, Method, Request, Response,
};
use libc::EINVAL;

use crate::{
    auth::BasicAuthorization, BlockingRequestHandler, ClientHandlerResult, DeviceHandlerResult,
    Error, ProxyBuilder,
};

///
static LAST_ERROR: Mutex<Cow<'static, str>> = Mutex::new(Cow::Borrowed(""));

///
type RawHeaderIter<'a> = Peekable<HeaderIter<'a, HeaderValue>>;

///
type DeviceHandler = unsafe extern "C" fn(
    context: *mut c_void,
    authorization: *const BasicAuthorization,
    result: *mut Result<DeviceHandlerResult, Error>,
);

///
type ClientHandler = unsafe extern "C" fn(
    context: *mut c_void,
    request: *mut Request<Body>,
    result: *mut Result<ClientHandlerResult, Error>,
);

///
#[derive(Copy, Clone)]
struct RawRequestHandler {
    handle_device: DeviceHandler,
    handle_client: ClientHandler,
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

macro_rules! throw {
    ($code:expr, $msg:expr) => {
        // set the error message
        set_last_error(Cow::from($msg));

        // ... and return the error code
        return $code;
    };
}

macro_rules! try_result {
    ($code:expr, $res:expr) => {
        match $res {
            Ok(ok) => ok,
            Err(err) => {
                // set the error message
                set_last_error(Cow::from(err.to_string()));

                // ... and return the error code
                return $code;
            }
        }
    };
}

///
#[no_mangle]
extern "C" fn gcdp_get_last_error(buffer: *mut c_char, size: *mut usize) {
    let err = LAST_ERROR.lock().unwrap();

    unsafe {
        *size = str_to_cstr(&err, buffer, *size);
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

    if let Some(hostname) = try_result!(EINVAL, cstr_to_str(hostname)) {
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
extern "C" fn gcdp__proxy_config__free(config: *mut ProxyConfig) {
    unsafe {
        Box::from_raw(config);
    }
}

///
#[no_mangle]
extern "C" fn gcdp__proxy__new(config: *const ProxyConfig) -> *mut c_void {
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
            if let Err(err) = builder.tls_identity(key, cert) {
                // set the error message
                set_last_error(Cow::from(err.to_string()));

                // and return null
                return ptr::null_mut();
            }
        }
    }

    // TODO: we need to get the handle immediately
    let proxy = builder.build(config.handler).serve();

    unimplemented!("")
}

///
#[no_mangle]
extern "C" fn gcdp__proxy__stop() {
    // TODO
}

///
#[no_mangle]
extern "C" fn gcdp__proxy__abort() {
    // TODO
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

    if let Some(location) = try_result!(EINVAL, cstr_to_str(location)) {
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

    *result = Err(try_result!(EINVAL, error_cstr_to_error(error)));

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

    let request = Box::from_raw(request);

    if let Some(device_id) = try_result!(EINVAL, cstr_to_str(device_id)) {
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

    *result = Err(try_result!(EINVAL, error_cstr_to_error(error)));

    0
}

///
#[no_mangle]
extern "C" fn gcdp__request__get_method(request: *const Request<Body>) -> *const c_char {
    let request = unsafe { &*request };

    let res: &[u8] = match *request.method() {
        Method::CONNECT => b"CONNECT\0",
        Method::DELETE => b"DELETE\0",
        Method::GET => b"GET\0",
        Method::HEAD => b"HEAD\0",
        Method::OPTIONS => b"OPTIONS\0",
        Method::PATCH => b"PATCH\0",
        Method::POST => b"POST\0",
        Method::PUT => b"PUT\0",
        Method::TRACE => b"TRACE\0",
        _ => return ptr::null(),
    };

    res.as_ptr() as _
}

///
#[no_mangle]
extern "C" fn gcdp__request__get_uri(
    request: *const Request<Body>,
    buffer: *mut c_char,
    size: *mut usize,
) {
    let request = unsafe { &*request };

    let uri = request.uri();

    unsafe {
        *size = str_to_cstr(&uri.to_string(), buffer, *size);
    }
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__request__get_header_value(
    request: *const Request<Body>,
    name: *const c_char,
    buffer: *mut c_char,
    size: *mut usize,
) -> c_int {
    let request = &*request;

    let name = if let Some(n) = try_result!(EINVAL, cstr_to_str(name)) {
        n
    } else {
        throw!(EINVAL, "header name cannot be null");
    };

    let header = request
        .headers()
        .get(name)
        .map(|val| val.as_bytes())
        .unwrap_or_default();

    *size = bstr_to_cstr(header, buffer, *size);

    0
}

///
#[no_mangle]
extern "C" fn gcdp__request__get_header_iter<'a>(
    request: *const Request<Body>,
) -> *mut RawHeaderIter<'a> {
    let request = unsafe { &*request };

    let mut iter = request.headers().iter().peekable();

    let first = iter.peek();

    if first.is_some() {
        Box::into_raw(Box::new(iter))
    } else {
        ptr::null_mut()
    }
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__header_iter__get_name(
    iter: *mut RawHeaderIter<'_>,
    buffer: *mut c_char,
    size: *mut usize,
) {
    let iter = &mut *iter;

    let (name, _) = iter.peek().unwrap_unchecked();

    *size = str_to_cstr(name.as_str(), buffer, *size);
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__header_iter__get_value(
    iter: *mut RawHeaderIter<'_>,
    buffer: *mut c_char,
    size: *mut usize,
) {
    let iter = &mut *iter;

    let (_, value) = iter.peek().unwrap_unchecked();

    *size = bstr_to_cstr(value.as_bytes(), buffer, *size);
}

///
#[no_mangle]
extern "C" fn gcdp__header_iter__next(iter: *mut RawHeaderIter<'_>) -> *mut RawHeaderIter<'_> {
    let iter = unsafe { &mut *iter };

    // remove the first item
    iter.next();

    // and get the next one
    let next = iter.peek();

    if next.is_some() {
        return iter;
    }

    unsafe {
        let _ = Box::from_raw(iter);
    }

    ptr::null_mut()
}

///
#[no_mangle]
extern "C" fn gcdp__header_iter__free(iter: *mut RawHeaderIter<'_>) {
    unsafe {
        let _ = Box::from_raw(iter);
    }
}

///
#[no_mangle]
extern "C" fn gcdp__response__new(status: u16) -> *mut Response<Body> {
    let response = Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap();

    Box::into_raw(Box::new(response))
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__response__add_header(
    response: *mut Response<Body>,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    let response = &mut *response;

    let name = if let Some(n) = try_result!(EINVAL, cstr_to_str(name)) {
        n
    } else {
        throw!(EINVAL, "header name cannot be null");
    };

    let value = if let Some(v) = cstr_to_bstr(value) {
        try_result!(EINVAL, HeaderValue::from_bytes(v))
    } else {
        throw!(EINVAL, "header value cannot be null");
    };

    response.headers_mut().append(name, value);

    0
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__response__set_header(
    response: *mut Response<Body>,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    let response = &mut *response;

    let name = if let Some(n) = try_result!(EINVAL, cstr_to_str(name)) {
        n
    } else {
        throw!(EINVAL, "header name cannot be null");
    };

    let value = if let Some(v) = cstr_to_bstr(value) {
        try_result!(EINVAL, HeaderValue::from_bytes(v))
    } else {
        throw!(EINVAL, "header value cannot be null");
    };

    response.headers_mut().insert(name, value);

    0
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__response__set_body(
    response: *mut Response<Body>,
    body: *const u8,
    size: usize,
) {
    let response = &mut *response;

    let body = std::slice::from_raw_parts(body, size);

    *response.body_mut() = Body::from(body);
}

///
#[no_mangle]
extern "C" fn gcdp__response__free(response: *mut Response<Body>) {
    unsafe {
        Box::from_raw(response);
    }
}

///
unsafe fn raw_addr_to_socket_addr(addr: *const c_char, port: u16) -> Result<SocketAddr, Error> {
    let addr: IpAddr = cstr_to_str(addr)
        .transpose()
        .ok_or_else(|| Error::from_static_msg("address cannot be null"))?
        .ok()
        .map(|addr| addr.parse())
        .and_then(|res| res.ok())
        .ok_or_else(|| Error::from_static_msg("invalid address"))?;

    Ok(SocketAddr::from((addr, port)))
}

///
unsafe fn error_cstr_to_error(error: *const c_char) -> Result<Error, Error> {
    match cstr_to_str(error) {
        Ok(Some(msg)) => Ok(Error::from_msg(msg)),
        Ok(None) => Ok(Error::from_static_msg("unknown error")),
        Err(_) => Err(Error::from_static_msg("invalid error string")),
    }
}

///
unsafe fn cstr_to_bstr<'a>(str: *const c_char) -> Option<&'a [u8]> {
    if str.is_null() {
        None
    } else {
        let res = CStr::from_ptr(str).to_bytes();

        Some(res)
    }
}

///
unsafe fn cstr_to_str<'a>(str: *const c_char) -> Result<Option<&'a str>, Utf8Error> {
    if str.is_null() {
        Ok(None)
    } else {
        CStr::from_ptr(str).to_str().map(Some)
    }
}

///
unsafe fn str_to_cstr(s: &str, buffer: *mut c_char, size: usize) -> usize {
    bstr_to_cstr(s.as_bytes(), buffer, size)
}

///
unsafe fn bstr_to_cstr(s: &[u8], buffer: *mut c_char, size: usize) -> usize {
    if buffer.is_null() || size == 0 {
        return s.len();
    }

    let buffer = std::slice::from_raw_parts_mut(buffer as *mut u8, size);

    let copy = size.min(s.len() + 1) - 1;

    let src = &s[..copy];
    let dst = &mut buffer[..copy];

    dst.copy_from_slice(src);

    dst[copy] = 0;

    s.len()
}

///
fn set_last_error(error: Cow<'static, str>) {
    *LAST_ERROR.lock().unwrap() = error;
}
