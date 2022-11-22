use std::os::raw::{c_char, c_int};

use hyper::{http::header::HeaderValue, Body, Response};
use libc::EINVAL;

/// Create a new HTTP response with a given status code.
#[no_mangle]
extern "C" fn gcdp__response__new(status: u16) -> *mut Response<Body> {
    let response = Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap();

    Box::into_raw(Box::new(response))
}

/// Add a given HTTP header field to the response.
#[no_mangle]
unsafe extern "C" fn gcdp__response__add_header(
    response: *mut Response<Body>,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    let response = &mut *response;

    let name = if let Some(n) = try_result!(EINVAL, super::cstr_to_str(name)) {
        n
    } else {
        throw!(EINVAL, "header name cannot be null");
    };

    let value = if let Some(v) = super::cstr_to_bstr(value) {
        try_result!(EINVAL, HeaderValue::from_bytes(v))
    } else {
        throw!(EINVAL, "header value cannot be null");
    };

    response.headers_mut().append(name, value);

    0
}

/// Replace all header fields with a given name (ignoring case).
#[no_mangle]
unsafe extern "C" fn gcdp__response__set_header(
    response: *mut Response<Body>,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    let response = &mut *response;

    let name = if let Some(n) = try_result!(EINVAL, super::cstr_to_str(name)) {
        n
    } else {
        throw!(EINVAL, "header name cannot be null");
    };

    let value = if let Some(v) = super::cstr_to_bstr(value) {
        try_result!(EINVAL, HeaderValue::from_bytes(v))
    } else {
        throw!(EINVAL, "header value cannot be null");
    };

    response.headers_mut().insert(name, value);

    0
}

/// Set the response body.
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

/// Free the response.
#[no_mangle]
extern "C" fn gcdp__response__free(response: *mut Response<Body>) {
    unsafe { super::free(response) }
}
