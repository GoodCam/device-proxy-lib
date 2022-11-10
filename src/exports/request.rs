use std::{
    iter::Peekable,
    os::raw::{c_char, c_int},
    ptr,
};

use hyper::{
    http::header::{HeaderValue, Iter as HeaderIter},
    Body, Method, Request,
};
use libc::EINVAL;

///
type RawHeaderIter<'a> = Peekable<HeaderIter<'a, HeaderValue>>;

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
        *size = super::str_to_cstr(&uri.to_string(), buffer, *size);
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

    let name = if let Some(n) = try_result!(EINVAL, super::cstr_to_str(name)) {
        n
    } else {
        throw!(EINVAL, "header name cannot be null");
    };

    let header = request
        .headers()
        .get(name)
        .map(|val| val.as_bytes())
        .unwrap_or_default();

    *size = super::bstr_to_cstr(header, buffer, *size);

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
extern "C" fn gcdp__request__free(request: *mut Request<Body>) {
    unsafe { super::free(request) }
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

    *size = super::str_to_cstr(name.as_str(), buffer, *size);
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

    *size = super::bstr_to_cstr(value.as_bytes(), buffer, *size);
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

    // drop the iterator if it's been depleted
    unsafe {
        let _ = Box::from_raw(iter);
    }

    ptr::null_mut()
}

///
#[no_mangle]
extern "C" fn gcdp__header_iter__free(iter: *mut RawHeaderIter<'_>) {
    unsafe { super::free(iter) }
}
