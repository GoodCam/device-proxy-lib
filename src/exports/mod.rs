#[macro_use]
mod macros;

mod log;
mod proxy;
mod request;
mod response;

use std::{
    borrow::Cow,
    ffi::CStr,
    os::raw::{c_char, c_int},
    str::Utf8Error,
    sync::Mutex,
};

use crate::Error;

///
static LAST_ERROR: Mutex<(c_int, Option<Cow<'static, str>>)> = Mutex::new((0, None));

///
#[no_mangle]
extern "C" fn gcdp__version__major() -> c_int {
    env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap()
}

///
#[no_mangle]
extern "C" fn gcdp__version__minor() -> c_int {
    env!("CARGO_PKG_VERSION_MINOR").parse().unwrap()
}

///
#[no_mangle]
extern "C" fn gcdp__version__micro() -> c_int {
    env!("CARGO_PKG_VERSION_PATCH").parse().unwrap()
}

///
#[no_mangle]
extern "C" fn gcdp_get_last_error(buffer: *mut c_char, size: *mut usize) -> c_int {
    let err = LAST_ERROR.lock().unwrap();

    let (code, msg) = &*err;

    if *code == 0 {
        return 0;
    }

    let msg = msg.as_deref().unwrap_or_default();

    if !size.is_null() {
        unsafe {
            *size = str_to_cstr(msg, buffer, *size);
        }
    }

    *code
}

///
fn set_last_error(code: c_int, error: Cow<'static, str>) {
    *LAST_ERROR.lock().unwrap() = (code, Some(error));
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
unsafe fn cstr_to_error(error: *const c_char) -> Result<Error, Error> {
    match cstr_to_str(error) {
        Ok(Some(msg)) => Ok(Error::from_msg(msg)),
        Ok(None) => Ok(Error::from_static_msg("unknown error")),
        Err(_) => Err(Error::from_static_msg("invalid error string")),
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

    buffer[copy] = 0;

    s.len()
}

///
unsafe fn free<T>(object: *mut T) {
    if !object.is_null() {
        Box::from_raw(object);
    }
}
