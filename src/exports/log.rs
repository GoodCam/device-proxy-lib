use std::{
    ffi::c_void,
    os::raw::{c_char, c_int},
};

use log::{Level, LevelFilter, Log, Metadata, Record};

///
type RawLogHandlerFn = unsafe extern "C" fn(context: *mut c_void, request: *const Record);

///
struct Logger {
    context: *mut c_void,
    handler: RawLogHandlerFn,
}

impl Log for Logger {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn flush(&self) {}

    fn log(&self, record: &Record) {
        unsafe { (self.handler)(self.context, record) }
    }
}

unsafe impl Send for Logger {}
unsafe impl Sync for Logger {}

///
#[no_mangle]
extern "C" fn gcdp_set_logger(handler: RawLogHandlerFn, context: *mut c_void) -> c_int {
    let logger = Logger { context, handler };

    try_result!(libc::EALREADY, log::set_boxed_logger(Box::new(logger)));

    log::set_max_level(LevelFilter::Debug);

    0
}

///
#[no_mangle]
extern "C" fn gcdp__log_record__get_level(record: *const Record) -> c_int {
    let record = unsafe { &*record };

    match record.level() {
        Level::Trace => 0,
        Level::Debug => 1,
        Level::Info => 2,
        Level::Warn => 3,
        Level::Error => 4,
    }
}

///
#[no_mangle]
unsafe extern "C" fn gcdp__log_record__get_message(
    record: *const Record,
    buffer: *mut c_char,
    size: *mut usize,
) {
    let record = &*record;

    let args = record.args();

    if let Some(msg) = args.as_str() {
        *size = super::str_to_cstr(msg, buffer, *size);
    } else {
        *size = super::str_to_cstr(&args.to_string(), buffer, *size);
    }
}
