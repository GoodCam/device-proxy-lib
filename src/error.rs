use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter},
    io,
};

use hyper::{Body, Response};

///
#[derive(Debug)]
pub struct Error {
    msg: Cow<'static, str>,
    cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    /*///
    pub fn new<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            msg: Cow::Owned(msg.to_string()),
            cause: None,
        }
    }*/

    ///
    pub fn from_msg<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            msg: Cow::Owned(msg.to_string()),
            cause: None,
        }
    }

    ///
    pub fn from_static_msg(msg: &'static str) -> Self {
        Self {
            msg: Cow::Borrowed(msg),
            cause: None,
        }
    }

    ///
    pub fn from_cause<C>(cause: C) -> Self
    where
        C: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            msg: Cow::Borrowed(""),
            cause: Some(cause.into()),
        }
    }

    ///
    pub fn from_static_msg_and_cause<C>(msg: &'static str, cause: C) -> Self
    where
        C: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            msg: Cow::Borrowed(msg),
            cause: Some(cause.into()),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.msg.is_empty() {
            if let Some(cause) = self.cause.as_ref() {
                Display::fmt(cause, f)
            } else {
                f.write_str("unknown error")
            }
        } else if let Some(cause) = self.cause.as_ref() {
            write!(f, "{}: {}", self.msg, cause)
        } else {
            f.write_str(&self.msg)
        }
    }
}

impl std::error::Error for Error {}

impl From<h2::Error> for Error {
    fn from(err: h2::Error) -> Self {
        Self::from_cause(err)
    }
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Self {
        Self::from_cause(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::from_static_msg_and_cause("IO", err)
    }
}

impl From<native_tls::Error> for Error {
    fn from(err: native_tls::Error) -> Self {
        Self::from_static_msg_and_cause("TLS", err)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::from_static_msg_and_cause("OpenSSL", err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::from_cause(err)
    }
}

///
pub trait ToResponse {
    ///
    fn to_response(&self) -> Response<Body>;
}

///
#[derive(Debug)]
pub struct HttpError {
    inner: InnerHttpError,
}

impl HttpError {
    ///
    pub fn to_response(&self) -> Option<Response<Body>> {
        if let InnerHttpError::WithResponse(err) = &self.inner {
            Some(err.to_response())
        } else {
            None
        }
    }
}

impl Display for HttpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.inner {
            InnerHttpError::WithResponse(err) => Display::fmt(err, f),
            InnerHttpError::Other(err) => Display::fmt(err, f),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<crate::Error> for HttpError {
    fn from(err: crate::Error) -> Self {
        Self {
            inner: InnerHttpError::Other(Box::new(err)),
        }
    }
}

impl From<hyper::Error> for HttpError {
    fn from(err: hyper::Error) -> Self {
        Self {
            inner: InnerHttpError::Other(Box::new(err)),
        }
    }
}

impl<T> From<T> for HttpError
where
    T: std::error::Error + ToResponse + Send + Sync + 'static,
{
    fn from(err: T) -> Self {
        Self {
            inner: InnerHttpError::WithResponse(Box::new(err)),
        }
    }
}

///
trait ErrorWithResponse: std::error::Error + ToResponse {}

impl<T> ErrorWithResponse for T where T: std::error::Error + ToResponse {}

///
#[derive(Debug)]
enum InnerHttpError {
    WithResponse(Box<dyn ErrorWithResponse + Send + Sync>),
    Other(Box<dyn std::error::Error + Send + Sync>),
}

/*///
#[derive(Debug, Clone)]
pub struct BadRequest {
    msg: Cow<'static, str>,
}

impl BadRequest {
    ///
    pub fn from_static_msg(msg: &'static str) -> Self {
        Self {
            msg: Cow::Borrowed(msg),
        }
    }
}

impl Display for BadRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "bad request: {}", self.msg)
    }
}

impl std::error::Error for BadRequest {}

impl ToResponse for BadRequest {
    fn to_response(&self) -> Response<Body> {
        crate::response::bad_request(&self.msg)
    }
}*/

///
#[derive(Debug, Copy, Clone)]
pub struct Unauthorized;

impl Display for Unauthorized {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("unauthorized")
    }
}

impl std::error::Error for Unauthorized {}

impl ToResponse for Unauthorized {
    fn to_response(&self) -> Response<Body> {
        crate::response::unauthorized()
    }
}

///
#[derive(Debug, Copy, Clone)]
pub struct BadGateway;

impl Display for BadGateway {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("bad gateway")
    }
}

impl std::error::Error for BadGateway {}

impl ToResponse for BadGateway {
    fn to_response(&self) -> Response<Body> {
        crate::response::bad_gateway()
    }
}
