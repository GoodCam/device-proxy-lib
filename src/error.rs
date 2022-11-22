use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter},
    io,
};

use hyper::{Body, Response};

/// Error type.
#[derive(Debug)]
pub struct Error {
    msg: Cow<'static, str>,
    cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    /// Create a new error with a given error message.
    pub fn from_msg<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            msg: Cow::Owned(msg.to_string()),
            cause: None,
        }
    }

    /// Create a new error with a given error message.
    pub fn from_static_msg(msg: &'static str) -> Self {
        Self {
            msg: Cow::Borrowed(msg),
            cause: None,
        }
    }

    /// Create a new error from a given cause.
    pub fn from_cause<C>(cause: C) -> Self
    where
        C: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            msg: Cow::Borrowed(""),
            cause: Some(cause.into()),
        }
    }

    /// Create a new error with a given error message and cause.
    pub fn from_msg_and_cause<T, C>(msg: T, cause: C) -> Self
    where
        T: ToString,
        C: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            msg: Cow::Owned(msg.to_string()),
            cause: Some(cause.into()),
        }
    }

    /// Create a new error with a given error message and cause.
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

/// Helper trait for transforming objects into HTTP responses.
pub trait ToResponse {
    /// Create an HTTP response.
    fn to_response(&self) -> Response<Body>;
}

/// Error that can be converted into an HTTP response.
#[derive(Debug)]
pub struct HttpError {
    inner: InnerHttpError,
}

impl HttpError {
    /// Create an HTTP response (if possible).
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

/// Helper trait.
trait ErrorWithResponse: std::error::Error + ToResponse {}

impl<T> ErrorWithResponse for T where T: std::error::Error + ToResponse {}

/// HTTP error variants.
#[derive(Debug)]
enum InnerHttpError {
    WithResponse(Box<dyn ErrorWithResponse + Send + Sync>),
    Other(Box<dyn std::error::Error + Send + Sync>),
}

/// Unauthorized access error.
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

/// Bad gateway error.
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
