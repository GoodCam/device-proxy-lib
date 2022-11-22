//! Helpers for constructing HTTP responses.

use hyper::{Body, Response};

/// Create a new HTTP response with a given status code and body.
fn response_with_body<T>(status: u16, body: T) -> Response<Body>
where
    T: Into<Body>,
{
    Response::builder()
        .status(status)
        .body(body.into())
        .unwrap()
}

/// Create an empty HTTP response with a given status code.
fn empty_response(status: u16) -> Response<Body> {
    response_with_body(status, Body::empty())
}

/// Create a Temporary Redirect response with a given location header.
pub fn temporary_redirect<T>(location: T) -> Response<Body>
where
    T: ToString,
{
    Response::builder()
        .status(307)
        .header("Location", location.to_string())
        .body(Body::empty())
        .unwrap()
}

/// Create an Unauthorized response.
pub fn unauthorized() -> Response<Body> {
    empty_response(401)
}

/// Create an Internal Server Error response.
pub fn internal_server_error() -> Response<Body> {
    empty_response(500)
}

/// Create a Bad Gateway response.
pub fn bad_gateway() -> Response<Body> {
    empty_response(502)
}
