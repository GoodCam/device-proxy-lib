use hyper::{Body, Response};

///
fn response_with_body<T>(status: u16, body: T) -> Response<Body>
where
    T: Into<Body>,
{
    Response::builder()
        .status(status)
        .body(body.into())
        .unwrap()
}

/*///
fn error_response<T>(status: u16, error: T) -> Response<Body>
where
    T: ToString,
{
    response_with_body(status, &ErrorResponse::new(error))
}*/

/// Create an empty HTTP response with a given status code.
fn empty_response(status: u16) -> Response<Body> {
    response_with_body(status, Body::empty())
}

/// Create a Temporary Redirect response.
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

/*/// Create a Bad Request response.
pub fn bad_request<T>(msg: T) -> Response<Body>
where
    T: ToString,
{
    error_response(400, msg)
}*/

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

/*///
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl ErrorResponse {
    ///
    fn new<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            error: msg.to_string(),
        }
    }
}

impl From<&ErrorResponse> for Body {
    fn from(response: &ErrorResponse) -> Self {
        let body = serde_json::to_string(response);

        Self::from(body.unwrap())
    }
}*/
