//! Authorization types.

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

/// Invalid authorization header.
#[derive(Debug, Copy, Clone)]
pub struct InvalidAuthorizationHeader;

impl Display for InvalidAuthorizationHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("invalid authorization header")
    }
}

impl Error for InvalidAuthorizationHeader {}

/// Basic authorization header.
pub struct BasicAuthorization {
    username: String,
    password: String,
}

impl BasicAuthorization {
    /// Create a new Basic authorization header containing a given username and
    /// password.
    pub fn new<T, U>(username: T, password: U) -> Self
    where
        T: ToString,
        U: ToString,
    {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// Get the username.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the password.
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl FromStr for BasicAuthorization {
    type Err = InvalidAuthorizationHeader;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let whitespace = s.find(|c: char| c.is_ascii_whitespace()).unwrap_or(0);

        let (auth_type, rest) = s.split_at(whitespace);

        if !auth_type.eq_ignore_ascii_case("basic") {
            return Err(InvalidAuthorizationHeader);
        }

        let credentials = base64::decode(rest.trim())
            .ok()
            .map(String::from_utf8)
            .and_then(|res| res.ok())
            .ok_or(InvalidAuthorizationHeader)?;

        let colon = credentials.find(':').ok_or(InvalidAuthorizationHeader)?;

        let (username, rest) = credentials.split_at(colon);

        let password = &rest[1..];

        Ok(Self::new(username, password))
    }
}
