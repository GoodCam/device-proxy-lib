use std::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use futures::FutureExt;
use h2::ext::Protocol;
use http::uri::{Authority, Scheme, Uri};
use hyper::{HeaderMap, Method, Request, Version};
use tokio::task::{JoinError, JoinHandle};

use crate::binding::ConnectionInfo;

/// Request extensions/helpers.
pub trait RequestExt {
    /// Check if this is a device request.
    fn is_device_request(&self) -> bool;

    /// Get ACME challenge token (if this is an AMC challenge request).
    fn get_acme_challenge_token(&self) -> Option<&str>;

    /// Get complete URL including scheme and authority.
    fn get_url(&self) -> Uri;

    /// Create a corresponding HTTP2 request that can be forwarded to a device.
    fn to_h2_request(&self) -> Request<()>;
}

impl<T> RequestExt for Request<T> {
    fn is_device_request(&self) -> bool {
        let uri = self.uri();
        let headers = self.headers();

        let path = uri.path();

        let is_upgrade = headers.is_connection_upgrade();

        let is_gc_device_upgrade = headers
            .as_ext()
            .get_all_tokens("upgrade")
            .any(|token| token.eq_ignore_ascii_case("goodcam-device-proxy"));

        self.version() == Version::HTTP_11
            && self.method() == Method::GET
            && path == "/"
            && is_upgrade
            && is_gc_device_upgrade
    }

    fn get_acme_challenge_token(&self) -> Option<&str> {
        let uri = self.uri();

        let path = uri.path();

        path.strip_prefix("/.well-known/acme-challenge/")
    }

    fn get_url(&self) -> Uri {
        let headers = self.headers();
        let extensions = self.extensions();

        let mut uri = self.uri().clone().into_parts();

        if uri.scheme.is_none() {
            let scheme = if let Some(info) = extensions.get::<ConnectionInfo>() {
                if info.is_https() {
                    Scheme::HTTPS
                } else {
                    Scheme::HTTP
                }
            } else {
                Scheme::HTTP
            };

            uri.scheme = Some(scheme);
        }

        if uri.authority.is_none() {
            if let Some(host) = headers.get("host") {
                uri.authority = Result::ok(Authority::try_from(host.as_bytes()));
            }
        }

        if uri.authority.is_none() {
            if let Some(info) = extensions.get::<ConnectionInfo>() {
                let remote_addr = info.remote_addr();
                let authority = Authority::try_from(remote_addr.to_string())
                    .unwrap_or_else(|_| Authority::from_static("localhost"));

                uri.authority = Some(authority);
            } else {
                uri.authority = Some(Authority::from_static("localhost"));
            }
        }

        Uri::from_parts(uri).expect("invalid URL")
    }

    fn to_h2_request(&self) -> Request<()> {
        let mut builder = Request::builder()
            .version(Version::HTTP_2)
            .uri(self.get_url());

        let extensions = self.extensions();
        let headers = self.headers();

        // forward protocol extension (if present)
        if let Some(protocol) = extensions.get::<Protocol>() {
            builder = builder.extension(protocol.clone());
        }

        let mut new_headers = headers.clone();

        // translate connection upgrade to HTTP2
        if headers.is_connection_upgrade() {
            builder = builder.method(Method::CONNECT);

            let protocol: Protocol = headers
                .get("upgrade")
                .map(|val| val.to_str())
                .and_then(|res| res.ok())
                .unwrap_or("")
                .into();

            builder = builder.extension(protocol);
        } else {
            builder = builder.method(self.method());
        }

        // remove hop-by-hop headers
        new_headers.remove_hop_by_hop_headers();

        // remove non-h2 headers
        new_headers.remove("host");

        let mut res = builder.body(()).unwrap();

        *res.headers_mut() = new_headers;

        res
    }
}

/// Helper for extending the `HeaderMap`.
pub trait HeaderMapExt {
    /// Get the extended header map.
    fn as_ext(&self) -> ExtHeaderMap;

    /// Check if this is a connection upgrade.
    fn is_connection_upgrade(&self) -> bool;

    /// Remove all hop-by-hop headers.
    fn remove_hop_by_hop_headers(&mut self);
}

impl HeaderMapExt for HeaderMap {
    fn as_ext(&self) -> ExtHeaderMap {
        ExtHeaderMap { inner: self }
    }

    fn is_connection_upgrade(&self) -> bool {
        self.as_ext()
            .get_all_tokens("connection")
            .any(|token| token.eq_ignore_ascii_case("upgrade"))
    }

    fn remove_hop_by_hop_headers(&mut self) {
        let connection_options = self
            .as_ext()
            .get_all_tokens("connection")
            .map(|option| option.to_string())
            .collect::<Vec<_>>();

        for option in connection_options {
            self.remove(&option);
        }

        self.remove("connection");
        self.remove("proxy-connection");
        self.remove("keep-alive");
        self.remove("te");
        self.remove("transfer-encoding");
        self.remove("upgrade");
    }
}

/// Private helpers/extensions of the `HeaderMap`.
pub struct ExtHeaderMap<'a> {
    inner: &'a HeaderMap,
}

impl<'a> ExtHeaderMap<'a> {
    /// Get iterator over tokens from a given field.
    ///
    /// The field is expected to contain a list of tokens.
    pub fn get_all_tokens(&self, name: &str) -> impl Iterator<Item = &str> {
        self.inner.get_all(name).into_iter().flat_map(|header| {
            header
                .to_str()
                .unwrap_or("")
                .split(',')
                .map(|token| token.trim())
                .filter(|token| !token.is_empty())
        })
    }
}

impl<'a> Deref for ExtHeaderMap<'a> {
    type Target = HeaderMap;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

/// Task join handle that will abort the task when dropped.
pub struct AbortOnDrop<T> {
    inner: JoinHandle<T>,
}

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_unpin(cx)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.inner.abort();
    }
}

impl<T> Deref for AbortOnDrop<T> {
    type Target = JoinHandle<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for AbortOnDrop<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> From<JoinHandle<T>> for AbortOnDrop<T> {
    fn from(handle: JoinHandle<T>) -> Self {
        Self { inner: handle }
    }
}
