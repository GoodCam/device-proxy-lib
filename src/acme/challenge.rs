use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use futures::{
    channel::oneshot::{self, Sender},
    ready, FutureExt,
};
use hyper::{Body, Response};

/// Collection of ACME challenge registrations.
#[derive(Clone)]
pub struct ChallengeRegistrations {
    inner: Arc<Mutex<HashMap<String, ChallengeRegistration>>>,
}

impl ChallengeRegistrations {
    /// Create a new collection.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a given ACME challenge.
    pub fn register(&self, challenge: &Challenge) -> ChallengeAuthorized {
        let token = String::from(challenge.token());

        let (registration, authorized) = ChallengeRegistration::new(challenge.key_authorization());

        self.inner.lock().unwrap().insert(token, registration);

        authorized
    }

    /// Create challenge response for a given challenge token or return `None`
    /// if the token is not known.
    pub fn create_response(&self, token: &str) -> Option<Response<Body>> {
        let mut inner = self.inner.lock().unwrap();

        let registration = inner.get_mut(token)?;

        Some(registration.to_http_response())
    }

    /// Remove a given challenge registration.
    pub fn deregister(&self, token: &str) {
        self.inner.lock().unwrap().remove(token);
    }
}

/// ACME challenge registration.
struct ChallengeRegistration {
    key_authorization: String,
    authorized_tx: Option<Sender<()>>,
}

impl ChallengeRegistration {
    /// Create a new ACME challenge registration.
    fn new<T>(key_authorization: T) -> (Self, ChallengeAuthorized)
    where
        T: ToString,
    {
        let (tx, rx) = oneshot::channel();

        let registration = Self {
            key_authorization: key_authorization.to_string(),
            authorized_tx: Some(tx),
        };

        let authorized = ChallengeAuthorized { rx };

        (registration, authorized)
    }

    /// Construct an HTTP response for this challenge registration.
    #[allow(clippy::wrong_self_convention)]
    fn to_http_response(&mut self) -> Response<Body> {
        let guard = SendGuard {
            tx: self.authorized_tx.take(),
        };

        Response::builder()
            .extension(guard)
            .status(200)
            .header("Content-Type", "application/octet-stream")
            .body(Body::from(self.key_authorization.clone()))
            .unwrap()
    }
}

/// Send guard that will resolve the corresponding [`ChallengeAuthorized`]
/// future when the corresponding response is delivered to the remote ACME
/// service.
struct SendGuard {
    tx: Option<Sender<()>>,
}

impl Drop for SendGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Future that will be resolved once the corresponding ACME challenge was
/// requested by the corresponding ACME service.
pub struct ChallengeAuthorized {
    rx: oneshot::Receiver<()>,
}

impl Future for ChallengeAuthorized {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(self.rx.poll_unpin(cx)) {
            Ok(_) => Poll::Ready(()),
            Err(_) => Poll::Pending,
        }
    }
}

/// ACME challenge.
pub struct Challenge {
    token: String,
    key_authorization: String,
}

impl Challenge {
    /// Create a new ACME challenge.
    pub fn new<T, U>(token: T, key_authorization: U) -> Self
    where
        T: ToString,
        U: ToString,
    {
        Self {
            token: token.to_string(),
            key_authorization: key_authorization.to_string(),
        }
    }

    /// Get the challenge token (i.e. the challenge identification).
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Get the challenge key authorization (i.e. the challenge response).
    pub fn key_authorization(&self) -> &str {
        &self.key_authorization
    }
}
