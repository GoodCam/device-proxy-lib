use std::{
    future::Future,
    io,
    sync::{Arc, Mutex},
};

use native_tls::Identity;
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{HasPrivate, HasPublic, PKey, PKeyRef, Private},
    x509::{X509NameBuilder, X509ReqBuilder},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_native_tls::TlsStream;

use crate::{
    acme::{self, Account},
    Error,
};

/// TLS mode.
pub enum TlsMode {
    None,
    Simple(Identity),
    LetsEncrypt,
}

impl TlsMode {
    /// Create a new ACME account.
    ///
    /// The method will create a new ACME account only if the TLS mode is set
    /// to `LetsEncrypt`. In all other cases it will return `Ok(None)`.
    pub async fn create_acme_account(&self) -> Result<Option<Account>, Error> {
        if matches!(self, Self::LetsEncrypt) {
            let account = acme::Client::new()
                .await?
                .open_directory(acme::LETS_ENCRYPT_DIRECTORY)
                .await?
                .new_account(None)
                .await?;

            Ok(Some(account))
        } else {
            Ok(None)
        }
    }

    /// Create a new TLS acceptor.
    ///
    /// The method will create a new TLS acceptor only if the TLS mode is set
    /// to `Simple(_)` or `LetsEncrypt`. In all other cases it will return
    /// `Ok(None)`.
    ///
    /// If the TLS mode is set to `LetsEncrypt` the returned acceptor will be
    /// a dummy rejecting all incoming connections. The acceptor must be later
    /// updated using an ACME account to accept incoming TLS connections.
    pub fn create_tls_acceptor(&self) -> Result<Option<TlsAcceptor>, Error> {
        match self {
            Self::None => Ok(None),
            Self::Simple(identity) => {
                let acceptor = TlsAcceptor::new(identity.clone())?;

                Ok(Some(acceptor))
            }
            Self::LetsEncrypt => Ok(Some(TlsAcceptor::dummy())),
        }
    }
}

/// TLS acceptor.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<Mutex<Option<Arc<tokio_native_tls::TlsAcceptor>>>>,
}

impl TlsAcceptor {
    /// Create a new acceptor dummy.
    ///
    /// The acceptor will reject all incoming connections.
    pub fn dummy() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a new TLS acceptor with a given TLS identity.
    pub fn new(identity: Identity) -> Result<Self, Error> {
        let acceptor = native_tls::TlsAcceptor::new(identity)?;

        let res = Self {
            inner: Arc::new(Mutex::new(Some(Arc::new(acceptor.into())))),
        };

        Ok(res)
    }

    /// Set the TLS acceptor identity.
    pub fn set_identity(&self, identity: Identity) -> Result<(), Error> {
        let acceptor = native_tls::TlsAcceptor::new(identity)?;

        let mut inner = self.inner.lock().unwrap();

        *inner = Some(Arc::new(acceptor.into()));

        Ok(())
    }

    /// Accept a given incoming connection.
    pub fn accept<S>(&self, stream: S) -> impl Future<Output = io::Result<TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let acceptor = self.inner.lock().unwrap().clone();

        async move {
            acceptor
                .ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionRefused))?
                .accept(stream)
                .await
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        }
    }
}

/// Generate a new TLS key.
pub fn generate_tls_key() -> Result<PKey<Private>, Error> {
    let ec_group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let ec_key = EcKey::generate(&ec_group)?;
    let key = PKey::from_ec_key(ec_key)?;

    Ok(key)
}

/// Create a new CSR for a given key.
pub fn create_csr<T>(key: &PKeyRef<T>, hostname: &str) -> Result<Vec<u8>, Error>
where
    T: HasPrivate + HasPublic,
{
    let mut subject_name_builder = X509NameBuilder::new()?;

    subject_name_builder.append_entry_by_nid(Nid::COMMONNAME, hostname)?;

    let subject_name = subject_name_builder.build();

    let mut csr_builder = X509ReqBuilder::new()?;

    csr_builder.set_version(1)?;
    csr_builder.set_subject_name(&subject_name)?;
    csr_builder.set_pubkey(key)?;

    csr_builder.sign(key, MessageDigest::sha256())?;

    let res = csr_builder.build().to_der()?;

    Ok(res)
}
