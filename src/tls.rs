use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
};

use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{HasPrivate, HasPublic, PKey, PKeyRef, Private},
    ssl::{Ssl, SslAcceptor, SslMethod, SslSessionCacheMode, SslVersion},
    x509::{X509NameBuilder, X509ReqBuilder, X509},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_openssl::SslStream;

use crate::{
    acme::{self, Account},
    Error,
};

/// TLS identity.
#[derive(Clone)]
pub struct Identity {
    key: PKey<Private>,
    cert: X509,
    chain: Vec<X509>,
}

impl Identity {
    /// Create a new TLS identity.
    pub fn from_pkcs8(chain: &[u8], key: &[u8]) -> Result<Self, Error> {
        let key = PKey::private_key_from_pem(key)?;
        let chain = X509::stack_from_pem(chain)?;

        let mut chain = chain.into_iter();

        let cert = chain
            .next()
            .ok_or_else(|| Error::from_static_msg("empty certificate chain"))?;

        let res = Self {
            key,
            cert,
            chain: chain.collect(),
        };

        Ok(res)
    }
}

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
                .await
                .map_err(|err| {
                    Error::from_static_msg_and_cause(
                        "unable to open the Let's Encrypt directory",
                        err,
                    )
                })?
                .new_account(None)
                .await
                .map_err(|err| {
                    Error::from_static_msg_and_cause(
                        "unable to create a Let's Encrypt account",
                        err,
                    )
                })?;

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
    inner: Arc<Mutex<Option<SslAcceptor>>>,
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
        let res = Self::dummy();

        res.set_identity(identity)?;

        Ok(res)
    }

    /// Set the TLS acceptor identity.
    pub fn set_identity(&self, identity: Identity) -> Result<(), Error> {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;

        builder.set_session_cache_mode(SslSessionCacheMode::OFF);
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_private_key(&identity.key)?;
        builder.set_certificate(&identity.cert)?;

        for cert in identity.chain.iter() {
            builder.add_extra_chain_cert(cert.to_owned())?;
        }

        let acceptor = builder.build();

        let mut inner = self.inner.lock().unwrap();

        *inner = Some(acceptor);

        Ok(())
    }

    /// Accept a given incoming connection.
    pub fn accept<S>(&self, stream: S) -> impl Future<Output = io::Result<TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let acceptor = self.inner.lock().unwrap().clone();

        async move {
            let acceptor =
                acceptor.ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionRefused))?;

            let mut stream = Ssl::new(acceptor.context())
                .and_then(|ssl| SslStream::new(ssl, stream))
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            SslStream::accept(Pin::new(&mut stream))
                .await
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            Ok(stream)
        }
    }
}

/// Type alias.
pub type TlsStream<T> = SslStream<T>;

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
