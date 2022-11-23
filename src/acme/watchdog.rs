use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use native_tls::Identity;
use openssl::{
    asn1::Asn1Time,
    pkey::{PKey, Private},
    x509::X509,
};

use crate::{
    acme::{Account, ChallengeRegistrations},
    error::Error,
    tls::{self, TlsAcceptor},
};

/// ACME watchdog that will keep the given TLS identity up to date.
pub struct Watchdog {
    key: Arc<PKey<Private>>,
    key_pem: Vec<u8>,
    account: Account,
    challenges: ChallengeRegistrations,
    tls_acceptor: TlsAcceptor,
    hostname: String,
}

impl Watchdog {
    /// Create a new watchdog.
    pub async fn new<T>(
        account: Account,
        challenges: ChallengeRegistrations,
        tls_acceptor: TlsAcceptor,
        hostname: T,
    ) -> Result<Self, Error>
    where
        T: ToString,
    {
        let key: Arc<PKey<Private>> = tokio::task::spawn_blocking(tls::generate_tls_key)
            .await
            .map_err(|_| Error::from_static_msg("terminating"))??
            .into();

        let key_pem = key.private_key_to_pem_pkcs8()?;

        let res = Self {
            key,
            key_pem,
            account,
            challenges,
            tls_acceptor,
            hostname: hostname.to_string(),
        };

        Ok(res)
    }

    /// Run the watchdog.
    pub async fn watch(self) {
        loop {
            info!("renewing TLS certificate");

            let res = self.renew_certificate().await;

            if let Err(err) = &res {
                warn!("unable to renew TLS certificate: {err}");
            } else {
                info!("TLS certificate renewed");
            }

            let delay = res
                .map(|expires_in| expires_in * 2 / 3)
                .unwrap_or_else(|_| Duration::from_secs(10));

            info!("next TLS certificate renew in {:?}", delay);

            let start = Instant::now();

            loop {
                let elapsed = start.elapsed();

                if delay <= elapsed {
                    break;
                }

                let remaining = delay - elapsed;

                // sleep at most one hour at a time to avoid timer overflow
                tokio::time::sleep(remaining.min(Duration::from_secs(3_600))).await;
            }
        }
    }

    /// Renew the TLS certificate.
    async fn renew_certificate(&self) -> Result<Duration, Error> {
        let chain = self.get_new_certificate().await?;

        let identity = Identity::from_pkcs8(&chain, &self.key_pem)?;

        self.tls_acceptor.set_identity(identity)?;

        let stack = X509::stack_from_pem(&chain)?;

        let cert = stack
            .first()
            .ok_or_else(|| Error::from_static_msg("no certificate in the chain"))?;

        let expires_in = Asn1Time::days_from_now(0)
            .and_then(|now| now.diff(cert.not_after()))
            .map(|diff| (diff.days as i64) * 86_400 + (diff.secs as i64))?;

        if expires_in > 0 {
            Ok(Duration::from_secs(expires_in as u64))
        } else {
            Err(Error::from_static_msg("received expired certificate"))
        }
    }

    /// Get a new TLS certificate.
    async fn get_new_certificate(&self) -> Result<Bytes, Error> {
        let order = self.account.new_order(&self.hostname).await?;

        let challenge = order.challenge();

        let authorized = self.challenges.register(challenge);

        let guard = ChallengeRegistrationGuard {
            challenges: &self.challenges,
            token: challenge.token(),
        };

        let key = self.key.clone();
        let hostname = self.hostname.clone();

        let blocking = tokio::task::spawn_blocking(move || tls::create_csr(&key, &hostname));

        let csr = blocking
            .await
            .map_err(|_| Error::from_static_msg("terminating"))??;

        let cert = self.account.close_order(&order, authorized, &csr).await?;

        std::mem::drop(guard);

        Ok(cert)
    }
}

/// Helper struct that will remove a given registration when dropped.
struct ChallengeRegistrationGuard<'a> {
    challenges: &'a ChallengeRegistrations,
    token: &'a str,
}

impl<'a> Drop for ChallengeRegistrationGuard<'a> {
    fn drop(&mut self) {
        self.challenges.deregister(self.token);
    }
}
