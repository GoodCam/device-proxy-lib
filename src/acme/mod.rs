mod challenge;
mod client;
mod jws;
mod utils;
mod watchdog;

use std::{future::Future, time::Duration};

use bytes::Bytes;
use serde::Deserialize;

use self::{
    client::{AccountClient, DirectoryClient, HeaderMapExt},
    jws::Key,
};

use crate::Error;

pub use self::{
    challenge::{Challenge, ChallengeAuthorized, ChallengeRegistrations},
    client::Client,
    watchdog::Watchdog,
};

//pub const LETS_ENCRYPT_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

///
#[derive(Clone)]
pub struct Directory {
    client: DirectoryClient,
    new_account_url: String,
    new_order_url: String,
}

impl Directory {
    ///
    pub async fn new_account(&self, contact: Option<&str>) -> Result<Account, Error> {
        let mut contacts = Vec::new();

        if let Some(c) = contact {
            contacts.push(c);
        }

        let payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": contacts,
        });

        let response = self.client.post(&self.new_account_url, &payload).await?;

        response.error_for_status()?;

        let account_url = response
            .headers()
            .location()?
            .ok_or_else(|| Error::from_static_msg("missing account URL"))?;

        let account = response.parse_json::<NewAccountResponse>()?;

        if account.status != "valid" {
            return Err(Error::from_msg(format!(
                "ACME account status: {}",
                account.status
            )));
        }

        let res = Account {
            client: self.client.to_account_client(account_url),
            new_order_url: self.new_order_url.clone(),
        };

        Ok(res)
    }
}

///
#[derive(Clone)]
pub struct Account {
    client: AccountClient,
    new_order_url: String,
}

impl Account {
    ///
    pub async fn new_order(&self, hostname: &str) -> Result<Order, Error> {
        let payload = serde_json::json!({
            "identifiers": [
                {
                    "type": "dns",
                    "value": hostname,
                },
            ],
        });

        let response = self.client.post(&self.new_order_url, &payload).await?;

        response.error_for_status()?;

        let order_url = response
            .headers()
            .location()?
            .ok_or_else(|| Error::from_static_msg("missing order URL"))?
            .to_string();

        let response = response.parse_json::<NewOrderResponse>()?;

        let authorization_url =
            response.authorizations.into_iter().next().ok_or_else(|| {
                Error::from_static_msg("no authorizations in the new-order response")
            })?;

        let authorization = self.get_authorization(&authorization_url).await?;

        let challenge = authorization
            .challenges
            .into_iter()
            .find(|c| c.kind == "http-01")
            .ok_or_else(|| Error::from_static_msg("no HTTP challenge"))?;

        let identity = self.client.identity();

        let key_authorization = format!("{}.{}", challenge.token, identity.thumbprint());

        let http_challenge = Challenge::new(challenge.token, key_authorization);

        let res = Order {
            http_challenge,
            order_url,
            authorization_url,
            challenge_url: challenge.url,
            finalize_url: response.finalize,
        };

        Ok(res)
    }

    ///
    pub async fn close_order<F>(
        &self,
        order: &Order,
        authorized: F,
        csr: &[u8],
    ) -> Result<Bytes, Error>
    where
        F: Future<Output = ()>,
    {
        self.confirm_http_challenge(&order.challenge_url).await?;

        // we need to wait until Let's Encrypt requests the challenge endpoint
        authorized.await;

        // ... and then we need to poll the authorization endpoint until the
        // authorization becomes valid
        loop {
            let authorization = self.get_authorization(&order.authorization_url).await?;

            match authorization.status.as_str() {
                "pending" => (),
                "valid" => break,
                _ => return Err(Error::from_static_msg("invalid authorization")),
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        self.finalize_order(order, csr).await
    }

    ///
    async fn get_authorization(
        &self,
        authorization_url: &str,
    ) -> Result<AuthorizationResponse, Error> {
        let response = self.client.get(authorization_url).await?;

        response.error_for_status()?;

        let response = response.parse_json::<AuthorizationResponse>()?;

        Ok(response)
    }

    ///
    async fn confirm_http_challenge(&self, challenge_url: &str) -> Result<(), Error> {
        let payload = serde_json::json!({});

        let response = self.client.post(challenge_url, &payload).await?;

        response.error_for_status()?;

        Ok(())
    }

    ///
    async fn finalize_order(&self, order: &Order, csr: &[u8]) -> Result<Bytes, Error> {
        let payload = serde_json::json!({
            "csr": utils::base64url(csr),
        });

        let mut response = self.client.post(&order.finalize_url, &payload).await?;

        response.error_for_status()?;

        let mut order_status;

        loop {
            order_status = response.parse_json::<OrderStatusResponse>()?;

            match order_status.status {
                "processing" => (),
                "valid" => break,
                _ => return Err(Error::from_static_msg("invalid order")),
            }

            let r = self.client.get(&order.order_url).await?;

            r.error_for_status()?;

            response = r;
        }

        let certificate_url = order_status
            .certificate
            .ok_or_else(|| Error::from_static_msg("missing certificate URL"))?;

        self.download_certificate(certificate_url).await
    }

    ///
    async fn download_certificate(&self, certificate_url: &str) -> Result<Bytes, Error> {
        let response = self.client.get(certificate_url).await?;

        response.error_for_status()?;

        let body = response.body();

        Ok(body.clone())
    }
}

///
pub struct Order {
    http_challenge: Challenge,
    order_url: String,
    authorization_url: String,
    challenge_url: String,
    finalize_url: String,
}

impl Order {
    ///
    pub fn challenge(&self) -> &Challenge {
        &self.http_challenge
    }
}

///
#[derive(Deserialize)]
struct NewAccountResponse<'a> {
    status: &'a str,
}

///
#[derive(Deserialize)]
struct NewOrderResponse {
    authorizations: Vec<String>,
    finalize: String,
}

///
#[derive(Deserialize)]
struct OrderStatusResponse<'a> {
    status: &'a str,
    #[serde(default)]
    certificate: Option<&'a str>,
}

///
#[derive(Deserialize)]
struct AuthorizationResponse {
    status: String,
    challenges: Vec<ChallengeEntry>,
}

///
#[derive(Deserialize)]
struct ChallengeEntry {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    token: String,
}
