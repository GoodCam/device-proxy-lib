use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::{Hasher, MessageDigest},
    nid::Nid,
    pkey::Private,
};
use serde::{Serialize, Serializer};

use crate::{acme::utils, Error};

/// JSON Web Key.
pub trait Key {
    /// Get name of the algorithm.
    fn algorithm(&self) -> &str;

    /// Get key parameters.
    fn params(&self) -> &Params;

    /// Get key thumbprint.
    fn thumbprint(&self) -> &str;

    /// Sign a given JWS header and payload.
    fn sign(&self, header: &str, payload: &str) -> Result<Vec<u8>, Error>;
}

/// JWK parameters.
#[derive(Serialize)]
pub struct Params {
    #[serde(flatten)]
    internal: InternalParams,
}

impl Params {
    /// Create new parameters.
    fn new(internal: InternalParams) -> Self {
        Self { internal }
    }
}

/// Internal JWK parameters.
#[derive(Serialize)]
#[serde(tag = "kty")]
enum InternalParams {
    #[serde(rename = "EC")]
    EllipticCurve(EllipticCurveParams),
}

impl From<EllipticCurveParams> for InternalParams {
    fn from(params: EllipticCurveParams) -> Self {
        Self::EllipticCurve(params)
    }
}

/// EC parameters.
#[derive(Clone, Serialize)]
pub struct EllipticCurveParams {
    crv: &'static str,
    x: String,
    y: String,
}

/// ECDSA key using P-256 and SHA-256.
pub struct ES256 {
    key: EcKey<Private>,
    params: Params,
    thumbprint: String,
}

impl ES256 {
    /// Generate a new key.
    pub fn new() -> Result<Self, Error> {
        let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&ec_group)?;

        let mut bn_context = BigNumContext::new()?;

        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;

        let pub_key = ec_key.public_key();

        pub_key.affine_coordinates(&ec_group, &mut x, &mut y, &mut bn_context)?;

        let params = EllipticCurveParams {
            crv: "P-256",
            x: utils::base64url(&x.to_vec()),
            y: utils::base64url(&y.to_vec()),
        };

        let thumbprint = format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            params.crv, params.x, params.y
        );

        let mut hasher = Hasher::new(MessageDigest::sha256())?;

        hasher.update(thumbprint.as_bytes())?;

        let thumbprint = hasher.finish()?;

        let res = Self {
            key: ec_key,
            params: Params::new(params.into()),
            thumbprint: utils::base64url(&thumbprint),
        };

        Ok(res)
    }
}

impl Key for ES256 {
    fn algorithm(&self) -> &str {
        "ES256"
    }

    fn params(&self) -> &Params {
        &self.params
    }

    fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    fn sign(&self, header: &str, payload: &str) -> Result<Vec<u8>, Error> {
        let mut hasher = Hasher::new(MessageDigest::sha256())?;

        hasher.update(header.as_bytes())?;
        hasher.update(b".")?;
        hasher.update(payload.as_bytes())?;

        let hash = hasher.finish()?;

        let signature = EcdsaSig::sign(&hash, &self.key)?;

        let r = signature.r();
        let s = signature.s();

        let mut res = r.to_vec();

        res.extend_from_slice(&s.to_vec());

        Ok(res)
    }
}

/// JWS message builder.
pub struct MessageBuilder<'a, K, P> {
    key: &'a K,
    payload: Option<&'a P>,
}

impl<'a, K> MessageBuilder<'a, K, Empty> {
    /// Create a new message builder that will use a given key.
    pub fn new(key: &'a K) -> Self {
        Self { key, payload: None }
    }
}

impl<'a, K, P> MessageBuilder<'a, K, P> {
    /// Set the message payload.
    pub fn with_payload<T>(self, payload: &'a T) -> MessageBuilder<'a, K, T> {
        MessageBuilder {
            key: self.key,
            payload: Some(payload),
        }
    }
}

impl<'a, K, P> MessageBuilder<'a, K, P>
where
    K: Key,
    P: Serialize,
{
    /// Create a new message with standard JWK fields.
    pub fn build_with_jwk_header(&self, url: &str, nonce: &str) -> Result<Message, Error> {
        let header = Header {
            alg: self.key.algorithm(),
            nonce,
            url,
            jwk: Some(self.key.params()),
            kid: None,
        };

        self.build(header)
    }

    /// Create a new message with key identified using a give key ID.
    pub fn build_with_kid_header(
        &self,
        kid: &str,
        url: &str,
        nonce: &str,
    ) -> Result<Message, Error> {
        let header = Header {
            alg: self.key.algorithm(),
            nonce,
            url,
            jwk: None,
            kid: Some(kid),
        };

        self.build(header)
    }

    /// Create a new message.
    fn build(&self, header: Header<'_>) -> Result<Message, Error> {
        let header = serde_json::to_vec(&header).map_err(|err| {
            Error::from_static_msg_and_cause("unable to serialize a JWS header", err)
        })?;

        let header = utils::base64url(&header);

        let payload = if let Some(payload) = self.payload {
            serde_json::to_vec(payload).map_err(|err| {
                Error::from_static_msg_and_cause("unable to serialize a given payload", err)
            })?
        } else {
            Vec::new()
        };

        let payload = utils::base64url(&payload);

        let signature = self.key.sign(&header, &payload)?;

        let signature = utils::base64url(&signature);

        let res = Message {
            protected: header,
            payload,
            signature,
        };

        Ok(res)
    }
}

/// JWS message.
#[derive(Serialize)]
pub struct Message {
    protected: String,
    payload: String,
    signature: String,
}

/// JWS message header.
#[derive(Serialize)]
struct Header<'a> {
    alg: &'a str,
    nonce: &'a str,
    url: &'a str,

    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<&'a Params>,

    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

/// Empty JWS message payload.
pub struct Empty;

impl Serialize for Empty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_unit()
    }
}
