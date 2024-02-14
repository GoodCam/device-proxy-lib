use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};

/// Encode given data using URL-safe Base64 encoding with no padding.
pub fn base64url(data: &[u8]) -> String {
    Engine::encode(&BASE64_URL_SAFE_NO_PAD, data)
}
