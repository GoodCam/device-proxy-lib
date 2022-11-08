/// Encode given data using URL-safe Base64 encoding with no padding.
pub fn base64url(data: &[u8]) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}
