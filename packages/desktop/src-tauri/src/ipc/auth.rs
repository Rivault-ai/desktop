//! HMAC-SHA256 with constant-time comparison. The IPC secret is a 32-byte
//! key in the macOS Keychain — see `keychain` module.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub fn sign(key: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify(key: &[u8], body: &[u8], signature_hex: &str) -> bool {
    let Ok(expected) = hex::decode(signature_hex) else {
        return false;
    };
    let actual_hex = sign(key, body);
    let Ok(actual) = hex::decode(actual_hex) else {
        return false;
    };
    if expected.len() != actual.len() {
        return false;
    }
    expected.ct_eq(&actual).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = b"secret-key-32-bytes-secret-key-x";
        let body = b"hello";
        let sig = sign(key, body);
        assert!(verify(key, body, &sig));
        assert!(!verify(key, b"hello!", &sig));
        assert!(!verify(b"other-key-32-bytes-other-key-xx!", body, &sig));
    }

    #[test]
    fn rejects_garbage_signature() {
        let key = b"secret-key-32-bytes-secret-key-x";
        assert!(!verify(key, b"x", "not hex"));
        assert!(!verify(key, b"x", ""));
    }
}
