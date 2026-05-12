//! HMAC-SHA256 with constant-time comparison. The IPC secret is a 32-byte
//! key in the macOS Keychain — see `keychain` module.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;

/// Replay protection window for HMAC-authenticated `/release` and
/// `/stop` requests. A captured payload + signature is only accepted
/// while the body's `timestamp` (ISO 8601) falls within this many
/// seconds of `now`. Both endpoints are same-machine local IPC, so
/// clock skew between caller and daemon is effectively zero — 60s is
/// generous against process scheduling jitter only.
pub const REPLAY_WINDOW_SECS: i64 = 60;

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

/// Confirm an ISO 8601 timestamp embedded in a HMAC-signed body falls
/// within [`REPLAY_WINDOW_SECS`] of `now_utc`. Used after `verify` on
/// `/release` and `/stop` to bound the replay window: an attacker who
/// captures a payload + signature can only re-use it for one minute.
///
/// `now_utc` is injected so tests can pin time; production callers
/// pass `OffsetDateTime::now_utc()`.
pub fn freshness_ok(timestamp_iso: &str, now_utc: OffsetDateTime) -> bool {
    let Ok(parsed) = OffsetDateTime::parse(timestamp_iso, &Rfc3339) else {
        return false;
    };
    let delta = (now_utc - parsed).whole_seconds().abs();
    delta <= REPLAY_WINDOW_SECS
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

    #[test]
    fn freshness_accepts_within_window() {
        let now = OffsetDateTime::now_utc();
        let just_now = now.format(&Rfc3339).unwrap();
        assert!(freshness_ok(&just_now, now));
        let thirty_seconds_ago = (now - time::Duration::seconds(30))
            .format(&Rfc3339)
            .unwrap();
        assert!(freshness_ok(&thirty_seconds_ago, now));
        let thirty_seconds_future = (now + time::Duration::seconds(30))
            .format(&Rfc3339)
            .unwrap();
        assert!(freshness_ok(&thirty_seconds_future, now));
    }

    #[test]
    fn freshness_rejects_outside_window() {
        let now = OffsetDateTime::now_utc();
        let two_minutes_ago = (now - time::Duration::seconds(120))
            .format(&Rfc3339)
            .unwrap();
        assert!(!freshness_ok(&two_minutes_ago, now));
        let two_minutes_future = (now + time::Duration::seconds(120))
            .format(&Rfc3339)
            .unwrap();
        assert!(!freshness_ok(&two_minutes_future, now));
    }

    #[test]
    fn freshness_rejects_unparseable() {
        let now = OffsetDateTime::now_utc();
        assert!(!freshness_ok("", now));
        assert!(!freshness_ok("not-an-iso-date", now));
        // Right shape (epoch-seconds), wrong format
        assert!(!freshness_ok("1234567890", now));
    }
}
