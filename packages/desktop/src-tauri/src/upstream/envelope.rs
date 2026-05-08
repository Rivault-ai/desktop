//! Envelope crypto for L2 vault items.
//!
//! Wire-compatible with the Rivault backend at
//! `/Users/hyulim/code/rivault/packages/api/src/lib/envelope.ts`.
//!
//! Protocol:
//! - Curve: NIST P-256 (a.k.a. secp256r1 / prime256v1)
//! - Key agreement: ECDH (raw shared secret, X coordinate of the shared point)
//! - KDF: HKDF-SHA256, salt=empty, info=`"rivault-envelope-v1"`, length=32
//! - AEAD: AES-256-GCM, IV=12 bytes, auth tag=16 bytes appended to ciphertext
//! - Encodings: SPKI DER for public keys; base64 (standard) for everything
//!   over the wire.
//!
//! The mobile app encrypts; the daemon decrypts. The daemon-side keypair is
//! ephemeral — generated per request, kept in memory only, dropped after one
//! decrypt.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const HKDF_INFO: &[u8] = b"rivault-envelope-v1";
const AES_KEY_LEN: usize = 32;
const GCM_IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// Wire shape of the encrypted blob the backend returns on
/// `GET /agent/{auth,hybrid,login}-request/{id}/status`.
///
/// All fields are base64 (standard alphabet). `mobile_ephemeral_public_key`
/// is SPKI-DER. `ciphertext` includes the 16-byte AES-GCM tag *appended* to
/// the actual ciphertext bytes — this matches the Web Crypto convention
/// the backend uses (`crypto.subtle.encrypt` returns ct||tag in one blob).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub mobile_ephemeral_public_key: String,
    pub iv: String,
    pub ciphertext: String,
}

/// An ephemeral P-256 keypair held by the daemon for the lifetime of one
/// vault request. Created by `Keypair::generate` before the upstream POST,
/// passed to [`Keypair::decrypt`] once on the matching status response.
pub struct Keypair {
    secret: SecretKey,
    /// Cached SPKI-DER bytes of the public key. Computed once at generation
    /// time so `public_spki_b64` is allocation-free on the hot path.
    public_spki_der: Vec<u8>,
}

impl Keypair {
    /// Generate a fresh P-256 keypair using the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let secret = SecretKey::random(&mut OsRng);
        let der = secret
            .public_key()
            .to_public_key_der()
            .context("encode public key SPKI")?
            .into_vec();
        Ok(Self {
            secret,
            public_spki_der: der,
        })
    }

    /// Public key as base64-encoded SPKI DER, suitable for sending as
    /// `agentEphemeralPublicKey` in the upstream request body.
    pub fn public_spki_b64(&self) -> String {
        B64.encode(&self.public_spki_der)
    }

    /// Decrypt one envelope. Consumes the keypair: the secret is dropped
    /// when this method returns, regardless of outcome.
    pub fn decrypt(self, envelope: &Envelope) -> Result<Vec<u8>> {
        decrypt_with(&self.secret, envelope)
    }

    /// Borrow the underlying secret key for multi-envelope decryption.
    ///
    /// Used by the hybrid-status flow, which decrypts N envelopes (one
    /// per authorized item + form field) against a single keypair. The
    /// caller is expected to drop the keypair via `discard()` once done
    /// — keep the secret in scope no longer than one logical operation.
    pub(crate) fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

/// Free-function form of decrypt, exposed `pub(crate)` so the hybrid-status
/// flow can decrypt multiple envelopes against one borrowed secret without
/// needing the consume-on-decrypt `Keypair::decrypt`.
pub(crate) fn decrypt_with(secret: &SecretKey, envelope: &Envelope) -> Result<Vec<u8>> {
    let peer_der = B64
        .decode(envelope.mobile_ephemeral_public_key.as_bytes())
        .context("decode mobileEphemeralPublicKey base64")?;
    let peer = PublicKey::from_public_key_der(&peer_der)
        .map_err(|e| anyhow!("decode mobileEphemeralPublicKey SPKI: {e}"))?;

    let iv = B64.decode(envelope.iv.as_bytes()).context("decode iv base64")?;
    if iv.len() != GCM_IV_LEN {
        bail!(
            "envelope.iv has {} bytes, expected {GCM_IV_LEN}",
            iv.len()
        );
    }

    let ct_and_tag = B64
        .decode(envelope.ciphertext.as_bytes())
        .context("decode ciphertext base64")?;
    if ct_and_tag.len() < GCM_TAG_LEN {
        bail!(
            "envelope.ciphertext has {} bytes, must be >= {GCM_TAG_LEN} for the tag",
            ct_and_tag.len()
        );
    }

    // ECDH → HKDF-SHA256 → 32-byte AES-256 key. Salt is empty; info is the
    // protocol-version-bound constant. Keep these byte-identical to the
    // backend or decryption silently produces garbage.
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let hk = Hkdf::<Sha256>::new(None, shared.raw_secret_bytes());
    let mut aes_key = [0u8; AES_KEY_LEN];
    hk.expand(HKDF_INFO, &mut aes_key)
        .map_err(|e| anyhow!("hkdf expand: {e}"))?;

    // aes-gcm::decrypt accepts ct||tag as a single buffer when given via
    // Payload; it splits internally based on tag length.
    let cipher = Aes256Gcm::new(&aes_key.into());
    let nonce = Nonce::from_slice(&iv);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct_and_tag,
                aad: &[],
            },
        )
        .map_err(|_| anyhow!("AES-GCM authentication failed (envelope corrupted or wrong key)"))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{AeadCore, OsRng as AeadOsRng};

    /// Construct an envelope with a known peer keypair so we can verify
    /// round-trip without the mobile app. This mirrors what `envelope.ts`
    /// on the backend does end-to-end.
    fn encrypt_for(daemon_pub: &PublicKey, plaintext: &[u8]) -> Envelope {
        let peer_secret = SecretKey::random(&mut OsRng);
        let peer_pub_der = peer_secret
            .public_key()
            .to_public_key_der()
            .unwrap()
            .into_vec();

        let shared = diffie_hellman(peer_secret.to_nonzero_scalar(), daemon_pub.as_affine());
        let hk = Hkdf::<Sha256>::new(None, shared.raw_secret_bytes());
        let mut key = [0u8; 32];
        hk.expand(HKDF_INFO, &mut key).unwrap();

        let cipher = Aes256Gcm::new(&key.into());
        let iv = aes_gcm::Aes256Gcm::generate_nonce(&mut AeadOsRng);
        let ct_and_tag = cipher
            .encrypt(
                &iv,
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .unwrap();

        Envelope {
            mobile_ephemeral_public_key: B64.encode(&peer_pub_der),
            iv: B64.encode(&iv),
            ciphertext: B64.encode(&ct_and_tag),
        }
    }

    #[test]
    fn round_trip() {
        let kp = Keypair::generate().unwrap();
        let pub_b64 = kp.public_spki_b64();
        // Decode the daemon's pubkey back the same way the mobile would.
        let der = B64.decode(pub_b64.as_bytes()).unwrap();
        let daemon_pub = PublicKey::from_public_key_der(&der).unwrap();

        let plaintext = b"hunter2-with-cake";
        let envelope = encrypt_for(&daemon_pub, plaintext);

        let got = kp.decrypt(&envelope).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn wrong_keypair_fails_authentication() {
        let kp1 = Keypair::generate().unwrap();
        let kp2 = Keypair::generate().unwrap();
        let der = B64.decode(kp1.public_spki_b64().as_bytes()).unwrap();
        let kp1_pub = PublicKey::from_public_key_der(&der).unwrap();
        let envelope = encrypt_for(&kp1_pub, b"secret");
        assert!(kp2.decrypt(&envelope).is_err());
    }

    #[test]
    fn corrupted_ciphertext_fails_authentication() {
        let kp = Keypair::generate().unwrap();
        let der = B64.decode(kp.public_spki_b64().as_bytes()).unwrap();
        let pub_key = PublicKey::from_public_key_der(&der).unwrap();
        let mut envelope = encrypt_for(&pub_key, b"secret");

        // Flip a bit in the ciphertext. AES-GCM authentication MUST fail.
        let mut bytes = B64.decode(envelope.ciphertext.as_bytes()).unwrap();
        bytes[0] ^= 0x01;
        envelope.ciphertext = B64.encode(&bytes);

        assert!(kp.decrypt(&envelope).is_err());
    }

    #[test]
    fn malformed_iv_length_rejected() {
        let kp = Keypair::generate().unwrap();
        let der = B64.decode(kp.public_spki_b64().as_bytes()).unwrap();
        let pub_key = PublicKey::from_public_key_der(&der).unwrap();
        let mut envelope = encrypt_for(&pub_key, b"secret");
        envelope.iv = B64.encode(b"too-short");
        assert!(kp.decrypt(&envelope).is_err());
    }

    #[test]
    fn malformed_peer_pubkey_rejected() {
        let kp = Keypair::generate().unwrap();
        let der = B64.decode(kp.public_spki_b64().as_bytes()).unwrap();
        let pub_key = PublicKey::from_public_key_der(&der).unwrap();
        let mut envelope = encrypt_for(&pub_key, b"secret");
        envelope.mobile_ephemeral_public_key = B64.encode(b"not-a-real-spki-der");
        assert!(kp.decrypt(&envelope).is_err());
    }
}
