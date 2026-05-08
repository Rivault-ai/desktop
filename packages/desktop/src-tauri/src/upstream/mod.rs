//! Rivault `/agent/*` upstream — HTTP client + envelope crypto.
//!
//! The single point of contact between the desktop daemon and the
//! Rivault backend at `api.rivault.ai`. Used by:
//! - the local MCP server (one client per tool invocation),
//! - the Tier-B reverse proxy (when transparently forwarding /agent/*),
//! - the Tier-C SSE subscriber (out-of-band release notifications).
//!
//! All envelope decryption happens here so the daemon owns the entire
//! L2 secret lifecycle: keypair generation → upstream POST → store →
//! poll → decrypt → drop.

pub mod client;
pub mod envelope;
pub mod keypair_store;
pub mod types;

pub use client::{
    AuthStatusOutcome, FormStatusOutcome, HybridAuthorizedDecrypted, HybridStatusOutcome,
    HybridSubmitted, LoginStatusOutcome, UpstreamClient,
};
pub use envelope::{Envelope, Keypair};
pub use keypair_store::KeypairStore;
