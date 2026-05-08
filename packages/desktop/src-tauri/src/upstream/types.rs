//! Wire shapes for the Rivault `/agent/*` HTTP API.
//!
//! Field naming follows the backend's serde/JSON conventions verbatim
//! (camelCase on the wire, snake_case in Rust via `#[serde(rename_all)]`).
//! When backend types drift, the daemon must drift in lockstep — historic
//! schema mismatches silently 400'd and lost release events.
//!
//! Cross-reference: `/Users/hyulim/code/rivault/packages/api/src/routes/agent/`.

use serde::{Deserialize, Serialize};

use crate::upstream::envelope::Envelope;

// ---- /agent/vault/search ---------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct SearchItem {
    pub id: String,
    pub available: bool,
    #[serde(rename = "sensitivityLevel")]
    pub sensitivity_level: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchResponse {
    pub results: Vec<SearchItem>,
}

// ---- /agent/vault/{id} -----------------------------------------------------

/// L1 returns the plaintext directly. L2 returns a stub indicating the
/// caller must use `/agent/auth-request` instead. The two shapes are
/// disjoint enough that we deserialise via untagged enum.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum GetSecretResponse {
    L1 {
        value: String,
        label: String,
    },
    L2 {
        requires_auth: bool,
        sensitivity_level: u8,
        label: String,
    },
}

// ---- /agent/auth-request ---------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRequestBody<'a> {
    pub item_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'a str>,
    pub agent_ephemeral_public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_session_id: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthRequestResponse {
    pub auth_request_id: String,
    pub auth_url: String,
    pub expires_at: String,
    pub agent_message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthStatusResponse {
    pub status: String,
    /// `"general"` or `"login"` — present when `status=approved` and an
    /// envelope is included.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub envelope: Option<Envelope>,
    /// Cleartext for login items; the password lives in the envelope.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
}

// ---- /agent/form-request ---------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormRequestBody<'a> {
    pub requested_label: &'a str,
    pub requested_category: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_session_id: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FormRequestResponse {
    pub form_request_id: String,
    pub form_url: String,
    pub expires_at: String,
    pub agent_message: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FormStatusResponse {
    pub status: String,
    /// Item the user chose to save the value under, when `status=submitted`.
    #[serde(default)]
    pub item_id: Option<String>,
}

// ---- /agent/hybrid-request -------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct HybridFormField {
    pub key: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HybridRequestBody<'a> {
    pub auth_item_ids: &'a [String],
    pub form_fields: &'a [HybridFormField],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'a str>,
    pub agent_ephemeral_public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_session_id: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HybridRequestResponse {
    pub hybrid_request_id: String,
    pub hybrid_url: String,
    pub expires_at: String,
    pub agent_message: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HybridAuthorizedItem {
    /// `"general"` or `"login"`.
    #[serde(rename = "type")]
    pub kind: String,
    pub envelope: Envelope,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HybridStatusResponse {
    pub status: String,
    /// fieldKey → envelope to decrypt for the user-collected form values.
    #[serde(default)]
    pub form_envelopes: std::collections::HashMap<String, Envelope>,
    /// itemId → entry containing an envelope plus optional cleartext fields.
    #[serde(default)]
    pub authorized_items: std::collections::HashMap<String, HybridAuthorizedItem>,
    #[serde(default)]
    pub created_item_ids: Vec<String>,
}

// ---- /agent/vault/logins ---------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct LoginSummary {
    pub id: String,
    pub label: String,
    pub website: String,
    pub username: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckLoginResponse {
    pub found: bool,
    #[serde(default)]
    pub logins: Vec<LoginSummary>,
}

// ---- /agent/login-request --------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequestBody<'a> {
    pub website: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'a str>,
    pub agent_ephemeral_public_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_session_id: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequestResponse {
    pub login_request_id: String,
    pub login_url: String,
    pub expires_at: String,
    pub agent_message: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStatusResponse {
    pub status: String,
    #[serde(default)]
    pub login_item_id: Option<String>,
    #[serde(default)]
    pub envelope: Option<Envelope>,
    #[serde(default)]
    pub website: Option<String>,
}
