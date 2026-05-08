//! HTTP client for the Rivault `/agent/*` API.
//!
//! Mirrors `packages/skill/src/client.ts` — every endpoint that file
//! exposes is reachable here, plus the L2 envelope-decryption flow that
//! the TypeScript client doesn't implement (the SKILL.md flow has been
//! decrypting agent-side via inline `node -e` blocks; the daemon takes
//! over that responsibility).
//!
//! On every L2 create-request, the client mints a fresh ephemeral P-256
//! keypair, sends the public SPKI as `agentEphemeralPublicKey`, and
//! stashes the secret in the [`KeypairStore`] keyed by the upstream-issued
//! request id. On every poll, if the response carries an envelope, the
//! client takes the secret from the store (single-use) and decrypts.

use anyhow::{anyhow, bail, Context, Result};
use reqwest::{Client, Method, Response, StatusCode};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

use crate::upstream::envelope::{decrypt_with, Envelope, Keypair};
use crate::upstream::keypair_store::KeypairStore;
use crate::upstream::types::*;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Outcome of an L2 status poll once the daemon has had a chance to
/// decrypt any envelope present.
///
/// `Approved` is the only variant where plaintext exists; downstream
/// callers (MCP server, ledger writer) treat this as the moment of
/// release and must redact transcripts that contain the plaintext.
#[derive(Debug)]
pub enum AuthStatusOutcome {
    Pending,
    Approved {
        plaintext: Vec<u8>,
        kind: Option<String>,
        username: Option<String>,
        website: Option<String>,
    },
    /// Backend says approved but no envelope (cache TTL elapsed). Caller
    /// should request auth again.
    ApprovedNoEnvelope,
    Denied,
    Expired,
    /// Anything we don't recognise — passed through as `{status}` for
    /// surface-area-preserving forwarding.
    Other(String),
}

#[derive(Debug)]
pub enum FormStatusOutcome {
    Pending,
    Submitted { item_id: Option<String> },
    Expired,
    Other(String),
}

/// Decrypted form values + decrypted authorized values, both keyed by
/// the original key (form `key`, vault `itemId`).
#[derive(Debug, Default)]
pub struct HybridSubmitted {
    pub form_values: std::collections::HashMap<String, Vec<u8>>,
    pub authorized_items: std::collections::HashMap<String, HybridAuthorizedDecrypted>,
    pub created_item_ids: Vec<String>,
}

#[derive(Debug)]
pub struct HybridAuthorizedDecrypted {
    pub kind: String,
    pub plaintext: Vec<u8>,
    pub username: Option<String>,
    pub website: Option<String>,
}

#[derive(Debug)]
pub enum HybridStatusOutcome {
    Pending,
    Submitted(HybridSubmitted),
    Expired,
    Other(String),
}

#[derive(Debug)]
pub enum LoginStatusOutcome {
    Pending,
    Submitted {
        plaintext: Vec<u8>,
        login_item_id: Option<String>,
        website: Option<String>,
    },
    Denied,
    Expired,
    Other(String),
}

#[derive(Clone)]
pub struct UpstreamClient {
    base_url: Arc<str>,
    api_key: Arc<str>,
    http: Client,
    keypairs: KeypairStore,
}

impl UpstreamClient {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Result<Self> {
        let http = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            base_url: base_url.into().into(),
            api_key: api_key.into().into(),
            http,
            keypairs: KeypairStore::new(),
        })
    }

    #[cfg(test)]
    pub fn with_keypair_store(mut self, store: KeypairStore) -> Self {
        self.keypairs = store;
        self
    }

    pub fn keypair_store(&self) -> &KeypairStore {
        &self.keypairs
    }

    // ---- /agent/vault/search -------------------------------------------

    pub async fn search(&self, query: &str) -> Result<SearchResponse> {
        let mut url = self.url("/agent/vault/search");
        url.push_str("?q=");
        url.push_str(&urlencoding::encode(query));
        self.json::<SearchResponse>(self.http.get(&url)).await
    }

    // ---- /agent/vault/{id} ---------------------------------------------

    pub async fn get_secret(&self, item_id: &str) -> Result<GetSecretResponse> {
        let url = self.url(&format!("/agent/vault/{}", urlencoding::encode(item_id)));
        self.json::<GetSecretResponse>(self.http.get(&url)).await
    }

    // ---- /agent/vault/logins -------------------------------------------

    pub async fn check_login(&self, website: &str) -> Result<CheckLoginResponse> {
        let mut url = self.url("/agent/vault/logins");
        url.push_str("?website=");
        url.push_str(&urlencoding::encode(website));
        self.json::<CheckLoginResponse>(self.http.get(&url)).await
    }

    // ---- /agent/auth-request -------------------------------------------

    pub async fn create_auth_request(
        &self,
        item_id: &str,
        reason: Option<&str>,
        callback_session_id: Option<&str>,
    ) -> Result<AuthRequestResponse> {
        let kp = Keypair::generate()?;
        let pub_b64 = kp.public_spki_b64();
        let body = AuthRequestBody {
            item_id,
            reason,
            agent_ephemeral_public_key: &pub_b64,
            callback_session_id,
        };
        let resp: AuthRequestResponse = self.post("/agent/auth-request", &body).await?;
        self.keypairs.store(&resp.auth_request_id, kp);
        Ok(resp)
    }

    pub async fn poll_auth_status(&self, auth_request_id: &str) -> Result<AuthStatusOutcome> {
        let url = self.url(&format!(
            "/agent/auth-request/{}/status",
            urlencoding::encode(auth_request_id)
        ));
        let raw: AuthStatusResponse = self.json(self.http.get(&url)).await?;
        match raw.status.as_str() {
            "pending" => Ok(AuthStatusOutcome::Pending),
            "denied" => Ok(AuthStatusOutcome::Denied),
            "expired" => Ok(AuthStatusOutcome::Expired),
            "approved" => match raw.envelope {
                Some(env) => {
                    let plaintext = self.decrypt_envelope(auth_request_id, &env)?;
                    Ok(AuthStatusOutcome::Approved {
                        plaintext,
                        kind: raw.kind,
                        username: raw.username,
                        website: raw.website,
                    })
                }
                None => Ok(AuthStatusOutcome::ApprovedNoEnvelope),
            },
            other => Ok(AuthStatusOutcome::Other(other.to_string())),
        }
    }

    // ---- /agent/form-request -------------------------------------------

    pub async fn create_form_request(
        &self,
        requested_label: &str,
        requested_category: &str,
        reason: Option<&str>,
        callback_session_id: Option<&str>,
    ) -> Result<FormRequestResponse> {
        let body = FormRequestBody {
            requested_label,
            requested_category,
            reason,
            callback_session_id,
        };
        self.post("/agent/form-request", &body).await
    }

    pub async fn poll_form_status(&self, form_request_id: &str) -> Result<FormStatusOutcome> {
        let url = self.url(&format!(
            "/agent/form-request/{}/status",
            urlencoding::encode(form_request_id)
        ));
        let raw: FormStatusResponse = self.json(self.http.get(&url)).await?;
        Ok(match raw.status.as_str() {
            "pending" => FormStatusOutcome::Pending,
            "submitted" => FormStatusOutcome::Submitted {
                item_id: raw.item_id,
            },
            "expired" => FormStatusOutcome::Expired,
            other => FormStatusOutcome::Other(other.to_string()),
        })
    }

    // ---- /agent/hybrid-request -----------------------------------------

    pub async fn create_hybrid_request(
        &self,
        auth_item_ids: &[String],
        form_fields: &[HybridFormField],
        reason: Option<&str>,
        callback_session_id: Option<&str>,
    ) -> Result<HybridRequestResponse> {
        let kp = Keypair::generate()?;
        let pub_b64 = kp.public_spki_b64();
        let body = HybridRequestBody {
            auth_item_ids,
            form_fields,
            reason,
            agent_ephemeral_public_key: &pub_b64,
            callback_session_id,
        };
        let resp: HybridRequestResponse = self.post("/agent/hybrid-request", &body).await?;
        self.keypairs.store(&resp.hybrid_request_id, kp);
        Ok(resp)
    }

    pub async fn poll_hybrid_status(
        &self,
        hybrid_request_id: &str,
    ) -> Result<HybridStatusOutcome> {
        let url = self.url(&format!(
            "/agent/hybrid-request/{}/status",
            urlencoding::encode(hybrid_request_id)
        ));
        let raw: HybridStatusResponse = self.json(self.http.get(&url)).await?;
        match raw.status.as_str() {
            "pending" => Ok(HybridStatusOutcome::Pending),
            "expired" => Ok(HybridStatusOutcome::Expired),
            "submitted" => {
                // One keypair decrypts every envelope in this response.
                // Take it once, borrow its secret across the loop, then
                // drop the keypair so the secret is zeroized.
                let kp = self.keypairs.take(hybrid_request_id).ok_or_else(|| {
                    anyhow!(
                        "no keypair stored for hybrid_request_id={hybrid_request_id}; \
                         daemon restart between create and poll?"
                    )
                })?;
                let secret = kp.secret();
                let mut out = HybridSubmitted {
                    created_item_ids: raw.created_item_ids,
                    ..Default::default()
                };
                for (key, env) in raw.form_envelopes {
                    let pt = decrypt_with(secret, &env)
                        .with_context(|| format!("decrypt form envelope key={key}"))?;
                    out.form_values.insert(key, pt);
                }
                for (item_id, item) in raw.authorized_items {
                    let pt = decrypt_with(secret, &item.envelope)
                        .with_context(|| format!("decrypt auth envelope itemId={item_id}"))?;
                    out.authorized_items.insert(
                        item_id,
                        HybridAuthorizedDecrypted {
                            kind: item.kind,
                            plaintext: pt,
                            username: item.username,
                            website: item.website,
                        },
                    );
                }
                drop(kp);
                Ok(HybridStatusOutcome::Submitted(out))
            }
            other => Ok(HybridStatusOutcome::Other(other.to_string())),
        }
    }

    // ---- /agent/login-request ------------------------------------------

    pub async fn create_login_request(
        &self,
        website: &str,
        reason: Option<&str>,
        callback_session_id: Option<&str>,
    ) -> Result<LoginRequestResponse> {
        let kp = Keypair::generate()?;
        let pub_b64 = kp.public_spki_b64();
        let body = LoginRequestBody {
            website,
            reason,
            agent_ephemeral_public_key: &pub_b64,
            callback_session_id,
        };
        let resp: LoginRequestResponse = self.post("/agent/login-request", &body).await?;
        self.keypairs.store(&resp.login_request_id, kp);
        Ok(resp)
    }

    pub async fn poll_login_status(&self, login_request_id: &str) -> Result<LoginStatusOutcome> {
        let url = self.url(&format!(
            "/agent/login-request/{}/status",
            urlencoding::encode(login_request_id)
        ));
        let raw: LoginStatusResponse = self.json(self.http.get(&url)).await?;
        match raw.status.as_str() {
            "pending" => Ok(LoginStatusOutcome::Pending),
            "denied" => Ok(LoginStatusOutcome::Denied),
            "expired" => Ok(LoginStatusOutcome::Expired),
            "submitted" => match raw.envelope {
                Some(env) => {
                    let plaintext = self.decrypt_envelope(login_request_id, &env)?;
                    Ok(LoginStatusOutcome::Submitted {
                        plaintext,
                        login_item_id: raw.login_item_id,
                        website: raw.website,
                    })
                }
                None => Ok(LoginStatusOutcome::Other("submitted-no-envelope".into())),
            },
            other => Ok(LoginStatusOutcome::Other(other.to_string())),
        }
    }

    // ---- internal helpers ----------------------------------------------

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn decrypt_envelope(&self, request_id: &str, env: &Envelope) -> Result<Vec<u8>> {
        let kp = self.keypairs.take(request_id).ok_or_else(|| {
            anyhow!(
                "no keypair stored for request_id={request_id}; \
                 daemon restart between create and poll?"
            )
        })?;
        kp.decrypt(env)
    }

    async fn json<T: serde::de::DeserializeOwned>(
        &self,
        rb: reqwest::RequestBuilder,
    ) -> Result<T> {
        let res = self.send(rb).await?;
        let bytes = res.bytes().await.context("read response body")?;
        serde_json::from_slice::<T>(&bytes)
            .with_context(|| format!("decode response body: {}", String::from_utf8_lossy(&bytes)))
    }

    async fn post<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R> {
        let url = self.url(path);
        let rb = self
            .http
            .request(Method::POST, &url)
            .header("Content-Type", "application/json")
            .json(body);
        self.json(rb).await
    }

    async fn send(&self, rb: reqwest::RequestBuilder) -> Result<Response> {
        let res = rb
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .context("upstream request")?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            bail!("upstream {status}: {text}");
        }
        // Don't blow up on non-application/json (the backend always returns
        // JSON for these routes, but tolerate proxies that strip the
        // Content-Type header).
        if let Some(ct) = res
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            if !ct.contains("json") && res.status() == StatusCode::OK {
                tracing::debug!(
                    "upstream returned 200 with non-json content-type: {ct}"
                );
            }
        }
        Ok(res)
    }
}

