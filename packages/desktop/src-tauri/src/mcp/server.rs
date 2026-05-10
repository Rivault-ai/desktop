//! Local Rivault MCP server, hosted inside the desktop daemon.
//!
//! Agents (Claude Code, Codex, Claude Desktop, OpenClaw) connect via
//! Streamable HTTP at `127.0.0.1:<port>/mcp`. Every tool call goes
//! through the daemon: it proxies the request to api.rivault.ai, observes
//! the response, inserts a ledger row when plaintext crosses through, and
//! returns the result to the agent.
//!
//! Why HTTP and not stdio? Multiple agents (and multiple sessions per
//! agent) can share one daemon process. stdio would require a shim
//! subprocess per session and fragment the lifecycle. HTTP is one app,
//! one listener — matches the desktop app's "everything in one process"
//! posture.
//!
//! Auth: bound to 127.0.0.1 only. Same-machine, same-user is the
//! security boundary, identical to the daemon's existing /release and
//! /stop endpoints (the discovery file at mode 0600 leaks the HMAC
//! key to any local process anyway).

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::daemon::release::{AgentRuntime, ReleaseEvent, Tier};
use crate::daemon::Daemon;
use crate::ledger::Channel;
use crate::mcp::transcript::resolve_transcript_paths;
use crate::upstream::types::{GetSecretResponse, HybridFormField};
use crate::upstream::{
    AuthStatusOutcome, FormStatusOutcome, HybridStatusOutcome, LoginStatusOutcome, UpstreamClient,
};

/// Per-instance state for the MCP server. Cloned (cheap — `Arc`s inside)
/// for every new session by [`StreamableHttpService`].
#[derive(Clone)]
pub struct RivaultMcp {
    daemon: Arc<Daemon>,
    upstream: UpstreamClient,
    /// Runtime label baked into the connection. The desktop setup flow
    /// passes this when registering the MCP entry per agent — Claude Code
    /// lands as `claude-code`, Codex as `codex`, etc. Defaults to
    /// `Custom` when absent (no transcript scrub possible).
    runtime: AgentRuntime,
    /// Populated and consumed by the `#[tool_router]` / `#[tool_handler]`
    /// macros via reflection — Rust's dead-code analysis can't see that.
    #[allow(dead_code)]
    tool_router: ToolRouter<RivaultMcp>,
}

impl RivaultMcp {
    pub fn new(daemon: Arc<Daemon>, upstream: UpstreamClient, runtime: AgentRuntime) -> Self {
        Self {
            daemon,
            upstream,
            runtime,
            tool_router: Self::tool_router(),
        }
    }
}

// ---- tool argument schemas (also feed the MCP tool descriptions) ----------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CheckArgs {
    /// One specific field to look up, e.g. "email", "phone number",
    /// "home address". Matches the upstream `/agent/vault/search?q=` API.
    pub query: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetSecretArgs {
    /// Vault item id, as returned by `rivault_check`. Only L1 items can
    /// be retrieved this way; L2 items must use `rivault_request_auth`.
    pub item_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CheckLoginArgs {
    /// URL or hostname; the server normalises to eTLD+1.
    pub website: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RequestAuthArgs {
    /// Vault item id requiring Face ID authorization.
    pub item_id: String,
    /// Why you need this item — surfaced to the user on their phone.
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional callback session id for OpenClaw-style poller resume.
    #[serde(default)]
    pub callback_session_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PollAuthArgs {
    pub auth_request_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RequestFormArgs {
    /// Human-friendly label of the requested item, e.g. "Work email".
    pub requested_label: String,
    /// Category tag, e.g. "email", "phone", "address".
    pub requested_category: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub callback_session_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PollFormArgs {
    pub form_request_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HybridFieldSchema {
    pub key: String,
    pub label: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RequestHybridArgs {
    /// L2 vault item ids needing user authorization.
    #[serde(default)]
    pub auth_item_ids: Vec<String>,
    /// Form fields to collect when items aren't yet in the vault.
    #[serde(default)]
    pub form_fields: Vec<HybridFieldSchema>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub callback_session_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PollHybridArgs {
    pub hybrid_request_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RequestLoginArgs {
    pub website: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub callback_session_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PollLoginArgs {
    pub login_request_id: String,
}

#[tool_router]
impl RivaultMcp {
    #[tool(
        description = "Check whether a specific field exists in the Rivault vault. \
                       Pass a single field name (\"email\", \"phone\", \"address\", \
                       etc.) — call once per field you need. \
                       \
                       MANDATORY: call this BEFORE asking the user for any \
                       personal data. Only ask the user if rivault_check returns \
                       no match. The user has Rivault installed specifically so \
                       they don't have to retype this data — do not skip this \
                       step. \
                       \
                       Returns matching item ids and their sensitivity tier (L1 \
                       retrievable directly via rivault_get_secret, L2 requires \
                       rivault_request_auth/hybrid)."
    )]
    async fn rivault_check(
        &self,
        Parameters(CheckArgs { query }): Parameters<CheckArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self.upstream.search(&query).await {
            Ok(resp) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string(&serde_json::json!({ "results": resp.results
                    .iter()
                    .map(|r| serde_json::json!({
                        "id": r.id,
                        "available": r.available,
                        "sensitivityLevel": r.sensitivity_level,
                    }))
                    .collect::<Vec<_>>() }))
                .unwrap_or_else(|_| "{}".into()),
            )])),
            Err(e) => Err(upstream_err("rivault_check", e)),
        }
    }

    #[tool(
        description = "Retrieve an L1 vault item's plaintext value by id. The daemon \
                       inserts a ledger row before returning, so the value is \
                       guaranteed to be redacted from this runtime's transcript when \
                       the task ends. For L2 items (requires_auth=true), use \
                       rivault_request_auth instead."
    )]
    async fn rivault_get_secret(
        &self,
        Parameters(GetSecretArgs { item_id }): Parameters<GetSecretArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let resp = self
            .upstream
            .get_secret(&item_id)
            .await
            .map_err(|e| upstream_err("rivault_get_secret", e))?;

        match resp {
            GetSecretResponse::L2 {
                requires_auth,
                sensitivity_level,
                label,
            } => {
                // Don't insert a ledger row — no plaintext crossed through.
                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string(&serde_json::json!({
                        "requires_auth": requires_auth,
                        "sensitivity_level": sensitivity_level,
                        "label": label,
                        "hint": "L2 item — call rivault_request_auth with this item_id",
                    }))
                    .unwrap_or_default(),
                )]))
            }
            GetSecretResponse::L1 { value, label } => {
                // Plaintext is in `value`. Log a release row before
                // returning so the redaction guarantee holds even if the
                // agent crashes mid-response.
                let session_id = mcp_session_id(&ctx);
                self.log_release(Tier::L1, &value, &session_id, &ctx)
                    .map_err(|e| internal_err("log release", e))?;

                Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string(&serde_json::json!({
                        "value": value,
                        "label": label,
                    }))
                    .unwrap_or_default(),
                )]))
            }
        }
    }

    #[tool(
        description = "Check whether the user has any saved login credentials for a \
                       given website. Returns the list of (id, label, website, \
                       username) entries — passwords are L2 and require \
                       rivault_request_auth to retrieve."
    )]
    async fn rivault_check_login(
        &self,
        Parameters(CheckLoginArgs { website }): Parameters<CheckLoginArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self.upstream.check_login(&website).await {
            Ok(resp) => Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string(&serde_json::json!({
                    "found": resp.found,
                    "logins": resp.logins
                        .iter()
                        .map(|l| serde_json::json!({
                            "id": l.id,
                            "label": l.label,
                            "website": l.website,
                            "username": l.username,
                        }))
                        .collect::<Vec<_>>(),
                }))
                .unwrap_or_default(),
            )])),
            Err(e) => Err(upstream_err("rivault_check_login", e)),
        }
    }

    // ---- L2: auth-request flow ----------------------------------------

    #[tool(
        description = "Request user authorization (Face ID) for a SINGLE L2 vault \
                       item. Returns an authUrl to send to the user verbatim AND \
                       a `nextAction` field naming the tool to call next. \
                       \
                       MANDATORY NEXT STEP: immediately after this returns, call \
                       `rivault_await_auth` with the returned authRequestId. Do \
                       NOT stop and wait for the user to say 'approved' — \
                       `rivault_await_auth` blocks internally until the user \
                       approves on their phone (or denies / expires). Forgetting \
                       to call `rivault_await_auth` will leave the agent idle \
                       forever. \
                       \
                       The daemon decrypts the envelope locally and returns the \
                       plaintext value through `rivault_await_auth`. The agent \
                       never holds the ephemeral private key. \
                       \
                       MULTI-ITEM HINT: if you need to authorize MULTIPLE L2 \
                       items at once, do NOT call this tool repeatedly — that \
                       creates one link per item. Use `rivault_request_hybrid` \
                       instead, which combines all items (and any missing form \
                       fields) into a single user-facing approval link."
    )]
    async fn rivault_request_auth(
        &self,
        Parameters(RequestAuthArgs {
            item_id,
            reason,
            callback_session_id,
        }): Parameters<RequestAuthArgs>,
    ) -> Result<CallToolResult, McpError> {
        let resp = self
            .upstream
            .create_auth_request(
                &item_id,
                reason.as_deref(),
                callback_session_id.as_deref(),
            )
            .await
            .map_err(|e| upstream_err("rivault_request_auth", e))?;
        let req_id = resp.auth_request_id.clone();
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string(&serde_json::json!({
                "authRequestId": resp.auth_request_id,
                "authUrl": resp.auth_url,
                "expiresAt": resp.expires_at,
                "agentMessage": resp.agent_message,
                "nextAction": {
                    "tool": "rivault_await_auth",
                    "args": {"auth_request_id": req_id},
                    "instruction": "Call rivault_await_auth NOW. Do not wait for the user; await blocks until approval.",
                },
            }))
            .unwrap_or_default(),
        )]))
    }

    #[tool(
        description = "Poll a pending auth-request. When status=approved with an \
                       envelope present, the daemon decrypts and returns the \
                       plaintext value; the release is logged in the ledger before \
                       this call returns. For login items, also returns username \
                       and website cleartext."
    )]
    async fn rivault_poll_auth(
        &self,
        Parameters(PollAuthArgs { auth_request_id }): Parameters<PollAuthArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let outcome = self
            .upstream
            .poll_auth_status(&auth_request_id)
            .await
            .map_err(|e| upstream_err("rivault_poll_auth", e))?;
        let session_id = mcp_session_id(&ctx);
        match outcome {
            AuthStatusOutcome::Pending => Ok(json_result(serde_json::json!({
                "status": "pending",
            }))),
            AuthStatusOutcome::Denied => Ok(json_result(serde_json::json!({
                "status": "denied",
            }))),
            AuthStatusOutcome::Expired => Ok(json_result(serde_json::json!({
                "status": "expired",
            }))),
            AuthStatusOutcome::ApprovedNoEnvelope => Ok(json_result(serde_json::json!({
                "status": "approved_no_envelope",
                "hint": "cache TTL elapsed; re-request auth",
            }))),
            AuthStatusOutcome::Approved {
                plaintext,
                kind,
                username,
                website,
            } => {
                let value = String::from_utf8_lossy(&plaintext).into_owned();
                self.log_release(Tier::L2, &value, &session_id, &ctx)
                    .map_err(|e| internal_err("log release", e))?;
                Ok(json_result(serde_json::json!({
                    "status": "approved",
                    "type": kind,
                    "value": value,
                    "username": username,
                    "website": website,
                })))
            }
            AuthStatusOutcome::Other(s) => Ok(json_result(serde_json::json!({
                "status": s,
            }))),
        }
    }

    #[tool(
        description = "Wait for the user to approve a Face ID authorization request, \
                       polling internally with 3-8s backoff for up to 3 minutes. \
                       Returns the same shape as rivault_poll_auth but the agent \
                       doesn't have to loop. Prefer this over rivault_poll_auth in \
                       runtimes without a background poller (Claude Code, Codex, \
                       Claude Desktop). Use rivault_poll_auth when you have a \
                       runtime-provided poller (OpenClaw)."
    )]
    async fn rivault_await_auth(
        &self,
        Parameters(PollAuthArgs { auth_request_id }): Parameters<PollAuthArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        use std::time::{Duration, Instant};
        let start = Instant::now();
        let timeout = Duration::from_secs(180);
        let mut interval = Duration::from_secs(3);
        let session_id = mcp_session_id(&ctx);
        loop {
            let outcome = self
                .upstream
                .poll_auth_status(&auth_request_id)
                .await
                .map_err(|e| upstream_err("rivault_await_auth", e))?;
            if matches!(outcome, AuthStatusOutcome::Pending) {
                if start.elapsed() >= timeout {
                    return Ok(json_result(serde_json::json!({"status": "expired"})));
                }
                tokio::time::sleep(interval).await;
                if interval < Duration::from_secs(8) {
                    interval += Duration::from_secs(1);
                }
                continue;
            }
            return self.format_auth_outcome(outcome, &session_id, &ctx);
        }
    }

    // ---- L2: form-request flow ----------------------------------------

    #[tool(
        description = "Ask the user to provide a value not currently in the vault. \
                       Returns a formUrl to send to the user verbatim; once they \
                       submit, poll with rivault_poll_form to learn the new \
                       itemId, then retrieve via rivault_get_secret or \
                       rivault_request_auth depending on tier."
    )]
    async fn rivault_request_form(
        &self,
        Parameters(RequestFormArgs {
            requested_label,
            requested_category,
            reason,
            callback_session_id,
        }): Parameters<RequestFormArgs>,
    ) -> Result<CallToolResult, McpError> {
        let resp = self
            .upstream
            .create_form_request(
                &requested_label,
                &requested_category,
                reason.as_deref(),
                callback_session_id.as_deref(),
            )
            .await
            .map_err(|e| upstream_err("rivault_request_form", e))?;
        Ok(json_result(serde_json::json!({
            "formRequestId": resp.form_request_id,
            "formUrl": resp.form_url,
            "expiresAt": resp.expires_at,
            "agentMessage": resp.agent_message,
        })))
    }

    #[tool(
        description = "Poll a pending form-request. Returns status=submitted with the \
                       new itemId once the user has saved the value. No plaintext \
                       crosses through this tool."
    )]
    async fn rivault_poll_form(
        &self,
        Parameters(PollFormArgs { form_request_id }): Parameters<PollFormArgs>,
    ) -> Result<CallToolResult, McpError> {
        let outcome = self
            .upstream
            .poll_form_status(&form_request_id)
            .await
            .map_err(|e| upstream_err("rivault_poll_form", e))?;
        Ok(match outcome {
            FormStatusOutcome::Pending => json_result(serde_json::json!({"status": "pending"})),
            FormStatusOutcome::Expired => json_result(serde_json::json!({"status": "expired"})),
            FormStatusOutcome::Submitted { item_id } => json_result(serde_json::json!({
                "status": "submitted",
                "itemId": item_id,
            })),
            FormStatusOutcome::Other(s) => json_result(serde_json::json!({"status": s})),
        })
    }

    // ---- L2: hybrid-request flow --------------------------------------

    #[tool(
        description = "Combined L2 authorization + missing-field collection in one \
                       URL. Pass every L2 item id needing approval AND every field \
                       not yet in the vault. The user gets a single hybridUrl. \
                       \
                       MANDATORY NEXT STEP: immediately after this returns, call \
                       `rivault_await_hybrid` with the returned hybridRequestId. \
                       Do NOT stop and wait for the user; `rivault_await_hybrid` \
                       blocks internally until submission and returns the \
                       decrypted bundle: { authorized, form, createdItemIds }."
    )]
    async fn rivault_request_hybrid(
        &self,
        Parameters(RequestHybridArgs {
            auth_item_ids,
            form_fields,
            reason,
            callback_session_id,
        }): Parameters<RequestHybridArgs>,
    ) -> Result<CallToolResult, McpError> {
        let fields: Vec<HybridFormField> = form_fields
            .into_iter()
            .map(|f| HybridFormField {
                key: f.key,
                label: f.label,
            })
            .collect();
        let resp = self
            .upstream
            .create_hybrid_request(
                &auth_item_ids,
                &fields,
                reason.as_deref(),
                callback_session_id.as_deref(),
            )
            .await
            .map_err(|e| upstream_err("rivault_request_hybrid", e))?;
        let req_id = resp.hybrid_request_id.clone();
        Ok(json_result(serde_json::json!({
            "hybridRequestId": resp.hybrid_request_id,
            "hybridUrl": resp.hybrid_url,
            "expiresAt": resp.expires_at,
            "agentMessage": resp.agent_message,
            "nextAction": {
                "tool": "rivault_await_hybrid",
                "args": {"hybrid_request_id": req_id},
                "instruction": "Call rivault_await_hybrid NOW. Do not wait for the user; await blocks until the user submits.",
            },
        })))
    }

    #[tool(
        description = "Poll a pending hybrid-request. When submitted, the daemon \
                       decrypts every authorized envelope and every form-field \
                       envelope, logs each plaintext as a separate ledger row, \
                       and returns the bundle: { authorized: { itemId: { type, \
                       value, username?, website? } }, form: { fieldKey: value }, \
                       createdItemIds }."
    )]
    async fn rivault_poll_hybrid(
        &self,
        Parameters(PollHybridArgs { hybrid_request_id }): Parameters<PollHybridArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let outcome = self
            .upstream
            .poll_hybrid_status(&hybrid_request_id)
            .await
            .map_err(|e| upstream_err("rivault_poll_hybrid", e))?;
        let session_id = mcp_session_id(&ctx);
        match outcome {
            HybridStatusOutcome::Pending => {
                Ok(json_result(serde_json::json!({"status": "pending"})))
            }
            HybridStatusOutcome::Expired => {
                Ok(json_result(serde_json::json!({"status": "expired"})))
            }
            HybridStatusOutcome::Other(s) => Ok(json_result(serde_json::json!({"status": s}))),
            HybridStatusOutcome::Submitted(submitted) => {
                let mut authorized = serde_json::Map::new();
                for (item_id, item) in submitted.authorized_items {
                    let value = String::from_utf8_lossy(&item.plaintext).into_owned();
                    self.log_release(Tier::L2, &value, &session_id, &ctx)
                        .map_err(|e| internal_err("log release (auth item)", e))?;
                    authorized.insert(
                        item_id,
                        serde_json::json!({
                            "type": item.kind,
                            "value": value,
                            "username": item.username,
                            "website": item.website,
                        }),
                    );
                }
                let mut form = serde_json::Map::new();
                for (key, bytes) in submitted.form_values {
                    let value = String::from_utf8_lossy(&bytes).into_owned();
                    // Form-collected values are L2 in transit even though
                    // they're brand-new and not stored as L2 in the vault.
                    // Tier::L2 here means "envelope-encrypted" — semantically
                    // accurate for redaction purposes.
                    self.log_release(Tier::L2, &value, &session_id, &ctx)
                        .map_err(|e| internal_err("log release (form field)", e))?;
                    form.insert(key, serde_json::Value::String(value));
                }
                Ok(json_result(serde_json::json!({
                    "status": "submitted",
                    "authorized": authorized,
                    "form": form,
                    "createdItemIds": submitted.created_item_ids,
                })))
            }
        }
    }

    #[tool(
        description = "Wait for the user to complete a hybrid request, polling \
                       internally with 3-8s backoff for up to 3 minutes. Same \
                       response shape as rivault_poll_hybrid. Prefer this in \
                       runtimes without a background poller."
    )]
    async fn rivault_await_hybrid(
        &self,
        Parameters(PollHybridArgs { hybrid_request_id }): Parameters<PollHybridArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        use std::time::{Duration, Instant};
        let start = Instant::now();
        let timeout = Duration::from_secs(180);
        let mut interval = Duration::from_secs(3);
        let session_id = mcp_session_id(&ctx);
        loop {
            let outcome = self
                .upstream
                .poll_hybrid_status(&hybrid_request_id)
                .await
                .map_err(|e| upstream_err("rivault_await_hybrid", e))?;
            if matches!(outcome, HybridStatusOutcome::Pending) {
                if start.elapsed() >= timeout {
                    return Ok(json_result(serde_json::json!({"status": "expired"})));
                }
                tokio::time::sleep(interval).await;
                if interval < Duration::from_secs(8) {
                    interval += Duration::from_secs(1);
                }
                continue;
            }
            return self.format_hybrid_outcome(outcome, &session_id, &ctx);
        }
    }

    // ---- L2: login-request flow ---------------------------------------

    #[tool(
        description = "Ask the user to add a new login (username + password) for a \
                       given website. Returns a loginUrl. \
                       \
                       MANDATORY NEXT STEP: immediately after this returns, call \
                       `rivault_await_login` with the returned loginRequestId. Do \
                       NOT stop and wait for the user; `rivault_await_login` \
                       blocks internally until submission and returns the \
                       decrypted password plus the cleartext website. The login \
                       is also saved to the vault for reuse."
    )]
    async fn rivault_request_login(
        &self,
        Parameters(RequestLoginArgs {
            website,
            reason,
            callback_session_id,
        }): Parameters<RequestLoginArgs>,
    ) -> Result<CallToolResult, McpError> {
        let resp = self
            .upstream
            .create_login_request(
                &website,
                reason.as_deref(),
                callback_session_id.as_deref(),
            )
            .await
            .map_err(|e| upstream_err("rivault_request_login", e))?;
        let req_id = resp.login_request_id.clone();
        Ok(json_result(serde_json::json!({
            "loginRequestId": resp.login_request_id,
            "loginUrl": resp.login_url,
            "expiresAt": resp.expires_at,
            "agentMessage": resp.agent_message,
            "nextAction": {
                "tool": "rivault_await_login",
                "args": {"login_request_id": req_id},
                "instruction": "Call rivault_await_login NOW. Do not wait for the user; await blocks until the user submits.",
            },
        })))
    }

    #[tool(
        description = "Poll a pending login-request. When submitted, decrypts the \
                       password envelope and returns it as `value`. The release is \
                       logged so the password is redacted from this runtime's \
                       transcript when the task ends."
    )]
    async fn rivault_poll_login(
        &self,
        Parameters(PollLoginArgs { login_request_id }): Parameters<PollLoginArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let outcome = self
            .upstream
            .poll_login_status(&login_request_id)
            .await
            .map_err(|e| upstream_err("rivault_poll_login", e))?;
        let session_id = mcp_session_id(&ctx);
        match outcome {
            LoginStatusOutcome::Pending => {
                Ok(json_result(serde_json::json!({"status": "pending"})))
            }
            LoginStatusOutcome::Denied => {
                Ok(json_result(serde_json::json!({"status": "denied"})))
            }
            LoginStatusOutcome::Expired => {
                Ok(json_result(serde_json::json!({"status": "expired"})))
            }
            LoginStatusOutcome::Other(s) => Ok(json_result(serde_json::json!({"status": s}))),
            LoginStatusOutcome::Submitted {
                plaintext,
                login_item_id,
                website,
            } => {
                let value = String::from_utf8_lossy(&plaintext).into_owned();
                self.log_release(Tier::L2, &value, &session_id, &ctx)
                    .map_err(|e| internal_err("log release", e))?;
                Ok(json_result(serde_json::json!({
                    "status": "submitted",
                    "value": value,
                    "loginItemId": login_item_id,
                    "website": website,
                })))
            }
        }
    }

    #[tool(
        description = "Wait for the user to submit a new-login request, polling \
                       internally with 3-8s backoff for up to 3 minutes. Same \
                       response shape as rivault_poll_login. Prefer this in \
                       runtimes without a background poller."
    )]
    async fn rivault_await_login(
        &self,
        Parameters(PollLoginArgs { login_request_id }): Parameters<PollLoginArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        use std::time::{Duration, Instant};
        let start = Instant::now();
        let timeout = Duration::from_secs(180);
        let mut interval = Duration::from_secs(3);
        let session_id = mcp_session_id(&ctx);
        loop {
            let outcome = self
                .upstream
                .poll_login_status(&login_request_id)
                .await
                .map_err(|e| upstream_err("rivault_await_login", e))?;
            if matches!(outcome, LoginStatusOutcome::Pending) {
                if start.elapsed() >= timeout {
                    return Ok(json_result(serde_json::json!({"status": "expired"})));
                }
                tokio::time::sleep(interval).await;
                if interval < Duration::from_secs(8) {
                    interval += Duration::from_secs(1);
                }
                continue;
            }
            return self.format_login_outcome(outcome, &session_id, &ctx);
        }
    }
}

#[tool_handler]
impl ServerHandler for RivaultMcp {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo and Implementation are #[non_exhaustive], so we
        // can't construct them with a struct literal from outside the
        // rmcp crate. Build via Default and mutate the public fields
        // we care about — same effect, future-compatible.
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2024_11_05;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info.name = "rivault-desktop".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info.server_info.title = Some("Rivault (local)".into());
        info.instructions = Some(
            "Local Rivault MCP. Every retrieval is recorded and redacted from \
             this runtime's transcript when the task ends — you don't need to \
             redact yourself, generate keypairs, or decrypt envelopes; the \
             daemon does all of that. Tool responses are final plaintext.\n\n\
             MANDATORY ORCHESTRATION (do not skip):\n\
             1. BEFORE asking the user for ANY personal data (email, phone, \
                address, name, password, payment info, etc.), call \
                `rivault_check` ONCE per field name. Only ask the user if \
                rivault_check returns no match. Skipping this step is the #1 \
                misuse — the user has Rivault installed specifically so they \
                don't have to retype this data; do not ignore it.\n\
             2. L1 items (sensitivityLevel=1): retrieve via `rivault_get_secret`.\n\
             3. L2 items (sensitivityLevel=2): if you need only ONE item, use \
                `rivault_request_auth` + `rivault_await_auth`. If you need \
                MULTIPLE L2 items, OR a mix of L2 items + missing fields, use \
                `rivault_request_hybrid` + `rivault_await_hybrid` — that's ONE \
                approval link instead of N. Calling `rivault_request_auth` in \
                a loop is misuse.\n\
             4. After EVERY `rivault_request_auth` / `rivault_request_hybrid` \
                / `rivault_request_login` call, you MUST immediately call the \
                matching `rivault_await_*` tool. Do not stop and wait for the \
                user to tell you they approved; do not poll manually; do not \
                return control. The `await` tool blocks internally for up to \
                3 minutes with 3-8s backoff and returns the plaintext when the \
                user approves (or `denied`/`expired`). Forgetting this step is \
                the #2 misuse.\n\
             5. Use `rivault_poll_*` (one-shot) ONLY if you have a runtime \
                that polls in the background for you. If unsure, use `await`."
                .into(),
        );
        info
    }
}

// ---- helpers --------------------------------------------------------------

impl RivaultMcp {
    /// Render a non-pending [`AuthStatusOutcome`] into a tool result + log
    /// the release row when plaintext is present. Shared between
    /// `rivault_poll_auth` (one-shot) and `rivault_await_auth` (blocking
    /// loop) so the response shape and ledger semantics stay identical.
    ///
    /// Callers must filter out `Pending` themselves — this function
    /// assumes the caller has decided not to retry.
    fn format_auth_outcome(
        &self,
        outcome: AuthStatusOutcome,
        session_id: &str,
        ctx: &RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        match outcome {
            AuthStatusOutcome::Pending => Ok(json_result(serde_json::json!({
                "status": "pending",
            }))),
            AuthStatusOutcome::Denied => Ok(json_result(serde_json::json!({
                "status": "denied",
            }))),
            AuthStatusOutcome::Expired => Ok(json_result(serde_json::json!({
                "status": "expired",
            }))),
            AuthStatusOutcome::ApprovedNoEnvelope => Ok(json_result(serde_json::json!({
                "status": "approved_no_envelope",
                "hint": "cache TTL elapsed; re-request auth",
            }))),
            AuthStatusOutcome::Approved {
                plaintext,
                kind,
                username,
                website,
            } => {
                let value = String::from_utf8_lossy(&plaintext).into_owned();
                self.log_release(Tier::L2, &value, session_id, ctx)
                    .map_err(|e| internal_err("log release", e))?;
                Ok(json_result(serde_json::json!({
                    "status": "approved",
                    "type": kind,
                    "value": value,
                    "username": username,
                    "website": website,
                })))
            }
            AuthStatusOutcome::Other(s) => {
                Ok(json_result(serde_json::json!({"status": s})))
            }
        }
    }

    /// Hybrid analogue of [`format_auth_outcome`]. Same shared role.
    fn format_hybrid_outcome(
        &self,
        outcome: HybridStatusOutcome,
        session_id: &str,
        ctx: &RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        match outcome {
            HybridStatusOutcome::Pending => Ok(json_result(serde_json::json!({
                "status": "pending"
            }))),
            HybridStatusOutcome::Expired => Ok(json_result(serde_json::json!({
                "status": "expired"
            }))),
            HybridStatusOutcome::Other(s) => {
                Ok(json_result(serde_json::json!({"status": s})))
            }
            HybridStatusOutcome::Submitted(submitted) => {
                let mut authorized = serde_json::Map::new();
                for (item_id, item) in submitted.authorized_items {
                    let value = String::from_utf8_lossy(&item.plaintext).into_owned();
                    self.log_release(Tier::L2, &value, session_id, ctx)
                        .map_err(|e| internal_err("log release (auth item)", e))?;
                    authorized.insert(
                        item_id,
                        serde_json::json!({
                            "type": item.kind,
                            "value": value,
                            "username": item.username,
                            "website": item.website,
                        }),
                    );
                }
                let mut form = serde_json::Map::new();
                for (key, bytes) in submitted.form_values {
                    let value = String::from_utf8_lossy(&bytes).into_owned();
                    self.log_release(Tier::L2, &value, session_id, ctx)
                        .map_err(|e| internal_err("log release (form field)", e))?;
                    form.insert(key, serde_json::Value::String(value));
                }
                Ok(json_result(serde_json::json!({
                    "status": "submitted",
                    "authorized": authorized,
                    "form": form,
                    "createdItemIds": submitted.created_item_ids,
                })))
            }
        }
    }

    /// Login analogue of [`format_auth_outcome`].
    fn format_login_outcome(
        &self,
        outcome: LoginStatusOutcome,
        session_id: &str,
        ctx: &RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        match outcome {
            LoginStatusOutcome::Pending => Ok(json_result(serde_json::json!({
                "status": "pending"
            }))),
            LoginStatusOutcome::Denied => Ok(json_result(serde_json::json!({
                "status": "denied"
            }))),
            LoginStatusOutcome::Expired => Ok(json_result(serde_json::json!({
                "status": "expired"
            }))),
            LoginStatusOutcome::Other(s) => {
                Ok(json_result(serde_json::json!({"status": s})))
            }
            LoginStatusOutcome::Submitted {
                plaintext,
                login_item_id,
                website,
            } => {
                let value = String::from_utf8_lossy(&plaintext).into_owned();
                self.log_release(Tier::L2, &value, session_id, ctx)
                    .map_err(|e| internal_err("log release", e))?;
                Ok(json_result(serde_json::json!({
                    "status": "submitted",
                    "value": value,
                    "loginItemId": login_item_id,
                    "website": website,
                })))
            }
        }
    }

    /// Build a release event for the just-retrieved plaintext and hand it
    /// to the daemon's existing `accept` flow. That validates the
    /// transcript path against the runtime's allowlist, inserts the
    /// ledger row, and arms the watcher + hard cap; from there the
    /// existing scrub lifecycle takes over.
    fn log_release(
        &self,
        tier: Tier,
        plaintext: &str,
        session_id: &str,
        ctx: &RequestContext<RoleServer>,
    ) -> anyhow::Result<()> {
        let release_id = uuid::Uuid::new_v4().to_string();
        let value_hash = hex::encode(Sha256::digest(plaintext.as_bytes()));
        // Per-session runtime: each runtime registers a different MCP URL
        // with a `?runtime=` query param (claude_code, codex,
        // claude_desktop). At tool-call time we read that param off the
        // request URI and use it for transcript-path resolution + the
        // ledger row's runtime tag. Fallback: the daemon's bake-in
        // default (`self.runtime`), which is set at server-mount time.
        let runtime = runtime_from_request(ctx).unwrap_or_else(|| self.runtime.clone());
        let transcript_paths = resolve_transcript_paths(&runtime);
        let released_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();

        let event = ReleaseEvent {
            release_id,
            session_id: session_id.to_string(),
            tier,
            agent_runtime: runtime,
            // mcp_mode is None: the daemon (not the cloud MCP server)
            // performed the retrieval. The existing variants describe
            // who decrypted on the upstream side, which is moot here.
            mcp_mode: None,
            value_plaintext: Some(plaintext.to_string()),
            value_hash,
            encoded_variants: Vec::new(),
            transcript_paths,
            released_at,
            rotation_supported: false,
        };

        // Channel::Localhost — the daemon's existing label for "came in
        // over 127.0.0.1 HTTP". The MCP path is a sibling of /release
        // on the same listener, so the label is already accurate.
        match self.daemon.clone().accept(event, Channel::Localhost) {
            Ok(_release_id) => Ok(()),
            Err(e) => {
                // accept() rejects when the resolved transcript path is
                // outside the runtime's allowlist. Log so the user sees
                // it — but don't fail the tool call: the plaintext has
                // already crossed to the agent and refusing now would
                // both fail the user's task AND leave nothing in the
                // ledger to scrub later.
                tracing::warn!(
                    error = %e,
                    "release log failed (transcript path outside allowlist?); \
                     value will not be scrubbed"
                );
                Ok(())
            }
        }
    }
}

fn mcp_session_id(ctx: &RequestContext<RoleServer>) -> String {
    ctx.extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.headers.get("mcp-session-id"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("mcp-{}", uuid::Uuid::new_v4()))
}

/// Per-session runtime detection.
///
/// Each agent runtime is registered with a different MCP URL — the
/// install commands write `http://127.0.0.1:<port>/mcp?runtime=claude_code`
/// (or `codex` / `claude_desktop`). At tool-call time we read that
/// query param off the request URI so the same daemon binary can serve
/// multiple runtimes correctly: the right transcript directory is used
/// for path resolution, and the ledger row's `agent_runtime` matches
/// the agent that actually made the call.
///
/// Returns None when the param is absent or unrecognised, so the caller
/// can fall back to the daemon's bake-in default.
fn runtime_from_request(ctx: &RequestContext<RoleServer>) -> Option<AgentRuntime> {
    let parts = ctx.extensions.get::<axum::http::request::Parts>()?;
    let query = parts.uri.query()?;
    let value = query.split('&').find_map(|kv| {
        let mut it = kv.splitn(2, '=');
        let k = it.next()?;
        let v = it.next()?;
        if k == "runtime" {
            Some(v)
        } else {
            None
        }
    })?;
    parse_runtime(value)
}

fn parse_runtime(s: &str) -> Option<AgentRuntime> {
    match s {
        "claude_code" | "claude-code" | "claudecode" => Some(AgentRuntime::ClaudeCode),
        "claude_desktop" | "claude-desktop" | "claudedesktop" => {
            Some(AgentRuntime::ClaudeDesktop)
        }
        "codex" => Some(AgentRuntime::Codex),
        "openclaw" => Some(AgentRuntime::Openclaw),
        "custom" => Some(AgentRuntime::Custom),
        _ => None,
    }
}

fn upstream_err(op: &str, e: anyhow::Error) -> McpError {
    McpError::internal_error(format!("{op}: {e:#}"), None)
}

fn internal_err(ctx: &str, e: anyhow::Error) -> McpError {
    McpError::internal_error(format!("{ctx}: {e:#}"), None)
}

fn json_result(value: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![Content::text(
        serde_json::to_string(&value).unwrap_or_else(|_| "{}".into()),
    )])
}
