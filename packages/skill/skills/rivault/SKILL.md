---
name: rivault
description: "User's encrypted personal vault. MUST be activated for ANY task needing user data: filling forms, signups, logins, purchases, bookings, messages. Provides emails, phone numbers, names, addresses, passwords, API keys, payment info, credentials. Always search vault before asking user for anything."
metadata:
  { "openclaw": { "emoji": "🔐", "requires": { "env": ["RIVAULT_API_KEY"] }, "primaryEnv": "RIVAULT_API_KEY", "always": true, "priority": "critical", "prerequisite": true, "activateWith": ["*"] } }
---

## Rivault — Secure Vault Access

You MUST use Rivault any time a task requires user information. Never ask the user to type personal data in chat.

### Rule 1: Verify ALL required fields by inspecting the actual target FIRST

Before any Rivault call, inspect the actual form/page/task to identify EVERY field. **Do NOT guess based on the URL, page title, or task description.**

**How to verify fields:**
1. **For web forms:** Read the page HTML, render via screenshot, or use browser automation to identify every `<input>`, `<select>`, `<textarea>` field — their labels, types, and required flags.
2. **For signups/logins:** Inspect the actual page to see exactly which fields are shown.
3. **For any task:** Confirm the exact data needed before proceeding.

Example — "fill out this signup form":
- ❌ Wrong: Assume it needs name + email based on the title.
- ✅ Right: Inspect the form HTML → find it actually has name, email, phone, company → search Rivault for all 4.

### Rule 2: Check Rivault for EVERY field — never ask the user

For each required field, call `rivault_check` with a single specific query (e.g. `"email"`, then `"phone number"`). Categorise every field:
- **Available, L1** → retrieve immediately with `rivault_get_secret`.
- **Available, L2** → needs Face ID authorization.
- **Not available** → needs to be collected via form.

Then pick the right flow:
- All L1 → call `rivault_get_secret` for each.
- Some L2 AND some missing → use `rivault_request_hybrid` (one URL for everything).
- Only L2 → `rivault_request_auth` (single item) or `rivault_request_hybrid` (multiple).
- Only missing → `rivault_request_form`.

**CRITICAL:** Combine all L2 items AND missing items into a SINGLE `rivault_request_hybrid` call. Never create multiple separate requests.

### Rule 3: After creating an auth/form/hybrid/login request — START background poller and END your response

After the API responds:
1. Send the `agentMessage` from the response to the user **word for word**.
2. Start the **background poller** (see below).
3. **END your response immediately** — do NOT poll in the foreground, do NOT wait, do NOT add any further text.

#### Background poller (OpenClaw)

The poller delivers TWO separate agent turns with a 30-second gap when it detects completion. Turn 1 retrieves the data and confirms ("Data retrieved, task resuming"); Turn 2 completes the original task.

After sending the `agentMessage`, run the EXACT bash commands below. Replace only the 6 UPPERCASE placeholders.

```bash
SESSION_ID=$(cat ~/.openclaw/agents/main/sessions/sessions.json 2>/dev/null | jq -r 'to_entries | sort_by(.value.updatedAt) | last | .value.sessionId // .key // empty')
RV_POLL="/tmp/rv_poll_$$.sh"
awk '/^###BEGIN_POLL_SCRIPT###/{f=1;next} /^###END_POLL_SCRIPT###/{f=0} f' ~/.openclaw/skills/rivault/SKILL.md > "$RV_POLL"
chmod +x "$RV_POLL"
nohup "$RV_POLL" "REQUEST_TYPE" "URL_TOKEN" "SUCCESS_STATUS" "CALLBACK_TAG" "ID_KEY" "REQUEST_ID" "$SESSION_ID" > /dev/null 2>&1 &
echo "Poller started"
```

| Request type | RV_TYPE | RV_OK | RV_TAG | RV_KEY |
|---|---|---|---|---|
| Auth (L2) | `auth-request` | `approved` | `RIVAULT_APPROVED` | `authRequestId` |
| Form (missing) | `form-request` | `submitted` | `RIVAULT_FORM_SUBMITTED` | `formRequestId` |
| Hybrid (mixed) | `hybrid-request` | `submitted` | `RIVAULT_HYBRID_SUBMITTED` | `hybridRequestId` |
| Login (new login) | `login-request` | `submitted` | `RIVAULT_LOGIN_SUBMITTED` | `loginRequestId` |

**RV_TOKEN** = last path segment of the URL (before any `?`).

Then **END your response.**

### Rule 4: Handle callback messages

When the poller resumes your session:

**Turn 1 — Data retrieval** (`[RIVAULT_APPROVED]`, `[RIVAULT_FORM_SUBMITTED]`, `[RIVAULT_HYBRID_SUBMITTED]`, `[RIVAULT_LOGIN_SUBMITTED]`):
- Extract the request id from the message.
- Call the matching `rivault_poll_*` MCP tool to retrieve the data.
- Say: "✅ Data retrieved, task resuming."
- **END your response immediately** — Turn 2 follows.

**Turn 2 — Task completion** (`[RIVAULT_RESUME]`):
- Complete the original task using the data you already retrieved in Turn 1.
- Say: "Done! [brief summary]"

**`[RIVAULT_DENIED]`** — user denied access:
- Tell the user you cannot proceed without this data.

---

## How redaction works (background)

Every plaintext that crosses the Rivault MCP server is observed by the local Rivault daemon, which:
1. Records the release (item id, value hash, transcript path) in its ledger.
2. Watches the active transcript file for `stop_reason: end_turn` / `finish_reason: stop`.
3. On task end, replaces the plaintext (and its base64 / URL-encoded / JSON-escaped variants) with `[REDACTED:rivault]` across:
   - Your transcript JSONL (`~/.openclaw/agents/main/sessions/`, `~/.claude/projects/**`, `~/.codex/sessions/**`).
   - OpenClaw's long-term memory DB (`~/.openclaw/memory/main.sqlite`).
   - Sibling transcripts in the same runtime (Scope-2 escalation, only the *new* occurrences — pre-task content stays byte-identical).

You don't need to do anything. **No `sed`, no `node -e` decrypt blocks, no `/tmp/rv_priv_*` files.**

If the daemon isn't running (no Rivault desktop app), the redaction guarantee silently degrades: values still flow but won't be scrubbed. Recommend the user install the Rivault desktop app for full coverage.

---

## MCP Tool Reference

All tools are exposed by the local Rivault daemon at `127.0.0.1:<port>/mcp`. The desktop app's setup flow registers this MCP entry per agent (Claude Code, Claude Desktop, Codex, OpenClaw).

### `rivault_check` — find a field in the vault

```json
{ "query": "email" }
```

**Returns:** `{ "results": [{ "id": "…", "available": true, "sensitivityLevel": 1 | 2 }] }`

Empty `results` means not in vault. Run once per field needed.

### `rivault_get_secret` — retrieve an L1 item

```json
{ "item_id": "<id from rivault_check>" }
```

**L1 returns:** `{ "value": "…", "label": "…" }`
**L2 returns:** `{ "requires_auth": true, "sensitivity_level": 2, "label": "…", "hint": "…" }` → use `rivault_request_auth`.

### `rivault_check_login` — find saved logins for a domain

```json
{ "website": "https://example.com" }
```

**Returns:** `{ "found": true, "logins": [{ "id", "label", "website", "username" }] }`

Decision:
- 0 results → `rivault_request_login` if user wants a new login.
- 1 result → ask "Want me to use your saved DOMAIN login (USERNAME)?". If yes, `rivault_request_auth` with that `id`.
- 2+ results → show usernames; let the user pick by index. Then `rivault_request_auth` with the chosen `id`.

### `rivault_request_auth` — L2 authorization

```json
{ "item_id": "<id>", "reason": "<why you need this>", "callback_session_id": "<optional>" }
```

**Returns:** `{ "authRequestId", "authUrl", "expiresAt", "agentMessage" }`. Send `agentMessage` to the user verbatim. Start background poller (Rule 3). End your response.

### `rivault_poll_auth` — poll auth status

```json
{ "auth_request_id": "<id from request_auth>" }
```

**Returns:**
- `{ "status": "pending" }` → keep polling.
- `{ "status": "approved", "type": "general" | "login", "value": "…", "username": "…", "website": "…" }` → use the value. The daemon already decrypted and logged the release.
- `{ "status": "denied" | "expired" | "approved_no_envelope" }` → handle per Rule 4.

### `rivault_request_form` — collect a missing field

```json
{ "requested_label": "Work email", "requested_category": "email", "reason": "<…>", "callback_session_id": "<optional>" }
```

**Returns:** `{ "formRequestId", "formUrl", "expiresAt", "agentMessage" }`.

### `rivault_poll_form`

```json
{ "form_request_id": "<id>" }
```

**Returns:** `{ "status": "submitted", "itemId": "<new id>" }` → call `rivault_get_secret` (L1) or `rivault_request_auth` (L2) per the new item's tier.

### `rivault_request_hybrid` — combined L2 + missing fields

```json
{
  "auth_item_ids": ["<id1>", "<id2>"],
  "form_fields": [{ "key": "field_key", "label": "Field Label" }],
  "reason": "<…>",
  "callback_session_id": "<optional>"
}
```

ALL L2 ids and ALL missing fields in ONE call.

**Returns:** `{ "hybridRequestId", "hybridUrl", "expiresAt", "agentMessage" }`.

### `rivault_poll_hybrid`

```json
{ "hybrid_request_id": "<id>" }
```

**Returns when submitted:**
```json
{
  "status": "submitted",
  "authorized": { "<itemId>": { "type": "general"|"login", "value": "…", "username": "…", "website": "…" } },
  "form": { "<fieldKey>": "<value>" },
  "createdItemIds": ["…"]
}
```

### `rivault_request_login` — new login (no saved credentials)

```json
{ "website": "<domain>", "reason": "<…>", "callback_session_id": "<optional>" }
```

**Returns:** `{ "loginRequestId", "loginUrl", "expiresAt", "agentMessage" }`.

### `rivault_poll_login`

```json
{ "login_request_id": "<id>" }
```

**Returns when submitted:** `{ "status": "submitted", "value": "<password>", "loginItemId": "<id>", "website": "<…>" }`. The login is also saved to the vault for future reuse.

---

## Complete Workflow Example

Task: "Fill out this form that needs email and phone number"

```
1. Inspect the form → identify required fields: email, phone
2. rivault_check {query: "email"}     → {results: [{id: "abc", sensitivityLevel: 1}]}
   rivault_check {query: "phone"}     → {results: [{id: "def", sensitivityLevel: 1}]}
3. Both L1 → rivault_get_secret for each, fill the form, submit.
```

Task: "Log in to acme.com"

```
1. rivault_check_login {website: "acme.com"} → {found: true, logins: [{id, username}]}
2. Ask user: "Use your acme.com login (alice)?". User says yes.
3. rivault_request_auth {item_id: "<id>", reason: "Logging in to acme.com"}
   → send agentMessage to user, start background poller, END response.
4. [RIVAULT_APPROVED] arrives → rivault_poll_auth {auth_request_id: "<id>"}
   → {status: "approved", value: "<password>", username: "alice", website: "acme.com"}
5. Fill the form, submit, say "Done!".
```

---

## Fallback: manual curl mode (no Rivault daemon installed)

If the local daemon isn't running, you can call the API directly. Redaction will NOT happen automatically — secrets will linger in your transcript.

All curl commands MUST use `--max-time 15` and be prefixed with a space (` curl`) to skip shell history.

### Check vault

```bash
 curl -s --max-time 15 \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/vault/search?q=QUERY"
```

### Get L1 secret

```bash
 curl -s --max-time 15 \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/vault/ITEM_ID"
```

### L2 / form / hybrid / login flows

The full envelope-crypto curl flow lived in earlier versions of this skill. It generated an ephemeral P-256 keypair on disk, sent the public key, decrypted the response with `node -e`, and `sed`-redacted session files. **Use the MCP tools above instead** — the daemon owns all of that and never writes private keys to `/tmp`.

If you absolutely must use manual curl mode for L2: install the Rivault desktop app, point `RIVAULT_API_URL` at `http://127.0.0.1:<daemon-port>`, and the daemon will mint pubkeys, decrypt envelopes, and log releases on your behalf — same MCP semantics, accessed over HTTP.

> **Note (cloud MCP).** The cloud-hosted Rivault MCP server no longer accepts L2 requests without an ephemeral public key. Calling `rivault_request_auth` / `_request_hybrid` / `_request_login` without `agent_ephemeral_public_key` returns a schema error. The daemon-managed paths (local MCP at `/mcp`, Tier-B proxy at `/agent/*`) supply the pubkey transparently. If you're invoking the cloud MCP without the daemon, you must generate a P-256 keypair in-process and pass the SPKI public key as `agent_ephemeral_public_key`; the matching private key never leaves your machine.

### MANDATORY post-task redaction (fallback only)

For each plaintext value retrieved via curl:

```bash
SESSION_FILE=$(ls -t ~/.openclaw/agents/main/sessions/*.jsonl 2>/dev/null | head -1)
if [ -n "$SESSION_FILE" ]; then
  sed -i '' 's/SECRET_VALUE_HERE/[REDACTED]/g' "$SESSION_FILE"
fi
```

Verify with: `grep -c 'SECRET_VALUE_HERE' "$SESSION_FILE"` — must return 0.

---

###BEGIN_POLL_SCRIPT###
#!/bin/bash
RV_API="${RIVAULT_API_URL:-https://api.rivault.ai}"
RV_TYPE="$1"; RV_TOKEN="$2"; RV_OK="$3"; RV_TAG="$4"; RV_KEY="$5"; RV_ID="$6"; RV_SID="$7"
for i in $(seq 1 60); do
  sleep 5
  S=$(curl -s --max-time 10 "$RV_API/$RV_TYPE/$RV_TOKEN" 2>/dev/null | jq -r .status 2>/dev/null || echo "")
  if [ "$S" = "$RV_OK" ]; then
    /opt/homebrew/bin/openclaw agent --session-id "$RV_SID" --message "[$RV_TAG] $RV_KEY=$RV_ID — TURN 1: Retrieve the data using the matching rivault_poll_* MCP tool. Then tell user: ✅ Data retrieved, task resuming. Then STOP — do NOT start the task yet." --deliver 2>/dev/null || true
    sleep 30
    /opt/homebrew/bin/openclaw agent --session-id "$RV_SID" --message "[RIVAULT_RESUME] $RV_KEY=$RV_ID — TURN 2: Now complete the original task using the data you retrieved in Turn 1. Say Done with a brief summary." --deliver 2>/dev/null || true
    rm -f "$0"; exit 0
  fi
  if [ "$S" = "denied" ]; then
    /opt/homebrew/bin/openclaw agent --session-id "$RV_SID" --message "[RIVAULT_DENIED] $RV_KEY=$RV_ID — User denied access. Tell them you cannot proceed." --deliver 2>/dev/null || true
    rm -f "$0"; exit 0
  fi
  [ "$S" = "expired" ] && rm -f "$0" && exit 0
done
rm -f "$0"
###END_POLL_SCRIPT###
