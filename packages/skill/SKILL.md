---
name: rivault
version: 0.3.0
updatedAt: 2026-05-12T23:00:00Z
description: "User's encrypted personal vault. MUST be activated for ANY task needing user data: filling forms, signups, logins, purchases, bookings, messages. Provides emails, phone numbers, names, addresses, passwords, API keys, payment info, credentials. Always search vault before asking user for anything."
metadata:
  { "openclaw": { "emoji": "🔐", "requires": { "env": ["RIVAULT_API_KEY"] }, "primaryEnv": "RIVAULT_API_KEY", "always": true, "priority": "critical", "prerequisite": true, "activateWith": ["*"] } }
---

<!--
  Maintaining version + updatedAt:
  - Bump `version` (semver) on ANY substantive change to this file
    (orchestration rules, security guidance, API references, scripts).
  - Set `updatedAt` to the commit's UTC timestamp in ISO 8601.
  - Keep `packages/skill/package.json` `version` in sync — that field
    drives the `openclaw plugins info rivault` output and the plugin
    install records in `~/.openclaw/openclaw.json`.
  - Future automation: `scripts/bump-skill.sh patch|minor|major` will
    bump both files together. Until that lands, update by hand.
-->


## Rivault — Secure Vault Access

You MUST use Rivault any time a task requires user information. Never ask the user to type personal data in chat.

### 🚨 Rule 0 (READ THIS FIRST EVERY TASK): Use the plugin tools — never bash curl

**If `rivault_check`, `rivault_get_secret`, `rivault_request_hybrid`, `rivault_poll_hybrid`, etc. are available as tools (they are in OpenClaw — the plugin is loaded as v0.2.6+), you MUST use them. Bash curl is a fallback for environments that do NOT have the plugin (raw bash testing only).**

Why this rule exists: agents in long sessions sometimes remember an earlier failure ("rivault_poll_hybrid timed out last hour, I'll just use curl") and fall back to Mode B. **DO NOT DO THIS.** The plugin has been fixed multiple times in this session — most recently a Content-Length header bug (v0.2.5) and a keypair-consumption race (v0.2.5). The bash fallback path BYPASSES the desktop daemon entirely, which means:

- The daemon never sees the release → **no ledger row in the desktop app**.
- The plaintext is **not redacted from the transcript** when the task ends.
- The background poller is never spawned → **the user gets no auto-resume** when they approve.

If a previous `rivault_*` tool call failed in THIS session, that's stale information. Try it again. If it fails a second time consecutively (not from memory — from a fresh attempt RIGHT NOW), tell the user "the plugin is failing — please run `openclaw gateway restart` and try again" and stop. Do not silently fall back to bash.

The bash sections (3-12 below) exist for documentation and for Mode B fallback when the plugin is genuinely unavailable — they are NOT a "try this if the plugin seems slow" path.

### Rule 1: Verify ALL required fields by inspecting the actual target FIRST

Before making any Rivault API call, you MUST inspect the actual form/page/task to identify EVERY field. **Do NOT guess based on the URL, page title, or task description.** You must verify definitively.

**How to verify fields:**
1. **For web forms:** Read the page HTML, render via screenshot, or use browser automation to identify every `<input>`, `<select>`, `<textarea>` field — their labels, types, and whether they are required
2. **For signups/logins:** Inspect the actual page to see exactly which fields are shown
3. **For any task:** Confirm the exact data needed before proceeding

**Only after you have a verified, complete list of fields** should you proceed to search Rivault.

Example — "fill out this signup form":
- ❌ Wrong: Assume it needs name + email based on the title, search Rivault immediately
- ✅ Right: Inspect the form HTML/screenshot → find it actually has name, email, phone, company → search Rivault for all 4

**Common mistake:** Guessing fields from context instead of inspecting the actual form. This leads to missing fields or searching for fields that don't exist.

### Rule 2: Check Rivault for EVERY field — never ask the user

For each required data field, check Rivault using the Check API (section 1 below). Check one field at a time (e.g., "email", then "phone number"). After checking, categorize every field:
- **Available, L1** → retrieve immediately with Get Secret (section 2)
- **Available, L2** → needs Face ID authorization
- **Not available** → needs to be collected via form

Then pick the right flow:
- All found as L1 → retrieve all and complete the task
- Some L2 AND some missing → use **Hybrid** (section 7) — one link for everything
- Only L2 (nothing missing) → use **Request Auth** (section 3) for single item, or **Hybrid** for multiple
- Only missing (nothing in vault) → use **Request Form** (section 5)

**CRITICAL:** Always combine all L2 items AND all missing items into a SINGLE request. Never create multiple separate requests.

### Rule 2.5: Always pass `website` when the task is tied to a specific site

Any `rivault_get_secret`, `rivault_request_auth`, `rivault_request_form`, or `rivault_request_hybrid` call MUST include the `website` parameter whenever the task is tied to a specific site (a signup, login, purchase, form fill, etc. on a known domain). In curl bodies, set `"website":"DOMAIN"`; in JS plugin tool calls, pass `website: "DOMAIN"`.

`DOMAIN` should be the site you're using the data on — eTLD+1 is preferred (e.g. `"amazon.com"`) but URLs and subdomains work too; the server normalizes to root domain. Examples:

- Filling a signup at `https://www.airbnb.com/host/welcome` → `"website":"airbnb.com"`
- Buying on Nike's mobile site → `"website":"nike.com"`
- Pure CLI task with no website (e.g. "what's my GitHub username?") → omit `website`.

What this does:
- For `rivault_get_secret` (L1) and `rivault_request_auth` (L2): appends `DOMAIN` to the vault item's **Used on** history. The user can audit every site their data has been used on.
- For `rivault_request_form` and `rivault_request_hybrid`: pre-populates the **Added for** field on the form page so newly created items are tagged with the right origin without the user typing it.

Same `website` value across multiple calls in the same task is fine — the server dedupes. Pass it on every call; the user's audit log is only as good as what agents send.

### Rule 3: After creating the request — send the URL, END your response

OpenClaw flushes the agent's text output to the user as a single message at the **end of the turn**. Any tool call that blocks for minutes inside the turn (e.g. waiting for the user to approve on their phone) also blocks the auth URL from reaching the user — they'd see nothing for the entire timeout and the flow deadlocks. That is why the JS plugin does **not** expose any `rivault_await_*` tools.

After calling any `rivault_request_auth` / `rivault_request_hybrid` and getting the API response:

1. Send the `agentMessage` from the response to the user **word for word**. The user must see the auth URL right now.
2. **END your response immediately.** Do NOT call any more tools. Do NOT manually poll. Do NOT ask the user to reply when they approve.
3. The `request_*` tool has already spawned a detached background poller. When the user approves on their phone, the poller calls `openclaw agent --deliver` and resumes this session in a NEW turn with a `[RIVAULT_APPROVED]` (or `[RIVAULT_HYBRID_SUBMITTED]`) message containing the request ID.

**Common mistakes to avoid:**
- ❌ Calling `rivault_poll_*` (or any other tool) in the same response — blocks the URL from being delivered to the user.
- ❌ Asking the user to reply "done" when they approve — the poller resumes automatically.
- ❌ Looping or sleeping in bash inside the agent turn — same blocking problem.
- ❌ Adding any text after the `agentMessage` — OpenClaw concatenates all output into one WhatsApp message, which the user then sees AFTER approval instead of before.

### Rule 4: Handle the resume callbacks in NEW turns

The background poller resumes your session with a system message when it detects approval. **Two-step delivery**: you get a NOTIFY callback first (so the user sees "✅ Authorization complete" right away in WhatsApp), then ~4s later a SUBMITTED callback with the actual work. Each callback lands in a separate turn — handle one at a time and END your response immediately so OpenClaw flushes to WhatsApp between turns.

**Quick-notify callbacks** — send a single user-facing message and end the turn. Do NOT call any tools yet.

- **`[RIVAULT_APPROVED_NOTIFY]`** → send: `"✅ Authorization complete — retrieving now."` and END.
- **`[RIVAULT_HYBRID_NOTIFY] ...`** → send: `"✅ Authorization complete — filling the form now."` and END. (The callback message includes the exact text to send.)

**Work callbacks** — retrieve, complete the task, redact, end.

- **`[RIVAULT_APPROVED] authRequestId=<id> itemId=<id>`** → call `rivault_poll_auth` with the IDs to retrieve the decrypted value, complete the task, run redaction (Security section), tell the user "Done — [one sentence summary]", end.
- **`[RIVAULT_HYBRID_SUBMITTED] hybridRequestId=<id>`** → call `rivault_poll_hybrid`, complete the task, run redaction, tell the user "Done — [one sentence summary]", end.
- **`[RIVAULT_FORM_SUBMITTED] formRequestId=<id>`** → call `rivault_poll_form` to get the new `itemId`, then `rivault_get_secret` (L1) or `rivault_request_auth` (L2) to retrieve, complete the task, redact, "Done — …", end.

**Failure callbacks**

- **`[RIVAULT_DENIED]`** — tell the user you cannot proceed without this data, end.
- **`[RIVAULT_HYBRID_EXPIRED]` / `[RIVAULT_AUTH_EXPIRED]`** — tell the user the link expired, offer to send a fresh one by calling `rivault_request_*` again with the same item ids.

### Manual fallback (Mode B — bash curl, no JS plugin)

If you are running outside the OpenClaw plugin (e.g. raw bash testing), the curl flow in sections 3-8 below still works. In that mode you DO need to poll manually — the JS plugin's spawn-poller pattern is unavailable.

### CRITICAL: Execute curl via bash — never fabricate responses

- Every API call MUST be run as a real bash command. Read the real response.
- NEVER fabricate URLs, tokens, IDs, or `agentMessage` values.
- NEVER construct a Rivault URL yourself. The URL comes only from the API response.
- The `agentMessage` from the API response is the user-facing message. Send it word for word.

---

## Environment

**Mode B preamble — auto-discover the Rivault desktop daemon and route through it when running.** When the Rivault desktop app is installed and signed in, it writes a discovery file at `~/Library/Application Support/Rivault/daemon.json` (mode 0600) with the localhost port it's bound to. Routing curls through that local port means the daemon (a) records every release in its ledger and (b) feeds the plaintext into the cross-runtime scanner that redacts it across every agent transcript on disk — including leaks from exec output (`browser-use type "$VALUE"` etc.) that the agent's own redaction step can't catch in time.

Run this block ONCE at the top of any Rivault-using bash flow before any curl:

```bash
DAEMON_JSON="${HOME}/Library/Application Support/Rivault/daemon.json"
if [ -z "${RIVAULT_API_URL:-}" ] && [ -r "$DAEMON_JSON" ]; then
  # Use jq (already required for the other curl pipelines below). The
  # earlier awk parser silently returned garbage when the file was
  # pretty-printed differently than expected; jq fails closed and the
  # `case` validates the result is a 1-5 digit number in the IANA
  # registered/dynamic ranges before we ever bind it into the URL.
  PORT=$(jq -r '.http_port // empty' "$DAEMON_JSON" 2>/dev/null)
  case "$PORT" in
    [1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]|[1-5][0-9][0-9][0-9][0-9]|6[0-4][0-9][0-9][0-9]|65[0-4][0-9][0-9]|655[0-2][0-9]|6553[0-5])
      export RIVAULT_API_URL="http://127.0.0.1:$PORT"
      ;;
  esac
fi
export RIVAULT_API_URL="${RIVAULT_API_URL:-https://api.rivault.ai}"
```

After this, every curl below uses `$RIVAULT_API_URL` and automatically routes through the daemon if it's running, the public API otherwise. No other change needed.

- `RIVAULT_API_KEY` (required) — API key
- `RIVAULT_API_URL` (optional) — defaults to the daemon URL if discovered, else `https://api.rivault.ai`
- `RIVAULT_RETURN_URL` (optional) — deep link for returning user to chat app after authorization. If set, include as `"returnUrl"` in POST request bodies. Per-platform values:
  - WhatsApp: `whatsapp://` (opens the app to the user's last chat)
  - Telegram: `tg://` (opens the app to the user's last chat)

### Sensitivity Levels
- **L1 (Agent-accessible)**: Agent retrieves directly via API key. Encrypted at rest, redacted from agent memory/logs after task completion.
- **L2 (Requires Face ID)**: Requires user Face ID authorization. Encrypted end-to-end (envelope crypto: ECDH-P256 + HKDF-SHA256 + AES-256-GCM); the Rivault server stores only ciphertext. Redacted from agent memory/logs after task completion.

---

## Envelope crypto: keypair generation + decryption (used by sections 3, 4, 7, 8, 10, 11, 12)

L2 retrieval is end-to-end encrypted between the user's mobile and your skill process. Every auth/hybrid/login request requires an ephemeral P-256 keypair generated locally before the request and used to decrypt the response after.

### Generate ephemeral keypair (run BEFORE the request curl)

```bash
PRIV_FILE_TMP="/tmp/rv_priv_pending_$$"
RV_PUBKEY=$(node -e "
const c=require('crypto'),fs=require('fs');
const kp=c.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
fs.writeFileSync(process.argv[1], kp.privateKey.export({format:'der',type:'pkcs8'}));
fs.chmodSync(process.argv[1], 0o600);
process.stdout.write(kp.publicKey.export({format:'der',type:'spki'}).toString('base64'));
" "$PRIV_FILE_TMP")
```

After the create curl returns and you have the `authRequestId` (or `hybridRequestId` / `loginRequestId`), rename the private-key file so the decrypt step can find it:

```bash
mv "$PRIV_FILE_TMP" "/tmp/rv_priv_$REQUEST_ID"
```

### Decrypt envelope (after polling /status, when status is approved/submitted and `envelope` is present)

```bash
PLAINTEXT=$(echo "$RESP" | node -e "
const c=require('crypto'),fs=require('fs');
const r=JSON.parse(fs.readFileSync(0,'utf8'));
if(!r.envelope){process.stderr.write('no envelope\n');process.exit(1)}
const e=r.envelope;
const priv=c.createPrivateKey({key:fs.readFileSync(process.argv[1]),format:'der',type:'pkcs8'});
const peer=c.createPublicKey({key:Buffer.from(e.mobileEphemeralPublicKey,'base64'),format:'der',type:'spki'});
const shared=c.diffieHellman({privateKey:priv,publicKey:peer});
const key=Buffer.from(c.hkdfSync('sha256',shared,Buffer.alloc(0),Buffer.from('rivault-envelope-v1'),32));
const iv=Buffer.from(e.iv,'base64');
const ct=Buffer.from(e.ciphertext,'base64');
const tag=ct.subarray(ct.length-16);
const body=ct.subarray(0,ct.length-16);
const d=c.createDecipheriv('aes-256-gcm',key,iv);
d.setAuthTag(tag);
process.stdout.write(Buffer.concat([d.update(body),d.final()]).toString('utf8'));
" "/tmp/rv_priv_$REQUEST_ID")
rm -f "/tmp/rv_priv_$REQUEST_ID"
```

The decrypted plaintext is the secret value (password for login items, raw value for general items). For login items, `$RESP` also carries `username` and `website` cleartext alongside the envelope.

**Cleanup**: always `rm -f "/tmp/rv_priv_$REQUEST_ID"` after decryption (success or failure). Stale private-key files are also swept by the post-task redaction step.

---

## API Reference

All curl commands MUST use `--max-time 15` and be prefixed with a space (` curl`) to skip shell history.

### 1. Check Vault

```bash
 curl -s --max-time 15 \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/vault/search?q=QUERY"
```

Check for one specific item at a time. QUERY should be a specific field name (e.g., "email", "phone number", "home address").

**Response:** `{ "results": [{ "id": "...", "available": true, "sensitivityLevel": 1 }] }`

Empty results means the item is not in the vault. Run this for EVERY piece of data you need. For example, if you need email and phone, run two checks: one for "email" and one for "phone".

### 2. Get Secret (L1 items)

```bash
 curl -s --max-time 15 \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/vault/ITEM_ID?website=DOMAIN"
```

Pass `?website=DOMAIN` whenever the retrieval is tied to a specific site (Rule 2.5). The server appends `DOMAIN` to the item's **Used on** history. Omit only for site-less tasks.

**L1 response:** `{ "value": "...", "label": "..." }`
**L2 response:** `{ "requires_auth": true, "sensitivity_level": 2, "label": "..." }` → use Request Auth instead.

### 3. Request Auth (L2 items only)

Generate an ephemeral keypair first (see "Envelope crypto" section above), then create the request. After the response, rename the private-key tempfile to `/tmp/rv_priv_$authRequestId` so the poller decrypt step can find it.

```bash
SESSION_ID=$(cat ~/.openclaw/agents/main/sessions/sessions.json 2>/dev/null | jq -r 'to_entries | sort_by(.value.updatedAt) | last | .value.sessionId // .key // empty')

# Generate ephemeral keypair (writes priv to PRIV_FILE_TMP, sets RV_PUBKEY)
PRIV_FILE_TMP="/tmp/rv_priv_pending_$$"
RV_PUBKEY=$(node -e "
const c=require('crypto'),fs=require('fs');
const kp=c.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
fs.writeFileSync(process.argv[1], kp.privateKey.export({format:'der',type:'pkcs8'}));
fs.chmodSync(process.argv[1], 0o600);
process.stdout.write(kp.publicKey.export({format:'der',type:'spki'}).toString('base64'));
" "$PRIV_FILE_TMP")

RESP=$( curl -s --max-time 15 -X POST \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"itemId\":\"ITEM_ID\",\"reason\":\"REASON\",\"website\":\"DOMAIN\",\"agentEphemeralPublicKey\":\"$RV_PUBKEY\",\"callbackSessionId\":\"$SESSION_ID\"}" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/auth-request")

# Move private key to authRequestId-keyed location
RV_ID=$(echo "$RESP" | jq -r '.authRequestId')
mv "$PRIV_FILE_TMP" "/tmp/rv_priv_$RV_ID"
echo "$RESP"
```

Include `"website":"DOMAIN"` per Rule 2.5 whenever the auth is tied to a specific site. The server appends it to the item's **Used on** history and renders an "Authorizing agent access on `DOMAIN`" banner on the user's auth page.

**Response:** `{ "authRequestId": "...", "authUrl": "...", "expiresAt": "...", "agentMessage": "..." }`

**After (Mode A — JS plugin):** Send `agentMessage` word for word, then immediately call `rivault_await_auth` (Rule 3). The await tool blocks until approval and returns the value.

**After (Mode B — manual bash):** Send `agentMessage` word for word, then poll `/agent/auth-request/$RV_ID/status` every 5-8s until status is no longer `pending`.

### 4. Poll Auth Status

Run this when you receive a `[RIVAULT_APPROVED]` callback. The response now contains an envelope you must decrypt locally with the private key saved in section 3.

**IMPORTANT:** Set `RV_ID` once at the top to the actual `authRequestId` from the callback — every other reference uses `$RV_ID` so there's only one place to substitute. Do **not** use the literal string `AUTH_REQUEST_ID` anywhere; that breaks the file-path lookup.

```bash
# Replace the placeholder below with the actual authRequestId from the callback:
RV_ID="<paste authRequestId here>"

RESP=$( curl -s --max-time 15 \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/auth-request/$RV_ID/status")

# Decrypt envelope (see "Envelope crypto" section). Plaintext goes to stdout.
PLAINTEXT=$(echo "$RESP" | node -e "
const c=require('crypto'),fs=require('fs');
const r=JSON.parse(fs.readFileSync(0,'utf8'));
if(!r.envelope){process.stderr.write('no envelope\n');process.exit(1)}
const e=r.envelope;
const priv=c.createPrivateKey({key:fs.readFileSync(process.argv[1]),format:'der',type:'pkcs8'});
const peer=c.createPublicKey({key:Buffer.from(e.mobileEphemeralPublicKey,'base64'),format:'der',type:'spki'});
const shared=c.diffieHellman({privateKey:priv,publicKey:peer});
const key=Buffer.from(c.hkdfSync('sha256',shared,Buffer.alloc(0),Buffer.from('rivault-envelope-v1'),32));
const iv=Buffer.from(e.iv,'base64');
const ct=Buffer.from(e.ciphertext,'base64');
const tag=ct.subarray(ct.length-16);
const body=ct.subarray(0,ct.length-16);
const d=c.createDecipheriv('aes-256-gcm',key,iv);
d.setAuthTag(tag);
process.stdout.write(Buffer.concat([d.update(body),d.final()]).toString('utf8'));
" "/tmp/rv_priv_$RV_ID")
rm -f "/tmp/rv_priv_$RV_ID"
```

**Response:** `{ "status": "approved", "type": "general"|"login", "envelope": {...}, "username"?: "...", "website"?: "..." }`

- `approved` + `envelope` → run the decrypt block above. For login items: `$PLAINTEXT` is the password; `$RESP`'s `username` and `website` (cleartext) complete the credentials.
- `approved` without `envelope` → cache TTL elapsed; re-request auth.
- `denied` → tell user you cannot proceed.
- `expired` → offer to create new request.

### 5. Request Form (item not in vault)

```bash
SESSION_ID=$(cat ~/.openclaw/agents/main/sessions/sessions.json 2>/dev/null | jq -r 'to_entries | sort_by(.value.updatedAt) | last | .value.sessionId // .key // empty')

 curl -s --max-time 15 -X POST \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"requestedLabel\":\"LABEL\",\"requestedCategory\":\"CATEGORY\",\"reason\":\"REASON\",\"website\":\"DOMAIN\",\"callbackSessionId\":\"$SESSION_ID\"}" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/form-request"
```

Include `"website":"DOMAIN"` per Rule 2.5 whenever the form is being collected for a specific site. The server pre-populates the **Added for** field on the user's form page so the saved vault item is tagged with the right origin.

**Response:** `{ "formRequestId": "...", "formUrl": "...", "expiresAt": "...", "agentMessage": "..." }`

**After (Mode A — JS plugin):** Send `agentMessage` word for word, then immediately call the matching `rivault_await_*` tool (Rule 3).

**After (Mode B — manual bash):** Send `agentMessage` word for word, then poll the matching `/status` endpoint every 5-8s.

### 6. Poll Form Status

Run this when you receive a `[RIVAULT_FORM_SUBMITTED]` callback:

```bash
 curl -s --max-time 15 \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/form-request/FORM_REQUEST_ID/status"
```

**Response:** `{ "status": "submitted", "itemId": "..." }`

- `submitted` + `itemId` → use Get Secret (section 2) or Request Auth (section 3) with itemId to get the value, then complete the task
- `submitted` without `itemId` → user chose not to save, item unavailable
- `expired` → inform user, offer new request

### 7. Request Hybrid (L2 items + missing items combined)

Use when you need BOTH authorization for stored L2 items AND collection of missing items. Creates ONE link for everything. Same envelope-crypto protocol as auth: generate keypair before the request, decrypt envelopes after.

```bash
SESSION_ID=$(cat ~/.openclaw/agents/main/sessions/sessions.json 2>/dev/null | jq -r 'to_entries | sort_by(.value.updatedAt) | last | .value.sessionId // .key // empty')

PRIV_FILE_TMP="/tmp/rv_priv_pending_$$"
RV_PUBKEY=$(node -e "
const c=require('crypto'),fs=require('fs');
const kp=c.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
fs.writeFileSync(process.argv[1], kp.privateKey.export({format:'der',type:'pkcs8'}));
fs.chmodSync(process.argv[1], 0o600);
process.stdout.write(kp.publicKey.export({format:'der',type:'spki'}).toString('base64'));
" "$PRIV_FILE_TMP")

RESP=$( curl -s --max-time 15 -X POST \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "authItemIds": ["ITEM_ID_1", "ITEM_ID_2"],
    "formFields": [{"key": "field_key", "label": "Field Label"}],
    "reason": "REASON",
    "website": "DOMAIN",
    "agentEphemeralPublicKey": "'"$RV_PUBKEY"'",
    "callbackSessionId": "'"$SESSION_ID"'"
  }' \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/hybrid-request")

RV_ID=$(echo "$RESP" | jq -r '.hybridRequestId')
mv "$PRIV_FILE_TMP" "/tmp/rv_priv_$RV_ID"
echo "$RESP"
```

Include ALL L2 item IDs in `authItemIds` and ALL missing fields in `formFields`. Do not leave any out. Pass `"website":"DOMAIN"` per Rule 2.5 — it both pre-populates **Added for** on newly collected items and appends to **Used on** for every authorized item.

**Response:** `{ "hybridRequestId": "...", "hybridUrl": "...", "expiresAt": "...", "agentMessage": "..." }`

**After (Mode A — JS plugin):** Send `agentMessage` word for word, then immediately call the matching `rivault_await_*` tool (Rule 3).

**After (Mode B — manual bash):** Send `agentMessage` word for word, then poll the matching `/status` endpoint every 5-8s.

### 8. Poll Hybrid Status

Run this when you receive a `[RIVAULT_HYBRID_SUBMITTED]` callback. Each authorized item and each form field comes back as an envelope you must decrypt locally.

**IMPORTANT:** Set `RV_ID` once at the top to the actual `hybridRequestId` from the callback — every other reference uses `$RV_ID`.

```bash
# Replace the placeholder below with the actual hybridRequestId from the callback:
RV_ID="<paste hybridRequestId here>"

RESP=$( curl -s --max-time 15 \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/hybrid-request/$RV_ID/status")

# Decrypt every envelope and print as JSON { authorized: {itemId: {value, type, username?, website?}}, form: {fieldKey: value} }
DECRYPTED=$(echo "$RESP" | node -e "
const c=require('crypto'),fs=require('fs');
const r=JSON.parse(fs.readFileSync(0,'utf8'));
const priv=c.createPrivateKey({key:fs.readFileSync(process.argv[1]),format:'der',type:'pkcs8'});
function dec(e){
  const peer=c.createPublicKey({key:Buffer.from(e.mobileEphemeralPublicKey,'base64'),format:'der',type:'spki'});
  const shared=c.diffieHellman({privateKey:priv,publicKey:peer});
  const key=Buffer.from(c.hkdfSync('sha256',shared,Buffer.alloc(0),Buffer.from('rivault-envelope-v1'),32));
  const iv=Buffer.from(e.iv,'base64');
  const ct=Buffer.from(e.ciphertext,'base64');
  const tag=ct.subarray(ct.length-16);
  const body=ct.subarray(0,ct.length-16);
  const d=c.createDecipheriv('aes-256-gcm',key,iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(body),d.final()]).toString('utf8');
}
const out={authorized:{},form:{}};
for(const [id,entry] of Object.entries(r.authorizedItems||{})){
  out.authorized[id]={type:entry.type,value:dec(entry.envelope),username:entry.username,website:entry.website};
}
for(const [k,e] of Object.entries(r.formEnvelopes||{})){
  out.form[k]=dec(e);
}
process.stdout.write(JSON.stringify(out));
" "/tmp/rv_priv_$RV_ID")
rm -f "/tmp/rv_priv_$RV_ID"
```

**Response:** `{ "status": "submitted", "formEnvelopes": {...}, "authorizedItems": {...}, "createdItemIds": [...] }`

- `submitted` → run the decrypt block above. `$DECRYPTED` is `{ authorized: { itemId: { type, value, username?, website? } }, form: { fieldKey: value } }` — use these to complete the original task.
- `expired` → inform user, offer new request.

---

### 9. Check Login (find existing logins for a website)

When a task benefits from logging in to a website, FIRST check Rivault for saved credentials.

```bash
 curl -s --max-time 15 \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/vault/logins?website=DOMAIN"
```

`DOMAIN` may be any URL or hostname — the server normalizes to the eTLD+1.

**Response:** `{ "found": true|false, "logins": [{ "id", "label", "website", "username" }] }`

Decision tree:
- 0 results → step 11 (request a new login from the user, if they want one).
- 1 result → ask the user "Want me to use your saved DOMAIN login (USERNAME)?". If yes, do step 10 (auth flow) with that `id`.
- 2+ results → show the user the list of usernames; let them pick by index. Then do step 10 with the chosen `id`.

### 10. Retrieve a saved login (existing login flow)

Reuse the auth flow with the same envelope-crypto protocol as section 3. The auth-status response carries `username` + `website` cleartext for login items, plus the password inside the envelope.

```bash
 # Generate keypair (see section 3)
PRIV_FILE_TMP="/tmp/rv_priv_pending_$$"
RV_PUBKEY=$(node -e "
const c=require('crypto'),fs=require('fs');
const kp=c.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
fs.writeFileSync(process.argv[1], kp.privateKey.export({format:'der',type:'pkcs8'}));
fs.chmodSync(process.argv[1], 0o600);
process.stdout.write(kp.publicKey.export({format:'der',type:'spki'}).toString('base64'));
" "$PRIV_FILE_TMP")

 # Request authorization for the chosen login item. Per Rule 2.5, include
 # "website":"DOMAIN" — even though the login item already has its own
 # website, this also tags the item's "Used on" history.
RESP=$( curl -s --max-time 15 -H "Authorization: Bearer $RIVAULT_API_KEY" \
  -H "Content-Type: application/json" \
  -X POST -d "{\"itemId\":\"ITEM_ID\",\"reason\":\"Logging in to DOMAIN\",\"website\":\"DOMAIN\",\"agentEphemeralPublicKey\":\"$RV_PUBKEY\"}" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/auth-request")
RV_ID=$(echo "$RESP" | jq -r '.authRequestId')
mv "$PRIV_FILE_TMP" "/tmp/rv_priv_$RV_ID"

 # After user approves (callback), poll + decrypt as in section 4. The
 # decrypted plaintext is the password; username/website come from the cleartext
 # response fields.
```

### 11. Request a new login (no saved credentials)

If `rivault_check_login` returned no results AND the user said yes to "do you have an existing DOMAIN account you'd like me to use?", ask Rivault to collect the credentials. Same envelope-crypto protocol — generate the keypair before the request.

```bash
PRIV_FILE_TMP="/tmp/rv_priv_pending_$$"
RV_PUBKEY=$(node -e "
const c=require('crypto'),fs=require('fs');
const kp=c.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
fs.writeFileSync(process.argv[1], kp.privateKey.export({format:'der',type:'pkcs8'}));
fs.chmodSync(process.argv[1], 0o600);
process.stdout.write(kp.publicKey.export({format:'der',type:'spki'}).toString('base64'));
" "$PRIV_FILE_TMP")

RESP=$( curl -s --max-time 15 \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  -H "Content-Type: application/json" \
  -X POST \
  -d "{\"website\":\"DOMAIN\",\"reason\":\"Logging in\",\"agentEphemeralPublicKey\":\"$RV_PUBKEY\"}" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/login-request")

RV_ID=$(echo "$RESP" | jq -r '.loginRequestId')
mv "$PRIV_FILE_TMP" "/tmp/rv_priv_$RV_ID"
echo "$RESP"
```

**Response:** `{ "loginRequestId", "loginUrl", "expiresAt", "agentMessage" }`. Send `agentMessage` to the user verbatim, then start the poller (same script as auth/form/hybrid) targeting `login-request`.

If the user does NOT have an existing account, V1 behavior: proceed without logging in. (Account creation is V2.)

### 12. Poll Login Status

Run this when you receive a `[RIVAULT_LOGIN_SUBMITTED]` callback. Decrypt the envelope to get the password.

**IMPORTANT:** Set `RV_ID` once at the top to the actual `loginRequestId` from the callback — every other reference uses `$RV_ID`.

```bash
# Replace the placeholder below with the actual loginRequestId from the callback:
RV_ID="<paste loginRequestId here>"

RESP=$( curl -s --max-time 15 \
  -H "Authorization: Bearer $RIVAULT_API_KEY" \
  "${RIVAULT_API_URL:-https://api.rivault.ai}/agent/login-request/$RV_ID/status")

PASSWORD=$(echo "$RESP" | node -e "
const c=require('crypto'),fs=require('fs');
const r=JSON.parse(fs.readFileSync(0,'utf8'));
if(!r.envelope){process.stderr.write('no envelope\n');process.exit(1)}
const e=r.envelope;
const priv=c.createPrivateKey({key:fs.readFileSync(process.argv[1]),format:'der',type:'pkcs8'});
const peer=c.createPublicKey({key:Buffer.from(e.mobileEphemeralPublicKey,'base64'),format:'der',type:'spki'});
const shared=c.diffieHellman({privateKey:priv,publicKey:peer});
const key=Buffer.from(c.hkdfSync('sha256',shared,Buffer.alloc(0),Buffer.from('rivault-envelope-v1'),32));
const iv=Buffer.from(e.iv,'base64');
const ct=Buffer.from(e.ciphertext,'base64');
const tag=ct.subarray(ct.length-16);
const body=ct.subarray(0,ct.length-16);
const d=c.createDecipheriv('aes-256-gcm',key,iv);
d.setAuthTag(tag);
process.stdout.write(Buffer.concat([d.update(body),d.final()]).toString('utf8'));
" "/tmp/rv_priv_$RV_ID")
rm -f "/tmp/rv_priv_$RV_ID"
```

**Response:** `{ "status": "submitted", "loginItemId": ..., "envelope": {...}, "website": ... }`. The envelope decrypts to the password; the website comes from the cleartext field. The login was also saved to the user's vault for future reuse. Use the password to fill the form, then redact.

---

## Complete Workflow Example

Task: "Fill out this form that needs email and phone number"

```
Step 1: Inspect the form → identify required fields: email, phone number

Step 2: Search Rivault for "email" → found "Email Address" (L1, id: abc123)
        Search Rivault for "phone" → found "Phone number" (L1, id: def456)

Step 3: Both L1 → use Hybrid with authItemIds: ["abc123", "def456"], formFields: []
        API response: hybridRequestId="xyz789", hybridUrl="https://.../h/tok456"

Step 4: Send agentMessage to user (word for word from API response)

Step 5: Extract URL token "tok456" from hybridUrl
        Extract poller script and start it:
          awk '...' ~/.openclaw/skills/rivault/SKILL.md > /tmp/rv_poll_$$.sh
          nohup /tmp/rv_poll_$$.sh "hybrid-request" "tok456" "submitted" \
            "RIVAULT_HYBRID_SUBMITTED" "hybridRequestId" "xyz789" "$SESSION_ID" &

Step 6: END response ← user sees the link and taps it

        ... user authorizes on Rivault ...
        ... background poller detects "submitted" ...
        ... poller fires Turn 1 --deliver ...

Step 7: Agent receives [RIVAULT_HYBRID_SUBMITTED] hybridRequestId=xyz789
        Agent runs: curl .../agent/hybrid-request/xyz789/status
        Agent retrieves the data
        Agent says: "✅ Data retrieved, task resuming."
        Agent ENDs response ← MESSAGE 1 delivered to WhatsApp

        ... poller sleeps 30s, then fires Turn 2 --deliver ...

Step 8: Agent receives [RIVAULT_RESUME]
        Agent completes the original task using retrieved data
        Agent says: "Done! [summary]"
        Agent ENDs response ← MESSAGE 2 delivered to WhatsApp

Step 9: Run redaction (Security section)
```

User sees TWO separate messages (30s apart):
1. "✅ Data retrieved, task resuming." (Turn 1 — data retrieval only)
2. "Done! Form filled successfully." (Turn 2 — task completion)

---

## Security Rules

### Absolute Rules

- Never ask users to type secrets in chat
- Never echo, repeat, or display secret values in messages
- ALL vault values (L1 and L2) must NEVER be written to persistent storage (files, memory, session history, logs)
- Use retrieved values only in-memory for the single operation, then discard
- After the operation, do not reference or summarize the secret value
- If a secret was written to any file, replace it with `[REDACTED:rivault]` immediately
- Always use `reason` parameter to explain why you need each item

### Bash + Curl Security

- Prefix all curl commands with a space (` curl`) to skip shell history
- Use `--max-time 15` on every curl command
- Pipe curl output through `jq` to extract only needed fields
- Never echo/log/store curl output containing secret values

### Exec-output leak vector — pass secrets via files, not shell variables

Some tools echo their input back to stdout (e.g. `browser-use type "$PHONE"` prints `typed: <value>`). OpenClaw captures that stdout into the exec-completion system message which lands in the session JSONL **before** the agent's own redaction step runs. The Rivault daemon's cross-runtime scanner catches this on the next file-write event (~500ms-1s later) **only if** the curl that retrieved the value went through the daemon — see the "Mode B preamble" above. Even with that, prefer to avoid the leak entirely:

- ❌ `browser-use type "$PHONE"` — echoes the value
- ✅ Write the value to a 0600 tempfile and have the tool read from it:

  ```bash
  TMPF=$(mktemp); chmod 600 "$TMPF"
  printf '%s' "$PHONE" > "$TMPF"
  browser-use type --from-file "$TMPF"
  rm -f "$TMPF"
  ```

Same principle for any tool with stdout echo. When no `--from-file` option exists, redirect stdout to `/dev/null` and verify the result via a separate state check rather than reading echoed output.

### MANDATORY Post-Task Redaction

**After ANY task that retrieved secret values, you MUST run this before ending your response:**

For EACH secret value from curl output, run:

```bash
SESSION_FILE=$(ls -t ~/.openclaw/agents/main/sessions/*.jsonl 2>/dev/null | head -1)
if [ -n "$SESSION_FILE" ]; then
  SECRET='SECRET_VALUE_HERE' python3 -c '
import os, sys
secret = os.environ["SECRET"]
for path in sys.argv[1:]:
    with open(path, "r") as fh:
        data = fh.read()
    new = data.replace(secret, "[REDACTED:rivault]")
    if new != data:
        with open(path, "w") as fh:
            fh.write(new)
' "$SESSION_FILE"
fi
```

Replace `SECRET_VALUE_HERE` with each actual plaintext value. Run once per value.

The redaction uses a byte-literal `str.replace`, not a regex, so any secret value works — including ones containing `/`, `.`, `&`, `[`, `]`, `$`, `^`, `*`, or `\` that would silently break a `sed` substitution. The marker `[REDACTED:rivault]` matches what the daemon writes when it scrubs files itself, so transcripts read consistently regardless of which side did the scrub.

For login credentials retrieved via the auth or login flows, redact BOTH the `username` and the `password` (`value`) fields — usernames are saved L1 server-side but should still not appear in session transcripts.

Verify with: `grep -c 'SECRET_VALUE_HERE' "$SESSION_FILE"` — must return 0.

**Sweep stale ephemeral private keys.** The envelope crypto helpers write per-request private keys to `/tmp/rv_priv_<requestId>` (mode 0600). Each section 4/8/12 decrypt block deletes its own file on success, but on errors they may linger. Run after every task:

```bash
find /tmp -maxdepth 1 -name 'rv_priv_*' -mmin +30 -delete 2>/dev/null
```

---

###BEGIN_POLL_SCRIPT###
#!/bin/bash
RV_API="${RIVAULT_API_URL:-https://api.rivault.ai}"
RV_TYPE="$1"; RV_TOKEN="$2"; RV_OK="$3"; RV_TAG="$4"; RV_KEY="$5"; RV_ID="$6"; RV_SID="$7"
for i in $(seq 1 60); do
  sleep 5
  S=$(curl -s --max-time 10 "$RV_API/$RV_TYPE/$RV_TOKEN" 2>/dev/null | jq -r .status 2>/dev/null || echo "")
  if [ "$S" = "$RV_OK" ]; then
    /opt/homebrew/bin/openclaw agent --session-id "$RV_SID" --message "[$RV_TAG] $RV_KEY=$RV_ID — TURN 1: Retrieve the data by polling the $RV_TYPE status. Then tell user: ✅ Data retrieved, task resuming. Then STOP — do NOT start the task yet." --deliver 2>/dev/null || true
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
