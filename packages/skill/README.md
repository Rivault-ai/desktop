# @rivault/skill

Rivault is a secure, encrypted vault for storing personal secrets — passwords, API keys, addresses, payment info, and any sensitive data you want AI agents to access on your behalf. This OpenClaw skill gives AI agents a structured, authorization-gated way to retrieve secrets from your Rivault vault without ever asking you to type them in chat.

Sensitive items require Face ID authorization via a unique one-time link. Public items are returned immediately. Items not yet in your vault can be requested via a secure form, with the option to save them for future use.

---

## How it works

Installing Rivault requires two components:

| Component | What it does | Where it lives |
|-----------|-------------|----------------|
| **Plugin** | Registers 6 vault tools with the AI agent | `~/.openclaw/extensions/rivault/` |
| **Skill prompt** | Injects instructions into the LLM context; makes Rivault appear in the web UI | `~/.openclaw/skills/rivault/SKILL.md` |

`openclaw plugins install` handles the plugin. The skill prompt must be copied separately into OpenClaw's managed skills directory (`~/.openclaw/skills/`) — that is the source the web UI and agent context loader read from.

---

## Requirements

- [OpenClaw](https://openclaw.ai) 2026.3 or later
- A Rivault account with at least one agent API key (see **Settings > Agent Access > API Keys**)
- The Rivault API reachable (self-hosted or `https://rivault-api.up.railway.app`)

---

## Installation

### Step 1 — Install the plugin

```bash
openclaw plugins install /path/to/rivault/dist/tarballs/rivault-skill-current.tgz
```

To build from source first:

```bash
# In packages/skill:
npm run build && npm pack
openclaw plugins install ./rivault-0.1.0.tgz
```

### Step 2 — Run the setup script

The setup script copies the skill prompt, allowlists the plugin, and restarts the gateway:

```bash
bash ~/.openclaw/extensions/rivault/scripts/install.sh
```

That's it. The script handles steps 3–5 below automatically. Skip to **Step 6** to set your API key.

---

### Steps 3–5 (manual alternative to the script)

#### Step 3 — Copy the skill prompt

```bash
mkdir -p ~/.openclaw/skills/rivault
cp ~/.openclaw/extensions/rivault/skills/rivault/SKILL.md ~/.openclaw/skills/rivault/SKILL.md
```

This is what makes Rivault appear in `openclaw skills list` and the web UI at `/skills`.

#### Step 4 — Allowlist the plugin

Required. Without it the LaunchAgent-managed gateway silently skips non-bundled plugins on every restart.

```bash
openclaw config set plugins.allow '["rivault"]'
```

Or add it manually to `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "allow": ["rivault"]
  }
}
```

#### Step 5 — Restart the gateway

```bash
openclaw gateway restart
```

---

### Step 6 — Set your API key

**Via the web UI (recommended):**

Open `http://127.0.0.1:18789/skills`, find Rivault, and paste your API key into the input field.

**Via config directly:**

```bash
openclaw config set plugins.entries.rivault.config.apiKey "rv_your_api_key_here"
openclaw gateway restart
```

**Optional** — override the API base URL (for self-hosted or staging):

```bash
openclaw config set plugins.entries.rivault.config.apiUrl "https://your-rivault-instance.example.com"
openclaw gateway restart
```

---

### Verify

```bash
openclaw skills list    # rivault should appear as ✓ ready
openclaw plugins list   # rivault should show "loaded"
```

---

## Development

### Live reload

```bash
cd packages/skill
npm run dev             # watches src/ and recompiles on change
```

Install as a linked path so OpenClaw picks up rebuilds without reinstalling:

```bash
openclaw plugins install --link /path/to/rivault/packages/skill
bash ~/.openclaw/extensions/rivault/scripts/install.sh
```

Restart the gateway after each rebuild to reload the plugin.

---

## How It Works

The skill exposes six tools to the LLM. Every flow starts with a vault search to check whether the item already exists, then branches based on whether the item was found and what sensitivity level it has.

### Flow 1 — L1 item (agent retrieves directly)

```
User:  "What's my GitHub username?"
Agent: rivault_check("github username")
       → found: item id=abc123, label="GitHub Username", L1
       rivault_get_secret(item_id="abc123")
       → value: "jsmith"
Agent: "Your GitHub username is jsmith."
```

The value is returned in the tool response. No user interaction required. Value is redacted from agent memory after use.

### Flow 2 — L2 item (Face ID authorization required)

```
User:  "Buy me a coffee from Blue Bottle."
Agent: rivault_check("credit card")
       → found: item id=xyz789, label="Visa ending 4242", L2
       rivault_request_auth(item_id="xyz789", reason="needed to complete Blue Bottle purchase")
       → authRequestId: "req_abc", authUrl: "https://auth.rivault.ai/req_abc"
Agent: "🔐 I need your Visa ending 4242 to complete this task.
        Please authorize here: https://auth.rivault.ai/req_abc
        This link expires in 15 minutes."
       [polls rivault_poll_auth every 5 seconds]
       → status: approved, value: "4242..."
Agent: [completes purchase silently]
       "Done! Your coffee is ordered."
```

The secret value is transmitted only through the tool response, never displayed to the user.

### Flow 3 — Item not in vault (form request)

```
User:  "Ship a birthday gift to my sister."
Agent: rivault_check("sister address")
       → no items found
       rivault_request_form(
         requested_label="Sister's Shipping Address",
         requested_category="identity",
         reason="needed to ship birthday gift"
       )
       → formRequestId: "form_001", formUrl: "https://form.rivault.ai/form_001"
Agent: "📝 I need your Sister's Shipping Address to complete this task.
        Please provide it here: https://form.rivault.ai/form_001
        Once saved, I'll automatically continue."
       [polls rivault_poll_form every 5 seconds]
       → status: submitted, itemId: "new_item_99"
       rivault_get_secret(item_id="new_item_99")  ← or rivault_request_auth if L1/L2
       → value: "123 Oak St, Portland OR 97201"
Agent: [proceeds with shipping]
```

### Flow 4 — Mixed (some stored, some missing, some need auth)

The agent handles all cases in parallel where possible, presenting a clear summary to the user upfront:

```
Agent: "To complete your checkout I need three things:
        - Your name: found in vault (no action needed)
        - Your shipping address: needs your authorization
        - Your payment method: not yet in your vault

        Please:
        1. Authorize your address here: https://auth.rivault.ai/req_1
        2. Provide your payment details here: https://form.rivault.ai/form_2

        I'll proceed automatically once both are ready."
```

---

## Tool Reference

### `rivault_check`

Check if a specific piece of information exists in the vault. Query one field at a time. Does not list or browse vault contents.

| Parameter  | Type   | Required | Description                                                                   |
|------------|--------|----------|-------------------------------------------------------------------------------|
| `query`    | string | yes      | The specific item to check for (e.g. "email", "phone number", "home address") |

**Returns:** Whether the item exists, its item ID, and sensitivity level. Does not return labels, categories, or values.

---

### `rivault_get_secret`

Retrieve a secret value for an L1 item directly via API key. Returns an error message if the item requires Face ID authorization (L2).

| Parameter | Type   | Required | Description                              |
|-----------|--------|----------|------------------------------------------|
| `item_id` | string | yes      | Vault item ID from `rivault_check`      |

**Returns:** The secret value and label on success. A prompt to use `rivault_request_auth` if the item is L2.

---

### `rivault_request_auth`

Create a Face ID authorization request for an L1 or L2 item. Generates a unique, time-limited URL for the user to approve.

| Parameter | Type   | Required | Description                                                                         |
|-----------|--------|----------|-------------------------------------------------------------------------------------|
| `item_id` | string | yes      | Vault item ID from `rivault_check`                                                 |
| `reason`  | string | no       | Why you need this item — shown to the user on the authorization page                |

**Returns:** `authRequestId`, `authUrl`, and expiry time. The agent should send the URL to the user, then poll.

---

### `rivault_poll_auth`

Check whether the user has approved, denied, or ignored an authorization request.

| Parameter         | Type   | Required | Description                                          |
|-------------------|--------|----------|------------------------------------------------------|
| `auth_request_id` | string | yes      | The `authRequestId` from `rivault_request_auth`      |

**Returns:** Status (`pending`, `approved`, `denied`, `expired`). Includes the secret value when `approved`.

---

### `rivault_request_form`

Ask the user to provide a new secret via a secure form. Used when `rivault_check` returns no results.

| Parameter            | Type   | Required | Description                                                                         |
|----------------------|--------|----------|-------------------------------------------------------------------------------------|
| `requested_label`    | string | yes      | Human-readable name for what you need (e.g. "Home Address", "GitHub API Key")       |
| `requested_category` | string | yes      | Category: `identity`, `payment`, `api_key`, `password`, `preference`, `other`       |
| `reason`             | string | no       | Why you need this — shown on the form page                                           |

**Returns:** `formRequestId`, `formUrl`, and expiry time. The agent should send the URL to the user, then poll.

---

### `rivault_poll_form`

Check whether the user has submitted the form.

| Parameter        | Type   | Required | Description                                        |
|------------------|--------|----------|----------------------------------------------------|
| `form_request_id`| string | yes      | The `formRequestId` from `rivault_request_form`    |

**Returns:** Status (`pending`, `submitted`, `expired`). Includes `itemId` when submitted so the agent can retrieve the value.

---

## Example Conversation

```
User: Book me a flight to Tokyo next Friday, economy class.

Agent: [calls rivault_check("passport")]
       Found: "Passport Number" (L2 — requires Face ID), "Passport Expiry" (L1 — agent-accessible)

       [calls rivault_check("credit card")]
       Found: "Visa ending 4242" (L2 — requires Face ID)

       [calls rivault_get_secret for passport expiry — L1, no auth needed]
       Passport expires 2028-03-14. ✓

       [calls rivault_request_auth for passport number — L2]
       [calls rivault_request_auth for Visa — L2]

       "To book your flight I need to access two items from your vault.
        Please authorize both:

        1. Passport Number (very private): https://auth.rivault.ai/req_passport
        2. Visa ending 4242: https://auth.rivault.ai/req_visa

        Both links expire in 15 minutes."

       [User taps both links and approves via Face ID]

       [polls detect both approved]

       "Got everything I need. Searching flights to Tokyo..."
       [completes booking]
       "Done! Your flight is booked. Confirmation: JL742, departing March 14 at 11:05 AM.
        Confirmation code sent to your email."
```

---

## Security Notes

**The agent never stores secrets.** Values are retrieved once per task and used immediately. They are never written to logs, conversation history, or any persistent storage by this skill.

**Authorization links are one-time use.** Each `rivault_request_auth` creates a unique URL. Once approved, the URL cannot be reused. The secret value returned by `rivault_poll_auth` is also one-time — polling again after approval returns no value.

**Face ID authorization happens on your device.** The authorization and form pages are served by Rivault directly. The AI agent sees only the approval result, never your biometric data.

**L2 items require explicit approval for each access.** There is no "remember this" mode for very private items — every access requires a fresh Face ID tap.

**If you deny a request**, the agent is informed immediately and will explain it cannot complete the task without that information. It will not retry or find workarounds.

**API key scope.** Your `RIVAULT_API_KEY` is agent-scoped — it can only search metadata and create authorization/form requests. It cannot read vault values directly; those require your explicit Face ID approval per request.
