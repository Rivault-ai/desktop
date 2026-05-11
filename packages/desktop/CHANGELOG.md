# Rivault Desktop Changelog

The version shown in the app footer (e.g. `v0.3.0 · a1b2c3d · built …`) maps
to one of these entries. Click the footer to copy the full build identifier
to your clipboard when filing a bug report.

Versioning convention: semver. Patch bumps for fixes, minor bumps when a
new surface (tool, endpoint, scanner) ships, major bumps reserved for
breaking changes to the daemon's release-event contract.

---

## v0.3.0 — 2026-05-11

End-to-end deterministic redaction across all current agent runtimes, plus
operational resilience (keypair persistence, public-endpoint passthrough)
and the in-app version footer that lets you see exactly which build is
running.

**Daemon**
- **Cross-runtime continuous scanner.** Single `notify` watcher over the
  union of every runtime's allowlist roots. On any `*.jsonl` write, redacts
  every occurrence of every plaintext currently in the new TTL-bounded
  (24h, 1000-entry) in-memory `RecentReleasesIndex`. Closes the
  cross-session leak case where a value released through Rivault in
  session A surfaces in session B's transcript via an unrelated channel
  (chrome page read, screenshot OCR, etc.).
- **Per-session runtime tagging.** Each agent runtime registers its own
  MCP URL with a `?runtime=` query param so the same daemon binary
  correctly tags ledger rows and resolves transcript paths per call.
- **`stopReason` (camelCase) end-turn detection.** Adds OpenClaw's
  transcript shape to the watcher's stop-signal recogniser alongside the
  existing Anthropic snake_case and OpenAI `finish_reason` shapes.
- **Concurrent-scrub serialization.** New `scrub_mutex` on the daemon
  prevents the "one scrubbed, one unverified" race where two concurrent
  releases on the same transcript file clobber each other's redactions.
  Scope-2 escalation now includes primary transcript paths in the
  precount fallback so the verifier can rescue residue Scope-1 missed.
- **Persistent L2 keypair store.** Ephemeral private keys minted by the
  Tier-B proxy on `auth-request` / `hybrid-request` / `login-request`
  POST now persist at `~/Library/Application Support/Rivault/keypairs.db`,
  wrapped with AES-256-GCM using the daemon's per-install keychain
  secret. A daemon restart mid-approval no longer strands the pending
  request. Best-effort: keychain unavailable / DB corrupt fall back to
  in-memory mode.
- **Proxy public-endpoint passthrough.** New routes for
  `/auth-request/:token`, `/hybrid-request/:token`,
  `/form-request/:token`, `/login-request/:token` — the public
  status-check endpoints the skill's background poller uses to detect
  approval without consuming Redis values. Previously returned 404 and
  silently hung the poller.
- **OpenClaw SQLite memory scrubber.** Anchors `MAX(rowid)` per table at
  release time; on scrub, redacts only rows created during the task
  window. Pre-task content stays byte-identical. `wal_checkpoint(TRUNCATE)`
  after success.

**Local MCP server (Claude Code, Codex, Claude Desktop)**
- **`rivault_await_*` tools** that block in-process with 3-8s backoff up
  to 3min and return plaintext directly when the user approves. No
  manual polling, no subprocess. Works for streaming runtimes (every
  runtime except OpenClaw).
- **Mandatory orchestration in tool descriptions + server instructions.**
  Spells out: "call `rivault_check` BEFORE asking the user for any
  personal data"; "after `rivault_request_*`, you MUST immediately call
  `rivault_await_*` in the same response". Embeds a `nextAction` field
  in request responses naming the exact next tool + args.

**OpenClaw skill plugin**
- **URL discovery on every call.** Plugin no longer snapshots
  `apiBaseUrl` at registration; resolves `config.apiBaseUrl` fresh inside
  each `execute()` so a daemon that comes up *after* the OpenClaw gateway
  is picked up on the next tool call. Fixes the bug where the Tier-B
  proxy never saw OpenClaw traffic (so no ledger row was ever inserted
  and no transcript scrub fired).
- **Subprocess poller pattern retained for OpenClaw** (NOT in-process
  await) — OpenClaw flushes the agent's text to the user only at
  end-of-turn, so any blocking tool call would hold the auth URL hostage
  for the full timeout. The detached poller spawns immediately, the
  `request_*` tool returns, the user sees the URL right away.
- **Plugin discoverable at `~/.openclaw/extensions/rivault/`** with the
  built bundle deployed there (including `dist/index.js` entry, tool
  files, `openclaw.plugin.json`, scripts, README). Added `rivault` to
  `plugins.allow`. Refreshed `tools.alsoAllow` to include current tool
  names.
- **SKILL.md version + updatedAt** tracked in frontmatter so the agent
  always sees the current prompt version. `scripts/bump-skill.sh
  patch|minor|major` automates both fields plus `package.json`.

**Desktop UI**
- **Version footer** at the bottom of the app: `v0.3.0 · <git sha> ·
  built <timestamp>`. Click to copy the full build identifier to the
  clipboard for bug reports.

---

## v0.2.1 — initial release tracked in this changelog

Baseline before this changelog started. See git log between v0.2.1 and
v0.3.0 commits for the full set of intermediate PRs that landed under
v0.2.x development:
- PR #6 → multi-tier scrub scope ladder + byte-content prefilter
- PR #7 → always-redact Rule 5 in SKILL.md
- PR #8 → Tier-B proxy L2 envelope decryption
- PR #9 → SKILL.md mode commit (don't switch mid-task)
- PR #10 → SKILL runtime detection + multi-L2 hybrid hint
- PR #11 → per-session runtime + camelCase `stopReason` recognition
- PR #12 → `rivault_await_*` MCP tools + Mode B discovery
- PR #13 → mandatory check/await prompts + scrub serialization
- PR #14 → cross-runtime scanner + OpenClaw URL discovery + in-process await
- PR #15 → Mode B daemon discovery + exec-leak docs in SKILL.md
- PR #16 → skill versioning + bump-skill.sh helper
- PR #17 → revert JS plugin await tools (OpenClaw incompatibility)
- PR #18 → proxy public token routes (fix poller 404)
- PR #19 → persistent keypair store across daemon restarts
