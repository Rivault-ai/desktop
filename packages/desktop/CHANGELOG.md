# Rivault Desktop Changelog

The version shown in the app footer (e.g. `v0.3.0 · a1b2c3d · built …`) maps
to one of these entries. Click the footer to copy the full build identifier
to your clipboard when filing a bug report.

Versioning convention: semver. Patch bumps for fixes, minor bumps when a
new surface (tool, endpoint, scanner) ships, major bumps reserved for
breaking changes to the daemon's release-event contract.

---

## v0.3.2 — 2026-05-13

Sign-in flow now configures the OpenClaw plugin too, so users who
pair via the desktop app don't have to re-run `install.sh` (or hand-
edit `openclaw.json`) just to get the JS tools authenticated.

**Daemon**
- **`save_config` now mirrors the API key into OpenClaw's plugin
  config.** After validating against `/agent/me` and writing
  `~/Library/Application Support/Rivault/config.json`, the Tauri
  command also writes the key into `~/.openclaw/openclaw.json::
  plugins.entries.rivault.config.{apiKey, apiUrl}`, sets the entry
  to `enabled: true`, and adds `"rivault"` to `plugins.allow` if
  absent. Best-effort: OpenClaw not installed → no-op, never fails
  sign-in. New module `pairing::openclaw_export` mirrors the
  existing `openclaw_import` read path.
- **`clear_config` (sign out) now strips our credentials from
  OpenClaw's plugin config.** Symmetric with `save_config` so the
  next OpenClaw tool call fails fast on a missing key rather than
  using a stale one. `enabled` is left intact — clearing the key
  shouldn't disable the plugin entry the user may want to keep.

**Tests**
- Six unit tests on the new module: missing openclaw.json returns
  Ok(false); fresh write populates all fields and adds to `allow`;
  pre-existing plugins + skills survive; overwrite path replaces
  stale key; clear removes both fields in place; clear on
  already-empty config is a no-op.

---

## v0.3.1 — 2026-05-13

First-run UX fix: the MCP server now hot-mounts the moment `save_config`
validates the user's API key, instead of requiring a daemon restart.

**Daemon**
- **`mcp::UpstreamCell` (`Arc<RwLock<Option<UpstreamClient>>>`).** The
  MCP router is mounted on `/mcp` unconditionally at daemon startup.
  Tool handlers read+clone the upstream client from this cell on every
  call; an empty cell returns a clear "Rivault is not yet configured.
  Open the Rivault app and paste your `rv_live_` API key in Settings"
  McpError instead of a 404.
- **`save_config` hot-installs the upstream client** into the cell
  immediately after `/agent/me` validation. The next MCP tool call
  succeeds — no restart, no re-mount.
- **Tier-B proxy mounts unconditionally too**, defaulting to
  `https://api.rivault.ai`. Pass-through auth means the agent's own
  Authorization header is what matters, so the proxy works for any
  agent that has its own API key, with or without a configured daemon.

**Tests**
- Three new unit tests in `mcp/server.rs::tests`: empty cell errors
  with a Setup-pointing message; a hot-installed client is visible
  to the next call without restart; the helper's return type is
  owned so handlers can drop the lock before awaiting.

**Installer**
- **`install.sh` now registers the OpenClaw plugin.** Previously the
  installer only dropped the bundle at `~/.openclaw/skills/rivault/`,
  which OpenClaw's skill scanner reads (for `SKILL.md`) but the plugin
  loader does not. New users would see the SKILL.md prompt but the JS
  tools (`rivault_check`, …) never registered — agent fell back to
  bash+curl, bypassing the daemon's MCP-mediated redaction. The
  installer now also runs `openclaw plugins install <bundle>` so the
  plugin lands at `~/.openclaw/extensions/rivault/` and is wired into
  `openclaw.json`. Uninstall is symmetric: `install.sh --uninstall`
  runs `openclaw plugins uninstall rivault --force` first.

---

## v0.3.0 — 2026-05-12

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
- **Scanner failure banner.** When a cross-runtime transcript scrub
  fails on the same path three times in a row (permission denied,
  filesystem corruption, etc.), the desktop window surfaces a
  destructive-variant banner with the path, error, and consecutive
  count. Dismissible; auto-clears 30s after the most recent event.

**Security audit (closes the v0.2.x audit findings)**
- **P-256 point validation on the auth endpoint.** Backend now rejects
  ephemeral pubkeys that aren't on the P-256 curve, closing an
  invalid-curve attack that could have recovered mobile's ECDH private
  key over repeated requests.
- **Per-runtime MCP nonce.** Every managed MCP URL carries a nonce
  derived from the per-install keychain secret; the daemon rejects any
  `/mcp` request without a valid nonce. Closes the trivial spoofing of
  `?runtime=…` by a same-UID local process. Migration is automatic —
  the daemon rewrites every existing managed config on first launch.
- **Discovery file integrity.** The skill refuses any `daemon.json`
  that isn't a regular file at mode `0600` owned by the current UID;
  the daemon explicitly re-tightens the mode on every write.
- **`OsRng` for the keypair-store IV.** Replaced
  `rand::thread_rng()`-derived IVs with `OsRng` to eliminate the
  theoretical thread-reuse collision risk on AES-GCM wrap.
- **Encrypted-at-rest recent-releases cache.** New SQLite store under
  the daemon's data dir, wrapped with the same keychain secret used
  for the keypair store. 1h TTL. Cross-runtime scrubbing now survives
  a daemon restart.
- **Trailer / TE header stripping** in the Tier-B proxy so rewritten
  response bodies don't leave a strict client waiting for trailers
  that never arrive.
- **Sessions.json symlink defense** in the OpenClaw skill: the
  resolved path must stay under `~/.openclaw/` and be owned by the
  current UID; the previous behaviour followed symlinks blindly.
- **Timing-safe API key compare.** Backend always runs `argon2.verify`
  against a sentinel hash on the no-match path so the wall-clock
  difference between "no row" and "row + verify" can't be used to
  enumerate valid 16-char prefixes.
- **Browser one-time token rotation.** The localhost-HTTP
  `X-Rivault-Token` is now genuinely one-time-use: comparison is
  constant-time, and a successful release atomically swaps in a fresh
  token. Captured (header, body) pairs become inert on the next
  request.
- **`#[serde(deny_unknown_fields)]`** on every daemon-defined IPC
  wire struct (`ReleaseEvent`, `StopBody`, the unix-socket /
  websocket `Envelope` wrappers) so an attacker exploring the
  HMAC-authenticated surface gets a loud reject instead of silent
  field drops.
- **`O_NOFOLLOW` on every scrubber file open** — closes a same-UID
  TOCTOU window between `allowlist::validate_path` and the actual
  open where an attacker could swap a leaf for a symlink pointing
  outside the allowlist.
- **HMAC replay protection.** `/release` and `/stop` reject any
  signed payload whose `released_at` lies outside a ±60s window of
  wall-clock time.
- **EOF-stable scanner debounce.** The cross-runtime scanner waits
  for `(size, mtime)` to be unchanged for 200 ms before scrubbing so
  a multi-line tool result mid-write can't bait the scanner into
  scanning a partial file.
- **`jq` port parser in `SKILL.md`'s Mode B preamble** (was `awk`).
  Range-validates the result to `[1, 65535]`.
- **Skill poller log redaction.** Diagnostic log now keeps only the
  `rv_live_` brand prefix; previously leaked 8 bits of the random
  suffix.
- **Audit-anchor regression test on `ledger::insert`.** The
  orchestrator's no-panic discipline (`?` + `if let Err`) is pinned
  by a unit test so a future refactor can't silently re-introduce
  `.unwrap()`.

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
