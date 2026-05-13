# Rivault Desktop

The on-device side of [Rivault](https://rivault.ai) — a zero-knowledge encrypted secrets vault for AI agents.

This repo is **public** so anyone can audit what runs on your machine. It contains:

- **`packages/desktop/`** — the Rivault daemon, a Tauri app that watches agent transcripts and scrubs released vault values after every task.
- **`packages/skill/`** — the OpenClaw skill / adapter that lets agents request secrets from Rivault.
- **`install.sh`** — the one-step macOS installer.

The Rivault API server, web app, and billing infrastructure live in a separate private repo. The boundary between this repo and the server is the public REST API (`api.rivault.ai`).

## Install

```bash
# One-step curl install
curl -fsSL https://www.rivault.ai/install.sh | sh

# Or via Homebrew
brew tap rivault-ai/tap
brew install --cask rivault
```

You'll be prompted for an API key. Get one at [rivault.ai](https://rivault.ai).

## What the daemon does

When an AI agent (Claude Desktop, Codex, OpenClaw, etc.) retrieves a secret from your Rivault vault, the daemon:

1. Receives a release event from the local skill / MCP server.
2. Watches the agent's transcript file(s).
3. When the agent finishes its turn, replaces every occurrence of the secret value with `[REDACTED:rivault]` — including base64, URL-encoded, and JSON-escaped variants.
4. Verifies the scrub with a re-read pass, then marks the release as scrubbed in a local SQLite ledger.

The daemon never sends plaintext anywhere. The only outbound network call it makes is `GET /agent/me` to validate your API key on first launch.

## Build from source

```bash
pnpm install
pnpm rebuild esbuild
cd packages/desktop && pnpm tauri dev
```

Requires Rust (stable) and Node 20+. macOS only for now.

## License

[AGPL-3.0-or-later](LICENSE). The daemon is auditable and modifiable; if you build a derivative network service from this code you must release your changes under the same terms.

## Security disclosures

If you find a vulnerability, please email security@rivault.ai. Do not open a public issue.
