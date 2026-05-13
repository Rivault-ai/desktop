#!/bin/sh
# Rivault installer for macOS.
#
# Usage:
#   curl -fsSL https://www.rivault.ai/install.sh | sh
#
# Flags:
#   --uninstall  Remove the app, skill, and config (preserves the local ledger).
#   --version=X  Pin to a specific release tag (default: latest).
set -eu

REPO="Rivault-ai/desktop"
APP_NAME="Rivault.app"
APP_DIR="/Applications/${APP_NAME}"
SKILL_DIR="${HOME}/.openclaw/skills/rivault"
SUPPORT_DIR="${HOME}/Library/Application Support/Rivault"
CONFIG_FILE="${SUPPORT_DIR}/config.json"

# ---------- helpers ----------

bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
red()    { printf '\033[31m%s\033[0m\n' "$*" >&2; }
warn()   { printf '\033[33m%s\033[0m\n' "$*" >&2; }

die() {
    red "$*"
    exit 1
}

require() {
    command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# ---------- arg parsing ----------

ACTION="install"
VERSION="latest"
PURGE=0

for arg in "$@"; do
    case "$arg" in
        --uninstall)     ACTION="uninstall" ;;
        --purge)         PURGE=1 ;;
        --version=*)     VERSION="${arg#--version=}" ;;
        -h|--help)
            sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

# ---------- platform check ----------

if [ "$(uname -s)" != "Darwin" ]; then
    die "Rivault currently supports macOS only. Detected: $(uname -s)"
fi

require curl
require shasum
require ditto

# ---------- uninstall ----------

if [ "$ACTION" = "uninstall" ]; then
    bold "Uninstalling Rivault..."
    osascript -e 'quit app "Rivault"' >/dev/null 2>&1 || true
    [ -d "$APP_DIR" ] && rm -rf "$APP_DIR" && green "  removed $APP_DIR"
    [ -f "$CONFIG_FILE" ] && rm -f "$CONFIG_FILE" && green "  removed $CONFIG_FILE"

    # Strip per-runtime localhost overrides so the agents don't keep
    # routing to a dead daemon. Only touches the field if it points at
    # 127.0.0.1 — leaves user-authored non-local values alone.
    if command -v python3 >/dev/null 2>&1; then
        for f in \
            "${HOME}/.claude.json:mcpServers.rivault.url" \
            "${HOME}/Library/Application Support/Claude/claude_desktop_config.json:mcpServers.rivault.url" \
            "${HOME}/.openclaw/openclaw.json:skills.entries.rivault.apiUrl"
        do
            file="${f%%:*}"
            path="${f##*:}"
            [ -f "$file" ] || continue
            python3 - "$file" "$path" <<'PY' && green "  cleared local-mcp override in ${file#${HOME}/}"
import json, sys
file_path, dotted = sys.argv[1], sys.argv[2]
with open(file_path) as fh:
    data = json.load(fh)
keys = dotted.split(".")
# Walk to the parent of the leaf. We delete the whole leaf node (e.g.
# the full `mcpServers.rivault` object) instead of just its `url`
# subkey — otherwise an orphan `{ "type": "http" }` stays behind and
# Claude tries to connect to a deleted server.
parent = data
for k in keys[:-2]:
    if not isinstance(parent, dict) or k not in parent:
        sys.exit(1)
    parent = parent[k]
if not isinstance(parent, dict):
    sys.exit(1)
leaf_key = keys[-2]
leaf = parent.get(leaf_key)
if not isinstance(leaf, dict):
    sys.exit(1)
url = leaf.get(keys[-1], "")
if not isinstance(url, str) or ("127.0.0.1" not in url and "://localhost" not in url):
    sys.exit(1)
del parent[leaf_key]
with open(file_path, "w") as fh:
    json.dump(data, fh, indent=2)
PY
        done
        # Codex config is TOML — strip just our marker block.
        codex_cfg="${HOME}/.codex/config.toml"
        if [ -f "$codex_cfg" ] && grep -q "# >>> rivault (managed) >>>" "$codex_cfg"; then
            tmp=$(mktemp)
            awk 'BEGIN{skip=0} /^# >>> rivault \(managed\) >>>/{skip=1; next} /^# <<< rivault \(managed\) <<</{skip=0; next} !skip{print}' "$codex_cfg" > "$tmp" \
                && mv "$tmp" "$codex_cfg" \
                && green "  cleared local-mcp override in ${codex_cfg#${HOME}/}"
        fi
    else
        warn "  python3 not found — skipping per-runtime config cleanup"
    fi
    # The OpenClaw skill and the local ledger are preserved on purpose:
    #   - SKILL.md lives at $SKILL_DIR and stays valid even if the daemon
    #     is gone — OpenClaw can keep using Rivault via the public API.
    #   - The ledger at $SUPPORT_DIR holds release audit history the user
    #     may want to keep across reinstalls.
    # Pass --purge to nuke both.
    # Unregister the OpenClaw plugin first so `openclaw plugins list`
    # doesn't keep showing a stale entry pointing at a path we may be
    # about to delete. Best-effort: openclaw not installed is fine.
    if command -v openclaw >/dev/null 2>&1; then
        openclaw plugins uninstall rivault --force >/dev/null 2>&1 \
            && green "  unregistered OpenClaw plugin" \
            || true
    fi
    # Belt-and-suspenders: openclaw plugins uninstall sometimes leaves
    # the extension directory behind when its install record was already
    # cleared by a prior call (it then refuses with "not managed by
    # plugins config/install records and cannot be uninstalled"). Make
    # sure no orphaned plugin dir survives.
    if [ -d "${HOME}/.openclaw/extensions/rivault" ]; then
        rm -rf "${HOME}/.openclaw/extensions/rivault" \
            && green "  removed orphan ~/.openclaw/extensions/rivault"
    fi
    if [ "$PURGE" = "1" ]; then
        [ -d "$SKILL_DIR" ] && rm -rf "$SKILL_DIR" && green "  removed $SKILL_DIR"
        [ -d "$SUPPORT_DIR" ] && rm -rf "$SUPPORT_DIR" && green "  removed $SUPPORT_DIR"
    else
        warn "  preserved $SKILL_DIR (OpenClaw skill — still works without the desktop daemon)"
        warn "  preserved $SUPPORT_DIR (local ledger). Run again with --purge to delete both."
    fi
    green "Done."
    exit 0
fi

# ---------- install ----------

bold "Rivault installer"
echo "  repo:    $REPO"
echo "  version: $VERSION"
echo "  arch:    $(uname -m)"
echo

# Resolve "latest" -> actual tag via the GitHub API.
if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n1)
    [ -n "${VERSION:-}" ] || die "Could not resolve latest release. Has v0.x.0 been tagged yet?"
fi

ASSET_URL="https://github.com/${REPO}/releases/download/${VERSION}/Rivault-darwin.zip"
SUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

TMPDIR_=$(mktemp -d)
trap 'rm -rf "$TMPDIR_"' EXIT

echo "  Downloading $VERSION..."
curl -fsSL --progress-bar -o "$TMPDIR_/Rivault-darwin.zip" "$ASSET_URL" \
    || die "Download failed: $ASSET_URL"
curl -fsSL -o "$TMPDIR_/checksums.txt" "$SUMS_URL" \
    || die "Could not fetch checksums: $SUMS_URL"

echo "  Verifying checksum..."
EXPECTED=$(awk '/Rivault-darwin\.zip$/ {print $1}' "$TMPDIR_/checksums.txt")
ACTUAL=$(shasum -a 256 "$TMPDIR_/Rivault-darwin.zip" | awk '{print $1}')
if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
    die "Checksum mismatch. expected=$EXPECTED actual=$ACTUAL"
fi
green "  ok ($ACTUAL)"

echo "  Extracting..."
ditto -x -k "$TMPDIR_/Rivault-darwin.zip" "$TMPDIR_/extract"
[ -d "$TMPDIR_/extract/Rivault.app" ] || die "Archive missing Rivault.app"
[ -d "$TMPDIR_/extract/skill" ] || die "Archive missing skill/"

echo "  Installing $APP_DIR..."
osascript -e 'quit app "Rivault"' >/dev/null 2>&1 || true
[ -d "$APP_DIR" ] && rm -rf "$APP_DIR"
ditto "$TMPDIR_/extract/Rivault.app" "$APP_DIR"
# Strip the quarantine xattr so the unsigned build opens without the
# "developer cannot be verified" sheet on first launch.
xattr -dr com.apple.quarantine "$APP_DIR" 2>/dev/null || true

# Force-register the just-installed bundle with Launch Services so future
# `open -a Rivault` calls resolve to /Applications/Rivault.app, not to any
# stale dev-build copy LS may have indexed. Without this step, a developer
# who once built locally and then ran install.sh would get the OLD bundle
# launched every time, and the new code would never run.
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"
[ -x "$LSREGISTER" ] && "$LSREGISTER" -f "$APP_DIR" >/dev/null 2>&1 || true

echo "  Installing skill -> $SKILL_DIR"
mkdir -p "$(dirname "$SKILL_DIR")"
[ -d "$SKILL_DIR" ] && rm -rf "$SKILL_DIR"
ditto "$TMPDIR_/extract/skill" "$SKILL_DIR"

# Register the bundle as an OpenClaw plugin so the JS tools
# (rivault_check, rivault_get_secret, rivault_request_auth, …) load into
# the OpenClaw runtime. Without this step, OpenClaw scans only
# ~/.openclaw/extensions/ for plugins (see openclaw's
# `resolvePluginSourceRoots`) and falls back to bash+curl Mode B — which
# bypasses the daemon's transcript redaction.
#
# `openclaw plugins install <dir>` copies into ~/.openclaw/extensions/
# AND registers the plugin in ~/.openclaw/openclaw.json (entries +
# installs + allow). Idempotent: re-running just refreshes the install.
if command -v openclaw >/dev/null 2>&1; then
    echo "  Registering OpenClaw plugin..."
    # Idempotency: `openclaw plugins install` refuses to overwrite an
    # existing ~/.openclaw/extensions/<id> dir, so uninstall first so
    # re-running install.sh always lands a fresh, current bundle.
    openclaw plugins uninstall rivault --force >/dev/null 2>&1 || true
    if openclaw plugins install "$SKILL_DIR" >/dev/null 2>&1; then
        green "  registered as OpenClaw plugin"
    else
        warn "  openclaw plugins install failed (continuing with bash fallback)"
        warn "  to retry manually: openclaw plugins install $SKILL_DIR"
    fi
else
    warn "  openclaw not in PATH — Rivault tools won't load until you install OpenClaw"
    warn "  after installing OpenClaw, run: openclaw plugins install $SKILL_DIR"
fi

mkdir -p "$SUPPORT_DIR"

echo
bold "Almost done -- set your API key."
echo "Get one from https://rivault.ai (Settings -> API keys)."
printf "Paste your API key (rv_live_...) and press Enter, or leave blank to skip: "
# /dev/tty is necessary because stdin is the curl pipe
if [ -t 0 ]; then
    IFS= read -r API_KEY
else
    IFS= read -r API_KEY < /dev/tty || API_KEY=""
fi

if [ -n "${API_KEY:-}" ]; then
    BASE_URL=${RIVAULT_API_URL:-https://api.rivault.ai}
    cat > "$CONFIG_FILE" <<EOF
{
  "apiKey": "${API_KEY}",
  "baseUrl": "${BASE_URL}",
  "version": "${VERSION}"
}
EOF
    chmod 600 "$CONFIG_FILE"
    green "  wrote $CONFIG_FILE (mode 600)"

    # OpenClaw plugin reads the key from `plugins.entries.rivault.config.apiKey`
    # (OpenClaw injects it as `options.apiKey` when loading the plugin), with a
    # fallback to the `RIVAULT_API_KEY` env var. Writing to the plugin config
    # is the right path because (a) it doesn't touch the user's shell rc and
    # (b) it survives across shells, sessions, and reboots.
    OPENCLAW_CFG="${HOME}/.openclaw/openclaw.json"
    if [ -f "$OPENCLAW_CFG" ] && command -v python3 >/dev/null 2>&1; then
        if API_KEY="$API_KEY" BASE_URL="$BASE_URL" python3 - "$OPENCLAW_CFG" <<'PY'
import json, os, sys
path = sys.argv[1]
with open(path) as fh:
    data = json.load(fh)
plugins = data.setdefault("plugins", {})
entries = plugins.setdefault("entries", {})
rivault = entries.setdefault("rivault", {})
rivault["enabled"] = True
cfg = rivault.setdefault("config", {})
cfg["apiKey"] = os.environ["API_KEY"]
cfg["apiUrl"] = os.environ["BASE_URL"]
allow = plugins.setdefault("allow", [])
if "rivault" not in allow:
    allow.append("rivault")
with open(path, "w") as fh:
    json.dump(data, fh, indent=2)
PY
        then
            green "  wrote API key to OpenClaw plugin config"
        else
            warn "  could not write API key to $OPENCLAW_CFG — set it manually in OpenClaw"
        fi
    elif [ ! -f "$OPENCLAW_CFG" ]; then
        # OpenClaw not installed yet — the key in $CONFIG_FILE is enough
        # for the desktop daemon. When the user later installs OpenClaw,
        # they'll need to re-run this installer (or set RIVAULT_API_KEY
        # manually) to wire the key into the plugin config.
        :
    fi
else
    warn "  skipped -- set the key later via the desktop app's Settings tab."
fi

echo
bold "Installed. Launching Rivault..."
open "$APP_DIR" || warn "Could not auto-launch. Run: open \"$APP_DIR\""
echo
echo "Tools:"
echo "  open $APP_DIR         # launch the daemon dashboard"
echo "  $0 --uninstall           # remove app + skill + config"
echo
green "Welcome to Rivault."
