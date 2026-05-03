#!/bin/sh
# Rivault installer for macOS.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Rivault-ai/desktop/main/install.sh | sh
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

for arg in "$@"; do
    case "$arg" in
        --uninstall)     ACTION="uninstall" ;;
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
    [ -d "$SKILL_DIR" ] && rm -rf "$SKILL_DIR" && green "  removed $SKILL_DIR"
    [ -f "$CONFIG_FILE" ] && rm -f "$CONFIG_FILE" && green "  removed $CONFIG_FILE"
    warn "  preserved $SUPPORT_DIR (contains your local ledger). Delete manually if you want a clean slate."
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

echo "  Installing skill -> $SKILL_DIR"
mkdir -p "$(dirname "$SKILL_DIR")"
[ -d "$SKILL_DIR" ] && rm -rf "$SKILL_DIR"
ditto "$TMPDIR_/extract/skill" "$SKILL_DIR"

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
else
    warn "  skipped -- set the key later via the desktop app's Settings tab."
fi

echo
bold "Installed. Launching Rivault..."
open -a Rivault || warn "Could not auto-launch. Run: open -a Rivault"
echo
echo "Tools:"
echo "  open -a Rivault          # launch the daemon dashboard"
echo "  $0 --uninstall           # remove app + skill + config"
echo
green "Welcome to Rivault."
