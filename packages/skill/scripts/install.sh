#!/usr/bin/env bash
# Rivault post-plugin-install setup
# Run this once after: openclaw plugins install <tarball>
#
# Usage:
#   bash ~/.openclaw/extensions/rivault/scripts/install.sh

set -euo pipefail

EXTENSIONS_DIR="$HOME/.openclaw/extensions/rivault"
SKILLS_DIR="$HOME/.openclaw/skills/rivault"
SKILL_SRC="$EXTENSIONS_DIR/skills/rivault/SKILL.md"

# 1. Install the skill prompt into the managed skills directory
echo "→ Installing skill prompt..."
mkdir -p "$SKILLS_DIR"
cp "$SKILL_SRC" "$SKILLS_DIR/SKILL.md"
echo "  Copied to $SKILLS_DIR/SKILL.md"

# 2. Add rivault to plugins.allow so the LaunchAgent gateway loads it
echo "→ Allowlisting plugin..."
CURRENT_ALLOW=$(openclaw config get plugins.allow 2>/dev/null || echo "[]")
if echo "$CURRENT_ALLOW" | grep -q '"rivault"'; then
  echo "  Already allowlisted"
else
  openclaw config set plugins.allow "$(echo "$CURRENT_ALLOW" | python3 -c "
import json, sys
val = json.load(sys.stdin)
if 'rivault' not in val:
    val.append('rivault')
print(json.dumps(val))
  ")"
  echo "  Added rivault to plugins.allow"
fi

# 3. Restart gateway
echo "→ Restarting gateway..."
openclaw gateway restart

echo ""
echo "✓ Done! Open http://127.0.0.1:18789/skills and enter your API key for Rivault."
