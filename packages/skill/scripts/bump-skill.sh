#!/usr/bin/env bash
# Bump SKILL.md + package.json version together, stamp `updatedAt` with
# the current UTC time. Run from anywhere; resolves paths relative to the
# script.
#
# Usage:
#   scripts/bump-skill.sh patch         # 0.2.2 -> 0.2.3
#   scripts/bump-skill.sh minor         # 0.2.2 -> 0.3.0
#   scripts/bump-skill.sh major         # 0.2.2 -> 1.0.0
#   scripts/bump-skill.sh 0.3.0         # explicit
#
# Leaves changes uncommitted so you can include them with your real
# commit. Does not run pnpm build — call that yourself when ready.

set -euo pipefail

here() { cd "$(dirname "$0")" && cd .. && pwd; }
ROOT="$(here)"
SKILL_MD="$ROOT/SKILL.md"
PKG_JSON="$ROOT/package.json"

[[ -f "$SKILL_MD" ]] || { echo "missing $SKILL_MD" >&2; exit 1; }
[[ -f "$PKG_JSON" ]] || { echo "missing $PKG_JSON" >&2; exit 1; }

current_version() {
  python3 -c "
import re, sys
with open('$PKG_JSON') as f: data = f.read()
m = re.search(r'\"version\"\s*:\s*\"([^\"]+)\"', data)
print(m.group(1) if m else '0.0.0')
"
}

bump_version() {
  local part="$1"
  local cur="$2"
  python3 - "$part" "$cur" <<'PY'
import sys
part, cur = sys.argv[1], sys.argv[2]
if part in ("patch","minor","major"):
    major, minor, patch = (int(x) for x in cur.split("."))
    if part == "patch": patch += 1
    elif part == "minor": minor += 1; patch = 0
    elif part == "major": major += 1; minor = 0; patch = 0
    print(f"{major}.{minor}.{patch}")
else:
    print(part)
PY
}

ARG="${1:-patch}"
CUR=$(current_version)
NEW=$(bump_version "$ARG" "$CUR")
STAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

python3 - "$SKILL_MD" "$NEW" "$STAMP" <<'PY'
import re, sys
path, new_ver, stamp = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f: text = f.read()
# Replace or insert `version:` and `updatedAt:` in the YAML frontmatter.
def upsert(text, key, value):
    pat = re.compile(rf"^{key}: .*$", re.M)
    if pat.search(text):
        return pat.sub(f"{key}: {value}", text, count=1)
    return text.replace("name: rivault\n", f"name: rivault\n{key}: {value}\n", 1)
text = upsert(text, "version", new_ver)
text = upsert(text, "updatedAt", stamp)
with open(path, "w") as f: f.write(text)
PY

python3 - "$PKG_JSON" "$NEW" <<'PY'
import json, sys
path, new_ver = sys.argv[1], sys.argv[2]
with open(path) as f: data = json.load(f)
data["version"] = new_ver
with open(path, "w") as f:
    json.dump(data, f, indent=2); f.write("\n")
PY

echo "Bumped SKILL.md + package.json:"
echo "  version:   $CUR -> $NEW"
echo "  updatedAt: $STAMP"
echo
echo "Next steps:"
echo "  pnpm build"
echo "  cp SKILL.md ~/.openclaw/skills/rivault/SKILL.md"
echo "  rsync -a --delete --exclude node_modules --exclude src --exclude tsconfig.json ./ ~/.openclaw/extensions/rivault/"
echo "  git add SKILL.md package.json && git commit -m 'skill: vX.Y.Z [summary]'"
