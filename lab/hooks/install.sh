#!/usr/bin/env bash
# Install the CM pre-commit hook into a target repo (default: cwd).
# Also seeds .cm/rules with the harvested ruleset -- the rules derived from
# exploits CodeMender actually synthesized and ran.
set -euo pipefail
TARGET="${1:-$(pwd)}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GITDIR="$(git -C "$TARGET" rev-parse --git-dir)"
GITDIR="$(cd "$TARGET" && cd "$GITDIR" && pwd)"

install -m 0755 "$SRC/pre-commit" "$GITDIR/hooks/pre-commit"
mkdir -p "$TARGET/.cm/rules"
cp "$SRC/../pipeline/harvested-rules/"*.yaml "$TARGET/.cm/rules/" 2>/dev/null || true

# Rules you harvest in Step 7 name the findings you verified, and `git add -A`
# would otherwise commit them into the repo the agent clones -- an unscrubbed
# recall number then measures reading, not detection.
# Excluding it here, in the thing that creates it, beats hoping people notice.
IGN="$TARGET/.gitignore"
# `.cm/` (bare) would re-exclude .cm/risk-accepted/, which README 0f deliberately
# un-excludes with `.cm/*` + a negation. git cannot re-include a path inside an
# excluded DIRECTORY, so appending the bare form here silently killed the audited
# sign-off path: cm-risk-accept.yml triggers on `.cm/risk-accepted/**`, and the
# files could never be committed for it to see.
for pat in ".cm/*" "!.cm/risk-accepted/" "semgrep.json" "cm-findings.json" "cm-ledger.db" "find/" "ledger-report.html" "package-lock.json"; do
  grep -qxF "$pat" "$IGN" 2>/dev/null || echo "$pat" >> "$IGN"
done

echo "installed -> $GITDIR/hooks/pre-commit"
echo "rules     -> $TARGET/.cm/rules ($(ls "$TARGET/.cm/rules" 2>/dev/null | wc -l) file(s))"
echo
echo "knobs:  CM_HOOK_BUDGET=10   CM_HOOK_SKIP=1   CM_HOOK_RULES=<dir>"
echo "bypass: git commit --no-verify   (the server-side gate still applies)"
