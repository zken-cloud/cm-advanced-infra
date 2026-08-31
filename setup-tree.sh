#!/usr/bin/env bash
# Build ~/cm-lab for one user: their private repo, with the pipeline on top,
# committed and pushed. The bootstrap calls this; you can re-run it by hand if
# OS Login had not created your account when the VM first booted.
#
#   sudo cm-lab-setup-tree "$(id -un)"
set -euo pipefail
U="${1:?usage: cm-lab-setup-tree <username>}"
. /var/lib/cm-lab/env    # PROJECT REPO_FULL GH_SECRET GUIDE UPSTREAM

H=$(getent passwd "$U" | cut -d: -f6)
[ -n "$H" ] || { echo "no home directory for $U"; exit 1; }
[ -d "$H/cm-lab" ] && { echo "$H/cm-lab already exists -- nothing to do"; exit 0; }

TOKEN=$(gcloud secrets versions access latest --secret="$GH_SECRET" --project="$PROJECT")
[ -n "$TOKEN" ] || { echo "gh token secret is empty"; exit 1; }

run() { sudo -u "$U" -H "$@"; }

# Seed from upstream, then point origin at YOUR (empty) repo. Never push branches
# or let an agent write patches into somebody else's repository.
run git clone -q "$UPSTREAM" "$H/cm-lab"
run git -C "$H/cm-lab" remote remove origin
run git -C "$H/cm-lab" remote add origin "https://x-access-token:$TOKEN@github.com/$REPO_FULL.git"
run cp -r "$GUIDE/pipeline" "$GUIDE/hooks" "$GUIDE/k8s" "$GUIDE/.github" "$H/cm-lab/"
run cp -r "$GUIDE/targets/harvest-fp-cases" "$H/cm-lab/"
rm -rf "$H/cm-lab/pipeline/__pycache__" "$H/cm-lab/pipeline/.pytest_cache"

# `.cm/*` with a negation, never `.cm/`: git cannot re-include a path inside an
# excluded DIRECTORY, and the risk acceptances have to be committable.
run bash -c "printf '%s\n' '.cm/*' '!.cm/risk-accepted/' semgrep.json cm-findings.json \
  cm-ledger.db 'find/' ledger-report.html package-lock.json >> '$H/cm-lab/.gitignore'"

run npm --prefix "$H/cm-lab" install --silent || echo "WARN: npm install failed; run it in ~/cm-lab"

run git -C "$H/cm-lab" add -A
run git -C "$H/cm-lab" -c user.email="$U@cm-lab" -c user.name="$U" commit -q -m "add the cm pipeline"
# On main, before any branch is cut: this is what makes cm-fanout fire at all, and
# what Step 3's `cm vcs reset` will otherwise delete as untracked.
run git -C "$H/cm-lab" push -q origin HEAD:main || echo "WARN: push failed; push ~/cm-lab before Step 4"

ln -sfn "$GUIDE" "$H/cm-lab-payload"; chown -h "$U" "$H/cm-lab-payload"
echo "~/cm-lab ready for $U"
