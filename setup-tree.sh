#!/usr/bin/env bash
# Build ~/cm-lab for one user: their private repo, with the pipeline on top,
# committed and pushed. The bootstrap calls this; you can re-run it by hand if
# OS Login had not created your account when the VM first booted, or to repair an
# origin pointing at the wrong repo -- on a tree that already exists it re-points
# the remote and touches nothing else.
#
#   sudo cm-lab-setup-tree "$(id -un)"
set -euo pipefail
U="${1:?usage: cm-lab-setup-tree <username>}"
. /var/lib/cm-lab/env    # PROJECT REPO_FULL GH_SECRET GUIDE UPSTREAM

H=$(getent passwd "$U" | cut -d: -f6)
[ -n "$H" ] || { echo "no home directory for $U"; exit 1; }
TOKEN=$(gcloud secrets versions access latest --secret="$GH_SECRET" --project="$PROJECT")
[ -n "$TOKEN" ] || { echo "gh token secret is empty"; exit 1; }

run() { sudo -u "$U" -H "$@"; }

# --- per-user environment, independent of the tree ---------------------------
# Both of these run BEFORE the existing-tree exit, because they are properties of
# the ACCOUNT, not of the checkout, and a participant whose tree already exists
# needs them just as much.

# gh, for the user. The bootstrap authenticated gh as ROOT, which left every `gh`
# command the guide asks a participant to run -- the Step 4 checkpoint, the Step 6
# PR, the branch protection call -- failing with "not logged into any GitHub
# hosts" on a tree that was otherwise perfect. GH_TOKEN rather than
# `gh auth login`: login validates scopes and demands read:org, which this lab
# deliberately does not ask for. The token is already in this user's
# ~/cm-lab/.git/config, so ~/.bashrc adds no exposure that was not there.
if ! grep -q GH_TOKEN "$H/.bashrc" 2>/dev/null; then
  run tee -a "$H/.bashrc" >/dev/null <<BASHRC

# cm-lab: gh reads this. \`gh auth login\` would demand read:org; this does not.
export GH_TOKEN=$TOKEN
BASHRC
  echo "gh: GH_TOKEN exported in $H/.bashrc"
fi

# cm, for the user. `cm report import` in Step 3 fails outright without this --
# "CodeMender has not been initialized" -- and nothing in the lab ever ran it.
# Guarded: `cm init` on an initialised workspace PROMPTS to overwrite, and a `y`
# there destroys a config the participant may have edited.
if [ ! -d "$H/.codemender" ]; then
  run cm init >/dev/null 2>&1 && echo "cm: workspace initialised for $U" \
    || echo "WARN: cm init failed -- run it yourself before Step 3"
fi

# An existing tree used to mean "nothing to do", which made re-running this script
# useless as a repair: the one thing that can be wrong on a tree that already
# exists is its origin, and that was the one thing the early exit refused to touch.
# So repair the remote and stop. NEVER rebuild -- there is work in that tree, and
# the guide's Step 4 check sends people here.
if [ -d "$H/cm-lab" ]; then
  if run git -C "$H/cm-lab" rev-parse --git-dir >/dev/null 2>&1; then
    run git -C "$H/cm-lab" remote remove origin >/dev/null 2>&1 || true
    run git -C "$H/cm-lab" remote add origin "https://x-access-token:$TOKEN@github.com/$REPO_FULL.git"
    echo "$H/cm-lab already exists -- origin re-pointed at $REPO_FULL, nothing else touched"
  else
    echo "$H/cm-lab exists but is not a git repo -- move it aside and re-run"
  fi
  exit 0
fi

# Seed from upstream, then point origin at YOUR (empty) repo. Never push branches
# or let an agent write patches into somebody else's repository.
run git clone -q "$UPSTREAM" "$H/cm-lab"
run git -C "$H/cm-lab" remote remove origin
run git -C "$H/cm-lab" remote add origin "https://x-access-token:$TOKEN@github.com/$REPO_FULL.git"
run cp -r "$GUIDE/pipeline" "$GUIDE/hooks" "$GUIDE/k8s" "$GUIDE/.github" "$H/cm-lab/"
run cp -r "$GUIDE/targets/harvest-fp-cases" "$H/cm-lab/"
# targets/oracle-specs keeps its path: oracle-run.py takes --spec
# targets/oracle-specs/<target>.yaml, and it is where you write the spec for a
# finding you verified. Without it the four spec-integrity tests listdir a
# directory that is not there -- 19/19 in the repo, 15/19 in the lab tree, from
# layout alone.
run mkdir -p "$H/cm-lab/targets"
run cp -r "$GUIDE/targets/oracle-specs" "$H/cm-lab/targets/"
# The canary is the positive control for the exploit harness: it must FIRE on a
# vulnerable fixture and stay SILENT on a fixed one. test_harness_health.py looks
# for it at infra/runner-image/canary, and setup-tree has never copied infra/ --
# so that check has always failed in a participant's tree while passing in the
# repo. A harness-health suite that cannot exercise the harness is the exact
# blind spot it exists to close (invariant 7).
run mkdir -p "$H/cm-lab/infra/runner-image"
run cp -r "$GUIDE/infra/runner-image/canary" "$H/cm-lab/infra/runner-image/"
# .cm/ carries the risk-acceptance template and is where risk-accept.py writes.
# Missed in the payload move: `git ls-files` patterns that name directories skip
# dotfiles, and so did the check I used to convince myself the move was complete.
run cp -r "$GUIDE/.cm" "$H/cm-lab/"
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
# Say whose repo this is, at build time. Every push in Part C follows origin, and
# the participant has a second clone (the shared cm-advanced-infra) on their
# workstation where the same git commands are equally valid. Name, never URL:
# origin carries the PAT.
echo "~/cm-lab ready for $U -- origin is $REPO_FULL (your repo; the shared repos are read-only inputs)"
