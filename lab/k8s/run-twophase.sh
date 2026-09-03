#!/bin/bash
# Minimal on-cluster two-phase demo. Requires: kubectl context set, IMGREF, BUCKET.
set -euo pipefail
NS=cm; IMG="${IMGREF:?set IMGREF}"; BUCKET="${BUCKET:?set results bucket}"; POCBUCKET="${POCBUCKET:-${BUCKET%-results}-poc}"
PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
[ -n "$PROJECT" ] || { echo "FATAL: set PROJECT (the pods' GOOGLE_CLOUD_PROJECT)"; exit 1; }
SHARDS="${SHARDS:-3}"                       # K-replicated find over the target
REPO="${REPO:-https://github.com/zken-cloud/vulnerable-app.git}"   # any git URL; see README "pick a target"
REPONAME="$(basename "$REPO" .git)"
SCOPE="${SCOPE:-src}"                       # subtree the agent searches. NOT "." --
# the repo also holds pipeline/ and harvest-fp-cases/, which name the planted bugs.
SHA="${SHA:-}"                              # exact commit to scan; REQUIRED -- see 51-find-job.yaml
SCRUB="${SCRUB:---doc README.md --doc APP-README.md --doc .cm/rules/*.yaml --doc pipeline/harvested-rules/*.yaml}"
# ^ must match cm-fanout.yml. Both copies of the harvested ruleset are named:
# they map cm-v<N> to the planted bug and ship a pattern that finds it.
TIER="${TIER:-critical,high}"               # which severities to verify (verify-select)
TOPN="${TOPN:-20}"                          # keep the N most severe; 0 = no cap
MAXP="${MAXP:-100}"                         # verify cost ceiling
LEDGER="${LEDGER:-/tmp/tp/cm-ledger.db}"    # durable ledger; pulled/pushed to the results bucket

[ -n "$SHA" ] || { echo "FATAL: set SHA=<full 40-char commit> -- an unpinned scan attributes findings to a tree it never read"; exit 1; }
# must be the FULL sha: `git fetch --depth 1 origin <short>` fails with "couldn't
# find remote ref", and the assertion below compares against rev-parse's 40 chars.
case "$SHA" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) echo "FATAL: SHA must be the full 40-character commit, got '$SHA'"; exit 1 ;;
esac
# Render a Job manifest and REFUSE to apply one with a placeholder left in it.
# `git fetch origin __SHA__` fails at run time, not at apply time, so an unrendered
# manifest is accepted happily and every pod dies ninety seconds later. That is how
# __SHA__ shipped unsubstituted in the GitHub Actions path for a week.
render() {
  local out=$1; shift
  sed "$@" > "$out"
  local left
  # `|| true` is load-bearing: grep exits 1 when it matches NOTHING, and under
  # `set -o pipefail` that failure propagates through the assignment, so `set -e`
  # killed the script precisely when the render was CLEAN. Silently, with rc=1,
  # right after the PHASE banner -- the guard fired on success, not on failure.
  left=$(grep -o '__[A-Z]*__' "$out" | sort -u | tr '\n' ' ' || true)
  [ -z "$left" ] || { echo "FATAL: unsubstituted placeholder(s) in $out: $left" >&2; exit 1; }
}

echo "PHASE 1: find x$SHARDS @ $SHA"
kubectl -n $NS delete job cm-find --ignore-not-found
render /tmp/find-job.yaml \
  -e "s#__IMG__#$IMG#g" -e "s#__BUCKET__#$BUCKET#g" -e "s#__SHARDS__#$SHARDS#g" \
  -e "s#__REPOURL__#$REPO#g" -e "s#__REPO__#$REPONAME#g" -e "s#__SCRUB__#$SCRUB#g" \
  -e "s#__SCOPE__#$SCOPE#g" -e "s#__SHA__#$SHA#g" -e "s#__PROJECT__#$PROJECT#g" \
  "$(dirname "$0")/51-find-job.yaml"
kubectl -n $NS apply -f /tmp/find-job.yaml
# A CEILING, NOT A CONTRACT -- the same reasoning PHASE 2's wait already carried,
# which this line did not. Under `set -e` a bare `kubectl wait` that times out
# ABORTS THE WHOLE SCRIPT, so a find whose shards had already landed in GCS was
# never folded, never selected and never ingested. Measured 2026-09-03: the wait
# expired at 600s, the script died, and all three shards were sitting in
# find/$SHA/ complete and untouched. The pods publish on every exit path
# (invariant 5), so giving up on the WAIT must never mean giving up on the
# RESULTS -- PHASE 1.5 counts what actually landed and warns if it is partial.
#
# 600s was also simply too short: observed find durations in this cluster run
# 4m39s-7m18s, and a cold Autopilot scale-up adds two to three minutes on top.
FIND_WAIT="${FIND_WAIT:-1800}"
kubectl -n $NS wait --for=condition=complete job/cm-find --timeout=${FIND_WAIT}s || \
  kubectl -n $NS wait --for=condition=failed job/cm-find --timeout=10s || \
  echo "  find Job did not reach a terminal condition in ${FIND_WAIT}s -- collecting whatever landed"

echo "PHASE 1.5: consolidate + dedup + ledger-suppress"
# `*.db` alone leaves *.db-wal and *.db-shm behind, and sqlite will happily pick up
# a sidecar belonging to a DIFFERENT database on the next run. Observed 2026-09-03:
# Aug-30 sidecars sitting next to freshly downloaded Sep-03 shards.
mkdir -p /tmp/tp && rm -f /tmp/tp/*.db /tmp/tp/*.db-wal /tmp/tp/*.db-shm \
                         /tmp/tp/scrub-*.json /tmp/tp/coverage-*.json
for i in $(seq 0 $((SHARDS-1))); do
  gsutil cp "gs://$BUCKET/find/$SHA/$i.db" "/tmp/tp/$i.db" || true
  gsutil cp "gs://$BUCKET/find/$SHA/scrub-$i.json" "/tmp/tp/scrub-$i.json" || true
  # Coverage (Q13/D55). The find pods publish it; reconcile.py folds it; this path
  # never fetched it, so every manual run reported "coverage: NONE SUPPLIED" and the
  # sha stayed indistinguishable from unscanned -- the exact confusion the table exists
  # to remove.
  gsutil cp "gs://$BUCKET/find/$SHA/coverage-$i.json" "/tmp/tp/coverage-$i.json" || true
done
COVS=$(ls /tmp/tp/coverage-*.json 2>/dev/null | tr '\n' ' ')
# provenance: what the agent was NOT shown (follow-up #1). One line per shard.
echo "SCRUB PROVENANCE (what was withheld from the agent):"
for i in $(seq 0 $((SHARDS-1))); do
  [ -f "/tmp/tp/scrub-$i.json" ] && python3 -c "import json,sys;s=json.load(open('/tmp/tp/scrub-$i.json'))['summary'];print(f\"  shard $i: {s['docs_deleted']} docs, {s['comment_lines_removed']} inline hints, {s['block_comments_flagged']} flagged\")" || echo "  shard $i: no scrub report"
done
# INVARIANT 10, in the operator tool and not only in the pods. This used to be a
# bare `git clone` with no ref, which takes the DEFAULT BRANCH -- so fp3 loci were
# resolved against a tree nobody asked for while the pods scanned $SHA. That is
# exactly INCIDENTS #1, and `|| true` hid it. Fetch the pinned commit and assert it.
rm -rf /tmp/tp/clone
git init -q /tmp/tp/clone
git -C /tmp/tp/clone remote add origin "$REPO"
git -C /tmp/tp/clone fetch -q --depth 1 origin "$SHA" \
  || { echo "FATAL: cannot fetch $SHA from $REPO"; exit 1; }
git -C /tmp/tp/clone checkout -q FETCH_HEAD
GOT=$(git -C /tmp/tp/clone rev-parse HEAD)
[ "$GOT" = "$SHA" ] || { echo "FATAL: clone is at $GOT, expected $SHA"; exit 1; }
echo "  fingerprint source tree pinned at $SHA (asserted)"
# Count what actually LANDED. Passing $SHARDS unconditionally reported a partial
# scan as complete, which is the one thing the scans table (D22) exists to prevent.
LANDED=$(ls /tmp/tp/[0-9]*.db 2>/dev/null | wc -l)
[ "$LANDED" -eq "$SHARDS" ] || echo "  WARNING: only $LANDED/$SHARDS shard db(s) landed — this scan is PARTIAL"
SRC_ROOT=/tmp/tp/clone python3 pipeline/consolidate-dedup.py /tmp/tp/*.db | tee /tmp/tp/queue.txt

echo "PHASE 1.6: severity-selected verify dispatch (--tier $TIER --top-n $TOPN --max-parallelism $MAXP)"
python3 pipeline/verify-select.py --src-root /tmp/tp/clone \
  --tier "$TIER" --top-n "$TOPN" --max-parallelism "$MAXP" \
  ${SEED_VERIFIED:+--seed-verified "$SEED_VERIFIED"} \
  /tmp/tp/*.db | tee /tmp/tp/dispatch.txt
python3 pipeline/verify-select.py --src-root /tmp/tp/clone \
  --tier "$TIER" --top-n "$TOPN" --max-parallelism "$MAXP" --json \
  /tmp/tp/*.db > /tmp/tp/dispatch.json
SELECTED=$(python3 -c "import json;print(len(json.load(open('/tmp/tp/dispatch.json'))))")

if [ "${VERIFY:-0}" != "1" ]; then
  echo "PHASE 2: SKIPPED (set VERIFY=1 to run the paid verify fan-out over $SELECTED fingerprint(s))"
  exit 0
fi

echo "PHASE 2: verify fan-out over $SELECTED selected fingerprint(s)  [PAID]"
[ "$SELECTED" -gt 0 ] || { echo "nothing selected; done"; exit 0; }
kubectl -n $NS delete configmap cm-dispatch --ignore-not-found
kubectl -n $NS create configmap cm-dispatch --from-file=dispatch.json=/tmp/tp/dispatch.json
kubectl -n $NS delete job cm-verify --ignore-not-found
render /tmp/verify-job.yaml \
  -e "s#__IMG__#$IMG#g" -e "s#__BUCKET__#$BUCKET#g" -e "s#__POCBUCKET__#$POCBUCKET#g" \
  -e "s#__N__#$SELECTED#g" -e "s#__REPOURL__#$REPO#g" -e "s#__REPO__#$REPONAME#g" \
  -e "s#__SCRUB__#$SCRUB#g" -e "s#__SCOPE__#$SCOPE#g" -e "s#__SHA__#$SHA#g" \
  -e "s#__PROJECT__#$PROJECT#g" \
  "$(dirname "$0")/52-verify-job.yaml"
kubectl -n $NS apply -f /tmp/verify-job.yaml
# The wait must outlast ONE attempt budget or it always bails early and this
# script's output stops describing the run it started. D42 bounds each cm verify
# attempt at VERIFY_TIMEOUT (default 2700s); the old 2400s here predated that and
# was already shorter than a single attempt.
#
# It is a ceiling, not a contract: whatever happens, we fall through and collect
# whatever verdicts landed. The pods publish on every exit path (invariant 5), so
# giving up on the WAIT never means giving up on the RESULTS -- which is why this
# is `|| true` rather than a failure. Multi-attempt findings can legitimately run
# past this; the reconciler is what actually finishes them (D36), this script is a
# debugging tool.
TP_WAIT="${TP_WAIT:-$(( ${VERIFY_TIMEOUT:-2700} + 600 ))}"
kubectl -n $NS wait --for=condition=complete job/cm-verify --timeout=${TP_WAIT}s || \
  kubectl -n $NS wait --for=condition=failed job/cm-verify --timeout=10s || true

echo "PHASE 2.5: collect verdicts"
mkdir -p /tmp/tp/verify && rm -f /tmp/tp/verify/*.json
gsutil -m cp "gs://$BUCKET/verify/$SHA/*.json" /tmp/tp/verify/ 2>/dev/null || true
python3 - <<'PY'
import json, glob
rows = [json.load(open(f)) for f in sorted(glob.glob("/tmp/tp/verify/*.json"))]
by = {}
for r in rows: by[r["verdict"]] = by.get(r["verdict"], 0) + 1
print(f"\nVERDICTS ({len(rows)} pods): " + "  ".join(f"{k}={v}" for k, v in sorted(by.items())))
for r in sorted(rows, key=lambda r: r["verdict"]):
    print(f"  {r['verdict']:14} {r['canonical_path']:22} tried {r['attempts_tried']}/{r['attempts_budget']}  {r['fingerprint']}")
PY

echo "PHASE 3: ingest verdicts into the ledger + answer the merge gate"
# The ledger accumulates ACROSS runs -- the one thing a ~30%-variable detector
# requires (D16) -- so PHASE 3 is a read-modify-write of a single shared object.
# ledger-sync.sh makes that a compare-and-swap: it pulls a pinned generation, runs
# the fold, and pushes only if nobody wrote in between, re-folding from a fresh
# pull if they did. Measured: 8 concurrent unprotected ingests kept 1 of 8. The
# same 8 through this wrapper kept 8 of 8 (EXPERIMENTS.md).
# $SHA is the operator's pin, asserted against the clone above. It is NOT re-derived
# here: this line used to be `SHA=$(git -C ... rev-parse HEAD || echo unknown)`,
# which silently replaced the pinned commit with the clone's HEAD -- or with the
# literal string "unknown" -- and the ledger then recorded the scan against it.
DONE=$(kubectl -n $NS get job cm-verify -o jsonpath='{.status.succeeded}' 2>/dev/null || echo 0)
set +e
pipeline/ledger-sync.sh with "gs://$BUCKET/ledger/cm-ledger.db" "$LEDGER" \
  --attempts "${LEDGER_ATTEMPTS:-25}" --ok-codes 0,1,2 -- \
  python3 pipeline/ingest-verdicts.py --ledger "$LEDGER" --repo "$REPONAME" --sha "$SHA" \
    --shards-expected "$SHARDS" --shards-completed "$LANDED" --min-shards "$SHARDS" \
    --dispatch /tmp/tp/dispatch.json --verdicts "/tmp/tp/verify/*.json" \
    ${COVS:+--coverage $COVS} \
    --ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GATE=$?
set -e
# 75 = every attempt lost the race. The old code echoed a WARNING and exited 0,
# which turns a DROPPED fold into a green run and a gate that will answer RACE
# for a sha it actually scanned. It has to be fatal.
if [ "$GATE" -ge 3 ]; then
  echo "FATAL: ledger not persisted (ledger-sync rc=$GATE). Verdicts are in gs://$BUCKET/verify/$SHA/ -- re-run PHASE 3." >&2
  exit "$GATE"
fi
# PHASE 3.5: snapshot the ledger into the warehouse. Separate from the fold on
# purpose -- this is a READ, it never touches the ledger, and it must not be able
# to fail the run. A dashboard being a day stale is a nuisance; a gate answer
# being wrong is not, and they must not share a failure mode.
echo "PHASE 3.5: warehouse snapshot"
WH=/tmp/tp/warehouse; rm -rf "$WH"
if python3 pipeline/ledger-export.py --ledger "$LEDGER" --out-dir "$WH" \
     --ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --repo "$REPONAME"; then
  # Snapshot files are content-addressed by timestamp, so no two runs write the
  # same object and there is nothing to serialise -- unlike the ledger itself.
  gsutil -q -m cp -r "$WH"/* "gs://$BUCKET/warehouse/" \
    || echo "  WARNING: warehouse snapshot not uploaded (dashboards go stale; the gate does not care)"
else
  echo "  WARNING: warehouse export failed (see above); the ledger and gate are unaffected"
fi

case $GATE in
  0) echo "GATE: PASS  — merge allowed";;
  1) echo "GATE: BLOCK — verified, unfixed finding(s) present";;
  2) echo "GATE: RACE  — scan incomplete; P1 race policy decides (never a silent pass)";;
esac
exit 0
