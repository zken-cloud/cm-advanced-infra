#!/usr/bin/env bash
# Concurrency test for the GCS-backed ledger. Needs a real bucket -- the whole
# point is the atomicity of GCS generation preconditions, which no local mock has.
#
#   ./pipeline/test-ledger-cas.sh gs://<bucket>/_cas-test [N]
#
# Runs N ingests simultaneously twice: once through the unprotected pull-modify-push
# the pipeline used to do, once through ledger-sync.sh. Each writes a DISTINCT
# fingerprint, so the correct final count is exactly N and anything less is a lost
# update, not a duplicate-collapse.
set -uo pipefail
BASE="${1:?usage: test-ledger-cas.sh gs://bucket/prefix [N]}"
N="${2:-8}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/w.py" <<PY
import sys, importlib.util
_s = importlib.util.spec_from_file_location("ledger", "$HERE/ledger.py")
L = importlib.util.module_from_spec(_s); _s.loader.exec_module(L)
db = L.open_ledger(sys.argv[1])
L.ingest(db, sys.argv[2], {"source":"verify","canonical_path":"src/x.js",
         "enclosing_function":"f","cwe_class":"CWE-94"}, "verified",
         "cm-0.4.0","m","2026-01-01T00:00:00Z")
db.close()
PY

count() { gcloud storage cp "$1" "$WORK/c.db" >/dev/null 2>&1 &&
          python3 -c "import sqlite3;print(sqlite3.connect('$WORK/c.db').execute('select count(*) from findings').fetchone()[0])" ||
          echo 0; }

echo "== A. unprotected pull-modify-write, $N simultaneous =="
gcloud storage rm "$BASE/a.db" >/dev/null 2>&1
for i in $(seq 1 "$N"); do
  ( gcloud storage cp "$BASE/a.db" "$WORK/a$i.db" >/dev/null 2>&1
    python3 "$WORK/w.py" "$WORK/a$i.db" "fp3_a$i"
    gcloud storage cp "$WORK/a$i.db" "$BASE/a.db" >/dev/null 2>&1 ) &
done; wait
A=$(count "$BASE/a.db"); echo "   kept $A/$N  (lost $((N-A)))"

echo "== B. ledger-sync.sh compare-and-swap, $N simultaneous =="
gcloud storage rm "$BASE/b.db" >/dev/null 2>&1
for i in $(seq 1 "$N"); do
  ( "$HERE/ledger-sync.sh" with "$BASE/b.db" "$WORK/b$i.db" --attempts 25 -- \
      python3 "$WORK/w.py" "$WORK/b$i.db" "fp3_b$i" >/dev/null 2>&1 ) &
done; wait
B=$(count "$BASE/b.db"); echo "   kept $B/$N  (lost $((N-B)))"

gcloud storage rm "$BASE/a.db" "$BASE/b.db" >/dev/null 2>&1
[ "$B" -eq "$N" ] || { echo "FAIL: compare-and-swap lost $((N-B)) update(s)"; exit 1; }
[ "$A" -lt "$N" ] || echo "NOTE: the unprotected run lost nothing this time -- raise N to reproduce"
echo "PASS"
