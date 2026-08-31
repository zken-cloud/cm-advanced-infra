#!/usr/bin/env python3
"""The generated BQ schemas must match the ledger they mirror.

The warehouse is a projection of the ledger, so its schema is derived, not authored.
A hand-kept copy would be the fourth instance of this repo's most expensive pattern
(D38, D47): two copies of one truth, and the copy under test is not the copy that
runs. Here the copy that runs is a JSON file terraform reads at apply time, so the
only thing that keeps it honest is this test.
"""
import os, sys, json, tempfile, importlib.util, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCHEMA_DIR = os.path.join(ROOT, "infra", "terraform", "warehouse-schema")
if not os.path.isdir(SCHEMA_DIR):
    # Same reasoning as test_verify_manifest: the warehouse schema ships with the
    # payload, not with a participant's lab repo. Nothing to check here, and an
    # import-time FileNotFoundError would read as a broken suite.
    print("SKIP  warehouse schema checks (not a payload checkout)")
    raise SystemExit(0)

def load(name, fn):
    s = importlib.util.spec_from_file_location(name, os.path.join(HERE, fn))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

L = load("ledger", "ledger.py")

P, F = [], []
def check(name, cond, detail=""):
    (P if cond else F).append(name)
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not cond else ""))

# The authoritative comparison is against a REAL opened ledger, not against a
# re-reading of the DDL -- open_ledger() also applies the _ADDED migrations, and a
# parser that agreed with my reading of the CREATE TABLE but not with sqlite would
# pass a test and still be wrong. The first version of the generator did exactly
# that: it split on newlines, read one column per line, and produced an 11-column
# `findings` from a 16-column table.
db = L.open_ledger(os.path.join(tempfile.mkdtemp(), "l.db"))

for table in ("findings", "observations", "scans"):
    path = os.path.join(SCHEMA_DIR, f"{table}.json")
    if not os.path.exists(path):
        check(f"{table}.json exists", False); continue
    gen = {c["name"] for c in json.load(open(path))}
    real = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
    check(f"{table}: every ledger column is in the BQ schema",
          real <= gen, f"missing from BQ: {sorted(real - gen)}")
    # snapshot_ts is stamped by the exporter; dt is the hive partition key, which
    # BigQuery appends to an external table's schema whether you declare it or not.
    # Omitting dt made terraform plan a delete+create on every run.
    DERIVED = {"snapshot_ts"}
    check(f"{table}: no BQ column that is neither in the ledger nor derived",
          gen - real <= DERIVED, f"extra: {sorted(gen - real - DERIVED)}")
    check(f"{table}: carries snapshot_ts (every export row is stamped)",
          "snapshot_ts" in gen)
    # dt must NOT be declared: BigQuery rejects a create whose schema contains the
    # hive partition key, even though it returns it on read. See warehouse-schema.py.
    check(f"{table}: does NOT declare dt (BigQuery rejects the create)",
          "dt" not in gen)

# gate_events is written by gate-check.py's emit(), not by the ledger.
ge = {c["name"] for c in json.load(open(os.path.join(SCHEMA_DIR, "gate_events.json")))}
src = open(os.path.join(HERE, "gate-check.py"), encoding="utf8").read()
emitted = set()
for key in ("repo", "sha", "action", "reason", "run_id", "ts", "blocking_count", "blocking"):
    if f'"{key}":' in src:
        emitted.add(key)
check("gate_events: schema covers every field emit() writes",
      emitted <= ge, f"emitted but not in schema: {sorted(emitted - ge)}")

# And the artefact on disk must be what the generator produces today.
r = subprocess.run([sys.executable, os.path.join(HERE, "warehouse-schema.py"),
                    "--check", SCHEMA_DIR], capture_output=True, text=True)
check("the checked-in schemas match what the generator emits now",
      r.returncode == 0, (r.stdout + r.stderr).strip())

print(f"\n{len(P)}/{len(P)+len(F)} passed")
sys.exit(1 if F else 0)
