#!/usr/bin/env python3
"""Q14/D45 — a run that verified nothing must not read as a clean bill of health.

The hole: the merge gate is `scan_complete AND no verified-unfixed`. A fan-out whose
every pod died in setup satisfies both clauses — the find shards landed, and nothing
got verified — so the gate says PASS on a run that tested nothing. Measured
2026-08-25: Complete 6/6, every verdict setup_failed, zero verification.

These tests pin the discrimination, in BOTH directions. A control that only fires is
as useless as one that never does.
"""
import os, sys, tempfile, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location(
    "ledger", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ledger.py"))
ledger = importlib.util.module_from_spec(spec); spec.loader.exec_module(ledger)

P, F = [], []
def check(name, cond):
    (P if cond else F).append(name)
    print(f"{'PASS' if cond else 'FAIL'}  {name}")

def fresh():
    d = tempfile.mkdtemp()
    db = ledger.open_ledger(os.path.join(d, "l.db"))
    return db

def scanned(db, repo="r", sha="s", shards=3):
    ledger.record_scan(db, repo, sha, shards, shards, "cm-0.4.0", "2026-08-25T00:00:00Z")

# --- the failure this exists to catch -------------------------------------------
db = fresh(); scanned(db)
ledger.record_verify_health(db, "r", "s", 6, 0, "2026-08-25T00:00:00Z")
act, why, det = ledger.merge_gate(db, "r", "s", 1)
check("6 dispatched / 0 opinions -> RACE, never PASS", act == "RACE")
check("  and the reason names the harness, not the findings", "formed an opinion" in why)

# --- must NOT fire: a healthy run with nothing to block on ----------------------
db = fresh(); scanned(db)
ledger.record_verify_health(db, "r", "s", 6, 6, "2026-08-25T00:00:00Z")
act, _, _ = ledger.merge_gate(db, "r", "s", 1)
check("6 dispatched / 6 opinions, nothing verified -> PASS", act == "PASS")

# --- must NOT fire: a PARTLY broken run still produced evidence -----------------
# invariant 6 already stops the failed half poisoning anything, so a partial run is
# real evidence. Alarming here would make ordinary flakiness un-passable.
db = fresh(); scanned(db)
ledger.record_verify_health(db, "r", "s", 6, 3, "2026-08-25T00:00:00Z")
act, _, _ = ledger.merge_gate(db, "r", "s", 1)
check("6 dispatched / 3 opinions -> PASS (partial is still evidence)", act == "PASS")

# --- must NOT fire: a find-only run never dispatched verify ---------------------
# Marking these untrustworthy would make every discovery-only fan-out permanently
# un-passable, which is a different way of failing open (nobody would keep the gate).
db = fresh(); scanned(db)
ledger.record_verify_health(db, "r", "s", 0, 0, "2026-08-25T00:00:00Z")
act, _, _ = ledger.merge_gate(db, "r", "s", 1)
check("0 dispatched / 0 opinions (find-only) -> PASS", act == "PASS")

# --- BLOCK survives a broken harness --------------------------------------------
# A verified finding with a working exploit does not stop being real because other
# pods failed. Downgrading BLOCK to RACE here would let a broken run UNBLOCK a bug.
db = fresh(); scanned(db)
ledger.ingest(db, "fp3:aaa", {"canonical_path": "a.js", "cwe_class": "sqli",
                              "source": "verify", "repo": "r"},
              "verified", "cm-0.4.0", "m1", "2026-08-25T00:00:00Z")
ledger.record_verify_health(db, "r", "s", 6, 0, "2026-08-25T00:00:00Z")
act, _, _ = ledger.merge_gate(db, "r", "s", 1)
check("broken harness + a verified finding -> still BLOCK", act == "BLOCK")

# --- an older ledger with no health column must not become un-passable ----------
db = fresh(); scanned(db)
act, _, _ = ledger.merge_gate(db, "r", "s", 1)
check("pre-D45 scan with no health recorded -> PASS (no retro-blocking)", act == "PASS")

# --- the verdict split ----------------------------------------------------------
check("setup_failed counts as harness, not opinion", "setup_failed" in ledger.HARNESS_VERDICTS)
check("terminated counts as harness (D37 killed siblings)", "terminated" in ledger.HARNESS_VERDICTS)
check("exploit_failed is an OPINION, not a harness failure", "exploit_failed" not in ledger.HARNESS_VERDICTS)
check("timeout is an OPINION (D42: it is negative-cache data)", "timeout" not in ledger.HARNESS_VERDICTS)

# --- the canary itself, both directions -----------------------------------------
here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
canary = os.path.join(here, "infra", "runner-image", "canary", "exploit.sh")
if os.path.exists(canary):
    r = subprocess.run(["bash", canary], capture_output=True, text=True)
    check("canary fires against the vulnerable fixture", r.returncode == 0 and "FIRED" in r.stdout)
    d = tempfile.mkdtemp()
    subprocess.run(["cp", canary, d], check=True)
    open(os.path.join(d, "vulnerable.js"), "w").write(
        'const path=require("path");\n'
        'function safeJoin(b,u){const r=path.resolve(b,String(u));\n'
        '  return r.startsWith(path.resolve(b)+"/")?r:path.resolve(b);}\n'
        'module.exports={safeJoin};\n')
    r2 = subprocess.run(["bash", os.path.join(d, "exploit.sh")], capture_output=True, text=True)
    check("canary stays SILENT against a fixed fixture", r2.returncode == 1 and "DID NOT FIRE" in r2.stdout)
else:
    check("canary bundle present", False)

print(f"\n{len(P)}/{len(P)+len(F)} passed")
sys.exit(1 if F else 0)
