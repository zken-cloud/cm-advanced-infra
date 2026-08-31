#!/usr/bin/env python3
"""Assertions for the verify-suppression logic. Run: python3 test_ledger.py"""
import importlib.util, os, sys
_here=os.path.dirname(os.path.abspath(__file__))
spec=importlib.util.spec_from_file_location("ledger", os.path.join(_here,"ledger.py"))
L=importlib.util.module_from_spec(spec); spec.loader.exec_module(L)

AV, MV, TS = "codemender-0.2.0", "gemini-3", "2026-08-18T00:00:00Z"
META={"cwe_class":"sql-injection","enclosing_function":"login","canonical_path":"api.js","source":"verify"}

def fresh(): return L.open_ledger(":memory:")
def q(db, fps, av=AV, mv=MV, maxa=3):
    cons={fp:dict(META) for fp in fps}
    return L.build_verify_queue(db, cons, av, mv, max_attempts=maxa)

def test_new_fp_enqueued():
    db=fresh(); queue,supp=q(db,["fpA"])
    assert len(queue)==1 and len(supp)==0, "new fp must enqueue"

def test_verified_suppressed():
    db=fresh()
    L.ingest(db,"fpA",META,"verified",AV,MV,TS,poc_uri="gs://poc/fpA")
    queue,supp=q(db,["fpA"])
    assert len(queue)==0 and len(supp)==1, "verified must suppress"
    assert supp[0][2]=="already verified"
    assert supp[0][3]=="gs://poc/fpA", "suppression must carry the PoC"

def test_verified_stays_suppressed_on_version_bump():
    """A verified vuln is real regardless of agent version — terminal."""
    db=fresh()
    L.ingest(db,"fpA",META,"verified",AV,MV,TS)
    queue,supp=q(db,["fpA"], av="codemender-0.3.0")  # newer agent
    assert len(supp)==1 and "verified" in supp[0][2], "verified is terminal across versions"

def test_single_negative_retries_not_suppressed():
    """Verify is ~50% non-deterministic: one EXPLOIT_FAILED is a coin flip."""
    db=fresh()
    L.ingest(db,"fpA",META,"exploit_failed",AV,MV,TS)  # 1 attempt
    queue,supp=q(db,["fpA"], maxa=3)
    assert len(queue)==1 and "retry" in queue[0][2], "single negative must retry, not suppress"

def test_negative_cached_after_budget():
    db=fresh()
    for _ in range(3):
        L.ingest(db,"fpA",META,"exploit_failed",AV,MV,TS)  # 3 attempts
    queue,supp=q(db,["fpA"], maxa=3)
    assert len(supp)==1 and "negative-cached" in supp[0][2], "spent budget must negative-cache"

def test_version_bump_reopens_negative():
    """A stronger agent re-opens a negative cache (D8)."""
    db=fresh()
    for _ in range(3):
        L.ingest(db,"fpA",META,"exploit_failed",AV,MV,TS)
    queue,supp=q(db,["fpA"], av="codemender-0.3.0", maxa=3)
    assert len(queue)==1 and "cache invalid" in queue[0][2], "version bump re-opens negatives"

def test_monotonic_fold_verified_wins():
    """verified > unproven, and never regresses."""
    db=fresh()
    L.ingest(db,"fpA",META,"verified",AV,MV,TS)
    L.ingest(db,"fpA",META,"exploit_failed",AV,MV,TS)   # a later timeout must NOT downgrade
    row=db.execute("SELECT verdict FROM findings WHERE fingerprint='fpA'").fetchone()
    assert row["verdict"]=="verified", "monotonic fold: verified must not regress"


# ---- D22: the gate must fail CLOSED ----
def test_gate_no_scan_is_race_not_pass():
    db=L.open_ledger(":memory:")
    a,why,_=L.merge_gate(db,"r","sha1")
    assert a=="RACE", (a,why)          # absence of a verdict is NOT a clean verdict
def test_gate_partial_scan_is_race():
    db=L.open_ledger(":memory:"); L.record_scan(db,"r","s",3,1,"cm","t")
    assert L.merge_gate(db,"r","s",min_shards=3)[0]=="RACE"
def test_gate_complete_clean_passes():
    db=L.open_ledger(":memory:"); L.record_scan(db,"r","s",3,3,"cm","t")
    assert L.merge_gate(db,"r","s",min_shards=3)[0]=="PASS"
def test_gate_blocks_verified_unfixed():
    db=L.open_ledger(":memory:"); L.record_scan(db,"r","s",3,3,"cm","t")
    L.ingest(db,"fp3:a",{"cwe_class":"ssrf","source":"verify"},"verified","a","b","t")
    act,_,d=L.merge_gate(db,"r","s",min_shards=3)
    assert act=="BLOCK" and len(d["blocking"])==1
def test_gate_passes_after_fix():
    db=L.open_ledger(":memory:"); L.record_scan(db,"r","s",3,3,"cm","t")
    L.ingest(db,"fp3:a",{"cwe_class":"ssrf","source":"verify"},"verified","a","b","t")
    L.mark_fixed(db,"fp3:a","t2")
    assert L.merge_gate(db,"r","s",min_shards=3)[0]=="PASS"
def test_gate_race_still_reports_known_blockers():
    """No scan, but we already know of a verified bug -> still surfaced, not hidden."""
    db=L.open_ledger(":memory:")
    L.ingest(db,"fp3:a",{"cwe_class":"ssrf","source":"verify"},"verified","a","b","t")
    act,_,d=L.merge_gate(db,"r","nosha")
    assert act=="RACE" and len(d["blocking"])==1

# ---- D24: deferrals accumulate and eventually force admission ----
def test_deferrals_accumulate():
    db=L.open_ledger(":memory:")
    L.ingest(db,"fp3:d",{"cwe_class":"idor","source":"find"},"unproven","a","b","t")
    assert L.deferrals_of(db,"fp3:d")==0
    for _ in range(3): L.record_deferral(db,"fp3:d","t")
    assert L.deferrals_of(db,"fp3:d")==3

# ---- setup_failed must fold without KeyError and must not outrank verified ----
def test_setup_failed_folds():
    db=L.open_ledger(":memory:")
    L.ingest(db,"fp3:s",{"cwe_class":"x","source":"verify"},"verified","a","b","t")
    L.ingest(db,"fp3:s",{"cwe_class":"x","source":"verify"},"setup_failed","a","b","t2")
    r=db.execute("select verdict from findings where fingerprint='fp3:s'").fetchone()
    assert r["verdict"]=="verified", r["verdict"]

# ---- severity + repo (added 2026-08-24; both were computed then discarded) ----

def test_severity_is_recorded():
    db=fresh()
    L.ingest(db,"fpS",dict(META,severity="HIGH",repo="cm-lab"),"verified",AV,MV,TS)
    r=db.execute("select severity,repo from findings where fingerprint='fpS'").fetchone()
    assert r["severity"]=="HIGH", f"severity dropped: {r['severity']}"
    assert r["repo"]=="cm-lab", f"repo dropped: {r['repo']}"

def test_severity_folds_upward_only():
    """A later run relabelling CRITICAL as LOW must not lower the risk on record.
    The relabel is an observation, not a correction — same argument as the verdict
    fold, and the reason the SELECT has to carry the current severity."""
    db=fresh()
    for sev in ("HIGH","CRITICAL","LOW"):
        L.ingest(db,"fpS",dict(META,severity=sev),"verified",AV,MV,TS)
    r=db.execute("select severity from findings where fingerprint='fpS'").fetchone()
    assert r["severity"]=="CRITICAL", f"severity folded down to {r['severity']}"

def test_severity_absent_does_not_erase():
    """A find-path ingest carries no severity. It must not blank one already set."""
    db=fresh()
    L.ingest(db,"fpS",dict(META,severity="CRITICAL"),"verified",AV,MV,TS)
    L.ingest(db,"fpS",dict(META),"unproven",AV,MV,TS)          # no severity key
    r=db.execute("select severity from findings where fingerprint='fpS'").fetchone()
    assert r["severity"]=="CRITICAL", f"severity erased: {r['severity']}"

def test_migration_adds_columns_without_losing_rows():
    """CREATE TABLE IF NOT EXISTS is a no-op on an existing table, so a ledger
    written before these columns existed would silently keep returning NULL."""
    import sqlite3, tempfile, os as _os
    fd, path = tempfile.mkstemp(suffix=".db"); _os.close(fd); _os.remove(path)
    old = sqlite3.connect(path)
    old.executescript("""CREATE TABLE findings(fingerprint TEXT PRIMARY KEY, cwe_class TEXT,
        enclosing_function TEXT, canonical_path TEXT, verdict TEXT, attempts INTEGER DEFAULT 0,
        deferrals INTEGER DEFAULT 0, fixed_at TEXT, agent_version TEXT, model_version TEXT,
        fp_algo TEXT, poc_uri TEXT, first_seen TEXT, last_updated TEXT);""")
    old.execute("INSERT INTO findings(fingerprint,verdict) VALUES('legacy','verified')")
    old.commit(); old.close()
    db = L.open_ledger(path)
    cols = {r[1] for r in db.execute("PRAGMA table_info(findings)")}
    assert {"severity","repo"} <= cols, f"migration did not add the columns: {cols}"
    n = db.execute("select count(*) from findings").fetchone()[0]
    assert n==1, f"migration lost rows: {n}"
    L.ingest(db,"legacy",dict(META,severity="HIGH"),"verified",AV,MV,TS)
    r=db.execute("select severity from findings where fingerprint='legacy'").fetchone()
    assert r["severity"]=="HIGH", "migrated row must accept a severity"
    db.close(); _os.remove(path)

if __name__=="__main__":
    tests=[v for k,v in sorted(globals().items()) if k.startswith("test_")]
    p=0
    for t in tests:
        try: t(); print(f"PASS  {t.__name__}"); p+=1
        except AssertionError as e: print(f"FAIL  {t.__name__}: {e}")
    print(f"\n{p}/{len(tests)} passed")
    sys.exit(0 if p==len(tests) else 1)
