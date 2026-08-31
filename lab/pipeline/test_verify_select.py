#!/usr/bin/env python3
"""Assertions for verify-select.py. python3 test_verify_select.py

Builds cm-shaped state.db fixtures (the columns load_db reads) with varied
severity across pods, then checks the selection knobs and that suppression /
severity ordering hold."""
import os, sys, sqlite3, tempfile, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
def _load(name, fname):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, fname))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
VS = _load("vs", "verify-select.py")
ledger = VS.ledger

SCHEMA = """CREATE TABLE findings(finding_id TEXT, vuln_id TEXT, vuln_type TEXT, title TEXT,
  file_path TEXT, start_line INT, end_line INT, snippet TEXT, analysis TEXT,
  severity TEXT, status TEXT)"""

# (vuln_id, file, line, severity) -> distinct fingerprints by (path,class,line)
FINDINGS = [
    ("CWE-78",  "a.js", 10, "CRITICAL"),   # os-command-injection
    ("CWE-89",  "b.js", 20, "CRITICAL"),   # sql-injection
    ("CWE-918", "c.js", 30, "HIGH"),       # ssrf
    ("CWE-22",  "d.js", 40, "HIGH"),       # path-traversal
    ("CWE-1321","e.js", 50, "MEDIUM"),     # prototype-pollution
    ("CWE-799", "f.js", 60, "LOW"),        # business-logic
]

def _mkdb(path, rows, pod_tag):
    c = sqlite3.connect(path); c.execute(SCHEMA)
    for i, (cwe, f, ln, sev) in enumerate(rows):
        c.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  (f"{pod_tag}-{i}", cwe, "T", "t", f, ln, ln, "sink(x)", "", sev, "OPEN"))
    c.commit(); c.close()

_SUB = [0]
def _dbs(tmp, n_pods=3, rows=FINDINGS):
    d = os.path.join(tmp, f"set{_SUB[0]}"); _SUB[0]+=1; os.makedirs(d, exist_ok=True)
    paths = []
    for p in range(n_pods):
        pp = os.path.join(d, f"pod{p}.db"); _mkdb(pp, rows, f"p{p}"); paths.append(pp)
    return paths

def _merged(tmp):
    return VS.consolidate_fanout(_dbs(tmp), "")

def t_severity_carried():
    with tempfile.TemporaryDirectory() as tmp:
        merged = _merged(tmp)
        assert len(merged) == 6, len(merged)                 # 6 distinct, deduped across 3 pods
        sevs = sorted(m["severity_rank"] for m in merged.values())
        assert sevs == [1,2,3,3,4,4], sevs
        assert all(m["reproductions"] == 3 for m in merged.values())  # each seen by 3 pods

def t_tier_filters_to_crit_high():
    with tempfile.TemporaryDirectory() as tmp:
        merged = _merged(tmp); db = ledger.open_ledger(":memory:")
        disp, deferred, _ = VS.select(merged, db, "a", "m", tier="critical,high")
        assert len(disp) == 4 and all(d["severity_rank"] >= 3 for d in disp)
        assert {d["severity"] for d in disp} == {"CRITICAL","HIGH"}
        assert all("not in --tier" in r for _,_,r in deferred)   # medium+low deferred, not dropped

def t_min_severity_threshold():
    with tempfile.TemporaryDirectory() as tmp:
        merged = _merged(tmp); db = ledger.open_ledger(":memory:")
        disp, _, _ = VS.select(merged, db, "a", "m", min_severity="high")
        assert {d["severity"] for d in disp} == {"CRITICAL","HIGH"}

def t_top_n_keeps_most_severe():
    with tempfile.TemporaryDirectory() as tmp:
        merged = _merged(tmp); db = ledger.open_ledger(":memory:")
        disp, deferred, _ = VS.select(merged, db, "a", "m", top_n=2)
        assert len(disp) == 2 and all(d["severity"] == "CRITICAL" for d in disp)  # 2 crits win
        assert any("beyond --top-n" in r for _,_,r in deferred)

def t_ordering_severity_then_repro():
    with tempfile.TemporaryDirectory() as tmp:
        # crit seen by 1 pod vs high seen by 3: crit still first (severity dominates)
        dbs = _dbs(tmp, 1, [("CWE-78","a.js",10,"CRITICAL")]) + _dbs(tmp, 3, [("CWE-918","c.js",30,"HIGH")])
        merged = VS.consolidate_fanout(dbs, "")
        db = ledger.open_ledger(":memory:")
        disp, _, _ = VS.select(merged, db, "a", "m")
        assert disp[0]["severity"] == "CRITICAL" and disp[1]["severity"] == "HIGH"

def t_max_parallelism_caps():
    with tempfile.TemporaryDirectory() as tmp:
        merged = _merged(tmp); db = ledger.open_ledger(":memory:")
        disp, deferred, _ = VS.select(merged, db, "a", "m", max_parallelism=3)
        assert len(disp) == 3
        assert any("cost cap" in r for _,_,r in deferred)

def t_verified_is_suppressed_not_dispatched():
    with tempfile.TemporaryDirectory() as tmp:
        merged = _merged(tmp); db = ledger.open_ledger(":memory:")
        # pre-verify one CRITICAL fingerprint in the ledger
        crit_fp = next(fp for fp,m in merged.items() if m["severity"]=="CRITICAL")
        ledger.ingest(db, crit_fp, {"cwe_class":"x","source":"verify"}, "verified",
                      "a", "m", "2026-01-01", poc_uri="gs://poc/x")
        disp, _, suppressed = VS.select(merged, db, "a", "m")
        assert crit_fp not in {d["fingerprint"] for d in disp}
        assert crit_fp in {fp for fp,_,_ in suppressed}

def t_attempts_from_gate_by_class():
    with tempfile.TemporaryDirectory() as tmp:
        merged = _merged(tmp); db = ledger.open_ledger(":memory:")
        disp, _, _ = VS.select(merged, db, "a", "m", tier="critical")
        # os-command-injection p=0.85, target 0.99 (sev 4) -> 3 attempts; harness functional
        d = next(x for x in disp if x["cwe_class"] == "os-command-injection")
        assert d["harness"] == "functional-exploit" and d["attempts"] == 3, d

def t_shard_identifies_source_db():
    """dispatch must name the shard whose state.db holds the finding, so the verify
    pod restores it instead of re-discovering (which loses ~30% to detector noise)."""
    with tempfile.TemporaryDirectory() as tmp:
        d=os.path.join(tmp,"fan"); os.makedirs(d)
        # only shard "1" reports the SSRF; shards 0 and 2 report nothing
        _mkdb(os.path.join(d,"0.db"), [("CWE-89","b.js",20,"CRITICAL")], "p0")
        _mkdb(os.path.join(d,"1.db"), [("CWE-918","c.js",30,"HIGH")], "p1")
        _mkdb(os.path.join(d,"2.db"), [("CWE-89","b.js",20,"CRITICAL")], "p2")
        merged=VS.consolidate_fanout([os.path.join(d,f"{i}.db") for i in (0,1,2)], "")
        db=ledger.open_ledger(":memory:")
        disp,_,_=VS.select(merged, db, "a", "m")
        ssrf=next(x for x in disp if x["cwe_class"]=="ssrf")
        assert ssrf["shard"]=="1", ssrf            # <- the db to restore
        assert ssrf["reproductions"]==1
        sqli=next(x for x in disp if x["cwe_class"]=="sql-injection")
        assert sqli["shard"]=="0" and sqli["pods"]==["0","2"], sqli
        assert sqli["reproductions"]==2

def t_deferred_is_force_admitted_after_limit():
    """D24: a MEDIUM finding excluded by --tier must not be excluded forever.
    Measured motivation: CM moved filterProducts HIGH->MEDIUM between runs, so tier
    filtering alone made verification of a real bug a coin flip."""
    with tempfile.TemporaryDirectory() as tmp:
        merged=_merged(tmp); db=ledger.open_ledger(":memory:")
        med=next(fp for fp,m in merged.items() if m["severity"]=="MEDIUM")
        # first passes: deferred each time, deferral recorded
        for i in range(3):
            disp,deferred,_=VS.select(merged, db, "a","m", tier="critical,high",
                                      defer_limit=3, ts=f"t{i}")
            assert med not in {d["fingerprint"] for d in disp}
            assert med in {fp for fp,_,_ in deferred}
        # now aged past the limit -> force-admitted despite the tier filter
        disp,deferred,_=VS.select(merged, db, "a","m", tier="critical,high",
                                  defer_limit=3, ts="t3")
        d=next((x for x in disp if x["fingerprint"]==med), None)
        assert d is not None, "deferred finding never came back — silent permanent drop"
        assert "force-admitted" in d["queue_reason"], d["queue_reason"]

def t_no_deferral_recorded_without_ts():
    """ts=None keeps select() side-effect free for callers that only want a preview."""
    with tempfile.TemporaryDirectory() as tmp:
        merged=_merged(tmp); db=ledger.open_ledger(":memory:")
        med=next(fp for fp,m in merged.items() if m["severity"]=="MEDIUM")
        for _ in range(5):
            VS.select(merged, db, "a","m", tier="critical,high", defer_limit=3)
        assert ledger.deferrals_of(db, med)==0

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("t_")]
    p = 0
    for t in tests:
        try: t(); print(f"PASS  {t.__name__}"); p += 1
        except AssertionError as e: print(f"FAIL  {t.__name__}: {e}")
        except Exception as e:
            import traceback; print(f"ER*R  {t.__name__}: {e}"); traceback.print_exc()
    print(f"\n{p}/{len(tests)} passed"); sys.exit(0 if p == len(tests) else 1)
