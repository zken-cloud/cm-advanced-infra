#!/usr/bin/env python3
"""Assertions for verdict ingestion + the gate answer. python3 test_ingest.py"""
import os,sys,json,glob,tempfile,subprocess,importlib.util
HERE=os.path.dirname(os.path.abspath(__file__))
_s=importlib.util.spec_from_file_location("ledger",os.path.join(HERE,"ledger.py"))
L=importlib.util.module_from_spec(_s); _s.loader.exec_module(L)
ALGO=L.dedup.FP_ALGO

def _cov(tmp, n, in_scope, observed, scope="src"):
    """n shard coverage envelopes, each claiming `in_scope` files and `observed` seen."""
    paths=[]
    for i in range(n):
        files=[{"path":f"f{j}.js","in_scope":True,"skip_reason":None,
                "observed":j<observed,"content_hash":f"h{j}"} for j in range(in_scope)]
        env={"message_type":"coverage_filelevel","agent_version":"codemender-0.5.0",
             "scanned_at":"2026-01-01T00:00:00Z","repo":"r","sha":"abc123","scope":scope,
             "root":scope,"files_total":in_scope,"files_in_scope":in_scope,
             "files_excluded":0,"files_observed":observed,"excluded_by":{},"files":files}
        f=os.path.join(tmp,f"coverage-{i}.json"); json.dump(env,open(f,"w")); paths.append(f)
    return paths

def _run(tmp, verdicts, dispatch=None, shards=(3,3), sha="abc123", coverage=None):
    vd=os.path.join(tmp,"v"); os.makedirs(vd,exist_ok=True)
    for i,v in enumerate(verdicts): json.dump(v,open(os.path.join(vd,f"{i}.json"),"w"))
    dp=os.path.join(tmp,"d.json"); json.dump(dispatch or [],open(dp,"w"))
    led=os.path.join(tmp,"l.db")
    cmd=[sys.executable,os.path.join(HERE,"ingest-verdicts.py"),
        "--ledger",led,"--repo","r","--sha",sha,"--shards-expected",str(shards[0]),
        "--shards-completed",str(shards[1]),"--min-shards",str(shards[0]),
        "--dispatch",dp,"--verdicts",os.path.join(vd,"*.json"),
        "--ts","2026-01-01T00:00:00Z"]
    if coverage: cmd+=["--coverage"]+coverage
    p=subprocess.run(cmd,capture_output=True,text=True)
    return p.returncode, p.stdout+p.stderr, led

def t_verified_verdict_blocks():
    with tempfile.TemporaryDirectory() as t:
        fp=f"{ALGO}:aaaa"
        rc,out,_=_run(t,[{"fingerprint":fp,"verdict":"verified","canonical_path":"a.js"}],
                      [{"fingerprint":fp,"cwe_class":"ssrf","canonical_path":"a.js","enclosing_function":"f"}])
        assert rc==1 and "BLOCK" in out, out

def t_clean_scan_passes():
    with tempfile.TemporaryDirectory() as t:
        rc,out,_=_run(t,[])
        assert rc==0 and "PASS" in out, out

def t_a_later_publish_seq_supersedes_the_first():
    """INCIDENTS 9, with the credential taken into account. A verify pod whose trap
    fired early publishes `terminated`, computes the real answer, and CANNOT
    overwrite -- objectCreator refuses the second write to the same key. The
    correction arrives as a separate envelope with a higher publish_seq, and that
    one is the answer. Ingesting both, or taking the first, re-creates the bug."""
    with tempfile.TemporaryDirectory() as t:
        fp=f"{ALGO}:aaaa"
        rc,out,_=_run(t,[
            {"fingerprint":fp,"verdict":"terminated","canonical_path":"a.js","publish_seq":1},
            {"fingerprint":fp,"verdict":"verified","canonical_path":"a.js","publish_seq":2},
        ],[{"fingerprint":fp,"cwe_class":"ssrf","canonical_path":"a.js","enclosing_function":"f"}])
        assert "superseded" in out, out
        assert rc==1 and "BLOCK" in out, out          # the REAL answer gates

def t_the_first_envelope_does_not_supersede_a_later_one():
    """Order on disk must not decide it. Same pair, written the other way round."""
    with tempfile.TemporaryDirectory() as t:
        fp=f"{ALGO}:bbbb"
        rc,out,_=_run(t,[
            {"fingerprint":fp,"verdict":"verified","canonical_path":"a.js","publish_seq":2},
            {"fingerprint":fp,"verdict":"terminated","canonical_path":"a.js","publish_seq":1},
        ],[{"fingerprint":fp,"cwe_class":"ssrf","canonical_path":"a.js","enclosing_function":"f"}])
        assert rc==1 and "BLOCK" in out, out

def t_envelopes_with_no_seq_still_ingest():
    """Everything published before publish_seq existed has no field. It must read as
    seq 0 and behave exactly as it did, or this change rewrites history."""
    with tempfile.TemporaryDirectory() as t:
        fp=f"{ALGO}:cccc"
        rc,out,_=_run(t,[{"fingerprint":fp,"verdict":"verified","canonical_path":"a.js"}],
                      [{"fingerprint":fp,"cwe_class":"ssrf","canonical_path":"a.js","enclosing_function":"f"}])
        assert "superseded" not in out, out
        assert rc==1 and "BLOCK" in out, out

def t_different_fingerprints_never_supersede_each_other():
    with tempfile.TemporaryDirectory() as t:
        a,b=f"{ALGO}:dddd",f"{ALGO}:eeee"
        rc,out,_=_run(t,[
            {"fingerprint":a,"verdict":"not_exploitable","canonical_path":"a.js","publish_seq":1},
            {"fingerprint":b,"verdict":"verified","canonical_path":"b.js","publish_seq":1},
        ],[{"fingerprint":a,"cwe_class":"ssrf","canonical_path":"a.js","enclosing_function":"f"},
           {"fingerprint":b,"cwe_class":"ssrf","canonical_path":"b.js","enclosing_function":"g"}])
        assert "superseded" not in out, out
        assert rc==1 and "BLOCK" in out, out

def t_stale_algo_is_refused():
    with tempfile.TemporaryDirectory() as t:
        rc,out,_=_run(t,[{"fingerprint":"fp1:old","verdict":"verified","canonical_path":"a.js"}])
        assert "REFUSED" in out and "fp1" in out, out

def t_refused_verdicts_do_not_read_as_clean():
    """The fail-open trap one level up: results that never landed must not PASS."""
    with tempfile.TemporaryDirectory() as t:
        rc,out,_=_run(t,[{"fingerprint":"fp1:old","verdict":"verified","canonical_path":"a.js"}])
        assert rc==2 and "RACE" in out, out
        # match the gate LINE, not the substring inside "never PASS"
        assert "]: PASS" not in out, out

def t_scan_that_examined_nothing_is_not_a_clean_scan():
    """THE phantom scan. Measured 2026-09-03 on two fresh projects: `cm find` never
    started (StartSession timed out), the EXIT trap published the shards anyway
    (invariant 5, correct), the reconciler folded them, and the gate answered
    PASS "scanned (3/3 shards)" for a commit CodeMender had not read one file of.
    Coverage knew -- 24 in scope, 0 observed -- and nothing consulted it."""
    with tempfile.TemporaryDirectory() as t:
        rc,out,_=_run(t,[],coverage=_cov(t,3,in_scope=24,observed=0))
        assert rc==2 and "RACE" in out, out
        assert "]: PASS" not in out, out
        assert "NOT ONE observed" in out, out

def t_a_scan_that_examined_something_still_passes():
    """The other half: this clause must not turn real clean scans into RACE."""
    with tempfile.TemporaryDirectory() as t:
        rc,out,_=_run(t,[],coverage=_cov(t,3,in_scope=24,observed=9))
        assert rc==0 and "PASS" in out, out

def t_one_shard_that_looked_is_enough():
    """max over shards, not all: two dead shards plus one that read the tree is a
    partial scan, not a non-scan, and shards_completed already speaks to that."""
    with tempfile.TemporaryDirectory() as t:
        cov=_cov(t,2,in_scope=24,observed=0)+_cov(t,1,in_scope=24,observed=4)
        # _cov reuses indices, so re-point the last envelope to its own file
        import shutil; last=os.path.join(t,"coverage-live.json")
        shutil.copy(cov[-1],last); cov=cov[:2]+[last]
        rc,out,_=_run(t,[],coverage=cov)
        assert rc==0 and "PASS" in out, out

def t_empty_scope_is_not_reported_as_unexamined():
    """0 in scope means nothing to look at, which is not the same as not looking."""
    with tempfile.TemporaryDirectory() as t:
        rc,out,_=_run(t,[],coverage=_cov(t,3,in_scope=0,observed=0))
        assert rc==0 and "PASS" in out, out
        assert "NOT ONE observed" not in out, out

def t_exploit_failed_does_not_block():
    with tempfile.TemporaryDirectory() as t:
        fp=f"{ALGO}:bbbb"
        rc,out,_=_run(t,[{"fingerprint":fp,"verdict":"exploit_failed","canonical_path":"a.js"}])
        assert rc==0 and "PASS" in out, out      # unproven is a risk record, not a gate

def t_poc_uri_carried_to_the_gate():
    with tempfile.TemporaryDirectory() as t:
        fp=f"{ALGO}:cccc"
        rc,out,_=_run(t,[{"fingerprint":fp,"verdict":"verified","canonical_path":"a.js",
                          "poc_uri":"gs://b/poc/x.tgz"}],
                      [{"fingerprint":fp,"cwe_class":"ssrf","canonical_path":"a.js"}])
        assert "gs://b/poc/x.tgz" in out, out

def t_monotonic_across_runs():
    """verified must survive a later exploit_failed for the same fingerprint."""
    with tempfile.TemporaryDirectory() as t:
        fp=f"{ALGO}:dddd"
        rc,out,_=_run(t,[{"fingerprint":fp,"verdict":"verified","canonical_path":"a.js"},
                         {"fingerprint":fp,"verdict":"exploit_failed","canonical_path":"a.js"}])
        assert rc==1 and "BLOCK" in out, out

if __name__=="__main__":
    tests=[v for k,v in sorted(globals().items()) if k.startswith("t_")]
    p=0
    for t in tests:
        try: t(); print(f"PASS  {t.__name__}"); p+=1
        except AssertionError as e: print(f"FAIL  {t.__name__}: {e}")
        except Exception as e: print(f"ER*R  {t.__name__}: {e}")
    print(f"\n{p}/{len(tests)} passed"); sys.exit(0 if p==len(tests) else 1)
