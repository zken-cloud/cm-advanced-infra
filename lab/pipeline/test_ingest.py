#!/usr/bin/env python3
"""Assertions for verdict ingestion + the gate answer. python3 test_ingest.py"""
import os,sys,json,glob,tempfile,subprocess,importlib.util
HERE=os.path.dirname(os.path.abspath(__file__))
_s=importlib.util.spec_from_file_location("ledger",os.path.join(HERE,"ledger.py"))
L=importlib.util.module_from_spec(_s); _s.loader.exec_module(L)
ALGO=L.dedup.FP_ALGO

def _run(tmp, verdicts, dispatch=None, shards=(3,3), sha="abc123"):
    vd=os.path.join(tmp,"v"); os.makedirs(vd,exist_ok=True)
    for i,v in enumerate(verdicts): json.dump(v,open(os.path.join(vd,f"{i}.json"),"w"))
    dp=os.path.join(tmp,"d.json"); json.dump(dispatch or [],open(dp,"w"))
    led=os.path.join(tmp,"l.db")
    p=subprocess.run([sys.executable,os.path.join(HERE,"ingest-verdicts.py"),
        "--ledger",led,"--repo","r","--sha",sha,"--shards-expected",str(shards[0]),
        "--shards-completed",str(shards[1]),"--min-shards",str(shards[0]),
        "--dispatch",dp,"--verdicts",os.path.join(vd,"*.json"),
        "--ts","2026-01-01T00:00:00Z"],capture_output=True,text=True)
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
