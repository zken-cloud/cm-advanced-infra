#!/usr/bin/env python3
"""Validate that harvested rules fire on vulnerable code and stay silent on fixes.
Requires semgrep on PATH. Run: python3 test_harvest.py"""
import subprocess, tempfile, os, json, importlib.util, sys
here=os.path.dirname(os.path.abspath(__file__))
spec=importlib.util.spec_from_file_location("h",os.path.join(here,"harvest.py"))
H=importlib.util.module_from_spec(spec); spec.loader.exec_module(H)

# (class, vulnerable snippet, fixed snippet, ext)
CASES=[
 ("os-command-injection",
  "function f(req){ require('child_process').exec('ping '+req.q, cb); }",
  "function f(req){ require('child_process').execFile('ping',[req.q], cb); }", "js"),
 ("sql-injection",
  "function f(req){ db.query('SELECT * FROM u WHERE x='+req.q, cb); }",
  "function f(req){ db.query('SELECT * FROM u WHERE x=?',[req.q], cb); }", "js"),
 ("code-injection",
  "function f(req){ eval(req.q); }",
  "function f(req){ const n=Number(req.q); }", "js"),
 ("memory-corruption",
  "void f(char*s){ char b[8]; memcpy(b,s,strlen(s)); }",
  "void f(char*s){ char b[8]; strncpy(b,s,sizeof(b)-1); }", "c"),
]

def semgrep_count(rule_yaml, code, ext):
    with tempfile.TemporaryDirectory() as t:
        rp=os.path.join(t,"r.yaml"); cp=os.path.join(t,"c."+ext)
        open(rp,"w").write(rule_yaml); open(cp,"w").write(code)
        out=subprocess.run(["semgrep","--config",rp,cp,"--json"],capture_output=True,text=True)
        try: return len(json.loads(out.stdout)["results"])
        except: return -1

def make_rule(cls):
    finding={"vuln_id":{"os-command-injection":"CWE-78","sql-injection":"CWE-89",
             "code-injection":"CWE-94","memory-corruption":"CWE-121"}[cls],"status":"VERIFIED"}
    rule,err=H.harvest(finding,"fp2:test")
    assert not err, err
    return H.to_yaml(rule)

if __name__=="__main__":
    passed=0
    for cls,vuln,fixed,ext in CASES:
        y=make_rule(cls)
        v=semgrep_count(y,vuln,ext); f=semgrep_count(y,fixed,ext)
        ok = v>=1 and f==0
        print(f"{'PASS' if ok else 'FAIL'}  {cls:22} vuln={v} fixed={f}")
        passed += ok
    print(f"\n{passed}/{len(CASES)} classes: rule fires on vuln, silent on fix")
    sys.exit(0 if passed==len(CASES) else 1)
