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
 ("prototype-pollution",
  "function m(d,s){ for (const k in s) { d[k] = s[k]; } return d; }",
  "function m(d,s){ for (const k in s) { if (k === '__proto__') continue; d[k] = s[k]; } return d; }", "js"),
 ("path-traversal",
  "function f(n){ const c = n.replace(/\\.\\.\\//g, ''); return path.join(base, c); }",
  "function f(n){ const r = path.resolve(base, n); if (!r.startsWith(base)) throw 0; return r; }", "js"),
 ("redos",
  "function f(req){ const re = new RegExp('^(a+)+' + req.body.s); return re.test(req.body.v); }",
  "const RE = /^[a-z]+$/;\nfunction f(req){ return RE.test(req.body.v); }", "js"),
 ("weak-random",
  "function makeResetToken(){ return Math.random().toString(36); }",
  "function makeResetToken(){ return require('crypto').randomBytes(24).toString('hex'); }", "js"),
 ("mass-assignment",
  "function u(o,p){ Object.keys(p).forEach((k) => { o[k] = p[k]; }); return o; }",
  "function u(o,p){ for (const k of ['name','email']) { if (k in p) o[k] = p[k]; } return o; }", "js"),
 ("cwe-943",
  "function f(q,d){ if (q.x['$ne'] !== undefined && d.x !== q.x['$ne']) return true; return false; }",
  "function f(q,d){ const v = q.x; if (v !== null && typeof v === 'object') return false; return d.x === v; }", "js"),
 ("cwe-908",
  "function f(n){ return Buffer.allocUnsafe(n); }",
  "function f(n){ return Buffer.alloc(n); }", "js"),
 ("memory-leak-gc",
  "const c = {};\nfunction f(b,id){ c[id] = b.subarray(0,16); return c[id]; }",
  "const c = {};\nfunction f(b,id){ c[id] = Buffer.from(b.subarray(0,16)); return c[id]; }", "js"),
 ("ssrf",
  "function f(req){ return axios.get(req.query.url); }",
  "function f(req){ const u = new URL(req.query.url); if (u.host !== 'a.example') throw 0; return axios.get(u.href); }", "js"),
]

# Classes that CANNOT have a rule. harvest must say why, not "extend TEMPLATES" --
# sending someone to write a rule that provably cannot work is worse than a gap.
INFEASIBLE_CASES = [("timing-attack","CWE-208"), ("race-toctou","CWE-367"),
                    ("business-logic","CWE-799")]

def semgrep_count(rule_yaml, code, ext):
    with tempfile.TemporaryDirectory() as t:
        rp=os.path.join(t,"r.yaml"); cp=os.path.join(t,"c."+ext)
        open(rp,"w").write(rule_yaml); open(cp,"w").write(code)
        out=subprocess.run(["semgrep","--config",rp,cp,"--json"],capture_output=True,text=True)
        try: return len(json.loads(out.stdout)["results"])
        except: return -1

def make_rule(cls):
    finding={"vuln_id":{"os-command-injection":"CWE-78","sql-injection":"CWE-89",
             "code-injection":"CWE-94","memory-corruption":"CWE-121",
             "prototype-pollution":"CWE-1321","path-traversal":"CWE-22","redos":"CWE-1333",
             "weak-random":"CWE-330","mass-assignment":"CWE-915","cwe-943":"CWE-943",
             "cwe-908":"CWE-908","memory-leak-gc":"CWE-401","ssrf":"CWE-918"}[cls],
             "status":"VERIFIED"}
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

    extra=0
    for cls,cwe in INFEASIBLE_CASES:
        rule,err=H.harvest({"vuln_id":cwe,"status":"VERIFIED"},"fp3:test")
        ok = rule is None and err and "cannot be expressed as a static rule" in err \
             and "extend TEMPLATES" not in err
        print(f"{'PASS' if ok else 'FAIL'}  {cls:22} refuses with a reason, not a TODO")
        extra += ok
    # An unknown class must still say "extend TEMPLATES" AND list what exists, so the
    # message is actionable rather than a dead end.
    rule,err=H.harvest({"vuln_id":"CWE-99999","status":"VERIFIED"},"fp3:test")
    ok = rule is None and "extend TEMPLATES" in err and "Known classes:" in err
    print(f"{'PASS' if ok else 'FAIL'}  {'unknown-class':22} names the classes that do exist")
    extra += ok
    print(f"{extra}/{len(INFEASIBLE_CASES)+1} refusal messages correct")
    sys.exit(0 if passed==len(CASES) and extra==len(INFEASIBLE_CASES)+1 else 1)
