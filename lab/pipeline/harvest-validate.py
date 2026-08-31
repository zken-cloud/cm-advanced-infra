"""Validate harvested rules two ways: snippet pairs, then the real repo.

A rule that fires on an idealised before/after pair can still match nothing in the
codebase it was harvested from (measured: V4/V5/V11 all did exactly that). Both
checks are required before a harvested rule is worth shipping.

  harvest-validate.py --cases <answer-key-store>/<target>-rule-cases.py [--tree path/to/src]
"""
import os,subprocess,tempfile,json,sys,argparse,importlib.util

_ap=argparse.ArgumentParser()
_ap.add_argument("--cases",required=True,help="python file defining CASES")
_ap.add_argument("--tree",help="also run the full ruleset against this source tree")
_ap.add_argument("--fp-cases",help="dir of CORRECT code the ruleset must stay silent on. "
                 "Required before a rule may block: a guard factored into a helper makes "
                 "keyword-proxy rules (pattern-not-regex on __proto__ etc.) fire on a "
                 "correctly fixed function. Measured, that is not an edge case -- it is how "
                 "well-factored code guards.")
_A=_ap.parse_args()
_s=importlib.util.spec_from_file_location("cases",_A.cases)
_m=importlib.util.module_from_spec(_s); _s.loader.exec_module(_m)
CASES=_m.CASES
def sg(rule, code):
    with tempfile.TemporaryDirectory() as t:
        r=os.path.join(t,"r.yaml"); open(r,"w").write("rules:\n"+rule)
        f=os.path.join(t,"t.js");   open(f,"w").write(code)
        p=subprocess.run(["semgrep","--quiet","--json","--no-git-ignore","--metrics=off",
                          "--config",r,f],capture_output=True,text=True,timeout=180)
        if p.returncode not in (0,1):
            return None, (p.stderr or "")[-200:]
        try: return len(json.loads(p.stdout).get("results",[])), None
        except Exception as e: return None, str(e)
sound=fires=infeasible=broken=0
print(f"{'id':5}{'fires on vuln':>15}{'silent on fix':>15}   verdict")
rows=[]
for c in CASES:
    if c[1] is None:
        infeasible+=1; rows.append((c[0],"-","-","NO RULE POSSIBLE",c[2])); continue
    _id,rule,vuln,fixed=c
    nv,ev=sg(rule,vuln); nf,ef=sg(rule,fixed)
    if nv is None or nf is None:
        broken+=1; rows.append((_id,"ERR","ERR","RULE ERROR",(ev or ef))); continue
    f_ok=nv>0; s_ok=nf==0
    if f_ok: fires+=1
    if f_ok and s_ok: sound+=1; v="SOUND"
    elif f_ok and not s_ok: v="FALSE POSITIVE on fix"
    else: v="MISSES the vuln"
    rows.append((_id,f"{nv} hit" if f_ok else "no",f"{nf} hit" if not s_ok else "yes",v,""))
for r in rows:
    print(f"{r[0]:5}{r[1]:>15}{r[2]:>15}   {r[3]}")
    if r[4]: print(f"       ^ {r[4][:110]}")
tot=len(CASES)
print(f"\nSOUND rules: {sound}/{tot} = {100*sound//tot}%  |  no rule possible: {infeasible}/{tot}  |  rule errors: {broken}")

if _A.tree:
    open("/tmp/_all.yaml","w").write("rules:\n"+"".join(c[1] for c in CASES if c[1]))
    p=subprocess.run(["semgrep","--quiet","--json","--no-git-ignore","--metrics=off",
                      "--config","/tmp/_all.yaml",_A.tree],capture_output=True,text=True,timeout=600)
    res=json.loads(p.stdout).get("results",[])
    fired={r["check_id"].split(".")[-1] for r in res}
    total=sum(1 for c in CASES if c[1])
    print(f"\nreal tree {_A.tree}: {len(res)} findings, {len(fired)}/{total} rules fire")
    if len(fired)<total:
        print("  RULES THAT MATCH NOTHING IN THE REAL REPO (harvest failure):")
        allids=[c[1].split("id:")[1].split("\n")[0].strip() for c in CASES if c[1]]
        for i in allids:
            if i not in fired: print(f"    {i}")
