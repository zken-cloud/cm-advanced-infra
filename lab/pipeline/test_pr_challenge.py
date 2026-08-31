#!/usr/bin/env python3
"""pr-challenge.py — the properties that matter are what it REFUSES to do.

It is advisory by construction, so the tests are mostly about the ways an advisory
tool quietly stops being advisory, or starts lying.
"""
import os, sys, io, sqlite3, tempfile, importlib.util, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("prc", os.path.join(HERE, "pr-challenge.py"))
prc = importlib.util.module_from_spec(spec); spec.loader.exec_module(prc)

P, F = [], []
def check(name, cond, detail=""):
    (P if cond else F).append(name)
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))

# ---- the ledger lookup ----------------------------------------------------------
d = tempfile.mkdtemp(); led = os.path.join(d, "l.db")
db = sqlite3.connect(led)
db.execute("""CREATE TABLE findings (fingerprint TEXT, cwe_class TEXT, canonical_path TEXT,
              verdict TEXT, severity TEXT, poc_uri TEXT, attempts INT)""")
db.execute("INSERT INTO findings VALUES ('fp3:aaa','redos','x.js','verified','HIGH','gs://p/a.tgz',2)")
db.commit()

ctx = prc.finding_context(led, "fp3:aaa")
check("a known fingerprint yields its ledger row", "redos" in ctx and "verified" in ctx)
check("  and states that the bug is REAL, so the review judges the fix not the finding",
      "exploit was synthesised and RAN" in ctx)

ctx = prc.finding_context(led, "fp3:nope")
check("an unknown fingerprint says so rather than inventing context",
      "not in the ledger" in ctx)

ctx = prc.finding_context(None, None)
check("no ledger degrades to judging the diff, never to a fabricated finding",
      "on its own terms" in ctx)

ctx = prc.finding_context("/nonexistent/ledger.db", "fp3:aaa")
check("an unreadable ledger degrades the same way", "on its own terms" in ctx)

# ---- it must not silently shrink a security diff --------------------------------
src = io.open(os.path.join(HERE, "pr-challenge.py"), encoding="utf8").read()
check("a too-large diff is REFUSED, not truncated",
      "sys.exit(f\"diff is" in src and "truncat" in src.lower())
check("  no slicing of the diff anywhere in the file",
      "diff[:" not in src and "diff[0:" not in src)

# ---- advisory by construction ---------------------------------------------------
wf = os.path.join(os.path.dirname(HERE), ".github", "workflows", "cm-pr-challenge.yml")
w = io.open(wf, encoding="utf8").read()
import yaml
y = yaml.safe_load(w)
triggers = list(y[True] if True in y else y.get("on", {}))
check("opt-in only: workflow_dispatch, never on: pull_request",
      triggers == ["workflow_dispatch"], f"triggers={triggers}")
check("cannot write a status check (no checks: write)",
      "checks" not in (y.get("permissions") or {}))
check("cannot approve or merge (no gh pr review/merge anywhere)",
      "pr review" not in src and "pr merge" not in src and "pr merge" not in w)
check("uses the gate's READ-ONLY identity for the ledger",
      "cm-lab-gate@" in w)
check("the posted comment states it is not a gate",
      "advisory, not a gate" in src)

# ---- refusals are not reviews ---------------------------------------------------
check("a model refusal aborts instead of posting an empty review",
      'resp.stop_reason == "refusal"' in src and "Not posting" in src)
check("stop_reason is checked BEFORE content is read",
      src.index('stop_reason == "refusal"') < src.index("b.text for b in resp.content"))

# ---- the model contract ---------------------------------------------------------
check("asks the R5 question explicitly (defect vs exploit)",
      "only break the" in prc.SYSTEM and "EXPLOIT" in prc.SYSTEM)
check("model is pinned to a current id", prc.MODEL == "claude-opus-5")
check("refusal fallback is enabled (security review trips cyber classifiers)",
      'fallbacks="default"' in src and "server-side-fallback-2026-07-01" in src)

print(f"\n{len(P)}/{len(P)+len(F)} passed")
sys.exit(1 if F else 0)
