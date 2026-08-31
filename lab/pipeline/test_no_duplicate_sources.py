#!/usr/bin/env python3
"""Nothing may shadow a script in pipeline/.

`infra/runner-image/poc-normalise.py` was a copy of `pipeline/poc-normalise.py`
taken at 05:13 on 2026-08-24. The admissibility stamping added to the pipeline copy
at 05:16 therefore never reached any pod: the feature existed, had tests, passed
them, and had never once run in production. Nothing failed -- nothing could have,
because the tests exercised the file that was not shipped.

Same shape as the reconciler baking its own copy of k8s/ (D38) and the CWE->class
map diverging from the oracle routing table (D47): two copies of one truth, and the
copy under test is not the copy that runs.

Scoped deliberately to pipeline/ rather than "no repeated filename anywhere".
`infra/runner-image/build.sh` and `infra/reconciler-image/build.sh` share a name and
nothing else; flagging those would be noise, and a guard that cries wolf gets
deleted -- which is how you end up with no guard at all.
"""
import os, sys, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIPELINE = os.path.join(ROOT, "pipeline")
SKIP = {".git", "node_modules", "__pycache__", "targets", "build", "pipeline"}

def digest(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()[:12]

owned = {f: os.path.join(PIPELINE, f)
         for f in os.listdir(PIPELINE) if f.endswith((".py", ".sh"))}

shadows = []
for dirpath, dirnames, files in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP]
    if os.path.abspath(dirpath).startswith(PIPELINE):
        continue
    for f in files:
        if f in owned:
            here, there = os.path.join(dirpath, f), owned[f]
            shadows.append((os.path.relpath(here, ROOT), digest(here) == digest(there)))

P, F = [], []
def check(name, cond, detail=""):
    (P if cond else F).append(name)
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not cond else ""))

for rel, identical in sorted(shadows):
    check(f"{rel} does not shadow pipeline/", False,
          "IDENTICAL today, and nothing keeps it that way" if identical
          else "ALREADY DIVERGED — the shipped copy is not the tested copy")

if not shadows:
    check(f"no file shadows pipeline/ ({len(owned)} scripts checked)", True)

print(f"\n{len(P)}/{len(P)+len(F)} passed")
sys.exit(1 if F else 0)
