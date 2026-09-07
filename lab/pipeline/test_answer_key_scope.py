#!/usr/bin/env python3
"""The answer key must never be readable by the agent. python3 test_answer_key_scope.py

README 0f copies `pipeline/` into the participant's lab repo, and that repo IS the
tree the find pod clones. Any `pipeline/harvested-rules/*.yaml`
maps a runnable pattern to each finding a participant has verified, so it is an
answer key sitting inside the scanned tree by construction -- whether it was
shipped or harvested in Step 7.

Two controls, because one is how a recall number gets silently inflated:

  * SCOPE keeps the agent in src/ -- never "." , which would put pipeline/ and
    harvest-fp-cases/ in front of it;
  * the scrub globs delete BOTH copies of the ruleset (.cm/rules/, seeded by
    hooks/install.sh, and pipeline/harvested-rules/, the source).

The failure this guards is self-flattering: recall goes UP, so nothing looks wrong.
"""
import fnmatch
import os
import re
import sys
import tempfile
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
P, F = [], []


def check(msg, ok):
    (P if ok else F).append(msg)
    print(f"{'PASS' if ok else 'FAIL'}  {msg}")


FANOUT = open(os.path.join(ROOT, ".github", "workflows", "cm-fanout.yml")).read()
TWOPHASE = open(os.path.join(ROOT, "k8s", "run-twophase.sh")).read()
RECONCILE = open(os.path.join(HERE, "reconcile.py")).read()

ANSWER_KEYS = ["pipeline/harvested-rules/harvested.yaml",
               ".cm/rules/harvested.yaml"]


def globs_of(text):
    # `}` is excluded so the last glob in a shell ${VAR:-...} default does not
    # capture the closing brace -- the value is correct, the naive regex was not.
    # `'` likewise, since the workflow default now lives inside a quoted GitHub
    # expression: without it the LAST glob captured a trailing apostrophe and
    # silently stopped matching, while every earlier one passed.
    return re.findall(r"--doc ([^\s\"'#}\\]+)", text)


def env_default(text, key):
    """The fallback in `KEY: ${{ vars.SOMETHING || 'value' }}`.

    SCOPE and SCRUB_DOCS became repository variables so this pipeline can be aimed
    at another repo (Part D). The value that ships is the DEFAULT, so that is what
    these controls have to read -- asserting on the sed line stopped proving
    anything the moment the sed line became a variable reference.
    """
    m = re.search(key + r":\s*\$\{\{[^}]*\|\|\s*'([^']*)'\s*\}\}", text)
    return m.group(1) if m else None


# --- control 1: scope is never the whole tree -------------------------------
check("run-twophase defaults SCOPE to src, not '.' ('.' shows the agent pipeline/)",
      re.search(r'SCOPE="\$\{SCOPE:-src\}"', TWOPHASE) is not None)
check("run-twophase no longer defaults SCOPE to '.'",
      re.search(r'SCOPE="\$\{SCOPE:-\.\}"', TWOPHASE) is None)
check("CI defaults SCOPE to src, not '.'",
      env_default(FANOUT, "SCOPE") == "src")
check("CI dispatches the find Job with the SCOPE it resolved",
      "s#__SCOPE__#$SCOPE#g" in FANOUT)
check("the reconciler falls back to src, never '.'",
      're.get' not in RECONCILE and 'run.get("scope", "src")' in RECONCILE)

# --- control 2: both copies of the ruleset are scrubbed ----------------------
for label, text in (("CI find dispatch", env_default(FANOUT, "SCRUB_DOCS") or ""),
                    ("run-twophase default", TWOPHASE),
                    ("reconciler fallback", RECONCILE)):
    g = globs_of(text)
    for key in ANSWER_KEYS:
        hit = any(fnmatch.fnmatch(key, pat) or fnmatch.fnmatch(os.path.basename(key), pat)
                  for pat in g)
        check(f"{label}: scrub globs delete {key}", hit)

# --- the RUN.json the reconciler reads must carry the same list --------------
# It used to carry its own copy of the literal, which could drift from the sed line
# above it. Both now read one variable, so the control is that they SHARE it: two
# copies of one truth is D47, and a verify pod inheriting a different scrub list
# than the find pod used is exactly the shape that hides.
run_json = re.search(r'"scrub":"([^"]+)"', FANOUT)
check("RUN.json carries a scrub list (verify pods inherit it)", run_json is not None)
check("RUN.json and the find dispatch read the SAME scrub list",
      run_json is not None and run_json.group(1) == "$SCRUB_DOCS"
      and "s#__SCRUB__#$SCRUB_DOCS#g" in FANOUT)
check("RUN.json carries the resolved scope, not a second literal",
      re.search(r'"scope":"\$SCOPE"', FANOUT) is not None)

# --- end to end: the real scrubber, on a tree shaped like a lab repo ---------
with tempfile.TemporaryDirectory() as t:
    # Synthetic, deliberately: this repo ships no target-specific ruleset, and the
    # control being tested is the SCRUB GLOB, not the content it deletes. Reading a
    # real answer key here would make the test unrunnable wherever the key is absent
    # -- which is everywhere it should be.
    fixture = "rules:\n- id: cm-harvested-example-0000\n  pattern: $X\n"
    for rel in ANSWER_KEYS:
        d = os.path.join(t, os.path.dirname(rel))
        os.makedirs(d, exist_ok=True)
        open(os.path.join(t, rel), "w").write(fixture)
    os.makedirs(os.path.join(t, "src"), exist_ok=True)
    open(os.path.join(t, "src", "app.js"), "w").write("const a = 1;\n")
    argv = ["python3", os.path.join(HERE, "scrub-answer-key.py"), t] + \
        [x for pat in globs_of(env_default(FANOUT, "SCRUB_DOCS") or "")
         for x in ("--doc", pat)]
    subprocess.run(argv, capture_output=True, text=True)
    for rel in ANSWER_KEYS:
        check(f"end-to-end: {rel} is gone after the scrub",
              not os.path.exists(os.path.join(t, rel)))
    check("end-to-end: application source survives the scrub",
          os.path.exists(os.path.join(t, "src", "app.js")))

print(f"\n{len(P)}/{len(P) + len(F)} passed")
sys.exit(1 if F else 0)
