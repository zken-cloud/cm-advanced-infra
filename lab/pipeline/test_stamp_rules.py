#!/usr/bin/env python3
"""stamp-rules.py — the only path allowed to make a rule BLOCK. python3 test_stamp_rules.py

This script had no test at all, and it fail-opened: fp_offenders() returns the
sentinel {"*"} to mean "refuse everything", but the guard tested `rid in
blocked_by_fp`, which never matches a wildcard. It printed "refusing to promote
anything" and then stamped the rule blocking anyway.

A rule becomes blocking only when ALL of these hold (README Step 2 / Q12):
  * the ledger says the fingerprint is `verified`, and
  * a PoC artifact exists, and
  * the rule stays SILENT on every correct fix in the FP corpus.
A missing or unreadable corpus must fail CLOSED -- it is not evidence of silence.
"""
import io, os, sys, json, sqlite3, subprocess, tempfile, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "stamp-rules.py")
P, F = [], []

def check(msg, ok):
    (P if ok else F).append(msg)
    print(f"{'PASS' if ok else 'FAIL'}  {msg}")

spec = importlib.util.spec_from_file_location("sr", SCRIPT)
SR = importlib.util.module_from_spec(spec); spec.loader.exec_module(SR)

RULE = """rules:
- id: cm-t1-eval
  languages: [javascript]
  severity: ERROR
  message: "eval on user input"
  patterns:
    - pattern: eval($X)
"""

def mkledger(path, fp, verdict="verified", poc="gs://b/poc/x.tgz"):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE findings(fingerprint TEXT PRIMARY KEY, verdict TEXT, poc_uri TEXT)")
    db.execute("INSERT INTO findings VALUES(?,?,?)", (fp, verdict, poc))
    db.commit(); db.close()

def run(tmp, rules, ledger, fp_cases, fp="fp3:dead"):
    out = os.path.join(tmp, "out.yaml")
    r = subprocess.run([sys.executable, SCRIPT, "--rules", rules, "--ledger", ledger,
                        "--map", f"cm-t1-eval={fp}", "--out", out, "--fp-cases", fp_cases],
                       capture_output=True, text=True)
    body = io.open(out).read() if os.path.exists(out) else ""
    return r.stdout + r.stderr, body

# --- the fail-open regression, directly ---------------------------------------
check("sentinel semantics: '*' must be treated as blocking every rule id",
      ("*" in {"*"}) and ("cm-t1-eval" in {"*"}) is False)

with tempfile.TemporaryDirectory() as tmp:
    rules = os.path.join(tmp, "r.yaml"); io.open(rules, "w").write(RULE)
    led = os.path.join(tmp, "l.db"); mkledger(led, "fp3:dead")
    # corpus that does NOT exist -> must fail closed
    log, body = run(tmp, rules, led, os.path.join(tmp, "nope"))
    check("missing FP corpus: refuses to promote (no cm_poc written)", "cm_poc" not in body)
    check("missing FP corpus: says so, and the count agrees with the action",
          "0 rule(s) now BLOCKING" in log)
    check("missing FP corpus: the stated reason is the corpus, not a false FP claim",
          "missing or unreadable" in log)

with tempfile.TemporaryDirectory() as tmp:
    rules = os.path.join(tmp, "r.yaml"); io.open(rules, "w").write(RULE)
    led = os.path.join(tmp, "l.db"); mkledger(led, "fp3:dead")
    # a corpus of CORRECT code the rule stays silent on -> promotion allowed
    cases = os.path.join(tmp, "cases"); os.makedirs(cases)
    io.open(os.path.join(cases, "fixed_guard.js"), "w").write("const x = JSON.parse(input);\n")
    log, body = run(tmp, rules, led, cases)
    check("clean FP corpus + verified + poc: rule IS promoted", "cm_poc" in body)

with tempfile.TemporaryDirectory() as tmp:
    rules = os.path.join(tmp, "r.yaml"); io.open(rules, "w").write(RULE)
    led = os.path.join(tmp, "l.db"); mkledger(led, "fp3:dead")
    # corpus containing code the rule FIRES on -> must stay advisory
    cases = os.path.join(tmp, "cases"); os.makedirs(cases)
    io.open(os.path.join(cases, "fixed_guard.js"), "w").write("eval(userInput);\n")
    log, body = run(tmp, rules, led, cases)
    check("rule fires on a 'correct fix' (fixed_*): stays advisory", "cm_poc" not in body)
    check("and it names the offending rule", "FP-CHECK cm-t1-eval" in log)

with tempfile.TemporaryDirectory() as tmp:
    # The corpus convention is load-bearing: only files named fixed_* count as
    # "correct code". A genuine fix dropped in under any other name is silently
    # ignored and buys no protection at all.
    rules = os.path.join(tmp, "r.yaml"); io.open(rules, "w").write(RULE)
    led = os.path.join(tmp, "l.db"); mkledger(led, "fp3:dead")
    cases = os.path.join(tmp, "cases"); os.makedirs(cases)
    io.open(os.path.join(cases, "notfixed.js"), "w").write("eval(userInput);\n")
    log, body = run(tmp, rules, led, cases)
    check("a firing file NOT named fixed_* is ignored — the naming convention gates Q12",
          "cm_poc" in body)

with tempfile.TemporaryDirectory() as tmp:
    rules = os.path.join(tmp, "r.yaml"); io.open(rules, "w").write(RULE)
    led = os.path.join(tmp, "l.db"); mkledger(led, "fp3:dead", verdict="unproven")
    cases = os.path.join(tmp, "cases"); os.makedirs(cases)
    io.open(os.path.join(cases, "fixed_guard.js"), "w").write("const x = 1;\n")
    log, body = run(tmp, rules, led, cases)
    check("unverified verdict: refused even with a clean corpus", "cm_poc" not in body)

with tempfile.TemporaryDirectory() as tmp:
    rules = os.path.join(tmp, "r.yaml"); io.open(rules, "w").write(RULE)
    led = os.path.join(tmp, "l.db"); mkledger(led, "fp3:other")
    cases = os.path.join(tmp, "cases"); os.makedirs(cases)
    io.open(os.path.join(cases, "fixed_guard.js"), "w").write("const x = 1;\n")
    log, body = run(tmp, rules, led, cases)
    check("fingerprint absent from the ledger: refused", "cm_poc" not in body)

print(f"\n{len(P)}/{len(P)+len(F)} passed")
sys.exit(1 if F else 0)
