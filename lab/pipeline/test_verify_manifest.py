#!/usr/bin/env python3
"""The verify Job's invariants, as executable checks rather than comments.

Every assertion here is a bug that actually shipped. They are static checks on
k8s/52-verify-job.yaml because that file is where the expensive, hard-to-observe
failures live: a verify pod runs for 20-40 minutes, in a cluster, and most of its
failure modes look exactly like success from the outside.

The reason this file exists at all: D37 was written as a comment saying the exporter
runs on every exit path, and the comment was true while the code was not. A comment
cannot fail CI.
"""
import os, re, sys, subprocess, tempfile
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(os.path.dirname(HERE), "k8s", "52-verify-job.yaml")
SUBS = {"__IMG__": "img", "__BUCKET__": "buck", "__POCBUCKET__": "pb", "__N__": "4",
        "__REPOURL__": "https://example.com/x/y.git", "__REPO__": "y",
        "__SCRUB__": "--doc README.md", "__SCOPE__": "src", "__SHA__": "a" * 40,
        "__PROJECT__": "proj"}

P, F = [], []
def check(name, cond, detail=""):
    (P if cond else F).append(name)
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not cond else ""))

raw = open(MANIFEST, encoding="utf8").read()
for k, v in SUBS.items():
    raw = raw.replace(k, v)
check("no unsubstituted placeholders", not re.findall(r"__[A-Z]+__", raw))

job = [d for d in yaml.safe_load_all(raw) if d and d.get("kind") == "Job"][0]
spec = job["spec"]
script = job["spec"]["template"]["spec"]["containers"][0]["args"][-1]
lines = script.splitlines()
code = [l for l in lines if l.strip() and not l.strip().startswith("#")]
code_text = "\n".join(code)

with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as t:
    t.write(script); path = t.name
check("the rendered script is valid bash",
      subprocess.run(["bash", "-n", path], capture_output=True).returncode == 0)

# ---- D37: one index's failure must not end the batch ----------------------------
check("Indexed completion mode", spec.get("completionMode") == "Indexed")
check("D37: backoffLimitPerIndex is set", spec.get("backoffLimitPerIndex") is not None)
check("D37: maxFailedIndexes is set", spec.get("maxFailedIndexes") is not None)
check("D37: backoffLimit is NOT 0 (a whole-Job budget kills healthy siblings)",
      spec.get("backoffLimit") != 0, f"backoffLimit={spec.get('backoffLimit')}")
# D42: a Job-level deadline terminates every sibling, same failure shape as above.
check("D42: no activeDeadlineSeconds (it would kill siblings)",
      spec.get("activeDeadlineSeconds") is None)
check("D42: ttlSecondsAfterFinished reclaims finished Jobs",
      spec.get("ttlSecondsAfterFinished") is not None)

# ---- invariant 5: the exporter is a trap, and safe when installed ----------------
check("invariant 5: exporter is a trap, not a final line", "trap publish" in code_text)
trap_at = code_text.index("trap publish")
handler = code_text[code_text.index("publish()"):trap_at]
head = code_text[:trap_at]
reads = set(re.findall(r"\$\{?([A-Z_][A-Z0-9_]*)\}?", handler))
def assigned(v):
    return (re.search(rf"(^|\s|;){v}=", head, re.M) or re.search(rf"read .*\b{v}\b", head)
            or re.search(rf"name: {v}\b", raw[:raw.index('trap publish')]))
# TOK/SAFE are assigned inside the handler itself, before use.
missing = [v for v in sorted(reads)
           if v not in ("PATH", "HOME", "TOK", "SAFE") and not assigned(v)]
check("invariant 5: every var the handler reads is set before the trap is installed",
      not missing, f"unset: {missing}")

# ---- D46: the cleanup must not be able to match itself --------------------------
check("D46: no bare pkill (matches the pod's own /bin/bash -c cmdline)",
      not [l for l in code if "pkill" in l], f"{[l.strip() for l in code if 'pkill' in l]}")
check("D46: reap selects on an ANCHORED command line",
      re.search(r'pgrep -f "\^', code_text) is not None)
reap_def = [i for i, l in enumerate(lines) if l.strip() == "reap() {"]
reap_use = [i for i, l in enumerate(lines) if l.strip() == "reap"]
check("D46: reap is defined before every use",
      bool(reap_def) and bool(reap_use) and min(reap_use) > reap_def[0])
# The self-match test, run for real against a shell whose cmdline holds the strings.
pat = re.search(r'pgrep -f "([^"]+)"', code_text).group(1)
probe = subprocess.run(
    ["bash", "-c", f'echo "app.listen server_runner .exploit/ node"; '
                   f'M=$(pgrep -f "{pat}" 2>/dev/null | tr "\\n" " "); '
                   f'case " $M " in *" $$ "*) echo SELFMATCH;; *) echo SAFE;; esac'],
    capture_output=True, text=True)
check("D46: a shell whose cmdline CONTAINS the strings is not matched",
      "SAFE" in probe.stdout, probe.stdout.strip())

# ---- D46: a later verdict must win ----------------------------------------------
check("D46: publish() is keyed on the verdict, not publish-once",
      '[ "$PUBLISHED" = "$VERDICT" ]' in code_text)

# ---- D39 / D45 / invariant 6 ----------------------------------------------------
check("D39: verify cds to find's recorded project_root", "project_root" in code_text)
check("D45: the canary runs in preflight", "canary/exploit.sh" in code_text)
check("D45: canary failure is setup_failed, never a negative",
      re.search(r"canary.*\n(.*\n)*?.*VERDICT=setup_failed", code_text) is not None)
check("D42: cm verify is bounded", "timeout -k" in code_text)
check("D42: exit 124 is classified as timeout", "VERDICT=timeout" in code_text)
# invariant 6: the preflight must fail as setup_failed, never exploit_failed
pre = code_text[:code_text.index("for a in $(seq")]
check("invariant 6: nothing before the verify loop can emit exploit_failed",
      "exploit_failed" not in pre)


# ---------------------------------------------------------------------------
# D47/D50: does the IMAGE actually ship what this pod reaches for?
#
# cm-runner:0.4.1 was built three hours before poc-normalise.py was added to the
# Dockerfile, so a pod cloned, restored and ran for three minutes before dying on a
# missing file. The preflight turned that into a fast setup_failed, which is better
# than a slow one -- but nothing checks the two files agree BEFORE a pod runs, and
# the fix for a whole class of bug should not be "notice it faster at runtime".
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DOCKERFILE = os.path.join(_ROOT, "infra", "runner-image", "Dockerfile")
_df = open(_DOCKERFILE).read().replace("\\\n", " ")

_provided_files, _provided_dirs = set(), set()
for line in _df.splitlines():
    line = line.strip()
    if not line.upper().startswith("COPY "):
        continue
    parts = line[5:].split()
    parts = [q for q in parts if not q.startswith("--")]
    if len(parts) < 2:
        continue
    srcs, dest = parts[:-1], parts[-1]
    if dest.endswith("/") and (len(srcs) > 1 or srcs[0].endswith("/")):
        for sc in srcs:
            if sc.endswith("/"):
                _provided_dirs.add(dest)                 # whole directory copied in
            else:
                _provided_files.add(dest + os.path.basename(sc))
    elif dest.endswith("/"):
        _provided_files.add(dest + os.path.basename(srcs[0]))
    else:
        _provided_files.add(dest)

# Every /opt/cm path EITHER job names. The find job reaches for coverage.py and had
# no drift check at all until 2026-08-25 -- the verify job's check would have passed
# while a find pod died on a missing file.
_find_yaml = os.path.join(_ROOT, "k8s", "51-find-job.yaml")
try:
    import yaml as _y
    _find_text = _y.safe_load(open(_find_yaml))["spec"]["template"]["spec"]["containers"][0]["args"][0]
except Exception as _e:
    _find_text = ""
    check(f"D55: the find manifest is readable ({_e})", False)

_wanted = set(re.findall(r"/opt/cm/[A-Za-z0-9._/-]+", code_text + "\n" + _find_text))
_missing = []
for w in sorted(_wanted):
    if w in _provided_files or any(w.startswith(d) for d in _provided_dirs):
        continue
    _missing.append(w)
check("D50: every /opt/cm path the pod uses is COPY'd by the runner Dockerfile "
      f"(missing: {_missing})", not _missing)
check("D50: the oracle specs directory ships in the image",
      "/opt/cm/oracle-specs/" in _provided_dirs)

# D51: the spec must be consulted for EVERY finding. Gating it on $NEEDS_ORACLE put
# a stable key (fp3) behind an unstable one (CM's CWE class) and lost a finding that
# was already provable.
# Asserted by INTENT, not by adjacency: the spec check must not sit inside a
# NEEDS_ORACLE conditional. Adjacency broke when a "no spec found" warning was added
# between the two lines, which does not change what is being tested.
_spec_if = code_text.index('if [ -f "$ORACLE_SPEC" ]')
# the ORACLE_RAN=0 that guards this block is the LAST one before it -- there is an
# earlier one in the publish setup, and anchoring on that spans the whole script
_oracle_ran = code_text.rindex("ORACLE_RAN=0", 0, _spec_if)
_between = code_text[_oracle_ran:_spec_if]
check("D51: the oracle spec is consulted whenever it exists, not only when the "
      "CWE class routed to an oracle",
      "NEEDS_ORACLE" not in _between)
check("D51: attempt capping still keys on the route, not on the spec",
      'if [ "$NEEDS_ORACLE" = "1" ]; then' in code_text)

# The oracle app root is the CHECKOUT root, never the scan scope. Passing $VDIR
# (=$CDIR/$SCOPE) made the spec's repo-root-relative `boot` resolve to src/src/...,
# so every oracle-routed finding returned setup_failed under the documented SCOPE=src.
check("oracle-run.py gets --project-root \"$CDIR\" (app root), not $VDIR (scan scope)",
      re.search(r'--project-root\s+"\$CDIR"', code_text) is not None)
check("no oracle invocation passes $VDIR as --project-root",
      re.search(r'--project-root\s+"\$VDIR"', code_text) is None)

# INVARIANT 7. A poc_uri is a promise that there is an object at that path to
# replay. It used to be assigned on the line after the upload, unconditionally,
# with the status code going only to a log line nobody reads. A verify pod logged
# `poc published http=403` and wrote the URI anyway; gate-check and ingest-verdicts
# print `poc=MISSING` only for an EMPTY field, so the dangling URI read as a banked
# PoC and the positive control had nothing to replay.
_up = code_text.index("name=poc/$SAFEFP/$SHA.tgz")
_head, _tail = code_text[:_up], code_text[_up:_up + 1400]
check("invariant 7: the PoC upload's status is captured, not just echoed",
      re.search(r"PCODE=\$\(curl", _head[-400:]) is not None)
# Without the precondition, an overwrite denied by objectCreator and a real
# permission failure are the same 403 and cannot be told apart.
check("invariant 7: 'already banked' is distinguishable from a permission failure",
      "ifGenerationMatch=0" in _head[-500:])
check("invariant 7: poc_uri is assigned per status, never unconditionally",
      'case "$PCODE" in' in _tail)
_case = _tail[_tail.index('case "$PCODE" in'):]
_case = _case[:_case.index("esac")]
_catchall = _case[_case.rindex("*)"):]
check("invariant 7: the catch-all arm banks no gs:// URI",
      "gs://" not in _catchall)

os.unlink(path)
print(f"\n{len(P)}/{len(P)+len(F)} passed")
sys.exit(1 if F else 0)
