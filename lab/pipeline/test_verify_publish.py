#!/usr/bin/env python3
"""Drive 52-verify-job.yaml's publish() with a stubbed curl.

INCIDENTS 9: a trap that fires early publishes the pre-loop default, and if the pod
cannot correct that later it reports `terminated` forever and discards the real
answer. The correction was written as a re-publish to the SAME object name — which
this pod cannot do, because it holds objectCreator (invariant 3). So the fix existed,
had a test, and could never land.

A correction now goes to a new object carrying a higher publish_seq. This exercises
the shell that decides that, because the branch only fires when a verdict CHANGES
after a publish, and no healthy verify run ever does.

Run: python3 test_verify_publish.py
"""
import os, re, subprocess, sys, tempfile, yaml

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(os.path.dirname(HERE), "k8s", "52-verify-job.yaml")


def extract(fn_name):
    d = yaml.safe_load(open(MANIFEST))
    c = d["spec"]["template"]["spec"]["containers"][0]
    script = [x for k in ("command", "args") if k in c for x in c[k] if f"{fn_name}()" in x][0]
    lines = script.split("\n")
    start = next(i for i, l in enumerate(lines) if l.strip().startswith(f"{fn_name}() {{"))
    ind = len(lines[start]) - len(lines[start].lstrip())
    end = next(i for i in range(start + 1, len(lines))
               if lines[i].strip() == "}" and (len(lines[i]) - len(lines[i].lstrip())) == ind)
    return "\n".join(l[ind:] for l in lines[start:end + 1]).replace("__SHA__", "SHA")


HARNESS = r'''
set -u
SHA=deadbeef; I=0; FP="fp3:abc123"; CPATH="src/a.js"; FID="f1"; TRIED=1; ATT=2
EXPLOIT=0; RESTORED=1; POC_URI=""; SHARD="0"; CWE_CLASS="ssrf"
HARNESS="functional-exploit"; NEEDS_ORACLE=0; BUCKET=B; PUBLISHED=""; SEQ=0
VERDICT=terminated
curl() {
  local url=""; for a in "$@"; do case "$a" in http*) url="$a";; esac; done
  case "$url" in *metadata.google.internal*) printf '{"access_token":"tok"}'; return 0;; esac
  local obj="${url##*name=}"
  case " ${TAKEN:-} " in *" $obj "*) printf '412'; return 0;; esac
  echo "$obj" >> "$WRITTEN"
  printf '200'
}
'''


def run(body):
    with tempfile.TemporaryDirectory() as t:
        written = os.path.join(t, "w")
        script = (f'WRITTEN={written}\n' + HARNESS + "\n" + extract("publish")
                  + "\n" + body)
        p = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        objs = open(written).read().split() if os.path.exists(written) else []
        return p.stdout + p.stderr, objs


T = []
def check(name, got, want):
    ok = got == want
    T.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name:52}" + ("" if ok else f" {got!r} != {want!r}"))


out, objs = run('publish\npublish\nVERDICT=verified; EXPLOIT=1; publish\npublish\n')
check("first publish keeps the historic object name", objs[0], "verify/SHA/fp3_abc123.json")
check("a changed verdict goes to a NEW object",       objs[1], "verify/SHA/fp3_abc123.2.json")
check("exactly two objects for four calls",           len(objs), 2)
check("the correction is not an overwrite",           objs[0] != objs[1], True)
check("seq is stamped in the log",                    "seq=2" in out, True)
check("the real verdict is the later one",            out.rindex("verified") > out.rindex("terminated"), True)

# publish_seq must be IN the envelope: the ingester selects on the field, not the name.
out2, _ = run('publish\nVERDICT=verified; publish\ncat /tmp/result.json\n')
check("envelope carries publish_seq",                 '"publish_seq":2' in out2, True)

# A sibling attempt of the same index owning slot 1 is expected, not an error.
out3, objs3 = run('TAKEN="verify/SHA/fp3_abc123.json" publish\n')
check("a taken slot reports 412, not failure",        "already exists" in out3, True)
check("and writes nothing",                           objs3, [])
check("412 is not reported as a publish failure",     "PUBLISH FAILED" in out3, False)

print(f"\n{sum(T)}/{len(T)} passed")
sys.exit(0 if all(T) else 1)
