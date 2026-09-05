#!/usr/bin/env python3
"""A verify pod publishes a correction as a SEPARATE object -- it holds
objectCreator and cannot overwrite its first envelope (INCIDENTS 9). Everything
that counts verdicts must therefore count fingerprints, not objects.

Counting objects makes `have < want` false one fingerprint early, so the
re-dispatch that would have covered the unverified finding is skipped and the
fold proceeds without it. Run: python3 test_verdict_supersede.py"""
import importlib.util, os, sys
HERE=os.path.dirname(os.path.abspath(__file__))
spec=importlib.util.spec_from_file_location("r", os.path.join(HERE,"reconcile.py"))
R=importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
fp=R.verdict_object_fp

CASES=[
 ("first publish keeps its name",            "fp3_aaaa1111.json",    "fp3_aaaa1111"),
 ("a correction collapses onto it",          "fp3_aaaa1111.2.json",  "fp3_aaaa1111"),
 ("double-digit seq, not just 2..9",         "fp3_aaaa1111.10.json", "fp3_aaaa1111"),
 ("a non-numeric suffix is part of the fp",  "fp3_aaaa.beef.json",   "fp3_aaaa.beef"),
 ("markers are left alone",                  "_folded",              "_folded"),
]
passed=0
for name, obj, want in CASES:
    got=fp(obj); ok = got==want
    print(f"{'PASS' if ok else 'FAIL'}  {name:38} {obj} -> {got}")
    passed += ok

# The count that gates re-dispatch. 3 fingerprints, one of them corrected = 4
# objects. Counting objects says 4 and skips the re-dispatch for the 4th finding.
objs=["fp3_a.json","fp3_b.json","fp3_b.2.json","fp3_c.json"]
distinct=len({fp(o) for o in objs})
ok = distinct==3
print(f"{'PASS' if ok else 'FAIL'}  {'4 objects, 3 fingerprints':38} counted {distinct}")
passed += ok
# and the naive count is what this guards against
print(f"{'PASS' if len(objs)==4 else 'FAIL'}  {'(object count would say 4)':38} {len(objs)}")
passed += (len(objs)==4)

total=len(CASES)+2
print(f"\n{passed}/{total} passed")
sys.exit(0 if passed==total else 1)
