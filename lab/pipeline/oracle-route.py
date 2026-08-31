#!/usr/bin/env python3
"""Route a finding to the harness that can actually prove it.

Some vulnerability classes cannot be proven by a scripted functional exploit, and
asking one to try is not a neutral failure -- it produces `exploit_failed`, which
the ledger folds as a NEGATIVE and caches. Measured on this target: a ReDoS finding
took 3 of its 5 attempts before a functional exploit happened to work, and V1
(closure GC leak) and V10 (non-constant-time compare) admit no functional exploit
at all. They are also exactly the findings CM is uniquely good at surfacing, so
losing them to the wrong harness is expensive twice over.

`gate.py` has known the routing since it was written and nothing consumed it. This
is the consumer: the verify pod asks what harness a finding needs, and adjusts.

Two things change for an oracle-class finding:

  * ATTEMPTS ARE CAPPED AT 1. Retrying a harness that structurally cannot succeed
    is not resilience, it is paying five times for the same wrong answer.
  * exploit_failed BECOMES unproven. "The wrong instrument found nothing" is not
    evidence of absence, and recording it as a negative poisons the cache for a
    finding nobody has actually tested (invariant 6, one level up: the harness did
    not fail to run, it was never capable).

  oracle-route.py --cwes CWE-400,CWE-1333        -> {"cwe_class": "redos", ...}
"""
import os, sys, json, argparse, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def route(cwes):
    """(cwe_class, harness, needs_oracle) for a finding's CWE list.

    A finding can carry several CWEs. If ANY of them is an oracle class, the finding
    routes to the oracle: the classes are disjoint in practice, and being wrong
    towards `unproven` costs a re-verify, while being wrong towards
    `exploit_failed` caches a negative on a live bug.
    """
    dedup = _load("dedup", "consolidate-dedup.py")
    gate = _load("gate", "gate.py")
    classes = [dedup.cwe_class(c.strip()) for c in cwes if c.strip()]
    for c in classes:
        if c in gate.NONFUNCTIONAL_ORACLE:
            harness, _pkey, note = gate.NONFUNCTIONAL_ORACLE[c]
            # A harness of None means "an oracle is required and the CWE cannot say
            # which" (CWE-400). Still needs_oracle: the cap and the no-false-negative
            # rule follow from "a functional exploit cannot prove this", which IS
            # known. Only the target's oracle spec can supply the instrument.
            return {"cwe_class": c, "harness": harness or "oracle-required-unspecified",
                    "needs_oracle": True, "note": note}
    return {"cwe_class": classes[0] if classes else "unknown",
            "harness": "functional-exploit", "needs_oracle": False, "note": ""}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cwes", required=True, help="comma-separated, e.g. CWE-400,CWE-1333")
    ap.add_argument("--field", help="print just this field (shell-friendly)")
    a = ap.parse_args()
    r = route(a.cwes.split(","))
    print(r[a.field] if a.field else json.dumps(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
