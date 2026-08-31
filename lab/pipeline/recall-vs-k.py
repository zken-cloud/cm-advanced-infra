#!/usr/bin/env python3
"""Measure recall vs replication factor K against a ground-truth answer key.

Answers Q9. Find is ~30% non-deterministic, so a single run's recall is noise; the
useful question is how much replication buys and where it stops buying. Averages
over every K-subset of the supplied find dbs.

The ceiling matters more than the curve: bugs no run finds are a SYSTEMATIC gap
that replication cannot close (measured on vulnerable-app: race / weak-random /
business-logic). Report coverage against the achievable ceiling, never against 100%.

  recall-vs-k.py --src-root <clone> --ground-truth gt.json find/*.db

ground-truth JSON: {"<file>::<function|*>": "<id>", ...}
"""
import os, sys, json, argparse, itertools, statistics, importlib.util

_here = os.path.dirname(os.path.abspath(__file__))
_s = importlib.util.spec_from_file_location("vs", os.path.join(_here, "verify-select.py"))
VS = importlib.util.module_from_spec(_s); _s.loader.exec_module(VS)


def load_gt(path):
    raw = json.load(open(path))
    gt = {}
    for k, v in raw.items():
        f, _, fn = k.partition("::")
        gt[(f, None if fn in ("*", "") else fn)] = v
    return gt


def found(dbs, src_root, gt):
    hits = set()
    for meta in VS.consolidate_fanout(list(dbs), src_root).values():
        k = (meta["canonical_path"], meta["enclosing_function"])
        if k in gt: hits.add(gt[k])
        elif (meta["canonical_path"], None) in gt: hits.add(gt[(meta["canonical_path"], None)])
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("find_dbs", nargs="+")
    ap.add_argument("--src-root", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--max-subsets", type=int, default=40, help="cap per K (combinatorics)")
    a = ap.parse_args()

    gt = load_gt(a.ground_truth); total = len(set(gt.values()))
    pods = list(a.find_dbs)
    print(f"{len(pods)} find observations · ground truth {total} bugs\n")
    print(f"{'K':>2}  {'mean recall':>12}  {'min':>7}  {'max':>7}   found")
    curve = {}
    for K in range(1, len(pods) + 1):
        subs = list(itertools.combinations(pods, K))[:a.max_subsets]
        rs = [len(found(c, a.src_root, gt)) for c in subs]
        curve[K] = statistics.mean(rs)
        print(f"{K:>2}  {100*curve[K]/total:>11.1f}%  {100*min(rs)/total:>6.1f}%  {100*max(rs)/total:>6.1f}%   {curve[K]:.1f}/{total}")

    print("\nmarginal gain per added pod:")
    for K in range(2, len(pods) + 1):
        print(f"  K={K-1}->{K}: {100*(curve[K]-curve[K-1])/total:+.1f} pts")

    allh = found(pods, a.src_root, gt)
    missed = sorted(set(gt.values()) - allh)
    print(f"\nceiling (union of all {len(pods)}): {len(allh)}/{total} = {100*len(allh)/total:.0f}%")
    if missed:
        print(f"SYSTEMATIC misses — no run found these, replication cannot help: {missed}")
        print(f"  stochastic (recoverable by K): {100*(curve[len(pods)]-curve[1])/total:.1f} pts")
        print(f"  systematic  (not recoverable): {100*len(missed)/total:.1f} pts")


if __name__ == "__main__":
    main()
