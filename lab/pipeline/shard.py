#!/usr/bin/env python3
"""Phase-1 find sharder. Decides which files each find pod scans.

Two modes, per the measured recall/dedup tradeoff (README, Reference):

  discovery : DISJOINT. Partition the file set so each file is scanned by exactly
              one pod. No two pods scan the same file -> zero duplicate find cost.
              Recall gaps are recovered over time by re-scans (weekly campaign).

  delta     : REPLICATED x K. Each changed file is scanned by K pods. A single
              `cm find` pass has 6-10/identical-input recall variance (measured),
              so K independent passes + union recover the ~10-40% a single pass
              misses. Dedup collapses the overlap to zero downstream verify cost.

Cost is bounded two ways (item #2):
  - pods = min(requested, max_pods)         # hard ceiling
  - delta replication only applies to the (small) changed set, never the whole repo
"""
import sys, json, argparse, hashlib

def _stable_bucket(path, n):
    # deterministic, balanced assignment without Math.random (which is unavailable
    # in the workflow runtime and non-reproducible anyway).
    h=int(hashlib.sha256(path.encode()).hexdigest()[:8],16)
    return h % n

def shard_disjoint(files, pods):
    pods=max(1,min(pods,len(files) or 1))
    buckets=[[] for _ in range(pods)]
    for f in sorted(files):
        buckets[_stable_bucket(f,pods)].append(f)
    return [b for b in buckets if b]

def shard_replicated(files, K, max_pods):
    """Each file to K distinct pods. pods = min(len(files), max_pods); each file
    is placed on K pods chosen by rotating hash so load stays balanced."""
    files=sorted(files)
    pods=max(1,min(max_pods, max(K, len(files))))
    K=min(K,pods)
    buckets=[[] for _ in range(pods)]
    for f in files:
        base=_stable_bucket(f,pods)
        for j in range(K):
            buckets[(base+j)%pods].append(f)
    return [b for b in buckets if b]

def plan(files, mode, K, max_pods, requested_pods):
    if mode=="discovery":
        return shard_disjoint(files, min(requested_pods,max_pods))
    return shard_replicated(files, K, max_pods)

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--mode",choices=["discovery","delta"],required=True)
    ap.add_argument("--k",type=int,default=3,help="replication factor (delta mode)")
    ap.add_argument("--max-pods",type=int,default=100,help="cost ceiling (item #2)")
    ap.add_argument("--pods",type=int,default=20,help="requested pods (discovery)")
    ap.add_argument("files",nargs="*",help="file list; or stdin, one per line")
    a=ap.parse_args()
    files=a.files or [l.strip() for l in sys.stdin if l.strip()]
    assignments=plan(files, a.mode, a.k, a.max_pods, a.pods)
    total_scans=sum(len(b) for b in assignments)
    print(json.dumps({
        "mode":a.mode, "files":len(files), "pods":len(assignments),
        "replication":a.k if a.mode=="delta" else 1,
        "total_file_scans":total_scans,
        "assignments":{f"pod{i}":b for i,b in enumerate(assignments)},
    }, indent=1))
