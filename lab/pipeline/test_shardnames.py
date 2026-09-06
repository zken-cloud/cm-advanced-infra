#!/usr/bin/env python3
"""Q15: a find retry publishes into the next free slot, because it cannot overwrite.
Everything reading find/<sha>/ must count SHARDS not objects, and read the NEWEST
attempt not all of them. Run: python3 test_shardnames.py"""
import importlib.util, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("s", os.path.join(HERE, "shardnames.py"))
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)

T = []
def check(name, got, want):
    ok = got == want
    T.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name:52} {got!r}" + ("" if ok else f" != {want!r}"))

# --- parsing ---------------------------------------------------------------
check("first attempt keeps the historic name",      S.split_attempt("0.db"), ("0.db", 1))
check("a retry is slot 2",                          S.split_attempt("0.2.db"), ("0.db", 2))
check("prefix survives the split",                  S.split_attempt("coverage-0.2.json"), ("coverage-0.json", 2))
check("double digits are one slot, not two",        S.split_attempt("3.10.db"), ("3.db", 10))
check("cm log",                                     S.split_attempt("cm-1.2.log"), ("cm-1.log", 2))

# --- which shard -----------------------------------------------------------
check("index of a plain shard db",                  S.shard_index("0.db"), 0)
check("index survives the attempt suffix",          S.shard_index("coverage-12.2.json"), 12)
check("RUN.json names no shard",                    S.shard_index("RUN.json"), None)
check("dispatch.json names no shard",               S.shard_index("dispatch.json"), None)

# --- counting: the merge gate's input --------------------------------------
# INCIDENTS 11 inverted. Counting objects reports 4 shards from a 3-shard fan-out
# with one retry, and shards_completed is what the gate reads.
objs = ["0.db", "0.2.db", "1.db", "2.db"]
check("3 shards, one retried, 4 objects",           S.distinct_shards(objs), 3)
check("(counting objects would have said 4)",       len(objs), 4)
check("markers never count as a shard",             S.distinct_shards(["RUN.json", "dispatch.json"]), 0)

# --- selection: never feed the dedup one shard twice -----------------------
check("newest attempt per shard wins",              S.newest(objs), ["0.2.db", "1.db", "2.db"])
check("order on disk does not decide it",           S.newest(["0.2.db", "0.db"]), ["0.2.db"])
check("slot 10 beats slot 9",                       S.newest(["4.9.db", "4.10.db"]), ["4.10.db"])
check("coverage selects independently of dbs",
      S.newest(["coverage-0.json", "coverage-0.2.json", "coverage-1.json"]),
      ["coverage-0.2.json", "coverage-1.json"])
check("nothing in, nothing out",                    S.newest([]), [])

# --- the historic corpus still parses --------------------------------------
old = ["0.db", "1.db", "2.db", "coverage-0.json", "coverage-1.json", "coverage-2.json",
       "cm-0.log", "scrub-0.json"]
check("pre-Q15 objects are all attempt 1",          {S.split_attempt(o)[1] for o in old}, {1})
check("pre-Q15 shard count is unchanged",           S.distinct_shards(["0.db","1.db","2.db"]), 3)
check("pre-Q15 selection returns everything",       S.newest(old), sorted(old))

# --- the rules must be USED, not just exist -------------------------------
# Same idiom as test_policy.py: reconcile.py is a long-running service, so this
# asserts on its source. A helper nothing calls is how `shards_completed` goes on
# counting objects while the module that knows better sits beside it.
rec = open(os.path.join(HERE, "reconcile.py")).read()
check("reconcile counts shards, not .db objects",
      'len([u for u in ls(f"gs://{self.bucket}/find/{sha}/") if u.endswith(".db")])' in rec, False)
check("reconcile uses distinct_shards",             rec.count("shardnames.distinct_shards") >= 2, True)
check("reconcile selects newest dbs and coverage",  rec.count("shardnames.newest") >= 2, True)

tp = open(os.path.join(os.path.dirname(HERE), "k8s", "run-twophase.sh")).read()
check("run-twophase no longer fetches $i.db by name", '/find/$SHA/$i.db' in tp, False)
check("run-twophase selects with shardnames",       "shardnames.py --canonical" in tp, True)

job = open(os.path.join(os.path.dirname(HERE), "k8s", "51-find-job.yaml")).read()
check("find job takes the next free slot on 412",   "412) _n=$((_n+1))" in job, True)
check("find job still creates-only",                "ifGenerationMatch=0" in job, True)

print(f"\n{sum(T)}/{len(T)} passed")
sys.exit(0 if all(T) else 1)
