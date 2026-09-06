#!/usr/bin/env python3
"""Which shard a find artifact belongs to, and which attempt wrote it.

A find pod cannot overwrite what it published: it holds `roles/storage.objectCreator`
-- invariant 3's publish-only credential, *add an object, never replace one*. So a
retry cannot correct its predecessor in place. Before Q15 it could not correct it at
all: attempt 1 owned `find/<sha>/<idx>.db`, attempt 2's publish was refused, and a
shard that failed transiently and then SUCCEEDED had its real findings thrown away
while the stale envelope stood.

A retry now publishes into the next free slot instead:

    0.db                first attempt of shard 0
    0.2.db              a later attempt of shard 0
    coverage-0.json     first attempt's coverage
    coverage-0.2.json   the later attempt's

Two rules follow, and everything that reads these objects needs both:

  * COUNT DISTINCT SHARDS, never objects. `shards_completed` is the merge gate's
    input; counting objects would report 4 shards from a 3-shard fan-out with one
    retry, which is INCIDENTS 11 inverted -- over-counting into a PASS instead of
    under-reading into one.
  * READ THE NEWEST ATTEMPT, never all of them. Feeding both to the dedup counts
    one shard's findings twice and inflates the agreement K-replication is measured
    by.

The first attempt keeps the historic name, so objects published before any of this
existed parse as attempt 1 and behave exactly as they did.
"""
import os
import re

_ATTEMPT = re.compile(r"^(?P<stem>.+)\.(?P<n>\d+)$")
_INDEX   = re.compile(r"(?P<idx>\d+)$")


def split_attempt(name):
    """('0.2.db') -> ('0', 2). The stem keeps its prefix: coverage-0.2.json -> coverage-0."""
    base = os.path.basename(name)
    stem, ext = os.path.splitext(base)
    m = _ATTEMPT.match(stem)
    if m:
        return m.group("stem") + ext, int(m.group("n"))
    return base, 1


def shard_index(name):
    """The shard this artifact belongs to, as an int, or None if it names no shard.

    Markers and anything else that is not `<something->?<digits>` return None so a
    caller counting shards never counts RUN.json or dispatch.json.
    """
    stem, _ = split_attempt(name)
    stem, _ext = os.path.splitext(stem)
    m = _INDEX.search(stem)
    return int(m.group("idx")) if m else None


def newest(names):
    """One name per (stem) group: the highest attempt. Input order is irrelevant."""
    best = {}
    for n in names:
        stem, att = split_attempt(n)
        if stem not in best or att > best[stem][0]:
            best[stem] = (att, n)
    return [n for _, n in sorted(best.values(), key=lambda t: t[1])]


def distinct_shards(names):
    """How many shards these artifacts represent. Objects != shards, once a shard
    can publish twice."""
    return len({i for i in (shard_index(n) for n in names) if i is not None})


if __name__ == "__main__":
    import sys
    # So run-twophase.sh can select without reimplementing these rules in bash,
    # which is how two copies of one truth start (D47).
    #
    #   shardnames.py            names...   -> the newest name per shard
    #   shardnames.py --canonical names...  -> "<newest name>\t<name to save it as>"
    #
    # --canonical exists because the operator path globs /tmp/tp/*.db in four
    # places. Downloading `0.2.db` under its own name would need every one of those
    # to learn the slot rules; downloading it AS `0.db` needs none of them to.
    args = sys.argv[1:]
    canonical = "--canonical" in args
    names = [a for a in args if not a.startswith("--")]
    names = names or [l.strip() for l in sys.stdin if l.strip()]
    for n in newest(names):
        print(f"{n}\t{split_attempt(n)[0]}" if canonical else n)
