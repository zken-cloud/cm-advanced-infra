#!/usr/bin/env python3
"""Audit the PoC corpus: how much of it can actually serve as a regression oracle?

The corpus is described as the highest value-to-effort artefact in the design, and
until 2026-08-25 nobody had asked that question of it. The answer was 6 of 9 --
a third of the banked exploits prove their finding but can never be REPLAYED,
because they assume something is already listening (D30 requires relocatable AND
self-booting; the verify pod only checks the first).

That gap is not dangerous -- poc-replay.py refuses an inadmissible PoC with
INADMISSIBLE_POC, so nothing untrustworthy reaches the regression gate. It is
MISLEADING, which is its own problem: a corpus of N exploits where only M can be
replayed provides M/N of the regression coverage it appears to, and the difference
is invisible until someone replays them one at a time.

  poc-corpus-audit.py gs://bucket/poc          # audit the live corpus
  poc-corpus-audit.py ./poc-corpus-backup      # or a local copy
  poc-corpus-audit.py gs://bucket/poc --json
"""
import os, sys, glob, json, shutil, tarfile, argparse, tempfile, subprocess, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("pr", os.path.join(HERE, "poc-replay.py"))
pr = importlib.util.module_from_spec(spec); spec.loader.exec_module(pr)


def fetch(src):
    """Return a local directory holding the corpus, downloading it if needed."""
    if not src.startswith("gs://"):
        return src, None
    tmp = tempfile.mkdtemp(prefix="corpus-")
    r = subprocess.run(["gcloud", "storage", "cp", "-r", src.rstrip("/"), tmp],
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"could not fetch {src}: {(r.stderr or '').strip()[-300:]}")
    return tmp, tmp


def audit_one(tgz):
    """Unpack one PoC bundle and ask poc-replay whether it is oracle-grade."""
    d = tempfile.mkdtemp()
    try:
        with tarfile.open(tgz) as t:
            t.extractall(d)
        entry = sorted(glob.glob(os.path.join(d, "*.sh")))
        if not entry:
            return {"admissible": False, "reason": "no entry script in bundle"}
        a = pr.audit_bundle(entry[0])
        # Two independent ways to be useless as an oracle, and they are NOT the same
        # question: `admissible` is "can it test the tree it is pointed at", while
        # oracle_safe is "does no-fire actually mean fixed". A PoC proving via an
        # out-of-band callback boots fine and still proves nothing in a sealed
        # network. Report both rather than collapsing them into one verdict.
        return {"admissible": bool(a.get("admissible")),
                "oracle_safe": bool(a.get("oracle_safe")),
                "tier": a.get("tier"), "self_booting": bool(a.get("self_booting")),
                "pinned": bool(a.get("pinned_paths")),
                "reason": ("" if a.get("admissible")
                           else "tier>0 and does not start its own target"
                           if not a.get("self_booting")
                           else "pinned to an absolute path from the tree it was born in")}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", help="gs://bucket/poc or a local directory")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    root, cleanup = fetch(a.corpus)
    try:
        tgzs = sorted(glob.glob(os.path.join(root, "**", "*.tgz"), recursive=True))
        rows = []
        for t in tgzs:
            rel = os.path.relpath(t, root)
            fp = os.path.basename(os.path.dirname(t))
            rows.append({"fingerprint": fp, "sha": os.path.basename(t)[:-4],
                         "path": rel, **audit_one(t)})
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)

    good = [r for r in rows if r["admissible"] and r.get("oracle_safe", True)]
    if a.json:
        print(json.dumps({"total": len(rows), "usable": len(good), "poc": rows}, indent=2))
        return 0

    if not rows:
        print(f"no PoC bundles under {a.corpus}")
        return 0
    print(f"{'FINGERPRINT':<26} {'SHA':<14} {'TIER':<5} {'BOOTS':<6} {'SAFE':<5} ORACLE")
    for r in rows:
        print(f"{r['fingerprint']:<26} {r['sha'][:12]:<14} {str(r.get('tier')):<5} "
              f"{str(r.get('self_booting')):<6} {str(r.get('oracle_safe')):<5} "
              f"{'yes' if r['admissible'] and r.get('oracle_safe', True) else 'NO — ' + r['reason']}")
    print(f"\n{len(good)}/{len(rows)} usable as regression oracles")
    # Deliberately exit 0 even when some are unusable. This is a REPORT, not a gate:
    # an inadmissible PoC is still valid evidence that its finding is real, and
    # failing CI over corpus composition would push people to stop banking exploits
    # -- which costs far more than the coverage it would buy back.
    if len(good) < len(rows):
        print(f"{len(rows) - len(good)} bank fine as evidence but cannot be replayed "
              f"(D30 needs relocatable AND self-booting; verify only checks the first)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
