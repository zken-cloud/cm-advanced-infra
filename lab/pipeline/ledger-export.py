#!/usr/bin/env python3
"""Export the ledger to newline-delimited JSON for the warehouse.

The ledger is a 28 KB SQLite object: right for a point lookup on a merge gate,
useless for "are we getting faster". This dumps it to a layout BigQuery can read
as an external table, so managers query the warehouse and the gate keeps reading
the object. Nothing queries the ledger but the gate; nothing queries BigQuery but
dashboards.

Every export is a SNAPSHOT, stamped with `snapshot_ts` and written under a
`dt=YYYY-MM-DD` prefix. That is deliberate: `findings` is mutable -- verdicts fold
upward, `fixed_at` gets set -- so a single current-state view can answer "what is
open" but can never answer "was it worse last quarter". Keeping the snapshots IS
the trend history. Deduplicate at query time, not here.

    ledger-export.py --ledger cm-ledger.db --out-dir /tmp/warehouse \
                     --ts 2026-08-24T12:00:00Z [--repo cm-lab]

Output:
    <out>/findings/dt=2026-08-24/findings-<ts>.json
    <out>/observations/dt=2026-08-24/observations-<ts>.json
    <out>/scans/dt=2026-08-24/scans-<ts>.json
"""
import argparse, json, os, sqlite3, sys

# `coverage` is append-mostly and by far the largest; `risk_acceptances` and
# `patch_prs` are small and are the two tables an auditor asks for by name.
TABLES = ("findings", "observations", "scans", "coverage", "risk_acceptances",
          "patch_prs")


def export(ledger_path, out_dir, ts, repo=None):
    if not os.path.exists(ledger_path):
        raise SystemExit(f"ledger-export: no ledger at {ledger_path}")
    day = ts[:10]
    # mode=ro: the exporter is a reader like the gate. It must never be the reason
    # a ledger changes, and read-only makes that structural (invariant 3).
    db = sqlite3.connect(f"file:{ledger_path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    have = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
    written = {}
    for t in TABLES:
        if t not in have:
            written[t] = 0                     # absent, not empty -- say so
            continue
        d = os.path.join(out_dir, t, f"dt={day}")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"{t}-{ts.replace(':', '').replace('-', '')}.json")
        n = 0
        with open(path, "w") as fh:
            for row in db.execute(f"select * from {t}"):
                rec = dict(row)
                rec["snapshot_ts"] = ts
                # `findings` carries repo per row now, but rows written before that
                # column existed are NULL. Backfill from the run so old snapshots
                # are still attributable instead of silently un-grouped.
                if repo and not rec.get("repo"):
                    rec["repo"] = repo
                fh.write(json.dumps(rec, default=str) + "\n")
                n += 1
        written[t] = n
    return written


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--ts", required=True, help="RFC3339; also the snapshot identity")
    ap.add_argument("--repo", help="backfill rows predating the findings.repo column")
    a = ap.parse_args()
    w = export(a.ledger, a.out_dir, a.ts, a.repo)
    print("  export " + " · ".join(f"{k}={v}" for k, v in w.items()) + f"  -> {a.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
