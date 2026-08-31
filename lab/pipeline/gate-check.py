#!/usr/bin/env python3
"""The developer-facing merge gate, as a READ-ONLY query.

Separate from ingest-verdicts.py on purpose. The ingester is the sole writer
(invariant 3); the gate must never write, and the gate SA holds only
storage.objectViewer. Opening the ledger `mode=ro` makes that structural rather
than a promise -- a gate that can write is a gate that can mark its own blocker
fixed.

    exit 0  PASS   scan on record for this sha AND nothing verified-and-unfixed
    exit 1  BLOCK  a verified, unfixed finding is present
    exit 2  RACE   no scan, or a partial one -- the race policy decides
    exit 3  ERROR  ledger unreadable -> fail closed, never silently green

--event-out writes the decision as ONE new object, for the warehouse. This is the
only thing the programme knows about its own effect on developers: BLOCK rate,
RACE rate, and how long a blocked sha stays blocked. It lived nowhere but Actions
logs, which age out.

It does NOT weaken invariant 3. The event goes to a separate prefix under an
objectCreator-only binding: create a new object, never read the ledger, never
overwrite anything. The name is content-addressed by (sha, run) so two gate runs
cannot collide -- no contention, no CAS, no retry.
"""
import argparse, json, os, sqlite3, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib
ledger = importlib.import_module("ledger")

# RISK_ACCEPTED exits 0: it is a PASSING gate. It is a separate action rather than
# PASS because the event stream has to be able to answer "what shipped with known
# verified bugs, and who signed" -- which a shared exit code erases (D53).
EXIT = {"PASS": 0, "RISK_ACCEPTED": 0, "BLOCK": 1, "RACE": 2}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--min-shards", type=int, default=1)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--event-out", help="write the decision as NDJSON to this path "
                                        "(the caller uploads it; the gate never talks to GCS)")
    ap.add_argument("--run-id", default="local", help="CI run id — part of the event's identity")
    ap.add_argument("--ts", help="RFC3339 timestamp for the event")
    a = ap.parse_args()

    def emit(action, reason, details=None):
        """One line of NDJSON. Called on EVERY exit path, including the two that
        return before the ledger is opened -- a gate that only records its
        successes reports a BLOCK rate of zero."""
        if not a.event_out:
            return
        try:
            with open(a.event_out, "w") as fh:
                fh.write(json.dumps({
                    "repo": a.repo, "sha": a.sha, "action": action, "reason": reason,
                    # Q8: this event IS the merge-attempt timestamp. The gate may not
                    # write the ledger (invariant 3), so the race's third stamp is
                    # reconstructed from gate_events at report time rather than
                    # written here. A gate that could stamp the ledger is a gate that
                    # could stamp other things.
                    "run_id": a.run_id, "ts": a.ts,
                    "blocking_count": len((details or {}).get("blocking", [])),
                    "blocking": [b.get("fingerprint") for b in (details or {}).get("blocking", [])],
                }, default=str) + "\n")
        except Exception as e:                  # telemetry must never fail a merge
            print(f"gate: could not write event ({e})", file=sys.stderr)

    # A missing ledger is RACE, not PASS. First run of a fresh repo lands here,
    # and "we have never scanned this" must never read as "this is clean".
    if not os.path.exists(a.ledger):
        msg = f"no ledger at {a.ledger} — nothing has ever been scanned"
        print(json.dumps({"action": "RACE", "reason": msg}) if a.json
              else f"GATE [{a.repo}@{a.sha[:12]}]: RACE — {msg}")
        emit("RACE", msg)
        return 2

    try:
        db = sqlite3.connect(f"file:{a.ledger}?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        action, reason, details = ledger.merge_gate(db, a.repo, a.sha, a.min_shards,
                                                    now=a.ts)
    except Exception as e:                      # unreadable/corrupt -> fail closed
        print(f"GATE: ERROR — {e} (failing closed)", file=sys.stderr)
        emit("ERROR", str(e))
        return 3

    # Record BEFORE rendering. Formatting is cosmetic; the decision is the data,
    # and a crash in the pretty-printer must not cost us the event.
    emit(action, reason, details)

    if a.json:
        print(json.dumps({"action": action, "reason": reason, **details}, default=str))
    else:
        print(f"GATE [{a.repo}@{a.sha[:12]}]: {action} — {reason}")
        for b in details.get("blocking", []):
            # `or` not the dict default: cwe_class is a COLUMN that is often NULL,
            # so .get() returns None rather than missing, and f"{None:24}" raises
            # TypeError. That crashed the gate with exit 1 -- indistinguishable
            # from a legitimate BLOCK, which is how it went unnoticed.
            print(f"  BLOCKING  {(b.get('cwe_class') or '?'):24} {b.get('canonical_path') or '?'}")
            print(f"            fp={b.get('fingerprint') or '?'}  poc={b.get('poc_uri') or '—'}")
        for b in details.get("accepted", []):
            acc = b["acceptance"]
            print(f"  ACCEPTED  {(b.get('cwe_class') or '?'):24} {b.get('canonical_path') or '?'}")
            print(f"            {acc['owner']} ({acc['reason_code']}) until {acc['expires_at']} — {acc['pr_url']}")
    return EXIT.get(action, 3)


if __name__ == "__main__":
    sys.exit(main())
