#!/usr/bin/env python3
"""The audited sign-off path: how a human accepts a verified risk (P2 / D53).

A verified, unfixed finding blocks. `sign-off-required` means it can still ship —
but only if a named human accepts the risk in a way that can be queried later. That
is the whole difference between a policy and a bypass.

WHERE THE ACCEPTANCE LIVES. In the target repo, as
`.cm/risk-accepted/<fingerprint>.yaml`, added by a pull request. The PR *is* the
audit trail: GitHub already records who opened it, who approved it, when, and what
was said. Reinventing that in a bespoke tool would produce a worse record and one
nobody trusts. CODEOWNERS on `.cm/risk-accepted/` routes it to whoever is allowed
to sign.

WHY NOT JUST READ THE FILE AT GATE TIME. Invariant 3: the ingester is the sole
writer to the ledger, and the gate reads the ledger. A gate that reads files from
the branch under test is a gate the branch under test can rewrite.

  risk-accept.py --check .cm/risk-accepted/          # PR validation, writes nothing
  risk-accept.py --ingest .cm/risk-accepted/ --ledger cm-ledger.db \
                 --repo cm-lab-user1 --pr-url ... --approved-by ... --now ...

WHAT --check REFUSES, and why each one is a real failure and not a formality:

  * a fingerprint that is not `verified` in the ledger — you cannot accept a risk
    nobody has established. This also stops an acceptance being filed pre-emptively
    against a finding that has not been verified yet, which would be a bypass with
    extra steps;
  * a fingerprint already `fixed_at` — the acceptance is stale, and merging it would
    park an expiry timer on a bug that is gone;
  * a missing or unbounded expiry. An acceptance with no end date is not a decision,
    it is a silent policy change;
  * a reason outside RISK_REASONS. Free text cannot be grouped, and the rate per
    category is the signal that tells you whether the DETECTOR is wrong rather than
    the fix queue (Q11);
  * self-approval: `approved_by` equal to the file's `owner`. One person accepting
    their own risk is the failure mode the whole gate exists to prevent.
"""
import os
import sys
import glob
import json
import argparse
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_EXPIRY_DAYS = 90


def _ledger_mod():
    s = importlib.util.spec_from_file_location("ledger", os.path.join(HERE, "ledger.py"))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


REQUIRED = ("fingerprint", "scope", "reason_code", "owner", "expires_at")


def load(path):
    import yaml
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _days_between(a, b):
    """Whole days from ISO date a to ISO date b. Dates, not wall-clock: the caller
    supplies `now`, so this stays testable and the ledger stays reproducible."""
    from datetime import date
    pa = date.fromisoformat(a[:10])
    pb = date.fromisoformat(b[:10])
    return (pb - pa).days


def validate(doc, path, now, ledger=None, approved_by=None):
    """Return a list of problems. Empty means the acceptance may be merged."""
    L = _ledger_mod()
    problems = []
    base = os.path.basename(path)

    for k in REQUIRED:
        if not doc.get(k):
            problems.append(f"{base}: missing required field `{k}`")
    if problems:
        return problems

    fp = doc["fingerprint"]
    if not base.startswith(fp.replace(":", "_")):
        problems.append(f"{base}: filename must start with the fingerprint ({fp}) — "
                        f"one acceptance per file, discoverable by name")

    if doc["reason_code"] not in L.RISK_REASONS:
        problems.append(f"{base}: reason_code {doc['reason_code']!r} is not one of "
                        f"{sorted(L.RISK_REASONS)}")

    try:
        days = _days_between(now, doc["expires_at"])
    except ValueError:
        problems.append(f"{base}: expires_at {doc['expires_at']!r} is not an ISO date")
        return problems
    if days <= 0:
        problems.append(f"{base}: expires_at {doc['expires_at']} is not in the future")
    elif days > MAX_EXPIRY_DAYS:
        problems.append(f"{base}: expires_at is {days} days out; the maximum is "
                        f"{MAX_EXPIRY_DAYS}. A long acceptance is a decision nobody "
                        f"revisits — renew it deliberately instead")

    if approved_by and approved_by == doc["owner"]:
        problems.append(f"{base}: {approved_by} cannot approve their own acceptance")

    # The finding must actually be verified. Without the ledger we cannot tell, and
    # PASSING on 'cannot tell' is exactly the fail-open this design refuses.
    if ledger is None:
        problems.append(f"{base}: no ledger supplied — cannot confirm the finding is "
                        f"verified, and an unconfirmed acceptance must not merge")
        return problems
    db = L.open_ledger(ledger)
    row = db.execute("SELECT verdict, fixed_at FROM findings WHERE fingerprint=?",
                     (fp,)).fetchone()
    if row is None:
        problems.append(f"{base}: fingerprint {fp} is not in the ledger — nothing to accept")
    elif row["verdict"] != "verified":
        problems.append(f"{base}: fingerprint {fp} is `{row['verdict']}`, not `verified`. "
                        f"Only an established risk can be accepted; an unproven one is "
                        f"a verify job, not a sign-off")
    elif row["fixed_at"]:
        problems.append(f"{base}: fingerprint {fp} was fixed at {row['fixed_at']} — "
                        f"the acceptance is stale")
    return problems


def ingest(doc, db, repo, pr_url, approved_by, now):
    """Write the acceptance row. Append-only: superseding one is a new row."""
    db.execute("""INSERT INTO risk_acceptances(fingerprint,repo,scope,reason_code,
                  reason_text,owner,approved_by,pr_url,expires_at,created_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?)""",
               (doc["fingerprint"], repo, doc["scope"], doc["reason_code"],
                doc.get("reason_text"), doc["owner"], approved_by, pr_url,
                doc["expires_at"], now))
    db.commit()
    return db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]


def active(db, fingerprint, repo, now, scope=None):
    """The acceptance covering this finding right now, or None.

    Expiry and revocation are evaluated HERE rather than by a sweeper, so an
    acceptance that lapses stops covering the finding the moment it lapses — there
    is no window in which a stale row still says PASS because nothing has run."""
    rows = db.execute("""SELECT * FROM risk_acceptances
                         WHERE fingerprint=? AND repo=? AND revoked_at IS NULL
                         ORDER BY acceptance_id DESC""", (fingerprint, repo)).fetchall()
    for r in rows:
        if r["expires_at"][:10] < now[:10]:
            continue
        if scope and r["scope"] not in (scope, "trunk"):
            continue
        return dict(r)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("directory")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--ingest", action="store_true")
    ap.add_argument("--ledger")
    ap.add_argument("--repo")
    ap.add_argument("--pr-url")
    ap.add_argument("--approved-by")
    ap.add_argument("--now", required=True, help="ISO date; no wall-clock dependence")
    a = ap.parse_args()

    files = sorted(glob.glob(os.path.join(a.directory, "*.yaml")) +
                   glob.glob(os.path.join(a.directory, "*.yml")))
    if not files:
        print(f"no acceptance files in {a.directory} — nothing to do")
        return 0

    problems, docs = [], []
    for f in files:
        try:
            doc = load(f)
        except Exception as e:
            problems.append(f"{os.path.basename(f)}: unparseable ({e})")
            continue
        p = validate(doc, f, a.now, a.ledger, a.approved_by)
        problems.extend(p)
        if not p:
            docs.append((f, doc))

    for p in problems:
        print(f"REFUSED  {p}")
    for f, d in docs:
        print(f"ok       {os.path.basename(f)}  {d['reason_code']}  "
              f"owner={d['owner']}  expires={d['expires_at']}")

    if problems:
        return 1
    if a.ingest:
        L = _ledger_mod()
        db = L.open_ledger(a.ledger)
        for f, d in docs:
            aid = ingest(d, db, a.repo, a.pr_url, a.approved_by, a.now)
            print(f"ingested acceptance_id={aid} for {d['fingerprint']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
