#!/usr/bin/env python3
"""Promote a harvested semgrep rule to BLOCKING by stamping ledger provenance.

The pre-commit hook blocks on a rule only if it carries `cm_fingerprint` and
`cm_poc`. This is the only thing that may add them, and it refuses on TWO
independent grounds:

  1. the ledger must say the finding is `verified` AND carry a PoC artifact; and
  2. the rule must stay SILENT on every correct-fix case in the FP corpus.

Both refusals are the point. (1) stops "blocking rule" degrading to "rule someone
felt strongly about". (2) stops a rule blocking code that is already correct --
measured, a harvested prototype-pollution rule proxied "is this guarded" with a
regex over guard keywords, so a
guard factored into a helper makes it fire on a properly fixed function. A hook
that blocks correct code gets bypassed by habit, and then it protects nothing.

Q12 decided: a rule that fails the FP corpus ships ADVISORY. It still fires, it
still tells the developer, it simply may not stop the commit. The merge gate is
the non-bypassable control; the hook is a convenience, and a convenience that
blocks correct work is not one.

    python3 stamp-rules.py --ledger cm-ledger.db \\
        --rules pipeline/harvested-rules/<your-harvested>.yaml \\
        --map cm-harvested-<cwe>-<hash>=fp3:<fingerprint>

Unmapped rules are left advisory, on purpose.
"""
import argparse, sqlite3, sys
import yaml


def fp_offenders(rules_path, cases_dir):
    """Rule ids that fire on code which is already CORRECT.

    Files named fixed_* in the FP corpus are genuine fixes. Any rule matching one
    of them would block a developer who did the right thing, so it may not be
    promoted. Semgrep unavailable or corpus missing => refuse to promote anything,
    because an unchecked blocking rule is the failure this exists to prevent.
    """
    import json, shutil, subprocess, tempfile, os
    if not os.path.isdir(cases_dir):
        print(f"  WARNING: no FP corpus at {cases_dir} — refusing to promote anything")
        return {"*"}
    if not shutil.which("semgrep"):
        print("  WARNING: semgrep not installed — cannot check correct-fix cases, "
              "refusing to promote anything")
        return {"*"}
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "r.json")
        subprocess.run(["semgrep", "scan", "--config", rules_path, "--metrics=off",
                        "--quiet", "--json", "-o", out, cases_dir],
                       capture_output=True, check=False)
        try:
            res = json.load(open(out)).get("results", [])
        except Exception:
            return {"*"}
    bad = {r["check_id"].split(".")[-1] for r in res
           if os.path.basename(r["path"]).startswith("fixed_")}
    for b in sorted(bad):
        print(f"  FP-CHECK {b}: fires on a correct fix")
    return bad


def ledger_rows(path):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    return {r["fingerprint"]: dict(r) for r in db.execute("select * from findings")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--rules", required=True)
    # append + nargs="+" so BOTH forms work: `--map a=1 b=2` and `--map a=1 --map b=2`.
    # With nargs alone, a repeated flag silently OVERWRITES -- four --map arguments
    # stamped one rule and reported success, which is the worst way to lose input.
    ap.add_argument("--map", nargs="+", action="append", required=True,
                    metavar="RULE_ID=FINGERPRINT")
    ap.add_argument("--out", help="default: in place")
    ap.add_argument("--fp-cases", default="targets/harvest-fp-cases",
                    help="dir of CORRECT code the rule must stay silent on (Q12)")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="stamp even if the ledger has not verified it (NOT for the hook)")
    ap.add_argument("--skip-fp-check", action="store_true",
                    help="skip the correct-fix check. Only for offline inspection.")
    a = ap.parse_args()

    found = ledger_rows(a.ledger)
    blocked_by_fp = fp_offenders(a.rules, a.fp_cases) if not a.skip_fp_check else set()
    doc = yaml.safe_load(open(a.rules))
    by_id = {r["id"]: r for r in doc.get("rules", [])}

    stamped = refused = 0
    for pair in [p for group in a.map for p in group]:
        if "=" not in pair:
            sys.exit(f"error: --map wants RULE_ID=FINGERPRINT, got {pair!r}")
        rid, fp = pair.split("=", 1)
        rule = by_id.get(rid)
        if rule is None:
            print(f"  SKIP    {rid}: no such rule in {a.rules}")
            continue
        row = found.get(fp)
        if row is None:
            print(f"  REFUSED {rid}: {fp} is not in the ledger")
            refused += 1
            continue
        # "*" is the fail-CLOSED sentinel fp_offenders() returns when the corpus is
        # missing or unreadable. A plain `rid in blocked_by_fp` never matches it, so
        # the script printed "refusing to promote anything" and then promoted -- the
        # one path allowed to make a pre-commit rule block a developer, inverted.
        if "*" in blocked_by_fp or rid in blocked_by_fp:
            why = (f"the FP corpus at {a.fp_cases} is missing or unreadable"
                   if "*" in blocked_by_fp
                   else f"it fires on a CORRECT fix in {a.fp_cases}")
            print(f"  ADVISORY {rid}: {why} — stays advisory (Q12). "
                  f"It will still warn, it may not block.")
            refused += 1
            continue
        verdict, poc = row.get("verdict"), row.get("poc_uri")
        if not a.allow_unverified and verdict != "verified":
            print(f"  REFUSED {rid}: {fp} verdict={verdict!r}, not 'verified' — stays advisory")
            refused += 1
            continue
        if not a.allow_unverified and not poc:
            print(f"  REFUSED {rid}: {fp} is verified but has NO PoC artifact — nothing to stand on")
            refused += 1
            continue
        md = rule.setdefault("metadata", {})
        md["cm_fingerprint"] = fp
        md["cm_poc"] = poc or ""
        md["cm_verdict"] = verdict
        md["cm_proven_sha"] = row.get("proven_sha") or row.get("last_seen_sha") or ""
        # D28: reproduction is not impact. A rule that blocks commits on the
        # strength of a reproduction alone repeats the gate's mistake at the desk.
        md["cm_impact_review"] = row.get("impact_review") or "unreviewed"
        stamped += 1
        print(f"  STAMPED {rid} <- {fp}  poc={poc}")

    out = a.out or a.rules
    with open(out, "w") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False, width=100)
    print(f"\n{stamped} rule(s) now BLOCKING, {refused} refused -> {out}")
    return 1 if refused and not stamped else 0


if __name__ == "__main__":
    sys.exit(main())
