#!/usr/bin/env python3
"""semgrep JSON -> the 'simple JSON' shape `cm report import` accepts.

Why this exists: `cm report import --help` advertises SARIF, but cm 0.4.0 answers
a SARIF file with "failed to parse as simple JSON (SARIF support coming soon)".
Simple JSON is the only working path, and its schema is only discoverable by
sending a bad file and reading the error:

    [{"file_path": "src/main.c", "line": 42, "title": "Buffer Overflow",
      "message": "strcpy called without bounds check",
      "severity": "HIGH", "vuln_type": "CWE-120"}]

`file_path` and a positive integer `line` are required; the rest are optional but
`cm fix` reasons better with all of them.

    semgrep scan --config=p/javascript --json -o sg.json .
    python3 semgrep-to-cm.py sg.json -o cm-findings.json
    cm report import -f cm-findings.json -p .
"""
import argparse, json, sys

# semgrep severities are ERROR/WARNING/INFO; cm wants CRITICAL/HIGH/MEDIUM/LOW.
# Deliberately no ERROR->CRITICAL mapping: a static match is a candidate, and
# minting CRITICAL from a pattern hit inflates every downstream severity gate.
SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def cwe_of(md):
    """semgrep puts CWE in metadata.cwe, as a string or a list of strings."""
    c = md.get("cwe")
    if isinstance(c, list):
        c = c[0] if c else None
    if not c:
        return None
    return c.split(":")[0].strip() or None       # "CWE-79: Improper..." -> "CWE-79"


def convert(sg):
    out = []
    for r in sg.get("results", []):
        extra = r.get("extra", {})
        md = extra.get("metadata", {}) or {}
        line = (r.get("start") or {}).get("line") or 0
        if not r.get("path") or line < 1:
            continue                              # cm rejects line < 1 outright
        rule = r.get("check_id", "semgrep")
        out.append({
            "file_path": r["path"],
            "line": line,
            "title": rule.rsplit(".", 1)[-1].replace("-", " ").replace("_", " ").title(),
            # keep the rule id in the message: it is the join key back to semgrep,
            # and cm's finding_id is its own and unrelated.
            "message": f"[{rule}] {extra.get('message','').strip()}",
            "severity": SEV.get(str(extra.get("severity", "")).upper(), "MEDIUM"),
            "vuln_type": cwe_of(md) or "CWE-noinfo",
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("semgrep_json")
    ap.add_argument("-o", "--out", required=True)
    a = ap.parse_args()
    sg = json.load(open(a.semgrep_json))
    if "runs" in sg and "results" not in sg:
        sys.exit("error: that looks like SARIF. cm 0.4.0 cannot import SARIF -- "
                 "re-run semgrep with --json, not --sarif.")
    rows = convert(sg)
    json.dump(rows, open(a.out, "w"), indent=1)
    print(f"{len(rows)} finding(s) -> {a.out}")
    for r in rows:
        print(f"  {r['severity']:6} {r['vuln_type']:12} {r['file_path']}:{r['line']}")


if __name__ == "__main__":
    main()
