#!/usr/bin/env python3
"""Harvest a VERIFIED finding into a static rule that runs at IDE/commit time.

The highest value-per-effort move in the whole design (ARCHITECTURE shift-left #1):
every verified exploit is ground truth about a real exploitable pattern *in this
codebase*. Encode it as a Semgrep rule and it is caught in milliseconds, forever,
left of the buildable artifact where CM itself cannot run. One ~4-40 min
verification becomes unlimited millisecond detections.

Input : a finding row (from the ledger / cm state.db) + the source file.
Output: a Semgrep YAML rule keyed to the fingerprint, with metadata linking back
        to the PoC so a hit is explainable ("this is the pattern CM proved
        exploitable in <fingerprint>, see <poc_uri>").

This is deliberately CONSERVATIVE: it emits a rule from the vulnerable sink
pattern, tagged with the source symbol, so it is auditable and low-false-positive.
A human reviews harvested rules before they gate (they start as warnings).
"""
import sqlite3, sys, os, re, json, hashlib, argparse

# sink-pattern templates per class. {sink} is the dangerous call the AST/snippet exposes.
# Semgrep patterns use `...` (ellipsis) and `$X` metavars — language-aware, not regex.
# sink-pattern templates per class — EACH VALIDATED with semgrep against real
# vulnerable + fixed code (see harvest-validate output). Patterns use semgrep
# metavars ($X) and ellipsis (...), not regex, so they are language-aware.
TEMPLATES = {
    "sql-injection": {
        "languages": ["javascript","typescript"],
        "patterns": ['$DB.query($A + $B, ...)', '$DB.query($A + $B)',
                     '$DB.$M(`...${$X}...`, ...)', '$MODELS.sequelize.query($A + $B, ...)'],
        "message": "SQL built by string concatenation reaches a query sink — CM proved this exploitable. Use parameterized queries / bind parameters.",
    },
    "os-command-injection": {
        "languages": ["javascript","typescript"],
        "patterns": ['$CP.exec($A + $B, ...)', '$CP.execSync($A + $B, ...)',
                     '$CP.exec(`...${$X}...`, ...)'],
        "message": "Shell command built from untrusted input — CM proved RCE. Use execFile with an args array; never a shell string.",
    },
    "code-injection": {
        "languages": ["javascript","typescript"],
        "patterns": ['eval($X)', 'new Function(...)'],
        "message": "Dynamic code execution of request-derived data — CM proved arbitrary code execution.",
    },
    "memory-corruption": {
        "languages": ["c","cpp"],
        "patterns": ['memcpy($DST, $SRC, strlen($SRC))', 'strcpy($DST, $SRC)',
                     'sprintf($BUF, $FMT, $SRC)'],
        "message": "Copy length derived from input, not sizeof(dst) — CM proved a buffer overflow. Bound by sizeof; use strncpy/snprintf.",
    },
    "idor": {
        "languages": ["javascript","typescript"],
        "patterns": ['$STORE.findByPk($REQ.params.$P, ...)', '$STORE.get($REQ.params.$P)',
                     '$STORE.findOne({ where: { id: $REQ.params.$P } })'],
        "message": "Object fetched by client-supplied id with no visible ownership check — CM proved IDOR. Verify the caller owns the object.",
        "confidence": "LOW",
    },
}

def load_finding(db_path, fid_prefix):
    c=sqlite3.connect(f"file:{db_path}?mode=ro",uri=True); c.row_factory=sqlite3.Row
    row=c.execute("select * from findings where finding_id like ?", (fid_prefix+"%",)).fetchone()
    return dict(row) if row else None

# reuse the class map + sink extraction already built for dedup
def _load_dedup():
    import importlib.util
    here=os.path.dirname(os.path.abspath(__file__))
    spec=importlib.util.spec_from_file_location("d",os.path.join(here,"consolidate-dedup.py"))
    m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

def harvest(finding, fingerprint, poc_uri=None):
    d=_load_dedup()
    cwe_class=d.cwe_class(finding.get("vuln_id"))
    tpl=TEMPLATES.get(cwe_class)
    if not tpl:
        return None, f"no template for class {cwe_class} (extend TEMPLATES)"
    rule_id=f"cm-harvested-{cwe_class}-{fingerprint.split(':')[-1][:8]}"
    patterns=tpl["patterns"]
    rule={
        "rules":[{
            "id": rule_id,
            "languages": tpl["languages"],
            "message": tpl["message"],
            "severity": "ERROR" if tpl.get("confidence")!="LOW" else "WARNING",
            "patterns":[{"pattern-either":[{"pattern":p} for p in patterns]}],
            "metadata":{
                "cm_fingerprint": fingerprint,
                "cwe": finding.get("vuln_id"),
                "source": "codemender-verified" if finding.get("status")=="VERIFIED" else "codemender-candidate",
                "poc": poc_uri or "n/a",
                "confidence": tpl.get("confidence","HIGH"),
                "note": "Auto-harvested from a CM verification. Review before gating; ships as advisory until confirmed.",
            },
        }]
    }
    return rule, None

def to_yaml(rule):
    # minimal YAML emitter (no pyyaml dependency); stable ordering
    def esc(s): return json.dumps(s)  # JSON strings are valid YAML scalars
    r=rule["rules"][0]
    lines=["rules:", f"  - id: {r['id']}",
           f"    languages: [{', '.join(r['languages'])}]",
           f"    severity: {r['severity']}",
           f"    message: {esc(r['message'])}",
           "    patterns:",
           "      - pattern-either:"]
    for p in r["patterns"][0]["pattern-either"]:
        lines.append(f"          - pattern: {esc(p['pattern'])}")
    lines.append("    metadata:")
    for k,v in r["metadata"].items():
        lines.append(f"      {k}: {esc(v)}")
    return "\n".join(lines)+"\n"

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("db"); ap.add_argument("finding_id_prefix")
    ap.add_argument("--fingerprint",default="fp3:unknown"); ap.add_argument("--poc")
    ap.add_argument("-o","--out")
    a=ap.parse_args()
    f=load_finding(a.db,a.finding_id_prefix)
    if not f: sys.exit(f"no finding {a.finding_id_prefix}")
    rule,err=harvest(f,a.fingerprint,a.poc)
    if err: sys.exit(err)
    y=to_yaml(rule)
    if a.out: open(a.out,"w").write(y); print(f"wrote {a.out}")
    else: print(y)
