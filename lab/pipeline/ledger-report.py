#!/usr/bin/env python3
"""Step 7 -- render the ledger as a self-contained HTML page.

Reads the central ledger (the SQLite file the ingester folds verdicts into) and
answers the questions a lab participant actually has:

  * what is BLOCKING a merge right now, and what is merely open
  * how much verify time has been spent, and on what
  * which findings are verified but NOT yet impact-reviewed (D28) -- the ones that
    would block a merge without anyone having judged whether they matter
  * what was EXAMINED (coverage), separately from what was FOUND

No external assets: one file, opens offline, safe to attach to a ticket.
"""
import argparse, html, json, os, sqlite3, datetime

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
VERDICT_COLOR = {
    "verified": "#B3261E", "exploit_failed": "#6C757D", "setup_failed": "#B87406",
    "unproven": "#5C6879", "timeout": "#B87406", "error": "#B87406",
    "not_found": "#8A94A3",
}


def cols(db, table):
    return {r[1] for r in db.execute(f"PRAGMA table_info({table})")}


def load(path):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    have = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
    out = {"findings": [], "scans": [], "coverage": []}
    if "findings" in have:
        out["findings"] = [dict(r) for r in db.execute("select * from findings")]
    if "scans" in have:
        out["scans"] = [dict(r) for r in db.execute("select * from scans")]
    if "coverage" in have:
        out["coverage"] = [dict(r) for r in db.execute("select * from coverage")]
    return out


def esc(x):
    return html.escape("" if x is None else str(x))


def render(d, title):
    f = d["findings"]
    verified = [x for x in f if x.get("verdict") == "verified"]
    unfixed = [x for x in verified if not x.get("fixed_at")]
    # D28: verified is NOT the same claim as "is a vulnerability". A verified
    # finding with no impact review is what would block a merge unjudged.
    unjudged = [x for x in unfixed if not x.get("impact_review")]
    by_verdict = {}
    for x in f:
        by_verdict[x.get("verdict") or "unknown"] = by_verdict.get(x.get("verdict") or "unknown", 0) + 1

    def rows(items):
        items = sorted(items, key=lambda r: (SEV_ORDER.get((r.get("severity") or "").upper(), 9),
                                             r.get("canonical_path") or ""))
        if not items:
            return '<tr><td colspan="5" class="empty">nothing here — that is the good outcome</td></tr>'
        out = []
        for r in items:
            v = r.get("verdict") or "—"
            out.append(
                f'<tr><td class="mono fp">{esc((r.get("fingerprint") or "")[:28])}</td>'
                f'<td>{esc(r.get("severity") or "—")}</td>'
                f'<td class="mono">{esc(r.get("cwe_class") or "—")}</td>'
                f'<td class="mono">{esc(r.get("canonical_path") or "—")}</td>'
                f'<td><span class="pill" style="background:{VERDICT_COLOR.get(v,"#8A94A3")}">{esc(v)}</span></td></tr>')
        return "".join(out)

    chips = "".join(
        f'<span class="chip"><b>{n}</b> {esc(k)}</span>' for k, n in sorted(by_verdict.items()))
    scans = "".join(
        f'<tr><td class="mono">{esc(s.get("repo"))}</td><td class="mono">{esc((s.get("sha") or "")[:12])}</td>'
        f'<td>{esc(s.get("shards_completed"))}/{esc(s.get("shards_expected"))}</td>'
        f'<td class="mono">{esc(s.get("ts"))}</td></tr>' for s in d["scans"]) or \
        '<tr><td colspan="4" class="empty">no scan recorded — the gate must answer RACE, never PASS</td></tr>'

    gate = ("BLOCK" if unfixed else "PASS") if d["scans"] else "RACE"
    gate_note = {
        "BLOCK": f"{len(unfixed)} verified, unfixed finding(s)",
        "PASS": "scan on record, nothing verified-and-unfixed",
        "RACE": "no scan recorded for any sha — never a silent pass (D22)",
    }[gate]
    gate_color = {"BLOCK": "#B3261E", "PASS": "#2C7A55", "RACE": "#B87406"}[gate]

    warn = ""
    if unjudged:
        warn = (f'<div class="warn"><b>{len(unjudged)} verified finding(s) have no impact review.</b> '
                f'Each would block a merge on the strength of a reproduction alone. '
                f'<code>cm verify</code> proves the described behaviour reproduces — it does not '
                f'adjudicate security impact, and it has returned VERIFIED at 100% confidence on a '
                f'non-vulnerability. See D28.</div>')

    return f"""<!doctype html><meta charset="utf-8"><title>{esc(title)}</title>
<style>
 :root{{--ink:#1B2430;--mut:#5C6879;--hair:#D5DAE1;--bg:#fff;--surf:#F6F8FA}}
 @media(prefers-color-scheme:dark){{:root{{--ink:#E6EBF1;--mut:#98A4B3;--hair:#2A323D;--bg:#0F1319;--surf:#181E27}}}}
 body{{font:14px/1.5 'IBM Plex Sans',system-ui,sans-serif;color:var(--ink);background:var(--bg);margin:0;padding:32px;max-width:1100px}}
 h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:14px;margin:28px 0 8px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut)}}
 .sub{{color:var(--mut);margin-bottom:20px}}
 .gate{{display:inline-block;padding:10px 18px;border-radius:8px;color:#fff;font-weight:600;font-size:18px;background:{gate_color}}}
 .gate-note{{color:var(--mut);margin-left:12px}}
 .chip{{display:inline-block;background:var(--surf);border:1px solid var(--hair);border-radius:14px;padding:3px 11px;margin:3px 4px 3px 0;font-size:12px}}
 table{{border-collapse:collapse;width:100%;margin-top:6px}}
 th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid var(--hair);font-size:12.5px;vertical-align:top}}
 th{{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.06em}}
 .mono{{font-family:'IBM Plex Mono',ui-monospace,monospace;font-size:11.5px}}
 .fp{{color:var(--mut)}}
 .pill{{color:#fff;border-radius:10px;padding:2px 9px;font-size:11px;font-family:ui-monospace,monospace}}
 .empty{{color:var(--mut);font-style:italic}}
 .warn{{background:#FDF3E7;border-left:4px solid #B87406;padding:12px 14px;margin:14px 0;border-radius:0 6px 6px 0;color:#1B2430}}
 .wrap{{overflow-x:auto}}
</style>
<h1>{esc(title)}</h1>
<div class="sub">generated {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M')}Z — the ledger is the only shared state between the developer path and the agents</div>
<div><span class="gate">GATE: {gate}</span><span class="gate-note">{esc(gate_note)}</span></div>
{warn}
<h2>Verdict mix — {len(f)} finding(s)</h2><div>{chips or '<span class="chip">no findings</span>'}</div>
<h2>Blocking a merge right now</h2><div class="wrap"><table>
<tr><th>fingerprint</th><th>sev</th><th>class</th><th>path</th><th>verdict</th></tr>{rows(unfixed)}</table></div>
<h2>All findings</h2><div class="wrap"><table>
<tr><th>fingerprint</th><th>sev</th><th>class</th><th>path</th><th>verdict</th></tr>{rows(f)}</table></div>
<h2>Coverage — what was EXAMINED</h2><div class="wrap"><table>
<tr><th>repo</th><th>sha</th><th>shards</th><th>recorded</th></tr>{scans}</table></div>
<div class="sub" style="margin-top:10px">CM emits no coverage of its own — its <code>file_hashes</code> table is empty after a
completed scan. Without these rows, &ldquo;found nothing&rdquo; and &ldquo;never looked&rdquo; are the same string.</div>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ledger")
    ap.add_argument("-o", "--out", default="ledger-report.html")
    ap.add_argument("--title", default="CodeMender ledger")
    a = ap.parse_args()
    if not os.path.exists(a.ledger):
        raise SystemExit(f"no ledger at {a.ledger}")
    d = load(a.ledger)
    open(a.out, "w").write(render(d, a.title))
    print(f"{len(d['findings'])} finding(s), {len(d['scans'])} scan(s) -> {a.out}")


if __name__ == "__main__":
    main()
