#!/usr/bin/env python3
"""Exporter-computed file-level coverage (Q13 / D55).

CM 0.2.0 exposes NO sink-level coverage (`sinks_enumerated`/`sinks_triaged` do
not exist). So the exporter computes coverage itself from information it already
has: the scan scope, the extension include/exclude filters, and the size limit.

For every file in the scan root it emits: scanned vs skipped, and WHY skipped
(extension / size / not-in-scope). The release gate reads this to distinguish
"CM looked and found nothing" from "CM never looked" — the whole point of
coverage. This is honest and cheap, unlike the sink-level fields the envelope
asked for, which cannot be populated and would gate on two NULLs.
"""
import re
import os, sys, json, hashlib, argparse

def load_config_filters(cfg):
    inc=set(x.lower() for x in cfg.get("include",[]))
    exc=[x.lower() for x in cfg.get("exclude",[])]
    max_kb=cfg.get("max_file_size_kb",500)
    return inc, exc, max_kb

def classify(path, inc, exc, max_kb):
    """IN SCOPE or excluded, and why. Deliberately NOT called "scanned".

    This function simulates the agent's input filters against the tree. It can say
    the file was OFFERED to the agent; it cannot say the agent read it, and CM emits
    nothing that would. Naming the positive case `scanned` is how a reconstruction
    gets read as an observation, which is the whole failure Q13 is about."""
    name=os.path.basename(path).lower()
    ext=os.path.splitext(name)[1]
    if inc and ext not in inc:
        return False,"extension"
    for e in exc:
        if name.endswith(e):
            return False,"exclude-pattern"
    try:
        if os.path.getsize(path) > max_kb*1024:
            return False,"size"
    except OSError:
        return False,"unreadable"
    return True,None

def walk_coverage(root, cfg, observed_paths=None):
    """One row per file: was it in scope, and did CM demonstrably touch it.

    `observed_paths` are paths CM ITSELF referenced (extracted from its state.db).
    They set `observed`, a separate column -- they no longer overwrite the scope
    verdict, because "CM mentioned this file" and "this file passed the filters" are
    different facts and a file can be either without the other."""
    inc,exc,max_kb=load_config_filters(cfg)
    observed_paths=set(observed_paths or [])
    rows=[]
    for r,dirs,files in os.walk(root):
        dirs[:]=[d for d in dirs if d not in (".git","node_modules")]
        for f in files:
            full=os.path.join(r,f); rel=os.path.relpath(full,root)
            in_scope,reason=classify(full,inc,exc,max_kb)
            try: h=hashlib.sha256(open(full,'rb').read()).hexdigest()[:16]
            except OSError: h=None
            rows.append({"path":rel,"in_scope":in_scope,"skip_reason":reason,
                         "observed":(rel in observed_paths or f in observed_paths),
                         "content_hash":h})
    return rows


def observed_from_state_db(state_db):
    """Paths CM referenced in its own run. The only DIRECT evidence available.

    `file_hashes` is the table that would answer this properly and it is empty after
    every completed scan measured -- so this falls back to the file paths on the
    findings themselves. That is a small set by construction: CM names a file only
    when it has something to say about it. It is still worth recording, because one
    observed file is proof the agent reached that far into the tree."""
    import sqlite3
    out=set()
    try:
        db=sqlite3.connect(f"file:{state_db}?mode=ro", uri=True)
        for t,c in (("file_hashes","path"),("findings","file_path")):
            try:
                for (v,) in db.execute(f"SELECT DISTINCT {c} FROM {t}"):
                    if v: out.add(os.path.basename(v)); out.add(v)
            except sqlite3.Error:
                continue
    except sqlite3.Error:
        pass
    return out

def coverage_envelope(root, cfg, agent_version, scanned_at, observed_paths=None,
                      repo=None, sha=None, scope="."):
    rows=walk_coverage(root,cfg,observed_paths)
    in_scope=[r for r in rows if r["in_scope"]]
    excluded=[r for r in rows if not r["in_scope"]]
    return {
        "message_type":"coverage_filelevel",
        "agent_version":agent_version, "scanned_at":scanned_at,
        "repo":repo, "sha":sha, "scope":scope,
        "root":os.path.basename(root.rstrip('/')),
        "files_total":len(rows),
        # in_scope, NOT "scanned". The exporter reconstructs what the agent was
        # OFFERED; CM emits nothing that would let anyone say what it read.
        "files_in_scope":len(in_scope),
        "files_excluded":len(excluded),
        "files_observed":sum(1 for r in rows if r["observed"]),
        "excluded_by":_count(excluded),
        "files":rows,
    }

def _count(rows):
    from collections import Counter
    return dict(Counter(r["skip_reason"] for r in rows))


def emit(root, cfg, agent_version, ts, state_db=None, repo=None, sha=None, scope="."):
    """The exporter entry point: build the envelope, including whatever CM itself
    referenced. Called from the find pod alongside the state.db upload."""
    observed = observed_from_state_db(state_db) if state_db and os.path.exists(state_db) else set()
    return coverage_envelope(root, cfg, agent_version, ts, observed, repo, sha, scope)

def _ver(s):
    """('codemender-0.5.0') -> (0,5,0). None when there is no version in the string.

    A raw string compare was wrong twice over: 'codemender-0.10.0' sorts BELOW
    'codemender-0.5.0' because '1'<'5', and 'codemender-unknown' sorts ABOVE every
    real version because 'u'>'0' -- so an unstamped envelope passed the staleness
    gate as though it came from the newest agent ever built."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(g) for g in m.groups()) if m else None

def gate_stale(envelope, required_agent_version):
    """Release gate check: every scanned file at >= required agent version, and
    no unexplained skips. Returns (ok, reasons)."""
    reasons=[]
    got, want = _ver(envelope.get("agent_version")), _ver(required_agent_version)
    if got is None:
        # Fail CLOSED. An envelope that cannot say which agent produced it is not
        # evidence, and a gate is the wrong place to give it the benefit of the doubt.
        reasons.append(f"coverage agent version unusable: {envelope.get('agent_version')!r}")
    elif want is not None and got < want:
        reasons.append(f"coverage from {envelope['agent_version']} < required {required_agent_version}")
    unexpl=[r["path"] for r in envelope["files"] if not r["in_scope"] and r["skip_reason"] in (None,"unreadable")]
    if unexpl:
        reasons.append(f"{len(unexpl)} file(s) skipped for no valid reason: {unexpl[:3]}")
    return (len(reasons)==0, reasons)

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--include",nargs="*",default=[".js",".ts",".c",".h",".go",".py",".java"])
    ap.add_argument("--exclude",nargs="*",default=[".min.js"])
    ap.add_argument("--max-kb",type=int,default=500)
    ap.add_argument("--agent",default="codemender-unknown")  # never guess a version
    ap.add_argument("--ts",default="2026-08-18T00:00:00Z")
    ap.add_argument("--state-db",help="cm state.db, for the paths CM itself referenced")
    ap.add_argument("--repo"); ap.add_argument("--sha"); ap.add_argument("--scope",default=".")
    ap.add_argument("--out",help="write the envelope here")
    ap.add_argument("--verbose",action="store_true")
    a=ap.parse_args()
    cfg={"include":a.include,"exclude":a.exclude,"max_file_size_kb":a.max_kb}
    env=emit(a.root,cfg,a.agent,a.ts,a.state_db,a.repo,a.sha,a.scope)
    if a.out:
        json.dump(env,open(a.out,"w"))
    print(json.dumps({k:v for k,v in env.items() if k!="files"},indent=1))
    if a.verbose:
        print("\nper-file:")
        for r in env["files"]:
            print(f"  {'in-scope' if r['in_scope'] else 'excluded':9}"
                  f"{'obs' if r['observed'] else '   ':4}{r['skip_reason'] or '':16} {r['path']}")
