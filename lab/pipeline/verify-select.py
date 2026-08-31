#!/usr/bin/env python3
"""Severity-selected verify dispatch — decide WHICH deduped findings to verify.

Stage 3d of the flow. `build_verify_queue` (ledger.py) already drops what must
never be verified: fingerprints already `verified` (the suppression invariant) and
negatives whose attempt budget is spent under the current agent/model. This layer
adds the developer-/operator-facing knob the flow calls for:

    which findings, at what depth, under a cost cap.

  --tier critical,high     verify only these severities (default: all)
  --min-severity high      or a single threshold (critical|high|medium|low)
  --top-n K                after filtering, keep the K most severe (0 = no cap)
  --max-parallelism N      hard cost ceiling on concurrent verifies (default 100)

Selection order is severity desc, then reproductions desc (a finding independent
agents all reported is a stronger candidate). Per-finding verify depth comes from
gate.admit() — severity x diff-reachability x novelty -> attempt budget. Nothing
here re-derives identity or suppression; it only ranks and caps an already-safe
queue. Emits a JSON worklist (--json) for the verify Job, or a human summary.

  verify-select.py --src-root <clone> [--ledger L] [--seed-verified DB] \
                   --tier critical,high --top-n 20 find/*.db
"""
import os, sys, json, argparse, importlib.util

_here = os.path.dirname(os.path.abspath(__file__))
def _load(name, fname):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_here, fname))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
ledger = _load("ledger", "ledger.py")
gate   = _load("gate", "gate.py")
dedup  = ledger.dedup

RANK_LABEL = {4:"critical", 3:"high", 2:"medium", 1:"low", 0:"info"}


def consolidate_fanout(find_dbs, src_root):
    """Consolidate the whole find fan-out JOINTLY (not per-db) so `reproductions`
    counts the distinct pods that independently reported each fingerprint — a real
    confidence signal the ranker uses. Per-db consolidation + dict.update loses it.

    The pod tag is the db's filename stem, which IS the shard index in the pipeline
    (find/<shard>.db). `pods` carries that through to dispatch so a verify pod can
    restore the state.db that actually contains the finding instead of re-running
    find — measured: re-discovery lost 33% of verify pods to not_found."""
    dedup.SRC_ROOT = src_root
    findings = []
    for dbp in find_dbs:
        tag = os.path.splitext(os.path.basename(dbp))[0]
        findings += dedup.load_db(dbp, tag)
    out = {}
    for k, obs in dedup.consolidate(findings).items():
        fp = dedup.fingerprint(k, obs); f0 = obs[0]
        lab, rk = dedup.cluster_severity(obs)
        pods = sorted({o["pod"] for o in obs})
        out[fp] = {"cwe_class": dedup.cluster_class(obs), "enclosing_function": (k[2] if k[0] == "fn" else None),
                   "canonical_path": dedup.relpath(f0["file_path"]),
                   "vuln_id": f0.get("vuln_id"), "title": f0.get("title"),
                   "cwes": sorted({o["vuln_id"] for o in obs if o.get("vuln_id")}),
                   "severity": lab, "severity_rank": rk,
                   "pods": pods, "reproductions": len(pods),
                   "needs_triage": dedup.needs_triage(obs)}
    return out


def select(merged, db, agent, model, tier=None, min_severity=None,
           top_n=0, max_parallelism=100, defer_limit=3, ts=None):
    """merged: {fp: meta}. Returns (dispatch, deferred, suppressed) lists.

    dispatch entries carry the gate's harness + attempt budget so the verify Job
    knows how the class proves (functional exploit vs a non-functional oracle) and
    how many times to retry."""
    # `ts` is the selection's own clock; passing it lets an EXPIRED negative cache
    # re-enter the queue (P6). Without it the TTL is declared and never applied.
    queue, suppressed = ledger.build_verify_queue(db, merged, agent, model, now=ts)

    allow = None
    if tier:
        allow = {t.strip().lower() for t in tier.split(",") if t.strip()}
    floor = dedup.severity_rank(min_severity) if min_severity else None

    passed, deferred = [], []
    for fp, meta, reason in queue:
        sr = meta.get("severity_rank", 2)
        # D24: nothing is excluded forever. A finding skipped `defer_limit` times is
        # force-admitted regardless of tier -- otherwise a --tier setting silently
        # shrinks what is ever checked (config-as-bypass), and CM's noisy severity
        # (measured: 3 of 9 stable fingerprints changed tier between runs) decides
        # by coin flip which real bugs get proven.
        aged = ledger.deferrals_of(db, fp) >= defer_limit
        if aged:
            passed.append((fp, meta, f"{reason} (force-admitted after {defer_limit} deferrals)")); continue
        if allow is not None and RANK_LABEL.get(sr) not in allow:
            deferred.append((fp, meta, f"severity {meta.get('severity')} not in --tier {sorted(allow)}")); continue
        if floor is not None and sr < floor:
            deferred.append((fp, meta, f"severity {meta.get('severity')} below --min-severity {min_severity}")); continue
        passed.append((fp, meta, reason))

    # rank: severity desc, then independent reproductions desc, then fp for stability
    passed.sort(key=lambda t: (-t[1].get("severity_rank", 2),
                               -t[1].get("reproductions", 1), t[0]))

    if top_n and len(passed) > top_n:
        for fp, meta, _ in passed[top_n:]:
            deferred.append((fp, meta, f"beyond --top-n {top_n}"))
        passed = passed[:top_n]
    if len(passed) > max_parallelism:
        for fp, meta, _ in passed[max_parallelism:]:
            deferred.append((fp, meta, f"over --max-parallelism {max_parallelism} (cost cap)"))
        passed = passed[:max_parallelism]

    dispatch = []
    for fp, meta, reason in passed:
        # novel = introduced by this change (absent from base ledger) vs pre-existing.
        # "new"/"retry"/"cache invalid" from build_verify_queue all mean not-yet-verified;
        # only a row already in findings and NOT this run is pre-existing debt. We admit
        # everything the queue passed (it already applied suppression); admit() sets depth.
        ok, attempts, why = gate.admit(meta, diff_reachable=True, novel=True,
                                       severity_rank=meta.get("severity_rank", 2))
        v = gate.class_verifier(meta["cwe_class"])
        dispatch.append({
            "fingerprint": fp, "cwe_class": meta["cwe_class"],
            "severity": meta.get("severity"), "severity_rank": meta.get("severity_rank", 2),
            "reproductions": meta.get("reproductions", 1),
            "enclosing_function": meta.get("enclosing_function"),
            "canonical_path": meta.get("canonical_path"),
            "cwes": meta.get("cwes", []),   # verify pod maps fp -> local finding_id by (path, cwe)
            # the shard whose state.db holds this finding — restored by the verify pod
            # so the finding is not re-discovered (and lost ~30% of the time)
            "shard": (meta.get("pods") or [None])[0],
            "pods": meta.get("pods", []),
            "needs_triage": meta.get("needs_triage", False),
            "harness": v["harness"], "attempts": attempts,
            "queue_reason": reason, "admit_reason": why,
        })
    # persist the deferral so it ages toward force-admission (D24)
    if ts is not None:
        for fp, _meta, _why in deferred:
            ledger.record_deferral(db, fp, ts, meta=_meta,
                                   agent_version=agent, model_version=model)
    return dispatch, deferred, [(fp, meta, r) for fp, meta, r, _poc in suppressed]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("find_dbs", nargs="+")
    ap.add_argument("--src-root", required=True)
    ap.add_argument("--ledger", default=":memory:")
    ap.add_argument("--seed-verified", help="cm state.db whose VERIFIED findings pre-populate the ledger")
    ap.add_argument("--agent", default="codemender-0.2.0")
    ap.add_argument("--model", default="gemini-3")
    ap.add_argument("--ts", default="2026-08-18T00:00:00Z")
    ap.add_argument("--tier", help="comma list e.g. critical,high (default: all)")
    ap.add_argument("--min-severity", choices=["critical","high","medium","low"])
    ap.add_argument("--top-n", type=int, default=0, help="keep the N most severe (0 = no cap)")
    ap.add_argument("--max-parallelism", type=int, default=100, help="cost ceiling (item #2)")
    ap.add_argument("--defer-limit", type=int, default=3,
                    help="force-admit a finding deferred this many times (D24; 0 disables)")
    ap.add_argument("--json", action="store_true", help="emit the dispatch worklist as JSON")
    a = ap.parse_args()

    dedup.SRC_ROOT = a.src_root
    db = ledger.open_ledger(a.ledger)
    if a.seed_verified:
        seed = dedup.load_db(a.seed_verified, "seed")
        for k, obs in dedup.consolidate(seed).items():
            fp = dedup.fingerprint(k, obs); f0 = obs[0]
            verdict = "verified" if any(o.get("status") == "VERIFIED" for o in obs) else "unproven"
            meta = {"cwe_class": dedup.cluster_class(obs), "canonical_path": dedup.relpath(f0["file_path"]), "source": "verify"}
            ledger.ingest(db, fp, meta, verdict, a.agent, a.model, a.ts,
                          poc_uri=("gs://poc/" + fp if verdict == "verified" else None))

    merged = consolidate_fanout(a.find_dbs, a.src_root)

    dispatch, deferred, suppressed = select(
        merged, db, a.agent, a.model, tier=a.tier, min_severity=a.min_severity,
        top_n=a.top_n, max_parallelism=a.max_parallelism,
        defer_limit=(a.defer_limit or 10**9), ts=a.ts)

    if a.json:
        print(json.dumps(dispatch, indent=2)); return

    sel = a.tier or (f">= {a.min_severity}" if a.min_severity else "all severities")
    print(f"consolidated : {len(merged)} fingerprints   selection: {sel}"
          + (f", top-{a.top_n}" if a.top_n else "") + f", cap {a.max_parallelism}")
    print(f"--> DISPATCH : {len(dispatch)}   DEFERRED: {len(deferred)}   SUPPRESSED: {len(suppressed)}\n")
    print("DISPATCH (fan out one verify each, most severe first):")
    for d in dispatch:
        print(f"  {d['fingerprint']:24}{d['severity']:9}{d['cwe_class']:20}"
              f"x{d['reproductions']}  {d['harness']:24} {d['attempts']}x  <- {d['admit_reason']}")
    if deferred:
        print("\nDEFERRED (recorded, not verified this run):")
        for fp, meta, why in deferred:
            print(f"  {fp:24}{str(meta.get('severity')):9}{meta['cwe_class']:20}<- {why}")
    if suppressed:
        print("\nSUPPRESSED (invariant — never re-verified):")
        for fp, meta, why in suppressed:
            print(f"  {fp:24}{str(meta.get('severity')):9}{meta['cwe_class']:20}<- {why}")


if __name__ == "__main__":
    main()
