#!/usr/bin/env python3
"""Close the loop: fold a run's verdicts into the ledger, then answer the gate.

Fixes the gap where the ledger — the linchpin the merge gate reads — was not in
the loop at all: run-twophase used an in-memory SQLite and verdicts landed in a
bucket, so suppression and the gate were proven in principle but never exercised
by the pipeline. That also meant nothing accumulated across runs, which is the one
thing a ~30%-variable detector requires (D16).

Deliberately NOT a Cloud Run service. At this volume a single durable ledger file
plus this step is the efficient answer; Pub/Sub and an ingester service are
deferred until finding volume justifies them (see DECISIONS, minimum core).

Still honours the invariants: the ingester is the sole writer, identity is computed
centrally (never taken from an agent), the fold is monotonic, and a scan-completion
row is recorded so the gate can fail closed (D22).

  ingest-verdicts.py --ledger cm.db --repo <name> --sha <sha> \
      --shards-expected 3 --shards-completed 3 \
      --dispatch dispatch.json --verdicts verify/*.json
"""
import os, sys, json, glob, argparse, importlib.util

_here = os.path.dirname(os.path.abspath(__file__))
_s = importlib.util.spec_from_file_location("ledger", os.path.join(_here, "ledger.py"))
ledger = importlib.util.module_from_spec(_s); _s.loader.exec_module(ledger)

# an agent-reported verdict string -> the ledger's vocabulary. Anything unknown is
# recorded as 'error' (rank 1) rather than silently dropped or trusted.
VERDICT_MAP = {"verified": "verified", "exploit_failed": "exploit_failed",
               "setup_failed": "setup_failed", "not_found": "not_found",
               "timeout": "timeout", "unproven": "unproven", "error": "error"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--shards-expected", type=int, required=True)
    ap.add_argument("--shards-completed", type=int, required=True)
    ap.add_argument("--dispatch", help="dispatch.json — supplies meta for each fingerprint")
    ap.add_argument("--verdicts", nargs="*", default=[], help="verify/*.json envelopes")
    ap.add_argument("--agent", default="codemender-unknown")  # a wrong stamp is
    # worse than an absent one: it attributes results to an agent that never ran
    ap.add_argument("--model", default="gemini-3")
    ap.add_argument("--ts", required=True)
    ap.add_argument("--min-shards", type=int, default=1)
    ap.add_argument("--no-candidates", action="store_true",
                    help="do NOT record dispatched-but-unverified fingerprints as unproven")
    ap.add_argument("--pushed-at", help="RUN.json dispatched_at — the origin for Q8's race")
    ap.add_argument("--coverage", nargs="*", default=[],
                    help="coverage-*.json envelopes from the find shards (Q13/D55)")
    a = ap.parse_args()

    db = ledger.open_ledger(a.ledger)

    meta_by_fp = {}
    if a.dispatch and os.path.exists(a.dispatch):
        for d in json.load(open(a.dispatch)):
            meta_by_fp[d["fingerprint"]] = {
                "cwe_class": d.get("cwe_class"), "enclosing_function": d.get("enclosing_function"),
                "canonical_path": d.get("canonical_path"),
                # verify-select computes severity and the ledger used to discard it
                # here. Nothing downstream could answer "how many CRITICALs are
                # open" -- the first thing anyone asks of the programme.
                "severity": d.get("severity"),
                "repo": a.repo,
                "source": "verify"}

    files = []
    for pat in a.verdicts:
        files.extend(sorted(glob.glob(pat)) if any(c in pat for c in "*?[") else [pat])

    def _algo(fp): return fp.split(":", 1)[0] if ":" in fp else "?"
    cur_algo = ledger.dedup.FP_ALGO
    mismatched = set()

    counts = {}
    for f in files:
        try:
            v = json.load(open(f))
        except Exception as e:
            print(f"  SKIP {f}: {e}"); continue
        fp = v.get("fingerprint")
        if not fp:
            print(f"  SKIP {f}: no fingerprint"); continue
        # An algo bump re-keys every finding (fp2 -> fp3). Ingesting stale-keyed
        # verdicts would quietly create orphan rows the gate can never match, which
        # is exactly the silent cache invalidation the explicit bump exists to
        # prevent. Refuse them loudly instead.
        if _algo(fp) != cur_algo:
            mismatched.add(_algo(fp)); print(f"  REFUSED {os.path.basename(f)}: {fp} is "
                                             f"{_algo(fp)}, ledger is {cur_algo}"); continue
        verdict = VERDICT_MAP.get(v.get("verdict"), "error")
        if fp not in meta_by_fp and a.dispatch:
            print(f"  WARN {fp}: not in dispatch — ingesting without meta")
        meta = dict(meta_by_fp.get(fp, {})); meta["source"] = "verify"
        ledger.ingest(db, fp, meta, verdict, a.agent, a.model, a.ts,
                      poc_uri=(v.get("poc_uri") or None))
        counts[verdict] = counts.get(verdict, 0) + 1

    # Every candidate the fan-out surfaced goes on record as `unproven`, whether or
    # not a verdict came back. Without this a find-only run persists a scan and NO
    # findings, so the ledger cannot answer "what is outstanding on this sha?" --
    # the verify queue is recomputed from scratch every run, and D24's deferral
    # decay has no row to decay, which is the silent permanent drop it exists to
    # prevent. `unproven` is also the honest word: it was found and selected, and
    # nothing has been proven about it either way. It does not block (D22).
    if not a.no_candidates and not mismatched:
        seeded = 0
        for fp, meta in meta_by_fp.items():
            if _algo(fp) != cur_algo:
                continue
            if db.execute("SELECT 1 FROM findings WHERE fingerprint=?", (fp,)).fetchone():
                continue                      # a verdict already spoke for it
            m = dict(meta); m["source"] = "find"
            ledger.ingest(db, fp, m, "unproven", a.agent, a.model, a.ts)
            seeded += 1
        if seeded:
            print(f"recorded {seeded} candidate(s) as unproven (found, not yet verified)")

    # D22: record that lane 3 ran for THIS sha, so absence != clean.
    # If verdicts were REFUSED the results did not actually land, so this run is not
    # a completed scan — recording it as complete would let a broken pipeline read
    # as a clean bill of health, the same fail-open bug D22 exists to close.
    # Q13/D55, WITH TEETH. The coverage table exists to separate "looked and found
    # nothing" from "never looked" -- and until 2026-09-03 nothing consulted it, so
    # the distinction was recorded and then ignored at the only place it matters.
    #
    # Measured twice that day, on two fresh projects: `cm find` never started
    # (`StartSession timed out`), the EXIT trap published the shards anyway -- which
    # is correct, invariant 5 -- the reconciler folded them, and the ledger recorded
    # shards_completed=3 / findings=0. The gate then answered
    #   PASS "scanned (3/3 shards), no verified-unfixed findings"
    # for a commit CodeMender had not read a single file of. That is exactly the
    # confusion this whole design exists to prevent, arriving at the one surface
    # that gates a merge.
    #
    # The test is `in_scope > 0 and observed == 0` across EVERY shard. Not the
    # agent version: on the failed runs the coverage envelope still said
    # codemender-0.5.0, because the binary reports its version fine -- it is the
    # SESSION that dies -- so a version check would have caught nothing.
    # `max` over the shards, not `all`: one shard that genuinely looked is enough to
    # make this a scan, and this clause is aimed at the total outage, which is the
    # case that reads as clean.
    cov_envs = []
    for f in a.coverage:
        try:
            cov_envs.append((f, json.load(open(f))))
        except Exception as e:
            print(f"  coverage: {os.path.basename(f)} unreadable ({e}) — SKIPPED, "
                  f"this shard's files will look uncovered")
    unexamined = False
    if cov_envs:
        cov_in_scope = max(int(e.get("files_in_scope") or 0) for _, e in cov_envs)
        cov_observed = max(int(e.get("files_observed") or 0) for _, e in cov_envs)
        unexamined = cov_in_scope > 0 and cov_observed == 0

    landed = a.shards_completed if not (mismatched or unexamined) else 0
    if mismatched:
        print(f"  scan recorded as INCOMPLETE: {len(files)} verdict(s) refused, none landed")
    if unexamined:
        print(f"  scan recorded as INCOMPLETE: {cov_in_scope} file(s) in scope and "
              f"NOT ONE observed by the agent — nothing examined this sha. The shards "
              f"published (invariant 5) but the agent never read the tree; recording "
              f"this as a completed scan is what let a CodeMender outage answer PASS.")
    ledger.record_scan(db, a.repo, a.sha, a.shards_expected, landed, a.agent, a.ts)

    # Q8/D57: the race, stamped where the facts are. `--pushed-at` comes from the
    # fan-out's RUN.json, which is the only place the developer's push time survives.
    if a.pushed_at:
        ledger.stamp_scan_time(db, a.repo, a.sha, "pushed_at", a.pushed_at)
    # Verdicts are complete when this ingest carried some and none were refused.
    if a.verdicts and not mismatched:
        ledger.stamp_scan_time(db, a.repo, a.sha, "verdicts_complete_at", a.ts)

    # COVERAGE (Q13/D55) — what was EXAMINED, recorded apart from what was FOUND.
    #
    # Shards overlap: each covers its own slice of the tree and they are merged by
    # (path, scope) with `in_scope` winning, because a file one shard excluded and
    # another had in scope WAS in the campaign's scope. `observed` ORs for the same
    # reason -- one shard reaching a file is enough.
    #
    # Recorded even when the scan found nothing. That case is the entire point: "0
    # findings across 24 in-scope files" and "nobody looked" have been the same row
    # count since this design started, and D33's argument for not scanning prod
    # rests on being able to tell them apart.
    if cov_envs:
        merged, scope, cov_agent = {}, ".", a.agent
        for f, env in cov_envs:
            scope = env.get("scope") or scope
            cov_agent = env.get("agent_version") or cov_agent
            for r in env.get("files", []):
                prev = merged.get(r["path"])
                if prev is None:
                    merged[r["path"]] = dict(r)
                else:
                    prev["in_scope"] = prev.get("in_scope") or r.get("in_scope")
                    prev["observed"] = prev.get("observed") or r.get("observed")
                    if prev.get("in_scope"):
                        prev["skip_reason"] = None
        n = ledger.record_coverage(db, a.repo, a.sha, scope, list(merged.values()),
                                   cov_agent, a.ts)
        summ = ledger.coverage_summary(db, a.repo, a.sha, scope)
        print(f"coverage: {n} file(s) recorded — {summ['in_scope']} in scope, "
              f"{summ['observed']} observed by CM, excluded: {summ['excluded_by'] or 'none'}")
    else:
        print("coverage: NONE SUPPLIED — this sha cannot be distinguished from unscanned")

    # Q14/D45: record whether this run's verify stage produced EVIDENCE or only
    # harness failures. `counts` is keyed by the ledger's vocabulary, so the split is
    # simply which verdicts mean "the agent formed an opinion". Only ever recorded
    # when verdict files were actually present -- a find-only run has not failed at
    # verifying, it has not verified, and marking it untrustworthy would make every
    # discovery-only fan-out permanently un-passable.
    if files:
        attempted = sum(c for v, c in counts.items() if v not in ledger.HARNESS_VERDICTS)
        ledger.record_verify_health(db, a.repo, a.sha, len(files), attempted, a.ts)
        if attempted == 0:
            print(f"  *** HARNESS: {len(files)} verdict(s) and NONE formed an opinion "
                  f"— this run is not evidence, the gate will not PASS on it ***")

    if mismatched:
        print(f"\n*** {len(mismatched)} stale fingerprint algo(s) refused: {sorted(mismatched)} "
              f"— re-key or re-run under {cur_algo} (DECISIONS: bump => explicit re-key) ***\n")
    print(f"ingested {sum(counts.values())} of {len(files)} verdict(s): " + ("  ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"))
    rows = db.execute("SELECT verdict, COUNT(*) c FROM findings GROUP BY verdict").fetchall()
    print("ledger findings: " + "  ".join(f"{r['verdict']}={r['c']}" for r in rows))

    action, reason, detail = ledger.merge_gate(db, a.repo, a.sha, min_shards=a.min_shards,
                                               now=a.ts)
    print(f"\nMERGE GATE [{a.repo}@{a.sha[:12]}]: {action}\n  {reason}")
    for b in detail["blocking"]:
        print(f"    BLOCKING {b['fingerprint']}  {b['cwe_class']}  {b['canonical_path']}"
              + (f"  poc={b['poc_uri']}" if b.get("poc_uri") else "  poc=MISSING"))
    for b in detail.get("accepted", []):
        acc = b["acceptance"]
        print(f"    ACCEPTED {b['fingerprint']}  {b['cwe_class']}  "
              f"owner={acc['owner']} ({acc['reason_code']}) until {acc['expires_at']}  {acc['pr_url']}")
    # exit code is the gate decision: 0 pass, 1 block, 2 race (P1 policy decides).
    # RISK_ACCEPTED exits 0 -- it is a PASSING gate -- but it is a distinct action
    # in the event stream, because "shipped clean" and "shipped with a named owner
    # holding the risk" must be countable apart (D53).
    sys.exit({"PASS": 0, "RISK_ACCEPTED": 0, "BLOCK": 1, "RACE": 2}[action])


if __name__ == "__main__":
    main()
