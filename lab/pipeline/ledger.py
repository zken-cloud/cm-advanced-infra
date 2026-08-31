#!/usr/bin/env python3
"""Central ledger + verify-queue builder.

Enforces the invariant: NEVER VERIFY A FINDING TWICE IF IT IS ALREADY VERIFIED.

Before Phase-2 fan-out, each consolidated fingerprint is checked against the
ledger. A fingerprint that already holds a `verified` verdict is suppressed — the
merge gate reads that verdict, so re-running the 2-minute verify is pure waste.

The suppression is NOT symmetric (design invariants D4/D6/D8):
  - `verified`  is TERMINAL  → suppress forever (until the AST hash changes and it
                               re-keys to a new fingerprint).
  - `unproven`/`exploit_failed`/`timeout` is NOT terminal → verify is ~50%
    non-deterministic (measured), so a negative is a coin flip. Retry up to
    max_attempts, THEN negative-cache — and even then re-open on an agent/model
    version bump, because a stronger agent may succeed where an older one failed.

Identity comes from consolidate-dedup.py (path|enclosing_function; fp3, no CWE).
This is the sole component that decides what gets the expensive stage.
"""
import sqlite3, sys, os, time, importlib.util

# reuse the *tested* fingerprint logic rather than reimplementing it
_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("dedup", os.path.join(_here, "consolidate-dedup.py"))
dedup = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(dedup)

SEV_RANK = {"CRITICAL":4, "HIGH":3, "MEDIUM":2, "LOW":1, "INFO":0, None:-1, "":-1}
VERDICT_RANK = {"verified":3, "exploit_failed":2, "unproven":2, "timeout":1, "error":1, "crash":1,
                "setup_failed":1, "not_found":0, None:0, "":0}
# stamp the algo the fingerprints were ACTUALLY computed with -- a stale constant here
# silently mislabels the cache and defeats the explicit-rekey rule.
FP_ALGO = dedup.FP_ALGO

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings(
  fingerprint TEXT PRIMARY KEY,
  cwe_class TEXT, enclosing_function TEXT, canonical_path TEXT,
  severity TEXT,                 -- computed by verify-select, and DROPPED here until
                                 -- 2026-08-24. "How many CRITICALs are open" is the
                                 -- first question anyone asks and it was unanswerable.
  repo TEXT,                     -- `scans` had it, `findings` did not, so nothing
                                 -- could be attributed once a second repo appeared.
  verdict TEXT DEFAULT 'unproven',
  attempts INTEGER DEFAULT 0,
  deferrals INTEGER DEFAULT 0,   -- D24: times selection skipped it; forces admission
  fixed_at TEXT,                 -- set when a fix lands; until then a verified finding blocks
  agent_version TEXT, model_version TEXT, fp_algo TEXT,
  poc_uri TEXT, first_seen TEXT, last_updated TEXT
);
CREATE TABLE IF NOT EXISTS observations(  -- append-only, one row per agent run
  obs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT, source TEXT, verdict TEXT,
  agent_version TEXT, model_version TEXT, created_at TEXT
);
-- D22: per-sha scan completion. WITHOUT this, "no findings" and "never scanned"
-- are the same row-count (zero) and the gate fails OPEN.
CREATE TABLE IF NOT EXISTS scans(
  repo TEXT, sha TEXT, shards_expected INTEGER, shards_completed INTEGER,
  agent_version TEXT, completed_at TEXT,
  PRIMARY KEY (repo, sha)
);
-- P2/D53: an accepted risk. The ONLY way a verified, unfixed finding may ship, and
-- it is a row, not a conversation. A hard block cannot be queried -- the answer is
-- always "nothing shipped", right up until someone bypasses it in a way that leaves
-- no trace. This table is what makes "what shipped with known verified bugs, who
-- signed, and is it still open?" a question with an answer.
--
-- Append-only: a superseded acceptance is a new row, never an UPDATE. Whoever asks
-- later what the risk position was on a given date needs the row that was live then,
-- not the row that survived.
CREATE TABLE IF NOT EXISTS risk_acceptances(
  acceptance_id INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT NOT NULL,
  repo TEXT NOT NULL,
  scope TEXT NOT NULL,           -- 'trunk' or a release tag; never blanket
  reason_code TEXT NOT NULL,     -- from RISK_REASONS: greppable, so the rate per
                                 -- category is a quality signal about the detector
  reason_text TEXT,
  owner TEXT NOT NULL,           -- the accountable human, by handle
  approved_by TEXT NOT NULL,     -- who approved the PR; MUST differ from the author
  pr_url TEXT NOT NULL,          -- the audit trail: review, discussion, timestamps
  expires_at TEXT NOT NULL,      -- mandatory. An acceptance with no expiry is a
                                 -- silent policy change, not a decision
  revoked_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_risk_fp ON risk_acceptances(fingerprint, repo);
-- Q13/D55: what was EXAMINED, as distinct from what was FOUND. Without it,
-- "CM looked and found nothing" and "CM never looked" are the same zero rows, and
-- D33's argument for not scanning prod -- that trunk's history already covers it --
-- rests on inference rather than evidence.
--
-- THE HONEST DISTINCTION, and the reason this table has two columns instead of one:
--
--   in_scope  the file was inside the campaign's scope, passed the extension/size
--             filters, and its shard completed. RECONSTRUCTED by the exporter from
--             the scan config and the tree. It says the agent was OFFERED the file.
--   observed  CM demonstrably touched it -- something in its state.db references
--             this path. Rare, because CM only mentions files it has something to
--             say about.
--
-- `in_scope` is not "examined" and must never be reported as it. CM emits no
-- coverage of its own (`file_hashes` is empty after every completed scan measured),
-- so "the agent read this file and concluded it was clean" is NOT KNOWABLE today
-- and no column here claims it. What this does close is the much larger gap: a file
-- with no row at all was never in any campaign's scope, and that is now visible
-- instead of indistinguishable from clean.
--
-- Keyed on (repo, sha, path, scope). Scope is part of the key because a sliced scan
-- misses off-chain bugs in files it fully contains (EXPERIMENTS, "AST slicing trades
-- breadth for depth", p=0.0079) -- so "covered under scope=src/api" is a different
-- fact from "covered under scope=.".
CREATE TABLE IF NOT EXISTS coverage(
  repo TEXT NOT NULL, sha TEXT NOT NULL, canonical_path TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT '.',
  in_scope INTEGER NOT NULL,
  skip_reason TEXT,
  observed INTEGER NOT NULL DEFAULT 0,
  content_hash TEXT,
  agent_version TEXT, examined_at TEXT NOT NULL,
  PRIMARY KEY (repo, sha, canonical_path, scope)
);
CREATE INDEX IF NOT EXISTS ix_cov_path ON coverage(repo, canonical_path, examined_at);
-- P4/D58: fix PRs opened against a team, and what became of them.
--
-- The rate limit is the obvious half and the less useful one. The metric that
-- actually says whether the programme is working is the ACCEPTANCE RATE: a team
-- merging 9 of 10 can take more; a team closing 7 of 10 is being handed patches it
-- does not want, and raising the limit would make that worse rather than better.
-- Volume is the lever, acceptance is the signal, and a limit set without the signal
-- is a guess with a number on it.
CREATE TABLE IF NOT EXISTS patch_prs(
  repo TEXT NOT NULL, team TEXT NOT NULL, fingerprint TEXT NOT NULL,
  pr_url TEXT NOT NULL PRIMARY KEY,
  opened_at TEXT NOT NULL,
  outcome TEXT NOT NULL DEFAULT 'open',   -- open | merged | closed
  closed_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_patch_team ON patch_prs(repo, team, opened_at);
"""

# P4: fix PRs per team per week. Deliberately low. The failure this prevents is not
# load, it is ATTENTION: above a handful a week the reviews stop being reviews, and a
# rubber-stamped security patch is worse than no patch because it also carries
# authority. Raise it only when the acceptance rate says the team wants more.
PATCH_PR_LIMIT_PER_WEEK = 3

# How old a campaign may be and still count as evidence that a file was covered.
# Q13 asked for this number and the design had none. 90 days is a deliberate choice,
# not a measurement: it is one quarter, it is the same horizon as a risk acceptance
# (D53), and a file whose last covering campaign predates the current agent version
# is stale for a better reason than the clock anyway -- see `covering_campaign`.
COVERAGE_HORIZON_DAYS = 90

# Structured, not free text. A reason you can group by turns "we accepted 40 risks"
# into "31 of them were `no-attacker`, which means selection is wrong, not the fix
# queue" (Q11).
RISK_REASONS = {
    "no-attacker":      "no attacker can reach this path in any deployed configuration",
    "fails-closed":     "the failure mode is denial, not compromise",
    "config-only":      "not exploitable under our configuration, and the config is enforced",
    "already-mitigated": "a compensating control already blocks exploitation",
    "accepted-cost":    "real and unmitigated; the business is accepting it, knowingly",
}

# Columns added after ledgers existed in the wild. CREATE TABLE IF NOT EXISTS is a
# no-op on an existing table, so a plain schema bump would leave old ledgers silently
# missing the column and every downstream query returning NULL.
_ADDED = [("findings", "severity", "TEXT"), ("findings", "repo", "TEXT"),
          ("scans", "verify_dispatched", "INTEGER"), ("scans", "verify_attempted", "INTEGER"),
          # Q8: the race, made measurable. `pushed_at` comes from the fan-out's
          # RUN.json; `verdicts_complete_at` is stamped when the verify fold lands;
          # `merge_attempted_at` when the gate first runs for this sha. Three columns
          # because the question -- do verdicts beat merges? -- is a comparison of
          # two durations from one origin, and until now none of the three was kept.
          ("scans", "pushed_at", "TEXT"),
          ("scans", "verdicts_complete_at", "TEXT"),
          ("scans", "merge_attempted_at", "TEXT")]


def open_ledger(path):
    db = sqlite3.connect(path); db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    for table, col, typ in _ADDED:
        if col not in {r[1] for r in db.execute(f"PRAGMA table_info({table})")}:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
    db.commit()
    return db

def _now(ts): return ts  # caller passes a timestamp (no wall-clock dependence)

def ingest(db, fp, meta, verdict, agent_version, model_version, ts, poc_uri=None):
    """Append an observation, then monotonic-fold the finding verdict.
    verified > unproven/exploit_failed > error. One exploit proves real; N
    timeouts never prove not-real."""
    db.execute("INSERT INTO observations(fingerprint,source,verdict,agent_version,model_version,created_at) VALUES(?,?,?,?,?,?)",
               (fp, meta.get("source","find"), verdict, agent_version, model_version, ts))
    row = db.execute("SELECT verdict,attempts,severity FROM findings WHERE fingerprint=?", (fp,)).fetchone()
    is_attempt = 1 if verdict in ("verified","exploit_failed","unproven","timeout","error","crash") and meta.get("source")=="verify" else 0
    sev = (meta.get("severity") or None)
    if row is None:
        db.execute("""INSERT INTO findings(fingerprint,cwe_class,enclosing_function,canonical_path,
                      severity,repo,verdict,attempts,agent_version,model_version,fp_algo,poc_uri,
                      first_seen,last_updated)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (fp, meta.get("cwe_class"), meta.get("enclosing_function"), meta.get("canonical_path"),
                    sev, meta.get("repo"),
                    verdict, is_attempt, agent_version, model_version, FP_ALGO, poc_uri, ts, ts))
    else:
        new_verdict = verdict if VERDICT_RANK[verdict] > VERDICT_RANK[row["verdict"]] else row["verdict"]
        # Severity folds UPWARD only, like the verdict. A later run relabelling a
        # CRITICAL as MEDIUM must not quietly lower the risk on record -- the
        # relabel is an observation, not a correction, and observations keeps it.
        cur_sev = row["severity"]
        new_sev = sev if SEV_RANK.get(sev, -1) > SEV_RANK.get(cur_sev, -1) else cur_sev
        db.execute("""UPDATE findings SET verdict=?, attempts=attempts+?, agent_version=?, model_version=?,
                      severity=?, repo=COALESCE(repo,?), poc_uri=COALESCE(?,poc_uri),
                      last_updated=? WHERE fingerprint=?""",
                   (new_verdict, is_attempt, agent_version, model_version, new_sev,
                    meta.get("repo"), poc_uri, ts, fp))
    db.commit()

# ---- D22: the merge gate. Two clauses; absence of a verdict is not a pass. ----
def record_scan(db, repo, sha, shards_expected, shards_completed, agent_version, ts):
    """Called once lane 3 finishes. Partial completion is recorded as partial."""
    db.execute("""INSERT INTO scans(repo,sha,shards_expected,shards_completed,agent_version,completed_at)
                  VALUES(?,?,?,?,?,?)
                  ON CONFLICT(repo,sha) DO UPDATE SET
                    shards_completed=MAX(scans.shards_completed, EXCLUDED.shards_completed),
                    shards_expected=EXCLUDED.shards_expected,
                    agent_version=EXCLUDED.agent_version, completed_at=EXCLUDED.completed_at""",
               (repo, sha, shards_expected, shards_completed, agent_version, ts))
    db.commit()


# Q14/D45. A verdict either reflects the agent forming an OPINION about
# exploitability, or it reflects the harness failing to get that far. Only the first
# kind is evidence. Splitting them is what lets a run say "I examined this and found
# nothing exploitable" without it being confused for "I never managed to look".
HARNESS_VERDICTS = {"setup_failed", "not_found", "terminated", "error", "crash"}


def record_verify_health(db, repo, sha, dispatched, attempted, ts):
    """How many verify pods were asked for, and how many formed an opinion."""
    db.execute("""INSERT INTO scans(repo,sha,shards_expected,shards_completed,
                                    agent_version,completed_at,
                                    verify_dispatched,verify_attempted)
                  VALUES(?,?,0,0,'',?,?,?)
                  ON CONFLICT(repo,sha) DO UPDATE SET
                    verify_dispatched=EXCLUDED.verify_dispatched,
                    verify_attempted=EXCLUDED.verify_attempted""",
               (repo, sha, ts, dispatched, attempted))
    db.commit()


def verify_trustworthy(db, repo, sha):
    """False when verify was dispatched and NOT ONE pod formed an opinion.

    This is the hole Q14 named. The merge gate is `scan_complete AND no
    verified-unfixed`, and a run whose every pod died in setup satisfies both: the
    find shards landed, so the scan is complete, and nothing was verified, so there
    is nothing to block on. The gate says PASS on a run that tested NOTHING.

    Measured 2026-08-25: a fan-out returned Complete 6/6 with every verdict
    setup_failed. Pods succeeded, verdicts published, PoCs banked, Job green -- and
    zero verification had happened. Only the aggregate was wrong, and nothing looked
    at the aggregate.

    Deliberately not "alarm if ANY pod failed setup". A partly-failed run still
    produced real evidence, and invariant 6 already stops the failed half from
    poisoning anything: no attempts consumed, no cached negatives. The untrustworthy
    case is the total one -- nobody looked, so the run's silence means nothing.
    """
    r = db.execute("""SELECT verify_dispatched, verify_attempted FROM scans
                      WHERE repo=? AND sha=?""", (repo, sha)).fetchone()
    if r is None or r["verify_dispatched"] is None:
        return True, "no verify health recorded (pre-D45 scan)"
    d, a = r["verify_dispatched"] or 0, r["verify_attempted"] or 0
    if d > 0 and a == 0:
        return False, f"verify dispatched {d} pod(s) and none formed an opinion — harness failure, not evidence"
    return True, f"{a}/{d} verify pod(s) formed an opinion"


def scan_complete(db, repo, sha, min_shards=1):
    """True only if lane 3 demonstrably ran for THIS sha and enough shards landed."""
    r = db.execute("SELECT shards_expected,shards_completed FROM scans WHERE repo=? AND sha=?",
                   (repo, sha)).fetchone()
    if r is None:
        return False, "no scan recorded for this sha"
    if r["shards_completed"] < max(1, min_shards):
        return False, f"only {r['shards_completed']}/{r['shards_expected']} shards completed"
    return True, f"{r['shards_completed']}/{r['shards_expected']} shards"


def mark_fixed(db, fp, ts):
    db.execute("UPDATE findings SET fixed_at=?, last_updated=? WHERE fingerprint=?", (ts, ts, fp))
    db.commit()


def active_acceptance(db, fingerprint, repo, now, scope=None):
    """The signed acceptance covering this finding right now, or None (D53).

    Expiry and revocation are evaluated HERE, at lookup, rather than by a sweeper.
    A sweeper leaves a window in which a lapsed row still says accepted because
    nothing has run yet, and that window is exactly when nobody is looking.

    Lives in ledger.py, not risk-accept.py, because it is a ledger query and
    risk-accept.py already imports this module. Two copies of one truth is the bug
    that left four oracle routes unreachable (D47)."""
    if not now:
        return None
    try:
        rows = db.execute("""SELECT * FROM risk_acceptances
                             WHERE fingerprint=? AND repo=? AND revoked_at IS NULL
                             ORDER BY acceptance_id DESC""", (fingerprint, repo)).fetchall()
    except sqlite3.OperationalError as e:
        # A ledger written before this table existed. `open_ledger` migrates it, but
        # the GATE opens the ledger READ-ONLY (invariant 3: it may not write), so it
        # cannot migrate and will meet the old schema until the next ingest.
        #
        # Absent table == no acceptances, which is the CONSERVATIVE reading: an
        # acceptance can only ever make the gate more permissive, so treating it as
        # missing biases towards BLOCK. Without this the gate raised, every check
        # returned ERROR, and the only developer-facing control was down until an
        # ingest happened to run.
        #
        # Deliberately narrow: any other OperationalError still propagates and still
        # fails closed. "The table is not there yet" and "the ledger is corrupt" are
        # different facts and must not share a branch.
        if "no such table" not in str(e):
            raise
        return None
    for r in rows:
        if r["expires_at"][:10] < now[:10]:
            continue
        if scope and r["scope"] not in (scope, "trunk"):
            continue
        return dict(r)
    return None


def merge_gate(db, repo, sha, min_shards=1, now=None):
    """THE only developer-facing check (D1/D22). Returns (action, reason, details).

        PASS           <=> scan_complete(sha) AND no verified-and-unfixed finding
        RISK_ACCEPTED  <=  every blocker is covered by a signed acceptance (D53)
        BLOCK          <=  a verified, unfixed, unaccepted finding exists
        RACE           <=  no/partial scan for this sha -> the P1 race policy decides,
                           NEVER a silent pass. This is the fail-closed clause: a lost
                           webhook or a dead job must not look like a clean bill of
                           health.

    `now` is an ISO date supplied by the caller — this module takes no wall clock, so
    a gate decision is reproducible from the ledger plus a date. WITHOUT it no
    acceptance is honoured and a covered finding still BLOCKS: "cannot evaluate the
    expiry" must fail towards blocking, never towards shipping.

    Deliberately a point lookup — no agent, single-digit ms. Consulting acceptances
    keeps it one: an indexed read per blocker, and there are rarely any.

    RISK_ACCEPTED IS NOT PASS. It is a passing gate and a different row, because
    "shipped clean" and "shipped with a named owner holding the risk" have to be
    countable apart, or the question D53 exists to answer has no answer."""
    all_blocking = [dict(r) for r in db.execute(
        "SELECT fingerprint,cwe_class,canonical_path,poc_uri FROM findings "
        "WHERE verdict='verified' AND fixed_at IS NULL")]
    blocking, accepted = [], []
    for b in all_blocking:
        acc = active_acceptance(db, b["fingerprint"], repo, now)
        if acc:
            accepted.append({**b, "acceptance": acc})
        else:
            blocking.append(b)
    ok, why = scan_complete(db, repo, sha, min_shards)
    if not ok:
        # report what we DO know, but the verdict is unknown-not-clean
        return ("RACE", f"scan incomplete: {why} — routes to P1 race policy, never PASS",
                {"blocking": blocking, "accepted": accepted, "scan": why})
    # BLOCK is computed from evidence and is trustworthy even from a broken run: a
    # verified finding with a working exploit does not stop being real because other
    # pods failed. So check harness health only on the path that would otherwise
    # PASS -- a clean answer is only worth as much as the run behind it (Q14/D45).
    if not blocking:
        healthy, vwhy = verify_trustworthy(db, repo, sha)
        if not healthy:
            return ("RACE", f"scan complete but {vwhy} — a run that verified nothing "
                            f"is not a clean bill of health",
                    {"blocking": [], "accepted": accepted, "scan": why, "verify": vwhy})
    if blocking:
        return ("BLOCK", f"{len(blocking)} verified, unfixed finding(s)",
                {"blocking": blocking, "accepted": accepted, "scan": why})
    if accepted:
        who = ", ".join(f"{a['acceptance']['owner']} until {a['acceptance']['expires_at']}"
                        for a in accepted)
        return ("RISK_ACCEPTED",
                f"scanned ({why}); {len(accepted)} verified finding(s) shipping under "
                f"signed acceptance — {who}",
                {"blocking": [], "accepted": accepted, "scan": why})
    return ("PASS", f"scanned ({why}), no verified-unfixed findings",
            {"blocking": [], "accepted": [], "scan": why})


# ---- P4/D58: patch volume, and the acceptance rate that says whether it is right ----
def record_patch_pr(db, repo, team, fingerprint, pr_url, opened_at):
    db.execute("""INSERT OR IGNORE INTO patch_prs(repo,team,fingerprint,pr_url,opened_at)
                  VALUES(?,?,?,?,?)""", (repo, team, fingerprint, pr_url, opened_at))
    db.commit()


def close_patch_pr(db, pr_url, outcome, closed_at):
    if outcome not in ("merged", "closed"):
        raise ValueError(f"outcome must be merged|closed, not {outcome!r}")
    db.execute("UPDATE patch_prs SET outcome=?, closed_at=? WHERE pr_url=?",
               (outcome, closed_at, pr_url))
    db.commit()


def patch_acceptance(db, repo, team=None, since=None):
    """merged / (merged + closed). `open` is excluded: a PR nobody has decided on is
    not evidence either way, and counting it as a rejection would make a slow reviewer
    look like an unwilling one."""
    q = "SELECT outcome, count(*) n FROM patch_prs WHERE repo=?"
    args = [repo]
    if team:
        q += " AND team=?"; args.append(team)
    if since:
        q += " AND opened_at>=?"; args.append(since)
    counts = {r["outcome"]: r["n"] for r in db.execute(q + " GROUP BY outcome", args)}
    merged, closed = counts.get("merged", 0), counts.get("closed", 0)
    decided = merged + closed
    return {"merged": merged, "closed": closed, "open": counts.get("open", 0),
            "decided": decided,
            "acceptance_rate": (merged / decided) if decided else None}


def patch_budget(db, repo, team, now, window_days=7, limit=None):
    """May another fix PR be opened for this team right now?

    Returns the decision AND the acceptance rate, together, on purpose: the number
    that says whether the limit is set correctly should never be a separate lookup
    someone can skip."""
    lim = PATCH_PR_LIMIT_PER_WEEK if limit is None else limit
    rows = db.execute("SELECT opened_at FROM patch_prs WHERE repo=? AND team=?",
                      (repo, team)).fetchall()
    recent = [r for r in rows if _days_apart(r["opened_at"], now) < window_days]
    acc = patch_acceptance(db, repo, team)
    over = len(recent) >= lim
    if over:
        why = (f"{len(recent)} fix PR(s) opened in the last {window_days}d, limit {lim} — "
               f"queue this one rather than opening it")
    else:
        why = f"{len(recent)}/{lim} opened in the last {window_days}d"
    if acc["acceptance_rate"] is not None and acc["acceptance_rate"] < 0.5 and acc["decided"] >= 4:
        why += (f". WARNING: acceptance {acc['acceptance_rate']:.0%} over {acc['decided']} "
                f"decided — this team is closing more patches than it merges, which is "
                f"a selection problem, not a throughput one")
    return {"allowed": not over, "opened_in_window": len(recent), "limit": lim,
            "reason": why, **acc}


# ---- Q8/D57: is the async model actually async, or is it blocking with extra steps? ----
def stamp_scan_time(db, repo, sha, column, ts, first_only=True):
    """Record one of the race timestamps. `first_only` keeps the EARLIEST, because
    the question is when the developer first met the gate, not the last time CI ran.

    A no-op when the row does not exist yet: the scan row is created by the fold, and
    a gate check that arrives first is exactly the race being measured -- it must not
    invent a scan that has not happened."""
    if column not in ("pushed_at", "verdicts_complete_at", "merge_attempted_at"):
        raise ValueError(f"not a race column: {column}")
    row = db.execute("SELECT * FROM scans WHERE repo=? AND sha=?", (repo, sha)).fetchone()
    if row is None:
        return False
    if first_only and row[column]:
        return False
    db.execute(f"UPDATE scans SET {column}=? WHERE repo=? AND sha=?", (ts, repo, sha))
    db.commit()
    return True


def race_latencies(db, repo=None):
    """Per sha: push->verdicts and push->merge, in seconds. Q8's raw material.

    Rows missing a timestamp are returned with None rather than skipped. A sha whose
    verdicts never completed is the most interesting row in the table and dropping it
    would bias the very distribution this exists to measure."""
    from datetime import datetime

    def _p(v):
        if not v:
            return None
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None

    q = "SELECT * FROM scans" + (" WHERE repo=?" if repo else "")
    out = []
    for r in db.execute(q, (repo,) if repo else ()):
        pushed, done, merged = _p(r["pushed_at"]), _p(r["verdicts_complete_at"]), _p(r["merge_attempted_at"])
        out.append({
            "repo": r["repo"], "sha": r["sha"],
            "push_to_verdicts_s": (done - pushed).total_seconds() if pushed and done else None,
            "push_to_merge_s": (merged - pushed).total_seconds() if pushed and merged else None,
            # The whole question, per sha. True means the developer waited.
            "verdicts_beat_merge": (None if not (done and merged) else done <= merged),
        })
    return out


def race_summary(db, repo=None):
    """p50/p90 of both durations, and how often verdicts won.

    P1(a) -- block and wait -- costs nothing if verdicts almost always land first,
    and is a blocking CI stage wearing a ledger's clothes if they do not. This is the
    number that decides which."""
    rows = race_latencies(db, repo)

    def pct(vals, p):
        vals = sorted(v for v in vals if v is not None)
        if not vals:
            return None
        return vals[min(len(vals) - 1, int(round((p / 100) * (len(vals) - 1))))]

    v = [r["push_to_verdicts_s"] for r in rows]
    m = [r["push_to_merge_s"] for r in rows]
    decided = [r["verdicts_beat_merge"] for r in rows if r["verdicts_beat_merge"] is not None]
    return {
        "n_scans": len(rows),
        "n_measurable": len(decided),
        "p50_push_to_verdicts_s": pct(v, 50), "p90_push_to_verdicts_s": pct(v, 90),
        "p50_push_to_merge_s": pct(m, 50), "p90_push_to_merge_s": pct(m, 90),
        "verdicts_beat_merge_rate": (sum(decided) / len(decided)) if decided else None,
        # Named so nobody reads a small n as a distribution.
        "verdicts_never_completed": sum(1 for r in rows if r["push_to_verdicts_s"] is None),
    }


# ---- Q13/D55: coverage — what was examined, separately from what was found ----
def record_coverage(db, repo, sha, scope, rows, agent_version, ts):
    """Persist one campaign's coverage. Idempotent per (repo, sha, path, scope).

    REPLACE rather than IGNORE: a re-run of the same campaign with a wider scope or
    a newer agent should overwrite, and re-running the exporter must not silently
    keep the first answer."""
    db.executemany(
        """INSERT OR REPLACE INTO coverage(repo,sha,canonical_path,scope,in_scope,
           skip_reason,observed,content_hash,agent_version,examined_at)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        [(repo, sha, r["path"], scope, 1 if r.get("in_scope") else 0,
          r.get("skip_reason"), 1 if r.get("observed") else 0, r.get("content_hash"),
          agent_version, ts) for r in rows])
    db.commit()
    return len(rows)


def covering_campaign(db, repo, path, now, horizon_days=None, agent_version=None):
    """The most recent campaign that had `path` in scope, or None.

    Two ways a covering campaign stops counting, and the second matters more:

      * AGE. Older than the horizon. A clock is a weak proxy, which is why it is the
        backstop and not the primary rule.
      * AGENT VERSION. Coverage by an older agent is not evidence about a newer one,
        for exactly the reason the negative cache is version-scoped (D8): a better
        detector may find what the old one walked past. Pass `agent_version` to
        require coverage at or above it.

    Returns the row so the caller can say WHICH campaign, not merely that one exists.
    "Covered" with no citation is the inference this table was built to replace."""
    horizon = COVERAGE_HORIZON_DAYS if horizon_days is None else horizon_days
    rows = db.execute(
        """SELECT * FROM coverage
           WHERE repo=? AND canonical_path=? AND in_scope=1
           ORDER BY examined_at DESC""", (repo, path)).fetchall()
    for r in rows:
        if agent_version and (r["agent_version"] or "") < agent_version:
            continue
        if horizon is not None and _days_apart(r["examined_at"], now) > horizon:
            continue
        return dict(r)
    return None


def _days_apart(a, b):
    from datetime import date
    return abs((date.fromisoformat(b[:10]) - date.fromisoformat(a[:10])).days)


def exposure_register(db, repo, paths, now, horizon_days=None, agent_version=None):
    """Files running somewhere with no covering campaign in the ledger.

    Q13's third sub-question: under the design as it was, such a file was invisible —
    neither a finding nor a drift-set member, just absent. Absent is what "never
    scanned" and "scanned and clean" both looked like. Each entry carries WHY it
    does not count: never covered at all, aged out, or covered only by an agent
    older than the one we now require."""
    out = []
    for p in paths:
        hit = covering_campaign(db, repo, p, now, horizon_days, agent_version)
        if hit:
            continue
        ever = db.execute(
            """SELECT * FROM coverage WHERE repo=? AND canonical_path=? AND in_scope=1
               ORDER BY examined_at DESC LIMIT 1""", (repo, p)).fetchone()
        if ever is None:
            reason, last = "never in any campaign's scope", None
        elif agent_version and (ever["agent_version"] or "") < agent_version:
            reason = f"last covered by {ever['agent_version']}, older than required {agent_version}"
            last = ever["examined_at"]
        else:
            reason = f"last covered {_days_apart(ever['examined_at'], now)} days ago, past the horizon"
            last = ever["examined_at"]
        out.append({"path": p, "reason": reason, "last_covered": last})
    return out


def coverage_summary(db, repo, sha, scope="."):
    """One campaign's shape, for the report. `observed` is deliberately reported
    apart from `in_scope`: conflating them is the overstatement this exists to
    prevent."""
    r = db.execute(
        """SELECT count(*) total, sum(in_scope) in_scope, sum(observed) observed
           FROM coverage WHERE repo=? AND sha=? AND scope=?""", (repo, sha, scope)).fetchone()
    skips = {row["skip_reason"]: row["n"] for row in db.execute(
        """SELECT skip_reason, count(*) n FROM coverage
           WHERE repo=? AND sha=? AND scope=? AND in_scope=0
           GROUP BY skip_reason""", (repo, sha, scope))}
    return {"files_total": r["total"] or 0, "in_scope": r["in_scope"] or 0,
            "observed": r["observed"] or 0, "excluded_by": skips}


# ---- D24: a deferred finding must decay back into the queue, never vanish ----
def record_deferral(db, fp, ts, meta=None, agent_version=None, model_version=None):
    """A deferred finding must be PERSISTED, not merely counted — otherwise a
    first-time finding that selection skips leaves no row, the counter updates
    nothing, and it is silently dropped forever (D24). Recording it as an
    observation with source='select' also keeps it an owned, visible risk without
    consuming any verify attempt budget."""
    row = db.execute("SELECT 1 FROM findings WHERE fingerprint=?", (fp,)).fetchone()
    if row is None:
        m = dict(meta or {}); m["source"] = "select"
        ingest(db, fp, m, "unproven", agent_version, model_version, ts)
    db.execute("UPDATE findings SET deferrals=deferrals+1, last_updated=? WHERE fingerprint=?", (ts, fp))
    db.commit()


def deferrals_of(db, fp):
    r = db.execute("SELECT deferrals FROM findings WHERE fingerprint=?", (fp,)).fetchone()
    return (r["deferrals"] if r else 0) or 0


# P6: how long a NEGATIVE stays cached. The primary invalidation is the agent/model
# version below -- a better detector may find what the old one walked past, and that
# is a real event rather than a guess about one. This clock is the BACKSTOP for the
# case where nothing upgrades for a long time: a "not exploitable" from six months ago
# against code nobody has re-examined is an assertion, not a measurement.
#
# 90 days, matching the coverage horizon (D55) and a risk acceptance (D53), so the
# design has one number for "how long may we go on believing something" rather than
# three. Deliberately chosen, not measured; D52 changed the sharper question anyway --
# what makes a negative ADMISSIBLE (corroboration) matters more than how long one
# survives.
NEGATIVE_CACHE_TTL_DAYS = 90


def build_verify_queue(db, consolidated, agent_version, model_version, max_attempts=3,
                       now=None, ttl_days=None):
    """Given this run's consolidated fingerprints, decide which to verify.
    Returns (queue, suppressed) with a reason on each suppression."""
    queue, suppressed = [], []
    for fp, meta in consolidated.items():
        row = db.execute("SELECT verdict,attempts,agent_version,model_version,poc_uri,last_updated FROM findings WHERE fingerprint=?", (fp,)).fetchone()
        if row is None:
            queue.append((fp, meta, "new")); continue
        # THE INVARIANT: already verified -> never verify again.
        if row["verdict"] == "verified":
            suppressed.append((fp, meta, "already verified", row["poc_uri"])); continue
        # negative cache is version-scoped: a newer agent/model re-opens it (D8).
        if (row["agent_version"], row["model_version"]) != (agent_version, model_version):
            queue.append((fp, meta, f"cache invalid: {row['agent_version']}->{agent_version}")); continue
        # non-terminal negative: retry until the attempt budget is spent (verify is ~50%).
        if row["attempts"] >= max_attempts:
            # ...unless the cached negative has simply gone stale (P6). Without a
            # clock, a finding whose budget was spent under an agent that never
            # upgrades is suppressed forever, and "we stopped looking" reads exactly
            # like "there is nothing there".
            ttl = NEGATIVE_CACHE_TTL_DAYS if ttl_days is None else ttl_days
            age = (_days_apart(row["last_updated"], now)
                   if now and ttl is not None and row["last_updated"] else None)
            if age is not None and age > ttl:
                queue.append((fp, meta, f"negative cache expired: {age}d > {ttl}d")); continue
            suppressed.append((fp, meta, f"negative-cached after {row['attempts']} attempts", None)); continue
        queue.append((fp, meta, f"retry {row['attempts']+1}/{max_attempts}"))
    return queue, suppressed

# ---- helper: turn a cm state.db into consolidated {fp: meta} using the tested key ----
def consolidate_db(db_path, src_root):
    dedup.SRC_ROOT = src_root
    findings = dedup.load_db(db_path, os.path.basename(os.path.dirname(db_path)))
    clusters = dedup.consolidate(findings)
    out = {}
    for k, obs in clusters.items():
        fp = dedup.fingerprint(k, obs)
        f0 = obs[0]
        sev_label, sev_rank = dedup.cluster_severity(obs)
        out[fp] = {"cwe_class": dedup.cluster_class(obs), "enclosing_function": (k[2] if k[0]=="fn" else None),
                   "canonical_path": dedup.relpath(f0["file_path"]),
                   "vuln_id": f0["vuln_id"], "title": f0["title"],
                   "severity": sev_label, "severity_rank": sev_rank,
                   "reproductions": len({o["pod"] for o in obs})}
    return out

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", default=":memory:")
    ap.add_argument("--src-root", required=True)
    ap.add_argument("--seed-verified", help="cm state.db whose VERIFIED findings pre-populate the ledger")
    ap.add_argument("find_dbs", nargs="+", help="cm state.db(s) from this run's find fan-out")
    ap.add_argument("--agent", default="codemender-0.2.0")
    ap.add_argument("--model", default="gemini-3")
    ap.add_argument("--ts", default="2026-08-18T00:00:00Z")
    a = ap.parse_args()

    dedup.SRC_ROOT = a.src_root
    db = open_ledger(a.ledger)

    # seed: ingest a prior run's real verified verdicts
    if a.seed_verified:
        dedup.SRC_ROOT = a.src_root
        seed = dedup.load_db(a.seed_verified, "seed")
        clusters = dedup.consolidate(seed)
        n=0
        for k, obs in clusters.items():
            fp = dedup.fingerprint(k, obs); f0 = obs[0]
            verdict = "verified" if any((o.get("status")=="VERIFIED") for o in obs) else "unproven"
            meta = {"cwe_class":dedup.cluster_class(obs), "enclosing_function":(k[2] if k[0]=="fn" else None),
                    "canonical_path":dedup.relpath(f0["file_path"]), "source":"verify"}
            ingest(db, fp, meta, verdict, a.agent, a.model, a.ts,
                   poc_uri=("gs://poc/"+fp if verdict=="verified" else None))
            if verdict=="verified": n+=1
        print(f"seeded ledger: {n} verified fingerprint(s) from {os.path.basename(a.seed_verified)}\n")

    # this run: consolidate the find fan-out (union of all pods), then build the queue
    merged = {}
    for dbp in a.find_dbs:
        merged.update(consolidate_db(dbp, a.src_root))
    queue, suppressed = build_verify_queue(db, merged, a.agent, a.model)

    print(f"consolidated this run : {len(merged)} distinct fingerprints")
    print(f"--> VERIFY QUEUE       : {len(queue)}")
    print(f"--> SUPPRESSED         : {len(suppressed)}\n")
    print("SUPPRESSED (not re-verified):")
    for fp, meta, reason, poc in suppressed:
        print(f"  {fp}  {meta['cwe_class']:20} {str(meta.get('enclosing_function')):12} <- {reason}"
              + (f"  poc={poc}" if poc else ""))
    print("\nVERIFY QUEUE (fan out one verify each):")
    for fp, meta, reason in queue:
        print(f"  {fp}  {meta['cwe_class']:20} {str(meta.get('enclosing_function')):12} <- {reason}")
