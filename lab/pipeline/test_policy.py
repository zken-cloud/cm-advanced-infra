#!/usr/bin/env python3
"""P4, P6 and Q8 — the policy machinery. python3 test_policy.py

Three controls that are easy to declare and easy to leave inert:

  * P6, the negative-cache TTL: a number in a constant that nothing reads suppresses
    findings forever while looking like a policy;
  * Q8, the race: three timestamps nobody stamps make the distribution unmeasurable,
    and P1(a) was chosen on the assumption that verdicts usually win;
  * P4, patch volume: a limit without the acceptance rate beside it is a guess with a
    number on it.

So each block ends with a check that the thing is actually WIRED, not merely present.
"""
import os
import sys
import tempfile
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, fn):
    s = importlib.util.spec_from_file_location(name, os.path.join(HERE, fn))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


L = _load("ledger", "ledger.py")
NOW = "2026-08-26"


def _db():
    return L.open_ledger(tempfile.mktemp(suffix=".db"))


def _spent(db, fp="fp3:x", updated="2026-01-01T00:00:00Z"):
    db.execute("""INSERT INTO findings(fingerprint,verdict,attempts,agent_version,
                  model_version,last_updated) VALUES(?,?,?,?,?,?)""",
               (fp, "exploit_failed", 3, "cm-0.4.0", "g3", updated))
    db.commit()
    return {fp: {"cwe_class": "ssrf"}}


# ---------------------------------------------------------------- P6
def t_stale_negative_reenters_the_queue():
    db = _db(); cons = _spent(db)
    q, sup = L.build_verify_queue(db, cons, "cm-0.4.0", "g3", now=NOW)
    assert q and "expired" in q[0][2], (q, sup)


def t_fresh_negative_stays_suppressed():
    db = _db(); cons = _spent(db, updated="2026-08-20T00:00:00Z")
    q, sup = L.build_verify_queue(db, cons, "cm-0.4.0", "g3", now=NOW)
    assert not q and sup, (q, sup)


def t_without_a_clock_behaviour_is_unchanged():
    """The TTL must be opt-in by supplying a clock. A caller that passes none should
    behave exactly as it did before P6 existed."""
    db = _db(); cons = _spent(db)
    q, sup = L.build_verify_queue(db, cons, "cm-0.4.0", "g3")
    assert not q and sup


def t_agent_upgrade_still_beats_the_clock():
    """Version invalidation is the PRIMARY rule; the TTL is the backstop. A fresh
    negative from an older agent must still re-open."""
    db = _db(); cons = _spent(db, updated="2026-08-25T00:00:00Z")
    q, sup = L.build_verify_queue(db, cons, "cm-0.5.0", "g3", now=NOW)
    assert q and "cache invalid" in q[0][2], (q, sup)


def t_the_ttl_is_actually_applied_by_selection():
    src = open(os.path.join(HERE, "verify-select.py")).read()
    assert "now=ts" in src, "verify-select never passes a clock, so the TTL is inert"


# ---------------------------------------------------------------- Q8
def _raced(db, sha, push, done, merge):
    L.record_scan(db, "r", sha, 3, 3, "cm-0.4.0", push)
    L.stamp_scan_time(db, "r", sha, "pushed_at", push)
    if done:
        L.stamp_scan_time(db, "r", sha, "verdicts_complete_at", done)
    if merge:
        L.stamp_scan_time(db, "r", sha, "merge_attempted_at", merge)


def t_race_measures_both_durations():
    db = _db()
    _raced(db, "a", "2026-08-26T00:00:00Z", "2026-08-26T00:25:00Z", "2026-08-26T02:00:00Z")
    r = L.race_latencies(db, "r")[0]
    assert r["push_to_verdicts_s"] == 1500 and r["push_to_merge_s"] == 7200
    assert r["verdicts_beat_merge"] is True


def t_a_sha_whose_verdicts_never_landed_is_kept_not_dropped():
    """The most interesting row in the table. Dropping it biases the very
    distribution this exists to measure."""
    db = _db()
    _raced(db, "c", "2026-08-26T00:00:00Z", None, "2026-08-26T00:15:00Z")
    rows = L.race_latencies(db, "r")
    assert len(rows) == 1 and rows[0]["push_to_verdicts_s"] is None
    assert rows[0]["verdicts_beat_merge"] is None
    assert L.race_summary(db, "r")["verdicts_never_completed"] == 1


def t_merge_stamp_keeps_the_earliest():
    """When the developer FIRST met the gate, not the last time CI re-ran."""
    db = _db()
    _raced(db, "a", "2026-08-26T00:00:00Z", None, "2026-08-26T01:00:00Z")
    L.stamp_scan_time(db, "r", "a", "merge_attempted_at", "2026-08-26T09:00:00Z")
    got = db.execute("SELECT merge_attempted_at FROM scans WHERE sha='a'").fetchone()[0]
    assert got == "2026-08-26T01:00:00Z", got


def t_stamping_an_unknown_sha_invents_nothing():
    """A gate check arriving before the fold IS the race. It must not create a scan
    row, or 'never scanned' becomes 'scanned' by observation."""
    db = _db()
    assert L.stamp_scan_time(db, "r", "ghost", "pushed_at", NOW) is False
    assert db.execute("SELECT count(*) FROM scans").fetchone()[0] == 0


def t_race_column_names_are_validated():
    db = _db()
    _raced(db, "a", "2026-08-26T00:00:00Z", None, None)
    try:
        L.stamp_scan_time(db, "r", "a", "verdict", NOW)
    except ValueError:
        return
    raise AssertionError("an arbitrary column name was accepted into an UPDATE")


def t_the_push_time_is_actually_plumbed():
    ing = open(os.path.join(HERE, "ingest-verdicts.py")).read()
    rec = open(os.path.join(HERE, "reconcile.py")).read()
    assert '"--pushed-at"' in ing and "pushed_at" in ing, "ingest never stamps the push time"
    assert "--pushed-at" in rec, "the reconciler never passes RUN.json's dispatched_at"


# ---------------------------------------------------------------- P4
def t_budget_blocks_past_the_limit():
    db = _db()
    for i in range(3):
        L.record_patch_pr(db, "r", "payments", f"fp{i}", f"https://gh/pr/{i}", "2026-08-24")
    b = L.patch_budget(db, "r", "payments", NOW)
    assert b["allowed"] is False and "queue this one" in b["reason"]


def t_budget_window_rolls_off():
    db = _db()
    for i in range(3):
        L.record_patch_pr(db, "r", "payments", f"fp{i}", f"https://gh/pr/{i}", "2026-06-01")
    assert L.patch_budget(db, "r", "payments", NOW)["allowed"] is True


def t_acceptance_ignores_undecided_prs():
    """A PR nobody has decided on is not evidence either way; counting it as a
    rejection makes a slow reviewer look like an unwilling one."""
    db = _db()
    L.record_patch_pr(db, "r", "t", "f1", "u1", "2026-08-01")
    L.record_patch_pr(db, "r", "t", "f2", "u2", "2026-08-01")
    L.close_patch_pr(db, "u1", "merged", "2026-08-02")
    a = L.patch_acceptance(db, "r", "t")
    assert a["acceptance_rate"] == 1.0 and a["open"] == 1, a


def t_low_acceptance_is_surfaced_with_the_budget():
    """The number that says whether the limit is right must not be a separate lookup
    someone can skip."""
    db = _db()
    for i, o in enumerate(["closed", "closed", "closed", "merged"]):
        L.record_patch_pr(db, "r", "checkout", f"g{i}", f"u{i}", "2026-08-01")
        L.close_patch_pr(db, f"u{i}", o, "2026-08-05")
    b = L.patch_budget(db, "r", "checkout", NOW)
    assert "selection problem" in b["reason"], b["reason"]
    assert b["acceptance_rate"] == 0.25


def t_acceptance_is_none_not_zero_when_nothing_is_decided():
    """0% acceptance and 'no data' must not be the same number."""
    db = _db()
    L.record_patch_pr(db, "r", "t", "f1", "u1", "2026-08-01")
    assert L.patch_acceptance(db, "r", "t")["acceptance_rate"] is None


def t_outcome_is_validated():
    db = _db()
    L.record_patch_pr(db, "r", "t", "f1", "u1", "2026-08-01")
    try:
        L.close_patch_pr(db, "u1", "abandoned", NOW)
    except ValueError:
        return
    raise AssertionError("an unknown outcome was recorded")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("t_")]
    p = 0
    for t in tests:
        try:
            t(); print(f"PASS  {t.__name__}"); p += 1
        except AssertionError as e:
            print(f"FAIL  {t.__name__}: {e}")
        except Exception as e:
            print(f"ER*R  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{p}/{len(tests)} passed")
    sys.exit(0 if p == len(tests) else 1)
