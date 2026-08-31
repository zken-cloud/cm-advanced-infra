#!/usr/bin/env python3
"""Assertions for the audited sign-off path. python3 test_risk_accept.py

An acceptance is the only way a verified finding ships. Every check here is a way
that could go wrong quietly:

  * accepting a finding that is not verified is a bypass with extra steps;
  * an acceptance with no expiry is a silent policy change, not a decision;
  * self-approval defeats the gate entirely;
  * an expired acceptance that still covers a finding is the worst of all — the
    gate says PASS and everyone believes a decision is still standing.
"""
import os
import sys
import json
import tempfile
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, fn):
    s = importlib.util.spec_from_file_location(name, os.path.join(HERE, fn))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


RA = _load("ra", "risk-accept.py")
L = _load("ledger", "ledger.py")
G = _load("gate", "gate.py")

NOW = "2026-08-25"


def _ledger(verdict="verified", fixed_at=None, fp="fp3:abc"):
    path = tempfile.mktemp(suffix=".db")
    db = L.open_ledger(path)
    db.execute("INSERT INTO findings(fingerprint,verdict,fixed_at,repo) VALUES(?,?,?,?)",
               (fp, verdict, fixed_at, "cm-lab-user1"))
    db.commit()
    return path, db


def _doc(**over):
    d = {"fingerprint": "fp3:abc", "scope": "trunk", "reason_code": "no-attacker",
         "owner": "alice", "expires_at": "2026-10-01",
         "reason_text": "not reachable in any deployed configuration"}
    d.update(over)
    return d


def _path(fp="fp3:abc"):
    return f"/tmp/{fp.replace(':', '_')}.yaml"


# ---------------------------------------------------------------- validation
def t_valid_acceptance_passes():
    led, _ = _ledger()
    assert RA.validate(_doc(), _path(), NOW, led, "bob") == []


def t_unverified_finding_cannot_be_accepted():
    """The core rule. Accepting a risk nobody established is a bypass."""
    led, _ = _ledger(verdict="unproven")
    p = RA.validate(_doc(), _path(), NOW, led, "bob")
    assert any("not `verified`" in x for x in p), p


def t_unknown_fingerprint_cannot_be_accepted():
    led, _ = _ledger(fp="fp3:other")
    p = RA.validate(_doc(), _path(), NOW, led, "bob")
    assert any("not in the ledger" in x for x in p), p


def t_fixed_finding_acceptance_is_stale():
    led, _ = _ledger(fixed_at="2026-08-20")
    p = RA.validate(_doc(), _path(), NOW, led, "bob")
    assert any("stale" in x for x in p), p


def t_missing_expiry_is_refused():
    led, _ = _ledger()
    d = _doc(); d.pop("expires_at")
    p = RA.validate(d, _path(), NOW, led, "bob")
    assert any("expires_at" in x for x in p), p


def t_expiry_in_the_past_is_refused():
    led, _ = _ledger()
    p = RA.validate(_doc(expires_at="2026-08-01"), _path(), NOW, led, "bob")
    assert any("not in the future" in x for x in p), p


def t_unbounded_expiry_is_refused():
    led, _ = _ledger()
    p = RA.validate(_doc(expires_at="2030-01-01"), _path(), NOW, led, "bob")
    assert any("maximum is" in x for x in p), p


def t_self_approval_is_refused():
    led, _ = _ledger()
    p = RA.validate(_doc(), _path(), NOW, led, "alice")
    assert any("cannot approve their own" in x for x in p), p


def t_freetext_reason_is_refused():
    led, _ = _ledger()
    p = RA.validate(_doc(reason_code="because I said so"), _path(), NOW, led, "bob")
    assert any("reason_code" in x for x in p), p


def t_no_ledger_refuses_rather_than_assuming():
    """'Cannot tell' must never read as 'fine'. This is the fail-open the whole
    design refuses, in the one place where it would be most tempting."""
    p = RA.validate(_doc(), _path(), NOW, None, "bob")
    assert any("cannot confirm" in x for x in p), p


def t_filename_must_carry_the_fingerprint():
    led, _ = _ledger()
    p = RA.validate(_doc(), "/tmp/whatever.yaml", NOW, led, "bob")
    assert any("filename must start" in x for x in p), p


# ---------------------------------------------------------------- lookup
def t_active_finds_a_live_acceptance():
    led, db = _ledger()
    RA.ingest(_doc(), db, "cm-lab-user1", "https://x/1", "bob", NOW)
    a = RA.active(db, "fp3:abc", "cm-lab-user1", NOW)
    assert a and a["owner"] == "alice", a


def t_expired_acceptance_does_not_cover():
    led, db = _ledger()
    RA.ingest(_doc(expires_at="2026-09-01"), db, "cm-lab-user1", "https://x/1", "bob", NOW)
    assert RA.active(db, "fp3:abc", "cm-lab-user1", "2026-09-02") is None


def t_revoked_acceptance_does_not_cover():
    led, db = _ledger()
    aid = RA.ingest(_doc(), db, "cm-lab-user1", "https://x/1", "bob", NOW)
    db.execute("UPDATE risk_acceptances SET revoked_at=? WHERE acceptance_id=?", (NOW, aid))
    db.commit()
    assert RA.active(db, "fp3:abc", "cm-lab-user1", NOW) is None


def t_acceptance_is_scoped_to_its_repo():
    led, db = _ledger()
    RA.ingest(_doc(), db, "cm-lab-user1", "https://x/1", "bob", NOW)
    assert RA.active(db, "fp3:abc", "some-other-repo", NOW) is None


def t_ingest_is_append_only():
    """A superseding acceptance is a new row. Asking what the risk position was on a
    past date needs the row that was live then, not the row that survived."""
    led, db = _ledger()
    RA.ingest(_doc(), db, "cm-lab-user1", "https://x/1", "bob", NOW)
    RA.ingest(_doc(owner="carol"), db, "cm-lab-user1", "https://x/2", "bob", NOW)
    n = db.execute("SELECT count(*) c FROM risk_acceptances").fetchone()["c"]
    assert n == 2, n
    assert RA.active(db, "fp3:abc", "cm-lab-user1", NOW)["owner"] == "carol"


# ---------------------------------------------------------------- the gate
def t_gate_passes_only_with_an_acceptance():
    f = {"verdict": "verified", "cwe_class": "ssrf", "severity_rank": 4}
    assert G.gate_decision(f, race_policy="block")[0] == "BLOCK"
    acc = {"owner": "alice", "reason_code": "no-attacker", "expires_at": "2026-10-01",
           "approved_by": "bob", "pr_url": "https://x/1"}
    assert G.gate_decision(f, race_policy="block", acceptance=acc)[0] == "RISK_ACCEPTED"


def t_accepted_is_not_the_same_action_as_pass():
    """`RISK_ACCEPTED` and `PASS` must be distinguishable in gate_events, or the
    question 'what shipped with known verified bugs' has no answer."""
    f = {"verdict": "verified", "cwe_class": "ssrf", "severity_rank": 4}
    acc = {"owner": "a", "reason_code": "no-attacker", "expires_at": "2026-10-01",
           "approved_by": "b", "pr_url": "u"}
    action, ack, reason = G.gate_decision(f, acceptance=acc)
    assert action == "RISK_ACCEPTED" and action != "PASS"
    for token in ("a", "no-attacker", "2026-10-01", "b", "u"):
        assert token in reason, f"{token!r} missing from the audit reason: {reason}"


def t_acceptance_never_rescues_a_nonverified_finding():
    """An acceptance covers an established risk. It must not turn a setup_failed
    into a pass -- that verdict means the harness broke, and nobody accepted that."""
    acc = {"owner": "a", "reason_code": "no-attacker", "expires_at": "2026-10-01",
           "approved_by": "b", "pr_url": "u"}
    f = {"verdict": "setup_failed", "cwe_class": "ssrf", "severity_rank": 4}
    assert G.gate_decision(f, acceptance=acc)[0] == "REQUEUE_VERIFY"


# ---------------------------------------------------------------- the REAL gate
def _gated(verdict="verified"):
    path = tempfile.mktemp(suffix=".db")
    db = L.open_ledger(path)
    db.execute("INSERT INTO findings(fingerprint,verdict,repo,cwe_class,canonical_path) "
               "VALUES('fp3:abc',?,'r','ssrf','a.js')", (verdict,))
    L.record_scan(db, "r", "sha1", 3, 3, "cm-0.4.0", "2026-08-25T00:00:00Z")
    L.record_verify_health(db, "r", "sha1", 1, 1, "2026-08-25T00:00:00Z")
    db.commit()
    return db


def t_merge_gate_blocks_without_an_acceptance():
    assert L.merge_gate(_gated(), "r", "sha1", now=NOW)[0] == "BLOCK"


def t_merge_gate_returns_risk_accepted_when_signed():
    db = _gated()
    RA.ingest(_doc(), db, "r", "https://gh/pr/7", "bob", NOW)
    action, why, d = L.merge_gate(db, "r", "sha1", now=NOW)
    assert action == "RISK_ACCEPTED", (action, why)
    assert d["blocking"] == [] and len(d["accepted"]) == 1
    assert "alice" in why


def t_merge_gate_blocks_again_once_the_acceptance_expires():
    db = _gated()
    RA.ingest(_doc(expires_at="2026-09-01"), db, "r", "https://gh/pr/7", "bob", NOW)
    assert L.merge_gate(db, "r", "sha1", now="2026-09-02")[0] == "BLOCK"


def t_merge_gate_without_a_timestamp_fails_closed():
    """No `now` means the expiry cannot be evaluated. That must fail towards
    BLOCKING, never towards shipping — the acceptance might have lapsed a year ago."""
    db = _gated()
    RA.ingest(_doc(), db, "r", "https://gh/pr/7", "bob", NOW)
    assert L.merge_gate(db, "r", "sha1")[0] == "BLOCK"


def t_an_acceptance_for_a_different_finding_does_not_cover_this_one():
    db = _gated()
    RA.ingest(_doc(fingerprint="fp3:zzz"), db, "r", "https://gh/pr/7", "bob", NOW)
    assert L.merge_gate(db, "r", "sha1", now=NOW)[0] == "BLOCK"


def t_gate_survives_a_ledger_that_predates_the_table():
    """The gate opens the ledger READ-ONLY (invariant 3), so it cannot migrate and
    will meet the old schema until the next ingest. Raising there took the only
    developer-facing control down entirely: every check returned ERROR.

    Absent table == no acceptances, which biases towards BLOCK — an acceptance can
    only ever make the gate more permissive."""
    import sqlite3
    path = tempfile.mktemp(suffix=".db")
    db = L.open_ledger(path)
    db.execute("INSERT INTO findings(fingerprint,verdict,repo,cwe_class,canonical_path) "
               "VALUES('fp3:abc','verified','r','ssrf','a.js')")
    L.record_scan(db, "r", "sha1", 3, 3, "cm-0.4.0", "2026-08-25T00:00:00Z")
    db.execute("DROP TABLE risk_acceptances")          # a pre-D53 ledger
    db.commit(); db.close()
    ro = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    ro.row_factory = sqlite3.Row
    action, why, _ = L.merge_gate(ro, "r", "sha1", now=NOW)
    assert action == "BLOCK", (action, why)
    assert L.active_acceptance(ro, "fp3:abc", "r", NOW) is None


def t_a_corrupt_ledger_still_raises():
    """Narrow, not blanket. 'The table is not there yet' and 'the ledger is corrupt'
    are different facts and must not share a branch — swallowing both would turn a
    broken ledger into a clean-looking gate."""
    import sqlite3
    path = tempfile.mktemp(suffix=".db")
    db = L.open_ledger(path)
    db.execute("DROP TABLE risk_acceptances")
    db.execute("CREATE TABLE risk_acceptances(wrong_column TEXT)")
    db.commit()
    try:
        L.active_acceptance(db, "fp3:abc", "r", NOW)
    except sqlite3.OperationalError:
        return
    raise AssertionError("a malformed risk_acceptances table was swallowed")


# ------------------------------------------------- is it actually WIRED UP?
# This design has now shipped the same bug four times: a table, a route, or a
# parameter that is correct, tested, and that nothing in the live path calls
# (D47 twice, D51, and this feature on the day it was written). A unit test on
# merge_gate cannot see that. These can.
def t_ingest_exits_cleanly_when_there_is_nothing_to_ingest():
    """The path filter fires on ANY change under .cm/risk-accepted/ -- a README, or
    the example template. Demanding an approver for a push that ingests nothing
    fails CI for no reason, and a check that goes red for no reason is one people
    learn to ignore. Measured: it fired on the merge that first shipped the
    directory."""
    wf = open(os.path.join(os.path.dirname(HERE), ".github", "workflows",
                           "cm-risk-accept.yml")).read()
    i = wf.index("Record the acceptance in the ledger")
    body = wf[i:]
    early = body.index("nothing to ingest")
    approver = body.index("merged with no recorded approval")
    assert early < approver, ("the approver gate runs before the is-there-work check, "
                              "so an unrelated push fails CI")


def t_the_example_template_is_not_an_acceptance():
    """It must not match the *.yaml glob, or every fresh clone tries to ingest it."""
    d = os.path.join(os.path.dirname(HERE), ".cm", "risk-accepted")
    names = os.listdir(d)
    assert names, "the example is missing; nobody will know the format"
    assert not [n for n in names if n.endswith((".yaml", ".yml"))], names


def t_the_live_gate_callers_pass_a_timestamp():
    """Without `now=`, merge_gate honours no acceptance and the whole sign-off path
    is inert while every unit test still passes."""
    for f in ("gate-check.py", "ingest-verdicts.py"):
        src = open(os.path.join(HERE, f)).read()
        i = src.index("merge_gate(")
        call = src[i:i + 260]
        assert "now=" in call, f"{f} calls merge_gate without now= — acceptances would be ignored"


def t_the_live_gate_callers_treat_risk_accepted_as_passing():
    for f, needle in (("gate-check.py", '"RISK_ACCEPTED": 0'),
                      ("ingest-verdicts.py", '"RISK_ACCEPTED": 0')):
        src = open(os.path.join(HERE, f)).read()
        assert needle in src, f"{f} does not map RISK_ACCEPTED to a passing exit code"


def t_the_live_gate_callers_report_what_shipped_accepted():
    """An accepted finding that is not printed is one nobody reviews."""
    for f in ("gate-check.py", "ingest-verdicts.py"):
        src = open(os.path.join(HERE, f)).read()
        assert 'details.get("accepted"' in src or 'detail.get("accepted"' in src, \
            f"{f} never renders the accepted findings"


# ---------------------------------------------------------------- schema
def t_reason_codes_are_documented():
    assert set(L.RISK_REASONS) >= {"no-attacker", "fails-closed", "config-only",
                                   "already-mitigated", "accepted-cost"}
    for k, v in L.RISK_REASONS.items():
        assert len(v) > 20, f"{k} has no meaningful description"


def t_acceptance_table_requires_its_audit_fields():
    led, db = _ledger()
    cols = {r[1] for r in db.execute("PRAGMA table_info(risk_acceptances)")}
    for c in ("owner", "approved_by", "pr_url", "expires_at", "reason_code", "scope"):
        assert c in cols, f"risk_acceptances is missing {c}"


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
