#!/usr/bin/env python3
"""Assertions for coverage — what was EXAMINED, apart from what was FOUND.
python3 test_coverage.py

Q13's whole problem is that "CM looked and found nothing" and "CM never looked" have
been the same zero rows. So the failures worth testing are the ones where a gap
reads as a clean bill of health:

  * `in_scope` must never be reported as "scanned"/"examined". It is reconstructed
    from the agent's input filters and says the file was OFFERED, nothing more;
  * a file with no coverage row must surface in the exposure register, not vanish;
  * coverage from an older agent must not count as coverage for a newer one, for the
    same reason the negative cache is version-scoped (D8);
  * and the module must actually be CALLED — `coverage.py` sat in the tree, complete
    and unused, from the day it was written until 2026-08-25.
"""
import os
import sys
import json
import tempfile
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _load(name, fn):
    s = importlib.util.spec_from_file_location(name, os.path.join(HERE, fn))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


C = _load("cov", "coverage.py")
L = _load("ledger", "ledger.py")

CFG = {"include": [".js"], "exclude": [".min.js"], "max_file_size_kb": 500}
NOW = "2026-08-26"


def _tree():
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "sub"), exist_ok=True)
    open(os.path.join(d, "a.js"), "w").write("x")
    open(os.path.join(d, "sub", "b.js"), "w").write("y")
    open(os.path.join(d, "notes.md"), "w").write("z")
    open(os.path.join(d, "vendor.min.js"), "w").write("q")
    return d


# ---------------------------------------------------------------- classification
def t_classify_separates_scope_from_observation():
    d = _tree()
    rows = {r["path"]: r for r in C.walk_coverage(d, CFG)}
    assert rows["a.js"]["in_scope"] is True
    assert rows["notes.md"]["in_scope"] is False and rows["notes.md"]["skip_reason"] == "extension"
    assert rows["vendor.min.js"]["skip_reason"] == "exclude-pattern"
    assert all(not r["observed"] for r in rows.values())


def t_observed_is_a_separate_fact_from_in_scope():
    """The old code let an observed path OVERWRITE the scope verdict. A file CM
    mentioned but which the filters excluded is a genuinely interesting row, and
    collapsing the two made it unrepresentable."""
    d = _tree()
    rows = {r["path"]: r for r in C.walk_coverage(d, CFG, observed_paths={"notes.md"})}
    assert rows["notes.md"]["observed"] is True
    assert rows["notes.md"]["in_scope"] is False, "observation must not rewrite scope"


def t_envelope_never_says_scanned():
    """The word is load-bearing. `files_scanned` invites exactly the reading this
    whole table exists to prevent."""
    d = _tree()
    env = C.coverage_envelope(d, CFG, "cm-0.4.0", NOW)
    assert "files_in_scope" in env and "files_scanned" not in env
    assert '"scanned"' not in json.dumps(env), "a per-file status still claims 'scanned'"


def t_observed_from_a_missing_state_db_is_empty_not_an_error():
    assert C.observed_from_state_db("/nonexistent/state.db") == set()


# ---------------------------------------------------------------- the ledger
def _db_with(rows, sha="sha1", agent="cm-0.4.0", ts="2026-08-26T00:00:00Z", scope="."):
    db = L.open_ledger(tempfile.mktemp(suffix=".db"))
    L.record_coverage(db, "r", sha, scope, rows, agent, ts)
    return db


def t_covering_campaign_cites_the_campaign():
    """'Covered' with no citation is the inference this replaces."""
    db = _db_with([{"path": "a.js", "in_scope": True}])
    hit = L.covering_campaign(db, "r", "a.js", NOW)
    assert hit and hit["sha"] == "sha1" and hit["examined_at"]


def t_a_file_only_ever_excluded_is_not_covered():
    db = _db_with([{"path": "notes.md", "in_scope": False, "skip_reason": "extension"}])
    assert L.covering_campaign(db, "r", "notes.md", NOW) is None


def t_coverage_ages_out():
    db = _db_with([{"path": "a.js", "in_scope": True}], ts="2026-01-01T00:00:00Z")
    assert L.covering_campaign(db, "r", "a.js", NOW, horizon_days=90) is None
    assert L.covering_campaign(db, "r", "a.js", NOW, horizon_days=3650) is not None


def t_an_older_agent_does_not_cover_for_a_newer_one():
    """D8's rule, one table over: a better detector may find what the old one walked
    past, so old coverage is not evidence about the new one."""
    db = _db_with([{"path": "a.js", "in_scope": True}], agent="cm-0.4.0")
    assert L.covering_campaign(db, "r", "a.js", NOW, agent_version="cm-0.5.0") is None
    assert L.covering_campaign(db, "r", "a.js", NOW, agent_version="cm-0.4.0") is not None


def t_exposure_register_names_the_never_scanned():
    """D33's weak spot: code deleted from trunk but still running in prod."""
    db = _db_with([{"path": "a.js", "in_scope": True}])
    reg = L.exposure_register(db, "r", ["a.js", "legacy/gone.js"], NOW)
    assert len(reg) == 1 and reg[0]["path"] == "legacy/gone.js"
    assert "never in any campaign" in reg[0]["reason"]
    assert reg[0]["last_covered"] is None


def t_exposure_register_distinguishes_stale_from_never():
    """'Nobody ever looked' and 'the last look was too long ago' are different
    exposures and want different responses."""
    db = _db_with([{"path": "a.js", "in_scope": True}], ts="2026-01-01T00:00:00Z")
    reg = L.exposure_register(db, "r", ["a.js"], NOW, horizon_days=90)
    assert "past the horizon" in reg[0]["reason"], reg
    assert reg[0]["last_covered"] is not None


def t_summary_reports_observed_apart_from_in_scope():
    db = _db_with([{"path": "a.js", "in_scope": True, "observed": True},
                   {"path": "b.js", "in_scope": True},
                   {"path": "n.md", "in_scope": False, "skip_reason": "extension"}])
    s = L.coverage_summary(db, "r", "sha1", ".")
    assert s == {"files_total": 3, "in_scope": 2, "observed": 1,
                 "excluded_by": {"extension": 1}}, s


def t_scope_is_part_of_the_key():
    """A sliced scan misses off-chain bugs in files it fully contains (p=0.0079), so
    'covered under scope=src/api' is not 'covered under scope=.'."""
    db = _db_with([{"path": "a.js", "in_scope": True}], scope="src/api")
    L.record_coverage(db, "r", "sha1", ".", [{"path": "a.js", "in_scope": True}],
                      "cm-0.4.0", "2026-08-26T00:00:00Z")
    n = db.execute("SELECT count(*) c FROM coverage WHERE canonical_path='a.js'").fetchone()["c"]
    assert n == 2, f"scope collapsed into one row ({n})"


def t_recording_the_same_campaign_twice_overwrites():
    db = _db_with([{"path": "a.js", "in_scope": False, "skip_reason": "size"}])
    L.record_coverage(db, "r", "sha1", ".", [{"path": "a.js", "in_scope": True}],
                      "cm-0.4.0", "2026-08-26T00:00:00Z")
    assert L.covering_campaign(db, "r", "a.js", NOW) is not None


# ------------------------------------------------- is it actually WIRED UP?
def t_the_find_pod_emits_coverage():
    """coverage.py existed complete and uncalled from the day it was written. That
    is the fifth instance of this pattern in the record; it gets a standing check."""
    import yaml
    y = yaml.safe_load(open(os.path.join(ROOT, "k8s", "51-find-job.yaml")))
    script = y["spec"]["template"]["spec"]["containers"][0]["args"][0]
    assert "/opt/cm/coverage.py" in script, "the find pod never runs the coverage exporter"
    assert "coverage-$I.json" in script, "the find pod computes coverage and never publishes it"


def t_the_reconciler_passes_coverage_to_ingest():
    src = open(os.path.join(HERE, "reconcile.py")).read()
    assert "coverage-*.json" in src, "the reconciler never downloads the coverage envelopes"
    assert "--coverage" in src, "the reconciler never passes them to ingest"


def t_ingest_accepts_and_records_coverage():
    src = open(os.path.join(HERE, "ingest-verdicts.py")).read()
    assert '"--coverage"' in src
    assert "record_coverage" in src, "ingest takes --coverage and never writes it"


def t_ingest_says_so_when_coverage_is_absent():
    """Silence about coverage is the bug. A run with none must announce it."""
    src = open(os.path.join(HERE, "ingest-verdicts.py")).read()
    assert "cannot be distinguished from unscanned" in src


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
