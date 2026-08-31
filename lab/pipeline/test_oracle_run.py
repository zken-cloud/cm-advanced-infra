#!/usr/bin/env python3
"""Assertions for the oracle spec runner. python3 test_oracle_run.py

The load-bearing properties, in order of how much damage getting them wrong does:

  * a finding with NO spec entry is `unproven`, never a negative. This is the whole
    reason the design chose a per-target spec over extraction from CM's artefacts:
    the failure mode has to be loud and non-caching (D50);
  * an AMBIGUOUS path match refuses rather than guessing — a wrong guess drives the
    wrong endpoint and calls the answer evidence;
  * OracleSetupError maps to setup_failed, not exploit_failed (invariant 6);
  * every spec entry names an oracle the runner can actually dispatch, and params
    the oracle actually takes. The four unreachable routes in D47 existed because
    two tables were allowed to disagree with no test standing between them.
"""
import os
import sys
import json
import importlib.util

HERE = os.path.dirname(os.path.abspath(HERE_F := __file__))
ROOT = os.path.dirname(HERE)


def _load(name, path):
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


R = _load("orun", os.path.join(HERE, "oracle-run.py"))
SPEC_DIR = os.path.join(ROOT, "targets", "oracle-specs")


def _spec():
    import yaml
    return yaml.safe_load(open(os.path.join(SPEC_DIR, "vulnerable-app.yaml")))


# ---------------------------------------------------------------- matching
def t_exact_fp3_matches():
    e = R.select(_spec(), "cryptoUtils.js::generateSessionContextId", "weak-random")
    assert e and e["oracle"] == "predictability-oracle", e


def t_prod_style_full_path_matches_basename_spec():
    """relpath is basename in the lab and clone-root-relative in prod. A spec
    written against one form must match the other, or every finding silently
    degrades to unproven the day the path form changes."""
    e = R.select(_spec(), "src/api/middlewares/validation.middleware.js::validateCorporateEmail",
                 "redos")
    assert e and e["oracle"] == "wall-clock-timeout-oracle", e


def t_fp3_entry_wins_over_a_functional_cwe_class():
    """The V15 regression. CM labelled a buffer-retention leak `prototype-pollution`;
    the class router therefore said functional-exploit and the fp3 entry that proves
    it was never consulted. fp3 is the STABLE key (D17); the class is the one field
    identity deliberately excludes. Selection must not depend on the class when an
    fp3 entry exists."""
    e = R.select(_spec(), "mediaCache.js::extractAndCacheHeader", "prototype-pollution")
    assert e and e["oracle"] == "rss-growth-oracle", e


def t_file_wildcard_matches():
    e = R.select(_spec(), "tracking.middleware.js::anythingAtAll", "memory-leak-gc")
    assert e and e["oracle"] == "rss-growth-oracle", e


def t_no_entry_returns_none_not_a_guess():
    assert R.select(_spec(), "totallyUnknown.js::nope", "redos") is None


def t_ambiguous_suffix_refuses():
    """Two spec entries whose paths both suffix-match the finding: refuse. Driving
    one of two plausible endpoints and recording the result as evidence is worse
    than not testing."""
    spec = {"oracles": [
        {"match": {"fp3": "a/cache.js::get"}, "oracle": "x"},
        {"match": {"fp3": "b/cache.js::get"}, "oracle": "y"},
    ]}
    assert R.select(spec, "cache.js::get", "redos") is None


def t_suffix_respects_segment_boundary():
    """`cache.js` must not match `mediaCache.js`."""
    spec = {"oracles": [{"match": {"fp3": "cache.js::get"}, "oracle": "x"}]}
    assert R.select(spec, "mediaCache.js::get", "redos") is None


def t_class_fallback_is_last():
    spec = {"oracles": [
        {"match": {"cwe_class": "redos"}, "oracle": "by-class"},
        {"match": {"fp3": "f.js::g"}, "oracle": "by-fp3"},
    ]}
    assert R.select(spec, "f.js::g", "redos")["oracle"] == "by-fp3"
    assert R.select(spec, "other.js::h", "redos")["oracle"] == "by-class"


# ---------------------------------------------------------------- verdicts
def _run(argv):
    old = sys.argv
    sys.argv = ["oracle-run.py"] + argv
    try:
        return R.main()
    finally:
        sys.argv = old


def t_missing_spec_file_is_unproven(tmp="/tmp/_or_missing.json"):
    _run(["--fp3", "a.js::b", "--cwe-class", "redos", "--spec", "/nonexistent.yaml",
          "--project-root", "/tmp", "--out", tmp])
    d = json.load(open(tmp))
    assert d["verdict"] == "unproven", d
    assert "no oracle spec" in d["reason"]


def t_unmatched_finding_is_unproven_and_says_so(tmp="/tmp/_or_nomatch.json"):
    _run(["--fp3", "nothing.js::here", "--cwe-class", "redos",
          "--spec", os.path.join(SPEC_DIR, "vulnerable-app.yaml"),
          "--project-root", "/tmp", "--out", tmp])
    d = json.load(open(tmp))
    assert d["verdict"] == "unproven", d
    # The wording matters: this text is what stops someone reading the row as a
    # tested-and-clean finding.
    assert "must not cache as a negative" in d["reason"], d["reason"]


def t_boot_failure_is_setup_failed_not_a_negative(tmp="/tmp/_or_boot.json"):
    """Invariant 6. An app that never started tells us nothing about the bug."""
    _run(["--fp3", "cryptoUtils.js::generateSessionContextId", "--cwe-class", "weak-random",
          "--spec", os.path.join(SPEC_DIR, "vulnerable-app.yaml"),
          "--project-root", "/tmp/definitely-not-a-checkout", "--out", tmp])
    d = json.load(open(tmp))
    assert d["verdict"] == "setup_failed", d
    assert d["verdict"] != "exploit_failed"


# ---------------------------------------------------------------- spec integrity
def t_every_spec_entry_is_dispatchable():
    """Each entry names an oracle `run_entry` knows, and supplies the params that
    oracle requires. D47's four dead routes were exactly this check missing."""
    required = {
        "wall-clock-timeout-oracle": {"path", "benign", "malicious"},
        "predictability-oracle": {"request", "extract", "predict"},
        "statistical-timing-oracle": {"request_true", "request_false"},
        "rss-growth-oracle": {"drive"},
    }
    for name in os.listdir(SPEC_DIR):
        if not name.endswith((".yaml", ".yml")):
            continue
        import yaml
        spec = yaml.safe_load(open(os.path.join(SPEC_DIR, name)))
        for e in spec.get("oracles") or []:
            o = e["oracle"]
            assert o in required, f"{name}: no runner for oracle {o!r}"
            missing = required[o] - set((e.get("params") or {}))
            assert not missing, f"{name}: {o} entry missing params {missing}"


def t_every_spec_oracle_exists_in_oracles_py():
    O = _load("o", os.path.join(HERE, "oracles.py"))
    import yaml
    for name in os.listdir(SPEC_DIR):
        if not name.endswith((".yaml", ".yml")):
            continue
        spec = yaml.safe_load(open(os.path.join(SPEC_DIR, name)))
        for e in spec.get("oracles") or []:
            assert e["oracle"] in O.ORACLES, f"{name}: {e['oracle']} not implemented"


def t_every_spec_entry_states_a_claim():
    """The claim travels into the evidence and is what the ledger records as proven.
    An entry without one lets a narrow measurement be read as the CWE's worst case."""
    import yaml
    for name in os.listdir(SPEC_DIR):
        if not name.endswith((".yaml", ".yml")):
            continue
        spec = yaml.safe_load(open(os.path.join(SPEC_DIR, name)))
        for e in spec.get("oracles") or []:
            c = (e.get("claim") or "").strip()
            assert len(c) > 40, f"{name}: {e['match']} has no meaningful claim"


def t_app_block_can_boot_and_be_probed():
    import yaml
    for name in os.listdir(SPEC_DIR):
        if not name.endswith((".yaml", ".yml")):
            continue
        spec = yaml.safe_load(open(os.path.join(SPEC_DIR, name)))
        app = spec["app"]
        for k in ("boot", "base", "ready"):
            assert k in app, f"{name}: app block missing {k!r}"
        assert isinstance(app["boot"], list), f"{name}: boot must be argv, not a shell string"


# ---------------------------------------------------------------- banking
def t_banked_bundle_is_admissible_as_a_regression_oracle():
    """Invariant 7. A banked PoC that the audit calls inadmissible is not a
    regression test, and an oracle bundle self-boots by construction."""
    import tempfile
    dest = tempfile.mkdtemp()
    spec = _spec()
    entry = spec["oracles"][0]
    R.bank(dest, spec, entry, {"fp3": "validation.middleware.js::validateCorporateEmail",
                               "cwe_class": "redos", "verdict": "verified"})
    for f in ("replay.sh", "oracle-spec.yaml", "cm-oracle.json"):
        assert os.path.exists(os.path.join(dest, f)), f"bundle missing {f}"
    PR = _load("pr", os.path.join(HERE, "poc-replay.py"))
    a = PR.audit_bundle(os.path.join(dest, "replay.sh"))
    assert a["self_booting"], a
    assert not a["pinned_paths"], f"banked PoC pins paths outside itself: {a['pinned_paths']}"
    assert a["admissible"], a


def t_banked_spec_carries_only_this_finding():
    """Banking the whole target spec would make every replay carry every other
    finding's endpoints and payloads."""
    import tempfile, yaml
    dest = tempfile.mkdtemp()
    spec = _spec()
    R.bank(dest, spec, spec["oracles"][0], {"fp3": "a::b", "cwe_class": "redos"})
    banked = yaml.safe_load(open(os.path.join(dest, "oracle-spec.yaml")))
    assert len(banked["oracles"]) == 1, banked
    assert banked["app"], "banked spec must keep the app block or replay cannot boot"


# ---------------------------------------------------------------- predictor
def t_base36_millis_matches_javascript():
    """Date.now().toString(36). If this drifts the V11 prediction silently stops
    matching and the finding reads as not-weak-random."""
    assert R._base36(0) == "0"
    assert R._base36(35) == "z"
    assert R._base36(36) == "10"
    # a real millisecond timestamp, cross-checked against node's toString(36)
    assert R._base36(1787654321000) == "mt8j8608", R._base36(1787654321000)


def t_unknown_predictor_is_an_error_not_a_pass():
    try:
        R._predictor("no-such-predictor", 6)
    except ValueError:
        return
    raise AssertionError("unknown predictor silently accepted")


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
