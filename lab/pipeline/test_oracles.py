#!/usr/bin/env python3
"""Assertions for the non-functional verify oracles. python3 test_oracles.py

Two properties are load-bearing and get direct tests:
  * a setup failure raises OracleSetupError -> caller records setup_failed, never
    "not exploitable" (invariant 6);
  * where the signal is statistical, a NEGATIVE control gates the verdict — an
    oracle with no noise floor proves only its own noise."""
import os, sys, time, importlib.util

HERE=os.path.dirname(os.path.abspath(__file__))
spec=importlib.util.spec_from_file_location("o", os.path.join(HERE,"oracles.py"))
O=importlib.util.module_from_spec(spec); spec.loader.exec_module(O)

# ---- wall-clock (ReDoS) ----
def t_wallclock_fires_on_slow_input():
    calls={"n":0}
    def fake(url,payload,timeout):
        calls["n"]+=1
        return (0.01 if payload.get("x")=="benign" else 5.0), b"", None
    O._post, real = fake, O._post
    try:
        fired,ev=O.wall_clock_timeout("u",{"x":"benign"},{"x":"evil"},bound_s=2.0)
        assert fired and ev["ratio"]>100, ev
    finally: O._post=real

def t_wallclock_refuses_when_control_is_slow():
    def fake(url,payload,timeout): return 9.0, b"", None
    O._post, real = fake, O._post
    try:
        try:
            O.wall_clock_timeout("u",{},{},bound_s=2.0); assert False,"should have raised"
        except O.OracleSetupError as e:
            assert "bound mis-set" in str(e)
    finally: O._post=real

def t_wallclock_benign_failure_is_setup_not_negative():
    def fake(url,payload,timeout): return 0.0, b"", "ConnectionRefused"
    O._post, real = fake, O._post
    try:
        try:
            O.wall_clock_timeout("u",{},{}); assert False,"should have raised"
        except O.OracleSetupError: pass
    finally: O._post=real

# ---- predictability (weak randomness) ----
def t_predictability_fires_on_correct_prediction():
    seq=iter(["a","b","c","d","PREDICTED"])
    fired,ev=O.predictability(lambda:next(seq),samples=4,predict=lambda s:"PREDICTED")
    assert fired and ev["actual_judged"]=="PREDICTED" and ev["actual_raw"]=="PREDICTED"
def t_predictability_judges_the_projection_not_the_whole_value():
    """A part-predictable token (clock component + opaque component) is the normal
    case. The prediction is judged against the projection; the claim in the spec is
    what says which component was proven."""
    seq=iter(["a1","b2","c3","d4","CLOCK-opaque"])
    fired,ev=O.predictability(lambda:next(seq),samples=4,
                              predict=lambda s:"CLOCK",project=lambda v:v.split("-")[0])
    assert fired and ev["projected"] and ev["actual_raw"]=="CLOCK-opaque", ev
def t_predictability_repeat_check_runs_on_the_raw_value():
    """A projection coarse enough to be predictable is coarse enough to collide.
    Running the repeat check on it would report 'generator repeats values' for a
    generator that repeats nothing -- right verdict, false reasoning."""
    seq=iter(["ab","ac","ad","ae","af"])
    fired,ev=O.predictability(lambda:next(seq),samples=4,
                              predict=lambda s:"zz",project=lambda v:v[0])
    assert not fired, ev
    assert "reason" not in ev, f"repeat check fired on the projection: {ev}"
def t_predictability_fires_on_repeats():
    fired,ev=O.predictability(lambda:"same",samples=3,predict=None)
    assert fired and "repeats" in ev["reason"]
def t_predictability_needs_a_predictor():
    seq=iter(list("abcdef"))
    try:
        O.predictability(lambda:next(seq),samples=3,predict=None); assert False
    except O.OracleSetupError: pass
def t_predictability_silent_on_good_randomness():
    import secrets
    fired,_=O.predictability(lambda:secrets.token_hex(8),samples=4,predict=lambda s:"nope")
    assert not fired

# ---- statistical timing ----
def t_timing_fires_on_real_separation():
    import random
    fired,ev=O.statistical_timing(lambda:random.gauss(2.0,0.05),
                                  lambda:random.gauss(1.0,0.05), n=200)
    assert fired and abs(ev["z"])>3 and ev["relative_effect"]>0.15, ev
def t_timing_silent_when_no_separation():
    # SEEDED. Unseeded, this test drew the oracle's own noise control over the
    # threshold by chance (z=-3.2) roughly one run in a hundred and reported a
    # failure that was the oracle working correctly. A flaky test of a
    # noise-rejecting instrument teaches everyone to re-run the suite, which is the
    # habit that hides real failures.
    import random
    r=random.Random(20260826)
    fired,ev=O.statistical_timing(lambda:r.gauss(1.0,0.05),
                                  lambda:r.gauss(1.0,0.05), n=200)
    assert not fired, ev
def t_timing_refuses_when_environment_is_noisy():
    """Same-condition control separates -> no verdict, rather than a false one."""
    vals=iter([1.0]*100+[5.0]*100+[1.0]*10000)  # ctrl_a=100x1.0, ctrl_b=100x5.0
    try:
        O.statistical_timing(lambda:next(vals), lambda:1.0, n=200)
        assert False, "should have refused"
    except O.OracleSetupError as e:
        assert "too noisy" in str(e)

# ---- rss growth ----
def t_rss_bad_pid_is_setup_error():
    try:
        O.rss_growth(999999, lambda:None, rounds=1, per_round=1); assert False
    except O.OracleSetupError: pass
def t_rss_fires_on_monotonic_growth():
    vals=iter([1000]+[1000,1000,1000]+[1000+i*2000 for i in range(1,13)])  # guard + 3 baseline + 12
    O._rss_kb, real = (lambda pid: next(vals)), O._rss_kb
    try:
        fired,ev=O.rss_growth(1, lambda:None, rounds=12, per_round=1, settle_s=0)
        assert fired and ev["growth_kb"]>4096, ev
    finally: O._rss_kb=real
def t_rss_silent_on_flat_usage():
    vals=iter([1000]*4+[1000+(i%2)*50 for i in range(12)])  # guard + 3 baseline + 12
    O._rss_kb, real = (lambda pid: next(vals)), O._rss_kb
    try:
        fired,_=O.rss_growth(1, lambda:None, rounds=12, per_round=1, settle_s=0)
        assert not fired
    finally: O._rss_kb=real

def t_rss_baseline_is_taken_under_load_not_at_rest():
    """A process that simply NEEDS memory to serve requests must not read as a leak.
    Baselining at rest made a 40 MB working set look like 40 MB of growth, and the
    same finding measured 2.5 MB and 43 MB on one machine hours apart."""
    # reads: 1 liveness check, then 3 warmed-baseline samples, then 12 series.
    # The warm-up rounds DRIVE load and read nothing -- that is the point of them.
    seq=iter([50_000]                        # liveness check
             +[50_000,50_100,50_050]         # warmed baseline: working set paid for
             +[50_100]*12)                   # flat under load -> not a leak
    O._rss_kb, real = (lambda pid: next(seq)), O._rss_kb
    try:
        fired,ev=O.rss_growth(1, lambda:None, rounds=12, per_round=1,
                              min_growth_kb=4096, settle_s=0, warmup_rounds=3)
        assert not fired, ev
        assert ev["growth_kb"] < 4096, ev
    finally: O._rss_kb=real

def t_rss_still_fires_on_growth_that_outlives_the_warm_up():
    seq=iter([50_000]+[50_000,50_000,50_000]+[60_000+i*10_000 for i in range(12)])
    O._rss_kb, real = (lambda pid: next(seq)), O._rss_kb
    try:
        fired,ev=O.rss_growth(1, lambda:None, rounds=12, per_round=1,
                              min_growth_kb=4096, settle_s=0, warmup_rounds=3)
        assert fired and ev["growth_kb"] > 100_000, ev
    finally: O._rss_kb=real

def t_rss_warm_up_actually_drives_the_workload():
    """A warm-up that does not run the load warms nothing."""
    calls={"n":0}
    seq=iter([1]*40)
    O._rss_kb, real = (lambda pid: next(seq)), O._rss_kb
    try:
        O.rss_growth(1, lambda: calls.__setitem__("n",calls["n"]+1),
                     rounds=2, per_round=5, settle_s=0, warmup_rounds=3)
        # 3 warm-up + 3 baseline + 2 measured rounds, 5 drives each
        assert calls["n"] == 8*5, calls
    finally: O._rss_kb=real

def t_every_routed_harness_has_an_implementation():
    import importlib.util as iu
    g=iu.spec_from_file_location("g",os.path.join(HERE,"gate.py"))
    G=iu.module_from_spec(g); g.loader.exec_module(G)
    # A harness of None is DELIBERATE: the class needs an oracle and the CWE cannot
    # say which (CWE-400 covers backtracking and retention alike). Only an fp3 entry
    # in a target's oracle spec can supply the instrument.
    routed={v[0] for v in G.NONFUNCTIONAL_ORACLE.values() if v[0] is not None}
    missing=routed-set(O.ORACLES)-{"asan-crash-oracle"}
    assert not missing, f"gate routes to harnesses that do not exist: {missing}"

def t_harnessless_class_still_requires_an_oracle():
    """CWE-400 must not silently fall back to a functional exploit: needs_oracle
    stays true, so attempts are capped and exploit_failed cannot cache."""
    import importlib.util as iu
    r=iu.spec_from_file_location("r",os.path.join(HERE,"oracle-route.py"))
    R=iu.module_from_spec(r); r.loader.exec_module(R)
    got=R.route(["CWE-400"])
    assert got["needs_oracle"] is True, got
    assert got["harness"]!="functional-exploit", got

if __name__=="__main__":
    tests=[v for k,v in sorted(globals().items()) if k.startswith("t_")]
    p=0
    for t in tests:
        try: t(); print(f"PASS  {t.__name__}"); p+=1
        except AssertionError as e: print(f"FAIL  {t.__name__}: {e}")
        except Exception as e: print(f"ER*R  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{p}/{len(tests)} passed"); sys.exit(0 if p==len(tests) else 1)
