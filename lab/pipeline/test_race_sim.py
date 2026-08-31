#!/usr/bin/env python3
"""Assertions for the Q8 race simulator. python3 test_race_sim.py

A simulator's danger is that it always produces a number, and a number is easy to
quote as a measurement. So the properties tested here are about honesty as much as
arithmetic: the shares must account for every trial, the stuck fraction must not
quietly improve as PRs get slower, and the output must say it is synthetic.
"""
import os
import sys
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
s = importlib.util.spec_from_file_location("sim", os.path.join(HERE, "race-sim.py"))
S = importlib.util.module_from_spec(s)
s.loader.exec_module(S)


def t_shares_account_for_every_trial():
    r = S.simulate(n=5000)
    total = (r["verdict_ready_at_merge_pct"] + r["developer_waits_pct"]
             + r["never_completes_pct"])
    assert abs(total - 100.0) < 1e-6, total


def t_slower_prs_mean_fewer_developers_wait():
    fast = S.simulate(n=5000, pr_median_min=15)
    slow = S.simulate(n=5000, pr_median_min=480)
    assert slow["developer_waits_pct"] < fast["developer_waits_pct"]
    assert slow["verdict_ready_at_merge_pct"] > fast["verdict_ready_at_merge_pct"]


def t_the_stuck_share_does_not_improve_with_slower_prs():
    """The point of reporting it separately. A sha whose verdicts never complete
    blocks under P1(a) no matter how leisurely the PR was, so it cannot be waited
    out -- it needs an escape hatch, and averaging it into 'waits' would hide that."""
    fast = S.simulate(n=8000, pr_median_min=15)
    slow = S.simulate(n=8000, pr_median_min=1440)
    assert abs(fast["never_completes_pct"] - slow["never_completes_pct"]) < 1.0


def t_faster_verification_reduces_waiting():
    slow_v = S.simulate(n=5000, verify_median_min=60, pr_median_min=120)
    fast_v = S.simulate(n=5000, verify_median_min=10, pr_median_min=120)
    assert fast_v["developer_waits_pct"] < slow_v["developer_waits_pct"]


def t_zero_timeout_rate_removes_the_stuck_share():
    r = S.simulate(n=5000, timeout_rate=0.0)
    assert r["never_completes_pct"] == 0.0


def t_it_is_deterministic():
    """A simulator whose answer moves between runs invites re-rolling until the
    number is congenial."""
    assert S.simulate(n=3000) == S.simulate(n=3000)


def t_the_distribution_is_right_skewed():
    """A normal distribution would understate the tail -- PRs that sit over a
    weekend, verifies that hit the timeout -- and the tail is what the race policy
    is actually about."""
    import random
    g = S.lognormal_sampler(random.Random(1), median=100, sigma=1.0)
    xs = sorted(g() for _ in range(20000))
    med = xs[len(xs) // 2]
    mean = sum(xs) / len(xs)
    assert mean > med * 1.2, (mean, med)
    assert 85 < med < 115, med


def t_output_declares_itself_synthetic():
    """It must be impossible to paste this into a doc and have it read as data."""
    src = open(os.path.join(HERE, "race-sim.py")).read()
    assert "SYNTHETIC" in src and "not a measurement" in src
    assert "cannot tell you what your p50 PR lifetime is" in src


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
