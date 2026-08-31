#!/usr/bin/env python3
"""Q8 under simulation: what does P1(a) cost, as a function of the race?

WHY SIMULATE. Q8 wants the distribution of `push -> verdicts complete` against
`push -> merge attempt` over real PRs. A lab cannot produce that: there is one
participant, no review latency, no working day, no queue. D57 built the
instrumentation for when real PRs exist. This answers the different question a lab
CAN answer -- *given* a race, what does the chosen policy cost -- so P1(a) is at
least sized rather than assumed.

THIS IS SYNTHETIC AND SAYS SO. Every number below comes from sampled distributions,
not from measurement. It cannot tell you what your p50 PR lifetime is. What it can
tell you is which values of that number make P1(a) free and which make it a blocking
CI stage wearing a ledger's clothes -- and that shape does not depend on the lab.

The two inputs that matter:

  verify_min   how long push -> all verdicts takes. Grounded: measured find ~6 min
               plus verify 20-40 min per finding, partly parallel.
  pr_lifetime  how long push -> someone clicks merge. NOT grounded. This is the
               number your organisation has and this design does not.

  race-sim.py --pr-median-min 240
  race-sim.py --sweep
"""
import sys
import random
import argparse
import statistics


def lognormal_sampler(rng, median, sigma):
    """PR lifetimes and job durations are right-skewed -- a long tail of PRs that sit
    over a weekend, and of verifies that hit the timeout. A normal distribution would
    understate exactly the tail the race policy is about."""
    import math
    mu = math.log(max(median, 1e-9))
    return lambda: math.exp(rng.gauss(mu, sigma))


def simulate(n=20000, verify_median_min=32.0, verify_sigma=0.55,
             pr_median_min=240.0, pr_sigma=1.1, timeout_rate=0.04, seed=20260826):
    """One trial = one PR. Returns the shares that decide what P1(a) costs.

    `timeout_rate` is the fraction of shas whose verdicts never complete at all --
    a dead job, a lost event, a pod evicted. Under P1(a) those do not merely wait,
    they block until someone intervenes, which is the cost most likely to be
    forgotten when the policy is chosen."""
    rng = random.Random(seed)
    verify = lognormal_sampler(rng, verify_median_min, verify_sigma)
    pr = lognormal_sampler(rng, pr_median_min, pr_sigma)

    waited, waits, never, ready = 0, [], 0, 0
    for _ in range(n):
        v, p = verify(), pr()
        if rng.random() < timeout_rate:
            never += 1
            continue
        if v <= p:
            ready += 1
        else:
            waited += 1
            waits.append(v - p)
    blocked = waited + never
    return {
        "n": n,
        "verdict_ready_at_merge_pct": 100.0 * ready / n,
        "developer_waits_pct": 100.0 * waited / n,
        "never_completes_pct": 100.0 * never / n,
        "any_block_pct": 100.0 * blocked / n,
        "median_wait_min": statistics.median(waits) if waits else 0.0,
        "p90_wait_min": (sorted(waits)[int(0.9 * (len(waits) - 1))] if waits else 0.0),
    }


def sweep(**kw):
    print("P1(a) = block and wait. How much of that is waiting?\n")
    print(f"{'PR lifetime (median)':>22} {'ready':>8} {'waits':>8} {'stuck':>8} "
          f"{'med wait':>10} {'p90 wait':>10}")
    print("-" * 70)
    for pr_med in (15, 30, 60, 120, 240, 480, 1440):
        r = simulate(pr_median_min=pr_med, **kw)
        label = f"{pr_med} min" if pr_med < 120 else f"{pr_med/60:.0f} h"
        print(f"{label:>22} {r['verdict_ready_at_merge_pct']:>7.1f}% "
              f"{r['developer_waits_pct']:>7.1f}% {r['never_completes_pct']:>7.1f}% "
              f"{r['median_wait_min']:>9.0f}m {r['p90_wait_min']:>9.0f}m")
    print("""
  ready  the verdict had landed; the gate is the lookup the design promises
  waits  the developer is blocked on a verify that is still running
  stuck  verdicts never completed -- blocked until a human intervenes. This column
         does not shrink as PRs get slower, and it is the one that decides whether
         P1(a) needs an escape hatch.""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr-median-min", type=float, default=240.0)
    ap.add_argument("--verify-median-min", type=float, default=32.0)
    ap.add_argument("--timeout-rate", type=float, default=0.04)
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.sweep:
        sweep(verify_median_min=a.verify_median_min, timeout_rate=a.timeout_rate, n=a.n)
        return 0
    r = simulate(n=a.n, verify_median_min=a.verify_median_min,
                 pr_median_min=a.pr_median_min, timeout_rate=a.timeout_rate)
    if a.json:
        import json
        print(json.dumps(r, indent=1)); return 0
    print(f"SYNTHETIC — not a measurement. verify median {a.verify_median_min}min, "
          f"PR median {a.pr_median_min}min, timeout rate {a.timeout_rate:.0%}\n")
    for k, v in r.items():
        print(f"  {k:32} {v:.1f}" + ("%" if k.endswith("_pct") else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
