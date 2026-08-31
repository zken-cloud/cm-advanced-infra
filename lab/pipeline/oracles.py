#!/usr/bin/env python3
"""Non-functional verify oracles — proving bugs a scripted exploit cannot.

`gate.py` routes memory→ASAN, leak→RSS-growth, ReDoS→wall-clock, timing→statistical,
weak-random→predictability. It only ROUTED; these are the oracles.

Why they matter beyond tidiness: measured on this target, V1 (closure GC leak) and
V10 (non-constant-time compare) are found by CM and admit no static rule — they are
part of CM's unique value — yet neither can be proven by a functional exploit
script. Without an oracle they stay unproven risk forever, and the retry budget
burns attempts on a harness that cannot succeed.

Every oracle returns (fired, evidence) and follows two rules:
  * a setup failure is NEVER a negative (invariant 6) -> raises OracleSetupError;
  * a NEGATIVE control is mandatory where the signal is statistical, otherwise the
    oracle proves nothing but its own noise floor.
"""
import os, time, json, math, statistics, subprocess, urllib.request, urllib.error


class OracleSetupError(RuntimeError):
    """Harness could not run. Caller must record setup_failed, never 'not exploitable'."""


# ---------------------------------------------------------------- helpers
def _post(url, payload, timeout):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"content-type": "application/json"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(65536)
        return time.perf_counter() - t0, body, None
    except urllib.error.HTTPError as e:
        return time.perf_counter() - t0, e.read(4096), e.code
    except Exception as e:
        return time.perf_counter() - t0, b"", repr(e)


def _rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        return None
    return None


# ---------------------------------------------------------------- oracles
def wall_clock_timeout(url, benign, malicious, bound_s=2.0, timeout=30):
    """ReDoS. Proof = a crafted input blows a wall-clock bound the benign input meets.

    The benign request is the NEGATIVE control: if it is already slow, the bound is
    mis-set and a 'fired' result would be meaningless."""
    t_b, _, err_b = _post(url, benign, timeout)
    if isinstance(err_b, str):
        raise OracleSetupError(f"benign request failed: {err_b}")
    if t_b > bound_s:
        raise OracleSetupError(f"negative control already exceeds the bound "
                               f"({t_b:.2f}s > {bound_s}s) — bound mis-set, result would be noise")
    t_m, _, err_m = _post(url, malicious, timeout)
    timed_out = isinstance(err_m, str) and "timed out" in err_m.lower()
    fired = timed_out or t_m > bound_s
    return fired, {"benign_s": round(t_b, 4), "malicious_s": round(t_m, 4),
                   "bound_s": bound_s, "ratio": round(t_m / max(t_b, 1e-6), 1),
                   "timed_out": timed_out}


def predictability(generator, samples=5, predict=None, project=None):
    """Weak randomness. Proof = the next value is predicted before it is produced.

    `generator()` yields a token; `predict(previous)` returns the predicted next.
    A correct prediction of an unseen value is the exploit — no guessing loop.

    `project` narrows what the prediction is judged against, and exists because a
    token is often part-predictable: `Date.now()+Math.random()` has a derivable
    clock component and an opaque one. Predicting the whole token is impossible and
    predicting nothing is wrong, so the honest claim is about the component — the
    caller supplies the projection and states the claim in its spec.

    The repeat check deliberately runs on the RAW value, never the projection: a
    projection coarse enough to be predictable is also coarse enough to collide
    across two quick samples, and reporting that as "generator repeats values"
    would reach the right verdict by false reasoning."""
    seen = [generator() for _ in range(samples)]
    if len(set(seen)) < len(seen):
        return True, {"reason": "generator repeats values", "samples": seen[:samples]}
    if predict is None:
        raise OracleSetupError("no predictor supplied — cannot prove predictability")
    guess = predict(seen)
    actual = generator()
    judged = project(actual) if project else actual
    return guess == judged, {"predicted": guess, "actual_judged": judged,
                             "actual_raw": actual, "projected": project is not None,
                             "samples": seen[-2:]}


def statistical_timing(measure_true, measure_false, n=400, min_effect=0.15, alpha_z=3.0):
    """Timing side channel. Proof = a separation that survives a noise estimate.

    `measure_*` return one timing sample each. The NEGATIVE control is two samples
    drawn from the SAME condition: if same-vs-same already separates, the
    environment is too noisy and no verdict is issued."""
    def _welch(a, b):
        ma, mb = statistics.mean(a), statistics.mean(b)
        va, vb = statistics.pvariance(a), statistics.pvariance(b)
        se = math.sqrt(va / len(a) + vb / len(b)) or 1e-12
        return (ma - mb) / se, ma, mb

    ctrl_a = [measure_true() for _ in range(n // 2)]
    ctrl_b = [measure_true() for _ in range(n // 2)]
    z_ctrl, _, _ = _welch(ctrl_a, ctrl_b)
    if abs(z_ctrl) > alpha_z:
        raise OracleSetupError(f"same-condition control already separates (z={z_ctrl:.1f}) — "
                               f"environment too noisy for a timing verdict")
    a = [measure_true() for _ in range(n)]
    b = [measure_false() for _ in range(n)]
    z, ma, mb = _welch(a, b)
    effect = abs(ma - mb) / max(ma, mb, 1e-12)
    fired = abs(z) > alpha_z and effect > min_effect
    return fired, {"z": round(z, 2), "z_control": round(z_ctrl, 2),
                   "mean_true": round(ma, 6), "mean_false": round(mb, 6),
                   "relative_effect": round(effect, 3), "n": n}


def rss_growth(pid, drive, rounds=12, per_round=25, min_growth_kb=4096, settle_s=0.3,
               warmup_rounds=3):
    """Memory retention. Proof = RSS climbs under flat, repeated load and does not
    return — a leak, not merely a working set.

    THE BASELINE IS TAKEN AFTER A WARM-UP, UNDER THE SAME LOAD. Taking it at rest was
    wrong and produced confident false positives: a process that simply needs 40 MB
    to serve requests shows 40 MB of "growth" against an idle baseline, and the
    oracle called that a leak. Measured on V1, whose middleware allocates ~1 MB per
    request and releases it: 2.5 MB of apparent growth in one session and 43 MB in
    another on the SAME machine — a 15x swing that was never about the code.

    After warm-up the working set is already paid for, so what is left is the part
    that keeps climbing. A real leak still climbs (V15: ~350 MB); a working set
    plateaus.

    The warm-up rounds are also the honest noise band: `noise` is now the spread
    across warmed samples under load, not the flatness of an idle process, and
    an idle process is flat for reasons that say nothing about serving traffic."""
    if _rss_kb(pid) is None:
        raise OracleSetupError(f"cannot read RSS for pid {pid}")
    for _ in range(max(0, warmup_rounds)):
        for _ in range(per_round):
            drive()
        time.sleep(settle_s)
    base = []
    for _ in range(3):
        for _ in range(per_round):
            drive()
        time.sleep(settle_s)
        base.append(_rss_kb(pid))
    noise = max(base) - min(base)
    series = []
    for _ in range(rounds):
        for _ in range(per_round):
            drive()
        time.sleep(settle_s)
        series.append(_rss_kb(pid))
    # Growth over the WARMED baseline, not over an idle one.
    growth = series[-1] - max(base)
    rising = sum(1 for i in range(1, len(series)) if series[i] > series[i - 1])
    fired = growth > max(min_growth_kb, noise * 4) and rising >= (len(series) - 1) * 0.6
    return fired, {"baseline_kb": base, "noise_kb": noise, "series_kb": series,
                   "growth_kb": growth, "rising_steps": rising, "threshold_kb": min_growth_kb}


ORACLES = {
    "wall-clock-timeout-oracle": wall_clock_timeout,
    "predictability-oracle": predictability,
    "statistical-timing-oracle": statistical_timing,
    "rss-growth-oracle": rss_growth,
    # asan-crash-oracle lives with the native toolchain; see EXPERIMENTS (M1-M4)
}
