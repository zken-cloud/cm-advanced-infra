#!/usr/bin/env python3
"""Merge-gate risk router + admission control.

Fixes critique #1: the binary gate ("block only on verified") lets ~12% of real
bugs pass silently, because verify is ~50% per attempt. This turns the gate into
a RISK ROUTER with three actions, so a found-but-unverified high-severity bug
becomes a *recorded, owned* risk-acceptance — never an invisible pass.

And admission control (severity x diff-reachability x novelty) decides which
findings are worth ~2 agent-minutes of verify at all, and how many retries.
"""
import math, argparse, json

# ---- retry budget: how many verify attempts to hit a target detection probability ----
def attempts_for_target(p_success_per_attempt, p_target):
    """n such that 1-(1-p)^n >= p_target.  e.g. p=0.5, target=0.95 -> 5."""
    if p_success_per_attempt <= 0: return math.inf
    if p_success_per_attempt >= 1: return 1
    return math.ceil(math.log(1 - p_target) / math.log(1 - p_success_per_attempt))

# measured per-class success rates (extend as data accrues). Some classes verify
# far more reliably against a dedicated NON-functional oracle than a scripted
# functional exploit -- memory via ASAN is the original case; the Node target
# adds leak/ReDoS/timing/PRNG in the same
# shape (see the vulnerable-app ground truth, stored outside this repo).
# For those the paired `*-<oracle>` p replaces the low functional p.
CLASS_P = {
    "sql-injection": 0.9, "os-command-injection": 0.85, "code-injection": 0.85,
    "ssrf": 0.7, "idor": 0.6, "authz": 0.6, "mass-assignment": 0.6,
    "prototype-pollution": 0.85, "path-traversal": 0.85, "nosql-injection": 0.8,
    "info-disclosure": 0.6, "business-logic": 0.5,
    "race-toctou": 0.4,
    "memory-corruption": 0.2,        # functional exploit is hard...
    "memory-corruption-asan": 0.9,   # ...but a sanitizer crash IS the proof
    "memory-leak-gc": 0.2,           # scripting a GC-leak "exploit" is hard...
    "memory-leak-gc-rss": 0.9,       # ...but sustained RSS growth under flat load IS the proof
    "redos": 0.3,                    # a functional DoS "exploit" is flaky...
    "redos-timeout": 0.9,            # ...but one input past a wall-clock bound IS the proof
    "timing-attack": 0.2,            # a functional timing "exploit" barely works...
    "timing-attack-stat": 0.75,      # ...statistical separation proves it (noisy -> lower ceiling)
    "weak-random": 0.3,              # guessing a token functionally is hard...
    "weak-random-predict": 0.9,      # ...predicting the next token from the seed model IS the proof
    "resource-exhaustion": 0.25,     # needs an oracle, but the CWE does not say WHICH
}

# Classes whose honest proof is a dedicated non-functional oracle, not a scripted
# functional exploit. Each maps to (harness, CLASS_P key, note). The memory->ASAN
# case is the template; the rest are its JS analogues.
NONFUNCTIONAL_ORACLE = {
    "memory-corruption": ("asan-crash-oracle", "memory-corruption-asan",
        "compile with -fsanitize=address; a sanitizer abort is the exploit proof"),
    "memory-leak-gc": ("rss-growth-oracle", "memory-leak-gc-rss",
        "drive the endpoint under flat workload; sustained RSS growth is the proof"),
    "redos": ("wall-clock-timeout-oracle", "redos-timeout",
        "one crafted input exceeding a wall-clock bound is the proof; no functional exploit"),
    "timing-attack": ("statistical-timing-oracle", "timing-attack-stat",
        "N-sample timing separation at significance is the proof; inherently noisy"),
    "weak-random": ("predictability-oracle", "weak-random-predict",
        "reconstruct the seed model and predict the next token; a correct prediction is the proof"),
    # Deliberately harness-less. CWE-400 covers catastrophic backtracking AND
    # unbounded retention, which are proven by opposite instruments, so naming one
    # here would be a guess dressed as a route. What IS knowable from the CWE alone
    # is that a functional exploit cannot prove it -- so this still caps attempts and
    # still refuses to cache a negative. Only an explicit fp3 entry in a target's
    # oracle spec can supply the instrument.
    "resource-exhaustion": (None, "resource-exhaustion",
        "resource exhaustion, subtype unknown: no oracle can be chosen from the CWE alone"),
}

def class_verifier(cwe_class):
    """Route a finding to its verify harness. Classes in NONFUNCTIONAL_ORACLE
    verify via a dedicated oracle (ASAN abort, RSS growth, wall-clock blowup,
    statistical timing, next-token prediction) whose success rate replaces the much
    lower functional-exploit rate. Everything else uses a functional exploit."""
    if cwe_class in NONFUNCTIONAL_ORACLE:
        harness, pkey, note = NONFUNCTIONAL_ORACLE[cwe_class]
        return {"harness": harness, "p": CLASS_P[pkey], "note": note}
    return {"harness": "functional-exploit", "p": CLASS_P.get(cwe_class, 0.5)}

# ---- admission control: is this finding worth verifying, and how hard? ----
def admit(finding, diff_reachable, novel, severity_rank):
    """Return (admit?, verify_attempts, reason). Not everything earns 30 agent-min."""
    if not novel:
        return (False, 0, "already in base ledger (pre-existing debt -> CODEOWNERS PR)")
    if not diff_reachable and severity_rank < 3:
        return (False, 0, "not reachable from the diff and below high severity")
    v = class_verifier(finding["cwe_class"])
    target = 0.99 if severity_rank >= 4 else 0.95
    n = attempts_for_target(v["p"], target)
    return (True, n, f"admit: {v['harness']}, p={v['p']}, target={target} -> {n} attempts")

# ---- the risk router: three verdict tiers, three gate actions ----
def gate_decision(finding, sast_corroborates=False, race_policy="record",
                  acceptance=None):
    """finding: {verdict, cwe_class, severity_rank, confidence, attempts, max_attempts}
    acceptance: the active risk_acceptances row covering this finding, or None.
    Returns (action, requires_ack, reason).

    P2/D53 — `acceptance` is what makes sign-off-required different from a bypass.
    It is looked up from the LEDGER by the caller, never read from the branch under
    test, and it is only ever produced by a merged, reviewed PR. The action it yields
    is RISK_ACCEPTED, not PASS: the distinction is the whole point, because "shipped
    clean" and "shipped with a named owner holding the risk" must never be the same
    row in the gate_events log."""
    v = finding["verdict"]; sev = finding.get("severity_rank", 2)
    if v == "verified":
        if acceptance:
            return ("RISK_ACCEPTED", False,
                    f"verified, accepted by {acceptance['owner']} "
                    f"({acceptance['reason_code']}) until {acceptance['expires_at']}, "
                    f"approved by {acceptance['approved_by']} in {acceptance['pr_url']}")
        # policy P1: block, OR merge-with-recorded-acceptance above a threshold
        if race_policy == "block": return ("BLOCK", False, "verified + unfixed introduced here")
        return ("RISK_ACCEPT_REQUIRED", True, "verified exploit — sign-off written to ledger")
    if v == "setup_failed":
        # invariant 6: a PoC that couldn't build/boot is NOT "not exploitable".
        return ("REQUEUE_VERIFY", False, "setup failed (build/boot) — re-attempt with a fixed harness, never a negative")
    if v in ("exploit_failed","unproven","timeout"):
        exhausted = finding.get("attempts",0) >= finding.get("max_attempts",3)
        high_risk = sev >= 3 or sast_corroborates
        if exhausted and high_risk:
            # THE FIX: do not silently pass. A found, high-severity, unverified bug
            # is a recorded, owned risk — not an invisible one.
            return ("RISK_ACCEPT_REQUIRED", True,
                    "found + high-severity but verify budget spent unproven — owned risk, logged")
        if not exhausted:
            return ("REQUEUE_VERIFY", False, f"retry {finding.get('attempts',0)+1}/{finding.get('max_attempts',3)}")
        return ("PASS", False, "found but low-severity and unverified after budget")
    return ("PASS", False, "no finding")

if __name__=="__main__":
    print("=== retry budget to hit a detection target (per-attempt success p) ===")
    for p in (0.9,0.6,0.5,0.2):
        for t in (0.95,0.99):
            print(f"  p={p}  target={t}  ->  {attempts_for_target(p,t)} attempts")
    print("\n=== class verifiers ===")
    for c in ("sql-injection","idor","memory-corruption","memory-leak-gc","redos","timing-attack","weak-random"):
        print(f"  {c:20} {class_verifier(c)}")
    print("\n=== gate router examples ===")
    cases=[
      {"verdict":"verified","cwe_class":"sql-injection","severity_rank":4},
      {"verdict":"exploit_failed","cwe_class":"memory-corruption","severity_rank":4,"attempts":3,"max_attempts":3},
      {"verdict":"unproven","cwe_class":"idor","severity_rank":2,"attempts":3,"max_attempts":3},
      {"verdict":"exploit_failed","cwe_class":"ssrf","severity_rank":3,"attempts":1,"max_attempts":3},
    ]
    for f in cases:
        a,ack,why=gate_decision(f)
        print(f"  {f['verdict']:15} {f['cwe_class']:18} sev{f['severity_rank']} -> {a:22} ack={ack}  ({why})")
