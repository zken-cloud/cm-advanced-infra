#!/usr/bin/env python3
"""Assertions for the risk-router gate + admission control. python3 test_gate.py"""
import importlib.util, os, sys, math
spec=importlib.util.spec_from_file_location("g",os.path.join(os.path.dirname(os.path.abspath(__file__)),"gate.py"))
G=importlib.util.module_from_spec(spec); spec.loader.exec_module(G)

def t_budget_math():
    assert G.attempts_for_target(0.5,0.95)==5
    assert G.attempts_for_target(0.9,0.95)==2
    assert G.attempts_for_target(0.2,0.99)==21     # memory functional exploit: infeasible
def t_asan_makes_memory_feasible():
    fn=G.class_verifier("memory-corruption")
    assert fn["harness"]=="asan-crash-oracle" and fn["p"]>=0.9
    assert G.attempts_for_target(fn["p"],0.95)<=2  # ...vs 14 with functional exploit
def t_verified_never_silent():
    a,ack,_=G.gate_decision({"verdict":"verified","cwe_class":"sql-injection","severity_rank":4})
    assert a in ("BLOCK","RISK_ACCEPT_REQUIRED") and (a=="BLOCK" or ack)
def t_found_highsev_unverified_is_owned_not_passed():
    # THE FIX: high-severity, found, verify budget spent -> recorded risk, not silent pass
    a,ack,_=G.gate_decision({"verdict":"exploit_failed","cwe_class":"memory-corruption",
                             "severity_rank":4,"attempts":3,"max_attempts":3})
    assert a=="RISK_ACCEPT_REQUIRED" and ack
def t_lowsev_unverified_passes():
    a,ack,_=G.gate_decision({"verdict":"unproven","cwe_class":"idor","severity_rank":1,
                             "attempts":3,"max_attempts":3})
    assert a=="PASS"
def t_not_exhausted_requeues():
    a,_,_=G.gate_decision({"verdict":"exploit_failed","cwe_class":"ssrf","severity_rank":3,
                           "attempts":1,"max_attempts":3})
    assert a=="REQUEUE_VERIFY"
def t_admission_drops_preexisting():
    ok,n,_=G.admit({"cwe_class":"sql-injection"},diff_reachable=True,novel=False,severity_rank=4)
    assert not ok and n==0

def t_nonfunctional_oracles_lift_p():
    # the JS analogues of memory->ASAN: a dedicated oracle beats a functional exploit
    cases={
      "memory-leak-gc":("rss-growth-oracle",0.9),
      "redos":("wall-clock-timeout-oracle",0.9),
      "timing-attack":("statistical-timing-oracle",0.75),
      "weak-random":("predictability-oracle",0.9),
    }
    for cls,(harness,p) in cases.items():
        fn=G.class_verifier(cls)
        assert fn["harness"]==harness, (cls,fn)
        assert fn["p"]>=p and fn["p"]>G.CLASS_P[cls], (cls,fn)  # oracle p beats functional p
        assert "note" in fn
def t_functional_classes_unchanged():
    for cls in ("sql-injection","ssrf","prototype-pollution","path-traversal","nosql-injection"):
        fn=G.class_verifier(cls)
        assert fn["harness"]=="functional-exploit" and fn["p"]==G.CLASS_P[cls]
def t_unknown_class_defaults():
    fn=G.class_verifier("brand-new-class")
    assert fn["harness"]=="functional-exploit" and fn["p"]==0.5

if __name__=="__main__":
    tests=[v for k,v in sorted(globals().items()) if k.startswith("t_")]
    p=0
    for t in tests:
        try: t(); print(f"PASS  {t.__name__}"); p+=1
        except AssertionError as e: print(f"FAIL  {t.__name__}")
    print(f"\n{p}/{len(tests)} passed"); sys.exit(0 if p==len(tests) else 1)
