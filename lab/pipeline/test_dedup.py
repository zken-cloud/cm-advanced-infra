#!/usr/bin/env python3
"""Assertions for the enclosing-function resolver. python3 test_dedup.py

Regression cover for the dominant JS idiom `exports.foo = (...) => {}`: the
resolver must name the arrow from its binding site, never from a callback param."""
import os, sys, tempfile, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("dedup", os.path.join(HERE, "consolidate-dedup.py"))
D = importlib.util.module_from_spec(spec); spec.loader.exec_module(D)

SRC = """\
const path = require('path');
exports.getSafeDownloadPath = (filename) => {
    const sanitized = filename.replace(/\\.\\.\\//g, '');
    return path.join('downloads', sanitized);
};
exports.fetchRemoteAsset = (target, cb) => {
    http.get(target, (proxyRes) => {
        let body = '';
        proxyRes.on('data', chunk => body += chunk);
    });
};
const helper = function () { return 41; };
function plainDecl(a) { return a + 1; }
module.exports.filterProducts = (query) => {
    return list.filter(doc => doc.ok);
};
"""

def _resolve(tmp, line):
    p = os.path.join(tmp, "src", "m.js"); os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(SRC)
    return D.enclosing_func("/pod/abs/m.js", line, tmp, end_line=line)  # abs path, resolved by basename

def t_exports_arrow_named_from_binding():
    with tempfile.TemporaryDirectory() as t:
        assert _resolve(t, 3) == "getSafeDownloadPath"      # inside the arrow body

def t_callback_param_not_used_as_name():
    with tempfile.TemporaryDirectory() as t:
        # line 9 is inside `chunk => ...`; must resolve to the OUTER named fn, not "chunk"/"proxyRes"
        n = _resolve(t, 9)
        assert n == "fetchRemoteAsset", f"got {n!r}"

def t_const_function_expression():
    with tempfile.TemporaryDirectory() as t:
        assert _resolve(t, 12) == "helper"

def t_plain_declaration_still_works():
    with tempfile.TemporaryDirectory() as t:
        assert _resolve(t, 13) == "plainDecl"

def t_module_exports_member():
    with tempfile.TemporaryDirectory() as t:
        assert _resolve(t, 15) == "filterProducts"          # nested filter(doc=>) must not win

def t_no_src_root_returns_none():
    assert D.enclosing_func("x.js", 5, "", end_line=5) is None


# ---- D17: identity must not move when the agent relabels a finding ----
def _cluster(rows, src):
    """rows: (vuln_id, severity) at the same site -> fingerprints produced."""
    import tempfile, os
    with tempfile.TemporaryDirectory() as t:
        pth=os.path.join(t,"src","m.js"); os.makedirs(os.path.dirname(pth)); open(pth,"w").write(src)
        D.SRC_ROOT=t; D._SRC_INDEX.clear(); D._AST_CACHE.clear(); D._BRACE_CACHE.clear()
        finds=[{"finding_id":f"f{i}","vuln_id":c,"vuln_type":"T","title":"t",
                "file_path":"/pod/abs/m.js","start_line":2,"end_line":2,
                "snippet":"","analysis":"","severity":sv,"status":"OPEN","pod":f"p{i}"}
               for i,(c,sv) in enumerate(rows)]
        return {D.fingerprint(k,o) for k,o in D.consolidate(finds).items()}, finds

SRC_ONE = "exports.doThing = (x) => {\n  return x;\n};\n"

def t_fingerprint_invariant_to_cwe_relabel():
    """Measured: CM reassigned CWE-200/244 -> CWE-201 on the same function between
    runs. Under fp2 that produced different fingerprints -> the ledger lookup missed
    -> a verified vuln could pass the merge gate. fp3 must be immune."""
    a,_=_cluster([("CWE-200","HIGH")], SRC_ONE)
    b,_=_cluster([("CWE-201","HIGH")], SRC_ONE)
    c,_=_cluster([("CWE-244","CRITICAL")], SRC_ONE)
    assert a==b==c, (a,b,c)
    assert len(a)==1

def t_relabels_collapse_to_one_finding():
    """Three runs disagreeing about the CWE of ONE bug = one finding, not three."""
    fps,_=_cluster([("CWE-200","HIGH"),("CWE-201","HIGH"),("CWE-244","CRITICAL")], SRC_ONE)
    assert len(fps)==1, fps

def t_class_is_a_fold_not_identity():
    _,finds=_cluster([("CWE-200","HIGH"),("CWE-200","HIGH"),("CWE-918","HIGH")], SRC_ONE)
    assert D.cluster_class(finds)=="info-disclosure" or D.cluster_class(finds)=="cwe-200", D.cluster_class(finds)
    # modal wins: two CWE-200 beat one CWE-918
    assert D.cluster_class(finds)!="ssrf"

def t_algo_version_bumped():
    assert D.FP_ALGO=="fp3", "changing the key REQUIRES an explicit algo bump"

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("t_")]
    p = 0
    for t in tests:
        try: t(); print(f"PASS  {t.__name__}"); p += 1
        except AssertionError as e: print(f"FAIL  {t.__name__}: {e}")
        except Exception as e: print(f"ER*R  {t.__name__}: {e}")
    print(f"\n{p}/{len(tests)} passed"); sys.exit(0 if p == len(tests) else 1)
