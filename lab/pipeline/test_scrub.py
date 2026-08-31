#!/usr/bin/env python3
"""Assertions for scrub-answer-key.py. python3 test_scrub.py

The scrubber MODIFIES source files, so its two risky behaviors get direct tests:
trailing-comment stripping must be quote-aware (never touch `http://`), and code
must survive byte-for-byte minus the comment."""
import importlib.util, os, sys, tempfile, json
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("s", os.path.join(HERE, "scrub-answer-key.py"))
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)

def t_trailing_comment_quote_aware():
    # a // inside a string literal is NOT a comment
    assert S.trailing_comment_at('const u = "http://safe.com";') is None
    assert S.trailing_comment_at("const u = 'a//b';") is None
    # a real trailing comment is found
    i = S.trailing_comment_at('doThing(x); // Vuln 5 Sink')
    assert i is not None and 'Vuln 5' in 'doThing(x); // Vuln 5 Sink'[i:]
    # escaped quote inside a string does not end it early
    assert S.trailing_comment_at('const s = "a\\"//b"; // real') is not None

def t_hint_matches_annotations():
    assert S.HINT.search("// Vulnerability 7: RCE Constructor Extraction")
    assert S.HINT.search("// Vuln 5 Sink")
    assert not S.HINT.search("// increment the counter")

def _scrub(tmp, files, **kw):
    root = Path(tmp)
    for name, body in files.items():
        p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(body)
    rep = root / "r.json"
    import sys as _s; argv = _s.argv
    _s.argv = ["scrub", str(root), "--report", str(rep)] + list(kw.get("extra", []))
    try: S.main()
    finally: _s.argv = argv
    return json.loads(rep.read_text())

def t_strips_trailing_keeps_code():
    with tempfile.TemporaryDirectory() as tmp:
        _scrub(tmp, {"a.js": 'foo(bar);   // Vuln 5 Sink\nbaz();\n'})
        out = (Path(tmp) / "a.js").read_text()
        assert "foo(bar);" in out and "Vuln 5" not in out and "baz();" in out

def t_removes_comment_run_block():
    with tempfile.TemporaryDirectory() as tmp:
        _scrub(tmp, {"a.js": '// Vulnerability 4: Prototype Pollution\n// hides in a merge\nrun();\n'})
        out = (Path(tmp) / "a.js").read_text()
        assert out.strip() == "run();"

def t_preserves_url_in_code():
    with tempfile.TemporaryDirectory() as tmp:
        _scrub(tmp, {"a.js": 'get("http://internal-network/x");  // Vuln 6 Sink\n'})
        out = (Path(tmp) / "a.js").read_text()
        assert 'http://internal-network/x' in out and "Vuln 6" not in out

def t_deletes_answer_key_doc():
    with tempfile.TemporaryDirectory() as tmp:
        rep = _scrub(tmp, {"SEEDED-VULNS.md": "the answers\n", "keep.js": "ok();\n"})
        assert not (Path(tmp) / "SEEDED-VULNS.md").exists()
        assert (Path(tmp) / "keep.js").exists()
        assert "SEEDED-VULNS.md" in rep["docs_deleted"]

def t_benign_comment_untouched():
    with tempfile.TemporaryDirectory() as tmp:
        src = "// increment counter\ni++;  // loop index\n"
        _scrub(tmp, {"a.js": src})
        assert (Path(tmp) / "a.js").read_text() == src


def t_deletes_the_labs_own_groundtruth_files():
    """The lab's answer key is named *GROUNDTRUTH*, which the default globs did not
    cover — the safety net protected against hypothetical filenames but not our own."""
    with tempfile.TemporaryDirectory() as tmp:
        rep = _scrub(tmp, {"vulnerable-app-GROUNDTRUTH.md": "V1..V15\n",
                           "vulnerable-app-groundtruth.json": "{}\n",
                           "keep.js": "ok();\n"})
        assert not (Path(tmp) / "vulnerable-app-GROUNDTRUTH.md").exists()
        assert not (Path(tmp) / "vulnerable-app-groundtruth.json").exists()
        assert (Path(tmp) / "keep.js").exists()
        assert len(rep["docs_deleted"]) == 2, rep["docs_deleted"]


def t_doc_glob_with_a_directory_component():
    """A glob like `.cm/rules/*.yaml` must match. Basename-only matching silently
    ignored it, and a ruleset naming every seeded bug reached the agent."""
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / ".cm" / "rules").mkdir(parents=True)
        (Path(tmp) / "src").mkdir()
        (Path(tmp) / ".cm" / "rules" / "harvested.yaml").write_text("rules:\n- id: cm-harvested-example\n")
        (Path(tmp) / "src" / "app.js").write_text("const a=1;\n")
        rep = _scrub(tmp, {}, extra=["--doc", ".cm/rules/*.yaml"])
        assert ".cm/rules/harvested.yaml" in rep["docs_deleted"], rep["docs_deleted"]
        assert (Path(tmp) / "src" / "app.js").exists(), "scrubbed application source"

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("t_")]
    p = 0
    for t in tests:
        try: t(); print(f"PASS  {t.__name__}"); p += 1
        except AssertionError: print(f"FAIL  {t.__name__}")
        except Exception as e: print(f"ER*R  {t.__name__}: {e}")
    print(f"\n{p}/{len(tests)} passed"); sys.exit(0 if p == len(tests) else 1)
