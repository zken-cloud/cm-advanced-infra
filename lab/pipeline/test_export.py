#!/usr/bin/env python3
"""The warehouse path: ledger snapshots, and the gate's own decisions.

Run: python3 test_export.py

Two things are being protected here.

1. Every export is a SNAPSHOT, not a current-state dump. `findings` is mutable --
   verdicts fold upward, fixed_at gets set -- so a single row per fingerprint can
   answer "what is open" and can never answer "was it worse last quarter". The
   duplicates across snapshots ARE the trend history.
2. The gate emits an event on EVERY exit path. A gate that only records the runs
   where it read the ledger successfully reports a BLOCK rate of zero and a RACE
   rate of zero, which is exactly backwards -- RACE is the interesting one.
"""
import importlib.util, json, os, subprocess, sqlite3, sys, tempfile, shutil

_here = os.path.dirname(os.path.abspath(__file__))
_s = importlib.util.spec_from_file_location("ledger", os.path.join(_here, "ledger.py"))
L = importlib.util.module_from_spec(_s); _s.loader.exec_module(L)
_e = importlib.util.spec_from_file_location("lexport", os.path.join(_here, "ledger-export.py"))
X = importlib.util.module_from_spec(_e); _e.loader.exec_module(X)

META = {"cwe_class": "sql-injection", "enclosing_function": "login",
        "canonical_path": "api.js", "source": "verify", "severity": "CRITICAL", "repo": "cm-lab"}
TS1, TS2 = "2026-08-24T01:00:00Z", "2026-08-25T02:00:00Z"


def _ledger(path, verdict="verified", fixed=None):
    db = L.open_ledger(path)
    L.ingest(db, "fp3:a", META, verdict, "cm-0.4.0", "gemini-3", TS1)
    L.record_scan(db, "cm-lab", "deadbeef", 3, 3, "cm-0.4.0", TS1)
    if fixed:
        L.mark_fixed(db, "fp3:a", fixed)
    db.commit(); db.close()


def _rows(d, table, day):
    p = os.path.join(d, table, f"dt={day}")
    out = []
    for f in sorted(os.listdir(p)):
        out += [json.loads(l) for l in open(os.path.join(p, f)) if l.strip()]
    return out


def test_export_layout_and_stamp():
    d = tempfile.mkdtemp()
    try:
        _ledger(os.path.join(d, "l.db"))
        n = X.export(os.path.join(d, "l.db"), os.path.join(d, "wh"), TS1, repo="cm-lab")
        assert n["findings"] == 1 and n["scans"] == 1, n
        r = _rows(os.path.join(d, "wh"), "findings", "2026-08-24")[0]
        assert r["snapshot_ts"] == TS1, "every row must carry the snapshot it came from"
        assert r["severity"] == "CRITICAL" and r["repo"] == "cm-lab", r
    finally:
        shutil.rmtree(d)


def test_snapshots_accumulate_rather_than_overwrite():
    """The same fingerprint, exported twice, must appear twice under two dt=
    partitions. If the second export replaced the first there would be no trend."""
    d = tempfile.mkdtemp()
    try:
        lp = os.path.join(d, "l.db"); wh = os.path.join(d, "wh")
        _ledger(lp)
        X.export(lp, wh, TS1, repo="cm-lab")
        db = L.open_ledger(lp); L.mark_fixed(db, "fp3:a", TS2); db.commit(); db.close()
        X.export(lp, wh, TS2, repo="cm-lab")
        a = _rows(wh, "findings", "2026-08-24")[0]
        b = _rows(wh, "findings", "2026-08-25")[0]
        assert a["fixed_at"] is None and b["fixed_at"] == TS2, (a["fixed_at"], b["fixed_at"])
        assert a["fingerprint"] == b["fingerprint"], "same finding, two points in time"
    finally:
        shutil.rmtree(d)


def test_export_never_writes_the_ledger():
    """The exporter is a reader, like the gate. mode=ro makes it structural."""
    d = tempfile.mkdtemp()
    try:
        lp = os.path.join(d, "l.db"); _ledger(lp)
        before = open(lp, "rb").read()
        X.export(lp, os.path.join(d, "wh"), TS1)
        assert open(lp, "rb").read() == before, "export mutated the ledger"
    finally:
        shutil.rmtree(d)


def _gate(ledger, sha, ev, min_shards=1):
    rc = subprocess.run([sys.executable, os.path.join(_here, "gate-check.py"),
                         "--ledger", ledger, "--repo", "cm-lab", "--sha", sha,
                         "--min-shards", str(min_shards), "--event-out", ev,
                         "--run-id", "42", "--ts", TS1],
                        capture_output=True, text=True).returncode
    got = json.load(open(ev)) if os.path.exists(ev) else None
    return rc, got


def test_gate_emits_on_every_exit_path():
    d = tempfile.mkdtemp()
    try:
        lp = os.path.join(d, "l.db"); ev = os.path.join(d, "e.json")

        rc, e = _gate(os.path.join(d, "missing.db"), "abc", ev)
        assert (rc, e and e["action"]) == (2, "RACE"), (rc, e)          # no ledger at all

        open(os.path.join(d, "bad.db"), "w").write("not a database")
        os.remove(ev)
        rc, e = _gate(os.path.join(d, "bad.db"), "abc", ev)
        assert (rc, e and e["action"]) == (3, "ERROR"), (rc, e)          # unreadable

        _ledger(lp)
        os.remove(ev)
        rc, e = _gate(lp, "deadbeef", ev, min_shards=3)
        assert (rc, e["action"], e["blocking_count"]) == (1, "BLOCK", 1), (rc, e)
        assert e["blocking"] == ["fp3:a"] and e["run_id"] == "42", e

        os.remove(ev)
        rc, e = _gate(lp, "0" * 40, ev)
        assert (rc, e["action"]) == (2, "RACE"), (rc, e)                 # unscanned sha
    finally:
        shutil.rmtree(d)


def test_gate_pass_is_recorded_too():
    """PASS is the denominator. Without it, BLOCK rate is meaningless."""
    d = tempfile.mkdtemp()
    try:
        lp = os.path.join(d, "l.db"); ev = os.path.join(d, "e.json")
        _ledger(lp, fixed=TS2)
        rc, e = _gate(lp, "deadbeef", ev, min_shards=3)
        assert (rc, e["action"], e["blocking_count"]) == (0, "PASS", 0), (rc, e)
    finally:
        shutil.rmtree(d)


def test_gate_survives_a_null_cwe_class():
    """cwe_class is a COLUMN that is often NULL, so .get(k, '?') returns None and
    f"{None:24}" raises. That crashed the gate with exit 1 -- indistinguishable
    from a legitimate BLOCK, and it swallowed the event."""
    d = tempfile.mkdtemp()
    try:
        lp = os.path.join(d, "l.db"); ev = os.path.join(d, "e.json")
        db = L.open_ledger(lp)
        L.ingest(db, "fp3:n", {"source": "verify"}, "verified", "cm", "m", TS1)   # no cwe_class
        L.record_scan(db, "cm-lab", "deadbeef", 3, 3, "cm", TS1)
        db.commit(); db.close()
        rc, e = _gate(lp, "deadbeef", ev, min_shards=3)
        assert rc == 1 and e["action"] == "BLOCK", (rc, e)
    finally:
        shutil.rmtree(d)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    p = 0
    for t in tests:
        try:
            t(); print(f"PASS  {t.__name__}"); p += 1
        except AssertionError as e:
            print(f"FAIL  {t.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{p}/{len(tests)} passed")
    sys.exit(0 if p == len(tests) else 1)
