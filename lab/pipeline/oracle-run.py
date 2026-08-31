#!/usr/bin/env python3
"""Run the non-functional oracle a finding needs, from a per-target spec.

`oracle-route.py` answers *which* harness a finding needs. `oracles.py` holds the
harnesses. Neither could run one, because an oracle takes a URL and callables and a
verify pod has a CWE list. This is the middle: a per-target YAML says which endpoint
to drive and with what, and this turns that into the callables the oracle wants.

WHY A SPEC AND NOT EXTRACTION FROM CM'S ARTEFACTS. Extraction needs no config and
works on any target, and it fails silently: when CM's artefact shape drifts the
extractor finds nothing, the oracle never runs, and the finding degrades to a
verdict nobody notices is unearned. A missing spec entry is loud and its failure
mode is `unproven`, which costs a re-verify and cannot cache a negative on a live
bug (D50).

VERDICTS. This is the whole point of building the oracles, so it is worth being
exact about what changed:

  fired                     -> verified       the oracle proved its claim
  ran cleanly, did not fire -> exploit_failed a CAPABLE instrument found nothing.
                                              Before the oracles existed this class
                                              could only reach `unproven`, because
                                              the only instrument available was one
                                              that structurally could not succeed
                                              (D47). A real negative is now
                                              reachable, and that is the gain.
  OracleSetupError          -> setup_failed   invariant 6: could not run != negative
  boot/readiness failure    -> setup_failed   likewise
  no spec entry matches     -> unproven       never a negative, and says so loudly

Evidence always carries the spec's `claim` string, so the ledger records the narrow
property that was proven rather than the CWE's worst-case reading. Whether that
property matters is `impact_review`, and that is a human's (D28).

  oracle-run.py --fp3 'cryptoUtils.js::generateSessionContextId' \
                --cwe-class weak-random --spec targets/oracle-specs/vulnerable-app.yaml \
                --project-root /work/clone --out /tmp/oracle.json
"""
import os
import sys
import time
import json
import signal
import argparse
import subprocess
import urllib.request
import urllib.error
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# --------------------------------------------------------------- predictors
def _base36(n):
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    if n == 0:
        return "0"
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = digits[r] + out
    return out


def _predictor(name, chars):
    """Named predictors. A predictor derives the next value WITHOUT observing it —
    anything that reads `seen` to extrapolate is a different (weaker) claim and
    would need its own name here."""
    if name == "base36-millis":
        # Date.now().toString(36), truncated to `chars`. Ignores `seen` on purpose:
        # the claim is that the attacker's own clock is enough.
        return lambda seen: _base36(int(time.time() * 1000))[:chars]
    raise ValueError(f"unknown predictor {name!r}")


# --------------------------------------------------------------- http
def _request(base, defaults, rq, seq=None):
    """Build and send one declarative request; return (elapsed_s, status, body)."""
    method = rq.get("method", "POST").upper()
    url = base + rq["path"]
    headers = dict(defaults.get("headers") or {})
    headers.update(rq.get("headers") or {})
    body = rq.get("body")
    data = None
    if body is not None:
        raw = json.dumps(body)
        if seq is not None:
            raw = raw.replace("{seq}", str(seq))
        data = raw.encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=rq.get("timeout", 30)) as r:
            return time.perf_counter() - t0, r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        return time.perf_counter() - t0, e.code, e.read(65536)


def _extract(body, rule):
    """Pull the value under test out of a response."""
    if "json" in rule:
        return json.loads(body.decode())[rule["json"]]
    if "regex" in rule:
        import re
        m = re.search(rule["regex"], body.decode())
        if not m:
            raise OracleSetupErrorProxy(f"extract regex {rule['regex']!r} matched nothing")
        return m.group(1)
    raise ValueError(f"unsupported extract rule {rule!r}")


class OracleSetupErrorProxy(RuntimeError):
    """Raised before the oracles module is loaded; re-raised as OracleSetupError."""


# --------------------------------------------------------------- app lifecycle
class App:
    """Boots the target under its own process group so teardown can never reach
    anything it did not start.

    D46 is the reason this is a class and not two lines of `pkill`: a pattern-based
    kill in a verify pod matched PID 1's own command line — the shell running the
    whole script — and four pods that had computed `verified` published
    `not_found`. Killing a process group we created has no pattern to get wrong."""

    def __init__(self, cfg, project_root, log, skip_install=False, env_overlay=None):
        self.cfg, self.root, self.log = cfg, project_root, log
        self.skip_install = skip_install
        self.env_overlay = env_overlay or {}
        self.proc = None

    def start(self):
        env = dict(os.environ)
        env.update({k: str(v) for k, v in (self.cfg.get("env") or {}).items()})
        env.update({k: str(v) for k, v in self.env_overlay.items()})
        install = None if self.skip_install else self.cfg.get("install")
        if install:
            r = subprocess.run(install, cwd=self.root, env=env, capture_output=True,
                               text=True, timeout=600)
            if r.returncode != 0:
                raise OracleSetupErrorProxy(
                    f"install failed rc={r.returncode}: {r.stderr[-800:]}")
        self.proc = subprocess.Popen(
            self.cfg["boot"], cwd=self.root, env=env,
            stdout=open(self.log, "wb"), stderr=subprocess.STDOUT,
            start_new_session=True)
        self._await_ready()
        return self.proc.pid

    def _await_ready(self):
        base = self.cfg["base"]
        ready = self.cfg.get("ready")
        deadline = time.time() + self.cfg.get("ready_timeout_s", 60)
        last = "no attempt made"
        while time.time() < deadline:
            if self.proc.poll() is not None:
                tail = open(self.log, "rb").read()[-800:].decode(errors="replace")
                raise OracleSetupErrorProxy(
                    f"app exited rc={self.proc.returncode} before ready: {tail}")
            try:
                # Any HTTP answer means the listener is up. A 4xx is ready.
                _request(base, {}, ready)
                return
            except Exception as e:            # connection refused while booting
                last = repr(e)
            time.sleep(0.4)
        raise OracleSetupErrorProxy(f"not ready within timeout; last attempt: {last}")

    def stop(self):
        if not self.proc or self.proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            self.proc.wait(timeout=15)
        except Exception:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except Exception:
                pass


# --------------------------------------------------------------- spec matching
def _suffix(spec_path, actual_path):
    """Does the spec's path name the same file? Segment-boundary suffix match.

    `consolidate-dedup.relpath` is basename today and clone-root-relative in prod,
    so a spec written against one form must still match the other. The boundary
    check is what keeps `cache.js` from matching `mediaCache.js`."""
    if spec_path == actual_path:
        return True
    return actual_path.endswith("/" + spec_path) or spec_path.endswith("/" + actual_path)


def select(spec, fp3, cwe_class):
    """Most specific wins: exact fp3, then `path::*`, then a path-suffix match on
    the same function, then the finding's class.

    Returns None when nothing matches, which is a verdict of its own — see module
    docstring. It is never treated as "the oracle ran and found nothing".

    An AMBIGUOUS suffix match returns None rather than guessing. Two files that end
    the same way are exactly where a wrong guess would drive the wrong endpoint and
    call the answer evidence."""
    entries = spec.get("oracles") or []
    for e in entries:
        if e.get("match", {}).get("fp3") == fp3:
            return e

    fpath, _, ffunc = (fp3 or "").partition("::")
    for e in entries:
        m = e.get("match", {}).get("fp3", "")
        if m.endswith("::*") and fpath and _suffix(m[:-3], fpath):
            return e

    hits = []
    for e in entries:
        m = e.get("match", {}).get("fp3", "")
        sp, _, sf = m.partition("::")
        if sf and ffunc and sf == ffunc and _suffix(sp, fpath):
            hits.append(e)
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        return None

    for e in entries:
        if e.get("match", {}).get("cwe_class") == cwe_class:
            return e
    return None


# --------------------------------------------------------------- dispatch
def run_entry(entry, app_cfg, defaults, oracles, pid):
    """Turn declarative params into the callables the oracle wants, and call it."""
    base = app_cfg["base"]
    name = entry["oracle"]
    p = dict(entry.get("params") or {})

    if name == "wall-clock-timeout-oracle":
        return oracles.wall_clock_timeout(
            base + p["path"], p["benign"], p["malicious"],
            bound_s=p.get("bound_s", 2.0), timeout=p.get("timeout", 30))

    if name == "predictability-oracle":
        rq, rule = p["request"], p["extract"]

        def generator():
            _, _, body = _request(base, defaults, rq)
            return _extract(body, rule)

        chars = p.get("predict_chars")
        return oracles.predictability(
            generator, samples=p.get("samples", 5),
            predict=_predictor(p["predict"], chars),
            project=(lambda v: v[:chars]) if chars else None)

    if name == "statistical-timing-oracle":
        rt, rf = p["request_true"], p["request_false"]
        return oracles.statistical_timing(
            lambda: _request(base, defaults, rt)[0],
            lambda: _request(base, defaults, rf)[0],
            n=p.get("n", 400), min_effect=p.get("min_effect", 0.15))

    if name == "rss-growth-oracle":
        rq = p["drive"]
        counter = {"n": 0}

        def drive():
            counter["n"] += 1
            _request(base, defaults, rq, seq=counter["n"])

        return oracles.rss_growth(
            pid, drive, rounds=p.get("rounds", 12), per_round=p.get("per_round", 25),
            min_growth_kb=p.get("min_growth_kb", 4096))

    raise ValueError(f"no runner for oracle {name!r}")


# --------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fp3", required=True)
    ap.add_argument("--cwe-class", default="")
    ap.add_argument("--spec", required=True)
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--log", default="/tmp/oracle-app.log")
    ap.add_argument("--bank", help="directory to write a replayable PoC bundle into "
                                   "(only written when the oracle fires)")
    ap.add_argument("--passes", type=int, default=int(os.environ.get("VERIFY_MIN_PASSES", "2")),
                    help="minimum independent passes before a NON-fired result is "
                         "admissible as a negative (default 2). A fire stops early.")
    a = ap.parse_args()

    import yaml
    oracles = _load("oracles", "oracles.py")
    result = {"fp3": a.fp3, "cwe_class": a.cwe_class, "spec": os.path.basename(a.spec),
              "runtime": runtime_env()}

    if not os.path.exists(a.spec):
        result.update(verdict="unproven", oracle=None,
                      reason=f"no oracle spec for this target ({a.spec})")
        return _emit(result, a.out)

    spec = yaml.safe_load(open(a.spec)) or {}
    entry = select(spec, a.fp3, a.cwe_class)
    if entry is None:
        result.update(verdict="unproven", oracle=None,
                      reason=f"no spec entry matches fp3={a.fp3!r} or class={a.cwe_class!r}; "
                             f"this finding was NOT tested and must not cache as a negative")
        return _emit(result, a.out)

    result["oracle"] = entry["oracle"]
    result["claim"] = " ".join((entry.get("claim") or "").split())

    app = None
    try:
        # INDEPENDENT PASSES BEFORE A NEGATIVE IS ADMISSIBLE (P6/D52).
        #
        # A fire is monotonic -- one proof is enough and further passes cannot
        # unprove it -- so success stops immediately. A NON-fire is the case that
        # needs corroboration: the underlying detector is ~30% non-deterministic,
        # and the noisier oracles (RSS thresholds, timing separation) have a real
        # false-negative rate of their own. One quiet pass is a sample, not a result,
        # and caching it as a negative is how a live bug reads as "checked, clean".
        #
        # This matters MORE since the oracles started running, not less: D50 made a
        # real negative reachable for the first time, and reachable from a single
        # pass is not the same as earned.
        # EVERY pass runs; there is no early exit on a fire. The first version of
        # this stopped as soon as the oracle fired, on the reasoning that a proof is
        # monotonic. That reasoning holds for a working exploit and NOT for a
        # threshold: measured on V1, two runs of the RSS oracle against byte-identical
        # source returned 3264 KB (silent) and 4172 KB (fired) against a 4096 KB
        # bound -- opposite verdicts, 1.9% either side of the line. An early exit
        # would have recorded the fire as proof and never seen the disagreement.
        #
        # A FRESH APP PER PASS. The first version reused one process and produced a
        # disagreement that was an artefact of the harness, not a fact about the
        # code: V15's pass 2 started against the ~350 MB pass 1 had already leaked,
        # so its baseline was contaminated and its RSS series no longer rose
        # monotonically. A second measurement inside a polluted process is not an
        # independent pass, it is a continuation. `npm install` still runs once.
        # RUNTIME VARIANTS (P6b/D56). For a class whose answer depends on the runtime
        # rather than on the code, passes under ONE configuration are not independent
        # in the way that matters. Measured: V1 fires 2/2 in a GKE pod at ~20 MB of
        # growth and 2/2 does NOT on the lab VM at ~2.5 MB, same source, same bound.
        # Both runs unanimous, and contradicting each other.
        #
        # The mechanism is not mystery: V8 sizes its old-space from the container's
        # memory ceiling, so a GC verdict is a statement about a heap size. Varying
        # `--max-old-space-size` across passes tests exactly that variable, in one
        # pod, instead of paying for a second pod to maybe land on a different node.
        variants = entry.get("runtime_variants") or spec["app"].get("runtime_variants") or [{}]
        passes = []
        for i in range(max(1, a.passes)):
            overlay = variants[i % len(variants)]
            app = App(spec["app"], a.project_root, f"{a.log}.{i}",
                      skip_install=(i > 0), env_overlay=overlay)
            pid = app.start()
            try:
                f, ev = run_entry(entry, spec["app"], spec.get("defaults") or {},
                                  oracles, pid)
            finally:
                app.stop()
            passes.append({"pass": i + 1, "fired": f, "evidence": ev,
                           "runtime_variant": overlay or None})
        outcomes = {p["fired"] for p in passes}
        evidence = passes[-1]["evidence"]
        if len(outcomes) > 1:
            # The instrument could not separate this finding from its own noise.
            # That is precisely `unproven`: not proven, and NOT evidence of absence.
            # Recording either side would be reporting the coin, not the bug.
            fired = False
            verdict = "unproven"
        else:
            fired = passes[0]["fired"]
            verdict = "verified" if fired else "exploit_failed"
        result.update(verdict=verdict, fired=fired, evidence=evidence,
                      passes_run=len(passes), passes_required=max(1, a.passes),
                      passes_agreed=len(outcomes) == 1, passes=passes)
        result["runtime_variants_used"] = [p["runtime_variant"] for p in passes]
        if len(outcomes) > 1:
            varied = len({json.dumps(p["runtime_variant"], sort_keys=True) for p in passes}) > 1
            result["reason"] = (
                "oracle passes disagreed across RUNTIME VARIANTS -- the verdict is a "
                "property of the heap configuration, not of the code, so neither a "
                "proof nor a negative is earned"
                if varied else
                "oracle passes disagreed on byte-identical source -- the finding is "
                "inside this instrument's noise band, so neither a proof nor a "
                "negative is earned")
        if fired and a.bank:
            bank(a.bank, spec, entry, result)
    except oracles.OracleSetupError as e:
        result.update(verdict="setup_failed", reason=str(e))
    except OracleSetupErrorProxy as e:
        result.update(verdict="setup_failed", reason=str(e))
    except Exception as e:
        result.update(verdict="setup_failed", reason=f"{type(e).__name__}: {e}")
    finally:
        if app:
            app.stop()

    return _emit(result, a.out)


REPLAY = """#!/usr/bin/env bash
# Positive-control replay for an ORACLE-verified finding (invariant 7).
#
# The exploit for this finding is not a script -- it is an instrument plus the
# parameters to point it at. Both travel in this bundle, so the replay is the same
# measurement that proved the finding, run against a different tree.
#
# Run from inside the candidate tree. Exit 0 means the oracle FIRED, i.e. the
# vulnerability is still present. Anything else is not-fired or could-not-run, and
# poc-replay.py distinguishes those against the control tree.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${CM_ORACLE_RUN:-/opt/cm/oracle-run.py}" \
  --fp3 %(fp3)s \
  --cwe-class %(cls)s \
  --spec "$HERE/oracle-spec.yaml" \
  --project-root "${1:-.}" \
  --out "$(mktemp -t oracle-replay.XXXXXX)"
"""


def bank(dest, spec, entry, result):
    """Write a replayable PoC bundle: the instrument's parameters, and a script that
    re-runs the measurement.

    A verified finding whose proof is discarded has paid full price for a one-shot
    answer. That applies to an oracle exactly as it does to an exploit script — the
    difference is only that what gets banked is the spec entry rather than the
    synthesized code."""
    import shlex
    os.makedirs(dest, exist_ok=True)
    # Only this finding's entry, plus the app block it needs to boot. Banking the
    # whole target spec would make every replay carry every other finding's params.
    trimmed = {"target": spec.get("target"), "app": spec["app"],
               "defaults": spec.get("defaults") or {}, "oracles": [entry]}
    import yaml
    with open(os.path.join(dest, "oracle-spec.yaml"), "w") as f:
        yaml.safe_dump(trimmed, f, sort_keys=False, allow_unicode=True)
    with open(os.path.join(dest, "cm-oracle.json"), "w") as f:
        json.dump(result, f, indent=2)
    rp = os.path.join(dest, "replay.sh")
    with open(rp, "w") as f:
        f.write(REPLAY % {"fp3": shlex.quote(result["fp3"]),
                          "cls": shlex.quote(result.get("cwe_class") or "")})
    os.chmod(rp, 0o755)


def runtime_env():
    """The environment a measurement was taken in.

    Measured 2026-08-25: V1 (closure retention) fires 2/2 in a GKE pod at ~20 MB of
    growth and 2/2 NOT on the lab VM at ~2.5 MB, against the same 4 MB bound and the
    same source. Both runs are internally unanimous, so D52's corroboration check
    passes in each -- and they contradict each other. Unanimity within one runtime is
    not reproducibility across runtimes.

    For a GC-sensitive oracle that is not noise, it is the answer changing with heap
    sizing: a verdict of this class is only meaningful relative to where it was
    taken. So it travels with the verdict rather than being reconstructed later from
    a pod name nobody kept."""
    env = {}
    try:
        env["node"] = subprocess.run(["node", "--version"], capture_output=True,
                                     text=True, timeout=10).stdout.strip()
    except Exception:
        env["node"] = None
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    env["mem_total_kb"] = int(line.split()[1]); break
    except OSError:
        pass
    try:
        env["cpus"] = os.cpu_count()
        # cgroup v2 memory ceiling: what the CONTAINER may use, which is what
        # actually sizes the heap. MemTotal is the node's and is not the constraint.
        with open("/sys/fs/cgroup/memory.max") as f:
            v = f.read().strip()
            env["cgroup_memory_max"] = None if v == "max" else int(v)
    except OSError:
        pass
    for k in ("NODE_OPTIONS",):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def _emit(result, out):
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result))
    # Exit code carries the verdict for the shell: 0 verified, 1 everything else.
    # The pod reads the JSON; this is only so a bare `if` reads correctly.
    return 0 if result.get("verdict") == "verified" else 1


if __name__ == "__main__":
    sys.exit(main())
