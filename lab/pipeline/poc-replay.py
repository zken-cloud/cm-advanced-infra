#!/usr/bin/env python3
"""Replay a verified PoC as a regression test — with a mandatory positive control.

Invariant 7 / D15. A verified exploit is the durable capital of the whole design:
once you have paid 20–40 minutes to synthesize it, replaying costs seconds forever.
But a replay that does NOT fire is ambiguous, and that ambiguity is dangerous:

    exploit did not fire  ==  "the vulnerability is fixed"
                          OR  "the harness is broken"

Defaulting to the first reading turns the regression gate into a green light that
means nothing — harness rot. The positive control disambiguates by replaying the
same PoC against the commit where it WAS proven exploitable:

  control fires + candidate fires      -> REGRESSION   (vuln still present)
  control fires + candidate silent     -> FIXED        (trustworthy)
  control silent                       -> HARNESS_BROKEN (candidate result is MEANINGLESS)

A PoC that proves exploitation via an out-of-band callback (DNS/HTTP to a
collaborator host) silently never fires in a sealed network and is indistinguishable
from a fix. Those are detected and refused as regression oracles rather than
silently believed.

  poc-replay.py --poc e.sh --tree ./head --control-tree ./vuln-commit
  poc-replay.py --poc e.sh --tree ./head --control-tree ./vuln --json
"""
import os, re, sys, json, shutil, argparse, subprocess, tempfile

FIRED, NOT_FIRED, ERROR = "fired", "not_fired", "error"
SETUP_FAILED = "setup_failed"

# A PoC that could not reach its target did not "fail to exploit" -- it never ran.
# Invariant 6, in the replay path: a connection refused must NEVER read as fixed.
NO_TARGET = re.compile(r"ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ETIMEDOUT|connection refused"
                       r"|Connection refused|Failed to connect|Empty reply from server", re.I)
PORT_RE = re.compile(r"(?:port\s*[:=]?\s*|listen\(|:)(\d{4,5})(?![\d.])")
# a PoC is only admissible as a Tier-1+ oracle if it starts its own target
SELF_BOOT = re.compile(r"app\.listen|server_runner|\.listen\s*\(|npm\s+start|node\s+\S*server", re.I)
# Absolute paths baked into a PoC pin it to the tree it was BORN in. Then it
# always exercises that tree, whatever candidate the harness is pointed at --
# and the positive control cannot detect it, because BOTH replays boot the same
# hardcoded tree and dutifully agree. Only a static check catches this.
ABS_PATH = re.compile(r"""["\x27\s(](/(?:tmp|home|work|Users|var|opt)/[A-Za-z0-9._/-]+)""")

# a PoC reaching any of these is talking to a host we do not control
EXTERNAL_HOST = re.compile(
    r"""https?://(?!(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|host\.docker\.internal))"""
    r"""[A-Za-z0-9.\-]+""", re.I)
CALLBACK_HINT = re.compile(r"\b(burpcollaborator|interact\.sh|oast\.|ngrok|requestbin|webhook\.site|dnslog)\b", re.I)

# Tier is what the PoC NEEDS, not what it does. Tier 1 said "boots the app", which
# is a claim about the PoC -- and it is the wrong claim: tier is decided by whether
# the text mentions a runtime, while whether it actually starts its own target is
# `self_booting`, computed separately. A tier-1 PoC that does not self-boot is
# inadmissible, so a label asserting it boots the app describes the opposite of the
# case you most need to notice.
TIERS = {0: "in-process, no server", 1: "needs a runtime", 2: "needs full stack"}


def audit_poc(poc_path):
    """Static checks that decide whether this PoC can serve as a regression oracle."""
    text = open(poc_path, encoding="utf8", errors="replace").read()
    externals = sorted(set(EXTERNAL_HOST.findall(text)))
    callbacks = sorted(set(CALLBACK_HINT.findall(text)))
    return {
        "external_hosts": externals,
        "callback_service": callbacks,
        # out-of-band proof cannot be trusted in a sealed network: no fire != fixed
        "oracle_safe": not callbacks and not externals,
        "tier": 0 if not re.search(r"\b(node|npm|python3?|serve|listen|curl)\b", text) else
                (2 if re.search(r"\b(docker|compose|postgres|mysql|redis)\b", text, re.I) else 1),
    }


def audit_self_sufficiency(poc_path):
    """A Tier-1+ PoC that does NOT boot its own target is inadmissible as a
    regression oracle, and dangerously so: measured, the same PoC reported
    REGRESSION when a stale server from an earlier run happened to be listening,
    and FIXED (ECONNREFUSED) when nothing was -- wrong in both directions, with
    the vulnerability unchanged either way. Record the ports it expects so the
    replay can assert nothing else already owns them."""
    text = open(poc_path, encoding="utf8", errors="replace").read()
    a = audit_poc(poc_path)
    here = os.path.dirname(os.path.abspath(poc_path))
    # `/opt/cm/` is the HARNESS, not the tree under test. A PoC referencing the
    # oracle runner is pinned to its runner the way any test is pinned to its test
    # framework -- it still exercises whatever tree it is pointed at, which is the
    # only property `pinned_paths` exists to protect. What must never be baked in is
    # a path into the tree the PoC was BORN in (D47's server_runner.js case).
    pinned = sorted({m for m in ABS_PATH.findall(text)
                     if not os.path.abspath(m).startswith(here)
                     and not m.startswith("/opt/cm/")})
    self_boot = bool(SELF_BOOT.search(text))
    return {
        "tier": a["tier"],
        "self_booting": self_boot,
        "expects_ports": sorted({int(x) for x in PORT_RE.findall(text) if 1024 < int(x) < 65536}),
        "pinned_paths": pinned,
        "admissible": (a["tier"] == 0 or self_boot) and not pinned,
    }


def audit_bundle(poc_path):
    """Audit the whole PoC DIRECTORY, not just the entry script.

    A PoC is a bundle. `exploit.sh` was clean while the `server_runner.js` it
    invokes hardcoded /tmp/vt1/src/app.js -- auditing only the entry point passed
    a PoC that can never test anything but the tree it was born in.
    """
    here = os.path.dirname(os.path.abspath(poc_path))
    agg = audit_self_sufficiency(poc_path)
    agg["bundle_files"] = []
    for name in sorted(os.listdir(here)):
        f = os.path.join(here, name)
        if not os.path.isfile(f) or os.path.splitext(name)[1] not in (".sh", ".js", ".py", ".yaml", ".yml", ""):
            continue
        agg["bundle_files"].append(name)
        try:
            sub = audit_self_sufficiency(f)
        except Exception:
            continue
        agg["self_booting"] = agg["self_booting"] or sub["self_booting"]
        agg["expects_ports"] = sorted(set(agg["expects_ports"]) | set(sub["expects_ports"]))
        agg["pinned_paths"] = sorted(set(agg["pinned_paths"]) | set(sub["pinned_paths"]))
    # An ORACLE bundle boots its target by construction: `oracle-run.py` starts the
    # app from the spec's `boot` command, waits for readiness, and tears down the
    # process group it created. That is a fact about the runner, not a string in a
    # script, so the SELF_BOOT text heuristic cannot see it and would mark the most
    # reliably self-booting PoC in the corpus inadmissible (D50).
    if os.path.exists(os.path.join(here, "cm-oracle.json")):
        agg["oracle_bundle"] = True
        agg["self_booting"] = True
    agg["admissible"] = (agg["tier"] == 0 or agg["self_booting"]) and not agg["pinned_paths"]
    # Carry the out-of-band checks alongside the self-sufficiency ones so a single
    # call answers the whole question. Admissibility and oracle-safety are separate
    # failure modes -- a PoC can boot its own target and still prove nothing in a
    # sealed network -- and splitting them across two functions is how a caller ends
    # up reporting one and silently ignoring the other.
    for k, v in audit_poc(poc_path).items():
        agg.setdefault(k, v)
    return agg


def ports_busy(ports):
    """Ports already listening. A replay against a port someone else owns tests
    THAT process, not the tree under test."""
    import socket
    busy = []
    for p in ports:
        s = socket.socket()
        s.settimeout(0.3)
        try:
            if s.connect_ex(("127.0.0.1", p)) == 0:
                busy.append(p)
        finally:
            s.close()
    return busy


def replay(poc_path, tree, timeout=180, env=None):
    """Run the PoC against an isolated COPY of `tree` (exploits mutate state).
    Contract: exit 0 and/or 'EXPLOIT SUCCESSFUL' means fired."""
    if not os.path.isdir(tree):
        return ERROR, {"reason": f"tree not found: {tree}"}
    with tempfile.TemporaryDirectory(prefix="replay-") as work:
        dst = os.path.join(work, "t")
        try:
            shutil.copytree(tree, dst, symlinks=True,
                            ignore=shutil.ignore_patterns(".git"))
        except OSError as e:
            return ERROR, {"reason": f"copy failed: {e}"}
        # Copy the WHOLE bundle, not just the entry script. A PoC that invokes a
        # helper (server_runner.js) could otherwise never boot its target, and the
        # missing file surfaced as HARNESS_BROKEN -- a correct refusal for entirely
        # the wrong reason.
        bundle = os.path.dirname(os.path.abspath(poc_path))
        # Stage into `.exploit/` specifically. cm creates the bundle there and the
        # exploit's own relative paths (`node .exploit/server_runner.js >
        # .exploit/server.log`) depend on it -- but capture does
        # `tar -C $POCDIR .`, which FLATTENS the prefix away. Reconstruct it, or
        # every multi-file PoC fails on a missing file and reads as not_fired.
        staged = os.path.join(dst, ".exploit")
        shutil.copytree(bundle, staged, dirs_exist_ok=True)
        poc = os.path.join(staged, os.path.basename(poc_path))
        os.chmod(poc, 0o755)
        e = dict(os.environ)
        # CM_TARGET is the tree UNDER TEST for this particular replay. It must be
        # rebound per call: pinning it once makes the control and the candidate
        # exercise the same tree, which is the defect normalisation exists to remove.
        e["CM_TARGET"] = os.path.abspath(tree)
        e.setdefault("CM_WORK", os.path.join(work, "scratch"))
        os.makedirs(e["CM_WORK"], exist_ok=True)
        e.update(env or {})
        try:
            p = subprocess.run(["bash", poc], cwd=dst, env=e, timeout=timeout,
                               capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            return ERROR, {"reason": f"timeout after {timeout}s"}
        out = (p.stdout or "") + (p.stderr or "")
        fired = p.returncode == 0 or "EXPLOIT SUCCESSFUL" in out
        if fired:
            return FIRED, {"rc": p.returncode, "tail": out[-400:]}
        # Did not fire -- but WHY? "nothing was listening" is a setup failure, not
        # evidence of a fix. Collapsing the two is how a live vulnerability gets
        # recorded as remediated.
        if NO_TARGET.search(out):
            return SETUP_FAILED, {"rc": p.returncode, "tail": out[-400:],
                                  "reason": "could not reach the target -- the PoC never ran"}
        return NOT_FIRED, {"rc": p.returncode, "tail": out[-400:]}


def check(poc_path, tree, control_tree, timeout=180, env=None):
    """The full oracle. Returns a verdict dict; `trustworthy` is the field that
    decides whether a gate may act on it."""
    audit = audit_poc(poc_path)
    suff = audit_bundle(poc_path)
    audit.update(suff)

    if not audit["oracle_safe"]:
        return {"verdict": "UNTRUSTED_POC", "trustworthy": False, "audit": audit,
                "reason": "PoC proves exploitation out-of-band; in a sealed network "
                          "'did not fire' is indistinguishable from 'fixed'"}

    # Judged after out-of-band, which is the more specific defect: a callback PoC
    # is untrustworthy whether or not it boots its own target.
    # A Tier-1+ PoC that cannot boot its own target is INADMISSIBLE, and the reason
    # is not tidiness. Measured on a real corpus entry: with a stale server from an
    # earlier run listening on its port it reported REGRESSION; with the port free
    # it got ECONNREFUSED and read as FIXED. Same PoC, same unchanged vulnerability,
    # opposite verdicts decided by ambient state.
    if suff["pinned_paths"]:
        return {"verdict": "INADMISSIBLE_POC", "trustworthy": False, "audit": audit,
                "reason": f"PoC hardcodes absolute path(s) {suff['pinned_paths']} outside its own "
                          f"directory, so it exercises THAT tree whatever candidate it is given. "
                          f"Demonstrated: a fully fixed candidate still reported EXPLOIT "
                          f"SUCCESSFUL, and the positive control agreed, because both replays "
                          f"booted the same pinned tree"}
    if not suff["admissible"]:
        return {"verdict": "INADMISSIBLE_POC", "trustworthy": False, "audit": audit,
                "reason": f"tier-{suff['tier']} PoC does not start its own target, so its "
                          f"verdict is decided by whatever happens to be listening on "
                          f"{suff['expects_ports'] or 'its port'} — not by the code under test"}

    # Nothing else may already own the ports it needs, or the replay tests that
    # process instead of the tree.
    busy = ports_busy(suff["expects_ports"])
    if busy:
        return {"verdict": "PORT_CONFLICT", "trustworthy": False, "audit": audit,
                "reason": f"port(s) {busy} already listening — a replay here would "
                          f"exercise a foreign process, not this tree"}

    # POSITIVE CONTROL FIRST — never interpret the candidate before proving the harness.
    c_out, c_ev = replay(poc_path, control_tree, timeout, env)
    if c_out != FIRED:
        return {"verdict": "HARNESS_BROKEN", "trustworthy": False, "audit": audit,
                "control": {"outcome": c_out, **c_ev},
                "reason": "PoC does not fire on the commit where it was PROVEN "
                          "exploitable — the harness has rotted; any result against "
                          "the candidate is meaningless (invariant 7)"}

    h_out, h_ev = replay(poc_path, tree, timeout, env)
    if h_out in (ERROR, SETUP_FAILED):
        return {"verdict": "REPLAY_ERROR", "trustworthy": False, "audit": audit,
                "candidate": {"outcome": h_out, **h_ev},
                "reason": "replay could not run or could not reach the target — "
                          "never recorded as fixed (invariant 6)"}
    if h_out == FIRED:
        return {"verdict": "REGRESSION", "trustworthy": True, "audit": audit,
                "control": {"outcome": c_out}, "candidate": {"outcome": h_out, **h_ev},
                "reason": "the exploit still fires — the vulnerability is present"}
    return {"verdict": "FIXED", "trustworthy": True, "audit": audit,
            "control": {"outcome": c_out}, "candidate": {"outcome": h_out, **h_ev},
            "reason": "control fires, candidate does not — genuinely fixed"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--poc", required=True)
    ap.add_argument("--tree", required=True, help="candidate tree (the code under test)")
    ap.add_argument("--control-tree", help="commit where the PoC was PROVEN exploitable")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--audit-only", action="store_true")
    a = ap.parse_args()

    if a.audit_only:
        # Audit the BUNDLE and report `admissible`. This used to print audit_poc()
        # alone, which omits self_booting/pinned_paths -- i.e. it omitted the field
        # that DECIDES whether the PoC can be an oracle, while printing a tier label
        # that reads "(boots the app)" for any PoC merely mentioning node. Auditing a
        # 9-PoC corpus with this flag returned nothing that answered the question,
        # and a caller keying on the absent `admissible` scores every PoC the same
        # way regardless of truth. An audit that cannot state its own verdict is
        # worse than no audit: it looks like it answered.
        r = audit_bundle(a.poc)
        print(json.dumps(r, indent=2) if a.json else
              f"tier={r['tier']} ({TIERS[r['tier']]})  ADMISSIBLE={r['admissible']}  "
              f"self_booting={r['self_booting']}  oracle_safe={r['oracle_safe']}  "
              f"pinned={r['pinned_paths']}  external={r['external_hosts']}  "
              f"callback={r['callback_service']}")
        return
    if not a.control_tree:
        sys.exit("--control-tree is required: without a positive control a silent "
                 "replay cannot be distinguished from a fix (invariant 7)")

    r = check(a.poc, a.tree, a.control_tree, a.timeout)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"{r['verdict']}  (trustworthy={r['trustworthy']})\n  {r['reason']}")
    # exit non-zero on anything a gate must not treat as clean
    sys.exit(0 if r["verdict"] == "FIXED" else 1)


if __name__ == "__main__":
    main()
