#!/usr/bin/env python3
"""Make a captured PoC relocatable, so it can serve as a regression test.

Run this at CAPTURE time, before the tarball is published. CM writes exploits that
work perfectly where they were born and nowhere else:

  * `server_runner.js` requires `/tmp/vt1/src/app.js` -- an absolute path to the
    verify pod's own tree. Replayed against any other checkout it still boots THAT
    tree, so a fully fixed candidate reports EXPLOIT SUCCESSFUL. Measured on all
    four banked PoCs: 3 of 4 pinned this way.
  * artefacts land on fixed paths like `/tmp/rce-test`, so two replays collide.
  * some PoCs never boot a target at all, and their verdict is then decided by
    whatever happens to be listening on the port.

The positive control (invariant 7) cannot catch any of this: both the control and
the candidate replay boot the same pinned tree and agree. Only rewriting the paths
fixes it.

    poc-normalise.py <poc-dir> --tree /work/c0 [--check]
"""
import argparse, os, re, sys

TREE_VAR = "${CM_TARGET}"
WORK_VAR = "${CM_WORK}"
TEXT_EXT = (".sh", ".js", ".py", ".yaml", ".yml", ".json", ".md")

PREAMBLE = """# --- injected by poc-normalise.py: makes this PoC relocatable ---
# CM_TARGET is the tree under test; CM_WORK is a scratch dir for artefacts.
# Without these the PoC hardcodes the checkout it was created in and will report
# the vulnerability present no matter what it is pointed at.
: "${CM_TARGET:?set CM_TARGET to the tree under test}"
: "${CM_WORK:=$(mktemp -d)}"
export CM_TARGET CM_WORK
# --- end injected block ---
"""


def rewrite(text, tree, is_shell):
    """Point tree references at CM_TARGET and scratch artefacts at CM_WORK."""
    n = 0
    tree = tree.rstrip("/")
    # the verify tree itself -> CM_TARGET
    for pat in (re.escape(tree), r"/tmp/vt\d+", r"/work/c\d+"):
        text, k = re.subn(pat, TREE_VAR if is_shell else "' + process.env.CM_TARGET + '", text)
        n += k
    # fixed scratch artefacts -> CM_WORK (skip real system paths)
    def scratch(m):
        p = m.group(0)
        if re.match(r"^/tmp/(?:vt\d+|c\d+)$", p) or p in ("/tmp",):
            return p
        return (WORK_VAR if is_shell else "' + process.env.CM_WORK + '") + "/" + os.path.basename(p)
    text, k = re.subn(r"/tmp/[A-Za-z0-9._-]+(?:\.[A-Za-z0-9]+)?", scratch, text)
    return text, n + k


def normalise(poc_dir, tree, check_only=False):
    changed, findings = [], []
    # Does ANY file in the bundle depend on CM_TARGET? If so the entry script must
    # declare it, even if the entry script itself contains no tree path -- the
    # helper it invokes will otherwise resolve CM_TARGET to the empty string and
    # boot nothing, which reads as "fixed".
    needs_env = False
    for n_ in os.listdir(poc_dir):
        f_ = os.path.join(poc_dir, n_)
        if os.path.isfile(f_) and os.path.splitext(n_)[1] in TEXT_EXT:
            t_ = open(f_, encoding="utf8", errors="replace").read()
            if re.search(re.escape(tree.rstrip("/")) + r"|/tmp/vt\d+|/work/c\d+", t_):
                needs_env = True
    for name in sorted(os.listdir(poc_dir)):
        f = os.path.join(poc_dir, name)
        if not os.path.isfile(f) or os.path.splitext(name)[1] not in TEXT_EXT:
            continue
        try:
            orig = open(f, encoding="utf8", errors="replace").read()
        except OSError:
            continue
        is_shell = name.endswith(".sh")
        new, n = rewrite(orig, tree, is_shell)
        if is_shell and needs_env and TREE_VAR not in new:
            n += 1                       # force the preamble into the entry script
        if is_shell and "CM_TARGET:?" not in new:
            lines = new.split("\n")
            i = 1 if lines and lines[0].startswith("#!") else 0
            new = "\n".join(lines[:i] + [PREAMBLE] + lines[i:])
        if new != orig:
            changed.append((name, n))
            if not check_only:
                open(f, "w").write(new)
    # still-pinned absolute paths after rewriting are a hard failure
    for name in sorted(os.listdir(poc_dir)):
        f = os.path.join(poc_dir, name)
        if not os.path.isfile(f) or os.path.splitext(name)[1] not in TEXT_EXT:
            continue
        t = open(f, encoding="utf8", errors="replace").read()
        for m in re.findall(r"['\"\s(](/(?:tmp|home|work|Users)/[A-Za-z0-9._/-]+)", t):
            if not m.startswith(os.path.abspath(poc_dir)):
                findings.append(f"{name}: still pinned to {m}")
    return changed, findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("poc_dir")
    ap.add_argument("--tree", required=True, help="the verify tree the PoC was created against")
    ap.add_argument("--check", action="store_true", help="report only, change nothing")
    a = ap.parse_args()
    if not os.path.isdir(a.poc_dir):
        sys.exit(f"no such PoC dir: {a.poc_dir}")
    changed, findings = normalise(a.poc_dir, a.tree, a.check)

    # Stamp admissibility alongside the artefact. A PoC that cannot serve as an
    # ORACLE is still valuable EVIDENCE for a verified finding -- it is just not a
    # regression test, and the difference must travel with the tarball rather than
    # being rediscovered (or forgotten) at replay time.
    verdict = {"relocatable": not findings, "still_pinned": findings,
               "normalised_files": [c[0] for c in changed], "tree_at_capture": a.tree}
    try:
        import importlib.util
        _s = importlib.util.spec_from_file_location(
            "pr", os.path.join(os.path.dirname(os.path.abspath(__file__)), "poc-replay.py"))
        _m = importlib.util.module_from_spec(_s); _s.loader.exec_module(_m)
        entry = os.path.join(a.poc_dir, "exploit.sh")
        if os.path.exists(entry):
            verdict.update(_m.audit_bundle(entry))
    except Exception as e:
        verdict["audit_error"] = str(e)
    if not a.check:
        import json
        json.dump(verdict, open(os.path.join(a.poc_dir, "cm-admissibility.json"), "w"), indent=1)
    print(f"  admissible_as_oracle={verdict.get('admissible')}"
          f"  self_booting={verdict.get('self_booting')}")
    for name, n in changed:
        print(f"  {'would rewrite' if a.check else 'rewrote'} {name} ({n} path(s))")
    for f in findings:
        print(f"  STILL PINNED  {f}")
    if findings:
        print("\nPoC is NOT relocatable — do not bank it as a regression test.")
        return 1
    print(f"\n{len(changed)} file(s) normalised; PoC is relocatable "
          f"(set CM_TARGET at replay time).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
