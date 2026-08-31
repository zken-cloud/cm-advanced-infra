#!/usr/bin/env python3
"""Challenge a CM fix PR with a second model. ADVISORY ONLY — never a gate.

WHY THIS EXISTS, AND WHY IT IS NOT A GATE

R5 in DECISIONS.md is an explicitly RETRACTED option: "auto-merge patches when PoC
replay passes". The reason it was retracted is the whole reason this script exists —
replay passing proves that *specific exploit* no longer fires, not that the
vulnerability is fixed. An agent can patch the exploit path rather than the root
cause, and **the replay signal actively conceals that**: the greener it looks, the
more thoroughly the real defect is hidden.

So the one question worth asking a reviewer is not "does this look fine" but:

    Does this patch fix the DEFECT, or does it only break the EXPLOIT?

A human answers that today, and keeps answering it — this changes nothing about who
merges. The model is a second opinion that can be wrong, and is wired so that being
wrong is cheap: it posts a comment and touches nothing else.

  * it cannot approve, merge, or set a status check;
  * it cannot write the ledger (no credential — the gate reads the ledger, and a
    reviewer that could write it could clear its own blocker, which is invariant 3
    stated for a different actor);
  * it runs on workflow_dispatch, so it is never in the lab's default path.

The lab keeps PR-as-HITL: participants read the fix, read this challenge if they
asked for one, and approve. Deliberately NOT `on: pull_request` — a review that
appears automatically on every PR becomes wallpaper, and wallpaper is worse than
nothing because it looks like coverage.

  pr-challenge.py --repo zken-cloud/cm-lab-user1 --pr 7            # dry run
  pr-challenge.py --repo ... --pr 7 --fingerprint fp3:abc --post
"""
import os, sys, json, argparse, subprocess, sqlite3

MODEL = "claude-opus-5"
MAX_DIFF_CHARS = 200_000          # ~50k tokens; larger PRs are summarised, never silently cut

SYSTEM = """You are reviewing a security fix produced by an automated vulnerability \
remediation agent (Google DeepMind CodeMender). The finding was VERIFIED: a working \
exploit was synthesised and run against the vulnerable code, so the vulnerability is \
real and not a false positive.

Your job is one specific question, not general code review:

  Does this patch fix the underlying DEFECT, or does it only break the particular \
EXPLOIT that was used to prove it?

This distinction is the entire point. An agent that narrows a regex, blocks one \
payload shape, or special-cases the exact input from the proof-of-concept will make \
the regression test pass while leaving the vulnerability reachable by a different \
input. A replay-based signal cannot detect that — it is the thing being fooled.

Judge these, in order of importance:

1. ROOT CAUSE vs EXPLOIT PATH. Would a competent attacker with a different payload \
still reach the sink? Name a concrete bypass if you believe one exists.
2. COMPLETENESS. Does the same defect appear elsewhere in the diff's context, \
unfixed? Sibling call sites, other parameters into the same helper.
3. REGRESSION RISK. Does the patch change behaviour beyond the fix — stricter \
parsing, altered return shapes, edge cases that were previously valid?
4. NEW DEFECTS. Did the patch introduce one.

Be concrete and short. Cite specific lines. If the fix is genuinely correct, say so \
plainly in one or two sentences and stop — padding a clean review with hedges \
trains readers to skim. If you are unsure, say you are unsure and say what evidence \
would settle it. You are advisory: a human decides."""


def sh(*cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode:
        sys.exit(f"{' '.join(cmd[:3])} failed: {(r.stderr or '').strip()[-400:]}")
    return r.stdout


def finding_context(ledger, fingerprint):
    """What the ledger knows about the finding this PR claims to fix.

    Without it the model is reviewing a diff blind. With it, it can check the patch
    against the class of bug that was actually PROVEN, not the one the PR title
    claims. Absent ledger or fingerprint is fine — say so rather than invent.
    """
    if not (ledger and fingerprint and os.path.exists(ledger)):
        return "No ledger entry supplied; judge the diff on its own terms."
    db = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    r = db.execute("""SELECT fingerprint, cwe_class, canonical_path, verdict, severity,
                             poc_uri, attempts FROM findings WHERE fingerprint=?""",
                   (fingerprint,)).fetchone()
    if not r:
        return f"Fingerprint {fingerprint} is not in the ledger."
    return ("The finding this PR claims to fix, as recorded in the ledger:\n"
            + json.dumps({k: r[k] for k in r.keys()}, indent=2)
            + "\n\nverdict=verified means an exploit was synthesised and RAN. "
              "The bug is real; the only question is whether this patch closes it.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True)
    ap.add_argument("--ledger")
    ap.add_argument("--fingerprint")
    ap.add_argument("--post", action="store_true", help="post as a PR comment (default: stdout)")
    a = ap.parse_args()

    import anthropic
    client = anthropic.Anthropic()

    diff = sh("gh", "pr", "diff", a.pr, "--repo", a.repo)
    meta = json.loads(sh("gh", "pr", "view", a.pr, "--repo", a.repo,
                         "--json", "title,body,files"))
    if len(diff) > MAX_DIFF_CHARS:
        # Never silently truncate a security diff: the part that gets cut is exactly
        # where a bad fix would hide. Refuse and say what to do instead.
        sys.exit(f"diff is {len(diff)} chars (> {MAX_DIFF_CHARS}). Review it in pieces "
                 f"— truncating a security diff hides the half that matters.")

    prompt = (f"{finding_context(a.ledger, a.fingerprint)}\n\n"
              f"PR title: {meta['title']}\n\n"
              f"PR body:\n{meta.get('body') or '(empty)'}\n\n"
              f"Files changed: {', '.join(f['path'] for f in meta.get('files', []))}\n\n"
              f"Diff:\n```diff\n{diff}\n```")

    # Streaming because a large diff plus adaptive thinking can outrun the
    # non-streaming HTTP timeout. fallbacks="default" because security review is a
    # plausible false-positive for the cyber classifier — a refused review must
    # degrade to a different model, not to silence.
    with client.beta.messages.stream(
        model=MODEL,
        max_tokens=16000,
        system=SYSTEM,
        thinking={"type": "adaptive"},
        fallbacks="default",
        betas=["server-side-fallback-2026-07-01"],
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        resp = stream.get_final_message()

    # stop_reason first: on a refusal `content` can be empty, and reading content[0]
    # unconditionally turns a refusal into a crash that looks like a bug in the tool.
    if resp.stop_reason == "refusal":
        cat = getattr(resp.stop_details, "category", None) if resp.stop_details else None
        sys.exit(f"the model declined this review (category={cat}). "
                 f"Not posting — a refusal is not a clean review.")

    body = "\n".join(b.text for b in resp.content if b.type == "text").strip()
    if not body:
        sys.exit("empty review, not posting")

    comment = (
        "## 🤖 Automated challenge review — advisory, not a gate\n\n"
        "_A second model was asked one question: **does this patch fix the defect, "
        "or only break the exploit that proved it?** It cannot approve, merge, or "
        "block. A human still decides._\n\n"
        f"{body}\n\n"
        f"<sub>model: `{MODEL}` · opt-in via workflow_dispatch · "
        f"see DECISIONS.md R5 for why replay-passing is not sufficient evidence</sub>"
    )
    if not a.post:
        print(comment)
        return 0
    subprocess.run(["gh", "pr", "comment", a.pr, "--repo", a.repo, "--body", comment],
                   check=True)
    print(f"posted challenge review to {a.repo}#{a.pr}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
