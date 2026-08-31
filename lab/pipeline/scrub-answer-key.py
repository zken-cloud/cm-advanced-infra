#!/usr/bin/env python3
"""Remove a lab target's answer key before the agent sees it.

Lab-integrity control. A seeded-vulnerability app usually ships its own answer
key -- a VULNS.md, and (worse) comments sitting directly above each planted bug.
An agent that reads `// Vulnerability 7: RCE Constructor Extraction` has not
discovered anything; it has read the label off the tin. Recall measured against
an un-scrubbed target is reading comprehension, not detection.

An earlier target leaked via one file (SEEDED-VULNS.md, deleted in the find Job).
zken-cloud/vulnerable-app leaks *inline*: 15 annotated comment blocks in src/.

Two rules, both conservative:
  1. delete whole documents whose name matches an answer-key glob;
  2. delete a run of contiguous single-line comments if ANY line in the run
     discusses the planted bug;
  3. strip a trailing comment that discusses it, keeping the code. These matter
     most -- `// Vuln 5 Sink` labels the exact sink line.
Block comments (/* */) are never edited -- they are reported for manual review,
because deleting one line of a block comment breaks the code around it.

Writes a JSON report of everything removed. That report is the provenance for
the recall number: it shows what the agent was NOT told.

  scrub-answer-key.py <root> [--report r.json] [--doc GLOB] [--hint REGEX] [--dry-run]
"""
import re, sys, json, argparse, fnmatch
from pathlib import Path

# *GROUNDTRUTH* covers this lab's own answer-key filenames
# (vulnerable-app-GROUNDTRUTH.md + .json). Those live outside this repo entirely,
# but the safety net must still catch them if a copy ever slips into a scanned tree.
DOC_GLOBS = ["SEEDED-VULNS.md", "VULNS.md", "ANSWERS.md", "ANSWER-KEY.md", "SOLUTIONS.md",
             "*GROUNDTRUTH*", "*groundtruth*", "*Groundtruth*"]

# a comment run containing any of these is discussing the planted bug
HINT = re.compile(r"(?i)\b(vuln|vulnerability|sast|exploit|attacker|insecure|"
                  r"logical flaw|payload|bypass|malicious|backdoor)\b")

LINE_COMMENT = re.compile(r"^\s*(//|#)")
BLOCK_OPEN   = re.compile(r"/\*")
CODE_EXT = {".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".c", ".h", ".java", ".rb", ".php"}
SKIP_DIR = {".git", "node_modules", "vendor", "dist", "build", ".venv", "__pycache__"}


def trailing_comment_at(line):
    """Index of a trailing `//` comment, or None. Quote-aware so `http://` survives."""
    q = None
    i = 0
    while i < len(line):
        c = line[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = None
        elif c in "\"'`":
            q = c
        elif c == "/" and line[i + 1:i + 2] == "/":
            return i
        i += 1
    return None


def comment_runs(lines):
    """Yield (start, end) half-open index ranges of contiguous single-line comments."""
    i = 0
    while i < len(lines):
        if LINE_COMMENT.match(lines[i]):
            j = i
            while j < len(lines) and LINE_COMMENT.match(lines[j]):
                j += 1
            yield (i, j)
            i = j
        else:
            i += 1


def scrub_source(path, hint):
    """Return (new_text, [removed_lines]) for one source file."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    drop = set()
    removed = []
    for start, end in comment_runs(lines):
        run = lines[start:end]
        if any(hint.search(l) for l in run):
            drop.update(range(start, end))
            removed.extend(f"{path}:{start+k+1}: {run[k].strip()}" for k in range(len(run)))
    kept = []
    for k, line in enumerate(lines):
        if k in drop:
            continue
        i = trailing_comment_at(line)
        if i is not None and hint.search(line[i:]):
            removed.append(f"{path}:{k+1}: {line[i:].strip()}")
            line = line[:i].rstrip() + ("\n" if line.endswith("\n") else "")
        kept.append(line)
    if not drop and len(removed) == 0:
        return None, []
    return "".join(kept), removed


def block_comment_hints(path, hint):
    """Block comments are not edited -- surfaced so a human decides."""
    out, inside = [], False
    for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if BLOCK_OPEN.search(line):
            inside = True
        if inside and hint.search(line):
            out.append(f"{path}:{n}: {line.strip()}")
        if "*/" in line:
            inside = False
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--report")
    ap.add_argument("--doc", action="append", default=[], help="extra answer-key filename glob")
    ap.add_argument("--hint", help="override the hint regex")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    root = Path(a.root)
    if not root.is_dir():
        sys.exit(f"not a directory: {root}")
    hint = re.compile(a.hint, re.I) if a.hint else HINT
    globs = DOC_GLOBS + a.doc

    rep = {"root": str(root), "docs_deleted": [], "comments_removed": [],
           "block_comments_flagged": [], "files_edited": []}

    for p in sorted(root.rglob("*")):
        if any(d in SKIP_DIR for d in p.parts) or not p.is_file():
            continue
        rel = p.relative_to(root)
        # Match the BASENAME *and* the root-relative path. Basename-only silently
        # ignores any glob with a directory in it -- `.cm/rules/*.yaml` could never
        # match, so a ruleset naming every seeded bug shipped straight to the agent.
        relp = rel.as_posix()
        if any(fnmatch.fnmatch(p.name, g) or fnmatch.fnmatch(relp, g) for g in globs):
            rep["docs_deleted"].append(str(rel))
            if not a.dry_run:
                p.unlink()
            continue
        if p.suffix not in CODE_EXT:
            continue
        rep["block_comments_flagged"] += [h.replace(str(root) + "/", "") for h in block_comment_hints(p, hint)]
        new, removed = scrub_source(p, hint)
        if new is None:
            continue
        rep["files_edited"].append(str(rel))
        rep["comments_removed"] += [r.replace(str(root) + "/", "") for r in removed]
        if not a.dry_run:
            p.write_text(new, encoding="utf-8")

    rep["summary"] = {"docs_deleted": len(rep["docs_deleted"]),
                      "files_edited": len(rep["files_edited"]),
                      "comment_lines_removed": len(rep["comments_removed"]),
                      "block_comments_flagged": len(rep["block_comments_flagged"])}
    if a.report:
        Path(a.report).write_text(json.dumps(rep, indent=2))
    s = rep["summary"]
    print(f"scrub{' (dry-run)' if a.dry_run else ''}: {s['docs_deleted']} docs deleted, "
          f"{s['comment_lines_removed']} comment lines removed from {s['files_edited']} files, "
          f"{s['block_comments_flagged']} block-comment lines flagged for review")
    for d in rep["docs_deleted"]:
        print(f"  deleted  {d}")
    for f in rep["files_edited"]:
        print(f"  scrubbed {f}")
    for b in rep["block_comments_flagged"]:
        print(f"  REVIEW   {b}")


if __name__ == "__main__":
    main()
