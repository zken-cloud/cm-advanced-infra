#!/usr/bin/env python3
"""Advance every scanned commit through the pipeline. No human in the loop.

The pipeline is a graph -- find x3 -> dedup -> select -> verify xN -> fold -> gate
-- and until now only its first and last edges were automated. The middle ran from
`run-twophase.sh` on somebody's workstation, so the gate answered RACE for scans
that had demonstrably completed.

This is LEVEL-TRIGGERED on purpose. It does not subscribe to events and it does not
wait for anything: on each pass it reads the state that actually exists (objects in
GCS, rows in the ledger, Jobs in the cluster) and does whatever that state implies.
A crashed pod, a cancelled workflow, a lost message, a cluster restart, a pass that
died halfway -- all of it converges on the next pass, because nothing depends on an
event having been observed. An edge-triggered ingester is lower latency and one
dropped message leaves a commit unfolded forever, which the gate then reports as
RACE for a scan that succeeded.

Every state transition is gated on a fact that is already durable:

    shards complete, no `scans` row   -> fold the find, select, dispatch verify
    verify finished, no fold marker   -> fold the verdicts
    anything else                     -> nothing; say so and move on

which is what makes re-running it free.

WHAT INVOKES THIS IS A DEPLOYMENT CHOICE, NOT AN ARCHITECTURE ONE. The entrypoint
takes a bucket and a namespace and reads the world; it has no opinion about its own
clock. Three shapes, same code:

  * in-cluster CronJob (retired) -- nothing new to run, because the
    cluster already exists. Cheapest per participant; polls.
  * Cloud Run Job + Cloud Scheduler -- fully managed, per-invocation billing, no
    pod idling. Costs you GKE control-plane reachability from outside the cluster
    (authorized networks or a VPC connector), which the in-cluster form gets free.
  * Eventarc on GCS object-finalize -> the same Cloud Run Job. The best shape, and
    the reason is subtle: the event is only a HINT TO LOOK. The logic stays level-
    triggered, so a dropped event costs latency, never correctness -- which is
    exactly what an event-driven ingester cannot say. Pair it with a slow schedule
    (every 30 min) as the backstop and you get event latency with poll safety.

Cloud Workflows and Composer orchestrate but do not execute: the fold is tree-sitter
fingerprinting in Python, so it needs a container either way. They would add a
service without removing one.

It folds ONCE PER COMMIT, never once per shard or once per verdict. That is D34's
constraint made structural: the ledger is a single object under a generation CAS,
and per-artifact folds would turn one fan-out into a 3- or 20-way write burst.
"""
import argparse, json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def sh(*cmd, check=False, quiet=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd)} -> {r.returncode}\n{r.stderr}")
    if not quiet and r.stderr.strip():
        print(f"    ! {r.stderr.strip().splitlines()[-1]}", file=sys.stderr)
    return r


def ls(uri):
    r = sh("gcloud", "storage", "ls", uri)
    return [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("gs://")]


def cat(uri):
    with tempfile.NamedTemporaryFile(suffix=".json") as t:
        if sh("gcloud", "storage", "cp", uri, t.name).returncode:
            return None
        return json.load(open(t.name))


def exists(uri):
    return sh("gcloud", "storage", "objects", "describe", uri).returncode == 0



def verdict_object_fp(name):
    """The fingerprint a verify verdict object belongs to.

    `<safe-fp>.json` is the first publish; `<safe-fp>.<seq>.json` is a correction
    from the same pod (INCIDENTS 9 -- it cannot overwrite the first). Both name the
    same finding, so anything counting verdicts must collapse them. safe-fp is the
    fingerprint with ':' and '/' mapped to '_', so it never contains a dot and this
    split is unambiguous.
    """
    base = name[:-5] if name.endswith(".json") else name
    head, sep, tail = base.rpartition(".")
    return head if sep and tail.isdigit() else base


class Reconciler:
    def __init__(self, bucket, ns, namespace_job_prefix="cm-verify", dry_run=False):
        self.bucket, self.ns, self.pfx, self.dry = bucket, ns, namespace_job_prefix, dry_run

    # ---- the durable facts -------------------------------------------------
    def runs(self):
        """Commits we know were dispatched. The RUN.json manifest is written by the
        dispatcher, not inferred from object names: a reconciler that guesses at
        `shards_expected` cannot tell "2 of 3 landed" from "2 of 2 landed", and
        that difference is the whole point of the scans table (D22)."""
        out = []
        for d in ls(f"gs://{self.bucket}/find/"):
            r = cat(d.rstrip("/") + "/RUN.json")
            if r and r.get("sha"):
                out.append(r)
        return out

    def shards_landed(self, sha):
        return len([u for u in ls(f"gs://{self.bucket}/find/{sha}/") if u.endswith(".db")])

    def scan_recorded(self, ledger, repo, sha):
        import sqlite3
        if not os.path.exists(ledger):
            return False
        db = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True)
        return db.execute("select 1 from scans where repo=? and sha=?", (repo, sha)).fetchone() is not None

    def job_phase(self, name):
        """Terminal state comes from the Job's CONDITIONS, never from its counters.

        `status.succeeded` and `status.failed` are COUNTS OF PODS, not booleans.
        Reading them as booleans meant a 6-pod fan-out reported "complete" the
        moment the FIRST pod finished. Measured 2026-08-25: three of six pods were
        done at 03:02:39, the pass folded that partial set, wrote the `_folded`
        marker -- which makes every later pass a no-op by design -- and the three
        verdicts that landed afterwards were never ingested. Four VERIFIED findings,
        each with a working exploit and a banked PoC, silently missing from the
        ledger the merge gate reads.

        `failed` is the same trap and worse under D37: with backoffLimitPerIndex a
        single failed index sets failed=1 while every other index is still working,
        so one bad shard would truncate the whole fold.

        This is `backoffLimit: 0` again in a different costume -- a Kubernetes count
        read as a yes/no. The conditions are the yes/no.
        """
        r = sh("kubectl", "-n", self.ns, "get", "job", name, "-o", "json")
        if r.returncode:
            return None
        st = json.loads(r.stdout).get("status", {})
        true_conds = {c.get("type") for c in st.get("conditions", [])
                      if c.get("status") == "True"}
        # SuccessCriteriaMet/FailureTarget are the newer signals; Complete/Failed
        # remain the settled ones. Accept either so this does not depend on the
        # cluster's version.
        if true_conds & {"Complete", "SuccessCriteriaMet"}:
            return "complete"
        if true_conds & {"Failed", "FailureTarget"}:
            return "failed"
        return "running"

    # ---- transitions -------------------------------------------------------
    def clone(self, run, dest):
        """fp3 is (canonical path, ENCLOSING FUNCTION), resolved with tree-sitter, so
        selection needs the source -- the shard databases alone cannot produce a
        fingerprint. Pinned and asserted like every other agent (D29): a clone that
        silently took the default branch would fingerprint against a tree nobody
        scanned."""
        url = run["repourl"]
        tok = os.environ.get("GH_TOKEN")
        if tok and url.startswith("https://"):
            url = url.replace("https://", f"https://x-access-token:{tok}@", 1)
        sh("git", "init", "-q", dest, check=True)
        sh("git", "-C", dest, "remote", "add", "origin", url, check=True)
        if sh("git", "-C", dest, "fetch", "-q", "--depth", "1", "origin", run["sha"]).returncode:
            raise RuntimeError(f"cannot fetch {run['sha'][:12]}")
        sh("git", "-C", dest, "checkout", "-q", "FETCH_HEAD", check=True)
        got = sh("git", "-C", dest, "rev-parse", "HEAD").stdout.strip()
        if got != run["sha"]:
            raise RuntimeError(f"wanted {run['sha']} got {got}")
        return dest

    def fold_find(self, run, ledger):
        """shards complete + no scans row -> consolidate, select, record, dispatch."""
        sha, repo = run["sha"], run["repo"]
        work = tempfile.mkdtemp(prefix=f"rec-{sha[:7]}-")
        sh("gcloud", "storage", "cp", f"gs://{self.bucket}/find/{sha}/*.db", work + "/")
        # Coverage envelopes (Q13/D55). Best effort: a campaign whose shards produced
        # no coverage still folds -- but ingest says so out loud, because the whole
        # point of the table is that silence about coverage is itself the bug.
        covdir = os.path.join(work, "cov"); os.makedirs(covdir, exist_ok=True)
        sh("gcloud", "storage", "cp", f"gs://{self.bucket}/find/{sha}/coverage-*.json", covdir + "/")
        covs = [os.path.join(covdir, f) for f in sorted(os.listdir(covdir)) if f.endswith(".json")]
        dbs = [os.path.join(work, f) for f in sorted(os.listdir(work)) if f.endswith(".db")]
        if not dbs:
            return f"no shard databases downloaded for {sha[:7]}"
        try:
            src = self.clone(run, os.path.join(work, "src"))
        except RuntimeError as e:
            return f"{sha[:7]}: {e} — not folding against a tree we cannot verify"

        # A read-only copy for SUPPRESSION only: selection must not re-verify a
        # fingerprint the ledger already calls verified. The authoritative pull
        # happens inside ledger-sync when the fold actually writes.
        ro = os.path.join(work, "suppress.db")
        sh("gcloud", "storage", "cp", f"gs://{self.bucket}/ledger/cm-ledger.db", ro)

        sel = os.path.join(work, "dispatch.json")
        r = sh(sys.executable, os.path.join(HERE, "verify-select.py"), "--src-root", src,
               "--ledger", ro if os.path.exists(ro) else ":memory:",
               "--tier", run.get("tier", "critical,high"), "--top-n", str(run.get("top_n", 20)),
               "--max-parallelism", str(run.get("max_parallelism", 20)),
               "--json", *dbs)
        if r.returncode:
            return f"select failed for {sha[:7]}: {(r.stderr or '').strip()[-200:]}"
        try:
            dispatch = json.loads(r.stdout)
        except ValueError:
            return f"select produced no worklist for {sha[:7]}: {r.stdout[:120]!r}"
        json.dump(dispatch, open(sel, "w"), indent=1)

        # One fold for the whole commit, under the generation CAS.
        rc = subprocess.run([
            os.path.join(HERE, "ledger-sync.sh"), "with",
            f"gs://{self.bucket}/ledger/cm-ledger.db", ledger, "--ok-codes", "0,1,2", "--",
            sys.executable, os.path.join(HERE, "ingest-verdicts.py"),
            "--ledger", ledger, "--repo", repo, "--sha", sha,
            "--shards-expected", str(run["shards"]), "--shards-completed", str(len(dbs)),
            "--min-shards", str(run["shards"]), "--dispatch", sel,
            "--ts", run.get("ts") or _now(),
            *(["--coverage", *covs] if covs else []),
            # Q8: RUN.json's dispatched_at is the developer's push time -- the only
            # place it survives -- and it is the origin both race durations measure
            # from. Absent on older runs, which is why the column is nullable.
            *(["--pushed-at", run["dispatched_at"]] if run.get("dispatched_at") else []),
        ]).returncode
        if rc >= 3:
            return f"ledger not persisted for {sha[:7]} (rc={rc}) — will retry next pass"

        sh("gcloud", "storage", "cp", sel, f"gs://{self.bucket}/find/{sha}/dispatch.json")
        if not dispatch:
            # Nothing selected is a legitimate outcome, and it must be recorded as
            # finished or the commit is reconsidered forever.
            sh("gcloud", "storage", "cp", "/dev/null", f"gs://{self.bucket}/verify/{sha}/_folded")
            return f"{sha[:7]}: folded, 0 selected for verify — done"
        made = self.dispatch_verify(run, sel, len(dispatch))
        how = (f"dispatched {len(dispatch)} verify pod(s)" if made
               else f"verify Job already existed — {len(dispatch)} selected, NOT dispatched")
        return f"{sha[:7]}: folded {len(dbs)} shard(s), {how}"

    def dispatch_verify(self, run, dispatch_path, n):
        """True if this call created the Job; False if one already existed."""
        sha = run["sha"]
        name = f"{self.pfx}-{sha[:7]}"
        if self.job_phase(name):
            return False
        sh("kubectl", "-n", self.ns, "create", "configmap", f"cm-dispatch-{sha[:7]}",
           f"--from-file=dispatch.json={dispatch_path}")
        man = open(os.path.join(HERE, "..", "k8s", "52-verify-job.yaml")).read()
        subs = {"__IMG__": run["image"], "__BUCKET__": self.bucket,
                "__POCBUCKET__": run["poc_bucket"], "__N__": str(n),
                "__REPOURL__": run["repourl"], "__REPO__": run["repo"],
                # fallback for a RUN.json predating the fuller glob list; must stay
                # in step with cm-fanout.yml (both harvested-rule copies named).
                "__SCRUB__": run.get("scrub", "--doc README.md --doc APP-README.md --doc .cm/rules/*.yaml --doc pipeline/harvested-rules/*.yaml"),
                "__SCOPE__": run.get("scope", "src"), "__SHA__": sha}
        # RUN.json carries the project since 2026-08-28; older manifests fall back
        # to the reconciler's own env. Neither set → the unsubstituted-placeholder
        # guard below refuses to dispatch, which is the correct loud failure.
        project = run.get("project") or os.environ.get("GCP_PROJECT")
        if project:
            subs["__PROJECT__"] = project
        for k, v in subs.items():
            man = man.replace(k, v)
        left = sorted(set(__import__("re").findall(r"__[A-Z]+__", man)))
        if left:
            raise RuntimeError(f"refusing to dispatch {name}: unsubstituted {left}")
        man = man.replace("name: cm-verify", f"name: {name}") \
                 .replace("name: cm-dispatch", f"name: cm-dispatch-{sha[:7]}")
        if self.dry:
            return
        p = subprocess.run(["kubectl", "-n", self.ns, "apply", "-f", "-"],
                           input=man, text=True, capture_output=True)
        if p.returncode:
            raise RuntimeError(f"dispatch {name}: {p.stderr.strip()[:200]}")
        return True

    def selected(self, sha):
        """How many fingerprints this commit's dispatch asked to verify."""
        d = cat(f"gs://{self.bucket}/find/{sha}/dispatch.json")
        return len(d) if d else 0

    def verdicts_landed(self, sha):
        """How many DISTINCT fingerprints this commit's verify pods published a
        verdict for. Objects, not fingerprints, was wrong the moment a pod could
        publish twice: a corrected verdict lands as <fp>.<seq>.json alongside
        <fp>.json (it cannot overwrite -- objectCreator), so counting objects
        reports one extra and `have < want` stops being true one fingerprint early.
        The re-dispatch that should have covered the missing one is then skipped and
        the fold proceeds without it, which is exactly the "ask what landed" control
        below failing while looking like it worked."""
        r = sh("gcloud", "storage", "ls", f"gs://{self.bucket}/verify/{sha}/")
        return len({verdict_object_fp(ln.strip().rsplit("/", 1)[-1])
                    for ln in (r.stdout or "").splitlines()
                    if ln.strip().endswith(".json")})

    def redispatch(self, run, want):
        sha = run["sha"]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as t:
            json.dump(cat(f"gs://{self.bucket}/find/{sha}/dispatch.json"), t)
            path = t.name
        try:
            made = self.dispatch_verify(run, path, want)
            if not made:
                return f"{sha[:7]}: verify Job exists after all — not re-dispatched"
            return f"{sha[:7]}: verify Job was missing — re-dispatched {want} pod(s)"
        except RuntimeError as e:
            return f"{sha[:7]}: re-dispatch failed ({e}) — retrying next pass"

    def fold_verdicts(self, run, ledger):
        sha, repo = run["sha"], run["repo"]
        work = tempfile.mkdtemp(prefix=f"vf-{sha[:7]}-")
        sh("gcloud", "storage", "cp", f"gs://{self.bucket}/verify/{sha}/*.json", work + "/")
        got = {verdict_object_fp(f) for f in os.listdir(work) if f.endswith(".json")}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as t:
            pass
        sh("gcloud", "storage", "cp", f"gs://{self.bucket}/find/{sha}/dispatch.json", t.name)
        # shards_completed must be COUNTED, never assumed. Asserting run["shards"]
        # here re-reported a partial scan as complete: record_scan upserts with
        # MAX(existing, new), so an honest 2/3 from fold_find was promoted to 3/3 by
        # this later fold on the same (repo,sha) -- turning a correct RACE into a
        # clean PASS with nothing in any artifact to show it happened. The find
        # shard dbs in GCS are the same source of truth fold_find counts.
        landed = len([u for u in ls(f"gs://{self.bucket}/find/{sha}/") if u.endswith(".db")])
        rc = subprocess.run([
            os.path.join(HERE, "ledger-sync.sh"), "with",
            f"gs://{self.bucket}/ledger/cm-ledger.db", ledger, "--ok-codes", "0,1,2", "--",
            sys.executable, os.path.join(HERE, "ingest-verdicts.py"),
            "--ledger", ledger, "--repo", repo, "--sha", sha,
            "--shards-expected", str(run["shards"]), "--shards-completed", str(landed),
            "--min-shards", str(run["shards"]), "--dispatch", t.name,
            "--verdicts", os.path.join(work, "*.json"), "--ts", _now(),
            *(["--pushed-at", run["dispatched_at"]] if run.get("dispatched_at") else []),
        ]).returncode
        if rc >= 3:
            return f"{sha[:7]}: verdict fold not persisted (rc={rc}) — retry next pass"
        # The marker is what makes the next pass a no-op. Written only AFTER the
        # ledger push succeeded, so a crash in between re-folds rather than skips.
        sh("gcloud", "storage", "cp", "/dev/null", f"gs://{self.bucket}/verify/{sha}/_folded")
        # The dispatch ConfigMap outlives its Job -- nothing owns it, and with
        # ttlSecondsAfterFinished reaping the Job it would be left behind for good.
        # It is only ever a copy of find/<sha>/dispatch.json, which is authoritative
        # and stays in GCS, so dropping it loses nothing. Best effort: a namespace
        # slowly filling with orphaned ConfigMaps is untidy, not unsafe, and must
        # never turn a successful fold into a failed pass.
        sh("kubectl", "-n", self.ns, "delete", "configmap", f"cm-dispatch-{sha[:7]}",
           "--ignore-not-found")
        return f"{sha[:7]}: folded {len(got)} verdict(s)"

    # ---- one pass ----------------------------------------------------------
    def pass_once(self, ledger):
        # REFRESH THE SNAPSHOT scan_recorded() reads. It reads this LOCAL file, and
        # nothing else in a pass guarantees it is current: ledger-sync only pulls
        # inside a fold. On a cold instance /tmp/cm-ledger.db does not exist at all,
        # so scan_recorded() answers False for EVERY commit and the pass re-folds and
        # re-dispatches all of them. Verify is the 20-40 minute stage, so a deploy or
        # a scale-to-zero would silently re-run the most expensive work in the
        # pipeline, and it would look like ordinary activity in the log.
        # Measured 2026-08-25: a revision rollout re-dispatched an already-folded
        # commit. Note the _folded marker does NOT protect against this -- it is
        # checked after scan_recorded, so an empty snapshot skips straight past it.
        # Advisory only; the authoritative pull is the CAS pull inside the fold.
        sh("gcloud", "storage", "cp", f"gs://{self.bucket}/ledger/cm-ledger.db", ledger)
        acted = []
        for run in self.runs():
            sha, repo = run["sha"], run["repo"]
            landed, want = self.shards_landed(sha), run["shards"]
            if not self.scan_recorded(ledger, repo, sha):
                if landed < want:
                    acted.append(f"{sha[:7]}: {landed}/{want} shards — waiting")
                    continue
                acted.append(self.fold_find(run, ledger))
                continue
            if exists(f"gs://{self.bucket}/verify/{sha}/_folded"):
                continue                                   # terminal
            phase = self.job_phase(f"{self.pfx}-{sha[:7]}")
            if phase is None:
                # No Job. That is NOT "finished" -- it is "never started", and
                # treating the two alike marks the commit folded and skips verify
                # forever. But it is not automatically "never started" either: the
                # verify Job carries ttlSecondsAfterFinished, so a Job that ran to
                # completion is REAPED, and a reconciler that had been down longer
                # than the TTL would find no Job, assume dispatch failed, and re-run
                # a whole 20-40 minute fan-out whose verdicts are already sitting in
                # the bucket. Ask what landed, not just what was asked for.
                want = self.selected(sha)
                have = self.verdicts_landed(sha)
                if want and have < want:
                    acted.append(self.redispatch(run, want))
                    continue
                acted.append(self.fold_verdicts(run, ledger))
            elif phase in ("complete", "failed"):
                # `failed` folds too: a verify Job that gave up still published a
                # verdict on every exit path (invariant 5), and those verdicts are
                # the negative-cache entries. Waiting for a clean exit loses them.
                acted.append(self.fold_verdicts(run, ledger))
            else:
                acted.append(f"{sha[:7]}: verify {phase} — waiting")
        return acted


def _now():
    return subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                          capture_output=True, text=True).stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--namespace", default="cm")
    ap.add_argument("--ledger", default="/tmp/cm-ledger.db")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    r = Reconciler(a.bucket, a.namespace, dry_run=a.dry_run)
    acted = r.pass_once(a.ledger)
    print(f"reconcile: {len(acted)} commit(s) considered")
    for line in acted:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
