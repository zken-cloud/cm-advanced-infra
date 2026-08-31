#!/usr/bin/env python3
"""Eventarc entrypoint for the reconciler.

Eventarc delivers a CloudEvent per finalized object, so one fan-out produces
several (three shards, three scrub reports, a RUN.json). That is fine and it is the
point: **the event is only a hint to look.** Nothing here reads the event payload.
A pass reads the world and does what the state implies, exactly as the CronJob form
does, so a duplicate event is a cheap no-op and a DROPPED event costs latency rather
than correctness. That is the property an event-driven ingester cannot offer, and
it is why the logic stays level-triggered under an edge-triggered clock.

Two things this has to get right that a cron form does not:

1. ACK IMMEDIATELY. A pass clones a repo and fingerprints with tree-sitter; it
   takes minutes. Pub/Sub push would hit its ack deadline and redeliver, so the
   handler returns 204 at once and works in the background. Cloud Run must run with
   CPU always allocated or the background thread is throttled the moment the
   response is written.

2. COALESCE, DO NOT QUEUE. Seven events for one fan-out should cause one pass, not
   seven. But a pass that is already listing objects will not see an object that
   lands a second later -- so a request arriving mid-pass sets a dirty flag and the
   runner goes round again. Dropping it would lose exactly the event that mattered.
"""
import os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util
_s = importlib.util.spec_from_file_location("reconcile",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "reconcile.py"))
R = importlib.util.module_from_spec(_s); _s.loader.exec_module(R)

BUCKET = os.environ["RESULTS_BUCKET"]
NS = os.environ.get("CM_NAMESPACE", "cm")
LEDGER = os.environ.get("CM_LEDGER", "/tmp/cm-ledger.db")

_lock = threading.Lock()
_running = False
_dirty = False


def _run():
    global _running, _dirty
    while True:
        try:
            for line in R.Reconciler(BUCKET, NS).pass_once(LEDGER):
                print(f"  {line}", flush=True)
        except Exception as e:                    # a bad pass must not kill the loop
            print(f"reconcile pass failed: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        with _lock:
            if not _dirty:
                _running = False
                return
            _dirty = False


def wake():
    global _running, _dirty
    with _lock:
        if _running:
            _dirty = True                          # arrived mid-pass: go round again
            return "coalesced"
        _running = True
    threading.Thread(target=_run, daemon=True).start()
    return "started"


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        print(f"event -> {wake()}", flush=True)
        self.send_response(204); self.end_headers()

    def do_GET(self):                              # Cloud Run startup probe
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    def log_message(self, *a):                     # the CloudEvent is not the news
        pass


def kubeconfig():
    """Cloud Run has no in-cluster identity, so fetch one at startup rather than on
    the first event -- a broken credential should fail the revision, not silently
    turn every reconcile pass into a no-op that logs and returns 204."""
    import subprocess
    cluster = os.environ.get("GKE_CLUSTER")
    if not cluster:
        return
    r = subprocess.run(["gcloud", "container", "clusters", "get-credentials", cluster,
                        "--region", os.environ.get("GKE_REGION", "us-central1"),
                        "--project", os.environ["GCP_PROJECT"]],
                       capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f"cannot reach the cluster: {r.stderr.strip()[-300:]}")
    print(f"kubeconfig for {cluster} ok", flush=True)


if __name__ == "__main__":
    kubeconfig()
    HTTPServer(("", int(os.environ.get("PORT", 8080))), H).serve_forever()
