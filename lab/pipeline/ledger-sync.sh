#!/usr/bin/env bash
# Compare-and-swap wrapper for the GCS-backed ledger.
#
# The ledger is ONE object that every ingest rewrites whole. Pull-modify-push with
# no precondition is last-writer-wins: two overlapping runs and the second push
# silently discards the first's findings, observations and PoC pointers. GCS gives
# us the primitive to make that safe -- an atomic generation precondition -- so the
# whole read-modify-write becomes optimistic concurrency with a retry.
#
#   ledger-sync.sh with gs://bucket/ledger/cm-ledger.db /tmp/l.db -- <command...>
#
# The command is re-run from a fresh pull on every retry. That is not an
# optimisation, it is the correctness condition: the fold must be computed against
# the state it is about to overwrite, never against a snapshot someone has since
# replaced.
#
#   --attempts N    tries before giving up (default 25 -- see below; a 16-way
#                   burst needs ~16 serialised rounds, so 5 is not enough)
#   --ok-codes a,b  command exit codes that still mean "push this" (default 0,1,2 --
#                   ingest-verdicts.py returns the GATE verdict, so 1=BLOCK and
#                   2=RACE are successful runs, not failures)
set -uo pipefail

ATTEMPTS=25
OK_CODES="0,1,2"
MODE="${1:-}"; shift || true
[ "$MODE" = "with" ] || { echo "usage: ledger-sync.sh with <gs-uri> <local> [--attempts N] [--ok-codes a,b] -- cmd..." >&2; exit 64; }
URI="${1:-}"; LOCAL="${2:-}"; shift 2 || { echo "ledger-sync: need <gs-uri> and <local>" >&2; exit 64; }
while [ $# -gt 0 ]; do
  case "$1" in
    --attempts) ATTEMPTS="$2"; shift 2;;
    --ok-codes) OK_CODES="$2"; shift 2;;
    --) shift; break;;
    *) echo "ledger-sync: unexpected arg '$1'" >&2; exit 64;;
  esac
done
[ $# -gt 0 ] || { echo "ledger-sync: no command after --" >&2; exit 64; }

is_ok() { case ",$OK_CODES," in *",$1,"*) return 0;; *) return 1;; esac; }

for ((try=1; try<=ATTEMPTS; try++)); do
  # ---- PULL, pinned to the generation we are going to assert on push ----
  GEN=$(gcloud storage objects describe "$URI" --format='value(generation)' 2>/dev/null || true)
  rm -f "$LOCAL"                      # never let a previous attempt's file survive
  if [ -n "$GEN" ]; then
    # read THAT generation, not "latest" -- otherwise we fold over one state and
    # assert another, and the precondition stops meaning what it says
    if ! gcloud storage cp "${URI}#${GEN}" "$LOCAL" >/dev/null 2>&1; then
      echo "ledger-sync: generation $GEN vanished between describe and read; retrying" >&2
      sleep $(( (RANDOM % 3) + 1 )); continue
    fi
  else
    GEN=0                             # absent: push becomes create-if-absent
  fi

  # ---- MODIFY ----
  "$@"; RC=$?
  if ! is_ok "$RC"; then
    echo "ledger-sync: command exited $RC (not in $OK_CODES) -- NOT pushing a partial fold" >&2
    exit "$RC"
  fi

  # ---- PUSH, only if nobody else wrote since the pull ----
  ERR=$(gcloud storage cp "$LOCAL" "$URI" --if-generation-match="$GEN" 2>&1); PRC=$?
  if [ "$PRC" -eq 0 ]; then
    [ "$try" -gt 1 ] && echo "ledger-sync: pushed on attempt $try/$ATTEMPTS" >&2
    exit "$RC"
  fi
  if echo "$ERR" | grep -qiE 'precondition|pre-condition|generation|412|conflict'; then
    # Exponential backoff with full jitter, capped. Linear backoff convoys: every
    # loser retries on nearly the same schedule, so the same writer keeps losing.
    CAP=$(( 1 << (try < 6 ? try : 6) ))          # 2,4,8,16,32,64 then flat
    BACK=$(( (RANDOM % CAP) + 1 ))
    echo "ledger-sync: lost the race on attempt $try/$ATTEMPTS (gen $GEN is stale); re-folding in ${BACK}s" >&2
    sleep "$BACK"; continue
  fi
  echo "ledger-sync: push failed for a NON-precondition reason -- not retrying:" >&2
  echo "$ERR" >&2
  exit 74
done

# Exhausting the retries must be LOUD. The old code said "WARNING: ledger not
# persisted" and exited 0, which turns a lost fold into a green run.
echo "ledger-sync: FATAL -- $ATTEMPTS attempts all lost the race. Ledger NOT persisted." >&2
exit 75
