# pipeline — two-phase fan-out (find → consolidate/dedup → verify/fix)

The runbook is [`../README.md`](../README.md). This file is a map of the directory.

| File | Role | Tested |
|---|---|---|
| `shard.py` | Phase-1 sharder: disjoint (discovery) or K-replicated (delta). Caps pods for cost | ✅ |
| `consolidate-dedup.py` | Central identity — **fp3**: `(locus_type, canonical_path, locus)`, locus = tree-sitter enclosing fn → cross-file sink → line-overlap. **Deliberately excludes the CWE**: keying on it gave 81% carry-over between runs and let a relabelled finding pass the gate silently | ✅ |
| `ledger.py` | Verify-queue builder. **Never verify an already-verified finding.** Monotonic fold; version-scoped negative cache | ✅ `test_ledger.py` 19/19 |
| `coverage.py` | Exporter-computed file-level coverage + release-gate staleness check | ✅ `test_coverage.py` 17/17 |
| `gate.py` | Risk-router merge gate + admission control + retry-budget math | ✅ `test_gate.py` 10/10 |
| `harvest.py` | Verified finding → Semgrep rule (shift-left: one verify → millisecond detections forever) | ✅ `test_harvest.py` 4/4 |
| `stamp-rules.py` | The only path that may make a rule **block**. Refuses unless the ledger confirms it AND it stays quiet on every correct fix in the FP corpus | ✅ `test_stamp_rules.py` 10/10 |

Dedup is measured at **33 → 9 fingerprints** on a dedup-mechanism test with known
ground truth, and **29 → 13 (55% avoided)** on the clean sha-pinned end-to-end run
the runbook quotes. An earlier **29 → 12 (58%)** figure is still cited in D59/Q5, but
it came from the run INCIDENTS #1 records as having scanned the wrong tree — do not
quote it as the runbook's number. See [`../docs/EXPERIMENTS.md`](../docs/EXPERIMENTS.md).

```bash
pip3 install --break-system-packages -r requirements.txt   # Debian 12 is PEP 668
for t in test_*.py; do python3 "$t"; done                   # 22 suites, 303 cases
# Use this loop, NOT pytest. Seven suites are standalone scripts that call sys.exit()
# at module scope, so `pytest` dies with "Interrupted: 7 errors during collection"
# on a green tree.
SRC_ROOT=/path/to/clone python3 consolidate-dedup.py pod*/state.db
```

The identity algorithm is stamped (`FP_ALGO = "fp3"`); a change re-keys explicitly
rather than silently. `fp2` was the previous version, which keyed on `cwe_class`.
