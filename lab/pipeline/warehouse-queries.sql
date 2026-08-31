-- Programme-level questions, against the BigQuery external tables over
-- gs://<results>/warehouse/. Nothing here touches the ledger: the gate reads the
-- object, dashboards read these. Substitute your dataset for cm_lab_warehouse.
--
-- Every export is a SNAPSHOT, so `findings` and `scans` contain one row per
-- fingerprint PER EXPORT. Current-state queries must pin to the latest
-- snapshot_ts; trend queries deliberately use them all.

-- ---------------------------------------------------------------- current state
-- Open findings by severity and repo. The question everyone asks first, and the
-- one that was unanswerable until findings carried severity and repo.
SELECT repo, severity, COUNT(*) AS open_findings
FROM `cm_lab_warehouse.findings`
WHERE snapshot_ts = (SELECT MAX(snapshot_ts) FROM `cm_lab_warehouse.findings`)
  AND verdict = 'verified' AND fixed_at IS NULL
GROUP BY repo, severity
ORDER BY repo, CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                             WHEN 'MEDIUM' THEN 2 ELSE 3 END;

-- Aging of the verified-unfixed backlog. A programme is judged on the tail, not
-- the count: ten week-old criticals is a different story from one from March.
SELECT repo, severity, fingerprint, canonical_path,
       DATE_DIFF(CURRENT_DATE(), DATE(PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', first_seen)), DAY) AS age_days
FROM `cm_lab_warehouse.findings`
WHERE snapshot_ts = (SELECT MAX(snapshot_ts) FROM `cm_lab_warehouse.findings`)
  AND verdict = 'verified' AND fixed_at IS NULL
ORDER BY age_days DESC;

-- ---------------------------------------------------------------------- trends
-- Backlog over time. This is what the snapshots exist for -- a current-state
-- store can answer "how many are open" and can never answer "are we winning".
SELECT DATE(PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', snapshot_ts)) AS day, repo,
       COUNTIF(verdict = 'verified' AND fixed_at IS NULL) AS verified_open,
       COUNTIF(verdict = 'verified' AND fixed_at IS NOT NULL) AS verified_fixed,
       COUNTIF(verdict = 'unproven') AS unproven
FROM `cm_lab_warehouse.findings`
GROUP BY day, repo ORDER BY day;

-- Mean time to remediate, by severity. Only findings that were actually fixed --
-- averaging in the unfixed ones flatters the number by excluding the worst cases.
SELECT repo, severity, COUNT(*) AS fixed,
       ROUND(AVG(TIMESTAMP_DIFF(PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', fixed_at),
                                PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', first_seen), HOUR)) / 24, 1) AS mttr_days
FROM `cm_lab_warehouse.findings`
WHERE snapshot_ts = (SELECT MAX(snapshot_ts) FROM `cm_lab_warehouse.findings`)
  AND fixed_at IS NOT NULL
GROUP BY repo, severity;

-- ------------------------------------------------------- effect on developers
-- Gate outcomes. RACE is the number to watch: it means the scan had not landed
-- when the developer asked, so it is the programme's own latency showing up as
-- developer friction -- not a finding, and not the developer's fault.
SELECT repo, action, COUNT(*) AS runs,
       ROUND(100 * COUNT(*) / SUM(COUNT(*)) OVER (PARTITION BY repo), 1) AS pct
FROM `cm_lab_warehouse.gate_events`
GROUP BY repo, action ORDER BY repo, runs DESC;

-- How long a sha stays blocked: first BLOCK to first PASS on the same sha.
SELECT repo, sha,
       TIMESTAMP_DIFF(MIN(IF(action = 'PASS',  PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', ts), NULL)),
                      MIN(IF(action = 'BLOCK', PARSE_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', ts), NULL)), MINUTE) AS blocked_minutes
FROM `cm_lab_warehouse.gate_events`
GROUP BY repo, sha
HAVING blocked_minutes IS NOT NULL
ORDER BY blocked_minutes DESC;

-- ------------------------------------------------------------------- detection
-- Agreement across the K replicas. A fingerprint seen by one pod out of three is
-- a different confidence claim from one seen by all three (D16).
SELECT f.fingerprint, f.severity, f.verdict, COUNT(DISTINCT o.obs_id) AS observations
FROM `cm_lab_warehouse.findings` f
JOIN `cm_lab_warehouse.observations` o USING (fingerprint)
WHERE f.snapshot_ts = (SELECT MAX(snapshot_ts) FROM `cm_lab_warehouse.findings`)
GROUP BY 1, 2, 3 ORDER BY observations DESC;

-- Scan cadence and completeness. Partial shard counts are the leading indicator
-- of RACE verdicts downstream.
SELECT repo, sha, shards_completed, shards_expected, completed_at
FROM `cm_lab_warehouse.scans`
WHERE snapshot_ts = (SELECT MAX(snapshot_ts) FROM `cm_lab_warehouse.scans`)
ORDER BY completed_at DESC;

-- NOT ANSWERABLE YET: coverage. "What fraction of the codebase have we examined"
-- has no table, because CM emits no coverage (Q13). Until that is reconstructed
-- from the session log, "we found nothing" and "we never looked" are the same row.
