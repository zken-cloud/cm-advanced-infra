# Findings, verdicts, coverage -- and the ledger itself at ledger/cm-ledger.db.
resource "google_storage_bucket" "results" {
  name                        = "${var.project_id}-${var.name_prefix}-results"
  location                    = var.region
  force_destroy               = var.bucket_force_destroy
  uniform_bucket_level_access = true
  # NOT conditional. The ledger is a single object rewritten by every run, and
  # versioning is the only undo it has -- the difference between a bad fold
  # being recoverable and being the new truth. It was declared conditionally,
  # left unapplied, and the live bucket ran without it (D34).
  versioning { enabled = true }

  # The TTL is SCOPED BY PREFIX, and must stay that way. An unscoped rule deletes
  # ledger/cm-ledger.db along with the blobs -- one quiet fortnight and every
  # finding, suppression and PoC pointer is gone, after which the gate answers
  # RACE forever because no sha has a scan on record. Adding a prefix here is
  # opt-IN to deletion: a new prefix that nobody lists is merely kept, which is
  # the safe direction to fail.
  dynamic "lifecycle_rule" {
    for_each = var.results_bucket_ttl_days > 0 ? var.results_ttl_prefixes : []
    content {
      condition {
        age            = var.results_bucket_ttl_days
        matches_prefix = [lifecycle_rule.value]
      }
      action { type = "Delete" }
    }
  }
}

# The PoC corpus. Never TTL'd by default: a verified exploit is the one artifact
# here that took 20-40 agent-minutes to produce and costs seconds to replay.
resource "google_storage_bucket" "poc" {
  name                        = "${var.project_id}-${var.name_prefix}-poc"
  location                    = var.region
  force_destroy               = var.bucket_force_destroy
  uniform_bucket_level_access = true
  dynamic "lifecycle_rule" {
    for_each = var.poc_bucket_ttl_days > 0 ? [1] : []
    content {
      condition { age = var.poc_bucket_ttl_days }
      action { type = "Delete" }
    }
  }
}
