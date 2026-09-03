variable "project_id" {
  type        = string
  description = "GCP project. CodeMender is in Public Preview, so the project must be enabled for it; the CLI download itself is public."
}
variable "region" {
  type    = string
  default = "us-central1"
}
variable "name_prefix" {
  type    = string
  default = "cm-lab"
}

# --- cost controls (see COST.md) ---
variable "cluster_release_channel" {
  type    = string
  default = "REGULAR"
}
variable "max_verify_parallelism" {
  type        = number
  default     = 100
  description = <<-EOT
    NOT WIRED. Read by this file and outputs.tf and consumed by nothing else --
    it is NOT passed to verify-select.py, and changing it changes nothing.
    The cap actually in force is `max_parallelism` in RUN.json, which
    reconcile.py defaults to 20 and passes as --max-parallelism.
    Kept as the intended knob; do not rely on it.
  EOT
}

# Spot is deliberately absent. Measured: spot preemption failed the verify Job
# at 3/12 completions, and a preempted verify pod costs its full agent-minutes
# for no verdict. Autopilot on-demand pods run to completion. Do not re-add.

variable "enable_pubsub" {
  type        = bool
  default     = false
  description = <<-EOT
    Provision the observation topic + ingester subscription. Off by default:
    the current write path is the exporter publishing blobs to GCS and PHASE 3
    folding them in. Pub/Sub earns its place once observations arrive from
    agents this run does not orchestrate.
  EOT
}
variable "results_bucket_ttl_days" {
  type        = number
  default     = 14
  description = "Age-out for find/verify blobs. 0 = keep forever."
}
variable "results_ttl_prefixes" {
  type        = list(string)
  default     = ["find/", "verify/"]
  description = <<-EOT
    Which prefixes the TTL is allowed to delete. Deliberately an allow-list, not
    a blanket rule: ledger/ must never appear here. The ledger is a single object
    rewritten each run, so an age-based delete removes the entire finding history
    of any repo that goes quiet for results_bucket_ttl_days.
  EOT
}
variable "bucket_force_destroy" {
  type        = bool
  default     = true
  description = <<-EOT
    Whether `terraform destroy` may delete the results and PoC buckets while they
    still hold objects.

    TRUE is right for a disposable lab: the teardown in the README is meant to
    work, and a bucket that refuses to go leaves a project nobody can fully clean
    up. Back the corpus up first -- the README's teardown says so, and means it.

    SET IT FALSE ON ANY LONG-LIVED PROJECT. The PoC corpus is the highest
    value-to-effort artifact in this design (invariant 7): every exploit in it cost
    20-40 agent-minutes to produce and seconds to replay. The ledger lives in the
    results bucket too. On 2026-09-03 the shared project got Terraform state for the
    first time, which made `destroy` possible there at all -- and with it, one
    mistyped command away from taking 26 verified PoCs and the whole finding history
    with it. Versioning is not a defence: deleting the bucket takes the versions.
  EOT
}

variable "poc_bucket_ttl_days" {
  type        = number
  default     = 0
  description = "0 = retain the PoC corpus forever (it is the regression suite). Invariant 7."
}
variable "runner_namespace" {
  type    = string
  default = "cm"
}
variable "bq_location" {
  type        = string
  default     = "US"
  description = "BigQuery dataset location. Must be compatible with the results bucket's region."
}
variable "reconciler_image" {
  type        = string
  description = "Digest-pinned reconciler image. NOT the runner image: the agent runs model-generated code and must never hold a Kubernetes credential."
}
variable "github_token_secret" {
  type        = string
  default     = ""
  description = <<-EOT
    Secret Manager secret holding a GitHub token that can clone the target.
    Required for a PRIVATE target: the reconciler must fetch the source to resolve
    fp3's enclosing function. Empty means public targets only. Create it with the
    same token the GKE pods use:
      printf %s "<PAT>" | gcloud secrets create cm-lab-gh-token --data-file=-
  EOT
}

variable "github_repos" {
  description = <<-EOT
    owner/repo for every participant repo whose GitHub Actions may assume the gate
    and ingester identities. Empty by default: an unlisted repo simply cannot
    authenticate, which is the correct failure for a repo nobody has vouched for.
  EOT
  type        = list(string)
  default     = []
}

variable "wif_pool_id" {
  description = "Workload Identity Pool id created in step 0g (not owned by this config)."
  type        = string
  default     = "github"
}
