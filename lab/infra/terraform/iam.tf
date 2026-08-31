# Three least-privilege identities. The split is the whole point of invariant 3:
# an agent that can write the ledger can mark its own finding fixed.
resource "google_service_account" "runner" {
  account_id   = "${var.name_prefix}-runner"
  display_name = "CodeMender runner (WIF): Vertex + publish-only"
}
resource "google_service_account" "ingester" {
  account_id   = "${var.name_prefix}-ingester"
  display_name = "Ledger ingester: sole writer"
}
resource "google_service_account" "gate" {
  account_id   = "${var.name_prefix}-gate"
  display_name = "Merge/release gate: read-only ledger"
}

# --- runner: reach the model, publish results, never read the ledger ---
resource "google_project_iam_member" "runner_aiplatform" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.runner.email}"
}
# The cm-fanout dispatch job authenticates AS the runner to create the find Job.
# Measured on a clean project: without this the workflow dies at
# get-gke-credentials with `iam.serviceAccounts.getAccessToken denied`, 12s in,
# before a single pod exists. wif_runner below covers the IN-CLUSTER principal
# (svc.id.goog) -- that is a different principal and does not imply this one.
# Every earlier end-to-end run passed only because the binding had been added by
# hand to a long-lived project.
resource "google_service_account_iam_member" "gh_runner" {
  for_each           = toset(var.github_repos)
  service_account_id = google_service_account.runner.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "${local.wif_principal_prefix}${each.value}"
}

# ...and having been impersonated, it needs to reach the cluster API to create the
# Job. container.developer is broader than this job strictly needs: the tight form
# is container.clusterViewer plus a Role/RoleBinding for Jobs in the runner
# namespace. That is the better shape if this is ever tightened; it is deliberately
# not done here because the reconciler already holds container.developer and one
# unexplained asymmetry is worse than one known-broad grant.
resource "google_project_iam_member" "runner_container" {
  project = var.project_id
  role    = "roles/container.developer"
  member  = "serviceAccount:${google_service_account.runner.email}"
}

resource "google_pubsub_topic_iam_member" "runner_publish" {
  count  = var.enable_pubsub ? 1 : 0
  topic  = google_pubsub_topic.observations[0].name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.runner.email}"
}
# INVARIANT 3: the ingester is the sole writer to the ledger, and the ledger lives
# in THIS bucket at ledger/cm-ledger.db. objectAdmin here let the agent identity
# overwrite or delete it -- "an agent that can write the ledger can mark its own
# finding fixed", as the header of this file says. objectCreator is what a
# publish-only credential means: add an object, never replace or remove one. The
# condition keeps agents inside the prefixes they legitimately publish to, so the
# ledger prefix is unreachable even by creation.
resource "google_storage_bucket_iam_member" "runner_results" {
  bucket = google_storage_bucket.results.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.runner.email}"
  condition {
    title      = "agent publish prefixes only"
    expression = <<-EOT
      resource.name.startsWith("projects/_/buckets/${google_storage_bucket.results.name}/objects/find/") ||
      resource.name.startsWith("projects/_/buckets/${google_storage_bucket.results.name}/objects/verify/")
    EOT
  }
}
# objectCreator, not objectAdmin: a runner may add a PoC, never delete one.
# The corpus only grows (invariant 7).
resource "google_storage_bucket_iam_member" "runner_poc" {
  bucket = google_storage_bucket.poc.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.runner.email}"
}

# --- ingester: the only identity that may rewrite ledger/cm-ledger.db ---
resource "google_storage_bucket_iam_member" "ingester_results" {
  bucket = google_storage_bucket.results.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.ingester.email}"
}
resource "google_storage_bucket_iam_member" "ingester_poc_read" {
  bucket = google_storage_bucket.poc.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.ingester.email}"
}

# --- gate: read the ledger, and nothing else, ever ---
# Without this the gate cannot answer at all, and a gate that cannot answer is
# a gate that gets bypassed.
resource "google_storage_bucket_iam_member" "gate_results_read" {
  bucket = google_storage_bucket.results.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.gate.email}"
}
resource "google_storage_bucket_iam_member" "gate_poc_read" {
  bucket = google_storage_bucket.poc.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.gate.email}"
}

# --- WIF: bind the in-cluster KSA to each GSA ---
# The KSA name must match the binding exactly. A mismatch yields an EMPTY
# identity and a 401 from Vertex that reads like a quota problem (deploy note W1).
resource "google_service_account_iam_member" "wif_runner" {
  service_account_id = google_service_account.runner.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.runner_namespace}/${var.name_prefix}-runner]"
}
resource "google_service_account_iam_member" "wif_ingester" {
  service_account_id = google_service_account.ingester.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.runner_namespace}/${var.name_prefix}-ingester]"
}

# The gate records its own decisions -- and ONLY that. objectCreator can create a
# new object and nothing else: it cannot read the ledger with this binding, cannot
# overwrite an existing event, and cannot delete. Invariant 3 survives: a gate that
# could write the ledger is a gate that could mark its own blocker fixed. The
# condition pins it to the one prefix; without it, "write access to the results
# bucket" is exactly what the invariant forbids.
resource "google_storage_bucket_iam_member" "gate_events_create" {
  bucket = google_storage_bucket.results.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.gate.email}"

  condition {
    title       = "gate-events-prefix-only"
    description = "Create-only, and only under warehouse/gate-events/."
    expression  = "resource.name.startsWith('projects/_/buckets/${google_storage_bucket.results.name}/objects/warehouse/gate-events/')"
  }
}

# --- GitHub Actions -> GSA, via Workload Identity Federation ---
#
# These bindings existed only as hand-run `gcloud` commands until 2026-08-25, which
# meant `terraform plan` was clean while the thing that lets CI authenticate lived
# nowhere in the config. The gate's binding was made by hand and the ingester's was
# never made at all -- so the sign-off path (D53) would have failed at auth on its
# first real use, with a credentials error that reads like a WIF misconfiguration
# rather than a missing grant.
#
# The pool and provider are created in step 0g of the guide (they are shared with
# other things in this project and are not owned here), so this binds to them by
# name rather than declaring them.
data "google_project" "this" {
  project_id = var.project_id
}

locals {
  wif_principal_prefix = join("", [
    "principalSet://iam.googleapis.com/projects/",
    data.google_project.this.number,
    "/locations/global/workloadIdentityPools/",
    var.wif_pool_id,
    "/attribute.repository/",
  ])
}

# The gate identity: reads the ledger, writes only its own event objects.
resource "google_service_account_iam_member" "gh_gate" {
  for_each           = toset(var.github_repos)
  service_account_id = google_service_account.gate.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "${local.wif_principal_prefix}${each.value}"
}

# The ingester identity: the sole writer to the ledger (invariant 3). A participant
# repo assumes this ONLY from the cm-risk-accept ingest job, which runs on a merge to
# the default branch -- i.e. after review. The branch protection is what makes that
# meaningful; this grant alone would let any workflow in the repo assume it.
resource "google_service_account_iam_member" "gh_ingester" {
  for_each           = toset(var.github_repos)
  service_account_id = google_service_account.ingester.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "${local.wif_principal_prefix}${each.value}"
}
