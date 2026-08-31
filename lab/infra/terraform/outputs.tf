output "cluster_name" { value = google_container_cluster.cluster.name }
output "cluster_location" { value = google_container_cluster.cluster.location }
output "registry" { value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}" }
output "runner_gsa" { value = google_service_account.runner.email }
output "ingester_gsa" { value = google_service_account.ingester.email }
output "gate_gsa" { value = google_service_account.gate.email }
output "results_bucket" { value = google_storage_bucket.results.name }
output "poc_bucket" { value = google_storage_bucket.poc.name }

output "observations_topic" {
  value       = var.enable_pubsub ? google_pubsub_topic.observations[0].name : "disabled"
  description = "Scale-out write path; see var.enable_pubsub."
}
output "ledger_uri" {
  description = "Where the gate and the ingester look for the ledger."
  value       = "gs://${google_storage_bucket.results.name}/ledger/cm-ledger.db"
}
output "max_verify_parallelism" {
  value       = var.max_verify_parallelism
  description = "Pass to run-twophase.sh as MAXP; verify-select.py truncates the worklist there."
}

# The one credential terraform does NOT manage: cloning a private target needs a
# GitHub token or App, and WIF does not reach GitHub. Create it out-of-band:
#   export GH_PAT=...; kubectl -n cm create secret generic gh-token --from-literal=token="$GH_PAT"
output "github_secret_note" {
  value = "kubectl -n ${var.runner_namespace} create secret generic gh-token --from-literal=token=\"$GH_PAT\"  # public targets: any token with no scopes"
}
