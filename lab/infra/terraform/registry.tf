resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = var.name_prefix
  format        = "DOCKER"
  description   = "CM runner images"
  depends_on    = [time_sleep.services_ready]
}
