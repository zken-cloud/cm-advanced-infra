locals {
  services = [
    "container.googleapis.com", "artifactregistry.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "aiplatform.googleapis.com", "pubsub.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudbuild.googleapis.com", "iam.googleapis.com",
    "eventarc.googleapis.com",
    "run.googleapis.com", "cloudscheduler.googleapis.com",
    # needed to create the VPC the cluster runs on; implicit on projects that
    # still have the auto-created default network, absent on ones that do not.
    "compute.googleapis.com"
  ]
}
resource "google_project_service" "svc" {
  for_each           = toset(local.services)
  service            = each.value
  disable_on_destroy = false
}
