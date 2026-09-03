locals {
  # Enabled FIRST, and nothing else in this config touches a Google API until
  # time_sleep.services_ready has passed. Ordering against google_project_service
  # alone is not enough: the enable operation returns before the service is
  # serving, which surfaces as a 403 SERVICE_DISABLED on a resource that already
  # declares depends_on.
  #
  # ../../../main.tf (the quickstart module) enables all of these too and does so
  # minutes earlier, so in the normal path every window here has already closed.
  # They stay declared because this config is also applied on its own -- and
  # because bigquery was NOT in this list, which worked only because BigQuery is
  # auto-enabled on new projects and would have failed on one where it is not.
  services = [
    "serviceusage.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    # needed to create the VPC the cluster runs on; implicit on projects that
    # still have the auto-created default network, absent on ones that do not.
    "compute.googleapis.com",
    "iam.googleapis.com",
    "storage.googleapis.com",
    "logging.googleapis.com",
    "container.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "aiplatform.googleapis.com",
    "pubsub.googleapis.com",
    "secretmanager.googleapis.com",
    "eventarc.googleapis.com",
    "run.googleapis.com",
    "cloudscheduler.googleapis.com",
    "bigquery.googleapis.com", # google_bigquery_dataset.warehouse
  ]
}

resource "google_project_service" "svc" {
  for_each           = toset(local.services)
  service            = each.value
  disable_on_destroy = false
}

# See the note above: this, not google_project_service.svc, is what the rest of
# the config orders against.
resource "time_sleep" "services_ready" {
  depends_on      = [google_project_service.svc]
  create_duration = "60s"
}
