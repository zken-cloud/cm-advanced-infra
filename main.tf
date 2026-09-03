# ---------------------------------------------------------------------------
# Quickstart: everything between "I have a GCP project" and "I can run Step 1".
#
# What this owns: the APIs, the lab VM and its identity, the IAP path to it, the
# Workload Identity federation GitHub authenticates through, your copy of the
# vulnerable app, and the PAT secret. What it does NOT own: the cluster, buckets,
# ledger and reconciler -- ../terraform owns those, and the VM's bootstrap runs it.
#
# The split is deliberate. This module needs nothing that does not exist yet; the
# main config needs two image digests, which cannot exist until something has
# built them. The VM is that something.
# ---------------------------------------------------------------------------

locals {
  # Enabled FIRST. Nothing else in this module may touch a Google API until
  # time_sleep.services_ready below has passed.
  #
  # depends_on = [google_project_service.svc] is NOT sufficient and was measured
  # not to be: a resource carrying exactly that still died on
  #   403 SERVICE_DISABLED -- Secret Manager API has not been used in project
  #   <p> before or it is disabled
  # The enable operation returns before the service is serving, so ordering
  # against the enable is not ordering against the API being usable.
  #
  # The list is deliberately wider than what this module creates. The VM applies
  # lab/infra/terraform minutes later; every service enabled here is a
  # propagation window that has already closed by the time that apply runs. Both
  # configs set disable_on_destroy = false, so declaring a service in both is
  # idempotent -- unlike the Artifact Registry repository, an enabled API is not
  # a resource a destroy in one state can take away from the other.
  services = [
    "serviceusage.googleapis.com", # enabling anything at all
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com", # creates the default compute SA that Cloud Build runs as
    "oslogin.googleapis.com", # roles/compute.osAdminLogin has nothing to act on otherwise
    "iap.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com", # WIF token exchange
    "sts.googleapis.com",
    "storage.googleapis.com",    # the tfstate bucket here, results + poc later
    "logging.googleapis.com",    # roles/logging.logWriter has nowhere to write otherwise
    "aiplatform.googleapis.com", # cm calls Vertex as the VM's ADC identity
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "secretmanager.googleapis.com",
    "container.googleapis.com",
    # Below here: not used by THIS module. Front-loaded for the VM's apply of
    # lab/infra/terraform, per the note above.
    "pubsub.googleapis.com",
    "run.googleapis.com",
    "eventarc.googleapis.com",
    "cloudscheduler.googleapis.com",
    "bigquery.googleapis.com",
  ]
  repo_full = "${var.github_owner}/${var.lab_repo_name}"
}

resource "google_project_service" "svc" {
  for_each           = toset(local.services)
  service            = each.value
  disable_on_destroy = false
}

# THE barrier. A service-enable API call returns before the service is actually
# serving, and depends_on cannot express "and is now serving" -- so this waits,
# and everything downstream orders against this rather than against svc.
#
# Measured on a cold project: terraform enabled iam.googleapis.com, waited for the
# operation, and the very next resource died on
#   403 Permission 'iam.workloadIdentityPools.create' denied
# A second `terraform apply` then converged with no changes to the config -- the
# classic signature of enablement lag, not of a missing permission.
#
# 120s rather than 60s. That is a margin, not a measurement: the slowest thing
# gated here is the default compute service account, which compute.googleapis.com
# creates asynchronously some time after its own enable returns. It costs 120s on
# every apply, including ones that would not have raced. That is the right trade
# for the FIRST command of the lab: a hard 403 there is indistinguishable, to a
# participant, from a broken PAT or a wrong project.
resource "time_sleep" "services_ready" {
  depends_on      = [google_project_service.svc]
  create_duration = "120s"
}

# ---------------------------------------------------------------------------
# The lab VM's identity. These five roles are for the WORKLOAD -- pushing images
# and writing results. They deliberately cannot enable APIs or edit IAM, which is
# why the bootstrap runs terraform as the VM SA only after this module has already
# granted it what it needs.
# ---------------------------------------------------------------------------

resource "google_service_account" "vm" {
  account_id   = "${var.name_prefix}-vm"
  display_name = "CodeMender lab VM"
  depends_on   = [time_sleep.services_ready]
}

resource "google_project_iam_member" "vm" {
  for_each = toset([
    "roles/artifactregistry.writer",
    "roles/storage.objectAdmin",
    "roles/cloudbuild.builds.editor",
    "roles/container.developer",
    "roles/aiplatform.user",
    # the bootstrap runs ../terraform as this account, which creates the cluster,
    # buckets, service accounts and the Cloud Run reconciler.
    "roles/editor",
    "roles/resourcemanager.projectIamAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/secretmanager.admin",
    # Without this the guest agent cannot write to Cloud Logging and floods the
    # SERIAL CONSOLE with PermissionDenied for every log line it tried to ship --
    # which is the one surface you have for debugging a bootstrap that failed
    # before SSH worked. Measured on a first apply into an empty project: the
    # bootstrap's own output was unreadable underneath it.
    "roles/logging.logWriter",
    # roles/editor does NOT include run.services.setIamPolicy, so the reconciler's
    # invoker bindings fail with a 403 that never clears -- measured, every attempt
    # of a four-attempt retry on a clean project. Setting an IAM policy is excluded
    # from editor for Cloud Run; run.admin is what grants it.
    "roles/run.admin",
  ])
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.vm.email}"
}

# ---------------------------------------------------------------------------
# Cloud Build runs as the DEFAULT COMPUTE service account, and a new project grants
# that account nothing. Enabling compute.googleapis.com is what creates it -- grant
# before it exists and the binding silently does nothing.
#
# Measured, first apply into an empty project: without these the image build dies on
#   403 ...-compute@developer.gserviceaccount.com does not have storage.objects.get
#   on .../<project>_cloudbuild/objects/source/...
# which reads like a bucket problem and is an IAM one.
#
# Artifact Registry is deliberately NOT created here. AR has no auto-create (unlike
# gcr.io), so it must exist before the first push -- but ../terraform also declares
# it, and two states owning one repository means a destroy here deletes something
# the other still tracks. The bootstrap creates it with gcloud and then imports it,
# so ../terraform is its single Terraform owner.
# ---------------------------------------------------------------------------

resource "google_project_iam_member" "cloudbuild_default" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/artifactregistry.writer",
    "roles/storage.objectAdmin",
  ])
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${data.google_project.this.number}-compute@developer.gserviceaccount.com"

  # The barrier, not depends_on = [google_project_service.svc], is what makes this
  # safe. Enabling compute.googleapis.com is what CREATES this account and it does
  # so asynchronously after the enable returns, so the original ordering produced
  #   400 Service account ...-compute@developer.gserviceaccount.com does not exist
  # which reads like a wrong address and was a race.
  #
  # This was briefly a data.google_compute_default_service_account, which is the
  # more honest way to say "wait for the account". Reverted: a data source is read
  # during plan AND during `terraform import`, so on a project where compute is not
  # yet enabled it 403s and takes every unrelated import down with it -- measured
  # on cm-advanced-lab-zken1, where tf-init.sh created the state bucket and
  # tf-adopt.sh could then not adopt it, leaving apply to 409 on the bucket. That
  # is the greenfield path, which is the one path that must work.
  depends_on = [time_sleep.services_ready]
}

# ---------------------------------------------------------------------------
# Remote state for the cluster half.
#
# ../terraform is applied BY THE VM, and a VM is a disposable thing. With local
# state on its disk, replacing the VM loses the state and the next apply fails with
# 409 already-exists on everything the previous one built -- measured, on the fourth
# apply of this module. Worse, teardown becomes impossible from anywhere else, while
# the runbook tells you to destroy from the VM.
#
# Versioned, because a corrupted state file with no history is a cluster you can
# neither change nor delete.
# ---------------------------------------------------------------------------

resource "google_storage_bucket" "tfstate" {
  name                        = "${var.project_id}-${var.name_prefix}-tfstate"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = false # state is not something to lose to a typo

  versioning {
    enabled = true
  }

  depends_on = [time_sleep.services_ready]
}

# ---------------------------------------------------------------------------
# Network. No external IP: the VM runs model-generated code and does not need to
# be reachable from the internet. Egress is via Cloud NAT, which is all it needs
# for apt, npm and the cm download.
# ---------------------------------------------------------------------------

resource "google_compute_network" "vpc" {
  name                    = "${var.name_prefix}-qs-net"
  auto_create_subnetworks = false
  depends_on              = [time_sleep.services_ready]
}

resource "google_compute_subnetwork" "subnet" {
  name                     = "${var.name_prefix}-qs-subnet"
  ip_cidr_range            = "10.20.0.0/20"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  private_ip_google_access = true
}

resource "google_compute_router" "router" {
  name    = "${var.name_prefix}-qs-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.name_prefix}-qs-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# 35.235.240.0/20 is IAP's fixed forwarding range. It is not your address, and it
# is not a placeholder to narrow -- traffic arrives from there or not at all.
resource "google_compute_firewall" "iap_ssh" {
  name          = "${var.name_prefix}-allow-iap-ssh"
  network       = google_compute_network.vpc.name
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["${var.name_prefix}-vm"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# Three separate things, and having one is not having the others: the firewall rule
# above says traffic may ARRIVE, tunnelResourceAccessor says you may open the
# tunnel, and osAdminLogin says the VM will let you in and give you sudo.
#
# osAdminLogin rather than osLogin because cm-lab-status runs
# `sudo cm-lab-setup-tree` to build your tree on first run -- plain osLogin gets a
# shell with no sudo, and the first thing the guide tells you to run then fails.
# Project ownership grants none of these explicitly; it only works because owner
# happens to include them.
resource "google_project_iam_member" "iap_tunnel" {
  for_each = toset(var.iap_ssh_members)
  project  = var.project_id
  role     = "roles/iap.tunnelResourceAccessor"
  member   = each.value

  depends_on = [time_sleep.services_ready]
}

resource "google_project_iam_member" "os_login" {
  for_each = toset(var.iap_ssh_members)
  project  = var.project_id
  role     = "roles/compute.osAdminLogin"
  member   = each.value

  depends_on = [time_sleep.services_ready]
}
