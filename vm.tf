# ---------------------------------------------------------------------------
# The lab VM. Bootstraps itself, then applies ../terraform for the cluster half.
# Watch it with:  gcloud compute ssh ... --tunnel-through-iap --command 'cm-lab-status'
# ---------------------------------------------------------------------------

resource "google_compute_instance" "lab" {
  name         = "${var.name_prefix}-vm"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["${var.name_prefix}-vm"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = var.boot_disk_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet.id
    # no access_config block == no external IP. Reach it over IAP.
  }

  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"] # the default set is storage read-only; pushing an image 403s
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin = "TRUE"

    # setup-tree.sh travels with the module, not with the guide repo. It used to be
    # installed from the guide checkout, which silently made this public module
    # depend on a private repo's layout; metadata keeps the two halves of one
    # module together. file(), not templatefile() -- the script's own ${1:?...}
    # must reach the VM intact.
    setup-tree = file("${path.module}/setup-tree.sh")

    startup-script = templatefile("${path.module}/bootstrap.sh", {
      project         = var.project_id
      region          = var.region
      zone            = var.zone
      name_prefix     = var.name_prefix
      guide_repo      = var.guide_repo
      guide_ref       = var.guide_ref
      repo_full       = local.repo_full
      gh_token_secret = google_secret_manager_secret.gh_token.secret_id
      wif_pool_id     = var.wif_pool_id
      upstream_target = var.upstream_target
      tfstate_bucket  = google_storage_bucket.tfstate.name
    })
  }

  depends_on = [
    google_project_iam_member.vm,
    google_project_iam_member.cloudbuild_default,
    google_storage_bucket.tfstate,
    google_compute_router_nat.nat,
    google_secret_manager_secret_version.gh_token,
    github_repository.lab,
    github_actions_variable.vars,
  ]
}
