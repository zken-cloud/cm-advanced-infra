# ---------------------------------------------------------------------------
# Workload Identity federation: how your repo's GitHub Actions authenticate to
# GCP without a stored key.
# ---------------------------------------------------------------------------

resource "google_iam_workload_identity_pool" "github" {
  count                     = var.create_wif_pool ? 1 : 0
  workload_identity_pool_id = var.wif_pool_id
  display_name              = "GitHub (CodeMender lab)"
  depends_on                = [google_project_service.svc]
}

locals {
  pool_name = var.create_wif_pool ? google_iam_workload_identity_pool.github[0].name : "projects/${data.google_project.this.number}/locations/global/workloadIdentityPools/${var.wif_pool_id}"
}

data "google_project" "this" {
  project_id = var.project_id
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = var.wif_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  display_name                       = "GitHub OIDC"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }

  # THE control. Without it, ANY repo on GitHub can mint a token for your service
  # accounts -- a full project compromise, and the most common WIF mistake.
  attribute_condition = "assertion.repository == \"${local.repo_full}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  depends_on = [google_iam_workload_identity_pool.github]
}

# ---------------------------------------------------------------------------
# Your copy of the vulnerable app. Private, on your account. You will push
# branches to it and let an agent write patches -- never do that to someone
# else's repository.
# ---------------------------------------------------------------------------

# Created EMPTY and seeded by the VM, not forked and not templated. A fork is
# public-linked, carries upstream's issues and PRs, and has Actions disabled by
# default. `template` is not an option either -- the upstream target is a normal
# repository, and GitHub rejects a template clone of one.
resource "github_repository" "lab" {
  name        = var.lab_repo_name
  description = "CodeMender SDLC lab -- my copy. Deliberately vulnerable code."
  visibility  = "private"
  auto_init   = false

  # The VM pushes the seeded tree here; do not let terraform fight it.
  lifecycle {
    ignore_changes = [description]
  }
}

# The five variables the workflows read. RUNNER_IMAGE is deliberately absent --
# it is a digest, and no digest exists until the VM has built the image. The
# bootstrap sets it.
resource "github_actions_variable" "vars" {
  for_each = {
    GCP_PROJECT    = var.project_id
    WIF_PROVIDER   = google_iam_workload_identity_pool_provider.github.name
    RESULTS_BUCKET = "${var.project_id}-${var.name_prefix}-results"
    POC_BUCKET     = "${var.project_id}-${var.name_prefix}-poc"
  }
  repository    = github_repository.lab.name
  variable_name = each.key
  value         = each.value
}

# ---------------------------------------------------------------------------
# The PAT, for the things that run without you: find pods clone your private repo,
# and the reconciler fetches it to resolve fp3's enclosing function. An empty
# secret here is the silent hour -- shards land, nothing folds, and the gate
# reports RACE with no error anywhere you are told to look.
# ---------------------------------------------------------------------------

resource "google_secret_manager_secret" "gh_token" {
  secret_id = "${var.name_prefix}-gh-token"
  replication {
    auto {}
  }
  depends_on = [google_project_service.svc]
}

resource "google_secret_manager_secret_version" "gh_token" {
  secret      = google_secret_manager_secret.gh_token.id
  secret_data = var.github_token
}
