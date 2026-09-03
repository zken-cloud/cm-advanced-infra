terraform {
  required_version = ">= 1.5"

  # Partial config -- the bucket name contains the project id, and a backend block
  # cannot use variables. ./tf-init.sh creates the bucket and supplies the rest
  # via backend.hcl. Do NOT run bare `terraform init`; it will ask you for these.
  backend "gcs" {}

  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
    github = { source = "integrations/github", version = "~> 6.0" }
    time   = { source = "hashicorp/time", version = "~> 0.12" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# The same PAT the lab uses for cloning. It needs `repo` + `workflow`: without
# `workflow` the repo copy cannot carry .github/workflows/ and the fan-out never
# fires.
provider "github" {
  owner = var.github_owner
  token = var.github_token
}
