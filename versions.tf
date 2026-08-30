terraform {
  required_version = ">= 1.5"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
    github = { source = "integrations/github", version = "~> 6.0" }
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
