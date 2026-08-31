# ---------------------------------------------------------------------------
# Everything you must supply. There are four. The rest have working defaults.
# ---------------------------------------------------------------------------

variable "project_id" {
  description = "GCP project id. CodeMender must be enabled on it (Public Preview)."
  type        = string
}

variable "github_owner" {
  description = "Your GitHub user or org. The lab repo is created here."
  type        = string
}

variable "github_token" {
  description = <<-EOT
    GitHub PAT with `repo` and `workflow` scopes. Used three ways: to create your
    lab repo, to set its Actions variables, and -- stored in Secret Manager -- by
    the in-cluster find pods and the Cloud Run reconciler to clone it.

    Set it in the environment, NOT in a file:  export TF_VAR_github_token=ghp_...
    A PAT in a .tfvars is a PAT in your shell history and, eventually, in a commit.
  EOT
  type        = string
  sensitive   = true
}

variable "iap_ssh_members" {
  description = <<-EOT
    Who may open the IAP tunnel, as IAM members: ["user:you@example.com"].
    Being project owner is NOT sufficient -- roles/iap.tunnelResourceAccessor is a
    separate grant, and its absence reads as `4033: not authorized`.
  EOT
  type        = list(string)
}

# --- defaults you can usually leave alone -----------------------------------

variable "region" {
  description = "Must stay us-central1: .github/workflows/cm-fanout.yml hardcodes it."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "name_prefix" {
  type    = string
  default = "cm-lab"
}

variable "lab_repo_name" {
  description = "Name of the private repo created in your account for the lab."
  type        = string
  default     = "cm-lab"
}

variable "upstream_target" {
  description = "The vulnerable app your repo is seeded from."
  type        = string
  default     = "https://github.com/zken-cloud/vulnerable-app.git"
}

variable "guide_repo" {
  description = "The lab payload, cloned onto the VM by the bootstrap. PUBLIC: no credentials."
  type        = string
  default     = "https://github.com/zken-cloud/cm-advanced-infra.git"
}

variable "guide_ref" {
  description = <<-EOT
    Branch or tag of the guide the VM builds from. Pinned rather than "whatever the
    default branch is today" -- the same argument as invariant 10, one layer down:
    a VM that silently bootstraps from a moved branch is running a lab nobody
    reviewed.
  EOT
  type        = string
  default     = "main"
}

variable "machine_type" {
  description = "Several cm processes run at once."
  type        = string
  default     = "n2-standard-8"
}

variable "boot_disk_gb" {
  description = "100 GB, measured: 25 GB ran out. Each agent gets its own npm tree."
  type        = number
  default     = 100
}

variable "wif_pool_id" {
  description = <<-EOT
    Workload Identity Pool id. If your project already has a pool with this id --
    any project that has used GitHub Actions before does -- set
    `create_wif_pool = false` and this config will bind to it instead of failing
    with ALREADY_EXISTS. Never delete a pool to get around that: deletion is a
    30-day soft delete and the name stays taken the whole time.
  EOT
  type        = string
  default     = "cm-lab-github"
}

variable "create_wif_pool" {
  type    = bool
  default = true
}
