# cm-advanced-infra

Terraform for the CodeMender advanced lab environment. One `apply` builds a
lab VM reachable only over IAP, a private copy of the target repository,
Workload Identity federation for GitHub Actions, and a GKE Autopilot cluster.

This repository is **only the environment**. The lab exercises, the pipeline and
the write-up live in `zken-cloud/cm-advanced-lab`, which is private — it ships
answer-key material for a public deliberately-vulnerable target, and publishing
it would solve the benchmark it measures.

## What you need first

| | |
|---|---|
| `terraform` | >= 1.5 |
| `gcloud` | logged in, **including** `gcloud auth application-default login` |
| GCP project | CodeMender enabled, billing on, you are Owner |
| GitHub PAT | classic, scopes **`repo`** and **`workflow`** |

`gcloud auth login` alone is not enough. Terraform reads Application Default
Credentials, so skipping the second login fails on the first resource with a
permissions error rather than a login prompt.

The PAT needs `repo` to create your lab repository and let the in-cluster pods
clone it, and `workflow` because the seeded tree carries `.github/workflows/` —
without it the push is rejected outright and the fan-out never fires. Check
before you spend twenty minutes finding out:

```bash
curl -sI -H "Authorization: token $TF_VAR_github_token" https://api.github.com/user \
  | grep -i x-oauth-scopes          # must list BOTH repo and workflow
```

## Run it

```bash
git clone https://github.com/zken-cloud/cm-advanced-infra.git
cd cm-advanced-infra
cp terraform.tfvars.example terraform.tfvars     # project_id, github_owner, iap_ssh_members
export TF_VAR_github_token=ghp_xxxxxxxx          # the ENVIRONMENT, never the file
terraform init && terraform apply
```

Apply takes about three minutes. The VM then works for another fifteen to
twenty on its own: it installs the toolchain, builds two container images,
applies the cluster half, and seeds your repository. Watch it:

```bash
gcloud compute ssh cm-lab-vm --zone us-central1-a --tunnel-through-iap \
  --project "$PROJECT" --command cm-lab-status
```

`--tunnel-through-iap` is not optional. The VM has no external IP.

> **Keep the PAT out of `terraform.tfvars`.** A token in a file is a token in
> your shell history and eventually in a commit. It still lands in
> `terraform.tfstate`, so treat that as a secret too — it is gitignored here.

## What it builds

- **VM** — Debian 12, `n2-standard-8`, 100 GB, no external IP, Shielded VM on,
  a dedicated service account. 25 GB runs out: every agent gets its own npm tree.
- **Access** — IAP only. Firewall opens tcp:22 to `35.235.240.0/20`, IAP's fixed
  range, not your address. Each member gets `iap.tunnelResourceAccessor` **and**
  `compute.osAdminLogin`; project ownership does not include either.
- **WIF** — pool and OIDC provider with an attribute condition pinning **one**
  repository. Without that condition any repository on GitHub can mint a token
  for your service accounts. It is the single most important line here.
- **Your lab repo** — private, created empty and seeded by the VM. Not a fork: a
  fork is public-linked, inherits upstream's issues and PRs, and ships with
  Actions disabled.
- **Remote state** — a versioned GCS bucket. The cluster half is applied *by the
  VM*; with local state, replacing a disposable VM strands a cluster that
  nothing can destroy.

## Teardown

```bash
terraform destroy
```

Two errors here are the guardrails working, not failures: deleting the repo
needs `delete_repo` scope, which the lab deliberately does not ask for, and the
state bucket refuses to delete without `force_destroy`. Remove both by hand if
you actually want them gone. **Revoke the PAT** — a third copy lives in Secret
Manager so pods can clone, and it outlives your shell.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
