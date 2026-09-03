# cm-advanced-infra

Terraform for the CodeMender advanced lab environment. One `apply` builds a
lab VM reachable only over IAP, a private copy of the target repository,
Workload Identity federation for GitHub Actions, and a GKE Autopilot cluster.

This repository is **self-contained**: the terraform at the root builds the
environment, and `lab/` carries everything that runs inside it — the pipeline, the
container images, the cluster terraform, the Kubernetes Jobs, the hooks and the
workflows. The VM clones it anonymously. Nothing here needs a credential to read.

What is deliberately **not** here is any rule that names a bug in the lab target.
Deriving those from your own verified findings is Step 7 of the lab, and shipping
them pre-made would both solve the exercise and solve the public benchmark the
exercise is measured against. `lab/pipeline/harvested-rules/` therefore holds one
generic example rule and nothing else.

The written guide, the decision record and the measurements live separately and
are not needed to run any of this.

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

## Layout

    *.tf, bootstrap.sh, setup-tree.sh   the environment: VM, IAP, WIF, your repo
    lab/infra/{runner,reconciler}-image the two container images the VM builds
    lab/infra/terraform                 the cluster half, applied BY the VM
    lab/k8s                             find/verify Jobs, namespace, service account
    lab/pipeline                        ledger, fingerprinting, harvest, gate, replay
    lab/hooks                           the pre-commit hook
    lab/.github/workflows               fan-out, gate, risk-accept — copied into YOUR repo

`lab/.github/` is deliberately not the repository's own `.github/`: those workflows
are meant to run in a participant's lab repo, and at the root GitHub would try to
run them here, where the variables they need do not exist.

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

### If apply fails on `already exists`

```
409 Service account cm-lab-vm already exists within project ...
409 Your previous request to create the named bucket succeeded and you already own it
422 Repository creation failed. name already exists on this account
```

Nothing is wrong with those resources. Terraform is declarative over **its own
state**, not over the project, so a resource that exists but is not in state is
one it believes it must create — and the API refuses.

This module keeps **local state**, so its state is bound to the directory you
ran from. Applying the same project from a fresh clone, a second working copy or
a new machine gives you an empty state and this error on every resource at once.

`./tf-adopt.sh` imports what already exists and leaves the rest for apply:

```bash
terraform init
./tf-adopt.sh          # adopts pre-existing resources into state
terraform apply
```

It is idempotent, safe on a completely fresh project (it adopts nothing), and
never creates, modifies or deletes a cloud resource — `terraform import` only
writes local state. Run `terraform plan` afterwards and check it says
`0 to destroy` before you apply.

The durable fix is a remote backend for this module, the way the cluster half
already has one. Until then, keep `terraform.tfstate` and run from one place.

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

**Two states, and the order matters.** The terraform at this root owns the VM, the
network, IAP, WIF and the secret. It does **not** own the GKE cluster, the results
and PoC buckets, BigQuery, the Cloud Run reconciler, the Eventarc trigger or the
Cloud Scheduler job — `lab/infra/terraform` owns those, and the VM applied it. So
destroying this root first deletes the machine the other state was applied from and
strands everything above it, still billing, behind a teardown that reported success.

```bash
# 1. ON THE VM — the cluster half, first
gcloud compute ssh cm-lab-vm --zone us-central1-a --tunnel-through-iap --project "$PROJECT"
cd /opt/cm-lab-payload/lab/infra/terraform && sudo terraform destroy

# 2. ON YOUR MACHINE — then this root: VM, IAP path, NAT, WIF, secret
terraform destroy
```

Back up anything you want to keep **before** step 1 — the PoC corpus especially,
which is the one artifact here that cost agent-minutes to produce:

```bash
gcloud storage cp -r "gs://$PROJECT-cm-lab-poc/poc" ./poc-corpus-backup
```

Step 2 ends with two errors, and both are the guardrails working, not failures:
deleting the repo needs `delete_repo` scope, which the lab deliberately does not
ask for (`403 Must have admin rights to Repository`), and the state bucket refuses
to delete without `force_destroy`. Remove both by hand if you actually want them
gone. **Revoke the PAT** — a third copy lives in Secret Manager so pods can clone,
and it outlives your shell.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
