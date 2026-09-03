#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Adopt resources that already exist into Terraform state, then let apply build
# the rest.
#
# Terraform is declarative over ITS OWN STATE, not over reality. A resource that
# exists in the project but not in state is one Terraform believes it must
# create, so it calls create and the API refuses:
#
#   409 Service account cm-lab-vm already exists within project ...
#   409 Your previous request to create the named bucket succeeded and you
#       already own it
#   422 Repository creation failed. name already exists on this account
#
# None of that means anything is wrong with the resources. It means state and
# reality disagree, which happens whenever this module is applied from a
# different directory than last time -- its state is LOCAL, so it is bound to
# whatever directory you ran from. /tmp/participant and /tmp/participant4 held
# two different projects' state for exactly this reason.
#
# Run this between `terraform init` and `terraform apply`:
#
#   terraform init
#   ./tf-adopt.sh
#   terraform apply
#
# It is idempotent and safe on a completely fresh project, where it adopts
# nothing and prints nothing but "create". It never creates, modifies or deletes
# a cloud resource -- `terraform import` only writes local state.
#
# NOT covered, deliberately:
#   * google_project_iam_member -- non-authoritative. Re-adding a binding that
#     is already there is a no-op, so these never 409.
#   * google_secret_manager_secret_version -- the version to adopt is not
#     knowable from the config. Apply adds a fresh version carrying the same
#     token, which is harmless; adopting the WRONG version is not.
# ---------------------------------------------------------------------------
set -uo pipefail

command -v terraform >/dev/null || { echo "terraform not on PATH" >&2; exit 1; }
[ -d .terraform ] || { echo "run 'terraform init' first" >&2; exit 1; }

# Read the config the way Terraform does -- tfvars, TF_VAR_*, and the defaults in
# variables.tf -- rather than re-parsing terraform.tfvars and getting it subtly
# wrong when a value is overridden in the environment.
# ONE LINE. terraform console evaluates its input line by line, so a pretty
# multi-line expression is read as several broken ones and fails with no output.
CFG=$(echo 'jsonencode({project = var.project_id, region = var.region, zone = var.zone, prefix = var.name_prefix, repo = var.lab_repo_name, pool = var.wif_pool_id, create_pool = var.create_wif_pool, services = local.services})' | terraform console 2>/dev/null) || {
  echo "terraform console failed -- are project_id/github_owner/github_token set?" >&2; exit 1; }

# console can exit 0 having printed nothing but an error to stderr, in which case
# the `||` above never fires and the parse below dies on an empty string.
[ -n "$CFG" ] || { echo "terraform console returned nothing; run 'terraform validate'" >&2; exit 1; }

# Once state is in GCS, console prints "Acquiring state lock..." on STDOUT ahead
# of the value, so the payload is not the whole output and not necessarily the
# first line. Take the first line that parses; do not assume a position.
eval "$(python3 - "$CFG" <<'PY'
import json, shlex, sys
c = None
for line in sys.argv[1].splitlines():
    try:
        v = json.loads(line.strip())
        c = json.loads(v) if isinstance(v, str) else v
        if isinstance(c, dict) and "project" in c:
            break
        c = None
    except (ValueError, TypeError):
        continue
if c is None:
    sys.exit("could not parse terraform console output:\n" + sys.argv[1][:400])
for k in ("project", "region", "zone", "prefix", "repo", "pool"):
    print(f"{k.upper()}={shlex.quote(c[k])}")
print(f"CREATE_POOL={str(c['create_pool']).lower()}")
print(f"SERVICES={shlex.quote(' '.join(c['services']))}")
PY
)" || { echo "failed to read config from terraform console" >&2; exit 1; }

STATE=$(terraform state list 2>/dev/null)
adopted=0 skipped=0 absent=0

# Adopt one resource. Absence is the normal path on a fresh project and is NOT
# an error: apply creates it. Anything already in state is left alone -- import
# would refuse, and re-importing a managed resource is how you get two addresses
# pointing at one object.
adopt() {
  local addr=$1 id=$2
  if grep -qxF "$addr" <<<"$STATE"; then
    printf '  managed  %s\n' "$addr"; skipped=$((skipped + 1)); return
  fi
  local out
  if out=$(terraform import -input=false -no-color "$addr" "$id" 2>&1); then
    printf '  ADOPTED  %s\n' "$addr"; adopted=$((adopted + 1))
  else
    # A provider that cannot configure itself fails EVERY import, and reporting
    # that as "absent" is the worst possible answer: the plan that follows
    # recreates resources that exist and the apply dies on 409 again, one layer
    # further from the cause. A bad PAT is the likely reason and it is not a
    # missing resource, so stop rather than mislabel.
    if grep -qE 'Bad credentials|failed to lookup organization|Invalid provider configuration|could not find default credentials' <<<"$out"; then
      echo >&2
      echo "PROVIDER FAILED TO CONFIGURE -- aborting rather than reporting everything absent." >&2
      printf '%s\n' "$out" | grep -E '^Error|Bad credentials|organization' | head -3 >&2
      echo "Check TF_VAR_github_token and 'gcloud auth application-default login'." >&2
      exit 1
    fi
    printf '  absent   %s\n' "$addr"; absent=$((absent + 1))
    # Keep the reason available without drowning the normal path in it.
    printf '%s\n' "$out" | sed 's/^/           | /' >>"${ADOPT_LOG:-/dev/null}"
  fi
}

echo "Adopting pre-existing resources in ${PROJECT} into state:"

for s in $SERVICES; do
  adopt "google_project_service.svc[\"${s}\"]" "${PROJECT}/${s}"
done

adopt google_service_account.vm \
  "projects/${PROJECT}/serviceAccounts/${PREFIX}-vm@${PROJECT}.iam.gserviceaccount.com"
adopt google_storage_bucket.tfstate "${PROJECT}-${PREFIX}-tfstate"
adopt google_compute_network.vpc "projects/${PROJECT}/global/networks/${PREFIX}-qs-net"
adopt google_compute_subnetwork.subnet \
  "projects/${PROJECT}/regions/${REGION}/subnetworks/${PREFIX}-qs-subnet"
adopt google_compute_router.router \
  "projects/${PROJECT}/regions/${REGION}/routers/${PREFIX}-qs-router"
adopt google_compute_router_nat.nat \
  "${PROJECT}/${REGION}/${PREFIX}-qs-router/${PREFIX}-qs-nat"
adopt google_compute_firewall.iap_ssh \
  "projects/${PROJECT}/global/firewalls/${PREFIX}-allow-iap-ssh"
adopt google_compute_instance.lab \
  "projects/${PROJECT}/zones/${ZONE}/instances/${PREFIX}-vm"
adopt google_secret_manager_secret.gh_token \
  "projects/${PROJECT}/secrets/${PREFIX}-gh-token"

# A pool that already exists is the ALREADY_EXISTS case variables.tf warns about.
# Adopting it is strictly better than setting create_wif_pool = false, which
# leaves the pool unmanaged and undestroyable by this module.
if [ "$CREATE_POOL" = "true" ]; then
  adopt "google_iam_workload_identity_pool.github[0]" \
    "projects/${PROJECT}/locations/global/workloadIdentityPools/${POOL}"
fi
adopt google_iam_workload_identity_pool_provider.github \
  "projects/${PROJECT}/locations/global/workloadIdentityPools/${POOL}/providers/github-oidc"

adopt github_repository.lab "${REPO}"
for v in GCP_PROJECT WIF_PROVIDER RESULTS_BUCKET POC_BUCKET; do
  adopt "github_actions_variable.vars[\"${v}\"]" "${REPO}:${v}"
done

echo
echo "adopted ${adopted}, already managed ${skipped}, absent (apply will create) ${absent}"
echo "Now run: terraform plan   -- it should show creates only for what is absent."
