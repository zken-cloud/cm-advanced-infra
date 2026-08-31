#!/usr/bin/env bash
# Lab VM bootstrap. Runs once, unattended, as root, at first boot.
#
# It does 0b, 0c, 0e, 0f and 0g so the participant starts at Step 1. It is
# deliberately noisy and deliberately fails loudly: a half-built lab that looks
# finished costs more than one that says which step died.
#
# Progress:  cm-lab-status        Full log:  /var/log/cm-lab-bootstrap.log
set -uo pipefail
exec > >(tee -a /var/log/cm-lab-bootstrap.log) 2>&1

# The metadata script runner gives you NO HOME. Everything that writes a dotfile
# then fails in its own dialect -- gcloud container get-credentials says
# "environment variable HOME or KUBECONFIG must be set to store credentials for
# kubectl", which sounds like a kubectl problem and is an environment one. The same
# commands work by hand because sudo sets HOME for you.
# $$ escapes the terraform interpolation -- this file is a templatefile.
export HOME="$${HOME:-/root}"

PROJECT="${project}"
REGION="${region}"
ZONE="${zone}"
PREFIX="${name_prefix}"
GUIDE_REPO="${guide_repo}"
GUIDE_REF="${guide_ref}"
REPO_FULL="${repo_full}"
GH_SECRET="${gh_token_secret}"
WIF_POOL="${wif_pool_id}"
UPSTREAM="${upstream_target}"
TFSTATE_BUCKET="${tfstate_bucket}"

STATE=/var/lib/cm-lab
mkdir -p "$STATE"
step() { echo "=== [$(date -u +%H:%M:%S)] $1"; echo "$1" > "$STATE/step"; }
die()  { echo "FAILED at: $1"; echo "FAILED: $1" > "$STATE/step"; exit 1; }

# The status command the guide tells people to run.
cat > /usr/local/bin/cm-lab-status <<'STATUS'
#!/usr/bin/env bash
# Reports where the bootstrap is -- and builds ~/cm-lab if it is not there yet.
#
# It has to do that rather than just report, because OS Login creates your account
# on FIRST LOGIN: at boot there is no uid 1000 for the bootstrap to build a tree
# for. A /etc/profile.d hook was the first attempt and is not enough -- it runs for
# login shells only, so `gcloud compute ssh --command ...` silently skips it and
# you get a READY that is not true.
S=$(cat /var/lib/cm-lab/step 2>/dev/null || echo "not started")
LOCAL=$([ -f /var/lib/cm-lab/local-done ] && echo yes || echo no)

if [ "$LOCAL" = yes ] && [ ! -d "$HOME/cm-lab" ]; then
  echo "setting up ~/cm-lab for $(id -un) (first run) ..."
  sudo /usr/local/bin/cm-lab-setup-tree "$(id -un)" || {
    echo "TREE SETUP FAILED -- sudo cm-lab-setup-tree \"$(id -un)\" to retry"; exit 1; }
fi

# kubectl credentials, per user. The bootstrap ran get-credentials as root, so the
# kubeconfig landed in /root/.kube -- and every Part C step that runs kubectl then
# fails with "connection to the server localhost:8080 was refused", which reads as a
# broken cluster and is a missing file in YOUR home.
if [ "$S" = READY ] && [ ! -f "$HOME/.kube/config" ]; then
  . /var/lib/cm-lab/env 2>/dev/null || true
  echo "fetching cluster credentials for $(id -un) ..."
  gcloud container clusters get-credentials "$${PREFIX:-cm-lab}" \
    --region "$${REGION:-us-central1}" --project "$PROJECT" >/dev/null 2>&1 \
    || echo "  could not fetch credentials -- gcloud container clusters get-credentials, by hand"
fi

TREE=$([ -d "$HOME/cm-lab/src" ] && echo yes || echo no)
case "$S" in
  READY)
    if [ "$TREE" = yes ]; then echo "READY -- everything is up, cluster included."
    else echo "cluster READY, but ~/cm-lab is missing: sudo cm-lab-setup-tree \"$(id -un)\""; fi ;;
  FAILED:*)
    echo "$S"
    [ "$TREE" = yes ] && echo "Part B still works: your lab tree is built and needs nothing below."
    echo "log: sudo tail -50 /var/log/cm-lab-bootstrap.log" ;;
  *)
    if [ "$TREE" = yes ]; then
      echo "PART B READY -- start Step 1 now. The cluster half is still building ($S)."
      echo "Part C needs it; run this again before Step 4."
    else
      echo "still working: $S"
    fi
    echo "log: sudo tail -f /var/log/cm-lab-bootstrap.log" ;;
esac
STATUS
chmod 0755 /usr/local/bin/cm-lab-status

# ---------------------------------------------------------------------------
step "0b/1 apt packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || die "apt update"
apt-get install -y -qq git python3-pip python3-yaml pipx jq sqlite3 unzip \
  build-essential ca-certificates curl gnupg lsb-release || die "apt packages"

step "0b/2 node 22, terraform, kubectl, gh"
curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null 2>&1 || die "nodesource"
curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg || die "hashicorp key"
echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list
mkdir -p /etc/apt/keyrings
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg || die "gh key"
chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list
apt-get update -qq || die "apt update (repos)"
apt-get install -y -qq nodejs terraform kubectl google-cloud-cli-gke-gcloud-auth-plugin gh || die "toolchain"

step "0b/3 semgrep (pipx: Debian 12 is PEP 668)"
# PIPX_HOME must NOT be root's. The first version let pipx default to
# /root/.local/pipx and symlinked /usr/local/bin/semgrep at it -- and /root is 0700,
# so a lab user could not traverse the link and `command -v semgrep` returned
# nothing. Step 1 IS a semgrep command, so that broke the first thing the guide asks
# anyone to do, while every root-run check said semgrep was installed.
export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
pipx install semgrep >/dev/null 2>&1 || pip3 install --break-system-packages -q semgrep || die "semgrep"
chmod -R a+rX /opt/pipx 2>/dev/null || true
# Prove it works as somebody who is not root -- the only test that mattered, since
# every root-run check passed while the lab user had nothing.
#
# HOME must be writable. Without it this check fails on a PERFECTLY GOOD install:
# `nobody`'s home is /nonexistent and semgrep mkdirs a config dir on startup, so the
# first version of this guard failed every bootstrap and blocked a working build.
# A control that fails closed still has to be right about what it is testing.
# The HOME must be writable BY NOBODY, not merely writable. `mktemp -d` returns a
# 0700 directory owned by root -- the second wrong version of this guard, which also
# failed a good install. Chmod it, and clean it up.
SGHOME=$(mktemp -d); chmod 0777 "$SGHOME"
su -s /bin/bash nobody -c "HOME=$SGHOME semgrep --version" >/dev/null 2>&1 \
  || { rm -rf "$SGHOME"; die "semgrep is installed but not usable by a non-root user (check PIPX_HOME perms)"; }
rm -rf "$SGHOME"

step "0b/4 codemender CLI (--version=stable)"
cd /tmp
gcloud artifacts generic download --project=cmoc-prod --location=us \
  --repository=codemender-cli-production --package=cm --version=stable \
  --name=cm-linux-amd64.zip --destination=/tmp >/dev/null || die "cm download (is CodeMender enabled on this project?)"
unzip -o -q /tmp/cm-linux-amd64.zip -d /tmp && install -m0755 /tmp/cm /usr/local/bin/cm || die "cm install"
CM_SHA=$(sha256sum /usr/local/bin/cm | cut -d' ' -f1)
echo "cm $(/usr/local/bin/cm --version 2>&1 | head -1)  sha256=$CM_SHA"

step "0f/1 clone the guide @ $${GUIDE_REF}"
# The token is still read here -- the find pods and the reconciler need it to clone
# the PARTICIPANT's repo -- but the payload clone below no longer uses it.
GH_TOKEN=$(gcloud secrets versions access latest --secret="$GH_SECRET" --project="$PROJECT") || die "read gh token secret"
[ -n "$GH_TOKEN" ] || die "gh token secret is EMPTY -- nothing downstream can clone"
# ANONYMOUS. The payload lives in this same public repo under lab/. It used to be a
# private repo cloned with the PAT, which meant `terraform apply` could succeed in
# full and the VM would then die here, ~2 minutes later, in a process nobody is
# watching -- a silent failure reported by a participant whose PAT had no access.
# A public clone cannot fail that way.
git clone -q --branch "$GUIDE_REF" "$GUIDE_REPO" /opt/cm-lab-payload || die "clone payload from $GUIDE_REPO @ $GUIDE_REF (public: no credentials involved)"
# Record what we got, then DROP the .git. Two reasons, both about the participant's
# repo being the only one that matters:
#   * setup-tree symlinks ~/cm-lab-payload into this tree. With .git present that
#     puts the user inside a checkout whose origin is the shared public repo, one
#     `git push` away from writing to it -- and an org member HAS that access.
#   * nothing after the clone needs git here. The payload is read-only input.
# PROVENANCE keeps the pinned sha, which is the part worth keeping (invariant 10).
git -C /opt/cm-lab-payload rev-parse HEAD > /tmp/payload-sha
printf 'payload %s @ %s\nsha %s\n' "$GUIDE_REPO" "$GUIDE_REF" "$(cat /tmp/payload-sha)" \
  > /opt/cm-lab-payload/PROVENANCE
rm -rf /opt/cm-lab-payload/.git
echo "payload pinned at $(cat /tmp/payload-sha) (.git dropped: read-only input)"
GUIDE=/opt/cm-lab-payload/lab

step "0f/2 the lab tree"
# Config for setup-tree, which is the ONE implementation and is what cm-lab-status
# calls if your tree is not there yet.
cat > "$STATE/env" <<ENV
PROJECT=$PROJECT
REPO_FULL=$REPO_FULL
GH_SECRET=$GH_SECRET
GUIDE=$GUIDE
UPSTREAM=$UPSTREAM
PREFIX=$PREFIX
REGION=$REGION
ENV
# From instance metadata, where vm.tf put it -- NOT from the guide checkout. The
# two files are one module and must not be able to drift apart, and the guide repo
# no longer carries a copy to drift from.
curl -sf -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/setup-tree \
  -o /usr/local/bin/cm-lab-setup-tree || die "fetch setup-tree from instance metadata"
chmod 0755 /usr/local/bin/cm-lab-setup-tree

# OS Login creates the participant's account on FIRST LOGIN, so at boot there is
# usually no uid 1000 and there is nobody to build a tree for. That is normal and
# not a failure: cm-lab-status builds it on first run instead. Build it now only if
# somebody is already there.
LAB_USER=$(getent passwd 1000 | cut -d: -f1 || true)
if [ -n "$LAB_USER" ]; then
  /usr/local/bin/cm-lab-setup-tree "$LAB_USER" || die "lab tree setup"
  echo "built ~/cm-lab for $LAB_USER"
else
  echo "no uid-1000 user yet (OS Login creates it on first SSH) -- cm-lab-status will build the tree"
fi

# ---------------------------------------------------------------------------
# The LOCAL half is done: tools, cm, the guide, and setup-tree installed. This
# marker says exactly that and no more. It is deliberately NOT called
# "partb-ready": the first version was, and it claimed a readiness it had never
# checked -- the tree did not exist and the status said PART B READY anyway.
# Whether Part B can actually start is a question about $HOME, so cm-lab-status
# answers it by looking, per user.
# ---------------------------------------------------------------------------
touch "$STATE/local-done"
echo "=== LOCAL HALF DONE. cm-lab-status will build ~/cm-lab and start Step 1. ==="

step "0c/0 artifact registry"
# No auto-create, unlike gcr.io: pushing into a repo that does not exist fails with
# a bare `NOT_FOUND: Requested entity was not found`, which names nothing.
gcloud artifacts repositories describe "$PREFIX" --location="$REGION" --project="$PROJECT" >/dev/null 2>&1 \
  || gcloud artifacts repositories create "$PREFIX" --repository-format=docker \
       --location="$REGION" --project="$PROJECT" --description="runner + reconciler images" \
  || die "artifact registry repo"

step "0c/1 build the runner image"
# The Dockerfile pins cm's sha256 and fails the build on a mismatch -- that is the
# control that stops an unpinned agent binary reaching a pod. `stable` moved once
# already, so reconcile the pin with what we actually downloaded rather than
# shipping a build that cannot succeed.
cp /usr/local/bin/cm "$GUIDE/infra/runner-image/cm"
PINNED=$(grep -oE '[a-f0-9]{64}' "$GUIDE/infra/runner-image/Dockerfile" | head -1)
if [ "$PINNED" != "$CM_SHA" ]; then
  echo "NOTE: stable has moved since this guide was written."
  echo "      Dockerfile pins $PINNED"
  echo "      downloaded      $CM_SHA"
  echo "      Repinning to the binary actually installed, and recording it."
  sed -i "s/$PINNED/$CM_SHA/" "$GUIDE/infra/runner-image/Dockerfile"
  echo "$CM_SHA" > "$STATE/cm-sha-repinned"
fi
cd "$GUIDE" && PROJECT=$PROJECT REGION=$REGION TAG=qs-1 bash infra/runner-image/build.sh > /tmp/runner-build.log 2>&1 \
  || { tail -30 /tmp/runner-build.log; die "runner image build"; }
RUNNER_DIGEST=$(tail -1 /tmp/runner-build.log)
echo "runner: $RUNNER_DIGEST"
case "$RUNNER_DIGEST" in *@sha256:*) ;; *) die "runner build produced no digest" ;; esac

step "0c/2 build the reconciler image"
cd "$GUIDE" && PROJECT=$PROJECT REGION=$REGION TAG=qs-1 bash infra/reconciler-image/build.sh > /tmp/recon-build.log 2>&1 \
  || { tail -30 /tmp/recon-build.log; die "reconciler image build"; }
RECON_DIGEST=$(tail -1 /tmp/recon-build.log)
echo "reconciler: $RECON_DIGEST"
case "$RECON_DIGEST" in *@sha256:*) ;; *) die "reconciler build produced no digest" ;; esac

step "0e apply the cluster half (GKE, buckets, ledger, reconciler)"
cd "$GUIDE/infra/terraform"
cat > terraform.tfvars <<TFVARS
project_id          = "$PROJECT"
region              = "$REGION"
name_prefix         = "$PREFIX"
reconciler_image    = "$RECON_DIGEST"
github_repos        = ["$REPO_FULL"]
github_token_secret = "$GH_SECRET"
wif_pool_id         = "$WIF_POOL"
TFVARS
# Remote state, so this survives the VM. Written here rather than committed: the
# manual path in docs/MANUAL-SETUP.md has no bucket to point at.
cat > backend.tf <<BACKEND
terraform {
  backend "gcs" {
    bucket = "$TFSTATE_BUCKET"
    prefix = "cluster"
  }
}
BACKEND
terraform init -input=false -reconfigure >/dev/null || die "terraform init (remote state)"
# 0c/0 created the repo with gcloud, because it had to exist before the first push.
# Adopt it here so ../terraform is its single Terraform owner, rather than failing on
# ALREADY_EXISTS forever.
terraform import google_artifact_registry_repository.images \
  "projects/$PROJECT/locations/$REGION/repositories/$PREFIX" >/dev/null 2>&1 || true
# Retry with a wait. A first apply into a young project races Google's own service
# agents, and these two were seen for real:
#
#   Error creating Trigger: Permission denied while using the Eventarc Service Agent
#   Error applying IAM policy for cloudrunv2 service ...
#
# Honest status: they are PLAUSIBLY transient -- that is the documented shape of
# service-agent provisioning -- but this lab has not observed them clear. The run
# that hit them was retried once and failed the same way; the run after it failed
# for an unrelated reason (lost state, fixed by the GCS backend above). So the
# retries are a reasonable hedge, not a proven fix, and the errors are printed if
# they run out.
APPLIED=0
for ATTEMPT in 1 2 3 4; do
  if terraform apply -input=false -auto-approve >> /tmp/tf-apply.log 2>&1; then
    APPLIED=1; echo "  apply converged on attempt $ATTEMPT"; break
  fi
  echo "  apply attempt $ATTEMPT did not converge; waiting 60s (service-agent propagation)"
  sleep 60
done
[ "$APPLIED" = 1 ] || { grep -aoE 'Error:[^"]{0,200}' /tmp/tf-apply.log | tail -10; die "terraform apply (see /tmp/tf-apply.log)"; }

step "0g set RUNNER_IMAGE (a digest exists only now)"
echo "$GH_TOKEN" | gh auth login --with-token || die "gh auth"
gh variable set RUNNER_IMAGE --repo "$REPO_FULL" --body "$RUNNER_DIGEST" || die "gh variable RUNNER_IMAGE"
gh variable list --repo "$REPO_FULL"

step "0e/2 kubernetes namespace, KSA and clone secret"
gcloud container clusters get-credentials "$PREFIX" --region "$REGION" --project "$PROJECT" || die "get-credentials"
sed -e "s#__PROJECT__#$PROJECT#g" "$GUIDE/k8s/00-ns-sa.yaml" | kubectl apply -f - || die "namespace/KSA"
kubectl -n cm delete secret gh-token --ignore-not-found >/dev/null 2>&1
kubectl -n cm create secret generic gh-token --from-literal=token="$GH_TOKEN" || die "clone secret"

step "READY"
echo "=== bootstrap complete ==="
