#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Replaces `terraform init` for this module. Puts its state in GCS instead of on
# your laptop, then adopts anything that already exists.
#
# WHY: this module used to keep LOCAL state, so its state was bound to whatever
# directory it was last applied from. A second working copy, a fresh clone, or a
# new machine gave you an empty state and 409/422 already-exists on every
# resource at once -- measured on cm-lab-test-zken, where the service account,
# state bucket, network and WIF pool were all left orphaned by a run whose state
# no longer existed anywhere. The cluster half already stores state in GCS for
# exactly this reason (see the note above google_storage_bucket.tfstate); the
# root module is now consistent with it.
#
#   ./tf-init.sh && terraform apply
#
# CHICKEN AND EGG: a backend must exist before `terraform init`, and this module
# DECLARES the bucket it stores state in. So the bucket is created here with
# gcloud first and imported into state afterwards -- the same pattern bootstrap.sh
# already uses for the Artifact Registry repository, and for the same reason.
#
# That is also why the three values below are read out of terraform.tfvars by
# hand rather than with `terraform console`: console needs an initialised
# backend, which is the thing we are creating. Their defaults MUST match
# variables.tf.
# ---------------------------------------------------------------------------
set -euo pipefail

command -v terraform >/dev/null || { echo "terraform not on PATH" >&2; exit 1; }
command -v gcloud    >/dev/null || { echo "gcloud not on PATH" >&2; exit 1; }

tfvar() { # tfvar <name> <default>; TF_VAR_<name> wins, then terraform.tfvars.
  local name=$1 def=${2-} env_val
  env_val=$(printenv "TF_VAR_${name}" || true)
  if [ -n "$env_val" ]; then printf '%s' "$env_val"; return; fi
  if [ -f terraform.tfvars ]; then
    local v
    v=$(sed -nE "s/^[[:space:]]*${name}[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\1/p" \
          terraform.tfvars | head -1)
    if [ -n "$v" ]; then printf '%s' "$v"; return; fi
  fi
  printf '%s' "$def"
}

PROJECT=$(tfvar project_id)
REGION=$(tfvar region us-central1)
PREFIX=$(tfvar name_prefix cm-lab)
[ -n "$PROJECT" ] || { echo "project_id not found in terraform.tfvars or TF_VAR_project_id" >&2; exit 1; }

BUCKET="${PROJECT}-${PREFIX}-tfstate"
STATE_PREFIX="quickstart"           # the cluster half uses its own prefix in the same bucket
REMOTE="gs://${BUCKET}/${STATE_PREFIX}/default.tfstate"

echo "project ${PROJECT} / state gs://${BUCKET}/${STATE_PREFIX}"

# --- the bucket ------------------------------------------------------------
# Versioned, for the reason main.tf already gives: a corrupted state file with no
# history is a cluster you can neither change nor delete.
if gcloud storage buckets describe "gs://${BUCKET}" --project="$PROJECT" >/dev/null 2>&1; then
  echo "  bucket exists"
else
  echo "  creating bucket"
  gcloud storage buckets create "gs://${BUCKET}" --project="$PROJECT" \
    --location="$REGION" --uniform-bucket-level-access >/dev/null
fi
gcloud storage buckets update "gs://${BUCKET}" --project="$PROJECT" --versioning >/dev/null

# --- decide how to init ----------------------------------------------------
# Clobbering one of these with the other is the one genuinely destructive thing
# this script could do, so when both exist it stops and lets you choose.
have_remote=false; have_local=false
gcloud storage ls "$REMOTE" >/dev/null 2>&1 && have_remote=true
[ -s terraform.tfstate ] && grep -q '"resources"' terraform.tfstate 2>/dev/null && have_local=true

cat > backend.hcl <<EOF
bucket = "${BUCKET}"
prefix = "${STATE_PREFIX}"
EOF

if $have_remote && $have_local; then
  echo >&2
  echo "REFUSING TO GUESS: state exists BOTH remotely and in ./terraform.tfstate." >&2
  echo "  remote: ${REMOTE}" >&2
  echo "  local:  $(pwd)/terraform.tfstate" >&2
  echo "Keep one. To keep local and overwrite remote:" >&2
  echo "  terraform init -backend-config=backend.hcl -migrate-state -force-copy" >&2
  echo "To keep remote, move the local file aside and re-run this script." >&2
  exit 1
elif $have_local; then
  echo "  migrating local state -> ${REMOTE}"
  terraform init -input=false -backend-config=backend.hcl -migrate-state -force-copy
else
  # -reconfigure rather than plain init: a .terraform/ left over from a local-state
  # run remembers that backend and init then asks an interactive question.
  terraform init -input=false -reconfigure -backend-config=backend.hcl
fi

# --- adopt whatever already exists, including the bucket we just made ------
echo
exec ./tf-adopt.sh
