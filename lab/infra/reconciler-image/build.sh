#!/usr/bin/env bash
# The build context is the repo root: the image needs pipeline/ and k8s/, and the
# agent image deliberately contains neither a kubeconfig nor these scripts.
set -euo pipefail
: "${PROJECT:?set PROJECT}"
REGION="${REGION:-us-central1}"
TAG="${TAG:-0.1.0}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMG="$REGION-docker.pkg.dev/$PROJECT/cm-lab/cm-reconciler:$TAG"

cp "$ROOT/pipeline/requirements.txt" "$ROOT/requirements.txt"
cat > "$ROOT/cloudbuild.reconciler.yaml" <<YAML
steps:
  - name: gcr.io/cloud-builders/docker
    args: ['build','-f','infra/reconciler-image/Dockerfile','-t','$IMG','.']
images: ['$IMG']
YAML
trap 'rm -f "$ROOT/requirements.txt" "$ROOT/cloudbuild.reconciler.yaml"' EXIT

gcloud builds submit "$ROOT" --config="$ROOT/cloudbuild.reconciler.yaml" --project="$PROJECT"
gcloud artifacts docker images describe "$IMG" --project="$PROJECT" \
  --format='value(image_summary.fully_qualified_digest)'
