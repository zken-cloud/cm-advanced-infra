#!/usr/bin/env bash
# The build context is the REPO ROOT: the image needs pipeline/ scripts, and copying
# them into this directory is how poc-normalise.py silently ran a version three
# minutes older than the one under test for a whole day (D47).
set -euo pipefail
: "${PROJECT:?set PROJECT}"
REGION="${REGION:-us-central1}"
TAG="${TAG:-0.7.0}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMG="$REGION-docker.pkg.dev/$PROJECT/cm-lab/cm-runner:$TAG"

cat > "$ROOT/cloudbuild.runner.yaml" <<YAML
steps:
  - name: gcr.io/cloud-builders/docker
    args: ['build','-f','infra/runner-image/Dockerfile','-t','$IMG','.']
images: ['$IMG']
YAML
trap 'rm -f "$ROOT/cloudbuild.runner.yaml"' EXIT

gcloud builds submit "$ROOT" --config="$ROOT/cloudbuild.runner.yaml" --project="$PROJECT"
gcloud artifacts docker images describe "$IMG" --project="$PROJECT" \
  --format='value(image_summary.fully_qualified_digest)'
