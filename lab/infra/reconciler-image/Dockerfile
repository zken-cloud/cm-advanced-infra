# The reconciler advances the pipeline. It is NOT the agent image, and that
# separation is the point: the agent runs model-generated code, so it must never
# hold a Kubernetes credential or a ledger write. This image holds both and runs
# nothing it did not ship with.
FROM python:3.11-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg git \
 && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
      | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
      > /etc/apt/sources.list.d/google-cloud-sdk.list \
 && apt-get update && apt-get install -y --no-install-recommends \
      google-cloud-cli google-cloud-cli-gke-gcloud-auth-plugin kubectl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/cm/requirements.txt
RUN pip install --no-cache-dir -r /opt/cm/requirements.txt

COPY pipeline/ /opt/cm/pipeline/
COPY k8s/ /opt/cm/k8s/
WORKDIR /opt/cm
ENTRYPOINT ["python3", "/opt/cm/pipeline/reconcile.py"]
