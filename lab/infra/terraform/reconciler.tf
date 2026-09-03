# Eventarc -> Cloud Run: the reconciler, woken by object writes rather than a clock.
#
# The EVENT IS ONLY A HINT TO LOOK. Nothing in the handler reads the payload; a pass
# reads the world and does what the state implies. So a duplicate delivery is a
# no-op and a dropped delivery costs latency, not correctness -- which is precisely
# what an event-driven INGESTER cannot claim, and why the logic stays
# level-triggered under an edge-triggered clock.
resource "google_service_account" "reconciler" {
  account_id   = "${var.name_prefix}-reconciler"
  display_name = "Reconciler: advances scans through the pipeline"
  depends_on   = [time_sleep.services_ready]
}

# Writes the ledger, so it needs object admin -- it IS the ingester in this shape.
resource "google_storage_bucket_iam_member" "reconciler_results" {
  bucket = google_storage_bucket.results.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.reconciler.email}"
}

# Creates verify Jobs. container.developer, NOT container.admin: it may schedule
# work in the cluster and may not reconfigure the cluster it schedules into.
resource "google_project_iam_member" "reconciler_gke" {
  project = var.project_id
  role    = "roles/container.developer"
  member  = "serviceAccount:${google_service_account.reconciler.email}"
}

resource "google_secret_manager_secret_iam_member" "reconciler_gh_token" {
  count     = var.github_token_secret == "" ? 0 : 1
  secret_id = var.github_token_secret
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.reconciler.email}"
}

resource "google_cloud_run_v2_service" "reconciler" {
  name     = "${var.name_prefix}-reconciler"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_ONLY" # only Eventarc reaches it

  # The provider defaults this to TRUE for Cloud Run v2, and the effect is not
  # "warn loudly" -- it is that the service can be neither replaced nor destroyed:
  #
  #   Error: cannot destroy service without setting deletion_protection=false
  #
  # Found on the greenfield apply (D49), and it applies to the LIVE project too: the
  # documented `terraform destroy` teardown would have failed on this resource and
  # left the reconciler, its Eventarc trigger and its scheduler job billing. The
  # cluster and the BigQuery tables already set this false; Cloud Run was silently
  # inheriting the opposite default.
  #
  # False is right here. The reconciler holds no state — it reads GCS and creates
  # Jobs. Everything durable is in the buckets, and the buckets are protected on
  # their own terms.
  deletion_protection = false

  # SERVICE-level scaling is not the same block as template.scaling below, and the
  # API always returns a default for it. Undeclared, that default is a permanent
  # one-line diff -- and a plan that is never clean is worse than no plan, because
  # real drift then hides in noise nobody reads any more. We manage instance count
  # via template.scaling; this block is the API's, not ours.
  lifecycle {
    ignore_changes = [scaling]
  }

  template {
    service_account = google_service_account.reconciler.email
    # One instance, one request at a time. A pass that is already running is the
    # reason a second event coalesces instead of starting a competing pass -- two
    # passes would both see "shards complete, no scans row" and both dispatch
    # verify. The ledger CAS keeps the WRITES safe; it does not refund the pods.
    max_instance_request_concurrency = 1
    scaling { max_instance_count = 1 }

    containers {
      image   = var.reconciler_image
      command = ["python3", "/opt/cm/pipeline/reconcile_server.py"]
      env {
        name  = "RESULTS_BUCKET"
        value = google_storage_bucket.results.name
      }
      env {
        name  = "GCP_PROJECT"
        value = var.project_id
      }
      env {
        name = "GKE_CLUSTER"
        # A STRING, not a resource reference (D54). Reading
        # `google_container_cluster.cluster.name` here made the Cloud Run service
        # depend on the cluster, so `terraform apply -target` on the service pulled
        # the cluster's pending REPLACEMENT into scope and executed it. The
        # reconciler needs a name; it does not need an edge in the graph.
        value = var.name_prefix
      }
      env {
        name  = "GKE_REGION"
        value = var.region
      }
      # fp3 is (path, ENCLOSING FUNCTION), resolved with tree-sitter, so the fold
      # needs the source -- which for a private target needs a token. Cloud Run has
      # no in-cluster Secret to borrow, so it reads the same credential from Secret
      # Manager. Without it the reconciler REFUSES to fold rather than fingerprint
      # against a tree it could not fetch (D29); the symptom is a commit that stays
      # at "cannot fetch <sha>" forever, which is the safe failure but still a stop.
      dynamic "env" {
        for_each = var.github_token_secret == "" ? [] : [1]
        content {
          name = "GH_TOKEN"
          value_source {
            secret_key_ref {
              secret  = var.github_token_secret
              version = "latest"
            }
          }
        }
      }
      resources {
        # CPU MUST stay allocated: the handler acks in milliseconds and folds in the
        # background, and a throttled instance would stop mid-clone the moment the
        # 204 is written.
        cpu_idle = false
        limits   = { cpu = "1", memory = "2Gi" }
      }
      startup_probe {
        http_get { path = "/" }
        failure_threshold = 10
        period_seconds    = 5
      }
    }
    timeout = "3600s"
  }
}

# Eventarc's GCS source publishes through Pub/Sub as the storage service agent.
data "google_storage_project_service_account" "gcs" {
  depends_on = [time_sleep.services_ready]
}

resource "google_project_iam_member" "gcs_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

resource "google_service_account" "eventarc" {
  account_id   = "${var.name_prefix}-eventarc"
  display_name = "Eventarc trigger identity"
  depends_on   = [time_sleep.services_ready]
}

resource "google_cloud_run_v2_service_iam_member" "eventarc_invoke" {
  location = google_cloud_run_v2_service.reconciler.location
  name     = google_cloud_run_v2_service.reconciler.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.eventarc.email}"
}

resource "google_project_iam_member" "eventarc_receiver" {
  project = var.project_id
  role    = "roles/eventarc.eventReceiver"
  member  = "serviceAccount:${google_service_account.eventarc.email}"
}

resource "google_eventarc_trigger" "results_written" {
  name            = "${var.name_prefix}-results-written"
  location        = var.region
  service_account = google_service_account.eventarc.email

  matching_criteria {
    attribute = "type"
    value     = "google.cloud.storage.object.v1.finalized"
  }
  matching_criteria {
    attribute = "bucket"
    value     = google_storage_bucket.results.name
  }

  destination {
    cloud_run_service {
      service = google_cloud_run_v2_service.reconciler.name
      region  = var.region
      path    = "/"
    }
  }
  depends_on = [google_project_iam_member.gcs_pubsub_publisher]
}

# ---------------------------------------------------------------------------
# THE BACKSTOP. Eventarc is the primary clock; this is the second one.
#
# D36 pairs the event path with a slow schedule, because level-triggered logic
# only helps if SOMETHING invokes it. An event path alone has no answer for "the
# event never arrived" -- a deleted trigger, an Eventarc outage, a revision that
# will not start -- and the symptom is commits that stay unfolded while the gate
# answers RACE for scans that actually succeeded.
#
# This replaces the in-cluster CronJob (k8s/60-reconciler.yaml, retired). That
# CronJob needed its own KSA, its own Workload Identity binding, RBAC, manifest
# rendering and a kubectl apply outside Terraform -- a second identity path and a
# manual step, to run logic that already runs here. Cloud Scheduler against the
# service that already exists is three resources, fully managed, and reuses the
# exact same code path rather than a parallel copy of it.
#
# Every 30 minutes, not every 3: if this is the thing making progress, something
# upstream is broken and the latency should be visible rather than papered over.
resource "google_service_account" "scheduler" {
  account_id   = "${var.name_prefix}-scheduler"
  display_name = "Reconciler backstop: wakes the reconciler on a slow timer"
  depends_on   = [time_sleep.services_ready]
}

# The ONLY right this identity has. It cannot read the ledger, touch the cluster,
# or create a Job -- it can ask the reconciler to look, and nothing else.
resource "google_cloud_run_v2_service_iam_member" "scheduler_invoke" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.reconciler.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}

resource "google_cloud_scheduler_job" "reconcile_backstop" {
  name        = "${var.name_prefix}-reconcile-backstop"
  region      = var.region
  description = "Level-triggered backstop for the reconciler. The event is only a hint to look; this is the reminder to look anyway."
  schedule    = "*/30 * * * *"
  time_zone   = "Etc/UTC"

  # A missed tick is not worth retrying: the NEXT tick is the retry, and the pass
  # is idempotent by construction. Retrying would only stack passes that the
  # reconciler would coalesce anyway.
  retry_config {
    retry_count = 0
  }

  http_target {
    http_method = "POST"
    uri         = google_cloud_run_v2_service.reconciler.uri
    body        = base64encode("{\"source\":\"scheduler-backstop\"}")
    headers     = { "Content-Type" = "application/json" }
    oidc_token {
      service_account_email = google_service_account.scheduler.email
      audience              = google_cloud_run_v2_service.reconciler.uri
    }
  }
  depends_on = [time_sleep.services_ready]
}
