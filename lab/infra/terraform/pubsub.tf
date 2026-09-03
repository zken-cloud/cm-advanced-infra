# The scale-out write path, off by default (var.enable_pubsub). See ledger.tf
# for why: today the exporter writes blobs and PHASE 3 folds them in.
resource "google_pubsub_topic" "observations" {
  count      = var.enable_pubsub ? 1 : 0
  name       = "${var.name_prefix}-observations"
  depends_on = [time_sleep.services_ready]
}
resource "google_pubsub_subscription" "ingest" {
  count = var.enable_pubsub ? 1 : 0
  name  = "${var.name_prefix}-ingest"
  topic = google_pubsub_topic.observations[0].id

  ack_deadline_seconds       = 60
  message_retention_duration = "86400s"
  expiration_policy { ttl = "" }
}
# Ingester is the sole subscriber (invariant 3).
resource "google_pubsub_subscription_iam_member" "ingester_sub" {
  count        = var.enable_pubsub ? 1 : 0
  subscription = google_pubsub_subscription.ingest[0].name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.ingester.email}"
}
