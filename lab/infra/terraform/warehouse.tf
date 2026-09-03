# The analytics half. Nothing here is on a developer's critical path: the gate
# reads the ledger object and never BigQuery, dashboards read BigQuery and never
# the ledger. LAB-DESIGN 4.1 stated that separation when the ledger was going to
# be Postgres; removing Postgres (D34) did not change it, it only changed the
# mechanism from Datastream to a snapshot export.
#
# EXTERNAL tables, not loaded ones. The data already lives in GCS, it is tens of
# megabytes, and an external table means the warehouse is never a second copy that
# can disagree with the ledger.
resource "google_bigquery_dataset" "warehouse" {
  dataset_id                 = replace("${var.name_prefix}_warehouse", "-", "_")
  location                   = var.bq_location
  description                = "Snapshot exports of the CM ledger. Read-only analytics; the merge gate never queries this."
  delete_contents_on_destroy = true

  depends_on = [time_sleep.services_ready]
}

# findings and scans are MUTABLE in the ledger -- verdicts fold upward, fixed_at
# gets set -- so each export is a point-in-time snapshot and the duplicates across
# dt= partitions ARE the trend history. Deduplicate in a view, never on export.
locals {
  warehouse_tables = toset(["findings", "observations", "scans", "coverage",
  "risk_acceptances", "patch_prs"])
  # gate-events uses a hyphen in its prefix but an underscore in its table id, so it
  # is declared separately below; the seed objects cover both spellings.
}


resource "google_bigquery_table" "ledger" {
  for_each            = local.warehouse_tables
  dataset_id          = google_bigquery_dataset.warehouse.dataset_id
  table_id            = each.value
  deletion_protection = false

  # SCHEMA IS DECLARED, NOT INFERRED, and generated from ledger.py by
  # pipeline/warehouse-schema.py -- so it is one source of truth, not a hand-kept
  # mirror. `autodetect` reads the shape from whatever files happen to be present:
  # the table then changes silently when the exporter changes, and it cannot be
  # created at all over an empty prefix (`Schema has no fields`, which is what broke
  # the greenfield apply). An inferred schema is a guess that looks like a contract.
  schema = file("${path.module}/warehouse-schema/${each.value}.json")

  external_data_configuration {
    autodetect    = false
    source_format = "NEWLINE_DELIMITED_JSON"
    source_uris   = ["gs://${google_storage_bucket.results.name}/warehouse/${each.value}/*"]

    # CUSTOM, not AUTO. AUTO infers the partition keys from paths, so it needs at
    # least one object to exist before the table can be created -- a chicken-and-egg
    # on a fresh project. Declaring the layout removes the dependency on data
    # existing, and states the contract the exporter is already writing to.
    hive_partitioning_options {
      mode                     = "CUSTOM"
      source_uri_prefix        = "gs://${google_storage_bucket.results.name}/warehouse/${each.value}/{dt:DATE}"
      require_partition_filter = false
    }
  }
  # BigQuery APPENDS the hive partition key `dt` to an external table's schema on
  # read, but REJECTS a create whose schema declares it. So the config can never
  # equal the API's answer, and terraform plans a delete+create forever.
  #
  # ignore_changes on `schema` is the narrowest fix available: it silences exactly
  # the field with the asymmetry. The cost is real -- a genuine schema change no
  # longer shows in the plan -- and that cost is paid by
  # pipeline/test_warehouse_schema.py, which compares the generated schema against
  # the live ledger on every run. The contract is still checked; it is just checked
  # by the tests rather than by terraform.
  lifecycle {
    ignore_changes = [schema]
  }
}

# Gate decisions are the programme's only record of its own effect on developers:
# BLOCK rate, RACE rate, how long a blocked sha stays blocked. They are written by
# the gate itself, one new object per run, which is why this is a separate prefix
# and a separate table -- see the objectCreator binding in iam.tf.
resource "google_bigquery_table" "gate_events" {
  dataset_id          = google_bigquery_dataset.warehouse.dataset_id
  table_id            = "gate_events"
  deletion_protection = false

  schema = file("${path.module}/warehouse-schema/gate_events.json")

  external_data_configuration {
    autodetect    = false
    source_format = "NEWLINE_DELIMITED_JSON"
    source_uris   = ["gs://${google_storage_bucket.results.name}/warehouse/gate-events/*"]

    hive_partitioning_options {
      mode                     = "CUSTOM"
      source_uri_prefix        = "gs://${google_storage_bucket.results.name}/warehouse/gate-events/{dt:DATE}"
      require_partition_filter = false
    }
  }

  # BigQuery APPENDS the hive partition key `dt` to an external table's schema on
  # read, but REJECTS a create whose schema declares it. So the config can never
  # equal the API's answer, and terraform plans a delete+create forever.
  #
  # ignore_changes on `schema` is the narrowest fix available: it silences exactly
  # the field with the asymmetry. The cost is real -- a genuine schema change no
  # longer shows in the plan -- and that cost is paid by
  # pipeline/test_warehouse_schema.py, which compares the generated schema against
  # the live ledger on every run. The contract is still checked; it is just checked
  # by the tests rather than by terraform.
  lifecycle {
    ignore_changes = [schema]
  }
}
