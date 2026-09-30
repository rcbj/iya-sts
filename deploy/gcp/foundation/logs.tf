# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# CONTAINER LOGS, KEPT AFTER THE ENVIRONMENT THAT WROTE THEM IS GONE
# (deploy/aws/foundation/logs.tf).
#
# Every node runs its containers with Docker's `gcplogs` driver, which writes
# to the log `gcplogs-docker-driver` with the instance and container in each
# entry; a sink routes that log into a bucket of this project's own, under
# the project key, kept `log_retention_days`. Several environments share it
# without meeting: an entry names its instance (`mock-sts-<env>-node-a-…`) and
# its container.
#
# Cloud Logging is project-wide, so logs outlive an environment here by
# construction; the bucket is what gives them the AWS retention and key. The
# `_Default` bucket still receives a copy for its own 30 days — excluding them
# there would be a change to a sink every other thing in the project shares.
# ---------------------------------------------------------------------------
resource "google_logging_project_bucket_config" "containers" {
  project        = var.project_id
  location       = var.region
  bucket_id      = "${var.name}-containers"
  retention_days = var.log_retention_days
  description    = "mock-sts container logs (issue #95)"

  cmek_settings {
    kms_key_name = google_kms_crypto_key.main.id
  }

  depends_on = [google_kms_crypto_key_iam_member.service_agents]
}

resource "google_logging_project_sink" "containers" {
  name        = "${var.name}-containers"
  destination = "logging.googleapis.com/${google_logging_project_bucket_config.containers.id}"
  filter      = "logName=\"projects/${var.project_id}/logs/gcplogs-docker-driver\""

  # A sink into a log bucket of the same project needs no grant.
  unique_writer_identity = true
}
