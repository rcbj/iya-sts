# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE IMAGE REPOSITORY (deploy/aws/foundation/ecr.tf).
#
# Artifact Registry, Docker format, in the home region, under the project
# key. Per build: `<sha>` (the service, built with
# STS_CLOUD_SDKS="@google-cloud/secret-manager @google-cloud/kms" — Secret
# Manager for the database password, Cloud KMS for the key-encryption key,
# #391), `schema-<sha>`
# (deploy/gcp/schema-init) and `init-<sha>` (deploy/gcp/node-init: the
# secrets and the ACME certificate).
#
# THE SAME TRIM AS ECR: untagged versions go after a day, and the sixteen most
# recent versions are kept whatever their age — count and not age, so that a
# long-lived `testidp` node can always be restarted on the image it runs.
# ---------------------------------------------------------------------------
resource "google_artifact_registry_repository" "main" {
  repository_id = var.name
  location      = var.region
  format        = "DOCKER"
  description   = "iya-sts (issue #95): service, schema-init and node-init images"
  kms_key_name  = google_kms_crypto_key.main.id

  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "delete-untagged"
    action = "DELETE"
    condition {
      tag_state  = "UNTAGGED"
      older_than = "86400s"
    }
  }

  cleanup_policies {
    id     = "keep-sixteen-most-recent"
    action = "KEEP"
    most_recent_versions {
      keep_count = 16
    }
  }

  # A tagged version the KEEP rule does not cover is deleted after a week;
  # without a DELETE rule for it Artifact Registry deletes nothing tagged.
  cleanup_policies {
    id     = "delete-older-tagged"
    action = "DELETE"
    condition {
      tag_state  = "TAGGED"
      older_than = "604800s"
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.service_agents]
}
