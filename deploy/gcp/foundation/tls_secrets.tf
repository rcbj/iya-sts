# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# WHERE AN ENVIRONMENT'S PUBLIC CERTIFICATE AND ITS KEY ARE KEPT (issue #95).
#
# ON AWS the node presents an EXPORTABLE ACM certificate that cert-init
# exports on every start (deploy/aws/CLAUDE.md, *TLS passes through the
# NLB*). GCP HAS NO EQUIVALENT: Certificate Manager never releases a private
# key, so a certificate from it can be presented only by a Google load
# balancer that terminates TLS — the arrangement AWS reversed on 2026-09-17,
# because then no client certificate reaches the node.
#
# SO THE CERTIFICATE IS AN ACME ONE (Let's Encrypt by default), issued by
# node-a against a DNS-01 challenge in the public zone and kept HERE, one
# secret per environment with a public name: the key and the full chain in
# one PEM bundle, under the project key. Every node reads it on every start
# (deploy/gcp/node-init/cert.sh); node-a issues it when there is none and
# renews it when it has under thirty days left.
#
# IN THE FOUNDATION AND NOT THE ENVIRONMENT, because the environment is
# rebuilt many times: Let's Encrypt issues at most FIVE certificates a week
# for the same set of names, and a secret destroyed with every environment
# would mean a new certificate for every build. Here the certificate outlives
# the environment and a rebuild reuses it.
#
# THE KEY IS IN NO TERRAFORM STATE: Terraform makes the empty secret, and the
# only writer of a version is the node. The environment's service account may
# read it and add and disable versions; nothing else may, except a project
# owner and the deployer (roles/secretmanager.admin, iam_deployer.tf).
# ---------------------------------------------------------------------------
resource "google_secret_manager_secret" "tls" {
  for_each  = local.public_environments
  secret_id = "${var.name}-${each.key}-tls"

  labels = {
    environment = each.key
  }

  annotations = {
    public-hostname = each.value.public_hostname
  }

  replication {
    user_managed {
      replicas {
        location = var.region
        customer_managed_encryption {
          kms_key_name = google_kms_crypto_key.main.id
        }
      }
    }
  }

  # Old versions are not pruned here: node-a DISABLES the version it
  # replaces (cert.sh), so an old key can no longer be read, and a disabled
  # version costs nothing.

  depends_on = [google_kms_crypto_key_iam_member.service_agents]
}

resource "google_secret_manager_secret_iam_member" "tls_access" {
  for_each  = local.public_environments
  secret_id = google_secret_manager_secret.tls[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.environment[each.key].member
}

resource "google_secret_manager_secret_iam_member" "tls_versions" {
  for_each  = local.public_environments
  secret_id = google_secret_manager_secret.tls[each.key].id
  role      = "roles/secretmanager.secretVersionManager"
  member    = google_service_account.environment[each.key].member
}
