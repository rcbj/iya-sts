# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# WHAT AN ENVIRONMENT'S NODES RUN AS: ONE SERVICE ACCOUNT PER ENVIRONMENT.
#
# AWS lets the deployer CREATE task roles because a permissions boundary caps
# whatever it makes (deploy/aws/foundation/iam_deployer.tf). GCP has no
# boundary: an identity the deployer could create, it could also give any
# role it is allowed to grant. So the deployer creates NO identity. The
# accounts are made here, one per entry in `environments`, and the deployer
# may only ATTACH its environment's to a VM (roles/iam.serviceAccountUser on
# that one account) and grant it access to the secrets that environment made.
#
#   mock-sts-env-<env>@<project>.iam.gserviceaccount.com
#
# What the account holds here, for the life of the project:
#   * roles/logging.logWriter   — Docker's gcplogs driver and COS's own agent
#   * roles/monitoring.metricWriter — COS's node metrics
#   * roles/artifactregistry.reader on the repository only
#   * with a public name: roles/dns.admin on the public zone (the ACME
#     DNS-01 challenge; the zone holds nothing but this project's records),
#     and reading, adding and disabling versions of ITS certificate secret (tls_secrets.tf)
#   * roles/cloudkms.cryptoKeyEncrypterDecrypter and roles/cloudkms.viewer
#     on the service's key-encryption key `mock-sts-kek` only (kms.tf, #391)
#
# What the ENVIRONMENT grants it (deploy/gcp/environment/secrets.tf): reading
# each secret that environment made, one secret at a time. The environment's
# secrets die with it and the grants with them.
#
# ONE ACCOUNT FOR THE WHOLE VM, where AWS had two roles per task: ECS reads
# the task's secrets as the EXECUTION role and the container runs as the TASK
# role, so the service itself could never read the database master password.
# A VM's containers all reach the same metadata server, so the service here
# COULD read every secret its environment has — the master password included.
# The CLAUDE.md records it as the one place this pattern is weaker than AWS's.
# ---------------------------------------------------------------------------
resource "google_service_account" "environment" {
  for_each     = var.environments
  account_id   = "${var.name}-env-${each.key}"
  display_name = "mock-sts ${each.key}: the nodes"
  description  = "What every node of the ${each.key} environment runs as (issue #95). Made by the foundation; the deployer only attaches it."

  depends_on = [google_project_service.apis]
}

locals {
  environment_project_roles = {
    for pair in setproduct(keys(var.environments), [
      "roles/logging.logWriter",
      "roles/monitoring.metricWriter",
    ]) : "${pair[0]}-${pair[1]}" => { env = pair[0], role = pair[1] }
  }
}

resource "google_project_iam_member" "environment" {
  for_each = local.environment_project_roles
  project  = var.project_id
  role     = each.value.role
  member   = google_service_account.environment[each.value.env].member
}

resource "google_artifact_registry_repository_iam_member" "environment" {
  for_each   = var.environments
  location   = google_artifact_registry_repository.main.location
  repository = google_artifact_registry_repository.main.name
  role       = "roles/artifactregistry.reader"
  member     = google_service_account.environment[each.key].member
}

# The ACME DNS-01 challenge (deploy/gcp/node-init/cert.sh): node-a writes
# `_acme-challenge.<name>` TXT records and removes them. The narrowest role
# that can is dns.admin, on this ONE zone.
resource "google_dns_managed_zone_iam_member" "environment_acme" {
  for_each     = local.public_environments
  managed_zone = google_dns_managed_zone.public.name
  role         = "roles/dns.admin"
  member       = google_service_account.environment[each.key].member
}
