# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE DEPLOYER: WHAT deploy/gcp/environment/ IS APPLIED AS (issue #95).
#
# deploy/aws/foundation/iam_deployer.tf's counterpart, and the one place the
# two clouds' arrangements differ by more than names. AWS scopes the deployer
# by NAME (`mock-sts-*`), by TAG (`Project = STS`) and by REGION, and caps
# every role it creates with a permissions boundary. GCP has none of those
# tools for most of what an environment makes, so the fences are:
#
#   1. THE PROJECT. Every project-level role below is bounded by it, which is
#      why this deployment wants a project of its own (variables.tf).
#   2. NO IDENTITY CREATION. The deployer holds no role that can create a
#      service account, a key or a project IAM binding. The node accounts are
#      made here (identities.tf), and the deployer may only ATTACH each to a
#      VM — roles/iam.serviceAccountUser on that account and no other.
#   3. RESOURCE-LEVEL GRANTS where the resource exists up front: dns.admin on
#      the one public zone (it can write records there and create or delete
#      no zone), write on the state bucket only.
#
# THE PROJECT ROLES, AND WHAT EACH IS FOR:
#   compute.networkAdmin        the VPC, subnets, addresses, the PSC endpoint
#   compute.securityAdmin       firewall rules
#   compute.instanceAdmin.v1    templates, managed instance groups, disks
#   compute.loadBalancerAdmin   health check, backend service, forwarding rules
#   cloudsql.admin              the primary and the replica
#   secretmanager.admin         the environment's secrets, and granting its
#                               node account access to each (a secret's IAM)
#   cloudkms.viewer             finding the project key by name
#   artifactregistry.reader     reading an image's digest (and writer on the one
#                               repository, to push — below)
#   serviceusage.serviceUsageConsumer   calling the APIs at all
#
# secretmanager.admin can read every secret in the project, the foundation's
# certificate secrets included; so can a project owner. That is the price of
# the deployer granting per-secret access at all, and a dedicated project is
# what keeps "every secret" small.
#
# NO KEY. A person IMPERSONATES the deployer (`deployer_members` hold
# roles/iam.serviceAccountTokenCreator on it; terraform-local.sh sets
# GOOGLE_IMPERSONATE_SERVICE_ACCOUNT), so its credentials last an hour and
# are refreshed by the provider — the problem AWS's host-credentials.js was
# written for does not arise. A GitHub workflow would use Workload Identity
# Federation, not a key; it is not built yet (deploy/gcp/CLAUDE.md).
#
# A MISSING PERMISSION shows up as a 403 naming it on plan or apply; add the
# narrowest role that has it here, and an administrator re-applies. The
# deployer cannot widen itself: it holds no IAM administration role.
# ---------------------------------------------------------------------------
resource "google_service_account" "deployer" {
  account_id   = "${var.name}-deployer"
  display_name = "mock-sts deployer"
  description  = "Applies deploy/gcp/environment (issue #95). Impersonated; has no key."

  depends_on = [google_project_service.apis]
}

locals {
  deployer_project_roles = [
    "roles/artifactregistry.reader",
    "roles/cloudkms.viewer",
    "roles/cloudsql.admin",
    "roles/compute.instanceAdmin.v1",
    "roles/compute.loadBalancerAdmin",
    "roles/compute.networkAdmin",
    "roles/compute.securityAdmin",
    "roles/secretmanager.admin",
    "roles/serviceusage.serviceUsageConsumer",
  ]
}

resource "google_project_iam_member" "deployer" {
  for_each = toset(local.deployer_project_roles)
  project  = var.project_id
  role     = each.key
  member   = google_service_account.deployer.member
}

# Attaching an environment's node account to its VMs, and nothing else about
# it: serviceAccountUser grants actAs, not key creation or token minting.
resource "google_service_account_iam_member" "deployer_attaches_environment" {
  for_each           = var.environments
  service_account_id = google_service_account.environment[each.key].name
  role               = "roles/iam.serviceAccountUser"
  member             = google_service_account.deployer.member
}

# The environments' A records, in the one zone.
resource "google_dns_managed_zone_iam_member" "deployer" {
  managed_zone = google_dns_managed_zone.public.name
  role         = "roles/dns.admin"
  member       = google_service_account.deployer.member
}

# Every environment's state, under `environment/` in the one bucket. Object
# admin on the bucket, because the GCS backend writes a lock object beside
# the state and deletes it again.
resource "google_storage_bucket_iam_member" "deployer_state" {
  bucket = local.state_bucket
  role   = "roles/storage.objectAdmin"
  member = google_service_account.deployer.member
}

# Who may act as the deployer.
resource "google_service_account_iam_member" "deployer_impersonators" {
  for_each           = toset(var.deployer_members)
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = each.key
}

# Pushing the three images a build makes (deploy/gcp/CLAUDE.md, *Running it
# by hand*), on the one repository — AWS's deployer pushes to ECR the same way.
resource "google_artifact_registry_repository_iam_member" "deployer_push" {
  location   = google_artifact_registry_repository.main.location
  repository = google_artifact_registry_repository.main.name
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.deployer.member
}
