# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# WHAT A MULTI-CLOUD ENVIRONMENT'S GCP CELLS SHARE, MADE BY AN ADMINISTRATOR
# (#97, 2026-09-30).
#
# ONE GLOBAL VPC PER ENVIRONMENT, `mock-sts-<env>`, which all three GCP cells
# make their subnets in (deploy/gcp/environment, `cell`). A GCP network is
# global, and with GLOBAL dynamic routing a route one region's HA VPN learns
# reaches every region's subnets — so each AWS cell's VPN, to its partner in
# the same metro, joins it to all three GCP cells, and no transit between the
# AWS VPCs (whose peering is not transitive) is ever needed. A VPC per GCP
# cell, as AWS has, would need three VPNs per AWS cell or a transit hub.
#
# HERE AND NOT IN THE ENVIRONMENT, for AWS's dns_inside.tf reason and one of
# GCP's own:
#   * PRIVATE ZONES. The cells find each other's inter-cell listener by name
#     (STS_CELL_PEERS); a GCP cell's name is a record in a private zone, and an
#     AWS cell's is forwarded to that cell's Route 53 inbound resolver. Making
#     a zone takes project-wide dns.admin, which could delete the public zone;
#     the deployer holds dns.admin on the public zone alone.
#   * PRIVATE SERVICES ACCESS, the peering with Google's service network that
#     puts a Cloud SQL instance on this VPC. The global tier's copy in a GCP
#     cell must DIAL OUT to the writer in AWS, which a Private Service Connect
#     endpoint — the cell databases' arrangement, #95 — cannot. PSA's peering
#     does not tear down cleanly with its instances, which is why #95 avoided
#     it; made once here, it is not torn down per run at all.
#
# ALL OF IT IS FREE while nothing runs on it: a network, reserved ranges, a
# peering and private zones cost nothing, the VPN tunnels and the instances
# are the environment's.
#
# EVERY ADDRESS HERE IS COMPUTED, never read from a cell, because this is
# applied before any cell exists. Two formulas must stay in step with the
# stacks that make the addresses:
#   * a GCP cell's inter-cell load balancer: .5 of the cell's first /24
#     (deploy/gcp/environment/intercell.tf, `intercell_address`);
#   * an AWS cell's inbound resolver: .53 of its first two private /24s
#     (deploy/aws/environment/locals.tf's `private_cidrs`, and
#     deploy/multicloud/interconnect).
# ---------------------------------------------------------------------------
resource "google_compute_network" "multicell" {
  for_each                = local.multicell
  name                    = "${var.name}-${each.key}"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  description             = "mock-sts ${each.key}: the GCP cells' shared network (#97)"

  depends_on = [google_project_service.apis]
}

# ONE RANGE PER GCP CELL, its `global_db_cidr` — pinned to that cell's
# instance with `allocated_ip_range`, so a cell's copy of the global tier has
# an address range of its own that the AWS writer's security group admits.
resource "google_compute_global_address" "psa" {
  for_each      = local.gcp_cells
  name          = "${var.name}-${each.value.env}-${each.value.id}-psa"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  address       = split("/", each.value.global_db_cidr)[0]
  prefix_length = tonumber(split("/", each.value.global_db_cidr)[1])
  network       = google_compute_network.multicell[each.value.env].id
}

resource "google_service_networking_connection" "psa" {
  for_each = local.multicell
  network  = google_compute_network.multicell[each.key].id
  service  = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [
    for k, c in local.gcp_cells : google_compute_global_address.psa[k].name if c.env == each.key
  ]
  # Deleting the connection while any instance ever used it fails for days;
  # abandoning it leaves a peering that goes with the network.
  deletion_policy = "ABANDON"
}

# THE VPN'S ROUTES REACH THE CLOUD SQL INSTANCES: a Cloud SQL instance lives
# in Google's service network, which learns this network's routes over the
# peering only when they are exported — without this, a subscription's
# packets to the RDS writer have no route back.
resource "google_compute_network_peering_routes_config" "psa" {
  for_each             = local.multicell
  project              = var.project_id
  peering              = google_service_networking_connection.psa[each.key].peering
  network              = google_compute_network.multicell[each.key].name
  import_custom_routes = false
  export_custom_routes = true
}

# ---------------------------------------------------------------------------
# THE INTER-CELL NAMES, INSIDE THE GCP NETWORK.
#   nodes.<gcp cell>.<env>.mock-sts.internal  A  the cell's internal load
#                                              balancer (a fixed address)
#   <aws cell>.<env>.mock-sts.internal         forwarded to that AWS cell's
#                                              inbound resolver, which answers
#                                              from its Cloud Map namespace
# Forwarded to the cell's OWN region's resolver: when that region is down its
# names do not matter, and no other region depends on it.
# ---------------------------------------------------------------------------
resource "google_dns_managed_zone" "intercell_gcp" {
  for_each    = local.gcp_cells
  name        = "${var.name}-${each.value.env}-${each.value.id}-intercell"
  dns_name    = "${each.value.id}.${each.value.env}.${var.name}.internal."
  description = "mock-sts ${each.value.env}: cell ${each.value.id}'s inter-cell name (#97)"
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.multicell[each.value.env].id
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_dns_record_set" "intercell_gcp" {
  for_each     = local.gcp_cells
  managed_zone = google_dns_managed_zone.intercell_gcp[each.key].name
  name         = "nodes.${each.value.id}.${each.value.env}.${var.name}.internal."
  type         = "A"
  ttl          = 60
  rrdatas      = [cidrhost(cidrsubnet(each.value.vpc_cidr, 8, 0), 5)]
}

resource "google_dns_managed_zone" "intercell_aws" {
  for_each    = local.aws_cells
  name        = "${var.name}-${each.value.env}-${each.value.id}-intercell"
  dns_name    = "${each.value.id}.${each.value.env}.${var.name}.internal."
  description = "mock-sts ${each.value.env}: AWS cell ${each.value.id}'s names, forwarded to its inbound resolver (#97)"
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.multicell[each.value.env].id
    }
  }

  # PRIVATE forwarding: the targets are RFC 1918 addresses across the VPN,
  # and Cloud DNS sends from 35.199.192.0/19, which the Cloud Router
  # advertises to AWS for that reason (deploy/multicloud/interconnect).
  forwarding_config {
    target_name_servers {
      ipv4_address    = cidrhost(cidrsubnet(each.value.vpc_cidr, 8, 10), 53)
      forwarding_path = "private"
    }
    target_name_servers {
      ipv4_address    = cidrhost(cidrsubnet(each.value.vpc_cidr, 8, 11), 53)
      forwarding_path = "private"
    }
  }

  depends_on = [google_project_service.apis]
}

# ---------------------------------------------------------------------------
# EACH GCP CELL'S IDENTITY AND CERTIFICATE SECRET (identities.tf and
# tls_secrets.tf argue both for a single-cell environment). Per CELL here:
# each is a separate unit of failure and residency, and the certificate's
# key is kept in the cell's own region, under its region's key.
# `mock-sts-env-<env>-<cell>` is at most 30 characters for an environment name
# of up to 11 and a five-character cell.
# ---------------------------------------------------------------------------
resource "google_service_account" "cell" {
  for_each     = local.gcp_cells
  account_id   = "${var.name}-env-${each.value.env}-${each.value.id}"
  display_name = "mock-sts ${each.value.env} ${each.value.id}: the nodes"
  description  = "What every node of cell ${each.value.id} of ${each.value.env} runs as (#97). Made by the foundation; the deployer only attaches it."

  depends_on = [google_project_service.apis]
}

locals {
  cell_project_roles = {
    for pair in setproduct(keys(local.gcp_cells), [
      "roles/logging.logWriter",
      "roles/monitoring.metricWriter",
    ]) : "${pair[0]}-${pair[1]}" => { cell = pair[0], role = pair[1] }
  }
}

resource "google_project_iam_member" "cell" {
  for_each = local.cell_project_roles
  project  = var.project_id
  role     = each.value.role
  member   = google_service_account.cell[each.value.cell].member
}

resource "google_artifact_registry_repository_iam_member" "cell" {
  for_each   = local.gcp_cells
  location   = google_artifact_registry_repository.main.location
  repository = google_artifact_registry_repository.main.name
  role       = "roles/artifactregistry.reader"
  member     = google_service_account.cell[each.key].member
}

# The ACME DNS-01 challenge, followed from Route 53 by CNAME into this zone.
resource "google_dns_managed_zone_iam_member" "cell_acme" {
  for_each     = local.gcp_cells
  managed_zone = google_dns_managed_zone.public.name
  role         = "roles/dns.admin"
  member       = google_service_account.cell[each.key].member
}

resource "google_service_account_iam_member" "deployer_attaches_cell" {
  for_each           = local.gcp_cells
  service_account_id = google_service_account.cell[each.key].name
  role               = "roles/iam.serviceAccountUser"
  member             = google_service_account.deployer.member
}

resource "google_secret_manager_secret" "cell_tls" {
  for_each  = local.gcp_cells
  secret_id = "${var.name}-${each.value.env}-${each.value.id}-tls"

  labels = {
    environment = each.value.env
    cell        = each.value.id
  }

  replication {
    user_managed {
      replicas {
        location = each.value.region
        customer_managed_encryption {
          kms_key_name = local.kms_keys[each.value.region]
        }
      }
    }
  }

  depends_on = [
    google_kms_crypto_key_iam_member.service_agents,
    google_kms_crypto_key_iam_member.regional_service_agents,
  ]
}

resource "google_secret_manager_secret_iam_member" "cell_tls_access" {
  for_each  = local.gcp_cells
  secret_id = google_secret_manager_secret.cell_tls[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.cell[each.key].member
}

resource "google_secret_manager_secret_iam_member" "cell_tls_versions" {
  for_each  = local.gcp_cells
  secret_id = google_secret_manager_secret.cell_tls[each.key].id
  role      = "roles/secretmanager.secretVersionManager"
  member    = google_service_account.cell[each.key].member
}
