# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# A VPC OF THE ENVIRONMENT'S OWN (deploy/aws/environment/network.tf).
#
#   <prefix>-nodes    10.x.0.0/24   the three nodes, each with an external
#                                    address (no NAT, AWS's reason)
#   <prefix>-private  10.x.10.0/24  the database's Private Service Connect
#                                    endpoint, and nothing else
#
# A GCP subnet spans the region's zones, so where AWS has three of each this
# has one; the zones are the instance groups' (nodes.tf).
#
# NO NAT: each node has an ephemeral external address so it can reach
# Artifact Registry, Secret Manager, Cloud Logging and the ACME server, and
# the firewall (firewall.tf) admits nothing to it but the load balancer's
# traffic and the health checkers. Private Google Access is on as well, so
# a node that lost its address would still reach Google's APIs.
#
# NO ROUTE IS WRITTEN: a VPC's default internet route and its subnet routes
# are what AWS writes by hand.
# ---------------------------------------------------------------------------
# A CELL MAKES NO NETWORK (#97): it makes its subnets in the environment's
# shared global VPC, which the foundation made (network_multicell.tf there).
resource "google_compute_network" "main" {
  count                   = local.multi ? 0 : 1
  name                    = local.prefix
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "mock-sts ${var.environment} (issue #95)"
}

resource "google_compute_subnetwork" "nodes" {
  name                     = "${local.prefix}-nodes"
  network                  = local.network_id
  region                   = local.region
  ip_cidr_range            = local.nodes_cidr
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "private" {
  name                     = "${local.prefix}-private"
  network                  = local.network_id
  region                   = local.region
  ip_cidr_range            = local.private_cidr
  private_ip_google_access = true
}

data "google_compute_network" "shared" {
  count = local.multi ? 1 : 0
  name  = local.shared_network
}

locals {
  network_id   = local.multi ? data.google_compute_network.shared[0].id : google_compute_network.main[0].id
  network_name = local.multi ? data.google_compute_network.shared[0].name : google_compute_network.main[0].name
}

moved {
  from = google_compute_network.main
  to   = google_compute_network.main[0]
}
