# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE INTER-CELL LISTENER, 8446, AT A FIXED PRIVATE ADDRESS (#97).
#
# The service's own mutual TLS between cells (issue #98, section 4), on the
# cell Issuing CA's certificates — nothing here to issue — and never on the
# public load balancer or in public DNS.
#
# AN INTERNAL PASSTHROUGH LOAD BALANCER, where AWS uses Cloud Map. AWS could
# not put an internal NLB in front (ECS allows five target groups per service
# and the public NLB takes them all); GCP has no such limit, and a load
# balancer gives the one thing a cross-cloud name needs: an address that does
# not change when a node is replaced. That is what lets the name be a fixed
# record made before any cell exists — in the foundation's private zone for
# the GCP side and a Route 53 private zone for the AWS side
# (deploy/multicloud/interconnect) — rather than a registration that follows
# every task.
#
# THE ADDRESS IS .5 OF THE CELL'S FIRST /24, a formula the foundation repeats
# to write the record (deploy/gcp/foundation/network_multicell.tf); change
# both or neither. GLOBAL ACCESS is on: an AWS cell's packets arrive through
# the HA VPN in whichever GCP region its partner is in, and another GCP cell's
# from its own region.
# ---------------------------------------------------------------------------
locals {
  intercell_address = cidrhost(local.nodes_cidr, 5)
}

resource "google_compute_address" "intercell" {
  count        = local.multi ? 1 : 0
  name         = "${local.prefix}-intercell"
  region       = local.region
  subnetwork   = google_compute_subnetwork.nodes.id
  address_type = "INTERNAL"
  address      = local.intercell_address
  description  = "mock-sts ${var.environment} ${var.cell}: the inter-cell listener (#97)"
}

resource "google_compute_region_health_check" "intercell" {
  count  = local.multi ? 1 : 0
  name   = "${local.prefix}-intercell"
  region = local.region

  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  # A TCP connect: the listener asks every caller for a certificate, and a
  # health check has none to give.
  tcp_health_check {
    port = local.intercell_port
  }
}

resource "google_compute_region_backend_service" "intercell" {
  count                 = local.multi ? 1 : 0
  name                  = "${local.prefix}-intercell"
  region                = local.region
  load_balancing_scheme = "INTERNAL"
  protocol              = "TCP"
  network               = local.network_id
  health_checks         = [google_compute_region_health_check.intercell[0].id]
  session_affinity      = "NONE"

  connection_draining_timeout_sec = 30

  dynamic "backend" {
    for_each = local.node_groups
    content {
      group          = backend.value
      balancing_mode = "CONNECTION"
    }
  }
}

resource "google_compute_forwarding_rule" "intercell" {
  count                 = local.multi ? 1 : 0
  name                  = "${local.prefix}-intercell"
  region                = local.region
  load_balancing_scheme = "INTERNAL"
  ip_protocol           = "TCP"
  ip_address            = google_compute_address.intercell[0].address
  network               = local.network_id
  subnetwork            = google_compute_subnetwork.nodes.id
  backend_service       = google_compute_region_backend_service.intercell[0].id
  ports                 = [tostring(local.intercell_port)]
  allow_global_access   = true
}
