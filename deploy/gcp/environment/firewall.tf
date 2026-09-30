# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE FIREWALL: AWS'S THREE SECURITY GROUPS, COLLAPSED INTO RULES ON THE NODES.
#
#   allowed_cidrs ──443,389,636,80,88,8092,8181──▶ (LB address) ──▶ nodes
#   health checkers ──443──────────────────────────────────────────▶ nodes
#   nodes ──443 (Google APIs, ACME) / 53 (DNS-01 checks) ──▶ internet
#   nodes ──5432──▶ the database's PSC endpoint
#
# A PASSTHROUGH LOAD BALANCER IS NOT A HOP (lb.tf): the client's packets
# reach the node with the client's address and the load balancer's address
# as their destination. So the load balancer has no security group of its
# own; the rule that AWS put on the NLB is on the NODES here, and it names
# the load balancer's address as its DESTINATION — an allowed client can reach
# the published ports through the load balancer and not the node's own
# external address.
#
# TARGETED BY SERVICE ACCOUNT, not by network tag: a tag is set by whoever
# can edit an instance, a service account only by whoever may act as it
# (foundation/iam_deployer.tf).
#
# EGRESS IS CLOSED BY A LOW-PRIORITY DENY, AWS's egress rules: 443 anywhere
# (Google's API addresses have no stable list), 53 anywhere for the ACME
# client's propagation check (only with a public name) and the database. The
# metadata server (169.254.169.254) is reachable whatever a rule says; that
# is where a node's credentials and DNS come from.
# ---------------------------------------------------------------------------
locals {
  node_accounts = [data.google_service_account.nodes.email]

  # Google's health-check ranges for a passthrough load balancer, and for a
  # managed instance group's autohealing probe.
  health_check_ranges = [
    "35.191.0.0/16",
    "130.211.0.0/22",
    "209.85.152.0/22",
    "209.85.204.0/22",
  ]
}

resource "google_compute_firewall" "clients" {
  name        = "${local.prefix}-clients"
  network     = local.network_id
  description = "The published ports, from allowed_cidrs, to the load balancer's address"
  direction   = "INGRESS"
  priority    = 1000

  source_ranges           = var.allowed_cidrs
  destination_ranges      = ["${local.lb_address}/32"]
  target_service_accounts = local.node_accounts

  allow {
    protocol = "tcp"
    ports    = [for p in values(local.all_ports) : tostring(p.listener)]
  }
}

resource "google_compute_firewall" "health_checks" {
  name        = "${local.prefix}-health-checks"
  network     = local.network_id
  description = "Google's load balancer and autohealing health checks, on 443"
  direction   = "INGRESS"
  priority    = 1000

  source_ranges           = local.health_check_ranges
  target_service_accounts = local.node_accounts

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "egress_https" {
  name        = "${local.prefix}-egress-https"
  network     = local.network_id
  description = "Google APIs, Artifact Registry, the ACME server"
  direction   = "EGRESS"
  priority    = 1000

  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = local.node_accounts

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "egress_dns" {
  count       = local.public_name ? 1 : 0
  name        = "${local.prefix}-egress-dns"
  network     = local.network_id
  description = "The ACME client asking the zone's name servers whether the DNS-01 record has propagated"
  direction   = "EGRESS"
  priority    = 1000

  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = local.node_accounts

  allow {
    protocol = "udp"
    ports    = ["53"]
  }

  allow {
    protocol = "tcp"
    ports    = ["53"]
  }
}

resource "google_compute_firewall" "egress_database" {
  name        = "${local.prefix}-egress-database"
  network     = local.network_id
  description = "PostgreSQL over TLS, to the database's Private Service Connect endpoint"
  direction   = "EGRESS"
  priority    = 1000

  destination_ranges      = ["${google_compute_address.database.address}/32"]
  target_service_accounts = local.node_accounts

  allow {
    protocol = "tcp"
    ports    = [tostring(local.db_port)]
  }
}

resource "google_compute_firewall" "egress_deny" {
  name        = "${local.prefix}-egress-deny"
  network     = local.network_id
  description = "Nothing else leaves a node"
  direction   = "EGRESS"
  priority    = 65000

  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = local.node_accounts

  deny {
    protocol = "all"
  }
}

# ---------------------------------------------------------------------------
# A CELL'S OWN TRAFFIC (#97): the inter-cell listener, both ways, with every
# OTHER cell of both clouds (their CIDRs arrive over the VPN or the shared
# network); and the global tier — the RDS writer in the primary AWS cell,
# across the VPN, and this cell's Cloud SQL copy in its private-services
# range. The internal load balancer's health checks come from the ranges the
# public one's do (health_checks, above), on 8446.
# ---------------------------------------------------------------------------
resource "google_compute_firewall" "intercell_in" {
  count       = local.multi ? 1 : 0
  name        = "${local.prefix}-intercell-in"
  network     = local.network_id
  description = "The inter-cell listener, from every other cell (#97)"
  direction   = "INGRESS"
  priority    = 1000

  source_ranges           = concat(local.peer_cidrs, local.health_check_ranges)
  target_service_accounts = local.node_accounts

  allow {
    protocol = "tcp"
    ports    = [tostring(local.intercell_port)]
  }
}

resource "google_compute_firewall" "intercell_out" {
  count       = local.multi ? 1 : 0
  name        = "${local.prefix}-intercell-out"
  network     = local.network_id
  description = "The inter-cell listener of every other cell (#97)"
  direction   = "EGRESS"
  priority    = 1000

  destination_ranges      = local.peer_cidrs
  target_service_accounts = local.node_accounts

  allow {
    protocol = "tcp"
    ports    = [tostring(local.intercell_port)]
  }
}

resource "google_compute_firewall" "egress_global_database" {
  count       = local.multi ? 1 : 0
  name        = "${local.prefix}-egress-global-db"
  network     = local.network_id
  description = "The global tier: the RDS writer across the VPN, and this cell's Cloud SQL copy (#97)"
  direction   = "EGRESS"
  priority    = 1000

  destination_ranges = compact([
    var.cells[var.primary_cell].vpc_cidr,
    local.this_cell.global_db_cidr,
  ])
  target_service_accounts = local.node_accounts

  allow {
    protocol = "tcp"
    ports    = [tostring(local.db_port)]
  }
}
