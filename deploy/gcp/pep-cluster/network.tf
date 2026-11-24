# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE PEP ENVIRONMENT'S OWN NETWORK: a VPC peered with nothing, one subnet,
# and Cloud NAT on ONE reserved address — the environment's single egress
# address (`egress_ip`), the one the identity service admits.
#
# FIREWALL RULES TARGET THE MEMBERS' SERVICE ACCOUNT, as an environment's
# target its nodes' (deploy/gcp/environment/firewall.tf): a tag is set by
# anybody who can edit an instance. In: Google's front ends and health
# checkers on 9443 and 9543, and nothing else — no rule names the companion's
# 9700. Out: 443, and everything else denied.
#
# PRIVATE GOOGLE ACCESS on the subnet, so the registry, Secret Manager and
# logging are reached without the NAT; only the identity service is.
# ---------------------------------------------------------------------------

resource "google_compute_network" "main" {
  name                    = local.prefix
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "members" {
  name                     = "${local.prefix}-members"
  region                   = var.region
  network                  = google_compute_network.main.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
}

resource "google_compute_address" "egress" {
  name         = "${local.prefix}-egress"
  region       = var.region
  address_type = "EXTERNAL"
  description  = "iya-sts ${var.environment}: the PEP cluster's one egress address, for the identity service to admit"
}

resource "google_compute_router" "main" {
  name    = local.prefix
  region  = var.region
  network = google_compute_network.main.id
}

resource "google_compute_router_nat" "main" {
  name                               = local.prefix
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "MANUAL_ONLY"
  nat_ips                            = [google_compute_address.egress.self_link]
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.members.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

locals {
  # Where Google's front ends and health checkers connect from.
  google_front_ends = ["35.191.0.0/16", "130.211.0.0/22"]
  member_accounts   = [data.google_service_account.pep.email]
}

resource "google_compute_firewall" "health_checks" {
  name        = "${local.prefix}-front-ends"
  network     = google_compute_network.main.id
  description = "The load balancer's front ends and health checks, to the members' 9443 and 9543"
  direction   = "INGRESS"
  priority    = 1000

  source_ranges           = local.google_front_ends
  target_service_accounts = local.member_accounts

  allow {
    protocol = "tcp"
    ports    = [tostring(local.pep_https_port), tostring(local.pep_proxy_port)]
  }
}

resource "google_compute_firewall" "egress_https" {
  name        = "${local.prefix}-egress-https"
  network     = google_compute_network.main.id
  description = "The registry, Secret Manager, logging and the identity service, on 443"
  direction   = "EGRESS"
  priority    = 1000

  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = local.member_accounts

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "egress_deny" {
  name        = "${local.prefix}-egress-deny"
  network     = google_compute_network.main.id
  description = "Everything else out"
  direction   = "EGRESS"
  priority    = 65000

  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = local.member_accounts

  deny {
    protocol = "all"
  }
}
