# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# ONE JURISDICTION'S PAIR: AN AWS CELL AND ITS GCP PARTNER IN THE SAME METRO,
# JOINED BY HA VPN (#97).
#
# GOOGLE'S DOCUMENTED PATTERN for HA VPN to AWS: a GCP HA VPN gateway (two
# interfaces) and a Cloud Router on one side; on the other, a virtual private
# gateway on the cell's VPC, one customer gateway per GCP interface, and one
# Site-to-Site connection per customer gateway — two tunnels each, FOUR in
# all, every one carrying BGP. Any one tunnel keeps the pair joined, and GCP
# gives the arrangement its 99.99% availability.
#
# WHAT CROSSES IT: every AWS cell's VPC CIDR one way (the VGW advertises its
# VPC), and the other way everything the GCP network holds — with GLOBAL
# routing, every GCP cell's subnets, not only this partner's — plus two
# things GCP must advertise by hand: the private-services ranges (the global
# tier's Cloud SQL copies, which subscribe to the RDS writer) and
# 35.199.192.0/19, where Cloud DNS's forwarding comes from (the AWS cells'
# inter-cell names, forwarded to this cell's inbound resolver, below).
#
# THE INSIDE ADDRESSES AND KEYS ARE CHOSEN HERE, not left to AWS, so that
# GCP's router interfaces can be written from them: four /30s of
# 169.254.100.0/24 per pair (`index`), the VGW on .1 and GCP on .2 of each —
# none in the ranges AWS reserves (169.254.0.0/28-ish and 169.254.169.252/30).
# ---------------------------------------------------------------------------
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    google = {
      source = "hashicorp/google"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

variable "prefix" {
  description = "mock-sts-<env>-<aws cell>"
  type        = string
}

variable "index" {
  description = "The pair's number (0-3): its inside /30s and its ASNs."
  type        = number
}

variable "aws_cell" {
  description = "The AWS cell's VPC, route tables and private subnets (its state's outputs)."
  type = object({
    id                   = string
    vpc_id               = string
    vpc_cidr             = string
    route_table_ids      = map(string)
    private_subnet_ids   = list(string)
    private_subnet_cidrs = list(string)
  })
}

variable "gcp_region" {
  description = "The GCP partner's region, where the HA VPN gateway and router are."
  type        = string
}

variable "network" {
  description = "The GCP cells' shared network (self link)."
  type        = string
}

variable "advertised_ranges" {
  description = "What GCP advertises beyond its subnets: the private-services ranges and Cloud DNS's forwarding range."
  type        = list(string)
}

locals {
  gcp_asn = 64600 + var.index
  aws_asn = 64520 + var.index
  # tunnel t (0-3): connection t/2, that connection's tunnel t%2 + 1
  tunnels = {
    for t in range(4) : t => {
      connection = floor(t / 2)
      aws_tunnel = t % 2 + 1
      inside     = cidrsubnet("169.254.100.0/24", 6, var.index * 4 + t)
    }
  }
}

# ---- GCP ------------------------------------------------------------------
resource "google_compute_router" "vpn" {
  name    = "${var.prefix}-vpn"
  region  = var.gcp_region
  network = var.network

  bgp {
    asn               = local.gcp_asn
    advertise_mode    = "CUSTOM"
    advertised_groups = ["ALL_SUBNETS"]
    dynamic "advertised_ip_ranges" {
      for_each = var.advertised_ranges
      content {
        range = advertised_ip_ranges.value
      }
    }
  }
}

resource "google_compute_ha_vpn_gateway" "gcp" {
  name    = "${var.prefix}-vpn"
  region  = var.gcp_region
  network = var.network
}

# ---- AWS ------------------------------------------------------------------
resource "aws_vpn_gateway" "cell" {
  vpc_id          = var.aws_cell.vpc_id
  amazon_side_asn = local.aws_asn
  tags            = { Name = "${var.prefix}-vgw" }
}

resource "aws_customer_gateway" "gcp" {
  count      = 2
  bgp_asn    = local.gcp_asn
  ip_address = google_compute_ha_vpn_gateway.gcp.vpn_interfaces[count.index].ip_address
  type       = "ipsec.1"
  tags       = { Name = "${var.prefix}-gcp-${count.index}" }
}

# Pre-shared keys: letters and digits, never starting with 0 (AWS's rule).
resource "random_password" "psk" {
  count   = 4
  length  = 40
  special = false
}

locals {
  psk = [for p in random_password.psk : "k${p.result}"]
}

resource "aws_vpn_connection" "gcp" {
  count               = 2
  vpn_gateway_id      = aws_vpn_gateway.cell.id
  customer_gateway_id = aws_customer_gateway.gcp[count.index].id
  type                = "ipsec.1"
  static_routes_only  = false

  tunnel1_inside_cidr   = local.tunnels[count.index * 2].inside
  tunnel2_inside_cidr   = local.tunnels[count.index * 2 + 1].inside
  tunnel1_preshared_key = local.psk[count.index * 2]
  tunnel2_preshared_key = local.psk[count.index * 2 + 1]
  tunnel1_ike_versions  = ["ikev2"]
  tunnel2_ike_versions  = ["ikev2"]

  tags = { Name = "${var.prefix}-gcp-${count.index}" }
}

# The GCP cells' routes, learned by BGP, into both of the cell's route tables
# (its nodes' and its databases').
resource "aws_vpn_gateway_route_propagation" "cell" {
  for_each       = var.aws_cell.route_table_ids
  vpn_gateway_id = aws_vpn_gateway.cell.id
  route_table_id = each.value
}

# ---- GCP's four tunnels and their BGP sessions ----------------------------
resource "google_compute_external_vpn_gateway" "aws" {
  name            = "${var.prefix}-aws"
  redundancy_type = "FOUR_IPS_REDUNDANCY"

  dynamic "interface" {
    for_each = local.tunnels
    content {
      id = interface.key
      ip_address = interface.value.aws_tunnel == 1 ? (
        aws_vpn_connection.gcp[interface.value.connection].tunnel1_address
      ) : aws_vpn_connection.gcp[interface.value.connection].tunnel2_address
    }
  }
}

resource "google_compute_vpn_tunnel" "aws" {
  for_each                        = local.tunnels
  name                            = "${var.prefix}-aws-${each.key}"
  region                          = var.gcp_region
  vpn_gateway                     = google_compute_ha_vpn_gateway.gcp.id
  vpn_gateway_interface           = each.value.connection
  peer_external_gateway           = google_compute_external_vpn_gateway.aws.id
  peer_external_gateway_interface = each.key
  shared_secret                   = local.psk[each.key]
  router                          = google_compute_router.vpn.id
  ike_version                     = 2
}

resource "google_compute_router_interface" "aws" {
  for_each   = local.tunnels
  name       = "${var.prefix}-aws-${each.key}"
  region     = var.gcp_region
  router     = google_compute_router.vpn.name
  ip_range   = "${cidrhost(each.value.inside, 2)}/30"
  vpn_tunnel = google_compute_vpn_tunnel.aws[each.key].name
}

resource "google_compute_router_peer" "aws" {
  for_each                  = local.tunnels
  name                      = "${var.prefix}-aws-${each.key}"
  region                    = var.gcp_region
  router                    = google_compute_router.vpn.name
  interface                 = google_compute_router_interface.aws[each.key].name
  peer_ip_address           = cidrhost(each.value.inside, 1)
  peer_asn                  = local.aws_asn
  advertised_route_priority = 100
}

# ---------------------------------------------------------------------------
# THE CELL'S INBOUND RESOLVER: where Cloud DNS forwards this AWS cell's
# inter-cell names (the GCP foundation's forwarding zone), answered from the
# Cloud Map namespace ECS keeps. At .53 of the cell's first two private /24s,
# the addresses the foundation wrote before this existed; admitting only
# Cloud DNS's forwarding range.
# ---------------------------------------------------------------------------
resource "aws_security_group" "resolver" {
  name        = "${var.prefix}-resolver"
  description = "mock-sts: the inbound resolver, from Cloud DNS forwarding over the HA VPN (#97)"
  vpc_id      = var.aws_cell.vpc_id
  tags        = { Name = "${var.prefix}-resolver" }
}

resource "aws_vpc_security_group_ingress_rule" "resolver" {
  for_each          = toset(["udp", "tcp"])
  security_group_id = aws_security_group.resolver.id
  description       = "DNS from Cloud DNS forwarding (35.199.192.0/19)"
  cidr_ipv4         = "35.199.192.0/19"
  ip_protocol       = each.key
  from_port         = 53
  to_port           = 53
}

resource "aws_route53_resolver_endpoint" "inbound" {
  name               = "${var.prefix}-inbound"
  direction          = "INBOUND"
  security_group_ids = [aws_security_group.resolver.id]

  ip_address {
    subnet_id = var.aws_cell.private_subnet_ids[0]
    ip        = cidrhost(var.aws_cell.private_subnet_cidrs[0], 53)
  }

  ip_address {
    subnet_id = var.aws_cell.private_subnet_ids[1]
    ip        = cidrhost(var.aws_cell.private_subnet_cidrs[1], 53)
  }

  tags = { Name = "${var.prefix}-inbound" }
}

output "tunnels_up_hint" {
  description = "Where to look for the BGP sessions."
  value       = "gcloud compute routers get-status ${google_compute_router.vpn.name} --region ${var.gcp_region}"
}
