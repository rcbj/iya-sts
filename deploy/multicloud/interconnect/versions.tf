# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# WHAT JOINS THE TWO CLOUDS INTO ONE ENVIRONMENT, AND WHAT PUTS IT BEHIND ONE
# NAME (#97, 2026-09-30).
#
#   network.tf   an HA VPN per jurisdiction pair (modules/pair), each AWS
#                cell's inbound resolver, and the GCP cells' inter-cell names
#                inside the AWS VPCs
#   routing.tf   the public name's Route 53 tree over all six cells —
#                geolocation for the pinned countries, geoproximity for
#                everyone else — the GCP cells' health checks and console
#                names, the ACME challenge delegations, and the GCP firewall
#                rule that lets Route 53's checkers in
#
# Applied after every cell's `base` phase (it reads each one's state) and
# before any `full` phase: the VPN is what a GCP cell's nodes reach the
# global writer through, and the challenge delegation is what a GCP node's
# certificate is issued through. Applied as BOTH deployers; state in the AWS
# bucket, under `environment/<env>/`, where the AWS deployer may write:
#   environment/<env>/interconnect.tfstate
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "s3" {
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
