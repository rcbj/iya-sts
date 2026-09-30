# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE ONE CROSS-CLOUD STACK: gcp.iyasec.io DELEGATED FROM ROUTE 53 (#95).
#
# AWS manages the iyasec.io public zone and always will. This stack writes ONE
# record into it — `gcp.iyasec.io NS <Cloud DNS's four name servers>` — read
# from the GCP foundation's zone, so the two cannot disagree.
#
# Applied ONCE, by an administrator holding BOTH clouds' credentials, after
# the GCP foundation: the deployer roles of either cloud may not write it
# (the AWS deployer may write only the names in foundation/'s `public_dns`,
# and an NS record at a zone cut is not one to hand to a per-environment
# role). Re-applied only if the Cloud DNS zone is ever re-created, which
# changes its name servers.
#
# STATE IN THE GCP STATE BUCKET, beside the foundation's:
#   terraform -chdir=deploy/gcp/dns-delegation init \
#     -backend-config=bucket=mock-sts-terraform-state-<project>
#   terraform -chdir=deploy/gcp/dns-delegation apply -var project_id=<project>
#
# #97 (load balancing across clouds) will put its records in the same Route
# 53 zone; this stack owns only the delegation.
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "gcs" {
    prefix = "dns-delegation"
  }
}
