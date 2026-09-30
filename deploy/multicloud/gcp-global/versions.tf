# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE GLOBAL TIER'S GCP HALF, IN A MULTI-CLOUD ENVIRONMENT (#97).
#
# AWS's global/ stack holds the global tier: the RDS writer in the primary
# AWS cell, a physical read replica in every other AWS cell, and the global
# secrets, replicated to every AWS cell region. RDS cannot make a replica in
# GCP, so this stack gives each GCP cell the two things the AWS cells get
# from that one:
#
#   * THE GLOBAL SECRETS, copied from Secrets Manager into Secret Manager —
#     one secret per value, replicated to every GCP cell's region under that
#     region's key, readable by every GCP cell's node account. The values are
#     READ from AWS here, never generated: every cell must hold the same KEK
#     and passwords, and the AWS stack is where they were made.
#   * A COPY OF THE GLOBAL DATABASE per GCP cell: a Cloud SQL instance in the
#     cell's region, on the environment's shared network through private
#     services access, which the cell's own nodes subscribe to the writer's
#     publication at every start (units/sts-global-schema). PostgreSQL's
#     native logical replication, rcbj's choice on 2026-09-30 over reading an
#     AWS replica across the VPN: a GCP cell keeps reading the global tier
#     when AWS is down. The writer stays the one writer (issue #98, D3).
#
# Applied after AWS's global/ (whose state it reads) and before any GCP
# cell's `full` phase (which reads this state). State in the GCP bucket:
#   environment/<env>/gcp-global
# Applied as BOTH deployers: AWS's reads the secrets and the state, GCP's
# makes everything (deploy/multicloud/entrypoint.sh).
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
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
  }

  backend "gcs" {}
}
