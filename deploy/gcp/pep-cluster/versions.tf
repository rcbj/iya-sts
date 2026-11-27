# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A REMOTE XACML PEP CLUSTER ON GCP, AN ENVIRONMENT OF ITS OWN (#1284):
# deploy/aws/pep-cluster/'s design, built from GCP's parts (main.tf). Its own
# VPC, NAT, load balancer, Cloud Armor policy and instance groups, reading
# nothing of any iya-sts environment.
#
# Its state is under `environment/<pep env>/pep-cluster/<cluster>` in the
# one state bucket (entrypoint.sh), the prefix the deployer may write.
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }

  backend "gcs" {}
}
