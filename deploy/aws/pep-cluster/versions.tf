# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A REMOTE XACML PEP CLUSTER, AN ENVIRONMENT OF ITS OWN (#1284): its own VPC,
# load balancer, WAF and ECS cluster, reading nothing of any iya-sts
# environment (main.tf). Applied after the members are provisioned
# (provision.sh).
#
# The state key names the PEP environment and the cluster:
#   environment/<pep env>/pep-cluster/<cluster>.tfstate
# under `environment/` because that is the one prefix the deployer role may
# write state under. entrypoint.sh builds it from TF_ENV and TF_PEP_CLUSTER.
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "s3" {
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
