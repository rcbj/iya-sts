# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# ONE REMOTE XACML PEP CLUSTER ON AN ENVIRONMENT'S LOAD BALANCER (#1284).
# A stack of its own, applied AFTER `environment/` is up and after the
# members are provisioned (provision.sh): it adds ECS services, listeners,
# target groups and security-group rules beside what that stack built, and
# changes nothing of it — the `spiffe-realm/` arrangement.
#
# The state key names the environment and the cluster:
#   environment/<env>/pep-cluster/<cluster>.tfstate
# entrypoint.sh builds it from TF_ENV and TF_PEP_CLUSTER, and destroys it
# before the environment it stands on.
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
