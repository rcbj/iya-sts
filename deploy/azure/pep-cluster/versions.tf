# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A REMOTE XACML PEP CLUSTER, AN ENVIRONMENT OF ITS OWN, ON AZURE (#1284):
# deploy/aws/pep-cluster/ built from Azure's parts (main.tf). Applied after
# the members are provisioned (provision.sh). Its state is
#   pep-cluster/<pep env>/<cluster>.tfstate
# in the one state container, beside the environments'; entrypoint.sh builds
# the key from TF_ENV and TF_PEP_CLUSTER.
# ---------------------------------------------------------------------------
terraform {
  required_version = ">= 1.11"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.50"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  backend "azurerm" {
    container_name   = "tfstate"
    use_azuread_auth = true
  }
}
