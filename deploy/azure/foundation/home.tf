# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# WHAT THERE IS ONE OF (#96): the foundation's own resource group in the home
# region, the image registry, the public DNS zone, and each region's keys,
# disk-encryption sets and logs (modules/region).
# ---------------------------------------------------------------------------
resource "azurerm_resource_group" "foundation" {
  name     = "${var.name}-foundation"
  location = var.home_region
  tags     = local.common_tags
}

module "region" {
  source   = "./modules/region"
  for_each = local.regions

  region             = each.key
  code               = local.region_codes[each.key]
  name               = var.name
  subscription_id    = local.subscription_id
  tenant_id          = local.tenant_id
  admin_object_id    = data.azurerm_client_config.current.object_id
  tags               = local.common_tags
  log_retention_days = var.log_retention_days
  key_rotation_days  = var.key_rotation_days
}

# ---------------------------------------------------------------------------
# THE IMAGE REGISTRY: ECR's and Artifact Registry's counterpart.
#
# PREMIUM, because Premium is the tier that GEO-REPLICATES: a replica in
# every other region an environment runs in, so a cell's nodes pull from
# their own region and still start when the home region is the one that
# failed (AWS's ECR replication, #98). The name is global and alphanumeric,
# so it carries a hash of the subscription.
#
# NO ADMIN USER: the nodes pull with their managed identity (AcrPull,
# units.tf) and the deployer pushes with its Entra ID token (AcrPush,
# iam_deployer.tf).
#
# Encrypted under Microsoft's key, not ours: a customer-managed key on a
# registry cannot be removed once set and must be in the registry's region,
# and the images are public source built into public layers. Listed in
# deploy/azure/CLAUDE.md with the other hardening steps.
# ---------------------------------------------------------------------------
resource "azurerm_container_registry" "main" {
  name                = "${replace(var.name, "-", "")}${substr(sha1(local.subscription_id), 0, 8)}"
  location            = var.home_region
  resource_group_name = azurerm_resource_group.foundation.name
  sku                 = "Premium"
  admin_enabled       = false

  # Untagged manifests (every push of a tag that moved) are deleted after a
  # week — ECR's lifecycle rule, near enough.
  retention_policy_in_days = 7

  dynamic "georeplications" {
    for_each = setsubtract(local.regions, [var.home_region])
    content {
      location                = georeplications.value
      zone_redundancy_enabled = false
      tags                    = local.common_tags
    }
  }

  tags = local.common_tags
}

# ---------------------------------------------------------------------------
# THE PUBLIC SUB-ZONE, azure.iyasec.io (#96).
#
# AWS MANAGES iyasec.io AND ALWAYS WILL (rcbj, 2026-09-30). This subscription
# answers only the sub-domain delegated to it: Azure DNS holds the zone, and
# an NS record in the Route 53 zone names its name servers
# (deploy/azure/dns-delegation/). Until that record exists nothing here
# resolves from the internet and an ACME DNS-01 challenge fails.
#
# HERE AND NOT IN environment/ for GCP's reason: the deployer may write
# records in this one zone (DNS Zone Contributor on it, iam_deployer.tf) and
# may create or delete no zone.
#
# NO DNSSEC: it would need a DS record in the parent beside the NS record,
# and the parent's signing is AWS's.
# ---------------------------------------------------------------------------
resource "azurerm_dns_zone" "public" {
  name                = var.dns_zone_name
  resource_group_name = azurerm_resource_group.foundation.name
  tags                = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}
