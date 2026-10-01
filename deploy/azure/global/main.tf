# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

locals {
  subscription_id = data.azurerm_client_config.current.subscription_id

  # `mock-sts-<env>-global`: every name here, and the foundation's resource
  # group of the same name, in the primary cell's region.
  prefix         = "${var.name}-${var.environment}-global"
  resource_group = "${var.name}-${var.environment}-global"

  primary        = var.cells[var.primary_cell]
  primary_region = local.primary.region
  replica_cells  = { for id, c in var.cells : id => c if id != var.primary_cell }

  tags = merge(var.tags, {
    Project     = "STS"
    Environment = var.environment
    Cell        = "global"
  })

  db_name        = "sts"
  db_master_user = "stsadmin"
  db_app_user    = "sts_app"
  db_port        = 5432

  # A REGION'S SHORT CODE: ../foundation/locals.tf's table, which argues it,
  # repeated here and in ../environment/cells.tf because one stack cannot
  # read another's locals. Keep the three in step.
  region_codes = {
    australiaeast      = "ae"
    brazilsouth        = "brs"
    canadacentral      = "cnc"
    canadaeast         = "cne"
    centralindia       = "inc"
    centralus          = "cus"
    eastasia           = "ea"
    eastus             = "eus"
    eastus2            = "eus2"
    francecentral      = "frc"
    germanywestcentral = "gwc"
    japaneast          = "jpe"
    koreacentral       = "krc"
    malaysiawest       = "myw"
    northeurope        = "ne"
    southeastasia      = "sea"
    swedencentral      = "sdc"
    switzerlandnorth   = "szn"
    uksouth            = "uks"
    westeurope         = "we"
    westus2            = "wus2"
    westus3            = "wus3"
  }

  # A CELL'S ADDRESSES ARE A FORMULA OF ITS CIDR — ../environment/cells.tf's
  # `cell_private`, which argues it. Keep the two in step.
  global_db_ip = {
    for id, c in var.cells : id => cidrhost(cidrsubnet(c.vpc_cidr, 8, 10), 12)
  }
}

# ---------------------------------------------------------------------------
# EVERY CELL, AS ITS OWN APPLY LEFT IT: its VNet, its private subnet, its
# security group, its load balancer's address — outputs of ../environment/
# (outputs.tf there, *What the global/ stack reads*), which is why every cell
# is applied, at least in `base`, before this stack.
# ---------------------------------------------------------------------------
data "terraform_remote_state" "cell" {
  for_each = var.cells
  backend  = "azurerm"
  config = {
    subscription_id      = var.subscription_id
    resource_group_name  = var.state_resource_group
    storage_account_name = var.state_storage_account
    container_name       = "tfstate"
    key                  = "environment/${var.environment}/${each.key}.tfstate"
    use_azuread_auth     = true
  }
}

locals {
  cell = {
    for id, c in var.cells : id => {
      region            = c.region
      code              = local.region_codes[c.region]
      resource_group    = data.terraform_remote_state.cell[id].outputs.resource_group
      vnet_id           = data.terraform_remote_state.cell[id].outputs.vnet_id
      vnet_name         = data.terraform_remote_state.cell[id].outputs.vnet_name
      private_subnet_id = data.terraform_remote_state.cell[id].outputs.private_subnet_id
      nodes_nsg_name    = data.terraform_remote_state.cell[id].outputs.nodes_nsg_name
      lb_public_ip_id   = data.terraform_remote_state.cell[id].outputs.lb_public_ip_id
      outbound_address  = data.terraform_remote_state.cell[id].outputs.outbound_address
      container_ports   = data.terraform_remote_state.cell[id].outputs.container_ports
    }
  }
}

data "azurerm_resource_group" "global" {
  name = local.resource_group
}

# THE FOUNDATION'S PER-REGION PARTS the global tier uses: the `mock-sts` key
# (the global tier is what every region may hold) and the identity a server
# reads it as — in each cell's region, because a server's key must be in its
# own region.
data "azurerm_key_vault" "keys" {
  for_each            = var.cells
  name                = "msk${local.region_codes[each.value.region]}-${substr(sha1("${local.subscription_id}/${var.name}/${each.value.region}"), 0, 6)}"
  resource_group_name = "${var.name}-${local.region_codes[each.value.region]}"
}

data "azurerm_key_vault_key" "main" {
  for_each     = var.cells
  name         = var.name
  key_vault_id = data.azurerm_key_vault.keys[each.key].id
}

data "azurerm_user_assigned_identity" "postgres" {
  for_each            = var.cells
  name                = "${var.name}-${local.region_codes[each.value.region]}-postgres"
  resource_group_name = "${var.name}-${local.region_codes[each.value.region]}"
}

# Each cell's vault (the foundation's formula, ../foundation/locals.tf).
data "azurerm_key_vault" "cell" {
  for_each            = var.cells
  name                = "ms${var.environment}${each.key}-${substr(sha1("${local.subscription_id}/${var.name}/${var.environment}/${each.key}"), 0, 4)}"
  resource_group_name = "${var.name}-${var.environment}-${each.key}"
}
