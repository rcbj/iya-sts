# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A CELL: THIS STACK, APPLIED ONCE PER REGION OF A MULTI-REGION ENVIRONMENT
# (#96) — deploy/aws/environment/cells.tf's arrangement on Azure, and the
# same contract with the service (issue #98, section 8).
#
# **`cell` EMPTY IS THE SINGLE-REGION STACK, UNCHANGED**: every addition is
# conditional on `local.multi`, and `dev`, `ci` and `testidp` set no cell.
#
# SET, what changes:
#   * the REGION is the cell's, and so are its resource group, node identity
#     and vault — the foundation made one of each per cell;
#   * every name carries the cell (`iya-sts-<env>-<cell>-…`) and the state
#     key is `environment/<env>/<cell>.tfstate` (entrypoint.sh);
#   * the VNet is the cell's own CIDR from the cells file, distinct in every
#     cell, so the cells can be peered (the global/ stack does it);
#   * the cell's own data — its database, disks, secrets — is sealed under
#     its region's `iya-sts-cell` key, which is replicated nowhere; the
#     key-encryption key every cell shares, and the other values that must be
#     the same in every cell, are the global/ stack's, written into this
#     cell's vault;
#   * the nodes answer the other cells on 8446 through an internal load
#     balancer at a fixed address (intercell.tf), and the public name is
#     Traffic Manager's (the global/ stack), with a name of the cell's own
#     beside it (dns.tf).
#
# TWO PHASES, AS ON AWS: `base` makes everything but running nodes (every
# scale set at 0 instances) and reads no global state; `full`, after the
# global/ stack exists, starts the nodes and tells them where it is.
# ---------------------------------------------------------------------------
variable "cell" {
  description = "Which cell of `cells` this apply is (e.g. `zwus2`). EMPTY — the default — is a single-cell environment."
  type        = string
  default     = ""
  validation {
    condition     = var.cell == "" || contains(keys(var.cells), var.cell)
    error_message = "cell must be empty (a single-cell environment) or a key of cells."
  }
}

variable "cells" {
  description = <<-EOT
    Every cell of the environment, by id — from `envs/<env>.cells.tfvars.json`.
    An Azure cell's id is `z` and its region's short code (westus2 is zwus2,
    germanywestcentral zgwc, southeastasia zsea: the table below).
    `jurisdiction` is the legal boundary it sits in (issue #98, section 2);
    `vpc_cidr` its VNet, which must not overlap another cell's. The countries
    Traffic Manager pins are a JURISDICTION's (`jurisdictions`, below).
  EOT
  type = map(object({
    region       = string
    jurisdiction = string
    vpc_cidr     = string
    cloud        = optional(string, "azure")
  }))
  default = {}
  validation {
    condition     = alltrue([for c in values(var.cells) : c.cloud == "azure"])
    error_message = "every cell here is an Azure cell (a multi-cloud environment with Azure cells is not built yet)."
  }
  validation {
    condition     = length(distinct([for c in values(var.cells) : c.vpc_cidr])) == length(var.cells)
    error_message = "every cell's vpc_cidr must be distinct: the cells are peered, and peered VNets may not overlap."
  }
  validation {
    condition     = length(distinct([for c in values(var.cells) : c.region])) == length(var.cells)
    error_message = "one cell per region: a cell is its region's unit of residency."
  }
  validation {
    # EACH CELL IN THE REGION ITS ID NAMES, by `region_codes` below.
    condition = alltrue([
      for id, c in var.cells :
      can(cidrnetmask(c.vpc_cidr)) && id == "z${lookup(local.region_codes, c.region, "?")}"
    ])
    error_message = "each cell's id must be `z` and its region's short code (westus2 is zwus2, germanywestcentral zgwc, southeastasia zsea), in a region the table knows, and vpc_cidr a CIDR."
  }
}

variable "jurisdictions" {
  description = "The jurisdictions and the countries Traffic Manager pins to each (#367's model), from the cells file. Unread here: the routing is the global/ stack's."
  type = map(object({
    geolocation_countries = optional(list(string), [])
  }))
  default = {}
}

variable "primary_cell" {
  description = "The cell whose region holds the global database's WRITER (issue #98, D3). Required with `cells`."
  type        = string
  default     = ""
  validation {
    condition     = length(var.cells) == 0 || contains(keys(var.cells), var.primary_cell)
    error_message = "primary_cell must be a key of cells."
  }
}

variable "cell_phase" {
  description = "`full` (the default, and always, for a single-cell environment) or `base` — see this file's header. entrypoint.sh chooses it."
  type        = string
  default     = "full"
  validation {
    condition     = contains(["base", "full"], var.cell_phase)
    error_message = "cell_phase is base or full."
  }
}

locals {
  # A REGION'S SHORT CODE: ../foundation/locals.tf's table, which argues it,
  # repeated here and in ../global/main.tf because one stack cannot read
  # another's locals. Keep the three in step; adding a region is a row in
  # each.
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

  multi      = var.cell != ""
  this_cell  = local.multi ? var.cells[var.cell] : null
  region     = local.multi ? local.this_cell.region : var.region
  full       = !local.multi || var.cell_phase == "full"
  is_primary = local.multi && var.cell == var.primary_cell

  # Every OTHER cell: the ones this cell's nodes talk to on 8446, whose
  # CIDRs it admits, and which the service is told about.
  peers = local.multi ? { for id, c in var.cells : id => c if id != var.cell } : {}

  # A CELL'S ADDRESSES ARE A FORMULA OF ITS CIDR, so that no cell reads
  # another's state to reach it — the global/ stack uses the same one
  # (../global/main.tf, `cell_addresses`; keep the two in step):
  #   private subnet     the /16's tenth /24
  #   .5 of it           the inter-cell internal load balancer (8446)
  #   .10 of it          the cell database's private endpoint
  #   .12 of it          the global tier's private endpoint in this cell —
  #                      the writer's in the primary cell, the replica's
  #                      elsewhere
  cell_private = {
    for id, c in var.cells : id => {
      private_cidr   = cidrsubnet(c.vpc_cidr, 8, 10)
      intercell_ip   = cidrhost(cidrsubnet(c.vpc_cidr, 8, 10), 5)
      global_db_ip   = cidrhost(cidrsubnet(c.vpc_cidr, 8, 10), 12)
      intercell_host = "nodes.${id}.${var.environment}.${var.name}.internal"
    }
  }

  intercell_port     = 8446
  intercell_hostname = local.multi ? local.cell_private[var.cell].intercell_host : ""
  cell_console_host  = local.multi && local.public_name ? "${var.cell}.${var.public_hostname}" : ""
  all_cell_cidrs     = [for c in values(var.cells) : c.vpc_cidr]
  peer_cidrs         = [for c in values(local.peers) : c.vpc_cidr]
}

# ---------------------------------------------------------------------------
# THE GLOBAL TIER, AS THE global/ STACK LEFT IT — read from its state, and
# only in `full`. REMOTE STATE rather than anything published: AWS's
# argument (deploy/aws/environment/cells.tf) — the values are known at plan
# time, the deployer already reads every state, and global/ must precede a
# cell's `full` anyway, because the database must exist before a node uses
# it.
# ---------------------------------------------------------------------------
data "terraform_remote_state" "global" {
  count   = local.multi && local.full ? 1 : 0
  backend = "azurerm"
  config = {
    subscription_id      = var.subscription_id
    resource_group_name  = var.state_resource_group
    storage_account_name = var.state_storage_account
    container_name       = "tfstate"
    key                  = "environment/${var.environment}/global.tfstate"
    use_azuread_auth     = true
  }
}

locals {
  # Field by field, with empty values in `base` — the lesson of AWS's first
  # testidpna apply (a conditional needs both sides to have one type).
  global = local.multi && local.full ? {
    writer_host = data.terraform_remote_state.global[0].outputs.writer_host
    read_host   = data.terraform_remote_state.global[0].outputs.read_hosts[var.cell]
    db_port     = data.terraform_remote_state.global[0].outputs.db_port
    db_name     = data.terraform_remote_state.global[0].outputs.db_name
    db_app_user = data.terraform_remote_state.global[0].outputs.db_app_user
    } : {
    writer_host = ""
    read_host   = ""
    db_port     = 5432
    db_name     = ""
    db_app_user = ""
  }

  # THE CONTRACT WITH THE SERVICE — AWS's `cell_environment`, name for name,
  # with the `azure` secret provider where AWS has `aws`. The secrets are in
  # THIS cell's vault: its own (`cell-kek`) and the global ones the global/
  # stack wrote there (`kek`, `global-db-app-password`, …). The global
  # database password has no vault setting and is read from the
  # key-encryption key's vault: this one with kek_provider = "secret", the
  # environment's GLOBAL vault with "kms", where the global stack writes a
  # copy (kek.tf). The service KEK itself is kek.tf's, the same for every
  # cell. The cell key names its vault itself, because it has no fallback
  # (`keys.cellKekVault`, #96), and stays a SECRET in either mode: the
  # service refuses a key management service for it.
  cell_environment = local.multi ? merge({
    STS_CELL_ID           = var.cell
    STS_CELL_JURISDICTION = local.this_cell.jurisdiction
    STS_CELL_PORT         = tostring(local.intercell_port)
    STS_CELL_HOSTNAME     = local.intercell_hostname
    STS_CELL_PEERS = jsonencode([
      for id in sort(keys(local.peers)) : merge({
        id           = id
        jurisdiction = local.peers[id].jurisdiction
        url          = "https://${local.cell_private[id].intercell_host}:${local.intercell_port}"
        }, local.cell_console_host != "" ? {
        consoleUrl = "https://${id}.${var.public_hostname}"
      } : {})
    ])
    STS_CELL_CONSOLE_URL  = local.cell_console_host != "" ? "https://${local.cell_console_host}" : ""
    STS_CELL_KEK_PROVIDER = "azure"
    STS_CELL_KEK_VAULT    = local.vault_uri
    STS_CELL_KEK_REF      = "cell-kek"
    }, local.full ? {
    STS_GLOBAL_DATABASE_URL               = "postgres://${local.global.db_app_user}@${local.global.writer_host}:${local.global.db_port}/${local.global.db_name}?sslmode=require"
    STS_GLOBAL_DATABASE_READ_URL          = "postgres://${local.global.db_app_user}@${local.global.read_host}:${local.global.db_port}/${local.global.db_name}?sslmode=require"
    STS_GLOBAL_DATABASE_PASSWORD_PROVIDER = "azure"
    STS_GLOBAL_DATABASE_PASSWORD_REF      = "global-db-app-password"
  } : {}) : {}
}
