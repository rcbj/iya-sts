# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

locals {
  subscription_id = data.azurerm_client_config.current.subscription_id
  tenant_id       = data.azurerm_client_config.current.tenant_id

  common_tags = merge(var.tags, { Project = "STS" })

  # ---------------------------------------------------------------------------
  # A REGION'S SHORT CODE, AND A CELL'S ID (#96).
  #
  # AWS derives a cell's id from its region by rule (us-west-2 is usw2,
  # #367); an Azure region's name has no such shape (westus2,
  # germanywestcentral, southeastasia), so the codes are a TABLE — the
  # abbreviations Microsoft's own naming guidance uses — and an Azure cell's
  # id is `z` and the code: zwus2, zgwc, zsea. `z` because `g` is GCP's
  # (#97, gusw1) and `a…` would read as AWS's ap-*. A code is at most four
  # characters, so an id is at most five, which the names it goes into need.
  #
  # THE SAME TABLE IS IN ../environment/cells.tf AND ../global/main.tf,
  # because a variable's validation sees no local of another stack. Keep the
  # three in step; adding a region is a row in each.
  # ---------------------------------------------------------------------------
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

  # THE MULTI-REGION ENVIRONMENTS: those with a cells file, read here as the
  # environment and global stacks read it, so the three cannot disagree.
  cells_files = {
    for e, v in var.environments :
    e => jsondecode(file("${path.module}/../environment/envs/${e}.cells.tfvars.json"))
    if fileexists("${path.module}/../environment/envs/${e}.cells.tfvars.json")
  }

  # EACH ENVIRONMENT'S PUBLIC NAME: a multi-region one's is in its cells
  # file, which every stack of it reads; any other's is `environments`'.
  env_hostnames = {
    for e, v in var.environments :
    e => contains(keys(local.cells_files), e) ? lookup(local.cells_files[e], "public_hostname", "") : v.public_hostname
  }

  # ---------------------------------------------------------------------------
  # A UNIT is one thing that runs nodes: a single-cell environment, or one
  # cell of a multi-region one. Each gets a resource group, a node identity
  # and a vault (units.tf). Keyed `<env>` or `<env>-<cell>`, which is also
  # the middle of every name it owns (`mock-sts-<key>-…`) and of its
  # state key.
  # ---------------------------------------------------------------------------
  units = merge(
    {
      for e, v in var.environments : e => {
        env             = e
        cell            = ""
        region          = var.home_region
        public_hostname = v.public_hostname
        # The names a unit's certificate carries: the public name, and in a
        # cell its own console name (#361) — both written by the ACME
        # challenge node-a answers.
        alt_names = []
      } if !contains(keys(local.cells_files), e)
    },
    merge([
      for e, f in local.cells_files : {
        for id, c in f.cells : "${e}-${id}" => {
          env             = e
          cell            = id
          region          = c.region
          public_hostname = local.env_hostnames[e]
          alt_names       = local.env_hostnames[e] != "" ? ["${id}.${local.env_hostnames[e]}"] : []
        }
      }
    ]...),
  )

  # A MULTI-REGION ENVIRONMENT'S GLOBAL GROUP (#98's global tier): the
  # writer, its replicas, Traffic Manager — in the primary cell's region, and
  # allowed every region a cell of the environment is in.
  global_groups = {
    for e, f in local.cells_files : e => {
      region  = f.cells[f.primary_cell].region
      regions = distinct([for c in values(f.cells) : c.region])
    }
  }

  # EVERY REGION SOMETHING HERE IS NEEDED IN: a key, the disk-encryption
  # sets, a log workspace and a registry replica each (modules/region).
  regions = toset(distinct(concat(
    [var.home_region],
    [for u in values(local.units) : u.region],
    var.extra_regions,
  )))

  # A VAULT NAME IS GLOBAL across Azure, at most 24 characters, and a
  # deleted one keeps its name while soft-deleted. So each carries a short
  # hash of the subscription and what it is for — the same formula in the
  # environment stack (../environment/locals.tf), which finds its vault by
  # name rather than by reading this state.
  #   ms<env><cell>-<4 hex>   an environment's or a cell's (≤ 24)
  #   msk<code>-<6 hex>       a region's key vault (≤ 14)
  unit_vault_names = {
    for k, u in local.units :
    k => "ms${u.env}${u.cell}-${substr(sha1("${local.subscription_id}/${var.name}/${u.env}/${u.cell}"), 0, 4)}"
  }
}

check "every_public_name_is_in_the_zone" {
  assert {
    condition = alltrue([
      for e, h in local.env_hostnames : h == "" || endswith(h, ".${var.dns_zone_name}")
    ])
    error_message = "A cells file's public_hostname is not inside dns_zone_name."
  }
}

check "every_region_has_a_code" {
  assert {
    condition     = alltrue([for r in local.regions : contains(keys(local.region_codes), r)])
    error_message = "A region in use has no short code in local.region_codes (locals.tf); add a row here, in ../environment/cells.tf and in ../global/main.tf."
  }
}
