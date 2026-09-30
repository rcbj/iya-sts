# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# A CELL: THIS STACK, APPLIED ONCE PER REGION OF A MULTI-REGION ENVIRONMENT
# (issue #98, 2026-09-28).
#
# Issue #98's design, section 7: a CELL is one application of this stack in
# one region — its own VPC, load balancer, nodes, cell PostgreSQL (primary and
# same-region replica, exactly as today), exportable ACM certificate for the
# SAME public name and logs — and it is the unit of failure and of data
# residency. (The issue lists an SES identity per cell too; this stack has
# none to give each cell yet — deploy/aws/CLAUDE.md, *Cells*.) The cells of an environment, and which one holds the
# global database's writer, are one map, `cells`, read from
# `envs/<env>.cells.tfvars.json`; `cell` says which of them this apply is.
#
# **`cell` EMPTY IS TODAY'S STACK, UNCHANGED.** Every addition in this file
# and the others is conditional on `local.multi`, every name is spelt the way
# it was when it is false, and nothing a single-cell environment renders —
# a name, a policy, a task definition, an environment variable — differs.
# `dev`, `ci` and `testidp` set no cell.
#
# SET, what changes, and why:
#   * the REGION is the cell's (`cells[cell].region`), not `aws_region`;
#   * every globally unique name carries the cell: resources are
#     `mock-sts-<env>-<cell>-…`, IAM roles `mock-sts-env-<env>-<cell>-…`,
#     secrets `mock-sts/<env>/<cell>/…`; the state key is
#     `environment/<env>/<cell>.tfstate` (entrypoint.sh);
#   * the VPC is the cell's own CIDR from the map, distinct in every cell, so
#     the cells can be peered (the global/ stack does it);
#   * the cell's own data is sealed under its CELL key, single-region and never
#     replicated; the key-encryption key every cell shares, and the other
#     secrets that must be the same in every cell, are the global/ stack's,
#     replicated into this region;
#   * the public name is a Route 53 record TREE rather than a CNAME
#     (dns_cells.tf), and the nodes are reachable from the other cells on
#     8446, on a private name (intercell.tf);
#   * the nodes are told the contract the service reads (below).
#
# THE TWO PHASES. A cell and the global/ stack need each other: the global
# database's primary and replicas live IN the cells' VPCs, and a cell's nodes
# need the global database's addresses before they can start. So a new cell
# is applied twice, and entrypoint.sh does it:
#   `base`  everything but running nodes (every service at a desired count
#           of 0), and no read of the global stack's state;
#   `full`  after global/ has applied: the nodes, told where the global tier
#           is. Every later apply is `full`.
# `cell_phase` defaults to `full`, which is what a single-cell stack always is.
# ---------------------------------------------------------------------------

variable "cell" {
  description = <<-EOT
    Which cell of `cells` this apply is (e.g. `usw2`). EMPTY — the default —
    is a single-cell environment, which is everything this stack was before
    issue #98 and renders exactly as it did.
  EOT
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
    A cell's id names its region, by foundation/locals.tf's rule (#367): the
    area, the direction's initials and the number — us-west-2 = usw2,
    us-east-2 = use2, eu-west-1 = euw1, ap-southeast-5 = apse5.
    `jurisdiction` is the legal boundary it sits in (issue #98, section 2),
    and several cells may share one (globalidp's two `us` and two `eu`);
    `vpc_cidr` is its VPC, which must not overlap another cell's;
    `db_snapshot_identifier`, empty but for a cell CONVERTED from a
    single-region environment, is the RDS snapshot the cell database is
    restored from (conversion.tf) — in the cell's region and under the cell's
    own key, and read once, when the database is created. The countries
    Route 53 pins are a JURISDICTION's, not a cell's (`jurisdictions`,
    below; they were a cell's `geolocation_countries` until #367).
  EOT
  type = map(object({
    region                 = string
    jurisdiction           = string
    vpc_cidr               = string
    db_snapshot_identifier = optional(string, "")
  }))
  default = {}
  validation {
    condition     = length(distinct([for c in values(var.cells) : c.vpc_cidr])) == length(var.cells)
    error_message = "every cell's vpc_cidr must be distinct: the cells are peered, and peered VPCs may not overlap."
  }
  validation {
    condition     = length(distinct([for c in values(var.cells) : c.region])) == length(var.cells)
    error_message = "one cell per region: a cell is its region's unit of residency."
  }
  validation {
    # EACH CELL IN THE REGION ITS ID NAMES — foundation/locals.tf's rule,
    # `cell_of_region` (#367; keep the copies in step). The id is at most
    # five characters, which the names it goes into (32 at most) need, and a
    # one-digit region number guarantees.
    condition = alltrue([
      for id, c in var.cells :
      can(cidrnetmask(c.vpc_cidr)) &&
      can(regex("^[a-z]{2}-(north|south|east|west|central|northeast|northwest|southeast|southwest)-[1-9]$", c.region)) &&
      id == join("", [
        split("-", c.region)[0],
        lookup({
          north     = "n", south = "s", east = "e", west = "w", central = "c",
          northeast = "ne", northwest = "nw", southeast = "se", southwest = "sw",
        }, split("-", c.region)[1], "?"),
        split("-", c.region)[2],
      ])
    ])
    error_message = "each cell's id must be its region shortened by rule (us-west-2 is usw2, eu-central-1 euc1, ap-southeast-5 apse5), in a commercial region of the form area-direction-digit, and vpc_cidr a CIDR."
  }
}

variable "jurisdictions" {
  description = <<-EOT
    The environment's jurisdictions, by code, and the ISO 3166 countries whose
    clients Route 53 PINS to each because the law requires it (dns_cells.tf,
    #367) — globalidp's `eu` holds the EU and EEA countries, answered by
    whichever of its two cells is nearer and never by a cell outside it. A
    jurisdiction with no pinned country needs no entry. From the cells file.
  EOT
  type = map(object({
    geolocation_countries = optional(list(string), [])
  }))
  default = {}
  validation {
    condition = alltrue([
      for j, v in var.jurisdictions :
      length(v.geolocation_countries) == 0 ||
      contains([for c in values(var.cells) : c.jurisdiction], j)
    ])
    error_message = "a jurisdiction that pins countries must have a cell: Route 53 would have nowhere to send them."
  }
  validation {
    condition = length(flatten([
      for v in values(var.jurisdictions) : v.geolocation_countries
      ])) == length(distinct(flatten([
        for v in values(var.jurisdictions) : v.geolocation_countries
    ])))
    error_message = "a country is pinned to one jurisdiction at most: Route 53 holds one geolocation record per country."
  }
  validation {
    condition = alltrue([
      for v in values(var.jurisdictions) : alltrue([
        for c in v.geolocation_countries : can(regex("^[A-Z]{2}$", c))
      ])
    ])
    error_message = "a pinned country is an ISO 3166-1 alpha-2 code, upper case (DE, SG)."
  }
}

variable "primary_cell" {
  description = "The cell whose VPC holds the global database's WRITER (issue #98, D3). Required with `cells`."
  type        = string
  default     = ""
  validation {
    condition     = length(var.cells) == 0 || contains(keys(var.cells), var.primary_cell)
    error_message = "primary_cell must be a key of cells."
  }
}

variable "cell_phase" {
  description = <<-EOT
    `full` (the default, and always, for a single-cell environment) or `base`:
    the first apply of a new cell, before the global/ stack exists — every
    node service at a desired count of 0 and no read of the global stack's
    state. entrypoint.sh chooses it; see this file's header.
  EOT
  type        = string
  default     = "full"
  validation {
    condition     = contains(["base", "full"], var.cell_phase)
    error_message = "cell_phase is base or full."
  }
}

variable "cell_hold_nodes" {
  description = <<-EOT
    TRUE ONLY WHILE A RESTORED CELL IS BEING CONVERTED (conversion.tf):
    `full` with every node service at a desired count of 0, so that the
    one-off conversion task runs against the two databases with no node
    serving from them. entrypoint.sh sets it (TF_CELL_HOLD) for the one apply
    before the conversion and never otherwise.
  EOT
  type        = bool
  default     = false
}

variable "state_region" {
  description = <<-EOT
    The region of the Terraform state BUCKET, which is the home region and
    not the cell's: one bucket holds every environment's state, and the
    backend block in versions.tf names the same region. Read here only for the
    global/ stack's state.
  EOT
  type        = string
  default     = "us-west-2"
}

locals {
  multi     = var.cell != ""
  this_cell = local.multi ? var.cells[var.cell] : null
  # Every OTHER cell of the environment: the ones this cell's nodes talk to on
  # 8446, whose CIDRs it admits, and which the service is told about.
  peers      = local.multi ? { for id, c in var.cells : id => c if id != var.cell } : {}
  is_primary = local.multi && var.cell == var.primary_cell
  full       = var.cell_phase == "full"

  # A single-cell stack is always `full`. A cell in `base` runs no node, and
  # neither does a restored cell while its conversion is pending
  # (conversion.tf).
  node_desired_count = local.full && !var.cell_hold_nodes ? 1 : 0

  # Where the NODES of every cell are, for the rules that admit them: the
  # whole VPC CIDR of each, because a Fargate task takes whatever address its
  # subnet gives it.
  all_cell_cidrs  = [for c in values(var.cells) : c.vpc_cidr]
  peer_cell_cidrs = [for c in values(local.peers) : c.vpc_cidr]

  # THE INTER-CELL LISTENER (issue #98, section 4): the service's own mutual
  # TLS between cells, on the cell's own Issuing CA's certificates — nothing
  # for Terraform to issue. Never on the public load balancer and never in
  # public DNS (intercell.tf).
  intercell_port = 8446
}

# ---------------------------------------------------------------------------
# THE GLOBAL TIER, AS THE global/ STACK LEFT IT — read from its state, and
# only in the `full` phase, when that state exists.
#
# REMOTE STATE, NOT SSM PARAMETERS (issue #98 left the choice open). The
# values are known at PLAN time, so a plan shows the task definition the
# nodes will actually get; the deployer may already read every state under
# `environment/` (foundation/iam_deployer.tf, TerraformStateObjects) and needs
# no new right, where parameters would need `ssm:*` in every cell region and
# a second copy of each value; and the ordering it imposes — global/ before a
# cell's `full` apply — is one entrypoint.sh enforces anyway, because the
# database must exist before a node can use it.
# ---------------------------------------------------------------------------
data "terraform_remote_state" "global" {
  count   = local.multi && local.full ? 1 : 0
  backend = "s3"
  config = {
    region = var.state_region
    bucket = "${var.name}-terraform-state-${local.account_id}"
    key    = "environment/${var.environment}/global.tfstate"
  }
}

locals {
  # The global stack's outputs, or — in `base`, and in a single-cell stack —
  # empty values that nothing reads, so the expressions below need no second
  # condition.
  # The fields are picked one by one rather than taking the outputs whole:
  # a conditional needs both results to have one type, and the global stack
  # has outputs this stack does not read (peering_connection_ids), so the
  # whole object and this fallback differed and every full phase failed.
  global = local.multi && local.full ? {
    primary_address   = data.terraform_remote_state.global[0].outputs.primary_address
    db_port           = data.terraform_remote_state.global[0].outputs.db_port
    db_name           = data.terraform_remote_state.global[0].outputs.db_name
    db_app_user       = data.terraform_remote_state.global[0].outputs.db_app_user
    read_addresses    = data.terraform_remote_state.global[0].outputs.read_addresses
    secret_arns       = data.terraform_remote_state.global[0].outputs.secret_arns
    master_secret_arn = data.terraform_remote_state.global[0].outputs.master_secret_arn
    } : {
    primary_address   = ""
    db_port           = 5432
    db_name           = ""
    db_app_user       = ""
    read_addresses    = {}
    secret_arns       = {}
    master_secret_arn = ""
  }
  global_secret_arns = local.multi ? try(local.global.secret_arns[var.cell], {}) : {}
  global_read_host   = local.multi ? try(local.global.read_addresses[var.cell], "") : ""

  # The private name this cell's nodes answer 8446 on, and each peer's
  # (intercell.tf). Deterministic, so no cell has to read another's state to
  # know where its peers are.
  intercell_zone     = local.multi ? "${var.cell}.${var.environment}.${var.name}.internal" : ""
  intercell_hostname = local.multi ? "nodes.${local.intercell_zone}" : ""

  # THE CONTRACT WITH THE SERVICE (issue #98, section 8, rcbj 2026-09-28):
  # what every node of a cell is told, beside everything a single-cell node
  # already is. Empty for a single-cell environment, so nothing is added to its
  # task definition.
  #
  #   STS_CELL_ID, STS_CELL_JURISDICTION   this cell
  #   STS_CELL_PORT                        the inter-cell listener, 8446
  #   STS_CELL_HOSTNAME                    the private name the other cells
  #                                        dial it by — the host part of the
  #                                        `url` its peers are given — so the
  #                                        cell Issuing CA's leaf can name it
  #   STS_CELL_PEERS                       every OTHER cell: id, jurisdiction,
  #                                        https://<its name>:8446
  #   STS_GLOBAL_DATABASE_URL              the global primary, TLS required
  #   STS_GLOBAL_DATABASE_READ_URL         the global replica in THIS region;
  #                                        the primary, in the primary cell
  #   STS_GLOBAL_DATABASE_PASSWORD_*       its password, from Secrets Manager
  #                                        in this region (a replica)
  #   STS_CELL_KEK_*                       this cell's OWN key-encryption key,
  #                                        which is replicated nowhere
  # STS_KEYS_KEK_* stay the global KEK (replicated here), STS_DATABASE_URL
  # stays the CELL database, and STS_PUBLIC_BASE_URL stays the one public name.
  cell_environment = local.multi ? merge({
    STS_CELL_ID           = var.cell
    STS_CELL_JURISDICTION = local.this_cell.jurisdiction
    STS_CELL_PORT         = tostring(local.intercell_port)
    STS_CELL_HOSTNAME     = local.intercell_hostname
    STS_CELL_PEERS = jsonencode([
      for id in sort(keys(local.peers)) : merge({
        id           = id
        jurisdiction = local.peers[id].jurisdiction
        url          = "https://nodes.${id}.${var.environment}.${var.name}.internal:${local.intercell_port}"
        }, local.cell_console_host != "" ? {
        consoleUrl = "https://${id}.${var.public_hostname}"
      } : {})
    ])
    # THIS CELL'S OWN CONSOLE ADDRESS (#361), '' without a public name.
    STS_CELL_CONSOLE_URL  = local.cell_console_host != "" ? "https://${local.cell_console_host}" : ""
    STS_CELL_KEK_PROVIDER = "aws"
    STS_CELL_KEK_REF      = aws_secretsmanager_secret.main["cell-kek"].arn
    STS_CELL_KEK_REGION   = local.region
    }, local.full ? {
    STS_GLOBAL_DATABASE_URL               = "postgres://${local.global.db_app_user}@${local.global.primary_address}:${local.global.db_port}/${local.global.db_name}?sslmode=require"
    STS_GLOBAL_DATABASE_READ_URL          = "postgres://${local.global.db_app_user}@${local.global_read_host}:${local.global.db_port}/${local.global.db_name}?sslmode=require"
    STS_GLOBAL_DATABASE_PASSWORD_PROVIDER = "aws"
    STS_GLOBAL_DATABASE_PASSWORD_REF      = lookup(local.global_secret_arns, "global-db-app-password", "")
    STS_GLOBAL_DATABASE_PASSWORD_REGION   = local.region
  } : {}) : {}
}
