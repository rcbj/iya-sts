# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A GCP CELL OF A MULTI-CLOUD ENVIRONMENT: THIS STACK, ONCE PER GCP CELL
# (#97, 2026-09-30) — deploy/aws/environment/cells.tf's arrangement on GCP,
# and the same contract with the service (issue #98, section 8).
#
# **`cell` EMPTY IS #95'S STACK, UNCHANGED**: every addition is conditional on
# `local.multi`, and a single-cell environment renders what it did.
#
# SET, what changes:
#   * the REGION is the cell's; every name carries the cell
#     (`iya-sts-<env>-<cell>-…`); the node account is the foundation's
#     `iya-sts-env-<env>-<cell>`; the state prefix is `environment/<env>/<cell>`;
#   * the NETWORK is the environment's shared global VPC, which the
#     foundation made (network_multicell.tf there); the cell makes its own
#     subnets in it;
#   * the cell's own data — its database, disks, secrets and certificate —
#     is sealed under its REGION's key, which is replicated nowhere;
#   * the key-encryption key and the other values every cell shares are the
#     GLOBAL ones, copied from AWS into Secret Manager by
#     deploy/multicloud/gcp-global, as is the cell's copy of the global tier —
#     a Cloud SQL instance subscribed to the RDS writer's publication. So a
#     cell's KEK is a SECRET, never #391's Cloud KMS key: `kek_provider` must
#     be `secret` in a cell, and kek.tf refuses anything else;
#   * the nodes answer the other cells on 8446 through an internal load
#     balancer at a fixed address (intercell.tf), and the public name's
#     Route 53 tree is deploy/multicloud/interconnect's.
#
# TWO PHASES, AS ON AWS: `base` makes everything but running nodes (each
# group at size 0) and reads no global state; `full`, after the global tier
# exists, starts the nodes and tells them where it is.
# ---------------------------------------------------------------------------
variable "cell" {
  description = "Which GCP cell of `cells` this apply is (e.g. `gusw1`). EMPTY — the default — is a single-cell environment (#95)."
  type        = string
  default     = ""
  validation {
    condition     = var.cell == "" || try(var.cells[var.cell].cloud, "") == "gcp"
    error_message = "cell must be empty or a GCP cell of cells: an AWS cell is deploy/aws/environment's."
  }
}

variable "cells" {
  description = "Every cell of the multi-cloud environment, from deploy/multicloud/envs/<env>.cells.tfvars.json (deploy/aws/environment/cells.tf describes each field)."
  type = map(object({
    region                 = string
    jurisdiction           = string
    vpc_cidr               = string
    db_snapshot_identifier = optional(string, "")
    cloud                  = optional(string, "aws")
    coordinates            = optional(object({ latitude = string, longitude = string }))
    global_db_cidr         = optional(string, "")
  }))
  default = {}
}

variable "primary_cell" {
  description = "The AWS cell whose VPC holds the global writer. Read from the cells file; unread here beyond its existence."
  type        = string
  default     = ""
}

variable "cell_phase" {
  description = "`full` (the default) or `base` — see this file's header."
  type        = string
  default     = "full"
  validation {
    condition     = contains(["base", "full"], var.cell_phase)
    error_message = "cell_phase is base or full."
  }
}

locals {
  multi     = var.cell != ""
  this_cell = local.multi ? var.cells[var.cell] : null
  region    = local.multi ? local.this_cell.region : var.region
  full      = !local.multi || var.cell_phase == "full"
  peers     = local.multi ? { for id, c in var.cells : id => c if id != var.cell } : {}

  # The GCP cells' shared network (the foundation's), or this stack's own.
  shared_network = "${var.name}-${var.environment}"

  intercell_port     = 8446
  intercell_zone     = local.multi ? "${var.cell}.${var.environment}.${var.name}.internal" : ""
  intercell_hostname = local.multi ? "nodes.${local.intercell_zone}" : ""
  cell_console_host  = local.multi && local.public_name ? "${var.cell}.${var.public_hostname}" : ""
  peer_cidrs         = [for c in values(local.peers) : c.vpc_cidr]
}

# ---------------------------------------------------------------------------
# THE GLOBAL TIER, AS deploy/multicloud/gcp-global LEFT IT — only in `full`.
# Its state is in this project's bucket, beside the cells'.
# ---------------------------------------------------------------------------
data "terraform_remote_state" "global" {
  count   = local.multi && local.full ? 1 : 0
  backend = "gcs"
  config = {
    bucket = "${var.name}-terraform-state-${var.project_id}"
    prefix = "environment/${var.environment}/gcp-global"
  }
}

locals {
  # Field by field, with empty values in `base` — the lesson of AWS's first
  # testidpna apply (deploy/aws/environment/cells.tf).
  global = local.multi && local.full ? {
    writer_address  = data.terraform_remote_state.global[0].outputs.writer_address
    db_port         = data.terraform_remote_state.global[0].outputs.db_port
    db_name         = data.terraform_remote_state.global[0].outputs.db_name
    db_app_user     = data.terraform_remote_state.global[0].outputs.db_app_user
    publication     = data.terraform_remote_state.global[0].outputs.publication
    repl_user       = data.terraform_remote_state.global[0].outputs.repl_user
    secrets         = data.terraform_remote_state.global[0].outputs.secret_names
    writer_ca_pem   = data.terraform_remote_state.global[0].outputs.writer_ca_pem
    copy_host       = data.terraform_remote_state.global[0].outputs.copies[var.cell].hostname
    copy_address    = data.terraform_remote_state.global[0].outputs.copies[var.cell].address
    copy_ca_pem     = data.terraform_remote_state.global[0].outputs.copies[var.cell].ca_pem
    copy_master_ref = data.terraform_remote_state.global[0].outputs.copies[var.cell].master_secret
    } : {
    writer_address  = ""
    db_port         = 5432
    db_name         = ""
    db_app_user     = ""
    publication     = ""
    repl_user       = ""
    secrets         = {}
    writer_ca_pem   = ""
    copy_host       = ""
    copy_address    = ""
    copy_ca_pem     = ""
    copy_master_ref = ""
  }

  # THE CONTRACT WITH THE SERVICE — AWS's `cell_environment`, name for name,
  # with the `gcp` secret provider where AWS has `aws`. The global password
  # is the one the writer's `sts_app` holds; the copy's `sts_app` is made
  # with the same one by its subscriber init (units/sts-global-schema).
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
    STS_CELL_CONSOLE_URL = local.cell_console_host != "" ? "https://${local.cell_console_host}" : ""
    # The cell's OWN key-encryption key: a secret in every case — the
    # service refuses a KMS key for it (#391), so `kek_provider` does not
    # reach it.
    STS_CELL_KEK_PROVIDER = "gcp"
    STS_CELL_KEK_REF      = google_secret_manager_secret.main["cell-kek"].id
    }, local.full ? {
    # The writer is RDS, dialled across the HA VPN by its own endpoint name,
    # which resolves publicly to its private address; the copy is this
    # cell's Cloud SQL, by the name its certificate carries.
    STS_GLOBAL_DATABASE_URL               = "postgres://${local.global.db_app_user}@${local.global.writer_address}:${local.global.db_port}/${local.global.db_name}?sslmode=require"
    STS_GLOBAL_DATABASE_READ_URL          = "postgres://${local.global.db_app_user}@${local.global.copy_host}:${local.global.db_port}/${local.global.db_name}?sslmode=require"
    STS_GLOBAL_DATABASE_PASSWORD_PROVIDER = "gcp"
    STS_GLOBAL_DATABASE_PASSWORD_REF      = lookup(local.global.secrets, "global-db-app-password", "")
  } : {}) : {}
}

variable "jurisdictions" {
  description = "The jurisdictions and the countries pinned to each (#367's model), from the cells file. Unread here: the Route 53 tree is deploy/multicloud/interconnect's."
  type = map(object({
    geolocation_countries = optional(list(string), [])
  }))
  default = {}
}
