# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A CELL CONVERTED FROM A SINGLE-REGION ENVIRONMENT (#98, 2026-09-28).
#
# `testidp` became cell `usw2` of `testidpna` without losing its database —
# the risk datasets and their history in `sts_risk_*` above all, which take
# days to build again and cannot be rebuilt at all for the refused-password
# and sign-in history. What that takes of this stack is three things, each
# present only in a cell that names `db_snapshot_identifier`:
#
#   1. THE CELL DATABASE RESTORED FROM A SNAPSHOT of the old environment's
#      (rds.tf). RDS restores a snapshot under THE SNAPSHOT'S OWN KMS KEY —
#      RestoreDBInstanceFromDBSnapshot has no key parameter — so the snapshot
#      named here must already be a COPY re-encrypted under the cell's key
#      (`alias/mock-sts-cell-<cell>`, CopyDBSnapshot with KmsKeyId), which
#      deploy/aws/convert-to-cells.sh makes. A snapshot under the project key
#      would restore under the project key, `kms_key_id` would disagree with
#      the instance on every later plan, and the provider would REPLACE the
#      database to reconcile it — an empty one;
#   2. `cell_hold_nodes` (cells.tf): the one `full` apply that makes every
#      node service with a desired count of 0, so nothing serves from the
#      restored database before it has been converted;
#   3. A ONE-OFF CONVERSION TASK DEFINITION, below — what entrypoint.sh
#      (`orchestrate_cells`) runs between those two applies.
#
# THE CONVERSION TASK is a node's task, not a node: the same roles, network,
# image, environment and secrets, the same two schema inits first (the cell
# schema always, the global schema in the primary cell), and in place of the
# service, `node persistence/cell_convert.js` — the one-time tool that moves
# the single-region store's rows into the cell and global tiers. It exits 0
# when it converted or finds the store already converted, and non-zero with
# every source row left where it was. A task definition of its own rather
# than the node's with a command override, for two reasons: the node's
# declares the risk upload volume `configure_at_launch`, which a RunTask would
# then have to configure (and pass the infrastructure role for); and the
# schema inits must run in the SAME task and before the tool, which an
# override of one container's command cannot order.
#
# WHAT IT IS NOT GIVEN: the public certificate. `cert-init` is not in it and
# STS_TLS_CERT_FILE / STS_TLS_KEY_FILE are left out of its environment,
# because the tool binds no listener and the files would not exist; every
# other variable a node has, it has, so the tool reads the same stores under
# the same keys the nodes then will.
#
# A cell that names no snapshot renders nothing from this file, and neither
# does any single-cell environment.
# ---------------------------------------------------------------------------
locals {
  # A single-cell environment restores from `var.db_snapshot_identifier`
  # (variables.tf) — the same restore, and no conversion: its rows are
  # already in the single-cell layout, so `converted` is a cell's alone.
  db_snapshot_identifier = local.multi ? local.this_cell.db_snapshot_identifier : var.db_snapshot_identifier
  restored               = local.db_snapshot_identifier != ""
  converted              = local.restored && local.multi

  convert_environment = {
    for k, v in local.node_environment : k => v
    if !contains(["STS_TLS_CERT_FILE", "STS_TLS_KEY_FILE"], k)
  }
}

resource "aws_ecs_task_definition" "convert" {
  # `full` only: the task needs the global tier's addresses and secrets.
  count = local.converted && local.full ? 1 : 0

  family                   = "${local.prefix}-convert"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  task_role_arn            = aws_iam_role.task.arn
  execution_role_arn       = aws_iam_role.execution.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode(concat(
    local.global_schema_init ? [local.global_schema_init_container["convert"]] : [],
    [
      local.schema_init_container["convert"],
      {
        name      = "cell-convert"
        image     = "${local.ecr_repository_url}:${var.image_tag}"
        essential = true
        command   = ["node", "persistence/cell_convert.js"]
        # Both databases at the schema the image expects, and the cell
        # database's `sts_app` role holding THIS environment's password —
        # schema-init ALTERs a role the snapshot already has — before the
        # tool opens either.
        dependsOn = concat(
          [{ containerName = "schema-init", condition = "SUCCESS" }],
          local.global_schema_init ? [{ containerName = "global-schema-init", condition = "SUCCESS" }] : [],
        )
        environment = [
          for k, v in merge(local.convert_environment, { STS_CLUSTER_NODE_NAME = "convert" }) :
          { name = k, value = v }
        ]
        secrets          = local.node_secrets
        logConfiguration = local.container_log["convert"]
      },
  ]))
}
