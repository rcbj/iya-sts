# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE GLOBAL DATABASE: ONE WRITER IN THE PRIMARY CELL, ONE CROSS-REGION READ
# REPLICA IN EVERY OTHER (issue #98, D3, 2026-09-28).
#
# The global tier holds what every cell needs and no person's data: realms,
# settings, applications, policies, federation, signing keys and their
# generations, the Root and Intermediates, the routing index (issue #98, §3).
# It is written rarely and administratively, so every write may pay the
# round trip to the writer; it is read by every node, so every cell reads a
# copy in its own region. RDS for PostgreSQL makes a cross-region read replica
# of the engine the cells already run — Aurora Global Database and logical
# replication were considered in the issue and not chosen — so this is the
# cells' own `rds.tf`, twice over, with the replica in another region.
#
# THE SAME SCHEMA as a cell database: the primary cell's nodes run a second
# schema-init against this writer (../environment/ecs.tf,
# `global-schema-init`), and a replica takes the schema, the `sts_app` role
# and its password by replication.
#
# PLACED IN THE CELLS' VPCs, in the subnet group and behind the security group
# each cell made for it (../environment/global_db.tf), which admit every
# cell's CIDR on 5432 — the writer is written to across the peering.
#
# ENCRYPTED UNDER THE GLOBAL multi-region key, primary and replicas: the
# global tier is exactly what every region may hold. TLS required on the
# listener, as on a cell database. A replica keeps no backups of its own.
# ---------------------------------------------------------------------------
resource "aws_db_parameter_group" "global" {
  name        = "${local.prefix}-pg18"
  family      = "postgres18"
  description = "mock-sts ${var.environment}: the global database, TLS required"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  parameter {
    name         = "ssl_min_protocol_version"
    value        = "TLSv1.2"
    apply_method = "pending-reboot"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "primary" {
  identifier     = "${local.prefix}-primary"
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  db_name  = local.db_name
  username = local.db_master_user
  password = random_password.db_master.result
  port     = local.db_port

  allocated_storage = var.db_allocated_storage
  storage_type      = "gp3"
  storage_encrypted = true
  kms_key_id        = data.aws_kms_key.global.arn

  multi_az               = false
  publicly_accessible    = false
  db_subnet_group_name   = local.cell[var.primary_cell].global_db_subnet_group
  vpc_security_group_ids = [local.cell[var.primary_cell].global_db_security_group_id]
  parameter_group_name   = aws_db_parameter_group.global.name
  ca_cert_identifier     = "rds-ca-rsa2048-g1"

  # Backups are what a cross-region replica is made from, so they are on.
  backup_retention_period  = var.backup_retention_days
  backup_window            = "10:30-11:00"
  maintenance_window       = "sun:11:30-sun:12:00"
  copy_tags_to_snapshot    = true
  delete_automated_backups = var.delete_automated_backups
  skip_final_snapshot      = true
  deletion_protection      = false

  auto_minor_version_upgrade = true
  apply_immediately          = true
}

# ---------------------------------------------------------------------------
# ONE REPLICA PER NON-PRIMARY CELL, each through the provider of its region
# (providers.tf). A block per region the design names, present only when that
# region holds a cell that is not the primary one.
# ---------------------------------------------------------------------------
locals {
  replica_common = {
    prefix             = local.prefix
    name               = var.name
    environment        = var.environment
    source_db_arn      = aws_db_instance.primary.arn
    instance_class     = var.db_instance_class
    parameter_family   = "postgres18"
    ca_cert_identifier = "rds-ca-rsa2048-g1"
  }
}

module "replica_usw2" {
  source    = "./modules/replica"
  count     = contains(keys(local.replica_cells), "usw2") ? 1 : 0
  providers = { aws = aws.usw2 }

  cell                 = "usw2"
  common               = local.replica_common
  db_subnet_group      = try(local.cell["usw2"].global_db_subnet_group, "")
  db_security_group_id = try(local.cell["usw2"].global_db_security_group_id, "")
}

module "replica_cac1" {
  source    = "./modules/replica"
  count     = contains(keys(local.replica_cells), "cac1") ? 1 : 0
  providers = { aws = aws.cac1 }

  cell                 = "cac1"
  common               = local.replica_common
  db_subnet_group      = try(local.cell["cac1"].global_db_subnet_group, "")
  db_security_group_id = try(local.cell["cac1"].global_db_security_group_id, "")
}

module "replica_euc1" {
  source    = "./modules/replica"
  count     = contains(keys(local.replica_cells), "euc1") ? 1 : 0
  providers = { aws = aws.euc1 }

  cell                 = "euc1"
  common               = local.replica_common
  db_subnet_group      = try(local.cell["euc1"].global_db_subnet_group, "")
  db_security_group_id = try(local.cell["euc1"].global_db_security_group_id, "")
}

module "replica_apse1" {
  source    = "./modules/replica"
  count     = contains(keys(local.replica_cells), "apse1") ? 1 : 0
  providers = { aws = aws.apse1 }

  cell                 = "apse1"
  common               = local.replica_common
  db_subnet_group      = try(local.cell["apse1"].global_db_subnet_group, "")
  db_security_group_id = try(local.cell["apse1"].global_db_security_group_id, "")
}

locals {
  # Where each cell READS the global tier: its own replica, and the writer
  # itself in the primary cell (which has no replica of its own).
  read_addresses = merge(
    { (var.primary_cell) = aws_db_instance.primary.address },
    { for m in module.replica_usw2 : "usw2" => m.address },
    { for m in module.replica_cac1 : "cac1" => m.address },
    { for m in module.replica_euc1 : "euc1" => m.address },
    { for m in module.replica_apse1 : "apse1" => m.address },
  )
}
