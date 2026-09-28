# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# ONE CROSS-REGION READ REPLICA OF THE GLOBAL DATABASE, IN ONE CELL'S VPC
# (issue #98, D3). The provider passed in is the cell's region's.
#
# Asynchronous streaming replication from the writer in the primary cell's
# region, read-only: the cell's nodes READ the global tier here
# (STS_GLOBAL_DATABASE_READ_URL) and WRITE it at the primary. RDS carries the
# replication itself — it does not cross the VPC peering — and bills the
# transfer between regions.
#
# Encrypted under the GLOBAL key's replica in this region: a cross-region
# replica of an encrypted source must name a key in its own region, and the
# multi-region replica is the same key, so nothing is re-encrypted under a
# key the other regions cannot use.
# ---------------------------------------------------------------------------
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

variable "cell" {
  description = "The cell this replica is in."
  type        = string
}

variable "common" {
  description = "What every replica shares, from ../../database.tf."
  type = object({
    prefix             = string
    name               = string
    environment        = string
    source_db_arn      = string
    instance_class     = string
    parameter_family   = string
    ca_cert_identifier = string
  })
}

variable "db_subnet_group" {
  description = "The cell's subnet group for the global database (../../../environment/global_db.tf)."
  type        = string
}

variable "db_security_group_id" {
  description = "The cell's security group for the global database."
  type        = string
}

data "aws_kms_key" "global" {
  key_id = "alias/${var.common.name}-global"
}

# A parameter group is regional, so each replica's region has its own: the
# same TLS floor as the writer's.
resource "aws_db_parameter_group" "global" {
  name        = "${var.common.prefix}-${var.cell}-pg18"
  family      = var.common.parameter_family
  description = "mock-sts ${var.common.environment}: the global database's replica in ${var.cell}, TLS required"

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

resource "aws_db_instance" "replica" {
  identifier = "${var.common.prefix}-${var.cell}"
  # CROSS-REGION: the source is named by its ARN, which is what tells RDS (and
  # the provider, which signs the request in the source's region) that the
  # replica is made from another region.
  replicate_source_db = var.common.source_db_arn
  instance_class      = var.common.instance_class

  storage_type      = "gp3"
  storage_encrypted = true
  kms_key_id        = data.aws_kms_key.global.arn

  multi_az               = false
  publicly_accessible    = false
  db_subnet_group_name   = var.db_subnet_group
  vpc_security_group_ids = [var.db_security_group_id]
  parameter_group_name   = aws_db_parameter_group.global.name
  ca_cert_identifier     = var.common.ca_cert_identifier

  backup_retention_period = 0
  skip_final_snapshot     = true
  deletion_protection     = false

  auto_minor_version_upgrade = true
  apply_immediately          = true
}

output "address" {
  description = "The replica's address, in this cell's VPC (TLS required)."
  value       = aws_db_instance.replica.address
}
