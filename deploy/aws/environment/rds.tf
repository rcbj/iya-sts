# ---------------------------------------------------------------------------
# RDS POSTGRESQL 18: A PRIMARY AND ONE READ REPLICA, IN DIFFERENT AZS.
#
# NOT PUBLIC. `publicly_accessible = false`, private subnets with no route out,
# and a security group that admits the nodes' group only.
#
# TLS REQUIRED ON THE LISTENER. `rds.force_ssl = 1` in a parameter group of
# the environment's own — refused plaintext, not merely offered TLS — on both
# instances. The nodes connect with `sslmode=require` and verify the server
# against the RDS CA bundle baked into the image
# (STS_DATABASE_TLS_REJECT_UNAUTHORIZED=true, NODE_EXTRA_CA_CERTS).
#
# ENCRYPTED AT REST with the project KMS key: `storage_encrypted` is RDS's
# volume encryption (AES-256), and it covers the storage, the automated
# backups, snapshots, the replica and its logs. RDS gives no operating-system
# access, so a filesystem layer (LUKS and the like) cannot be added beneath it;
# this is the encryption RDS offers for the volumes an instance runs on.
#
# BACKUPS: automated, 14 days, encrypted by the same key. A read replica
# requires backups on its source, so the replica and the retention are
# connected.
#
# THE REPLICA is asynchronous streaming replication, read-only. mock-sts writes
# and reads through the primary endpoint only — the replica is a copy and a
# manually promotable standby, not an automatic failover target (that would be
# Multi-AZ, which is a different product with no readable standby here).
# ---------------------------------------------------------------------------
resource "aws_db_subnet_group" "main" {
  name        = local.prefix
  description = "mock-sts ${var.environment}: private subnets, three AZs"
  subnet_ids  = aws_subnet.private[*].id
}

resource "aws_db_parameter_group" "main" {
  name        = "${local.prefix}-pg18"
  family      = "postgres18"
  description = "mock-sts ${var.environment}: TLS required"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  # The CA bundle in the image verifies TLS 1.2 and later; nothing older.
  parameter {
    name  = "ssl_min_protocol_version"
    value = "TLSv1.2"
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
  kms_key_id        = data.aws_kms_key.main.arn

  availability_zone      = local.azs[0]
  multi_az               = false
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]
  parameter_group_name   = aws_db_parameter_group.main.name
  ca_cert_identifier     = "rds-ca-rsa2048-g1"

  backup_retention_period  = var.backup_retention_days
  backup_window            = "10:00-10:30"
  maintenance_window       = "sun:11:00-sun:11:30"
  copy_tags_to_snapshot    = true
  delete_automated_backups = var.delete_automated_backups
  skip_final_snapshot      = true
  deletion_protection      = false

  auto_minor_version_upgrade = true
  apply_immediately          = true
}

resource "aws_db_instance" "replica" {
  identifier          = "${local.prefix}-replica"
  replicate_source_db = aws_db_instance.primary.identifier
  instance_class      = var.db_instance_class

  storage_type      = "gp3"
  storage_encrypted = true
  kms_key_id        = data.aws_kms_key.main.arn

  availability_zone      = local.azs[1]
  multi_az               = false
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.database.id]
  parameter_group_name   = aws_db_parameter_group.main.name
  ca_cert_identifier     = "rds-ca-rsa2048-g1"

  # A replica keeps no backups of its own; the primary's are the record.
  backup_retention_period = 0
  skip_final_snapshot     = true
  deletion_protection     = false

  auto_minor_version_upgrade = true
  apply_immediately          = true
}
