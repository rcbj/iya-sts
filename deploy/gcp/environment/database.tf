# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# CLOUD SQL FOR POSTGRESQL 18: A PRIMARY AND ONE READ REPLICA, IN DIFFERENT
# ZONES (deploy/aws/environment/rds.tf).
#
# NOT PUBLIC: no public address at all (`ipv4_enabled = false`). The nodes
# reach the primary through a PRIVATE SERVICE CONNECT ENDPOINT — an address
# in this VPC's private subnet that forwards to the instance's service
# attachment — and the firewall lets only the nodes dial it (firewall.tf).
#
# PSC AND NOT PRIVATE SERVICES ACCESS, which is the older way to give Cloud
# SQL a private address: PSA peers the VPC with Google's service network
# through a reserved range and a `servicenetworking` connection that does not
# tear down cleanly — a destroy that leaves the peering behind is a VPC that
# will not delete — and an environment here is built and destroyed many times.
# A PSC endpoint is a forwarding rule of this VPC's own and goes with it.
#
# TLS REQUIRED: `ssl_mode = ENCRYPTED_ONLY` refuses a plaintext connection
# (AWS's `rds.force_ssl = 1`); no client certificate is asked for, as on RDS.
# **THE NODES VERIFY THE SERVER, AND BY NAME.** The server certificate is
# issued by Google's CA Service hierarchy (`GOOGLE_MANAGED_CAS_CA`), which
# names the instance by its `dns_name`; the node dials that name — mapped to
# the endpoint's address inside the container (`--add-host`,
# units/sts-node.service.tftpl), so no private DNS zone is needed — and
# verifies the chain against the instance's CA (`server_ca_cert`), which
# cloud-init writes to the VM and the container reads as NODE_EXTRA_CA_CERTS.
# AWS bakes the RDS bundle into the image; here the CA is per instance and
# arrives with it, so the SAME image serves any environment.
#
# ENCRYPTED AT REST under the project key (CMEK): the disks, the backups and
# the replica. Backups daily with point-in-time recovery, the last
# `backup_retention_days` kept. Cloud SQL deletes an instance's automated
# backups with it — AWS's `delete_automated_backups = true`, always.
#
# THE REPLICA is asynchronous and read-only, as on AWS: a copy and a
# promotable standby, not a failover target; mock-sts reads and writes the
# primary only. It gets no PSC endpoint, because nothing dials it.
#
# **THE NAMES CARRY A RANDOM SUFFIX, WHERE AWS'S DO NOT**: Cloud SQL will not
# give a deleted instance's name to a new one for up to a week, and an
# environment is destroyed and rebuilt far more often than that.
# ---------------------------------------------------------------------------
resource "random_id" "database" {
  byte_length = 3
}

resource "random_password" "db_master" {
  length  = 40
  special = false
}

locals {
  db_suffix = random_id.database.hex

  # The instance's DNS name without the root's trailing dot: what the node's
  # connection string names and what node's TLS matches the certificate
  # against (node strips a trailing dot on both sides; libpq does not, hence
  # `schema_init_sslmode`).
  db_hostname = trimsuffix(google_sql_database_instance.primary.dns_name, ".")
  # The instance's CA, which the provider marks sensitive with the rest of
  # `server_ca_cert` — and which is a CERTIFICATE, public by design. Left
  # sensitive it would hide every node's whole cloud-init from a plan, which
  # is where a reader checks what a node will run.
  db_ca_pem = nonsensitive(join("\n", [for c in google_sql_database_instance.primary.server_ca_cert : c.cert]))

  db_ip_configuration = {
    ipv4_enabled   = false
    ssl_mode       = "ENCRYPTED_ONLY"
    server_ca_mode = "GOOGLE_MANAGED_CAS_CA"
  }
}

resource "google_sql_database_instance" "primary" {
  name                = "${local.prefix}-primary-${local.db_suffix}"
  region              = local.region
  database_version    = var.db_version
  encryption_key_name = data.google_kms_crypto_key.main.id
  deletion_protection = false

  settings {
    tier                        = var.db_tier
    edition                     = "ENTERPRISE"
    availability_type           = "ZONAL"
    disk_type                   = "PD_SSD"
    disk_size                   = var.db_disk_gib
    disk_autoresize             = true
    deletion_protection_enabled = false

    location_preference {
      zone = local.zones[0]
    }

    ip_configuration {
      ipv4_enabled   = local.db_ip_configuration.ipv4_enabled
      ssl_mode       = local.db_ip_configuration.ssl_mode
      server_ca_mode = local.db_ip_configuration.server_ca_mode

      psc_config {
        psc_enabled               = true
        allowed_consumer_projects = [var.project_id]
      }
    }

    backup_configuration {
      enabled                        = true
      start_time                     = "10:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = var.backup_retention_days
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = 7
      hour         = 11
      update_track = "stable"
    }

    # The CA the image verifies against is the instance's, and TLS 1.2 is
    # what node's pg speaks at least; nothing older is offered.
    database_flags {
      name  = "ssl_min_protocol_version"
      value = "TLSv1.2"
    }
  }
}

resource "google_sql_database_instance" "replica" {
  name                 = "${local.prefix}-replica-${local.db_suffix}"
  region               = local.region
  database_version     = var.db_version
  master_instance_name = google_sql_database_instance.primary.name
  encryption_key_name  = data.google_kms_crypto_key.main.id
  deletion_protection  = false

  replica_configuration {
    failover_target = false
  }

  settings {
    tier                        = var.db_tier
    edition                     = "ENTERPRISE"
    availability_type           = "ZONAL"
    disk_type                   = "PD_SSD"
    disk_size                   = var.db_disk_gib
    disk_autoresize             = true
    deletion_protection_enabled = false

    location_preference {
      zone = local.zones[1]
    }

    ip_configuration {
      ipv4_enabled   = local.db_ip_configuration.ipv4_enabled
      ssl_mode       = local.db_ip_configuration.ssl_mode
      server_ca_mode = local.db_ip_configuration.server_ca_mode

      psc_config {
        psc_enabled               = true
        allowed_consumer_projects = [var.project_id]
      }
    }

    database_flags {
      name  = "ssl_min_protocol_version"
      value = "TLSv1.2"
    }
  }
}

resource "google_sql_database" "sts" {
  name     = local.db_name
  instance = google_sql_database_instance.primary.name
}

# The master user schema-init applies the schema as — cloudsqlsuperuser, not
# a superuser, as RDS's master is not; postgres/schema.sql needs neither.
# ABANDONED on destroy: dropping a role that owns objects fails, and the
# instance goes with the environment anyway.
resource "google_sql_user" "master" {
  name            = local.db_master_user
  instance        = google_sql_database_instance.primary.name
  password        = random_password.db_master.result
  deletion_policy = "ABANDON"
}

# ---------------------------------------------------------------------------
# THE PRIVATE SERVICE CONNECT ENDPOINT: the primary, at an address of this
# VPC's own. A fixed address (the private subnet's .10), so the firewall rule
# and the containers' host mapping name something known at plan time.
# ---------------------------------------------------------------------------
resource "google_compute_address" "database" {
  name         = "${local.prefix}-database"
  region       = local.region
  subnetwork   = google_compute_subnetwork.private.id
  address_type = "INTERNAL"
  address      = cidrhost(local.private_cidr, 10)
  description  = "mock-sts ${var.environment}: the Cloud SQL primary's PSC endpoint"
}

resource "google_compute_forwarding_rule" "database" {
  name                  = "${local.prefix}-database"
  region                = local.region
  network               = local.network_id
  ip_address            = google_compute_address.database.id
  target                = google_sql_database_instance.primary.psc_service_attachment_link
  load_balancing_scheme = ""
}
