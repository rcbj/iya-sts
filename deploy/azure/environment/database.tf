# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# AZURE DATABASE FOR POSTGRESQL FLEXIBLE SERVER 18: A PRIMARY AND ONE READ
# REPLICA, IN DIFFERENT ZONES (deploy/aws/environment/rds.tf,
# deploy/gcp/environment/database.tf).
#
# NOT PUBLIC: `public_network_access_enabled = false`. The nodes reach the
# primary through a PRIVATE ENDPOINT — an address in this VNet's private
# subnet — and the security group lets only the nodes dial it (nsg.tf).
#
# A PRIVATE ENDPOINT AND NOT VNET INTEGRATION, GCP's choice for GCP's reason:
# VNet integration delegates a subnet to the service and joins the server
# to a private DNS zone, and a delegated subnet with a server's service
# association in it is what refuses to delete when a teardown runs in the
# wrong order — an environment here is built and destroyed many times. An
# endpoint is a network interface of this VNet's own and goes with it.
#
# NO PRIVATE DNS ZONE: the endpoint is at a FIXED address (.10 of the
# private subnet), and the node dials the server's own name mapped to it
# inside the container (`--add-host`, nodes.tf) — GCP's arrangement. The
# server's certificate names that name, so TLS verifies it.
#
# TLS REQUIRED (`require_secure_transport`, on by default and set anyway —
# AWS's `rds.force_ssl`). **The certificate chains to a PUBLIC root**
# (DigiCert Global Root G2, Microsoft RSA Root CA 2017), so the node's own
# trust store verifies it and no CA file has to travel with the instance, as
# GCP's did; schema-init verifies it by name (`verify-full`).
#
# ENCRYPTED AT REST under the region's customer-managed key — `mock-sts` for
# a single-cell environment, `mock-sts-cell` for a cell — read by the
# region's PostgreSQL identity (../foundation/modules/region). Backups
# daily, `backup_retention_days` kept, and not geo-redundant: a copy in the
# paired region would be a copy outside the cell.
#
# THE REPLICA is asynchronous and read-only, as on AWS and GCP: a copy and a
# promotable standby, not a failover target; mock-sts reads and writes the
# primary only, and nothing dials the replica, so it has no endpoint.
# (Flexible Server's zone-redundant HIGH AVAILABILITY would be the Azure way
# to survive a zone; it is a different thing from AWS's arrangement, and
# deploy/azure/CLAUDE.md lists it as the step to take for a real
# deployment.)
#
# **THE NAMES CARRY A RANDOM SUFFIX**, GCP's lesson: a server's name is
# global (`<name>.postgres.database.azure.com`), and a rebuilt environment
# should never wait on a name the last one held.
# ---------------------------------------------------------------------------
resource "random_id" "database" {
  byte_length = 3
}

resource "random_password" "db_master" {
  length  = 40
  special = false
}

locals {
  db_suffix   = random_id.database.hex
  db_hostname = azurerm_postgresql_flexible_server.primary.fqdn
}

resource "azurerm_postgresql_flexible_server" "primary" {
  name                = "${local.prefix}-primary-${local.db_suffix}"
  location            = local.region
  resource_group_name = data.azurerm_resource_group.unit.name
  version             = var.db_version
  sku_name            = var.db_sku
  storage_mb          = var.db_storage_mb
  auto_grow_enabled   = true
  zone                = local.zones[0]

  administrator_login    = local.db_master_user
  administrator_password = random_password.db_master.result

  public_network_access_enabled = false
  backup_retention_days         = var.backup_retention_days
  geo_redundant_backup_enabled  = false

  authentication {
    password_auth_enabled         = true
    active_directory_auth_enabled = false
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [data.azurerm_user_assigned_identity.postgres.id]
  }

  customer_managed_key {
    key_vault_key_id                  = data.azurerm_key_vault_key.data.versionless_id
    primary_user_assigned_identity_id = data.azurerm_user_assigned_identity.postgres.id
  }

  maintenance_window {
    day_of_week  = 0
    start_hour   = 11
    start_minute = 0
  }

  tags = local.tags

  lifecycle {
    # Azure moves a server between zones only on a failover it chose; a plan
    # that wanted to move it back would rebuild the database.
    ignore_changes = [zone]
  }
}

resource "azurerm_postgresql_flexible_server_configuration" "tls" {
  for_each = {
    require_secure_transport = "on"
    ssl_min_protocol_version = "TLSv1.2"
  }
  name      = each.key
  server_id = azurerm_postgresql_flexible_server.primary.id
  value     = each.value
}

resource "azurerm_postgresql_flexible_server_database" "sts" {
  name      = local.db_name
  server_id = azurerm_postgresql_flexible_server.primary.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server" "replica" {
  count               = var.db_replica ? 1 : 0
  name                = "${local.prefix}-replica-${local.db_suffix}"
  location            = local.region
  resource_group_name = data.azurerm_resource_group.unit.name
  version             = var.db_version
  sku_name            = var.db_sku
  storage_mb          = var.db_storage_mb
  auto_grow_enabled   = true
  zone                = local.zones[1]

  create_mode      = "Replica"
  source_server_id = azurerm_postgresql_flexible_server.primary.id

  public_network_access_enabled = false

  identity {
    type         = "UserAssigned"
    identity_ids = [data.azurerm_user_assigned_identity.postgres.id]
  }

  customer_managed_key {
    key_vault_key_id                  = data.azurerm_key_vault_key.data.versionless_id
    primary_user_assigned_identity_id = data.azurerm_user_assigned_identity.postgres.id
  }

  tags = local.tags

  lifecycle {
    ignore_changes = [zone]
  }

  depends_on = [azurerm_postgresql_flexible_server_database.sts]
}

# ---------------------------------------------------------------------------
# THE PRIVATE ENDPOINT: the primary, at a fixed address of this VNet's own.
# ---------------------------------------------------------------------------
resource "azurerm_private_endpoint" "database" {
  name                          = "${local.prefix}-database"
  location                      = local.region
  resource_group_name           = data.azurerm_resource_group.unit.name
  subnet_id                     = azurerm_subnet.private.id
  custom_network_interface_name = "${local.prefix}-database"

  private_service_connection {
    name                           = "database"
    private_connection_resource_id = azurerm_postgresql_flexible_server.primary.id
    subresource_names              = ["postgresqlServer"]
    is_manual_connection           = false
  }

  ip_configuration {
    name               = "database"
    private_ip_address = local.db_endpoint_ip
    subresource_name   = "postgresqlServer"
    member_name        = "postgresqlServer"
  }

  tags = local.tags
}
