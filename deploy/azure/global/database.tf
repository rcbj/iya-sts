# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE GLOBAL DATABASE: ONE WRITER IN THE PRIMARY CELL'S REGION, ONE
# CROSS-REGION READ REPLICA IN EVERY OTHER (issue #98, D3) —
# deploy/aws/global/database.tf's model on Flexible Server, which makes a
# cross-region read replica of the engine the cells already run.
#
# The global tier holds what every cell needs and no person's data — realms,
# settings, applications, policies, signing keys, the Root and
# Intermediates, the routing index (issue #98, section 3). It is written
# rarely, so every write may pay the round trip to the writer across the
# peering; it is read by every node, so every cell reads a copy in its own
# region.
#
# THE SAME SCHEMA as a cell database: the primary cell's nodes run a second
# schema-init against this writer (../environment/units/
# sts-global-schema.service.tftpl), and a replica takes the schema, the
# `sts_app` role and its password by replication.
#
# REACHED THROUGH PRIVATE ENDPOINTS AT FIXED ADDRESSES, one per server, in
# its cell's private subnet (.12, ../environment/cells.tf's formula): the
# writer's is dialled by every cell's nodes across the peering, a replica's
# by its own cell's. Each node maps the server's name to the address
# (`--add-host`), so no private DNS zone is shared between the cells —
# which a VNet may link only one of per name.
#
# ENCRYPTED UNDER EACH REGION'S `mock-sts` KEY: the global tier is what every
# region may hold, and a replica's key must be in its own region. TLS
# required, as on a cell database. Only the writer keeps backups.
# ---------------------------------------------------------------------------
resource "random_id" "database" {
  byte_length = 3
}

resource "azurerm_postgresql_flexible_server" "writer" {
  name                = "${local.prefix}-writer-${random_id.database.hex}"
  location            = local.primary_region
  resource_group_name = data.azurerm_resource_group.global.name
  version             = var.db_version
  sku_name            = var.db_sku
  storage_mb          = var.db_storage_mb
  auto_grow_enabled   = true
  zone                = "1"

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
    identity_ids = [data.azurerm_user_assigned_identity.postgres[var.primary_cell].id]
  }

  customer_managed_key {
    key_vault_key_id                  = data.azurerm_key_vault_key.main[var.primary_cell].versionless_id
    primary_user_assigned_identity_id = data.azurerm_user_assigned_identity.postgres[var.primary_cell].id
  }

  maintenance_window {
    day_of_week  = 0
    start_hour   = 11
    start_minute = 30
  }

  tags = local.tags

  lifecycle {
    ignore_changes = [zone]
  }
}

resource "azurerm_postgresql_flexible_server_configuration" "tls" {
  for_each = {
    require_secure_transport = "on"
    ssl_min_protocol_version = "TLSv1.2"
  }
  name      = each.key
  server_id = azurerm_postgresql_flexible_server.writer.id
  value     = each.value
}

resource "azurerm_postgresql_flexible_server_database" "sts" {
  name      = local.db_name
  server_id = azurerm_postgresql_flexible_server.writer.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

# ---------------------------------------------------------------------------
# ONE REPLICA PER NON-PRIMARY CELL, in that cell's region, in the global
# group (the foundation allows it every cell's region). Asynchronous
# physical replication, read-only; Azure carries it and bills the transfer
# between regions.
# ---------------------------------------------------------------------------
resource "azurerm_postgresql_flexible_server" "replica" {
  for_each            = local.replica_cells
  name                = "${local.prefix}-${each.key}-${random_id.database.hex}"
  location            = each.value.region
  resource_group_name = data.azurerm_resource_group.global.name
  version             = var.db_version
  sku_name            = var.db_sku
  storage_mb          = var.db_storage_mb
  auto_grow_enabled   = true
  zone                = "1"

  create_mode      = "Replica"
  source_server_id = azurerm_postgresql_flexible_server.writer.id

  public_network_access_enabled = false

  identity {
    type         = "UserAssigned"
    identity_ids = [data.azurerm_user_assigned_identity.postgres[each.key].id]
  }

  customer_managed_key {
    key_vault_key_id                  = data.azurerm_key_vault_key.main[each.key].versionless_id
    primary_user_assigned_identity_id = data.azurerm_user_assigned_identity.postgres[each.key].id
  }

  tags = merge(local.tags, { Cell = each.key })

  lifecycle {
    ignore_changes = [zone]
  }

  depends_on = [azurerm_postgresql_flexible_server_database.sts]
}

locals {
  # Every global server by the cell it serves: the writer in the primary
  # cell, a replica in each other.
  servers = merge(
    { (var.primary_cell) = azurerm_postgresql_flexible_server.writer },
    azurerm_postgresql_flexible_server.replica,
  )
}

resource "azurerm_private_endpoint" "global" {
  for_each                      = var.cells
  name                          = "${var.name}-${var.environment}-${each.key}-global-db"
  location                      = each.value.region
  resource_group_name           = data.azurerm_resource_group.global.name
  subnet_id                     = local.cell[each.key].private_subnet_id
  custom_network_interface_name = "${var.name}-${var.environment}-${each.key}-global-db"

  private_service_connection {
    name                           = "global-db"
    private_connection_resource_id = local.servers[each.key].id
    subresource_names              = ["postgresqlServer"]
    is_manual_connection           = false
  }

  ip_configuration {
    name               = "global-db"
    private_ip_address = local.global_db_ip[each.key]
    subresource_name   = "postgresqlServer"
    member_name        = "postgresqlServer"
  }

  tags = merge(local.tags, { Cell = each.key })
}
