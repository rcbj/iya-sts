# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1

locals {
  subscription_id = data.azurerm_client_config.current.subscription_id

  # THE UNIT (../foundation/locals.tf): `<env>`, or `<env>-<cell>` in a cell.
  # Every name starts `mock-sts-<unit>`, as on AWS.
  unit   = local.multi ? "${var.environment}-${var.cell}" : var.environment
  prefix = "${var.name}-${local.unit}"

  # The region's short code (cells.tf), which names its foundation group,
  # `mock-sts-<code>`.
  region_code = local.region_codes[local.region]

  # THE CELL'S OWN DATA IS UNDER ITS REGION'S `mock-sts-cell` KEY, and a
  # single-cell environment's under `mock-sts` — AWS's cell key and project
  # key (../foundation/modules/region).
  key_kind = local.multi ? "cell" : "main"

  tags = merge(var.tags, {
    Project     = "STS"
    Environment = var.environment
    Cell        = var.cell
  })

  # Two /24s of the /16, numbered as AWS numbers its subnets: the nodes in
  # the first (AWS's public subnets), the database's private endpoint and
  # the inter-cell load balancer in number 10 (AWS's private subnets). An
  # Azure subnet spans the region's zones, so one of each covers all three.
  vpc_cidr     = local.multi ? local.this_cell.vpc_cidr : var.vpc_cidr
  nodes_cidr   = cidrsubnet(local.vpc_cidr, 8, 0)
  private_cidr = cidrsubnet(local.vpc_cidr, 8, 10)
  # The cell database's private endpoint, at a FIXED address so the rules and
  # the containers' host mapping name something known at plan time.
  db_endpoint_ip = cidrhost(local.private_cidr, 10)

  zones = ["1", "2", "3"]
  nodes = { for i in range(var.node_count) : "node-${substr("abc", i, 1)}" => i }

  db_name        = "sts"
  db_master_user = "stsadmin"
  db_app_user    = "sts_app"
  db_port        = 5432

  registry_host    = data.azurerm_container_registry.main.login_server
  schema_image_tag = var.schema_image_tag != "" ? var.schema_image_tag : "schema-${var.image_tag}"
  init_image_tag   = var.init_image_tag != "" ? var.init_image_tag : "init-${var.image_tag}"
  service_image    = "${local.registry_host}/${var.name}:${var.image_tag}"
  schema_image     = "${local.registry_host}/${var.name}:${local.schema_image_tag}"
  init_image       = "${local.registry_host}/${var.name}:${local.init_image_tag}"

  # The name clients use: `public_hostname` when set (dns.tf), otherwise the
  # load balancer's address — AWS uses the NLB's DNS name, and an Azure load
  # balancer has an address (and, in a cell, a name only Traffic Manager
  # uses).
  public_name     = var.public_hostname != ""
  lb_address      = azurerm_public_ip.lb.ip_address
  public_host     = local.public_name ? var.public_hostname : local.lb_address
  public_base_url = "https://${local.public_host}"

  # A DEFAULT PORT IS LEFT OUT of the URL that goes inside a certificate:
  # deploy/aws/environment/locals.tf, `pki_public_url`, argues it.
  pki_public_url = var.pki_listener_port == 80 ? "http://${local.public_host}" : "http://${local.public_host}:${var.pki_listener_port}"

  # EVERY PORT THE LOAD BALANCER PUBLISHES and the node port behind it —
  # AWS's map, row for row (deploy/aws/environment/locals.tf argues each).
  # **THE LOAD BALANCER MAPS THEM, AS AWS'S DOES AND GCP'S CANNOT**: an
  # Azure load-balancing rule has a frontend and a backend port, so the
  # container listens where it always has and Docker publishes each port
  # 1:1 (units/sts-node.service.tftpl).
  published_ports = merge({
    https = { listener = 443, container = 8081 }
    ldap  = { listener = 389, container = 389 }
    ldaps = { listener = 636, container = 636 }
    pki   = { listener = var.pki_listener_port, container = 8082 }
    }, var.publish_kerberos ? {
    kerberos = { listener = 88, container = 88 }
  } : {})

  # THE DEFAULT REALM'S SPIFFE PORTS (AWS: spiffe_default.tf), part of every
  # environment, the same number on both sides.
  spiffe_default_ports = {
    workload = var.spiffe_workload_port
    server   = var.spiffe_server_port
  }

  all_ports = merge(local.published_ports, {
    for k, p in local.spiffe_default_ports :
    "spiffe-${k}" => { listener = p, container = p }
  })

  # WHERE THE NODE READS WHAT THE INIT UNITS LEFT, on the VM and in the
  # container. /run is a tmpfs on Ubuntu, so nothing secret written there
  # reaches a disk. Spelt once, like AWS's TLS paths.
  host_run_dir    = "/run/sts"
  host_tls_dir    = "/run/sts/tls"
  container_tls   = "/var/run/sts-tls"
  tls_cert        = "/var/run/sts-tls/certificate.pem"
  tls_keyfile     = "/var/run/sts-tls/key.pem"
  host_upload_dir = "/mnt/risk-uploads"
  risk_upload_dir = "/usr/src/sts/data/risk-uploads"

  # The vault's URL, with Key Vault's trailing slash removed: the SDK and
  # the REST calls both take it either way, and a URL spelt one way is easier
  # to compare in a log.
  vault_uri = trimsuffix(data.azurerm_key_vault.unit.vault_uri, "/")
}

# ---------------------------------------------------------------------------
# THE FOUNDATION'S RESOURCES, FOUND BY NAME. Read-only lookups; this stack
# changes none of them. Not finding one means the foundation does not list
# this environment (or cell), or was not re-applied after it was added.
# ---------------------------------------------------------------------------
data "azurerm_resource_group" "unit" {
  name = local.prefix
}

data "azurerm_user_assigned_identity" "nodes" {
  name                = "${local.prefix}-nodes"
  resource_group_name = data.azurerm_resource_group.unit.name
}

# The vault's name is ../foundation/locals.tf's formula; keep the two in step.
data "azurerm_key_vault" "unit" {
  name                = "ms${var.environment}${var.cell}-${substr(sha1("${local.subscription_id}/${var.name}/${var.environment}/${var.cell}"), 0, 4)}"
  resource_group_name = data.azurerm_resource_group.unit.name
}

data "azurerm_key_vault" "keys" {
  name                = "msk${local.region_code}-${substr(sha1("${local.subscription_id}/${var.name}/${local.region}"), 0, 6)}"
  resource_group_name = "${var.name}-${local.region_code}"
}

data "azurerm_key_vault_key" "data" {
  name         = local.key_kind == "cell" ? "${var.name}-cell" : var.name
  key_vault_id = data.azurerm_key_vault.keys.id
}

data "azurerm_disk_encryption_set" "data" {
  name                = local.key_kind == "cell" ? "${var.name}-${local.region_code}-cell" : "${var.name}-${local.region_code}"
  resource_group_name = "${var.name}-${local.region_code}"
}

data "azurerm_user_assigned_identity" "postgres" {
  name                = "${var.name}-${local.region_code}-postgres"
  resource_group_name = "${var.name}-${local.region_code}"
}

data "azurerm_monitor_data_collection_rule" "syslog" {
  name                = "${var.name}-${local.region_code}-syslog"
  resource_group_name = "${var.name}-${local.region_code}"
}

data "azurerm_container_registry" "main" {
  name                = "${replace(var.name, "-", "")}${substr(sha1(local.subscription_id), 0, 8)}"
  resource_group_name = "${var.name}-foundation"
}

data "azurerm_dns_zone" "public" {
  count               = local.public_name ? 1 : 0
  name                = var.dns_zone_name
  resource_group_name = "${var.name}-foundation"
}
