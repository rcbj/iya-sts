# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

locals {
  # Every name starts `mock-sts-<environment>`, as on AWS — and carries the
  # cell in a cell (#97, cells.tf).
  prefix      = local.multi ? "${var.name}-${var.environment}-${var.cell}" : "${var.name}-${var.environment}"
  secret_path = local.prefix

  # THE REGION'S FIRST THREE ZONES, one node in each (nodes.tf) — AWS's
  # first three availability zones.
  zones = slice(sort(data.google_compute_zones.available.names), 0, 3)

  # Two /24s of the /16, numbered as AWS numbers its subnets: the nodes in
  # the first (AWS's public subnets), the database endpoint in number 10
  # (AWS's private subnets). A GCP subnet is REGIONAL, so one of each covers
  # all three zones.
  #
  # A CELL'S ARE CUT FROM ITS OWN CIDR in the cells file, distinct from every
  # other cell's on both clouds, because they share routes over the VPN.
  vpc_cidr     = local.multi ? local.this_cell.vpc_cidr : var.vpc_cidr
  nodes_cidr   = cidrsubnet(local.vpc_cidr, 8, 0)
  private_cidr = cidrsubnet(local.vpc_cidr, 8, 10)

  nodes = { for i in range(var.node_count) : "node-${substr("abc", i, 1)}" => i }

  db_name        = "sts"
  db_master_user = "stsadmin"
  db_app_user    = "sts_app"
  db_port        = 5432

  registry_host    = "${var.region}-docker.pkg.dev"
  registry_url     = "${local.registry_host}/${var.project_id}/${var.name}"
  schema_image_tag = var.schema_image_tag != "" ? var.schema_image_tag : "schema-${var.image_tag}"
  init_image_tag   = var.init_image_tag != "" ? var.init_image_tag : "init-${var.image_tag}"
  service_image    = "${local.registry_url}/${var.name}:${var.image_tag}"
  schema_image     = "${local.registry_url}/${var.name}:${local.schema_image_tag}"
  init_image       = "${local.registry_url}/${var.name}:${local.init_image_tag}"

  # The name clients use: `public_hostname` when set (dns.tf), otherwise the
  # load balancer's address — AWS uses the NLB's DNS name, and a GCP
  # passthrough load balancer has an address and no name.
  public_name     = var.public_hostname != ""
  lb_address      = google_compute_address.lb.address
  public_host     = local.public_name ? var.public_hostname : local.lb_address
  public_base_url = "https://${local.public_host}"

  # A DEFAULT PORT IS LEFT OUT of the URL that goes inside a certificate:
  # deploy/aws/environment/locals.tf, `pki_public_url`, argues it.
  pki_public_url = var.pki_listener_port == 80 ? "http://${local.public_host}" : "http://${local.public_host}:${var.pki_listener_port}"

  # EVERY PORT THE LOAD BALANCER PUBLISHES and the node port behind it —
  # AWS's map, row for row (deploy/aws/environment/locals.tf argues each).
  #
  # **THE MAPPING IS DOCKER'S HERE, NOT THE LOAD BALANCER'S.** A GCP
  # passthrough load balancer does not translate ports: a packet for 443
  # arrives at the VM for 443. So each row is published by Docker on the
  # VM (`-p <listener>:<container>`, units/sts-node.service.tftpl), and the
  # container listens where it always has — 8081 behind 443, 8082 behind 80.
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
  # container. /run is a tmpfs on Container-Optimized OS, so nothing secret
  # written there reaches a disk. Spelt once, like AWS's TLS paths.
  host_run_dir     = "/run/sts"
  host_tls_dir     = "/run/sts/tls"
  host_db_ca       = "/run/sts/database-ca.pem"
  container_tls    = "/var/run/sts-tls"
  tls_cert         = "/var/run/sts-tls/certificate.pem"
  tls_keyfile      = "/var/run/sts-tls/key.pem"
  container_db_ca  = "/var/run/sts/database-ca.pem"
  host_upload_dir  = "/mnt/disks/risk-uploads"
  risk_upload_dir  = "/usr/src/sts/data/risk-uploads"
  risk_upload_disk = "risk-uploads"
}

data "google_compute_zones" "available" {
  region = local.region
  status = "UP"
}

# The foundation's resources, found by name. Read-only lookups; this stack
# never changes them.
data "google_kms_key_ring" "main" {
  name     = var.name
  location = local.region
}

data "google_kms_crypto_key" "main" {
  name     = var.name
  key_ring = data.google_kms_key_ring.main.id
}

# The node account the foundation made for this environment. Not finding it
# means the environment is not in the foundation's `environments`.
data "google_service_account" "nodes" {
  account_id = local.multi ? "${var.name}-env-${var.environment}-${var.cell}" : "${var.name}-env-${var.environment}"
}

data "google_dns_managed_zone" "public" {
  count = local.public_name ? 1 : 0
  name  = replace(var.dns_zone_name, ".", "-")
}

data "google_secret_manager_secret" "tls" {
  count     = local.public_name ? 1 : 0
  secret_id = "${local.prefix}-tls"
}

# Container-Optimized OS, the stable channel: Google maintains the OS, Docker
# and the logging agent, which is what Fargate bought on AWS
# (deploy/gcp/CLAUDE.md, *Why VMs*).
data "google_compute_image" "cos" {
  family  = "cos-stable"
  project = "cos-cloud"
}
