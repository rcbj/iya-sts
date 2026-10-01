# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THREE mock-sts NODES, ONE MANAGED INSTANCE GROUP PER ZONE
# (deploy/aws/environment/ecs.tf).
#
# WHY VMs. Fargate's GCP counterpart is Cloud Run, and Cloud Run publishes
# HTTP(S) on one port: no LDAP on 389 and 636, no KDC on 88, no SPIFFE gRPC,
# and no client certificate (it terminates TLS). GKE would publish all of it
# and bring a cluster to keep. So a node is a VM on CONTAINER-OPTIMIZED OS —
# Google keeps the OS, Docker and the logging agent current, which is what
# Fargate bought — running the same containers AWS's task definition runs, as
# systemd units cloud-init writes (units/).
#
# WHY A GROUP PER ZONE, EACH OF SIZE ONE: AWS's service per availability
# zone, for AWS's reasons — one node per zone by construction, and node-a
# made and STABLE before node-b and node-c are created, which orders the cold
# start (cluster/CLAUDE.md) and makes node-a's schema-init the first. A group
# rather than a bare VM because it AUTOHEALS: a node failing /healthcheck is
# re-created, as ECS replaced an unhealthy task.
#
# `wait_for_instances_status = "STABLE"` waits until the group has no action
# in flight, which with autohealing includes VERIFYING the new instance —
# the nearest thing to ECS's wait for steady state.
#
# EACH VM RUNS, IN ORDER (units/):
#   sts-disk      the upload disk, mounted and emptied
#   sts-registry  Docker's credentials for Artifact Registry
#   sts-secrets   Secret Manager → env files on a tmpfs (ECS `secrets`)
#   sts-cert      the ACME certificate (only with a public name; AWS cert-init)
#   sts-schema    postgres/schema.sql as the master user (AWS schema-init)
#   sts-node      mock-sts itself, restarted by systemd if it exits
#
# A NEW IMAGE IS A NEW TEMPLATE, and the group REPLACES its one instance —
# stops it, then makes the new one (AWS's minimum healthy percent 0), keeping
# its name.
# ---------------------------------------------------------------------------
locals {
  # The settings every node agrees on (AWS: `node_environment`). The cluster
  # refuses a node whose must-agree settings differ, so they are spelt once.
  node_environment = merge({
    STS_MODE                    = var.sts_mode
    STS_PERSISTENCE_MODE        = "postgres"
    STS_PERSISTENCE_COORDINATE  = "true"
    STS_KEYS_SOURCE             = "persisted"
    STS_CLUSTER_MODE            = "active-active"
    STS_PUBLIC_BASE_URL         = local.public_base_url
    STS_TLS_HOSTNAMES           = join(",", distinct(compact([local.public_name ? var.public_hostname : "", local.cell_console_host, "localhost"])))
    STS_TLS_IPS                 = join(",", ["127.0.0.1", local.lb_address])
    STS_WORKERS_REQUEST_COUNT   = tostring(var.workers_request_count)
    STS_WORKERS_SURFACE_COUNT   = tostring(var.workers_surface_count)
    STS_WORKERS_DISPATCH        = var.workers_dispatch
    STS_WORKERS_READ_YOUR_WRITE = tostring(var.workers_read_your_write)
    GOOGLE_CLOUD_PROJECT        = var.project_id

    # NO PROXY HEADER: a passthrough load balancer delivers the client's own
    # packets (lb.tf), so the peer IS the client and no proxy is trusted.
    STS_PROXY_PROTOCOL  = "off"
    STS_TRUSTED_PROXIES = ""

    # The key-encryption key and the database password, from Secret Manager
    # through common/secrets.js — the path issue #51 exists to exercise, on
    # the `gcp` provider. The rest arrive in the env file (secrets.tf).
    STS_KEYS_KEK_PROVIDER          = "gcp"
    STS_KEYS_KEK_REF               = local.shared_secret_names["kek"]
    STS_DATABASE_PASSWORD_PROVIDER = "gcp"
    STS_DATABASE_PASSWORD_REF      = local.secret_names["db-app-password"]

    # No password in the URL. The host is the instance's DNS name, mapped to
    # the PSC endpoint inside the container, so the certificate's name
    # matches (database.tf).
    STS_DATABASE_URL                     = "postgres://${local.db_app_user}@${local.db_hostname}:${local.db_port}/${local.db_name}?sslmode=require"
    STS_DATABASE_TLS_REJECT_UNAUTHORIZED = "true"
    NODE_EXTRA_CA_CERTS                  = local.container_db_ca

    # Where a certificate says its CRL and OCSP are: the FRONT-END port
    # (AWS's argument, deploy/aws/environment/ecs.tf).
    PKI_DISTRIBUTION_BASE_URL  = local.pki_public_url
    PKI_DISTRIBUTION_LDAP_HOST = local.public_host
    PKI_DISTRIBUTION_LDAP_PORT = tostring(local.published_ports.ldap.listener)

    LDAP_MAX_ENTRIES          = tostring(var.ldap_max_entries)
    STS_APPLICATIONS_MAX      = tostring(var.applications_max)
    STS_RISK_UPLOAD_DIRECTORY = local.risk_upload_dir
    },
    # The public certificate, where there is one: both settings or neither.
    local.public_name ? {
      STS_TLS_CERT_FILE = local.tls_cert
      STS_TLS_KEY_FILE  = local.tls_keyfile
    } : {},
    # A CELL'S CONTRACT WITH THE SERVICE (#97, cells.tf); empty otherwise.
    local.cell_environment,
  var.extra_environment)

  # `KEY=projects/…/secrets/…` pairs, comma-separated, for node-init's
  # secrets.sh. Resource names hold no comma.
  node_secret_map   = join(",", [for k, v in local.node_secret_env : "${k}=${v}"])
  schema_secret_map = join(",", [for k, v in local.schema_secret_env : "${k}=${v}"])
  # A cell's subscriber init (#97); '' elsewhere, and the unit then reads
  # nothing for it.
  global_schema_secret_map = join(",", [for k, v in local.global_schema_secret_env : "${k}=${v}"])

  # THE GLOBAL TIER'S COPY, IN A CELL'S `full` PHASE (#97): its init runs
  # before the node, and the node dials it by the name its certificate
  # carries, mapped to its private-services address as the cell database's
  # name is mapped to its endpoint.
  global_copy = local.multi && local.full

  node_requires = join(" ", concat(
    ["sts-disk.service", "sts-secrets.service", "sts-schema.service"],
    local.public_name ? ["sts-cert.service"] : [],
    local.global_copy ? ["sts-global-schema.service"] : [],
  ))

  node_ports = join(" \\\n  ", concat(
    [for p in values(local.all_ports) : "-p ${p.listener}:${p.container}"],
    # The inter-cell listener, behind the internal load balancer (#97).
    local.multi ? ["-p ${local.intercell_port}:${local.intercell_port}"] : [],
  ))

  # --add-host for every private name a container dials by a name its peer's
  # certificate carries: the cell database, and in a cell the global copy.
  extra_hosts = join(" \\\n  ", concat(
    ["--add-host ${local.db_hostname}:${google_compute_address.database.address}"],
    local.global_copy ? ["--add-host ${local.global.copy_host}:${local.global.copy_address}"] : [],
  ))

  # EVERY DATABASE CA A NODE VERIFIES, IN ONE FILE (NODE_EXTRA_CA_CERTS takes
  # one): the cell database's; and in a cell, the global copy's and the RDS
  # writer's region bundle (deploy/multicloud/gcp-global fetched it). All
  # public certificates.
  db_ca_bundle = join("\n", compact([
    local.db_ca_pem,
    local.global_copy ? local.global.copy_ca_pem : "",
    local.global_copy ? local.global.writer_ca_pem : "",
  ]))

  unit_files = {
    for node, i in local.nodes : node => merge({
      "sts-disk.service" = templatefile("${path.module}/units/sts-disk.service.tftpl", {})
      "sts-registry.service" = templatefile("${path.module}/units/sts-registry.service.tftpl", {
        registry_host = local.registry_host
      })
      "sts-secrets.service" = templatefile("${path.module}/units/sts-secrets.service.tftpl", {
        run_dir                  = local.host_run_dir
        init_image               = local.init_image
        node_secret_map          = local.node_secret_map
        schema_secret_map        = local.schema_secret_map
        global_schema_secret_map = local.global_schema_secret_map
      })
      "sts-schema.service" = templatefile("${path.module}/units/sts-schema.service.tftpl", {
        run_dir      = local.host_run_dir
        schema_image = local.schema_image
        db_host      = local.db_hostname
        db_address   = google_compute_address.database.address
        db_port      = local.db_port
        db_name      = local.db_name
        db_user      = local.db_master_user
        db_app_user  = local.db_app_user
        sslmode      = var.schema_init_sslmode
        db_ca        = local.host_db_ca
      })
      "sts-node.service" = templatefile("${path.module}/units/sts-node.service.tftpl", {
        node             = node
        environment      = var.environment
        requires         = local.node_requires
        run_dir          = local.host_run_dir
        image            = local.service_image
        extra_hosts      = local.extra_hosts
        ports            = local.node_ports
        upload_host      = local.host_upload_dir
        upload_container = local.risk_upload_dir
        db_ca            = local.host_db_ca
        db_ca_container  = local.container_db_ca
        # READ-ONLY: the node reads the certificate and must never be able
        # to change it.
        tls_mount = local.public_name ? "-v ${local.host_tls_dir}:${local.container_tls}:ro" : ""
      })
      }, local.public_name ? {
      "sts-cert.service" = templatefile("${path.module}/units/sts-cert.service.tftpl", {
        init_image  = local.init_image
        tls_dir     = local.host_tls_dir
        tls_secret  = data.google_secret_manager_secret.tls[0].id
        hostname    = var.public_hostname
        alt_names   = local.cell_console_host
        issuer      = node == "node-a" ? "true" : "false"
        acme_server = var.acme_server
        acme_email  = var.acme_email
        renew_days  = var.acme_renew_days
        project     = var.project_id
        dns_zone    = data.google_dns_managed_zone.public[0].name
      })
      } : {}, local.global_copy ? {
      # THE CELL'S COPY OF THE GLOBAL TIER (#97): the schema, the
      # application role made read-only, and the subscription to the RDS
      # writer's publication — deploy/aws/schema-init/apply.sh, as its
      # master user.
      "sts-global-schema.service" = templatefile("${path.module}/units/sts-global-schema.service.tftpl", {
        run_dir      = local.host_run_dir
        schema_image = local.schema_image
        db_host      = local.global.copy_host
        db_address   = local.global.copy_address
        db_port      = local.global.db_port
        db_name      = local.global.db_name
        db_user      = local.db_master_user
        db_app_user  = local.global.db_app_user
        sslmode      = var.schema_init_sslmode
        db_ca        = local.host_db_ca
        writer       = local.global.writer_address
        publication  = local.global.publication
        repl_user    = local.global.repl_user
        subscription = "${local.global.publication}_${var.cell}"
      })
    } : {})
  }

  # CLOUD-INIT: the units, the non-secret environment, the database's CA
  # (a public certificate) and the disk script — and then start the node.
  # Container-Optimized OS runs it on EVERY boot (/etc is not kept), so a
  # rebooted VM comes back the same. Metadata is readable by anybody who can
  # describe the instance: no secret is in it (secrets.tf).
  cloud_init = {
    for node, i in local.nodes : node => join("\n", ["#cloud-config", yamlencode({
      write_files = concat(
        [for name, body in local.unit_files[node] : {
          path        = "/etc/systemd/system/${name}"
          permissions = "0644"
          owner       = "root"
          content     = body
        }],
        [
          {
            path        = "/etc/sts/node.env"
            permissions = "0600"
            owner       = "root"
            content = join("\n", [
              for k, v in merge(local.node_environment, { STS_CLUSTER_NODE_NAME = node }) : "${k}=${v}"
            ])
          },
          {
            path        = local.host_db_ca
            permissions = "0644"
            owner       = "root"
            content     = local.db_ca_bundle
          },
          {
            path        = "/etc/sts/disk.sh"
            permissions = "0700"
            owner       = "root"
            content = templatefile("${path.module}/units/sts-disk.sh.tftpl", {
              device    = local.risk_upload_disk
              mount_dir = local.host_upload_dir
            })
          },
        ],
      )
      runcmd = [
        "systemctl daemon-reload",
        "systemctl start --no-block sts-node.service",
      ]
    })])
  }
}

resource "google_compute_instance_template" "node" {
  for_each = local.nodes

  name_prefix  = "${local.prefix}-${each.key}-"
  machine_type = var.machine_type
  region       = local.region
  description  = "mock-sts ${var.environment} ${each.key}, image ${var.image_tag}"

  # The boot disk: Container-Optimized OS, under the project key.
  disk {
    boot         = true
    source_image = data.google_compute_image.cos.self_link
    disk_type    = "pd-balanced"
    disk_size_gb = var.boot_disk_gib
    auto_delete  = true
    disk_encryption_key {
      kms_key_self_link = data.google_kms_crypto_key.main.id
    }
  }

  # THE UPLOAD DISK (#214 on AWS): blank, under the project key, deleted
  # with the instance. Its device name is how sts-disk finds it
  # (/dev/disk/by-id/google-risk-uploads).
  disk {
    boot         = false
    device_name  = local.risk_upload_disk
    disk_type    = "pd-balanced"
    disk_size_gb = var.risk_upload_volume_gib
    auto_delete  = true
    disk_encryption_key {
      kms_key_self_link = data.google_kms_crypto_key.main.id
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.nodes.id
    # An ephemeral external address, for egress with no NAT (network.tf).
    access_config {
      network_tier = "PREMIUM"
    }
  }

  service_account {
    email  = data.google_service_account.nodes.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    user-data                 = local.cloud_init[each.key]
    google-logging-enabled    = "true"
    google-monitoring-enabled = "true"
    enable-oslogin            = "TRUE"
    block-project-ssh-keys    = "TRUE"
  }

  labels = {
    node = each.key
  }

  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = !local.public_name || var.acme_email != ""
      error_message = "public_hostname needs acme_email: the ACME account's contact address."
    }
    # A cell's name is in Route 53 (#97); its ACME challenge is delegated
    # into dns_zone_name by CNAME (deploy/multicloud/interconnect).
    precondition {
      condition     = !local.public_name || local.multi || endswith(var.public_hostname, ".${var.dns_zone_name}")
      error_message = "public_hostname must be a name inside dns_zone_name."
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.nodes]
}

locals {
  # Five minutes before autohealing judges a new node: the init units, the
  # image pulls and the service's own start (AWS: the grace period, 300 s).
  mig_initial_delay_sec = 300
}

# node-a, alone, until it is STABLE (the cold-start ordering in the header).
# Two resources rather than one `for_each`, as AWS has `first` and `others`:
# a `depends_on` cannot order the members of one `for_each`.
resource "google_compute_instance_group_manager" "first" {
  name               = "${local.prefix}-node-a"
  zone               = local.zones[0]
  base_instance_name = "${local.prefix}-node-a"
  # 0 in a new cell's `base` phase (#97), before the global tier exists.
  target_size = local.full ? 1 : 0

  version {
    instance_template = google_compute_instance_template.node["node-a"].self_link_unique
  }

  auto_healing_policies {
    health_check      = google_compute_region_health_check.https.id
    initial_delay_sec = local.mig_initial_delay_sec
  }

  # One instance per group: replacing it means stopping it first, and the
  # name is kept (AWS: minimum healthy 0, maximum 100).
  update_policy {
    type                  = "PROACTIVE"
    minimal_action        = "REPLACE"
    replacement_method    = "RECREATE"
    max_surge_fixed       = 0
    max_unavailable_fixed = 1
  }

  wait_for_instances        = true
  wait_for_instances_status = "STABLE"

  depends_on = [
    google_compute_firewall.health_checks,
    google_compute_firewall.egress_https,
    google_compute_firewall.egress_database,
    google_compute_forwarding_rule.database,
    google_sql_database.sts,
    google_sql_user.master,
    google_secret_manager_secret_version.main,
  ]

  timeouts {
    create = "30m"
    update = "30m"
  }
}

resource "google_compute_instance_group_manager" "others" {
  for_each = { for k, v in local.nodes : k => v if k != "node-a" }

  name               = "${local.prefix}-${each.key}"
  zone               = local.zones[each.value]
  base_instance_name = "${local.prefix}-${each.key}"
  # 0 in a new cell's `base` phase (#97), before the global tier exists.
  target_size = local.full ? 1 : 0

  version {
    instance_template = google_compute_instance_template.node[each.key].self_link_unique
  }

  auto_healing_policies {
    health_check      = google_compute_region_health_check.https.id
    initial_delay_sec = local.mig_initial_delay_sec
  }

  update_policy {
    type                  = "PROACTIVE"
    minimal_action        = "REPLACE"
    replacement_method    = "RECREATE"
    max_surge_fixed       = 0
    max_unavailable_fixed = 1
  }

  wait_for_instances        = true
  wait_for_instances_status = "STABLE"

  depends_on = [google_compute_instance_group_manager.first]

  timeouts {
    create = "30m"
    update = "30m"
  }
}

locals {
  # Every node's instance group, by node name: the load balancer's backends.
  node_groups = merge(
    { "node-a" = google_compute_instance_group_manager.first.instance_group },
    { for k, m in google_compute_instance_group_manager.others : k => m.instance_group },
  )
}
