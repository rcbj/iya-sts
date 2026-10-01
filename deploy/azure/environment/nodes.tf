# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THREE mock-sts NODES, ONE SCALE SET PER AVAILABILITY ZONE
# (deploy/aws/environment/ecs.tf, deploy/gcp/environment/nodes.tf).
#
# WHY VMs. Fargate's nearest Azure counterparts are Container Apps and
# Container Instances. Container Apps terminates or proxies what it
# publishes; Container Instances has no zonal load-balanced service. Neither
# gives LDAP on 389 and 636, the KDC on 88, SPIFFE's gRPC and a client
# certificate reaching the node through a load balancer that follows its
# instances. AKS would, and is a cluster to keep. So a node is a VM on
# UBUNTU 24.04 LTS — Canonical's image, security updates applied by
# unattended-upgrades, which is Azure's nearest to Container-Optimized OS —
# running the same containers AWS's task definition runs, as systemd units
# cloud-init writes (units/).
#
# WHY A SCALE SET PER ZONE, EACH OF ONE INSTANCE: GCP's managed instance
# group per zone, for its reasons — one node per zone by construction, and
# node-a made first, which orders the cold start (cluster/CLAUDE.md) and makes
# node-a's schema-init the first. A scale set (Flexible orchestration) rather
# than a bare VM because it REPAIRS: the Application Health extension asks
# the node's own /healthcheck, and a node that fails it past the grace
# period is replaced, as ECS replaced an unhealthy task.
#
# EACH VM RUNS, IN ORDER (units/):
#   sts-disk      the upload disk, mounted and emptied
#   sts-registry  Docker's login to the registry, with the VM's identity
#   sts-secrets   Key Vault → env files on a tmpfs (ECS `secrets`)
#   sts-cert      the ACME certificate (only with a public name; AWS cert-init)
#   sts-schema    postgres/schema.sql as the administrator (AWS schema-init)
#   sts-global-schema   the same against the global writer (a primary cell)
#   sts-node      mock-sts itself, restarted by systemd if it exits
#
# A NEW IMAGE IS A NEW SCALE SET. A Flexible scale set's instances keep the
# model they were made with, so a changed image, environment or unit would
# reach a node only when it was next replaced; instead each scale set is
# REPLACED when its node's cloud-init changes (`replace_triggered_by`) —
# destroyed, then made again, which is AWS's minimum healthy percent of 0,
# and node-a before the others.
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

    # NO PROXY HEADER: a pass-through load balancer delivers the client's
    # own packets (lb.tf), so the peer IS the client and no proxy is trusted.
    STS_PROXY_PROTOCOL  = "off"
    STS_TRUSTED_PROXIES = ""

    # The key-encryption key and the database password, from Key Vault
    # through common/secrets.js — the path issue #51 exists to exercise, on
    # the `azure` provider. DefaultAzureCredential finds the VM's managed
    # identity; naming its client id means it never has to guess. The rest
    # arrive in the env file (secrets.tf).
    AZURE_CLIENT_ID                = data.azurerm_user_assigned_identity.nodes.client_id
    STS_KEYS_KEK_PROVIDER          = "azure"
    STS_KEYS_KEK_VAULT             = local.vault_uri
    STS_KEYS_KEK_REF               = "kek"
    STS_DATABASE_PASSWORD_PROVIDER = "azure"
    STS_DATABASE_PASSWORD_REF      = "db-app-password"

    # No password in the URL. The host is the server's own name, mapped to
    # the private endpoint inside the container, so the certificate's name
    # matches (database.tf); the certificate chains to a public root the
    # node already trusts.
    STS_DATABASE_URL                     = "postgres://${local.db_app_user}@${local.db_hostname}:${local.db_port}/${local.db_name}?sslmode=require"
    STS_DATABASE_TLS_REJECT_UNAUTHORIZED = "true"

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
    # A CELL'S CONTRACT WITH THE SERVICE (cells.tf); empty otherwise.
    local.cell_environment,
  var.extra_environment)

  # `KEY=<secret name>` pairs, comma-separated, for node-init's secrets.sh.
  node_secret_map          = join(",", [for k, v in local.node_secret_env : "${k}=${v}"])
  schema_secret_map        = join(",", [for k, v in local.schema_secret_env : "${k}=${v}"])
  global_schema_secret_map = join(",", [for k, v in local.global_schema_secret_env : "${k}=${v}"])
  global_schema            = local.global_schema_secret_map != ""

  node_requires = join(" ", concat(
    ["sts-disk.service", "sts-secrets.service", "sts-schema.service"],
    local.public_name ? ["sts-cert.service"] : [],
    local.global_schema ? ["sts-global-schema.service"] : [],
  ))

  # EVERY PORT, 1:1 — the load balancer translates (lb.tf) — and the
  # inter-cell listener behind its internal load balancer.
  node_ports = join(" \\\n  ", concat(
    [for p in sort(distinct([for q in values(local.all_ports) : q.container])) : "-p ${p}:${p}"],
    local.multi ? ["-p ${local.intercell_port}:${local.intercell_port}"] : [],
  ))

  # --add-host FOR EVERY PRIVATE NAME A CONTAINER DIALS BY A NAME ITS PEER'S
  # CERTIFICATE CARRIES: the cell database; and in a cell the global writer
  # and this cell's replica of it, and every other cell's inter-cell load
  # balancer (cells.tf's formula). No private DNS zone anywhere.
  global_hosts = local.multi && local.full ? distinct([
    "--add-host ${local.global.writer_host}:${local.cell_private[var.primary_cell].global_db_ip}",
    "--add-host ${local.global.read_host}:${local.cell_private[var.cell].global_db_ip}",
  ]) : []

  extra_hosts = join(" \\\n  ", concat(
    ["--add-host ${local.db_hostname}:${local.db_endpoint_ip}"],
    local.global_hosts,
    [for id in sort(keys(local.peers)) : "--add-host ${local.cell_private[id].intercell_host}:${local.cell_private[id].intercell_ip}"],
  ))

  unit_files = {
    for node, i in local.nodes : node => merge({
      "sts-disk.service"     = templatefile("${path.module}/units/sts-disk.service.tftpl", {})
      "sts-registry.service" = templatefile("${path.module}/units/sts-registry.service.tftpl", {})
      "sts-secrets.service" = templatefile("${path.module}/units/sts-secrets.service.tftpl", {
        run_dir                  = local.host_run_dir
        init_image               = local.init_image
        vault_url                = local.vault_uri
        client_id                = data.azurerm_user_assigned_identity.nodes.client_id
        node_secret_map          = local.node_secret_map
        schema_secret_map        = local.schema_secret_map
        global_schema_secret_map = local.global_schema_secret_map
      })
      "sts-schema.service" = templatefile("${path.module}/units/sts-schema.service.tftpl", {
        run_dir      = local.host_run_dir
        schema_image = local.schema_image
        db_host      = local.db_hostname
        db_address   = local.db_endpoint_ip
        db_port      = local.db_port
        db_name      = local.db_name
        db_user      = local.db_master_user
        db_app_user  = local.db_app_user
        sslmode      = var.schema_init_sslmode
      })
      "sts-node.service" = templatefile("${path.module}/units/sts-node.service.tftpl", {
        node             = node
        environment      = local.unit
        requires         = local.node_requires
        run_dir          = local.host_run_dir
        image            = local.service_image
        extra_hosts      = local.extra_hosts
        ports            = local.node_ports
        upload_host      = local.host_upload_dir
        upload_container = local.risk_upload_dir
        # READ-ONLY: the node reads the certificate and must never be able
        # to change it.
        tls_mount = local.public_name ? "-v ${local.host_tls_dir}:${local.container_tls}:ro" : ""
      })
      }, local.public_name ? {
      "sts-cert.service" = templatefile("${path.module}/units/sts-cert.service.tftpl", {
        init_image      = local.init_image
        tls_dir         = local.host_tls_dir
        vault_url       = local.vault_uri
        tls_secret      = "tls"
        hostname        = var.public_hostname
        alt_names       = local.cell_console_host
        issuer          = node == "node-a" ? "true" : "false"
        acme_server     = var.acme_server
        acme_email      = var.acme_email
        renew_days      = var.acme_renew_days
        client_id       = data.azurerm_user_assigned_identity.nodes.client_id
        subscription_id = var.subscription_id
        dns_zone_group  = data.azurerm_dns_zone.public[0].resource_group_name
        dns_zone        = data.azurerm_dns_zone.public[0].name
      })
      } : {}, local.global_schema ? {
      "sts-global-schema.service" = templatefile("${path.module}/units/sts-global-schema.service.tftpl", {
        run_dir      = local.host_run_dir
        schema_image = local.schema_image
        db_host      = local.global.writer_host
        db_address   = local.cell_private[var.primary_cell].global_db_ip
        db_port      = local.global.db_port
        db_name      = local.global.db_name
        db_user      = local.db_master_user
        db_app_user  = local.global.db_app_user
        sslmode      = var.schema_init_sslmode
      })
    } : {})
  }

  # CLOUD-INIT: Docker from Ubuntu's archive, the units, the non-secret
  # environment and the two scripts — and then start the node. Written once,
  # at the VM's first boot; the units are ENABLED, so a reboot starts the node
  # again, and /run (the secrets and the certificate) is re-filled because it
  # is a tmpfs the units re-populate. The model is readable by whoever can
  # read the scale set: no secret is in it (secrets.tf).
  cloud_init = {
    for node, i in local.nodes : node => join("\n", ["#cloud-config", yamlencode({
      package_update = true
      packages       = ["docker.io", "jq"]
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
            path        = "/etc/sts/disk.sh"
            permissions = "0700"
            owner       = "root"
            content = templatefile("${path.module}/units/sts-disk.sh.tftpl", {
              mount_dir = local.host_upload_dir
            })
          },
          {
            path        = "/etc/sts/registry-login.sh"
            permissions = "0700"
            owner       = "root"
            content = templatefile("${path.module}/units/registry-login.sh.tftpl", {
              registry  = local.registry_host
              client_id = data.azurerm_user_assigned_identity.nodes.client_id
              tenant_id = data.azurerm_client_config.current.tenant_id
            })
          },
        ],
      )
      runcmd = [
        "systemctl daemon-reload",
        "systemctl enable --now docker.service",
        "systemctl enable sts-node.service",
        "systemctl start --no-block sts-node.service",
      ]
    })])
  }

  # One node model per node: what a change REPLACES the scale set on.
  node_models = { for node, _ in local.nodes : node => sha256(local.cloud_init[node]) }
}

resource "terraform_data" "node_model" {
  for_each = local.nodes
  input    = local.node_models[each.key]
}

# Nobody logs in (no rule admits 22), and Azure refuses a Linux VM with
# neither a password nor a key; this key is made, handed to Azure, and its
# private half is never used.
resource "tls_private_key" "unused" {
  algorithm = "ED25519"
}

locals {
  # THIRTY MINUTES before a node failing its health check is replaced: the
  # first boot installs Docker, pulls three images and runs the init units
  # before the service starts (AWS: the grace period, 300 s, for a task whose
  # image is already on the host; GCP's autohealing delay). The extension's
  # own grace period (below) is the ten minutes a restarted service gets.
  repair_grace = "PT30M"

  health_settings = jsonencode({
    protocol          = "https"
    port              = local.published_ports.https.container
    requestPath       = "/healthcheck"
    intervalInSeconds = 10
    numberOfProbes    = 3
    gracePeriod       = 600
  })

  monitor_settings = jsonencode({
    authentication = {
      managedIdentity = {
        identifier-name  = "mi_res_id"
        identifier-value = data.azurerm_user_assigned_identity.nodes.id
      }
    }
  })

  lb_pools = concat(
    [azurerm_lb_backend_address_pool.nodes.id],
    local.multi ? [azurerm_lb_backend_address_pool.intercell[0].id] : [],
  )
}

# node-a, alone, first (the cold-start ordering in the header). Two
# resources rather than one `for_each`, as AWS has `first` and `others`: a
# `depends_on` cannot order the members of one `for_each`.
resource "azurerm_orchestrated_virtual_machine_scale_set" "first" {
  name                = "${local.prefix}-node-a"
  location            = local.region
  resource_group_name = data.azurerm_resource_group.unit.name
  sku_name            = var.vm_size
  # 0 in a new cell's `base` phase, before the global tier exists.
  instances                   = local.full ? 1 : 0
  platform_fault_domain_count = 1
  zones                       = [local.zones[local.nodes["node-a"]]]

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  os_profile {
    custom_data = base64gzip(local.cloud_init["node-a"])
    linux_configuration {
      admin_username                  = "stsadmin"
      disable_password_authentication = true
      provision_vm_agent              = true
      admin_ssh_key {
        username   = "stsadmin"
        public_key = tls_private_key.unused.public_key_openssh
      }
    }
  }

  os_disk {
    caching                = "ReadWrite"
    storage_account_type   = "StandardSSD_LRS"
    disk_size_gb           = var.os_disk_gib
    disk_encryption_set_id = data.azurerm_disk_encryption_set.data.id
  }

  # THE UPLOAD DISK (#214 on AWS): blank, under the region's key, deleted
  # with the instance, at LUN 0 (units/sts-disk.sh.tftpl).
  data_disk {
    lun                    = 0
    caching                = "None"
    create_option          = "Empty"
    disk_size_gb           = var.risk_upload_volume_gib
    storage_account_type   = "StandardSSD_LRS"
    disk_encryption_set_id = data.azurerm_disk_encryption_set.data.id
  }

  network_interface {
    name    = "nic"
    primary = true
    ip_configuration {
      name                                   = "ipconfig"
      primary                                = true
      subnet_id                              = azurerm_subnet.nodes.id
      load_balancer_backend_address_pool_ids = local.lb_pools
    }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [data.azurerm_user_assigned_identity.nodes.id]
  }

  extension {
    name                               = "health"
    publisher                          = "Microsoft.ManagedServices"
    type                               = "ApplicationHealthLinux"
    type_handler_version               = "2.0"
    auto_upgrade_minor_version_enabled = true
    settings                           = local.health_settings
  }

  extension {
    name                               = "monitor"
    publisher                          = "Microsoft.Azure.Monitor"
    type                               = "AzureMonitorLinuxAgent"
    type_handler_version               = "1.0"
    auto_upgrade_minor_version_enabled = true
    settings                           = local.monitor_settings
  }

  automatic_instance_repair {
    enabled      = true
    grace_period = local.repair_grace
    action       = "Replace"
  }

  boot_diagnostics {}

  tags = merge(local.tags, { Node = "node-a" })

  lifecycle {
    replace_triggered_by = [terraform_data.node_model["node-a"]]
    precondition {
      condition     = !local.public_name || var.acme_email != ""
      error_message = "public_hostname needs acme_email: the ACME account's contact address."
    }
    precondition {
      condition     = !local.public_name || endswith(var.public_hostname, ".${var.dns_zone_name}")
      error_message = "public_hostname must be a name inside dns_zone_name."
    }
  }

  depends_on = [
    azurerm_subnet_network_security_group_association.nodes,
    azurerm_network_security_rule.rules,
    azurerm_lb_rule.published,
    azurerm_lb_outbound_rule.nodes,
    azurerm_lb_rule.intercell,
    azurerm_private_endpoint.database,
    azurerm_postgresql_flexible_server_database.sts,
    azurerm_postgresql_flexible_server_configuration.tls,
    azurerm_key_vault_secret.main,
  ]

  timeouts {
    create = "45m"
    update = "45m"
  }
}

resource "azurerm_orchestrated_virtual_machine_scale_set" "others" {
  for_each = { for k, v in local.nodes : k => v if k != "node-a" }

  name                        = "${local.prefix}-${each.key}"
  location                    = local.region
  resource_group_name         = data.azurerm_resource_group.unit.name
  sku_name                    = var.vm_size
  instances                   = local.full ? 1 : 0
  platform_fault_domain_count = 1
  zones                       = [local.zones[each.value]]

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  os_profile {
    custom_data = base64gzip(local.cloud_init[each.key])
    linux_configuration {
      admin_username                  = "stsadmin"
      disable_password_authentication = true
      provision_vm_agent              = true
      admin_ssh_key {
        username   = "stsadmin"
        public_key = tls_private_key.unused.public_key_openssh
      }
    }
  }

  os_disk {
    caching                = "ReadWrite"
    storage_account_type   = "StandardSSD_LRS"
    disk_size_gb           = var.os_disk_gib
    disk_encryption_set_id = data.azurerm_disk_encryption_set.data.id
  }

  data_disk {
    lun                    = 0
    caching                = "None"
    create_option          = "Empty"
    disk_size_gb           = var.risk_upload_volume_gib
    storage_account_type   = "StandardSSD_LRS"
    disk_encryption_set_id = data.azurerm_disk_encryption_set.data.id
  }

  network_interface {
    name    = "nic"
    primary = true
    ip_configuration {
      name                                   = "ipconfig"
      primary                                = true
      subnet_id                              = azurerm_subnet.nodes.id
      load_balancer_backend_address_pool_ids = local.lb_pools
    }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [data.azurerm_user_assigned_identity.nodes.id]
  }

  extension {
    name                               = "health"
    publisher                          = "Microsoft.ManagedServices"
    type                               = "ApplicationHealthLinux"
    type_handler_version               = "2.0"
    auto_upgrade_minor_version_enabled = true
    settings                           = local.health_settings
  }

  extension {
    name                               = "monitor"
    publisher                          = "Microsoft.Azure.Monitor"
    type                               = "AzureMonitorLinuxAgent"
    type_handler_version               = "1.0"
    auto_upgrade_minor_version_enabled = true
    settings                           = local.monitor_settings
  }

  automatic_instance_repair {
    enabled      = true
    grace_period = local.repair_grace
    action       = "Replace"
  }

  boot_diagnostics {}

  tags = merge(local.tags, { Node = each.key })

  lifecycle {
    replace_triggered_by = [terraform_data.node_model[each.key]]
  }

  depends_on = [azurerm_orchestrated_virtual_machine_scale_set.first]

  timeouts {
    create = "45m"
    update = "45m"
  }
}

locals {
  node_scale_sets = merge(
    { "node-a" = azurerm_orchestrated_virtual_machine_scale_set.first },
    azurerm_orchestrated_virtual_machine_scale_set.others,
  )
}

# THE CONTAINER LOGS: each node's agent, associated with its region's syslog
# rule (../foundation/modules/region). The workspace is the region's own, so
# a cell's logs stay in it.
resource "azurerm_monitor_data_collection_rule_association" "syslog" {
  for_each                = local.nodes
  name                    = "${local.prefix}-${each.key}-syslog"
  target_resource_id      = local.node_scale_sets[each.key].id
  data_collection_rule_id = data.azurerm_monitor_data_collection_rule.syslog.id
  description             = "mock-sts ${local.unit} ${each.key}: container logs"
}
