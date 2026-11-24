# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A REMOTE XACML PEP CLUSTER AS AN ENVIRONMENT OF ITS OWN, ON AZURE (#1284).
#
# deploy/aws/pep-cluster/ is the design and its header the argument; this is
# that environment built from Azure's parts, in deploy/azure's conventions.
# It READS NOTHING OF ANY iya-sts ENVIRONMENT: no remote state, no shared load
# balancer, no shared group. The identity service is `idp_url`, dialled over
# the internet as any customer's deployment would.
#
#   browser ──443──▶ WAF ▶ Application Gateway ─HTTPS, cookie─▶ member 9543
#   app     ──9443─▶ WAF ▶ Application Gateway ─HTTPS──────────▶ member 9443
#   member  ──443──▶ NAT gateway (egress_ip) ───────────────────▶ idp_url
#
# WHAT EACH AWS PIECE BECAME:
#   ALB + regional WAF      Application Gateway WAF_v2 + a WAF policy
#                           (gateway.tf: why, and why the allowlist is a BLOCK)
#   ACM certificate         the vault's `gateway` CERTIFICATE: a Key Vault
#                           self-signed placeholder the foundation makes, then
#                           member 1's ACME certificate (node-init's cert.sh,
#                           RSA), imported as its next version
#   NAT gateway + EIP       a NAT gateway with one static address (network.tf)
#   Fargate service/task    a Flexible scale set per member of ONE VM
#                           (per-instance), or one of N (shared); Ubuntu 24.04
#                           and Docker from Ubuntu's archive, as the nodes
#   ECS `secrets`           pep-secrets.sh: the VM's identity reads the
#                           member's ONE Key Vault secret into /run/pep (a
#                           tmpfs) at every start; nothing secret in custom data
#   ECS deployment          provision.sh restarts a member's VMs after it
#                           writes the member's listener pair
#   Application Auto        Azure Monitor autoscale on the shared scale set
#     Scaling
#   no task role            the members' identity is the foundation's:
#                           read the vault, pull the images, and on member 1
#                           the ACME TXT records and the gateway certificate
#
# WHAT IS DIFFERENT FROM AWS, AND WHY (deploy/azure/CLAUDE.md carries it):
#   * the gateway VERIFIES each member's listener pair (AWS's ALB does not),
#     so it needs the identity service's Root (`member_trust_anchor`) and a
#     SECOND apply after provision.sh's second pass;
#   * the WAF's allowlist is a negated BLOCK, because Application Gateway
#     runs custom rules before managed ones and a custom allow ends evaluation;
#   * the listener certificate is obtained by a MEMBER, because Azure has no
#     free certificate an Application Gateway can present.
# ---------------------------------------------------------------------------

locals {
  prefix = "${var.name}-${var.environment}"
  tags = merge(var.tags, {
    Project     = "STS"
    Environment = var.environment
    PepCluster  = var.cluster
  })

  registry_host   = data.azurerm_container_registry.main.login_server
  image           = var.pep_image != "" ? var.pep_image : "${local.registry_host}/${var.name}:pep-${var.image_tag}"
  companion_image = var.companion_image != "" ? var.companion_image : "${local.registry_host}/${var.name}:companion-${var.image_tag}"
  init_image      = "${local.registry_host}/${var.name}:init-${var.image_tag}"

  idp_base   = trimsuffix(var.idp_url, "/")
  realm_path = var.realm == "" ? "" : "/realm/${var.realm}"
  pdp_url    = "${local.idp_base}${local.realm_path}"

  # THE MEMBERS. per-instance: `<cluster>-pep-1` … `-<n>`, one VM each, in
  # zone ((n-1) % 3) + 1. shared: `<cluster>-pep`, `instance_count` VMs over
  # the three zones. `n` picks the notify port; member n == 1 issues the
  # gateway's certificate. A SHARED scale set's VMs are alike, so every one
  # of them is the issuer: node-init's cert.sh issues only when the bundle is
  # missing or near expiry, but N VMs started at once on a fresh environment
  # can each find it missing and each issue — at most N of Let's Encrypt's
  # five a week. Start a shared environment at one VM if that matters.
  per_instance = var.credential_mode == "per-instance"
  members = local.per_instance ? {
    for i in range(1, var.instance_count + 1) : "${var.cluster}-pep-${i}" => {
      n         = i
      instances = 1
      zones     = [tostring(((i - 1) % 3) + 1)]
      issuer    = i == 1
    }
    } : {
    "${var.cluster}-pep" = {
      n         = 1
      instances = var.instance_count
      zones     = ["1", "2", "3"]
      issuer    = true
    }
  }

  autoscale = !local.per_instance && var.autoscale_max > var.instance_count
  notify    = length(var.notify_cidrs) > 0
  notify_ports = local.notify ? {
    for m, v in local.members : m => var.notify_port_base + v.n
  } : {}

  # The PEP's own ports, on the VM (host networking).
  pep_https_port = 9443
  pep_proxy_port = 9543
  companion_port = 9700

  # Where pep-secrets writes the keys (a tmpfs) and sts-cert the bundle.
  run_dir  = "/run/pep"
  acme_dir = "/run/pep-acme"

  vault_uri = trimsuffix(data.azurerm_key_vault.pep.vault_uri, "/")

  pep_environment = {
    for m, v in local.members : m => merge({
      PEP_PDP_URL          = local.pdp_url
      PEP_NAME             = m
      PEP_CLIENT_ID        = "sts-remote-pep"
      PEP_ASSERTION_KEY    = "${local.run_dir}/pep-assertion.key"
      PEP_HTTPS_CERT       = "${local.run_dir}/server/pep-server.crt"
      PEP_HTTPS_KEY        = "${local.run_dir}/server/pep-server.key"
      PEP_HTTPS_PORT       = tostring(local.pep_https_port)
      PEP_POLL_INTERVAL_MS = tostring(var.poll_interval_ms)
      PEP_LOG_LEVEL        = "info"
      }, local.notify ? {
      # THE NUDGE THROUGH THE GATEWAY, to this member's own port, at the
      # name on the gateway's certificate — the host the service checks.
      PEP_NOTIFY_URL = "https://${var.public_hostname}:${local.notify_ports[m]}/notify"
    } : {}, var.extra_environment)
  }

  companion_environment = {
    COMPANION_PORT       = tostring(local.companion_port)
    COMPANION_PUBLIC_URL = "http://127.0.0.1:${local.companion_port}"
    # The service, at its public name, verified against the image's roots.
    COMPANION_STS_URL           = local.pdp_url
    COMPANION_STS_PUBLIC_URL    = local.pdp_url
    COMPANION_KRB5_SERVICE_PORT = "off"
  }

  # Each member's unit files.
  unit_files = {
    for m, v in local.members : m => merge({
      # The nodes' own registry login, word for word: one copy of it.
      "sts-registry.service" = templatefile("${path.module}/../environment/units/sts-registry.service.tftpl", {})
      "pep-secrets.service"  = templatefile("${path.module}/units/pep-secrets.service.tftpl", {})
      "pep-member.service" = templatefile("${path.module}/units/pep-member.service.tftpl", {
        member      = m
        environment = var.environment
        run_dir     = local.run_dir
        image       = local.image
        wants       = v.issuer ? "pep-cert.service" : ""
      })
      }, v.issuer ? {
      "pep-cert.service" = templatefile("${path.module}/units/pep-cert.service.tftpl", {
        init_image      = local.init_image
        tls_dir         = local.acme_dir
        vault_url       = local.vault_uri
        hostname        = var.public_hostname
        acme_server     = var.acme_server
        acme_email      = var.acme_email
        renew_days      = var.acme_renew_days
        client_id       = data.azurerm_user_assigned_identity.members.client_id
        subscription_id = var.subscription_id
        dns_zone_group  = data.azurerm_dns_zone.public.resource_group_name
        dns_zone        = data.azurerm_dns_zone.public.name
      })
      } : {}, var.companion ? {
      "pep-companion.service" = templatefile("${path.module}/units/pep-companion.service.tftpl", {
        environment = var.environment
        image       = local.companion_image
      })
    } : {})
  }

  # CLOUD-INIT: Docker and jq from Ubuntu's archive, the units, the
  # non-secret environment and the scripts — then start the member. NO
  # SECRET IS IN IT: the model is readable by whoever can read the scale set.
  cloud_init = {
    for m, v in local.members : m => join("\n", ["#cloud-config", yamlencode({
      package_update = true
      packages       = ["docker.io", "jq"]
      write_files = concat(
        [for name, body in local.unit_files[m] : {
          path        = "/etc/systemd/system/${name}"
          permissions = "0644"
          owner       = "root"
          content     = body
        }],
        [
          {
            path        = "/etc/pep/pep.env"
            permissions = "0600"
            owner       = "root"
            content     = join("\n", [for k, val in local.pep_environment[m] : "${k}=${val}"])
          },
          {
            path        = "/etc/pep/secrets.sh"
            permissions = "0700"
            owner       = "root"
            content = templatefile("${path.module}/units/pep-secrets.sh.tftpl", {
              vault_url = local.vault_uri
              secret    = "pep-${var.cluster}-${m}"
              client_id = data.azurerm_user_assigned_identity.members.client_id
              run_dir   = local.run_dir
            })
          },
          {
            path        = "/etc/sts/registry-login.sh"
            permissions = "0700"
            owner       = "root"
            content = templatefile("${path.module}/../environment/units/registry-login.sh.tftpl", {
              registry  = local.registry_host
              client_id = data.azurerm_user_assigned_identity.members.client_id
              tenant_id = data.azurerm_client_config.current.tenant_id
            })
          },
        ],
        v.issuer ? [{
          path        = "/etc/pep/gateway-cert.sh"
          permissions = "0700"
          owner       = "root"
          content = templatefile("${path.module}/units/gateway-cert.sh.tftpl", {
            vault_url = local.vault_uri
            client_id = data.azurerm_user_assigned_identity.members.client_id
            tls_dir   = local.acme_dir
          })
        }] : [],
        var.companion ? [{
          path        = "/etc/pep/companion.env"
          permissions = "0600"
          owner       = "root"
          content     = join("\n", [for k, val in local.companion_environment : "${k}=${val}"])
        }] : [],
      )
      runcmd = concat([
        "systemctl daemon-reload",
        "systemctl enable --now docker.service",
        "systemctl enable pep-member.service",
        "systemctl start --no-block pep-member.service",
        ], var.companion ? [
        "systemctl enable pep-companion.service",
        "systemctl start --no-block pep-companion.service",
      ] : [])
    })])
  }

  member_models = { for m, _ in local.members : m => sha256(local.cloud_init[m]) }

  # The gateway pools a member's NIC joins: the proxy's, the decision API's,
  # and its own notify pool.
  member_pools = {
    for m, _ in local.members : m => concat(
      [local.pool_ids[local.proxy_pool]],
      var.publish_decision_api ? [local.pool_ids[local.api_pool]] : [],
      local.notify ? [local.pool_ids["notify-${m}"]] : [],
    )
  }

  # THE MEMBER'S OWN LIVENESS, asked by the Application Health extension on
  # the VM: its 9443 /healthcheck. Three failures after the repair grace
  # replace the VM (deploy/azure/environment/nodes.tf's arrangement); the
  # grace is long because a member has no 9443 until provision.sh's second
  # pass (variables.tf, `repair_grace`).
  health_settings = jsonencode({
    protocol          = "https"
    port              = local.pep_https_port
    requestPath       = "/healthcheck"
    intervalInSeconds = 10
    numberOfProbes    = 3
    gracePeriod       = 600
  })
}

# ---------------------------------------------------------------------------
# THE FOUNDATION'S RESOURCES, FOUND BY NAME (../foundation/pep_units.tf).
# Not finding one means the foundation does not list this PEP environment.
# ---------------------------------------------------------------------------
data "azurerm_resource_group" "pep" {
  name = local.prefix
}

data "azurerm_user_assigned_identity" "members" {
  name                = "${local.prefix}-members"
  resource_group_name = data.azurerm_resource_group.pep.name
}

data "azurerm_user_assigned_identity" "gateway" {
  name                = "${local.prefix}-gateway"
  resource_group_name = data.azurerm_resource_group.pep.name
}

# The vault's name is ../foundation/pep_units.tf's formula; keep them in step.
data "azurerm_key_vault" "pep" {
  name                = "mp${var.environment}-${substr(sha1("${var.subscription_id}/${var.name}/pep/${var.environment}"), 0, 4)}"
  resource_group_name = data.azurerm_resource_group.pep.name
}

# Its PUBLIC half and ids only: this data source reads no private key.
data "azurerm_key_vault_certificate" "gateway" {
  name         = "gateway"
  key_vault_id = data.azurerm_key_vault.pep.id
}

data "azurerm_container_registry" "main" {
  name                = "${replace(var.name, "-", "")}${substr(sha1(var.subscription_id), 0, 8)}"
  resource_group_name = "${var.name}-foundation"
}

data "azurerm_dns_zone" "public" {
  name                = var.dns_zone_name
  resource_group_name = "${var.name}-foundation"
}

# Nobody logs in (no rule admits 22), and Azure refuses a Linux VM with
# neither a password nor a key; this key is made, handed to Azure, and its
# private half is never used (the nodes' arrangement).
resource "tls_private_key" "unused" {
  algorithm = "ED25519"
}

resource "terraform_data" "member_model" {
  for_each = local.members
  input    = local.member_models[each.key]
}

# --- The members --------------------------------------------------------------

resource "azurerm_orchestrated_virtual_machine_scale_set" "member" {
  for_each = local.members

  name                        = "${local.prefix}-${each.key}"
  location                    = var.region
  resource_group_name         = data.azurerm_resource_group.pep.name
  sku_name                    = var.vm_size
  instances                   = each.value.instances
  platform_fault_domain_count = 1
  zones                       = each.value.zones

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  os_profile {
    custom_data = base64gzip(local.cloud_init[each.key])
    linux_configuration {
      admin_username                  = "pepadmin"
      disable_password_authentication = true
      provision_vm_agent              = true
      admin_ssh_key {
        username   = "pepadmin"
        public_key = tls_private_key.unused.public_key_openssh
      }
    }
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  # NO PUBLIC ADDRESS: in through the gateway, out through the NAT gateway.
  network_interface {
    name    = "nic"
    primary = true
    ip_configuration {
      name                                         = "ipconfig"
      primary                                      = true
      subnet_id                                    = azurerm_subnet.members.id
      application_gateway_backend_address_pool_ids = local.member_pools[each.key]
    }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [data.azurerm_user_assigned_identity.members.id]
  }

  extension {
    name                               = "health"
    publisher                          = "Microsoft.ManagedServices"
    type                               = "ApplicationHealthLinux"
    type_handler_version               = "2.0"
    auto_upgrade_minor_version_enabled = true
    settings                           = local.health_settings
  }

  automatic_instance_repair {
    enabled      = true
    grace_period = var.repair_grace
    action       = "Replace"
  }

  boot_diagnostics {}

  tags = merge(local.tags, { Member = each.key })

  lifecycle {
    # A Flexible scale set's VMs keep the model they were made with, so a
    # changed image or setting REPLACES the scale set (the nodes' rule).
    replace_triggered_by = [terraform_data.member_model[each.key]]
    # Azure Monitor autoscale owns a shared scale set's count.
    ignore_changes = [instances]

    precondition {
      condition     = !(local.per_instance && var.autoscale_max > 0)
      error_message = "autoscale_max is for credential_mode = shared: per-instance members are a fixed count, each with its own key."
    }
    precondition {
      condition     = var.acme_email != ""
      error_message = "acme_email is required: the ACME account's contact address, for the gateway's certificate."
    }
  }

  depends_on = [
    azurerm_subnet_nat_gateway_association.members,
    azurerm_subnet_network_security_group_association.members,
    azurerm_network_security_rule.members,
  ]
}

# --- Autoscale (shared only) --------------------------------------------------

resource "azurerm_monitor_autoscale_setting" "shared" {
  count               = local.autoscale ? 1 : 0
  name                = "${local.prefix}-${var.cluster}-cpu"
  location            = var.region
  resource_group_name = data.azurerm_resource_group.pep.name
  target_resource_id  = azurerm_orchestrated_virtual_machine_scale_set.member["${var.cluster}-pep"].id
  tags                = local.tags

  profile {
    name = "cpu"
    capacity {
      default = var.instance_count
      minimum = var.instance_count
      maximum = var.autoscale_max
    }

    rule {
      metric_trigger {
        metric_name        = "Percentage CPU"
        metric_resource_id = azurerm_orchestrated_virtual_machine_scale_set.member["${var.cluster}-pep"].id
        time_grain         = "PT1M"
        statistic          = "Average"
        time_window        = "PT5M"
        time_aggregation   = "Average"
        operator           = "GreaterThan"
        threshold          = var.autoscale_cpu_target
      }
      scale_action {
        direction = "Increase"
        type      = "ChangeCount"
        value     = "1"
        cooldown  = "PT5M"
      }
    }

    rule {
      metric_trigger {
        metric_name        = "Percentage CPU"
        metric_resource_id = azurerm_orchestrated_virtual_machine_scale_set.member["${var.cluster}-pep"].id
        time_grain         = "PT1M"
        statistic          = "Average"
        time_window        = "PT10M"
        time_aggregation   = "Average"
        operator           = "LessThan"
        threshold          = floor(var.autoscale_cpu_target / 2)
      }
      scale_action {
        direction = "Decrease"
        type      = "ChangeCount"
        value     = "1"
        cooldown  = "PT10M"
      }
    }
  }
}
