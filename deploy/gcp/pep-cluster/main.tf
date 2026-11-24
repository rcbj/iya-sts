# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A REMOTE XACML PEP CLUSTER ON GCP, AS AN ENVIRONMENT OF ITS OWN (#1284).
#
# deploy/aws/pep-cluster/ is the design and its CLAUDE.md section the
# argument: the remote PEP needs no clustering mechanism (#676), so this is
# the PEP image on VMs behind a load balancer with a WAF in front, reaching
# the identity service at `idp_url` over the internet, reading nothing of any
# iya-sts environment (rcbj, 2026-11-23). What each AWS piece became:
#
#   AWS                                  GCP (this stack)
#   ECS service of one task per member   a ZONAL managed instance group of
#                                        size one per member, on COS
#   one ECS service (shared)             one REGIONAL group, optional autoscaler
#   ALB + regional AWS WAF               a global external Application Load
#                                        Balancer + a Cloud Armor policy
#   ACM certificate                      a Google-managed certificate
#   ALB cookie stickiness (proxy)        GENERATED_COOKIE affinity
#   decision API on port 9443            on `decision_hostname`, port 443:
#                                        the global load balancer serves 80
#                                        and 443 only
#   notify port per member               a notify NAME per member,
#                                        `<member>.<public_hostname>`
#   NAT gateway, one EIP                 Cloud NAT on one reserved address
#   ECS `secrets` from Secrets Manager   node-init's sts-secret-files, Secret
#                                        Manager → files on /run (a tmpfs)
#   execution role, no task role         the foundation's `iya-sts-pep-<env>`
#                                        account (the deployer makes none)
#
#   browser ─443─▶ Cloud Armor ▶ ALB (managed cert) ─GENERATED_COOKIE─▶ member 9543
#   app     ─443─▶ Cloud Armor ▶ ALB at decision_hostname ────────────▶ member 9443
#   member  ─443─▶ Cloud NAT (egress_ip) ──────────────────────────────▶ idp_url
#
# THE KEYS ARE IN SECRET MANAGER, NEVER IN THIS STATE OR IN METADATA. Each
# member's five secrets, `<prefix>-pep-<cluster>-<member>-<part>`, are made
# and written by provision.sh; this stack looks each up by NAME (metadata
# only) and grants the members' account `secretAccessor` on the four a member
# mounts. On the VM, sts-secret-files reads them into /run/pep — a tmpfs, so
# a reboot keeps nothing — and the PEP container mounts it read-only. Instance
# metadata, which anybody who can describe the VM reads, holds the units and
# the non-secret environment only.
#
# WRITTEN AND CHECKED STATICALLY ONLY (deploy/gcp/CLAUDE.md, *A remote PEP
# cluster*): nothing here has been applied.
# ---------------------------------------------------------------------------

locals {
  prefix = "${var.name}-${var.environment}"

  registry_host   = "${var.region}-docker.pkg.dev"
  registry_url    = "${local.registry_host}/${var.project_id}/${var.name}"
  image           = var.pep_image != "" ? var.pep_image : "${local.registry_url}/${var.name}:pep-${var.image_tag}"
  companion_image = var.companion_image != "" ? var.companion_image : "${local.registry_url}/${var.name}:companion-${var.image_tag}"
  init_image      = "${local.registry_url}/${var.name}:init-${var.image_tag}"

  idp_base = trimsuffix(var.idp_url, "/")
  pdp_url  = "${local.idp_base}${var.realm == "" ? "" : "/realm/${var.realm}"}"

  # THE MEMBERS, named as AWS names them. per-instance: one zonal group of one
  # VM each, spread round the zones. shared: one name for one regional group.
  per_instance = var.credential_mode == "per-instance"
  members = local.per_instance ? {
    for i in range(1, var.instance_count + 1) : "${var.cluster}-pep-${i}" => { n = i }
  } : { "${var.cluster}-pep" = { n = 1 } }
  autoscaling = !local.per_instance && var.autoscaling_max > var.instance_count
  zones       = slice(sort(data.google_compute_zones.available.names), 0, 3)

  # THE NUDGE, by name (variables.tf, `notify_cidrs`).
  notify = length(var.notify_cidrs) > 0
  notify_hosts = local.notify ? {
    for m, v in local.members : m => "${m}.${var.public_hostname}"
  } : {}

  # The PEP's own ports, on the VM (Docker publishes them 1:1).
  pep_https_port = 9443
  pep_proxy_port = 9543
  companion_port = 9700

  # WHERE THE KEYS LAND: /run is a tmpfs on Container-Optimized OS.
  pep_dir = "/run/pep"

  # A MEMBER'S SECRETS, each one secret (a PEM value has newlines, which an
  # env file cannot hold — node-init/secret-files.sh). `mounted` is the path
  # under pep_dir the PEP reads; `assertion-cert` is provision.sh's alone
  # (it is what lets the utility recognise a key it already certified).
  secret_parts = {
    "assertion-key"  = { mounted = "pep-assertion.key" }
    "https-cert"     = { mounted = "server/pep-server.crt" }
    "https-key"      = { mounted = "server/pep-server.key" }
    "service-ca"     = { mounted = "service-ca.pem" }
    "assertion-cert" = { mounted = "" }
  }
  member_secrets = merge([
    for m in keys(local.members) : {
      for part, p in local.secret_parts : "${m}/${part}" => {
        member  = m
        part    = part
        mounted = p.mounted
        id      = "${local.prefix}-pep-${var.cluster}-${m}-${part}"
      }
    }
  ]...)

  # What each member's container is told. No secret: those are files.
  member_environment = {
    for m in keys(local.members) : m => merge({
      PEP_PDP_URL          = local.pdp_url
      PEP_NAME             = m
      PEP_CLIENT_ID        = "sts-remote-pep"
      PEP_ASSERTION_KEY    = "${local.pep_dir}/pep-assertion.key"
      PEP_HTTPS_CERT       = "${local.pep_dir}/server/pep-server.crt"
      PEP_HTTPS_KEY        = "${local.pep_dir}/server/pep-server.key"
      PEP_HTTPS_PORT       = tostring(local.pep_https_port)
      PEP_POLL_INTERVAL_MS = tostring(var.poll_interval_ms)
      PEP_LOG_LEVEL        = "info"
      }, local.notify ? {
      # The member's own notify name, on the load balancer's certificate —
      # the name the service checks the notify URL's host against.
      PEP_NOTIFY_URL = "https://${local.notify_hosts[m]}/notify"
    } : {}, var.extra_environment)
  }

  unit_files = {
    for m in keys(local.members) : m => merge({
      "pep-registry.service" = templatefile("${path.module}/units/pep-registry.service.tftpl", {
        registry_host = local.registry_host
      })
      "pep-secrets.service" = templatefile("${path.module}/units/pep-secrets.service.tftpl", {
        pep_dir    = local.pep_dir
        init_image = local.init_image
        secret_files = join(",", [
          for k, s in local.member_secrets :
          "${s.mounted}=${data.google_secret_manager_secret.member[k].id}"
          if s.member == m && s.mounted != ""
        ])
      })
      "xacml-pep.service" = templatefile("${path.module}/units/xacml-pep.service.tftpl", {
        member      = m
        environment = var.environment
        image       = local.image
        pep_dir     = local.pep_dir
        https_port  = local.pep_https_port
        proxy_port  = local.pep_proxy_port
      })
      }, var.companion ? {
      "pep-companion.service" = templatefile("${path.module}/units/pep-companion.service.tftpl", {
        member      = m
        environment = var.environment
        image       = local.companion_image
        port        = local.companion_port
        idp_url     = local.pdp_url
      })
    } : {})
  }

  # CLOUD-INIT, run by COS on every boot: the units and the non-secret
  # environment, then start the PEP (and its companion).
  cloud_init = {
    for m in keys(local.members) : m => join("\n", ["#cloud-config", yamlencode({
      write_files = concat(
        [for name, body in local.unit_files[m] : {
          path        = "/etc/systemd/system/${name}"
          permissions = "0644"
          owner       = "root"
          content     = body
        }],
        [{
          path        = "/etc/pep/pep.env"
          permissions = "0600"
          owner       = "root"
          content     = join("\n", [for k, v in local.member_environment[m] : "${k}=${v}"])
        }],
      )
      runcmd = concat(
        ["systemctl daemon-reload", "systemctl start --no-block xacml-pep.service"],
        var.companion ? ["systemctl start --no-block pep-companion.service"] : [],
      )
    })])
  }
}

# --- What the foundation made ------------------------------------------------

data "google_compute_zones" "available" {
  region = var.region
  status = "UP"
}

data "google_compute_image" "cos" {
  family  = "cos-stable"
  project = "cos-cloud"
}

data "google_kms_key_ring" "main" {
  name     = var.name
  location = var.region
}

data "google_kms_crypto_key" "main" {
  name     = var.name
  key_ring = data.google_kms_key_ring.main.id
}

# The members' account. Not finding it means the PEP environment is not in
# the foundation's `pep_environments`.
data "google_service_account" "pep" {
  account_id = "${var.name}-pep-${var.environment}"
}

data "google_dns_managed_zone" "public" {
  name = replace(var.dns_zone_name, ".", "-")
}

# EACH MEMBER'S SECRETS, BY NAME. Metadata only, and FAILING when one is
# missing, which is the point: run provision.sh first.
data "google_secret_manager_secret" "member" {
  for_each  = local.member_secrets
  secret_id = each.value.id
}

# Reading the four a member mounts, one secret at a time (the foundation
# grants nothing project-wide). `assertion-cert` is provision.sh's alone.
resource "google_secret_manager_secret_iam_member" "member" {
  for_each  = { for k, s in local.member_secrets : k => s if s.mounted != "" }
  secret_id = data.google_secret_manager_secret.member[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = data.google_service_account.pep.member
}

# --- The members -------------------------------------------------------------

resource "google_compute_instance_template" "member" {
  for_each = local.members

  name_prefix  = "${local.prefix}-${each.key}-"
  machine_type = var.machine_type
  region       = var.region
  description  = "iya-sts ${var.environment}: remote PEP ${each.key}, image ${var.image_tag}"

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

  # NO EXTERNAL ADDRESS: in through the load balancer only, out through Cloud
  # NAT only (network.tf).
  network_interface {
    subnetwork = google_compute_subnetwork.members.id
  }

  service_account {
    email  = data.google_service_account.pep.email
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
    member = each.key
  }

  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = endswith(var.public_hostname, ".${var.dns_zone_name}")
      error_message = "public_hostname must be a name inside dns_zone_name."
    }
    precondition {
      condition     = !var.publish_decision_api || (var.decision_hostname != "" && endswith(var.decision_hostname, ".${var.dns_zone_name}") && var.decision_hostname != var.public_hostname)
      error_message = "publish_decision_api needs decision_hostname: a name of its own inside dns_zone_name (the global load balancer serves 443 only, so the decision API is told apart by name)."
    }
    precondition {
      condition     = !(local.per_instance && var.autoscaling_max > 0)
      error_message = "autoscaling_max is for credential_mode = shared: per-instance members are a fixed count, each with its own key."
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.member]
}

# A named port for each backend service: the proxy and the decision API.
locals {
  named_ports = {
    proxy    = local.pep_proxy_port
    decision = local.pep_https_port
  }
}

# PER-INSTANCE: one zonal group of one VM per member. Its update replaces the
# one VM — stops it, then makes the new one — keeping its name, as an
# environment's nodes are replaced (deploy/gcp/environment/nodes.tf).
resource "google_compute_instance_group_manager" "member" {
  for_each = local.per_instance ? local.members : {}

  name               = "${local.prefix}-${each.key}"
  zone               = local.zones[(each.value.n - 1) % length(local.zones)]
  base_instance_name = "${local.prefix}-${each.key}"
  target_size        = 1

  dynamic "named_port" {
    for_each = local.named_ports
    content {
      name = named_port.key
      port = named_port.value
    }
  }

  version {
    instance_template = google_compute_instance_template.member[each.key].self_link_unique
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.member.id
    initial_delay_sec = var.health_check_grace_seconds
  }

  update_policy {
    type                  = "PROACTIVE"
    minimal_action        = "REPLACE"
    replacement_method    = "RECREATE"
    max_surge_fixed       = 0
    max_unavailable_fixed = 1
  }

  depends_on = [
    google_compute_router_nat.main,
    google_compute_firewall.health_checks,
    google_compute_firewall.egress_https,
  ]
}

# SHARED: one regional group of `instance_count` VMs, all one member.
resource "google_compute_region_instance_group_manager" "shared" {
  count = local.per_instance ? 0 : 1

  name                      = "${local.prefix}-${var.cluster}-pep"
  region                    = var.region
  base_instance_name        = "${local.prefix}-${var.cluster}-pep"
  distribution_policy_zones = local.zones
  target_size               = local.autoscaling ? null : var.instance_count

  dynamic "named_port" {
    for_each = local.named_ports
    content {
      name = named_port.key
      port = named_port.value
    }
  }

  version {
    instance_template = google_compute_instance_template.member["${var.cluster}-pep"].self_link_unique
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.member.id
    initial_delay_sec = var.health_check_grace_seconds
  }

  update_policy {
    type                         = "PROACTIVE"
    minimal_action               = "REPLACE"
    instance_redistribution_type = "PROACTIVE"
    max_surge_fixed              = length(local.zones)
    max_unavailable_fixed        = 0
  }

  depends_on = [
    google_compute_router_nat.main,
    google_compute_firewall.health_checks,
    google_compute_firewall.egress_https,
  ]
}

resource "google_compute_region_autoscaler" "shared" {
  count  = local.autoscaling ? 1 : 0
  name   = "${local.prefix}-${var.cluster}-pep"
  region = var.region
  target = google_compute_region_instance_group_manager.shared[0].id

  autoscaling_policy {
    min_replicas    = var.instance_count
    max_replicas    = var.autoscaling_max
    cooldown_period = 120
    cpu_utilization {
      target = var.autoscaling_cpu_target
    }
  }
}

locals {
  # Every group the load balancer's backends name, by member.
  member_groups = local.per_instance ? {
    for m, g in google_compute_instance_group_manager.member : m => g.instance_group
  } : { "${var.cluster}-pep" = google_compute_region_instance_group_manager.shared[0].instance_group }
}
