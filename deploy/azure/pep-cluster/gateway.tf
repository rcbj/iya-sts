# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# APPLICATION GATEWAY WAF_v2 IN FRONT OF THE MEMBERS (AWS: the ALB and its
# regional WAF, deploy/aws/pep-cluster/alb.tf and waf.tf).
#
# WHY APPLICATION GATEWAY. Azure's WAF attaches to Application Gateway, Front
# Door and Application Gateway for Containers, never to the Standard Load
# Balancer the service's own nodes use. Front Door is global and the edge
# would be one more party between the browser and a sign-in; Application
# Gateway is the regional reverse proxy with a WAF, which is what AWS's ALB
# and WAF are.
#
#   443             the reverse proxy (the members' 9543), COOKIE AFFINITY
#   80              redirected to 443
#   decision_port   the decision API and AuthZEN (the members' 9443), no
#                   affinity — each decision stands alone
#   notify ports    with notify_cidrs: member n's own 9443, for the nudge
#
# THE GATEWAY ENDS TLS with the vault's `gateway` certificate (the foundation's
# self-signed placeholder until member 1 imports the ACME one,
# ../foundation/pep_units.tf) and opens a NEW TLS connection to the member,
# to the pair the realm issued it. Unlike AWS's ALB it VERIFIES that pair:
# v2 refuses an HTTPS backend whose chain does not reach a well-known root
# or one it was given, and the realm's certificates chain to the identity
# service's own Root. So that Root is `member_trust_anchor` (provision.sh's
# second pass), and the host name checked is `public_hostname`, which every
# member's pair names (provision.sh --pep-host). Until the anchor is given,
# the backends are unhealthy — which they are anyway, until the second pass
# issues the pairs.
#
# EVERY PROBE ASKS THE MEMBER'S 9443 /healthcheck, the image's own liveness
# question, also for the proxy's backend (the proxy answers only once a
# route exists).
# ---------------------------------------------------------------------------

resource "azurerm_public_ip" "gateway" {
  name                = "${local.prefix}-gateway"
  location            = var.region
  resource_group_name = data.azurerm_resource_group.pep.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
  tags                = local.tags
}

resource "azurerm_dns_a_record" "public" {
  name                = trimsuffix(var.public_hostname, ".${var.dns_zone_name}")
  zone_name           = data.azurerm_dns_zone.public.name
  resource_group_name = data.azurerm_dns_zone.public.resource_group_name
  ttl                 = 300
  target_resource_id  = azurerm_public_ip.gateway.id
}

# ---------------------------------------------------------------------------
# THE WAF POLICY (rcbj, 2026-11-23: "the full aws waf in front of its load
# balancer"). PREVENTION mode.
#
# THE ORDER IS NOT AWS'S, AND THE ALLOWLIST IS A BLOCK. Application Gateway's
# WAF runs CUSTOM rules before MANAGED ones, and a custom ALLOW ends
# evaluation — so an "allow allowed_cidrs" rule, AWS's shape, would exempt
# every allowed address from the OWASP set. Instead:
#   custom 1  block what is NOT from allowed_cidrs (or notify_cidrs)
#   custom 2  block an address past `waf_rate_limit` per five minutes
#   managed   OWASP CRS 3.2, then Microsoft's bot manager set, on whatever
#             the custom rules let through
#   default   allow — what reaches here is an allowed address that every
#             rule passed, which is the default-block posture AWS's ACL takes
# ---------------------------------------------------------------------------
resource "azurerm_web_application_firewall_policy" "main" {
  name                = "${local.prefix}-pep-waf"
  location            = var.region
  resource_group_name = data.azurerm_resource_group.pep.name
  tags                = local.tags

  custom_rules {
    name      = "notallowed"
    priority  = 1
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator           = "IPMatch"
      negation_condition = true
      match_values       = local.waf_allowed
    }
  }

  custom_rules {
    name                 = "ratelimit"
    priority             = 2
    rule_type            = "RateLimitRule"
    action               = "Block"
    rate_limit_duration  = "FiveMins"
    rate_limit_threshold = var.waf_rate_limit
    group_rate_limit_by  = "ClientAddr"

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator     = "IPMatch"
      match_values = ["0.0.0.0/0"]
    }
  }

  managed_rules {
    managed_rule_set {
      type    = "OWASP"
      version = "3.2"
    }
    managed_rule_set {
      type    = "Microsoft_BotManagerRuleSet"
      version = "1.0"
    }
  }

  policy_settings {
    enabled                          = true
    mode                             = "Prevention"
    request_body_check               = true
    max_request_body_size_in_kb      = var.waf_body_limit_kb
    request_body_inspect_limit_in_kb = var.waf_body_limit_kb
    file_upload_limit_in_mb          = var.waf_file_upload_limit_mb
  }
}

locals {
  waf_allowed = distinct(concat(var.allowed_cidrs, var.notify_cidrs))

  anchored = trimspace(var.member_trust_anchor) != ""

  # Names inside the gateway's own document.
  fe_ip      = "public"
  cert_name  = "listener"
  root_name  = "member-root"
  proxy_pool = "members-proxy"
  api_pool   = "members-api"

  backend_common = {
    protocol                       = "Https"
    request_timeout                = 60
    host_name                      = var.public_hostname
    pick_host_name_from_backend    = false
    trusted_root_certificate_names = local.anchored ? [local.root_name] : []
  }
}

resource "azurerm_application_gateway" "main" {
  name                = "${local.prefix}-gateway"
  location            = var.region
  resource_group_name = data.azurerm_resource_group.pep.name
  zones               = ["1", "2", "3"]
  firewall_policy_id  = azurerm_web_application_firewall_policy.main.id
  tags                = local.tags

  sku {
    name = "WAF_v2"
    tier = "WAF_v2"
  }

  autoscale_configuration {
    min_capacity = 1
    max_capacity = 2
  }

  # The foundation's identity, which may read the vault's secrets and
  # nothing else (../foundation/pep_units.tf).
  identity {
    type         = "UserAssigned"
    identity_ids = [data.azurerm_user_assigned_identity.gateway.id]
  }

  gateway_ip_configuration {
    name      = "gateway"
    subnet_id = azurerm_subnet.gateway.id
  }

  frontend_ip_configuration {
    name                 = local.fe_ip
    public_ip_address_id = azurerm_public_ip.gateway.id
  }

  # TLS 1.2 and 1.3, forward-secret AEAD suites only.
  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101S"
  }

  # THE VERSION-LESS SECRET of the vault's `gateway` certificate: the
  # gateway follows each new version member 1 imports (within four hours).
  ssl_certificate {
    name                = local.cert_name
    key_vault_secret_id = data.azurerm_key_vault_certificate.gateway.versionless_secret_id
  }

  dynamic "trusted_root_certificate" {
    for_each = local.anchored ? [1] : []
    content {
      name = local.root_name
      data = base64encode(var.member_trust_anchor)
    }
  }

  # --- Ports and listeners ----------------------------------------------------

  frontend_port {
    name = "http"
    port = 80
  }

  frontend_port {
    name = "https"
    port = 443
  }

  dynamic "frontend_port" {
    for_each = var.publish_decision_api ? [1] : []
    content {
      name = "decision"
      port = var.decision_port
    }
  }

  dynamic "frontend_port" {
    for_each = local.notify_ports
    content {
      name = "notify-${frontend_port.key}"
      port = frontend_port.value
    }
  }

  http_listener {
    name                           = "http"
    frontend_ip_configuration_name = local.fe_ip
    frontend_port_name             = "http"
    protocol                       = "Http"
  }

  http_listener {
    name                           = "https"
    frontend_ip_configuration_name = local.fe_ip
    frontend_port_name             = "https"
    protocol                       = "Https"
    ssl_certificate_name           = local.cert_name
    host_name                      = var.public_hostname
  }

  dynamic "http_listener" {
    for_each = var.publish_decision_api ? [1] : []
    content {
      name                           = "decision"
      frontend_ip_configuration_name = local.fe_ip
      frontend_port_name             = "decision"
      protocol                       = "Https"
      ssl_certificate_name           = local.cert_name
      host_name                      = var.public_hostname
    }
  }

  dynamic "http_listener" {
    for_each = local.notify_ports
    content {
      name                           = "notify-${http_listener.key}"
      frontend_ip_configuration_name = local.fe_ip
      frontend_port_name             = "notify-${http_listener.key}"
      protocol                       = "Https"
      ssl_certificate_name           = local.cert_name
      host_name                      = var.public_hostname
    }
  }

  # --- Backends ---------------------------------------------------------------
  # The pools are EMPTY here: each member's NIC joins them from its scale set
  # (main.tf), so a replaced VM joins and leaves on its own.

  backend_address_pool {
    name = local.proxy_pool
  }

  dynamic "backend_address_pool" {
    for_each = var.publish_decision_api ? [1] : []
    content {
      name = local.api_pool
    }
  }

  dynamic "backend_address_pool" {
    for_each = local.notify_ports
    content {
      name = "notify-${backend_address_pool.key}"
    }
  }

  probe {
    name                                      = "healthcheck"
    protocol                                  = "Https"
    host                                      = var.public_hostname
    port                                      = local.pep_https_port
    path                                      = "/healthcheck"
    interval                                  = 10
    timeout                                   = 5
    unhealthy_threshold                       = 3
    pick_host_name_from_backend_http_settings = false
    match {
      status_code = ["200"]
    }
  }

  # A browser stays on one member for the length of its session: the
  # sign-in waiting for its callback, the session and its tokens, and the
  # DPoP key they are bound to all live in that member.
  backend_http_settings {
    name                                = "proxy"
    port                                = local.pep_proxy_port
    protocol                            = local.backend_common.protocol
    request_timeout                     = local.backend_common.request_timeout
    host_name                           = local.backend_common.host_name
    pick_host_name_from_backend_address = local.backend_common.pick_host_name_from_backend
    trusted_root_certificate_names      = local.backend_common.trusted_root_certificate_names
    probe_name                          = "healthcheck"
    cookie_based_affinity               = "Enabled"
    affinity_cookie_name                = "iya_pep_affinity"
  }

  dynamic "backend_http_settings" {
    for_each = var.publish_decision_api || local.notify ? [1] : []
    content {
      name                                = "api"
      port                                = local.pep_https_port
      protocol                            = local.backend_common.protocol
      request_timeout                     = local.backend_common.request_timeout
      host_name                           = local.backend_common.host_name
      pick_host_name_from_backend_address = local.backend_common.pick_host_name_from_backend
      trusted_root_certificate_names      = local.backend_common.trusted_root_certificate_names
      probe_name                          = "healthcheck"
      cookie_based_affinity               = "Disabled"
    }
  }

  # --- Rules ------------------------------------------------------------------

  redirect_configuration {
    name                 = "to-https"
    redirect_type        = "Permanent"
    target_listener_name = "https"
    include_path         = true
    include_query_string = true
  }

  request_routing_rule {
    name                        = "http"
    priority                    = 100
    rule_type                   = "Basic"
    http_listener_name          = "http"
    redirect_configuration_name = "to-https"
  }

  request_routing_rule {
    name                       = "proxy"
    priority                   = 110
    rule_type                  = "Basic"
    http_listener_name         = "https"
    backend_address_pool_name  = local.proxy_pool
    backend_http_settings_name = "proxy"
  }

  dynamic "request_routing_rule" {
    for_each = var.publish_decision_api ? [1] : []
    content {
      name                       = "decision"
      priority                   = 120
      rule_type                  = "Basic"
      http_listener_name         = "decision"
      backend_address_pool_name  = local.api_pool
      backend_http_settings_name = "api"
    }
  }

  dynamic "request_routing_rule" {
    for_each = local.notify_ports
    content {
      name                       = "notify-${request_routing_rule.key}"
      priority                   = 200 + request_routing_rule.value - var.notify_port_base
      rule_type                  = "Basic"
      http_listener_name         = "notify-${request_routing_rule.key}"
      backend_address_pool_name  = "notify-${request_routing_rule.key}"
      backend_http_settings_name = "api"
    }
  }

  lifecycle {
    precondition {
      condition     = endswith(var.public_hostname, ".${var.dns_zone_name}")
      error_message = "public_hostname must be a name inside dns_zone_name."
    }
    precondition {
      condition     = length(setintersection(toset(concat([80, 443], var.publish_decision_api ? [var.decision_port] : [])), toset(values(local.notify_ports)))) == 0
      error_message = "decision_port and the notify ports (notify_port_base + 1..n) must all differ, and differ from 80 and 443."
    }
  }

  depends_on = [
    azurerm_subnet_network_security_group_association.gateway,
    azurerm_network_security_rule.gateway,
  ]
}

locals {
  # Each pool's id, for the members' NICs (main.tf).
  pool_ids = { for p in azurerm_application_gateway.main.backend_address_pool : p.name => p.id }
}
