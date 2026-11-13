# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AZURE FRONT DOOR IN FRONT OF THE LOAD BALANCER, WHERE `cdn_enabled` IS SET
# (rcbj, 2026-11-13, #1341; AWS's CloudFront, #1336, is the pattern:
# deploy/aws/environment/cloudfront.tf argues every decision this repeats).
#
#   browser ─ Front Door (WAF allowlist) ─ direct_hostname ─ LB 443 ─ node 8081
#   client certificate, Kerberos, LDAP, SPIFFE ─ direct_hostname ─ LB ─ node
#
#   * TWO NAMES. Front Door ends TLS, so no client certificate reaches a node
#     through it, and it speaks only HTTP. `public_hostname` is a CNAME to the
#     Front Door endpoint and stays the issuer; `direct_hostname` is the load
#     balancer (single region) or the Traffic Manager tree (several regions,
#     ../global/routing.tf), and it is Front Door's ORIGIN either way.
#   * ONE PROFILE PER ENVIRONMENT: a single-region environment's own, and in a
#     multi-region one the PRIMARY cell's, in its `full` phase — the origin
#     secret is the global/ stack's (`edge-secret`, copied into every cell's
#     vault), which a `base` phase cannot read. Its origin is the tree, so an
#     edge reaches the nearest healthy cell; Traffic Manager places the
#     edge's resolver, not the browser, and the service, not DNS, is
#     authoritative on residency (issue #98, section 6).
#   * NOTHING BUT THE STATIC SURFACES IS COMPRESSED OR CACHED (the BREACH
#     decision, 2026-10-05). The route has NO cache, so nothing is cached and
#     nothing compressed; a rule turns caching and compression on for `*.js`,
#     `*.css`, `/web/*` and `/realm/<r>/web/*` only, honouring the origin's
#     Cache-Control (`no-store` and `no-cache` are kept).
#   * THE FORWARDED HEADERS ARE FRONT DOOR'S. X-Forwarded-Host and -Proto are
#     among the headers Front Door reserves and sets itself, so a rule cannot
#     write them (CloudFront's custom headers have no counterpart). What keeps
#     a caller from choosing the Host they carry is that the route serves the
#     public name ONLY: `link_to_default_domain = false`, so the endpoint's
#     own `*.azurefd.net` name answers nothing.
#   * THE ALLOWLIST IS A FRONT DOOR WAF POLICY: `allowed_cidrs`, matched
#     against SocketAddr — the address that connected to the edge. RemoteAddr
#     would read X-Forwarded-For, which a caller writes.
#   * THE ORIGIN SECRET. The `AzureFrontDoor.Backend` addresses are every
#     Front Door customer's, as CloudFront's are, so a rule adds
#     X-Origin-Verify and the service refuses an edge without it
#     (`global.edgeProxies`, `global.edgeSecret`, common/client_address.js).
#     The secret is in the rule set's configuration: anybody who can read the
#     profile can read it. The load balancer's own probe (AzureLoadBalancer,
#     168.63.129.16) is not an edge, so it is unaffected.
#   * NO FRONT DOOR HEALTH PROBE: it comes from the edge ranges and could not
#     carry the secret, and an origin group of one origin has nothing to fail
#     over to — Microsoft's advice for one origin is to turn the probe off.
#     The cells' health is Traffic Manager's and the load balancer's.
#   * A NODE CALLING ITS OWN PUBLIC NAME does not go through the edge: the
#     name is mapped to the load balancer's address inside the container
#     (nodes.tf, `--add-host`), which the `self` rule admits — the
#     arrangement this stack had before Front Door.
# ---------------------------------------------------------------------------
locals {
  cdn = var.cdn_enabled
  # Whether this stack writes the profile: a single-region environment, or a
  # multi-region one's primary cell once the global tier exists.
  frontdoor_here = local.cdn && (!local.multi || (local.is_primary && local.full))

  # The name that reaches the load balancer (or the cells' tree) itself.
  direct_host = local.cdn ? var.direct_hostname : local.public_host

  # The origin secret: this stack's own, or the global tier's.
  edge_secret_value = local.multi ? local.global_edge_secret : try(random_password.edge_secret[0].result, "")
  # Whether the node asks it of an edge: in a cell, once the global tier
  # has written it into this vault.
  edge_on = local.cdn && (!local.multi || local.full)

  frontdoor_static_regex = "^/?(realm/[^/]+/)?web/"
  public_label           = trimsuffix(var.public_hostname, ".${var.dns_zone_name}")

  edge_environment = local.edge_on ? {
    STS_TRUST_PROXY     = "true"
    STS_TRUSTED_PROXIES = join(",", data.azurerm_network_service_tags.frontdoor[0].ipv4_cidrs)
    STS_EDGE_PROXIES    = join(",", data.azurerm_network_service_tags.frontdoor[0].ipv4_cidrs)
    } : {
    STS_TRUSTED_PROXIES = ""
  }
}

# The addresses Front Door connects to an origin from: every customer's.
data "azurerm_network_service_tags" "frontdoor" {
  count    = local.cdn ? 1 : 0
  location = local.region
  service  = "AzureFrontDoor.Backend"
}

resource "random_password" "edge_secret" {
  count   = local.cdn && !local.multi ? 1 : 0
  length  = 48
  special = false
}

resource "azurerm_cdn_frontdoor_profile" "main" {
  count                    = local.frontdoor_here ? 1 : 0
  name                     = "${local.prefix}-fd"
  resource_group_name      = data.azurerm_resource_group.unit.name
  sku_name                 = "Standard_AzureFrontDoor"
  response_timeout_seconds = 60
  tags                     = local.tags

  lifecycle {
    precondition {
      condition     = local.public_name && var.direct_hostname != "" && var.direct_hostname != var.public_hostname && endswith(var.direct_hostname, ".${var.dns_zone_name}")
      error_message = "cdn_enabled needs public_hostname, and a direct_hostname of its own inside dns_zone_name."
    }
  }
}

resource "azurerm_cdn_frontdoor_endpoint" "main" {
  count                    = local.frontdoor_here ? 1 : 0
  name                     = "${local.prefix}-fd"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main[0].id
  tags                     = local.tags
}

# ONE ORIGIN, NO PROBE (the header).
resource "azurerm_cdn_frontdoor_origin_group" "main" {
  count                    = local.frontdoor_here ? 1 : 0
  name                     = "direct"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main[0].id
  session_affinity_enabled = false

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }
}

# The direct name, with the public name as the Host: the node's certificate
# carries both, and Front Door checks it against the Host it sends.
resource "azurerm_cdn_frontdoor_origin" "main" {
  count                          = local.frontdoor_here ? 1 : 0
  name                           = "direct"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.main[0].id
  enabled                        = true
  host_name                      = var.direct_hostname
  origin_host_header             = var.public_hostname
  http_port                      = 80
  https_port                     = 443
  certificate_name_check_enabled = true
  priority                       = 1
  weight                         = 1000
}

resource "azurerm_cdn_frontdoor_custom_domain" "public" {
  count                    = local.frontdoor_here ? 1 : 0
  name                     = replace(var.public_hostname, ".", "-")
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main[0].id
  dns_zone_id              = data.azurerm_dns_zone.public[0].id
  host_name                = var.public_hostname

  tls {
    certificate_type = "ManagedCertificate"
  }
}

resource "azurerm_dns_txt_record" "frontdoor_validation" {
  count               = local.frontdoor_here ? 1 : 0
  name                = "_dnsauth.${local.public_label}"
  zone_name           = data.azurerm_dns_zone.public[0].name
  resource_group_name = data.azurerm_dns_zone.public[0].resource_group_name
  ttl                 = 300
  tags                = local.tags

  record {
    value = azurerm_cdn_frontdoor_custom_domain.public[0].validation_token
  }
}

# THE PUBLIC NAME, a CNAME to the endpoint. A multi-region environment's
# Traffic Manager CNAME is at the direct name then (../global/routing.tf).
resource "azurerm_dns_cname_record" "frontdoor" {
  count               = local.frontdoor_here ? 1 : 0
  name                = local.public_label
  zone_name           = data.azurerm_dns_zone.public[0].name
  resource_group_name = data.azurerm_dns_zone.public[0].resource_group_name
  ttl                 = 300
  record              = azurerm_cdn_frontdoor_endpoint.main[0].host_name
  tags                = local.tags
}

resource "azurerm_cdn_frontdoor_rule_set" "main" {
  count                    = local.frontdoor_here ? 1 : 0
  name                     = "iyasts"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main[0].id
}

# Every request: the origin secret, overwriting whatever a caller sent.
resource "azurerm_cdn_frontdoor_rule" "origin_secret" {
  count                     = local.frontdoor_here ? 1 : 0
  name                      = "originsecret"
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.main[0].id
  order                     = 1
  behavior_on_match         = "Continue"

  actions {
    request_header_action {
      header_action = "Overwrite"
      header_name   = "X-Origin-Verify"
      value         = local.edge_secret_value
    }
  }

  depends_on = [azurerm_cdn_frontdoor_origin_group.main, azurerm_cdn_frontdoor_origin.main]
}

# The static surfaces: cached as the origin says, and compressed.
resource "azurerm_cdn_frontdoor_rule" "static_files" {
  count                     = local.frontdoor_here ? 1 : 0
  name                      = "staticfiles"
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.main[0].id
  order                     = 2
  behavior_on_match         = "Continue"

  conditions {
    url_file_extension_condition {
      operator         = "Equal"
      match_values     = ["js", "css"]
      negate_condition = false
      transforms       = ["Lowercase"]
    }
  }

  actions {
    route_configuration_override_action {
      cache_behavior                = "HonorOrigin"
      query_string_caching_behavior = "UseQueryString"
      compression_enabled           = true
    }
  }

  depends_on = [azurerm_cdn_frontdoor_origin_group.main, azurerm_cdn_frontdoor_origin.main]
}

resource "azurerm_cdn_frontdoor_rule" "static_web" {
  count                     = local.frontdoor_here ? 1 : 0
  name                      = "staticweb"
  cdn_frontdoor_rule_set_id = azurerm_cdn_frontdoor_rule_set.main[0].id
  order                     = 3
  behavior_on_match         = "Continue"

  conditions {
    url_path_condition {
      operator         = "RegEx"
      match_values     = [local.frontdoor_static_regex]
      negate_condition = false
    }
  }

  actions {
    route_configuration_override_action {
      cache_behavior                = "HonorOrigin"
      query_string_caching_behavior = "UseQueryString"
      compression_enabled           = true
    }
  }

  depends_on = [azurerm_cdn_frontdoor_origin_group.main, azurerm_cdn_frontdoor_origin.main]
}

# EVERY PATH, NO CACHE (the header), the public name only, HTTP redirected.
resource "azurerm_cdn_frontdoor_route" "main" {
  count                           = local.frontdoor_here ? 1 : 0
  name                            = "public"
  cdn_frontdoor_endpoint_id       = azurerm_cdn_frontdoor_endpoint.main[0].id
  cdn_frontdoor_origin_group_id   = azurerm_cdn_frontdoor_origin_group.main[0].id
  cdn_frontdoor_origin_ids        = [azurerm_cdn_frontdoor_origin.main[0].id]
  cdn_frontdoor_rule_set_ids      = [azurerm_cdn_frontdoor_rule_set.main[0].id]
  cdn_frontdoor_custom_domain_ids = [azurerm_cdn_frontdoor_custom_domain.public[0].id]
  enabled                         = true
  forwarding_protocol             = "HttpsOnly"
  https_redirect_enabled          = true
  patterns_to_match               = ["/*"]
  supported_protocols             = ["Http", "Https"]
  link_to_default_domain          = false

  depends_on = [
    azurerm_cdn_frontdoor_rule.origin_secret,
    azurerm_cdn_frontdoor_rule.static_files,
    azurerm_cdn_frontdoor_rule.static_web,
  ]
}

resource "azurerm_cdn_frontdoor_custom_domain_association" "public" {
  count                          = local.frontdoor_here ? 1 : 0
  cdn_frontdoor_custom_domain_id = azurerm_cdn_frontdoor_custom_domain.public[0].id
  cdn_frontdoor_route_ids        = [azurerm_cdn_frontdoor_route.main[0].id]
}

# THE ALLOWLIST, against the connecting address (the header).
resource "azurerm_cdn_frontdoor_firewall_policy" "allowlist" {
  count               = local.frontdoor_here ? 1 : 0
  name                = replace("${local.prefix}allowlist", "-", "")
  resource_group_name = data.azurerm_resource_group.unit.name
  sku_name            = "Standard_AzureFrontDoor"
  enabled             = true
  mode                = "Prevention"
  tags                = local.tags

  custom_rule {
    name     = "outsideallowedcidrs"
    enabled  = true
    priority = 1
    type     = "MatchRule"
    action   = "Block"

    match_condition {
      match_variable     = "SocketAddr"
      operator           = "IPMatch"
      negation_condition = true
      match_values       = var.allowed_cidrs
    }
  }
}

resource "azurerm_cdn_frontdoor_security_policy" "allowlist" {
  count                    = local.frontdoor_here ? 1 : 0
  name                     = "allowlist"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.main[0].id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.allowlist[0].id

      association {
        domain {
          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_custom_domain.public[0].id
        }
        patterns_to_match = ["/*"]
      }
    }
  }
}
