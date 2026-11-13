# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A CDN IN FRONT OF THE LOAD BALANCER, WHERE `cdn_enabled` IS SET (rcbj,
# 2026-11-13, #1341; AWS's CloudFront, #1336, is the pattern:
# deploy/aws/environment/cloudfront.tf argues every decision this repeats).
#
# A SINGLE-REGION ENVIRONMENT: CLOUD CDN, BEHIND A GLOBAL EXTERNAL
# APPLICATION LOAD BALANCER.
#
#   browser ─ Google's edge (Cloud Armor allowlist) ─ ALB 443 ─ HTTPS ─ node 443
#   client certificate, Kerberos, LDAP, SPIFFE ─ direct_hostname ─ the
#                                                passthrough NLB (lb.tf) ─ node
#
#   * TWO NAMES, for AWS's reason: the ALB ends TLS, so no client certificate
#     reaches a node through it, and it speaks only HTTP. `public_hostname`
#     goes to the ALB's global address and stays the issuer; `direct_hostname`
#     is the passthrough load balancer, under the same allowlist as ever.
#   * NOTHING BUT THE STATIC SURFACES IS COMPRESSED OR CACHED (the BREACH
#     decision, 2026-10-05). Two backend services over the same instance
#     groups: `api` has no CDN and no compression, and `static`, chosen by the
#     URL map for `*.js`, `*.css`, `/web/*` and `/realm/<r>/web/*`, has Cloud
#     CDN in USE_ORIGIN_HEADERS mode — a response is cached only when the
#     origin's Cache-Control says so, so `no-store` and `no-cache` are kept —
#     with negative caching OFF, so no error is cached.
#   * THE TWO X-FORWARDED HEADERS ARE THE LOAD BALANCER'S. The URL map
#     REPLACES X-Forwarded-Host and -Proto on every request, so a viewer's own
#     copy never reaches a node, and an unmatched Host is redirected to the
#     public name rather than served.
#   * THE ALLOWLIST IS CLOUD ARMOR: `allowed_cidrs`, ten ranges a rule (Cloud
#     Armor's limit), on the backend services, and the same list as an EDGE
#     policy on `static`, because a cache hit never reaches a backend policy.
#     It matches the connecting address, never a forwarded header.
#   * NO ORIGIN SECRET, AND THAT IS ARGUED, NOT FORGOTTEN. On AWS an edge is
#     any CloudFront customer's, so the service refuses an edge without the
#     secret (`global.edgeProxies`). Here the ALB reaches the nodes from
#     Google's front-end ranges (35.191.0.0/16, 130.211.0.0/22), and only a
#     load balancer IN THIS PROJECT can have these instance groups as its
#     backends; another customer's load balancer reaches the internet from
#     other ranges, and the passthrough address admits `allowed_cidrs` only.
#     The same two ranges are where every Google HEALTH CHECK comes from, and a
#     health check cannot carry a header — so naming them as edges would
#     refuse every health check and replace every node. They are TRUSTED
#     PROXIES instead, with the ALB's own address, which the ALB appends to
#     X-Forwarded-For after the client's.
#   * A NODE CALLING ITS OWN PUBLIC NAME does not go through the edge: the
#     name is mapped to the passthrough address inside the container
#     (nodes.tf, `--add-host`), which the guest agent answers locally — the
#     arrangement this stack had before the CDN, and AWS's private zone.
#
# A GCP CELL OF A MULTI-CLOUD ENVIRONMENT (#97): CLOUDFRONT. Its CDN is the
# AWS primary cell's distribution, whose origin is the Route 53 tree at the
# direct name (deploy/multicloud/interconnect). Nothing is made here; the
# cell's nodes believe CloudFront's ranges, refuse an edge without the
# environment's origin secret (the AWS global tier's `edge-secret`, copied by
# deploy/multicloud/gcp-global), and present the direct name too. The
# interconnect admits CloudFront on 443 to this cell's load balancer.
# ---------------------------------------------------------------------------
locals {
  cdn = var.cdn_enabled
  # Cloud CDN, made here: a single-region environment.
  cdn_here = local.cdn && !local.multi

  # The name that reaches the passthrough load balancer itself.
  direct_host = local.cdn ? var.direct_hostname : local.public_host

  # Where Google's front ends and health checkers connect from
  # (firewall.tf's `health_checks` admits them on 443 already).
  google_front_ends = ["35.191.0.0/16", "130.211.0.0/22"]

  # What may be cached: each surface's `*.js`, the stylesheets, the catalogs
  # and brand assets under `/web` in the default realm and under a realm's
  # prefix (AWS's `cloudfront_static_paths`). The origin's Cache-Control
  # decides for how long. Matched against the path without its query.
  cdn_static_regex = "^(/realm/[^/]+)?/web/.*$|^.*\\.(js|css)$"

  # Cloud Armor takes ten ranges a rule.
  allowed_chunks = chunklist(var.allowed_cidrs, 10)

  # IN A CELL: CloudFront's ranges and the origin secret's copy, from the
  # global tier — empty in `base`, and on an environment whose global tier
  # predates the secret, when the cell asks nothing of an edge.
  edge_secret_name = local.cdn && local.multi ? lookup(local.global.secrets, "edge-secret", "") : ""
  edge_on          = local.edge_secret_name != ""

  # WHAT THE NODE IS TOLD ABOUT WHO IS IN FRONT OF IT. With neither CDN it is
  # what it always was: no proxy is trusted.
  edge_environment = local.cdn_here ? {
    STS_TRUST_PROXY     = "true"
    STS_TRUSTED_PROXIES = join(",", concat(local.google_front_ends, ["${google_compute_global_address.cdn[0].address}/32"]))
    } : local.edge_on ? {
    STS_TRUST_PROXY     = "true"
    STS_TRUSTED_PROXIES = join(",", local.global.cloudfront_cidrs)
    STS_EDGE_PROXIES    = join(",", local.global.cloudfront_cidrs)
    } : {
    STS_TRUSTED_PROXIES = ""
  }
}

resource "google_compute_global_address" "cdn" {
  count        = local.cdn_here ? 1 : 0
  name         = "${local.prefix}-cdn"
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
  description  = "iya-sts ${var.environment}: the CDN's address (${var.public_hostname})"
}

# Google-managed, for the public name only: it is the edge's certificate and
# never the node's, so its key staying in Google is what is wanted. It is
# issued once the public name resolves to the address above (dns.tf).
resource "google_compute_managed_ssl_certificate" "cdn" {
  count = local.cdn_here ? 1 : 0
  name  = "${local.prefix}-cdn"

  managed {
    domains = [var.public_hostname]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_ssl_policy" "cdn" {
  count           = local.cdn_here ? 1 : 0
  name            = "${local.prefix}-cdn"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}

# A global check for a global backend service: the passthrough's is regional.
resource "google_compute_health_check" "cdn" {
  count = local.cdn_here ? 1 : 0
  name  = "${local.prefix}-cdn"

  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  https_health_check {
    port         = 443
    request_path = "/healthcheck"
  }
}

# THE ALLOWLIST AT THE BACKEND: what is not a cache hit.
resource "google_compute_security_policy" "allowlist" {
  count       = local.cdn_here ? 1 : 0
  name        = "${local.prefix}-allowlist"
  description = "iya-sts ${var.environment}: allowed_cidrs and nobody else"
  type        = "CLOUD_ARMOR"

  dynamic "rule" {
    for_each = local.allowed_chunks
    content {
      action   = "allow"
      priority = 1000 + rule.key
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = rule.value
        }
      }
      description = "allowed_cidrs, part ${rule.key + 1}"
    }
  }

  rule {
    action   = "deny(403)"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "everybody else"
  }
}

# THE SAME LIST AT THE EDGE: a cache hit is answered before any backend
# policy is consulted.
resource "google_compute_security_policy" "edge_allowlist" {
  count       = local.cdn_here ? 1 : 0
  name        = "${local.prefix}-edge-allowlist"
  description = "iya-sts ${var.environment}: allowed_cidrs at the edge, for cached answers"
  type        = "CLOUD_ARMOR_EDGE"

  dynamic "rule" {
    for_each = local.allowed_chunks
    content {
      action   = "allow"
      priority = 1000 + rule.key
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = rule.value
        }
      }
      description = "allowed_cidrs, part ${rule.key + 1}"
    }
  }

  rule {
    action   = "deny(403)"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "everybody else"
  }
}

# EVERYTHING BUT THE STATIC SURFACES: no CDN, no compression.
resource "google_compute_backend_service" "api" {
  count                 = local.cdn_here ? 1 : 0
  name                  = "${local.prefix}-api"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"
  port_name             = "https"
  timeout_sec           = 60
  health_checks         = [google_compute_health_check.cdn[0].id]
  security_policy       = google_compute_security_policy.allowlist[0].id
  enable_cdn            = false

  connection_draining_timeout_sec = 30

  dynamic "backend" {
    for_each = local.node_groups
    content {
      group           = backend.value
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1
    }
  }
}

# THE STATIC SURFACES: Cloud CDN, the origin's Cache-Control deciding.
resource "google_compute_backend_service" "static" {
  count                 = local.cdn_here ? 1 : 0
  name                  = "${local.prefix}-static"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"
  port_name             = "https"
  timeout_sec           = 60
  health_checks         = [google_compute_health_check.cdn[0].id]
  security_policy       = google_compute_security_policy.allowlist[0].id
  edge_security_policy  = google_compute_security_policy.edge_allowlist[0].id
  enable_cdn            = true
  compression_mode      = "AUTOMATIC"

  connection_draining_timeout_sec = 30

  cdn_policy {
    cache_mode       = "USE_ORIGIN_HEADERS"
    negative_caching = false
    # An address that differs only by its build query is a different file;
    # no cookie reaches a static file's key.
    cache_key_policy {
      include_host         = true
      include_protocol     = true
      include_query_string = true
    }
  }

  dynamic "backend" {
    for_each = local.node_groups
    content {
      group           = backend.value
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1
    }
  }
}

resource "google_compute_url_map" "cdn" {
  count       = local.cdn_here ? 1 : 0
  name        = "${local.prefix}-cdn"
  description = "iya-sts ${var.environment}: ${var.public_hostname}"

  # A Host that is not the public name (the bare address, anything else) is
  # sent to the public name rather than served.
  default_url_redirect {
    host_redirect          = var.public_hostname
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }

  host_rule {
    hosts        = [var.public_hostname]
    path_matcher = "main"
  }

  path_matcher {
    name            = "main"
    default_service = google_compute_backend_service.api[0].id

    route_rules {
      priority = 1
      service  = google_compute_backend_service.static[0].id
      match_rules {
        regex_match = local.cdn_static_regex
      }
    }
  }

  # THE TWO FORWARDED HEADERS ARE OURS, REPLACING A VIEWER'S (the header).
  header_action {
    request_headers_to_add {
      header_name  = "X-Forwarded-Host"
      header_value = var.public_hostname
      replace      = true
    }
    request_headers_to_add {
      header_name  = "X-Forwarded-Proto"
      header_value = "https"
      replace      = true
    }
  }
}

resource "google_compute_target_https_proxy" "cdn" {
  count            = local.cdn_here ? 1 : 0
  name             = "${local.prefix}-cdn"
  url_map          = google_compute_url_map.cdn[0].id
  ssl_certificates = [google_compute_managed_ssl_certificate.cdn[0].id]
  ssl_policy       = google_compute_ssl_policy.cdn[0].id
  # Under the node's 60-second keep-alive (#406), as CloudFront's is.
  http_keep_alive_timeout_sec = 55
}

resource "google_compute_global_forwarding_rule" "cdn_https" {
  count                 = local.cdn_here ? 1 : 0
  name                  = "${local.prefix}-cdn-https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_protocol           = "TCP"
  port_range            = "443"
  ip_address            = google_compute_global_address.cdn[0].address
  target                = google_compute_target_https_proxy.cdn[0].id
}

# PORT 80 ONLY REDIRECTS, as CloudFront's `redirect-to-https` does. The
# plain-HTTP revocation listener is at the direct name.
resource "google_compute_url_map" "cdn_redirect" {
  count = local.cdn_here ? 1 : 0
  name  = "${local.prefix}-cdn-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "cdn_redirect" {
  count   = local.cdn_here ? 1 : 0
  name    = "${local.prefix}-cdn-redirect"
  url_map = google_compute_url_map.cdn_redirect[0].id
}

resource "google_compute_global_forwarding_rule" "cdn_http" {
  count                 = local.cdn_here ? 1 : 0
  name                  = "${local.prefix}-cdn-http"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_protocol           = "TCP"
  port_range            = "80"
  ip_address            = google_compute_global_address.cdn[0].address
  target                = google_compute_target_http_proxy.cdn_redirect[0].id
}

# THE DIRECT NAME, at the passthrough load balancer (dns.tf has the public
# one). A cell's is in Route 53, in the interconnect's tree.
resource "google_dns_record_set" "direct" {
  count        = local.cdn_here ? 1 : 0
  managed_zone = data.google_dns_managed_zone.public[0].name
  name         = "${var.direct_hostname}."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_address.lb.address]
}
