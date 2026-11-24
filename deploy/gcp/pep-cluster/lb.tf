# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE LOAD BALANCER: a global external Application Load Balancer
# (EXTERNAL_MANAGED), a Google-managed certificate, and Cloud Armor (armor.tf)
# on every backend.
#
#   public_hostname        the reverse proxy (members' 9543), GENERATED_COOKIE
#                          affinity: a sign-in, its session and its DPoP key
#                          live in one member
#   decision_hostname      the decision API and AuthZEN (members' 9443), no
#                          affinity — each decision stands alone
#   <member>.<public>      with notify_cidrs: that member's 9443 alone, for
#                          the nudge
#   port 80                redirected to 443
#
# BY NAME, NOT BY PORT: a global external Application Load Balancer's
# forwarding rule takes 80, 8080 and 443 only, so AWS's 9443 and its notify
# ports are host names here, on the same 443 and the same certificate.
#
# THE LOAD BALANCER ENDS TLS and opens a new TLS connection to the member, to
# the pair the realm issued it; it does not verify a backend's certificate.
# A client sees only the managed certificate, whichever member answers. The
# price is the client certificate: none reaches a member.
#
# EVERY BACKEND HEALTH-CHECKS THE MEMBER'S 9443 /healthcheck: the proxy
# listener answers only once a route exists, and a member with no route is
# still live. The same check autoheals the groups (main.tf).
# ---------------------------------------------------------------------------

locals {
  # Every name the certificate carries and DNS answers.
  lb_hosts = distinct(concat(
    [var.public_hostname],
    var.publish_decision_api ? [var.decision_hostname] : [],
    values(local.notify_hosts),
  ))
}

resource "google_compute_global_address" "lb" {
  name         = local.prefix
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
  description  = "iya-sts ${var.environment}: the PEP cluster's load balancer (${var.public_hostname})"
}

# Issued once every name resolves to the address above (dns, below).
resource "google_compute_managed_ssl_certificate" "lb" {
  name = local.prefix
  managed {
    domains = local.lb_hosts
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_ssl_policy" "lb" {
  name            = local.prefix
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_health_check" "member" {
  name                = "${local.prefix}-member"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  https_health_check {
    port_specification = "USE_FIXED_PORT"
    port               = local.pep_https_port
    request_path       = "/healthcheck"
  }
}

resource "google_compute_backend_service" "proxy" {
  name                  = "${local.prefix}-proxy"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"
  port_name             = "proxy"
  timeout_sec           = 60
  health_checks         = [google_compute_health_check.member.id]
  security_policy       = google_compute_security_policy.main.id

  # A browser stays on one member for the length of its session.
  session_affinity        = "GENERATED_COOKIE"
  affinity_cookie_ttl_sec = 86400

  connection_draining_timeout_sec = 30

  dynamic "backend" {
    for_each = local.member_groups
    content {
      group           = backend.value
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1
    }
  }
}

resource "google_compute_backend_service" "decision" {
  count                 = var.publish_decision_api ? 1 : 0
  name                  = "${local.prefix}-decision"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"
  port_name             = "decision"
  timeout_sec           = 30
  health_checks         = [google_compute_health_check.member.id]
  security_policy       = google_compute_security_policy.main.id
  session_affinity      = "NONE"

  connection_draining_timeout_sec = 30

  dynamic "backend" {
    for_each = local.member_groups
    content {
      group           = backend.value
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1
    }
  }
}

# THE NUDGE: one backend per member, that member's group alone, held to the
# identity service's addresses by a policy of its own.
resource "google_compute_backend_service" "notify" {
  for_each              = local.notify_hosts
  name                  = "${local.prefix}-notify-${each.key}"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"
  port_name             = "decision"
  timeout_sec           = 10
  health_checks         = [google_compute_health_check.member.id]
  security_policy       = google_compute_security_policy.notify[0].id

  backend {
    group           = local.member_groups[each.key]
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1
  }
}

resource "google_compute_url_map" "main" {
  name            = local.prefix
  default_service = google_compute_backend_service.proxy.id

  dynamic "host_rule" {
    for_each = var.publish_decision_api ? [1] : []
    content {
      hosts        = [var.decision_hostname]
      path_matcher = "decision"
    }
  }
  dynamic "path_matcher" {
    for_each = var.publish_decision_api ? [1] : []
    content {
      name            = "decision"
      default_service = google_compute_backend_service.decision[0].id
    }
  }

  dynamic "host_rule" {
    for_each = local.notify_hosts
    content {
      hosts        = [host_rule.value]
      path_matcher = "notify-${host_rule.key}"
    }
  }
  dynamic "path_matcher" {
    for_each = local.notify_hosts
    content {
      name            = "notify-${path_matcher.key}"
      default_service = google_compute_backend_service.notify[path_matcher.key].id
    }
  }
}

resource "google_compute_target_https_proxy" "main" {
  name             = local.prefix
  url_map          = google_compute_url_map.main.id
  ssl_certificates = [google_compute_managed_ssl_certificate.lb.id]
  ssl_policy       = google_compute_ssl_policy.lb.id
}

resource "google_compute_global_forwarding_rule" "https" {
  name                  = "${local.prefix}-https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_protocol           = "TCP"
  port_range            = "443"
  ip_address            = google_compute_global_address.lb.address
  target                = google_compute_target_https_proxy.main.id
}

resource "google_compute_url_map" "redirect" {
  name = "${local.prefix}-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  name    = "${local.prefix}-redirect"
  url_map = google_compute_url_map.redirect.id
}

resource "google_compute_global_forwarding_rule" "http" {
  name                  = "${local.prefix}-http"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_protocol           = "TCP"
  port_range            = "80"
  ip_address            = google_compute_global_address.lb.address
  target                = google_compute_target_http_proxy.redirect.id
}

# Every name, at the load balancer, in the foundation's zone.
resource "google_dns_record_set" "lb" {
  for_each     = toset(local.lb_hosts)
  managed_zone = data.google_dns_managed_zone.public.name
  name         = "${each.value}."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.lb.address]
}
