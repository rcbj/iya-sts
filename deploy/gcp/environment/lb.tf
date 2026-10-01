# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE PUBLIC FRONT DOOR: A REGIONAL EXTERNAL PASSTHROUGH NETWORK LOAD BALANCER
# (deploy/aws/environment/nlb.tf).
#
# PASSTHROUGH, NOT PROXY, for AWS's reason: mock-sts terminates its own TLS,
# and a client certificate presented to the main port reaches the service
# only if the TCP stream does. GCP's passthrough load balancer is not even a
# connection endpoint — it forwards packets, so the node's TLS is the client's
# TLS, and `GET /tls/sign-in` and RFC 8705 mutual TLS work as on AWS.
#
# **THE CLIENT'S ADDRESS ARRIVES AS THE PEER, AND THERE IS NO PROXY HEADER.**
# AWS turns client-IP preservation off and PROXY v2 on, because an NLB with
# preservation on made the node refuse the client as an untrusted proxy. Here
# the packet itself carries the client's address, so the node is told
# `STS_PROXY_PROTOCOL=off` and trusts no proxy (nodes.tf) — which is the
# simpler arrangement, and the one where a spoofed header cannot exist.
#
# ONE ADDRESS, TWO FORWARDING RULES. A forwarding rule carries at most five
# ports; the published ports are five with the KDC, and the default realm's
# SPIFFE ports are a second rule on the same address and backend service.
# **SO THE SPIFFE PORTS NEED NONE OF AWS'S REGISTER-BY-ADDRESS WORKAROUND**
# (deploy/aws/CLAUDE.md, *THE NODES ARE REGISTERED BY ADDRESS*): the backend
# is the instance groups, which follow their instances, and there is no
# five-target-group limit to run into.
#
# ONE HEALTH CHECK, NOT ONE PER PORT: a backend service takes one. It is an
# HTTPS GET of /healthcheck on 443 — AWS's check of the main port — and a
# node whose LDAPS failed to bind is NOT taken out of service by it, where on
# AWS it was (ECS requires every target group healthy). The service records
# that failure on `GET /admin/ldap/service` either way.
#
# Every zone's node is a backend, which is AWS's cross-zone load balancing:
# `sts_cluster_alternation` needs every node to answer.
# ---------------------------------------------------------------------------
resource "google_compute_address" "lb" {
  name         = "${local.prefix}-lb"
  region       = local.region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"
  description  = "mock-sts ${var.environment}: the load balancer's address"
}

resource "google_compute_region_health_check" "https" {
  name   = "${local.prefix}-https"
  region = local.region

  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  # The main port is HTTPS on a certificate the cluster issues itself (or
  # the ACME one); a health check does not verify it, it asks whether the
  # service answers. Docker maps 443 to the container's 8081.
  https_health_check {
    port         = 443
    request_path = "/healthcheck"
  }

  log_config {
    enable = false
  }
}

resource "google_compute_region_backend_service" "nodes" {
  name                  = "${local.prefix}-nodes"
  region                = local.region
  load_balancing_scheme = "EXTERNAL"
  protocol              = "TCP"
  health_checks         = [google_compute_region_health_check.https.id]
  session_affinity      = "NONE"

  connection_draining_timeout_sec = 30

  dynamic "backend" {
    for_each = local.node_groups
    content {
      group          = backend.value
      balancing_mode = "CONNECTION"
    }
  }
}

resource "google_compute_forwarding_rule" "published" {
  name                  = "${local.prefix}-published"
  region                = local.region
  load_balancing_scheme = "EXTERNAL"
  ip_protocol           = "TCP"
  ip_address            = google_compute_address.lb.address
  network_tier          = "PREMIUM"
  backend_service       = google_compute_region_backend_service.nodes.id
  ports                 = [for p in values(local.published_ports) : tostring(p.listener)]
}

resource "google_compute_forwarding_rule" "spiffe_default" {
  name                  = "${local.prefix}-spiffe"
  region                = local.region
  load_balancing_scheme = "EXTERNAL"
  ip_protocol           = "TCP"
  ip_address            = google_compute_address.lb.address
  network_tier          = "PREMIUM"
  backend_service       = google_compute_region_backend_service.nodes.id
  ports                 = [for p in values(local.spiffe_default_ports) : tostring(p)]
}
