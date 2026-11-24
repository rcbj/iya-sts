# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# CLOUD ARMOR IN FRONT OF THE LOAD BALANCER: GCP's AWS WAF
# (deploy/aws/pep-cluster/waf.tf; rcbj, 2026-11-23: "the full aws waf in
# front of its load balancer").
#
# THE RULES, IN THE ORDER THEY ARE ASKED (lowest priority number first; the
# first that matches ends it):
#   100-150  the preconfigured WAF rules (Google's ModSecurity CRS 3.3
#            signatures), sensitivity 1 — the level that blocks with the
#            fewest false positives:
#              sqli-v33-stable, xss-v33-stable, lfi-v33-stable,
#              rfi-v33-stable, rce-v33-stable, protocolattack-v33-stable,
#              scannerdetection-v33-stable, methodenforcement-v33-stable
#   200      a per-address rate limit (`waf_rate_limit` a minute), then 429
#   1000+    ALLOW `allowed_cidrs` (ten ranges a rule, Cloud Armor's limit)
#   2147483647  DENY everything else — the allowlist posture testidp's
#            CloudFront WAF and AWS's PEP WAF take
#
# THE SIGNATURES COME BEFORE THE ALLOW, because an allow ends evaluation: an
# allowed address is still held to them, as on AWS.
#
# THE BODY. Cloud Armor inspects the first 8 KB of a body (64 KB once
# raised); a larger one is inspected as far as that and passed. AWS's
# SizeRestrictions_BODY was COUNTED for the same reason — the proxy forwards
# an application's own POSTs — and Cloud Armor has no size rule to count.
#
# THE NUDGE'S POLICY (with notify_cidrs) admits the identity service's
# addresses and nobody else, on the notify names' backends only.
# ---------------------------------------------------------------------------

locals {
  waf_rules = [
    "sqli-v33-stable",
    "xss-v33-stable",
    "lfi-v33-stable",
    "rfi-v33-stable",
    "rce-v33-stable",
    "protocolattack-v33-stable",
    "scannerdetection-v33-stable",
    "methodenforcement-v33-stable",
  ]
  allowed_chunks = chunklist(var.allowed_cidrs, 10)
  notify_chunks  = chunklist(var.notify_cidrs, 10)
}

resource "google_compute_security_policy" "main" {
  name        = "${local.prefix}-pep"
  description = "iya-sts ${var.environment}: PEP cluster ${var.cluster} - WAF signatures, a rate limit, and allowed_cidrs only"
  type        = "CLOUD_ARMOR"

  dynamic "rule" {
    for_each = local.waf_rules
    content {
      action      = "deny(403)"
      priority    = 100 + rule.key
      description = "Preconfigured WAF: ${rule.value}"
      match {
        expr {
          expression = "evaluatePreconfiguredWaf('${rule.value}', {'sensitivity': 1})"
        }
      }
    }
  }

  rule {
    action      = "throttle"
    priority    = 200
    description = "At most waf_rate_limit requests a minute from one address"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = var.waf_rate_limit
        interval_sec = 60
      }
    }
  }

  dynamic "rule" {
    for_each = local.allowed_chunks
    content {
      action      = "allow"
      priority    = 1000 + rule.key
      description = "allowed_cidrs, part ${rule.key + 1}"
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = rule.value
        }
      }
    }
  }

  rule {
    action      = "deny(403)"
    priority    = 2147483647
    description = "Everyone else"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

resource "google_compute_security_policy" "notify" {
  count       = local.notify ? 1 : 0
  name        = "${local.prefix}-pep-notify"
  description = "iya-sts ${var.environment}: PEP cluster ${var.cluster} - the identity service's nudge, from notify_cidrs only"
  type        = "CLOUD_ARMOR"

  dynamic "rule" {
    for_each = local.notify_chunks
    content {
      action      = "allow"
      priority    = 1000 + rule.key
      description = "notify_cidrs, part ${rule.key + 1}"
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = rule.value
        }
      }
    }
  }

  rule {
    action      = "deny(403)"
    priority    = 2147483647
    description = "Everyone else"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}
