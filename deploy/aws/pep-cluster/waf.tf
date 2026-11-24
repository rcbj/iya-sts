# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# AWS WAF IN FRONT OF THE LOAD BALANCER (rcbj, 2026-11-23: "I want the full
# aws waf in front of its load balancer"). A REGIONAL web ACL on the ALB.
#
# THE RULES, IN THE ORDER THEY ARE ASKED (the first that ends a request
# wins):
#   0  AWSManagedRulesAmazonIpReputationList   blocks addresses AWS threat
#                                              intelligence lists
#   1  AWSManagedRulesKnownBadInputsRuleSet    Log4j, Java deserialisation,
#                                              host-header and similar
#   2  AWSManagedRulesCommonRuleSet            the OWASP-style core set, with
#                                              SizeRestrictions_BODY COUNTED
#                                              rather than blocked: the proxy
#                                              forwards an application's own
#                                              POSTs, and 8 KB is not a limit
#                                              this service can know is right
#   3  rate-per-address                        `waf_rate_limit` per five
#                                              minutes, then blocked
#   10 allowed                                 allowed_cidrs (and notify_cidrs)
#                                              are ALLOWED
#   default                                    BLOCK — the allowlist posture
#                                              testidp's CloudFront ACL takes
#
# The managed groups come before the allowlist so that an allowed address is
# still held to them: an ALLOW is terminating, so a group after it would see
# nothing.
# ---------------------------------------------------------------------------

resource "aws_wafv2_ip_set" "allowed" {
  name               = "${local.prefix}-allowed"
  description        = "iya-sts ${var.environment}: allowed_cidrs and notify_cidrs"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = distinct(concat(var.allowed_cidrs, var.notify_cidrs))
}

resource "aws_wafv2_web_acl" "main" {
  name        = "${local.prefix}-pep"
  description = "iya-sts ${var.environment}: PEP cluster ${var.cluster} - managed rules, a rate limit, and allowed_cidrs only"
  scope       = "REGIONAL"

  default_action {
    block {}
  }

  rule {
    name     = "aws-ip-reputation"
    priority = 0
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.prefix}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.prefix}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-common"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
        rule_action_override {
          name = "SizeRestrictions_BODY"
          action_to_use {
            count {}
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.prefix}-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-per-address"
    priority = 3
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.prefix}-rate"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "allowed"
    priority = 10
    action {
      allow {}
    }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.allowed.arn
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.prefix}-allowed"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.prefix}-pep"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}
