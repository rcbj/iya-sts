# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A CLOUDFRONT DISTRIBUTION IN FRONT OF THE LOAD BALANCER, WHERE
# `cloudfront_enabled` IS SET (rcbj, 2026-11-05).
#
#   browser ─ CloudFront edge (WAF allowlist) ─ NLB 443 ─ PROXY v2 ─ node 8081
#   client certificate, Kerberos, LDAP, SPIFFE ─ direct_hostname ─ NLB ─ node
#
# WHY: a browser far from the region lost its connection to the load balancer
# for a minute at a time, about one fetch in six, on a TCP connection crawling
# through retransmissions across the whole path. An edge ends that connection
# near the browser. deploy/aws/CLAUDE.md, *CloudFront*, argues the rest. The
# decisions here that are not the account's usual distribution:
#
#   * TWO NAMES. CloudFront ends TLS, so no client certificate reaches a node
#     through it, and it speaks only HTTP. `public_hostname` goes to CloudFront
#     and stays the issuer; `direct_hostname` stays on the load balancer for
#     everything else, under the same allowlist as ever.
#   * THE ALLOWLIST IS A WAF WEB ACL. The load balancer's security group now
#     admits every edge, so `allowed_cidrs` is enforced here for this door. It
#     holds IPv4 only, and IPv6 is OFF because of that: an IPv6 viewer would
#     be refused by an allowlist it could never be on.
#   * NOTHING BUT THE STATIC SURFACES IS COMPRESSED OR CACHED. rcbj's BREACH
#     decision (2026-10-05, common/CLAUDE.md, 3cl) is that an API or protocol
#     answer is not compressed, because it can carry a secret beside text the
#     caller chose. An edge would undo that silently, so the default behaviour
#     says `compress = false` and only `local.cloudfront_static_paths` compress.
#   * THE ORIGIN'S TWO X-FORWARDED HEADERS ARE FIXED HERE. `global.trustProxy`
#     has to be on for the client's address (ecs.tf), and that also believes
#     X-Forwarded-Host and -Proto from a trusted peer. AllViewer would forward
#     a viewer's own copy, which would let a caller choose the `htu` its DPoP
#     proof is checked against. A custom origin header OVERWRITES the viewer's.
#   * THE ORIGIN SECRET. `com.amazonaws.global.cloudfront.origin-facing` admits
#     every CloudFront customer, so another account's distribution pointed at
#     this load balancer would pass the security group and never meet this WAF.
#     This distribution adds a secret header and the service refuses an edge's
#     request without it (common/client_address.js, #1336).
#   * NO ERROR IS CACHED. CloudFront keeps a 403, 404, 405, 414, 416 and 5xx for
#     ten seconds by default, whatever the cache policy says, and an answer to
#     one person must not reach another: `error_caching_min_ttl = 0` for each.
#
# The origin is the load balancer's own DNS name, with Host forwarded on every
# behaviour: CloudFront then sends that Host as the SNI and checks the node's
# certificate against it. A behaviour that did not forward Host would fail at
# the handshake with a 502.
# ---------------------------------------------------------------------------
locals {
  cloudfront = var.cloudfront_enabled

  # Each surface's runtime is `*.js` at any depth; the catalogs, the brand
  # assets and the theme are under `/web` (common/public_assets.ts,
  # common/branding.ts), in the default realm and under a realm's prefix.
  # Each answers its own Cache-Control: `immutable` for an address carrying
  # the build, `no-cache` otherwise, `no-store` for a pending draft. So this
  # list says what MAY be cached and the origin says for how long.
  cloudfront_static_paths = ["*.js", "*.css", "/web/*", "/realm/*/web/*"]

  # AWS's managed policies. Their identifiers are the same in every account.
  cloudfront_caching_disabled = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
  cloudfront_all_viewer       = "216adef6-5c7f-47e4-b989-5492eafa07d3"
  cloudfront_host_only        = "bf0718e1-ba1e-49d1-88b1-f726733018ae"

  # What CloudFront will otherwise hold for its default ten seconds.
  cloudfront_error_codes = [403, 404, 405, 414, 416, 500, 501, 502, 503, 504]
}

# A CloudFront certificate must be in us-east-1, and so must a CloudFront web
# ACL. This one is not the node's exportable certificate (dns.tf): it is free,
# so it lives and dies with the environment.
resource "random_password" "edge_secret" {
  count   = local.cloudfront ? 1 : 0
  length  = 48
  special = false
}

resource "aws_acm_certificate" "cloudfront" {
  count             = local.cloudfront ? 1 : 0
  provider          = aws.us_east_1
  domain_name       = var.public_hostname
  validation_method = "DNS"
  key_algorithm     = "EC_prime256v1"
  tags              = { Name = "${var.public_hostname} CloudFront" }

  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = !local.multi && local.public_name && var.direct_hostname != "" && endswith(var.direct_hostname, ".${var.public_zone_name}")
      error_message = "cloudfront_enabled needs a single-cell environment, public_hostname, and a direct_hostname inside public_zone_name."
    }
  }
}

# The node's certificate for the same name is validated by the same record, so
# each stack may overwrite the other's. An environment destroy deleting it is
# repaired by the certificate stack's next apply, which runs first.
resource "aws_route53_record" "cloudfront_validation" {
  count           = local.cloudfront ? 1 : 0
  zone_id         = data.aws_route53_zone.public[0].zone_id
  name            = tolist(aws_acm_certificate.cloudfront[0].domain_validation_options)[0].resource_record_name
  type            = tolist(aws_acm_certificate.cloudfront[0].domain_validation_options)[0].resource_record_type
  records         = [tolist(aws_acm_certificate.cloudfront[0].domain_validation_options)[0].resource_record_value]
  ttl             = 300
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "cloudfront" {
  count                   = local.cloudfront ? 1 : 0
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.cloudfront[0].arn
  validation_record_fqdns = aws_route53_record.cloudfront_validation[*].fqdn
}

resource "aws_wafv2_ip_set" "allowed" {
  count              = local.cloudfront ? 1 : 0
  provider           = aws.us_east_1
  name               = "${local.prefix}-allowed"
  description        = "iya-sts ${var.environment}: allowed_cidrs"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = var.allowed_cidrs
}

resource "aws_wafv2_web_acl" "allowlist" {
  count       = local.cloudfront ? 1 : 0
  provider    = aws.us_east_1
  name        = "${local.prefix}-allowlist"
  description = "iya-sts ${var.environment}: allowed_cidrs and nobody else"
  scope       = "CLOUDFRONT"

  default_action {
    block {}
  }

  rule {
    name     = "allowed-cidrs"
    priority = 0

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.allowed[0].arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.prefix}-allowed-cidrs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.prefix}-allowlist"
    sampled_requests_enabled   = true
  }
}

# The origin's Cache-Control decides, and an address that differs only by its
# build query is a different file. No cookie reaches a static file.
resource "aws_cloudfront_cache_policy" "static" {
  count       = local.cloudfront ? 1 : 0
  name        = "${local.prefix}-static"
  comment     = "iya-sts ${var.environment}: static surfaces; the origin's Cache-Control decides"
  min_ttl     = 0
  default_ttl = 0
  max_ttl     = 31536000

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true

    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "all"
    }
  }
}

resource "aws_cloudfront_distribution" "main" {
  count           = local.cloudfront ? 1 : 0
  enabled         = true
  comment         = "iya-sts ${var.environment}: ${var.public_hostname}"
  aliases         = [var.public_hostname]
  http_version    = "http2"
  is_ipv6_enabled = false
  # Every CloudFront edge location, which is what rcbj asked for.
  price_class = "PriceClass_All"
  web_acl_id  = aws_wafv2_web_acl.allowlist[0].arn

  origin {
    origin_id   = "nlb"
    domain_name = aws_lb.main.dns_name

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
      origin_read_timeout    = 60
      # Under the node's 60-second keep-alive (ecs.tf, #406), so the node is
      # never the one to close a connection the edge is about to reuse.
      origin_keepalive_timeout = 55
    }

    custom_header {
      name  = "X-Origin-Verify"
      value = random_password.edge_secret[0].result
    }
    custom_header {
      name  = "X-Forwarded-Host"
      value = var.public_hostname
    }
    custom_header {
      name  = "X-Forwarded-Proto"
      value = "https"
    }
  }

  default_cache_behavior {
    target_origin_id         = "nlb"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods           = ["GET", "HEAD"]
    compress                 = false
    cache_policy_id          = local.cloudfront_caching_disabled
    origin_request_policy_id = local.cloudfront_all_viewer
  }

  dynamic "ordered_cache_behavior" {
    for_each = local.cloudfront_static_paths
    content {
      path_pattern             = ordered_cache_behavior.value
      target_origin_id         = "nlb"
      viewer_protocol_policy   = "redirect-to-https"
      allowed_methods          = ["GET", "HEAD"]
      cached_methods           = ["GET", "HEAD"]
      compress                 = true
      cache_policy_id          = aws_cloudfront_cache_policy.static[0].id
      origin_request_policy_id = local.cloudfront_host_only
    }
  }

  dynamic "custom_error_response" {
    for_each = local.cloudfront_error_codes
    content {
      error_code            = custom_error_response.value
      error_caching_min_ttl = 0
    }
  }

  dynamic "logging_config" {
    for_each = var.cloudfront_log_bucket != "" ? [1] : []
    content {
      bucket          = "${var.cloudfront_log_bucket}.s3.amazonaws.com"
      prefix          = var.cloudfront_log_prefix
      include_cookies = false
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.cloudfront[0].certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# THE LOAD BALANCER ADMITS EVERY EDGE ON 443, IN A GROUP OF ITS OWN. This
# prefix list counts as 55 rules against a group's 60, so it cannot sit beside
# `nlb_ports`' rules; a load balancer may hold several groups. An edge is every
# CloudFront customer's, which is what the origin secret above is for.
data "aws_ec2_managed_prefix_list" "cloudfront" {
  count = local.cloudfront ? 1 : 0
  name  = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_security_group" "nlb_cloudfront" {
  count       = local.cloudfront ? 1 : 0
  name        = "${local.prefix}-nlb-cloudfront"
  description = "iya-sts ${var.environment}: the load balancer, open to CloudFront on 443"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.prefix}-nlb-cloudfront" }
}

resource "aws_vpc_security_group_ingress_rule" "nlb_from_cloudfront" {
  count             = local.cloudfront ? 1 : 0
  security_group_id = aws_security_group.nlb_cloudfront[0].id
  description       = "443 from the CloudFront origin-facing addresses"
  prefix_list_id    = data.aws_ec2_managed_prefix_list.cloudfront[0].id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# THE PEERS WHOSE X-FORWARDED-FOR IS BELIEVED (ecs.tf). Read at each apply: a
# range AWS adds later is a peer the service takes for the client until the
# next apply, which misattributes an address and opens nothing.
data "aws_ip_ranges" "cloudfront" {
  count    = local.cloudfront ? 1 : 0
  services = ["cloudfront"]
}

# THE DIRECT NAME, outside and inside the VPC. Inside, a name under
# public_hostname resolves only through that name's private zone (dns.tf), so
# without the second record a node could not dial it.
resource "aws_route53_record" "direct" {
  count   = local.cloudfront ? 1 : 0
  zone_id = data.aws_route53_zone.public[0].zone_id
  name    = var.direct_hostname
  type    = "CNAME"
  ttl     = 300
  records = [aws_lb.main.dns_name]
}

resource "aws_route53_record" "direct_inside" {
  count           = local.cloudfront ? 1 : 0
  zone_id         = data.aws_route53_zone.inside[0].zone_id
  name            = var.direct_hostname
  type            = "A"
  ttl             = 60
  records         = data.aws_network_interface.nlb[*].private_ip
  allow_overwrite = true
  depends_on      = [aws_route53_zone_association.inside]
}
