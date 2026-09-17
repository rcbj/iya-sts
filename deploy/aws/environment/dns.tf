# ---------------------------------------------------------------------------
# A PUBLIC NAME AND A PUBLIC CERTIFICATE, WHEN `public_hostname` IS SET.
#
#   test-idp.iyasec.io  CNAME  mock-sts-<env>-….elb.us-west-2.amazonaws.com
#
# The certificate is ACM's, DNS-validated in the same zone, and it is
# presented by the NLB's 443 listener (nlb.tf), which terminates TLS and opens
# a new TLS connection to the node — the node's own leaf, under the cluster's
# Root, is then seen only by the load balancer, which does not verify it.
#
# WHAT TERMINATING COSTS: a client certificate presented on 443 ends at the
# load balancer (an NLB cannot pass one through a TLS listener), so
# `GET /tls/sign-in` and RFC 8705 mutual TLS on the main port see no
# certificate. The test environments keep passthrough by leaving the name
# empty, and `sts_global_logout`'s certificate sign-in needs it.
#
# A CNAME and not an alias: that is what was asked for, and the name is not a
# zone apex, which is the one place a CNAME cannot go.
# ---------------------------------------------------------------------------
locals {
  public_name = var.public_hostname != ""
}

data "aws_route53_zone" "public" {
  count        = local.public_name ? 1 : 0
  name         = var.public_zone_name
  private_zone = false
}

resource "aws_acm_certificate" "public" {
  count             = local.public_name ? 1 : 0
  domain_name       = var.public_hostname
  validation_method = "DNS"
  key_algorithm     = "EC_prime256v1"
  tags              = { Name = var.public_hostname }

  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = var.public_zone_name != "" && endswith(var.public_hostname, ".${var.public_zone_name}")
      error_message = "public_hostname must be a name inside public_zone_name, and public_zone_name must be set."
    }
  }
}

resource "aws_route53_record" "certificate_validation" {
  for_each = local.public_name ? {
    for o in aws_acm_certificate.public[0].domain_validation_options :
    o.domain_name => o
  } : {}

  zone_id         = data.aws_route53_zone.public[0].zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  records         = [each.value.resource_record_value]
  ttl             = 300
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "public" {
  count                   = local.public_name ? 1 : 0
  certificate_arn         = aws_acm_certificate.public[0].arn
  validation_record_fqdns = [for r in aws_route53_record.certificate_validation : r.fqdn]
}

resource "aws_route53_record" "public" {
  count   = local.public_name ? 1 : 0
  zone_id = data.aws_route53_zone.public[0].zone_id
  name    = var.public_hostname
  type    = "CNAME"
  ttl     = 300
  records = [aws_lb.main.dns_name]
}
