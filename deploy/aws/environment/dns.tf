# ---------------------------------------------------------------------------
# A PUBLIC NAME AND A PUBLIC CERTIFICATE, WHEN `public_hostname` IS SET.
#
#   test-idp.iyasec.io  CNAME  mock-sts-<env>-….elb.us-west-2.amazonaws.com
#
# The certificate is ACM's, DNS-validated in the same zone, and **the NODE
# presents it** — the load balancer passes TCP through untouched (nlb.tf) and
# `cert-init` exports the certificate into the task before the node starts
# (deploy/aws/cert-init/).
#
# IT WAS THE LOAD BALANCER'S UNTIL 2026-09-17, and that was the mistake this
# reverses. A TLS listener on an NLB terminates, and **an NLB cannot pass a
# client certificate through a TLS listener** — so `GET /tls/sign-in` and RFC
# 8705 mutual TLS on the main port saw none, which is most of what this
# service exists to exercise. Passthrough is what the test environments always
# used; the only thing that made this deployment different was wanting a
# PUBLICLY TRUSTED certificate on the main port, and serving it from the node
# gives it that without giving up the client's.
#
# SO THE CERTIFICATE IS REQUESTED AS EXPORTABLE (`options { export }`), and
# that is not a flag that can be turned on afterwards: an existing certificate
# has to be replaced by one requested this way. It is billed per certificate,
# unlike an ACM certificate used only by an integrated service, and it is the
# only way AWS releases a public certificate's PRIVATE KEY — which is what a
# node needs in order to present it. The key is never in Terraform state: the
# export happens in the task, per start (cert-init/export.sh).
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

  # THE WHOLE POINT: without this ACM will not release the private key, and a
  # certificate whose key cannot leave ACM can only ever be presented by an
  # integrated AWS service — which is the arrangement this replaces. ACM
  # CANNOT change it on an existing certificate ("Export option for
  # certificates cannot be updated"), and the provider plans it as an
  # in-place update rather than a replacement, so a certificate made without
  # it needs `-replace='aws_acm_certificate.public[0]'` once — which is how
  # testidp's was moved over on 2026-09-17 (`create_before_destroy` below
  # keeps the old one serving until the new one has validated).
  options {
    export = "ENABLED"
  }

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
