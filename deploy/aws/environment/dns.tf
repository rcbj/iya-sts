# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
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
  count       = local.public_name ? 1 : 0
  domain_name = var.public_hostname
  # A cell's certificate also names its own console name (#361), which the
  # node presents to a browser that asked for it.
  subject_alternative_names = local.cell_console_host != "" ? [local.cell_console_host] : []
  validation_method         = "DNS"
  key_algorithm             = "EC_prime256v1"
  tags                      = { Name = var.public_hostname }

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

# A CELL WRITES THE RECORD TREE IN dns_cells.tf INSTEAD (#98): a CNAME may not
# share its name with any other record, so the two are exclusive.
resource "aws_route53_record" "public" {
  count   = local.public_name && !local.multi ? 1 : 0
  zone_id = data.aws_route53_zone.public[0].zone_id
  name    = var.public_hostname
  type    = "CNAME"
  ttl     = 300
  records = [aws_lb.main.dns_name]
}

# ---------------------------------------------------------------------------
# AND THE SAME NAME INSIDE THE VPC (#311): the load balancer's PRIVATE
# addresses, in the private zone foundation/dns_inside.tf made for this name.
# A node dialling its own public name (a Shared Signals receiver reading this
# service's configuration, a Provider Command to its own mock relying party)
# otherwise left through the internet gateway with a public address the load
# balancer does not admit, and timed out. From inside, it arrives from a
# node's private address, which security.tf's `nlb_from_nodes` admits — and,
# as the PROXY header says, from a node: `STS_TRUSTED_PROXIES` is the public
# subnets, where these addresses are.
#
# The load balancer's interfaces are found one per public subnet by their
# description, so the count is known at plan time and the addresses are read
# once the load balancer exists.
# ---------------------------------------------------------------------------
data "aws_route53_zone" "inside" {
  count        = local.public_name ? 1 : 0
  name         = var.public_hostname
  private_zone = true
}

resource "aws_route53_zone_association" "inside" {
  count   = local.public_name ? 1 : 0
  zone_id = data.aws_route53_zone.inside[0].zone_id
  vpc_id  = aws_vpc.main.id
}

data "aws_network_interface" "nlb" {
  count = local.public_name ? length(aws_subnet.public) : 0
  filter {
    name   = "description"
    values = ["ELB ${aws_lb.main.arn_suffix}"]
  }
  filter {
    name   = "subnet-id"
    values = [aws_subnet.public[count.index].id]
  }
}

resource "aws_route53_record" "inside" {
  count           = local.public_name ? 1 : 0
  zone_id         = data.aws_route53_zone.inside[0].zone_id
  name            = var.public_hostname
  type            = "A"
  ttl             = 60
  records         = data.aws_network_interface.nlb[*].private_ip
  allow_overwrite = true
  depends_on      = [aws_route53_zone_association.inside]
}
