# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# A PUBLIC NAME AND A PUBLIC CERTIFICATE, WHEN `public_hostname` IS SET.
#
#   test-idp.iyasec.io  CNAME  iya-sts-<env>-….elb.us-west-2.amazonaws.com
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
# export happens in the task, per start (cert-init/export.sh). BECAUSE it is
# billed per issuance, the certificate is not this stack's any more and
# outlives every destroy (below, and deploy/aws/certificate/).
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

# THE CERTIFICATE ITSELF IS NOT THIS STACK'S (rcbj, 2026-10-01). It is
# deploy/aws/certificate/'s, a stack an environment destroy never touches,
# because an exportable certificate is billed per issuance and re-issuing one
# on every build was the largest line item of September's AWS bill. That
# stack's header argues the rest; here it is READ, from its state, which
# entrypoint.sh applies before every environment apply.
data "terraform_remote_state" "certificate" {
  count   = local.public_name ? 1 : 0
  backend = "s3"
  config = {
    bucket = "${var.name}-terraform-state-${data.aws_caller_identity.current.account_id}"
    key = var.cell != "" ? (
      "environment/${var.environment}/${var.cell}/certificate.tfstate"
    ) : "environment/${var.environment}/certificate.tfstate"
    region = "us-west-2"
  }
}

locals {
  # The VALIDATED certificate's ARN (certificate/outputs.tf). Empty when there
  # is no public name, and when the certificate stack has not been applied —
  # which the check below says out loud rather than failing a plan.
  public_certificate_arn = local.public_name ? try(
    data.terraform_remote_state.certificate[0].outputs.certificate_arn, ""
  ) : ""
}

check "certificate_stack_applied" {
  assert {
    condition = !local.public_name || (local.public_certificate_arn != "" &&
    try(data.terraform_remote_state.certificate[0].outputs.public_hostname, "") == var.public_hostname)
    error_message = "public_hostname is set, but the certificate stack (deploy/aws/certificate) holds no issued certificate for it. entrypoint.sh applies that stack before every environment apply; apply it (TF_STACK=certificate TF_ACTION=apply) and plan again."
  }
}

# AN ENVIRONMENT MADE BEFORE THE MOVE STILL RECORDS THE CERTIFICATE: these
# FORGET it rather than destroying it, and the certificate stack's first
# apply adopts it (certificate/main.tf, the import block). entrypoint.sh also
# removes the three from this state before a destroy, so a destroy that does
# not honour these blocks still leaves the certificate alone.
removed {
  from = aws_acm_certificate.public
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_route53_record.certificate_validation
  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_acm_certificate_validation.public
  lifecycle {
    destroy = false
  }
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
