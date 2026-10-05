# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# THE PUBLIC CERTIFICATE, IN A STACK THAT AN ENVIRONMENT DESTROY NEVER TOUCHES
# (rcbj, 2026-10-01).
#
# It was environment/dns.tf's, so every destroy deleted it and every apply
# requested a new one. It is an EXPORTABLE certificate (`options { export }`,
# which is how a node gets its private key — environment/dns.tf argues why),
# and an exportable certificate is BILLED PER ISSUANCE: re-issuing one on each
# build was the single largest line item of September's AWS bill. So it lives
# here, one state per environment (and per cell — an ACM certificate is
# regional), and:
#
#   * entrypoint.sh applies this stack before every environment apply, and an
#     apply of an unchanged certificate changes nothing and costs nothing;
#   * the environment reads the ARN from this stack's state (environment/
#     dns.tf, terraform_remote_state) and owns no certificate;
#   * an environment destroy, single-cell or multi-cell, does not destroy this
#     stack, and entrypoint.sh REFUSES `TF_STACK=certificate TF_ACTION=destroy`
#     unless STS_DESTROY_CERTIFICATE=yes says that is really meant;
#   * the first apply ADOPTS a certificate that already exists rather than
#     requesting another: entrypoint.sh finds an issued, exportable ACM
#     certificate for the name and passes its ARN as `adopt_certificate_arn`,
#     and the import block below takes it into this state.
#
# A change that forces a NEW certificate (the name, a cell's console name
# added to the SANs, the key algorithm) still replaces it — create first, so
# the old one serves until the new one has validated. That is one issuance per
# real change, not one per build.
# ---------------------------------------------------------------------------
locals {
  public_name = var.public_hostname != ""
  # A cell's certificate also names its own console name (#361), which the
  # node presents to a browser that asked for it (environment/dns_cells.tf
  # computes the same name for the record).
  cell_console_host = local.public_name && var.cell != "" ? "${var.cell}.${var.public_hostname}" : ""
}

variable "adopt_certificate_arn" {
  description = <<-EOT
    The ARN of an existing exportable certificate to take into this state on
    its first apply, instead of requesting a new one. entrypoint.sh sets it
    when this state holds no certificate and ACM holds an issued, exportable
    one for public_hostname; empty otherwise.
  EOT
  type        = string
  default     = ""
}

import {
  for_each = local.public_name && var.adopt_certificate_arn != "" ? { "0" = var.adopt_certificate_arn } : {}
  to       = aws_acm_certificate.public[tonumber(each.key)]
  id       = each.value
}

data "aws_route53_zone" "public" {
  count        = local.public_name ? 1 : 0
  name         = var.public_zone_name
  private_zone = false
}

resource "aws_acm_certificate" "public" {
  count                     = local.public_name ? 1 : 0
  domain_name               = var.public_hostname
  subject_alternative_names = local.cell_console_host != "" ? [local.cell_console_host] : []
  validation_method         = "DNS"
  key_algorithm             = "EC_prime256v1"
  tags                      = { Name = var.public_hostname }

  # Without this ACM will not release the private key, and a node cannot
  # present the certificate (environment/dns.tf). ACM cannot change it on an
  # existing certificate.
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

# The validation records are free, and overwriting is what lets an adopted
# certificate's records (left in the zone by the environment that made it)
# be taken over rather than refused as already existing.
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
