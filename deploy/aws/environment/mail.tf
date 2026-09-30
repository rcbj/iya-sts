# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# OUTBOUND MAIL THROUGH AMAZON SES, WHEN `mail_ses_domain` IS SET (#311).
#
# The mail channel (#63, common/CLAUDE.md 3ba) sends through SES v2 with the
# task role's credentials (`mail.transport=ses`); nothing here is a secret.
# What an environment has to supply is an IDENTITY SES will send as, and the
# DNS that proves it:
#
#   aws_sesv2_email_identity   the domain, with Easy DKIM (RSA 2048)
#   three CNAMEs               <token>._domainkey.<domain> → <token>.dkim.amazonses.com
#
# THE DOMAIN IS THE PUBLIC HOST NAME, NOT THE ZONE — `test-idp.iyasec.io`,
# not `iyasec.io` — for two reasons. The DKIM names then fall under
# `*.test-idp.iyasec.io`, which the deployer may already write
# (foundation/variables.tf `public_dns`), so the zone's other records stay out
# of reach; and the zone's own mail (its MX, SPF and DMARC, whoever runs them)
# is not touched. DMARC aligns on the DKIM signature's `d=`, which is this
# domain, so the envelope sender being SES's own does not matter.
#
# THE IDENTITY IS DESTROYED WITH THE ENVIRONMENT, like the certificate: a
# rebuild re-creates it and SES re-verifies it from the CNAMEs, usually within
# minutes. Mail queued before it verifies waits in the outbox and is retried
# by `mail.deliver` (the outbox is the service's, not SES's).
#
# THE ACCOUNT'S SES SANDBOX IS NOT TERRAFORM'S. A sandboxed account sends only
# to verified recipients; leaving the sandbox is a support request made by a
# person. deploy/aws/CLAUDE.md, *Mail*.
# ---------------------------------------------------------------------------
locals {
  mail_ses  = var.mail_ses_domain != ""
  mail_from = var.mail_from != "" ? var.mail_from : "no-reply@${var.mail_ses_domain}"
}

resource "aws_sesv2_email_identity" "mail" {
  count          = local.mail_ses ? 1 : 0
  email_identity = var.mail_ses_domain

  dkim_signing_attributes {
    next_signing_key_length = "RSA_2048_BIT"
  }

  lifecycle {
    precondition {
      condition     = local.public_name && (var.mail_ses_domain == var.public_hostname || endswith(var.mail_ses_domain, ".${var.public_hostname}"))
      error_message = "mail_ses_domain must be public_hostname or a name under it: the deployer may write DNS only there."
    }
  }
}

resource "aws_route53_record" "mail_dkim" {
  count   = local.mail_ses ? 3 : 0
  zone_id = data.aws_route53_zone.public[0].zone_id
  name    = "${aws_sesv2_email_identity.mail[0].dkim_signing_attributes[0].tokens[count.index]}._domainkey.${var.mail_ses_domain}"
  type    = "CNAME"
  ttl     = 300
  records = ["${aws_sesv2_email_identity.mail[0].dkim_signing_attributes[0].tokens[count.index]}.dkim.amazonses.com"]
}
