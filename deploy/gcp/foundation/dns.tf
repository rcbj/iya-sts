# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# THE PUBLIC SUB-ZONE, gcp.iyasec.io (issue #95).
#
# AWS MANAGES iyasec.io AND ALWAYS WILL. This project answers only the
# sub-domain delegated to it: Cloud DNS holds the zone, and an NS record in
# the Route 53 zone names Cloud DNS's name servers
# (deploy/gcp/dns-delegation/, applied by an administrator with AWS
# credentials once this exists). Until that record exists nothing here
# resolves from the internet, and an ACME DNS-01 challenge fails.
#
# HERE AND NOT IN environment/ for the reason AWS's inside zones are in its
# foundation: deleting a zone. An environment writes its records into this
# one zone, and the deployer holds roles/dns.admin on THIS zone only
# (iam_deployer.tf), so it can neither create nor delete a zone.
#
# NO DNSSEC. It would need a DS record in the parent beside the NS record,
# and the parent's signing is AWS's; it can be turned on when iyasec.io is
# signed.
# ---------------------------------------------------------------------------
resource "google_dns_managed_zone" "public" {
  name        = replace(var.dns_zone_name, ".", "-")
  dns_name    = "${var.dns_zone_name}."
  description = "mock-sts (issue #95): delegated from the Route 53 zone of the parent"
  visibility  = "public"

  # Records an environment wrote would otherwise block the zone's deletion
  # and be forgotten by nobody; destroying this is an administrator's act.
  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.apis]
}
