# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# A PUBLIC NAME, WHEN `public_hostname` IS SET (deploy/aws/environment/dns.tf).
#
#   test-idp.gcp.iyasec.io  A  <the load balancer's address>
#
# In the foundation's Cloud DNS zone, which Route 53's iyasec.io delegates
# (deploy/gcp/dns-delegation/). An A record and not a CNAME: the load
# balancer has an address and no name.
#
# THE CERTIFICATE IS NOT HERE. On AWS this file requested it; on GCP it is an
# ACME certificate node-a obtains at start (deploy/gcp/node-init/cert.sh) and
# keeps in the foundation's secret, because Google releases no private key
# for a certificate it issues.
#
# NO PRIVATE ZONE FOR THE SERVICE CALLING ITSELF, which AWS needed (#311):
# a passthrough load balancer's address is configured LOCALLY on every
# backend VM by the guest agent, so a node dialling its own public name is
# answered by itself without leaving the VM, and no rule has to admit it.
# ---------------------------------------------------------------------------
# A CELL WRITES NO RECORD HERE (#97): its public name is in Route 53, in the
# tree deploy/multicloud/interconnect writes over every cell of both clouds.
resource "google_dns_record_set" "public" {
  count        = local.public_name && !local.multi ? 1 : 0
  managed_zone = data.google_dns_managed_zone.public[0].name
  name         = "${var.public_hostname}."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_address.lb.address]
}
