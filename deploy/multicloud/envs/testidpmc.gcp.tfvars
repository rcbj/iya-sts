# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# testidpmc's GCP CELLS (#97): the AWS cells' settings (testidpmc.aws.tfvars),
# in GCP's variables — the must-agree settings (mode, public base URL, the
# names) are the same, or the cluster refuses the node.
#
# The certificate is ACME's for the shared name and the cell's console name,
# through the challenge delegation deploy/multicloud/interconnect writes.
# ---------------------------------------------------------------------------
public_hostname = "test-idp.iyasec.io"
dns_zone_name   = "gcp.iyasec.io"
acme_email      = "tester1@iyasec.io"

extra_environment = {
  STS_DOMAIN                       = "iyasec.io"
  KRB5_REALM                       = "IYASEC.IO"
  KRB5_SERVICE_PRINCIPAL           = "HTTP/test-idp.iyasec.io"
  STS_SPIFFE_TRUST_DOMAIN          = "iyasec.io"
  STS_WORKERS_START_TIMEOUT_MS     = "300000"
  STS_WORKERS_HEAP_LIMIT_MB        = "-1"
  STS_PERSISTENCE_MINTED_RETENTION = "7200000"
}

# THE KEY-ENCRYPTION KEY STAYS THE GLOBAL SECRET (#391). deploy/gcp's
# default is its Cloud KMS key, which an AWS cell cannot use; and every cell
# must name the SAME KEK, because the service stores the KEK's name in every
# wrapped data key and refuses a row whose name differs. So a GCP cell reads
# the global `kek` deploy/multicloud/gcp-global copied from AWS, as an AWS
# cell reads the original. deploy/gcp/environment/kek.tf refuses `kms` in a
# cell; this says it rather than relying on the refusal.
kek_provider = "secret"

sts_mode                = "product"
workers_request_count   = 2
workers_surface_count   = 0
workers_dispatch        = "*"
workers_read_your_write = true

machine_type = "e2-standard-2"

labels = {
  managed-by = "terraform"
  stack      = "iya-sts-environment"
  lifecycle  = "long-lived"
}
