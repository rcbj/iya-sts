# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# testidp ON GCP (issue #95): what differs from the test environments, as
# deploy/aws/environment/envs/testidp.tfvars — the same product mode, workers,
# node size and iyasec.io names, under the GCP sub-domain.
#
# **ITS PUBLIC NAME IS test-idp.gcp.iyasec.io, NOT test-idp.iyasec.io.** AWS
# answers test-idp.iyasec.io and manages iyasec.io; this environment's name
# is in the zone Route 53 delegates to Cloud DNS. One name for both clouds is
# #97's question.
#
# The foundation must list `testidp` with this public_hostname: that is
# what made the certificate's secret and let node-a answer the challenge.
# ---------------------------------------------------------------------------
public_hostname = "test-idp.gcp.iyasec.io"

# The ACME account's contact (expiry notices): an address at iyasec.io, the
# one mail is delivered to for this project.
acme_email = "tester1@iyasec.io"

extra_environment = {
  STS_DOMAIN                       = "iyasec.io"
  KRB5_REALM                       = "IYASEC.IO"
  KRB5_SERVICE_PRINCIPAL           = "HTTP/test-idp.gcp.iyasec.io"
  STS_SPIFFE_TRUST_DOMAIN          = "iyasec.io"
  STS_WORKERS_START_TIMEOUT_MS     = "300000"
  STS_WORKERS_HEAP_LIMIT_MB        = "-1"
  STS_PERSISTENCE_MINTED_RETENTION = "7200000"
  LDAP_WORKER_DIRECTORY            = "postgres-lru"
}

sts_mode                = "product"
workers_request_count   = 2
workers_surface_count   = 1
workers_dispatch        = "*"
workers_read_your_write = true

# 2 vCPU / 8 GB, AWS's 2048 / 8192.
machine_type = "e2-standard-2"

vpc_cidr = "10.52.0.0/16"

labels = {
  managed-by = "terraform"
  stack      = "mock-sts-environment"
  lifecycle  = "long-lived"
}
