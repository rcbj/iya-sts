# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# ---------------------------------------------------------------------------
# `testidpna` ON AZURE — THE TWO-REGION CLUSTER (#96): AWS's testidpna in
# Azure's regions — zwus2 (westus2, jurisdiction `us`, the primary) and zcnc
# (canadacentral, `ca`, Canada pinned) — behind na-idp.azure.iyasec.io.
#
# WHAT EVERY CELL SETS. The cells themselves — regions, jurisdictions, VNet
# CIDRs, the countries Traffic Manager pins, which one holds the global
# database's writer, and the environment's public name — are
# `testidpna.cells.tfvars.json`, beside this file,
# which the foundation and the global/ stack read too and entrypoint.sh
# reads to know the cells. Applied like any environment, and the entrypoint
# does the rest in order:
#   IMAGE_TAG=<tag> deploy/azure/terraform-local.sh testidpna apply
#   deploy/azure/terraform-local.sh testidpna destroy
#
# A NAME OF ITS OWN, where AWS's testidpna shares test-idp.iyasec.io with
# testidp and cannot run beside it: here each of the three environments can
# stand at once.
#
# Everything else is `testidp.tfvars`'s, for its reasons, and AWS's
# testidpna.tfvars's where a cell differs (no directory window, no surface
# worker, the permitted transfers).
# ---------------------------------------------------------------------------
# The PUBLIC NAME is in the cells file, which the foundation and the
# global/ stack read too: na-idp.azure.iyasec.io.
acme_email = "tester1@iyasec.io"

extra_environment = {
  STS_DOMAIN                       = "iyasec.io"
  KRB5_REALM                       = "IYASEC.IO"
  KRB5_SERVICE_PRINCIPAL           = "HTTP/na-idp.azure.iyasec.io"
  STS_SPIFFE_TRUST_DOMAIN          = "iyasec.io"
  STS_WORKERS_START_TIMEOUT_MS     = "300000"
  STS_WORKERS_HEAP_LIMIT_MB        = "-1"
  STS_PERSISTENCE_MINTED_RETENTION = "7200000"
  # AWS testidpna's #361 choice (rcbj, 2026-09-30): a person's session may be
  # held in the other region, both ways.
  STS_CELL_PERMITTED_TRANSFERS = "us>ca,ca>us"
}

sts_mode                = "product"
workers_request_count   = 2
workers_surface_count   = 0
workers_dispatch        = "*"
workers_read_your_write = true

vm_size = "Standard_D2s_v5"

tags = {
  ManagedBy = "terraform"
  Stack     = "mock-sts-environment"
  Lifecycle = "long-lived"
}
