# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# `globalidp` ON AZURE — THE THREE-REGION CLUSTER (#96): one cell per
# continent, the three jurisdictions #97 chose — zwus2 (westus2, `us`, the
# primary), zgwc (germanywestcentral, Frankfurt, `eu`, the EU 27 and IS, LI
# and NO pinned) and zsea (southeastasia, Singapore, `sg`, SG pinned) —
# behind global-idp.azure.iyasec.io.
#
# The cells are `globalidp.cells.tfvars.json`; the rest is testidpna's.
# ---------------------------------------------------------------------------
# The PUBLIC NAME is in the cells file, which the foundation and the
# global/ stack read too: global-idp.azure.iyasec.io.
acme_email = "tester1@iyasec.io"

extra_environment = {
  STS_DOMAIN                       = "iyasec.io"
  KRB5_REALM                       = "IYASEC.IO"
  KRB5_SERVICE_PRINCIPAL           = "HTTP/global-idp.azure.iyasec.io"
  STS_SPIFFE_TRUST_DOMAIN          = "iyasec.io"
  STS_WORKERS_START_TIMEOUT_MS     = "300000"
  STS_WORKERS_HEAP_LIMIT_MB        = "-1"
  STS_PERSISTENCE_MINTED_RETENTION = "7200000"
  # AWS globalidp's choice (rcbj, 2026-09-30), for this environment's three
  # jurisdictions: a session may be held in any other one. Delete it to test
  # #98 D4's strict default.
  STS_CELL_PERMITTED_TRANSFERS = "us>eu,us>sg,eu>us,eu>sg,sg>us,sg>eu"
}

sts_mode                = "product"
workers_request_count   = 2
workers_surface_count   = 0
workers_dispatch        = "*"
workers_read_your_write = true

vm_size = "Standard_D2s_v5"

tags = {
  ManagedBy = "terraform"
  Stack     = "iya-sts-environment"
  Lifecycle = "test-case"
}
