# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# `testpep` on GCP: two remote PEP members in front of the companion's
# /pep-app, pulling from GCP's testidp at its public name (#1284). AWS's
# testpep (deploy/aws/pep-cluster/envs/testpep.tfvars) on GCP's names.
#   TF_STACK=pep-cluster IMAGE_TAG=<tag> deploy/gcp/terraform-local.sh testpep apply
# ALLOWED_CIDR unset admits this host's current address. testidp must admit
# this environment's `egress_ip`.
# ---------------------------------------------------------------------------
idp_url           = "https://test-idp.gcp.iyasec.io"
public_hostname   = "test-pep.gcp.iyasec.io"
decision_hostname = "decision.test-pep.gcp.iyasec.io"
subnet_cidr       = "10.61.0.0/24"
instance_count    = 2
companion         = true
