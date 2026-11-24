# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ---------------------------------------------------------------------------
# `testpep` on Azure: a remote PEP cluster of two members in front of the
# companion's /pep-app, pulling from Azure's testidp at its public name
# (#1284, deploy/aws/pep-cluster/envs/testpep.tfvars's counterpart).
#   TF_STACK=pep-cluster IMAGE_TAG=<tag> deploy/azure/terraform-local.sh testpep apply
# ALLOWED_CIDR unset admits this host's current address, as for testidp.
# testidp must admit this environment's `egress_ip` in its own ALLOWED_CIDR.
# The foundation must list `testpep` in `pep_environments` (its default).
# ---------------------------------------------------------------------------
idp_url         = "https://test-idp.azure.iyasec.io"
public_hostname = "test-pep.azure.iyasec.io"
vnet_cidr       = "10.62.0.0/16"
instance_count  = 2
companion       = true
acme_email      = "tester1@iyasec.io"
