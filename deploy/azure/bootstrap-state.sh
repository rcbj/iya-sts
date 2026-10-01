#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/azure/bootstrap-state.sh
#
# ---------------------------------------------------------------------------
# THE STORAGE ACCOUNT TERRAFORM KEEPS ITS STATE IN, CREATED ONCE (issue #96).
#
# deploy/aws/bootstrap-state.sh's and deploy/gcp/bootstrap-state.sh's
# arrangement on Azure Storage, and NOT managed by Terraform for the same
# reason: it holds Terraform's state, so the stack that would create it has
# nowhere to record having done so.
#
#   iya-sts-terraform-state          the resource group, in the home region
#   iyaststate<subscription, cut>    the account: its name is a FORMULA of
#                                     the subscription (24 characters at
#                                     most, letters and digits), which
#                                     entrypoint.sh repeats — so no stack
#                                     has to be told it
#     tfstate                         the container every stack's key is in
#
# SHARED KEYS OFF: every reader — the backend, the remote-state reads, the
# deployer — authenticates with Entra ID (`use_azuread_auth`) and holds a
# blob data role on the one container (foundation/iam_deployer.tf). No
# public blob access; TLS 1.2 at least.
#
# VERSIONING AND SOFT DELETE are what make a bad apply recoverable: the
# previous state is a previous version for ninety days. The azurerm backend
# locks with a blob lease, so nothing else is needed.
#
# Idempotent: an existing account is left as it is and the settings below are
# (re)applied, which changes nothing when they already hold.
#
# Run with credentials allowed to create a resource group — an administrator,
# once:
#   AZURE_SUBSCRIPTION_ID=<id> deploy/azure/bootstrap-state.sh
# ---------------------------------------------------------------------------
set -euo pipefail

SUBSCRIPTION="${AZURE_SUBSCRIPTION_ID:-$(az account show --query id -o tsv 2> /dev/null)}"
[ -n "${SUBSCRIPTION}" ] || {
  echo "ERROR: set AZURE_SUBSCRIPTION_ID (or az account set --subscription <id>)." >&2
  exit 1
}
REGION="${AZURE_REGION:-westus2}"
GROUP="${STATE_RESOURCE_GROUP:-iya-sts-terraform-state}"
ACCOUNT="${STATE_STORAGE_ACCOUNT:-$(printf 'iyaststate%s' "${SUBSCRIPTION//-/}" | cut -c1-24)}"

az account set --subscription "${SUBSCRIPTION}"

echo "==> Resource group ${GROUP} in ${REGION}."
az group create --name "${GROUP}" --location "${REGION}" \
  --tags Project=STS ManagedBy=bootstrap-state.sh > /dev/null

if az storage account show --name "${ACCOUNT}" --resource-group "${GROUP}" > /dev/null 2>&1;
then
  echo "==> ${ACCOUNT} exists; re-applying its settings."
else
  echo "==> Creating ${ACCOUNT}."
  az storage account create --name "${ACCOUNT}" --resource-group "${GROUP}" \
    --location "${REGION}" --sku Standard_ZRS --kind StorageV2 \
    --min-tls-version TLS1_2 --allow-blob-public-access false \
    --allow-shared-key-access false --https-only true \
    --tags Project=STS ManagedBy=bootstrap-state.sh > /dev/null
fi

az storage account update --name "${ACCOUNT}" --resource-group "${GROUP}" \
  --min-tls-version TLS1_2 --allow-blob-public-access false \
  --allow-shared-key-access false --https-only true > /dev/null

az storage account blob-service-properties update \
  --account-name "${ACCOUNT}" --resource-group "${GROUP}" \
  --enable-versioning true \
  --enable-delete-retention true --delete-retention-days 90 \
  --enable-container-delete-retention true --container-delete-retention-days 90 > /dev/null

# The administrator creating the container needs blob data rights too; the
# role is granted at the account and may take a minute to be honoured.
me="$(az ad signed-in-user show --query id -o tsv 2> /dev/null || true)"
account_id="$(az storage account show --name "${ACCOUNT}" --resource-group "${GROUP}" --query id -o tsv)"
if [ -n "${me}" ];
then
  az role assignment create --assignee-object-id "${me}" --assignee-principal-type User \
    --role "Storage Blob Data Owner" --scope "${account_id}" > /dev/null 2>&1 || true
fi
attempt=0
until az storage container create --name tfstate --account-name "${ACCOUNT}" \
        --auth-mode login > /dev/null 2>&1;
do
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge 12 ];
  then
    echo "ERROR: could not create the tfstate container (a blob data role is needed on ${ACCOUNT})." >&2
    exit 1
  fi
  sleep 10
done

echo "==> Done. The state account is ${ACCOUNT}. Next:"
echo "    terraform -chdir=deploy/azure/foundation init" \
     "-backend-config=subscription_id=${SUBSCRIPTION}" \
     "-backend-config=resource_group_name=${GROUP}" \
     "-backend-config=storage_account_name=${ACCOUNT}"
