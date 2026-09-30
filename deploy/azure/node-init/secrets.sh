#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# File: deploy/azure/node-init/secrets.sh
#
# ---------------------------------------------------------------------------
# KEY VAULT → AN ENV FILE THE NEXT CONTAINER TAKES AS --env-file
# (deploy/gcp/node-init/secrets.sh, against Key Vault).
#
#   STS_SECRET_MAP   NAME=<secret name>, comma-separated
#   STS_SECRET_OUT   the file to write, on a tmpfs (/run/sts)
#   STS_VAULT_URL    the environment's vault
#
# Written ATOMICALLY and 0600: a partly written file would start a container
# with half its secrets. A value holding a newline is refused, because an env
# file has one variable per line and the rest of it would become a variable
# of its own.
# ---------------------------------------------------------------------------
set -euo pipefail
. /usr/local/lib/sts/lib.sh

: "${STS_SECRET_MAP:?STS_SECRET_MAP is required}"
: "${STS_SECRET_OUT:?STS_SECRET_OUT is required}"
: "${STS_VAULT_URL:?STS_VAULT_URL is required}"
: "${AZURE_CLIENT_ID:?AZURE_CLIENT_ID is required}"

umask 077
tmp="$(mktemp "${STS_SECRET_OUT}.XXXXXX")"
trap 'rm -f "${tmp}"' EXIT

IFS=',' read -r -a pairs <<< "${STS_SECRET_MAP}"
for pair in "${pairs[@]}"; do
  name="${pair%%=*}"
  secret="${pair#*=}"
  attempt=0
  # RETRIED, because a VM can start while its identity's grant on the vault
  # is still propagating (Azure RBAC is eventually consistent), and — in a
  # cell — before the global/ stack's copy is readable.
  until value="$(sts_secret_read "${secret}")"; do
    attempt=$((attempt + 1))
    if [ "${attempt}" -ge 20 ];
    then
      echo "sts-secrets: could not read ${secret} for ${name}." >&2
      exit 1
    fi
    sleep 15
  done
  case "${value}" in
    *$'\n'*)
      echo "sts-secrets: ${secret} holds a newline; ${name} cannot be an env-file line." >&2
      exit 1
      ;;
  esac
  printf '%s=%s\n' "${name}" "${value}" >> "${tmp}"
  # The name, never the value.
  echo "sts-secrets: ${name} from ${secret}."
done

mv -f "${tmp}" "${STS_SECRET_OUT}"
trap - EXIT
echo "sts-secrets: wrote ${STS_SECRET_OUT}."
