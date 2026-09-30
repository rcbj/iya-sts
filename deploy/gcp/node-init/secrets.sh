#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# File: deploy/gcp/node-init/secrets.sh
#
# ---------------------------------------------------------------------------
# SECRET MANAGER → AN ENV FILE THE NEXT CONTAINER TAKES AS --env-file.
#
# What ECS's `secrets` did for a task definition: the values reach the
# container as environment variables and are never written into anything a
# person can read by describing the deployment (instance metadata, here).
#
#   STS_SECRET_MAP   NAME=projects/<p>/secrets/<s>, comma-separated
#   STS_SECRET_OUT   the file to write, on a tmpfs (/run/sts)
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

umask 077
tmp="$(mktemp "${STS_SECRET_OUT}.XXXXXX")"
trap 'rm -f "${tmp}"' EXIT

IFS=',' read -r -a pairs <<< "${STS_SECRET_MAP}"
for pair in "${pairs[@]}"; do
  name="${pair%%=*}"
  secret="${pair#*=}"
  attempt=0
  # RETRIED, because a VM can start while its account's new grant on a
  # secret is still propagating (IAM is eventually consistent).
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
