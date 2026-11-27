#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: deploy/gcp/node-init/secret-files.sh
#
# ---------------------------------------------------------------------------
# SECRET MANAGER → FILES, ONE SECRET A FILE (#1284, deploy/gcp/pep-cluster/).
#
# sts-secrets' sibling for what an env file cannot hold: a PEM key or
# certificate is several lines, and sts-secrets refuses a value with a
# newline. A remote PEP member's assertion key, its listener pair and the
# service's anchor are each a secret of their own, and each lands here as a
# file the PEP container mounts read-only.
#
#   STS_SECRET_FILES   <relative path>=projects/<p>/secrets/<s>, comma-separated
#   STS_SECRET_DIR     where they go: a tmpfs (/run/pep), so nothing is kept
#                      on disk across a reboot
#
# A SECRET WITH NO VERSION IS NOT AN ERROR: the file is simply absent. That
# is the listener pair before provision.sh's second pass (the realm issues it
# only to a registered PEP), and the anchor where the service's certificate
# is publicly trusted. Any other failure is: the member must not start
# without its assertion key, so the unit fails and the PEP does not start.
#
# Each file is written 0600 beside its final name and renamed into place, so
# a container never reads half a key.
# ---------------------------------------------------------------------------
set -euo pipefail
. /usr/local/lib/sts/lib.sh

: "${STS_SECRET_FILES:?STS_SECRET_FILES is required}"
: "${STS_SECRET_DIR:?STS_SECRET_DIR is required}"

umask 077
mkdir -p "${STS_SECRET_DIR}"
IFS=',' read -r -a pairs <<< "${STS_SECRET_FILES}"
for pair in "${pairs[@]}"; do
  rel="${pair%%=*}"
  secret="${pair#*=}"
  case "${rel}" in
    /*|*..*|"")
      echo "sts-secret-files: '${rel}' is not a relative path inside ${STS_SECRET_DIR}." >&2
      exit 1
      ;;
  esac
  path="${STS_SECRET_DIR}/${rel}"
  mkdir -p "$(dirname "${path}")"
  tmp="$(mktemp "${path}.XXXXXX")"
  # RETRIED for IAM's propagation, as sts-secrets is; a 3 (no version) ends
  # the loop at once.
  attempt=0
  while :; do
    rc=0
    sts_secret_read "${secret}" > "${tmp}" || rc=$?
    if [ "${rc}" -eq 0 ] || [ "${rc}" -eq 3 ];
    then
      break
    fi
    attempt=$((attempt + 1))
    if [ "${attempt}" -ge 20 ];
    then
      rm -f "${tmp}"
      echo "sts-secret-files: could not read ${secret} for ${rel}." >&2
      exit 1
    fi
    sleep 15
  done
  if [ "${rc}" -eq 3 ];
  then
    rm -f "${tmp}" "${path}"
    # The path and the secret's name, never a value.
    echo "sts-secret-files: ${rel}: ${secret} has no version yet; left absent."
    continue
  fi
  mv -f "${tmp}" "${path}"
  echo "sts-secret-files: ${rel} from ${secret}."
done
echo "sts-secret-files: wrote ${STS_SECRET_DIR}."
