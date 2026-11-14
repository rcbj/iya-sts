#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# Sourced by the database container's command, before anything else runs. It
# makes the owner's and the service role's passwords once, the first time a
# stack starts, so that no two stacks share one and neither is written in
# docker-compose.yml. A value the deployment sets wins over the generated one.
#
# The files live on a volume of their own, which the seeder reads to put the
# service role's password in the secret store.
#
# The umask is in a subshell because this file is SOURCED: at the top level it
# would stay in force for generate-tls.sh, whose public certificate the service
# has to be able to read, and for the database itself.
STS_DB_SECRETS_DIR="${STS_DB_SECRETS_DIR:-/run/sts-db-secrets}"
(
  umask 077
  mkdir -p "${STS_DB_SECRETS_DIR}"
  for name in owner app; do
    if [ ! -s "${STS_DB_SECRETS_DIR}/${name}" ]; then
      openssl rand -hex 32 > "${STS_DB_SECRETS_DIR}/${name}"
    fi
  done
) || exit 1
POSTGRES_PASSWORD="${STS_POSTGRES_PASSWORD:-$(cat "${STS_DB_SECRETS_DIR}/owner")}"
STS_DB_APP_PASSWORD="${STS_DB_APP_PASSWORD:-$(cat "${STS_DB_SECRETS_DIR}/app")}"
export POSTGRES_PASSWORD STS_DB_APP_PASSWORD
