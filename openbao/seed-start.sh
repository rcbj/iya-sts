#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# Runs the seeder with the database password postgres/db-secrets.sh generated.
# That file appears when the database container starts, which nothing orders
# against this one, so this waits for it, and gives up rather than leaving the
# service waiting on a seeder that can never finish. A value the deployment
# set needs no file at all.
STS_DB_SECRETS_DIR="${STS_DB_SECRETS_DIR:-/run/sts-db-secrets}"
if [ -z "${STS_DB_APP_PASSWORD}" ]; then
  waited=0
  until [ -s "${STS_DB_SECRETS_DIR}/app" ]; do
    waited=$((waited + 1))
    if [ "${waited}" -ge 300 ]; then
      echo "seed-start: no database password in ${STS_DB_SECRETS_DIR}" >&2
      exit 1
    fi
    sleep 1
  done
  STS_DB_APP_PASSWORD="$(cat "${STS_DB_SECRETS_DIR}/app")"
  export STS_DB_APP_PASSWORD
fi
exec node openbao/seed.js
