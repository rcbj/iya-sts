#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# File: deploy/aws/schema-init/apply.sh
#
# ---------------------------------------------------------------------------
# postgres/schema.sql AGAINST RDS, AS THE MASTER USER, WITH TLS VERIFIED.
#
# The task definition supplies every value and this script supplies none of
# its own, so what it connects to is visible in one place:
#
#   PGHOST, PGPORT, PGDATABASE   the RDS primary's endpoint and database
#   PGUSER, PGPASSWORD           the RDS master user, from the secret RDS
#                                manages (ECS injects the password)
#   STS_DB_APP_USER              the least-privilege role to create or update
#   STS_DB_APP_PASSWORD          its password, from the project's secret
#   STS_DB_SCHEMA                the schema the tables go in (default sts)
#   STS_SCHEMA_SSLMODE           verify-full (the default) or verify-ca —
#                                GCP's Cloud SQL only (deploy/gcp/, #95)
#
# `PGSSLMODE` and `PGSSLROOTCERT` are set here rather than trusted to the
# caller: this is the one connection that carries the master password, and a
# caller that forgot them would send it to whatever answered. A caller may
# choose verify-ca and nothing weaker.
#
# **IT RETRIES THE FIRST CONNECTION**, because a task can start moments after
# RDS reports available and before the endpoint's DNS or security group rule
# has settled. It does not retry the schema itself: `ON_ERROR_STOP` makes a
# failed statement a failed container, and ECS then stops the node from
# starting, which is the point.
# ---------------------------------------------------------------------------
set -euo pipefail

: "${PGHOST:?PGHOST is required}"
: "${PGUSER:?PGUSER is required}"
: "${PGPASSWORD:?PGPASSWORD is required}"
: "${STS_DB_APP_PASSWORD:?STS_DB_APP_PASSWORD is required}"

export PGPORT="${PGPORT:-5432}"
export PGDATABASE="${PGDATABASE:-sts}"
# VERIFY-FULL unless the deployment says verify-ca, and nothing weaker: the
# GCP pattern (deploy/gcp/, #95) runs this same script against Cloud SQL,
# whose server certificate names the instance with a trailing dot libpq does
# not match, and says so with STS_SCHEMA_SSLMODE=verify-ca. The CA is
# verified either way. AWS sets nothing and is unchanged.
case "${STS_SCHEMA_SSLMODE:-verify-full}" in
  verify-full|verify-ca) export PGSSLMODE="${STS_SCHEMA_SSLMODE:-verify-full}" ;;
  *)
    echo "sts-schema: STS_SCHEMA_SSLMODE='${STS_SCHEMA_SSLMODE}' is neither" \
         "verify-full nor verify-ca." >&2
    exit 1
    ;;
esac
export PGSSLROOTCERT=/usr/local/share/sts/database-ca.pem
export PGCONNECT_TIMEOUT=10

APP_ROLE="${STS_DB_APP_USER:-sts_app}"
APP_SCHEMA="${STS_DB_SCHEMA:-sts}"

attempt=0
until psql --no-psqlrc -tAc 'SELECT 1' > /dev/null 2>&1;
do
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge 30 ];
  then
    echo "sts-schema: could not connect to ${PGHOST}:${PGPORT}/${PGDATABASE}" \
         "as ${PGUSER} after ${attempt} attempts." >&2
    psql --no-psqlrc -tAc 'SELECT 1' || true
    exit 1
  fi
  sleep 5
done

echo "sts-schema: applying schema.sql to ${PGHOST}/${PGDATABASE} as ${PGUSER}" \
     "(role ${APP_ROLE}, schema ${APP_SCHEMA})."
psql --no-psqlrc -v ON_ERROR_STOP=1 \
     -v sts_schema="${APP_SCHEMA}" \
     -v sts_app_role="${APP_ROLE}" \
     -v sts_app_password="${STS_DB_APP_PASSWORD}" \
     -f /usr/local/share/sts/schema.sql
echo "sts-schema: done."
