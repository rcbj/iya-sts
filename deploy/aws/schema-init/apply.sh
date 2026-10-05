#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
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
# AND, IN A MULTI-CLOUD ENVIRONMENT (#97) ONLY, one of two more steps after
# the schema — the global tier crossing from RDS to Cloud SQL by PostgreSQL's
# own logical replication (deploy/multicloud/CLAUDE.md):
#
#   STS_DB_PUBLICATION, STS_DB_REPL_USER, STS_DB_REPL_PASSWORD
#       on the global WRITER (AWS's primary cell): the replication role and
#       the publication — every table in the schema but `sts_schema`, which
#       every database seeds with its own row and which would collide
#   STS_DB_SUBSCRIBE_HOST (+ _PORT, _DBNAME), STS_DB_SUBSCRIPTION, and the
#   three above
#       on a GCP cell's COPY of the global tier: the application role made
#       READ-ONLY there (a write to a logical replica diverges it silently,
#       where a physical one refuses), and the subscription made, or
#       re-pointed and refreshed so that a table the writer gained is copied
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

# ---------------------------------------------------------------------------
# THE PUBLICATION, ON THE GLOBAL WRITER (#97). Idempotent like the schema:
# the role is made or its password reset, and every table the publication
# does not hold yet is added — so a table a later schema adds is published at
# the next start of the primary cell's nodes. `rds_replication` is RDS's
# grant for a replication login, because RDS's master may not set the
# REPLICATION attribute; anywhere else the attribute is what a walsender asks
# for (the first run of this against a plain PostgreSQL 18 said so).
# ---------------------------------------------------------------------------
if [ -n "${STS_DB_PUBLICATION:-}" ] && [ -z "${STS_DB_SUBSCRIBE_HOST:-}" ];
then
  : "${STS_DB_REPL_USER:?STS_DB_REPL_USER is required with STS_DB_PUBLICATION}"
  : "${STS_DB_REPL_PASSWORD:?STS_DB_REPL_PASSWORD is required with STS_DB_PUBLICATION}"
  echo "sts-schema: publication ${STS_DB_PUBLICATION} for ${STS_DB_REPL_USER}."
  psql --no-psqlrc -v ON_ERROR_STOP=1 \
       -v sts_schema="${APP_SCHEMA}" \
       -v publication="${STS_DB_PUBLICATION}" \
       -v repl_user="${STS_DB_REPL_USER}" \
       -v repl_password="${STS_DB_REPL_PASSWORD}" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'repl_user', :'repl_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'repl_user')
\gexec
SELECT format('ALTER ROLE %I LOGIN PASSWORD %L', :'repl_user', :'repl_password')
\gexec
SELECT format('GRANT rds_replication TO %I', :'repl_user')
WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rds_replication')
\gexec
SELECT format('ALTER ROLE %I REPLICATION', :'repl_user')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rds_replication')
\gexec
SELECT format('GRANT USAGE ON SCHEMA %I TO %I', :'sts_schema', :'repl_user')
\gexec
SELECT format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO %I', :'sts_schema', :'repl_user')
\gexec
SELECT format('CREATE PUBLICATION %I', :'publication')
WHERE NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = :'publication')
\gexec
SELECT format('ALTER PUBLICATION %I ADD TABLE %I.%I', :'publication', t.schemaname, t.tablename)
FROM pg_tables t
WHERE t.schemaname = :'sts_schema'
  AND t.tablename <> 'sts_schema'
  AND NOT EXISTS (SELECT 1 FROM pg_publication_tables p
                  WHERE p.pubname = :'publication'
                    AND p.schemaname = t.schemaname
                    AND p.tablename = t.tablename)
\gexec
SQL
fi

# ---------------------------------------------------------------------------
# THE SUBSCRIPTION, ON A GCP CELL'S COPY OF THE GLOBAL TIER (#97).
#
# READ-ONLY FIRST: schema.sql has just granted the application role its
# writes, and on a logical replica a write is not refused, it DIVERGES the
# copy. The service writes the global tier only through the writer's URL; this
# makes a mistake there an error rather than a silent fork.
#
# A NEW SUBSCRIPTION EMPTIES THE TABLES IT WILL FILL: its initial copy
# inserts every row, and a table that already holds rows (a subscription
# dropped after its slot was lost, and made again) would stop the copy on
# the first duplicate key. It is a replica; the writer is the record.
#
# `sslmode=require`, not verify-full: a Cloud SQL instance cannot be given
# the RDS CA to verify with, so the writer is not authenticated by
# certificate here — the connection runs inside the HA VPN, whose tunnels
# are, and it is encrypted either way (deploy/multicloud/CLAUDE.md).
# ---------------------------------------------------------------------------
if [ -n "${STS_DB_SUBSCRIBE_HOST:-}" ];
then
  : "${STS_DB_SUBSCRIPTION:?STS_DB_SUBSCRIPTION is required with STS_DB_SUBSCRIBE_HOST}"
  : "${STS_DB_PUBLICATION:?STS_DB_PUBLICATION is required with STS_DB_SUBSCRIBE_HOST}"
  : "${STS_DB_REPL_USER:?STS_DB_REPL_USER is required with STS_DB_SUBSCRIBE_HOST}"
  : "${STS_DB_REPL_PASSWORD:?STS_DB_REPL_PASSWORD is required with STS_DB_SUBSCRIBE_HOST}"
  conninfo="host=${STS_DB_SUBSCRIBE_HOST} port=${STS_DB_SUBSCRIBE_PORT:-5432}"
  conninfo="${conninfo} dbname=${STS_DB_SUBSCRIBE_DBNAME:-${PGDATABASE}}"
  conninfo="${conninfo} user=${STS_DB_REPL_USER} password=${STS_DB_REPL_PASSWORD}"
  conninfo="${conninfo} sslmode=require"
  echo "sts-schema: subscription ${STS_DB_SUBSCRIPTION} to" \
       "${STS_DB_PUBLICATION} on ${STS_DB_SUBSCRIBE_HOST} (the password is not shown)."
  psql --no-psqlrc -v ON_ERROR_STOP=1 \
       -v sts_schema="${APP_SCHEMA}" \
       -v sts_app_role="${APP_ROLE}" \
       -v publication="${STS_DB_PUBLICATION}" \
       -v subscription="${STS_DB_SUBSCRIPTION}" \
       -v conninfo="${conninfo}" <<'SQL'
SELECT format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA %I FROM %I',
              :'sts_schema', :'sts_app_role')
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLES FROM %I',
              :'sts_schema', :'sts_app_role')
\gexec
SELECT format('TRUNCATE %s', string_agg(format('%I.%I', schemaname, tablename), ', '))
FROM pg_tables
WHERE schemaname = :'sts_schema' AND tablename <> 'sts_schema'
  AND NOT EXISTS (SELECT 1 FROM pg_subscription WHERE subname = :'subscription')
HAVING count(*) > 0
\gexec
SELECT format('CREATE SUBSCRIPTION %I CONNECTION %L PUBLICATION %I',
              :'subscription', :'conninfo', :'publication')
WHERE NOT EXISTS (SELECT 1 FROM pg_subscription WHERE subname = :'subscription')
\gexec
SELECT format('ALTER SUBSCRIPTION %I CONNECTION %L', :'subscription', :'conninfo')
\gexec
SELECT format('ALTER SUBSCRIPTION %I REFRESH PUBLICATION', :'subscription')
\gexec
SQL
fi

echo "sts-schema: done."
