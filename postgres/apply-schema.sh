#!/usr/bin/env bash
#
# File: postgres/apply-schema.sh
#
# ---------------------------------------------------------------------------
# RUN postgres/schema.sql ONCE, ON THE START THAT CREATES THE CLUSTER.
#
# `docker-entrypoint.sh` runs initdb, brings a TEMPORARY server up on a unix
# socket, runs everything in /docker-entrypoint-initdb.d in sorted order, stops
# it, and only then starts the real server — which is the same mechanism
# `require-tls.sh` uses, and this file sorts after it (`00-` then `10-`).
#
# **WHY A SHELL SCRIPT AND NOT THE .sql FILE MOUNTED STRAIGHT IN.** The
# entrypoint runs a `.sql` file with `psql -f` and no `-v`, so a schema file
# dropped in that directory takes its defaults and there is no way to hand it
# the role name and password this stack was started with. This wrapper is the
# three lines that turn two environment variables into two psql variables. The
# SQL stays a plain file an operator can run by hand, which is the whole point:
# ONE copy of the DDL, run identically by a person and by the image.
#
# **IT RUNS ONLY ON A FRESH VOLUME, AND THAT IS THE TRAP WORTH KNOWING.**
# Everything in /docker-entrypoint-initdb.d is skipped when the data directory
# already has a cluster in it — so a `sts-db` volume created before this file
# existed has the tables and NOT the application role, and the service then
# fails to start with `password authentication failed for user "sts_app"`,
# which names a role that was never created rather than a volume that is old.
# `docker compose down -v` is the answer and costs nothing: what that volume
# holds is the directory, the realm registry and the appconfig overrides, and
# never anything this service minted.
#
# The same applies to a database that is not this stack's: run
# `postgres/schema.sql` against it by hand, once, with psql. See its header.
# ---------------------------------------------------------------------------
set -euo pipefail

SCHEMA_SQL="${STS_SCHEMA_SQL:-/usr/local/share/sts/schema.sql}"

# The application role the service dials with. The defaults are
# docker-compose.yml's, and they are spelt in both places rather than only here
# because the compose file has to put the same values in STS_DATABASE_URL —
# there is no way for it to read one out of this script.
APP_ROLE="${STS_DB_APP_USER:-sts_app}"
APP_PASSWORD="${STS_DB_APP_PASSWORD:-sts_app}"
APP_SCHEMA="${STS_DB_SCHEMA:-sts}"

if [ ! -f "${SCHEMA_SQL}" ];
then
  # FATAL rather than skipped. A stack that came up with no schema and no
  # application role would fail later, in the service's container, as a
  # connection error — which is a long way from the mount that was missing.
  echo "sts-schema: ${SCHEMA_SQL} is not mounted; refusing to start a" \
       "database with no schema and no application role." >&2
  exit 1
fi

echo "sts-schema: applying ${SCHEMA_SQL} to database ${POSTGRES_DB:-postgres}" \
     "as ${POSTGRES_USER:-postgres}."

# ON_ERROR_STOP so that a failed grant is a failed container start rather than
# a database that is up and half-privileged. `--no-psqlrc` because an
# operator's ~/.psqlrc has no business in a container build.
psql -v ON_ERROR_STOP=1 --no-psqlrc \
     --username "${POSTGRES_USER}" \
     --dbname "${POSTGRES_DB}" \
     -v "sts_schema=${APP_SCHEMA}" \
     -v "sts_app_role=${APP_ROLE}" \
     -v "sts_app_password=${APP_PASSWORD}" \
     -f "${SCHEMA_SQL}"

echo "sts-schema: ${APP_ROLE} may read and write the rows in ${APP_SCHEMA} and cannot change it."
