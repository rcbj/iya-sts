# CLAUDE.md — `postgres/`

**Four files the database container runs, and nothing else. None of them is
run by this service**, and nothing in this repository requires them —
`docker-compose.yml` mounts them into the PostgreSQL image. It was two until
2026-09-06, when the schema stopped being something this service builds for
itself.

| File | What it does |
|---|---|
| `generate-tls.sh` | makes the server key pair on first start |
| `require-tls.sh` | rewrites every `host` rule in `pg_hba.conf` to `hostssl` |
| `schema.sql` | **builds the schema and the least-privileged role this service dials with.** Plain SQL, idempotent, takes psql variables, and runnable by hand against any database |
| `apply-schema.sh` | runs `schema.sql` once, on the start that creates the cluster, with the role name and password the stack was given |

## How `docker-compose.yml` runs them

Moved here from the compose file's comments on 2026-10-07, when that file lost
them all.

* **`postgres:18`, not `-alpine`**: the alpine image has busybox and no bash,
  and the scripts here are bash. The Debian image already has openssl.
* **One mount, at `/var/lib/postgresql`, not `.../data`.** From 18 the image
  keeps the cluster in a version-specific directory (`/var/lib/postgresql/18/docker`)
  so `pg_upgrade --link` works within one mount, and it REFUSES TO START with
  a volume at the old `.../data` path ("unused mount/volume", which reads as a
  warning and is fatal; docker-library/postgres#1259). The TLS pair lives
  inside that volume (`/var/lib/postgresql/tls`) because a second mount
  under it is the shape the image refuses.
* **`generate-tls.sh` runs from a `command` wrapper, not as an initdb
  script**: `ssl_cert_file` is read when the server boots, and initdb scripts
  run after a first boot. The wrapper `exec`s `docker-entrypoint.sh` so
  postgres keeps pid 1 and gets the stop signal.
* **`require-tls.sh` is `00-` and `apply-schema.sh` is `10-`** in
  `/docker-entrypoint-initdb.d`, so TLS hardening runs first. `schema.sql`
  is mounted OUTSIDE that directory on purpose: the entrypoint runs every
  `*.sql` there itself, with no way to pass the role name and password, so
  it would run a second time with the defaults and undo `STS_DB_APP_PASSWORD`.
* **The service waits on `pg_isready` (`service_healthy`), and the wait is
  not optional**: without it the service starts first about half the time,
  and since 2026-08-28 a configured store that cannot be opened is fatal
  (`persistence/CLAUDE.md`), so the stack restart-loops.
* **5432 is not published**, for the reason 389 and 636 are not: a host
  already running postgres fails to start the stack on a port nobody was
  thinking about.
* **`sts_app` is spelt twice in the compose file** — `STS_DB_APP_USER` and
  inside `STS_DATABASE_URL` — because a connection string is one string and
  building it from the parts would make an override of the whole string
  ambiguous. `tests/postgres_schema.js` notices when they disagree.

## The schema is built by an OWNER and used by somebody who cannot change it

**Until 2026-09-06 the service's own database role had to be able to `CREATE
TABLE`**, because `persistence/persistence_postgres.js` ran its whole schema on
every `open()` — and in this stack that role was the cluster's bootstrap
superuser. A mock identity service that can create a table can also drop one.

So there are two roles now. `sts` owns the tables — seven on 2026-09-13,
when `sts_used_assertions` joined them, and fifteen (counting `sts_schema`)
since the cluster's tables arrived with schema version 5 (#46), and
twenty-eight since the thirteen `sts_risk_*` tables of risk scoring arrived with
version 7 (#62, 2026-09-22), and twenty-nine since `sts_risk_terms_acceptances`
arrived with version 8 (2026-09-23) — version 10 (#262) added a column,
`sts_realms.retiring_at`, and no table, and thirty since
`sts_node_snapshots` arrived with version 11 (#332, 2026-09-28) — which
develop's version 11 also numbers `sts_cell_routing` (#98); the two were
merged on 2026-09-29 and both tables are created by name — and version
12 (#333) added a column, `sts_minted.expires_at`, with the partial index
`sts_minted_expires`, and no table, and version 13 (#349, after #333's
12) six GENERATED lookup columns on `sts_ldap_entries` and seven indexes over
them, for a request worker that holds the people and devices as a window
(`persistence/directory_queries.js`) — and version 15 (#432 phase 5)
`sts_cluster_budgets`, a GNAP right's limits spent with one conditional
upsert (`cluster/cluster_counters.js`); `sts_app` holds
`SELECT`, `INSERT`, `UPDATE` and `DELETE` on them and `USAGE` — not `CREATE` —
on the schema, and is what `STS_DATABASE_URL` dials. `schema.sql` creates both
halves and argues every line of it; do not argue it again here.

**A DATABASE BUILT BEFORE 2026-09-13 HAS NO `sts_used_assertions`, AND THE
SERVICE WILL NOT START AGAINST IT WITH `sts_app`** — the driver probes, finds the
table missing, cannot `CREATE` it, and refuses with `STS-STORE-0029` naming this
file. Running `schema.sql` again as the owner is the upgrade: every statement in
it is `IF NOT EXISTS` or re-runnable, its `GRANT … ON ALL TABLES` covers the new
table, and it writes schema version 4 beside the 3 already there. That was
checked against a real version-3 database rather than reasoned about.
`persistence/CLAUDE.md` and `common/used_assertions.js` argue why the history
is a table of its own rather than a handle in `sts_minted`.

**A COLUMN IS THE SAME UPGRADE, AND ITS INDEX WAITS FOR IT (#333).** A
version-11 database has no `sts_minted.expires_at`; `sts_app` cannot `ALTER`
a table it does not own, so the service refuses with `STS-STORE-0029` until the
owner runs `schema.sql` again, whose `ALTER … ADD COLUMN IF NOT EXISTS` adds it
(existing rows get NULL — no expiry — and fall under the write-age rule once;
there is no other migration). The script creates `sts_minted_expires` after
that `ALTER`, and the driver's own `open()` does the same: an object marked
`afterColumns` in `SCHEMA_OBJECTS` is created after `SCHEMA_COLUMNS`, because
an index on a column an older table does not have yet cannot be built before
it.

**THE DRIVER STILL CREATES WHAT IS MISSING AND THAT IS NOT A CONTRADICTION.**
It probes with `to_regclass` first and issues a `CREATE` only for an object that
is not there, so against a database this script has built it issues none. That
change was not optional: **`CREATE TABLE IF NOT EXISTS` checks `CREATE` on the
schema BEFORE it checks whether the table exists** (PostgreSQL's own
`parse_utilcmd.c` says so in a comment), and `CREATE INDEX IF NOT EXISTS` takes
the table's ownership first — so the old code would have been refused on every
start by six statements that had nothing to do. Measured, not assumed: as
`sts_app`, `CREATE TABLE IF NOT EXISTS sts_keys` against the existing
`sts_keys` fails `42501 permission denied for schema sts`.

**THE INIT SCRIPTS RUN ONLY ON A VOLUME WITH NO CLUSTER IN IT**, which is the
trap this directory now owns: a `sts-db` volume created before that date has the
tables and no `sts_app`, and the service container then restart-loops on
`password authentication failed`. `docker compose down -v` is the answer, and
what it throws away is the directory, the realm registry and the appconfig
overrides — and, in product mode (the compose stack's default), the sealed
signing keys and what this service minted under them.

**`tests/postgres_schema.js` is what keeps `schema.sql` and the driver from
drifting**, since the DDL is now written down twice: it fails on a `CREATE`
either one has and the other does not, on a schema version they disagree about,
on a grant to the application role that is not exactly those four verbs, and on
the role name being changed in one of the three files that spell it.

**The key pair is generated rather than committed, which is the same decision
every other key in this repository follows**: a certificate committed to a
repository is a private key committed to a repository. It is also why this
service's own signing keys are generated rather than shipped — per start in
development mode, once and sealed in product mode (`common/CLAUDE.md`).

**`require-tls.sh` is what makes TLS REQUIRED rather than merely available.** A
server that supports TLS and still accepts a plaintext connection is one
misconfigured client away from sending credentials in the clear; rewriting the
rules means the database refuses, so both ends say it and neither can be quietly
relaxed.

**The argument for both is in `persistence/CLAUDE.md`** — *TLS TO THE DATABASE,
REQUIRED AT BOTH ENDS* — along with the thing this arrangement deliberately does
NOT do: the certificate is signed by nobody, so the connection is encrypted and
the server is not authenticated, and `/admin/persistence` reports those as two
facts rather than one tick. Do not argue it again here.

## On a managed database the owner is not a superuser (2026-09-15)

RDS's master user is a member of `rds_superuser` and not a superuser, and
PostgreSQL 16 and later refuse `NOSUPERUSER`, `NOREPLICATION` and
`NOBYPASSRLS` from such a role even when turning them off. `schema.sql` stopped
there on its first run against RDS (issue #51) and rolled the whole schema back.
It now sets all five attributes only as a superuser; otherwise it sets the two a
non-superuser may and **checks** the other three, failing the run if the
application role holds any of them. `deploy/aws/schema-init/` is how that file
reaches RDS: an init container that runs it with psql before each node starts.

