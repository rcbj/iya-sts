# CLAUDE.md — `postgres/`

**Four files the database container runs, and nothing else. None of them is
run by this service**, and nothing in this repository requires them —
`docker-compose.yml` mounts them into the PostgreSQL image. It was two until
2026-09-06, when the schema stopped being something this service builds for
itself.

| File | What it does |
|---|---|
| `generate-tls.sh` | makes the server key pair on first start, and with `POSTGRES_TLS_PUBLIC_DIR` copies the certificate (never the key) there as `<CN>.crt` on every start |
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
* **The certificate leaves the container through a SECOND volume, and the
  key never does (2026-10-12).** The service verifies the database's
  certificate by default, and a self-signed one verifies only against
  itself, so `POSTGRES_TLS_PUBLIC_DIR=/run/sts-db-ca` (the `sts-db-ca`
  volume) receives `postgres.crt`, which `sts` mounts read-only and names in
  `STS_DATABASE_TLS_CA_FILE`. The key stays in `/var/lib/postgresql/tls`,
  inside `sts-db`, which only this container mounts — sharing the TLS
  directory itself would have handed `sts` the key. It is a mount at
  `/run`, NOT under `/var/lib/postgresql`, for the reason the bullet above
  gives. Copied on every start, after a generation or not, and written to a
  hidden temporary name and renamed, so a restored data volume and a fresh
  share agree and a reader never sees half a file. **It exists by the time
  `sts` starts**: the copy runs before `exec docker-entrypoint.sh`, and `sts`
  waits for `service_healthy`. One file per CN, so the cells test layer's
  `postgres-global` and `postgres-cellb` (which `extends` this service and
  inherits the volume and the variable) write beside it without a race.
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

## The server's settings, on the command line (#630, 2026-10-14)

**From measuring 8081 under the LDAP bulk load** (`load-users/dbperf/` on
the host). `docker-compose.yml` passes them after `max_connections`; it
carries no comments, so the reasons are here. `docs/docker-compose.md`
lists them for a user.

**THE SAME LIST IS IN `docker-compose-quick.yml` AND
`docker-compose-run-tests.yml` (#633)**, and in the copy of the quick file
that `docs/getting-started.md` prints. #630 changed only the first file, so
the quick start and the suite ran the defaults it had measured against, the
quick start with 100 connections. `tests/postgres_schema.js` now holds all
four to one list, name and value, so a setting changes in every file or the
test fails. The cells layer's two extra databases `extends` the suite's, so
they carry it too.

* **`shared_buffers=2GB`** (`STS_POSTGRES_SHARED_BUFFERS`): the default 128 MB
  against a 9.4 GB database read at a 96.9% hit ratio. A variable because
  the test stacks run up to three of these on one machine (the cells layer
  `extends` this service); it is a ceiling, not memory taken at start.
  Launchers set nothing, so no `COMPOSE_ENV` row is owed.
* **`max_wal_size=8GB`, `checkpoint_timeout=15min`**: every checkpoint was
  a REQUESTED one (the WAL filled), each followed by a burst of full-page
  images.
* **`wal_compression=lz4`**: 4.4 full-page images an add.
* **`max_parallel_workers_per_gather=0`**: the batched directory lookups
  went parallel and tripled the server's CPU for nothing; the service's
  statements are small and many.
* **`track_io_timing=on`, `log_lock_waits=on`**: what the analysis had to
  infer from wait sampling, recorded.
* **`pg_stat_statements` and `auto_explain` preloaded**, with the analysis's
  exact settings (`track=all`, `max=10000`; plans over 200 ms logged with
  `analyze`, `buffers` and nested statements, without per-node timing,
  which is the expensive part of `analyze`). `schema.sql` creates the
  extension, in `public`, only where the running role may — a superuser
  here, RDS's master user there — and warns and goes on otherwise. **The
  application role gets no `pg_read_all_stats`**, as it gets no
  `pg_monitor` (`persistence/CLAUDE.md`, the metrics page): the view is for
  the owner, and the service reads none of it.

**THEY TAKE EFFECT AT THE CONTAINER'S NEXT START** (every one is a server
start parameter, and `shared_preload_libraries` cannot change any other way);
nothing in the `sts-db` volume changes, and a stack started before this keeps
the old values until it is restarted.

**RDS IS NOT DONE**: `deploy/aws/environment/rds.tf` and
`deploy/aws/global/database.tf` still set only the TLS parameters. RDS's own
defaults already size `shared_buffers` from the instance's memory and load
`pg_stat_statements`, but `auto_explain`, `wal_compression`,
`max_parallel_workers_per_gather`, `checkpoint_timeout`, `max_wal_size` and
`log_lock_waits` would be parameters of those groups (`pending-reboot` for
the preload), and want a reboot window and an instance-sized
`max_wal_size` — a decision for the next AWS apply, not a change made blind.

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
upsert (`cluster/cluster_counters.js`) — and version 18 (#618 phase 2) two
partial indexes in place of two whole ones, and no table
(`persistence/CLAUDE.md`, *Only the asked names and the group classes are
indexed*); `sts_app` holds
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

**AN INDEX A LATER VERSION REPLACED IS DROPPED BY THE SAME RUN (#618,
version 18).** `schema.sql` builds `sts_ldap_entries_asked_names` and
`sts_ldap_entries_group_classes` and only then drops
`sts_ldap_entries_attr_names` and `sts_ldap_entries_classes`, the driver's
`SCHEMA_RETIRED`, so no question is ever without an index; leaving one
behind would keep its write cost, which is what the version removes. Both
builds read the whole table once under the `SHARE` lock `CREATE INDEX` takes
(seconds at 1.2M entries), inside the script's transaction. **Run it before
the version-18 image starts**, which cannot build the indexes as `sts_app`
and is refused; a version-17 process still running meanwhile answers its
holder and group questions without an index until it is replaced.
`tests/postgres_schema.js` holds the drops to `SCHEMA_RETIRED` and their
order. **The same run switches the directory's six GIN indexes to
`fastupdate = off` and flushes each one's pending list once**
(`gin_clean_pending_list()`, which only the owner may call):
`persistence/CLAUDE.md`, *The directory's GIN indexes have no pending list*.
On 8081 the four lists held ~205,000 tuples each, so the flush is a few
seconds of index writes inside the script's transaction.

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

**VERSION 19 (#630) IS THE SAME UPGRADE, AND MORE THAN COLUMNS.** It shards
the two counter tables (a `shard` column, then a primary key that holds it —
a `DO` block, because the swap must happen once), replaces the two fold
routines under new names and drops the old ones, swaps `sts_minted`'s
`written_at` btree for a BRIN, and sets storage parameters on three tables.
Every statement is idempotent; checked against a real version-17 database
with rows and counters in it, and re-run on it and on a fresh one. The
driver's `SCHEMA_UPGRADES` holds the same statements under the same
conditions (`persistence/CLAUDE.md`).

**VERSION 20 (#639) IS ONE STATISTIC.** `parent_key`'s `n_distinct` set to
100,000 and the one column analyzed: at 50.2M entries ANALYZE's sample saw
one parent, and a parent the planner cannot see was estimated as the whole
realm. The owner's to run (an `ALTER TABLE` and an `ANALYZE`); the driver's
`SCHEMA_UPGRADES` carries it as an ADVISORY step, so a role that does not
own the table is told (`STS-STORE-0083`) and starts — the statements a start
runs no longer depend on it (`persistence/CLAUDE.md`, *`parent_key`'s
`n_distinct`*). Checked on a private stack: a version 19 store with 23
realms, re-scripted as the owner, then the service started on it.

**VERSION 21 (#350) ADDS `sts_sessions`.** Not columns on `sts_minted`:
a session's expiry is `sts_sessions.expires_at`, and `sts_minted.expires_at`
stays NULL so the generic purge cannot end a session. The index row is
written and deleted in the same transaction as the sealed body. The full
in-memory session map stays resident.

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
REQUIRED AT BOTH ENDS* — along with how the server is AUTHENTICATED since
2026-10-12 (verification on by default, the certificate shared as above and
trusted for the database alone through `persistence.databaseTlsCaFile`,
`sslmode=verify-full`), and `/admin/persistence` reporting encryption and
authentication as two facts rather than one tick. Do not argue it again here.

## On a managed database the owner is not a superuser (2026-09-15)

RDS's master user is a member of `rds_superuser` and not a superuser, and
PostgreSQL 16 and later refuse `NOSUPERUSER`, `NOREPLICATION` and
`NOBYPASSRLS` from such a role even when turning them off. `schema.sql` stopped
there on its first run against RDS (issue #51) and rolled the whole schema back.
It now sets all five attributes only as a superuser; otherwise it sets the two a
non-superuser may and **checks** the other three, failing the run if the
application role holds any of them. `deploy/aws/schema-init/` is how that file
reaches RDS: an init container that runs it with psql before each node starts.

