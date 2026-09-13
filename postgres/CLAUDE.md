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

## The schema is built by an OWNER and used by somebody who cannot change it

**Until 2026-09-06 the service's own database role had to be able to `CREATE
TABLE`**, because `persistence/persistence_postgres.js` ran its whole schema on
every `open()` — and in this stack that role was the cluster's bootstrap
superuser. A mock identity service that can create a table can also drop one.

So there are two roles now. `sts` owns the tables — seven since 2026-09-13,
when `sts_used_assertions` joined them; `sts_app` holds
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
overrides — never anything this service minted.

**`tests/postgres_schema.js` is what keeps `schema.sql` and the driver from
drifting**, since the DDL is now written down twice: it fails on a `CREATE`
either one has and the other does not, on a schema version they disagree about,
on a grant to the application role that is not exactly those four verbs, and on
the role name being changed in one of the three files that spell it.

**The key pair is generated rather than committed, which is the same decision
every other key in this repository follows**: a certificate committed to a
repository is a private key committed to a repository. It is the reason this
service's own signing key is regenerated on every start too.

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
