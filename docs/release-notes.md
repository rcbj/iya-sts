---
title: Release notes
---

# Release notes

## 1.0.1

1.0.1 upgrades a deployment that is already running 1.0.0. Keep the
database volume. The 1.0.0 service can keep answering while the database
is upgraded. Start the 1.0.1 image after the upgrade script exits 0.

A store that is only in memory has nothing to upgrade. A database whose
schema version is below 31 is a pre-release build, and the script refuses
it. Those builds are covered under
[Not backwards compatible with earlier builds](#not-backwards-compatible-with-earlier-builds).

### PostgreSQL

Release 1.0.0's database is schema version 31. 1.0.1 adds two indexes on
`sts_sessions` and records schema version 32 beside it:

* `sts_sessions_started`, so the console's session pages can list sessions
  newest first without sorting the whole table.
* `sts_sessions_subject_band`, used by the per-subject session sweep.

Run the script as the table owner, from a checkout of 1.0.1. On the
compose stack the owner is `sts`. The application role `sts_app` cannot
create an index.

```bash
docker compose exec -T postgres \
  psql -U sts -d sts -v ON_ERROR_STOP=1 \
  -f - < postgres/upgrade-1.0.0.sql
```

Against a database you reach directly:

```bash
psql -v ON_ERROR_STOP=1 -f postgres/upgrade-1.0.0.sql \
     "postgres://owner@host:5432/sts"
```

Do not pass `--single-transaction`. The indexes are built with
`CREATE INDEX CONCURRENTLY`, which PostgreSQL refuses inside a
transaction. For a large `sts_sessions` table,
`-v sts_maintenance_work_mem=1GB` gives this session more memory for the
build and does not change the server. `-v sts_schema=sts` selects the
schema and is the default.

Then start the 1.0.1 image. Until both indexes exist, that image refuses
to open the store and records `STS-STORE-0029`. Run the script and start
it again. Replacing the image before the script does not damage the
volume.

**Leave the volume in place.** `docker compose down -v` deletes the
directory, the realm registry and the setting overrides, and in product
mode the sealed signing keys and everything minted under them.

**Do not run `postgres/schema.sql` again for this upgrade.** On a 1.0.0
database that script rebuilds `sts_ldap_entries_asked_names`, which
version 31 already has, and sets the application role's password again.
`postgres/upgrade-1.0.0.sql` does neither.

A second run finds the indexes already valid and changes nothing else. If
the script stops because an index of one of those names has the wrong
definition, drop that index and run the script again. An index left
invalid by an interrupted build is dropped and built again by the script.

Returning to the 1.0.0 image ignores both indexes. Leave them.

[PostgreSQL schema](postgres-schema.md) records what version 32 adds.

### MariaDB

MariaDB is the [second engine](persistence.md#a-second-engine-mariadb).
Its upgrade adds `sts_sessions_started` and records schema version 32.
`sts_sessions_subject_band` is PostgreSQL only. The build does not block
writers. Run it as an account that can `ALTER` the table,
in the service's database, and pass `--abort-source-on-error`:

```bash
mariadb --abort-source-on-error -u root -p sts \
  < mariadb/upgrade-1.0.0.sql
```

`sts` is that database's name. Use the name from the connection string
when it differs (`sts_store` in the MariaDB example). The same cautions
apply: leave the database in place, and do not run `mariadb/schema.sql`
again, which sets the application account's password on every run. A
second run inserts nothing. A valid index of the wrong shape is left as
it is; drop it and run the script again, then start the 1.0.1 image.

## 1.0.0

1.0.0 is the first release of iya-sts. Every build before it was a
pre-release.

### Not backwards compatible with earlier builds

**1.0.0 is not backwards compatible with the pre-release builds that came
before it.** Moving an existing deployment from a pre-release build to 1.0.0
works in many situations, but there are edge cases with no clean upgrade path.
Stored settings, directory entries, persisted data or client configurations
created by an earlier build may need to be recreated rather than carried
forward.

This is deliberate. The earlier builds were pre-release versions, and we are
not attempting to keep 1.0.0 compatible with them.

**If this causes you trouble, open an issue** on the GitHub repository:
[github.com/rcbj/iya-sts/issues](https://github.com/rcbj/iya-sts/issues). Say
which build you are moving from and what did not carry over.

### Backwards compatibility from here on

**Our goal is backwards compatibility going forward.** Releases after 1.0.0
are intended to upgrade cleanly from 1.0.0 and from each other. The steps
from a running 1.0.0 deployment to 1.0.1 are in
[1.0.1](#101) above. Where a later release cannot upgrade cleanly, its
notes on this page will say so and describe the path.

### Version numbers

A build reports its version as `M.N.O.<build>`. `M.N.O` is the release, and
for 1.0.0 the release build is `1.0.0.0`. Other builds of the same code carry
the UTC time they were built as their build number. After 1.0.0, each change
published from `main` is the next patch release (1.0.1, 1.0.2, …), and a new
minor or major release starts when the repository's `VERSION` file is set to
it. The running service shows its version on the admin console and in its
metadata.
