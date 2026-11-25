---
title: "the audit log is append-only in the database"
kind: added
issue: 1616
---

Where the audit log is stored (product mode on PostgreSQL or MariaDB, or
any deployment with request workers or several nodes), each event is now one
sealed row of a table of its own, `sts_audit`. The database role the service
connects as may add rows and read them, and may not change or delete one
(ASVS 5.0.0 16.4.2). Until 1.2.0 the log was kept with sessions and tokens,
where that role could rewrite it: the keyed checksums showed a change, and
nothing stopped one.

Old rows leave through two functions the table's owner owns. Retention runs
every ten minutes (the `audit.retain` scheduler job), removes what is past
each realm's `audit.maxEvents`, and keeps at least 1000 rows per realm
whatever the service asks. A removed realm's rows go once the realm is gone.
The audit page shows each realm's newest `audit.maxEvents` events across
every process.

A data key that audit rows are sealed under is no longer destroyed while
they remain, because those rows cannot be re-encrypted. Retention removes
them, and then the key can go.

If the service's role can still change the table (it owns it, or holds
`UPDATE`, `DELETE` or `TRUNCATE` on it), the service starts, logs
`STS-AUDIT-0019`, and `/admin/mode` reports the requirement as not met.

**Upgrading from 1.1.** Run the upgrade script as the table owner **before
starting the 1.2.0 image**. It creates `sts_audit` and its two functions,
gives the application role `SELECT` and `INSERT` on it and nothing more, and
records schema version 33. On MariaDB it also replaces the application
account's database-wide grant with one grant per table, because MariaDB
cannot take one table out of a database grant. A 1.2.0 image started first
does not start: its role cannot create the table (`STS-STORE-0029`, naming
the script). At its first start the 1.2.0 service copies the audit rows the
old log held into `sts_audit`, with their checksums, and removes the old
rows. The commands are the ones under [the scopes change](#behaviour-change-a-client-that-declares-no-scopes-is-issued-openid-alone).
A new install gets everything from `postgres/schema.sql` or
`mariadb/schema.sql`.
