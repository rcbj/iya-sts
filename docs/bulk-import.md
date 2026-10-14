---
title: Bulk directory import
nav_order: 14
---

# Bulk directory import

Adding people one LDAP add at a time is bounded to a few hundred a second,
because every add makes a protocol round trip, claims, a flush transaction,
change-log rows and replication to every process. At that rate, two hundred
million people take a month. The bulk import loads people from an LDIF file
straight into the PostgreSQL store, thousands a second. It leaves every row
exactly as an LDAP add by an administrator would have left it.

**It runs with the service stopped.** It is a command in the service's image,
configured exactly as the service is.

## Running it

1. **Stop every node and every request worker.** The import refuses to start
   while any process of the service has reported into the change log in the
   last 60 seconds (`STS-LDAP-0153`). It asks again before every batch.
2. **Run the import in the image**, with the service's own environment: the
   same `CONFIG_FILE`, `STS_DATABASE_URL` or password provider, database TLS
   settings and key-encryption key settings.

   ```bash
   docker run --rm --network <the stack's network> \
     --env-file <the service's environment> -v "$PWD:/import:ro" \
     iyasec/iya-sts node persistence/bulk_import.js \
       --file=/import/people.ldif [--realm=<id>] [--batch=5000] \
       [--skip=<records>] [--report=/import/report.json]
   ```

3. **Start the service again.** Every process reads the store as it is, so
   nothing has to be told about the new people.

| Argument | Meaning |
|---|---|
| `--file` | The LDIF file (RFC 2849). It is read as a stream, so its size does not matter. |
| `--realm` | The trust realm whose `ou=users` the people go under. The default realm when omitted. |
| `--batch` | Records per transaction, from 1 to 50,000. The default is 5,000. |
| `--skip` | Records to pass over without asking the store. This is for resuming (see below). |
| `--report` | Where the JSON report goes. Standard output when omitted. |

**Exit status:**
- 0: every record was imported or was already there.
- 3: done, but some records were not imported. The report says which kinds and lists the first twenty.
- 1: stopped or failed.
- 2: usage error.

## What a record may be

Each record is one person directly under the realm's `ou=users`:
- **The DN** is `uid=<name>,ou=users,<the realm's base>`. Its RDN must be a
  plain `uid=` with no escape and no `+`, and the entry's `uid` values must
  include that name (`STS-LDAP-0155`).
- **`objectClass`** must be among `top`, `person`, `organizationalPerson` and
  `inetOrgPerson`.
- **The other attributes** must come from the person attributes of RFC 4519
  and RFC 2798: `cn`, `sn`, `givenName`, `displayName`, `mail`,
  `telephoneNumber`, `title`, `ou`, `employeeNumber`, `manager`,
  `preferredLanguage` and the rest of those two lists.
- **Refused** (`STS-LDAP-0156`):
  - `userPassword` and the certificate and PKCS #12 attributes, because they
    are credentials;
  - the binary attributes `audio`, `jpegPhoto` and `photo`;
  - every operational and `sts…` attribute;
  - a URL value (`name:< url`), an empty value, a NUL byte;
  - a `changetype` other than `add`.

A refused record is counted and skipped, and the rest of the file is imported.

**One entry per person.** A record's names are its RDN value and every `uid`
it carries. A name already held by another entry under `ou=users` is not
imported (`STS-LDAP-0160`), and neither is a name held by a record earlier in
the same file. This is the rule an LDAP add enforces. A record whose DN is
already in the directory is counted as **present** and skipped. That is what
makes running the same file twice safe: the second run adds nothing.

## What an imported person is

An imported person is exactly what an administrator's LDAP add makes:
- the record's attributes, plus `createTimestamp` and `modifyTimestamp`;
- a random `entryUUID`, which is the person's `sub` and SCIM id;
- `preferredLanguage` from the realm's locale policy, where the record names
  none;
- the first `mail` as a verified address, because the operator importing the
  file is a trusted source.

The entry is sealed under the realm's current directory data key, and the
directory's counters and data-key counters are kept by the database itself.
Every row's origin is `bulk import`, so the console's directory page counts
what each import made.

## What it does not do

- **No credentials.** An imported person has no password, no Kerberos keys and
  no second factor until one is set through a normal door: the console, the
  management API, SCIM or the portal's activation link.
- **No events.** There is no audit row and no RISC or CAEP event per person,
  and nothing is pushed to outbound SCIM clients. A system downstream that
  needs these people should be loaded with its own full synchronisation. The
  record of an import is its report, the service log, and the `bulk import`
  origin on every row.
- **No groups, no memberships, no updates.** An existing entry is never
  overwritten.
- **No cells, and no `ldif` or memory store** (`STS-LDAP-0151`).

## Size, and resuming

`ldap.maxEntries` applies, read in the realm as an add reads it. The import
stops at the ceiling (`STS-LDAP-0157`) and keeps what it committed. Raise the
setting before a large import.

Every committed batch logs `committed through record R`. A run that stopped
for any reason can be resumed with `--skip=R`. Running again without `--skip`
is also correct, only slower, because every record is checked first.

**On schema version 17, run it as the table's owner.** That schema's name
index keeps a GIN pending list, which the per-batch name check reads in full
every time. The import merges the list after every batch, which needs the
index's owner. As any other role the import says so once (`STS-LDAP-0161`),
never asks, and gets slower as the list grows. Schema 18 has no pending list
on that index.

At the end, the import merges the directory's GIN pending lists and analyzes
the table, so the first sign-ins after a large import do not pay for it. The
merge needs the table's owner; the analyze needs the owner or, on PostgreSQL
17 and later, `MAINTAIN` on the table. The import asks the database what its
role may do before it does either, and skips what it may not, with one line
(`STS-LDAP-0161`). Then have the owner run
`VACUUM (ANALYZE) sts_ldap_entries;`. The analyze never waits for an
autovacuum of the table that is already running; it leaves the statistics
to it.

## Several imports at once

You can run several imports at once against one store, each on its own file,
to load faster than one process can parse and seal.

**What is safe.** Every batch of every import takes the realm's import lock
(a PostgreSQL advisory lock) for its last step: it checks its names against
the store again, inserts, and commits. Imports of one realm therefore check
and insert one at a time, and everything before that step runs side by side:
reading the file, checking the batch once without the lock, and sealing it.
In detail:
- The one-entry-per-person rule holds across imports exactly as it holds
  across the batches of one import.
- The directory's counters and data-key counters stay exact.
- `ldap.maxEntries` is read under the lock, so several imports together stop
  at the ceiling and do not pass it.
- Two imports that make the realm's first directory data key at the same
  moment both keep their key. The store holds both, and the service opens
  what either sealed.
- An import never counts as a running service, so imports do not refuse one
  another. A running service is still refused (`STS-LDAP-0153`).
- The lock does not block autovacuum, so the table is vacuumed while the
  imports run.

**The files should not overlap.** Make them with
`generate-people-ldif.js --start --count`, or split your own file by
person, so that no DN and no username is in two files. If they do overlap,
nothing breaks the rule. A DN in both files is imported once, and the other
import counts it as present. A username proposed by two different DNs is
imported for whichever import reaches it first, and the other import
reports it as taken (`STS-LDAP-0160`). Which import wins a name is a race,
so overlapping files give you a directory that depends on timing.

**Run every import from the same build.** An import from before #637 locks
the table instead, which does not hold an import from this build out of its
check. Two such imports of overlapping files could both admit a name.

**How many.** Start with as many imports as you have cores to spare for
them, and no more than four. Each import's report gives `seconds`,
`lockSeconds` (time holding the lock) and `lockWaitSeconds` (time waiting for
it). When `lockWaitSeconds` grows to a large share of `seconds`, the imports
are queueing for the lock and another one will not help. At that point the
database's insert is the limit, not the import.

## Making a test file

`tests/tools/generate-people-ldif.js --count=N [--start=K] [--stamp=S]
[--base=dc=example,dc=com] [--out=file]` writes N synthetic people in the
shape the LDAP load tool adds (`load-<stamp>-<n>`). Use `--start` to make a
large load as several files that do not overlap.
