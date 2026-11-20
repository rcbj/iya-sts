---
title: Attribute sources
---

# Attribute sources

An **attribute source** is a SQL database a realm reads people's attributes
from. Values are written onto each person's directory entry, where a token
or assertion can carry them.

A typical use is an HR table holding each person's cost centre and grade.
The source reads that person's row when they sign in and writes
`costCenter` and `employeeType` onto their entry. An attribute claim then
puts `cost_center` in their tokens.

Sources are configured per realm on **Directory → Attribute sources**
(`/admin/attribute-sources`) or through `/admin-api/attribute-sources`.

## What a source says

| | |
|---|---|
| **Database** | PostgreSQL, or MySQL / MariaDB. SQL Server and Oracle come in a later release. |
| **Host, port, database, user** | Where to connect. The connection always uses TLS and always verifies the server's certificate; there is no plaintext option. **Server name** sets the name the certificate is checked against (the host, when empty). |
| **Trusted CA certificates** | The database's trust chain, pasted as PEM. Each source has its own, and the page shows each certificate's subject, expiry and SHA-256 fingerprint. **When a source has its own chain, that chain alone is trusted**, unless you tick *also trust the public roots*. A source with no chain uses the public roots, since it has nothing else to verify against. A chain that doesn't parse, or has an expired or not-yet-valid certificate, is refused (`STS-ATTR-0015`). **CA file** adds a PEM file from this service's disk to the chain. |
| **Password from** | Where the password is read from: `file`, `aws`, `gcp`, `azure` or `vault` (OpenBao), using the same providers as the key-encryption key. Choose `none` for a database that needs no password. The password itself is never stored or shown here. An empty location means the key-encryption key's location, and **field** picks a value out of a JSON secret. |
| **Table or view, key column** | The one row a person has is the row whose key column holds their **key attribute** (`uid` by default, or `employeeNumber`, `entryUUID`, …). If you need a join, create a view in your database. |
| **Columns** | `column=attribute`, one per line: which column is written onto which attribute of the person's entry. |
| **Read** | When a person is read (see below). |
| **On failure** | `keep` (the default): the values already on the entry stand and the sign-in goes ahead. `refuse`: the sign-in is refused. |

Choose a database user that can read only that table or view. The service
only ever sends one statement, `SELECT <columns> FROM <table> WHERE
<key column> = ?`. It builds the statement itself and passes the person's key
as a bound parameter, so nothing typed into the console becomes SQL.

## When a person is read

A source may use any combination of these:

* **sign-in**: at every new session, before the first token or assertion is
  issued. The read is limited by the source's timeout (2 seconds by default).
* **once**: the first time the person signs in after the source is added.
* **schedule**: the `attribute-sources.refresh` scheduler job reads the realm's
  people a page at a time (`attributeSources.refreshBatch` per run) whenever
  the source's interval has passed. **Read everyone now** starts a pass
  straight away.
* **on-demand**: **Read one person now** on the page, or the `refresh-person`
  action.

**Test** connects and reads one person's row without writing anything.

## What is written, and what is not

* **Values from the source replace what the entry holds.** They also replace
  invented development values. A `NULL` column removes the attribute. If there
  is no row for the person, nothing changes.
* **Each attribute has one source.** Naming an attribute that another source
  already writes is refused.
* **Some attributes are never written.** A source can't write:
  * `mail`, whose verification and change notice belong to the mail flow;
  * anything this service keeps (`sts*`, `app*`, `fed*`, `pwd*`, `hoba*`);
  * the entry's identity or structure: `uid`, `objectClass` or the
    operational attributes;
  * group membership (`memberOf`).
* **Each write is recorded on the entry.** `stsAttributeSourced` names each
  attribute a source wrote (`<source>:<attribute>`), and
  `stsAttributeSourceSeen` records when each source last read the person.
* **A change is announced.** When a value changes, the usual change events
  fire: CAEP `token-claims-change` for live tokens that carry it, and RISC for
  an identifier.

To carry an attribute in a token or assertion, add an **attribute claim** on
the claims pages ([the admin console](admin-console.md)).

## Who may configure a source

A realm's own administrators manage that realm's sources, including the host.
**`attributeSources.hostPatterns` is empty by default, which allows any
host.** That means a realm administrator can make this service connect to any
host its network reaches, including internal ones. Set it (for example
`*.hr.example.com`) for every realm whose administrators you don't trust with
that. Only a service administrator can change it.

## Drivers

The PostgreSQL driver is always included. The MySQL / MariaDB driver
(`mysql2`) is optional and is added when the image is built:

```bash
docker build --build-arg STS_CLOUD_SDKS="mysql2" -t iya-sts .
```

A source whose driver is missing is refused with an error that names the
package (`STS-ATTR-0001`).

## Errors

`STS-ATTR-0001` to `STS-ATTR-0014`; see [error codes](error-codes.md). An
error code is recorded in the log and audit trail and never sent to a client.
