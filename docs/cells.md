---
title: Several regions (cells)
nav_order: 19
---

# One service in several regions: cells

iya-sts can be deployed as **cells**. A cell is a copy of the whole service in
one cloud region, with its own PostgreSQL, and every cell sits in exactly one
legal **jurisdiction** (`us`, `ca`, `eu`, `sg` and so on). Every cell answers
on the same public name, with the same issuer and the same keys, so a client
cannot tell one cell from another. What differs is where each person's data
lives:

* **A person is homed in one cell.** Their entry, credentials, devices and
  group memberships exist only in that cell's database. Those rows are sealed
  under a key that lives only in that region, and nothing personal is copied
  to another jurisdiction unless the realm has said it may be.
* **Configuration is global.** Realms, settings, applications, policies,
  signing keys, the certificate authority and the routing index have one
  writable database for the whole service, with a read replica in every
  cell.

Without `cells.id` the service runs in **single-cell mode**. It keeps
everything in one database and behaves exactly as it always has.

The design is issue #98, with its decisions D1–D11.
[How cells work](cells-concepts.md) explains each idea with a diagram.
[A cluster in AWS](aws-cluster.md) describes the Terraform that builds cells
in AWS.

## What a person sees

**Signing in away from home.** A person homed in `us` who opens a sign-in
screen at the `eu` cell types their username there. The `eu` cell finds their
home and sends the browser back to the start of the sign-in, pinned to the
`us` cell. From then on the `us` cell runs the whole sign-in, including any
second factor. The password is never read in `eu`. The only cost to the person
is typing their username twice. A federation partner's sign-in works the same
way.

**Holding the session near the traveller.** By default every later request
is relayed to the home cell. That is slower, but no personal data leaves the
home jurisdiction.

A realm can permit a transfer with `cells.permittedTransfers`, for example
`us>ca`. The session is then copied to the cell the traveller reaches, with a
projection of the person that has every credential removed. That cell serves
the session locally. The home cell stays in charge:

* A disable, a password change or a sign-out everywhere at home is pushed to
  that cell.
* That cell asks home again before every refresh or token exchange, and
  whenever its last answer is older than `cells.subjectCheckS`.

> **Warning.** Each entry in `cells.permittedTransfers` decides that personal
> data may be processed in the serving jurisdiction. Add one only where the
> law of both jurisdictions allows it.

**A hard geofence.** With `cells.hardGeofence` on, a person reaching a cell
outside their home jurisdiction (and not permitted by a listed transfer) is
refused there rather than relayed.

**If home cannot be reached.** With `cells.homeUnreachable=fail-closed`, the
default, a sign-in or refresh for someone homed in an unreachable cell is
refused. `fail-open` lets a session held elsewhere be refreshed for up to
`cells.failOpenGraceS`.

> **Warning.** In `fail-open`, a disable or revocation made at home during the
> outage is not seen until home answers again.

## What a client sees

Nothing new. Codes, refresh tokens, device codes, CIBA ids, pushed request
references, SAML artifacts, OpenID4VC transactions, GNAP handles and ACME
identifiers each carry a short keyed tag of the cell that minted them. A
client may present one at any cell; it is relayed to the right one. The tag
names no cell to anyone without the service's key. Access tokens verify
against the same JWKS in every cell.

## Settings

| Setting | What it does |
|---|---|
| `cells.id`, `cells.jurisdiction` | This cell, and its jurisdiction. Empty `cells.id` means single-cell mode. |
| `cells.peers` | Every other cell as JSON: `[{"id","jurisdiction","url"}]`. The URL is a private inter-cell address. It is never published: only administrators see it, on the Cells page and in `/admin-api/cells`'s settings. |
| `cells.port`, `cells.hostname` | The inter-cell listener: mutual TLS 1.3, and the name its certificate carries. |
| `persistence.globalDatabaseUrl`, `persistence.globalDatabaseReadUrl` | The global tier's writer and this cell's replica. |
| `persistence.globalDatabasePassword*` | The global tier's password, read from a secret store. |
| `keys.cellKek*` | This cell's own key-encryption key. It is required in product mode and has no fallback. |
| `cells.homeCell`, `cells.jurisdictions` | Per realm: where a new person is homed by default, and which jurisdictions people may be homed in. |
| `cells.permittedTransfers`, `cells.hardGeofence` | Per realm: the loosenings of the strict default, and the refusal instead of a relay. |
| `cells.homeUnreachable`, `cells.failOpenGraceS`, `cells.subjectCheckS` | How a cell behaves when a person's home cannot be reached, and how often it re-confirms a session it holds for someone homed elsewhere. |
| `cells.delivery*` | How the pushes between cells (revocations, changed projections) are retried. |

A cell refuses to start when:

* its settings are inconsistent;
* there is no global database;
* the signing keys are not persisted, or there is no operator key-encryption
  key;
* `global.publicBaseUrl` is not set;
* it is in product mode and has no cell key.

`docs/error-codes.md` lists every `STS-CELL-*` code.

## Seeing every cell from one console

The console you sign in to is one cell's: the shared public name goes to
whichever cell is nearest. Two things let you see the rest:

- **Monitoring → Cluster** lists this cell's nodes, then **every other
  cell's** — its running nodes (a node restarted under the same name is
  shown once, with how often it restarted), its leases and its worker pools,
  asked over the inter-cell channel when the page is drawn. A cell that does
  not answer is shown as unreachable, with the reason. `GET
  /admin-api/cluster` answers the same (`status.otherCells`). Names and
  counts only: no cell's addresses cross.
- **Server configuration → Cells** links **each cell's own console**, at an
  address that reaches that cell and no other (`cells.consoleUrl`; on AWS
  `https://<cell>.<public name>`). The console there signs you in at that
  address and shows that cell. This page is the one place a cell's address
  is shown.

## Where people live, and moving them

* **A new person** is homed in the realm's `cells.homeCell`, or in the cell
  that creates them. The console, `/admin-api/users/create` and SCIM
  (`urn:ietf:params:scim:schemas:extension:iya-sts:2.0:User:homeCell`) can
  name a home, and a creation that names another cell is carried out there.
  A login name is unique in a realm across every cell.
* **Listing people.** The console, `/admin-api`, LDAP searches and SCIM
  lists answer with the serving cell's residents. **Server configuration →
  Cells** can list another cell's residents, and `/admin-api/...?cell=<id>`
  sends a whole management call to another cell. Either is answered only
  where the other cell's release policy permits.
* **Re-homing.** A person is moved by an administrator on **Server
  configuration → Cells**, or with `POST /admin-api/cells/rehome`:
  * everything the person holds is ended first;
  * their entry, devices and group memberships move with their entryUUID
    (their `sub`) kept, and their credentials are sealed again under the
    receiving cell's key;
  * they are removed from the old cell.

## Turning a single-cell deployment into a cell

A service that has been running in single-cell mode keeps everything in one
database. It can become one cell of a new multi-cell service **without losing
anything**: its people, their credentials and devices, its realms and signing
keys, and its whole risk-scoring history. This is a **one-time conversion**,
made by an operator's tool that runs once before the new cells first start:

```bash
node persistence/cell_convert.js --dry-run   # say what would move; change nothing
node persistence/cell_convert.js             # convert
```

Run it inside the service's image, **configured exactly like the cell the
database will become**:

* `cells.id` (`STS_CELL_ID`) is the new cell;
* `persistence.databaseUrl` is the single-cell deployment's database (for
  example, restored from its snapshot), which becomes that cell's own;
* `persistence.globalDatabaseUrl` is the new global database, created empty
  and at the current schema (`postgres/schema.sql`);
* the service key-encryption key (`keys.kek*`) and both password providers
  are the ones the service would use.

The tool makes no change to any other database.

**What moves to the global database:**

* realms and settings;
* signing keys and the certificate authorities;
* the used-assertion history and the cluster's shared secrets;
* applications, policies and every other configuration entry;
* each group's definition and its non-person members;
* the stored state that belongs to the whole service, such as revocations
  and replay caches.

**What stays in the cell:**

* the people, with their credentials and devices;
* each group's person members;
* everything the deployment minted, such as sessions and tokens;
* the audit log;
* every `sts_risk_*` table, untouched.

**The routing index is filled in:** every person the database holds is
recorded as homed in this cell.

It copies first, reads the copy back and compares it, and only then removes
the moved rows from the cell database, so a failure never loses anything.
Running it again is always safe:

* After a partial failure, a re-run finishes the job.
* After a success, it reports the store already converted and changes
  nothing.
* It refuses a global database that already holds another service's realms
  or keys, and it refuses when there is nothing to convert.

Every refusal is an `STS-CELL-020x` code, and the exit status is non-zero.

> **Warning.** Stop the single-cell service before converting, and keep it
> stopped: a process still writing the old database would write global rows
> into it that no cell reads. Take a snapshot first.

## The decisions are policy

Whether a session may be held away from home, whether a request may be
served at all, and whether a cell's people may be listed from another
jurisdiction are all questions to the realm's **issuance policy**. The facts
it receives are:

* the home and serving jurisdictions;
* the client's country;
* whether the realm lists the transfer;
* whether the hard geofence is on.

The built-in rules are the strict default. A realm's own XACML policy can
decide differently; see [XACML](xacml.md).

## What is not placed yet

A Kerberos AS-REQ over TCP or UDP port 88, sent to a cell other than the
principal's home, is answered there. The KDC's socket code belongs to the
parent project, and a hook it would need is recorded in
`kerberos/CLAUDE.md`. Over HTTPS (`/KdcProxy`) the request is placed at home.
