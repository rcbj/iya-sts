# attribute-sources/

**Attribute sources (#94 part C, 2026-09-28).** These are the operators' SQL
databases a realm reads people's attributes from. The values are written onto
each person's directory entry, where an attribute claim (#94 part A,
`common/CLAUDE.md` rule 3d) or the catalogue carries them into tokens and
assertions. `docs/attribute-sources.md` is the user's guide; this file is why
the code is the way it is.

| File | What it is |
|---|---|
| `attribute_sources.ts` | The register, the refresh by mode, the sign-in gate's work, the scheduled job, and `view()` / `act()`, which the console and the API both call. A library: it registers no route. |
| `attribute_source_drivers.ts` | Knex, per dialect, with verified TLS. It keeps one pool per source per process, and runs the one parameterised lookup. |
| `attribute_sources_admin.ts` | Directory → Attribute sources (`/admin/attribute-sources`). |
| `attribute_sources_api.ts` | `/admin-api/attribute-sources` and its six actions, spread into `mgmt-api/admin_api.ts`'s table. |

## rcbj's decisions (on #94, 2026-09-28)

1. **Knex is this service's database layer, adopted in phases.** This family
   is the first thing built on it. #326 moves the service's own PostgreSQL
   onto Knex, still PostgreSQL-only. A second database for the service's own
   store is a later ticket, if wanted. It is a query builder, not an ORM: a
   source reads one row of a table somebody else owns, and there is no model
   of it to map here.
2. **No ORM-level cache.** Caches live in `common/cache_registry.js`. The one
   here, `attribute-sources.lookups`, is per process and 30 s long, so a burst
   of sign-ins makes one query.
3. **Structured, no SQL.** A definition names a table or view, a key column,
   the person attribute that key matches, and a column → attribute map. Knex
   builds `SELECT … WHERE <key> = ?` with the key bound, from identifiers
   validated against `IDENTIFIER` / `TABLE`.
4. **Four refresh modes, any of them per source:** `once`, `sign-in`,
   `schedule` and `on-demand`.
5. **On failure, per source, default `keep`.** `refuse` refuses the sign-in
   (STS-ATTR-0012).
6. **Realm administrators may configure sources, host included.**
   `attributeSources.hostPatterns` can narrow the hosts, and **defaults to any
   host**. That setting's description and the guide both warn about it, and
   only a service administrator may write it (`admin_scope.ts`'s
   `SERVICE_SETTING_PREFIXES`).
7. **The databases:** PostgreSQL and MySQL / MariaDB in this step, SQL Server
   and Oracle in the next. Each driver is an optional peer installed at image
   build (`STS_CLOUD_SDKS="mysql2"`). `pg` is always present.

## What a source may write

* **`common/sourced_attributes.ts`'s rule, and `mail`.** The rule refuses
  the attributes this service keeps (`sts*`, `app*`, `fed*`, `pwd*`,
  `hoba*`) and the entry's identity, structure and membership. `mail` is
  refused here as well: its verification and its change notice belong to the
  mail flow. Federation keeps `mail` writable because a partner's `email` is
  its ordinary default target.
* **The rule is checked at definition time and at the write.**
  `problemOf()` refuses the definition (STS-ATTR-0008), and
  `ldap_server.js`'s `applySourcedAttributes()` refuses the write again.
* **One owner per attribute.** A second source naming an attribute is refused
  (STS-ATTR-0009), so which source a value came from is never a race.

## The write, and who hears of it

`ldap_server.js` offers ONE write, `applySourcedAttributes(key, source,
changes)`, through this module's directory slot:
* **It assigns.** The source wins, including over development's invented
  persona values. A NULL column removes the attribute; no row changes nothing.
* **Provenance goes on the person:**
  * `stsAttributeSourced` holds `<source>:<attribute>`;
  * `stsAttributeSourceSeen` holds `<source>=<time>`. It is written only
    when the source had not read the person or a value moved, so a steady
    sign-in is not a directory write.
* **A change fires `noteAccountChange('updated')` once per person.** That
  reaches CAEP token-claims-change, RISC and Provider Commands, as the
  federated write does since #94 part B.

**The directory slot is a module-level holder, not an instance member.**
`ldap_server.js` fills it when it loads, which may come before the composition
root builds this module (18r). A holder outside the instance makes that order
irrelevant.

## The sign-in gate

**`authn.startSession()` is synchronous, and a first-time person has no entry
until it runs**, so the read cannot happen before it. It happens after the
session exists and before the browser is sent back, which is before the first
artifact, because every door hands off with a redirect and the code, token or
assertion is minted on the next request:

* `startSession()` notes the session it made on `res.locals`. Keyed callers
  (SCIM, SPIRE) are excluded.
* `authn.afterSignIn(res, go, refuse)` awaits `refreshAtSignIn()`. A refusal
  ends the session (`dropSession(…, 'policy')`) and calls `refuse`.
* **Where it is called:**
  * `returnToCaller()` calls it, so every sign-in-screen door is covered,
    including the password, the second factors, SPNEGO and the wallet (via
    `completeAuthentication()`).
  * `federation/federation_sp.ts` calls it before its own redirect or result
    page, after the partner's attributes are written, so a source wins over a
    partner for an attribute both name.
  * `tls/tls_server.js`'s `/tls/sign-in` calls it inside the realm the session
    is in, which is the certificate's realm and not necessarily the request's.
* **Grants with no session are refreshed by the schedule and on demand only.**
  These are the password grant, an LDAP bind and WS-Trust, where the token is
  issued before `startSession()`.

## The scheduled refresh

`attribute-sources.refresh` is a cluster job, per realm, every minute
(`cluster/CLAUDE.md`'s table).
* **What one run does:** for each source whose interval is due, or whose Read
  everyone now asked, it reads the next `attributeSources.refreshBatch`
  people after the source's cursor.
* **The cursor** is on the source's status row (`attribute_sources.status`,
  persisted, `retain: 'age'`), and a pass ends when a page comes back short.
* **`ctx.stillOwner()`** is asked between sources.

## What has no test yet

* **No real database.** `tests/attribute_sources.js` holds everything this
  service decides, but with the driver stubbed. A protocol job against a real
  PostgreSQL over verified TLS, and MariaDB in the test stack, are still
  owed. They need a database the runner can create a table in and a CA it
  trusts.
* **The console page** has no browser test.
