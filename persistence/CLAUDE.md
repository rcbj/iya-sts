# CLAUDE.md — `persistence/`

## What is in here

| File | What it is |
|---|---|
| `persistence.js` | The driver interface, the mode selection, the diff, the flush scheduler, the restore, the appliers, and the status object three surfaces render. A LIBRARY — it registers no route. |
| `persistence_ldif.js` | The `ldif` driver, and the RFC 2849 codec under it. `tests/ldif_codec.js` guards the codec. It deliberately has NO `loadMinted`/`saveMinted`/`purgeMinted`, and the absence is the answer — see below. |
| `persistence_postgres.js` | The `postgres` driver: seven tables, one transaction per flush, and a `pg_notify` that something listens to now. The seventh, `sts_used_assertions` (2026-09-13), is written by ATOMIC CLAIM rather than by the flush — see below. |
| **`persistence_minted.js`** | **What this process MINTS, written down — in product mode, and nowhere else** (2026-09-06). The registry of declared stores, the journal, the seal, the restore. A LIBRARY that is HANDED its driver, which is what lets `tests/minted_persistence.js` drive the whole of it against a stub. |
| **`persistence_replication.js`** | **Several processes against one store** (2026-09-06). The change-log poller, the `LISTEN` client, and the fan-in for the counters. A LIBRARY, handed its driver and its appliers; `tests/replication.js` drives it against a stub. |

## THE METRICS SURFACE, AND THE PROCESS EXIT IT EXPOSED (2026-09-11)

`/admin/database` reports everything PostgreSQL will say about itself, and the
state of the schema this service owns in it. **`persistence_postgres.js` owns
the statements and the console owns none of them**, which is the whole
layering: `admin-ui/` must never hold a connection string — it is a credential
— and must never require `pg`, which is a dependency only this mode needs and
which this directory takes care to require lazily. The console asks
`persistence.databaseMetrics()`, that routes to the active driver, and only a
driver that HAS a database answers.

**`METRIC_PROBES` IS A TABLE AND EVERY ENTRY IS A `SELECT`.** There is no query
box on that page and there must never be one: the role this service dials with
holds INSERT, UPDATE and DELETE on seven tables, so a console that could hand it
a statement would be a console that could empty the directory. Nothing in any
probe is composed from anything a request carries, and
`tests/database_metrics.js` asserts that against the SQL rather than trusting
it — no write verb, no statement separator, no parameter.

**THE STATISTICS VIEWS ARE ASKED FOR ALL THEIR COLUMNS**, which is
`crypto_metadata.js`'s rule one layer out: the shape is the SERVER's and it
moves between major versions. Measured on the two this repository has met —
`pg_stat_bgwriter` has ELEVEN columns on PostgreSQL 16 and FOUR on 18, when the
checkpoint counters moved to `pg_stat_checkpointer`, a view that does not exist
before 17; `pg_stat_wal` nine and five; `pg_stat_database` twenty-eight and
thirty. A probe naming its columns would be wrong on every server but the one
somebody tested, and wrong in the way that reads as a blank cell.

**EVERY PROBE IS RUN, TIMED AND CAUGHT SEPARATELY.** The role is `sts_app` and
not `pg_monitor`; which views that narrows depends on the server version and on
the operator's grants, so one rejection must cost one row on the page rather
than the page. The SQLSTATE is reported beside the message because `42P01` (no
such relation — an older server) and `42501` (insufficient privilege) are
completely different things to do about. **One answer is narrowed WITHOUT
failing**, which is worse and is called out on the page: `pg_stat_activity`
shows another role's backend as a ROW with `state` null and `query` set to the
literal string `<insufficient privilege>` — a value, not an error, which
anything that did not know would draw as somebody's SQL.

### A CHECKED-OUT CLIENT HAD NO ERROR LISTENER, AND THAT WAS A PROCESS EXIT

**This is the defect the metrics work found and it was in the WRITE PATH, not
in the new code.** `pool.on('error')` in this driver covers a client that dies
while IDLE IN THE POOL and its comment is right about why that matters — a mock
identity service must not exit because a database restarted. It does not cover
a client that is CHECKED OUT, and that is not an oversight in this file: it is
what `pg-pool` does. `_acquireClient()` calls
`client.removeListener('error', idleListener)` as it hands the client over,
because from that moment the borrower owns it.

So a connection that died while somebody held it emitted `'error'` on an
EventEmitter with no listener, and node's rule for that is to throw. Measured:
`docker stop` on the database while a page was reading from it exited the
process with `Unhandled 'error' event ... 57P01 terminating connection due to
administrator command`.

**`withTransaction()` has borrowed a client for every flush since this driver
was written**, so a database restarted during one took the service with it —
the failure was simply far rarer than a page somebody opens. `guardClient()`
wraps both call sites and removes its listener before release; leaving it
attached would leak one per checkout onto a client the pool reuses (node warns
at eleven) and would sit beside the idle listener pg puts back, reporting one
dead connection twice.

**The rule it leaves**: in this driver, anything that calls `pool.connect()`
owns that client's errors until it releases it. There are two such call sites
and a third would need this guard too.


## The sentence this directory reverses

Every document in this repository said, in one wording or another, that this
service **persists nothing at all** and that everything is gone on restart. That
was true until 2026-08-27. It is not true now, and the replacement sentence has
to be said exactly, because a half-remembered version of it is worse than either
version:

**Three things persist when a store is configured — and since 2026-09-06 a
FOURTH in product mode on a postgres store, which is everything this process
mints. The two halves have to be said together or the sentence is worse than
either half.**

* **The embedded LDAP directory** — every entry under every realm's base. In
  this service that is also the applications registry, the federation register,
  the SPIFFE registry and the group roster, because those *are* directory
  entries and are not copies of anything kept elsewhere.
* **The trust realm registry** — the rows, their names, descriptions and
  per-realm overrides.
* **The runtime appconfig overrides** — the top of `config.js`'s five layers,
  the one a console Save or `POST /admin-api/config/set` writes.

**In DEVELOPMENT MODE nothing this service MINTS persists, in any store.**
Sessions, access tokens, ID Tokens, refresh tokens, authorization codes,
pre-authorized codes, SAML artifacts, Kerberos tickets, the replay caches, the
statistics and the audit log are all in memory and gone on restart.

**ONE THING A REQUEST WRITES PERSISTS IN BOTH MODES, AND THE ARGUMENT BELOW IS
WHY IT MAY (2026-09-13): THE RFC 7523 / RFC 7522 USED-ASSERTION HISTORY.** The
rule rests on the signing key being regenerated, so that a restored token
verifies against nothing. An assertion is not signed by this service: it is
signed by the CLIENT's key, which is on the application's directory entry, which
persists in every store — so after a restart the assertion still verifies, and
forgetting it was spent is a replay. `common/used_assertions.js` holds it and
this module installs its store in `openStore()`, beside the keystore and the
minted journal and NOT through either: on `postgres` it is its own table
(`sts_used_assertions`) written by one `INSERT … ON CONFLICT` per assertion so
that every process agrees at once, and on `ldif` a file per realm
(`used-assertions-<id>.json`) written before the response leaves. The `ldif`
driver's refusal of minted state is about size and rate, and this file is
bounded by `oauth2.assertionReplayCacheSize` and changes only when an assertion
is presented — its header says so where the refusal is. `memory` keeps it in the
process, and loses nothing a restart would not also lose: every key that could
verify one of those assertions goes with it.

That was deliberate rather than unfinished, and there was one fact behind it:
**the signing key is regenerated on every start.** A token restored from a disk
would verify against nothing, an assertion would be a document nobody can check,
and a statistics file that outlived the key that signed the tokens it described
would be worse than none. The rule was: **what persists is what somebody TYPED,
and what resets is what this process MINTED or COUNTED.**

**IN PRODUCT MODE ON A POSTGRES STORE, ALL OF IT PERSISTS — because the premise
is gone.** `common/keystore.js` generates a realm's signing keys ONCE and reads
them back, encrypted under a key-encryption key from outside the database, which
is why product mode REQUIRES a store. A token restored beside the key that
signed it verifies. So the old rule survives exactly where its reason does:

* **development mode persists nothing it minted**, because the key is
  regenerated there. Unchanged, and the default.
* **product mode on postgres persists all of it**, because the key is not.
* **the `ldif` store persists none of it in either mode**, and says so once at
  startup. It writes WHOLE FILES per flush — right for a directory somebody
  types into, wrong for a session table and an audit ring that change on every
  request. That was refused rather than deferred: the deployment that wants
  durable sessions wants a database.

**EVERY MINTED ROW IS SEALED**, with `keystore.seal()` — the same AES-256-GCM
under the same key-encryption key as `sts_keys`. A session id is a cookie value,
an authorization code is redeemable, a SAML artifact handle is dereferenceable
and a Kerberos long-term key IS the password, so a dump of `sts_minted` must not
be a set of usable credentials. What it costs is that nothing in that table is
queryable by SQL; what wants querying is the directory, which is JSONB and is
not sealed.

**A STORE BECOMES PERSISTENT AT ITS DECLARATION AND NOWHERE ELSE**, which is
`common/CLAUDE.md`'s per-realm rule read a second time and is why this was ~40
one-line edits rather than ~200 call-site edits:

```js
const sessions = realms.map({ persist: 'authn.sessions' });
```

Every mutation of the three shapes already funnels through `set`, `delete`,
`clear` or an array mutator, so naming the store names every write to it.
**What that does NOT name is an edit to an OBJECT the store holds**, and two
stores declared on 2026-09-12 are made of them: `ssf/caep.js`'s and
`ssf/risc.js`'s registers, whose state machines do `row.counts[uri] += 1` on a
row already in the map. Each has a `touch()` that re-sets the key after an edit;
without it the flush would write every row as it was CREATED, and a restart
would put back a session that was never revoked. A new store holding mutable
rows owes the same, and `tests/realm_isolation.js` asserts the two that have it
against a real observer. The same day added `vc_offers.deferredAccessTokens`
(keyed by a digest of the token, never the token) and moved
`spiffe.recordedConnections` from `scope: 'shared'` to a realm's partition — see
`common/CLAUDE.md`'s table of the seven stores that sweep converted.
**A JOURNAL AND NOT THE DIFF NEXT DOOR**, and the two arguments are opposite and
both right: the directory is diffed because `touchDirectory()` is one choke
point that does not say which entry moved and the directory is COLD; these
stores have two to four mutation points each and are HOT, so in postgres mode —
where the flush delay is 0 — a full sweep would stringify the audit ring on
every request that touched it.

`persistence_minted.js` carries all of it at length, including the two
carve-outs: `oauth2.signedMetadataCache` and `xacml_store.parsed` are CACHES,
and a cache is not minted state.

`memory` is still the default. A run that says nothing about persistence behaves
exactly as every run before this existed — which is the whole compatibility
story, and is why not one job in the parent project's suite had to be told about
any of this.

## Why this is not a node-ldapjs feature

It is the first question anybody asks and the answer is that it cannot be.
`ldapjs` is a **protocol** library: a BER codec, a client, and a `Server` that
parses an operation and routes it to a handler you wrote. It ships no storage of
any kind and never has.

`node-ldapjs/lib/persistent_search.js` is a trap on the name — it implements the
LDAP *persistent search* change-notification control, which is about telling a
connected client that something changed, and has nothing to do with a disk.

The store in this service is ours and always was: `ldap/ldap_server.js`'s
`const entries = realms.map()`, a Map of normalised DN to
`{dn, attributes, createdAt, modifiedAt, origin}`.

## Why not a real directory instead

Standing up OpenLDAP beside this service and proxying to it would give
persistence for free, and it would **end the service**. This directory is
schemaless on purpose, accepts any bind, creates a person on first sight of any
name in any protocol, and is written into DIRECTLY by six other modules
(`admin_stats.js`, `applications.js`, `federation.js`, `spiffe_registry.js`,
`scim.js`, `group_claims.js`) as ordinary function calls. Against slapd every
one of those becomes a network round trip against a schema that would refuse
half of what they write.

So the store stays ours, and it learns to write itself down.

## Three modes, and the middle one is the one most people will use

| Mode | What it is |
|---|---|
| `memory` | Nothing is written, nothing is read, this whole directory is inert. **The default.** |
| `ldif` | Local development, where there is no database and nobody wants one. An RFC 2849 LDIF file per realm, plus `realms.json` and `appconfig.json`. |
| `postgres` | The shared store. Three tables, one transaction per flush. |

**LDIF for the directory and JSON for the other two** is a split by kind rather
than a compromise. A directory has an interchange format that predates this
service by thirty years and that every other tool speaks, so the file is
something `ldapadd -f`, `slapadd`, `ldifde` and a reviewer can all read — and
the answer to "how do I get this into a real directory" is "you already have
it". A realm registry and a map of overrides have no such format, and inventing
an LDIF spelling for them would be a private format wearing a public one's
syntax.

**What LDIF costs is `origin`**, this service's marker for how an entry came to
exist. It has no home in the format and rides as an RFC 2849 COMMENT —
`# sts-origin: seed` — immediately above the record. Every other reader ignores
it. The alternative was an invented attribute, which is worse in a way that is
easy to miss: an attribute would be REAL on reload, would appear in search
results, would match filters, and would turn a private marker into directory
content. `tests/ldif_codec.js` asserts both halves.

## The write path goes through one function

`ldap/ldap_server.js` already required every writer to call `touchDirectory()` —
the rule is stated at length above that function and exists because a reverse
index of group membership goes stale otherwise. So there was already ONE choke
point that every add, modify, delete, modifyDN, attribute append and typed
delete passes through, already documented, already enforced by prose, and
already the thing a new writer is told to call. This hangs off it.

The alternative was to instrument the fifteen-odd writers individually with a
"this DN changed" call. It would be more precise and **it would be forgotten**:
a new writer that forgets `touchDirectory()` produces a stale groups claim,
which is bad; a new writer that forgets `persist(dn)` produces an entry that is
in the directory until the process restarts and then is not, which is worse and
takes a day to find.

**What the choke point costs is that it does not say which entry changed**, and
the answer is a DIFF. This module keeps a shadow of what it last wrote — one
`JSON.stringify` per entry — and compares the live stores against it on each
flush. That produces exactly the upserts and deletes a database wants, catches
an entry a writer changed in place, and catches a realm going away: the realm's
whole store is dropped by `realms.map()`'s purge, so there is nothing left to
walk and the shadow is the only remaining record that its rows were written.

### The one bug this has had, and it lived in the shadow

`primeShadow()` is "what the store already holds", and the first flush writes
the difference between it and the live directory. The obvious way to prime it is
from the live directory — and that is exactly wrong, because it declares that
the store already holds everything. **On a first run, where the store is empty
and the live directory is the seeded tree, the first diff came out empty and the
seed was never written down.** The service reported a healthy store, `lastError`
was null, and the tables had nothing in them.

It hid because the two drivers make it look different. The ldif driver rewrites
a whole FILE for any realm the diff touched at all, so the handful of entries
that change just after startup dragged all nineteen into the file and the result
looked correct. Postgres writes exactly the rows in the diff, so the same run
put three rows in the table and it was obvious.

The shadow is now primed only for realms whose contents actually came OUT of the
store. A realm that was seeded rather than loaded gets an empty shadow, so every
one of its entries is new and is written.

## When the flush happens

Both modes schedule; they differ only in the delay.

| Mode | Delay | Why |
|---|---|---|
| `postgres` | 0 | Every change made while handling one request coalesces into ONE transaction that runs the moment that request's synchronous work is done. Write-through at the granularity anybody cares about, and what stops a bulk SCIM import from becoming one transaction per entry. |
| `ldif` | `persistence.writeDelay`, 1500ms | The unit of writing there is a whole FILE. A realm build writes thirteen entries; three of those in one file rewrite is the point of the delay. |

Both flush on the way out: `server.js` traps SIGTERM and SIGINT and calls
`stop()`. `kill -9` sends SIGKILL, which cannot be trapped by anything, and what
that costs is up to `writeDelay` milliseconds in ldif mode and nothing in
postgres mode.

## A failed write is logged and never thrown

The service keeps answering out of memory, `GET /admin/ldap/service` and `/admin/persistence`
both carry the error, and the next flush recomputes the same diff — **the shadow
is only advanced on success**, so nothing is lost by a failure and the retry
needs no queue.

The alternative — refusing the LDAP operation whose write failed — was
considered and rejected: it would make a database outage take down sixteen
protocol families that do not need a database, and no other refusal in this
service is that expensive. This was verified by stopping the database under a
running service: the `POST /admin-api/users/create` succeeded, `/healthcheck`
answered 200, `/admin/ldap/service` reported `healthy: false` with the connection error, and
when the database came back the next change wrote the entry made during the
outage along with the new one.

### IT BINDS NOTHING, AND IT STILL GOES FIRST — THE ORDERING IS A DEPENDENCY

**This moved here from the root `CLAUDE.md`'s *Four modules start listeners*
section when that file was broken up.** That section lists the four modules
whose listeners start from `listen()` rather than at require time; this one
is on it for the same SHAPE of reason and a different specific one.

**THE FIFTH IS `persistence/persistence.js` AND IT BINDS NOTHING, WHICH IS WHY
IT IS WORTH ADDING TO THIS LIST RATHER THAN A LIST OF ITS OWN.** It is here for
the same shape of reason and a different specific one: opening a PostgreSQL
connection pool is ASYNCHRONOUS, and a `require` cannot await. So the store is
opened, and the directory, the realm registry and the saved appconfig overrides
are read back, from `persistence.start()` — which `server.js` calls BEFORE the
HTTP listener binds, and before the four socket families above start.

**It goes first among the five, and that ordering is a dependency rather than
tidiness.** Between binding and restoring, this service would answer
`/oauth2/authorize` out of a seeded directory, `/admin/applications` out of an
empty registry and `/federation/acs/{id}` out of a register with no
relationships in it — and that last one is a SECURITY surface, where "not
configured yet" and "disabled" are the same refusal to a caller and very
different facts. There is no window in which that can happen.


### AND A FAILED OPEN IS FATAL, WHICH IS THE OPPOSITE AND IS NOT AN INCONSISTENCY

`start()` rejects, and `server.js` exits non-zero without binding a listener,
when a CONFIGURED store cannot be opened or read — a database that is not
there, a data directory that cannot be written, a driver that will not load.
The heading above still holds for every write AFTER that.

The two are opposite because the states are. **A running service that loses its
database has already restored everything it was going to restore and is still
telling the truth about what it holds**; refusing its LDAP operations would take
down sixteen protocol families that do not need a database, which is the
paragraph above. **A process that never opened its store is answering out of a
SEEDED directory while presenting itself as the one that was configured** —
every endpoint works, the console draws, and the realms, applications and
federation partners somebody creates are thrown away by the next restart, which
is the restart they will do precisely because they expected the work to survive
it. The fallback was reported on `/admin/persistence` and in the log, and
neither is where anybody is looking while the service appears to be working.

This REVERSES what this repository said until 2026-08-28 — *a mock that refused
to start because a database blinked would be the one failure mode a mock must
not have* — at rcbj's ask, and the reversal is scoped: it applies to a store
that was CONFIGURED, so `persistence.mode=memory` (the default) reaches none of
it and a service nobody asked to persist behaves exactly as it always has.
There is deliberately NO setting to turn the refusal off: the way to run
without a store is to say so, which is the same one setting.

The failure message is built rather than thrown bare, because it is the last
thing an operator sees: it names the mode, what actually went wrong, and that
`persistence.mode=memory` is the way to run without one. `server.js` logs it at
FATAL and exits 1 rather than letting the rejection escape, so a stack trace
does not print over the sentence that says what to do.

**The compose file's `depends_on: condition: service_healthy` is what keeps
this from being a startup race**, and it was already there — its comment had
anticipated exactly this and argued for the wait on the other half of the
reason. The parent project's `tests/sts_persistence_postgres.js` asserts the
whole of this: that the process exits non-zero, that it never answered a
request first, and that the message names the mode, the cause and the way out.

## The wiring: two slots, one event, one plain require

Rule 3e says a slot is what you reach for when a require would close a cycle or
move a route, and that a sixth must not be added by analogy. There are two here
and neither is an analogy.

* **`config.setOverrideStore()`** (rule 3q), filled by this module. It reads
  `persistence.mode` and four more settings through `config.value()`, so it
  requires `config.js`; a require back closes that cycle, and node answers a
  cycle with a half-initialised module whose exports are `undefined`. The
  symptom would arrive later as "notify is not a function" from inside a console
  Save — the one place nobody would look for a require-order problem. It is a
  NOTIFICATION and not a store: it takes a realm id and returns nothing, because
  which of the two places a write belongs in is the thing only `config.js` can
  say, and it already makes that decision for its own purposes.
* **`persistence.setDirectory()`**, offered here and filled by
  `ldap/ldap_server.js`. This one is about ROUTE ORDER rather than a cycle: that
  module registers `/ldap` and `/admin/ldap/directory` at its require time, and this
  module is required at #4a — far above `admin.js`. A require from here would
  drag both routes to the front of the express router, which is the exact
  failure rule 1 exists to prevent. It carries two functions, validated WHOLE
  when installed, for `admin.js`'s logout-reader reason: a half-filled slot
  would leave this module able to READ the directory and unable to restore it,
  which looks exactly like an empty database.

**`realms.onChange()` is an EVENT, not a third slot**, and the distinction is
worth keeping. A slot is a hole one module leaves for another to fill. This is
the opposite shape: this module REQUIRES `realms.js` in the ordinary direction
and subscribes. Nothing over there knows what persistence is, and a process that
never loaded this module has an empty listener list and behaves as it did.
`onChange()` exists because `onCreate()` and `onRemove()` covered only two of
the five doors into that registry — `update()`, `setOverride()` and
`clearOverride()` had no hook, because until a realm could be written down
nothing needed to know a name had changed.

**`realms.js` itself is a plain require** and fails rule 3e's test both ways
round: it registers no route, and it does not require this module.

## Restoring, and the one property that makes it safe to do it that late

`start()` runs from `server.js` after every module has been required and before
the HTTP listener binds. The order inside is a dependency order:

1. **The appconfig overrides**, first, because everything below reads settings.
2. **The realm rows**, because a realm has to EXIST before its directory can be
   loaded into it. They go back through `realms.create()` — the same function
   `/admin/realms` calls — so that every builder registered by every module
   fires exactly as it would for a realm somebody typed, including
   `ldap_server.js`'s, which seeds the realm's subtree. Anything else would be a
   second way to make a realm, and the second way is the one that is missing a
   step. `createdAt` is put back afterwards, because `create()` stamps it with
   now and for a restore that is a lie.
3. **The directory**, last, replacing what was seeded.

**Applying settings that late is safe for a reason that is a property of the
table rather than of the ordering.** Only a `runtime: true` setting can be
overridden at all — `checkOverride()` refuses every other by name — and a
runtime setting is BY DEFINITION one that is read per call rather than captured
at require time. So there is nothing in a saved override file that any module
could already have read and cached, and `global.https`, `oauth2.rfc9700`,
`ldap.port` and `ldap.baseDn` are exactly what the environment and the appconfig
file said. **A saved file cannot change the scheme this service answers on.**

Every saved value is re-checked rather than trusted: the file was written by
this service, but possibly by an older version of it, and a setting may have
been renamed, retyped, its enum narrowed or turned restart-only since.

## The bug the restore found, and it was not in this directory

A restored directory came back with twenty entries — `ldapsearch` and
`/admin/ldap/directory` showed all of them — and **`/admin/users` reported
`known: 0`**. It reads as a failed restore and is a page reading a different
store: `/admin/users`, `/admin-api/users` and the user drill-down are driven by
`admin_stats.js`'s identity register, not by the directory.

Until 2026-08-27 that register could only be filled by somebody
AUTHENTICATING, and that was a complete account of how a person came to be
known, because until then a person could only come to be known that way. **A
restored directory is the first thing that ever put an entry under `ou=users`
without a sign-in.**

`admin_stats.js` gained `noteKnownIdentity()` for it, and the sentence it fills
the register with is the true one: `authentications: 0`, `knownBy: 'restored'`,
and `authenticated` FALSE on the row — which is what keeps `authenticatedHere`
counting sign-ins rather than people. **The counts are deliberately not
restored**: how many times somebody signed in, when they first did, which
protocols they used and every event in their drill-down are statistics about a
process, and this service's statistics have always been per process.

**A SEEDED PERSON IS SKIPPED.** alice, bob and carol are written by `seed()` on
every start and have never been in that register, so registering them on a
restore would make a fresh service list nobody and the same service after one
restart list three people who had still done nothing. A restored process's
`/admin/users` is now identical to a fresh one's plus exactly the people
somebody created or who authenticated.

**AND THE SAME GAP WAS ALREADY THERE ON THE CREATE PATH**, which is the part
worth knowing because it was not caused by this work and was found by it.
`createUser()` — reached by the console, `POST /admin-api/users/create` and a
SCIM create — wrote a directory entry and never touched the register, so a
person created by hand appeared on `/admin/users` NOWHERE until they signed in,
while that page's own description said "a person can be created here ahead of
their first sign-in". It calls `noteKnownIdentity(name, 'created')` now. The
early return in that function is load-bearing on the authentication path:
`recordAuthentication()` builds the record before it reaches the user observer
and `autoCreateUser()`, so without it somebody signing in for the first time
would be marked as not having signed in.

## The seam is closed (2026-09-06)

**This section was a checklist of what a later phase would need. Every item on
it is done.** It opened *"the ask was persistence, and persistence is what this
is. It is not coordination"* — two processes pointed at one database each held
their own copy, and neither saw the other's until it restarted. That was written
here so it would be found rather than discovered, and it is what
`persistence_replication.js` reverses.

**THE ONE SENTENCE IS: THE CHANGE LOG IS THE CONTRACT AND THE NOTIFICATION IS
ONLY LATENCY.** `sts_changes` is a monotonic log — `seq bigserial`, an origin, a
kind, a realm and a key — **written inside the transaction that made the
change**. A process remembers the highest `seq` it has applied and asks for
everything after it. That single fact makes every hard part easy: a listener
that dropped for four seconds misses nothing, the 8000-byte `pg_notify` limit
stops mattering because the payload is a POINTER and never a row, and the
database can restart underneath it. So `LISTEN`/`NOTIFY` stays exactly what it
was — a nudge that wakes the poll early — and is allowed to be lossy.

**THAT IS THE ARGUMENT `xacml-pep/` ALREADY MAKES ABOUT ITS OWN PULL**, and
citing it is the point rather than a flourish: this repository has run that
trade in production shape once already, in the one other place where the
alternative was a push nobody could guarantee.

**AN ORM WAS THE OBVIOUS ANSWER AND IT DOES NOT FIT**, for a reason about this
service rather than about any ORM. The authority here is an IN-MEMORY MAP, read
SYNCHRONOUSLY by every protocol module inside a request; the database is a
write-behind mirror of it. What is needed is cache coherence, not data access.
An ORM solves the layer below that, would put a second schema definition beside
`postgres/schema.sql` for the two to drift apart, and routing reads through it
would make every one of those synchronous lookups an `await` — a rewrite of the
service rather than a feature.

The old checklist, as it was answered:

* The `LISTEN` is on a connection of its own — a pooled client cannot hold one,
  because the pool hands it to somebody else. `watchChanges()`.
* The change is applied to the in-memory Map rather than reloading the realm,
  inside `realms.run()` so the ambient realm is right. **That is the single most
  likely bug in the feature and `tests/replication.js` asserts it**: an apply
  outside a realm context puts realm `acme`'s session in the default realm,
  silently, and the only symptom is somebody signed in to the wrong place.
* A process ignores its own rows — in the SQL (`origin <> $2`) and again in
  `applyRows()`. Belt and braces, because the failure it prevents is the one
  unbounded one: two processes exchanging one row for ever, both answering
  correctly the whole time.
* `ldap.maxEntries` is still a ceiling on what THIS PROCESS holds, and is
  reported as such.
* The group index is fed by `touchDirectory()`, and `applyEntry()` goes through
  it — a replicated write that skipped it would produce exactly the stale groups
  claim that function exists to prevent.
* **AND THE LAST ITEM IS REVERSED.** It read *"nothing about tokens, sessions or
  codes, which are not in this database and are not going to be"*. They are, in
  product mode, and they replicate through the same log — because a design that
  coordinated the directory and not the sessions would be a service where two
  processes agree about who exists and disagree about who is signed in.

### Last writer wins, and the two shapes where that is wrong

A row is whole-valued, so a later write replaces an earlier one — which is
EXACTLY the semantics a single process already has for two concurrent requests,
so nothing anybody relies on changes. Two shapes are not like that, and both
declare it (`merge: 'own'` in `common/realms.js`):

* **A COUNTER.** `nums.callTotal++` is this process's tally. Two processes
  overwriting one row loses counts and the number stays plausible.
* **AN APPEND-ONLY RING.** The audit log is a sequence, not a value. Overwriting
  throws away another process's events; merging into memory and writing back
  makes each process re-report the other's as its own.

Both write ONE ROW PER ORIGIN and the fan-in happens where the value is
REPORTED — `audit.js`'s `list()` and `summary()`, `admin_stats.js`'s
`snapshot()`, `xacml_monitor.js`'s. The test for `own` is one question: **is a
write to this store an ASSIGNMENT or an INCREMENT?**

**AND A THIRD SHAPE SINCE 2026-09-12: A ROW PARTLY BUILT FROM CODE.** Last
writer wins assumes the row is the only source of its value. `krb5.principals`
holds rows that are not: a configured Kerberos account is BUILT FROM SETTINGS at
require time and only then written down, so a restored or replicated copy is an
older answer to a question the settings already answered — and restoring it
whole undid a changed `krb5.servicePassword` and put back accounts the current
settings no longer create. `realms.sharedMap()` takes a `reconcile` option for
it, asked by the `restore` and `remove` accessors — **which are what both
`restore()` and `applyLocally()` in `persistence_minted.js` call, so a restart
and another process obey one rule and neither file changed**. A reconciler that
throws applies nothing. `common/realms.js` argues the hook and
`kerberos/CLAUDE.md` the rule it carries; nothing here writes a reconciled row
back, because two processes with different settings would then exchange it for
ever.

### A FAILED MINTED FLUSH MUST NOT GROW, AND IT DID (2026-09-12)

Three faults compounded on one dispatched run, and each is fixed where it was:

* **`saveMinted()` took row locks in journal order**, upserts then deletes, so
  request workers flushing overlapping rows deadlocked (~112 times). The
  statements are sorted on (handle, realm, key) now, interleaved, so every
  transaction takes locks in one order.
* **the retry re-noted `storedKey()`'s answer.** For a `merge: 'own'` store
  that is the key base64url-encoded with the origin appended, so every
  consecutive failure encoded it again. Keys grew past the btree limit
  (`index row size 3880 exceeds … 2704`), which made every later flush fail by
  construction, and on into gigabytes — one worker at 5.6 GB spending a whole
  CPU profile in `note()`, its commit announcements and so the read barrier
  stalled behind it. Each row carries `journalKey` and the retry notes that.
* **`recordChanges()` put a whole batch in one INSERT**, four parameters a row,
  and past 16,383 rows the 16-bit count wrapped (`bind message has 63088
  parameter formats but 0 parameters`). It chunks at 5,000 rows.

`tests/minted_persistence.js` section 5a and `tests/postgres_minted_writes.js`
pin the three. **What to look for next time**: `STS-STORE-0021` repeating on one
pid while `STS-WORKER-0007` barrier timeouts pile up — the flush is failing, not
slow.

### What still does not coordinate

* **The sockets.** The KDC, both LDAP listeners, the two TLS ports and SPIFFE's
  four are bound per process. Coordination is about state.
* **The replay caches and DPoP `jti` sets CONVERGE rather than synchronise, and
  that is a security statement.** Between a write in one process and its arrival
  in another there is a window the size of `persistence.pollInterval` in which a
  proof one process refused is accepted by another. Sticky sessions close it;
  nothing here does. **The RFC 7523 / RFC 7522 used-assertion history left this
  list on 2026-09-13**: it was three journalled caches and a replay to a second
  worker inside that window was accepted, and it is a table claimed with one
  atomic statement now, under the primary key's own lock. Measured against a
  real server: twenty-five concurrent claims of one assertion, one accepted.
  What is left here is the DPoP `jti` set, the Kerberos acceptor's replay cache
  and SCIM's Digest and HOBA state.
* **A realm's signing keys are not adopted mid-life.** `applyKeysChange()` logs
  and does nothing: taking a new key would strand everything this process has
  already signed. Rotation across processes is a rolling restart, which is what
  it is everywhere else.

## Adding a driver

Implement the contract `persistence.js` calls — `open`, `close`,
`loadDirectory`, `loadRealms`, `loadOverrides`, `saveDirectory`, `saveRealms`,
`saveOverrides` — and add the mode to `MODES` here AND to `enumValues` on
`persistence.mode` in `common/config.js`.

**TWO GROUPS ARE OPTIONAL AND ARE TESTED FOR BY NAME**, which is what lets the
`ldif` driver have neither and be a smaller store rather than a broken one:
`loadMinted`/`saveMinted`/`purgeMinted` (minted state — `persistence_minted.js`'s
`supports()`), and `origin`/`latestChangeSeq`/`changesSince`/`readEntry`/
`readMinted`/`watchChanges`/`purgeChanges` (coordination —
`persistence_replication.js`'s). **A THIRD SINCE 2026-09-13**, and it is
two alternatives rather than one list: `claimUsedAssertion`/
`settleUsedAssertion`/`listUsedAssertions`/`purgeUsedAssertions`/
`removeUsedAssertions` for a DATABASE store, or `loadUsedAssertions`/
`saveUsedAssertions`/`removeUsedAssertions` for a SNAPSHOT store —
`common/used_assertions.js`'s `setStore()` tests for them by name and a driver
with neither is WARNED about (`STS-STORE-0044`) and the history held in memory.
A driver missing either of the first two groups is REPORTED on
`/admin/persistence` with the reason rather than silently doing less. Those two
lists are two copies of one fact; `start()` checks them against each other and
says so rather than trusting them.

`saveDirectory()` is handed both a per-entry diff and the whole live picture. A
database driver uses `upserts`/`deletes`; a snapshot driver uses `all` and reads
the diff only for `touched`, the list of realms something actually happened in.
Rewriting only those is what stops a change in `acme` from rewriting the default
realm's file — which matters because these files are meant to be diffable, and a
rewrite with no change is still a new mtime.

**Require the driver's own dependency LAZILY**, the way the postgres driver
requires `pg`. A person running `ldif` — or the default `memory`, which is
everybody who has not asked for any of this — must not be stopped by the absence
of a package they will never use.

## TLS TO THE DATABASE, REQUIRED AT BOTH ENDS (2026-08-30)

The postgres mode dialled its database in the clear until this date, on a
compose bridge, while every other socket in this stack had been TLS since
2026-08-30 that morning. It is encrypted now, and **required rather than
merely available** — which is the distinction that matters, because `ssl=on`
alone lets a client use TLS and does not make one.

### Both ends say it, so neither can be quietly relaxed

* **The server refuses plaintext.** `postgres/require-tls.sh` runs as an initdb
  script and rewrites every `host` rule in `pg_hba.conf` to `hostssl`. A
  plaintext client is then refused BY THE DATABASE with `no pg_hba.conf entry
  for host …, no encryption`, which names the cause. `local` rules are left
  alone deliberately: they are unix-socket connections inside the container,
  which is what `pg_isready` and the entrypoint use, and TLS on a socket that
  never leaves the filesystem buys nothing and would break the healthcheck the
  stack waits on.
* **The client refuses to make one.** `?sslmode=require` is in the compose
  default for `STS_DATABASE_URL`, and `persistence_postgres.js` passes `ssl` to
  the pool only when the URL asked for it — because passing `ssl` regardless
  would make `sslmode=disable` mean its opposite, a connection string saying
  one thing while the client does another.

### The key pair is generated at container start

`postgres/generate-tls.sh`, and it is the decision `helpers.js` and
`tls_server.js` already make about every other key here: nothing about a mock
is worth persisting, and a certificate committed to a repository is a private
key committed to a repository.

**IT IS NOT REGENERATED PER START**, and that is the one place it differs from
the STS's own keys. Those are remade every boot on purpose — the `kid` is
derived from the material and clients are expected to refetch. A database
client is not: `sslmode=verify-*` pins this certificate, and a stack that
handed out a different one every morning would be teaching people to turn
verification off, which is the habit this change exists to break. Delete the
volume for a new pair.

**It is openssl and not the STS's own generator**, which could mint it — but
would have to be RUNNING to do it, and this key is needed by the database the
STS refuses to start without. A circular dependency at boot is worse to own
than four lines of openssl in an image that already ships it.

### ENCRYPTION AND AUTHENTICATION ARE TWO ANSWERS

`persistence.databaseTlsRejectUnauthorized` is **off by default**, and that is
a statement about the stack rather than a weakened default: the certificate is
generated in the container and signed by nobody, so there is no anchor to
verify it against and turning it on would refuse every connection with a
message about a self-signed certificate. **The connection is encrypted either
way.** `/admin/persistence` draws them as one *Transport* row saying both,
because "encrypted" and "authenticated" are different facts and a single tick
would have to round one of them.

The flag is READ in `persistence.js` and PASSED IN to the driver, rather than
read there: that module takes its url and its logger as options and reaches for
nothing, which is what lets a test construct one against any database without
this file's settings existing.

### The upgrade to 18, and the mount that changed with it

`postgres:16-alpine` became `postgres:18` — Debian rather than alpine, because
the two scripts are bash and alpine ships busybox.

**THE VOLUME MOUNT MOVED FROM `/var/lib/postgresql/data` TO
`/var/lib/postgresql`, and getting that wrong is fatal rather than untidy.**
From 18 these images keep the cluster in a major-version-specific directory
(`/var/lib/postgresql/18/docker`) so `pg_upgrade --link` works across one mount
point; a volume at the old path makes the container REFUSE TO START with a
message about an "unused mount/volume", which reads as a warning. See
docker-library/postgres#1259. The TLS pair lives inside that single volume for
the same reason — a second mount underneath it is the shape the image refuses.

**A major upgrade does not read the old data directory.** A `sts-db` volume
written by 16 stops an 18 container with "database files are incompatible with
server". `docker compose down -v` is the answer and costs nothing here: that
volume holds the directory, the realm registry and the appconfig overrides —
the three things somebody TYPED — and never anything this service minted.

## A FOURTH THING PERSISTS, AND IT IS THE FIRST THAT IS A SECRET (2026-09-06)

This directory's header has said since it was written that **three things
persist** — the embedded directory, the trust realm registry and the runtime
appconfig overrides — and that **nothing this service MINTS ever does**, because
the signing key is regenerated on every start and a token that outlived it would
verify against nothing.

**The second half of that is now conditional on the MODE.** In `product` mode
the signing keys are generated ONCE and read back, because a token issued
yesterday has to verify today — which is most of the difference between a mock
and an identity provider. In `development` mode nothing changed and nothing
will: a key regenerated per start is what makes two instances impossible to
confuse, since the `kid` is derived from the key material.

### What goes in the store is CIPHERTEXT, and neither driver ever holds a key

`common/keystore.js` encrypts with AES-256-GCM before anything reaches a driver,
so `keys.json` and `sts_keys.material` hold `$aesgcm$1$salt$iv$tag$body` and
nothing else. That is what makes it acceptable for private keys to live beside
the directory in the same store — and it is asserted rather than assumed:
`tests/keystore.js` checks that no `BEGIN` survives into the stored form.

**The key that opens it is never in the store, never in the configuration and
never generated by this service.** `common/secrets.js` reads it from one of five
places — a mounted file (the default), AWS Secrets Manager, GCP Secret Manager,
Azure Key Vault or HashiCorp Vault.

### Product mode REQUIRES a store, and this is where that bites

`persistence.mode=memory` with `keys.source=persisted` is a configuration that
cannot work, and `keystore.start()` refuses it by name rather than starting and
generating a key every time. That is the same decision this directory already
made about a store that was configured and could not be opened — see the
*failed-open-is-fatal* argument above — and it is sharper here:

> **A service that cannot read its own signing key must not come up generating a
> new one.** Every token, assertion and signed document it ever issued stops
> verifying at that moment, silently, at somebody else's relying party, with
> nothing in any log here to point at.

So a KEK that does not decrypt the stored material is FATAL, and the message
says so at length and names both fixes: correct the key, or set
`keys.source=generated` to accept a new key on every start, which is what
development mode does.

### The schema version moved to 2

`sts_keys` is the fourth table and the first with a `PRIMARY KEY` that is a realm
id. `SCHEMA_VERSION` was 1 over three tables and is 2 over four — nothing reads
it yet, which is exactly why leaving it behind would have made the one thing it
is for useless.

### The write is queued, not awaited, and the window is the one already there

`helpers.js` builds a key set inside a PROPERTY READ — `STS.privateKey` on a
Proxy — so it cannot await a write. A realm created at runtime therefore
generates its keys synchronously and has them written a moment later; if the
process dies between the two it generates different ones next time. That is the
same window `schedule()`'s write delay already gives everything else in this
store, and it is stated rather than closed because closing it would mean making
every signature in this service asynchronous.

## THE SCHEMA IS BUILT BY SOMEBODY ELSE NOW, AND THIS SERVICE CANNOT CHANGE IT (2026-09-06)

**Until this date the role this service dialled with had to be able to `CREATE
TABLE`.** `persistence_postgres.js` carried the whole schema as `CREATE TABLE IF
NOT EXISTS` and ran the list on every `open()`, and `docker-compose.yml` dialled
as `sts` — the cluster's bootstrap superuser. Nothing was wrong with the schema;
what was wrong is that a mock identity service which can create a table can also
alter, truncate and drop one, and the only thing standing between the two was
that this driver happened not to.

There are two roles now and the split is the whole change:

| Role | What it is | What it may do |
|---|---|---|
| `sts` | the OWNER — the cluster's bootstrap user, what `postgres/schema.sql` is run as | everything, and it is used ONCE |
| `sts_app` | what `persistence.databaseUrl` dials | `SELECT`, `INSERT`, `UPDATE`, `DELETE` on the six tables; `USAGE` and NOT `CREATE` on the schema |

`postgres/schema.sql` creates both halves and is the file to read; it is plain
SQL taking psql variables, so an operator runs it by hand against their own
database and `postgres/apply-schema.sh` runs the same file inside the compose
stack's database on the start that creates the cluster. **`postgres/CLAUDE.md`
carries the deployment half and this section carries the driver half.**

### `open()` probes, and it had to

The obvious reading is that `IF NOT EXISTS` already handles a schema somebody
else built, so the driver could be left alone. It does not:

> **`CREATE TABLE IF NOT EXISTS` checks `CREATE` on the schema BEFORE it checks
> whether the table exists.** PostgreSQL's `parse_utilcmd.c` says so in a
> comment on the line that does it — *"this also checks permissions on the
> creation namespace, possibly causing a permission failure before the IF NOT
> EXISTS test is performed"*. `CREATE INDEX IF NOT EXISTS` is worse by one step:
> it takes the table's OWNERSHIP first.

So the old `open()` would have been refused on every single start, by six
statements that had nothing to do, with `42501 permission denied for schema
sts`. That is measured rather than reasoned: as `sts_app`, against the schema
this script builds, `CREATE TABLE IF NOT EXISTS sts_keys` is refused and `CREATE
INDEX IF NOT EXISTS sts_ldap_entries_realm` is refused with *must be owner of
table*.

`open()` therefore asks `to_regclass` for the whole list in one query — which
needs no privilege at all and answers NULL rather than raising — and issues a
`CREATE` only for what is missing. **The CREATEs stay and must stay**: `node
server.js` against an empty local database, which is what the default connection
string is for, has no script to have been run and builds its own schema exactly
as it always did. What changed is only that it stops doing so when there is
nothing to build.

**A `42501` out of `open()` is caught and re-thrown with the answer in it** —
build the schema with `postgres/schema.sql`, and if the objects ARE there check
the search path. It stays fatal, because a failed open has been fatal since
2026-08-28 and this changes what is SAID rather than what happens.

### A schema of its own, and the search path that goes with it

The tables are in a schema called `sts` rather than in `public`, for one reason:
**a schema is where `CREATE` is granted**, so "read and write the rows and do not
change the shape" is expressible as `USAGE` without `CREATE` on a schema this
service owns, without touching a `public` that every database has. The script
sets `search_path` on the DATABASE, so every role that connects finds the tables
and this driver goes on naming them unqualified — which is what keeps it a
driver for PostgreSQL rather than for this stack.

**The default `"$user", public` would have been a trap and not an error**: the
owner is called `sts` and so is the schema, so the owner would have found the
tables through `"$user"` and `sts_app` would not.

### Two copies of the DDL, and what pays for them

`tests/postgres_schema.js` reads `postgres/schema.sql` and this module's
exported `SCHEMA`, and fails on a `CREATE` either one has and the other does
not, on a schema version they disagree about, on a grant to the application role
that is not exactly those four verbs, and on the role name having moved in one
of the three files that spell it. Without it, a column added here and not there
gives a database one column short and a service that is not allowed to add it —
arriving at a person as a permission error naming neither the column nor the
file.
## ENCRYPTION BELOW THIS DRIVER IS THE OPERATOR'S LAYER (2026-09-12)

**This directory encrypts nothing.** What arrives sealed arrives sealed —
`keystore.seal()` is applied by the modules that own the values, above the
driver — and everything else is written as it was handed over. So the directory
entries, the realms, the settings and (in development mode) the lot are
plaintext in whatever store is configured, and the answer to *encrypt the rest*
is underneath: LUKS or an encrypted ZFS dataset under `PGDATA`, a cloud disk
with a customer-managed key, or one of the forks that has TDE — community
PostgreSQL has none.

`docs/encryption-at-rest.md` is the whole argument, including what column-level
encryption misses that block-level does not (the WAL, spilled sorts, `pg_dump`
output, replicas, query logs) and why the compose stack's `sts-secrets` volume
must not sit on the same unencrypted disk as the database. **One fact from it
belongs in a reader's head before they get there**: there is ONE
key-encryption key for the service, not one per trust realm, so a realm is not a
cryptographic boundary at rest — `common/CLAUDE.md` carries that argument beside
`keystore.js`.


## THE DATABASE PASSWORD DOES NOT HAVE TO BE IN THE CONNECTION STRING (2026-09-12)

`persistence.databasePasswordProvider` reads it from the five places
`common/secrets.js` already reads the key-encryption key from — a mounted file,
AWS Secrets Manager, Google Secret Manager, Azure Key Vault, HashiCorp Vault —
and by default out of the SAME file or secret, told apart by a field. That
module owns *what the password is* and this one owns *where it goes*.

**`start()` SPLIT IN TWO FOR IT, AND THE SPLIT IS A FUNCTION RATHER THAN AN
`await`.** Reading a secret is a network call to somebody else's service and the
pool is built synchronously out of a finished string, so the string has to be
resolved first — the same ordering `keystore.start()` has with its own secret.
What decided the shape is the driver-load `try`: a rejection raised inside the
promise chain is caught at the foot of this file and wrapped in *the store could
not be read*, which for a missing `pg` package is the sentence twice — exactly
what the comment on that catch says not to do. So `resolveDatabaseUrl()` runs
BEFORE `openStore()`, which is the old body under a new name.

**IT IS INJECTED INTO THE STRING AND NOT PASSED BESIDE IT, AND THAT IS `pg`'s
DOING.** `ConnectionParameters` does `Object.assign({}, config,
parse(config.connectionString))` — everything parsed out of the string wins over
an explicit field — and `pg-connection-string` returns `password: ''` as an own
property even for a string that carries none. So a `password` passed beside a
`connectionString` is silently overwritten with the empty one, and there is no
arrangement of those two options that works.

**`encodeURIComponent` FIRST, WHICH LOOKS LIKE FUSSINESS AND IS NOT.**
`URL.password = value` percent-encodes the userinfo set and leaves `%`, `&` and
`+` alone; `pg` then runs `decodeURIComponent()` over what it finds. A password
containing a `%` therefore arrives mangled, or throws `URI malformed` inside the
driver. Encoding first and letting the setter pass the escapes through
round-trips every byte, and `tests/database_password.js` asserts it **through
`pg`'s own parser** for every character that has ever caused this.

**A PASSWORD ALREADY IN THE URL IS REPLACED** and the log says so without saying
what with; two passwords for one connection is a question with no good answer,
and the configured provider is the one somebody chose deliberately. **A string
in libpq's keyword/value form is REFUSED** rather than dialled without the
password somebody configured: `pg` accepts that shape and this cannot edit one
safely.

**A FAILED READ IS FATAL**, through the same path an unopenable store takes —
a process told where the password lives that carried on with the one in the URL
would be ignoring the configuration that exists to keep it out of the URL.
`describeDatabase()` reports WHERE it came from and never what it is, which is
the Password row on `/admin/persistence`.

## THE `ldif` STORE HAD STOPPED WRITING THE DIRECTORY (fixed 2026-09-12)

The journalled flush (2026-09-08) hands the driver `all: null` when it knows
which DNs moved, which is right for `postgres`. The `ldif` driver writes a WHOLE
FILE per touched realm and read `change.all.get(realmId)` to do it — so every
flush that named its DNs failed with *Cannot read properties of null (reading
'get')*, was logged, and was retried on the next change, which failed the same
way. The service answered correctly out of memory the whole time and the file on
disk stopped moving: in `ldif` mode, anything written to the directory by a
writer that named its DN was lost at the next restart.

**Nothing saw it** because `tests/appconfig_persistence.js` fills the directory
slot with a stub that never names a DN, so every flush it drove took the
full-walk path. `tests/truststore_persistence.js` found it by writing a real
entry through the real directory and reading it back from a second process.

`flush()` now builds the snapshot for the TOUCHED realms only when the driver is
`ldif`, which keeps the journal's saving for every realm nothing happened in.

**AND THE DIRECTORY NOW CARRIES THE CLIENT TRUSTSTORE'S RUNTIME ANCHORS**, in
`ou=trustAnchors` in the default realm — so "the embedded directory persists"
includes them. `tls/CLAUDE.md` argues it.
