# CLAUDE.md — `persistence/`

## What is in here

| File | What it is |
|---|---|
| `persistence.js` | The driver interface, the mode selection, the diff, the flush scheduler, the restore, the appliers, and the status object three surfaces render. A LIBRARY — it registers no route. |
| `persistence_ldif.js` | The `ldif` driver, and the RFC 2849 codec under it. `tests/ldif_codec.js` guards the codec. It deliberately has NO `loadMinted`/`saveMinted`/`purgeMinted`, and the absence is the answer — see below. |
| `persistence_postgres.js` | The `postgres` driver: seven tables, one transaction per flush, and a `pg_notify` that something listens to now. The seventh, `sts_used_assertions` (2026-09-13), is written by ATOMIC CLAIM rather than by the flush — see below. **`sts_keys` is written by `mergeKeys()` since 2026-09-14 (#46)** — the row locked, the caller's merge decides, a change row only when it moved — and `loadKey()` reads one row; `common/CLAUDE.md` argues it. |
| **`persistence_minted.js`** | **What this process MINTS, written down — in product mode, and nowhere else** (2026-09-06). The registry of declared stores, the journal, the seal, the restore. A LIBRARY that is HANDED its driver, which is what lets `tests/minted_persistence.js` drive the whole of it against a stub. |
| **`directory_merge.js`** | **One directory entry written by two nodes** (2026-09-14, #46 section 3): the three-way merge (base = the shadow, mine = live, theirs = the row under `FOR UPDATE`) the postgres driver writes a directory upsert through, and `persistence.js` applies again to a write that raced the flush or a replicated row. A LEAF with no requires. See *Several nodes writing one row* below. |
| **`persistence_replication.js`** | **Several processes against one store** (2026-09-06). The change-log poller, the `LISTEN` client, and the fan-in for the counters. A LIBRARY, handed its driver and its appliers; `tests/replication.js` drives it against a stub. |
| **`bulk_import.js`**, **`ldif_stream.js`** | **The bulk directory import** (#629, 2026-10-14): people from an LDIF file straight into `sts_ldap_entries`, offline, thousands a second. A TOOL — no route, nothing requires it. See *THE BULK IMPORT* below; `docs/bulk-import.md` is the operator's page. |

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
stores declared on 2026-09-12 are made of them: `ssf/caep.ts`'s and
`ssf/risc.ts`'s registers, whose state machines do `row.counts[uri] += 1` on a
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

**THE SWEEP OF 2026-09-14 (#46): EVERY UNDECLARED STORE, AND WHY.** The
suite's `cluster` mode found flow state that had never been declared — a store
read back by a LATER request of the same browser or client, which behind a
balancer is another node. Every `realms.map()` / `arr()` / `obj()` /
`sharedMap()` / `keyed()` without `persist` was then read, and this is the
verdict for each; a new undeclared store owes a row here.

| Store | Verdict |
|---|---|
| `credentials.js` `pendingTotp`, `pendingBackupCodes`, `pendingKeys` | **Persisted** — flow state (`common/CLAUDE.md`, *Enrolment is two steps*). |
| `vc_issuer.js` `lastCredentialRequests` | **Persisted** as `vc_issuer.lastCredentialRequest` — a wallet's read-back (`oid4vc/CLAUDE.md`). |
| a session's `saml2ServiceProviders`, `saml11RelyingParties`, `wsfedRealms`, `oidcClients` | Not a store: in-place edits of a persisted row, now told to it (`authn/CLAUDE.md`, `noteSessionChanged()`). |
| `scim_auth.js` `digestCounts`, `hobaSeen` | **Persisted since 2026-09-18** (`scim.digestCounts`, `scim.hobaSeen`, `retain: 'age'`) so the fast refusal survives a restart; the claim still decides between live processes. A count row is an array, not a Set. |
| `request_object.js` `requestUriCache`, `oauth2.js` `signedMetadataCache`, `applications.js` `ssfAllowedCache` | Fine — caches of something re-derivable. |
| `ldap_server.js` `entries` | Persisted another way — the directory's diff, above. |
| `ldap_server.js` `usernameIndexes`, `subtreeClocks`, `groupIndexes`, `uuidIndexes`; `federation.js` `releaseIndexes` | Fine — derived from the directory and rebuilt from it. |
| `helpers.js` `stsKeysFor` | Persisted another way — `keystore.js`. |
| `ssf_streams.ts` `deadCounts`, `tally` | Fine — an estimate rebuilt at every sweep, and the count behind the sweep's one log line; the letters themselves are persisted. |
| `ssf_dead_letter_report.ts` `sweepNotes` | **Persisted since 2026-09-18** as `ssf_dead_letter_report.sweeps`, `merge: 'own'`, and the page fans every process's in — it was the dead-letter page's sweep history, emptied by every restart. |

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

### And the second, which was the same loss through the JOURNAL (#631, 2026-10-14)

An empty shadow is only half of it: the first flush must also LOOK at every
entry, and it was left to infer that from an empty journal (the seed runs
before the store is enabled, so `directoryChanged()` journals none of it). In
a windowed process — every postgres process since #320 — the window's pinned
seed (the people) made the flush read "empty journal beside window writes" as
"nothing resident to walk": the people reached the table and the base DN, the
containers, the groups and the applications did not (24 rows of 59 on the
whole stack; the bulk import's own test seeded with
`LDAP_WORKER_DIRECTORY=memory` to dodge it). `openStore()` now sets
`dirtyEverything` beside `directoryDirty`, so the first flush is a whole diff
and the window's `collect(null)` in every process, whatever was journalled
before it ran. It walks what an empty journal already made it walk; nothing
new is paid at start. `tests/directory_window.js` section M starts the real
directory over an empty store double in both modes and compares the rows.

## When the flush happens

Both modes schedule; they differ only in the delay.

| Mode | Delay | Why |
|---|---|---|
| `postgres` | 0 | Every change made while handling one request coalesces into ONE transaction that runs the moment that request's synchronous work is done. Write-through at the granularity anybody cares about, and what stops a bulk SCIM import from becoming one transaction per entry. |
| `ldif` | `persistence.writeDelay`, 1500ms | The unit of writing there is a whole FILE. A realm build writes thirteen entries; three of those in one file rewrite is the point of the delay. |

A response that wrote waits for this flush in postgres mode (#351; the next
section): the zero delay is not waited out — the wait starts the flush.

Both flush on the way out: `server.js` traps SIGTERM and SIGINT and calls
`stop()`. `kill -9` sends SIGKILL, which cannot be trapped by anything, and what
that costs is up to `writeDelay` milliseconds in ldif mode and nothing in
postgres mode.

## A failed write is logged and never thrown — and in postgres mode never acknowledged (#351)

The service keeps answering out of memory, `GET /admin/ldap/service` and
`/admin/persistence` both carry the error, and the write is retried — **the
shadow is only advanced on success**, so the retry recomputes the same diff.

**What this section said until 2026-09-29, and why it stopped being true.** It
said the next CHANGE retries, and that refusing the operation whose write
failed "would make a database outage take down sixteen protocol families that
do not need a database". On testidp (#351) a SCIM Bulk load starved a request
worker's pool: its deletes were answered 204 while their writes failed
(STS-STORE-0002), the worker then exited on a lost origin claim
(STS-STORE-0061), and ~600 people it had reported deleted came back from the
database. No `try`/`catch` fixes that — nothing threw, and nothing survives a
SIGKILL, an OOM kill or a lost node. The guarantee that holds is **never
answer a write until it is committed**, and it is now the rule.

### A write is answered after its commit

* **Where it waits: `cluster/cluster_barrier.js`, rule 2** — the same
  `res.end()` hold active-active mode already had, installed in `common/app.js`
  directly below the request pool, so it runs in whichever process SERVES the
  request (a worker, or the front process for what it keeps) and covers every
  route, including redirects (`res.redirect()` ends through `res.end()`).
  `persistence.answersAfterCommit()` turns it on for every postgres process,
  one node or many. Rule 1 (catching up with other nodes) stays active-active
  only. There is no second mechanism: the request worker's commit
  announcement (`request_worker.ts`) is unchanged and still tells the front
  process which tickets committed.
* **Which flush carries a request's changes: the write position.** A request
  reads `writeGeneration()` — the directory generation (which the realm and
  settings writes move too) and the minted generation less its observation
  tallies — when it arrives and again when it answers; if it moved,
  `commitThrough()` waits for the flush in flight that took that position, or
  starts one. The position is process-wide, so a request that overlapped
  another's write waits for that too — conservative, never wrong. The call
  log's own success row is left out, as it always was for active-active.
* **No debounce is waited out.** In postgres mode the schedule's delay is 0,
  and `directoryThrough()` / `flushThrough()` call `flush()` at once rather
  than waiting for the timer; a commit is the cost of the rows written.
* **The stores it covers**: the directory, the realm registry and the
  settings overrides (one flush, one generation); every minted store
  (`flushThrough()`); and the keystore's queued rows — a key set or a
  certificate authority row whose write fails is now a failure of the
  request that caused it (its outcome's `error` was dropped before; a realm
  was answered as created and generated different keys at the next restart).
  Nothing a request writes goes to the store any other way.
* **A failed commit is 503 with `Retry-After`** (STS-STORE-0066, marked on the
  response and recorded as a second audit row carrying the 503) and the
  handler's response is discarded whole — its body, `Location`, `Set-Cookie`
  and `Content-*`; the security headers and CORS stay. A response whose
  headers already left (a handler that streamed or called `writeHead()`
  itself; none that writes does) is destroyed rather than completed. An
  **LDAP** operation is wrapped at registration in `ldap/ldap_server.js`,
  inside what a worker runs, and answered **`unavailable` (52)**
  (STS-STORE-0067) — RFC 4511's "a subsystem necessary to complete the
  operation is offline", which is true, where `busy` (51) is not; it is also
  what a worker that dies mid-operation is already answered. An LDAP read
  (search, compare) is held only for directory or key changes, never for its
  audit rows — the HTTP call log's reason.
* **The change a refused request made is still in memory, and is retried**:
  a failed flush puts its dirty bits AND ITS JOURNAL back (the journal was
  lost until #351, so the next journalled flush advanced the commit position
  past the failed DNs and they reached the store only if a full walk ever
  ran), and arms ONE retry of the whole flush — 1 s, doubling to 30 s, reset
  by the first success; the failed key rows are queued again with it
  (`keystore.retryFailed()`). It is the retry of one failed write, not a
  periodic job, and it exists only while a write is failing.
* **A client's retry must be safe against a change already in memory.** A
  retried DELETE finds the entry gone and answers 404, a retried create finds
  it and answers 409. So while a refused write waits for its retry
  (`commitBacklog()`), a request with a WRITING method (POST, PUT, PATCH,
  DELETE; add, delete, modify, modifyDN) is held for that retry's commit too,
  even when it changed nothing itself: its 404 then means the delete is in the
  store, or it is 503 again. Reads are answered from memory as always.
* **What is NOT waited for**: `ldif` (its unit is a whole file on
  `persistence.writeDelay`; waiting would put 1.5 s on every write of a
  development store) and memory mode. Both behave as before, except that a
  failed ldif write now keeps its journal and retries on its own.

`tests/answer_after_commit.js` holds each of these in process; what it cannot
hold is a real pool starved by a real load, which only a run against postgres
shows.

### The liveness connection

The origin-claim renewal, the cluster heartbeat and the lease statements run
on a `pg.Client` of their own (`liveQuery()` in `persistence_postgres.js`) —
like the LISTEN connection, opened on first use and again after it drops, with
no timer — so write load cannot starve the lease that keeps a process writing.
If it cannot be opened (a server at `max_connections`) the statement goes
through the pool once rather than failing (STS-STORE-0070). A write's own
fence checks stay inside its transaction. Each process now holds up to
`poolMax() + 2` connections; `POOL_FLOOR` stays 4, argued above it.

**A lapsed origin claim is not purged with the other claims** (for a day):
`purgeClaims()` deleted every expired claim, so a claim that lapsed during a
stall was deleted at the next purge, the owner's renewal matched no row, and it
exited reading "another process took it" when nobody had — a likely route to
the testidp STS-STORE-0061.

**And a late renewal says why**: `persistence.event-loop-lag`, a per-process
scheduler job, reads `perf_hooks.monitorEventLoopDelay()` every ten seconds
into `status().eventLoop` and warns STS-STORE-0068 past 5 s; a renewal that
started or answered more than half the claim's lifetime late logs
STS-STORE-0069 naming the loop's worst delay, so the next lost origin says
whether the loop, the pool or the database was the cause.

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
`ldap.port` and `global.domain` are exactly what the environment and the appconfig
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

**THE RESTORE HALF WAS TAKEN OUT AGAIN BY #613 (2026-10-13); the create half
stays.** `/admin/users` has listed the directory's people from the directory
since #610 (`admin-core/admin_views.ts`'s `peopleRows()`: a capped listing and
the store's count), so the `known: 0` page this section describes cannot
recur without the register's help, and the help had become the most expensive
thing a start did: `ldap/CLAUDE.md`, *Restoring*, has the figures. A restored
person is a `directory` row now, and the register holds what this service
observed.

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
was — a nudge that wakes the poll early — and is allowed to be lossy. Since
#630 it is sent after the COMMIT and coalesced, one a 25 ms window per
process (*What the write path waited on*, below).

**THAT IS THE ARGUMENT `xacml-pep/` ALREADY MAKES ABOUT ITS OWN PULL**, and
citing it is the point rather than a flourish: this repository has run that
trade in production shape once already, in the one other place where the
alternative was a push nobody could guarantee. **`persistence.coordinate` turns
it off.**

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
so nothing anybody relies on changes. (**Between NODES it is not**, and three
kinds of row no longer work this way — the directory, the realm registry and
settings, and ended or jointly edited minted rows: *Several nodes writing one
row*, below.) Two shapes are not like that, and both
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

### ONE FLUSH QUEUED BEHIND THE RUNNING ONE, NOT ONE PER CALLER (2026-09-13)

`flush()` answered a caller that arrived while a flush was running with
`flushing.then(flush)` — a waiter per caller. `schedule()` arms a zero-delay
timer per write in postgres mode, so every write made during a transaction
added one; when it settled all of them ran, one started the next flush and the
rest chained themselves again. **Under a sustained load they never drained.**
A sampling heap profile of a single-process postgres service during
`sts_directory_bulk_load_ldap_50k` put over 3 GB of 6.6 GB allocated in fifteen
seconds in that line; RSS went 1 GB → 4.2 GB with 2.6s and 5.3s GC stalls, one
run ended in `JavaScript heap out of memory`, and the suite's `postgres` mode
reported it as `fetch failed` on the read-back. Now the first caller during a
flush creates ONE queued flush and every later caller is handed it; it takes
the whole journal when it starts, so every write made before any of those calls
is written when it resolves. The same load: 50.3s → 19.2s, 815 MB peak, worst
healthcheck 33ms. **Look for it next time as RSS climbing during a write load
and falling back when the load stops** — garbage, not a leak.

**AND `changeRowsWritten()` COUNTS AT COMMIT.** `persistence_postgres.js`
added a transaction's change rows to the counter when the INSERT was built, so
an open transaction or one about to roll back had already moved it. A request
worker reads it to say whether it `wrote` — since its LAST ANNOUNCEMENT now,
not either side of one flush — and the front process reads it to mark workers
stale. `tests/flush_waiters_and_commit_counts.js` pins both, four mutants caught.

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

### ONE MINTED FLUSH AT A TIME PER PROCESS, OR THE OLDER VALUE CAN WIN (2026-09-13)

**A flush READS a value when it takes the journal and WRITES it when its
transaction commits.** `minted.flush()` had two callers that did not wait for
each other — `persistence.js`'s scheduled flush and `request_worker.ts`'s
commit announcement (`flushMinted()`) — so two transactions from ONE process
could be open at once, a key written between their journal takes was in both
with two different values, and `ON CONFLICT DO UPDATE` kept whichever COMMITTED
last. Sorting the statements (above) stops a deadlock; it does not stop a wait,
and a wait is exactly what reverses the order.

**It is the whole of `sts_global_logout`'s intermittent `dispatch` failure.** A
browser arriving at `/wsfed` gets an ARRIVAL session (`anonymous`,
`chosen: false`) and the sign-in upgrades the same row in place. On worker 34
the arrival went out in a transaction that began at 15:00:44.079 and the
upgrade in one that began at 15:00:44.267; the first waited on a lock the second
held and committed after it. `sts_changes` shows it: the two rows for that
session have their `seq` the opposite way round from their `at` (41715 at .267,
41778 at .079). Every other process applied an anonymous row nobody had chosen,
worker 34 held the signed-in session in memory, and the global sign-out —
answered by worker 33 — listed seven sessions of eight, ended seven, and left
the eighth authorising `prompt=none` at worker 34. **The read barrier worked**:
worker 33 caught up correctly, to a store that was wrong. So neither a barrier
change nor a sign-out that syncs first could have fixed it.

`flush()` now keeps `flushInFlight`: a call made while one is in flight waits
and then takes the journal itself, so within a process commit order is journal
order. Waiters coalesce (the first takes everything written during the wait),
`reset()` forgets a write in flight, and a waiter clears a marker left on a
settled promise rather than spinning on it. **Two different processes writing
one key is untouched** and is still last-writer-wins, as above.

**`stop()` WAITS TOO, AND THAT MOVED A TEST ORDERING.**
`appconfig_persistence.js` calls `persistence.stop()` without awaiting it, and
`minted.stop()` marks the module stopped after its flush — so the mark can land
inside a later file that shares the process. `tests/minted_flush_order.js` runs
its assertions in a child for that reason. (`minted_persistence.js` run
immediately after `appconfig_persistence.js` with `--only` fails section 3 the
same way, with or without this change; in the full ordering files between them
absorb it.)

**What to look for next time**: the same minted key in `sts_changes` with `seq`
and `at` in opposite orders from ONE origin — the query is
`lag(at) over (partition by origin, kind, key order by seq) > at`. It found 18
across a whole dispatched run, one of them a session.
`tests/minted_flush_order.js` pins it with a store that commits when told to;
four mutants caught, two recorded as equivalent (both clear the marker in a
branch the waiter's own clear makes redundant).

### SEVERAL CONTAINERS, NOT ONLY SEVERAL PROCESSES (2026-09-14, #46)

Everything above was argued for the processes of ONE container, which agree
through the front process's IPC. `cluster/CLAUDE.md` carries what several
containers against this store need, and three things changed here for it:

* **The origin is a UUID** (`pid-<uuid>`), not `pid-Date.now()`: identical
  containers hold identical pids, and a shared origin silently drops the other
  node's rows for ever.
* **`withTransaction()` checks the cluster fence first** when `cluster/cluster.js`
  has installed one — the node's membership, and any lease the write needs, under
  `FOR SHARE` — and a fenced transaction calls back into cluster.js, which exits
  the process or fails the one write.
* **The pull no longer stops at a hole.** It applies everything visible above
  `highest`, remembers each hole, re-asks for them with `changesAt()` on every
  pull, and gives one up after ten minutes (`STS-STORE-0049`) instead of four
  seconds — which is what "### ONLY THE CONTIGUOUS RUN" in the replication file's
  history used to do, and why a transaction slower than four seconds used to be
  lost in every process that skipped it. `applied` is a low-water mark now and
  `highest` is beside it; `/admin/persistence` reports both and the hole count.

`persistence.clusterStore()` hands the driver to `cluster/cluster_claims.js` and
`cluster/cluster_secrets.ts`. The four `sts_cluster_*` tables are schema version
5.

**A CREATE'S CLAIMS GO BACK IN THE FLUSH THAT COMMITS IT (#628, 2026-10-14).**
`releaseClaimsAtCommit(rows)` queues claim rows with the directory generation
of the moment; the first `saveDirectory()` whose take covers that generation
carries them as `change.releaseClaims`, and the driver deletes them as the
last statement before COMMIT (the tiered driver sends each to the tier its
scope is claimed in). Rows whose writes committed earlier are deleted alone
— on the "nothing is dirty" path, or after a directory step that carried
none. **A transaction that fails rolls them back, and they are not queued
again**: the claims stay until they expire (`STS-CLUSTER-0164`), the cost
rcbj accepted. `cluster/CLAUDE.md`, *Claims and shared secrets*, and
`ldap/CLAUDE.md`, *SEVERAL NODES: A CREATE CLAIMS ITS NAME*, have the rest.

**WHAT THE CLUSTER BARRIER HOLDS A RESPONSE ON (2026-09-14, #46 follow-up).** It
was `persistence.pendingWrites()` — anything dirty, journalled, scheduled or in
flight anywhere in the process — and that held nearly every request behind the
previous request's audit row. Now there are WRITE POSITIONS:
`persistence.writeGeneration()` is `{ directory, minted }`, each a counter bumped
wherever a dirty bit is set (persistence.js) or a key journalled
(`persistence_minted.js`'s `note()`); a flush records the generation its take
covered and, on success, the highest such is the COMMITTED generation.
`persistence.commitThrough(position)` resolves once both halves have committed
that far: `directoryThrough()` waits on the flush in flight when its take covers
the target and otherwise asks `flush()` (the queued flush takes the target);
`persistence_minted.flushThrough()` returns the minted flush in flight when its
take covers the target — not the one queued behind it, which under concurrent
writers is a second transaction holding none of that response's writes — and
`flush()` otherwise. A failed write resolves its waiters with `error`; a
position already committed costs no flush. `pendingWrites()` is kept for a
persistence double with no positions. `tests/cluster_barrier_throughput.js`
sections 2 and 4.

**AND AN OBSERVATION IS COUNTED APART (2026-09-15, #46).** A store declared
`observation: true` at `realms.map()` (`common/realms.js`) holds tallies of what
requests did — `xacml_monitor.counters` is the one — and `persistence_minted.js`'s
`note()` counts its keys in `observedGeneration` as well as `generation`, cached
per handle because `note()` is on every store write. `writeGeneration()` carries
it as `observed`; the barrier subtracts it before asking whether a request WROTE
(`cluster/CLAUDE.md`, *What the barrier cost*). The rows are journalled, flushed
and replicated exactly like any other; only the barrier's question changes.
`tests/cluster_observation_counters.js` section 2.

**AND `syncNow()` NO LONGER READS THE LOG'S HEAD.** A pull that STARTED after the
call reads with snapshots taken after it, so its pages and its hole re-check
apply everything committed before the call; `highest >= latestBlockingChangeSeq()`
added nothing to that, and the query (`MAX(seq) WHERE kind <> 'minted-own' AND
origin <> $1`) walked back past every row the node itself had written — on a
node answering alone, the whole log: a read went from 4ms to 68ms as the log
grew. A pull in flight at the call is waited out on its promise (it was polled
every 5ms) and is not accepted as the proof; section 3 of the test pins that
with a page read before a row committed, which `cluster_foundation.js` section 2
recorded it could not time. The driver keeps `latestBlockingChangeSeq()`;
nothing in the barrier calls it.

**A pull in flight is waited out only until the barrier's deadline
(2026-10-07).** Until then the barrier waited for the running pull to
finish and checked its deadline (`SYNC_DEADLINE_MS`, 4.6 s) only after
that. A pull applying a burst of rows therefore held every reader for as
long as it ran. In the `cluster` mode the leader rotated the signing keys of
dozens of realms at once, and the other node's pull took about 17 s. A
Kerberos AS-REQ waiting on that barrier was answered 20 s late, after its
client had given up (`sts_kerberos_rc4`). The barrier now waits for whichever
comes first, the pull or the deadline. At the deadline it answers from what
the process has (`STS-STORE-0039`), and the pull goes on.
`tests/replication.js` section 8c covers it.

**`audit.events` IS STORED IN SEGMENTS OF 32** (`realms.arr({ segment })`,
`common/CLAUDE.md`): a whole-array `merge: 'own'` row was 2.3 MB sealed and
written per flush and read back by every other process. Another origin's
segments are put back together by `persistence_replication.remoteSegmentedRows()`;
a whole-array row an older build wrote is read as one list beside them and ages
out under `persistence.mintedRetention` like any dead origin's row.

### A MINTED WRITE ASKS FOR A FLUSH (2026-09-14)

**Nothing ever called `persistence.mintedChanged()`.** It was written as "the
one door that marks nothing and only schedules", and `persistence_minted.js`'s
`note()` journalled every key without asking for a flush — so a minted row
reached the store only when something else flushed: a directory, realm or
settings change in the same process, or an explicit `flushMinted()` (the
cluster barrier's commit-before-respond, a request worker's commit
announcement, a credential spend). A sign-in usually writes the directory, so
sessions were stored; a SIGN-OUT writes nothing else, so its tombstone waited
in the journal and the ended session stayed live in `sts_minted` — for the next
node to read and for a restart to restore.

It was the unexplained half of section 3's session probe (the cluster OFF: 8 of
8 revoked sessions live in the store), and it was not a race: with no other
node touching the session 4 of 4 stayed live, on ONE node alone 4 of 4, and in
single-container dispatch mode (two request workers) 8 of 8. Active-active
read 0 of 8 only because its barrier flushes every writing response. Now the
first key journalled after a flush calls the scheduler `persistence.js` hands
over with `minted.setScheduler(mintedChanged)`: 0 of 8 with two nodes off, 0 of
4 untouched, 0 of 8 in dispatch, 0 of 4 on one node. Once per flush rather than
per write (`flushAsked`, cleared where the journal is taken), and a key put
back after a FAILED write does not ask, so a database outage is not a loop of
zero-delay retries — the next write retries, as `STS-STORE-0021` says.

**So the tombstone and the merge hold whenever processes share a postgres
store**, cluster or not: neither was ever gated on the cluster mode (the SQL is
the driver's, the declarations the store's); what failed was the write that
carries them. Two NODES with `cluster.mode=off` remain unsupported for every
other reason `cluster/CLAUDE.md` gives.

### SEVERAL NODES WRITING ONE ROW (2026-09-14, #46 section 3)

Last writer wins (above) was the semantics of one process and became data loss
with two: the later write carried the writer's whole copy of a row or a table,
and what another node had put there went with it. Three families of it, and
the capability rows are `store.no-foreign-deletes` and
`directory.concurrent-writes` (both provided by `persistence_postgres.js`) and
`sessions.no-resurrection` (`persistence_minted.js`).

**A SAVE NEVER DELETES A ROW FOR BEING ABSENT FROM THIS PROCESS'S COPY.**
`saveRealms()` and `saveOverrides()` ran `DELETE … WHERE NOT (id = ANY(<what I
hold>))`: a realm created on node B was deleted by any realm change node A saved
before B's row reached it, and a setting written on B by A's next save of any
setting. And `diff()` reported as REMOVED every realm in the directory shadow
that the registry lacked — which is also a realm another node created whose
entries replicated here before its registry row — so the same flush deleted its
directory and everything it had minted. Now:

* the realm registry and the settings each have a SHADOW (`realmShadow`,
  `appconfigShadow`) primed from the restore and advanced by every write and
  every apply, and a flush sends a DELTA against it: the realms whose name,
  description or overrides moved (overrides set and cleared BY KEY and merged in
  SQL — `(stored - cleared) || set` — so a setting another node made on the
  same realm stays), the settings set and cleared. The driver interface grew a
  second argument, `saveRealms(rows, delta)` and `saveOverrides(map, delta)`;
  the `ldif` driver ignores it and writes its whole file, which is right for a
  store one process owns.
* a realm is DELETED only when `realms.remove()` was called in this process
  (`removedHere`, filled by the `onChange()` watcher unless restoring), and the
  directory's `removedRealms` is the same list.
* a stored realm this process could not restore (`STS-STORE-0007`) is left out
  of the shadow, so it is neither overwritten nor deleted — the wholesale write
  used to delete it at the first flush.
* the appliers merge what this process has changed and not yet written ON TOP of
  what they read (`applyRealmsChange()`, `applyAppconfigChange()`,
  `applyDirectoryChange()`): each used to apply the stored value whole, which
  erased a local change made a moment earlier and left the diff with nothing to
  write. And a realm another node REMOVED is removed here, which nothing did
  before — this process's next save used to write it straight back.
  **The directory applier's base is what a RUNNING flush sent for that key,
  not the shadow (2026-09-23)**: the shadow advances only when the flush
  settles, so a change made while it was out that UNDID the flush's own change
  (a disable in flight, an enable after it) matched the shadow, looked like
  nothing this process had changed, and lost to a replicated row still holding
  the old value — the enable was never written anywhere. `inFlightDirectory`
  holds the sent JSON until the flush settles; `tests/cluster_lww_stores.js`
  section D holds a COMMIT open to reproduce it.

A reset-all in one process still clears every stored setting, because there the
shadow is the table; in a cluster it clears what this node knew was stored.

**A DIRECTORY UPSERT IS A THREE-WAY MERGE WITH THE ROW AS IT IS NOW.** An upsert
carries `base` (the shadow's JSON, or null), and `saveDirectory()` locks every
existing row the flush touches with ONE `SELECT … ORDER BY realm, dn_key FOR
UPDATE` before it writes — a single lock order, `saveMinted()`'s deadlock
argument — then writes `directory_merge.js`'s answer: an attribute one side
changed takes that side; both changed, a list (`member`, `objectClass`, the
security keys, or any attribute with more than one value on some side) is merged
by value and anything else takes mine, a credential never becoming a union; two
adds of one DN under different `entryUUID`s keep the FIRST committed as the
entry — its `entryUUID` and its single values (`STS-STORE-0052` when mine adds
nothing) — **plus, since 2026-10-02, what mine added: an attribute only mine
holds and a list value theirs lacks** (`mergeCreations()`; two nodes seeding a
realm's role group lost a grant's member otherwise); a change to an entry
deleted elsewhere is dropped
(`STS-STORE-0053`). A new row is `INSERT … ON CONFLICT DO NOTHING`, and losing
that race locks the row and merges again. The driver answers `{ outcomes }` —
what the store decided that this process does not hold — and
`applyDirectoryOutcomes()` puts each into the live directory with the journal
suppressed and the shadow set to the STORED row; a local write made while the
flush was out is merged once more and journalled, not overwritten.

The merge cannot tell a client that its add lost. So the create DOORS claim
their names first — `ldap/CLAUDE.md`, *Several nodes: a create claims its name*.

**AN ENDED MINTED ROW STAYS ENDED, AND A ROW TWO NODES EDIT IS MERGED.** A
session ended on A was written back by B's older copy the next time B touched it
(`noteSessionUsed()`, `touchArrivalSession()` re-set the row), so a sign-out
did not hold; B's arrival copy undid A's sign-in upgrade; and a relying party A
added to the session's front-channel list was lost to B's write. A store now
declares two things at `realms.map()` (`common/realms.js`):

* `tombstone: true` — a delete is written as a row whose body is the marker
  `$tombstone$1`, an upsert of a key holding one does nothing (`… DO UPDATE …
  WHERE sts_minted.body <> $tombstone`), every reader (`loadMinted`,
  `readMinted`, `readMintedMany`) treats it as absent, and what was refused is
  dropped from this process too (`STS-STORE-0054`). ONLY for random-handle keys
  that are never legitimately written again: `authn.sessions`,
  `oauth2.authzCodes`, `oauth2_bcp.refreshTokens`. A counter, a per-origin row
  or anything keyed by a name must not.
* `mergeRow(mine, theirs)` — the driver reads the row `FOR UPDATE`, hands it to
  a closure `persistence_minted.js` builds (open, merge, seal: the driver never
  holds a key), writes the answer and reports it, and this process takes it
  unless a newer local write is already journalled. `authn/CLAUDE.md` carries
  the session rule; `oauth2_bcp.refreshTokens` keeps `rotated` moving forward
  only. A merge that cannot open the row writes this copy (`STS-STORE-0056`).

Tombstones expire with `persistence.mintedRetention` (0 keeps them with
everything else): `purgeTombstones()`, at most every ten minutes from a
successful minted flush, any node (`STS-STORE-0055` when it fails).

`tests/cluster_lww_stores.js` holds all three against a `pg` double both
"nodes'" drivers share, and `persistence.js` itself over it; five mutants
caught (the wholesale realm delete, `removedHere` ignored, the tombstone guard,
the list merge, the session rank).

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
  What is left here is the Kerberos acceptor's replay cache and SCIM's Digest
  and HOBA state. **SCIM's Digest and HOBA state left it too on 2026-09-14
  (#46 section 5)** — `scim/CLAUDE.md`, *Several nodes*. **The DPoP `jti` set left the list on 2026-09-14 (#46)**, with
  the authorization code, the PAR `request_uri` and the rotated refresh token:
  each is spent through `cluster/cluster_claims.js` on a postgres store —
  `oauth-oidc/CLAUDE.md`, *Several nodes*.
* ~~**A realm's signing keys are not adopted mid-life.**~~ **Reversed
  2026-09-14 (#46 section 1)** wherever the store arbitrates (`cluster.mode`
  not `off`): `applyKeysChange()` hands every `keys` change to
  `keystore.applyStoredChange()`, which reads the current row and adopts a key
  set or a certificate authority another process wrote — a rotation included,
  because `deleteKeys()` now logs a change row. The argument that it strands
  what this process signed is answered in `common/CLAUDE.md` (*Between nodes the
  store is the arbiter*): the set adopted away from is one the store already
  refused. With the cluster off it still logs and does nothing.

### THE CHANGE LOG IS TRIMMED (2026-09-14, #46 section 8)

`sts_changes` grew for ever: `purgeChanges()` existed and nothing called it.
`persistence_replication.js`'s RETENTION block argues the design; the facts:

* **Every process that reads the log reports its low-water mark** into
  `sts_change_readers` (`reportChangeReader()`) — at start, after a pull at most
  every 15 seconds, and removed at a clean stop. A request worker reports its
  own: it is an origin with its own `applied`, and its front process cannot see
  it.
* **The trim is one statement** (`purgeChangeLog()`): readers that have not
  reported for `max(retention, 2 minutes)`, or that name a cluster node which is
  no longer a live member, are declared gone; a change is deleted only below the
  lowest remaining mark AND older than `persistence.changeLogRetentionS` (3600
  by default, 0 turns it off) by the database clock; with no reader, nothing.
  Every five minutes, as the scheduler job `persistence.change-log-purge`
  (#49 P5) — on the scheduler's leader in a cluster (it replaced the
  `ops.change-log-purge` lease), and in every front process outside one — two
  trims agree, because the bound is the readers' and not the trimmer's.
* **A process declared gone that was only paused** finds its row missing on its
  next report and logs `STS-STORE-0057`: trimmed changes may be missing from what
  it holds, and a restart restores from the store.
* **Measured against a real postgres** (2026-09-14, the driver against
  `sts_ops_agent`): with no reader nothing was trimmed; with readers at 6 and 13
  the rows below 6 went and 6 stayed; rows younger than the retention stayed
  below the bound; a reader backdated past its lifetime was declared gone and
  the next report re-inserted it (`inserted: true`); a reader naming a node
  that is not a member was declared gone.
* **And against two live active-active nodes** (2 request workers each, a
  private postgres): six readers reported; four rows left by the previous run's
  request workers — a worker is stopped by its front process and never runs
  `leaveChangeReader()` — were declared gone by the node rule on the first trim,
  because their nodes had left. A trim run by hand with a one-second retention
  removed 2426 of 2427 rows below the lowest live mark while both nodes served,
  and afterwards a user created on one node was seen on the other 20 of 20 and
  no node logged `STS-STORE-0057`. So a stopped worker's row is removed by the
  node rule in a cluster, and by the reader lifetime outside one.
* **What is NOT trimmed**: `sts_minted`'s `merge: 'own'` rows. Since
  2026-09-18 a restarted process takes its origin back (below), so a restart
  no longer leaves one behind; an origin whose node never returns (a scale-in)
  keeps its rows, which every fan-in goes on reading — they are the history
  that node wrote, and `retain` keeps them. Nor `sts_cluster_nodes` rows,
  which `joinCluster()` sweeps.
* The capability `ops.change-log-retention` is provided by
  `persistence_replication.js`, not `persistence.js` as the row first named.

## EVERY DIRECTORY ENTRY IS SEALED (#391 phase 6, 2026-10-01)

rcbj's decision on #391: an entry's attributes are stored as ONE sealed blob
under its realm's `directory` data key, in `sts_ldap_entries.attrs` — the cell
tier's key for a cell's people, the service's for the global tier's entries —
and the DN stays readable. `directory_codec.js` is the whole of it; the
postgres driver writes and reads every entry through it.

* **THE BLOB NAMES ITS DN** (`{ dn, a }`), and an open refuses a blob whose
  DN is not its row's: a blob copied onto another entry's row does not open
  as that entry.
* **THE LOOKUPS ARE KEYED DIGESTS THE SERVICE WRITES** (schema version 14):
  `name_keys`, `mail_keys`, `uuid_keys`, `class_keys` stopped being generated
  from `attrs`, and `value_keys` (the `byAttribute()` attributes:
  `VALUE_INDEXED`) and `attr_names` (the NAMES, in the clear) are new.
  `parent_key` and `rdn_value` are still generated from the DN. A database
  built before version 14 is refused at open (STS-STORE-0074): #391 recreates
  rather than migrates, and the service's role may not alter the schema.
* **`value_keys` HOLDS A DEVICE'S FOUR LOOKUPS SINCE #636 (2026-10-14)**:
  `stsDeviceKeyThumbprint`, `stsDeviceSecretHash`, `stsDeviceCredentialId`
  and `owner` joined `VALUE_INDEXED`, so a windowed process recognises a
  device, and lists an owner's, with one `byAttribute` rather than a walk of
  `ou=devices` (`ldap/CLAUDE.md`, *`ou=devices`*). `byAttribute` takes an
  optional parent (`parent_key = $4`): `owner` is also a group's, and an
  owner's devices are the rows directly under `ou=devices`. **`keyArgs()`
  refuses `byAttribute` for an attribute `value_keys` does not hold**, as it
  refuses `classesUnder` for a class `class_keys` does not: either would
  answer "nobody" to a question that looks right. No schema version: the
  column and its index are unchanged, only what the service writes into
  them, and a row written before is not rewritten (it is found again once
  next written).
* **A QUERY IS KEYED AND OPENED ON THE THREAD THAT HOLDS THE KEYS.** The
  windowed directory's bridge thread builds a statement and shapes its rows
  with no keystore, so `persistence.js` wraps the bridge: `keyArgs()` before
  the question, `openAnswer()` after. The driver's own `directoryQuery()`
  does the same.
* **AN ENTRY THAT DOES NOT OPEN IS NEVER TAKEN FOR ONE THAT IS ABSENT.**
  `readEntry()` and the flush's lock read THROW (STS-STORE-0072) rather than
  answer null — the change applier would remove it, a merge would write over
  it. The restore leaves it out and says how many.
* **THE RE-ENCRYPTION JOB WALKS THE DIRECTORY.** A blob hides the values
  sealed inside it (a TOTP secret, Kerberos keys) from LIKE, and a key counted
  as unused is destroyed. `countSealed()`, `countAllSealed()` and
  `resealSealed()` open every entry, a page at a time, and count or re-seal
  the blob's key and every key inside it (STS-STORE-0073 if the walk fails).
* **The keystore starts before the directory is restored** (see
  `persistence.js`): a blob cannot be opened before the key-encryption key is
  read.
* `cell_convert.js` opens the source entries to plan them (a group's members
  split between tiers) and seals what it writes for the tier it writes to.
* A file (ldif) store is not sealed.

## A MINTED ROW'S NAME IS A DIGEST, AND THE NAME IS SEALED (#222, 2026-10-01)

`sts_minted.key` held the name a store filed a record under, and that is
often the credential: a session id (the cookie), a SAML artifact. It is now
the name's KEYED DIGEST (`persistence_minted.js`'s `keyColumnOf()`, under the
keystore's digest key, the same on every node), and `key_sealed` (schema
version 14) holds the name sealed (label `minted-key`). Three readers, three
answers:

* **a reader that has the name** (a change's reader, read-your-write) asks for
  the digest of it;
* **the restore** has no name to start from, and opens `key_sealed`;
* **a change-log row** carries the SEALED name (the driver's
  `recordChanges()`), not the digest, because a reader told of a DELETE must
  drop that name from its own store and a digest cannot say which.

A row with an empty `key_sealed` (written with no key held, or by a test) is
read with its `key` as its name. Both new places are on `EXTRA_SEALED`, so the
re-encryption job re-seals them. `cell_convert.js` carries `key_sealed` with
the row.

## SECRET SETTINGS ARE SEALED AT THE DRIVER'S DOOR (#222, 2026-10-01)

A runtime setting marked `secret: true` in `common/config.js` (today only
`scim.digestPassword`) is sealed when `sts_appconfig` or a realm's
`sts_realms.overrides` is written, and opened when it is read —
`sealed_settings.js` wraps the four settings methods of whatever driver
`openStore()` made (the tiered one in a cell, whose settings go to the global
tier). **Not earlier**: the settings are saved as a delta against a shadow of
plaintext values, and a fresh ciphertext per flush would make every flush a
change. A value that does not open is dropped (STS-STORE-0071) and the setting
falls back to its configured value. Both columns are on the postgres driver's
`EXTRA_SEALED` list, so the re-encryption job counts and re-seals them — **a
column that holds sealed values and is not on that list is one whose data key
the job destroys with the values still in it**.

## THE BULK IMPORT (#629, 2026-10-14)

`node persistence/bulk_import.js --file=… [--realm] [--batch] [--skip]
[--report]`, in the image, with the service's own settings, **with the
service stopped**. rcbj asked for it to take the directory from 10M to 50M
and on toward 200M; an LDAP add is hundreds a second at best. The design is
on #629 (the comment of 2026-10-14). What a maintainer needs:

* **OFFLINE, AND REFUSED WHILE THE SERVICE RUNS (STS-LDAP-0153).** A running
  window holds ABSENCES, and a whole-directory process sees nothing it was
  not told through the change log — one change row an entry would be 200M
  rows. Every postgres process reports into `sts_change_readers` every 15 s
  and a clean stop deletes its row, so a report in the last 60 s is a
  running service; asked after `open()` and before every batch.
* **A ROW IS EXACTLY WHAT AN ADMIN WRITE BINDER'S LDAP ADD WRITES**:
  `putEntry()`'s attributes in its order (timestamps, the locale policy's
  `preferredlanguage` through `localePolicy.populationFor('')` fed the
  realm's `ou=localePolicies` rows from the store, a random v4 `entryuuid`,
  `stsmailverified`), sealed and indexed by `directory_codec`'s
  `sealAttributes()`, `index()` and `dekKeys()` — the three calls
  `entryParams()` makes — origin `bulk import`. **A change to what `putEntry()`
  or `entryParams()` writes is owed here too**; `tests/bulk_import.js` D1
  opens rows and recomputes their columns, and A5 pins the order.
* **THE CHECK IS THREE STATEMENTS A BATCH, NEVER A CORRELATED EXISTS A ROW.**
  The first version guarded the insert with `EXISTS (… name_keys @>
  jsonb_build_array(x))` per row; the planner prices jsonb containment at a
  default selectivity, chose a scan per row, and one 5,000-row batch took
  79 s against 30,000 entries. Now: `dn_key = ANY()`, `rdn_value = ANY()`
  and `name_keys @> ANY($::jsonb[])` (a bitmap scan, one GIN probe a digest),
  matched in JavaScript — `byName()`'s rule for every name of every record.
  **Two more planner traps, both measured:** with `realm`/`parent_key` in
  the same WHERE as `@> ANY()` the planner walked the `(realm, parent_key,
  rdn_value)` btree and compared every person with every digest (14.7 s a
  batch at 20,000 entries), so the digests go through a MATERIALIZED CTE on
  the GIN index alone, with `SET LOCAL enable_seqscan = off` in the batch;
  and on schema 17 the name index's `fastupdate` pending list is read whole
  by every probe (25.8 s for 5,000 probes at 25,000 entries, 13 ms merged),
  so it is merged after every batch where permitted (`namePendingMerger()`;
  schema 18 has `fastupdate = off` and nothing to merge).
* **ONE TRANSACTION A BATCH, COMMITTED UNDER THE REALM'S IMPORT LOCK** —
  `pg_advisory_xact_lock(629, hashtext(realm))` — taken AFTER the insert,
  held through the authoritative check to the commit (see *THE INSERT AND
  THE SEAL ARE OUTSIDE THE LOCK*, below). The insert is `INSERT … SELECT
  FROM unnest($n::text[]…) ON CONFLICT DO NOTHING RETURNING dn_key`; a DN it
  did not insert is one another import inserted meanwhile, and counts as
  present. No `COPY`: the image has no COPY client, and the application
  role cannot create a staging table.
* **IT WAS `LOCK TABLE … SHARE ROW EXCLUSIVE` UNTIL #637, AND THAT IS WHAT
  KEPT AUTOVACUUM OFF THE TABLE.** Every table lock mode that keeps writers
  out conflicts with autovacuum's SHARE UPDATE EXCLUSIVE, and a lock request
  that waits `deadlock_timeout` behind an autovacuum CANCELS it. Measured on
  postgres 18 against a crawling autovacuum: the `LOCK TABLE` request, then
  `ERROR: canceling autovacuum task` one second later. During a multi-file
  import the table's autovacuum never finished (#637: 12M rows inserted
  since the last vacuum at 22M). #637 blamed the end-of-run
  `gin_clean_pending_list()` and `ANALYZE`; the same probe, as a role that
  owns neither, cancelled NOTHING — neither waits on a lock autovacuum holds
  (`ANALYZE` as a non-owner is a WARNING and a skip on 18). **Do not put
  a table lock back** for any reason that a lock between imports serves.
  What the table lock seemed to add — holding a RUNNING service's add out —
  it never did: a running process decides an add against its own window
  before its flush, so a duplicate could arise on its side with or without
  the lock. The guard against a running service is the refusal
  (STS-LDAP-0153), asked before every batch and again under the lock.
* **THE INSERT AND THE SEAL ARE OUTSIDE THE LOCK (#637), SO SEVERAL IMPORTS
  PAY.** A batch: (1) a FIRST LOOK, the three statements without the lock —
  present and taken records dropped and reported, so a re-run still seals
  nothing; (2) the seal and `settleDeks()`; (3) `BEGIN`, the INSERT in
  `dn_key` order; (4) the lock; the live check; the three statements AGAIN
  ON A SECOND CONNECTION; `DROP_OWN` of the batch's rows whose name another
  import committed first, and of any past the ceiling; `COMMIT`. **Why it
  holds:** every import commits under the lock and a commit is visible
  before its lock is released, so a batch holding the lock sees every other
  import's committed rows; their uncommitted rows will see this one's once
  it commits. Two batches never both commit a name. **Why a second
  connection:** it cannot see the batch's own uncommitted rows. Asked in the
  batch's own transaction, every one of its digests matched its own row and
  the name check took ~580 ms a batch under the lock against ~60 ms finding
  nothing, and a WHERE `NOT (dn_key = ANY($own))` compared each own row with
  the whole array (both measured; a lone import fell to 2,600 a second).
  **Why `dn_key` order:** the primary key is the one unique index, so the
  only wait between two inserts is on another import's uncommitted row of
  the same DN (overlapping files), and two batches taking the same keys in
  the same order cannot wait on each other in a cycle; D7 runs the same
  people in opposite orders. **Measured** (postgres 18 with 4 cores, 5,000 a
  batch, as a non-owner): one import 4,200 a second holding the lock 14% of
  its run (develop's: 4,750, since it checks once); two 6,400; four 10,500;
  six 11,800, the database the limit. Under the old table lock, with the
  seal and the insert inside, four ran at 1.6 times one. The report's
  `lockSeconds` and `lockWaitSeconds` say how much of a run could not
  overlap. **Mixing builds is NOT safe**: an older import takes the table
  lock, does not take this one, and checks before it inserts, so it and a
  new one over overlapping files could both admit a name.
  `docs/bulk-import.md` (*Several imports at once*) is the operator's half.
* **WHAT ELSE SEVERAL IMPORTS SHARE, AND WHY EACH IS SAFE** (read for #637):
  `sts_change_readers` — an import never reports there (only
  `persistence_replication.js` does, and the import does not start it), so
  imports never refuse one another; the #618/#623 counters — the deltas are
  keyed by `txid` and folded at COMMIT into this connection's shard, and
  batches of one realm commit one at a time anyway; `REALM_COUNT` — summed
  over the sixteen shards (it read ONE shard from #630 until #637, so the
  ceiling was checked against a fraction of the realm — D6 fails with the
  old statement) and read under the lock, so the ceiling is exact across
  imports, the rows past it deleted before the commit; the realm's `directory`
  data key — two imports making the first one at once each queue a row
  write, and `mergeKeys()` UNIONS the row under `FOR UPDATE`, so both keys
  are kept and each process seals under its own (no key lost; the service
  then picks one by `chooseActive()`); the digest key — made at most once at
  `keystore.start()`, first writer wins and the loser adopts and prunes
  before any digest is taken; `entryuuid` — `crypto.randomUUID()`, random
  rather than process-local; `createtimestamp` — a clock reading, which
  need not be unique; `sts_changes` — written only by a data-key row write,
  through the `seq` sequence, which readers already treat as having holes;
  the realm's row — read once, never written.
* **THE #618 AND #623 COUNTERS NEED NOTHING.** Their triggers are statement
  level over transition tables, so one insert of N rows writes one delta per
  parent and per data key, folded at commit. D2/D4/D6 compare every counter
  with a fresh count.
* **DATA KEYS**: a seal that makes the realm's `directory` DEK queues its row;
  `keystore.settleDeks()` is awaited before the insert (the order rule). The
  keystore is handed the driver's own key functions, as `persistence.js`
  hands them.
* **AFTER THE LAST BATCH** it merges the GIN pending lists
  (`gin_clean_pending_list()` on each GIN index of the table that keeps one)
  and ANALYZEs it: forty million rows in `fastupdate` pending lists make
  every lookup scan them. **ASKED BEFORE IT IS ISSUED (#637)**:
  `maintenanceRights()` asks `pg_has_role(current_user, relowner, 'USAGE')`
  (the merge needs the index's OWNER — MAINTAIN on the table is not enough,
  measured on 18) and, from postgres 17, `has_table_privilege(…,
  'MAINTAIN')` (enough to ANALYZE); what the role may not do is skipped with
  one STS-LDAP-0161 line naming the owner's `VACUUM (ANALYZE)`, and the
  import is still done. The per-batch merge on schema 17 asks the same, once.
  `ANALYZE (SKIP_LOCKED)`, so that the owner's ANALYZE never waits for, and
  so cancels, an autovacuum of the table already running.
* **IT DOES NOT REQUIRE `ou=users` AS A ROW.** Every process seeds the
  containers in memory at start. **A windowed front process on an EMPTY
  store was seen to write the seed's people and not its containers** (the
  base, `ou=users`, the groups): 24 rows where a whole-directory process
  writes 59. Not this tool's to fix, and recorded here because the test's
  seed child uses `ldap.workerDirectory=memory` to get a whole tree.

## A WINDOWED WORKER'S DIRECTORY (#349, 2026-09-29)

With `ldap.workerDirectory=postgres-lru` the directory slot carries a
`window` (`ldap/directory_window.ts`) and a `forgetEntry()`, and this module
does four things differently. `ldap/CLAUDE.md` argues the window itself.

* **`start()` refuses** postgres-lru without a postgres store or with cells
  (`STS-LDAP-0133`), in every process, before anything is opened; and on
  postgres it hands the window its bridge (`common/sync_query.ts`, dialled
  with the driver's `bridgeConnection()`) BEFORE the restore. `stop()` ends
  the bridge's thread after the last flush. **The bridge also carries
  `queryAsync()` since #615**: the same question through the driver's
  `directoryQuery()` (same builder, same keyed values, same opened answer)
  on the read pool, for a scheduler job that can wait —
  `DirectoryWindow.holdersAsync()`, the Android recheck's holders.
* **The flush asks the window first** — `collect()`, with the journal or null
  for a write that named nothing — before deciding whether anything is dirty:
  an entry edited in place is found only by comparison, and the window lets go
  of what it handed out only when a flush has looked. Its upserts (each with
  its own base) and deletes go in the SAME `saveDirectory()` transaction as the
  resident diff; `committed()` or `failed()` answers them, and the write
  shadow is never advanced by them (a windowed key is never in it:
  `realmEntries()` and `entryAt()` answer the resident half).
* **`directoryTouched()`** is a fifth door: an entry was handed out, so a
  flush is scheduled; it marks nothing and moves no generation, because a
  read is not a write and the barrier must not wait on one.
* **`applyDirectoryChange()` merges nothing for a windowed key**: it reads
  the row, as it always does, and hands it to `forgetEntry()` — which notes a
  person another process made in the identity register, as `applyEntry()`
  does — and a busy key (changed, in flight or handed out) is left for this
  process's own flush, which the store merges against the window's base,
  while any other is forgotten and read again when asked for.
  `applyDirectoryOutcomes()` leaves windowed
  keys to `committed()`.

* **The restore reads the RESIDENT entries only** (`loadDirectoryRows()`,
  the `residentOnly` question with each realm's windowed containers from the
  slot's `windowedContainers()`): the people and devices are read when first
  asked for, which takes the directory out of a worker's start (#333 measured
  it at a fifth of a sixty-eight-second start). The identity register was
  still filled with every restored person, from their NAMES read a page at
  a time, until #613 removed that pass (`ldap/CLAUDE.md`): nothing under a
  windowed container is read at start now. A realm's seed is still built at
  require time in every process.

`tests/directory_window.js` section F drives all of it through this module
over a `pg` double, including a change made here and one made there to the
same entry both surviving, and the resident-only restore.

## WHAT A RESTART MUST NOT LOSE (2026-09-18)

A redeploy of the testidp cluster showed `/admin/users` with one authenticated
row of 423. Tracing it found four ways a restart lost data, and each is fixed
where it was:

* **RETENTION WAS BY AGE FOR EVERY STORE.** `persistence_minted.restore()`
  dropped, and `purgeMinted()` DELETED, every row whose `written_at` was older
  than `persistence.mintedRetention` (seven days) — and a row is rewritten
  only when it changes. So a named authorization server, a custom claim set,
  an ACME account, a status-list entry, a revocation or a runtime Kerberos
  principal made more than a week ago and not touched since left the
  database at the next start of ANY node, and every other node at its own.
  Now a store declares `retain` at `realms.map()` (`common/realms.js`):
  `'keep'`, the default, is never dropped by age; `'age'` is the short-lived
  stores — nonces, codes, pending flows, in-flight transactions — whose rows
  are left behind only by a process that stopped before sweeping them, and
  whose every lifetime is far below the retention. (Since #333 the restore
  only SKIPS those rows, in its query, and the `persistence.minted-expiry-purge`
  job deletes them — see the next section; `purgeMinted(before)` is now only
  the ephemeral-key clear, where nothing in the table can be opened anyway.) An
  unknown word is `STS-CORE-0098` and read as `'keep'`: a retention policy
  that fails must keep data. Forty-three stores are `'age'`.
* **A RESTARTED PROCESS WAS A NEW ORIGIN.** The origin was `pid-<uuid>` per
  start, so what a container's previous life wrote to a `merge: 'own'` store
  became another origin's contribution, read only by fan-in readers — and
  then deleted by the rule above. Now `persistence.js`'s
  `adoptStableOrigin()` names the origin `n:<cluster.nodeName()>:<slot>`
  (`front`, or `protocol-N` / `surfaces-N` from `STS_REQUEST_WORKER_SLOT`,
  which `request_pool.js` hands each worker) and the postgres driver's
  `adoptOrigin()` takes it through a claim in `sts_cluster_claims` (scope
  `persistence.origin`, 30 s, renewed every 10 s, released at a clean stop).
  A live holder is waited out for 35 s — a crashed one's claim lapses in
  that time — and after that the process keeps a random origin
  (`STS-STORE-0060`), which is safe because the fan-in reads it. **Every
  transaction checks the claim** (`checkOriginFence()`, under `FOR SHARE`,
  before the cluster fence), so a process paused past its claim finds its
  writes refused rather than overwriting its successor's rows; outside a
  cluster it exits (`STS-STORE-0061`), inside one the cluster's fail-stop
  does. **LAPSED IS NOT TAKEN (2026-09-21)**: ownership is the RESERVATION
  on the row, which a process that takes the claim replaces — so the
  renewal and the fence's `reassertOrigin()` extend a claim that still
  carries this process's reservation even after it lapsed, and only a
  reservation that is somebody else's is fenced. Until then both asked for
  a LIVE claim, and the suite's first product-mode run killed its own
  service: under the SCIM bulk load the pool (`max: 4`) had no connection
  for two renewals, the claim lapsed with no other process anywhere, and
  the process exited saying another one held it
  (`tests/persistence_origin.js` section B2). The membership node id is still random per start: a node whose
  membership lapsed must not come back as itself. **Since #617 a request
  worker gives its claim back as it exits, and a claim whose node membership
  has LEFT or EXPIRED is taken over rather than waited out** — see *What a
  start waits on*, below. A platform that gives each
  container a random host name needs `cluster.nodeName` set for any of this
  to apply.
* **TWO ACCUMULATORS WERE NEVER FANNED IN** — `admin_stats.scimCounts`
  (`scimCountsAll()`, a deep merge) and `ssf_streams.received`
  (`listReceived()`, deleted with `POST /ssf/receive` by #593). The users register had the same defect and was fixed in
  its own change (`tests/user_register_fan_in.js`).
* **THREE STORES WERE NEVER PERSISTED** — see the table above.

`tests/persistence_origin.js` holds B, C and D against a fake `pg` whose
claims table two drivers share; `tests/minted_persistence.js` section 6 holds
retention both ways. Ten mutants across the two, all caught.

## A START READS ONLY LIVE ROWS OF DEFINED REALMS (2026-09-28, #333)

Measured on testidp (build c8a2327b): each process — front, three request
workers and a surface worker, on every node — spent **31 s** in
`persistence_minted.restore()` reading `127131 minted row(s) … across 138
declared store(s)`, which pushed a request worker's start past its 60 s limit
and made the pool give up. `loadMinted()` was a `SELECT` of the whole of
`sts_minted` with no `WHERE`; every row was fetched, decrypted and parsed, and
the only filter was in JavaScript — `retain: 'age'`'s seven days of WRITE age.
Rows of the 132 realms the suite had left behind, and every code, nonce and
pending flow that had expired days earlier but was written within the week,
were all read back.

rcbj's decision: **the startup query asks only for currently valid data in
currently defined realms.** Four parts:

* **The read says what it wants.** `restoreFilter()` in
  `persistence_minted.js` hands `loadMinted(filter)` the realm partitions that
  exist (`''` for the shared stores, the default realm, and `realms.list()` —
  the registry `persistence.start()` has already loaded), the instant, and the
  `retain: 'age'` handles with the retention cutoff. The driver turns it into
  `realm = ANY($2) AND (expires_at IS NULL OR expires_at > $3) AND NOT
  (expires_at IS NULL AND handle = ANY($4) AND written_at < $5)`. The filter is
  REQUIRED: a caller that does not say what it wants is refused rather than
  handed the table. A realm created on another node in the seconds between
  this process loading the registry and reading its rows is not in the list;
  that window is the one that already existed between the restore and
  `coordinate()`'s starting sequence number, and the realm's later writes
  arrive through the change log as before.
* **A row carries its own expiry.** A store declares `expiresAt(value, key)`
  beside `retain` (`common/realms.js`; `realms.expiryField(field, scale)` is
  the common shape), the flush writes its answer to `sts_minted.expires_at`
  (epoch ms on the writing process's clock, compared with the reading
  process's `Date.now()` — `sts_used_assertions`' arrangement), a merged row
  writes the MERGED record's answer, and a tombstone writes NULL so only its
  own purge ever takes it. The hook runs inside the row's realm, so a lifetime
  setting is read for the realm the row belongs to. A hook that throws writes
  NULL (`STS-STORE-0064`, once per store): kept is the safe failure. **The rule
  a hook must keep: never earlier than the store itself would drop the row.**
  So a store that keeps a record past its expiry on purpose answers that later
  instant — `admin_stats.tokens` its `exp` plus the skew plus
  `oauth2.expiredTokenRetentionS`, CIBA and device codes a finished request's
  end plus their hour of retention — and a record whose ending does something
  has NO hook: a pending CIBA request (its expiry sends the push client
  `expired_token`), `authn.sessions` (the sweep audits, signals CAEP and plans
  back-channel logout for each), the three outbound delivery queues and
  `mail.outbox` (a stale pending row becomes a dead letter, audited, first),
  `gnap.tokens` (RFC 9635 section 6.1.1 lets an EXPIRED token be rotated,
  and this AS does), and `vc_status.entries` (a dropped entry would publish
  its bit as VALID). Those stores' own sweeps delete their rows, and each
  delete reaches the table like any other write.
* **The restore deletes nothing.** It used to purge stale rows in EVERY
  process at every start; now the CLUSTER job `persistence.minted-expiry-purge`
  does (every five minutes): expired rows, rows of a realm not in `sts_realms`
  written over an hour ago (a realm another node is creating writes its minted
  rows and its registry row in two transactions, and the grace covers the
  gap), and stale short-lived rows with no expiry. Each batch is one `DELETE …
  WHERE ctid = ANY(ARRAY(SELECT ctid … LIMIT 5000))`, so a row rewritten
  between the two halves has a new ctid and is left alone; at most twenty
  batches of each kind per run, the rest left for the next — a start skips
  them meanwhile, so a backlog costs disk and never start-up time. One summary
  line per run that deleted anything; `STS-STORE-0065` when it fails.
  `STS-STORE-0025` (the restore's purge failing) is retired.
* **A removed realm's rows.** `realms.remove()` already deletes its
  `sts_minted` rows in the directory transaction (`saveDirectory()`'s
  `removedRealms`), for a realm this process removed. What could still leave
  one behind is another process's flush in flight for that realm; the
  orphan clause of the job collects it.

**Schema version 12**: `sts_minted.expires_at bigint` and the partial index
`sts_minted_expires ON sts_minted (expires_at) WHERE expires_at IS NOT NULL`
(`postgres/CLAUDE.md` for the upgrade). Existing rows get NULL and fall under
the write-age rule once; there is no other migration. The index is partial
because the rows with no expiry are never looked up by it, and every INSERT
into this, the busiest table, pays for an index.

**`scheduler.runs` has a hook too, and it is not a record's own expiry
(#338).** A run row has no lifetime of its own; what ends it is the history's
BOUND — per job, its last `scheduler.runHistoryCount` runs or its last
`scheduler.runHistoryHours`, whichever keeps more — and `scheduler.history`,
not the expiry purge, deletes it, through the store (tombstoned, so every
process drops it). The hook answers an instant past the first moment that
purge could delete the row, so a start skips most of what it has not got to
yet, and the purge PINS (`keepUntil`) a kept row whose instant is near — a job
that stopped running, a bound raised later — so the hook's rule, never
earlier than the store would drop the row, holds. `cluster/CLAUDE.md`, *The
scheduler*, argues it. Rows written before #338 carry NULL and are read until
the purge has deleted them.

**What is still read whole, and why.** The `merge: 'own'` accumulators —
`audit.events` above all — carry no expiry: a row is a process's share of a
ring or a counter, not a record with a lifetime. `audit.events` is one row per
32-event segment, per realm, per ORIGIN, up to `audit.maxEvents` (5000) events
each — about 157 rows per origin per realm that has any events — and a start
decrypts every origin's: its own into its ring, every other origin's into the
replication fan-in (`replication.contribute()`), which the console reads. With
five processes per node, a three-node cluster has fifteen origins, and a
random origin left by a process that could not take its stable one is never
aged out. That is kept as it is here and reported on #333.

**A removal from the fan-in takes its empty levels with it (#618,
2026-10-14).** `contribute(handle, realm, key, origin, null)` deleted the
origin and left the key's Map behind, empty, for ever; a removal of something
never held MADE the levels to empty them. `admin_stats.users` notes every
replicated create in every process and journals the eviction of each note past
its `MAX_USERS` cap, so a bulk load left one empty Map, its table and its key
string per person ever added in every process. A heap snapshot of a request
worker on 8081 at about 974K people held 798,858 keys under
`admin_stats.users`, 796,728 of them empty: about 300 bytes a person per
isolate, the live-heap growth #618 measured, and `everyUserRecord()` walked
them all on every read of the users register. Now a removal looks up without
creating and deletes each level it empties, all O(1), so what is held is
bounded by what the other processes HOLD (origins x the store's own cap).
`contributionCounts()` counts it; `tests/replication_fan_in_bounded.js` drives
thirty thousand notes and evictions through three origins and holds the count
at the cap.

**And a dead process's contributions go (#618 phase 2, 2026-10-14)**, which
closes the "never aged out" above for the fan-in in memory. The cap is per
ORIGIN, and a random origin, or a node that left the cluster, never removes
its rows — so every such process left up to a cap of each store in every
other process until that one restarted, and the restart read them back.
`pruneFanIn()` drops an origin that has not been a LIVE READER of the change
log (`liveChangeReaders()`: `sts_change_readers`, reported within the reader
TTL and naming no node that left — the trim's own test, read without
deleting) for the grace, `max(reader TTL, 15 minutes)`. The floor is because
most origins are stable since 2026-09-18: a process restarting under its
name takes its origin back, and anything dropped while it was away returns
only as it is rewritten (a counter on its next change, an audit segment
never) or when the reading process restarts. **It is not a job of its own**:
the change-log pull's per-process job runs it after a pull, at most once a
minute, one read of a table with a row per process, and a walk of the fan-in
only when an origin is dropped. A failed read drops nothing
(`STS-STORE-0082`): an origin is dropped on the readers' evidence, never on
its absence. Only memory is dropped; the rows stay in `sts_minted` under
`mintedRetention`. `tests/replication_fan_in_bounded.js` section 6.

**The second map the heap snapshot saw growing** (4K to 6.4K slots in 21
minutes, mostly deleted-entry slots) is THIS process's own
`admin_stats.users` partition (`realms.map`, the one `userRecord()` caps):
the same 3,987 live records in both snapshots of 8081's worker, and 4,840
holes in the second. The holes are V8's: an ordered hash table marks a
deleted entry and reclaims it at its next rehash, so note-then-evict churn
fills the table with holes up to its capacity, which is bounded by about
twice the live count. It is bounded, and nothing was changed for it. (Why a
worker holds 3,987 records under a cap of 2,000 was not settled: `restore`
writes a row without the cap, and a row whose origin is this process's is
restored rather than fanned in.)

`tests/minted_persistence.js` sections 6 and 6b hold it against a stub driver
that applies the same WHERE: the filter's realms, cutoff and short-lived
handles; an expired row not restored, a live one and a non-expiring one
restored; the undefined realm's row left out and purged; the hook's value
written, NULL for a hook that throws; the job a cluster
job; one run bounded at 100,000 rows with `more`, the next finishing.

## WHAT A START COSTS THAT GROWS WITH THE DATA (#613, 2026-10-13)

Measured on 8081 (product, postgres, the window on, 131,546 people in the
default realm, front + 2 protocol workers): about 1 m 35 s from the first log
line to the second worker ready, each process's event loop held 14–18 s at
once, a heartbeat 15 s late (STS-CLUSTER-0025) and an origin-claim renewal
that took 22.5 s of a 30 s claim (STS-STORE-0069). A larger directory would
have cost the node its membership. Four costs, and what became of each;
`tests/tools/startup_profile.js` measures the first three above the SQL
(`docker run --rm <tests image> node tests/tools/startup_profile.js`):

| Cost on 8081 | Cause | Now |
|---|---|---|
| 14–18 s held, per process, in `replaceRealm()` | the identity register pre-fill: every restored person's name read through the synchronous bridge (263 pages of 500) and noted | **gone** — `ldap/CLAUDE.md`, *Restoring*. The notes alone are 0.43 s for 131,546 names in the profile; the rest was the bridge |
| the 11.2 s gap after `sts: persistence is postgres` | the same pass's journal: the register is a minted store capped at `MAX_USERS`, so the pre-fill journalled 131,546 keys (2,000 writes, 129,546 deletes of rows that never existed), and the bootstrap's `flushMinted()` (`credentials.bootstrapOnce()`) waited for them to be sealed, written and appended to the change log — which moved ~132K positions per process start and was then pulled by every other process | **gone** with it. The profile holds the loop 2.6 s for that flush against a `Map`; on postgres it was the gap. Attributed from the change log's movement and the profile, not re-measured on 8081, which was not restarted |
| ~4–5 s per process restoring ~48K minted rows | `restore()`'s loop — open, parse and restore every row — was one synchronous `forEach` | **sliced**: `restoreInSlices()` in `persistence_minted.js` yields every 50 ms; writes between slices are kept aside like the writes made while the rows were loading, and flushed after. 48K small rows: 0.60 s in one piece before, under 60 ms at a time now. The total is unchanged and still linear in the rows (the #333 filter is what bounds the rows) |
| ~2 s per process publishing 279 CRLs | every process signed and wrote every authority's CRL into the shared directory at start | **once a node**: a request worker publishes none (`common/pki.js`, `start()`); the front did before forking it — and since #617 after its listener binds (next section) |

**The workers still start one after another** (`workers.startConcurrency`,
default 1): #342's reason is the node's memory, not time, and it has not
changed — each start restores the store into its own heap. With the pre-fill
and the CRLs gone a worker's start loses ~18 s, and the listener already binds
after the first worker of each pool (`common/CLAUDE.md`, *Workers start one at
a time*). An operator with memory to spare raises the setting.

**What is still linear and was left**, and why: a store WITHOUT the window
(memory, ldif, cells, or `ldap.workerDirectory=memory`) restores every entry in
`replaceRealm()` in one pass — the directory is the data there, held whole by
choice (40,000 people: ~0.2 s in `tests/startup_large_directory.js`). The
replication appliers' note of a person ANOTHER process created, which was the
next candidate named here, is gone (#618 phase 2, *WHAT ONE ADD WRITES TO THE
CHANGE LOG*, below).

`tests/startup_large_directory.js` holds the fix: 40,000 people behind a
window restore with the loop held under 250 ms, no person read from the store
and the register the same size as with 400; the whole directory in memory
leaves the register empty; 40,000 minted rows restore with the loop never held
250 ms.

## WHAT A START WAITS ON (#617, 2026-10-14)

Measured on 8081 (product, postgres, 23 realms, ~200K entries, 52K minted
rows, two request workers): 31.7 s from container start to the listener —
about 18 s in the front process before its first worker was forked, then 13.5
s of that worker, because the listener binds once the first worker of each
pool is ready. Four things on that path were not needed there, and each moved:

* **The CRLs** (4.2 s of the front, 279 lists): published after the listener
  binds, from `server.js`'s `announce()`, yielding between lists —
  `common/pki.js` (`publishStartupCrls()`) argues why nothing before the socket
  needs them.
* **The origin claim** (2 s of the first worker, and up to the claim's 30 s):
  a worker held its claim until it lapsed, because only the front process
  ever released one (`stop()`). Now `common/request_worker.ts` calls
  `persistence.releaseOrigin()` once its server has closed — the journals
  written first, the claim given back last, the thread exiting at once — and
  the postgres driver's `adoptOrigin()` TAKES OVER a claim whose node
  membership has gone: a claim records the membership that took it (after an
  `@` in the row's informational `origin` column, so the schema version is
  unchanged), and one whose membership's `sts_cluster_nodes` row has left or
  expired is replaced in one statement. A claim of a LIVE membership —
  another container under this node name, a sibling worker of the same front
  still draining — and one naming no membership (clustering off, or a front
  that has not joined yet) are waited for exactly as before, and the old
  holder is fenced as after a lapse. A front process joins under the id it
  took its claim with (`cluster.plannedNodeId()`). `tests/persistence_origin.js`
  section B3.
* **`scheduler.runs` in a request worker** (42,740 of the 52,234 rows): not
  restored — `restoreInWorkers: false` at its declaration, the page and its
  API pinned to the front process (`cluster/CLAUDE.md`, *A request worker does
  not read the history back*). Why not lazily, or every store: a minted store
  is a synchronous `Map` every request reads in memory, so a row a worker did
  not restore is a row it answers WITHOUT — the change log brings only what
  is written after the worker's start. A store can be left out only where
  nothing a worker answers reads it whole, and the run history is the one
  that is true of and worth it; `admin_stats.users` (8,177 rows) and
  `audit.events` (594 rows, 13.6 MB, the fan-in) are read by console pages a
  worker answers, and stay.
* **The management API's request validators** (~1.3 s of every process's
  module load): compiled on first use (`mgmt-api/CLAUDE.md`).

| Process, phase | 8081 before (log) | After | How the after was got |
|---|---|---|---|
| front: module load | 5.7 s | ~4.4 s | management API load and wire 1,250–1,431 ms → 37–49 ms, tests image, three runs each |
| front: open, origin, join | 0.1 s | 0.1 s | unchanged (its predecessor's `stop()` released the claim) |
| front: keys | 2.0 s | 2.0 s | unchanged |
| front: directory | 1.4 s | 1.4 s | unchanged |
| front: minted restore (52,234 rows) | 3.0 s | 3.0 s | unchanged: the front restores every store |
| front: PKI | 0.4 s | 0.4 s | unchanged |
| front: CRLs into the directory | 4.2 s | 0 before the listener | after it, yielding (`tests/crl_directory_publication.js` F) |
| **front: to the first fork** | **~18 s** | **~12.5 s** | sum |
| worker 1: module load | 5.3 s | ~4.0 s | as the front's |
| worker 1: waiting for its origin claim | 2.0 s (up to 30 s) | 0 | `waitedMs: 0`, B3 |
| worker 1: keys | 1.7 s | 1.7 s | unchanged |
| worker 1: directory | 1.3 s | 1.3 s | unchanged |
| worker 1: minted restore | 2.5 s (52,234 rows) | ~0.5–0.9 s (9,494 rows) | above the SQL, `tests/tools/startup_profile.js` `split`: 900 ms → 161 ms; the query reads 18% of the rows and about 37% of the bytes |
| **worker 1: to ready** | **13.5 s** | **~8.5 s** | sum |
| **container start to listener** | **31.7 s** | **~21 s** | front + worker 1 |

**The after column is measured in process and summed, not measured on a
stack**: the 8081 container was not restarted, and a private product stack
with 52K minted rows and 200K entries was not built for this. A second worker
(and every worker the pool forks later) saves the same ~5 s, behind the
listener.

**Found on the way and left, with why:**

* **The change log's starting point is taken AFTER the restore.**
  `coordinate()` asks `latestChangeSeq()` once every store is restored, and
  `replication.start()` treats everything at or below it as applied — so a
  change committed after a restore's own read and before that call is in
  neither, and a process that starts behind a live listener (every worker
  after the first) can answer without it. Taking the mark BEFORE the minted
  restore's read would close the minted half (re-applying a minted change is
  idempotent: the applier reads the current row) and shrink the rest; it was
  not changed here because it moves the replication contract every process
  starts on, and wants the full suite.
* **The keystore's start** (2.0 s front, 1.7 s each worker: 25 authorities,
  204 data encryption keys) and **each process writing the default realm's
  certificate authority back to the store at every start** ("written to the
  store, encrypted", and "built by worker 2; every process here now agrees"
  eight times on 8081) — not looked into.
* **`audit.events`' 594 rows (13.6 MB)** decrypted into every process's fan-in
  at every start — the next-largest cost, read by the console's audit pages,
  which workers answer.

## WHAT ONE ADD WRITES TO THE CHANGE LOG (#618 phase 2, 2026-10-14)

**Every minted row a flush writes is a row of `sts_changes` too**: sealed,
inserted, NOTIFY'd, and then pulled, opened and applied by every other
process. On 8081 (about 3M entries, 55 LDAP adds a second) one LDAP add cost
about 9.7 of them, and PostgreSQL spent about 1.6 cores on it.

| Store | Before | After | Why it was written |
|---|---|---|---|
| directory | 1 | 1 | the entry |
| `admin_stats.users` (own) | 4.0 | 0 | every OTHER process noted the replicated create in its identity register, and past `MAX_USERS` journalled the eviction |
| `risc.register` | 2.3 | 0 | a blank row per account created, and past `risc.maxAccountsTracked` the eviction of the oldest |
| `admin_stats.nums` (own) | 0.9 | 0 | `usersForgotten`, bumped by those evictions |
| `audit.events` (own) | 0.8 | ≤ 1 | the add's audit event |
| `audit.nums` (own) | 0.7 | ≤ 1 | its counter |

The two fixes are argued where they live: the appliers' note in
`ldap/CLAUDE.md` (the creator's record reaches every process through the
fan-in) and the RISC row in `ssf/CLAUDE.md` (a row is kept when it says
something an absent row does not).

**A COUNTER IS ALREADY ONE ROW PER FLUSH**: the journal is a Set of keys, and
a `realms.obj()` store journals its one key, so ten audit events in one flush
write `audit.nums` once. What makes it one row per ADD is the cadence — in
postgres mode the flush delay is 0 and a request worker flushes at every
commit announcement — and that cadence is the read-your-write barrier's, so
it stays. `audit.nums` could leave the change log only by being derived from
the ring (its `recorded` is the ring's absolute end); that is not done.

**AN EVICTION FROM A CAPPED STORE IS STILL JOURNALLED AS A DELETE**, and has to
be: a row not deleted stays in `sts_minted` and in every other process's
fan-in for ever, which is the store and the heap growing with the directory
— the defect `tests/replication_fan_in_bounded.js` holds. The fix was to stop
writing the rows that were evicted, not to stop deleting them. What still
pays it: a person made through a DOOR (`createUser()`: the console,
`/admin-api/users/create`, SCIM) is noted `created` in the creating process's
register, and past `MAX_USERS` that is a note and an eviction — two rows, in
that one process only.

`tests/change_rows_per_add.js` counts what the stores journal (a persist
observer) with a flush after every operation, past both caps, in a process
holding the whole directory and in a windowed worker: a replicated create
journals nothing, a local LDAP add at most the audit event and its counter,
ten adds in one flush the counter once; a door create is still `created`, and
an account created disabled, a service account and an update of a held
account still have their RISC rows. Seven mutants, all caught.

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
`persistence_replication.js`'s; `reportChangeReader`/`leaveChangeReader`/
`purgeChangeLog` beside them since 2026-09-14, and a driver without them is
never trimmed). **A THIRD SINCE 2026-09-13**, and it is
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

**THE SAVES TAKE A DELTA AND ANSWER WHAT THE STORE DECIDED (2026-09-14, #46).**
`saveRealms(rows, delta)` and `saveOverrides(map, delta)` — a snapshot driver
writes the first argument, a database the second and must delete nothing the
delta does not name; `saveDirectory()` may answer `{ outcomes }` and
`saveMinted()` `{ refused, merged }`, and a driver that answers nothing is read
as having written exactly what it was handed. See *Several nodes writing one
row*.

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
* **The client refuses to make one, IN EVERY MODE AND WHATEVER THE STRING
  SAYS (#273, 2026-10-07).** `dialOptions()` dials every connection over TLS:
  a string with no `sslmode` is `require` (the default
  `persistence.databaseUrl` has none, and until #273 it connected IN THE CLEAR
  with a warning, against any database that allowed it), and `prefer` is TLS
  too. A string whose `sslmode` is `disable` or `allow`, or that is not a
  `postgres://` URL (a libpq keyword/value string cannot be edited safely, so
  what `pg` would do with it cannot be told), is REFUSED with
  `STS-STORE-0078` — not overridden, because passing `ssl` regardless would
  make `sslmode=disable` mean its opposite, a connection string saying one
  thing while the client does another. `persistence.start()` is the one fatal
  open, so the service does not start. The same holds for the read and global
  databases and for `cell_convert.js`, which dial through the same function.
  A Unix socket has no TLS: postgres answers the request with "N" and the
  connection fails.

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

`/admin/persistence` draws them as one *Transport* row saying both, because
"encrypted" and "authenticated" are different facts and a single tick would
have to round one of them.

**AUTHENTICATION IS ON BY DEFAULT, IN EVERY MODE (rcbj, 2026-10-12).**
`persistence.databaseTlsRejectUnauthorized` defaults to `true`. It was off,
argued as "a statement about the stack rather than a weakened default": the
compose certificate is self-signed, so there was nothing to verify it
against. That argued from one stack to the default every deployment gets,
and an unauthenticated database is one anything at its address can
impersonate, reading and writing every row — so the stack was changed
instead of the default:

* **`persistence.databaseTlsCaFile` — the database's own trust anchor.** A
  PEM file, or a directory whose `.crt` and `.pem` files are all read,
  trusted for the database connections ONLY: `databaseTlsCa()` reads and
  checks it, and `dialOptions(url, verifyTls, ca)` puts it on the `ssl`
  option as `ca`, which REPLACES node's default store for that connection
  and no other. `NODE_EXTRA_CA_CERTS` would have worked and was refused for
  the stack: it trusts the anchor for every outbound connection this process
  makes. Every dialler gets it — both tiers' pools and LISTEN clients and
  the read pool (`create()`'s `tlsCa`), the directory bridge's thread (PEM
  text crosses; `bridgeConnection()` keeps `ca` when it rewrites verify-ca
  as data, and `common/sync_query_thread.ts` keeps it when it puts the hook
  back), and the two processes that are not the service through
  `databaseConnection()` / `globalDatabaseConnection()` (the risk loader,
  `cell_convert`). **A file named and unusable is FATAL**, `STS-STORE-0079`,
  read inside `openStore()`'s `try`: falling back to the default store would
  dial with a trust anchor nobody chose and then fail with "self-signed
  certificate", pointing at the wrong thing. The status report catches it
  and says the store is not dialled rather than throwing.
* **The compose stacks share the certificate, never the key.**
  `postgres/generate-tls.sh` copies `server.crt` to
  `${POSTGRES_TLS_PUBLIC_DIR}/<CN>.crt` on every start (`postgres/CLAUDE.md`);
  `sts` mounts that volume read-only, names it in `STS_DATABASE_TLS_CA_FILE`
  and dials `sslmode=verify-full`. The test stack names the DIRECTORY, so
  the cells layer's two cells trust `postgres-global.crt` and their own
  database's from one setting — the reason a directory is accepted at all.
* **Turning it off is loud.** `create()` logs a WARNING rather than an info
  line, the status prose for an unverified connection begins `WARNING` and
  says what it costs, Monitoring → Database draws it as a warning box and
  `/admin/persistence`'s *Transport* row in red.

**The connection is encrypted either way** (#273, above); this decides only
whether the server is believed.

**`sslmode=verify-ca` AND `verify-full` VERIFY, WHATEVER THE FLAG SAYS (rcbj,
#543 round 2, 2026-10-12).** Until then `dialOptions()` stripped the
parameter and the flag alone decided, so a string that said `verify-full`
beside the default flag dialled an unauthenticated server — the string saying
one thing and the client doing another, the shape #273 removed for
encryption and had left standing for authentication. Now the verify modes
mean what libpq means: `verify-full` checks the chain and the host name,
`verify-ca` the chain only (a `checkServerIdentity` that checks nothing,
because node checks the name whenever it checks the chain). The flag decides
only for no sslmode, `require` and `prefer`, both halves together; it can add
verification there and never take it from a verify mode. A certificate that
fails is a connection `pg` refuses, and at start that is the fatal open,
`STS-STORE-0006`, with node's reason. **A function cannot be posted to a
thread**, so the directory bridge's options (`bridgeConnection()`) say
verify-ca as `hostnameUnchecked` and `common/sync_query_thread.ts` puts the
hook back — dropping it instead would make the thread check a name the pools
do not, and refuse a server they accept. `dialOptions()` answers
`verifyChain` and `verifyHostname`, and `describeDatabase()` reports from
those, so the *Transport* row says what the driver checks.

The flag and the CA are READ in `persistence.js` and PASSED IN to the driver,
rather than read there: that module takes its url and its logger as options and reaches for
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
so `keys.json` and `sts_keys.material` hold `$aesgcm$2$<dek id>$iv$tag$body`
and, beside them, the `dek:<scope>:<realm>` rows of DATA ENCRYPTION KEYS each
wrapped under the key-encryption key (#391, `common/CLAUDE.md`) — nothing
else. That is what makes it acceptable for private keys to live beside
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

### A realm being retired is a column of its row (#262, schema version 10)

`sts_realms.retiring_at` is `realms.retire()`'s mark (`common/CLAUDE.md`,
*`retire()` and `onRetire()`*). It rides the realm row rather than a minted
store because the realm registry is replicated in BOTH modes and minted state
only in product. `realmRows()` carries it as `retiringSince`,
`realmChangeOf()` reports a mark the shadow lacks as `retiring`, the upsert
writes it with `COALESCE(sts_realms.retiring_at, EXCLUDED.retiring_at)` so no
write ever clears one, and `restoreRealms()` hands it to a replicated
`update()` (or sets it on a realm restored at start, whose removal was begun
and not finished). This module's `realms.onRetire()` hook is a `mark` that
flushes, so the row and its change-log row are committed before `retire()`
ends anything. The ldif driver needs nothing: it writes the rows as JSON.

### Each node's snapshot is a table of its own (#332, schema version 11)

`sts_node_snapshots` holds each cluster node's latest Monitoring → Worker
Pools and → Node Health views, one row per node NAME, overwritten every
fifteen seconds by `cluster/node_snapshots.ts`'s per-process job and read by
whichever node draws those pages. The driver's `putNodeSnapshot()` (one
upsert at the database's clock), `nodeSnapshots()` (every row, at most 64,
with the database's `now`) and `purgeNodeSnapshots(olderThanMs, keepNames)`
(one DELETE of the rows older than the age by the database's clock whose name
is not kept, answering the names; an empty keep list is refused, because it
means a membership read that failed) are the whole interface, reached through
`clusterStore()`; memory and ldif have neither, and the pages say there is
no cluster store. **Not `sts_cluster_nodes.info`**, which is where another
node's cache figures ride: that column is rewritten on every heartbeat and
read, for every retained row, on every heartbeat — a snapshot is kilobytes,
and the heartbeat is what a node's life depends on. The write is not fenced:
it is a report, not state anything acts on, and its age is drawn.
`schema.sql` adds it with `CREATE TABLE IF NOT EXISTS`, and the grants on
every table in the schema cover it.

### The directory's counts are kept by the database (#618, schema version 16)

`sts_ldap_counts` holds, per realm and per base (every ancestor of a row's
DN, and `''` for the realm), the entries strictly under it and those holding
a counted attribute (`directory_queries.COUNTED_ATTRIBUTES`: `userpassword`,
the one the #610 tiles ask). `count` and `countHolding` read it — one
primary-key read where each was a `count(*)` linear in the realm's rows, on
`DirectoryWindow.capCount()`/`sizeIn()`/`exactCount()` (`ldap.maxEntries`),
`recentCountUnder()`/`countUnder()` and `countHolding()`.

**TRIGGERS, NOT THE DRIVER**, because the driver is not the only writer: the
flush's per-row statements, the merge, a removed realm's DELETE, a cell
conversion's upserts and a hand-run statement all land in the same table, and
a counter kept by one of them is wrong the first time another writes. Each
statement-level trigger reads its transition tables, so it counts its own
rows, never the directory.

**AND NOT DIRECTLY INTO THE COUNTERS.** Every write of a realm touches the
same rows (`''`, the base DN, `ou=users`). A trigger updating them would hold
that lock from a flush's first statement to its commit, serialising every
flush of the realm across processes, and would close a deadlock with the
entry locks the flush takes in key order (`saveDirectory()`'s *one lock order*).
So a statement appends its net per parent to `sts_ldap_count_deltas`
(insert only), the transaction's first delta also appends a row with `fold`
set, and that row's deferred constraint trigger folds the transaction's
deltas into the counters at COMMIT: one statement, in key order, after every
entry lock is taken. A rollback (whole, or to a savepoint) takes its deltas
with it. Nothing periodic is involved, so there is no scheduler job.

**ONE COUNT, ONCE.** `open()` probes the functions and triggers by name
(`pg_proc`, `pg_trigger`: `to_regclass()` knows only relations) and creates
what is missing. When it created a trigger, it LOCKs `sts_ldap_entries`
(SHARE ROW EXCLUSIVE, which every writer waits on) and runs `COUNTS_BACKFILL`
while the counters are empty. `postgres/schema.sql` does the same. That is
the only count of the directory, and an operator upgrading a large store pays
for it once. `tests/directory_counts.js` holds the statements, the window's
arithmetic and the one count in process. With `STS_TEST_POSTGRES_URL` it also
checks exactness against a real postgres under eight concurrent writers (run
on #618 against a scratch postgres:18). `tests/postgres_schema.js` holds the
script and the driver together, functions and triggers included.

### What the directory holds under each data key (#623, schema version 17)

`sts_ldap_entries.dek_keys` is `{ "<dek id>": <values> }` — the sealed
blob's own data key once, and the key of every value sealed INSIDE the blob
(a TOTP secret, Kerberos keys) once per value: `directory_codec.js`'s
`dekKeysOf()`, written by `entryParams()` beside the lookups, by the
re-seal's UPDATE and by `cell_convert.js`. It replaced the directory WALK of
the re-encryption job and the data-key count (`walkDirectory()`, every row
opened on the front process, twice an hour while any key was superseded:
about 90 s of the thread at 1.5M entries on 8081), so:

* **A re-seal reads `dek_keys ?| <superseded ids>`** (GIN, default operator
  class), in key order after a cursor, and opens only those rows.
* **A count reads `sts_ldap_dek_counts`**, kept by triggers on
  `sts_ldap_entries` exactly as `sts_ldap_counts` is, for the same two
  reasons above (every writer, and deltas folded at COMMIT so no flush holds
  the realm's `directory`-key row): `sts_ldap_dek_note()` appends each
  statement's net per key to `sts_ldap_dek_deltas`, `sts_ldap_dek_fold()`
  folds it in. Functions and triggers with NAMES OF THEIR OWN rather than more
  statements in #618's: `open()` probes routines by name, so a changed body
  under an old name would never reach a store that has the old one.
  `DEK_COUNTS_BACKFILL` runs under the same lock, on the same condition.
* **NULL IS "NOT KNOWN", NOT "NONE"**, which is why the column has no
  default: adding it rewrites nothing, and every row written before it reads
  NULL. `indexSealed()` (both jobs call it first, through
  `keystore.sealedStore().index`) reads those through the partial index
  `sts_ldap_entries_dek_unknown`, opens them a page at a time with a yield
  between pages, and sets their keys COMPARE-AND-SET (still NULL, same blob),
  for at most the budget the job gives it. Until none is left the driver
  REFUSES a count (`STS-STORE-0080`): a count missing them could read 0 for a
  key still in use, and a key is destroyed on 0. A blob that does not open,
  after the data-key rows are read again once a pass, gets its own key only,
  which is what the walk counted.
* **A NODE ON AN OLDER BUILD** writes `attrs` and leaves `dek_keys` as it
  was, so a cluster upgrades whole (as with every schema version). The
  catch-up's compare-and-set on `attrs` keeps it from stamping keys on a
  blob another writer changed under it.

`tests/data_key_index.js` holds it counted (no statement of either job reads
`sts_ldap_entries` without naming `dek_keys`) and, with
`STS_TEST_POSTGRES_URL`, the triggers' exactness against a real database;
`tests/no_full_directory_walk_in_jobs.js` holds that the walk stays gone.

### Only the asked names and the group classes are indexed (#618, schema version 18)

**Two GIN indexes took a key for every name and every class of every entry,
and nothing asked about most of them.** On a copy of 8081's 1.2M-entry store:
`attr_names` averaged 15.2 names a row, twelve of them in 99.9% of rows and
fourteen more in a sixth; `class_keys` held four classes a row, each in more
than 99%. So a person insert wrote about nineteen GIN entries that no
question could narrow by — nobody asks "who holds a `mail`" or "who is an
`inetOrgPerson`". Version 18 replaces both, PARTIAL, with nothing a person
writes to:

* **`sts_ldap_entries_asked_names`** is a GIN over
  `directory_queries.ASKED_NAMES`, an IMMUTABLE `jsonb_path_query_array()`
  of `attr_names` keeping only `ASKED_ATTRIBUTES` — the names
  `withAttribute()` and `anyWithAttribute()` are asked about, read from their
  callers — `WHERE directory_queries.ASKED_NAMES_HELD`
  (`attr_names ?| ARRAY[…]`).
  Every query spells both from those two constants, because the planner uses
  an expression index only for its own expression and a partial one only
  where the query repeats its predicate. **The predicate is `?|` and not
  `<expression> <> '[]'`, and that was measured**: the database checks a
  partial index's predicate on every insert and computes the expression only
  for a row that passes, and the jsonpath cost about 30 µs a row where `?|`
  over the same names cost about 2. **A name not in the list is still
  answered**, by `attr_names ? $n` with no index (said once in the log),
  because a holder question that answered "nobody" would be worse than a
  slow one; a new caller adds its name to the list, which changes the index
  expression and so is a schema version. `tests/directory_asked_names.js`
  reads the names out of the call sites and fails on one the list lacks, or a
  listed name nobody asks.
* **`userpassword` is not in the list**: nearly every person holds one. The
  two questions asked about it are the counters' — `countHolding()` already,
  and `anyWithAttribute()` (`anybodyHoldsACredential()`) now reads the
  realm's counter row instead of the index.
* **`sts_ldap_entries_group_classes`** is a GIN over `class_keys` `WHERE
  class_keys <> '[]'`, and `directory_codec.js` writes into `class_keys`
  only the GROUP classes (`CLASS_INDEXED`, which is `ldap_server.js`'s
  `GROUP_CLASSES`): `classesUnder()`, the one question asked of the column,
  is only ever asked for those. **It is the column that is narrowed, not an
  expression**, because the values are keyed digests the database cannot
  read. `keyArgs()` refuses `classesUnder` for any other class rather than
  answer "nobody". An entry written before version 18 holds all its classes
  until it is next written; the question answers the same over either, so
  nothing is migrated — it only stays in the index until then.
* **The two indexes they replace are RETIRED** (`SCHEMA_RETIRED`): an index
  nothing reads is still written on every insert. `schema.sql` drops them
  after building their replacements, and `open()` drops any still in the
  catalogue (probed through `pg_class`, so a fake `pg` answering every
  `to_regclass` as present issues no DROP) — which only a role that may
  will; the least-privileged role finds none once the script has run, and
  is refused with `STS-STORE-0029` on a version-17 store, whose new indexes
  it cannot build.

Measured on the 1.2M-entry copy (EXPLAIN ANALYZE of a 20,000-person INSERT
inside a rolled-back transaction, alternated): about 265K WAL records and
80 MB for version 17's indexes, about 222K and 58 MB for version 18's — the
same as with neither index — so about 2.1 WAL records and 1.1 KB of WAL less
per person. The names' index went from 23 MB to 16 kB; the classes' stays at
6 MB until the old rows are rewritten. Every query still plans on its index
(bitmap scans on `sts_ldap_entries_asked_names` and
`sts_ldap_entries_group_classes`, custom and generic plans), and the
password question is a primary-key read of `sts_ldap_counts`. The figures
are on #618.

### The directory's GIN indexes have no pending list (#618, schema version 18)

**Every directory GIN index but `dek_keys`' is `WITH (fastupdate = off)`.**
With the default, an insert lands in the index's pending list, merged only at
`gin_pending_list_limit` (4 MB) or by a vacuum, and EVERY SEARCH READS THE
WHOLE LIST. On 8081 under the bulk load the names', uuids', mails' and
values' lists held about 205,000 tuples (503 pages) each, so every `byName()`
and `byUuid()` probe read ~500 buffers, 8.9–17.6 ms, beside 0.02 ms for the
RDN branch of the same query; when autovacuum flushed them the add rate went
from 45 to 73 a second and the database CPU per add halved
(`load-users/dbperf/`). Off, an insert pays its entries at once — about
0.04 ms a person for the four on the 1.2M-entry copy — and a probe after
60,000 committed inserts read 4 buffers in 0.01 ms with no pending tuple.
The two partial indexes above take it too: a person writes nothing to them,
so a list there would buy nothing and only be read. `dek_keys`' keeps the
default: one or two keys a row, searched only by the hourly job.

An existing store is switched by `SCHEMA_RELOPTIONS` — `ALTER INDEX … SET
(fastupdate = off)` and one `gin_clean_pending_list()`, because turning the
option off stops the list growing and does not empty it. `open()` probes
`pg_class.reloptions` and issues them only where the option is missing (so
the least-privileged role issues none once `schema.sql` has run);
`schema.sql` carries the same statements after the CREATEs.
`tests/postgres_schema.js` and `tests/directory_queries.js` (C8) hold it.

### The data-key index catches up in hours, not days (#618)

On 8081 `sts_ldap_entries_dek_unknown` (#623) was 245 MB over 2.93M entries
still NULL. The catch-up WAS running — the 13:00Z re-encryption pass logged
46,500 entries indexed in its ten seconds — but the job was hourly, so the
rest would have taken about 62 hours, every data-key count refused
(`STS-STORE-0080`) meanwhile; and the pass returned before indexing at all
when no key was superseded, leaving a store that never rotated the daily
count's ten seconds (~60 days at that size). `data_key_rotation.ts` now
indexes on every re-encryption pass, superseded keys or none, and the job's
interval is `INDEX_CATCHUP_MS` (five minutes) while the last pass left
entries unindexed — ten seconds of the front process in every three hundred,
about five hours at 2.9M — and an hour again once it is complete.
`tests/data_key_rotation.js` K5 and K6.

### What the write path waited on, measured, and taken out (#630, schema version 19)

From 8081 under the LDAP bulk load (`load-users/dbperf/` on the host; a
pgbench replay of one add's statements against a copy of that database).
Each item is a lock or a write every add paid that bought nothing:

* **THE NOTIFY GOES OUT AFTER THE COMMIT, AND AT MOST ONE A 25 MS WINDOW.**
  A transaction that has called `pg_notify` takes the server's notify-queue
  lock at COMMIT and holds it through its WAL flush, so every writing
  transaction of every process committed one after another: `Lock:object`
  at COMMIT held 0.34–0.58 backends, and the replay went from 42 to 108
  adds/s with the notify moved out. `recordChanges()` now holds a
  transaction's kinds against its client beside its rows (`written`'s
  arrangement, counted at commit), and `transactionOnce()` hands them to
  `announce()` once COMMIT returns. `announce()` sends at once when the
  last notify is a window old, and otherwise joins the one notify the
  window's end sends (the union of kinds, the sum of rows), on the pool.
  **Nothing about correctness moved**: the change-log row is still written
  in the transaction, a rolled-back transaction still wakes nobody, and a
  nudge lost between a COMMIT and its notify (the process died, the pool
  refused) is a lost nudge, which the poll was always the answer to. The
  timer is a debounce armed by a commit — never self-re-arming, so not a
  scheduler job — and `close()` sends a nudge still due before the pool
  ends. `tests/notify_after_commit.js` counts it.
* **THE COUNTERS ARE SHARDED.** With the notify gone, every add still
  updated four `sts_ldap_counts` rows and one `sts_ldap_dek_counts` row at
  its COMMIT, the same rows for every add of a realm, and the replay's
  ceiling was those row locks (`Lock:transactionid` at 4.4 backends, 104
  adds/s; 326 with sixteen shards). `shard` is in both keys and the folds
  (`sts_ldap_count_fold_sharded()`, `sts_ldap_dek_fold_sharded()`) add to
  `pg_backend_pid() % 16`; `count()`, `countHolding()` and
  `directoryDekCounts()` sum. **New routine NAMES, because routines are
  probed by name**: a new body under `sts_ldap_count_fold` would never reach
  a store that has the old one. The old trigger and function are
  SCHEMA_UPGRADES' to drop, in the same transaction that creates the new
  ones, so no commit ever sees both folds (which would race for a
  transaction's deltas) or neither.
* **`sts_minted` UPDATES ARE HOT.** 2.2 updates an add, 0% HOT: every upsert
  sets `written_at = now()`, and the btree on it made each update a new row
  version on a new page with an entry in every index. The btree is a BRIN
  now (`sts_minted_written_brin`) — a summarizing index, which PostgreSQL 16
  and later leave out of the HOT decision — and the fillfactor is 80, so
  the next version fits on the page: 99% HOT in the replay and about nine
  fewer WAL records an add. **What it costs the sweeps** (`purgeTombstones()`,
  `purgeMinted()`, the 'orphan' and 'stale' batches of the expiry purge, the
  only readers of `written_at`): a BRIN range only widens as its rows are
  rewritten, so on a churned table `written_at < x` reads most ranges, and a
  sweep tends towards a scan of the table — off the request path, in
  batches, on the scheduler. `sts_minted_expires` is still a btree; an
  `expires_at` that moves (a sliding session) makes that update non-HOT,
  and the purge it serves needs the ordered index.
* **AUTOVACUUM PER TABLE**: `sts_changes` at a 2% scale factor and a cost
  limit of 2000 (its workers sat in `VacuumDelay` with 287,263 dead rows
  waiting), and `sts_ldap_entries` at an insert scale factor of 1% (it
  waited for about 600,000 inserts at 2.9M rows).

**SCHEMA_UPGRADES** (new with this version) is how an older store is owed
more than a missing object or column: a primary key that takes in `shard`,
routines replaced under new names, an index retired, storage parameters.
Each step is probed by a SQL condition in one query and run where owed,
after the columns and before the routines, in `open()`'s one transaction. A
required step a role may not take fails the open (STS-STORE-0029, as a
missing object does); an advisory one (the storage parameters and the
retired btree) is skipped and logged (STS-STORE-0083), because it is a cost
and never a wrong answer. `postgres/schema.sql` carries every statement and
condition, and `tests/postgres_schema.js` holds the two together. It runs
after #618's SCHEMA_RELOPTIONS and SCHEMA_RETIRED, which it is the general
form of: `sts_minted_written` is retired here rather than there because
dropping it is a tuning a non-owner may skip, where #618's retired GIN
indexes are dropped by whoever may — so `checkTheRetiredAgree()` counts the
script's `DROP INDEX` statements against both lists.

**An existing store needs two things**: `postgres/schema.sql` run again as
the owner (the shards, the routines, the BRIN, the storage parameters and
`pg_stat_statements`; the service's own role is refused at start with
STS-STORE-0029 until then), and the compose stack's postgres restarted for
its new server settings (`postgres/CLAUDE.md`).

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
output, replicas, query logs) and why a key-encryption key kept in a file
must not sit on the same unencrypted disk as the database (the compose stack
keeps none since #254: its key is OpenBao's Transit key, `openbao/CLAUDE.md`). **One fact from it
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

**A PROCESS THAT IS NOT THE SERVICE DIALS THE SAME WAY (#213, 2026-09-26).**
`databaseConnection()` answers `{ url, verifyTls, tlsCa }` —
`resolveDatabaseUrl()`, `verifiesDatabaseTls()`, the one reading of
`persistence.databaseTlsRejectUnauthorized` that `openStore()` and
`describeDatabase()` now use too, and `databaseTlsCa()` (2026-10-12) — for an out-of-process tool to hand
`persistence_postgres.create()`. Its first caller is the install-time risk
loader (`risk/risk_install.ts`), which dialled `STS_DATABASE_URL` alone and so
could not sign in to any shipped stack. **A tool that dials the database
calls this rather than copying the injection**, because the encoding above is
exactly the kind of detail a copy gets wrong. Requiring this module does not
open anything (only `start()` does), so a CLI may load it.

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

## TIERS: A CELL'S STORE IS TWO DATABASES (#98, 2026-09-28)

**A service deployed as cells** (`common/cells.ts`, `cells.id` set) keeps its
store in two places per cell, and this directory is where the split lives.
The design and its decisions are issue #98's body; this section is the part a
maintainer of this directory has to know.

| Tier | Where | What |
|---|---|---|
| GLOBAL | one writer for the service (`persistence.globalDatabaseUrl`), read from this cell's replica (`…ReadUrl`) | realms, settings, signing keys and the certificate authorities, the shared cluster secrets, the used-assertion history, the routing index, applications, policies and the other configuration entries, and the minted stores `tiers.js` lists as global |
| CELL | this cell's own database (`persistence.databaseUrl`) | the people homed here and their devices, group membership of those people, and everything this cell mints — sessions, codes, tokens, deliveries, the audit log, risk history, the cluster's membership and leases |

**`tiers.js` IS THE ONE PLACE A STORE'S TIER IS DECIDED, AND EVERY STORE IS
IN IT.** A directory entry's tier comes from where it sits (below `ou=users`
is a person, cell tier; a device by its owner's kind; a group is SPLIT — its
definition global, its person members in their cell — `splitGroup()` and
`joinGroup()`); a minted store's from its handle, listed global or cell by
name. `tests/cell_tiers.js` reads every `persist:` in the tree and fails on
one in neither list: a default tier would be a default answer to a residency
question, and the wrong default is a person's data in another country with
nothing failing. A GLOBAL minted store is the exception that is argued beside
its name — configuration, a revocation every cell must see, or a replay set a
CLIENT chooses the keys of (a DPoP `jti`, a Kerberos authenticator), which a
per-cell set would accept once per cell.

**`persistence_tiered.js` IS THE DRIVER THE SERVICE SEES**, with the postgres
driver's whole interface: the cell driver's methods bound by default (the
cluster is the cell's), the global ones over them, and the directory and the
minted rows split row by row. Three things it does beyond routing:

* **The routing index** (`sts_cell_routing`, schema version 11) is kept at the
  flush, the one place every person passes: a person written for the first
  time claims their login name and entryUUID as keyed digests
  (`common/cell_routing.ts` makes them), a delete releases both, and a claim
  answered with another cell is counted (STS-CELL-0020) rather than failing
  the flush — creation paths claim first, and this is the race that check
  cannot close.
* **A projected entry is never written here** (origin `projection:<home>`,
  `common/cell_sessions.ts`); a change to one is handed to the sessions module,
  which sends it home. `persistence.materializeEntry()` is how a projection
  enters the directory without becoming a row: `restoring` set and the shadow
  advanced, exactly as a replicated entry is applied.
* **What is not atomic across the two databases** is said in its header: a
  flush touching both tiers is two transactions, global first, and a failure
  between them is written by the next flush because the shadow only advances
  on success. A global write is not fenced by the cell's membership.

**TWO CHANGE LOGS, TWO FOLLOWERS.** `persistence_replication.js` is a factory
since #98: the module's own exports are the instance for the process's main
log (the cell's, or the only one), and `persistence.js`'s `coordinate()`
builds `createReplication('global')` on the global driver itself, so its own
rows are skipped by the origin the global driver stamps. Its pull and trim
jobs carry `global` in their ids. The two may pull at once; the one thing they
share, `persistence_minted.js`'s page prefetch, never answers across them
because a handle is in exactly one tier. **The read barrier waits on the
cell's log only**: a global change made in another cell arrives after the
replica's lag, which `/admin/cells` shows — a barrier on it would put a
cross-region round trip on every request, which #98 D3 declined.

**THE READ POOL.** `persistence_postgres.js` takes a `readUrl`: every
statement that only reads (the restore, the change log, the row a change
points at, the routing lookups) goes to it, and everything that writes, locks
or claims stays on the writer. A change row and its data row are read from the
same replica, which replays the writer's commits whole and in order, so a
pointer is never read ahead of what it points at.

**A GLOBAL JOB RUNS IN ONE CELL, NOT IN EVERY CELL.** A cluster job claims its
run in its cluster's database, and a cell is a cluster — so a job whose work
is the global tier's (a realm signing-key rotation, the krbtgt key, a SPIFFE
authority, the OpenID Federation key, a client secret's expiry, the global
used-assertion purge; `tiers.js`'s `GLOBAL_JOBS`) claimed there would run once
per cell. In multi-cell mode the scheduler claims those runs under
`scheduler.run.global` (`tiers.GLOBAL_RUN_SCOPE`), and the tiered driver keeps
that scope in the global database (`claimTierOf()`); `purgeClaims()` runs on
both. A new job that writes global state belongs on that list.

**SEALING BY TIER.** A cell-tier minted row is sealed under the cell's own
key-encryption key (`keys.cellKek*`, `keystore.seal(…, 'cell')`), which lives
only in the cell's region and has no fallback; `keystore.open()` tries the
cell key and then the service key, since AES-GCM's tag makes the wrong one
fail rather than answer. Single-cell mode seals everything under the service
key, as it always did.

**WHAT A CELL REFUSES AT START** (`checkCells()`): inconsistent cell settings
(STS-CELL-0001), a store that is not postgres or no global database (0002), no
cell key in product mode (0003), keys that are not persisted or no operator
key-encryption key (0004 — every cell must sign with the same realm keys, #98
D8), and no `global.publicBaseUrl` (0005 — a relayed request reaches the
owning cell under a private name).

### Converting a single-cell store (#98, 2026-09-28)

**`cell_convert.js` turns a single-cell deployment's database into a cell,
ONCE** — `node persistence/cell_convert.js [--dry-run]`, run in the image and
configured exactly as the cell it becomes (`cells.id`, the cell's
`databaseUrl` pointing at the old database, the global database built empty,
the service KEK). It dials both through `databaseConnection()`,
`globalDatabaseConnection()` and the driver's `dialOptions()`, and holds the
KEK through `keystore.start()`, which also proves that key opens the stored
key sets — a routing digest under the wrong key would route nobody.

**IT WRITES WHAT THE TIERED DRIVER WOULD HAVE.** Every row of the tables
whose methods are in `GLOBAL_METHODS` moves (realms, appconfig, keys, used
assertions, cluster secrets), the directory is split by
`tiers.directoryTierOf()`, a group into its `splitGroup()` halves (a cell half
that is empty is DELETED, as `splitChange()` deletes it), a minted row moves
when `mintedTierOf()` says global (an unclassified handle stays, as
`byHandleTier()` keeps it), and a `scheduler.run.global` claim moves. The
routing index is backfilled through `persistence.routingDigest()` — the one
digest, now also the one the tiered driver is built with — from
`persistence_tiered.loginNameOf()` and `uuidOf()`, so a backfilled row is the
row `indexPeople()` writes. Rows are copied verbatim, jsonb as parsed values
and timestamps as UTC text; nothing is re-sealed (`keystore.open()` falls back
to the service key). `sts_risk_*` is only ever counted.

**COPY, VERIFY, THEN DELETE**, one transaction each on the global and then
the cell database, so the only states a failure leaves are *not started*
(global empty), *copied* (global holds exactly the cell's realms and keys: a
re-run copies again and finishes) and *converted* (the cell holds no realm and
no key: nothing moves, a missing index row is claimed, exit 0). A global
database whose realms or keys differ, or whose index names another cell, is a
second source and is refused (STS-CELL-0203); STS-CELL-0200 to 0209 are its
codes.

**THE CHANGE LOGS ARE NOT COPIED.** Nothing runs across a conversion, and a
process that starts restores the tables and follows each log from its end —
so the global database's `sts_changes` and `sts_change_readers` start empty,
and the old deployment's readers and nodes in the cell database are dropped
by the next trim and the dead-node purge like any dead node's.

`tests/cell_convert.js` holds the rules over two in-memory databases;
`tests/tools/rehearse-cell-conversion.sh` rehearses it against real
PostgreSQL (`tests/CLAUDE.md`).
