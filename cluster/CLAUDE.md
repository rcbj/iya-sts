# CLAUDE.md — `cluster/`

Several containers of this service against **one** postgres store (issue #46,
built from 2026-09-14 on `feature/46`). Inside one container the processes
agree because the front process coordinates its workers over IPC; between
containers the only link was `sts_changes`, so a second container started,
looked healthy and gave wrong answers nothing reported. This directory is what
makes the containers a cluster: membership, leases, the fence every write is
held to, the gate in front of each mode, atomic claims, the shared secrets, and
the barrier that makes one node see what another committed.

## What is in here

| File | What it is |
|---|---|
| `cluster.js` | Membership, heartbeat, leases, the fence provider, fail-stop, the settings agreement, and `gate()` — which `persistence.js` calls before anything is restored. |
| `cluster_capabilities.js` | The table of what active-active mode depends on, one row per failure #46 describes, each `provide()`d by the module that fixed it. |
| `cluster_claims.js` | `claim()` / `release()`: an atomic "once" in the store for every single-use value. Memory on a store that cannot be shared. |
| `cluster_counters.js` | `advance()`: a value that may only go UP, agreed by every node — a WebAuthn signature counter, the last RFC 6238 step spent. One conditional upsert in the store. Memory on a store that cannot be shared. And `countInWindow()`: a rate-limit bucket's count inside a fixed window, one budget for every node. |
| `cluster_secrets.ts` | The secrets every node must agree on (the CSRF key, the ACME nonce key, the SSF receiver secret, and the BBS key pair), sealed in the store, first writer wins. |
| `cluster_barrier.js` | The middleware that makes a request wait for other nodes' commits, and holds a writing response until its own commit lands. Active-active only. |
| `scheduler.ts` | **The one scheduler every periodic job runs on** (#49, 2026-09-22): a leader on the `ops.scheduler` lease, a claim and a fence per run, slots by the database clock, manual runs and a step-down as command rows in the store, cluster and per-process jobs. `/admin/scheduler` draws it. See *The scheduler*, below. |

The SQL is `persistence/persistence_postgres.js`'s — the driver owns every
statement, as it does for `/admin/database` — and the six tables
(`sts_cluster_nodes`, `sts_cluster_leases`, `sts_cluster_claims`,
`sts_cluster_secrets`, `sts_cluster_counters`, `sts_cluster_windows`) are in
`postgres/schema.sql` at schema version 5, beside `sts_change_readers`
(`persistence/CLAUDE.md`).

## rcbj's decisions (2026-09-14)

1. **Straight to active-active** as the goal. Active-passive exists because it
   is the safe default while active-active is incomplete, not as a stage to
   stop at.
2. **A node without the service lease WAITS BEFORE IT RESTORES OR BINDS
   ANYTHING** — rather than a warm standby answering 503. `gate()` runs right
   after `driver.open()` in `persistence.openStore()`, while `restoring` is
   still true, so every "something changed" door is closed and a standby cannot
   write to a store another node owns. The cost is the restore at takeover.
3. **On by default in product mode on postgres**: `cluster.mode=auto` resolves
   to `active-passive` there and `off` everywhere else, so nothing that ran in
   development mode, or on memory or ldif, changes.
4. **The fence is checked inside every write transaction, and a node that
   cannot renew its membership exits.**
5. **A development-mode sign-in's auto-created entry gets a name-derived
   `entryUUID`** wherever two processes can race to create it (a cluster mode,
   or a dispatched pool) — `ldap/ldap_server.js` `putEntry()`; a single process
   keeps random values.
6. **The barrier holds a response for its audit row only when that row is a
   REFUSAL** (chosen 2026-09-15). A successful call that wrote nothing else is
   answered at once and its row reaches the other nodes on their next pull, so
   a cross-node audit read straight after a successful read may miss it;
   holding for it would put a commit under every read in the service. See
   *What the barrier cost* below.

## Membership

A **node is a container, not a process**. The front process joins with a fresh
UUID, heartbeats, and holds the leases; its request workers are the same node.
`gate()` puts the node id, the mode and the service lease's token into
`process.env` under `STS_CLUSTER_INTERNAL_*`, and `request_pool.js` forks with
`Object.assign({}, process.env, …)`, so every worker inherits them and
`attach()`es — the same fence, no row, no heartbeat.

**Every time is the database's clock** (`DB_NOW` in the driver). Two
containers' clocks differ, and a lease that expires by whoever-is-asking's clock
is a lease two nodes both hold.

**A membership row that has expired is dead for good.** The heartbeat's UPDATE
refuses to renew an expired row, so a node that paused past its lifetime cannot
come back quietly; its next heartbeat reports `alive: false` and it exits
(`STS-CLUSTER-0005`). A node whose heartbeats fail for `ttl − heartbeat` exits
on its own (`STS-CLUSTER-0004`), because the others may already have taken over.

**The join is serialised by an advisory lock** (`JOIN_LOCK`) and compares only
the MODE. **The settings are compared afterwards**, in `agree()`, because the
fingerprint is an HMAC keyed by the key-encryption key, which the keystore opens
after the join. A bare hash in a database row would be a dictionary attack on
`krb5.krbtgtPassword`. `AGREEMENT_SETTINGS` is the list; `global.port` is
deliberately NOT on it (it is per host, and a local two-node test binds two).

### Two bugs the first real run found, both mine

* **The fence was installed before the join, and the join is a transaction.**
  The first node fenced itself for having no membership row inside the
  statement that wrote it. `fenceFor()` answers null until `joinedAt` is set.
* **The join compared fingerprints, which a joining node does not have yet**,
  so the second node was always refused. Mode only at join; settings in
  `agree()`.

### A node's thread and its lifetime (2026-09-14)

**A heartbeat is a JavaScript timer, so a node whose event loop is blocked does
not heartbeat, and its row expires by the database's clock while nothing in it
runs.** That is correct and stays: to every other node a stall is a partition,
and the stalled node may already have lost what it held. What was wrong was
the load that caused it and the sentence that reported it.

* **The cause that was measured — a realm's key set generated on the thread.**
  Twenty realms created through node A's `/admin-api` and then listed on node
  B (which held no keys for them): both nodes exited with `STS-CLUSTER-0011`,
  B's heartbeat 11.2s late; twenty concurrent first requests to those realms
  on B: B exited the same way. With the fix both survive — the list of 20
  answered in 7.4s while B answered 54 other requests (worst 452ms), a list of
  40 in 17.5s (worst 415ms), twenty first-use JWKS fetches with 173 requests
  answered alongside (worst 984ms). `helpers.prepareKeySet()` generates the
  RSA half in node's thread pool before a read needs it (`common/CLAUDE.md`,
  *A realm's key set, made off the event loop*).
* **`STS-CLUSTER-0025`** is logged whenever a heartbeat runs a heartbeat or
  more late, measured on the monotonic clock, and `STS-CLUSTER-0005` /
  `STS-CLUSTER-0011` append *the likely cause is THIS NODE* when a recent
  stall was longer than the lifetime. `0011` used to say only that the row
  "has expired or been left", which sends an operator to the database. The
  status object carries `lastStallMs`.
* **`cluster.nodeTtlMs` is 30000 (it was 10000).** The largest computation a
  supported console action still makes on the thread is an SLH-DSA-SHAKE-128s
  signature on `/admin/pki`'s authoring pane: 13.7s measured with the vendored
  signer (`common/CLAUDE.md` 3aa says why that pane does not use the pool),
  past 10000 − 2000 and inside 30000 − 2000 with its own length to spare. The
  cost is an active-passive takeover after a CRASH (up to 30s); a clean stop
  releases the lease and hands over in one heartbeat either way, and in
  active-active serving never waited on the lifetime. The fence is unchanged.

### The roster on `/admin/cluster` (2026-09-17)

`admin-ui/admin.ts`'s `clusterStatusBlock()` lists the members, and **the only
thing one node knows about another is that node's row**: there is no channel
between two containers but the store, so anything the page shows about a member
had to be written into `sts_cluster_nodes.info` by that member first.
`nodeInfo()` is what goes in it and is rewritten on the join and **on every
heartbeat**, which is why nothing in it is computed and nothing in it grows — a
member that cost a query would put that query on the beat a node's life depends
on. What is in it: the host, the port and the pid (which is how an operator
finds the log), the process's uptime, how many processes answer requests there,
and `lastStallMs` — the stall that explains a late heartbeat and that no other
node can see. The worker count is a LAZY require of `common/request_pool`,
`versionString()`'s pattern and for a reason of its own: this module is called
from inside the store's own gate, and a require at the top of the file would
pull the keystore in there, which is the thing `gate()` exists to run before.

**AND THE NODE'S CACHE FIGURES (2026-09-18)**, as `info.caches`: the compact
`cache_registry.snapshot()` — per store the name, size, fullest realm, valid
count, bound and four counters, about sixty bytes a store — so another node's
`/admin/caches` can show them with no request crossing between nodes. It
breaks the "nothing in it is computed" rule in the only way that keeps it: the
snapshot is taken on a timer of its OWN (`CACHE_REPORT_MS`, thirty seconds,
first five seconds after the join), because it walks every store's rows, and
`nodeInfo()` attaches the last one taken. So the beat stays a lookup, and a
report that cannot be taken costs the other nodes this node's figures and
never a heartbeat. `cache_registry.js` requires only `config` and
`error_codes`, so it is a plain require at the top of this file.

Three things the page decides rather than reads:

* **Live and gone are separated**, and the gone fold under a `<details>`. A row
  whose lifetime has passed is dead for good, and a node that expired while its
  process kept running is this file's own failure mode — so the rows are folded
  rather than dropped.
* **Serving or standby is read from the LEASE TABLE and not from the node's own
  mode.** In active-passive one member holds the service lease and serves while
  every other one has restored nothing and bound nothing, and a member's row
  cannot say which of the two it is.
* **Every time on it is the database's clock** (`state.now`), for the reason
  the rest of this file gives. `info.uptimeMs` is the one exception and is
  labelled as the node's own, because no other clock can say how long a process
  has been running.

The section is drawn in `off` mode too, saying there is no membership to list:
a section that disappears reads as a page that has not loaded. **And a
clustered process with no snapshot yet says THAT, not the same sentence**
(2026-09-18): the first version said *cluster.mode resolved to off* for both,
and on testidp — where `/admin` is served by a request worker and a worker's
first draw started the read it could not wait for — it told somebody looking at
a healthy three-node active-active cluster that it was not clustered.
`attach()` now starts the read when a worker attaches, so a first draw
normally has one; the page still says *has not read the member list yet* for
the gap, which is the true sentence. `GET
/admin-api/cluster` answers the same rows under `status.nodes[]`, `info`
included (rule 7).

## Leases and the fence

A lease is a named role one node holds, with a **fencing token that goes up
every time it changes hands**. A released lease is expired, never deleted, so
the token never goes back to 1. Re-acquiring a lease you still hold returns the
same token — a re-ask is not a new tenure — which is also what lets any process
of a node acquire a role on the node's behalf: renewal is by `holder = node`,
so the front process's heartbeat renews it.

`checkFence()` runs first in every `withTransaction()`: the membership row must
be live (unlocked — only its own heartbeat renews it), and every lease the write
needs must still be held at its token, **under `FOR SHARE` held to COMMIT**, so a
takeover — an UPDATE of that row — waits for the transaction and cannot land
between the check and the write. The error carries `reason: 'node' | 'lease'`:
a lost membership, or the service lease in active-passive mode, is fatal
(`STS-CLUSTER-0011`); a lost role lease under active-active fails that one
write and the node stays up. `withLease(name, fn)` is how a lease-guarded write
is made — an AsyncLocalStorage context the fence reads.

**What is NOT fenced:** single statements on the pool rather than in a
transaction — the used-assertion claims, the cluster claims, the purges.
(`deleteKeys` left this list on 2026-09-14: it is a transaction that logs a
change row now, so a rotation reaches the other nodes.) A claim is a decision rather than a state write, and a deposed node
making one decides for a request it is still answering.

## The two modes

**Active-passive.** The service lease (`SERVICE_LEASE`). The first node takes
it and serves; the rest wait in `waitForServiceLease()`, asking every
heartbeat. A clean stop releases it in `persistence.stop()` → `cluster.leave()`,
so a standby takes over in one heartbeat; a crash costs one lifetime.

**Active-active.** Every node serves. `resolve()` refuses it without an
operator key-encryption key (`STS-CLUSTER-0008`) — a key generated per process,
or development mode's ephemeral KEK shared only inside one container, is a
different key on every node — and **without `global.publicBaseUrl`
(`STS-CLUSTER-0026`, 2026-09-14)**: every issuer a client verifies (a token's
`iss`, the management API's audience, a Shared Signals stream's `iss`) is that
setting or the address the request came in on, behind a load balancer the
second is a different name per node, and an empty value is the same value on
every node, so the settings agreement cannot catch it. Active-passive is not
refused — one node answers at a time. `gate()` refuses it while any row of
`cluster_capabilities.js` is missing and not named in
`cluster.acceptMissingCapabilities` (`STS-CLUSTER-0009`). **There is no
wildcard**: a list somebody has to write is a list somebody has read.

**A capability is provided at REQUIRE TIME by the module that implements it**,
never on a runtime success: `gate()` checks the table before anything later in
startup runs, so a capability declared by a step that succeeds later would
never count. `tests/cluster_foundation.js` holds every `provide()` call to a row
and to the file the row names.

## The barrier (active-active)

Two rules, argued in `cluster_barrier.js`: a request is served after its node
has applied everything committed before it arrived (one shared change pull per
batch of requests that arrived before it started), and **a request
that wrote is answered only once its writes have committed** — without the
second, a redirect answered by A reaches B before A's flush and B's read of the
head misses it. `request_worker.js` rejected commit-before-answer on 2026-09-07
as unaffordable because the flush then diffed the whole directory; the journalled
flush (2026-09-08) removed that cost, which is why it is acceptable here.

It is installed in `app.js` directly below `requestPool.middleware()`, so it
runs in the process that serves a request and never in one that only proxies.
It does not make CONCURRENT requests serialisable — that is `cluster_claims.js`.

### And the replication change underneath it

`persistence_replication.js` used to stop at the first hole in `seq` (a
transaction still committing), wait up to four seconds, and then skip it for
ever. With several nodes committing at once there is nearly always a hole, so
every node's view stalled behind every other node's slowest transaction, and a
transaction slower than four seconds was lost in every process that skipped it.
It now applies everything visible, remembers each hole, re-asks for the holes on
every pull (`changesAt()`), and gives one up only after ten minutes
(`STS-STORE-0049`). **This is safe because every applier reads the CURRENT row
rather than replaying an operation** — order of application does not matter. A
barrier is satisfied only by a pull that STARTED after it was called
(`lastCompletedStartNo > needNo`) — since 2026-09-14 that is the whole proof and
the head query is gone (*What the barrier cost*, below). The rule's test is
`tests/cluster_barrier_throughput.js` section 3: a page read before a row
committed, which `cluster_foundation.js` section 2 could not time.

### Measured, and the control that made the measurement mean something

Two nodes, two request workers each, `workers.dispatch=*`, product mode: a user
created through node 1's `/admin-api` and read from node 2 on the next request.
**`cluster.mode=off`: 0 of 40 seen** (the same read against node 1: 20 of 20;
against node 2 after two seconds: 20 of 20, so the probe is sound).
**`active-active`: 120 of 120 seen.** The first probe tried — a sign-in form
minted on one node and posted to the other — passed 40 of 40 with the cluster
OFF: that handler answers "Authentication failed" without needing the pending
record, so it measured nothing. Run the off control before believing a probe.

The recipe (scratchpad scripts, not in the tree): nodes on offset ports against
one database, `ADMIN_API_CLIENT_SECRET` pinned and `STS_PUBLIC_BASE_URL` set to
one address on both (the token's audience), a client_credentials token with
`resource=<base>/admin-api`, and node 1 started FULLY before node 2 — until
`keys.agreement` exists, a simultaneous cold start gives two signing key sets
and node 2 refuses node 1's tokens.

### What the barrier cost, and where it went (2026-09-14, #46 follow-up)

The suite's `cluster` mode measured a management-API create at 190ms (5/s)
against 2.3ms in `postgres` mode, a SCIM create at ~500ms, and the 5,000-user
SCIM load hit its thirty-minute watchdog at 3,500. Profiled on two nodes (a
preload wrapping `pg`'s queries and the persistence entry points, scratchpad),
four costs, in order, and what each became:

1. **The audit ring was one `sts_minted` row** — 2.3 MB sealed and written per
   flush, read and opened by the other node per request: 3.3 MB of the 3.4 MB
   of minted rows 100 creates wrote. It is stored in segments of 32
   (`realms.arr({ segment })`, `common/CLAUDE.md`).
2. **Every request was held for ANY pending write** (`pendingWrites()`), and the
   call log's rows from the previous request were always pending: 1,705 of
   1,706 requests held on one node, a discovery document at 23-66ms. A request
   is now held only when the store's write position moved while it was handled,
   and only for the flush covering it (`persistence/CLAUDE.md`, *SEVERAL
   CONTAINERS*). After: 456 of 6,187 held under a mixed load.
3. **The barrier read the log's head first**, a query that walks back past the
   node's own rows — the whole log on a node answering alone, so reads slowed as
   the log grew (4ms, then 23ms, then 68ms). Removed; the pull is the proof.
4. **A barrier polled a running pull every 5ms**; it now waits on its promise.

**What rule 2 now covers that it did not**: the call log (`app.js`) records the
statistics and the audit row in `res.end()` rather than on `finish`, and tells
the barrier where the write position was before it did. A request that wrote is
held and its call-log rows ride the same commit; a request that wrote nothing
else is held for its row ONLY IF THE ROW IS A REFUSAL — so `admin_api`'s
refused `POST /healthcheck` on node A is in node B's next audit read (live: 1 of
60 read back across nodes before, 60 of 60 after; same node 20 of 20). A
successful call that wrote nothing else is NOT held for its row: that would put
a transaction under every read in the service, which is cost 2 again. Its row
commits within one flush and reaches the other node's next pull; it is the one
row rule 2 does not promise, and `cluster_barrier.js` argues why.

**A decision counted is not a write either (2026-09-15).** The XACML monitor's
counters were journalled only when created, so each node's page added its live
tally to the other's frozen row and `sts_portal_sessions` read two totals for
one service (`xacml/CLAUDE.md`). Journalling every decision would have put a
commit under every console, portal and `/admin-api` read, because the access
PEP counts one on each — the cost this section removed. So the store is
declared `observation: true` and the barrier compares the minted position LESS
the observed count (`mintedWrites()`): a request whose only rows are tallies is
answered at once, like a success's call-log row; a request that wrote anything
else is held and `commitThrough(now)` takes its tallies with it, `now` being the
whole position. Decision 6 is unchanged — nothing that was unheld is held. A
tally from an unheld request reaches the other node within one flush, as a
success row does. `tests/cluster_observation_counters.js` section 3.

**Anything this node SENDS because a store changed must leave after the
commit** — the receiver may ask another node next. The remote PEP's nudge went
from inside the write, its pull landed on the other node, and it converged on
its heartbeat (2018ms, 916ms; 65ms after): `xacml/CLAUDE.md`, *The nudge*. The
same question applies to any new push a family adds.

**And a realm created on node A was a 404 on node B's first request** (live,
before: 3 of 12 cross-node requests matched; after: 12 of 12; a realm that
exists nowhere is still `Cannot GET`). The realm middleware now catches up first
on an active-active node — `common/CLAUDE.md`.

**MEASURED, before and after in one sitting** (development mode, one process per
node, sequential client alternating nodes, keep-alive, audit rings filled to
5,000 per node first; this machine's load average was 6-9 throughout and moves
every number by up to 2x, so compare within a row):

| mean ms (rps) | `postgres`, 1 node | active-active, 1 node | active-active, 2 nodes |
|---|---|---|---|
| `/admin-api/users/create` before | 1.6-3.7 | 131 (7.6/s) | 117 (8.5/s) |
| after | 2.8-3.0 | 29 (34/s) | 32 (32/s); 16 (63/s) at load 6 |
| SCIM `POST /Users` before | 7.5-13.6 | 158 (6.3/s) | 264 (3.8/s) |
| after | 9.4-13.0 | 45 (22/s) | 53 (19/s); 20-26/s over 1,200 fresh-connection creates, no upward trend |
| `GET /admin-api/users?user=` before | 2.7-4.8 | 74 | 63 |
| after | 3.8-5.2 | 6.7 | 7.1 |
| discovery document before | 1.0-1.6 | 72 | 69 |
| after | 1.5-1.8 | 3.0 | 3.1 |

`postgres` mode is unchanged within noise (two interleaved before/after pairs).
**What is left in a create is commits**: a directory-create claim, the directory
transaction and the minted transaction, each a fsync on this disk (2-26ms here).
The next biggest rows a SCIM create writes are not the audit ring any more but
`ssf_streams.streams` (~35 KB, twice per create), `admin_stats.scimCounts`
(~16 KB, a whole counter row that grows) and `caep.register` (~8.5 KB) — each
rewritten whole per event. Not changed here.

## Claims and shared secrets

`cluster_claims.claim({ scope, value, ttlMs })`: the key stored is SHA-256 of
scope and value, never the value; the lifetime is the database's clock; a store
that cannot be asked answers `reason: 'store'` and the caller refuses (fail
closed). **A won claim answers `claimedAt` as well since 2026-09-17**, the
store's own clock: a claim re-taken after its lifetime lapsed carries a LATER
time than the one it replaced, so a caller can use it as a FENCING TOKEN. The
back-channel Logout Token deliveries do — one claim per delivery attempt, and
the row keeps whichever copy carries the higher claim time, so a process that
stalled past its lease cannot overwrite the outcome of the one that took over
(`oauth-oidc/CLAUDE.md`, 3aq). `releaseUnlessSucceeded(res, handle)` gives a claim back when the
response is not 2xx/3xx. On memory or ldif it is this process's map, which is
exactly as atomic as the map it replaces.

`cluster_secrets`: values are TEXT (callers derive with the string, as before).
The front process reads the store's value (sealed; first writer wins) and puts
it in the environment variable before it forks, so workers inherit it; an
operator's variable set before start wins; a store that cannot share, no KEK, or
**an ephemeral KEK** (which changes at every restart, so last run's row would not
open) leaves one value per container, as before. The DPoP server nonce is NOT a
shared secret: it is a persisted store of issued nonces, which the barrier makes
current on every node.

**The BBS key pair WAS the fourth (2026-09-14 to 2026-09-22, capability
`vc.keys-agreement`)** — one per service, offered by a `generate` on its row
and handed to workers in `STS_BBS_KEYPAIR` — so that `/bbs/keys/1` answered
one `publicKeyMultibase` on every node. **It left this table on 2026-09-22
(#49 P5, rcbj's D6 answer)** to become a member of each REALM's key set — the
unit `bbs:BBS`, with generations, rotated with the realm's signing keys —
because a secret made once for the store can never change while the service
runs. It is agreed across nodes and workers the way every member is (the
store's first writer, the sibling channel's enrichment rule), which is what
`vc.keys-agreement` still stands for; `/bbs/keys/<kid>` and the DID document
publish every live generation, and a realm no longer shares its BBS key with
another.

**The rest of the per-process key material was checked the same day and has
not got this shape:** the did:web document's JOSE keys are the realm's key set
(`keys.agreement`); the OpenID4VCI request-encryption key, the RFC 9101 request
object keys, the refresh-token keys and the post-quantum keys are all members of
that set (`common/helpers.js`); a did:jwk is made per request by design.

## Counters: when "once" is not the property (2026-09-14)

`cluster_counters.advance({ scope, key, value })` exists because two
credentials are defended by a number that must never go BACKWARDS, and a claim
cannot say that: a claim refuses the same value twice and accepts a LOWER one
after a higher one. A WebAuthn signature counter that one node recorded at 11
and another wrote back at 10 (the entry is last writer wins) let a cloned
authenticator presenting 11 in everywhere; `totp.verify()` refuses every step
at or below the last, not only the last. So `sts_cluster_counters` holds one
row per counter and `advanceCounter` is one `INSERT … ON CONFLICT DO UPDATE …
WHERE value < new`: of two advances to one value exactly one gets a row back,
and the stored value is the highest ever given whatever order commits land in.

* **Zero is not a refusal** when the stored value is zero (WebAuthn Level 3
  section 6.1.1 — every synced passkey reports 0 for ever); zero after a real
  value is a counter that went backwards.
* **Fail closed**, `cluster_claims.js`'s rule (`STS-CLUSTER-0022`).
* **A row is never removed** (one per credential ever used, a few dozen bytes);
  `updated_at` is there for the day somebody sweeps rows of removed keys.
* The entry keeps its copy and stays the FIRST check (no round trip for the
  ordinary repeat); the counter decides the race.

### And a count inside a window: the rate limiter (2026-09-14)

`countInWindow()`, `peekWindow()` and `clearWindow()` are the third shape: a
count that RESETS, which neither "once" nor "only up" is. `sts_cluster_windows`
holds one row per rate-limit bucket (the key digested, the realm '') and
`countWindow` is one upsert — `count = CASE WHEN the window has passed THEN 1
ELSE count + 1 END` — returning the count this attempt made. "Now" is read once
in that statement (from the inserted row's own window end), because two
readings of `clock_timestamp()` at the boundary would reset the count and keep
the old window. There is **no memory fallback in this file**: `websecurity.js`
asks `sharesWindows()` first and keeps its own buckets where nothing is shared,
and a store that cannot be asked is `STS-CLUSTER-0023` and the limiter's own
buckets deciding (`common/CLAUDE.md`, *Several nodes: one rate-limit budget*).
Finished rows are swept at most once a minute by whichever process counts next
(`STS-CLUSTER-0024` if that fails). Measured against a real postgres: a hundred
concurrent counts of one bucket from two driver instances returned the counts
1 to 100 once each, and a count after the window passed returned 1.

## The scheduler (2026-09-22, #49)

rcbj's directive of 2026-09-21 (root `CLAUDE.md`, *Anything periodic is a
scheduler job*) made this the place every periodic job in the service runs;
the plan and rcbj's answers D1–D10 are on #49. `scheduler.ts`'s header is the
argument; what a maintainer needs to find quickly is this.

**Registering a job** is one call at the owner's load time, and starts
nothing:

```js
scheduler.register({
  id: 'authn.session-expiry',        // dot/hyphen words; the page's key
  title: 'Session expiry', describe: '…', owner: 'authn/authn.ts',
  kind: 'cluster',                    // default; or 'per-process'
  scope: 'service',                   // default; or 'realm' (one run per realm)
  everySetting: 'authn.sessionSweepS', everySettingUnit: 's',
  // or everyMs: () => n, or cron: '0 3 * * *' (UTC, croner), or manualOnly
  off: (realmId) => '',               // why it is off now, or ''
  manual: true,                       // may an administrator Run now
  timeoutS: 600,                      // default scheduler.runTimeoutS
  run: async (ctx) => ({ summary })   // ctx.stillOwner(), ctx.nowMs(), …
});
```

A registration missing a member is refused WHOLE and thrown
(`STS-SCHED-0009`). A setting of 0 for an interval means OFF, and the page
says so; it is never read with `|| n`.

**EVERY PROCESS MUST REGISTER THE SAME JOBS (2026-09-22).** A registration is
the owner's load-time call, so a job registered LAZILY — at a process's first
claim, first count, first assertion — is listed by the processes that have
done that thing and by no others. With request workers that is visible from
outside: `/admin/scheduler` is answered by a SURFACE worker and
`GET /admin-api/scheduler` by a PROTOCOL worker, so the two doors reported
different job lists and `sts_scheduler`'s *the page and the API agree* failed
in `single-node` — once for `cluster.claims-purge`, then again for
`cluster.rate-window-purge`, which is the same defect in the next owner.

The three shared-table sweeps — `cluster/cluster_claims.js`,
`cluster/cluster_counters.js` and `common/used_assertions.js` — are therefore
registered at the foot of `scheduler.ts`, which calls each `ensure…Job()` with
the scheduler INSTANCE. It is done from here rather than at each owner's own
load because two of the three require this module back, and passing the
instance is what keeps that from being a cycle. Each owner keeps its lazy call
for the process that reaches the store first; it finds the job already there.

**And the `…Registered` guard is set AFTER the registration, never before.**
It was set on the way in, so a call that reached a HALF-BUILT scheduler
through the cycle marked the job registered while registering nothing, and no
later call could put it right — a job missing from one process for the life of
that process. A guard that latches before the work is done is a guard that
remembers a failure as a success.

**Four things that are easy to get wrong:**

* **A run is idempotent per SLOT, and only the current slot is ever due.**
  An interval job's slots are multiples of its interval on the database clock
  (so every node agrees on the next time); a cron job's slot is its most
  recent occurrence. A slot missed while nobody led runs ONCE. So a job that
  must not run at a fresh start — a signer rotation — decides from its own
  state (the key's age), not from being called.
* **The claim is the fence, not the lease.** The leader claims
  `scheduler.run` for the run's id for its time limit, writes the claim's
  database time on the row as `fenceAt`, and writes the outcome only while
  the row still carries it. A run whose claim lapsed and was re-taken is
  recorded `abandoned` (`STS-SCHED-0011`), and the late outcome is fenced out
  (`STS-SCHED-0003`). `ctx.stillOwner()` is the question a job asks before a
  step it cannot take back.
* **It never starts at require time, in a standby or — for a cluster job — in
  a request worker.** `server.js` calls `start('front')` after the state is
  restored and before it binds; `common/request_worker.ts` calls
  `start('per-process')`.
* **Everything the page draws is in the store** (`scheduler.runs`, a
  persisted per-realm `realms.map`): runs, the leader's row, each process's
  latest per-process run, and the command rows. A manual run or a step-down
  asked of any node is a row the leader obeys at its next tick.

**The step-down** (`POST /admin-api/scheduler/step-down`, D10) is
`cluster.stepDown('ops.scheduler')`: the lease is expired at the token held,
`onLose()` fires, and this node does not campaign for the role again for three
heartbeats — without the hold-off it would take the lease straight back on its
next beat. It is the one addition this feature made to `cluster.js`.

**The jobs registered today**, and where each is argued:

| Job | Kind, scope | Owner and argument |
|---|---|---|
| `authn.session-expiry` | cluster, service | `authn/authn.ts`, `authn/CLAUDE.md` |
| `pki.crl-directory-refresh` | cluster, service | `common/pki_revocation.js` |
| `scheduler.history` | cluster, service | `cluster/scheduler.ts` |
| `signing.rotate` | cluster, realm; hourly, deciding per unit from the NEXT key's age | `common/signing_rotation.ts` (#42) |
| `signing.retire` | cluster, realm; hourly | `common/signing_rotation.ts` (#42) |
| `signing.rotate-now` | cluster, realm; manual only, ON in every mode — what `/admin/keys` and `POST /admin-api/keys/rotate` queue | `common/signing_rotation.ts` (#48) |
| `oauth2.backchannel-logout-sweep` | cluster, service; `oauth2.backchannelLogoutSweepS` | `oauth-oidc/backchannel_logout.ts` (P5) |
| `mail.deliver` | cluster, service; `mail.deliverS` — every realm's outbox: the messages due, dead-lettering past `mail.retentionS`, removing finished rows (#63) | `common/mail.ts` |
| `ssf.dead-letter-sweep` | per-process; `ssf.deadLetterSweepS` — its summary and history are the process's own | `ssf/ssf.ts` (P5) |
| `ssf.stream-maintenance` | cluster, realm; `ssf.streamMaintenanceSweepS`, off while `ssf.inactivityTimeoutS` and `ssf.verificationEveryS` are both 0 — SSF 1.0's inactivity timeout and transmitter-initiated verification | `ssf/ssf.ts` (#144) |
| `risc.opt-out-effective` | cluster, realm; every 5 minutes, off while `risc.enabled` is off — sends RISC `opt-out-effective` for each account whose holder opted out on `/portal/signals` at least `risc.optOutDelayHours` ago (RISC 1.0 section 2.8, #146) | `ssf/ssf.ts` |
| `risk.dataset-directory` | cluster, service; `risk.datasetsDirectoryScanS`, off while `risk.datasetsDirectory` is empty — imports each manifest's dataset file once (#62) | `risk/risk_datasets.ts` |
| `risk.rescore` | cluster, service; `risk.rescoreEveryS`, off while `risk.assessSignIns` is — re-checks every live session against the datasets and the failure history and raises one that became riskier (#62 P4) | `risk/risk_engine.ts` |
| `risk.retention` | cluster, service; hourly — deletes the rows of superseded and refused dataset versions and the failures past their retention (#62) | `risk/risk_datasets.ts` |
| `saml2.sp-metadata-refresh` | cluster, service; `saml2.spMetadataRefreshIntervalS` | `saml/sp_metadata.ts` (P5) |
| `persistence.change-log-pull` | per-process, **quiet**; `persistence.pollInterval` | `persistence/persistence_replication.js` (P5) |
| `persistence.change-log-purge` | cluster, service; five minutes — replaced the `ops.change-log-purge` lease | `persistence/persistence_replication.js` (P5) |
| `persistence.tombstone-purge` | cluster, service; ten minutes, registered at the first flush | `persistence/persistence_minted.js` (P5) |
| `cluster.cache-report` | per-process, quiet; front processes that joined | `cluster/cluster.js` (P5) |
| `cluster.claims-purge` | cluster, service; a minute, registered at the first claim against a database | `cluster/cluster_claims.js` (P5) |
| `cluster.rate-window-purge` | cluster, service; a minute, registered at the first shared count | `cluster/cluster_counters.js` (P5) |
| `oauth2.used-assertion-purge` | cluster, service; a minute, registered at the first claim against a database | `common/used_assertions.js` (P5) |
| `ldap.connection-mirror-maintenance` | per-process, quiet; socket-holding processes | `ldap/ldap_cluster_connections.ts` (P5) |
| `spiffe.authority-rotation` | cluster, realm; hourly, from each authority's own age, in both modes | `spiffe/spiffe_ca.ts` (D6) |
| `caches.eject-expired` | per-process, quiet; every minute — each store's own `eject()` | `admin-ui/caches_admin.ts`, `common/CLAUDE.md` 3ap (P5) |
| `oauth2.expired-token-purge` | cluster, service; hourly — a token record past its expiry and `oauth2.expiredTokenRetentionS`, and the revocation of an expired token | `common/admin_stats.js` (P5; the ticket's "tracked tokens") |
| `oauth2.client-secret-expiry` | cluster, realm; daily — warns (audit + log) about secrets expiring within `oauth2.clientSecretExpiryWarningDays` or expired, and clears a rotated-out secret past `oauth2.clientSecretOverlapS` | `common/signing_rotation.ts`, `common/applications.js` (P5) |

**The timers still outside it** are listed, each with the reason it stays, in
`tests/no_periodic_timers.js`, which fails on a new one and on an entry whose
timer has gone. **P5 of #49 emptied the `becomes` half (2026-09-22)**; what is
left is `permanent`: the heartbeat and origin-claim renewal the scheduler
stands on, and one-shot timeouts and debounces.

**Two things P5 added to the scheduler for them:**

* **A tick is scheduled at the next due job**, bounded by `scheduler.tickS`
  and floored at 100 ms (`nextDelayMs()`), so a job whose interval is shorter
  than a tick — the back-channel sweep's ten seconds, the change-log pull's
  five — runs on its own interval rather than rounded up. The leader's row is
  still refreshed at most once a tick interval.
* **A `quiet` per-process job** records its run in the store only when its
  outcome changes, or once a minute (`QUIET_RECORD_MS`): the change-log pull
  would otherwise write a row per pull per process, which the next pull
  fetches. The report allows a quiet job's row to be that old before calling
  it stale.

**A job registered at first use** (the four purges) requires the scheduler
LAZILY, at that use: `scheduler.ts` requires `cluster_claims.js`, and
`used_assertions.js` is in the parent project's Kerberos COPY closure.

## What is done and what is not (2026-09-14)

**Done — the foundation:** membership, leases, fence, fail-stop, active-passive
with standby wait, the active-active gate and capability table, settings
agreement, UUID origins, holes applied late, the barrier with
commit-before-respond, claims, shared secrets (CSRF, ACME nonce, SSF receiver),
`/admin/cluster` and `GET /admin-api/cluster`.

**Done — section 2, OAuth** (`oauth.codes-once`, `oauth.refresh-rotation`,
`oauth.dpop-jti`): authorization codes, PAR request_uris, rotated refresh tokens
and their families, DPoP jtis and the hosted surfaces' renewal, each spent
through a claim — `oauth-oidc/CLAUDE.md`, *Several nodes*.

**Done — section 2, credentials and enrollment, and section 8's bootstrap**
(`authn.second-factors-once`, `credentials.links-once`,
`enrollment.credentials-once`, `ops.bootstrap-once`): a TOTP step and a
WebAuthn signature counter advanced through `cluster_counters.js`, a WebAuthn
challenge, a recovery code, an activation or reset link, an EAB binding, a SCEP
challenge and transaction, an ACME nonce and finalize, and a SPIFFE join token
each spent through a claim, recovery codes a stale write-back resurrected made
to converge on their claims, and one bootstrap per realm for the cluster —
`common/CLAUDE.md`, *Several nodes: second factors, links, enrollment
credentials and the bootstrap*.

**Verified against a real postgres** (two nodes on one host, product mode): the
second node waits as a standby and binds nothing; SIGTERM on the active node
hands the lease over in ~1.3s at token 2; SIGSTOP on the active node past its
lifetime lets the standby take over, and on SIGCONT the paused node's heartbeat
finds its row expired and it exits with `STS-CLUSTER-0005`.

**Section 1 — keys and the CA — is provided (2026-09-14)**: `keys.agreement`
(`common/keystore.js`), `pki.agreement` (`common/pki.js`),
`pki.revocation-register` (`common/pki_revocation.js`, with
`common/pki_merge.js`), `scep.ra-agreement` (`scep/scep_ra.ts`) and
`spiffe.authority-agreement` (`spiffe/spiffe_ca.ts`), and — added after the
suite's `cluster` mode found it — `vc.keys-agreement`
(`cluster/cluster_secrets.ts`, the BBS key pair; *Claims and shared secrets*). `common/CLAUDE.md` argues
the store arbitration, the merge and the build claim (*Between nodes the store
is the arbiter*, *One build of a scope in the cluster*). Measured against a real
postgres, two product nodes started together against an empty store:

| Probe | `active-active` | control `cluster.mode=off` |
|---|---|---|
| `/oauth2/jwks` (every kid), with and without 2 request workers each | one set | two sets |
| service Root, process Intermediate, default JOSE Issuing CA | one of each | two when the starts overlap |
| an admin API token minted on one node, used on the other | 200 | 401 |
| a realm created on one node, first used on both at once, 3s later | one JWKS | two |
| twelve concurrent revocations of one CA, alternating nodes | 12 of 12 on both CRLs | 6 of 12 on each |
| SCEP GetCACert on both nodes at once | one RA certificate | two |

**Done — section 2's rate limits, section 5's SCIM and SPNEGO state, and
section 8's operations** (`security.rate-limits`, `scim.challenge-state`,
`spnego.pending`, `ops.change-log-retention`): every limiter door counts in
`sts_cluster_windows` (`common/CLAUDE.md`, *Several nodes: one rate-limit
budget*); SCIM's Digest nonces and HOBA challenges are persisted and a nonce
count or signature is spent through a claim (`scim/CLAUDE.md`, *Several
nodes*); a SPNEGO negotiation is keyed by an id the client carries, or matched
by its MIC, and spent through a claim (`kerberos/CLAUDE.md`); the change log is
trimmed below every reader's reported position (`persistence/CLAUDE.md`, *The
change log is trimmed*). And three that are not capability rows: the OpenBao
seeder's check-and-set and second-stack path (`openbao/CLAUDE.md`),
`global.trustedProxies` with the L4-passthrough requirement, and pool sizing
(`common/CLAUDE.md`).

**Done — section 3, last writer wins** (`store.no-foreign-deletes`,
`directory.concurrent-writes`, `sessions.no-resurrection`): the realm registry
and the settings are saved as deltas against a shadow and delete only what this
node removed; a directory upsert is a three-way merge with the row under `FOR
UPDATE`, and the create doors (LDAP add, SCIM, `/admin-api` users and groups)
claim their names across nodes; an ended session, code or refresh token leaves
a tombstone the upsert cannot overwrite, and two copies of one session merge —
`persistence/CLAUDE.md`, *Several nodes writing one row*. Measured on two
nodes against one postgres (2026-09-14), with a CONTROL build of the same tree
that had the section's fixes reverted: twenty groups each given three members
on each node at once — control active-active kept all six in 2 of 20 (53
members lost), control off 0 of 20 (60 lost); fixed, 20 of 20 in both modes, in
the store and on both nodes. A realm created on node B while node A saved realm
and setting changes in a loop: control lost a realm in 1 of 3 runs active-active
(and 2 of 3 earlier runs with the cluster off); fixed, 10 of 10 in all six runs.
A session revoked on A while B's requests touched it: control left 2 of 8 live
rows in the store active-active; fixed active-active 0 of 8, with the eight
refusals logged (`STS-STORE-0054`). **Explained and fixed on 2026-09-14**: the
same probe with the cluster OFF left 8 of 8 rows live because a minted write
never asked for a flush — nothing called `persistence.mintedChanged()` — so a
revocation's tombstone waited for an unrelated write, and active-active hid it
only because the barrier flushes every writing response. It was not a race:
with no other node touching the session, 4 of 4 stayed live, on one node alone
too, and in single-container dispatch mode 8 of 8 (`persistence/CLAUDE.md`, *A
minted write asks for a flush*). Fixed: 0 of 8 two nodes off, 0 of 4
untouched, 0 of 8 dispatch, 0 of 4 one node. The probe's per-node check
(`/logout` answering 200 with the cookie) measures nothing — treat the session
result as the store rows only.

**Done — section 4, sign-out, and section 6, Shared Signals**
(`ldap.connections-cluster`, `ssf.delivery`): a sign-out writes an instruction
by identity that every other node's socket-holding process acts on, and a
per-node table lists every node's bound connections — reported as instructed,
never closed (`ldap/CLAUDE.md`, *And across NODES*); the certificate sign-in and
the KDC catch up with the cluster before a session or a TGS-REQ — it was the
8443 and 9443 listeners' own handler until both were deleted on 2026-09-16 and
is `GET /tls/sign-in` now
(`tls/CLAUDE.md`, `kerberos/CLAUDE.md`); a session's end is reported once
through a claim (`authn/CLAUDE.md`); a poll on a shared store never writes a
row an acknowledgement deleted, a stream's dead and revived transitions are
reported once and one node probes, and a GNAP proof on the SSF endpoints is
spent across the cluster (`ssf/CLAUDE.md`, *Several nodes*). Measured on two
active-active nodes: an LDAPS bind on one listed on the other 10 of 10 and
closed by a sign-out there 10 of 10 (4–22ms after the answer); with the cluster
off, 0 of 10 and 0 of 10. Refusing active-active with `global.publicBaseUrl`
empty, argued for in `ssf/CLAUDE.md`, is done (`STS-CLUSTER-0026`, *The two
modes*).

**Not done** is exactly the capability rows `/admin/cluster` shows as missing —
the remaining single-use values (section 2).

**The suite runs against a cluster (2026-09-14)**: `--modes=cluster` on either
launcher is two single-process nodes, active-active on one postgres and one
OpenBao, behind an HAProxy in TCP mode, with every job opening a new connection
per request so its requests alternate between the nodes. Not a capability row,
because no node can check it. What it proves, what it does not (UDP 88, per-node
sockets), PROXY protocol v2 from the balancer, and the job that fails
if the alternation stops are in `tests/CLAUDE.md`, *THE `cluster` MODE*.
