---
title: How the cluster works
nav_order: 18
---

# How the cluster works, with diagrams

A cluster is several containers of iya-sts against one database. This page
explains how they behave as one service, one idea at a time, for the person
who runs them. [A cluster in AWS](aws-cluster.md) shows how to deploy one;
[Architecture](architecture.md) describes what runs inside a single node.
Every diagram shows a three-node cluster: `node-a`, `node-b` and `node-c`.

## 1. The words

| Word | Meaning |
|---|---|
| **Node** | One container of the service. It is a member of the cluster, with a name (`cluster.nodeName`, or the host name). |
| **Front process** | The node process that owns every listener of the node. [Architecture](architecture.md) calls it the *leader process*; it is not the scheduler's leader below. |
| **Request worker** | A worker thread inside a node that answers requests the front process hands it ([Where a request waits](request-path.md)). It belongs to its node and has no membership of its own. |
| **Store** | The one database every node reads and writes: PostgreSQL, or MariaDB ([Persistence](persistence.md)). Nothing else connects the nodes. |
| **Change log** | A table in the store with one row for every change, written in the same transaction as the change. Every process reads it to find what the others wrote. |
| **Membership row** | A node's row in the store, renewed by its heartbeat. A node whose row expires is no longer a member. |
| **Lease** | A named role that exactly one node holds, such as serving in active-passive mode or leading the scheduler. It expires unless its holder keeps renewing it. |
| **Fencing token** | A number that goes up every time a lease changes hands. A write made under an old token is refused. |
| **Claim** | A row taken in the store with one atomic statement, so that of several nodes trying at once exactly one wins. Used for every value that may be used once. |
| **Leader** | The node holding the scheduler's lease. It is the only node that starts cluster jobs. |
| **Cell** | A whole cluster with its own database in one region. Several cells make one service across regions ([How cells work](cells-concepts.md)); this page is about one cell. |

## 2. Three modes

`cluster.mode` decides how a node behaves when other nodes share its store.

```
  off              one node only. Nothing is coordinated beyond the change
                   log. Two nodes in this mode give wrong answers, silently.

  active-passive   every node joins; ONE holds the service lease and serves.
                   The others restore nothing and bind no port until they
                   take the lease over.

                      node-a ── serving (holds "service")
                      node-b ── standby, waiting
                      node-c ── standby, waiting

  active-active    every node serves.

                      node-a ── serving ┐
                      node-b ── serving ├── one store
                      node-c ── serving ┘
```

| Value | When it applies |
|---|---|
| `auto` (the default) | `active-passive` in product mode on a database store; `off` everywhere else. |
| `off` | One container. |
| `active-passive` | Several containers, one answering at a time. A standby takes over within one heartbeat of a clean stop, and within one node lifetime (`cluster.nodeTtlMs`, 30 seconds) of a crash. It restores the store when it takes over. |
| `active-active` | Several containers, all answering, normally behind a load balancer. |

**`active-active` refuses to start unless all of these hold:**

- The store is a database (`persistence.mode` is `postgres` or `mariadb`).
  Every clustered mode needs this (`STS-CLUSTER-0007`).
- Keys are kept in the store under a key-encryption key you provide
  (`STS-CLUSTER-0008`). Every node must sign with the same keys and open the
  same sealed rows.
- `global.publicBaseUrl` is set to the address clients use, the load
  balancer's (`STS-CLUSTER-0026`). Every node must issue tokens under one
  name.
- `persistence.minted` is on (`STS-CLUSTER-0040`), so that sessions, codes
  and tokens are in the store and not in one node's memory. Every clustered
  mode needs this too.
- Every capability on the **What active-active depends on** table of
  `/admin/cluster` is provided by this build, or named in
  `cluster.acceptMissingCapabilities` (`STS-CLUSTER-0009`). Each row is one
  known way two nodes could give different answers. There is no "accept
  all".

## 3. Every node serves, and the store is the only link

In active-active mode the load balancer may send each request to any node.
The nodes never talk to each other directly: there is no channel between
them, and no node's address is published. Everything one node needs to know
about another arrives through the store.

```
                        clients
                           │
                     load balancer          (global.publicBaseUrl)
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
       ┌──────────┐  ┌──────────┐  ┌──────────┐
       │ node-a   │  │ node-b   │  │ node-c   │
       │ front    │  │ front    │  │ front    │   each owns its own
       │ workers  │  │ workers  │  │ workers  │   sockets and memory
       └────┬─────┘  └────┬─────┘  └────┬─────┘
            │             │             │
            └─────────────┼─────────────┘
                          ▼
            ┌──────────────────────────────┐
            │ the store                    │
            │  directory, realms, settings │
            │  sessions, codes, tokens     │
            │  keys (sealed)               │
            │  the change log              │
            │  membership, leases, claims  │
            └──────────────────────────────┘
```

Each process keeps the state it answers from in memory and writes it to the
store. The store is where nodes agree; memory is where each node answers
quickly.

## 4. How a node sees another node's writes

Every change is written to the change log **inside the transaction that made
it**. Each process remembers the last change it applied and asks the log for
everything after it.

```
  node-a                         store                         node-b
    │ create user carol            │                              │
    ├── one transaction: ─────────▶│ directory row: carol         │
    │                              │ change log: #4812 carol      │
    │                              │                              │
    │                              │── NOTIFY "something new" ───▶│ (PostgreSQL)
    │                              │                              │
    │                              │◀── changes after #4811? ─────┤
    │                              │─── #4812: read carol's row ─▶│
    │                              │                              │ carol is now
    │                              │                              │ in memory here
```

- **The log is the contract; the notification only makes it quick.** On
  PostgreSQL a `LISTEN`/`NOTIFY` message wakes the other processes at once.
  If a notification is lost (a dropped connection, a database restart),
  nothing is lost with it: every process also asks on a timer,
  `persistence.pollInterval` (5 seconds).
- **MariaDB has no notification**, so every process polls the log, every
  second unless `persistence.pollInterval` says otherwise. The same applies
  on PostgreSQL with `persistence.sqlDialect=portable`.
- **Order does not matter.** Applying a change reads the row as it is now,
  rather than replaying an operation. A transaction that commits late leaves
  a gap in the numbering; later changes are applied at once and the gap is
  asked for again on every pull, for up to ten minutes (`STS-STORE-0049` if
  it never arrives).
- **The log is trimmed** below the lowest position every reading process has
  reported, and only once a row is older than
  `persistence.changeLogRetentionS` (an hour). The
  `persistence.change-log-purge` job does it.

On its own, the log means another node sees a change *soon*: within
milliseconds with a notification, and within the poll interval without one.
Section 6 explains how a request is made to see it *at once*.

## 5. Membership and heartbeats

A node joins before it restores anything from the store or binds any port.

```
  start ──▶ JOIN ───────────────▶ AGREE ─────────────▶ restore, bind, serve
            a membership row        a keyed digest of the
            under a fresh id;       settings every node
            same mode as the        must share, compared
            live nodes, or          with every live node's;
            refused                 differ, and the node
            (STS-CLUSTER-0002)      does not start

  while running:
     every cluster.heartbeatMs (2 s): renew the row and every lease held,
     in one statement, by the DATABASE's clock

     ──┬───┬───┬───┬───┬──────────────────────────────▶ time
       hb  hb  hb  hb  hb
                         │◀──── cluster.nodeTtlMs (30 s) ─────▶│
                         last renewal                    row expires
```

- **A join is refused** when the node's mode differs from the live nodes'.
  The settings compared afterwards include `global.mode`, `global.https`,
  `global.publicBaseUrl`, `persistence.mode`, the key settings, the OAuth
  modes, the SPIFFE trust domain, the Kerberos keys and realm, and
  `realms.maxCount`. The digest is keyed by the key-encryption key, because
  several of them are passwords.
- **Every time is the database's clock.** Two containers' clocks differ, and
  a lifetime judged by each node's own clock would let two nodes both hold
  one lease.
- **A node that cannot renew exits.** A failed heartbeat is a warning
  (`STS-CLUSTER-0003`). Once a node has gone a lifetime less one heartbeat
  without a renewal it exits (`STS-CLUSTER-0004`), because the other nodes
  may already have taken over what it held. A row that has already expired
  is never renewed: a node that paused past its lifetime finds that out on
  its next heartbeat and exits (`STS-CLUSTER-0005`). Your container platform
  restarts it, and it joins again under a new id.
- **A blocked node looks dead.** The heartbeat is a timer on the front
  process's thread, so a thread blocked for longer than the lifetime costs
  the node its membership. A heartbeat that runs a heartbeat or more late is
  logged as `STS-CLUSTER-0025`, and the exit message then says the likely
  cause is the node itself rather than the database.
- **A clean stop leaves at once.** On SIGTERM a node releases its leases and
  marks its row as left, so another node can take its roles on its next
  heartbeat. A crash costs one lifetime.
- **Name every node.** The node's name is what the console shows, and what
  its TLS listener key is stored under. Set `cluster.nodeName`
  (`STS_CLUSTER_NODE_NAME`) when your platform gives containers random host
  names, and give no two nodes the same name.

**Server configuration → Cluster** (`/admin/cluster`, and
`GET /admin-api/cluster`) shows:

- this node's mode, role and heartbeat;
- every running member: its name, serving or standby, version, uptime,
  when it was last seen and when its row expires, the leases it holds, and
  whether its settings agree;
- the members that left or expired, one row per name, folded away; a node
  restarted under the same name is counted on its running row;
- each lease, its holder and its fencing token;
- the capability table, and the shared secrets with where this process's
  value came from.

**Monitoring → Worker Pools** and **Monitoring → Node Health** show every
node by name. The node drawing the page shows its own figures live; every
other node's come from a snapshot it writes to the store every 15 seconds.
A snapshot older than 45 seconds is marked **stale**, a node that is no
longer a member is marked **gone**, and a gone node is removed after
`cluster.nodeSnapshotRetentionHours` (24). **Monitoring → Caches** shows
each other node's cache figures the same way, from a report it writes every
30 seconds ([Caches](caches.md#watching-them)).

## 6. Leases and fences

A lease is a role one node holds. A node acquires it by writing its id on
the lease's row; it keeps it by renewing it with every heartbeat; the
fencing token goes up each time a different node takes it.

```
  lease "ops.scheduler"
  ┌────────────┬──────────┐
  │ holder     │ token    │
  ├────────────┼──────────┤
  │ node-a     │ 7        │ ◀──── renewed every heartbeat
  └────────────┴──────────┘
        node-a stops renewing; the lease expires a lifetime later
  ┌────────────┬──────────┐
  │ node-b     │ 8        │ ◀──── taken on node-b's next heartbeat
  └────────────┴──────────┘
        a write node-a still makes "under token 7" is refused
```

**Every write a clustered node makes is fenced.** Each transaction first
checks that the node's membership row is live and, in active-passive mode,
that the node still holds the service lease at its token. The check holds
those rows until the transaction commits, so a takeover cannot land between
the check and the write. A node fenced out for its membership, or for the
service lease, exits (`STS-CLUSTER-0011`). A node that loses a lease for one
role in active-active mode fails that one write and keeps serving.

The heartbeat and the leases run on a database connection of their own, so
a heavy write load cannot take the connections they need.

## 7. The scheduler: each job runs once, on one node

Everything the service does periodically (expiring sessions, rotating keys,
refreshing a CRL, purging old rows) is a job on one scheduler. Every node
runs a scheduler, and the node holding the `ops.scheduler` lease is the
**leader**. Only the leader starts cluster jobs. With clustering off, the one
process is the leader.

```
  every scheduler.tickS (15 s), or sooner when a job is due:

  leader (node-a)                                 store
    │ which jobs are due in the current slot?       │
    │   slot = a multiple of the job's interval,    │
    │   by the database's clock                     │
    │ claim run "signing.rotate | acme | 10:00" ───▶│ one row; a second
    │◀── won, at claim time T ──────────────────────│ leader would lose
    │ run row: running, fence = T  ────────────────▶│
    │                                               │
    │ hand the body to the least-busy request worker│
    │   worker: run(), commit its writes            │
    │◀── result ──                                  │
    │ run row: succeeded  (only while fence = T) ──▶│
```

- **A slot, not a timer.** An interval job's slots are multiples of its
  interval on the database's clock, so every node agrees on when a job is
  due, and a run's id is made from the job, the realm and the slot. Two
  leaders reaching the same slot claim one row. A slot missed while nobody
  led runs once when somebody does, not once per slot missed.
- **The claim is the fence.** A run is claimed for its time limit
  (`scheduler.runTimeoutS`, 600 seconds, unless the job sets its own), and
  the claim's time is written on the run's row. The outcome is written only
  while the row still carries that time. A run still going at its time
  limit is recorded as failed (`STS-SCHED-0002`) and anything it does later
  is fenced out (`STS-SCHED-0003`).
- **A queue, and a cap.** Every hourly job in every realm falls due on the
  same second. The leader starts at most `scheduler.maxConcurrentRuns` (2)
  runs at once, a person's **Run now** first, and the rest wait for the
  next tick. The cap is always below the store's connection pool, so jobs
  cannot take every connection from requests.

### When the leader dies mid-run

```
  node-a (leader) ── claims run R, starts it ── ✗ crash
                                                  │
  ops.scheduler lease expires (one lifetime, 30 s)│
  node-b takes the lease on its next heartbeat ◀──┘
  node-b: R's claim is still held until R's time limit has passed
       ├─ R's slot is still the current one ─▶ node-b claims R again and runs
       │                                       it; the first attempt is
       │                                       recorded "abandoned"
       └─ R's slot has passed ───────────────▶ R is recorded "abandoned"
                                               (STS-SCHED-0011); that slot is
                                               not run again, the next one is
```

A job must therefore be safe to run again in the same slot. Jobs that must
not run twice decide from their own state (a key's age, say), not from
being called.

### Where a run's body runs

The leader keeps the lease, the claim, the fence, the time limit and the run
row. The work itself, a job's body, is handed to the node's ready request
worker with the fewest requests in flight, so that a long job never holds
the thread that answers the node's listeners. It runs on the front process
instead when:

- the node has no request workers (or they have stopped);
- the job names a reason it must run there; Monitoring → Scheduler shows it.
  A handful do, for example the run-history purge and the report jobs;
- a worker answers that it does not know the job's realm yet (a realm
  created a moment ago), for that one run.

A scheduled run of a job that may wait is held for a while when even the
least-busy worker is busy (`scheduler.niceBusyThreshold`,
`scheduler.niceLagMs`), never longer than `scheduler.niceMaxDeferS` and never
more than half its interval. A manual run is never held.

**A body on a worker owns its run only while the leader says so.** The
hand-off grants it 20 seconds. Every 5 seconds the leader checks every run
in flight and renews the grant while it still leads, the run has not timed
out, and the job is still switched on. The body stops at its next step when:

- the leader sends a fence (it lost the lease, or another node took the
  run over);
- the grant runs out because no renewal arrived (`STS-SCHED-0021`): the
  front process's thread is stuck, for instance;
- the run's time limit passes;
- the job is switched off.

A worker that ends in the middle of a run fails the run (`STS-SCHED-0019`).

### Switching jobs off

| Switch | Effect |
|---|---|
| `scheduler.enabled` off | No job runs anywhere. |
| `scheduler.disabledJobs` | The jobs named there do not run, on their schedule or by hand. |
| The job's interval setting at 0 | That job is off. |

A run already going when one of these is switched stops at its next step and
is recorded as it ends, with a note that it was switched off. It is not
counted as a failure.

### Per-process jobs

Some state can be cleaned only by the process that holds it: an in-memory
cache, the process's own read of the change log, its memory report. Those
are **per-process** jobs. Each runs in every process of every node, request
workers included, takes no claim, and has one row per node and process on
Monitoring → Scheduler. The quiet ones (the change-log pull, cache ejection,
the node snapshot) write their row only when the outcome changes, or once a
minute.

**Monitoring → Scheduler** (`/admin/scheduler`, `GET /admin-api/scheduler`)
lists every job, who leads and since when, each job's recent runs and where
they ran, and **Run now**. A Run now pressed on any node is a row in the
store that the leader starts at its next tick.
`POST /admin-api/scheduler/step-down` makes the leader give up the lease; it
does not ask for it again for three heartbeats, so another node takes it.

In a service deployed as cells, each cell is its own cluster with its own
leader, and the jobs that change the global tier run in one cell per slot
([How cells work](cells-concepts.md#14-background-jobs-once-per-cell-or-once-for-the-service)).

## 8. A write is answered only after it is committed and visible

Two rules make a flow that moves between nodes behave as it does on one
node. A browser that signs in through `node-a` and is redirected may land on
`node-b`; a code minted on `node-b` may be redeemed at `node-c`.

```
  browser      node-a                     store                node-b
     │ POST login │                          │                     │
     ├───────────▶│ session written          │                     │
     │            │── commit ───────────────▶│  RULE 2: the 302 is │
     │            │◀─ committed ─────────────│  held until here    │
     │◀── 302 ────┤                          │                     │
     │ GET /oauth2/authorize ─────────────────────────────────────▶│
     │            │                          │◀── RULE 1: pull the │
     │            │                          │    change log first │
     │            │                          │─── the session ────▶│
     │◀────────────────────────────── the code, for that session ──┤
```

- **Rule 1, catch up before serving** (active-active only). Before a request
  is handled, the process serving it pulls the change log, and waits for a
  pull that started after the request arrived. Requests arriving together
  share one pull. If the pull cannot finish within about four and a half
  seconds, the request is served anyway and `STS-CLUSTER-0018` is logged.
- **Rule 2, commit before answering** (on every database store, one node or
  many). A request that wrote anything is answered only after its writes have
  committed. If the commit fails, the client gets `503` with `Retry-After`
  instead of the success, or LDAP result `unavailable` (52) for an LDAP
  write ([Persistence](persistence.md#with-postgres-a-write-is-answered-only-after-it-has-committed)).
  A response sent before its commit is an acknowledgement a crashed node
  could lose.
- **Messages a node sends wait too** (active-active). A back-channel logout,
  a CIBA ping or push, or an OpenID Provider Command is sent only after the
  writes it depends on have committed, because the receiver's answer may
  arrive at another node.
- **One exception: the audit row of a successful read.** A request that
  wrote nothing else is not held for its own audit row, because holding it
  would put a commit under every read in the service. The row commits within
  one flush and reaches the other nodes on their next pull, so an audit read
  on another node straight afterwards may not show it yet. A refusal's audit
  row is always held for.

Inside one node, the same question between request workers is answered by
`workers.readYourWrite` and the ticket and barrier waits on
[Where a request waits](request-path.md#read-your-write). Both rules add
time to a request; the `request phases` log line measures it.

**What rule 1 does not do** is make two requests that arrive at the same
moment on two nodes see each other. That is what claims are for (section
10).

## 9. What each node holds alone, and how each is kept in step

Anything that is not a row in the store, such as a socket, a timer or a
listener, belongs to one process and cannot be reached from another. Each
one has its own way of being kept in step:

| Held by one process | How the cluster keeps it in step |
|---|---|
| **Listeners**: the main port, LDAP and LDAPS, the KDC, SPIFFE, the custom listeners | Every node binds every listener in its own front process. A setting change (a new custom listener, a policy) reaches every node through the change log, and each node binds, rebinds or closes its own. |
| **The TLS listener certificate** | One certificate authority for the cluster, kept in the store. Each node keeps its own listener key, filed under its node name, and certificate. When a node adopts a re-issued authority from the store it re-issues its own listener certificate and applies it to its sockets, LDAPS and SPIFFE included, for the next handshake. Every node's current listener certificates are on its membership row, so the SAML metadata any node publishes names all of them. |
| **The client-certificate truststore** | The anchors added at `/admin/tls/trust` are directory entries, so they reach every node through the change log, and each node's front process applies them to its own listeners. The page and its API are always answered by the front process, because only it holds the listeners. |
| **LDAP connections** | A sign-out writes an instruction naming the identity. Every node that applies it closes that identity's bound connections. Each node also writes a list of its bound connections to the store, so `/admin/sessions` on any node shows them all. A connection on another node is reported as *instructed*, not as closed, because it closes when that node applies the change. |
| **TLS session tickets** (LDAPS) | In active-active mode one ticket key is kept in the store and rotated by the `tls.ticket-key-rotate` job, so a session resumed on another node works. The main port does not share it: a client certificate must be presented again on a node that never saw it. |
| **In-memory caches** | Each process has its own, emptied of expired entries by the per-process `caches.eject-expired` job. Two processes may hold two different cached answers until both expire ([Caches](caches.md)). |
| **The directory, sessions and other state in memory** | A copy in every process, brought up to date from the change log (section 4). With `ldap.workerDirectory=postgres-lru`, request workers hold only part of the directory and read the rest from the store ([Persistence](persistence.md#request-workers-can-hold-the-directory-as-a-window)). |
| **Timers** | No module repeats work on a timer of its own. Periodic work is a scheduler job, so it runs once (a cluster job) or in each process on purpose (a per-process job). |
| **Secrets every node must share** (the CSRF key, the ACME nonce key, the Shared Signals receiver secret) | Kept sealed in the store, first writer wins. |
| **Signing keys and certificate authorities** | Kept sealed in the store. When two nodes make a realm's keys at once, the store keeps the first, and the other node adopts it. A rotation on one node reaches the others through the change log. |

## 10. Two nodes writing at once

Without care, the later of two writes to one row would replace the earlier
one whole, and whatever the other node put there would be lost. The store
avoids that in four ways.

```
  CLAIM: a value used once            node-a ──claim code X──▶ ┐
                                      node-b ──claim code X──▶ ├ one wins;
                                                               ┘ the other
                                                                 is refused

  MERGE: one directory entry          base:   member = [ann]
         changed on two nodes         node-a: member = [ann, bob]
                                      node-b: member = [ann, cy]
                                      stored: member = [ann, bob, cy]

  TOMBSTONE: an ended session         node-a: sign-out ──▶ row = ended
                                      node-b: older copy ──▶ refused; stays
                                                             ended

  COUNTER: a number that only rises   WebAuthn signature counter, TOTP step:
                                      the store keeps the highest ever given
```

- **Claims.** An authorization code, a refresh token's rotation, a DPoP
  proof, a SAML artifact, a TOTP step, a recovery code, an emailed link, a
  Kerberos authenticator, an ACME nonce: each value that may be used once is
  spent through a claim, one atomic statement in the store. Of two nodes
  spending it at once, one wins. If the store cannot be asked, the value is
  refused: a value the service cannot prove unused is not accepted.
- **Directory merges.** A directory write is merged with the entry as it is
  in the store: an attribute one node changed takes that node's value; a
  list both changed (group members, object classes) is merged by value.
  Of two creations of one entry, the first committed is kept, with what
  the second added to it.
- **Creates claim their names.** An LDAP add, a SCIM create and the
  management API's user and group creates claim the entry's name across the
  cluster before they check whether it exists, in active-active mode. A
  second create of the same name waits for the first and then gets the
  ordinary "already exists" (`409`, or LDAP 68). A name still claimed after
  the wait is refused the same way (`STS-LDAP-0092`).
- **Tombstones.** An ended session, a used authorization code or a revoked
  refresh token leaves a marker row that a later write cannot overwrite, so a
  node holding an older copy cannot bring it back (`STS-STORE-0054`). Two
  copies of one live session are merged instead. The
  `persistence.tombstone-purge` job removes old markers.
- **Realms and settings** are saved as changes, never as a whole table, so a
  realm or setting another node created is never deleted for being absent
  from this node's copy.
- **Rate limits** count in the store, so the limit is one budget for the
  whole cluster rather than one per node.

## 11. What does not coordinate, and what is not supported

- **Two nodes with `cluster.mode=off` against one store are not supported.**
  Nothing detects it. Each node applies the other's changes through the
  change log, but no node catches up before a request, no node is fenced, and
  periodic jobs run on both. Use `active-passive` or `active-active`.
- **Sockets are never shared.** A connection, and anything held for it, stays
  on the node it reached. Use a load balancer that passes TCP through (the
  [PROXY protocol](configuration.md#behind-an-l4-load-balancer--the-proxy-protocol)
  carries the client's address).
- **A successful read's audit row** may reach another node a moment after the
  response (section 8).
- **Caches** are per process and converge by expiring (section 9).
- **Mixed builds.** A rolling upgrade runs old and new nodes side by side.
  [A cluster in AWS](aws-cluster.md#upgrading-a-cluster-every-node-at-once-across-the-october-2026-release)
  names the one release that must replace every node at once.
- **On MariaDB** a cluster works, with polling instead of notification, but
  the directory and session windows and cells are refused
  ([Persistence](persistence.md#a-second-engine-mariadb)).

## 12. Where to look

| Question | Where |
|---|---|
| Which nodes are members, which leases they hold, what active-active is missing | Server configuration → Cluster (`/admin/cluster`), `GET /admin-api/cluster` |
| Each node's workers and memory | Monitoring → Worker Pools (`/admin/worker-pools`), Monitoring → Node Health (`/admin/node-health`) |
| Who leads the scheduler, every job and its runs | Monitoring → Scheduler (`/admin/scheduler`), `GET /admin-api/scheduler` |
| How far this process has read the change log, and its gaps | Server configuration → Persistence (`/admin/persistence`) |
| Why a node stopped or refused to start | the node's log: [`STS-CLUSTER-*`](error-codes.md#sts-cluster) for membership, leases and the barrier; [`STS-SCHED-*`](error-codes.md#sts-sched) for jobs; [`STS-STORE-*`](error-codes.md#sts-store) for the store and the change log |
| How long requests waited for each other | the `request phases` log line ([Where a request waits](request-path.md#reading-the-request-phases-log-line)) |

### The settings

Every `cluster.*` setting is read when a node joins, so a change takes a
restart.

| Setting | Environment variable | Default | What it does |
|---|---|---|---|
| `cluster.mode` | `STS_CLUSTER_MODE` | `auto` | `off`, `active-passive`, `active-active`, or `auto` (section 2). |
| `cluster.nodeName` | `STS_CLUSTER_NODE_NAME` | *(the host name)* | The node's name on every page, and what its TLS listener key is stored under. |
| `cluster.heartbeatMs` | `STS_CLUSTER_HEARTBEAT_MS` | `2000` | How often a node renews its membership and leases. A third of the lifetime or less. |
| `cluster.nodeTtlMs` | `STS_CLUSTER_NODE_TTL_MS` | `30000` | How long a membership row and a lease last after their last renewal. The longest a crashed node's roles wait for a takeover, and the longest the node's thread may be blocked. At least three heartbeats. |
| `cluster.acceptMissingCapabilities` | `STS_CLUSTER_ACCEPT_MISSING_CAPABILITIES` | *(empty)* | Capability ids active-active may start without. Each one is a known way nodes disagree. |
| `cluster.nodeSnapshotRetentionHours` | `STS_CLUSTER_NODE_SNAPSHOT_RETENTION_HOURS` | `24` | How long a gone node stays on Worker Pools and Node Health. Changes while running. |

The settings the cluster depends on from other groups:

| Setting | Default | Why it matters here |
|---|---|---|
| `global.publicBaseUrl` | *(empty)* | Required in active-active: the one name every node issues under. |
| `persistence.mode` | `memory` | `postgres` or `mariadb` for any clustered mode. |
| `persistence.coordinate` | `true` | Whether a process applies other processes' changes at all. |
| `persistence.pollInterval` | `5000` ms | The longest a change waits to be seen when a notification is lost; one second on MariaDB unless set. |
| `persistence.changeLogRetentionS` | `3600` | The least time a change-log row is kept. |
| `workers.readYourWrite` | `session` | Read-your-write between the request workers inside one node. |
| `scheduler.*` | | [Configuration](configuration.md#scheduler) lists them; `scheduler.enabled`, `scheduler.disabledJobs`, `scheduler.tickS`, `scheduler.runTimeoutS` and `scheduler.maxConcurrentRuns` are described in section 7. |

## 13. Related

- [Architecture](architecture.md): one node's processes, worker pools and
  listeners.
- [Where a request waits](request-path.md): the dispatcher and the waits
  inside one node.
- [Persistence](persistence.md): the store, what survives, and the commit
  rule.
- [A cluster in AWS](aws-cluster.md): deploying three nodes.
- [Several regions (cells)](cells.md) and [How cells work](cells-concepts.md):
  several clusters as one service.
- [Caches](caches.md): what each process remembers on its own.
- [Configuration](configuration.md): every setting.
