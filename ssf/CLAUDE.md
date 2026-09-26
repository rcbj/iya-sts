# ssf/

The Shared Signals Framework (OpenID SSF 1.0, **final 2 September 2025**), and
the four IETF documents it is assembled from. The **seventeenth** protocol
family here and the first one that TALKS BACK.

| File | What it is |
|---|---|
| `ssf.ts` | The routes. The metadata document, the stream management API, status, subjects, verification, poll delivery, and the two endpoints that are not SSF at all — `POST /ssf/receive` and `GET /ssf/received`, which are this service acting as a RECEIVER so that a client can be the transmitter. |
| `ssf_subjects.js` | **RFC 9493** subject identifiers: the eight formats with their CLOSED member sets, SSF's complex subject, and the nesting ban. A LIBRARY. |
| `ssf_events.js` | The event vocabulary — SSF's two — and the **RFC 8417** Security Event Token they travel in. A LIBRARY. |
| `ssf_streams.ts` | The streams, their subjects and their queues, per trust realm — the queue as a row per SET since 2026-09-13. A LIBRARY. |
| `ssf_http.ts` | **THE SECOND OUTBOUND REQUEST IN THIS REPOSITORY.** RFC 8935 push delivery. A LIBRARY. |
| `ssf_auth.ts` | Who may drive a stream: three schemes (OAuth 2.0, Basic, GNAP) and two scopes. A LIBRARY. |
| `caep.ts` | **CAEP's session register**: what state CAEP believes each session is in, and how many events of which type have been sent about it. A LIBRARY, and one of the two files here that are not vocabulary. |
| `risc.ts` | **RISC's account register**: the three states RISC tracks per account, the opt-out gate, and how many events of which type have been sent. A LIBRARY, and `caep.ts`'s SIBLING rather than a generalization of it — see below. |
| `ssf_receivers.ts` | **THIS SERVICE'S OWN TWO SURFACES AS RECEIVERS** (2026-09-10): the seeded streams, the inboxes, what a receive endpoint checks, and the per-person filter the portal narrows with. A LIBRARY — the two receive endpoints and the two inbox pages are registered by the SURFACES, because a receiver hosts its own endpoint. |
| `ssf_dead_letter_report.ts` | What the dead-letter queues hold, counted, for Monitoring → Shared Signals → Dead letters and `/admin-api/ssf/dead-letters` (2026-09-14). A LIBRARY. |
| `ssf_cluster.ts` | Several nodes (2026-09-14, #46): one report per stream health transition, one prober, and the GNAP key-proof spend as route middleware. A LIBRARY. |
| `account_signals.ts` | What a credential change on the admin and portal doors says over CAEP and RISC (2026-09-13), read out of `require.cache`. A LIBRARY. |

Twelve of the thirteen register nothing (rule 3), so their position in the
route order is not a position. `ssf.ts` is required at **23b in
`common/protocol_stack.ts`** — after `admin-ui/admin.ts`, whose slots
(`setSignalsReporter`, `setCaepReporter`, `setRiscReporter`) it fills, and
before `sts_metadata.ts`, which is last for everybody.

---

## ONE STREAM PER SURFACE, HOWEVER MANY PROCESSES SEED IT (2026-09-12)

**This is the second half of the fix the receiver TOKEN got on 2026-09-11, and
the first half is why the second was needed at all.** That day made the token
derived — an HMAC over the realm and the surface — because each process seeded
its own random one and every loopback push was refused as the wrong
authorization header: 132,546 refused pushes in half an hour.

What it left random was the stream's IDENTITY. `createStream()` minted `'ssf-'
+ randomId(12)`, so each process still created a stream **of its own**. In
development mode that is invisible: minted state is per process, nothing
reconciles it, and the token fix made the pushes land. With a **persisted,
coordinated store** the duplicates are shared and they SURVIVE — the front
process and every request worker seed a pair per start, and every start adds
more.

**AND `emitProtocolEvent()` FANS OUT TO EVERY STREAM THAT ASKS FOR THE TYPE**,
so the cost of a single session event grows with how many times this service
has ever started. Measured on a four-hour test stack in `dispatch` mode:

| | |
|---|---|
| streams in the default realm | **14**, where 2 belong — seven pairs, at seven timestamps |
| events in one bulk-load run | 16,421, each logged `went to 12 of 12 stream(s)` |
| loopback pushes that implies | ~197,000, each signing a JWS and opening a TLS connection to this service from itself |
| `connect EAGAIN` on the worker sockets | **19,737** in the worst run, and it appeared in all eight dispatch runs that day (3,930 to 19,737) |

The front process pinned at a full core and stopped answering; four bulk-load
jobs failed on a **10-second connect timeout** rather than on any assertion,
which reads as a hang rather than as a fan-out.

### The fix is to derive the id, and its two rules are NOT the token's

`internalStreamId()` is `'ssf-internal-' + realm + '-' + surface`, and
`createStream()` takes it **on the context and never from the body** — that
argument is in `ssf_streams.ts` beside the line: `body` is the request body at
`POST /ssf/stream`, so an id read from there would let a receiver name its own
stream and therefore somebody else's. The store writes with
`store.set(stream_id, …)`, so a second process seeding the same id overwrites
rather than adds.

Two rules it has to satisfy that the token does not:

* **IT MUST NOT USE `internalSecret()`.** That secret was per RUN — generated
  at startup, put in the environment so a forked worker inherits it (a store
  several nodes share has kept one since #46, *Several nodes* below) — which
  is right for a credential and fatal here: an id derived from it agrees across
  the processes of ONE run and mints a fresh set on the next start, which is
  this defect moved one level along.
* **IT IS NOT A SECRET AND MUST NOT LOOK LIKE ONE.** A stream id is published
  on `/admin/ssf` and in every stream configuration, so it is the realm and the
  surface written out rather than a hash of them. A reader who sees
  `ssf-internal-default-admin-console` knows what it is; a hash would only have
  hidden which of fourteen streams was which.

### Two things came with it

**`streamFor()` asks for the derived id FIRST and the marker second**, and the
order is the point. `internalSurface` is set on the record after
`createStream()` returns and is not an SSF member, so it is the half of that
lookup a persisted round-trip can lose — and a lookup that missed would now
seed again, which with a derived id means OVERWRITING the stream that is there.
That would quietly undo a pause, and *an existing stream is left exactly as it
is* is that function's whole job.

**`sweepDuplicates()` removes what already accumulated**, because the fix stops
new duplicates and does nothing about a store carried over. It identifies them
by **where they deliver** rather than by the marker — the endpoint is a core
member of every stream configuration and cannot have been lost, which the
marker can — refuses to touch anything carrying the derived id, and says out
loud what it removed, since a stream disappearing is otherwise
indistinguishable from a receiver that was never registered.

**What `tests/ssf_receivers.js` could not see before, and now does.** Its
existing check seeds twice and asserts nothing is made — which passes in ONE
process and always will, because the second call finds the first call's record
in the same in-memory store. Section B2 is the arrangement that actually
happens: a process that never set the marker, a legacy duplicate delivering to
the same path, and the per-run secret rotated under it. Three mutants, all
caught.


## THE QUEUE IS ONE ROW PER SET, AND A STREAM RECORD IS TOUCHED (2026-09-13)

**A stream's queue was an array on the record, and nothing that changed it was
ever written down.** `realms.map()` journals a `set()` and a `delete()`;
`enqueue()` pushed onto `record.queue` and `poll()` filtered it, and neither
called either — nor did a PATCH, a status change or a subject added. In one
process that is invisible. In `dispatch` mode it made the queue PER WORKER:
`sts_ssf_allowed_events` emitted through `/admin-api/risc/emit` (one worker),
polled a control stream (another) and got `[]`; `sts_gnap_signals` acknowledged
a SET on one worker and was handed it again by the next, which RFC 8936 section
2.4 forbids. Both green in the two single-process modes, red in the last three
dispatch runs. **Six parallel polls against the kept stack after one
acknowledgement answered 0, 0, 1, 1, 1, 1** — two workers had the ack and four
had the SET. Sequential polls from an idle client all landed on one worker and
passed, which is why re-running either job alone never reproduced it.

**THE FIX IS TWO THINGS AND THE SECOND IS THE ONE THAT NEEDED ARGUING.**

* **`touch()` on the record**, `caep.ts`'s precedent, at every in-place edit —
  and `liveRecord()` beside it for the two places in `transmit()` that cross an
  `await` (the signature, the push), because a record another worker's write
  has REPLACED in the meantime is a copy `touch()` refuses to write back.
* **The queue moved to `ssf_streams.queued`, a store of its own keyed
  `<stream_id> <jti>`.** A `touch()` alone would have made the queue replicate
  and left it WRONG: a record is whole-valued, the later write wins, and a SET
  is often queued by a transmission that runs AFTER its request answered (a
  GNAP revocation answers and then signs) on a worker that has not yet applied
  an acknowledgement committed a moment earlier — so its whole-record write
  puts the acknowledged SET back, and the reverse race loses one outright.
  With a row per SET, queueing is a new key nobody else writes and an
  acknowledgement is a DELETE of one key, and the two cannot overwrite each
  other in either order. **A poll writes a SET's row only on its FIRST
  delivery**, because a row write is the one thing that could resurrect a SET
  another worker has just deleted.

**What is still whole-valued** is the rest of the record — counters, the log,
`eventCounts`, the agreement — so a concurrent write can still lose an
increment or revert a field another process changed in the same instant. That
is a number on a console page rather than a security event delivered twice.
**Nothing reads `record.queue` any more**: `queueOf()` is the reader,
`tests/ssf_queue_rows.js` fails on the member coming back, and a record an
earlier build wrote has it dropped at its first `touch()` rather than adopted —
nothing ever journalled a change to it, so what a stored one holds is whatever
was waiting at creation.

`tests/ssf_queue_rows.js` holds it by making "another worker wrote this" the
two accessor calls `persistence_minted.js`'s `applyLocally()` makes, in a child
process with a real persist observer. Four mutants, all caught.

## SEVERAL NODES (2026-09-14, #46 section 6) — capability `ssf.delivery`

The section above made the queue correct between the workers of ONE container.
Between containers four things were still decided by whichever process was
looking. `ssf_cluster.ts` holds three of them; `ssf.ts` provides the capability.

* **AN ACKNOWLEDGED SET, POLLED ON ANOTHER NODE.** A SEQUENTIAL ack on A then a
  poll on B needed nothing new: the ack's response is held until its row delete
  commits and B's poll catches up first (the cluster barrier). A CONCURRENT
  poll on B that hands a SET out for the first time while its ack commits on A
  used to write the row back (the first-delivery write above), after the
  delete — the SET queued again until acknowledged a second time. **On a store
  a claim store is shared by (`persistence.clusterStore()`) `poll()` writes no
  first-delivery row**: `deliveredAt` stays the local node's view and
  `counters.delivered` may count one SET once per node that first handed it
  out — a number on a page, where the other was a resurrected event. Two
  concurrent polls on two nodes both RETURNING one unacknowledged SET is left
  alone, and deliberately: one node already returns it on every poll until it
  is acknowledged, and RFC 8936 section 2.4 lets a transmitter redeliver ("MAY
  redeliver SETs it has previously delivered") and tells the recipient it
  "SHOULD accept repeat SETs and acknowledge the SETs regardless". What the RFC
  frames as done is acknowledgement (section 2.1, "redelivery is no longer
  required"), and that is now never undone. A claim per delivery would make a
  poll asynchronous to stop a repeat the receiver is told to expect.
* **A SESSION'S END, ONCE.** `authn/authn.ts`'s `sessionEndOnce()`; see
  `authn/CLAUDE.md`. Every `session-revoked` this family sends starts there.
* **STREAM HEALTH.** Declared dead and revived are each REPORTED once
  (`transitionOnce()`: a claim on the realm, stream and transition for half
  `ssf.deadStreamTimeoutS` — the same transition cannot recur inside one
  timeout); a store that cannot be asked reports anyway (`STS-SSF-0098`). **One
  process PROBES**: `leadsProbes()` is the front process of the node holding the
  `ssf.dead-stream-probes` lease (`cluster.lead()` at require time, campaigned
  on each heartbeat), never a request worker, and every process outside
  active-active as before; half-open goes with the probe. **The four dead-stream
  members stay on the record, which is last writer wins**: a node whose copy
  predates a declaration and writes the record for a counter can revert it. It
  does not oscillate — `failingSinceMs` is already past the timeout on every
  copy, so the next failure anywhere declares it again at once, and the claim
  keeps that from being reported twice — and lost updates to the record are
  section 3's.
* **GNAP ON THESE ENDPOINTS.** `ssf_auth.ts` judged a GNAP token with the
  synchronous `gnap_rs.presentation()`, whose key-proof replay check is this
  process's memory. `ssfCluster.spendGnapProof` is middleware on the twelve
  gated routes: it runs the presentation and `gnap_proof.spendProof()` (a claim
  per replay key) before the handler and leaves both on the request, and
  `attemptGnap()` reads that rather than presenting again — which the in-memory
  cache would refuse as a replay. A spend that lost refuses with the GNAP code
  (`STS-GNAP-0715`/`0716`); on a shared store a GNAP request that reached the
  gate without the middleware is refused (`STS-SSF-0099`).

**WHAT STAYS PER PROCESS, STATED FOR SIZING A CLUSTER.** `ssf.pushConcurrency`
and `ssf.pushBacklog` are a gate in each process: N nodes of P processes push up
to N×P×`pushConcurrency` at once. Each sweep's `STS-SSF-0094` summary counts the
SETs its own process dead-lettered, so N nodes log N lines about N different
sets of pushes — a sum, never a duplicate. Both are left per process: a shared
cap would be a database round trip per push, to bound a number an operator can
set per node.

**TWO DEPLOYMENT REQUIREMENTS, which no node can check for another.**
* **Every node needs the same `global.port`.** The console's and portal's own
  receiver streams are seeded with `https://<loopback>:<global.port>/…`
  (`ssf_http.ts`'s `loopbackOrigin()`); the stream is shared, so a node pushes
  to the SEEDING node's port on its own loopback. With different ports that is
  nothing — ECONNREFUSED, a dead stream, two empty inbox pages. (A same-host test
  with two ports works by accident: node B's loopback reaches node A.)
* **`global.publicBaseUrl` must be pinned.** Unpinned, a seeded stream's `iss`
  and every request-derived issuer is whichever address the seeding node or the
  client used; `publicBaseUrl` is in the cluster agreement fingerprint, so
  pinned it is also checked. **Active-active refuses to start with it empty
  (`STS-CLUSTER-0026`, 2026-09-14)**: every issuer a client verifies — tokens,
  the SSF `iss`, the management API's audience — needs one name for the
  cluster, and an empty value "agrees" on every node while meaning a different
  name on each. The refusal is in `cluster/cluster.js`'s `resolve()`.

`tests/cluster_signout_signals.js` sections 3–6 hold the four, each with its
control (the old behaviour on a store that is not shared); five mutants caught.

## THE ONE PARAGRAPH TO READ FIRST: SSF IS THE PIPE AND NOT THE VOCABULARY

SSF says how a RECEIVER and a TRANSMITTER agree a **stream**, who the events on
it are about, what they travel in, and how they get delivered. It defines
**exactly two events of its own**, and both are about the pipe rather than
about a person:

* **verification** — the receiver asked "is this stream alive?", and this is the
  answer travelling the ordinary delivery path. It is the ONLY end-to-end test
  a stream has: a 200 from the management API says the configuration was
  accepted and says nothing whatever about whether an event can reach the
  receiver.
* **stream updated** — the stream's status changed and the receiver is being
  told IN BAND rather than having to poll. It is the one event a receiver gets
  without asking for it, and the one whose absence is hardest to notice: a
  stream quietly paused at the transmitter looks exactly like a service where
  nothing has happened lately.

The vocabularies are **CAEP** (what happened to a SESSION) and **RISC** (what
happened to an ACCOUNT). **CAEP has been here since 2026-09-03 and RISC since
2026-09-04.** The family is complete.

**THE PROMISE THIS FILE MADE WAS KEPT TWICE, AND THE SECOND TIME IS THE ONE
THAT PROVES IT.** The claim was that adding a vocabulary would be rows in
`ssf_events.js`'s table and nothing else, because the envelope, the subject
grammar, the delivery, the queues, the stream management, the console page and
the management API are all vocabulary-independent. CAEP tested it once and
this file then recorded four things outside the table that had to change.
**RISC changed NONE of those four.** `checkMember()` grew not one value type;
`transmit()`'s subject refusal was already written against the ROW and did not
move; `streamCoversSubject()`'s complex-subject rule is CAEP's and RISC's
subjects are plain, so it was not touched. Fourteen event types cost the
catalogue's machinery nothing at all, which is the only kind of evidence a
claim like that can have.

What RISC did add outside the table is one thing CAEP also added and one
genuinely new: a REGISTER of its own (`risc.ts` — an account is not a session)
and an observer on a DIFFERENT store. CAEP watches `authn.js`; RISC watches
`ldap_server.js`. That is not a second copy of one mechanism, it is the
provisioning layer and the authentication layer, and the whole difference
between the two profiles is which of them the sentence is about.

Eight event types later, the things outside that table that had to change
were:

* **`caep.ts`**, which is not vocabulary. A row says what an event MEANS; that
  file holds what the events are ABOUT — a session, the state CAEP believes it
  is in, and what has been said concerning it. None of that is a property of
  any event type or derivable from the catalogue.
* **one refusal in `transmit()`**, and it is written against the ROW rather
  than against a vocabulary: an event whose row says `subject: 'required'` and
  that carries none is refused. RISC's rows are `required` too, and that line
  did not change for them.
* **one rule in `streamCoversSubject()`**, without which CAEP would deliver
  nothing at all: a stream that names a PERSON covers a complex subject naming
  a session of theirs. That is SSF section 4's own intent rather than CAEP's,
  and it was simply unreachable while no event carried a complex subject.
* **`checkMember()` in `ssf_events.js`**, which grew four value types —
  number, array-of-strings, object and language map. That is the catalogue's
  own machinery and not a branch naming an event type.

Nothing else. If a function anywhere in this directory grows a branch that
names one of SSF's own two event types, one of CAEP's eight or one of RISC's
fourteen, that is the design going wrong.

---

## WHAT RISC COST, AND WHY `risc.ts` IS `caep.ts`'s SIBLING AND NOT ITS
## GENERALIZATION

* `ssf/ssf_events.js` — fourteen rows, three common members written once and
  used on ONE of them, one shared `CREDENTIAL_TYPES` array (RISC 1.0 section
  2.7 defines `credential_type` BY REFERENCE to CAEP's, so the two lists are
  one list and not two alike ones), a `subjectFormats` column, a `deprecated`
  column, `subjectAdvice()` and `nearestMember()`. **No new value type in
  `checkMember()`.**
* `ssf/risc.ts` — the register, three state machines and the opt-out gate.
  NEW, and a LIBRARY.
* `ssf/ssf.ts` — the require, `risc.noteTransmitted()` beside CAEP's,
  `riscAutoEmit()`, `sendOneRiscEvent()`, the observer installation and the
  tenth admin slot's filler.
* `ldap/ldap_server.js` — **`setAccountObserver()`, an INVERTED HOOK**, on the
  same terms as `authn.setSessionObserver()` and with five call sites rather
  than one. See below.
* `common/config.js` — a `RISC` group of eleven, `env/defaults.js`
  regenerated.
* `common/audit.js` — four actions in the existing `signals` category.
* `admin-ui/admin.ts` — the tenth slot, `/admin/risc`, `/admin/risc-accounts`
  and `/admin/risc-accounts/account`, `riscAccountChooser()`, two `SECTIONS`
  rows, two `LIST_PARAMS` rows and a `SETTING_HOMES` row.
* `mgmt-api/admin_api.ts` — two GETs and a POST with three actions;
  `mgmt-api/admin_api_spec.ts` — the `Risc` schema.
* `sts_metadata.ts` — one `SPECS` entry and **six** `ENDPOINTS` rows, three
  admin and three management API — which is the count the CAEP block's own
  note warns about: a family's protocol endpoints are obvious and the CONSOLE
  and MANAGEMENT API rows it also costs are the ones a checklist forgets.
* `tests/risc_register.js` — the three state machines, the gate and the
  register in process.

**WHY THE REGISTER IS A SECOND FILE.** A session and an account are not the
same kind of thing. A session begins, is used and ends, and there are many of
them per person; an account IS the person, has no beginning this service can
see, and outlives every session on it. A register serving both would have one
row that is sometimes one and sometimes the other. Three further differences
each fall out of that and none of them is a preference:

* **`observe()` answers with a LIST.** A session act is one act. A directory
  write is not: one `PUT /Users/:id` can set `active` to false AND change a
  mail address, which is two RISC events about one write, and an observer that
  returned the first would drop the second with nothing anywhere saying so.
* **The register is keyed on the PERSON and not on the subject.** A RISC
  subject is composed in whichever format `risc.subjectFormat` names, and the
  two identifier events ignore that setting and use `email` — so one account
  legitimately produces two different `subjectKey()`s, and a register keyed on
  the subject would split one person into two rows *at exactly the moment
  their identifier changed*, which is the one moment the row is worth having.
* **The state is three things.** A lifecycle, an opt-out state and a
  credential standing, moving independently: an account can be opted out and
  perfectly healthy, or compromised and still enabled. A CAEP row has one
  `state` because a session is alive or it is not.

---

## THE ADMIN CONSOLE AND THE USER PORTAL ARE RECEIVERS (2026-09-10)

Each has a **stream of its own**, seeded per trust realm, asking for every CAEP
and every RISC event type; each hosts a **receive endpoint**; and each draws
what arrived on a page of its own — `/admin/signals` and `/portal/signals`.
`ssf_receivers.ts` is the module and carries the design at length. Six things
about it reach outside that file and this is the index of them.

**THE ARGUMENT IS `common/oidc_rp.ts`'s, MADE A SECOND TIME.** That file turned
these same two surfaces into OpenID Connect relying parties on 2026-09-06, and
its complaint was that this service's own two applications were the only
applications in the process that did not use the protocol this service exists
to demonstrate — a real relying party has no access to the provider's session
store and these two read it. The same sentence was true here: a page drawing a
security event by reaching into `caep.ts`'s register is not a receiver, it is
this service reading its own notes. A receiver is something a stream was agreed
with, that gets a signed document it has to verify, addressed to an audience it
has to recognise.

**1. DELIVERY IS A REAL RFC 8935 PUSH OVER THE LOOPBACK INTERFACE, AND THE
IN-PROCESS VERSION WAS WRITTEN FIRST AND TAKEN OUT.** Handing the SET to the
inbox by function call would have skipped the body, the media type, the
authorization header and the signature — everything a receiver does, leaving
only the part that looks run. So `ssf_http.ts` dials this service's own address
like any other receiver.

**2. TWO OF `ssf_http.ts`'s FOUR BOUNDS DO NOT APPLY TO THAT ONE ADDRESS, AND A
THIRD DELIBERATELY DOES.** `ssf.pushAllowedHosts` exists to stop this service
dialling a host somebody named in a stream configuration, and this host is not
named by anybody — it is computed from `global.port`. The https rule exists
because a SET is somebody's security posture in transit, and a request from this
process to itself does not traverse a network. **`ssf.pushDelivery` is NOT
exempt**: with it off both internal receivers go silent, which is said at
seeding time, on both inbox pages and in `status()`. `isOwnLoopback()` is an
ORIGIN comparison and never a substring match, and `tests/ssf_receivers.js`
asserts the refusal rather than the match.

**3. THE ANCHOR IS PINNED RATHER THAN THE CHECK RELAXED.** The listener's
certificate is issued by this service's own Root (or, with none, is
self-signed per start) — nobody a public truststore knows — so the ordinary
check would refuse every internal push, and `ssf.pushSkipTlsVerification` is
NOT the way round it, because that setting turns the check off for every
receiver in the world to fix a connection to ourselves — and is not honoured in
product mode at all (#171). Our own trust anchor
(`tls_server.serverCertificate().trustAnchorPem`), the hostname check skipped:
`oidc_rp.js`'s back channel does exactly this and these are the same three
lines.

**4. THE STREAMS ARE IN EVERY REALM.** This point once contrasted them with the
console's client entry, seeded in the default realm only; that entry is in
every realm since 2026-09-11 (`applications.js`), so the contrast is gone and
the reason is the streams' own: events happen in the realm they happen in,
streams are per realm, and the console draws one realm at a time — so a
console with no stream in `acme` would show an empty page in `acme` while
`acme`'s sessions were being revoked. **A client entry is about signing
somebody IN and a stream is about what HAPPENED.**

**5. THE RECEIVE ENDPOINTS ARE GUARDED BY THE STREAM'S OWN
`authorization_header`**, minted per stream and per start and given to nothing
but this service's own transmitter, compared in constant time; then the `aud`,
refusing `invalid_audience`; then the signature. **That member had never been
set by anything here before** — a receiver supplies it, and this service had
never been one — so the code path that sends it had never run against a receiver
that reads it. It is what lets `/admin/signals/receive` sit outside the console's
gate without being a hole, which `admin-ui/CLAUDE.md` argues as the console's
third gate exemption.

**AND IT IS DERIVED RATHER THAN RANDOM SINCE 2026-09-11, WHICH IS THE ONE PLACE
"per start" WAS NOT A COMPLETE SENTENCE.** `seedStreams()` runs at startup in
whichever process is starting, and a dispatched service starts FOUR: the front
process and every request worker load the whole protocol stack. These streams
are minted state, which development mode neither persists nor coordinates, so
nothing reconciled them afterwards — each process seeded its own pair with its
own `randomId(32)`. The transmitter ran in the process the event happened in and
the loopback push landed on whichever worker the front process routed it to, so
the two almost never agreed: **every push this service made to itself was
refused with "the wrong authorization header"**.

Measured on 2026-09-11 in `dispatch` mode: **132,546 refused pushes in half an
hour** across eight realms, while the SCIM bulk load ran — a real HTTP request
each, through the proxy, competing with the traffic under test for the workers'
unix sockets until they answered `EAGAIN`. That job died on the suite's
thirty-minute bound.

**NOTHING COULD SEE IT, AND THAT IS THE part worth keeping.** No assertion
anywhere fails when a receiver hears nothing: an inbox that was never delivered
to and an inbox that refused everything are the same empty page, and
`ssf/CLAUDE.md`'s own list of what an empty inbox can mean did not have this on
it. The only signal was a `warn` line in a log nobody reads while the suite is
green.

So the token is DERIVED — one per-run secret in the environment, which a forked
worker inherits (the cluster's shared secret since #46; see *Several nodes*
above), and an HMAC over the realm and the surface, so every process
arrives at the same answer without being told and the console's token is still
not the portal's. `crypto.js`'s `deriveSharedCredential()` is the derivation,
because that is the one place this service does cryptography.
`tests/ssf_receivers.js` asserts it by computing what a SECOND process would
derive rather than by starting one — the property is that two processes agree
WITHOUT talking, so a test that made them talk would be testing something else.

**6. THE PORTAL'S FILTER FAILS CLOSED AND THAT IS A RULE RATHER THAN A
SETTING.** One stream carries events about everybody the portal serves, so the
narrowing is on the way out and the person is composed from the session and from
nothing else. An identifier the filter cannot resolve to an account — a phone
number, an opaque id this service did not compose — is **not** a match: showing
one person another person's account lockout is a disclosure, and failing to show
somebody one of their own is an incomplete page, and those are not the same size
of mistake. The page says so out loud. `portal/CLAUDE.md` argues it as this
directory's hardest A01 case.

**AND ONE THING IT COST OUTSIDE SHARED SIGNALS ENTIRELY, WHICH NOTHING HERE
WOULD HAVE PREDICTED.** `authn.js` mints an ARRIVAL SESSION on the front doors,
matched by prefix, and both receive endpoints are registered UNDER a front door
— `/admin` and `/portal`. So every delivered event minted a browser session for
a machine that will never send the cookie back: a service telling its own
console about every sign-in minted a second session for every session. That is
the failure that file's own comment names ("one row per metadata poll, for
ever") arriving from a direction a prefix match cannot see, and it is fixed by
`NOT_ARRIVAL_PATHS` there rather than by moving the endpoints, because the path
is what says which receiver a SET was delivered to. **It was found by running
the thing, not by reading it.**

**WHAT THE READING OF A SET COST THIS DIRECTORY** is three functions moving:
`readSet()`, `verifySet()` and `publicKeyForHeader()` are `ssf_events.js`'s now
and were private to `ssf.ts`, because three receivers reading a SET three ways
would be three opinions about what arrived. Building a SET and reading one back
are the two directions of one format and belong in one file.

## AND THEY ACT ON WHAT THEY RECEIVE (#62, 2026-09-22)

rcbj asked for "surfaces act on signals". Until then both receivers only
recorded what arrived. #117 pointed out that recording only was the one thing
keeping an unverified SET harmless. So acting came with #117's rule, and the
rule is enforced in code, not in policy.

* **Nothing acts on a SET unless it verified.** `actOn()` runs only for a
  SET that passed every check `accept()` makes (typ, iss, aud) AND whose
  signature verified. That holds whatever `ssf.receiveRequireSignature` says
  about accepting it. An unverified SET is recorded, and nothing else
  happens.
* **What a verified SET may do is policy.** `xacml/xacml_signal_pep.ts` asks
  the built-in `signal-response` policy (`xacml.signalResponsePolicy`) once
  per event type in the SET. Its one reaction today, `signal-end-sessions`,
  ends the RECEIVING surface's own relying-party sessions for the person
  named, through `authn.endRelyingPartySessions()`. It never ends the
  provider's sessions: those are the transmitter's to end, and it has
  usually ended them already (the cascade in `dropSession()`).
* **Who the SET is about is `isAbout()`**, the portal's fail-closed match,
  with the person composed as `personOf()` composes one.
* **Confined to the realm the SET arrived in.** The console keeps every
  realm's sessions in the default realm's partition, so a session is matched
  on the realm it came from (`derivedFromRealm`) as well as the person.
  `alice` in one realm is not `alice` in another.
* **Development observes** (`mode.observesSignalsOnly()`), unless
  `ssf.actOnSignalsInDevelopment` is on. A suite driving the console emits
  events about the people it is signed in as.
* **The row says what was done.** `reactions` is written onto the inbox row
  BEFORE the row is recorded, because rows are written once and never
  rewritten. The row shows whether it was taken and how many sessions it
  ended, observed, or failed (`STS-SSF-0111`). A policy that cannot be
  loaded is `STS-SSF-0110`.

`tests/signal_response.js` covers the policy, its decisions, and a real
signed SET through `accept()`: development observes; the person's own
console session is ended, once; somebody else's event, an unverified SET
and an unpermitted event end nothing; and a disabled policy ends nothing.

**A FOREIGN transmitter's events are acted on since #153** (see *THIS REALM
AS A RECEIVER*, below), under the same rule: nothing acts unless the SET
verified, and what it does is the same policy's decision.

---

## THE OPT-OUT GATE, AND THE EXCEPTION WITHOUT WHICH IT IS A TRAP

RISC section 2.8 gives an account three states — `opt-in`,
`opt-out-initiated`, `opt-out` — and says the last means it is NOT
participating in event exchange. `risc.honourOptOut` is on by default because
that is the conforming behaviour, and a suppressed event is counted on the row
(`suppressed`), which is the one number in this console that says a receiver
heard nothing **on purpose**.

**The four opt-out events are never suppressed**, and that exception is the
whole rule rather than a convenience:

* `opt-out-effective` is the event that ANNOUNCES the account has reached the
  silent state. Gating it would enter that state without telling anybody, so a
  receiver would see the signals simply stop — indistinguishable at the far end
  from a transmitter that has gone down.
* `opt-in` is sent FROM the opt-out state by definition. It is the only way a
  receiver ever learns the account came back, and gating it would make the
  opt-out permanent for every receiver in the world.

The middle state exchanges everything, and the specification says why: it
exists to stop a hijacker from opting out the moment they take an account over
and silencing the very events that would report them.

**One more asymmetry, and it looks like a bug until it is stated.** A
suppressed AUTOMATIC event still moves the register and a suppressed HAND
EMISSION does not. In `observe()` the directory really changed — somebody was
deleted, `active` really did go false — so the register follows the act whether
or not anybody was told. In `riscEmit()` the act IS the emission: nothing
happened except that somebody asked this service to say something and it did
not, and applying the state would leave a register asserting that an account
was purged on the strength of a message never sent.

---

## WHAT RISC IS SENT BY ITSELF, AND FROM WHERE (rewritten for #146, 2026-09-22)

| Act | Event | Where it is noticed |
|---|---|---|
| a person is deleted | `account-purged` | `deletePerson()` and the LDAP delete handler |
| `pwdAccountLockedTime` appears | `account-disabled`, with `reason` only when an administrator gave one (`hijacking`, `bulk-account`) | every write of the entry: `account_state.ts`'s disable, SCIM `active: false`, an `ldapmodify` |
| `pwdAccountLockedTime` goes | `account-enabled` | the same |
| `mail` / `telephoneNumber` / `mobile` moves | `identifier-changed`, the subject the OLD value | the same |
| a create or a contact change takes an address another account released within `risc.recycleWindowDays` | `identifier-recycled`, the subject the address | the same, read against the register's `releasedIdentifiers` |
| a password reset, a reset link | `account-credential-change-required` | the admin doors (`observeAct()`) |
| a reset link | `recovery-activated` | the admin door |
| a reset marked "the credential was compromised" | `credential-compromise` (`password`) | the admin doors |
| recovery codes cleared, or confirmed on the portal | `recovery-information-changed` | the admin doors, `/portal/mfa` |
| the account holder opts out, cancels, opts in | `opt-out-initiated`, `opt-out-cancelled`, `opt-in` | `POST /portal/signals` |
| an opt-out's delay has passed | `opt-out-effective` | the `risc.opt-out-effective` scheduler job |

**THE DIRECTORY OBSERVER SITS ON THE STORE AND NOT ON A DOOR**, which is why
there are several call sites in `ldap_server.js` rather than one in `scim.js`.
The same act reaches this directory over SCIM, over LDAP and from the console,
and a feature that noticed only the SCIM one would report a deprovisioning
done with a PATCH and stay silent about one done with an `ldapmodify`. That is
a transmitter lying by omission about half its own traffic. **CAEP shipped
exactly that defect for one revision** (`session-presented` from the OAuth2
authorization endpoint alone), and it took a test naming every protocol to
find it, because a count of zero is also what *nobody asked for that type*
looks like.

**AND IT IS HANDED THE ATTRIBUTES BEFORE AND AFTER, AND `risc.ts` DECIDES.**
The directory knows what a write is; it does not know that a lock appearing is
an `account-disabled`. The one thing it carries besides the attributes is the
administrator's RISC `reason` for a disable (`notice.reason`, threaded from
`admin_actions.ts` through `account_state.ts`, `credentials.ts` and
`writePersonFlag()`). A reason is never invented. Until #146 every disable
said `hijacking`, which told receivers an account had been taken over when
somebody had merely left.

**AN ABSENT ENTRY IS NOT AN ACTIVE ONE.** `activeIn()` answers `null` for a
create's `before` and a delete's `after`, so creating a person is not an
`account-enabled` and deleting a disabled one is not either.

**`identifier-recycled` IS READ FROM THE REGISTER'S OWN HISTORY.**
- Each row keeps `releasedIdentifiers`: an address it moved off, or everything
  it held when purged, each with its time.
- An account taking one of those within the window is the act, and the event's
  subject is the address.
- The memory is the register's, so it is also bounded by
  `risc.maxAccountsTracked`: a trimmed row forgets what it released.

**THE ACCOUNT HOLDER'S OPT-OUT.** Section 2.8 makes it their choice, so
`/portal/signals` offers the one move the state diagram allows from where the
account is (`risc.optOutOf()`).
- Opting out stays in `opt-out-initiated`, and receivers keep being told
  everything, until `risc.optOutDelayHours` has passed; the scheduler job then
  sends `opt-out-effective`. The delay is the section's own defence: somebody
  who has just taken an account over cannot silence it at once.
- The row's `optOutInitiatedAt` is what the job reads. It is set on both paths
  that move the state: `applyOptOut()` when the event is transmitted, and
  `applyActLocally()` when it is not.
- A move is refused unless the register actually moved (STS-PORTAL-0075 and
  -0076). With Shared Signals off there is nothing to record it.

**Three older gaps #146's HTTP job found:**
- **`createUser()` never told the account observer.** The console,
  `/admin-api` and SCIM all create through it, and only an LDAP add told the
  observer. So an account created disabled sent no `account-disabled`, and a
  created address could not be recycled. It calls `noteAccountChange()` now.
- **Identifiers are released when the directory says so** (`observe()`), not
  only when an event about it has been delivered. The next write can take the
  address before a push has come back.
- **A `phone_number` subject is read back** (`accountIdOf()`). A transmitted
  phone `identifier-changed` matched no account before, and
  `applyToState()`'s identifier branch filed every change as the email.

**`optOutsDue()` CLAIMS what it returns.** The state moves to `opt-out` only
after delivery, so without the claim a second run of the job would send
`opt-out-effective` twice (seen).

**Not here:**
- `credential-compromise` has no detector (#62).
- ~~A person cannot start recovery themselves until there is a mail channel
  (#63).~~ Since #63 (2026-09-22) a person starts it at
  `/portal/forgot-password`, and `recovery-activated` is sent with the person
  as the initiating entity (`common/mail_uses.ts`).
- The deprecated `sessions-revoked` is by hand only.
- A received event is acted on only by the console's and portal's own
  receivers (#62), and by a realm receiving a foreign transmitter (#153).

---

## THREE THINGS ABOUT RISC'S ROWS THAT SURPRISE SOMEBODY WHO KNOWS CAEP

* **Eleven of the fourteen have no payload members at all**, and only
  `credential-compromise` has a required one. **The subject carries the entire
  message**, so a subject naming the wrong person is not a partly wrong event —
  it is a wholly wrong one with nothing else in it to notice by. That is what
  makes `risc.subjectFormat` the consequential setting in the group.
* **The four common claims are not common here.** CAEP section 2 gives four to
  all eight of its events. RISC gives THREE — no `initiating_entity` — and
  gives them to exactly ONE of its fourteen. A reader porting CAEP's
  `withCommon()` across would attach four members to fourteen rows and produce
  thirteen events carrying members their specification does not define, which
  nothing would report.
* **One member name in the whole of Shared Signals uses a hyphen**, and it is
  `identifier-changed`'s `new-value`. `new_value` typed from habit produces an
  event that is well-formed, delivers, and tells the receiver nothing.
  `nearestMember()` in `ssf_events.js` names the near miss, and the generator
  deliberately does **not** silently correct it: a mock that quietly repaired
  the commonest mistake in an event type would be a mock that hid it.

**AND ONE OF THE FOURTEEN IS DEPRECATED BY ITS OWN SPECIFICATION.**
`sessions-revoked` — plural, every session the account has — is replaced by
CAEP's `session-revoked` — singular, the one the subject names. It is offered
by default and warned about on every event, because a transmitter that cannot
produce a deprecated event cannot be used to find out what a receiver does with
one, and receivers in the field still send and expect it.

**RISC SECTION 3.1 IS THE ONLY DELIBERATE DEFECT IN THIS SERVICE THAT A
SPECIFICATION ASKS FOR BY NAME.** Google's production RISC transmitter spells a
subject identifier's discriminator `subject_type` rather than `format`; the
specification records this, says the usage is deprecated, says new services
MUST NOT use it, and then tells relying parties they need code to work around
it anyway. `risc.googleSubjectType` renames the member on every RISC subject
this service sends, and on nothing else: CAEP and SSF's own events keep
`format`, because their specifications never had the problem.

---

## WHY THE SUBJECT GRAMMAR IS WRITTEN OUT HERE AND NOT VENDORED

`common/vendored/` holds byte-identical copies of the parent project's files,
and `kerberos/`'s eight codec modules are vendored for a reason this file's
`ssf_subjects.js` deliberately does not follow: **one wire codec must not exist
twice.**

A subject identifier is not a wire codec. It is JSON, and the defect that
matters in it is a READING — an accepted extra member, a missing required one,
a format name spelt from memory. If both ends of this project read one
implementation, a misunderstanding they SHARE is one neither can see: the round
trip passes and the workflow interoperates with nothing.

So the debugger has `client/src/ssf_client.js`'s grammar, this service has
`ssf_subjects.js`, they were written independently, and the parent project's
`tests/ssf_protocol.js` drives one against the other **over the wire** — every
one of the eight formats, the complex subject, and three refusals. That is the
argument `common/pq_jose.js` makes about the composite construction, applied to
a grammar instead of to a signature.

**THE CLOSED MEMBER SET IS THE CHECK THAT EARNS IT.** RFC 9493 section 3 gives
each format a closed set of members and every conforming receiver MUST reject
an identifier carrying one it does not recognise — it cannot tell whether the
member NARROWS the subject. A transmitter that accepted a loose subject would
teach a receiver to send documents nothing else takes, and the sender would
never find out.

**AND TWO INDEPENDENT GRAMMARS STILL SHARED A MISTAKE, WHICH IS WORTH KNOWING
(#144, 2026-09-22).** Both copies spelt two format names from the drafts,
`issuer_subject_id` and `decentralized_identifier`, where RFC 9493 and its IANA
registry say `iss_sub` and `did`. Both also shaped the complex subject the
pre-final way, with no `"format": "complex"`. The round trip passed because
both ends were wrong in the same way. Independence catches a misreading only
one end makes, and a name both ends copied from the same draft slips through.
The check that would have caught it is the one #144 used: read the final text
and the registry, not the other implementation. This file now has the
registry's names, SSF 1.0 section 3.5's three formats and the final complex
shape. The debugger's copy is rcbj/id-proto-debugger#300.

---

## `ssf_http.ts` IS THE SECOND OUTBOUND REQUEST, AND IT IS A WEAKER CASE THAN
## THE FIRST

`federation/federation_http.ts` is the first, and its header makes an argument
this one **cannot**:

> THOSE URLS ARE SUPPLIED BY THE CALLER. THESE ARE SUPPLIED BY THE
> ADMINISTRATOR.

It enforces that by refusing to take a URL at all: `fetchJson()` takes a
relationship record and the NAME of an attribute on it, and there are three
legal names.

**A push delivery endpoint cannot work that way, and pretending otherwise would
be the dangerous version of this feature.** RFC 8935 push delivery IS the
receiver telling the transmitter where to post — that is what the delivery
method is, not an implementation choice here — so any transmitter that speaks
push takes a caller-supplied URL, including every commercial one.

So the honest statement is that this file makes an outbound request to an
address a caller chose, and these are the four bounds:

1. **`ssf.pushDelivery` turns it off entirely.** With it off this service still
   speaks the whole of SSF over POLL delivery, where nothing is dialled at all,
   and `delivery_methods_supported` then advertises only `urn:ietf:rfc:8936` —
   so a receiver finds out at stream creation rather than by never receiving
   anything.
2. **`ssf.pushAllowedHosts` is an allowlist and is EMPTY BY DEFAULT, meaning
   any.** That default is the one deliberate looseness here and it is what makes
   this usable as a mock. It is a HOST list rather than a URL list on purpose: a
   receiver legitimately moves its endpoint path and does not legitimately move
   to another host.
3. **https only, with the receiver's certificate verified** (#171, 2026-09-23).
   What travels on a push is not a credential, it is an EVENT — that somebody's
   session was revoked, that an account was disabled — which is somebody's
   security posture in transit, and the receiver's own `authorization_header`
   travels beside it. Both halves want TLS, and RFC 8935 requires the receiver
   authenticated. It was ONE setting, `ssf.pushAllowInsecure`, that allowed
   plain http AND turned verification off, and product mode honoured it. Three
   now, asked through `common/outbound_tls.ts` (shared with GNAP, federation
   and XACML): `ssf.pushAllowHttp` (development only; product refuses plain
   http, `STS-SSF-0108`), `ssf.pushSkipTlsVerification` (development only;
   ignored in product, `STS-SSF-0109`, and refused on write, `STS-CORE-0103`)
   and `ssf.pushCaFile` (a private CA beside node's store; unreadable refuses,
   `STS-CORE-0104`). This service's own receivers are exempt from all three —
   the pin in point 3 above is what that connection checks. Every insecure
   request is LOGGED rather than only the setting being logged once.
4. **No redirects, a capped body and a timeout.** A 302 from a push endpoint is
   not a protocol this service speaks, and following one would post the event —
   and the receiver's authorization header — wherever the Location said.

**One thing is NOT a bound and must not be mistaken for one.** The management
API is gated unconditionally — `mode.gatesSharedSignals()`, where this was
`ssf.authRequired` until 2026-09-06 — but Basic is a turnstile in
development: any username with any password but `invalid` passes it (in product
mode the Basic password is verified — see *Three schemes* below). **A token's
scope is tied to its client in both modes since #110 (2026-09-22)**: the token
endpoint and GNAP issue `ssf:read`/`ssf:write` only to a client whose
`oauthAllowedScope` declares them, and `undeclaredRefusal()` asks every OAuth
and GNAP token whether its client still does (`STS-SSF-0107`), so withdrawing
the declaration cuts off tokens already issued (`common/scope_policy.ts`).
"A receiver created the stream" is therefore not evidence of much.

---

## IT DOES NOT RETRY A FAILED PUSH BY DEFAULT, AND THAT IS DELIBERATE

RFC 8935 section 2.4 lets a transmitter retry. This service does not unless
`ssf.pushRetries` says to — **0 by default since that setting arrived on
2026-09-12, which is exactly the old behaviour** — because a mock that retried
would make a receiver's ONE-SHOT failure invisible: a client under test that
answers 500 to the first push and 202 to the second looks, from its own logs,
like a client that works. A deployment is the other case, and
`ssf_http.ts`'s `pushSetWithRetries()` retries only what could go differently
(no connection, a timeout, a 5xx, a 429) and never a 400 refusal, with a linear
`ssf.pushRetryDelayMs` between attempts.

~~The failure is recorded on the stream's own log, the event stays on the queue,
and `POST /admin-api/ssf/transmit` sends another when somebody asks.~~ **Since
2026-09-14 a final failure goes to the stream's DEAD-LETTER QUEUE**, with the
reason, for inspection — see the next section. Nothing resends it; `POST
/admin-api/ssf/transmit` still sends another when somebody asks.

---

## UNDELIVERABLE SETs, DEAD STREAMS AND THE PUSH CAP (2026-09-14)

**What asked for it.** A `dispatch` run's SCIM bulk load emitted two events per
directory write to forty-two push streams — forty of them other realms' console
and portal receivers, put in the default realm by the partition leak
`common/CLAUDE.md` records under `realms.js` — all at once through
`emitProtocolEvent()`'s `Promise.all()`. Every refused SET stayed on the live
queue for ever (`queueOf()` is a scan and a sort on every event sent), wrote an
`ssf.event.refused` audit row whose code put a line in the log (30,698 in one
second when a session sweep revoked 1,398 sessions), and the pushes back into
this service's own receivers filled every worker. The service answered nothing
for fourteen minutes. rcbj chose all four answers below.

**THE PUSH CAP** (`ssf_http.ts`'s `pushSetGated()`): `ssf.pushConcurrency` (8)
pushes in flight per PROCESS, the rest waiting in order, at most
`ssf.pushBacklog` (2000) of them; past that the push is not made and the SET is
dead-lettered with `STS-SSF-0092`. A retry waits for a slot of its own. The
dispatcher's batch lane (`common/CLAUDE.md`, `request_pool.js`) is the other
half: the receive endpoints are batch paths.

**THE DEAD-LETTER QUEUE** (`ssf_streams.deadLetters`, a store of its own keyed
`<stream_id> <jti>` for `queued`'s reason). In: a push that failed after
`ssf.pushRetries`, a push over the backlog, everything waiting when a stream is
declared dead, and every SET sent to a dead stream — the last UNSIGNED, because
signing what nothing will receive is the cost this exists to stop. Each letter
keeps the claims, the token if signed, the reason, the code and the receiver's
status. Out: after `ssf.deadLetterRetentionS` (3600), the oldest past
`ssf.deadLetterMaxPerStream` (1000), a delivered probe, a deleted stream, or
`clear-dead-letters`. **Nothing resends a dead letter** except a probe.

**DEAD STREAMS** (`notePushFailure()` / `notePushSuccess()`). A push stream whose
pushes have all failed for `ssf.deadStreamTimeoutS` (300; 0 off) is DEAD —
four members on the record (`failingSinceMs`, `deadSinceMs`, `nextProbeAtMs`,
`deadReason`) so the state replicates with it. **It is not an SSF status**: the
stream stays `enabled`, because `paused`/`disabled` are the receiver's and the
operator's words and rewriting one would tell a receiver somebody paused it. A
dead stream is not pushed to; once per timeout the SWEEP pushes its oldest dead
letter (signing it if it was not) and a success revives it. With no letter left
it goes HALF-OPEN: the next SET is pushed and one failure kills it again. A
`verification` event is pushed to a dead stream anyway — a receiver asking to
verify is the probe it asked for. `revive` by hand refuses a live stream
(`STS-SSF-0095`).

**LOGGING IS PER STREAM OR PER SWEEP, NEVER PER SET** — rcbj's rule, "do not log
every undeliverable signal". One audit row and log line when a stream is
declared dead (`ssf.stream.dead`, `STS-SSF-0093`) and one when it revives
(`ssf.stream.revived`); one line per realm per sweep
(`ssf.deadLetterSweepS`, 60) counting what was dead-lettered since the last,
by stream and by code (`STS-SSF-0094`); and on the stream's own log one line
when a run of failures STARTS, not per failure. `ssf.event.refused` is no longer
written by a push. **Every process sweeps**: deletes are idempotent, the counts
summarised are each process's own, and `nextProbeAtMs` is set before a probe so
processes rarely probe one stream twice in a period. **In active-active mode
one process of the cluster probes** (#46; *Several nodes*, above).

**Where to look**: `/admin/ssf` (a DEAD marker, the dead letters, *Revive* and
*Drop its dead letters*), `GET /admin-api/ssf` (`streamDetail[].dead`,
`deadLetters`, and `deadLetters.pushes` — this process's cap), and `POST
/admin-api/ssf/revive` / `/clear-dead-letters`. `tests/ssf_dead_letters.js`
holds it, eight mutants caught. **The counts over every stream at once are
Monitoring → Shared Signals → Dead letters** — the next section.

**AND THE SEEDER SWEEPS ANOTHER REALM'S RECEIVER STREAMS**:
`ssf_receivers.ts`'s `sweepDuplicates()` also removes a stream whose id is
`ssf-internal-<other realm>-<surface>`, so a store that already holds the leaked
copies heals at the next start or realm creation. By id, because the endpoint of
a leaked copy names the other realm's prefix. `tests/ssf_receivers.js` B3.

## MONITORING → SHARED SIGNALS → DEAD LETTERS (2026-09-14)

`/admin/ssf/dead-letters` and `GET /admin-api/ssf/dead-letters`: every held
dead letter in the ambient realm COUNTED — by cause, error code, the receiver's
HTTP status, event type, time and stream — and the letters searched
(`dlq`, exact `dlstream` and `dlcause`) and paged (`lettersPage`). rcbj asked
for it as a new section of Monitoring → SSF; Monitoring had no such group, so
the three Shared Signals pages already there became one (`admin-ui/CLAUDE.md`).
rcbj chose: the group, all four sets of numbers, read-only with the controls a
link away on each stream's card, and the ambient realm only.

**`ssf_dead_letter_report.ts` IS THE ONE PLACE THE NUMBERS ARE COMPUTED**, a
library registering nothing, reached through a `deadLetters` member of
`setSignalsReporter()` rather than a slot of its own — rule 3e's test for a
new slot is a new cycle or a moved route, and a second reader of one family
through one require adds neither. `admin-core/admin_views.ts`'s
`ssfDeadLettersJson()` adds only the narrowing and the slice, for both doors.

* **THE QUEUE IS PER REALM, NOT A GLOBAL QUEUE WITH A REALM ON EACH ROW.**
  `deadLetters` is a `realms.map()` — one Map per realm partition; in
  PostgreSQL the rows share `sts_minted` with the realm in the primary key.
  rcbj asked for that to be confirmed, and it is what the page's first
  sentence says.
* **FOUR CAUSES, NOT ONE PER CODE.** `STS-SSF-0092` (backlog full), `-0093`
  (waiting when declared dead) and `-0096` (sent to a dead stream) say this
  service decided not to push; every other code is a push that FAILED, and the
  code is still on every row and in `byCode`. The cause is what an operator
  acts on differently.
* **THREE THINGS ARE PER PROCESS AND SAY SO**: the push cap — per process and
  SHARED BY EVERY REALM, the one limit here that is not per realm, so a storm
  in one realm dead-letters another's with 0092 — the recent-sweep history, and
  the since-start totals. In a dispatched service the console is answered by a
  SURFACE worker whose push gate is not the protocol workers', which is why the
  reply names the pid and the role. A sweep's *held*, *expired* and *orphaned*
  are the shared store; its *new* is its own process's pushes.
  `sweepSignalsRealm()` calls `noteSweep()` before the probes run.
* **NO TOKEN LEAVES**, as on `/admin/ssf`; a row says whether it was signed.
* **STREAM STATES ARE FOUR WORDS**: `dead` (`isDead()`), `half-open` (failing
  for at least `ssf.deadStreamTimeoutS` without being dead — what `halfOpen()`
  leaves, and one more failure kills it), `failing`, and — for letters whose
  stream this process does not hold — `unknown`. A delivering stream with no
  letters is not a row.
* **THE TIMELINE** is the retention window in round buckets (sixty at most,
  epoch-aligned); a letter older than the window is counted beside it as
  `olderThanWindow`, not piled into the first bucket.

`tests/ssf_dead_letter_report.js` holds the report and the narrowing, five
mutants caught. Verified over HTTP by hand against an isolated instance: real
refused and 503 pushes, a stream declared dead and sent to, and
`sts_metadata.js`, `admin_api.js`, `sts_admin_api_operations.js` and
`sts_admin_console.js` passing with the page and operation in their lists.

## THE THREE OUTCOMES OF A PUSH ARE THREE AND NOT TWO

A 202 is delivery. A **400 with `{err, description}`** is the receiver
REFUSING — it read the SET and would not take it — and that is a completely
different fact from a network failure. It is also the most interesting thing a
receiver ever says, and `pushSet()` reports it separately for exactly that
reason: the stream's log can then tell "nothing answered" from "the receiver
said invalid_audience".

200 and 204 are accepted as well, and **not silently**: a receiver answering one
of those is very slightly wrong, the event did arrive, and a mock that refused
would be testing the transmitter's pedantry rather than the receiver's
behaviour. The note says which it was.

---

## EACH STREAM IS ITS RECEIVER'S, AND `aud` IS THE TRANSMITTER'S (#144, 2026-09-22)

**Until this date every management call looked a stream up by id alone**, and a
`GET /ssf/stream` with no id returned every stream in the realm with its
`authorization_header`. So any caller holding `ssf:read` could read the
console's and portal's receiver tokens (and, with #117, inject rows into their
inboxes), and any caller holding `ssf:write` could PATCH another receiver's
`endpoint_url` to itself or delete its stream. In product mode HTTP Basic is on
by default and every verified directory person gets both scopes. SSF 1.0
section 8 says the authorization "MUST associate a Receiver with one or more
stream IDs and aud values"; nothing here did.

* **The owner is `createdBy`**: the identifier the creator authenticated as
  (`ssf_auth.ts`'s principal: a client's `client_id` in both modes, a person's
  `sub`, a GNAP client instance, a Basic username). `ssf_streams.ts`'s
  `ownedBy()` / `streamOwnedBy()` / `streamsOwnedBy()` are the only reading of
  it, and every `/ssf/*` route that takes a `stream_id` goes through
  `ssf.ts`'s `ownedStream()`.
* **Not yours answers exactly as absent: 404, the same sentence.** The
  specification's own words are "no Event Stream with the given stream_id FOR
  THIS EVENT RECEIVER", and any other answer tells a caller which ids exist.
* **This service's own two streams are nobody's.** They are marked
  `internalSurface` AT CREATION, from the context and never from the body, and
  `ownedBy()` refuses a marked stream whatever `createdBy` says. `createdBy`
  alone would not do: they are created as `internal`, and in development any
  Basic username authenticates, including that one. They are managed on
  `/admin/ssf` and through `/admin-api` only.
* **`ssf.maxStreams` is per owner**, and a create past it is a 403 (section
  8.1.1.1's "not allowed to create a stream"). It was per realm, so one
  receiver could use up everyone's allowance.
* **`aud` is Transmitter-Supplied** (section 8.1.1). This file used to argue the
  opposite: that `aud` was the receiver's, required and never defaulted, because
  a receiver given a default would never learn it was required. The final text
  settles it the other way, so `assignAudience()` gives a new stream the
  identifier its creator authenticated as. A receiver may instead name any of
  the values it is associated with (`audiencesFor()`: that identifier, and the
  application identifier and `ssfReceiverId` values on the application entry
  `applications.ssfAllowedEventsFor()` finds for it), and nothing else. An
  update may carry `aud`, or any other Transmitter-Supplied member, only
  unchanged (`transmitterSuppliedMismatch()`, sections 8.1.1.3/8.1.1.4).
  In-process callers that need a particular audience (the seeded receivers, the
  in-process tests) pass it as `ctx.audience`, which a remote caller cannot
  build.

The receivers still CHECK `aud`, and now `iss` and `typ` too (sections 4.1.6 and
4.1.1): `ssf_receivers.ts`'s `accept()` against the stream's own values, and
`/ssf/receive` against `ssf.receiveIssuers` / `ssf.receiveAudiences`, which
default to the only issuer whose key it holds and to the endpoint's own URL.

---

## STATUS CHANGES, IN THE ORDER SECTION 8.1.5 GIVES (#144)

SSF 1.0's three statuses, and the difference between the middle one and the last
is the whole reason a receiver has a pause: it is "I was not listening" against
"it did not happen". `setStatus()` drops the queue on a disable and says how
many went.

**Every door that changes a status goes through `ssf.ts`'s `changeStatus()`**:
the receiver's `POST /ssf/status`, the console and `/admin-api`, the inactivity
timeout and a dead stream. Stopping a stream (enabled to paused or disabled)
transmits the `stream-updated` event FIRST and changes the status once that has
settled, because section 8.1.5 says the event MUST be sent "before stopping the
stream". Enabling changes the status first, then transmits, then `drainHeld()`
pushes what a paused push stream held, in queue order. Until #144 every path set
the status and transmitted afterwards, so a disable dropped the queue before the
event could go.

* **A paused PUSH stream holds.** `transmit()` queued the SET and then POSTed it
  whatever the status was, so a receiver that paused its stream kept receiving
  (section 8.1.2.1: "MUST NOT transmit"). Now the SET waits on the queue.
* **A stopped POLL stream hands out its stream-updated events and nothing
  else**, and a disable keeps them when it drops the rest
  (`clearQueueFor(id, true)`). On poll, "sent" means "collectable", so dropping
  that event with everything else would announce the change to nobody.
* **SSF's own two events are sent whether or not the stream agreed them**
  (sections 8.1.4 and 8.1.5 both say MAY), because the transmitter MUST send
  stream-updated when it changes a status and an agreement check would make that
  impossible.
* **A DEAD stream is paused** (`pausedForHealth`), with the announcement
  attempted first (it lands on the dead-letter queue with the rest). A revival
  (a probe, a delivered push, or Revive) enables it again and announces it,
  but only when this transmitter was the one that paused it. While paused for
  health, a verification event is still pushed, because it is the probe.

---

## INACTIVITY AND TRANSMITTER-INITIATED VERIFICATION ARE ONE SCHEDULER JOB (#144)

`ssf.stream-maintenance`: cluster, realm, every `ssf.streamMaintenanceSweepS`,
off while both of its settings are 0, which is the default. `inactivity_timeout`
(section 8.1.1) is `ssf.inactivityTimeoutS`. Activity is any management call a
receiver makes about its stream, and a poll; `noteActivity()` records it. The
timeout is published on the stream configuration while it is set, and
`ssf.inactivityAction` chooses pause, disable or delete. **Off by default
because a push receiver never has to call back after creating its stream**, so
a timeout that was on by default would pause every healthy push stream.
`ssf.verificationEveryS` sends each enabled stream a verification event with no
`state` (section 8.1.4.2 forbids one the receiver did not supply); the console's
**Send a verification event** and `POST /admin-api/ssf/verify` do it once. Both
leave the internal streams alone.

`POST /ssf/verify` answers **204 once the event is queued** (section 8.1.4.2:
receivers "MUST NOT depend on the Verification Event being transmitted
synchronously"). It waited for the push and answered 400 on a failure until
#144; a failure is a dead letter now, like any other.

---

## THE PATHS USE A SLASH WHERE SSF's EXAMPLES USE A COLON

SSF's own examples write `/subjects:add`, and **express reads `:add` as a route
parameter** — so a route registered that way matches
`/ssf/subjectsANYTHING` and matches the literal path only by accident.

Nothing about this is visible on the wire: SSF fixes no paths and publishes
every endpoint in its configuration metadata, so a receiver reads
`add_subject_endpoint` and never composes one. It is written down because the
next person to "fix" the paths will reach for the colon.

---

## THE METADATA DOCUMENT IS NEVER GATED, AND ANSWERS WHILE THE FAMILY IS OFF

Two separate decisions, both deliberate.

**Never gated**, whatever the endpoints it describes require: a receiver has to be able to
read what the endpoints are and which schemes they take BEFORE it can
authenticate to one, and a transmitter whose discovery document needs a
credential is one nothing can bootstrap against. It is the rule
`scim.authDiscovery` expresses for the ServiceProviderConfig, with the setting
left out because there is no version of this that is useful closed.

**Answers while `ssf.enabled` is off**, when every other endpoint answers 501:
a receiver that finds this document and then a 501 has learned something
specific, where a 404 would leave it unable to tell "this service does not speak
SSF" from "the path is wrong".

---

## THREE SCHEMES AND TWO SCOPES

SSF 1.0 section 8 requires these endpoints to be protected and — unlike RFC
7644, which names six schemes and leaves it there — has the transmitter
**publish** what it accepts, in `authorization_schemes`. So a receiver discovers
how to authenticate rather than guessing, and `ssf_auth.ts`'s list and that
member are one table.

**Two schemes and not six, and that is a decision** — the third, GNAP, came
later and for a different reason (below). SCIM offers all six of RFC
7644's because that RFC names all six and a provisioning client meets them in
the wild. SSF names none — `authorization_schemes` is an open list of
`spec_urn` values and the only one its examples use is OAuth 2.0 — so this
offers that one and HTTP Basic beside it, which exists so that a client under
test that has not implemented a token flow yet can still reach every endpoint.

**`ssf:read` and `ssf:write` differ in what they permit**, which is the second
place in this service after SCIM where two scopes do. A read token is refused
for every write with a 403 NAMING THE SCOPE, because a refusal a caller cannot
act on is worse than none.

Basic grants BOTH, and says so: a scheme with no scope in it cannot express the
difference, and returning a read-only decision would be a refusal with nothing
a client could send to get past it.

**IN PRODUCT MODE THE BASIC PASSWORD IS VERIFIED, SINCE 2026-09-12**, through
`common/credentials.ts` — the call `scim_auth.js` makes. Until then this file
never asked the mode, so a product deployment's streams could be driven with
any name and any password. A verified person still gets both scopes, which is
SCIM's identical grant; `ssf.authBasic` turns the scheme off (and out of
`authorization_schemes`) for a deployment that wants the scope split enforced
for every caller.

**A THIRD SCHEME SINCE 2026-09-12: GNAP.** `ssf_auth.ts`'s `attemptGnap()` accepts
a key-bound GNAP access token whose access names `ssf:read` / `ssf:write`, so a
GNAP web application owns a stream as ITSELF — which is what
`gnap/gnap_signals.ts`'s subject scope needs. It takes only the `GNAP` scheme;
`Bearer` on these endpoints stays OAuth 2.0.

## `ssfAllowedEvents`: THE ONE PLACE AN APPLICATION ENTRY LIMITS A STREAM (2026-09-12)

rcbj asked for it after asking whether ticking Shared Signals on the application
screen enabled CAEP and RISC. It did not, because no declaration does anything:
a receiver chose its event types in `events_requested` and nothing on its entry
could narrow that. **This attribute can**, and it is the first thing on an
application entry that limits this family — so the registry's "declaring grants
nothing" sentence now names it as one of two exceptions.

* **Values** are `caep`, `risc`, or event type URIs this transmitter knows;
  anything else is refused at both write doors (`STS-REG-0053`), and the
  attribute is family-scoped to `ssf` like `oauthTokenExchangeRefreshToken` is
  to OAuth (`STS-REG-0010`). **Empty means unrestricted**, which is every entry
  that existed before it.
* **The owner is `createdBy`** — whatever authenticated to `/ssf/stream` —
  matched as an application identifier or among an entry's `ssfReceiverId`s.
* **It is asked twice, and a mutation run showed why both matter.**
  `ssf_streams.ts` narrows `events_delivered` when a stream is created or
  updated, and `deliversEvent()` asks again at every delivery — the candidate
  filters in `ssf.ts`, `transmit()` itself (`STS-SSF-0081`), and the per-receiver
  "takes" columns all go through it, and `streamConfiguration()` reports the
  effective list. Delivery alone would let a limit lifted later hand back types
  withheld at agreement; agreement alone would let a receiver escape a tightened
  limit by having created its stream first.
* **SSF's own two events are always allowed**, because a receiver refused its
  verification event cannot learn that its stream works.

`tests/vendored/sts_ssf_allowed_events.js` holds all of it against an
unrestricted control stream; six mutants, all caught, two only after the job
was tightened.

---

## THE OWNER LOOKUP IS CHEAP AND CACHED (2026-09-14), AND IT WAS A 58-SECOND STALL

`deliversEvent()` asks `allowedEventsFor()` for every event on every stream, and
it called `applications.get()` then `applications.list()` — a whole view of every
application, sealed keys opened — to read one attribute. The console's and
portal's own streams are owned by `internal`, which names no application, so
every call walked the registry. A postgres-mode session sweep that expired 2,412
sessions (a session-revoked each, to two streams) blocked the one process for 58
seconds and an LDAP modify in `sts_directory_bulk_load_ldap` timed out.
`applications.ssfAllowedEventsFor()` reads raw attributes and keeps its answer
per realm until the directory's `applicationsVersion()` — the `ou=applications`
subtree clock — moves: 2,400 expiries with 300 applications registered take
344ms. `tests/ssf_allowed_events_cache.js` asserts every change is seen at once,
the LDAP modify handler's unlocated touch included; two mutants caught.

## A FOURTH VOCABULARY OF ONE EVENT: THIS SERVICE'S OWN (2026-09-22, #42)

`urn:iya:sts:secevent:event-type:signing-key-rotated`, `family: 'sts'`, no
subject — rcbj's D4. `common/signing_rotation.ts` calls
`ssf.signingKeyRotated()` after a rotation has happened, and every stream that
asked for the type gets one SET naming the realm, the units rotated (`<unit>
<previous kid> -> <kid>`), the reason (`scheduled`, `requested`,
`emergency`) and the JWKS and crypto metadata addresses. It is a URN of this
service's own because no specification defines the event; a receiver that
does not know it ignores it, as SSF says. The refresh-token encryption keys
rotate in the same act and are never named: they are published nowhere. An
emergency rotation also sends CAEP `session-revoked` and RISC
`sessions-revoked` (#48, P4) — those are about PEOPLE, and this is not.

## THE OTHER KEYS A RELYING PARTY PINS, AS SIBLING URNs (2026-09-26, #245)

`federation-key-rotated`, `spiffe-authority-rotated` and
`tls-certificate-changed` join `signing-key-rotated` and
`kerberos-tickets-invalidated` in the `sts` family, and
`ssf.serviceKeyChanged(kind, notice)` sends them. **They are SIBLING URNs and
not more units of #42's event, and the reason is the receiver's handling.** A
stream chooses what it receives BY TYPE, and each type means one action: fetch
THIS document again (the JWKS, the Entity Configuration, the SPIFFE bundle, the
listener's anchor). Widening the #42 event would have handed every receiver that
caches the JWKS three kinds of change it cannot act on. It would have had to
parse `rotated` to tell them apart, and the event's `jwks_uri` would name the
wrong document for all three. So each keeps #42's members (`realm`, `rotated` as
`<unit> <from> -> <to>`, `reason` from the same three words, one `*_uri`,
`event_timestamp`). SPIFFE adds `trust_domain` and `bundle_changed`, which is
false for an X.509 authority re-issued under the Root, because the bundle
publishes the Root. The type `boolean` is new to `checkMember()` for that
member.

The OWNERS do not require this module. `ssf/service_signals.ts` is a library in
`account_signals.ts`'s shape: it reads `ssf.ts` from `require.cache`, runs the
send inside the key's realm (in every realm for the listener, `*`), and never
throws into the rotation. `oidfed/federation_keys.ts` announces `rotate()` and
`revoke()`, but not a next key merely published. `spiffe/spiffe_ca.ts`
announces both rotations, `scheduled` from its job and `requested` otherwise.
`tls/tls_server.js` announces a listener certificate it REPLACES; the first
certificate a process takes over its self-signed bootstrap is not announced.
`admin-ui/pki_admin.ts` announces a realm whose SPIFFE Issuing CA an act on the
hierarchy moved. **Not in any setting**: the `sts` family is always offered
(`supportedEventUris()`), so #86's closed sets needed no new value.
`kerberos-tickets-invalidated` gained the reason `nothing-retained`: an
ORDINARY rotation by hand with `krb5.retainedKeyVersions` 0 keeps nothing, and
until #245 it ended every TGT unannounced (`kerberos/CLAUDE.md`).
`tests/service_key_signals.js`, `tests/vendored/sts_service_key_signals.js`.

## A CHANGE TO THE CERTIFICATE HIERARCHY TELLS THE PEOPLE UNDER IT (2026-09-26, #244)

`ssf/service_signals.ts` also carries the fan-out that `/admin/pki`'s acts on
the TIERS owe the people holding leaves. `caRevoked()` handles an Issuing CA or
Intermediate put on its parent's list: it walks down to every live
person-held certificate beneath it and sends `revoke`, plus RISC
`credential-compromise` for `keyCompromise` / `cACompromise`, through
`accountSignals.credentialCompromised()`, the funnel #231 uses for a leaf.
`snapshot()` before, and `hierarchyChanged()` after, `build`, `build-root`,
`build-scope`, `reissue-use-case`, `recertify`, `import-ca` and `clear`, which
compare per certificate. A slot re-minted from the current tree gets `update`,
naming the new certificate. Anything else gets `revoke`, naming the old one.
**What is re-minted is settled from the code, not assumed.** Only the
register's SLOTS are re-minted (a person's TLS client certificate). The issued
register (RFC 7523/7522 key pairs, every ACME, EST and SCEP enrolment) never is,
because this service holds no key for them. A branch rebuild re-certifies only
the realm's signing keys, so a TLS client certificate is orphaned there. Only
certificates live under the CURRENT tree count, so a rebuild never re-announces
what an earlier act orphaned. **The fan-out is batched**: 50 people at a time,
each batch handed over (into the queue and the push cap) before the next, with
a turn of the event loop between batches and the console's answer ahead of all
of it. `tests/ca_hierarchy_signals.js`,
`tests/vendored/sts_ca_hierarchy_signals.js`.

## A STREAM THIS TRANSMITTER DELETES IS TOLD FIRST (2026-09-26, #245)

`retireStream()`: the console / `/admin-api` delete and
`ssf.inactivityAction: delete` used to call `streams.removeStream()` directly.
They now go through `changeStatus(record, 'disabled', reason)`, which transmits
BEFORE it stops the stream, and only then remove it. SSF 1.0 has no delete
event, and this is the one notice available. A push is attempted and settled
before the removal. On a poll stream the SET leaves with the stream, as for any
disable. An already-disabled stream and this service's own receivers are
removed without a notice. The receiver's own `DELETE /ssf/stream` sends
nothing, because it asked.

## WHAT THIS FAMILY DELIBERATELY DOES NOT DO

Each of these is on `GET /ssf` in the same words, because a mock's omissions are
the half a reader cannot discover from a protocol trace.

* **~~It generates no event on its own.~~ IT DOES NOW, AND CAEP IS WHY.** That
  sentence led this list until 2026-09-03 and the reason it could is exactly
  the reason it no longer can: SSF defines no event about a session, so a
  transmitter that emitted one would have been inventing a vocabulary — and
  CAEP *is* that vocabulary. A sign-in emits `session-established`, a session
  presented again and honoured emits `session-presented`, and a sign-out emits
  `session-revoked`, on every stream that asked for the type and whose subjects
  cover that session, with nobody having typed anything.

  **THE MIDDLE ONE WAS OIDC-ONLY UNTIL 2026-09-03, and it was the one real gap
  in this feature.** The other two go through a FUNNEL — `startSession()` and
  `dropSession()`, which every browser SSO profile here reaches — so both were
  protocol-independent from the day CAEP landed. A presentation has no funnel:
  it is a thing each protocol endpoint decides it is doing, and only
  `oauth-oidc/oauth2.ts` called `authn.notePresented()`. `saml2_sso.ts`,
  `saml11_sso.ts` and `wsfed.ts` each read `sessionOf(req)` to answer a request
  out of an existing session — which *is* single sign-on — and reported
  nothing. So a receiver watching a SAML or WS-Federation session saw it start
  and end with every single sign-on between the two **missing**, and the
  evidence was a count of zero, which in this protocol is also exactly what
  *nobody asked for that type* looks like. All four call it now, each from the
  branch that HONOURS the session rather than from `sessionOf()` (which runs
  several times per request, so an event there would be several events for one
  act) and below the branches that refuse or step up — a `wauth` this session
  cannot satisfy, an `authn_error`, an IsPassive with nothing usable — since
  those end in a refusal or a new sign-in and nothing was honoured. `tests/caep_presented_every_protocol.js`
  holds all four to it. `caep.autoEmit` puts the old behaviour back rather
  than leaving it only in the history of this file. `credential-change`
  (2026-09-13, every door since #145) and `assurance-level-change`
  (2026-09-14) have automatic triggers too, and `token-claims-change` goes out
  for a directory change to a claim somebody's live tokens carry (#145) and a
  modified GNAP grant, and `risk-level-change` (#62 P4) when a person's risk
  level changes and the `risk-response` policy permits announcing it
  (`riskAutoEmit()`), and — since #164 — the device register sends
  `device-compliance-change`, a device's `risk-level-change` and its
  credentials' `credential-change` (*A DEVICE'S EVENTS*, below). Every one of
  CAEP's eight now has an act here.
* **It does not retry a failed push unless `ssf.pushRetries` says to.** See
  above.
* ~~It is not a receiver of anybody else's transmitter~~ — **reversed
  2026-09-26 (#153)**: a realm registers a foreign transmitter by its issuer
  and receives from it; see *THIS REALM AS A RECEIVER*, below.
* **It verifies nothing about a subject.** A stream may name somebody who has
  never been here, which is what a receiver's "I do not know this subject" path
  needs.
* **A `verified: true` on an Add Subject request is believed.** SSF lets a
  receiver say it has already confirmed the subject; a real transmitter may then
  skip a confirmation step, and there is none here to skip.
* **Streams are in memory and die with the process IN DEVELOPMENT**, like
  everything else this service mints. `persistence/CLAUDE.md`'s rule decides it:
  the signing key is regenerated there, so a queue restored from disk would be
  tokens nothing can verify. In product mode on postgres `ssf_streams.streams`
  persists with the rest — and so, since 2026-09-12, do the CAEP and RISC
  registers (below), and since 2026-09-13 the queue, as rows of its own (see
  *THE QUEUE IS ONE ROW PER SET* below).

---

## THE TWO DELIBERATE DEFECTS

The same device as `oauth2.breakIdTokenNonce` and the Kerberos names that stay
unknown: a permissive transmitter is hard to write error handling against, so
the errors have to be reachable on purpose.

* **`ssf.legacySubClaim`** adds the deprecated `sub` claim beside `sub_id`. RFC
  8417 section 2.2 discourages it and SSF uses `sub_id` because the thing an
  event is about may be a person AND a device AND a session at once; a client
  written against a transmitter that gets this wrong reads nothing from a
  conforming one, and this is how that client is caught.
* **`ssf.breakSetSignature`** changes ONE CHARACTER of the signature after
  signing.

**BOTH ARE DEVELOPMENT MODE'S ONLY (#104, 2026-09-23).** Product mode honoured
them until then, which let a deployment emit SETs nothing had signed. Each row
carries `onlyWhile: 'spoilsOnPurpose'` — refused on write in a product realm
(`STS-CORE-0103`) — and `ssf_events.js` reads both through
`mode.valueInForce()`, `buildSet()` for the claim and `signSet()`'s `.then()`
for the signature, so a realm switched to product with either still stored
stops producing the defect on its next SET and says so once (`STS-CORE-0106`).
`caep.omitEventTimestamp` and `risc.omitEventTimestamp` are NOT marked: they
are conforming. `risc.googleSubjectType` — non-conforming on purpose, and
honoured in product — was found in the same sweep and left for a decision of
its own, which **#181 (2026-09-23) took**: it carries `spoilsOnPurpose` too,
and `risc.ts`'s `googleSubjectType()` and the RISC view read it through
`mode.valueInForce()`.

**And the second one has a trap in it that cost a test run.** It changes the
**first** character of the signature and not the last, and that is not a style
choice: the last character of a base64url string usually carries PADDING BITS
the decoder discards. An RS256 signature is 256 bytes — 2048 bits in 342
base64url characters of six bits each — so its final character has four bits
nothing reads, and changing `A` to `B` there produces a token that looks
altered, **decodes to the same bytes, and verifies perfectly**. A deliberate
defect that is not a defect is worse than none at all, because a test passes
against it.

It is a character change rather than a truncation for a different reason: a
truncated signature is refused by the base64url decode and never reaches the
verify, so a client reports a MALFORMED TOKEN rather than a BAD SIGNATURE — two
different bugs for whoever is being tested.

---

## THE SIGNATURE GOES THROUGH `helpers.signJwtAs()` AND GETS THE WHOLE TABLE

`ssf_events.js` has no signer of its own, which is what gives this family every
algorithm the rest of the service has for no code at all: RS256, the PS and ES
families, EdDSA, and the **post-quantum** ones — ML-DSA at three sizes, SLH-DSA
at two, and the six composite ML-DSA + traditional algorithms.
`ssf.signingAlgorithm` picks one.

**A SET is the document in this service most worth signing that way.** It
records that something HAPPENED, RFC 8417 section 4.1.4 forbids it to expire,
and it is therefore read long after it was written — which is the case a
harvest-now-decrypt-later argument is actually about.

`signSet()` is **asynchronous and must stay that way**: an SLH-DSA-SHAKE-128s
signature measured 14.6 seconds on this service's own thread on 2026-08-29,
during which it answers nobody. `signJwtAsAsync()` routes a post-quantum
signature to the worker pool and resolves an RS256 one in place.

### IT ALSO FOUND A DEFECT IN `common/crypto.js`, AND THAT IS WORTH KEEPING

RFC 8417 section 2.2 gives a SET `typ: "secevent+jwt"`, and a receiver that
dispatches on the media type — several do — drops one without it with no error
anybody sees. `ssf_events.js` asks for that header.

`jsonwebtoken` merges `options.header`, so the library path had always honoured
it. **The other two signers did not**: the `ownSigner` branch (EdDSA and ES256K,
the two the library refuses) and the post-quantum branch each hard-coded
`typ: 'JWT'` and ignored `options.header` entirely — so the SAME call produced a
different header depending on which algorithm was chosen, and no caller could
have seen that coming. `protectedHeaderFor()` in `common/crypto.js` is the fix
and all three paths go through it now; `alg` and `kid` are still that function's
to set, because the algorithm and the key are what was actually used.

---

## THE CONSOLE AND THE MANAGEMENT API

`/admin/ssf` and `/admin-api/ssf` reach this directory through
**`admin.setSignalsReporter()`**, the eighth slot on `admin-ui/admin.ts`, and
rule 3e's test answers yes in both directions at once: a require from
`admin.js` to `ssf.ts` would CLOSE A CYCLE (this file requires that one for the
page shell and the gate), and a require from `mgmt-api/admin_api.ts` would MOVE
ROUTES — every `/ssf` endpoint and the well-known document ahead of the
management API's own and of ldap, scim and spiffe.

The slot carries ONE object, validated whole, because a filler that installed
the reader without the action would leave that page able to LIST streams and
unable to change any of them. **It carries `deadLetters` since 2026-09-14**, the
dead-letter report for Monitoring's page — a member and not a ninth slot, see
the section on that page above.

**`action` returns a PROMISE and it is the only slot here that does.** Every
other action function in that console answers from memory; transmitting a
Security Event Token signs a JWS — possibly on the worker pool — and then POSTs
it to somebody else's endpoint. Neither can be done synchronously, and
pretending otherwise would mean the page reporting "sent" before anything had
been.

**There is deliberately no `create` action**, on the page or in the API, and
that is rule 7 read exactly rather than a gap. A stream carries a delivery
endpoint THIS SERVICE WILL DIAL, and the one place that URL may come from is a
receiver that authenticated at `POST /ssf/stream` and asked. A console form or a
management API operation that could mint one would be a second door, reached
with a credential any holder of the client secret can mint,
onto the outbound request `ssf_http.ts` spends its header bounding — so there is
no control to mirror, and the parity holds.

---

## WHAT ADDING A PROTOCOL FAMILY COST HERE

For the next person adding one, this family's full list:

* `common/config.js` — a `SSF` group, and `env/defaults.js` regenerated with
  `node env/generate_defaults.js`;
* `common/applications.js` — a row in `PROTOCOLS`, two rows in
  `SCHEMA.attributes`, two in `EDITABLE`, and **a new `deliveryAttribute` role
  in `declarationAttributes()`**: a push endpoint is where an EVENT goes, which
  is the same question `redirectAttribute` answers for a browser family and is
  not a browser redirect, and calling it one would make a table this repository
  reads literally say something false about the one attribute here with an
  outbound request behind it;
* `common/audit.js` — a `signals` category and eight actions;
* `admin-ui/admin.ts` — the eighth slot, `/admin/ssf` and its action route, a
  `SECTIONS` row with its `blurb`, and a `SETTING_HOMES` row;
* `admin-ui/crypto_metadata.ts` — a row in `FAMILIES`, whose `name` must match
  the card in `sts_metadata.ts`'s `PROTOCOLS` exactly, or the drift check
  reports it in both directions;
* `mgmt-api/admin_api.ts` — a GET and a POST with four actions;
  `mgmt-api/admin_api_spec.ts` — the `Ssf` schema;
* `sts_metadata.ts` — five `SPECS` entries, **fourteen** `ENDPOINTS` rows and a
  `PROTOCOLS` card. It was eleven until 2026-09-01, and the three that were
  missing are the ones that are not `/ssf/*` at all: `/admin/ssf`,
  `/admin-api/ssf` and `/admin-api/ssf/:action`. That is worth knowing because
  it is the shape of the mistake rather than one instance of it — a family's
  own endpoints are obvious and the CONSOLE and MANAGEMENT API rows it also
  costs are the ones a checklist forgets. `tests/vendored/sts_metadata.js` is
  what caught them, in the direction only it checks: registered and described
  nowhere;
* `oauth-oidc/oauth2.ts` — the two scopes in `scopes_supported`;
* `server.js` (now `common/protocol_stack.ts`) — the require, at 23b.

---

## AND WHAT ADDING A VOCABULARY OVER IT COST, WHICH IS THE MORE USEFUL LIST

CAEP is the first, RISC is the second, and the two lists are different sizes on
purpose — the point of the section above is that this one is short.

* `ssf/ssf_events.js` — eight rows, the four common claims written once, and
  four value types in `checkMember()`;
* `ssf/caep.ts` — the register, the state machine and the report. NEW, and a
  LIBRARY;
* `ssf/ssf.ts` — the require, the subject refusal in `transmit()`, the
  `caep.noteTransmitted()` call, `caepAutoEmit()`, the observer installation
  and the ninth admin slot's filler;
* `ssf/ssf_streams.ts` — the complex-subject coverage rule;
* `authn/authn.ts` — **`setSessionObserver()`, an INVERTED HOOK**, because
  `authn` is 8 in the require order and this directory is 23b. Plus
  `notePresented()`, spent once from `oauth-oidc/oauth2.ts`;
* `common/config.js` — a `CAEP` group of ten, and `env/defaults.js`
  regenerated;
* `common/audit.js` — four actions in the EXISTING `signals` category, because
  a CAEP event travelling is an `ssf.event.transmit` and a second category
  would have split one delivery across two filters;
* `admin-ui/admin.ts` — the ninth slot, `/admin/caep` and
  `/admin/caep-sessions` with their action routes, two `SECTIONS` rows with
  their blurbs, and a `SETTING_HOMES` row;
* `mgmt-api/admin_api.ts` — a GET and a POST with three actions;
  `mgmt-api/admin_api_spec.ts` — the `Caep` schema;
* `sts_metadata.ts` — one `SPECS` entry and **four** `ENDPOINTS` rows, of
  which the two that are easy to forget are again the CONSOLE and MANAGEMENT
  API ones rather than the protocol's own;
* `tests/caep_register.js` — the state machine and the register in process.

**THE ONE THING THAT IS NOT A FILE**, and it is the same one the eighth slot's
section warns about: the refusal sentence is `Unknown action "x". The three
are: …`, with the count from `helpers.numberWord(CAEP_CONSOLE_ACTIONS.length)`.
It is READ by `tests/vendored/admin_api.js` and
`tests/vendored/sts_admin_api_operations.js`, and a handler that writes it its
own way turns both checks off with nothing failing.

---

## THE ACTS THIS SERVICE CAN OBSERVE, AND THE EVENTS IT CANNOT CAUSE

`caep.autoEmitTypes` names the observable ones and drops anything else with a
warning, and the division is not arbitrary. This heading said THREE until two
more acts arrived: `credential-change` on 2026-09-13 (the section on
administrator credential acts below) and `assurance-level-change` on
2026-09-14.

| Act | Event | Where it is noticed |
|---|---|---|
| a session is created | `session-established` | `authn.startSession()` |
| a session is presented and honoured | `session-presented` | `authn.notePresented()`, from `oauth-oidc/oauth2.ts`'s authorization endpoint, `saml2_sso.ts`, `saml11_sso.ts`, `wsfed.ts` and `gnap/gnap_interact.ts` |
| a session ends | `session-revoked` | `authn.dropSession()`, which every sign-out door reaches |
| the same person re-authenticates on a session they hold, and `acr` moves | `assurance-level-change` | `authn.reauthenticateSession()`'s `reauthenticated` notice |

**A RE-AUTHENTICATION IS NOT A SESSION EVENT, AND THAT IS WHY THE FOURTH ROW
EXISTS.** Until 2026-09-14 the same person stepping up in the same browser went
through the change-of-person path, and a receiver was told `session-revoked`
then `session-established` about a session nobody had signed out of. Now
`observe()` emits `assurance-level-change` only when `acr` actually moved. A
re-authentication that leaves it where it was (an elapsed `max_age` answered
the same way) emits nothing and still updates the row. The scale is
**`urn:sts:acr`**, with levels spelt the way every token here carries `acr`
(`0`, `1`, `mfa`), because mapping them onto NIST's AALs would assert a
conformance nobody assessed (rcbj's choice). `caep.assuranceNamespace` stays
the default for an event emitted BY HAND. `change_direction` comes from
`oauth-oidc/step_up.ts`'s `LEVELS`, required rather than copied so that step-up
and this event cannot disagree about which way is up. `authn/CLAUDE.md`, *What
an authenticated identity is here*, carries the design and the probe.

*(Superseded, in stages: this paragraph said token claims, device compliance,
risk level and most credential changes had no act here. #145 gave the first
and last one, #62 the risk level, and #164 device compliance — so every CAEP
type now fires on its own, and `/admin/caep`'s hand emission is for an event
on demand. A row in `caep.autoEmitTypes` naming something that is not one of
`AUTO_ACTS` is still dropped with a warning rather than honoured.)*

**THE FIRST PRESENTATION OF A NEW SESSION IS NOT REPORTED**, and without that
rule the feature would be noise. Every sign-in here ends with the browser
coming back to the authorization endpoint, which *is* a presentation — so a
`session-established` and a `session-presented` would arrive milliseconds
apart, every time, and the event that is supposed to mean *single sign-on
happened* would mean nothing. `startSession()` sets a flag and
`notePresented()` spends it, which is exact rather than a time window.

---

## THE REGISTER OUTLIVES THE SESSION, ON PURPOSE

`authn.js` forgets a session the moment it is signed out. `caep.ts` does not: a
row whose state is `revoked` is the **only remaining evidence** that the
session existed and was revoked, and *"did anything go out when I signed that
person out?"* is the entire question `/admin/caep-sessions` answers.
`caep.maxSessionsTracked` caps it and the oldest goes first.

The two can also disagree the other way — a session this service still holds
whose row says `revoked` means somebody emitted a revocation by hand — and the
page says so rather than reconciling, because which of the two is wrong is
exactly the question.

**BOTH REGISTERS ARE PER TRUST REALM AND PERSISTED WHERE MINTED STATE IS, SINCE
2026-09-12, AND BOTH WERE ONE `new Map()` FOR THE PROCESS.** The streams they
count against have been per realm since this family arrived and the session
store and the directory they describe are too, so every realm's
`/admin/caep-sessions` listed every realm's sessions and a deletion in `acme`'s
directory put a `purged` row on the default realm's `/admin/risc-accounts`. They
are `realms.map({ persist: 'caep.register' })` and `'risc.register'`, merged by
replacement (a row is whole-valued), and the cap is per realm. **The ambient
realm is the right one on every path**: `observe()` is reached from inside the
request or the realm-scoped expiry sweep, `noteTransmitted()` from `transmit()`,
and a directory write on the LDAP socket runs inside
`realms.run(realmFor(dn))`. **Each file has a `touch()`**, because the state
machines edit a row already in the map and `realms.map()` journals only a
`set()` — without it product mode would write every row as it was created.
`tests/realm_isolation.js` holds both registers both ways round, across a purge,
and against a real persistence observer.

---

## THE COUNTS ARE NOT THE LIST

Each row carries `counts` (per event type, never forgotten) and `events` (a
ring of the last twenty-five). They answer different questions — *how many
session-revoked have gone out about this person* and *what were the last few
jtis* — and a page that answered the first out of the second would say
twenty-five where there were thirty. `tests/caep_register.js` sends thirty and
asserts both.

**AND ONE THING THAT IS NOT A FILE: THE REFUSAL SENTENCE HAS TO BE SPELLED THE
WAY EVERY OTHER ACTION HANDLER SPELLS IT.** `consoleAction()` answered an
unknown action with `"x" is not an action on this resource. The ones that are:
…` until 2026-09-01, which reads perfectly well and is INVISIBLE to the two
checks that depend on it: `tests/vendored/admin_api.js` requires
`/unknown action/i` before it parses the list — that is the console/API parity
check, so `/ssf`'s four actions were being compared against nothing — and
`tests/vendored/sts_admin_api_operations.js` matches `Unknown action "x".
<count phrase>: <list>.` across every documented resource, which is what caught
it. It is `Unknown action "x". The six are: …` now (four then), with the count
coming from `CONSOLE_ACTIONS.length` through `helpers.numberWord()` rather than
from a word typed beside it. **This sentence is not prose — it is READ**, and
that is the whole reason it is worth a paragraph in this file.

---

## The CAEP page's session picker is a SEARCH, not a `<select>` (2026-09-03)

`/admin/caep`'s *Emit one by hand* form chose its session from a dropdown built
out of the whole register. That register **grows by one row per sign-in for the
life of the process and never shrinks** — `caep.ts` keeps a row after the
session is signed out, deliberately, because the row is the evidence it existed
and was revoked — so a console left running for an afternoon of testing had a
dropdown of several hundred options, each labelled with a 24-character random
identifier and sorted by nothing a reader knows.

It is `chooserPane()` now, the same control `/admin/delegation` uses for its
application and user searches, with the same twenty-a-page and the same
clamping of a stale offset. Three things about it are decisions rather than
mechanics:

* **The search is over the PERSON and the results are SESSIONS.** Nobody knows
  a session identifier by heart — it is random, and it is the thing they came
  here to find — but everybody knows who they signed in as. So the searchable
  names are the username and the subject (and the session id, for a reader who
  has one from a log), and the result line carries the session with the
  **protocol that minted it** and its state beside it.
* **Only LIVE sessions are offered.** A revoked row stays in the register and
  stays on `/admin/caep-sessions`, where it is evidence; it is not offered here
  because the model's one hard refusal is a `session-presented` about a session
  already revoked, and a control that lists rows the very next click would be
  refused for is one that invites the mistake.
* **The form does not draw at all until a session is picked.** A CAEP event
  names a session; there is nothing for the form to be *about* until one is
  chosen, and a `?session=` naming a row that is gone says so rather than
  posting an identifier the register will not recognise.

`sessq`, `sessfrom` and `session` are in `LIST_PARAMS` for `/admin/caep`, so a
reader who searched a username, paged to the second twenty and picked a session
keeps all three across the reload that pressing **Emit** causes.

---

## `initiating_entity` IS NOT ALWAYS `admin` OR `user` (2026-09-04)

`observe()` chose between those two on a `revoked` act — `admin` when an
administrator did it, `user` otherwise. A SESSION THAT EXPIRED is neither: a
lifetime this service configured ran out, nobody did anything, and the event
would have gone out claiming the person signed themselves out. That is not
vague, it is false, and a receiver acting on `reason_user` would have shown them
a sentence about a sign-out that never happened.

The notice's own `initiatingEntity` now wins where it has one, validated against
CAEP section 2's four words, and `authn.js`'s expiry gives `policy` — the word
for a policy evaluation, where `system` is a maintenance activity and the other
two name a person. `reasonForUser()` takes the notice too, so an expiry says
"Your session expired" rather than "You have been signed out".

**IT IS ALSO THE FIRST TIME `session-revoked` FIRES WITH NO REQUEST BEHIND IT.**
The expiry sweep in `authn.js` runs on a timer, inside each realm, so
`issuerFor(null)` is what builds the subject — which is why that function must
go on answering without one. `authn/CLAUDE.md` argues the sweep.

**THE `admin` BRANCH WAS UNREACHABLE UNTIL THE SAME DAY, AND THAT IS THE OTHER
HALF OF THIS.** `dropSession()` decides between `admin` and `user` by testing
the `via` it is handed for `admin` or `console`, and every door went through
`logout.ts`'s session family, which passed one hard-coded string. So a support
desk ending somebody's session from `/admin/logout`, the Revoke button on
`/admin/sessions` and the management API all emitted an event saying **the
person had signed themselves out** — the one distinction this member exists to
draw, got wrong in the direction that matters, with no symptom anywhere: the
event is conforming and the value is a legal one. `logout/logout.ts` carries the
caller's own words on the context now, and the same phrase reaches
`reason_admin`, so the two cannot disagree about who ended a session.
`tests/caep_initiating_entity.js` is the guard, mutation-tested against five
mutants.

## PER-RECEIVER STATISTICS, AND THE COUNTER THEY NEEDED (2026-09-04)

`caepApplications()` answers what this transmitter has said to each RECEIVER
across every session — the third table on `/admin/caep-sessions`, the
`applications` member of the CAEP report, and therefore the same document
`/admin/caep` and both management API reads answer with.

**IT NEEDED A NEW COUNTER AND COULD NOT BORROW ONE.** The stream's `counters`
are about the PIPE — queued, delivered, failed, acknowledged — and none of them
knows an event TYPE. The register knows types and counts them PER SESSION,
keeping only the last twenty-five events per row, so summing its rings would
have been right until the first busy session and wrong afterwards. So
`ssf_streams.ts` gained `eventCounts` on the record, incremented by
`countEvent()` from `transmit()` beside `caep.noteTransmitted()` — at the same
moment and for that function's reason: the count is of what was SAID, so it
moves when the SET is built and queued, and a poll stream nobody has polled yet
still shows what is waiting for it.

**THE JOIN IS `createdBy` AND NOT `aud`, AND THE OBVIOUS ONE IS WRONG.**
`applications.js`'s `ssf` row says a receiver's identifier is "the `aud` those
SETs carry", and that prose is loose: `normaliseAudience()` requires `aud` and
deliberately never defaults it to the authenticated caller, while
`applications.seen()` files the entry under the PRINCIPAL. They coincide for a
receiver that sends its own name and diverge for one that does not — which is
legitimate — so the table carries both and says "the same" where they agree.

**TWO ROWS ARE THE POINT OF THE TABLE RATHER THAN EDGE CASES.** An application
with NO STREAM is the commonest state a receiver under test is in, and a list
that showed only receivers with streams would answer "where is my application"
with silence. And a row for streams belonging to no application at all is what
a stream agreed unauthenticated produces — no principal, nothing recorded, and the events
are real; dropping them would make this table's totals disagree with the two
above it.

## THE 2026-09-12 AUDIT OF HARD-CODED VALUES, AND WHAT IT CHANGED HERE

`tests/ssf_spiffe_scim_hardening.js` holds every item below.

* **THE REALM PREFIX WAS ADDED TWICE.** `helpers.baseUrlOf()` already carries
  it, and `ssf.ts` appended `realms.currentPrefix()` again for the issuer, every
  endpoint in the metadata, `jwks_uri` and `metadataUrl`, as did the seeded
  streams' issuer in `ssf_receivers.ts`. In any realm but the default one a
  receiver discovered `…/realm/acme/realm/acme/ssf/stream` and matched every
  SET's `iss` against a string no SET carried. Fixed in every mode.
* **THE ISSUER WITH NO REQUEST** was `baseUrlOf(null)` — `http://localhost:<port>`
  whatever `global.https` said — for a seeded stream and for the CAEP expiry
  sweep. `ssf_http.ts`'s `ownBaseUrl()` is `global.publicBaseUrl` where set,
  else the loopback origin in the listener's own scheme, prefixed once; and
  `transmitterIssuer()` beside it is now the ONE computation `ssf.ts` and
  `ssf_receivers.ts` share.
* **A CONFIGURED `ssf.issuer` IS PER REALM.** It was returned verbatim in every
  realm — two transmitters under one name. A value the REALM carries is used as
  it stands; a process-wide one gets the realm's prefix. Not in `realms.js`'s
  NAMED_BY_REALM, which seeds at creation and would miss every realm created
  before the setting was pinned.
* **THE INTERNAL PUSH DIALLED `127.0.0.1` LITERALLY**, which reaches nothing when
  `global.host` binds one interface or IPv6 only. `loopbackOrigin()` uses
  `helpers.loopbackHost()` and `hostForUrl()`.
* **SUBJECTS INVENTED ADDRESSES.** `subjectForUser()` knew only a username, so
  an `email` subject was `<name>@example.com` and a DID `did:example:<name>`
  even where RISC's row held a real `mail`. It takes `facts` (`mail`, `phone`,
  `did`) and a real value wins in both modes; where there is none,
  `mode.inventsClaimValues()` decides — development invents as before, product
  falls back to the issuer/subject pair. RISC's two identifier events, whose
  subject MUST be an address or a number, get NO subject in product when there
  is neither, and `transmit()` refuses them. The portal filter's invented-address
  match is development-only for the same reason.
* **A FOREIGN RS256 SET READ "INVALID".** `publicKeyForHeader()` sent every
  RS256 SET to this service's RSA key whatever its `kid`; it matches on the
  `kid` and falls back to the algorithm only when there is none, so a SET
  somebody else signed is *not verifiable here*.
* **SETTINGS FOR LITERALS**: `ssf.pushMaxResponseBytes` (65536),
  `ssf.pushRetries` (0), `ssf.pushRetryDelayMs` (1000), `ssf.authBasic` (true),
  `caep.eventsPerSession` (25), `caep.historyPerSession` (10),
  `risc.eventsPerAccount` (25), `risc.historyPerAccount` (10).
  `risc.EVENTS_PER_ACCOUNT` is a getter over the setting now.

**Left alone and said so**: the two internal surfaces' audiences
(`sts-admin-console`, `sts-user-portal`) and receive paths. They are the seeded
client ids and the routes the surfaces register; deriving them from
`common/oidc_rp.ts`'s table would put a require from this directory into a
module the portal loads just after `authn` (8) for two strings that change
only with those files.

## CREDENTIAL CHANGES FROM THE ADMIN DOORS: `account_signals.ts` (2026-09-13)

A person's `/admin/users` page gained controls that reset passwords, issue
reset links and remove second factors, and each owes a signal. The acts are:

| Door | CAEP `credential-change` | RISC |
|---|---|---|
| reset-password, set-password | `password`, `update` | reset only: `account-credential-change-required` |
| issue-password-reset | `password`, `revoke` (if one was removed) | `account-credential-change-required` |
| `/portal/reset-password` completed | `password`, `create`, initiated by `user` | — |
| disable-primary-keys, clear-key | `fido2-roaming`, `delete`, per key, label as `friendly_name` | — |
| disable-mfa | `app` and `fido2-roaming`, `delete`, per credential | `recovery-information-changed` if codes went |
| clear-totp | `app`, `delete` | — |
| clear-backup-codes | — | `recovery-information-changed` |

**`ssf/account_signals.ts` IS A LIBRARY THAT READS `ssf.ts` OUT OF
`require.cache`**, because the doors are at 18 (the actions layer) and just
after `authn`, 8 (the portal), and a require of `ssf.ts` from either would
register every `/ssf` route ahead of theirs and close a cycle through the
console. Not a slot: there is no require at all, only a cache lookup —
`admin-core/protocol_endpoints.ts`'s arrangement. A process that never loaded
SSF gets a no-op that says so. Nothing in it throws and callers do not await it: a slow receiver must not hold a page,
and a failed emission must not undo a credential change already written.

**`ssf.ts` gained `emitCredentialChange()` and `emitRiscAccountAct()`**
(`STS-SSF-0090`, `-0091`). The first builds the SET through `caep.buildPayload`
and sends it with a complex user subject (`iss_sub`) to the streams
that asked for the type and cover the person; it obeys `caep.autoEmitTypes`
through `caep.autoEmitActs()`, which gained `credential`. The second goes
through `risc.observeAct()` — `observe()`'s loop extracted into `dueForActs()`,
so an admin act meets the same `risc.autoEmitTypes` switch and the same opt-out
gate a directory write does — and `sendOneRiscEvent()`. `risc.ts`'s
`applyActLocally()`, `reasonFor()` and `reasonForUser()` know the two new acts.
**Both `autoEmitTypes` defaults name the new types**, so an unedited service
sends them; a deployment that pinned the old list sends none.

**The key credential type is `fido2-roaming` for every key**, because a stored
key records no authenticator attachment, and the label goes out as
`friendly_name` so two keys can be told apart. **The portal's own credential
pages and the LDAP socket emit nothing**, which is the scope that was asked for
(the admin user-page doors and the reset link), not a claim that nothing else
changes a credential. *(Both superseded by #145, below.)*

## EVERY DOOR, AND TOKEN-CLAIMS-CHANGE FROM THE DIRECTORY (#145, 2026-09-22)

**`credential-change` now goes out wherever a person's credential changes.**
Where one function is the only way to change a kind of credential, the event is
sent THERE, so no door can miss it:
* `common/person_assertions.js` `write()` and `clear()`, for signing key pairs;
* `common/cert_enrollment.ts` `issue()` and `revokeEnrolled()`, for ACME, EST
  and SCEP;
* `common/tls_client_certificates.js` `issue()` and `revoke()`;
* `oid4vc/vc_issued.ts` `record()` and `disown()`, as `verifiable-credential`.

Passwords, security keys and authenticator apps are written through
`common/credentials.ts` from many doors, and the admin doors already emitted
with their own reasons. So those are sent PER DOOR: the portal (password change,
activation, TOTP, keys), sign-in (a forced password change, MFA setup, a key
registered), an LDAP add or modify of `userPassword` (`notePasswordWritten()`,
where the bound DN decides `user` against `admin`), a person created with a
password, and `/admin/pki`'s revoke of a person's certificate (the holder read
from the authority's issued register). **A new door that changes a credential
through `credentials.ts` owes its own call.** A central hook there would
double-send every admin door.

**Security keys record `attachment` and `aaguid` at enrolment** (they were
handed to `addKey()` and dropped). `accountSignals.keyCredentialType(record)`
makes `platform` into `fido2-platform` and anything else `fido2-roaming`. The
AAGUID is kept as a UUID string (`Credentials.aaguidString()`), and all zeros
means none. A key stored before this change has neither and reads as it always
did; nothing is migrated.

**A certificate goes out as `x509` with `x509_issuer` and `x509_serial`**,
through `accountSignals.certificateChanged({ pem })`. That call uses
`common/crypto.js`'s `certificateIdentifiers()`: the issuer as an RFC 4514
string, and the serial as the lower-case hex the PKI registers use. Only a
PERSON's certificate is sent; an application has no CAEP subject here.
**Recovery codes have no CAEP type**, so the portal's confirm sends RISC's
`recovery-information-changed`, as the console's clear does.

**`token-claims-change` from the directory.** The observer `ldap_server.js`
calls is `ssf.ts`'s `directoryChanged()` now:
* a person's own write still goes to `riscAutoEmit()`;
* both kinds go to `claimsAutoEmit()`.

The directory also reports a group's membership change, per affected PERSON,
as `kind: 'membership'` (`noteMembershipChange()`: `putEntry()`, the LDAP
modify, delete and rename of a group, `deleteGroupEntry()`). RISC never sees
that kind.

`caep.claimsChangeFor()` reads which claims moved: catalogue attributes by
their claim names, `null` for an emptied one, and the groups claim as the whole
new list for a membership or `memberOf` change. `claimsAutoEmit()` asks the
cheap questions first (SSF on, the act chosen, a stream that takes the type),
decides the rest on a promise so a bulk group write returns at once, and sends
only when `admin_stats.holdsLiveIssuance()` finds a valid access, ID or refresh
token or an unexpired SAML assertion for the person. **That check comes BEFORE
`claimsChangeFor()`**, because the groups claim rebuilds the group index every
group write invalidates. With the order reversed a SCIM membership in the bulk
load cost 21.8 ms against 11.6 ms before #145; in this order, 10.5 ms. The subject is the person
(`iss_sub`): the change is to every token they hold. `caep.autoEmitTypes` names
it by default.

**`fp_ua`** on `session-established` and `session-presented` is
`crypto.userAgentFingerprint()`, the base64url SHA-256 of `User-Agent`. It is a
fingerprint, as CAEP defines the member, and not the header.

**Not here:**
* `device-compliance-change` is emitted by the device register (#164)
  whenever a device's compliance changes.
* Acting on a RECEIVED event: the console's and portal's receivers (#62)
  and foreign transmitters (#153), a received `device-compliance-change`
  included (below).

## THIS REALM AS A RECEIVER OF A FOREIGN TRANSMITTER (2026-09-26, #153)

rcbj's answers were every recommendation: only a transmitter an
administrator registers; both poll and push; act on session-revoked,
credential-change and account disabled or enabled; map subjects through a
federation relationship. `ssf/ssf_transmitters.ts` carries the argument in
its header. The points a reader of this directory needs:

* **Registration is by ISSUER.** The configuration document is fetched from
  `/.well-known/ssf-configuration` inserted before the issuer's path (section
  7), and it must name that issuer, a `jwks_uri` and a
  `configuration_endpoint`. Every address dialled afterwards comes from that
  document: stream management, status, subjects, verification and the poll
  endpoint the stream names. They go through
  `federation_http.fetchPublished()`, which gained `method`, `headers` and
  `body` for them. Its bounds are unchanged: internal addresses refused in
  product mode, the connection pinned, no redirect, a cap. It is the fifteenth
  row of root CLAUDE.md's "Dial a URL a CALLER supplied" index. It reverses
  this file's *no create stream on the console* rule for this direction only:
  there the address would be one a console user typed for us to deliver to,
  and here it is the transmitter's own.
* **This realm authenticates to the transmitter** by client credentials at
  an administrator-named token endpoint (token cached per process, short),
  or by a pasted bearer. Secrets live in the persisted register, sealed at
  rest like every minted row, and no page or answer shows them.
* **Push** is `POST /ssf/transmitters/{id}/push`. The Authorization header
  this realm gave the transmitter at stream creation is kept as its digest
  and compared in constant time. **Poll** is the `ssf.foreign-poll` cluster
  job, per realm. What was received is acknowledged (`ack`) or refused
  (`setErrs`) on the next request, with one more request after the last
  round to acknowledge it.
* **Verification** is done here, not by `ssf_events.verifySet()`, which only
  knows this realm's keys. The signature is checked against the
  transmitter's `jwks_uri`, reusing `oauth-oidc/client_jwks.js`'s cache, with
  the kid named or else each key and the asymmetric algorithms named. Then
  `typ` must be secevent+jwt, `iss` the transmitter's, and `aud` the
  stream's. A `jti` is accepted once, and the inbox that holds it is also the
  history. In product an unverified SET is refused (`invalid_key`). In
  development it is recorded and acted on in no way.
* **Reactions** come from the `signal-response` policy, asked with the
  surface `foreign:<id>`, and there are three new actions:
  * `signal-end-person-sessions`: a global sign-out of the person here;
  * `signal-disable-account` (`account_state.setDisabled`, which re-emits
    RISC to this realm's own receivers);
  * `signal-enable-account`, only for a lock this transmitter's own event put
    there (`ssf.foreignLocks`).

  The template's foreign rules require that surface prefix, so the console's
  and portal's receivers never match them. Development only records what it
  would do, unless `ssf.actOnSignalsInDevelopment` is on.
* **Subjects.** An `iss_sub` with the relationship's `fedPeer` is the ONE
  person whose `federationLink` holds it. An `email` subject is matched only
  where the relationship sets `fedSignalEmailMatch`, which is off by default:
  an address is not an identifier. Anything else names nobody, and the SET is
  recorded. A `complex` subject's `user` member is what is mapped.
* **CAEP device-compliance-change** goes to `devices.setCompliance()` when
  the device register offers it (#164). The device is found by the subject's
  `sub` or a key thumbprint.

## A RENAMED ACCOUNT KEEPS ITS RISC ROW (2026-09-14)

The RISC register is keyed by the account's name, and a rename reaches `observe()` as an
update naming the NEW one. Where no row holds that name, the entry's subject (off the
snapshot) finds the row already recorded under the old name; it is re-keyed, its counts
and state move with it, and the old name joins `formerIdentifiers` so an event naming it
still matches. `tests/stable_subject.js` D13.

## A SECOND-FACTOR PERSON'S BASIC PASSWORD, AND APP PASSWORDS OVER CAEP (2026-09-22, #101)

`attemptBasic()` passes `door: 'ssf'`, so in product a person who holds or must
hold a second factor is refused their own password with the one `STS-SSF-0009`
401 a wrong password gets, and uses an app password scoped to `ssf`.
`authn/CLAUDE.md` owns the rule. Making or revoking an app password — on
`/portal/app-passwords` (`initiating_entity` `user`) or on `/admin/users` and
`/admin-api` (`admin`) — is a `credential-change` (`password`, `create` or
`revoke`, the app password's name as `friendly_name`) through
`account_signals.ts`.

## A DEVICE'S EVENTS (#164 phases 3 and 4, 2026-09-26)

`common/devices.ts` is the device register's FUNNEL — the console, `/admin-api`,
the MDM feed, the portal, EST and SCEP and Native SSO all change a device
through it — so it is where a device's events are sent, through
`account_signals.ts`'s `deviceEvent()` and `sessionsRevoked()` (the same
`require.cache` arrangement) to `ssf.ts`'s `emitDeviceEvent()` and
`emitRiscAccountAct()`:

| Act | Event | Notes |
|---|---|---|
| compliance changes | CAEP `device-compliance-change` (act `compliance`, the eighth `AUTO_ACTS` row) | CAEP section 3.5.1 has TWO values, so `unknown` is sent as `not-compliant` and an event goes out only when the sent value moves |
| risk level changes | CAEP `risk-level-change`, `principal` `DEVICE` (act `risk`) | `devices.setRiskLevel()`, which #164 phase 5 calls; a compromise raises it to `HIGH`; `previous_level` only where there was one |
| a key added, re-issued, removed; a Native SSO secret issued, revoked | CAEP `credential-change` (act `credential`) | `x509`, `fido2-platform`/`fido2-roaming`, and two URNs of our own for a JWK key and a device_secret (#236) |
| a person's device compromised | RISC `credential-compromise` per kind of credential it held, and `sessions-revoked` | complex subject: the account AND the device |
| a person's device removed | RISC `sessions-revoked` | the same subject |

**THE DEVICE IS NAMED `iss_sub`**: this realm's issuer and the device's id,
the form CAEP section 3.5.2's own example uses. The id is unique only within
the realm that assigned it, which is exactly what an issuer-scoped identifier
says; `opaque` would say nothing about whose it is, and the
`urn:sts:device:<id>` a device certificate carries names no issuer either.
`caep.subjectFor()` names the session events' device the same way (it was
`opaque` and never filled until #164), from the `registeredDevice` on the
session's latest authentication event, so a receiver that added the device
gets its session events too.

**RISC'S SUBJECT IS COMPLEX FOR THESE TWO AND NO OTHER**, and `risc.ts`'s
subject section still holds: a complex subject on `account-disabled` would
mean nothing. On `sessions-revoked` the device member is what makes the
deprecated event TRUE — "all the sessions for the account" becomes every
session of the account on that device, which is what was ended; each ended
session also sends CAEP `session-revoked`, which RISC 1.0 section 2.11 points
at, and `risc.autoEmitTypes` can drop the RISC one. `accountIdOf()` reads a
complex subject's `user` member so the register still counts the event.

**STREAM SUBJECTS MATCH BY SSF 1.0 SECTION 8.1.3.1** (`complexSubjectsMatch()`
in `ssf_streams.ts`): a complex subject a receiver ADDED matches an event's
complex subject when every member both define is identical — and, a condition
the section's letter omits and all its examples meet, at least one member is
defined by both. Without it `{ device }` would match every session event of
every person, none of which names a device.

**What a compromise and a removal CAUSE** — sessions ended, certificates
revoked, the secret revoked — is `devices.ts`'s header; this directory only
reports it.

**A PAIRWISE OR EPHEMERAL STREAM OWNER IS TOLD THE DEVICE AS ITS TOKENS ARE
(#164 phase 6).** `subjectForReceiver()` has rewritten the `user` member to
the owner client's `sub` since #149. It now rewrites a person's `device` the
same way, through `pairwise_subjects.deviceIdFor()`:
* a pairwise client is told the sector-derived id its tokens' `device_id`
  carries;
* an ephemeral client is told no device, and the member is dropped;
* a public client is told the register's id.

An application's device has no `user` member and is sent as it is: pairwise
subjects protect End-Users. `oauth-oidc/CLAUDE.md` 3bo argues the claim.

**RISK SCORING SETS A DEVICE'S LEVEL** (#164 phase 5): after a sign-in the
person's own device proved, the device takes that sign-in's level, so the
`risk-level-change` with principal `DEVICE` above now fires on risk as well
as on a compromise (`risk/CLAUDE.md`, *The registered device*).

