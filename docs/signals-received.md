---
title: Signals received
nav_order: 12
---

# The console and the portal are Shared Signals receivers

This service is a Shared Signals **transmitter**: something happens, it builds a
Security Event Token, and it delivers it to whichever receivers agreed a stream
that covers it. Two of those receivers are **this service's own
two applications** — the admin console at `/admin` and the user portal at
`/portal`.

Each has a stream of its own, seeded when the service starts, asking for **every
CAEP event type and every RISC event type**. Each collects what its stream
holds over RFC 8936 poll, from this service's own `/ssf/poll`, every
`ssf.internalPollMs` (a second by default). And each draws what arrived on a
page:

| Page | Who it is for | What it shows |
|---|---|---|
| `/admin/signals` | an operator | every event delivered in the trust realm being read |
| `/portal/signals` | a person | only the events whose subject is them |

There is nothing to configure to get this. If you sign in to this service and
then open either page, what you did is on it.

## Why this is a real receiver and not a page reading a log

The console could have drawn these events by reading the registers this service
already keeps — `/admin/caep-sessions` and `/admin/risc-accounts` are exactly
that, and they were here first. It does not, and the difference is the point.

A receiver is something a **stream was agreed with**, that is **handed signed
documents**, that has to **verify the signature** and **find its own name in
the audience** before it believes anything. Delivering the event to the page by a
function call inside this process would have skipped every one of those steps
and left the part that merely looks run.

So the delivery is a real HTTP request. Each receiver dials this service's own
poll endpoint, on the loopback interface, with its TLS certificate pinned,
presenting a credential this service derives for that receiver and gives to
nothing else — and takes up to `ssf.pollMaxEvents` SETs to a request. It
checks that each SET is typed `secevent+jwt`, that its issuer
is the stream's and that its audience names the receiver, and verifies the
signature, exactly as a receiver you wrote would have to (SSF 1.0 sections
4.1.1 and 4.1.6). It acknowledges each one on its next request; a SET that
fails one of those checks is still listed, marked as refused, and is sent back
in `setErrs` (RFC 8936 section 2.2) so that it leaves the queue.

**Until #771 (2026-10-20) it was RFC 8935 push**: the transmitter POSTed every
SET to the receiver's own endpoint, one request each. Under a load of password
changes — each one sends CAEP `credential-change` to both surfaces — that was
two loopback requests per change. A SET now waits up to one poll interval
before either surface sees it and acts on it. The two receive endpoints,
`/admin/signals/receive` and `/portal/signals/receive`, still take a push for a
stream an operator sets back to push at `/admin/ssf`.

What a row keeps is the SET's header and claims and the verdict on it, with
the SET itself named by `tokenDigest`, its SHA-256 in base64url. The signed
token is not kept, so neither page nor `/admin-api` can show it. To match a
row against a SET a transmitter logged, hash that SET.

**The consequence worth knowing:** these two pages are the only surfaces here
that go EMPTY when delivery is broken. `/admin/ssf` will still show the streams,
`/admin/caep-sessions` will still show the sessions, and both will be perfectly
correct while nothing is reaching anybody. If you are testing a Shared Signals
integration, an empty `/admin/signals` is real evidence and a full
`/admin/caep-sessions` is not.

## An empty page has five causes and only one of them is "nothing happened"

Both pages say which apply, above the table, rather than leaving you to guess.
In the order to check them:

| Cause | What to do |
|---|---|
| `ssf.enabled` is off | this service is not a transmitter at all — nothing is built, queued or sent |
| `ssf.internalReceivers` is off | the two streams are not seeded; everything else about Shared Signals is unaffected |
| the stream was deleted | it is an **ordinary** stream: pause, narrow or delete it at `/admin/ssf` and it stays that way until a restart |
| `ssf.internalPollMs` is 0 | the `ssf.internal-poll` job is off, so neither surface collects. Events queue on the stream and are visible at `/admin/ssf`, and reach neither page |
| `caep.enabled` or `risc.enabled` is off | that vocabulary's types are not supported, so they are not delivered however the stream asked |

The console's copy of this names the settings. The portal's does not — somebody
reading their own account page cannot change any of them, so it says the portal
is not being told everything and points at the console.

## An event that was sent and not delivered

A push that fails does not disappear. After `ssf.pushRetries` it goes to the
stream's **dead-letter queue**, with the reason, the error code and whatever the
receiver answered, and it is kept for `ssf.deadLetterRetentionS` (an hour by
default). Every trust realm has dead-letter queues of its own. A stream whose
pushes have all failed for `ssf.deadStreamTimeoutS` is declared **dead**:
nothing more is pushed to it, and one letter is pushed as a probe each period
until a delivery revives it.

**Monitoring → Shared Signals → Dead letters** (`/admin/ssf/dead-letters`)
counts them for the realm you are reading:

| Section | What it answers |
|---|---|
| When | a chart of letters over the retention window, with the same numbers as a table |
| Why | the four causes — *push failed*, *backlog full* (`STS-SSF-0092`), *waiting when declared dead* (`STS-SSF-0093`), *sent to a dead stream* (`STS-SSF-0096`) — then by error code, by the receiver's HTTP status and by event type |
| Streams | which streams are dead, half-open (one more failure kills them) or failing, and how many letters each holds |
| The letters | every letter, searchable by jti, code, event, status or reason; no token is shown |
| This process | the push cap and the recent sweeps of the process that answered |

Two numbers on it belong to **one process**, and the page says which. The push
cap (`ssf.pushConcurrency` in flight, `ssf.pushBacklog` waiting) is per process
and shared by every realm, so a burst in one realm can dead-letter another
realm's events with `STS-SSF-0092`. With request workers turned on, two refreshes
can be answered by two processes.

The page changes nothing. To revive a dead stream or drop its letters, follow
the stream's link to its card at `/admin/ssf`. `GET
/admin-api/ssf/dead-letters` answers the same thing as JSON, narrowed by `dlq`,
`dlstream` and `dlcause` and paged by `lettersPage`. The streams table is paged
too, by `streamsPage`; `dlstream` and `dlcause` narrow it as they narrow the
letters.

## What a person sees, and what they do not

`/portal/signals` shows a person their own security activity: a session
established, a session presented, a session revoked, an account disabled or
enabled, an identifier changed.

One stream delivers events about **everybody** the portal serves — that is what
a receiver is — so the narrowing to one person happens when the page is drawn,
from the session and from nothing else. It **fails closed**: where an event
names somebody in a way this service cannot match to an account (a phone number,
for instance), it is left out rather than guessed at. So it is possible for
something about you to be missing from that page. It is not possible for
something about somebody else to be on it.

There is **no Clear button on the portal's page**, deliberately: a record of
what was said about an account would be worth nothing if the account's owner
could empty it. The console has one for its own inbox, and it drops only what is
held — the stream goes on delivering, and the audit log's record of every
delivery cannot be cleared at all.

## What the console and the portal do with a signal

A receiver acts on what it is told. When the console or the portal receives an
event, it can end **its own** sessions for the person the event names:

- the console signs that person out of the console;
- the portal signs that person out of the portal.

It never ends the identity provider's session. That session belongs to the
transmitter, which has usually ended it already.

The `signal-response` XACML policy decides which events do this. By default
they are:

- CAEP `session-revoked` and `credential-change`;
- RISC `account-disabled`, `account-purged`,
  `account-credential-change-required`, `sessions-revoked` and
  `credential-compromise`;
- a CAEP `risk-level-change` to `HIGH`.

You can change the list in the policy without a new release (see
[XACML](xacml.md)).

These rules can't be relaxed by any policy:

- **An event is acted on only if its signature verified**, whatever
  `ssf.receiveRequireSignature` says about accepting it, and only if it
  passed every other check. An unverified event is recorded and nothing
  else happens.
- **Who the event is about is decided the same way the portal's page decides
  it**, and it fails closed: an identifier this service can't match to the
  person holding a session ends nothing.
- **Development mode records what it would have done** and ends nothing,
  unless `ssf.actOnSignalsInDevelopment` is on. Product mode acts.

Each row on `/admin/signals` and `/portal/signals` says what was done with
that event.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `ssf.internalReceivers` | `true` | seed the two streams. Restart to apply |
| `ssf.actOnSignalsInDevelopment` | `false` | end the surfaces' own sessions on a received signal in development mode too; product always does |
| `xacml.signalResponsePolicy` | `signal-response` | the policy asked which received events end them |
| `ssf.internalPollMs` | `1000` | how often the two collect what their streams hold (the `ssf.internal-poll` scheduler job); 0 turns it off |
| `ssf.pollMaxEvents` | `20` | the most SETs one poll answers |
| `ssf.maxReceivedEvents` | `200` | how many delivered events each inbox keeps, per realm |

`ssf.pushDelivery`, `ssf.pushAllowedHosts`, `ssf.pushAllowHttp` and
`ssf.pushSkipTlsVerification` do **not** apply to these two: a poll is not a
push, the address is this process's own, computed rather than named by anybody,
and a request that does not leave the host is not a Security Event Token in
transit. Every other receiver is bound by them.

## Over the management API

`GET /admin-api/signals` is the console's page as JSON — the stream's state, the
reasons nothing would arrive, and the delivered events — and `POST
/admin-api/signals/clear` is its Clear. The portal's page has no management API
operation: it is a person's own page, narrowed by their session, and the
console's view already answers everything an operator can ask.

See also [CAEP events](caep-events.md) for what makes each session event fire,
and [what is not checked](what-is-not-checked.md).
