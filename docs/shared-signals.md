---
title: Shared Signals
---

# Shared Signals (SSF, CAEP and RISC)

iya-sts is a **Shared Signals transmitter**
([OpenID SSF 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)),
and a small receiver as well. A receiver agrees a **stream** with it, and it
then delivers a **Security Event Token**
([RFC 8417](https://www.rfc-editor.org/rfc/rfc8417)) when something happens,
by push ([RFC 8935](https://www.rfc-editor.org/rfc/rfc8935)) or poll
([RFC 8936](https://www.rfc-editor.org/rfc/rfc8936)). Subjects use the
[RFC 9493](https://www.rfc-editor.org/rfc/rfc9493) formats. Both vocabularies
that run over SSF are implemented:
[CAEP 1.0](https://openid.net/specs/openid-caep-1_0.html) (what happened to a
**session**) and [RISC 1.0](https://openid.net/specs/openid-risc-1_0.html)
(what happened to an **account**). Every trust realm has its own transmitter,
streams, queues and registers.

Every other protocol here answers a request. This is the one that **talks
back**: it sends an event that nobody asked for, at the moment the event
happens.

## Features

### SSF is the pipe, not the vocabulary

SSF covers how a receiver and a transmitter agree a stream, who the events on
it are about, what the events travel in and how they are delivered. It defines
only two events of its own, and both are about the pipe:

* **verification**: the receiver asked whether the stream is alive, and the
  answer comes back along the normal delivery path. This is the only
  end-to-end test a stream has. A 200 from the management API means the
  configuration was accepted. It says nothing about whether an event can reach
  the receiver.
* **stream updated**: the stream's status changed, and the receiver is told in
  band. A receiver does not have to ask for this event to get it.

The vocabularies run over that pipe:

| Vocabulary | Events | About | Emitted on its own when |
|---|---|---|---|
| **CAEP** | 8 | a session | someone signs in, uses single sign-on, signs out, a session expires, a person re-authenticates at a different `acr`, any credential of a person changes, a directory change moves a claim of somebody holding live tokens, a registered device's compliance, risk level or credentials change |
| **RISC** | 14 | an account | a person is deleted, disabled or enabled; any mail address or telephone number changes or is removed, or is given to an account after another released it; the recovery address is added, changed, removed or verified; an administrator resets a password (optionally marking it compromised) or issues a reset or activation link; recovery codes are cleared, confirmed or used; the account holder opts out or back in on `/portal/signals`; a person's registered device is compromised or removed |

Since #164 every CAEP and RISC event type has an act here that sends it: a
registered device's compliance changing (`device-compliance-change`), its risk
level changing (`risk-level-change`, principal `DEVICE`), its keys and Native
SSO secret changing (`credential-change`), and a person's device compromised or
removed (RISC `credential-compromise` and the deprecated `sessions-revoked`,
with the device beside the person in the subject). [Devices](devices.md) lists
each. You can still emit any of them by hand from the console or the
management API.
[CAEP events](caep-events.md) covers what triggers each CAEP event.

**RISC opt-out (section 2.8) is the account holder's choice.** On
`/portal/signals` a person can stop sharing security events about their
account. Their account enters `opt-out-initiated`; receivers keep being told
everything; and after `risc.optOutDelayHours` a scheduler job sends
`opt-out-effective`, after which only opt-out events are sent about them.
They can cancel during the wait, or opt back in afterwards. The wait stops
somebody who has just taken an account over from silencing it at once.
**Only the holder moves it**: an administrator's Reset or Clear on the RISC
register keeps the account's opt state, and a pending opt-out still becomes
effective on schedule.

**Every value of `mail`, `telephoneNumber` and `mobile` counts.** A second
address changing, or a `mobile` beside a `telephoneNumber`, is an
`identifier-changed`; an address removed is one with no `new-value`, and it
can then be `identifier-recycled` to another account. **The recovery
address** is the first `mail` value, which `/portal/forgot-password` mails:
its addition, change, removal or verification is
`recovery-information-changed` (a change is `identifier-changed` as well).
A recovery code used is `recovery-information-changed`, and at sign-in
`recovery-activated` too.

**`account-disabled` carries a `reason` only when an administrator gives one**
(`hijacking` or `bulk-account`, on the console's disable form or as
`riscReason` on `/admin-api/users/disable`).

One more event exists, and it belongs to this service rather than to any
specification: `urn:iya:sts:secevent:event-type:signing-key-rotated`. It goes
to every stream that asked for it after a signing key rotation, and it names
the realm, the keys rotated, the reason, and the JWKS and crypto metadata
addresses. A receiver that does not know the type ignores it, as SSF says it
should.

### Discovery and stream management

SSF fixes no paths. A receiver starts from the transmitter configuration
metadata and discovers every endpoint from it:

| Path | What it is |
|---|---|
| `GET /.well-known/ssf-configuration` | the transmitter configuration metadata. **Never gated**, and still answers while `ssf.enabled` is off |
| `GET /.well-known/ssf-configuration/realm/{id}` | the same document for a trust realm's transmitter, at the path SSF 1.0 section 7.2 builds from an issuer with a path |
| `/ssf/stream` | stream management: `POST` creates, `GET` reads, `PUT` and `PATCH` update, `DELETE` deletes |
| `/ssf/status` | read (`GET`) or change (`POST`) a stream's status |
| `POST /ssf/subjects/add`, `POST /ssf/subjects/remove` | add (an empty 200) or remove (204) a subject, SSF 1.0 sections 8.1.3.2 and 8.1.3.3 |
| `POST /ssf/verify` | ask for a verification event |
| `POST /ssf/poll` | RFC 8936 poll delivery and acknowledgement |
| `POST /ssf/receive`, `GET /ssf/received` | this service as a **receiver** (below) |
| `GET /ssf` | a description of the family; `?format=json` returns the same as data |

In a trust realm every path is under `/realm/{id}`. A realm's metadata is at
both `/realm/{id}/.well-known/ssf-configuration` and the section 7.2 form above,
which inserts the well-known name between the host and the issuer's path. The
subject paths use a slash where SSF's own examples use a colon
(`/subjects:add`). A receiver reads `add_subject_endpoint` from the metadata,
so it never sees the difference. `spec_version` is `1_0`.

A receiver picks its event types in `events_requested`. The transmitter
answers with `events_delivered`, which is the overlap with what it offers
(`ssf.eventsSupported`, `caep.eventsSupported` and `risc.eventsSupported`,
combined).

### Each stream belongs to its receiver

SSF 1.0 section 8 has the transmitter associate each receiver with its streams
and its `aud` values. Here, a stream belongs to the identity that created it:
a client's `client_id`, a person's `sub`, a GNAP client instance, or a Basic
username.

* **Another receiver's stream answers 404**, word for word as for a stream that
  does not exist, on every endpoint that takes a `stream_id`. That is the
  specification's own wording ("no Event Stream with the given stream_id for
  this Event Receiver"), and a different answer would reveal which ids exist.
* **`GET /ssf/stream` with no `stream_id` lists only the caller's own
  streams**, and an empty list when it has none.
* **`aud` is set by the transmitter** (section 8.1.1 lists it as
  Transmitter-Supplied). A new stream's `aud` is the identifier the receiver
  authenticated as. A receiver may instead send `aud` naming one or more of the
  names it is associated with: that identifier, plus the application
  identifier and every `ssfReceiverId` on its registered application entry. Any
  other value is refused. An update may carry `aud`, or any other
  Transmitter-Supplied member (`iss`, `events_supported`, `events_delivered`,
  `min_verification_interval`, `inactivity_timeout`), only unchanged.
* **`ssf.maxStreams` is per receiver.** Creating a stream past it answers 403.
* **The console's and portal's own streams belong to no remote receiver** and
  are managed only on `/admin/ssf` and through `/admin-api`.

### Subjects

A subject can be in any of the eight RFC 9493 formats under their registered
names (`account`, `email`, `iss_sub`, `opaque`, `phone_number`, `did`, `uri`,
`aliases`), in one of SSF 1.0 section 3.5's three (`jwt_id`,
`saml_assertion_id`, `ip-addresses`), or be SSF's **complex subject**, which
carries `"format": "complex"`. The complex subject's members (`user`,
`device`, `session`, `application`, `tenant`, `org_unit` and `group`, plus any
additional name section 3.3 allows) are what make *this session was revoked*
possible to say at all. Each format has a **closed** member set. A subject
carrying a member that its format does not define is refused, and the refusal
names the member, because a conforming receiver has to reject one. Nesting a
complex subject inside another is refused as well. The pre-RFC names
`issuer_subject_id` and `decentralized_identifier` are not accepted.

A stream that names a **person** covers a complex subject naming one of that
person's sessions. `ssf.defaultSubjects` controls what a stream with no
subjects covers. With `ALL`, the default, it covers everybody. With `NONE` it
covers nobody until a subject is added.

### Push and poll delivery

* **Poll (RFC 8936).** The receiver calls `POST /ssf/poll` — the stream's
  `delivery.endpoint_url`, which names the stream in its query
  (`?stream_id=…`), since RFC 8936's poll endpoint is per stream — and nothing is
  dialled. One poll returns at most `ssf.pollMaxEvents` SETs and sets
  `moreAvailable` when more are waiting. An acknowledged SET is never handed
  out again. Until it is acknowledged, it may be returned again, as RFC 8936
  section 2.4 allows.
* **Push (RFC 8935).** The service POSTs each SET to the endpoint the receiver
  named on its stream, with the stream's `authorization_header`. A 202 counts
  as delivery. A 400 with `{err, description}` means the receiver **refused**
  the SET, and it is recorded separately from a network failure. A 200 or 204
  is accepted, with a note that it is not quite right.

Push is the one place in SSF where this service makes a request to an address
that a caller chose. Four settings limit it: `ssf.pushDelivery` turns it off,
`ssf.pushAllowedHosts` is a host allowlist (empty by default, meaning any
host), only `https` with the receiver's certificate verified is used — plain
http only with `ssf.pushAllowHttp` and verification off only with
`ssf.pushSkipTlsVerification`, **both in development mode only** (#171);
product reaches a privately certified receiver through `ssf.pushCaFile` — and
every push has a timeout, a cap on the response size and **no redirects**. With push
turned off, SSF still works in full over poll, and `delivery_methods_supported`
lists only poll.

### Stream status

SSF 1.0 section 7.1.2 defines three statuses:

* **enabled**: events are delivered.
* **paused**: nothing is delivered and events **keep queueing**. On a push
  stream they are pushed, in the order they happened, when the stream is
  enabled again.
* **disabled**: the queue is **dropped**, and the stream's log records how many
  events went.

Every status change sends a `stream-updated` event on the stream, whether or
not the receiver asked for that type (section 8.1.5 allows it, and requires it
when the transmitter changes the status). It goes **before** the stream stops
when it is paused or disabled, and after it starts again when it is enabled. On
a poll stream that has been paused or disabled, `POST /ssf/poll` still hands out
the `stream-updated` event and nothing else. Setting the status a stream
already has sends nothing.

A new stream starts as `ssf.streamStatusOnCreate` (`enabled` by default). Set
it to `paused` to test a receiver that has to enable its own stream first.

### Inactivity and transmitter-initiated verification

* **`ssf.inactivityTimeoutS`** (section 8.1.1's `inactivity_timeout`, 0 by
  default, meaning none): a stream whose receiver has made no management call
  about it, and on a poll stream no poll either, for that long is paused,
  disabled or deleted, as `ssf.inactivityAction` says. A pause or disable is
  announced with `stream-updated` first. The value is published on every stream
  configuration while it is set. It is off by default because a push receiver
  never needs to call back after creating its stream.
* **`ssf.verificationEveryS`** (0 by default): every enabled stream is sent a
  verification event, with no `state`, when this transmitter has sent it none
  for that long. **Send a verification event** on `/admin/ssf` does the same
  once.

Both run as the `ssf.stream-maintenance` scheduler job every
`ssf.streamMaintenanceSweepS`. The console's and portal's own streams are left
alone.

### Verification

`POST /ssf/verify` answers **204 as soon as the event is queued**. Section
8.1.4.2 says a receiver must not depend on the event arriving synchronously,
so a failed delivery is not reported in the response: it goes to the stream's
dead-letter queue and log, like any other failed push. A paused stream holds
the event until it is enabled, and a disabled stream refuses the request with
400. The verification event is sent even if the stream did not agree to the
type.

### Signing

Every SET is signed with `ssf.signingAlgorithm`, using the same signer as
every other token here. You can pick any algorithm from the full list: RS256,
the PS and ES families, EdDSA, and the post-quantum ones (ML-DSA, SLH-DSA and
the composite ML-DSA algorithms). A SET has `typ: secevent+jwt`.
`ssf.setCertificateHeader` controls whether it carries the signing key's
certificate chain, as `x5u` (the default), `x5c`, both, or neither.

### Authentication: three schemes, two scopes

The metadata document lists the schemes it accepts in
`authorization_schemes`:

* **OAuth 2.0**: an access token from this service with `ssf:read` or
  `ssf:write`. DPoP- and certificate-bound tokens are checked the same way as
  at every other protected endpoint.
* **HTTP Basic**: a directory person's name and password, so that a client
  that has no token flow yet can still reach every endpoint. Basic carries no
  scope, so a Basic caller gets both. `ssf.authBasic` turns the scheme off.
  In product mode a person who holds or must hold a second factor is refused
  their own password with the `401` a wrong one gets, and uses an
  [app password](authentication.md#the-password-only-doors-and-app-passwords) scoped to `ssf`.
* **GNAP**: a key-bound GNAP access token whose access includes `ssf:read` or
  `ssf:write`, so that a GNAP web application can own a stream itself. See
  [GNAP](gnap.md).

`ssf:read` lets a caller read a stream, its status and the poll queue.
`ssf:write` is needed to create, change or delete a stream, change subjects or
status, or ask for verification. A read token that attempts a write gets a 403
that names the scope it needs.

### Limiting what an application's stream may carry

An application entry can carry `ssfAllowedEvents`: `caep`, `risc`, or
particular event type URIs. A stream owned by that application then gets only
those types. The limit applies when the stream is created or updated **and**
again at every delivery, so lifting a limit does not release types that were
held back when the stream was agreed, and a receiver that created its stream
before the limit was tightened gets no way around it. SSF's own two events are
always allowed. An empty value means no limit.

### Dead streams and dead letters

A push that cannot be delivered is not retried unless `ssf.pushRetries` says
so. The default is 0, because a transmitter that retried would hide a
receiver's one-off failure from whoever is testing it. When retries are on,
only failures that might go differently next time are retried: no connection,
a timeout, a 5xx or a 429. A 400 is never retried.

A SET that could not be delivered goes to its stream's **dead-letter queue**
with the reason, the error code and the receiver's HTTP status. That happens
when a push fails for good, when the push backlog is full, and when the stream
is dead. A push stream whose pushes have all failed for
`ssf.deadStreamTimeoutS` is declared **dead**. Nothing more is pushed to it,
and once per timeout the oldest dead letter is pushed as a probe. A dead
stream is also **paused**, with a `stream-updated` event attempted first,
because stopping delivery is a status change the receiver must be told about
(section 8.1.2). When a probe succeeds, or an operator revives the stream, it
is enabled again and announced, and whatever it held is pushed. A stream that
the receiver or an operator paused is never enabled by a revival. Nothing
resends a dead letter except a probe.

Failures are logged once per stream (when it dies and when it revives) and
once per sweep as a summary, never once per SET.

### This service as a receiver

`POST /ssf/receive` accepts a SET pushed **at** this service, for testing a
client that acts as the transmitter. It verifies the signature when it can
find a key. A SET that another party signed is reported as *not verifiable
here*, not as invalid. `GET /ssf/received` lists what arrived.
`ssf.receiveRequireSignature` makes it refuse a SET whose signature fails, the
way a strict receiver would. **Product mode always refuses one**, at this
endpoint and at the console's and portal's own receivers (#117).

Every SET that arrives is recorded, and it is then refused if its header's
`typ` is not `secevent+jwt` (section 4.1.1), if its `iss` is not one
`ssf.receiveIssuers` lists (`invalid_issuer`, section 4.1.6), or if its `aud`
names nothing `ssf.receiveAudiences` lists (`invalid_audience`). Left empty,
the first means this realm's own transmitter issuer and the second means the
endpoint's own URL, for example `https://host/ssf/receive`. The console's and
portal's receivers make the same `typ` and `iss` checks against their own
streams. To receive another transmitter's streams, see *Receiving from
another identity service*, below.

### Receiving from another identity service

A realm can receive CAEP and RISC events from another identity service's
transmitter, for people who sign in here through a federation relationship
with it ([#153](https://github.com/rcbj/iya-sts/issues/153)).

1. **Register it** on Protocols → SSF transmitters (`/admin/ssf/transmitters`)
   or with `POST /admin-api/ssf/transmitters/add`. You give it an id, its
   issuer, the federation relationship its subjects are mapped through,
   `poll` or `push`, and how this realm authenticates to it: client
   credentials at its token endpoint, or a bearer token. Its
   `/.well-known/ssf-configuration` and `jwks_uri` are fetched and checked.
2. **Create the stream** (`create-stream`). A poll stream is polled every
   `ssf.foreignPollS` seconds. A push stream is given
   `/ssf/transmitters/{id}/push` and an authorization header only the two
   services know.
3. **Link people.** A subject `{format: "iss_sub", iss, sub}` with the
   relationship's issuer names the person whose federation link holds it. An
   `email` subject is matched only where the relationship sets
   `fedSignalEmailMatch`.

A Security Event Token is acted on only if it verified: its signature against
the transmitter's keys, `typ`, `iss`, the stream's `aud`, and a `jti` never
seen before. Product mode refuses an unverified one. What it leads to is the
`signal-response` XACML policy's decision:

| Events | Reaction here |
|---|---|
| `session-revoked`, `credential-change`, `sessions-revoked`, `credential-compromise`, `account-purged` | end the person's sessions |
| `account-disabled` | disable the account |
| `account-enabled` | enable it again, only if that transmitter disabled it |

Development records what it would do and does nothing unless
`ssf.actOnSignalsInDevelopment` is on.

### The console and the portal are registered receivers

Each trust realm has two streams seeded by the service itself, one for the
admin console and one for the user portal. Both ask for every CAEP and RISC
event type, and both take delivery over a real RFC 8935 push to an endpoint of
their own. What arrives is shown at `/admin/signals` and `/portal/signals`.
[Signals received](signals-received.md) explains how this works, and why an
empty page has five possible causes. **Both act on what they receive**: a
verified event the `signal-response` policy permits ends the receiving
surface's own sessions for the person it names (product mode; development
records it). An unverified event is never acted on.

### Deliberate defects

A transmitter that is always correct is hard to write error handling against,
so each of these switches produces a known mistake.

**`ssf.legacySubClaim` and `ssf.breakSetSignature` make a SET wrong, and are
honoured in development mode only** (#104), **and so is
`risc.googleSubjectType`** (#181), whose `subject_type` RISC 1.0 section 3.1
says new services MUST NOT use. A realm in product mode ignores them where the
SET is built and signed — even one still stored from before the realm was
switched, which is logged once (`STS-CORE-0106`) — and refuses turning them on
(`STS-CORE-0103`). The other two produce SETs that conform to their
specifications, and are honoured in both modes.

| Setting | What it breaks |
|---|---|
| `ssf.legacySubClaim` | adds the deprecated `sub` claim beside `sub_id` |
| `ssf.breakSetSignature` | changes one character of the signature after signing. The first character is changed, not the last, because the last character's padding bits are discarded and a changed last character still verifies |
| `caep.omitEventTimestamp` | leaves out `event_timestamp`, which is optional and which many receivers assume is present |
| `risc.omitEventTimestamp` | the same, on `credential-compromise` |
| `risc.googleSubjectType` | spells the subject discriminator `subject_type` instead of `format`, as the RISC specification's own section 3.1 records one production transmitter doing |

### Not implemented

* **Subjects are not checked.** A stream may name somebody who has never been
  here, which is what a receiver's *I do not know this subject* path needs.
* **`verified: true` on Add Subject is believed.** There is no confirmation
  step to skip.
* **There is no console or API control that creates a stream.** A stream
  holds a delivery endpoint that this service will call, and that address may
  only come from a receiver that authenticated at `POST /ssf/stream`.
* **A realm receives only from a transmitter an administrator registered**
  ([#153](https://github.com/rcbj/iya-sts/issues/153)). It never follows a
  URL a SET or a request names; every address comes from that issuer's own
  configuration document.

## Development and product mode

| | Development | Product |
|---|---|---|
| Credential at `/ssf/*` | required, but only a check at the door: any name and any password except `invalid` passes Basic. A token carries `ssf:read` or `ssf:write` only when its client declares them in `oauthAllowedScope` (in both modes), and is honoured only while it still does (`STS-SSF-0107`) | required, and a Basic password is checked against the person's hashed `userPassword` |
| Access tokens | verified | verified |
| Subjects of automatic events | a person with no `mail` gets an invented `@example.com` address | a real value from the directory entry, or the issuer/subject pair. RISC's two identifier events are not sent when there is no real value |
| Streams, queues, CAEP and RISC registers | in memory, lost on restart | persisted with other minted state (product mode on postgres) |

See [What is not checked](what-is-not-checked.md).

**Running several nodes.** Every node needs the same `global.port`, because
the console's and portal's own streams are pushed to
`<loopback>:<global.port>`. `global.publicBaseUrl` has to be pinned, because
it becomes every SET's `iss`. Active-active mode refuses to start while it is
empty.

## Configuration

There are 63 settings in three groups, and the SSF table also lists one GNAP
setting that affects streams. Every one can be changed while the service runs
except `ssf.internalReceivers`. The CAEP and RISC groups have no
effect on SSF itself: turning either vocabulary off only removes its event
types from what a stream may ask for.

### Shared Signals (`ssf.*`)

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `ssf.enabled` | `STS_SSF_ENABLED` | `true` | yes | Turns the whole family on or off. When off, the routes stay and answer 501, and the metadata still answers. |
| `ssf.issuer` | `STS_SSF_ISSUER` | *(empty)* | yes | The `iss` of every SET and of the metadata. Empty means this realm's base URL. |
| `ssf.signingAlgorithm` | `STS_SSF_SIGNING_ALGORITHM` | `RS256` | yes | The JWS algorithm every SET is signed with, post-quantum ones included. |
| `ssf.setCertificateHeader` | `STS_SSF_SET_CERTIFICATE_HEADER` | `x5u` | yes | Whether a SET names its signing key's certificate chain: `none`, `x5c`, `x5u` or `both`. |
| `ssf.deliveryMethods` | `STS_SSF_DELIVERY_METHODS` | `urn:ietf:rfc:8935,urn:ietf:rfc:8936` | yes | Which delivery methods the service agrees to. `push` and `poll` are accepted as shorthand. |
| `ssf.defaultSubjects` | `STS_SSF_DEFAULT_SUBJECTS` | `ALL` | yes | What a stream with no subjects covers: everybody (`ALL`) or nobody (`NONE`). |
| `ssf.streamStatusOnCreate` | `STS_SSF_STREAM_STATUS_ON_CREATE` | `enabled` | yes | The status a new stream starts in. `paused` makes the receiver enable its own stream. |
| `ssf.minVerificationInterval` | `STS_SSF_MIN_VERIFICATION_INTERVAL` | `60` | yes | The `min_verification_interval` the service publishes. A stream that asks for less is refused. |
| `ssf.verificationRateLimit` | `STS_SSF_VERIFICATION_RATE_LIMIT` | `false` | yes | Answers 429 to a verification request that comes sooner than the published interval. |
| `ssf.criticalSubjectMembers` | `STS_SSF_CRITICAL_SUBJECT_MEMBERS` | *(empty)* | yes | The complex-subject members a receiver must understand. Adding a complex subject that leaves one out is refused. |
| `ssf.eventsSupported` | `STS_SSF_EVENTS_SUPPORTED` | verification, stream-updated | yes | Which of SSF's own two event types are offered. |
| `ssf.pushDelivery` | `STS_SSF_PUSH_DELIVERY` | `true` | yes | Whether the service may push SETs at all. When off, only poll is offered. |
| `ssf.pushAllowedHosts` | `STS_SSF_PUSH_ALLOWED_HOSTS` | *(empty)* | yes | Hosts the service may push to. Empty means any host. |
| `ssf.pushAllowHttp` | `STS_SSF_PUSH_ALLOW_HTTP` | `false` | yes | Allows `http://` endpoints, in development mode only. This service's own receivers are exempt in both modes. |
| `ssf.pushSkipTlsVerification` | `STS_SSF_PUSH_SKIP_TLS_VERIFICATION` | `false` | yes | **Development only — a warning.** Pushes to a receiver whose certificate nothing here trusts. Ignored in product, and refused on write there. |
| `ssf.pushCaFile` | `STS_SSF_PUSH_CA_FILE` | *(empty)* | yes | A PEM file of CA certificates a receiver may chain to, beside node's own store. |
| `ssf.pushTimeoutMs` | `STS_SSF_PUSH_TIMEOUT_MS` | `10000` | yes | How long to wait for a receiver to answer a push. |
| `ssf.pushMaxResponseBytes` | `STS_SSF_PUSH_MAX_RESPONSE_BYTES` | `65536` | yes | How much of a receiver's answer is read before the push counts as failed. |
| `ssf.pushRetries` | `STS_SSF_PUSH_RETRIES` | `0` | yes | How many times a failed push is retried. Only failures that could go differently are retried. |
| `ssf.pushRetryDelayMs` | `STS_SSF_PUSH_RETRY_DELAY_MS` | `1000` | yes | The wait before a retry, multiplied by the attempt number. |
| `ssf.pushConcurrency` | `STS_SSF_PUSH_CONCURRENCY` | `8` | yes | How many pushes one process makes at once. `0` removes the cap. |
| `ssf.pushBacklog` | `STS_SSF_PUSH_BACKLOG` | `2000` | yes | How many pushes may wait for a slot. Past that, the SET is dead-lettered. |
| `ssf.deadStreamTimeoutS` | `STS_SSF_DEAD_STREAM_TIMEOUT_S` | `300` | yes | How long a push stream has to fail completely before it is declared dead. `0` turns this off. |
| `ssf.deadLetterRetentionS` | `STS_SSF_DEAD_LETTER_RETENTION_S` | `3600` | yes | How long an undeliverable SET is kept on the dead-letter queue. |
| `ssf.deadLetterMaxPerStream` | `STS_SSF_DEAD_LETTER_MAX_PER_STREAM` | `1000` | yes | The most dead letters one stream keeps. The oldest is dropped first. |
| `ssf.deadLetterSweepS` | `STS_SSF_DEAD_LETTER_SWEEP_S` | `60` | yes | How often expired dead letters are deleted, due probes are sent and the summary is logged. |
| `ssf.authBasic` | `STS_SSF_AUTH_BASIC` | `true` | yes | Whether HTTP Basic is accepted and advertised. |
| `ssf.internalReceivers` | `STS_SSF_INTERNAL_RECEIVERS` | `true` | **no** | Seeds the console's and the portal's own receiver streams. |
| `ssf.maxStreams` | `STS_SSF_MAX_STREAMS` | `25` | yes | Streams per receiver in a realm. A create past the limit is refused with 403, and the refusal names this setting. The console's and portal's own streams do not count. |
| `ssf.inactivityTimeoutS` | `STS_SSF_INACTIVITY_TIMEOUT_S` | `0` | yes | SSF 1.0 section 8.1.1's `inactivity_timeout`: a stream whose receiver has made no management call about it (and, for a poll stream, no poll) for this long is dealt with as `ssf.inactivityAction` says. `0`, the default, is no timeout. It is off by default because a push receiver never calls back. |
| `ssf.inactivityAction` | `STS_SSF_INACTIVITY_ACTION` | `pause` | yes | `pause`, `disable` or `delete`. A pause or disable is announced with a stream-updated event before the stream stops. |
| `ssf.verificationEveryS` | `STS_SSF_VERIFICATION_EVERY_S` | `0` | yes | Sends every enabled stream a transmitter-initiated verification event (no `state`) when it has had none for this long. `0` sends none on a schedule. |
| `ssf.streamMaintenanceSweepS` | `STS_SSF_STREAM_MAINTENANCE_SWEEP_S` | `60` | yes | How often the `ssf.stream-maintenance` scheduler job applies the two settings above. |
| `ssf.receiveAudiences` | `STS_SSF_RECEIVE_AUDIENCES` | *(empty)* | yes | The `aud` values `POST /ssf/receive` accepts. Empty means the endpoint's own URL. Anything else is recorded and refused with `invalid_audience`. |
| `ssf.receiveIssuers` | `STS_SSF_RECEIVE_ISSUERS` | *(empty)* | yes | The `iss` values `POST /ssf/receive` accepts. Empty means this realm's own transmitter issuer. Anything else is recorded and refused with `invalid_issuer`. |
| `ssf.maxSubjectsPerStream` | `STS_SSF_MAX_SUBJECTS_PER_STREAM` | `100` | yes | How many subjects one stream may name. |
| `ssf.maxQueuedEvents` | `STS_SSF_MAX_QUEUED_EVENTS` | `200` | yes | How many undelivered SETs one stream holds. The oldest is dropped first. |
| `ssf.pollMaxEvents` | `STS_SSF_POLL_MAX_EVENTS` | `20` | yes | The most SETs one poll returns, whatever the receiver asks for. |
| `ssf.maxReceivedEvents` | `STS_SSF_MAX_RECEIVED_EVENTS` | `200` | yes | How many SETs `POST /ssf/receive` keeps for display. |
| `ssf.maxStreamLogEntries` | `STS_SSF_MAX_STREAM_LOG_ENTRIES` | `200` | yes | How many log lines each stream keeps. |
| `ssf.authScopeRead` | `STS_SSF_AUTH_SCOPE_READ` | `ssf:read` | yes | The scope needed to read a stream, its status or the poll queue. |
| `ssf.authScopeWrite` | `STS_SSF_AUTH_SCOPE_WRITE` | `ssf:write` | yes | The scope needed to change anything about a stream. |
| `ssf.receiveEnabled` | `STS_SSF_RECEIVE_ENABLED` | `true` | yes | Whether `POST /ssf/receive` accepts pushed SETs. When off, it answers 501. |
| `ssf.receiveRequireSignature` | `STS_SSF_RECEIVE_REQUIRE_SIGNATURE` | `false` | yes | Refuses a received SET whose signature fails, with 400 `invalid_key`, in development mode. Product mode always refuses one (#117). |
| `ssf.actOnSignalsInDevelopment` | `STS_SSF_ACT_ON_SIGNALS_IN_DEVELOPMENT` | `false` | yes | The console and portal end their own sessions on a received signal in development too; product always does. |
| `ssf.legacySubClaim` | `STS_SSF_LEGACY_SUB_CLAIM` | `false` | yes | Deliberate defect, development only: adds the deprecated `sub` claim beside `sub_id`. |
| `ssf.breakSetSignature` | `STS_SSF_BREAK_SET_SIGNATURE` | `false` | yes | Deliberate defect, development only: changes one character of every SET's signature. |
| `gnap.scopedSignals` | `STS_GNAP_SCOPED_SIGNALS` | `true` | yes | A stream owned by a GNAP application only hears about people who approved a grant to it. |

### CAEP (`caep.*`)

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `caep.enabled` | `STS_CAEP_ENABLED` | `true` | yes | Offers CAEP's eight event types and keeps the session register. |
| `caep.autoEmit` | `STS_CAEP_AUTO_EMIT` | `true` | yes | Sends CAEP events automatically for the session acts this service can observe. |
| `caep.autoEmitTypes` | `STS_CAEP_AUTO_EMIT_TYPES` | `session-established,session-presented,session-revoked,credential-change,assurance-level-change,token-claims-change,risk-level-change` | yes | Which of those acts produce an event. A type nothing here can cause is dropped with a warning. |
| `caep.eventsSupported` | `STS_CAEP_EVENTS_SUPPORTED` | all eight | yes | Which CAEP types a stream may ask for. Short names are accepted. |
| `caep.assuranceNamespace` | `STS_CAEP_ASSURANCE_NAMESPACE` | `NIST-AAL` | yes | The `namespace` of an `assurance-level-change` emitted by hand. Automatic ones use `urn:sts:acr`. |
| `caep.defaultRiskLevel` | `STS_CAEP_DEFAULT_RISK_LEVEL` | `MEDIUM` | yes | What a `risk-level-change` says when the caller does not choose a level. |
| `caep.reasonLanguage` | `STS_CAEP_REASON_LANGUAGE` | `en` | yes | The language tag the reason members are keyed under. |
| `caep.includeReasons` | `STS_CAEP_INCLUDE_REASONS` | `true` | yes | Whether automatic events carry the optional reason members. |
| `caep.maxSessionsTracked` | `STS_CAEP_MAX_SESSIONS_TRACKED` | `200` | yes | The size of the CAEP session register. The oldest row is dropped first. |
| `caep.eventsPerSession` | `STS_CAEP_EVENTS_PER_SESSION` | `25` | yes | How many recent events a register row lists. The per-type counts are never trimmed. |
| `caep.historyPerSession` | `STS_CAEP_HISTORY_PER_SESSION` | `10` | yes | How many `credential-change` details a row keeps. |
| `caep.omitEventTimestamp` | `STS_CAEP_OMIT_EVENT_TIMESTAMP` | `false` | yes | Deliberate defect: leaves out the optional `event_timestamp`. |

### RISC (`risc.*`)

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `risc.enabled` | `STS_RISC_ENABLED` | `true` | yes | Offers RISC's fourteen event types and keeps the account register. |
| `risc.autoEmit` | `STS_RISC_AUTO_EMIT` | `true` | yes | Sends RISC events automatically for the directory changes this service can observe. |
| `risc.autoEmitTypes` | `STS_RISC_AUTO_EMIT_TYPES` | every type but `sessions-revoked` | yes | Which of those acts produce an event. |
| `risc.recycleWindowDays` | `STS_RISC_RECYCLE_WINDOW_DAYS` | `365` | yes | How long after an account released an address or number another account taking it is reported as `identifier-recycled`. Also bounded by `risc.maxAccountsTracked`. `0` reports nothing. |
| `risc.optOutDelayHours` | `STS_RISC_OPT_OUT_DELAY_HOURS` | `24` | yes | How long an opt-out waits in `opt-out-initiated` before the `risc.opt-out-effective` job makes it effective. |
| `risc.eventsSupported` | `STS_RISC_EVENTS_SUPPORTED` | all fourteen | yes | Which RISC types a stream may ask for, including the deprecated `sessions-revoked`. |
| `risc.subjectFormat` | `STS_RISC_SUBJECT_FORMAT` | `iss_sub` | yes | The RFC 9493 format of an account subject: `iss_sub`, `email` or `opaque`. The two identifier events always use `email`. |
| `risc.honourOptOut` | `STS_RISC_HONOUR_OPT_OUT` | `true` | yes | Suppresses events for an account in the `opt-out` state, except the four opt-out events. |
| `risc.googleSubjectType` | `STS_RISC_GOOGLE_SUBJECT_TYPE` | `false` | yes | Deliberate defect: spells the subject discriminator `subject_type` on RISC subjects. Development mode only: ignored in product, and turning it on is refused (#181). |
| `risc.reasonLanguage` | `STS_RISC_REASON_LANGUAGE` | `en` | yes | The language tag of the reason members on `credential-compromise`. |
| `risc.includeReasons` | `STS_RISC_INCLUDE_REASONS` | `true` | yes | Whether `credential-compromise` carries its optional reason members. |
| `risc.omitEventTimestamp` | `STS_RISC_OMIT_EVENT_TIMESTAMP` | `false` | yes | Deliberate defect: leaves `event_timestamp` off `credential-compromise`. |
| `risc.maxAccountsTracked` | `STS_RISC_MAX_ACCOUNTS_TRACKED` | `200` | yes | The size of the RISC account register. The oldest row is dropped first. |
| `risc.eventsPerAccount` | `STS_RISC_EVENTS_PER_ACCOUNT` | `25` | yes | How many recent events a register row lists. |
| `risc.historyPerAccount` | `STS_RISC_HISTORY_PER_ACCOUNT` | `10` | yes | How many credential-compromise and identifier-change records a row keeps. |

For how a value is resolved and where it can be changed, see
[Configuration](configuration.md). Each group is on its own console page
(`/admin/ssf`, `/admin/caep`, `/admin/risc`), and every setting can also be
changed with `POST /admin-api/config/set`.

## Design decisions

* **SSF is the pipe; CAEP and RISC are vocabularies over it.** SSF's two
  events are about the stream itself. Session and account events are rows in
  a table on top of it, so adding RISC's fourteen types changed nothing in the
  envelope, the subjects, delivery or stream management.
* **CAEP keeps a register of sessions and RISC keeps a register of accounts,
  and they are separate.** A session starts, is used and ends, and one person
  can have many. An account *is* the person and outlives every session. RISC
  also tracks three things per account that change independently: its
  lifecycle, its opt-out state and whether a credential is compromised.
* **Both registers keep a row after the session or account is gone.** A
  revoked session disappears from the session store, and a purged account
  disappears from the directory. After that, the register row is the only
  evidence that anybody was told.
* **RISC watches the directory, not SCIM.** A person can be deleted or
  disabled over SCIM, LDAP or the console. A RISC feature that only noticed
  SCIM would say nothing about a deprovisioning done with `ldapmodify`.
* **An attribute that is absent is not the same as one that is false.** A
  write that does not mention `active` sends no `account-disabled`. Otherwise
  every person created without the attribute would be reported as disabled.
* **A transmitter reports, and a receiver decides.** RISC tells a receiver
  that an account was disabled or purged here. What the receiver does about
  it is the receiver's decision, which is how the profile divides the work.
* **The four opt-out events are never suppressed.** `opt-out-effective`
  announces that the account is going quiet, and `opt-in` is the only way a
  receiver learns it came back. Holding either back would make an opt-out look
  like a transmitter that had stopped working. The middle state,
  `opt-out-initiated`, still exchanges everything, so that someone who hijacks
  an account cannot silence the events that would report them.
* **The first time a new session is presented, no event is sent.** Every
  sign-in ends with the browser returning to the authorization endpoint. If
  that counted, `session-established` and `session-presented` would always
  arrive milliseconds apart.
* **`initiating_entity` says who really ended a session.** An expiry says
  `policy`. An administrator ending someone's session says `admin`. It never
  claims the person signed themselves out when they did not.
* **Push is not retried by default.** A transmitter that retried would hide a
  receiver's one-off failure. A deployment can set `ssf.pushRetries`.
* **A push that fails goes to a dead-letter queue; logging stays per stream.**
  A burst of failures produces one line when the stream dies and one summary
  per sweep. Signing a SET that nothing will receive is skipped.
* **The metadata document is always open.** A receiver has to read which
  schemes the endpoints take before it can authenticate to them.
* **`aud` is the transmitter's to assign.** It comes from the receiver's own
  identity, so a receiver cannot have its events addressed to another receiver.
* **The console's and portal's signals come through a real push.** Passing
  events to those pages internally would skip the body, media type,
  authorization header and signature, which is everything a receiver does.
  Their stream IDs and authorization tokens are derived from the realm and the
  surface, so every process and every node arrives at the same values.
* **SETs are worth signing with a post-quantum algorithm.** RFC 8417 forbids
  a SET from expiring, so it is read long after it was written.

## In the running service

* **Protocols → Shared Signals** (`/admin/ssf`): the `ssf.*` settings, and
  every stream this realm's transmitter holds, with its subjects, queue,
  counters, log and dead letters. A dead stream is marked. Each stream has
  controls to change its status, delete it, send it a SET, **Send a
  verification event**, **Revive** it and **Drop its dead letters**. What `POST /ssf/receive` received is listed too.
  There is no control to create a stream (see *Not implemented*).
* **Protocols → CAEP** (`/admin/caep`): the `caep.*` settings, the catalogue
  of the eight event types and their members, and the form for sending one by
  hand. You pick a session by searching for the person, and only live
  sessions are offered.
* **Protocols → RISC** (`/admin/risc`): the `risc.*` settings, the catalogue
  of the fourteen event types, and the form for sending one by hand about an
  account.
* **Monitoring → Shared Signals**: *CAEP sessions* (`/admin/caep-sessions`),
  *RISC accounts* (`/admin/risc-accounts`), *Signals received*
  (`/admin/signals`) and *Dead letters* (`/admin/ssf/dead-letters`). The
  dead-letters page counts every held SET by cause, error code, receiver HTTP
  status, event type, time and stream. It shows the letters themselves, but
  not their tokens.
* **The management API** mirrors all of these: `GET /admin-api/ssf` and
  `POST /admin-api/ssf/{action}` (`status`, `delete`, `transmit`,
  `clear-received`, `revive`, `clear-dead-letters`, `verify`),
  `GET /admin-api/ssf/dead-letters`, `GET /admin-api/caep`,
  `GET /admin-api/caep/sessions` and `POST /admin-api/caep/{action}` (`emit`,
  `reset-session`, `clear`), `GET /admin-api/risc`,
  `GET /admin-api/risc/accounts` and `POST /admin-api/risc/{action}` (`emit`,
  `reset-account`, `clear`), and `/admin-api/signals`. The request and
  response shapes are in `/admin-api/openapi.json`.
* **`GET /ssf`** describes the family, its gate and what it deliberately does
  not do. Every endpoint is listed live on `/admin/sts-metadata`.
* **Monitoring → Scheduler** (`/admin/scheduler`) lists the dead-letter sweep
  and the stream-maintenance jobs.

Every failure is recorded under an `STS-SSF-NNNN` code. See
[error codes](error-codes.md).

## Related

* [CAEP events](caep-events.md): what triggers each of the eight CAEP events
* [Signals received](signals-received.md): the console and portal as receivers
* [Sessions](sessions.md), [Signing out](signing-out.md): the session acts
  CAEP reports
* [GNAP](gnap.md): GNAP streams and the signals a grant produces
* [SCIM](scim.md), [LDAP](ldap.md): the directory writes RISC reports
* [OAuth 2.0 & OpenID Connect](oauth-oidc.md): getting an `ssf:*` token
* [Trust realms](trust-realms.md), [What is not checked](what-is-not-checked.md),
  [Configuration](configuration.md)
