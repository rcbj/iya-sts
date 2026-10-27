---
title: "Configuring Shared Signals: SSF, CAEP, RISC"
---

# Configuring Shared Signals: SSF, CAEP, RISC

This page shows how to set up iya-sts as a Shared Signals transmitter, and as
a receiver of a federation partner's signals. It covers the receiver to
register, the settings to change, the requests a receiver sends, and what an
operator does when delivery fails. Each recipe is given twice: once as steps
in the **admin console** and once as **Management API** calls.

The values come from this repository's test jobs, and each recipe names the
job it is taken from. Most are in `tests/protocol/` and run against a service
in both development and product mode. The jobs add a run-specific suffix to
every name; it is left off here. Change the identifiers, URLs and secrets to
your own.

How SSF, CAEP and RISC *behave*, and every setting with its default, is on
[Shared Signals](shared-signals.md). What fires each CAEP event is on
[CAEP events](caep-events.md), and the console and portal as receivers are on
[Signals received](signals-received.md). This page covers only what to fill
in. [Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the application attribute forms.

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/ssf` | **Protocols → Shared Signals** | Four tabs. **Metadata**: the endpoints. **Shared Signals**: the `ssf.*` settings and every stream, each with its controls. **CAEP** and **RISC**: each vocabulary's settings, its catalogue of event types, and a form to emit one by hand. |
| `/admin/applications?application=<id>` | **Directory → Applications**, then the receiver's row | Declare the receiver for **Shared Signals**, set its scopes and its per-receiver attributes, and pause or enable its streams on its **Shared Signals** tab. |
| `/admin/caep-sessions`, `/admin/risc-accounts` | **Monitoring → Shared Signals → CAEP sessions**, **RISC accounts** | See what has been said about each session and account. Reset one row, or clear the register. |
| `/admin/signals` | **Monitoring → Shared Signals → Signals received** | See what the console's own receiver was delivered. |
| `/admin/ssf/dead-letters` | **Monitoring → Shared Signals → Dead letters** | Count and search what could not be delivered. |
| `/admin/ssf/transmitters` | **Monitoring → Shared Signals → Signals from partners** | See what federation partners sent, and which sign-ins they blocked. Read only. |
| `/admin/federation` | **Protocols → Federation** | Configure a partner's stream, in the relationship's **Shared Signals from this partner** section. |

Each settings group is saved with its own button: **Save SSF**, **Save CAEP**
and **Save RISC**. The API equivalents are `POST /admin-api/config/set`,
`/config/set-many` and `/config/reset`. The live description of every
stream-side endpoint is `GET /ssf` and `GET /.well-known/ssf-configuration`;
the management operations and their bodies are in `/admin-api/openapi.json`.

**There is no console or API control that creates a stream.** A stream holds
an address this service will dial, so it may only be created by a receiver
that authenticated at `POST /ssf/stream`. What you configure is the receiver's
**application**, and the transmitter's settings. The console then manages the
streams receivers create.

**What development and product mode change.**
* **The Basic password.** Development accepts any name and any password
  except `invalid` over HTTP Basic. Product checks the person's
  `userPassword`, and refuses a person who holds or must hold a second factor
  unless they use an [app password](authentication.md#the-password-only-doors-and-app-passwords)
  scoped to `ssf`.
* **Push addresses.** Both modes push only to `https` with the receiver's
  certificate verified. `ssf.pushAllowHttp` and `ssf.pushSkipTlsVerification`
  loosen that **in development mode only**; product ignores them and refuses
  turning them on. A receiver with a private CA is reached through
  `ssf.pushCaFile`, in either mode.
* **The deliberate defects.** `ssf.legacySubClaim`, `ssf.breakSetSignature`
  and `risc.googleSubjectType` work only in development. See
  [Shared Signals → Deliberate defects](shared-signals.md#deliberate-defects).
* **Acting on what arrives.** A received signal ends sessions, blocks
  sign-ins or revokes grants in product mode. Development records what it
  would do, unless `ssf.actOnSignalsInDevelopment` is on.
* **Subjects of automatic events.** Development invents an `@example.com`
  address for a person with no `mail`. Product uses only real values, and does
  not send RISC's two identifier events when there is none.
* **What survives a restart.** Development keeps streams, queues and both
  registers in memory. Product on postgres persists them.

In **both** modes a token is issued `ssf.read` or `ssf.manage` only if the
client declares a scope granting it in `oauthAllowedScope` and the subject
holds the matching role (`SSF_READ` or `SSF_MANAGE`). Every token is
verified.

---

# The transmitter

## Register a receiver

A receiver is an OAuth 2.0 client declared for **Shared Signals**, with the
two Shared Signals scopes declared. The scopes are the CAEP Interoperability
Profile's names:

| Scope | Lets the caller |
|---|---|
| `ssf.read` | read a stream, its status and the poll queue (`POST /ssf/poll` is a read) |
| `ssf.manage` | everything `ssf.read` does, and create, update or delete a stream, add or remove subjects, change status, and ask for verification |

**Write includes read.** A client that declares only `ssf.manage` may also be
issued `ssf.read` when it holds `SSF_READ` as well. `SSF_MANAGE` does not
authorize `ssf.read` on the token. At the transmitter, a token that already
carries `ssf.manage` still includes read. A client that declares only
`ssf.read` is refused `ssf.manage` with `invalid_scope`. The colon names `ssf:read` and `ssf:write`
are **not** Shared Signals scopes: a client that declares them is refused
`ssf.read` and `ssf.manage`, and a token carrying them is refused by the
transmitter. `ssf.authScopeRead` and `ssf.authScopeWrite` add names of your
own beside the profile names, which stay accepted.

Taken from `sts_ssf_caep_scopes.js` and `sts_ssf_conformance.js`.

**Console:**
1. **Applications → New application ›**.
2. Set **Identifier** to `ssf-conf-a`.
3. Under **Protocol families it is declared for**, tick **OAuth 2.0** and **Shared Signals**.
4. In **The client secret**, click **Generate Secret** and copy the value.
5. Click **Create the application**.
6. On the application's page, in **Change one attribute by name**:
   - **Set** `oauthTokenEndpointAuthMethod` to `client_secret_post`.
   - **Add to** `oauthGrantType` the value `client_credentials`.
   - **Add to** `oauthAllowedScope` the values `ssf.read` and `ssf.manage`.

**API:**
```bash
SECRET=$(openssl rand -base64 32)
api applications/create '{
  "identifier": "ssf-conf-a", "name": "ssf-conf-a", "kind": "oauth2-client",
  "protocols": ["oauth2", "ssf"],
  "fields": {
    "oauthClientId": ["ssf-conf-a"],
    "oauthAllowedScope": ["ssf.read", "ssf.manage"],
    "oauthClientSecret": "'"$SECRET"'",
    "oauthGrantType": ["client_credentials"],
    "oauthTokenEndpointAuthMethod": "client_secret_post"
  }}'
```

**The receiver then gets its token:**
```
POST /oauth2/token
  grant_type=client_credentials&client_id=ssf-conf-a&client_secret=<secret>
  &scope=ssf.read ssf.manage
```

The default access-token lifetime (`oauth2.accessTokenTtlS`, 3600 seconds) is
the profile's sixty-minute ceiling. A token is honoured only while its client
still declares a scope that grants what the call needs: withdraw
`ssf.manage` and the client's tokens can still read but no longer write.

**Other ways to authenticate.** HTTP Basic with a directory person's name and
password works while `ssf.authBasic` is on (the default); Basic carries no
scope, so it gets both. A GNAP access token works too, see [GNAP](gnap.md).
So does the receiver's TLS client certificate, with no `Authorization`
header, when this realm issued it to the receiver's application:
```bash
api applications/issue-tls-client-certificate '{"application":"ssf-conf-a",
  "password":"<a PKCS#12 password>","keyAlg":"ec-p256"}'
```
The application must also be a member of `SSF_READ` or `SSF_MANAGE`, as it
must to be issued a token, and the receiver presents the certificate and its
key on every call (`curl --cert chain.pem --key key.pem ...`). It owns its
streams as `ssf-conf-a`. See
[Shared Signals](shared-signals.md#authentication-four-schemes-two-scopes).
A stream created with a person's own credential carries only events about
that person while `ssf.personStreamsSelfOnly` is on (the default).

**Optional: more names for the receiver.** A stream's `aud` is the identifier
the receiver authenticated as. To let it ask for another, add that name to
`ssfReceiverId` on its application (`sts_ssf_conformance.js` adds
`https://ssf-conf-a.example/web`):
```bash
api applications/add '{"application":"ssf-conf-a","attribute":"ssfReceiverId",
  "value":"https://ssf-conf-a.example/web"}'
```
A stream that names any other `aud` is refused with 400, and `aud` cannot be
changed by an update.

## A poll stream (RFC 8936)

The receiver creates a stream, then polls and acknowledges. Nothing is
dialled. Taken from `sts_ssf_conformance.js`.

The receiver finds every endpoint from the transmitter configuration
metadata, which is never gated:
```
GET /.well-known/ssf-configuration                      # the default realm
GET /.well-known/ssf-configuration/realm/<id>           # a trust realm (SSF 1.0 section 7.2)
```

**Create the stream** (`ssf.manage`):
```
POST /ssf/stream
  Authorization: Bearer <token>
  {"delivery": {"method": "urn:ietf:rfc:8936"},
   "events_requested": [
     "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
     "https://schemas.openid.net/secevent/ssf/event-type/verification",
     "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"]}
→ 201 {"stream_id": "...", "aud": "ssf-conf-a", "events_delivered": [...],
       "delivery": {"method": "urn:ietf:rfc:8936",
                    "endpoint_url": "https://.../ssf/poll?stream_id=..."}, ...}
```

`events_delivered` is the overlap of what the receiver asked for and what the
realm offers (`ssf.eventsSupported`, `caep.eventsSupported` and
`risc.eventsSupported`). A stream starts `enabled`, or as
`ssf.streamStatusOnCreate` says. A receiver may hold `ssf.maxStreams` streams
(25 by default).

**Poll and acknowledge** (`ssf.read`). Use the `endpoint_url` the stream was
given, or name the stream in the body:
```
POST /ssf/poll
  {"stream_id": "<id>", "returnImmediately": true, "maxEvents": 100}
→ 200 {"sets": {"<jti>": "<SET>", ...}, "moreAvailable": false}

POST /ssf/poll
  {"stream_id": "<id>", "ack": ["<jti>", ...], "returnImmediately": true,
   "maxEvents": 0}
```

One poll returns at most `ssf.pollMaxEvents` SETs (20 by default). An
unacknowledged SET may be handed out again. A stream holds at most
`ssf.maxQueuedEvents` undelivered SETs, dropping the oldest.

**The receiver's other calls** are `GET /ssf/stream` (its own streams, or one
with `?stream_id=`), `PATCH` and `PUT /ssf/stream`, and
`DELETE /ssf/stream?stream_id=<id>` (204). Another receiver's stream answers
404, exactly as a stream that does not exist.

## A push stream (RFC 8935)

The service POSTs each SET to the receiver's endpoint, with the
`authorization_header` the receiver chose. Taken from section 7b of
`sts_ssf_conformance.js`, which pushes to the test peer's receiver.

**Settings first.** Push is on by default (`ssf.pushDelivery`). If the
receiver's certificate is issued by a private CA, name that CA in
`ssf.pushCaFile`. To limit where pushes may go, list the hosts in
`ssf.pushAllowedHosts` (empty means any host).

**Console:** on **Protocols → Shared Signals**, tab **Shared Signals**, fill in
**CA certificates for push delivery** (`ssf.pushCaFile`) with a PEM file path the
service can read, and click **Save SSF**.

**API:**
```bash
api config/set '{"key":"ssf.pushCaFile","value":"/run/ca/receiver-ca.pem"}'
```

**The receiver creates its stream:**
```
POST /ssf/stream
  Authorization: Bearer <token>
  {"delivery": {"method": "urn:ietf:rfc:8935",
                "endpoint_url": "https://receiver.example.com/ssf/events",
                "authorization_header": "Bearer push-<random>"},
   "events_requested": [
     "https://schemas.openid.net/secevent/ssf/event-type/verification",
     "https://schemas.openid.net/secevent/risc/event-type/account-disabled"]}
```

A receiver answers a push with 202. A 400 with `{err, description}` records a
refusal. A failed push is not retried unless `ssf.pushRetries` says so (0 by
default), and goes to the stream's dead-letter queue (see
[Dead letters](#dead-letters-and-dead-streams)). The `authorization_header` is
returned only to the receiver that set it, never to the console or
`/admin-api`.

The values `/run/ca/receiver-ca.pem` and
`https://receiver.example.com/ssf/events` are examples. The job uses the test
peer's own CA file and push URL.

**In development only**, `ssf.pushAllowHttp` allows an `http://` endpoint and
`ssf.pushSkipTlsVerification` skips the certificate check. Neither works in
product.

## Subjects

With `ssf.defaultSubjects` at `ALL` (the default), a stream with no subjects
covers everybody, and adding a subject narrows it to the named ones. With
`NONE` it covers nobody until a subject is added. Taken from section 3 of
`sts_ssf_conformance.js`.

```
POST /ssf/subjects/add
  {"stream_id": "<id>",
   "subject": {"format": "iss_sub", "iss": "<the realm's issuer>", "sub": "someone"}}
→ 200

POST /ssf/subjects/add
  {"stream_id": "<id>",
   "subject": {"format": "complex",
               "user": {"format": "iss_sub", "iss": "<issuer>", "sub": "someone"},
               "application": {"format": "opaque", "id": "app"}}}

POST /ssf/subjects/add
  {"stream_id": "<id>",
   "subject": {"format": "ip-addresses", "ip-addresses": ["192.0.2.1"]}}

POST /ssf/subjects/remove
  {"stream_id": "<id>", "subject": {...}}
→ 204
```

A complex subject must carry `"format": "complex"`. Each format accepts only
its own members, and the drafts' names (`issuer_subject_id`,
`decentralized_identifier`) are refused. A stream may name at most
`ssf.maxSubjectsPerStream` subjects (100 by default). Subjects are not
checked against the directory, and `verified: true` is believed.
[Shared Signals → Subjects](shared-signals.md#subjects) lists every format.

## Verify a stream

Verification is the only end-to-end test a stream has. The answer is 204 as
soon as the event is queued; the event itself arrives by the normal delivery
path. Taken from `sts_ssf_conformance.js` and `sts_ssf_caep_scopes.js`.

**The receiver asks** (`ssf.manage`):
```
POST /ssf/verify
  {"stream_id": "<id>", "state": "conf-state"}
→ 204
```
The verification SET echoes `state`, carries a `txn`, and has
`typ: secevent+jwt`.

**An operator asks** (no `state`, because the receiver did not ask):

**Console:** on **Protocols → Shared Signals**, tab **Shared Signals**, find the
stream's card and click **Send a verification event**.

**API:**
```bash
api ssf/verify '{"stream_id":"<id>"}'
```

To send one to every enabled stream on a schedule, set
`ssf.verificationEveryS` (0, meaning never, by default). A receiver that asks
more often than `ssf.minVerificationInterval` (60 seconds) is answered 429
only while `ssf.verificationRateLimit` is on.

## Pause, enable, disable or delete a stream

A **paused** stream keeps queueing and delivers nothing. A **disabled** one
drops its queue. Each change sends `stream-updated` on the stream first,
whether or not the receiver asked for that type. Taken from section 6 of
`sts_ssf_conformance.js`, where a paused poll stream hands out only its
`stream-updated` and holds a RISC `account-disabled` until it is enabled.

**The receiver** (`ssf.manage`):
```
POST /ssf/status
  {"stream_id": "<id>", "status": "paused", "reason": "conformance"}
```

**Console:** on the stream's card, pick the status in **Set the status**, type
a reason if you like (it is shown to the receiver), and click **Set status**.
**Delete this stream** deletes it; the receiver is sent `stream-updated` with
status `disabled` first. A receiver's application page has **Pause** and
**Enable** for each stream it owns, on its **Shared Signals** tab.

**API:**
```bash
api ssf/status '{"stream_id":"<id>","status":"paused","reason":"maintenance"}'
api ssf/delete '{"stream_id":"<id>"}'
```

**To deal with receivers that go quiet**, set `ssf.inactivityTimeoutS` (0,
meaning never, by default) and `ssf.inactivityAction` (`pause`, `disable` or
`delete`). A push receiver never needs to call back after creating its stream,
so leave the timeout off unless your receivers poll.

## Limit what one receiver is sent, and give it its own settings

`ssfAllowedEvents` on a receiver's application limits its streams to `caep`,
`risc`, or named event type URIs. The limit is applied when the stream is
agreed **and** at every delivery. SSF's own verification event is always
allowed. Taken from `sts_ssf_allowed_events.js`.

**Console:** on the application's page, in **Change one attribute by name**,
**Add to** `ssfAllowedEvents` the value `caep`, and again the value
`https://schemas.openid.net/secevent/risc/event-type/account-disabled`.

**API:**
```bash
api applications/add '{"application":"ssf-limited","attribute":"ssfAllowedEvents",
  "value":"caep"}'
api applications/add '{"application":"ssf-limited","attribute":"ssfAllowedEvents",
  "value":"https://schemas.openid.net/secevent/risc/event-type/account-disabled"}'
```

A stream that asks for `session-revoked`, `account-disabled`, `account-purged`
and `verification` is then agreed all but `account-purged`. The attribute is
refused on an application not declared for Shared Signals, and a value that is
not `caep`, `risc` or a known event type is refused by name.

**Per-receiver settings.** An application declared for Shared Signals may
override twenty `ssf.*`, `caep.*` and `risc.*` settings for the streams it
owns, such as `ssfSigningAlgorithm` (`ssf.signingAlgorithm`),
`ssfCaepReasonLanguage` (`caep.reasonLanguage`),
`ssfCaepOmitEventTimestamp`, `ssfMaxStreams`, `ssfPollMaxEvents` and
`ssfPushRetries`. Set each one like any other attribute. The application's
**Shared Signals** tab lists the settings in force for its streams and where
each comes from. The in-process job `tests/ssf_application_settings.js` sets
`ES256` and `fr` and checks that only the owner's stream gets them:

```bash
api applications/set '{"application":"ssf-conf-a","attribute":"ssfSigningAlgorithm",
  "value":"ES256"}'
api applications/set '{"application":"ssf-conf-a","attribute":"ssfCaepReasonLanguage",
  "value":"fr"}'
```

The **Set** form's attribute list offers every override attribute on an
application declared for Shared Signals, and refuses a value the setting would
not take.

## Send CAEP and RISC events

**Most events send themselves.** With `caep.autoEmit` and `risc.autoEmit` on
(the defaults), sign-ins, sign-outs, credential changes and directory writes
send their events. `caep.autoEmitTypes` and `risc.autoEmitTypes` choose which
acts do. [CAEP events](caep-events.md) and
[Shared Signals → SSF is the pipe](shared-signals.md#ssf-is-the-pipe-not-the-vocabulary)
list the triggers.

To send one on demand, for a test or because you know something the service
does not:

### A CAEP event about a session

A CAEP event names a **session**, so the person must be signed in. Taken from
`sts_ssf_oidf_conformance.js`, which signs a person in and emits each event
the OpenID conformance suite asks for.

**Console:**
1. On **Protocols → Shared Signals**, tab **CAEP**, use **Find a person** to pick one of their live sessions.
2. Under **Emit one by hand**, pick the **Event** (for example `session-revoked`), set **Initiated by** to `admin`, and optionally fill **Payload (JSON, optional)**, `reason_admin` and `reason_user`.
3. Click **Emit**.

**API:**
```bash
# find the session
curl -sk "$BASE/admin-api/caep/sessions" -H "Authorization: Bearer $TOKEN"

api caep/emit '{"session_id":"<sessionId>","type":"session-revoked",
  "initiating_entity":"admin"}'
```

Emitting `session-revoked` reports the revocation; it does not sign anybody
out. To end the session, use [Sessions](sessions.md) or
[Signing out](signing-out.md).

### A RISC event about an account

A RISC event names an **account**, which does not have to be one this service
holds. Taken from `sts_ssf_conformance.js` and `sts_ssf_allowed_events.js`.

**Console:** on **Protocols → Shared Signals**, tab **RISC**, under **Emit one
by hand**, type the **Account** (or use **Find an account**), pick the
**Event**, and click **Emit**.

**API:**
```bash
api risc/emit '{"account_id":"alice","type":"account-disabled",
  "reason_admin":"sts_ssf_conformance"}'
api risc/emit '{"account_id":"alice","type":"credential-compromise",
  "payload":"{\"credential_type\":\"password\"}"}'
```

`payload` is a JSON string. `credential-compromise` requires
`credential_type`. The four opt-out events change the account's real opt-out
state when they are sent. Emitting `account-disabled` does not disable
anybody; disabling a person (on their page, through `/admin-api/users/disable`,
SCIM or LDAP) sends it on its own.

An event that no stream takes is not an error: the reply says nothing was
sent. **Monitoring → Shared Signals → CAEP sessions** and **RISC accounts**
show, beside each register, which streams would take each type.

---

# Receiving from a federation partner

A realm can receive a partner's CAEP and RISC events, on a federation
relationship where this service is the **service provider**. A partner that
signs nobody in here (a device manager, an HR system) is a relationship with
protocol `ssf`. Taken from `sts_ssf_foreign_receiver.js`, where realm A is the
partner's transmitter and realm B receives.

**At the partner**, this service needs a client that may manage a stream:
`client_credentials`, with `ssf.read` and `ssf.manage` declared, as in
[Register a receiver](#register-a-receiver). The job registers
`realm-b-receiver` at A that way.

**Console:**
1. On **Protocols → Federation**, under **Add a relationship**, set **Id** to `partner-a`, **This service is** to the service provider, **Protocol** to `oidc` (or `ssf` for a signals-only partner), and **Partner** to the partner's SSF issuer. Click **Add**.
2. On the relationship's page, in **Shared Signals from this partner**, **Set** `fedSignalsTokenUrl` to the partner's token endpoint, `fedSignalsClientId` to `realm-b-receiver`, `fedSignalsClientSecret` to its secret, and `fedSignalsDelivery` to `poll`.
3. **Turn on** `fedSignalsEnabled` (an `ssf` relationship has it on already), and **Turn on** `fedEnabled`.
4. Click **Create stream**. This fetches the partner's `/.well-known/ssf-configuration` and keys first. Then click **Verify**.

**API:**
```bash
api federation/create '{"id":"partner-a","role":"service-provider",
  "protocol":"oidc","peer":"https://partner.example.com"}'
api federation/set '{"id":"partner-a","field":"fedSignalsTokenUrl",
  "value":"https://partner.example.com/oauth2/token"}'
api federation/set '{"id":"partner-a","field":"fedSignalsClientId","value":"realm-b-receiver"}'
api federation/set '{"id":"partner-a","field":"fedSignalsClientSecret","value":"<secret>"}'
api federation/set '{"id":"partner-a","field":"fedSignalsDelivery","value":"poll"}'
api federation/set '{"id":"partner-a","field":"fedSignalsEnabled","value":"TRUE"}'
api federation/enable '{"id":"partner-a"}'
api federation/signals-create-stream '{"id":"partner-a"}'
api federation/signals-verify '{"id":"partner-a"}'
```

The partner URL `https://partner.example.com` is an example; the job uses
realm A's issuer, which it reads from A's configuration document.

* **The partner's issuer** is `fedSignalsIssuer`, or `fedPeer` when that is
  empty. Set it for a SAML or WS-Federation partner, whose entityID is not its
  SSF issuer.
* **Instead of client credentials**, set `fedSignalsBearer` to a token the
  partner issued. `fedSignalsScope` is the scope asked for; empty asks for
  `ssf.manage`. Both secrets are sealed and never shown.
* **`fedSignalsEvents`** lists the event types to ask for. Empty asks for
  whatever the partner supports.
* **A poll stream** is polled every `ssf.foreignPollS` seconds (30 by
  default); **Poll now** (`federation/signals-poll-now`) polls at once. **A
  push stream** (`fedSignalsDelivery` `push`) is given
  `/federation/signals/{id}` and a header only the two services know.
  `fedSignalsDelivery` is read when the stream is created; delete the stream
  and create it again to change it.
* **The outbound connection** is verified against `federation.outboundCaFile`
  where the partner's certificate needs a private CA.

**Link people.** For a sign-in partner, the links its sign-ins wrote are what
its `iss_sub` subjects match. For an `ssf` relationship, link each person
yourself: on their page (**Directory → Users**, **Federation links**, **Link a
partner's subject**) pick the relationship, and fill in the **Subject** and the
**Issuer** its events use.

```bash
api users/federation-link '{"user":"sf-b1","relationship":"partner-a-signals",
  "issuer":"https://partner.example.com","subject":"<the partner sub>"}'
```

An `email` subject is matched only where the relationship sets
`fedSignalEmailMatch`.

**What happens on arrival.** A SET is acted on only if its signature, `typ`,
`iss`, `aud` and a fresh `jti` all check out; product refuses an unverified
one. The `signal-response` XACML policy decides the reaction. By default a
sign-in partner's `account-disabled` blocks that partner's sign-ins of the
person and ends the sessions it started, and `account-enabled` lifts the
block; an `ssf` partner's events are recorded and do nothing. The full table is
in [Shared Signals → Receiving from a federation partner](shared-signals.md#receiving-from-a-federation-partner).
`ssf.signalsRevokeGrants` (on by default) also revokes the person's grants and
tokens on the strongest events. **In development** none of this happens unless
`ssf.actOnSignalsInDevelopment` is on; the job turns it on.

**Unblock** on the relationship's page (`federation/signals-unblock`) lifts a
block by hand. Everything that arrived is on **Monitoring → Shared Signals →
Signals from partners**, and in `GET /admin-api/ssf/transmitters`.

---

# Operating it

## Dead letters and dead streams

A SET that cannot be delivered goes to its stream's dead-letter queue, with
the reason, the error code and the receiver's HTTP status. A push stream whose
pushes have all failed for `ssf.deadStreamTimeoutS` (300 seconds) is declared
**dead** and paused: nothing more is pushed to it, and once per timeout the
oldest dead letter is pushed as a probe. A probe that succeeds revives the
stream. Taken from the in-process jobs `tests/ssf_dead_letters.js` and
`tests/ssf_dead_letter_report.js`.

**To see what is held:**

**Console:** **Monitoring → Shared Signals → Dead letters** counts every held
SET by cause, error code, receiver status, event type, time and stream, then
lists the letters (without their tokens). Narrow the list with the search box,
a stream, or a cause. Each stream row links to that stream's card on
**Protocols → Shared Signals**, where its controls are.

**API:**
```bash
curl -sk "$BASE/admin-api/ssf/dead-letters?dlcause=dead-stream" \
  -H "Authorization: Bearer $TOKEN"
curl -sk "$BASE/admin-api/ssf/dead-letters?dlstream=<id>&dlq=account-disabled" \
  -H "Authorization: Bearer $TOKEN"
```
The causes are `push-failed`, `backlog-full`, `declared-dead` and
`dead-stream`. The counts are always the whole realm's; the filters narrow
only the letters.

**To act, once the receiver is fixed:**

**Console:** on the stream's card, **Revive this stream** enables a dead
stream and pushes what it held. **Drop its dead letters** deletes them.
Nothing else resends a dead letter.

**API:**
```bash
api ssf/revive '{"stream_id":"<id>"}'
api ssf/clear-dead-letters '{"stream_id":"<id>"}'
```

A stream the receiver or an operator paused is never enabled by a revival.

**The settings that shape this:**

| Setting | Default | Why you would change it |
|---|---|---|
| `ssf.pushRetries` | `0` | Retry a push that failed for a reason that might go differently (no connection, timeout, 5xx, 429). |
| `ssf.pushRetryDelayMs` | `1000` | The wait before a retry, times the attempt number. |
| `ssf.pushTimeoutMs` | `10000` | How long a receiver has to answer. |
| `ssf.deadStreamTimeoutS` | `300` | How long a push stream must fail before it is dead. `0` turns this off. |
| `ssf.deadLetterRetentionS` | `3600` | How long a dead letter is kept. |
| `ssf.deadLetterMaxPerStream` | `1000` | The most letters one stream keeps; the oldest goes first. |
| `ssf.pushConcurrency`, `ssf.pushBacklog` | `8`, `2000` | Pushes in flight per process, and waiting per receiver. Past the backlog a SET is dead-lettered. |

The `ssf.dead-letter-sweep` and stream-maintenance jobs are on
**Monitoring → Scheduler**. Failures are logged once per stream (when it dies
and when it revives) and once per sweep as a summary.

## Send a SET by hand on one stream

To test a receiver's handling of one event type, an operator can send a SET on
one stream without any act behind it.

**Console:** on the stream's card, pick the type in **Transmit an event**,
fill in the payload and an optional `sub_id` as JSON, and click **Transmit**.

**API:**
```bash
api ssf/transmit '{"stream_id":"<id>",
  "type":"https://schemas.openid.net/secevent/ssf/event-type/verification",
  "payload":{"state":"a-value-the-receiver-chose"}}'
```

The type must be one the stream delivers. Unlike the CAEP and RISC emit
forms, this sends on the one stream only.

## The console's and portal's own receivers

Each realm seeds two receiver streams, for the console and the portal, while
`ssf.internalReceivers` is on (the default; read at start). There is nothing
to configure. **Monitoring → Shared Signals → Signals received** shows what
the console's receiver was delivered, and `/portal/signals` shows a person
theirs. An empty page has five causes; [Signals received](signals-received.md)
lists them. A person can opt out of RISC sharing on `/portal/signals`; the
opt-out takes effect after `risc.optOutDelayHours` (24).

## Running several nodes

Every node needs the same `global.port`, and `global.publicBaseUrl` must be
pinned, because it becomes every SET's `iss`. See
[Shared Signals → Development and product mode](shared-signals.md#development-and-product-mode).

## Related

* [Shared Signals](shared-signals.md): every setting, and why.
* [CAEP events](caep-events.md): what fires each CAEP event.
* [Signals received](signals-received.md): the console and the portal as receivers.
* [Federation](federation.md): the relationships a partner's signals arrive on.
* [GNAP](gnap.md): GNAP streams and GNAP tokens at `/ssf/*`.
* [Management API](management-api.md): the token, and the OpenAPI document at `/admin-api/openapi.json`.
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md): the client credentials grant the receivers use.
