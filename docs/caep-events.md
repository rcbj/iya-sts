---
title: CAEP events
nav_order: 11
---

# The eight CAEP events, and what makes each one fire

This service is a **CAEP transmitter**. The Continuous Access Evaluation Profile
1.0 (final, 2 September 2025) is a vocabulary about **sessions** spoken over
[Shared Signals](https://openid.net/specs/openid-sharedsignals-framework-1_0.html);
SSF is the pipe and defines two events of its own about the pipe, and these
eight are about a session. The sentence they exist to carry is *this session is
no longer trustworthy* — which is a different sentence from RISC's *this account
is no longer trustworthy*, and the whole reason there are two profiles.

This page answers one question in depth: **what, in this service, actually
causes each of the eight to be emitted.** The catalogue of members — every
member of every event, its type, whether it is required, and what it means — is
published live at `GET /admin/caep` and `GET /admin-api/caep`, read off the same
table the code emits from; go there for the full shape rather than to a copy on
this page. What is here instead is the part no endpoint can tell you: the
trigger.

The short version:

| Event | Emitted by this service on its own? |
|---|---|
| `session-established` | **yes** — every sign-in, through every protocol that starts a session |
| `session-presented` | **yes** — single sign-on, in four browser SSO profiles |
| `session-revoked` | **yes** — every sign-out, and every expiry |
| `token-claims-change` | **yes** — a directory change, a role, an identity verification, an address proved, a claims provider unlinked, or a configuration change (permissions, allowed scopes, claim sets, claim settings, a federation release list) that moves a claim of somebody holding live tokens or assertions, and a modified [GNAP](gnap.md) grant |
| `credential-change` | **yes** — any credential of a person created, changed, revoked or deleted, at every door that changes one |
| `assurance-level-change` | **yes** — a re-authentication on a held session that moves its `acr`, and an identity verification recorded or removed that moves a person's identity assurance level |
| `device-compliance-change` | no — by hand only, until [#164](https://github.com/rcbj/iya-sts/issues/164) gives it a source |
| `risk-level-change` | **yes** — when a person's risk level changes and the `risk-response` policy permits announcing it ([Risk scoring](risk-scoring.md#when-a-persons-risk-changes)) |

## Three gates every event passes, whatever fired it

An event reaching a receiver has cleared all three. Most reports of "nothing
arrived" are the third.

1. **Is CAEP on at all.** `caep.enabled` (default on). With it off the eight
   types are dropped from `events_supported`, so a stream asking for one gets it
   back missing from `events_delivered` — which is the only notice SSF gives a
   receiver, and exactly the case a receiver ought to be tested against.
   `caep.eventsSupported` narrows the eight without turning the profile off.
2. **Did something fire it.** For the automatic ones, `caep.autoEmit`
   (default on) and `caep.autoEmitTypes` (default: all seven — the three
   session events, `credential-change`, `assurance-level-change`, which goes
   out when the same person re-authenticates on a session they already hold
   and its `acr` changes, on the `urn:sts:acr` scale, and when their identity
   assurance level moves, on `urn:sts:ial` or `NIST-IAL`, `token-claims-change`,
   and `risk-level-change`).
   Naming any other type in
   `autoEmitTypes` is **dropped with a warning** rather than
   honoured — no code path here would ever fire it, and a setting that reads as
   configured and does nothing is worse than one that refuses.
3. **Does a stream take it.** A stream must both deliver that type *and* cover
   that subject. If none does, the event is still applied to the register and
   shown on `/admin/caep-sessions` **with nothing sent** — which is what makes
   "nothing arrived" traceable to "nobody asked" rather than to a bug. The log
   line at `info` says so once, naming the type and the subject, and the
   *Per application* table on that page says it per receiver: a row with no
   stream, or one whose *Takes* column is empty, is the answer.

   **An application's entry can narrow it further.**
   `ssfAllowedEvents` on the application that owns the stream lists what it may
   be sent — `caep`, `risc`, or individual event type URIs, one per line. Empty
   means no limit. A stream is agreed only those types when it is created or
   updated, and every delivery checks again, so removing a value stops existing
   streams receiving it. Lifting a limit does not hand back a type that was
   withheld when the stream was agreed: the receiver asks for it again. SSF's own
   verification and stream-updated events are always allowed. The same rule
   applies to RISC events.

**What a session IS here — the browser sign-on session these events are about,
and the two other things this service also calls a session — is
[Sessions](sessions.md).**

**A session that isn't in the register can't be the subject of anything.** The
register is capped at `caep.maxSessionsTracked` (default 200) and drops the
oldest. A row is created by a **session this service starts** — a browser
sign-on, and also a WS-Trust exchange, a SCIM client and a SPIRE Server API
caller, each of which is a session here (see *Sessions that are not a browser's*
at the foot of this page) — or by an event naming a session nothing here has
held, which is marked as such. There is nothing to emit about an LDAP bind or
a Kerberos ticket; see *What never produces one*.

**A session nobody signed in to is never announced.** A browser that arrives
at a protocol's front door with no cookie is given an anonymous tracking
session (it is how the flow is followed on `/admin/sessions`), and nobody has
chosen it: it gets no `session-established`, and so its expiry or removal
sends no `session-revoked` either. When the person signs in, the same row
becomes their session and is announced from then on.

## The subject: why it names two things

Every one of the eight is `subject: required`, and this transmitter composes
SSF's **complex** subject rather than a plain one:

```json
{
  "format":  "complex",
  "user":    { "format": "iss_sub", "iss": "…", "sub": "…" },
  "session": { "format": "opaque", "id": "…" }
}
```

The person is not revoked — **one session of theirs is**. A subject naming only
the person asks a receiver to end every session they have, which is a much
larger instruction than the one that was meant. `user` is an issuer/subject pair
because that is the identifier a receiver already holds (an ID Token's `iss` and
`sub`); `session` is `opaque` because a session identifier has no shape anybody
else can parse.

**The failure this shape invites** is a receiver that reads `user`, ignores
`session`, and signs the person out everywhere. `ssf.criticalSubjectMembers`
publishes `session` as a critical member, which obliges a receiver that does not
understand it to refuse the event instead — and it **ships empty**, deliberately,
so that both behaviours can be produced. Set it to `session` to find out whether
a receiver under test honours it.

## The four claims every event may carry

CAEP section 2 gives all eight the same four, and **all four are optional**:
`event_timestamp`, `initiating_entity`, `reason_admin`, `reason_user`.

Two of them are worth knowing before you read the rest of this page:

- **`event_timestamp` being optional surprises people**, because a receiver
  deciding whether to end a session wants it more than anything else in the
  payload — and a conforming transmitter need not send one.
  `caep.omitEventTimestamp` produces exactly that event on purpose. It is *not*
  the SET's `toe` and it is *not* `iat`: a transmitter may legitimately send
  both, and a receiver reading only one of them from a transmitter that sends
  only the other reads nothing at all.
- **`reason_admin` and `reason_user` are objects keyed by a language tag** —
  `{"en": "…"}` — not strings, which is the commonest way they are got wrong.
  `caep.includeReasons` (default on) and `caep.reasonLanguage` (default `en`)
  control them.

---

# The three session events this service emits by itself

## `session-established`

**What fires it: every sign-in, through every protocol that starts a session.**

There is one funnel — `authn.startSession()` — so this is protocol-independent
by construction rather than by six call sites remembering to do it. The callers:

| Activity | `via` on the event |
|---|---|
| Somebody types a name at `/authn/login`, reached from an OAuth 2.0 / OIDC authorization request | `OAuth 2.0 / OIDC` |
| The same screen reached from a WS-Federation `wsignin1.0` | `WS-Federation` |
| The same screen reached from a SAML 2.0 `AuthnRequest` | `SAML 2.0` |
| The same screen reached from a SAML 1.1 inter-site transfer | `SAML 1.1` |
| A Kerberos ticket spent at `/authn/spnego` — integrated authentication, no screen | `Kerberos v5 (SPNEGO)` |
| A wallet's presentation, collected at `/authn/wallet/wait` by the browser that started the sign-in | `OpenID4VP (a wallet)` |
| A federated assertion accepted at `/federation/acs/{id}` — the person signed in at a *foreign* identity provider | `Federation (SAML 2.0)`, and the same for the other four federation protocols |
| A WS-Trust exchange that signs somebody in | `WS-Trust` and the operation |
| The first call of a SCIM client, whatever scheme it authenticated with (each call after it is a `session-presented`) | `SCIM` |
| The first call of a SPIRE Server API caller, keyed by its SPIFFE ID (the same) | `SPIRE Server API` |

A re-authentication is a *new* session and therefore a new
`session-established`: `prompt=login` at the authorization endpoint, SAML 2.0's
`ForceAuthn` or a stale session against its freshness demand, and a
WS-Federation `wfresh` too old all end at the screen rather than being answered
from the session that exists.

**What it carries beyond the common four:** `acr` and `amr` off the session, and
`ext_id` — this transmitter's own identifier for the session, so a receiver can
correlate. `amr` is an **array**: a session authenticated by a password *and* a
security key has two values, and a receiver that read a string would see one.
`fp_ua` is the user agent's fingerprint: the base64url SHA-256 of the
`User-Agent` header the sign-in arrived with. It is a
fingerprint and not the header, which is what CAEP asks for. A session
established without a request to read one from goes without it.

**Why it matters more than it looks:** it is what closes the loop. Without it a
receiver only ever hears about sessions *ending*, so it cannot hold an inventory
of what is open and cannot notice a sign-in it did not expect.

**In the register:** sets the row's state to `established` and records `acr` and
`amr`. Establishing a session whose row is already `revoked` is carried with a
**warning** rather than refused — the same identifier can legitimately be reused,
and a receiver that kept the revocation will ignore everything about it from
here on, which is worth being able to see.

## `session-presented`

**What fires it: an existing session presented at a browser SSO endpoint and
honoured without a new authentication — which is single sign-on.**

Unlike the other two automatic events, this one has **no funnel**. A
presentation is something each endpoint decides it is doing, so it fires from
exactly four call sites, one per browser SSO profile — and from
`authn.startSession()` when a SCIM client or a SPIRE Server API caller
presents its credential again (*Sessions that are not a browser's*, below):

| Protocol | Activity | `via` |
|---|---|---|
| OAuth 2.0 / OIDC | an authorization request at `/oauth2/authorize` answered out of a session that already existed — no screen drawn | `OAuth 2.0 / OIDC` |
| SAML 2.0 | an `AuthnRequest` at `/saml2/sso`, over any of the three bindings, that reaches the answer step on an existing session | `SAML 2.0` |
| SAML 1.1 | an arrival at the inter-site transfer service carrying a `TARGET`, answered on an existing session | `SAML 1.1` |
| WS-Federation | a `wsignin1.0` at the passive requestor endpoint answered on an existing session | `WS-Federation` |

All four go through `authn.notePresented()`, which is protocol-independent: the
event names the **session**, and `via` records which door it came back through.

**The first presentation of a brand-new session is swallowed.** Every sign-in
here ends with the browser returning to the endpoint that sent it away, which is
technically a presentation — so without this rule the simplest possible flow
would emit `session-established` and `session-presented` milliseconds apart,
every time, and the event that is supposed to mean *single sign-on happened*
would mean nothing. A flag set when the session is created is spent by the first
presentation, so it is exact rather than a time window, and it is spent **across
protocols**: a sign-in at `/saml2/sso` followed by an OIDC authorization request
reports exactly one presentation between them — the OIDC one, named
`OAuth 2.0 / OIDC`.

Per-protocol edges:

- **OIDC** — `prompt=login` skips the branch entirely (screen → a new session).
  `prompt=none` on a live session **does** emit. It fires *above* the consent
  check, deliberately: the session was presented and honoured whatever the
  person then answers about scopes.
- **SAML 2.0** — `ForceAuthn`, or a session older than the request's freshness
  demand, never reach the answer step. `IsPassive` with nothing usable, and a
  sign-in that came back carrying an authentication error, answer with a status
  `Response` and emit nothing.
- **WS-Federation** — the call sits in the branch that answers from the
  session, which a `wauth` the session cannot meet never reaches: that request
  is sent to sign in again (a re-authentication, which reports itself), or
  refused if the one attempt did not produce the factor. A `wfresh` too old
  never reaches it either and re-authenticates instead.
- **SAML 1.1** — that profile has no `ForceAuthn` and no
  `RequestedAuthnContext`, so every arrival with a session is either single
  sign-on or that session's own sign-in coming back — exactly the pair the rule
  above tells apart.

**What it carries beyond the common four:** `ext_id`, and `fp_ua` — *the user
agent observed this time*, whose whole value is comparing it against the one on
the `session-established` event. The same session presented from a different
agent is the abnormality this event exists to make visible. Both events carry
the same fingerprint of the `User-Agent` header, so the
comparison is a string match.

**In the register:** sets the state to `presented` — **except** on a session the
register holds as `revoked`, which is **the one hard refusal in the whole state
machine**. That sentence says a session this transmitter has already declared
dead was just used and honoured, which is either a transmitter contradicting
itself or a receiver about to be told to trust something it was told to stop
trusting. Everything else that looks wrong is a warning; this is an error.

## `session-revoked`

**What fires it: every way a session ends.** Like `session-established` it has a
funnel — `authn.dropSession()` — and every sign-out door in the service goes
through it:

| Activity | `initiating_entity` | `reason_admin` says |
|---|---|---|
| `GET /oauth2/logout` — OpenID Connect RP-Initiated Logout | `user` | ended at *the sign-out endpoint for this browser* |
| `GET\|POST /wsfed?wa=wsignout1.0` — WS-Federation 1.2 section 13.2.4 | `user` | the same |
| `GET\|POST /saml2/slo` — SAML 2.0 Single Logout, from the browser or a service provider's back channel | `user` | the same, or *saml2-slo* and the service provider |
| `GET\|POST /logout` — the protocol-independent sign-out | `user` | ended at *the /logout endpoint* |
| the **Sign out** button on `/admin`, `/portal` or the protocol debugger — the person signing themselves out, and the sign-on session behind it | `user` | *the Sign out button on the admin console* (or the portal, or the debugger) |
| a federation partner's own sign-out reaching this service | `user` | *the federation partner …* |
| `/admin/logout` — an operator signing somebody else out | **`admin`** | ended at *the admin console at /admin/logout* |
| `/admin/sessions` — the Revoke button on a row | **`admin`** | ended at *the /admin/sessions page* |
| `POST /admin-api/logout/{global,end}` | **`admin`** | ended at *the admin console at /admin/logout* — it calls the same function that page does |
| `POST /admin-api/sessions/revoke` | **`admin`** | ended at *the management API at /admin-api/sessions* |
| an account **disabled** on `/admin/users`, `/admin-api/users/disable`, SCIM `active: false` or an `ldapmodify` of the lock | **`admin`** | *the account was disabled by an administrator …* |
| a person **deleted** — SCIM `DELETE` or an LDAP delete ([#241](https://github.com/rcbj/iya-sts/issues/241)) | **`admin`** | *the deletion of the account (…)* |
| a trust realm **removed** — every session in it ([#232](https://github.com/rcbj/iya-sts/issues/232)) | **`admin`** | *the removal of the trust realm "…"* |
| a federation link removed from a person, or a registered device removed or marked compromised by an administrator | **`admin`** | the act, in words |
| an **emergency key rotation** — every session of the realm | **`admin`** when an administrator requested it, **`system`** otherwise | *an emergency key rotation* |
| **risk scoring** ending or disabling a person, and a received SET's signal-response rule | **`policy`** | *the person's risk went to …* |
| the relying-party session a surface could not renew | **`system`** | *a token renewal that did not complete* |
| **the session lifetime running out** | **`policy`** | *the session lifetime ran out* |

`initiating_entity` is **stated by the door that ends the session** — it is
not read out of the sentence in `reason_admin`. Until
[#242](https://github.com/rcbj/iya-sts/issues/242) it was: the phrase was
searched for `admin` or `console`, which made the console's own Sign out button
an administrator ending the session of a person who signed themselves out, and
an emergency rotation and the risk engine the person. A session ended by a
door that says nothing is reported as `system` and logged (`STS-AUTHN-0290`).
A session derived from another — the console's or the portal's own session —
ends with its parent's entity.

The last row is the one worth knowing about. An expiry used to be silent: the
session was deleted with no event, and only *lazily* — when it was next looked
up — so somebody who closed their browser was never looked up again and nothing
ever fired at all, while the receiver that had been told the session was
established was told nothing when it ended. A sweep now runs every 30 seconds,
inside every trust realm, so the event goes out whether or not anybody comes
back to look.

`initiating_entity` on that one is **`policy`** and not `user` or `system`:
nobody signed out, a lifetime this service configured ran out, and that is what
CAEP section 2 means by a policy evaluation. `reason_user` says *"Your session
expired. Sign in again to carry on."* rather than *"You have been signed
out."* — a receiver that showed the second sentence would send somebody looking
for who signed them out.

**What it carries beyond the common four: nothing at all.** There is no
event-specific member, and that is not an oversight — everything it has to say
is in the subject and in the four common claims. Where the subject is a complex
one, the revocation applies to any session matching **every** part of it at once.

**In the register:** sets the state to `revoked`. A second revocation is a
**warning** rather than an error: it is harmless, a receiver should be
idempotent about it, and that is exactly the thing worth testing.

**One thing it deliberately does not do:** revoking tokens does not end a
session here, so `POST /admin-api/tokens/revoke-user` and the bulk buttons on
`/admin/tokens` emit nothing. A session outlives its tokens; ending it is the
act this event reports.

**GNAP is the exception, and it is not a contradiction.** A GNAP
grant is itself a DELEGATED SESSION between a client instance and a resource
owner — it has a lifetime, a continuation and a revocation of its own — so
revoking one IS ending a session, and this event says so. Three acts send it,
each with a complex subject whose `user` is the resource owner and whose
`session.id` names what ended:

| Act | `session.id` |
|---|---|
| `DELETE` on a grant's continuation URI, or *Revoke* on `/admin/gnap` | `gnap-grant:<grant>` |
| `DELETE` on an access token's management URI | `gnap-token:<jti>` |

A grant **modified** onto different access sends `token-claims-change` instead,
carrying the new `access` in `claims`. `gnap.caepEvents` turns all three off. A
stream OWNED by a GNAP web application — created with that application's own
GNAP access token — hears only about people who approved a grant to it; see
[GNAP](gnap.md).

---

# The five you can emit by hand

These five began as the ones this service had no way of observing, and all
five can be emitted **by hand**. Three have since gained an automatic trigger
as well — `credential-change` when any credential of a person changes,
`assurance-level-change` when a re-authentication moves a session's `acr`, and
`token-claims-change` when a directory change moves a claim somebody's live
tokens carry, or a GNAP grant is modified (see the table at the top) — and a
fourth, `risk-level-change`, when a person's risk level changes (#62) or a
registered device's (#164). **The fifth, `device-compliance-change`, is sent
since #164** whenever a device's compliance moves — set by an administrator,
the MDM feed or development's test control ([Devices](devices.md)). Emitting
by hand is still worth having: these are exactly the events a receiver is
hardest to test against, because in a real deployment they arrive from systems
you do not control.

Two doors, one function behind them, so a form and a script produce the same
bytes:

- **`/admin/caep`** — pick a session, pick a type, fill in a JSON payload, add
  `initiating_entity` (the form defaults it to `admin`), `reason_admin` and
  `reason_user`. The chooser offers only **live** sessions, because emitting
  about one that has already been revoked is mostly a way to produce the
  register's one hard refusal by accident.
- The API is less fussy on purpose: it will emit about any session the register
  still **holds**, revoked ones included, because reproducing exactly that
  refusal is a thing a test needs to do deliberately.
- **`POST /admin-api/caep/emit`** — `{ "session_id": "…", "type": "…",
  "payload": {…}, "initiating_entity": "…" }`. Short names are accepted as well
  as whole URIs. A type that is not one of the eight is refused *with the list
  of eight*; a session the register does not hold is refused saying so, because
  there would be nothing to compose a subject from.

Every payload is **validated before it is sent**, and the refusal names what was
wrong rather than silently sending something a receiver will drop. Refused: a
required member missing; a closed enum with a value not on it; `amr` as a bare
string where an array is meant (*a session authenticated two ways has two
values, and wrapping would hide a sender that can only ever say one*);
`event_timestamp` as a quoted number (*a quoted timestamp parses everywhere and
is compared numerically nowhere*); `reason_admin` or `reason_user` as a string
rather than a language map.

Two things are **carried with a warning** rather than refused, and both are
deliberate: an **open** enum's unlisted value, because refusing would make this
service unable to carry a vendor's own type — precisely what a mock is for — and
a member the event does not define, because an event vocabulary extends and a
receiver is expected to ignore what it does not know.

**Every one of the five also has a sensible default payload**, so an emit with an
empty body still produces a conforming event — which is what makes the form
usable before you have read the specification.

## `token-claims-change`

*A claim behind the token changed while the token is still valid — a role, a
group, a tenant.* It is the event that makes the access-token-lifetime argument
go away: the receiver does not have to wait for a refresh to find out that
somebody left the group that authorises them.

- **Required:** `claims` (an object).
- **The trap:** it is neither a whole token nor a diff. It carries **only the
  claims that moved, with their new values**, and a receiver applies them over
  what it holds. So *a group membership taken away is the new **list*** rather
  than the group that went — which catches people.
- **In the register:** the claims are **merged** into the row, not replaced,
  for that same reason. A `token-claims-change` about a session already
  `revoked` is a warning: nothing is wrong with saying so and there is nothing
  left to apply it to, which is what makes it worth noticing.
- **Default payload:** `{"groups": ["everyone"]}`.
- **Sent by itself** when a directory write moves a claim of
  a person who **holds something live** — a valid access, ID or refresh token,
  or an unexpired SAML assertion — and a stream takes the type:
  - an attribute the claim catalogue maps (`mail` is `email`, `l` is
    `address.locality`, and so on): the claim, with its new value, or `null`
    for one now empty;
  - a group joined or left, or a group renamed, and a person's own `memberOf`:
    the groups claim, with the whole list as it is now.
  - a **role** given or taken away (`/admin/roles`, `/admin-api/roles`, or an
    `ldapadd`, `ldapmodify`, `ldapdelete` or rename under `ou=roles`), for
    each person it named or whose group it named: the roles claim as it is
    now, or `null` when they hold no configured role any more. A description
    edited moves nobody;
  - a group joined or left **that a role names**: the roles claim beside the
    groups claim;
  - `email_verified`, when the address is proved (a verification link, a
    trusted door writing it) or changes;
  - an **identity verification** recorded, removed or recorded by a sign-in
    ([Identity Assurance](oauth-oidc.md#verified-claims-openid-connect-for-identity-assurance-10)): `verified_claims` as a token
    could carry it — each verification's `trust_framework` and
    `assurance_level` with the claims still current on the entry, **never its
    evidence**. A sign-in that rewrites its own automatic record with the same
    claims sends nothing;
  - a **Claims Provider** unlinked, or removed for everybody who linked it:
    `_claim_names` and `_claim_sources` with that provider's members `null`.
    **A source's value is never sent** — it holds a distributed source's access
    token or another issuer's signed claims.
  The door does not matter: the console, `/admin-api`, SCIM, an `ldapmodify` of
  the person or of a group. A person with nothing live gets no event, because
  it would be about tokens that do not exist. The subject names the person
  (`iss_sub`), since the change is to every token they hold rather than to one
  session.
- **Sent to every holder** when a CONFIGURATION change moves a claim in
  tokens already issued — one event per person holding a live artifact it
  shaped, with the value their newest such artifact would carry now:
  - a delegated permission revoked from a client (where grants are enforced:
    product mode, or `oauth2.delegatedPermissionsEnforced`), a permission
    removed from its resource, or an allowed scope removed that the scope
    policy now refuses: `scope`, less what went;
  - a custom claim added, changed or removed, or a directory attribute
    selected or dropped, on the access-token, ID Token or SAML claim sets;
  - `roles.claim`, `roles.claimName` and the `groups.claim*` settings: the
    claim under its old and new name;
  - a federation partner's release list edited, enabled, disabled or deleted:
    the claims now released or withheld for that application.

  The holders are walked **in slices of 100**, each slice's deliveries
  finished before the next starts on a later turn of the event loop, behind
  the push cap (`ssf.pushConcurrency`) — so a change touching thousands of
  holders runs in the background and answers requests throughout. Adding a
  grant or a scope sends nothing (a token carries what was asked for), and so
  does `appRequiredRole`, which changes who may be issued a token rather than
  any claim in one. The UserInfo claim set sends nothing: a UserInfo response
  is built on every call. **An application's own tokens** (a
  `client_credentials` grant, with no person) are not the subject of these
  events yet — see [#221](https://github.com/rcbj/iya-sts/issues/221).

## `credential-change`

*A credential was enrolled, renewed, revoked or deleted.* It is the event a
receiver acts on **without ending anything**: a second factor being deleted does
not invalidate the session it was used to establish, and it does change what that
session should be allowed to do next.

- **Required:** `credential_type` and `change_type`.
- `change_type` is **closed** — `create`, `revoke`, `update`, `delete`. Those
  four are the whole lifecycle and a fifth would be a receiver guessing.
- `credential_type` is **open** — `password`, `pin`, `x509`, `fido2-platform`,
  `fido2-roaming`, `fido-u2f`, `verifiable-credential`, `phone-voice`,
  `phone-sms`, `app` — and a value not on that list is carried with a warning,
  because the specification allows types two parties agree between themselves.
- **Optional and worth sending:** `friendly_name` (for a screen, not for a
  decision); `x509_issuer` and `x509_serial` together, because serial numbers are
  unique per *issuer* and not globally, so the second is useless without the
  first; `fido2_aaguid`, which names a *model* of authenticator rather than the
  individual one, which is what makes it publishable.
- **In the register:** appended to a short list of credential changes on the row
  (the last ten). It changes no state and produces no warning — nothing about
  this event contradicts anything.
- **Default payload:** `credential_type: password`, `change_type: update`.
- **Sent by itself** at every door that changes a person's credential:

  | Credential | `credential_type` | Doors |
  |---|---|---|
  | Password | `password` | `/admin/users` and `/admin-api` (set, reset, reset link, a new person), the portal (change, account activation, reset link), a change forced at sign-in, an LDAP add or modify of `userPassword` |
  | Security key | `fido2-platform` or `fido2-roaming`, with `fido2_aaguid` | enrolled at sign-in or on the portal, removed on the portal or the console |
  | Authenticator app | `app` | set up at sign-in, on the portal or at activation; removed on the portal or the console |
  | Certificate | `x509`, with `x509_issuer` and `x509_serial` | ACME, EST and SCEP issue and revoke, a TLS client certificate, an RFC 7523/7522 signing key pair, a person's certificate revoked on `/admin/pki`, and an act on the certificate authority above it (below) |
  | Wallet credential | `verifiable-credential` | issued over OpenID4VCI, disowned by a global sign-out |

  A security key is `fido2-platform` when the browser reported a platform
  authenticator at enrolment, and `fido2-roaming` otherwise. A key enrolled
  before the attachment was recorded has none and stays `fido2-roaming`, with
  no AAGUID. Recovery codes have no CAEP type; they send RISC's
  `recovery-information-changed`. `initiating_entity` is `user` when the person
  did it themselves, `admin` when somebody else did, and `system` for a
  certificate superseded by its renewal or a credential disowned by a
  sign-out.

  **An act on the certificate authority reaches every person under it
  ([#244](https://github.com/rcbj/iya-sts/issues/244)).** When an administrator
  revokes an Issuing CA or an Intermediate on `/admin/pki`, every person holding
  a live certificate beneath it is sent `revoke`. When the reason is
  `keyCompromise` or `cACompromise`, they are also sent RISC
  `credential-compromise` with `credential_type` `x509`.

  Building a Root, rebuilding a realm's branch, reissuing, renewing or importing
  an Issuing CA, or removing the realm's authority sends each affected person
  one of two change types:

  - `update`, naming the new certificate, when this service re-issued it. This
    applies to a TLS client certificate after a reissue, a renewal or an import.
  - `revoke`, naming the old certificate, when the certificate now chains to an
    authority that is gone or revoked. This applies to a signing key pair, to
    anything enrolled over ACME, EST or SCEP (this service keeps no key to
    re-issue those from), and to a TLS client certificate after a branch
    rebuild.

  A certificate that an earlier act already orphaned is not announced again.
  The events go out in batches, so a realm with thousands of certificates does
  not flood the queue.

## `assurance-level-change`

*The strength of the authentication behind this session moved.* **A decrease is
the interesting one**, and it is easy to forget it can happen at all: a second
factor that has expired, or a session carried forward past the window its step-up
was good for, both lower assurance without anybody signing in again.

- **Required:** `namespace` and `current_level`.
- `namespace` is required because **the event is useless without it**: "AAL2"
  means nothing until you know it is NIST's. The list is open —`RFC8176`,
  `RFC6711`, `ISO-IEC-29115`, `NIST-IAL`, `NIST-AAL`, `NIST-FAL` — and an
  unlisted one is carried with a warning. It defaults to
  `caep.assuranceNamespace` (`NIST-AAL`).
- `current_level` is a **free string**, precisely because the namespace decides
  its shape.
- **Optional and worth sending:** `previous_level` — without it a receiver can
  see that assurance changed and not whether it went *up*. And
  `change_direction` (`increase` / `decrease`), said outright rather than
  inferred, because a receiver cannot order two levels in a namespace it does not
  understand, which is the ordinary case across two organisations.
- **In the register:** the row's assurance is replaced. If the event's
  `previous_level` disagrees with what the register holds, a **warning** says so:
  one event about this session has been missed, or two transmitters are talking
  about it.
- **Default payload:** the configured namespace and `aal2`.
- **Sent by itself** in two cases:
  - a re-authentication on a held session moves its `acr`, on this service's
    own `urn:sts:acr` scale, about the session;
  - an **identity verification** recorded, removed or recorded by a sign-in
    moves the person's **identity assurance level**, about the person. The
    level is the `assurance_level` of their newest verification that states
    one, carried as recorded in this service's namespace **`urn:sts:ial`** —
    mapping an arbitrary trust framework onto NIST's levels would claim a
    conformance nobody assessed. **`NIST-IAL` is used only when that
    verification's `trust_framework` is `nist_800_63A`** and its level is
    `IAL1`, `IAL2` or `IAL3`. `urn:sts:ial` has two values of its own:
    `verified` (verifications stating no level) and `none` (nothing
    recorded). `previous_level` is sent only when the namespace did not
    change, and `change_direction` only where the levels have an order
    (IAL1 < IAL2 < IAL3; `none` < `verified` < a stated level).

## `device-compliance-change`

*The device the session runs on fell out of, or back into, compliance with
whatever the estate's policy is.*

- **Required:** **both** `previous_status` and `current_status`, each
  `compliant` or `not-compliant` — closed.
- **Why both are required** is the most useful thing about this event: it makes
  it safe to act on **out of order**. A receiver holding `compliant` that gets an
  event whose `previous_status` is `not-compliant` knows it has missed one, and
  that gap is invisible from either event on its own.
- **The spelling trap:** the hyphen in `not-compliant` is the specification's.
  `noncompliant` is silently ignored by a conforming receiver.
- **The subject trap:** it should normally name the **device** as well as the
  person, because the same person on a second device is unaffected and a
  receiver cannot tell that from a subject naming only them. The complex subject
  this service composes has room for `device` and `tenant` members, and
  **nothing here ever fills them in** — no device is attested to this service —
  so a `device-compliance-change` from this transmitter names the person and the
  session only. That is worth knowing before testing a receiver against it: the
  event is conforming, and it is less specific than the one a real device
  management system would send.
- **In the register:** the row's compliance is replaced, with the same
  missed-event warning as above — and here that warning is the whole reason CAEP
  makes `previous_status` required.
- **Default payload:** `compliant` → `not-compliant`.

## `risk-level-change`

*A risk engine changed its mind about somebody.* It is **the only one of the
eight that is a judgement rather than a fact** — the other seven report something
that happened — which is why it carries a reason and why a receiver is expected
to weigh it rather than act on it.

**This service sends it by itself since #62**: when a person's risk level
changes and the `risk-response` policy permits announcing it — every change
but a person's first level being LOW, by default. It names the person
(`principal` `USER`, an `iss_sub` subject), carries `previous_level` where
there was one, and puts the signals that moved it in `risk_reason`
([Risk scoring](risk-scoring.md#when-a-persons-risk-changes)).

- **Required:** `principal` and `current_level`.
- `principal` says **what** the risk level is about, and it is required because
  the subject alone cannot say: a complex subject names a person *and* a device
  *and* a session, and "risk went to HIGH" about the device is a different fact
  from the same sentence about the person. Values are open: `USER`, `DEVICE`,
  `SESSION`, `TENANT`, `ORG_UNIT`, `GROUP`. **They are upper case here and lower
  case in a complex subject's member names**, which catches everybody once.
- `current_level` is closed and upper case: `LOW`, `MEDIUM`, `HIGH`. It defaults
  to `caep.defaultRiskLevel` (`MEDIUM`).
- **Optional and worth sending:** `previous_level`, and `risk_reason` — which is
  *recommended* rather than required and is the member that decides whether a
  receiver can do anything but step up: "impossible travel" and "credential seen
  in a breach corpus" call for different answers.
- **In the register:** the row's risk is replaced, with the same missed-event
  warning.
- **Default payload:** `principal: SESSION` and the configured default level.

---

## Sessions that are not a browser's

Every artifact this service issues is a projection of a session
(`authn/CLAUDE.md`, *What an authenticated identity is here*), so three
families that are not a browser start one, through the same
`authn.startSession()`, and **are** the subject of the session events:

- a **WS-Trust** exchange that signs somebody in starts a session per request
  (`session-established`), which ends by the sign-out doors above or by
  expiry (`session-revoked`);
- a **SCIM** client, whichever of RFC 7644 section 2's schemes it
  authenticated with, starts one session keyed by the scheme and the
  principal: `session-established` at its first call, `session-presented` at
  every call after it, and `session-revoked` when the session expires or is
  ended;
- a **SPIRE Server API** caller, keyed by its SPIFFE ID, the same way.

**Where the session has no person as its subject** — a SPIFFE workload, or an
application's own credential rather than a person's — the event's `user`
names whatever the directory filed that caller under. What a non-human
subject should be, and whether such a session should be announced at all, is
[#221](https://github.com/rcbj/iya-sts/issues/221)'s question (service
accounts), which is open.

## What never produces a CAEP event

Nothing below is ever the subject of a *session* event. That is not an
omission — none of them is a session in CAEP's sense. The person-level events
are different: an LDAP password write, a SCIM change to a claim, and an
OpenID4VCI issuance do send `credential-change` or `token-claims-change` about
the PERSON, as the sections above say.

None of these is the subject of a session event:

- a **Kerberos** AS-REQ, TGS-REQ or AP-REQ, and a ticket-granting ticket
  expiring;
- an **LDAP** bind or unbind, though the connection *is* a session in RFC 4511's
  sense (`/admin/sessions` lists it as one);
- a browser that arrived at a front door and never signed in (its anonymous
  tracking session is never announced, above);
- **SPIFFE**'s Workload API, **OpenID4VCI** and **OpenID4VP** requests — a
  presentation at the Verifier's own pages included. A wallet sign-in at
  `/authn/wallet` is the exception, because it ends in a browser sign-on
  session like any other door;
- the **token, refresh, introspection, revocation and UserInfo** endpoints —
  including revoking every token a person holds;
- reading the **admin console**, which presents the same session on every page
  and reports nothing, because it is not a protocol SSO.

And one change sends **no CAEP event of any kind**: a realm's **authentication
policy being tightened** (Directory → Policies — a second factor required, a
mechanism withdrawn). A live session keeps the `acr` it was established at,
because that authentication did happen at that level, and CAEP 1.0 has no event
for "the level this realm requires went up": `assurance-level-change` says a
subject's assurance moved, and it did not. The next sign-in or step-up is held
to the new policy. `GET /ssf` states this under *What it deliberately does not
do*.

## Seeing what happened

- **`/admin/caep`** — the settings, the catalogue of all eight with every
  member, and the by-hand emit form.
- **`/admin/caep-sessions`** — one row per session this service has *held*,
  including the ones it no longer holds, with a count per event type. **The
  register outliving the session is the point:** a row saying `revoked` is the
  only remaining evidence that the session existed and was revoked.
- **`/admin/caep-sessions/session?id=…`** — one session opened out: every event
  actually sent about it, in order, with the `jti`, the stream it went out on,
  and what the register noticed as it was applied.
- **`/admin/caep-sessions`, *Per application*** — the same events counted the
  other way round: **what this transmitter has said to each RECEIVER, across
  every session**, with a count per event type, the distinct sessions it has
  been told about, and the pipe counters beside them. It is the table to read
  when more than one receiver exists and one of them is not getting what you
  expect. Two rows answer most of those questions on their own: an application
  with **no stream** (declared here, nothing agreed yet) and one whose *Takes*
  column says **none of CAEP's eight**.
- **`/admin/ssf`** — the streams. A session with a count of zero almost always
  means no stream asked for that type.
- **`GET /admin-api/caep`** and **`GET /admin-api/caep/sessions`** — the same,
  without a browser; the per-receiver rows are the `applications` member of
  both, searched with `appq` and paged with `applicationsPage`.

## The settings

| Setting | Default | What it does |
|---|---|---|
| `caep.enabled` | on | off drops all eight from `events_supported` |
| `caep.autoEmit` | on | off leaves the register accurate and sends nothing by itself |
| `caep.autoEmitTypes` | the seven | which of the seven observable acts emit; naming any other type is dropped with a warning |
| `caep.eventsSupported` | all eight | which types this transmitter will agree to deliver |
| `caep.omitEventTimestamp` | off | on produces a conforming event with **no** `event_timestamp`, to break a receiver that assumes one |
| `caep.includeReasons` | on | whether `reason_admin` / `reason_user` are sent |
| `caep.reasonLanguage` | `en` | the language tag those two are keyed by |
| `caep.assuranceNamespace` | `NIST-AAL` | the default namespace for `assurance-level-change` |
| `caep.defaultRiskLevel` | `MEDIUM` | the default level for `risk-level-change` |
| `caep.maxSessionsTracked` | 200 | how many sessions the register holds before dropping the oldest |
| `ssf.criticalSubjectMembers` | empty | publishing `session` makes a receiver that ignores it refuse the event instead of acting on the person |

All of them are runtime-settable on `/admin/caep`; see
[configuration](configuration.md).
