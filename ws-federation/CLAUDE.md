# ws-federation/

WS-Federation 1.2, the passive requestor profile, plus a mock relying party at
`/wsfed/rp` that verifies a sign-in response check by check. One file.

4. **`wsfed.ts` must stay after `authn/authn.ts` in the require order**, and
   that is a dependency rather than a preference: it signs users in to the
   browser session `authn.js` owns, through the `startSession` / `sessionOf` /
   `endSession` it exports, so that single sign-on works across the protocols.
   (The rule named `oauth2.js` while that module owned the session; `wsfed.ts`
   sits after both, at 10 in `../common/protocol_stack.ts`.) The dependency is
   one-way — `authn.js` knows nothing about WS-Federation — which is what keeps
   it out of the cycles rule 2 exists to avoid. Do not give WS-Federation a
   session store of its own to "decouple" them: two stores would each look
   correct alone and never see each other, and the symptom is a sign-on that
   silently is not single.


## A cross-site POST sign-in request does not see the session

Section 13.2.1 lets the sign-in request arrive as a cross-site form POST, which
`SameSite=Lax` keeps the session cookie off, so such a request is sent to the
sign-in screen even though a session exists. The quirk is kept rather than
worked around; `../authn/authn.ts`'s `startSession()` owns the cookie and says
why. (This section used to argue that WS-Federation needed a sign-in screen of
its own for this reason; it has none since 2026-08-26 — see below.)

---

## `wauth` is a STEP-UP, never a fake (2026-09-17, #36)

**Until 2026-09-17 a `wauth` the session could not meet was REFUSED**, 400
with `STS-WSFED-0009` (a hardware token) or `STS-WSFED-0010` (multi-factor),
and the root `CLAUDE.md` listed "Fake WS-Federation's `wauth`" among the things
this service deliberately does not do. The refusal had one argument left once
this profile moved onto `authn/`'s screen (2026-08-26): that `wauth` is read on
a request that ALREADY has a session, and re-authenticating somebody who is
signed in is `wfresh`'s job. RFC 9470 took that argument away one directory
over — `acr_values=mfa` on a one-factor session sends the person to sign in
again — and the identity model made it cheap: a re-authentication ADDS an event
to the same session rather than replacing it (`../authn/CLAUDE.md`). rcbj's
direction on #36 was to take the row off the list, so:

* **A demand the session does not meet is a step-up, in every mode.** The
  person is sent through `beginAuthentication()` with what the demand asks for
  — `step_up.screenDemand()` turns a multi-factor demand into `forceMfa` and a
  HARDWARE demand into `forceKey` (2026-09-17) — and the return address
  carries `step_up.ts`'s `step_up_honoured=1`. With no session at all, a
  demand makes the first sign-in require it too. **One mechanism, not a
  second**: both flags and the marker are RFC 9470's, and the authorization
  endpoint reads the same function for `acr_values` naming only the RFC 8176
  key aliases.
* **The assertion reports what HAPPENED.** `authnMethodsFor()` reads the
  session after the step-up; a password and a one-time code is
  `multipleauthn`, a password and a key is `multipleauthn` too, a passwordless
  key alone is `HardwareToken`. Nothing about the request changes the answer.
* **A HARDWARE demand is met by a key in EITHER role; a MULTI-FACTOR demand
  only by two real factors.** A passwordless key does not answer multi-factor,
  however phishing-resistant it is. **THE SCREEN NOW OFFERS EXACTLY THOSE TWO
  CHOICES (2026-09-17).** Under `forceMfa` alone it could not run a key by
  itself, so a hardware demand went to a screen that accepted a one-time code
  and produced a session this profile then refused on the way back — the
  demand was answerable only by luck. `forceKey` fixes it at the screen: the
  key alone or the key after a password, no code, no recovery code, no
  Kerberos ticket and no wallet (`../authn/CLAUDE.md`, *`forceKey`*). A person
  who holds a second factor and no key is told to enrol one rather than handed
  a ceremony that would enrol one for whoever knows their password.
* **ONE attempt, then the refusal.** A request carrying the marker whose
  session still does not meet the demand is refused with the codes it always
  had: `STS-WSFED-0009` or `STS-WSFED-0010`. That is the only place they are
  raised now, and it is what stops a demand the screen cannot meet — no factor
  enrolled, a code offered for a key — from looping. The marker can be forged
  onto a first request, and all that buys is the refusal, for `step_up.ts`'s
  reason.
* **An unknown `wauth` is still refused** (`STS-WSFED-0006`): a method this
  service cannot perform or report is not answered with one it can.
* **`wreqptr` is still never dereferenced** — fetching a URL handed over in a
  query parameter is a server-side request forgery with a specification
  citation attached. That half of the old non-goal row stays, as a row of its
  own.

Note also `authnMethodsFor()`, which used to test for `hwk` and call a
passwordless sign-in a two-factor one. Anything reading `hwk` to mean "two
factors" is wrong for the reason `../authn/CLAUDE.md` gives; this now tests for
`hwk` AND `pwd`.

## This module no longer owns a sign-in screen, and that was a hole in three features

Until 2026-08-26 it drew its own, on an argument that was right about the screen
and wrong about the funnel: the parameters a person needs to see for a
`wsignin1.0` are `wtrealm`, `wreply`, `wctx`, `wauth` and `whr`, and a screen
printing `client_id: (none)` would describe a request that does not exist. But
`beginAuthentication()` takes a `details` array for exactly that, and
`saml2_sso.ts` and `saml11_sso.ts` both pass their own protocol's parameters
through it. What owning the screen actually bought was owning the FUNNEL — and
three features live in the funnel and were therefore inert for this profile
alone:

* **Federation.** `appFederationRelationship` on the relying party's entry is
  read by `mechanismFor()`, which is reached only from `beginAuthentication()`.
  A `wtrealm` whose entry named a federation partner got a password box, and a
  federated relying party looked exactly like a working one.
* **`fedAuthnMechanism`** on an identity-provider-side relationship — how a
  partner asking this service to authenticate somebody says what it wants done,
  including `federation`, which is what makes this service an identity bridge.
  All four values did nothing here.
* **The WebAuthn step, in either role.** The old screen said so itself, calling
  it "a real limitation rather than an omission". It is neither now.

`POST /wsfed/login` and `pendingSignIns` went with the screen. The request
travels back on the query string of the return address instead, which is byte
for byte what that handler redirected to once it had a session — so there is one
less store to make per realm, and the realm-isolation hole that store had in
2026-08-25 cannot recur in it.

## `rpContexts` is per trust realm

`/wsfed/rp` answers under every realm prefix, so there is one mock relying party
per realm, and a `wctx` minted by one being recognised by another would make the
check that Map exists for — did my own value come back? — answer yes across a
boundary the rest of the profile does not cross. `realmSupport()` publishes this
family as `full` and says single sign-on with OAuth "does not cross realms".

## The autopost page is one of the seven scripted pages

Section 13.2.1's sign-in response is a self-submitting form, so
`/wsfed/autopost.js` is named in a relaxed `script-src`. It carries a REAL SUBMIT
BUTTON as well, labelled for a person, because with the script blocked the button
is the whole mechanism. See the root `CLAUDE.md`.

## 2026-09-12: the reply address, the persona claims, and the two issuer names

* **`wreply` must be registered in product mode** (`mode.acceptsUnregisteredAddresses()`):
  one of the `wsfedReplyUrl` values on the `wtrealm`'s entry, exact match, with
  none sent meaning the registered one and NO fallback to `/wsfed/rp`. The rule is
  `../saml/return_address.ts`, shared with both SAML profiles. Development passes
  no registration to it at all, so a request with no `wreply` still goes to the
  mock relying party even when the entry recorded one — byte for byte what it did.
  **Which `wsfedReplyUrl` values count is `applications.returnAddressesOf()`'s
  answer** (the same day): a `wreply` a development sighting wrote is marked
  OBSERVED on `appReturnAddressObserved`, and product refuses it with
  `STS-REG-0049` until an operator confirms it. See `../common/CLAUDE.md`.
* **`authnMethodsFor()` is `../saml/authn_context.ts`'s reading now**, which
  fixed the defect all three copies had (a certificate, a Kerberos ticket, a
  federated or unauthenticated session was `am:password`). The `wauth` hardware
  and multi-factor step-up reads `hardwareKey` / `multiFactor` off the same
  answer.
* **The persona claims** come off the directory entry in product mode or are
  omitted (`../saml/person_attributes.ts`), and **the signed metadata describes
  what the realm's mode emits** — it said `Always "Mock"` and
  `username@sts.example` in a product deployment's signed document.
* **`wsfed.entityId` and `saml.issuer` differing is reported** on `/wsfed` and
  once at startup (`issuerDisagreement()`): the metadata names one and every
  assertion the other, which a relying party's issuer registry refuses.
* `wsfed.mockRpContextTtlMin` (30) replaced the constant; the metadata signer
  reads `saml.signatureAlgorithm`.

`tests/saml_family_hardcoded.js` sections A, H and I pin these.

## What no test covers yet

`tests/saml_family_hardcoded.js` pins the 2026-09-12 changes above, and
`tests/wsfed_wauth_step_up.js` (2026-09-17) pins the `wauth` step-up: a
multi-factor demand on a one-factor session sent to sign in again with the
factor required and the marker on the return, the assertion reporting
`multipleauthn` after a one-time code, a hardware demand whose screen
offers the key in both roles and refuses a one-time code (`STS-AUTHN-0204`),
a person holding a code and no key told so, a session still keyless on the way
back refused `STS-WSFED-0009`, a REAL WebAuthn ceremony (a software
authenticator built in the test) meeting the demand passwordless AND as a
second factor, a forged marker refused
`STS-WSFED-0010`, and an unknown method still `STS-WSFED-0006`. Its mutant —
the marker ignored, so every unmet demand is refused as before — turned eight
of its assertions red. Nothing else here is
tested. The mock relying party makes the rest look covered — but a person has
to click it and read the page. What a test would add is the other negatives:
an altered `wctx`, `wfresh` read as seconds rather than minutes, a SAML 1.1
signature whose reference does not resolve because `AssertionID` was not
named, A passive requestor that issues a good token to a
working relying party looks finished and proves almost nothing.

## Schema validation (#188, 2026-09-24)

The federation metadata and the sign-in response's `wresult` — SAML 1.1 and
SAML 2.0 tokens in the 2005/02 and 1.3 wrappers — are validated against the
published WS-Federation 1.2, WS-Trust and SAML schemas by
`tests/vendored/sts_xml_schema_validation.js`, in a development and a product
realm. Both were valid on the first run.
