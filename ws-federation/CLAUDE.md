# ws-federation/

WS-Federation 1.2, the passive requestor profile, plus a mock relying party at
`/wsfed/rp` that verifies a sign-in response check by check. One file.

4. **`wsfed.ts` must stay after `authn/authn.js` in the require order**, and
   that is a dependency rather than a preference: it signs users in to the
   browser session `authn.js` owns, through the `startSession` / `sessionOf` /
   `endSession` it exports, so that single sign-on works across the protocols.
   (The rule named `oauth2.js` while that module owned the session; `wsfed.ts`
   sits after both, at 10 in `../common/protocol_stack.js`.) The dependency is
   one-way — `authn.js` knows nothing about WS-Federation — which is what keeps
   it out of the cycles rule 2 exists to avoid. Do not give WS-Federation a
   session store of its own to "decouple" them: two stores would each look
   correct alone and never see each other, and the symptom is a sign-on that
   silently is not single.


## A cross-site POST sign-in request does not see the session

Section 13.2.1 lets the sign-in request arrive as a cross-site form POST, which
`SameSite=Lax` keeps the session cookie off, so such a request is sent to the
sign-in screen even though a session exists. The quirk is kept rather than
worked around; `../authn/authn.js`'s `startSession()` owns the cookie and says
why. (This section used to argue that WS-Federation needed a sign-in screen of
its own for this reason; it has none since 2026-08-26 — see below.)

---

## `wauth` is refused rather than faked

* **WS-Federation's `wauth` is refused rather than faked.** A relying party demanding
  multi-factor against a password-only session gets an error and two ways forward, not
  an assertion claiming a second factor that did not happen. It is the one thing in
  this profile that could trivially have been faked, and faking it would have taught a
  relying party something false about how a person signed in. Likewise `wreqptr` is
  never dereferenced: fetching a URL handed over in a query parameter is a
  server-side request forgery with a specification citation attached.

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
  and multi-factor checks read `hardwareKey` / `multiFactor` off the same answer.
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

`tests/saml_family_hardcoded.js` pins the 2026-09-12 changes above, and nothing
else here is tested. The mock relying party makes the rest look covered — but a
person has to click it and read the page. What a test would add is the
negatives: an altered `wctx`, `wauth`
demanding a factor the session never had, `wfresh` read as seconds rather than
minutes, a SAML 1.1 signature whose reference does not resolve because
`AssertionID` was not named. A passive requestor that issues a good token to a
working relying party looks finished and proves almost nothing.
