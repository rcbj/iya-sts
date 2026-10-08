# ws-trust/

WS-Trust 1.0 through 1.4, at `/sts` (with the signing certificate at
`/sts/cert`). One file.

**ONE PARSER ANSWERS ALL FOUR VERSIONS**, and that is not a simplification. The
trust namespace alone has four versions in use, so `firstByLocal()` and
`textByLocal()` in `../common/helpers.js` match on LOCAL NAME WITH THE NAMESPACE
IGNORED. That is what lets one `RST` parser serve WS-Trust 1.0–1.4 instead of
four, and it is why those two functions are in `common/` rather than here — the
other two readers are `../ws-federation/wsfed.ts`'s `wreq` and the `wresult` the
mock relying party is POSTed.

It asks `../saml/saml2.ts` for the assertion it puts in an `RSTR`; it records the
`AppliesTo` as a relying party through `../common/applications.js`, and a
`AppliesTo` handed a SAML 2.0 assertion is BOTH a WS-Trust relying party AND that
assertion's service provider, so `seen()` is passed a LIST rather than called
twice — two calls would count two authentications for one act.

---

## `OnBehalfOf` and `ActAs` are TWO mechanisms now, not one with two spellings

`delegatedSubject()` used to collapse them with a `||`, and for everything that
reads it that was right — the token issued is identical either way. It is wrong
for `/admin/delegation`, where the difference is the whole point, and since #108
for the delegation policy, which needs the stronger permission for the first:

* **`wst:OnBehalfOf`** (1.3 §9.2) asks for a token ABOUT somebody. The relying
  party is handed an ordinary sign-in and cannot tell a middle tier was involved.
  IMPERSONATION.
* **`wst14:ActAs`** (1.4 §9.3) is composite by definition: the token is about
  the named subject AND says the requester is acting. DELEGATION.

So that function returns which element it found, `authenticate()` carries it out
on a `delegation` member (with the REQUESTER, who is the intermediary of the
chain and is the one party `subject` deliberately does not name), and
`handleRst()` records the act — there rather than in `authenticate()`, because
that is the first line at which the token exists and the only place that knows
the `AppliesTo`, which is the TARGET of the chain. A request carrying BOTH
elements is attributed to `OnBehalfOf`, the order the `||` always had, and the
row says so rather than choosing silently.

## The act names APPLICATIONS, not URLs, and it names what it was delegated WITH

Two things were added to that record on 2026-08-27 and both exist to make a
CHAIN of these hops readable — a person signs in to a web application over SAML
2.0, the application exchanges the assertion for one addressed to an ESB, and
the ESB exchanges that for one addressed to a back end. Neither changes what is
issued; both change what the console can draw.

* **The `AppliesTo` is resolved through the registry.** `applications`
  `.forAppliesTo()` reads `wstrustAppliesTo` and then `samlEntityId`, and the
  act is filed against whichever application registered the address, with the
  address itself kept in the sentence beside it. Without it the target of hop
  one is a box called `https://esb.example.com` and the intermediary of hop two
  is a box called `esb`, so a chain draws as two unconnected halves. This is
  `oauth2.js`'s `forAudience()` lookup arriving through a second protocol, and
  it has the same three properties: it is a lookup and not a permission, it is
  not case-folded, and it does not fall back to the identifier.
* **The token inside `<wst:OnBehalfOf>` is recorded as CONSUMED**, by its
  `ID` / `AssertionID` (or the `KeyIdentifier` that references it).
  `/admin/tokens/credential` joins what one act produced to what the next
  consumed, on the identifier and on nothing else — so until this was read,
  every WS-Trust lineage stopped one generation in, at the requester's
  WS-Security credential, which this service never issued and cannot name. That
  wall is still recorded beside the followable one, because "it began somewhere
  this register cannot name" and "this is where it began" are different answers.
  **Its note says what was CHECKED, by mode (#479).** In product the token
  was verified, and the note says so: an assertion against this realm's
  certificate and inside its Conditions, a JWT against this realm's key,
  with its issuer and `exp` checked. In development it was not, and the
  note says that. Until #479 the development sentence was written in every
  mode.

The requester also carries an `application` where this registry already holds an
entry under the name it authenticated as. It stays a LOOKUP: an unknown name
leaves the slot empty and the party is drawn from `presented`, as before.

**Both are authorized by the delegation policy since #108 (2026-09-23)**, and
the row names what allowed it in the same field where a Kerberos row names an
attribute on an account — see the next section. **The composite fact IS in
an `ActAs` token since #186.** A SAML assertion names every party that acted,
one `<del:Delegate>` each, least to most recent, in its SAML V2.0 Condition
for Delegation Restriction. A JWT names them in RFC 8693's nested `act`
claim (#476). An `OnBehalfOf` token adds nobody, and keeps whatever chain
the presented token carried. The act's note says which of these the issued
token does, in that token's vocabulary (`actNote()`, #478). Until #478 the
note and this paragraph still said no `ActAs` token carried the fact, "a gap
in the mock".

## WHO MAY ACT FOR WHOM, AND AS WHAT (#108, 2026-09-23; #186, 2026-10-03)

WS-Trust puts no authorization on either element — 1.3 section 9.2 and 1.4
section 9.3 describe what the requester ASKS for and leave the decision to the
STS. `handleRst()` asks `../common/delegation_policy.ts` (rule 3az,
`../common/CLAUDE.md`) after the role gate and the JWT-subject check and before
the token is built, with **the same rules as RFC 8693's token exchange**
(rcbj, #186): the ACTOR is the REQUESTER; the SUBJECT is the delegated token's;
S is the delegated assertion's Audience (`delegatedAudiences()`); R is the
`AppliesTo`. **The element is the requested semantics**: `OnBehalfOf` is
impersonation, `ActAs` delegation — and the policy decides whether the actor
and subject allow them (`appDelegationSemantics`, `stsDelegationSemantics`).

**A PERSON MAY ACT ONLY WITH THE ROLE `delegation.actorRole` NAMES**, and only
toward an R that accepts them by name; a requester the realm does not know at
all is refused the same way (`STS-WSTRUST-0019`). The credential an
application presents (a UsernameToken, verified against a `userPassword`) may
be kept on a service account entry of the same name, and the APPLICATION entry
is what the policy reads (`partyFacts()` asks the registry first).

**BOTH ELEMENTS IN ONE REQUEST ARE REFUSED IN EVERY MODE** —
`wst:InvalidRequest`, `STS-WSTRUST-0025`: they ask for opposite semantics.
**No `AppliesTo` is refused unless the act is a self one** (the policy's
`no-target`) — in development, where that refusal is not enforced. **In
product an RST with no `AppliesTo`, or one nobody registered, is refused
before the policy is asked** (#496, *An application nobody registered*,
below), so `no-target` and `unregistered-target` (`STS-WSTRUST-0024`) are not
reached from WS-Trust there; they still decide RFC 8693's exchange.

**A REFUSAL IS WS-TRUST 1.4 SECTION 11's `wst:RequestFailed`** ("The specified
request failed") — see *Every refusal names its section 11 fault code*, below,
for how `soapFault()` places it. The codes by refusal kind:
`intermediary` `STS-WSTRUST-0019`, a realm policy's `policy` `0020`,
`semantics` `0022`, `authority` `0023`, the target kinds (`target`,
`targets`, `unregistered-target`, `no-target`) `0024`, the rest (a protected
subject, may_act) `0018`.

**THE ROW SPEAKS WS-TRUST (#481).** `authorizedBy` on a WS-Trust act reads,
for example, `the issuance policy allowed delegation by "esb" for "alice" to
"back", the application the AppliesTo names (the token inside <wst14:ActAs>
was issued for "esb").` It names the AppliesTo and the token inside the
element. RFC 8693's "subject token" was written on every row until #481,
and the OAuth 2.0 and Kerberos rows keep the sentence they had.

**ENFORCED IN PRODUCT** (`mode.authorizesDelegation()`); development issues and
the act says "WOULD HAVE BEEN REFUSED in product: …". A refused act is recorded
with `outcome: refused` before the fault is answered, so it is on
`/admin/delegation` — the only list a refusal is in. A requester delegating
about ITSELF acts for nobody and needs nothing.

**A REFUSED DELEGATION LEAVES NO `/admin/users` ROW (#183, 2026-10-05).**
`authenticate()` used to record the delegated subject's `recordAuthentication()`
row before the policy was asked, so a refused `OnBehalfOf` / `ActAs` still
listed its subject as seen. `authenticate()` now records only the REQUESTER (who
did authenticate, whatever is decided after), and `handleRst()` records the
delegated subject in `recordDelegatedSubject()` once the decision has allowed
the act or not enforced its refusal. The policy was not moved into
`authenticate()`, which the "authenticate ABOVE the branch" rule below keeps
away from the `AppliesTo`. **The delegation decision moved instead: it is
asked AHEAD of the role gate and the JWT-subject check** (both elements,
`STS-WSTRUST-0025`, with it), because in development the record is what grows
the subject's directory entry (`ldap.autocreateUsers`), and those two checks
read that entry. Product creates nobody there. The cost: in development, a
subject this request is the first to name is decided before their entry
exists — an unknown party, where it used to be a freshly invented entry with
no delegation attributes. Development enforces only a `may_act` mismatch, and a
subject with no entry yet has no `stsMayAct` to mismatch; and the decision is
about who the directory says they are, not about an entry the request invented.
Validate and Cancel return before the decision, so a delegated subject named in
either is not recorded at all.

---

## Every refusal names its section 11 fault code (#183, 2026-10-05)

WS-Trust 1.4 section 11 defines the fault codes an STS returns, "in terms of
SOAP 1.1. For SOAP 1.2, the Fault/Code/Value is env:Sender ... and the
Fault/Code/Subcode/Value is the faultcode below." `soapFault()` takes the code
as its third argument and the request's own trust namespace as its fourth: on
SOAP 1.1 it REPLACES `soap:Client` as the `faultcode`, and on SOAP 1.2 it is the
`Subcode` under `soap:Sender`. Until #183 only the delegation refusals (#108)
and the 2004/04 Cancel (#188) named one; every other refusal was the generic
fault. Each refusal names its code at the place it refuses:

| Code | Refusals | Why that one |
|---|---|---|
| `InvalidScope` | `0030` (#496: product, an `AppliesTo` that resolves to no registered application) | 1.3 section 4.1 calls `wsp:AppliesTo` "the scope for which this security token is desired", so an AppliesTo this STS serves nobody under is section 11's "The request scope is invalid" — the exact sentence, where InvalidRequest would have been true and said less |
| `InvalidRequest` | `0031` (#496: product, an RST that issues and carries no `AppliesTo`, or an empty one), `0001` (not well-formed, qualified with 1.3's namespace: there is no document to read the request's own off), `0008` and a delegated token's `0004` / `0005` / `0007` (the token inside `OnBehalfOf` / `ActAs`), a delegated JWT's `0026` / `0028` (#477), `0012` (`?encrypt=1` with no recipient certificate), `0021`, `0025` | the REQUEST carries, or lacks, something that makes it unanswerable. A delegated token that does not verify is not FailedAuthentication: the requester did authenticate |
| `FailedAuthentication` | `0002`, `0003`, the requester's own `0004` / `0005` / `0007` and its own JWT's `0026` / `0028` (#519), `0009`, `0010` | the requester did not authenticate. One fault for a wrong password and an unknown user, the enumeration rule `requesterCredential()` states |
| `ExpiredData` | `0006`, in either seat, and a JWT's `0027` in either seat (#477, #519) | "The request data is out-of-date" is the more exact answer for an expired assertion than FailedAuthentication or InvalidRequest. `checkedAssertion()` returns it; the seat supplies the code for its other refusals |
| `RequestFailed` | `0011` and `STS-CORE-0121` (the role gate), `0013` (encryption to the certificate failed), `0017` (a JWT about nobody), `0018`–`0024` (the delegation policy), `STS-CELL-0124` / `0125` (a delegated subject's home cell) | the request was understood and authenticated, and could not be done |

**Not used, and why**: `InvalidSecurityToken` is "Security token has been
revoked" in 1.4's table, and nothing here checks revocation of a presented
token; `AuthenticationBadElements` is about digest elements, and request
signatures are not verified (`docs/ws-trust.md`, *Not implemented*);
`InvalidTimeRange` would refuse a `wst:Lifetime`, which is CLAMPED instead
(section 4.1 makes it a request the STS decides); `BadRequest`,
`RenewNeeded` and `UnableToRenew` have no refusal here that they describe
better than the codes above — an unknown RequestType is issued, and a Renew
re-issues whatever token it is handed. (`InvalidScope` was on this list until
#496, when an `AppliesTo` nobody registered stopped being issued for in
product.)

**`0015` IS NOT A REFUSAL**, and it is not a section 11 code: every one of
those is a Sender fault. An exception in the endpoint is `receiverFault()`'s
`soap:Receiver` (SOAP 1.2 Part 1 section 5.4.6) or `soap:Server` (SOAP 1.1
section 4.4.1), in the version the request was sent in — it was always a SOAP
1.2 envelope until #183. `0014` is a `wst:Status` in a 200, not a fault.

`tests/wstrust_fault_codes.js` asks every refusal above on both SOAP versions,
the namespace and the receiver fault included.

## Two rules about where a credential is read, and both were learnt the hard way

**"The observer is installed" is not the same claim as "this protocol calls the
funnel", and WS-Trust is what that cost.** Three of its paths accepted a
credential without ever reaching `recordAuthentication()`, so each produced
somebody who had authenticated here and appeared on no page and in no
directory: `Validate` and `Cancel` answered above the `authenticate()` call, a
request carrying both a UsernameToken and an `OnBehalfOf` returned at the
delegation branch before the UsernameToken had been looked at, and a `Renew`
with no security header read the assertion out of its own `RenewTarget` and
recorded that as the credential. Two rules come out of it and both generalise
to the next family: authenticate ABOVE the branch on the operation rather than
inside the branches that happen to need a subject, and look for a credential in
`wsse:Security` — anywhere else, only OUTSIDE the elements that hold somebody
else's token, since a document with four identities in it answers "which comes
first" and not "who is asking".

## PRODUCT MODE, AND FOUR DEFECTS FIXED IN EVERY MODE (2026-09-12)

**Product mode (`mode.verifiesCredentials()`) refuses, with a SOAP Fault naming
what to present:**

* a request with **no credential** — which also closes the Renew that issued a
  token for whoever its RenewTarget named, and Validate and Cancel, because every
  operation authenticates above the branch;
* a **SAML assertion as the credential** unless it verifies against THIS REALM'S
  OWN signing certificate and is inside its Conditions (`oauth2.clockSkewS`
  tolerance). That is the smallest real answer to "which issuer is trusted": the
  key this STS already publishes at `/sts/cert`, covering what an assertion is
  presented here for — renewing or exchanging a token this STS issued. A register
  of foreign issuers is the next step and does not exist; `checkedAssertion()`
  serialises the ONE element before verifying, because a SOAP document carries the
  requester's assertion and the delegated one;
* an **`OnBehalfOf` / `ActAs` with no requester credential**, and one whose inner
  token is not such an assertion — a name alone is not evidence of anybody;
* **`?encrypt=1` that cannot encrypt** (`opensTestControls()` — the flag is a
  non-spec test control and its plaintext fallback is the lenient half);
* no subject is invented: `saml-subject` and `delegated-subject` are development's.
* **a presented password is verified against `userPassword`** — WS-Trust had
  been checking only the reserved string `invalid` in both modes until
  2026-09-12.

**Fixed in both modes:**

* **The requested lifetime is clamped** to `wstrust.maxTokenLifetimeMin` (1440).
  A `wst:Lifetime` replaced the default with no bound, so a caller could mint a
  year-long bearer token by asking; WS-Trust 1.4 §4.1 makes it a request the STS
  decides. The default is `wstrust.tokenLifetimeMin` (60).
* **The issued assertion's AuthnContext names the credential** —
  PasswordProtectedTransport for a UsernameToken (as before), PreviousSession for
  an assertion, `unspecified` for a delegation or nothing. It was
  PasswordProtectedTransport for everything, an anonymous request included.
* **A delegation starts no session.** `signIn` was built from `auth.subject`,
  which on OnBehalfOf/ActAs is the DELEGATED subject — so the response to whoever
  asked carried a session cookie in the name of somebody who was not there. A
  session from an assertion credential has an empty amr rather than `pwd`.
* **The JWT carries a `jti` and a `kid`**, signed through `helpers.signJwtAs()`
  with `wstrust.jwtAlgorithm` (RS256 by default; RS*/PS*/ES*/EdDSA). It is still
  not in the token register — that funnel is RS256 by construction — but
  `/admin/delegation` can now name what a JWT exchange produced.
* **`?encrypt=1` honours `saml2.encryptionAlgorithm` / `saml2.keyTransportAlgorithm`**,
  answered for the AppliesTo as `/saml2` answers them for a service provider.
* **`wstrust.issuer` and `saml.issuer` disagreeing is SAID** — on `GET /sts` and
  in the startup log — rather than reconciled, because the split is deliberate.

`tests/saml_family_hardcoded.js` section E pins all of it in process.

## EACH VERSION ANSWERS IN ITS OWN SCHEMA'S ELEMENTS (#188, 2026-09-24)

The answer echoes the request's trust namespace, and until #188 it answered
every version in 1.3's vocabulary. Validating each answer against its own
version's published schema (`tests/vendored/sts_xml_schema_validation.js`)
found three elements the **2004/04** member submission does not have:

* **Issue is answered with the RSTR itself.** That version's
  `RequestSecurityTokenResponseCollection` holds `minOccurs='2'` responses —
  it is for several tokens at once — so a collection of one was invalid.
  The action is `.../RSTR/Issue`. 2005/02 (`minOccurs='1'`) and 1.3 (the
  collection is REQUIRED for an Issue's final response) are unchanged.
* **The reference is `wst:RequestedTokenReference`**, the element 2005/02
  renamed `RequestedAttachedReference`.
* **Cancel is refused** with that namespace's `wst:InvalidRequest` fault
  (`STS-WSTRUST-0021`): 2004/04 has no `CancelTarget` and no
  `RequestedTokenCancelled`, and answering in elements the version does not
  define is worse than saying it does not define the operation.

What is left in 2004/04 and is NOT a schema error, stated rather than
changed: the `wsp:AppliesTo` and `wsa:EndpointReference` in the answer are
the 2004/09 policy and 2005/08 addressing namespaces for every version (the
2004/04 schema imports 2002/12 and 2004/03), which its lax wildcard admits.

**The published 1.3 schema's own namespace is wrong**, and that is recorded
on #188 rather than worked around here: `ws-trust-1.3.xsd` declares
`http://docs.oasis-open.org/ws-sx/ws-trust/200512/` with a trailing slash,
which is not the specification's namespace and not what this endpoint (or
any other) speaks. The job validates against a copy with that one string
changed (`tests/tools/fetch-xml-schemas.sh`).

## What is tested, and what is not

`tests/wstrust_fault_codes.js` (#183) holds every refusal's section 11 code on
both SOAP versions, the receiver fault, and the `/admin/users` row of a
refused and an allowed delegation, in process in both modes.

The parent project has `tests/wstrust.js` and
`tests/wstrust_schema_validate.js`, which drive the DEBUGGER's client side
against this endpoint. Nothing tested this module on its own until
`tests/saml_family_hardcoded.js` (2026-09-12), which holds the product-mode
refusals above. Still untested, and where the value is: `Validate` and
`Cancel` answering above the `authenticate()` call, a document carrying both a
UsernameToken and an `OnBehalfOf`, a `Renew` with no security header. Every one
of those is drivable over HTTP, so by the root `CLAUDE.md`'s rule they belong
in the PARENT project's suite.

## A JWT'S `sub` IS A SUBJECT, AND THERE IS NONE WITHOUT AN ENTRY (2026-09-14)

A JWT is issued with `sub: urn:uuid:<entryUUID>`. For a person the directory does not
hold — `ldap.autocreateUsers` off and nobody provisioned — it is refused with a SOAP
Fault (`STS-WSTRUST-0017`) rather than issued with the bare name, which is the rule the
OAuth 2.0 grants follow (`STS-OAUTH-0510`): a bare name is a `sub` a relying party links
on and a person created later under the name would inherit. An `anonymous` request names
nobody by design and is unaffected, and so is a SAML assertion, whose `NameID` is the
username. A process with no directory still uses the name. `tests/stable_subject.js` D5b.

## THE JWT FOLLOWS RFC 9068 AND RFC 8693 IN ITS STRUCTURE AND CLAIMS (#476, 2026-10-06)

rcbj: "follow RFC-9068 and OAuth2 Token Exchange spec for claims in the
JWT", and "The only time oauth2 token exchange and rfc9068 should be
followed is for response token JWT structure and contents." So
`buildJwt()` changed, and nothing else did. The RST, the AppliesTo, the
requester's authentication, the RSTR and its `wst:TokenType`, and every
SAML assertion are WS-Trust's and SAML's, as before.

* **`typ: at+jwt`** (RFC 9068 section 2.1). The token is the bearer
  credential the AppliesTo's service accepts, which is what an access
  token is, and the header is what keeps it from being read as an ID Token
  (`oauth2.ts`'s `ownTokenKind()` now calls it an `access_token`).
* **`client_id`** (RFC 9068 section 2.2, RFC 8693 section 4.3) is the
  APPLICATION the requester authenticated as: the client_id it registers,
  else its identifier, the rule `may_act` uses. It is the requester of an
  OnBehalfOf or ActAs, or of a token about itself.
* **`act`** (RFC 8693 section 4.1) has the current actor outermost, as since
  #186. Each entry takes the shape this service's OAuth tokens give it.
  RFC 8693 permits each of these and requires none:
  * `iss` in every entry, this token's own (#471). Each prior delegate came
    from a token this STS issued, so this issuer vouches for all of them.
  * An application named by its client subject in the mode: `urn:sts:client:`
    in RFC 9700 mode (`oauth2_bcp.enabled()`, asked lazily, as
    `common/consent.ts` does), and the bare client_id otherwise (#471).
  * A person who acted is named by their `urn:uuid:` subject.
  * #443's original client needs no rule. In WS-Trust the first application
    of a chain is in `act` because it made the first ActAs itself.

**The exceptions, each with its reason:**

* **No `client_id` for a person's own token.** A person who asks with their
  own UsernameToken (or assertion) for a token about themselves has no
  client. A name in the claim that is not a client's would be worse than
  none.
* **No `scope` unless the application configures it** (#485). An RST asks
  for none and none is invented. The AppliesTo's application may name scopes
  on `wstrustJwtScope`, and those are carried after the judgement an OAuth
  access token's get (`configuredScope()`, `scopePolicy.narrow()`):
  * the application is the client, so its `oauthAllowedScope` declares what
    it may be issued, in product; the protected scopes are held to it in
    every mode;
  * the issuance policy asks its per-scope question;
  * what is left off gets the token endpoint's audit row, STS-OAUTH-0579.

  **A write naming an undeclared scope is ACCEPTED and dropped at
  issuance**, which is the token endpoint's own backstop. The declaration may
  change after the write, development grants undeclared scopes, and the
  field's description says to declare it on `oauthAllowedScope`. A SAML token
  has no scope.

  **AND IT IS SAID WHERE IT IS SET (#488).** Each value the policy would drop
  earns a warning from `scopePolicy.configuredScopeWarnings()`. It names the
  value and why, and says to declare it on `oauthAllowedScope` or remove it.
  In development it says what product would do. The warning appears:
  * beside the field on Configuration → WS-Trust;
  * after the Save reply's message;
  * as `warnings` on the `/admin-api/applications` `set` / `add` / `remove` /
    `update-fields` replies;
  * on the application's GET view.

  All four carry the one list (rule 7). The write still stands.
* **No `auth_time`, `acr` or `amr`.** RFC 9068 section 2.2.1 makes them
  optional, and a delegated JWT could only copy them from an
  authentication it never saw.
* ~~`iss` is `wstrust.issuer`~~ **Reversed by #480 (rcbj: "Realm's OAuth
  issuer").** `iss` is the realm's OAuth 2.0 issuer, the one
  `/.well-known/oauth-authorization-server` publishes at the request's base
  (`oauthIssuer()`, through `oauth2.issuerOf()`), in every mode. RFC 9068
  section 4 has a resource server compare `iss` with that metadata, and the
  signing key is already that server's, at `/oauth2/jwks`. Every `act`
  entry's `iss` is the same value (#471). GET /sts names it on a line of its
  own, `JWT issuer:`, beside the STS's name.
* **`exp` is the lifetime the RSTR's `wst:Lifetime` states.** WS-Trust 1.4
  section 4.1 makes that the STS's decision, so the two cannot disagree.
* **The SAML Delegation Restriction is unchanged.** Its `del:Delegate`s name
  applications by their bare identifiers in every mode. The `urn:sts:client:`
  form and `iss` are the JWT's alone.

`tests/wstrust_jwt_claims.js` holds each of these in both modes, in
process. `tests/delegation_policy.js` L13 holds the product form of `act`.

## A JWT THIS STS ISSUED IS READ INSIDE OnBehalfOf / ActAs (#477, 2026-10-06)

**This is a change to how a WS-Trust request is processed, and it is kept
apart from #476 for that reason. It needs rcbj's decision.**

WS-Trust names no kind of token for either element: 1.3 section 9.2 and
1.4 section 9.3 each hold "a security token or wsse:SecurityTokenReference".
Until #477 only a SAML assertion was read there, so a chain whose response
tokens were JWTs stopped at its first hop:

* product refused the JWT as `0008` ("no SAML assertion");
* development delegated for `delegated-subject`.

`delegatedJwt()` reads the `wsse:BinarySecurityToken` this STS's own RSTR
carries a JWT in (ValueType `urn:ietf:params:oauth:token-type:jwt`), on
`checkedAssertion()`'s footing, because the smallest real answer to "which
issuer is trusted" is this STS. **In product** the JWT is refused with a
fault unless all four of these hold:

* it verifies with this realm's own key (`helpers.verifyOwnJws()`), else
  `0026`;
* it is within its `exp` and `nbf`, else `0027`, `wst:ExpiredData`;
* its `iss` is the realm's OAuth issuer, the one this STS's own JWTs carry
  since #480, else `0026`. **Consequence of #480:** an OAuth access token
  from this realm carries the same issuer under the same key, so it is
  accepted here too. The realm is one issuer;
* its `sub` is the `urn:uuid:` of a person this directory holds, else
  `0028`.

**Development** reads it unverified and believes it, as it believes a
NameID.

What the rest of the request needs is read off the JWT as an assertion's
is:

| Read | From |
|---|---|
| the subject | `sub` |
| S | `aud` |
| the prior delegates | `act`, innermost first, so least to most recent. Each `sub` is read back to an application's identifier (from `urn:sts:client:<client_id>` or the bare client_id) or to a person's username |
| what the act consumed | `jti` |

The decision, the SAML assertion and the JWT that is issued do not change.
An assertion inside still wins where an element carries both.
`tests/wstrust_jwt_claims.js` K holds each of these in both modes.

## THE AppliesTo's CLAIM SETTINGS GOVERN BOTH TOKEN TYPES (#483, #484, 2026-10-06)

An application's claim settings are:
* its groups-claim settings (`appGroupsClaim`, `appGroupsClaimName`,
  `appGroupsClaimValue`, `appGroupsClaimFromMemberOf`);
* the roles claim (`roles.js`);
* its custom claims (`oauthClaimsAccessToken`, `saml2CustomAttributes`, and
  the realm's sets they sit over).

They reach a WS-Trust token through the same functions they reach an OAuth
access token and a SAML SSO assertion through: `stats.jwtClaims
('access_token', …)` and `stats.samlAttributes('saml2', …)`. There is no
second implementation. **What was verified, before the fix:**

* **The JWT carried none of them.** `buildJwt()` never asked `jwtClaims()`.
  `applicationClaims()` now asks it, with `customClaimContext()`'s members,
  and assigns the protocol's own claims over the result.
* **The SAML assertion carried the roles claim correctly.** Its groups claim
  used the REALM's settings, because `applications.settingFor()` looks an
  identifier up, and an AppliesTo URI is not one. Its custom attributes
  appeared for the first token only. After that, the OBSERVED entry
  `seen()` files under the AppliesTo URI answered `applications.get()`
  ahead of `forAppliesTo()`, and that entry has no rows.

**The fix is one context member, `application`.** WS-Trust resolves the
application the way the register does (`appliesToApplication()`:
`forAppliesTo()` first, which skips the self-named entry) and passes it to
both builders (`buildSamlAssertion()`'s `opts.application`). Three readers
ask for it first and keep their old lookups for every other caller:
`effectiveClaimSet()`, `GroupClaims.appOf()` and `claimApplicationsOf()`.

**Whose settings, and about whom.** The settings are the AppliesTo's
application's: the relying party the token is for, as a SAML assertion's
are its service provider's. The values are the SUBJECT's. An OnBehalfOf or
ActAs token carries the person's groups, roles and claims, and nothing of
the requester's.

**Exceptions:**

* ~~No SAML 1.1 token~~ **Closed by #487.** WS-Trust issues SAML 1.1 for the
  SAML 1.1 TokenType, and `saml11CustomAttributes`, the SAML 1.1 groups and
  roles attributes apply to it (see the #487 section).
* **Placeholders are each context's own.** A JWT's `${…}` are an OAuth
  access token's (`username`, `sub`, `email`, `name`, `client_id` — the
  JWT's own, the requester — `audience`). A SAML attribute's are the SAML
  builder's (`subject`, `audience`), as on SAML SSO.
* **The settings are the AppliesTo's, where OAuth reads the client's.** An
  OAuth access token takes its custom claims from its CLIENT's entry. A
  WS-Trust JWT takes them from the AppliesTo's application, which is the
  party the token is issued to and is what #483 and #484 ask for.

`tests/wstrust_token_claims.js` compares each WS-Trust token with what
`jwtClaims()` and `samlAttributes()` give OAuth and SAML SSO for the same
application, in both modes. The #473 chain jobs assert all of it at every
hop.

## THE NAMES IT SIGNS UNDER ARE THE SAML ENTITYID (#480, #494, 2026-10-06)

rcbj: "Align with SAML entityID" (#480, product only), then on #494 "in
development as well as product", with the placeholder dropped from
`env/docker-tests.js` and `env/test.js` so the suites run the rule. Three
settings name this service outside the SAML browser profile: `saml.issuer`
(a WS-Trust or WS-Federation assertion's Issuer), `wstrust.issuer` (the
STS's name on GET /sts) and `wsfed.entityId` (the FederationMetadata
entityID). Each shipped the development placeholder `urn:wstrust:mock:sts`;
since #494 their shipped default is EMPTY, meaning "the entityID".

`common/issuer_names.ts` reads all three, and every reader goes through it.
The rules, in order, the same in both modes (`mode.namesIssuersByEntityId()`
and its `issuer-names` requirement were retired by #494, no shim):

* **A value somebody set wins.** That means a realm value, a runtime
  override, the environment or the operator's appconfig. A realm's SEEDED
  `urn:<domain>:sts` is not somebody's choice, and is read as a default.
* **Otherwise the realm's `saml2.entityId`**, what `/saml2/metadata`
  publishes — per application for a REGISTERED one, below.
* **No name at all** only in product with `saml2.entityId` emptied:
  a SAML token is then refused (`STS-WSTRUST-0029`) as SAML SSO refuses
  (`STS-SAML-0004`); a JWT is unaffected.

**Per application, one name across three protocols (#494).** The SAML SSO
profile names itself to each service provider by `<entityID>:<sp>` where
`saml2.perApplicationEntityId` is on (`saml2_sso.idpEntityIdFor()`), in the
assertion's Issuer and in `/saml2/metadata/{sp}`. A WS-Trust assertion,
SAML 2.0 or SAML 1.1, whose AppliesTo a REGISTERED application answers to
(`appliesToApplication()`: `forAppliesTo()`, then the entry of that very
identifier) carries THAT application's entityID, keyed by its registry
identifier; WS-Federation does the same for a registered `wtrealm`, and
publishes it at `/wsfed/metadata/{rp}` (`../ws-federation/CLAUDE.md`). SSO's
function decides all of it, so the three cannot differ.

**"Registered" is `appRegisteredBy`** — an administrator, RFC 7591, an
OpenID Federation or this service's seeding. `handleRst()`'s own `seen()`
files every AppliesTo it issues for; counting that entry would give the
second token for an unregistered AppliesTo a different Issuer from the
first. An AppliesTo nobody registered carries the shared entityID, on every
request. Until #494 any entry counted, which is that bug, in product.

`wstrust.issuer` and `wsfed.entityId`'s shared form have no per-application
reading on GET /sts: the STS has one name.

## An application nobody registered gets nothing, in product (#496, 2026-10-06)

rcbj, on #496: in product an application that is not registered gets nothing
but its protocol's own "unknown application" error — and **an RST with no
`AppliesTo` at all is refused too**. `unregisteredApplication()` asks it,
behind `mode.issuesToUnregisteredApplications()` (the
`unregistered-applications` row on `/admin/mode`):

* **"Registered" is the #494 word above**: `appRegisteredBy` on the entry
  `appliesToApplication()` resolves the AppliesTo to, through
  `IssuerNames.registeredApplication()`. So the application refused and the
  one whose entityID an issued assertion would carry are one; an entry a
  development `seen()` filed is a sighting and is refused like no entry, so a
  realm switched from development keeps nothing development learnt.
* **`wst:InvalidScope`, `STS-WSTRUST-0030`** for an unregistered AppliesTo;
  **`wst:InvalidRequest`, `STS-WSTRUST-0031`** for none or an empty one (the
  fault table above argues both). HTTP 500, as every other Fault.
* **ABOVE `authenticate()`**, which is where the requester's
  `recordAuthentication()` row is written: a refused request leaves no
  `/admin/users` row, no `seen()` sighting, no delegation act and no token.
  The cost is that an unregistered AppliesTo with a bad credential is
  answered `InvalidScope` rather than `FailedAuthentication`; the request is
  unanswerable whoever sent it, and answering it first is what keeps the
  caller out of every register.
* **Every token type (SAML 2.0, SAML 1.1, JWT) and `OnBehalfOf` / `ActAs`**:
  it is asked before the token type or the delegation is read. **Issue and
  Renew** — every operation that mints; Validate and Cancel issue nothing and
  are not asked.
* **Development is unchanged**: a token for any AppliesTo or none, under the
  shared name, and `seen()` files the AppliesTo.
* **An entry an LDAP add made is not registered either**: the add writes no
  `appRegisteredBy` (the registry writes it, for the console, `/admin-api`,
  RFC 7591, an OpenID Federation and the seeds), so #494's definition reads
  it as one that turned up. Whether an LDAP add should count is open on
  #496; until it is decided, register through the console or `/admin-api`.

`tests/unregistered_applications.js` holds it in both modes, with the
nothing-recorded checks; `tests/wstrust_fault_codes.js` holds both faults.

**A JWT's `iss` is not one of these.** It is the realm's OAuth issuer
(#476's exceptions, above; rcbj kept it on #494).

## ANY TOKEN TYPE IN ANY SEAT, AND AN APPLICATION AS ITSELF (#519, 2026-10-08)

rcbj: "maximum flexibility in supported input / output token types for the
WS-Trust protocol". An RST has three seats that take a token, and each takes
SAML 2.0, SAML 1.1 and JWT:

| Seat | What it takes |
|---|---|
| the requester's credential, `wsse:Security` | a UsernameToken; an assertion this STS issued (either SAML version); **a JWT this STS issued (#519)**, in the `wsse:BinarySecurityToken` this STS's own RSTR carries one in |
| `<wst:OnBehalfOf>` / `<wst14:ActAs>` | an assertion (either version); a JWT (#477) |
| `wst:TokenType` | SAML 2.0, SAML 1.1 (#487), JWT (#476) |

**THE REQUESTER'S JWT** is read by `readOwnJwt()`, the one function the
delegated JWT goes through too, so the two seats cannot disagree about what
"a JWT this STS issued" means: in product verified with this realm's own key,
within `exp` / `nbf`, the realm's OAuth issuer (#480), and a subject this
realm knows. Its refusals are the requester's — `wst:FailedAuthentication`,
`wst:ExpiredData` for an expired one — under the delegated JWT's codes
(`0026`–`0028`). An accepted one is a credential issued earlier, so a SAML
assertion issued on it states PreviousSession, as on an assertion. A JWT
inside OnBehalfOf / ActAs is NOT read as the requester's
(`insideAnotherPartysToken()`), and `homeNameOf()` reads its `sub` to place
the request in a deployment of cells.

**AN APPLICATION AUTHENTICATES AS ITSELF, WITH ITS CLIENT SECRETS** (rcbj: "I
don't really want to use a user object service account along side the
application object. it's redundant"). A UsernameToken whose Username names
NO person and names an application — by identifier, else by client_id — is
checked against that application's unexpired client secrets
(`applicationSecretCredential()`), in product; development believes it, as
it believes a person's password, except the reserved `invalid`. A wrong
secret is the fault a wrong password gets (`0003`), for the enumeration
rule. **A person of the name is asked first**, so a service account (#221)
beside an application of its name authenticates exactly as before: service
accounts are still supported, and the application path is for a tier that
has none. **WS-Trust only**: the other password-only doors (LDAP bind, SCIM
and SSF Basic, EST) still read people alone.

* **An application's own token is about the application.** A JWT for it
  names it by its client subject — `urn:sts:client:<client_id>` where the
  token endpoint does (RFC 9700 mode, which product implies), bare
  otherwise, as an `act` entry names it — and `client_id` its own; so
  `0017` does not refuse it. A SAML assertion's NameID is its identifier.
  Presented back as the credential, either is read to the application
  (`applicationNamedBy()`), and the delegation policy reads the APPLICATION
  entry, as it always did for a service account.
* **Recorded as a client** (`recordAuthentication({ isClient })`), which is
  what keeps the directory from making a person of its name in development
  (`ldap.autocreateUsers`). Without it, the first token an application asked
  for would have grown exactly the service account this exists to avoid.
* **The act names the token the requester presented.** A delegation act's
  `WS-Security credential` row carries the identifier (assertion `ID` /
  `AssertionID`, JWT `jti`) of a token presented as the credential, so the
  register can follow the token a tier was issued for itself to the act it
  was spent on.

**A TOKEN AS THE CREDENTIAL IS ADDRESSED TO ITS HOLDER OR TO THE IdP**
(rcbj, 2026-10-08: "A caller's credential AppliesTo element can either be
the audience registered in the application object or a generic audience that
references the IdP"). In product, an assertion or a JWT presented in
`wsse:Security` is accepted only when one of its audiences is
(`credentialAudienceProblem()`):

* an audience its holder's APPLICATION registers — the subject's
  application by identifier or client_id (a service account is the
  application of its name), the audience resolving to it through the
  AppliesTo lookup (`appliesToApplication()`); this is the token a tier was
  issued for itself; or
* one of the names this IdP answers to (`idpAudiences()`): the WS-Trust
  issuer name GET /sts reports, the realm's SAML entityID, the realm's OAuth
  issuer, and the `/sts` address at the request's base.

Anything else is `STS-WSTRUST-0032`, `wst:FailedAuthentication`. It closes
what was open before #519 for an assertion credential too: a tier holding a
token about a person, addressed to the tier, was authenticated AS that
person by presenting it. A person who wants a credential of their own asks
for one addressed to the IdP. **An RST whose AppliesTo is one of the IdP's
names is issued in product**, beside #496's registered applications
(`unregisteredApplication()`): the IdP is not an application and is not
unregistered. Development verifies no credential and enforces none of it.

`tests/wstrust_jwt_claims.js` sections R and S hold it in process in both
modes; `tests/vendored/sts_wstrust_own_token_chain.js` drives the four-tier
chain on each tier's own token in every type, and the 36-request matrix.

## A SECOND-FACTOR PERSON'S USERNAMETOKEN (2026-09-22, #101)

`requesterCredential()` passes `door: 'wstrust'`, so in product a person who
holds or must hold a second factor is refused their own password with the one
`STS-WSTRUST-0003` fault a wrong password gets, and presents an app password
scoped to `wstrust` instead; the authentication row's method then says
`(app password)`. `authn/CLAUDE.md` owns the rule. WS-Trust has no rate limit
of its own for a refused UsernameToken, so there is nothing further to count.

## IN A SERVICE DEPLOYED AS CELLS (#98 D10, 2026-09-28)

`POST /sts` is a `handler` row of `common/cell_placement.ts`: an RST is
relayed WHOLE to the home cell of the person whose credential it presents,
before anything is read for the risk standing, verified, recorded or spent
(`homeNameOf()`, `stsEndpoint()`). The name is, in order, the requester's
UsernameToken's Username, the requester's own SAML assertion's NameID, and —
with no requester credential, which only development allows — the subject of
the OnBehalfOf / ActAs.

**A SAML ASSERTION THIS REALM SIGNED WOULD VERIFY IN ANY CELL**, since the
signing keys are the global tier's (D8), and it is relayed anyway: what
follows the signature is the person's — the authentication recorded against
their entry, the issuance policy and risk standing that read it, the issued
token's attributes, and the browser session the exchange may start. None of
that exists outside their home.

**A DELEGATION ACROSS CELLS** is served at the REQUESTER's home, which does
not hold the delegated subject's entry when they are homed elsewhere. That
home is asked for their credential-free attributes (`fetch-attributes`,
`common/cell_attributes.ts`), released only where the transfer policy says,
and the exchange runs with them held in this process's directory for its own
synchronous duration (`delegatedHere()`) — so the token's subject, its
configured attributes, the delegation policy's flags on their entry and the
issuance policy's roles are theirs. **Fail-closed (D6)**: home refusing
(`STS-CELL-0124`, 403) or unreachable (`STS-CELL-0125`, 503) is a Fault and
no token. A person already held here as a projection is read as they are.
A NameID that is not a login name (an email address, a pairwise value) is
unknown to the routing index and served where it arrives. Held in process by `tests/cell_saml_federation.js`.

