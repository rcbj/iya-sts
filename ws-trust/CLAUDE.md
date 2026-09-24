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

The requester also carries an `application` where this registry already holds an
entry under the name it authenticated as. It stays a LOOKUP: an unknown name
leaves the slot empty and the party is drawn from `presented`, as before.

**Both are authorized by the delegation policy since #108 (2026-09-23)**, and
the row names what allowed it in the same field where a Kerberos row names an
attribute on an account — see the next section. What this service does NOT do
is put the composite fact into an `ActAs` token — nothing in the assertion says
a middle tier acted — and the row states that as a gap in the mock rather than
in the profile.

## WHO MAY ACT FOR WHOM (#108, 2026-09-23)

WS-Trust puts no authorization on either element — 1.3 section 9.2 and 1.4
section 9.3 describe what the requester ASKS for and leave the decision to the
STS — and until #108 this one decided nothing. `handleRst()` now asks
`../common/delegation_policy.ts` (rule 3az, `../common/CLAUDE.md`) after the
role gate and the JWT-subject check and before the token is built: the one
place that knows the `AppliesTo`, which is the TARGET. The intermediary is the
REQUESTER; `OnBehalfOf` is `impersonation` and needs
`appTrustedToImpersonate`, `ActAs` is `delegation`.

**ONLY AN APPLICATION MAY DELEGATE** — the owner's decision on #108. The
requester's authenticated NAME must be an application entry's identifier;
the credential it presented (a UsernameToken, verified against a
`userPassword`) may be kept on a service account entry of the same name, which
is the only way an application authenticates here. A requester that is only a
PERSON is refused `STS-WSTRUST-0019`, and the fault says why.

**A REFUSAL IS WS-TRUST 1.4 SECTION 11's `wst:RequestFailed`** ("The specified
request failed"). `soapFault()` takes the fault code as an optional third
argument and the request's own trust namespace as the fourth: on SOAP 1.1 it
REPLACES `soap:Client` as the `faultcode`, and on SOAP 1.2 it is the `Subcode`
under `soap:Sender` — section 11's own mapping. Every other refusal here still
sends the generic fault, which is a gap worth a ticket rather than a sweep made
on the side. `STS-WSTRUST-0018` for the attribute rule, `0019` for a person
requester, `0020` for the XACML Deny.

**ENFORCED IN PRODUCT** (`mode.authorizesDelegation()`); development issues and
the act says "WOULD HAVE BEEN REFUSED in product: …". A refused act is recorded
with `outcome: refused` before the fault is answered, so it is on
`/admin/delegation` — the only list a refusal is in. A requester delegating
about ITSELF acts for nobody and needs nothing.

**THE ORDER COST ONE THING, AND IT IS STATED RATHER THAN FIXED.**
`authenticate()` records the delegated subject's `recordAuthentication()` row
before the policy is asked, so a refused delegation still leaves that row on
`/admin/users`. Moving the policy into `authenticate()` would need the
`AppliesTo`, which the "authenticate ABOVE the branch" rule below keeps out of
it.

---

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

## A SECOND-FACTOR PERSON'S USERNAMETOKEN (2026-09-22, #101)

`requesterCredential()` passes `door: 'wstrust'`, so in product a person who
holds or must hold a second factor is refused their own password with the one
`STS-WSTRUST-0003` fault a wrong password gets, and presents an app password
scoped to `wstrust` instead; the authentication row's method then says
`(app password)`. `authn/CLAUDE.md` owns the rule. WS-Trust has no rate limit
of its own for a refused UsernameToken, so there is nothing further to count.
