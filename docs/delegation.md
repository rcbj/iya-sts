---
title: Delegation and impersonation
---

# Delegation and impersonation

Four of the protocols iya-sts speaks let one party obtain a token **about
somebody else**:

* the **OAuth 2.0 token exchange**
  ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693));
* **WS-Trust**'s `OnBehalfOf` and `ActAs`
  ([1.3](https://docs.oasis-open.org/ws-sx/ws-trust/v1.3/ws-trust.html),
  [1.4](https://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html));
* **Kerberos**' two Microsoft extensions, S4U2Self and S4U2Proxy
  ([MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/)),
  and a forwarded ticket-granting ticket;
* **GNAP**'s trusted client presenting a user assertion, and a resource
  server deriving a downstream token
  ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635),
  [RFC 9767](https://www.rfc-editor.org/rfc/rfc9767)).

None of the four specifications says who may do this. RFC 8693 section 5
leaves it to "the policy of the authorization server", and WS-Trust describes
only what a requester *asks for*. Active Directory's answer for Kerberos is a
handful of account attributes.

iya-sts answers the question **once, for all four protocols**:

* the same settings on the same directory entries;
* the same two questions asked of the same
  [XACML issuance policy](xacml.html);
* the same record of every act, issued or refused, on Monitoring →
  Delegation.

This page describes that model, then what each protocol adds.

## The four parties

Every act names four parties. Each protocol finds them in its own message:

| Party | What it is | OAuth 2.0 token exchange | WS-Trust | Kerberos |
|---|---|---|---|---|
| **Subject** | who the new token is about | the `subject_token`'s subject | the subject of the token inside `OnBehalfOf` / `ActAs` | the user named in S4U2Self (`PA-FOR-USER` or `PA-S4U-X509-USER`), or the client of S4U2Proxy's evidence ticket |
| **Actor** | who is asking | the `actor_token`'s subject; without one, the authenticated client | the requester (whoever authenticated the RST) | S4U2Self: the service asking for a ticket to itself; S4U2Proxy: the front end presenting the evidence ticket |
| **S** (source) | the application the subject's token was issued *for* | the `subject_token`'s `aud`, else its `client_id` / `azp` | the delegated assertion's `Audience` | the service the evidence ticket was issued for |
| **R** (target) | the application the new token is *for* | the one `audience` or `resource` | the `AppliesTo` | the service named in the TGS-REQ |

**Parties are entries in the directory.**
* An application is named by its identifier, client ID or registered
  audience, `AppliesTo` or service principal name.
* A person is named by their username.

Every target is resolved to the application that registered it before
anything is compared. A target that no application registers is refused.

## Delegation, impersonation, and acting for yourself

An act has one of three **semantics**:

* **Delegation.** The actor acts for the subject *visibly*.
  * The issued token names the actor: RFC 8693's `act` claim, or a SAML 2.0
    Delegation Restriction condition.
  * Kerberos S4U2Proxy's ticket is the front end's request on the user's
    behalf.
  * `act` claims **nest**. A token that already carried an actor keeps it
    under the new one (RFC 8693 section 4.1).
* **Impersonation.** The actor obtains a token that is simply the subject's.
  * Nothing in the token names the actor.
  * A prior `act` is still kept. An exchange never turns a delegated token
    into an ordinary one.
* **Self.** The actor *is* the subject, or is S keeping the token for S.
  * Nobody is acted for, and nothing beyond the protocol's own checks is
    needed.
  * A self exchange that names no target is for the subject token's own
    audience.

**The policy chooses the semantics**, by this precedence:

1. what the **request** asks for:
   * RFC 8693: this service's extension parameter
     `exchange_semantics=delegation|impersonation`;
   * WS-Trust: the element (`ActAs` is delegation, `OnBehalfOf` is
     impersonation);
   * Kerberos: the extension (S4U2Self is impersonation, S4U2Proxy is
     delegation);
2. the **actor's** default (`appDefaultDelegationSemantics`);
3. the **subject's** default (`stsDefaultDelegationSemantics`);
4. the realm's `delegation.defaultSemantics` (**delegation** unless set).

A request may only ask for semantics that **both** the actor and the subject
allow:
* the actor's `appDelegationSemantics` — empty means delegation only;
* the subject's `stsDelegationSemantics` — empty means either.

## The common controls

These are the same for all four protocols. They live on the directory
entries, so they can be edited from the console, through `/admin-api`, or with
an `ldapmodify`.

**On an application entry** (Directory → Applications → the application):

| Attribute | Set on | Meaning | Active Directory analogue |
|---|---|---|---|
| `appAllowedToDelegateTo` | S | Applications S may hand a subject on to. For an impersonation, the applications the *actor* may reach. | `msDS-AllowedToDelegateTo` |
| `appAllowedToActOnBehalfOf` | R | Applications **and people** R accepts acting for others: resource-based delegation, set by the target's owner. | `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| `appDelegationSemantics` | the actor | Semantics it may use, `delegation` and/or `impersonation`. Empty means delegation only. | `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` (impersonation) |
| `appDefaultDelegationSemantics` | the actor | Its semantics when the request names none. | — |
| `appDelegationSubjectGroup` | the actor | Groups, by DN, whose members it may act for. Empty means anybody not protected. | — |
| `appNotDelegated` | an application as subject | Never acted for. | `NOT_DELEGATED` |
| `appMayAct` | an application as subject | The DN of one party it names as its delegate: tokens about it carry `may_act` naming that party, as the issuance policy assigns it. | — |
| `krb5TrustedForDelegation` | a Kerberos service | **Kerberos only, off by default.** Unconstrained delegation: it may receive and use a user's forwarded TGT. | `TRUSTED_FOR_DELEGATION` |
| `appAllowedProtocol` | any application | Protocols the application is used with. The controls above apply to whichever of WS-Trust, OAuth 2.0, Kerberos and GNAP it lists; there are no per-protocol copies. | — |

**On a person's entry** (Directory → People → the person, *Delegation*):

| Attribute | Meaning |
|---|---|
| `stsNotDelegated` | Never acted for, by anybody (`NOT_DELEGATED`). |
| `stsDelegationSemantics` | Semantics this person may be acted for with. Empty means either. |
| `stsDefaultDelegationSemantics` | Their default, after the actor's. |
| `stsMayAct` | One party this person names as their delegate. Their access tokens (and WS-Trust JWTs) carry RFC 8693 section 4.4's `may_act` claim naming it — the issuance policy's `assign-may-act` question assigns it, and a realm's policy may name another party or none. |

**Realm settings** (Protocols → OAuth 2.0 → Delegation, and `GET
/admin-api/config`):

| Setting | Environment variable | Default | What it does |
|---|---|---|---|
| `delegation.defaultSemantics` | `STS_DELEGATION_DEFAULT_SEMANTICS` | `delegation` | The last word on semantics. |
| `delegation.protectedGroups` | `STS_DELEGATION_PROTECTED_GROUPS` | (none) | Groups whose members are never acted for: Active Directory's *Protected Users*. The console's Admin Read and Admin Write rosters are always protected as well. |
| `delegation.actorRole` | `STS_DELEGATION_ACTOR_ROLE` | `DELEGATION_ACTOR` | The role a **person** needs before they may act for anybody. An application needs no role. |
| `delegation.maxRecords` | `DELEGATION_MAX_RECORDS` | `2000` | How many acts Monitoring → Delegation keeps. |

All four are runtime settings, per realm. This table is a copy: the live
values are on the console page and at `GET /admin-api/config`.

## How an act is decided

The issuance policy refuses in this order. The first refusal that applies is
the one the client hears.

1. **`may_act` names somebody else.** The subject's token carries `may_act`
   (RFC 8693 section 4.4) and it does not name the actor. Refused **in every
   mode**: the token itself says no.
2. **More than one target.** A token is issued for exactly one.
3. **The target is not registered.** No application in the realm registers it.
4. **No target**, unless the act is self.
5. **The subject is protected**: `stsNotDelegated` or `appNotDelegated`, a
   member of a `delegation.protectedGroups` group, or on the console roster.
6. **The actor is unknown**, or is a person without the role
   `delegation.actorRole` names.
7. **The semantics are not allowed** by the actor or the subject.
8. **The subject is outside the actor's `appDelegationSubjectGroup`**, unless
   the subject's `may_act` names the actor.
9. **The subject has no authority.** It holds none of the roles the
   application requires (`appRequiredRole`): S for a delegation, R otherwise.
10. **The relationship does not hold.**
    * **Delegation:** S must delegate to R (`appAllowedToDelegateTo` on S, or
      `appAllowedToActOnBehalfOf` on R). In addition, the actor must be S, R,
      or a party R accepts by name.
    * **Impersonation:** the actor must reach R: R is the actor itself, R is
      on the actor's `appAllowedToDelegateTo`, or R accepts the actor.

Everything else is allowed, with the semantics chosen above and R as the
audience.

### Product and development mode

**Product mode refuses.** **Development mode** asks the same questions,
issues the token anyway, and writes on the act *"WOULD HAVE BEEN REFUSED in
product: …"*, so a client under test still gets a working token and the
operator sees what would break.

Two refusals hold **in both modes**, because they are not policy but the
request contradicting itself:
* a `may_act` mismatch;
* a WS-Trust request carrying both `OnBehalfOf` and `ActAs`.

**The KDC refuses in both modes**, as it always has: in development its
fixture accounts carry delegation settings (seeded onto their entries) so that
every refusal and every success can be reached, and a KDC that issued a
refused ticket would change what goes on the wire. The act on Monitoring →
Delegation still says what refused it.

### Writing your own rules

The rules are rules of the issuance policy, so a realm can add its own. A
realm's issuance policy (Directory → Policies → XACML) is asked **first**;
the built-in policy answers whatever it says nothing about. To refuse more,
write a Deny on action-id `exchange-token` with the obligation
`urn:sts:xacml:obligation:exchange` (verdict `refuse`, refusal `policy`); the
client then hears its protocol's policy refusal. The attributes a rule can
test — the four parties, both semantics, `may_act`, the protocol and the
mode — are listed in [XACML](xacml.html).

## Per protocol

### OAuth 2.0 token exchange (RFC 8693)

* `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, with a
  `subject_token` and optionally an `actor_token`. In product mode each must
  be a token this realm signed and has not revoked, or an assertion from an
  issuer the realm declared ([below](#assertions-as-the-subject-or-the-actor)).
* `exchange_semantics=delegation|impersonation` is this service's extension
  for asking. Any other value, or the parameter sent twice, is
  `invalid_request` in every mode.
* **Delegation** puts `act: { sub: <actor> }` on the access token, nesting any
  `act` the subject token carried. **Impersonation** issues a token about the
  subject with no new `act`.
* **The chain begins with the original client.** When the subject token
  carries no `act` — the first exchange of a token — delegation nests the
  client that token was issued to (its `client_id`) beneath the actor. Two
  hops from a web application's sign-in therefore read
  `act: { sub: <second actor>, act: { sub: <first actor>, act: { sub:
  <web application> } } }`. A client's `sub` here is `urn:sts:client:<id>` in
  RFC 9700 mode (and so in product mode) and the bare `client_id` otherwise,
  as for an actor token from `client_credentials`. Nothing is nested when the
  client exchanging the token is the one it was issued to. Only the outermost
  `act` is the current actor; the nested ones are history.
* **Every entry names its issuer, and a client has one form.** Each `act`
  entry the exchange writes carries `iss`, the issuer of the token it is in,
  as the token-chaining profile requires — so two hops read
  `act: { sub: <second actor>, iss: <issuer>, act: { sub: <first actor>,
  iss: <issuer>, act: { sub: <web application>, iss: <issuer> } } }`. An entry
  copied from the subject token keeps its own `iss`; one without is given
  this issuer only when this service issued the subject token. A client named
  as an actor — including the exchanging client when the policy chooses a
  delegation and no actor token was sent — is always `urn:sts:client:<id>` in
  RFC 9700 mode (and so in product mode) and the bare `client_id` otherwise.
  A `may_act` naming the client in either form names it.
* **Introspection returns the chain.** `/oauth2/introspect` answers with the
  token's `act`, nested as in the token, and its `may_act` (RFC 8693 section
  7.2), in the JSON response and in the RFC 9701 JWT alike, under the rule
  every other member follows: an authenticated caller the token is not for
  is told only that it is not active.
* `may_act` is read off the verified subject token and compared with the
  actor's `sub` (and `iss`, when the claim has one). It is *issued* on a
  person's access tokens when their entry carries `stsMayAct`.
* **The scope may narrow, never widen** — a rule of the issuance policy too
  (`exchange-widens-scope`): in product, a scope outside the subject token's
  `scope` is `invalid_scope`. A subject token with no `scope` claim (an ID
  Token, a WS-Trust JWT) has nothing to compare against.
* **No `scope` on the exchange carries the subject token's forward.** The
  issued token is asked for the `scope` sent, else the subject token's `scope`
  claim, else nothing — the same rule for every kind of subject token. Either
  way it is then narrowed as every grant here is: to the scopes the client
  declares, the roles that authorize them, and — for an `audience` or
  `resource` that is not this service — without the OpenID Connect scopes
  (`openid`, `profile`, …), which belong to this service's own UserInfo
  (RFC 9068 section 2.2.3).
* **The response says what was issued.** `scope` names the scopes the access
  token carries and is left out when it carries none (RFC 6749 section 3.3
  has no empty value). An `id_token` comes back beside it only when the
  issued token's scope carries `openid` — so an exchange for another resource
  server returns an access token and nothing else, whatever the subject
  token's scope was. `issued_token_type` is always
  `urn:ietf:params:oauth:token-type:access_token`.
* **Refusals** are spoken as RFC 8693 section 2.2.2 says:

| Refusal | Error |
|---|---|
| no relationship; two targets; an unregistered target; no target | `invalid_target` |
| the semantics; authority; a protected subject; an unknown actor; `may_act`; a realm policy | `invalid_request` |

In development, two audiences are refused too, by RFC 9068 section 3: an
access token for two resources is ambiguous.

See [OAuth 2.0 and OpenID Connect](oauth-oidc.html) and
[Configuring OAuth 2.0 grants](configure-oauth2-grants.html).

#### Assertions as the subject or the actor

RFC 8693 section 3 names three assertion token types, and each is accepted as
the `subject_token` or the `actor_token` when a realm has **declared its
issuer**:

| `subject_token_type` / `actor_token_type` | What it is | Declared on the issuer's application entry |
|---|---|---|
| `urn:ietf:params:oauth:token-type:jwt` | an RFC 7523 JWT assertion | `oauthAssertionIssuer`, with a key as for the [JWT bearer grant](jwt-assertions.md) |
| `urn:ietf:params:oauth:token-type:saml2` | an RFC 7522 SAML 2.0 assertion | `oauthSamlAssertionIssuer`, with a certificate as for the [SAML bearer grant](saml-assertions.md) |
| `urn:ietf:params:oauth:token-type:saml1` | a SAML 1.1 assertion | the same as SAML 2.0 |

A `jwt` token this realm signed is still read as its own token. Anything else
of those types is verified **exactly as the assertion grant verifies it**:

* the issuer declared, or a person holding a key pair of their own — who may
  assert only about themselves;
* the signature against a key or certificate registered for that issuer. For
  SAML, a certificate that merely chains to the realm's CA is not enough;
* the certificate's chain and revocation;
* the expiry and the lifetime ceiling;
* **one use, ever**, in the same history as the grant. An assertion spent at
  the `jwt-bearer` or `saml2-bearer` grant is refused at the exchange, and the
  reverse. It is spent only when tokens are issued.

The grant's on/off switches (`oauth2.jwtBearerGrant`,
`oauth2.saml2BearerGrant`) do not apply: an exchange is not the grant.

**The subject is the person the assertion names**, provisioned as the grant
provisions one. An assertion naming nobody the directory holds is refused
(`STS-OAUTH-0798`). As the `actor_token`, the person it names is the actor and
`act.sub` is their subject. SAML 1.1 is read from its own elements: the
`AssertionID`, the `Issuer` attribute, the `NameIdentifier` in each statement,
the `urn:oasis:names:tc:SAML:1.0:cm:bearer` confirmation method, and the
`<AudienceRestrictionCondition>`. A SAML assertion whose version is not the
one its declared type says is refused (`STS-OAUTH-0797`).

**The audience** is `oauth2.tokenExchangeAudience`:

* `authorization-server` (the default) — the grant's rule. The assertion is
  addressed to this token endpoint or issuer, and a SAML `Recipient` is the
  token endpoint. S, the application the subject's token was issued for, is
  then the exchanging client: an assertion addressed to this server was issued
  for whoever presents it.
* `any-declared-relying-party` — also an application registered in the realm.
  This is **token forwarding**: a relying party that was handed an assertion
  trades it here. S is that relying party, a SAML `Recipient` may be an
  assertion consumer service registered on the exchanging client
  (`samlAssertionConsumerService`), and the act on `/admin/delegation` says the
  input was FORWARDED.

> **Warning.** Under `any-declared-relying-party`, every relying party an
> assertion was issued to can exchange it for a token from this service. Turn
> it on only where that is the design.

An audience the rule does not accept is `invalid_request` (`STS-OAUTH-0796`).
**Who may then exchange the assertion is the policy above**, unchanged: S, the
actor, R and the subject's protections, as for any subject token.

In **development** mode an undeclared or unverifiable `jwt` token is still read
without verifying, as it always was. A SAML token that does not verify is
refused in both modes: there is no unverified reading of XML to fall back on.

### WS-Trust OnBehalfOf and ActAs

* The **requester** is the actor; the token in the element is the subject's;
  its `Audience` is S; the `AppliesTo` is R.
* **`ActAs` asks for delegation** (WS-Trust 1.4 section 9.3). The issued token
  names the requester after any party the delegated assertion already named:
  * a **SAML 2.0** assertion carries the
    [SAML V2.0 Condition for Delegation Restriction](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-delegation-cs-01.html):
    one `del:Delegate` per party, least to most recent, as that profile
    orders them;
  * a **JWT** (`TokenType` `urn:ietf:params:oauth:token-type:jwt`) carries the
    same chain as nested `act` claims, the most recent outermost.
* **`OnBehalfOf` asks for impersonation** (1.3 section 9.2). The token is the
  subject's, and adds nobody to the chain; one the delegated assertion
  already carried is kept.
* **Both elements in one request** are refused with `wst:InvalidRequest`, in
  every mode.
* A request with **no `AppliesTo`** is refused unless it is a self one.
* **Every policy refusal is a SOAP Fault carrying WS-Trust 1.4 section 11's
  `wst:RequestFailed`**: the `faultcode` on SOAP 1.1, the `Subcode` on SOAP
  1.2. The fault's reason says which rule refused. A refused act is on
  `/admin/delegation`; its subject is not added to `/admin/users`, which lists
  a delegated subject only once the policy has allowed the act (or, in
  development, recorded that it would have refused it).
* `may_act` is not read here: the delegated token is always a SAML assertion,
  which has no such claim. A **JWT** issued about a person who set
  `stsMayAct` carries `may_act`, as an access token does.

See [WS-Trust](ws-trust.html).

### Kerberos (MS-SFU)

Kerberos service accounts are applications here: the entry whose identifier
is the service's `SPN@REALM`. Their delegation settings are the common ones
above, not a second set kept by the KDC. In development the fixture services'
rules (`HTTP/frontend` to `HTTP/backend`, the resource-based `HTTP/rbcd`, the
`HTTP/notrusted` that may not impersonate, the trusted `HTTP/web`) are seeded
onto their entries the first time the KDC is asked, filling only what an entry
does not already hold, and the person `sensitive` carries `stsNotDelegated`.

* **S4U2Self** (protocol transition) is **impersonation**:
  * the service asks for a ticket to *itself* for a user, named by
    `PA-FOR-USER` or by certificate with `PA-S4U-X509-USER`;
  * the actor is that service, and it is R as well;
  * it is never refused for want of a policy — a ticket to yourself is not
    the privilege — but it is **forwardable** only when the policy allows the
    impersonation: the service allows it (`appDelegationSemantics`, the job
    of Active Directory's `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION`) and the
    user is not protected;
  * PA-S4U-X509-USER names the user by name, by a certificate this realm
    issued to them (its TLS client or enrollment Issuing CA, `clientAuth`,
    one `urn:sts:person:` name, not revoked), or both, which must agree. Its
    checksum and the request's nonce are checked, and the reply carries it
    back with a checksum of its own (key usage 27 when the client asks).
* **S4U2Proxy** is **delegation**:
  * the front end presents the user's evidence ticket and asks for a ticket to
    the back end;
  * the actor is the front end, which is S;
  * **classic** constrained delegation is the front end's
    `appAllowedToDelegateTo` naming the back end, and needs a forwardable
    evidence ticket;
  * **resource-based** constrained delegation (the request carries
    `PA-PAC-OPTIONS` with the RBCD bit) is the back end's
    `appAllowedToActOnBehalfOf` naming the front end.
* **Protected users** (`delegation.protectedGroups`, `stsNotDelegated`) are
  never the subject of S4U, and their tickets are not forwardable.
* **The evidence ticket is not taken on trust.** It is encrypted in the
  front end's own key, so the front end could set its forwardable flag
  (CVE-2020-17049, *Bronze Bit*) or forge one for anybody. The KDC verifies
  the PAC's ticket signature — which covers the flags — and its KDC
  signature with the krbtgt key, and refuses an evidence ticket with no PAC.
* **Unconstrained delegation** is `krb5TrustedForDelegation` on the service's
  entry, off unless set: its tickets carry `ok-as-delegate`, which tells a
  client it may forward its TGT there. The KDC is never told where a
  forwarded TGT goes, so what it controls is the person: a protected
  person's TGT is not forwardable, and a forwarding request presenting one is
  refused.
* **Refusals** are the KDC's own errors: `KDC_ERR_BADOPTION` for a
  relationship that does not hold, `KRB_AP_ERR_MODIFIED` for evidence that
  does not verify, `KDC_ERR_POLICY` for the rest of the policy.
* Delegation across Kerberos realms and trusts is not yet decided by this
  policy; see issue #430.

See [Kerberos and SPNEGO](kerberos.html).

### GNAP (RFC 9635, RFC 9767)

* **A trusted client presenting a user assertion is impersonation** — the
  S4U2Self shape. A client whose entry carries `gnapSkipInteraction` and that
  presents a verified `id_token` or `saml2` assertion in the grant request's
  `user` is issued tokens for that person with nobody asked:
  * the actor is the client, the subject the person the assertion names;
  * there is no S;
  * R is each resource server the requested access rights resolve to (one
    question each), or the client itself when they name none — which still
    needs `impersonation` in the client's `appDelegationSemantics`, because
    the token can be presented;
  * a `may_act` claim in the ID Token must name the client (every mode).
  The token is the person's and names no actor.
* **Token derivation is delegation** — the S4U2Proxy shape. A resource server
  presenting `existing_access_token` (RFC 9767 section 4):
  * is the actor and S; the subject is the original token's person;
  * R is each downstream resource server the requested rights resolve to, or
    the deriving one itself when it only narrows (self);
  * the derived token carries **no more access** than the original, in every
    mode, and names the deriving resource server in an `act` chain — in all
    five token formats — capped by `gnap.maxDerivationDepth`.
* A client skipping interaction **without** an assertion acts for nobody and
  is asked nothing.
* **Refusals** are `request_denied` (HTTP 403); the audited code says which
  rule (`STS-GNAP-0770` to `0782`).

See [GNAP](gnap.html#acting-for-somebody-else).

## Watching it

* **Monitoring → Delegation** (`/admin/delegation`) lists every act, issued or
  refused, from all four protocols, with the four parties, the semantics, the
  tokens consumed and produced, and the sentence saying what allowed or
  refused it. Filter by protocol, semantics, outcome or any name. In
  development, a refused act reads *WOULD HAVE BEEN REFUSED*.
* **The picture** (`/admin/delegation/map`) draws the same acts as a diagram:
  * a box per party and a line per relationship;
  * chains across protocols join where they share an application;
  * an application is one box however it was named — its identifier, an
    audience it registered, its client_id, or the subject it acts under
    with a `client_credentials` token (`urn:sts:client:<id>` in product);
  * drill-downs per chain, per application and per person.
* **Who may act for whom** (the page's *policy* section) lists the configured
  relationships, actors with their semantics and subject groups, and
  protected people and groups.
* The same three are `GET /admin-api/delegation`,
  `GET /admin-api/delegation/policy` and the map's `?format=json`.

## Related

* [XACML 3.0 and ALFA](xacml.html): the issuance policy these rules are part of.
* [Applications](applications.html): where the application attributes are edited.
* [What is not checked](what-is-not-checked.html): the development-mode behaviour.
* [Error codes](error-codes.html): each refusal's `STS-OAUTH-`, `STS-WSTRUST-`
  and `STS-KRB5-` code, recorded on the audit row and never sent.
