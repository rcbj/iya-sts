---
title: Delegation and impersonation
---

# Delegation and impersonation

Four of the protocols iya-sts speaks let one party obtain a token **about
somebody else**:

* the **OAuth 2.0 token exchange**
  ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)), with this service's
  own tokens or with RFC 7523 / RFC 7522 / SAML 1.1 assertions as its input;
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
  [XACML issuance policy](xacml.md);
* the same record of every act, issued or refused, on Monitoring →
  Delegation.

This page describes that model, how to configure it, what each protocol
accepts and issues, the claims that come out, and a worked example of every
kind of act, with `curl` wherever the protocol is HTTP.

**Contents**

* [At a glance](#at-a-glance)
* [The four parties](#the-four-parties)
* [Delegation, impersonation, and acting for yourself](#delegation-impersonation-and-acting-for-yourself)
* [Configuring who may act for whom](#configuring-who-may-act-for-whom)
* [How an act is decided](#how-an-act-is-decided)
* [Token types: what goes in and what comes out](#token-types-what-goes-in-and-what-comes-out)
* [Claims in the issued token](#claims-in-the-issued-token)
* [Worked examples](#worked-examples)
* [Per protocol](#per-protocol)
* [Refusals and troubleshooting](#refusals-and-troubleshooting)
* [Watching it](#watching-it)

## At a glance

| Protocol | Mechanism | Semantics | What the request presents | What is issued | Where the actor shows in the result |
|---|---|---|---|---|---|
| OAuth 2.0 (RFC 8693) | token exchange, `exchange_semantics=delegation` or an actor token | delegation | `subject_token` (+ optional `actor_token`) of type `access_token`, `refresh_token`, `id_token`, `jwt`, `saml2` or `saml1` | an access token (`issued_token_type` `…:access_token`); a refresh token on request; an ID Token when `openid` survives | nested `act` claim |
| OAuth 2.0 (RFC 8693) | token exchange, `exchange_semantics=impersonation` | impersonation | the same | the same | nowhere (a prior `act` is kept) |
| WS-Trust 1.4 | `<wst14:ActAs>` | delegation | a SAML 2.0 assertion or a JWT this STS issued, plus the requester's own credential | SAML 2.0, SAML 1.1 or JWT (`wst:TokenType`) | SAML 2.0: `del:Delegate` in a Delegation Restriction condition; JWT: nested `act`; SAML 1.1: nowhere |
| WS-Trust 1.3 | `<wst:OnBehalfOf>` | impersonation | the same | the same | nowhere (a prior chain is kept) |
| Kerberos (MS-SFU) | S4U2Self (`PA-FOR-USER`, `PA-S4U-X509-USER`) | impersonation | the service's own TGT | a service ticket to the service itself, forwardable only when allowed | nowhere |
| Kerberos (MS-SFU) | S4U2Proxy, classic or resource-based | delegation | the service's TGT and the user's forwardable evidence ticket | a service ticket to the back end | `S4U_DELEGATION_INFO` in the PAC |
| Kerberos (RFC 4120) | forwarded TGT | recorded as impersonation | a forwardable TGT | a forwarded TGT | nowhere |
| GNAP (RFC 9635) | trusted client (`gnapSkipInteraction`) with `user.assertions` | impersonation | an `id_token` or `saml2` assertion issued to that client | GNAP access tokens in the client's format | nowhere |
| GNAP (RFC 9767) | `existing_access_token` | delegation | a GNAP access token issued for the deriving resource server | a derived GNAP access token, no wider than the original | `act`, in all five token formats |

Two more grants are recorded on Monitoring → Delegation as delegation,
because a third party is asserting who the subject is: the
[JWT bearer grant](jwt-assertions.md#it-is-recorded-as-a-delegation)
(RFC 7523) and the [SAML 2.0 bearer grant](saml-assertions.md) (RFC 7522).
They are not decided by the policy on this page; their own pages say what
they check.

## The four parties

Every act names four parties. Each protocol finds them in its own message:

| Party | What it is | OAuth 2.0 token exchange | WS-Trust | Kerberos | GNAP |
|---|---|---|---|---|---|
| **Subject** | who the new token is about | the `subject_token`'s subject | the subject of the token inside `OnBehalfOf` / `ActAs` | the user named in S4U2Self (`PA-FOR-USER` or `PA-S4U-X509-USER`), or the client of S4U2Proxy's evidence ticket | the person the user assertion names, or the original token's person |
| **Actor** | who is asking | the `actor_token`'s subject; without one, the authenticated client | the requester (whoever authenticated the RST) | S4U2Self: the service asking for a ticket to itself; S4U2Proxy: the front end presenting the evidence ticket | the client instance, or the deriving resource server |
| **S** (source) | the application the subject's token was issued *for* | the `subject_token`'s `aud`, else its `client_id` / `azp` | the delegated assertion's `Audience` | the service the evidence ticket was issued for | none for a user assertion; the deriving resource server for a derivation |
| **R** (target) | the application the new token is *for* | the one `audience` or `resource` | the `AppliesTo` | the service named in the TGS-REQ | each resource server the requested rights resolve to |

**Parties are entries in the directory.**
* An application is named by its identifier, client ID or registered
  audience (`oauthAudience`), `AppliesTo` (`wstrustAppliesTo`) or service
  principal name (`SPN@REALM`).
* A person is named by their username.

Every target is resolved to the application that registered it before
anything is compared. A target that no application registers is refused.

## Delegation, impersonation, and acting for yourself

An act has one of three **semantics**:

* **Delegation.** The actor acts for the subject *visibly*.
  * The issued token names the actor: RFC 8693's `act` claim, or a SAML 2.0
    Delegation Restriction condition.
  * Kerberos S4U2Proxy's ticket is the front end's request on the user's
    behalf, and its PAC names every service it passed through.
  * `act` claims **nest**. A token that already carried an actor keeps it
    under the new one (RFC 8693 section 4.1).
* **Impersonation.** The actor obtains a token that is simply the subject's.
  * Nothing in the token names the actor. Monitoring → Delegation is the only
    place the act is visible.
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
   * GNAP: the act (a user assertion is impersonation, a derivation is
     delegation);
2. the **actor's** default (`appDefaultDelegationSemantics`);
3. the **subject's** default (`stsDefaultDelegationSemantics`);
4. the realm's `delegation.defaultSemantics` (**delegation** unless set).

A request may only ask for semantics that **both** the actor and the subject
allow:
* the actor's `appDelegationSemantics` — empty means delegation only;
* the subject's `stsDelegationSemantics` — empty means either.

## Configuring who may act for whom

### The common controls

These are the same for all four protocols. They live on the directory
entries, so they can be edited from the console, through `/admin-api`, or with
an `ldapmodify`. There are no per-protocol copies.

**On an application entry** (Directory → Applications → the application →
Configuration, *Every protocol*):

| Attribute | Set on | Meaning | Active Directory analogue |
|---|---|---|---|
| `appAllowedToDelegateTo` | S | Applications S may hand a subject on to. For an impersonation, the applications the *actor* may reach. | `msDS-AllowedToDelegateTo` |
| `appAllowedToActOnBehalfOf` | R | Applications **and people** R accepts acting for others: resource-based delegation, set by the target's owner. | `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| `appDelegationSemantics` | the actor | Semantics it may use, `delegation` and/or `impersonation`. Empty means delegation only. | `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` (impersonation) |
| `appDefaultDelegationSemantics` | the actor | Its semantics when the request names none. | — |
| `appDelegationSubjectGroup` | the actor | Groups, by DN, whose members it may act for. Empty means anybody not protected. | — |
| `appNotDelegated` | an application as subject | Never acted for. | `NOT_DELEGATED` |
| `appMayAct` | an application as subject | The DN of one party it names as its delegate: tokens about it carry `may_act` naming that party, as the issuance policy assigns it. | — |
| `appRequiredRole` | S or R | Roles a subject must hold for the application; a subject with none of them has no authority to be acted for there. | — |
| `krb5TrustedForDelegation` | a Kerberos service | **Kerberos only, off by default.** Unconstrained delegation: it may receive and use a user's forwarded TGT. | `TRUSTED_FOR_DELEGATION` |
| `appAllowedProtocol` | any application | Protocols the application is used with. The controls above apply to whichever of WS-Trust, OAuth 2.0, Kerberos and GNAP it lists. | — |

The values of `appAllowedToDelegateTo` and `appAllowedToActOnBehalfOf` are
application **identifiers** (for a Kerberos service, `SPN@REALM`, such as
`HTTP/backend.example.com@EXAMPLE.COM`). Neither list may name the
application itself; the console and the API refuse that value
(`STS-REG-0335`). On the console each of the two cells carries a search over
the realm's applications, and `appDelegationSubjectGroup` one over its groups
(see *Finding the other application of a delegation* in
[Applications](applications.md)).

**On a person's entry** (Directory → People → the person, *Who may act for
them*):

| Attribute | Meaning |
|---|---|
| `stsNotDelegated` | Never acted for, by anybody (`NOT_DELEGATED`). |
| `stsDelegationSemantics` | Semantics this person may be acted for with. Empty means either. |
| `stsDefaultDelegationSemantics` | Their default, after the actor's. |
| `stsMayAct` | One party (the DN of a person or an application) this person names as their delegate. Their access tokens (and WS-Trust JWTs) carry RFC 8693 section 4.4's `may_act` claim naming it — the issuance policy's `assign-may-act` question assigns it, and a realm's policy may name another party or none. A person sets it themselves on `/portal/delegate`. |

### Realm settings

Protocols → OAuth 2.0 → Delegation, and `GET /admin-api/config`:

| Setting | Environment variable | Default | What it does |
|---|---|---|---|
| `delegation.defaultSemantics` | `STS_DELEGATION_DEFAULT_SEMANTICS` | `delegation` | The last word on semantics. |
| `delegation.protectedGroups` | `STS_DELEGATION_PROTECTED_GROUPS` | (none) | Groups whose members are never acted for: Active Directory's *Protected Users*. The console's Admin Read and Admin Write rosters are always protected as well. |
| `delegation.actorRole` | `STS_DELEGATION_ACTOR_ROLE` | `DELEGATION_ACTOR` | The role a **person** needs before they may act for anybody. An application needs no role. The role is not created for you: make it with `roles/create-role` and add members with `roles/add-member`. |
| `delegation.maxRecords` | `DELEGATION_MAX_RECORDS` | `2000` | How many acts Monitoring → Delegation keeps. |
| `oauth2.tokenExchangeAudience` | `STS_OAUTH2_TOKEN_EXCHANGE_AUDIENCE` | `authorization-server` | What an assertion presented to a token exchange may be addressed to ([below](#assertions-as-the-subject-or-the-actor)). |
| `oauth2.tokenExchangeRefreshToken` | `STS_OAUTH2_TOKEN_EXCHANGE_REFRESH_TOKEN` | `when-requested` | `never`, `when-requested` or `always`: whether an exchange returns a refresh token. `oauthTokenExchangeRefreshToken` on the exchanging client's entry overrides it. |
| `gnap.tokenDerivation` | `STS_GNAP_TOKEN_DERIVATION` | `true` | Whether a GNAP resource server may derive a token at all. |
| `gnap.maxDerivationDepth` | `STS_GNAP_MAX_DERIVATION_DEPTH` | `2` | How many resource servers a derived token's `act` chain may name. |

All are runtime settings, per realm. This table is a copy: the live values
are on the console pages and at `GET /admin-api/config`, and every setting
is in [Configuration](configuration.md).

### Setting them through the API

Every control above is reachable by a machine. The calls below use the
helper from [Management API](management-api.md#getting-a-token):

```bash
BASE=https://sts.example:8081          # add /realm/<id> to work in a trust realm
TOKEN=$(curl -sk -u "sts-management-api:$ADMIN_API_CLIENT_SECRET" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode 'scope=admin:read admin:write' \
  --data-urlencode "resource=$BASE/admin-api" \
  "$BASE/oauth2/token" | jq -r .access_token)

api() {   # api <path under /admin-api> '<json body>'
  curl -sk -X POST "$BASE/admin-api/$1" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    -d "$2"
}
```

**An application's controls** — several at once with `update-fields`, or one
value at a time with `set`, `add` and `remove`:

```bash
# apigw1 may hand a subject on to esb1, may delegate or impersonate,
# delegates unless asked otherwise, and acts only for members of one group.
api applications/update-fields '{"application":"apigw1","fields":{
  "appAllowedToDelegateTo":["esb1"],
  "appDelegationSemantics":["delegation","impersonation"],
  "appDefaultDelegationSemantics":"delegation",
  "appDelegationSubjectGroup":["cn=api-users,ou=groups,dc=example,dc=com"]}}'

# Resource-based instead: the TARGET names who may act toward it.
api applications/add '{"application":"esb1",
  "attribute":"appAllowedToActOnBehalfOf","value":"apigw1"}'

# An application nobody may act for.
api applications/set '{"application":"payroll-batch",
  "attribute":"appNotDelegated","value":"TRUE"}'
```

In `update-fields`, a multi-valued attribute is made to hold exactly the
values given and an empty string or array clears an attribute.

**A person's controls:**

```bash
api users/set-not-delegated '{"user":"carol","value":true}'
api users/set-may-act '{"user":"alice","delegate":"uid=bob,ou=users,dc=example,dc=com"}'
api users/set-may-act '{"user":"alice","delegate":""}'          # clears it
api users/set-delegation-semantics '{"user":"alice",
  "semantics":["delegation"],"default":"delegation"}'
```

**The realm's settings, and the role a person needs to act:**

```bash
api config/set '{"key":"delegation.protectedGroups",
  "value":"cn=executives,ou=groups,dc=example,dc=com"}'
api roles/create-role '{"role":"DELEGATION_ACTOR"}'
api roles/add-member '{"role":"DELEGATION_ACTOR","kind":"user","member":"dave"}'
```

**Reading it back** — the whole policy, paged into the configured pairs, the
actors and the protected people:

```bash
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/admin-api/delegation/policy" | jq
```

The OpenAPI document at `GET /admin-api/openapi.json` describes every one of
these operations and their bodies.

**With LDAP.** The same attributes can be written with `ldapmodify` over
LDAPS, by an identity holding Admin Write in product mode
([LDAP](ldap.md#development-and-product-mode)); nothing caches them, so the
next request reads the change:

```
dn: uid=alice,ou=users,dc=example,dc=com
changetype: modify
replace: stsDelegationSemantics
stsDelegationSemantics: delegation
-
replace: stsMayAct
stsMayAct: uid=bob,ou=users,dc=example,dc=com
```

### Development and product mode

**Product mode refuses.** **Development mode** asks the same questions,
issues the token anyway, and writes on the act *"WOULD HAVE BEEN REFUSED in
product: …"*, so a client under test still gets a working token and the
operator sees what would break.

| | Development | Product |
|---|---|---|
| A policy refusal (OAuth, WS-Trust, GNAP) | token issued; the act records what would have refused it | refused |
| `may_act` naming somebody else | refused | refused |
| WS-Trust `OnBehalfOf` and `ActAs` in one request | refused | refused |
| Kerberos delegation rules | enforced; the fixture services carry rules so every refusal and success is reachable | enforced; there are no rules until an operator writes one |
| A `subject_token` / `actor_token` this realm cannot verify | read without verifying, for its name | refused (`STS-OAUTH-0555`, `0556`) |
| A token this realm has revoked | refused | refused (`STS-OAUTH-0557`) |
| A `jwt` assertion from an undeclared issuer, or that does not verify | read without verifying | refused |
| A `saml2` / `saml1` assertion that does not verify | refused | refused |
| A scope wider than the subject token's | issued, and logged | refused (`invalid_scope`) |
| WS-Trust delegation with no requester credential | accepted | refused (`wst:FailedAuthentication`) |
| WS-Trust inner token | any assertion | an assertion or JWT this STS signed, unexpired, naming a person |
| Client authentication at the token endpoint | not checked outside RFC 9700, OAuth 2.1 and FAPI mode | checked (product mode implies RFC 9700 mode) |

See [What is not checked](what-is-not-checked.md) for the rest of what
development mode lets through.

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
mode — are listed in [XACML](xacml.md). The `may_act` a person's tokens carry
is the answer to a second question, `assign-may-act`, which a realm's policy
can also answer.

## Token types: what goes in and what comes out

### RFC 8693 token exchange

The grant type is `urn:ietf:params:oauth:grant-type:token-exchange`, at
`POST /oauth2/token` (`/realm/<id>/oauth2/token` in a trust realm).

| Parameter | Required | What this service does with it |
|---|---|---|
| `subject_token` | yes | The token the new one is about. |
| `subject_token_type` | yes | One of the types below. It must be what the token is: an ID Token declared as an access token is refused (`STS-OAUTH-0628`). |
| `actor_token` | no | A token about the actor. Without it, the authenticated client is the actor. |
| `actor_token_type` | exactly when `actor_token` is sent | One of the types below, or Native SSO's device secret. |
| `audience` / `resource` | for anything but a self exchange | The target. Both may be sent, but together they must name **one** target, registered on an application (`oauthAudience`, or its client ID). |
| `scope` | no | May narrow the subject token's scope, never widen it. Omitted, the subject token's scope is carried forward. |
| `requested_token_type` | no | `urn:ietf:params:oauth:token-type:refresh_token` asks for a refresh token beside the access token. Any other value is read as a request and answered with an access token, never refused. |
| `exchange_semantics` | no | **This service's extension**: `delegation` or `impersonation`, sent at most once. Any other value is `invalid_request` (`STS-OAUTH-0795`). |
| `authorization_details` | no | RFC 9396, as for a direct grant. |

**Accepted as `subject_token_type` and `actor_token_type`:**

| URI | What it must be |
|---|---|
| `urn:ietf:params:oauth:token-type:access_token` | an access token this realm issued |
| `urn:ietf:params:oauth:token-type:refresh_token` | a refresh token this realm issued (it is opened and verified like any other) |
| `urn:ietf:params:oauth:token-type:id_token` | an ID Token this realm issued |
| `urn:ietf:params:oauth:token-type:jwt` | any other JWT this realm signed (a WS-Trust JWT, for one), or an RFC 7523 assertion from a declared issuer |
| `urn:ietf:params:oauth:token-type:saml2` | an RFC 7522 SAML 2.0 assertion from a declared issuer, base64url-encoded |
| `urn:ietf:params:oauth:token-type:saml1` | a SAML 1.1 assertion from a declared issuer, base64url-encoded |
| `urn:openid:params:token-type:device-secret` | as `actor_token_type` only, beside an `id_token` subject: OpenID Connect Native SSO, which is not a delegation ([OpenID Connect flows](configure-oidc-flows.md#native-sso)) |

Anything else is `invalid_request` (`STS-OAUTH-0627`).

**The response** is a token response with `issued_token_type`, always
`urn:ietf:params:oauth:token-type:access_token`, because it describes the
token in the `access_token` member — even when a refresh token was asked for
and came back beside it. The `refresh_token` member is an ordinary refresh
token of this service, bound to the same DPoP key or client certificate as
the access token. `scope` names what the access token carries and is left out
when it carries nothing; an `id_token` comes back only when `openid`
survives, which it does not on a token for another resource server
(RFC 9068 section 2.2.3). `token_type` is `DPoP` when the exchange was made
with a DPoP proof and `Bearer` otherwise.

### WS-Trust

The token inside `OnBehalfOf` or `ActAs` is one this STS issued: a SAML 2.0
assertion, or a JWT in the `wsse:BinarySecurityToken` an RSTR carries one in.
What is issued is chosen by `wst:TokenType`:

| `wst:TokenType` | Issued |
|---|---|
| `urn:ietf:params:oauth:token-type:jwt` | a JWT in a `wsse:BinarySecurityToken` with that `ValueType` |
| `http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1` or `urn:oasis:names:tc:SAML:1.0:assertion` | a SAML 1.1 assertion; an `ActAs` here names no delegate, because SAML 1.1 has no Delegation Restriction |
| anything else, or none (`http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0` is the usual one) | a SAML 2.0 assertion |

See [WS-Trust](ws-trust.md#token-types).

### Kerberos and GNAP

Kerberos issues service tickets (and, for a forwarded TGT, a ticket-granting
ticket); the evidence S4U2Proxy consumes is a forwardable service ticket. GNAP
issues tokens in the client's or resource server's configured format —
`jwt-signed`, `jwt-encrypted`, `macaroon` and the others
[GNAP](gnap.md#access-token-formats) lists — and a derivation consumes a GNAP
access token issued for the deriving resource server.

## Claims in the issued token

### `act`: who acted

On a **delegation**, the access token carries RFC 8693 section 4.1's `act`:

* The **outermost** entry is the current actor: the `actor_token`'s `sub`, or
  — with no actor token — the exchanging client.
* **Every entry carries `iss`**, the issuer of the token it is in. An entry
  copied from the subject token keeps its own `iss`; one without is given
  this issuer only when this service issued the subject token.
* **A client has one form**: `urn:sts:client:<client_id>` in RFC 9700 mode
  (and so in product mode), and the bare `client_id` otherwise — the `sub`
  its own `client_credentials` token carries.
* **The chain begins with the original client.** On the first exchange of a
  token this realm issued (one with no `act`), the client it was issued to is
  nested beneath the actor — unless that client is the actor. Only the
  outermost `act` is the current actor; the nested ones are history.
* **An impersonation adds nothing**, and keeps any `act` the subject token
  already carried.

`act` is a reserved claim name: a custom claim cannot set or replace it.

### `may_act`: who may act

An access token about a person whose entry carries `stsMayAct` (or an
application with `appMayAct`) carries RFC 8693 section 4.4's `may_act`,
naming the delegate: a person by their `urn:uuid:` subject, an application
by its client ID. When that token is later exchanged, an actor other than the
one named is refused **in every mode** (`STS-OAUTH-0620`). The comparison
accepts both forms of a client's name. `may_act` is read only off a verified
subject token.

### Introspection

`POST /oauth2/introspect` returns a token's `act`, nested as in the token, and
its `may_act` (RFC 8693 section 7.2), in the JSON response and in the RFC 9701
JWT alike. As for every other member, an authenticated caller the token is not
for is told only that it is not active.

### Custom claims

The claims a delegated token carries beyond the protocol's own come from the
same places as any other token's. They are evaluated **for the subject**, not
for the actor, and placeholders read what the token itself says — under a
token exchange, `${sub}` is the subject's.

* **The realm's sets** (Protocols → OAuth2 / OIDC → Custom claims,
  `/admin-api/claims`): typed claims, directory attributes, and the groups
  claim (`groups.claim`, `groups.claimName`, `groups.claimValue`). An
  exchanged access token carries the realm's `access_token` set.
* **The application's own rows**, added to the realm's and winning by name.
  For an exchanged access token, the application is the **exchanging
  client** (the token's `client_id`). For a WS-Trust token, it is the
  **`AppliesTo`'s** application: its access-token claims for a JWT, its
  custom SAML attributes for an assertion, and its groups-claim settings.
* **Kerberos** puts the realm's and the service's `kerberos-pac` claims in
  the PAC ([Kerberos](kerberos.md#pac-claims)).

```bash
# Every access token from now on: a typed claim, and a directory attribute.
api claims/add '{"set":"access_token","name":"dept","value":"engineering"}'
api claims/add-attribute-claim '{"set":"access_token","name":"cost_center",
  "attribute":"costCenter"}'

# Only tokens issued to apigw1 (including the ones it exchanges for):
api applications/set-custom-claim '{"application":"apigw1","set":"access_token",
  "name":"tier","value":"gold-${username}"}'

# What the realm's sets would put in a token about alice:
curl -sk -H "Authorization: Bearer $TOKEN" "$BASE/admin-api/claims?user=alice" | jq .attributeClaims
```

A value may use `${username}`, `${sub}`, `${email}`, `${name}`,
`${given_name}`, `${family_name}`, `${client_id}`, `${audience}`, `${now}` and
`${iso}`. Custom claims are additive only: a name the protocol sets itself
(`iss`, `sub`, `aud`, `exp`, `scope`, `client_id`, `act` and the rest) is
refused when you configure it. The full rules are in
[OAuth 2.0 and OpenID Connect](oauth-oidc.md#custom-claims--adminclaims) and
[Applications](applications.md#custom-claims-saml-attributes-and-token-lifetimes).
A JWT assertion's own extra claims reach the token it is exchanged for only
through the [JWT bearer grant](jwt-assertions.md), not through an exchange.

## Worked examples

The examples share one cast, in the default realm unless a realm prefix is
shown:

| Entry | Role |
|---|---|
| `webapp1` | a public web client the person signs in to |
| `apigw1` | an API gateway, audience `https://apigw1.example.com`, confidential |
| `esb1` | a service bus, audience `https://esb1.example.com`, confidential |
| `sp1` | a back-end service, audience `https://sp1.example.com` |
| `bob` | the person |

Responses are trimmed and tokens decoded. Variables: `$BASE`, `$TOKEN` and
`api()` are from [Setting them through the API](#setting-them-through-the-api).
`-k` is there because development mode's listener certificate comes from an
authority generated at each start ([TLS](tls.md)).

### 0. Provision the cast

```bash
APIGW_SECRET=$(api applications/generate-secret '{}' | jq -r .clientSecret)
ESB_SECRET=$(api applications/generate-secret '{}' | jq -r .clientSecret)
SP_SECRET=$(api applications/generate-secret '{}' | jq -r .clientSecret)
XCH=urn:ietf:params:oauth:grant-type:token-exchange

api users/create '{"username":"bob","invent":false,"credential":"password",
  "password":"'"$BOB_PASSWORD"'",
  "attributes":{"cn":"Bob","sn":"B","mail":"bob@example.com"}}'

api applications/create '{"identifier":"webapp1","name":"webapp1",
  "protocols":["oauth2","oidc"],"fields":{"oauthClientId":"webapp1",
  "oauthTokenEndpointAuthMethod":["none"],
  "oauthRedirectUri":["https://webapp1.example.com/callback"],
  "oauthGrantType":["authorization_code","refresh_token"],
  "oauthAllowedScope":["openid","profile","app1-scope"]}}'

api applications/create '{"identifier":"apigw1","name":"apigw1",
  "protocols":["oauth2","oidc"],"fields":{"oauthClientId":"apigw1",
  "oauthAudience":["https://apigw1.example.com"],
  "oauthConfidential":"TRUE","oauthClientSecret":"'"$APIGW_SECRET"'",
  "oauthTokenEndpointAuthMethod":["client_secret_basic"],
  "oauthGrantType":["'"$XCH"'","client_credentials"],
  "oauthAllowedScope":["app1-scope"],
  "appAllowedToDelegateTo":["esb1"],
  "appDelegationSemantics":["delegation","impersonation"],
  "appDefaultDelegationSemantics":"delegation"}}'

api applications/create '{"identifier":"esb1","name":"esb1",
  "protocols":["oauth2","oidc"],"fields":{"oauthClientId":"esb1",
  "oauthAudience":["https://esb1.example.com"],
  "oauthConfidential":"TRUE","oauthClientSecret":"'"$ESB_SECRET"'",
  "oauthTokenEndpointAuthMethod":["client_secret_basic"],
  "oauthGrantType":["'"$XCH"'","client_credentials"],
  "oauthAllowedScope":["app1-scope"],
  "appAllowedToDelegateTo":["sp1"],
  "appDelegationSemantics":["delegation"],
  "appDefaultDelegationSemantics":"delegation"}}'

api applications/create '{"identifier":"sp1","name":"sp1",
  "protocols":["oauth2","oidc"],"fields":{"oauthClientId":"sp1",
  "oauthAudience":["https://sp1.example.com"],
  "oauthConfidential":"TRUE","oauthClientSecret":"'"$SP_SECRET"'",
  "oauthTokenEndpointAuthMethod":["client_secret_basic"],
  "oauthAllowedScope":["app1-scope"]}}'
```

`app1-scope` is declared on every tier because product mode issues only
declared scopes ([Configuring OAuth 2.0 grants](configure-oauth2-grants.md#what-development-and-product-mode-change)).

### 1. Get the subject token

bob signs in to `webapp1` with the authorization code flow and PKCE, asking
for a token **for the gateway** with RFC 8707's `resource`
([Configuring OAuth 2.0 grants](configure-oauth2-grants.md#authorization-code-with-pkce)
walks it). The code is redeemed so:

```bash
SUBJECT_TOKEN=$(curl -sk "$BASE/oauth2/token" \
  -d grant_type=authorization_code -d client_id=webapp1 \
  -d code="$CODE" -d code_verifier="$VERIFIER" \
  --data-urlencode redirect_uri=https://webapp1.example.com/callback \
  --data-urlencode resource=https://apigw1.example.com \
  | jq -r .access_token)
```

The token is about bob, issued to `webapp1`, for the gateway:

```json
{ "iss": "https://sts.example:8081", "sub": "urn:uuid:3f6c…", "username": "bob",
  "aud": "https://apigw1.example.com", "client_id": "webapp1",
  "scope": "app1-scope", "jti": "…", "exp": 1790000000 }
```

So S (its audience) is `apigw1`. In development mode only, the password grant
is a shorter way to a subject token
([Password](configure-oauth2-grants.md#password-development-only)).

### 2. RFC 8693 delegation, the client as the actor

`apigw1` exchanges bob's token for one addressed to `esb1`. No actor token:
the client is the actor, and its default semantics is delegation.

```bash
curl -sk -u "apigw1:$APIGW_SECRET" "$BASE/oauth2/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$SUBJECT_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  --data-urlencode audience=https://esb1.example.com \
  -d scope=app1-scope \
  -d exchange_semantics=delegation
```

```json
{ "access_token": "eyJ…", "token_type": "Bearer", "expires_in": 3600,
  "scope": "app1-scope",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token" }
```

The access token, in product mode (RFC 9700 mode names clients
`urn:sts:client:<id>`):

```json
{ "iss": "https://sts.example:8081", "sub": "urn:uuid:3f6c…", "username": "bob",
  "aud": "https://esb1.example.com", "client_id": "apigw1",
  "scope": "app1-scope",
  "act": { "sub": "urn:sts:client:apigw1", "iss": "https://sts.example:8081",
           "act": { "sub": "urn:sts:client:webapp1",
                    "iss": "https://sts.example:8081" } } }
```

The policy allowed it because S (`apigw1`, the subject token's audience)
delegates to R (`esb1`) and the actor is S.

### 3. RFC 8693 delegation with an actor token

The actor can be named by a token of its own — here `apigw1`'s
`client_credentials` token:

```bash
ACTOR_TOKEN=$(curl -sk -u "apigw1:$APIGW_SECRET" "$BASE/oauth2/token" \
  -d grant_type=client_credentials -d scope=app1-scope | jq -r .access_token)

curl -sk -u "apigw1:$APIGW_SECRET" "$BASE/oauth2/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$SUBJECT_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d actor_token="$ACTOR_TOKEN" \
  -d actor_token_type=urn:ietf:params:oauth:token-type:access_token \
  --data-urlencode audience=https://esb1.example.com -d scope=app1-scope
```

`act.sub` is the actor token's `sub`. An actor token about a **person**
makes that person the actor; they need the role `delegation.actorRole` names,
and R must accept them in `appAllowedToActOnBehalfOf`.

**The next hop** is the same call by `esb1`, presenting the token it was
given and asking for `https://sp1.example.com`. The result nests the new
actor over the old chain:

```json
"act": { "sub": "urn:sts:client:esb1", "iss": "https://sts.example:8081",
  "act": { "sub": "urn:sts:client:apigw1", "iss": "https://sts.example:8081",
    "act": { "sub": "urn:sts:client:webapp1", "iss": "https://sts.example:8081" } } }
```

### 4. RFC 8693 impersonation

The same exchange asking for impersonation. `apigw1` may, because
`impersonation` is in its `appDelegationSemantics` and `esb1` is on its
`appAllowedToDelegateTo` (the actor reaches R):

```bash
curl -sk -u "apigw1:$APIGW_SECRET" "$BASE/oauth2/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$SUBJECT_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  --data-urlencode audience=https://esb1.example.com -d scope=app1-scope \
  -d exchange_semantics=impersonation
```

The token is bob's, addressed to `esb1`, and carries no `act` (a subject
token that already had one would keep it):

```json
{ "sub": "urn:uuid:3f6c…", "username": "bob", "aud": "https://esb1.example.com",
  "client_id": "apigw1", "scope": "app1-scope" }
```

Only Monitoring → Delegation records that `apigw1` obtained it.

### 5. A self exchange

The actor is S, keeping the token for itself — for example to drop a scope.
With no `audience`, the new token keeps the subject token's audience, and no
delegation control is consulted:

```bash
curl -sk -u "apigw1:$APIGW_SECRET" "$BASE/oauth2/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$SUBJECT_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d scope=app1-scope
```

### 6. Asking for a refresh token

```bash
curl -sk -u "apigw1:$APIGW_SECRET" "$BASE/oauth2/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$SUBJECT_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  --data-urlencode audience=https://esb1.example.com -d scope=app1-scope \
  -d requested_token_type=urn:ietf:params:oauth:token-type:refresh_token
```

```json
{ "access_token": "eyJ…", "refresh_token": "eyJ…", "token_type": "Bearer",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", … }
```

The refresh token renews a token for `esb1` only. Under
`oauth2.tokenExchangeRefreshToken=never` the exchange still succeeds, without
one.

### 7. A JWT assertion as the subject token

An RFC 7523 JWT from an issuer this realm **declared**. Declare it once, on an
application entry with the issuer's public key
([JWT assertions](jwt-assertions.md)):

```bash
api applications/create '{"identifier":"partner-idp","name":"partner-idp",
  "protocols":["oauth2"],"fields":{"oauthClientId":["partner-idp"],
  "oauthAssertionIssuer":["https://idp.partner.example"],
  "oauthAssertionJwks":"{\"keys\":[ … the issuer'"'"'s public JWK … ]}"}}'
```

The assertion names a person the directory holds, is addressed to this
token endpoint (the default `oauth2.tokenExchangeAudience`), and has a
`jti`:

```json
{ "iss": "https://idp.partner.example", "sub": "urn:uuid:3f6c…",
  "aud": "https://sts.example:8081/oauth2/token",
  "iat": 1790000000, "exp": 1790000120, "jti": "a1b2…" }
```

```bash
curl -sk -u "apigw1:$APIGW_SECRET" "$BASE/oauth2/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$JWT_ASSERTION" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode audience=https://esb1.example.com -d scope=app1-scope
```

The issued token is about the person the assertion names. An assertion
addressed to this server was issued for whoever presents it, so S is the
exchanging client (`apigw1`). The assertion is spent: presenting it again,
here or at the `jwt-bearer` grant, is refused.

### 8. A SAML 2.0 or SAML 1.1 assertion as the subject token

Declare the issuer with `oauthSamlAssertionIssuer` and give it a certificate
([SAML assertions](saml-assertions.md)). A certificate that merely chains to
the realm's authority is not enough. Then send the signed assertion
base64url-encoded:

```bash
SAML_B64U=$(base64 -w0 < assertion.xml | tr '+/' '-_' | tr -d '=')

curl -sk -u "apigw1:$APIGW_SECRET" "$BASE/oauth2/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$SAML_B64U" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:saml2 \
  --data-urlencode audience=https://esb1.example.com -d scope=app1-scope
```

For a SAML 1.1 assertion the type is
`urn:ietf:params:oauth:token-type:saml1`. A SAML 2.0 assertion declared as
`saml1` (or the reverse) is refused (`STS-OAUTH-0797`).

### 9. An assertion as the actor token

Any of the three assertion types names the actor too. The person it names is
the actor, and `act.sub` is their subject:

```bash
curl -sk -u "apigw1:$APIGW_SECRET" "$BASE/oauth2/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$SUBJECT_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d actor_token="$ACTOR_JWT_ASSERTION" \
  -d actor_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode audience=https://esb1.example.com -d scope=app1-scope
```

**Token forwarding.** With `oauth2.tokenExchangeAudience` set to
`any-declared-relying-party`, an assertion addressed to a relying party
registered here (its `oauthAudience`, or for SAML its
`samlAssertionConsumerService` as `Recipient`) may be exchanged by that
relying party. S is then that relying party, and the act is recorded as
FORWARDED.

```bash
api config/set '{"key":"oauth2.tokenExchangeAudience","value":"any-declared-relying-party"}'
```

> **Warning.** Under `any-declared-relying-party`, every relying party an
> assertion was issued to can exchange it for a token from this service. Turn
> it on only where that is the design.

### 10. Introspect a delegated token

The far end checks the token with the issuer. Introspection authenticates
its caller in product mode:

```bash
curl -sk -u "sp1:$SP_SECRET" "$BASE/oauth2/introspect" \
  --data-urlencode token="$DELEGATED_TOKEN" -d token_type_hint=access_token
```

```json
{ "active": true, "sub": "urn:uuid:3f6c…", "aud": "https://sp1.example.com",
  "client_id": "esb1", "scope": "app1-scope",
  "act": { "sub": "urn:sts:client:esb1", "iss": "https://sts.example:8081",
           "act": { … } } }
```

### 11. WS-Trust: provision the requesters

WS-Trust's requester authenticates with a WS-Security UsernameToken, checked
in product mode against a `userPassword`. An application entry cannot hold
one, so each requester gets a [service account](service-accounts.md) of the
**same name**; the application entry is what the policy reads.

```bash
for tier in webapp1:https://webapp1.example.com \
            apigw1:https://apigw1.example.com \
            esb1:https://esb1.example.com; do
  id=${tier%%:*}; at=${tier#*:}
  api applications/update-fields '{"application":"'"$id"'",
    "protocols":["wstrust","saml2","oauth2","oidc"],
    "fields":{"wstrustAppliesTo":["'"$at"'"],"samlEntityId":["'"$at"'"]}}'
done

# webapp1 acts first: it may impersonate or delegate, toward apigw1.
api applications/update-fields '{"application":"webapp1","fields":{
  "appAllowedToDelegateTo":["apigw1"],
  "appDelegationSemantics":["delegation","impersonation"]}}'

# Its service account, owned by a group of operators.
api users/create '{"username":"webapp1","invent":false,"credential":"password",
  "password":"'"$WEBAPP_PASSWORD"'","serviceAccount":true,
  "owner":"'"$OWNER_GROUP_DN"'",
  "attributes":{"cn":"webapp1","sn":"webapp1"}}'
```

### 12. WS-Trust: bob's sign-in, the token to delegate

An Issue with bob's own UsernameToken, `AppliesTo` webapp1. Its assertion is
about bob and restricted to webapp1 (S):

```bash
WSSE=http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd
WST=http://docs.oasis-open.org/ws-sx/ws-trust/200512
SAML2=http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0

rst() {   # rst <user> <password> <AppliesTo> [<OnBehalfOf|ActAs> <token xml>]
  local inner=""
  case "$4" in
    OnBehalfOf) inner="<wst:OnBehalfOf>$5</wst:OnBehalfOf>" ;;
    ActAs) inner="<wst14:ActAs xmlns:wst14=\"http://docs.oasis-open.org/ws-sx/ws-trust/200802\">$5</wst14:ActAs>" ;;
  esac
  cat <<EOF
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="$WSSE">
 <s:Header><wsse:Security><wsse:UsernameToken>
  <wsse:Username>$1</wsse:Username><wsse:Password>$2</wsse:Password>
 </wsse:UsernameToken></wsse:Security></s:Header>
 <s:Body><wst:RequestSecurityToken xmlns:wst="$WST">
  <wst:RequestType>$WST/Issue</wst:RequestType>
  <wst:TokenType>${TOKEN_TYPE:-$SAML2}</wst:TokenType>
  <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
   <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
    <wsa:Address>$3</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>
  $inner
 </wst:RequestSecurityToken></s:Body></s:Envelope>
EOF
}

rst bob "$BOB_PASSWORD" https://webapp1.example.com \
  | curl -sk "$BASE/sts" -H 'Content-Type: application/soap+xml' --data-binary @- \
  > signin.xml

# The <saml:Assertion> inside <wst:RequestedSecurityToken>:
BOB_ASSERTION=$(xmllint --xpath \
  '//*[local-name()="RequestedSecurityToken"]/*' signin.xml)
```

The endpoint is `POST /sts` (`/realm/<id>/sts` in a trust realm), SOAP 1.2
here; a SOAP 1.1 envelope with `text/xml` works too. Pass the assertion on
exactly as it came: it is signed.

### 13. WS-Trust `OnBehalfOf` (impersonation)

webapp1, authenticated as itself, presents bob's assertion and asks for a
token for apigw1:

```bash
rst webapp1 "$WEBAPP_PASSWORD" https://apigw1.example.com OnBehalfOf "$BOB_ASSERTION" \
  | curl -sk "$BASE/sts" -H 'Content-Type: application/soap+xml' --data-binary @-
```

The RSTR carries a SAML 2.0 assertion about bob, audience
`https://apigw1.example.com`, with no Delegation Restriction:

```xml
<wst:RequestSecurityTokenResponseCollection …>
 <wst:RequestSecurityTokenResponse>
  <wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</wst:TokenType>
  <wst:RequestedSecurityToken>
   <saml:Assertion …>
    <saml:Subject><saml:NameID …>bob</saml:NameID>…</saml:Subject>
    <saml:Conditions …>
     <saml:AudienceRestriction><saml:Audience>https://apigw1.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions> …
```

### 14. WS-Trust `ActAs` (delegation)

The same request with `ActAs`:

```bash
rst webapp1 "$WEBAPP_PASSWORD" https://apigw1.example.com ActAs "$BOB_ASSERTION" \
  | curl -sk "$BASE/sts" -H 'Content-Type: application/soap+xml' --data-binary @-
```

The assertion now names webapp1 as the party acting, in a
[SAML V2.0 Condition for Delegation Restriction](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-delegation-cs-01.html):

```xml
<saml:Conditions …>
 <saml:AudienceRestriction><saml:Audience>https://apigw1.example.com</saml:Audience></saml:AudienceRestriction>
 <saml:Condition xmlns:del="urn:oasis:names:tc:SAML:2.0:conditions:delegation"
                 xsi:type="del:DelegationRestrictionType">
  <del:Delegate DelegationInstant="2026-10-06T12:00:00Z">
   <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">…webapp1…</saml:NameID>
  </del:Delegate>
 </saml:Condition>
</saml:Conditions>
```

Each further `ActAs` hop adds one `del:Delegate`, least to most recent.

**As a JWT.** With `TOKEN_TYPE=urn:ietf:params:oauth:token-type:jwt`, the
token comes back in a `<wsse:BinarySecurityToken
ValueType="urn:ietf:params:oauth:token-type:jwt">`, with `typ: at+jwt`, the
chain as nested `act`, and `client_id` the requester's application:

```json
{ "iss": "https://sts.example:8081", "sub": "urn:uuid:3f6c…",
  "aud": "https://apigw1.example.com", "client_id": "webapp1",
  "act": { "sub": "urn:sts:client:webapp1", "iss": "https://sts.example:8081" } }
```

For the next hop, put that whole `wsse:BinarySecurityToken` element inside
the next request's `ActAs` or `OnBehalfOf`. A request carrying both elements
is refused in every mode.

### 15. Kerberos: S4U2Self, S4U2Proxy, resource-based, forwarding

Kerberos is not HTTP, so these use the MIT Kerberos client tools (`kinit`,
`kvno`, `klist`; `kvno`'s `-U`, `-F` and `-P` need a recent MIT release —
check `man kvno` for your version). They use development mode's fixture
accounts, whose rules are seeded onto their application entries:

| Fixture | Entry | Rules |
|---|---|---|
| `HTTP/frontend.example.com` | front end | `appAllowedToDelegateTo` `HTTP/backend.example.com@EXAMPLE.COM`; `delegation` and `impersonation`; `krb5TrustedForDelegation` |
| `HTTP/backend.example.com` | classic back end | none |
| `HTTP/rbcd.example.com` | resource-based back end | `appAllowedToActOnBehalfOf` `HTTP/frontend.example.com@EXAMPLE.COM` |
| `HTTP/notrusted.example.com` | front end that may not impersonate | `appAllowedToDelegateTo` the back end only |
| `sensitive` | a person | `stsNotDelegated` |

Their development passwords are published at `GET /krb5/principals`. In product
mode, create a service with `api kerberos/principals/create-service
'{"spn":"HTTP/frontend.example.com"}'` (the reply's `keytab` is the only copy),
then set its rules on the application entry `HTTP/frontend.example.com@<REALM>`
as in [Setting them through the API](#setting-them-through-the-api).

A `krb5.conf` for the KDC on TCP 88:

```ini
[libdefaults]
  default_realm = EXAMPLE.COM
  dns_lookup_kdc = false
  dns_lookup_realm = false
  udp_preference_limit = 1
[realms]
  EXAMPLE.COM = { kdc = sts.example:88 }
  # or over HTTPS, MS-KKDCP: kdc = https://sts.example:8081/KdcProxy
  # (with http_anchors = FILE:/path/to/the-service-root.pem)
[domain_realm]
  .example.com = EXAMPLE.COM
```

```bash
export KRB5_CONFIG=$PWD/krb5.conf KRB5CCNAME=FILE:/tmp/frontend.cc

# The front end's own TGT (or: kinit -k -t frontend.keytab …).
kinit HTTP/frontend.example.com@EXAMPLE.COM

# S4U2Self — impersonation: a ticket to ITSELF for alice, with no password
# of alice's. Forwardable, because the front end allows impersonation.
kvno -U alice HTTP/frontend.example.com
klist -f            # Flags include F (forwardable)

# S4U2Self by certificate (PA-S4U-X509-USER): a certificate this realm
# issued to alice, with clientAuth.
kvno -F alice-cert.pem HTTP/frontend.example.com

# S4U2Proxy, classic constrained delegation — delegation: alice's ticket to
# the back end, permitted by the front end's appAllowedToDelegateTo.
kvno -U alice -P HTTP/backend.example.com

# S4U2Proxy, resource-based: permitted by the back end's
# appAllowedToActOnBehalfOf; the request must carry PA-PAC-OPTIONS.
kvno -U alice -P HTTP/rbcd.example.com
```

The back end's ticket carries `S4U_DELEGATION_INFO` in its PAC: the target
(`HTTP/backend.example.com`) and every service delegated through
(`HTTP/frontend.example.com@EXAMPLE.COM`).

What the refusals look like:

```bash
kvno -U sensitive -P HTTP/backend.example.com      # protected: not forwardable,
                                                   # KDC_ERR_BADOPTION
KRB5CCNAME=FILE:/tmp/nt.cc kinit HTTP/notrusted.example.com@EXAMPLE.COM
KRB5CCNAME=FILE:/tmp/nt.cc kvno -U alice -P HTTP/backend.example.com
                    # S4U2Self ticket not forwardable: KDC_ERR_BADOPTION
```

**A forwarded TGT** (unconstrained delegation). A service with
`krb5TrustedForDelegation` gets `ok-as-delegate` on its tickets, which tells a
client it may forward its TGT there:

```bash
KRB5CCNAME=FILE:/tmp/alice.cc kinit -f alice@EXAMPLE.COM
KRB5CCNAME=FILE:/tmp/alice.cc kvno HTTP/frontend.example.com
KRB5CCNAME=FILE:/tmp/alice.cc klist -f   # the service ticket shows O (ok-as-delegate)
```

A GSS-API client then forwards the TGT when it authenticates — for
example `curl --negotiate -u : --delegation policy <url>`, which forwards
only where `ok-as-delegate` is set. A protected person's TGT is not
forwardable, and a forwarding request presenting one is refused. Every one of
these acts is on Monitoring → Delegation.

### 16. GNAP: a trusted client presenting a user assertion (impersonation)

A GNAP client whose entry carries `gnapSkipInteraction`, with `impersonation`
in its `appDelegationSemantics` and each resource server reachable
(`appAllowedToDelegateTo`, or accepted by the resource server), presents an
ID Token **issued to it**:

```json
POST /gnap
{
  "client": { "key": { "proof": "mtls", "cert": "<base64 DER of the client certificate>" } },
  "access_token": { "access": [ { "type": "https://apigw1.example.com/api",
                                  "actions": ["read"] } ] },
  "user": { "assertions": [ { "format": "id_token", "value": "<bob's ID Token>" } ] }
}
```

Every GNAP request is key-proofed. With the `mtls` proof method curl can send
it directly, over the certificate the key names:

```bash
curl -sk --cert client.pem --key client.key "$BASE/gnap" \
  -H 'Content-Type: application/json' --data @grant.json
```

With `httpsig`, `jwsd` or `jws`, sign the request as RFC 9635 section 7.3
says ([GNAP](gnap.md#what-is-supported)). The response carries a token for
bob in the client's format, naming no actor. A `saml2` assertion works the
same way (`"format": "saml2"`). An assertion issued to another client is
refused `unknown_user` (`STS-GNAP-0073`).

### 17. GNAP: a resource server deriving a token (delegation)

A resource server sends the token it was given as `existing_access_token`
(RFC 9767 section 4), proofed with its own key, and asks for rights at the
next resource server:

```json
POST /gnap
{
  "client": { "key": { "proof": "mtls", "cert": "<the resource server's certificate>" } },
  "existing_access_token": "<the token it was presented>",
  "access_token": { "access": [ { "type": "https://esb1.example.com/api",
                                  "actions": ["read"] } ] }
}
```

Its `appAllowedToDelegateTo` must name the downstream resource server (or
that one's `appAllowedToActOnBehalfOf` must name it). The derived token has no
more access than the original and names the deriving resource server in
`act`, up to `gnap.maxDerivationDepth` deep.

### 18. Read the register

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$BASE/admin-api/delegation?protocol=OAuth%202.0&outcome=refused" | jq '.acts[0]'
```

Filters: `type` (for example `oauth-delegation`, `oauth-impersonation`,
`wstrust-actas`, `wstrust-onbehalfof`, `krb5-s4u2self`,
`krb5-s4u2proxy-classic`, `krb5-s4u2proxy-rbcd`, `krb5-forwarded`,
`gnap-impersonation`, `gnap-derivation`), `mode` (`delegation` or
`impersonation`), `outcome` (`issued` or `refused`), `protocol` and `q`. Each
act names its four parties, the tokens consumed and produced, and
`authorizedBy`: what allowed it or, in development, what would have refused
it.

## Per protocol

### OAuth 2.0 token exchange (RFC 8693)

* `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, with a
  `subject_token` and optionally an `actor_token`. In product mode each must
  be a token this realm signed and has not revoked, or an assertion from an
  issuer the realm declared ([below](#assertions-as-the-subject-or-the-actor)).
* `exchange_semantics=delegation|impersonation` is this service's extension
  for asking. Any other value, or the parameter sent twice, is
  `invalid_request` in every mode.
* **Delegation** puts `act` on the access token naming the actor, nesting any
  `act` the subject token carried, or the original client on a first
  exchange ([`act`](#act-who-acted)). **Impersonation** issues a token about
  the subject with no new `act`.
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
* **Refusals** are spoken as RFC 8693 section 2.2.2 says: `invalid_target`
  for the target and the relationship, `invalid_request` for everything else
  the policy refuses ([codes](#oauth-20-token-exchange)).

In development, two audiences are refused too, by RFC 9068 section 3: an
access token for two resources is ambiguous.

See [OAuth 2.0 and OpenID Connect](oauth-oidc.md) and
[Configuring OAuth 2.0 grants](configure-oauth2-grants.md#token-exchange-rfc-8693).

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
    same chain as nested `act` claims, the most recent outermost, in the
    shape an OAuth 2.0 token exchange writes:
    * each entry has `iss`;
    * an application is named `urn:sts:client:<client_id>` in RFC 9700 mode
      and by its bare client_id otherwise;
    * the JWT's `client_id` is the requester's application;
  * a **SAML 1.1** assertion names no delegate.
* **`OnBehalfOf` asks for impersonation** (1.3 section 9.2). The token is the
  subject's, and adds nobody to the chain; one the delegated assertion
  already carried is kept.
* **Both elements in one request** are refused with `wst:InvalidRequest`, in
  every mode.
* A request with **no `AppliesTo`** is refused unless it is a self one.
* **A person may be the requester** only with the role `delegation.actorRole`
  names, and only toward an R that accepts them by name.
* **Every policy refusal is a SOAP Fault carrying WS-Trust 1.4 section 11's
  `wst:RequestFailed`**: the `faultcode` on SOAP 1.1, the `Subcode` on SOAP
  1.2. The fault's reason says which rule refused. A refused act is on
  `/admin/delegation`; its subject is not added to `/admin/users`, which lists
  a delegated subject only once the policy has allowed the act (or, in
  development, recorded that it would have refused it).
* `may_act` is not compared here, even when the delegated token is a JWT. A
  **JWT** issued about a person who set `stsMayAct` carries `may_act`, as an
  access token does, and is compared when that JWT is later the
  `subject_token` of a token exchange.

See [WS-Trust](ws-trust.md#delegation-onbehalfof-and-actas).

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
    `appAllowedToDelegateTo` naming the back end;
  * **resource-based** constrained delegation (the request carries
    `PA-PAC-OPTIONS` with the RBCD bit) is the back end's
    `appAllowedToActOnBehalfOf` naming the front end;
  * both need a **forwardable evidence ticket** ([MS-SFU] 3.2.5.2.1 and,
    since the CVE-2020-16996 update, 3.2.5.2.3);
  * the ticket out of it is forwardable when the request asks for it, the
    front end's TGT is forwardable and the user is not protected (RFC 4120
    section 3.3.3);
  * its PAC carries `S4U_DELEGATION_INFO` ([MS-PAC] 2.9): the target's name
    (`HTTP/backend.example.com`) and every service delegated through, each
    with its realm (`HTTP/frontend.example.com@EXAMPLE.COM`), oldest first.
* **The register records each mechanism by its own mode**, as [MS-SFU]
  names them: S4U2Self is protocol transition, so impersonation, and
  S4U2Proxy is constrained delegation, so delegation, whatever made its
  evidence. A Kerberos impersonation chain — a service signs somebody in
  without Kerberos, uses S4U2Self, then S4U2Proxy hop after hop — therefore
  has ONE impersonation row and the rest delegation, where an OAuth 2.0
  impersonation chain is impersonation at every hop. The difference is real:
  an S4U2Proxy ticket carries the chain in its PAC, and a token exchanged as
  an impersonation carries none.
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
  does not verify, `KDC_ERR_POLICY` for the rest of the policy. The error's
  `e-text` names the attribute and its current value.
* Delegation across Kerberos realms and trusts is not yet decided by this
  policy; see issue #430.

See [Kerberos and SPNEGO](kerberos.md#delegation).

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
  * a `may_act` claim in the ID Token must name the client (every mode);
  * the assertion must have been issued to the presenting client, in every
    mode.
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
* **Refusals** are `request_denied` (HTTP 403).

See [GNAP](gnap.md#acting-for-somebody-else).

## Refusals and troubleshooting

Every refusal has an error code `STS-<SUBSYSTEM>-<NNNN>`. **The code is
recorded, never sent**: it is on the audit row, at the front of the log line
and on the act on Monitoring → Delegation, and the client hears only its
protocol's own error. Look a code up in [Error codes](error-codes.md). In
development mode most policy refusals are not refused at all — read the act's
*WOULD HAVE BEEN REFUSED* line to see what product will do.

### OAuth 2.0 token exchange

| What happened | Client hears | Code |
|---|---|---|
| No `subject_token` | `invalid_request` | `STS-OAUTH-0224` |
| `subject_token_type` missing; `actor_token` without `actor_token_type`, or the reverse | `invalid_request` | `STS-OAUTH-0626` |
| A token type this service does not exchange; a device secret anywhere but as the actor beside an ID Token | `invalid_request` | `STS-OAUTH-0627` |
| A verified token that is not the type declared | `invalid_request` | `STS-OAUTH-0628` |
| Product: the `subject_token` / `actor_token` does not verify | `invalid_request` | `STS-OAUTH-0555` / `0556` |
| The token was revoked | `invalid_request` | `STS-OAUTH-0557` |
| `exchange_semantics` neither `delegation` nor `impersonation`, or repeated | `invalid_request` | `STS-OAUTH-0795` |
| An assertion addressed to an audience `oauth2.tokenExchangeAudience` does not accept | `invalid_request` | `STS-OAUTH-0796` |
| A SAML assertion of the other version than its declared type | `invalid_request` | `STS-OAUTH-0797` |
| An assertion naming nobody the directory holds | `invalid_request` | `STS-OAUTH-0798` |
| `may_act` names somebody else (every mode) | `invalid_request` | `STS-OAUTH-0620` |
| More than one `audience` / `resource` | `invalid_target` | `STS-OAUTH-0792` |
| A target no application registers | `invalid_target` | `STS-OAUTH-0793` |
| No target on a delegation or impersonation | `invalid_target` | `STS-OAUTH-0794` |
| The relationship does not hold (neither `appAllowedToDelegateTo` nor `appAllowedToActOnBehalfOf`) | `invalid_target` | `STS-OAUTH-0619` |
| The semantics are not allowed by the actor or the subject | `invalid_request` | `STS-OAUTH-0790` |
| The subject holds none of the application's required roles | `invalid_request` | `STS-OAUTH-0791` |
| A protected subject, an unknown actor, a person actor without the role, a subject outside `appDelegationSubjectGroup` | `invalid_request` | `STS-OAUTH-0618` |
| A realm's own policy refused, or no policy answered | `invalid_request` | `STS-OAUTH-0622` |
| Product: a scope wider than the subject token's | `invalid_scope` | `STS-OAUTH-0621` |

### WS-Trust

| What happened | Fault | Code |
|---|---|---|
| Both `OnBehalfOf` and `ActAs` | `wst:InvalidRequest` | `STS-WSTRUST-0025` |
| Product: no requester credential on a delegation | `wst:FailedAuthentication` | `STS-WSTRUST-0009` |
| Product: the element carries no SAML assertion | `wst:InvalidRequest` | `STS-WSTRUST-0008` |
| Product: the inner assertion does not verify | `wst:InvalidRequest` | `STS-WSTRUST-0004` |
| Product: the inner JWT does not verify or is not this realm's / has expired / names nobody | `wst:InvalidRequest` / `wst:ExpiredData` / `wst:InvalidRequest` | `STS-WSTRUST-0026` / `0027` / `0028` |
| The requester has no entry here, or is a person without `delegation.actorRole` | `wst:RequestFailed` | `STS-WSTRUST-0019` |
| The semantics are not allowed | `wst:RequestFailed` | `STS-WSTRUST-0022` |
| The subject has no authority | `wst:RequestFailed` | `STS-WSTRUST-0023` |
| No, several or an unregistered target | `wst:RequestFailed` | `STS-WSTRUST-0024` |
| A realm's own policy refused, or no policy answered | `wst:RequestFailed` | `STS-WSTRUST-0020` |
| Any other policy refusal (a protected subject, the relationship) | `wst:RequestFailed` | `STS-WSTRUST-0018` |

In product mode an RST with no `AppliesTo`, or one nobody registered, is
refused before the policy is asked (`wst:InvalidRequest` /
`wst:InvalidScope`); see [WS-Trust](ws-trust.md#faults).

### Kerberos

| What happened | KDC error | Code |
|---|---|---|
| S4U2Self for a service other than the requester | `KDC_ERR_BADOPTION` | `STS-KRB-0006` |
| S4U2Self for a disabled person | `KDC_ERR_CLIENT_REVOKED` | `STS-KRB-0129` |
| `PA-S4U-X509-USER`: undecodable, bad checksum, wrong nonce, unknown certificate, name/certificate mismatch | `KDC_ERR_BADOPTION`, `KRB_AP_ERR_MODIFIED`, `KDC_ERR_C_PRINCIPAL_UNKNOWN`, `KDC_ERR_CLIENT_NAME_MISMATCH` | `STS-KRB-0170` to `0175` |
| S4U2Proxy not permitted by either attribute | `KDC_ERR_BADOPTION` | `STS-KRB-0010` |
| Resource-based permission only, but no `PA-PAC-OPTIONS` RBCD bit | `KDC_ERR_BADOPTION` | `STS-KRB-0011` |
| Evidence ticket not forwardable (classic / resource-based) | `KDC_ERR_BADOPTION` | `STS-KRB-0012` / `0199` |
| Evidence ticket's PAC missing or its signatures do not verify | `KRB_AP_ERR_MODIFIED` | `STS-KRB-0176` |
| The issuance policy's other rules (protected user, subject groups, semantics, authority) | `KDC_ERR_BADOPTION` or `KDC_ERR_POLICY` | `STS-KRB-0177` |
| A forwarding request with a non-forwardable ticket, or for a protected person | `KDC_ERR_BADOPTION` | `STS-KRB-0041` / `0042` |

### GNAP

| What happened | Error | Code |
|---|---|---|
| A user assertion issued to another client | `unknown_user` | `STS-GNAP-0073` |
| A trusted client's impersonation refused by the policy | `request_denied` (403) | `STS-GNAP-0770` to `0775` |
| Token derivation turned off (`gnap.tokenDerivation`) | `request_denied` (403) | `STS-GNAP-0510` |
| `existing_access_token` malformed / not active / not issued for this resource server | `invalid_request` / `invalid_request` / `request_denied` | `STS-GNAP-0056` / `0511` / `0512` |
| A derivation refused by the policy | `request_denied` (403) | `STS-GNAP-0776` to `0781` |
| The `act` chain would exceed `gnap.maxDerivationDepth` | `request_denied` (403) | `STS-GNAP-0782` |

### Common causes

* **`invalid_target` on an exchange that should work.** The `audience` or
  `resource` must be on an application's `oauthAudience` (or be its client
  ID), and the value in `appAllowedToDelegateTo` is the target's
  **identifier**, not its audience URI. Send one target, not an `audience`
  and a different `resource`.
* **A delegation refused although S delegates to R.** For a delegation the
  actor must also be S, R, or accepted by R. A client exchanging a token
  issued for somebody else is not S.
* **An impersonation refused.** The actor needs `impersonation` in
  `appDelegationSemantics` — empty means delegation only.
* **Refused in every mode with `may_act`.** The subject's token names one
  delegate. Clear `stsMayAct` (or `appMayAct`) for a chain with more than one
  actor.
* **A person cannot be an actor.** They need the role `delegation.actorRole`
  names (`DELEGATION_ACTOR` by default), which must be created.
* **S4U2Proxy refused with a non-forwardable evidence ticket.** The front
  end lacks `impersonation` in `appDelegationSemantics`, or the user is
  protected.
* **Works in development, refused in product.** Read the act on Monitoring →
  Delegation: in development it states what product would have refused.

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

* [XACML 3.0 and ALFA](xacml.md): the issuance policy these rules are part of.
* [Applications](applications.md): where the application attributes are edited.
* [Service accounts](service-accounts.md): the credential a WS-Trust requester
  authenticates with.
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md): the other grants,
  including the ones that produce subject tokens.
* [JWT assertions](jwt-assertions.md) and [SAML assertions](saml-assertions.md):
  declaring an assertion issuer.
* [What is not checked](what-is-not-checked.md): the development-mode behaviour.
* [Error codes](error-codes.md): every refusal's code, recorded on the audit
  row and never sent.
