---
title: "Verifiable credentials and wallets (OID4VC)"
---

# Verifiable credentials and wallets (OID4VC)

This page is the starting point for everything iya-sts does with digital
wallets: issuing credentials into a wallet, asking a wallet to present one,
signing a person in with a wallet, and the DIDs involved. It is written for an
operator or integrator who has not seen the code. It explains what each part
does, sets out the common tasks as recipes, walks through the admin console
and the user portal, and shows how to connect a web wallet and a native
wallet.

The detail lives on four pages, and this one links to them rather than
repeating them:

* [OpenID4VCI and status lists](oid4vci.md): every issuer feature and setting.
* [OpenID4VP, wallet sign-in and DIDs](oid4vp.md): every Verifier, sign-in,
  SIOPv2 and DID feature and setting.
* [Configuring OpenID4VCI](configure-oid4vci.md) and
  [Configuring OpenID4VP and wallet sign-in](configure-oid4vp.md): recipes
  with exact console steps and Management API calls, taken from the test jobs.

* TOC
{:toc}

## What iya-sts does

| Role | Specification | Where | Read |
|---|---|---|---|
| **Credential Issuer** | [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | `/.well-known/openid-credential-issuer`, `/oid4vci/*`, the token endpoint | [OpenID4VCI](oid4vci.md) |
| **Verifier** | [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), DCQL | `/oid4vp/*`, `/admin-api/verifications` | [OpenID4VP](oid4vp.md) |
| **Wallet sign-in** | OpenID4VP 1.0, the [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/) | `/authn/wallet` | [OpenID4VP](oid4vp.md#signing-in-with-a-wallet) |
| **Relying party of a Self-Issued OP** | [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) | `/authn/wallet`, `/portal/self-issued` | [OpenID4VP](oid4vp.md#self-issued-id-tokens-siopv2) |
| **Status publisher** | IETF Token Status List, W3C Bitstring Status List | `/oid4vci/status-lists*` | [OpenID4VCI](oid4vci.md#status-lists) |
| **DID publisher** | W3C DID Core, DIF Well Known DID Configuration | `/.well-known/did.json`, `/.well-known/did-configuration.json` | [OpenID4VP](oid4vp.md#did-core-and-domain-linkage) |
| **HAIP** | [OpenID4VC HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) | defaults and settings, not a mode | [HAIP](#haip) below |

**iya-sts holds no wallet.** It issues to wallets, verifies what wallets
present, and accepts self-issued ID Tokens that wallets sign. It is never the
Self-Issued OP itself. To try the flows you need a wallet;
[Integrating wallets](#integrating-wallets) covers two that have been used
against it.

### As an issuer

The issuer offers **five fixed credential configurations** in three formats:
SD-JWT VC (`dc+sd-jwt`), `jwt_vc_json`, and `ldp_vc` secured with `bbs-2023`.
`mso_mdoc` is not issued. The configurations are not configurable; what you
choose is which **claims** they carry, taken from the person's directory
entry. The issuer metadata is the live list:

| Configuration | Format | Scope |
|---|---|---|
| `IdentityCredential` | `dc+sd-jwt` | `identity_credential` |
| `IdentityCredentialJwtVcJson` | `jwt_vc_json` | `identity_credential_jwt` |
| `IdentityCredentialLdpVc` | `ldp_vc` | `identity_credential_ldp` |
| `IdentityCredentialDid` | `dc+sd-jwt`, issuer named by `did:web` | `identity_credential_did` |
| `IdentityCredentialLdpVcDid` | `ldp_vc`, issuer named by `did:web` | `identity_credential_ldp_did` |

A wallet collects a credential in one of three ways:

* **A pre-authorized offer with a Transaction Code**, which a signed-in person
  makes for their own wallet on the user portal's **Add to your wallet**
  page (OpenID4VCI Appendix H.2, or H.3 for deferred issuance). This is the
  usual way, and it needs no wallet registration.
* **The authorization code flow**, which the wallet starts itself for a
  configuration's scope. The wallet must be registered as an OAuth client.
* **A same-device Credential Offer** that your own issuer web site builds,
  telling the wallet to start the authorization code flow (Appendix H.1).

Every credential carries a status entry, can be suspended or revoked, and is
recorded in an **issued-credentials register**. Only a credential in that
register can later sign anybody in.

### As a verifier

The Verifier asks for a credential with a DCQL query and checks everything it
can: the issuer signature, every SD-JWT disclosure, the holder's key-binding
proof, the nonce, the audience, the validity window, the requested claims and
the credential's status. It trusts this realm's own issuer by default, and
other issuers whose certificates you add. A verification is started through
the console or the Management API, and its verdict is recorded. **A
verification signs nobody in.**

### Signing in with a wallet

**Sign in with a wallet** on the sign-in screen is the Verifier used as an
authentication method. It is on by default (`oid4vp.signIn`). It signs a
person in only with **a credential this realm issued to them**, as recorded in
the issued-credentials register, never on the strength of what the
credential's own `sub` says. Every format signs in, each with its own proof
of the holder key. The default request is signed under the `x509_hash`
Client Identifier and answered encrypted (`direct_post.jwt`), which is what
HAIP 1.0 has a Verifier send.

### Signing in with a self-issued ID (SIOPv2)

With `oid4vp.signInSelfIssued` on (it is off by default), the sign-in screen
also offers **Sign in with a self-issued ID**. The wallet answers with an ID
Token signed by its own key. Nobody vouches for that key, so it signs in only
the person it was **enrolled** for: the person proves it from the portal, or
an administrator enrols it by value. A DID the person proved can then be
their **preferred DID**, released to applications as the `did` claim, and a
credential configuration can be **bound** to it.

### DIDs

Each realm publishes a `did:web` for its issuer, with a Domain Linkage
Credential that ties it to the origin. An application can have a `did:web` of
its own. A person's DIDs (`did:jwk`, `did:key`, `did:web`) are enrolled as
self-issued subjects. This service does not host a `did:web` for a person;
that is ticket #775 and is not built.

## Before you start

**The service Root is the one trust anchor.** The service's TLS certificate,
the Verifier's request-signing certificate (`x5c` in a signed request) and
the credential signing certificate (`x5c` in a credential and in its Status
List Token) all chain to one Root CA, and the Root itself is never in those
chains. A wallet that checks any of them must be given that Root:

```bash
# PEM, from the Verifier's certificate document
curl -sk https://sts.example/oid4vp/verifier-certificate | jq -r .trust_anchor_pem > sts-root.pem
# or DER, from the PKI
curl -sk https://sts.example/pki/ca/service/root.cer | openssl x509 -inform DER -out sts-root.pem
```

**In development mode the Root is rebuilt at every start**, so a wallet that
was given it must be given the new one after a restart. In product mode it
survives restarts. See [TLS](tls.md#when-a-browser-refuses-the-certificate)
for adding it to a browser.

**Fix the public address.** The realm's `did:web`, the issuer identifier and
the `x509_san_dns` name follow the address the service was reached at unless
`global.publicBaseUrl` is set. Set it in any deployment a wallet will remember.

**A person needs a directory entry**, and in product mode a password, before
they can sign in to the portal and make an offer. See
[Configuring OpenID4VCI](configure-oid4vci.md#pre-authorized-code-with-a-transaction-code-from-the-portal)
for an example `users/create` call.

## Use cases

Each recipe says who does what, where. The console path is
**Protocols → Verifiable Credentials** (`/admin/vc`) unless another page is
named. The Management API calls use the `api` shell helper described in
[Configuring OAuth 2.0 grants](configure-oauth2-grants.md#before-you-start).

### Issue a credential to a person's wallet from the portal

Nothing needs configuring: **Add to your wallet** is on in every realm and in
both modes.

1. Optionally, choose the claims: on the **Credential claims** tab, tick the
   attributes and click **Save this selection**. One selection applies to all
   five configurations.
2. The person signs in to `/portal`, opens **Add to your wallet**, picks a
   credential (*Identity Credential*, `dc+sd-jwt`, is the one most wallets
   hold) and clicks **Make an offer**.
3. Their wallet scans the QR code, or they click **Open in a wallet on this
   device**, and type the Transaction Code shown beside it.

[The user portal](#the-user-portal-step-by-step) below has every control on
the page. The wallet's own requests are in
[Configuring OpenID4VCI](configure-oid4vci.md#pre-authorized-code-with-a-transaction-code-from-the-portal).

### An operator issues or offers a credential

**There is no console page or Management API operation that makes a
pre-authorized offer for somebody else**, in either mode. A pre-authorized
code is an authorization, so only the person, signed in, can have one made
for their own wallet. What an operator can do:

* **Run an issuer web site** that hands the wallet a same-device offer for
  the authorization code flow. The person then signs in at this service's
  authorization server. Register the wallet as a public OAuth client first.
  See [A same-device Credential Offer](configure-oid4vci.md#a-same-device-credential-offer-issuer-initiated)
  and [Authorization code flow](configure-oid4vci.md#authorization-code-flow-wallet-initiated).
* **Issue through the W3C VC API** (`/vc-api`), which is off by default
  (`vcApi.enabled`) and signs a credential the caller supplies, with keys of
  its own. See [W3C VC API](vc-api.md).
* **In development only**, use the
  [companion](docker-compose.md#the-companion-development-only), a separate
  container whose sample issuer page makes a same-device offer and links the
  person to the portal for a pre-authorized one.

### Verify a presentation

A verification is a relying party's presentation request. It records a
verdict and the holder, and starts no session.

* **Console:** on the **Verifier request** tab, choose what to ask for under
  **The claims** and save it, then use **Start a verification** (format,
  request by value or by reference, and optionally the Client Identifier
  prefix, response type, response mode and device) and click **Start**. The
  request appears under **Open verifications**, whose **Outcome** changes
  from *waiting for the wallet* to *accepted* or *refused*.
* **API:** `POST /admin-api/verifications/start` (Admin Write), then
  `GET /admin-api/verifications?state=<state>` (Admin Read) for the verdict.

```bash
api verifications/start '{"format":"dc+sd-jwt","by":"reference",
  "client_id_prefix":"x509_hash","response_mode":"direct_post.jwt",
  "redirect_uri":"https://verifier.example/verified"}'
# → state, requestUri (openid4vp://… for a QR code or a link), walletUrl, request_uri, …
curl -sk "$BASE/admin-api/verifications?state=$STATE" -H "Authorization: Bearer $TOKEN"
```

`redirect_uri` is your page, where the wallet is sent after it answers; in
product mode it must be one of the calling client's registered redirect URIs.
By default the Verifier trusts only this realm's issuer: add another issuer's
PEM certificate to `oid4vp.trustedIssuerCertificates`. Every presented
credential must name a status that resolves VALID
(`oid4vp.requireStatusReference`, `all`). Details:
[Start a verification](configure-oid4vp.md#start-a-verification-and-read-its-outcome),
[Trust another issuer](configure-oid4vp.md#trust-another-issuer-and-the-status-rules).

### Sign in with a wallet

On by default. What has to be true:

1. The person holds a credential **this realm issued to them** on an access
   token it verified, for example from **Add to your wallet**. A credential
   from another realm or another issuer verifies and signs nobody in.
2. The wallet trusts the service Root (the request is signed under
   `x509_hash` and carries the Verifier's chain).
3. The application the person is signing in to is registered, as for any
   sign-in.

The person chooses **Sign in with a wallet** on the sign-in screen, then one
of:

* **Use a wallet on this or a nearby device**: the browser's Digital
  Credentials API, the default and the safest path;
* **Open your wallet on this device**: an `openid4vp://` link for a wallet
  app;
* **Open your web wallet**: only where `oid4vp.walletUrl` is set;
* **Show a QR code instead**: only where `oid4vp.signInCrossDevice` is on. It
  is off because a QR code can be relayed to a victim.

The session records `amr ["pop"]`, or more where a key attestation the issuer
verified says so. A wallet can be followed by a second factor, or be the
second factor after a password. To send one application's people straight to
the wallet, point that application's `appAuthnPolicy` at a [named
authentication policy](authentication.md#named-authentication-policies)
whose only first factor is `wallet`. See
[Sign in with a wallet](configure-oid4vp.md#sign-in-with-a-wallet) and
[What the session says](oid4vp.md#what-the-session-says).

### Sign in with a self-issued ID (SIOPv2)

1. Turn it on: set `oid4vp.signInSelfIssued` on the **OpenID4VP** tab and
   click **Save OID4VP**, or
   `api config/set '{"key":"oid4vp.signInSelfIssued","value":true}'`.
2. The person enrols their wallet's key (next recipe).
3. On the sign-in screen they choose **Sign in with a self-issued ID**, and the
   wallet answers a `siopv2://` request with an ID Token signed by the
   enrolled key.

The ID Token's subject may be a JWK thumbprint, a `did:jwk`, a `did:key` or a
`did:web`. What is checked is in
[Self-issued ID Tokens](oid4vp.md#self-issued-id-tokens-siopv2).

### Enrol a wallet key or DID

A self-issued subject belongs to one person per realm, and a person may hold
ten.

* **The person, by proof** (the only way that counts for the `did` claim and
  for DID holder binding): on `/portal/self-issued`, **Enrol a wallet**. The
  wallet answers a SIOPv2 request from the session they already hold, and the
  key that signed it is enrolled. Nothing is typed. A `did:web` is fetched
  once for the enrolment and its key is pinned. Needs
  `oid4vp.signInSelfIssued` on.
* **An administrator, by value**: on the person's page under
  **Directory → Users**, section **Self-issued IDs**, enter the **Subject**
  and a **Label** and click **Enrol** (Admin Write). The row says *By value,
  unproven*. A `did:web` is fetched as you enrol it and its authentication
  keys are pinned; if it cannot be fetched, the enrolment is refused
  (`STS-ADMIN-0871`). API:

```bash
api users/enrol-self-issued-subject '{"user":"alice","subject":"did:jwk:eyJ…","label":"phone"}'
curl -sk "$BASE/admin-api/users/self-issued-subjects?user=alice" -H "Authorization: Bearer $TOKEN"
api users/remove-self-issued-subject '{"user":"alice","subject":"did:jwk:eyJ…"}'
```

**Proving a subject that is already enrolled proves it again.** That is how an
administrator's entry becomes a proved one, and how a `did:web` whose
document now names another key is re-pinned. Until it is re-proved, a
sign-in with the new key is refused (`STS-VC-0126`).

### A preferred DID and the `did` claim

A person may mark **one** DID they proved as preferred. With `oauth2.didClaim`
on, that DID is released as the `did` claim in the ID Token and the UserInfo
response.

1. The person proves the DID (above), then clicks **Make preferred** beside it
   on `/portal/self-issued`. An administrator can do the same from the
   person's page, or with
   `api users/set-preferred-self-issued-subject '{"user":"alice","subject":"did:jwk:eyJ…"}'`
   (no `subject` clears it).
2. Turn the claim on: `api config/set '{"key":"oauth2.didClaim","value":true}'`.
3. Add `did` to the client's `oauthAllowedScope`. This is needed in both modes.
4. The client asks for `scope=openid did`, and the person consents on the
   consent screen.

A JWK thumbprint and an administrator's by-value entry cannot be preferred
(`STS-PORTAL-0615`, `STS-ADMIN-0872`). A client using pairwise or ephemeral
subjects is not told the DID unless its `oauthDidClaimWithPairwise` is
`TRUE`. The claim is never put in a SAML assertion. When any condition fails,
the claim is left out, never an error. Every condition is in
[Release a person's DID as a claim](configure-oidc-flows.md#release-a-persons-did-as-a-claim).

### Bind credentials to the person's DID

By default a credential is bound to the key the wallet's proof names, with a
different key for each copy of a batch. A configuration named in
`oid4vci.didHolderBinding` binds instead to a `did:jwk` or `did:key` **the
person proved** on `/portal/self-issued`.

```bash
api config/set '{"key":"oid4vci.didHolderBinding","value":"IdentityCredential"}'
```

The wallet's key proof must then name the DID in its `kid`
(`did:jwk:…#0`, `did:key:z…#z…`) instead of carrying a `jwk`. Refusals are
`invalid_proof`: a `jwk` proof (`STS-VC-0145`), a DID an administrator typed
in (`STS-VC-0149`), somebody else's (`STS-VC-0150`), one enrolled for nobody
(`STS-VC-0148`), and a `did:web` (`STS-VC-0142`), which is not offered.
**Every copy then carries the same DID, so any two can be linked.** Neither
wallet described below sends a `kid` proof, so neither can collect a
DID-bound credential. See
[Binding a credential to the person's DID](configure-oid4vci.md#binding-a-credential-to-the-persons-did).

### Suspend, reinstate and revoke issued credentials

* **The operator:** **Monitoring → Verifiable Credentials**
  (`/admin/vc/monitor`), **Credentials** tab: **Suspend**, **Reinstate** or
  **Revoke** a credential by its status-list index. Revoked is final. API:
  `api vc-status/suspend '{"idx":4711}'` (and `reinstate`, `revoke`;
  `GET /admin-api/vc-status` lists them).
* **The person:** **Remove** on **Add to your wallet** revokes the credential
  (or one copy, or all copies of a batch). It is not deleted from the wallet:
  no protocol lets an issuer do that, and the page tells the person to delete
  it there.
* **Also:** a revocation on **Tokens** (`/admin/tokens`), an administrator's
  global sign-out, and a disabled account. The person's own global logout at
  `/logout` does **not** change a credential's status.

A credential that is not VALID is refused by every verifier that reads its
status list, and signs nobody in here. See
[Status lists](configure-oid4vci.md#status-lists-suspend-reinstate-revoke).

### Set it up in a trust realm

Every [trust realm](trust-realms.md) is a separate issuer and Verifier with
its own metadata, keys, offers, status lists, sign-in register, DID and
settings:

| | Default realm | Realm `acme` |
|---|---|---|
| Issuer identifier | `https://sts.example` | `https://sts.example/realm/acme` |
| Issuer metadata | `/.well-known/openid-credential-issuer` | `/.well-known/openid-credential-issuer/realm/acme` |
| DID | `did:web:sts.example` | `did:web:sts.example:realm:acme` (document at `/realm/acme/did.json`) |
| Console | `/admin/vc` | `/realm/acme/admin/vc` |
| Settings by API | `/admin-api/config/set` | `/realm/acme/admin-api/config/set` |
| Portal | `/portal/wallet` | `/realm/acme/portal/wallet` |

A setting changed in one realm does not change it in another. A credential
issued by one realm verifies at another realm's Verifier only if that realm
trusts the issuer's certificate, and it never signs anybody in there.

### Development mode and product mode

The Verifier's checks, the sign-in rules and the status checks are the same in
both modes. What differs:

| | Development | Product |
|---|---|---|
| Access token at the credential, deferred and notification endpoints | Read without verifying it; a credential issued this way signs nobody in | Must verify against this realm's key and not be revoked, else `invalid_token` |
| Claim values a directory entry lacks | Invented, deterministically and in fictional ranges | Left out |
| Wrong Transaction Codes | Not counted | The `oid4vci.txCodeMaxAttempts`th (5) spends the code |
| Signing keys and the service Root | New at every start | Kept, sealed, and rotated on a schedule |
| `wallet` named by a verification start | Any URL | `oid4vp.walletUrl` or one in `oid4vp.allowedWalletUrls` |
| `redirect_uri` named by a verification start | Any absolute http(s) URL | One of the calling client's registered redirect URIs |
| `x509_san_dns` with no configured name | The request's host | Refused |
| A `did:web` enrolled before key pinning | Pinned at its next sign-in | Refused until enrolled again (`STS-VC-0127`) |
| `oid4vp.requireStatusReference=off` | Allowed | Refused, and a stored `off` is read as `all` |

The full lists are in [OpenID4VCI](oid4vci.md#development-and-product-mode),
[OpenID4VP](oid4vp.md#development-and-product-mode) and
[What is not checked](what-is-not-checked.md).

## The admin console, page by page

Everything below needs a console role (`/admin`); changing anything needs
Admin Write. Each control has a Management API twin, listed at the end.

### Protocols → Verifiable Credentials (`/admin/vc`)

One page with five tabs.

1. **Metadata** lists the issuer and Verifier endpoints of this realm, with
   links to the live documents.
2. **OpenID4VCI** holds every `oid4vci.*` setting, and the two `vcApi.*`
   settings, saved with **Save OID4VCI** (and **Save W3C VC API**). The ones
   you are most likely to set:
   * `oid4vci.walletUrl` and `oid4vci.walletIssuancePath`: a web wallet,
     offered as **Open in the web wallet** beside the wallet-app link.
   * `oid4vci.walletInvocation`: `haip-vci` to hand offers over under
     `haip-vci://`.
   * `oid4vci.credentialSigningAlgorithm`: RS256 by default; ES256 for HAIP.
   * `oid4vci.batchSize`: copies per issuance (4; 1 turns batches off).
   * `oid4vci.didHolderBinding`: the configurations bound to a proved DID.
   * `oid4vci.keyAttestationTrustedCertificates` and
     `oid4vci.keyAttestationRequired`: wallet-provider key attestations.
   * `oid4vci.sdJwtIssuerDid`, `oid4vci.ldpVcIssuerDid`: name the plain
     configurations' issuer by `did:web`. These two take effect after a
     restart.
3. **Credential claims** chooses which directory attributes every credential
   carries: tick them in the **In** column and click **Save this selection**.
   Saving also fills those attributes on every person's entry where they are
   missing (invented values in development, nothing in product). **Preview
   the credential for** shows one person's credential as it would be now.
   **Restore the six default claims** goes back to the default.
4. **OpenID4VP** holds every `oid4vp.*` setting, saved with **Save OID4VP**:
   the Verifier's Client Identifier, the trusted issuers, the status rules, the
   wallet URLs, and all the wallet sign-in and SIOPv2 settings.
5. **Verifier request** chooses what the Verifier asks for (**The claims**,
   **Save this request**; claims outside the catalogue under **Also ask for a
   claim that is not in the catalogue**), and in which format by default. **The
   query this builds** shows the next `dcql_query`. Below are **Start a
   verification** and **Open verifications**.

### Monitoring → Verifiable Credentials (`/admin/vc/monitor`)

Two tabs. **Metadata** shows the counts (valid, suspended, revoked), where
this realm's status lists are served and their lifetimes, and **Publish now**
for each Bitstring Status List. **Credentials** lists every issued credential
with its **Index**, **Format**, **Status**, **Changed by** and **Expires**,
and **Suspend**, **Reinstate** and **Revoke**.

### Directory → Users (`/admin/users?user=<name>`)

On a person's page, the section *Second factors, and what this person can
sign in with* has a **Self-issued IDs** block: each enrolled subject with
**How** (*Proved by the person's wallet* or *By value, unproven (an
administrator)*), **Location**, **Preferred DID** with **Make preferred** or
**Clear**, and a remove button; and the form to enrol one by value. The block
says whether `oid4vp.signInSelfIssued` is on. The users list also shows every
holder whose presentation verified, as it shows every other identity that
authenticated.

### Directory → Applications

* **A wallet as an OAuth client**, for the authorization code flow: a public
  client declared for OAuth 2.0 and OpenID4VCI, `oauthTokenEndpointAuthMethod`
  `none`, `authorization_code`, and the configurations' scopes in `oauthScope`.
  Not needed for a pre-authorized offer. See
  [Configuring OpenID4VCI](configure-oid4vci.md#authorization-code-flow-wallet-initiated).
* **`wallet` as the only first factor of the named authentication policy**
  an application names in `appAuthnPolicy` sends its people straight to the
  wallet sign-in.
* **`oauthAllowedScope` `did`** lets a client be told the preferred DID.
* **An application's own DID**: declare it for the DID family and generate a
  key on its **Credentials** tab. See
  [An application's DID](configure-oid4vp.md#an-applications-did).

### Other pages that show wallet activity

* **Tokens** (`/admin/tokens`): issued credentials among everything else this
  realm issued, with the revocation that disowns one.
* **Sessions** (`/admin/sessions`): wallet sign-ins, like any other session.
* **Sign-out** (`/admin/logout`): a global sign-out disowns the person's
  credentials, and each wallet credential's register row can be ended on its
  own.
* `/admin/sts-metadata`: every endpoint, read from the running router.

### The same controls through the Management API

Every `oid4vci.*`, `oid4vp.*` and `oauth2.didClaim` setting is changed with
`POST /admin-api/config/set` (or `config/set-many`, `config/reset`). The rest:

| Operation | What it does |
|---|---|
| `GET /admin-api/oid4vci-settings`, `GET /admin-api/oid4vp-settings` | Read the two settings tabs |
| `GET /admin-api/credential-claims`, `POST …/credential-claims/{select,add,remove,defaults}` | What a credential carries |
| `GET /admin-api/verifier-request`, `POST …/verifier-request/{select,add,remove,defaults,format}` | What the Verifier asks for |
| `POST /admin-api/verifications/start`, `GET /admin-api/verifications` | Start a verification; read its verdict, or list the open ones |
| `GET /admin-api/vc-status`, `POST …/vc-status/{suspend,reinstate,revoke,publish}` | Issued credentials and their status |
| `GET /admin-api/oid4vci/notifications?id=`, `GET /admin-api/oid4vci/last-request` | What a wallet reported to the Notification Endpoint; how the last credential request arrived |
| `GET /admin-api/users/self-issued-subjects?user=`, `POST …/users/{enrol,remove}-self-issued-subject`, `POST …/users/set-preferred-self-issued-subject` | A person's self-issued subjects |

`GET /admin-api/openapi.json` describes each one. See
[Management API](management-api.md) for getting a token.

## The user portal, step by step

The portal (`/portal`, or `/realm/<id>/portal`) is the person's own account
page. Both pages below act only for the person signed in; nobody else can be
named. Their API is the [account API](account-api.md).

### Add to your wallet (`/portal/wallet`)

1. Under **Which credential**, choose a configuration. The names are the
   issuer metadata's; *issuer named by DID* marks the two DID configurations.
2. Under **When it is issued**, choose **As soon as your wallet asks for it**,
   or **Later: your wallet is told to come back for it (deferred issuance)**.
3. Under **Signing algorithm**, keep the configured default or choose another
   the configuration allows. Post-quantum algorithms are defined by drafts,
   and a wallet or verifier may not accept them yet.
4. Click **Make an offer**. The page shows, once:
   * **Scan this with your wallet**: a QR code of the offer by reference;
   * the **Transaction Code**, which is not in the QR code;
   * **Open in a wallet on this device**: the offer by value, as an
     `openid-credential-offer://` link (or `haip-vci://`);
   * **Open in the web wallet**: only where `oid4vci.walletUrl` is set;
   * **The offer, as a link**.

   The offer is good for `oid4vci.offerTtlS` (ten minutes) and can be redeemed
   once. Reloading the page does not show it again; make a new one.
5. The wallet redeems the offer and asks for the Transaction Code.

Under **Credentials issued to you**, every credential this realm still
records for the person is listed, newest first, one row per issuance, with its
**Status** and what **Your wallet reported** to the Notification Endpoint
(*Stored it*, *Could not store it*, *Deleted it*). With batch issuance on, the
copies are folded under the row as *Copy 2 of 4*, each with the start of its
wallet key's thumbprint and its status-list entry. **Remove** revokes the
credential (**Remove all copies**, or **Remove this copy**). The person then
deletes it in the wallet.

An offer is made on the sign-on session the portal is using. If that session
is no longer known, the offer is refused (`STS-PORTAL-0590`); signing in again
fixes it.

### Self-issued IDs (`/portal/self-issued`)

The page lists the wallet keys that sign the person in, one row each:

| Column | What it shows |
|---|---|
| **Subject** | The subject, shortened to its start and end; hover for all of it. Under a DID, a **DID document** link (below) |
| **Label** | The enrolment's label |
| **Enrolled** | When |
| **How** | *Proved with your wallet* or *Added by an administrator* |
| **Location** | Where the key came from: a web wallet's host and port (hover for its address), the name a wallet app reported in its `User-Agent` (labelled as reported), *Browser (DC API)*, *Administrator*, or *Not recorded* for an enrolment made before this was recorded |
| **Preferred DID** | *Preferred*, or **Make preferred** / **Clear** on a proved DID |
| | **Remove** |

* **Enrol a wallet** (shown while `oid4vp.signInSelfIssued` is on) opens the
  wallet sign-in page in enrolment mode, with the same choices as a sign-in:
  the Digital Credentials API button, **Open your wallet on this device**
  (`siopv2://`), the web wallet where one is configured, and the QR code where
  it is on. The wallet signs an ID Token and the key is enrolled. Nothing is
  typed. The page returns with *Your wallet's key is enrolled*.
* **DID document** opens in a new tab. For a `did:web` it is the published
  document at the DID's own address. For a `did:jwk` or `did:key` it is
  `/portal/self-issued/did?subject=…`, the document resolved from the
  identifier itself, with nothing fetched. A JWK thumbprint has no link.
* **Make preferred** marks one proved DID as the one the `did` claim
  releases. The note under the table says whether this realm releases it
  (`oauth2.didClaim`). **Clear** removes the mark.
* **Remove** takes a subject off; it no longer signs the person in. Removing
  the preferred subject clears the mark.

If signing in with a self-issued ID is off, the page says so and offers no
enrolment; the subjects already enrolled stay.

## Integrating wallets

### How a request reaches a wallet

| What iya-sts is doing | Wallet app link | Web wallet link | Other ways |
|---|---|---|---|
| Credential Offer (portal) | `openid-credential-offer://?credential_offer=…`, or `haip-vci://` | `oid4vci.walletUrl` + `oid4vci.walletIssuancePath` + `?credential_offer=…` | QR code of `…?credential_offer_uri=…` |
| Wallet sign-in, verification | `openid4vp://?client_id=…&request_uri=…`, or `haip-vp://` | `oid4vp.walletUrl` + `oid4vp.walletPresentationPath` + `?client_id=…&request_uri=…` | Digital Credentials API; QR code where on |
| SIOPv2 sign-in or enrolment (ID Token alone) | `siopv2://?client_id=…&request_uri=…` | as above | Digital Credentials API; QR code where on |

* **No web wallet is offered unless one is configured.** `oid4vp.walletUrl`
  falls back to `oid4vci.walletUrl`, so one setting covers both unless you
  set the second.
* **The Digital Credentials API** (`navigator.credentials.get`) is how a
  browser or platform wallet is reached. The request is the signed
  `openid4vp-v1-signed` form, whose `expected_origins` names this service, and
  the answer is encrypted by default (`dc_api.jwt`). A browser without the API
  says so, and the link is the way on.
* **The cross-device QR code** for a sign-in is off
  (`oid4vp.signInCrossDevice`), because it can be relayed: whoever scans it
  signs in the browser that showed it. The portal's offer QR code is not
  affected; the Transaction Code protects it.
* **In product mode**, a verification start that names a different `wallet`
  is refused unless that URL is `oid4vp.walletUrl` or is listed in
  `oid4vp.allowedWalletUrls` (`STS-VC-0033`).

### What any wallet needs

To take a credential and sign in with it, a third-party wallet must:

1. **Trust the service Root** (see [Before you start](#before-you-start)) for
   the TLS connection, for the `x5c` chain of a signed request, and to check
   the issuer chain in a credential. A wallet in the EUDI ecosystem can
   instead read the issuer's signed trusted list at `/oid4vci/trusted-list`
   once it trusts the Root as the list's operator.
2. **Redeem a pre-authorized code without a client** (the metadata says
   `pre-authorized_grant_anonymous_access_supported: true`), or, if it names a
   `client_id`, be registered in product mode.
3. **Send a `jwt` key proof** (`openid4vci-proof+jwt`) with a fresh `c_nonce`
   from `/oid4vci/nonce`. A batch of up to `oid4vci.batchSize` proofs gets a
   credential per proof.
4. **Open a request signed under `x509_hash`** (the sign-in default) and
   **encrypt its answer** for `direct_post.jwt`. The request offers an X-Wing
   (`HPKE-10-KE`) key and an ECDH-ES P-256 key; a wallet with only ECDH-ES
   uses the second. A wallet that cannot do either needs
   `oid4vp.signInClientIdPrefix=pre-registered` or
   `oid4vp.signInResponseMode=direct_post`.
5. **Answer a DCQL query** that offers one credential query per format in
   `oid4vp.signInFormats` and accepts any one. A wallet that understands only
   `dc+sd-jwt` can be helped by `oid4vp.signInFormats=dc+sd-jwt`.
6. For SIOPv2, **sign an ID Token** whose subject is one of the types in the
   request's `subject_syntax_types_supported` (JWK thumbprint, `did:jwk`,
   `did:key`, `did:web`), with `iss` equal to `sub`, the request's `nonce`
   and the Verifier's Client Identifier as `aud`.

### A web wallet: the EUDI Dev Wallet

The [EUDI Dev Wallet](https://github.com/eudi-dev/eudi-dev) (`eudi`) is a test
wallet with a web UI, a CLI and an HTTP API. It speaks OpenID4VCI 1.0,
OpenID4VP 1.0 and HAIP 1.0, holds SD-JWT VC, `jwt_vc_json` and mdoc
credentials, and has a debug mode (the default) that reports what an issuer
or verifier gets wrong and carries on, and a strict mode that refuses. It is
for testing only: its own documentation says it stores keys unencrypted and
must never hold real credentials.

**Install and start it** (from its README):

```bash
brew install eudi-dev/tap/eudi-dev     # or a release binary, or: go build -o eudi .
eudi wallet serve --pid                # web UI at http://localhost:8085
```

It listens on `127.0.0.1:8085` and keeps its state in `~/.eudi-dev/wallet/`.
`--register` also registers it for `openid4vp://`, `haip-vp://`,
`openid-credential-offer://` and `haip-vci://` links on macOS and Linux.

**Point iya-sts at it.** The wallet answers presentation requests at
`/authorize` and credential offers at `/credential-offer`:

```bash
api config/set-many '{"oid4vci.walletUrl":"http://localhost:8085",
  "oid4vci.walletIssuancePath":"/credential-offer",
  "oid4vp.walletPresentationPath":"/authorize"}'
```

`oid4vp.walletUrl` is left empty and falls back to `oid4vci.walletUrl`. The
portal now shows **Open in the web wallet**, and the wallet sign-in page
**Open your web wallet**.

**Trust.** In debug mode the wallet does not verify HTTPS certificates and
reports untrusted chains as warnings. To check this service's chains, give it
the Root: `--tls-ca sts-root.pem` for HTTPS in strict mode, and, for the
credentials and their status lists, the trusted list:

```bash
eudi trust add-ca --list trusted-list-ca --ca sts-root.pem
eudi trust add-list https://sts.example/oid4vci/trusted-list
```

**Flows:**

* **Issuance:** make an offer on **Add to your wallet**, click **Open in the
  web wallet**, type the Transaction Code in the wallet's consent dialog and
  approve. The wallet also accepts the offer by reference, so the QR code
  works with its `wallet scan`, and it collects a deferred credential.
* **Wallet sign-in:** **Sign in with a wallet**, then **Open your web wallet**,
  and approve in the wallet's consent dialog. The wallet sends the browser
  back to the wait page, which finishes the sign-in.
* **SIOPv2:** the wallet signs its self-issued ID Token with its own holder
  key and names it by the key's **JWK thumbprint**, not by a DID
  (`internal/wallet/idtoken.go`). It enrols and signs in as a thumbprint, so
  it cannot be a person's preferred DID.
* **Not usable with it:** DID holder binding (its key proofs carry a `jwk`),
  and a combined `vp_token id_token` request: it binds each issued credential
  to a fresh key, while its ID Token is signed by its holder key, and this
  service requires the two to be the same key.

**Two cautions.** The wallet's Docker image derives its keys from a public
seed (`eudi-dev`), so its holder key is the same in every copy of the image:
never enrol that key for a person whose account matters. And its `--haip`
check reports a signed request under any prefix but `x509_hash` as a finding
(strict mode refuses it). Only an administrator's verification sends one by
default; the sign-in's `x509_hash` passes.

[Configuring OpenID4VCI](configure-oid4vci.md#a-worked-example-the-eudi-dev-wallet-a-hand-run)
describes a hand run of the portal with this wallet (not a test job).

### A native wallet: OID4VC Wallet for Linux

[OID4VC Wallet](https://github.com/rcbj/oid4vc-wallet) (`oid4vc-wallet`) is a
desktop wallet for Linux, written to exercise iya-sts. It stores credentials
sealed with AES-256-GCM under a key held by GNOME Keyring, KWallet or two
FIDO2 security keys. Its user guide is at
<https://rcbj.github.io/oid4vc-wallet/>.

**Install it** (from its README; building needs a stable Rust toolchain and
`libudev-dev`):

```bash
./install/install.sh                                    # builds it and registers it for this user
sudo ./install/install.sh --system                      # or for every user
./install/appimage.sh && ./dist/OID4VC_Wallet-0.1.0-x86_64.AppImage install   # or as an AppImage
```

The installer registers it for `openid-credential-offer://`, `openid4vp://`
and `siopv2://`; with `--haip` (or **Also register haip-vci:// and haip-vp://**
on **Settings → Registration**) also for `haip-vci://` and `haip-vp://`.
Nothing needs configuring on iya-sts: it uses the wallet-app links, which are
the default.

**Trust.** It accepts the TLS certificate of an issuer on `localhost`,
`127.0.0.1` or `::1` without further setup, so a local iya-sts works. For any
other host, add the service Root on **Settings → Trust anchors**.

**Flows:**

* **Issuance:** on **Add to your wallet**, click **Open in a wallet on this
  device**. The wallet opens on **Accept** and asks for the Transaction Code;
  type it and choose **Redeem**. It stores every copy of a batch, each with its
  own key. **It does not fetch an offer by reference**, so the QR code (which
  is by reference) cannot be used with it, and it does not wait for deferred
  issuance: choose **As soon as your wallet asks for it**.
* **Wallet sign-in:** **Sign in with a wallet**, then **Open your wallet on
  this device**. The wallet fetches the request, checks it against the
  `x509_hash` (or `x509_san_dns`) Client Identifier, picks a matching
  credential, asks **Use this credential?**, and answers encrypted with
  ECDH-ES. It presents `dc+sd-jwt` credentials only.
* **SIOPv2:** **Enrol a wallet** on the portal, or **Sign in with a self-issued
  ID**, then **Open your wallet on this device**. The first `siopv2://`
  request creates a self-issued key and stores it as a credential. **Settings
  → Security → Self-issued ID subject** chooses how the ID Token names it: JWK
  thumbprint (the default), `did:jwk`, `did:key` or `did:web`. For `did:web`,
  the tab shows the DID document to publish and the https address to serve it
  at; iya-sts fetches it once at enrolment and pins the key (in product mode
  not from an address inside its own network). A DID proved this way can be
  made the person's preferred DID. Changing the choice changes the
  identifier, which must then be enrolled again.
* **Not usable with it:** the Digital Credentials API (it is a desktop app),
  DID holder binding (its key proofs carry a `jwk`), and `jwt_vc_json` or
  `ldp_vc` presentations.

### Which flows each wallet supports here

| Flow | EUDI Dev Wallet (web) | OID4VC Wallet (native) |
|---|---|---|
| Portal offer, by value | yes (**Open in the web wallet**) | yes (**Open in a wallet on this device**) |
| Portal offer, by reference (QR code) | yes | no |
| Deferred issuance | yes | no |
| Wallet sign-in | yes, by the web wallet link | yes, `dc+sd-jwt` |
| SIOPv2 subject | JWK thumbprint | thumbprint, `did:jwk`, `did:key`, `did:web` |
| Preferred DID / `did` claim | no (no DID) | yes |
| DID holder binding (`kid` proof) | no | no |
| `haip-vci://`, `haip-vp://` | yes, with `--register` | yes, with `--haip` |

## HAIP

**There is no HAIP mode or HAIP switch in iya-sts.** The OpenID4VC High
Assurance Interoperability Profile is met through defaults and a few
settings, and "HAIP" in a setting's description means that value is what the
profile asks for.

**Already the default, with nothing to set:**

* The wallet sign-in's request is signed under `x509_hash`
  (`oid4vp.signInClientIdPrefix`) and answered encrypted with
  `direct_post.jwt` (`oid4vp.signInResponseMode`); a plaintext answer is
  refused (`STS-VC-0096`).
* The encrypted answer may use an ECDH-ES P-256 key, offered beside the X-Wing
  key (`oid4vp.responseEncryptionKeyAlgs`).
* The x509 request certificate is ES256 (`oid4vp.x509SigningAlgorithm`).
* A credential and its Status List Token carry their chain in `x5c`, without
  the Root (`oid4vci.credentialCertificateHeader`).
* A wallet that asks for an encrypted credential response may give an EC key
  (ECDH-ES on P-256, P-384 or P-521) as well as an RSA one.

**What you set:**

| To | Set |
|---|---|
| Hand offers over under `haip-vci://` | `oid4vci.walletInvocation=haip-vci` |
| Hand presentation requests (sign-in link, QR code, a verification's `requestUri`) over under `haip-vp://` | `oid4vp.walletInvocation=haip-vp` (an ID Token alone stays `siopv2://`) |
| Sign credentials with ES256 | `oid4vci.credentialSigningAlgorithm=ES256` (RS256 is the default) |
| Accept Wallet Attestation (`attest_jwt_client_auth`) at the token endpoint | `oauth2.clientAttestationTrustAnchors`, and under a FAPI 2.0 profile `oauth2.fapiAllowClientAttestation` — see [Attestation-based client authentication](oauth-oidc.md#attestation-based-client-authentication-wallet-attestation) |
| Accept or require key attestations | `oid4vci.keyAttestationTrustedCertificates`, `oid4vci.keyAttestationRequired` |
| Make an administrator's verification HAIP-shaped | `client_id_prefix: "x509_hash"` and `response_mode: "direct_post.jwt"` on the start (its default prefix is `pre-registered`, `oid4vp.clientIdPrefix`) |

The OpenID Foundation's HAIP issuer test plan runs against a realm with
`oauth2.fapi=2-security`, Wallet Attestation trusted and allowed under FAPI
2.0, and `x5c` (see [Conformance suites](conformance.md)).

**Not covered:** `mso_mdoc` is neither issued nor verified, and the Digital
Credentials API's unsigned and multi-signed request forms and
`transaction_data` are not implemented.

## Settings

The tables below are the settings most deployments touch. Every
`oid4vci.*` and `oid4vp.*` setting, with its environment variable, is on
[OpenID4VCI](oid4vci.md#configuration) and
[OpenID4VP](oid4vp.md#configuration); the live source is the console's tabs
and `GET /admin-api/config`. All of these can be changed while the service
runs, per realm, except the two marked *restart*.

**Issuer:**

| Setting | Environment variable | Default | What it does |
|---|---|---|---|
| `oid4vci.walletUrl` | `OID4VCI_WALLET_URL` | *(empty)* | A web wallet, offered beside the wallet-app link |
| `oid4vci.walletIssuancePath` | `OID4VCI_WALLET_ISSUANCE_PATH` | *(empty)* | The page under the web wallet an offer goes to |
| `oid4vci.walletInvocation` | `OID4VCI_WALLET_INVOCATION` | `openid-credential-offer` | `haip-vci` for `haip-vci://` |
| `oid4vci.offerTtlS` | `OID4VCI_OFFER_TTL_S` | `600` | How long an offer and its code can be used |
| `oid4vci.txCodeLength` | `OID4VCI_TX_CODE_LENGTH` | `5` | Digits in the Transaction Code |
| `oid4vci.txCodeMaxAttempts` | `OID4VCI_TX_CODE_MAX_ATTEMPTS` | `5` | Product mode: wrong codes before the offer is spent |
| `oid4vci.batchSize` | `OID4VCI_BATCH_SIZE` | `4` | Proofs, and so copies, per request |
| `oid4vci.credentialLifetimeS` | `OID4VCI_CREDENTIAL_LIFETIME_S` | `2592000` | Credential validity (thirty days) |
| `oid4vci.credentialSigningAlgorithm` | `OID4VCI_CREDENTIAL_SIGNING_ALGORITHM` | `RS256` | Signs `dc+sd-jwt`, `jwt_vc_json` and the status lists |
| `oid4vci.credentialCertificateHeader` | `OID4VCI_CREDENTIAL_CERTIFICATE_HEADER` | `x5c` | How a credential carries its chain |
| `oid4vci.didHolderBinding` | `OID4VCI_DID_HOLDER_BINDING` | *(empty)* | Configurations bound to a proved `did:jwk` or `did:key` |
| `oid4vci.keyAttestationTrustedCertificates` | `OID4VCI_KEY_ATTESTATION_TRUSTED_CERTIFICATES` | *(empty)* | Wallet providers whose key attestations are believed |
| `oid4vci.keyAttestationRequired` | `OID4VCI_KEY_ATTESTATION_REQUIRED` | `false` | Require a key attestation |
| `oid4vci.statusListTtlS` | `OID4VCI_STATUS_LIST_TTL_S` | `300` | How long a verifier may keep a status list |
| `oid4vci.sdJwtIssuerDid`, `oid4vci.ldpVcIssuerDid` | `OID4VCI_SD_JWT_ISSUER_DID`, `OID4VCI_LDP_VC_ISSUER_DID` | `false` | *Restart.* Name the plain configurations' issuer by `did:web` |

**Verifier and sign-in:**

| Setting | Environment variable | Default | What it does |
|---|---|---|---|
| `oid4vp.signIn` | `OID4VP_SIGN_IN` | `true` | Offer **Sign in with a wallet** |
| `oid4vp.signInSelfIssued` | `OID4VP_SIGN_IN_SELF_ISSUED` | `false` | Offer **Sign in with a self-issued ID** and the portal enrolment |
| `oid4vp.signInFormats` | `OID4VP_SIGN_IN_FORMATS` | `dc+sd-jwt,jwt_vc_json,ldp_vc` | Formats a sign-in asks for |
| `oid4vp.signInClientIdPrefix` | `OID4VP_SIGN_IN_CLIENT_ID_PREFIX` | `x509_hash` | How a sign-in's request names the Verifier |
| `oid4vp.signInResponseMode` | `OID4VP_SIGN_IN_RESPONSE_MODE` | `direct_post.jwt` | Encrypted answer, or `direct_post` |
| `oid4vp.signInDcApiResponseMode` | `OID4VP_SIGN_IN_DC_API_RESPONSE_MODE` | `dc_api.jwt` | Encrypted Digital Credentials API answer, or `dc_api` |
| `oid4vp.responseEncryptionKeyAlgs` | `OID4VP_RESPONSE_ENCRYPTION_KEY_ALGS` | `HPKE-10-KE,ECDH-ES` | Keys an encrypted answer may use |
| `oid4vp.signInCrossDevice` | `OID4VP_SIGN_IN_CROSS_DEVICE` | `false` | Offer the relayable QR code |
| `oid4vp.signInTtlS` | `OID4VP_SIGN_IN_TTL_S` | `300` | How long a sign-in waits |
| `oid4vp.walletUrl` | `OID4VP_WALLET_URL` | `oid4vci.walletUrl` | A web wallet for presentations |
| `oid4vp.walletPresentationPath` | `OID4VP_WALLET_PRESENTATION_PATH` | *(empty)* | The page under it a request goes to |
| `oid4vp.walletInvocation` | `OID4VP_WALLET_INVOCATION` | `openid4vp` | `haip-vp` for `haip-vp://` |
| `oid4vp.allowedWalletUrls` | `OID4VP_ALLOWED_WALLET_URLS` | *(empty)* | Product mode: other wallets a start may name |
| `oid4vp.clientIdPrefix` | `OID4VP_CLIENT_ID_PREFIX` | `pre-registered` | How an administrator's signed request names the Verifier |
| `oid4vp.clientId` | `OID4VP_CLIENT_ID` | `sts-verifier` | The `pre-registered` Client Identifier |
| `oid4vp.x509DnsName` | `OID4VP_X509_DNS_NAME` | *(empty)* | The `x509_san_dns` name; must be the Response URI's host |
| `oid4vp.trustedIssuerCertificates` | `OID4VP_TRUSTED_ISSUER_CERTIFICATES` | *(empty)* | Other issuers the Verifier accepts |
| `oid4vp.requireStatusReference` | `OID4VP_REQUIRE_STATUS_REFERENCE` | `all` | Whether a credential must name its status |
| `oid4vp.siopIdTokenMaxAgeS` | `OID4VP_SIOP_ID_TOKEN_MAX_AGE_S` | `300` | How old a self-issued ID Token may be |

**Elsewhere:**

| Setting | Environment variable | Default | What it does |
|---|---|---|---|
| `oauth2.didClaim` | `STS_OAUTH2_DID_CLAIM` | `false` | Release the preferred DID as the `did` claim |
| `vcApi.enabled` | `STS_VC_API_ENABLED` | `false` | Serve the W3C VC API |
| `global.publicBaseUrl` | `STS_PUBLIC_BASE_URL` | *(empty)* | The address clients use (`https://idp.example.com`); fixes the DIDs, the issuer identifier and the `x509_san_dns` name |

## Endpoints

The authoritative list is `/admin/sts-metadata`, read from the running router
(see [Endpoints](endpoints.md)). In a trust realm the issuer's and Verifier's
paths take `/realm/<id>` in front (`/realm/acme/oid4vci/credential`), the two
`.well-known` issuer documents take it after
(`/.well-known/openid-credential-issuer/realm/acme`), and the realm's DID
document is `/realm/<id>/did.json`.

| Path | What it is |
|---|---|
| `GET /.well-known/openid-credential-issuer` | Credential Issuer Metadata |
| `GET /.well-known/jwt-vc-issuer` | SD-JWT VC issuer key resolution |
| `GET /oid4vci/credential-offer/{id}` | An offer passed by reference |
| `POST /oauth2/token` | The pre-authorized code grant, and every other grant |
| `POST /oid4vci/nonce`, `/oid4vci/credential`, `/oid4vci/deferred_credential`, `/oid4vci/notification` | The issuer's endpoints |
| `GET /oid4vci/status-lists/1`, `/oid4vci/status-lists`, `/oid4vci/status-lists/bitstring/{revocation,suspension}` | Token Status List, its aggregation, the Bitstring Status Lists |
| `GET /oid4vci/trusted-list` | The issuer's signed list of trusted entities (ETSI TS 119 602) |
| `GET /oid4vp/request/{id}`, `POST /oid4vp/response` | A signed request by reference, and the Response URI |
| `GET /oid4vp/verifier-certificate` | The x509 Client Identifiers, the chain and `trust_anchor_pem` |
| `GET /.well-known/did.json`, `/did.json`, `/.well-known/did-configuration.json` | The realm's DID document and domain linkage |
| `GET /applications/{id}/did.json` | An application's DID document |
| `GET /pki/ca/service/root.cer` | The service Root (DER) |
| `/authn/wallet`, `/authn/wallet/wait`, `/authn-api/wallet*` | The wallet sign-in and SIOPv2 pages and their API |
| `/portal/wallet`, `/portal/self-issued`, `/portal/self-issued/did` | The portal pages |
| `/account-api/credentials/{offerable,offers,remove}`, `/account-api/self-issued`, `/account-api/self-issued/did` | Their account API |

## Error codes you will meet

Every refusal is recorded under a code on the audit row and in the log. **The
code is never sent to the wallet or the browser**; the person sees a sentence,
and the wallet sees the specification's error (`invalid_proof`,
`invalid_grant`, `invalid_token`). Look the code up in
[Error codes](error-codes.md). The ones that come up most:

| Code | What happened |
|---|---|
| `STS-PORTAL-0589` | An offer named a configuration this issuer does not offer |
| `STS-PORTAL-0590` | An offer was refused because the portal's sign-on session is no longer known; sign in again |
| `STS-PORTAL-0591` | A **Remove** named a credential that is not the person's |
| `STS-OAUTH-0938` | A pre-authorized code was redeemed for a person with no directory entry |
| `STS-VC-0051` | The cluster store could not be asked about a single-use value, so the request was refused |
| `STS-VC-0053` | `/authn/wallet` was reached with no pending sign-in; start from the application |
| `STS-VC-0058` | A presentation verified but was signed by a trusted foreign issuer, so it signs nobody in |
| `STS-VC-0059` | A presentation verified but this realm has no record of issuing it to anybody |
| `STS-VC-0061` | A sign-in's presentation did not verify |
| `STS-VC-0072` | A presented credential is revoked or suspended, or its status could not be established |
| `STS-VC-0088` | A presented credential names no status, and `oid4vp.requireStatusReference` requires one |
| `STS-VC-0096` | An answer was not in the response mode asked for, for example plaintext to a `direct_post.jwt` request |
| `STS-VC-0093` | A SIOPv2 enrolment came from a browser with no sign-on session, or for somebody else |
| `STS-VC-0094` | A proved key was not enrolled: somebody else holds it, or the person already has ten |
| `STS-VC-0126` | A `did:web` ID Token was signed by a key its enrolment did not pin; enrol it again |
| `STS-VC-0128` | A `did:web` document could not be fetched for its enrolment |
| `STS-VC-0142`–`STS-VC-0150` | A credential bound to the person's DID was refused (see [Bind credentials](#bind-credentials-to-the-persons-did)) |
| `STS-PORTAL-0615`, `STS-ADMIN-0872` | A subject could not be made preferred (not proved, or not a DID) |
| `STS-ADMIN-0871` | An administrator's `did:web` enrolment found no key to pin |
| `STS-VC-0033` | A wallet URL that is not configured or allowed was named, in product mode |
| `STS-VC-0123` | A verification start's `redirect_uri` was not allowed |

## Limits and what is not supported

* **`mso_mdoc`** is neither issued nor verified.
* **DIF Presentation Exchange** is not supported; requests are DCQL.
* **The five credential configurations are fixed.** Only their claims, signing
  algorithm and binding are configurable.
* **No Management API operation makes a pre-authorized offer** for someone
  else.
* **No protocol lets this service delete a credential from a wallet.** Revoking
  it is what **Remove** does.
* **Holder binding to a `did:web`** is not offered, and **a `did:web` hosted
  by the realm for a person** is not built (#775).
* **The `did` claim** is released in ID Tokens and UserInfo only, never in a
  SAML assertion.
* **SIOPv2:** this service is only the relying party. The `fragment` response
  mode and dynamic discovery of a Self-Issued OP are not offered.
* **The Digital Credentials API:** the unsigned and multi-signed request forms
  and `transaction_data` are not implemented.
* **Historical status lists** (`?time=`) answer `501`.
* **Post-quantum:** a trusted issuer certificate or a key attestation
  certificate with a post-quantum key cannot be read, and the x509 request
  certificate cannot be post-quantum. Credentials can be signed with ML-DSA,
  SLH-DSA or a composite, which are drafts many wallets do not accept.
* **The sign-in register is bounded** (`oid4vp.signInRegisterMaxEntries`,
  10000 per realm). Past it the oldest row is dropped, and that credential no
  longer signs anybody in.

## Departures from the specifications

In development mode the credential endpoints read an access token without
verifying it, and wrong Transaction Codes are not counted. Credentials are
signed RS256 unless you choose otherwise, key attestation is not required, and
the Verifier refuses a credential that names no status although the status
reference is optional in SD-JWT VC. Each is listed, with the setting that
changes it, under
[OpenID4VCI, OpenID4VP and verifiable credentials](spec-departures.md#openid4vci-openid4vp-and-verifiable-credentials).

## Related

* [OpenID4VCI and status lists](oid4vci.md) and
  [Configuring OpenID4VCI](configure-oid4vci.md)
* [OpenID4VP, wallet sign-in and DIDs](oid4vp.md) and
  [Configuring OpenID4VP and wallet sign-in](configure-oid4vp.md)
* [W3C VC API](vc-api.md)
* [Authentication](authentication.md), for the sign-in screen and second
  factors
* [Configuring OpenID Connect flows](configure-oidc-flows.md#release-a-persons-did-as-a-claim),
  for the `did` claim
* [Account API](account-api.md) and
  [User-facing pages](user-facing-pages.md#the-user-portal)
* [PKI](pki.md) and [TLS](tls.md), for the service Root
* [Trust realms](trust-realms.md)
* [What is not checked](what-is-not-checked.md)
