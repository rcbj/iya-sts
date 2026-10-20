---
title: "Configuring OpenID4VP and wallet sign-in"
---

# Configuring OpenID4VP and wallet sign-in

This page shows how to set up iya-sts as a
[OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
Verifier, how to let people sign in with a wallet, how to accept self-issued
ID Tokens (SIOPv2), and how to publish an application's DID. Each recipe is
given twice, once as steps in the **admin console** (`/admin`) and once as
calls to the **Management API** (`/admin-api`), and the user portal steps
where the person does the work.

**The values come from this repository's own test jobs**, and each recipe
names the job it is taken from. Change the identifiers and URLs to your own.
How the Verifier and the sign-in *behave*, and every setting with its
default, is on [OpenID4VP, wallet sign-in and DIDs](oid4vp.md). This page
covers only what to fill in. Issuing the credentials a wallet presents is on
[Configuring OpenID4VCI](configure-oid4vci.md).
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the application attribute editor.

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/vc#vc-tab-oid4vp` | **Protocols → Verifiable Credentials**, tab **OpenID4VP** | Every `oid4vp.*` setting, the wallet sign-in's among them, saved with **Save OID4VP**. |
| `/admin/vc#vc-tab-verifier-request` | the same page, tab **Verifier request** | What the Verifier asks for, in which format, and the **Start a verification** form with the **Open verifications** list. |
| `/admin/vc#vc-tab-status` | tab **Credential status** | Suspend, reinstate or revoke a credential, which stops it signing in. |
| `/admin/users` | **Directory → Users**, a person's page | Enrol or remove a person's self-issued IDs. |
| `/admin/applications?application=<id>` | **Directory → Applications** | `appAuthnMechanism`, and an application's DID. |
| `/portal/wallet`, `/portal/self-issued` | user portal | A person collects a credential, and enrols their own self-issued ID. |

`GET /admin-api/oid4vp-settings` reads the settings tab, and
`GET /admin-api/verifier-request` the Verifier request tab.
`GET /oid4vp/verifier-certificate` publishes the Verifier's x509 Client
Identifiers, its chain and its trust anchor.

**What the Verifier supports.** A request is a DCQL query (`dcql_query`, with
`credential_sets`); DIF Presentation Exchange (`presentation_definition`) is
not supported. It asks for `dc+sd-jwt`, `jwt_vc_json` or `ldp_vc`, and not
`mso_mdoc`. The response modes are `direct_post`, `direct_post.jwt`
(encrypted) and, for SIOPv2, `form_post`; over the Digital Credentials API
they are `dc_api.jwt` and `dc_api`.

## What development and product mode change

The Verifier's checks, the sign-in rules, the browser binding and the status
check are the same in both modes. What differs is what a start or a setting
may name:

* **The wallet a verification start names.** Development mode sends a request
  to any URL. Product mode sends it only to `oid4vp.walletUrl` or one listed in
  `oid4vp.allowedWalletUrls`.
* **The `redirect_uri` a start names.** Development mode accepts any absolute
  `http` or `https` URL without a fragment. Product mode accepts only one of
  the calling client's registered redirect URIs, matched whole
  (`STS-VC-0123`).
* **The `x509_san_dns` name.** Without `oid4vp.x509DnsName` or
  `global.publicBaseUrl`, development mode uses the host the request arrived
  at. Product mode refuses the request.
* **`oid4vp.requireStatusReference=off`.** Development mode only. Product mode
  refuses to set it and reads a stored `off` as `all`.
* **A password after a wallet.** As everywhere, development mode does not check
  it and product mode does.
* **Which credentials sign in.** In both modes, only a credential this realm
  issued on an access token it verified. In development the credential
  endpoint also issues on a token it did not verify; such a credential still
  verifies at the Verifier and signs nobody in.

## Choose what the Verifier asks for

What the Verifier asks for is configuration, separate from what the issuer
mints. Asking for a claim no credential here carries is allowed: it is how a
wallet's *I cannot satisfy this request* path is reached. Taken from
`admin_api.js` and `sts_oid4vp_status_reference.js`.

**Console:**
1. Open **Protocols → Verifiable Credentials**, tab **Verifier request**.
2. Under **The claims**, tick each claim to ask for in the **Ask** column, for
   example `given_name` and `family_name`. The **Issued now** column says
   whether the issuer currently mints it.
3. Click **Save this request**.
4. To ask for a claim that is not in the catalogue, type it under **Also ask
   for a claim that is not in the catalogue** and click **Add**.
5. Under **The credential types that can be submitted**, choose **Ask for
   this one by default** on the format a start uses when it names none.

**Back to what this process started with** returns to `oid4vp.claims`
(`given_name,family_name` by default). **The query this builds** shows the
next request's `dcql_query`.

**API:**
```bash
api verifier-request/select '{"claims":["given_name","family_name"]}'
api verifier-request/add '{"claim":"no_credential_here_carries_this"}'
api verifier-request/remove '{"claim":"no_credential_here_carries_this"}'
api verifier-request/format '{"format":"dc+sd-jwt"}'
api verifier-request/defaults '{}'
```

`select` with `{"claims":[]}` asks for no claim. DCQL reads that as the whole
credential, and `sts_oid4vp_status_reference.js` uses it so that a credential
which discloses nothing answers the request. The claims are frozen onto each
request when it is built, so a change does not affect a presentation already
in flight.

## Start a verification and read its outcome

A verification is a relying party's presentation request. The presentation
is verified and the verdict recorded, and nobody is signed in. Taken from
`sts_oid4vp_wallet.js`, section 7.

**Console:** on the **Verifier request** tab, under **Start a verification**,
choose the **Format** (`dc+sd-jwt`), **Request** (by reference), and
optionally the **Client Identifier Prefix**, **Response type**, **Response
mode** and **Device**, then click **Start**. The request appears under **Open
verifications**, and its **Outcome** changes from *waiting for the wallet* to
*accepted* or *refused*.

**API** (needs `admin:write` to start, `admin:read` to read):
```bash
api verifications/start '{"by":"reference","format":"dc+sd-jwt",
  "redirect_uri":"https://verifier.example/verified"}'
# → state, walletUrl (same device), requestUri (openid4vp:// for a QR code),
#   request_uri, dcql_query, expiresAt, …

curl -sk "$BASE/admin-api/verifications?state=$STATE" -H "Authorization: Bearer $TOKEN"
# → found: true, received, verdict {ok, checks, claims, …}
```

`redirect_uri` is your own page, where the Response Endpoint sends the wallet
once it has answered. In product mode it must be one of the calling client's
registered redirect URIs, so the job leaves it out there; a start without one
gets `{}` back from `/oid4vp/response`. The other body members are `by`
(`value` or `reference`), `client_id_prefix`, `response_type` (`vp_token`,
`id_token`, `vp_token id_token`), `response_mode` (`direct_post`,
`direct_post.jwt`, `form_post`), `mode` (`same-device` or `cross-device`) and
`wallet`. `GET /admin-api/verifications` without `state` lists the open
verifications.

**Settings:** `oid4vp.presentationRequestTtlS` (600 s) is how long a request
waits for a wallet, and `oid4vp.kbMaxAgeS` (600 s) how old a Key Binding JWT
may be. `oid4vp.expectedVct` is the `vct` a presented SD-JWT VC must carry.

## How a signed request names the Verifier

A request by value uses the `redirect_uri:` Client Identifier. A signed
request, by reference, uses the prefix `oid4vp.clientIdPrefix` names
(default `pre-registered`, with `oid4vp.clientId`, default `sts-verifier`),
or the `client_id_prefix` a start names. A wallet sign-in has its own setting,
`oid4vp.signInClientIdPrefix`, below.

### `x509_san_dns` and `x509_hash`

Taken from `sts_oid4vp_x509.js`. The Verifier's certificate is issued from
the realm's CA the first time a request needs it.

1. Read what a wallet must be configured with:
   ```bash
   curl -sk "$BASE/oid4vp/verifier-certificate"
   # → response_uri, x509_san_dns {client_id, dns_name, …}, x509_hash {client_id, …},
   #   trust_anchor_pem
   ```
2. **In product mode**, `x509_san_dns` is refused (`x509_san_dns` is `null`)
   until a name is configured, unless `global.publicBaseUrl` already names the
   host. Set the name to the Response URI's host:
   ```bash
   api config/set '{"key":"oid4vp.x509DnsName","value":"sts.example.com"}'
   ```
   A name that is not the Response URI's host builds no `x509_san_dns`
   request. `x509_hash` needs no name.
3. Start a request under either prefix:
   ```bash
   api verifications/start '{"client_id_prefix":"x509_hash"}'
   ```
   or make it the realm's default:
   ```bash
   api config/set '{"key":"oid4vp.clientIdPrefix","value":"x509_hash"}'
   ```

The wallet must trust the service Root (`trust_anchor_pem`). The
`x509_hash` value changes whenever the certificate does: on renewal, on key
rotation, or when `oid4vp.x509SigningAlgorithm` (default `ES256`) changes.

### The other prefixes

`siop.js` sets each of these, and each needs only the setting:

| `oid4vp.clientIdPrefix` | What else it needs |
|---|---|
| `decentralized_identifier` | nothing: the realm's `did:web` and its DID document |
| `verifier_attestation` | `oid4vp.verifierAttestation`: a Verifier Attestation JWT an attestation issuer signed. Empty, the realm attests itself, which only a wallet that already trusts it accepts. |
| `openid_federation` | nothing: the realm's Entity Configuration; see [OpenID Federation](oidfed.md) |

## Trust another issuer, and the status rules

By default the Verifier trusts only this realm's own issuer. Taken from
`sts_oid4vp_status_reference.js`.

**Console:** on the **OpenID4VP** tab, paste the issuer's PEM certificate into
`oid4vp.trustedIssuerCertificates`, and click **Save OID4VP**.

**API:**
```bash
api config/set '{"key":"oid4vp.trustedIssuerCertificates",
  "value":"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"}'
```

**Every presented credential must name its status** by default
(`oid4vp.requireStatusReference` = `all`, in both modes). A trusted issuer
that publishes no status can be exempted by the SHA-256 thumbprint of its
certificate (hex, colon-hex as `openssl x509 -fingerprint -sha256` prints it,
or base64url):

```bash
api config/set '{"key":"oid4vp.statusOptionalIssuers","value":"<sha-256 thumbprint>"}'
# or exempt every foreign issuer (warning: a credential its issuer revoked is then accepted)
api config/set '{"key":"oid4vp.requireStatusReference","value":"own-only"}'
```

`off` also accepts this realm's own credentials without a status; it is
refused in product mode (`STS-CORE-0103`). A foreign issuer's status list is
fetched, verified against the certificate that verified the credential, and
kept no longer than `oid4vp.statusListMaxCacheS` (3600 s).

## Sign in with a wallet

The sign-in screen offers **Sign in with a wallet** to every request that
reaches it: an OAuth authorization request, a SAML `AuthnRequest`, a
`wsignin1.0`, the console and the portal. It is on by default
(`oid4vp.signIn`). Taken from `sts_oid4vp_wallet.js`, which runs it against a
running service in either mode and changes no setting.

**What has to be true first:**
1. **The person holds a credential this realm issued**, on an access token
   this realm verified: from `/portal/wallet`, or by the authorization code
   flow (see [Configuring OpenID4VCI](configure-oid4vci.md)). A credential
   from another realm, a trusted partner or a foreign token verifies and signs
   nobody in.
2. **The wallet trusts this service's Root.** A sign-in's request is signed
   under the `x509_hash` Client Identifier by default and carries the
   Verifier's chain in `x5c`. `GET /oid4vp/verifier-certificate` shows the
   anchor (`trust_anchor_pem`).
3. **The relying party is registered** as for any sign-in. The job registers
   a public OpenID Connect client, `sts-oid4vp-wallet-job-rp`, with redirect
   URI `https://rp.sts-oid4vp-wallet-job.example.test/cb` and scope `openid`;
   see [Configuring OpenID Connect flows](configure-oidc-flows.md#authorization-code-flow).

**What the person does:** on the sign-in screen, **Sign in with a wallet**,
then **Use a wallet on this or a nearby device** (the Digital Credentials
API) or **Open your wallet on this device**. The wallet shows what is asked
for, answers, and the browser continues the waiting request. The session says
`amr ["pop"]`.

**Settings** (on the **OpenID4VP** tab). The response mode and Client
Identifier defaults are what HAIP 1.0 has a Verifier send; change them only
for a wallet that needs it:

| Setting | Default | Why you would change it |
|---|---|---|
| `oid4vp.signIn` | `true` | `false` removes the wallet from the screen; `/authn/wallet` then answers 403. |
| `oid4vp.signInFormats` | `dc+sd-jwt,jwt_vc_json,ldp_vc` | The formats asked for, in order. `oid4vp_sign_in_formats.js` narrows it to `jwt_vc_json`. |
| `oid4vp.signInResponseMode` | `direct_post.jwt` | `direct_post` for a wallet that cannot encrypt. |
| `oid4vp.signInClientIdPrefix` | `x509_hash` | `pre-registered` for a wallet that knows `oid4vp.clientId` out of band. |
| `oid4vp.signInDcApiResponseMode` | `dc_api.jwt` | `dc_api` for a Digital Credentials API answer in the clear. |
| `oid4vp.responseEncryptionKeyAlgs` | `HPKE-10-KE,ECDH-ES` | The keys an encrypted answer may be encrypted to. Leaving out `ECDH-ES` refuses every wallet that has only it. |
| `oid4vp.walletInvocation` | `openid4vp` | `haip-vp` hands the request over under `haip-vp://`. |
| `oid4vp.signInCrossDevice` | `false` | `true` offers **Show a QR code instead**, for a wallet on another device. A QR code can be relayed to a victim, so it is off. |
| `oid4vp.signInTtlS` | `300` | How long a sign-in waits for the wallet and the browser. |
| `oid4vp.signInPollS` | `3` | How often the QR-code page checks. |

`oid4vp_sign_in.js` turns the wallet sign-in off, turns the QR code on, and
sets these together for a wallet that answers in the clear under a
pre-registered identifier:

```bash
api config/set-many '{"oid4vp.walletInvocation":"haip-vp",
  "oid4vp.signInResponseMode":"direct_post",
  "oid4vp.signInClientIdPrefix":"pre-registered"}'
```

**Disowning a credential.** A credential stops signing in once it is
suspended or revoked on the **Credential status** tab, revoked on **Tokens**
(`/admin/tokens`), or after an administrator's global sign-out. An ordinary
sign-out of one application disowns nothing.

### A wallet as one of two factors

Taken from `oid4vp_wallet_mfa.js`. Nothing extra needs configuring:

* When the request, the realm's authentication policy or the account demands
  two factors, the person is asked for a second factor after the wallet
  (their authenticator app, their security key, or their password), and the
  session says, for example, `amr ["pop","otp"]` and `acr "mfa"`.
* After a password, every second-factor screen links to **Use your wallet
  instead**. Only the same person's credential is accepted (`STS-VC-0084`).
* A key attestation the issuer verified can make the wallet two factors on
  its own; see [Configuring OpenID4VCI → Key proofs](configure-oid4vci.md#key-proofs-and-key-attestations).

### Send an application's people straight to the wallet

`appAuthnMechanism` lists the mechanisms an application's people may sign in
with. With `wallet` listed, a sign-in to that application goes straight to
`/authn/wallet`. Taken from `oid4vp_wallet_mfa.js`.

**Console:** on the application's page, in **Change what it is allowed to
do**, tick `wallet` under `appAuthnMechanism`.

**API:**
```bash
api applications/add '{"application":"wsi-wallet","attribute":"appAuthnMechanism","value":"wallet"}'
```

While `oid4vp.signIn` is off, the screen says the wallet is switched off
instead.

## Offer a web wallet for presentations

By default a request is handed to a wallet **app** under `openid4vp://`. A
web wallet is offered beside it, as **Open your web wallet**, only where one
is configured. Taken from `oid4vp_sign_in.js`:

```bash
api config/set-many '{"oid4vp.walletUrl":"https://web-wallet.example/w",
  "oid4vp.walletPresentationPath":"/present"}'
```

The link is then `https://web-wallet.example/w/present?client_id=…&request_uri=…`.
`oid4vp.walletUrl` falls back to `oid4vci.walletUrl`, so a web wallet set for
issuance is offered here too. For the embedded debugger's web wallet the path
is `/vc-presentation-1.html`. In product mode a verification start may name
another `wallet` only if it is in `oid4vp.allowedWalletUrls`.

The eudi-dev hand run in `tests/eudi-wallet-poc/README.md` (a hand run, not a
test job; see [Configuring OpenID4VCI](configure-oid4vci.md#a-worked-example-the-eudi-dev-wallet-a-hand-run))
signs in this way: it chooses **Sign in with a wallet** on the screen,
follows **Open your web wallet** to the wallet on port 8085, and approves the
wallet's consent dialog.

## Self-issued ID Tokens (SIOPv2)

A wallet can sign a person in with an ID Token it signs with its own key.
Nobody vouches for such a key, so it signs in only the person it was enrolled
for, in both modes. Taken from `sts_siop.js`.

**1. Turn it on** (off by default):

**Console:** on the **OpenID4VP** tab, set `oid4vp.signInSelfIssued` and click
**Save OID4VP**.

**API:**
```bash
api config/set '{"key":"oid4vp.signInSelfIssued","value":true}'
```

The sign-in screen then offers **Sign in with a self-issued ID**, and the
portal's `/portal/self-issued` page lets a person enrol a key.

**2. Enrol a key**, one of two ways:

* **The person**, on `/portal/self-issued`: **Enrol a wallet**. The wallet
  answers a SIOPv2 request from the session the person already holds, and the
  key that signed it is enrolled. Nothing is typed.
* **An administrator**: on the person's page under **Directory → Users**,
  section **Self-issued IDs**, enter the **Subject** (a `did:jwk`, or the JWK
  thumbprint) and a **Label**, then click **Enrol**. Through the API:

```bash
api users/enrol-self-issued-subject '{"user":"<username>",
  "subject":"<base64url JWK thumbprint>","label":"job wallet"}'
curl -sk "$BASE/admin-api/users/self-issued-subjects?user=<username>" -H "Authorization: Bearer $TOKEN"
# → subjects listed as urn:ietf:params:oauth:jwk-thumbprint:sha-256:<thumbprint>
api users/remove-self-issued-subject '{"user":"<username>","subject":"<thumbprint>"}'
```

Enrolling the same key twice is refused. A person may hold ten, and a subject
belongs to one person per realm. A removed key signs nobody in.

**3. Without signing anybody in**, a verification can exercise a Self-Issued
OP:
```bash
api verifications/start '{"response_type":"id_token","response_mode":"form_post"}'
```

`oid4vp.siopIdTokenMaxAgeS` (300 s) is how old the ID Token's `iat` may be.

## DIDs

### The realm's own DID

Each realm has a `did:web`, derived from the address the service is reached
at. Nothing needs configuring. The document is at `/.well-known/did.json`
(for a realm, `/realm/<id>/did.json`), and the Domain Linkage Credential at
`/.well-known/did-configuration.json`. Set `global.publicBaseUrl` so the DID
does not change with the host name. The issuer configurations that use it are
in [Configuring OpenID4VCI → An issuer named by a DID](configure-oid4vci.md#an-issuer-named-by-a-did).

### An application's DID

An application declared for the DID family gets
`did:web:<host>[:realm:<id>]:applications:<identifier>`, with its document at
`/applications/<identifier>/did.json`. Taken from `application_did.js`.

**Console:**
1. Create the application with **Decentralized Identifier (DID)** ticked under
   **Protocol families it is declared for**, or add the family to an existing
   one.
2. On its **Credentials** tab, under **DID key pair**, choose an algorithm
   after **Generate a key pair:** (ES256, ES384 or EdDSA) and click
   **Generate**. The private key is shown once, and a sealed copy is kept so
   the service can sign the domain linkage. Tick **replace the keys there** to
   make the new key the only one.
3. Add a `LinkedDomains` service to `didService`, for example
   `LinkedDomains|https://app.example.com`, with **Add to** in **Change what
   it is allowed to do**.
4. Under **Domain linkage**, click **Download did-configuration.json** and
   host the file at `https://app.example.com/.well-known/did-configuration.json`.

**API:**
```bash
api applications/create '{"identifier":"ad-app","name":"ad-app","protocols":["did"],"fields":{}}'
api applications/generate-did-key '{"application":"ad-app","algorithm":"ES384","replace":true}'
api applications/add '{"application":"ad-app","attribute":"didService",
  "value":"LinkedDomains|https://app.example.com"}'
api applications/add '{"application":"ad-app","attribute":"didAlsoKnownAs",
  "value":"https://app.example.com"}'
api applications/sign-domain-linkage '{"application":"ad-app","origin":"https://app.example.com"}'
# → didConfiguration, to host at hostAt
```

A key you hold yourself can be added to `didPublicKeyJwk` as a public JWK
instead, but only a key `generate-did-key` made can sign the domain linkage
(`STS-VC-0115`). The Domain Linkage Credential is good for
`oid4vci.domainLinkageLifetimeS` (a year by default).

## Related

* [OpenID4VP, wallet sign-in and DIDs](oid4vp.md): the behaviour and every setting.
* [Configuring OpenID4VCI](configure-oid4vci.md): issuing what a wallet presents.
* [Authentication](authentication.md), for the sign-in screen and second factors.
* [OpenID Federation](oidfed.md), for the `openid_federation` prefix.
* [Configuring OpenID Connect flows](configure-oidc-flows.md) and [Configuring OAuth 2.0 grants](configure-oauth2-grants.md).
