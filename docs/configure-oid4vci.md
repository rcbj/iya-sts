---
title: "Configuring OpenID4VCI"
---

# Configuring OpenID4VCI

This page shows how to set up iya-sts as a credential issuer for each way
[OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
lets a wallet collect a credential: what to configure, who does it, and the
requests the wallet then sends. Where an administrator does the work, the
recipe is given twice, once as steps in the **admin console** (`/admin`) and
once as calls to the **Management API** (`/admin-api`). Where the person does
it, the recipe gives the **user portal** steps and the
[account API](account-api.md) call behind them.

**The values come from this repository's own test jobs**, and each recipe
names the job it is taken from. Change the identifiers, URLs and passwords to
your own. What each feature *does*, and every setting with its default, is on
[OpenID4VCI](oid4vci.md). This page covers only what to fill in. Presenting a
credential, the Verifier and signing in with a wallet are on
[Configuring OpenID4VP and wallet sign-in](configure-oid4vp.md).
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the application attribute editor.

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/vc` | **Protocols → Verifiable Credentials** | One page with five tabs: **Metadata**, **OpenID4VCI**, **Credential claims**, **OpenID4VP** and **Verifier request**. |
| `/admin/vc#vc-tab-oid4vci` | the **OpenID4VCI** tab | Every `oid4vci.*` setting, saved with **Save OID4VCI**. |
| `/admin/vc#vc-tab-claims` | the **Credential claims** tab | Choose which directory attributes a credential carries. |
| `/admin/vc/monitor` | **Monitoring → Verifiable Credentials** | **Suspend**, **Reinstate** or **Revoke** one issued credential, on its **Credentials** tab. It was the **Credential status** tab of `/admin/vc`, whose old address opens it. |
| `/admin/applications?application=<id>` | **Directory → Applications** | Register a wallet as an OAuth client, for the authorization code flow. |
| `/portal/wallet` | user portal: **Add to your wallet** | A person makes an offer for their own wallet, and sees and removes what was issued to them. |

The API equivalents of the settings tab are `POST /admin-api/config/set`,
`/config/set-many` and `/config/reset`, as for every other setting.
`GET /admin-api/oid4vci-settings` reads the tab.

**The live list of what this issuer offers** is its metadata,
`/.well-known/openid-credential-issuer` (in a trust realm,
`/.well-known/openid-credential-issuer/realm/<id>`). Read it rather than a
copy. It names five configurations in three formats: `dc+sd-jwt`,
`jwt_vc_json` and `ldp_vc` (with `bbs-2023`). The configurations themselves
are fixed and are not set anywhere. `mso_mdoc` is not issued.

## What development and product mode change

* **The access token at the credential endpoint.** Development mode accepts
  any token there and reads its claims unverified. Product mode refuses a
  token this realm did not issue, or one it revoked, with `invalid_token`.
  A credential issued on an unverified token still verifies, but it signs
  nobody in, in either mode.
* **The values in a credential.** Development mode invents what a person's
  directory entry lacks, deterministically and in fictional ranges. Product
  mode invents nothing: an attribute the entry does not hold is left out of
  the credential.
* **Wrong Transaction Codes.** Development mode does not count them. Product
  mode counts them across the cluster, and the `oid4vci.txCodeMaxAttempts`th
  wrong one (5 by default) spends the pre-authorized code.
* **Offers.** In both modes the only door that mints a pre-authorized offer
  is the person's own, on `/portal/wallet`. No Management API operation makes
  an offer for somebody else.
* **Signing keys.** Development mode makes new credential signing keys on
  every start and rotates nothing. Product mode keeps them in the store and
  rotates them on `signing.credentialRotationIntervalDays`.
* **A wallet client.** Product mode refuses an unregistered client, so a
  wallet that names a `client_id` must be registered. A wallet that redeems a
  pre-authorized code without naming one is the anonymous wallet
  (`urn:sts:oid4vci:anonymous-wallet`) in both modes.

## Choose what a credential carries

A credential carries claims chosen from a catalogue of **LDAP attribute
types**. Each value is read from the person's own directory entry. One
selection applies to all five configurations, and the issuer metadata is
built from it too. Taken from `admin_api.js`.

**Console:**
1. Open **Protocols → Verifiable Credentials**, tab **Credential claims**.
2. Under **The attributes**, tick the attributes to carry in the **In**
   column, for example `givenName` and `sn`.
3. Click **Save this selection**.

Saving also *populates the directory*: every person under `ou=users` gains the
selected attributes they are missing. In development these values are
invented; an attribute already there is never overwritten. **Restore the six
default claims** puts the default back, and **Populate the directory now**
runs the sweep alone. **Preview the credential for** shows what one person's
credential would carry now.

**API:**
```bash
api credential-claims/select '{"attributes":["givenName","sn"]}'
api credential-claims/add '{"attribute":"title"}'
api credential-claims/remove '{"attribute":"title"}'
api credential-claims/defaults '{}'
curl -sk "$BASE/admin-api/credential-claims?user=alice" -H "Authorization: Bearer $TOKEN"
```

An `ldp_vc` credential can carry only the terms its JSON-LD context defines.
The tab names any selected attribute that the format cannot express. A
wallet may still ask for a subset of these claims, in the `claims` member of
its `authorization_details`; see [OpenID4VCI → What a credential says](oid4vci.md#what-a-credential-says).

## Pre-authorized code with a Transaction Code (from the portal)

This is the cross-device flow (OpenID4VCI Appendix H.2). The person signs in
to the user portal and makes an offer for their own wallet. The offer carries
a pre-authorized code, and the page shows a Transaction Code (`tx_code`) that
is not in the offer. The wallet needs no registration. Taken from
`sts_oid4vci_preauth_subject.js`, which runs it in both modes.

**What the administrator sets up.** Only the person, with a password. Nothing
else is needed: `/portal/wallet` is on in every realm.

```bash
api users/create '{"username":"v158-holder","invent":false,
  "credential":"password","password":"<password>",
  "attributes":{"cn":"VCI v158-holder","givenName":"VCI","sn":"Holder",
                "mail":"v158-holder@vci158.test"}}'
```

**Portal:**
1. The person signs in to `/portal` and opens **Add to your wallet**.
2. Under **Which credential**, they choose one. *Identity Credential*
   (`IdentityCredential`, `dc+sd-jwt`) is the one most wallets hold.
3. Under **When it is issued**, they choose **As soon as your wallet asks for
   it**.
4. They click **Make an offer**.
5. The page shows **Scan this with your wallet** with a QR code, the
   Transaction Code beside it, and **Open in a wallet on this device**. The
   wallet scans the code (or opens the link) and asks for the Transaction
   Code.

**Account API** (what the page sends, with the portal's DPoP-bound
`account:manage` token; see [Account API](account-api.md)):
```
POST /account-api/credentials/offers
{"configuration":"IdentityCredential","mode":"cross-device"}
→ the Credential Offer, by value (openid-credential-offer://?credential_offer=…)
  and by reference (credential_offer_uri), expiresAt, txCode
```

`GET /account-api/credentials/offerable` lists the configurations the person
may be offered, as the metadata names them. A body that names another person
still makes the offer for the token's own person.

**The wallet's requests:**
```
POST /oauth2/token
  grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
  &pre-authorized_code=<code from the offer>&tx_code=<the Transaction Code>
→ access_token (sub = the person's urn:uuid: subject,
                client_id = urn:sts:oid4vci:anonymous-wallet)

POST /oid4vci/nonce
→ {"c_nonce":"…"}

POST /oid4vci/credential
  Authorization: Bearer <access_token>
  {"credential_configuration_id":"IdentityCredential",
   "proofs":{"jwt":["<openid4vci-proof+jwt>"]}}
```

The proof is a JWS with header `{"alg":"ES256","typ":"openid4vci-proof+jwt",
"jwk":<the holder's public key>}` and payload `{"aud":<the credential
issuer>,"iat":<now>,"nonce":<c_nonce>}`. The credential comes back in
`credentials[0].credential`, bound to that key (`cnf.jwk`).

**Settings** (on the **OpenID4VCI** tab):

| Setting | Default | Why you would change it |
|---|---|---|
| `oid4vci.offerTtlS` | `600` | How long the offer and its pre-authorized code can be used. |
| `oid4vci.txCodeLength` | `5` | The number of digits in the Transaction Code. |
| `oid4vci.txCodeMaxAttempts` | `5` | In product mode, how many wrong codes spend the pre-authorized code. |

The offer is made on the sign-on session the portal's token came from. A
token whose session is no longer known is refused.

## Authorization code flow (wallet-initiated)

The wallet starts an OAuth authorization code flow for a configuration's
scope, the person signs in, and the access token is redeemed at the
credential endpoint. A wallet is a public client. Taken from
`sts_oid4vp_wallet.js`, section 2.

**Console:**
1. **Applications → New application ›**.
2. Set **Identifier** to `sts-oid4vp-wallet-job`.
3. Under **Protocol families it is declared for**, tick **OAuth 2.0** and
   **OpenID4VCI**. A wallet needs an access token, not an ID Token, so it is
   not declared for OpenID Connect.
4. In **Where responses go back to**, enter
   `https://wallet.sts-oid4vp-wallet-job.example.test/cb`.
5. Click **Create the application**.
6. On the application's page, in **Change what it is allowed to do**:
   - **Tick** `none` under `oauthTokenEndpointAuthMethod`, and nothing else.
   - **Set** `oauthConfidential` to `FALSE`.
   - **Tick** `authorization_code` under `oauthGrantType`.
   - **Add to** `oauthScope` the values `identity_credential` and
     `identity_credential_jwt`.

**API:**
```bash
api applications/create '{
  "identifier": "sts-oid4vp-wallet-job", "name": "OpenID4VP wallet job",
  "protocols": ["oauth2", "oid4vci"],
  "fields": {
    "oauthClientId": "sts-oid4vp-wallet-job",
    "oauthGrantType": ["authorization_code"],
    "oauthTokenEndpointAuthMethod": "none",
    "oauthConfidential": "FALSE",
    "oauthRedirectUri": ["https://wallet.sts-oid4vp-wallet-job.example.test/cb"],
    "oauthResponseType": ["code"],
    "oauthScope": ["identity_credential", "identity_credential_jwt"]
  }}'
```

Each configuration's scope is in the issuer metadata (`scope` on the
configuration). In product mode, a client with an empty `oauthAllowedScope`
is issued the standard scopes plus this realm's OpenID4VCI scopes, so these
need no further listing.

**The wallet's requests:**
```
GET /oauth2/authorize?response_type=code&client_id=sts-oid4vp-wallet-job
    &redirect_uri=https://wallet.sts-oid4vp-wallet-job.example.test/cb
    &scope=identity_credential identity_credential_jwt&state=<random>
    &code_challenge=<BASE64URL(SHA256(verifier))>&code_challenge_method=S256

POST /oauth2/token
  grant_type=authorization_code&code=<code>&client_id=sts-oid4vp-wallet-job
  &redirect_uri=https://wallet.sts-oid4vp-wallet-job.example.test/cb
  &code_verifier=<verifier>
```

Then `/oid4vci/nonce` and `/oid4vci/credential` as in the
[pre-authorized recipe](#pre-authorized-code-with-a-transaction-code-from-the-portal),
once per configuration (`IdentityCredential`, then
`IdentityCredentialJwtVcJson`). Consent is on by default, so the person
approves the wallet on `/oauth2/consent` the first time. Instead of a scope,
the authorization request may carry `authorization_details` of type
`openid_credential`, with a `claims` member to ask for a subset.

## A same-device Credential Offer (issuer-initiated)

An issuer's own web site can make an offer that tells the wallet to start the
authorization code flow (OpenID4VCI Appendix H.1). The service draws no
issuer page for this: the offer is a JSON object the site builds and hands to
the wallet. Taken from `sts_oid4vci_conformance.js`, which makes it as the
issuer's web site would:

```
openid-credential-offer://?credential_offer=<URL-encoded JSON>

{"credential_issuer": "<credential_issuer from the issuer metadata>",
 "credential_configuration_ids": ["IdentityCredential"],
 "grants": {"authorization_code": {}}}
```

The offer has no `issuer_state`, which section 4.1.1 allows. The wallet then
runs the [authorization code flow](#authorization-code-flow-wallet-initiated),
so it must be registered as above.

## Deferred issuance

The wallet redeems the offer now and collects the credential later
(Appendix H.3). Taken from `portal_wallet.js`.

**Portal:** as in the [pre-authorized recipe](#pre-authorized-code-with-a-transaction-code-from-the-portal),
but under **When it is issued** choose **Later: your wallet is told to come
back for it (deferred issuance)**.

**Account API:**
```
POST /account-api/credentials/offers
{"configuration":"IdentityCredential","mode":"deferred"}
```

**The wallet's requests.** The credential request is the same, and is
answered `202` with `{"transaction_id":"…","interval":2}`. The wallet then
polls, with the same access token:

```
POST /oid4vci/deferred_credential
  Authorization: Bearer <access_token>
  {"transaction_id":"<id>"}
→ 202 and the same transaction_id until the credential is ready, then 200 and the credential
```

**Settings:**

| Setting | Default | Why you would change it |
|---|---|---|
| `oid4vci.deferredReadyMs` | `4000` | How long the credential stays pending. |
| `oid4vci.deferredIntervalS` | `2` | The `interval` the wallet is told to wait between polls. |

## Batch issuance

One request may carry several proofs, each for a different holder key, and
gets one credential per proof. A wallet can then show a different copy to
each verifier, so its presentations cannot be linked by the key. Taken from
`portal_wallet_batch.js`.

**Setting:** `oid4vci.batchSize` (default `4`) is the most proofs one request
may carry. Set it to `1` to turn batches off.

```bash
api config/set '{"key":"oid4vci.batchSize","value":4}'
```

**The wallet's request** quotes one `c_nonce` in every proof:
```
POST /oid4vci/credential
  {"credential_configuration_id":"IdentityCredential",
   "proofs":{"jwt":["<proof for key 1>","<proof for key 2>",
                    "<proof for key 3>","<proof for key 4>"]}}
→ credentials: four entries, one per key
```

On `/portal/wallet` the four copies are listed as one issuance, each **Copy n
of 4** with the thumbprint of the key it is bound to. **Remove this copy**
revokes one, and **Remove all copies** revokes them all.

## Key proofs and key attestations

Every credential request needs a proof of the holder key: the `jwt` proof
type (`openid4vci-proof+jwt`), or the `attestation` proof type. A `jwt` proof
may also carry a **key attestation** from the wallet's provider in its
`key_attestation` header. What it attests is recorded at issuance, and a
later wallet sign-in may claim more because of it: `hwk`, and `acr "mfa"`
(see [OpenID4VP → What the session says](oid4vp.md#what-the-session-says)).
Taken from `oid4vp_wallet_mfa.js`.

**Settings:**
```bash
# PEM certificate(s) of the Wallet Providers whose attestations are believed
api config/set '{"key":"oid4vci.keyAttestationTrustedCertificates",
  "value":"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"}'
# require one with every credential request, and say so in the metadata
api config/set '{"key":"oid4vci.keyAttestationRequired","value":true}'
```

The test's attestation is a JWS with header `{"alg":"RS256",
"typ":"key-attestation+jwt"}`, signed by the provider's key, whose payload
carries `attested_keys` (the holder's public JWK), the `c_nonce` as `nonce`,
`key_storage` and `user_authentication`. `iso_18045_moderate` in both gives
the session `amr ["pop","hwk","mfa"]` and `acr "mfa"`. An attestation from a
provider not in the list is refused at issuance.

The proof's `iat` must be within `oid4vci.proofIatWindowS` (600 s) of now, and
its `c_nonce` within `oid4vci.cNonceTtlS` (300 s) of being handed out. Each
`c_nonce` is spent once.

## Encrypting requests and responses

A wallet may encrypt its credential request to the realm's own key, which the
metadata publishes in `credential_request_encryption`, and may ask for an
encrypted response with `credential_response_encryption` (`jwk` and `enc`) in
the request. Both are optional by default. To make either one mandatory:

```bash
api config/set '{"key":"oid4vci.requestEncryptionRequired","value":true}'
api config/set '{"key":"oid4vci.responseEncryptionRequired","value":true}'
```

`oid4vci.requestEncryptionKeyBits` (2048) sets the size of the realm's
RSA-OAEP-256 key. It applies to keys made after the change.
`oid4vci.requestEncryptionEncValues` and `…responseEncryptionEncValues`
(`A128GCM,A256GCM`) list the content encryption algorithms offered. No test
job turns the two `…Required` settings on; `vci_request_encryption_key.js`
covers the realm's key.

## The signing algorithm and the certificate chain

`oid4vci.credentialSigningAlgorithm` (default `RS256`) signs `dc+sd-jwt` and
`jwt_vc_json` credentials, the status lists and the Domain Linkage
Credential. The post-quantum ML-DSA, SLH-DSA and composite algorithms are
allowed. `ldp_vc` is always signed with the realm's BBS key. The value
below is from `oid4vp_sign_in_formats.js`, which signs in with an ML-DSA-44
credential; the per-offer choice is from `portal_wallet_signing_alg.js`.

```bash
api config/set '{"key":"oid4vci.credentialSigningAlgorithm","value":"ML-DSA-44"}'
```

**A person may choose per offer.** `/portal/wallet` has a **Signing
algorithm** list for the chosen credential, with the configured default
selected. Through the account API, add `"signingAlg"` to the offer body; it
must be one of the configuration's `signingAlgs` in
`GET /account-api/credentials/offerable`. A post-quantum algorithm is defined
only by drafts, so a wallet or verifier may not accept it yet.

**The certificate chain.** `oid4vci.credentialCertificateHeader` is `x5c` by
default: a credential and its Status List Token carry their signing key's
chain inline, without the service Root. HAIP 1.0 requires `x5c`, and the
HAIP issuer plan in `sts_oid4vci_conformance.js` runs with it. The other
values are `x5u`, `both` and `none`. Give a wallet or verifier the service
Root to trust, from `/pki/ca/service/root.cer`.

## Status lists: suspend, reinstate, revoke

Every credential has a status-list index. The JOSE formats name a Token
Status List entry, the W3C formats a Bitstring Status List entry, and the
index is the same in every list. Taken from `vc_status_list.js`.

**Console:**
1. Open **Monitoring → Verifiable Credentials** (`/admin/vc/monitor`).
2. On its **Credentials** tab, find the credential by its **Index**,
   **Format** or **Expires**.
3. Click **Suspend**, **Reinstate** or **Revoke**. A revoked credential is
   INVALID, and that is final. A suspended one can be reinstated.

**API:**
```bash
curl -sk "$BASE/admin-api/vc-status" -H "Authorization: Bearer $TOKEN"   # rows[].idx
api vc-status/suspend '{"idx":4711}'
api vc-status/reinstate '{"idx":4711}'
api vc-status/revoke '{"idx":4711}'
```

A credential that is not VALID is refused by every verifier that reads the
list, and signs nobody in. The person can revoke their own credential with
**Remove** on `/portal/wallet` (`POST /account-api/credentials/remove` with
`{"id":"…"}`). An administrator's global sign-out and a disabled account also
make credentials INVALID. The person's own sign-out at `/logout` does not.

**Settings:** `oid4vci.statusListTtlS` (300 s) is how long a verifier may keep
a list, and `oid4vci.statusListLifetimeS` (86400 s) how long a list says it is
valid. Where the lists are served is on the tab and in
[OpenID4VCI → Status lists](oid4vci.md#status-lists).

## An issuer named by a DID

The configurations `IdentityCredentialDid` (`dc+sd-jwt`) and
`IdentityCredentialLdpVcDid` (`ldp_vc`) always name the issuer by the realm's
`did:web`, so nothing needs setting to offer them: choose one on
`/portal/wallet`, or ask for its scope (`identity_credential_did`,
`identity_credential_ldp_did`). Taken from `vc_did.js`.

To move the **plain** configurations to the DID as well:

```bash
api config/set '{"key":"oid4vci.sdJwtIssuerDid","value":true}'
api config/set '{"key":"oid4vci.ldpVcIssuerDid","value":true}'
```

Both are off by default, and both take effect only after a **restart**. For
`dc+sd-jwt` a DID issuer is an extension: SD-JWT VC defines no DID-based key
resolution. The DID document is at `/.well-known/did.json` (a realm's at
`/realm/<id>/did.json`) and the domain linkage at
`/.well-known/did-configuration.json`; see
[OpenID4VP → DID Core and domain linkage](oid4vp.md#did-core-and-domain-linkage).
The DID follows the address the service is reached at, so set
`global.publicBaseUrl` if it must not change.

## Handing the offer to a wallet

By default an offer is handed to a wallet **app**, under
`openid-credential-offer://` (OpenID4VCI section 4.1). No web wallet is
offered unless one is configured.

| Setting | Default | What it does |
|---|---|---|
| `oid4vci.walletInvocation` | `openid-credential-offer` | `haip-vci` hands the offer over under HAIP's `haip-vci://` instead. |
| `oid4vci.walletUrl` | *(empty)* | A web wallet. `/portal/wallet` then also shows **Open in the web wallet**. |
| `oid4vci.walletIssuancePath` | *(empty)* | The page under `oid4vci.walletUrl` the offer is sent to. |

The web wallet's link is `oid4vci.walletUrl` + `oid4vci.walletIssuancePath` +
`?credential_offer=…` (or `?credential_offer_uri=…` for the offer by
reference). `sts_oid4vci_conformance.js` sets `oid4vci.walletUrl` to the
conformance suite's offer endpoint and `oid4vci.walletIssuancePath` to empty;
`portal_wallet.js` checks `haip-vci`. For the embedded debugger's web wallet,
the issuance path is `/vc-issuance-1.html`.

```bash
api config/set-many '{"oid4vci.walletUrl":"https://wallet.example.com",
  "oid4vci.walletIssuancePath":""}'
```

`oid4vp.walletUrl` falls back to `oid4vci.walletUrl`, so the same web wallet
is also offered for presentations unless you set that one too.

### A worked example: the eudi-dev wallet (a hand run)

`tests/eudi-wallet-poc/README.md` records the scripts used on 2026-10-17 to
drive the user portal with the eudi-dev wallet (`rcbj/eudi-dev`) as its web
wallet. **They are a hand run, not a test job**: no suite runs them. The
outline:

1. Build and start the wallet on port 8085:
   `go build -o eudi . && ./eudi wallet serve --port 8085`. The 8081 stack's
   web wallet is `http://localhost:8085`.
2. Trust the issuer in the wallet. The trusted list at
   `/oid4vci/trusted-list` anchors the credentials and their status lists
   once the service Root is trusted as its operator
   ([OpenID4VCI](oid4vci.md) gives the commands):
   `eudi trust add-ca --list trusted-list-ca --ca root.pem`, then
   `eudi trust add-list https://<host>/oid4vci/trusted-list`.
3. Sign in to the portal as a regular user, make an `IdentityCredential`
   offer on `/portal/wallet`, follow **Open in the web wallet**, type the
   Transaction Code into the wallet's consent dialog and approve.
4. The status indices of the copies the wallet holds are in
   `~/.eudi-dev/wallet/wallet.json`; `statuscheck.py` decodes
   `/oid4vci/status-lists/1` to show each one's status.

The README lists the traps that run found, including that headless Chrome's
own User-Agent is scored as an automated client and refused at sign-in.

## Related

* [OpenID4VCI](oid4vci.md): what each feature does, and every setting.
* [Configuring OpenID4VP and wallet sign-in](configure-oid4vp.md): presenting what was issued.
* [Account API](account-api.md) and [User-facing pages](user-facing-pages.md#the-user-portal): the portal's side.
* [W3C VC API](vc-api.md): issuing and verifying over the VC API instead.
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md), for the shared mechanics and the token endpoint.
* [PKI](pki.md), for the service Root a wallet trusts.
