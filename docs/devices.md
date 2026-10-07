---
title: Devices
---

# Devices

This service keeps a **device register**: every phone, computer and host a
trust realm knows, each an entry under `ou=devices` in the realm's directory
([LDAP schema](ldap-schema.md)), owned by **one** person or **one**
application. A device is recognised again by the keys it holds, and each device
records whether it is attested, whether it is compliant, and which
applications used it.

The register was built in six phases (issues #164 and #218): the register;
recognition; compliance and the MDM feed; Shared Signals; risk scoring; and
the issuance policy, an acr and a token claim. All six are built, and a
received CAEP `device-compliance-change` is acted on by the Shared Signals
receiver (#153). The console's **Protocols → Device registration** page
says the same from the running build, and is the one to trust.

## Features

* **Two kinds of owner.** A person (a username), or an application entry — a
  workload or a server host registering the machines it runs on.
* **Keys a device is known by**, each with a SHA-256 thumbprint:
  * `x509` — a certificate; the thumbprint is over its SubjectPublicKeyInfo, so
    a renewed certificate over the same key is the same key;
  * `jwk` — a public JWK or DPoP key; the thumbprint is RFC 7638, which is
    DPoP's `jkt`;
  * `webauthn` — a security key the owner enrolled, linked to the device;
  * and the OpenID Connect Native SSO `device_secret`, which is not a key and is
    held only as a hash.

  One key belongs to one device in the realm. Keys are public material: a JWK
  with a private member, or any symmetric key, is refused.
* **Attestation**: a device is `attested` when a verifier checked an
  attestation statement for one of its keys and it chained to a trusted
  root, and `self-asserted` otherwise. The statements verified are an
  Android Key Attestation, an Apple App Attest statement, a TPM key
  attestation in a certificate request, and a WebAuthn attestation (checked
  when the credential was registered).
* **Compliance**: `compliant`, `not-compliant` or `unknown` (where every device
  starts), with the previous value and who set it — an administrator, an MDM
  or posture feed, or development's test control ([below](#compliance)).
* **Status and risk**: a device can be marked **compromised**, which ends the
  sessions it authenticated and revokes what it was trusted with
  ([below](#a-compromised-or-removed-device)); and it carries a risk level —
  `LOW`, `MEDIUM` or `HIGH` — set by risk scoring and by a compromise.
* **Shared Signals**: every change that matters to a relying party goes out
  as a CAEP or RISC event ([below](#what-goes-out-over-shared-signals)).
* **Risk scoring**: the device that proved a sign-in is scored — compromised,
  not compliant, missing, or the person's own and compliant, which lowers
  the score ([below](#risk-scoring)).
* **The issuance policy**: facts about the device go into every issuance
  decision; a compromised device is refused by default, and a realm can
  require a compliant device ([below](#the-issuance-policy)).
* **An acr and a claim**: `urn:sts:acr:compliant-device`, and `device_id` in
  the ID Token and the access token ([below](#tokens-and-the-acr)).

## How a device is registered

| Method | Built | What happens |
|---|---|---|
| Native SSO | yes | The first app's authorization-code grant with `device_sso` makes the device ([OAuth 2.0 and OpenID Connect](oauth-oidc.md)). |
| An administrator | yes | **Directory → Devices** (`/admin/devices`) or `POST /admin-api/devices/create`, owned by a person or an application, with keys typed by value. A key added this way is recorded as proven by nobody and self-asserted. |
| The owner, on the portal | yes | `/portal/devices`: proving a key (below), or linking a WebAuthn platform credential enrolled on `/portal/keys` with a fresh assertion. |
| EST and SCEP | yes | A certificate from the `device` profile, issued to the device entry. |
| A remembered browser | yes (#265) | "Remember this browser" at sign-in or on `/portal/devices`: a device known by a signed and encrypted cookie, in any browser. The lowest assurance the register has — [below](#remembered-browsers). |

A person sees their devices on `/portal/devices` and can remove one.

### Proving a key on the portal

1. The signed-in person asks for a **challenge** — the **Get a challenge**
   button, or `POST /portal/devices/challenge` with `{"purpose":"key"}` as
   `application/json` for a device app holding the portal session. The
   answer names the challenge, the `aud` to sign for (this page's absolute
   address) and the `typ`. A challenge is bound to that session, lives
   `devices.challengeTtlSeconds` and is answered once.
2. The device answers with **one** of:
   * a compact JWS with header `{"typ":"device-key-proof+jwt","alg":…,
     "jwk":<the public key>}` over `{"nonce":<challenge>,"aud":<aud>,
     "iat":<now>}`, signed by the key it will be known by (any asymmetric JWS
     algorithm, ML-DSA included). An Android app adds the key's attestation
     certificate chain as `x5c`; its `attestationChallenge` must be the
     challenge.
   * an Apple App Attest key id and attestation object, made with the
     challenge's SHA-256 as the client data hash, for an app named in
     `devices.appleAppAttestAppIds`.
3. The person pastes it into the form — or the app posts
   `{"challenge", "proof" | "app_attest":{"key_id","attestation"},
   "device_id"?, "label"?, "platform"?, "model"?, "os"?}` to
   `POST /portal/devices/proof`, answered `201` with the device.

### A certificate over EST or SCEP

`/.well-known/est/device/simpleenroll` (EST, authenticated as usual), or a
SCEP challenge password created for the `device` profile. The certificate
names only `urn:sts:device:<id>`: a request whose subjectAltName names an
existing device's URN certifies a key for that device (its owner, or an
administrator); one naming none creates a device owned by the requester. A
request may carry a TPM key attestation in the `id-aa-attestation` attribute
of draft-ietf-lamps-csr-attestation, as a TCG `tcg-attest-tpm-certify`
statement with the Attestation Key's certificate chain; it is attested when
that chain ends at `devices.tpmTrustAnchors`.

The statement must also be **fresh**. Its `extraData` must be a nonce from
EST's `/.well-known/est/device/nonce`, sent back with that answer's cookie
([EST](est.md#the-attestation-freshness-nonce)). Product mode refuses a
statement that is not fresh (STS-DEVICE-0050). Development mode records
freshness `unproven`. SCEP has no nonce operation, so in product mode a TPM
statement over SCEP is refused.

**The statement format.** No current specification defines the TPM
statement. draft-ietf-lamps-csr-attestation revision 29 defines none, and
revision 21 removed the TPM appendix. The service reads revision 20's
appendix A.2.3: `Tcg-csr-tpm-certify ::= SEQUENCE { tpmSAttest, signature,
tpmTPublic OPTIONAL }`, each an OCTET STRING, with the TPM structures sized
or bare. The places where that text disagrees with itself are listed in
`common/crypto.js`, beside the codec.

A device renews by enrolling
again, naming its URN; `/simplereenroll` and SCEP RenewalReq are refused for
it, and ACME does not issue it.

## How a device is recognised

Presenting any key a device holds identifies it:

| Evidence | Where |
|---|---|
| a client certificate whose key is a device's x509 key | a sign-in, and the token endpoint (RFC 8705) — a certificate refused on revocation is not |
| a linked WebAuthn credential | a sign-in |
| a DPoP proof whose key (`jkt`) is a device's jwk key | the token endpoint |
| the Native SSO `device_secret` | the token endpoint |
| a remembered browser's cookie (`browser-cookie`) | a sign-in — the weakest evidence, used only when nothing else names a device |

The recognised device is recorded on the sign-in's authentication event and
on the token issuance. Risk scoring, the issuance policy, the acr and the
`device_id` claim all read it from there. A compromised device is still
recognised. **Monitoring → Devices** counts recognitions by kind.

A device found at a sign-in is read again from the register whenever it is
used later: at the next token request on that session, and for the acr. So a
device an MDM reports not compliant, or an administrator marks compromised,
counts as such for everything issued afterwards on sessions it already
proved. A device removed since counts as no device.

## Remembered browsers

The register above recognises a device by a key it proved: a WebAuthn platform
credential, a DPoP key, a client certificate or a Native SSO secret. A general
browser often can prove none of these. Linux Firefox, for example, has no
built-in authenticator at all. A **remembered browser** works in every
browser, and it is deliberately weaker: the browser carries a token in a
cookie rather than proving a key. Whoever holds a copy of the cookie *is* that
browser until the copy is caught. Everything about how the rest of the service
treats it follows from that.

### How a browser is remembered

1. The person ticks **Remember this browser** on the sign-in screen, or
   presses the button on `/portal/devices` while signed in. Nothing is
   remembered unless they ask.
2. When the session starts, a device is registered for them:
   - enrolment method `browser`;
   - named after the browser, for example `Firefox on Linux`;
   - attestation level **`bearer`**, which is below `self-asserted`;
   - no keys.
3. The browser is sent a cookie holding the device token:
   - `HttpOnly`, `SameSite=Lax` and `Path=/`;
   - `Secure` with a `__Host-` prefix when the service is on HTTPS;
   - one cookie per trust realm.

   It lasts `devices.browserTokenLifetimeDays` (180 days), and each time the
   browser is used the clock starts again. Page scripts cannot read it.

### What the token is

A nested JWT that only this service ever reads:

- **Signed** (JWS, ES256, `typ: browser-device+jwt`) with a key pair used for
  nothing else:
  - in the `per-algorithm` signer model, the realm's dedicated browser-device
    signing key;
  - in `hybrid-groups`, the ES256 key of the `browser-devices` signer group,
    whose certificate is hybrid with an ML-DSA-44 partner like every group's.
- **Encrypted** (JWE, ECDH-ES+A256KW with A256GCM) to the realm's own
  browser-device encryption key. Encryption keeps the device id and the owner
  out of anybody's cookie jar. The signature is what makes the token trusted.
- **Claims:**
  - `iss` and `aud`: `urn:sts:browser-device:<realm>`;
  - `sub`: the device id;
  - `owner`: the username;
  - `gen`: the generation, which goes up by one at every sign-in;
  - `jti`, `iat` and `exp`.
- **Classical keys, deliberately.** A cookie holds about 4 KB, and a
  post-quantum signature does not fit in one. A token that would be too large
  is not issued (`STS-DEVICE-0043`). The usual cause is setting
  `devices.browserTokenCertificateHeader` to `x5c`.

Both key pairs are members of the realm's key set. They are sealed at rest in
product mode, shared by every request worker and node, and added to a key set
that was stored before they existed. Neither is published.

### How it is recognised, and how a copy is caught

At a sign-in, the cookie is decrypted, its signature and claims are checked,
and the device it names is looked up. Recognition makes the browser the
person's **own recognised device**. Beyond that, what the token tells the rest
of the service depends on the generation:

| Case | What happens |
|---|---|
| **Current** generation | The token is issued again with `gen + 1` after the sign-in, so the cookie rotates on every use. |
| **One behind**, within `devices.browserReissueGraceSeconds` (60) | Accepted as a second tab that signed in at the same moment. |
| **Older** than that | The cookie was **copied**. The device is marked **compromised**, which ends every session it holds, and the cookie is cleared (`STS-DEVICE-0041`). |
| Names **somebody else's** device | Not treated as this person's device (`STS-DEVICE-0042`). |
| Presented by a **different browser family or OS** than it was bound to | Recorded as a changed context. |
| **Unreadable** or expired | Cleared, and the browser is treated as unrecognised (`STS-DEVICE-0040`). |

### What it counts for

A remembered browser can only **remove** suspicion. It never **adds** trust:

- **Risk scoring:** a sign-in from the person's own remembered browser is
  neither `new-device` nor `unregistered-device`. It never earns the
  compliant-device signals that lower risk.
  - A copied cookie is `browser-token-replayed`.
  - Someone else's cookie is `browser-token-foreign`.
  - A changed browser is `browser-context-changed`.
- **Compliance:** a `bearer` device cannot be marked compliant, by an
  administrator or by an MDM feed (`STS-DEVICE-0039`). So it never satisfies
  `devices.requireCompliantDevice` and never meets
  `urn:sts:acr:compliant-device`.
- **The issuance policy** sees `via: browser-cookie` and attestation `bearer`
  like any other device fact, so a rule can tell it apart.
- **If the person later links a real key to it**, the device takes that key's
  level.

### Skipping the second factor

An administrator may let a remembered browser stand in for the second factor.
This is in the realm's authentication policy on **Directory → Policies**:

- **A remembered browser may skip the second factor**: off by default.
- **How long a remembered browser skips the second factor**: 30 days by
  default, from the last time the second factor was given *on that browser*.

Even with the policy on, the second factor is still asked for when any of
these is true:

- the sign-in is for the **admin console**, the **user portal** or the
  **protocol debugger**;
- the person holds a **console role** (Admin Read or Admin Write);
- the sign-in's **risk** is MEDIUM or higher;
- the cookie was copied, belongs to someone else, is presented by a different
  browser, or names a compromised device;
- a relying party **demanded** a second factor (`acr_values`, `wauth`), a
  security key was demanded, or risk scoring asked for a step-up.

When it is skipped, the session is **one factor**: `amr ["pwd"]` and acr `1`,
exactly as for a person who has no second factor. A relying party that needs
two factors asks for them and always gets them.

**The warning:** anyone who copies the cookie skips the second factor too,
until the copy is caught. The copy is caught the next time either browser
signs in after the other, and that ends every session the device holds. Only
turn the skip on where that trade is acceptable.

## Compliance

A device's compliance is set through four doors. Each change records the
previous value, when, the **source** and who acted; **Monitoring → Devices**
counts changes by source, day by day.

| Door | Source | Who may use it |
|---|---|---|
| An administrator: the **Compliance** form on a device's page, or `POST /admin-api/devices/set-compliance` | `admin` | Admin Write. May also set `unknown`, withdrawing a vouch. |
| An MDM or posture feed: `POST /admin-api/device-compliance` | `mdm` | A client holding an access token with the **`device:compliance`** scope, and nothing else, whose application is a member of the `DEVICE_COMPLIANCE` role. |
| The test control: `POST /devices/test/compliance` | `test-control` | Anybody, **in development only**; product answers `403`. |
| A received CAEP `device-compliance-change` from a trusted transmitter | `caep` | A federation partner whose Shared Signals this realm receives, as the `signal-response` policy permits (#153, #373). A device manager is an `ssf` relationship on **Federation** (#374). The device is named by its id (an `iss_sub` subject's `sub`) or a key thumbprint. |

### Integrating an MDM or posture feed

1. **Register the feed as an application** in the realm
   (`/admin/applications/new`, or `POST /admin-api/applications/add`) with a
   client secret (or a certificate or key for `private_key_jwt`), and declare
   `device:compliance` in its **allowed scopes** (`oauthAllowedScope`).
   `device:compliance` is a **protected scope**: the token endpoint issues it
   only to a client that declares it, in both modes, and `/admin-api` asks
   again on every call, so removing it from the application stops the tokens
   the feed already holds.
2. **Add the application to the `DEVICE_COMPLIANCE` role** (#309), on
   `/admin/roles` or with `POST /admin-api/roles/add-member`
   `{"role": "DEVICE_COMPLIANCE", "kind": "application", "member": "<feed>"}`.
   The role authorizes `device:compliance`. It exists in every realm with no
   members, so no client is the feed until you add one; declaring the scope
   alone is not enough. Taking the application out of the role stops the
   tokens it already holds at the next call.
3. **Get a token** with the client credentials grant:
   `POST /oauth2/token` with `grant_type=client_credentials`,
   `scope=device:compliance` and `resource=<base>/admin-api` (the resource
   indicator puts the management API in the token's `aud`; without it every
   call is refused `401`).
4. **Report**: `POST /admin-api/device-compliance` with
   `Authorization: Bearer <token>` and a JSON body — one report, or up to
   `devices.complianceFeedMaxReports` of them:

   ```json
   { "reports": [
       { "thumbprint": "fZXwv9eBhY5TwEjZxaWhjv9ad9QunF5Jw0YCDskz_10",
         "keyKind": "x509", "status": "compliant" },
       { "certificate": "-----BEGIN CERTIFICATE-----\n...",
         "status": "not-compliant", "reason": "Disk not encrypted" },
       { "id": "527e640b-72d3-4a7b-89e4-6534c639701e",
         "status": "compliant" } ] }
   ```

   A report names its device by **`id`**, by a key **`thumbprint`** (base64url
   SHA-256: of the SubjectPublicKeyInfo for a certificate, RFC 7638 for a JWK;
   `keyKind` narrows it) or by its **`certificate`** (PEM) — so an MDM that
   issued or inventoried a device's certificate can report it without knowing
   this service's id. `status` is `compliant` or `not-compliant`; `reason` is
   optional and becomes the event's `reason_admin`.

The answer is `200` with `applied`, `refused` and `results` — one per report,
in order, with its `id`, `previous`, `status`, `changed` and `signalled`, or
its `errors`. A report naming no device is refused on its own and the rest
apply; a request with no report or too many is refused whole (`400`,
`STS-DEVICE-0034`). The feed sets **compliance only**: ownership, keys and
status are an administrator's. A token carrying `admin:write` is refused here,
so a report recorded with source `mdm` always came from a feed.

## A compromised or removed device

**Marking a device compromised** (the **Mark compromised** button on its page,
or `POST /admin-api/devices/set-status` with `"status":"compromised"`):

* ends every sign-on session one of its keys authenticated — each a CAEP
  `session-revoked` and its relying parties' back-channel Logout Tokens;
* revokes its Native SSO `device_secret`;
* revokes every certificate this service's EST or SCEP Issuing CA issued it,
  with reason **keyCompromise**, so its CRL and OCSP responder say so;
* ends every GNAP grant whose client key is one of the device's keys —
  including a client proving by mutual TLS with one of the device's
  certificates — and revokes every OAuth access or refresh token bound to the
  device: DPoP-bound to one of its JWK keys, or bound by mutual TLS (RFC 8705
  `x5t#S256`) to a certificate over one of its keys — the certificate the
  device's `x509` key holds, or any other certificate over the same key (one
  another CA issued, or a re-issue this register never saw), because the key
  under a bound certificate is recorded when the token is issued
  ([#432](https://github.com/rcbj/iya-sts/issues/432)). A WebAuthn key binds
  no token;
* raises its risk level to `HIGH`;
* sends RISC `credential-compromise` for a person's device, and
  `sessions-revoked` where `risc.autoEmitTypes` names it (below).

The device stays in the register, recognised and marked compromised.
**Restoring it** puts back the risk level the compromise raised; nothing
revoked comes back — a certificate is re-issued, and a secret is minted at the
next Native SSO sign-in.

**Removing a device** ends the sessions it authenticated and revokes its
certificates with reason **cessationOfOperation** (keyCompromise when it was
compromised). For a person's device it sends RISC `sessions-revoked` where
`risc.autoEmitTypes` names it.

## What goes out over Shared Signals

Each event is sent to every stream that asked for its type and covers its
subject, when `caep.autoEmitTypes` or `risc.autoEmitTypes` names it (all of
them do by default, except RISC `sessions-revoked`).

| Event | When |
|---|---|
| CAEP `device-compliance-change` | a device's compliance changes in a way a receiver can be told (below) |
| CAEP `risk-level-change`, `principal` `DEVICE` | a device's risk level changes — risk scoring, or a compromise (`HIGH`) |
| CAEP `credential-change` | a device key is added (`create`), re-issued over EST (`update`) or removed (`delete`); a Native SSO secret is issued (`create`) or revoked (`revoke`); a device is removed (`delete`, per credential) |
| CAEP `session-established`, `session-presented`, `session-revoked` | as for every session — and the subject names the **device** when a registered device authenticated the session |
| RISC `credential-compromise` | a person's device is marked compromised: one per kind of credential it held |
| RISC `sessions-revoked` | a person's device is marked compromised or removed — only where `risc.autoEmitTypes` names it, which the default does not |

**The subject** is SSF's complex subject with a `device` member —
`{"format":"iss_sub","iss":<this realm's issuer>,"sub":<the device id>}`, the
form CAEP's own example uses — and a `user` member naming the owner when the
owner is a person. A receiver that adds `{"format":"complex","device":{…}}`
to its stream is sent that device's events (SSF 1.0 section 8.1.3.1); one that
added the person is sent them too.

**Compliance on the wire.** CAEP knows two values, `compliant` and
`not-compliant`, so a device's `unknown` is sent as `not-compliant`: nobody
has vouched for it. An event goes out only when the sent value changes —
`unknown` → `not-compliant` is no event, `unknown` → `compliant` is
`not-compliant` → `compliant`, and an administrator setting a compliant
device back to `unknown` is `compliant` → `not-compliant`.
`initiating_entity` is `admin` for an administrator and `system` for the feed
and the test control.

**Credential types.** A certificate is `x509` with its issuer and serial; a
linked WebAuthn credential is `fido2-platform` or `fido2-roaming`. A device's
JWK key and its Native SSO secret fit none of CAEP's registered types, so they
are sent as `urn:iya:sts:credential-type:device-key` and
`urn:iya:sts:credential-type:device-secret` — CAEP allows a type the
transmitter and receiver agree on.

**RISC and the deprecated `sessions-revoked`.** RISC 1.0 says new
implementations should use CAEP's `session-revoked`, and each ended session
sends one. So `sessions-revoked` is not in `risc.autoEmitTypes`' default
([#269](https://github.com/rcbj/iya-sts/issues/269)). Add it for a receiver
that still needs it: it goes out with the device beside the person in the
subject, meaning *every session of this account on this device*.

## Risk scoring

Every sign-in is scored ([Risk scoring](risk-scoring.md)). The device that
proved the sign-in adds up to eight signals. Each is a factor on the score, and
`risk.signalFactors` can change it:

| Signal | Factor | When |
|---|---|---|
| `compromised-device` | ×50 | The device is marked compromised. This is HIGH on its own. |
| `non-compliant-device` | ×3 | The device is `not-compliant`. |
| `unregistered-device` | ×2 | No device of the person's own was recognised: none at all, or someone else's. |
| `compliant-attested-device` | ×0.5 | The person's own device, compliant and attested. This lowers the score. |
| `compliant-device` | ×0.8 | The person's own device, compliant and self-asserted. This lowers it less. |
| `browser-token-replayed` | ×50 | A remembered browser presented an older token than its device holds: the cookie was copied, and the device is now compromised. This is HIGH on its own. |
| `browser-token-foreign` | ×2 | The browser carries another person's remembered-browser cookie. |
| `browser-context-changed` | ×2 | A remembered browser's cookie arrived from a different browser or operating system than it was bound to. |

* **`unregistered-device` is scoped.** It fires only for a person who has
  registered a device, or for anybody while `devices.expectRegistered` is on.
  It also waits until the person has `risk.minimumHistory` earlier sign-ins.
  In a realm where nobody has registered anything, it never fires.
* **The two lowering factors** never make a sign-in scored on their own.
  They are never applied to a compromised device.
* **The person's own registered device is never `new-device`.** The history
  records it under its register id rather than the browser fingerprint.
* **The device's own risk level.** After a sign-in the person's own device
  proved, the device takes that sign-in's level: `LOW`, `MEDIUM` or `HIGH`.
  CAEP `risk-level-change` (principal `DEVICE`) is sent only when the level
  changes.
  * An UNSCORED sign-in sets nothing.
  * A compromised device stays `HIGH` until it is restored.
* **Monitoring → Risk** shows the device beside the browser on each
  assessment.

**The screen's own WebAuthn step is scored too.** The sign-in screen
scores the sign-in before its WebAuthn ceremony, because the score decides
whether to ask for one. When the ceremony is done, the same assessment is
amended with the device the key belongs to, before the session is decided.
Only the device's signals are worked out again, and the history counts the
sign-in once. So a person signing in with a platform credential linked to
their own registered device is not `unregistered-device`, and a compliant
device lowers the score. This works whether the key is the first factor or the
second, and after a password, a wallet or an emailed code. Monitoring → Risk
shows the amended assessment. A client certificate on the connection is
scored at every door.

## The issuance policy

Facts about the device go into every issuance decision as XACML environment
attributes. The built-in `role-issuance` policy decides on them, and a realm's
own policy can too ([XACML](xacml.md)):

| Attribute | Value |
|---|---|
| `urn:sts:xacml:device-recognized` | a boolean |
| `urn:sts:xacml:device-id` | the register's id |
| `urn:sts:xacml:device-via` | `x509`, `webauthn`, `jwk` or `native-sso` |
| `urn:sts:xacml:device-owner-matches` | a boolean: the device is the subject's own |
| `urn:sts:xacml:device-owner-kind` | `person` or `application` |
| `urn:sts:xacml:device-compliance` | `compliant`, `not-compliant` or `unknown` |
| `urn:sts:xacml:device-attestation` | `attested` or `self-asserted` |
| `urn:sts:xacml:device-status` | `active` or `compromised` |
| `urn:sts:xacml:device-risk-level` | `LOW`, `MEDIUM` or `HIGH`, when assessed |
| `urn:sts:xacml:device-requirement` | what this realm's settings require: `not-compromised`, `compliant`, `attested` |

The built-in policy has two device rules. Settings switch them on and off,
so no policy edit is needed:

* **A compromised device is refused**, for every application. This is on by
  default in both modes (`devices.refuseCompromised`), and the refusal is
  `STS-DEVICE-0038`. A compromise ends the device's sessions and revokes its
  certificates and secret, but its JWK and WebAuthn keys still identify it.
  A token request bound to one of them is exactly what this rule refuses.
  With the setting off, a compromised device is only a risk signal.
* **A realm can require a compliant registered device**
  (`devices.requireCompliantDevice`). This is **off by default in both
  modes.** While it is on, anything not from the subject's own compliant,
  uncompromised device is refused (`STS-DEVICE-0037`). An application's
  device counts too, such as a kiosk or a managed host.
  * With `devices.compliantDeviceAttested` on, the device must also be
    attested.
  * The console and the portal are exempt, because the portal is where a
    person registers a device. The template's `deviceExempt` parameter
    names the exempt applications.
  * A door that carries no device evidence is refused while the rule is on,
    for example a Kerberos ticket, or a password grant without DPoP.

The client is told only that authentication failed, or that a compliant
registered device is required. The rule and the device are on the audit row.

Somebody else's device is only a fact: `device-owner-matches` is false. The
built-in policy refuses nothing for that alone. A person may sign in on a
shared machine, or on a kiosk an application owns. A realm that wants to
refuse it writes that rule.

## Tokens and the acr

**`device_id`** is a private claim in the ID Token and the access token (JWT
and introspection). It is present when a registered device was recognised
and that device is the token subject's own:

* **Whose device:** a person's own, or an application's own device on a
  `client_credentials` token.
* **Which device:** the one the token request proved (a DPoP key, a client
  certificate or a Native SSO secret). If the request proved none, it is the
  device the session's sign-in recognised.
* **Its value** follows the client's subject type:

  | Client subject type | `device_id` |
  |---|---|
  | public | the register's id, the same `sub` SSF names the device by |
  | pairwise | derived for the client's sector, so two clients cannot join their records on it |
  | ephemeral | none, because a stable device id would link one authentication to the next |

* **`claims_supported` lists it.** UserInfo does not return it: it describes
  the authentication, not the person, just as `acr`, `amr` and `sid` do.

Where the device's key is also the token's binding key, the existing `cnf`
already names it:

* a DPoP `jkt` is the device JWK's RFC 7638 thumbprint;
* a certificate is its `x5t#S256`.

No second confirmation is added.

**`urn:sts:acr:compliant-device`** is published in `acr_values_supported`,
after `0`, `1` and `mfa`.

* **What meets it:** an authentication from the person's own registered
  device, compliant and not compromised. With `devices.compliantDeviceAttested`
  on, the device must also be attested.
* **Where it sits:** it describes where the authentication came from, not
  how many factors it had. It neither meets nor is met by `mfa`.
* **A session without such a device:** a request for it is sent to sign in
  once more, and then refused with `unmet_authentication_requirements`
  (RFC 9470).
* **A session that meets it:** its tokens carry it as their `acr`.

## Development and product mode

Registration and recognition behave the same in both modes, with one
difference: **product refuses a key a device or its owner presents without
an attestation that verified and chained to a trusted root** (a portal key
proof, a linked WebAuthn credential, an EST or SCEP device certificate);
development registers it as self-asserted. An administrator's key entered by
value is accepted in both, recorded as self-asserted. **The compliance test
control is open in development only**; product refuses it
(`STS-DEVICE-0035`), and the MDM feed under `device:compliance` is the door.

### Attestation trust

| Statement | Trusted roots |
|---|---|
| Android Key Attestation | `devices.androidAttestationTrustAnchors`, or Google's published hardware attestation roots, shipped with the service and pinned by SHA-256 |
| Apple App Attest | `devices.appleAppAttestTrustAnchors`, or the Apple App Attestation Root CA, shipped and pinned |
| TPM key attestation | `devices.tpmTrustAnchors` — nothing shipped |
| WebAuthn | the FIDO Metadata Service import and `webauthn.attestationTrustAnchors` |

A statement that does not verify is refused; one that verifies and chains to
none of these is self-asserted. **Protocols → Device registration** lists the
shipped roots by subject and fingerprint.

### Google's Android attestation status list

A chain can reach Google's roots and still contain a certificate that Google
has **revoked or suspended**, for example a leaked batch key. Google publishes
these certificates by serial number at
`https://android.googleapis.com/attestation/status` (#256). Every certificate
of an Android chain is looked up in that list. This happens both when a device
registers and when a WebAuthn `android-key` statement arrives at sign-in:

- **Revoked or suspended:** the device key is *self-asserted* (product refuses
  it, `STS-DEVICE-0047`) and the WebAuthn statement is *untrusted*
  (`STS-AUTHN-0297`).
- **Not on the list:** the key is attested as before, and its summary names the
  list version that was checked.
- **No current list** (never downloaded, the download failing, or older than
  `devices.androidStatusStaleHours`): the key is still attested, with its
  revocation **unchecked** and the reason. When
  `devices.androidRevocationRequired` is on in product mode, an unchecked chain
  counts as unattested instead (`STS-DEVICE-0048`).

The list is the risk dataset `android.attestation-status`, shown on
**Monitoring → Risk**. The `devices.android-status-refresh` scheduler job
downloads it daily from `devices.androidStatusUrl`, which is Google's address by
default. The list can also be uploaded there by hand. Each key keeps its
chain's serial numbers, so whenever a new list is activated, and daily, the
`devices.android-status-recheck` job looks them up again:

- A device key the new list revokes is **downgraded to self-asserted**. The
  device's level is recomputed, an audit row is written, and a CAEP
  `credential-change` (`update`) is sent. The device's *status* is not
  changed: the attestation no longer proves where the key lives, which is not
  the same as the device being compromised.
- A security key's attestation is marked untrusted in the same way. The key
  still signs its person in.
- A key registered before this check was added has no serial numbers stored,
  so it cannot be rechecked. Its page says *revocation unknown*.

**Protocols → Device registration** shows the active list, its age, the
address and the job (`GET /admin-api/device-registration`, `androidStatus`).

## Configuration

Drawn on **Protocols → Device registration**; the live source is that page and
`GET /admin-api/config`.

| Setting | Environment | Default | Runtime | What it does |
|---|---|---|---|---|
| `devices.maxPerPerson` | `STS_DEVICES_MAX_PER_PERSON` | `20` | yes | Devices one person owns. A Native SSO sign-in at the bound replaces the least recently used device whose session has ended; an administrator's registration is refused. It was `oauth2.maxDevicesPerPerson`. |
| `devices.maxPerApplication` | `STS_DEVICES_MAX_PER_APPLICATION` | `1000` | yes | Devices one application owns; a registration at the bound is refused. |
| `devices.maxKeysPerDevice` | `STS_DEVICES_MAX_KEYS_PER_DEVICE` | `10` | yes | Keys one device holds. |
| `devices.eventsKept` | `STS_DEVICES_EVENTS_KEPT` | `5000` | yes | Registrations, removals, evictions and compliance changes kept for **Monitoring → Devices**. |
| `devices.complianceFeedMaxReports` | `STS_DEVICES_COMPLIANCE_FEED_MAX_REPORTS` | `500` | yes | The most reports one `POST /admin-api/device-compliance` may carry. |
| `devices.challengeTtlSeconds` | `STS_DEVICES_CHALLENGE_TTL_SECONDS` | `300` | yes | How long an enrolment challenge may be answered. |
| `devices.maxChallenges` | `STS_DEVICES_MAX_CHALLENGES` | `10000` | yes | Unanswered enrolment challenges held per realm. |
| `devices.androidAttestationTrustAnchors` | `STS_DEVICES_ANDROID_ATTESTATION_TRUST_ANCHORS` | *(empty: Google's)* | yes | Android Key Attestation roots, replacing the shipped ones. |
| `devices.androidMinimumSecurityLevel` | `STS_DEVICES_ANDROID_MINIMUM_SECURITY_LEVEL` | `trusted-environment` | yes | `trusted-environment` or `strongbox`. |
| `devices.androidStatusUrl` | `STS_DEVICES_ANDROID_STATUS_URL` | Google's status list | yes | Where `devices.android-status-refresh` downloads the status list from; empty dials nobody. |
| `devices.androidStatusRefreshS` | `STS_DEVICES_ANDROID_STATUS_REFRESH_S` | `86400` | yes | How often it is downloaded. |
| `devices.androidStatusMaxBytes` | `STS_DEVICES_ANDROID_STATUS_MAX_BYTES` | `16777216` | yes | The most read of one download. |
| `devices.androidStatusStaleHours` | `STS_DEVICES_ANDROID_STATUS_STALE_HOURS` | `48` | yes | After this long the active list is stale and chains are unchecked. |
| `devices.androidRevocationRequired` | `STS_DEVICES_ANDROID_REVOCATION_REQUIRED` | `false` | yes | In product mode, an unchecked chain is not attested. |
| `devices.appleAppAttestTrustAnchors` | `STS_DEVICES_APPLE_APP_ATTEST_TRUST_ANCHORS` | *(empty: Apple's)* | yes | App Attest roots, replacing the shipped one. |
| `devices.appleAppAttestAppIds` | `STS_DEVICES_APPLE_APP_ATTEST_APP_IDS` | *(empty)* | yes | `TEAMID.bundle.id` of the apps whose keys are registered; empty accepts none. |
| `devices.appleAppAttestAllowDevelopment` | `STS_DEVICES_APPLE_APP_ATTEST_ALLOW_DEVELOPMENT` | `false` | yes | Accept App Attest's development environment. |
| `devices.tpmTrustAnchors` | `STS_DEVICES_TPM_TRUST_ANCHORS` | *(empty)* | yes | TPM manufacturer or AK CA roots. |
| `devices.lastUsedResolutionSeconds` | `STS_DEVICES_LAST_USED_RESOLUTION_SECONDS` | `60` | yes | How often a recognised device's last use is written. |
| `devices.expectRegistered` | `STS_DEVICES_EXPECT_REGISTERED` | `false` | yes | Makes `unregistered-device` fire for anybody, not only people who registered a device. |
| `devices.refuseCompromised` | `STS_DEVICES_REFUSE_COMPROMISED` | `true` | yes | Refuses anything asked for from a compromised device. |
| `devices.browserDevices` | `STS_DEVICES_BROWSER_DEVICES` | `true` | yes | Offers "Remember this browser" and reads the cookie. Off: no browser is remembered and a cookie already issued is not read. |
| `devices.browserTokenLifetimeDays` | `STS_DEVICES_BROWSER_TOKEN_LIFETIME_DAYS` | `180` | yes | How long a remembered browser may go unused before it is forgotten (1–400). |
| `devices.browserReissueGraceSeconds` | `STS_DEVICES_BROWSER_REISSUE_GRACE_SECONDS` | `60` | yes | How long the previous token is still accepted after a reissue (two tabs); older is a copied cookie. |
| `devices.browserTokenCertificateHeader` | `STS_DEVICES_BROWSER_TOKEN_CERTIFICATE_HEADER` | `x5u` | yes | The certificate header on the signed token. `x5c` and `both` make it too large for a cookie. |
| `devices.requireCompliantDevice` | `STS_DEVICES_REQUIRE_COMPLIANT_DEVICE` | `false` | yes | Requires the subject's own compliant registered device. The console and the portal are exempt. |
| `devices.compliantDeviceAttested` | `STS_DEVICES_COMPLIANT_DEVICE_ATTESTED` | `false` | yes | A compliant device must also be attested, both for the rule above and for the acr. |

## In the running service

* **Directory → Devices** (`/admin/devices`, `GET /admin-api/devices`): the
  register, paged and filtered, with a page per device.
* **Directory → As the directory holds it → Device entries**
  (`/admin/ldap/devices`, `GET /admin-api/ldap/devices`): the entries attribute
  by attribute, and the schema.
* **Protocols → Device registration** (`/admin/device-registration`,
  `GET /admin-api/device-registration`).
* **Monitoring → Devices** (`/admin/devices/monitor`,
  `GET /admin-api/devices/monitor`): counts by owner kind, compliance,
  attestation, key kind, attestation format and risk level, registrations,
  removals, evictions and compliance changes by source day by day, and —
  counted by the node serving the page —
  recognitions by kind, enrolments by method and attestation outcomes.

Every operation is in the OpenAPI document at `GET /admin-api/openapi.json`.

## Related

[LDAP schema](ldap-schema.md) · [OAuth 2.0 and OpenID Connect](oauth-oidc.md) ·
[Shared Signals](shared-signals.md) · [CAEP events](caep-events.md) ·
[Risk scoring](risk-scoring.md) · [XACML](xacml.md) ·
[Management API](management-api.md) · [Configuration](configuration.md)
