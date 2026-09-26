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

The register is being built in phases (issue #164): the register,
recognition, compliance and the MDM feed, and Shared Signals are built; risk
scoring and policy follow. This page says what is built today; the console's **Protocols → Device registration** page says the
same, from the running build, and is the one to trust.

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

## How a device is registered

| Method | Built | What happens |
|---|---|---|
| Native SSO | yes | The first app's authorization-code grant with `device_sso` makes the device ([OAuth 2.0 and OpenID Connect](oauth-oidc.md)). |
| An administrator | yes | **Directory → Devices** (`/admin/devices`) or `POST /admin-api/devices/create`, owned by a person or an application, with keys typed by value. A key added this way is recorded as proven by nobody and self-asserted. |
| The owner, on the portal | yes | `/portal/devices`: proving a key (below), or linking a WebAuthn platform credential enrolled on `/portal/keys` with a fresh assertion. |
| EST and SCEP | yes | A certificate from the `device` profile, issued to the device entry. |

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
that chain ends at `devices.tpmTrustAnchors`. A device renews by enrolling
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

The recognised device is recorded on the sign-in and on the token issuance,
for the phases that act on it; a compromised device is still recognised.
**Monitoring → Devices** counts recognitions by kind.

## Compliance

A device's compliance is set through four doors. Each change records the
previous value, when, the **source** and who acted; **Monitoring → Devices**
counts changes by source, day by day.

| Door | Source | Who may use it |
|---|---|---|
| An administrator: the **Compliance** form on a device's page, or `POST /admin-api/devices/set-compliance` | `admin` | Admin Write. May also set `unknown`, withdrawing a vouch. |
| An MDM or posture feed: `POST /admin-api/device-compliance` | `mdm` | A client holding an access token with the **`device:compliance`** scope, and nothing else. |
| The test control: `POST /devices/test/compliance` | `test-control` | Anybody, **in development only**; product answers `403`. |
| A received CAEP `device-compliance-change` from a trusted transmitter | `caep` | **Not built yet: it arrives with #153**, the Shared Signals receiver. |

### Integrating an MDM or posture feed

1. **Register the feed as an application** in the realm
   (`/admin/applications/new`, or `POST /admin-api/applications/add`) with a
   client secret (or a certificate or key for `private_key_jwt`), and declare
   `device:compliance` in its **allowed scopes** (`oauthAllowedScope`).
   `device:compliance` is a **protected scope**: the token endpoint issues it
   only to a client that declares it, in both modes, and `/admin-api` asks
   again on every call, so removing it from the application stops the tokens
   the feed already holds.
2. **Get a token** with the client credentials grant:
   `POST /oauth2/token` with `grant_type=client_credentials`,
   `scope=device:compliance` and `resource=<base>/admin-api` (the resource
   indicator puts the management API in the token's `aud`; without it every
   call is refused `401`).
3. **Report**: `POST /admin-api/device-compliance` with
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
* raises its risk level to `HIGH`;
* sends RISC `credential-compromise` and `sessions-revoked` for a person's
  device (below).

The device stays in the register, recognised and marked compromised.
**Restoring it** puts back the risk level the compromise raised; nothing
revoked comes back — a certificate is re-issued, and a secret is minted at the
next Native SSO sign-in.

**Removing a device** ends the sessions it authenticated and revokes its
certificates with reason **cessationOfOperation** (keyCompromise when it was
compromised), and sends RISC `sessions-revoked` for a person's device.

## What goes out over Shared Signals

Each event is sent to every stream that asked for its type and covers its
subject, when `caep.autoEmitTypes` or `risc.autoEmitTypes` names it (all of
them do by default).

| Event | When |
|---|---|
| CAEP `device-compliance-change` | a device's compliance changes in a way a receiver can be told (below) |
| CAEP `risk-level-change`, `principal` `DEVICE` | a device's risk level changes — risk scoring, or a compromise (`HIGH`) |
| CAEP `credential-change` | a device key is added (`create`), re-issued over EST (`update`) or removed (`delete`); a Native SSO secret is issued (`create`) or revoked (`revoke`); a device is removed (`delete`, per credential) |
| CAEP `session-established`, `session-presented`, `session-revoked` | as for every session — and the subject names the **device** when a registered device authenticated the session |
| RISC `credential-compromise` | a person's device is marked compromised: one per kind of credential it held |
| RISC `sessions-revoked` | a person's device is marked compromised or removed |

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
does send one. `sessions-revoked` is sent as well, with the device beside the
person in the subject, meaning *every session of this account on this
device*. Remove it from `risc.autoEmitTypes` to send only the CAEP events.

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
| `devices.appleAppAttestTrustAnchors` | `STS_DEVICES_APPLE_APP_ATTEST_TRUST_ANCHORS` | *(empty: Apple's)* | yes | App Attest roots, replacing the shipped one. |
| `devices.appleAppAttestAppIds` | `STS_DEVICES_APPLE_APP_ATTEST_APP_IDS` | *(empty)* | yes | `TEAMID.bundle.id` of the apps whose keys are registered; empty accepts none. |
| `devices.appleAppAttestAllowDevelopment` | `STS_DEVICES_APPLE_APP_ATTEST_ALLOW_DEVELOPMENT` | `false` | yes | Accept App Attest's development environment. |
| `devices.tpmTrustAnchors` | `STS_DEVICES_TPM_TRUST_ANCHORS` | *(empty)* | yes | TPM manufacturer or AK CA roots. |
| `devices.lastUsedResolutionSeconds` | `STS_DEVICES_LAST_USED_RESOLUTION_SECONDS` | `60` | yes | How often a recognised device's last use is written. |

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
[Management API](management-api.md) · [Configuration](configuration.md)
