---
title: "Passkeys and WebAuthn"
---

# Passkeys and WebAuthn

This page is the guide to passkeys in iya-sts: what a passkey can be used for
here, how to set up each use, what the person sees, and how to check that it
worked. iya-sts is a [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
relying party. It accepts passkeys stored on a device, in a password manager,
on a phone, or on a hardware security key (FIDO CTAP2).

Each recipe gives the **admin console** steps, the **Management API** calls,
or both. The longer explanations of *why* the service behaves as it does are
on [Authentication](authentication.md#webauthn), and this page links to them
rather than repeating them. Every setting in full is in
[Configuration → WebAuthn](configuration.md#webauthn).

* TOC
{:toc}

## Before you start

### Words used on this page

| Word | Meaning here |
|---|---|
| **passkey** | Any WebAuthn credential, wherever it is kept. The service and its pages use *passkey* for every kind. |
| **security key** | A passkey on a separate hardware device, reached over USB, NFC or Bluetooth (a *cross-platform* authenticator). |
| **platform authenticator** | The authenticator built into the device: Touch ID, Windows Hello, an Android screen lock. |
| **synced** / **device-bound** | A synced passkey is copied by its provider to the person's other devices. A device-bound one never leaves the authenticator that made it. The authenticator reports which with the *backup eligible* (BE) flag. |
| **use** | How a passkey answers a sign-in: **first factor** (passwordless, no password read) or **second factor** (a step after a password). A passkey has no fixed purpose: the person is asked nothing about it when they create it, and every passkey they hold may be used either way, as the realm allows. Until [#1135](https://github.com/rcbj/iya-sts/issues/1135) each passkey had a *role* chosen at its creation. |
| **usernameless** | Signing in with a passkey and no username typed. The passkey tells the service who the person is. This needs a *discoverable* (resident) credential. |
| **RP ID** | The domain a passkey is bound to. By default it is the host the service was reached on. |
| **user handle** | The random identifier a passkey is created under (64 bytes on the person's entry). It is never the username. |
| **attestation** | A statement from the authenticator, at registration, about what model it is (its **AAGUID**) and who made it. |
| **lane** | `classical` or `pqc`. A person has two lanes only where [a classical and a post-quantum passkey side by side](#a-classical-and-a-post-quantum-passkey-side-by-side) is on for them; otherwise every passkey is in the one (`classical`) lane, whatever its algorithm. |
| **classical** / **post-quantum** | A passkey's kind, from its signature algorithm alone: an **ML-DSA passkey** (ML-DSA-44, -65 or -87) is post-quantum, any other is classical. The lane does not decide it. |
| **post-login activity** | Something a realm asks a person to do after they sign in, before they return to the application: today, registering an ML-DSA passkey. See [Post-login activities](#post-login-activities-moving-people-to-post-quantum-passkeys). |

### Where things are

| What | Console | API |
|---|---|---|
| Every `webauthn.*` setting | **Protocols → WebAuthn** (`/admin/webauthn`), **Settings** tab | `GET /admin-api/webauthn`; change one with `POST /admin-api/config/set` |
| What a registration requests right now: the algorithms in order, and why each other one is not offered | **Protocols → WebAuthn**, **Metadata** tab | `GET /admin-api/webauthn` (`status.algorithms`, `status.algorithmsSource`) |
| The passkey policy | **Directory → Policies** (`/admin/policies`), **Passkey policy** tab, with the sub-tabs **Default**, **Named policies** and **New policy** | `GET /admin-api/policies` (the `passkey` member); `POST /admin-api/policies/save-passkey-policy` and `reset-passkey-policy` |
| The authentication policy (which sign-in methods are accepted, and whether a second factor is required) | **Directory → Policies**, **Authentication policy** tab | `GET /admin-api/policies` (the `authn` member); `POST /admin-api/policies/save-authn-policy` and `reset-authn-policy` |
| A person's passkeys | **Directory → Users** (`/admin/users`), the person's page, **Passkeys (WebAuthn)** | `GET /admin-api/users?user=<username>`; `POST /admin-api/users/{action}` |
| Who holds which factor, across the realm | **Directory → Users** | `GET /admin-api/mfa` |
| Who holds which passkey algorithm, across the realm | **Monitoring → Passkeys** (`/admin/passkey-report`) | `GET /admin-api/passkey-report`, `/export`, `POST /admin-api/passkey-report/recount` |
| The post-login activity policy (who is asked to register an ML-DSA passkey after signing in) | **Directory → Policies**, **Post-login activity policy** tab | `GET /admin-api/policies` (the `postLogin` member); `POST /admin-api/policies/save-postLogin-policy` and `reset-postLogin-policy` |
| Mail reminders to sign in and register one | **Directory → Post-login activities** (`/admin/post-login-activities`) | `GET /admin-api/post-login-activities`; `POST /admin-api/post-login-activities/{start,pause,resume,end}` |
| The move over time, ceremonies by client, each person's progress | the reports application, `/report`: the sources `passkeyHistory`, `passkeyCeremonies` and `postLoginProgress` | the [report API](reporting.md), `/report-api` |
| A passkey's long-term attestation evidence | **Directory → Users**, the person's page, **Passkeys (WebAuthn)** | `GET /admin-api/passkey-report/evidence?username=<name>&credentialId=<id>` |
| A new person with an activation link | **Directory → Users → New user** (`/admin/users/new`) | `POST /admin-api/users/create` |
| Which methods one application accepts | **Directory → Applications**, the application's **Configuration** tab | `POST /admin-api/applications/add`, `/remove`, `/update-fields` |
| Live sessions, and the record of what happened | **Monitoring → Sessions**, **Monitoring → Audit log** (`/admin/audit`) | `GET /admin-api/sessions`, `GET /admin-api/audit?code=<error code>` |
| The person's own passkeys | the user portal's **Passkeys** page, `/portal/keys` | the [Account API](account-api.md): `GET` and `POST /account-api/keys` |
| Signing in | `/authn/login`, then `/authn/webauthn` or `/authn/mfa-setup` | the [sign-in API](authn-api.md), `/authn-api` |

**A token and the `api` helper.** The API examples below use the variables
and the `api` shell function set up in
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start).
The token needs the `admin:write` scope.

**Everything is per [trust realm](trust-realms.md).** The settings, the
passkey policy, the authentication policy and the people all belong to a
realm. A console page saves to the realm it is shown in. For the API, use
`$BASE/realm/<id>/admin-api/...`. A person in a realm uses
`/realm/<id>/portal/keys` and signs in at `/realm/<id>/authn/login`. See
[Realms](#realms) below.

**A save of a policy replaces the whole profile.** When you call
`save-passkey-policy` or `save-authn-policy`, send every field. Read the
current values from `GET /admin-api/policies`: each kind has a `fields` list,
and each field has its `key`, its current `value` and its `default`. The
console form does this for you.

## How a passkey is used

**A passkey is registered, and nothing else is asked.** The person does not
choose whether it replaces their password or follows it. Whether a passkey
is used on its own (passwordless), as the second factor after a password,
both or neither is decided **at the sign-in**, in layers, for every passkey
alike:

1. **The realm.** Its [authentication policy](authentication.md#the-authentication-policy)
   chooses which first-factor and second-factor mechanisms the realm
   supports: its `passkey` row as a first factor (`passkeyPrimary`) and its
   `securityKey` row as a second factor (`securityKeySecondFactor`), together
   with `webauthn.primaryAllowed` and `webauthn.mfaAllowed`. A use the realm
   does not accept is refused (`STS-AUTHN-0045`, `0253` as a first factor;
   `0046`, `0254` as a second). Where it accepts neither, no new passkey can
   be registered (`STS-AUTHN-0531`), because it could never be used.
2. **The application**, where it overrides the realm, and only at a browser
   sign-in to it. Its `appAuthnMechanism` lists the first-factor mechanisms
   its people may sign in with (`webauthn` among them); the issuance
   policy's `authn-mechanism` rule enforces it and re-prompts a session that
   used another. Its `appMfaMechanism` lists the second factors it allows
   (`securityKey` among them); it narrows the second step to another factor
   the person holds, or has them prove one and set up an allowed one, or
   refuses. It only narrows: what the realm switched off stays off. See
   [Sign-in mechanisms](applications.md#sign-in-mechanisms-how-its-people-may-sign-in)
   and [Second factors](applications.md#second-factors-which-ones-its-people-may-use).
3. **The passkey itself has no say.** A registered passkey is used wherever
   those layers accept a passkey: passwordless, as the second factor, or
   both. (Until [#1135](https://github.com/rcbj/iya-sts/issues/1135) each
   passkey had a role chosen at its registration, and answered only that
   step.)

With the defaults (every row on, no application list) a passkey answers both
steps.

How the person signed in is what the session records:

| How the person signed in | `amr` | `acr` |
|---|---|---|
| a password, then a passkey | `["pwd","hwk"]` | `mfa` |
| a passkey, with the username typed and no password | `["hwk"]` | `1` (one factor) |
| a passkey with no username (usernameless) | `["hwk","user"]` | `mfa` |
| a password alone | `["pwd"]` | `1` |

A passkey with the username typed counts as **one factor**, even when the
authenticator checked a PIN or a fingerprint. The usernameless sign-in always
requires that check (user verification), so it records two.
[Authentication → WebAuthn](authentication.md#webauthn) explains why.

A relying party can also ask for a *phishing-resistant* sign-in with the
OpenID Connect `acr` values `phr` and `phrh`. A passkey earns `phr`. A passkey
with a trusted attestation that is not synced also earns `phrh`. See
[Phishing-resistant sign-in](oauth-security.md#phishing-resistant-sign-in-phr-phrh).

Every registration and every sign-in is verified **in both development and
product mode**: the challenge, the origin, the RP ID, the user-presence and
user-verification flags, the signature, and the signature counter. What
development mode relaxes is the password in front of a passkey, and (by
default) the check of the attestation statement. See
[Development and product mode](#development-and-product-mode).

## Recipes

### A passkey as a second factor after a password

**Settings.** Nothing to change: this is on by default. It needs
`webauthn.enabled` and `webauthn.mfaAllowed` on (both default `true`), and the
authentication policy's **Passkey (second factor) — as a second factor**
row on (`securityKeySecondFactor`, default on).

**What the person does.** Either of these:

1. **On the portal.** Sign in, open `/portal/keys`, and under **Add a
   passkey** press **Create a passkey** (a passkey on this device or a
   phone) or **Use a security key**. Nothing else is asked. The browser asks
   them to create the passkey. The new passkey then appears on its row under a default name,
   and its row's **Rename** gives it a nickname.
2. **At the sign-in screen.** Type the username and password and tick **Use a
   passkey as a second step (WebAuthn)**. If the person holds no second factor
   yet, this step registers a passkey. If they already hold any second factor,
   the screen does not register a new one here. (Otherwise anybody who knew
   the password could add their own authenticator.)

**From then on**, where the realm (and the application, if it overrides the
realm) accepts a passkey as a second factor, the person is asked for the
passkey at every sign-in after the password. Where the realm accepts a passkey
as a second factor, **holding any passkey is holding a second factor**, so in
product mode the doors that can only take a password (an LDAP simple bind, a WS-Security UsernameToken, HTTP Basic at
SCIM, Shared Signals and EST, and the Kerberos KDC) refuse a bare password to
that person. Those doors are not browser sign-ins to an application, so only
the realm's layer applies there. See
[the password-only doors](what-is-not-checked.md#app-passwords-at-the-password-only-doors). They do not have to tick anything. What a person holds decides
the second factor, not a checkbox. See
[Which second factor is asked for](authentication.md#which-second-factor-is-asked-for).

**Check it.**
* On the person's page under **Directory → Users**, the **Passkeys (WebAuthn)**
  table lists the passkey with its algorithm and backup state.
* After a sign-in, **Monitoring → Sessions** shows the session, and the audit
  log's `session.start` row records `amr` `pwd, hwk`, `acr` `mfa`, and the
  passkey's algorithm (`credentialAlgorithm`).

### Signing in with a passkey instead of a password

**Settings.** On by default. It needs `webauthn.primaryAllowed` on (default
`true`) and the authentication policy's **Passkey (passwordless) — as a first
factor** row on (`passkeyPrimary`, default on).

**What the person does.**
1. On `/portal/keys`, press **Create a passkey** or **Use a security key**.
   It is the same passkey as in the recipe above: any passkey the person
   holds signs them in here, and the same passkey still answers the step
   after a password.
2. At the sign-in screen, they can either:
   * press **Sign in with a passkey** with no username typed (see the next
     recipe), or
   * type the username and tick **Sign in with a passkey instead of a
     password**. The password field is then not read.

**Product mode never registers a passkey at the sign-in screen's passwordless box.**
A person who ticks the passwordless box and holds no passkey is
refused (`STS-AUTHN-0206`). In development mode the screen registers one on
the spot, so the first person to claim a username gets it. In product mode a
person with no password registers their passkey on `/portal/keys` or through an
[activation link](#a-passwordless-account-from-the-start).

With `webauthn.primaryAllowed` (or the `passkeyPrimary` row) off, no passkey
signs anybody in on its own, including a passkey registered while it was on:
the person signs in with a password and the passkey is asked for next. A
person with no password then cannot sign in with their passkey, so turn it
off only where everybody has another way in.

### Signing in with no username

**Settings.** On by default: the passkey policy's `allowUsernameless` row
(Directory → Policies → Passkey policy). It also needs `webauthn.enabled`,
`webauthn.primaryAllowed` and the `passkeyPrimary` row of the authentication
policy.

**What the person sees.** The sign-in screen shows **Sign in with a passkey**.
In browsers that support it, the username field also offers the person's
passkeys as autofill. The browser asks for any passkey this service holds for
the person, and the passkey's user handle names the account.

* **User verification is always required here** (a PIN or a biometric),
  whatever `webauthn.userVerification` says. The session records
  `amr ["hwk","user"]` and `acr "mfa"`.
* **Any passkey the person holds answers**, while the realm lets a passkey
  be a first factor. (Until #1135 only a passkey registered "instead of my
  password" did.)
* **Passkeys must be discoverable.** *Create a passkey* always asks the
  authenticator to store a discoverable credential. *Use a security key* does
  too, unless the passkey policy's `securityKeyResidentKey` lowers it while
  usernameless sign-in is on. A security key registered that way may need the
  username.
* **A passkey created before user handles existed** was created under the
  username. It still works where the username is typed. Register it again to
  use it with no username.

**Making it the only way in for one application** (the passkey policy's
`requireUsernameless`). Set the application's `appAuthnMechanism` to
`webauthn` and nothing else
([Sign-in mechanisms](applications.md#sign-in-mechanisms-how-its-people-may-sign-in)),
and turn `requireUsernameless` on. That application's sign-in screen then has
no username field. A sign-in that names a person anyway is refused
(`STS-AUTHN-0333`). The `default` profile never applies this to the admin
console, the user portal or the embedded debugger. To apply it to one of them,
create a [named passkey policy](#different-rules-for-different-applications-or-groups)
that selects it. The details are in
[the passkey policy](authentication.md#the-passkey-policy), under
*Requiring it*.

### A passwordless account from the start

By default an administrator does not enrol a passkey for somebody. The
passkey policy's `adminEnrolment` is off, and the ceremony runs in the
person's own browser against their own authenticator. What the
administrator gives them is a single-use **activation link**. When
`adminEnrolment` is on, an administrator with **Admin Write** can enrol
one in their own browser; that is
[below](#an-administrator-enrols-a-passkey).

**Console (a new person).**
1. **Directory → Users → New user** (`/admin/users/new`). Fill in the
   username and any attributes.
2. Under the credential choice, pick **No credential, and an activation
   link**. Tick the mail box to mail it to the address on the entry, or leave
   it unticked to be shown the link **once**.
3. Create the person, and send them the link.

**API.**
```bash
# A new person, with an activation link
api users/create '{"username":"dana","credential":"activation",
  "attributes":{"mail":"dana@example.com"}}'

# Somebody who already exists (no console button does this)
api users/issue-activation '{"user":"dana"}'

# Either one, mailed to the address on the entry instead of returned
api users/issue-activation '{"user":"dana","deliver":"mail"}'
```

The answer carries `activationUrl` (a path on the service) and `expiresAt`,
unless the link was mailed. The link lasts `security.activationTtlMinutes`
(1440, one day), is stored only as a hash, and issuing another one replaces
it.

**What the person does.** At `/portal/activate`:
1. Leave the two password boxes empty.
2. Under **2. A passkey**, choose to register a passkey.
3. Press **Continue**, then create the passkey on the next screen.

The account is not set up, and the link is not used up, until the passkey is
created. To have both a password and a passkey, they fill in the password
too and still choose to register a passkey; the page asks nothing about how
the passkey will be used. That passkey signs them in on its own and is the
step after their password, as the realm allows. (An older client that still
posts `key_role` `primary` or `mfa` is understood as "register a passkey",
and `none` as "do not".)

### An administrator enrols a passkey

The passkey policy's `adminEnrolment` is off by default
([#945](https://github.com/rcbj/iya-sts/issues/945)). Set it to `on` on the
profile that applies to the person (the default profile, or a
[named one](#different-rules-for-different-applications-or-groups)). An
administrator holding **Admin Write** then sees **Enrol** on the person's
page under **Directory → Users**, **Passkeys (WebAuthn)**, while WebAuthn
is on. The note on the button says to enrol only a key you know is theirs:
whoever holds it signs in as that person.

The ceremony runs in the administrator's browser, against an authenticator
they hold (a security key to hand over, for example), under the person's
user handle. The registration is verified exactly as the person's own is: attestation,
algorithms and that profile's registration rules. Nothing made elsewhere
can be imported. The key records which administrator enrolled it and when
(`enrolledBy`), the person is sent the security notice `passkey-enrolled`,
and the audit row is `admin.passkey.enrolled`.

While the row is off, **Enrol** is still on the page and the ceremony is
refused (`STS-AUTHN-0440`). A name nobody in this realm's directory holds
is refused in every mode (`STS-AUTHN-0441`). The caller's token must be a
person's, so the key can record who enrolled it (`STS-AUTHN-0445`). The
enrolment lasts five minutes and is single use (`STS-AUTHN-0442`).

**API.** `begin-passkey-enrolment`, then `finish-passkey-enrolment`, on
`POST /admin-api/users`. Begin takes `user` and, optionally, `lane`
(`classical` or `pqc`, where both lanes are on) and `kind` (`passkey` or
`security-key`). A `role` member, which the request carried until #1135, is
accepted and ignored. It answers
`enrolmentId` and `ceremony`. Finish takes `user`, `enrolmentId` and
`credential` (the browser's registration as JSON). The request bodies are
in `GET /admin-api/openapi.json`.

### Requiring a passkey

Several controls require a second factor or a passkey. They differ in **who**
they apply to:

| Who | How | Where it is explained |
|---|---|---|
| everybody in a realm must have a second factor | the authentication policy's `requireSecondFactor`: `always` | [Requiring a second factor of everybody](authentication.md#requiring-a-second-factor-of-everybody) |
| one person | **Require MFA for this person** on their page (`POST /admin-api/users/require-mfa`) | [Admin console](admin-console.md) |
| administrators | the authentication policy's `requireSecondFactorForAdministrators` | [Administrators](#administrators) below |
| the people of one application, which second factor | the application's `appMfaMechanism`: tick `securityKey` alone | [Second factors](applications.md#second-factors-which-ones-its-people-may-use) |
| the people of one application, which sign-in | the application's `appAuthnMechanism`: tick `webauthn` alone for a passkey with no password | [Sign-in mechanisms](applications.md#sign-in-mechanisms-how-its-people-may-sign-in) |
| one request | `acr_values=hwk` (a hardware key), or `phr` / `phrh` | [Which second factor is asked for](authentication.md#which-second-factor-is-asked-for), [Phishing-resistant sign-in](oauth-security.md#phishing-resistant-sign-in-phr-phrh) |
| everything an application is issued | the issuance policy's `requirePhishingResistant` or `requireHardwareProtected` option | [Phishing-resistant sign-in](oauth-security.md#phishing-resistant-sign-in-phr-phrh) |

**When a second factor is required and the person holds none**, the sign-in
screen sends them to `/authn/mfa-setup` after the password. It offers **Set up
an authenticator app** and **Set up a passkey**. No session starts until they
finish. A passwordless sign-in is refused for such a person
(`STS-AUTHN-0171`).

**To offer only passkeys as the second factor in a realm**, turn off the
authentication policy's TOTP row (**Authenticator app (TOTP) — as a second
factor**). The set-up step then offers only a passkey. **This does not take
an authenticator app away from somebody who already has one**: they go on
being asked for it. Remove it on their page (**Disable all MFA**, or `POST
/admin-api/users/clear-totp`), or narrow an application to `securityKey`
with `appMfaMechanism`
([Second factors](applications.md#second-factors-which-ones-its-people-may-use)).

**A request can demand a passkey.** An OpenID Connect client that sends
`acr_values=hwk` (or a WS-Federation `wauth` for a hardware token) gets a
sign-in in which only a passkey, alone or after a password, is accepted. A
one-time code or a recovery code is refused (`STS-AUTHN-0204`).

### Administrators

1. **Require a second factor of every administrator.** On the default realm's
   authentication policy, set **Second factor for administrators**
   (`requireSecondFactorForAdministrators`) to `always`. The default, `offer`,
   lets an administrator press **Ignore**. Every realm inherits the default
   realm's policy unless it saves its own. The built-in administrator
   (`admin.bootstrapUsername`) is only ever *offered* one, so the service is
   never left with nobody who can sign in. See
   [A second factor for administrators](authentication.md#a-second-factor-for-administrators).
2. **Hold administrators' passkeys to stricter rules.** Create a
   [named passkey policy](#different-rules-for-different-applications-or-groups)
   that selects the group your administrators are in, or the application
   `sts-admin-console`. In it, set for example **backupEligibility** to
   `disallow` (device-bound passkeys only) or **postQuantumRequired** to
   `sign-in`. Give it a low precedence number, such as `5`.
3. **Require a passkey, rather than any second factor, for the console.** On
   the application `sts-admin-console`, set `appMfaMechanism` to `securityKey`
   alone.

> **Warning.** Changes 2 and 3 can lock an administrator out of the console
> if they hold no passkey that meets them. Before you save, make sure each
> administrator has registered a suitable passkey, and keep a second
> administrator session open while you test.

### Device-bound passkeys only, or one kind of authenticator

**Device-bound only.** On the passkey policy, set **backupEligibility** to
`disallow`. A synced passkey is then **not registered**
(`STS-AUTHN-0312`) and **does not sign anybody in** (`STS-AUTHN-0313`). That
second rule also stops synced passkeys registered before you changed it, and
`/portal/keys` tells their owners. Most passkeys people already hold in a
phone or browser password manager are synced, which is why the default is
`allow`. See *Synced passkeys* under
[the passkey policy](authentication.md#the-passkey-policy).

**Only security keys, or only the device's own authenticator.** Set
`webauthn.authenticatorAttachment` to `cross-platform` or `platform` (default
`any`). **This is a filter in the browser, not a check by the service**: the
browser offers only matching authenticators, but the service does not refuse
a passkey whose attachment turned out to be the other kind. To *enforce* the
kind of authenticator, use attestation (next recipe).

**Which authenticator the browser leads with.** The passkey policy's
`passkeyHints`, `securityKeyHints` and `signInHints` rows send WebAuthn
*hints* (`client-device`, `hybrid` for a phone, `security-key`). They change
what the browser offers first. They are not enforced.

### Only approved authenticator models

To accept passkeys only from particular models, the service needs a
**trusted attestation**: a statement from the authenticator whose certificate
chains to a root the service trusts.

1. **Load the FIDO Metadata Service (MDS3) BLOB** on **Monitoring → Risk**, or
   point `risk.mdsUrl` at it. It gives the roots and the status of every
   certified model. See [The FIDO metadata](risk-scoring.md#the-fido-metadata).
   To check what it says about one model, for example before you put its
   AAGUID in `webauthn.attestationAllowedAaguids`, use **Look up an
   authenticator** on the same page
   ([Looking up an authenticator](risk-scoring.md#looking-up-an-authenticator)).
2. **Optionally add roots of your own** in `webauthn.attestationTrustAnchors`
   (a PEM bundle): a corporate CA, a vendor root or a test root.
3. **Choose what to require:**

| Setting | Default | Effect |
|---|---|---|
| `webauthn.attestationPolicy` | `by-mode` | `verify-if-present` verifies every statement and refuses one that fails. `require-trusted` also refuses a passkey whose statement does not chain to a trusted root, so it refuses every synced passkey (they send none). `by-mode` is `verify-if-present` in product mode and `off` in development. `off` (development only) verifies nothing. |
| `webauthn.attestationAllowedAaguids` | empty | Only these models (AAGUIDs, comma-separated). Requires a trusted attestation. |
| `webauthn.attestationMinCertificationLevel` | `none` | The lowest FIDO certification level (`L1` to `L3plus`). Requires a trusted attestation from a model MDS lists. |
| `webauthn.attestationRequireFips` | `false` | Only models MDS reports as FIPS 140 certified. Requires a trusted attestation. |

Models that MDS reports as revoked or compromised are refused at
registration in every case where the statement is verified.

4. **Hold existing passkeys to the rules too.** These settings apply at
   registration. To apply them at every sign-in, turn on the passkey policy's
   `enforceAttestationAtSignIn`. A passkey that no longer meets them is then
   refused (`STS-AUTHN-0316`), and if the metadata cannot be checked the
   sign-in is refused (`STS-AUTHN-0317`).

The passkey's recorded attestation is shown on `/portal/keys` and on the
person's console page. A statement nothing verified is shown as *claimed*.

**What the attestation was signed with.** Each registration also records the
algorithm of the attestation statement (for example `ML-DSA-65` or
`ES256`) and of every certificate in its chain, from the leaf to the trust
anchor. The person's console page shows it under the attestation, marked
post-quantum where every one of them is, and `GET /admin-api/users?user=`
returns it for each passkey as `attestationAlgorithms`:

| Field | What it holds |
|---|---|
| `recorded` | `false` for a passkey registered before this was recorded, or with no attestation |
| `verified`, `trusted` | whether the statement was verified, and whether it chains to a trusted root |
| `statement` | the statement's own signature algorithm; empty for `apple` and `none` |
| `certificates` | each certificate's signature algorithm, leaf first and the anchor last, with its family and whether it is post-quantum |
| `postQuantum` | `true` only when there is a certificate and every signature above is post-quantum (ML-DSA, SLH-DSA or composite ML-DSA) |

Under `webauthn.attestationPolicy` `off` the algorithms are what the
authenticator claimed, and `verified` says so. What the attestation is signed
with is recorded separately from the passkey's own algorithm: an ML-DSA
passkey may come with an attestation certificate signed with a classical
algorithm, and an ES256 passkey with an ML-DSA one. `attestationAlgorithms`
is about the attestation; `postQuantumRequired` is about the passkey. To require a post-quantum
attestation, see
[Requiring a post-quantum attestation](#requiring-a-post-quantum-attestation).

### RFC 4998 evidence for classical attestations

Optionally, set `webauthn.attestationEvidenceTsaUrl` to an HTTPS RFC 3161
timestamp service and `webauthn.attestationEvidenceTsaTrustAnchors` to its
PEM trust anchor(s) ([#947](https://github.com/rcbj/iya-sts/issues/947)).
For each newly registered classical attestation that this service verifies
and trusts, it timestamps the exact attestation bytes and the verified
assessment, then stores the RFC 4998 EvidenceRecord on that passkey. A missing
TSA configuration leaves evidence recording disabled. When enabled, a TSA
failure refuses registration rather than saving an unattested evidence record.

The daily passkey report recount renews timestamp chains before the timestamp
certificate approaches expiry. Set
`webauthn.attestationEvidenceHashAlgorithm` to `sha384` or `sha512` to migrate
records by RFC 4998 hash-tree renewal; the recount adds a new chain covering
the archived object and all previous chains. Admins can download a passkey's
evidence from its person page or
`GET /admin-api/passkey-report/evidence?username=<name>&credentialId=<id>`.
The export contains the RFC 4998 DER record, the archived object and the
timestamp tokens. Evidence is not backfilled for existing passkeys. The
default digest is SHA-256. The TSA URL and trust anchors are available under
**Protocols → WebAuthn** and in `GET /admin-api/webauthn`; the TSA URL must use
HTTPS, and its signing certificate must chain to the configured anchors and
have the critical `id-kp-timeStamping` purpose.

### Enterprise attestation

Enterprise attestation (WebAuthn Level 3 section 5.4.7) is an attestation
that may identify the individual authenticator, for example by its serial
number. A browser passes the request through only for an RP ID its own
policy allows, and an authenticator answers it only for an RP ID it was
provisioned for, so this service asks for it only where you list the RP ID.

1. List the RP IDs in `webauthn.attestationEnterpriseRpIds`, comma-separated
   (for example `sts.example.com`). These must be the RP IDs your browsers
   and authenticators are provisioned to release enterprise attestation for.
2. Set `webauthn.attestation` to `enterprise`. Both are on **Protocols →
   WebAuthn**; saving `enterprise` with the list empty is refused
   (`STS-AUTHN-0500`), and so is emptying the list while `enterprise` is
   chosen. Saving both in one form, or in one
   `POST /admin-api/config/set-many`, works.

A registration at a listed RP ID asks for `enterprise`. **At any other RP ID
it asks for `direct`**, and says so in two places: the passkey's attestation
record carries `conveyance: direct` and `enterpriseDowngraded: true`, and the
attestation part of the registration's `webauthn.ceremony` audit row
(the third part of its `authenticator` detail) begins `enterprise not
listed, asked direct`. A registration at a listed RP ID
records `conveyance: enterprise`.

**The device serial is read only from a statement an enterprise request
produced.** A serial number in the certificate of an ordinary `direct`
attestation is not recorded and binds nobody, so with
`enterpriseSerialAttribute` set, a security key registered at an unlisted RP
ID names no serial and is refused (`STS-AUTHN-0321`).

**Binding security keys to the people they were issued to.** With enterprise
attestation, the passkey policy's `enterpriseSerialAttribute` lets a security
key register only for the person whose entry lists its serial number
(`STS-AUTHN-0320`, `STS-AUTHN-0321`). It needs set-up outside this service.
See *Binding security keys to the people they were issued to* under
[the passkey policy](authentication.md#the-passkey-policy).

### Other passkey policy rows

The passkey policy has more rows than the recipes above use. Each is
described under [the passkey policy](authentication.md#the-passkey-policy):

| Row | What it is for |
|---|---|
| `enforcePinLength`, `minPinLength`, `pinLengthOnlyIfSupported` | A minimum security-key PIN length. Only security keys configured to report it to this service's RP ID can report one. |
| `userDisplayName`, `rpNameExtras`, `credentialLabel` | The names a passkey prompt and the passkey list show. `rpNameExtras` helps somebody with accounts in several realms tell them apart. |
| `aggregateDevices` | One **Use passkey** choice for all of a person's passkeys (the default), or a list to pick one from. |
| `recoveryAssurance` | Whether getting back in without the passkey restores access at once. See [Recovery](#losing-a-passkey-and-account-recovery). |
| `postQuantumRequired` | See [Requiring a post-quantum passkey](#requiring-a-post-quantum-passkey). |
| `attestationAlgorithms` | See [Requiring a post-quantum attestation](#requiring-a-post-quantum-attestation). |
| `postQuantumAllowCredentials` | While a post-quantum passkey is required: name only the post-quantum passkeys at sign-in, or name them all and refuse a classical one with a page saying why. See [Narrow, or list and refuse](#narrow-or-list-and-refuse). |
| `registrationAlgorithms`, `registrationMode` | Which algorithms a registration for this profile's people offers, and whether ML-DSA comes first, alone, or not at all. The console calls the first **Algorithms a passkey registration offers**. `realm`, the default, uses the list on **Protocols → WebAuthn**; a list here replaces that list for this profile's people only. The **Metadata** tab of **Protocols → WebAuthn** says when a profile's list is the one in force. |
| `lanes` | `realm` by default, following `webauthn.pqcAlongsideClassical`. `both` gives this profile's people [a classical and a post-quantum passkey side by side](#a-classical-and-a-post-quantum-passkey-side-by-side), `one` gives them one lane. |
| `clientRules` | Empty by default. The browsers and systems whose registrations offer no ML-DSA. See [Clients that cannot make an ML-DSA passkey](#clients-that-cannot-make-an-ml-dsa-passkey). |
| `adminEnrolment` | Off by default. On, an administrator may enrol a passkey for a person this profile applies to. See [An administrator enrols a passkey](#an-administrator-enrols-a-passkey). |
| `deviceBoundRequired` | Off by default. On, an issuance to an application this profile covers waits for a device-bound session. See [Sessions](sessions.md#binding-the-cookie-to-the-browser-device-bound-session-credentials). |

### Different rules for different applications or groups

Beside the `default` passkey policy, a realm can keep **named passkey
policies**. Each has every row above, plus three selectors: the applications
it applies to, the groups whose members it applies to, and a precedence from
1 to 1000. At a sign-in, the named policy that lists the application, or a
group the person is in, applies. Where several match, the **lowest
precedence number wins**. Where none matches, `default` applies.
Registration on `/portal/keys` has no application, so only group selectors
apply there.

**Console.** Directory → Policies → **Passkey policy** → **New policy**. Give
it a name, list the applications (the **Find** box searches the realm's
applications) and groups, set the precedence and the rows, and save. An
application's own page shows which passkey policies select it
([The passkey policy that applies to it](applications.md#the-passkey-policy-that-applies-to-it)).

**API.** Send the whole profile, with `profile` naming it:
```bash
api policies/save-passkey-policy '{"profile":"strict-admins",
  "selectApplications":"sts-admin-console","selectGroups":"","precedence":5,
  "allowUsernameless":true,"requireUsernameless":false,
  "securityKeyResidentKey":"required","backupEligibility":"disallow",
  "enforcePinLength":false,"minPinLength":4,"pinLengthOnlyIfSupported":false,
  "enforceAttestationAtSignIn":false,"passkeyHints":"client-device,hybrid",
  "securityKeyHints":"security-key","signInHints":"none",
  "enterpriseSerialAttribute":"","userDisplayName":"","rpNameExtras":"none",
  "credentialLabel":"","aggregateDevices":true,"postQuantumRequired":"off",
  "registrationAlgorithms":"realm","registrationMode":"realm",
  "adminEnrolment":"off","deviceBoundRequired":false}'

# Remove it
api policies/reset-passkey-policy '{"profile":"strict-admins"}'
```

Unlike `default`, a realm's named policies are not inherited from the default
realm.

### Several host names

A passkey is bound to its **RP ID**, which by default is the host the service
was reached on. A passkey registered at `sts.example.com` therefore does not
work at `login.example.com`.

To use one passkey across sibling hosts:
1. Set `webauthn.rpId` to the shared registrable domain, for example
   `example.com`. It may only *widen* the RP ID to a suffix of the host.
   Anything else is refused by the browser. In product mode the service also
   refuses the ceremony by name (`STS-AUTHN-0023`). Development mode falls
   back to the host and logs why.
2. Set `webauthn.allowedOrigins` to every origin the ceremony may come from,
   for example `https://sts.example.com,https://login.example.com`.
3. If those hosts are separate [listeners](listeners.md), set
   `authn.cookieDomain` to the same domain, so they share one sign-in.

Every host under the RP ID can then use these passkeys, so widen it only
deliberately.

## Algorithms: classical and post-quantum

`webauthn.algorithms` is the list of signature algorithms offered to the
authenticator, in order of preference. The authenticator takes the first one
it supports. The default offers every algorithm the service can verify, with
the post-quantum ones first, strongest first:

* **Post-quantum (RFC 9964):** `ML-DSA-87`, `ML-DSA-65`, `ML-DSA-44` (COSE
  -50, -49, -48), so an authenticator that can make every parameter set
  makes ML-DSA-87
  ([#1078](https://github.com/rcbj/iya-sts/issues/1078)).
* **Classical:** `ESP256`, `ES256`, `Ed25519`, `EdDSA`, `ESP384`, `ES384`,
  `ESP512`, `ES512`, `Ed448`, `ES256K`, `PS256`, `PS384`, `PS512`, `RS256`,
  `RS384`, `RS512`.

On **Protocols → WebAuthn**, the Settings tab gives each algorithm a checkbox
(offered or not) and a number (its place in the order). A passkey whose
algorithm was not offered is refused at registration (`STS-AUTHN-0228`).

* **Select all** is a switch above the list. Switching it on ticks every
  algorithm the two settings below allow: not `RS1` unless
  `webauthn.insecureAlgorithms` is on, and only ML-DSA while
  `webauthn.pqcOnly` is on. It reads those two as the form shows them, so a
  change you have not saved yet counts. Switching it off unticks every
  algorithm.
* **At least one must be ticked.** With none ticked, Save is disabled and the
  list says so. A save that sends an empty list anyway is refused
  (`STS-ADMIN-0840`).
* **The Metadata tab** lists what a registration actually requests: the
  offered algorithms first, numbered in the order they are sent, then the
  others, each with the reason it is not offered. When the selected passkey
  policy profile sets *Algorithms a passkey registration offers*, the profile's
  list replaces `webauthn.algorithms` for that profile's people, and the tab
  says so ([#1130](https://github.com/rcbj/iya-sts/issues/1130)).

Two more settings change the list:
* **`webauthn.pqcOnly`** (default `false`) offers only ML-DSA. A passkey made
  with anything else is then refused at registration. Passkeys already
  registered keep working.
* **`webauthn.insecureAlgorithms`** (default `false`, development mode only)
  also offers SHA-1's `RS1`. While it is off, a passkey made with `RS1` does
  not sign in (`STS-AUTHN-0294`). Product mode never uses it.

**What an authenticator must support.** The service offers the list and
verifies whatever comes back. It does not check the browser or the
authenticator beforehand, and it keeps no list of products. Nearly every
authenticator can make an `ES256` passkey; Windows Hello and some older TPMs
make `RS256`. **Few authenticators can make an ML-DSA passkey yet.** With the
default list, an authenticator that can make ML-DSA does so, and every other
one falls back to a classical algorithm, so nobody is shut out.

### When the device cannot make an ML-DSA passkey

Some platforms do not simply skip an algorithm their authenticator cannot do:
they fail the whole registration. Since
[#944](https://github.com/rcbj/iya-sts/issues/944) the passkey step at sign-in
and `/portal/keys` help the person when that happens.

**What the person sees.** When a registration that asked for ML-DSA fails with
the browser's `NotSupportedError`, the page shows, in the person's language:

* **where a classical passkey is allowed**: "Your device could not make a
  post-quantum (ML-DSA) passkey", and a **Try again with a classical
  passkey** button. The retry asks for the classical algorithms only (the
  configured list less ML-DSA). On `/portal/keys` it starts the same kind of
  passkey again.
* **where it is not**: "This service requires a post-quantum (ML-DSA)
  passkey, and this device could not make one. Use another device, or a
  security key that can." No retry is offered.

A failure the browser reports less precisely (`NotAllowedError`, which is
also what a cancelled prompt or a timeout gives, or `UnknownError`) shows the
same guidance worded with "if". Any other failure is reported as before. Where
the browser says, through `PublicKeyCredential.getClientCapabilities()`, that
it can make a passkey on a phone or another device nearby, the page adds a
line saying so. That call has no way to report which algorithms an
authenticator supports, so it cannot be used to choose the algorithms
beforehand.

**When the retry is not offered, and is refused.** A classical passkey is not
allowed, so the page offers no retry and the service refuses one asked for
anyway (`STS-AUTHN-0420`), when:

| Where | Refused when |
|---|---|
| `/portal/keys` | the person's passkey policy has `registrationMode: pq-only`, or that row is `realm` and `webauthn.pqcOnly` is on, or `postQuantumRequired` is `registration-and-sign-in` |
| the passkey step at sign-in | as above, or `postQuantumRequired` is `sign-in` for this application (the new classical passkey would not sign the person in) |

`registrationMode: pq-first` still offers the classical retry where the
realm's `webauthn.pqcOnly` is on. `classical-only` never asks for ML-DSA,
so this failure does not arise. See
[the passkey policy](authentication.md#the-passkey-policy).

With [both lanes](#a-classical-and-a-post-quantum-passkey-side-by-side) on, the
retry creates a passkey in the classical lane.

**Over the API.** `POST /authn-api/mfa/{id}/webauthn/options` and the Account
API's `POST /account-api/keys` (`action: begin`) take `algorithms:
"classical"` for the retry. The armed ceremony's `fallback` says whether it
asks for ML-DSA (`asksPostQuantum`), whether the retry may be offered
(`classical`), and whether this ceremony is the retry (`retrying`). See the
[sign-in API](authn-api.md) and the [Account API](account-api.md).

**See what was registered.** Each passkey's algorithm is shown on
`/portal/keys` (**Details**), in the **Algorithm** column on the person's
console page (marked *post-quantum* or *insecure*), and on the audit log's
`session.start` row of every sign-in it made (`credentialAlgorithm`).

### Clients that cannot make an ML-DSA passkey

The retry above helps after the failure. Where you already know a client
fails, you can stop the failure happening: a registration from that client
is offered the list **less ML-DSA** from the start (ES256 and RS256 where that
leaves nothing), exactly as if the person had pressed the retry. There are
two ways to name such a client, and both can be used together.

A **client** is a browser and an operating system, by family and major
version only, written the way the passkey ceremony rows write it:
`Chrome 141 on macOS 15`, `Firefox 144 on Linux`. It is read from the
browser's User-Agent and nothing else. Look at the `client` field of the
`webauthn.ceremony` rows in the audit log
([below](#watching-the-move-to-post-quantum-passkeys-the-ceremony-audit-rows))
to see what your people's browsers are called.

**Configured rules.** The passkey policy's **`clientRules`** row, on the
default profile and on each named profile, empty by default. It holds up to
20 rules separated by `;`. Each rule is `<browser> on <system>`. Each side
is a family, or `*` for any, and may be followed by a major-version range:
`141`, `130-140`, `130-` (130 and later) or `-140` (140 and earlier).
Families are matched without regard to case.

```text
Firefox 140- on Linux; * on Android 13
```

A range needs a version to match, so `Chrome 130- on *` does not match a
client whose version could not be read. Set the row on
**Directory → Policies → Passkey policy**, or include it in
`POST /admin-api/policies/save-passkey-policy`:

```bash
curl -s -X POST "$STS/admin-api/policies/save-passkey-policy" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"profile":"default", ... ,"clientRules":"Firefox 140- on Linux"}'
```

A save is refused (`STS-AUTHN-0309`) with the first rule it could not read.

#### Learned clients

The realm can also learn which clients fail. Turn on
**`webauthn.clientLearning`** (per realm, **off** by default) on
**Protocols → WebAuthn** or with `POST /admin-api/config/set`. While it is
on:

* A registration that asked for ML-DSA and failed in the browser with
  `NotSupportedError` is counted against its client. Other failures
  (`NotAllowedError`, which is also a cancel or a timeout, and the rest)
  are not counted, because they say nothing about the algorithm.
* Each person counts **once** however often they try, so one account cannot
  stop ML-DSA being offered to everybody else on the same browser.
* When **`webauthn.clientLearningFailures`** (default 3) different people
  have failed this way from one client within
  **`webauthn.clientLearningWindowHours`** (default 168, one week), and no
  registration from it has succeeded, the client is **learned**: its
  registrations offer no ML-DSA from then on. The audit log gets one
  `webauthn.client.learned` row.
* A registration from a learned client that asked for ML-DSA and succeeded
  (where no rule applied, for example under `registrationMode: pq-only`)
  removes the entry, and so does clearing it.
* Turning the switch off stops counting and stops applying what was
  learned. The entries are kept, and apply again if it is turned back on.

The learned clients are listed on **Directory → Policies → Passkey policy →
Learned clients**, learned ones first, with the clients still being counted
after them. Each has a **Clear** button, and **Clear every learned client**
clears them all. Over the API:

| Operation | What it does |
|---|---|
| `GET /admin-api/policies?clientsPage=1&clientsPer=25` | `passkey.clients`: whether learning is on, the two settings, and a page of `rows` (`client`, `learned`, `learnedAt`, `learnedFailures`, `failures` in the window, `firstAt`, `lastAt`) with `paging` |
| `POST /admin-api/policies/clear-passkey-client` | `{"client":"Chrome 141 on macOS 15"}`: clear one entry. One that is not listed is refused (`STS-AUTHN-0477`). |
| `POST /admin-api/policies/clear-passkey-clients` | `{}`: clear every entry |

The scheduler job **`passkeys.client-learning-sweep`** runs hourly in each
realm and removes the entries that were never learned and whose failures
have all aged out of the window. A realm keeps at most 500 entries. When it
is full of learned clients, a new client is not counted until one is
cleared (`STS-AUTHN-0478` in the service log).

#### Where neither kind applies

The offer is never narrowed where a classical passkey is not allowed — the
same cases that refuse the retry (the table above): `registrationMode:
pq-only`, `webauthn.pqcOnly`, `postQuantumRequired:
registration-and-sign-in`, and at the passkey step at sign-in
`postQuantumRequired: sign-in`. It is not narrowed in the post-quantum lane
either (with [both lanes](#a-classical-and-a-post-quantum-passkey-side-by-side)
on, the person chose an ML-DSA passkey), nor for the
[upgrade](#upgrading-a-classical-passkey) or the post-login migration, whose
point is ML-DSA. An administrator's enrolment on a person's behalf is not
narrowed. Failures at all of these still count towards learning.

#### What the ceremony row says

The `offered` field of the `webauthn.ceremony` row lists the algorithms the
registration actually offered. Where a rule named the client, a `|` and what
the rule did follow:

| `offered` ends with | Meaning |
|---|---|
| `\|configured: Firefox 140- on Linux` | the configured rule left ML-DSA out |
| `\|learned: Firefox 144 on Linux` | the learned client left ML-DSA out |
| `\|not applied (webauthn.pqcOnly): configured: ...` | a rule named the client and was not applied, and why |

## A classical and a post-quantum passkey side by side

This section describes the setting `webauthn.pqcAlongsideClassical`,
added by [#643](https://github.com/rcbj/iya-sts/issues/643), and the
passkey policy's **`lanes`** row, which sets it per population
([#1104](https://github.com/rcbj/iya-sts/issues/1104)): `realm` (the default)
follows the setting, `both` gives the profile's people two lanes even where
the setting is off, and `one` gives them one lane even where it is on.
`webauthn.pqcOnly` still means one lane, and `lanes: both` is refused beside
`registrationMode: classical-only` (`STS-AUTHN-0476`).

### What it is, and why you would want it

It lets one person hold **two passkeys of different kinds at once**, often on
the same authenticator:

* a **classical** passkey (ES256, RSA and the like), which nearly every
  authenticator, browser and password manager supports; and
* a **post-quantum** passkey (ML-DSA), which a quantum computer is not
  expected to be able to break.

You would turn it on to start moving people to post-quantum passkeys without
losing the classical one they can use everywhere. The person can sign in with
either. Later you can require the post-quantum one, for everybody or for some
applications ([next section](#requiring-a-post-quantum-passkey)).

**Why a setting is needed for this.** Without it, a person cannot hold both on
one authenticator. Every passkey is created under the person's one user
handle. An authenticator *replaces* the passkey it already holds for this
service when asked for another under the same handle, and the service asks for
ML-DSA first. So by default a person holds one kind or the other on a given
device.

### How it works

With two lanes, each new passkey is created in a **lane**:

| | Classical lane | Post-quantum lane |
|---|---|---|
| Algorithms offered | `webauthn.algorithms` without ML-DSA (`ES256` and `RS256` if that leaves none) | ML-DSA only: the ML-DSA algorithms `webauthn.algorithms` names, or all three if it names none |
| User handle | the person's usual one | a second one, created the first time and then kept |
| Name the authenticator and password manager show | the username, for example `alice` | `alice+ml-dsa`, then `alice+ml-dsa-65` (see below) |
| Display name shown | the person's name | the person's name followed by `(ML-DSA)` |
| Passkeys the browser is told to skip | the person's classical passkeys | the person's post-quantum passkeys |

Because each lane has its own user handle, the authenticator and the password
manager treat the two as **two separate accounts**. That is what lets both fit
on one device.

### Turning it on

It is a setting **per realm**, off by default. To give two lanes to some
people only, leave the setting off and set `lanes` to `both` on a
[named passkey policy](#different-rules-for-different-applications-or-groups)
that selects them (or set the setting on and `lanes` to `one` for the people
who should not have two).

**Console.** In the realm, open **Protocols → WebAuthn**, turn on **Post-quantum
passkey alongside a classical one**, and save.

**API.**
```bash
api config/set '{"key":"webauthn.pqcAlongsideClassical","value":true}'

# In a trust realm
curl -sk -X POST "$BASE/realm/acme/admin-api/config/set" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"key":"webauthn.pqcAlongsideClassical","value":true}'
```

Or set `STS_WEBAUTHN_PQC_ALONGSIDE_CLASSICAL=true` for the whole service.

**It cannot be on together with `webauthn.pqcOnly`**: a save that would turn
both on is refused (`STS-AUTHN-0353`). Turn `webauthn.pqcOnly` off first. If
both reach the service another way (an environment variable or a file),
`pqcOnly` wins and there is only one lane.

The classical lane offers the classical algorithms `webauthn.algorithms`
names. If it names only ML-DSA, the classical lane offers `ES256` and
`RS256`.

### What the person does

Every place a passkey is created asks **Classical or post-quantum?** where the
person has two lanes. The choices are **A classical passkey** ("ES256 or RSA — what
nearly every authenticator can make") and **A post-quantum passkey** ("ML-DSA,
listed as a second account ending in +ml-dsa. Few authenticators can make one
yet.").

**On the portal**, to hold both:
1. Sign in and open `/portal/keys`.
2. Under **Add a passkey**, **Classical or post-quantum?**, choose **A
   classical passkey**. Press **Create a passkey** or **Use a security
   key**, and create it.
3. Back on **Add a passkey**, choose **A post-quantum passkey**, and create
   it with the same authenticator or another one.

The list now shows two passkeys. Under each one's **Details**, the
**Cryptography** row says `classical` or "post-quantum (ML-DSA), listed as a
second account ending in “+ml-dsa”", and the **Algorithm** row names the
algorithm.

The **Cryptography** row is read from the passkey's algorithm: an ML-DSA
passkey says post-quantum and any other says `classical`. Whether it was
made as a second account is added for a post-quantum passkey in that lane.
So in a realm that does not offer the two side by side, an ML-DSA passkey
says "post-quantum (ML-DSA)" with no mention of a second account.

The same question appears on the other doors that create a passkey:
* the **activation link** (`/portal/activate`), when the person chooses a
  passkey;
* the **sign-in screen's passkey step** (`/authn/webauthn`) when it
  registers a passkey, including the set-up step `/authn/mfa-setup` that a
  required second factor leads to.

Each door creates one passkey. To get the second one, the person goes to
`/portal/keys` afterwards.

**With the Account API**, the lane is the `lane` member (`classical` or `pqc`)
of the `begin` action:
```bash
# with a token for the person (see account-api.md)
curl -sk -X POST "$BASE/account-api/keys" -H "Authorization: DPoP $AT" \
  -H "DPoP: $PROOF" -H 'content-type: application/json' \
  -d '{"action":"begin","kind":"passkey","lane":"pqc"}'
```
`GET /account-api/keys` lists the lanes the realm offers in `enrol.lanes`.

### How the post-quantum passkey is named

* **When it is created**, the service cannot yet know which ML-DSA algorithm
  the authenticator will choose, so the account is created as
  `<username>+ml-dsa` with the display name `<name> (ML-DSA)`.
* **Afterwards**, `/portal/keys` uses the WebAuthn Signal API to tell the
  person's credential manager the exact algorithm, for example
  `alice+ml-dsa-65`. It does this when every post-quantum passkey the person
  holds uses the same algorithm. If they hold more than one ML-DSA variant,
  the name stays `<username>+ml-dsa`. Whether the credential manager shows the
  new name depends on whether it supports the Signal API.
* The Signal API is sent once per lane, so a passkey removed on the portal
  also disappears from the credential manager in either lane.

**The name is never a username.** The person signs in as `alice`, never as
`alice+ml-dsa`. A name typed at the sign-in screen that ends in `+ml-dsa`,
`+ml-dsa-<n>` or `+pqc` is refused, in every mode (`STS-AUTHN-0354`).

### How sign-in picks between them

Nothing special is needed. **Either passkey signs the person in**, with or
without the username:
* **With the username typed**, the request lists all of the person's
  passkeys, so the browser offers whichever one is present.
* **With no username**, the browser's account chooser shows both accounts
  (`alice` and `alice+ml-dsa…`). Either one names the same person.
* With the passkey policy's `aggregateDevices` off, a person with more than one
  passkey picks one from a list by its name first.

The audit log's `session.start` row records which kind was used:
`credentialAlgorithm` (for example `ML-DSA-65 (-49)`) and `credentialLane`
(`classical` or `pqc`).

`webauthn.maxKeysPerPerson` (default 10) counts **both lanes together**.

### Checking that it worked

| Where | What to look for |
|---|---|
| **Protocols → WebAuthn** | **Post-quantum passkey alongside a classical one** is on in this realm. |
| `GET /admin-api/mfa` | `webauthn.pqcAlongsideClassical` is `true`, and `webauthn.lanes` lists both lanes with each lane's algorithms. |
| the person's page, **Directory → Users** | In **Passkeys (WebAuthn)**, the post-quantum passkey's **Algorithm** is an ML-DSA algorithm marked *post-quantum* and *post-quantum lane, beside a classical passkey*. |
| `GET /admin-api/users?user=<username>` | Each passkey's `algorithm` has `name`, `postQuantum` and `lane` (`classical` or `pqc`). |
| `/portal/keys` | **Details** shows **Cryptography** for each passkey. |
| **Monitoring → Audit log** | `session.start` rows carry `credentialLane` and `credentialAlgorithm`. |

### Turning it off again

While the setting is off, a post-quantum passkey already registered **goes on
signing in**. No new one can be created in the post-quantum lane
(`STS-AUTHN-0351`). Every new passkey is created as before, with ML-DSA first
in the list.

### Pitfalls

* **An ML-DSA passkey made before you turned the setting on counts as
  classical-lane.** It was created under the person's usual user handle. It
  is still post-quantum for the purpose of
  [requiring a post-quantum passkey](#requiring-a-post-quantum-passkey),
  which looks at the algorithm. But on that same authenticator, creating a
  *classical* passkey is refused by the browser, because the authenticator
  already holds a passkey in that lane. Remove the old one first, or create
  the classical one on another authenticator.
* **The two passkeys look like two accounts** in the person's password
  manager. Tell people that `alice+ml-dsa` is the same account as `alice`.
* **Few authenticators make ML-DSA passkeys** (see [where ML-DSA passkeys
  are expected to work](#where-ml-dsa-passkeys-are-expected-to-work)).
* **Requiring a post-quantum passkey at registration changes the question.**
  While `postQuantumRequired` is `registration-and-sign-in`, only the
  post-quantum lane is offered, and the pages do not ask.
* **The maximum counts both lanes.** A person at `webauthn.maxKeysPerPerson`
  cannot add the second kind until they remove one (`STS-AUTHN-0067`).
* **It cannot be combined with `webauthn.pqcOnly`** (`STS-AUTHN-0353`).

## Where ML-DSA passkeys are expected to work

Support for ML-DSA passkeys depends on the whole chain: the browser, the
operating system, the passkey provider or security key, and how the
authenticator is reached. A browser that supports WebAuthn does not
necessarily make or use an ML-DSA passkey, and the service cannot ask
beforehand: WebAuthn has no way to report which algorithms an
authenticator supports. This section describes the **kinds of failure** to
plan for, what the service does about each, and how to find out which
ones your own people meet
([#1113](https://github.com/rcbj/iya-sts/issues/1113)). It does not list
products or versions, because support is changing quickly and such a list
would soon be wrong. Measure your own realm instead (below).

The service verifies ML-DSA-44, ML-DSA-65 and ML-DSA-87 (RFC 9964) at
registration and sign-in, and its tests cover all three with a software
authenticator. No real platform authenticator or security key has been
tested by this project.

### The kinds of failure

| What happens | What the person sees | What the ceremony row shows |
|---|---|---|
| **The whole registration fails** instead of falling back to a classical algorithm. Some platforms do not skip an offered algorithm they cannot do; they abandon the ceremony. | An error, or nothing, after the prompt. | `outcome` `refused`, `clientError` `NotSupportedError` (sometimes `NotAllowedError` or `UnknownError`), `offered` starting with ML-DSA. |
| **The offered order is not honoured.** The client makes a classical passkey even though ML-DSA was offered first. From the service's side this looks the same as an authenticator that cannot make ML-DSA. | Nothing unusual: a passkey is registered. | `outcome` `success`, an ML-DSA `offeredFirst`, a classical `algorithm`. |
| **A security key with no PIN set refuses to make a credential.** The service asks for user verification by default (`webauthn.userVerification` is `required`, and always for a sign-in with no username), and a key with no PIN or biometric cannot give it. Some browsers ask the person to set a PIN first; others end the ceremony. | A prompt to set a PIN, or an error. | `attachment` `cross-platform`, `outcome` `refused`, `clientError` `NotAllowedError` or `InvalidStateError`. |
| **The key or signature is too large for the transport.** ML-DSA public keys are 1,312 to 2,592 bytes and signatures 2,420 to 4,627 bytes, against about 70 bytes for an `ES256` signature. A transport with tight message limits (some NFC, Bluetooth or cross-device paths) may fail or time out. | An error or a timeout, often only with one way of reaching the key. | `transports` names the path; compare `outcome` by `transports` and `algorithm`. |
| **Ceremonies are slower with the larger parameter sets.** ML-DSA-87 keys and signatures are about twice the size of ML-DSA-44's, and some authenticators take noticeably longer to make them. | A longer wait at the prompt. | `durationMs`, compared by `algorithm` over many rows. |

### What the service does about each

* **A registration that fails outright: the classical retry.** Where a
  classical passkey is allowed, the page offers **Try again with a
  classical passkey** after a `NotSupportedError` (and words the same
  advice with "if" after a less precise error). See [when the device
  cannot make an ML-DSA passkey](#when-the-device-cannot-make-an-ml-dsa-passkey)
  ([#944](https://github.com/rcbj/iya-sts/issues/944)).
* **Clients known to fail: leaving ML-DSA out of the offer.** The passkey
  policy's `clientRules`, and the clients a realm learns from failed
  registrations, leave ML-DSA out of a registration's offer for a browser
  and operating system known to fail, so the person never meets the
  failure; never where a classical passkey is not allowed. See [clients
  that cannot make an ML-DSA passkey](#clients-that-cannot-make-an-ml-dsa-passkey)
  ([#1112](https://github.com/rcbj/iya-sts/issues/1112)). A ceremony row
  narrowed this way shows the rule in the report's `offerRule` column.
* **The passkey policy's registration modes** decide what a group of
  people is offered. `pq-first` offers ML-DSA first and the classical
  algorithms after it, so a client that can make ML-DSA does and the
  others fall back. `pq-only` offers only ML-DSA and refuses the classical
  retry: use it only for people whose devices you know work. `classical-only`
  offers no ML-DSA, for a group whose devices fail the whole registration.
  Profiles can be [selected per group or application](#different-rules-for-different-applications-or-groups),
  so you can move a pilot group first. See
  [the passkey policy](authentication.md#the-passkey-policy).
* **The order of the offer.** The algorithms are offered in the order set
  on **Protocols → WebAuthn** (`webauthn.algorithms`) or in a profile's
  `registrationAlgorithms`, and the **Metadata** tab of **Protocols →
  WebAuthn** lists them in that order, numbered. The default puts
  `ML-DSA-87` first. Putting
  `ML-DSA-44` first instead asks for the smallest keys and signatures,
  which helps on tight transports and slow authenticators; a profile can
  do that for one group only.
* **A person who has an ML-DSA passkey but keeps using the old one.**
  While a post-quantum passkey is required at sign-in,
  `postQuantumAllowCredentials: list-and-refuse` lets the person pick any
  of their passkeys, then refuses a classical one with a page that says
  why and links to adding a post-quantum passkey. See
  [narrow, or list and refuse](#narrow-or-list-and-refuse)
  ([#946](https://github.com/rcbj/iya-sts/issues/946)).
* **A security key with no PIN.** Nothing in the service sets a PIN. Tell
  people to set one with their key's own tool before registering; lowering
  `webauthn.userVerification` is not the answer, because it weakens every
  passkey in the realm.

### How to find out for your realm

Every registration and sign-in writes a [ceremony audit
row](#watching-the-move-to-post-quantum-passkeys-the-ceremony-audit-rows),
and the [`passkeyCeremonies` source in `/report`](reporting.md#passkeyceremonies)
reads them as a table you can filter, group and schedule
([#1107](https://github.com/rcbj/iya-sts/issues/1107),
[#1108](https://github.com/rcbj/iya-sts/issues/1108)). Its page lists
three predefined queries:

1. **ML-DSA registrations that failed, by client**: where the whole
   registration fails. Group by `clientError` to see how.
2. **Registrations that asked for ML-DSA and made a classical passkey, by
   client**: where the client cannot make ML-DSA, or does not honour the
   order.
3. **Classical sign-ins by people who hold an ML-DSA passkey**: who
   requiring post-quantum at sign-in would refuse today.

For the other failure kinds, start from any of them and change the
filter: `attachment` `cross-platform` with `clientError` `NotAllowedError`
for security keys, `transports` for the transport, and a select of
`client`, `algorithm` and `durationMs` sorted by `durationMs` for slow
ceremonies. The `client` column is the browser and operating system by
name and major version, so the answer is per client family, not per
device.

The audit ring holds only the latest `audit.maxEvents` rows. To keep a
history, save a definition with a schedule and keep its reports. The
[realm report](#measuring-the-move-to-post-quantum-passkeys) counts who
holds which kind of passkey now, and the
[`passkeyHistory` source](reporting.md#passkeyhistory)
([#1109](https://github.com/rcbj/iya-sts/issues/1109)) shows how that
count moved day by day. Before requiring ML-DSA, run both against
a pilot group.

## Requiring a post-quantum passkey

This section describes the passkey policy row `postQuantumRequired`, added by
[#718](https://github.com/rcbj/iya-sts/issues/718). It works with or without
the side-by-side setting above.

### The row

A passkey counts as **post-quantum** when its signature algorithm is
`ML-DSA-44`, `ML-DSA-65` or `ML-DSA-87`, as recorded when it was registered.
The algorithm decides, not the lane: an ML-DSA passkey created while
`webauthn.pqcAlongsideClassical` was off is post-quantum.

| Value | Registration | Sign-in |
|---|---|---|
| `off` (default) | any passkey | any passkey |
| `sign-in` | any passkey is still registered | a classical passkey does not sign anybody in (`STS-AUTHN-0356`) |
| `registration-and-sign-in` | only ML-DSA is offered, and a classical passkey is refused (`STS-AUTHN-0355`) | as `sign-in` |

It applies to **every use of a passkey**: in place of a password, after a
password, and the usernameless sign-in.

### Turning it on

**For the whole realm (console).** Directory → Policies → **Passkey policy**
→ **Default**. Set the post-quantum row to `sign-in` or
`registration-and-sign-in`, and save.

**For one application or one group.** Create a
[named passkey policy](#different-rules-for-different-applications-or-groups)
that selects it, with the row set. The rest of the realm is unaffected.

**API.** Send the whole profile with `postQuantumRequired` set, as in the
named-policy example above (leave out `profile` for the `default` policy).

**The save is refused while the realm offers no ML-DSA** (`STS-AUTHN-0357`):
when `webauthn.algorithms` names no ML-DSA algorithm and neither
`webauthn.pqcOnly` nor `webauthn.pqcAlongsideClassical` is on. Otherwise
nobody could register a passkey that meets it.

**Do this before you require it at sign-in:** make sure the people it applies
to have registered a post-quantum passkey, or a classical passkey that is
their only way in stops working. [Measuring the move](#measuring-the-move-to-post-quantum-passkeys)
below says how to find them.

### What the person sees

* **With the username typed**, the passkey step asks the browser only for the
  person's post-quantum passkeys. A person who holds none is told so before
  any prompt appears.
* **With no username**, the request cannot be narrowed. If the person picks
  a classical passkey, the sign-in is refused after the prompt.
* With `postQuantumAllowCredentials` set to `list-and-refuse`, the passkey
  step lists every passkey and refuses a classical one after the prompt,
  with a page that says why. See [Narrow, or list and refuse](#narrow-or-list-and-refuse).
* `/portal/keys` and the console mark each classical passkey that no longer
  signs its owner in. The portal says: "This passkey signs with a classical
  algorithm, and this realm now accepts only post-quantum (ML-DSA) passkeys,
  so it will not sign you in. Remove it and register a post-quantum passkey."
* The first time each classical passkey is refused, a Shared Signals CAEP
  `credential-change` is sent.
* Under `registration-and-sign-in`, every new passkey is offered ML-DSA only.
  With the side-by-side setting on, only the post-quantum lane is offered.

### Narrow, or list and refuse

With the username typed, the service can build the browser's request in one
of two ways while a post-quantum passkey is required at sign-in
([#946](https://github.com/rcbj/iya-sts/issues/946)):

| Behaviour | What the request names | What the person meets |
|---|---|---|
| `narrow` (default) | the person's post-quantum passkeys only | A classical passkey is never offered. But a person whose device holds only their classical passkey gets the browser's own "no passkey found" message, which does not say why. |
| `list-and-refuse` | every passkey the person holds | The person may pick a classical passkey. It is then refused after the prompt, and the sign-in screen says that this application requires a post-quantum passkey and links to **Add a post-quantum passkey** on the account page (`/portal/keys`). |

**The trade-off.** `list-and-refuse` lets a person pick a passkey that will be
refused, in exchange for a clear reason when they do. Either way, a person who
holds no post-quantum passkey at all is told before any prompt, with the same
page.

The account page link works only if the person can sign in to the portal:
another way in, or a portal application whose passkey policy does not
require a post-quantum passkey.

**A refused passkey is not a sign-in.** The refusal comes before any session,
authentication event or `session.start` row. It is recorded as a
`session.refuse` row with `STS-AUTHN-0356`. The passkey's signature counter is
still advanced, as for every verified passkey, so the same answer cannot be
replayed.

**Setting it.**
* **For the realm:** `webauthn.postQuantumAllowCredentials` (`narrow` or
  `list-and-refuse`) on **Protocols → WebAuthn**, or with
  `POST /admin-api/config/set`.
* **For one passkey policy:** the row `postQuantumAllowCredentials` on
  Directory → Policies → **Passkey policy**: `realm` (the default, follows the
  setting), `narrow` or `list-and-refuse`. Over the API it is optional in
  `POST /admin-api/policies/save-passkey-policy`; left out, `realm` is kept.

### How it is decided: the XACML facts

Every passkey registration and sign-in asks the realm's **issuance policy**
(XACML) a question: the action `register-passkey` or `use-passkey`. The built-in
policy's rule reads the passkey policy row and the passkey's facts. Since
#718, the question carries three more facts about the passkey, in the
resource category:

| Attribute | Type | Value |
|---|---|---|
| `urn:sts:xacml:passkey:algorithm` | string | the algorithm's name, for example `ML-DSA-65` |
| `urn:sts:xacml:passkey:post-quantum` | boolean | `true` for ML-DSA-44, -65 or -87 |
| `urn:sts:xacml:passkey:lane` | string | `classical` or `pqc` |

The row itself is `urn:sts:xacml:passkey-policy:postQuantumRequired`, and the
fact groups a question carries are listed in `urn:sts:xacml:passkey:facts`
(`algorithm` for these three), both in the environment category. The built-in
rule reads `post-quantum` and never `lane`, for the reason given above.
Since #946 the environment also carries
`urn:sts:xacml:passkey-policy:postQuantumAllowCredentials`, `narrow` or
`list-and-refuse` (the realm's setting where the row is `realm`). No built-in
rule reads it. A realm's own rule can use it, for example to treat a classical
passkey the person picked from a full list differently.

**Most realms need nothing more than the row.** To decide differently, for
example "post-quantum required only for a certain resource", you can write
your own rule:

1. Create an override of the issuance policy from its template, as in
   [Override a built-in policy in one realm](configure-xacml.md#override-a-built-in-policy-in-one-realm).
   Start from the template: it contains the passkey rules (`decidePasskeys`).
2. Add a Deny rule targeted at the action `use-passkey` (or
   `register-passkey`), with a condition on
   `urn:sts:xacml:passkey:post-quantum` and on `urn:sts:xacml:passkey:facts`
   containing `algorithm`. Give it the obligation
   `urn:sts:xacml:obligation:passkey`, with
   `urn:sts:xacml:passkey-verdict` set to `refuse` and, optionally,
   `urn:sts:xacml:passkey-code` and `urn:sts:xacml:passkey-reason`. The
   override you created from the template already contains the built-in
   post-quantum rule, one for each action, so open it in the **Policy
   editor** tab and use that rule as the starting point.
3. A refusal with no code of its own is recorded as `STS-AUTHN-0322`.

**An override built before #718 does not contain the post-quantum rule.** It
answers passkey questions itself, so the row has no effect in that realm.
Rebuild the override from the current template. See [XACML](xacml.md) and
[Configuring XACML and ALFA](configure-xacml.md).

## Requiring a post-quantum attestation

The passkey policy row `attestationAlgorithms`
([#941](https://github.com/rcbj/iya-sts/issues/941)) is about the passkey's
**attestation**: the authenticator's signed statement and the certificate
chain behind it. `postQuantumRequired` (above) is about the passkey's own
algorithm. A realm moving to post-quantum passkeys may want both: an ML-DSA
passkey, attested by a chain a quantum computer cannot forge.

### The row

| Value | Effect |
|---|---|
| `none` (default) | no rule |
| `post-quantum` | every signature may be any ML-DSA, SLH-DSA or composite ML-DSA one |
| `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` | that ML-DSA parameter set |
| `slh-dsa`, `composite-ml-dsa` | any SLH-DSA, or any composite ML-DSA, signature |

The value is a comma-separated list. Each signature — the statement's, and
each certificate's from the leaf to the trust anchor — must be one an entry
allows. `ml-dsa-65` alone refuses an ML-DSA-65 attestation key whose
certificate an ML-DSA-87 root signed; `ml-dsa-65,ml-dsa-87` accepts it.

* **A trusted attestation is required**, as for an AAGUID list: the chain
  must reach a root in `webauthn.attestationTrustAnchors` or the FIDO
  metadata. Anybody can make an ML-DSA certificate; only a trusted one says
  something about the authenticator. Setting the row also makes registration
  ask the browser for direct attestation.
* **Registration**: a passkey whose attestation does not meet the list is not
  registered (`STS-AUTHN-0411`). `none` and self attestation carry no
  certificate and are refused.
* **Sign-in**: only with `enforceAttestationAtSignIn` on, by what was
  recorded at registration (`STS-AUTHN-0412`). A passkey registered before
  this service recorded attestation algorithms stops signing in then. The
  first refusal of each passkey sends a CAEP `credential-change`.

Set it on the default policy, or on a
[named policy](#different-rules-for-different-applications-or-groups) for one
application or group. Over the API it is one more field of the profile
(`POST /admin-api/policies/save-passkey-policy`); a save that leaves it out
keeps the default.

**Check what your passkeys hold first.** Few authenticators sign their
attestation with a post-quantum algorithm today. Read each person's passkeys
(`GET /admin-api/users?user=`, `attestationAlgorithms`) before requiring
it, or nobody may be able to register.

### The XACML facts

A question carrying the fact group `attestation-algorithm` has, in the
resource category:

| Attribute | Type | Value |
|---|---|---|
| `urn:sts:xacml:passkey:attestation-statement-algorithm` | string | the statement's algorithm, for example `ML-DSA-65` |
| `urn:sts:xacml:passkey:attestation-certificate-algorithm` | string bag | each certificate's signature algorithm, leaf to anchor (`ML-DSA-87`, `sha256-ecdsa`, `id-MLDSA65-ECDSA-P256-SHA512`) |
| `urn:sts:xacml:passkey:attestation-post-quantum` | boolean | every one of them is post-quantum |
| `urn:sts:xacml:passkey:attestation-algorithm-allowed` | boolean | they meet the profile's list (the built-in rule reads only this) |

The list itself is `urn:sts:xacml:passkey-policy:attestationAlgorithms` in
the environment, one value per entry. A realm's own rule can use the raw
facts, as for [the post-quantum passkey facts](#how-it-is-decided-the-xacml-facts).
An issuance policy override built before #941 has no rule for the row:
rebuild it from the template.

## Post-login activities: moving people to post-quantum passkeys

[Requiring a post-quantum passkey](#requiring-a-post-quantum-passkey)
refuses a classical one. Before you turn that on, people need an ML-DSA
passkey, and the way to get them one is to ask them when they sign in. A
**post-login activity** is something a realm asks a person to do after
they sign in, before they are sent back to the application. The one
activity today, `pqc-passkey-migration`, asks them to register an ML-DSA
passkey.

This section walks through it. Every field, audit row and error code is on
[Post-login activities](post-login-activities.md), the reference.

### Who is asked

* **A person holding a classical passkey and no ML-DSA one** is asked for
  an ML-DSA passkey. All their passkeys are asked about at once: a passkey
  has no role, so one ML-DSA passkey is enough. (Until #1135 each role was
  asked about separately, `primary` first.)
* **A person with no passkey** is not asked unless the profile says so:
  `noPasskey` `invite` (they can always skip) or `require` (they can skip
  until the allotted time has passed). The profile's `noPasskeyRole`, which
  chose the role of that passkey, is gone since #1135.
* **A person whose passkeys are all ML-DSA** is not asked, unless
  the profile's `attestation` is `post-quantum`. Then an ML-DSA passkey
  counts only when its recorded attestation is post-quantum too, and a
  person whose ML-DSA passkey has a classical attestation (or none recorded)
  is asked for another one beside it. See
  [Requiring a post-quantum attestation](#requiring-a-post-quantum-attestation)
  for what a post-quantum attestation is.

What counts as post-quantum is the passkey's **algorithm**, never its lane:
an ML-DSA passkey made in a realm with one lane counts.

**Nobody is asked where the realm cannot make an ML-DSA passkey**:
WebAuthn off, no use of a passkey accepted (`webauthn.primaryAllowed` and
`webauthn.mfaAllowed` both off, or both of the authentication policy's
passkey rows), no ML-DSA algorithm offered, or a passkey profile
that refuses the post-quantum lane (`registrationMode: classical-only`). The
default `webauthn.algorithms` offers ML-DSA, so a realm with the default
settings can be asked. A sign-in is never held for something the person
cannot do there.

### Turning it on, and for whom

The policy is **off by default** in every realm. Open **Directory →
Policies → Post-login activity policy**, or use
`POST /admin-api/policies/save-postLogin-policy` (send the whole profile,
as for the other policies; `GET /admin-api/policies`, the `postLogin`
member, has every field's current value).

* **The `default` profile** reaches everybody in the realm. A realm without
  its own follows the default realm's.
* **A named profile** reaches the members of the groups in its
  `selectGroups`. Where several reach one person, the lowest `precedence`
  (1 to 1000) wins. Post-login profiles select by group only, never by
  application: the activity is about the person, not what they signed in
  to.
* **To leave a group out**, give it a named profile with `enabled` off and a
  lower precedence than the profile that would otherwise reach it. That
  keeps them out of a started activity too (below).
* **Or start the activity for some groups instead** of switching the policy
  on: a started activity on **Directory → Post-login activities** asks the
  members of its groups (or the whole realm) at sign-in, under the rules of
  the profile the policy selects for each person, even where that profile
  is off. See [Reminders by mail](#reminders-by-mail).

A rollout usually goes like this:

1. **Count first.** On **Monitoring → Passkeys**, see how many people hold
   only classical passkeys, and on which authenticator models
   ([below](#measuring-the-move-to-post-quantum-passkeys)).
2. **Start with a pilot group.** A named profile for the group, `enabled`
   on, with no allotted time (`graceDays` `0`), so everybody can skip:

   ```bash
   api policies/save-postLogin-policy '{"profile":"pqc-pilot",
     "selectGroups":["pqc-pilot"],"precedence":10,
     "enabled":true,"activity":"pqc-passkey-migration",
     "snoozeDays":7,"graceDays":0,"noPasskey":"leave",
     "method":"automatic","attestation":"any",
     "noPasskeyFallback":"none"}'
   ```

3. **Watch where it fails** in the `passkeyCeremonies` report source
   ([below](#watching-progress)), and fix what you can before widening it.
4. **Set a deadline.** Give `graceDays` a value. From each person's first
   invitation they have that many days; after that Skip is gone and the
   sign-in waits until the passkey is registered.
5. **Remind the people who rarely sign in** [by mail](#reminders-by-mail).
6. **Require it.** When the people who hold only classical passkeys are
   near zero, set `postQuantumRequired` on their passkey profile. Do not do
   it earlier: a person whose only way in is a classical passkey is refused
   at the passkey step, before any post-login activity can ask them.

### At the sign-in

1. They sign in at the sign-in screen as usual: a password, a passkey, a
   one-time code, an emailed code, and so on.
2. If they are due the activity, the session is **held, not started**. The
   page `/authn/post-login`, **Register a post-quantum passkey**, says why
   they are asked and, where there is a deadline, until when they can skip.
   It has **Register a post-quantum passkey**, **Skip for N day(s)** while
   skipping is still allowed, and **Start over**.
3. **Skip** puts the activity off for the profile's `snoozeDays`, and the
   held session starts.
4. **Register** goes to the passkey page. Only ML-DSA is offered, and there
   is no classical retry, except for a person with no passkey under
   `noPasskeyFallback` (below). How a classical passkey is moved is the
   profile's `method`:

   | `method` | What happens |
   |---|---|
   | `upgrade` | The person uses their classical passkey once, then creates the ML-DSA passkey on the same authenticator. It **replaces the classical one in place**, there and here: one passkey, nothing left to clean up. See [Upgrading a classical passkey](#upgrading-a-classical-passkey). |
   | `alongside` | An ML-DSA passkey is added beside the classical one: in the post-quantum lane where the person's passkey profile has [two lanes](#a-classical-and-a-post-quantum-passkey-side-by-side), or on a **different** authenticator where it has one (the page says which). |
   | `automatic` (default) | `alongside` where the person's passkey profile has two lanes, `upgrade` where it has one. |

   A person asked only because of the attestation rule always adds the new
   passkey alongside: there is nothing classical to replace.
5. When the passkey is registered, the held session starts and the person
   goes back to the application. The session keeps the `amr` and `acr` of
   the sign-in they had already completed; the new passkey does not change
   them.

**A person with no passkey whose device cannot make ML-DSA.** With the
profile's `noPasskeyFallback` set to `classical`, a failed ML-DSA
registration is followed by **Try again with a classical passkey**, where
the person's passkey profile allows a classical one
([when the device cannot make an ML-DSA passkey](#when-the-device-cannot-make-an-ml-dsa-passkey)).
A classical passkey is better than a password, and its holder is asked to
migrate it later like everybody else. The default, `none`, offers ML-DSA
only.

**Any other device that cannot make it.** The browser's error sends the
person back to `/authn/post-login`, which names the error and says what to
do: register on a separate security key that supports ML-DSA, or ask an
administrator; and Skip, while it is still allowed. An administrator can
[upgrade a classical passkey](#upgrading-a-classical-passkey) from the
person's page, or, where the person's passkey profile has `adminEnrolment`
on, [enrol one](#an-administrator-enrols-a-passkey). Each such failure
writes an `authn.post-login.unsupported` audit row with the error name, the
browser and the platform. The passkey policy's `clientRules` and learned
clients do **not** narrow this registration: its point is ML-DSA.

**Sign-ins that do not use the sign-in screen** — a federation partner, a
wallet, Kerberos, a client certificate — cannot show the page. An optional
activity does not interrupt them. A required one refuses them
(`STS-AUTHN-0473`), and the person is told to sign in at the sign-in screen.

### Reminders by mail

The activity is asked only at a sign-in, so somebody who rarely signs in may
reach a deadline without being asked. An administrator can start the
activity on **Directory → Post-login activities**
(`/admin/post-login-activities`, or the `/admin-api` operations of the same
name), optionally only for the members of groups chosen by search. While it
runs, those people are **asked at their next sign-in** whether or not the
policy is on (a named profile switched off still leaves its group out), and
the people it is due for are **mailed** every so many days, each person
once a round, up to a maximum per person, until it is paused or ended.

The mail only asks the person to sign in. Its one link carries no code and
nothing about the person, it goes to the address on their entry, and a
person may decline it on `/portal/email`. A mail is not an invitation: the
allotted time still starts at the first sign-in that asks them. The fields
and the scheduler job are in
[Post-login activities](post-login-activities.md#starting-an-activity).

### Watching progress

Three sources in the [reports application](reporting.md) (`/report`) follow
the move. Each comes with predefined queries you can run, change, save and
schedule:

| Source | What it answers |
|---|---|
| [`postLoginProgress`](reporting.md#postloginprogress) | Where each person stands: first asked, how often asked and skipped, done, when their allotted time ends, and the reminders mailed to them. Its queries: progress by activity, the people past their grace period, the people who skipped most. |
| [`passkeyHistory`](reporting.md#passkeyhistory) | The share of people holding an ML-DSA passkey, day by day, for the realm and for each named passkey profile ([The move over time](#the-move-over-time)). |
| [`passkeyCeremonies`](reporting.md#passkeyceremonies) | Every registration and sign-in, with the client and the browser's error: where ML-DSA registrations fail, and who still signs in with a classical passkey after making an ML-DSA one ([the ceremony audit rows](#watching-the-move-to-post-quantum-passkeys-the-ceremony-audit-rows)). An upgrade's ceremonies have the door `upgrade`; the activity's other registrations, `sign-in-step`. |

**Monitoring → Passkeys** counts who holds which kind of passkey now. The
audit log has a row for each person asked, skipping and done
(`authn.post-login.asked`, `.skipped`, `.done`), and for each failure on a
device (`authn.post-login.unsupported`).

## Upgrading a classical passkey

An upgrade moves one classical passkey to ML-DSA **in place**, on the same
authenticator. It runs in two places: at a sign-in, as the
[post-login activity](#post-login-activities-moving-people-to-post-quantum-passkeys)
when its `method` is `upgrade` (or `automatic` for a person whose passkey
profile has one lane), and from the console, run by an administrator on the
person's behalf (below). There is no upgrade button on `/portal/keys` and no
setting that switches it on: at a sign-in, the post-login activity policy,
or a started post-login activity, is the switch.

**The ceremony** is two steps:

1. **Prove it.** The person uses the classical passkey once. It is not
   changed.
2. **Register ML-DSA.** The registration offers ML-DSA only and leaves that
   classical credential out of `excludeCredentials`, under its own user
   handle, so the same authenticator answers and replaces it. There is no
   classical retry: the point of the upgrade is ML-DSA.

The ML-DSA passkey then replaces the classical one **in place**: one row,
keeping its name, recording when it was upgraded and from which algorithm.
The person keeps one passkey, on the same authenticator, and nothing is left
behind for them to clean up. Where the post-login activity adds the ML-DSA
passkey **alongside** instead, see
[the methods](#at-the-sign-in).

The classical passkey on this service is touched only once the new
registration has been verified, so a failed upgrade leaves it as it was. The
authenticator itself may replace the credential it holds as soon as it
creates the new one, which can be before this service has accepted the
answer. A registration that fails after that leaves the classical passkey
here and no classical credential on that device; the person signs in another
way and is asked again.

**On the console.** Directory → Users, on a classical passkey, **Upgrade to
ML-DSA**: an administrator runs the same two steps on a person's behalf, in
the administrator's browser, against the person's authenticator. The
console's upgrade follows the person's lanes rather than a `method`: with
two lanes it adds the ML-DSA passkey in the post-quantum lane and keeps the
classical one, with one lane it replaces the classical one in place. Over
the API the actions are `begin-passkey-upgrade`, `prove-passkey-upgrade`,
`finish-passkey-upgrade` and `cancel-passkey-upgrade` on
`POST /admin-api/users`.

A ceremony that does not complete leaves the classical passkey as it was
(`STS-AUTHN-0450` when the realm cannot make an ML-DSA passkey, `0451`–`0458`
for the steps). The new passkey meets every rule a registration does,
including `postQuantumRequired` and `attestationAlgorithms`.

### A passkey that may have been replaced on its authenticator

An authenticator keeps one discoverable credential per relying party and user
handle: a new one created under the same handle **replaces** the old one on
the device, while iya-sts would keep both rows. So when a passkey is
registered under a user handle another of the person's passkeys uses, **with
the same AAGUID** (the same model of authenticator), the older row is marked
*may have been replaced*. It is a marker, never a deletion — two keys of one
model are two devices.

- `/portal/keys` and the console's person page show the marker; **Remove**
  (or **Clear key**) deletes the row.
- The marker goes away when that passkey signs somebody in.
- The "last way in" check on a removal does not count a marked passkey.
- Each marking leaves an audit row, `webauthn.key.possibly-replaced`.

A passkey with no user handle recorded (registered before handles were kept)
or no AAGUID (attestation `none` on a platform that blanks it) is never
marked: nothing says it was the same authenticator.

## Measuring the move to post-quantum passkeys

**Monitoring → Passkeys** (`/admin/passkey-report`) counts the realm's people
as post-quantum only, classical only, both or none, every passkey by
algorithm and lane, and which authenticator models (AAGUIDs) hold which
algorithms. [Admin console → Passkeys](admin-console.md#passkeys--adminpasskey-report)
describes every tab.

**Before requiring post-quantum passkeys for a group or an application:**

Moving them first is the
[post-login activity](#post-login-activities-moving-people-to-post-quantum-passkeys);
this report tells you when they have moved. Keep another way in for each
person until their new passkey has signed them in on their own device.

1. Open **Monitoring → Passkeys**. On **Profiles**, find the named policy that
   selects the group, and click *count its population*; or type the group's
   cn in **Group**.
2. On **People**, the *classical only* count is the people the rule would
   refuse at sign-in. Click *list them*, and **Export CSV** for a list of
   them; [mail reminders](#reminders-by-mail) can ask them for you.
3. On **Models**, see which authenticators already make ML-DSA passkeys, and
   which of your people's do not.
4. When *classical only* is near zero, set `postQuantumRequired` on that
   policy (above).

**API.**

```bash
get() {   # get <path and query under /admin-api>
  curl -sk "$BASE/admin-api/$1" -H "Authorization: Bearer $TOKEN"
}
# The whole realm
get passkey-report
# One group, and its classical-only people
get "passkey-report?group=engineering&list=classical-only&per=50"
# The next page: send back the cursor the answer gave
get "passkey-report?group=engineering&list=classical-only&per=50&page=2&from=<list.paging.nextFrom>"
# The same list as a file
get "passkey-report/export?group=engineering&list=classical-only&format=csv" > classical.csv
# Count the realm again now (after a bulk import, for example)
api passkey-report/recount '{}'
```

The reads need a token with `admin:read`; the recount needs `admin:write`.
The counts are kept as passkeys are written and recounted once a day, so they
are current without reading the directory. Under a group or profile filter
the members are read (at most 50,000). The answer's `counted` says which.

### The move over time

Monitoring → Passkeys shows today. To see whether the share of people
holding an ML-DSA passkey is rising, or where it stalled, read the
**passkey history** in the [reports application](reporting.md#passkeyhistory)
(`/report`).

Each time the daily recount runs, it also keeps one row for the realm for
that day: the people by kind, the passkeys by algorithm, by lane and by
attestation algorithm, and the population of each named passkey profile
that selects people by group. A recount you start with **Recount now**
replaces that day's row with its newer count. The rows are kept for
`webauthn.passkeyHistoryDays` days (400 by default), and the same recount
removes older ones.

1. Open `/report`, choose the source `passkeyHistory`, and pick the
   predefined query **Post-quantum adoption by day**. Press Run. You get
   one row a day: the people holding a passkey, how many of them hold an
   ML-DSA one, and that as a percentage (`postQuantumShare`).
2. **Post-quantum adoption by passkey profile by day** gives the same
   numbers for each named profile's group, so you can see which group to
   remind, or which is ready for `postQuantumRequired`.
3. Save a query as a definition and schedule it to keep a copy of the
   numbers outside the service, or to have it emailed.

Things to know:

* **A day on which the recount did not run has no row.** The recount is a
  scheduler job (`passkeys.report-recount`); if it is off, or the scheduler
  is paused, the history stops too.
* **A profile's numbers cover at most 50,000 of its members**, as the
  profile filter on Monitoring → Passkeys does; `complete` is false on a
  day when there were more. At most 25 profiles are counted a day; the rest
  appear with `counted` false.
* **The numbers are the realm's at the moment of the recount.** Passkeys
  registered later that day appear in the next day's row.

## Watching the move to post-quantum passkeys: the ceremony audit rows

Every passkey registration and sign-in at the sign-in screen, the
usernameless sign-in, `/portal/keys`, an activation link, an upgrade, an
administrator's enrolment and a device link on `/portal/devices` writes one
audit row, `webauthn.ceremony`, whether it completed or not
([#943](https://github.com/rcbj/iya-sts/issues/943),
[#1108](https://github.com/rcbj/iya-sts/issues/1108)). The
[passkey ceremonies source in `/report`](reporting.md#passkeyceremonies)
reads them back as a table you can filter and group. Find them on
**Monitoring → Audit log** or with
`GET /admin-api/audit?action=webauthn.ceremony` (add `actor=` for one
person, `outcome=refused` for the ones that failed). The row's detail:

| Field | What it holds |
|---|---|
| `ceremony` | `registration` or `assertion` |
| `door` | `sign-in-step`, `usernameless`, `portal`, `activation`, `upgrade`, `admin-enrolment` or `device-link` |
| `role`, `lane` | for a sign-in, the step the passkey answered: `primary` (passwordless) or `mfa` (after a password); empty for a registration, since a passkey is registered with no role (#1135). `classical` or `pqc` |
| `application` | the application the sign-in was for (its client or relying-party id); absent at `/portal/keys`, an activation link, a device link and an administrator's enrolment |
| `durationMs` | milliseconds from the ceremony's options being issued to its response arriving, measured by the service (never reported by the browser). It includes the time the person spent at the prompt, so compare many rows, not one |
| `offered` | the algorithms offered, in order: for a registration, the list the browser was given (`pubKeyCredParams`); for a sign-in, the algorithms of the person's passkeys the ceremony could use |
| `algorithm` | the algorithm that was used; it is post-quantum when it is one of the ML-DSA algorithms |
| `client` | the browser and operating system, by name and major version only (`Chrome 141 on macOS 15`), from the User-Agent |
| `clientError` | for a ceremony the browser did not complete, the error name its script reported: `NotAllowedError` (declined, timed out, or no passkey — the browser does not say which), `NotSupportedError`, `InvalidStateError`, `SecurityError`, `AbortError`, ...; `other` for anything else. The error's message is never recorded |
| `capabilities` | the client capabilities the browser reported as available, from a fixed list |
| `authenticator` | three facts separated by `\|`: the attachment (`platform` or `cross-platform`), the transports the browser reported (`internal`, `hybrid`, `usb`...), and for a registration what its attestation was signed with, leaf to anchor, with `(PQ)` where all of it is post-quantum, led by `enterprise not listed, asked direct` where `webauthn.attestation` is `enterprise` and this RP ID is not on its list. For example `platform\|internal,hybrid\|ES256` |

Rows written before #1108 carry `attachment`, `transports`, `attestation`
and `postQuantum` as separate fields instead of `authenticator`, and a few
written in between carry the capabilities on `client` after a `|`; the
`/report` source reads all of them.

A refused row carries the error code the refusal was recorded under (for a
browser that gave up, `STS-AUTHN-0022`).

**A separate row, `webauthn.algorithm-mismatch`**, is written when a person
who holds an ML-DSA passkey signs in with a classical one, where
post-quantum was not required. Its detail names the algorithm `used`, the
post-quantum algorithms the person `held`, the `door` and the `client`.
Many of these mean people still reach for their old passkey, and requiring
post-quantum at sign-in would refuse them today.

What these rows answer:

* **Is ML-DSA offered, and offered first?** `offered` on registrations.
* **Which browsers make an ML-DSA passkey when asked?** Registrations whose
  `offered` lists ML-DSA first, grouped by `client` and `algorithm`.
* **Which fail, and how?** `outcome=refused` with `clientError`:
  `NotSupportedError` where nothing on the device can make any algorithm
  offered, `NotAllowedError` where the person declined or nothing answered.
* **Who has a post-quantum passkey but does not use it?** The mismatch rows.

No service log line is written per ceremony or per failed ceremony: the
rows are the record, and a refusal's one log line comes from the request
itself.

## Losing a passkey, and account recovery

**Hold more than one.** The simplest recovery is a second passkey on a
different device or a security key. `/portal/keys` says so to anybody with
only one.

**Recovery codes.** A person who uses a passkey as a second step can generate
single-use recovery codes on `/portal/mfa`. Where they hold codes, the
passkey step offers **I do not have my passkey — use a recovery code**, which
takes them to `/authn/backup-code`.
A recovery code replaces a *second* factor only: it does not sign in a person
whose passkey is their only credential. See
[Recovery codes](authentication.md#recovery-codes).

**Removing a lost passkey.**
* **The person**, on `/portal/keys`, with **Remove**. They cannot remove their
  last way in (`STS-AUTHN-0070`): no password and no other passkey, while
  the realm lets a passkey sign somebody in on its own. Where it does not
  (`webauthn.primaryAllowed` off), no passkey is a way in and the removal is
  not refused.
* **An administrator**, on the person's page under **Directory → Users**, with
  **Remove** beside the passkey, or `POST /admin-api/users/clear-key` with
  `user` and `credentialId`.
* **Removing a passkey ends the sessions it signed in**, as the first factor
  or as the step after a password. The person's other sessions are kept. A
  CAEP `credential-change` is sent.

**An administrator's reset.** There is no self-service reset of a second
factor. On the person's page:
* **Remove every passkey** (`disable-primary-keys`) removes every passkey
  the person holds, and ends the sessions each of those passkeys signed in.
  Other sessions stay.
* **Disable all MFA** (`disable-mfa`) removes the authenticator app, every
  passkey and the recovery codes, and ends the sessions each removed factor
  signed in. A session a password alone signed in stays.

Both are withheld where the person has no password and passkeys may be a
first factor in the realm, and the API refuses them there
(`STS-AUTHN-0161`), so neither can lock anybody out.

Until #1135 the first removed only the passkeys enrolled to sign in on their
own and the second only those enrolled as a second step; a passkey has no
role now, so both take every passkey.
* **Generate a password reset link** (`issue-password-reset`), or an
  activation link through the API (`issue-activation`), lets a person who
  lost their only passkey set up a new credential.

**Whether a recovery restores access at once** is the passkey policy's
`recoveryAssurance` row, for a person who holds a passkey:

| Value | After a reset link, an activation link, a generated password, a recovery code or an emailed code |
|---|---|
| `any` (development default) | access is restored at once |
| `not-weaker` (product default) | the first sign-in reaches no application. The person is asked to register a new passkey, then signs in with it. |
| `operator-only` | as `not-weaker`, and the self-service doors (forgot-password, recovery codes, emailed factors) are refused. Only an administrator's link or generated password is left. |

The codes are `STS-AUTHN-0380` (refused) and `STS-AUTHN-0381` (limited to
registering a passkey). See *Account recovery* under
[the passkey policy](authentication.md#the-passkey-policy).

## Realms

* **Settings and policies are per realm.** Every `webauthn.*` setting can be
  set per realm. The `default` passkey policy and the authentication policy
  are inherited from the default realm until a realm saves its own. Named
  passkey policies are not inherited.
* **The RP ID comes from the host, not the realm.** Realms on one host share
  an RP ID. Each person's passkeys are created under their own random user
  handle, so a person with accounts in two realms has two separate passkeys.
  `rpNameExtras` adds the realm's name to the prompt so they can tell them
  apart.
* **Some browser hints need a single realm.** A usernameless sign-in tells the
  browser about a passkey the service holds for nobody
  (`signalUnknownCredential`) only where one trust realm is defined.
* **Across [cells](cells.md)**, a usernameless sign-in finds only people whose
  home is the cell that drew the screen. Anybody else types their username.

## Development and product mode

| | Development | Product |
|---|---|---|
| The ceremony (challenge, origin, RP ID, flags, signature, counter) | verified | verified |
| The password in front of a passkey | not checked | checked |
| The passwordless box, for a name with no passkey | registers a passkey on the spot | refused (`STS-AUTHN-0206`) |
| `webauthn.rpId` that does not fit the host | the host is used, and logged | the ceremony is refused (`STS-AUTHN-0023`) |
| `webauthn.attestationPolicy` `by-mode` | `off`: nothing verified, the format recorded | `verify-if-present`; `off` cannot be set |
| `webauthn.insecureAlgorithms` | may be turned on | cannot be set |
| `recoveryAssurance` default | `any` | `not-weaker` |
| `phrh` | never earned under the default attestation policy | earned by a trusted, device-bound passkey |

See also [Authentication → Development and product mode](authentication.md#development-and-product-mode)
and [What is not checked](what-is-not-checked.md).

## Settings

Every `webauthn.*` setting. All can be changed while running, per realm, on
**Protocols → WebAuthn** or with `POST /admin-api/config/set`. The full
description of each is in [Configuration → WebAuthn](configuration.md#webauthn).

| Setting | Environment variable | Default |
|---|---|---|
| `webauthn.enabled` | `STS_WEBAUTHN_ENABLED` | `true` |
| `webauthn.rpName` | `STS_WEBAUTHN_RP_NAME` | `IYA STS` |
| `webauthn.rpId` | `STS_WEBAUTHN_RP_ID` | empty (the host) |
| `webauthn.allowedOrigins` | `STS_WEBAUTHN_ALLOWED_ORIGINS` | empty (derived from the address) |
| `webauthn.algorithms` | `STS_WEBAUTHN_ALGORITHMS` | every algorithm the verifier knows: `ML-DSA-87`, `ML-DSA-65`, `ML-DSA-44`, then the classical ones |
| `webauthn.insecureAlgorithms` | `STS_WEBAUTHN_INSECURE_ALGORITHMS` | `false` |
| `webauthn.pqcOnly` | `STS_WEBAUTHN_PQC_ONLY` | `false` |
| `webauthn.pqcAlongsideClassical` | `STS_WEBAUTHN_PQC_ALONGSIDE_CLASSICAL` | `false` |
| `webauthn.postQuantumAllowCredentials` | `STS_WEBAUTHN_POST_QUANTUM_ALLOW_CREDENTIALS` | `narrow` |
| `webauthn.clientLearning` | `STS_WEBAUTHN_CLIENT_LEARNING` | `false` |
| `webauthn.clientLearningFailures` | `STS_WEBAUTHN_CLIENT_LEARNING_FAILURES` | `3` |
| `webauthn.clientLearningWindowHours` | `STS_WEBAUTHN_CLIENT_LEARNING_WINDOW_HOURS` | `168` |
| `webauthn.userVerification` | `STS_WEBAUTHN_USER_VERIFICATION` | `required` |
| `webauthn.attestation` | `STS_WEBAUTHN_ATTESTATION` | `direct` |
| `webauthn.attestationEnterpriseRpIds` | `STS_WEBAUTHN_ATTESTATION_ENTERPRISE_RP_IDS` | empty |
| `webauthn.attestationPolicy` | `STS_WEBAUTHN_ATTESTATION_POLICY` | `by-mode` |
| `webauthn.attestationTrustAnchors` | `STS_WEBAUTHN_ATTESTATION_TRUST_ANCHORS` | empty |
| `webauthn.attestationEvidenceTsaUrl` | `STS_WEBAUTHN_ATTESTATION_EVIDENCE_TSA_URL` | empty (disabled) |
| `webauthn.attestationEvidenceTsaTrustAnchors` | `STS_WEBAUTHN_ATTESTATION_TSA_TRUST_ANCHORS` | empty |
| `webauthn.attestationEvidenceHashAlgorithm` | `STS_WEBAUTHN_ATTESTATION_HASH_ALGORITHM` | `sha256` |
| `webauthn.passkeyHistoryDays` | `STS_WEBAUTHN_PASSKEY_HISTORY_DAYS` | `400` |
| `webauthn.attestationAllowedAaguids` | `STS_WEBAUTHN_ATTESTATION_ALLOWED_AAGUIDS` | empty |
| `webauthn.attestationMinCertificationLevel` | `STS_WEBAUTHN_ATTESTATION_MIN_CERTIFICATION` | `none` |
| `webauthn.attestationRequireFips` | `STS_WEBAUTHN_ATTESTATION_REQUIRE_FIPS` | `false` |
| `webauthn.attestationAllowSafetynet` | `STS_WEBAUTHN_ATTESTATION_ALLOW_SAFETYNET` | `false` |
| `webauthn.attestationAndroidSoftwareKeys` | `STS_WEBAUTHN_ATTESTATION_ANDROID_SOFTWARE` | `false` |
| `webauthn.timeoutMs` | `STS_WEBAUTHN_TIMEOUT_MS` | `60000` |
| `webauthn.authenticatorAttachment` | `STS_WEBAUTHN_ATTACHMENT` | `any` |
| `webauthn.credProps` | `STS_WEBAUTHN_CRED_PROPS` | `true` |
| `webauthn.primaryAllowed` | `STS_WEBAUTHN_PRIMARY_ALLOWED` | `true` |
| `webauthn.mfaAllowed` | `STS_WEBAUTHN_MFA_ALLOWED` | `true` |
| `webauthn.maxKeysPerPerson` | `STS_WEBAUTHN_MAX_KEYS` | `10` |

**Three ceremony settings are enforced, not just requested**:
`webauthn.userVerification` (with `required`, an authenticator that did not
verify the person is refused), `webauthn.algorithms` with `webauthn.pqcOnly`
and `webauthn.insecureAlgorithms` (a credential whose algorithm was not
offered is refused), and `webauthn.rpId` (checked through the RP ID hash).
The others are requests to the browser
([why](configuration.md#the-webauthn-settings-and-the-ceremony-settings-this-service-checks)).

**Turning a setting off never removes passkeys people already hold**, but
since #1135 the two use settings stop the use they name for every passkey.
`webauthn.enabled` off stops new registrations; the passkeys already held stay
listed. `webauthn.primaryAllowed` off means no passkey signs anybody in on its
own, and `webauthn.mfaAllowed` off means no passkey answers the step after a
password; with both off (or both of the authentication policy's passkey rows)
no new passkey can be registered (`STS-AUTHN-0531`). Until #1135 these
settings stopped only new passkeys in a role, and a passkey already enrolled
in it went on working. Before turning `webauthn.primaryAllowed` off, make sure
the people who have no password have another way in.

Two related settings are not `webauthn.*`: `authn.mfaStepTtlS` (300 seconds)
is how long a person has to finish the passkey step, so a
`webauthn.timeoutMs` longer than that does not help; and
`security.activationTtlMinutes` is how long an activation link lasts.

The passkey policy's rows are listed under
[the passkey policy](authentication.md#the-passkey-policy), and the
authentication policy's under
[the authentication policy](authentication.md#the-authentication-policy).
`webauthn.residentKey` and `webauthn.usernameless` no longer exist: the
passkey policy's `securityKeyResidentKey` and `allowUsernameless` replaced
them, and a configuration that still names either is refused at start.

## Management API operations

Every console control has an API operation. The request bodies are in
`GET /admin-api/openapi.json`.

| Operation | What it does |
|---|---|
| `GET /admin-api/webauthn` | the `webauthn.*` settings and what the ceremony offers |
| `GET /admin-api/mfa` | who holds which factor, and the WebAuthn report (algorithms, lanes, attestation) |
| `GET /admin-api/passkey-report` | who holds which passkey algorithm across the realm, by kind, algorithm, lane and model, filtered by `group`, `profile` or `application`, with the people behind a count (`list`, `page`, `per`, `from`) |
| `GET /admin-api/passkey-report/export` | the people behind a count, as CSV or JSON (`format`) |
| `POST /admin-api/passkey-report/recount` | count the realm's passkeys again now, on the scheduler |
| `GET /admin-api/users?user=<name>` | one person, with each passkey's algorithm, lane, backup state, attestation and any policy refusal |
| `POST /admin-api/users/begin-passkey-enrolment`, `finish-passkey-enrolment` | enrol a passkey for a person, in the caller's browser, when their profile's `adminEnrolment` is `on` |
| `POST /admin-api/users/begin-passkey-upgrade`, `prove-passkey-upgrade`, `finish-passkey-upgrade`, `cancel-passkey-upgrade` | upgrade one of a person's classical passkeys to ML-DSA |
| `GET /admin-api/passkey-report/evidence` | one passkey's RFC 4998 evidence (`username`, `credentialId`) |
| `POST /admin-api/users/clear-key` | remove one passkey (`user`, `credentialId`) |
| `POST /admin-api/users/rename-key` | rename one passkey (`user`, `credentialId`, `label`; empty restores the default) |
| `POST /admin-api/users/disable-primary-keys` | remove every passkey the person holds, and end the sessions each signed in |
| `POST /admin-api/users/disable-mfa` | remove every second factor, and end the sessions each removed factor signed in |
| `POST /admin-api/users/require-mfa`, `stop-requiring-mfa` | require a second factor of one person |
| `POST /admin-api/users/issue-activation` | a single-use activation link (`user`, optional `deliver: "mail"`) |
| `GET /admin-api/policies` | the passkey, authentication and post-login activity policies (among the others), with every field's current value, and the learned clients (`passkey.clients`) |
| `POST /admin-api/policies/save-passkey-policy`, `reset-passkey-policy` | save a passkey policy (optionally named with `profile`), or remove it |
| `POST /admin-api/policies/clear-passkey-client`, `clear-passkey-clients` | clear one learned client (`client`), or all of them |
| `POST /admin-api/policies/save-authn-policy`, `reset-authn-policy` | save the authentication policy, or go back to inheriting |
| `POST /admin-api/policies/save-postLogin-policy`, `reset-postLogin-policy` | save a post-login activity profile (optionally named with `profile`), or remove it |
| `GET /admin-api/post-login-activities`; `POST /admin-api/post-login-activities/start`, `/pause`, `/resume`, `/end` | started post-login activities and their mail reminders: list them, search the groups to start one for, start one, or change its state |
| `POST /admin-api/config/set`, `/config/reset` | change or reset a setting |

The person's own operations are on the [Account API](account-api.md)
(`/account-api/keys`), and the sign-in screen's on the
[sign-in API](authn-api.md).

## Error codes you will meet

A code is recorded on the audit row and in the log. It is never sent to the
browser or a client. Look a code up in the audit log with
`GET /admin-api/audit?code=STS-AUTHN-0356`. Every code is listed under
[Error codes → STS-AUTHN](error-codes.md#sts-authn).

| Code | What happened |
|---|---|
| `STS-AUTHN-0023` | product mode: `webauthn.rpId` does not fit the host |
| `STS-AUTHN-0035` | the signature counter did not go up (a possibly cloned authenticator) |
| `STS-AUTHN-0044` | passkeys are off in this realm (`webauthn.enabled`): no new passkey is registered, and one already held goes on working |
| `STS-AUTHN-0045`, `0046` | a passkey was refused as a first factor (`webauthn.primaryAllowed`) or as a second factor (`webauthn.mfaAllowed`) |
| `STS-AUTHN-0531` | a passkey was not registered: the realm accepts a passkey neither as a first nor as a second factor |
| `STS-AUTHN-0067` | the person already holds `webauthn.maxKeysPerPerson` passkeys |
| `STS-AUTHN-0070` | removing the passkey would remove the person's last way in |
| `STS-AUTHN-0171` | a passwordless sign-in, where a second factor is required |
| `STS-AUTHN-0204` | a request demanded a passkey and got something else |
| `STS-AUTHN-0206` | product mode: passwordless sign-in for a person with no passkey |
| `STS-AUTHN-0228` | the passkey's algorithm was not one of those offered |
| `STS-AUTHN-0294` | a passkey with an insecure algorithm (`RS1`) |
| `STS-AUTHN-0303` | the passkey's user handle is not the one it was registered under |
| `STS-AUTHN-0309` | a passkey policy was not saved: a field missing or not one of its values, a hint list that contradicts its request, or a `clientRules` rule that could not be read |
| `STS-AUTHN-0312`, `0313` | a synced passkey, where only device-bound ones are accepted (registration, sign-in) |
| `STS-AUTHN-0314`, `0315` | a security key's PIN is shorter than the minimum (registration, sign-in) |
| `STS-AUTHN-0316`, `0317` | the attestation rules refused the passkey at sign-in, or could not be checked |
| `STS-AUTHN-0320`, `0321` | an enterprise security key whose serial is not the person's, or unreadable |
| `STS-AUTHN-0322` | a realm's own issuance policy refused the passkey without a code of its own |
| `STS-AUTHN-0333` | a username was given where only a usernameless passkey sign-in is allowed |
| `STS-AUTHN-0350`, `0351`, `0352` | a passkey lane was refused: unknown, not offered here, or no ML-DSA available |
| `STS-AUTHN-0353` | `webauthn.pqcAlongsideClassical` and `webauthn.pqcOnly` cannot both be on |
| `STS-AUTHN-0354` | the typed username ends in `+ml-dsa`, `+ml-dsa-<n>` or `+pqc` |
| `STS-AUTHN-0355`, `0356` | a classical passkey, where a post-quantum one is required (registration, sign-in) |
| `STS-AUTHN-0357` | a passkey policy requiring post-quantum, while the realm offers no ML-DSA |
| `STS-AUTHN-0380`, `0381` | an account recovery refused, or limited to registering a new passkey |
| `STS-AUTHN-0411`, `0412` | a passkey whose attestation is not signed with what `attestationAlgorithms` allows (registration, sign-in) |
| `STS-AUTHN-0413`, `0414` | a passkey change could not be noted in the passkey report, or its daily recount failed; the report catches up at the next recount |
| `STS-AUTHN-0415` | the passkey report could not read the directory (503) |
| `STS-AUTHN-0416` | a passkey report filter was refused: two at once, or a profile or application that is not here |
| `STS-AUTHN-0419` | an RFC 4998 evidence record could not be renewed; the previous one is kept |
| `STS-AUTHN-0421`, `0422` | an evidence export named no passkey, or the passkey has no evidence record |
| `STS-AUTHN-0420` | a registration retried with the classical algorithms only, where a classical passkey is not allowed |
| `STS-AUTHN-0430`, `0431` | a passkey policy was not saved: `registrationMode` `classical-only` contradicts `postQuantumRequired` or `attestationAlgorithms`, or `pq-only` / `pq-first` would offer no ML-DSA |
| `STS-AUTHN-0432` | a passkey's algorithm is not one the selected profile offers at registration |
| `STS-AUTHN-0433` | the post-quantum lane was asked for where the profile's `registrationMode` is `classical-only` |
| `STS-AUTHN-0440` | an administrator's passkey enrolment, where the person's profile has `adminEnrolment` off. `0441`–`0448` are the other refusals of that ceremony |
| `STS-AUTHN-0450` | a passkey upgrade, where the realm cannot make an ML-DSA passkey. `0451`–`0458` are the other refusals of that ceremony |
| `STS-AUTHN-0459` | a sign-in that must earn `phrh`, where none of the person's passkeys for the step can earn it |
| `STS-AUTHN-0461` | a passkey policy requires a device-bound session while `authn.deviceBoundSessions` is off |
| `STS-AUTHN-0462` | an issuance waited for a device-bound session the browser skipped or did not finish |
| `STS-AUTHN-0470`–`0475` | the post-login activity policy or its step: see [Post-login activities](post-login-activities.md#error-codes-you-will-meet) |
| `STS-AUTHN-0476` | a passkey policy was not saved: `lanes` `both` with `registrationMode` `classical-only` |
| `STS-AUTHN-0477` | a learned client was not cleared: none named, or not on the list |
| `STS-AUTHN-0478` | the realm's learned clients are full of learned entries, so a new client was not counted (service log) |
| `STS-AUTHN-0490`–`0495` | the post-login activity's mail reminders: see [Post-login activities](post-login-activities.md#error-codes-you-will-meet) |
| `STS-AUTHN-0500` | `webauthn.attestation` `enterprise` with `webauthn.attestationEnterpriseRpIds` empty |
| `STS-AUTHN-0520`–`0522` | the day's passkey history row, its pruning, or one profile's count in it could not be written or read |
| `STS-ADMIN-0522` | an administrator's removal of a passkey was refused |

**When the browser shows no prompt at all**, the passkey step has a link,
**My browser did not ask — tell me why**, and a **Technical details** section
with the RP ID, the user-verification requirement and whether this step
registers or asks for a passkey. A wrong `webauthn.rpId` usually shows up this
way, because the browser refuses the ceremony before the service sees it.

## Limits, and what is not supported

* **An administrator enrols a passkey only when the passkey policy allows
  it** (`adminEnrolment`, off by default). The ceremony runs in the
  administrator's browser, against an authenticator they hold, and is
  verified as the person's own registration. Nothing made elsewhere can be
  imported. While the row is off, give the person an
  [activation link](#a-passwordless-account-from-the-start).
* **A passkey cannot be used at the password-only doors** (an LDAP bind,
  WS-Trust, SCIM, Shared Signals, EST Basic). A person with a second factor
  uses an [app password](authentication.md#the-password-only-doors-and-app-passwords)
  there.
* **`webauthn.authenticatorAttachment` and the hints are not enforced.** Use
  the passkey policy's `backupEligibility` or the attestation settings to
  enforce what kind of passkey is accepted.
* **A passkey with the username typed is one factor** (`acr "1"`), whatever
  user verification the authenticator did. Only the usernameless sign-in, which
  requires user verification, records two.
* **A minimum PIN length is reported only by security keys configured to tell
  this service.** Platform authenticators and synced passkeys report nothing.
* **SAML honours the EAP class URIs.** A SAML 2.0 `RequestedAuthnContext`,
  or SAML 1.1's non-spec `authnContextClassRef` parameter, naming only
  `phr` or only `phrh` is the same demand as `acr_values`. When the request
  does not name them, the assertion's class is unchanged. A WS-Federation
  `wauth` naming one of those URIs, and a GNAP `interact.acr` of `phr` or
  `phrh`, are the same demand. With `acr_values=phrh`
  (or a required detail acr of `phrh`), the passkey step offers only
  passkeys whose recorded attestation is trusted and whose backup
  eligibility is clear, and says so before the ceremony when none of the
  held keys can earn it. A usernameless sign-in has no list to narrow and
  is still refused after the ceremony.
* **Only some authenticators make ML-DSA passkeys**, and the service cannot
  tell beforehand which: WebAuthn has no way to ask. It helps after a
  failure (the classical retry), leaves ML-DSA out for clients known to fail
  (`clientRules` and learned clients), and lets you measure your own realm.
  See [Where ML-DSA passkeys are expected to work](#where-ml-dsa-passkeys-are-expected-to-work).
* **A post-quantum attestation has been tested only with a chain made for
  the test.** No real authenticator's post-quantum attestation has been
  tried; the attestation algorithms are recorded and enforced as WebAuthn
  and the ML-DSA certificate profile describe them.
* **A ceremony row records the browser's error name, never its message.**
  When a browser declines a registration, the row keeps the error's name
  from a fixed list and the client capabilities it reported, and the pending
  ceremony stays available for its retry.
* **An in-place upgrade can leave the classical credential only on this
  service.** The authenticator may replace the credential it holds as soon
  as it creates the new one, which can be before this service has accepted
  the registration. A registration that fails after that leaves the
  classical passkey here and none on that device
  ([Upgrading a classical passkey](#upgrading-a-classical-passkey)).
* **A person cannot upgrade a passkey on `/portal/keys`.** The upgrade runs
  at a sign-in, when the
  [post-login activity](#post-login-activities-moving-people-to-post-quantum-passkeys)
  asks for it, or from the console. The refusal page shown when a
  post-quantum passkey is required links to adding one on `/portal/keys`.
* **Device Bound Session Credentials** (binding the session cookie to the
  browser) are a separate, optional feature. A passkey profile can require
  a bound session (`deviceBoundRequired`), and only while
  `authn.deviceBoundSessions` is on. See
  [Sessions](sessions.md#binding-the-cookie-to-the-browser-device-bound-session-credentials).
* **The FIDO Alliance's conformance tools have not been run.** The relying
  party is covered by this project's own ceremony and attestation tests
  ([Conformance suites](conformance.md)).

## Related

* [Authentication](authentication.md): the sign-in service, passwords,
  TOTP, recovery codes, and the full reasoning behind passkeys
* [Security profiles](oauth-security.md): `acr_values`, step-up and
  phishing-resistant sign-in
* [Applications](applications.md): `appAuthnMechanism` and `appMfaMechanism`
* [Devices](devices.md): linking a platform passkey to a registered device,
  and a remembered browser skipping the second factor
* [Risk scoring](risk-scoring.md): the FIDO metadata, and compromised
  authenticator models
* [XACML 3.0 and ALFA](xacml.md) and [Configuring XACML](configure-xacml.md):
  the issuance policy that decides passkey questions
* [CAEP events](caep-events.md): what a passkey added, removed or refused
  sends
* [Trust realms](trust-realms.md), [Sessions](sessions.md),
  [Error codes](error-codes.md)
