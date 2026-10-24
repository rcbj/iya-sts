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
| **role** | What a passkey is for: **`mfa`**, a second step after a password, or **`primary`**, the only credential (no password). The person chooses when they create it. |
| **usernameless** | Signing in with a passkey and no username typed. The passkey tells the service who the person is. This needs a *discoverable* (resident) credential. |
| **RP ID** | The domain a passkey is bound to. By default it is the host the service was reached on. |
| **user handle** | The random identifier a passkey is created under (64 bytes on the person's entry). It is never the username. |
| **attestation** | A statement from the authenticator, at registration, about what model it is (its **AAGUID**) and who made it. |
| **lane** | `classical` or `pqc`. Used only when [a classical and a post-quantum passkey side by side](#a-classical-and-a-post-quantum-passkey-side-by-side) is on. |

### Where things are

| What | Console | API |
|---|---|---|
| Every `webauthn.*` setting | **Protocols → WebAuthn** (`/admin/webauthn`) | `GET /admin-api/webauthn`; change one with `POST /admin-api/config/set` |
| The passkey policy | **Directory → Policies** (`/admin/policies`), **Passkey policy** tab, with the sub-tabs **Default**, **Named policies** and **New policy** | `GET /admin-api/policies` (the `passkey` member); `POST /admin-api/policies/save-passkey-policy` and `reset-passkey-policy` |
| The authentication policy (which sign-in methods are accepted, and whether a second factor is required) | **Directory → Policies**, **Authentication policy** tab | `GET /admin-api/policies` (the `authn` member); `POST /admin-api/policies/save-authn-policy` and `reset-authn-policy` |
| A person's passkeys | **Directory → Users** (`/admin/users`), the person's page, **Passkeys (WebAuthn)** | `GET /admin-api/users?user=<username>`; `POST /admin-api/users/{action}` |
| Who holds which factor, across the realm | **Directory → Users** | `GET /admin-api/mfa` |
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

A passkey has one of two roles, and the session records which:

| How the person signed in | `amr` | `acr` |
|---|---|---|
| a password, then a passkey in the `mfa` role | `["pwd","hwk"]` | `mfa` |
| a passkey in the `primary` role, with the username typed | `["hwk"]` | `1` (one factor) |
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
authentication policy's **Security key (second factor) — as a second factor**
row on (`securityKeySecondFactor`, default on).

**What the person does.** Either of these:

1. **On the portal.** Sign in, open `/portal/keys`, and under **Add a
   passkey**, **How will you use it?**, choose **As a second step after my
   password**. Then press **Create a passkey** (a passkey on this device or a
   phone) or **Use a security key**. The browser asks them to create the
   passkey. The page then offers to give it a nickname.
2. **At the sign-in screen.** Type the username and password and tick **Use a
   passkey as a second step (WebAuthn)**. If the person holds no second factor
   yet, this step registers a passkey. If they already hold any second factor,
   the screen does not register a new one here. (Otherwise anybody who knew
   the password could add their own authenticator.)

**From then on**, the person is asked for the passkey at every sign-in after
the password. They do not have to tick anything. What a person holds decides
the second factor, not a checkbox. See
[Which second factor is asked for](authentication.md#which-second-factor-is-asked-for).

**Check it.**
* On the person's page under **Directory → Users**, the **Passkeys (WebAuthn)**
  table lists the passkey with its role, algorithm and backup state.
* After a sign-in, **Monitoring → Sessions** shows the session, and the audit
  log's `session.start` row records `amr` `pwd, hwk`, `acr` `mfa`, and the
  passkey's algorithm (`credentialAlgorithm`).

### Signing in with a passkey instead of a password

**Settings.** On by default. It needs `webauthn.primaryAllowed` on (default
`true`) and the authentication policy's **Security key or passkey
(passwordless) — as a first factor** row on (`passkeyPrimary`, default on).

**What the person does.**
1. On `/portal/keys`, choose **Instead of my password** under **How will you
   use it?**, then **Create a passkey** or **Use a security key**.
2. At the sign-in screen, they can either:
   * press **Sign in with a passkey** with no username typed (see the next
     recipe), or
   * type the username and tick **Sign in with a passkey instead of a
     password**. The password field is then not read.

**Product mode never registers a passwordless passkey at the sign-in screen.**
A person who ticks the passwordless box and holds no `primary` passkey is
refused (`STS-AUTHN-0206`). In development mode the screen registers one on
the spot, so the first person to claim a username gets it. In product mode a
passwordless passkey is created on `/portal/keys` or through an
[activation link](#a-passwordless-account-from-the-start).

A person with no password can still hold a passkey in the `mfa` role, but it
signs nobody in on its own: the portal warns them.

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
* **Only a passkey in the `primary` role answers.** A passkey registered as a
  second step after a password does not.
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

An administrator **cannot create a passkey for somebody**: the ceremony runs in
the person's own browser against their own authenticator. What the
administrator gives them instead is a single-use **activation link**.

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
2. Under **2. A passkey**, choose **Use a passkey instead of a password**.
3. Press **Continue**, then create the passkey on the next screen.

The account is not set up, and the link is not used up, until the passkey is
created. To have both a password and a passkey as a second step, they fill in
the password and choose **Use a passkey as a second step, after the password
above**.

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
| `postQuantumAllowCredentials` | While a post-quantum passkey is required: name only the post-quantum passkeys at sign-in, or name them all and refuse a classical one with a page saying why. See [Narrow, or list and refuse](#narrow-or-list-and-refuse). |

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
  "credentialLabel":"","aggregateDevices":true,"postQuantumRequired":"off"}'

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
the post-quantum ones first:

* **Post-quantum (RFC 9964):** `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` (COSE
  -48, -49, -50).
* **Classical:** `ESP256`, `ES256`, `Ed25519`, `EdDSA`, `ESP384`, `ES384`,
  `ESP512`, `ES512`, `Ed448`, `ES256K`, `PS256`, `PS384`, `PS512`, `RS256`,
  `RS384`, `RS512`.

On **Protocols → WebAuthn**, each algorithm has a checkbox (offered or not)
and a number (its place in the order). A passkey whose algorithm was not
offered is refused at registration (`STS-AUTHN-0228`).

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
  passkey again, in the same role.
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
| `/portal/keys` | `webauthn.pqcOnly` is on, or the person's passkey policy has `postQuantumRequired: registration-and-sign-in` |
| the passkey step at sign-in | as above, or `postQuantumRequired` is `sign-in` for this application (the new classical passkey would not sign the person in) |

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

## A classical and a post-quantum passkey side by side

This section describes the setting `webauthn.pqcAlongsideClassical`,
added by [#643](https://github.com/rcbj/iya-sts/issues/643).

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

With the setting on, each new passkey is created in a **lane**:

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

It is a setting **per realm**, off by default.

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

Every place a passkey is created asks **Classical or post-quantum?** while the
setting is on. The choices are **A classical passkey** ("ES256 or RSA — what
nearly every authenticator can make") and **A post-quantum passkey** ("ML-DSA,
listed as a second account ending in +ml-dsa. Few authenticators can make one
yet.").

**On the portal**, to hold both:
1. Sign in and open `/portal/keys`.
2. Under **Add a passkey**, choose the role (**Instead of my password** or
   **As a second step after my password**).
3. Under **Classical or post-quantum?**, choose **A classical passkey**.
   Press **Create a passkey** or **Use a security key**, and create it.
4. Back on **Add a passkey**, choose the role again, then **A post-quantum
   passkey**, and create it with the same authenticator or another one.

The list now shows two passkeys. Under each one's **Details**, the
**Cryptography** row says `classical` or "post-quantum (ML-DSA), listed as a
second account ending in “+ml-dsa”", and the **Algorithm** row names the
algorithm.

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
  -d '{"action":"begin","role":"primary","kind":"passkey","lane":"pqc"}'
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
* **With the username typed**, the request lists all of the person's passkeys
  in the role being asked for, so the browser offers whichever one is
  present.
* **With no username**, the browser's account chooser shows both accounts
  (`alice` and `alice+ml-dsa…`). Either one names the same person.
* With the passkey policy's `aggregateDevices` off, a person with more than one
  passkey picks one from a list by its name first.

The audit log's `session.start` row records which kind was used:
`credentialAlgorithm` (for example `ML-DSA-65 (-49)`) and `credentialLane`
(`classical` or `pqc`).

`webauthn.maxKeysPerPerson` (default 10) counts **both lanes together**.

### Which browsers and authenticators can make an ML-DSA passkey

**Be prepared for most of them not to.** The service does not check this. It
offers ML-DSA in the post-quantum lane and verifies what comes back. If the
authenticator cannot make an ML-DSA passkey, the browser reports that the
ceremony failed and nothing is registered. The page then offers to try again
with a classical passkey, where one is allowed
([When the device cannot make an ML-DSA passkey](#when-the-device-cannot-make-an-ml-dsa-passkey)).

This project's own tests make ML-DSA-44 and ML-DSA-65 passkeys with a software
authenticator. Before you tell people to create a post-quantum passkey, try it
yourself with the authenticators and browsers they actually use.

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
* **Few authenticators make ML-DSA passkeys** (see above).
* **Requiring a post-quantum passkey at registration changes the question.**
  While `postQuantumRequired` is `registration-and-sign-in`, only the
  post-quantum lane is offered, and the pages do not ask.
* **The maximum counts both lanes.** A person at `webauthn.maxKeysPerPerson`
  cannot add the second kind until they remove one (`STS-AUTHN-0067`).
* **It cannot be combined with `webauthn.pqcOnly`** (`STS-AUTHN-0353`).

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

It applies to **both roles**: the passkey instead of a password, the passkey
after a password, and the usernameless sign-in.

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
their only way in stops working.

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
  last way in (`STS-AUTHN-0070`): no password and no other `primary` passkey.
* **An administrator**, on the person's page under **Directory → Users**, with
  **Remove** beside the passkey, or `POST /admin-api/users/clear-key` with
  `user` and `credentialId`.
* **Removing a passkey ends the sessions it signed in**, as the first factor
  or as the step after a password. The person's other sessions are kept. A
  CAEP `credential-change` is sent.

**An administrator's reset.** There is no self-service reset of a second
factor. On the person's page:
* **Disable passkeys as primary sign-in** (`disable-primary-keys`) removes
  every passkey that signs them in on its own. It is offered only while they
  have a password.
* **Disable all MFA** (`disable-mfa`) removes the authenticator app, every
  second-step passkey and the recovery codes.
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
| The passwordless box, for a name with no `primary` passkey | registers a passkey on the spot | refused (`STS-AUTHN-0206`) |
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
| `webauthn.algorithms` | `STS_WEBAUTHN_ALGORITHMS` | every algorithm the verifier knows, ML-DSA first |
| `webauthn.insecureAlgorithms` | `STS_WEBAUTHN_INSECURE_ALGORITHMS` | `false` |
| `webauthn.pqcOnly` | `STS_WEBAUTHN_PQC_ONLY` | `false` |
| `webauthn.pqcAlongsideClassical` | `STS_WEBAUTHN_PQC_ALONGSIDE_CLASSICAL` | `false` |
| `webauthn.postQuantumAllowCredentials` | `STS_WEBAUTHN_POST_QUANTUM_ALLOW_CREDENTIALS` | `narrow` |
| `webauthn.userVerification` | `STS_WEBAUTHN_USER_VERIFICATION` | `required` |
| `webauthn.attestation` | `STS_WEBAUTHN_ATTESTATION` | `direct` |
| `webauthn.attestationPolicy` | `STS_WEBAUTHN_ATTESTATION_POLICY` | `by-mode` |
| `webauthn.attestationTrustAnchors` | `STS_WEBAUTHN_ATTESTATION_TRUST_ANCHORS` | empty |
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

**Turning a setting off never removes passkeys people already hold.**
`webauthn.enabled`, `webauthn.primaryAllowed` and `webauthn.mfaAllowed` stop
*new* registrations. A passkey already registered goes on working, so that a
switch cannot silently drop an account to one factor or lock somebody out.

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
| `GET /admin-api/users?user=<name>` | one person, with each passkey's role, algorithm, lane, backup state, attestation and any policy refusal |
| `POST /admin-api/users/clear-key` | remove one passkey (`user`, `credentialId`) |
| `POST /admin-api/users/rename-key` | rename one passkey (`user`, `credentialId`, `label`; empty restores the default) |
| `POST /admin-api/users/disable-primary-keys` | remove every passkey that signs the person in on its own |
| `POST /admin-api/users/disable-mfa` | remove every second factor |
| `POST /admin-api/users/require-mfa`, `stop-requiring-mfa` | require a second factor of one person |
| `POST /admin-api/users/issue-activation` | a single-use activation link (`user`, optional `deliver: "mail"`) |
| `GET /admin-api/policies` | the passkey and authentication policies, with every field's current value |
| `POST /admin-api/policies/save-passkey-policy`, `reset-passkey-policy` | save a passkey policy (optionally named with `profile`), or remove it |
| `POST /admin-api/policies/save-authn-policy`, `reset-authn-policy` | save the authentication policy, or go back to inheriting |
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
| `STS-AUTHN-0044`, `0045`, `0046` | a passkey was not registered: passkeys are off, or not allowed in that role |
| `STS-AUTHN-0067` | the person already holds `webauthn.maxKeysPerPerson` passkeys |
| `STS-AUTHN-0070` | removing the passkey would remove the person's last way in |
| `STS-AUTHN-0171` | a passwordless sign-in, where a second factor is required |
| `STS-AUTHN-0204` | a request demanded a passkey and got something else |
| `STS-AUTHN-0206` | product mode: passwordless sign-in for a person with no `primary` passkey |
| `STS-AUTHN-0228` | the passkey's algorithm was not one of those offered |
| `STS-AUTHN-0294` | a passkey with an insecure algorithm (`RS1`) |
| `STS-AUTHN-0303` | the passkey's user handle is not the one it was registered under |
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
| `STS-AUTHN-0420` | a registration retried with the classical algorithms only, where a classical passkey is not allowed |
| `STS-ADMIN-0522` | an administrator's removal of a passkey was refused |

**When the browser shows no prompt at all**, the passkey step has a link,
**My browser did not ask — tell me why**, and a **Technical details** section
with the RP ID, the user-verification requirement and whether this step
registers or asks for a passkey. A wrong `webauthn.rpId` usually shows up this
way, because the browser refuses the ceremony before the service sees it.

## Limits, and what is not supported

* **An administrator cannot create a passkey for somebody.** The ceremony runs
  in the person's own browser. Use an activation link.
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
* **SAML and WS-Federation do not yet carry `phr` / `phrh`**, and a GNAP
  request cannot ask for them. With `acr_values=phrh`, the passkey step does
  not yet narrow the browser's choice to the passkeys that can earn it.
* **Only some authenticators make ML-DSA passkeys**, and the service cannot
  tell beforehand which. It helps after a failure instead (the classical
  retry).
* **Upgrading a classical passkey to a post-quantum one in place** is not
  built yet ([#939](https://github.com/rcbj/iya-sts/issues/939)). The refusal
  page links to registration only.
* **Device Bound Session Credentials** (binding the session cookie to the
  browser) are a separate, optional feature, and an application cannot yet
  require them. See
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
