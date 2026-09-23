---
title: Authentication
---

# The sign-in service

Every browser protocol in iya-sts — OAuth 2.0 and OpenID Connect, SAML 2.0 and
1.1, WS-Federation, the admin console and the user portal — sends a person who
is not signed in to **one sign-in service at `/authn`**. That service owns the
**session**, and every token or assertion a protocol issues is drawn from it.
Beside the password it offers three second factors: security keys as a
[WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) relying party, an
authenticator app ([RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) TOTP),
and single-use recovery codes. Each [trust realm](trust-realms.md) has its own
sign-in screen, sessions and settings.

## Features

### The sign-in screen and the session

A protocol endpoint that needs a person saves its request and redirects to
`/authn/login?authn={id}`. When the person has signed in, the browser is sent
back to the original request (with a 303), and the protocol answers it as its
specification says. The sign-in service never reads a protocol's own
parameters. Cancel sends the calling protocol `access_denied`, which it turns
into its own kind of refusal. `/authn/login` is not a page to visit directly:
it needs a pending request.

What a successful sign-in produces is a **session**, an internal record that
belongs to no protocol:

* a **subject**, `urn:uuid:<entryUUID>`, the person's directory entry
  identifier, which never changes, even when the entry is renamed;
* a list of **authentication events**: when, how (`amr`, `acr`), and through
  which door;
* a stable **`sid`**, and a cookie handle that rotates on every
  re-authentication.

An ID Token, a SAML `AuthnStatement` or a WS-Federation token is rendered
*from* the session and carries its `sid` or `SessionIndex`. A re-authentication
by the same person (`prompt=login`, `max_age`, SAML `ForceAuthn`, RFC 9470
`acr_values`) adds an event to the session. A different person replaces the
session. A signed-in session needs a directory entry for the person; a
sign-in whose person has none is refused (`STS-AUTHN-0180`).

[Sessions](sessions.md) defines the record in full, with its lifetime, idle
timeout and where it is visible. [Signing out](signing-out.md) covers how one
ends.

### Other ways to establish a session

Other doors end in the same session:

| Door | Page |
|---|---|
| a federation partner's button, or an automatic redirect to one | [Federation](federation.md) |
| `/authn/spnego`, a Kerberos ticket | [Kerberos](kerberos.md) |
| `/authn/wallet`, a verifiable credential | [OpenID4VP](oid4vp.md#signing-in-with-a-wallet) |
| `GET /tls/sign-in`, a verified client certificate | [TLS](tls.md) |

With `authn.unauthenticatedSessions` on, a third button, **Continue without
signing in**, starts a real session for the stable `anonymous` principal. The
session is marked `authenticated: false`, with empty `amr` and `acr "0"`. It
satisfies an application that admits everybody and is refused by one that
requires an authenticated user. It is not Cancel: the flow continues.

### Passwords

In **development mode** no password is checked: any password except the
reserved string `invalid` is accepted, and the name typed becomes the identity.
In **product mode** every presented password is verified against the scrypt
hash on the person's entry, and a person with no stored password cannot sign
in. Attempts are rate-limited per identity and per address, across the
cluster (`security.rateLimit*`).

* **Password policy.** A realm's policy is a directory entry drawn at
  *Directory → Policies* (`/admin/policies`): minimum length (12), symbols (1),
  an uppercase letter, a digit, and none of the last five passwords. It is
  enforced in product mode wherever a password is set, and it shapes every
  password the service generates.
* **Forced change.** `pwdReset: TRUE` on an entry (from
  [draft-behera-ldap-password-policy](https://datatracker.ietf.org/doc/html/draft-behera-ldap-password-policy))
  means the password must be changed before it is used. The sign-in screen
  draws `/authn/password-change` in place of a session, and after the change
  the sign-in continues, second factor included. Every other door that takes a
  password refuses the account until then (product mode).
* **Reset link.** **Send a reset link** on a person's `/admin/users` page (or
  `POST /admin-api/users/issue-password-reset`) removes the current password,
  signs the person out everywhere, and issues a single-use link to
  `/portal/reset-password`. The link is valid for
  `security.passwordResetTtlMinutes`, stored hashed, and either shown to the
  operator to hand over or — with **Mail the link** ticked, or `deliver:
  "mail"` — mailed to the address on the person's entry and never shown
  ([mail](mail.md)).
* **Forgot your password?** Where a mail transport is configured and the mode
  verifies passwords, the sign-in screen links to `/portal/forgot-password`: a
  person names their account and a single-use reset link is mailed to its
  (verified, by default) address. The answer is the same whether or not the
  account exists, and the current password keeps working until the link is
  used ([mail](mail.md)).
* **Activation link.** A new account may be given a single-use activation link
  to `/portal/activate` (`security.activationTtlMinutes`), where the person sets
  a password or enrols a security key or an authenticator app.
* A person changes their own password at `/portal/password`; an operator sets
  one with `POST /admin-api/users/set-password`.

### WebAuthn

Security keys and passkeys, as a WebAuthn Level 3 relying party over FIDO
CTAP2. A key is enrolled in one of two **roles**:

* **`mfa`** — a second factor after a password: `amr ["pwd","hwk"]`,
  `acr "mfa"`;
* **`primary`** — the only credential, with no password read (the
  passwordless box): `amr ["hwk"]`, `acr "1"`. That is **one factor**, even
  with `webauthn.userVerification` set to `required`, because RFC 8176 has no
  value this service could honestly assert for "the authenticator verified the
  user".

The ceremony is `/authn/webauthn`. It is one of the few pages here with a
script (`/authn/webauthn.js`), because a WebAuthn ceremony is a browser API
call. **Registration and every assertion are verified in both modes**: the
challenge, the origin, the RP ID hash, the flags, the signature over
`authenticatorData ‖ SHA-256(clientDataJSON)` against the registered COSE key
(ES256, ES384, ES512, EdDSA, RS256, RS384, RS512, PS256, PS384, PS512, and
ML-DSA-44/65/87 from RFC 9964), and a signature counter that must go up. A
registration is also held to section 7.1's remaining checks: the credential's
algorithm must be one that was offered, its id at most 1023 bytes, and the
backup state flag set only where the credential is backup eligible. Across a cluster, each assertion's challenge is claimed once and
each credential id can be registered once.

**The attestation statement is verified under `webauthn.attestationPolicy`**
(#105): in product mode by default (`verify-if-present`), in development when
the realm asks. All eight formats of WebAuthn Level 3 section 8 — `packed`,
`tpm`, `android-key`, `android-safetynet`, `fido-u2f`, `none`, `apple` and
`compound` — are verified by their own procedures; the certificate chain is
checked against `webauthn.attestationTrustAnchors` and the attestation roots
the FIDO Metadata Service lists for the model (the MDS3 BLOB is uploaded on
Monitoring → Risk or downloaded from `risk.mdsUrl`), revocation is consulted,
and a model MDS reports REVOKED, USER_VERIFICATION_BYPASS or KEY_COMPROMISE is
refused. `none` and self attestation are accepted and recorded as untrusted —
synced passkeys send `none` — unless the realm is `require-trusted` or names an
AAGUID allow-list, a certification level or FIPS, each of which demands a
trusted statement. What each key's statement proved is shown beside it on
`/portal/keys`, on its `/admin/users` row and in `GET /admin-api/users`.
**`webauthn.userVerification` is the one ceremony option
that is enforced**, because the UV flag sits inside the bytes the authenticator
signed. The others are requests to the browser, and what came back is recorded
(the attachment, and whether the credential is discoverable, from `credProps`).

The RP ID is the host the service was reached on, unless `webauthn.rpId` widens
it to a registrable domain suffix. The accepted origins are derived from the
same address unless `webauthn.allowedOrigins` lists them.

**Where a key is enrolled:**

* `/portal/keys`, signed in, up to `webauthn.maxKeysPerPerson` keys, in either
  role;
* an activation link;
* the sign-in screen's second-factor box, which enrols on first use, but only
  for somebody who holds **no** second factor yet. Otherwise anybody who knew
  the password could register their own authenticator.

A person removes a key on `/portal/keys`, and an operator on the person's
`/admin/users` page (`POST /admin-api/users/clear-key`).

### TOTP MFA

An authenticator app as a second factor: RFC 6238 over
[RFC 4226](https://www.rfc-editor.org/rfc/rfc4226). It is typed into a form,
so it works from a phone, a script or a test job, and the code page
`/authn/totp` has no script.

* **Enrolment** happens on `/portal/mfa`, on an activation link, or at
  `/authn/mfa-setup` when a second factor is required. It is two steps. The
  page shows a QR code (a server-drawn SVG) and the base32 secret written out.
  Nothing is written to the entry until a code proves the app has the secret,
  and an unconfirmed secret expires after `totp.enrolmentTtlMinutes`.
* **The code is verified for real, in both modes**, against the secret and the
  clock with `totp.window` steps of skew either side. A code is accepted
  **once** (RFC 6238 section 5.2): the code that confirmed the enrolment cannot
  also sign anybody in, and a replay is refused as a replay, not as a wrong
  code. Wrong codes are rate-limited, and a wrong code keeps the step so the
  person can try again.
* The session says `amr ["pwd","otp"]`, `acr "mfa"`.
* **It can never be a first factor.** This service holds the same secret the
  app does, which proves somebody still has the app but is not something to
  hang an account on.
* **One secret per person**; enrolling again replaces it. In product mode the
  secret is sealed under the key-encryption key. In development it is stored as
  base32, because that mode's key does not survive a restart.
* All three digests are implemented, but **leave `totp.algorithm` at `SHA1`**:
  several popular apps ignore the parameter and always compute SHA-1. The
  digest, the digits, the period and the secret length apply to **new**
  enrolments only. `totp.window` applies to everybody.
* A person removes their own app on `/portal/mfa`; an operator clears it on the
  person's `/admin/users` page (`POST /admin-api/users/clear-totp`).

### Recovery codes

A set of single-use codes for when the second factor is not to hand. No
specification defines a recovery code, so every rule here is this service's
own.

* **A person generates their own set** on `/portal/mfa`. It is shown **once**,
  and stored only when they confirm they have saved it, as one scrypt hash per
  code. Nothing can show a stored code again. An unconfirmed set waits
  `backupCodes.pendingTtlS` and changes nothing if it expires.
* **Generating again replaces** the whole set. A set is never topped up.
* The default is ten codes of ten characters: fifty bits each, from a 32
  character alphabet with no confusable pairs, printed in groups
  (`A2CDE-FGH3J`). Dashes and spaces are ignored when a code is typed.
* A code is used at `/authn/backup-code`, reached only from a link on the TOTP
  or security-key step, drawn last. It is **checked and spent in both modes**,
  and a spend that cannot be written refuses the sign-in, because a code that
  cannot be marked spent would be a permanent credential. The session says
  `amr ["pwd","otp"]`, `acr "mfa"`. The audit row and `/admin/sessions` say
  that it was a recovery code.
* A recovery code is **never the factor a sign-in asks for**, and holding only a
  set does not make a second factor required. A person who holds a second
  factor and no set is prompted to generate one.
* Nobody but the person sees the codes. The console and the API report counts.
  An operator can delete a set (`POST /admin-api/users/clear-backup-codes`).

### Which second factor is asked for

The screen decides from **what the person holds** first, and only then from the
checkboxes. A checkbox cannot opt out of a factor the account is configured
for.

| The person | What is asked for |
|---|---|
| holds nothing, box unticked | nothing (one factor) |
| holds nothing, second-factor box ticked | the security-key ceremony, which enrols on first use |
| holds an `mfa` key | the key |
| holds an authenticator app | the code |
| holds both | the key, with a link to the code |
| holds a `primary` key, passwordless box ticked | the passwordless ceremony |

A relying party can **demand** more. `acr_values` that only two factors can
meet (`mfa`, `hwk`, `phr`, `phrh`) ticks the second-factor box and refuses the
passwordless path server-side. A demand for a hardware key (RFC 8176 `hwk`, or
a WS-Federation `wauth` for a hardware token) allows only a security key, alone
or after a password, and refuses the code and recovery-code steps
(`STS-AUTHN-0204`). See [OAuth security profiles](oauth-security.md) for
RFC 9470 step-up.

### `authn.mfaRequired`

With `authn.mfaRequired` on, everyone who signs in at this realm's screen must
present a second factor. **Require MFA** on a person's `/admin/users` page
(`stsMfaRequired`) does the same for one person. A person who holds none is
sent to `/authn/mfa-setup` after the password to enrol an authenticator app or
a security key, and no session is started until they do. A passwordless sign-in
is refused (`STS-AUTHN-0171`). If both mechanisms are switched off, the sign-in
is refused and the settings are named (`STS-AUTHN-0172`).

**This screen is the only door that can ask for the second factor.** A
federated assertion, a SPNEGO ticket or a Kerberos AS-REQ, and a TLS client
certificate do not reach it, and an existing session is not ended.

### The password-only doors, and app passwords

An LDAP bind, a WS-Trust UsernameToken, SCIM, Shared Signals and EST Basic take
a password and nothing else, so they cannot ask for a second factor. **In
product mode they refuse the own password of a person who holds a second factor
or of whom one is required** (by the realm or on their entry) — answered
exactly as a wrong password, and counted against the rate limit as one; the
log and the audit row say `STS-AUTHN-0213`. Development accepts it, as it
accepts every password.

What such a person uses there is an **app password**:

* made on `/portal/app-passwords` after signing in, or by an administrator on
  the person's `/admin/users` page or with `POST
  /admin-api/users/create-app-password`;
* generated here — twenty-four characters, printed in six groups of four —
  shown **once**, and stored as a scrypt hash on the entry;
* named, and scoped to one or more of `ldap`, `wstrust`, `scim`, `ssf` and
  `est`. It is accepted at those doors only, and **never at `/authn/login`** or
  any browser sign-in (`STS-AUTHN-0214` where it is presented elsewhere);
* one factor: the door records that an app password was used;
* revocable one at a time on the same pages or with `POST
  /admin-api/users/revoke-app-password`, with a CAEP `credential-change` for
  each make and revoke. Its last use is recorded. A disabled account refuses
  it; a password reset leaves it working.

`authn.passwordAloneDoors` lists doors that accept the password alone anyway.
**Each door listed is one factor for every such person** — use it only for a
client that cannot be given an app password. `appPasswords.enabled` and
`appPasswords.maxPerPerson` (10) govern making them.

### Disabling an account

**Disable** on `/admin/users` (`POST /admin-api/users/disable`), a SCIM
`active: false`, or an LDAP write of the attribute sets `pwdAccountLockedTime`
(from draft-behera-ldap-password-policy) on the entry. It then:

* ends everything the person holds, as a global sign-out does: sessions, tokens
  and codes, directory connections, and wallet credentials, each with its CAEP
  and back-channel logout consequences;
* refuses every door, **in both modes**: any password (`STS-AUTHN-0200`), any
  new session (`STS-AUTHN-0201`), a session they already hold, every token or
  assertion issuance, a Kerberos request, and the management API.

The sign-in screen answers "Authentication failed", the same words as a wrong
password, so it does not reveal that the account exists. **Enable** clears the
lock and ends nothing.

## Development and product mode

| | Development | Product |
|---|---|---|
| Passwords | Not checked, except the reserved `invalid` | Verified against the stored hash; a person with none cannot sign in |
| The password policy | Not enforced (history is still recorded) | Enforced wherever a password is set |
| `pwdReset` | Handled at the sign-in screen only | Also refused at every other password door (`STS-AUTHN-0142`) |
| Passwordless box for somebody with no primary key | Enrols a key on the spot: the first person to claim a name gets it | Refused before a step is minted (`STS-AUTHN-0206`), with the same words whether or not the name exists |
| A `webauthn.rpId` that does not fit the host | The host is used, and the log says why | The ceremony is refused, naming the problem |
| The TOTP secret on the entry | Stored as base32 | Sealed under the key-encryption key |
| TOTP codes, recovery codes, WebAuthn ceremonies, disabled accounts | Verified | Verified |

A second factor is still asked for only at the sign-in screen in product mode.
See [What is not checked](what-is-not-checked.md).

## Configuration

### Sign-in and session settings

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `authn.sessionLifetimeS` | `STS_AUTHN_SESSION_LIFETIME_S` | `3600` | yes | How long a sign-on session lasts from its creation; absolute for a browser. |
| `authn.sessionIdleTimeoutS` | `STS_AUTHN_SESSION_IDLE_TIMEOUT_S` | `0` | yes | How long a session may go unused before it ends; `0` means no idle timeout. |
| `authn.sessionSweepS` | `STS_AUTHN_SESSION_SWEEP_S` | `30` | yes | Interval of the scheduler job that ends expired sessions and reports them; `0` switches it off. |
| `authn.pendingTtlS` | `STS_AUTHN_PENDING_TTL_S` | `600` | yes | How long an interrupted request waits at the sign-in screen. |
| `authn.mfaStepTtlS` | `STS_AUTHN_MFA_STEP_TTL_S` | `300` | yes | How long a person who passed the password step has to present a second factor. |
| `authn.mfaRequired` | `STS_AUTHN_MFA_REQUIRED` | `false` | yes | Require a second factor of everybody signing in at this realm's screen. |
| `authn.unauthenticatedSessions` | `STS_AUTHN_UNAUTHENTICATED_SESSIONS` | `false` | yes | Show *Continue without signing in*, which starts an unauthenticated session. |
| `security.rateLimitWindowS` | `STS_SECURITY_RATE_WINDOW_S` | `60` | yes | The length of a fixed rate-limit window. |
| `security.rateLimitPerIdentity` | `STS_SECURITY_RATE_PER_IDENTITY` | `5` | yes | Credential attempts one identity may make in a window, from any address. |
| `security.rateLimitPerAddress` | `STS_SECURITY_RATE_PER_ADDRESS` | `20` | yes | Credential attempts one address may make in a window, for any identity. |
| `security.activationTtlMinutes` | `STS_SECURITY_ACTIVATION_TTL_MINUTES` | `1440` | yes | How long an activation link stays valid. |
| `security.passwordResetTtlMinutes` | `STS_SECURITY_PASSWORD_RESET_TTL_MINUTES` | `60` | yes | How long an administrator's password reset link stays valid. |
| `security.passwordHashLogN` | `STS_SECURITY_PASSWORD_HASH_LOG_N` | `15` | yes | scrypt cost (as a power of two) for newly stored passwords, secrets, tokens and recovery codes; floor 14. |
| `security.passwordHashR` | `STS_SECURITY_PASSWORD_HASH_R` | `8` | yes | scrypt block size for a newly stored hash. |
| `security.passwordHashP` | `STS_SECURITY_PASSWORD_HASH_P` | `1` | yes | scrypt parallelism for a newly stored hash. |
| `credentials.factorScanLimit` | `STS_CREDENTIALS_FACTOR_SCAN_LIMIT` | `5000` | yes | How many entries the second-factor columns on `/admin/users` and `GET /admin-api/mfa` read before they stop. |

### WebAuthn settings

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `webauthn.enabled` | `STS_WEBAUTHN_ENABLED` | `true` | yes | Offer WebAuthn ceremonies at all; off does not remove enrolled keys. |
| `webauthn.rpName` | `STS_WEBAUTHN_RP_NAME` | `Mock authorization server` | yes | The `rp.name` a browser shows; no security meaning. |
| `webauthn.rpId` | `STS_WEBAUTHN_RP_ID` | *(empty: the host)* | yes | Widen the RP ID to a registrable domain suffix of the host. |
| `webauthn.allowedOrigins` | `STS_WEBAUTHN_ALLOWED_ORIGINS` | *(empty: derived)* | yes | The origins a ceremony is accepted from; empty derives one from the address. |
| `webauthn.algorithms` | `STS_WEBAUTHN_ALGORITHMS` | `ES256,RS256` | yes | `pubKeyCredParams`, in preference order. |
| `webauthn.userVerification` | `STS_WEBAUTHN_USER_VERIFICATION` | `preferred` | yes | Whether the authenticator must verify the person; `required` is enforced. |
| `webauthn.attestation` | `STS_WEBAUTHN_ATTESTATION` | `direct` | yes | Attestation conveyance asked for; no statement is verified. |
| `webauthn.timeoutMs` | `STS_WEBAUTHN_TIMEOUT_MS` | `60000` | yes | The `timeout` hint handed to the browser. |
| `webauthn.authenticatorAttachment` | `STS_WEBAUTHN_ATTACHMENT` | `any` | yes | `platform`, `cross-platform` or `any`; a filter in the browser. |
| `webauthn.residentKey` | `STS_WEBAUTHN_RESIDENT_KEY` | `discouraged` | yes | Whether the credential should be discoverable on the authenticator. |
| `webauthn.credProps` | `STS_WEBAUTHN_CRED_PROPS` | `true` | yes | Ask the browser to report whether the credential is discoverable. |
| `webauthn.primaryAllowed` | `STS_WEBAUTHN_PRIMARY_ALLOWED` | `true` | yes | Allow a key to be the only credential (passwordless). |
| `webauthn.mfaAllowed` | `STS_WEBAUTHN_MFA_ALLOWED` | `true` | yes | Allow a key to be enrolled as a second factor. |
| `webauthn.maxKeysPerPerson` | `STS_WEBAUTHN_MAX_KEYS` | `10` | yes | How many keys one person may hold; refuses the enrolment, never a sign-in. |

### TOTP settings

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `totp.enabled` | `STS_TOTP_ENABLED` | `true` | yes | Allow new authenticator-app enrolments; off does not disable existing ones. |
| `totp.issuer` | `STS_TOTP_ISSUER` | *(empty: the realm's host)* | yes | The issuer name an app shows beside the account. |
| `totp.algorithm` | `STS_TOTP_ALGORITHM` | `SHA1` | yes | The HMAC digest, for new enrolments. |
| `totp.digits` | `STS_TOTP_DIGITS` | `6` | yes | Digits per code, for new enrolments. |
| `totp.period` | `STS_TOTP_PERIOD` | `30` | yes | Seconds per time step, for new enrolments. |
| `totp.window` | `STS_TOTP_WINDOW` | `1` | yes | Steps of clock skew accepted either side; applies to everybody. |
| `totp.secretBytes` | `STS_TOTP_SECRET_BYTES` | `20` | yes | Length of a new shared secret. |
| `totp.enrolmentTtlMinutes` | `STS_TOTP_ENROLMENT_TTL_MINUTES` | `10` | yes | How long a shown but unconfirmed secret stays available. |

### Recovery code settings

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `backupCodes.enabled` | `STS_BACKUP_CODES_ENABLED` | `true` | yes | Allow a person to generate a set; off does not invalidate a set already held. |
| `backupCodes.count` | `STS_BACKUP_CODES_COUNT` | `10` | yes | Codes in a set. |
| `backupCodes.length` | `STS_BACKUP_CODES_LENGTH` | `10` | yes | Characters per code, from a 32-character alphabet. |
| `backupCodes.groupSize` | `STS_BACKUP_CODES_GROUP_SIZE` | `5` | yes | How a code is broken up for reading; `0` prints it unbroken. |
| `backupCodes.pendingTtlS` | `STS_BACKUP_CODES_PENDING_TTL_S` | `900` | yes | How long a generated set waits for the person to confirm they saved it. |

See [Configuration](configuration.md) for how a value is resolved. The
settings are on their console pages (below) in the realm they apply to, and can
be changed with `POST /admin-api/config/set`.

## Design decisions

* **The sign-in service belongs to no protocol, and it owns the session.** Two
  session stores would each look correct on their own and never see each
  other, and single sign-on would silently stop being single.
* **The session is an internal record, not an ID Token.** An ID Token is a
  statement *to* one relying party. A session is addressed to nobody, so making
  a token the anchor would push OAuth's naming and lifetimes into every SAML and
  WS-Federation sign-in.
* **A re-authentication adds an event; a different person replaces the
  session.** Treating a step-up like a new sign-in used to end derived sessions,
  lose the list of relying parties to sign out, and revoke other clients'
  refresh tokens.
* **The cookie handle rotates on every re-authentication, and `sid` never
  does.** Rotation is OWASP's rule for a change of privilege. A stable `sid` is
  what logout and `/admin/sessions` need.
* **TOTP codes, recovery codes and WebAuthn ceremonies are verified even in
  development.** A permissive one-time-password verifier is a broken verifier,
  with nothing left for an integrator to test. What development relaxes is the
  password in front of them.
* **What a person holds decides the second factor; a checkbox cannot.** A
  factor that can be opted out of is not a factor. For the same reason, the
  sign-in screen enrols a security key only for somebody holding no second
  factor at all.
* **A passwordless key is one factor.** `acr "mfa"` would claim more than
  anybody checked.
* **Settings that turn a mechanism off do not remove what people already
  hold.** Otherwise a switch would silently downgrade accounts to one factor,
  or lock out someone whose only credential is a primary key.
* **An authenticator app can never be a first factor.** The service holds the
  same secret.
* **Recovery codes are generated on request, shown once and hashed.** Hashing
  is only possible while a code is in the clear, so an automatic issue would
  hash a list nobody ever saw. A prompt nudges people who hold a second factor
  and no set.
* **The code screens refuse wrong codes by name.** The person has already
  given a first factor, so there is nothing to enumerate, and "already used"
  and "wrong" call for different actions.
* **In product the sign-in screen enrols no primary key.** Before 2026-09-21 it
  did, and anybody who knew a username could take an account that had no key.
* **A disabled account is refused everywhere, not only at the password.** The
  lock is `pwdAccountLockedTime`, which LDAP tooling already understands, and
  it is enforced more widely than the draft requires, which is the safe
  direction for a lock.
* **A reset link or an activation link is mailed only to the address on the
  person's entry** — never to an address a request supplies — and a
  self-service reset only to a VERIFIED one by default
  (`mail.resetRequiresVerifiedAddress`). Both links are single-use and stored
  hashed; an operator may still be shown one to hand over instead
  ([mail](mail.md)).

## In the running service

* **Protocols → WebAuthn** (`/admin/webauthn`): the thirteen ceremony, CTAP2
  and policy settings, and `authn.mfaRequired`. API: `GET /admin-api/webauthn`.
* **Protocols → TOTP MFA** (`/admin/totp`): the eight RFC 6238 parameters, and
  `authn.mfaRequired`. API: `GET /admin-api/totp`.
* **Protocols → Recovery codes** (`/admin/backup-codes`): the four settings and
  what a code is made of. API: `GET /admin-api/backup-codes`.
* **Users** (`/admin/users`): per person, who holds which factor and how many
  recovery codes are left, with **Require MFA**, **Send a reset link**, set
  password, clear the authenticator app, a key or the recovery codes,
  **Disable** and **Enable**, and the person's **app passwords** — make one
  (shown once) or revoke one. API: `POST /admin-api/users/{action}`, the
  roster at `GET /admin-api/mfa`, and one person's app passwords, paged, at
  `GET /admin-api/users/app-passwords`.
* **Directory → Policies** (`/admin/policies`): the password policy.
* **Sessions** (`/admin/sessions`): every live session, with how it was
  established.
* **The user portal**: `/portal/mfa` (authenticator app, recovery codes),
  `/portal/keys` (security keys), `/portal/app-passwords` (app passwords for
  the password-only doors), `/portal/kerberos` (a Kerberos keytab from your own
  password), `/portal/password`, `/portal/activate` and
  `/portal/reset-password`; and `/portal/consents`, where a person withdraws
  what they agreed an application may ask for, revoking what it was issued
  under it (see [OAuth 2.0 and OpenID Connect](oauth-oidc.md#withdrawing-consent)).
  `/portal/delegate` names the one party who may act for you — it is the
  `may_act` claim of your access tokens (see
  [OAuth 2.0 and OpenID Connect](oauth-oidc.md#token-exchange-rfc-8693)).
* Failures are recorded under `STS-AUTHN-NNNN` codes; see
  [Error codes](error-codes.md).

## Related

* [Sessions](sessions.md) and [Signing out](signing-out.md)
* [OAuth security profiles](oauth-security.md), for RFC 9470 step-up and
  `acr_values`
* [OpenID4VP](oid4vp.md), for signing in with a wallet
* [Kerberos](kerberos.md), [Federation](federation.md) and [TLS](tls.md), for
  the other sign-in doors
* [CAEP events](caep-events.md), for what a sign-in or sign-out sends
* [Trust realms](trust-realms.md)
* [Configuration](configuration.md)
* [What is not checked](what-is-not-checked.md)
