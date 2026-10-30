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

For OAuth, the authorization endpoint is entered twice:

```
GET  /oauth2/authorize?response_type=code&client_id=…      no session
  -> /authn/login?authn=8mQ2…                              the screen
POST /authn/login   username=alice                         Set-Cookie: sts_session=…
  303 -> /oauth2/authorize?response_type=code&client_id=…  the ORIGINAL request
  -> http://localhost:3000/callback?code=…                 answered per spec
```

* **The return URL is the interrupted request, whole, minus `prompt`.**
  `prompt` has been honoured by then and would otherwise prompt for ever.
  Everything else goes back untouched, because the second pass is where the
  PKCE challenge, the nonce, `authorization_details` and the rest are read.
  That is also why the authorization endpoint keeps no state across the two
  entries: it is the same query string both times.
* **The return URL must be a path on this service**, and is checked to be one.
  An authentication service that will redirect a browser anywhere after signing
  somebody in is a credential phishing tool with a login screen in front of it.
* **The rows the screen shows about the interrupted request** — client, scope,
  redirect URI, the Credential Offer an `issuer_state` came from — are supplied
  by the caller, because only the caller knows what its own parameters mean.
* **Cancelling comes back too.** The browser returns to the caller with
  `authn_error=access_denied`, and the caller turns that into its own
  protocol's refusal: for OAuth, a redirect to the client's `redirect_uri`, or
  in `response_mode=form_post` a self-submitting form — which is not a redirect
  at all, and is exactly why the sign-in service does not try to answer for the
  protocol.

**It is not always the screen.** The same redirect goes to
`/federation/login/{id}` when the application's entry names one usable
federation relationship, and to **`/authn/select-idp`** when it names several —
a page with one button per partner and no password field. The calling protocol
cannot tell the three apart and must not: what it asked for is "get this person
authenticated and bring them back", and which identity provider does it, or
whether the person was asked which, is not its business. See
[Federation](federation.md) for home realm discovery.

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

**Continue with your certificate.** When the browser presented a TLS client
certificate on the connection, and that certificate names a person in the
realm the sign-in is for, the sign-in screen offers **Continue as *name* with
your certificate**. It completes the sign-in on the certificate, so every
protocol that sends people to this screen — SAML, WS-Federation, OpenID
Connect, GNAP — can be answered with it. The session records the same event
as `GET /tls/sign-in` (`amr ["swk"]`, `acr "1"`): one factor, so a request
or a requirement for two asks for a second one afterwards. It is offered only
where the authentication policy accepts a TLS client certificate as a first
factor, and not on a linking sign-in, for an application that names the
sign-in mechanisms it allows, or where a security key or passkey is demanded.
A certificate from an outside certificate authority names the person only
when it is stored, byte for byte, in `userCertificate` on their entry and no
other ([TLS](tls.md#a-certificate-from-an-outside-certificate-authority));
its common name is never read. A revoked certificate, an application's
certificate, a certificate from another realm's authority and an outside one
stored on no entry (`STS-AUTHN-0468`) or on several (`STS-AUTHN-0469`) are
refused, and the screen says why. See
[Sign in with a client certificate](configure-tls.md#sign-in-with-a-client-certificate).

With `authn.unauthenticatedSessions` on, a third button, **Continue without
signing in**, starts a real session for the stable `anonymous` principal. The
session is marked `authenticated: false`, with empty `amr` and `acr "0"`. It
satisfies an application that admits everybody and is refused by one that
requires an authenticated user. It is not Cancel: the flow continues.

### Post-login activities: a sign-in held until something is done

A realm can ask a person to do something after they sign in, before they
are sent back to the application: a **post-login activity**. The one today
asks for a post-quantum (ML-DSA) passkey. It is a policy on **Directory →
Policies** (**Post-login activity policy**), off by default and targeted by
group. A person it is due for gets `/authn/post-login` in place of a
started session: they register the passkey, or skip it while the profile
allows, and the session they signed in for then starts with the `amr` and
`acr` of that sign-in. A door that cannot show the page (federation, a
wallet, Kerberos, a client certificate) is not interrupted for an optional
activity and is refused for a required one (`STS-AUTHN-0473`).

[Passkeys → Post-login activities](passkeys.md#post-login-activities-moving-people-to-post-quantum-passkeys)
walks through it, and [Post-login activities](post-login-activities.md) is
the reference.

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
  password the service generates. See
  [Different password rules for different applications or
  groups](#different-password-rules-for-different-applications-or-groups).
* **Forced change.** `pwdReset: TRUE` on an entry (from
  [draft-behera-ldap-password-policy](https://datatracker.ietf.org/doc/html/draft-behera-ldap-password-policy))
  means the password must be changed before it is used. The sign-in screen
  draws `/authn/password-change` in place of a session, and after the change
  the sign-in continues, second factor included. Every other door that takes a
  password refuses the account until then (product mode).
* **Start over.** Every page after the sign-in screen — a second factor, the
  set-up step, an emailed code or link, the forced password change — has a
  **Start over** button. It returns to the sign-in screen for the same
  request, so the application that sent the person still gets its answer
  once they sign in again. Nothing from the step is kept: a mailed code or
  link stops working, an authenticator app half set up is discarded, and the
  first factor has to be given again.
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


### Different password rules for different applications or groups

Besides `default`, a realm can hold **named password policies**, each with
every rule `default` has and a **precedence** from 1 to 1000. Add one on
*Directory → Policies → Password policy → New policy*, or with
`POST /admin-api/policies/save-password-policy` naming a `profile` other
than `default`:

```bash
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  https://sts.example.com/admin-api/policies/save-password-policy \
  -d '{"profile":"admins","precedence":10,"minLength":20,"history":10,
       "minSymbols":1,"requireUppercase":true,"requireDigit":true,
       "generatedLength":32}'
```

A policy applies to the people something names it for:

- a **group**, in its `stsPasswordPolicy` (the group's page, or
  `POST /admin-api/groups/set-policy` with `"attribute":"stsPasswordPolicy"`),
  holds every member to it;
- an **application**, in its `appPasswordPolicy` (a field of the
  application's *Every protocol* settings, or
  `POST /admin-api/applications/set`), holds to it a password chosen while
  signing in to that application — the forced change after a reset.

Of the policies named for a person, the **lowest precedence** applies, ties
by name; where nothing names one, `default` does. A door with no application
in hand — the portal's password page, activation, a reset link, the console,
`/admin-api` and an LDAP write — ranks the person's groups' policies alone,
and the rules a page shows before a password is typed are the ones that will
be applied. The same policy decides the length of a password the service
generates for the person and how their password is hashed.

Each reference accepts only `default` or a policy the realm holds, and a
named policy that a group or an application still names cannot be removed
(`STS-AUTHN-0540`). If a reference names a policy the realm does not hold —
written past the console — the person is held to `default`, whatever else is
named, and the service logs `STS-AUTHN-0539`. Named policies belong to their
realm and are not inherited by other realms.

### WebAuthn

> **A step-by-step guide** to every way passkeys can be used here — as a
> second factor, without a password, without a username, required for
> administrators, restricted to approved models, a classical and a
> post-quantum passkey side by side, and moving people to post-quantum
> passkeys after they sign in — is on
> [Passkeys and WebAuthn](passkeys.md). This section is the reference.

Passkeys — on a device, in a password manager, on a phone or on a security
key — as a WebAuthn Level 3 relying party over FIDO CTAP2. **A key carries
no role** (since [#1135](https://github.com/rcbj/iya-sts/issues/1135)): it is
registered with nothing asked about its purpose. Whether it is used, and how,
is decided at the sign-in in layers: the realm's authentication policy (its
`passkey` first-factor and `securityKey` second-factor rows) with
`webauthn.primaryAllowed` and `webauthn.mfaAllowed`; then, at a browser
sign-in, the [named authentication
policy](#named-authentication-policies) an application names, where it
narrows the realm (`webauthn` among its first factors, `securityKey` among
its second); and never the key itself. A key a person holds may answer
either of the two **uses** wherever those layers accept it:

* **as a second factor** after a password: `amr ["pwd","hwk"]`,
  `acr "mfa"`. Allowed while `webauthn.mfaAllowed` and the authentication
  policy's security-key row as a second factor are on; otherwise refused
  (`STS-AUTHN-0046`, `0254`);
* **as a first factor**, with no password read (the passwordless box):
  `amr ["hwk"]`, `acr "1"`. Allowed while `webauthn.primaryAllowed` and the
  policy's passkey row as a first factor are on; otherwise refused
  (`STS-AUTHN-0045`, `0253`). That is **one factor**, even
  with `webauthn.userVerification` set to `required`, because RFC 8176 has no
  value this service could honestly assert for "the authenticator verified the
  user".

A password alone records `amr ["pwd"]`, `acr "1"`. These RFC 8176 values go
into the ID Token whenever the session recorded them, so their *absence* means
something too, which is why they are not emitted unconditionally.

The ceremony is `POST /authn/webauthn` for both uses: the first use for a
username **enrols** a credential (section 7.1) where enrolment is allowed (see
*Where a key is enrolled* below, and product mode's rule), and every later sign-in
**asserts** with it (section 7.2), against a challenge minted on the server and
held for five minutes with the interrupted request. The person is then returned
to that request exactly as the password-only path returns them. The two uses
perform the same ceremony, with the same keys offered; what differs is what the
session then says, and that is decided from the step the screen armed and
carried on the pending record — never re-read from the ceremony's own POST,
which is the browser's result and says nothing about what somebody chose a
screen earlier. Where the realm accepts neither use, no new key can be
registered (`STS-AUTHN-0531`).

Like every sign-in page since #572, it is drawn by the sign-in page's
script, which runs the ceremony (a WebAuthn ceremony is a browser API call). **Registration and every assertion are verified in both modes**: the
challenge, the origin, the RP ID hash, the user-presence and user-verification
flags, the signature over
`authenticatorData ‖ SHA-256(clientDataJSON)` against the registered COSE key
(every algorithm `webauthn.algorithms` may name: ML-DSA-44/65/87 from
RFC 9964, the ECDSA, EdDSA, RSASSA-PSS and RSASSA-PKCS1-v1_5 families, and
RFC 9864's fully specified ESP256, ESP384, ESP512, Ed25519 and Ed448), and a signature counter that must strictly go
up — with the one exemption the specification asks for, an authenticator that
reports zero and always will. A
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
`/portal/keys`, on its `/admin/users` row and in `GET /admin-api/users`. A key
whose statement nothing verified is shown as *claimed*: a client that believed
this service's word on an unverified statement would have learned something
false about a real device.

ML-DSA passkey creation and assertion support depends on the browser,
operating system and authenticator, and is not implied by ordinary WebAuthn
support. See [where ML-DSA passkeys are expected to
work](passkeys.md#where-ml-dsa-passkeys-are-expected-to-work), and measure
your own realm, before requiring post-quantum passkeys for a population.

**Optional long-term evidence for trusted classical attestations (#947).**
Configure `webauthn.attestationEvidenceTsaUrl` with an HTTPS RFC 3161 timestamp
authority and `webauthn.attestationEvidenceTsaTrustAnchors` with its PEM trust
anchors. The service then archives the exact attestation bytes together with
the verification result in an RFC 4998 EvidenceRecord. The TSA token's
signature, message imprint, certificate path and critical
`id-kp-timeStamping` purpose are verified before registration succeeds. This
feature is off when the TSA URL is empty; when enabled, a TSA failure refuses
the registration. It applies to newly registered trusted classical
attestations, not post-quantum or untrusted statements. Daily passkey report
recounts renew timestamps; setting
`webauthn.attestationEvidenceHashAlgorithm` to `sha384` or `sha512` requests
hash-tree renewal into a new chain. Admins can export a record from the
person's passkey page or the evidence export endpoint documented in
[Passkeys and WebAuthn](passkeys.md#rfc-4998-evidence-for-classical-attestations).

**A classical passkey and a post-quantum one, side by side**
(`webauthn.pqcAlongsideClassical`, off by default, per realm, or the passkey
policy's `lanes` row for one profile's people). An
authenticator replaces a passkey it already holds for this service when it
is asked for another under the same account, and is asked for ML-DSA first
whenever it supports it, so by default one person holds one kind or the
other on a device. With two lanes, every place a passkey is created —
`/portal/keys`, the activation link, the sign-in screen's first passkey and
its set-up step — asks which: **classical** (the configured algorithms less
ML-DSA) or **post-quantum** (ML-DSA only). Each kind is its own account to
the authenticator and the password manager, with its own user handle, so
both fit on one device. The post-quantum one is listed as
`<username>+ml-dsa` when it is created, and as `<username>+ml-dsa-65` (for
example) once every post-quantum passkey the person holds uses that one
algorithm; that name is never typed to sign in, and the sign-in screen
refuses any typed name ending in `+ml-dsa`, `+ml-dsa-<n>` or `+pqc` (in
any letter case, in every mode; `STS-AUTHN-0354`). Either passkey signs the person in, with or
without the username. `webauthn.maxKeysPerPerson` counts both kinds. The
setting cannot be on together with `webauthn.pqcOnly` (`STS-AUTHN-0353`).
Turned off, a post-quantum passkey already held goes on signing in and no
new one can be created (`STS-AUTHN-0351`). Few authenticators make ML-DSA
passkeys yet.

**Upgrading a classical passkey.** A person who already holds a classical
passkey moves it to ML-DSA at a sign-in, when the realm's
[post-login activity policy](post-login-activities.md) asks them to; an
administrator can run the same ceremony from the person's page. There is
no upgrade on `/portal/keys`. See
[Passkeys](passkeys.md#upgrading-a-classical-passkey).

**`webauthn.userVerification` is the one ceremony option
that is enforced**, because the UV flag sits inside the bytes the authenticator
signed. The others are requests to the browser, and what came back is recorded
(the attachment, and whether the credential is discoverable, from `credProps`).

The RP ID is the host the service was reached on, unless `webauthn.rpId` widens
it to a registrable domain suffix of that host — never anything else, because
WebAuthn binds a ceremony to the calling origin and that is the whole of its
phishing resistance. The accepted origins are derived from the
same address unless `webauthn.allowedOrigins` lists them.

**The two uses reach the directory differently.** A passwordless sign-in is an
authentication in its own right, so it is recorded against the person's
directory entry as a password sign-in is. A second factor authenticates nobody
new — the person is the one the password step named — so it creates nothing,
and writes a flag on the entry that already exists (see [LDAP](ldap.md)).

**Where a key is enrolled:**

* `/portal/keys`, signed in, up to `webauthn.maxKeysPerPerson` keys, with
  nothing asked but the kind of authenticator (and, with two lanes, classical
  or post-quantum);
* an activation link;
* the sign-in screen's second-factor box, which enrols on first use, but only
  for somebody who holds **no** second factor yet. Otherwise anybody who knew
  the password could register their own authenticator;
* an administrator's browser, when the person's passkey policy has
  `adminEnrolment` on (off by default). See
  [Passkeys](passkeys.md#an-administrator-enrols-a-passkey);
* the post-login activity's step, after a complete sign-in, when the
  realm's [post-login activity policy](post-login-activities.md) asks the
  person for an ML-DSA passkey. It is ML-DSA only, and is not held to
  product mode's rule against registering a passkey at the sign-in
  screen's passwordless box, because the person has already signed in.

A person removes a key on `/portal/keys`, and an operator on the person's
`/admin/users` page (`POST /admin-api/users/clear-key`).

**The Passkeys page** (`/portal/keys`, #470) follows the FIDO Alliance's
passkey management guidelines. It uses *passkey* for every kind and puts them
under one heading in two groups:

* **Passkeys on your devices** — a credential that may be backed up (the BE
  flag), or one from an authenticator built into the device.
* **Passkeys on security keys** — a cross-platform credential that cannot be
  backed up.

Each row shows:

* an icon;
* a name — the person's own, otherwise the provider's, otherwise "Passkey"
  or "Security key";
* the provider;
* when it was created and when it was last used;
* **Rename** and **Remove**;
* a *Details* section with the algorithm, the attestation, the
  AAGUID, the backup state and the transports.

**Where the provider's name comes from:**

* When an MDS3 BLOB is loaded, the name is only ever the description FIDO MDS
  lists for the key's AAGUID.
* Otherwise a short built-in table of the major credential managers names it.

The name is a label for the owner, and nothing this service decides reads it.

**Creating one:**

* There are two buttons. *Create a passkey* hints `client-device`, then
  `hybrid`, and REQUIRES a discoverable credential (`residentKey:
  required`), so the passkey can sign in with no username. *Use a security
  key* asks for `cross-platform` and hints `security-key`.
* Every passkey a person registers is created under their **user handle**:
  64 random bytes stored on their entry, never their username (WebAuthn
  Level 3 section 5.4.3). A passkey's authenticator hands it back, and an
  assertion whose handle is not the one its key was created under is
  refused (section 7.2, step 6).
* The new passkey appears on its row under a default name, its provider's or
  *Passkey* or *Security key*; rename it there with the row's **Rename**.
* A person renames one on `/portal/keys` (`POST /account-api/keys/rename`),
  an operator with `POST /admin-api/users/rename-key`. An empty name restores the default.

The page also uses the WebAuthn Signal API, under the person's user handle.
It tells their credential manager which passkeys are still accepted, so one
removed here disappears there too, and gives it their display name. A person
whose passkeys were all registered before the user handle existed (when it
was the username, which every realm shares) is sent nothing.

### The passkey policy

How passkeys behave in a realm is a policy on **Directory → Policies**, beside
the password, authentication and service-account policies: the **passkey
policy**, `cn=default,ou=passkeyPolicies`. A realm without its own follows the
default realm's, and the built-in defaults apply where neither exists. Change
it on the console or with `POST /admin-api/policies/save-passkey-policy`;
`reset-passkey-policy` goes back to inheriting.

These rows say how the realm's passkeys behave. Since #536 the **issuance
policy** decides whether a given passkey may be registered or may sign
somebody in, from the key's facts and these rows: the actions
`register-passkey` and `use-passkey`, with the built-in rules giving the
refusals described below. A realm's own issuance policy may decide
differently. For example, one rule can let synced passkeys sign in where the
row says `disallow`. See [XACML](xacml.md).

| Field | Default | What it does |
|---|---|---|
| `allowUsernameless` | on | Offers a passkey sign-in with **no username**, described below. |
| `requireUsernameless` | off | Makes a passkey sign-in with no username the **only** way in, for an application that signs in with a passkey alone (below). Needs `allowUsernameless`. |
| `securityKeyResidentKey` | `required` | What *Use a security key* asks the authenticator to store **while usernameless sign-in is on**: `discouraged`, `preferred` or `required`. |
| `backupEligibility` | `allow` | `disallow` accepts only **device-bound** passkeys, refusing a synced one at registration and at sign-in (below). |
| `enforcePinLength` | off | Requires a minimum **security-key PIN length**, as the key reports it (below). |
| `minPinLength` | 4 | The minimum, 4 to 63 characters, while `enforcePinLength` is on. |
| `pinLengthOnlyIfSupported` | off | On, a key that does not report its PIN length is accepted. |
| `enforceAttestationAtSignIn` | off | Holds every passkey sign-in to the attestation rules in force, not only registration (below). |
| `passkeyHints` | `client-device,hybrid` | The WebAuthn hints *Create a passkey* sends, in order (below). |
| `securityKeyHints` | `security-key` | The hints *Use a security key* sends. |
| `signInHints` | `none` | The hints a passkey sign-in sends. |
| `userDisplayName` | empty | The directory attributes a passkey prompt shows as the person's name (below). |
| `rpNameExtras` | `none` | `realm`, `organisation` or `realm-and-organisation`: appended to the service's name in a passkey prompt. |
| `credentialLabel` | empty | The name a new passkey is given; `{provider}` and `{kind}` are filled in. |
| `aggregateDevices` | on | A person's passkeys are one sign-in choice; off, one per passkey (below). |
| `enterpriseSerialAttribute` | empty | The attribute of a person's entry holding the serials of the security keys issued to them; set, a key registers only if its enterprise attestation names one of them (below). |
| `postQuantumRequired` | `off` | `sign-in` accepts only a **post-quantum** (ML-DSA) passkey at sign-in; `registration-and-sign-in` refuses a classical one at registration too (below). |
| `attestationAlgorithms` | `none` | The algorithms a passkey's **attestation** must be signed with — the statement and every certificate of its chain, leaf to anchor: a list of `post-quantum`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, `slh-dsa`, `composite-ml-dsa`. Set, it requires a trusted attestation (below). |
| `postQuantumAllowCredentials` | `realm` | While a post-quantum passkey is required at sign-in: `narrow` names only the person's post-quantum passkeys, `list-and-refuse` names every one and refuses a classical one after the prompt with a page saying why, `realm` follows `webauthn.postQuantumAllowCredentials` (below). |
| `registrationAlgorithms` | `realm` | The signature algorithms a registration for this profile's people offers, in order. `realm` follows `webauthn.algorithms`. A passkey whose algorithm is not one the profile offers is refused (`STS-AUTHN-0432`). |
| `registrationMode` | `realm` | `realm` follows `webauthn.pqcOnly` and `webauthn.pqcAlongsideClassical`. `pq-only` offers only ML-DSA and refuses a classical retry. `pq-first` offers ML-DSA first and the classical algorithms after it, even where the realm requests ML-DSA only. `classical-only` offers no ML-DSA (below). |
| `lanes` | `realm` | `realm` follows `webauthn.pqcAlongsideClassical`. `both` gives this profile's people a classical and a post-quantum passkey side by side, each under its own user handle, where the setting is off; `one` gives them one lane where it is on. `webauthn.pqcOnly` still means one lane, and `both` is refused beside `registrationMode` `classical-only` (`STS-AUTHN-0476`). |
| `clientRules` | empty | The clients — `<browser> on <system>`, each a family or `*`, with an optional major-version range, `;` between rules — whose registrations offer no ML-DSA, where a classical passkey is allowed. See [Passkeys → Clients that cannot make an ML-DSA passkey](passkeys.md#clients-that-cannot-make-an-ml-dsa-passkey). |
| `adminEnrolment` | `off` | `on` lets an administrator holding Admin Write enrol a passkey for a person this profile applies to, in the administrator's browser (below). |
| `deviceBoundRequired` | off | On, an issuance to an application this profile covers waits until the sign-on session is bound to the browser's key. Refused while `authn.deviceBoundSessions` is off (`STS-AUTHN-0461`). |
| `recoveryAssurance` | `any` in development, `not-weaker` in product | Whether recovering an account without its passkey restores access at once (`any`), only once a new passkey has signed the person in (`not-weaker`), or only through an administrator and then only that way (`operator-only`) (below). |

**Both portal buttons ask for a discoverable credential by default.** *Create
a passkey* always asks `residentKey: required`. *Use a security key* asks
`required` too while usernameless sign-in is off, whatever
`securityKeyResidentKey` says, so one security key gives the same result
through either button; while it is on, it asks `securityKeyResidentKey`. A
realm can lower that to `preferred` or `discouraged` to spare a security key's
few resident slots, and a key enrolled that way may need the username to sign
in.

**Account recovery** (`recoveryAssurance`). A password reset link, the
forgot-password form, an activation link, a recovery code and an emailed code
or link all get a person back into their account without their passkey. For
a person who holds a passkey, that would make the passkey policy's other rows
easy to step round: a mailed link and a password reach the same applications
a device-bound, attested security key does.

* `any` (the default in development) restores access at once.
* `not-weaker` (the default in product) lets the recovery happen, but the
  first sign-in after it that is not a passkey sign-in reaches no
  application. The sign-in screen asks the person to register a new passkey,
  held to this policy's registration rules, and then sends them back to sign
  in with it. That passkey sign-in completes the recovery. It applies to the
  sign-in after a reset or activation link, after a password an
  administrator generated, and to a recovery code or an emailed code or link
  used at sign-in.
* `operator-only` does the same, and also refuses the self-service doors to
  a person who holds a passkey: the forgot-password form sends no mail (and
  answers its usual sentence), a reset link they asked for is refused when it
  is used, and the sign-in step offers no recovery code or emailed factor.
  Only an administrator's reset link, generated password or activation link
  remains.

A person holding no passkey is not affected by any value. Whether a recovery
may restore access is decided by the issuance policy (`recover-account`), so
a realm's own policy can refine it. The codes are `STS-AUTHN-0380` (refused)
and `STS-AUTHN-0381` (limited to registering a passkey).

**Synced passkeys** (`backupEligibility`). A *synced* passkey is one its
provider copies to the person's other devices, or keeps a backup of: a
passkey in a phone's or a browser's password manager usually is. A
*device-bound* one never leaves the authenticator it was made on: a hardware
security key usually is. The authenticator says which in every registration
and every sign-in, with the **backup eligible** (BE) flag of WebAuthn Level 3
section 6.1, and the BE flag never changes for a credential's life.

A realm may refuse synced passkeys because a copy of the key is a copy of the
credential: it is only as safe as the person's account with the provider that
syncs it, and it can sign in from a device the realm has never seen. A realm
that needs to know which physical authenticator holds a key — the usual case
for an administrator, or for a regulated deployment — sets `disallow`. Most
passkeys people already hold are synced, which is why the default is `allow`.

While it is `disallow`:

- a passkey with BE set is **not registered**, at the sign-in screen, on
  `/portal/keys` or through an activation link (`STS-AUTHN-0312`), and the
  page says why;
- a passkey with BE set **does not sign anybody in**, whether it is the
  first factor, the step after a password, or a sign-in with no username
  (`STS-AUTHN-0313`, a `session.refuse` audit row). That catches a synced
  passkey registered before the realm said no, and `/portal/keys` marks
  such a key so its owner can replace it.

The console lists a person's keys with what the authenticator said about
backup: *device-bound*, *eligible, not backed up*, or *backed up*.

**A minimum PIN length** (`enforcePinLength`, `minPinLength`,
`pinLengthOnlyIfSupported`). User verification on a security key is usually a
PIN, and a key with a four-digit PIN satisfies `required` user verification
as well as one with a twelve-character PIN. While `enforcePinLength` is on,
every registration asks the authenticator for the minimum PIN length it
enforces, through the CTAP 2.1 `minPinLength` extension (CTAP 2.1 section
12.4), records the answer on the key, and:

- refuses a key that reports less than `minPinLength`, at registration
  (`STS-AUTHN-0314`) **and at every sign-in** (`STS-AUTHN-0315`, a
  `session.refuse` audit row). Raising the minimum therefore stops a key
  registered under a lower one; `/portal/keys` marks such a key so its owner
  can replace it;
- refuses a key that reports nothing, unless `pinLengthOnlyIfSupported` is on.

**A key reports its minimum PIN length only to relying parties it was
configured to tell.** The key's administrator sets that up with CTAP 2.1's
`setMinPINLength` command, naming this service's RP ID (the host name it is
reached at, or `webauthn.rpId`). A key nobody configured, every platform
authenticator and every synced passkey reports nothing. So with
`pinLengthOnlyIfSupported` off, the default, only configured security keys
can be registered at all. With it on, every other key is accepted, and the
rule then binds only the keys that report: **it is weaker, and is meant for a
realm moving its keys over one at a time.** The browser must also pass the
extension on; one that does not is a key that reports nothing.

**A post-quantum passkey required** (`postQuantumRequired`). A passkey is
*post-quantum* when its signature algorithm is ML-DSA-44, ML-DSA-65 or
ML-DSA-87 (RFC 9964), which a quantum computer is not expected to break; a
*classical* one signs with ES256, RS256 or another algorithm that one could.
The **algorithm** decides, as the key recorded it when it was registered —
not the kind of passkey the person chose. With
`webauthn.pqcAlongsideClassical` off, an authenticator that can make ML-DSA
does so, and that key counts as post-quantum.

- `off`, the default, accepts any passkey.
- `sign-in`: a classical passkey **does not sign anybody in**, as the first
  factor, as the step after a password, or with no username
  (`STS-AUTHN-0356`, a `session.refuse` audit row). A classical one may still
  be registered.
- `registration-and-sign-in`: a classical passkey is **not registered**
  either (`STS-AUTHN-0355`), and every registration then offers only ML-DSA
  (with `webauthn.pqcAlongsideClassical` on, only the post-quantum kind).

While it is required at sign-in, the passkey step asks the authenticator only
for the person's post-quantum passkeys (`narrow`, the default), and a person
holding none is told so before any prompt appears. Under `narrow` a person
whose device holds only their classical passkey sees the browser's own "no
passkey found" message. With `postQuantumAllowCredentials` (or the realm's
`webauthn.postQuantumAllowCredentials`) set to `list-and-refuse`, the step
names every passkey instead, and a classical one picked is refused after the
prompt (`STS-AUTHN-0356`) with a page that says the application requires a
post-quantum passkey and links to adding one; the trade-off is that the
person may pick a passkey that will be refused. A refused passkey starts no
session and records no authentication. A sign-in with no username cannot be
narrowed either way, so it is refused after the prompt, with the same page. `/portal/keys` and the console mark a
classical passkey that no longer signs its owner in, and the first time each
one is refused a CAEP `credential-change` is sent. Like every row, it can be
set on a named policy, so a single application or group can require
post-quantum passkeys while the rest of the realm does not.

**Who would be refused** is on **Monitoring → Passkeys**
([admin console](admin-console.md#passkeys--adminpasskey-report)): the people
holding classical passkeys only, across the realm or in one group or one
policy's population, listed and exported. Check it before turning the row on.

A save that requires it is **refused while the realm offers no ML-DSA**
(`STS-AUTHN-0357`): with `webauthn.algorithms` naming none, and neither
`webauthn.pqcOnly` nor `webauthn.pqcAlongsideClassical` on, nobody could
register a passkey that satisfies it. If `webauthn.algorithms` changes
afterwards, registration offers all three ML-DSA algorithms anyway.

**When a device cannot make the ML-DSA passkey asked for** (#944), the
passkey step and `/portal/keys` say so in the person's language and, where a
classical passkey is allowed, offer **Try again with a classical passkey**.
The retry is refused (`STS-AUTHN-0420`) when the profile's
`registrationMode` is `pq-only`, when that row is `realm` and
`webauthn.pqcOnly` is on, under `registration-and-sign-in`, and at the
sign-in step under `sign-in`. `pq-first` still offers the retry where the
realm requests ML-DSA only. See
[Passkeys](passkeys.md#when-the-device-cannot-make-an-ml-dsa-passkey).

A realm that keeps an issuance policy of its own, built from the
`role-issuance` template before the post-quantum row existed, decides
passkeys with that document: rebuild it from the template for the realm
to be held to the row.

**Algorithms a registration offers** (`registrationAlgorithms`,
`registrationMode`). `realm`, the default of both, follows the realm:
`webauthn.algorithms`, and `webauthn.pqcOnly` with
`webauthn.pqcAlongsideClassical`. A profile can name its own ordered list,
from the algorithms `webauthn.algorithms` may name, which then replaces
`webauthn.algorithms` for that profile's people only; the **Metadata** tab
of **Protocols → WebAuthn** says when a profile's list is the one in force.
It can also name a mode:

* `pq-only` offers only ML-DSA, and refuses a retry with the classical
  algorithms (`STS-AUTHN-0420`).
* `pq-first` offers ML-DSA first and the classical algorithms after it,
  even where the realm requests ML-DSA only.
* `classical-only` offers no ML-DSA, for people whose devices fail an
  ML-DSA registration. A post-quantum lane is refused (`STS-AUTHN-0433`).
  A passkey already registered in that lane goes on signing in.

A save is refused when `classical-only` is combined with
`postQuantumRequired` other than `off`, or with `attestationAlgorithms`
set (`STS-AUTHN-0430`), and when `pq-only` or `pq-first` would offer no
ML-DSA (`STS-AUTHN-0431`). A passkey whose algorithm is not one the
profile offers is refused at the write (`STS-AUTHN-0432`). Left out of a
save, `realm` is kept.

**An administrator enrols a passkey** (`adminEnrolment`). Off by default.
`on` lets an administrator holding the Admin Write console role enrol a
passkey for a person this profile applies to, from the person's page or
`POST /admin-api/users/begin-passkey-enrolment`. The ceremony runs in the
administrator's browser, against an authenticator they hold, under the
person's user handle, and is verified as the person's own registration.
Nothing made elsewhere can be imported. The key records who enrolled it
and when, and the person is told. While the row is off the ceremony is
refused (`STS-AUTHN-0440`), including when the row is turned off during
the ceremony. See
[Passkeys](passkeys.md#an-administrator-enrols-a-passkey).

**A device-bound session** (`deviceBoundRequired`). Off by default. On, an
issuance to an application this profile covers waits until the sign-on
session is bound to the browser's key, and is refused when the browser
skipped that registration or the wait elapsed without a binding. A session
that was never offered registration is not refused by this row. A save is
refused while `authn.deviceBoundSessions` is off (`STS-AUTHN-0461`). See
[Sessions](sessions.md#binding-the-cookie-to-the-browser-device-bound-session-credentials).

**A post-quantum attestation required** (`attestationAlgorithms`). This is
about the passkey's **attestation** — the authenticator's signed statement
about what made the key, and the certificate chain behind it — not the
passkey's own algorithm, which `postQuantumRequired` covers. Every
registration records what its attestation was signed with: the statement's
algorithm, and the algorithm each certificate of the chain was signed with,
from the leaf to the trust anchor. An ML-DSA passkey whose attestation chain
ends in an ECDSA root is only as strong as that root.

- `none`, the default, accepts an attestation whatever it is signed with.
- A list — `post-quantum` (any ML-DSA, SLH-DSA or composite ML-DSA
  signature), `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, `slh-dsa`,
  `composite-ml-dsa` — registers a passkey only when its attestation is
  **trusted** (it chains to a root in `webauthn.attestationTrustAnchors` or
  the FIDO metadata) and every one of those signatures is one the list
  allows (`STS-AUTHN-0411`). A passkey with `none` or self attestation has
  no certificate and is refused. Like an AAGUID list, setting it asks the
  browser for direct attestation, so synced passkeys, which send none, are
  refused.
- With `enforceAttestationAtSignIn` on, every sign-in holds the passkey to
  the list by what its registration recorded (`STS-AUTHN-0412`). A passkey
  registered before this service recorded attestation algorithms recorded
  none, and stops signing in.

Few authenticators sign their attestation with a post-quantum algorithm yet.
Look at what the passkeys a realm already holds were attested with (the
person's console page, or `GET /admin-api/users?user=`) before requiring it.

**The attestation rules at sign-in** (`enforceAttestationAtSignIn`). The
`webauthn.attestation*` settings — the attestation policy, the list of
allowed authenticator models (`webauthn.attestationAllowedAaguids`), the
minimum certification level and FIPS — decide which keys may be
**registered**. A key registered before a rule was tightened would otherwise
go on working. With `enforceAttestationAtSignIn` on, every passkey sign-in
holds the key to the rules in force now, using what was recorded when it was
registered (its model, and whether its attestation was verified and trusted)
and the FIDO Metadata Service as it is now:

- a key whose model is no longer on the list, or below the level or FIPS
  certification asked for, is refused (`STS-AUTHN-0316`);
- a key the metadata service now reports **compromised** is refused;
- a key registered with **no trusted attestation** — `none`, self
  attestation, or before this service verified attestations — fails every
  rule that demands one, an AAGUID list included: its model is only what the
  authenticator claimed.

The first refusal of a key marks it, sends a Shared Signals CAEP
`credential-change`, and `/portal/keys` tells its owner. If the metadata
service cannot be asked, the sign-in is refused (`STS-AUTHN-0317`).

**Hints** (`passkeyHints`, `securityKeyHints`, `signInHints`). WebAuthn
Level 3 section 5.4.8 lets a relying party tell the browser which kind of
authenticator to lead with: `security-key`, `client-device` (the device's
own) or `hybrid` (a phone, by QR code). Each row is an ordered list of them,
or `none`. The defaults are what this service always sent: *Create a passkey*
leads with this device then a phone, *Use a security key* with a security
key, and a sign-in names none, so the browser offers every way it knows.

A hint must agree with the authenticator attachment the same request asks
for: `client-device` implies `platform`, `security-key` and `hybrid` imply
`cross-platform`. *Use a security key* always asks for `cross-platform`, and
*Create a passkey* asks for whatever `webauthn.authenticatorAttachment` says,
so a list that contradicts its request is refused when the policy is saved,
naming the hint. If the setting changes later, a hint it now contradicts is
not sent, and the log says so (`STS-AUTHN-0319`).

**Binding security keys to the people they were issued to**
(`enterpriseSerialAttribute`). An organisation that hands out security keys
usually wants each key to work only for the person it was given to. With
*enterprise attestation* (WebAuthn Level 3 section 5.4.7, CTAP 2.1 section
7.1) a key's attestation certificate carries its serial number, and this
service reads it from either of two places:

- the certificate subject's `serialNumber` attribute, or
- Yubico's device serial extension (`1.3.6.1.4.1.41482.13.1`), written in
  decimal as printed on the key.

A key whose certificate keeps its serial anywhere else has no serial this
service can read, and is refused.

Set `enterpriseSerialAttribute` to the attribute of a person's entry that
lists their keys' serials (for example `serialNumber`, which may hold
several values). Then a security key registers only if:

- its attestation verifies and chains to a trusted anchor, because a serial
  is worth only what the certificate naming it is worth; and
- the serial it names is one of that person's values (`STS-AUTHN-0320`).

A key whose certificate names no readable serial is refused
(`STS-AUTHN-0321`). The serial is recorded on the key and shown on the
console and on `/portal/keys`.

**Enterprise attestation must be switched on outside this service.** Set
`webauthn.attestation` to `enterprise`, list this service's RP ID in
`webauthn.attestationEnterpriseRpIds`, and arrange with the key's vendor or
the platform (a managed browser policy, or the vendor's RP ID list) for
enterprise attestation to be released to that RP ID. Without that, the
browser quietly sends ordinary attestation, which carries no serial, and
every registration is refused. **The serial is read only from a statement an
enterprise request produced**: a registration at an RP ID the list does not
name asks for `direct`, and any serial its certificate carries is ignored
([Enterprise attestation](passkeys.md#enterprise-attestation)).

**The names a passkey prompt shows** (`userDisplayName`, `rpNameExtras`,
`credentialLabel`). When a browser or phone asks somebody to create or use a
passkey, it shows the service's name (`rp.name`) and the person's
(`user.displayName`; the username is always `user.name`).

- `userDisplayName` lists up to six directory attributes in order, separated
  by commas, for example `displayName, givenName sn, mail`. A group joined
  by spaces combines its values. The first group whose every attribute has a
  value becomes the display name. Empty, the default, keeps the name the
  sign-in already knows, or the username.
- `rpNameExtras` appends the realm's name and/or `saml.organizationName` to
  `webauthn.rpName`, so somebody with accounts in several realms can tell
  the prompts apart.
- `credentialLabel` is what a new passkey is called on `/portal/keys` and the
  console, for example `Work {kind}`. Empty keeps the default: the provider's
  name, or *Passkey* or *Security key*. The person can still rename it.

Every value shown goes through the same cleaning: control characters and
characters that change text direction are removed, whitespace is collapsed,
and the result is at most 64 characters (60 for a label). A person who can
edit their own `displayName` therefore cannot make a prompt read right to
left, or hide part of it. The service's name is built only from settings an
administrator controls. A label is stored as written and is not translated.

**One choice, or one per passkey** (`aggregateDevices`). By default a person
with several passkeys is shown one *Use passkey* button, and the request lists
all of them so the browser offers whichever is present. With
`aggregateDevices` off, somebody with more than one first chooses which to use
from a list of their passkeys by name, and the request then names only that
one, with a link back to choose another. The choice is a list of links. The rule applies to the passwordless step and to the passkey
asked for after a password. Either way the assertion is checked against the
passkey it names; only the request changes.

**Named passkey policies** (#535, #1235). Beside `default`, a realm may keep
named passkey policies, for example a strict one for administrators. Each has
all the rows above and a precedence, from 1 to 1000. A named policy lists
nothing itself; what it covers names it:

- an application, in its `appPasskeyPolicy`;
- a group, in its `stsPasskeyPolicy`, chosen on the group's page.

At a sign-in, the candidates are the policy the application names and the
policy each of the person's groups names. The one with the **lowest
precedence** wins, ties by name, and where nothing names one, `default`
applies. An application's policy and a group's are not ranked by kind: give
the stricter one the lower number. For example, a strict application at 5
beats a lenient group at 50.

Registration on `/portal/keys` or through an activation link has no
application, so only the groups' policies apply there. A realm's named
policies are its own: unlike `default`, they are not inherited from the
default realm. A named policy that an application or a group names cannot be
removed until they name another.

Manage them on Directory → Policies, or with
`POST /admin-api/policies/save-passkey-policy` naming `profile` and
`precedence`. `reset-passkey-policy` with a named `profile` removes it. Name
one with `POST /admin-api/applications/set` (`appPasskeyPolicy`) or
`POST /admin-api/groups/set-policy` (`stsPasskeyPolicy`).

The *Passkey policy* tab there has three sub-tabs (#609):

- **Default**: the `default` policy, which applies wherever no named one
  does.
- **Named policies**: every named policy, each with the applications and
  groups that name it, its precedence, its form and a Remove.
- **New policy**: the form that adds one.

An application's own page shows the same relation read-only: see
[the passkey policy card](applications.md#the-passkey-policy-that-applies-to-it).

The policy replaced the settings `webauthn.usernameless` and
`webauthn.residentKey` (#527); a configuration that still names either is
refused at start.

**Signing in with a passkey and no username** (the passkey policy's
`allowUsernameless`, on by default). Where it is on, the sign-in screen draws
*Sign in with a passkey*, and the username field offers passkeys as autofill in browsers that
support conditional mediation. The browser is asked for any passkey of this
service, the user handle it returns names the account, and:

* **user verification is required** — a PIN or biometric on the
  authenticator — whatever `webauthn.userVerification` says, so the session
  records `amr ["hwk","user"]` and `acr "mfa"`;
* only a passkey registered for **signing in** (not one used as a second
  step after a password) answers it;
* a passkey registered before this existed was created under the username,
  and still works only where the username is typed — register it again to
  use it without one;
* nothing is enrolled at the sign-in screen this way;
* a passkey this service holds for nobody is reported to the browser
  (`signalUnknownCredential`), where only one trust realm is defined.

The button is a real submit button; without JavaScript it explains that a
passkey needs it, and the password form works as before.

**Requiring it** (the passkey policy's `requireUsernameless`, off by
default). Where it is on, an application whose [named authentication
policy](#named-authentication-policies) lists `webauthn` as its only first
factor gets a sign-in screen with **no username
field** and no *Sign In*: *Sign in with a passkey* is the way in, and the
second-step box is greyed out. A sign-in that names a person anyway is
refused (`STS-AUTHN-0333`), so the screen's shape is not the only thing
that enforces it. Three things hold it back:

* an application with any other mechanism beside `webauthn` (or none
  declared) keeps its screen as it was;
* a save that turns it on with `allowUsernameless` off is refused;
* the `default` profile **never applies it to the admin console, the
  embedded debugger or the user portal** (`sts-admin-console`,
  `sts-debugger-ui`, `sts-user-portal`). To hold one of them to it, create a
  named profile that selects that application and turn it on there — and
  point the application at a named authentication policy whose only first
  factor is `webauthn`.

### TOTP MFA

An authenticator app as a second factor: RFC 6238 over
[RFC 4226](https://www.rfc-editor.org/rfc/rfc4226). It is typed into a form,
so it works from a phone, a script or a test job (`POST
/authn-api/mfa/{id}/totp`, [the sign-in API](authn-api.md)).

* **Enrolment** happens on `/portal/mfa`, on an activation link, or at
  `/authn/mfa-setup` when a second factor is required. It is two steps. The
  page shows a QR code (drawn by the browser from the `otpauth:` URI) and the
  same base32 secret in
  groups of four, with the algorithm, digits and period written out. The
  typed form is not a fallback nobody sees: scanning is impossible when the
  phone *is* the browser showing the page, when a desktop authenticator has no
  camera, and when a `localhost` QR code photographed off a screen points at a
  host the phone cannot reach. Any app that implements the specification works
  — Google Authenticator, Microsoft Authenticator, Authy, 1Password,
  Bitwarden, Aegis, FreeOTP, KeePassXC — and nothing here is tied to one.
  Nothing is written to the entry until a code proves the app has the secret,
  and an unconfirmed secret expires after `totp.enrolmentTtlMinutes`.
* **Once enrolled, a password alone stops working**, which is what a person
  means by having turned this on: the sign-in screen asks for a code without
  anybody ticking anything.
* **The code is verified for real, in both modes**, against the secret and the
  clock with `totp.window` steps of skew either side. A code is accepted
  **once** (RFC 6238 section 5.2): the code that confirmed the enrolment cannot
  also sign anybody in, and a replay is refused as a replay, not as a wrong
  code — signing in twice inside one window asks for the next code rather than
  saying the first was wrong. Wrong codes are rate-limited, and a wrong code
  keeps the step so the person can try again. What stays permissive in
  development is everything around the code: the password in front of it is
  not checked, and any name may enrol.
* The session says `amr ["pwd","otp"]`, `acr "mfa"`. `otp` is RFC 8176's
  registered value, whose registry entry names RFC 4226 and RFC 6238, and
  `acr "mfa"` is honest here in a way it is not for a passkey used alone: two
  factors really were presented.
* **It can never be a first factor.** This service holds the same secret the
  app does, which proves somebody still has the app but is not something to
  hang an account on.
* **One secret per person**; enrolling again replaces it. It is stored on the
  person's own entry as `stsTotpCredential`, and it is **the one attribute in
  the directory that can be read back and used**: verifying a code means
  computing it, so it cannot be hashed the way `userPassword` is. In product
  mode the secret is sealed under the key-encryption key that protects the
  signing keys, so a directory dump shows ciphertext. In development it is
  stored as base32, because that mode's key is generated per run and sealing
  would mean an authenticator that silently stopped working at the next
  restart.
* All three digests are implemented, but **leave `totp.algorithm` at `SHA1`**:
  several popular apps ignore the parameter and always compute SHA-1. The
  digest, the digits, the period and the secret length apply to **new**
  enrolments only. `totp.window` applies to everybody.
* A person removes their own app on `/portal/mfa`; an operator clears it on the
  person's `/admin/users` page (`POST /admin-api/users/clear-totp`). **There is
  no self-service reset** for a lost phone: the shared secret lives on a device
  this service cannot reach, and a second factor anybody can remove is no
  second factor, so an operator clearing the enrolment is the only way back.
  Clearing drops an account to one factor, never to none.

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
| holds a passkey (and the realm, and the application where it lists second factors, accept a passkey as one) | the passkey |
| holds an authenticator app | the code |
| holds both | the passkey, with a link to the code |
| holds a passkey, passwordless box ticked (and the realm, and the application where it lists mechanisms, accept a passkey as a first factor) | the passwordless ceremony |

Every passkey counts: until #1135 only a key enrolled in the `mfa` role was
asked for after a password, and only a `primary` key answered the
passwordless box.

A relying party can **demand** more. `acr_values` that only two factors can
meet (`mfa`, `hwk`) ticks the second-factor box and refuses the passwordless
path server-side. A demand for a hardware key (RFC 8176 `hwk`, or a
WS-Federation `wauth` for a hardware token) allows only a security key, alone
or after a password, and refuses the code and recovery-code steps
(`STS-AUTHN-0204`). A demand for a **phishing-resistant** sign-in (OpenID
Connect EAP's `phr`, or `phrh` for a hardware-protected key) asks for a
security key the same way. A passkey alone meets it. A synced or unattested
passkey meets `phr` and never `phrh`. A key enrolled during that sign-in meets
neither: it was added on the strength of a password. See [OAuth security
profiles](oauth-security.md#phishing-resistant-sign-in-phr-phrh). A WS-Federation `wauth` for **multi-factor** is met only by
a session that really had two factors, so a passkey used alone does not meet it.
A session that does not meet a demand is sent through the sign-in screen again
with what was asked for required, rather than answered. See
[OAuth security profiles](oauth-security.md) for RFC 9470 step-up and
[WS-Federation](ws-federation.md) for `wauth`.

### The authentication policy

**Which ways of signing in a realm accepts** — as a first factor and as a
second — and whether a second factor is required of everybody, are the
authentication policy's, on Directory → Policies beside the password policy
(#64). It is `cn=default,ou=authnPolicies` in the realm's directory. **A realm
with no profile of its own follows the default realm's**, and the built-in
defaults apply where neither has one; removing a realm's own profile puts it
back to following. Every door asks it: a mechanism it does not accept in the
role it answered in gets no session (`STS-AUTHN-0268`, `STS-AUTHN-0269`), and
the sign-in screen draws only what it accepts.

It replaced three settings: `authn.mfaRequired` is `requireSecondFactor`
(`if-held` or `always` — there is no "never", because a second factor a person
holds is always asked for), and `totp.enabled` and `backupCodes.enabled` are the
TOTP and recovery-code rows. Those two keep their settings' contract: off stops
NEW enrolments and never a factor already held.

API: `GET /admin-api/policies` (the `authn` member) and `POST
/admin-api/policies/save-authn-policy` / `reset-authn-policy`.

### Named authentication policies

**An application can be held to fewer ways of signing in than the realm
accepts** by naming a **named authentication policy** (#1148). They are on
the same tab, Directory → Policies → *Authentication policy*, which has the
passkey policy's three sub-tabs: **Default** (the realm's own policy),
**Named policies** (the list, with Change and Delete) and **New policy**.
Each named policy holds exactly two lists:

* **the first-factor mechanisms it allows**: `password`, `password-mfa`,
  `webauthn`, `spnego`, `wallet`, `federation`;
* **the second factors it allows**: `password`, `securityKey`, `totp`,
  `recoveryCode`, `emailCode`, `emailLink`, `wallet`.

**None ticked in a list allows every one** (for the second factors: leaves
the realm's as they are). Everything else about signing in — which
mechanisms the realm accepts at all, and whether a second factor is
required — stays the realm's policy above, and a named policy only narrows
it: a mechanism the realm has switched off stays off.

An application names one in **`appAuthnPolicy`**, on its Configuration tab
(*Every protocol*). `default`, or empty, is the realm's policy as it is. One
field replaced the two lists an application used to hold itself
(`appAuthnMechanism` and `appMfaMechanism`). What the lists then do at a
browser sign-in to the application — the routing, the re-prompt, the
narrowed second factor — is in [Applications](applications.md#sign-in-mechanisms-how-its-people-may-sign-in).

* A policy is stored as `cn=<name>,ou=authnPolicies` in the realm's
  directory, beside the realm's own `cn=default`. A name is lower-case
  letters, digits and hyphens, and cannot be `default` (`STS-AUTHN-0532`).
  A realm's policies are its own: nothing is inherited from the default
  realm.
* **Deleting a policy an application names is refused** (`STS-AUTHN-0534`).
  Point the application elsewhere first.
* **A name no policy holds allows nothing.** The console and the API accept
  only `default` or a policy the realm holds, but an `ldapmodify` can write
  any value; an application naming a policy that does not exist allows no
  mechanism at all until the policy exists or the name changes
  (`STS-AUTHN-0536`).

API: the `named` list in the `authn` member of `GET /admin-api/policies`;
`POST /admin-api/policies/save-named-authn-policy` with `name`,
`description`, `mechanisms` and `secondFactors` (it replaces a policy of the
same name); `POST /admin-api/policies/delete-named-authn-policy` with
`name`; and `POST /admin-api/applications/set` with
`attribute: appAuthnPolicy` to point an application at one.

### Emailed codes and links

A six-digit code, or a single-use sign-in link, mailed to the person's
**verified** address — as a first factor ("Email me a sign-in code" and "Email
me a sign-in link" on the sign-in screen, with the username alone) or as a
second (the person opts in on `/portal/mfa`).

> **Warning.** NIST SP 800-63B-4 section 3.1.3.1: "Email SHALL NOT be used
> for out-of-band authentication", because a mailbox may be reached with a
> password alone, and mail may be read in transit or rerouted. **Both are OFF
> in the built-in policy.** Turn them on only where that is an accepted risk.

- They are offered only where the realm can send mail; Directory → Policies
  draws them disabled otherwise, and a save turning one on is refused
  (`STS-AUTHN-0244`).
- A code or link is kept only as a scrypt hash, is valid for at most ten
  minutes (`emailCodeTtlS`), works once, and a new one replaces the last. A
  step ends after `emailCodeAttempts` wrong codes, and the sign-in rate limits
  apply as well. A person's emailed factor is turned off after
  `emailFailureLimit` consecutive failures (at most 100, section 3.2.2).
- **A link finishes the sign-in only in the browser that asked for it.**
  Opening it anywhere else signs nobody in. Opening it at all spends nothing
  until Continue is pressed, so a mail scanner that fetches it does nothing.
  The page that waits for it checks every few seconds and, once the link is
  opened, says the sign-in went on in the other tab.
- As a first factor, **the page is the same whether or not the account exists
  or has a verified address**, and nothing is mailed for one that does not.
- The session records `amr ["otp"]` — RFC 8176 has no value for email — with
  `acr "1"` alone and `acr "mfa"` after another factor. **An emailed factor
  never satisfies a step-up on risk**, and the issuance policy's
  `refuseEmailFactor` option refuses any session standing on one.
- An emailed factor is never the second factor after an emailed first factor.
  A person who holds an authenticator app or a security key is asked for that
  first, and offered the email as a way round it.

### Requiring a second factor of everybody

With the authentication policy's `requireSecondFactor` set to `always`
(Directory → Policies; it was the `authn.mfaRequired` setting until #64),
everyone who signs in at this realm's screen must present a second factor. **Require MFA** on a person's `/admin/users` page
(`stsMfaRequired`) does the same for one person. A person who holds none is
sent to `/authn/mfa-setup` after the password to enrol an authenticator app or
a security key, and no session is started until they do. A passwordless sign-in
is refused (`STS-AUTHN-0171`). If both mechanisms are switched off, the sign-in
is refused and the settings are named (`STS-AUTHN-0172`).

### A second factor for administrators

Whether the people who can change everything must use a second factor depends
on the organization, so the authentication policy decides it (#246). Its
`requireSecondFactorForAdministrators` field applies to anyone who holds a
console role, **Admin Read or Admin Write**, through the roster groups. Set it
in the default realm's policy; every realm inherits it unless the realm saves
its own.

| Value | An administrator who holds no second factor |
|---|---|
| `offer` (the default for now) | is shown `/authn/mfa-setup` after the password, with an **Ignore** button. Ignore signs them in with the password alone, and they are offered again at the next sign-in. |
| `always` | must set one up before any session starts, as under `requireSecondFactor: always`. |
| `if-held` | is treated like everybody else. |

> **Warning.** `offer` and `if-held` are weaker than `always`: an administrator
> who signs in with a password alone can be impersonated by anyone who has the
> password.

**The default realm's built-in administrator (`admin.bootstrapUsername`, `admin`
by default) is only ever offered a second factor, even under `always`.** It is
the account you recover a service through when it has no other administrator.

An administrator who holds a factor is always asked for it, whatever this field
says. The offer is made at a sign-in of elevated risk too, because the console
is never locked out on risk (#226), and that offer is recorded under
`STS-RISK-0039`. Posting Ignore on a required step is refused
(`STS-AUTHN-0270`). The audit log records `authn.mfa.enrolment.offered`,
`authn.mfa.enrolment.declined` and `authn.mfa.enrolment.at-risk`.

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
| Passwordless box for somebody with no passkey | Enrols a key on the spot: the first person to claim a name gets it | Refused before a step is minted (`STS-AUTHN-0206`), with the same words whether or not the name exists |
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
| `authn.maxSessions` | `STS_AUTHN_MAX_SESSIONS` | `100000` | yes | The most sessions a realm holds. At the cap a new row is refused; nothing is ended to make room for somebody else. |
| `authn.maxSessionsPerSubject` | `STS_AUTHN_MAX_SESSIONS_PER_SUBJECT` | `32` | yes | How many countable sessions one subject may hold. At the cap their own oldest countable session is ended. An arrival does not count. |
| `authn.sessionShedPerSweep` | `STS_AUTHN_SESSION_SHED_PER_SWEEP` | `100` | yes | How many of a subject's own surplus sessions one session-expiry run ends in that realm. |
| `authn.sessionIdleTimeoutS` | `STS_AUTHN_SESSION_IDLE_TIMEOUT_S` | `0` | yes | How long a session may go unused before it ends; `0` means no idle timeout. |
| `authn.sessionSweepS` | `STS_AUTHN_SESSION_SWEEP_S` | `30` | yes | Interval of the scheduler job that ends expired sessions and reports them; `0` switches it off. |
| `authn.pendingTtlS` | `STS_AUTHN_PENDING_TTL_S` | `600` | yes | How long an interrupted request waits at the sign-in screen. |
| `authn.mfaStepTtlS` | `STS_AUTHN_MFA_STEP_TTL_S` | `300` | yes | How long a person who passed the password step has to present a second factor. |
| `authn.unauthenticatedSessions` | `STS_AUTHN_UNAUTHENTICATED_SESSIONS` | `false` | yes | Show *Continue without signing in*, which starts an unauthenticated session. |
| `security.rateLimitWindowS` | `STS_SECURITY_RATE_WINDOW_S` | `60` | yes | The length of a fixed rate-limit window. |
| `security.rateLimitPerIdentity` | `STS_SECURITY_RATE_PER_IDENTITY` | `5` | yes | Credential attempts one identity may make in a window, from any address. |
| `security.rateLimitPerAddress` | `STS_SECURITY_RATE_PER_ADDRESS` | `20` | yes | Credential attempts one address may make in a window, for any identity. |
| `security.activationTtlMinutes` | `STS_SECURITY_ACTIVATION_TTL_MINUTES` | `1440` | yes | How long an activation link stays valid. |
| `security.passwordResetTtlMinutes` | `STS_SECURITY_PASSWORD_RESET_TTL_MINUTES` | `60` | yes | How long an administrator's password reset link stays valid. |
| `security.passwordHashLogN` | `STS_SECURITY_PASSWORD_HASH_LOG_N` | `15` | yes | scrypt cost (as a power of two) for newly stored secrets, tokens and recovery codes; floor 14. A person's password is hashed as the password policy says (scrypt at 2^15, r=8, p=1 by default). |
| `security.passwordHashR` | `STS_SECURITY_PASSWORD_HASH_R` | `8` | yes | scrypt block size for a newly stored hash. |
| `security.passwordHashP` | `STS_SECURITY_PASSWORD_HASH_P` | `1` | yes | scrypt parallelism for a newly stored hash. |
| `credentials.factorScanLimit` | `STS_CREDENTIALS_FACTOR_SCAN_LIMIT` | `5000` | yes | How many entries the second-factor columns on `/admin/users` and `GET /admin-api/mfa` read before they stop. |

### WebAuthn settings

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `webauthn.enabled` | `STS_WEBAUTHN_ENABLED` | `true` | yes | Offer WebAuthn ceremonies at all; off does not remove enrolled keys. |
| `webauthn.rpName` | `STS_WEBAUTHN_RP_NAME` | `IYA STS` | yes | The `rp.name` a browser shows; no security meaning. |
| `webauthn.rpId` | `STS_WEBAUTHN_RP_ID` | *(empty: the host)* | yes | Widen the RP ID to a registrable domain suffix of the host. |
| `webauthn.allowedOrigins` | `STS_WEBAUTHN_ALLOWED_ORIGINS` | *(empty: derived)* | yes | The origins a ceremony is accepted from; empty derives one from the address. |
| `webauthn.algorithms` | `STS_WEBAUTHN_ALGORITHMS` | `ML-DSA-87`, `ML-DSA-65`, `ML-DSA-44`, `EdDSA`, `ES256`, `RS256`, in that order (#1166); every other algorithm may be ticked — `ES384` is off by default because certain browsers on Windows are incompatible with it | yes | `pubKeyCredParams`, in preference order. On **Protocols → WebAuthn** each algorithm has a checkbox (requested or not) and a number (1 is the most preferred). A **Select all** switch ticks every algorithm `webauthn.insecureAlgorithms` and `webauthn.pqcOnly` allow, or unticks them all; Save needs at least one ticked. The **Metadata** tab lists the algorithms in the order they are requested. See [Configuration](configuration.md) for the list and [Passkeys](passkeys.md#algorithms-classical-and-post-quantum) for the controls. |
| `webauthn.insecureAlgorithms` | `STS_WEBAUTHN_INSECURE_ALGORITHMS` | `false` | yes | Development mode only: also request and accept SHA-1's `RS1` (-65535), offered last. Off, `RS1` is neither requested nor accepted even where `webauthn.algorithms` names it, and a key enrolled with it is refused at sign-in (`STS-AUTHN-0294`). Cannot be set in product mode. |
| `webauthn.pqcOnly` | `STS_WEBAUTHN_PQC_ONLY` | `false` | yes | Request only ML-DSA-44/65/87 (whichever `webauthn.algorithms` names, all three where it names none); a new passkey made with another algorithm is refused at registration. A classical key already enrolled goes on signing in. |
| `webauthn.pqcAlongsideClassical` | `STS_WEBAUTHN_PQC_ALONGSIDE_CLASSICAL` | `false` | yes | Let a person hold a classical and a post-quantum (ML-DSA) passkey at once, choosing the kind when creating one (see above). Refused beside `webauthn.pqcOnly`. |
| `webauthn.postQuantumAllowCredentials` | `STS_WEBAUTHN_POST_QUANTUM_ALLOW_CREDENTIALS` | `narrow` | yes | Read while a passkey policy requires a post-quantum passkey at sign-in and the profile's own row is `realm`. `narrow` names only the person's ML-DSA passkeys; `list-and-refuse` names every passkey and refuses a classical one after the ceremony (`STS-AUTHN-0356`). |
| `webauthn.clientLearning` | `STS_WEBAUTHN_CLIENT_LEARNING` | `false` | yes | Learn which clients cannot make an ML-DSA passkey, and stop offering it to them ([Passkeys](passkeys.md#learned-clients)). |
| `webauthn.clientLearningFailures` | `STS_WEBAUTHN_CLIENT_LEARNING_FAILURES` | `3` | yes | Different people whose registrations from one client failed with `NotSupportedError` before it is learned. |
| `webauthn.clientLearningWindowHours` | `STS_WEBAUTHN_CLIENT_LEARNING_WINDOW_HOURS` | `168` | yes | The hours a failure counts for. |
| `webauthn.userVerification` | `STS_WEBAUTHN_USER_VERIFICATION` | `required` | yes | Whether the authenticator must verify the person; `required` is enforced. |
| `webauthn.attestation` | `STS_WEBAUTHN_ATTESTATION` | `direct` | yes | The attestation conveyance asked for at registration. Whether a statement is verified is `webauthn.attestationPolicy`'s decision, not this setting's ([WebAuthn](#webauthn), above). |
| `webauthn.attestationEnterpriseRpIds` | `STS_WEBAUTHN_ATTESTATION_ENTERPRISE_RP_IDS` | *(empty)* | yes | The RP IDs, comma-separated, at which `enterprise` attestation is asked for; elsewhere a registration asks `direct`. `enterprise` with the list empty is refused (`STS-AUTHN-0500`) ([Passkeys](passkeys.md#enterprise-attestation)). |
| `webauthn.attestationPolicy` | `STS_WEBAUTHN_ATTESTATION_POLICY` | `by-mode` | yes | What a registration's attestation statement must be: `verify-if-present` verifies every statement and refuses one that does not verify (`none`, self attestation and an unknown chain are accepted and recorded); `require-trusted` refuses anything that does not chain to an anchor, so no synced passkey; `off` verifies nothing (development only; product reads it as `by-mode`). `by-mode` is `verify-if-present` in product mode and `off` in development. |
| `webauthn.attestationTrustAnchors` | `STS_WEBAUTHN_ATTESTATION_TRUST_ANCHORS` | *(empty)* | yes | Root certificates (a PEM bundle) an attestation certificate may chain to, beside those the FIDO Metadata Service lists; empty trusts only what the active MDS BLOB lists. |
| `webauthn.attestationEvidenceTsaUrl` | `STS_WEBAUTHN_ATTESTATION_EVIDENCE_TSA_URL` | *(empty)* | yes | HTTPS RFC 3161 timestamp authority for optional RFC 4998 evidence records. Empty disables evidence recording; when enabled, TSA failure refuses registration of an eligible attestation. |
| `webauthn.attestationEvidenceTsaTrustAnchors` | `STS_WEBAUTHN_ATTESTATION_TSA_TRUST_ANCHORS` | *(empty)* | yes | PEM trust anchors for validating timestamp tokens and their TSA certificate path. |
| `webauthn.attestationEvidenceHashAlgorithm` | `STS_WEBAUTHN_ATTESTATION_HASH_ALGORITHM` | `sha256` | yes | Digest for new evidence records; `sha384` or `sha512` triggers RFC 4998 hash-tree renewal during the daily passkey report recount. |
| `webauthn.passkeyHistoryDays` | `STS_WEBAUTHN_PASSKEY_HISTORY_DAYS` | `400` | yes | How many days of the daily passkey history row a realm keeps, for the `passkeyHistory` report source ([Passkeys](passkeys.md#the-move-over-time)). |
| `webauthn.attestationAllowedAaguids` | `STS_WEBAUTHN_ATTESTATION_ALLOWED_AAGUIDS` | *(empty: any model)* | yes | The authenticator models (AAGUIDs, comma-separated) a key may be registered from. Set, it requires a trusted attestation whatever the policy says. |
| `webauthn.attestationMinCertificationLevel` | `STS_WEBAUTHN_ATTESTATION_MIN_CERTIFICATION` | `none` | yes | The least FIDO certification level (`L1` to `L3plus`) a model must hold, from MDS status reports; anything but `none` requires a trusted attestation from a model MDS lists. |
| `webauthn.attestationRequireFips` | `STS_WEBAUTHN_ATTESTATION_REQUIRE_FIPS` | `false` | yes | Refuse a model MDS does not report as FIPS 140 certified; on, it requires a trusted attestation from a model MDS lists. |
| `webauthn.attestationAllowSafetynet` | `STS_WEBAUTHN_ATTESTATION_ALLOW_SAFETYNET` | `false` | yes | Whether a (deprecated) `android-safetynet` statement may count as trusted. It is verified either way; off records it as untrusted and `require-trusted` refuses it. |
| `webauthn.attestationAndroidSoftwareKeys` | `STS_WEBAUTHN_ATTESTATION_ANDROID_SOFTWARE` | `false` | yes | Off, an `android-key` statement's `origin` and `purpose` are read from the hardware-enforced (TEE or StrongBox) list only; on, from the union of the software- and hardware-enforced lists. |
| `webauthn.timeoutMs` | `STS_WEBAUTHN_TIMEOUT_MS` | `60000` | yes | The `timeout` hint handed to the browser. |
| `webauthn.authenticatorAttachment` | `STS_WEBAUTHN_ATTACHMENT` | `any` | yes | `platform`, `cross-platform` or `any`; a filter in the browser. |
| `webauthn.credProps` | `STS_WEBAUTHN_CRED_PROPS` | `true` | yes | Ask the browser to report whether the credential is discoverable. |
| `webauthn.primaryAllowed` | `STS_WEBAUTHN_PRIMARY_ALLOWED` | `true` | yes | Whether any passkey may sign somebody in on its own (passwordless), asked at the sign-in. Off, no passkey is a first factor, including one registered while it was on. |
| `webauthn.mfaAllowed` | `STS_WEBAUTHN_MFA_ALLOWED` | `true` | yes | Whether any passkey may be the second factor after a password, asked at the sign-in. With both this and `webauthn.primaryAllowed` off, no new passkey can be registered (`STS-AUTHN-0531`). |
| `webauthn.maxKeysPerPerson` | `STS_WEBAUTHN_MAX_KEYS` | `10` | yes | How many keys one person may hold; refuses the enrolment, never a sign-in. |

### TOTP settings

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
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
* **A passkey used alone (passwordless) is one factor.** `acr "mfa"` would claim more than
  anybody checked. Calling it `mfa` because it is phishing-resistant would be
  exactly the fake that WS-Federation's `wauth` handling refuses to write.
* **A demand for two factors is enforced on the server.** A relying party's
  `acr_values` is how it demands a second factor, and a service that ignored it
  would let a client's step-up request appear to work while proving nothing.
  The sign-in screen disables the opt-outs, but `disabled` is a property of a
  browser and not of an HTTP request, so the passwordless path is refused on
  the server as well.
* **Enrolling an authenticator app is two steps, and the first writes
  nothing.** An unconfirmed secret on somebody's entry would be a second factor
  they cannot produce: open the page, be interrupted, come back tomorrow, and a
  one-step enrolment has locked somebody out of their own account with a form
  they abandoned.
* **The WebAuthn verifier is independent of the parent project's.** It shares
  no code with the debugger's decoder — not the CBOR reader, the COSE mapping
  or the signature check — so the cross-implementation test there compares two
  implementations rather than one agreeing with itself. (This side verifies
  ECDSA in its native DER form; the browser side converts DER to raw `r‖s`
  because Web Crypto will not take DER.)
* **The ceremony runs in the sign-in page's own script** (`/authn/signin.js`)
  since #572, armed by `POST /authn-api/mfa/{id}/webauthn/options`; the page's
  policy allows only `'self'` scripts, never an inline one. Whether a step
  registers a passkey or asks for one is the step's, never the browser's to
  choose.
* **Settings that turn a mechanism off do not remove what people already
  hold.** Otherwise a switch would silently downgrade accounts to one factor.
  The two passkey use settings are the exception in effect, not in data: since
  #1135 they say how ANY passkey may be used, so turning
  `webauthn.primaryAllowed` off stops every passkey signing anybody in on its
  own — a person with no password then needs another way in — and the
  passkeys stay held.
* **An authenticator app can never be a first factor.** The service holds the
  same secret.
* **Recovery codes are generated on request, shown once and hashed.** Hashing
  is only possible while a code is in the clear, so an automatic issue would
  hash a list nobody ever saw. A prompt nudges people who hold a second factor
  and no set.
* **The code screens refuse wrong codes by name.** The person has already
  given a first factor, so there is nothing to enumerate, and "already used"
  and "wrong" call for different actions.
* **In product the passwordless box enrols no passkey.** If it
  did, anybody who knew a username could take an account that had no key.
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

* **Protocols → WebAuthn** (`/admin/webauthn`): the **Settings** tab has
  every `webauthn.*` setting — the ceremony, CTAP2, algorithm and
  attestation settings; the **Metadata** tab says what a ceremony is asked
  for now, with the algorithms in the order they are requested. The
  authentication policy is on Directory → Policies. API:
  `GET /admin-api/webauthn`.
* **Protocols → TOTP MFA** (`/admin/totp`): the eight RFC 6238 parameters, and
  the authentication policy (Directory → Policies). API: `GET /admin-api/totp`.
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
  `/portal/keys` (passkeys), `/portal/app-passwords` (app passwords for
  the password-only doors), `/portal/kerberos` (a Kerberos keytab from your own
  password), `/portal/password`, `/portal/activate` and
  `/portal/reset-password`; and `/portal/consents`, where a person withdraws
  what they agreed an application may ask for, revoking what it was issued
  under it (see [OAuth 2.0 and OpenID Connect](oauth-oidc.md#withdrawing-consent)).
  `/portal/delegate` names the one party who may act for you — typed as a
  DN, or found by part of a person's username — and it is the
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
