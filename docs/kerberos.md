---
title: Kerberos
---

# Kerberos, KKDCP and SPNEGO

iya-sts runs a **Kerberos v5 KDC**
([RFC 4120](https://www.rfc-editor.org/rfc/rfc4120)) on raw TCP and UDP port
88 and over [MS-KKDCP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/),
a **Kerberos-protected service** that accepts an
[RFC 4121](https://www.rfc-editor.org/rfc/rfc4121) GSS token, and the same
acceptor over HTTP as **SPNEGO**
([RFC 4178](https://www.rfc-editor.org/rfc/rfc4178) carried by
[RFC 4559](https://www.rfc-editor.org/rfc/rfc4559)). A verified ticket can also
**sign a person in**: `/authn/spnego` turns it into the browser session every
other protocol reads. Every trust realm that turns Kerberos on gets **a KDC, a
Kerberos realm and keys of its own**, on the shared port 88.

Kerberos is the one protocol here that cannot be permissive about a password:
the password *is* the key, so even a development KDC has to use a key the
client cannot guess.

## Features

### The KDC

* **The AS and TGS exchanges**, over TCP and UDP on `krb5.kdcPort` (88), and
  over HTTPS at **`/KdcProxy`** (MS-KKDCP). A UDP reply larger than
  `krb5.udpMaxReplyBytes` is answered `KRB_ERR_RESPONSE_TOO_BIG` so the client
  retries over TCP, as a real KDC does.
* **Pre-authentication**: `KDC_ERR_PREAUTH_REQUIRED` offers PA-ENC-TIMESTAMP
  and carries the salt in PA-ETYPE-INFO2. MIT Kerberos `kinit`, `klist`, `kvno`
  and `curl --negotiate` complete against it end to end.
* **FAST and a second factor** (RFC 6113, RFC 6560, RFC 8129) — see
  [A second factor over Kerberos](#a-second-factor-over-kerberos-fast-and-otp)
  below.
* **Encryption types** from `krb5.enctypes`: aes256-cts-hmac-sha1-96 (18),
  aes128-cts-hmac-sha1-96 (17), aes256-cts-hmac-sha384-192 (20),
  aes128-cts-hmac-sha256-128 (19) and rc4-hmac (23). Removing 23 is what a
  hardened domain does. **rc4-hmac is development mode's** (#182): RFC 8429
  deprecates it, so in product mode the list is read without 23 — no RC4 key
  is derived, stored or put in a keytab, an AS-REQ or TGS-REQ offering only
  RC4 is refused `KDC_ERR_ETYPE_NOSUPP` (`STS-KRB-0156`), an RC4 session key
  or subkey in a TGS-REQ, an AP-REQ or FAST armor is refused (`STS-KRB-0157`,
  `0158`, `0159`), and a write naming 23 is refused (`STS-CORE-0103`).
* **A signed [MS-PAC]** in every ticket, built under `krb5.domainSid`, with
  `krb5.logonServer` as the LogonServer.
* **Renewable tickets**, bounded by `krb5.ticketLifetimeSeconds` and
  `krb5.renewLifetimeSeconds` (Active Directory's ten hours and seven days).
* **Cross-realm referrals**, in development mode, to a second realm
  (`krb5.trustedRealm`, `PARTNER.COM`) through an inter-realm trust key.
* **A deliberate clock offset** (`krb5.clockOffset`), so `KRB_AP_ERR_SKEW` can
  be produced on purpose — in development mode only: a product realm's KDC runs
  on the machine's clock whatever is stored (#181) — and **names that stay unknown**
  (`krb5.unknownUsers`), so `KDC_ERR_C_PRINCIPAL_UNKNOWN` stays reachable.

`GET /krb5/principals` lists the principal database, what each account is for,
whether each socket bound, and what is not implemented.

### Delegation

All four ways Kerberos can act on somebody's behalf:
[MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/)
**S4U2Self** (protocol transition), **S4U2Proxy** under classic constrained
delegation (`msDS-AllowedToDelegateTo` on the front end) and resource-based
constrained delegation (`msDS-AllowedToActOnBehalfOfOtherIdentity` on the back
end, which also needs `PA-PAC-OPTIONS`), and a **forwarded ticket-granting
ticket**. The account flags `NOT_DELEGATED` and
`TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` are honoured; `ok-as-delegate` is
advice to the client, not a control.

**Kerberos is the only family here that polices delegation.** A refusal names
the attribute and its current value in the error's `e-text`. Every act —
issued or refused — is recorded on `/admin/delegation`, which also publishes the
policy: every permitted pair from both attributes in one list, and a warning for
a front end with `msDS-AllowedToDelegateTo` but no
`TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION`, whose S4U2Self ticket is not
forwardable. In development mode fixture accounts (including one,
`HTTP/notrusted`, that produces exactly that failure) make both the refusals
and the successes reachable; in product mode there are no rules until an
operator writes one.

### The protected service

An acceptor on `krb5.servicePort` (8888) that decrypts an AP-REQ under the
long-term key of `krb5.servicePrincipal`, checks the ticket, refuses a
**replayed Authenticator**, and proves itself back with an AP-REP.
`GET /krb5/service` describes it and, when the account could not be created,
says why. Its replay cache is shared across a cluster, so an AP-REQ replayed to
another node is refused too.

### SPNEGO over HTTP

* **`/spnego`** describes the negotiation: the SPN, the realm, the mechanisms,
  the hosts it will answer for, and three knobs.
* **`/spnego/protected`** answers `401 WWW-Authenticate: Negotiate` to an
  unauthenticated request and `200` with an AP-REP in that header to a valid
  one. The 401 also carries `X-Krb5-Service-Principal` and
  `X-Krb5-Accepts-Spn-Hosts` — nobody's standard, and there because SPNEGO
  carries no SPN: a client has to guess `HTTP/<url host>`, and a wrong guess is
  the commonest SPNEGO failure there is.
* **NegTokenInit** with the optimistic mechToken, **NegTokenResp** in all four
  negStates, and the **mechListMIC** in both directions. Only Kerberos is
  offered; NTLM is recognised in a client's list and never selected.
* The three knobs on `/spnego/protected` only: `mic=require` (force the
  mechListMIC round trip), `mech=none` (reject the negotiation) and
  `mutual=off` (accept the ticket, send no AP-REP).

A `request-mic` exchange takes two HTTP requests; between them it is held for
`krb5.spnegoPendingTtlSeconds` and matched by a cookie
(`sts_spnego_negotiation`), or by its MIC for a client with no cookie jar.

### Signing in with a ticket: `/authn/spnego`

The same handshake, through the same acceptor, followed by a browser session.
It is the one sign-in here that rests on a credential the service genuinely
verified. What the session claims is read off the **ticket's own flags**:

| Ticket flags | `amr` | `acr` |
|---|---|---|
| `pre-authent` | `["pwd"]` | `1` |
| `hw-authent` | `["hwk"]` | `1` |
| both | `["pwd","hwk"]` | `mfa` |
| `pre-authent`, and the RFC 8129 indicator `otp` | `["pwd","otp"]` | `mfa` |
| neither | *(empty)* | `0` |

The indicator is believed only from an AD-CAMMAC whose verifier checks under
the service's own key, and only in a ticket from this realm's KDC.

The local realm is stripped from the principal (`alice@EXAMPLE.COM` signs in
`alice`, the same entry a typed sign-in finds); a foreign realm is kept whole.

It is available to every application and registered for none, three ways:

1. **"Sign in with Kerberos"** on `/authn/login` (`krb5.spnegoLoginButton`),
   for whatever flow is in progress — OAuth 2.0, WS-Federation, SAML, the
   console;
2. **`appAuthnMechanism: spnego`** on an application entry — its people never
   see the screen;
3. **`fedAuthnMechanism: spnego`** on an identity-provider-side
   [federation](federation.md) relationship.

The button is withheld from a request that demanded two factors, and says why.
Every refusal draws a page linking back to the sign-in screen, because a bare
`401 Negotiate` is a dead end in a browser not configured for this host
(Chrome's `--auth-server-allowlist`, Firefox's
`network.negotiate-auth.trusted-uris`, plus a credential cache in the realm).
With `krb5.spnegoAuthentication` off the door answers 403 naming the setting,
and `/spnego/protected` still performs the whole handshake.

### Signing out

A [sign-out](signing-out.md) stamps a **sign-out instant** on the principal,
and a TGS-REQ whose ticket was authenticated before it is refused
**`KDC_ERR_TGT_REVOKED` (20)**. It is checked on `authtime`, so a renewal cannot
launder a signed-out ticket. The next AS exchange succeeds, and **does not lift
the instant**: its new ticket is accepted — the exchange waits, at most a
second, for the sign-out's whole second to pass, because `authtime` has no
fractions — while every ticket from before the sign-out stays refused until the
latest one could still be valid (the sign-out plus the longer of
`krb5.ticketLifetimeSeconds` and `krb5.renewLifetimeSeconds`, plus
`krb5.clockSkew`). The instant is taken on the KDC's clock, so
`krb5.clockOffset` (development only) moves it with `authtime`. A service ticket already in a cache
keeps working against the service that accepts it — nothing contacts the KDC on
that exchange — and `/logout` says so. `logout.kerberosSignOut` turns it off.
The console's `restore-kerberos` clears an instant in development mode and is
refused in product mode.

### A KDC per trust realm

Port 88 routes a request by the **Kerberos realm name inside it**, so each
[trust realm](trust-realms.md) with `krb5.enabled` answers for its own
`krb5.realm`, from its own principal database, with its own settings,
statistics and audit log. A realm is created with Kerberos **off**, and turning
it on is refused until it has a `krb5.realm` no other realm answers to
(`STS-KRB-0123`, `STS-KRB-0124`); renaming one while it is on is refused
(`STS-KRB-0125`), because every key is salted with the name.

* The sockets and a bare `/KdcProxy` route by name, which is what `krb5.conf`
  configures. **`/realm/{id}/KdcProxy` is pinned** to that realm and refuses
  another realm's name with `KDC_ERR_WRONG_REALM`.
* Every name in a realm's database follows that realm's own domain — a realm
  called `CORP.BANK.EXAMPLE` holds `alice@CORP.BANK.EXAMPLE` and
  `HTTP/web.corp.bank.example`.
* **Trust realms do not trust each other's Kerberos**: no referrals between
  them. The two sockets and the development second realm stay the process's.

### Stored long-term keys (product mode)

* **A person's keys are derived from their own password** when it is set or a
  sign-in verifies it, and stored sealed on their directory entry. Somebody
  whose keys have not been derived yet is told to sign in once.
  `krb5.personKeys` turns this off. The details are under
  [How a person's keys are derived](#how-a-persons-keys-are-derived) below.
* **Service principals** created at `/admin/kerberos/principals` (or
  `POST /admin-api/kerberos/principals/create-service`) get a random key per
  enctype, stored sealed on the application entry for `<spn>@<realm>`, and
  handed over **once** as an MIT keytab. Rotate replaces the key at the next
  kvno; Delete removes it. The KDC issues tickets for that SPN under the stored
  key in both modes, and the acceptor prefers a stored key for its own SPN over
  `krb5.servicePassword` — which is how the acceptor in product mode gets a key
  without a password printed anywhere.
* **A password change or a Rotate keeps the previous key version** —
  `krb5.retainedKeyVersions` of them, each for `krb5.retainedKeyTtlS` — so a
  ticket issued under it is still accepted, while pre-authentication and
  issuance use the current key only: an old password never signs in. A
  rotation's keytab carries every kept version. **Drop previous versions** ends
  the window early. See [Previous key versions](#previous-key-versions) below.
* **A person's keytab** (#59) is always derived from a password in hand, never
  read out of storage, and holds the current kvno only:
  * **on `/portal/kerberos`** the person types their current password and gets
    a keytab for their own principal; nothing on the account changes, and the
    keytab stops working when the password next changes;
  * **on their page under Directory → Users** an administrator uses **Reset
    password and download keytab** — a typed password, or a generated one that
    nobody is shown. **This changes their password**: the old one stops
    working everywhere, they are signed out, and the kvno moves up by one.
    They are not asked to change it at their next sign-in, because that would
    end the keytab. The same act over the API is
    `POST /admin-api/kerberos/principals/reset-person-keytab`.

  On the portal the typed password is verified first — it is also the
  re-authentication a password-equivalent export needs. Either way the key is
  derived again and compared with the one the KDC holds before the keytab is
  handed over. Use it with `kinit -k -t <file> <user>@<REALM>`. In development
  mode every user is keyed from `krb5.userPassword`, so the keytab holds that
  key (`source: "development"`).
* No page, API reply, directory search or audit row ever shows a key — except
  the keytab a create, rotate or keytab download hands over, once. An LDAP
  search and the directory dump withhold both key attributes, ciphertext
  included.

#### How a person's keys are derived

A person's password is stored as a scrypt hash, and no Kerberos key can be
derived from a hash. So the keys are derived at the two moments a plaintext
password is in hand:

* when it is **set** — the console, `/admin-api`, the portal's form, an
  activation link, the bootstrap;
* when a sign-in **verifies** it — the sign-in screen, an LDAP bind, SCIM
  Basic, a WS-Trust UsernameToken, SSF Basic, the password grant.

RFC 3961/3962/8009 string-to-key runs for every enctype in `krb5.enctypes`
(never 23 in product) with the default salt `<REALM><name>`
(`EXAMPLE.COMalice`), and the keys are stored on the person's own entry as ONE
sealed value (`stsKrb5Keys`, with the public `stsKrb5KeyInfo` beside it). So:

* **Somebody who had a password before keys were stored gets them at their
  first sign-in anywhere.** Until then the KDC refuses them
  `KDC_ERR_C_PRINCIPAL_UNKNOWN` with the e-text *this principal has no Kerberos
  keys yet - sign in once with the password, or reset it*.
* **A password change adds one to the kvno and replaces the keys**, so an
  AS-REQ with the old password fails pre-authentication. The previous version
  is kept only to open tickets already sealed under it. A TGT already issued is
  sealed under the krbtgt key and is not recalled by a password change —
  Kerberos has no such mechanism.
* **The keys carry a stamp of the password hash they were derived beside**, and
  the KDC refuses keys whose stamp is not the entry's current hash — so a
  password changed by any door, an `ldapmodify` included, is never answered
  with a key from the old one.
* **The derivation is asynchronous and lags the password by a few tens of
  milliseconds**; in that window the person is refused rather than keyed from
  anything older.
* **The trust realm is the one the password was set in.** A trust realm whose
  `krb5.enabled` is on has a Kerberos realm and a principal database of its
  own, so the people it keys are the people in its own directory subtree, and
  their keys go onto their own entries there. A password set in a realm with no
  KDC derives nothing.
* `krb5.personKeys` turns it off — the setting for a deployment whose Kerberos
  is a real KDC elsewhere and which uses this service only as an acceptor.

#### Previous key versions

A rotation or a password change keeps the version it replaced, sealed in the
same value as the current keys, as a real KDC keeps the previous kvno in its
database and a service keeps it in its keytab — so a ticket issued under the old
key an instant before the change is still accepted until it could have expired,
and is refused `KRB_AP_ERR_BADKEYVER` after that.

* At most `krb5.retainedKeyVersions` previous versions (default 1; 0 keeps
  none), each for `krb5.retainedKeyTtlS` (default 0, meaning
  `krb5.ticketLifetimeSeconds` plus `krb5.clockSkew` — no ticket here outlives
  its lifetime, a renewal needs an unexpired ticket and re-seals under the
  current key, and an acceptor tolerates the skew). Both bounds are applied at
  every read, so lowering either takes effect on the next request.
* **A kept version only OPENS a ticket already sealed under it** — at the KDC
  (the ticket in a TGS-REQ, or an S4U2Proxy evidence ticket) and at the
  acceptor. The KDC always issues under the current kvno.
* A rotation's keytab carries every kept version beside the new one, as MIT's
  `ktadd` without `-k` leaves a keytab.
* `/admin/kerberos/principals` and `GET /admin-api/kerberos/principals` list
  each kept version (kvno, enctypes, expiry) and never its key; **Drop previous
  versions** (`drop-previous-service-keys`, `drop-previous-person-keys`) ends
  the window at once — after a compromise, say — leaving the current key
  untouched.

### A second factor over Kerberos: FAST and OTP

**In product, a person who holds or must hold a second factor gets no ticket
on a password alone** — an authenticator app, a security key in the `mfa`
role, `stsMfaRequired` on their entry, or the realm's authentication policy (`requireSecondFactor`),
the same rule the [password-only doors](what-is-not-checked.md#app-passwords-at-the-password-only-doors)
follow. An AS-REQ that proves only the password is refused `KDC_ERR_POLICY`
(12), **after** the password verified: a wrong password is still
`KDC_ERR_PREAUTH_FAILED`, so the refusal tells nobody without the password
anything. Development issues the ticket (`mode.issuesTicketsOnPasswordAlone()`).

What such a person uses instead:

* **FAST armor (RFC 6113).** Every `KDC_ERR_PREAUTH_REQUIRED` advertises
  PA-FX-FAST. The armor is a ticket-granting ticket the client HOST got with its
  own keytab — make the host a principal at `/admin/kerberos/principals` (or
  `POST /admin-api/kerberos/principals/create-service`) and `kinit -k` it. The
  armored exchange carries every padata and every error encrypted; the reply
  carries a KrbFastFinished over the ticket, and the reply key is always
  strengthened. The encrypted challenge (the password inside FAST) is served,
  with a replay check.
* **OTP pre-authentication (RFC 6560)** inside the armor, for a person with an
  authenticator app: the KDC asks for the code and, separately, the PIN — and
  **the PIN is the password**, checked as the Kerberos key it derives. Both
  factors in one exchange. The code is verified by the sign-in screen's own
  verifier and spent from the same once-only step, so one code cannot be used
  at both. An app password is not a Kerberos key and is refused.
* **The ticket says so (RFC 8129)**: an AD-CAMMAC carrying the authentication
  indicator `otp`, copied into the service tickets the TGT buys. At
  [`/authn/spnego`](#signing-in-with-a-ticket-authnspnego) it makes the session
  two factors.

With MIT Kerberos:

```bash
kinit -k -t host.keytab -c FILE:/tmp/armor host/ws1.example.com@EXAMPLE.COM
kinit -T FILE:/tmp/armor alice@EXAMPLE.COM
# Enter OTP Token Value: <the six digits>
# OTP Token PIN: <alice's password>
```

The KRB-FX-CF2 and the Kerberos PRF FAST needs are section 9 of
`common/crypto.js`, held to RFC 3961's and MIT's test vectors.

`/admin/kerberos` and `GET /admin-api/kerberos` (`status`) say what the KDC
does in the realm. A person whose only second factor is a security key cannot
use Kerberos yet: PKINIT is [#179](https://github.com/rcbj/iya-sts/issues/179).

### The `krbtgt` key, and its rotation

Every ticket-granting ticket a realm issues is sealed under its `krbtgt` key,
so whoever holds that key can forge a TGT for anybody in the realm (a "golden
ticket"). Since #169:

* **Product mode keys `krbtgt` at random.** RFC 3961 random-to-key for every
  enctype in `krb5.enctypes` (never rc4-hmac there), made once per realm at its
  first start — once for a cluster, by whichever node wins a claim — and kept
  sealed on the directory entry `krbtgt/<REALM>@<REALM>` under
  `ou=applications`. It is never shown, never in a keytab, never in an audit row
  or an LDAP search. `krb5.krbtgtPassword` is development's only and is ignored
  in product.
* **Development keeps the published password** (`krbtgt-mock-password`), so a
  reader can decrypt a TGT — until somebody rotates it by hand, which replaces
  it with a random stored key.
* **It rotates.** The `krb5.krbtgt-rotate` scheduler job checks each realm every
  hour and rotates a key at least `krb5.krbtgtRotationIntervalDays` old (180 by
  default, Active Directory's common guidance; 0 is off; product only). A
  rotation moves the kvno up by one and **keeps the version it replaced** for
  the longest a TGT under it can live — the longer of the ticket and renew
  lifetimes plus the clock skew, unless `krb5.retainedKeyTtlS` names a number —
  so every TGT, and a FAST armor ticket or cookie made under it, goes on
  working until it expires. **The job never rotates while that window is still
  open**, so the schedule cannot make the "two resets inside one TGT lifetime"
  that strands a live ticket. With `krb5.retainedKeyVersions` at 0 it stays
  off: a rotation that keeps nothing would sign everybody out unannounced.
* **By hand, in both modes**, on **Protocols → Kerberos → Principals** or
  `POST /admin-api/kerberos/principals/rotate-krbtgt`: queued on the scheduler
  and run once, on its leader. **Rotate and invalidate**
  (`rotate-krbtgt-invalidate`, with `confirm: "invalidate"` typed) is Active
  Directory's double reset in one act, for a key presumed compromised: nothing
  is kept, every TGT in the realm is refused `KRB_AP_ERR_BADKEYVER` (44) at its
  next use, everybody runs a fresh AS exchange, and the Shared Signals event
  `urn:iya:sts:secevent:event-type:kerberos-tickets-invalidated` says so. It is
  also the one act that replaces a stored record the service cannot open.
  **Drop previous versions** ends a rotation's window early.
* **A sign-out still works across a rotation** (#111): it is a stamp on the
  person's principal checked against the TGT's `authtime`, whatever key sealed
  the ticket.
* **Upgrading from a release before #169** gives a product realm a new random
  `krbtgt` key at its first start; TGTs sealed under the old password-derived
  key stop working once, and everybody signs in again.
* **Not rotated**: `krbtgt/<partner realm>`, the inter-realm trust key, is a
  secret shared with the partner (development only here).
* **Post-quantum.** No post-quantum Kerberos enctype is standardised. The
  strongest registered ones — aes256-cts-hmac-sha384-192 (20, RFC 8009) and
  aes256-cts-hmac-sha1-96 (18) — are symmetric, and Grover's algorithm leaves
  AES-256 at about 128-bit strength, so rotation needs no new enctype. The
  quantum-exposed part of Kerberos is PKINIT's public-key key agreement, which
  this service does not implement (#179).

### Not implemented

PKINIT (#179), FAST in the TGS exchange (a TGS-REQ carrying implicit armor is
answered unarmored, which MIT's client accepts), anonymous PKINIT armor, the
FAST hide-client-names option (refused as an unknown critical option), OTP
PIN change and hashed OTP values, kpasswd, user-to-user, request signatures,
SID filtering (see [the PAC](#the-pac) below), claims and device info in the
PAC, and rotation of an inter-realm trust key. DES is decoded and never
produced: Windows Server 2025 removed it and it is not coming back. The **AP
exchange** is not missing from the KDC — it belongs to a service rather than to
a KDC, and it lives in the [protected service](#the-protected-service).
`GET /krb5/principals` carries the current list. The UDP socket cannot carry a
PROXY protocol header, so behind a load balancer Kerberos clients use TCP.

## Development and product mode

| | Development | Product |
|---|---|---|
| User accounts | any name authenticates and **every user shares one password** (`password!`, `krb5.userPassword`), created on first sight | directory people authenticate with **keys derived from their own password**; nobody is created on demand |
| Service accounts | a service-shaped name is created on demand for a host in `krb5.serviceDomains`, with `krb5.autoServicePassword` | nothing is created on demand; service principals are made at `/admin/kerberos/principals` |
| Fixtures | alice, bob, misconfigured users, a computer account, delegation services with `msDS-*` rules, and the trusted second realm | none; `PARTNER.COM` is `KDC_ERR_WRONG_REALM` |
| `krbtgt` | derived from the published `krb5.krbtgtPassword`, until rotated by hand | a **random** key, stored sealed on the directory and rotated every `krb5.krbtgtRotationIntervalDays` (#169); `krb5.krbtgtPassword` is ignored |
| The acceptor's account | built from the published password | built only when `krb5.servicePassword` is **not** the published default; otherwise refused, and `/krb5/service` and `/krb5/principals` say why |
| Passwords on `/krb5/principals` | published, so a reader can decrypt a ticket and read its PAC | withheld |
| The PAC | invents `passwordLastSet` and `logonCount` | the zero FILETIME and 0 |
| Delegation | fixture rules make every refusal and success reachable | no rule until an operator writes one |
| A password alone, for a person who holds or must hold a second factor | a ticket | `KDC_ERR_POLICY`, after the password verified; FAST with OTP gets one |

In product mode every Kerberos listener binds `global.host`. The only principals a product realm starts with are
`krbtgt/<realm>` and the account `krb5.servicePrincipal` names — the latter
only where `krb5.servicePassword` is set to something other than its published
default.

What stays a refusal in development: a service-shaped name for a host this
service is not willing to be (`KDC_ERR_S_PRINCIPAL_UNKNOWN`), the names in
`krb5.unknownUsers` (`KDC_ERR_C_PRINCIPAL_UNKNOWN`), and a wrong password
(`KDC_ERR_PREAUTH_FAILED`). **The acceptor verifies real tickets in both
modes**, and a replay is refused in both. See
[What is not checked](what-is-not-checked.md).

## Configuration

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `krb5.enabled` | `KRB5_ENABLED` | `true` | yes | Whether this realm's KDC answers; on a trust realm, whether the realm has a Kerberos realm at all (created off). |
| `krb5.realm` | `KRB5_REALM` | `EXAMPLE.COM` | no | The Kerberos realm; its lower-cased form is the domain, and port 88 routes by it. |
| `krb5.kdcPort` | `KRB5_KDC_PORT` | `88` | no | The KDC's TCP and UDP port; `0` asks for any free port. A failure to bind is recorded, not fatal. |
| `krb5.servicePort` | `KRB5_SERVICE_PORT` | `8888` | no | The Kerberized test service that accepts an AP-REQ. |
| `krb5.servicePrincipal` | `KRB5_SERVICE_PRINCIPAL` | `HTTP/web.example.com` | no | The acceptor's SPN; a trust realm left at this default derives `HTTP/web.<its domain>`. |
| `krb5.servicePassword` | `KRB5_SERVICE_PASSWORD` | `service-account-password` | no | The acceptor account's password (the keytab equivalent); the default is refused in product mode. |
| `krb5.serviceSalt` | `KRB5_SERVICE_SALT` | *(empty)* | no | The string-to-key salt for that account; set it to accept tickets from a real Active Directory KDC. |
| `krb5.enctypes` | `KRB5_ENCTYPES` | `18,17,20,19,23` | no | The RFC 3961 encryption types used, strongest first; an unimplemented number stops startup. **Warning:** 23 (rc4-hmac) is deprecated by RFC 8429 and is used in development mode only — product reads the list without it and refuses a write naming it. |
| `krb5.kvno` | `KRB5_KVNO` | `3` | no | The kvno of every account built from a configured password, and the starting kvno of stored keys. |
| `krb5.ticketLifetimeSeconds` | `KRB5_TICKET_LIFETIME_S` | `36000` | yes | The longest a ticket is valid. |
| `krb5.renewLifetimeSeconds` | `KRB5_RENEW_LIFETIME_S` | `604800` | yes | How far `renew-till` reaches for a renewable ticket. |
| `krb5.logonServer` | `KRB5_LOGON_SERVER` | `DC01` | yes | The LogonServer name in every PAC. |
| `krb5.maxRequestBytes` | `KRB5_MAX_REQUEST_BYTES` | `131072` | yes | The most a client may send on one TCP connection before it is closed. |
| `krb5.udpMaxReplyBytes` | `KRB5_UDP_MAX_REPLY_BYTES` | `1465` | yes | A larger UDP reply is answered `KRB_ERR_RESPONSE_TOO_BIG`. |
| `krb5.serviceMaxTokenBytes` | `KRB5_SERVICE_MAX_TOKEN_BYTES` | `65536` | yes | The largest token the acceptor and SPNEGO accept. |
| `krb5.replayCacheMaxEntries` | `KRB5_REPLAY_CACHE_MAX_ENTRIES` | `10000` | yes | How many Authenticators the acceptor remembers; when full, a new one is refused rather than an old one forgotten. |
| `krb5.spnegoPendingTtlSeconds` | `KRB5_SPNEGO_PENDING_TTL_S` | `120` | yes | How long a `request-mic` exchange may sit between its two requests. |
| `krb5.spnegoMaxPending` | `KRB5_SPNEGO_MAX_PENDING` | `64` | yes | How many of those are held at once; the oldest is dropped. |
| `krb5.clockSkew` | `KRB5_CLOCK_SKEW` | `300` | yes | How far the KDC's and a client's clocks may differ before `KRB_AP_ERR_SKEW`. |
| `krb5.clockOffset` | `KRB5_CLOCK_OFFSET` | `0` | yes | Moves the KDC's clock deliberately, to produce a skew failure on purpose. Development mode only: anything but 0 is ignored in product (the KDC runs on the machine's clock), and setting it is refused (#181). |
| `krb5.userPassword` | `KRB5_USER_PASSWORD` | `password!` | no | The one password every development user account has, published on `/krb5/principals`. |
| `krb5.unknownUsers` | `KRB5_UNKNOWN_USERS` | `nosuchuser,nobody` | yes | Names never created on demand, so `KDC_ERR_C_PRINCIPAL_UNKNOWN` stays reachable. |
| `krb5.serviceDomains` | `KRB5_SERVICE_DOMAINS` | the realm's domain, `localhost`, `sts`, `127.0.0.1` | no | The host domains a service principal is created on demand for; empty creates none. |
| `krb5.autoServicePassword` | `KRB5_AUTO_SERVICE_PASSWORD` | `auto-service-password` | no | The published password of every on-demand service account. |
| `krb5.krbtgtPassword` | `KRB5_KRBTGT_PASSWORD` | `krbtgt-mock-password` | no | Development only: the password the key that seals every TGT is derived from. Product keys `krbtgt` at random and ignores it (#169). |
| `krb5.krbtgtRotationIntervalDays` | `KRB5_KRBTGT_ROTATION_INTERVAL_DAYS` | `180` | yes | How old a realm's `krbtgt` key gets before the `krb5.krbtgt-rotate` job replaces it; `0` is off. Product only; a rotation by hand works in both modes. |
| `krb5.domainSid` | `KRB5_DOMAIN_SID` | `S-1-5-21-1004336348-1177238915-682003330` | no | The domain SID every PAC is built under. |
| `krb5.trustedRealm` | `KRB5_TRUSTED_REALM` | `PARTNER.COM` | no | The second realm, for cross-realm referrals (development). |
| `krb5.trustPassword` | `KRB5_TRUST_PASSWORD` | `inter-realm-trust-password` | no | The shared secret of the cross-realm trust. |
| `krb5.trustedDomainSid` | `KRB5_TRUSTED_DOMAIN_SID` | `S-1-5-21-2035427030-2118130302-1178042555` | no | The trusted realm's domain SID. |
| `krb5.trustedKrbtgtPassword` | `KRB5_TRUSTED_KRBTGT_PASSWORD` | `partner-krbtgt-password` | no | The trusted realm's krbtgt password. |
| `krb5.spnegoAuthentication` | `KRB5_SPNEGO_AUTHENTICATION` | `true` | yes | Whether `/authn/spnego` may turn a ticket into a browser session. |
| `krb5.spnegoLoginButton` | `KRB5_SPNEGO_LOGIN_BUTTON` | `true` | yes | Show "Sign in with Kerberos" on `/authn/login`. |
| `krb5.personKeys` | `KRB5_PERSON_KEYS` | `true` | yes | Product mode only: derive and store people's keys from their passwords; off, the KDC refuses every person. |
| `krb5.retainedKeyVersions` | `KRB5_RETAINED_KEY_VERSIONS` | `1` | yes | How many previous key versions a stored key keeps; `0` keeps none. |
| `krb5.retainedKeyTtlS` | `KRB5_RETAINED_KEY_TTL_S` | `0` | yes | How long a previous version is kept; `0` means the ticket lifetime plus the clock skew — for the `krbtgt`, the longer of the ticket and renew lifetimes plus the skew. |
| `krb5.s2kparams` | `KRB5_S2KPARAMS` | `omit` | yes | Whether PA-ETYPE-INFO2 carries s2kparams; `omit` matches Windows Server, `send` exercises a client that reads it. |
| `logout.kerberosSignOut` | `LOGOUT_KERBEROS_SIGN_OUT` | `true` | yes | Whether a sign-out stamps the instant after which an older TGT is refused `KDC_ERR_TGT_REVOKED`. |

Most `krb5.*` settings are restart-only because the principal database is built
from them when the process starts (for a trust realm, when its Kerberos is
turned on). `global.proxyProtocol` also covers the KDC's TCP socket — see
[TLS](tls.md).

This table is a copy of rows in `common/config.js`; the live source is
`/admin/kerberos` and `GET /admin-api/config`.

See [Configuration](configuration.md) for how a value is resolved and where it
is changed: on `/admin/kerberos`, through `POST /admin-api/config/set`, or in an
appconfig file.

## Design decisions

* **Kerberos checks the key, and cannot not.** A permissive KDC still has to
  encrypt under a key the client can derive, so development mode's permissive
  equivalent is one shared, published password and accounts created on first
  sight.
* **Some refusals stay reachable on purpose.** Unknown client, unknown service
  and wrong password are the errors a client most needs to render correctly, so
  development keeps them producible.
* **A service is created on demand only for a host this service is willing to
  be.** A client derives `HTTP/<url host>`, and the KDC and acceptor share one
  table, so an on-demand service is one the acceptor can decrypt; any other
  host stays unknown.
* **The published passwords are refused in product mode.** A service key from
  the published password is a silver ticket, so that account is not built until
  a real secret is set. A krbtgt from it would be a golden one, and since #169
  product does not derive the krbtgt from a password at all: it is random.
* **The krbtgt rotates without stranding a ticket.** The version it replaces
  is kept for the longest a TGT under it can live, the schedule never rotates
  inside that window, and the one act that ends every TGT at once — rotate and
  invalidate — is a separate, confirmed control.
* **The session's `amr` and `acr` come from the ticket's flags.** It is the one
  place here where they are read off something a credential actually says; a
  ticket claiming neither flag gets an empty `amr`, not an assumed password.
* **`/authn/spnego` and `/spnego/protected` are the same negotiation.** One
  documents the other, so they share one acceptor and one verdict, and the
  diagnostic knobs are kept off the door that mints sessions.
* **A sign-out is enforced at the TGS exchange.** Kerberos has no logout and no
  revocation; the TGS exchange is the one moment a KDC is back in the loop,
  which is also where disabling an Active Directory account bites.
  `KDC_ERR_TGT_REVOKED` is registered but no specification emits it — this is an
  invention using the closest code.
* **Signing out is not disabling.** The next AS exchange succeeds — without
  lifting the instant, so tickets from before it stay refused (#111); a
  disabled account is `KDC_ERR_CLIENT_REVOKED` and refuses the AS exchange
  too.
* **Port 88 routes by the realm name in the request.** Every AS-REQ and TGS-REQ
  names a realm, so that is the discriminator; routing once, before any
  handler, means no handler can answer from the wrong realm's database.
* **Trust realms do not trust each other's Kerberos.** A realm's KDC holds no
  `krbtgt/<other realm>`.
* **A full replay cache refuses rather than forgets.** Evicting an Authenticator
  still inside its window would let an attacker push a captured AP-REQ out and
  replay it.
* **Kept key versions only open tickets already sealed under them.** A password
  change must not strand a ticket issued a moment earlier, and must not let the
  old password sign in.
* **Only Kerberos is offered in SPNEGO.** Advertising NTLM, which this service
  cannot perform, would be a lie a client would act on.
* **The listeners are raw sockets.** Everything else here answers a request over
  HTTP; Kerberos speaks DER over TCP and UDP port 88. That is why `/KdcProxy`
  exists — for a client, such as a browser, that cannot open a socket at all —
  and why `/admin/sts-metadata`, which reads the HTTP router, has to list the
  KDC's sockets by hand.

## The protocol, as a client debugger needs to see it

This service exists to exercise Kerberos *clients*, so the KDC and the acceptor
reproduce the details real deployments get wrong, and make each failure
drivable on purpose rather than by breaking something. What follows is
development mode's principal database unless it says otherwise.

### Two messages, and the salt

**The two-message dance is the interesting part, not the ticket.** A client's
first AS-REQ usually carries no pre-authentication, and a real KDC does not
treat that as an error to be logged and forgotten: it answers
`KDC_ERR_PREAUTH_REQUIRED` **carrying PA-ETYPE-INFO2**, which is where the
client learns the **salt** and iteration count it needs to turn a password into
a key. A client that treats that error as a failure cannot authenticate to
Active Directory at all. Both halves are implemented, and a principal
(`noreauth`) is configured the other way so the one-message case can be seen
too.

The salt is why this matters and why it is a database rather than a formula.
AD's salt for a **user** is the realm followed by the sAMAccountName with no
separator — `EXAMPLE.COMalice` — and for a **computer account** it is a
different shape entirely: `EXAMPLE.COMhostws01.example.com`. An implementation
that derives the salt from the principal name works right up to the first
machine account, which is exactly the point at which somebody is debugging a
service rather than a user.

### Any username, one password

Everything else in development mode checks no password at all: the name typed
at `/authn/login` becomes the identity. Kerberos cannot work that way, and the
reason is structural rather than a decision — the password *is* the key.
Pre-authentication is a timestamp encrypted under it and the AS-REP's enc-part
is encrypted under it too, so a KDC that accepted any password would still have
to choose one to encrypt the reply with, and a client that used a different one
could not read the ticket it was sent. So the nearest thing the protocol allows
is what happens here: **one password, `password!` (`krb5.userPassword`), shared
by every user account, and an account for every username that turns up.** A
name nobody configured is created on first sight with AD's user-shaped salt
(`EXAMPLE.COMzaphod`) and a PAC identity of its own, with RIDs from 5000 up so a
runtime account can be told from a configured one by its SID alone. This
applies to the second realm too, with *its* realm in the salt.

Three things are deliberately *not* included in that, and each is a failure
worth keeping:

* **A service principal is created only for a host this service will answer
  for.** `krb5.serviceDomains` (default: the realm's own domain, plus
  `localhost`, `sts` and `127.0.0.1`) is the list; an entry matches a host that
  *is* it or ends with a dot and it, and anything else is still
  `KDC_ERR_S_PRINCIPAL_UNKNOWN` — the most common Kerberos failure there is,
  and one worth keeping producible (`HTTP/app.elsewhere.invalid` is what the
  parent project's tests use). A KDC must not invent services in general
  because it would hand back a ticket sealed with a key the service does not
  hold, which surfaces at the AP exchange as *decrypt integrity check failed* —
  the same message a genuinely wrong key gives, pointing nowhere near the real
  cause. That does not apply here: **this process is both the KDC and the
  acceptor**, and the acceptor looks the presented SPN up in the same table, so
  a ticket for a name created on demand opens with the key that sealed it. A
  client derives its SPN from the URL's host (`HTTP/<host>` — RFC 4559, and
  what every browser does), so without this every way of reaching the service
  would ask for a name nobody had configured. The acceptor answers for its
  canonical `krb5.servicePrincipal` and for names created this way — and for
  **no other configured account**, because `HTTP/frontend.example.com` and
  `HTTP/backend.example.com` exist to be separate identities, and accepting
  their tickets would make this service every service in the realm.
* **The reserved names stay unknown** (`nosuchuser`, `nobody`, or whatever
  `krb5.unknownUsers` says), so `KDC_ERR_C_PRINCIPAL_UNKNOWN` is still
  reachable. A client that renders it as "wrong password" sends a person off to
  reset a password that was never the problem, which is exactly the misreading
  a debugger exists to correct.
* **A wrong password still fails**, with `KDC_ERR_PREAUTH_FAILED` and a re-sent
  PA-ETYPE-INFO2, because the client may simply have used the wrong salt.

Service, computer and `krbtgt` accounts keep their own distinct passwords.
Nobody types those, and `krbtgt/EXAMPLE.COM`, `krbtgt/PARTNER.COM` and the
trust have to hold three *different* secrets, or every assertion about which
key sealed which ticket would pass for the wrong reason.

### The misconfigured principals are the point

`GET /krb5/principals` lists the whole database — names, salts, offered
etypes, kvno, the pre-auth/revoked/expired/ok-as-delegate flags, which entries
were created at runtime, and a sentence on what each account is *for*. It
publishes no keys and no *service* passwords; the one user password it does
publish, in `accountPolicy`, is a policy of this mock rather than a secret —
every account holds it, and a debugger whose accounts cannot be used without
reading the source is worse than one that says so on the page.

Among the configured accounts: `locked` (a disabled account), `expired` (a
stale password), `aesonly` and `rc4only` (whose etype sets are chosen so that a
negotiation can be made to fail on purpose, which is what RC4 being switched
off looks like), `sensitive` (NOT_DELEGATED, the one control that stops
unconstrained delegation), a computer account, and a set of service accounts
wired for the delegation cases below. A debugger is judged on how it renders
failure, and these are the failures a real deployment produces. So is the
clock: `krb5.clockOffset` makes the KDC lie about its own time, because
`KRB_AP_ERR_SKEW` is one of the most common Kerberos failures in the field, and
the error carries the KDC's time so a client can *measure* the difference
rather than guess it.

### The PAC

**Every ticket carries a signed PAC** ([MS-PAC]), the half of Kerberos that
Windows added and RFC 4120 knows nothing about. A ticket proves *who* you are
and says nothing about your groups; a Windows service authorizes on the groups.
So "authentication succeeded but access was denied" is nearly always a question
about this structure, and a debugger that decodes a ticket and stops at `cname`
has shown the less interesting half.

Two things about it are silent when wrong, and are why `krb5_ndr.js` is its
own module. The PAC's logon information arrives in **NDR**, Windows' RPC
marshalling, which is little-endian in a protocol whose every other integer is
big-endian, and aligned from the start of the stream — miss one pad byte and
every field after it reads in range and false. And it sits three layers deep,
inside `AD-IF-RELEVANT`, so a reader that looks for ad-type 128 at the top
level finds nothing. A TGT gets two signatures and a service ticket four
(sections 2.8.2 and 2.8.3).

Claims and device info are not produced, and **SID filtering across a trust is
not implemented** — a re-signed PAC keeps every SID it arrived with, which is
the one place this KDC is more permissive than a real one in a way that
matters.

### Two realms, one shared key, and a referral that looks like success

In development this KDC answers for both `EXAMPLE.COM` and `PARTNER.COM`, which
a real one never does — the simplification hides finding the other realm's KDC
(DNS and SRV records) and none of the protocol. A trust is not a setting: it is
one principal, `krbtgt/PARTNER.COM@EXAMPLE.COM`, whose key both realms hold. Ask
for a service in the other realm and this KDC does not refuse; it issues a
ticket-granting ticket for that realm sealed with the trust key and expects the
client to notice. The trap is on the client side, which is why it is worth
being able to produce: the reply is a perfectly ordinary, successful TGS-REP,
and the *only* signal that it is a referral is that its `sname` is not what was
asked for.

### Delegation, with the distinctions drawn on purpose

The asymmetry between the two S4U2Proxy routes is the entire security story of
resource-based constrained delegation, so both kinds of account exist here
rather than one. Classic delegation is authorized by `msDS-AllowedToDelegateTo`
on the **front-end** account, which only a domain admin can set; RBCD is
authorized by `msDS-AllowedToActOnBehalfOfOtherIdentity` on the **back-end**
account (`HTTP/rbcd.example.com`, naming `HTTP/frontend.example.com` as
permitted to act on its behalf) — so whoever controls that object can turn "I
can write to this computer account" into "I can reach this service as anybody".
Same messages, same KDC options, opposite direction of trust.

Classic delegation additionally requires the evidence ticket to be forwardable,
which S4U2Self grants only to an account holding
TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION. So `HTTP/frontend.example.com` and
`HTTP/notrusted.example.com` differ in exactly that one attribute and nothing
else, because the flag's absence is invisible where it is set: S4U2Self still
succeeds and returns a ticket that simply is not forwardable, and classic
S4U2Proxy then fails a step later complaining about the evidence. RBCD needs
neither, but does need `PA-PAC-OPTIONS` with the RBCD bit, without which
[MS-SFU] says a KDC MUST answer `KDC_ERR_BADOPTION` — an error mentioning
nothing about padata, so it is refused here with an explanation.

### A service that will not talk to you without a ticket

Until something decrypts a ticket and proves its own identity back, "the ticket
looks right" is the strongest claim available. `krb5_service.js` is a raw TCP
acceptor — deliberately, because that is the shape of the Windows services
people actually debug — and `GET /krb5/service` describes it and the ordered
checks it applies:

1. the GSS wrapper;
2. the ticket decrypting under *its own* key at the kvno named;
3. the ticket being for *it* (a ticket for another service that happens to
   decrypt because two accounts share a password must still be refused);
4. the Authenticator under the ticket's session key;
5. the Authenticator's `cname` matching the ticket's;
6. the clock;
7. **the replay cache** — the check a mock is most tempted to skip, and the
   only thing between a captured AP-REQ and a free impersonation;
8. the 0x8003 checksum.

If mutual authentication was asked for, the AP-REP echoes the Authenticator's
`ctime` under the session key, and that echo *is* the proof — only something
holding the service's long-term key could have learned the session key to
produce it.

### The 0x8003 checksum is not a checksum

It is the single most commonly botched field in Kerberos: a structure carrying
channel bindings and the GSS flags, which `krb5_gss.js` writes out explicitly
because it fails in the least helpful way available — a service answers
`KRB_AP_ERR_INAPP_CKSUM` and nothing anywhere says "your flags word is in the
wrong byte order". Its fields are **little-endian**, alone in a protocol whose
every other integer is not, so a mistake produces `0x02000000` where
`0x00000002` was meant — a request for delegation where mutual authentication
was intended. The `Bnd` field is sixteen **zero** bytes when there are no
channel bindings, not absent. And per-message tokens are keyed by who is
speaking: an initiator signs with key usage 25 and seals with 24, an acceptor 23
and 22, and the wrong pair produces a token the far end cannot verify with an
error naming the checksum rather than the direction.

### Encryption types

The RFC 3961 framework covers the etypes Kerberos actually meets:
aes128/256-cts-hmac-sha1-96 (17, 18 — the AD workhorses),
aes128/256-cts-hmac-sha256/384 (19, 20 — RFC 8009) and, in development mode,
arcfour-hmac-md5 (23), which is there because a debugger whose only story
about RC4 is "that is deprecated" cannot help anybody still running it. DES is
decoded and never produced.

## In the running service

* **Protocols → Kerberos → Kerberos settings** (`/admin/kerberos`): the realm,
  the two raw ports, the clock skew and offset, the shared user password, the
  names that stay unknown, the krbtgt and trust keys, and whether
  `/authn/spnego` may start a session. Its endpoints are listed on the page.
* **Protocols → Kerberos → Principals** (`/admin/kerberos/principals`): who the
  KDC holds a stored key for — directory people (with kvno, enctypes, whether
  the keys still match the password, and kept versions) and service principals.
  Create, Rotate (each hands over a keytab once), Delete, clear a person's keys,
  and Drop previous versions; and the realm's `krbtgt` key — its kvno, last and
  next rotation and kept versions — with **Rotate the krbtgt key** and **Rotate
  and invalidate**. The controls need Admin Write.
* **Monitoring → Scheduler** (`/admin/scheduler`): the `krb5.krbtgt-rotate` and
  `krb5.krbtgt-rotate-now` jobs; each run's result names the kvno, the last
  rotation and when the next is due.
* **`/admin/delegation`**: every delegation act, refusals included, and the
  published policy.
* **Live descriptions**: `GET /krb5/principals` (the database, the sockets and
  what is not implemented), `GET /krb5/service` (the acceptor), `GET /spnego`.
* **Management API**: `GET /admin-api/kerberos`,
  `GET /admin-api/kerberos/principals` and
  `POST /admin-api/kerberos/principals/{create-service, rotate-service,
  delete-service, clear-person-keys, drop-previous-service-keys,
  drop-previous-person-keys, reset-person-keytab, rotate-krbtgt,
  rotate-krbtgt-invalidate}` — see
  `/admin-api/openapi.json`.
* **User portal**: `/portal/kerberos` — the signed-in person's principal, and a
  keytab made from their own password.
* The raw sockets register no HTTP route, so `/admin/sts-metadata` lists them by
  hand. Failures are recorded under `STS-KRB-NNNN` codes — see
  [Error codes](error-codes.md).

## Related

* [Authentication](authentication.md) — the sign-in screen and its Kerberos
  button
* [Sessions](sessions.md) and [Signing out](signing-out.md)
* [Federation](federation.md) — `fedAuthnMechanism: spnego`
* [Trust realms](trust-realms.md) — a KDC per realm
* [LDAP](ldap.md) — the directory people's keys are stored on
* [TLS](tls.md) — the certificate `/KdcProxy` is served with, and the PROXY
  protocol
* [What is not checked](what-is-not-checked.md)
* [Configuration](configuration.md)
