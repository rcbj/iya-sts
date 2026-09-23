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
* **Encryption types** from `krb5.enctypes`: aes256-cts-hmac-sha1-96 (18),
  aes128-cts-hmac-sha1-96 (17), aes256-cts-hmac-sha384-192 (20),
  aes128-cts-hmac-sha256-128 (19) and rc4-hmac (23). Removing 23 is what a
  hardened domain does.
* **A signed [MS-PAC]** in every ticket, built under `krb5.domainSid`, with
  `krb5.logonServer` as the LogonServer.
* **Renewable tickets**, bounded by `krb5.ticketLifetimeSeconds` and
  `krb5.renewLifetimeSeconds` (Active Directory's ten hours and seven days).
* **Cross-realm referrals**, in development mode, to a second realm
  (`krb5.trustedRealm`, `PARTNER.COM`) through an inter-realm trust key.
* **A deliberate clock offset** (`krb5.clockOffset`), so `KRB_AP_ERR_SKEW` can
  be produced on purpose, and **names that stay unknown**
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
| neither | *(empty)* | `0` |

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
launder a signed-out ticket; the next AS exchange succeeds and clears the
instant. A service ticket already in a cache keeps working against the service
that accepts it — nothing contacts the KDC on that exchange — and `/logout`
says so. `logout.kerberosSignOut` turns it off.

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
  `krb5.personKeys` turns this off.
* **Service principals** created at `/admin/kerberos/principals` get a random
  key, handed over **once** as an MIT keytab. A keytab minted for
  `krb5.servicePrincipal` keys the acceptor instead of `krb5.servicePassword`.
* **A password change or a Rotate keeps the previous key version** —
  `krb5.retainedKeyVersions` of them, each for `krb5.retainedKeyTtlS` — so a
  ticket issued under it is still accepted, while pre-authentication and
  issuance use the current key only: an old password never signs in. A
  rotation's keytab carries every kept version. **Drop previous versions** ends
  the window early.
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

  Use it with `kinit -k -t <file> <user>@<REALM>`. In development mode every
  user is keyed from `krb5.userPassword`, so the keytab holds that key.
* No page, API reply, directory search or audit row ever shows a key — except
  the keytab a create, rotate or keytab download hands over, once.

### Not implemented

FAST, PKINIT, kpasswd, user-to-user, SID filtering, and rotation of the
`krbtgt` key (a TGT under an older `krb5.krbtgtPassword` is refused).
`GET /krb5/principals` carries the current list. The UDP socket cannot carry a
PROXY protocol header, so behind a load balancer Kerberos clients use TCP.

## Development and product mode

| | Development | Product |
|---|---|---|
| User accounts | any name authenticates and **every user shares one password** (`password!`, `krb5.userPassword`), created on first sight | directory people authenticate with **keys derived from their own password**; nobody is created on demand |
| Service accounts | a service-shaped name is created on demand for a host in `krb5.serviceDomains`, with `krb5.autoServicePassword` | nothing is created on demand; service principals are made at `/admin/kerberos/principals` |
| Fixtures | alice, bob, misconfigured users, a computer account, delegation services with `msDS-*` rules, and the trusted second realm | none; `PARTNER.COM` is `KDC_ERR_WRONG_REALM` |
| `krbtgt` and the acceptor's account | built from the published passwords | built only when `krb5.krbtgtPassword` / `krb5.servicePassword` are **not** the published defaults (`STS-KRB-0062`); otherwise refused, and `/krb5/service` and `/krb5/principals` say why |
| Passwords on `/krb5/principals` | published, so a reader can decrypt a ticket and read its PAC | withheld |
| The PAC | invents `passwordLastSet` and `logonCount` | the zero FILETIME and 0 |
| Delegation | fixture rules make every refusal and success reachable | no rule until an operator writes one |

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
| `krb5.enctypes` | `KRB5_ENCTYPES` | `18,17,20,19,23` | no | The RFC 3961 encryption types used, strongest first; an unimplemented number stops startup. |
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
| `krb5.clockOffset` | `KRB5_CLOCK_OFFSET` | `0` | yes | Moves the KDC's clock deliberately, to produce a skew failure on purpose. |
| `krb5.userPassword` | `KRB5_USER_PASSWORD` | `password!` | no | The one password every development user account has, published on `/krb5/principals`. |
| `krb5.unknownUsers` | `KRB5_UNKNOWN_USERS` | `nosuchuser,nobody` | yes | Names never created on demand, so `KDC_ERR_C_PRINCIPAL_UNKNOWN` stays reachable. |
| `krb5.serviceDomains` | `KRB5_SERVICE_DOMAINS` | the realm's domain, `localhost`, `sts`, `127.0.0.1` | no | The host domains a service principal is created on demand for; empty creates none. |
| `krb5.autoServicePassword` | `KRB5_AUTO_SERVICE_PASSWORD` | `auto-service-password` | no | The published password of every on-demand service account. |
| `krb5.krbtgtPassword` | `KRB5_KRBTGT_PASSWORD` | `krbtgt-mock-password` | no | The key that seals every TGT; the default is refused in product mode. |
| `krb5.domainSid` | `KRB5_DOMAIN_SID` | `S-1-5-21-1004336348-1177238915-682003330` | no | The domain SID every PAC is built under. |
| `krb5.trustedRealm` | `KRB5_TRUSTED_REALM` | `PARTNER.COM` | no | The second realm, for cross-realm referrals (development). |
| `krb5.trustPassword` | `KRB5_TRUST_PASSWORD` | `inter-realm-trust-password` | no | The shared secret of the cross-realm trust. |
| `krb5.trustedDomainSid` | `KRB5_TRUSTED_DOMAIN_SID` | `S-1-5-21-2035427030-2118130302-1178042555` | no | The trusted realm's domain SID. |
| `krb5.trustedKrbtgtPassword` | `KRB5_TRUSTED_KRBTGT_PASSWORD` | `partner-krbtgt-password` | no | The trusted realm's krbtgt password. |
| `krb5.spnegoAuthentication` | `KRB5_SPNEGO_AUTHENTICATION` | `true` | yes | Whether `/authn/spnego` may turn a ticket into a browser session. |
| `krb5.spnegoLoginButton` | `KRB5_SPNEGO_LOGIN_BUTTON` | `true` | yes | Show "Sign in with Kerberos" on `/authn/login`. |
| `krb5.personKeys` | `KRB5_PERSON_KEYS` | `true` | yes | Product mode only: derive and store people's keys from their passwords; off, the KDC refuses every person. |
| `krb5.retainedKeyVersions` | `KRB5_RETAINED_KEY_VERSIONS` | `1` | yes | How many previous key versions a stored key keeps; `0` keeps none. |
| `krb5.retainedKeyTtlS` | `KRB5_RETAINED_KEY_TTL_S` | `0` | yes | How long a previous version is kept; `0` means the ticket lifetime plus the clock skew. |
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
* **The published passwords are refused in product mode.** A krbtgt from the
  README's password is a golden ticket, a service key from it a silver one, so
  those accounts are simply not built until a real secret is set.
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
* **Signing out is not disabling.** The next AS exchange succeeds and clears the
  instant; a disabled account is `KDC_ERR_CLIENT_REVOKED` and refuses the AS
  exchange too.
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

## In the running service

* **Protocols → Kerberos → Kerberos settings** (`/admin/kerberos`): the realm,
  the two raw ports, the clock skew and offset, the shared user password, the
  names that stay unknown, the krbtgt and trust keys, and whether
  `/authn/spnego` may start a session. Its endpoints are listed on the page.
* **Protocols → Kerberos → Principals** (`/admin/kerberos/principals`): who the
  KDC holds a stored key for — directory people (with kvno, enctypes, whether
  the keys still match the password, and kept versions) and service principals.
  Create, Rotate (each hands over a keytab once), Delete, clear a person's keys,
  and Drop previous versions; the controls need Admin Write.
* **`/admin/delegation`**: every delegation act, refusals included, and the
  published policy.
* **Live descriptions**: `GET /krb5/principals` (the database, the sockets and
  what is not implemented), `GET /krb5/service` (the acceptor), `GET /spnego`.
* **Management API**: `GET /admin-api/kerberos`,
  `GET /admin-api/kerberos/principals` and
  `POST /admin-api/kerberos/principals/{create-service, rotate-service,
  delete-service, clear-person-keys, drop-previous-service-keys,
  drop-previous-person-keys, reset-person-keytab}` — see
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
