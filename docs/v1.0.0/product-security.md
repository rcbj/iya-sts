---
title: Security in product mode
---

# Security in product mode

Product mode (`global.mode=product`) turns on the controls described here. They
line up with [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/)
Level 2, which includes Level 1. Development mode leaves most of them off so that clients can be
exercised against behaviour a production service would refuse.

`/admin/mode` shows what each mode does in the running service, and shows a row
as not met when a setting on this page weakens it. Read that page to see the
state of your own deployment.

## Before people use a product deployment

1. **Give the main port a publicly trusted certificate.** Set
   `tls.certificateFile` and `tls.keyFile`. Browsers remember HSTS for a year,
   and then refuse an untrusted certificate with no way to click through. See
   [TLS](tls.md).
2. **Find the administrator's name and password at first start.** Unless you
   set `admin.bootstrapUsername` to a name of your own, the name is generated.
   Both are written to `bootstrap-admin-password` in `persistence.dataDir`,
   readable only by the service, and the log says where. See
   [The admin console](admin-console.md#the-bootstrap-administrator).
3. **Check that your clients can use the defaults.** The settings below turn
   older behaviour back on where a client cannot manage without it.

## Settings that weaken a default

Each of these is off by default, and each one moves the deployment away from
Level 2. Turn one on only for the clients that need it.

| Setting | What turning it on allows | Who needs it |
|---|---|---|
| `krb5.allowSha1Enctypes` | Kerberos enctypes 17 and 18 (AES with HMAC-SHA1-96) | Kerberos clients that speak nothing newer |
| `scep.allowInProduct` | SCEP, which requires RSAES-PKCS1-v1.5 and AES-CBC | Devices that can only enroll over SCEP |
| `ldap.plainListener` | The plain LDAP listener on 389, where a password can cross in the clear even though the bind is refused | Directory clients that cannot use LDAPS on 636 |
| `federation.allowAssertionWithoutAudience` | A partner's SAML 1.1 or WS-Federation assertion that names no audience | A partner that cannot send one |
| `oauth2.allowUndeclaredGrants` | Any grant for a client that lists none | Test stacks |
| `admin.allowDefaultUsername` | A bootstrap administrator named `admin`, `root`, `sa` or `administrator` | Test stacks |
| `security.fileRoots` | Where a file an administrator names may be read from. Set only in the environment or appconfig file | Add the directory your certificates and tokens are mounted in |
| `security.allowUnscopedPeople` | Any authenticated person at SCIM and Shared Signals, by a scheme with no scope | Test stacks; use OAuth scopes for real provisioning clients |
| `authn.allowOptionalSecondFactor` | Signing in without a second factor where the authentication policy allows it | A deployment that accepts ASVS 6.3.3 not being met |
| `oauth2.allowConfidentialWithoutPkce` | A confidential client omitting PKCE | A client that cannot send it |
| `federation.allowUntypedLogoutToken` | A partner's Logout Token typed `jwt` or carrying no type | A partner that does not send `logout+jwt` |
| `admin.logBootstrapPassword` | The generated first administrator password in the service log | Never outside a test stack |
| `crypto.allowCbcJwe` | JWE's CBC-HMAC content encryption | A partner that cannot read AES-GCM |
| `crypto.allowLegacyHashes` | OAEP over SHA-1 in XML encryption and JWE, the SHA-1 PKINIT key derivation, and S4U2Self's HMAC-MD5 checksum | Partners and Kerberos clients that support nothing newer |
| `persistence.allowDefaultDatabasePassword` | Starting with a well-known database password, such as `sts`, `sts_app` or `postgres`, or one equal to the user name | Test stacks |
| `audit.allowPlainSyslog` | A syslog audit destination over `tcp` or `udp` | A collector on a network you trust that cannot accept TLS |
| `secrets.allowLocalSecrets` | A key-encryption key in a file, or a database password in a file or the connection string | A host whose only secret store is its own file system |
| `security.pbes2MinIterations` | Set below 600000, a password-encrypted JWE (PBES2) with fewer PBKDF2 iterations | A sender whose library uses a smaller count |
| `malwareScan.allowCleartext` | A plain `icap://` malware scanner | A scanner on a network you trust |

Two settings are on by default in product mode, and turning one off weakens it
in the same way:

| Setting | Off means |
|---|---|
| `security.hstsIncludeSubDomains` | HSTS stops covering subdomains of the service's host name |
| `security.requestsPerAddressPerMinute` | Set to `0`, no ceiling on requests from one address (6000 a minute by default) |

Two switches exist to recover from a bad policy, and `/admin/mode` shows either
one when it is off:

| Setting | Off means |
|---|---|
| `xacml.enforceAccess` | The admin console, management API, portal, SCIM and SPIRE Server API stop asking the policy decision point |
| `roles.enforceIssuance` | Issuance stops checking roles |

Use them only to get back in after a policy has locked you out, and turn them
back on afterwards.

Two more have a stricter default in product mode, and setting them back to the
development value weakens it: `oauth2.refreshTokenMaxChainS` (30 days; `0` is no
limit), `oauth2.consentAlwaysForPublicClients` (on), and the three
single sign-on consent switches `saml2.ssoConsent`, `saml11.ssoConsent` and
`wsfed.ssoConsent` (on).

## Connections and browsers

* **HTTPS.** The main port is HTTPS, and a process with `global.https` off does
  not start. The plain-HTTP revocation and SCEP listener stays, because
  RFC 5280, RFC 5019 and RFC 8894 expect those services over HTTP.
* **HSTS.** Every response over TLS carries
  `Strict-Transport-Security: max-age=31536000; includeSubDomains`. Turn off
  `security.hstsIncludeSubDomains` if a subdomain of the host name must still
  answer over plain HTTP. See [TLS](tls.md#strict-transport-security).
* **Forwarded addresses.** With `global.trustProxy` on, `X-Forwarded-For`,
  `X-Forwarded-Proto` and `X-Forwarded-Host` are believed only from the proxies
  listed in `global.trustedProxies`. With no list, they are believed from nobody,
  so behind a proxy set both. See
  [TLS](tls.md#reverse-proxies-and-load-balancers).
* **Outbound requests.** A request a partner, client or caller can influence
  never reaches a loopback, private, link-local or reserved address. Set
  `security.outboundAllowedHosts` to limit it to named hosts as well. See
  [Communications](communications.md#outbound-locations-a-caller-can-name).
* **Requests per address.** One address may make 6000 requests a minute to one
  process, `security.requestsPerAddressPerMinute`. More are answered `429`. See
  [Availability](availability.md).
* **Cookie names.** Over TLS, every cookie this service sets is prefixed: `__Host-`,
  or `__Secure-` when it carries a `Domain` (see `authn.cookieDomain`) or a path
  narrower than `/`.
  `sts_session` arrives in a browser as `__Host-sts_session`, for example. An
  unprefixed cookie of the same name is ignored, so a client that reads or
  sends a cookie by name must use the prefixed one.
* **Character sets.** Text and XML responses name `charset=utf-8`.

## Certificates

* **Paranoid PKI mode is on.** `pki.paranoid` is `auto`, which is on in product
  mode: every certificate this service relies on, at a TLS handshake in either
  direction, under a signature, as an encryption recipient or in an attestation,
  needs a path to an anchor it was told about, validity now, revocation where a
  source is named, and the key usages its use case asks. See
  [Paranoid PKI mode](pki.md#paranoid-pki-mode).
* **A partner's CA goes in a truststore.** A third party's certificate that is
  not registered on the application or relationship it is used for must chain
  to an anchor this service holds: the
  [client-certificate truststore](tls.md#the-client-truststore) at a TLS
  handshake, and the realm's [signer truststore](signer-truststore.md) for
  everything else. A server this service dials that presents a self-signed certificate is
  refused until it is
  [accepted by name](signer-truststore.md#accepting-one-certificate-by-name).
* **One row per use case.** If one kind of certificate cannot meet the checks,
  turn off that use case's `pki.paranoid<UseCase>` row in the realm that needs
  it, not the whole mode. A row off in product is logged (`STS-PKI-0239`) and
  drawn red on `/admin/pki/trust`, which also lists every pinned certificate
  and its status.

## Passwords

* **Any composition is accepted.** A policy can set a minimum length and a
  history, but it cannot require symbols, upper-case letters or numbers.
* **Words that identify you are refused**: the service's names, the realm's name
  and domain, and `security.passwordContextWords`. See
  [Words a password may not contain](password-words.md).
* **A generated password is temporary.** One made by `reset-password`, by
  `set-password` with `generate: true`, or when a person is created, must be
  changed at the next sign-in, and Kerberos gives no ticket for it until it is. One
  an administrator types does not.
* **A password is changed where the current one is proved.** A person cannot
  replace their own `userPassword` over LDAP unless an operator adds it to
  `ldap.selfWritableAttributes`, which would weaken this.
* **Stored passwords.** Where the password policy hashes with scrypt, the
  parallelism is at least 3, whatever the policy names: the default is N=2^15,
  r=8, p=3, one of OWASP's pairs. A stored hash with other parameters is hashed
  again at the person's next successful sign-in. See
  [How a password is stored](configure-ldap.md#how-a-password-is-stored).
* **Repeated guesses are slowed, and no account is locked.** See
  [Authentication](authentication.md#how-repeated-password-guesses-are-slowed).

## Signing in

* **Second factor.** Required of everybody who signs in with a browser,
  administrators included, including with a certificate: `GET /tls/sign-in`
  starts no session for a person who owes one, and the sign-in screen's
  certificate button asks for it. A federation partner is
  the authentication, so federated sign-ins are not asked for one, and nor are
  programs that present a client certificate. The
  password-only doors (LDAP, WS-Trust, SCIM, Shared Signals and EST Basic) cannot
  ask for one, so a person uses an app password there, with no second factor. This
  is intentional: see [Authentication](authentication.md) and
  [Authentication pathways](authentication-pathways.md).
* **A TOTP code is good for one time step.** `totp.window` defaults to 0.
* **Changing how somebody signs in needs a recent sign-in**, within
  `account.recentAuthMinutes` (15 minutes). On the portal that covers the second
  factors, recovery codes, passkeys, app passwords, certificates, signing keys,
  self-issued IDs, the email address and a wallet credential offer; the person
  is sent to sign in again and returned to the page. An administrator changing a
  person's password, second factor, passkey, recovery codes, email address or
  app passwords through the console or `/admin-api` must have signed in within
  the same time: the console asks them to sign in again and carries on, and the
  API answers RFC 9470's `insufficient_user_authentication`. A program using the
  API with its own credentials is not asked.
* **Clearing a lost factor needs a reason.** An administrator removing a
  person's authenticator app, passkeys, recovery codes or emailed factor must say
  how the person's identity was verified. It is kept on the audit row.

## Sessions

* **An unused session ends after 30 minutes** (`authn.sessionIdleTimeoutS`), and
  every session after one hour (`authn.sessionLifetimeS`).
* **Ending a session revokes the access tokens issued on it**, and its refresh
  tokens other than `offline_access` ones, and tells the browser to clear this
  site's storage when no other account remains in it.
  [Sessions](sessions.md#what-ending-a-session-stops) says what cannot be
  recalled.
* **Ending your other sessions needs a recent sign-in**; signing yourself out
  never does. See [Signing out](signing-out.md#post-logout).
* **An administrator can end every session in a realm** at once, on
  `/admin/sessions`. See [Sessions](sessions.md#how-one-ends).

## Browser pages

Every page in the console, the portal, the report application and the sign-in
screens is drawn through one renderer. It removes scripts, event handlers and
unsafe addresses from the markup before it reaches the page, on top of each
page's Content Security Policy.

An unexpected failure is answered without its internal error text: at the
management API, the OAuth and OpenID Connect endpoints (the sign-out page
included), WS-Trust and the wallet sign-in. The text is in the log, under the
failure's error code.

## Secrets in addresses

* The admin console, portal and report application receive their authorization
  code in the URL fragment, which a browser does not send to any server. Other
  registered clients may still use `response_mode=query`, the OAuth 2.0 default.
* Emailed links carry their token in the fragment too. A portal page sends it in
  the `X-Link-Token` header, and the APIs refuse one in a query string.
* A sign-in, password-change or consent step's id travels in the URL fragment
  and an `X-Step-Id` header, not in anything a server logs. Only the browser that
  first asked about a step can use it.
* Two hops have no script to read a fragment: the SPNEGO exchange (RFC 4559)
  and the start of a federated sign-in. Their step id travels in a short-lived
  `HttpOnly` cookie instead, and the wallet's return and wait addresses carry
  it in the fragment.

## Access decisions

A decision the policy engine cannot make is a refusal: an error in the engine,
an empty answer, or a check that names no resource or action. In development
mode the same faults allow the request and are logged.

Issuing is held to the same rule. When the issuance decision cannot be made (the
engine throws or answers nothing), or the application register cannot be read
to judge a sign-in, no token is issued (`STS-XACML-0183`).

An administrator's `admin:read` is permission to read every object in that
realm: a realm is the boundary between tenants. A realm's own token is refused
at any other realm's `/admin-api`; a default-realm token is the service's and
reaches every realm. See [Management API](management-api.md).

At SCIM and Shared Signals, a scheme that carries no scope (HTTP Basic, the
session cookie) needs Admin Read to read and Admin Write to write.

## Clients and grants

* **A client gets only the code flow unless it declares more.** One that declares
  no grant types may use `authorization_code` and `refresh_token` alone, and one
  that declares no response types (and not the `implicit` grant) may use
  `response_type=code` alone (`unauthorized_client`). List what else it needs in
  `oauthGrantType` and `oauthResponseType`. See
  [Configuring OpenID Connect flows](configure-oidc-flows.md).
* **PKCE is required of every client**, confidential ones included. An
  authorization request with no `code_challenge` is refused `invalid_request`.
* **A repeated parameter is refused** at the authorization and token endpoints
  (RFC 6749 section 3.2), rather than the last value being taken.
* **A public client is asked consent every time.** Nothing proves which program
  holds a public client's `client_id`, so an earlier answer does not cover it.
  This service's own applications are not asked. See
  [Consent](oauth-oidc.md#consent).
* **Single sign-on asks before it signs a person in** to a SAML 2.0 service
  provider, a SAML 1.1 relying party or a WS-Federation relying party, once
  per application, on the same consent screen (ASVS 5.0.0 7.6.2).
  `saml2.ssoConsent`, `saml11.ssoConsent` and `wsfed.ssoConsent` turn it off,
  and `saml2SsoConsent`, `saml11SsoConsent` and `wsfedSsoConsent` on an
  application's entry turn it off or on for that application.

## Tokens

* **A chain of refresh tokens ends 30 days after its first token**, however
  often it was renewed; the person then signs in again.
* **A token whose `sub` no longer names a person is refused** at `/account-api`
  and `/report-api` (`invalid_token`), and holds no role at `/admin-api`, SCIM
  or any other door that asks a token's roles. It is not matched by its
  username, which may now belong to somebody else. In every mode these doors
  find the person by `sub` first.
* **A partner's Logout Token must be typed `logout+jwt`** unless
  `federation.allowUntypedLogoutToken` is on.
* **A GNAP user assertion that has expired is refused** unless an operator sets
  `gnap.assertionMaxAgeS`.

## Algorithms

* **Kerberos** uses enctypes 19 and 20 (RFC 8009).
* **RSA keys** this service generates are 3072 bits by default: RSA signing
  keys, certificate authorities, the self-signed listener certificate and the
  realms' encryption keys. A setting that names a size still decides, and keys
  that already exist stay until they are rotated.
* **Hashes.** SHA-1 and MD5 are off for key transport, PKINIT key derivation and
  S4U2Self unless `crypto.allowLegacyHashes` is on. Two uses remain. TOTP
  defaults to HMAC-SHA-1 for compatibility with authenticator apps, many of which
  support nothing else. PKINIT checks the SHA-1 `paChecksum` because RFC 4556
  section 3.2.1 requires it and RFC 8636 section 9 leaves it fixed at SHA-1; the
  request's security rests on a signature digest that is not SHA-1, a
  Diffie-Hellman reply key, and RFC 8636's KDF over SHA-256 or better, which
  binds the request to the reply.
* **JWE** offers and accepts AES-GCM only, and answers in A256GCM when a client
  names an algorithm and no `enc`, unless `crypto.allowCbcJwe` is on. Kerberos
  (RFC 8009) and the TPM credential step use the only ciphers their
  specifications define.
* **XML encryption** selects and accepts AES-GCM only. AES-CBC is refused when
  decrypting, and cannot be chosen in `saml2.encryptionAlgorithm`.
* **secp256k1.** ES256K is not offered in discovery, its key is not in
  `/oauth2/jwks`, and signing with it is refused (`STS-KEYS-0166`), unless
  `keys.signingAlgorithms` lists it. A signature in it from anybody else, a DPoP
  proof among them, is refused (`STS-KEYS-0179`) unless
  `keys.acceptedSigningAlgorithms` or `keys.signingAlgorithms` lists it, and the
  published `*_alg_values_supported` lists leave it out. An XML signature on
  secp256k1 follows the same rule (`STS-KEYS-0077`), and a COSE one is accepted
  only where `cose.acceptedAlgorithms` lists ES256K. See
  [OAuth and OpenID Connect](oauth-oidc.md#limiting-a-realm-to-named-signing-algorithms).
* **PBES2.** A JWE whose `p2c` is under `security.pbes2MinIterations` is refused
  before anything is derived: 600,000 in product mode, RFC 7518's recommended
  1000 in development. The key is derived on libuv's thread pool, never on the
  event loop. A PKCS#12 export uses PBKDF2 with SHA-256 at 600,000
  iterations, and so does a password-protected JWK export (a PBES2 JWE with
  `p2c` 600,000), in either mode.
* **SCEP** answers 503 until `scep.allowInProduct` is on. See [SCEP](scep.md).

## Uploaded files

Malware scanning of uploaded images and risk datasets is optional and off by
default. When it is on, product mode reaches the scanner over TLS only. See
[Malware scanning](malware-scanning.md) and [File uploads](file-uploads.md).

## Errors and logs

* **An internal error's text stays in the log.** A WS-Trust fault, the JWKS
  endpoint, a `500` from `/admin-api` and the OpenID Connect logout error page
  answer with a general message.
* **Request logs leave credentials out.** At `debug` and `trace`, the logged
  request and response headers lose `Authorization`, `Cookie`, `Set-Cookie`,
  `DPoP` and `X-API-Key`, and bodies are withheld. Tokens and assertions are still
  written before and after signing, so keep to `info` on a deployment with real
  data. See [Logging inventory](logging-inventory.md#log-level).
* **Audit log.** Configure an [audit export](audit-export.md) destination, so that
  a copy of the log leaves this service as it is written and a compromise here
  cannot alter it. Syslog destinations use TLS unless `audit.allowPlainSyslog` is
  on. Each held row also carries a keyed checksum and the checksum of the row
  before it: `GET /admin-api/audit/integrity` lists any row that no longer
  matches, any place a row is missing, and whether the newest rows are there.
* **Clocks.** With a database store, a node whose clock differs from the
  database's by more than five seconds logs a warning (`STS-SCHED-0022`), and a
  line when they agree again.

## Dependencies

[`SECURITY.md`](https://github.com/rcbj/iya-sts/blob/main/SECURITY.md) sets how
quickly a vulnerable dependency is fixed and how to report a vulnerability. Images
install exactly what the lockfiles name, and a daily check covers the published
image as well as the lockfiles.

The image holds a CycloneDX inventory of its npm dependencies at
`/usr/src/sts/sbom.cdx.json`, one of the optional SDKs under `/opt/sts-sdk` at
`/usr/src/sts/sbom-sdks.cdx.json`, and a list of its operating-system packages
at `/usr/src/sts/os-packages.txt`. It holds no source control metadata.

## Database

Product mode does not start with a well-known database password (`sts`,
`sts_app`, `postgres` and the like) or one equal to the user name, unless
`persistence.allowDefaultDatabasePassword` is on. The compose stack generates its
passwords at first start. See [The compose stack](docker-compose.md).

Product mode also takes the database password from a secret store, and the
key-encryption key from a secret store or a key management service. A password
written into the connection string, the `file` provider, or a key-encryption key
in a file stops the service unless `secrets.allowLocalSecrets` is on. The compose
stack uses OpenBao for both. See [Key management](key-management.md).

## Related

* [What is not checked](what-is-not-checked.md), in development mode
* [Input validation](validation.md)
* [Departures from the specifications](spec-departures.md)
* [Security profiles](oauth-security.md)
