---
title: Security in product mode
---

# Security in product mode

Product mode (`global.mode=product`) turns on the controls described here. They
line up with [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/)
Level 1. Development mode leaves most of them off so that clients can be
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
   set `admin.bootstrapUsername`, the name is generated. Both are printed once
   in the log. See [The admin console](admin-console.md).
3. **Check that your clients can use the defaults.** The settings below turn
   older behaviour back on where a client cannot manage without it.

## Settings that weaken a default

Each of these is off by default, and each one moves the deployment away from
Level 1. Turn one on only for the clients that need it.

| Setting | What turning it on allows | Who needs it |
|---|---|---|
| `krb5.allowSha1Enctypes` | Kerberos enctypes 17 and 18 (AES with HMAC-SHA1-96) | Kerberos clients that speak nothing newer |
| `scep.allowInProduct` | SCEP, which requires RSAES-PKCS1-v1.5 and AES-CBC | Devices that can only enroll over SCEP |
| `oauth2.allowUndeclaredGrants` | Any grant for a client that lists none | Test stacks |
| `admin.allowDefaultUsername` | A bootstrap administrator named `admin`, `root`, `sa` or `administrator` | Test stacks |
| `security.fileRoots` | Where a file an administrator names may be read from. Set only in the environment or appconfig file | Add the directory your certificates and tokens are mounted in |
| `security.allowUnscopedPeople` | Any authenticated person at SCIM and Shared Signals, by a scheme with no scope | Test stacks; use OAuth scopes for real provisioning clients |
| `authn.allowOptionalSecondFactor` | Signing in without a second factor where the authentication policy allows it | A deployment that accepts ASVS 6.3.3 not being met |
| `oauth2.allowConfidentialWithoutPkce` | A confidential client omitting PKCE | A client that cannot send it |
| `admin.logBootstrapPassword` | The generated first administrator password in the service log | Never outside a test stack |
| `crypto.allowCbcJwe` | JWE's CBC-HMAC content encryption | A partner that cannot read AES-GCM |
| `crypto.allowLegacyHashes` | OAEP over SHA-1 in XML encryption and JWE, the SHA-1 PKINIT key derivation, and S4U2Self's HMAC-MD5 checksum | Partners and Kerberos clients that support nothing newer |

Two switches exist to recover from a bad policy, and `/admin/mode` shows either
one when it is off:

| Setting | Off means |
|---|---|
| `xacml.enforceAccess` | The admin console, management API, portal, SCIM and SPIRE Server API stop asking the policy decision point |
| `roles.enforceIssuance` | Issuance stops checking roles |

Use them only to get back in after a policy has locked you out, and turn them
back on afterwards.

## Connections and browsers

* **HTTPS.** The main port is HTTPS, and a process with `global.https` off does
  not start. The plain-HTTP revocation and SCEP listener stays, because
  RFC 5280, RFC 5019 and RFC 8894 expect those services over HTTP.
* **HSTS.** Every response over TLS carries
  `Strict-Transport-Security: max-age=31536000`.
* **Cookie names.** Over TLS, every cookie this service sets is prefixed: `__Host-`,
  or `__Secure-` when it carries a `Domain` (see `authn.cookieDomain`).
  `sts_session` arrives in a browser as `__Host-sts_session`, for example. An
  unprefixed cookie of the same name is ignored, so a client that reads or
  sends a cookie by name must use the prefixed one.
* **Character sets.** Text and XML responses name `charset=utf-8`.

## Passwords

* **Any composition is accepted.** A policy can set a minimum length and a
  history, but it cannot require symbols, upper-case letters or numbers.
* **A generated password is temporary.** One made by `reset-password`, by
  `set-password` with `generate: true`, or when a person is created, must be
  changed at the next sign-in, and Kerberos gives no ticket for it until it is. One
  an administrator types does not.
* **A password is changed where the current one is proved.** A person cannot
  replace their own `userPassword` over LDAP unless an operator adds it to
  `ldap.selfWritableAttributes`, which would weaken this.
* **Repeated guesses are slowed, and no account is locked.** See
  [Authentication](authentication.md#how-repeated-password-guesses-are-slowed).

## Sessions

Ending a session revokes the access tokens and refresh tokens issued on it, and
tells the browser to clear this site's storage when no other account remains in
it. [Sessions](sessions.md#what-ending-a-session-stops) says what cannot be
recalled.

## Browser pages

Every page in the console, the portal, the report application and the sign-in
screens is drawn through one renderer. It removes scripts, event handlers and
unsafe addresses from the markup before it reaches the page, on top of each
page's Content Security Policy.

## Secrets in addresses

* The admin console, portal and report application receive their authorization
  code in the URL fragment, which a browser does not send to any server. Other
  registered clients may still use `response_mode=query`, the OAuth 2.0 default.
* Emailed links carry their token in the fragment too. A portal page sends it in
  the `X-Link-Token` header, and the APIs refuse one in a query string.
* A sign-in, password-change or consent step's id travels in the URL fragment
  and an `X-Step-Id` header, not in anything a server logs. Only the browser that
  first asked about a step can use it.
* Two hops still carry a step id in the query, because no script runs on them:
  the SPNEGO exchange (RFC 4559) and the start of a federated sign-in.

## Access decisions

A decision the policy engine cannot make is a refusal: an error in the engine,
an empty answer, or a check that names no resource or action. In development
mode the same faults allow the request and are logged.

An administrator's `admin:read` is permission to read every object in that
realm: a realm is the boundary between tenants. A token of one realm is refused
at any other realm's `/admin-api`.

At SCIM and Shared Signals, a scheme that carries no scope (HTTP Basic, the
session cookie) needs Admin Read to read and Admin Write to write.

## Clients and grants

A client that declares no grant types may use `authorization_code` and
`refresh_token` alone. List every other grant it needs in `oauthGrantType`. See
[Configuring OpenID Connect flows](configure-oidc-flows.md).

## Tokens

A GNAP user assertion that has expired is refused unless an operator sets
`gnap.assertionMaxAgeS`.

## Algorithms

* **Kerberos** uses enctypes 19 and 20 (RFC 8009).
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
* **Malware scanning** of uploaded images and risk datasets is optional and off
  by default. See [Malware scanning](malware-scanning.md).
* **Administrators changing credentials** must have signed in within
  `account.recentAuthMinutes`. The console asks them to sign in again and carries
  on; a program using the API with its own credentials is not asked.
* **Audit log.** Configure an [audit export](audit-export.md) destination, so that
  a copy of the log leaves this service as it is written and a compromise here
  cannot alter it.
* **Software bill of materials.** The image holds a CycloneDX inventory of its npm
  dependencies at `/usr/src/sts/sbom.cdx.json`.
* **Second factor.** Required of everybody who signs in with a browser,
  administrators included, including with a certificate. A federation partner is
  the authentication, so federated sign-ins are not asked for one, and nor are
  programs that present a client certificate. The
  password-only doors (LDAP, WS-Trust, SCIM, Shared Signals and EST Basic) cannot
  ask for one, so a person uses an app password there, with no second factor. This
  is intentional: see [Authentication](authentication.md).
* **XML encryption** selects and accepts AES-GCM only. AES-CBC is refused when
  decrypting, and cannot be chosen in `saml2.encryptionAlgorithm`.
* **SCEP** answers 503 until `scep.allowInProduct` is on. See [SCEP](scep.md).

## Dependencies

[`SECURITY.md`](https://github.com/rcbj/iya-sts/blob/main/SECURITY.md) sets how
quickly a vulnerable dependency is fixed and how to report a vulnerability. Images
install exactly what the lockfiles name.

## Related

* [What is not checked](what-is-not-checked.md), in development mode
* [Input validation](validation.md)
* [Departures from the specifications](spec-departures.md)
* [Security profiles](oauth-security.md)
