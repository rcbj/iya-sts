---
title: ACME
nav_order: 7
---

# ACME — Automatic Certificate Management Environment

iya-sts is an **ACME server** ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555))
with [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773) renewal information,
the `ip` ([RFC 8738](https://www.rfc-editor.org/rfc/rfc8738)) and `email`
([RFC 8823](https://www.rfc-editor.org/rfc/rfc8823)) identifier types,
[certificate profiles](https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/)
and the `permanent-identifier` type of
[device attestation](https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/).
Every trust realm has its own, issuing from the realm's **ACME Issuing CA** —
one of the Issuing CAs of the realm's [certificate authority](pki.md), under the
realm's Intermediate and the service Root.

Two things make it different from a public CA, and both are deliberate:

* **An account is bound to one directory entry, for life.** A new account
  REQUIRES an **External Account Binding** (RFC 8555 section 7.3.4), and an EAB
  key is issued for exactly one person or application. Every certificate the
  account is issued names that entry and is written onto it.
* **No challenge ever reaches out to you.** An identifier is authorized from the
  directory entry: a host name an administrator **registered** on it, a person's
  own `mail`, or the entry's own identifier. Those authorizations are created
  `valid`, so a client has nothing to do; an identifier the entry does not own is
  refused when the order is placed.

## The endpoints

All under the realm's base URL (`https://host:8081` in the default realm,
`https://host:8081/realm/<id>` in another). A client needs only the first.

| Method | Path | What it is |
|---|---|---|
| `GET` | `/enroll/acme/directory` | the directory (section 7.1.1) |
| `HEAD`, `GET` | `/enroll/acme/new-nonce` | a fresh `Replay-Nonce` (7.2) |
| `POST` | `/enroll/acme/new-account` | create or find an account (7.3) |
| `POST` | `/enroll/acme/account/{id}` | read, update or deactivate it (7.3.2, 7.3.6) |
| `POST` | `/enroll/acme/account/{id}/orders` | its orders (7.1.2.1) |
| `POST` | `/enroll/acme/new-order` | place an order (7.4) |
| `POST` | `/enroll/acme/order/{id}` | read an order |
| `POST` | `/enroll/acme/order/{id}/finalize` | finalize it with a CSR (7.4) |
| `POST` | `/enroll/acme/authz/{id}` | an authorization (7.5) |
| `POST` | `/enroll/acme/challenge/{id}` | its challenge (7.5.1) |
| `POST` | `/enroll/acme/cert/{id}` | download the certificate (7.4.2) |
| `POST` | `/enroll/acme/revoke-cert` | revoke a certificate (7.6) |
| `POST` | `/enroll/acme/key-change` | roll the account key over (7.3.5) |
| `GET` | `/enroll/acme/renewal-info/{certID}` | renewal information (RFC 9773) |

The path is `/enroll/acme` and not `/acme`, because the first segment of a path
is also where a trust realm's id goes.

## Getting an External Account Binding key

An EAB key is issued for ONE entry:

* **by the person themselves**, on the user portal;
* **by an administrator, for any person or application in the realm** — on
  **Protocols → ACME** (`/admin/acme`), or through the management API:

```bash
curl -s -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"kind":"person","identifier":"alice"}' \
     https://host:8081/realm/acme-demo/admin-api/acme/create-eab
```

```json
{
  "ok": true,
  "kid": "eab-p-YWxpY2U-a770cbcdf277212f",
  "hmacKey": "fTOM027GWjv59Gz4qXrudgK7hbtsdWRmOoIW5VZEZ1w",
  "alg": "HS256",
  "expiresAt": "2026-09-20T17:36:05.195Z",
  "directory": "https://host:8081/realm/acme-demo/enroll/acme/directory",
  "certbot": "certbot register --server … --eab-kid … --eab-hmac-key …"
}
```

**The HMAC key is shown once.** It is stored sealed on the entry and nothing
reads it back. A key binds one account and no other, and must bind within
`acme.eabLifetimeS` (a week by default). **This is also how an administrator
issues for somebody else**: create the key for their entry and hand it to
whoever runs the client — the account, and every certificate it gets, belongs
to that entry.

## Host names

A `dns` or `ip` identifier is authorized only when it is registered on the entry
the account is bound to. An administrator registers one on `/admin/acme`, or:

```bash
curl -s -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"kind":"application","identifier":"web1","hostName":"web1.example.com"}' \
     https://host:8081/realm/acme-demo/admin-api/acme/add-host-name
```

A registered `*.example.com` authorizes that wildcard, and only when written so.
The same registration serves EST and SCEP.

## Using a real client

The service's TLS certificate is issued by its own Root CA; point the client at
it (`/pki/ca/service/root.cer`, converted to PEM), for example with
`REQUESTS_CA_BUNDLE` for certbot.

### certbot

```bash
certbot register --server https://host:8081/realm/acme-demo/enroll/acme/directory \
  --eab-kid eab-a-d2ViMQ-0123456789abcdef --eab-hmac-key <hmacKey> \
  --agree-tos --register-unsafely-without-email

certbot certonly --server https://host:8081/realm/acme-demo/enroll/acme/directory \
  --standalone -d web1.example.com
```

The authorization for `web1.example.com` is already valid, so certbot performs
no challenge. certbot names no profile, so the order gets `acme.defaultProfile`
(`tls-client` unless changed): **set it to `tls-server`** for a realm whose
clients are web servers, or use a client that names a profile.

### acme.sh

```bash
acme.sh --register-account --server https://host:8081/realm/acme-demo/enroll/acme/directory \
  --eab-kid eab-a-d2ViMQ-0123456789abcdef --eab-hmac-key <hmacKey>
acme.sh --issue --server https://host:8081/realm/acme-demo/enroll/acme/directory \
  --standalone -d web1.example.com
```

## Orders

| Identifier `type` | `value` | Authorized when |
|---|---|---|
| `dns` | a host name, or `*.name` | it is registered on the entry |
| `ip` | an IPv4 or IPv6 address | it is registered on the entry |
| `email` | an address | it is the person's own `mail` |
| `permanent-identifier` | the entry's username or application identifier (or its `urn:sts:` URN) | it is the account's own entry |

An identifier the entry does not own refuses the whole order with
`rejectedIdentifier`, one subproblem per identifier. An order may name a
`profile`; with none it gets `acme.defaultProfile`. `notBefore` and `notAfter`
are refused: a certificate is valid for `acme.certificateLifetimeDays` (90 by
default), shortened to the Issuing CA's own expiry. An order may name the
certificate it `replaces` (RFC 9773); the replaced certificate is not revoked.

**The CSR must name exactly the order's identifiers** (section 7.4): every
subjectAltName and the common name must each be one of them, and all of them
must be named. The certificate is built from the order and the entry, not
copied from the CSR: its subject is `CN=<entry>, O=<organisation>`, it always
carries the entry's `urn:sts:person:<name>` or `urn:sts:application:<id>` URI,
and its key usages are the profile's.

## Profiles

The nine leaf profiles of [`/admin/pki`](pki.md), each allowed unless
`acme.allowedProfiles` leaves it out (the directory's `meta.profiles` lists the
allowed ones):

| Profile | Needs |
|---|---|
| `tls-server` | a `dns` or `ip` identifier registered on the entry |
| `tls-client` | — |
| `tls-server-client` | a `dns` or `ip` identifier registered on the entry |
| `digital-signature` | — |
| `key-encipherment` | — (an RSA key is what the key usage means) |
| `code-signing` | — |
| `email` | an `email` identifier: the person's own `mail` |
| `timestamping` | — |
| `smartcard-logon` | a person with `userPrincipalName` or `mail` — the certificate carries it as the UPN |

**Never issued over ACME**, whatever the setting says, answered
`invalidProfile` with the reason: `root-ca`, `intermediate-ca`, `issuing-ca`
(the holder could issue certificates for anybody), `ocsp-responder` (it could
sign `good` about a revoked certificate) and `kdc` (it could impersonate the
realm's KDC).

## Revocation and renewal

`revokeCert` may be signed by an account bound to the certificate's entry, or by
the certificate's own key (a `jwk` request). The reasons accepted are 0, 1, 3, 4,
5 and 9 of RFC 5280; the serial goes on the ACME Issuing CA's CRL at
`/pki/crl/<realm>/acme.crl` and its OCSP responder at `/pki/ocsp/<realm>/acme`
answers `revoked`. An administrator can revoke any of them on `/admin/acme`.

`GET /enroll/acme/renewal-info/<certID>` answers a window in the last third of
the certificate's validity, or — for a revoked certificate — a window in the
past, which tells a client to renew now.

## Configuration

Every `acme.*` setting is runtime and per trust realm, on **Protocols → ACME**
(`/admin/acme`). **Monitoring → ACME enrollments** shows what the server has
done.

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `acme.enabled` | `STS_ACME_ENABLED` | `true` | yes | Off makes every `/enroll/acme` endpoint answer 503 with a `serverInternal` problem naming the setting; accounts, orders and certificates are kept. |
| `acme.allowedProfiles` | `STS_ACME_ALLOWED_PROFILES` | all nine leaf profiles | yes | The `/admin/pki` profiles an order may name and the directory advertises; the five CA, OCSP and KDC profiles are never issued whatever this says. |
| `acme.defaultProfile` | `STS_ACME_DEFAULT_PROFILE` | `tls-client` | yes | The profile of an order that names none; it must also be in `acme.allowedProfiles`. |
| `acme.certificateLifetimeDays` | `STS_ACME_CERTIFICATE_LIFETIME_DAYS` | `90` | yes | The validity of a certificate issued at finalize, shortened to the ACME Issuing CA's own expiry. |
| `acme.maxRequestBytes` | `STS_ACME_MAX_REQUEST_BYTES` | `65536` | yes | A flattened JWS larger than this is refused (413) before it is parsed; a post-quantum CSR is the largest legitimate request. |
| `acme.attemptsPerIdentity` | `STS_ACME_ATTEMPTS_PER_IDENTITY` | `30` | yes | Refused requests one account or EAB key id may make in a web-security window before `rateLimited`. |
| `acme.attemptsPerAddress` | `STS_ACME_ATTEMPTS_PER_ADDRESS` | `120` | yes | Refused requests one client address may make in a web-security window before `rateLimited`. |
| `acme.nonceLifetimeS` | `STS_ACME_NONCE_LIFETIME_S` | `300` | yes | How long a `Replay-Nonce` may wait before it is presented; each is accepted once. |
| `acme.orderLifetimeS` | `STS_ACME_ORDER_LIFETIME_S` | `86400` | yes | How long an order stays pending or ready before it expires with its authorizations. |
| `acme.eabLifetimeS` | `STS_ACME_EAB_LIFETIME_S` | `604800` | yes | How long an EAB key may wait before it binds an account; each binds one account and no other. |

The nine leaf profiles are `tls-server`, `tls-client`, `tls-server-client`,
`digital-signature`, `key-encipherment`, `code-signing`, `email`,
`timestamping` and `smartcard-logon`. How many certificates one entry may hold
across ACME, EST and SCEP is `pki.enrollmentMaxCertificatesPerEntry`
([PKI](pki.md#configuration)). See [Configuration](configuration.md) for how a
value resolves and where it is changed — the console page, or
`POST /admin-api/config/set`.

## Development and product mode

In **product** mode a request that does not arrive over TLS is refused. In
**development** mode ACME also answers over plain HTTP and logs that it did.
Everything else is the same in both: the EAB MAC is verified, an account may be
issued only for its own entry, and a host name must be registered.

## Design decisions

* **An account is bound to one directory entry, for life, through a required
  External Account Binding.** Every certificate therefore names an entry and is
  kept on it, and an administrator issues for somebody else only by creating an
  EAB key for their entry — ACME has no other administrator's door. See
  [above](#getting-an-external-account-binding-key).
* **No challenge dials out.** This service never fetches from an address a
  caller supplied, so `http-01`, `dns-01`, `tls-alpn-01` and `email-reply-00`
  are not offered; an identifier is authorized from the entry and its
  authorization is created `valid`. The challenge type, `sts-entry-binding-01`,
  says what happened.
* **An identifier the entry does not own fails the order at once.** It is
  refused at `newOrder` with `rejectedIdentifier`, rather than leaving a
  `pending` authorization no client could ever complete.
* **A host name is issued only when an administrator registered it.** The same
  registration serves ACME, EST and SCEP, and a wildcard only when written as a
  wildcard — see [above](#host-names).
* **The certificate is built from the order and the entry, never the CSR.** The
  CSR must name exactly the order's identifiers, and the subject, the `urn:sts:`
  name and the key usages come from the entry and the profile.
* **ACME is CSR-only, and a private key is never kept.** The CA never sees the
  key; a server-generated key pair is EST's `/serverkeygen`.
* **The CA, OCSP-responder and KDC profiles are never issued.** Their holder
  could issue certificates for anybody, sign `good` about a revoked certificate
  or impersonate the realm's KDC — see [above](#profiles).
* **`replaces` does not revoke.** RFC 9773's `replaces` is a statement about
  renewal, and a client rolling over needs the old certificate to keep working
  until it deploys the new one.
* **A subscriber may give only the revocation reasons that are a subscriber's.**
  Reasons 2 and 10 are an authority's, 6 (`certificateHold`) is the one
  reversible reason, and 7 and 8 are unassigned or for delta CRLs; an
  administrator on the console may use any reason.
* **A nonce is spent only after the signature verifies.** Cheap checks run
  first, so a forged request cannot burn a nonce a client is holding, and two
  copies of one signed request cannot both pass.
* **A nonce carries its own proof.** It is MAC'd with a secret every process —
  and, on a shared store, every node — holds, so any process can check it with
  no lookup; one from before a restart fails and is answered `badNonce` with a
  fresh one, which a client retries.
* **A post-quantum account key is refused.** An account is found by its key's
  RFC 7638 thumbprint, and those key types have none; a post-quantum
  *certificate* key is fine.

## What is not implemented

* The `http-01`, `dns-01`, `tls-alpn-01`, `email-reply-00` and
  `device-attest-01` challenges — ownership comes from the directory.
* `notBefore`/`notAfter`, `newAuthz`, terms of service, alternate chains, and a
  `processing` wait at finalize (issuance is immediate).
* Post-quantum **account** keys (their key type has no RFC 7638 thumbprint).
  A certificate for a post-quantum **signing** key is fine; a KEM key cannot sign
  a CSR and is refused `badPublicKey` — use EST `/serverkeygen`.
* A server-generated key pair: ACME is CSR-only.

Errors are RFC 7807 problem documents with `urn:ietf:params:acme:error:*`
types; the operator-facing `STS-ACME-*` codes are on the
[error code page](error-codes.md) and in the audit log, never in a response.

## Related

* [PKI](pki.md) — the realm's certificate authority, its profiles, CRLs and
  OCSP responders
* [EST](est.md) and [SCEP](scep.md) — the other two enrollment protocols, over
  the same rules
* [TLS and mutual TLS](tls.md) — where an issued `tls-client` certificate signs
  a person in
* [Trust realms](trust-realms.md)
* [What is not checked](what-is-not-checked.md)
* [Configuration](configuration.md) and [error codes](error-codes.md)
