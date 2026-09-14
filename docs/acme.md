---
title: ACME
nav_order: 7
---

# ACME — Automatic Certificate Management Environment

mock-sts is an **ACME server** ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555))
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

## Settings

On **Protocols → ACME**, per realm: `acme.enabled`, `acme.allowedProfiles`,
`acme.defaultProfile`, `acme.certificateLifetimeDays`, `acme.maxRequestBytes`,
`acme.attemptsPerIdentity`, `acme.attemptsPerAddress`, `acme.nonceLifetimeS`,
`acme.orderLifetimeS` and `acme.eabLifetimeS`. **Monitoring → ACME
enrollments** shows what the server has done.

## Development and product mode

In **product** mode a request that does not arrive over TLS is refused. In
**development** mode ACME also answers over plain HTTP and logs that it did.
Everything else is the same in both: the EAB MAC is verified, an account may be
issued only for its own entry, and a host name must be registered.

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
