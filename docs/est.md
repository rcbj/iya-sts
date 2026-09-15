---
title: EST
nav_order: 7
---

# EST — Enrollment over Secure Transport

iya-sts is an **EST server** ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030),
with the clarifications of [RFC 8951](https://www.rfc-editor.org/rfc/rfc8951)).
A device, a person or an application authenticates, sends a PKCS#10 request,
and receives a certificate from the trust realm's **EST Issuing CA** — one of
the Issuing CAs of the realm's [certificate authority](pki.md), under the
realm's Intermediate and the service Root.

Every certificate issued over EST names a **directory entry**, a person or an
application, and is written onto that entry. A person may enroll only for
themselves, an application only for itself, and a holder of **Admin Write** for
any person or application in the realm.

## The endpoints

All under the realm's base URL (`https://host:8081` in the default realm,
`https://host:8081/realm/<id>` in another):

| Method | Path | RFC 7030 | Authenticated |
|---|---|---|---|
| `GET` | `/.well-known/est/cacerts` | 4.1 | no |
| `POST` | `/.well-known/est/simpleenroll` | 4.2.1 | yes |
| `POST` | `/.well-known/est/simplereenroll` | 4.2.2 | yes |
| `POST` | `/.well-known/est/serverkeygen` | 4.4 | yes |
| `GET` | `/.well-known/est/csrattrs` | 4.5 | no |
| `POST` | `/.well-known/est/fullcmc` | 4.3 | answers **501** |

The same six answer under a **label**, `/.well-known/est/<profile>/…`, where
the label is a certificate profile. The unlabelled path issues the realm's
`est.defaultProfile` (`tls-client` unless changed).

| Profile (label) | Needs |
|---|---|
| `tls-server` | a dNSName or iPAddress registered on the entry |
| `tls-client` | — |
| `tls-server-client` | a dNSName or iPAddress registered on the entry |
| `digital-signature` | — |
| `key-encipherment` | — |
| `code-signing` | — |
| `email` | a person with a `mail` attribute |
| `timestamping` | — |
| `smartcard-logon` | a person with `userPrincipalName` or `mail` |

**Never issued over EST** (403): `root-ca`, `intermediate-ca`, `issuing-ca`,
`ocsp-responder` and `kdc`. Each makes its holder an authority over everybody
else in the realm; `/admin/est` gives the reason for each. An unknown label is
404. `est.allowedProfiles` narrows the nine further per realm.

## Authenticating

* **HTTP Basic with a person's directory password** — checked in product mode;
  development mode accepts any password for a person who exists.
* **HTTP Basic with an application's `client_id` and `client_secret`** — the
  secret is required in product mode.
* **A TLS client certificate this realm issued** (for example one enrolled over
  EST with the `tls-client` profile), mapped to its entry by the
  `urn:sts:person:` or `urn:sts:application:` name in it. It must still be on
  the entry and unrevoked; a certificate from another realm is refused.

A Basic username is looked up as a **person first**, then as an application's
`client_id`. A request with no credential gets `401` with
`WWW-Authenticate: Basic realm="EST"`.

In **product** mode a request that did not arrive over TLS is refused.

## Requesting a certificate with curl and openssl

Get the CA certificates first (unauthenticated):

```sh
BASE=https://localhost:8081
curl -s --cacert sts-root.pem $BASE/.well-known/est/cacerts \
  | base64 -d | openssl pkcs7 -inform DER -print_certs > est-ca.pem
```

Make a key and a request, and enroll for the `tls-client` profile:

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout alice.key -subj "/CN=alice" -outform DER -out alice.csr.der

base64 alice.csr.der | curl -s --cacert sts-root.pem \
  -u alice:password \
  -H 'Content-Type: application/pkcs10' --data-binary @- \
  $BASE/.well-known/est/tls-client/simpleenroll \
  | base64 -d | openssl pkcs7 -inform DER -print_certs > alice.pem
```

A **server certificate** needs its host name registered on the entry first
(on `/admin/est`, or `POST /admin-api/est/add-host-name`), and the request must
ask for it:

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout web.key -subj "/CN=webapp1" \
  -addext "subjectAltName=DNS:web.example.com" -outform DER -out web.csr.der
base64 web.csr.der | curl -s --cacert sts-root.pem -u webapp1:secret \
  -H 'Content-Type: application/pkcs10' --data-binary @- \
  $BASE/.well-known/est/tls-server/simpleenroll
```

**Renew** with the certificate itself. The request must repeat the subject and
subjectAltName of the certificate being renewed; the old one goes on the EST
CRL as `superseded`:

```sh
openssl req -new -key alice-new.key -subj "/CN=alice/O=sts" \
  -addext "subjectAltName=URI:urn:sts:person:alice" -outform DER \
  -out renew.csr.der
base64 renew.csr.der | curl -s --cacert sts-root.pem \
  --cert alice.pem --key alice.key \
  -H 'Content-Type: application/pkcs10' --data-binary @- \
  $BASE/.well-known/est/simplereenroll
```

With Basic instead of the certificate, the certificate to renew is found among
the entry's valid EST certificates by the subject and names the request repeats.

**An administrator** enrolls for somebody else by naming them in a
`urn:sts:person:<username>` (or `urn:sts:application:<id>`) subjectAltName, or
by their username as the common name.

## Server-generated keys

`/serverkeygen` takes the request as a **template**: the key pair is generated
here in the template key's algorithm (an ML-KEM template gets an ML-KEM key, for
`key-encipherment` only), and the response is `multipart/mixed` with the PKCS#8
private key and the certificate, each base64. A sealed copy of the key is kept
on the entry. Turn it off with `est.serverKeyGeneration`.

The console's **Issue a certificate with a server-generated key** and
`POST /admin-api/est/issue-server-key` do the same for any entry, and show the
private key once.

## What `csrattrs` says

A DER `SEQUENCE OF AttrOrOID`: the signature algorithms a request may be signed
with (ECDSA with SHA-256 and SHA-384, RSA with SHA-256, Ed25519, ML-DSA-44/65/87),
the `extensionRequest` attribute, the profile's extended key usages, and — for
the server, email and smartcard profiles — a hint naming the subjectAltName kind
it needs (`dNSName`, `iPAddress`, `rfc822Name`, or the UPN otherName).

## What the CA decides, not the request

The subject is `CN=<username or identifier>, O=<organisation>`; the
subjectAltName always carries the entry's `urn:sts:` name plus any requested
name the entry owns — a name it does not own **refuses the request**. Key usage,
extended key usage and basic constraints come from the profile, whatever the
request asked for. The lifetime is `est.certificateLifetimeDays`.

## Not implemented

* **Full CMC** (RFC 7030 section 4.3) answers `501`.
* **tls-unique channel binding** (section 3.5): TLS 1.3 has no tls-unique, so a
  request's `challengePassword` is not read as one and is ignored.
* **An encrypted server-generated key** (section 4.4.1.2): a template carrying
  `DecryptKeyIdentifier` or `AsymmetricDecryptKeyIdentifier` is refused `501`
  rather than answered with an unencrypted key.
* **Deferred issuance** — `202` with `Retry-After` (section 4.2.3) is never
  sent; every request is issued or refused at once.
* A **KEM key** (ML-KEM) cannot be enrolled with `/simpleenroll`: it cannot sign
  the proof of possession. Use `/serverkeygen`.
* An EST credential of its own: EST uses passwords, client secrets and
  certificates the service already has.

## Console and management API

* **Protocols → EST** (`/admin/est`): the endpoints and every profile's
  labelled URLs, the EST Issuing CA, the credentials EST accepts, issuing with a
  server-generated key, certificate host names, the enrolled certificates with a
  Revoke on each, and the `est.*` settings.
* **Monitoring → EST enrollments** (`/admin/est/monitor`): requests, issuances
  and refusals by operation, profile, principal, error code and status.
* `GET /admin-api/est`, `GET /admin-api/est/monitor`, and
  `POST /admin-api/est/{issue-server-key,revoke-certificate,add-host-name,remove-host-name}`.

Refusals are recorded under `STS-EST-*` and `STS-ENROLL-*` codes on the audit
log (see [error codes](error-codes.md)); a client never sees a code.
