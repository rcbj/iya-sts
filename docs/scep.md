---
title: SCEP
nav_order: 7
---

# SCEP — Simple Certificate Enrolment Protocol

mock-sts is a **SCEP server** ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)).
A device holding a **challenge password** sends a PKCS#10 request, signed by
the device and encrypted to the SCEP RA, and receives a certificate from the
trust realm's **SCEP Issuing CA** — one of the Issuing CAs of the realm's
[certificate authority](pki.md), under the realm Intermediate and the service
Root.

Every certificate names a directory entry — a person or an application — in a
`urn:sts:person:` or `urn:sts:application:` subjectAltName, and is kept on that
entry.

## Endpoints

Every trust realm has its own server, under its own prefix:

| URL | What |
|---|---|
| `GET /enroll/scep?operation=GetCACaps` | What the server does, one capability per line |
| `GET /enroll/scep?operation=GetCACert` | The RA certificate and the CA chain (`application/x-x509-ca-ra-cert`) |
| `POST /enroll/scep?operation=PKIOperation` | A pkiMessage (`application/x-pki-message`), answered with a CertRep |
| `GET /enroll/scep?operation=PKIOperation&message=…` | The same, base64 in the query string |
| `/enroll/scep/pkiclient.exe` | The same server, for clients that append the CGI name |
| `/enroll/scep/{profile}` | The same server, naming a certificate profile |

In a realm: `https://host:8081/realm/acme/enroll/scep`.

GetCACaps answers `POSTPKIOperation`, `SHA-256`, `SHA-512`, `AES`,
`SCEPStandard` and `Renewal`.

**SCEP is not refused over plain HTTP**, in either mode: RFC 8894 section 2.1
runs it over HTTP on purpose, and every message is signed and encrypted CMS.

## Getting a challenge password

A challenge authorizes **one** enrollment, for **one** entry and **one**
profile. It is shown once and cannot be shown again.

* **A person** makes one for themselves on the user portal, at
  `/portal/certificates`.
* **An administrator** makes one for any person or application in the realm on
  Protocols → SCEP (`/admin/scep`), or through the management API:

```bash
curl -s -X POST https://host:8081/admin-api/scep/create-challenge \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind":"person","identifier":"alice","profile":"tls-client"}'
```

The reply carries `challenge`, the SCEP URL for its profile, and a ready-to-paste
`sscep` sequence. Whoever redeems the challenge is issued a certificate **as the
entry it names**: a request naming anybody else in its subjectAltName is refused.

## With sscep

```bash
URL=https://host:8081/enroll/scep/tls-client
sscep getca -u $URL -c ca.crt              # ca.crt-0 is the RA, ca.crt-1 the SCEP Issuing CA
openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out req.csr \
  -subj "/CN=alice" -config <(printf '[req]\ndistinguished_name=dn\nattributes=a\n[dn]\n[a]\nchallengePassword=%s\n' "$CHALLENGE")
sscep enroll -u $URL -c ca.crt-1 -e ca.crt-0 -k key.pem -r req.csr -l cert.pem \
  -S sha256 -E aes
```

`-S sha256 -E aes` matters: SHA-1, MD5, DES and 3DES are refused.

**Renewal** (`RenewalReq`) is signed by the certificate being renewed and needs
no challenge; the renewed certificate is revoked as `superseded`:

```bash
sscep enroll -u $URL -c ca.crt-1 -e ca.crt-0 -k newkey.pem -r new.csr \
  -K key.pem -O cert.pem -l newcert.pem -S sha256 -E aes
```

`GetCert`, `GetCRL` (the SCEP Issuing CA's CRL) and `CertPoll` are answered
too. A retried request with the same transactionID and the same CSR gets the
certificate it already produced, without using up another challenge.

## Profiles

| Profile | Needs |
|---|---|
| `tls-server` | a dNSName or iPAddress **registered on the entry**, requested in the CSR |
| `tls-client` | nothing beyond the entry |
| `tls-server-client` | as `tls-server` |
| `digital-signature` | nothing beyond the entry |
| `key-encipherment` | nothing beyond the entry |
| `code-signing` | nothing beyond the entry |
| `email` | a person with `mail` (the rfc822Name) |
| `timestamping` | nothing beyond the entry |
| `smartcard-logon` | a person with `userPrincipalName` or `mail` (the UPN otherName) |

`scep.allowedProfiles` narrows the nine per realm. **Never issued over any
enrollment protocol**: `root-ca`, `intermediate-ca`, `issuing-ca`,
`ocsp-responder` and `kdc` — their holder could issue certificates, answer OCSP
for this authority, or impersonate the KDC.

Host names are registered by an administrator on Protocols → SCEP or with
`POST /admin-api/scep/add-host-name`. This service never proves control of a
name by dialling it.

## What SCEP here does not do

| It does not | Why |
|---|---|
| Enroll an ECDSA, EdDSA or post-quantum key | The CertRep is encrypted to the requester with RSA key transport. Every profile is issued over SCEP for an **RSA** key; use [EST](est.md) or ACME for others. |
| Answer PENDING | Nothing is approved by hand: a request is issued or refused when it is made. |
| GetNextCACert | There is no pre-announced CA rollover; it answers 501 and is not advertised. |
| Accept SHA-1, MD5, DES or 3DES | Refused `badAlg`. |
| Take keyUsage, extendedKeyUsage or basicConstraints from the CSR | They come from the profile the challenge names. |

## When something is refused

A request too malformed to name answers an HTTP error (400, 405, 413, 415, 429,
501, 503). Anything else is a **CertRep FAILURE** — HTTP 200, signed by the RA —
with a `failInfo`: `badAlg`, `badMessageCheck`, `badRequest`, `badTime` or
`badCertId`. The reason is **not** in the reply; it is on the audit log and on
Monitoring → SCEP enrollments (`/admin/scep/monitor`) as an
[error code](error-codes.md) (`STS-SCEP-…` or `STS-ENROLL-…`).

## Settings

`scep.enabled`, `scep.allowedProfiles`, `scep.defaultProfile`,
`scep.certificateLifetimeDays`, `scep.maxRequestBytes`,
`scep.attemptsPerIdentity`, `scep.attemptsPerAddress`,
`scep.challengeLifetimeS` and `scep.raKeyAlgorithm`, all per realm, on
Protocols → SCEP. See [configuration](configuration.md).
