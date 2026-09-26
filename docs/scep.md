---
title: SCEP
nav_order: 7
---

# SCEP — Simple Certificate Enrolment Protocol

iya-sts is a **SCEP server** ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)).
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

**The same server answers on the plain-HTTP listener** (`pki.httpPort`, 8082 by
default — the one that serves the CRLs and OCSP): `http://host:8082/enroll/scep`
and `http://host:8082/realm/acme/enroll/scep` (#210). sscep and much of the
device firmware SCEP exists for have no TLS at all. Every other path this
service answers stays on the main port.

A POSTed PKIOperation may be labelled `application/x-pki-message`, which RFC
8894 section 4.3 names, **or `application/octet-stream`** (micromdm's client),
**or carry no Content-Type** (sscep); either way the bytes checked are the
bytes sent. Any other declared type is 415.

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

The reply carries `challenge`, the SCEP URL for its profile (`url`, on the main
port, and `plainUrl`, on the plain-HTTP listener), and a ready-to-paste `sscep`
sequence that runs as it is written — the suite runs it
(`tests/vendored/sts_scep_sscep.js`). Whoever redeems the challenge is issued a certificate **as the
entry it names**: a request naming anybody else in its subjectAltName is refused.

## With sscep

sscep has no TLS, so it uses the plain-HTTP URL:

```bash
URL=http://host:8082/enroll/scep/tls-client
sscep getca -u $URL -c ca.crt              # ca.crt-0 is the RA, ca.crt-1 the SCEP Issuing CA
openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out req.csr \
  -addext "subjectAltName=URI:urn:sts:person:alice" \
  -config <(printf '[req]\nprompt=no\ndistinguished_name=dn\nattributes=a\n[dn]\nCN=alice\nO=Example\nC=US\n[a]\nchallengePassword=%s\n' "$CHALLENGE")
sscep enroll -u $URL -c ca.crt-0 -e ca.crt-0 -k key.pem -r req.csr -l cert.pem \
  -S sha256 -E aes
```

Three details each stopped this working once:

* **`prompt=no`.** Without it OpenSSL reads the `[a]` section as prompt text and
  puts no challengePassword in the request, which is refused.
* **`-c ca.crt-0`**, the RA. sscep verifies the reply with `-c`, and the RA signs
  every CertRep; the Issuing CA there fails every reply as "error verifying
  signature".
* **The subject the certificate will carry** — `CN=<entry>, O=<organisation>`,
  or `CN=<host>, UID=<entry>, O=…` for a host — or sscep warns that the subject
  it got back is not the one it asked for. The certificate's content comes
  from the entry, never the CSR; the hint writes the right one.

`-S sha256 -E aes` matters: SHA-1, MD5, DES and 3DES are refused.

**Renewal** needs no challenge and is signed by the certificate being renewed;
the renewed certificate is revoked as `superseded`. sscep has no `RenewalReq`:
it renews with a `PKCSReq` signed by the old certificate — the form before
RFC 8894, which section 2.3 notes most implementations keep — and a PKCSReq
whose signer is a certificate this realm issued is handled exactly as a
RenewalReq (#210):

```bash
sscep enroll -u $URL -c ca.crt-0 -e ca.crt-0 -k newkey.pem -r new.csr \
  -K key.pem -O cert.pem -l newcert.pem -S sha256 -E aes
```

`GetCert`, `GetCRL` (the SCEP Issuing CA's CRL) and `CertPoll` (`sscep enroll
-R`) are answered too. A retried request with the same transactionID and the
same CSR gets the certificate it already produced, without using up another
challenge. A DIFFERENT request under a transactionID that already completed —
what certmonger and jscep send for every request with the same key, since they
derive the transactionID from it — is a new transaction, authorized from
scratch (until #249 it was refused `STS-SCEP-0037`, now retired).

## With certmonger

certmonger's `getcert` reads everything it needs from the server, so the plain
URL and a challenge are all it takes:

```bash
getcert add-scep-ca -c STS -u http://sts.example.com:8082/realm/acme/enroll/scep/tls-client
getcert request -c STS -k /etc/pki/tls/private/alice.key \
  -f /etc/pki/tls/certs/alice.crt -N "CN=alice,O=Example,C=US" \
  -L "$CHALLENGE" -w
getcert list        # status: MONITORING
```

It tracks the certificate and renews it before it expires, with the same key
(`getcert resubmit`) or a new one (`getcert rekey`); both are signed with the
certificate being renewed and need no challenge. Three things to know:

* **Use the plain-HTTP URL.** certmonger's `scep-submit` hands `-R` (the CA
  file for HTTPS) to its GetCACaps and GetCACert requests only; the
  PKIOperation that enrolls is then made with no CA file and fails
  "Error 60 … SSL peer certificate … was not OK" unless the service Root is
  in the host's system trust store. SCEP needs no TLS (RFC 8894 section 2.1):
  the request is encrypted to the RA and the reply to the requester.
* **A refusal shows as `CA_UNREACHABLE`**, with `ca-error: … failed to verify
  signature on server response … no content`, and certmonger retries it.
  RFC 8894 sends a FAILURE CertRep without signed content and certmonger's
  reader requires some, so it cannot tell a refusal from an outage. The reason
  is on Monitoring → SCEP with its error code; stop the retries with
  `getcert stop-tracking`.
* **Its transactionID is its public key's digest**, so every request for the
  same key carries the same one. A second request under a completed
  transactionID is a new transaction here, authorized from scratch — a
  challenge again, or the certificate being renewed.

## With jscep

jscep is a Java library: an application calls `Client.enrol()`, and jscep
negotiates the strongest cipher and digest GetCACaps offers — AES and
SHA-512 here. The application supplies the `CertificateVerifier` that decides
whether the CA certificate GetCACert answers is the right one: check the SCEP
Issuing CA against the realm's Intermediate (`/pki/ca/<realm>/intermediate.cer`)
and the service Root. For HTTPS, hand `UrlConnectionTransportFactory` an
`SSLSocketFactory` that trusts the Root. jscep renews with a `PKCSReq` signed
by the certificate being renewed, as sscep and certmonger do; its
transactionID is the SHA-1 of the request's public key, so a renewal that keeps
the key repeats it, which is handled as above.

## micromdm's scepclient cannot enroll here

micromdm/scep's `scepclient` (v2.3.0, and its `main` as of 2026-01) signs every
request over **SHA-1** and envelopes it with **single DES** — the fixed
defaults of the smallstep/pkcs7 library it is built on — and has no option to
change either; it reads GetCACaps only to choose POST. Both are refused
`badAlg` (`STS-SCEP-0020` for the signature), in both modes, and the refusal
spends no challenge. Its transport works — GetCACert, GetCACaps and a POSTed
PKIOperation as `application/octet-stream` — which the suite holds
(`tests/vendored/sts_scep_micromdm.js`).

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

## Configuration

Every `scep.*` setting is runtime and per trust realm, on **Protocols → SCEP**
(`/admin/scep`).

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `scep.enabled` | `STS_SCEP_ENABLED` | `true` | yes | Off makes every `/enroll/scep` request answer 503 in this realm; certificates already issued are kept. |
| `scep.allowedProfiles` | `STS_SCEP_ALLOWED_PROFILES` | all nine leaf profiles | yes | The `/admin/pki` profiles a challenge password may be made for; the five CA, OCSP and KDC profiles never are. |
| `scep.defaultProfile` | `STS_SCEP_DEFAULT_PROFILE` | `tls-client` | yes | The profile preselected when a challenge password is made. |
| `scep.certificateLifetimeDays` | `STS_SCEP_CERTIFICATE_LIFETIME_DAYS` | `365` | yes | The validity of a SCEP certificate, shortened to the SCEP Issuing CA's own expiry. |
| `scep.maxRequestBytes` | `STS_SCEP_MAX_REQUEST_BYTES` | `262144` | yes | A pkiMessage larger than this, POSTed or base64 in the GET `message` parameter, is refused before it is decoded. |
| `scep.attemptsPerIdentity` | `STS_SCEP_ATTEMPTS_PER_IDENTITY` | `10` | yes | Refused PKIOperations one challenge may cause in a web-security window before 429. |
| `scep.attemptsPerAddress` | `STS_SCEP_ATTEMPTS_PER_ADDRESS` | `60` | yes | Refused requests one client address may make in a web-security window before 429. |
| `scep.challengeLifetimeS` | `STS_SCEP_CHALLENGE_LIFETIME_S` | `3600` | yes | How long a challenge password may wait before it is redeemed; each is redeemed once. |
| `scep.raKeyAlgorithm` | `STS_SCEP_RA_KEY_ALGORITHM` | `rsa-2048` | yes | The RA certificate's RSA key size (`rsa-2048`, `rsa-3072`, `rsa-4096`); changing it re-issues the RA certificate on its next use. |

How many certificates one entry may hold across ACME, EST and SCEP is
`pki.enrollmentMaxCertificatesPerEntry` ([PKI](pki.md#configuration)). See
[Configuration](configuration.md) for how a value resolves and where it is
changed — the console page, or `POST /admin-api/config/set`.

## Design decisions

* **The challenge is the authorization, and it names the entry.** A challenge
  is made for one entry and one profile — by the person on the portal, or by an
  administrator for anybody in the realm — so whoever redeems it is issued a
  certificate as that entry and nobody else. The administrator's authority was
  used when the challenge was made; the device redeeming it is not an
  administrator.
* **A challenge is spent by the first request that proves it.** It is used up
  before the certificate authority rules on the request, so two transactions
  racing one challenge cannot both be issued. The cost is that a request
  refused afterwards — an unregistered host name, say — has used its challenge,
  and another must be made.
* **The challenge is verified in both modes.** A permissive challenge verifier
  would be a broken verifier, not a development convenience.
* **SCEP is not refused over plain HTTP, in either mode.** RFC 8894 section 2.1
  runs it over HTTP on purpose: the request is signed by the device and
  encrypted to the RA, and the reply is signed and its certificate encrypted
  back, so a transport refusal would refuse every conforming device and protect
  nothing the envelope does not.
* **A request too malformed to name gets an HTTP error; anything else gets a
  signed CertRep FAILURE.** Without a transaction id and a sender nonce there
  is nothing a CertRep could echo — see [above](#when-something-is-refused).
* **The reason for a refusal is never sent.** `failInfo` is the protocol's
  word, and this service's code goes to the audit log and the monitor —
  `failInfoText` is not used.
* **Only RSA requester keys, because the reply is encrypted with RSA key
  transport.** Every profile is issued over SCEP for an RSA key; use
  [EST](est.md) or [ACME](acme.md) for anything else.
* **Only modern algorithms.** SHA-256/384/512 and AES are accepted; SHA-1, MD5,
  DES and 3DES are refused `badAlg`, and a failed RSA key unwrap is
  indistinguishable from a wrong key, so a padding oracle has nothing to read.
* **A retried transaction gets the certificate it already produced.** Only
  successes are remembered, by transaction id: the same CSR gets the same
  certificate without spending another challenge, and a refused request may be
  corrected and retried under the same id.
* **One RA certificate for the whole cluster.** It is an RSA leaf of the SCEP
  Issuing CA, re-issued on demand when it is missing, near expiry, the wrong
  size or no longer under the current Issuing CA, and several nodes agree on
  one rather than each issuing its own.
* **Nothing is approved by hand.** A request is issued or refused when it is
  made, so PENDING is never answered.
* **The CA, OCSP-responder and KDC profiles are never issued.** A challenge for
  one cannot even be created.

## Related

* [PKI](pki.md) — the realm's certificate authority, its profiles, CRLs and
  OCSP responders
* [ACME](acme.md) and [EST](est.md) — the other two enrollment protocols, over
  the same rules
* [Trust realms](trust-realms.md)
* [What is not checked](what-is-not-checked.md)
* [Configuration](configuration.md) and [error codes](error-codes.md)
