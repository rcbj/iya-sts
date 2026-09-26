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

### Reaching a realm through the label

A realm other than the default is also reached **by naming it in the label
position**, at the root of the origin — for EST clients that are given a host,
a port and at most one label and can put nothing in front of
`/.well-known/est` (RFC 8615 puts a well-known URI at the root; libest's
estclient is one such client):

| Path | Reaches |
|---|---|
| `/.well-known/est/<realm>/<operation>` | realm `<realm>`, its `est.defaultProfile` |
| `/.well-known/est/<realm>/<profile>/<operation>` | realm `<realm>`, that profile |
| `/realm/<realm>/.well-known/est/[<profile>/]<operation>` | the same, by the prefix |

The two forms reach the same server with the same settings, CA and
certificates. The rules:

* **A realm may not be called by a label's name** — any of the nine profiles
  above or the five never issued. Creating one is refused (`STS-CORE-0107`), so
  one segment always means one thing. (A realm created with such a name before
  2026-09-26 keeps it, is reached by its prefix only, and the segment still
  means the profile.)
* **A request names its realm once.** A label that names a realm after the
  realm was already named — `/realm/a/.well-known/est/b/cacerts`, or
  `/.well-known/est/a/b/cacerts` — is refused 404 (`STS-EST-0022`), never
  read as a second realm or as a profile.
* An unknown name in the label position is an unknown label: 404.
* `/admin/est` in a realm, and `GET /realms` for every realm (`estLabelUrl`),
  show the label-form address.

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
| `device` | a DEVICE entry: the one the request's `urn:sts:device:<id>` names (its owner, or an administrator), or a new one owned by the requester; a TPM key attestation in product. See [Devices](devices.md) |

**Never issued over EST** (403): `root-ca`, `intermediate-ca`, `issuing-ca`,
`ocsp-responder` and `kdc`. Each makes its holder an authority over everybody
else in the realm; `/admin/est` gives the reason for each. An unknown label is
404. `est.allowedProfiles` narrows the nine further per realm.

## Authenticating

* **HTTP Basic with a person's directory password** — checked in product mode;
  development mode accepts any password for a person who exists. In product a
  person who holds or must hold a second factor — an administrator enrolling
  for somebody else included — is refused their own password with the `401` a
  wrong one gets, and uses an [app password](authentication.md#the-password-only-doors-and-app-passwords) scoped to `est`, or a certificate.
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

## With libest's estclient

Cisco's `estclient` (libest, the reference implementation) bootstraps from the
Root and then uses the `/cacerts` answer as its trust anchors, as RFC 7030
section 4.1.1 has a client do:

```sh
export EST_OPENSSL_CACERT=sts-root.pem
estclient -g -s host -p 8081 -o out                     # out/cacert-0-0.pkcs7
base64 -d out/cacert-0-0.pkcs7 | openssl pkcs7 -inform DER -print_certs > est-ca.pem
export EST_OPENSSL_CACERT=est-ca.pem
estclient -e -s host -p 8081 -o out -u alice -h "$PASSWORD" --common-name alice --pem-output
estclient -r -s host -p 8081 -o out -c out/cert-0-0.pem -k out/key-x-x.pem --pem-output
estclient -q -s host -p 8081 -o out -x key.pem -u alice -h "$PASSWORD" --common-name alice --pem-output
estclient -e -s host -p 8081 -o out -y web.csr --path-seg tls-server -u alice -h "$PASSWORD"
```

Things to know, each found by the suite's run of it
(`tests/vendored/sts_est_libest.js`):

* **It reaches another realm through the label** (#251): estclient builds its
  URL as `https://host:port/.well-known/est[/label]/op` and accepts ONE label
  segment, so `--path-seg <realm>` names the realm (see *Reaching a realm
  through the label*) and the profile is that realm's `est.defaultProfile`.
  A labelled profile inside a realm needs two segments, which estclient
  refuses to send; `/realm/<id>/.well-known/est` it cannot build at all.
* With only the Root as `EST_OPENSSL_CACERT`, every `-r` warns "unable to get
  local issuer certificate": estclient verifies what it was issued against its
  trust anchors, which must hold the Issuing CA and the Intermediate — the
  `/cacerts` answer.
* `-q` prints `OSSL error: (null)` on success: libest dumps OpenSSL's (empty)
  error queue whether or not anything failed. The key it writes
  (`key-0-0.key`) is base64 PKCS#8 without PEM armour.
* It exits 0 whether or not it enrolled; read what it wrote.
* It builds against OpenSSL 1.1 only (`FIPS_mode()` is gone from 3.0).
* `-z` enrolls, but the challengePassword is not read (see *Not implemented*),
  and `--srp` is refused at the handshake.

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

The subject is `CN=<username or identifier>, O=<organisation>` — or, for a
certificate that names a host, `CN=<the first dNSName, else iPAddress>,
UID=<username or identifier>, O=<organisation>` (#207: a client that reads a
certificate's names back as its CN and its dNSNames, as certbot and lego do,
asked for the entry's name as a host on every renewal; the UID keeps the
subject naming exactly one entry). The subjectAltName always carries the entry's `urn:sts:` name plus any requested
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

## Configuration

Every `est.*` setting is runtime and per trust realm, on **Protocols → EST**
(`/admin/est`).

| Setting | Environment variable | Default | Runtime? | What it does |
|---|---|---|---|---|
| `est.enabled` | `STS_EST_ENABLED` | `true` | yes | Off makes every `/.well-known/est` endpoint answer 503 in this realm; certificates already issued are kept. |
| `est.allowedProfiles` | `STS_EST_ALLOWED_PROFILES` | all nine leaf profiles | yes | The `/admin/pki` profiles a label may name; the five CA, OCSP and KDC profiles are never issued whatever this says. |
| `est.defaultProfile` | `STS_EST_DEFAULT_PROFILE` | `tls-client` | yes | What the unlabelled `/.well-known/est/simpleenroll` issues. |
| `est.certificateLifetimeDays` | `STS_EST_CERTIFICATE_LIFETIME_DAYS` | `365` | yes | The validity of an EST certificate, shortened to the EST Issuing CA's own expiry. |
| `est.maxRequestBytes` | `STS_EST_MAX_REQUEST_BYTES` | `65536` | yes | A PKCS#10 body larger than this is refused (413) before it is decoded. |
| `est.attemptsPerIdentity` | `STS_EST_ATTEMPTS_PER_IDENTITY` | `10` | yes | Refused authentications or enrollments one username, `client_id` or certificate may make in a web-security window before 429. |
| `est.attemptsPerAddress` | `STS_EST_ATTEMPTS_PER_ADDRESS` | `60` | yes | Refused requests one client address may make in a web-security window before 429. |
| `est.basicAuthentication` | `STS_EST_BASIC_AUTHENTICATION` | `true` | yes | Accepts HTTP Basic with a person's password or an application's `client_id` and secret; whether the password is checked follows `global.mode`. |
| `est.certificateAuthentication` | `STS_EST_CERTIFICATE_AUTHENTICATION` | `true` | yes | Accepts a TLS client certificate this realm issued, mapped to its entry; required for `/simplereenroll` with no Basic credential. |
| `est.serverKeyGeneration` | `STS_EST_SERVER_KEY_GENERATION` | `true` | yes | Whether `/serverkeygen` generates the key pair — the one enrollment path in which this service holds a private key, kept sealed on the entry. |

The nine leaf profiles are those in the table under
[The endpoints](#the-endpoints). How many certificates one entry may hold
across ACME, EST and SCEP is `pki.enrollmentMaxCertificatesPerEntry`
([PKI](pki.md#configuration)). See [Configuration](configuration.md) for how a
value resolves and where it is changed — the console page, or
`POST /admin-api/config/set`.

## Design decisions

* **A label is a profile, not a CA.** RFC 7030 lets a server label its CAs;
  here there is one EST Issuing CA per realm, and the label says what kind of
  certificate is asked for. An unknown label is 404, a refused or disallowed
  one 403.
* **Authentication uses credentials the service already has.** A person's
  password, an application's client secret or a certificate this realm issued —
  EST gets no credential of its own. See [above](#authenticating).
* **A Basic username is a person first.** Then an application's `client_id`,
  so a person and an application sharing a name authenticate as the person.
* **Nothing is parsed for an unauthenticated client.** The query string,
  whether EST is on, the transport, the label, the rate limit, the media type
  and the size are all decided before a credential is read, and the
  credential before the body, so an unauthenticated client is never why a CSR
  is decoded and verified.
* **The certificate is decided by the profile and the entry.** Key usage,
  extended key usage and basic constraints come from the profile, and a
  requested name the entry does not own refuses the request rather than being
  dropped — see [above](#what-the-ca-decides-not-the-request).
* **A private key is kept only when this service generated it.**
  `/simpleenroll` never sees one; `/serverkeygen` keeps a sealed copy on the
  entry the certificate names — see [above](#server-generated-keys).
* **A re-enrollment must repeat what it renews.** The subject and
  subjectAltName must match the certificate being renewed (RFC 7030 section
  4.2.2's "identical"), and the renewed certificate goes on the EST CRL as
  `superseded`.
* **A KEM key is certified for `key-encipherment` only.** An ML-KEM key cannot
  sign a proof of possession, so it comes only from `/serverkeygen`, and never
  under a profile whose key usage it cannot perform.
* **A request body is decoded strictly.** RFC 8951 made whitespace legal and no
  other stray byte, so anything outside the base64 alphabet is refused rather
  than skipped the way a lenient decoder would.
* **The CA, OCSP-responder and KDC profiles are never issued.** Each would make
  its holder an authority over everybody else in the realm.
* **Refusals are one plain-text sentence, and the code stays behind.** RFC 7030
  asks for a human-readable message; the `STS-EST-*` code is on the audit row
  and the monitor, never in the body.

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

## Related

* [PKI](pki.md) — the realm's certificate authority, its profiles, CRLs and
  OCSP responders
* [ACME](acme.md) and [SCEP](scep.md) — the other two enrollment protocols,
  over the same rules
* [TLS and mutual TLS](tls.md) — the client certificate EST accepts, and what
  it signs in
* [Trust realms](trust-realms.md)
* [What is not checked](what-is-not-checked.md) — which passwords are checked
  in which mode
* [Configuration](configuration.md) and [error codes](error-codes.md)
