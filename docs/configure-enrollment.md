---
title: "Configuring certificate enrollment: ACME, EST, SCEP"
---

# Configuring certificate enrollment: ACME, EST, SCEP

This page shows how to set up iya-sts so that a client can enroll for a
certificate over ACME, EST or SCEP: the realm's certificate authority, the
directory entry the certificate is for, the credential the client needs, and
the commands the client then runs. Each recipe is given twice, once as steps
in the **admin console** (`/admin`) and once as calls to the **Management
API** (`/admin-api`).

**The values come from this repository's own test jobs** in
`tests/vendored/` and `tests/`, and each recipe names the job it is taken
from. The client recipes come from the jobs that drive real clients: certbot,
lego, libest's `estclient`, sscep and certmonger. Change the realm, the names
and the host names to your own.

How each protocol *behaves*, and every setting with its default, is on
[ACME](acme.md), [EST](est.md), [SCEP](scep.md) and [PKI](pki.md). This page
covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token, the `api` shell helper used
below, and the application attribute editor.

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/pki` | **Protocols → PKI** | Build the realm's certificate authority, and revoke any certificate it issued. |
| `/admin/cert-issuance#cert-tab-acme` | **Protocols → Cert issuance**, **ACME** tab | Create External Account Binding (EAB) keys, register host names, see accounts and certificates, revoke, and change the `acme.*` settings. |
| `/admin/cert-issuance#cert-tab-est` | **Protocols → Cert issuance**, **EST** tab | Register host names, issue a certificate with a server-generated key, revoke, and change the `est.*` settings. |
| `/admin/cert-issuance#cert-tab-scep` | **Protocols → Cert issuance**, **SCEP** tab | Create challenge passwords, register host names, re-issue the RA certificate, revoke, and change the `scep.*` settings. |
| `/admin/cert-issuance` | **Protocols → Cert issuance**, **Metadata** tab | Every endpoint of the three servers in this realm, with EST's label-form address. |
| `/admin/applications?application=<id>` | **Directory → Applications** | Declare an application for ACME, EST or SCEP, and override the realm's enrollment rules for it. |
| `/admin/acme/monitor`, `/admin/est/monitor`, `/admin/scep/monitor` | **Monitoring → Cert issuance** | What each server did, and the error code of every refusal. |
| `/portal/certificates` | the user portal | A person makes their own EAB key or SCEP challenge, and revokes their own certificates. |

The settings on each tab are saved with their group's button: **Save ACME**,
**Save EST** or **Save SCEP**. The API equivalents are
`POST /admin-api/config/set`, `/config/set-many` and `/config/reset`. Every
`acme.*`, `est.*` and `scep.*` setting takes effect at runtime and is per
[trust realm](trust-realms.md).

The `GET` operations `/admin-api/acme`, `/admin-api/est` and
`/admin-api/scep` answer everything the tabs draw, including the absolute
endpoints of the realm's server. The live list of every operation and its body
is `GET /admin-api/openapi.json`.

## What development and product mode change

The three protocols do the same thing in both modes, with these exceptions:

* **ACME and EST refuse plain HTTP in product mode.** In development they
  also answer over HTTP and log that they did. The main port is HTTPS by
  default, so this matters only when you turn TLS off. SCEP is answered over
  plain HTTP in both modes, because RFC 8894 secures its own messages.
* **EST checks the password or client secret in product mode only.** In
  development mode any password is accepted for a person who exists, and an
  application's secret is not checked. In product mode a person who holds,
  or must hold, a second factor cannot use their own password for EST; give
  them an [app password](authentication.md#the-password-only-doors-and-app-passwords)
  scoped to `est`.
* **An application must be declared for the protocol in product mode.** An
  application declared for other protocol families, but not ACME, EST or
  SCEP, is refused (`STS-ENROLL-0094`). Development mode refuses nothing,
  and an application declared for nothing is not refused in either mode.
* **A device certificate needs a TPM attestation in product mode.** See
  [Devices](devices.md#a-certificate-over-est-or-scep).

What does not change: the ACME EAB key and the SCEP challenge are checked in
both modes, a certificate is issued only for the entry that authenticated (or
that an administrator named), and a host name is issued only when it is
registered on the entry.

## Before you start: the realm and its certificate authority

Each realm has an **ACME Issuing CA**, an **EST Issuing CA** and a **SCEP
Issuing CA**, under the realm's Intermediate CA and the service Root. They are
made the first time one is needed, as long as the service Root exists, which
it does by default (`pki.autoBuild`). See
[PKI → An Issuing CA per use case](pki.md#an-issuing-ca-per-use-case).

Every job below works in a throwaway realm of its own, and builds the realm's
branch first so that the organisation in every subject is its own. Taken from
`enroll_clients_kit.js`, which the certbot, lego, estclient, sscep and
certmonger jobs share.

**Console:**
1. Create the realm on **Trust realms** (`/admin/realms`), then switch to it.
2. On **Protocols → PKI**, fill in **Organisation (O=)** and
   **Country (C=)**, and click **Build the certificate authority**.

**API:**
```bash
api realms/create '{"id":"enroll-demo","domain":"enroll-demo.example.net",
  "name":"enrollment"}'
BASE=https://localhost:8081/realm/enroll-demo     # every call below is in the realm
api pki/build '{"organisation":"Enrollment Demo","country":"US"}'
```

**Building again replaces the branch**, and everything it issued then chains
to nothing. Build once, before anything is enrolled. See
[PKI → A branch is built whole, or not at all](pki.md#a-branch-is-built-whole-or-not-at-all).

**The trust anchor.** The main port's certificate and every enrolled
certificate chain to the service Root. A client is given it as PEM:

```bash
curl -s http://localhost:8082/pki/ca/service/root.cer |
  openssl x509 -inform DER -out sts-root.pem
```

Port 8082 is `pki.httpPort`, the plain-HTTP listener that serves `/pki/` and
SCEP. The main port answers the same path.

**The person or application.** A certificate always names a directory entry,
and is written onto it. The jobs create a person with a generated password,
because product mode checks it:

```bash
api users/create '{"username":"alice","invent":false,"credential":"generate",
  "attributes":{"cn":"alice","givenName":"alice","sn":"alice",
                "mail":"alice@example.test"}}'
```

The reply carries the password, once. `givenName`, `sn` and `mail` are there
because a product-mode realm's attribute policy requires them.

## Host names, for all three protocols

A `dNSName` or `iPAddress` is issued in a certificate only when it is
registered on the entry. One registration serves ACME, EST and SCEP. A
registered `*.example.com` authorizes that wildcard, and only when it is
written so. This service never dials a host to prove control of it.

Taken from `sts_acme_certbot.js`.

**Console:** on any of the three tabs, in **Registered host names** (on the
EST tab, **Certificate host names**), choose **person** or **application**,
type the identifier and the **host name or address**, and click
**Register**. On an application's page, its **Certificate enrollment** tab
has the same form.

**API** (`acme/`, `est/` or `scep/`; the three are the same register):
```bash
api acme/add-host-name '{"kind":"person","identifier":"alice",
  "hostName":"www.alice.test"}'
api acme/add-host-name '{"kind":"person","identifier":"alice",
  "hostName":"api.alice.test"}'
```

`acme/remove-host-name` (and the EST and SCEP ones) takes the same body.

---

# ACME

An ACME account is bound to one directory entry, for life, by a required
External Account Binding key. No challenge is performed: an identifier is
authorized from the entry, and the authorization is created `valid`. See
[ACME](acme.md) for why.

## An EAB key for a person

Taken from `sts_acme_certbot.js` and `sts_acme_enrollment.js`.

**Console:**
1. On **Protocols → Cert issuance**, **ACME** tab, go to **External Account
   Binding keys**.
2. Choose **person**, type the **identifier** `alice`, and leave
   **lifetime (s)** empty for the realm's `acme.eabLifetimeS` (a week).
3. Click **Create EAB key**. Copy the key id and the HMAC key. **The HMAC key
   is shown once.**

**API:**
```bash
api acme/create-eab '{"kind":"person","identifier":"alice"}'
```

The reply carries `kid` (`eab-p-…`), `hmacKey`, `alg` (`HS256`),
`expiresAt`, the realm's `directory` URL, and a ready-to-paste `certbot` line.
`lifetimeS` (60 to 31536000, at most `acme.eabLifetimeS`) shortens it; the
enrollment job makes a sixty-second one to check that an expired key is
refused.

**A person can make their own** on `/portal/certificates`, with **Make an ACME
account binding key**. `sts_portal_certificates.js` covers that door.

An EAB key binds one account and no other. To delete one before it binds, use
**Delete** on its row, or `acme/delete-eab` with `{"kid":"…"}`.

## certbot

Taken from `sts_acme_certbot.js`, which drives certbot 5.8.0. The realm's
directory is `$BASE/enroll/acme/directory`; the EAB reply names it.

```bash
DIR=https://localhost:8081/realm/enroll-demo/enroll/acme/directory
export REQUESTS_CA_BUNDLE=sts-root.pem

certbot register --server $DIR --agree-tos --no-eff-email \
  -m alice@example.test --eab-kid "$KID" --eab-hmac-key="$HMAC"

certbot certonly --server $DIR --cert-name plain \
  --standalone --http-01-port 18888 -d www.alice.test -d api.alice.test
```

* **Write `--eab-hmac-key=<key>` as one argument.** A base64url key may begin
  with `-`, and certbot then reads it as an option.
* **No challenge is performed.** certbot still wants an authenticator named;
  `--standalone` binds its port and receives nothing.
* **An order of host names only is issued `tls-server`** (serverAuth) when it
  names no profile. `--required-profile tls-server` and
  `--preferred-profile tls-server-client` name one.
* The certificate's subject is `CN=www.alice.test, UID=alice, O=<organisation>`.

Renew, revoke and manage the account:

```bash
certbot renew --server $DIR --cert-name plain --force-renewal \
  --no-random-sleep-on-renew
certbot revoke --server $DIR --cert-path <lineage>/cert.pem \
  --reason keycompromise --no-delete-after-revoke
certbot update_account --server $DIR -m renamed-alice@example.test
certbot unregister --server $DIR
```

A plain `certbot renew` consults the renewal information (RFC 9773) and
renews nothing that is not due. The revoked serial goes on the ACME Issuing
CA's CRL. `unregister` deactivates the account, and the **Accounts** section
lists it deactivated.

## lego

Taken from `sts_acme_lego.js`, which drives lego v5.5.2:

```bash
export LEGO_CA_CERTIFICATES=sts-root.pem
lego accounts register --server $DIR --accept-tos -m bob@example.test \
  --eab --eab.kid "$KID" --eab.hmac="$HMAC"
lego run --server $DIR -m bob@example.test --profile tls-server -c web \
  -d www.bob.test -d api.bob.test --http --http.address 127.0.0.1:18889
lego accounts keyrollover --server $DIR -m bob@example.test --key-type RSA2048
lego certificates revoke --server $DIR -m bob@example.test -c web --reason 4 --keep
```

lego, unlike certbot, does key rollover. `--not-after` and `--not-before` are
refused, because the realm sets the lifetime. **A refused registration leaves
lego holding a key with no account**; register again in a fresh `--path`.

## An application's own certificate

Taken from `sts_acme_enrollment.js`. An application gets an account the same
way a person does: an administrator creates the EAB key for it.

**Console:**
1. Create the application on **Applications → New application ›**, and tick
   **ACME** under **Protocol families it is declared for**.
2. Register its host names as [above](#host-names-for-all-three-protocols),
   choosing **application**.
3. On the **ACME** tab, create an EAB key for **application** `acmeapp`, and
   hand the key id and HMAC key to whoever runs the client.

**API:**
```bash
api applications/create '{"identifier":"acmeapp","protocols":["oauth2","acme"],
  "fields":{"oauthClientId":"acmeapp"}}'
api acme/create-eab '{"kind":"application","identifier":"acmeapp"}'
```

The key id of an application's key begins `eab-a-`. An application's account
is refused a person's identifiers.

## Profiles and lifetime

An order may name a profile. One that names none gets `tls-server` when every
identifier is a host name, and `acme.defaultProfile` (`tls-client`) otherwise.
The CA, OCSP-responder and KDC profiles are never issued. The full table is on
[ACME → Profiles](acme.md#profiles).

To narrow the realm to one profile (from `sts_acme_enrollment.js`):

```bash
api config/set '{"key":"acme.allowedProfiles","value":"tls-client"}'
api config/reset '{"key":"acme.allowedProfiles"}'
```

An order naming any other profile is then refused `invalidProfile`. The
certificate lifetime is `acme.certificateLifetimeDays` (90). For a per-application
override, see [Rules for one application](#rules-for-one-application).

---

# EST

EST has no credential of its own. A client authenticates with a person's
password, an application's `client_id` and `client_secret`, or a TLS client
certificate this realm issued. The path is `/.well-known/est/<profile>/<operation>`,
and the unlabelled path issues `est.defaultProfile` (`tls-client`). See
[EST](est.md).

## A person, with libest's estclient

Taken from `sts_est_libest.js`. The person is `alice` with the password the
`users/create` reply gave, and `dev.alice.test` is registered on her entry.

**First, turn TLS 1.2 back on.** Every listener is TLS 1.3 only by default
(`tls.disableTls12`), and estclient is built on OpenSSL 1.1 and negotiates TLS
1.2. The job turns it on for the whole service and resets it afterwards. To
change only the main port, set `listenerMain.disableTls12` to `off` instead; see
[TLS and mutual TLS](tls.md).

```bash
api config/set '{"key":"tls.disableTls12","value":false}'
```

Then bootstrap from the Root, and use the `/cacerts` answer as the trust
anchors from then on:

```bash
export EST_OPENSSL_CACERT=sts-root.pem
estclient -g -s localhost -p 8081 -o out
base64 -d out/cacert-0-0.pkcs7 | openssl pkcs7 -inform DER -print_certs > est-ca.pem
export EST_OPENSSL_CACERT=est-ca.pem

estclient -e -s localhost -p 8081 -o out -u alice -h "$PASSWORD" \
  --common-name alice --pem-output                          # /simpleenroll
estclient -r -s localhost -p 8081 -o out -c out/cert-0-0.pem -k <key> \
  --pem-output                                              # /simplereenroll
estclient -q -s localhost -p 8081 -o out -x <key> -u alice -h "$PASSWORD" \
  --common-name alice --pem-output                          # /serverkeygen
```

**A server certificate** needs the host registered and the `tls-server`
label, with a request made by `openssl`:

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout web.key -out web.csr \
  -subj /CN=dev.alice.test -addext subjectAltName=DNS:dev.alice.test
estclient -e -s localhost -p 8081 -o out --path-seg tls-server -y web.csr \
  --pem-output -u alice -h "$PASSWORD"
```

The certificate's subject is `CN=dev.alice.test, UID=alice, O=…`. A host not
registered on the entry is refused.

**In a realm other than the default**, estclient cannot build
`/realm/<id>/.well-known/est`, and it sends only one label. Name the realm in
the label position instead: `--path-seg <realm>`. The profile is then that
realm's `est.defaultProfile`, so the job sets it before asking for a server
certificate:

```bash
api config/set '{"key":"est.defaultProfile","value":"tls-server"}'
estclient -e -s localhost -p 8081 -o out --path-seg enroll-demo -y web.csr \
  -u alice -h "$PASSWORD"
```

A realm may not be named after a profile, so the segment always means one
thing. See [EST → Reaching a realm through the label](est.md#reaching-a-realm-through-the-label).

estclient exits 0 whether or not it enrolled; read what it wrote to `out/`.
[EST → With libest's estclient](est.md#with-libests-estclient) lists the
other things it prints that are not the server's.

## An application, with curl

Taken from `sts_est_enrollment.js`, which sends these requests with its own
client. The application authenticates with HTTP Basic, its `client_id` and its
`client_secret`.

**Console:**
1. Create the application on **Applications → New application ›**: tick
   **OAuth 2.0** and **EST**, and generate a secret in **The client secret**.
2. Register its host name, choosing **application**.

**API:**
```bash
APP_SECRET=$(openssl rand -base64 18)
api applications/create '{"identifier":"estapp","protocols":["oauth2","est"],
  "fields":{"oauthClientId":"estapp","oauthClientSecret":"'"$APP_SECRET"'"}}'
api est/add-host-name '{"kind":"application","identifier":"estapp",
  "hostName":"estapp.svc.example.test"}'
```

**Request** (the body is the base64 of the DER PKCS#10):
```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout app.key -subj /CN=estapp \
  -addext subjectAltName=DNS:estapp.svc.example.test -outform DER -out app.csr.der
base64 app.csr.der | curl -s --cacert sts-root.pem -u "estapp:$APP_SECRET" \
  -H 'Content-Type: application/pkcs10' --data-binary @- \
  https://localhost:8081/realm/enroll-demo/.well-known/est/tls-server/simpleenroll \
  | base64 -d | openssl pkcs7 -inform DER -print_certs > app.pem
```

A Basic username is looked up as a person first, then as an application's
`client_id`. A wrong secret is refused in product mode.

**Which credentials are accepted.** `est.basicAuthentication` and
`est.certificateAuthentication` (both on) turn each method off for the realm,
and the application's `estBasicAuthentication` and
`estCertificateAuthentication` override them for it. In the console these are
in the EST tab's **Settings**, and on the application's **Certificate
enrollment** tab.

## A key pair made by the service

`/serverkeygen` makes the key pair here and keeps a sealed copy on the entry.
An administrator can do the same for any entry. Taken from
`tests/est_handlers.js`.

**Console:** on the **EST** tab, in **Issue a certificate with a
server-generated key**, choose the entry, the **Profile** and the **Key
algorithm**, and click **Issue with a server-generated key**. The private key
is shown once.

**API:**
```bash
api est/issue-server-key '{"kind":"person","identifier":"alice",
  "profile":"digital-signature","keyAlg":"ec-p256"}'
```

The reply carries `privateKeyPem`, once. `keyAlg` is one of the
`keyAlgorithms` that `GET /admin-api/est` lists; an ML-KEM key is certified
for `key-encipherment` only. `est.serverKeyGeneration` turns this off.

---

# SCEP

A SCEP client authenticates its first enrollment with a **challenge
password**, made for one entry and one profile and redeemed once. A renewal is
signed by the certificate being renewed and needs no challenge. Only RSA keys
can be enrolled, and SHA-1, MD5, DES and 3DES are refused. See [SCEP](scep.md).

## A challenge password

Taken from `sts_scep_sscep.js`.

**Console:**
1. On **Protocols → Cert issuance**, **SCEP** tab, go to **Challenge
   passwords**.
2. Choose **person**, type `carol`, pick the profile `tls-client`, and leave
   the lifetime empty for `scep.challengeLifetimeS` (an hour).
3. Click **Create a challenge**. **It is shown once.**

**API:**
```bash
api scep/create-challenge '{"kind":"person","identifier":"carol","profile":"tls-client"}'
```

The reply carries `challenge`, the `url` on the main port, the `plainUrl` on
the plain-HTTP listener, and `hint`: the three shell lines that make a request
and enroll with sscep. The job runs the hint as it is written, and it enrolls.

**A person can make their own** on `/portal/certificates`, with **Make a SCEP
challenge password**. An application has no portal, so an administrator makes
its challenges with `"kind":"application"`.

A challenge is spent by the first request that proves it, even if the request
is then refused (for an unregistered host name, say). Make another.

## sscep

sscep has no TLS, so it uses the plain-HTTP URL, `http://<host>:8082/realm/<realm>/enroll/scep/<profile>`.
Taken from `sts_scep_sscep.js`:

```bash
URL=http://localhost:8082/realm/enroll-demo/enroll/scep/tls-client
sscep getca -u $URL -c ca.crt           # ca.crt-0 is the RA, ca.crt-1 the SCEP Issuing CA

cat > req.cnf <<EOF
[req]
prompt=no
distinguished_name=dn
attributes=attrs
[dn]
CN=carol
O=<the organisation the hint names>
C=US
[attrs]
challengePassword=$CHALLENGE
EOF
openssl req -new -newkey rsa:2048 -nodes -keyout carol.key -out carol.csr \
  -config req.cnf -addext subjectAltName=URI:urn:sts:person:carol

sscep enroll -u $URL -c ca.crt-0 -e ca.crt-0 -k carol.key -r carol.csr \
  -l carol.pem -S sha256 -E aes
```

* **`prompt=no`**, or OpenSSL puts no challengePassword in the request.
* **`-c ca.crt-0`, the RA**, because the RA signs every reply.
* **The subject the certificate will carry**, or sscep warns. The hint
  writes the right one.

Renew with the old certificate and a new key; no challenge is needed, and the
old serial goes on the SCEP CRL:

```bash
sscep enroll -u $URL -c ca.crt-0 -e ca.crt-0 -k new.key -r new.csr \
  -K carol.key -O carol.pem -S sha256 -E aes -l renewed.pem
```

`sscep enroll … -R` resumes the same transaction and gets the same
certificate back. `sscep getcert` and `sscep getcrl`, signed with the enrolled
certificate, answer the certificate and the SCEP Issuing CA's CRL.

## certmonger

Taken from `sts_scep_certmonger.js`, where erin makes her own challenge on
`/portal/certificates`. Use the plain-HTTP URL here too:
certmonger passes its CA file only to GetCACaps and GetCACert, so an HTTPS
enrollment fails unless the service Root is in the host's trust store.

```bash
getcert add-scep-ca -c STS -u http://localhost:8082/realm/enroll-demo/enroll/scep/tls-client
getcert request -c STS -k "$PWD/erin.key" -f "$PWD/erin.pem" \
  -N "CN=erin,O=<organisation>,C=US" -L "$CHALLENGE" -I erin -w
getcert resubmit -i erin -w     # renew with the same key
getcert rekey -i erin -w        # renew with a new key
```

A refusal shows as `CA_UNREACHABLE`, and certmonger retries it. The reason is
on **Monitoring → Cert issuance → SCEP enrollments**; stop the retries with
`getcert stop-tracking -i erin`.

## The RA certificate

SCEP requests are encrypted to the realm's RA certificate, an RSA leaf of the
SCEP Issuing CA. Its key size is `scep.raKeyAlgorithm` (`rsa-2048`). To
replace it (from `sts_scep_enrollment.js`):

**Console:** on the **SCEP** tab, **RA certificate**, click **Re-issue the RA
certificate**.

**API:**
```bash
api scep/reissue-ra '{}'
```

The old RA certificate goes on the CRL as `superseded`. A client encrypting
to it is answered `badMessageCheck` until it runs GetCACert again.

---

# For all three

## Rules for one application

An application can override the realm's enrollment rules. Taken from
`tests/application_enrollment.js`.

**Console:** on the application's page, **Configuration** tab:
1. In **Protocol families**, tick **ACME**, **EST** or **SCEP**, and click
   **Save**.
2. In **Certificate enrollment**, fill in any override and click **Save**. An
   empty field takes the realm's value.

**API:**
```bash
api applications/set '{"application":"estapp","attribute":"estCertificateLifetimeDays","value":"30"}'
api applications/add '{"application":"estapp","attribute":"estAllowedProfiles","value":"tls-server"}'
api applications/set '{"application":"estapp","attribute":"estBasicAuthentication","value":"FALSE"}'
```

The attributes are `<family>AllowedProfiles`, `<family>DefaultProfile` and
`<family>CertificateLifetimeDays` for `acme`, `est` and `scep`;
`enrollMaxCertificates`; and, for EST only, `estBasicAuthentication`,
`estCertificateAuthentication` and `estServerKeyGeneration` (`TRUE` or
`FALSE`). [Applications → Certificate enrollment](applications.md#certificate-enrollment-acme-est-scep)
describes each.

How many certificates one entry may hold across the three protocols is
`pki.enrollmentMaxCertificatesPerEntry` (20). Past it a request is refused
(`STS-ENROLL-0040`); no older certificate is dropped to make room.

## Revocation, as a client sees it

Every enrolled certificate names its Issuing CA's CRL and OCSP responder, on
the plain-HTTP listener (`pki.httpPort`, 8082). The `<scope>` is the realm id,
or `default` in the default realm, and `<ca>` is `acme`, `est` or `scep`:

| What | Where |
|---|---|
| The CRL | `http://<host>:8082/pki/crl/<scope>/<ca>.crl` (the `.crl` is optional) |
| The OCSP responder | `http://<host>:8082/pki/ocsp/<scope>/<ca>` (GET or POST) |
| The Issuing CA's certificate | `http://<host>:8082/pki/ca/<scope>/<ca>.cer` |
| Every authority's addresses | `GET /pki/revocation` |

A CRL is signed when it is fetched, and its `nextUpdate` is
`pki.crlLifetimeMinutes` (60) away. Behind a port mapping, set
`pki.distributionPort` or `pki.distributionBaseUrl` so that the addresses
written into a certificate are reachable; see
[PKI → Revocation is published, and consulted](pki.md#revocation-is-published-and-consulted).

**A client revokes** with its own protocol: ACME `revokeCert` (signed by the
account or by the certificate's own key), or nothing for EST and SCEP. A
person revokes their own on `/portal/certificates`. EST and SCEP renewals
revoke the old certificate as `superseded`; an ACME order's `replaces` does
not.

**An administrator revokes** on the protocol's tab (**Revoke** on the
certificate's row, with a reason), on **Protocols → PKI**, or through the
API. The serial is named differently in each:

```bash
api acme/revoke-certificate '{"serial":"<serial>","reason":"superseded"}'          # sts_acme_enrollment.js
api est/revoke-certificate  '{"serialHex":"<serial>","reason":"keyCompromise"}'   # sts_est_enrollment.js
api scep/revoke-certificate '{"serial":"<serial>","reason":"keyCompromise"}'      # sts_scep_enrollment.js
```

The serial is hexadecimal, as `GET /admin-api/acme`, `/est` or `/scep` lists
it. From then on the serial is on the CRL and OCSP answers `revoked`; the jobs
check both. An ACME client asking for renewal information about a revoked
certificate is told to renew now.

Revoking here publishes the revocation. Whether anything then refuses the
certificate is up to whoever relies on it; this service itself checks what is
presented to it under `pki.revocationCheck`.

## When something is refused

The client sees only the protocol's own error: an ACME problem document, an
EST HTTP status with one plain sentence, or a SCEP CertRep FAILURE with a
`failInfo`. The reason is on the protocol's monitoring page and on the audit
log, as an `STS-ACME-…`, `STS-EST-…`, `STS-SCEP-…` or `STS-ENROLL-…` code.
`GET /admin-api/acme/monitor` (and `est/monitor`, `scep/monitor`) answers the
same counts. Look the code up on [Error codes](error-codes.md).

## Related

* [ACME](acme.md), [EST](est.md) and [SCEP](scep.md): the behaviour and every setting.
* [PKI](pki.md): the certificate authority, its profiles, CRLs and OCSP responders.
* [Devices](devices.md): the `device` profile over EST and SCEP.
* [Configuring TLS and mutual TLS](configure-tls.md): using an enrolled `tls-client` certificate to sign in.
* [Configuring SPIFFE](configure-spiffe.md): X509-SVIDs, the fourth thing on **Cert issuance**.
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md): the API token and the `api` helper.
