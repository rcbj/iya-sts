---
title: "Configuring TLS and mutual TLS"
---

# Configuring TLS and mutual TLS

This page shows how to set up the TLS side of iya-sts: the certificate its
listeners present, the client certificates it trusts, signing in with a
certificate, and the extra HTTPS listeners it can answer on. Each recipe is
given twice where both exist: once as steps in the **admin console**
(`/admin`) and once as calls to the **Management API** (`/admin-api`). Some
settings are read only at startup, and those recipes use environment
variables instead.

**The values come from this repository's own test jobs**, and each recipe
names the job it is taken from. Jobs in `tests/protocol/` run over HTTP
against a running service in both modes; files directly in `tests/` run the
service in process. Change the names, ports and certificates to your own.

What each feature *does*, and every setting with its default, is on
[TLS and mutual TLS](tls.md) and [Listeners and hosted applications](listeners.md).
This page covers only what to fill in.
[Configuring OAuth 2.0 grants → Before you start](configure-oauth2-grants.md#before-you-start)
explains the shared mechanics: the API token and the `api` shell helper used
below.

* TOC
{:toc}

## Where things are

| Page | Console menu | What you do there |
|---|---|---|
| `/admin/tls` | **Protocols → TLS / mutual TLS** | Read the certificate the main port and LDAPS present, and what the service does with a client certificate. |
| `/admin/tls/trust` | **Protocols → Client-certificate truststore** | Add and remove the CAs that client certificates are verified against. |
| `/admin/listeners` | **Server configuration → Listeners** | Every listener's TLS policy and client-certificate toggles, HTTP/2, custom listeners and which hosted application is on which. |
| `/admin/tls-connection` | **Monitoring → TLS connection** | See what the service saw of your own request: TLS version, cipher, client certificate, forwarding headers. |
| `/admin/applications?application=<id>` | **Directory → Applications** | Issue an application a TLS client certificate (**Credentials → Mutual TLS (RFC 8705)**) and set its RFC 8705 attributes. |
| `/portal/signing-key` | the user portal | A person issues themselves a TLS client certificate. |

The Listeners page has these tabs: **Listeners** (the built-in sockets),
**Custom listeners** (the definitions and the mapping, each a JSON text box),
**Applications** (where each hosted application is), **Service-wide
defaults** (what every listener inherits), and one tab per built-in TLS
listener, such as **Main port**. Each settings group is saved with its own
**Save <group>** button. The API equivalents are `POST /admin-api/config/set`,
`/config/set-many` and `/config/reset`.

**Some settings are read only at startup.** The listener certificate's names
and files, the startup truststore file, `tls.trustIssuedClientCertificates`,
`listeners.adminOnMain` and `global.https` are restart-only. The console shows
them with the reason, and `config/set` refuses them. Set them in the
environment (`docker run -e …`, or `docker-compose.yml`) or in an appconfig
file, and restart. Everything else on this page takes effect at the next
handshake or the next connection, with no restart.

**The client truststore and the built-in listeners belong to the process,
not to a realm.** Every trust realm shares them, so change them in the default
realm. A realm can have custom listeners of its own (see
[A trust realm on a listener of its own](#a-trust-realm-on-a-listener-of-its-own)).

## What development and product mode change

The TLS settings mean the same in both modes. What differs is what happens to
a client certificate once it has verified:

* **Revocation.** `pki.revocationCheck` is `auto` by default: **soft-fail in
  development** (a revoked certificate is refused, an unknown status is
  accepted and reported) and **hard-fail in product** (an unknown status is
  refused too).
* **A certificate from your own CA must name a CRL or OCSP responder in
  product mode.** Under hard-fail, `pki.revocationRequireDistributionPoint`
  (`auto`) refuses a foreign CA's certificate that names neither, because
  nobody could ever revoke it. Give your CA a CRL distribution point the
  service can fetch. Certificates this service issued are checked against its
  own register and need nothing.
* **The person must already exist in product mode.** `GET /tls/sign-in`
  signs in the person a certificate names. Development mode creates a missing
  directory entry; product mode signs in only somebody who was provisioned
  first.

The truststore, the identity gate on certificates this service issued, and
the listener settings are the same in both modes.

## Trust the listener certificate

Every TLS listener (the main port, LDAPS 636, the protocol debugger, and each
custom listener that has no certificate file) presents a certificate issued
under this service's Root CA. A client needs the Root in its truststore. In
development mode the Root is rebuilt at every start, so fetch it again after
a restart.

Taken from `tests/tools/trust.js`, which every node-driven job uses.

```bash
# The first fetch cannot be verified: nothing holds the anchor yet.
curl -sk "$BASE/tls/server-certificate" > sts-chain.pem   # leaf, chain, then the Root last
curl --cacert sts-chain.pem "$BASE/healthcheck"           # verified from here on
export NODE_EXTRA_CA_CERTS=$PWD/sts-chain.pem             # for a node client
```

Keep the whole file, or at least the Root (the last certificate in it). A
truststore that holds only the leaf builds no path, and the client reports
`unable to get local issuer certificate`. For a browser, import the Root as
an authority; [TLS and mutual TLS → When a browser refuses the certificate](tls.md#when-a-browser-refuses-the-certificate)
has the steps.

### What the handshake sends

Every listener sends four certificates: its own, the TLS Issuing CA, the
Intermediate, and the service Root. RFC 8446 section 4.4.2 lets a server send
the Root or leave it out; this service sends it. That covers the main port,
LDAPS 636, the custom and realm listeners, the protocol debugger, the channel
between cells and the SPIFFE gRPC listeners. A remote XACML PEP's
`fullChainPem` has the Root last too.

The Root arrives so that you can see which one it is. **Receiving it does not
make your client trust it**: a client trusts only the Roots in its own store
(RFC 5280 section 6.1). Every install builds its own Root, and every Root is
named `CN=iya-sts Root CA, O=iya-sts` (`CN=sts Root CA, O=sts` for one built
before #1294). A certificate viewer that shows only the name can make two
installs look as if they share one Root. Compare thumbprints instead:

```bash
openssl s_client -connect "$HOST:8081" -showcerts </dev/null 2>/dev/null \
  | awk '/BEGIN CERT/,/END CERT/' > presented.pem      # four certificates
curl -sk "$BASE/pki/ca/%2Aservice/root" | openssl x509 -inform der \
  -noout -fingerprint -sha256                          # this install's Root
```

If you trusted an earlier install's Root, remove it. It has the same name as
the new one but a different key, and it anchors nothing this install issues.

A certificate you supply from your own files (`tls.certificateFile`, or a
custom listener's `certificateFile`) is sent as the file holds it, with a Root
only if the file includes one.

**Console:** **Protocols → TLS / mutual TLS** shows the certificate the main
port presents. **Server configuration → Cryptography**
(`/admin/crypto-metadata`) lists every certificate the service is configured
with.

## Name the listener certificate, or supply your own

### The names in the certificate

The certificate carries `tls.hostnames` as DNS names and `tls.ips` as IP
addresses. Reach the service by one of those names, or a client fails with a
name mismatch. Both are restart-only.

Taken from `tests/docker-compose-run-tests-cluster.yml`, whose nodes sit
behind a load balancer named `sts-lb`:

```bash
docker run --rm -p 8081:8081 \
  -e STS_TLS_HOSTNAMES=sts-lb,localhost,sts,sts2,sts-mock,sts.example.com \
  -e STS_TLS_IPS=127.0.0.1 \
  iyasec/iya-sts
```

### A post-quantum certificate beside the RSA one

`tls.certificateAlgorithms` is `rsa` by default. Name an ML-DSA level as
well, and a client that offers ML-DSA in its handshake gets that certificate
while every other client still gets RSA. Taken from
`tests/pq_key_certification.js`:

```bash
-e STS_TLS_CERT_ALGS=rsa,ml-dsa-65
```

`GET /tls/server-certificate` then returns every certificate. Trust the Root,
which signs both.

### A certificate somebody else issued

Set `tls.certificateFile` and `tls.keyFile` together; one alone stops the
service at startup. The certificate file may be a chain, leaf first. The key
must be unencrypted PKCS#8 or PKCS#1. A supplied certificate is presented as
it is and is never re-issued.

```bash
docker run --rm -p 8081:8081 \
  -v /srv/certs:/run/certs:ro \
  -e STS_TLS_CERT_FILE=/run/certs/sts.pem \
  -e STS_TLS_KEY_FILE=/run/certs/sts.key \
  iyasec/iya-sts
```

No job runs the main port on a supplied file, so the paths above are
examples. A custom listener takes its own files instead (see
[Move the console and the API to a listener of their own](#move-the-console-and-the-api-to-a-listener-of-their-own)).

## Trust a CA for client certificates

The client truststore holds the CAs that a client certificate is verified
against. **It starts empty**: node's public roots are not used. A certificate
that does not verify still completes the handshake, but nothing that reads a
certificate accepts it. The truststore is shared by every listener that asks
for a client certificate and by every realm, and holds at most 32 anchors.

Two kinds of certificate verify without an anchor of yours, because the
service's own Root is in the truststore while `tls.trustIssuedClientCertificates`
is on (the default): a person's TLS client certificate from the portal, and an
application's from its **Credentials** section.

### At runtime

Taken from `sts_tls_connection.js` and `sts_main_port_pooling.js`, which add a
test Root this way and remove it again by its fingerprint.

**Console:**
1. Open **Protocols → Client-certificate truststore**.
2. Under **Add anchors**, paste one or more `-----BEGIN CERTIFICATE-----`
   blocks: the root, or the whole chain above the leaf.
3. Click **Trust these**.
4. To stop trusting one, click **Remove** on its row.

Changing the list needs the Admin Write role.

**API:**
```bash
jq -n --arg c "$(cat my-root-ca.pem)" '{certificates:$c}' |
  curl -sk -X POST "$BASE/admin-api/tls/trust/add" \
    -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
    --data-binary @-

# list them; each row carries fingerprint256
curl -sk "$BASE/admin-api/tls/trust" -H "Authorization: Bearer $TOKEN"

api tls/trust/remove '{"fingerprint":"3F:1A:9C:…:77:B0"}'
```

The add is all or nothing: if any block cannot be read, none is added. A
certificate already held is counted in `duplicates` and not added twice. The
next handshake uses the new list; open connections keep the one they started
with. A runtime anchor is written to the directory (`ou=trustAnchors`), so it
survives a restart wherever the directory is persisted. There is no bulk
clear: remove the rows you mean.

Two anchors with the same subject and different keys are both kept. OpenSSL
looks an issuer up by subject name and may check a certificate against either
of them; which one it finds first is not promised, and can change at a
restart. When their subject key identifiers do not tell them apart (either
has none, or both have the same one), the add's `warning` names both
fingerprints, the service log carries `STS-TLS-0064`, and each row's
`shadowedBy` is the other's fingerprint (the lowest, when several anchors
share the subject). Every anchor a listener verifies against is compared,
including a listener's own trust anchors file and this service's Root.

Presenting either certificate itself still verifies when it is self-signed and
its own extended key usage (`clientAuth`, when it has the extension), key
usage, validity and critical extensions allow a client certificate. A
certificate one of them issued may fail with `CERT_SIGNATURE_FAILURE` while
both are installed. Two anchors whose subject key identifiers differ are a key
rollover: no warning, and both verify.

An anchor that is not self-signed, such as an Intermediate installed without
its Root, or another authority's end-entity certificate installed alone, is
not verified when its holder presents it. Install the authority that issued
it.

### At startup

`tls.trustAnchorsFile` names a PEM file of CA certificates loaded before any
listener binds. It is restart-only, and a file that is missing, unreadable or
empty stops the service. This is the way to fill the truststore from
configuration in product mode. Taken from `tests/ldap_tls_product_mode.js`:

```bash
-v /srv/anchors:/run/anchors:ro -e STS_TLS_TRUST_ANCHORS_FILE=/run/anchors/client-cas.pem
```

An anchor from the file can be removed on the page, but it comes back at the
next start.

## See what the service made of your certificate

`GET /admin-api/tls-connection` describes the request that calls it: the TLS
version and cipher, whether a client certificate was presented and whether it
verified (or OpenSSL's reason if not), its fingerprint and RFC 8705
thumbprint, what the identity gate made of it, its revocation verdict, and
every forwarding header. It changes nothing and starts no session. The console
page is **Monitoring → TLS connection**, which describes the console's own
call to that operation. Taken from `sts_tls_connection.js`:

```bash
curl -s --cacert sts-chain.pem --cert client.pem --key client.key \
  "$BASE/admin-api/tls-connection" -H "Authorization: Bearer $TOKEN" |
  jq .clientCertificate
```

`clientCertificate.presented` and `clientCertificate.verified` are the two
fields to read first. A certificate whose CA you have not added arrives
`presented: true, verified: false`.

## Sign in with a client certificate

`GET /tls/sign-in` on the main port turns a verified client certificate into
a sign-on session, the same session the password screen starts, so the holder
is then signed in to every surface here. The answer is JSON: `signedIn`, the
`session`, whether the certificate was `presented` and `verified`, the
`thumbprint` a token would be bound to, and the `revocation` verdict. The
session carries `amr ["swk"]` and `acr "1"`, or `hwk` (and `sc`) when the
certificate's key is on an attested hardware token or smart card. A browser
that already holds a session keeps it.

The main port **asks** every connection for a client certificate and requires
none, so nothing needs turning on. If you have set
`tls.mainPortDisableOptionalClientCertificate`, this route can never see a
certificate.

### A person's own certificate, from the portal

The certificate is issued from the realm's TLS client CA, names the person
(`CN=<username>` and `urn:sts:person:<username>`, or `urn:sts:sa:<username>`
for a service account) and carries `clientAuth`. It
signs the person in to the realm whose CA issued it. No anchor needs adding.
Taken from `sts_portal_signing_key.js` (the portal) and
`tests/tls_client_certificates.js` (the sign-in).

**Portal:** the person signs in to `/portal/signing-key` and, under **TLS
client certificate**:
1. Optionally names it after the device (the job uses `laptop`), and picks the
   key algorithm. No file password is asked for.
2. Clicks **Generate my TLS client certificate**. The page is drawn again with
   the new certificate's row scrolled into view, and that row carries two
   downloads: **the private key** (`<name>-<label>-tls-client-key.pem`,
   unencrypted PKCS#8) and **the certificate chain**
   (`<name>-<label>-tls-client-chain.pem`, the leaf and the two CAs above it).
   **That is the only time the files can be downloaded.**
3. Presents them from a client that takes a key and a certificate, such as
   `curl --cert <chain> --key <key> https://<host>:8081/tls/sign-in`.

The portal offers no PKCS#12, so a browser cannot import what it hands out. A
certificate for a browser is issued by an administrator, whose issue answers a
password-protected `.p12` (below).

A person may hold at most `pki.personTlsClientCertificateMax` valid ones (5 by
default). The person can revoke one with **Revoke** on the same page; after
that it signs nobody in.

### A PIV smart card's certificate

A certificate for a key generated on a YubiKey's PIV applet is enrolled with
the card's attestation, on the portal's **Tokens and keys → PIV** tab or over
EST, from the realm's EST Issuing CA; like a portal certificate, it needs no
anchor added. The card is then recorded as a hardware token, and a sign-in
with it records `hwk` and `sc`. Enrolling it, what the attestation must
carry and the clients it is used with (OpenSC, `curl` with a `pkcs11:` key)
are in [Hardware tokens](hardware-tokens.md#piv-key-attestation); the
`curl` line is in [TLS](tls.md#signing-in-with-a-certificate-get-tlssign-in).
A government PIV or CAC card from somebody else's CA is under
[Smart-card and certificate sign-in](#smart-card-and-certificate-sign-in).

### A certificate from your own CA

Taken from `sts_main_port_pooling.js`, which mints a Root, an Issuing CA and a
leaf `CN=pooling-<stamp>,O=iya-sts tests`, and signs it in.

1. Create the person the certificate is to sign in, in both modes. The
   certificate's common name is not read: the entry can be called anything.
   ```bash
   api users/create '{"username":"pooling-1","invent":false,"credential":"generate",
     "attributes":{"givenName":"Pooling","sn":"pooling-1","mail":"pooling-1@pooling.test"}}'
   ```
2. Store the leaf on that entry, byte for byte. Only the leaf: its authority
   goes in the truststore in the next step. In the console this is **Users →**
   the person **→ Stored certificates**.
   ```bash
   api users/add-certificate "$(jq -n --rawfile pem pooling-1.pem \
     '{user:"pooling-1", certificate:$pem}')"
   ```
   A certificate stored on no entry, or on more than one, signs nobody in
   (`STS-TLS-0054`, `STS-TLS-0055`), and a renewed certificate is stored
   again. [TLS](tls.md#a-certificate-from-an-outside-certificate-authority)
   has the whole rule.
3. Add your Root to the truststore, as in
   [Trust a CA for client certificates](#trust-a-ca-for-client-certificates).
   In product mode the certificates must name a CRL or OCSP responder the
   service can reach (the job serves a CRL for its CA).
4. Present the certificate:
   ```bash
   curl -s --cacert sts-chain.pem --cert pooling-1.pem --key pooling-1.key \
     -c cookies.txt "$BASE/tls/sign-in" | jq '{signedIn, clientCertificate}'
   ```

The cookie jar now holds the `sts_session` cookie. A certificate from an
anchor you added signs in to the realm of the request (`/realm/<id>/tls/sign-in`
for another realm, whose entry must then store it) as the person whose entry
stores it.

### On the sign-in screen

The certificate is also offered on the sign-in screen that every browser
protocol sends people to. Present it to the main port (choose it when the
browser asks) and, wherever an application sends you to sign in, the screen
shows **Continue as *name* with your certificate** above the emailed-code
buttons. Pressing it signs you in with the certificate and returns you to the
application, after a second factor if the request or your account needs two.

The button appears only when:

* the certificate verified and names a **person** in the realm the sign-in is
  for: one this realm's CA issued to them, or one from an outside authority
  stored on their entry (`STS-AUTHN-0468` when it is stored on no entry,
  `STS-AUTHN-0469` on more than one). A certificate from another realm's CA
  is not offered there;
* the realm's authentication policy (**Directory → Policies**,
  **Authentication policy** tab, or `GET /admin-api/policies`) has **TLS
  client certificate — as a first factor** on, which it is by default;
* the application does not restrict sign-in mechanisms (the [named
  authentication policy](authentication.md#named-authentication-policies)
  it names in `appAuthnPolicy` lists none): a certificate is not one of the
  mechanisms a policy can list;
* the sign-in is not linking a federated account, and no security key or
  passkey is demanded.

The button is a convenience, not the check: the service checks the
certificate again when it is pressed, including its revocation. A refusal
is shown on the screen and recorded under `STS-AUTHN-0463` to
`STS-AUTHN-0469` ([error codes](error-codes.md)). The button's operation is
`POST /authn-api/pending/{id}/certificate`.

### What signs nobody in

* **An application's TLS client certificate.** It authenticates the
  application at the token endpoint (RFC 8705) and is answered with
  `session.application`, not a session.
* **Any other certificate this service issued that is not a TLS client
  certificate**, such as an RFC 7523 signing key. It chains to the same Root,
  and is answered with `refusedAsIdentity`.
* **A revoked certificate**, answered with `refusedOnRevocation`, stored on
  an entry or not.
* **A certificate from an outside authority stored on no entry, or on more
  than one**, answered with `refusedAsStored` (`NOT_STORED` or
  `STORED_TWICE`). Its common name and subject are never read, unless a
  [certificate sign-in profile](#smart-card-and-certificate-sign-in) covers
  it and the administrator opted in to a name.
* **A certificate a profile covers that is outside it, or whose bindings name
  nobody or more than one account**, answered the same way (below).

## Smart-card and certificate sign-in

A person can sign in with a client certificate from an authority this service
does not run: a federal PIV card, a CAC, an enterprise smart card, or a
software certificate from your own CA. Storing each certificate on its entry
(above) works for a few people. For a whole population, give the realm a
**certificate sign-in profile** for the CA. It says what a certificate from
that CA must carry, and how the service finds the one account it belongs to
without anybody storing the certificate.

Everything here is off or empty by default, and then the service behaves as
the sections above describe. The logic is held by `tests/certificate_binding.js`,
in process, over certificates it makes at run time. No test job yet drives a
physical card, the handoff over two real listeners, or a real proxy.

### What decides a certificate

Every door that reads a certificate as a person asks the same question:
`GET /tls/sign-in`, the sign-in screen, the certificate handoff below, SCIM,
the XACML gates, Shared Signals, WS-Trust and LDAP SASL EXTERNAL. The answer
comes from the first of these that applies:

1. **A profile covers it** when one of the profile's `issuers` is in the
   certificate's validated path, above the leaf: the chain the handshake built
   to an anchor of the client truststore. The first such profile in the list
   decides, and the older mappings below are never asked.
2. **No profile covers it**: the certificate stored in `userCertificate` on
   exactly one entry, or, for a card from a CA in `piv.externalIssuers`, the
   card UUID in `stsPivCardUuid`
   ([Hardware tokens](hardware-tokens.md#outside-piv-and-cac-cards)).

A profile does not replace verification. The certificate must still chain to
the [client truststore](#trust-a-ca-for-client-certificates) and pass the
revocation check.

### The members of a profile

`certSignIn.profiles` is a JSON array of profiles, set per realm. It holds at
most 32 profiles, and each list in a profile at most 32 values.

| Member | Required | What it is |
|---|---|---|
| `id` | yes | Lower-case letters, digits and hyphens, at most 64; unique in the array. It appears in the log and in every refusal. |
| `issuers` | yes | The CAs the profile covers: the SHA-256 of each CA's DER SubjectPublicKeyInfo, 64 hexadecimal digits (colons and a `sha256:` prefix are accepted). Because it names the CA's **key**, a CA certificate renewed under the same key is still covered. Name a root, and every CA under it is covered. Only a CA whose signature over the certificate below it verifies counts: a certificate a client merely sends along does not. This service's own CAs are refused here, since the certificates they issue are identities by their own rules. |
| `keyUsage` | no | keyUsage bits the leaf must **all** carry: `digitalSignature`, `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly`. |
| `extendedKeyUsage` | no | Purposes as dotted OIDs, **one** of which the leaf must carry, such as `1.3.6.1.5.5.7.3.2` (clientAuth). |
| `policies` | no | Certificate policies as dotted OIDs. RFC 5280 section 6.1 policy processing runs over the validated path with these as the initial policy set and an explicit policy required, so the path must carry one of them down to the leaf. Policy mappings are honoured: an agency policy mapped to one of these through a bridge counts. |
| `bindings` | no | The methods that say which account the certificate is (below). Default `["certificate-sha256", "issuer-serial"]`. |
| `lowAffinity` | no | `true` lets `bindings` name a low-affinity (name) method. Without it, a name method is refused when the setting is written. |
| `description` | no | Free text, at most 500 characters. |

A write that is not a well-formed array is refused with `STS-TLS-0065` and a
sentence naming the profile and the member. A stored value that is not
well-formed is logged under the same code and covers nothing.

### Binding methods

**High-affinity** methods are tied to one certificate or one key:

| Method | Matches | Where the value lives |
|---|---|---|
| `certificate-sha256` | The leaf itself, byte for byte | The certificate in `userCertificate` (**Users →** the person **→ Stored certificates**, as above), or its SHA-256 in `stsCertificateBinding` |
| `issuer-serial` | The issuing CA and the leaf's serial number | `stsCertificateBinding` |
| `issuer-ski` | The issuing CA and the leaf's subjectKeyIdentifier. A leaf without one matches nobody | `stsCertificateBinding` |
| `spki-sha256` | The leaf's public key | `stsCertificateBinding` |
| `card-uuid` | The FIPS 201 card UUID: the one `urn:uuid:` URI in the leaf's subjectAltName | `stsPivCardUuid` |

**Low-affinity** methods match a name, which another certificate can carry too.
They are accepted only on a profile with `"lowAffinity": true`:

| Method | Matches | Where the value lives |
|---|---|---|
| `upn` | The one UPN in the leaf's subjectAltName, ignoring case | The person's `userPrincipalName` |
| `email` | The one rfc822Name in the leaf's subjectAltName | The person's `mail` |
| `issuer-subject` | The issuing CA and the leaf's subject DN | `stsCertificateBinding` |
| `subject` | The leaf's subject DN alone | `stsCertificateBinding` |

"The issuing CA" is the CA that signed the leaf, named by the SHA-256 of its
SubjectPublicKeyInfo, exactly as in `issuers`. For a federal card that is the
agency's issuing CA, not the root the profile names.

**Every method in `bindings` is asked, and the ones that find somebody must
agree.** The certificate signs in the one person they all found. It signs
nobody in when:

* no method finds anybody, or only a name does where the profile names a
  high-affinity method too (`STS-TLS-0068` in the log; the door answers
  `NOT_STORED`: `STS-TLS-0054` at `/tls/sign-in`, `STS-AUTHN-0468` on the
  screen);
* one method finds two people, or two methods find different people
  (`STS-TLS-0067`; the door answers `STORED_TWICE`: `STS-TLS-0055`,
  `STS-AUTHN-0469`);
* the leaf is outside its profile: a keyUsage bit missing, none of the listed
  extendedKeyUsage purposes, or a path that does not carry a listed policy
  (`STS-TLS-0066`; answered as `NOT_STORED`).

A failed high-affinity match never falls back to a name. A profile without
`lowAffinity` has no name method to fall back to.

### Example: federal PIV cards

PIV Authentication certificates from any agency whose CA chains to the
Federal Common Policy CA G2, under `id-fpki-common-authentication`, bound by
issuer and serial or by the card UUID:

```json
[{
  "id": "fpki-piv",
  "description": "PIV Authentication certificates under the Federal Common Policy",
  "issuers": ["<SHA-256 of the Federal Common Policy CA G2's SubjectPublicKeyInfo>"],
  "keyUsage": ["digitalSignature"],
  "policies": ["2.16.840.1.101.3.2.1.3.13"],
  "bindings": ["issuer-serial", "card-uuid"]
}]
```

Because the policy is checked over the whole path with mappings honoured, an
agency CA that reaches the root through a bridge and maps its own policy to
`id-fpki-common-authentication` is accepted. `piv.externalIssuers` cannot do
that: it accepts only cards a listed CA issued directly. A PIV-I card
(`2.16.840.1.101.3.2.1.3.18`, `id-fpki-certpcy-pivi-hardware`) is outside
this profile; add that OID to `policies` to take it as well.

Add the Federal Common Policy root to the client truststore, and the
intermediate CAs between it and the cards that the browsers do not send with
the certificate. The truststore holds at most 32 anchors.

### Example: an enterprise CA

Smart-card certificates from your own issuing CA, bound by key, so a renewal
on the same card needs nothing recorded again:

```json
[{
  "id": "corp-smartcard",
  "issuers": ["<SHA-256 of Example Corp Issuing CA 1's SubjectPublicKeyInfo>"],
  "keyUsage": ["digitalSignature"],
  "extendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
  "bindings": ["spki-sha256", "issuer-serial"]
}]
```

Several profiles go in one array. The first one whose `issuers` match decides,
so list a narrower profile (an issuing CA) before a wider one (its root).

### Setting the profiles

The setting is read at every sign-in, so no restart is needed. Set it in the
realm the people sign in to (`/realm/<id>/admin-api/...` for a realm other
than the default).

**In the console** it is in the *Certificate sign-in* settings group, on
**Protocols → PIV** and on the **Certificate sign-in** tab of **Server
configuration → Listeners**, drawn as a form, one card per profile:

* **Id** and **Description**.
* **Issuers**: pick a CA from the client truststore, which the page lists by
  subject with its SubjectPublicKeyInfo SHA-256 computed by the service;
  paste a hash; or paste or choose a CA's certificate and **Read and add**,
  which adds each CA certificate in it by its digest. A CA that is not in the
  truststore (an intermediate the card sends) is added the second or third
  way.
* **Key usage**, one box per bit; **Extended key usage**, boxes for TLS client
  authentication (`1.3.6.1.5.5.7.3.2`), Microsoft smart card logon
  (`1.3.6.1.4.1.311.20.2.2`) and the Kerberos PKINIT client
  (`1.3.6.1.5.2.3.4`), and any other OID typed in; **Certificate policies**, a
  box for `id-fpki-common-authentication` (`2.16.840.1.101.3.2.1.3.13`, PIV
  Authentication) and any other OID typed in.
* **Bindings** in two groups: high affinity, and low affinity, whose boxes
  stay disabled until **Accept a name method (lowAffinity)** is ticked;
  unticking it takes the name methods out. A profile that never set its
  bindings shows the default ticked and keeps it unwritten until a box is
  changed.
* **The certificates it covers are smart cards**, the `smartCard` member.
* **Move up**, **Move down**, **Remove** and **Add a profile**: the first
  profile naming a CA in a certificate's path covers it.

The form writes the same JSON the setting always held into the box under
**As JSON**, which can still be edited by hand, and **Save** posts it through
the same `config/set-many` operation, so the same rule (`STS-TLS-0065`)
judges it. A profile written by hand comes back from the form unchanged,
members and order alike; a value the form cannot show is left to the box,
with the reason. With the API, keep the array in a file and send it as a
string:

```bash
api config/set "$(jq -n --arg v "$(jq -c . profiles.json)" \
  '{key:"certSignIn.profiles", value:$v}')"
api config/reset '{"key":"certSignIn.profiles"}'   # back to empty: no profile
```

### Working out the values

The console works out the three values a binding on a person most often
needs, and a CA's digest for `issuers`, from the certificate itself (above,
and [Recording a binding on a person](#recording-a-binding-on-a-person)).
By hand, every hexadecimal value may be written with or without colons, in
either case.

```bash
# A CA's SubjectPublicKeyInfo SHA-256: for "issuers", and the issuer part of
# issuer-serial, issuer-ski and issuer-subject.
openssl x509 -in ca.pem -pubkey -noout | openssl pkey -pubin -outform der |
  openssl dgst -sha256 -r | cut -d' ' -f1

# The same for the leaf's own key: spki-sha256.
openssl x509 -in card.pem -pubkey -noout | openssl pkey -pubin -outform der |
  openssl dgst -sha256 -r | cut -d' ' -f1

# The leaf's serial number: issuer-serial. Prints serial=<hex>.
openssl x509 -in card.pem -noout -serial

# The leaf's subjectKeyIdentifier: issuer-ski.
openssl x509 -in card.pem -noout -ext subjectKeyIdentifier

# The leaf's subject DN, most specific RDN first: issuer-subject and subject.
openssl x509 -in card.pem -noout -subject -nameopt RFC2253

# The leaf's own SHA-256, what certificate-sha256 matches.
openssl x509 -in card.pem -outform der | openssl dgst -sha256 -r | cut -d' ' -f1
```

To get a card's certificate, export its PIV Authentication certificate
(slot 9a) with your card middleware. The card UUID is the `urn:uuid:` URI
among its subjectAltNames
(`openssl x509 -in card.pem -noout -ext subjectAltName`).

### Recording a binding on a person

A value of `stsCertificateBinding` is one binding, in one of these forms:

```text
certificate-sha256:<the leaf's SHA-256>
issuer-serial:<issuing CA's SPKI SHA-256>:<serial, hex>
issuer-ski:<issuing CA's SPKI SHA-256>:<subjectKeyIdentifier, hex>
spki-sha256:<the leaf key's SPKI SHA-256>
issuer-subject:<issuing CA's SPKI SHA-256>:<subject DN>
subject:<subject DN>
```

Every write stores a value in one form: the method lower-cased, hexadecimal
lower-cased without colons, a serial without leading zeros, and a DN
lower-cased with the spaces around `=`, `,` and `+` removed. The colon
separates the parts, so write the issuer's digest without colons; a serial
and a subjectKeyIdentifier may keep them. So
`ISSUER-SERIAL:3B1F…9C0A:00:4F:2A:19` is stored as
`issuer-serial:3b1f…9c0a:4f2a19`. A person may hold several values, one per
card or certificate.

A subject with a **multi-valued RDN**, such as `UID=12345+CN=SMITH.JANE`, may
be written with its attributes in any order: an RDN is a set, so
`CN=SMITH.JANE+UID=12345` is the same value. Copy what `openssl -nameopt
RFC2253` prints and it matches.

A value is removed by the same text it was added with, in any of these
spellings: `users/remove-attribute` puts it in the stored form before it
looks for it, and adding a value already held in another spelling is
refused as already held.

* **Console:** **Directory → Users →** the person **→ Credentials →
  Certificate sign-in** lists the values held, each with **Remove**. Under
  *From the person's certificate*, paste or choose the person's certificate
  (followed by its issuing CA's, when that CA is not in the client
  truststore) and **Derive the bindings**: the service reads it and answers
  `spki-sha256`, `issuer-serial` and `issuer-ski`, each with **Add**, which is
  `users/add-attribute`. Without the issuer only `spki-sha256` is derived.
  The *Certificate sign-in bindings* field on **→ Attributes** still takes
  any value typed in.
* **API:**
  ```bash
  api users/add-attribute '{"user":"alice","attribute":"stsCertificateBinding",
    "value":"issuer-serial:3b1f…9c0a:4f2a19"}'
  api users/remove-attribute '{"user":"alice","attribute":"stsCertificateBinding",
    "value":"issuer-serial:3b1f…9c0a:4f2a19"}'
  ```
* **LDAP, SCIM or a bulk import**, as any attribute of the person.

A card UUID goes in `stsPivCardUuid`, as
[Hardware tokens](hardware-tokens.md#outside-piv-and-cac-cards) describes; a
`certificate-sha256` binding is the certificate itself, on **Stored
certificates**. `upn` and `email` read the person's `userPrincipalName` and
`mail`, so nothing is recorded for them.

Every write refuses a value in none of the forms above (`STS-TLS-0069`) and
one another entry of the realm already holds (`STS-TLS-0070`), so one binding
cannot name two people. Only an administrator writes the attribute: a person
cannot set it on the portal, because a person who could would choose whose
certificate signs them in. The holder of a value is found through an index, so
a sign-in costs the same with a million people as with ten.

### When a certificate is renewed

| Method | New certificate, same key | New key or new card | The CA re-keys |
|---|---|---|---|
| `certificate-sha256` | store the new certificate | store the new certificate | store the new certificate |
| `issuer-serial` | record the new serial | record the new serial | record it again with the new CA key |
| `issuer-ski` | nothing, where the CA derives the identifier from the key (the usual practice); otherwise record it | record the new identifier | record it again with the new CA key |
| `spki-sha256` | nothing | record the new key | nothing |
| `card-uuid` | nothing | a new card: record its UUID | nothing |
| `upn`, `email` | nothing, while the name is the same | nothing, while the name is the same | nothing |
| `issuer-subject` | nothing, while the subject is the same | nothing, while the subject is the same | record it again with the new CA key |
| `subject` | nothing, while the subject is the same | nothing, while the subject is the same | nothing |

A CA certificate renewed under the **same key** changes nothing, because the
CA is named by its key. A CA that **re-keys** is a new issuer: add its key to
the profile's `issuers` beside the old one while certificates from both are in
use. Old bindings can stay on the entry until their certificates expire.

### Low affinity: what you accept by opting in

A name method trusts the CA to have written the right name, and trusts every
CA the profile covers equally. With `"lowAffinity": true`:

* **Any CA under the profile's `issuers` can sign anybody in**, by writing
  their UPN, address or subject into a certificate. A profile that names a
  root or a bridge covers every CA under it. Name the issuing CAs you trust to
  assign those names, not the root above them.
* **A name is never a fallback.** On a profile that also names a
  high-affinity method, a certificate that only a name matches signs nobody
  in: the names then only corroborate the high-affinity match, and a name
  naming somebody else is still a disagreement. A name signs a certificate in
  by itself only on a profile whose `bindings` are names alone.
* **`upn`, `email` and `subject` are not issuer-scoped.** They match the name
  wherever in the directory it is held, whichever covered CA wrote it; use
  `issuer-subject` to tie a subject to one CA.
* **`email` trusts `mail` as written.** The directory does not prove that a
  person controls the address in their `mail`, so an administrator or a sync
  that writes `mail` decides who an `email` binding signs in.
* **`upn` waits for the index.** On a store kept in a database, a
  `userPrincipalName` written before this version is indexed by a one-time
  background walk; until it finishes, the `upn` method matches nobody.
* **The directory decides who a name is.** Changing a person's `mail` or
  `userPrincipalName` changes which certificates sign them in, and so does
  giving that name to somebody else. An address two people hold signs nobody
  in.
* **A subject DN is compared as text**, case and spacing aside. A CA that
  re-orders or re-encodes the DN in a renewal breaks the binding.

Prefer a high-affinity method. Where a name is the only thing that ties your
certificates to your accounts, keep the profile's `issuers` to the CAs that
assign those names.

### Require a verified revocation status

`certSignIn.requireRevocation` decides whether a certificate sign-in needs a
**verified** revocation status: every certificate in the path looked up, and
none on a list.

| Value | Development | Product |
|---|---|---|
| `auto` (default) | as `pki.revocationCheck` says | required |
| `on` | required | required |

Where it is required, a status that could not be established, or a check that
was not made (`pki.revocationCheck` off), refuses the sign-in where soft-fail
would have accepted it: `STS-TLS-0071` at `/tls/sign-in`, `STS-AUTHN-0464` on
the screen. A revoked certificate is refused either way. It applies to
sign-ins only (`/tls/sign-in`, the screen and the handoff); RFC 8705 and the
other doors keep `pki.revocationCheck`. The CRLs and OCSP responders the
certificates name must be reachable from the service, and the first sign-in
waits on the fetch (`pki.revocationFetchTimeoutMs`).

```bash
api config/set '{"key":"certSignIn.requireRevocation","value":"on"}'
```

### A listener of its own for the card (the handoff)

When the sign-in screen's listener asks every connection for a certificate,
a browser with a card in the reader asks for it, and for its PIN, whoever came
to type a password. The **handoff** moves that question to one request, on a
listener of its own:

1. With `certSignIn.handoff` on, the screen shows **Sign in with a smart card
   or certificate**. It links to `/authn/certificate/continue` on the listener
   the `certificate-sign-in` hosted application is mapped to.
2. There the browser asks for the certificate and the PIN, and the service
   checks the certificate exactly as the screen does: revocation, the realm's
   requirement, every profile.
3. The browser comes back to the screen, which offers **Continue as *name*
   with your certificate**. The sign-in goes on as it would for a certificate
   on the screen's own connection: the authentication policy, then a second
   factor where one is needed.

**Set it up** on **Server configuration → Listeners → Custom listeners**, or
with the API:

```bash
# A listener that asks for a certificate, on the main port's host name.
api listeners/set-listeners '{"value":[{"id":"smartcard","port":8443,
  "publicBaseUrl":"https://sts.example.com:8443","clientAuth":"optional"}]}'

# The handoff path, and only it, on that listener.
api listeners/set-applications '{"value":{
  "certificate-sign-in":{"listeners":["smartcard"]}}}'

api config/set '{"key":"certSignIn.handoff","value":true}'

# Optional: the main port stops asking anybody for a certificate.
api config/set '{"key":"tls.mainPortDisableOptionalClientCertificate","value":true}'
```

`clientAuth` may be `optional` or `required`. With `optional`, a browser that
presents nothing comes back to the screen, which says why. With `required`,
it gets the browser's own TLS error instead. Turning off the main port's
question also stops RFC 8705, `GET /tls/sign-in`, EST with a certificate and
the remote XACML PEP there
([Require a client certificate, or stop asking for one](#require-a-client-certificate-or-stop-asking-for-one)).
Move those to a listener that asks, or leave the main port asking.

**The sign-on session cookie must reach the listener.** The certificate is
bound to the pending sign-in and to the browser's `sts_session` cookie on both
legs, so a link sent to somebody else cannot attach their certificate to the
sender's sign-in. Give the listener the main port's host name on another port,
as above: the cookie is host-only, and ports on one host name share it. A
listener on another host name needs `authn.cookieDomain` to name a domain both
are under, and a mapping that breaks this is refused (`STS-CORE-0155`). Read
[The sign-on session across host names](listeners.md#the-sign-on-session-across-host-names)
first.

A handoff lasts five minutes and is used once. An expired, used or unknown
one, or any one while `certSignIn.handoff` is off, is answered 400
(`STS-TLS-0074`). One arriving without the starting browser's cookie is
answered 403 (`STS-TLS-0075`). The person starts again from the screen.

### A TLS-terminating proxy in front of certificate sign-in

Where a proxy terminates TLS, the service never sees the client's handshake.
It can still read the certificate the proxy received, as RFC 9440's
`Client-Cert` header (and `Client-Cert-Chain` for the certificates the client
sent with it), but only from a proxy named by **both** of these:

* `tls.trustedProxyCertificates`: the SHA-256 fingerprint of the client
  certificate the **proxy** presents when it connects to the service
  (`openssl x509 -in proxy.pem -noout -fingerprint -sha256`; colons and a
  `sha256:` prefix are accepted). Such a pin stops matching when the proxy's
  certificate is renewed. To pin the proxy's **key** instead, write `spki:`
  and the SHA-256 of its SubjectPublicKeyInfo in the same hex form; a
  certificate renewed under the same key still matches:

  ```bash
  openssl x509 -in proxy.pem -noout -pubkey | openssl pkey -pubin \
    -outform DER | openssl dgst -sha256 -hex    # write as spki:<that hex>
  ```

  Both kinds may be listed together. An entry that is neither is refused
  when it is written (`STS-TLS-0077`);
* `tls.trustedProxyAddresses`: the addresses or CIDR ranges it connects from.

```bash
api config/set-many '{"tls.trustedProxyCertificates":"5d:41:…:c2:9a",
  "tls.trustedProxyAddresses":"10.20.0.0/24"}'
```

What the service does with it:

* **The proxy's own certificate must verify** against the client truststore,
  so add its CA there. The listener the proxy connects to must ask for a
  certificate. The main port does unless
  `tls.mainPortDisableOptionalClientCertificate` is on; with it on (as with
  the certificate handoff above), give the proxy a custom listener of its own
  whose `clientAuth` is `optional` or `required`, and map to it the
  applications the proxy serves.
* **The forwarded certificate is verified here** as the listener the proxy
  reached verifies a handshake's: to that listener's client truststore with
  every path rule, as a TLS client certificate (its keyUsage and an
  extendedKeyUsage of clientAuth where it has one), on a NIST curve where its
  key is EC, and under paranoid PKI mode with the fields a handshake is held
  to. Revocation, the profiles and the identity rules then
  apply to it exactly as to a handshake's certificate, at every door.
* **A request from the proxy with no `Client-Cert`, or with one that does not
  verify, presents no certificate** (`STS-TLS-0073` in the log for the
  second). The proxy's own certificate never signs anybody in.
* **From any other sender both headers are removed** before anything reads
  them, and that is recorded (`STS-TLS-0072`, at most once a minute).
* **One setting without the other trusts no proxy** (`STS-TLS-0076` in the
  log).

The headers are RFC 8941 byte sequences: `Client-Cert: :<base64 DER>:`, and
`Client-Cert-Chain` a comma-separated list of them, at most eight
certificates and 32 KB a header.

**What the proxy must do**, because the service believes it:

* remove any `Client-Cert` and `Client-Cert-Chain` a client sends, and set
  them only from the TLS connection it terminated (RFC 9440's processing
  rules);
* send them only to this service, over its own mutual TLS connection;
* keep its client certificate's key as safe as a CA key: anybody holding it,
  from inside the trusted range, can present any certificate the truststore
  accepts.

Keep `tls.trustedProxyAddresses` to the proxy's own addresses. A proxy that
terminates TLS is also where `global.trustProxy` and `global.trustedProxies`
come in, for `X-Forwarded-*`
([TLS → Reverse proxies and load balancers](tls.md#reverse-proxies-and-load-balancers)).
They are separate settings, and neither implies the other.

## RFC 8705 `tls_client_auth`: the TLS side

The OAuth side (the application's `oauthTokenEndpointAuthMethod` and the
token request) is in
[Configuring OAuth 2.0 grants → Client authentication methods](configure-oauth2-grants.md#client-authentication-methods).
On the TLS side there are two cases. Taken from `tests/rfc8705_mtls.js`.

**A certificate this service issues to the application** needs nothing on the
TLS side. It is issued from the realm's TLS client CA with
`urn:sts:application:<identifier>` in its subjectAltName, which is the
implicit mapping, and the service's Root already verifies it.

* Console: on the application's page, **Credentials → Mutual TLS (RFC 8705) →
  Issue a TLS client certificate from this realm's CA**.
* API:
  ```bash
  api applications/issue-tls-client-certificate '{"application":"mtls-impl",
    "password":"correct horse battery","keyAlg":"ec-p256"}'
  ```
  The reply's `files` (a PKCS#12, an encrypted PEM key and the PEM chain,
  all protected by `password`) is the only copy of the private key. The key
  algorithms are `rsa-2048`, `rsa-3072`, `ec-p256` and `ec-p384`. An
  application holds at most `pki.applicationTlsClientCertificateMax` (5)
  valid ones. `applications/revoke-tls-client-certificate` with
  `{application, serialHex}` revokes one.

**A certificate from your own CA** needs two things:
1. **Its CA in the client truststore**, as in
   [Trust a CA for client certificates](#trust-a-ca-for-client-certificates).
   The job adds its `CN=RFC 8705 Test Foreign CA`. Without it the certificate
   arrives unverified and the client is refused.
2. **Exactly one subject parameter on the application**, which the
   certificate must match. The job's certificate is
   `C=US, O=Example Corp, Inc., CN=ext-client`, with these subjectAltNames, and
   each row authenticates:

| Attribute | Value the job registers |
|---|---|
| `oauthTlsClientAuthSubjectDn` | `cn=EXT-CLIENT, o=Example Corp\, Inc., c=US` (compared as a name, so case and spacing do not matter) |
| `oauthTlsClientAuthSanDns` | `ext.example.com` |
| `oauthTlsClientAuthSanUri` | `https://client.example.com/id` |
| `oauthTlsClientAuthSanIp` | `2001:db8::7` |
| `oauthTlsClientAuthSanEmail` | `Ops@example.com` |

```bash
api applications/create '{"identifier":"mtls-dns","name":"mtls-dns",
  "protocols":["oauth2"],
  "fields":{"oauthClientId":"mtls-dns",
            "oauthTokenEndpointAuthMethod":"tls_client_auth",
            "oauthTlsClientAuthSanDns":"ext.example.com"}}'
```

`self_signed_tls_client_auth` needs no anchor: the certificate is matched by
the application's `oauthJwks` (`x5c`) or `oauthTlsClientCertificateThumbprint`.

A token issued on a connection that carried a client certificate is bound to
it (`cnf["x5t#S256"]`), whichever way the client authenticated.

## Require a client certificate, or stop asking for one

Each built-in TLS listener has two toggles: do not ask for a client
certificate, and require one. "Require" wins. A required certificate must
chain to the client truststore, or the handshake is refused. Taken from
`tests/listener_tls_policy.js`, section E.

| Listener | Do not ask | Require | Defaults |
|---|---|---|---|
| Main port | `tls.mainPortDisableOptionalClientCertificate` | `tls.mainPortRequireClientCertificate` | off / off |
| LDAPS | `ldap.ldapsDisableOptionalClientCertificate` | `ldap.ldapsRequireClientCertificate` | **on** / off |
| Protocol debugger | `debugger.disableOptionalClientCertificate` | `debugger.requireClientCertificate` | off / off |

**Console:** **Server configuration → Listeners**, the listener's tab (for
example **Main port**), then **Save Listener: Main port**.

**API:**
```bash
api config/set '{"key":"tls.mainPortRequireClientCertificate","value":true}'
api config/reset '{"key":"tls.mainPortRequireClientCertificate"}'
```

> **Warning.** Requiring a certificate on the main port refuses every browser
> without one, discovery, the JWKS and every public document, and a load
> balancer's HTTPS health check. Turning off "ask" on the main port stops RFC
> 8705, `GET /tls/sign-in`, EST with a certificate and the remote XACML PEP
> there. To require certificates for some applications only, give them a
> custom listener with `"clientAuth": "required"` instead (below).

The same tabs hold each listener's TLS policy: `tls.disableTls12` (on by
default, so TLS 1.3 only), the TLS 1.3 suites (`tls.tls13CipherSuites`) and
`tls.pqcOnly`. A row named `listener<Id>.<setting>`, such as
`listenerLdaps.disableTls12`, decides for one listener; `inherit` follows the
service-wide value on the **Service-wide defaults** tab. The same job sets
them like this:

```bash
api config/set '{"key":"tls.disableTls12","value":false}'   # allow TLS 1.2 again
api config/set '{"key":"tls.tls13CipherSuites","value":"TLS_AES_128_GCM_SHA256"}'
api config/set '{"key":"tls.pqcOnly","value":true}'
```

[TLS and mutual TLS → The listeners](tls.md#the-listeners-tls-12-the-tls-13-suites-post-quantum-only-client-certificates)
says what each setting does and which combinations are refused.

## HTTP/2

Every HTTPS listener offers HTTP/2 and HTTP/1.1, and the client chooses in the
handshake (ALPN). It is on by default. Turn it off for a client or balancer
whose HTTP/2 misbehaves. A new connection follows the change at once; an open
one keeps the protocol it chose. Taken from `tests/main_port_http2.js`,
section 6.

**Console:** **Server configuration → Listeners → Service-wide defaults**,
**Offer HTTP/2**, then **Save HTTP connections**. One listener's own row (for
example **Main port: offer HTTP/2**, `inherit`, `on` or `off`) is on its tab.

**API:**
```bash
api config/set '{"key":"http.http2","value":false}'          # every listener
api config/set '{"key":"listenerMain.http2","value":"on"}'   # but the main port keeps it
```

A custom listener takes `"tls": {"http2": "off"}` in its definition
(`"on"`, `"true"` and `"false"`, or the JSON `true` and `false`, work as
well; `tests/main_port_http2.js` section 11). To check
what a connection negotiated:

```bash
curl -s --cacert sts-chain.pem --http2 -o /dev/null -w '%{http_version}\n' "$BASE/healthcheck"
```

`2` is HTTP/2; `1.1` is HTTP/1.1. One HTTP/2 connection may have at most
`http.http2MaxConcurrentStreams` (100) requests open at once. Each TLS
listener's tab on **Server configuration → Listeners** shows that cap beside
**HTTP/2 offered**, and `GET /admin-api/listeners` answers it as each
listener's `http.http2MaxConcurrentStreams` (`tests/main_port_http2.js` section
15).

A `CONNECT` request is answered `501 Not Implemented` over either protocol:
this service is not a proxy (section 13). `OPTIONS *` is answered `204` by
the process that holds the listener, never by a request worker (section 14).

## Move the console and the API to a listener of their own

A custom listener is another HTTPS port, bound on every node, that answers
only the hosted applications mapped to it. This recipe puts the console
(`admin-console`) and the Management API (`management-api`) on a listener of
their own, so the main port no longer answers them. Taken from
`tests/custom_listeners.js`, which uses the listener `adm` on
`admin.example.test`.

**Console:**
1. Open **Server configuration → Listeners → Custom listeners**.
2. In the first box (**The listener definition**), enter the listeners as a
   JSON array, and click **Save the listeners**:
   ```json
   [{ "id": "adm", "port": 9443,
      "publicBaseUrl": "https://admin.example.test:9443",
      "certificateFile": "/run/certs/admin.pem",
      "privateKeyFile": "/run/certs/admin.key" }]
   ```
3. In the second box (**The mapping**), enter the mapping and click **Save the
   mapping**:
   ```json
   { "admin-console":  { "listeners": ["adm"] },
     "management-api": { "listeners": ["adm"] } }
   ```
   If you are using the console through the main port, this takes the API off
   the listener you are on. Tick **Take the management API off the listener
   this page was reached on** to confirm, then continue on the new listener.

**API:**
```bash
api listeners/set-listeners '{"value":[{"id":"adm","port":9443,
  "publicBaseUrl":"https://admin.example.test:9443",
  "certificateFile":"/run/certs/admin.pem","privateKeyFile":"/run/certs/admin.key"}]}'

api listeners/set-applications '{"value":{
  "admin-console":{"listeners":["adm"]},
  "management-api":{"listeners":["adm"]}},"confirm":true}'

curl -sk "$BASE/admin-api/listeners" -H "Authorization: Bearer $TOKEN"
```

The job generates its certificate and port at run time; `9443` and the file
paths above are examples. What to know:

* **Leave out the two files** and the realm's CA issues a certificate for
  `hostnames` (the host of `publicBaseUrl` when that is left out), and renews
  it. A client must trust the service's Root to accept it. For a listener
  browsers reach, supply a public CA's certificate.
* **`clientAuth`** is `optional` by default, as on the main port. `required`
  refuses a handshake without a certificate that chains to the client
  truststore, and `none` sends no certificate request. The API's own example
  is `{"id":"admin","port":9443,"publicBaseUrl":"https://admin.example.com:9443","clientAuth":"required"}`.
* **`tls`** takes the per-listener TLS settings by their short names, such as
  `{"disableTls12":"on","pqcOnly":"on"}`.
* On another listener, the console and the API now answer 404, and the log
  names where they are (`STS-TLS-0047`). An application the mapping does not
  name stays on `main` alone.
* The console's sign-in still calls `/oauth2/token` on the listener the
  authorization server is advertised on; the shell lets the browser connect
  there.

**The writes refuse** a public base that is not an `https` origin
(`STS-CORE-0146`), the main port or another socket the service uses
(`STS-CORE-0147`), a mapping naming an unknown application or listener, or
removing a listener a mapping still names (`STS-CORE-0154`). Putting the
sign-in service and the portal on listeners with different host names is
refused (`STS-CORE-0155`) unless `authn.cookieDomain` covers both; see
[Listeners → The sign-on session across host names](listeners.md#the-sign-on-session-across-host-names)
before you set it.

**If you lock yourself out**, start the service with
`STS_LISTENERS_ADMIN_ON_MAIN=true`. It puts the console and the API back on
the main port whatever the mapping says, and no write can turn it off.

## A trust realm on a listener of its own

A realm can define listeners that answer that realm alone, under its
`/realm/<id>` prefix, and map its applications to them. Taken from
`sts_realm_listener.js`, which runs on port 8099.

**Console:** switch to the realm, then on **Server configuration → Listeners →
Custom listeners** the boxes are **This realm's own listeners** and **This
realm's mapping**. Fill them in as in the recipe above.

**API:** make each call under the realm's prefix:
```bash
api realms/create '{"id":"rlis-1","name":"Realm listener"}'

RAPI="$BASE/realm/rlis-1/admin-api"
curl -sk -X POST "$RAPI/listeners/set-listeners" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"value":[{"id":"rl-1","port":8099,"publicBaseUrl":"https://localhost:8099"}]}'
curl -sk -X POST "$RAPI/listeners/set-applications" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"value":{"*":{"listeners":["main","rl-1"],"advertised":"rl-1"},
                "scim":{"listeners":["rl-1"]}}}'
```

The job stamps the realm and listener ids with the time; `rlis-1` and `rl-1`
stand in for them. What follows from these two calls, as the job checks:

* `https://localhost:8099/realm/rlis-1/.well-known/openid-configuration`
  answers, and its issuer is on the listener's base. With no certificate
  files, the realm's own CA issued the listener's certificate, and it
  verifies against the service's Root.
* The realm still answers on the main port (`main` is in the `*` entry),
  with the same issuer.
* The default realm's paths, and other realms', are 404 on port 8099
  (`STS-TLS-0041`).
* SCIM, mapped to `rl-1` alone, is 404 on the main port (`STS-TLS-0047`).

**Changing where `oauth-oidc` is advertised changes the realm's issuer**, and
every client and token names the issuer. `oidfed` has to be on the listener
`oauth-oidc` is advertised on. The main port is refused as a realm's listener.

## Related

* [TLS and mutual TLS](tls.md): every TLS setting, the certificate, the
  truststore and the sign-in in full.
* [Listeners and hosted applications](listeners.md): every member of a
  listener definition, and the hosted applications.
* [Configuring OAuth 2.0 grants](configure-oauth2-grants.md#client-authentication-methods):
  `tls_client_auth` and `self_signed_tls_client_auth` on the OAuth side.
* [PKI](pki.md): the CA hierarchy behind every certificate here, and
  revocation.
* [Configuring SPIFFE](configure-spiffe.md) and
  [Configuring certificate enrollment](configure-enrollment.md): the other
  pages about certificates.
* [Management API](management-api.md): the token, and `/admin-api/openapi.json`.
