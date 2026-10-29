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
named `CN=sts Root CA, O=sts`. A certificate viewer that shows only the name
can make two installs look as if they share one Root. Compare thumbprints
instead:

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
session carries `amr ["swk"]` and `acr "1"`. A browser that already holds a
session keeps it.

The main port **asks** every connection for a client certificate and requires
none, so nothing needs turning on. If you have set
`tls.mainPortDisableOptionalClientCertificate`, this route can never see a
certificate.

### A person's own certificate, from the portal

The certificate is issued from the realm's TLS client CA, names the person
(`CN=<username>` and `urn:sts:person:<username>`) and carries `clientAuth`. It
signs the person in to the realm whose CA issued it. No anchor needs adding.
Taken from `sts_portal_signing_key.js` (the portal) and
`tests/tls_client_certificates.js` (the sign-in).

**Portal:** the person signs in to `/portal/signing-key` and, under **TLS
client certificate**:
1. Optionally names it after the browser or device (the job uses `laptop`),
   and picks the key algorithm.
2. Types **A password for the downloaded file** and **The same password
   again**. This protects the key inside the file; it is not their account
   password.
3. Clicks **Generate and download my TLS client certificate**, and downloads
   the `.p12` (and the PEM files) from the page that follows. **That page is
   the only time the files can be downloaded.**
4. Imports the `.p12` into a browser and opens `/tls/sign-in` there, choosing
   the certificate when the browser asks.

A person may hold at most `pki.personTlsClientCertificateMax` valid ones (5 by
default). The person can revoke one with **Revoke** on the same page; after
that it signs nobody in.

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
  `STORED_TWICE`). Its common name and subject are never read.

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

A custom listener takes `"tls": {"http2": "off"}` in its definition. To check
what a connection negotiated:

```bash
curl -s --cacert sts-chain.pem --http2 -o /dev/null -w '%{http_version}\n' "$BASE/healthcheck"
```

`2` is HTTP/2; `1.1` is HTTP/1.1. One HTTP/2 connection may have at most
`http.http2MaxConcurrentStreams` (100) requests open at once.

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
