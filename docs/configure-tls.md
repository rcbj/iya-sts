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
names the job it is taken from. Jobs in `tests/vendored/` run over HTTP
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
