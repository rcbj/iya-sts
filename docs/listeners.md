---
title: Listeners and hosted applications
---

# Listeners and hosted applications

iya-sts answers every HTTP protocol, the admin console, the management API and
the user portal on **one port**, the main port (`global.port`), unless you say
otherwise. You can define **custom listeners** — more HTTPS ports, each with
its own address, certificate, TLS policy and client authentication — and say
which **hosted application** each one answers. An application can be on
several listeners at once.

Two common uses:

* **The sign-in service behind mutual TLS.** A listener that requires a client
  certificate, with `authn` on it, so every sign-in starts with a verified
  certificate.
* **The console and the management API off the main port.** A listener on an
  internal address, with `admin-console` and `management-api` on it alone, so
  the main port — the one the internet reaches — does not answer them.

Everything is on Server configuration → **Listeners** in the console, and on
`GET /admin-api/listeners` and `POST /admin-api/listeners/{action}`.

## The hosted applications

A path belongs to exactly one application. The list is fixed; you map the
applications, you do not define them. **Listeners → Applications** shows each
one, the paths it answers and where it is.

| Application | What it is |
|---|---|
| `home` | `GET /`, the documentation, terms and policy pages, the realm list |
| `authn` | The sign-in service, its second factors, the wallet, SPNEGO and certificate sign-ins (`/tls/sign-in`), and `/logout` |
| `portal` | The user portal |
| `admin-console` | The admin console, `/admin` |
| `management-api` | `/admin-api` |
| `oauth-oidc` | The authorization server and OpenID provider, their discovery documents, the access-token status list |
| `saml2`, `saml11`, `ws-trust`, `ws-federation` | The SAML, WS-Trust and WS-Federation identity providers |
| `federation`, `oidfed` | Federation relationships, and OpenID Federation |
| `oid4vc` | OpenID4VCI, OpenID4VP, DIDs and the VC-API test endpoints |
| `scim`, `ssf`, `gnap`, `xacml` | SCIM, Shared Signals, GNAP, XACML |
| `acme`, `est`, `scep`, `pki` | Certificate enrollment, and the certificate authority's public documents |
| `kerberos`, `spiffe`, `tls`, `devices` | MS-KKDCP and SPNEGO pages, the SPIFFE bundle, the TLS views, the device test control |

`/healthcheck` is no application's: every listener answers it, for the load
balancer in front of it.

## Defining a listener

A listener is a JSON object:

```json
{
  "id": "admin",
  "port": 9443,
  "publicBaseUrl": "https://admin.internal.example.com:9443",
  "hostnames": ["admin.internal.example.com"],
  "certificateFile": "/run/certs/admin.pem",
  "privateKeyFile": "/run/certs/admin.key",
  "clientAuth": "required",
  "tls": { "pqcOnly": "on" }
}
```

| Member | |
|---|---|
| `id` | Lower-case letters, digits and hyphens, from a letter; one name in the whole service. `main` is the main port. |
| `port` | Bound on **every node**: put your own load balancer in front of it. It may not be another listener's or one of the service's own sockets. |
| `publicBaseUrl` | The https origin the listener is reached at, with no path. Every URL of an application **advertised** on this listener is built on it. |
| `hostnames` | The DNS names an issued certificate carries; the host of `publicBaseUrl` when left out. |
| `certificateFile`, `privateKeyFile` | Your certificate (a public CA's for a browser-facing listener) and its key — both or neither. Without them the owning realm's certificate authority issues one for `hostnames` and renews it; a client must trust the service's Root to accept it. |
| `clientAuth` | `none` (no CertificateRequest), `optional` (asked, not required — the default, as on the main port) or `required` (a handshake without a certificate chaining to the [client truststore](tls.md) is refused). |
| `tls` | The listener's own TLS settings, by the short names the main port's per-listener rows use: `minVersion`, `disableTls12`, `ciphers`, `tls13CipherSuites`, `pqcOnly`, `groups`, `signatureAlgorithms`, `trustAnchorsFile`, `trustIssuedClientCertificates`, `sessionTimeoutS`, `sessionCacheSize`, `keepAliveTimeoutS`, `headersTimeoutS`, `maxRequestsPerSocket`, `maxConnections`. A value left out, `inherit`, `""` or `-1` follows the service-wide setting. |

**The service's listeners** are `listeners.custom` (in the default realm) and
answer every realm under its `/realm/<id>` prefix. **A realm's own listeners**
are `listeners.realm`, set on that realm, and answer that realm's paths alone —
the default realm's or another realm's is a 404 there.

A change binds, rebinds or closes the listener on every node at once; a change
of `clientAuth` or `tls` is applied at the next handshake without dropping a
connection. A listener that cannot bind (the port in use, a certificate file
that cannot be read) is shown as failed on the Listeners page and never stops
the service.

## Mapping applications to listeners

`listeners.applications` is a JSON object from an application id — or `*`,
every application not named — to the listeners that answer it and the one it
is **advertised** on:

```json
{
  "admin-console":  { "listeners": ["admin"] },
  "management-api": { "listeners": ["admin"] },
  "authn":          { "listeners": ["main", "mtls"], "advertised": "mtls" }
}
```

* A path of an application is answered **only** on the listeners it is on.
  On any other it is a 404 that names where the application is
  (`STS-TLS-0046` in the log).
* An application the mapping does not name is on `main` alone, so an empty
  mapping is the service as it always was.
* `advertised` (the first listener when left out) is where the application's
  URLs are built: its issuer, metadata, redirects, mailed links. One URL per
  endpoint is published. Where a specification has a place for another
  address, the other listeners are published there too: an `oauth-oidc`
  listener asking for a client certificate is the metadata's RFC 8705
  `mtls_endpoint_aliases`, and SAML 2.0's metadata lists a second
  `SingleSignOnService` and `SingleLogoutService` Location for each other
  `saml2` listener.
* A link or redirect from one application to another that is not on the same
  listener — the authorization endpoint sending a browser to `/authn/login`,
  the console calling `/oauth2/token` and `/admin-api` — is made absolute on
  the other application's advertised base. The console's page is allowed to
  call those origins.
* **Per realm.** A realm's own `listeners.applications` is read entry by entry
  before the service's: its entry for an application, then its `*`, then the
  service's entry, then the service's `*`. A realm says only what differs.
  To serve a whole realm on its own listener (what a realm's own listener was
  before), map `*` to it — beside `main` to keep the main port answering too:

  ```json
  { "*": { "listeners": ["main", "acme-front"], "advertised": "acme-front" } }
  ```

**Changing where an application is advertised changes its URLs.** For
`oauth-oidc` that is its **issuer**: every client's discovery and every token
names the old one. `oidfed` must be on the listener `oauth-oidc` is advertised
on, because a realm's Entity Identifier is its issuer.

## The sign-on session across host names

The sign-in service, the authorization server, the SAML, WS-Federation and
federation identity providers, GNAP's interaction and the portal all read one
**sign-on session cookie**. It is **host-only** by default, which is the
stronger setting: different ports on one host name share it, different host
names do not.

A mapping that puts those applications on listeners with different host names
is refused (`STS-CORE-0155`) unless `authn.cookieDomain` names a domain every
one of them is under — `example.com` for `auth.example.com` and
`portal.example.com`.

> **Warning.** With `authn.cookieDomain` set, every host under that domain is
> sent the session cookie, including hosts this service does not run. Set it to
> the narrowest domain your listeners share, never to a domain other parties
> host under. Set `webauthn.rpId` to the same domain, or a passkey registered on
> one host is not usable on another; the Listeners page warns when it is not.

## Not locking yourself out

* A change that takes `management-api` off the listener the request making it
  arrived on is refused (`STS-CORE-0156`) unless it says `"confirm": true`
  (`POST /admin-api/listeners/set-applications`, or the checkbox on the
  page).
* `listeners.adminOnMain=true` (`STS_LISTENERS_ADMIN_ON_MAIN=true`), set in the
  environment or the appconfig file and applied at the next start, puts the
  console and the management API back on the main port and advertises them
  there, whatever the mapping says. No write can turn it off.
* A listener a mapping names cannot be removed until the mapping no longer
  names it.

## The management API

```http
GET  /admin-api/listeners
POST /admin-api/listeners/set-listeners      {"value": [ ...listeners... ]}
POST /admin-api/listeners/set-applications   {"value": { ...mapping... }, "confirm": true}
```

Both writes act in the realm the call is made in (`/realm/<id>/admin-api/...`):
the service's listeners and mapping in the default realm, the realm's own in
any other. An empty `value` means none. The operations are in
`GET /admin-api/openapi.json`.

## Not supported

* Custom listeners while the service runs as several cells (`STS-CORE-0148`).
* The embedded protocol debugger, LDAP and LDAPS, the KDC, SPIFFE's gRPC
  listeners and the channel between cells are listeners of their own
  protocols, with their own settings on the Listeners page; they answer no
  hosted application and are not mapped.
* An application advertised on the main port while a request arrives on a
  custom listener builds its URLs on that request's host name and the main
  port. Set `global.publicBaseUrl` to say the main port's address outright.
