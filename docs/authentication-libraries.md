---
title: Authentication libraries
nav_order: 21
---

# Authentication libraries

These libraries are the relying party's side of a protocol iya-sts
implements, packaged so an application can sign people in without writing
the protocol itself. They are a set of client libraries for integrating
applications with iya-sts. Each one is written to its specification, so it
also works with other providers that implement the same specification.

The Node.js modules below are published on npm and have been run against
iya-sts. The same four server-side libraries — OpenID Connect, GNAP,
SAML 2.0, and WS-Federation — also exist for Python, Java, Rust, Go, and
C#. Those repositories are public. The packages are not yet published to
PyPI, Maven Central, crates.io, the Go module proxy, or NuGet. Clone the
repository. Its README is the documentation and says how to build the
library and run its tests. The license of those libraries is the MIT
License.

How a library is called is in that library's own documentation. How
iya-sts behaves as the provider is on the protocol page for that family:
[OAuth 2.0 and OpenID Connect](oauth-oidc.md),
[SAML 2.0 Web Browser SSO](saml2-sso.md),
[WS-Federation](ws-federation.md), [GNAP](gnap.md) and
[Shared Signals](shared-signals.md).

A longer guide to the browser OpenID Connect client, and to the Swift
client for native macOS apps, is
[OpenID Connect and CAEP clients](client-libraries.md).

## Node.js (TypeScript and JavaScript)

Six modules, published on npm by
[rcbj](https://www.npmjs.com/~rcbj). Each is written in TypeScript and can
be required from JavaScript. Install one with `npm install <name>`.

| Module | Description | Repository | Documentation |
|---|---|---|---|
| [`oidc-caep-client`](https://www.npmjs.com/package/oidc-caep-client) | In-browser OpenID Connect public client (PKCE, PAR, DPoP, RFC 9207) with token caching and auto-refresh, and a Shared Signals (SSF) / CAEP event receiver | [rcbj/oidc-caep-client](https://github.com/rcbj/oidc-caep-client) | [documentation](https://rcbj.github.io/oidc-caep-client/) |
| [`oidc-caep-risc-nodejs`](https://www.npmjs.com/package/oidc-caep-risc-nodejs) | Server-side OpenID Connect confidential client: Authorization Code with PKCE, client authentication, and a CAEP and RISC Shared Signals receiver | [rcbj/oidc-caep-risc-nodejs](https://github.com/rcbj/oidc-caep-risc-nodejs) | [documentation](https://rcbj.github.io/oidc-caep-risc-nodejs/) |
| [`gnap-caep-client`](https://www.npmjs.com/package/gnap-caep-client) | In-browser GNAP (RFC 9635) client: HTTP message signature key proofs, redirect interaction, subject information for user sign-in, key-bound token caching and rotation, and a Shared Signals (SSF) / CAEP event receiver | [rcbj/gnap-caep-js](https://github.com/rcbj/gnap-caep-js) | [documentation](https://rcbj.github.io/gnap-caep-js/) |
| [`gnap-caep-risc-nodejs`](https://www.npmjs.com/package/gnap-caep-risc-nodejs) | Server-side GNAP (RFC 9635) client for traditional web applications: a registered key proved by mutual TLS, HTTP message signatures or detached JWS, key-bound tokens, redirect and push interaction finish, and a CAEP and RISC Shared Signals receiver | [rcbj/gnap-caep-risc-nodejs](https://github.com/rcbj/gnap-caep-risc-nodejs) | [documentation](https://rcbj.github.io/gnap-caep-risc-nodejs/) |
| [`saml2-sp-nodejs`](https://www.npmjs.com/package/saml2-sp-nodejs) | Server-side SAML 2.0 service provider: signed AuthnRequests on HTTP-Redirect or HTTP-POST, and Responses on HTTP-POST, HTTP-Redirect or HTTP-Artifact (with SOAP artifact resolution), validated strictly | [rcbj/saml2-sp-nodejs](https://github.com/rcbj/saml2-sp-nodejs) | [documentation](https://rcbj.github.io/saml2-sp-nodejs/) |
| [`wsfed-caep-nodejs`](https://www.npmjs.com/package/wsfed-caep-nodejs) | Server-side WS-Federation relying party: the passive requestor profile (`wsignin1.0`, `wsignout1.0`, `wsignoutcleanup1.0`) with SAML 2.0 assertions validated strictly, and a CAEP and RISC receiver that ends sessions | [rcbj/wsfed-caep-nodejs](https://github.com/rcbj/wsfed-caep-nodejs) | [documentation](https://rcbj.github.io/wsfed-caep-nodejs/) |

## Python, Java, Rust, Go, and C#

The four server-side libraries in the Node.js table also exist in these
languages. The two in-browser clients stay in that table. The Swift client
for native macOS apps stays on
[OpenID Connect and CAEP clients](client-libraries.md).

Each library follows its Node.js module: the same protocol behaviour and
the same JSON configuration keys. `signals` omitted or true keeps the CAEP
and RISC receiver. `false` does not start that receiver and does not
require transmitter metadata, so the library can sign people in at a
provider that does not implement Shared Signals. OpenID Connect and GNAP
also leave `ssf.read` and `ssf.manage` out of the request when `signals`
is false. SAML 2.0 and WS-Federation do not send OAuth scopes, so the flag
only gates the receiver.

The package column is the name in that language. The documentation link is
the repository README.

### Python

Import `gnap_caep_risc`, `oidc_caep_risc`, `wsfed_caep`, or `saml2_sp`.

| Package | Protocol | Repository | Documentation |
|---|---|---|---|
| `gnap-caep-risc` | GNAP | [rcbj/gnap-caep-risc-python](https://github.com/rcbj/gnap-caep-risc-python) | [README](https://github.com/rcbj/gnap-caep-risc-python/blob/main/README.md) |
| `oidc-caep-risc` | OpenID Connect | [rcbj/oidc-caep-risc-python](https://github.com/rcbj/oidc-caep-risc-python) | [README](https://github.com/rcbj/oidc-caep-risc-python/blob/main/README.md) |
| `saml2-sp` | SAML 2.0 | [rcbj/saml2-sp-python](https://github.com/rcbj/saml2-sp-python) | [README](https://github.com/rcbj/saml2-sp-python/blob/main/README.md) |
| `wsfed-caep` | WS-Federation | [rcbj/wsfed-caep-python](https://github.com/rcbj/wsfed-caep-python) | [README](https://github.com/rcbj/wsfed-caep-python/blob/main/README.md) |

### Java

Java 17. The Maven group is `com.iyasec`.

| Artifact | Protocol | Repository | Documentation |
|---|---|---|---|
| `gnap-caep-risc` | GNAP | [rcbj/gnap-caep-risc-java](https://github.com/rcbj/gnap-caep-risc-java) | [README](https://github.com/rcbj/gnap-caep-risc-java/blob/main/README.md) |
| `oidc-caep-risc` | OpenID Connect | [rcbj/oidc-caep-risc-java](https://github.com/rcbj/oidc-caep-risc-java) | [README](https://github.com/rcbj/oidc-caep-risc-java/blob/main/README.md) |
| `saml2-sp` | SAML 2.0 | [rcbj/saml2-sp-java](https://github.com/rcbj/saml2-sp-java) | [README](https://github.com/rcbj/saml2-sp-java/blob/main/README.md) |
| `wsfed-caep` | WS-Federation | [rcbj/wsfed-caep-java](https://github.com/rcbj/wsfed-caep-java) | [README](https://github.com/rcbj/wsfed-caep-java/blob/main/README.md) |

### Rust

| Crate | Protocol | Repository | Documentation |
|---|---|---|---|
| `gnap-caep-risc` | GNAP | [rcbj/gnap-caep-risc-rust](https://github.com/rcbj/gnap-caep-risc-rust) | [README](https://github.com/rcbj/gnap-caep-risc-rust/blob/main/README.md) |
| `oidc-caep-risc` | OpenID Connect | [rcbj/oidc-caep-risc-rust](https://github.com/rcbj/oidc-caep-risc-rust) | [README](https://github.com/rcbj/oidc-caep-risc-rust/blob/main/README.md) |
| `saml2-sp` | SAML 2.0 | [rcbj/saml2-sp-rust](https://github.com/rcbj/saml2-sp-rust) | [README](https://github.com/rcbj/saml2-sp-rust/blob/main/README.md) |
| `wsfed-caep` | WS-Federation | [rcbj/wsfed-caep-rust](https://github.com/rcbj/wsfed-caep-rust) | [README](https://github.com/rcbj/wsfed-caep-rust/blob/main/README.md) |

### Go

The module path is `github.com/rcbj/` plus the repository name. The
repositories require Go 1.27.

| Module | Protocol | Repository | Documentation |
|---|---|---|---|
| `github.com/rcbj/gnap-caep-risc-go` | GNAP | [rcbj/gnap-caep-risc-go](https://github.com/rcbj/gnap-caep-risc-go) | [README](https://github.com/rcbj/gnap-caep-risc-go/blob/main/README.md) |
| `github.com/rcbj/oidc-caep-risc-go` | OpenID Connect | [rcbj/oidc-caep-risc-go](https://github.com/rcbj/oidc-caep-risc-go) | [README](https://github.com/rcbj/oidc-caep-risc-go/blob/main/README.md) |
| `github.com/rcbj/saml2-sp-go` | SAML 2.0 | [rcbj/saml2-sp-go](https://github.com/rcbj/saml2-sp-go) | [README](https://github.com/rcbj/saml2-sp-go/blob/main/README.md) |
| `github.com/rcbj/wsfed-caep-go` | WS-Federation | [rcbj/wsfed-caep-go](https://github.com/rcbj/wsfed-caep-go) | [README](https://github.com/rcbj/wsfed-caep-go/blob/main/README.md) |

### C#

The packages target `net8.0`.

| Package | Namespace | Protocol | Repository | Documentation |
|---|---|---|---|---|
| `IyaSec.GnapCaepRisc` | `IyaSec.Gnap` | GNAP | [rcbj/gnap-caep-risc-csharp](https://github.com/rcbj/gnap-caep-risc-csharp) | [README](https://github.com/rcbj/gnap-caep-risc-csharp/blob/main/README.md) |
| `IyaSec.OidcCaepRisc` | `IyaSec.Oidc` | OpenID Connect | [rcbj/oidc-caep-risc-csharp](https://github.com/rcbj/oidc-caep-risc-csharp) | [README](https://github.com/rcbj/oidc-caep-risc-csharp/blob/main/README.md) |
| `IyaSec.Saml2Sp` | `IyaSec.Saml` | SAML 2.0 | [rcbj/saml2-sp-csharp](https://github.com/rcbj/saml2-sp-csharp) | [README](https://github.com/rcbj/saml2-sp-csharp/blob/main/README.md) |
| `IyaSec.WsFedCaep` | `IyaSec.WsFed` | WS-Federation | [rcbj/wsfed-caep-csharp](https://github.com/rcbj/wsfed-caep-csharp) | [README](https://github.com/rcbj/wsfed-caep-csharp/blob/main/README.md) |
