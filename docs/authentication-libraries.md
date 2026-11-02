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

There are four server-side libraries — OpenID Connect, GNAP, SAML 2.0 and
WS-Federation — in Node.js, Python, Java, Rust, Go, C#, and C and C++.
There are also two in-browser clients, for OpenID Connect and GNAP, and a
Swift client for native macOS apps. Every repository is public and every
library is under the MIT License.

| Language | Where the packages are published |
|---|---|
| Node.js (TypeScript and JavaScript) | [npm](https://www.npmjs.com/~rcbj) |
| Python | [PyPI](https://pypi.org/) |
| Java | Not yet on Maven Central (group `com.iyasec`); build it from the repository |
| Rust | [crates.io](https://crates.io/), with API documentation on [docs.rs](https://docs.rs/) |
| Go | No tagged release yet; `go get` resolves the latest commit through the Go module proxy |
| C# | [NuGet](https://www.nuget.org/profiles/IyaSec) |
| C and C++ | Not published to a package manager; build it from the repository |
| Swift | No tagged release yet; add the repository URL to Swift Package Manager |

Each repository has a test that signs its demo application in to a fresh
iya-sts built from the latest `main` branch. The test then sends two CAEP
events — a credential change and a revoked session — and checks the library
acted on both. A nightly workflow in each repository runs that test with
the rest of the suite.

How a library is called is in that library's own documentation. How
iya-sts behaves as the provider is on the protocol page for that family:
[OAuth 2.0 and OpenID Connect](oauth-oidc.md),
[SAML 2.0 Web Browser SSO](saml2-sso.md),
[WS-Federation](ws-federation.md), [GNAP](gnap.md) and
[Shared Signals](shared-signals.md).

A longer guide to the browser OpenID Connect client, and to the Swift
client for native macOS apps, is
[OpenID Connect and CAEP clients](client-libraries.md).

## Trusting iya-sts's TLS certificate

Every server-side library has a setting for the CA trust chain of
iya-sts's TLS listener: `tlsCa` for OpenID Connect and GNAP, `idpCa` for
SAML 2.0 and WS-Federation. Each repository's install script writes the
whole chain iya-sts publishes at `GET /tls/server-certificate` to the
file that setting names, and the demo's image build copies that file in.
Run the install script again and rebuild the image when you point the demo
at a different iya-sts. The libraries trust only that chain when the
setting is present, and they check the host name against the certificate.

## Node.js (TypeScript and JavaScript)

Six modules, published on npm by
[rcbj](https://www.npmjs.com/~rcbj). Each is written in TypeScript and can
be required from JavaScript. Install one with `npm install <name>`. The
`latest` tag is the release from `main`; the `next` tag is the
pre-release from `develop`.

| Module | Description | Repository | Documentation |
|---|---|---|---|
| [`oidc-caep-client`](https://www.npmjs.com/package/oidc-caep-client) | In-browser OpenID Connect public client (PKCE, PAR, DPoP, RFC 9207) with token caching and auto-refresh, and a Shared Signals (SSF) / CAEP event receiver | [rcbj/oidc-caep-client](https://github.com/rcbj/oidc-caep-client) | [documentation](https://rcbj.github.io/oidc-caep-client/) |
| [`oidc-caep-risc-nodejs`](https://www.npmjs.com/package/oidc-caep-risc-nodejs) | Server-side OpenID Connect confidential client: Authorization Code with PKCE, client authentication, and a CAEP and RISC Shared Signals receiver | [rcbj/oidc-caep-risc-nodejs](https://github.com/rcbj/oidc-caep-risc-nodejs) | [documentation](https://rcbj.github.io/oidc-caep-risc-nodejs/) |
| [`gnap-caep-client`](https://www.npmjs.com/package/gnap-caep-client) | In-browser GNAP (RFC 9635) client: HTTP message signature key proofs, redirect interaction, subject information for user sign-in, key-bound token caching and rotation, and a Shared Signals (SSF) / CAEP event receiver | [rcbj/gnap-caep-js](https://github.com/rcbj/gnap-caep-js) | [documentation](https://rcbj.github.io/gnap-caep-js/) |
| [`gnap-caep-risc-nodejs`](https://www.npmjs.com/package/gnap-caep-risc-nodejs) | Server-side GNAP (RFC 9635) client for traditional web applications: a registered key proved by mutual TLS, HTTP message signatures or detached JWS, key-bound tokens, redirect and push interaction finish, and a CAEP and RISC Shared Signals receiver | [rcbj/gnap-caep-risc-nodejs](https://github.com/rcbj/gnap-caep-risc-nodejs) | [documentation](https://rcbj.github.io/gnap-caep-risc-nodejs/) |
| [`saml2-sp-nodejs`](https://www.npmjs.com/package/saml2-sp-nodejs) | Server-side SAML 2.0 service provider: signed AuthnRequests on HTTP-Redirect or HTTP-POST, and Responses on HTTP-POST, HTTP-Redirect or HTTP-Artifact (with SOAP artifact resolution), validated strictly | [rcbj/saml2-sp-nodejs](https://github.com/rcbj/saml2-sp-nodejs) | [documentation](https://rcbj.github.io/saml2-sp-nodejs/) |
| [`wsfed-caep-nodejs`](https://www.npmjs.com/package/wsfed-caep-nodejs) | Server-side WS-Federation relying party: the passive requestor profile (`wsignin1.0`, `wsignout1.0`, `wsignoutcleanup1.0`) with SAML 2.0 assertions validated strictly, and a CAEP and RISC receiver that ends sessions | [rcbj/wsfed-caep-nodejs](https://github.com/rcbj/wsfed-caep-nodejs) | [documentation](https://rcbj.github.io/wsfed-caep-nodejs/) |

## Python, Java, Rust, Go, C#, and C and C++

The four server-side libraries in the Node.js table also exist in these
languages. The two in-browser clients stay in that table. The Swift client
for native macOS apps is [below](#swift).

Each library follows its Node.js module: the same protocol behaviour and
the same JSON configuration keys. `signals` omitted or true keeps the CAEP
and RISC receiver. `false` does not start that receiver and does not
require transmitter metadata, so the library can sign people in at a
provider that does not implement Shared Signals. OpenID Connect and GNAP
also leave `ssf.read` and `ssf.manage` out of the request when `signals`
is false. SAML 2.0 and WS-Federation do not send OAuth scopes, so the flag
only gates the receiver.

The package column is the name in that language, linked to its page on the
registry where it is published. The documentation link is the repository
README.

### Python

Install with `pip install <package>`. Import `gnap_caep_risc`,
`oidc_caep_risc`, `wsfed_caep`, or `saml2_sp`.

| Package | Protocol | Repository | Documentation |
|---|---|---|---|
| [`gnap-caep-risc`](https://pypi.org/project/gnap-caep-risc/) | GNAP | [rcbj/gnap-caep-risc-python](https://github.com/rcbj/gnap-caep-risc-python) | [README](https://github.com/rcbj/gnap-caep-risc-python/blob/main/README.md) |
| [`oidc-caep-risc`](https://pypi.org/project/oidc-caep-risc/) | OpenID Connect | [rcbj/oidc-caep-risc-python](https://github.com/rcbj/oidc-caep-risc-python) | [README](https://github.com/rcbj/oidc-caep-risc-python/blob/main/README.md) |
| [`saml2-sp`](https://pypi.org/project/saml2-sp/) | SAML 2.0 | [rcbj/saml2-sp-python](https://github.com/rcbj/saml2-sp-python) | [README](https://github.com/rcbj/saml2-sp-python/blob/main/README.md) |
| [`wsfed-caep`](https://pypi.org/project/wsfed-caep/) | WS-Federation | [rcbj/wsfed-caep-python](https://github.com/rcbj/wsfed-caep-python) | [README](https://github.com/rcbj/wsfed-caep-python/blob/main/README.md) |

### Java

Java 17. The Maven group is `com.iyasec`. The artifacts are not yet on
Maven Central. Each repository builds the library module (`library/`) and
the demo module (`demo/`) separately.

| Artifact | Protocol | Repository | Documentation |
|---|---|---|---|
| `gnap-caep-risc` | GNAP | [rcbj/gnap-caep-risc-java](https://github.com/rcbj/gnap-caep-risc-java) | [README](https://github.com/rcbj/gnap-caep-risc-java/blob/main/README.md) |
| `oidc-caep-risc` | OpenID Connect | [rcbj/oidc-caep-risc-java](https://github.com/rcbj/oidc-caep-risc-java) | [README](https://github.com/rcbj/oidc-caep-risc-java/blob/main/README.md) |
| `saml2-sp` | SAML 2.0 | [rcbj/saml2-sp-java](https://github.com/rcbj/saml2-sp-java) | [README](https://github.com/rcbj/saml2-sp-java/blob/main/README.md) |
| `wsfed-caep` | WS-Federation | [rcbj/wsfed-caep-java](https://github.com/rcbj/wsfed-caep-java) | [README](https://github.com/rcbj/wsfed-caep-java/blob/main/README.md) |

### Rust

Add one with `cargo add <crate>`.

| Crate | Protocol | Repository | Documentation |
|---|---|---|---|
| [`gnap-caep-risc`](https://crates.io/crates/gnap-caep-risc) | GNAP | [rcbj/gnap-caep-risc-rust](https://github.com/rcbj/gnap-caep-risc-rust) | [docs.rs](https://docs.rs/gnap-caep-risc), [README](https://github.com/rcbj/gnap-caep-risc-rust/blob/main/README.md) |
| [`oidc-caep-risc`](https://crates.io/crates/oidc-caep-risc) | OpenID Connect | [rcbj/oidc-caep-risc-rust](https://github.com/rcbj/oidc-caep-risc-rust) | [docs.rs](https://docs.rs/oidc-caep-risc), [README](https://github.com/rcbj/oidc-caep-risc-rust/blob/main/README.md) |
| [`saml2-sp`](https://crates.io/crates/saml2-sp) | SAML 2.0 | [rcbj/saml2-sp-rust](https://github.com/rcbj/saml2-sp-rust) | [docs.rs](https://docs.rs/saml2-sp), [README](https://github.com/rcbj/saml2-sp-rust/blob/main/README.md) |
| [`wsfed-caep`](https://crates.io/crates/wsfed-caep) | WS-Federation | [rcbj/wsfed-caep-rust](https://github.com/rcbj/wsfed-caep-rust) | [docs.rs](https://docs.rs/wsfed-caep), [README](https://github.com/rcbj/wsfed-caep-rust/blob/main/README.md) |

### Go

The module path is `github.com/rcbj/` plus the repository name. The
repositories require Go 1.27. There is no tagged release yet, so
`go get github.com/rcbj/<repository>@latest` resolves the latest commit on
`main` through the Go module proxy.

| Module | Protocol | Repository | Documentation |
|---|---|---|---|
| `github.com/rcbj/gnap-caep-risc-go` | GNAP | [rcbj/gnap-caep-risc-go](https://github.com/rcbj/gnap-caep-risc-go) | [README](https://github.com/rcbj/gnap-caep-risc-go/blob/main/README.md) |
| `github.com/rcbj/oidc-caep-risc-go` | OpenID Connect | [rcbj/oidc-caep-risc-go](https://github.com/rcbj/oidc-caep-risc-go) | [README](https://github.com/rcbj/oidc-caep-risc-go/blob/main/README.md) |
| `github.com/rcbj/saml2-sp-go` | SAML 2.0 | [rcbj/saml2-sp-go](https://github.com/rcbj/saml2-sp-go) | [README](https://github.com/rcbj/saml2-sp-go/blob/main/README.md) |
| `github.com/rcbj/wsfed-caep-go` | WS-Federation | [rcbj/wsfed-caep-go](https://github.com/rcbj/wsfed-caep-go) | [README](https://github.com/rcbj/wsfed-caep-go/blob/main/README.md) |

### C#

The packages target `net8.0`. Add one with `dotnet add package <package>`.

| Package | Namespace | Protocol | Repository | Documentation |
|---|---|---|---|---|
| [`IyaSec.GnapCaepRisc`](https://www.nuget.org/packages/IyaSec.GnapCaepRisc) | `IyaSec.Gnap` | GNAP | [rcbj/gnap-caep-risc-csharp](https://github.com/rcbj/gnap-caep-risc-csharp) | [README](https://github.com/rcbj/gnap-caep-risc-csharp/blob/main/README.md) |
| [`IyaSec.OidcCaepRisc`](https://www.nuget.org/packages/IyaSec.OidcCaepRisc) | `IyaSec.Oidc` | OpenID Connect | [rcbj/oidc-caep-risc-csharp](https://github.com/rcbj/oidc-caep-risc-csharp) | [README](https://github.com/rcbj/oidc-caep-risc-csharp/blob/main/README.md) |
| [`IyaSec.Saml2Sp`](https://www.nuget.org/packages/IyaSec.Saml2Sp) | `IyaSec.Saml` | SAML 2.0 | [rcbj/saml2-sp-csharp](https://github.com/rcbj/saml2-sp-csharp) | [README](https://github.com/rcbj/saml2-sp-csharp/blob/main/README.md) |
| [`IyaSec.WsFedCaep`](https://www.nuget.org/packages/IyaSec.WsFedCaep) | `IyaSec.WsFed` | WS-Federation | [rcbj/wsfed-caep-csharp](https://github.com/rcbj/wsfed-caep-csharp) | [README](https://github.com/rcbj/wsfed-caep-csharp/blob/main/README.md) |

### C and C++

One implementation per protocol, written in C++17. A C program calls it
through the C header, which is an `extern "C"` interface; a C++ program
can use the C++ header's classes. Both link the same library. OpenSSL
provides the cryptography. The libraries are not published to a package
manager; the README says how to build one with CMake.

| Library | Protocol | Repository | Documentation |
|---|---|---|---|
| `gnap-caep-risc` | GNAP | [rcbj/gnap-caep-risc-c](https://github.com/rcbj/gnap-caep-risc-c) | [README](https://github.com/rcbj/gnap-caep-risc-c/blob/main/README.md) |
| `oidc-caep-risc` | OpenID Connect | [rcbj/oidc-caep-risc-c](https://github.com/rcbj/oidc-caep-risc-c) | [README](https://github.com/rcbj/oidc-caep-risc-c/blob/main/README.md) |
| `saml2-sp` | SAML 2.0 | [rcbj/saml2-sp-c](https://github.com/rcbj/saml2-sp-c) | [README](https://github.com/rcbj/saml2-sp-c/blob/main/README.md) |
| `wsfed-caep` | WS-Federation | [rcbj/wsfed-caep-c](https://github.com/rcbj/wsfed-caep-c) | [README](https://github.com/rcbj/wsfed-caep-c/blob/main/README.md) |

## Swift

`OIDCCAEPClient` is an OpenID Connect public client (PKCE, PAR, DPoP) and
a CAEP receiver for native macOS apps, the native counterpart of
`oidc-caep-client`. There is no tagged release yet: add
`https://github.com/rcbj/swift-oidc-caep-native-app` to Swift Package
Manager and depend on its `main` branch. The detailed guide is
[OpenID Connect and CAEP clients](client-libraries.md).

| Product | Platform | Repository | Documentation |
|---|---|---|---|
| `OIDCCAEPClient` | macOS 13 or later; Linux desktops too | [rcbj/swift-oidc-caep-native-app](https://github.com/rcbj/swift-oidc-caep-native-app) | [documentation](https://rcbj.github.io/swift-oidc-caep-native-app/) |
