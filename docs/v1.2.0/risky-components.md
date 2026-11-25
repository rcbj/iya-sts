---
title: Risky third-party components
nav_order: 15
---

# Risky third-party components

This page is for whoever reviews or deploys iya-sts and wants to know which of
the third-party components it ships carry more risk than the rest. It names
each one with the version the repository pins, what the service uses it for,
why it is riskier, how its use is contained, and how it is kept current. It
satisfies ASVS 5.0.0 requirement 15.1.4.

A component is on this list when at least one of these is true:

* it parses input an outside party controls, in a format with a history of
  parser flaws (XML, ASN.1, protobuf, multipart, zip);
* it is unmaintained or slow-moving: its last release is years old, or its
  upstream has stopped;
* it is a fork this project maintains;
* it is native code or WebAssembly;
* it implements cryptography;
* it has several published advisories in its history.

The versions are the ones in `package-lock.json`, `sdk/package-lock.json`, the
`node-ldapjs` submodule, `rust/Cargo.lock`, the `Dockerfile` and
`icap-clamav/Dockerfile` on 2026-11-24. Release dates are the npm registry's.
The image holds the exact list of what it ships (see
[How the list is kept](#how-the-list-is-kept)).

The parts of iya-sts itself that do something dangerous, many of them with
these components, are on [Dangerous functionality](dangerous-functionality.md).

## XML

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **@xmldom/xmldom** 0.9.12 | The one XML parser: SAML 2.0 and 1.1, WS-Trust, WS-Federation, XACML, SAML metadata, PSKC | Parses XML from callers who have not authenticated. Several advisories in its history | Reached only through `common/xml_parser.js`, which refuses a document carrying `<!DOCTYPE` or `<!ENTITY` before the parser sees it (`STS-CORE-0174`). xmldom resolves no external entity. A message is at most 1 MiB ([Input validation](validation.md#limits-by-kind-of-value)) | Root lockfile |
| **xml-crypto** 6.1.2 | Nothing in the service. The tests use it as an independent check of this service's XML Signatures | An XML Signature library with several advisories in its history | No service module requires it. XML Signature and XML Encryption are this service's own `common/crypto_impl/xmldsig.js`, over node's OpenSSL since 1.2.0. It is still installed in the image (see Known gaps) | Root lockfile |
| **xml2js** 0.6.2 | Pulled in by `dbus-next` (below), to read D-Bus introspection XML | XML parsing; last release 2023-07-26 | Installed only in an image built with the `dbus-next` SDK. It reads what the host's systemd sends, not what a caller sends. The version is held by an override in `sdk/package.json` | SDK lockfile |

## ASN.1, X.509 and CMS

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **pkijs** 3.4.0 and **asn1js** 3.0.10 | X.509 certificates, CRLs and OCSP, CMS for SCEP, EST, PKINIT and S/MIME, ACME, SPIFFE and passkey attestation | BER and DER parsing in JavaScript, some of it from callers who have not authenticated (OCSP, SCEP, PKINIT). Both have newer major lines (pkijs 4, asn1js 4) | asn1js refuses nesting deeper than 100 by default. Each unauthenticated entry point caps the body first: OCSP 64 KiB, `est.maxRequestBytes` (64 KiB), `scep.maxRequestBytes` (256 KiB), `krb5.maxRequestBytes` (128 KiB). SCEP answers 503 in product mode until `scep.allowInProduct` is on | Root lockfile |
| **node-forge** 1.4.2 | PEM and certificate parsing, base64 and binary strings, and the AES under JOSE encryption (`common/crypto_impl/symmetric_crypto.js`) | Cryptography and ASN.1 parsing in JavaScript. Several advisories in its history | Since 1.2.0 (#1615) every XML Signature and XML Encryption primitive is node's OpenSSL, and forge is left for parsing and encoding, plus the JOSE ciphers. Required only by `common/crypto.js` and two engines under `common/crypto_impl/` | Root lockfile |

## LDAP

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **ldapjs** 3.0.7, the `node-ldapjs` submodule at commit `ba3ab95a9126`, with **@ldapjs/asn1** 2.0.0 (and 1.2.0 as `ldapjs-asn1-v1`) | The embedded directory's LDAP server on 636 (LDAPS) and 389 | A fork this project maintains: the upstream package was decommissioned, and its last release was 2023-12-01. It decodes BER from a connection before any bind | Plain LDAP on 389 is off in product mode (`ldap.plainListener`). Changes are made only in the fork (`rcbj/node-ldapjs`), such as ending a connection whose request is malformed rather than hanging. Substring matching is this service's own one-pass scan, never the library's ([LDAP](ldap.md#how-a-filter-value-is-matched)). Searches are bounded by `ldap.sizeLimit` (500) and `ldap.timeLimit` (30 s). No limit is set on the size of one LDAP message (see [Dangerous functionality](dangerous-functionality.md#known-gaps)) | The submodule pin, bumped in the change that uses a fork commit |

## JSON-LD and token formats

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **jsonld** 9.0.0, **jsonld-signatures** 11.6.0, **rdf-canonize** 5.0.0, **@digitalbazaar/zcap** 9.0.1 | Data Integrity proofs on verifiable credentials, the W3C VC API, bbs-2023, and GNAP ZCAP tokens | A JSON-LD processor dereferences every context a document names. Canonicalization is complex | The document loaders fetch nothing. They answer only from contexts shipped with the service, each held to its SHA-256 by `tests/vc_jsonld.js`, and refuse every other URL. Canonicalization runs in safe mode. The VC API is off by default (`vcApi.enabled`) | Root lockfile |
| **@digitalbazaar/bbs-signatures** 3.1.0 | bbs-2023 selective-disclosure credentials | Cryptography | Loaded on first use only | Root lockfile |
| **@biscuit-auth/biscuit-wasm** 0.6.0 | GNAP access tokens in the Biscuit format | WebAssembly and cryptography; last release 2025-09-26 | Used only for the `biscuit` format. Remove `biscuit` from `gnap.tokenFormats` and none is issued | Root lockfile |
| **macaroon** 3.0.4 | GNAP access tokens in the macaroon format | Cryptography; last release 2019-01-09 | Used only for the `macaroon` format; remove it from `gnap.tokenFormats` to stop. Caveats are read against anchored patterns (`gnap/token_macaroon.ts`) | Root lockfile |
| **jsonwebtoken** 9.0.3 | Parts of JWT handling | Several advisories in earlier major versions | Required only by `common/crypto.js` | Root lockfile |
| **openpgp** 6.3.2 | OpenPGP keys for mail encryption and the Web Key Directory | Parses keys a person uploads; cryptography | A key is at most 64 KiB and a signed message 16 KiB before it is parsed. Reached only through `common/crypto_impl/openpgp_engine.js` | Root lockfile |
| **@noble/curves** 1.4.0, **@noble/hashes** 1.4.0, **@noble/post-quantum** 0.4.1 | Elliptic-curve and hash helpers, and expanding a stored post-quantum seed into its key | Cryptography. Held at older versions on purpose | Post-quantum signing and key establishment run on node's OpenSSL (`common/pq_native.js`). Each pin has a recorded review and reason in `.github/dependency-reviews.json` | Root lockfile, with the recorded review |

## Protocol parsers and uploads

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **@grpc/grpc-js** 1.14.5 and **protobufjs** 7.6.5 | SPIFFE's Workload API and SPIRE Server API | Parse protobuf from workloads. The Workload API answers without authentication, as its specification requires. protobufjs has advisories in its history | The SPIRE Server API requires an X509-SVID over mutual TLS. See [SPIFFE](spiffe.md) | Root lockfile |
| **ajv** 8.20.0 | Validating JSON against schemas: the API models, GNAP requests, and the RFC 9396 access-type schemas an administrator writes | It turns a schema into generated JavaScript | The service's own schemas come from its code. An administrator's access-type schema is at most 64 KiB, and Ajv is given no loader, so a `$ref` fetches nothing. Its `pattern` keywords are not checked for catastrophic backtracking (see [Dangerous functionality](dangerous-functionality.md#known-gaps)) | Root lockfile |
| **busboy** 1.6.0 | Multipart parsing of risk dataset uploads | Parses uploaded bodies; last release 2022-04-19 | Admin Write only. At most `risk.uploadMaxBytes` (2 GiB), streamed to disk | Root lockfile |
| **yauzl** 3.4.0 | Reading a zipped risk dataset | Zip parsing | Exactly one file per archive. Expanded size at most `risk.expandedMaxBytes` (8 GiB) and `risk.expansionMaxRatio` (100) times the upload | Root lockfile |
| **scimmy** 1.3.5 | SCIM 2.0 resources, filters and PATCH | Parses filter expressions and patches; last release 2025-03-05 | `/scim/v2` requires a credential in every mode. See [SCIM](scim.md) | Root lockfile |
| **sanitize-html** 2.18.1 (with htmlparser2 12.0.0) | Checking the HTML of a realm's own mail templates | HTML parsing | Only a realm's own templates, which its administrators write, are checked. The renderer escapes every value, and a template carrying an image, a script, a form or an absolute link is refused. See [Mail](mail.md) | Root lockfile |
| **express** 4.22.2 and **body-parser** 2.4.0 | Routing every HTTP request and reading its body | Every request goes through them. Several advisories in their history. A newer major line (express 5) exists | A body is at most 5 MB ([Input validation](validation.md)) | Root lockfile |
| **dtrace-provider** 0.8.8 | An optional dependency of the logger (bunyan) | Native code with an install script; last release 2019-08-17 | Optional: the logger works without it | Root lockfile |

## Native code and optional SDKs

These are installed only in an image built with `STS_CLOUD_SDKS` naming them,
from `sdk/package-lock.json`. See [Security in product mode](product-security.md#dependencies).

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **pkcs11js** 2.1.7 | Keys in a hardware security module | A native C++ module loaded into the service process, which loads the vendor's PKCS#11 library | Not a dependency of the service. Used only when `keys.kekProvider` is `pkcs11` or a realm's signing keys are in an HSM, with the module named by `keys.pkcs11Module`. Reached only through `common/crypto.js`. A blocking call is refused unless `keys.pkcs11SynchronousSign` is on. See [Keys in a hardware security module](hsm.md) | SDK lockfile. The only SDK whose install script runs, to build it |
| **dbus-next** 0.10.2 (with **usocket** 1.1.0, native) | SPIFFE's `systemd` workload attestor | Last release 2021-10-10 | Used only when `spiffe.workloadAttestors` (default `unix`) names `systemd`. Without the SDK, such a connection is refused (`STS-SPIFFE-0124`) | SDK lockfile |
| **oracledb** 26.0.0 | An optional database client | Ships native code for its optional thick mode | Installed only when named | SDK lockfile |
| **spiffe/native/peercred.node** | Reading a Unix socket peer's credentials for SPIFFE attestation | Native code. This repository's own, compiled from `spiffe/native/peercred.c` in the image build | Five functions, no state. Built only in an image, against the same Node.js version the image runs | This repository |

The other optional SDKs are the cloud providers' and the secret store's
clients. They speak only to infrastructure an operator configures.

## Runtime, operating system and other containers

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **Node.js** 24.22.1, with its bundled OpenSSL 3.5, HTTP/1.1 and HTTP/2 parsers and zlib | Every TLS handshake, certificate check, HTTP request and decompression; most cryptography | Native code parsing every connection | The image copies the `node` binary from `node:24.22.1-bookworm-slim`. Compressed messages are inflated up to a fixed limit | The base image tag, and the daily image scan |
| **Debian bookworm-slim** packages: `iproute2`, `curl`, `jq`, `ca-certificates` | `ip addr` for per-realm SPIFFE addresses, and tools for an operator | Native code | The service passes no untrusted input to them | The daily image scan |
| **ClamAV** (`clamav/clamav:1.5.4`) and **c-icap** with its virus-scan module, from Debian | Malware scanning of uploads | Native code that parses files assumed to be hostile | Separate containers, started with a scale of 0 by default. Scanning is off by default (`malwareScan.enabled`), and product mode reaches the scanner over TLS only. See [Malware scanning](malware-scanning.md) | The compose image tag; c-icap is whatever Debian has when the adapter is built (see Known gaps) |
| **The remote PEP** (Rust): hyper 1.11.1, h2 0.4.19, roxmltree 0.21.1, regex 1.13.1, serde_json 1.0.151, reqwest 0.12.28, and OpenSSL 3.6.3 built in (`openssl-src` 300.6.1) | The remote XACML PEP container | Parses HTTP and XML from the requests it guards. Links native OpenSSL | A separate container, not part of the service. The workspace forbids `unsafe` code in its own crates. See [Remote PEP](remote-pep.md) | `rust/Cargo.lock`, built `--locked` (see Known gaps) |

## How the list is kept

* **Exact installs.** Every image installs what the lockfiles name, with
  `npm ci`. The optional SDKs are installed from `sdk/package-lock.json` with
  install scripts off, and a build that names an SDK the lockfile does not pin
  fails. The remote PEP is built with `cargo build --locked`.
* **Advisory windows.** `tests/tools/dependency-windows.js` runs on every CI
  run (the `dependency-windows` job) over both lockfiles, the root's and
  `sdk/`'s. It fails when an advisory is past the window
  [`SECURITY.md`](https://github.com/rcbj/iya-sts/blob/main/SECURITY.md) sets:
  7 days for critical, 30 for high, 90 for moderate, counted from publication.
* **The image scan.** A daily workflow (`.github/workflows/dependency-windows.yml`)
  scans the iya-sts image with Trivy, which covers the operating system's
  packages and the Node.js runtime as well as the npm trees, and holds the
  findings to the same windows.
* **The 90-day review.** The same daily run fails on a direct dependency whose
  first newer release is more than 90 days old, unless
  `.github/dependency-reviews.json` records a review of the pinned version in
  the last 90 days and the reason it stays.
* **The inventory.** The image carries a CycloneDX SBOM of its npm
  dependencies at `/usr/src/sts/sbom.cdx.json`, one of its optional SDKs at
  `/usr/src/sts/sbom-sdks.cdx.json`, and its operating-system packages in
  `/usr/src/sts/os-packages.txt`. The `Dockerfile` writes all three when it
  builds the image.
* **This page** is updated when a component is added that meets one of the
  criteria at the top, and when one of these is removed.

## Known gaps

| Gap | Where | What would close it |
|---|---|---|
| xml-crypto is installed in the product image though no service module requires it | `package.json:59`; used by `tests/crypto_module.js` and others | Move it to `tests/package.json`, which the image does not install |
| The 90-day review only fires when a newer release exists, so a package that has stopped releasing (dbus-next, macaroon, busboy, dtrace-provider) is never flagged | `tests/tools/dependency-windows.js:125-128` | Also fail on a direct dependency whose last release is older than a set age, unless a review is recorded |
| The 90-day review skips linked and non-registry packages, so the `node-ldapjs` fork and its packages are never reviewed | `tests/tools/dependency-windows.js:209` | Review the submodule's pin against the fork's own history, with a recorded review |
| The remote PEP has no advisory audit, no SBOM, and its image is not scanned. Its built-in OpenSSL is not an operating-system package, so an OS scan would not see it | `.github/workflows/tests.yml:686`; `.github/workflows/dependency-windows.yml` | Run a Rust advisory audit of `rust/Cargo.lock` under the same windows, and write an SBOM into the PEP image |
| The malware-scanning adapter installs c-icap without a pinned version, and neither it nor the ClamAV image is scanned | `icap-clamav/Dockerfile:8` | Pin the packages and add both images to the daily scan |
| The root `npm ci` in the image build runs install scripts, where the SDK install does not | `Dockerfile:233` | Pass `--ignore-scripts` and build only what needs it, as the SDK stage does |

## Related

* [Dangerous functionality](dangerous-functionality.md)
* [Security in product mode](product-security.md#dependencies)
* [Malware scanning](malware-scanning.md)
* [Keys in a hardware security module](hsm.md)
