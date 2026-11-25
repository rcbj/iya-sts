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
| **xml2js** 0.6.2 | Pulled in by `dbus-next` (below), to read D-Bus introspection XML | XML parsing; last release 2023-07-26 | Installed only in an image built with the `dbus-next` SDK. It reads what the host's systemd sends, not what a caller sends. The version is held by an override in `sdk/package.json` | SDK lockfile |

xml-crypto, the XML Signature library the tests use as an independent check of
this service's signatures, is not in the image: since 1.2.0 it is a dependency
of `tests/package.json` only, and no service module requires it. XML Signature
and XML Encryption are this service's own `common/crypto_impl/xmldsig.js`, over
node's OpenSSL.

## ASN.1, X.509 and CMS

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **pkijs** 3.4.0 and **asn1js** 3.0.10 | X.509 certificates, CRLs and OCSP, CMS for SCEP, EST, PKINIT and S/MIME, ACME, SPIFFE and passkey attestation | BER and DER parsing in JavaScript, some of it from callers who have not authenticated (OCSP, SCEP, PKINIT). Both have newer major lines (pkijs 4, asn1js 4) | asn1js refuses nesting deeper than 100 by default. Each unauthenticated entry point caps the body first: OCSP 64 KiB, `est.maxRequestBytes` (64 KiB), `scep.maxRequestBytes` (256 KiB), `krb5.maxRequestBytes` (128 KiB). SCEP answers 503 in product mode until `scep.allowInProduct` is on | Root lockfile |
| **node-forge** 1.4.2 | PEM and certificate parsing, base64 and binary strings, and the AES under JOSE encryption (`common/crypto_impl/symmetric_crypto.js`) | Cryptography and ASN.1 parsing in JavaScript. Several advisories in its history | Since 1.2.0 (#1615) every XML Signature and XML Encryption primitive is node's OpenSSL, and forge is left for parsing and encoding, plus the JOSE ciphers. Required only by `common/crypto.js` and two engines under `common/crypto_impl/` | Root lockfile |

## LDAP

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **ldapjs** 3.0.7, the `node-ldapjs` submodule at commit `ba3ab95a9126`, with **@ldapjs/asn1** 2.0.0 (and 1.2.0 as `ldapjs-asn1-v1`) | The embedded directory's LDAP server on 636 (LDAPS) and 389 | A fork this project maintains: the upstream package was decommissioned, and its last release was 2023-12-01. It decodes BER from a connection before any bind | Plain LDAP on 389 is off in product mode (`ldap.plainListener`). Changes are made only in the fork (`rcbj/node-ldapjs`), such as ending a connection whose request is malformed rather than hanging. Substring matching is this service's own one-pass scan, never the library's ([LDAP](ldap.md#how-a-filter-value-is-matched)). Searches are bounded by `ldap.sizeLimit` (500) and `ldap.timeLimit` (30 s). No limit is set on the size of one LDAP message (see [Dangerous functionality](dangerous-functionality.md#known-gaps)) | The submodule pin, bumped in the change that uses a fork commit. Its review is recorded under [The fork](#the-fork) |

## JSON-LD and token formats

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **jsonld** 9.0.0, **jsonld-signatures** 11.6.0, **rdf-canonize** 5.0.0, **@digitalbazaar/zcap** 9.0.1 | Data Integrity proofs on verifiable credentials, the W3C VC API, bbs-2023, and GNAP ZCAP tokens | A JSON-LD processor dereferences every context a document names. Canonicalization is complex | The document loaders fetch nothing. They answer only from contexts shipped with the service, each held to its SHA-256 by `tests/vc_jsonld.js`, and refuse every other URL. Canonicalization runs in safe mode. The VC API is off by default (`vcApi.enabled`) | Root lockfile |
| **@digitalbazaar/bbs-signatures** 3.1.0 | bbs-2023 selective-disclosure credentials | Cryptography | Loaded on first use only | Root lockfile |
| **@biscuit-auth/biscuit-wasm** 0.6.0 | GNAP access tokens in the Biscuit format | WebAssembly and cryptography; last release 2025-09-26 | Used only for the `biscuit` format. Remove `biscuit` from `gnap.tokenFormats` and none is issued | Root lockfile |
| **macaroon** 3.0.4 | GNAP access tokens in the macaroon format | Cryptography; last release 2019-01-09 | Used only for the `macaroon` format; remove it from `gnap.tokenFormats` to stop. Caveats are read against anchored patterns (`gnap/token_macaroon.ts`) | Root lockfile; recorded under [Packages with no release in three years](#packages-with-no-release-in-three-years) |
| **jsonwebtoken** 9.0.3 | Parts of JWT handling | Several advisories in earlier major versions | Required only by `common/crypto.js` | Root lockfile |
| **openpgp** 6.3.2 | OpenPGP keys for mail encryption and the Web Key Directory | Parses keys a person uploads; cryptography | A key is at most 64 KiB and a signed message 16 KiB before it is parsed. Reached only through `common/crypto_impl/openpgp_engine.js` | Root lockfile |
| **@noble/curves** 1.4.0, **@noble/hashes** 1.4.0, **@noble/post-quantum** 0.4.1 | Elliptic-curve and hash helpers, and expanding a stored post-quantum seed into its key | Cryptography. Held at older versions on purpose | Post-quantum signing and key establishment run on node's OpenSSL (`common/pq_native.js`). Each pin has a recorded review and reason in `.github/dependency-reviews.json` | Root lockfile, with the recorded review |

## Protocol parsers and uploads

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **@grpc/grpc-js** 1.14.5 and **protobufjs** 7.6.5 | SPIFFE's Workload API and SPIRE Server API | Parse protobuf from workloads. The Workload API answers without authentication, as its specification requires. protobufjs has advisories in its history | The SPIRE Server API requires an X509-SVID over mutual TLS. See [SPIFFE](spiffe.md) | Root lockfile |
| **ajv** 8.20.0 | Validating JSON against schemas: the API models, GNAP requests, and the RFC 9396 access-type schemas an administrator writes | It turns a schema into generated JavaScript | The service's own schemas come from its code. An administrator's access-type schema is at most 64 KiB, and Ajv is given no loader, so a `$ref` fetches nothing. Its `pattern` keywords are not checked for catastrophic backtracking (see [Dangerous functionality](dangerous-functionality.md#known-gaps)) | Root lockfile |
| **busboy** 1.6.0 | Multipart parsing of risk dataset uploads | Parses uploaded bodies; last release 2022-04-19 | Admin Write only. At most `risk.uploadMaxBytes` (2 GiB), streamed to disk | Root lockfile; recorded under [Packages with no release in three years](#packages-with-no-release-in-three-years) |
| **yauzl** 3.4.0 | Reading a zipped risk dataset | Zip parsing | Exactly one file per archive. Expanded size at most `risk.expandedMaxBytes` (8 GiB) and `risk.expansionMaxRatio` (100) times the upload | Root lockfile |
| **scimmy** 1.3.5 | SCIM 2.0 resources, filters and PATCH | Parses filter expressions and patches; last release 2025-03-05 | `/scim/v2` requires a credential in every mode. See [SCIM](scim.md) | Root lockfile |
| **sanitize-html** 2.18.1 (with htmlparser2 12.0.0) | Checking the HTML of a realm's own mail templates | HTML parsing | Only a realm's own templates, which its administrators write, are checked. The renderer escapes every value, and a template carrying an image, a script, a form or an absolute link is refused. See [Mail](mail.md) | Root lockfile |
| **express** 4.22.2 and **body-parser** 2.4.0 | Routing every HTTP request and reading its body | Every request goes through them. Several advisories in their history. A newer major line (express 5) exists | A body is at most 5 MB ([Input validation](validation.md)) | Root lockfile |
| **dtrace-provider** 0.8.8 | An optional dependency of the logger (bunyan) | Native code with an install script; last release 2019-08-17 | Never built: every image build installs with install scripts off, and the library falls back to a stub that does nothing. The logger works without it | Root lockfile; recorded under [Packages with no release in three years](#packages-with-no-release-in-three-years) |

## Native code and optional SDKs

These are installed only in an image built with `STS_CLOUD_SDKS` naming them,
from `sdk/package-lock.json`. See [Security in product mode](product-security.md#dependencies).

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **pkcs11js** 2.1.7 | Keys in a hardware security module | A native C++ module loaded into the service process, which loads the vendor's PKCS#11 library | Not a dependency of the service. Used only when `keys.kekProvider` is `pkcs11` or a realm's signing keys are in an HSM, with the module named by `keys.pkcs11Module`. Reached only through `common/crypto.js`. A blocking call is refused unless `keys.pkcs11SynchronousSign` is on. See [Keys in a hardware security module](hsm.md) | SDK lockfile. The only SDK whose install script runs, to build it |
| **dbus-next** 0.10.2 (with **usocket** 1.1.0, native) | SPIFFE's `systemd` workload attestor | Last release 2021-10-10 | Used only when `spiffe.workloadAttestors` (default `unix`) names `systemd`. Without the SDK, such a connection is refused (`STS-SPIFFE-0124`) | SDK lockfile; recorded under [Packages with no release in three years](#packages-with-no-release-in-three-years) |
| **oracledb** 26.0.0 | An optional database client | Ships native code for its optional thick mode | Installed only when named | SDK lockfile |
| **spiffe/native/peercred.node** | Reading a Unix socket peer's credentials for SPIFFE attestation | Native code. This repository's own, compiled from `spiffe/native/peercred.c` in the image build | Five functions, no state. Built only in an image, against the same Node.js version the image runs | This repository |

The other optional SDKs are the cloud providers' and the secret store's
clients. They speak only to infrastructure an operator configures.

## Runtime, operating system and other containers

| Component | Used for | Why riskier | How its use is contained | Kept current by |
|---|---|---|---|---|
| **Node.js** 24.22.1, with its bundled OpenSSL 3.5, HTTP/1.1 and HTTP/2 parsers and zlib | Every TLS handshake, certificate check, HTTP request and decompression; most cryptography | Native code parsing every connection | The image copies the `node` binary from `node:24.22.1-bookworm-slim`. Compressed messages are inflated up to a fixed limit | The base image tag, and the daily image scan |
| **Debian bookworm-slim** packages: `iproute2`, `curl`, `jq`, `ca-certificates` | `ip addr` for per-realm SPIFFE addresses, and tools for an operator | Native code | The service passes no untrusted input to them | The daily image scan |
| **ClamAV** (`clamav/clamav:1.5.4`) and **c-icap** with its virus-scan module, from Debian | Malware scanning of uploads | Native code that parses files assumed to be hostile | Separate containers, started with a scale of 0 by default. Scanning is off by default (`malwareScan.enabled`), and product mode reaches the scanner over TLS only. See [Malware scanning](malware-scanning.md) | The compose image tag for ClamAV; c-icap, its library and its virus-scan module pinned to Debian's versions in `icap-clamav/Dockerfile`. Both images are in the daily image scan |
| **The remote PEP** (Rust): hyper 1.11.1, h2 0.4.19, roxmltree 0.21.1, regex 1.13.1, serde_json 1.0.151, reqwest 0.12.28, and OpenSSL 3.6.3 built in (`openssl-src` 300.6.1) | The remote XACML PEP container | Parses HTTP and XML from the requests it guards. Links native OpenSSL | A separate container, not part of the service. The workspace forbids `unsafe` code in its own crates. See [Remote PEP](remote-pep.md) | `rust/Cargo.lock`, built `--locked`, audited against the RustSec advisories every day, and inventoried in the image's SBOM, OpenSSL included. The image is in the daily image scan |

## Packages with no release in three years

A package whose upstream has stopped releasing gets no fix when an advisory
arrives. These are every package the images install, from the root and `sdk/`
lockfiles, whose newest release is more than three years old, each with that
date (the npm registry's), why it is kept and what would replace it. The
dates are in `tests/package_release_dates.json`, written by
`node tests/tools/release-dates.js` with the day it read them (`asOf`), so
the test `tests/long_unreleased_packages.js` needs no network. It fails when
a package more than three years past its last release on that day is not
listed here, when a listed package has released since or is no longer
installed, and when a date here differs from the one the registry gave. Three
years are counted from `asOf`, not from the day the test runs, so the list
changes when the file is refreshed (after a lockfile change, and from time to
time), never because a day passed.

Most of these are small modules that do one finished thing (a byte-count
parser, a stream splitter, a lodash function on its own) and have no reason to
release. They are kept for as long as the package that needs them is, and
leave with it.

### The fork

| Package | Pinned at | Why it is kept | Replacement plan |
|---|---|---|---|
| **node-ldapjs** (ldapjs 3.0.7), commit `ba3ab95a9126` of 2026-11-14 | The `node-ldapjs` submodule, from `rcbj/node-ldapjs` | Upstream ldapjs was decommissioned in 2024; its last release, 3.0.7, was 2023-12-01. No maintained Node.js library serves LDAP. Since 3.0.7 the fork holds the upstream's decommission note and eleven commits of this project's: anonymous binds routed to the handler, `errorMessage` sent as the diagnostic message, SASL binds, a delay before closing a failed connection, the five `@ldapjs` packages it decodes with, and a malformed request ending its connection instead of hanging the process. The registry packages it still uses are `@ldapjs/asn1` (2023-02-22), `@ldapjs/change` (2023-02-22) and `@ldapjs/protocol` (2022-12-17), BER and protocol codecs that are complete; the first is held at 2.0.0 and, for the controls package, 1.2.0. Reviewed 2026-11-25 against the fork's history | A fix is made in the fork and the pin bumped in the change that uses it (`ldap/CLAUDE.md`). The Rust runtime replaces it with `ldap3_proto` ([rust/DESIGN.md](https://github.com/rcbj/iya-sts/blob/main/rust/DESIGN.md)) |

### Packages the service or an SDK names

| Package | Held at | Why it is kept | Replacement plan |
|---|---|---|---|
| `macaroon` (2019-01-09) | 3.0.4 | The macaroon V2 format is fixed and the library implements it; GNAP's `macaroon` token format needs it. It pulls in `tweetnacl` (2020-02-10) and `tweetnacl-util` (2020-01-29) | Remove `macaroon` from `gnap.tokenFormats` to stop using it. If an advisory has no fix, the format is implemented in `gnap/token_macaroon.ts` over `common/crypto.js` (HMAC-SHA256 and the V2 binary layout) and the package dropped |
| `busboy` (2022-04-19) | 1.6.0 | The multipart parser of risk dataset uploads, Admin Write only. It is complete, and `streamsearch` (2021-12-19) is its one dependency | Node's own `Request.formData()` buffers the whole body, which a 2 GiB upload cannot afford. A streaming replacement is written when busboy has an advisory it does not fix |
| `bunyan` (2021-01-08) | 1.8.15 | The logger of every process, the same version the parent project uses. Its optional `dtrace-provider` (2019-08-17) is native code the image never builds: install scripts are off and the library falls back to its stub. It pulls in `safe-json-stringify` (2018-05-24), and through `mv`: `mv` (2015-06-22), `ncp` (2015-02-22), `mkdirp` (2023-04-24), `minimist` (2023-02-25), `inflight` (2016-10-13), `once` (2016-09-06), `wrappy` (2021-04-22), `path-is-absolute` (2018-11-08) and `concat-map` (2022-10-12); `mv` is used only by file rotation, which this service never configures | Moving to another logger means changing every module's `log` and the parent project's together. It is planned with the Rust runtime, which logs in the same JSON shape |
| `@digitalbazaar/security-context` (2023-06-13) | 1.0.1 | The W3C Security Vocabulary JSON-LD context, a fixed document. The document loaders answer from it without fetching | None needed: it is data. It leaves when the context's URL is no longer used |
| `dbus-next` (2021-10-10) | 0.10.2 | SDK only: SPIFFE's `systemd` workload attestor, installed only when `STS_CLOUD_SDKS` names it. It pulls in `xml2js` (2023-07-26), `xmlbuilder` (2020-04-08), `@nornagon/put` (2019-04-18), `bindings` (2019-02-27), `file-uri-to-path` (2019-10-11), and `event-stream` (2018-09-29) with `through` (2015-07-03), `stream-combiner` (2015-06-05), `duplexer` (2020-08-12), `split` (2017-08-03), `pause-stream` (2013-09-20), `map-stream` (2017-03-19) and `from` (2017-03-11). `event-stream` 4.0.1 is the release after the 2018 compromise, which was 3.3.6 | Replace it with a minimal D-Bus client in `spiffe/` when it has an advisory it does not fix, or drop the `systemd` attestor |

### Pulled in by another package

| Pulled in by | Packages, with their last release | Why kept, and the plan |
|---|---|---|
| express and body-parser | `utils-merge` (2017-09-20), `escape-html` (2015-09-01), `destroy` (2022-03-20), `parseurl` (2019-04-16), `forwarded` (2021-05-31), `methods` (2016-01-18), `merge-descriptors` (2023-11-16), `array-flatten` (2019-11-21), `unpipe` (2015-06-14), `toidentifier` (2021-11-14), `setprototypeof` (2019-07-18), `depd` (2018-10-26), `bytes` (2022-01-28), `ee-first` (2015-05-25), `safer-buffer` (2018-04-08), `inherits` (2019-06-19), `function-bind` (2023-10-12) | Maintained by the express project, which releases express itself. Express 5 drops several; moving to it is planned with the express 5 review |
| jsonwebtoken (and SDKs) | `ecdsa-sig-formatter` (2019-01-25), `buffer-equal-constant-time` (2013-12-16), `safe-buffer` (2020-05-10), `lodash.once` (2016-08-13), `lodash.isstring` (2016-02-03), `lodash.isplainobject` (2016-08-13), `lodash.isnumber` (2016-02-03), `lodash.isinteger` (2016-08-13), `lodash.isboolean` (2016-02-03), `lodash.includes` (2016-08-13) | Small finished helpers. jsonwebtoken is required only by `common/crypto.js`; they leave with it |
| ldapjs (the fork) | `verror` (2021-11-02), `extsprintf` (2021-11-02), `core-util-is` (2021-08-31), `assert-plus` (2016-01-27), `vasync` (2021-11-04), `backoff` (2016-03-12), `precond` (2014-06-21), `abstract-logging` (2020-10-17) | The fork's own dependencies. A fix goes in the fork, which can drop any of them |
| The JSON-LD libraries (`@digitalbazaar/*`, jsonld, jsonld-signatures) | `base58-universal` (2022-05-14), `base64url-universal` (2022-06-02), `base64url` (2018-11-26), `crypto-ld` (2022-06-02), `ed25519-signature-2020-context` (2021-04-22), `setimmediate` (2016-09-12) | Encoders and a fixed context; the Digital Bazaar libraries that need them still release |
| @grpc/grpc-js and @grpc/proto-loader (and the Google SDKs) | `@protobufjs/aspromise` (2017-04-24), `@protobufjs/base64` (2017-06-09), `@protobufjs/float` (2017-04-02), `@protobufjs/path` (2017-02-23), `@protobufjs/pool` (2017-01-25), `@js-sdsl/ordered-map` (2023-07-21), `lodash.camelcase` (2016-08-13), `y18n` (2021-04-07), `require-directory` (2015-05-28), `get-caller-file` (2019-03-09) | protobufjs's own helper modules and the argument parser of proto-loader's command line; protobufjs and grpc-js still release |
| qrcode | `dijkstrajs` (2023-04-15), `pngjs` (2023-02-20), `p-try` (2021-10-04), `path-exists` (2021-08-12), `which-module` (2023-04-21), `set-blocking` (2016-05-17), `require-main-filename` (2019-01-28) | The QR encoder's image and command-line parts. If one has an unfixed advisory, the QR code is drawn as SVG without it |
| knex | `colorette` (2023-04-16), `esm` (2019-05-17), `get-package-type` (2020-05-19), `getopts` (2021-02-15), `interpret` (2022-06-29), `path-parse` (2021-05-25), `resolve-from` (2019-04-15), `supports-preserve-symlinks-flag` (2022-01-03), `tildify` (2021-08-12) | knex's command line and configuration loader, which the service never runs; knex still releases |
| pg | `pg-int8` (2017-11-14), `postgres-date` (2021-12-08), `split2` (2023-03-26), `xtend` (2019-07-08) | Type parsers of the postgres driver, which still releases |
| ajv | `fast-deep-equal` (2020-06-08), `json-schema-traverse` (2020-12-13), `require-from-string` (2018-04-09) | ajv's own helpers; ajv still releases |
| sanitize-html | `escape-string-regexp` (2021-04-17), `parse-srcset` (2016-12-10) | Finished helpers of a package that still releases |
| yauzl | `pend` (2014-11-23) | A counter yauzl's author wrote; yauzl still releases |
| node-vault (SDK) | `mustache` (2021-03-28), `tv4` (2017-03-20), `combined-stream` (2019-05-12), `delayed-stream` (2015-04-30) | The Vault client's request templating and schema checks. node-vault itself still releases |
| mysql2 (SDK) | `generate-function` (2018-08-31), `is-property` (2014-12-25) | mysql2's row parser generator; mysql2 still releases |
| tedious and @azure/communication-email (SDK) | `abort-controller` (2019-03-30), `buffer` (2020-11-23), `event-target-shim` (2021-01-07), `events` (2021-02-27), `ieee754` (2020-10-27), `native-duplexpair` (2018-05-10), `process` (2017-04-26), `jwt-decode` (2023-10-27) | Browser polyfills and helpers of the Microsoft SDKs; installed only when named |
| @azure/identity (SDK) | `define-lazy-prop` (2021-04-14), `is-inside-container` (2023-02-15) | Helpers of the browser-login path, which the service never takes |
| The Google SDKs | `base64-js` (2020-11-11), `extend` (2018-07-19), `fetch-blob` (2023-05-18), `formdata-polyfill` (2021-09-30), `json-bigint` (2020-07-14), `node-fetch` (2023-08-23), `object-hash` (2022-02-18), `string_decoder` (2019-08-07), `util-deprecate` (2015-10-07) | Helpers of Google's HTTP client; installed only when named |

## How the list is kept

* **Exact installs.** Every image installs what the lockfiles name, with
  `npm ci` and install scripts off: no package's install script runs in the
  service's image build. Of the service's tree only `dtrace-provider` and
  `protobufjs` have one, and neither builds anything the service loads; a new
  package with one fails `tests/sdk_lockfile.js` until the `Dockerfile` says
  whether it needs building. The optional SDKs are installed from
  `sdk/package-lock.json` the same way (only `pkcs11js` is built after), and a
  build that names an SDK the lockfile does not pin fails. The remote PEP is
  built with `cargo build --locked`.
* **Advisory windows.** `tests/tools/dependency-windows.js` runs on every CI
  run (the `dependency-windows` job) over both lockfiles, the root's and
  `sdk/`'s. It fails when an advisory is past the window
  [`SECURITY.md`](https://github.com/rcbj/iya-sts/blob/main/SECURITY.md) sets:
  7 days for critical, 30 for high, 90 for moderate, counted from publication.
* **The remote PEP's advisories.** The same daily workflow runs `cargo audit`
  over `rust/Cargo.lock` against the RustSec database, which names advisories
  in the OpenSSL that `openssl-src` builds as well as in the crates. It fails
  the daily run on every vulnerability not recorded, with its reason, in
  `rust/.cargo/audit.toml`. It is daily rather than on every push so that an
  advisory published today fails the check meant to catch it, not every
  merge. The one recorded is RUSTSEC-2023-0071 in `rsa`
  0.9, which has no fixed release.
* **The image scan.** A daily workflow (`.github/workflows/dependency-windows.yml`)
  scans four images with Trivy: the iya-sts image, the remote PEP's, the ICAP
  adapter's, and ClamAV's at the tag `docker-compose.yml` names. That covers
  the operating systems' packages and the Node.js runtime as well as the npm
  trees, and the PEP's crates through the SBOM its image carries. Every
  finding is held to the same windows.
* **The 90-day review.** The same daily run fails on a direct dependency whose
  first newer release is more than 90 days old, unless
  `.github/dependency-reviews.json` records a review of the pinned version in
  the last 90 days and the reason it stays.
* **The inventory.** The image carries a CycloneDX SBOM of its npm
  dependencies at `/usr/src/sts/sbom.cdx.json`, one of its optional SDKs at
  `/usr/src/sts/sbom-sdks.cdx.json`, and its operating-system packages in
  `/usr/src/sts/os-packages.txt`. The `Dockerfile` writes all three when it
  builds the image. The remote PEP's image carries a CycloneDX SBOM of every
  crate its binary is built from at `/usr/src/pep/sbom.cdx.json`, written by
  `cargo cyclonedx`. Its `openssl-src` component names the OpenSSL built into
  the binary: `300.6.1+3.6.3` is OpenSSL 3.6.3.
* **Packages that have stopped releasing** are listed above with their
  reasons, and `tests/long_unreleased_packages.js` fails when one is missing.
* **This page** is updated when a component is added that meets one of the
  criteria at the top, and when one of these is removed.

## Known gaps

None. The one advisory the remote PEP's audit lets through, RUSTSEC-2023-0071
in `rsa` 0.9, has no fixed release, and its reason is recorded in
`rust/.cargo/audit.toml` (see [How the list is kept](#how-the-list-is-kept)).


## Related

* [Dangerous functionality](dangerous-functionality.md)
* [Security in product mode](product-security.md#dependencies)
* [Malware scanning](malware-scanning.md)
* [Keys in a hardware security module](hsm.md)
