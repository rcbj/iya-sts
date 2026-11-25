---
title: Dangerous functionality
nav_order: 15
---

# Dangerous functionality

This page is for whoever reviews or deploys iya-sts and needs one list of the
parts of it that do something dangerous: parse hostile formats, fetch what
someone else names, take files, run processes or native code, read back what it
stored, or run rules an administrator wrote. Each row says what the part does,
where it lives, what could go wrong, which controls hold it, and where it is
covered in depth. It satisfies ASVS 5.0.0 requirement 15.1.5.

It describes product mode. Where development mode differs, the row says so.
The third-party components these parts rest on are on
[Risky third-party components](risky-components.md).

## Parsing XML

| What | Where | Risk | Controls | More |
|---|---|---|---|---|
| **Parsing XML** from SAML 2.0, SAML 1.1, WS-Trust, WS-Federation, XACML, SAML metadata and PSKC | `common/xml_parser.js`, the one parser every module takes `DOMParser` from | Entity expansion, external entities, very large documents | A document carrying `<!DOCTYPE` or `<!ENTITY` anywhere is refused before the parser sees it (`STS-CORE-0174`). No external entity is ever resolved. A SAML message, SOAP envelope or XACML document is at most 1 MiB, and a compressed message is inflated up to a fixed limit. SAML metadata from a service provider is at most `saml2.spMetadataMaxBytes` (512 KiB) | [Input validation](validation.md#formats) |
| **Verifying XML Signatures** | `common/crypto_impl/xmldsig.js`, called through `common/crypto.js` | Signature wrapping: a valid signature over one element while another is used. Weak algorithms | WS-Security signatures are found by position: the Envelope's own Body and the security header's own Timestamp, every id unique, exclusive canonicalization only, and a request element outside the signed Body is refused. A SAML document whose signature cannot be checked (an algorithm nothing verifies, wrapping, no octets) is refused (`STS-SAML-0062`). Which algorithms a realm accepts is set per surface | [Signature algorithms](crypto.md), [WS-Trust](ws-trust.md), [SAML 2.0 SSO](saml2-sso.md) |
| **Decrypting XML Encryption** | `common/crypto.js` (`decryptElement()`), over node's OpenSSL since 1.2.0 | A padding or decryption oracle; weak key transport | A federation relationship accepts exactly one key-management and one content-encryption algorithm. AES-CBC and RSA PKCS#1 v1.5 are refused in every mode (`STS-FED-0139`). Every decryption failure is one error with one sentence (`STS-FED-0138`), so the endpoint is no oracle. In product mode an unencrypted assertion that crosses the browser is refused (`STS-FED-0140`) unless the relationship sets `fedAllowUnencrypted` | [Federation](federation.md) |

## Parsing ASN.1, CBOR and other binary formats

| What | Where | Risk | Controls | More |
|---|---|---|---|---|
| **Kerberos messages**, over TCP and UDP on 88 and over `POST /KdcProxy` | `kerberos/krb5_asn1.js` and the `krb5_*_codec` modules, this service's own | DER from callers who have not authenticated yet | The reader takes at most 2 MiB, refuses nesting deeper than 32 and refuses an indefinite length (Kerberos is DER). A TCP request is at most `krb5.maxRequestBytes` (128 KiB). The KDC is on by default (`krb5.enabled`) | [Kerberos](kerberos.md) |
| **LDAP messages** on 636 and 389 | The `node-ldapjs` fork, then `ldap/ldap_server.js` | BER from a connection before it binds | Plain LDAP on 389 is off in product mode (`ldap.plainListener`); on, it answers only the root DSE. A malformed request ends its connection. Substring matching is a single linear scan, and a substring assertion of more than 32 components is refused before any entry is read (`STS-LDAP-0226`). Searches stop at `ldap.sizeLimit` (500) entries or `ldap.timeLimit` (30 s). **No limit is set on the size of one LDAP message** | [LDAP](ldap.md#how-a-filter-value-is-matched) |
| **X.509 certificates, CRLs and OCSP requests** | pkijs and asn1js, under `common/pki.js`, `common/crypto.js` and `common/revocation_status.js` | BER and DER parsing; OCSP is unauthenticated, on the plain-HTTP listener (8082) | asn1js refuses nesting deeper than 100. An OCSP request is at most 64 KiB (`STS-PKI-0073`). A certificate is validated through one door, with paranoid PKI mode on in product by default (`pki.paranoid`) | [PKI](pki.md), [Truststores](truststores.md) |
| **CMS**: SCEP and EST requests, PKINIT, S/MIME | `scep/scep_cms.ts`, `est/est_codec.ts`, `kerberos/krb5_pkinit_codec.ts`, `common/crypto.js` | Nested signed and enveloped structures; SCEP is unauthenticated by design | `scep.maxRequestBytes` (256 KiB), `est.maxRequestBytes` (64 KiB). SCEP answers 503 in product mode until `scep.allowInProduct` is on | [SCEP](scep.md), [EST](est.md) |
| **CBOR**: WebAuthn attestation objects, COSE keys, ISO mdoc | `authn/webauthn.js`, `oid4vc/vc_status_codec.ts`, `oid4vc/vc_mdoc.ts` | Deep nesting, indefinite lengths | The WebAuthn reader takes definite lengths only and refuses nesting deeper than 24 | [Passkeys](passkeys.md) |
| **OpenPGP keys** a person uploads | `common/crypto_impl/openpgp_engine.js`, through `common/crypto.js` | A complex packet format, parsed by a library | A key is at most 64 KiB and a signed message 16 KiB before it is parsed | [OpenPGP](openpgp.md) |
| **Protobuf** on SPIFFE's sockets | `spiffe/spiffe_grpc.ts`, with @grpc/grpc-js | The Workload API answers without authentication, as its specification requires | The SPIRE Server API requires an X509-SVID over mutual TLS. A TCP caller of the Workload API is never attested | [SPIFFE](spiffe.md) |

## JSON-LD contexts

| What | Where | Risk | Controls | More |
|---|---|---|---|---|
| **Canonicalizing and signing JSON-LD**: Data Integrity proofs on credentials, bbs-2023, GNAP ZCAP tokens | `oid4vc/vc_jsonld.ts`, `common/crypto_impl/bbs2023.js`, `common/crypto.js` (`zcapLoader()`) | A JSON-LD processor fetches every context a document names, so a caller could make the service dial a URL and change what a document means | **Nothing is fetched.** Each loader answers only from contexts shipped in the image (`oid4vc/contexts/`, `common/crypto_impl/contexts/`), each held to its SHA-256, and refuses any other URL with the URL named. The ZCAP loader serves only its suite contexts, the controller document built from the service's own key and the one root capability the token's target derives. Canonicalization runs in safe mode with no base. The W3C VC API is off by default (`vcApi.enabled`) | [Verifiable credentials](verifiable-credentials.md), [VC API](vc-api.md) |

## Fetching what someone else names

| What | Where | Risk | Controls | More |
|---|---|---|---|---|
| **URLs a caller can influence**: a client's `jwks_uri`, a `sector_identifier_uri`, a `request_uri`, GNAP's finish push, status lists, `did:web`, WebFinger, SPIFFE's `http_challenge`, AuthZEN callbacks and the rest | `federation/federation_http.ts` and each family | Server-side request forgery into the deployment's network; slow or huge answers | Each URL is dialled only under a condition listed on the communication inventory. In product mode: no redirects, internal and private addresses refused with the connection pinned, `federation.maxResponseBytes` (256 KiB), `federation.outboundTimeoutMs` (15 s), https with verified TLS. `security.outboundAllowedHosts` limits every such request to hosts you name. WS-Federation's `wreqptr` is never dereferenced | [Communication inventory](communications.md#outbound-locations-a-caller-can-name) |
| **Addresses an administrator names**: attribute-source databases, the SCIM client, XACML PEP notifications, the CSP report forward, audit export | `attribute-sources/`, `scim/scim_client.ts`, `xacml/`, `common/csp_reports.ts`, `common/audit_export.ts` | An administrator, including a realm's own, can make the service connect inside its network | `attributeSources.hostPatterns` (empty by default, allowing any host), `xacml.pepNotifyAllowedHosts`, `security.outboundAllowedHosts`. A CA file an administrator names must be inside a directory `security.fileRoots` lists, in product mode | [Attribute sources](attribute-sources.md#who-may-configure-a-source), [Communication inventory](communications.md) |

## Files

| What | Where | Risk | Controls | More |
|---|---|---|---|---|
| **Profile photos and sign-in logos** | `common/profile_photo.ts`, `common/branding.ts`, `common/image_metadata.ts` | A hostile image; metadata that leaks location; content served back to browsers | The type is decided by the bytes (JPEG or PNG for a photo, also WebP for a logo). The service walks the image's container and keeps only the listed segments, removing EXIF, XMP and text chunks; the size in pixels is read from the header, and the image itself is not decoded. A file it cannot walk to its end is refused. `profilePhoto.maxFileBytes` (5 MiB), `profilePhoto.maxStoredBytes` (1 MiB), `branding.logoMaxBytes` (256 KiB). Served with `nosniff` under a sandboxing policy | [File uploads](file-uploads.md) |
| **Risk datasets** | `risk/risk_upload.ts`, `risk/risk_expand.ts` | Very large or compressed files; zip bombs | Admin Write only. `risk.uploadMaxBytes` (2 GiB) as sent; expanded at most `risk.expandedMaxBytes` (8 GiB) and `risk.expansionMaxRatio` (100). A zip holds exactly one file. Streamed to disk, read as rows, never executed or served, deleted when the import ends | [File uploads](file-uploads.md), [Risk scoring](risk-scoring.md) |
| **LDIF, RFC 9728 metadata and SAML metadata imports** | `admin-core/admin_actions.ts`, `saml/sp_metadata.ts` | Parsing an administrator's file | Admin Write only. Parsed as data into one application, or refused; never kept or served | [File uploads](file-uploads.md) |
| **Malware scanning** of photos, logos and risk datasets | `common/malware_scan.ts`, and the `icap` and `clamav` containers | The scanner itself parses hostile files | Off by default (`malwareScan.enabled`). Runs in separate containers. A file the scanner flags, or cannot answer for, is refused | [Malware scanning](malware-scanning.md) |

## Processes, code generation and native code

| What | Where | Risk | Controls | More |
|---|---|---|---|---|
| **Re-executing itself with a heap limit** | `common/process_memory.ts` (`process.execve`) | Starting a process | At start only, with its own executable, arguments and a marker in the environment. Nothing from a request reaches it | — |
| **Reading the container's memory limit on ECS** | `common/process_memory.ts` (`execFileSync` of `node -e`) | Running a child process | Only when `ECS_CONTAINER_METADATA_URI_V4` is set. The script is fixed in the source; the address comes from the environment, not a request. Bounded by a timeout | — |
| **Reading the commit id** | `common/version.js` (`execFileSync('git', …)`) | Running a child process | Only when `GIT_COMMIT` is unset. Fixed arguments; the image has no `.git`, so it fails quietly there | — |
| **The protocol debugger's api** | `debugger/debugger_api_process.ts` (`child_process.fork`) | A second process that dials what a signed-in administrator names | See [The embedded debugger](#the-embedded-debugger) | [The protocol debugger](debugger/index.md) |
| **`vm`** | `common/heap_collector.ts` | Running code in a new context | One fixed expression, `gc`, to obtain a garbage-collection function, from Monitoring → Node Health's Collect buttons. No other module uses `vm` | — |
| **`eval` and `new Function`** | — | Running a string as code | No service module calls either | — |
| **Generated validators** | Ajv, under `common/applications.js`, `common/response_models.ts`, `gnap/gnap_schemas.ts`, `mgmt-api/admin_api.ts` | Ajv turns a JSON Schema into generated JavaScript | The service's own schemas come from its code and models. An RFC 9396 access-type schema an administrator writes is at most 64 KiB and must compile; Ajv is given no loader, so a `$ref` fetches nothing. Its `pattern` keywords are not checked for catastrophic backtracking | [Applications](applications.md) |
| **PKCS#11** | `common/crypto_impl/pkcs11.js`, reached only through `common/crypto.js`; `pkcs11js` loads the vendor's library | A native module and a vendor's library inside the service process | Only in an image built with the `pkcs11js` SDK, and only when `keys.kekProvider` is `pkcs11` or a realm's keys are in an HSM. The library is `keys.pkcs11Module`, read once at start. Blocking calls run only while `keys.pkcs11SynchronousSign` is on (off by default); the rest run off the event loop | [Keys in a hardware security module](hsm.md) |
| **Post-quantum cryptography** | `common/pq_native.js` | Slow operations holding the event loop | Not native code of this service's own: ML-DSA, SLH-DSA and ML-KEM run on node's OpenSSL, and the slow ones on libuv's thread pool | [Availability](availability.md) |
| **Unix socket peer credentials** | `spiffe/native/peercred.c`, built into `peercred.node` in the image | Native code of this repository's own | Five functions and no state, built only in an image build. Without it, a Unix socket peer is treated as not local (`STS-SPIFFE-0119`) | [SPIFFE](spiffe.md) |
| **Operator scripts** | `utilities/` | Some run child processes | Shipped in the image but run only by an operator from a shell. The service never runs them | — |

## Stored state, patterns and templates

| What | Where | Risk | Controls | More |
|---|---|---|---|---|
| **Reading back stored state** | `persistence/` | Deserializing data an attacker with database access changed | Everything is stored as JSON and read with `JSON.parse`. No format that can carry code is used. Every minted row (sessions, codes, keys) and every directory entry is sealed with AES-256-GCM under the key-encryption key, so a changed row does not open. A sealed directory entry names its DN and does not open on another entry's row. Audit rows carry a keyed checksum chained to the row before | [Persistence](persistence.md), [Encryption at rest](encryption-at-rest.md) |
| **LDAP substring filters** | `ldap/ldap_matching.ts` | A regular expression built from a filter could backtrack for a very long time | Since 1.2.0 (#2137) no regular expression is built: one linear scan, and at most 32 components | [LDAP](ldap.md#how-a-filter-value-is-matched) |
| **Federation subject patterns** | `federation/federation.js` | An administrator's regular expression run against a partner's value | Refused on write when it nests a quantifier or does not compile. A pattern that would be refused matches nothing, and a value longer than a fixed limit matches nothing | [Federation](federation.md) |
| **XACML regular-expression functions** | `xacml/xacml_functions.js` | A policy's pattern run against request values | Anchored, and XML Schema character-class subtraction is refused. **Not checked for nested quantifiers, and no length limit is set on the value** | [XACML](xacml.md) |
| **SPIFFE patterns** | `spiffe/spiffe_sigstore.ts`, `spiffe/spiffe_attestor_http_challenge.ts` | Administrator-set regular expressions run against identities and host names | A sigstore pattern that does not compile matches nothing (`spiffe.dockerSigstoreAllowedIdentities`), and an `http_challenge` pattern that does not compile is reported as a problem. `spiffe.httpChallengeAllowedDnsPatterns` empty means no host is dialled. **Not checked for nested quantifiers** | [SPIFFE](spiffe.md) |
| **Mail templates** | `common/mail_templates.ts` | A realm's own wording rendered into mail | The renderer escapes every value in HTML and strips control characters from the text and subject. A template carrying an image, a stylesheet, a script, a form, an event handler or an absolute URL is refused when it is saved. A link is always a path on this service's origin | [Mail](mail.md) |
| **Server-drawn pages** | `common/html.ts`, `common/shell_document.ts` | Reflected content | Every value is escaped by `Html.esc()`. Pages on the service's origin run with `script-src 'none'`, or `'self'` for a static surface, and none but the OP iframe carries an inline script | [User-facing pages](user-facing-pages.md) |

## Rules an administrator writes

| What | Where | Risk | Controls | More |
|---|---|---|---|---|
| **XACML and ALFA policies** | `xacml/` | A policy decides who gets what; a bad one grants or refuses everything | Written by the realm's administrators. The engine evaluates no XPath. At most `xacml.maxPolicies` (200) policies and `xacml.maxApplicationPolicies` (500) application policies. See the XACML pattern row above | [XACML](xacml.md) |
| **Attribute-source SQL** | `attribute-sources/` | SQL injection; reaching a database inside the network | The service sends only `SELECT <columns> FROM <table> WHERE <key column> = ?`, with the key bound. Table and column names must be letters, digits, `_` and `$`, not starting with a digit (`STS-ATTR-0005`). Always TLS with a verified certificate. `attributeSources.hostPatterns` limits the hosts | [Attribute sources](attribute-sources.md) |
| **RFC 9396 access-type schemas** | `common/applications.js` | See *Generated validators* above | At most 64 KiB; must compile | [Applications](applications.md) |

## Entry points that parse before anyone authenticates

These read and parse a body from anybody who can reach the port.

| Entry point | What is parsed | Limit |
|---|---|---|
| KDC, TCP and UDP on 88, and `POST /KdcProxy` | Kerberos DER | `krb5.maxRequestBytes` (128 KiB) on TCP |
| LDAPS on 636 (and 389 when it is on) | LDAP BER | None on one message (Known gaps) |
| OCSP on the revocation listener (8082) | DER | 64 KiB |
| SCEP on 8082 | CMS | `scep.maxRequestBytes` (256 KiB); 503 in product until `scep.allowInProduct` |
| SAML, WS-Federation and WS-Trust endpoints | XML | 1 MiB a message, no document type |
| OAuth token and authorization endpoints | JWTs: client assertions, request objects, DPoP proofs | The field limits on [Input validation](validation.md) |
| SPIFFE Workload API | Protobuf | gRPC's own |
| `POST /web/csp-report` | JSON | 16 KiB, no `Content-Encoding`, 60 reports a minute per address, read before every other body parser. Only chosen fields are recorded (the directive, the document's path, the blocked origin); a forward is off by default (`cspReports.forwardUrl`) and at most 8 are outstanding |
| Every HTTP request | Headers and body | 5 MB a body; `security.requestsPerAddressPerMinute` (6000 in product, none in development) |

## The embedded debugger

| What | Where | Risk | Controls | More |
|---|---|---|---|---|
| **The identity protocol debugger**: pages that render tokens and assertions from any provider, and an api that dials token endpoints, KDCs, directories and TLS servers on request | `debugger/`, on its own listener (`debugger.port`, 8444) | Its pages carry inline scripts; its api is a relay | **Off in product mode** (`debugger.enabled` is `auto`: on in development, off in product). Its own origin, so its scripts cannot drive the console. The gate is always on and admits only a console administrator's sign-in session. The api is a separate forked process with an allow-listed environment. In product it may dial only this service and `debugger.allowedDestinations`. A request is at most `debugger.maxRequestBytes` (5 MiB) | [The protocol debugger](debugger/index.md) |

## Known gaps

| Gap | Where | What would close it |
|---|---|---|
| No limit on the size of one LDAP message. The parser buffers until the length a message's header declares has arrived, before any bind | `node-ldapjs/lib/messages/parser.js:75`, `node-ldapjs/lib/server.js:630` | A maximum message size in the fork, with a setting, refused before the buffer grows |
| XACML's regular-expression functions compile a policy's pattern without the nested-quantifier check federation applies, and set no limit on the length of the value | `xacml/xacml_functions.js:1045-1066`, `1075-1079` | Reuse `federation/federation.js`'s check (`:685-730`) when a policy is written, and cap the value |
| SPIFFE's sigstore identity patterns and `http_challenge` DNS patterns have no nested-quantifier check | `spiffe/spiffe_sigstore.ts:750`, `spiffe/spiffe_attestor_http_challenge.ts:174` | The same check when the setting is written |
| An RFC 9396 access-type schema may hold any JSON Schema keyword, and its `pattern` keywords are run against a client's `authorization_details` with no backtracking check | `common/applications.js:7172` | Hold the definition to a keyword subset, as its `limits` schema already is, and check each `pattern` |

## Related

* [Risky third-party components](risky-components.md)
* [Communication inventory](communications.md)
* [File uploads](file-uploads.md)
* [Input validation](validation.md)
* [Availability and resource limits](availability.md)
* [Security in product mode](product-security.md)
