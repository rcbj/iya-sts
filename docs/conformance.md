---
title: Conformance and interoperability suites
---

# Conformance and interoperability suites

iya-sts is tested against suites that it did not write. Standards bodies and
test-vector projects publish these suites, and other vendors ship the
independent implementations it is tested with. Each one runs from this
repository's own test suite (`./run-tests.sh`). It needs no manual step, and
**a failure fails the run**.

This page lists every such suite, what it checks, and where it stands. The
[protocol pages](index.md) cover what each protocol does. `tests/CLAUDE.md`
in the repository covers how each job is built.

## How a result is judged

Every suite is held to the same rule, and the rule is stricter than "the
suite passed":

* **Every ERROR fails the job, and so does every WARNING** unless the job
  names that warning's condition with a reason. For the SAML peers and the
  enrollment clients, this also covers any warning or error line in the
  **peer's own log**, not just the suite's verdict.
* **An exception is keyed by the condition, not by the test.** One argued
  difference in a module cannot hide a second failure in the same module.
  Each exception gives its reason: a specification clause, a defect in the
  suite, or a design choice documented on the protocol's page. The same
  reason is recorded on the GitHub issue that added the suite.
* **An exception that no longer occurs is reported**, so the list shrinks
  when the reason goes away.
* **A floor on what ran.** Where a suite can skip, the job asserts a minimum
  number of passes or validated documents. If a flow silently stops
  producing its message, the job fails instead of passing with less coverage.
* **Nothing is weakened for the suite.** Each finding was fixed in the
  service in every mode, with a regression check that runs without the
  suite. A realm setting changed for a suite is named in its driver with
  the reason.

Third-party code and data are **pinned** (a release, a commit or an image tag,
checked by SHA-256) and fetched when the tests image is built. None of it is
committed, because several corpora carry published test private keys.

## Summary

Every suite below passed in the full runs of 2026-09-26 and 2026-09-27.

| Area | Suite | Published by | Scale |
|---|---|---|---|
| OpenID Connect, OAuth 2.0 | [OpenID conformance suite](#the-openid-foundation-conformance-suite), `release-v5.3.1` | OpenID Foundation | 9 OP certification profiles, `oidcc-test-plan` × 5 client authentications × 3 response modes, 4 logout plans, Identity Assurance |
| FAPI | the same suite | OpenID Foundation | FAPI 2.0 Security Profile, FAPI 2.0 Message Signing, FAPI 1.0 Advanced, FAPI-CIBA, with their variants |
| Shared Signals, CAEP | the same suite | OpenID Foundation | SSF transmitter and CAEP interop transmitter, by push and by poll |
| OpenID Federation | the same suite | OpenID Foundation | Leaf and Trust Anchor entity plans, and automatic registration into a federation the suite plays |
| OpenID4VCI, OpenID4VP | the same suite | OpenID Foundation | issuer (wallet- and issuer-initiated, pre-authorized, HAIP) and verifier (`direct_post`, `direct_post.jwt`, x509 client identifiers) |
| Verifiable Credentials | [W3C VC test suites](#w3c-verifiable-credentials-and-did-suites) | W3C VC Working Group | VC Data Model 2.0, Data Integrity EdDSA, Data Integrity ECDSA (incl. `ecdsa-sd-2023`), Bitstring Status List, VC-JOSE-COSE |
| DIDs | [did-test-suite](#w3c-verifiable-credentials-and-did-suites) | W3C DID Working Group | DID Core: did:web, did:key, did:jwk, resolution and dereferencing |
| XACML 3.0 | [OASIS conformance tests](#xacml-30) (via AT&T and AuthzForce) | OASIS XACML TC | **454 of 455** mandatory cases |
| SAML, WS-Trust, WS-Federation | [the published XML Schemas](#saml-ws-trust-and-ws-federation-documents) | OASIS, W3C | 31 schema files; every document the service emits, 198 validations per run |
| SAML 2.0 and 1.1 | [four independent service providers](#saml-service-providers) | Shibboleth Consortium, pysaml2, SimpleSAMLphp, Keycloak | SSO over every binding, Single Logout, attribute queries, negatives |
| XML Signature and Encryption | [W3C interop cases](#cryptography) | W3C XML Security WGs | XMLDSig 1.1, Exclusive C14N, C14N 1.1, XML Encryption 1.1 |
| Cryptography | [Wycheproof](#cryptography) | C2SP | ~83,000 vectors through every signing, verification, encryption and key-wrap path |
| Post-quantum | [NIST ACVP](#cryptography) | NIST | all ten ML-KEM, ML-DSA and SLH-DSA vector sets (FIPS 203, 204, 205) |
| X.509 path validation | [x509-limbo](#certificate-path-validation) | C2SP | 9,802 cases through six validators, including real TLS handshakes |
| X.509 path validation | [NIST PKITS](#certificate-path-validation) | NIST | 224 tests (249 subparts), including RFC 5280 policy processing |
| TLS | [tlsfuzzer](#tls) | tlsfuzzer project | every applicable script of ~170, against the main port, LDAPS 636 and the debugger's listener |
| Kerberos | [Samba's raw KDC tests](#kerberos) | Samba | 268 passing, 31 documented exceptions, 4,398 not applicable (Active Directory only) |
| Kerberos, SPNEGO | [Heimdal's client tools](#kerberos) | Heimdal | AS, TGS, keytabs, FAST, SPNEGO over HTTP |
| SCIM 2.0 | [scim2-tester and scim2/test-suite](#scim-20) | python-scim, scim2 | discovery, CRUD and PATCH per attribute; filters, sort, paging, Bulk, `If-Match` |
| ACME | [certbot, lego](#certificate-enrollment-acme-est-scep) | EFF, go-acme | registration with EAB, profiles, renewal (ARI), revocation, key rollover |
| EST | [libest's `estclient`](#certificate-enrollment-acme-est-scep) | Cisco | enroll, re-enroll, server key generation, CSR attributes, per-realm labels |
| SCEP | [sscep, micromdm, certmonger, jscep](#certificate-enrollment-acme-est-scep) | certnanny, MicroMDM, Red Hat, jscep | GetCACaps/Cert, enrolment, polling, renewal, GetCert/GetCRL, algorithm refusals |

## The OpenID Foundation conformance suite

The OpenID Foundation's own published images (the server, its MongoDB and its
nginx) run beside the service under a compose profile, pinned at
`release-v5.3.1`. Each plan runs in a throwaway [trust realm](trust-realms.md)
configured for the profile it tests. The job does everything a human tester
would do in the suite's UI: it registers clients with keys made at run
time, signs a person in on `/authn/login` and approves consent, approves
CIBA requests through `/admin-api`, emits CAEP events for the SSF interop
module, delivers credential offers and transaction codes, and acts as the
End-User for the OpenID4VP verifier.

| Job | Plans |
|---|---|
| `sts_oidcc_conformance` | the nine OP certification profiles (Basic with dynamic and static clients, Implicit, Hybrid, Config, Dynamic, the three form_post profiles, 3rd-party-initiated login); `oidcc-test-plan` once per client authentication (`client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, mutual TLS) across query, fragment and form_post; RP-Initiated, Front-Channel, Back-Channel and Session Management logout; Identity Assurance (`ekyc-test-plan-oidccore`) |
| `sts_fapi_conformance` | FAPI 2.0 Security Profile, FAPI 2.0 Message Signing (with Grant Management), FAPI 1.0 Advanced (with PAR and JARM), FAPI-CIBA (poll and ping), with mutual TLS as both client authentication and sender constraint |
| `sts_ssf_oidf_conformance` | the SSF transmitter plan and the CAEP interop transmitter plan, each by push and by poll |
| `sts_oidfed_conformance` | the deployed-entity plan for a Leaf realm and for the default realm as Trust Anchor; the plan in which the suite runs a federation that a realm's OP joins, registering the RP automatically |
| `sts_oid4vci_conformance` | the issuer plan (SD-JWT VC) wallet-initiated, issuer-initiated and pre-authorized with a transaction code; the HAIP issuer plan (`attest_jwt_client_auth`) |
| `sts_oid4vp_conformance` | the verifier plan for SD-JWT VC by `direct_post` and `direct_post.jwt`, with the `redirect_uri`, `x509_san_dns` and `x509_hash` client identifier prefixes |

**What it found**, each now fixed in every mode:

* A refresh token issued to one client could be redeemed by another, and
  with a wider scope, outside RFC 9700 mode.
* A repeated authorization code was answered again instead of refused.
* `nonce` was optional in the hybrid flow.
* `updated_at` and `phone_number_verified` were missing from UserInfo.
* A `post_logout_redirect_uri` with no `id_token_hint` or `client_id` was
  followed.
* Identity Assurance's `value`/`values` were not enforced inside
  `verified_claims`.
* The Session Management iframe failed in a browser without Web Crypto.
* FAPI 1.0 Advanced accepted `code` without JARM.
* Several SSF, OpenID Federation and OpenID4VCI details departed from the
  final specification texts.

**Warnings that stay.** Every module warns that the realm's JWKS carries
post-quantum keys the suite cannot parse. The OpenID Connect realms turn off
`oauth2.requestUriFragmentCheck`, because the suite's `request_uri`
fragments are random rather than hashes. The default stays the stricter
check.

**Not run, and why:**

* The relying-party plans: this service is no one's relying party but its
  own.
* The Brazil, panva and superseded-draft plans, and AuthZEN.
* The SSF receiver plans.
* FAPI 1.0 Baseline: the suite no longer publishes a plan for it, so the
  repository's own `sts_fapi_baseline.js` is Baseline's only check.
* FAPI 2.0 Message Signing's `plain_response` variant: section 5.4.1 has the
  authorization server require JARM.
* Push-mode FAPI-CIBA: the suite publishes no plan for it.

## W3C Verifiable Credentials and DID suites

The Working Groups' own mocha and jest suites run unmodified, at pinned
commits, against the [VC-API test endpoints](vc-api.md) of a throwaway
development realm. A local wrapper answers the JSON-LD contexts from the
hashed copies the service ships, so a run never depends on w3.org.

| Suite | Result |
|---|---|
| vc-data-model-2.0-test-suite (eddsa-rdfc-2022 and jose-p256 issuers, both verifiers) | passes; 3 documented exceptions |
| vc-di-eddsa-test-suite (eddsa-rdfc-2022, eddsa-jcs-2022, VC 1.1 and 2.0) | passes; no exceptions |
| vc-di-ecdsa-test-suite (ecdsa-rdfc-2019, ecdsa-jcs-2019 over P-256 and P-384, ecdsa-sd-2023) | passes; no exceptions |
| vc-bitstring-status-list-test-suite | passes, and additionally checks revocation and suspension end to end |
| vc-jose-cose-test-suite (35 tests) | passes; 4 documented exceptions |
| did-test-suite (DID Core) | passes; 1 documented exception |

Each exception is a suite fixture that disagrees with a specification:

* The Data Model suite's enveloped presentation carries a `vp` claim that
  VC-JOSE-COSE 1.1.2.1 forbids.
* In the VC-JOSE-COSE suite, the "unknown extensions" are in fact defined by
  the examples context, a fixture expired in 2024, and two presentations
  carry credentials that cannot be verified.
* The DID suite asks an unsuccessful `resolveRepresentation` for a content
  type.

The suites found five defects, all fixed:

* canonicalizing a value with `@direction`;
* verifying a proof chain;
* a controller check that refused the ECDSA specification's own vectors;
* an ignored `ecdsa-sd-2023` canonicalization option;
* a missing JOSE `typ` refused where the specification says SHOULD.

They also found one DID document context error.

## XACML 3.0

The OASIS XACML Technical Committee's conformance tests, as upgraded to
XACML 3.0 by AT&T and corrected by AuthzForce, are vendored byte for byte
(Apache-2.0) and run against the policy engine.

| Group | Result |
|---|---|
| IIA attribute references | 18 of 18 |
| IIB target matching | 55 of 55 |
| IIC function library | 261 of 261 |
| IID combining algorithms | 57 of 57 |
| IIE policy references | 2 of 3 |
| IIF other mandatory | 3 of 3 |
| IIIA obligations | 58 of 58 |

The one exception is **IIE003**. The case's own notes say that a referenced
policy must not be type-checked until evaluation reaches it, and the engine
behaves exactly that way. The expected response in the corpus assumes
otherwise. See [XACML 3.0 and ALFA](xacml.md).

## SAML, WS-Trust and WS-Federation documents

OASIS publishes no conformance tool for these families, only their schemas.
So **the schemas are the official machine check**. The job gathers every
document the service emits and validates each one with `xmllint --nonet`
against 31 pinned schema files. It runs in a development realm, a product
realm, and a realm federating to the first. The documents include:

* metadata;
* SAML 2.0 responses over all four bindings, encrypted assertions, artifact
  responses, errors, and logout in both directions;
* the SAML 1.1 Browser/POST response and the attribute responder's answers;
* WS-Trust 2004/04, 2005/02 and 1.3 over SOAP 1.1 and 1.2, for every request
  type, including faults;
* the WS-Federation sign-in response;
* the federation module's outbound requests.

A document is valid only if all three of these hold:

* It has no error and no warning.
* Every namespace it uses is loaded.
* Every element is declared in its namespace's schema, because lax
  wildcards would otherwise pass a misspelled element.

The first run found three defects, all fixed:

* WS-Trust 2004/04 answers used elements that version does not define.
* WS-Federation relationship metadata lacked
  `fed:ApplicationServiceEndpoint`.
* A metadata extension element had no schema; the service now publishes
  one at `/crypto/metadata.xsd`.

One published schema is corrected in a derived copy: the OASIS Standard's
`ws-trust-1.3.xsd` has a target namespace with a trailing slash that the
specification and every implementation lack.

## SAML service providers

No maintained SAML conformance tool exists: Kantara's interoperability
programme ended, and `saml2test` was archived in 2014. So four independent
service providers are run against both identity providers, in a development
and a product realm. Each registers by the service **consuming its own SP
metadata**, and each one's own log is checked for warnings and errors.

| Peer | Exercised |
|---|---|
| Shibboleth SP 3.6.0 | SAML 2.0 SP- and IdP-initiated over Redirect, POST, POST-SimpleSign and Artifact; SAML 1.1 Browser/POST and Browser/Artifact; SAML 2.0 and 1.1 attribute queries; Single Logout both ways; the back channel trusted from metadata alone |
| pysaml2 7.5.5 | every request/response binding pair; signed and unsigned AuthnRequests under each `saml2.requireSignedAuthnRequests` setting; ForceAuthn, IsPassive, four NameID formats; the refusals: bad signature, wrong Destination, stale IssueInstant, replay |
| SimpleSAMLphp 2.5.3.1 | its metadata validator; SP-initiated SSO over Redirect and POST (encrypted); ForceAuthn, IsPassive, NameIDPolicy; IdP-initiated SSO; Single Logout both ways, with XML validation on |
| Keycloak 26.6.4 | brokered sign-in with signed and encrypted assertions and attribute mappers; four NameID formats; back-channel, front-channel and IdP-initiated logout |

What they found is recorded in the repository's `saml/CLAUDE.md`. Each
finding is fixed and has a check that runs without the peers. How the
service behaves toward each peer is described in
[SAML 2.0 Web Browser SSO](saml2-sso.md).

## Cryptography

Three corpora test `common/crypto.js`, the one module in which the service
signs, verifies, encrypts and decrypts. The expected answers come from the
corpora, never from the service.

* **C2SP Wycheproof** (~83,000 vectors). Every file is either applied
  through the service's own entry points (JWS, JWE, COSE, XML Signature and
  Encryption, AES key wrap, ECDH-ES, RSA-OAEP) or listed as not applicable
  with a reason. A new, unclassified file fails the run. The JOSE files run
  again in product mode, where the answers differ. **It found twelve
  defects, all fixed**, including:
  * HMAC keys shorter than the hash accepted in product mode;
  * ECDSA over weak curves in XML signatures;
  * an AES-CBC padding oracle in XML decryption, which now fails every way
    with one refusal.
* **NIST ACVP**, all ten ML-KEM, ML-DSA and SLH-DSA sets:
  * key generation from NIST's seeds;
  * deterministic signing checked byte for byte;
  * the default hedged signature checked to differ from the deterministic
    one and still verify;
  * every published signature through every verification path (JWS, COSE,
    XML, raw).

  No vector has failed.
* **The W3C XML Security interop cases**: XML Signature 1.1, the merlin and
  phaos signature and encryption sets, Exclusive C14N, C14N 1.1, and XML
  Encryption 1.1 from Oracle, Microsoft and IBM. Signature cases run in
  development mode, in development mode with SHA-1 allowed, and in product
  mode, and every published canonical form is compared.

## Certificate path validation

* **C2SP x509-limbo** (9,802 cases) runs through all six places the service
  validates a chain: the general path validator, the signer-chain check,
  the one-hop check used by SPIFFE and key attestation, CRL evaluation, and
  real TLS handshakes both as a server asking for client certificates and
  as an outbound client. It found and fixed:
  * name constraints unevaluated;
  * greedy path building;
  * self-issued certificates counted against `pathLen`;
  * SHA-1 and MD5 certificate signatures accepted;
  * no critical-extension check on two paths;
  * OpenSSL accepting chains the rules refuse;
  * a CN fallback and partial wildcards in the outbound host check
    (RFC 9525);
  * CRL reader defects.
* **NIST PKITS** (224 tests, 249 subparts) runs with each test's policy
  inputs and CRLs. It found that RFC 5280 policy processing was missing
  entirely, and four CRL defects. All are fixed.

## TLS

**tlsfuzzer**, pinned at a commit and run unmodified, covers version
negotiation, extensions, record-layer limits, renegotiation, certificate
requests and known attacks. It runs against the main HTTPS port, LDAPS 636
and the embedded debugger's listener, with client certificates in RSA, EC,
Ed25519, RSA-PSS and ML-DSA-65.

Every upstream script is classified in one of three ways:

* **Not applicable**, because it tests something the service does not
  offer: CBC, RSA key exchange, finite-field DHE, CCM, heartbeat, or
  external PSK. The timing scripts are here too, because they need a quiet
  dedicated host.
* **Run**, with each failed probe matched to a documented design choice or
  to a documented OpenSSL behaviour the service cannot configure.
* **Run as a refusal**, where every probe must be refused.

The adapter tells the scripts only what they cannot be told on a command
line:

* the main port asks every connection for a client certificate;
* LDAPS carries LDAP;
* TLS 1.2 is ECDHE AES-GCM only.

It led to:

* refusing client certificates on non-NIST curves;
* post-quantum hybrid groups first, with no finite-field groups;
* removing DSA and SHA-224 signatures;
* disabling TLS 1.2 renegotiation;
* building the debugger's listener from the whole TLS policy.

See [TLS and mutual TLS](tls.md).

## Kerberos

* **Samba 4.25.0's raw KDC tests** (`python/samba/tests/krb5`) build every
  message by hand and check every field. They run unchanged against a
  realm's KDC on port 88. Tests that need an Active Directory domain
  controller are skipped, and each skip names what the test needed. The
  first complete runs had 268 passing and 31 documented exceptions.
* **Heimdal's client tools** (`kinit`, `klist`, `kgetcred`, `kvno`,
  `ktutil`, `gss-token`, and curl built against Heimdal's GSSAPI) cover AS
  and TGS per realm, keytabs, FAST armoring, RC4 by mode, and SPNEGO at
  `/authn/spnego`, in both modes. Heimdal found two things MIT's client
  could not: FAST's `hide-client-names` on every TGS-REQ, and RFC 6806's
  `enc-pa-rep`.

MIT Kerberos's client tools are also used throughout the repository's own
Kerberos jobs. See [Kerberos and SPNEGO](kerberos.md).

## SCIM 2.0

The IETF published no SCIM conformance suite, so two independent harnesses
run against `/scim/v2` with an OAuth token:

* **scim2-tester** covers discovery, then create, read, list, `.search`,
  `attributes`, replace, PATCH of every published attribute, and delete, per
  resource type.
* **scim2/test-suite** reports one result per RFC 7643/7644 requirement:
  filters, `sortBy`, pagination, Bulk and `If-Match`.

Any ERROR, CRITICAL, DEVIATION, FAIL or WARN fails the job unless it is a
documented exception. The exceptions are resource types or attributes only
the harness's own server defines, and one fuzzed URL. The departures the
harnesses found are all fixed. They include:

* `/Schemas` advertising members the directory cannot hold;
* `If-Match` not honoured;
* case-insensitive `userName` filtering;
* a SCIM-shaped 404 for unknown paths.

See [SCIM 2.0](scim.md).

## Certificate enrollment: ACME, EST, SCEP

No official conformance suite exists for any of the three, so the check is
the clients their operators actually run. Every key, CSR and account is made
at run time.

| Protocol | Client | What it drives |
|---|---|---|
| ACME | certbot 5.8.0 | EAB registration (and its refusals), profiles, `renew` with ARI, revocation onto the CRL, account update and deactivation |
| ACME | lego v5.5.2 | EAB, profiles, `--not-after`, ARI renewal, key rollover, revocation |
| EST | Cisco libest `estclient` | `/cacerts` bootstrap, `csrattrs`, enroll by password and by certificate, re-enroll, `serverkeygen`, per-realm labels, eight refusals |
| SCEP | sscep | GetCACaps, GetCACert, enrolment, GetCert, GetCRL, renewal, refusals of 3DES and SHA-1 |
| SCEP | micromdm `scepclient` v2.3.0 | transport over HTTPS and HTTP; its fixed SHA-1/DES is refused by design |
| SCEP | certmonger 0.79.21 | the daemon end to end: enrolment, polling, resubmit, rekey, refusals |
| SCEP | jscep 3.0.1 | all six AES × SHA-2 combinations, polling, GetCert, GetCRL, renewal, refusals |

A successful command must log no warning and no error. How to point each
client at the service is on the [ACME](acme.md), [EST](est.md) and
[SCEP](scep.md) pages. What the clients found is recorded in each
directory's `CLAUDE.md` in the repository.

## Not incorporated

* **FIDO2 / WebAuthn conformance tools.** The FIDO Alliance's tools are
  available only on request. The WebAuthn relying party is covered by the
  repository's own attestation and ceremony tests instead.
* **SPIFFE, LDAP and GNAP**: no official conformance suite is published.
  WS-Trust and WS-Federation have only their schemas, which are applied
  above.

## Running them

`./run-tests.sh` runs them all; see [Getting started](getting-started.md).

* The OpenID Foundation plans take about two hours. By default they run in
  the `memory` mode only (`STS_TEST_CONFORMANCE_MODES`). In CI they are a
  job of their own.
* The four SAML peers run in `memory` and `single-node`
  (`STS_TEST_SAML_PEERS_MODES`).
* Everything else runs in every local mode.
* A job whose suite was not brought up is reported **skipped, with the
  reason**, and never passed.

## Related

* [What is not checked](what-is-not-checked.md): where development mode is
  deliberately permissive, which is why most plans run in realms set to
  their profile.
* [Endpoints](endpoints.md): what the service claims for each
  specification, with its coverage notes.
