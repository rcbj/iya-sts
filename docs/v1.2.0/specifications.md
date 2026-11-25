---
title: Specifications
---

# Specifications

iya-sts aims to support a wide range of security specifications. This page
names every one in the service's own specification table (`SPECS` in
`sts_metadata.ts`), grouped for reading; [What it speaks](index.md#what-it-speaks)
is the same ground by protocol family, with the page to read for each.

**Being listed is not a claim of full conformance.** Each entry carries a
coverage statement that starts `full`, `partial` or `minimal` and says what is
missing. A running instance shows them on the console at `/admin/sts-metadata`
and to a program at `GET /admin-api/sts-metadata` (see
[Endpoints](endpoints.md)). Entries marked *draft* follow a document that may
still change.

## Every specification

| Group | Specifications |
|---|---|
| OAuth 2.0 | RFC 6749, RFC 6750, RFC 7009, RFC 7521, RFC 7522, RFC 7523, RFC 7591, RFC 7592, RFC 7636, RFC 7662, RFC 7800, RFC 8176, RFC 8414, RFC 8628, RFC 8693, RFC 8705, RFC 8707, RFC 9068, RFC 9101, RFC 9126, RFC 9207, RFC 9396, RFC 9440, RFC 9449, RFC 9470, RFC 9700, RFC 9701, RFC 9728; BCP 47 (RFC 5646, RFC 4647); The OAuth 2.1 Authorization Framework (draft); OAuth 2.0 Attestation-Based Client Authentication (draft); OAuth 2.0 Multiple Response Type Encoding Practices; OAuth 2.0 Form Post Response Mode; JWT Secured Authorization Response Mode for OAuth 2.0 (JARM); Grant Management for OAuth 2.0 (draft) |
| OpenID Connect | OpenID Connect Core 1.0; OpenID Connect Discovery 1.0; OpenID Connect Dynamic Client Registration 1.0; OpenID Connect Session Management 1.0; OpenID Connect Front-Channel Logout 1.0; OpenID Connect Back-Channel Logout 1.0; OpenID Connect RP-Initiated Logout 1.0; OpenID Connect Client-Initiated Backchannel Authentication Flow — Core 1.0 (CIBA); OpenID Connect Native SSO for Mobile Apps 1.0; OpenID Connect Key Binding 1.0; OpenID Connect EAP ACR Values 1.0; OpenID Connect for Identity Assurance 1.0; OpenID Connect for Identity Assurance Claims Registration 1.0; OpenID Connect Claims Aggregation; OpenID Provider Commands 1.0 (draft); OpenID Connect Enterprise Extensions 1.0 (draft); OpenID Connect Ephemeral Subject Identifier (draft); WebFinger (RFC 7033) |
| FAPI | FAPI 1.0 Part 1: Baseline Security Profile; FAPI 1.0 Part 2: Advanced Security Profile; FAPI 2.0 Security Profile, with its Attacker Model; FAPI 2.0 Message Signing; FAPI 2.0 Http Signatures (draft); FAPI: Client Initiated Backchannel Authentication Profile |
| OpenID Federation | OpenID Federation 1.1; OpenID Federation for OpenID Connect 1.1; OpenID Federation Extended Subordinate Listing 1.0 (draft); OpenID Federation Entity Collection Endpoint 1.0 (draft); OpenID Federation Subordinate Events Endpoint 1.0 (draft) |
| JOSE, COSE and CWT | RFC 7515, RFC 7516, RFC 7517, RFC 7518, RFC 7519, RFC 8392, RFC 9052 |
| GNAP, UMA and capability tokens | RFC 9635, RFC 9767, RFC 9421, RFC 9530; User-Managed Access (UMA) 2.0 Grant for OAuth 2.0 Authorization; Federated Authorization for User-Managed Access (UMA) 2.0; Macaroons: Cookies with Contextual Caveats (NDSS 2014) and the libmacaroons V2 format; Biscuit authorization token specification; W3C CCG Authorization Capabilities for Linked Data (ZCAP-LD) v0.3 |
| Authorization | OASIS XACML 3.0 (core); JSON Profile of XACML 3.0 v1.1; ALFA for XACML Version 1.0 (draft); AuthZEN Authorization API 1.0; AuthZEN Access Request and Approval Profile 1.0 (draft); AuthZEN Callback Notifications Profile 1.0 (draft); AuthZEN Access Request Catalog Profile 1.0 (draft); AuthZEN Actor Delegation Profile 1.0 (draft); AuthZEN Bulk Access Requests Profile 1.0 (draft) |
| Shared Signals | OpenID Shared Signals Framework 1.0; OpenID Continuous Access Evaluation Profile 1.0 (CAEP); OpenID RISC Profile Specification 1.0; RFC 8417, RFC 8935, RFC 8936, RFC 9493 |
| SAML, WS-* and XML security | SAML 2.0 Core; SAML 2.0 Bindings; SAML 2.0 Profiles; SAML 2.0 Metadata; SAML 1.1 Core; SAML 1.1 Bindings and Profiles; SAML 1.1 Profiles; WS-Trust 1.4 (and 1.0 to 1.3); WS-MetadataExchange (2004/09); WS-Federation 1.2; WS-Security UsernameToken Profile 1.1; WS-Security Kerberos Token Profile 1.1; XML Signature and XML Encryption |
| Kerberos and SPNEGO | RFC 4120, RFC 4121, RFC 3961, RFC 3962, RFC 4757, RFC 8009, RFC 4556, RFC 5349, RFC 6113, RFC 6560, RFC 8062, RFC 8070, RFC 8129 (over RFC 7751's AD-CAMMAC), RFC 8636, RFC 4178, RFC 4559; [MS-SFU] Kerberos Protocol Extensions: Service for User and Constrained Delegation; [MS-PAC] Privilege Attribute Certificate; [MS-KKDCP] Kerberos KDC Proxy Protocol |
| LDAP, SCIM and HTTP authentication | LDAP: RFC 4511, RFC 4512, RFC 4513, RFC 4514, RFC 4515, RFC 4519, RFC 2849. SCIM 2.0: RFC 7642, RFC 7643, RFC 7644. HTTP: RFC 7235, RFC 7616, RFC 7617, RFC 7486 |
| SPIFFE and SPIRE | SPIFFE-ID; X509-SVID; JWT-SVID; SPIFFE Trust Domain and Bundle; SPIFFE Workload API and Workload Endpoint; SPIFFE Broker API and Broker Endpoint; SPIRE Server API |
| PKI, TLS and certificate enrolment | X.509 and OCSP: RFC 5280, RFC 6960, RFC 5019, RFC 9935. TLS: RFC 8446, RFC 5246. ACME: RFC 8555, RFC 9773, RFC 8738, RFC 8823; ACME Profiles (draft); ACME Device Attestation Extension (draft). EST: RFC 7030, RFC 8951, RFC 5967. SCEP: RFC 8894. Attestation in certificate requests: Use of Remote Attestation with Certification Signing Requests (draft); Requesting a Freshness Nonce for Attestation Evidence in Certificate Signing Requests (draft). SSH: OpenSSH certificate keys (PROTOCOL.certkeys); OpenSSH key revocation lists (PROTOCOL.krl). PIV: Personal Identity Verification (PIV) of Federal Employees and Contractors (FIPS 201-3) and SP 800-73-4; YubiKey PIV Attestation |
| Sign-in factors and sessions | Web Authentication (WebAuthn) Level 3; Client to Authenticator Protocol (CTAP) 2.1; FIDO Universal 2nd Factor (U2F) 1.2; W3C Device Bound Session Credentials (draft); HOTP (RFC 4226); TOTP (RFC 6238); PSKC (RFC 6030); Yubico OTP; YubiKey Validation Protocol 2.0; NIST SP 800-63B-4 — Digital Identity Guidelines: Authentication and Authenticator Management |
| Verifiable credentials and DIDs | OpenID for Verifiable Credential Issuance 1.0; OpenID for Verifiable Presentations 1.0; Self-Issued OpenID Provider v2; SD-JWT (RFC 9901); SD-JWT-based Verifiable Credentials (draft); W3C Verifiable Credentials Data Model 1.1 and 2.0; W3C Data Integrity — ecdsa-jcs-2019, eddsa-jcs-2022, mldsa44-jcs-2024 and slhdsa128-jcs-2024; W3C Data Integrity — eddsa-rdfc-2022 and ecdsa-rdfc-2019; W3C Data Integrity — ecdsa-sd-2023; W3C Data Integrity — bbs-2023 cryptosuite; W3C Securing Verifiable Credentials using JOSE and COSE; W3C Verifiable Credentials API (VCALM); Token Status List (draft); W3C Bitstring Status List v1.0; ETSI TS 119 602 V1.1.1, Lists of trusted entities (LoTE); W3C Digital Credentials API; RDF Dataset Canonicalization (URDNA2015) and JSON-LD 1.1; W3C DID Core 1.0 (did:web, did:key, did:jwk); DIF Well Known DID Configuration |
| Mail and OpenPGP | SMTP and DKIM: RFC 5321, RFC 3207, RFC 8314, RFC 4954, RFC 5322, RFC 6376, RFC 8463. OpenPGP and S/MIME: RFC 9580, RFC 4880, RFC 9980, RFC 3156, RFC 8551, RFC 9629; OpenPGP Web Key Directory (draft) |
| Keys in a hardware security module | PKCS #11 Specification Version 3.2; The PKCS #11 URI Scheme (RFC 7512) |
| API description | OpenAPI Specification 3.1.0 |
