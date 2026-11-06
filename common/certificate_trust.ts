// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: common/certificate_trust.ts
//
// ===========================================================================
// THE ONE CERTIFICATE-VALIDATION DOOR, AND PARANOID PKI MODE (#1360,
// 2026-11-06).
//
// A site that relies on an X.509 certificate calls `assess()` with a PURPOSE
// and gets one verdict. The field checks are `common/crypto.js` section 18, the
// paths `common/pki.js`, revocation `common/revocation_status.js`: this module
// composes them with the purpose table and the settings, and holds nothing of
// its own but the counters and the last inventory.
//
// **PARANOID PKI MODE IS `pki.paranoid`**, `auto|on|off`, and `auto` asks
// `mode.enforcesParanoidPki()`: on in product, OFF IN DEVELOPMENT, by rcbj's
// decision of 2026-11-06. Each purpose has a `pki.paranoid<UseCase>` row,
// consulted only while the master is in force. A row off, or the master not in
// force, runs that purpose's BASELINE: the central functions the site called
// before #1360, so "off restores today's behaviour" is true by construction
// rather than by a second code path at each site. There is no third state.
//
// **THE RULE UNDER PARANOID: A CHECK NOBODY MADE IS A REFUSAL.** A verdict names
// every check as `passed`, `failed`, `not-asked` or `exempt-by-spec`, and
// `not-asked` fails it, with `name-match` the one exception (whether a name is
// expected at all is the caller's business). What a use case does not ask at
// all, because no specification asks it of that use case (an extendedKeyUsage
// of a JOSE signer), passes rather than being `not-asked`: the rule is about a
// check the use case needs and could not make. So `pki.revocationCheck=off`
// under paranoid refuses a certificate naming a source, and the way out is the
// row, drawn red on the page. A certificate naming no source has no check to
// perform (rcbj): see `nothingToAsk()`.
//
// **AN EXEMPTION IS WRITTEN INTO THE TABLE, NEVER AT A CALL SITE**, with the
// specification that makes it. No entry, relationship or JWK may exempt one
// certificate: rcbj's decision, and `tests/paranoid_settings.js` reads this
// file to hold it.
//
// **A LEAF ACCEPTED SELF-SIGNED MAY CARRY cA=TRUE.** Every `openssl req -x509`
// certificate does; `pki.verifySignerChain()`'s `pinned` branch argued that on
// 2026-09-13, and a use case the specification defines as certificate equality
// has no chain for the flag to mean anything in. The table's `mayBeCa: false`
// is about a leaf on a chain.
//
// **THE COUNTERS ARE NOT A CACHE**: one row per realm and purpose, bounded by
// construction and dropped with the realm, so they are not on /admin/caches.
//
// A LIBRARY (rule 3): no route, no listener, and its one job is registered by
// `install()`. It requires only libraries, so it cannot close a cycle.
// ===========================================================================

import fs = require('fs');
import tls = require('tls');
import path = require('path');
import helpers = require('./helpers');
import config = require('./config');
import mode = require('./mode');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import stsCrypto = require('./crypto');
import cacheRegistry = require('./cache_registry');
import pki = require('./pki');
import revocationStatus = require('./revocation_status');
import signerTruststore = require('./signer_truststore');
import certificateSubject = require('./certificate_subject');

type Json = any;
type CheckId = import('../types/certificate_trust').CheckId;
type Purpose = import('../types/certificate_trust').Purpose;
type TrustVerdict = import('../types/certificate_trust').TrustVerdict;
type PinnedSource = import('../types/certificate_trust').PinnedSource;
type PinnedCertificate = import('../types/certificate_trust').PinnedCertificate;

// `bundledAnchors()`'s index.
let bundledRoots: Map<string, Buffer> | null = null;
const { EKU } = stsCrypto;
const SIGNS = ['digitalSignature'];
const TLS_CLIENT_USAGE = ['digitalSignature', 'keyAgreement'];
const TLS_SERVER_USAGE = ['digitalSignature', 'keyAgreement',
                          'keyEncipherment'];
const ENCIPHERS = ['keyEncipherment', 'keyAgreement'];
const DAY_MS = 86400000;
const AUDIT_JOB = 'pki.pins.audit';

// The order a verdict's `code` is chosen in: the most specific fact first, so
// an expired leaf is reported as expired and not as a path that failed.
const CHECK_ORDER: CheckId[] = ['validity', 'basic-constraints', 'key-usage',
  'extended-key-usage', 'signature-strength', 'key-strength',
  'critical-extensions', 'self-signed-allowed', 'name-constraints', 'path',
  'revocation', 'name-match'];
// What `verifyPathToAnchors()` or the path rules call a failed rule, as a check.
const RULE_CHECKS: Json = {
  critical: 'critical-extensions', 'weak-signature': 'signature-strength',
  'unaccepted-signature': 'signature-strength',
  'name-constraints': 'name-constraints'
};
// `pki.authorityCode()`'s table, for a rule the path broke.
const RULE_CODES: Json = {
  'name-constraints': 'STS-PKI-0194', critical: 'STS-PKI-0195',
  malformed: 'STS-PKI-0196', unusable: 'STS-PKI-0196',
  'weak-signature': 'STS-PKI-0197', policy: 'STS-PKI-0199',
  'unaccepted-signature': 'STS-KEYS-0185'
};

function leaf(keyUsage: string[], oids?: string[], required?: boolean): Json {
  return { keyUsage: keyUsage,
           eku: oids ? { oids: oids, required: !!required } : null,
           mayBeCa: false };
}

// THE PURPOSE TABLE. One row per use case; `docs/pki-use-cases.md` is written
// from it, and `tests/paranoid_settings.js` holds it to `common/config.js`.
const PURPOSES: Purpose[] = [
  { id: 'tls-client', setting: 'pki.paranoidTlsClient',
    title: 'A client certificate at a TLS handshake',
    covers: 'A client certificate presented to the main port, a custom ' +
      'listener, LDAPS or the debugger listener, and everything that reads ' +
      'the verdict of that handshake. On SPIFFE\'s gRPC sockets it holds no ' +
      'connection and only refuses to bind the SPIRE Server API in the clear; ' +
      'the channel between cells is `cell-peer`.',
    adds: 'The path rules on every listener, not only the main port; ' +
      'clientAuth and keyUsage on every leaf; revocation on every listener; ' +
      'a demoted connection stays demoted across TLS resumption; a failure ' +
      'inside the check refuses.',
    sites: ['tls/tls_server.js holdToPathRules', 'ldap/ldap_server.js',
            'debugger/debugger_server.ts',
            'spiffe/spiffe_server.ts plain bind'],
    anchors: ['client-truststore', 'realm'],
    leaf: leaf(TLS_CLIENT_USAGE, [EKU.clientAuth]),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [], baseline: 'peer-chain', code: 'STS-PKI-0240', phase: 1 },
  { id: 'tls-client-self-signed', setting: 'pki.paranoidTlsClientSelfSigned',
    title: 'A self-signed TLS client certificate a client registered',
    covers: 'RFC 8705 self_signed_tls_client_auth, and a GNAP key proved by a ' +
      'pinned certificate.',
    adds: 'The validity window; keyUsage; the register\'s revocation. A ' +
      'self-signed leaf is accepted only here at a handshake.',
    sites: ['oauth-oidc/client_auth.js', 'gnap/gnap_proof.ts verifyMtls'],
    anchors: ['pinned'],
    leaf: leaf(TLS_CLIENT_USAGE, [EKU.clientAuth]),
    selfSigned: 'allow-by-spec', validity: 'now', revocation: 'required',
    exemptions: [{ check: 'path',
                   spec: 'RFC 8705 section 2.2 and RFC 9635 section 7.3.2 ' +
                         'define the method as certificate equality' }],
    baseline: 'none', code: 'STS-PKI-0241', phase: 1 },
  { id: 'tls-server-outbound', setting: 'pki.paranoidOutboundTls',
    title: 'The server certificate of an outbound request',
    covers: 'Every address this service dials: federation back channels, SSF ' +
      'and GNAP push, the XACML PEP nudge, SCIM provisioning, mail, the ' +
      'database, the secret store, the cloud SDKs, CRL and OCSP over https, ' +
      'LDAPS.',
    adds: 'Revocation of the peer\'s certificate, stapled first, before any ' +
      'request body is written; serverAuth; the path rules and the host check ' +
      'in every process; the signer truststore beside each family\'s CA file.',
    sites: ['common/outbound_tls.ts gatedAgent'],
    anchors: ['caller', 'signer-truststore'],
    leaf: leaf(TLS_SERVER_USAGE, [EKU.serverAuth]),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [{ check: 'revocation',
                   spec: 'RFC 5280 section 4.2.1.13: a CRL or OCSP fetch over ' +
                         'plain http has no certificate to check' },
                 { check: 'self-signed-allowed',
                   spec: 'Not a specification, rcbj\'s decision: one ' +
                         'self-signed certificate accepted by name in the ' +
                         'signer truststore, or configured byte for byte as ' +
                         'this dialer\'s own CA, still held to its window ' +
                         'and fields' }],
    // THE STORE, NOT A SPECIFICATION, AND THE ONE WEAKENING IN THIS TABLE: the
    // database is dialled before anything else can answer, so a source it names
    // being unreachable would stop the service starting. A certificate revoked
    // is still refused. rcbj kept this on #1360.
    variants: { store: { softRevocation: true } },
    baseline: 'peer-chain', code: 'STS-PKI-0242', phase: 2 },
  { id: 'jose-signer', setting: 'pki.paranoidJoseSigner',
    title: 'A JOSE signer\'s certificate chain',
    covers: 'The x5c behind an RFC 7523 assertion, private_key_jwt, a JAR ' +
      'request object, a software statement or a registered JWK.',
    adds: 'An incomplete registered chain completed from the signer truststore ' +
      'before it is refused; keyUsage on the leaf; a self-signed x5c[0] in a ' +
      'JWK held to the upload door\'s rule.',
    sites: ['oauth-oidc/assertion_grant.js', 'oauth-oidc/client_auth.js',
            'oauth-oidc/request_object.ts', 'common/oidc_rp.ts'],
    anchors: ['realm', 'registered-root', 'signer-truststore'],
    leaf: leaf(SIGNS),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [], baseline: 'signer-chain', code: 'STS-PKI-0243', phase: 3 },
  { id: 'saml-signer', setting: 'pki.paranoidSamlSigner',
    title: 'A SAML signer\'s certificate',
    covers: 'The certificate behind an RFC 7522 assertion, a service ' +
      'provider\'s signed request, the SOAP artifact caller and an SP metadata ' +
      'signature.',
    adds: 'Validity at every use; a chain to the signer truststore when the ' +
      'certificate is not self-signed; revocation; keyUsage; SP metadata that ' +
      'reaches no anchor is refused.',
    sites: ['saml/request_signature.ts', 'saml/sp_metadata.ts',
            'oauth-oidc/saml_assertion_grant.js'],
    anchors: ['registered-root', 'signer-truststore', 'pinned'],
    leaf: leaf(SIGNS),
    selfSigned: 'allow-by-spec', validity: 'now', revocation: 'required',
    exemptions: [{ check: 'self-signed-allowed',
                   spec: 'SAML Metadata section 2.4.1.1 lets a provider ' +
                         'publish a self-signed certificate, when it is ' +
                         'registered on the application' }],
    baseline: 'none', code: 'STS-PKI-0244', phase: 3 },
  { id: 'federation-partner', setting: 'pki.paranoidFederationPartner',
    title: 'A federation partner\'s signing certificate',
    covers: 'A partner\'s SAML or WS-Federation signature, a partner JWK\'s ' +
      'x5c and a federated logout signer.',
    adds: 'Validity at every use; a chain to the signer truststore when the ' +
      'certificate is not self-signed; revocation on logout and sign-in alike; ' +
      'field checks when the certificate is registered.',
    sites: ['federation/federation_sp.ts', 'federation/federation_slo.ts',
            'federation/federation.ts'],
    anchors: ['registered-root', 'signer-truststore', 'pinned'],
    leaf: leaf(SIGNS),
    selfSigned: 'allow-by-spec', validity: 'now', revocation: 'required',
    exemptions: [{ check: 'self-signed-allowed',
                   spec: 'SAML Metadata section 2.4.1.1, when it is registered ' +
                         'on the relationship' }],
    baseline: 'none', code: 'STS-PKI-0245', phase: 3 },
  { id: 'wss-x509-token', setting: 'pki.paranoidWsSecurityToken',
    title: 'A WS-Security X.509 token',
    covers: 'The WS-Security X.509 Token Profile signer of a WS-Trust request.',
    adds: 'A stored outside leaf must chain to the signer truststore; the ' +
      'OCSP or CRL issuer comes from that path, never from the leaf\'s own ' +
      'Authority Information Access alone.',
    sites: ['ws-trust/wstrust.ts', 'common/tls_client_certificates.js'],
    anchors: ['realm', 'signer-truststore'],
    leaf: leaf(SIGNS),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [], baseline: 'realm-leaf', code: 'STS-PKI-0246', phase: 3 },
  { id: 'jose-bare-key', setting: 'pki.paranoidJoseBareKey',
    title: 'A bare JWK that carries an x5c',
    covers: 'OpenID Federation entity keys, SSF transmitter keys, ' +
      'claims-provider keys and GNAP cert keys.',
    adds: 'A JWK that carries an x5c is validated as a JOSE signer; a bare ' +
      'JWK is left alone.',
    sites: ['oidfed/entity_statement.ts', 'ssf/ssf_transmitters.ts',
            'oauth-oidc/claims_providers.ts', 'gnap/gnap_keys.ts'],
    anchors: ['registered-root', 'signer-truststore'],
    leaf: leaf(SIGNS),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [{ check: 'path',
                   spec: 'OpenID Federation 1.1 section 3: entity keys are ' +
                         'bare JWKs by design, when no x5c is present' }],
    baseline: 'none', code: 'STS-PKI-0247', phase: 3 },
  { id: 'encryption-recipient', setting: 'pki.paranoidEncryptionRecipient',
    title: 'An encryption recipient\'s certificate',
    covers: 'The certificate a SAML assertion is encrypted to, and a JWE ' +
      'recipient\'s x5c.',
    adds: 'Validity; keyUsage keyEncipherment or keyAgreement; revocation; ' +
      'nothing is ever encrypted to a certificate merely observed on a request.',
    sites: ['saml/saml2_sso.ts encryptionCertificateFor',
            'oauth-oidc/introspection_jwt.ts recipientKey'],
    anchors: ['registered-root', 'signer-truststore', 'pinned'],
    leaf: leaf(ENCIPHERS),
    selfSigned: 'allow-by-spec', validity: 'now', revocation: 'required',
    exemptions: [{ check: 'self-signed-allowed',
                   spec: 'SAML Metadata section 2.4.1.1, when it is registered ' +
                         'on the application' },
                 { check: 'path',
                   spec: 'RFC 7517 section 4.7 makes x5c optional, so a bare ' +
                         'JWK has no certificate to check' }],
    baseline: 'none', code: 'STS-PKI-0248', phase: 4 },
  { id: 'client-attestation', setting: 'pki.paranoidClientAttestation',
    title: 'An attestation-based client authentication chain',
    covers: 'The attester\'s certificate behind OAuth attestation-based client ' +
      'authentication.',
    adds: 'Revocation; keyUsage on the leaf.',
    sites: ['oauth-oidc/client_attestation.ts attesterKeys'],
    anchors: ['caller', 'signer-truststore'],
    leaf: leaf(SIGNS),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [], baseline: 'caller-path', code: 'STS-PKI-0249', phase: 5 },
  { id: 'webauthn-attestation', setting: 'pki.paranoidWebauthnAttestation',
    title: 'A WebAuthn attestation chain',
    covers: 'A passkey\'s attestation statement.',
    adds: 'Each format\'s extendedKeyUsage and keyUsage made explicit (the TPM ' +
      'AIK EKU required for tpm). Validity is evaluated at now, as before: an ' +
      'expired attestation certificate makes the statement untrusted.',
    sites: ['authn/webauthn_attestation.ts'],
    anchors: ['caller', 'signer-truststore'],
    leaf: leaf(SIGNS),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [],
    variants: { tpm: { leaf: { eku: { oids: [EKU.tcgAik], required: true } } } },
    baseline: 'caller-path', code: 'STS-PKI-0250', phase: 5 },
  { id: 'device-attestation', setting: 'pki.paranoidDeviceAttestation',
    title: 'A device attestation chain',
    covers: 'Android key attestation, Apple App Attest and TPM attestation of ' +
      'a registered device.',
    adds: 'OCSP or CRL for the Apple and TPM chains where the chain names any; ' +
      'the extendedKeyUsage each format asks.',
    sites: ['common/device_attestation.ts chainOf'],
    anchors: ['caller', 'signer-truststore'],
    leaf: leaf(SIGNS),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [],
    variants: { tpm: { leaf: { eku: { oids: [EKU.tcgAik], required: true } } } },
    baseline: 'caller-path', code: 'STS-PKI-0251', phase: 5 },
  { id: 'spiffe-svid', setting: 'pki.paranoidSpiffeSvid',
    title: 'An X509-SVID presented to the SPIRE Server or Broker API',
    covers: 'The X509-SVID a caller of the SPIRE Server API or the Broker API ' +
      'presents, and a federated SVID.',
    adds: 'The extendedKeyUsage X509-SVID section 4.3 recommends becomes ' +
      'required; a federated bundle\'s authority certificate is field-checked.',
    sites: ['spiffe/spiffe_auth.ts verifyPresentedCertificate',
            'spiffe/spiffe_ca.ts checkBundleDocument'],
    anchors: ['caller'],
    leaf: leaf(SIGNS, [EKU.clientAuth, EKU.serverAuth], true),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [{ check: 'revocation',
                   spec: 'A federated SVID: the federated authority publishes ' +
                         'nothing this service may dial' }],
    variants: { federated: { revocation: 'exempt-by-spec' } },
    baseline: 'direct', code: 'STS-PKI-0252', phase: 5 },
  { id: 'spiffe-attestation', setting: 'pki.paranoidSpiffeAttestation',
    title: 'A SPIFFE node attestor\'s certificate',
    covers: 'The x509pop, TPM DevID, Azure IMDS, AWS instance identity and ' +
      'sigstore attestors.',
    adds: 'Revocation where the chain names any; the keyUsage and ' +
      'extendedKeyUsage each attestor asks; the AWS pinned certificate\'s ' +
      'validity; the Azure AIA intermediate must chain before it is used.',
    sites: ['spiffe/spiffe_attestor_x509pop.ts',
            'spiffe/spiffe_attestor_tpm_devid.ts',
            'spiffe/spiffe_attestor_azure_imds.ts',
            'spiffe/spiffe_attestor_aws_iid.ts', 'spiffe/spiffe_sigstore.ts'],
    anchors: ['caller', 'signer-truststore', 'pinned'],
    leaf: leaf(SIGNS),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [{ check: 'validity',
                   spec: 'The Sigstore client specification evaluates a ' +
                         'certificate at its notBefore' }],
    variants: {
      sigstore: { validity: 'not-before-by-spec',
                  leaf: { eku: { oids: [EKU.codeSigning], required: true } } },
      aws: { selfSigned: 'allow-by-spec' },
      tpm: { leaf: { eku: { oids: [EKU.tcgAik], required: false } } }
    },
    baseline: 'caller-path', code: 'STS-PKI-0253', phase: 5 },
  { id: 'pkinit', setting: 'pki.paranoidPkinit',
    title: 'A PKINIT client certificate',
    covers: 'The client certificate in an RFC 4556 AS-REQ.',
    adds: 'Already full; the door makes it one call.',
    sites: ['kerberos/krb5_pkinit.ts checkCertificate'],
    anchors: ['caller'],
    leaf: leaf(SIGNS, [EKU.pkinitClientAuth, EKU.msSmartCardLogon], true),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [], baseline: 'caller-path', code: 'STS-PKI-0254', phase: 5 },
  { id: 'enrollment-credential', setting: 'pki.paranoidEnrollmentCredential',
    title: 'A certificate presented to enroll or renew',
    covers: 'The client certificate an EST request presents, and the signer ' +
      'of a SCEP renewal.',
    adds: 'Already full for EST; SCEP\'s self-signed PKCSReq signer gets the ' +
      'validity window.',
    sites: ['common/cert_enrollment.ts authenticatePresentedCertificate',
            'scep/scep_cms.ts verifySigner'],
    anchors: ['realm'],
    leaf: leaf(SIGNS, [EKU.clientAuth], true),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [{ check: 'path',
                   spec: 'RFC 8894 section 2.3: the PKCSReq signer is ' +
                         'self-signed by definition' }],
    variants: {
      scep: { selfSigned: 'allow-by-spec',
              leaf: { eku: { oids: [EKU.clientAuth], required: false } } }
    },
    baseline: 'realm-leaf', code: 'STS-PKI-0255', phase: 5 },
  { id: 'vc-key-attestation', setting: 'pki.paranoidVcKeyAttestation',
    title: 'An OpenID4VCI key attestation chain',
    covers: 'The x5c of a wallet\'s key attestation at the credential endpoint.',
    adds: 'A real path with intermediates, not one hop; revocation; keyUsage ' +
      'on the leaf.',
    sites: ['oid4vc/vc_issuer.ts verifyKeyAttestation'],
    anchors: ['caller', 'signer-truststore'],
    leaf: leaf(SIGNS),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [], baseline: 'direct', code: 'STS-PKI-0256', phase: 5 },
  { id: 'vc-issuer', setting: 'pki.paranoidVcIssuer',
    title: 'A credential issuer\'s or status-list signer\'s certificate',
    covers: 'An mdoc\'s IACA-to-DS chain, a CWT status-list signer, an OpenID4VP ' +
      'trusted issuer certificate and a foreign status list\'s signer.',
    adds: 'The ISO 18013-5 document-signer EKU and profile; revocation for the ' +
      'status-list signer; validity and a chain for a trusted-issuer ' +
      'certificate that is not self-signed.',
    sites: ['oid4vc/vc_mdoc.ts chainToAnchors', 'oid4vc/vc_verifier.ts',
            'oid4vc/vc_status.ts'],
    anchors: ['caller', 'signer-truststore', 'pinned'],
    leaf: leaf(SIGNS),
    selfSigned: 'allow-by-spec', validity: 'now', revocation: 'required',
    exemptions: [{ check: 'self-signed-allowed',
                   spec: 'A configured trusted-issuer certificate: OpenID4VP ' +
                         'trust is configured, not chained' }],
    variants: {
      mdoc: { selfSigned: 'refuse',
              leaf: { eku: { oids: [EKU.mdocDs], required: true } } }
    },
    baseline: 'none', code: 'STS-PKI-0257', phase: 5 },
  { id: 'cell-peer', setting: 'pki.paranoidCellPeer',
    title: 'The other cell at the inter-cell channel',
    covers: 'The certificate the other cell presents on the inter-cell ' +
      'channel, in both directions.',
    adds: 'Revocation from the register; clientAuth and serverAuth; the path ' +
      'rules.',
    sites: ['common/cell_channel.ts peerCellOf', 'common/cell_channel.ts dial'],
    anchors: ['realm'],
    leaf: leaf(TLS_SERVER_USAGE, [EKU.clientAuth, EKU.serverAuth], true),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [], baseline: 'peer-chain', code: 'STS-PKI-0258', phase: 1 },
  { id: 'ca-import', setting: 'pki.paranoidCaImport',
    title: 'A CA or key pair an operator imports',
    covers: 'The import of an operator\'s Root or Issuing CA at /admin/pki, and ' +
      'a pinned key pair.',
    adds: 'An imported Issuing CA must chain to the service Root; cA, ' +
      'keyCertSign, validity and pathLen; a pinned leaf is field-checked.',
    sites: ['common/pki.js importCa', 'common/pki.js pinKeyPair'],
    anchors: ['realm'],
    leaf: { keyUsage: ['keyCertSign'], eku: null, mayBeCa: true },
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [{ check: 'path',
                   spec: 'An imported Root is its own anchor' }],
    variants: {
      root: { selfSigned: 'allow-by-spec', revocation: 'exempt-by-spec' },
      pin: { leaf: { keyUsage: SIGNS, mayBeCa: false } }
    },
    baseline: 'none', code: 'STS-PKI-0259', phase: 1 },
  { id: 'anchor-admission', setting: 'pki.paranoidAnchorAdmission',
    title: 'Admission to a truststore',
    covers: 'What /admin/tls/trust, the signer truststore, tls.trustAnchorsFile ' +
      'and pki.signerTrustAnchorsFile accept.',
    adds: 'An anchor is a self-signed CA within validity whose self-signature ' +
      'verifies; an intermediate is a CA that chains to an anchor held; a leaf ' +
      'is refused from both. The signer truststore holds to this whatever the ' +
      'row says: it has no earlier behaviour to restore.',
    sites: ['tls/tls_server.js addAnchors', 'common/signer_truststore.ts add'],
    anchors: ['caller'],
    leaf: { keyUsage: ['keyCertSign'], eku: null, mayBeCa: true },
    selfSigned: 'allow-by-spec', validity: 'now', revocation: 'exempt-by-spec',
    exemptions: [{ check: 'revocation',
                   spec: 'An anchor is what revocation answers are believed ' +
                         'on, so no authority above it could revoke it' }],
    baseline: 'none', code: 'STS-PKI-0260', phase: 0 },
  { id: 'revocation-signer', setting: 'pki.paranoidRevocationSigner',
    title: 'An OCSP responder or CRL signer',
    covers: 'The delegated OCSP responder certificate and the CRL signer ' +
      'revocation answers are believed on.',
    adds: 'Already full; the door is asked so the checks are the same code.',
    sites: ['common/revocation_status.js'],
    anchors: ['caller'],
    leaf: leaf(SIGNS, [EKU.ocspSigning], true),
    selfSigned: 'refuse', validity: 'now', revocation: 'exempt-by-spec',
    exemptions: [{ check: 'revocation',
                   spec: 'RFC 6960 section 4.2.2.2.1: id-pkix-ocsp-nocheck' }],
    variants: { crl: { leaf: { keyUsage: ['cRLSign'], eku: null,
                               mayBeCa: true } } },
    baseline: 'none', code: 'STS-PKI-0261', phase: 5 },
  { id: 'fido-mds', setting: 'pki.paranoidFidoMds',
    title: 'The FIDO Metadata Service BLOB signer',
    covers: 'The signer of an imported FIDO MDS3 BLOB.',
    adds: 'Already full; the door is asked so the checks are the same code. ' +
      'The administrator\'s audited overrideSignature is unchanged.',
    sites: ['risk/risk_datasets.ts importMds'],
    anchors: ['caller', 'signer-truststore'],
    leaf: leaf(SIGNS),
    selfSigned: 'refuse', validity: 'now', revocation: 'required',
    exemptions: [], baseline: 'caller-path', code: 'STS-PKI-0262', phase: 5 }
];

const BY_ID: Json = {};
PURPOSES.forEach(function (one) {
  BY_ID[one.id] = one;
});

// Who has been told a check is off in product, once per process per setting.
// At most one name per row of this table, so it is bounded by construction.
const announced = new Set<string>();
// Per realm, per purpose: `{ assessed, refused, lastRefusal }`. Process-local.
const counts = new Map<string, Json>();
// Each owner's list of what it pins, registered at build.
const pinSources = new Map<string,
  (realmId: string) => Promise<PinnedSource[]> | PinnedSource[]>();
// What the audit last found, per realm; the page draws it and the job compares
// against it, so a restart does not re-announce every certificate.
const lastAudit = realms.map({ persist: 'pki.pins.lastAudit' });

realms.onRemove(function (id: string) {
  counts.delete(id);
});

// WHAT WAS LAST FETCHED ABOUT A PINNED CERTIFICATE, for the doors that cannot
// wait (`pinnedSync()`). Keyed by fingerprint, so it is about a certificate and
// not a realm, and the policy is applied when the answer was fetched: the
// lifetime is short for that reason.
const MAX_PIN_VERDICTS = 1024;
const PIN_VERDICT_MS = 300000;
const pinVerdicts = new Map<string, Json>();
const pinVerdictCount = cacheRegistry.register({
  name: 'pki.pinned-verdicts',
  title: 'Revocation of pinned certificates',
  description: 'What was last fetched about a pinned certificate, for the ' +
    'doors that answer in one tick under paranoid PKI mode. Keyed by the ' +
    'certificate\'s fingerprint.',
  owner: 'common/certificate_trust.ts', scope: 'process', kind: 'cache',
  bound: 'Enforced: 1024 entries, the oldest write dropped and fetched again ' +
         'when next needed.',
  maxEntries: function (): number {
    return MAX_PIN_VERDICTS;
  },
  lifetime: function (): string {
    return '5 minutes';
  },
  eject: cacheRegistry.mapEjector(pinVerdicts, function (row: Json, key: string,
                                                         nowMs: number) {
    return !row || row.until <= nowMs;
  }),
  entries: function (): Json[] {
    return Array.from(pinVerdicts.entries()).map(function (pair: Json) {
      return { realm: '', key: cacheRegistry.clipKey(pair[0]),
               validUntil: new Date(pair[1].until).toISOString(),
               valid: pair[1].until > Date.now(),
               basis: pair[1].verdict.status };
    });
  }
});

/**
 * The one door every X.509 validation goes through, and the settings of
 * paranoid PKI mode.
 *
 * A static utility class: `common/outbound_tls.ts`'s shape. It composes
 * `crypto.js`'s field checks, `pki.js`'s paths and `revocation_status.js`.
 */
class CertificateTrust {
  static readonly PURPOSES = PURPOSES;
  static readonly CHECK_ORDER = CHECK_ORDER;
  static readonly AUDIT_JOB = AUDIT_JOB;

  /**
   * One row of the purpose table.
   *
   * @param id - the purpose
   * @returns the row
   * @throws Error for a purpose the table does not name: a programming error
   */
  static purpose(id: string): Purpose {
    helpers.log.debug("Entering CertificateTrust.purpose().");
    const row = BY_ID[id];
    if (!row) {
      // error-code: none — a caller naming a purpose the table lacks is a bug
      throw new Error('certificate_trust: no such purpose "' + id + '"');
    }
    helpers.log.debug("Leaving CertificateTrust.purpose().");
    return row;
  }

  // Runs `fn` with the realm named as the ambient one.
  private static inRealm(realmId: string | undefined, fn: () => Json): Json {
    helpers.log.debug("Entering CertificateTrust.inRealm().");
    if (!realmId || realmId === realms.currentId()) {
      helpers.log.debug("Leaving CertificateTrust.inRealm().");
      return fn();
    }
    const realm = realms.get(realmId);
    helpers.log.debug("Leaving CertificateTrust.inRealm().");
    return realm ? realms.run(realm, fn) : fn();
  }

  /**
   * Whether the master is in force in a realm.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @returns `{ master, inForce, decidedBy }`
   */
  static inForce(realmId?: string): Json {
    helpers.log.debug("Entering CertificateTrust.inForce().");
    const answer = CertificateTrust.inRealm(realmId, function () {
      const master = String(config.value('pki.paranoid') || 'auto');
      const product = mode.enforcesParanoidPki();
      if (master === 'on' || master === 'off') {
        return { master: master, inForce: master === 'on',
                 decidedBy: 'pki.paranoid=' + master };
      }
      return { master: 'auto', inForce: product,
               decidedBy: 'pki.paranoid=auto in ' +
                          (product ? 'product' : 'development') + ' mode' };
    });
    helpers.log.debug("Leaving CertificateTrust.inForce().");
    return answer;
  }

  /**
   * Whether a purpose's own row is on.
   *
   * @param id - the purpose
   * @param realmId - the realm; the ambient one where omitted
   * @returns the row's value
   */
  static rowOn(id: string, realmId?: string): boolean {
    helpers.log.debug("Entering CertificateTrust.rowOn().");
    const setting = CertificateTrust.purpose(id).setting;
    const on = CertificateTrust.inRealm(realmId, function () {
      return config.value(setting) !== false;
    });
    helpers.log.debug("Leaving CertificateTrust.rowOn().");
    return on;
  }

  /**
   * Whether paranoid applies to a purpose: the master in force AND its row on.
   *
   * @param id - the purpose
   * @param realmId - the realm; the ambient one where omitted
   * @returns true when the door holds this use case to the full checks
   */
  static applies(id: string, realmId?: string): boolean {
    helpers.log.debug("Entering CertificateTrust.applies().");
    const inForce = CertificateTrust.inForce(realmId).inForce;
    const on = CertificateTrust.rowOn(id, realmId);
    CertificateTrust.announceIfOff(id, realmId);
    helpers.log.debug("Leaving CertificateTrust.applies().");
    return inForce && on;
  }

  // The log line of a check switched off in product: once per process per
  // setting, with nothing refused.
  private static announceIfOff(id: string, realmId?: string): void {
    helpers.log.debug("Entering CertificateTrust.announceIfOff().");
    CertificateTrust.inRealm(realmId, function () {
      if (!mode.isProduct()) {
        return;
      }
      const master = String(config.value('pki.paranoid') || 'auto');
      if (master === 'off') {
        CertificateTrust.announce('pki.paranoid');
      } else if (!CertificateTrust.rowOn(id)) {
        CertificateTrust.announce(CertificateTrust.purpose(id).setting);
      }
    });
    helpers.log.debug("Leaving CertificateTrust.announceIfOff().");
  }

  private static announce(setting: string): void {
    helpers.log.debug("Entering CertificateTrust.announce(). " + setting);
    if (!announced.has(setting)) {
      announced.add(setting);
      helpers.log.warn(errorCodes.tag('STS-PKI-0239') + 'pki: ' + setting +
        ' is off in product mode, so that use case is not held to the checks ' +
        'of paranoid PKI mode. /admin/pki/trust draws it red. Said once per ' +
        'process.');
    }
    helpers.log.debug("Leaving CertificateTrust.announce().");
  }

  /**
   * Which settings have been announced as off in this process.
   *
   * @returns the settings
   */
  static announcedSettings(): string[] {
    helpers.log.debug("Entering CertificateTrust.announcedSettings().");
    helpers.log.debug("Leaving CertificateTrust.announcedSettings().");
    return Array.from(announced);
  }

  /**
   * The write rule of the paranoid rows: it refuses nothing, because an
   * operator may have a reason, and it is the one place a write that turns a
   * check off in product is logged.
   *
   * @param key - the setting
   * @param parsed - the value being written
   * @returns null, always
   */
  static writeRule(key: string, parsed: unknown): null {
    helpers.log.debug("Entering CertificateTrust.writeRule().");
    if (/^pki\.paranoid/.test(key) && mode.isProduct() &&
        (parsed === false || parsed === 'off')) {
      CertificateTrust.announce(key);
    }
    helpers.log.debug("Leaving CertificateTrust.writeRule().");
    return null;
  }

  // What a purpose asks in one of its variants.
  private static ruleOf(purpose: Purpose, variant?: string): Json {
    helpers.log.debug("Entering CertificateTrust.ruleOf().");
    const v = (variant && purpose.variants && purpose.variants[variant]) || {};
    helpers.log.debug("Leaving CertificateTrust.ruleOf().");
    return {
      leaf: Object.assign({}, purpose.leaf, v.leaf || {}),
      selfSigned: v.selfSigned || purpose.selfSigned,
      validity: v.validity || purpose.validity,
      revocation: v.revocation || purpose.revocation,
      softRevocation: !!(v as Json).softRevocation
    };
  }

  // A verdict that has decided nothing yet: every check not asked.
  private static blank(id: string, inForce: boolean): TrustVerdict {
    helpers.log.debug("Entering CertificateTrust.blank().");
    const checks: Json = {};
    CHECK_ORDER.forEach(function (check) {
      checks[check] = 'not-asked';
    });
    helpers.log.debug("Leaving CertificateTrust.blank().");
    return { ok: false, purpose: id, inForce: inForce, anchor: 'none',
             path: [], revocation: null, checks: checks, code: '', why: '' };
  }

  // Every spelling of a certificate as DER, or null.
  private static derOf(cert: Json): Buffer | null {
    helpers.log.debug("Entering CertificateTrust.derOf().");
    try {
      // A string with no armour is an `x5c` member: base64 DER.
      const text = Buffer.isBuffer(cert) || cert instanceof Uint8Array ? '' :
        String(cert);
      helpers.log.debug("Leaving CertificateTrust.derOf().");
      return stsCrypto.parseCertificate(
        Buffer.isBuffer(cert) || cert instanceof Uint8Array ? cert :
          (/-----BEGIN/.test(text) ? text : Buffer.from(text, 'base64'))).raw;
    } catch (e) {
      helpers.log.debug("Caught in CertificateTrust.derOf(): " +
                        ((e && e.message) || e));
      helpers.log.debug("Leaving CertificateTrust.derOf().");
      return null;
    }
    helpers.log.debug("Leaving CertificateTrust.derOf().");
  }

  // The material's leaf and chain, read from whichever member carries them.
  // A peer certificate is `getPeerCertificate(true)`'s linked list.
  private static certificatesOf(material: Json): Json {
    helpers.log.debug("Entering CertificateTrust.certificatesOf().");
    const m = material || {};
    const chain: Buffer[] = [];
    let leafDer: Buffer | null = null;
    if (m.peer && m.peer.raw) {
      leafDer = Buffer.from(m.peer.raw);
      let link = m.peer.issuerCertificate;
      const seen = [m.peer];
      while (link && link.raw && seen.indexOf(link) === -1 &&
             chain.length < 16) {
        seen.push(link);
        chain.push(Buffer.from(link.raw));
        link = link.issuerCertificate;
      }
    } else {
      leafDer = CertificateTrust.derOf(m.leaf);
    }
    const given = (m.chain || []).map(CertificateTrust.derOf);
    if (!leafDer || given.indexOf(null) !== -1) {
      helpers.log.debug("Leaving CertificateTrust.certificatesOf().");
      return null;
    }
    helpers.log.debug("Leaving CertificateTrust.certificatesOf().");
    return { leaf: leafDer, chain: chain.concat(given) };
  }

  // Can the field checks read it? Node's parser and pkijs disagree about some
  // malformed certificates, and a verdict is what the door promises for a bad
  // certificate, never a throw (x509-limbo found one that reached it).
  private static readable(der: Buffer, chain?: Buffer[]): boolean {
    helpers.log.debug("Entering CertificateTrust.readable().");
    try {
      [der].concat(chain || []).forEach(function (one) {
        stsCrypto.certificateFacts(one);
      });
      helpers.log.debug("Leaving CertificateTrust.readable().");
      return true;
    } catch (e) {
      helpers.log.debug("Caught in CertificateTrust.readable(): " +
                        ((e && e.message) || e));
      helpers.log.debug("Leaving CertificateTrust.readable().");
      return false;
    }
    helpers.log.debug("Leaving CertificateTrust.readable().");
  }

  private static pemOf(der: Buffer): string {
    helpers.log.debug("Entering CertificateTrust.pemOf().");
    helpers.log.debug("Leaving CertificateTrust.pemOf().");
    return pki.certificateFromDer(der).pem;
  }

  private static stepOf(der: Buffer): Json {
    helpers.log.debug("Entering CertificateTrust.stepOf().");
    const facts = stsCrypto.certificateFacts(der);
    helpers.log.debug("Leaving CertificateTrust.stepOf().");
    return { der: der, subject: facts.subject,
             fingerprint256: facts.fingerprint256 };
  }

  private static async isSelfSigned(der: Buffer): Promise<boolean> {
    helpers.log.debug("Entering CertificateTrust.isSelfSigned().");
    const entry = pki.certificateFromDer(der);
    if (entry.x509.subject !== entry.x509.issuer) {
      helpers.log.debug("Leaving CertificateTrust.isSelfSigned().");
      return false;
    }
    helpers.log.debug("Leaving CertificateTrust.isSelfSigned().");
    return !!(await pki.pathSigned(entry, entry));
  }

  // Tries each anchor source the purpose may reach, first success winning.
  private static async buildPath(purpose: Purpose, rule: Json, certs: Json,
                                 material: Json, opts: Json,
                                 realmId: string): Promise<Json> {
    const { log } = helpers;
    log.debug("Entering CertificateTrust.buildPath().");
    const pathOpts = { now: opts.now, skewMs: opts.skewMs,
                       allowCritical: opts.allowCritical, realmId: realmId,
                       purpose: purpose.id, allowSha1: opts.allowSha1,
                       policy: opts.policy };
    const sources = opts.anchorSources || purpose.anchors;
    let failure: Json = null;
    const note = function (result: Json): void {
      // The last refusal that says something about THIS certificate outranks
      // a source that simply held nothing.
      if (!failure || (result.check !== 'no-anchor' &&
                       result.check !== 'no-path')) {
        failure = result;
      }
    };
    const m = material || {};
    for (let i = 0; i < sources.length; i++) {
      const source = sources[i];
      let result: Json = null;
      if (source === 'realm') {
        if (rule.leaf.mayBeCa) {
          result = await pki.verifyPathToAnchors(certs.leaf, certs.chain,
                                                 'realm', pathOpts);
        } else {
          const leafy = await pki.verifyLeaf(realmId,
            CertificateTrust.pemOf(certs.leaf),
            certs.chain.map(CertificateTrust.pemOf), { revocation: false });
          result = leafy.ok ?
            { ok: true, chain: [certs.leaf].concat(certs.chain)
              .map(function (der: Buffer) {
                return { der: der };
              }) } :
            { ok: false, check: 'no-path', reason: leafy.why };
        }
      } else if (source === 'registered-root') {
        const registered = m.registered && (m.registered.chain || []);
        const roots = (registered || []).map(CertificateTrust.derOf)
          .filter(Boolean).filter(function (der: Buffer) {
            const entry = pki.certificateFromDer(der);
            return entry.x509.subject === entry.x509.issuer;
          }).map(function (der: Buffer) {
            return pki.certificateFromDer(der);
          });
        if (roots.length) {
          result = await pki.verifyPathToAnchors(certs.leaf,
            registered.map(CertificateTrust.derOf).filter(Boolean)
              .concat(certs.chain), roots, pathOpts);
        }
      } else if (source === 'signer-truststore') {
        result = await pki.verifyPathToAnchors(certs.leaf, certs.chain,
                                               'signer-truststore', pathOpts);
      } else if (source === 'client-truststore') {
        // OpenSSL built this one against the truststore; the verdict it gave
        // is the caller's to hand over, and the rules are asked here.
        if (m.peer && m.verified === true) {
          const problem = pki.peerChainProblem(m.peer);
          result = problem ?
            { ok: false, check: problem.check, reason: problem.why } :
            { ok: true, chain: [certs.leaf].concat(certs.chain)
              .map(function (der: Buffer) {
                return { der: der };
              }) };
        }
      } else if (source === 'caller') {
        const roots = (opts.anchors || []).map(CertificateTrust.derOf)
          .filter(Boolean).map(function (der: Buffer) {
            return pki.certificateFromDer(der);
          });
        if (roots.length) {
          result = await pki.verifyPathToAnchors(certs.leaf, certs.chain,
                                                 roots, pathOpts);
        }
      }
      if (result && result.ok) {
        log.debug("Leaving CertificateTrust.buildPath(). " + source);
        return { ok: true, anchor: source, chain: result.chain };
      }
      if (result) {
        note(result);
      }
    }
    log.debug("Leaving CertificateTrust.buildPath(). None reached.");
    return failure || { ok: false, check: 'no-anchor',
                        reason: 'no anchor this use case may reach was ' +
                                'configured' };
  }

  // Fills the field checks in, marking the ones the certificate failed. A use
  // case that asks nothing of a field passes it: see the header.
  private static fieldChecks(verdict: TrustVerdict, der: Buffer, rule: Json,
                             opts: Json, mayBeCa: boolean): Json[] {
    helpers.log.debug("Entering CertificateTrust.fieldChecks().");
    const options: Json = Object.assign({}, rule.leaf, {
      role: 'leaf', now: opts.now, skewMs: opts.skewMs,
      allowSha1: opts.allowSha1, allowCritical: opts.allowCritical,
      mayBeCa: mayBeCa || rule.leaf.mayBeCa
    });
    if (rule.validity === 'not-before-by-spec') {
      options.validityAt = stsCrypto.certificateFacts(der).notBefore;
      verdict.checks.validity = 'exempt-by-spec';
    }
    const problems = stsCrypto.certificateFieldProblems(der, options);
    ['validity', 'basic-constraints', 'key-usage', 'extended-key-usage',
     'signature-strength', 'key-strength', 'critical-extensions']
      .forEach(function (check) {
        if (verdict.checks[check] === 'not-asked') {
          verdict.checks[check] = 'passed';
        }
      });
    problems.forEach(function (one: Json) {
      verdict.checks[one.check] = 'failed';
    });
    helpers.log.debug("Leaving CertificateTrust.fieldChecks().");
    return problems;
  }

  // Does this certificate carry the name the caller expected?
  private static nameMatches(der: Buffer, expected: Json): boolean {
    helpers.log.debug("Entering CertificateTrust.nameMatches().");
    const { dn } = expected;
    const others = Object.assign({}, expected);
    delete others.dn;
    const sanAsked = Object.keys(others).some(function (key) {
      return !!others[key];
    });
    if (sanAsked && !stsCrypto.certificateNameMatches(der, others)) {
      helpers.log.debug("Leaving CertificateTrust.nameMatches().");
      return false;
    }
    if (dn) {
      const parsed = stsCrypto.parseCertificate(der);
      helpers.log.debug("Leaving CertificateTrust.nameMatches().");
      return certificateSubject.normalDn(String(dn)) ===
             certificateSubject.normalDn(
               certificateSubject.subjectOf(parsed).text);
    }
    helpers.log.debug("Leaving CertificateTrust.nameMatches().");
    return sanAsked;
  }

  // Sets the verdict's outcome from its checks, and counts it.
  private static compose(purpose: Purpose, verdict: TrustVerdict,
                         codes: Json, whys: Json, realmId: string,
                         quiet: boolean): TrustVerdict {
    helpers.log.debug("Entering CertificateTrust.compose().");
    // What FAILED is named before what nobody asked: a check not asked is
    // usually only not asked because an earlier one ended the walk.
    const failed = CHECK_ORDER.filter(function (check) {
      return verdict.checks[check] === 'failed';
    }).concat(CHECK_ORDER.filter(function (check) {
      return verdict.checks[check] === 'not-asked' && verdict.inForce &&
             check !== 'name-match';
    }));
    verdict.ok = failed.length === 0;
    if (!verdict.ok) {
      const first = failed[0];
      verdict.code = codes[first] || purpose.code;
      verdict.why = whys[first] ||
        'nothing established "' + first + '" for ' + purpose.id;
    }
    if (!quiet) {
      CertificateTrust.count(purpose, verdict, realmId);
    }
    helpers.log.debug("Leaving CertificateTrust.compose().");
    return verdict;
  }

  private static count(purpose: Purpose, verdict: TrustVerdict,
                       realmId: string): void {
    helpers.log.debug("Entering CertificateTrust.count().");
    let realm = counts.get(realmId);
    if (!realm) {
      realm = {};
      counts.set(realmId, realm);
    }
    const row = realm[purpose.id] ||
      { assessed: 0, refused: 0, lastRefusal: null };
    realm[purpose.id] = row;
    row.assessed += 1;
    if (!verdict.ok) {
      row.refused += 1;
      row.lastRefusal = { code: verdict.code, why: verdict.why,
                          at: Date.now() };
      if (verdict.inForce) {
        audit.failure(verdict.code, {
          action: 'service.failure', protocol: purpose.id, channel: 'internal',
          // error-code: none — `verdict.code` is this row's code
          summary: verdict.why, outcome: 'refused',
          // One member per check: a row's values are short scalars.
          detail: Object.assign({ purpose: purpose.id }, verdict.checks)
        });
      }
    }
    helpers.log.debug("Leaving CertificateTrust.count().");
  }

  // THE BASELINE: what the site did before #1360, through the same central
  // function, with the checks it never made left `not-asked`.
  private static async baseline(purpose: Purpose, certs: Json, material: Json,
                                opts: Json, realmId: string,
                                quiet: boolean): Promise<TrustVerdict> {
    helpers.log.debug("Entering CertificateTrust.baseline(). " + purpose.id);
    const verdict = CertificateTrust.blank(purpose.id, false);
    const codes: Json = {};
    const whys: Json = {};
    const m = material || {};
    const refuse = function (check: string, code: string, why: string): void {
      verdict.checks[check] = 'failed';
      codes[check] = code;
      whys[check] = why;
    };
    if (purpose.baseline === 'peer-chain' && m.peer) {
      const problem = pki.peerChainProblem(m.peer);
      if (problem) {
        refuse('path', RULE_CODES[problem.check] || 'STS-PKI-0198',
               problem.why);
      } else {
        verdict.checks.path = 'passed';
      }
    } else if (purpose.baseline === 'signer-chain') {
      const result = await pki.verifySignerChain(realmId, {
        certificate: CertificateTrust.pemOf(certs.leaf),
        chain: certs.chain.map(CertificateTrust.pemOf),
        key: m.key, source: m.source
      });
      if (result.ok) {
        verdict.checks.path = 'passed';
        verdict.anchor = result.anchor === 'pinned' ? 'pinned' :
          (result.anchor === 'realm' ? 'realm' : 'registered-root');
      } else {
        refuse('path', errorCodes.codeOf(result) || purpose.code, result.why);
      }
    } else if (purpose.baseline === 'caller-path') {
      const roots = (opts.anchors || []).map(CertificateTrust.derOf)
        .filter(Boolean).map(function (der: Buffer) {
          return pki.certificateFromDer(der);
        });
      const result = await pki.verifyPathToAnchors(certs.leaf, certs.chain,
        roots, { now: opts.now, skewMs: opts.skewMs });
      if (result.ok) {
        verdict.checks.path = 'passed';
        verdict.anchor = 'caller';
      } else {
        refuse('path', purpose.code, result.reason);
      }
    } else if (purpose.baseline === 'direct') {
      const result = pki.verifyIssuedDirectly(certs.leaf, opts.anchors || [],
        { now: opts.now, skewMs: opts.skewMs });
      if (result.ok) {
        verdict.checks.path = 'passed';
        verdict.anchor = 'caller';
      } else {
        refuse('path', purpose.code, result.reason);
      }
    } else if (purpose.baseline === 'realm-leaf') {
      const result = await pki.verifyLeaf(realmId,
        CertificateTrust.pemOf(certs.leaf),
        certs.chain.map(CertificateTrust.pemOf), {});
      if (result.ok) {
        verdict.checks.path = 'passed';
        verdict.anchor = 'realm';
        verdict.revocation = result.revocation || null;
      } else {
        refuse('path', errorCodes.codeOf(result) || purpose.code, result.why);
      }
    }
    helpers.log.debug("Leaving CertificateTrust.baseline().");
    return CertificateTrust.compose(purpose, verdict, codes, whys, realmId,
                                    quiet);
  }

  /**
   * THE DOOR. Holds a certificate to what its use case asks and answers one
   * verdict. Never rejects for a bad certificate; a verdict says so.
   *
   * @param id - the purpose
   * @param material - `{ leaf, chain, key, registered: { chain }, pinned,
   *   peer, verified, source }`; `peer` is `getPeerCertificate(true)`
   * @param options - `{ realmId, now, skewMs, expectName, anchors,
   *   anchorSources (only narrower), allowCritical, allowSha1, variant, role,
   *   heldAnchors, force }`; `force` holds it to the checks whatever the
   *   settings say, for the inventory, and neither counts nor audits it
   * @returns a promise of the verdict
   */
  static async assess(id: string, material: Json,
                      options?: Json): Promise<TrustVerdict> {
    const { log } = helpers;
    log.debug("Entering CertificateTrust.assess(). " + id);
    const purpose = CertificateTrust.purpose(id);
    const opts = options || {};
    const realmId = opts.realmId || realms.currentId();
    const quiet = !!opts.force;
    const verdict = await CertificateTrust.inRealm(realmId, async function () {
      const inForce = quiet || CertificateTrust.applies(id, realmId);
      const certs = CertificateTrust.certificatesOf(material);
      const blank = CertificateTrust.blank(id, inForce);
      if (!certs) {
        blank.checks.path = 'failed';
        return CertificateTrust.compose(purpose, blank,
          { path: 'STS-PKI-0238' },
          { path: 'what was handed to the door is not an X.509 certificate' },
          realmId, quiet);
      }
      if (!inForce) {
        return CertificateTrust.baseline(purpose, certs, material, opts,
                                         realmId, quiet);
      }
      if (!CertificateTrust.readable(certs.leaf, certs.chain)) {
        blank.checks.path = 'failed';
        return CertificateTrust.compose(purpose, blank,
          { path: 'STS-PKI-0238' },
          { path: 'what was handed to the door cannot be read as X.509' },
          realmId, quiet);
      }
      if (id === 'anchor-admission') {
        return CertificateTrust.assessAdmission(purpose, blank, certs, opts,
                                                realmId, quiet);
      }
      return CertificateTrust.assessInForce(purpose, blank, certs, material,
                                            opts, realmId, quiet);
    });
    log.debug("Leaving CertificateTrust.assess(). " + verdict.ok);
    return verdict;
  }

  // Admission is one function, `pki.anchorProblem()`, whatever store asks.
  private static async assessAdmission(purpose: Purpose, verdict: TrustVerdict,
                                       certs: Json, opts: Json, realmId: string,
                                       quiet: boolean): Promise<TrustVerdict> {
    helpers.log.debug("Entering CertificateTrust.assessAdmission().");
    const problem = await pki.anchorProblem(certs.leaf, {
      role: opts.role, heldAnchors: opts.heldAnchors, now: opts.now
    });
    CHECK_ORDER.forEach(function (check) {
      verdict.checks[check] = 'passed';
    });
    verdict.checks.revocation = 'exempt-by-spec';
    verdict.checks['name-match'] = 'not-asked';
    const codes: Json = {};
    const whys: Json = {};
    if (problem) {
      verdict.checks.path = 'failed';
      codes.path = problem.code;
      whys.path = problem.why;
    }
    verdict.anchor = 'caller';
    helpers.log.debug("Leaving CertificateTrust.assessAdmission().");
    return CertificateTrust.compose(purpose, verdict, codes, whys, realmId,
                                    quiet);
  }

  // The full checks: `assess()` under paranoid.
  private static async assessInForce(purpose: Purpose, verdict: TrustVerdict,
                                     certs: Json, material: Json, opts: Json,
                                     realmId: string,
                                     quiet: boolean): Promise<TrustVerdict> {
    helpers.log.debug("Entering CertificateTrust.assessInForce().");
    const rule = CertificateTrust.ruleOf(purpose, opts.variant);
    const m = material || {};
    const codes: Json = {};
    const whys: Json = {};
    const selfSigned = await CertificateTrust.isSelfSigned(certs.leaf);
    // A self-signed leaf is accepted only where the table says the
    // specification defines the method that way, and only when it is the one
    // registered: a stranger's self-signed certificate is not a pin.
    const pinned = selfSigned && rule.selfSigned === 'allow-by-spec' &&
      (m.pinned === true || !!m.registered || purpose.anchors.length === 1);
    const problems = CertificateTrust.fieldChecks(verdict, certs.leaf, rule,
                                                  opts, pinned);
    problems.forEach(function (one: Json) {
      if (!codes[one.check]) {
        codes[one.check] = one.code;
        whys[one.check] = one.why;
      }
    });
    let chain: Buffer[] = [certs.leaf];
    if (pinned) {
      verdict.anchor = 'pinned';
      verdict.checks.path = 'exempt-by-spec';
      verdict.checks['self-signed-allowed'] = 'exempt-by-spec';
      verdict.checks['name-constraints'] = 'exempt-by-spec';
    } else if (selfSigned && !rule.leaf.mayBeCa &&
               rule.selfSigned === 'refuse') {
      verdict.checks['self-signed-allowed'] = 'failed';
      verdict.checks.path = 'failed';
      codes['self-signed-allowed'] = purpose.code;
      whys['self-signed-allowed'] = 'a self-signed certificate is not ' +
        'accepted for ' + purpose.id;
    } else if (selfSigned && rule.selfSigned === 'allow-by-spec') {
      verdict.checks['self-signed-allowed'] = 'failed';
      verdict.checks.path = 'failed';
      codes['self-signed-allowed'] = purpose.code;
      whys['self-signed-allowed'] = 'a self-signed certificate is accepted ' +
        'for ' + purpose.id + ' only when it is the one registered';
    } else {
      verdict.checks['self-signed-allowed'] = 'passed';
      const built = await CertificateTrust.buildPath(purpose, rule, certs, m,
                                                     opts, realmId);
      if (built.ok) {
        verdict.anchor = built.anchor;
        verdict.checks.path = 'passed';
        verdict.checks['name-constraints'] = 'passed';
        chain = built.chain.map(function (step: Json) {
          return step.der;
        });
      } else {
        const named = RULE_CHECKS[built.check] || 'path';
        verdict.checks.path = 'failed';
        verdict.checks[named] = 'failed';
        // The leaf's own field failing says it better, if it did.
        codes[named] = codes[named] || RULE_CODES[built.check] || purpose.code;
        whys[named] = whys[named] || built.reason;
        codes.path = codes.path || RULE_CODES[built.check] || purpose.code;
        whys.path = whys.path || built.reason;
        verdict.checks['name-constraints'] = named === 'name-constraints' ?
          'failed' : 'not-asked';
      }
    }
    verdict.path = chain.map(CertificateTrust.stepOf);
    if (opts.expectName) {
      verdict.checks['name-match'] =
        CertificateTrust.nameMatches(certs.leaf, opts.expectName) ?
          'passed' : 'failed';
      if (verdict.checks['name-match'] === 'failed') {
        whys['name-match'] = 'the certificate does not carry the name expected';
      }
    }
    await CertificateTrust.revocationCheck(verdict, rule, chain, certs, codes,
                                           whys);
    helpers.log.debug("Leaving CertificateTrust.assessInForce().");
    return CertificateTrust.compose(purpose, verdict, codes, whys, realmId,
                                    quiet);
  }

  // Revocation, once there is a path to ask about: the issuer comes from that
  // path, so an address inside the leaf is never what decides who answers.
  private static async revocationCheck(verdict: TrustVerdict, rule: Json,
                                       chain: Buffer[], certs: Json,
                                       codes: Json, whys: Json): Promise<void> {
    helpers.log.debug("Entering CertificateTrust.revocationCheck().");
    if (rule.revocation === 'exempt-by-spec') {
      verdict.checks.revocation = 'exempt-by-spec';
      helpers.log.debug("Leaving CertificateTrust.revocationCheck().");
      return;
    }
    if (verdict.checks.path !== 'passed' &&
        verdict.checks.path !== 'exempt-by-spec') {
      helpers.log.debug("Leaving CertificateTrust.revocationCheck().");
      return;
    }
    const answer = await revocationStatus.verdictFor(
      { leaf: certs.leaf, chain: chain.slice(1), verified: true }, {});
    CertificateTrust.readRevocation(verdict, answer, codes, whys);
    CertificateTrust.nothingToAsk(verdict, [certs.leaf].concat(chain.slice(1)));
    helpers.log.debug("Leaving CertificateTrust.revocationCheck().");
  }

  private static readRevocation(verdict: TrustVerdict, answer: Json,
                                codes: Json, whys: Json): void {
    helpers.log.debug("Entering CertificateTrust.readRevocation().");
    verdict.revocation = answer;
    if (answer.refused) {
      verdict.checks.revocation = 'failed';
      codes.revocation = revocationStatus.codeOf(answer) ||
                         revocationStatus.CODE_REVOKED;
      whys.revocation = answer.why;
    } else if (answer.status === 'unchecked') {
      // `pki.revocationCheck=off`: a check nobody made.
      verdict.checks.revocation = 'not-asked';
      whys.revocation = 'revocation was not consulted ' +
                        '(pki.revocationCheck is off)';
    } else if ((answer.unknown || []).some(function (one: Json) {
      return one.kind === 'not-consulted';
    })) {
      verdict.checks.revocation = 'not-asked';
      whys.revocation = 'this door cannot wait for a revocation fetch';
    } else {
      verdict.checks.revocation = 'passed';
    }
    helpers.log.debug("Leaving CertificateTrust.readRevocation().");
  }

  /**
   * The synchronous door, for a site that cannot wait: a one-hop path through
   * `verifyIssuedDirectly()` and the register alone. A purpose whose
   * revocation needs a fetch answers `not-asked`, which paranoid refuses: the
   * right answer here, since such a caller must move to `assess()`.
   *
   * @param id - the purpose
   * @param material - `{ leaf, chain }`
   * @param options - as `assess()`; `anchors` are the authorities
   * @returns the verdict
   */
  static assessSync(id: string, material: Json, options?: Json): TrustVerdict {
    const { log } = helpers;
    log.debug("Entering CertificateTrust.assessSync(). " + id);
    const purpose = CertificateTrust.purpose(id);
    const opts = options || {};
    const realmId = opts.realmId || realms.currentId();
    const verdict = CertificateTrust.inRealm(realmId, function () {
      const inForce = CertificateTrust.applies(id, realmId);
      const answer = CertificateTrust.blank(id, inForce);
      const codes: Json = {};
      const whys: Json = {};
      const certs = CertificateTrust.certificatesOf(material);
      if (!certs || (inForce && !CertificateTrust.readable(certs.leaf))) {
        answer.checks.path = 'failed';
        codes.path = 'STS-PKI-0238';
        whys.path = 'what was handed to the door is not an X.509 certificate';
        return CertificateTrust.compose(purpose, answer, codes, whys, realmId,
                                        false);
      }
      // A pin (RFC 8705 section 2.2, GNAP pinned) has no path to walk: the
      // method is equality, which the caller has just established. The
      // baseline `none` is what those sites asked before: nothing.
      const rule0 = CertificateTrust.ruleOf(purpose, opts.variant);
      const pinned = rule0.selfSigned === 'allow-by-spec' &&
                     (material || {}).pinned === true;
      if (!inForce && purpose.baseline === 'none') {
        return CertificateTrust.compose(purpose, answer, codes, whys, realmId,
                                        false);
      }
      const direct: Json = pinned ? { ok: true, chain: [] } :
        pki.verifyIssuedDirectly(certs.leaf, opts.anchors || [],
          { now: opts.now, skewMs: opts.skewMs,
            allowCritical: opts.allowCritical });
      if (pinned) {
        answer.checks.path = 'exempt-by-spec';
        answer.checks['name-constraints'] = 'exempt-by-spec';
        answer.anchor = 'pinned';
      } else if (direct.ok) {
        answer.checks.path = 'passed';
        answer.checks['name-constraints'] = 'passed';
        answer.anchor = 'caller';
      } else {
        answer.checks.path = 'failed';
        codes.path = purpose.code;
        whys.path = direct.reason;
      }
      if (inForce) {
        const rule = CertificateTrust.ruleOf(purpose, opts.variant);
        answer.checks['self-signed-allowed'] = 'passed';
        CertificateTrust.fieldChecks(answer, certs.leaf, rule, opts, pinned)
          .forEach(function (one: Json) {
            codes[one.check] = codes[one.check] || one.code;
            whys[one.check] = whys[one.check] || one.why;
          });
        if (rule.revocation === 'exempt-by-spec') {
          answer.checks.revocation = 'exempt-by-spec';
        } else if (direct.ok) {
          const chain = (direct.chain || []).slice(1).map(function (one: Json) {
            return one.der || one;
          });
          CertificateTrust.readRevocation(answer,
            revocationStatus.localVerdictFor(
              { leaf: certs.leaf, chain: chain, verified: true }),
            codes, whys);
          CertificateTrust.nothingToAsk(answer, [certs.leaf].concat(chain));
        }
      }
      return CertificateTrust.compose(purpose, answer, codes, whys, realmId,
                                      false);
    });
    log.debug("Leaving CertificateTrust.assessSync(). " + verdict.ok);
    return verdict;
  }

  /**
   * THE HOLD ON A HANDSHAKE: what can be decided while OpenSSL's verdict is
   * being read, before any request on the connection is. OpenSSL built the
   * path, so this asks the rules of it, and under paranoid the leaf's fields.
   * Not in force, it is the baseline: the rules alone, which is what
   * `holdToPathRules()` asked before #1360. Revocation is a fetch, so a
   * listener asks it apart (`tls_server.js`'s `holdConnectionsOn()`), except
   * `options.register`, this service's own register, which has no network.
   *
   * @param id - the purpose: `tls-client` or `cell-peer`
   * @param peer - `getPeerCertificate(true)`
   * @param options - `{ realmId, now, register }`
   * @returns `{ ok, inForce, check, code, why }`
   */
  static holdPeer(id: string, peer: Json, options?: Json): Json {
    helpers.log.debug("Entering CertificateTrust.holdPeer(). " + id);
    const opts = options || {};
    const purpose = CertificateTrust.purpose(id);
    const inForce = CertificateTrust.applies(id, opts.realmId);
    const rule = pki.peerChainProblem(peer);
    if (rule) {
      helpers.log.debug("Leaving CertificateTrust.holdPeer(). A path rule.");
      return { ok: false, inForce: inForce, check: rule.check,
               code: 'STS-PKI-0198', why: rule.why };
    }
    if (!inForce) {
      helpers.log.debug("Leaving CertificateTrust.holdPeer(). The baseline.");
      return { ok: true, inForce: false, check: '', code: '', why: '' };
    }
    const read = CertificateTrust.certificatesOf({ peer: peer });
    const certs = read && CertificateTrust.readable(read.leaf) ? read : null;
    const named = !!certs &&
      CertificateTrust.acceptedByName(id, certs.leaf, opts);
    const field = certs && stsCrypto.certificateFieldProblem(certs.leaf,
      Object.assign({}, purpose.leaf, { role: 'leaf', now: opts.now,
                                        mayBeCa: named }));
    if (!certs || field) {
      helpers.log.debug("Leaving CertificateTrust.holdPeer(). A field.");
      return { ok: false, inForce: true,
               check: field ? field.check : 'path',
               code: field ? field.code : 'STS-PKI-0238',
               why: field ? field.why :
                 'what was presented is not an X.509 certificate' };
    }
    const facts = stsCrypto.certificateFacts(certs.leaf);
    if (facts.selfIssued && !facts.ca && !named) {
      helpers.log.debug("Leaving CertificateTrust.holdPeer(). Self-signed.");
      return { ok: false, inForce: true, check: 'self-signed-allowed',
               code: purpose.code,
               why: '"' + facts.subject + '" is a self-signed leaf, which ' +
                    'is not accepted for ' + id };
    }
    if (opts.register) {
      const answer = revocationStatus.localVerdictFor(
        { leaf: certs.leaf, chain: certs.chain, verified: true });
      if (answer.refused) {
        helpers.log.debug("Leaving CertificateTrust.holdPeer(). Revoked.");
        return { ok: false, inForce: true, check: 'revocation',
                 code: revocationStatus.codeOf(answer) ||
                       revocationStatus.CODE_REVOKED, why: answer.why };
      }
    }
    helpers.log.debug("Leaving CertificateTrust.holdPeer(). Holds.");
    return { ok: true, inForce: true, check: '', code: '', why: '' };
  }

  // Subject and key, which is what makes a certificate the same trust anchor
  // as another: a cross-signed copy of a root differs in nothing that matters.
  private static anchorIdOf(der: Json): string {
    helpers.log.debug("Entering CertificateTrust.anchorIdOf().");
    const facts = stsCrypto.certificateFacts(der);
    helpers.log.debug("Leaving CertificateTrust.anchorIdOf().");
    return facts.subject + '|' + facts.spkiSha256;
  }

  // Node's bundled roots, indexed once: they cannot change while it runs.
  private static bundledAnchors(): Map<string, Buffer> {
    helpers.log.debug("Entering CertificateTrust.bundledAnchors().");
    if (!bundledRoots) {
      bundledRoots = new Map();
      pki.certificateBundle(tls.rootCertificates.join('\n')).certificates
        .forEach(function (one: Json) {
          bundledRoots.set(CertificateTrust.anchorIdOf(one.der), one.der);
        });
    }
    helpers.log.debug("Leaving CertificateTrust.bundledAnchors().");
    return bundledRoots;
  }

  // A PATH ENDS AT ITS TRUST ANCHOR (RFC 5280 section 6.1). A server may send a
  // root cross-signed by an older one: Google's chains end at GTS Root R4 under
  // GlobalSign Root CA, which it does not send. OpenSSL stops at the anchor it
  // holds, and asking revocation of what lies above it asked about a
  // certificate nothing relies on, which hard-fail then refused for having no
  // issuer: every Google endpoint, in product mode. Nothing here makes a chain
  // trusted: OpenSSL has verified it by the time this is asked, and what is
  // below the anchor is still walked.
  private static endingAtAnchor(chain: Buffer[], realmId: string): Buffer[] {
    helpers.log.debug("Entering CertificateTrust.endingAtAnchor().");
    const anchors = new Map(CertificateTrust.bundledAnchors());
    signerTruststore.anchorsFor(realmId, 'tls-server-outbound').anchors
      .forEach(function (der: Buffer) {
        anchors.set(CertificateTrust.anchorIdOf(der), der);
      });
    helpers.log.debug("Leaving CertificateTrust.endingAtAnchor().");
    return CertificateTrust.cutAtAnchor(chain, anchors);
  }

  // The chain as far as its first certificate that is one of these anchors.
  private static cutAtAnchor(chain: Buffer[],
                             anchors: Map<string, Buffer>): Buffer[] {
    helpers.log.debug("Entering CertificateTrust.cutAtAnchor().");
    for (let i = 0; i < chain.length; i++) {
      if (!CertificateTrust.readable(chain[i])) {
        continue;
      }
      const anchor = anchors.get(CertificateTrust.anchorIdOf(chain[i]));
      if (anchor) {
        helpers.log.debug("Leaving CertificateTrust.cutAtAnchor(). " + i);
        return chain.slice(0, i).concat([anchor]);
      }
    }
    helpers.log.debug("Leaving CertificateTrust.cutAtAnchor(). None.");
    return chain;
  }

  /**
   * The same stop for a client certificate, under paranoid PKI mode: a chain
   * that OpenSSL verified ends at the listener's own anchor. Only what that
   * listener trusts counts, so a public root is no anchor here. Out of force
   * the chain is as presented, which is what the row off owes.
   *
   * @param chain - what is above the leaf, as DER
   * @param anchors - the listener's anchors, as DER
   * @returns the chain to ask revocation of
   */
  static endingAtClientAnchor(chain: Buffer[], anchors: Buffer[]): Buffer[] {
    helpers.log.debug("Entering CertificateTrust.endingAtClientAnchor().");
    if (!CertificateTrust.applies('tls-client', realms.DEFAULT_ID)) {
      helpers.log.debug("Leaving CertificateTrust.endingAtClientAnchor(). " +
                        "Off.");
      return chain;
    }
    const held = new Map<string, Buffer>();
    anchors.forEach(function (der: Buffer) {
      held.set(CertificateTrust.anchorIdOf(der), der);
    });
    helpers.log.debug("Leaving CertificateTrust.endingAtClientAnchor().");
    return CertificateTrust.cutAtAnchor(chain, held);
  }

  // NO SOURCE NAMED, NO CHECK TO PERFORM (rcbj, #1360). The walk has already
  // been asked, so a certificate this service issued met its own register
  // whatever it names. This covers the one case the walk leaves `not-asked`:
  // a door that
  // cannot wait, or `pki.revocationCheck=off`, about a chain naming nothing.
  private static nothingToAsk(verdict: TrustVerdict, chain: Buffer[]): void {
    helpers.log.debug("Entering CertificateTrust.nothingToAsk().");
    if (verdict.checks.revocation === 'not-asked' &&
        !chain.some(revocationStatus.namesSource)) {
      verdict.checks.revocation = 'passed';
    }
    helpers.log.debug("Leaving CertificateTrust.nothingToAsk().");
  }

  // A SERVER'S CERTIFICATE ACCEPTED CASE BY CASE (rcbj, #1360), which is not a
  // softer rule: it is this one certificate, byte for byte, and it is still
  // held to its window and its fields. Either the operator accepted it in the
  // signer truststore, or this dialer was configured with it as its own CA: the
  // shipped OpenBao's and postgres's, which `generate-tls` makes and the stack
  // delivers, and without which a new install in product mode would not start.
  // A public root, or an anchor of the signer truststore, reached this dialer's
  // `ca` without anybody naming this server, so neither counts.
  private static acceptedByName(id: string, leaf: Buffer, opts: Json): boolean {
    helpers.log.debug("Entering CertificateTrust.acceptedByName().");
    if (id !== 'tls-server-outbound') {
      helpers.log.debug("Leaving CertificateTrust.acceptedByName(). Not here.");
      return false;
    }
    const realmId = opts.realmId || realms.currentId();
    if (signerTruststore.accepted(realmId, leaf)) {
      helpers.log.debug("Leaving CertificateTrust.acceptedByName(). Accepted.");
      return true;
    }
    const wanted = leaf.toString('base64');
    const armoured = function (pem: unknown): string {
      helpers.log.debug("Entering armoured().");
      helpers.log.debug("Leaving armoured().");
      return String(pem).replace(/-----[^-]+-----|\s+/g, '');
    };
    const blocks: string[] = ([] as unknown[]).concat(opts.pinnedTo || [])
      .map(function (one: unknown) {
        return String(one);
      }).join('\n').match(
        /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
    const configured = blocks.some(function (pem: string) {
      return armoured(pem) === wanted;
    });
    const elsewhere = CertificateTrust.bundledAnchors()
      .has(CertificateTrust.anchorIdOf(leaf)) ||
      (signerTruststore.pemsFor(realmId, id) as string[])
        .some(function (pem: string) {
          return armoured(pem) === wanted;
        });
    helpers.log.debug("Leaving CertificateTrust.acceptedByName(). " +
                      (configured && !elsewhere));
    return configured && !elsewhere;
  }

  /**
   * What a handshake's peer owes once OpenSSL has verified it, with revocation:
   * `holdPeer()`, then the fetch a hold cannot wait for. Counted and audited as
   * `assess()` is. A staple is asked first, and the `store` variant refuses
   * only what is revoked (see the table).
   *
   * @param id - the purpose
   * @param peer - `getPeerCertificate(true)`
   * @param options - `{ realmId, now, staple, variant, expectName, pinnedTo }`;
   *   `pinnedTo` is the dialer's own `ca`
   * @returns a promise of `{ ok, inForce, code, why }`
   */
  static async assessPeer(id: string, peer: Json,
                          options?: Json): Promise<Json> {
    helpers.log.debug("Entering CertificateTrust.assessPeer(). " + id);
    const opts = options || {};
    const purpose = CertificateTrust.purpose(id);
    const realmId = opts.realmId || realms.currentId();
    const answer = await CertificateTrust.inRealm(realmId, async function () {
      const verdict = CertificateTrust.blank(id, true);
      const codes: Json = {};
      const whys: Json = {};
      const held = CertificateTrust.holdPeer(id, peer,
        { realmId: realmId, now: opts.now, pinnedTo: opts.pinnedTo });
      if (!held.inForce) {
        return held;
      }
      CHECK_ORDER.forEach(function (check) {
        verdict.checks[check] = 'passed';
      });
      verdict.checks['name-match'] = 'not-asked';
      verdict.checks.revocation = 'not-asked';
      if (!held.ok) {
        const named = RULE_CHECKS[held.check] || held.check;
        const check = CHECK_ORDER.indexOf(named) === -1 ? 'path' : named;
        verdict.checks[check] = 'failed';
        codes[check] = held.code;
        whys[check] = held.why;
      } else {
        const rule = CertificateTrust.ruleOf(purpose, opts.variant);
        const certs = CertificateTrust.certificatesOf({ peer: peer });
        const fetched = await revocationStatus.verdictFor(
          { leaf: certs.leaf,
            chain: CertificateTrust.endingAtAnchor(certs.chain, realmId),
            verified: true },
          { stapled: opts.staple || undefined });
        if (rule.softRevocation && fetched.refused &&
            fetched.status !== 'revoked') {
          verdict.checks.revocation = 'passed';
          verdict.revocation = fetched;
        } else {
          CertificateTrust.readRevocation(verdict, fetched, codes, whys);
          CertificateTrust.nothingToAsk(verdict,
                                        [certs.leaf].concat(certs.chain));
        }
      }
      return CertificateTrust.compose(purpose, verdict, codes, whys, realmId,
                                      false);
    });
    helpers.log.debug("Leaving CertificateTrust.assessPeer(). " + answer.ok);
    return answer;
  }

  /**
   * A registered key's certificate chain, at the use: what the RFC 7523 and RFC
   * 7522 verifiers call in place of `pki.verifySignerChain()`, with its answer's
   * shape. Not in force it IS that function. In force: an incomplete chain is
   * completed from the signer truststore before it is refused, the leaf's fields
   * are asked, and a self-signed `x5c[0]` is held to the purpose's rule, which
   * closes the asymmetry with the upload door. Revocation stays where the sites
   * already ask it, `registeredKeyVerdictFor()`.
   *
   * @param id - the purpose: `jose-signer` or `saml-signer`
   * @param material - `{ certificate, chain, key, source, index }`
   * @param options - `{ realmId }`
   * @returns a promise of `verifySignerChain()`'s answer
   */
  static async signerChain(id: string, material: Json,
                           options?: Json): Promise<Json> {
    helpers.log.debug("Entering CertificateTrust.signerChain(). " + id);
    const opts = options || {};
    const purpose = CertificateTrust.purpose(id);
    const answer = await pki.verifySignerChain(opts.realmId, material);
    if (!CertificateTrust.applies(id, opts.realmId)) {
      helpers.log.debug("Leaving CertificateTrust.signerChain(). The baseline.");
      return answer;
    }
    const refuse = function (code: string, why: string): Json {
      helpers.log.debug("Entering refuse(). " + code);
      const verdict = CertificateTrust.blank(id, true);
      verdict.checks.path = 'failed';
      CertificateTrust.compose(purpose, verdict, { path: code }, { path: why },
                               opts.realmId || realms.currentId(), false);
      helpers.log.debug("Leaving refuse().");
      return errorCodes.mark({ ok: false, why: why, path: answer.path || [] },
                             code);
    };
    const read = CertificateTrust.certificatesOf(
      { leaf: material.certificate, chain: [].concat(material.chain || [])
        .filter(Boolean) });
    const certs = read && CertificateTrust.readable(read.leaf) ? read : null;
    if (!certs) {
      helpers.log.debug("Leaving CertificateTrust.signerChain(). Unreadable.");
      return answer.ok ? refuse('STS-PKI-0238',
                                'its certificate is not X.509') : answer;
    }
    let result = answer;
    if (!answer.ok) {
      const built = await pki.verifyPathToAnchors(certs.leaf, certs.chain,
        'signer-truststore', { realmId: opts.realmId, purpose: id });
      if (!built.ok) {
        helpers.log.debug("Leaving CertificateTrust.signerChain(). No path.");
        return answer;
      }
      result = { ok: true, anchor: 'signer-truststore',
                 links: answer.links || [], path: answer.path || [],
                 chain: built.chain.map(function (step: Json) {
                   return step.pem;
                 }) };
    } else if (answer.anchor === 'pinned' && purpose.selfSigned === 'refuse') {
      helpers.log.debug("Leaving CertificateTrust.signerChain(). Self-signed.");
      return refuse(purpose.code, 'a self-signed certificate is not accepted ' +
                    'for ' + id + ': register the authority that issued it, ' +
                    'or add it to the signer truststore');
    }
    const field = stsCrypto.certificateFieldProblem(certs.leaf,
      Object.assign({}, purpose.leaf, { role: 'leaf',
                                        mayBeCa: answer.anchor === 'pinned' }));
    if (field) {
      helpers.log.debug("Leaving CertificateTrust.signerChain(). A field.");
      return refuse(field.code, field.why);
    }
    helpers.log.debug("Leaving CertificateTrust.signerChain().");
    return result;
  }

  /**
   * A pinned certificate at a door that cannot wait: a SAML request's signature
   * and a WS-Security token are answered in one tick, inside handlers that hand
   * back a value. Fields, the pin rule, and one hop through the signer truststore
   * are decided here. **REVOCATION IS READ FROM WHAT WAS LAST FETCHED**, and a
   * certificate nothing has been fetched about starts that fetch and is refused
   * this once, since a check nobody made is a refusal; `pki.pins.audit` and the
   * first request both fill it. A certificate that names no list and no responder
   * has nothing to fetch, and the register answers for it now.
   *
   * @param id - the purpose
   * @param cert - PEM or DER
   * @param options - `{ realmId, now, registered (a pin) }`
   * @returns `{ ok, code, why }`; `ok` when paranoid does not apply
   */
  static pinnedSync(id: string, cert: Json, options?: Json): Json {
    helpers.log.debug("Entering CertificateTrust.pinnedSync(). " + id);
    const opts = options || {};
    const realmId = opts.realmId || realms.currentId();
    if (!CertificateTrust.applies(id, realmId)) {
      helpers.log.debug("Leaving CertificateTrust.pinnedSync(). Not in force.");
      return { ok: true, code: '', why: '' };
    }
    const purpose = CertificateTrust.purpose(id);
    const verdict = CertificateTrust.blank(id, true);
    const codes: Json = {};
    const whys: Json = {};
    const done = function (): Json {
      helpers.log.debug("Entering done().");
      CHECK_ORDER.forEach(function (check) {
        if (verdict.checks[check] === 'not-asked' && check !== 'revocation' &&
            check !== 'name-match') {
          verdict.checks[check] = 'passed';
        }
      });
      CertificateTrust.compose(purpose, verdict, codes, whys, realmId, false);
      helpers.log.debug("Leaving done().");
      return { ok: verdict.ok, code: verdict.code, why: verdict.why };
    };
    const der = CertificateTrust.derOf(cert);
    if (!der || !CertificateTrust.readable(der)) {
      verdict.checks.path = 'failed';
      codes.path = 'STS-PKI-0238';
      whys.path = 'it is not an X.509 certificate';
      helpers.log.debug("Leaving CertificateTrust.pinnedSync(). Unreadable.");
      return done();
    }
    const facts = stsCrypto.certificateFacts(der);
    let selfSigned = false;
    if (facts.selfIssued) {
      try {
        selfSigned = stsCrypto.parseCertificate(der)
          .verify(stsCrypto.parseCertificate(der).publicKey);
      } catch (e) {
        // A key node cannot read: the name is what is left to go on, and the
        // signature that brought this here was verified with that key.
        helpers.log.debug("Caught in CertificateTrust.pinnedSync(): " +
                          ((e && e.message) || e));
        selfSigned = true;
      }
    }
    CertificateTrust.fieldChecks(verdict, der,
      CertificateTrust.ruleOf(purpose, opts.variant), opts, selfSigned)
      .forEach(function (one: Json) {
        codes[one.check] = codes[one.check] || one.code;
        whys[one.check] = whys[one.check] || one.why;
      });
    let issuers: Buffer[] = [];
    if (selfSigned) {
      if (purpose.selfSigned !== 'allow-by-spec') {
        verdict.checks['self-signed-allowed'] = 'failed';
        codes['self-signed-allowed'] = purpose.code;
        whys['self-signed-allowed'] = 'a self-signed certificate is not ' +
          'accepted for ' + id;
        helpers.log.debug("Leaving CertificateTrust.pinnedSync(). Self-signed.");
        return done();
      }
      verdict.checks.path = 'exempt-by-spec';
    } else {
      const held = signerTruststore.anchorsFor(realmId, id);
      issuers = held.anchors.concat(held.intermediates);
      const direct = pki.verifyIssuedDirectly(der, issuers.map(function (one) {
        return { raw: one };
      }), { now: opts.now });
      if (!direct.ok) {
        verdict.checks.path = 'failed';
        codes.path = purpose.code;
        whys.path = 'it chains to nothing in this realm\'s signer truststore: ' +
                    direct.reason;
        helpers.log.debug("Leaving CertificateTrust.pinnedSync(). No path.");
        return done();
      }
    }
    CertificateTrust.pinRevocation(verdict, der, facts, issuers, codes, whys);
    helpers.log.debug("Leaving CertificateTrust.pinnedSync().");
    return done();
  }

  // What was last fetched about a pin, or the fetch begun.
  private static pinRevocation(verdict: TrustVerdict, der: Buffer, facts: Json,
                               issuers: Buffer[], codes: Json,
                               whys: Json): void {
    helpers.log.debug("Entering CertificateTrust.pinRevocation().");
    const input = { leaf: der, chain: issuers, verified: true };
    const local = revocationStatus.localVerdictFor(input);
    if (local.refused) {
      CertificateTrust.readRevocation(verdict, local, codes, whys);
      helpers.log.debug("Leaving CertificateTrust.pinRevocation().");
      return;
    }
    const parsed = stsCrypto.parseCertificate(der);
    const names = revocationStatus.distributionPointsOf(parsed).fetchable.length ||
                  revocationStatus.ocspRespondersOf(parsed).fetchable.length;
    if (!names) {
      verdict.checks.revocation = 'passed';
      verdict.revocation = local;
      helpers.log.debug("Leaving CertificateTrust.pinRevocation().");
      return;
    }
    const key = facts.fingerprint256;
    const held = pinVerdicts.get(key);
    if (held && held.until > Date.now()) {
      pinVerdictCount.hit();
      CertificateTrust.readRevocation(verdict, held.verdict, codes, whys);
      helpers.log.debug("Leaving CertificateTrust.pinRevocation().");
      return;
    }
    pinVerdictCount.miss();
    cacheRegistry.makeRoom(pinVerdicts, MAX_PIN_VERDICTS,
                           { counter: pinVerdictCount });
    pinVerdicts.set(key, { until: Date.now() + PIN_VERDICT_MS,
      verdict: { status: 'unknown', refused: true, why: 'its revocation is ' +
                 'being established: ask again in a moment' } });
    revocationStatus.verdictFor(input, {}).then(function (answer: Json) {
      pinVerdicts.set(key, { until: Date.now() + PIN_VERDICT_MS,
                             verdict: answer });
    }, function (e: Json) {
      helpers.log.debug("Caught in CertificateTrust.pinRevocation(): " +
                        ((e && e.message) || e));
      pinVerdicts.delete(key);
    });
    verdict.checks.revocation = 'not-asked';
    whys.revocation = 'its revocation is being established: ask again in a ' +
                      'moment';
    helpers.log.debug("Leaving CertificateTrust.pinRevocation().");
  }

  /**
   * Whether what a leaf's own Authority Information Access led to reaches an
   * anchor this realm holds, so an address in a certificate decides nothing.
   *
   * @param leaf - the leaf's DER
   * @param issuers - what was fetched, as DER
   * @returns a promise of true or false
   */
  static async reachesHeld(leaf: Buffer, issuers: Buffer[]): Promise<boolean> {
    helpers.log.debug("Entering CertificateTrust.reachesHeld().");
    const held = await pki.verifyPathToAnchors(leaf, issuers,
      'signer-truststore', { purpose: 'saml-signer' });
    const ours = held.ok ? held :
      await pki.verifyPathToAnchors(leaf, issuers, 'realm', {});
    helpers.log.debug("Leaving CertificateTrust.reachesHeld(). " + ours.ok);
    return !!ours.ok;
  }

  /**
   * A JWK that carries an `x5c` is held as `jose-signer` would hold its leaf; a
   * bare one is left alone, which OpenID Federation 1.1 section 3 defines.
   *
   * @param jwk - the key that verified
   * @param options - as `pinnedSync()`
   * @returns `{ ok, code, why }`
   */
  static bareKey(jwk: Json, options?: Json): Json {
    helpers.log.debug("Entering CertificateTrust.bareKey().");
    const x5c = jwk && Array.isArray(jwk.x5c) ? jwk.x5c : [];
    if (!x5c.length) {
      helpers.log.debug("Leaving CertificateTrust.bareKey(). Bare.");
      return { ok: true, code: '', why: '' };
    }
    helpers.log.debug("Leaving CertificateTrust.bareKey().");
    return CertificateTrust.pinnedSync('jose-bare-key',
      Buffer.from(String(x5c[0]), 'base64'), options);
  }

  /**
   * A certificate at the door it is registered through, under paranoid PKI mode:
   * its fields only. A write is not a use, so its chain and revocation are asked
   * at the use, and something that will expire next year is written today.
   *
   * @param id - the purpose it will be used for
   * @param cert - PEM or DER
   * @param options - `{ realmId, now }`
   * @returns null, or `{ code, why }`
   */
  static registrationProblem(id: string, cert: Json, options?: Json): Json {
    helpers.log.debug("Entering CertificateTrust.registrationProblem().");
    const opts = options || {};
    if (!CertificateTrust.applies(id, opts.realmId)) {
      helpers.log.debug("Leaving CertificateTrust.registrationProblem(). Off.");
      return null;
    }
    const der = CertificateTrust.derOf(cert);
    if (!der || !CertificateTrust.readable(der)) {
      helpers.log.debug("Leaving CertificateTrust.registrationProblem(). Bad.");
      return { code: 'STS-PKI-0238', why: 'it is not an X.509 certificate' };
    }
    const purpose = CertificateTrust.purpose(id);
    const facts = stsCrypto.certificateFacts(der);
    const problem = stsCrypto.certificateFieldProblem(der,
      Object.assign({}, purpose.leaf, { role: 'leaf', now: opts.now,
                                        mayBeCa: facts.selfIssued }));
    helpers.log.debug("Leaving CertificateTrust.registrationProblem().");
    return problem ? { code: problem.code, why: problem.why } : null;
  }

  /**
   * `assess()`, thrown: a refusal is an Error carrying `.code` and `.verdict`.
   *
   * @param id - the purpose
   * @param material - as `assess()`
   * @param options - as `assess()`
   * @returns a promise of the verdict, when it holds
   */
  static async require(id: string, material: Json,
                       options?: Json): Promise<TrustVerdict> {
    helpers.log.debug("Entering CertificateTrust.require(). " + id);
    const verdict = await CertificateTrust.assess(id, material, options);
    if (!verdict.ok) {
      const refusal: Json = new Error(verdict.why);
      refusal.code = verdict.code;
      refusal.verdict = verdict;
      errorCodes.mark(refusal, verdict.code);
      helpers.log.debug("Leaving CertificateTrust.require(). Refused.");
      throw refusal;
    }
    helpers.log.debug("Leaving CertificateTrust.require().");
    return verdict;
  }

  /**
   * What the door has answered in this process.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @returns per purpose, `{ assessed, refused, lastRefusal }`
   */
  static counters(realmId?: string): Json {
    helpers.log.debug("Entering CertificateTrust.counters().");
    const realm = counts.get(realmId || realms.currentId()) || {};
    const out: Json = {};
    PURPOSES.forEach(function (one) {
      out[one.id] = realm[one.id] ||
        { assessed: 0, refused: 0, lastRefusal: null };
    });
    helpers.log.debug("Leaving CertificateTrust.counters().");
    return out;
  }

  /**
   * Registers one owner's list of what it pins.
   *
   * @param name - the source's name
   * @param fn - `(realmId) => PinnedSource[]`, or a promise of them
   */
  static registerPinSource(name: string, fn: (realmId: string) =>
    Promise<PinnedSource[]> | PinnedSource[]): void {
    helpers.log.debug("Entering CertificateTrust.registerPinSource(). " + name);
    pinSources.set(name, fn);
    helpers.log.debug("Leaving CertificateTrust.registerPinSource().");
  }

  /**
   * Removes a pin source, for a test putting back what it found.
   *
   * @param name - the source's name
   */
  static forgetPinSource(name: string): void {
    helpers.log.debug("Entering CertificateTrust.forgetPinSource(). " + name);
    pinSources.delete(name);
    helpers.log.debug("Leaving CertificateTrust.forgetPinSource().");
  }

  // One pin as the inventory shows it: held to the checks whatever the settings
  // say, because an operator with a row off still wants to see what is expired.
  private static async pinRow(row: PinnedSource, realmId: string,
                              horizonMs: number,
                              now: number): Promise<PinnedCertificate> {
    helpers.log.debug("Entering CertificateTrust.pinRow().");
    const out: Json = Object.assign({
      subject: '', notBefore: 0, notAfter: 0, selfSigned: false, chainedTo: '',
      revocation: '', status: 'unreadable', code: '', fingerprint256: ''
    }, row);
    if (!row.pem) {
      out.status = row.thumbprint ? 'thumbprint-only' : 'unreadable';
      out.fingerprint256 = row.thumbprint || '';
      helpers.log.debug("Leaving CertificateTrust.pinRow().");
      return out;
    }
    const der = CertificateTrust.derOf(row.pem);
    if (!der || !CertificateTrust.readable(der)) {
      helpers.log.debug("Leaving CertificateTrust.pinRow().");
      return out;
    }
    const facts = stsCrypto.certificateFacts(der);
    out.subject = facts.subject;
    out.notBefore = facts.notBefore;
    out.notAfter = facts.notAfter;
    out.fingerprint256 = facts.fingerprint256;
    out.selfSigned = await CertificateTrust.isSelfSigned(der);
    const verdict = await CertificateTrust.assess(row.purpose,
      { leaf: der, chain: row.chain || [], pinned: true,
        registered: { chain: row.chain || [] } },
      { realmId: realmId, force: true, now: now });
    out.code = verdict.code;
    out.chainedTo = verdict.anchor;
    out.revocation = verdict.revocation ? verdict.revocation.status : '';
    if (now > facts.notAfter) {
      out.status = 'expired';
    } else if (now < facts.notBefore) {
      out.status = 'not-yet-valid';
    } else if (verdict.checks.revocation === 'failed') {
      out.status = 'revoked';
    } else if (facts.notAfter - now < horizonMs) {
      out.status = 'expiring';
    } else if (verdict.checks.path === 'failed') {
      out.status = 'chain-missing';
    } else if (out.selfSigned) {
      out.status = 'self-signed';
    } else {
      out.status = 'valid';
    }
    helpers.log.debug("Leaving CertificateTrust.pinRow().");
    return out;
  }

  /**
   * Every certificate the realm pins, from every source, with its status.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param options - `{ now }`
   * @returns a promise of the rows
   */
  static async pinnedCertificates(realmId?: string,
                                  options?: Json): Promise<PinnedCertificate[]> {
    const { log } = helpers;
    log.debug("Entering CertificateTrust.pinnedCertificates().");
    const id = realmId || realms.currentId();
    const now = (options && options.now) || Date.now();
    const rows: PinnedCertificate[] = [];
    await CertificateTrust.inRealm(id, async function () {
      const horizonMs = Number(config.value('pki.pinnedCertificateWarningDays')) *
                        DAY_MS;
      const names = Array.from(pinSources.keys());
      for (let i = 0; i < names.length; i++) {
        let listed: PinnedSource[] = [];
        try {
          listed = await pinSources.get(names[i])(id);
        } catch (e) {
          log.error(errorCodes.tag('STS-PKI-0265') + 'pki: the pin source "' +
                    names[i] + '" could not list its certificates: ' +
                    ((e && e.message) || e));
        }
        for (let j = 0; j < listed.length; j++) {
          rows.push(await CertificateTrust.pinRow(listed[j], id, horizonMs,
                                                  now));
        }
      }
    });
    log.debug("Leaving CertificateTrust.pinnedCertificates(). " + rows.length);
    return rows;
  }

  /**
   * What the audit last found for a realm.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @returns `{ assessedAt, pins, truststore }`, or an empty answer
   */
  static lastAudit(realmId?: string): Json {
    helpers.log.debug("Entering CertificateTrust.lastAudit().");
    const held = CertificateTrust.inRealm(realmId, function () {
      return lastAudit.get('last');
    });
    helpers.log.debug("Leaving CertificateTrust.lastAudit().");
    return held || { assessedAt: 0, pins: [], truststore: [] };
  }

  /**
   * The audit of one realm: every pin and every truststore entry, the result
   * kept for the page, and a log line and a mail only for what CHANGED, so a
   * daily job does not say the same thing daily.
   *
   * @param realmId - the realm; the ambient one where omitted
   * @param options - `{ now }`
   * @returns a promise of `{ pins, truststore, changes }`
   */
  static async auditRealm(realmId?: string, options?: Json): Promise<Json> {
    const { log } = helpers;
    log.debug("Entering CertificateTrust.auditRealm().");
    const id = realmId || realms.currentId();
    const now = (options && options.now) || Date.now();
    const answer = await CertificateTrust.inRealm(id, async function () {
      const before = CertificateTrust.lastAudit(id);
      const pins = await CertificateTrust.pinnedCertificates(id, { now: now });
      const held = signerTruststore.list(id);
      const anchorPems = held.filter(function (row: Json) {
        return row.kind === 'anchor';
      }).map(function (row: Json) {
        return row.pem;
      });
      const entries: Json[] = [];
      for (let i = 0; i < held.length; i++) {
        const verdict = await CertificateTrust.assess('anchor-admission',
          { leaf: held[i].pem },
          { realmId: id, force: true, now: now, role: held[i].kind,
            heldAnchors: anchorPems });
        entries.push({
          fingerprint256: held[i].fingerprint256, subject: held[i].subject,
          status: now > held[i].notAfter ? 'expired' :
            (verdict.ok ? 'valid' : 'chain-missing'),
          code: verdict.code
        });
      }
      const was: Json = {};
      (before.pins || []).concat(before.truststore || [])
        .forEach(function (row: Json) {
          was[row.fingerprint256] = row.status;
        });
      const changes = pins.map(function (row: Json) {
        return { fingerprint256: row.fingerprint256, subject: row.subject,
                 where: row.where, status: row.status };
      }).concat(entries.map(function (row: Json) {
        return { fingerprint256: row.fingerprint256, subject: row.subject,
                 where: 'the signer truststore', status: row.status };
      })).filter(function (row: Json) {
        return was[row.fingerprint256] !== row.status &&
               ['expiring', 'expired', 'revoked', 'chain-missing']
                 .indexOf(row.status) !== -1;
      });
      changes.forEach(function (row: Json) {
        const code = row.status === 'expiring' ? 'STS-PKI-0263' :
                                                 'STS-PKI-0264';
        log.warn(errorCodes.tag(code) + 'pki: ' + row.where + ': "' +
                 row.subject + '" is now ' + row.status + '.');
      });
      lastAudit.set('last', { assessedAt: now, pins: pins,
                              truststore: entries });
      if (changes.length) {
        CertificateTrust.mailChanges(changes);
      }
      return { pins: pins.length, truststore: entries.length,
               changes: changes.length };
    });
    log.debug("Leaving CertificateTrust.auditRealm().");
    return answer;
  }

  // Tells the realm's administrators: never per run, only on a change, and
  // never in a way that could fail the audit.
  private static mailChanges(changes: Json[]): void {
    helpers.log.debug("Entering CertificateTrust.mailChanges().");
    try {
      require('./mail_uses').pkiPinStatus({
        changes: changes.map(function (row: Json) {
          return row.where + ': ' + row.subject + ' (' + row.status + ')';
        }).join('\n'),
        dedupKey: 'pki-pin-status:' + changes.map(function (row: Json) {
          return row.fingerprint256 + '=' + row.status;
        }).join(',')
      });
    } catch (e) {
      helpers.log.debug("Caught in CertificateTrust.mailChanges(): " +
                        ((e && e.message) || e));
    }
    helpers.log.debug("Leaving CertificateTrust.mailChanges().");
  }

  /**
   * Registers the audit job and the write rule: called once per process by the
   * composition root, which every process runs, so all register the same jobs.
   *
   * @param schedulerInstance - the scheduler; the service's where omitted
   * @returns true when this call registered the job
   */
  static install(schedulerInstance?: Json): boolean {
    helpers.log.debug("Entering CertificateTrust.install().");
    // Lazily: `cluster/scheduler` reads this service's stores at load.
    const scheduler = schedulerInstance || require('../cluster/scheduler');
    if (scheduler.job(AUDIT_JOB)) {
      helpers.log.debug("Leaving CertificateTrust.install(). Already.");
      return false;
    }
    scheduler.register({
      id: AUDIT_JOB, title: 'Pinned certificate audit',
      describe: 'Holds every pinned certificate and every signer truststore ' +
        'entry of the realm to the checks of paranoid PKI mode, keeps the ' +
        'result /admin/pki/trust draws, and logs and mails what changed.',
      owner: 'common/certificate_trust.ts', kind: 'cluster', scope: 'realm',
      // Daily, in the shape every other daily job has. A new realm's first run
      // is its next tick, as any job's current slot is.
      everyMs: function (): number {
        return DAY_MS;
      },
      manual: true, timeoutS: 600,
      run: function (ctx: Json): Promise<Json> {
        return CertificateTrust.auditRealm(ctx.realm);
      }
    });
    helpers.log.debug("Leaving CertificateTrust.install().");
    return true;
  }

  /**
   * The published table of use cases, generated from the purpose table so the
   * documentation and the code cannot disagree.
   *
   * @returns the whole of `docs/pki-use-cases.md`
   */
  static docsPage(): string {
    helpers.log.debug("Entering CertificateTrust.docsPage().");
    const cell = function (text: string): string {
      return String(text || '').replace(/\|/g, '\\|');
    };
    const anchorWords: Json = {
      realm: 'this service\'s own Root',
      'signer-truststore': 'the signer truststore',
      'client-truststore': 'the client-certificate truststore',
      caller: 'the use case\'s own setting',
      'registered-root': 'the root registered with it',
      pinned: 'the registered certificate itself'
    };
    const rows = PURPOSES.map(function (one) {
      const exemptions = one.exemptions.map(function (ex) {
        return ex.check + ': ' + ex.spec;
      }).join('; ');
      const usage = one.leaf.keyUsage.join(' or ') || 'none asked';
      const eku = one.leaf.eku ?
        one.leaf.eku.oids.join(' or ') +
          (one.leaf.eku.required ? ' (required)' : ' (if present)') :
        'none asked';
      return '| `' + one.id + '` | ' + cell(one.covers) + ' | ' +
        cell(one.anchors.map(function (a) {
          return anchorWords[a];
        }).join(', ')) + ' | ' + cell(one.adds) + ' | ' + usage + ' | ' + eku +
        ' | ' + cell(exemptions || 'none') + ' | `' + one.setting + '` | ' +
        one.phase + ' |';
    });
    helpers.log.debug("Leaving CertificateTrust.docsPage().");
    return '---\ntitle: PKI use cases\nnav_order: 7\n---\n\n' +
      '<!-- GENERATED by node common/certificate_trust.js --docs. ' +
      'Do not edit. -->\n\n# PKI use cases\n\n' +
      'Every X.509 certificate this service relies on is validated for one ' +
      'of these use cases. See [Certificate validation](pki.md#certificate-' +
      'validation-what-is-checked-and-where) for what each check means and ' +
      '[Paranoid PKI mode](pki.md#paranoid-pki-mode) for when they apply. The ' +
      'last column is the phase of the rollout that holds that use case\'s ' +
      'sites to the row: until then its setting is present and governs ' +
      'nothing.\n\n' +
      '| Use case | What it covers | Anchors it may reach | What paranoid ' +
      'adds | keyUsage | extendedKeyUsage | Specification exemption | ' +
      'Setting | Phase |\n|---|---|---|---|---|---|---|---|---|\n' +
      rows.join('\n') + '\n';
  }

  /**
   * Where the generated page lives.
   *
   * @returns its path
   */
  static docsPath(): string {
    helpers.log.debug("Entering CertificateTrust.docsPath().");
    helpers.log.debug("Leaving CertificateTrust.docsPath().");
    return path.join(__dirname, '..', 'docs', 'pki-use-cases.md');
  }
}

config.addWriteRule(CertificateTrust.writeRule);

export = CertificateTrust;

if (require.main === module) {
  if (process.argv.indexOf('--docs') !== -1) {
    fs.writeFileSync(CertificateTrust.docsPath(), CertificateTrust.docsPage());
    process.exit(0);
  }
  process.stdout.write(CertificateTrust.docsPage());
  process.exit(0);
}
