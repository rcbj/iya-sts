// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: common/truststore_use_cases.ts
//
// ===========================================================================
// EVERY USE CASE THAT TRUSTS A CERTIFICATE OR A KEY SET, AND THE TRUSTSTORES
// IT POINTS AT BY DEFAULT (#2118, 2026-11-24).
//
// rcbj's design on #2118: the signer truststore and the client-certificate
// truststore became ONE concept, named truststores (`common/truststores.ts`),
// and every place this service validates a signature or dials a TLS server
// names the truststores it trusts, or `system`. This file is the list of
// those places. Nothing else decides what a use case is; `truststores.ts`
// resolves the names, `certificate_trust.ts` builds the paths, and
// `outbound_tls.ts` hands a dialer its `ca`.
//
// **A ROW'S DEFAULT REPRODUCES WHAT THE USE CASE TRUSTED BEFORE #2118.** The
// legacy settings and the two older stores are not copied anywhere: each is a
// read-only VIEW with a name (`setting:<key>`, `signers`,
// `client-certificates`), and a default list names the views. An upgrade
// therefore changes nothing a deployment trusts, needs no script, and every
// legacy key, page and API keeps working because it writes the same data the
// view reads. An administrator moves a use case by ASSIGNING it a list.
//
// **SCOPE (D2).** A `service` use case is decided with no realm in hand — a TLS
// handshake, an outbound dial, the database — so it may name only truststores
// defined in the default realm and the built-ins. A `realm` use case is
// decided inside a realm and may name that realm's truststores too.
//
// **KIND.** `x509` names anchor sets. `spiffe` names SPIFFE bundle truststores
// only (D5): a trust domain's bundle is ONE truststore holding its X.509
// authorities and its JWT-SVID keys. `pins` is a use case whose trust is a
// certificate stored on the entry that uses it (RFC 8705 section 2.2's
// equality, GNAP's pinned key): listed so the catalogue is complete, with no
// list to assign. `fixed` is a use case whose anchor is this service's own
// hierarchy by definition (the inter-cell channel, an enrollment credential
// this service issued, its own loopback): listed, shown, not assignable.
// `admission` is not a trust decision at all but the rule a certificate is
// admitted INTO a store under (ca-import, anchor-admission).
//
// **FALLBACK.** Several use cases trusted "the setting, or else what ships":
// `piv.attestationAnchors` else Yubico's roots, `risk.mdsTrustAnchors` else
// GlobalSign Root CA - R3. `fallback` is that list: used only when the
// default list yields no anchor at all. An ASSIGNED list has no fallback —
// an administrator who assigns a list means exactly that list.
//
// A LEAF (rule 3): data and four lookups, no route, requires only the logger.
// ===========================================================================

import helpers = require('./helpers');

const log = helpers.log;

type Scope = 'service' | 'realm';
// `jwks` (#2149): a JSON Web Signature verified against a key set bound to the
// party that signed it, never against a pool.
type Kind = 'x509' | 'spiffe' | 'pins' | 'fixed' | 'admission' | 'jwks';

interface UseCase {
  id: string;
  scope: Scope;
  kind: Kind;
  direction: 'inbound' | 'outbound';
  title: string;
  sites: string[];
  defaults: string[];
  fallback?: string[];
  // The `common/certificate_trust.ts` purpose (and variant) this use case is,
  // where it is one: the door resolves the anchors of a purpose through here.
  purpose?: string;
  variant?: string;
}

// Shorthand for a legacy setting's view.
function setting(key: string): string {
  log.debug("Entering setting().");
  log.debug("Leaving setting().");
  return 'setting:' + key;
}

const ROWS: UseCase[] = [
  // ----- Inbound: a certificate or a key presented to this service --------
  { id: 'tls-client', scope: 'service', kind: 'x509', direction: 'inbound',
    title: 'A client certificate at a TLS handshake',
    sites: ['tls/tls_server.js', 'ldap/ldap_server.js',
            'debugger/debugger_server.ts',
            'common/forwarded_client_certificate.ts', 'oauth-oidc/mtls.js'],
    defaults: ['client-certificates',
               setting('tls.trustIssuedClientCertificates')],
    purpose: 'tls-client' },
  { id: 'tls-client-self-signed', scope: 'realm', kind: 'pins',
    direction: 'inbound',
    title: 'A self-signed TLS client certificate a client registered',
    sites: ['oauth-oidc/client_auth.js', 'gnap/gnap_proof.ts'],
    defaults: [], purpose: 'tls-client-self-signed' },
  { id: 'jose-signer', scope: 'realm', kind: 'x509', direction: 'inbound',
    title: 'The certificate of a key that signed a JWT this service relies on',
    sites: ['oauth-oidc/client_auth.js', 'oauth-oidc/assertion_grant.js',
            'oauth-oidc/request_object.ts',
            'oauth-oidc/software_statement.ts'],
    defaults: ['service-root', 'signers'], purpose: 'jose-signer' },
  { id: 'saml-signer', scope: 'realm', kind: 'x509', direction: 'inbound',
    title: 'The certificate of a key that signed a SAML message',
    sites: ['saml/request_signature.ts',
            'oauth-oidc/saml_assertion_grant.js'],
    defaults: ['signers'], purpose: 'saml-signer' },
  { id: 'saml-metadata-signer', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'The certificate that signed a service provider\'s metadata',
    sites: ['saml/sp_metadata.ts'],
    defaults: [setting('saml2.metadataTrustAnchors')] },
  { id: 'federation-partner', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'A federation partner\'s signing certificate',
    sites: ['federation/federation_sp.ts', 'federation/federation_slo.ts'],
    defaults: ['signers'], purpose: 'federation-partner' },
  { id: 'wss-x509-token', scope: 'realm', kind: 'x509', direction: 'inbound',
    title: 'The certificate that signed a WS-Trust request',
    sites: ['ws-trust/wstrust.ts'],
    defaults: ['service-root', 'signers'], purpose: 'wss-x509-token' },
  { id: 'jose-bare-key', scope: 'realm', kind: 'x509', direction: 'inbound',
    title: 'The x5c of a key a partner published in a key set',
    sites: ['ssf/ssf_transmitters.ts', 'oauth-oidc/claims_providers.ts',
            'federation/federation_sp.ts'],
    defaults: ['signers'], purpose: 'jose-bare-key' },
  { id: 'encryption-recipient', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'A certificate this service encrypts to',
    sites: ['saml/saml2_sso.ts', 'ws-trust/ws_encryption.ts'],
    defaults: ['signers'], purpose: 'encryption-recipient' },
  { id: 'policy-signer', scope: 'realm', kind: 'x509', direction: 'inbound',
    title: 'The certificate that signed an imported policy bundle',
    sites: ['admin-core/policy_transfer.ts'],
    defaults: ['signers'], purpose: 'policy-signer' },
  { id: 'client-attestation', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'An OAuth client attestation\'s certificate chain',
    sites: ['oauth-oidc/client_attestation.ts'],
    defaults: [setting('oauth2.clientAttestationTrustAnchors'), 'signers'],
    purpose: 'client-attestation' },
  { id: 'webauthn-attestation', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'A passkey\'s attestation certificate chain',
    sites: ['authn/webauthn_attestation.ts'],
    defaults: [setting('webauthn.attestationTrustAnchors'), 'fido-mds',
               'signers'],
    purpose: 'webauthn-attestation' },
  { id: 'fido-mds', scope: 'service', kind: 'x509', direction: 'inbound',
    title: 'The FIDO Metadata Service BLOB\'s signer',
    sites: ['common/pki.js verifyFidoMdsBlob', 'risk/risk_datasets.ts'],
    defaults: [setting('risk.mdsTrustAnchors'), 'signers'],
    fallback: ['fido-mds-signer', 'signers'], purpose: 'fido-mds' },
  { id: 'timestamp-authority', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'The RFC 3161 timestamp authority behind passkey evidence',
    sites: ['common/passkey_evidence.ts'],
    defaults: [setting('webauthn.attestationEvidenceTsaTrustAnchors')] },
  { id: 'device-attestation-android', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'An Android Key Attestation chain',
    sites: ['common/device_attestation.ts'],
    defaults: [setting('devices.androidAttestationTrustAnchors'), 'signers'],
    fallback: ['device-vendors', 'signers'],
    purpose: 'device-attestation', variant: 'android' },
  { id: 'device-attestation-apple', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'An Apple App Attest chain',
    sites: ['common/device_attestation.ts'],
    defaults: [setting('devices.appleAppAttestTrustAnchors'), 'signers'],
    fallback: ['device-vendors', 'signers'],
    purpose: 'device-attestation', variant: 'apple' },
  { id: 'device-attestation-tpm', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'A TPM attestation key\'s certificate chain',
    sites: ['common/device_attestation.ts'],
    defaults: [setting('devices.tpmTrustAnchors'), 'signers'],
    purpose: 'device-attestation', variant: 'tpm' },
  { id: 'piv-attestation', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'A YubiKey PIV key attestation',
    sites: ['common/piv_attestation.ts'],
    defaults: [setting('piv.attestationAnchors')],
    fallback: ['yubico-piv'], purpose: 'piv-attestation' },
  { id: 'piv-card', scope: 'realm', kind: 'x509', direction: 'inbound',
    title: 'An outside PIV or CAC card\'s issuing CA',
    sites: ['common/piv_attestation.ts cardIdentityOf'],
    defaults: [setting('piv.externalIssuers')], purpose: 'piv-card' },
  { id: 'vc-issuer', scope: 'realm', kind: 'x509', direction: 'inbound',
    title: 'A verifiable credential issuer\'s certificate',
    sites: ['oid4vc/vc_verifier.ts', 'oid4vc/vc_status.ts'],
    defaults: [setting('oid4vp.trustedIssuerCertificates'), 'signers'],
    purpose: 'vc-issuer' },
  { id: 'vc-issuer-mdoc', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'An mdoc Issuing Authority CA',
    sites: ['oid4vc/vc_mdoc.ts'],
    defaults: [setting('oid4vp.mdocTrustAnchors'), 'mdoc-own-iaca',
               'signers'],
    purpose: 'vc-issuer', variant: 'mdoc' },
  { id: 'vc-key-attestation', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'A wallet\'s key attestation chain',
    sites: ['oid4vc/vc_issuer.ts'],
    defaults: [setting('oid4vci.keyAttestationTrustedCertificates'),
               'signers'],
    purpose: 'vc-key-attestation' },
  { id: 'pkinit', scope: 'realm', kind: 'x509', direction: 'inbound',
    title: 'A Kerberos PKINIT client certificate',
    sites: ['kerberos/krb5_pkinit.ts'],
    defaults: ['service-root'], purpose: 'pkinit' },
  { id: 'enrollment-credential', scope: 'realm', kind: 'fixed',
    direction: 'inbound',
    title: 'An EST client certificate or SCEP renewal signer this service ' +
      'issued',
    sites: ['common/cert_enrollment.ts', 'scep/scep.ts', 'est/est.ts'],
    defaults: ['service-root'], purpose: 'enrollment-credential' },
  { id: 'spiffe-attestation-x509pop', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'A SPIFFE node\'s x509pop certificate',
    sites: ['spiffe/spiffe_attestor_x509pop.ts'],
    defaults: [setting('spiffe.x509popCaBundle'), 'signers'],
    purpose: 'spiffe-attestation', variant: 'x509pop' },
  { id: 'spiffe-attestation-tpm-devid', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'A SPIFFE node\'s TPM DevID certificate',
    sites: ['spiffe/spiffe_attestor_tpm_devid.ts'],
    defaults: [setting('spiffe.tpmDevidCaBundle'), 'signers'],
    purpose: 'spiffe-attestation', variant: 'tpm-devid' },
  { id: 'spiffe-attestation-tpm-ek', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'A SPIFFE node\'s TPM endorsement key certificate',
    sites: ['spiffe/spiffe_attestor_tpm_devid.ts'],
    defaults: [setting('spiffe.tpmEndorsementCaBundle'), 'signers'],
    purpose: 'spiffe-attestation', variant: 'tpm-ek' },
  { id: 'spiffe-attestation-azure', scope: 'realm', kind: 'x509',
    direction: 'inbound',
    title: 'An Azure IMDS attested document\'s signer',
    sites: ['spiffe/spiffe_attestor_azure_imds.ts'],
    defaults: [setting('spiffe.azureImdsTrustBundle'), 'cloud-attestation',
               'signers'],
    purpose: 'spiffe-attestation', variant: 'azure' },
  { id: 'spiffe-svid', scope: 'realm', kind: 'spiffe', direction: 'inbound',
    title: 'An X509-SVID, against the bundle of its trust domain',
    sites: ['spiffe/spiffe_auth.ts'],
    defaults: ['spiffe:*'], purpose: 'spiffe-svid' },
  { id: 'spiffe-jwt-svid', scope: 'realm', kind: 'spiffe',
    direction: 'inbound',
    title: 'A JWT-SVID, against the bundle of its trust domain',
    sites: ['spiffe/spiffe_ca.ts ValidateJWTSVID'],
    defaults: ['spiffe:*'] },
  // KEY SETS (#2149, rcbj 2026-11-25). A JWK names no owner, so these never
  // pool: each list names sources, and at a verification only the presenting
  // party's own contribute — its registration (`registered-keys`, the
  // default, which is what each site read before) and any key-set truststore
  // bound to it.
  { id: 'client-jws', scope: 'realm', kind: 'jwks', direction: 'inbound',
    title: 'A JWT or signature a client made: private_key_jwt, an RFC 7523 ' +
      'assertion, a request object, an HTTP message signature',
    sites: ['oauth-oidc/assertion_grant.js keysForParty',
            'oauth-oidc/client_auth.js', 'oauth-oidc/request_object.ts',
            'oauth-oidc/http_signatures.ts'],
    defaults: ['registered-keys'] },
  { id: 'federation-jwt', scope: 'realm', kind: 'jwks',
    direction: 'inbound',
    title: 'A token a federation partner signed: its ID Token, logout ' +
      'token or signed response',
    sites: ['federation/federation_sp.ts keysFor'],
    defaults: ['registered-keys'] },
  { id: 'ssf-set', scope: 'realm', kind: 'jwks', direction: 'inbound',
    title: 'A Security Event Token an SSF transmitter partner signed',
    sites: ['ssf/ssf_transmitters.ts'],
    defaults: ['registered-keys'] },
  { id: 'claims-provider-jwt', scope: 'realm', kind: 'jwks',
    direction: 'inbound',
    title: 'Aggregated or distributed claims a claims provider signed',
    sites: ['oauth-oidc/claims_providers.ts verifyFrom'],
    defaults: ['registered-keys'] },
  { id: 'revocation-signer', scope: 'service', kind: 'x509',
    direction: 'inbound',
    title: 'A CRL issuer outside the path of the certificate checked',
    sites: ['common/revocation_status.js'],
    defaults: [setting('pki.revocationCrlIssuersFile')],
    purpose: 'revocation-signer' },
  { id: 'cell-peer', scope: 'service', kind: 'fixed', direction: 'inbound',
    title: 'Another cell of this deployment',
    sites: ['common/cell_channel.ts'],
    defaults: ['service-root'], purpose: 'cell-peer' },
  { id: 'ca-import', scope: 'realm', kind: 'admission', direction: 'inbound',
    title: 'A certificate authority imported into this service\'s hierarchy',
    sites: ['common/pki.js importCa'], defaults: [], purpose: 'ca-import' },
  { id: 'anchor-admission', scope: 'realm', kind: 'admission',
    direction: 'inbound',
    title: 'A certificate added to a truststore',
    sites: ['common/truststores.ts', 'common/signer_truststore.ts',
            'tls/tls_server.js'],
    defaults: [], purpose: 'anchor-admission' },

  // ----- Outbound: the server certificate of whoever this service dials ---
  { id: 'outbound-federation', scope: 'service', kind: 'x509',
    direction: 'outbound',
    title: 'Federation partners, and every fetch that uses their transport',
    sites: ['federation/federation_http.ts'],
    defaults: ['system', setting('federation.outboundCaFile')] },
  { id: 'outbound-ssf', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'Shared Signals push delivery',
    sites: ['ssf/ssf_http.ts'],
    defaults: ['system', setting('ssf.pushCaFile')] },
  { id: 'outbound-gnap', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'GNAP push interaction finish',
    sites: ['gnap/gnap_http.ts'],
    defaults: ['system', setting('gnap.pushCaFile')] },
  { id: 'outbound-xacml-pep', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'The remote XACML PEP notification',
    sites: ['xacml/xacml_pep_http.ts'],
    defaults: ['system', 'service-root',
               setting('xacml.pepNotifyCaFile')] },
  { id: 'outbound-audit', scope: 'service', kind: 'x509',
    direction: 'outbound',
    title: 'Audit export to a webhook, Splunk HEC or syslog over TLS',
    sites: ['common/audit_export.ts'],
    defaults: ['system', setting('auditExport.caFile')] },
  { id: 'outbound-authzen-pdp', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'The external AuthZEN PDP',
    sites: ['authzen/authzen_external_pdp.ts'],
    defaults: [setting('authzen.externalPdpCaFile')],
    fallback: ['system', setting('federation.outboundCaFile')] },
  { id: 'outbound-scim', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'Outbound SCIM provisioning',
    sites: ['scim/scim_client.ts'],
    defaults: ['system', setting('scimClient.caFile')] },
  { id: 'outbound-secret-push', scope: 'service', kind: 'x509',
    direction: 'outbound',
    title: 'A rotated password pushed to a secret store',
    sites: ['common/secrets.js pushSecret'], defaults: ['system'] },
  { id: 'outbound-attribute-source', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'An operator\'s SQL attribute source',
    sites: ['attribute-sources/attribute_source_drivers.ts'],
    defaults: ['system'] },
  { id: 'outbound-smtp', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'The SMTP relay',
    sites: ['common/mail_transports.ts'],
    defaults: ['system', setting('mail.smtpCaFile')] },
  { id: 'outbound-icap', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'The ICAP malware scanner',
    sites: ['common/malware_scan.ts'],
    defaults: ['system', setting('malwareScan.caFile')] },
  { id: 'outbound-revocation-http', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'OCSP responders and CRLs over HTTPS',
    sites: ['common/revocation_status.js'],
    defaults: ['system', setting('pki.revocationHttpsCaFile')] },
  { id: 'outbound-revocation-ldap', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'CRLs over LDAPS',
    sites: ['common/revocation_status.js'],
    defaults: ['system', setting('pki.revocationLdapCaFile')] },
  { id: 'outbound-database', scope: 'service', kind: 'fixed',
    direction: 'outbound',
    title: 'The persistence database: dialled before the directory that ' +
      'holds the truststores can be read, so its own setting decides',
    sites: ['persistence/knex_store.js', 'persistence/persistence_postgres.js'],
    defaults: [setting('persistence.databaseTlsCaFile')],
    fallback: ['system'] },
  { id: 'outbound-secret-store', scope: 'service', kind: 'fixed',
    direction: 'outbound',
    title: 'The Vault or OpenBao secret store: dialled before the ' +
      'directory can be read, so its own setting decides',
    sites: ['common/secrets.js vaultTls'],
    defaults: [setting('keys.vaultCaCert')], fallback: ['system'] },
  { id: 'outbound-kubelet', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'The kubelet a SPIFFE workload runs on',
    sites: ['spiffe/spiffe_workload_attestor_k8s.ts'],
    defaults: [setting('spiffe.k8sKubeletCaFile')],
    fallback: ['k8s-in-cluster'] },
  { id: 'outbound-k8s-api', scope: 'service', kind: 'x509',
    direction: 'outbound', title: 'The Kubernetes API server (TokenReview)',
    sites: ['spiffe/spiffe_attestor_k8s_psat.ts'],
    defaults: ['k8s-in-cluster'], fallback: ['system'] },
  { id: 'outbound-cloud-sdk', scope: 'service', kind: 'fixed',
    direction: 'outbound',
    title: 'AWS, Google Cloud and Azure APIs: their SDKs build their own ' +
      'TLS from node\'s store and NODE_EXTRA_CA_CERTS',
    sites: ['common/secrets.js', 'common/mail_transports.ts',
            'cluster/spiffe_targets.js'],
    defaults: ['system'] },
  { id: 'outbound-loopback', scope: 'service', kind: 'fixed',
    direction: 'outbound', title: 'This service, dialled by itself',
    sites: ['common/oidc_rp.ts', 'ssf/ssf_http.ts'],
    defaults: ['service-root'] }
];

/**
 * The catalogue of use cases. A static utility class over one table.
 */
class TruststoreUseCases {
  static readonly ROWS: readonly UseCase[] = ROWS;

  /**
   * One use case.
   *
   * @param id - its id
   * @returns the row, or null
   */
  static get(id: string): UseCase | null {
    log.debug("Entering TruststoreUseCases.get(). " + id);
    const found = ROWS.filter(function (row) {
      return row.id === id;
    })[0] || null;
    log.debug("Leaving TruststoreUseCases.get().");
    return found;
  }

  /**
   * The use case a `certificate_trust.ts` purpose resolves its anchors
   * through, with a variant where one matters.
   *
   * @param purpose - the purpose id
   * @param variant - the variant, if any
   * @returns the row, or null where the purpose has none
   */
  static forPurpose(purpose: string, variant?: string): UseCase | null {
    log.debug("Entering TruststoreUseCases.forPurpose(). " + purpose);
    const matching = ROWS.filter(function (row) {
      return row.purpose === purpose;
    });
    const exact = matching.filter(function (row) {
      return (row.variant || '') === (variant || '');
    })[0];
    const any = matching.filter(function (row) {
      return !row.variant;
    })[0];
    log.debug("Leaving TruststoreUseCases.forPurpose().");
    return exact || any || matching[0] || null;
  }

  /**
   * Whether a use case takes an assigned list at all.
   *
   * @param row - the use case
   * @returns true for `x509` and `spiffe`
   */
  static assignable(row: UseCase | null): boolean {
    log.debug("Entering TruststoreUseCases.assignable().");
    log.debug("Leaving TruststoreUseCases.assignable().");
    return !!row && (row.kind === 'x509' || row.kind === 'spiffe' ||
                     row.kind === 'jwks');
  }

  /**
   * Whether a realm other than the default may assign a service-wide use case
   * a list of its own (#2148, rcbj 2026-11-24): an OUTBOUND x509 use case,
   * whose dial is made in a realm, used for that realm's own dials only. A
   * handshake has no realm, and a fixed row takes no list.
   *
   * @param row - the use case
   * @returns true for an assignable outbound service-wide use case
   */
  static overridable(row: UseCase | null): boolean {
    log.debug("Entering TruststoreUseCases.overridable().");
    log.debug("Leaving TruststoreUseCases.overridable().");
    return !!row && row.scope === 'service' && row.direction === 'outbound' &&
      row.kind === 'x509';
  }

  /**
   * Every legacy setting a default list names, once.
   *
   * @returns the setting keys
   */
  static legacySettings(): string[] {
    log.debug("Entering TruststoreUseCases.legacySettings().");
    const out: string[] = [];
    ROWS.forEach(function (row) {
      row.defaults.concat(row.fallback || []).forEach(function (name) {
        if (name.indexOf('setting:') === 0 &&
            out.indexOf(name.slice(8)) === -1) {
          out.push(name.slice(8));
        }
      });
    });
    log.debug("Leaving TruststoreUseCases.legacySettings(). " + out.length);
    return out;
  }
}

export = TruststoreUseCases;
