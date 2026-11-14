// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// ===========================================================================
// EVERY CERTIFICATE THIS SERVICE PINS, AS THE INVENTORY READS THEM (#1360,
// Phase 6).
//
// `CertificateTrust.pinnedCertificates()` asks a list of sources and holds what
// they name to the checks; this module is that list. A pin is a certificate an
// operator or a partner wrote down, which no chain vouches for and which nothing
// else would tell anybody had expired. So the owners are asked where their
// values live, and each owner is reached LAZILY, at the audit: several of them
// are route modules, and this library is required with the door, ahead of them.
//
// **`anchor-admission` IS THE PURPOSE OF A SETTING THAT HOLDS ANCHORS**: a root
// is judged as a root, and not as the leaf a signer's row would ask for. A
// certificate that signs in its own right keeps the row of its use case.
//
// A LIBRARY (rule 3): it registers no route, and it reads, never writes.
// ===========================================================================

import helpers = require('./helpers');
import config = require('./config');
import CertificateTrust = require('./certificate_trust');

type Json = any;
type PinnedSource = import('../types/certificate_trust').PinnedSource;

// Settings naming certificates: the setting, the page that edits it, and the
// purpose its contents are held to.
const SETTINGS: [string, string, string][] = [
  ['oid4vp.trustedIssuerCertificates', '/admin/vc', 'vc-issuer'],
  ['oid4vp.mdocTrustAnchors', '/admin/vc', 'anchor-admission'],
  ['oid4vci.keyAttestationTrustedCertificates', '/admin/vc',
   'anchor-admission'],
  ['webauthn.attestationTrustAnchors', '/admin/webauthn', 'anchor-admission'],
  ['webauthn.attestationEvidenceTsaTrustAnchors', '/admin/webauthn',
   'anchor-admission'],
  ['oauth2.clientAttestationTrustAnchors', '/admin/oauth2',
   'anchor-admission'],
  ['devices.androidAttestationTrustAnchors', '/admin/devices',
   'anchor-admission'],
  ['devices.appleAppAttestTrustAnchors', '/admin/devices', 'anchor-admission'],
  ['devices.tpmTrustAnchors', '/admin/devices', 'anchor-admission'],
  ['saml2.metadataTrustAnchors', '/admin/saml2', 'anchor-admission'],
  ['risk.mdsTrustAnchors', '/admin/risk', 'anchor-admission'],
  ['spiffe.x509popCaBundle', '/admin/spiffe', 'anchor-admission'],
  ['spiffe.tpmDevidCaBundle', '/admin/spiffe', 'anchor-admission'],
  ['spiffe.tpmEndorsementCaBundle', '/admin/spiffe', 'anchor-admission'],
  ['spiffe.azureImdsTrustBundle', '/admin/spiffe', 'anchor-admission']
];

// An application's attributes holding one certificate each.
const APPLICATION_CERTIFICATES: [string, string][] = [
  ['samlSigningCertificate', 'saml-signer'],
  ['samlSpMetadataSigningCertificate', 'saml-signer'],
  ['samlEncryptionCertificate', 'encryption-recipient'],
  ['oauthSamlAssertionSigningCertificate', 'saml-signer'],
  ['oauthSamlAssertionCertificate', 'saml-signer']
];

// An application's attributes holding a JWK set whose keys may carry an x5c.
const APPLICATION_JWKS = ['oauthJwks', 'oauthAssertionJwks'];

// The PEM blocks in a value; a value with none names nothing.
const PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/**
 * Registers every source with the door, and reads what each of them names.
 * A static utility class: `common/outbound_tls.ts`'s shape.
 */
class CertificatePins {
  /**
   * The certificates in a value that may hold several.
   *
   * @param value - PEM text, or nothing
   * @returns the PEM blocks
   */
  static blocksOf(value: unknown): string[] {
    helpers.log.debug("Entering CertificatePins.blocksOf().");
    helpers.log.debug("Leaving CertificatePins.blocksOf().");
    return String(value === undefined || value === null ? '' : value)
      .match(PEM_BLOCK) || [];
  }

  // The first value of an attribute, as a string. BY NAME ON PURPOSE
  // (#1579): the audit reports each pin as `<application> <attribute>`, so
  // the attribute is the answer as well as where the value is read from,
  // and the tables below name the attributes that hold a certificate.
  private static fieldOf(record: Json, name: string): string {
    helpers.log.debug("Entering CertificatePins.fieldOf().");
    const raw = record && record.fields ? record.fields[name] : undefined;
    const value = Array.isArray(raw) ? raw[0] : raw;
    helpers.log.debug("Leaving CertificatePins.fieldOf().");
    return value === undefined || value === null ? '' : String(value);
  }

  // The `x5c[0]` of every key in a JWK set: a value that is not JSON names no
  // certificate here, and its own door reports that it is not JSON.
  private static x5cOf(text: string): { pem: string; chain: string[] }[] {
    helpers.log.debug("Entering CertificatePins.x5cOf().");
    let keys: Json[] = [];
    try {
      const parsed = text ? JSON.parse(text) : null;
      keys = parsed && Array.isArray(parsed.keys) ? parsed.keys : [];
    } catch (e) {
      helpers.log.debug("Caught in CertificatePins.x5cOf(): " +
                        ((e && e.message) || e));
    }
    const out = keys.filter(function (key: Json) {
      return key && Array.isArray(key.x5c) && key.x5c.length;
    }).map(function (key: Json) {
      return { pem: String(key.x5c[0]), chain: key.x5c.slice(1).map(String) };
    });
    helpers.log.debug("Leaving CertificatePins.x5cOf(). " + out.length);
    return out;
  }

  /**
   * What the realm's settings pin.
   *
   * @returns the rows
   */
  static fromSettings(): PinnedSource[] {
    helpers.log.debug("Entering CertificatePins.fromSettings().");
    const rows: PinnedSource[] = [];
    SETTINGS.forEach(function (row) {
      CertificatePins.blocksOf(config.value(row[0]))
        .forEach(function (pem, i) {
          rows.push({ source: 'setting', where: row[0] + ' #' + (i + 1),
                      purpose: row[2], pem: pem, href: row[1] });
        });
    });
    helpers.log.debug("Leaving CertificatePins.fromSettings(). " + rows.length);
    return rows;
  }

  /**
   * What the realm's applications pin. A thumbprint alone is listed as one,
   * since the certificate it names is not here to read.
   *
   * @returns the rows
   */
  static fromApplications(): PinnedSource[] {
    helpers.log.debug("Entering CertificatePins.fromApplications().");
    const rows: PinnedSource[] = [];
    require('./applications').list().forEach(function (app: Json) {
      const where = function (attribute: string): string {
        helpers.log.debug("Entering where().");
        helpers.log.debug("Leaving where().");
        return app.identifier + ' ' + attribute;
      };
      const href = '/admin/applications?application=' +
                   encodeURIComponent(app.identifier);
      APPLICATION_CERTIFICATES.forEach(function (row) {
        const pem = CertificatePins.fieldOf(app, row[0]);
        if (pem) {
          rows.push({ source: 'application', where: where(row[0]),
                      purpose: row[1], pem: pem, href: href });
        }
      });
      APPLICATION_JWKS.forEach(function (attribute) {
        CertificatePins.x5cOf(CertificatePins.fieldOf(app, attribute))
          .forEach(function (one) {
            rows.push({ source: 'application', where: where(attribute),
                        purpose: 'jose-signer', pem: one.pem, chain: one.chain,
                        href: href });
          });
      });
      const thumbprint = CertificatePins.fieldOf(
        app, 'oauthTlsClientCertificateThumbprint');
      if (thumbprint) {
        rows.push({ source: 'application',
                    where: where('oauthTlsClientCertificateThumbprint'),
                    purpose: 'tls-client-self-signed', thumbprint: thumbprint,
                    href: href });
      }
    });
    helpers.log.debug("Leaving CertificatePins.fromApplications(). " +
                      rows.length);
    return rows;
  }

  /**
   * What the realm's federation relationships pin.
   *
   * @returns the rows
   */
  static fromFederation(): PinnedSource[] {
    helpers.log.debug("Entering CertificatePins.fromFederation().");
    const rows: PinnedSource[] = [];
    require('../federation/federation').list().forEach(function (one: Json) {
      const href = '/admin/federation/' + encodeURIComponent(one.id);
      CertificatePins.blocksOf(one.fedSigningCertificate)
        .forEach(function (pem) {
          rows.push({ source: 'federation',
                      where: one.id + ' fedSigningCertificate',
                      purpose: 'federation-partner', pem: pem, href: href });
        });
      CertificatePins.x5cOf(String(one.fedJwks || ''))
        .forEach(function (key) {
          rows.push({ source: 'federation', where: one.id + ' fedJwks',
                      purpose: 'federation-partner', pem: key.pem,
                      chain: key.chain, href: href });
        });
    });
    helpers.log.debug("Leaving CertificatePins.fromFederation(). " + rows.length);
    return rows;
  }

  /**
   * The authorities in the realm's federated SPIFFE bundles.
   *
   * @returns the rows
   */
  static fromSpiffeBundles(): PinnedSource[] {
    helpers.log.debug("Entering CertificatePins.fromSpiffeBundles().");
    const rows: PinnedSource[] = [];
    require('../spiffe/spiffe_ca').federatedBundles()
      .forEach(function (bundle: Json) {
        const keys = (bundle.document && bundle.document.keys) || [];
        keys.forEach(function (key: Json) {
          ((key && key.use === 'x509-svid' && key.x5c) || [])
            .forEach(function (one: string) {
              rows.push({ source: 'spiffe',
                          where: 'federated bundle ' + bundle.trustDomain,
                          purpose: 'anchor-admission', pem: String(one),
                          href: '/admin/spiffe' });
            });
        });
      });
    helpers.log.debug("Leaving CertificatePins.fromSpiffeBundles(). " +
                      rows.length);
    return rows;
  }

  /**
   * The certificate a registered GNAP client instance presents by value.
   *
   * @returns the rows
   */
  static fromGnapClients(): PinnedSource[] {
    helpers.log.debug("Entering CertificatePins.fromGnapClients().");
    const rows: PinnedSource[] = [];
    require('./applications').list().forEach(function (app: Json) {
      const text = CertificatePins.fieldOf(app, 'gnapKey');
      if (!text) {
        return;
      }
      let key: Json = null;
      try {
        key = JSON.parse(text);
      } catch (e) {
        // `gnap_grants.ts` logs a gnapKey that is not JSON, and it names no key.
        helpers.log.debug("Caught in CertificatePins.fromGnapClients(): " +
                          ((e && e.message) || e));
      }
      if (key && key.cert) {
        rows.push({ source: 'gnap', where: app.identifier + ' gnapKey',
                    purpose: 'tls-client-self-signed', pem: String(key.cert),
                    href: '/admin/applications?application=' +
                          encodeURIComponent(app.identifier) });
      } else if (key && key['cert#S256']) {
        rows.push({ source: 'gnap', where: app.identifier + ' gnapKey',
                    purpose: 'tls-client-self-signed',
                    thumbprint: String(key['cert#S256']),
                    href: '/admin/applications?application=' +
                          encodeURIComponent(app.identifier) });
      }
    });
    helpers.log.debug("Leaving CertificatePins.fromGnapClients(). " +
                      rows.length);
    return rows;
  }

  /**
   * The cloud providers' certificates this service ships, once per certificate:
   * they are pinned by the image, so the realm never wrote them down, and an
   * expired one is still something its operator needs to hear. The image is
   * the same for every realm, so only the default realm lists them, and a
   * realm's audit does not repeat eighty-odd assessments.
   *
   * @param realmId - the realm the audit is asking about
   * @returns the rows
   */
  static fromCloudAnchors(realmId: string): PinnedSource[] {
    helpers.log.debug("Entering CertificatePins.fromCloudAnchors().");
    if (realmId !== 'default') {
      helpers.log.debug("Leaving CertificatePins.fromCloudAnchors(). Not here.");
      return [];
    }
    const table = require('./pki_cloud_anchors.json');
    const seen = new Set<string>();
    const rows: PinnedSource[] = [];
    const add = function (where: string, pem: string): void {
      helpers.log.debug("Entering add().");
      if (!seen.has(pem)) {
        seen.add(pem);
        rows.push({ source: 'cloud', where: where,
                    purpose: 'spiffe-attestation', pem: pem,
                    href: '/admin/spiffe' });
      }
      helpers.log.debug("Leaving add().");
    };
    ['awsRsa2048', 'awsRsa1024'].forEach(function (name) {
      Object.keys(table[name]).forEach(function (region) {
        add(name + ' ' + region, table[name][region]);
      });
    });
    add('awsRsa1024 default', table.awsRsa1024Default);
    table.azureRoots.forEach(function (pem: string, i: number) {
      add('azureRoots #' + (i + 1), pem);
    });
    helpers.log.debug("Leaving CertificatePins.fromCloudAnchors(). " +
                      rows.length);
    return rows;
  }

  /**
   * The client-certificate truststore, for completeness: the service's own, so
   * only the default realm lists it, and its page has its own link. It holds
   * parsed facts rather than PEM, so a row is its fingerprint.
   *
   * @param realmId - the realm the audit is asking about
   * @returns the rows
   */
  static fromClientTruststore(realmId: string): PinnedSource[] {
    helpers.log.debug("Entering CertificatePins.fromClientTruststore().");
    if (realmId !== 'default') {
      helpers.log.debug("Leaving CertificatePins.fromClientTruststore(). " +
                        "Not here.");
      return [];
    }
    const held = require('../tls/tls_server').truststore.list().anchors;
    const rows = held.map(function (one: Json) {
      return { source: 'client-truststore', where: one.subject,
               purpose: 'anchor-admission', thumbprint: one.fingerprint256,
               href: '/admin/tls/trust' };
    });
    helpers.log.debug("Leaving CertificatePins.fromClientTruststore(). " +
                      rows.length);
    return rows;
  }

  /**
   * Hands every source to the door.
   */
  static install(): void {
    helpers.log.debug("Entering CertificatePins.install().");
    CertificateTrust.registerPinSource('settings',
                                       CertificatePins.fromSettings);
    CertificateTrust.registerPinSource('applications',
                                       CertificatePins.fromApplications);
    CertificateTrust.registerPinSource('federation',
                                       CertificatePins.fromFederation);
    CertificateTrust.registerPinSource('spiffe-bundles',
                                       CertificatePins.fromSpiffeBundles);
    CertificateTrust.registerPinSource('gnap-clients',
                                       CertificatePins.fromGnapClients);
    CertificateTrust.registerPinSource('cloud-anchors',
                                       CertificatePins.fromCloudAnchors);
    CertificateTrust.registerPinSource('client-truststore',
                                       CertificatePins.fromClientTruststore);
    helpers.log.debug("Leaving CertificatePins.install().");
  }
}

export = CertificatePins;
