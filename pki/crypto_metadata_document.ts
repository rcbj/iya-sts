'use strict';
//
// File: pki/crypto_metadata_document.ts
//
// ===========================================================================
// THE PUBLIC CRYPTO METADATA DOCUMENT, PER REALM (2026-09-22, #42; rcbj's D8
// and D9).
//
// Every signer certificate of every unit of this realm — each key GENERATION,
// current, next and retired (`common/helpers.js`, KEY GENERATIONS) — with its
// kid, its chain to the Root, its validity, SHA-256 fingerprint, state and,
// for a retired key, until when it still verifies; every algorithm per use
// case and the default of each; and the rotation policy the realm runs. A
// document of this service's own design: no specification defines one, which
// is why its XML has a namespace and a schema of its own
// (`urn:iya:sts:crypto-metadata:1`, `/crypto/metadata.xsd`).
//
//   GET /crypto/metadata          by `Accept`: JSON (the default), XML, or the
//                                 signed JSON (`application/jwt`)
//   GET /crypto/metadata.json     the model, as JSON
//   GET /crypto/metadata.xml      the same model, as XML
//   GET /crypto/metadata.jwt      the JSON, signed — a JWS by the current
//                                 `jose` signer, through the one signer RFC
//                                 8414's `signed_metadata` uses (D9)
//   GET /crypto/metadata.signed.xml   the XML with an enveloped XML Signature
//                                 by the current `xml` signer (D9)
//   GET /crypto/metadata.xsd      the schema
//
// Per realm by the realm prefix (`/realm/<id>/crypto/metadata.json`), like
// every other document here. **PUBLIC AND ANONYMOUS IN BOTH MODES**, like the
// JWKS, because it holds public material only: it is built from the SAME
// lookups the JWKS and the SAML metadata are built from
// (`helpers.ownRsaCertificates()`, `helpers.standbyOf()`, the key set's own
// public JWKs) and no private half is ever read. **`Cache-Control:
// no-store`**, as every document that describes a key is (root CLAUDE.md).
//
// **ONE MODEL, TWO SERIALISATIONS.** `model()` is the document; `toXml()`
// writes the same object as XML, so the two cannot describe different keys.
// It is NOT `/admin/crypto-metadata`, which is gated and reports this
// service's algorithm tables and settings — an operator's business. This is
// the published subset, and that page links here.
//
// A ROUTE MODULE in `pki/` because `pki/` is this service's public,
// credential-free surface for certificates (`pki_service.ts`); registered by
// `common/protocol_stack.ts` beside it (17c).
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import InstanceSlot = require('../common/instance_slot');
import nodeCrypto = require('crypto');

type Req = any;
type Res = any;
type Json = any;

const BASE = '/crypto/metadata';
const XML_NS = 'urn:iya:sts:crypto-metadata:1';
const SPEC_VERSION = 1;

// What each unit's key signs, by use case — the purposes a relying party
// might look a key up for. A per-token-type signer (D2's later phase) makes
// this a table of its own; until then every JOSE purpose is the JOSE unit's.
const PURPOSES: Json = {
  'jose:RS256': ['access_token', 'id_token', 'refresh_token', 'logout_token',
                 'userinfo_response', 'introspection_response',
                 'signed_metadata', 'software_statement', 'security_event',
                 'credential', 'status_list', 'request_object'],
  jose: ['id_token', 'userinfo_response', 'credential', 'introspection_response',
         'logout_token', 'signed_metadata'],
  xml: ['saml2_assertion', 'saml2_protocol_message', 'saml11_assertion',
        'wsfed_token', 'saml_metadata', 'wsfed_metadata', 'authn_request']
};

interface CryptoMetadataDeps {
  log: typeof helpers.log;
  helpers: typeof helpers;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  // The PKI, required LAZILY: `pki.js` requires `keystore.js`, and this module
  // is loaded where the stack's order says, not where the CA's does.
  pki: () => Json;
  revocation: () => Json;
  // `oauth2.ts`'s `signPublishedDocument()` — the one JWS signer for a
  // published document (D9). Lazy for the same reason.
  signPublishedDocument: (claims: Json, issuer: string, lifetimeS: number,
                          useCase: string) => string;
  now: () => number;
}

class CryptoMetadataDocument {
  static readonly BASE = BASE;
  static readonly XML_NS = XML_NS;

  constructor(private readonly deps: CryptoMetadataDeps) {
    deps.log.debug("Entering CryptoMetadataDocument.constructor().");
    deps.log.debug("Leaving CryptoMetadataDocument.constructor().");
  }

  static defaultDeps(): CryptoMetadataDeps {
    helpers.log.debug("Entering CryptoMetadataDocument.defaultDeps().");
    helpers.log.debug("Leaving CryptoMetadataDocument.defaultDeps().");
    return {
      log: helpers.log,
      helpers: helpers,
      config: config,
      realms: realms,
      errorCodes: errorCodes,
      stsCrypto: stsCrypto,
      pki: function (): Json {
        return require('../common/pki');
      },
      revocation: function (): Json {
        return require('../common/pki_revocation');
      },
      signPublishedDocument: function (claims: Json, issuer: string,
                                       lifetimeS: number,
                                       useCase: string): string {
        // certificate-header: none — a pass-through: the use case is the
        // caller's, and signedJson() names 'oauth-signed-metadata'.
        return require('../oauth-oidc/oauth2')
          .signPublishedDocument(claims, issuer, lifetimeS, useCase);
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // A certificate PEM as the base64 of its DER, for `x5c`.
  private der64(pem: string): string {
    const { log } = this.deps;
    log.debug("Entering CryptoMetadataDocument.der64().");
    log.debug("Leaving CryptoMetadataDocument.der64().");
    return String(pem || '').replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, '');
  }

  // One certificate's public facts: the chain leaf first, validity, the
  // SHA-256 fingerprint of the DER, the serial, and where its issuer's CRL,
  // OCSP responder and certificate are.
  private certificateOf(realmId: string, useCaseId: string, slot: string,
                        kid: string, fallbackPem: string): Json {
    const { log, pki, revocation } = this.deps;
    log.debug("Entering CryptoMetadataDocument.certificateOf(). " + kid);
    let record: Json = null;
    try {
      record = pki().certificateFor(realmId, useCaseId, slot, kid);
    } catch (e) {
      log.debug("Caught in CryptoMetadataDocument.certificateOf(): " +
                ((e && e.message) || e));
      record = null;
    }
    const pem = record ? record.certificatePem : fallbackPem;
    if (!pem) {
      log.debug("Leaving CryptoMetadataDocument.certificateOf(). None.");
      return null;
    }
    const x509 = new nodeCrypto.X509Certificate(pem);
    let points: Json = null;
    if (record) {
      try {
        points = revocation().distributionPoints(realmId, useCaseId);
      } catch (e) {
        log.debug("Caught in CryptoMetadataDocument.certificateOf(): " +
                  ((e && e.message) || e));
        points = null;
      }
    }
    const out: Json = {
      x5c: [this.der64(pem)].concat(((record && record.chainPem) || [])
        .map(this.der64.bind(this))),
      subject: x509.subject.replace(/\n/g, ', '),
      issuer: x509.issuer.replace(/\n/g, ', '),
      serialNumber: x509.serialNumber,
      notBefore: new Date(x509.validFrom).toISOString(),
      notAfter: new Date(x509.validTo).toISOString(),
      sha256Fingerprint: nodeCrypto.createHash('sha256').update(x509.raw)
        .digest('hex'),
      selfSigned: !record,
      crl: points ? [points.http, points.ldap] : [],
      ocsp: points ? points.ocsp : null,
      caIssuers: points ? points.caIssuers : null
    };
    log.debug("Leaving CryptoMetadataDocument.certificateOf().");
    return out;
  }

  // Every unit of the realm, and every live generation of each.
  private unitsOf(realmId: string): Json[] {
    const { log, helpers } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadataDocument.unitsOf().");
    const keys: Json = helpers.stsKeysFor.of(realmId);
    // The PKI's scope is the key set's own realm id — what `ownRsaCertificates`
    // and `certifyKeySet()` name it by.
    const scope = String(keys.realm || realmId);
    const xml = helpers.xmlKeyFor(keys);
    const now = this.deps.now();
    const out = helpers.signingUnitsOf(keys).map(function (row: Json): Json {
      const current: Json = { kid: row.kid, state: 'current' };
      let currentPem = '';
      if (row.unit === 'jose:RS256') {
        currentPem = keys.selfSignedCertPem || keys.certPem;
        current.jwk = Object.assign(nodeCrypto.createPublicKey(currentPem)
          .export({ format: 'jwk' }), { kid: row.kid, use: 'sig' });
      } else if (row.unit === 'xml:RS256') {
        currentPem = xml.selfSignedCertPem;
      } else if (row.kind === 'bbs') {
        // A BBS key has no JWK; it is published as a Multikey (#49 P5).
        current.jwk = null;
        current.publicKeyMultibase = 'u' + Buffer.from(keys.bbsKey.publicKey)
          .toString('base64url');
      } else if (row.kind === 'group') {
        // A SIGNER-GROUP CERTIFICATE (#68): its primary key and — rcbj's D5,
        // stated here because the JWKS publishes the partner bare — the
        // ML-DSA key certified beside it in subjectAltPublicKeyInfo.
        const members: Json[] = keys.signerGroups || [];
        const primary = members.filter(function (one: Json): boolean {
          return one.slot === row.slot;
        })[0];
        const partner = row.pairedSlot
          ? members.filter(function (one: Json): boolean {
              return one.slot === row.pairedSlot;
            })[0] : null;
        current.group = row.group;
        current.jwk = row.useCase === 'xml' ? null
          : ((primary || {}).publicJwk || null);
        if (partner) {
          current.alternativeKey = {
            kid: partner.publicJwk.kid, alg: partner.alg,
            jwk: row.useCase === 'xml' ? null : partner.publicJwk,
            certifiedAs: 'subjectAltPublicKeyInfo (ITU-T X.509 clause 9.8)'
          };
        }
      } else {
        const list = row.kind === 'pq' ? keys.pqKeys : keys.extraKeys;
        current.jwk = (list[row.index] || {}).publicJwk || null;
      }
      current.certificate = self.certificateOf(scope, row.useCase,
                                               row.slot, row.kid, currentPem);
      const standby = helpers.standbyOf(keys, row.unit)
        .filter(function (one: Json): boolean {
          return one.role === 'next' || !(Number(one.retiredUntil) > 0) ||
                 Number(one.retiredUntil) > now;
        }).map(function (one: Json): Json {
          return {
            kid: one.kid, state: one.role,
            // Which half of a signer-group pair this is (#68).
            slot: row.kind === 'group' ? one.slot : undefined,
            createdAt: one.createdAt
              ? new Date(Number(one.createdAt)).toISOString() : null,
            retiredAt: one.retiredAt
              ? new Date(Number(one.retiredAt)).toISOString() : null,
            retiredUntil: one.retiredUntil
              ? new Date(Number(one.retiredUntil)).toISOString() : null,
            jwk: row.useCase === 'xml' || row.kind === 'bbs' ? null
              : one.publicJwk,
            publicKeyMultibase: one.publicKeyB64
              ? 'u' + Buffer.from(one.publicKeyB64, 'base64')
                .toString('base64url') : undefined,
            certificate: self.certificateOf(scope, row.useCase, row.slot,
                                            one.kid, one.certPem || '')
          };
        });
      return {
        unit: row.unit, useCase: row.useCase, alg: row.alg,
        crv: row.crv || null, kind: row.kind,
        purposes: PURPOSES[row.unit] || PURPOSES[row.useCase] || [],
        lastRotated: keys.generations && keys.generations.rotated &&
          keys.generations.rotated[row.unit]
          ? new Date(Number(keys.generations.rotated[row.unit])).toISOString()
          : null,
        keys: [current].concat(standby)
      };
    });
    log.debug("Leaving CryptoMetadataDocument.unitsOf(). " + out.length +
              " unit(s).");
    return out;
  }

  // The algorithms, per use case, and the default of each.
  private algorithms(): Json {
    const { log, stsCrypto, config } = this.deps;
    log.debug("Entering CryptoMetadataDocument.algorithms().");
    let xmlDefault = '';
    try {
      xmlDefault = require('../saml/document_settings').signatureOptions()
        .sigAlg;
    } catch (e) {
      log.debug("Caught in CryptoMetadataDocument.algorithms(): " +
                ((e && e.message) || e));
      xmlDefault = '';
    }
    const out = {
      jose: {
        signing: stsCrypto.JWS_ASYMMETRIC_ALGS.slice(),
        default: 'RS256',
        signedMetadata: String(config.value('oauth2.signedMetadataAlgorithm') ||
                               'RS256'),
        encryption: {
          alg: stsCrypto.JWE_ALGS.slice(),
          enc: Object.keys(stsCrypto.JWE_ENCS)
        }
      },
      xml: {
        // What is VERIFIED, SHA-1 and all (flagged weak on /admin/crypto-
        // metadata); a relying party reads `default` for what is SENT.
        signing: stsCrypto.xmlSignatureAlgorithms().verified
          .filter(function (row: Json): boolean {
            return !row.weak;
          }).map(function (row: Json): string {
            return row.uri;
          }),
        default: xmlDefault
      }
    };
    log.debug("Leaving CryptoMetadataDocument.algorithms().");
    return out;
  }

  // The rotation policy the realm runs (#42).
  private rotation(): Json {
    const { log, config } = this.deps;
    log.debug("Entering CryptoMetadataDocument.rotation().");
    let product = false;
    try {
      product = !!require('../common/mode').rotatesSigningKeys();
    } catch (e) {
      log.debug("Caught in CryptoMetadataDocument.rotation(): " +
                ((e && e.message) || e));
      product = false;
    }
    const interval = Number(config.value('signing.rotationIntervalDays'));
    const out = {
      scheduled: product && interval > 0,
      intervalDays: interval,
      retiredKeyGraceDays: Number(config.value('signing.retiredKeyGraceDays')),
      why: product ? (interval > 0 ? 'every signing key is replaced every ' +
                      interval + ' day(s); its next key is published from ' +
                      'the moment it is minted'
                                   : 'signing.rotationIntervalDays is 0')
        : 'this is a development-mode service, whose keys are made anew at ' +
          'every start and are not rotated'
    };
    log.debug("Leaving CryptoMetadataDocument.rotation().");
    return out;
  }

  // THE MODEL — the document, as one object, which both serialisations write.
  model(req: Req): Json {
    const { log, helpers, realms, now } = this.deps;
    log.debug("Entering CryptoMetadataDocument.model().");
    const realmId = realms.currentId();
    const base = helpers.baseUrlOf(req);
    const out = {
      specVersion: SPEC_VERSION,
      issuer: base,
      realm: realmId,
      generatedAt: new Date(now()).toISOString(),
      rotation: this.rotation(),
      units: this.unitsOf(realmId),
      algorithms: this.algorithms(),
      links: {
        jwks_uri: base + '/oauth2/jwks',
        openid_configuration: base + '/.well-known/openid-configuration',
        saml2_metadata: base + '/saml2/metadata',
        wsfed_metadata: base +
                        '/FederationMetadata/2007-06/FederationMetadata.xml',
        json: base + BASE + '.json',
        xml: base + BASE + '.xml',
        signed_json: base + BASE + '.jwt',
        signed_xml: base + BASE + '.signed.xml',
        schema: base + BASE + '.xsd'
      }
    };
    log.debug("Leaving CryptoMetadataDocument.model().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE XML SERIALISATION of the same model, in the document's namespace.
  // ---------------------------------------------------------------------------
  private esc(value: unknown): string {
    const { log, helpers } = this.deps;
    log.debug("Entering CryptoMetadataDocument.esc().");
    log.debug("Leaving CryptoMetadataDocument.esc().");
    return helpers.xmlEscape(String(value === null || value === undefined ? ''
                                                                        : value));
  }

  private el(name: string, value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering CryptoMetadataDocument.el().");
    log.debug("Leaving CryptoMetadataDocument.el().");
    return value === null || value === undefined || value === '' ? ''
      : '<cm:' + name + '>' + this.esc(value) + '</cm:' + name + '>';
  }

  private certificateXml(c: Json): string {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadataDocument.certificateXml().");
    if (!c) {
      log.debug("Leaving CryptoMetadataDocument.certificateXml(). None.");
      return '';
    }
    log.debug("Leaving CryptoMetadataDocument.certificateXml().");
    return '<cm:Certificate selfSigned="' + (c.selfSigned ? 'true' : 'false') +
      '">' + self.el('Subject', c.subject) + self.el('Issuer', c.issuer) +
      self.el('SerialNumber', c.serialNumber) +
      self.el('NotBefore', c.notBefore) + self.el('NotAfter', c.notAfter) +
      self.el('Sha256Fingerprint', c.sha256Fingerprint) +
      '<cm:Chain>' + c.x5c.map(function (one: string): string {
        return self.el('X509Certificate', one);
      }).join('') + '</cm:Chain>' +
      (c.crl || []).map(function (u: string): string {
        return self.el('CrlDistributionPoint', u);
      }).join('') + self.el('Ocsp', c.ocsp) +
      self.el('CaIssuers', c.caIssuers) + '</cm:Certificate>';
  }

  toXml(m: Json): string {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadataDocument.toXml().");
    const units = m.units.map(function (u: Json): string {
      return '<cm:Unit id="' + self.esc(u.unit) + '" useCase="' +
        self.esc(u.useCase) + '" alg="' + self.esc(u.alg) + '"' +
        (u.crv ? ' crv="' + self.esc(u.crv) + '"' : '') + ' kind="' +
        self.esc(u.kind) + '">' + self.el('LastRotated', u.lastRotated) +
        '<cm:Purposes>' + u.purposes.map(function (p: string): string {
          return self.el('Purpose', p);
        }).join('') + '</cm:Purposes>' +
        u.keys.map(function (k: Json): string {
          return '<cm:Key kid="' + self.esc(k.kid) + '" state="' +
            self.esc(k.state) + '">' + self.el('CreatedAt', k.createdAt) +
            self.el('RetiredAt', k.retiredAt) +
            self.el('RetiredUntil', k.retiredUntil) +
            (k.jwk ? self.el('Jwk', JSON.stringify(k.jwk)) : '') +
            self.certificateXml(k.certificate) + '</cm:Key>';
        }).join('') + '</cm:Unit>';
    }).join('');
    const list = function (name: string, items: string[]): string {
      return (items || []).map(function (one: string): string {
        return self.el(name, one);
      }).join('');
    };
    const a = m.algorithms;
    const xml = '<?xml version="1.0" encoding="UTF-8"?>' +
      '<cm:CryptoMetadata xmlns:cm="' + XML_NS + '" ID="_cm' +
      nodeCrypto.randomBytes(8).toString('hex') + '" specVersion="' +
      m.specVersion + '" issuer="' + self.esc(m.issuer) + '" realm="' +
      self.esc(m.realm) + '" generatedAt="' + self.esc(m.generatedAt) + '">' +
      '<cm:Rotation scheduled="' + (m.rotation.scheduled ? 'true' : 'false') +
      '" intervalDays="' + m.rotation.intervalDays + '" retiredKeyGraceDays="' +
      m.rotation.retiredKeyGraceDays + '">' + self.esc(m.rotation.why) +
      '</cm:Rotation>' +
      '<cm:Units>' + units + '</cm:Units>' +
      '<cm:Algorithms>' +
      '<cm:UseCase id="jose" default="' + self.esc(a.jose.default) + '">' +
      list('Signing', a.jose.signing) + list('KeyEncryption',
                                             a.jose.encryption.alg) +
      list('ContentEncryption', a.jose.encryption.enc) + '</cm:UseCase>' +
      '<cm:UseCase id="xml" default="' + self.esc(a.xml.default) + '">' +
      list('Signing', a.xml.signing) + '</cm:UseCase>' +
      '</cm:Algorithms>' +
      '<cm:Links>' + Object.keys(m.links).map(function (k: string): string {
        return '<cm:Link rel="' + self.esc(k) + '">' + self.esc(m.links[k]) +
               '</cm:Link>';
      }).join('') + '</cm:Links>' +
      '</cm:CryptoMetadata>';
    log.debug("Leaving CryptoMetadataDocument.toXml().");
    return xml;
  }

  // The XSD, served at `/crypto/metadata.xsd`.
  //
  // **IT DECLARES `cm:CryptoMetadataLocation` TOO (#188, 2026-09-24)** — the
  // one element of this namespace that is NOT in this document: the SAML 2.0
  // identity provider metadata carries it in its `md:Extensions`
  // (`saml/saml2_sso.ts`, #42 D8) to say where this document is. It was in
  // no schema at all until then, so a validator loading this one to check
  // that extension found nothing to check it against —
  // tests/vendored/sts_xml_schema_validation.js loads this file for exactly
  // that and refused the metadata until the declaration was here.
  static schema(): string {
    helpers.log.debug("Entering CryptoMetadataDocument.schema().");
    helpers.log.debug("Leaving CryptoMetadataDocument.schema().");
    const t = function (name: string): string {
      return '<xs:element name="' + name + '" type="xs:string" minOccurs="0"/>';
    };
    const many = function (name: string): string {
      return '<xs:element name="' + name + '" type="xs:string" minOccurs="0" ' +
             'maxOccurs="unbounded"/>';
    };
    return '<?xml version="1.0" encoding="UTF-8"?>' +
      '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" ' +
      'xmlns:cm="' + XML_NS + '" targetNamespace="' + XML_NS + '" ' +
      'elementFormDefault="qualified">' +
      '<xs:element name="CryptoMetadata"><xs:complexType><xs:sequence>' +
      '<xs:any namespace="http://www.w3.org/2000/09/xmldsig#" ' +
      'processContents="lax" minOccurs="0"/>' +
      '<xs:element name="Rotation"><xs:complexType><xs:simpleContent>' +
      '<xs:extension base="xs:string">' +
      '<xs:attribute name="scheduled" type="xs:boolean" use="required"/>' +
      '<xs:attribute name="intervalDays" type="xs:int" use="required"/>' +
      '<xs:attribute name="retiredKeyGraceDays" type="xs:int" ' +
      'use="required"/></xs:extension></xs:simpleContent></xs:complexType>' +
      '</xs:element>' +
      '<xs:element name="Units"><xs:complexType><xs:sequence>' +
      '<xs:element name="Unit" minOccurs="0" maxOccurs="unbounded">' +
      '<xs:complexType><xs:sequence>' + t('LastRotated') +
      '<xs:element name="Purposes"><xs:complexType><xs:sequence>' +
      many('Purpose') + '</xs:sequence></xs:complexType></xs:element>' +
      '<xs:element name="Key" maxOccurs="unbounded"><xs:complexType>' +
      '<xs:sequence>' + t('CreatedAt') + t('RetiredAt') + t('RetiredUntil') +
      t('Jwk') +
      '<xs:element name="Certificate" minOccurs="0"><xs:complexType>' +
      '<xs:sequence>' + t('Subject') + t('Issuer') + t('SerialNumber') +
      t('NotBefore') + t('NotAfter') + t('Sha256Fingerprint') +
      '<xs:element name="Chain"><xs:complexType><xs:sequence>' +
      many('X509Certificate') + '</xs:sequence></xs:complexType>' +
      '</xs:element>' + many('CrlDistributionPoint') + t('Ocsp') +
      t('CaIssuers') + '</xs:sequence>' +
      '<xs:attribute name="selfSigned" type="xs:boolean" use="required"/>' +
      '</xs:complexType></xs:element></xs:sequence>' +
      '<xs:attribute name="kid" type="xs:string" use="required"/>' +
      '<xs:attribute name="state" use="required"><xs:simpleType>' +
      '<xs:restriction base="xs:string"><xs:enumeration value="current"/>' +
      '<xs:enumeration value="next"/><xs:enumeration value="retired"/>' +
      '</xs:restriction></xs:simpleType></xs:attribute>' +
      '</xs:complexType></xs:element></xs:sequence>' +
      '<xs:attribute name="id" type="xs:string" use="required"/>' +
      '<xs:attribute name="useCase" type="xs:string" use="required"/>' +
      '<xs:attribute name="alg" type="xs:string" use="required"/>' +
      '<xs:attribute name="crv" type="xs:string"/>' +
      '<xs:attribute name="kind" type="xs:string" use="required"/>' +
      '</xs:complexType></xs:element></xs:sequence></xs:complexType>' +
      '</xs:element>' +
      '<xs:element name="Algorithms"><xs:complexType><xs:sequence>' +
      '<xs:element name="UseCase" maxOccurs="unbounded"><xs:complexType>' +
      '<xs:sequence>' + many('Signing') + many('KeyEncryption') +
      many('ContentEncryption') + '</xs:sequence>' +
      '<xs:attribute name="id" type="xs:string" use="required"/>' +
      '<xs:attribute name="default" type="xs:string"/>' +
      '</xs:complexType></xs:element></xs:sequence></xs:complexType>' +
      '</xs:element>' +
      '<xs:element name="Links"><xs:complexType><xs:sequence>' +
      '<xs:element name="Link" maxOccurs="unbounded"><xs:complexType>' +
      '<xs:simpleContent><xs:extension base="xs:anyURI">' +
      '<xs:attribute name="rel" type="xs:string" use="required"/>' +
      '</xs:extension></xs:simpleContent></xs:complexType></xs:element>' +
      '</xs:sequence></xs:complexType></xs:element>' +
      '</xs:sequence>' +
      '<xs:attribute name="ID" type="xs:ID" use="required"/>' +
      '<xs:attribute name="specVersion" type="xs:int" use="required"/>' +
      '<xs:attribute name="issuer" type="xs:anyURI" use="required"/>' +
      '<xs:attribute name="realm" type="xs:string" use="required"/>' +
      '<xs:attribute name="generatedAt" type="xs:dateTime" use="required"/>' +
      '</xs:complexType></xs:element>' +
      '<xs:element name="CryptoMetadataLocation" type="xs:anyURI"/>' +
      '</xs:schema>';
  }

  // THE XML, SIGNED — an enveloped signature, FIRST, by the realm's current
  // `xml` signer, through the one XML signer (D9).
  signedXml(m: Json): string {
    const { log, stsCrypto, helpers } = this.deps;
    log.debug("Entering CryptoMetadataDocument.signedXml().");
    const xml = this.toXml(m);
    const how = require('../saml/document_settings').signatureOptions();
    // The key for the configured algorithm (#68): `STS.xmlSigner`.
    const signer = helpers.STS.xmlSigner;
    const id = (/ID="([^"]+)"/.exec(xml) || [])[1];
    const signed = stsCrypto.signXml(xml, {
      privateKeyPem: signer.privateKeyPem,
      privateKey: signer.privateKey,
      certPem: signer.certPem,
      sigAlg: how.sigAlg, c14nAlg: how.c14nAlg,
      placement: stsCrypto.PLACEMENT.FIRST,
      id: id
    });
    log.debug("Leaving CryptoMetadataDocument.signedXml().");
    return signed;
  }

  // THE JSON, SIGNED — a JWS by the realm's current `jose` signer, through
  // `signPublishedDocument()` (D9). `sub` is the issuer, as RFC 8414's
  // signed_metadata is.
  signedJson(m: Json): string {
    const { log, signPublishedDocument } = this.deps;
    log.debug("Entering CryptoMetadataDocument.signedJson().");
    const out = signPublishedDocument(Object.assign({}, m, { sub: m.issuer }),
                                      m.issuer, 3600, 'oauth-signed-metadata');
    log.debug("Leaving CryptoMetadataDocument.signedJson().");
    return out;
  }

  // Which of the forms a request asked for, by suffix, then `Accept`.
  formOf(req: Req, suffix: string): string {
    const { log } = this.deps;
    log.debug("Entering CryptoMetadataDocument.formOf().");
    if (suffix) {
      log.debug("Leaving CryptoMetadataDocument.formOf(). " + suffix);
      return suffix;
    }
    const accept = String((req.headers && req.headers.accept) || '');
    let form = 'json';
    if (/application\/jwt/.test(accept)) {
      form = 'jwt';
    } else if (/(application|text)\/xml/.test(accept) &&
               !/application\/json/.test(accept)) {
      form = 'xml';
    }
    log.debug("Leaving CryptoMetadataDocument.formOf(). " + form);
    return form;
  }

  answer(req: Req, res: Res, suffix: string): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering CryptoMetadataDocument.answer(). " + suffix);
    res.set('Cache-Control', 'no-store');
    if (suffix === 'xsd') {
      res.status(200).type('application/xml')
         .send(CryptoMetadataDocument.schema());
      log.debug("Leaving CryptoMetadataDocument.answer(). The schema.");
      return;
    }
    let m: Json;
    try {
      m = this.model(req);
    } catch (e) {
      log.error(errorCodes.tag('STS-PKI-0187') + 'crypto metadata: the ' +
                'document could not be built: ' + ((e && e.message) || e));
      errorCodes.mark(res, 'STS-PKI-0187');
      res.status(500).type('application/json')
         .send(JSON.stringify({ error: 'server_error' }));
      log.debug("Leaving CryptoMetadataDocument.answer(). Failed.");
      return;
    }
    const form = this.formOf(req, suffix);
    if (form === 'xml') {
      res.status(200).type('application/xml').send(this.toXml(m));
    } else if (form === 'signed.xml') {
      res.status(200).type('application/xml').send(this.signedXml(m));
    } else if (form === 'jwt') {
      res.status(200).type('application/jwt').send(this.signedJson(m));
    } else {
      res.status(200).type('application/json')
         .send(JSON.stringify(m, null, 2));
    }
    log.debug("Leaving CryptoMetadataDocument.answer(). " + form);
  }

  registerRoutes(app: { get: Function }): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering CryptoMetadataDocument.registerRoutes().");
    [['', ''], ['.json', 'json'], ['.xml', 'xml'], ['.jwt', 'jwt'],
     ['.signed.xml', 'signed.xml'], ['.xsd', 'xsd']].forEach(
      function (pair: string[]): void {
        app.get(BASE + pair[0], function (req: Req, res: Res): void {
          log.debug('Entering GET ' + BASE + pair[0] + '.');
          self.answer(req, res, pair[1]);
          log.debug('Leaving GET ' + BASE + pair[0] + '.');
        });
      });
    log.debug("Leaving CryptoMetadataDocument.registerRoutes().");
  }
}

const slot = new InstanceSlot<CryptoMetadataDocument>(
  'pki/crypto_metadata_document',
  () => new CryptoMetadataDocument(CryptoMetadataDocument.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  CryptoMetadataDocument: CryptoMetadataDocument,
  installInstance: (instance: CryptoMetadataDocument): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  BASE: BASE,
  XML_NS: XML_NS,
  model: slot.forward('model'),
  toXml: slot.forward('toXml')
};
