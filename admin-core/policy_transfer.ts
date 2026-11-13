// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin-core/policy_transfer.ts
//
// ===========================================================================
// EXPORTING AND IMPORTING A REALM'S POLICIES (#1713, rcbj 2026-11-13).
//
// rcbj: "I want to be able to import and export policies within a realm or
// between realms. The export should be JSON. It should be digitally signed.
// The import process should automatically trust dsig certificates from its
// own realm. It should present a user with a question of whether to trust
// dsig certs from other realms. The signed JSON document should contain the
// entire signer trust chain. An accepted dsig cert from a foreign realm (even
// same instance) should be added to the dsig truststore. Include the entire
// trust chain. Do full PKI paranoid mode validation on these certs. Create a
// new Issuing CA for each realm that is the policy export signing cert. Make
// it configurable what algorithm is used."
//
// ---------------------------------------------------------------------------
// WHAT IS EXPORTED. Every kind on Directory → Policies (`policy_kinds.ts`),
// and of each kind only what THIS REALM STORES: its own `default` and its
// named policies. A profile the realm inherits from the default realm, or the
// built-in defaults, is not the realm's and is not written down, so an import
// of the document never turns an inheritance into a copy. Each profile is
// carried as the BODY its kind's `save()` takes (every field, the
// description, the precedence of a named policy), and the authentication
// policy's named policies as the body of `save-named-authn-policy`. An import
// therefore goes through the same doors a console save does, with every check
// and every refusal they make: nothing is written to the directory here.
//
// ---------------------------------------------------------------------------
// THE DOCUMENT. A JWS in the flattened JSON serialization (RFC 7515 section
// 7.2.2): `{ protected, payload, signature }`, so it is JSON, any JOSE library
// verifies it, and the claims are covered by the signature whole. The
// protected header carries `x5c` — the signing certificate, its Policy Export
// Signing CA, the realm's Intermediate AND the service Root: rcbj's "the
// entire signer trust chain", so an importing realm of ANOTHER service has
// every certificate it needs to decide.
//
// THE SIGNER. A fresh key for every export, of `pki.policyExportAlgorithm`
// (RS256 by default, the realm's JOSE default), certified by the realm's
// `policy-signing` Issuing CA (`common/pki.js`) into one slot and then
// FORGOTTEN: this process keeps no copy of the private key, so nothing can
// sign a second document with it. The slot is certified again by the next
// export WITHOUT superseding the last certificate, because superseding
// revokes, and a document exported yesterday must still import tomorrow:
// `certify()` keeps the displaced serial in the register, which answers
// `good` for it until it expires (`pki.leafLifetimeDays`).
//
// ---------------------------------------------------------------------------
// THE IMPORT, AND WHO IS TRUSTED. The signature is checked with the key in
// `x5c[0]`, and the chain is then held to the validation door
// (`common/certificate_trust.ts`, purpose `policy-signer`) — FORCED to the
// full paranoid checks while `pki.paranoidPolicySigner` is on, which is the
// default, so development checks exactly what product does. Three answers:
//
//   own        the chain ends at this service's Root AND its Issuing CA is
//              this realm's own Policy Export Signing CA: trusted without a
//              question. The Root alone would not do: every realm of the
//              service shares it, so "chains to our Root" is true of every
//              realm's export, and the boundary is the Issuing CA.
//   trusted    the realm's signer truststore holds the chain's Root AND its
//              Issuing CA for `policy-signer`: an administrator said yes to
//              that realm before.
//   foreign    anything else. Nothing is written until an administrator is
//              asked and answers yes NAMING THE ISSUING CA'S FINGERPRINT they
//              were shown, so a yes cannot be replayed onto another chain.
//              The yes adds every CA certificate of the chain — Root first,
//              then downward, as admission needs — to the signer truststore,
//              for `policy-signer` and no other use case, and the next
//              import from that realm is `trusted`.
//
// **WHY THE ISSUING CA IS PINNED AND NOT ONLY THE ROOT.** A foreign realm of
// THIS service shares its Root with every other realm here, so a store entry
// for that Root alone would make every realm's export trusted after one yes.
// Requiring the Issuing CA to be held too keeps the answer about the realm the
// administrator was shown. That membership is read with `list()`, which is a
// pin decision rather than a validation: the path itself is still the door's.
//
// A LIBRARY (rule 3): no route, no listener, no timer. `admin_actions.ts`
// answers the console and `/admin-api`, and audits each act.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import stsCrypto = require('../common/crypto');
import pki = require('../common/pki');
import errorCodes = require('../common/error_codes');
import CertificateTrust = require('../common/certificate_trust');
import signerTruststore = require('../common/signer_truststore');
import InstanceSlot = require('../common/instance_slot');
import PolicyKinds = require('./policy_kinds');

type Json = any;

// The document's own names: what an importer checks before anything else.
const FORMAT = 'iya-sts.policy-export';
const VERSION = 1;
const TYP = 'policy-export+json';
// The Issuing CA and the paranoid row.
const USE_CASE = 'policy-signing';
const PURPOSE = 'policy-signer';
const SLOT = 'policy-export';
// The algorithms an export may be signed with, and how each key is made: the
// rows of `pki.policyExportAlgorithm`. RSA through node's generator at 3072
// bits; the curves and ML-DSA through `helpers.makeFederationKey()`, the
// recipe a signing unit's next key is made by.
const ALGORITHMS: Readonly<Record<string, { keyAlg: string;
                                            maker: string }>> =
  Object.freeze({
    RS256: { keyAlg: 'rsa-3072', maker: 'rsa' },
    PS256: { keyAlg: 'rsa-3072', maker: 'rsa' },
    ES256: { keyAlg: 'ec-p256', maker: 'unit' },
    ES384: { keyAlg: 'ec-p384', maker: 'unit' },
    ES512: { keyAlg: 'ec-p521', maker: 'unit' },
    EdDSA: { keyAlg: 'ed25519', maker: 'unit' },
    'ML-DSA-44': { keyAlg: 'ml-dsa-44', maker: 'unit' },
    'ML-DSA-65': { keyAlg: 'ml-dsa-65', maker: 'unit' },
    'ML-DSA-87': { keyAlg: 'ml-dsa-87', maker: 'unit' }
  });
// A document is a few policies; anything larger is not one.
const MAX_DOCUMENT_BYTES = 2 * 1024 * 1024;
const MAX_CHAIN = 6;

interface PolicyTransferDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  crypto: typeof stsCrypto;
  pki: typeof pki;
  errorCodes: typeof errorCodes;
  trust: typeof CertificateTrust;
  signers: typeof signerTruststore;
  kinds: typeof PolicyKinds;
  makeKey: (alg: string) => Promise<Json>;
  now: () => number;
}

/**
 * Exports a realm's policies as a signed JSON document, and imports one:
 * the signer verified, its chain held to the validation door, and another
 * realm's chain trusted only once an administrator says so.
 *
 * A library: no route. `admin_actions.ts` answers the console and the API.
 */
class PolicyTransfer {
  static readonly FORMAT = FORMAT;
  static readonly VERSION = VERSION;
  static readonly TYP = TYP;
  static readonly USE_CASE = USE_CASE;
  static readonly PURPOSE = PURPOSE;
  static readonly ALGORITHMS = ALGORITHMS;

  /**
   * Creates the module.
   *
   * @param deps - its dependencies
   */
  constructor(private readonly deps: PolicyTransferDeps) {
    deps.log.debug("Entering PolicyTransfer.constructor().");
    deps.log.debug("Leaving PolicyTransfer.constructor().");
  }

  /**
   * The module's own dependencies.
   *
   * @returns the deps a default instance is built from
   */
  static defaultDeps(): PolicyTransferDeps {
    helpers.log.debug("Entering PolicyTransfer.defaultDeps().");
    helpers.log.debug("Leaving PolicyTransfer.defaultDeps().");
    return {
      log: helpers.log, config: config, realms: realms, crypto: stsCrypto,
      pki: pki, errorCodes: errorCodes, trust: CertificateTrust,
      signers: signerTruststore, kinds: PolicyKinds,
      makeKey: PolicyTransfer.makeKey,
      now: function (): number {
        return Date.now();
      }
    };
  }

  /**
   * Makes a signing key for one algorithm: the private key to sign with and
   * the SubjectPublicKeyInfo PEM to certify.
   *
   * @param alg - one of `ALGORITHMS`
   * @returns a promise of `{ alg, keyAlg, privateKey, publicKeyPem }`
   */
  static async makeKey(alg: string): Promise<Json> {
    helpers.log.debug("Entering PolicyTransfer.makeKey(). " + alg);
    const row = ALGORITHMS[alg];
    if (!row) {
      helpers.log.debug("Leaving PolicyTransfer.makeKey(). Unknown.");
      throw new Error('"' + alg + '" is not an algorithm a policy export ' +
                      'is signed with; they are ' +
                      Object.keys(ALGORITHMS).join(', ') + '.');
    }
    if (row.maker === 'rsa') {
      const pair = await stsCrypto.generateKeyPairAsync('rsa',
        { modulusLength: 3072, publicExponent: 0x10001 });
      helpers.log.debug("Leaving PolicyTransfer.makeKey(). RSA.");
      return { alg: alg, keyAlg: row.keyAlg, privateKey: pair.privateKey,
               publicKeyPem: String(pair.publicKey.export(
                 { type: 'spki', format: 'pem' })) };
    }
    const made = await helpers.makeFederationKey(alg);
    const publicKeyPem = /^ML-DSA-/.test(alg)
      ? pki.pqSubjectPublicKeyPem(alg, made.publicJwk)
      : String(stsCrypto.publicKeyFromJwk(made.publicJwk)
        .export({ type: 'spki', format: 'pem' }));
    helpers.log.debug("Leaving PolicyTransfer.makeKey().");
    return { alg: alg, keyAlg: row.keyAlg, privateKey: made.privateKey,
             publicKeyPem: publicKeyPem };
  }

  // A refusal, marked with its code: `{ ok: false, errors }` and anything the
  // caller wants beside it.
  private refuse(code: string, why: string, extra?: Json): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PolicyTransfer.refuse(). " + code);
    log.debug("Leaving PolicyTransfer.refuse().");
    return errorCodes.mark(Object.assign({ ok: false, errors: [why] },
                                         extra || {}), code);
  }

  // A base64 DER certificate, as PEM.
  private pemOf(b64: string): string {
    this.deps.log.debug("Entering PolicyTransfer.pemOf().");
    const body = String(b64).replace(/\s+/g, '').match(/.{1,64}/g) || [];
    this.deps.log.debug("Leaving PolicyTransfer.pemOf().");
    return '-----BEGIN CERTIFICATE-----\n' + body.join('\n') +
           '\n-----END CERTIFICATE-----\n';
  }

  // Upper hex with no colons, the signer truststore's spelling.
  private fingerprintOf(pem: string): string {
    this.deps.log.debug("Entering PolicyTransfer.fingerprintOf().");
    const out = String(this.deps.crypto.parseCertificate(pem).fingerprint256)
      .replace(/:/g, '').toUpperCase();
    this.deps.log.debug("Leaving PolicyTransfer.fingerprintOf().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // EXPORT.
  // ---------------------------------------------------------------------------

  // What one kind's stored profiles are, as the bodies its doors take.
  private kindExport(kind: Json): Json {
    const { log } = this.deps;
    log.debug("Entering PolicyTransfer.kindExport(). " + kind.id);
    const module = kind.module;
    const selectorKeys = (module.SELECTORS || []).map(function (one: Json) {
      return one.key;
    });
    const profiles = module.list().filter(function (profile: Json) {
      return profile && profile.stored === true;
    }).map(function (profile: Json) {
      const body: Json = {};
      module.FIELDS.forEach(function (field: Json) {
        if (profile[field.key] !== undefined) {
          body[field.key] = profile[field.key];
        }
      });
      selectorKeys.forEach(function (key: string) {
        if (profile[key] !== undefined) {
          body[key] = profile[key];
        }
      });
      if (profile.description) {
        body.description = String(profile.description);
      }
      if (String(profile.name) !== module.DEFAULT_PROFILE &&
          profile.precedence !== undefined) {
        body.precedence = profile.precedence;
      }
      return { name: String(profile.name), body: body };
    });
    const out: Json = { id: kind.id, profiles: profiles };
    // THE AUTHENTICATION POLICY'S NAMED POLICIES (#1148) have an act of their
    // own rather than a profile in `list()`: carried as that act's body.
    if (typeof module.named === 'function') {
      out.named = module.named().map(function (one: Json) {
        return { name: one.name,
                 body: { name: one.name, description: one.description,
                         precedence: one.precedence,
                         mechanisms: one.mechanisms.slice(),
                         secondFactors: one.secondFactors.slice() } };
      });
    }
    log.debug("Leaving PolicyTransfer.kindExport(). " + profiles.length +
              " profile(s).");
    return out;
  }

  /**
   * Exports the ambient realm's stored policies, signed by a fresh key under
   * the realm's Policy Export Signing CA.
   *
   * @param options - `{ actor }`, who asked
   * @returns a promise of `{ ok, document, filename, signer, counts }` or a
   *   refusal
   */
  async exportPolicies(options?: Json): Promise<Json> {
    const { log, config, realms, crypto, pki, kinds } = this.deps;
    log.debug("Entering PolicyTransfer.exportPolicies().");
    const opts = options || {};
    const realmId = realms.currentId();
    const alg = String(config.value('pki.policyExportAlgorithm') || 'RS256');
    if (!ALGORITHMS[alg]) {
      log.debug("Leaving PolicyTransfer.exportPolicies(). Algorithm.");
      return this.refuse('STS-ADMIN-0925', '"' + alg + '" is not an ' +
        'algorithm a policy export is signed with; they are ' +
        Object.keys(ALGORITHMS).join(', ') + '.');
    }
    const branch = await pki.ensureScope(realmId);
    const root = pki.serviceRoot();
    if (!branch.ok || !root) {
      log.debug("Leaving PolicyTransfer.exportPolicies(). No branch.");
      return this.refuse('STS-ADMIN-0925', 'This realm has no certificate ' +
        'authority to sign an export under: ' +
        ((branch.errors || []).join(' ') || 'there is no service Root') +
        '. Build one on /admin/pki first.');
    }
    let key: Json = null;
    try {
      key = await this.deps.makeKey(alg);
    } catch (e) {
      log.debug("Caught in PolicyTransfer.exportPolicies(): " +
                ((e && e.message) || e));
      log.debug("Leaving PolicyTransfer.exportPolicies(). No key.");
      return this.refuse('STS-ADMIN-0925', 'A ' + alg + ' signing key ' +
        'could not be made: ' + ((e && e.message) || e));
    }
    const label = realmId || 'default';
    const made = await pki.certify(realmId, USE_CASE, {
      slot: SLOT,
      alg: alg,
      keyAlg: key.keyAlg,
      label: 'Policy export signer',
      commonName: 'Policy Export Signer (' + label + ')',
      publicKeyPem: key.publicKeyPem,
      keyUsage: ['digitalSignature', 'nonRepudiation']
    });
    if (!made.ok) {
      log.debug("Leaving PolicyTransfer.exportPolicies(). Not certified.");
      return this.refuse('STS-ADMIN-0925', 'The export signer could not be ' +
        'certified: ' + (made.errors || []).join(' '));
    }
    const chain = [made.record.certificatePem]
      .concat(made.record.chainPem || [], [root.certificatePem]);
    const x5c = chain.map(function (pem: string) {
      return crypto.stripPem(pem);
    });
    const exportedAt = new Date(this.deps.now()).toISOString();
    const payload: Json = {
      format: FORMAT, version: VERSION,
      jti: crypto.randomUuid(),
      realm: label,
      realmDomain: realms.domainOf(realmId),
      exportedAt: exportedAt,
      exportedBy: String(opts.actor || ''),
      kinds: kinds.list().map((kind: Json) => {
        return this.kindExport(kind);
      })
    };
    // certificate-header: none — this document names its signer's chain
    // itself, always and whole, because an importing realm has no other way
    // to reach it: its x5c is built above from the certificate just issued.
    const compact = await crypto.signJwsAsync(payload, key.privateKey,
      { algorithm: alg, header: { typ: TYP, x5c: x5c } });
    key = null;
    const parts = String(compact).split('.');
    const document = { protected: parts[0], payload: parts[1],
                       signature: parts[2] };
    const counts: Json = {};
    payload.kinds.forEach(function (kind: Json) {
      counts[kind.id] = kind.profiles.length +
        (kind.named ? kind.named.length : 0);
    });
    log.info('policy transfer: the "' + label + '" realm\'s policies were ' +
             'exported, signed ' + alg + ' by ' + made.record.subject +
             ' (serial ' + made.record.serialHex + ').');
    log.debug("Leaving PolicyTransfer.exportPolicies().");
    const filename = 'policies-' + label + '-' +
                     exportedAt.replace(/[:.]/g, '-') + '.json';
    return {
      ok: true, document: document, filename: filename,
      // THE SAME DOCUMENT AS A FILE (`web_runtime.ts` saves an answer's
      // `files`), so the console's Export button is a download.
      files: [{ name: filename, mime: 'application/json',
                base64: Buffer.from(JSON.stringify(document, null, 2) + '\n',
                                    'utf8').toString('base64') }],
      signer: { subject: made.record.subject, alg: alg,
                serialHex: made.record.serialHex,
                notAfter: made.record.notAfter },
      counts: counts
    };
  }

  // ---------------------------------------------------------------------------
  // READING AND VERIFYING A DOCUMENT.
  // ---------------------------------------------------------------------------

  // The document, from a string or an object: `{ document, compact }`, or a
  // refusal.
  private readDocument(input: unknown): Json {
    const { log } = this.deps;
    log.debug("Entering PolicyTransfer.readDocument().");
    let doc: Json = input;
    if (typeof input === 'string') {
      if (Buffer.byteLength(input, 'utf8') > MAX_DOCUMENT_BYTES) {
        log.debug("Leaving PolicyTransfer.readDocument(). Too large.");
        return this.refuse('STS-ADMIN-0926', 'That is larger than a policy ' +
          'export can be (' + MAX_DOCUMENT_BYTES + ' bytes).');
      }
      try {
        doc = JSON.parse(input);
      } catch (e) {
        log.debug("Caught in PolicyTransfer.readDocument(): " +
                  ((e && e.message) || e));
        log.debug("Leaving PolicyTransfer.readDocument(). Not JSON.");
        return this.refuse('STS-ADMIN-0926', 'That is not JSON, so it is ' +
          'not a policy export.');
      }
    }
    const part = /^[A-Za-z0-9_-]+$/;
    if (!doc || typeof doc !== 'object' ||
        typeof doc.protected !== 'string' || !part.test(doc.protected) ||
        typeof doc.payload !== 'string' || !part.test(doc.payload) ||
        typeof doc.signature !== 'string' || !part.test(doc.signature)) {
      log.debug("Leaving PolicyTransfer.readDocument(). Not a JWS.");
      return this.refuse('STS-ADMIN-0926', 'That is not a policy export: ' +
        'one is a JWS in the flattened JSON serialization, with protected, ' +
        'payload and signature members.');
    }
    log.debug("Leaving PolicyTransfer.readDocument().");
    return { document: doc,
             compact: doc.protected + '.' + doc.payload + '.' +
                      doc.signature };
  }

  // The protected header, read before the signature is: it names the key.
  private headerOf(protectedPart: string): Json {
    const { log } = this.deps;
    log.debug("Entering PolicyTransfer.headerOf().");
    let header: Json = null;
    try {
      header = JSON.parse(Buffer.from(protectedPart, 'base64url')
        .toString('utf8'));
    } catch (e) {
      log.debug("Caught in PolicyTransfer.headerOf(): " +
                ((e && e.message) || e));
      header = null;
    }
    if (!header || typeof header !== 'object' || header.typ !== TYP ||
        !ALGORITHMS[String(header.alg)] || !Array.isArray(header.x5c) ||
        header.x5c.length < 2 || header.x5c.length > MAX_CHAIN ||
        !header.x5c.every(function (one: unknown) {
          return typeof one === 'string' && /^[A-Za-z0-9+/=]+$/.test(one);
        })) {
      log.debug("Leaving PolicyTransfer.headerOf(). Not ours.");
      return this.refuse('STS-ADMIN-0926', 'The document\'s protected ' +
        'header is not a policy export\'s: it names typ "' + TYP + '", an ' +
        'algorithm one is signed with (' + Object.keys(ALGORITHMS)
        .join(', ') + ') and the signer\'s whole chain in x5c.');
    }
    log.debug("Leaving PolicyTransfer.headerOf().");
    return { ok: true, header: header };
  }

  // Each certificate of the chain, described for the question an
  // administrator is asked.
  private describeChain(pems: string[]): Json[] {
    const { log, crypto } = this.deps;
    log.debug("Entering PolicyTransfer.describeChain().");
    const out = pems.map((pem: string) => {
      const facts = crypto.certificateFacts(pem);
      return { subject: facts.subject, issuer: facts.issuer,
               notBefore: facts.notBefore, notAfter: facts.notAfter,
               fingerprint256: this.fingerprintOf(pem) };
    });
    log.debug("Leaving PolicyTransfer.describeChain().");
    return out;
  }

  // Is this chain's Issuing CA this realm's own Policy Export Signing CA, and
  // its Root this service's Root?
  private ownRealm(pems: string[]): boolean {
    const { log, pki, realms } = this.deps;
    log.debug("Entering PolicyTransfer.ownRealm().");
    const issuer = pki.describeIssuer(realms.currentId(), USE_CASE);
    const root = pki.serviceRoot();
    const out = !!issuer && !!root &&
      this.fingerprintOf(issuer.certificatePem) ===
        this.fingerprintOf(pems[1]) &&
      this.fingerprintOf(root.certificatePem) ===
        this.fingerprintOf(pems[pems.length - 1]);
    log.debug("Leaving PolicyTransfer.ownRealm(). " + out);
    return out;
  }

  // Does this realm's signer truststore hold the chain's Root and its Issuing
  // CA for `policy-signer`? A pin decision, read with `list()`; the path is
  // the door's (see the header).
  private trustedForeign(pems: string[]): boolean {
    const { log, signers } = this.deps;
    log.debug("Entering PolicyTransfer.trustedForeign().");
    const held = signers.list().filter(function (row: Json) {
      return !row.purposes || !row.purposes.length ||
             row.purposes.indexOf(PURPOSE) !== -1;
    }).map(function (row: Json) {
      return String(row.fingerprint256);
    });
    const out = held.indexOf(this.fingerprintOf(pems[1])) !== -1 &&
      held.indexOf(this.fingerprintOf(pems[pems.length - 1])) !== -1;
    log.debug("Leaving PolicyTransfer.trustedForeign(). " + out);
    return out;
  }

  /**
   * Holds a signer's chain to the validation door, purpose `policy-signer`,
   * forced to the full checks while `pki.paranoidPolicySigner` is on.
   *
   * @param pems - the chain, leaf first, the Root last
   * @param sources - the anchor sources this question may reach
   * @returns a promise of the door's verdict
   */
  async verifySigner(pems: string[], sources: string[]): Promise<Json> {
    const { log, trust, realms } = this.deps;
    log.debug("Entering PolicyTransfer.verifySigner(). " + sources.join(','));
    const realmId = realms.currentId();
    const verdict = await trust.assess(PURPOSE,
      { leaf: pems[0], chain: pems.slice(1, -1) },
      { realmId: realmId, anchors: [pems[pems.length - 1]],
        anchorSources: sources, force: trust.rowOn(PURPOSE, realmId) });
    log.debug("Leaving PolicyTransfer.verifySigner(). " + verdict.ok);
    return verdict;
  }

  // The policy kinds a document names, checked against this service's.
  private claimsOf(payload: Json): Json {
    const { log, kinds } = this.deps;
    log.debug("Entering PolicyTransfer.claimsOf().");
    if (!payload || payload.format !== FORMAT ||
        payload.version !== VERSION || !Array.isArray(payload.kinds)) {
      log.debug("Leaving PolicyTransfer.claimsOf(). Not a format we read.");
      return this.refuse('STS-ADMIN-0926', 'The signed content is not a ' +
        'policy export of version ' + VERSION + ' (format "' + FORMAT +
        '").');
    }
    const unknown = payload.kinds.filter(function (one: Json) {
      return !one || !kinds.byId(String(one.id)) ||
             !Array.isArray(one.profiles);
    }).map(function (one: Json) {
      return String(one && one.id);
    });
    if (unknown.length) {
      log.debug("Leaving PolicyTransfer.claimsOf(). Unknown kinds.");
      return this.refuse('STS-ADMIN-0933', 'The export names a kind of ' +
        'policy this service does not have, or carries one unreadably: ' +
        unknown.join(', ') + '. Nothing was imported.');
    }
    log.debug("Leaving PolicyTransfer.claimsOf().");
    return { ok: true };
  }

  /**
   * Reads a document, verifies its signature and holds its signer to the
   * validation door, without writing anything: what the console shows before
   * it asks, and the first half of an import.
   *
   * @param input - the document, JSON text or the parsed object
   * @returns a promise of `{ ok, origin, trusted, signer, chain, realm,
   *   exportedAt, exportedBy, kinds, issuerFingerprint }` — `origin` is
   *   `own`, `trusted` or `foreign`, and only `foreign` needs a question —
   *   or a refusal
   */
  async inspect(input: unknown): Promise<Json> {
    const { log, crypto } = this.deps;
    log.debug("Entering PolicyTransfer.inspect().");
    const read = this.readDocument(input);
    if (read.ok === false) {
      log.debug("Leaving PolicyTransfer.inspect(). Unreadable.");
      return read;
    }
    const head = this.headerOf(read.document.protected);
    if (!head.ok) {
      log.debug("Leaving PolicyTransfer.inspect(). Header.");
      return head;
    }
    const pems = head.header.x5c.map((one: string) => {
      return this.pemOf(one);
    });
    let chain: Json[] = [];
    try {
      chain = this.describeChain(pems);
    } catch (e) {
      log.debug("Caught in PolicyTransfer.inspect(): " +
                ((e && e.message) || e));
      log.debug("Leaving PolicyTransfer.inspect(). Unreadable chain.");
      return this.refuse('STS-ADMIN-0927', 'A certificate in the ' +
        'document\'s x5c is not an X.509 certificate.');
    }
    let verified: Json = null;
    try {
      verified = crypto.verifyCompactJwsWithCertificate(read.compact, pems[0],
        { algorithms: [String(head.header.alg)] });
    } catch (e) {
      log.debug("Caught in PolicyTransfer.inspect(): " +
                ((e && e.message) || e));
      log.debug("Leaving PolicyTransfer.inspect(). Signature.");
      return this.refuse('STS-ADMIN-0927', 'The document\'s signature does ' +
        'not verify with the key in its x5c: it was altered after it was ' +
        'signed, or it was never signed by that certificate.');
    }
    const claims = verified.claims || verified.payload || {};
    const known = this.claimsOf(claims);
    if (!known.ok) {
      log.debug("Leaving PolicyTransfer.inspect(). Claims.");
      return known;
    }
    const own = this.ownRealm(pems);
    const held = !own && this.trustedForeign(pems);
    const sources = own ? ['caller'] : (held ? ['signer-truststore'] :
                                                ['caller']);
    const verdict = await this.verifySigner(pems, sources);
    const kindsSummary = claims.kinds.map(function (kind: Json) {
      return { id: kind.id,
               profiles: kind.profiles.map(function (one: Json) {
                 return String(one.name);
               }),
               named: (kind.named || []).map(function (one: Json) {
                 return String(one.name);
               }) };
    });
    const answer: Json = {
      ok: verdict.ok,
      origin: own ? 'own' : (held ? 'trusted' : 'foreign'),
      trusted: verdict.ok && (own || held),
      alg: String(head.header.alg),
      signer: chain[0], chain: chain,
      issuerFingerprint: chain[1].fingerprint256,
      realm: String(claims.realm || ''),
      realmDomain: String(claims.realmDomain || ''),
      exportedAt: String(claims.exportedAt || ''),
      exportedBy: String(claims.exportedBy || ''),
      kinds: kindsSummary,
      verdict: { ok: verdict.ok, code: verdict.code || '',
                 why: verdict.why || '', inForce: !!verdict.inForce,
                 checks: verdict.checks || {} }
    };
    if (!verdict.ok) {
      log.debug("Leaving PolicyTransfer.inspect(). The door refused.");
      return this.refuse('STS-ADMIN-0928', 'The signer\'s certificate chain ' +
        'was refused: ' + (verdict.why || verdict.code || 'it did not ' +
        'pass validation') + '. Nothing was imported.',
        Object.assign(answer, { ok: false }));
    }
    log.debug("Leaving PolicyTransfer.inspect(). " + answer.origin);
    return Object.assign(answer, { payload: claims, pems: pems });
  }

  // ---------------------------------------------------------------------------
  // IMPORT.
  // ---------------------------------------------------------------------------

  // Adds the chain's CA certificates to the signer truststore, Root first and
  // then downward, for `policy-signer` alone.
  private async trustChain(pems: string[], actor: string): Promise<Json> {
    const { log, signers, realms } = this.deps;
    log.debug("Entering PolicyTransfer.trustChain().");
    const cas = pems.slice(1).reverse();
    const added = await signers.add(realms.currentId(), cas.join('\n'),
      { purposes: [PURPOSE], addedBy: actor });
    log.debug("Leaving PolicyTransfer.trustChain(). " +
              (added.added || []).length + " added.");
    return added;
  }

  // Writes one kind's profiles through its own doors, `default` first.
  private async importKind(kind: Json, carried: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering PolicyTransfer.importKind(). " + kind.id);
    const module = kind.module;
    const imported: string[] = [];
    const refused: Json[] = [];
    const profiles = carried.profiles.slice().sort(function (a: Json,
                                                            b: Json) {
      const da = String(a.name) === module.DEFAULT_PROFILE ? 0 : 1;
      const db = String(b.name) === module.DEFAULT_PROFILE ? 0 : 1;
      return da - db;
    });
    for (const one of profiles) {
      const name = String(one && one.name);
      const body = Object.assign({}, (one && one.body) || {});
      const result = await Promise.resolve(module.save(name, body));
      if (result && result.ok) {
        imported.push(name);
      } else {
        refused.push({ kind: kind.id, name: name,
                       code: this.deps.errorCodes.codeOf(result) || '',
                       errors: (result && result.errors) || [] });
      }
    }
    for (const one of carried.named || []) {
      const name = String(one && one.name);
      const body = Object.assign({}, (one && one.body) || {}, { name: name });
      const result = typeof module.saveNamed === 'function'
        ? await Promise.resolve(module.saveNamed(name, body))
        : { ok: false, errors: ['this kind has no named policies of that ' +
                                'shape'] };
      if (result && result.ok) {
        imported.push(name);
      } else {
        refused.push({ kind: kind.id, name: name,
                       code: this.deps.errorCodes.codeOf(result) || '',
                       errors: (result && result.errors) || [] });
      }
    }
    log.debug("Leaving PolicyTransfer.importKind(). " + imported.length +
              " imported, " + refused.length + " refused.");
    return { imported: imported, refused: refused };
  }

  /**
   * Imports a document into the ambient realm. An own realm's signer, or one
   * the signer truststore already holds, is trusted at once; another realm's
   * is trusted only when `trustSigner` is true AND `issuerFingerprint` names
   * the Issuing CA `inspect()` showed, and then its chain is added to the
   * signer truststore for `policy-signer`. Each profile is written through
   * its kind's own save, so a profile a kind refuses is reported by name and
   * the others still go in.
   *
   * @param input - the document
   * @param options - `{ trustSigner, issuerFingerprint, actor }`
   * @returns a promise of `{ ok, origin, imported, refused, trustAdded }`,
   *   or a refusal; `needsTrust` on the refusal of an unanswered question
   */
  async importPolicies(input: unknown, options?: Json): Promise<Json> {
    const { log, kinds } = this.deps;
    log.debug("Entering PolicyTransfer.importPolicies().");
    const opts = options || {};
    const seen = await this.inspect(input);
    if (!seen.ok) {
      log.debug("Leaving PolicyTransfer.importPolicies(). Inspect refused.");
      return seen;
    }
    const chainPems: string[] = seen.pems;
    let trustAdded: Json[] = [];
    if (seen.origin === 'foreign') {
      const wanted = String(opts.issuerFingerprint || '')
        .replace(/[^0-9a-fA-F]/g, '').toUpperCase();
      const yes = opts.trustSigner === true || opts.trustSigner === 'true';
      if (!yes) {
        log.debug("Leaving PolicyTransfer.importPolicies(). Not asked.");
        return this.refuse('STS-ADMIN-0929', 'This export was signed by ' +
          'another realm ("' + seen.realm + '", ' + seen.signer.subject +
          '). Nothing was imported: confirm that its chain is to be ' +
          'trusted for policy imports in this realm, and it is added to ' +
          'the signer truststore.',
          { needsTrust: true, inspection: this.publicView(seen) });
      }
      if (wanted !== seen.issuerFingerprint) {
        log.debug("Leaving PolicyTransfer.importPolicies(). Another chain.");
        return this.refuse('STS-ADMIN-0930', 'The confirmation names ' +
          'another Issuing CA than this export\'s (' +
          seen.issuerFingerprint + '), so it is not an answer about this ' +
          'chain. Nothing was imported.',
          { needsTrust: true, inspection: this.publicView(seen) });
      }
      const added = await this.trustChain(chainPems, String(opts.actor || ''));
      if ((added.refused || []).length) {
        log.debug("Leaving PolicyTransfer.importPolicies(). Store refused.");
        return this.refuse('STS-ADMIN-0931', 'The signer\'s chain could not ' +
          'be added to the signer truststore: ' + added.refused
          .map(function (one: Json) {
            return (one.subject ? one.subject + ': ' : '') + one.why;
          }).join('; ') + '. Nothing was imported.',
          { trustAdded: added.added || [] });
      }
      trustAdded = added.added || [];
      const again = await this.inspect(input);
      if (!again.ok || again.origin !== 'trusted') {
        log.debug("Leaving PolicyTransfer.importPolicies(). Not trusted.");
        return this.refuse('STS-ADMIN-0928', 'The signer\'s chain was ' +
          'added to the signer truststore and still did not validate ' +
          'through it: ' + ((again.errors || []).join(' ') || again.origin) +
          '. Nothing was imported.', { trustAdded: trustAdded });
      }
    }
    const imported: Json[] = [];
    const refused: Json[] = [];
    for (const carried of seen.payload.kinds) {
      const kind = kinds.byId(String(carried.id));
      const done = await this.importKind(kind, carried);
      if (done.imported.length) {
        imported.push({ kind: kind.id, names: done.imported });
      }
      done.refused.forEach(function (one: Json) {
        refused.push(one);
      });
    }
    const written = imported.reduce(function (n: number, one: Json) {
      return n + one.names.length;
    }, 0);
    const answer = { ok: refused.length === 0, origin: seen.origin,
                     message: written + ' profile(s) imported from the "' +
                              seen.realm + '" realm\'s export' +
                              (refused.length ? ', ' + refused.length +
                               ' refused.' : '.'),
                     realm: seen.realm, signer: seen.signer,
                     imported: imported, refused: refused,
                     trustAdded: trustAdded };
    log.info('policy transfer: an export of "' + seen.realm + '" (' +
             seen.origin + ') was imported into "' +
             (this.deps.realms.currentId() || 'default') + '": ' +
             written + ' profile(s) written, ' + refused.length +
             ' refused.');
    if (refused.length) {
      log.debug("Leaving PolicyTransfer.importPolicies(). Partly refused.");
      return this.deps.errorCodes.mark(Object.assign(answer, {
        errors: refused.map(function (one: Json) {
          return one.kind + ' "' + one.name + '": ' + one.errors.join(' ');
        }) }), 'STS-ADMIN-0932');
    }
    log.debug("Leaving PolicyTransfer.importPolicies().");
    return answer;
  }

  // ---------------------------------------------------------------------------
  // THE VIEW (`GET /admin-api/policies/transfer`, the Export and import
  // tab): what an export from this realm is signed under and who this realm
  // has trusted, READ and never made. A realm whose branch has no Policy
  // Export Signing CA yet answers `issuingCa: null`: the first export builds
  // it (`pki.ensureScope()`), and a read does not mint a CA. The Issuing
  // CA's SHA-256 fingerprint is what another realm's import names in
  // `issuerFingerprint`, so it is published in that spelling and as RFC
  // 7515's `x5t#S256`. Certificates only: neither `describeIssuer()` nor the
  // signer truststore's `list()` reaches a private key.
  // ---------------------------------------------------------------------------

  // An instant as ISO 8601, or '' where nothing states one.
  private isoOf(value: unknown): string {
    this.deps.log.debug("Entering PolicyTransfer.isoOf().");
    const ms = typeof value === 'number' ? value : Date.parse(String(value));
    const out = value === null || value === undefined || value === '' ||
      !isFinite(ms) ? '' : new Date(ms).toISOString();
    this.deps.log.debug("Leaving PolicyTransfer.isoOf().");
    return out;
  }

  /**
   * This realm's policy-transfer view: the export algorithm in force, its
   * Policy Export Signing Issuing CA (null before the first export), the
   * paranoid row, and the signer truststore's entries that serve
   * `policy-signer`.
   *
   * @returns the view, which carries no private key
   */
  view(): Json {
    const { log, config, realms, crypto, pki, trust, signers } = this.deps;
    log.debug("Entering PolicyTransfer.view().");
    const realmId = realms.currentId();
    const alg = String(config.value('pki.policyExportAlgorithm') || 'RS256');
    const issuer: Json = pki.describeIssuer(realmId, USE_CASE);
    let issuingCa: Json = null;
    if (issuer) {
      const facts = crypto.certificateFacts(issuer.certificatePem);
      const root = issuer.root || {};
      issuingCa = {
        subject: String(facts.subject || ''),
        issuer: String(facts.issuer || ''),
        serialHex: String(facts.serialHex || ''),
        notBefore: this.isoOf(facts.notBefore),
        notAfter: this.isoOf(facts.notAfter),
        keyAlg: String(issuer.keyAlg || ''),
        signatureAlg: String(issuer.signatureAlg || ''),
        fingerprint256: this.fingerprintOf(issuer.certificatePem),
        'x5t#S256': crypto.certificateThumbprint(issuer.certificatePem),
        certificatePem: String(issuer.certificatePem),
        // From the Issuing CA upward, the Root excluded: the Root is every
        // realm's, and is named apart as `root`.
        chainPem: (issuer.chainPem || []).map(String),
        root: { subject: String(root.subject || ''),
                fingerprint256: root.certificatePem
                  ? this.fingerprintOf(root.certificatePem) : '' }
      };
    }
    const trusted = signers.list(realmId).filter(function (row: Json) {
      return !row.purposes || !row.purposes.length ||
             row.purposes.indexOf(PURPOSE) !== -1;
    }).map((row: Json) => {
      const one: Json = {
        subject: String(row.subject || ''),
        issuer: String(row.issuer || ''),
        kind: String(row.kind || ''),
        purposes: (row.purposes || []).map(String),
        fingerprint256: String(row.fingerprint256 || ''),
        notBefore: this.isoOf(row.notBefore || null),
        notAfter: this.isoOf(row.notAfter || null),
        source: String(row.source || ''),
        addedBy: String(row.addedBy || ''),
        addedAt: String(row.addedAt || '')
      };
      if (row.unadmittable) {
        one.unadmittable = String(row.unadmittable);
      }
      return one;
    });
    const out = {
      realm: realmId || 'default',
      algorithm: alg,
      algorithms: Object.keys(ALGORITHMS),
      paranoidPolicySigner: trust.rowOn(PURPOSE, realmId),
      issuingCa: issuingCa,
      trustedSigners: trusted
    };
    log.debug("Leaving PolicyTransfer.view(). " +
              (issuingCa ? 'An Issuing CA' : 'No Issuing CA') + ', ' +
              trusted.length + ' trusted.');
    return out;
  }

  /**
   * What `inspect()` answers, without the signed content and the PEMs: what
   * a page or an API caller is shown.
   *
   * @param seen - `inspect()`'s answer
   * @returns the answer less `payload` and `pems`
   */
  publicView(seen: Json): Json {
    this.deps.log.debug("Entering PolicyTransfer.publicView().");
    const out = Object.assign({}, seen);
    delete out.payload;
    delete out.pems;
    this.deps.log.debug("Leaving PolicyTransfer.publicView().");
    return out;
  }
}

const slot = new InstanceSlot<PolicyTransfer>(
  'admin-core/policy_transfer',
  () => new PolicyTransfer(PolicyTransfer.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Policy export and import: a signed JSON document, its signer verified and
 * held to the validation door, another realm's chain trusted on an
 * administrator's yes.
 *
 * @namespace
 */
export = {
  PolicyTransfer: PolicyTransfer,
  FORMAT: FORMAT,
  VERSION: VERSION,
  TYP: TYP,
  USE_CASE: USE_CASE,
  PURPOSE: PURPOSE,
  ALGORITHMS: ALGORITHMS,
  installInstance: (instance: PolicyTransfer): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  exportPolicies: slot.forward('exportPolicies'),
  inspect: slot.forward('inspect'),
  importPolicies: slot.forward('importPolicies'),
  verifySigner: slot.forward('verifySigner'),
  publicView: slot.forward('publicView'),
  view: slot.forward('view')
};
