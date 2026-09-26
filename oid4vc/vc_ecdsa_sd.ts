'use strict';
//
// File: vc_ecdsa_sd.ts
//
// ---------------------------------------------------------------------------
// ecdsa-sd-2023: THE SELECTIVE DISCLOSURE ECDSA CRYPTOSUITE (#196,
// 2026-09-26) — W3C Data Integrity ECDSA Cryptosuites v1.0, sections 3.4
// (the selective disclosure functions), 3.5 (the ecdsa-sd-2023 functions)
// and 3.6 (the cryptosuite): the issuer's BASE proof, the holder's DERIVED
// proof, and the verifier's check of a derived proof.
//
// How it works, in one paragraph, because every function below is a step of
// it. The issuer canonicalizes the credential with RDFC-1.0 and relabels
// every blank node with an HMAC of its canonical label, under a key only the
// base proof carries — so a label says nothing about the statements a holder
// withholds. The statements JSON pointers name as MANDATORY are hashed
// together; every other statement is signed on its own with a key made for
// this one proof and then thrown away; and the issuer's own key signs the
// proof configuration's hash, that proof-scoped public key and the
// mandatory hash. A holder reveals the mandatory statements and any subset
// of the rest, carrying only the revealed statements' signatures and the
// HMAC labels of the blank nodes they mention; a verifier canonicalizes what
// it was shown, maps its labels back through that label map, and checks the
// issuer's signature over the mandatory statements and the proof-scoped
// key's signature over every other one.
//
// **P-256 ONLY**, and that is the Recommendation's reading rather than a
// shortcut: section 3.5.8 fixes a derived proof's base signature at 64 bytes
// and its HMAC labels at 32 — P-256 with SHA-256 — so a P-384 issuer's
// derived proof has no encoding a conforming verifier would parse, and the
// proof-scoped key is P-256 whatever the issuer's is (3.6.5).
//
// **THE ALGORITHMS ARE THE SPECIFICATION'S STEPS, IMPLEMENTED HERE**, not
// `@digitalbazaar/ecdsa-sd-2023-cryptosuite`: the W3C suite derives and
// checks with that library, and a verifier built from it would agree with it
// by construction — `vendored/bbs2023.js`'s argument for a second
// implementation, made again. What IS shared, and must be, is the canonical
// form: `vc_jsonld.ts`'s RDFC-1.0 over the same closed context set.
// `tests/vc_ecdsa_sd.js` holds this file to the specification's own test
// vectors (its Appendix A.7, fetched with the other corpora).
//
// The primitives — ECDSA, HMAC-SHA-256, the proof-scoped key pair — are
// `common/crypto.js`'s (3r); CBOR is `vc_status_codec.ts`'s.
//
// A LIBRARY (rule 3): no route.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import InstanceSlot = require('../common/instance_slot');
import vcJsonLd = require('./vc_jsonld');
import codec = require('./vc_status_codec');

interface VcEcdsaSdDeps {
  log: typeof helpers.log;
  jsonld: typeof vcJsonLd;
  stsCrypto: typeof stsCrypto;
  cborEncode: (value: unknown) => Buffer;
  cborDecode: (bytes: Buffer) => any;
  randomUuid: () => string;
}

const CRYPTOSUITE = 'ecdsa-sd-2023';
const BASE_HEADER = Buffer.from([0xd9, 0x5d, 0x00]);
const DERIVED_HEADER = Buffer.from([0xd9, 0x5d, 0x01]);
// The skolem scheme blank nodes carry through selection (3.4.7).
const SKOLEM_PREFIX = 'urn:bnid:';

// A label map factory: canonical id map (input label -> c14n label) in,
// input label -> new label out.
type LabelMapFactory = (canonicalIdMap: Map<string, string>) =>
  Map<string, string>;

class VcEcdsaSd {
  static readonly CRYPTOSUITE = CRYPTOSUITE;

  constructor(private readonly deps: VcEcdsaSdDeps) {
    deps.log.debug("Entering VcEcdsaSd.constructor().");
    deps.log.debug("Leaving VcEcdsaSd.constructor().");
  }

  static defaultDeps(): VcEcdsaSdDeps {
    helpers.log.debug("Entering VcEcdsaSd.defaultDeps().");
    helpers.log.debug("Leaving VcEcdsaSd.defaultDeps().");
    return {
      log: helpers.log,
      jsonld: vcJsonLd,
      stsCrypto: stsCrypto,
      cborEncode: function cborEncode(value: unknown): Buffer {
        helpers.log.debug("Entering cborEncode().");
        helpers.log.debug("Leaving cborEncode().");
        return codec.cborEncode(value);
      },
      cborDecode: function cborDecode(bytes: Buffer): any {
        helpers.log.debug("Entering cborDecode().");
        helpers.log.debug("Leaving cborDecode().");
        return codec.cborDecode(bytes);
      },
      randomUuid: function randomUuid(): string {
        helpers.log.debug("Entering randomUuid().");
        helpers.log.debug("Leaving randomUuid().");
        return crypto.randomUUID();
      }
    };
  }

  // ---------------------------------------------------------------------------
  // THE P-256 MULTIKEY, as bytes: 0x80 0x24 (the p256-pub multicodec as a
  // varint), then the compressed point. Written here rather than asked of
  // `vc_data_integrity.ts`, which requires this module.
  // ---------------------------------------------------------------------------
  p256MultikeyBytes(jwk: any): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.p256MultikeyBytes().");
    const x = Buffer.from(String(jwk.x), 'base64url');
    const y = Buffer.from(String(jwk.y), 'base64url');
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || x.length !== 32 ||
        y.length !== 32) {
      log.debug("Leaving VcEcdsaSd.p256MultikeyBytes(). Not P-256.");
      throw new Error('not a P-256 public key.');
    }
    log.debug("Leaving VcEcdsaSd.p256MultikeyBytes().");
    return Buffer.concat([Buffer.from([0x80, 0x24,
      (y[y.length - 1] & 1) ? 3 : 2]), x]);
  }

  // Its inverse: a public JWK, the point decompressed by OpenSSL on import.
  p256JwkOfMultikeyBytes(bytes: Buffer): any {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.p256JwkOfMultikeyBytes().");
    if (!Buffer.isBuffer(bytes) || bytes.length !== 35 || bytes[0] !== 0x80 ||
        bytes[1] !== 0x24) {
      log.debug("Leaving VcEcdsaSd.p256JwkOfMultikeyBytes(). Not one.");
      throw new Error('PROOF_VERIFICATION_ERROR: the proof-scoped key is ' +
                      'not a compressed P-256 Multikey.');
    }
    const spki = Buffer.concat([Buffer.from('3039301306072a8648ce3d0201' +
      '06082a8648ce3d030107032200', 'hex'), bytes.subarray(2)]);
    const key = crypto.createPublicKey({ key: spki, format: 'der',
                                        type: 'spki' });
    const jwk: any = key.export({ format: 'jwk' });
    log.debug("Leaving VcEcdsaSd.p256JwkOfMultikeyBytes().");
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  }

  // ---------------------------------------------------------------------------
  // 3.4.3, 3.4.4: the label map factories.
  // ---------------------------------------------------------------------------
  hmacLabelMapFactory(hmacKey: Buffer): LabelMapFactory {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering VcEcdsaSd.hmacLabelMapFactory().");
    // One label per blank node, called in a loop: no Entering/Leaving pair
    // — the hot-path exception, stated as the style requires.
    const factory = function (canonicalIdMap: Map<string, string>):
      Map<string, string> {
      const out = new Map<string, string>();
      canonicalIdMap.forEach(function (c14n, input) {
        out.set(input, 'u' + stsCrypto.hmacSha256(hmacKey,
          Buffer.from(c14n, 'utf8')).toString('base64url'));
      });
      return out;
    };
    log.debug("Leaving VcEcdsaSd.hmacLabelMapFactory().");
    return factory;
  }

  labelMapFactory(labelMap: Map<string, string>): LabelMapFactory {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.labelMapFactory().");
    const factory = function (canonicalIdMap: Map<string, string>):
      Map<string, string> {
      const out = new Map<string, string>();
      canonicalIdMap.forEach(function (c14n, input) {
        out.set(input, labelMap.get(c14n));
      });
      return out;
    };
    log.debug("Leaving VcEcdsaSd.labelMapFactory().");
    return factory;
  }

  // The canonical id map without `_:` prefixes, whichever way the processor
  // wrote it.
  private stripPrefixes(map: Map<string, string>): Map<string, string> {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.stripPrefixes().");
    const out = new Map<string, string>();
    map.forEach(function (v, k) {
      out.set(k.indexOf('_:') === 0 ? k.slice(2) : k,
              v.indexOf('_:') === 0 ? v.slice(2) : v);
    });
    log.debug("Leaving VcEcdsaSd.stripPrefixes().");
    return out;
  }

  // Canonical N-Quads relabelled through a factory, one string per quad
  // (each ending in a newline) and sorted — 3.4.1's output.
  private relabelCanonical(canonical: string,
                           canonicalIdMap: Map<string, string>,
                           factory: LabelMapFactory): any {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.relabelCanonical().");
    const ids = this.stripPrefixes(canonicalIdMap);
    const labelMap = factory(ids);
    const c14nToNew = new Map<string, string>();
    labelMap.forEach(function (label, input) {
      c14nToNew.set(ids.get(input), label);
    });
    const nquads = canonical.split('\n').filter(function (line) {
      return line.length > 0;
    }).map(function (line) {
      return line.replace(/(_:([^\s]+))/g, function (m: string, s1: string,
                                                    label: string): string {
        return '_:' + c14nToNew.get(label);
      }) + '\n';
    });
    nquads.sort(this.compareCodePoints);
    log.debug("Leaving VcEcdsaSd.relabelCanonical(). " + nquads.length +
              " quad(s).");
    return { nquads: nquads, labelMap: labelMap };
  }

  // Unicode code point order, which RDFC-1.0 sorts canonical N-Quads by
  // (a JavaScript sort compares UTF-16 code units, which differs above the
  // BMP).
  private compareCodePoints(a: string, b: string): number {
    const ca = Array.from(a);
    const cb = Array.from(b);
    const n = Math.min(ca.length, cb.length);
    for (let i = 0; i < n; i++) {
      const x = ca[i].codePointAt(0);
      const y = cb[i].codePointAt(0);
      if (x !== y) {
        return x < y ? -1 : 1;
      }
    }
    return ca.length - cb.length;
  }

  // 3.4.1.
  async labelReplacementCanonicalizeNQuads(nquads: string[],
                                           factory: LabelMapFactory):
    Promise<any> {
    const { log, jsonld } = this.deps;
    log.debug("Entering VcEcdsaSd.labelReplacementCanonicalizeNQuads().");
    const canonicalIdMap = new Map<string, string>();
    const canonical = await jsonld.canonizeNQuads(nquads.join(''),
                                                  { canonicalIdMap });
    const out = this.relabelCanonical(canonical, canonicalIdMap, factory);
    log.debug("Leaving VcEcdsaSd.labelReplacementCanonicalizeNQuads().");
    return out;
  }

  // 3.4.2.
  async labelReplacementCanonicalizeJsonLd(document: any,
                                           factory: LabelMapFactory):
    Promise<any> {
    const { log, jsonld } = this.deps;
    log.debug("Entering VcEcdsaSd.labelReplacementCanonicalizeJsonLd().");
    const canonicalIdMap = new Map<string, string>();
    const canonical = await jsonld.canonize(document, { canonicalIdMap });
    const out = this.relabelCanonical(canonical, canonicalIdMap, factory);
    log.debug("Leaving VcEcdsaSd.labelReplacementCanonicalizeJsonLd().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // 3.4.5-3.4.9: skolemization — every blank node given a URN so that it
  // survives a JSON selection and comes back as the same blank node.
  // ---------------------------------------------------------------------------
  skolemizeExpanded(expanded: any[], labeler: { random: string;
                                                count: number }): any[] {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.skolemizeExpanded().");
    const out: any[] = [];
    for (let i = 0; i < expanded.length; i++) {
      const element = expanded[i];
      if (!element || typeof element !== 'object' ||
          element['@value'] !== undefined) {
        out.push(JSON.parse(JSON.stringify(element === undefined ? null :
                                           element)));
        continue;
      }
      const node: any = {};
      for (const property of Object.keys(element)) {
        const value = element[property];
        node[property] = Array.isArray(value)
          ? this.skolemizeExpanded(value, labeler)
          : this.skolemizeExpanded([value], labeler)[0];
      }
      if (node['@id'] === undefined) {
        node['@id'] = SKOLEM_PREFIX + '_' + labeler.random + '_' +
          labeler.count;
        labeler.count += 1;
      } else if (typeof node['@id'] === 'string' &&
                 node['@id'].indexOf('_:') === 0) {
        node['@id'] = SKOLEM_PREFIX + node['@id'].slice(2);
      }
      out.push(node);
    }
    log.debug("Leaving VcEcdsaSd.skolemizeExpanded().");
    return out;
  }

  async skolemizeCompact(document: any): Promise<any> {
    const { log, jsonld, randomUuid } = this.deps;
    log.debug("Entering VcEcdsaSd.skolemizeCompact().");
    if (!document || typeof document !== 'object' ||
        document['@context'] === undefined) {
      log.debug("Leaving VcEcdsaSd.skolemizeCompact(). No context.");
      throw new Error('a compact JSON-LD document with an @context is ' +
                      'needed.');
    }
    const expanded = await jsonld.expand(document);
    const skolemized = this.skolemizeExpanded(expanded,
      { random: randomUuid(), count: 0 });
    const compact = await jsonld.compact(skolemized, document['@context']);
    log.debug("Leaving VcEcdsaSd.skolemizeCompact().");
    return { expanded: skolemized, compact: compact };
  }

  async toDeskolemizedNQuads(document: any): Promise<string[]> {
    const { log, jsonld } = this.deps;
    log.debug("Entering VcEcdsaSd.toDeskolemizedNQuads().");
    const rdf = await jsonld.toNQuads(document);
    const out = rdf.split('\n').filter(function (line) {
      return line.length > 0;
    }).map(function (line) {
      return line.replace(/(<urn:bnid:([^>]+)>)/g, '_:$2') + '\n';
    });
    log.debug("Leaving VcEcdsaSd.toDeskolemizedNQuads().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // 3.4.10-3.4.15: JSON pointers and selection.
  // ---------------------------------------------------------------------------
  parsePointer(pointer: unknown): (string | number)[] {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.parsePointer().");
    if (typeof pointer !== 'string' || (pointer !== '' &&
                                        pointer.charAt(0) !== '/')) {
      log.debug("Leaving VcEcdsaSd.parsePointer(). Not a pointer.");
      throw new Error('"' + String(pointer) + '" is not a JSON pointer ' +
                      '(RFC 6901).');
    }
    const out = pointer.split('/').slice(1).map(function (path) {
      if (path.indexOf('~') < 0) {
        return /^(0|[1-9]\d*)$/.test(path) ? parseInt(path, 10) : path;
      }
      return path.replace(/~[01]/g, function (m: string): string {
        return m === '~1' ? '/' : '~';
      });
    });
    if (out.some(function (p) {
      return typeof p === 'string' && /~(?![01])/.test(p);
    })) {
      log.debug("Leaving VcEcdsaSd.parsePointer(). Bad escape.");
      throw new Error('"' + pointer + '" has an invalid escape.');
    }
    log.debug("Leaving VcEcdsaSd.parsePointer().");
    return out;
  }

  // 3.4.11.
  private initialSelection(source: any): any {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.initialSelection().");
    const selection: any = {};
    if (source && typeof source.id === 'string' &&
        source.id.indexOf('_:') !== 0) {
      selection.id = source.id;
    }
    if (source && source.type !== undefined) {
      selection.type = source.type;
    }
    log.debug("Leaving VcEcdsaSd.initialSelection().");
    return selection;
  }

  // 3.4.13 (and 3.4.12 inside it).
  selectJsonLd(document: any, pointers: string[]): any {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.selectJsonLd(). " + pointers.length +
              " pointer(s).");
    if (!pointers.length) {
      log.debug("Leaving VcEcdsaSd.selectJsonLd(). Nothing selected.");
      return null;
    }
    const arrays: any[][] = [];
    const selection: any = Object.assign({ '@context':
      JSON.parse(JSON.stringify(document['@context'])) },
      this.initialSelection(document));
    for (const pointer of pointers) {
      const paths = this.parsePointer(pointer);
      if (!paths.length) {
        log.debug("Leaving VcEcdsaSd.selectJsonLd(). The whole document.");
        return JSON.parse(JSON.stringify(document));
      }
      let value: any = document;
      let selectedParent: any = selection;
      let selectedValue: any = selection;
      for (const path of paths) {
        selectedParent = selectedValue;
        const parentValue = value;
        value = parentValue === null || parentValue === undefined
          ? undefined : parentValue[path];
        if (value === undefined) {
          log.debug("Leaving VcEcdsaSd.selectJsonLd(). No match.");
          throw new Error('PROOF_GENERATION_ERROR: the JSON pointer "' +
                          pointer + '" does not match the document.');
        }
        selectedValue = selectedParent[path];
        if (selectedValue === undefined) {
          if (Array.isArray(value)) {
            selectedValue = [];
            arrays.push(selectedValue);
          } else {
            selectedValue = this.initialSelection(value);
          }
          selectedParent[path] = selectedValue;
        }
      }
      if (value === null || typeof value !== 'object') {
        selectedValue = value;
      } else if (Array.isArray(value)) {
        selectedValue = JSON.parse(JSON.stringify(value));
      } else {
        selectedValue = Object.assign({}, selectedValue,
                                      JSON.parse(JSON.stringify(value)));
      }
      selectedParent[paths[paths.length - 1]] = selectedValue;
    }
    arrays.forEach(function (array) {
      let i = 0;
      while (i < array.length) {
        if (array[i] === undefined) {
          array.splice(i, 1);
        } else {
          i += 1;
        }
      }
    });
    log.debug("Leaving VcEcdsaSd.selectJsonLd().");
    return selection;
  }

  // 3.4.14.
  relabelBlankNodes(nquads: string[], labelMap: Map<string, string>):
    string[] {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.relabelBlankNodes().");
    const out = nquads.map(function (nq) {
      return nq.replace(/(_:([^\s]+))/g, function (m: string, s1: string,
                                                   label: string): string {
        return '_:' + labelMap.get(label);
      });
    });
    log.debug("Leaving VcEcdsaSd.relabelBlankNodes().");
    return out;
  }

  // 3.4.15.
  async selectCanonicalNQuads(document: any, pointers: string[],
                              labelMap: Map<string, string>): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.selectCanonicalNQuads().");
    const selection = this.selectJsonLd(document, pointers);
    const deskolemized = selection
      ? await this.toDeskolemizedNQuads(selection) : [];
    const nquads = this.relabelBlankNodes(deskolemized, labelMap);
    log.debug("Leaving VcEcdsaSd.selectCanonicalNQuads().");
    return { selection: selection, deskolemizedNQuads: deskolemized,
             nquads: nquads };
  }

  // 3.4.16.
  async canonicalizeAndGroup(document: any, factory: LabelMapFactory,
                             groups: Record<string, string[]>):
    Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.canonicalizeAndGroup().");
    const skolemized = await this.skolemizeCompact(document);
    const deskolemized = await this.toDeskolemizedNQuads(
      skolemized.expanded);
    const canonical = await this.labelReplacementCanonicalizeNQuads(
      deskolemized, factory);
    const out: any = {};
    for (const name of Object.keys(groups)) {
      const selected = await this.selectCanonicalNQuads(skolemized.compact,
        groups[name], canonical.labelMap);
      const matching = new Map<number, string>();
      const nonMatching = new Map<number, string>();
      canonical.nquads.forEach(function (nq: string, index: number) {
        if (selected.nquads.indexOf(nq) >= 0) {
          matching.set(index, nq);
        } else {
          nonMatching.set(index, nq);
        }
      });
      out[name] = { matching: matching, nonMatching: nonMatching,
                    deskolemizedNQuads: selected.deskolemizedNQuads };
    }
    log.debug("Leaving VcEcdsaSd.canonicalizeAndGroup().");
    return { groups: out, skolemized: skolemized,
             labelMap: canonical.labelMap, nquads: canonical.nquads };
  }

  // 3.4.17, and every other hash here: SHA-256 (P-256 only, see header).
  private sha256(data: string | Buffer): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.sha256().");
    log.debug("Leaving VcEcdsaSd.sha256().");
    return crypto.createHash('sha256')
      .update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data)
      .digest();
  }

  // The proof configuration's hash (3.6.3 and 3.5.9): the proof without its
  // value, with the document's @context, canonicalized.
  private async proofHash(document: any, proof: any): Promise<Buffer> {
    const { log, jsonld } = this.deps;
    log.debug("Entering VcEcdsaSd.proofHash().");
    const config = Object.assign({}, proof);
    delete config.proofValue;
    config['@context'] = document['@context'];
    const canonical = await jsonld.canonize(config);
    log.debug("Leaving VcEcdsaSd.proofHash().");
    return this.sha256(canonical);
  }

  private ecdsa(privateKey: any, data: Buffer): Buffer {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering VcEcdsaSd.ecdsa().");
    log.debug("Leaving VcEcdsaSd.ecdsa().");
    return stsCrypto.signRawSignature({ family: 'ecdsa', hash: 'sha256',
                                        encoding: 'p1363' }, privateKey, data);
  }

  // ---------------------------------------------------------------------------
  // 3.6.1-3.6.5: THE BASE PROOF. `options`: publicJwk (a P-256 key),
  // privateKey, verificationMethod, mandatoryPointers, created,
  // proofPurpose. Answers the secured document.
  // ---------------------------------------------------------------------------
  async createBaseProof(unsecured: any, options: any): Promise<any> {
    const { log, cborEncode, stsCrypto } = this.deps;
    log.debug("Entering VcEcdsaSd.createBaseProof().");
    const o = options || {};
    if (!o.publicJwk || o.publicJwk.kty !== 'EC' ||
        o.publicJwk.crv !== 'P-256') {
      log.debug("Leaving VcEcdsaSd.createBaseProof(). Not P-256.");
      throw new Error('ecdsa-sd-2023 signs with a P-256 key (see ' +
                      'oid4vc/vc_ecdsa_sd.ts).');
    }
    const mandatoryPointers: string[] = Array.isArray(o.mandatoryPointers)
      ? o.mandatoryPointers : [];
    mandatoryPointers.forEach((p) => {
      this.parsePointer(p);
    });
    const document = Object.assign({}, unsecured);
    delete document.proof;
    const proof: any = {
      type: 'DataIntegrityProof', cryptosuite: CRYPTOSUITE,
      created: o.created || new Date().toISOString()
        .replace(/\.\d{3}Z$/, 'Z'),
      verificationMethod: o.verificationMethod,
      proofPurpose: o.proofPurpose || 'assertionMethod'
    };
    const hmacKey = crypto.randomBytes(32);
    const grouped = await this.canonicalizeAndGroup(document,
      this.hmacLabelMapFactory(hmacKey), { mandatory: mandatoryPointers });
    const mandatory = Array.from(grouped.groups.mandatory.matching.values());
    const nonMandatory = Array.from(
      grouped.groups.mandatory.nonMatching.values());
    const proofHash = await this.proofHash(document, proof);
    const mandatoryHash = this.sha256((mandatory as string[]).join(''));
    const scoped = stsCrypto.ephemeralKeyPair('ec', 'prime256v1');
    const signatures = (nonMandatory as string[]).map((nq) => {
      return this.ecdsa(scoped.privateKey, Buffer.from(nq, 'utf8'));
    });
    const publicKey = this.p256MultikeyBytes(
      scoped.publicKey.export({ format: 'jwk' }));
    const baseSignature = this.ecdsa(o.privateKey,
      Buffer.concat([proofHash, publicKey, mandatoryHash]));
    const value = Buffer.concat([BASE_HEADER, cborEncode([baseSignature,
      publicKey, hmacKey, signatures, mandatoryPointers])]);
    proof.proofValue = 'u' + value.toString('base64url');
    log.debug("Leaving VcEcdsaSd.createBaseProof(). " + mandatory.length +
              " mandatory, " + nonMandatory.length + " signed.");
    return Object.assign(document, { proof: proof });
  }

  // 3.5.3.
  parseBaseProofValue(proofValue: unknown): any {
    const { log, cborDecode } = this.deps;
    log.debug("Entering VcEcdsaSd.parseBaseProofValue().");
    const bytes = this.multibaseU(proofValue);
    if (bytes.length < 3 || !bytes.subarray(0, 3).equals(BASE_HEADER)) {
      log.debug("Leaving VcEcdsaSd.parseBaseProofValue(). Not a base " +
                "proof.");
      throw new Error('PROOF_VERIFICATION_ERROR: not an ecdsa-sd-2023 ' +
                      'base proof (header 0xd95d00).');
    }
    const c = cborDecode(bytes.subarray(3));
    if (!Array.isArray(c) || c.length !== 5 || !Buffer.isBuffer(c[0]) ||
        !Buffer.isBuffer(c[1]) || !Buffer.isBuffer(c[2]) ||
        !Array.isArray(c[3]) || !Array.isArray(c[4])) {
      log.debug("Leaving VcEcdsaSd.parseBaseProofValue(). Malformed.");
      throw new Error('PROOF_VERIFICATION_ERROR: an ecdsa-sd-2023 base ' +
                      'proof is five components.');
    }
    log.debug("Leaving VcEcdsaSd.parseBaseProofValue().");
    return { baseSignature: c[0], publicKey: c[1], hmacKey: c[2],
             signatures: c[3], mandatoryPointers: c[4] };
  }

  private multibaseU(value: unknown): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcEcdsaSd.multibaseU().");
    if (typeof value !== 'string' || value.charAt(0) !== 'u' ||
        !/^u[A-Za-z0-9_-]*$/.test(value)) {
      log.debug("Leaving VcEcdsaSd.multibaseU(). Not base64url.");
      throw new Error('PROOF_VERIFICATION_ERROR: an ecdsa-sd-2023 ' +
                      'proofValue is multibase base64url-no-pad ("u").');
    }
    log.debug("Leaving VcEcdsaSd.multibaseU().");
    return Buffer.from(value.slice(1), 'base64url');
  }

  // ---------------------------------------------------------------------------
  // 3.5.4 and 3.6.6: A DERIVED PROOF, revealing the mandatory statements and
  // those `selectivePointers` name.
  // ---------------------------------------------------------------------------
  async deriveProof(secured: any, selectivePointers: string[]):
    Promise<any> {
    const { log, jsonld, cborEncode } = this.deps;
    log.debug("Entering VcEcdsaSd.deriveProof().");
    const proof = secured && secured.proof;
    if (!proof || proof.cryptosuite !== CRYPTOSUITE) {
      log.debug("Leaving VcEcdsaSd.deriveProof(). No base proof.");
      throw new Error('the credential carries no ecdsa-sd-2023 proof.');
    }
    const base = this.parseBaseProofValue(proof.proofValue);
    const document = Object.assign({}, secured);
    delete document.proof;
    const mandatoryPointers = base.mandatoryPointers as string[];
    const combinedPointers = mandatoryPointers.concat(
      selectivePointers || []);
    const grouped = await this.canonicalizeAndGroup(document,
      this.hmacLabelMapFactory(base.hmacKey), {
        mandatory: mandatoryPointers, selective: selectivePointers || [],
        combined: combinedPointers });
    const mandatoryIndexes: number[] = [];
    let relative = 0;
    Array.from(grouped.groups.combined.matching.keys()).forEach(
      function (absolute: number) {
        if (grouped.groups.mandatory.matching.has(absolute)) {
          mandatoryIndexes.push(relative);
        }
        relative += 1;
      });
    const filtered: Buffer[] = [];
    let index = 0;
    (base.signatures as Buffer[]).forEach(function (signature) {
      while (grouped.groups.mandatory.matching.has(index)) {
        index += 1;
      }
      if (grouped.groups.selective.matching.has(index)) {
        filtered.push(signature);
      }
      index += 1;
    });
    const reveal = this.selectJsonLd(document, combinedPointers);
    const canonicalIdMap = new Map<string, string>();
    await jsonld.canonizeNQuads(
      grouped.groups.combined.deskolemizedNQuads.join(''),
      { canonicalIdMap });
    const verifierLabelMap = new Map<number, Buffer>();
    this.stripPrefixes(canonicalIdMap).forEach(function (verifierLabel,
                                                         inputLabel) {
      const label = grouped.labelMap.get(inputLabel);
      verifierLabelMap.set(parseInt(verifierLabel.replace(/^c14n/, ''), 10),
                           Buffer.from(String(label).slice(1), 'base64url'));
    });
    const value = Buffer.concat([DERIVED_HEADER, cborEncode([
      base.baseSignature, base.publicKey, filtered, verifierLabelMap,
      mandatoryIndexes])]);
    const derivedProof = Object.assign({}, proof,
      { proofValue: 'u' + value.toString('base64url') });
    log.debug("Leaving VcEcdsaSd.deriveProof(). " + filtered.length +
              " selective signature(s).");
    return Object.assign(reveal || {}, { proof: derivedProof });
  }

  // 3.5.8.
  parseDerivedProofValue(proofValue: unknown): any {
    const { log, cborDecode } = this.deps;
    log.debug("Entering VcEcdsaSd.parseDerivedProofValue().");
    const bytes = this.multibaseU(proofValue);
    if (bytes.length < 3 || !bytes.subarray(0, 3).equals(DERIVED_HEADER)) {
      log.debug("Leaving VcEcdsaSd.parseDerivedProofValue(). Not " +
                "derived.");
      throw new Error('PROOF_VERIFICATION_ERROR: not an ecdsa-sd-2023 ' +
                      'derived proof (header 0xd95d01)' +
                      (bytes.subarray(0, 3).equals(BASE_HEADER)
                        ? '; this is a BASE proof, which is the holder\'s ' +
                          'to derive from and never a verifier\'s to accept'
                        : '') + '.');
    }
    const c = cborDecode(bytes.subarray(3));
    const ok = Array.isArray(c) && c.length === 5 &&
      Buffer.isBuffer(c[0]) && c[0].length === 64 &&
      Buffer.isBuffer(c[1]) && c[1].length === 35 &&
      c[1][0] === 0x80 && c[1][1] === 0x24 &&
      Array.isArray(c[2]) && c[2].every(function (s: any) {
        return Buffer.isBuffer(s) && s.length === 64;
      }) &&
      c[3] instanceof Map && Array.from(c[3].entries()).every(
        function (e: any) {
          return Number.isInteger(e[0]) && e[0] >= 0 &&
            Buffer.isBuffer(e[1]) && e[1].length === 32;
        }) &&
      Array.isArray(c[4]) && c[4].every(function (i: any) {
        return Number.isInteger(i) && i >= 0;
      });
    if (!ok) {
      log.debug("Leaving VcEcdsaSd.parseDerivedProofValue(). Malformed.");
      throw new Error('PROOF_VERIFICATION_ERROR: an ecdsa-sd-2023 derived ' +
        'proof is a 64-byte base signature, a 35-byte P-256 Multikey, 64-' +
        'byte signatures, a map of integers to 32-byte labels and an array ' +
        'of integers (section 3.5.8).');
    }
    const labelMap = new Map<string, string>();
    (c[3] as Map<number, Buffer>).forEach(function (v, k) {
      labelMap.set('c14n' + k, 'u' + v.toString('base64url'));
    });
    log.debug("Leaving VcEcdsaSd.parseDerivedProofValue().");
    return { baseSignature: c[0], publicKey: c[1], signatures: c[2],
             labelMap: labelMap, mandatoryIndexes: c[4] };
  }

  // ---------------------------------------------------------------------------
  // 3.5.9 and 3.6.7: VERIFY A DERIVED PROOF. `issuerJwk` is the base proof
  // verification method's key, resolved by the caller. Answers `{ ok,
  // detail }`; throws for nothing.
  // ---------------------------------------------------------------------------
  async verifyDerivedProof(secured: any, issuerJwk: any): Promise<any> {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering VcEcdsaSd.verifyDerivedProof().");
    try {
      if (!issuerJwk || issuerJwk.kty !== 'EC' || issuerJwk.crv !== 'P-256') {
        log.debug("Leaving VcEcdsaSd.verifyDerivedProof(). Not P-256.");
        return { ok: false, detail: 'the verification method is not a ' +
                 'P-256 key, which ecdsa-sd-2023 signs with.' };
      }
      const proof = secured.proof;
      const document = Object.assign({}, secured);
      delete document.proof;
      const parsed = this.parseDerivedProofValue(proof.proofValue);
      const proofHash = await this.proofHash(document, proof);
      const canonical = await this.labelReplacementCanonicalizeJsonLd(
        document, this.labelMapFactory(parsed.labelMap));
      const mandatory: string[] = [];
      const nonMandatory: string[] = [];
      canonical.nquads.forEach(function (nq: string, i: number) {
        if (parsed.mandatoryIndexes.indexOf(i) >= 0) {
          mandatory.push(nq);
        } else {
          nonMandatory.push(nq);
        }
      });
      if (parsed.signatures.length !== nonMandatory.length) {
        log.debug("Leaving VcEcdsaSd.verifyDerivedProof(). Count.");
        return { ok: false, detail: 'PROOF_VERIFICATION_ERROR: the ' +
                 'signature count (' + parsed.signatures.length + ') does ' +
                 'not match the non-mandatory statement count (' +
                 nonMandatory.length + ').' };
      }
      const mandatoryHash = this.sha256(mandatory.join(''));
      const issuerKey = crypto.createPublicKey({ key: issuerJwk,
                                                 format: 'jwk' });
      const scheme = { family: 'ecdsa', hash: 'sha256', encoding: 'p1363' };
      let verified = await stsCrypto.verifyRawSignature(scheme, issuerKey,
        Buffer.concat([proofHash, parsed.publicKey, mandatoryHash]),
        parsed.baseSignature);
      const scopedJwk = this.p256JwkOfMultikeyBytes(parsed.publicKey);
      const scopedKey = crypto.createPublicKey({ key: scopedJwk,
                                                 format: 'jwk' });
      for (let i = 0; i < nonMandatory.length && verified; i++) {
        verified = await stsCrypto.verifyRawSignature(scheme, scopedKey,
          Buffer.from(nonMandatory[i], 'utf8'), parsed.signatures[i]);
      }
      log.debug("Leaving VcEcdsaSd.verifyDerivedProof(). " + verified);
      return { ok: !!verified, detail: verified
        ? 'the base signature and ' + nonMandatory.length + ' statement ' +
          'signature(s) verify (' + mandatory.length + ' mandatory).'
        : 'a signature does not verify: the base signature over the proof, ' +
          'the proof-scoped key and the mandatory statements, or a ' +
          'disclosed statement\'s own.' };
    } catch (e) {
      log.debug("Caught in VcEcdsaSd.verifyDerivedProof(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcEcdsaSd.verifyDerivedProof(). Refused.");
      return { ok: false, detail: String((e && e.message) || e) };
    }
  }
}

const slot = new InstanceSlot<VcEcdsaSd>(
  'oid4vc/vc_ecdsa_sd',
  () => new VcEcdsaSd(VcEcdsaSd.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  VcEcdsaSd: VcEcdsaSd,
  installInstance: (instance: VcEcdsaSd): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  CRYPTOSUITE: CRYPTOSUITE,
  p256MultikeyBytes: slot.forward('p256MultikeyBytes'),
  p256JwkOfMultikeyBytes: slot.forward('p256JwkOfMultikeyBytes'),
  parsePointer: slot.forward('parsePointer'),
  selectJsonLd: slot.forward('selectJsonLd'),
  canonicalizeAndGroup: slot.forward('canonicalizeAndGroup'),
  createBaseProof: slot.forward('createBaseProof'),
  parseBaseProofValue: slot.forward('parseBaseProofValue'),
  deriveProof: slot.forward('deriveProof'),
  parseDerivedProofValue: slot.forward('parseDerivedProofValue'),
  verifyDerivedProof: slot.forward('verifyDerivedProof')
};
