// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_bbs.ts
//
// ---------------------------------------------------------------------------
// bbs-2023: THE W3C BBS CRYPTOSUITE (#1878, 2026-11-17) — Data Integrity BBS
// Cryptosuites v1.0 (https://www.w3.org/TR/vc-di-bbs/, Candidate
// Recommendation Draft 10 September 2026), its BASELINE form: the issuer's
// base proof (sections 3.3.1-3.3.2, serialized by 3.2.1), the holder's
// derived proof (3.3.3, serialized by 3.2.3) and the verifier's check of a
// derived proof (3.3.4-3.3.5). The anonymous-holder-binding and pseudonym
// variants (headers 0x04-0x09) are at risk in the CRD and are REFUSED by
// name rather than misread.
//
// UNTIL #1878 THIS SERVICE'S `bbs-2023` WAS ITS OWN FORMAT — every canonical
// statement a message, the header the proof options' N-Quads, the proofValue
// the raw signature, and a presentation an envelope of statements — under
// the W3C cryptosuite's name, so nothing else could verify what it issued and
// it could verify nothing else. `common/crypto_impl/bbs2023.js` keeps that
// format's READER for the verifier's legacy envelope; nothing makes it.
//
// How it works, in one paragraph, because every method below is a step of
// it. The issuer canonicalizes the credential with RDFC-1.0 and relabels
// every blank node `b<i>`, where `i` is the rank of an HMAC of its canonical
// label among all of them, under a key only the base proof carries — so a
// label says nothing about the statements a holder withholds, and (unlike
// ecdsa-sd-2023's) its length says nothing either. The statements the
// mandatory JSON pointers select are hashed; every other statement is a BBS
// message; and one BBS signature covers those messages under a header that
// is the proof configuration's hash followed by the mandatory hash. A holder
// derives a fresh, unlinkable BBS proof revealing the mandatory statements
// and any subset of the rest, as a REVEAL DOCUMENT — the credential with only
// what is revealed — carrying a label map (verifier label to `b<i>`), the
// mandatory statements' positions and the revealed messages' indexes. A
// verifier canonicalizes the reveal document, relabels through the map,
// re-hashes the mandatory statements and runs ProofVerify.
//
// **THE GENERIC STEPS ARE `vc_ecdsa_sd.ts`'s** — skolemization, JSON pointer
// selection, canonicalize-and-group, label replacement — which Data
// Integrity 1.1 now holds for every selective-disclosure suite, and which
// that file already implements against ecdsa-sd-2023's vectors. What is
// bbs-2023's own is here: the shuffled label map, the header, the two CBOR
// encodings (a compressed label map of integers, not of HMAC digests), and
// the BBS calls, which are `common/crypto.js`'s (rule 3r) through
// `common/crypto_impl/bbs2023.js`.
//
// **`created` IS NOT PUT IN A PROOF HERE BY DEFAULT**: the specification's
// privacy considerations name it as a value that shrinks the anonymity set,
// and Digital Bazaar's implementation drops it. A caller may still pass one.
//
// `tests/vc_bbs2023.js` holds this file to the specification's Appendix
// test vectors and to Digital Bazaar's bbs-2023-cryptosuite.
//
// A LIBRARY (rule 3): no route.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import InstanceSlot = require('../common/instance_slot');
import vcJsonLd = require('./vc_jsonld');
import vcEcdsaSd = require('./vc_ecdsa_sd');
import codec = require('./vc_status_codec');

// The BBS primitives this file asks for: `common/crypto.js`'s door to
// `common/crypto_impl/bbs2023.js`.
interface BbsPrimitives {
  sign: (input: any) => Promise<Uint8Array>;
  verifySignature: (input: any) => Promise<boolean>;
  deriveProof: (input: any) => Promise<Uint8Array>;
  verifyProof: (input: any) => Promise<boolean>;
}

interface VcBbsDeps {
  log: typeof helpers.log;
  jsonld: typeof vcJsonLd;
  sd: typeof vcEcdsaSd;
  stsCrypto: typeof stsCrypto;
  bbs: BbsPrimitives;
  cborEncode: (value: unknown) => Buffer;
  cborDecode: (bytes: Buffer) => any;
}

/**
 * The cryptosuite's name, `bbs-2023`.
 */
const CRYPTOSUITE = 'bbs-2023';
const PROOF_TYPE = 'DataIntegrityProof';
// Section 3.2.1 and 3.2.3: the baseline headers.
const BASE_HEADER = Buffer.from([0xd9, 0x5d, 0x02]);
const DERIVED_HEADER = Buffer.from([0xd9, 0x5d, 0x03]);
// The optional features' headers (section 4), at risk in the CRD and not
// implemented here: named, so a refusal says what it was handed.
const FEATURES: Record<number, string> = {
  0x04: 'anonymous_holder_binding', 0x05: 'anonymous_holder_binding',
  0x06: 'pseudonym', 0x07: 'pseudonym',
  0x08: 'holder_binding_pseudonym', 0x09: 'holder_binding_pseudonym'
};

// A label map factory: canonical id map (input label -> c14n label) in,
// input label -> new label out (`vc_ecdsa_sd.ts`'s type).
type LabelMapFactory = (canonicalIdMap: Map<string, string>) =>
  Map<string, string>;

/**
 * bbs-2023, the W3C Data Integrity BBS cryptosuite (baseline): the issuer's
 * base proof, the holder's derived proof and the verifier's check of it.
 * Each method is a step of the specification, named by section.
 */
class VcBbs {
  /**
   * The cryptosuite's name, `bbs-2023`.
   */
  static readonly CRYPTOSUITE = CRYPTOSUITE;

  /**
   * Builds the cryptosuite from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: VcBbsDeps) {
    deps.log.debug("Entering VcBbs.constructor().");
    deps.log.debug("Leaving VcBbs.constructor().");
  }

  /**
   * Returns the dependencies built from the real modules.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): VcBbsDeps {
    helpers.log.debug("Entering VcBbs.defaultDeps().");
    helpers.log.debug("Leaving VcBbs.defaultDeps().");
    return {
      log: helpers.log,
      jsonld: vcJsonLd,
      sd: vcEcdsaSd,
      stsCrypto: stsCrypto,
      // Through the lazy door, at the call: `stsCrypto.bbs` loads the BBS
      // library and `jsonld` on first use (#348).
      bbs: {
        sign: function sign(input: any): Promise<Uint8Array> {
          helpers.log.debug("Entering sign().");
          helpers.log.debug("Leaving sign().");
          return stsCrypto.bbs.sign(input);
        },
        verifySignature: function verifySignature(input: any):
          Promise<boolean> {
          helpers.log.debug("Entering verifySignature().");
          helpers.log.debug("Leaving verifySignature().");
          return stsCrypto.bbs.verifySignature(input);
        },
        deriveProof: function deriveProof(input: any): Promise<Uint8Array> {
          helpers.log.debug("Entering deriveProof().");
          helpers.log.debug("Leaving deriveProof().");
          return stsCrypto.bbs.deriveProof(input);
        },
        verifyProof: function verifyProof(input: any): Promise<boolean> {
          helpers.log.debug("Entering verifyProof().");
          helpers.log.debug("Leaving verifyProof().");
          return stsCrypto.bbs.verifyProof(input);
        }
      },
      cborEncode: function cborEncode(value: unknown): Buffer {
        helpers.log.debug("Entering cborEncode().");
        helpers.log.debug("Leaving cborEncode().");
        return codec.cborEncode(value);
      },
      cborDecode: function cborDecode(bytes: Buffer): any {
        helpers.log.debug("Entering cborDecode().");
        helpers.log.debug("Leaving cborDecode().");
        return codec.cborDecode(bytes);
      }
    };
  }

  // ---------------------------------------------------------------------------
  // THE SHUFFLED LABEL MAP (section 3.3.1's labelMapFactoryFunction, Data
  // Integrity 1.1's createShuffledIdLabelMapFunction): each canonical label's
  // HMAC, then `b` and that digest's rank among all of them.
  // ---------------------------------------------------------------------------
  /**
   * Returns the label map factory that relabels each blank node `b<i>`, `i`
   * the rank of the HMAC of its canonical label.
   *
   * @param hmacKey - the HMAC key
   * @returns the factory
   */
  shuffledLabelMapFactory(hmacKey: Buffer): LabelMapFactory {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering VcBbs.shuffledLabelMapFactory().");
    const factory = function (canonicalIdMap: Map<string, string>):
      Map<string, string> {
      const digests = new Map<string, string>();
      canonicalIdMap.forEach(function (c14n, input) {
        digests.set(input, 'u' + stsCrypto.hmacSha256(hmacKey,
          Buffer.from(c14n, 'utf8')).toString('base64url'));
      });
      // A plain sort, as the specification's and Digital Bazaar's: the
      // strings are base64url, ASCII, so code units are code points.
      const ranked = Array.from(digests.values()).sort();
      const out = new Map<string, string>();
      digests.forEach(function (digest, input) {
        out.set(input, 'b' + ranked.indexOf(digest));
      });
      return out;
    };
    log.debug("Leaving VcBbs.shuffledLabelMapFactory().");
    return factory;
  }

  // The SHA-256 every hash here is (the BBS SHA-256 ciphersuite's).
  private sha256(data: string | Buffer): Buffer {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering VcBbs.sha256().");
    log.debug("Leaving VcBbs.sha256().");
    return stsCrypto.digest('sha256', data);
  }

  // Data Integrity 1.1's proof configuration and its hash: the proof
  // without its value, with the document's @context, canonicalized.
  private async proofHash(document: any, proof: any): Promise<Buffer> {
    const { log, jsonld } = this.deps;
    log.debug("Entering VcBbs.proofHash().");
    const config = Object.assign({}, proof);
    delete config.proofValue;
    config['@context'] = document['@context'];
    const canonical = await jsonld.canonize(config);
    log.debug("Leaving VcBbs.proofHash().");
    return this.sha256(canonical);
  }

  private multibaseU(value: unknown): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcBbs.multibaseU().");
    if (typeof value !== 'string' || value.charAt(0) !== 'u' ||
        !/^u[A-Za-z0-9_-]*$/.test(value)) {
      log.debug("Leaving VcBbs.multibaseU(). Not base64url.");
      throw new Error('PROOF_VERIFICATION_ERROR: a bbs-2023 proofValue is ' +
                      'multibase base64url-no-pad ("u").');
    }
    log.debug("Leaving VcBbs.multibaseU().");
    return Buffer.from(value.slice(1), 'base64url');
  }

  // The three-byte header a proof value starts with, checked against the one
  // expected; an optional feature's is named in the refusal.
  private headerOf(bytes: Buffer, expected: Buffer, what: string): void {
    const { log } = this.deps;
    log.debug("Entering VcBbs.headerOf().");
    if (bytes.length >= 3 && bytes.subarray(0, 3).equals(expected)) {
      log.debug("Leaving VcBbs.headerOf().");
      return;
    }
    const feature = bytes.length >= 3 && bytes[0] === 0xd9 &&
      bytes[1] === 0x5d ? FEATURES[bytes[2]] : undefined;
    log.debug("Leaving VcBbs.headerOf(). Not " + what + ".");
    throw new Error('PROOF_VERIFICATION_ERROR: not a bbs-2023 baseline ' +
      what + ' (header 0x' + expected.toString('hex') + ')' +
      (feature ? '; this is the "' + feature + '" feature option, which ' +
                 'the CRD marks at risk and this service does not ' +
                 'implement' : '') +
      (what === 'derived proof' && bytes.subarray(0, 3).equals(BASE_HEADER)
        ? '; this is a BASE proof, which is the holder\'s to derive from ' +
          'and never a verifier\'s to accept' : '') + '.');
  }

  // ---------------------------------------------------------------------------
  // 3.3.1-3.3.2 (with Data Integrity 1.1's TransformSD and HashSD): THE BASE
  // PROOF. `options`: secretKey and publicKey (the BBS pair, bytes),
  // verificationMethod, mandatoryPointers, proofPurpose, and optionally
  // created and hmacKey (32 bytes; random when absent — fixed only to
  // reproduce the specification's vectors). Answers the secured document.
  // ---------------------------------------------------------------------------
  /**
   * Creates the issuer's base proof (sections 3.3.1 and 3.3.2).
   *
   * @param unsecured - the unsecured credential
   * @param options - `secretKey`, `publicKey`, `verificationMethod`,
   *   `mandatoryPointers`, `proofPurpose`, and optionally `created` and
   *   `hmacKey`
   * @returns the secured document
   * @throws Error (PROOF_GENERATION_ERROR) when a mandatory pointer is not a
   *   JSON pointer or names nothing in the document
   */
  async createBaseProof(unsecured: any, options: any): Promise<any> {
    const { log, sd, bbs, cborEncode, stsCrypto } = this.deps;
    log.debug("Entering VcBbs.createBaseProof().");
    const o = options || {};
    const publicKey = Buffer.from(o.publicKey || []);
    if (publicKey.length !== 96 || !o.secretKey) {
      log.debug("Leaving VcBbs.createBaseProof(). No BBS pair.");
      throw new Error('PROOF_GENERATION_ERROR: bbs-2023 signs with a ' +
                      'BLS12-381 key pair (a 96-byte G2 public key).');
    }
    const mandatoryPointers: string[] = Array.isArray(o.mandatoryPointers)
      ? o.mandatoryPointers.map(String) : [];
    mandatoryPointers.forEach((p) => {
      sd.parsePointer(p);
    });
    const document = Object.assign({}, unsecured);
    delete document.proof;
    const proof: any = { type: PROOF_TYPE, cryptosuite: CRYPTOSUITE };
    if (o.created) {
      proof.created = o.created;
    }
    proof.verificationMethod = o.verificationMethod;
    proof.proofPurpose = o.proofPurpose || 'assertionMethod';
    const hmacKey = o.hmacKey ? Buffer.from(o.hmacKey)
                              : stsCrypto.randomBytes(32);
    const grouped = await sd.canonicalizeAndGroup(document,
      this.shuffledLabelMapFactory(hmacKey),
      { mandatory: mandatoryPointers });
    const mandatory = Array.from(grouped.groups.mandatory.matching.values()
                                ) as string[];
    const nonMandatory = Array.from(
      grouped.groups.mandatory.nonMatching.values()) as string[];
    const proofHash = await this.proofHash(document, proof);
    const mandatoryHash = this.sha256(mandatory.join(''));
    const bbsHeader = Buffer.concat([proofHash, mandatoryHash]);
    const bbsSignature = Buffer.from(await bbs.sign({
      secretKey: o.secretKey, publicKey: new Uint8Array(publicKey),
      header: new Uint8Array(bbsHeader),
      messages: nonMandatory.map(function (nq) {
        return new Uint8Array(Buffer.from(nq, 'utf8'));
      })
    }));
    const value = Buffer.concat([BASE_HEADER, cborEncode([bbsSignature,
      bbsHeader, publicKey, hmacKey, mandatoryPointers])]);
    proof.proofValue = 'u' + value.toString('base64url');
    log.debug("Leaving VcBbs.createBaseProof(). " + mandatory.length +
              " mandatory, " + nonMandatory.length + " signed message(s).");
    return Object.assign(document, { proof: proof });
  }

  // 3.2.2.
  /**
   * Parses a base proof value (section 3.2.2).
   *
   * @param proofValue - the multibase proof value
   * @returns `{ bbsSignature, bbsHeader, publicKey, hmacKey,
   *   mandatoryPointers, featureOption }`
   * @throws Error when it is not a baseline base proof value
   */
  parseBaseProofValue(proofValue: unknown): any {
    const { log, cborDecode } = this.deps;
    log.debug("Entering VcBbs.parseBaseProofValue().");
    const bytes = this.multibaseU(proofValue);
    this.headerOf(bytes, BASE_HEADER, 'base proof');
    const c = cborDecode(bytes.subarray(3));
    const ok = Array.isArray(c) && c.length === 5 &&
      Buffer.isBuffer(c[0]) && Buffer.isBuffer(c[1]) &&
      c[1].length === 64 && Buffer.isBuffer(c[2]) && c[2].length === 96 &&
      Buffer.isBuffer(c[3]) && c[3].length === 32 && Array.isArray(c[4]) &&
      c[4].every(function (p: any) { return typeof p === 'string'; });
    if (!ok) {
      log.debug("Leaving VcBbs.parseBaseProofValue(). Malformed.");
      throw new Error('PROOF_VERIFICATION_ERROR: a bbs-2023 base proof is ' +
        'a BBS signature, a 64-byte header, a 96-byte public key, a 32-byte ' +
        'HMAC key and an array of JSON pointers (section 3.2.1).');
    }
    log.debug("Leaving VcBbs.parseBaseProofValue().");
    return { bbsSignature: c[0], bbsHeader: c[1], publicKey: c[2],
             hmacKey: c[3], mandatoryPointers: c[4],
             featureOption: 'baseline' };
  }

  // ---------------------------------------------------------------------------
  // THE BASE PROOF CHECKED, which no section of the specification defines —
  // a verifier is never handed one — and which an ISSUER owes before it
  // hands a credential out (this service validates every crypto operation it
  // makes), and a holder may run before it derives. The statements are
  // regrouped from the document with the proof's own HMAC key and pointers,
  // the header rebuilt and compared, and the signature verified under
  // `publicKey`. Never throws.
  // ---------------------------------------------------------------------------
  /**
   * Checks a base proof against the document it secures and a public key.
   * Never throws.
   *
   * @param secured - the credential with its base proof
   * @param publicKey - the BBS public key (96 bytes)
   * @returns `{ ok, detail, headerMatches, keyMatches, mandatory,
   *   nonMandatory }`
   */
  async verifyBaseProof(secured: any, publicKey: Uint8Array): Promise<any> {
    const { log, sd, bbs } = this.deps;
    log.debug("Entering VcBbs.verifyBaseProof().");
    try {
      const proof = (secured && secured.proof) || {};
      if (proof.type !== PROOF_TYPE || proof.cryptosuite !== CRYPTOSUITE) {
        log.debug("Leaving VcBbs.verifyBaseProof(). Not bbs-2023.");
        return { ok: false, detail: 'the proof is not a bbs-2023 ' +
                 'DataIntegrityProof.' };
      }
      const base = this.parseBaseProofValue(proof.proofValue);
      const document = Object.assign({}, secured);
      delete document.proof;
      const grouped = await sd.canonicalizeAndGroup(document,
        this.shuffledLabelMapFactory(base.hmacKey),
        { mandatory: base.mandatoryPointers });
      const mandatory = Array.from(
        grouped.groups.mandatory.matching.values()) as string[];
      const nonMandatory = Array.from(
        grouped.groups.mandatory.nonMatching.values()) as string[];
      const header = Buffer.concat([await this.proofHash(document, proof),
                                    this.sha256(mandatory.join(''))]);
      const headerMatches = header.equals(base.bbsHeader);
      const keyMatches = Buffer.from(publicKey || []).equals(base.publicKey);
      const verified = headerMatches && keyMatches &&
        await bbs.verifySignature({
          publicKey: new Uint8Array(base.publicKey),
          signature: new Uint8Array(base.bbsSignature),
          header: new Uint8Array(header),
          messages: nonMandatory.map(function (nq) {
            return new Uint8Array(Buffer.from(nq, 'utf8'));
          })
        });
      log.debug("Leaving VcBbs.verifyBaseProof(). " + verified);
      return { ok: !!verified, headerMatches: headerMatches,
               keyMatches: keyMatches, mandatory: mandatory.length,
               nonMandatory: nonMandatory.length,
               detail: verified
                 ? 'the base signature verifies over ' + nonMandatory.length +
                   ' message(s) and ' + mandatory.length + ' mandatory ' +
                   'statement(s).'
                 : !headerMatches
                   ? 'the document does not hash to the header the proof ' +
                     'carries: it changed, or canonicalizes differently.'
                   : !keyMatches
                     ? 'the proof carries a different public key.'
                     : 'the BBS signature does not verify.' };
    } catch (e) {
      log.debug("Caught in VcBbs.verifyBaseProof(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcBbs.verifyBaseProof(). Refused.");
      return { ok: false, detail: String((e && e.message) || e) };
    }
  }

  // ---------------------------------------------------------------------------
  // 3.3.3 (with Data Integrity 1.1's CreateDisclosureData) and 3.2.3: A
  // DERIVED PROOF, revealing the mandatory statements and those
  // `selectivePointers` name, bound to `presentationHeader` (bytes; empty
  // when absent). Answers the reveal document carrying the derived proof.
  // ---------------------------------------------------------------------------
  /**
   * Derives a proof revealing the mandatory statements and those the
   * selective pointers name (sections 3.3.3 and 3.2.3).
   *
   * @param secured - the credential with its base proof
   * @param selectivePointers - the JSON pointers to reveal
   * @param options - `presentationHeader` (bytes)
   * @returns the reveal document with its derived proof
   * @throws Error when the credential carries no bbs-2023 base proof, or a
   *   pointer names nothing in it
   */
  async deriveProof(secured: any, selectivePointers: string[],
                    options?: any): Promise<any> {
    const { log, sd, jsonld, bbs, cborEncode } = this.deps;
    log.debug("Entering VcBbs.deriveProof().");
    const proof = secured && secured.proof;
    if (!proof || proof.cryptosuite !== CRYPTOSUITE) {
      log.debug("Leaving VcBbs.deriveProof(). No base proof.");
      throw new Error('PROOF_GENERATION_ERROR: the credential carries no ' +
                      'bbs-2023 proof.');
    }
    const o = options || {};
    const presentationHeader = Buffer.from(o.presentationHeader || []);
    const base = this.parseBaseProofValue(proof.proofValue);
    const document = Object.assign({}, secured);
    delete document.proof;
    const selective = (selectivePointers || []).map(String);
    const mandatoryPointers = base.mandatoryPointers as string[];
    const combinedPointers = mandatoryPointers.concat(selective);
    const grouped = await sd.canonicalizeAndGroup(document,
      this.shuffledLabelMapFactory(base.hmacKey), {
        mandatory: mandatoryPointers, selective: selective,
        combined: combinedPointers });
    const mandatoryMatch: Map<number, string> =
      grouped.groups.mandatory.matching;
    const nonMandatoryMatch: Map<number, string> =
      grouped.groups.mandatory.nonMatching;
    // The mandatory statements' positions among the revealed ones, and the
    // revealed messages' among the signed ones ("adjusted" indexes).
    const mandatoryIndexes: number[] = [];
    Array.from(grouped.groups.combined.matching.keys()).forEach(
      function (absolute: number, relative: number) {
        if (mandatoryMatch.has(absolute)) {
          mandatoryIndexes.push(relative);
        }
      });
    const nonMandatoryKeys = Array.from(nonMandatoryMatch.keys());
    const selectiveIndexes: number[] = [];
    Array.from(grouped.groups.selective.matching.keys()).forEach(
      function (absolute: number) {
        const at = nonMandatoryKeys.indexOf(absolute);
        if (at >= 0) {
          selectiveIndexes.push(at);
        }
      });
    const bbsProof = Buffer.from(await bbs.deriveProof({
      publicKey: new Uint8Array(base.publicKey),
      signature: new Uint8Array(base.bbsSignature),
      header: new Uint8Array(base.bbsHeader),
      messages: Array.from(nonMandatoryMatch.values()).map(function (nq) {
        return new Uint8Array(Buffer.from(nq, 'utf8'));
      }),
      presentationHeader: new Uint8Array(presentationHeader),
      disclosedMessageIndexes: selectiveIndexes
    }));
    const reveal = sd.selectJsonLd(document, combinedPointers);
    // The verifier's labels: the reveal document's canonical labels, each
    // mapped to the `b<i>` the signer used — compressed to integers.
    const canonicalIdMap = new Map<string, string>();
    await jsonld.canonizeNQuads(
      grouped.groups.combined.deskolemizedNQuads.join(''),
      { canonicalIdMap });
    const pairs: [number, number][] = [];
    canonicalIdMap.forEach(function (verifierLabel, inputLabel) {
      const input = inputLabel.indexOf('_:') === 0 ? inputLabel.slice(2)
                                                   : inputLabel;
      const verifier = verifierLabel.indexOf('_:') === 0
        ? verifierLabel.slice(2) : verifierLabel;
      const label = String(grouped.labelMap.get(input));
      pairs.push([parseInt(verifier.replace(/^c14n/, ''), 10),
                  parseInt(label.replace(/^b/, ''), 10)]);
    });
    pairs.sort(function (a, b) { return a[0] - b[0]; });
    const compressedLabelMap = new Map<number, number>(pairs);
    const value = Buffer.concat([DERIVED_HEADER, cborEncode([bbsProof,
      compressedLabelMap, mandatoryIndexes, selectiveIndexes,
      presentationHeader])]);
    const derivedProof = Object.assign({}, proof,
      { proofValue: 'u' + value.toString('base64url') });
    log.debug("Leaving VcBbs.deriveProof(). " + mandatoryIndexes.length +
              " mandatory, " + selectiveIndexes.length + " of " +
              nonMandatoryKeys.length + " message(s) revealed.");
    return Object.assign(reveal || {}, { proof: derivedProof });
  }

  // 3.2.4.
  /**
   * Parses a derived proof value (section 3.2.4).
   *
   * @param proofValue - the multibase proof value
   * @returns `{ bbsProof, labelMap, mandatoryIndexes, selectiveIndexes,
   *   presentationHeader, featureOption }`, the label map decompressed
   *   (`c14n<i>` to `b<j>`)
   * @throws Error when it is not a baseline derived proof value
   */
  parseDerivedProofValue(proofValue: unknown): any {
    const { log, cborDecode } = this.deps;
    log.debug("Entering VcBbs.parseDerivedProofValue().");
    const bytes = this.multibaseU(proofValue);
    this.headerOf(bytes, DERIVED_HEADER, 'derived proof');
    const c = cborDecode(bytes.subarray(3));
    const integers = function (a: any): boolean {
      return Array.isArray(a) && a.every(function (i: any) {
        return Number.isInteger(i) && i >= 0;
      });
    };
    const ok = Array.isArray(c) && c.length === 5 && Buffer.isBuffer(c[0]) &&
      c[1] instanceof Map && Array.from(c[1].entries()).every(
        function (e: any) {
          return Number.isInteger(e[0]) && e[0] >= 0 &&
            Number.isInteger(e[1]) && e[1] >= 0;
        }) &&
      integers(c[2]) && integers(c[3]) && Buffer.isBuffer(c[4]);
    if (!ok) {
      log.debug("Leaving VcBbs.parseDerivedProofValue(). Malformed.");
      throw new Error('PROOF_VERIFICATION_ERROR: a bbs-2023 derived proof ' +
        'is a BBS proof, a map of integers to integers, two arrays of ' +
        'integers and a presentation header (section 3.2.3).');
    }
    const labelMap = new Map<string, string>();
    (c[1] as Map<number, number>).forEach(function (v, k) {
      labelMap.set('c14n' + k, 'b' + v);
    });
    log.debug("Leaving VcBbs.parseDerivedProofValue().");
    return { bbsProof: c[0], labelMap: labelMap, mandatoryIndexes: c[2],
             selectiveIndexes: c[3], presentationHeader: c[4],
             featureOption: 'baseline' };
  }

  // ---------------------------------------------------------------------------
  // 3.3.4-3.3.5 (with Data Integrity 1.1's CreateVerifyData): VERIFY A
  // DERIVED PROOF. `publicKey` is the BBS key the proof's verification
  // method resolves to — the caller decides which keys it trusts. Answers
  // `{ ok, detail, presentationHeader, statements }`, the statements being
  // the reveal document's canonical N-Quads in the signer's labels, mandatory
  // and revealed alike: what was verified. Never throws.
  // ---------------------------------------------------------------------------
  /**
   * Verifies a derived proof (sections 3.3.4 and 3.3.5). Never throws.
   *
   * @param secured - the reveal document with its derived proof
   * @param publicKey - the issuer's BBS public key (96 bytes)
   * @returns `{ ok, detail, presentationHeader, statements }`
   */
  async verifyDerivedProof(secured: any, publicKey: Uint8Array):
    Promise<any> {
    const { log, sd, bbs } = this.deps;
    log.debug("Entering VcBbs.verifyDerivedProof().");
    try {
      const proof = (secured && secured.proof) || {};
      if (proof.type !== PROOF_TYPE || proof.cryptosuite !== CRYPTOSUITE) {
        log.debug("Leaving VcBbs.verifyDerivedProof(). Not bbs-2023.");
        return { ok: false, statements: [], presentationHeader: null,
                 detail: 'the proof is not a bbs-2023 DataIntegrityProof.' };
      }
      const document = Object.assign({}, secured);
      delete document.proof;
      const parsed = this.parseDerivedProofValue(proof.proofValue);
      const proofHash = await this.proofHash(document, proof);
      const canonical = await sd.labelReplacementCanonicalizeJsonLd(
        document, sd.labelMapFactory(parsed.labelMap));
      const mandatory: string[] = [];
      const nonMandatory: string[] = [];
      (canonical.nquads as string[]).forEach(function (nq, i) {
        if (parsed.mandatoryIndexes.indexOf(i) >= 0) {
          mandatory.push(nq);
        } else {
          nonMandatory.push(nq);
        }
      });
      if (Array.from(canonical.labelMap.values()).some(function (l) {
        return l === undefined;
      })) {
        log.debug("Leaving VcBbs.verifyDerivedProof(). Unmapped label.");
        return { ok: false, statements: [], presentationHeader: null,
                 detail: 'PROOF_VERIFICATION_ERROR: the label map does not ' +
                 'name every blank node of the reveal document.' };
      }
      if (parsed.selectiveIndexes.length !== nonMandatory.length) {
        log.debug("Leaving VcBbs.verifyDerivedProof(). Count.");
        return { ok: false, statements: [], presentationHeader: null,
                 detail: 'PROOF_VERIFICATION_ERROR: ' +
                 parsed.selectiveIndexes.length + ' selective index(es) ' +
                 'for ' + nonMandatory.length + ' non-mandatory ' +
                 'statement(s).' };
      }
      const header = Buffer.concat([proofHash,
                                    this.sha256(mandatory.join(''))]);
      const verified = await bbs.verifyProof({
        publicKey: new Uint8Array(publicKey),
        proof: new Uint8Array(parsed.bbsProof),
        header: new Uint8Array(header),
        presentationHeader: new Uint8Array(parsed.presentationHeader),
        disclosedMessages: nonMandatory.map(function (nq) {
          return new Uint8Array(Buffer.from(nq, 'utf8'));
        }),
        disclosedMessageIndexes: parsed.selectiveIndexes
      });
      log.debug("Leaving VcBbs.verifyDerivedProof(). " + verified);
      return { ok: !!verified,
               presentationHeader: parsed.presentationHeader,
               statements: verified ? canonical.nquads : [],
               detail: verified
                 ? 'the BBS proof verifies over ' + mandatory.length +
                   ' mandatory statement(s) and ' + nonMandatory.length +
                   ' revealed message(s).'
                 : 'the BBS proof does not verify: the reveal document, ' +
                   'the key, or the presentation header is not the one it ' +
                   'was derived for.' };
    } catch (e) {
      log.debug("Caught in VcBbs.verifyDerivedProof(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcBbs.verifyDerivedProof(). Refused.");
      return { ok: false, statements: [], presentationHeader: null,
               detail: String((e && e.message) || e) };
    }
  }
}

const slot = new InstanceSlot<VcBbs>(
  'oid4vc/vc_bbs',
  () => new VcBbs(VcBbs.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * bbs-2023, the W3C Data Integrity BBS cryptosuite.
 *
 * @namespace
 */
export = {
  VcBbs: VcBbs,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: VcBbs): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  CRYPTOSUITE: CRYPTOSUITE,
  shuffledLabelMapFactory: slot.forward('shuffledLabelMapFactory'),
  createBaseProof: slot.forward('createBaseProof'),
  parseBaseProofValue: slot.forward('parseBaseProofValue'),
  verifyBaseProof: slot.forward('verifyBaseProof'),
  deriveProof: slot.forward('deriveProof'),
  parseDerivedProofValue: slot.forward('parseDerivedProofValue'),
  verifyDerivedProof: slot.forward('verifyDerivedProof')
};
