// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_mdoc.ts
//
// ---------------------------------------------------------------------------
// AN ISO mdoc, VERIFIED (#935, 2026-11-02): the Verifier's fourth format,
// `mso_mdoc` (OpenID4VP 1.0 Appendix B.2, ISO/IEC 18013-5:2021 section 9),
// which OpenID4VC HAIP 1.0 names beside the SD-JWT VC and the OpenID
// Foundation's HAIP verifier plan certifies a Verifier for.
//
// A presentation is a base64url DeviceResponse (B.2.4) holding ONE Document of
// the document type the request asked for (`meta.doctype_value`). What is
// checked, in ISO/IEC 18013-5 section 9.3.1's order:
//
//   * THE ISSUER. `issuerAuth` is a COSE_Sign1 by the document signer (DS)
//     whose certificate travels in its `x5chain` header (33). The chain is
//     built and checked to one of `oid4vp.mdocTrustAnchors` — the Issuing
//     Authority CA certificates (IACA, Annex B) an operator trusts — by
//     `common/pki.js`'s `verifyPathToAnchors()`, RFC 5280 section 6 and
//     nothing looser; this realm issues no mdoc, so there is no "our own"
//     case and an empty setting trusts nobody. Then the signature, by the
//     DS key, in an algorithm `issuerauth_alg_values` offers.
//   * THE MOBILE SECURITY OBJECT, the payload: `#6.24(bstr .cbor MSO)`, its
//     `docType` the Document's and the request's, its `validityInfo`
//     covering now and its `signed` inside the DS certificate's validity
//     (9.3.1 step 4), and a digest algorithm of SHA-256, -384 or -512.
//   * EVERY DISCLOSED ELEMENT. Each IssuerSignedItemBytes is digested AS IT
//     WAS RECEIVED — `vc_status_codec.ts` keeps a decoded tag's bytes for
//     exactly this — and must equal the MSO's `valueDigests` entry under its
//     namespace and `digestID`; an element the issuer never signed is the
//     forgery this catches (`STS-VC-0158`).
//   * THE HOLDER. `deviceAuth.deviceSignature`, a COSE_Sign1 with a detached
//     payload, by the MSO's `deviceKey` over DeviceAuthenticationBytes —
//     `["DeviceAuthentication", SessionTranscript, DocType,
//     DeviceNameSpacesBytes]` tagged 24. The SessionTranscript is the one
//     B.2.6.1 defines for a redirect: `[null, null, ["OpenID4VPHandover",
//     SHA-256(CBOR([client_id, nonce, jwkThumbprint, response_uri]))]]`,
//     built HERE from this request, so a presentation made for another
//     Verifier, another nonce, another response URI or another encryption
//     key does not verify (`STS-VC-0160`). The thumbprint is RFC 7638's of
//     the key the response was ENCRYPTED to, as raw bytes, and null for a
//     plaintext `direct_post`. `deviceMac` is refused (`STS-VC-0159`): its
//     key is agreed with a reader's ephemeral key, and an OpenID4VP request
//     carries none.
//   * DEVICE-SIGNED ELEMENTS, which a wallet may add, are accepted only where
//     the MSO's `keyAuthorizations` authorizes them (9.1.2.4).
//   * THE STATUS, where the MSO names one (`status.status_list`, draft-ietf-
//     oauth-status-list section 6.3): the Verifier asks `vc_status.ts`,
//     which fetches the CWT and has `statusListKey()` below find its signer
//     — a certificate in its `x5chain` that chains to the same anchors.
//
// Every check is a row of the verdict, as `vc_verifier.ts`'s are, so a wallet
// developer is told WHICH rule an mdoc broke.
//
// **POST-QUANTUM.** The signatures go through `common/crypto.js`'s
// `verifyCoseSignature()`, whose table carries ML-DSA-44/65/87 (RFC 9964)
// beside ECDSA (raw r||s here, RFC 9053 section 2.1) and EdDSA, and RFC
// 9864's fully specified ESP256/384/512 and Ed25519/Ed448. While
// `keys.postQuantumSigning` is off, or the wallet compatibility mode
// (`oid4vc.walletCompatibility`, #657) is on, the ML-DSA identifiers are
// neither offered nor accepted.
//
// A LIBRARY (rule 3): it registers no route. It requires `common/` leaves,
// the codec, and `authn/webauthn.js` for its COSE_Key reader (a library
// that registers nothing either); `common/pki.js` is reached lazily.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import codec = require('./vc_status_codec');
import algorithmRegistry = require('../common/crypto_impl/algorithm_registry');
import webauthn = require('../authn/webauthn');
// The wallet compatibility mode (#657), which turns the post-quantum
// algorithms off inside OpenID4VCI and OpenID4VP; a static utility class.
import VcAlgorithms = require('./vc_algorithms');

const { Tagged } = codec;

// The COSE signature algorithms an mdoc's issuer and device may sign with
// (IANA "COSE Algorithms"): ECDSA (RFC 9053, and RFC 9864's fully specified
// forms), EdDSA (RFC 9053, RFC 9864) and ML-DSA (RFC 9964), strongest
// classical first within each family.
const COSE_SIGNATURE_IDS: number[] = algorithmRegistry.coseIds('cose.mdoc');
// The post-quantum ones, offered only while `keys.postQuantumSigning` is on.
const PQ_IDS: number[] = COSE_SIGNATURE_IDS.filter(function (id: number) {
  return algorithmRegistry.bySpelling('cose', id).pqc !== null;
});
// ISO/IEC 18013-5 section 9.1.2.5: the MSO's digest algorithms.
const DIGEST_ALGS: Record<string, string> = {
  'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512'
};
// The COSE header carrying the certificate chain (RFC 9360).
const X5CHAIN = 33;
// CBOR tags: a tdate (RFC 8949 section 3.4.1) and encoded CBOR (3.4.5.1).
const TAG_TDATE = 0;
const TAG_ENCODED_CBOR = 24;
const TAG_COSE_SIGN1 = 18;

interface VcMdocDeps {
  log: typeof helpers.log;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  codec: typeof codec;
  coseKeyToJwk: (coseKey: unknown) => any;
  pki: () => any;
  walletCompatibility: () => boolean;
}

/**
 * What one verification is checked against: the request's own values.
 */
interface MdocContext {
  /** The Client Identifier the request carried, prefix and all. */
  clientId: string;
  /** The request's nonce. */
  nonce: string;
  /** The Response URI the wallet posted to. */
  responseUri: string;
  /** RFC 7638's SHA-256 of the encryption key, as bytes; null in clear. */
  jwkThumbprint: Buffer | null;
  /** The document type asked for. */
  doctype: string;
  /** The namespace the requested elements are in. */
  namespace: string;
  /** The requested data elements of that namespace. */
  elements: string[];
  /** `oid4vp.mdocTrustAnchors` as it stood. */
  anchorsPem: string;
  /** Now, in milliseconds; the clock by default. */
  now?: number;
}

/**
 * Verifies an ISO/IEC 18013-5 mdoc presented through OpenID4VP 1.0
 * (Appendix B.2): the issuer's chain and signature, the Mobile Security
 * Object, every disclosed element's digest and the device signature over
 * the request's session transcript.
 */
class VcMdoc {
  /**
   * The COSE signature algorithm identifiers this Verifier accepts.
   */
  static readonly COSE_SIGNATURE_IDS = COSE_SIGNATURE_IDS;

  /**
   * Builds the verifier from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: VcMdocDeps) {
    deps.log.debug("Entering VcMdoc.constructor().");
    deps.log.debug("Leaving VcMdoc.constructor().");
  }

  /**
   * Returns the dependencies built from the real modules.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): VcMdocDeps {
    helpers.log.debug("Entering VcMdoc.defaultDeps().");
    helpers.log.debug("Leaving VcMdoc.defaultDeps().");
    return {
      log: helpers.log, stsCrypto: stsCrypto, errorCodes: errorCodes,
      codec: codec, coseKeyToJwk: webauthn.coseKeyToJwk,
      // Lazily, as `vc_verifier.ts` reaches it: the certificate authority
      // is a large module every family has loaded by the time an mdoc is
      // presented.
      pki: function () {
        return require('../common/pki');
      },
      walletCompatibility: function () {
        return VcAlgorithms.walletCompatibility();
      }
    };
  }

  /**
   * Returns the COSE algorithms offered and accepted now: every one, less
   * ML-DSA while `keys.postQuantumSigning` is off or the wallet
   * compatibility mode (`oid4vc.walletCompatibility`, #657) is on.
   *
   * @returns the COSE algorithm identifiers
   */
  coseAlgs(): number[] {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering VcMdoc.coseAlgs().");
    const on = stsCrypto.postQuantumSigningOn() &&
               !this.deps.walletCompatibility();
    log.debug("Leaving VcMdoc.coseAlgs(). PQ " + on);
    return COSE_SIGNATURE_IDS.filter(function (id) {
      return on || PQ_IDS.indexOf(id) < 0;
    });
  }

  /**
   * Returns the `mso_mdoc` member of `vp_formats_supported` (OpenID4VP 1.0
   * Appendix B.2.2).
   *
   * @returns `{ issuerauth_alg_values, deviceauth_alg_values }`
   */
  vpFormat(): any {
    const { log } = this.deps;
    log.debug("Entering VcMdoc.vpFormat().");
    const algs = this.coseAlgs();
    log.debug("Leaving VcMdoc.vpFormat().");
    return { issuerauth_alg_values: algs.slice(),
             deviceauth_alg_values: algs.slice() };
  }

  /**
   * Returns the SessionTranscript of an OpenID4VP redirect (Appendix
   * B.2.6.1), as the CBOR structure.
   *
   * @param clientId - the request's Client Identifier
   * @param nonce - its nonce
   * @param jwkThumbprint - the encryption key's RFC 7638 thumbprint as
   *   bytes, or null
   * @param responseUri - its Response URI
   * @returns `[null, null, ["OpenID4VPHandover", hash]]`
   */
  sessionTranscript(clientId: string, nonce: string,
                    jwkThumbprint: Buffer | null, responseUri: string): any {
    const { log, codec, stsCrypto } = this.deps;
    log.debug("Entering VcMdoc.sessionTranscript().");
    const info = codec.cborEncode([String(clientId), String(nonce),
                                   jwkThumbprint ? Buffer.from(jwkThumbprint)
                                                 : null,
                                   String(responseUri)]);
    const hash = stsCrypto.digest('sha256', info);
    log.debug("Leaving VcMdoc.sessionTranscript().");
    return [null, null, ['OpenID4VPHandover', hash]];
  }

  /**
   * Returns the raw RFC 7638 thumbprint of a public JWK, the form the
   * SessionTranscript takes.
   *
   * @param jwk - the key
   * @returns the 32 bytes
   */
  thumbprintBytes(jwk: any): Buffer {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering VcMdoc.thumbprintBytes().");
    log.debug("Leaving VcMdoc.thumbprintBytes().");
    return Buffer.from(stsCrypto.jwkThumbprint(jwk), 'base64url');
  }

  // One row of the verdict, in `vc_verifier.ts`'s shape.
  private check(checks: any[], name: string, ok: unknown,
                detail: string): boolean {
    const { log } = this.deps;
    log.debug("Entering VcMdoc.check(). " + name + " " + !!ok);
    checks.push({ name: name, ok: !!ok, detail: detail });
    log.debug("Leaving VcMdoc.check().");
    return !!ok;
  }

  // A COSE_Sign1, tagged (18) or not — ISO/IEC 18013-5 sends it untagged —
  // read into its parts. The algorithm must be protected (RFC 9052 section
  // 3.1). Throws on anything else.
  private coseParts(item: unknown): any {
    const { log, codec } = this.deps;
    log.debug("Entering VcMdoc.coseParts().");
    const body = item instanceof Tagged && item.tag === TAG_COSE_SIGN1
      ? item.value : item;
    if (!Array.isArray(body) || body.length !== 4) {
      log.debug("Leaving VcMdoc.coseParts(). Not a COSE_Sign1.");
      throw new Error('not a COSE_Sign1 (an array of four)');
    }
    const [protectedBytes, unprotectedHeader, payload, signature] = body;
    if (!Buffer.isBuffer(protectedBytes) || !Buffer.isBuffer(signature) ||
        !(unprotectedHeader instanceof Map) ||
        !(payload === null || Buffer.isBuffer(payload))) {
      log.debug("Leaving VcMdoc.coseParts(). Malformed members.");
      throw new Error('a COSE_Sign1 is [bstr, map, bstr / nil, bstr]');
    }
    const protectedHeader = protectedBytes.length
      ? codec.cborDecode(protectedBytes) : new Map();
    if (!(protectedHeader instanceof Map)) {
      log.debug("Leaving VcMdoc.coseParts(). Bad protected header.");
      throw new Error('its protected header is not a map');
    }
    if (unprotectedHeader.has(1) || !protectedHeader.has(1)) {
      log.debug("Leaving VcMdoc.coseParts(). Algorithm not protected.");
      throw new Error('its algorithm (1) must be in the protected header');
    }
    log.debug("Leaving VcMdoc.coseParts().");
    return { protectedBytes: protectedBytes,
             protectedHeader: protectedHeader,
             unprotectedHeader: unprotectedHeader,
             payload: payload, signature: signature,
             alg: protectedHeader.get(1) };
  }

  // Does a COSE_Sign1 verify over `payload` (its own, or the detached one)
  // under `key`, in one of the algorithms offered now?
  private coseVerifies(parts: any, payload: Buffer, key: any): string {
    const { log, codec, stsCrypto } = this.deps;
    log.debug("Entering VcMdoc.coseVerifies(). alg=" + parts.alg);
    if (this.coseAlgs().indexOf(Number(parts.alg)) < 0) {
      log.debug("Leaving VcMdoc.coseVerifies(). Algorithm not accepted.");
      return 'it is signed with COSE algorithm ' + parts.alg + ', and this ' +
             'Verifier accepts ' + this.coseAlgs().join(', ');
    }
    const toBeSigned = codec.cborEncode(['Signature1', parts.protectedBytes,
                                         Buffer.alloc(0), payload]);
    const ok = stsCrypto.verifyCoseSignature(Number(parts.alg), key,
      toBeSigned, parts.signature, { ecdsaEncoding: 'ieee-p1363' });
    log.debug("Leaving VcMdoc.coseVerifies(). " + ok);
    return ok ? '' : 'the COSE algorithm ' + parts.alg + ' signature does ' +
                     'not verify';
  }

  // The certificates of an `x5chain` header (RFC 9360 section 2): one bstr,
  // or an array of them, leaf first. Protected or unprotected.
  private x5chainOf(parts: any): Buffer[] {
    const { log } = this.deps;
    log.debug("Entering VcMdoc.x5chainOf().");
    const value = parts.protectedHeader.has(X5CHAIN)
      ? parts.protectedHeader.get(X5CHAIN)
      : parts.unprotectedHeader.get(X5CHAIN);
    const list = Buffer.isBuffer(value) ? [value]
      : (Array.isArray(value) ? value : []);
    log.debug("Leaving VcMdoc.x5chainOf(). " + list.length);
    return list.every(function (one: unknown) {
      return Buffer.isBuffer(one);
    }) ? list : [];
  }

  /**
   * Checks a certificate chain from a COSE header against
   * `oid4vp.mdocTrustAnchors`.
   *
   * @param chain - the `x5chain` certificates, leaf first, as DER
   * @param anchorsPem - the anchors, PEM
   * @param now - milliseconds
   * @returns `{ ok, leaf, anchorPem, reason }`; `leaf` is the leaf as
   *   `certificateFromDer()` makes it
   */
  async chainToAnchors(chain: Buffer[], anchorsPem: string,
                       now: number): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcMdoc.chainToAnchors(). " + chain.length);
    const pki = this.deps.pki();
    if (!chain.length) {
      log.debug("Leaving VcMdoc.chainToAnchors(). No x5chain.");
      return { ok: false, reason: 'it carries no x5chain (33) naming its ' +
               'signer\'s certificate' };
    }
    const anchors = pki.certificateBundle(String(anchorsPem || ''))
      .certificates;
    if (!anchors.length) {
      log.debug("Leaving VcMdoc.chainToAnchors(). No anchors.");
      return { ok: false, reason: 'oid4vp.mdocTrustAnchors names no ' +
               'certificate, so no mdoc issuer is trusted' };
    }
    const path = await pki.verifyPathToAnchors(chain[0], chain.slice(1),
                                               anchors, { now: now });
    if (!path.ok) {
      log.debug("Leaving VcMdoc.chainToAnchors(). " + path.reason);
      return { ok: false, reason: 'its signer\'s certificate does not ' +
               'chain to oid4vp.mdocTrustAnchors: ' + path.reason };
    }
    log.debug("Leaving VcMdoc.chainToAnchors(). Chained.");
    return { ok: true, leaf: path.chain[0],
             anchorPem: path.chain[path.chain.length - 1].pem, reason: '' };
  }

  // A tdate (#6.0 tstr) as milliseconds, or NaN.
  private tdate(value: unknown): number {
    const { log } = this.deps;
    log.debug("Entering VcMdoc.tdate().");
    log.debug("Leaving VcMdoc.tdate().");
    return value instanceof Tagged && value.tag === TAG_TDATE &&
           typeof value.value === 'string' ? Date.parse(value.value) : NaN;
  }

  // An element value as JSON can carry it: a map an object, bytes base64url,
  // a tagged date its text.
  // Recursive and called per element, so no Entering/Leaving pair — the
  // hot-path exception the code style allows, stated as it requires.
  private plain(value: unknown): any {
    if (Buffer.isBuffer(value)) {
      return value.toString('base64url');
    }
    if (value instanceof Tagged) {
      return this.plain(value.value);
    }
    if (value instanceof Map) {
      const out: Record<string, unknown> = {};
      value.forEach((v, k) => {
        out[String(k)] = this.plain(v);
      });
      return out;
    }
    if (Array.isArray(value)) {
      return value.map((one) => {
        return this.plain(one);
      });
    }
    return value;
  }

  // `#6.24(bstr)` decoded, or a throw naming `what`.
  private embedded(item: unknown, what: string): any {
    const { log, codec } = this.deps;
    log.debug("Entering VcMdoc.embedded(). " + what);
    if (!(item instanceof Tagged) || item.tag !== TAG_ENCODED_CBOR ||
        !Buffer.isBuffer(item.value)) {
      log.debug("Leaving VcMdoc.embedded(). Not tag 24.");
      throw new Error(what + ' is not encoded CBOR (#6.24 bstr)');
    }
    log.debug("Leaving VcMdoc.embedded().");
    return codec.cborDecode(item.value);
  }

  /**
   * Verifies one mdoc presentation: a base64url DeviceResponse.
   *
   * @param token - the presentation from the `vp_token`
   * @param ctx - the request's values (see `MdocContext`)
   * @returns `{ ok, checks, claims, disclosed, extraDisclosed, doctype,
   *   issuerCertificatePem, anchorCertificatePem, statusReference }`
   */
  async verify(token: unknown, ctx: MdocContext): Promise<any> {
    const { log, codec, errorCodes } = this.deps;
    log.debug("Entering VcMdoc.verify().");
    const checks: any[] = [];
    const result: any = {
      ok: false, checks: checks, claims: {}, disclosed: [],
      extraDisclosed: [], vct: '', sub: '', doctype: '',
      credentialClaims: {}, statusReference: null
    };
    const now = ctx.now === undefined ? Date.now() : ctx.now;
    const done = (why: string): any => {
      log.debug("Leaving VcMdoc.verify(). " + why);
      result.ok = checks.every(function (c) {
        return c.ok;
      });
      return result;
    };
    // --- the DeviceResponse ------------------------------------------------
    let response: any = null;
    let document: any = null;
    try {
      const text = String(token || '');
      if (!/^[A-Za-z0-9_-]+$/.test(text)) {
        throw new Error('it is not base64url (OpenID4VP Appendix B.2.4)');
      }
      response = codec.cborDecode(Buffer.from(text, 'base64url'));
      if (!(response instanceof Map)) {
        throw new Error('the DeviceResponse is not a map');
      }
      const documents = response.get('documents');
      if (!Array.isArray(documents) || documents.length !== 1 ||
          !(documents[0] instanceof Map)) {
        throw new Error('the DeviceResponse carries ' +
                        (Array.isArray(documents) ? documents.length : 'no') +
                        ' Document(s); one is presented per credential ' +
                        'query');
      }
      if (response.get('status') !== 0) {
        throw new Error('its status is ' + response.get('status') +
                        ', not 0 (OK)');
      }
      document = documents[0];
    } catch (e) {
      log.debug("Caught in VcMdoc.verify(): " + ((e && e.message) || e));
      log.error(errorCodes.tag('STS-VC-0156') + 'oid4vp: an mso_mdoc ' +
                'presentation could not be read: ' + e.message);
      this.check(checks, 'Format', false, 'an mso_mdoc presentation is a ' +
                 'base64url DeviceResponse holding one Document; ' +
                 String((e && e.message) || e).replace(/\.+$/, '') + '.');
      return done('Unreadable.');
    }
    const docType = String(document.get('docType') || '');
    result.doctype = docType;
    this.check(checks, 'Format', true, 'a DeviceResponse (version ' +
               response.get('version') + ') holding one Document.');
    this.check(checks, 'Document type (docType)', docType === ctx.doctype,
               'docType is "' + docType + '"; this Verifier asked for "' +
               ctx.doctype + '" (oid4vp.expectedDoctype).');

    // --- the issuer: chain and signature -------------------------------------
    const issuerSigned = document.get('issuerSigned');
    let issuerAuth: any = null;
    try {
      if (!(issuerSigned instanceof Map)) {
        throw new Error('the Document has no issuerSigned map');
      }
      issuerAuth = this.coseParts(issuerSigned.get('issuerAuth'));
      if (!issuerAuth.payload) {
        throw new Error('issuerAuth carries no payload');
      }
    } catch (e) {
      log.debug("Caught in VcMdoc.verify(): " + ((e && e.message) || e));
      log.error(errorCodes.tag('STS-VC-0156') + 'oid4vp: an mdoc\'s ' +
                'issuerAuth could not be read: ' + e.message);
      this.check(checks, 'Issuer signature', false, 'issuerAuth cannot be ' +
                 'read: ' +
                 String((e && e.message) || e).replace(/\.+$/, '') + '.');
      return done('No issuerAuth.');
    }
    const chained = await this.chainToAnchors(this.x5chainOf(issuerAuth),
                                              ctx.anchorsPem, now);
    if (!chained.ok) {
      log.error(errorCodes.tag('STS-VC-0157') + 'oid4vp: an mdoc was ' +
                'refused: ' + chained.reason);
    }
    this.check(checks, 'Issuer certificate chain', chained.ok,
               chained.ok ? 'the document signer "' +
                 String(chained.leaf.x509.subject).replace(/\n/g, ', ') +
                 '" chains to a certificate in oid4vp.mdocTrustAnchors.'
                 : chained.reason + '.');
    if (!chained.ok) {
      return done('Untrusted.');
    }
    result.issuerCertificatePem = chained.leaf.pem;
    result.anchorCertificatePem = chained.anchorPem;
    result.issuerCertificateSource = 'an mdoc document signer certificate ' +
      'chaining to oid4vp.mdocTrustAnchors';
    const issuerProblem = this.coseVerifies(issuerAuth, issuerAuth.payload,
                                            chained.leaf.x509.publicKey);
    this.check(checks, 'Issuer signature', !issuerProblem,
               issuerProblem ? issuerProblem + '.'
                 : 'issuerAuth verifies against the document signer\'s key ' +
                   '(COSE algorithm ' + issuerAuth.alg + ').');
    if (issuerProblem) {
      return done('Issuer signature.');
    }

    // --- the Mobile Security Object -----------------------------------------
    let mso: any = null;
    try {
      mso = this.embedded(codec.cborDecode(issuerAuth.payload),
                          'the Mobile Security Object');
      if (!(mso instanceof Map)) {
        throw new Error('the Mobile Security Object is not a map');
      }
    } catch (e) {
      log.debug("Caught in VcMdoc.verify(): " + ((e && e.message) || e));
      log.error(errorCodes.tag('STS-VC-0156') + 'oid4vp: an mdoc\'s MSO ' +
                'could not be read: ' + e.message);
      this.check(checks, 'Mobile Security Object', false,
                 String((e && e.message) || e).replace(/\.+$/, '') + '.');
      return done('No MSO.');
    }
    const digestAlg = DIGEST_ALGS[String(mso.get('digestAlgorithm'))];
    this.check(checks, 'Mobile Security Object',
               mso.get('docType') === docType && !!digestAlg,
               'docType "' + mso.get('docType') + '" (the Document\'s is "' +
               docType + '"), digest algorithm ' +
               mso.get('digestAlgorithm') + (digestAlg ? '.'
                 : ', which is not SHA-256, SHA-384 or SHA-512.'));
    const validity = mso.get('validityInfo');
    const signed = this.tdate(validity instanceof Map ? validity.get('signed')
                                                      : undefined);
    const from = this.tdate(validity instanceof Map
                              ? validity.get('validFrom') : undefined);
    const until = this.tdate(validity instanceof Map
                               ? validity.get('validUntil') : undefined);
    const leafFrom = Date.parse(String(chained.leaf.x509.validFrom));
    const leafTo = Date.parse(String(chained.leaf.x509.validTo));
    this.check(checks, 'Validity window',
               from <= now && now < until && signed >= leafFrom &&
                 signed <= leafTo,
               'validFrom ' + new Date(from).toISOString() + ', validUntil ' +
               new Date(until).toISOString() + ', signed ' +
               new Date(signed).toISOString() + ' (the document signer\'s ' +
               'certificate is valid from ' + chained.leaf.x509.validFrom +
               ' to ' + chained.leaf.x509.validTo + '), now ' +
               new Date(now).toISOString() + '.');

    // --- every disclosed element ---------------------------------------------
    const digests = mso.get('valueDigests');
    const namespaces = issuerSigned.get('nameSpaces');
    let unmatched = 0;
    let presented = 0;
    const claims: Record<string, any> = {};
    if (namespaces !== undefined && !(namespaces instanceof Map)) {
      unmatched++;
    }
    (namespaces instanceof Map ? namespaces : new Map())
      .forEach((items: any, ns: any) => {
        const signedHere = digests instanceof Map ? digests.get(ns) : null;
        [].concat(Array.isArray(items) ? items : []).forEach((item: any) => {
          presented++;
          try {
            const element = this.embedded(item, 'an IssuerSignedItem');
            const id = element.get('digestID');
            const expected = signedHere instanceof Map
              ? signedHere.get(id) : undefined;
            const actual = digestAlg
              ? this.deps.stsCrypto.digest(digestAlg, item.raw) : null;
            if (!Buffer.isBuffer(expected) || !actual ||
                !actual.equals(expected)) {
              throw new Error('the item ' + ns + '/' +
                              element.get('elementIdentifier') + ' (digestID ' +
                              id + ') does not hash to a digest the issuer ' +
                              'signed');
            }
            const name = String(element.get('elementIdentifier'));
            claims[ns] = claims[ns] || {};
            claims[ns][name] = this.plain(element.get('elementValue'));
          } catch (e) {
            log.debug("Caught in VcMdoc.verify(): " +
                      ((e && e.message) || e));
            unmatched++;
            log.error(errorCodes.tag('STS-VC-0158') + 'oid4vp: ' + e.message);
          }
        });
        if (!Array.isArray(items)) {
          unmatched++;
        }
      });
    this.check(checks, 'Element digests', unmatched === 0,
               unmatched === 0
                 ? 'all ' + presented + ' disclosed element(s) hash to a ' +
                   'digest in the Mobile Security Object.'
                 : unmatched + ' disclosed element(s) were not signed by ' +
                   'the issuer.');

    // --- the holder: the device signature over this request ---------------
    const deviceSigned = document.get('deviceSigned');
    let deviceProblem = '';
    let deviceNames: any = new Map();
    try {
      if (!(deviceSigned instanceof Map)) {
        throw new Error('the Document has no deviceSigned map');
      }
      const deviceNamespacesBytes = deviceSigned.get('nameSpaces');
      deviceNames = this.embedded(deviceNamespacesBytes,
                                  'DeviceNameSpacesBytes');
      if (!(deviceNames instanceof Map)) {
        throw new Error('DeviceNameSpaces is not a map');
      }
      const deviceAuth = deviceSigned.get('deviceAuth');
      if (!(deviceAuth instanceof Map)) {
        throw new Error('the Document has no deviceAuth map');
      }
      if (deviceAuth.has('deviceMac')) {
        log.error(errorCodes.tag('STS-VC-0159') + 'oid4vp: an mdoc ' +
                  'authenticated its device by MAC, which an OpenID4VP ' +
                  'request gives it no reader key for.');
        throw new Error('deviceAuth is a deviceMac, whose key is agreed ' +
                        'with a reader\'s ephemeral key that an OpenID4VP ' +
                        'request does not carry; a deviceSignature is ' +
                        'required');
      }
      const deviceSignature = this.coseParts(deviceAuth.get('deviceSignature'));
      if (deviceSignature.payload !== null &&
          deviceSignature.payload.length !== 0) {
        throw new Error('the deviceSignature carries its payload; ISO/IEC ' +
                        '18013-5 section 9.1.3.6 detaches it');
      }
      const keyInfo = mso.get('deviceKeyInfo');
      const deviceKey = this.deps.coseKeyToJwk(
        keyInfo instanceof Map ? keyInfo.get('deviceKey') : undefined).jwk;
      const transcript = this.sessionTranscript(ctx.clientId, ctx.nonce,
                                                ctx.jwkThumbprint,
                                                ctx.responseUri);
      const authentication = codec.cborEncode(new Tagged(TAG_ENCODED_CBOR,
        codec.cborEncode(['DeviceAuthentication', transcript, docType,
                          deviceNamespacesBytes])));
      deviceProblem = this.coseVerifies(deviceSignature, authentication,
                                        deviceKey);
      if (deviceProblem) {
        log.error(errorCodes.tag('STS-VC-0160') + 'oid4vp: an mdoc\'s ' +
                  'device signature was refused: ' + deviceProblem);
        deviceProblem += ' over this request\'s session transcript (its ' +
          'client_id, nonce, response URI and encryption key) under the ' +
          'Mobile Security Object\'s device key';
      }
      // Device-signed elements, only as the issuer authorized them.
      const authorized = keyInfo instanceof Map &&
        keyInfo.get('keyAuthorizations') instanceof Map
        ? keyInfo.get('keyAuthorizations') : new Map();
      const wholeNamespaces = [].concat(authorized.get('nameSpaces') || []);
      const elementsByNs = authorized.get('dataElements') instanceof Map
        ? authorized.get('dataElements') : new Map();
      deviceNames.forEach((items: any, ns: any) => {
        (items instanceof Map ? items : new Map()).forEach(
          (value: any, name: any) => {
            const allowed = wholeNamespaces.indexOf(ns) >= 0 ||
              [].concat(elementsByNs.get(ns) || []).indexOf(name) >= 0;
            if (!allowed) {
              throw new Error('the device signed ' + ns + '/' + name +
                              ', which the issuer\'s keyAuthorizations do ' +
                              'not authorize');
            }
            claims[ns] = claims[ns] || {};
            claims[ns][String(name)] = this.plain(value);
          });
      });
    } catch (e) {
      log.debug("Caught in VcMdoc.verify(): " + ((e && e.message) || e));
      deviceProblem = e.message;
    }
    this.check(checks, 'Device signature', !deviceProblem,
               deviceProblem ? deviceProblem + '.'
                 : 'verifies against the device key in the Mobile Security ' +
                   'Object, over this request\'s session transcript.');

    // --- the claims, and did we get what we asked for? ----------------------
    const mine = claims[ctx.namespace] || {};
    Object.keys(claims).forEach(function (ns) {
      Object.keys(claims[ns]).forEach(function (name) {
        const key = ns === ctx.namespace ? name : ns + '/' + name;
        result.claims[key] = claims[ns][name];
        result.disclosed.push(key);
      });
    });
    result.namespaces = claims;
    const missing = ctx.elements.filter(function (name) {
      return !(name in mine);
    });
    this.check(checks, 'Requested claims', missing.length === 0,
               missing.length === 0
                 ? (ctx.elements.length
                     ? 'every element the DCQL query asked for is present (' +
                       ctx.elements.join(', ') + ' in ' + ctx.namespace + ').'
                     : 'this request named no elements, so there was ' +
                       'nothing to be missing.')
                 : 'missing from ' + ctx.namespace + ': ' +
                   missing.join(', ') + '.');
    result.extraDisclosed = ctx.elements.length
      ? result.disclosed.filter(function (name: string) {
        return ctx.elements.indexOf(name) < 0;
      }) : [];

    // --- the status reference, for the caller's status check ----------------
    try {
      result.statusReference = codec.referenceOfCose(mso.get('status'));
    } catch (e) {
      log.debug("Caught in VcMdoc.verify(): " + ((e && e.message) || e));
      this.check(checks, 'Credential status', false, 'the Mobile Security ' +
                 'Object\'s status is malformed: ' +
                 String((e && e.message) || e).replace(/\.+$/, '') + '.');
    }
    return done('Checked.');
  }

  /**
   * Finds the key a Status List Token in CWT form, referenced by an mdoc,
   * is verified with: the leaf of its `x5chain`, which must chain to
   * `oid4vp.mdocTrustAnchors` as the document signer does (ISO/IEC 18013-5
   * section 12.3.6.2).
   *
   * @param cwt - the token's bytes
   * @param anchorsPem - the anchors, PEM
   * @returns the leaf's public key
   * @throws Error when it carries no chain or the chain is not trusted
   */
  async statusListKey(cwt: Buffer, anchorsPem: string): Promise<any> {
    const { log, codec } = this.deps;
    log.debug("Entering VcMdoc.statusListKey().");
    const parts = this.coseParts(codec.cborDecode(cwt));
    const chained = await this.chainToAnchors(this.x5chainOf(parts),
                                              anchorsPem, Date.now());
    if (!chained.ok) {
      log.debug("Leaving VcMdoc.statusListKey(). " + chained.reason);
      throw new Error('the status list\'s ' + chained.reason.replace(
        /^its /, ''));
    }
    log.debug("Leaving VcMdoc.statusListKey().");
    return chained.leaf.x509.publicKey;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — the codec's
// arrangement: the exports are FACADES forwarding to the instance the root
// installs, and a process without the root builds a default at load.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<VcMdoc>(
  'oid4vc/vc_mdoc',
  () => new VcMdoc(VcMdoc.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading any module on the pattern does.
slot.buildNowUnlessDeferred();

/**
 * ISO/IEC 18013-5 mdoc verification for the OpenID4VP Verifier.
 *
 * @namespace
 */
export = {
  VcMdoc: VcMdoc,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: VcMdoc): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  COSE_SIGNATURE_IDS: COSE_SIGNATURE_IDS,
  coseAlgs: slot.forward('coseAlgs'),
  vpFormat: slot.forward('vpFormat'),
  sessionTranscript: slot.forward('sessionTranscript'),
  thumbprintBytes: slot.forward('thumbprintBytes'),
  chainToAnchors: slot.forward('chainToAnchors'),
  verify: slot.forward('verify'),
  statusListKey: slot.forward('statusListKey')
};
