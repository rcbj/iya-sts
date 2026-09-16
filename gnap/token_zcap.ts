'use strict';
//
// File: token_zcap.ts
//
// ===========================================================================
// THE `zcap` GNAP TOKEN FORMAT (RFC 9767 SECTION 5.3.2): A ZCAP-LD DELEGATED
// CAPABILITY SIGNED Ed25519Signature2020 BY THE AUTHORIZATION SERVER
// (2026-09-12).
//
// A route-free library: it registers nothing and requires `common/helpers.js`,
// `common/error_codes.js` and `gnap/gnap_access.ts`. The Digital Bazaar ZCAP
// and Ed25519 packages are ES modules, and they and `jsonld-signatures` (which
// pulls in the whole of jsonld) are loaded LAZILY, once, by the first call that
// needs them — never at require time.
//
// ---------------------------------------------------------------------------
// WHAT THE TOKEN IS.
//
// An authorization capability: a JSON-LD document naming what may be invoked
// (`invocationTarget`), by whom (`controller`), until when (`expires`), with
// which actions (`allowedAction`), delegated from a parent (`parentCapability`)
// and carrying a `capabilityDelegation` proof. ZCAP-LD's own root of trust is
// a ROOT CAPABILITY, `urn:zcap:root:<encoded target>`, whose controller is the
// party that owns the target; here that party is the AS, identified by its
// CONTROLLER DOCUMENT (`controllerDocument()`, published by the route module at
// `/gnap/zcap/controller`). So a GNAP zcap token is ONE delegation: the AS,
// controlling the root capability for the token's target, delegates it to the
// client's key.
//
//   '@context'          [ZCAP v1, Ed25519Signature2020 v1, the GNAP context]
//   id                  urn:gnap:token:<percent-encoded jti>
//   parentCapability    urn:zcap:root:<percent-encoded invocationTarget>
//   invocationTarget    aud[0] when it is a URI, urn:gnap:rs:<aud[0]> when it is
//                       not, or urn:gnap:as:<iss> when aud is empty
//   controller          from cnf:
//                         jkt  urn:ietf:params:oauth:jwk-thumbprint:sha-256:<tp>
//                         x5t  urn:gnap:x5t-s256:<tp>
//                         kid  urn:gnap:key-reference:<percent-encoded ref>
//                         none urn:gnap:bearer
//   expires             exp as ISO 8601
//   allowedAction       the union of every object right's actions; omitted
//                       when there are none (ZCAP reads absent as unrestricted
//                       and forbids an empty array)
//   gnapIssuer gnapSubject? gnapAudience gnapClient gnapAccess gnapFlags
//   gnapCnf gnapLabel? gnapIssuedAt gnapNotBefore?
//   proof               Ed25519Signature2020, created = iat,
//                       proofPurpose capabilityDelegation
//
// The jkt controller URN is RFC 9278's; the other three are this service's own,
// because no registry names a certificate thumbprint, a key reference or "no
// key" as a controller. ZCAP's `controller` is what an INVOCATION is checked
// against, and GNAP presents a token with an HTTP proof rather than a ZCAP
// invocation, so the controller here is a statement of the binding in ZCAP's
// own vocabulary; the binding CHECK is `gnap_access.checkBinding()` over
// `gnapCnf`, and verification refuses a controller that is not the one
// `gnapCnf` derives.
//
// ---------------------------------------------------------------------------
// THE GNAP CONTEXT IS INLINE, AND THE WHOLE `@context` MUST BE EXACTLY IT.
//
// The GNAP terms live under `urn:ietf:params:gnap#`; `access`, `flags`, `aud`
// and the two integers are `@json`, so their JSON survives canonicalisation
// byte for byte, and the strings are plain. Inline rather than a URL, because a
// URL would be one more document the offline loader serves and one more thing
// to version.
//
// **The verifier refuses any `@context` that is not deep-equal to the one this
// file writes, BEFORE the signature is checked**, and this is not pedantry. The
// signature covers the canonical RDF, not the JSON — and this file reads the
// model out of the JSON. A context that maps `gnapAccess` to `null` and some
// other key to `urn:ietf:params:gnap#access` produces IDENTICAL RDF, so the
// signature verifies, while the JSON key this file reads carries whatever the
// presenter wrote. Pinning the context closes the gap between what was signed
// and what is read. For the same reason a top-level member this file does not
// write is refused (safe mode would refuse an undefined term too; the list is
// cheaper and says which member).
//
// ---------------------------------------------------------------------------
// VERIFICATION IS FULLY OFFLINE.
//
// JSON-LD processing dereferences URLs — every context, the verification
// method, its controller document, the root capability — and a verifier that
// fetched them would be a verifier whose answer depends on the network and
// whose inputs somebody else chooses. `documentLoaderFor()` serves exactly:
// the ZCAP context (from the zcap package's own loader), the Ed25519 2020 suite
// context, the security v2 context (jsonld-signatures FRAMES a non-DID
// controller document with it), the controller document and verification
// method built from `keys`, and the ONE root capability the presented token's
// target derives. **Any other URL throws.** A proof naming another key, a
// capability chaining to another root, a context from elsewhere — each is a
// load failure and so a verification failure.
//
// The root capability's controller is always `keys.controller`, which is what
// makes deriving the expected root FROM the token's own `invocationTarget`
// safe: whatever target a presenter writes, the only root that loads for it is
// one the AS controls, so the chain can only verify if the AS signed it. The
// audience is then checked on the model like every other format.
//
// ---------------------------------------------------------------------------
// ORDER: shape and context, then the signature, then the model, then the
// shared checks.
//
// **THE ZCAP LIBRARY DOES NOT CHECK THE `expires` OF THE CAPABILITY IT IS
// VERIFYING, AND THAT IS THE ONE THING ABOUT IT A READER WILL ASSUME.**
// `CapabilityProofPurpose` compares `expires` against the verification date
// for every PARENT in the chain — and a GNAP token's only parent is a root
// capability, which may not carry one — so for a one-link delegation the
// library verifies an expired capability perfectly. ZCAP checks a leaf's
// expiry at INVOCATION, which GNAP never performs. So expiry here is enforced
// by `gnap_access.checkPresentation()` and by nothing else, and
// `tests/gnap_token_formats.js` asserts a capability a year past expiry is
// refused, with the shared code, so that a future reading of "the library
// handles expiry" cannot delete the only check there is.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `TokenZcap` takes the logger, the clock, the error-code table, the
// access model (`gnap_access`), node's `crypto` and an IMPORTER for the ZCAP
// libraries through its constructor. The importer is what keeps the ES
// modules lazy: the class calls it once, on the first call that needs them,
// and `import()` stays a real dynamic import in the compiled CommonJS (module
// `nodenext` preserves it). The module still exports its old names from a
// TRANSITIONAL instance for the unconverted modules and the tests that
// require it.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import gnapAccess = require('./gnap_access');

interface TokenZcapDeps {
  log: {
    debug(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
  nowSec(): number;
  errorCodes: { tag(code: string): string };
  // `gnap_access`: the model, its refusals and its presentation checks.
  access: any;
  crypto: { createPublicKey(key: any): any };
  // Loads the ZCAP libraries; called once, lazily (see the header).
  importLibraries(): Promise<any>;
}

const FORMAT = 'zcap';
const ZCAP_CONTEXT_URL = 'https://w3id.org/zcap/v1';
const SUITE_CONTEXT_URL = 'https://w3id.org/security/suites/ed25519-2020/v1';
const SECURITY_V2_URL = 'https://w3id.org/security/v2';
const ID_PREFIX = 'urn:gnap:token:';
const ROOT_PREFIX = 'urn:zcap:root:';
const AS_TARGET_PREFIX = 'urn:gnap:as:';

const CONTROLLER_PREFIXES = {
  jkt: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:',
  'x5t#S256': 'urn:gnap:x5t-s256:',
  kid: 'urn:gnap:key-reference:'
};
const BEARER_CONTROLLER = 'urn:gnap:bearer';

const GNAP_CONTEXT = {
  '@version': 1.1,
  gnap: 'urn:ietf:params:gnap#',
  gnapIssuer: 'gnap:iss',
  gnapSubject: 'gnap:sub',
  gnapAudience: { '@id': 'gnap:aud', '@type': '@json' },
  gnapClient: 'gnap:client',
  gnapAccess: { '@id': 'gnap:access', '@type': '@json' },
  gnapFlags: { '@id': 'gnap:flags', '@type': '@json' },
  gnapCnf: 'gnap:cnf',
  gnapLabel: 'gnap:label',
  gnapIssuedAt: { '@id': 'gnap:iat', '@type': '@json' },
  gnapNotBefore: { '@id': 'gnap:nbf', '@type': '@json' }
};
const CONTEXT = [ZCAP_CONTEXT_URL, SUITE_CONTEXT_URL, GNAP_CONTEXT];

const MEMBERS = ['@context', 'id', 'parentCapability', 'invocationTarget',
                 'controller', 'expires',
                 'allowedAction', 'gnapIssuer', 'gnapSubject', 'gnapAudience',
                 'gnapClient',
                 'gnapAccess', 'gnapFlags', 'gnapCnf', 'gnapLabel',
                 'gnapIssuedAt',
                 'gnapNotBefore', 'proof'];

const VALUE_RE = /^[A-Za-z0-9_-]+$/;

// An audience is a resource server's IDENTIFIER, which RFC 9767 does not
// require to be a URI — an application entry's identifier usually is not —
// and a ZCAP invocationTarget must be one. So a non-URI audience is carried as
// a URN of its own rather than refused: refusing it made a zcap token
// impossible for every resource server registered under a plain name.
const RS_TARGET_PREFIX = 'urn:gnap:rs:';

class TokenZcap {
  static readonly FORMAT = FORMAT;
  static readonly CONTEXT = CONTEXT;

  // The one load of the ES modules, shared by every call.
  private loading: Promise<any> | null = null;

  constructor(private readonly deps: TokenZcapDeps) {
    deps.log.debug("Entering TokenZcap.constructor().");
    deps.log.debug("Leaving TokenZcap.constructor().");
  }

  private refusal(code: string, why: string): any {
    const { log, access } = this.deps;
    log.debug("Entering TokenZcap.refusal().");
    log.debug("Leaving TokenZcap.refusal().");
    return access.refusal(code, why);
  }

  // -------------------------------------------------------------------------
  // The lazy load of the ES modules. A failure clears the promise so a later
  // call may try again (the biscuit loader's reasoning).
  // -------------------------------------------------------------------------
  private loadLibraries(): Promise<any> {
    const { log, importLibraries } = this.deps;
    log.debug("Entering TokenZcap.loadLibraries().");
    if (!this.loading) {
      this.loading = importLibraries().catch((e) => {
        log.debug("Caught in TokenZcap.loadLibraries(): " +
                  ((e && e.message) || e));
        this.loading = null;
        throw e;
      });
    }
    log.debug("Leaving TokenZcap.loadLibraries().");
    return this.loading;
  }

  private async libraries(): Promise<any> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering TokenZcap.libraries().");
    try {
      log.debug("Leaving TokenZcap.libraries().");
      return { ok: true, lib: await this.loadLibraries() };
    } catch (e) {
      log.debug("Caught in TokenZcap.libraries(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-GNAP-0331') + 'the ZCAP libraries ' +
                'could not be loaded: ' + e.message);
      log.debug("Leaving TokenZcap.libraries().");
      return this.refusal('STS-GNAP-0331',
                          'the ZCAP libraries could not be loaded: ' +
                          e.message);
    }
  }

  private isAbsoluteUrl(value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.isAbsoluteUrl().");
    if (typeof value !== 'string') {
      log.debug("Leaving TokenZcap.isAbsoluteUrl().");
      return false;
    }
    try {
      const u = new URL(value);
      log.debug("Leaving TokenZcap.isAbsoluteUrl().");
      return !!u.protocol && !u.hash;
    } catch (e) {
      log.debug("Caught in TokenZcap.isAbsoluteUrl(): " +
                ((e && e.message) || e));
      log.debug("Leaving TokenZcap.isAbsoluteUrl().");
      // Not a URL; `false` is the answer.
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // The keys, validated and turned into Ed25519VerificationKey2020 instances.
  // `wantPrivate` asks for the signing half.
  // -------------------------------------------------------------------------
  private async keyPairOf(lib: any, keys: any,
                          wantPrivate: boolean): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.keyPairOf(). wantPrivate=" + wantPrivate);
    const k = keys || {};
    if (!this.isAbsoluteUrl(k.controller) || typeof k.keyId !== 'string' ||
        k.keyId.indexOf(k.controller + '#') !== 0 ||
        k.keyId.length === k.controller.length + 1) {
      log.debug("Leaving TokenZcap.keyPairOf(). controller / keyId " +
                "unusable.");
      return this.refusal('STS-GNAP-0330', 'ZCAP keys need an absolute ' +
                          'controller URL and a keyId of ' +
                          '<controller>#<fragment>.');
    }
    const keyObject = wantPrivate ? k.privateKey : k.publicKey;
    if (!keyObject || typeof keyObject.export !== 'function' ||
        keyObject.asymmetricKeyType !== 'ed25519') {
      log.debug("Leaving TokenZcap.keyPairOf(). Not an Ed25519 KeyObject.");
      return this.refusal('STS-GNAP-0330',
                          'a ZCAP token is ' + (wantPrivate ? 'signed ' +
                              'with an Ed25519 private' :
                          'verified with an Ed25519 public') + ' KeyObject.');
    }
    const jwk = keyObject.export({ format: 'jwk' });
    let pair;
    if (wantPrivate) {
      // The seed IS the private key: generating from it reproduces the node
      // key.
      pair = await lib.Ed25519VerificationKey2020.generate({
        seed: new Uint8Array(Buffer.from(jwk.d, 'base64url')), id: k.keyId,
        controller: k.controller
      });
    } else {
      pair = await lib.Ed25519VerificationKey2020.fromJsonWebKey({
        id: k.keyId, controller: k.controller, type: 'JsonWebKey',
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }
      });
    }
    log.debug("Leaving TokenZcap.keyPairOf(). Ready.");
    return { ok: true, pair: pair };
  }

  private controllerDocumentFor(lib: any, keys: any, publicPair: any) {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.controllerDocumentFor().");
    log.debug("Leaving TokenZcap.controllerDocumentFor().");
    return {
      '@context': [SECURITY_V2_URL, SUITE_CONTEXT_URL],
      id: keys.controller,
      verificationMethod: [publicPair.export({ publicKey: true,
                                               includeContext: false })],
      assertionMethod: [keys.keyId],
      capabilityDelegation: [keys.keyId]
    };
  }

  // -------------------------------------------------------------------------
  // controllerDocument(keys): the document the AS publishes at
  // `/gnap/zcap/controller`. Asynchronous because the key classes are ES
  // modules. Returns the document, or a refusal when the keys are unusable.
  // -------------------------------------------------------------------------
  async controllerDocument(keys: any): Promise<any> {
    const { log, crypto } = this.deps;
    log.debug("Entering TokenZcap.controllerDocument().");
    const libs = await this.libraries();
    if (!libs.ok) {
      log.debug("Leaving TokenZcap.controllerDocument(). Libraries " +
                "unavailable.");
      return libs;
    }
    const publicKeys = Object.assign({}, keys || {});
    if (!publicKeys.publicKey && publicKeys.privateKey) {
      publicKeys.publicKey = crypto.createPublicKey(publicKeys.privateKey);
    }
    const pair = await this.keyPairOf(libs.lib, publicKeys, false);
    if (!pair.ok) {
      log.debug("Leaving TokenZcap.controllerDocument(). Keys unusable.");
      return pair;
    }
    log.debug("Leaving TokenZcap.controllerDocument().");
    return this.controllerDocumentFor(libs.lib, publicKeys, pair.pair);
  }

  private rootIdFor(target: string): string {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.rootIdFor().");
    log.debug("Leaving TokenZcap.rootIdFor().");
    return ROOT_PREFIX + encodeURIComponent(target);
  }

  // -------------------------------------------------------------------------
  // The offline document loader (see the header). `rootTarget` is the one
  // invocation target whose root capability may load.
  // -------------------------------------------------------------------------
  private documentLoaderFor(lib: any, keys: any, publicPair: any,
                            rootTarget: string): any {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.documentLoaderFor().");
    const controllerDoc = this.controllerDocumentFor(lib, keys, publicPair);
    const root = lib.zcap.createRootCapability({
      controller: keys.controller,
      invocationTarget: rootTarget });
    function answer(documentUrl, document) {
      log.debug("Entering answer().");
      log.debug("Leaving answer().");
      return { contextUrl: null, documentUrl: documentUrl, document: document,
               tag: 'static' };
    }
    log.debug("Leaving TokenZcap.documentLoaderFor().");
    return lib.zcap.extendDocumentLoader(async function offlineLoader(
        documentUrl) {
      log.debug("Entering offlineLoader().");
      if (documentUrl === SUITE_CONTEXT_URL) {
        log.debug("Leaving offlineLoader().");
        return answer(documentUrl,
                      lib.suiteContext.contexts.get(SUITE_CONTEXT_URL));
      }
      if (documentUrl === SECURITY_V2_URL) {
        log.debug("Leaving offlineLoader().");
        return answer(documentUrl, lib.securityContexts.get(SECURITY_V2_URL));
      }
      if (documentUrl === keys.controller) {
        log.debug("Leaving offlineLoader().");
        return answer(documentUrl, controllerDoc);
      }
      if (documentUrl === keys.keyId) {
        log.debug("Leaving offlineLoader().");
        return answer(documentUrl,
                      publicPair.export({ publicKey: true,
                                          includeContext: true }));
      }
      if (documentUrl === root.id) {
        log.debug("Leaving offlineLoader().");
        return answer(documentUrl, root);
      }
      log.debug("Leaving offlineLoader().");
      throw new Error('the offline ZCAP document loader serves no document ' +
                      'at ' + documentUrl);
    });
  }

  controllerFor(cnf: any): string {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.controllerFor().");
    if (!cnf) {
      log.debug("Leaving TokenZcap.controllerFor().");
      return BEARER_CONTROLLER;
    }
    const member = Object.keys(cnf)[0];
    const value = member === 'kid' ? encodeURIComponent(cnf.kid) :
      cnf[member];
    log.debug("Leaving TokenZcap.controllerFor().");
    return CONTROLLER_PREFIXES[member] + value;
  }

  private targetFor(model: any): string {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.targetFor().");
    if (!model.aud.length) {
      log.debug("Leaving TokenZcap.targetFor().");
      return AS_TARGET_PREFIX + model.iss;
    }
    const first = String(model.aud[0]);
    log.debug("Leaving TokenZcap.targetFor().");
    return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(first) ? first :
           RS_TARGET_PREFIX + encodeURIComponent(first);
  }

  private actionsOf(rights: any[]): string[] {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.actionsOf().");
    const out = [];
    rights.forEach(function (r) {
      if (r && typeof r === 'object' && Array.isArray(r.actions)) {
        r.actions.forEach(function (a) {
          if (out.indexOf(a) < 0) {
            out.push(a);
          }
        });
      }
    });
    log.debug("Leaving TokenZcap.actionsOf(). " + out.length +
              " action(s).");
    return out;
  }

  private isoSeconds(seconds: number): string {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.isoSeconds().");
    log.debug("Leaving TokenZcap.isoSeconds().");
    return new Date(seconds * 1000).toISOString().replace(/\.000Z$/, 'Z');
  }

  // The unsigned capability for a validated model.
  private capabilityFor(model: any): Record<string, any> {
    const { log, access } = this.deps;
    log.debug("Entering TokenZcap.capabilityFor().");
    const target = this.targetFor(model);
    const cap: Record<string, any> = {
      '@context': CONTEXT,
      id: ID_PREFIX + encodeURIComponent(model.jti),
      parentCapability: this.rootIdFor(target),
      invocationTarget: target,
      controller: this.controllerFor(model.cnf),
      expires: this.isoSeconds(model.exp)
    };
    const actions = this.actionsOf(model.access);
    if (actions.length) {
      cap.allowedAction = actions;
    }
    cap.gnapIssuer = model.iss;
    if (model.sub !== null) {
      cap.gnapSubject = model.sub;
    }
    cap.gnapAudience = model.aud;
    cap.gnapClient = model.instanceId;
    cap.gnapAccess = model.access;
    cap.gnapFlags = model.flags;
    cap.gnapCnf = model.cnf ? access.cnfToString(model.cnf) : 'bearer';
    if (model.label !== null) {
      cap.gnapLabel = model.label;
    }
    cap.gnapIssuedAt = model.iat;
    if (model.nbf !== null) {
      cap.gnapNotBefore = model.nbf;
    }
    log.debug("Leaving TokenZcap.capabilityFor().");
    return cap;
  }

  // -------------------------------------------------------------------------
  // mint(model, keys): keys = { privateKey, controller, keyId } (publicKey is
  // derived when absent).
  // -------------------------------------------------------------------------
  async mint(model: any, keys: any): Promise<any> {
    const { log, errorCodes, access, crypto } = this.deps;
    log.debug("Entering TokenZcap.mint().");
    const valid = access.validateModel(model);
    if (!valid.ok) {
      log.debug("Leaving TokenZcap.mint(). Model invalid.");
      return valid;
    }
    const target = this.targetFor(valid.model);
    if (!/^[A-Za-z][A-Za-z0-9+.-]*:/.test(target)) {
      log.debug("Leaving TokenZcap.mint(). Target is not an absolute URI.");
      return this.refusal('STS-GNAP-0330', 'a ZCAP invocationTarget must be ' +
                          'an absolute URI, and the token\'s first audience ' +
                          '"' + target + '" is not one.');
    }
    const libs = await this.libraries();
    if (!libs.ok) {
      log.debug("Leaving TokenZcap.mint(). Libraries unavailable.");
      return libs;
    }
    const lib = libs.lib;
    const signing = await this.keyPairOf(lib, keys, true);
    if (!signing.ok) {
      log.debug("Leaving TokenZcap.mint(). Signing key unusable.");
      return signing;
    }
    const publicKeys = Object.assign({}, keys,
                                     { publicKey: crypto.createPublicKey(
                                         keys.privateKey) });
    const verifying = await this.keyPairOf(lib, publicKeys, false);
    const cap = this.capabilityFor(valid.model);
    let signed;
    try {
      signed = await lib.jsigs.sign(cap, {
        suite: new lib.Ed25519Signature2020({ key: signing.pair,
                                              date: new Date(
                                                  valid.model.iat * 1000) }),
        purpose: new lib.zcap.CapabilityDelegation(
            { parentCapability: cap.parentCapability }),
        documentLoader: this.documentLoaderFor(lib, publicKeys,
                                               verifying.pair, target)
      });
    } catch (e) {
      log.debug("Caught in TokenZcap.mint(): " + ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-GNAP-0335') + 'ZCAP signing failed in ' +
               'the library: ' + e.message);
      log.debug("Leaving TokenZcap.mint(). Library failure.");
      return this.refusal('STS-GNAP-0335', 'the ZCAP libraries refused to ' +
                          'sign the capability: ' + e.message);
    }
    const value = Buffer.from(JSON.stringify(signed), 'utf8')
                        .toString('base64url');
    log.debug("Leaving TokenZcap.mint(). jti=" + valid.model.jti);
    return { value: value, format: FORMAT, jti: valid.model.jti };
  }

  private decodeValue(value: unknown): any {
    const { log, access } = this.deps;
    log.debug("Entering TokenZcap.decodeValue().");
    if (typeof value !== 'string' || !VALUE_RE.test(value)) {
      log.debug("Leaving TokenZcap.decodeValue(). Not base64url.");
      return this.refusal('STS-GNAP-0332',
                          'the token value is not unpadded base64url.');
    }
    let doc;
    try {
      doc = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
    } catch (e) {
      log.debug("Caught in TokenZcap.decodeValue(): " +
                ((e && e.message) || e));
      log.debug("Leaving TokenZcap.decodeValue(). Not JSON.");
      return this.refusal('STS-GNAP-0332', 'the token value is not ' +
                          'base64url JSON.');
    }
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
      log.debug("Leaving TokenZcap.decodeValue(). Not an object.");
      return this.refusal('STS-GNAP-0332', 'the token value is not a JSON ' +
                          'object.');
    }
    const extra = Object.keys(doc)
                        .filter(function (k) {
                          return MEMBERS.indexOf(k) < 0;
                        });
    if (extra.length) {
      log.debug("Leaving TokenZcap.decodeValue(). Unknown members.");
      return this.refusal('STS-GNAP-0332', 'the capability carries members ' +
                          'this format does not write: ' +
                          extra.join(', ') + '.');
    }
    if (access.canonicalJson(doc['@context']) !==
        access.canonicalJson(CONTEXT)) {
      log.debug("Leaving TokenZcap.decodeValue(). Context is not the pinned " +
                "one.");
      return this.refusal('STS-GNAP-0332', 'the capability\'s @context is ' +
                          'not exactly the GNAP ZCAP context, so what was ' +
                          'signed and what would be read could differ.');
    }
    log.debug("Leaving TokenZcap.decodeValue(). Decoded.");
    return { ok: true, doc: doc };
  }

  // -------------------------------------------------------------------------
  // The GNAP terms back into a model, and every derived member checked
  // against the model it should derive from.
  // -------------------------------------------------------------------------
  private readModel(doc: any): any {
    const { log, access } = this.deps;
    const self = this;
    log.debug("Entering TokenZcap.readModel().");
    function bad(why: string) {
      log.debug("Entering bad().");
      log.debug("Leaving TokenZcap.readModel(). " + why);
      return self.refusal('STS-GNAP-0334', 'the capability\'s GNAP terms ' +
                          'are inconsistent: ' + why + '.');
    }
    if (typeof doc.id !== 'string' || doc.id.indexOf(ID_PREFIX) !== 0) {
      log.debug("Leaving TokenZcap.readModel().");
      return bad('its id is not ' + ID_PREFIX + '<jti>');
    }
    let jti;
    try {
      jti = decodeURIComponent(doc.id.slice(ID_PREFIX.length));
    } catch (e) {
      log.debug("Caught in TokenZcap.readModel(): " +
                ((e && e.message) || e));
      log.debug("Leaving TokenZcap.readModel().");
      return bad('its id is not percent-encoded');
    }
    const exp = Date.parse(doc.expires);
    let cnf = null;
    if (doc.gnapCnf !== 'bearer') {
      cnf = access.cnfFromString(doc.gnapCnf);
      if (!cnf) {
        log.debug("Leaving TokenZcap.readModel().");
        return bad('gnapCnf is neither "bearer" nor a confirmation');
      }
    }
    const model = {
      jti: jti,
      iss: doc.gnapIssuer,
      sub: doc.gnapSubject === undefined ? null : doc.gnapSubject,
      aud: doc.gnapAudience,
      instanceId: doc.gnapClient,
      access: doc.gnapAccess,
      flags: doc.gnapFlags,
      cnf: cnf,
      iat: doc.gnapIssuedAt,
      nbf: doc.gnapNotBefore === undefined ? null : doc.gnapNotBefore,
      exp: Number.isNaN(exp) || exp % 1000 !== 0 ? undefined : exp / 1000,
      label: doc.gnapLabel === undefined ? null : doc.gnapLabel
    };
    const valid = access.validateModel(model);
    if (!valid.ok) {
      log.debug("Leaving TokenZcap.readModel().");
      return bad('they are not a valid token model (' + valid.why + ')');
    }
    const expected = this.capabilityFor(valid.model);
    const derived = ['id', 'parentCapability', 'invocationTarget',
                     'controller', 'expires', 'allowedAction'];
    for (let i = 0; i < derived.length; i++) {
      const name = derived[i];
      if (access.canonicalJson(doc[name]) !== access.canonicalJson(
          expected[name])) {
        log.debug("Leaving TokenZcap.readModel().");
        return bad('"' + name + '" is not the value the GNAP terms derive');
      }
    }
    log.debug("Leaving TokenZcap.readModel(). Read.");
    return valid;
  }

  // -------------------------------------------------------------------------
  // verify(value, keys, context) -> { ok:true, model } | refusal.
  // keys = { publicKey, controller, keyId }.
  // -------------------------------------------------------------------------
  async verify(value: unknown, keys: any, context?: any): Promise<any> {
    const { log, access, nowSec } = this.deps;
    log.debug("Entering TokenZcap.verify().");
    const decoded = this.decodeValue(value);
    if (!decoded.ok) {
      log.debug("Leaving TokenZcap.verify(). Decode refused.");
      return decoded;
    }
    const doc = decoded.doc;
    const ctx = context || {};
    const now = Number.isSafeInteger(ctx.now) ? ctx.now : nowSec();
    if (typeof doc.invocationTarget !== 'string' || !doc.invocationTarget) {
      log.debug("Leaving TokenZcap.verify(). No target.");
      return this.refusal('STS-GNAP-0334',
                          'the capability names no invocationTarget.');
    }
    const libs = await this.libraries();
    if (!libs.ok) {
      log.debug("Leaving TokenZcap.verify(). Libraries unavailable.");
      return libs;
    }
    const lib = libs.lib;
    const verifying = await this.keyPairOf(lib, keys, false);
    if (!verifying.ok) {
      log.debug("Leaving TokenZcap.verify(). Verification key unusable.");
      return verifying;
    }
    let result;
    try {
      result = await lib.jsigs.verify(doc, {
        suite: new lib.Ed25519Signature2020(),
        purpose: new lib.zcap.CapabilityDelegation({
          expectedRootCapability: this.rootIdFor(doc.invocationTarget),
          allowTargetAttenuation: true,
          date: new Date(now * 1000)
        }),
        documentLoader: this.documentLoaderFor(lib, keys, verifying.pair,
                                               doc.invocationTarget)
      });
    } catch (e) {
      log.debug("Caught in TokenZcap.verify(): " + ((e && e.message) || e));
      // jsigs reports through `result`; a throw is malformed input it could
      // not even start on, which is the same answer for the caller.
      result = { verified: false, error: e };
    }
    if (!result || !result.verified) {
      const errors = result && result.error ?
                     (result.error.errors || [result.error]) : [];
      const why = errors.map(function (e) {
        return e && e.message && e.message.replace(/\.$/, '');
      })
        .filter(Boolean).join('; ');
      log.debug("Leaving TokenZcap.verify(). Proof refused: " + why);
      return this.refusal('STS-GNAP-0333', 'the capability\'s delegation ' +
                          'proof does not verify under this authorization ' +
                          'server\'s key' + (why ? ': ' + why : '') + '.');
    }
    const read = this.readModel(doc);
    if (!read.ok) {
      log.debug("Leaving TokenZcap.verify(). Model refused.");
      return read;
    }
    const failed = access.checkPresentation(read.model,
                                            Object.assign({}, ctx,
                                                          { now: now }));
    if (failed) {
      log.debug("Leaving TokenZcap.verify(). Presentation refused.");
      return failed;
    }
    log.debug("Leaving TokenZcap.verify(). Verified jti=" + read.model.jti);
    return { ok: true, model: read.model, attenuated: false };
  }

  describe() {
    const { log, access } = this.deps;
    log.debug("Entering TokenZcap.describe().");
    const out = {
      name: FORMAT,
      libraries: ['@digitalbazaar/zcap', '@digitalbazaar/zcap-context',
                  'jsonld-signatures', 'jsonld',
                  '@digitalbazaar/ed25519-signature-2020',
                  '@digitalbazaar/ed25519-verification-key-2020',
                  '@digitalbazaar/security-context'].map(function (name) {
                    return access.libraryInfo(name);
                  }),
      algorithms: [
        ['Proof suite', ['Ed25519Signature2020']],
        ['Canonicalisation', ['RDF Dataset Canonicalization (URDNA2015)']],
        ['Digest', ['SHA-256']],
        ['Signature', ['Ed25519']],
        ['Proof purpose', ['capabilityDelegation, one link from a root the ' +
                           'AS controls']],
        ['Serialisation', ['JSON-LD, unpadded base64url']]
      ],
      carries: ['jti', 'iss', 'sub', 'aud', 'instanceId', 'access', 'flags',
                'cnf',
                'iat', 'nbf', 'exp', 'label'],
      cannot: []
    };
    log.debug("Leaving TokenZcap.describe().");
    return out;
  }
}

// THE TRANSITIONAL INSTANCE — see the header above. Built from the real
// modules, as the composition root will build one. The importer is the old
// module-level load, unchanged: three ES modules by dynamic import and two
// CommonJS packages by require, all at the first call that needs them.
const tokenZcap = new TokenZcap({
  log: helpers.log,
  nowSec: function () {
    return helpers.nowSec();
  },
  errorCodes: errorCodes,
  access: gnapAccess,
  crypto: crypto,
  importLibraries: function () {
    return Promise.all([
      import('@digitalbazaar/zcap'),
      import('@digitalbazaar/ed25519-signature-2020'),
      import('@digitalbazaar/ed25519-verification-key-2020')
    ]).then(function (mods: any[]) {
      const security = require('@digitalbazaar/security-context');
      return {
        jsigs: require('jsonld-signatures'),
        zcap: mods[0],
        Ed25519Signature2020: mods[1].Ed25519Signature2020,
        suiteContext: mods[1].suiteContext,
        Ed25519VerificationKey2020: mods[2].Ed25519VerificationKey2020,
        securityContexts: security.contexts
      };
    });
  }
});

export = {
  TokenZcap: TokenZcap,
  FORMAT: TokenZcap.FORMAT,
  CONTEXT: TokenZcap.CONTEXT,
  mint: tokenZcap.mint.bind(tokenZcap) as TokenZcap['mint'],
  verify: tokenZcap.verify.bind(tokenZcap) as TokenZcap['verify'],
  describe: tokenZcap.describe.bind(tokenZcap) as TokenZcap['describe'],
  controllerDocument: tokenZcap.controllerDocument.bind(tokenZcap) as
    TokenZcap['controllerDocument'],
  controllerFor: tokenZcap.controllerFor.bind(tokenZcap) as
    TokenZcap['controllerFor']
};
