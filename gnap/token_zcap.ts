'use strict';
//
// File: token_zcap.ts
//
// ===========================================================================
// THE `zcap` GNAP TOKEN FORMAT (RFC 9767 SECTION 5.3.2): A ZCAP-LD DELEGATED
// CAPABILITY SIGNED BY THE AUTHORIZATION SERVER (2026-09-12), WITH A DATA
// INTEGRITY `eddsa-jcs-2022` PROOF BY DEFAULT SINCE 2026-09-22 (#43).
//
// A route-free library: it registers nothing and requires `common/helpers.js`,
// `common/error_codes.js`, `gnap/gnap_access.ts` and
// `oid4vc/vc_data_integrity.ts` (a library, rule 3). The Digital Bazaar ZCAP
// and Ed25519 packages are ES modules, and they and `jsonld-signatures` (which
// pulls in the whole of jsonld) are loaded LAZILY, once, by the first call that
// needs them — never at require time.
//
// ---------------------------------------------------------------------------
// THE PROOF SUITE, AND WHY THE DEFAULT CHANGED (#43).
//
// RFC 9767 names [ZCAPLD] — Authorization Capabilities for Linked Data v0.3,
// a W3C CCG report — and no proof suite. v0.3 says a delegated capability's
// proof "MUST sign the document with Linked Data Proofs" ("DI proofs (Data
// Integrity Proofs, formerly known as Linked Data proofs)") and pins none;
// its examples use Ed25519Signature2020, and every example of v0.4.0-rc.6 is
// a `DataIntegrityProof` with `eddsa-jcs-2022` over an `@context` of
// [zcap/v1, data-integrity/v2, …]. `gnap.zcapCryptosuite` chooses, per realm:
//
//   eddsa-jcs-2022       DEFAULT. W3C Data Integrity EdDSA Cryptosuites v1.0
//                        (Recommendation), section 3.3.
//   mldsa44-jcs-2024     post-quantum: W3C Quantum-Resistant Cryptosuites v1.0
//   slhdsa128-jcs-2024   (First Public Working Draft), sections 3.3 and 3.4.
//   Ed25519Signature2020 COMPATIBILITY ONLY — the EdDSA Recommendation's own
//                        Appendix A calls it "an earlier version" that "new
//                        implementations should instead" replace.
//
// **WHY JCS.** Ed25519Signature2020 signs the RDF Dataset Canonicalization
// (URDNA2015) of the capability — a graph — while everything here, and every
// resource server, reads the JSON. The two differ exactly where a `@context`
// remaps a term, which is why the context has to be pinned (below) for that
// suite to be safe at all, why a verifier needs a JSON-LD processor and a
// document loader, and why a resource server that has neither can only
// check that the proof NAMES the right key (#43 was the RS job saying so).
// A JCS suite signs RFC 8785's canonical form of the JSON itself: what is
// signed is what is read, no JSON-LD processing touches the token, and a
// resource server verifies it with SHA-256 and the signature algorithm.
//
// The JCS proof is made and checked by `oid4vc/vc_data_integrity.ts` — the
// one implementation of those suites here, the OpenID4VP Verifier's — wrapped
// in a jsonld-signatures suite object (`jcsSuite()`) so that
// `@digitalbazaar/zcap`'s CapabilityDelegation purpose still does the ZCAP
// half: the capability chain, the root, the controller, attenuation.
//
// **A REALM VERIFIES ONLY THE SUITE IT IS SET TO**, refused as STS-GNAP-0336
// before any signature is checked: a realm on the default must not accept a
// token some other key or suite made because the library could check it.
// Changing the setting therefore strands the tokens already issued under the
// old one — a GNAP access token lives `gnap.accessTokenLifetimeS`.
//
// **THE CONTROLLER DOCUMENT FOLLOWS THE SUITE.** A JCS suite's verification
// method is a `Multikey` (EdDSA 2.1.1; Quantum-Resistant 2.1.1) in a document
// whose `@context` is Controlled Identifiers v1.0's; the compatibility suite's
// is an Ed25519VerificationKey2020 (EdDSA A.1.1.1), as it always was.
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
// **That paragraph is about Ed25519Signature2020.** Under a JCS suite the
// signature covers the JSON itself, so a remapping context changes the
// signed bytes and fails the signature; the pin and the member list stay
// anyway, because ZCAP-LD says a capability is JSON that "can be interpreted
// properly as JSON-LD" and "Other JSON-LD representations that deviate from
// the JSON expression of a zcap are not permitted" — and because each
// suite's pinned context is what tells a token of one suite from another.
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
// **A JCS suite needs less of it** (`jcsLoader()`): the root capability and
// the ZCAP context only. Its signature is not over JSON-LD, the key is
// resolved from what this module holds (`jcsSuite()`'s resolver), and the
// controller document is handed to the purpose instead of framed.
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
// libraries through its constructor. The importer is what keeps the ES modules
// lazy: the class calls it once, on the first call that needs them, and
// `import()` stays a real dynamic import in the compiled CommonJS (module
// `nodenext` preserves it). The module still exports its old names as FACADES
// forwarding to the instance the composition root builds (#50, R2), for the
// unconverted modules and the tests that require it. A process that loads this
// module without the root builds a default instance when the module loads.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import gnapAccess = require('./gnap_access');
import dataIntegrity = require('../oid4vc/vc_data_integrity');

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
  // `oid4vc/vc_data_integrity`: the JCS cryptosuites (see the header).
  dataIntegrity: any;
  // Loads the ZCAP libraries; called once, lazily (see the header).
  importLibraries(): Promise<any>;
}

const FORMAT = 'zcap';
const ZCAP_CONTEXT_URL = 'https://w3id.org/zcap/v1';
const SUITE_CONTEXT_URL = 'https://w3id.org/security/suites/ed25519-2020/v1';
const SECURITY_V2_URL = 'https://w3id.org/security/v2';
// ZCAP-LD v0.4.0-rc.6's second context, which defines DataIntegrityProof,
// `cryptosuite` and `proofValue`; and the Controlled Identifiers v1.0 context
// a Multikey controller document is written in. Neither is ever LOADED: no
// JSON-LD processing touches a JCS token, and the controller document this
// module checks against is the one it builds (see `jcsSuite()`).
const DATA_INTEGRITY_V2_URL = 'https://w3id.org/security/data-integrity/v2';
const CID_V1_URL = 'https://www.w3.org/ns/cid/v1';

const LEGACY_SUITE = 'Ed25519Signature2020';
const JCS_SUITES = ['eddsa-jcs-2022', 'mldsa44-jcs-2024',
                    'slhdsa128-jcs-2024'];
const CRYPTOSUITES = JCS_SUITES.concat([LEGACY_SUITE]);
const DEFAULT_CRYPTOSUITE = 'eddsa-jcs-2022';
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
// The pinned `@context` of each kind of proof: ZCAP-LD's first ("the first
// value is the zcapld context"), the proof's vocabulary second, the GNAP
// terms last. `CONTEXT` is the default suite's.
const CONTEXT = [ZCAP_CONTEXT_URL, DATA_INTEGRITY_V2_URL, GNAP_CONTEXT];
const LEGACY_CONTEXT = [ZCAP_CONTEXT_URL, SUITE_CONTEXT_URL, GNAP_CONTEXT];

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
  static readonly LEGACY_CONTEXT = LEGACY_CONTEXT;
  static readonly CRYPTOSUITES = CRYPTOSUITES;
  static readonly DEFAULT_CRYPTOSUITE = DEFAULT_CRYPTOSUITE;
  static readonly LEGACY_SUITE = LEGACY_SUITE;

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
  // THE SUITE A CALL IS FOR: `keys.cryptosuite`, which the caller reads from
  // `gnap.zcapCryptosuite`; absent, the default. Anything else is refused
  // rather than guessed — a suite nobody set is not one to sign with.
  // -------------------------------------------------------------------------
  private suiteOf(keys: any): any {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.suiteOf().");
    const suite = keys && keys.cryptosuite !== undefined &&
                  keys.cryptosuite !== null && keys.cryptosuite !== ''
      ? String(keys.cryptosuite) : DEFAULT_CRYPTOSUITE;
    if (CRYPTOSUITES.indexOf(suite) < 0) {
      log.debug("Leaving TokenZcap.suiteOf(). Unknown suite.");
      return this.refusal('STS-GNAP-0330', 'a zcap token is signed with ' +
                          CRYPTOSUITES.join(', ') + '; "' + suite +
                          '" is none of them.');
    }
    log.debug("Leaving TokenZcap.suiteOf(). " + suite);
    return { ok: true, suite: suite };
  }

  contextFor(suite: string): any[] {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.contextFor().");
    log.debug("Leaving TokenZcap.contextFor().");
    return suite === LEGACY_SUITE ? LEGACY_CONTEXT : CONTEXT;
  }

  // -------------------------------------------------------------------------
  // THE KEYS OF A JCS SUITE: the controller URL and the keyId under it (the
  // same rule as `keyPairOf()`), and a public JWK of the kind the suite
  // signs with — Ed25519 for eddsa-jcs-2022, an AKP ML-DSA-44 or
  // SLH-DSA-SHA2-128s key for the other two. `wantPrivate` asks for the
  // signing half as well: a node KeyObject for Ed25519, the key bytes for
  // the post-quantum ones (`helpers.js`'s `pqKeyFrom()` shape), both what
  // `vc_data_integrity.signDocument()` takes.
  // -------------------------------------------------------------------------
  private jcsKeysOf(keys: any, suite: string, wantPrivate: boolean): any {
    const { log, dataIntegrity } = this.deps;
    log.debug("Entering TokenZcap.jcsKeysOf(). suite=" + suite);
    const k = keys || {};
    if (!this.isAbsoluteUrl(k.controller) || typeof k.keyId !== 'string' ||
        k.keyId.indexOf(k.controller + '#') !== 0 ||
        k.keyId.length === k.controller.length + 1) {
      log.debug("Leaving TokenZcap.jcsKeysOf(). controller / keyId " +
                "unusable.");
      return this.refusal('STS-GNAP-0330', 'ZCAP keys need an absolute ' +
                          'controller URL and a keyId of ' +
                          '<controller>#<fragment>.');
    }
    let jwk = k.publicJwk;
    if (!jwk && k.publicKey && typeof k.publicKey.export === 'function') {
      jwk = k.publicKey.export({ format: 'jwk' });
    }
    let publicJwk = null;
    try {
      publicJwk = dataIntegrity.publicJwkOf(jwk);
    } catch (e) {
      log.debug("Caught in TokenZcap.jcsKeysOf(): " +
                ((e && e.message) || e));
      publicJwk = null;
    }
    if (!publicJwk || dataIntegrity.cryptosuiteForJwk(publicJwk) !== suite) {
      log.debug("Leaving TokenZcap.jcsKeysOf(). Wrong kind of key.");
      return this.refusal('STS-GNAP-0330', 'a zcap token signed with ' +
                          suite + ' needs a key of the kind that suite ' +
                          'signs with, and this realm\'s is not one.');
    }
    if (wantPrivate && !k.privateKey) {
      log.debug("Leaving TokenZcap.jcsKeysOf(). No private half.");
      return this.refusal('STS-GNAP-0330', 'a zcap token is signed with ' +
                          'the private half of the ' + suite + ' key, and ' +
                          'none was given.');
    }
    log.debug("Leaving TokenZcap.jcsKeysOf(). Ready.");
    return { ok: true, controller: k.controller, keyId: k.keyId,
             publicJwk: publicJwk, privateKey: k.privateKey };
  }

  // A Multikey verification method (Controlled Identifiers v1.0; EdDSA
  // Cryptosuites 2.1.1; Quantum-Resistant Cryptosuites 2.1.1).
  private multikeyMethod(keyId: string, controller: string,
                         publicJwk: any): any {
    const { log, dataIntegrity } = this.deps;
    log.debug("Entering TokenZcap.multikeyMethod().");
    log.debug("Leaving TokenZcap.multikeyMethod().");
    return { id: keyId, type: 'Multikey', controller: controller,
             publicKeyMultibase: dataIntegrity.multikeyOf(publicJwk) };
  }

  // The controller document of a JCS suite: every live generation of the
  // realm's key as a Multikey, the current one first, each authorized for
  // `capabilityDelegation` — the relationship a delegation proof is checked
  // against — and `assertionMethod`, as the compatibility document is.
  private jcsControllerDocument(keys: any, suite: string): any {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.jcsControllerDocument().");
    const current = this.jcsKeysOf(keys, suite, false);
    if (!current.ok) {
      log.debug("Leaving TokenZcap.jcsControllerDocument(). Keys unusable.");
      return current;
    }
    const document = {
      '@context': [CID_V1_URL],
      id: current.controller,
      verificationMethod: [this.multikeyMethod(current.keyId,
                                               current.controller,
                                               current.publicJwk)],
      assertionMethod: [current.keyId],
      capabilityDelegation: [current.keyId]
    };
    const others = Array.isArray(keys.others) ? keys.others : [];
    for (let i = 0; i < others.length; i++) {
      const one = this.jcsKeysOf(Object.assign({ controller:
                                                   current.controller },
                                               others[i]), suite, false);
      if (!one.ok) {
        continue;
      }
      document.verificationMethod.push(this.multikeyMethod(
          one.keyId, one.controller, one.publicJwk));
      document.assertionMethod.push(one.keyId);
      document.capabilityDelegation.push(one.keyId);
    }
    log.debug("Leaving TokenZcap.jcsControllerDocument(). " +
              document.verificationMethod.length + " method(s).");
    return { ok: true, document: document };
  }

  // -------------------------------------------------------------------------
  // THE OFFLINE LOADER OF A JCS SUITE: the ONE root capability the token's
  // target derives, and the ZCAP context (from the zcap package's own
  // loader). Nothing else — no key, no controller document, no proof
  // context — because nothing else is dereferenced: the signature is
  // checked over JCS, and the controller is the document handed to the
  // purpose.
  // -------------------------------------------------------------------------
  private jcsLoader(lib: any, controller: string, rootTarget: string): any {
    const { log } = this.deps;
    log.debug("Entering TokenZcap.jcsLoader().");
    const root = lib.zcap.createRootCapability({
      controller: controller, invocationTarget: rootTarget });
    log.debug("Leaving TokenZcap.jcsLoader().");
    return lib.zcap.extendDocumentLoader(async function jcsOfflineLoader(
        documentUrl) {
      log.debug("Entering jcsOfflineLoader().");
      if (documentUrl === root.id) {
        log.debug("Leaving jcsOfflineLoader().");
        return { contextUrl: null, documentUrl: documentUrl, document: root,
                 tag: 'static' };
      }
      log.debug("Leaving jcsOfflineLoader().");
      throw new Error('the offline ZCAP document loader serves no document ' +
                      'at ' + documentUrl);
    });
  }

  // -------------------------------------------------------------------------
  // A JSONLD-SIGNATURES SUITE OVER `vc_data_integrity.ts`. jsonld-signatures
  // asks a suite for four things — `ensureSuiteContext()`, `createProof()`,
  // `matchProof()` and `verifyProof()` — and hands a JCS proof over
  // unmodified (its `_getProofs()` special-cases "-jcs-"). The proof purpose
  // puts `proofPurpose` and `capabilityChain` on the proof before it is
  // signed, so both are covered.
  //
  // `verifyProof()` answers the verification method as { id, controller },
  // which is what the purpose checks against the parent capability's
  // controller (ZCAP) and against the controller document's
  // `capabilityDelegation` (jsonld-signatures' ControllerProofPurpose).
  // -------------------------------------------------------------------------
  private jcsSuite(suite: string, keys: any, created: string,
                   nowMs: number): any {
    const { log, dataIntegrity } = this.deps;
    log.debug("Entering TokenZcap.jcsSuite(). suite=" + suite);
    const methods: Record<string, any> = {};
    methods[keys.keyId] = keys.publicJwk;
    const controller = keys.controller;
    log.debug("Leaving TokenZcap.jcsSuite().");
    return {
      type: 'DataIntegrityProof',
      cryptosuite: suite,
      ensureSuiteContext: function ensureSuiteContext(
          options: any): void {
        log.debug("Entering ensureSuiteContext().");
        const context = [].concat((options && options.document &&
                                   options.document['@context']) || []);
        if (context.indexOf(DATA_INTEGRITY_V2_URL) < 0) {
          log.debug("Leaving ensureSuiteContext(). Missing.");
          throw new TypeError('a DataIntegrityProof capability names the ' +
                              'context ' + DATA_INTEGRITY_V2_URL + '.');
        }
        log.debug("Leaving ensureSuiteContext().");
      },
      matchProof: async function matchProof(options: any): Promise<boolean> {
        log.debug("Entering matchProof().");
        const proof = options && options.proof;
        log.debug("Leaving matchProof().");
        return !!proof && proof.type === 'DataIntegrityProof' &&
               proof.cryptosuite === suite;
      },
      createProof: async function createProof(options: any): Promise<any> {
        log.debug("Entering createProof().");
        let proof: any = { type: 'DataIntegrityProof', cryptosuite: suite,
                           created: created,
                           verificationMethod: keys.keyId };
        proof = await options.purpose.update(proof, {
          document: options.document, suite: this,
          documentLoader: options.documentLoader });
        const signed = await dataIntegrity.signDocument(options.document, {
          cryptosuite: suite,
          publicJwk: keys.publicJwk,
          privateKey: keys.privateKey,
          verificationMethod: keys.keyId,
          proofPurpose: proof.proofPurpose,
          created: created,
          proofMembers: { capabilityChain: proof.capabilityChain }
        });
        log.debug("Leaving createProof().");
        return signed.proof;
      },
      verifyProof: async function verifyProof(options: any): Promise<any> {
        log.debug("Entering verifyProof().");
        const secured = Object.assign({}, options.document,
                                      { proof: options.proof });
        const result = await dataIntegrity.verifyProof(secured, {
          allowedCryptosuites: [suite],
          expectedPurpose: 'capabilityDelegation',
          // A delegation proof carries neither (ZCAP-LD); `null` says so.
          expectedChallenge: null,
          expectedDomain: null,
          now: nowMs,
          resolveVerificationMethod: function resolveVerificationMethod(
              vm: unknown): any {
            log.debug("Entering resolveVerificationMethod().");
            const id = typeof vm === 'string' ? vm : '';
            if (!Object.prototype.hasOwnProperty.call(methods, id)) {
              log.debug("Leaving resolveVerificationMethod(). Not ours.");
              throw new Error('the proof names "' + id + '", which is not ' +
                              'this authorization server\'s key.');
            }
            log.debug("Leaving resolveVerificationMethod().");
            return { jwk: methods[id], controller: controller };
          }
        });
        if (!result.ok) {
          const why = result.checks.filter(function (c: any) {
            return !c.ok;
          }).map(function (c: any) {
            return c.name + ': ' + c.detail;
          }).join('; ');
          log.debug("Leaving verifyProof(). Refused.");
          return { verified: false, error: new Error(why) };
        }
        log.debug("Leaving verifyProof(). Verified.");
        return { verified: true,
                 verificationMethod: { id: result.verificationMethod,
                                       type: 'Multikey',
                                       controller: controller } };
      }
    };
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
    const chosen = this.suiteOf(keys);
    if (!chosen.ok) {
      log.debug("Leaving TokenZcap.controllerDocument(). Suite refused.");
      return chosen;
    }
    if (chosen.suite !== LEGACY_SUITE) {
      const built = this.jcsControllerDocument(keys, chosen.suite);
      log.debug("Leaving TokenZcap.controllerDocument(). " + chosen.suite);
      return built.ok ? built.document : built;
    }
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
    const document = this.controllerDocumentFor(libs.lib, publicKeys,
                                                pair.pair);
    // THE OTHER GENERATIONS OF THE KEY (#49 P5, D6): the next key and the
    // retired ones still verifying, each a verification method of its own,
    // so a capability signed before a rotation still resolves here. The
    // current one stays first.
    const others = Array.isArray(publicKeys.others) ? publicKeys.others : [];
    for (let i = 0; i < others.length; i++) {
      const one = Object.assign({ controller: publicKeys.controller },
                                others[i]);
      const extra = await this.keyPairOf(libs.lib, one, false);
      if (!extra.ok) {
        continue;
      }
      document.verificationMethod.push(extra.pair.export({
        publicKey: true, includeContext: false }));
      document.assertionMethod.push(one.keyId);
      document.capabilityDelegation.push(one.keyId);
    }
    log.debug("Leaving TokenZcap.controllerDocument().");
    return document;
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

  // The unsigned capability for a validated model, in a suite's context.
  private capabilityFor(model: any, suite: string): Record<string, any> {
    const { log, access } = this.deps;
    log.debug("Entering TokenZcap.capabilityFor().");
    const target = this.targetFor(model);
    const cap: Record<string, any> = {
      '@context': this.contextFor(suite),
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
  // mint(model, keys): keys = { cryptosuite, privateKey, controller, keyId }
  // plus, for a JCS suite, `publicJwk` (derived from an Ed25519 publicKey
  // when absent; the compatibility suite derives its publicKey from the
  // private one).
  // -------------------------------------------------------------------------
  async mint(model: any, keys: any): Promise<any> {
    const { log, errorCodes, access, crypto } = this.deps;
    log.debug("Entering TokenZcap.mint().");
    const valid = access.validateModel(model);
    if (!valid.ok) {
      log.debug("Leaving TokenZcap.mint(). Model invalid.");
      return valid;
    }
    const chosen = this.suiteOf(keys);
    if (!chosen.ok) {
      log.debug("Leaving TokenZcap.mint(). Suite refused.");
      return chosen;
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
    const cap = this.capabilityFor(valid.model, chosen.suite);
    let suiteObject;
    let documentLoader;
    if (chosen.suite === LEGACY_SUITE) {
      const signing = await this.keyPairOf(lib, keys, true);
      if (!signing.ok) {
        log.debug("Leaving TokenZcap.mint(). Signing key unusable.");
        return signing;
      }
      const publicKeys = Object.assign({}, keys,
                                       { publicKey: crypto.createPublicKey(
                                           keys.privateKey) });
      const verifying = await this.keyPairOf(lib, publicKeys, false);
      suiteObject = new lib.Ed25519Signature2020({
        key: signing.pair, date: new Date(valid.model.iat * 1000) });
      documentLoader = this.documentLoaderFor(lib, publicKeys,
                                              verifying.pair, target);
    } else {
      const signingKeys = this.jcsKeysOf(keys, chosen.suite, true);
      if (!signingKeys.ok) {
        log.debug("Leaving TokenZcap.mint(). Signing key unusable.");
        return signingKeys;
      }
      suiteObject = this.jcsSuite(chosen.suite, signingKeys,
                                  this.isoSeconds(valid.model.iat),
                                  valid.model.iat * 1000);
      documentLoader = this.jcsLoader(lib, signingKeys.controller, target);
    }
    let signed;
    try {
      signed = await lib.jsigs.sign(cap, {
        suite: suiteObject,
        purpose: new lib.zcap.CapabilityDelegation(
            { parentCapability: cap.parentCapability }),
        documentLoader: documentLoader
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
    log.debug("Leaving TokenZcap.mint(). jti=" + valid.model.jti + ", " +
              chosen.suite);
    return { value: value, format: FORMAT, jti: valid.model.jti,
             cryptosuite: chosen.suite };
  }

  private decodeValue(value: unknown, suite: string): any {
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
    // THE SUITE BEFORE THE CONTEXT, so that a token of another suite is
    // named as that (STS-GNAP-0336) rather than as a wrong context. A proof
    // SET is refused too: this format writes one proof, and a second one
    // would be a proof nothing here checks.
    const proof = doc.proof;
    const proofSuite = proof && typeof proof === 'object' &&
                       !Array.isArray(proof)
      ? (proof.type === 'DataIntegrityProof' ? proof.cryptosuite : proof.type)
      : undefined;
    if (proofSuite !== suite) {
      log.debug("Leaving TokenZcap.decodeValue(). Suite " + proofSuite +
                " is not " + suite + ".");
      return this.refusal('STS-GNAP-0336', 'the capability\'s proof is ' +
                          (typeof proofSuite === 'string' ? '"' + proofSuite +
                           '"' : 'not one proof of a known kind') +
                          '; this realm signs and accepts zcap tokens with ' +
                          suite + ' only (gnap.zcapCryptosuite).');
    }
    if (access.canonicalJson(doc['@context']) !==
        access.canonicalJson(this.contextFor(suite))) {
      log.debug("Leaving TokenZcap.decodeValue(). Context is not the pinned " +
                "one.");
      return this.refusal('STS-GNAP-0332', 'the capability\'s @context is ' +
                          'not exactly the GNAP ZCAP context for ' + suite +
                          ', so what was signed and what would be read ' +
                          'could differ.');
    }
    log.debug("Leaving TokenZcap.decodeValue(). Decoded.");
    return { ok: true, doc: doc };
  }

  // -------------------------------------------------------------------------
  // The GNAP terms back into a model, and every derived member checked
  // against the model it should derive from.
  // -------------------------------------------------------------------------
  private readModel(doc: any, suite: string): any {
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
    const expected = this.capabilityFor(valid.model, suite);
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
  // keys = { cryptosuite, controller, keyId } plus `publicKey` (an Ed25519
  // KeyObject) or `publicJwk` — one generation of the realm's key; the caller
  // tries each live generation in turn.
  // -------------------------------------------------------------------------
  async verify(value: unknown, keys: any, context?: any): Promise<any> {
    const { log, access, nowSec } = this.deps;
    log.debug("Entering TokenZcap.verify().");
    const chosen = this.suiteOf(keys);
    if (!chosen.ok) {
      log.debug("Leaving TokenZcap.verify(). Suite refused.");
      return chosen;
    }
    const decoded = this.decodeValue(value, chosen.suite);
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
    let options;
    if (chosen.suite === LEGACY_SUITE) {
      const verifying = await this.keyPairOf(lib, keys, false);
      if (!verifying.ok) {
        log.debug("Leaving TokenZcap.verify(). Verification key unusable.");
        return verifying;
      }
      options = {
        suite: new lib.Ed25519Signature2020(),
        purpose: new lib.zcap.CapabilityDelegation({
          expectedRootCapability: this.rootIdFor(doc.invocationTarget),
          allowTargetAttenuation: true,
          date: new Date(now * 1000)
        }),
        documentLoader: this.documentLoaderFor(lib, keys, verifying.pair,
                                               doc.invocationTarget)
      };
    } else {
      const verifyingKeys = this.jcsKeysOf(keys, chosen.suite, false);
      if (!verifyingKeys.ok) {
        log.debug("Leaving TokenZcap.verify(). Verification key unusable.");
        return verifyingKeys;
      }
      // The controller is the document built from THIS generation of the
      // key, handed to the purpose rather than loaded: it is this service's
      // own, and ControllerProofPurpose then reads its
      // `capabilityDelegation` directly instead of framing a document it
      // would have to fetch (and whose context it would have to load).
      const controllerDoc = this.jcsControllerDocument(
          { cryptosuite: chosen.suite, controller: verifyingKeys.controller,
            keyId: verifyingKeys.keyId, publicJwk: verifyingKeys.publicJwk },
          chosen.suite);
      options = {
        suite: this.jcsSuite(chosen.suite, verifyingKeys, '', now * 1000),
        purpose: new lib.zcap.CapabilityDelegation({
          expectedRootCapability: this.rootIdFor(doc.invocationTarget),
          allowTargetAttenuation: true,
          date: new Date(now * 1000),
          controller: controllerDoc.document
        }),
        documentLoader: this.jcsLoader(lib, verifyingKeys.controller,
                                       doc.invocationTarget)
      };
    }
    let result;
    try {
      result = await lib.jsigs.verify(doc, options);
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
    const read = this.readModel(doc, chosen.suite);
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
    log.debug("Leaving TokenZcap.verify(). Verified jti=" + read.model.jti +
              ", " + chosen.suite);
    return { ok: true, model: read.model, attenuated: false,
             cryptosuite: chosen.suite };
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
        ['Proof suite', ['DataIntegrityProof eddsa-jcs-2022 (default)',
                         'DataIntegrityProof mldsa44-jcs-2024',
                         'DataIntegrityProof slhdsa128-jcs-2024',
                         'Ed25519Signature2020 (compatibility)']],
        ['Canonicalisation', ['JSON Canonicalization Scheme (RFC 8785)',
                              'RDF Dataset Canonicalization (URDNA2015), ' +
                              'Ed25519Signature2020 only']],
        ['Digest', ['SHA-256']],
        ['Signature', ['Ed25519', 'ML-DSA-44', 'SLH-DSA-SHA2-128s']],
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

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before. The importer is the old
  // module-level load, unchanged: three ES modules by dynamic import and two
  // CommonJS packages by require, all at the first call that needs them.
  static defaultDeps(): TokenZcapDeps {
    helpers.log.debug("Entering TokenZcap.defaultDeps().");
    helpers.log.debug("Leaving TokenZcap.defaultDeps().");
    return {
      log: helpers.log,
      nowSec: function () {
        return helpers.nowSec();
      },
      errorCodes: errorCodes,
      access: gnapAccess,
      crypto: crypto,
      dataIntegrity: dataIntegrity,
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
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<TokenZcap>(
  'gnap/token_zcap',
  () => new TokenZcap(TokenZcap.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  TokenZcap: TokenZcap,
  installInstance: (instance: TokenZcap): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  FORMAT: TokenZcap.FORMAT,
  CONTEXT: TokenZcap.CONTEXT,
  LEGACY_CONTEXT: TokenZcap.LEGACY_CONTEXT,
  CRYPTOSUITES: TokenZcap.CRYPTOSUITES,
  DEFAULT_CRYPTOSUITE: TokenZcap.DEFAULT_CRYPTOSUITE,
  LEGACY_SUITE: TokenZcap.LEGACY_SUITE,
  mint: slot.forward('mint'),
  verify: slot.forward('verify'),
  describe: slot.forward('describe'),
  controllerDocument: slot.forward('controllerDocument'),
  controllerFor: slot.forward('controllerFor')
};
