'use strict';
//
// File: token_zcap.js
//
// ===========================================================================
// THE `zcap` GNAP TOKEN FORMAT (RFC 9767 SECTION 5.3.2): A ZCAP-LD DELEGATED
// CAPABILITY SIGNED Ed25519Signature2020 BY THE AUTHORIZATION SERVER
// (2026-09-12).
//
// A route-free library: it registers nothing and requires `common/helpers.js`,
// `common/error_codes.js` and `gnap/gnap_access.js`. The Digital Bazaar ZCAP
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

const crypto = require('crypto');
const helpers = require('../common/helpers');
const errorCodes = require('../common/error_codes');
const access = require('./gnap_access');

const log = helpers.log;

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

let loading = null;

function refusal(code, why) {
  log.debug("Entering refusal().");
  log.debug("Leaving refusal().");
  return access.refusal(code, why);
}

// ---------------------------------------------------------------------------
// The lazy load of the ES modules. A failure clears the promise so a later
// call may try again (the biscuit loader's reasoning).
// ---------------------------------------------------------------------------
function loadLibraries() {
  log.debug("Entering loadLibraries().");
  if (!loading) {
    loading = Promise.all([
      import('@digitalbazaar/zcap'),
      import('@digitalbazaar/ed25519-signature-2020'),
      import('@digitalbazaar/ed25519-verification-key-2020')
    ]).then(function (mods) {
      const security = require('@digitalbazaar/security-context');
      return {
        jsigs: require('jsonld-signatures'),
        zcap: mods[0],
        Ed25519Signature2020: mods[1].Ed25519Signature2020,
        suiteContext: mods[1].suiteContext,
        Ed25519VerificationKey2020: mods[2].Ed25519VerificationKey2020,
        securityContexts: security.contexts
      };
    }).catch(function (e) {
      loading = null;
      throw e;
    });
  }
  log.debug("Leaving loadLibraries().");
  return loading;
}

async function libraries() {
  log.debug("Entering libraries().");
  try {
    log.debug("Leaving libraries().");
    return { ok: true, lib: await loadLibraries() };
  } catch (e) {
    log.error(errorCodes.tag('STS-GNAP-0331') + 'the ZCAP libraries could ' +
                                                'not be loaded: ' + e.message);
    log.debug("Leaving libraries().");
    return refusal('STS-GNAP-0331',
                   'the ZCAP libraries could not be loaded: ' + e.message);
  }
}

function isAbsoluteUrl(value) {
  log.debug("Entering isAbsoluteUrl().");
  if (typeof value !== 'string') {
    log.debug("Leaving isAbsoluteUrl().");
    return false;
  }
  try {
    const u = new URL(value);
    log.debug("Leaving isAbsoluteUrl().");
    return !!u.protocol && !u.hash;
  } catch (e) {
    log.debug("Caught in isAbsoluteUrl(): " + ((e && e.message) || e));
    log.debug("Leaving isAbsoluteUrl().");
    // Not a URL; `false` is the answer.
    return false;
  }
}

// ---------------------------------------------------------------------------
// The keys, validated and turned into Ed25519VerificationKey2020 instances.
// `wantPrivate` asks for the signing half.
// ---------------------------------------------------------------------------
async function keyPairOf(lib, keys, wantPrivate) {
  log.debug("Entering keyPairOf(). wantPrivate=" + wantPrivate);
  const k = keys || {};
  if (!isAbsoluteUrl(k.controller) || typeof k.keyId !== 'string' ||
      k.keyId.indexOf(k.controller + '#') !== 0 ||
      k.keyId.length === k.controller.length + 1) {
    log.debug("Leaving keyPairOf(). controller / keyId unusable.");
    return refusal('STS-GNAP-0330', 'ZCAP keys need an absolute controller ' +
                   'URL and a keyId of <controller>#<fragment>.');
  }
  const keyObject = wantPrivate ? k.privateKey : k.publicKey;
  if (!keyObject || typeof keyObject.export !== 'function' ||
      keyObject.asymmetricKeyType !== 'ed25519') {
    log.debug("Leaving keyPairOf(). Not an Ed25519 KeyObject.");
    return refusal('STS-GNAP-0330',
                   'a ZCAP token is ' + (wantPrivate ? 'signed ' +
        'with an Ed25519 private' :
                   'verified with an Ed25519 public') + ' KeyObject.');
  }
  const jwk = keyObject.export({ format: 'jwk' });
  let pair;
  if (wantPrivate) {
    // The seed IS the private key: generating from it reproduces the node key.
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
  log.debug("Leaving keyPairOf(). Ready.");
  return { ok: true, pair: pair };
}

function controllerDocumentFor(lib, keys, publicPair) {
  log.debug("Entering controllerDocumentFor().");
  log.debug("Leaving controllerDocumentFor().");
  return {
    '@context': [SECURITY_V2_URL, SUITE_CONTEXT_URL],
    id: keys.controller,
    verificationMethod: [publicPair.export({ publicKey: true,
                                             includeContext: false })],
    assertionMethod: [keys.keyId],
    capabilityDelegation: [keys.keyId]
  };
}

// ---------------------------------------------------------------------------
// controllerDocument(keys): the document the AS publishes at
// `/gnap/zcap/controller`. Asynchronous because the key classes are ES
// modules. Returns the document, or a refusal when the keys are unusable.
// ---------------------------------------------------------------------------
async function controllerDocument(keys) {
  log.debug("Entering controllerDocument().");
  const libs = await libraries();
  if (!libs.ok) {
    log.debug("Leaving controllerDocument(). Libraries unavailable.");
    return libs;
  }
  const publicKeys = Object.assign({}, keys || {});
  if (!publicKeys.publicKey && publicKeys.privateKey) {
    publicKeys.publicKey = crypto.createPublicKey(publicKeys.privateKey);
  }
  const pair = await keyPairOf(libs.lib, publicKeys, false);
  if (!pair.ok) {
    log.debug("Leaving controllerDocument(). Keys unusable.");
    return pair;
  }
  log.debug("Leaving controllerDocument().");
  return controllerDocumentFor(libs.lib, publicKeys, pair.pair);
}

function rootIdFor(target) {
  log.debug("Entering rootIdFor().");
  log.debug("Leaving rootIdFor().");
  return ROOT_PREFIX + encodeURIComponent(target);
}

// ---------------------------------------------------------------------------
// The offline document loader (see the header). `rootTarget` is the one
// invocation target whose root capability may load.
// ---------------------------------------------------------------------------
function documentLoaderFor(lib, keys, publicPair, rootTarget) {
  log.debug("Entering documentLoaderFor().");
  const controllerDoc = controllerDocumentFor(lib, keys, publicPair);
  const root = lib.zcap.createRootCapability({ controller: keys.controller,
                                               invocationTarget: rootTarget });
  function answer(documentUrl, document) {
    log.debug("Entering answer().");
    log.debug("Leaving answer().");
    return { contextUrl: null, documentUrl: documentUrl, document: document,
             tag: 'static' };
  }
  log.debug("Leaving documentLoaderFor().");
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
    throw new Error('the offline ZCAP document loader serves no document at ' +
                    documentUrl);
  });
}

function controllerFor(cnf) {
  log.debug("Entering controllerFor().");
  if (!cnf) {
    log.debug("Leaving controllerFor().");
    return BEARER_CONTROLLER;
  }
  const member = Object.keys(cnf)[0];
  const value = member === 'kid' ? encodeURIComponent(cnf.kid) : cnf[member];
  log.debug("Leaving controllerFor().");
  return CONTROLLER_PREFIXES[member] + value;
}

// An audience is a resource server's IDENTIFIER, which RFC 9767 does not
// require to be a URI — an application entry's identifier usually is not — and
// a ZCAP invocationTarget must be one. So a non-URI audience is carried as a
// URN of its own rather than refused: refusing it made a zcap token impossible
// for every resource server registered under a plain name.
const RS_TARGET_PREFIX = 'urn:gnap:rs:';

function targetFor(model) {
  log.debug("Entering targetFor().");
  if (!model.aud.length) {
    log.debug("Leaving targetFor().");
    return AS_TARGET_PREFIX + model.iss;
  }
  const first = String(model.aud[0]);
  log.debug("Leaving targetFor().");
  return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(first) ? first :
         RS_TARGET_PREFIX + encodeURIComponent(first);
}

function actionsOf(rights) {
  log.debug("Entering actionsOf().");
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
  log.debug("Leaving actionsOf(). " + out.length + " action(s).");
  return out;
}

function isoSeconds(seconds) {
  log.debug("Entering isoSeconds().");
  log.debug("Leaving isoSeconds().");
  return new Date(seconds * 1000).toISOString().replace(/\.000Z$/, 'Z');
}

// The unsigned capability for a validated model.
function capabilityFor(model) {
  log.debug("Entering capabilityFor().");
  const target = targetFor(model);
  const cap = {
    '@context': CONTEXT,
    id: ID_PREFIX + encodeURIComponent(model.jti),
    parentCapability: rootIdFor(target),
    invocationTarget: target,
    controller: controllerFor(model.cnf),
    expires: isoSeconds(model.exp)
  };
  const actions = actionsOf(model.access);
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
  log.debug("Leaving capabilityFor().");
  return cap;
}

// ---------------------------------------------------------------------------
// mint(model, keys): keys = { privateKey, controller, keyId } (publicKey is
// derived when absent).
// ---------------------------------------------------------------------------
async function mint(model, keys) {
  log.debug("Entering mint().");
  const valid = access.validateModel(model);
  if (!valid.ok) {
    log.debug("Leaving mint(). Model invalid.");
    return valid;
  }
  const target = targetFor(valid.model);
  if (!/^[A-Za-z][A-Za-z0-9+.-]*:/.test(target)) {
    log.debug("Leaving mint(). Target is not an absolute URI.");
    return refusal('STS-GNAP-0330', 'a ZCAP invocationTarget must be an ' +
                   'absolute URI, and the token\'s first audience ' +
                   '"' + target + '" is not one.');
  }
  const libs = await libraries();
  if (!libs.ok) {
    log.debug("Leaving mint(). Libraries unavailable.");
    return libs;
  }
  const lib = libs.lib;
  const signing = await keyPairOf(lib, keys, true);
  if (!signing.ok) {
    log.debug("Leaving mint(). Signing key unusable.");
    return signing;
  }
  const publicKeys = Object.assign({}, keys,
                                   { publicKey: crypto.createPublicKey(
                                       keys.privateKey) });
  const verifying = await keyPairOf(lib, publicKeys, false);
  const cap = capabilityFor(valid.model);
  let signed;
  try {
    signed = await lib.jsigs.sign(cap, {
      suite: new lib.Ed25519Signature2020({ key: signing.pair,
                                            date: new Date(
                                                valid.model.iat * 1000) }),
      purpose: new lib.zcap.CapabilityDelegation(
          { parentCapability: cap.parentCapability }),
      documentLoader: documentLoaderFor(lib, publicKeys, verifying.pair, target)
    });
  } catch (e) {
    log.warn(errorCodes.tag('STS-GNAP-0335') + 'ZCAP signing failed in the ' +
                                               'library: ' + e.message);
    log.debug("Leaving mint(). Library failure.");
    return refusal('STS-GNAP-0335', 'the ZCAP libraries refused to sign the ' +
                                    'capability: ' + e.message);
  }
  const value = Buffer.from(JSON.stringify(signed), 'utf8')
                      .toString('base64url');
  log.debug("Leaving mint(). jti=" + valid.model.jti);
  return { value: value, format: FORMAT, jti: valid.model.jti };
}

function decodeValue(value) {
  log.debug("Entering decodeValue().");
  if (typeof value !== 'string' || !VALUE_RE.test(value)) {
    log.debug("Leaving decodeValue(). Not base64url.");
    return refusal('STS-GNAP-0332',
                   'the token value is not unpadded base64url.');
  }
  let doc;
  try {
    doc = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
  } catch (e) {
    log.debug("Caught in decodeValue(): " + ((e && e.message) || e));
    log.debug("Leaving decodeValue(). Not JSON.");
    return refusal('STS-GNAP-0332', 'the token value is not base64url JSON.');
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    log.debug("Leaving decodeValue(). Not an object.");
    return refusal('STS-GNAP-0332', 'the token value is not a JSON object.');
  }
  const extra = Object.keys(doc)
                      .filter(function (k) { return MEMBERS.indexOf(k) < 0; });
  if (extra.length) {
    log.debug("Leaving decodeValue(). Unknown members.");
    return refusal('STS-GNAP-0332', 'the capability carries members this ' +
                                    'format does not write: ' +
                   extra.join(', ') + '.');
  }
  if (access.canonicalJson(doc['@context']) !== access.canonicalJson(CONTEXT)) {
    log.debug("Leaving decodeValue(). Context is not the pinned one.");
    return refusal('STS-GNAP-0332', 'the capability\'s @context is not ' +
                   'exactly the GNAP ZCAP context, so what was signed and ' +
                   'what would be read could differ.');
  }
  log.debug("Leaving decodeValue(). Decoded.");
  return { ok: true, doc: doc };
}

// ---------------------------------------------------------------------------
// The GNAP terms back into a model, and every derived member checked against
// the model it should derive from.
// ---------------------------------------------------------------------------
function readModel(doc) {
  log.debug("Entering readModel().");
  function bad(why) {
    log.debug("Entering bad().");
    log.debug("Leaving readModel(). " + why);
    return refusal('STS-GNAP-0334', 'the capability\'s GNAP terms are ' +
                                    'inconsistent: ' + why + '.');
  }
  if (typeof doc.id !== 'string' || doc.id.indexOf(ID_PREFIX) !== 0) {
    log.debug("Leaving readModel().");
    return bad('its id is not ' + ID_PREFIX + '<jti>');
  }
  let jti;
  try {
    jti = decodeURIComponent(doc.id.slice(ID_PREFIX.length));
  } catch (e) {
    log.debug("Caught in readModel(): " + ((e && e.message) || e));
    log.debug("Leaving readModel().");
    return bad('its id is not percent-encoded');
  }
  const exp = Date.parse(doc.expires);
  let cnf = null;
  if (doc.gnapCnf !== 'bearer') {
    cnf = access.cnfFromString(doc.gnapCnf);
    if (!cnf) {
      log.debug("Leaving readModel().");
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
    log.debug("Leaving readModel().");
    return bad('they are not a valid token model (' + valid.why + ')');
  }
  const expected = capabilityFor(valid.model);
  const derived = ['id', 'parentCapability', 'invocationTarget', 'controller',
                   'expires', 'allowedAction'];
  for (let i = 0; i < derived.length; i++) {
    const name = derived[i];
    if (access.canonicalJson(doc[name]) !== access.canonicalJson(
        expected[name])) {
      log.debug("Leaving readModel().");
      return bad('"' + name + '" is not the value the GNAP terms derive');
    }
  }
  log.debug("Leaving readModel(). Read.");
  return valid;
}

// ---------------------------------------------------------------------------
// verify(value, keys, context) -> { ok:true, model } | refusal.
// keys = { publicKey, controller, keyId }.
// ---------------------------------------------------------------------------
async function verify(value, keys, context) {
  log.debug("Entering verify().");
  const decoded = decodeValue(value);
  if (!decoded.ok) {
    log.debug("Leaving verify(). Decode refused.");
    return decoded;
  }
  const doc = decoded.doc;
  const ctx = context || {};
  const now = Number.isSafeInteger(ctx.now) ? ctx.now : helpers.nowSec();
  if (typeof doc.invocationTarget !== 'string' || !doc.invocationTarget) {
    log.debug("Leaving verify(). No target.");
    return refusal('STS-GNAP-0334',
                   'the capability names no invocationTarget.');
  }
  const libs = await libraries();
  if (!libs.ok) {
    log.debug("Leaving verify(). Libraries unavailable.");
    return libs;
  }
  const lib = libs.lib;
  const verifying = await keyPairOf(lib, keys, false);
  if (!verifying.ok) {
    log.debug("Leaving verify(). Verification key unusable.");
    return verifying;
  }
  let result;
  try {
    result = await lib.jsigs.verify(doc, {
      suite: new lib.Ed25519Signature2020(),
      purpose: new lib.zcap.CapabilityDelegation({
        expectedRootCapability: rootIdFor(doc.invocationTarget),
        allowTargetAttenuation: true,
        date: new Date(now * 1000)
      }),
      documentLoader: documentLoaderFor(lib, keys, verifying.pair,
                                        doc.invocationTarget)
    });
  } catch (e) {
    // jsigs reports through `result`; a throw is malformed input it could not
    // even start on, which is the same answer for the caller.
    result = { verified: false, error: e };
  }
  if (!result || !result.verified) {
    const errors = result && result.error ?
                   (result.error.errors || [result.error]) : [];
    const why = errors.map(function (e) {
      return e && e.message && e.message.replace(/\.$/, '');
    })
      .filter(Boolean).join('; ');
    log.debug("Leaving verify(). Proof refused: " + why);
    return refusal('STS-GNAP-0333', 'the capability\'s delegation proof does ' +
                   'not verify under this authorization server\'s ' +
                   'key' + (why ? ': ' + why : '') + '.');
  }
  const read = readModel(doc);
  if (!read.ok) {
    log.debug("Leaving verify(). Model refused.");
    return read;
  }
  const failed = access.checkPresentation(read.model,
                                          Object.assign({}, ctx, { now: now }));
  if (failed) {
    log.debug("Leaving verify(). Presentation refused.");
    return failed;
  }
  log.debug("Leaving verify(). Verified jti=" + read.model.jti);
  return { ok: true, model: read.model, attenuated: false };
}

function describe() {
  log.debug("Entering describe().");
  const out = {
    name: FORMAT,
    libraries: ['@digitalbazaar/zcap', '@digitalbazaar/zcap-context',
                'jsonld-signatures', 'jsonld',
                '@digitalbazaar/ed25519-signature-2020',
                '@digitalbazaar/ed25519-verification-key-2020',
                '@digitalbazaar/security-context'].map(access.libraryInfo),
    algorithms: [
      ['Proof suite', ['Ed25519Signature2020']],
      ['Canonicalisation', ['RDF Dataset Canonicalization (URDNA2015)']],
      ['Digest', ['SHA-256']],
      ['Signature', ['Ed25519']],
      ['Proof purpose', ['capabilityDelegation, one link from a root the AS ' +
                         'controls']],
      ['Serialisation', ['JSON-LD, unpadded base64url']]
    ],
    carries: ['jti', 'iss', 'sub', 'aud', 'instanceId', 'access', 'flags',
              'cnf',
              'iat', 'nbf', 'exp', 'label'],
    cannot: []
  };
  log.debug("Leaving describe().");
  return out;
}

module.exports = {
  FORMAT: FORMAT,
  CONTEXT: CONTEXT,
  mint: mint,
  verify: verify,
  describe: describe,
  controllerDocument: controllerDocument,
  controllerFor: controllerFor
};
