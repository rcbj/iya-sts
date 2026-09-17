'use strict';
//
// File: gnap_httpsig.ts
//
// ---------------------------------------------------------------------------
// HTTP MESSAGE SIGNATURES (RFC 9421) AND CONTENT-DIGEST (RFC 9530): THE
// `httpsig` PROOF METHOD OF GNAP (RFC 9635 SECTION 7.3.1).
//
// GNAP binds a client instance to a KEY rather than to a secret, and the
// commonest way it proves possession of that key is to sign the HTTP request
// itself: the method, the target URI, the Content-Digest of the body and — once
// a token is bound — the Authorization header, with `tag="gnap"` and a
// `created` timestamp the verifier checks. This module is the whole of that
// mechanism and none of the GNAP policy around it: it builds a signature base,
// signs one, parses the two fields a signature travels in, and verifies — and
// it is told by its caller which components are required, which tag, how old a
// signature may be and which key a `keyid` names. `gnap/gnap_proof.ts` is where
// those answers are decided.
//
// ---------------------------------------------------------------------------
// THE SIGNATURE BASE IS THE WHOLE GAME, AND IT IS EASY TO GET RIGHT ENOUGH TO
// BE WRONG.
//
// An HTTP signature is a signature over a string neither party transmits. The
// signer builds it out of the message, the verifier builds it again out of the
// message it RECEIVED, and the two strings must agree byte for byte. Every
// place the two builds can diverge is a place a correct signature fails — or,
// worse, a place two different messages build the same string and one
// signature covers both. RFC 9421 section 2 is therefore a list of
// canonicalization rules, and each is implemented where it is stated and cited
// by number:
//
//   * a field value is STRIPPED, has obsolete line folding replaced by one
//     space, and repeated field lines are joined with exactly ", " (2.1);
//   * `@authority` and `@scheme` are LOWERCASED and the default port omitted
//     (2.2.3, 2.2.4), while `@method` is NOT — the method is case-sensitive
//     (2.2.1);
//   * `@path` and `@query` are the RAW, still-percent-encoded text of the
//     target URI (2.2.6, 2.2.7), and an absent query is `?`, not the empty
//     string — so a signature over a URI with no query cannot be moved to the
//     same URI with `?` appended... except that it can, and the specification
//     says so, which is why `@query` is not what GNAP requires;
//   * `@query-param` is DECODED AND RE-ENCODED (2.2.8), so that `+` and `%20`
//     sign alike, and a parameter named twice is an ERROR rather than the first
//     one — the ambiguity is exactly the one an attacker would choose;
//   * `;sf` and `;key=` re-serialize through `gnap/gnap_sf.ts` (2.1.1, 2.1.2)
//     and `;bs` wraps each field line as a Byte Sequence (2.1.3);
//   * a component identifier may appear ONCE (2.5 step 2.1), and equality
//     ignores parameter ORDER while serialization preserves it (2).
//
// `@signature-params` is always the last line and is never in the covered list,
// because it is what makes a signature cover its own metadata (2.3) — a
// verifier that let a signer list it, or let an attacker drop `created` from
// it, would be checking a timestamp the signature does not cover.
//
// ---------------------------------------------------------------------------
// WHAT IS REFUSED RATHER THAN IMPLEMENTED, AND WHY EACH IS A REFUSAL.
//
//   * `;req` (2.4) — it names a component of the REQUEST a RESPONSE answered,
//     and a request verifier has no such request. Deriving it from the message
//     itself would sign the wrong message's value and verify.
//   * `;tr` (2.1.4) — the message model here has no trailer section, and a
//     trailer read out of the header section is the confusion 2.1.4 forbids
//     ("MUST NOT be combined").
//   * `@status` on a REQUEST (2.2.9, "MUST NOT be used in a request message").
//     On a message that carries a `status` it is derived, because Appendix
//     B.2.4 is a response vector and a test that skipped it would be a test of
//     five vectors of six.
//   * `;sf` or `;key=` on a field whose Structured Field type this module does
//     not know. Section 2.1.1 says the flag "will produce an error" then, and
//     guessing a type is two parsers disagreeing about one value. Callers name
//     further types with `options.fieldTypes`.
//
// ---------------------------------------------------------------------------
// ALGORITHMS: SECTION 3.3's SIX, AND THE JWS ONES SECTION 3.3.7 ADMITS.
//
// GNAP's string-form proof (`"proof": "httpsig"`) derives the algorithm from
// the key — from a JWK's `alg` — so this module accepts RFC 7518's names as
// algorithms in their own right and applies section 3.3.7's two rules to them:
// the signature base is the JWS Signing Input as-is, and the `alg` signature
// PARAMETER is never used with one ("JWA values ... are not included as
// signature parameters"). A JWS algorithm arriving as that parameter is
// therefore unknown, and a JWS key with any `alg` parameter beside it is a
// conflict; RFC 9635 section 7.3.1 forbids the parameter outright, which is the
// caller's `forbidAlgParam`.
//
// Three representation choices that decide interoperability and are easy to
// get wrong: ECDSA signatures are r||s at the curve's coordinate size (IEEE
// P1363, node's `dsaEncoding: 'ieee-p1363'`) and never DER (3.3.4); RSASSA-PSS
// uses a salt as long as the hash (64 octets for `rsa-pss-sha512`, and the
// hash length for PS256/384/512 per RFC 7518 section 3.5); and an HMAC is
// compared in constant time, because a byte-at-a-time comparison of a MAC is a
// MAC oracle (section 7.3.3 and the ordinary lesson). RSA keys under 2048 bits
// and HMAC secrets shorter than their hash are refused — RFC 7518 sections 3.3
// and 3.2 make those MUSTs for the JWS names, and a service that accepted a
// weaker key under the HTTP name than under the JWS one would be offering the
// downgrade section 7.3.6 warns about.
//
// ---------------------------------------------------------------------------
// THE REFUSAL SHAPE is the GNAP subsystem's contract: `{ ok: false, errorCode,
// why }`, MARKED with the code so the call-log funnel finds it, and never a
// response — this module has no `req` and no `res`. The codes are
// the GNAP subsystem's 0200 range and each is raised in exactly one kind of
// place; the client-facing GNAP error (`invalid_client`, RFC 9635 section 3.6)
// is the caller's to choose, because the same failed signature is a grant
// endpoint refusing a client and a resource server refusing a request.
//
// IT IS A LIBRARY (rule 3). It registers no route and requires `helpers.js`,
// the error-code registry and `gnap_sf.ts`, none of which requires it back.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapHttpsig` takes node's crypto, the logger, the error-code table
// and `gnap_sf` through its constructor, and every helper is one of its
// private methods. The five tables are module constants; three are exported as
// before and are static members too. The module still exports the old names as
// FACADES forwarding to the instance the composition root builds (#50, R2),
// for `gnap_proof.ts`, the other GNAP modules and the tests, which require it
// by those names. A process that loads this module without the root builds a
// default instance when the module loads.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
// A leaf: the one table of codes, and `mark()`, which puts a code on a refusal
// object under a Symbol so that nothing serialises it.
import errorCodes = require('../common/error_codes');
import sf = require('./gnap_sf');

// A result in the one shape every GNAP library returns: `ok`, and either the
// refusal's members or the answer's.
interface Result {
  ok: boolean;
  [member: string]: any;
}

interface GnapHttpsigDeps {
  nodeCrypto: typeof nodeCrypto;
  log: {
    debug(message: string): void;
    warn(message: string): void;
  };
  errorCodes: {
    mark<T>(res: T, code: string): T;
    tag(code: string): string;
  };
  sf: typeof sf;
}

// ===========================================================================
// RFC 9530: CONTENT-DIGEST.
//
// Only the two "Active" algorithms of the registry (section 7.2) are here. The
// "Deprecated" ones (md5, sha, unixsum, unixcksum, adler, crc32c) MUST NOT be
// used where the digest is signed for authenticity (section 5), which is the
// only reason GNAP computes one — so they are not merely unpreferred here,
// they are unknown, and an unknown algorithm is ignored by the verifier exactly
// as section 2 allows ("A recipient MAY ignore any or all digests").
// ===========================================================================
const DIGEST_ALGORITHMS: Record<string, string> = {
  'sha-256': 'sha256',
  'sha-512': 'sha512'
};

// The derived components of section 2.2 and whether each belongs to a request
// or a response message.
const DERIVED: Record<string, string> = {
  '@method': 'request',
  '@target-uri': 'request',
  '@authority': 'request',
  '@scheme': 'request',
  '@request-target': 'request',
  '@path': 'request',
  '@query': 'request',
  '@query-param': 'request',
  '@status': 'response'
};

// Fields whose Structured Field type is known, so that `;sf` and `;key=` can be
// honoured (RFC 9421 section 2.1.1). Each row cites the document defining the
// type. A caller extends it per call with `options.fieldTypes`.
const KNOWN_FIELD_TYPES: Record<string, string> = {
  'signature': 'dictionary',            // RFC 9421 section 4.2
  'signature-input': 'dictionary',      // RFC 9421 section 4.1
  'accept-signature': 'dictionary',     // RFC 9421 section 5.1
  'content-digest': 'dictionary',       // RFC 9530 section 2
  'repr-digest': 'dictionary',          // RFC 9530 section 3
  'want-content-digest': 'dictionary',  // RFC 9530 section 4
  'want-repr-digest': 'dictionary',     // RFC 9530 section 4
  'client-cert': 'item',                // RFC 9440 section 2.2
  'client-cert-chain': 'list',          // RFC 9440 section 2.3
  'priority': 'dictionary',             // RFC 9218 section 4
  'cache-status': 'list',               // RFC 9211 section 2
  'proxy-status': 'list'                // RFC 9209 section 2
};

// The six registered metadata parameters (section 6.3.2) have types, and a
// parameter of the wrong type is a signature a conforming verifier cannot
// read: `created="1618884473"` is a String and not a timestamp. Parameters
// outside the six are allowed, because the registry is extensible and an
// unknown parameter changes nothing this module decides.
const PARAM_TYPES: Record<string, string> = {
  created: 'integer',
  expires: 'integer',
  nonce: 'string',
  alg: 'string',
  keyid: 'string',
  tag: 'string'
};

// ===========================================================================
// ALGORITHMS.
// ===========================================================================
const ALGORITHMS: Record<string, any> = {
  // RFC 9421 section 3.3, the "HTTP Signature Algorithms" registry.
  'rsa-pss-sha512': { registry: 'http', kind: 'rsa-pss', hash: 'sha512',
                      saltLength: 64,
                      spec: 'RFC 9421 section 3.3.1' },
  'rsa-v1_5-sha256': { registry: 'http', kind: 'rsa-v1_5', hash: 'sha256',
                       spec: 'RFC 9421 section 3.3.2' },
  'hmac-sha256': { registry: 'http', kind: 'hmac', hash: 'sha256',
                   minKeyBytes: 32,
                   spec: 'RFC 9421 section 3.3.3' },
  'ecdsa-p256-sha256': { registry: 'http', kind: 'ecdsa', hash: 'sha256',
                         curve: 'prime256v1',
                         coordinateBytes: 32, spec: 'RFC 9421 section 3.3.4' },
  'ecdsa-p384-sha384': { registry: 'http', kind: 'ecdsa', hash: 'sha384',
                         curve: 'secp384r1',
                         coordinateBytes: 48, spec: 'RFC 9421 section 3.3.5' },
  'ed25519': { registry: 'http', kind: 'eddsa', curves: ['ed25519'],
               spec: 'RFC 9421 section 3.3.6' },
  // RFC 9421 section 3.3.7: JWS algorithms (RFC 7518 section 3, RFC 8037).
  'RS256': { registry: 'jws', kind: 'rsa-v1_5', hash: 'sha256', spec: 'RFC ' +
      '7518 section 3.3' },
  'RS384': { registry: 'jws', kind: 'rsa-v1_5', hash: 'sha384', spec: 'RFC ' +
      '7518 section 3.3' },
  'RS512': { registry: 'jws', kind: 'rsa-v1_5', hash: 'sha512', spec: 'RFC ' +
      '7518 section 3.3' },
  'PS256': { registry: 'jws', kind: 'rsa-pss', hash: 'sha256', saltLength: 32,
             spec: 'RFC 7518 section 3.5' },
  'PS384': { registry: 'jws', kind: 'rsa-pss', hash: 'sha384', saltLength: 48,
             spec: 'RFC 7518 section 3.5' },
  'PS512': { registry: 'jws', kind: 'rsa-pss', hash: 'sha512', saltLength: 64,
             spec: 'RFC 7518 section 3.5' },
  'ES256': { registry: 'jws', kind: 'ecdsa', hash: 'sha256',
             curve: 'prime256v1',
             coordinateBytes: 32, spec: 'RFC 7518 section 3.4' },
  'ES384': { registry: 'jws', kind: 'ecdsa', hash: 'sha384', curve: 'secp384r1',
             coordinateBytes: 48, spec: 'RFC 7518 section 3.4' },
  'ES512': { registry: 'jws', kind: 'ecdsa', hash: 'sha512', curve: 'secp521r1',
             coordinateBytes: 66, spec: 'RFC 7518 section 3.4' },
  'EdDSA': { registry: 'jws', kind: 'eddsa', curves: ['ed25519', 'ed448'],
             spec: 'RFC 8037 section 3.1' },
  'HS256': { registry: 'jws', kind: 'hmac', hash: 'sha256', minKeyBytes: 32,
             spec: 'RFC 7518 section 3.2' },
  'HS384': { registry: 'jws', kind: 'hmac', hash: 'sha384', minKeyBytes: 48,
             spec: 'RFC 7518 section 3.2' },
  'HS512': { registry: 'jws', kind: 'hmac', hash: 'sha512', minKeyBytes: 64,
             spec: 'RFC 7518 section 3.2' }
};

class GnapHttpsig {
  static readonly ALGORITHMS = ALGORITHMS;
  static readonly DIGEST_ALGORITHMS = Object.keys(DIGEST_ALGORITHMS);
  static readonly KNOWN_FIELD_TYPES = KNOWN_FIELD_TYPES;

  constructor(private readonly deps: GnapHttpsigDeps) {
    deps.log.debug("Entering GnapHttpsig.constructor().");
    deps.log.debug("Leaving GnapHttpsig.constructor().");
  }

  // ---------------------------------------------------------------------------
  // THE ONE PLACE A REFUSAL IS MADE. Logged at warn with the code at the front
  // of the line — a failed proof is an operator's question before it is
  // anything else — and marked, per the subsystem contract.
  // ---------------------------------------------------------------------------
  private refuse(code: string, why: string): Result {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapHttpsig.refuse().");
    const result = { ok: false, errorCode: code, why: why };
    log.warn(errorCodes.tag(code) + why);
    log.debug("Leaving GnapHttpsig.refuse().");
    return errorCodes.mark(result, code);
  }

  private isRefusal(value) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.isRefusal().");
    log.debug("Leaving GnapHttpsig.isRefusal().");
    return !!value && value.ok === false;
  }

  private bodyBytes(body) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.bodyBytes().");
    if (body === undefined || body === null) {
      log.debug("Leaving GnapHttpsig.bodyBytes(). No content.");
      return Buffer.alloc(0);
    }
    if (Buffer.isBuffer(body)) {
      log.debug("Leaving GnapHttpsig.bodyBytes(). Buffer.");
      return body;
    }
    if (body instanceof Uint8Array) {
      log.debug("Leaving GnapHttpsig.bodyBytes(). Uint8Array.");
      return Buffer.from(body);
    }
    log.debug("Leaving GnapHttpsig.bodyBytes(). String.");
    return Buffer.from(String(body), 'utf8');
  }

  // `algorithm` may be one name or an array of names, in which case every
  // member is computed — section 2's second example, and what a client
  // supporting a population of verifiers sends. It THROWS on an unknown name,
  // carrying the code: an unsupported algorithm here is the caller's own
  // configuration, not anything a client sent.
  contentDigest(body, algorithm) {
    const { log, errorCodes, nodeCrypto, sf } = this.deps;
    log.debug("Entering GnapHttpsig.contentDigest().");
    const names = Array.isArray(algorithm) ? algorithm
                                           : [algorithm === undefined ?
                                              'sha-256' : algorithm];
    const bytes = this.bodyBytes(body);
    const dictionary = [];
    for (let k = 0; k < names.length; k++) {
      const hash = DIGEST_ALGORITHMS[names[k]];
      if (!hash) {
        const why = 'Content-Digest cannot be computed with "' +
                    String(names[k]) +
                    '": only sha-256 and sha-512, the two Active algorithms ' +
                    'of the RFC 9530 registry, are supported.';
        log.warn(errorCodes.tag('STS-GNAP-0200') + why);
        const err = new Error(why) as any;
        err.errorCode = 'STS-GNAP-0200';
        errorCodes.mark(err, 'STS-GNAP-0200');
        log.debug("Leaving GnapHttpsig.contentDigest(). Unsupported " +
                  "algorithm.");
        throw err;
      }
      dictionary.push([names[k], {
        type: 'bytes',
        value: nodeCrypto.createHash(hash).update(bytes).digest(),
        params: []
      }]);
    }
    log.debug("Leaving GnapHttpsig.contentDigest().");
    return sf.serializeDictionary(dictionary);
  }

  // Section 2 read with GNAP's requirement (RFC 9635 section 7.3.1: "The
  // verifier MUST validate this field value"): EVERY member whose algorithm is
  // accepted must match, and at least one must be present. "Any one matches"
  // would let a client send a correct sha-256 beside a wrong sha-512 and have a
  // verifier that prefers sha-512 accept a body the sha-512 does not describe.
  verifyContentDigest(headerValue, body, options) {
    const { log, nodeCrypto, sf } = this.deps;
    log.debug("Entering GnapHttpsig.verifyContentDigest().");
    const accepted = (options && Array.isArray(options.accepted))
      ? options.accepted : ['sha-256', 'sha-512'];
    for (let k = 0; k < accepted.length; k++) {
      if (!DIGEST_ALGORITHMS[accepted[k]]) {
        log.debug("Leaving GnapHttpsig.verifyContentDigest(). Unsupported " +
                  "accepted algorithm.");
        return this.refuse('STS-GNAP-0200',
                           'The verifier was configured to accept the ' +
                           'Content-Digest algorithm "' +
                           String(accepted[k]) + '", which is not supported; ' +
                           'only sha-256 and sha-512 are.');
      }
    }
    const text = Array.isArray(headerValue) ? headerValue.join(', ') :
                 headerValue;
    if (typeof text !== 'string' || text.trim() === '') {
      log.debug("Leaving GnapHttpsig.verifyContentDigest(). Absent.");
      return this.refuse('STS-GNAP-0201',
                         'The message has no Content-Digest field to ' +
                         'validate against its content (RFC 9530 section 2).');
    }
    let dictionary;
    try {
      dictionary = sf.parseDictionary(text);
    } catch (e) {
      log.debug("Caught in GnapHttpsig.verifyContentDigest(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapHttpsig.verifyContentDigest(). Malformed.");
      return this.refuse('STS-GNAP-0202',
                         'The Content-Digest field is not a Structured Field ' +
                         'Dictionary: ' + e.message);
    }
    const bytes = this.bodyBytes(body);
    const matched = [];
    for (let k = 0; k < dictionary.length; k++) {
      const name = dictionary[k][0];
      if (accepted.indexOf(name) < 0) {
        // Not accepted, or not an algorithm this module knows: ignored, as RFC
        // 9530 section 2 allows. It still had to PARSE — a malformed member
        // anywhere makes the whole field malformed (RFC 8941 section 4.2).
        continue;
      }
      const member = dictionary[k][1];
      if (!member || member.type !== 'bytes') {
        log.debug("Leaving GnapHttpsig.verifyContentDigest(). Not a byte " +
                  "sequence.");
        return this.refuse('STS-GNAP-0203',
                           'The Content-Digest member "' + name + '" is a ' +
                           (member ? member.type : 'nothing') +
                           ', not the Byte Sequence RFC 9530 section 2 ' +
                           'requires.');
      }
      const expected = nodeCrypto.createHash(DIGEST_ALGORITHMS[name])
                                 .update(bytes)
                                 .digest();
      if (expected.length !== member.value.length ||
          !nodeCrypto.timingSafeEqual(expected, member.value)) {
        log.debug("Leaving GnapHttpsig.verifyContentDigest(). Mismatch.");
        return this.refuse('STS-GNAP-0204',
                           'The Content-Digest member "' + name +
                           '" does not match the content: the body was ' +
                           'changed, or the digest was computed over ' +
                           'something other than the bytes sent.');
      }
      matched.push(name);
    }
    if (matched.length === 0) {
      log.debug("Leaving GnapHttpsig.verifyContentDigest(). No accepted " +
                "algorithm.");
      return this.refuse('STS-GNAP-0205',
                         'The Content-Digest field carries no digest in an ' +
                         'accepted algorithm (' + accepted.join(', ') +
                         '); it carries ' +
                         (dictionary.length ?
                          dictionary.map((p) => { return p[0]; }).join(', ')
                                            : 'no members') + '.');
    }
    log.debug("Leaving GnapHttpsig.verifyContentDigest(). " +
              matched.join(', '));
    return { ok: true, algorithms: matched };
  }

  // ===========================================================================
  // COMPONENT IDENTIFIERS.
  // ===========================================================================

  // A JavaScript value handed in as a parameter, turned into a bare item. A
  // value that is already a bare item is kept, so a caller that needs a Token
  // rather than a String can say so.
  private bareItemOf(value) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.bareItemOf().");
    let bare = null;
    if (value && typeof value === 'object' && !Buffer.isBuffer(value) &&
        typeof value.type === 'string' && 'value' in value) {
      bare = { type: value.type, value: value.value };
    } else if (typeof value === 'boolean') {
      bare = { type: 'boolean', value: value };
    } else if (Buffer.isBuffer(value)) {
      bare = { type: 'bytes', value: value };
    } else if (typeof value === 'number') {
      bare = { type: Number.isInteger(value) ? 'integer' : 'decimal',
               value: value };
    } else if (typeof value === 'string') {
      bare = { type: 'string', value: value };
    }
    log.debug("Leaving GnapHttpsig.bareItemOf(). " +
              (bare ? bare.type : 'not a bare item'));
    return bare;
  }

  // Parameters from either an ordered [[key, value]] array or a plain object
  // (in its insertion order). Duplicate keys are last-wins in the first
  // position, which is what a PARSER would have made of the same text (RFC 8941
  // section 4.2.3.2) — so a signer cannot build an identifier no verifier could
  // parse back to itself. THROWS on a value that is not a bare item; callers
  // map it.
  private paramsFrom(input) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.paramsFrom().");
    if (input === undefined || input === null) {
      log.debug("Leaving GnapHttpsig.paramsFrom(). None.");
      return [];
    }
    const pairs = Array.isArray(input) ? input :
                  Object.keys(input).map((key) => {
      return [key, input[key]];
    });
    const out = [];
    pairs.forEach((pair) => {
      if (!Array.isArray(pair) || pair.length !== 2) {
        throw new Error('each parameter must be a [key, value] pair');
      }
      if (pair[1] === undefined) {
        // An object member present but undefined is how a caller writes "no
        // such parameter" ({ expires: undefined }); section 2.3 step 5 skips
        // parameters "not available or not used", so it is skipped too.
        return;
      }
      sf.serializeKey(pair[0]);
      const bare = this.bareItemOf(pair[1]);
      if (!bare) {
        throw new Error('the parameter "' + pair[0] + '" has a value that is ' +
                        'not a Structured Field bare item');
      }
      sf.serializeBareItem(bare);
      let at = -1;
      for (let k = 0; k < out.length; k++) {
        if (out[k][0] === pair[0]) {
          at = k;
        }
      }
      if (at >= 0) {
        out[at][1] = bare;
      } else {
        out.push([pair[0], bare]);
      }
    });
    log.debug("Leaving GnapHttpsig.paramsFrom(). " + out.length +
              " parameter(s).");
    return out;
  }

  // A component identifier from any of the forms a caller may write:
  //
  //   '@method'                              a bare NAME, no parameters
  //   '"@query-param";name="Pet"'            a serialized identifier (it begins
  //                                          with a DQUOTE, which no name can)
  //   { name: 'signature', params: { key: 'old' } }
  //   { type: 'string', value: 'x', params: [[...]] }   a parsed sf-string item
  //
  // The NAME rule is section 2.1's: a field name is used LOWERCASED, and a name
  // that is not is refused rather than lowercased, because silently lowercasing
  // it would sign a component the signer did not name.
  private componentItem(component) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.componentItem().");
    let item;
    try {
      if (typeof component === 'string' && component[0] === '"') {
        item = sf.parseItem(component);
      } else if (typeof component === 'string') {
        item = { type: 'string', value: component, params: [] };
      } else if (component && typeof component === 'object' &&
                 component.type === 'string') {
        item = { type: 'string', value: component.value,
                 params: this.paramsFrom(component.params) };
      } else if (component && typeof component === 'object' &&
                 typeof component.name === 'string') {
        item = { type: 'string', value: component.name,
                 params: this.paramsFrom(component.params) };
      } else {
        throw new Error('it is not a name, a serialized identifier or a ' +
                        '{name, params} object');
      }
      if (item.type !== 'string') {
        throw new Error('a component name is an sf-string (RFC 9421 section ' +
                        '2.5), and this is a ' + item.type);
      }
      sf.serializeItem(item);
    } catch (e) {
      log.debug("Caught in GnapHttpsig.componentItem(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapHttpsig.componentItem(). Malformed.");
      return this.refuse('STS-GNAP-0206',
                         'A covered component identifier is malformed: ' +
                         e.message + '.');
    }
    const name = item.value;
    const fieldName = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/;
    if (!(name[0] === '@' && name.length > 1) && !fieldName.test(name)) {
      log.debug("Leaving GnapHttpsig.componentItem(). Bad name.");
      return this.refuse('STS-GNAP-0206',
                         'The component name "' + name +
                         '" is neither a derived component name nor a ' +
                         'lowercased HTTP field name (RFC 9421 sections 2.1 ' +
                         'and 2.2).');
    }
    log.debug("Leaving GnapHttpsig.componentItem(). " + name);
    return { ok: true, item: item };
  }

  // Two identifiers are the same when the names are equal and the parameters
  // are equal AS A SET — section 2: `"foo";bar;baz` and `"foo";baz;bar` "cannot
  // be in the same message".
  private identityOf(item) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.identityOf().");
    const params = (item.params || []).map((pair) => {
      return sf.serializeParams([pair]);
    }).sort();
    log.debug("Leaving GnapHttpsig.identityOf().");
    return JSON.stringify([item.value, params]);
  }

  // The header lines of a named field, as an array of strings, or null when the
  // field is absent. A header value may be one combined string or an array of
  // the separate field lines — the second form is needed only for `;bs`, which
  // wraps each line on its own (section 2.1.3).
  private fieldLines(message, name) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.fieldLines(). " + name);
    const headers = message && message.headers;
    if (!headers || typeof headers !== 'object') {
      log.debug("Leaving GnapHttpsig.fieldLines(). No headers.");
      return null;
    }
    let raw;
    const keys = Object.keys(headers);
    for (let k = 0; k < keys.length; k++) {
      if (keys[k].toLowerCase() === name) {
        raw = headers[keys[k]];
      }
    }
    if (raw === undefined || raw === null) {
      log.debug("Leaving GnapHttpsig.fieldLines(). Absent.");
      return null;
    }
    const lines = (Array.isArray(raw) ? raw : [raw]).map(String);
    log.debug("Leaving GnapHttpsig.fieldLines(). " + lines.length +
              " line(s).");
    return lines.length ? lines : null;
  }

  // Section 2.1 steps 2 and 3: strip the ends, and replace obsolete line
  // folding (OWS CRLF RWS, RFC 9112 section 5.2) with a single space.
  private normalizeLine(line) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.normalizeLine().");
    log.debug("Leaving GnapHttpsig.normalizeLine().");
    return line.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '')
               .replace(/[ \t]*\r?\n[ \t]+/g, ' ');
  }

  // The parts of the target URI, read out of the RAW string, because section
  // 2.2.6 and 2.2.7 want the path and query "before decoding any
  // percent-encoded octets" and a WHATWG URL object re-encodes and resolves dot
  // segments. The URL parser is used for what it is right about — that the
  // string is absolute, and the host normalization of 2.2.3.
  private targetParts(message) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.targetParts().");
    const raw = message && message.targetUri;
    if (typeof raw !== 'string') {
      log.debug("Leaving GnapHttpsig.targetParts(). No target URI.");
      return null;
    }
    const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#.*)?$/.exec(raw);
    if (!m) {
      log.debug("Leaving GnapHttpsig.targetParts(). Not absolute.");
      return null;
    }
    let url;
    try {
      url = new URL(raw);
    } catch (e) {
      log.debug("Caught in GnapHttpsig.targetParts(): " +
                ((e && e.message) || e));
      // Not a URI the WHATWG parser accepts; the caller refuses with the code
      // for a missing target, which is what this is to a signature base.
      log.debug("Leaving GnapHttpsig.targetParts(). Unparseable: " + e.message);
      return null;
    }
    const scheme = m[1].toLowerCase();
    let authority = url.host.toLowerCase();
    // WHATWG omits the default port for http and https only; section 2.2.3 says
    // the default port of the SCHEME is omitted, and those are the two schemes
    // an HTTP request has.
    const hashAt = raw.indexOf('#');
    log.debug("Leaving GnapHttpsig.targetParts().");
    return {
      targetUri: hashAt >= 0 ? raw.slice(0, hashAt) : raw,
      scheme: scheme,
      authority: authority,
      path: m[3] === '' ? '/' : m[3],
      query: m[4] === undefined ? null : m[4]
    };
  }

  // ---------------------------------------------------------------------------
  // `@query-param`, section 2.2.8: the WHATWG application/x-www-form-urlencoded
  // PARSER (section 5.1 of the URL Standard), then the "percent-encode after
  // encoding" step with the urlencoded percent-encode set and WITHOUT
  // space-as-plus — which is why the RFC's example turns `with+plus+whitespace`
  // into `with%20plus%20whitespace`. That set leaves exactly ASCII
  // alphanumerics and `*-._` unencoded.
  // ---------------------------------------------------------------------------
  private percentDecode(text) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.percentDecode().");
    const bytes = Buffer.from(text, 'utf8');
    const out = [];
    for (let k = 0; k < bytes.length; k++) {
      const b = bytes[k];
      if (b === 0x25 && k + 2 < bytes.length &&
          /^[0-9A-Fa-f]{2}$/.test(String.fromCharCode(bytes[k + 1],
                                                      bytes[k + 2]))) {
        out.push(parseInt(String.fromCharCode(bytes[k + 1], bytes[k + 2]), 16));
        k += 2;
      } else {
        out.push(b);
      }
    }
    log.debug("Leaving GnapHttpsig.percentDecode().");
    return Buffer.from(out).toString('utf8');
  }

  private urlencodedEncode(text) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.urlencodedEncode().");
    const bytes = Buffer.from(text, 'utf8');
    let out = '';
    for (let k = 0; k < bytes.length; k++) {
      const c = String.fromCharCode(bytes[k]);
      if (/^[A-Za-z0-9*\-._]$/.test(c)) {
        out += c;
      } else {
        out += '%' + bytes[k].toString(16).toUpperCase().padStart(2, '0');
      }
    }
    log.debug("Leaving GnapHttpsig.urlencodedEncode().");
    return out;
  }

  private queryParams(query) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.queryParams().");
    const out = [];
    (query || '').split('&').forEach((sequence) => {
      if (sequence === '') {
        return;
      }
      const eq = sequence.indexOf('=');
      const name = eq >= 0 ? sequence.slice(0, eq) : sequence;
      const value = eq >= 0 ? sequence.slice(eq + 1) : '';
      out.push([this.urlencodedEncode(this.percentDecode(name.replace(/\+/g,
                                      ' '))),
                this.urlencodedEncode(this.percentDecode(value.replace(/\+/g,
                                      ' ')))]);
    });
    log.debug("Leaving GnapHttpsig.queryParams(). " + out.length +
              " parameter(s).");
    return out;
  }

  // Which parameters a component may carry. A parameter outside this list is
  // "not understood" (section 2.5 step 2.5, first bullet) and is an error.
  private checkParams(name, params, allowed) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.checkParams(). " + name);
    for (let k = 0; k < params.length; k++) {
      const key = params[k][0];
      const value = params[k][1];
      if (allowed.indexOf(key) < 0) {
        log.debug("Leaving GnapHttpsig.checkParams(). Not understood.");
        return this.refuse('STS-GNAP-0207',
                           'The parameter "' + key +
                           '" is not understood on the component "' +
                           name + '" (RFC 9421 section 2.5 step 2.5).');
      }
      const isFlag = key === 'sf' || key === 'bs' || key === 'req' ||
                     key === 'tr';
      if (isFlag && !(value.type === 'boolean' && value.value === true)) {
        // A false flag would make `"x";sf=?0` a second identifier for the value
        // `"x"` already names — two identifiers, one value, and a signature
        // over one standing for the other.
        log.debug("Leaving GnapHttpsig.checkParams(). Flag not true.");
        return this.refuse('STS-GNAP-0207',
                           'The parameter "' + key + '" on "' + name +
                           '" is a Boolean flag and is only meaningful as ' +
                           'true (RFC 9421 sections 2.1 and 6.5.2).');
      }
      if ((key === 'key' || key === 'name') && value.type !== 'string') {
        log.debug("Leaving GnapHttpsig.checkParams(). Not a string.");
        return this.refuse('STS-GNAP-0207',
                           'The parameter "' + key + '" on "' + name +
                           '" must be a String, not a ' + value.type +
                           ' (RFC 9421 sections 2.1.2 and 2.2.8).');
      }
    }
    if (sf.param(params, 'req') !== undefined) {
      log.debug("Leaving GnapHttpsig.checkParams(). req.");
      return this.refuse('STS-GNAP-0208',
                         'The component "' + name +
                         '" carries ;req, which names a value from the ' +
                         'request a response answers (RFC 9421 section 2.4); ' +
                         'this verifier has no related request, and a ' +
                         'signature targeting a request MUST NOT use it.');
    }
    log.debug("Leaving GnapHttpsig.checkParams().");
    return null;
  }

  private derivedValue(message, name, params) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.derivedValue(). " + name);
    if (!Object.prototype.hasOwnProperty.call(DERIVED, name)) {
      log.debug("Leaving GnapHttpsig.derivedValue(). Unknown.");
      return this.refuse('STS-GNAP-0209',
                         'The derived component "' + name +
                         '" is not one this verifier understands (RFC 9421 ' +
                         'sections 2.2 and 2.5).');
    }
    const problem = this.checkParams(name, params,
                                     name === '@query-param' ? ['name', 'req'] :
                                     ['req']);
    if (problem) {
      log.debug("Leaving GnapHttpsig.derivedValue(). Parameters.");
      return problem;
    }
    const isResponse = message && message.status !== undefined &&
                       message.status !== null;
    if ((DERIVED[name] === 'response') !== isResponse) {
      log.debug("Leaving GnapHttpsig.derivedValue(). Wrong message kind.");
      return this.refuse('STS-GNAP-0210',
                         name === '@status'
                      ? '@status MUST NOT be used in a request message (RFC ' +
                         '9421 section 2.2.9).'
                      : 'The component "' + name + '" targets a request, and ' +
                         'this message is a response (RFC 9421 section 2.2).');
    }
    if (name === '@status') {
      const status = message.status;
      if (!Number.isInteger(status) || status < 100 || status > 999) {
        log.debug("Leaving GnapHttpsig.derivedValue(). Bad status.");
        return this.refuse('STS-GNAP-0210',
                           'The response status "' + String(status) +
                           '" is not a three-digit integer (RFC 9421 section ' +
                           '2.2.9).');
      }
      log.debug("Leaving GnapHttpsig.derivedValue(). @status");
      return { ok: true, value: String(status) };
    }
    if (name === '@method') {
      if (typeof message.method !== 'string' || message.method === '') {
        log.debug("Leaving GnapHttpsig.derivedValue(). No method.");
        return this.refuse('STS-GNAP-0211',
                           'The request has no method to derive @method from.');
      }
      log.debug("Leaving GnapHttpsig.derivedValue(). @method");
      return { ok: true, value: message.method };
    }
    const parts = this.targetParts(message);
    if (!parts) {
      log.debug("Leaving GnapHttpsig.derivedValue(). No target.");
      return this.refuse('STS-GNAP-0211',
                         'The request has no absolute target URI to derive ' +
                         name + ' from (RFC 9421 section 2.2.2); got ' +
                         JSON.stringify(message && message.targetUri) + '.');
    }
    let value;
    switch (name) {
      case '@target-uri':
        value = parts.targetUri;
        break;
      case '@authority':
        value = parts.authority;
        break;
      case '@scheme':
        value = parts.scheme;
        break;
      case '@request-target':
        value = typeof message.requestTarget === 'string'
          ? message.requestTarget
          : parts.path + (parts.query === null ? '' : '?' + parts.query);
        break;
      case '@path':
        value = parts.path;
        break;
      case '@query':
        value = '?' + (parts.query === null ? '' : parts.query);
        break;
      default: {
        const wanted = sf.paramValue(params, 'name');
        if (wanted === undefined) {
          log.debug("Leaving GnapHttpsig.derivedValue(). No name.");
          return this.refuse('STS-GNAP-0212',
                             '@query-param requires a name parameter (RFC ' +
                             '9421 section 2.2.8).');
        }
        const matches = this.queryParams(parts.query).filter((pair) => {
          return pair[0] === wanted;
        });
        if (matches.length === 0) {
          log.debug("Leaving GnapHttpsig.derivedValue(). Query parameter " +
                    "absent.");
          return this.refuse('STS-GNAP-0212',
                             'The query parameter "' + wanted +
                             '" named as a covered component does not occur ' +
                             'in the target URI (RFC 9421 section 2.2.8).');
        }
        if (matches.length > 1) {
          log.debug("Leaving GnapHttpsig.derivedValue(). Query parameter " +
                    "repeated.");
          return this.refuse('STS-GNAP-0213',
                             'The query parameter "' + wanted + '" occurs ' +
                             matches.length +
                             ' times; a parameter that occurs more than once ' +
                             'MUST NOT be covered by name (RFC 9421 section ' +
                             '2.2.8).');
        }
        value = matches[0][1];
      }
    }
    log.debug("Leaving GnapHttpsig.derivedValue(). " + name);
    return { ok: true, value: value };
  }

  private fieldValue(message, name, params, options) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.fieldValue(). " + name);
    const problem = this.checkParams(name, params, ['sf', 'key', 'bs', 'req',
                                     'tr']);
    if (problem) {
      log.debug("Leaving GnapHttpsig.fieldValue(). Parameters.");
      return problem;
    }
    if (sf.param(params, 'tr') !== undefined) {
      log.debug("Leaving GnapHttpsig.fieldValue(). Trailer.");
      return this.refuse('STS-GNAP-0214',
                         'The component "' + name +
                         '";tr names a trailer field, and trailers are not ' +
                         'part of the message this verifier is given (RFC ' +
                         '9421 section 2.1.4).');
    }
    const bs = sf.param(params, 'bs') !== undefined;
    const key = sf.paramValue(params, 'key');
    const strict = sf.param(params, 'sf') !== undefined;
    if (bs && (strict || key !== undefined)) {
      log.debug("Leaving GnapHttpsig.fieldValue(). Incompatible.");
      return this.refuse('STS-GNAP-0215',
                         'The component "' + name + '" combines ;bs with ' +
                         (strict ? ';sf' : ';key') + ', which are mutually ' +
                         'incompatible (RFC 9421 sections 2.1 and 2.5 step ' +
                         '2.5).');
    }
    const lines = this.fieldLines(message, name);
    if (!lines) {
      log.debug("Leaving GnapHttpsig.fieldValue(). Absent.");
      return this.refuse('STS-GNAP-0216',
                         'The HTTP field "' + name +
                         '" is a covered component and is not present in the ' +
                         'message (RFC 9421 section 2.5).');
    }
    const normalized = lines.map((line) => this.normalizeLine(line));
    if (bs) {
      log.debug("Leaving GnapHttpsig.fieldValue(). bs.");
      return {
        ok: true,
        value: sf.serializeList(normalized.map((line) => {
          return { type: 'bytes', value: Buffer.from(line, 'latin1'),
                   params: [] };
        }))
      };
    }
    const combined = normalized.join(', ');
    if (!strict && key === undefined) {
      log.debug("Leaving GnapHttpsig.fieldValue(). Plain.");
      return { ok: true, value: combined };
    }
    const types = Object.assign({}, KNOWN_FIELD_TYPES,
                                (options && options.fieldTypes) || {});
    const type = types[name];
    if (!type || (key !== undefined && type !== 'dictionary')) {
      log.debug("Leaving GnapHttpsig.fieldValue(). Type unknown.");
      return this.refuse('STS-GNAP-0217',
                         'The component "' + name + '" asks for ' +
                         (key !== undefined ? ';key' : ';sf') +
                         ', and "' + name + '" is ' +
                         (type ? 'a Structured Field ' + type +
                                 ', not a Dictionary'
                               : 'not a Structured Field type this ' +
                                 'verifier knows') +
                         ' (RFC 9421 sections 2.1.1 and 2.1.2).');
    }
    let value;
    try {
      if (key !== undefined) {
        const member = sf.member(sf.parseDictionary(combined), key);
        if (member === undefined) {
          log.debug("Leaving GnapHttpsig.fieldValue(). Key absent.");
          return this.refuse('STS-GNAP-0218',
                             'The Dictionary field "' + name +
                             '" has no member "' + key + '", which is a ' +
                             'covered component (RFC 9421 section 2.1.2).');
        }
        value = member.type === 'innerList' ? sf.serializeInnerList(member)
                                            : sf.serializeItem(member);
      } else if (type === 'dictionary') {
        value = sf.serializeDictionary(sf.parseDictionary(combined));
      } else if (type === 'list') {
        value = sf.serializeList(sf.parseList(combined));
      } else {
        value = sf.serializeItem(sf.parseItem(combined));
      }
    } catch (e) {
      log.debug("Caught in GnapHttpsig.fieldValue(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapHttpsig.fieldValue(). Malformed.");
      return this.refuse('STS-GNAP-0219',
                         'The field "' + name +
                         '" does not parse as a Structured Field ' + type +
                         ': ' + e.message);
    }
    log.debug("Leaving GnapHttpsig.fieldValue(). Strict.");
    return { ok: true, value: value };
  }

  // A component's canonical value, or a refusal. `identifier` is the serialized
  // component identifier the value is written after in a signature base.
  componentValue(message, component, options) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.componentValue().");
    const normalized = this.componentItem(component);
    if (this.isRefusal(normalized)) {
      log.debug("Leaving GnapHttpsig.componentValue(). Identifier.");
      return normalized;
    }
    const item = normalized.item;
    const name = item.value;
    if (name === '@signature-params') {
      log.debug("Leaving GnapHttpsig.componentValue(). @signature-params.");
      return this.refuse('STS-GNAP-0220',
                         '@signature-params MUST NOT be listed among the ' +
                         'covered components; it is always the last line of ' +
                         'the signature base (RFC 9421 section 2.3).');
    }
    const result = name[0] === '@' ? this.derivedValue(message, name,
        item.params)
                                   : this.fieldValue(message, name, item.params,
                                                     options);
    if (this.isRefusal(result)) {
      log.debug("Leaving GnapHttpsig.componentValue(). Refused.");
      return result;
    }
    // Section 2: a component value MUST NOT contain a newline; section 2.5 step
    // 4: the base is ASCII. Both are checked on the VALUE, so the refusal can
    // name the component that broke them.
    if (/[\r\n]/.test(result.value) || /[^\x20-\x7e\t]/.test(result.value)) {
      log.debug("Leaving GnapHttpsig.componentValue(). Not printable ASCII.");
      return this.refuse('STS-GNAP-0221',
                         'The value of the component "' + name +
                         '" contains a newline or a character outside ASCII, ' +
                         'which a signature base may not (RFC 9421 sections ' +
                         '2 and 2.5 step 4); ;bs exists for such a field.');
    }
    log.debug("Leaving GnapHttpsig.componentValue().");
    return { ok: true, value: result.value, identifier: sf.serializeItem(item),
             item: item };
  }

  // ===========================================================================
  // THE SIGNATURE BASE, SECTION 2.5, AND THE SIGNATURE PARAMETERS, SECTION 2.3.
  // ===========================================================================

  private checkSignatureParams(params) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.checkSignatureParams().");
    for (let k = 0; k < params.length; k++) {
      const wanted = PARAM_TYPES[params[k][0]];
      if (wanted && params[k][1].type !== wanted) {
        log.debug("Leaving GnapHttpsig.checkSignatureParams(). Wrong type.");
        return this.refuse('STS-GNAP-0222',
                           'The signature parameter "' + params[k][0] +
                           '" must be ' +
                           (wanted === 'integer' ? 'an Integer' : 'a String') +
                           ', not a ' +
                           params[k][1].type + ' (RFC 9421 section 2.3).');
      }
      if (wanted === 'integer' && params[k][1].value < 0) {
        log.debug("Leaving GnapHttpsig.checkSignatureParams(). Negative time.");
        return this.refuse('STS-GNAP-0222',
                           'The signature parameter "' + params[k][0] +
                           '" is a negative UNIX timestamp (RFC 9421 section ' +
                           '2.3).');
      }
    }
    log.debug("Leaving GnapHttpsig.checkSignatureParams().");
    return null;
  }

  // `covered` is either an Inner List (whose own `params` are used when
  // `signatureParams` is not given — which is what a PARSED Signature-Input
  // member is) or an array of components in any form `componentItem()` reads.
  // `signatureParams` is an ordered [[key, value]] array or a plain object.
  signatureBase(message, covered, signatureParams, options) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.signatureBase().");
    let components;
    let paramsInput = signatureParams;
    if (covered && covered.type === 'innerList' &&
        Array.isArray(covered.value)) {
      components = covered.value;
      if (paramsInput === undefined) {
        paramsInput = covered.params;
      }
    } else if (Array.isArray(covered)) {
      components = covered;
    } else {
      log.debug("Leaving GnapHttpsig.signatureBase(). No component list.");
      return this.refuse('STS-GNAP-0206',
                         'The covered components must be an array or an ' +
                         'Inner List.');
    }
    let params;
    try {
      params = this.paramsFrom(paramsInput);
    } catch (e) {
      log.debug("Caught in GnapHttpsig.signatureBase(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapHttpsig.signatureBase(). Parameters.");
      return this.refuse('STS-GNAP-0222',
                         'The signature parameters cannot be serialized: ' +
                         e.message + '.');
    }
    const paramProblem = this.checkSignatureParams(params);
    if (paramProblem) {
      log.debug("Leaving GnapHttpsig.signatureBase(). Parameter types.");
      return paramProblem;
    }
    const items = [];
    const lines = [];
    const seen = {};
    for (let k = 0; k < components.length; k++) {
      const normalized = this.componentItem(components[k]);
      if (this.isRefusal(normalized)) {
        log.debug("Leaving GnapHttpsig.signatureBase(). Identifier.");
        return normalized;
      }
      const identity = this.identityOf(normalized.item);
      if (seen[identity]) {
        log.debug("Leaving GnapHttpsig.signatureBase(). Duplicate.");
        return this.refuse('STS-GNAP-0223',
                           'The component ' +
                           sf.serializeItem(normalized.item) + ' is covered ' +
                           'more than once; each component identifier MUST ' +
                           'occur only once (RFC 9421 sections 2 and 2.5 ' +
                           'step 2.1).');
      }
      seen[identity] = true;
      const cv = this.componentValue(message, normalized.item, options);
      if (this.isRefusal(cv)) {
        log.debug("Leaving GnapHttpsig.signatureBase(). Component refused.");
        return cv;
      }
      items.push(normalized.item);
      lines.push(cv.identifier + ': ' + cv.value);
    }
    const serializedParams = sf.serializeInnerList(
        { type: 'innerList', value: items, params: params });
    lines.push('"@signature-params": ' + serializedParams);
    log.debug("Leaving GnapHttpsig.signatureBase(). " + items.length +
              " component(s).");
    return {
      ok: true,
      base: lines.join('\n'),
      signatureParams: serializedParams,
      components: items,
      params: params
    };
  }

  private algorithmNamed(name) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.algorithmNamed().");
    log.debug("Leaving GnapHttpsig.algorithmNamed().");
    return typeof name === 'string' &&
           Object.prototype.hasOwnProperty.call(ALGORITHMS, name)
      ? ALGORITHMS[name] : null;
  }

  // Is this key material appropriate for this algorithm (section 3.1 step 1,
  // section 3.2 step 8)? A key of the wrong family is refused BEFORE node is
  // asked, because node's answer to an Ed25519 key under an RSA algorithm is an
  // exception whose text names neither.
  private checkKey(name, entry, key, purpose) {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering GnapHttpsig.checkKey(). " + name + " " + purpose);
    if (entry.kind === 'hmac') {
      let length = -1;
      if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
        length = key.length;
      } else if (key instanceof nodeCrypto.KeyObject && key.type === 'secret') {
        length = key.symmetricKeySize;
      }
      if (length < 0) {
        log.debug("Leaving GnapHttpsig.checkKey(). Not a secret.");
        return this.refuse('STS-GNAP-0224',
                           name + ' needs a shared secret (a Buffer), and ' +
                           'the key given is not one.');
      }
      if (length < entry.minKeyBytes) {
        log.debug("Leaving GnapHttpsig.checkKey(). Secret too short.");
        return this.refuse('STS-GNAP-0224',
                           name + ' needs a secret of at least ' +
                           entry.minKeyBytes + ' octets, the size of its ' +
                           'hash; this one has ' + length + ' (RFC 7518 ' +
                           'section 3.2).');
      }
      log.debug("Leaving GnapHttpsig.checkKey(). Secret.");
      return null;
    }
    if (!(key instanceof nodeCrypto.KeyObject) || key.type === 'secret' ||
        (purpose === 'sign' && key.type !== 'private')) {
      log.debug("Leaving GnapHttpsig.checkKey(). Not an asymmetric key.");
      return this.refuse('STS-GNAP-0224',
                         name + ' needs ' +
                         (purpose === 'sign' ? 'a private' : 'a public') +
                         ' asymmetric KeyObject, and the key given is not ' +
                         'one.');
    }
    const type = key.asymmetricKeyType;
    const details = key.asymmetricKeyDetails || {};
    let problem = null;
    if (entry.kind === 'rsa-v1_5' || entry.kind === 'rsa-pss') {
      if (type !== 'rsa' && !(type === 'rsa-pss' && entry.kind === 'rsa-pss')) {
        problem = 'is a ' + type + ' key, not an RSA key' +
                  (type === 'rsa-pss' ? ' usable for PKCS#1 v1.5' : '');
      } else if (!(details.modulusLength >= 2048)) {
        problem = 'is an RSA key of ' + details.modulusLength +
            ' bits, under ' +
                  'the 2048 RFC 7518 section 3.3 requires';
      } else if (type === 'rsa-pss' && details.hashAlgorithm &&
                 details.hashAlgorithm !== entry.hash) {
        problem = 'is an RSASSA-PSS key restricted to ' + details.hashAlgorithm;
      }
    } else if (entry.kind === 'ecdsa') {
      if (type !== 'ec' || details.namedCurve !== entry.curve) {
        problem = 'is a ' + type +
                  (details.namedCurve ? ' ' + details.namedCurve : '') +
                  ' key, not an EC key on ' + entry.curve;
      }
    } else if (entry.kind === 'eddsa') {
      if (entry.curves.indexOf(type) < 0) {
        problem = 'is a ' + type + ' key, not ' + entry.curves.join(' or ');
      }
    }
    if (problem) {
      log.debug("Leaving GnapHttpsig.checkKey(). " + problem);
      return this.refuse('STS-GNAP-0224',
                         'The key for ' + name + ' ' + problem + ' (' +
                         entry.spec + ').');
    }
    log.debug("Leaving GnapHttpsig.checkKey().");
    return null;
  }

  // HTTP_SIGN, section 3.3. Throws whatever node throws; callers map it.
  private rawSign(entry, key, data) {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering GnapHttpsig.rawSign(). " + entry.kind);
    let out;
    switch (entry.kind) {
      case 'hmac':
        out = nodeCrypto.createHmac(entry.hash, key).update(data).digest();
        break;
      case 'rsa-v1_5':
        out = nodeCrypto.sign(entry.hash, data, key);
        break;
      case 'rsa-pss':
        out = nodeCrypto.sign(entry.hash, data, {
          key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: entry.saltLength
        });
        break;
      case 'ecdsa':
        out = nodeCrypto.sign(entry.hash, data,
                              { key: key, dsaEncoding: 'ieee-p1363' });
        break;
      default:
        out = nodeCrypto.sign(null, data, key);
    }
    log.debug("Leaving GnapHttpsig.rawSign().");
    return out;
  }

  // HTTP_VERIFY, section 3.3. The HMAC comparison is constant-time and a length
  // difference is a plain false: `timingSafeEqual` throws on unequal lengths,
  // and an exception there would be a different code path an attacker can time.
  private rawVerify(entry, key, data, signature) {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering GnapHttpsig.rawVerify(). " + entry.kind);
    let ok;
    switch (entry.kind) {
      case 'hmac': {
        const expected = nodeCrypto.createHmac(entry.hash, key)
                                   .update(data)
                                   .digest();
        ok = expected.length === signature.length &&
             nodeCrypto.timingSafeEqual(expected, signature);
        break;
      }
      case 'rsa-v1_5':
        ok = nodeCrypto.verify(entry.hash, data, key, signature);
        break;
      case 'rsa-pss':
        ok = nodeCrypto.verify(entry.hash, data, {
          key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: entry.saltLength
        }, signature);
        break;
      case 'ecdsa':
        // r||s at the coordinate size and nothing else: a DER signature, or one
        // of the other curve's length, is not this algorithm's output (3.3.4).
        ok = signature.length === 2 * entry.coordinateBytes &&
             nodeCrypto.verify(entry.hash, data,
                               { key: key, dsaEncoding: 'ieee-p1363' },
                               signature);
        break;
      default:
        ok = nodeCrypto.verify(null, data, key, signature);
    }
    log.debug("Leaving GnapHttpsig.rawVerify(). " + ok);
    return ok;
  }

  // ===========================================================================
  // SIGNING, SECTION 3.1, AND PUTTING A SIGNATURE IN A MESSAGE, SECTION 4.
  // ===========================================================================

  // options: { label, components, params, key, algorithm, fieldTypes }
  //
  // `algorithm` may be an HTTP registry name or a JWS name; when it is absent
  // the `alg` parameter names it. It is never INVENTED into the parameters:
  // whether the signature carries `alg` is the signer's decision (GNAP forbids
  // it), so the parameters are exactly what the caller passed, in the caller's
  // order.
  sign(message, options) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.sign().");
    const opts = options || {};
    try {
      sf.serializeKey(opts.label);
    } catch (e) {
      log.debug("Caught in GnapHttpsig.sign(): " + ((e && e.message) || e));
      log.debug("Leaving GnapHttpsig.sign(). Label.");
      return this.refuse('STS-GNAP-0225',
                         'The signature label ' + JSON.stringify(opts.label) +
                         ' is not a valid Dictionary key (RFC 9421 section ' +
                         '4.1): ' + e.message);
    }
    let params;
    try {
      params = this.paramsFrom(opts.params);
    } catch (e) {
      log.debug("Caught in GnapHttpsig.sign(): " + ((e && e.message) || e));
      log.debug("Leaving GnapHttpsig.sign(). Parameters.");
      return this.refuse('STS-GNAP-0222',
                         'The signature parameters cannot be serialized: ' +
                         e.message + '.');
    }
    const algParam = sf.paramValue(params, 'alg');
    const name = opts.algorithm !== undefined ? opts.algorithm : algParam;
    if (name === undefined) {
      log.debug("Leaving GnapHttpsig.sign(). No algorithm.");
      return this.refuse('STS-GNAP-0226',
                         'No signature algorithm was named, by the caller or ' +
                         'by an alg parameter (RFC 9421 section 3.1 step 1).');
    }
    const entry = this.algorithmNamed(name);
    if (!entry) {
      log.debug("Leaving GnapHttpsig.sign(). Unknown algorithm.");
      return this.refuse('STS-GNAP-0227',
                         'The signature algorithm ' + JSON.stringify(name) +
                         ' is not supported; the supported ones are ' +
                         Object.keys(ALGORITHMS).join(', ') + '.');
    }
    if (algParam !== undefined &&
        (entry.registry === 'jws' || algParam !== name)) {
      log.debug("Leaving GnapHttpsig.sign(). alg conflict.");
      return this.refuse('STS-GNAP-0228',
                         entry.registry === 'jws'
                      ? 'The JWS algorithm ' + name + ' cannot be signalled ' +
                         'with the alg signature parameter (RFC 9421 section ' +
                         '3.3.7).'
                      : 'The alg parameter "' + algParam + '" names a ' +
                         'different algorithm from the one signing, ' +
                         name + ' (RFC 9421 section 3.2 step 6.5).');
    }
    const keyProblem = this.checkKey(name, entry, opts.key, 'sign');
    if (keyProblem) {
      log.debug("Leaving GnapHttpsig.sign(). Key.");
      return keyProblem;
    }
    const built = this.signatureBase(message, opts.components || [], params,
                                     opts);
    if (this.isRefusal(built)) {
      log.debug("Leaving GnapHttpsig.sign(). Base.");
      return built;
    }
    let signatureBytes;
    try {
      signatureBytes = this.rawSign(entry, opts.key, Buffer.from(built.base,
                                    'ascii'));
    } catch (e) {
      log.debug("Caught in GnapHttpsig.sign(): " + ((e && e.message) || e));
      log.debug("Leaving GnapHttpsig.sign(). Primitive threw.");
      return this.refuse('STS-GNAP-0229',
                         'Signing with ' + name +
                         ' failed inside the cryptographic library: ' +
                         e.message);
    }
    log.debug("Leaving GnapHttpsig.sign(). " + opts.label);
    return {
      ok: true,
      label: opts.label,
      algorithm: name,
      signatureInput: opts.label + '=' + built.signatureParams,
      signature: opts.label + '=' +
                 sf.serializeItem({ type: 'bytes', value: signatureBytes,
                                    params: [] }),
      signatureParams: built.signatureParams,
      base: built.base,
      signatureBytes: signatureBytes
    };
  }

  private headerKeyFor(headers, name) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.headerKeyFor().");
    const keys = Object.keys(headers);
    for (let k = 0; k < keys.length; k++) {
      if (keys[k].toLowerCase() === name) {
        log.debug("Leaving GnapHttpsig.headerKeyFor().");
        return keys[k];
      }
    }
    log.debug("Leaving GnapHttpsig.headerKeyFor().");
    return name;
  }

  // A NEW message with `result`'s two members appended to the message's
  // Signature-Input and Signature fields — the shape of RFC 9635 section
  // 7.3.1.1, where the key-rotation signature is added beside the old key's and
  // covers it.
  //
  // It APPENDS TEXT rather than re-serializing what was there. A later
  // signature may cover the whole `signature-input` field without `;key`, and
  // that covers its bytes as sent; re-serializing the existing members would
  // change those bytes under a signature that has already been made. The
  // existing value is still PARSED first, because appending to a malformed
  // field makes one nobody can read, and a label already present in either
  // field is refused — section 4 says a label MUST be unique, and a second
  // member under it would replace the first for every last-wins parser.
  appendSignature(message, result) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.appendSignature().");
    if (!result || result.ok !== true ||
        typeof result.signatureInput !== 'string' ||
        typeof result.signature !== 'string') {
      log.debug("Leaving GnapHttpsig.appendSignature(). Not a signature.");
      return this.refuse('STS-GNAP-0230',
                         'Only a successful sign() result can be appended to ' +
                         'a message.');
    }
    const headers = Object.assign({}, (message && message.headers) || {});
    const fields = [['signature-input', result.signatureInput],
                    ['signature', result.signature]];
    for (let k = 0; k < fields.length; k++) {
      const lines = this.fieldLines({ headers: headers }, fields[k][0]);
      if (!lines) {
        continue;
      }
      let dictionary;
      try {
        dictionary = sf.parseDictionary(lines.join(', '));
      } catch (e) {
        log.debug("Caught in GnapHttpsig.appendSignature(): " +
                  ((e && e.message) || e));
        log.debug("Leaving GnapHttpsig.appendSignature(). Existing field " +
                  "malformed.");
        return this.refuse('STS-GNAP-0231',
                           'The message\'s existing ' + fields[k][0] +
                           ' field is not a Dictionary, so nothing can be ' +
                           'appended to it: ' + e.message);
      }
      if (sf.member(dictionary, result.label) !== undefined) {
        log.debug("Leaving GnapHttpsig.appendSignature(). Label taken.");
        return this.refuse('STS-GNAP-0230',
                           'The label "' + result.label +
                           '" is already used in the message\'s ' +
                           fields[k][0] +
                           ' field; a signature label MUST be unique (RFC ' +
                           '9421 section 4).');
      }
    }
    fields.forEach((field) => {
      const headerKey = this.headerKeyFor(headers, field[0]);
      const existing = headers[headerKey];
      if (existing === undefined || existing === null) {
        headers[headerKey] = field[1];
      } else if (Array.isArray(existing)) {
        headers[headerKey] = existing.concat([field[1]]);
      } else {
        headers[headerKey] = String(existing) + ', ' + field[1];
      }
    });
    log.debug("Leaving GnapHttpsig.appendSignature(). " + result.label);
    return { ok: true,
             message: Object.assign({}, message, { headers: headers }) };
  }

  // ===========================================================================
  // PARSING THE TWO FIELDS, SECTIONS 4.1, 4.2 AND 3.2 STEPS 1 TO 3.
  // ===========================================================================

  private parseSignatureField(message, name) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.parseSignatureField(). " + name);
    const lines = this.fieldLines(message, name);
    if (!lines) {
      log.debug("Leaving GnapHttpsig.parseSignatureField(). Absent.");
      return { ok: true, dictionary: [] };
    }
    const duplicates = [];
    let dictionary = [];
    try {
      // Line by line as well as combined: a label repeated on two field lines
      // is just as much a second signature under one name as one repeated
      // within a line (section 4.1: "unique across all field values").
      dictionary = sf.parseDictionary(lines.join(', '), {
        onDuplicate: (key) => {
          log.debug("Entering onDuplicate().");
          duplicates.push(key);
          log.debug("Leaving onDuplicate().");
        }
      });
    } catch (e) {
      log.debug("Caught in GnapHttpsig.parseSignatureField(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapHttpsig.parseSignatureField(). Malformed.");
      return this.refuse('STS-GNAP-0231',
                         'The ' + name + ' field is not a Structured Field ' +
                         'Dictionary (RFC 9421 section 4): ' + e.message);
    }
    if (duplicates.length) {
      log.debug("Leaving GnapHttpsig.parseSignatureField(). Duplicate label.");
      return this.refuse('STS-GNAP-0232',
                         'The ' + name + ' field uses the label "' +
                         duplicates[0] + '" more than once; labels MUST be ' +
                         'unique across all field values (RFC 9421 sections ' +
                         '4.1 and 4.2).');
    }
    log.debug("Leaving GnapHttpsig.parseSignatureField(). " +
              dictionary.length + " member(s).");
    return { ok: true, dictionary: dictionary };
  }

  private paramsObject(params) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.paramsObject().");
    const out = {};
    (params || []).forEach((pair) => {
      out[pair[0]] = pair[1].value;
    });
    log.debug("Leaving GnapHttpsig.paramsObject().");
    return out;
  }

  // Every signature the message carries, in Signature-Input order:
  // { ok: true, signatures: [{ label, components, componentIds, params,
  //   paramList, signature, serializedParams }] }, or a refusal.
  parseSignatures(message) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.parseSignatures().");
    const inputs = this.parseSignatureField(message, 'signature-input');
    if (this.isRefusal(inputs)) {
      log.debug("Leaving GnapHttpsig.parseSignatures(). Signature-Input.");
      return inputs;
    }
    const values = this.parseSignatureField(message, 'signature');
    if (this.isRefusal(values)) {
      log.debug("Leaving GnapHttpsig.parseSignatures(). Signature.");
      return values;
    }
    if (inputs.dictionary.length === 0 && values.dictionary.length === 0) {
      log.debug("Leaving GnapHttpsig.parseSignatures(). None.");
      return this.refuse('STS-GNAP-0233',
                         'The message carries no HTTP message signature: it ' +
                         'has no Signature-Input and no Signature field (RFC ' +
                         '9421 section 4).');
    }
    const labels = {};
    inputs.dictionary.forEach((pair) => { labels[pair[0]] = true; });
    values.dictionary.forEach((pair) => { labels[pair[0]] = true; });
    const out = [];
    const allLabels = Object.keys(labels);
    for (let k = 0; k < allLabels.length; k++) {
      const label = allLabels[k];
      const input = sf.member(inputs.dictionary, label);
      const value = sf.member(values.dictionary, label);
      if (input === undefined || value === undefined) {
        log.debug("Leaving GnapHttpsig.parseSignatures(). Label mismatch.");
        return this.refuse('STS-GNAP-0234',
                           'The signature label "' + label +
                           '" is present in the ' +
                           (input === undefined ? 'Signature'
                                                : 'Signature-Input') +
                           ' field and not in the ' +
                           (input === undefined ? 'Signature-Input'
                                                : 'Signature') +
                           ' field; the presence of a label in one field but ' +
                           'not the other is an error (RFC 9421 section 4).');
      }
      const componentsAreStrings = input.type === 'innerList' &&
                                   input.value.every((item) => {
        return item.type === 'string';
      });
      if (!componentsAreStrings || value.type !== 'bytes') {
        log.debug("Leaving GnapHttpsig.parseSignatures(). Member types.");
        return this.refuse('STS-GNAP-0235',
                           !componentsAreStrings
                        ? 'The Signature-Input member "' + label + '" is not ' +
                           'an Inner List of String component identifiers ' +
                           '(RFC 9421 section 4.1).'
                        : 'The Signature member "' + label +
                           '" is not a Byte Sequence (RFC 9421 section 4.2).');
      }
      out.push({
        label: label,
        components: input.value,
        componentIds: input.value.map((item) => {
          return sf.serializeItem(item);
        }),
        params: this.paramsObject(input.params),
        paramList: input.params,
        signature: value.value,
        serializedParams: sf.serializeInnerList(input)
      });
    }
    // Signature-Input order, which is the order a reader of the message sees.
    out.sort((a, b) => {
      return this.indexOfLabel(inputs.dictionary, a.label) -
             this.indexOfLabel(inputs.dictionary, b.label);
    });
    log.debug("Leaving GnapHttpsig.parseSignatures(). " + out.length +
              " signature(s).");
    return { ok: true, signatures: out };
  }

  private indexOfLabel(dictionary, label) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.indexOfLabel().");
    for (let k = 0; k < dictionary.length; k++) {
      if (dictionary[k][0] === label) {
        log.debug("Leaving GnapHttpsig.indexOfLabel().");
        return k;
      }
    }
    log.debug("Leaving GnapHttpsig.indexOfLabel().");
    return -1;
  }

  // ===========================================================================
  // VERIFYING, SECTION 3.2, WITH THE APPLICATION REQUIREMENTS OF 3.2.1.
  // ===========================================================================

  // options:
  //   label             verify only this signature (it must be present)
  //   keyFor(parsed)    -> { key, algorithm } | null; `parsed` is a
  //                     parseSignatures() entry. REQUIRED: section 3.2 step 5
  //                     says an unknown or untrusted key MUST fail.
  //   now               seconds; defaults to the clock
  //   maxAgeS           created must be within this many seconds of now
  //   skewS             how far in the FUTURE created may be; defaults to
  //   maxAgeS requireCreated    refuse a signature with no created (implied by
  //   maxAgeS) requireComponents components that MUST be covered
  //   requireTag        the tag parameter's required value
  //   forbidAlgParam    refuse any signature carrying alg (RFC 9635 7.3.1)
  //   allowedAlgorithms the algorithms policy allows (section 3.2 step 6.1)
  //   require           'all' (default): every candidate must verify;
  //                     'any': one verifying candidate is enough (RFC 9635
  //                     section 7.3.1's "until it finds (at least) one")
  //   fieldTypes        extra Structured Field types for ;sf and ;key
  //
  // Candidates are the labelled signature, else every signature with the
  // required tag, else every signature. The default is 'all' because a verifier
  // that quietly passed over a failing signature has made a policy decision its
  // caller did not.
  verify(message, options) {
    const { log } = this.deps;
    log.debug("Entering GnapHttpsig.verify().");
    const opts = options || {};
    const now = opts.now !== undefined ? opts.now
                                       : Math.floor(Date.now() / 1000);
    const parsed = this.parseSignatures(message);
    if (this.isRefusal(parsed)) {
      log.debug("Leaving GnapHttpsig.verify(). Parse.");
      return parsed;
    }
    let candidates = parsed.signatures;
    if (opts.label !== undefined) {
      candidates =
          candidates.filter((s) => { return s.label === opts.label; });
      if (candidates.length === 0) {
        log.debug("Leaving GnapHttpsig.verify(). Label absent.");
        return this.refuse('STS-GNAP-0236',
                           'The message carries no signature labelled "' +
                           String(opts.label) +
                           '" (RFC 9421 section 3.2 step 1.1).');
      }
    } else if (opts.requireTag !== undefined) {
      candidates = candidates.filter((s) => {
        return s.params.tag === opts.requireTag;
      });
      if (candidates.length === 0) {
        log.debug("Leaving GnapHttpsig.verify(). No signature with the tag.");
        return this.refuse('STS-GNAP-0237',
                           'No signature in the message carries tag="' +
                           String(opts.requireTag) +
                           '"; the tags present are ' + JSON.stringify(
                          parsed.signatures.map((s) => {
                        return s.params.tag === undefined ? null : s.params.tag;
                      })) + ' (RFC 9421 section 3.2.1).');
      }
    }
    const verified = [];
    let firstFailure = null;
    for (let k = 0; k < candidates.length; k++) {
      const result = this.verifyOne(message, candidates[k], opts, now);
      if (result.ok) {
        verified.push(result);
      } else if (opts.require !== 'any') {
        log.debug("Leaving GnapHttpsig.verify(). " + candidates[k].label +
                  " refused.");
        return result;
      } else if (!firstFailure) {
        firstFailure = result;
      }
    }
    if (verified.length === 0) {
      log.debug("Leaving GnapHttpsig.verify(). None verified.");
      return firstFailure;
    }
    log.debug("Leaving GnapHttpsig.verify(). " + verified.length +
              " verified.");
    return { ok: true, verified: verified };
  }

  private verifyOne(message, parsed, opts, now) {
    const { log, sf } = this.deps;
    log.debug("Entering GnapHttpsig.verifyOne(). " + parsed.label);
    const p = parsed.params;
    const paramProblem = this.checkSignatureParams(parsed.paramList);
    if (paramProblem) {
      log.debug("Leaving GnapHttpsig.verifyOne(). Parameter types.");
      return paramProblem;
    }
    if (opts.requireTag !== undefined && p.tag !== opts.requireTag) {
      log.debug("Leaving GnapHttpsig.verifyOne(). Tag.");
      return this.refuse('STS-GNAP-0237',
                         'The signature "' + parsed.label + '" carries ' +
                         (p.tag === undefined ? 'no tag' : 'tag="' + p.tag +
                          '"') +
                         ' and tag="' + opts.requireTag +
                         '" is required (RFC 9421 section 3.2.1).');
    }
    if (opts.forbidAlgParam && p.alg !== undefined) {
      log.debug("Leaving GnapHttpsig.verifyOne(). alg present.");
      return this.refuse('STS-GNAP-0238',
                         'The signature "' + parsed.label +
                         '" carries the alg parameter, which this ' +
                         'application forbids (RFC 9635 section 7.3.1: "The ' +
                         'explicit alg signature parameter MUST NOT be ' +
                         'included").');
    }
    if ((opts.requireCreated ||
         opts.maxAgeS !== undefined) && p.created === undefined) {
      log.debug("Leaving GnapHttpsig.verifyOne(). No created.");
      return this.refuse('STS-GNAP-0239',
                         'The signature "' + parsed.label +
                         '" has no created parameter, and its age must be ' +
                         'checked (RFC 9421 section 3.2.1).');
    }
    if (p.created !== undefined && opts.maxAgeS !== undefined) {
      const skew = opts.skewS !== undefined ? opts.skewS : opts.maxAgeS;
      if (now - p.created > opts.maxAgeS) {
        log.debug("Leaving GnapHttpsig.verifyOne(). Stale.");
        return this.refuse('STS-GNAP-0240',
                           'The signature "' + parsed.label + '" was created ' +
                           (now - p.created) +
                           ' seconds ago, more than the ' + opts.maxAgeS +
                           ' allowed.');
      }
      if (p.created - now > skew) {
        log.debug("Leaving GnapHttpsig.verifyOne(). Future.");
        return this.refuse('STS-GNAP-0241',
                           'The signature "' + parsed.label +
                           '" claims to be created ' + (p.created -
                       now) + ' seconds in the future, more than the ' + skew +
                           ' of clock skew allowed.');
      }
    }
    if (p.expires !== undefined && now >= p.expires) {
      log.debug("Leaving GnapHttpsig.verifyOne(). Expired.");
      return this.refuse('STS-GNAP-0242',
                         'The signature "' + parsed.label + '" expired ' +
                         (now - p.expires) +
                         ' seconds ago (RFC 9421 section 2.3, expires).');
    }
    const required = opts.requireComponents || [];
    const covered = {};
    parsed.components.forEach((item) => {
      covered[this.identityOf(item)] = true;
    });
    for (let k = 0; k < required.length; k++) {
      const wanted = this.componentItem(required[k]);
      if (this.isRefusal(wanted)) {
        log.debug("Leaving GnapHttpsig.verifyOne(). Required component " +
                  "malformed.");
        return wanted;
      }
      if (!covered[this.identityOf(wanted.item)]) {
        log.debug("Leaving GnapHttpsig.verifyOne(). Required component " +
                  "missing.");
        return this.refuse('STS-GNAP-0243',
                           'The signature "' + parsed.label +
                           '" does not cover the required component ' +
                           sf.serializeItem(wanted.item) + '; it covers (' +
                           parsed.componentIds.join(' ') +
                           ') (RFC 9421 section 3.2 step 4).');
      }
    }
    let keyed = null;
    try {
      keyed = typeof opts.keyFor === 'function' ? opts.keyFor(parsed) : null;
    } catch (e) {
      log.debug("Caught in GnapHttpsig.verifyOne(): " +
                ((e && e.message) || e));
      // A key lookup that throws is a key this verifier does not have; the
      // refusal below carries the reason rather than the process carrying the
      // exception.
      log.debug("keyFor() threw: " + e.message);
      keyed = null;
    }
    if (!keyed || keyed.key === undefined || keyed.key === null) {
      log.debug("Leaving GnapHttpsig.verifyOne(). No key.");
      return this.refuse('STS-GNAP-0244',
                         'No verification key is known for the signature "' +
                         parsed.label + '"' +
                         (p.keyid !== undefined ? ' (keyid="' + p.keyid +
                          '")' : '') +
                         '; an unknown or untrusted key MUST fail (RFC 9421 ' +
                         'section 3.2 step 5).');
    }
    const fromKey = keyed.algorithm;
    const fromParam = p.alg;
    if (fromParam !== undefined) {
      const paramEntry = this.algorithmNamed(fromParam);
      if (!paramEntry || paramEntry.registry !== 'http') {
        log.debug("Leaving GnapHttpsig.verifyOne(). alg parameter unknown.");
        return this.refuse('STS-GNAP-0227',
                           'The alg parameter "' + fromParam + '" is not an ' +
                           'algorithm in the HTTP Signature Algorithms ' +
                           'registry this verifier supports (RFC 9421 ' +
                           'sections 2.3 and 3.3.7).');
      }
      if (fromKey !== undefined && fromKey !== fromParam) {
        log.debug("Leaving GnapHttpsig.verifyOne(). alg conflict.");
        return this.refuse('STS-GNAP-0228',
                           'The signature "' + parsed.label + '" says alg="' +
                           fromParam + '" and its key is for ' +
                           fromKey + '; when the algorithm is stated in more ' +
                           'than one place they MUST agree (RFC 9421 section ' +
                           '3.2 step 6.5).');
      }
    }
    const name = fromKey !== undefined ? fromKey : fromParam;
    if (name === undefined) {
      log.debug("Leaving GnapHttpsig.verifyOne(). No algorithm.");
      return this.refuse('STS-GNAP-0226',
                         'No algorithm could be determined for the signature ' +
                         '"' + parsed.label +
                         '": the key names none and the signature carries no ' +
                         'alg parameter (RFC 9421 section 3.2 step 6).');
    }
    const entry = this.algorithmNamed(name);
    if (!entry) {
      log.debug("Leaving GnapHttpsig.verifyOne(). Unknown algorithm.");
      return this.refuse('STS-GNAP-0227',
                         'The signature algorithm ' + JSON.stringify(name) +
                         ' is not supported.');
    }
    if (Array.isArray(opts.allowedAlgorithms) &&
        opts.allowedAlgorithms.indexOf(name) < 0) {
      log.debug("Leaving GnapHttpsig.verifyOne(). Not allowed.");
      return this.refuse('STS-GNAP-0245',
                         'The algorithm ' + name +
                         ' is not one this verifier allows (' +
                         opts.allowedAlgorithms.join(', ') +
                         ') (RFC 9421 section 3.2 step 6.1).');
    }
    const keyProblem = this.checkKey(name, entry, keyed.key, 'verify');
    if (keyProblem) {
      log.debug("Leaving GnapHttpsig.verifyOne(). Key.");
      return keyProblem;
    }
    const built = this.signatureBase(message, parsed.components,
                                     parsed.paramList,
                                     opts);
    if (this.isRefusal(built)) {
      log.debug("Leaving GnapHttpsig.verifyOne(). Base.");
      return built;
    }
    let good;
    try {
      good = this.rawVerify(entry, keyed.key, Buffer.from(built.base, 'ascii'),
                            parsed.signature);
    } catch (e) {
      log.debug("Caught in GnapHttpsig.verifyOne(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapHttpsig.verifyOne(). Primitive threw.");
      return this.refuse('STS-GNAP-0229',
                         'Verifying with ' + name + ' failed inside the ' +
                         'cryptographic library: ' + e.message);
    }
    if (!good) {
      log.debug("Leaving GnapHttpsig.verifyOne(). Bad signature.");
      return this.refuse('STS-GNAP-0246',
                         'The signature "' + parsed.label +
                         '" does not verify with ' + name +
                         ' over the signature base rebuilt from the message: ' +
                         'the message was changed, or it was signed with a ' +
                         'different key (RFC 9421 section 3.2 step 8).');
    }
    log.debug("Leaving GnapHttpsig.verifyOne(). " + parsed.label +
              " verified.");
    return {
      ok: true,
      label: parsed.label,
      algorithm: name,
      keyid: p.keyid,
      components: parsed.componentIds,
      params: p,
      base: built.base
    };
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  static defaultDeps(): GnapHttpsigDeps {
    helpers.log.debug("Entering GnapHttpsig.defaultDeps().");
    helpers.log.debug("Leaving GnapHttpsig.defaultDeps().");
    return {
      nodeCrypto: nodeCrypto,
      log: helpers.log,
      errorCodes: errorCodes,
      sf: sf
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
const slot = new InstanceSlot<GnapHttpsig>(
  'gnap/gnap_httpsig',
  () => new GnapHttpsig(GnapHttpsig.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  GnapHttpsig: GnapHttpsig,
  installInstance: (instance: GnapHttpsig): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ALGORITHMS: GnapHttpsig.ALGORITHMS,
  DIGEST_ALGORITHMS: GnapHttpsig.DIGEST_ALGORITHMS,
  KNOWN_FIELD_TYPES: GnapHttpsig.KNOWN_FIELD_TYPES,
  contentDigest: slot.forward('contentDigest'),
  verifyContentDigest: slot.forward('verifyContentDigest'),
  componentValue: slot.forward('componentValue'),
  signatureBase: slot.forward('signatureBase'),
  sign: slot.forward('sign'),
  appendSignature: slot.forward('appendSignature'),
  parseSignatures: slot.forward('parseSignatures'),
  verify: slot.forward('verify')
};
