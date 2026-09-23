// @ts-check
// File: webauthn.js
//
// ---------------------------------------------------------------------------
// The relying party's half of WebAuthn, server side: verifying a registration
// and an assertion (W3C Web Authentication, sections 7.1 and 7.2).
//
// **Written independently of the debugger's own implementation, on purpose.**
// The wallet-side decoder lives in the debugger's
// client/src/{cbor,cose,webauthn}.js and this file shares no code with it — not
// the CBOR reader, not the COSE mapping, not the signature check. That is the
// same arrangement bbs2023.js is in, and for the same reason: two independent
// readings of one specification that agree is a real result, whereas one
// implementation agreeing with itself is none. tests/webauthn_cross_impl.js in
// the debugger repository runs both over the same real ceremonies and requires
// the same verdict on each.
//
// The independence is not cosmetic. This side verifies ECDSA through node's
// `crypto.verify`, which takes the signature in its native **DER** form; the
// browser side has to convert DER to raw `r‖s` because Web Crypto will not.
// Those are genuinely different code paths, so a mistake in one is not mirrored
// in the other — which is the whole value of the exercise.
//
// Scope: every check a relying party makes about the ceremony itself —
// challenge, origin, RP ID hash, flags, the credential's algorithm against
// what was offered, the credential id's length, and the signature over
// authenticatorData ‖ SHA-256(clientDataJSON). The ATTESTATION STATEMENT is
// decoded and handed back (`attStmt`, with the raw authenticator data and the
// client data hash its verification procedure takes) and NOT verified here:
// that is `authn/webauthn_attestation.ts` (#105, 2026-09-23), which needs
// trust anchors, the FIDO Metadata Service and the realm's policy — none of
// which this file may reach, because it is loaded on its own by the
// debugger's cross-implementation test.
// ---------------------------------------------------------------------------

'use strict';

const crypto = require('crypto');
// The service's shared logger when this module is loaded inside the service,
// and a silent fallback when it is loaded ON ITS OWN — which the debugger's
// cross-implementation test does, copying this one file next to its own
// scripts. `./helpers` is not there, and it could not usefully be: it reads
// process.env.CONFIG_FILE relative to its own directory and pulls in the
// service's dependencies. A verifier written to be checked by somebody else's
// test has no business dragging the whole service in behind it.
//
// THE FALLBACK IS SET BEFORE THE REQUIRE IS TRIED (fixed 2026-09-16). The catch
// used to call `log.debug` while `log` was still undefined, so a standalone
// load threw a TypeError from inside its own fallback. The caught reason is
// kept in `loadProblem` and reported by the silent logger's owner, if any.
const noop = function () {};
/** @type {any} */
let log = { debug: noop, info: noop, warn: noop, error: noop };
let loadProblem = '';
try {
  log = require('../common/helpers').log;
} catch (e) {
  loadProblem = 'the service logger is not reachable: ' +
                ((e && e.message) || e);
}
// `common/crypto.js` for base64url, and the same standalone case: without it,
// Node's own `base64url` encoding, which is what that function wraps.
let stsCrypto = null;
try {
  stsCrypto = require('../common/crypto');
} catch (e) {
  loadProblem = (loadProblem ? loadProblem + '; ' : '') +
                'common/crypto.js is not reachable: ' +
                ((e && e.message) || e);
}
log.debug('authn/webauthn.js loaded' +
          (loadProblem ? ' standalone (' + loadProblem + ').' : '.'));

// --- CBOR, enough of it, decode only -----------------------------------------
//
// A recursive-descent reader over a Buffer, returning [value, nextOffset].
// Definite lengths only: CTAP2's canonical CBOR forbids the indefinite forms,
// so meeting one means the input is not what it claims and saying so is better
// than coping. Maps come back as a Map because COSE keys are integers, several
// of them negative.

const MAX_DEPTH = 24;

function cborRead(buf, offset, depth) {
  log.debug('Entering cborRead().');
  if (depth > MAX_DEPTH) {
    throw new Error('CBOR nested deeper than ' + MAX_DEPTH + ' levels');
  }
  if (offset >= buf.length) {
    throw new Error('CBOR ran off the end of the buffer at ' + offset);
  }
  const initial = buf[offset];
  const major = initial >> 5;
  const info = initial & 0x1f;
  let value;
  let cursor = offset + 1;

  if (info < 24) {
    value = info;
  } else if (info === 24) {
    value = buf.readUInt8(cursor); cursor += 1;
  } else if (info === 25) {
    value = buf.readUInt16BE(cursor); cursor += 2;
  } else if (info === 26) {
    value = buf.readUInt32BE(cursor); cursor += 4;
  } else if (info === 27) {
    const hi = buf.readUInt32BE(cursor), lo = buf.readUInt32BE(cursor + 4);
    value = hi * 4294967296 + lo; cursor += 8;
    if (!Number.isSafeInteger(value)) {
      throw new Error('CBOR argument exceeds the exactly-representable range');
    }
  } else {
    throw new Error('CBOR additional information ' + info + ' is reserved or ' +
                    'indefinite; CTAP2 canonical CBOR uses neither');
  }

  switch (major) {
    case 0:
      log.debug('Leaving cborRead().');
      return [value, cursor];
    case 1:
      log.debug('Leaving cborRead().');
      return [-1 - value, cursor];
    case 2: {
      if (cursor + value > buf.length) {
        throw new Error('a CBOR byte string claims ' + value + ' bytes, past ' +
            'the end of the input');
      }
      log.debug('Leaving cborRead().');
      return [buf.subarray(cursor, cursor + value), cursor + value];
    }
    case 3: {
      if (cursor + value > buf.length) {
        throw new Error('a CBOR text string claims ' + value + ' bytes, past ' +
            'the end of the input');
      }
      log.debug('Leaving cborRead().');
      return [buf.toString('utf8', cursor, cursor + value), cursor + value];
    }
    case 4: {
      const arr = [];
      for (let i = 0; i < value; i++) {
        const [item, next] = cborRead(buf, cursor, depth + 1);
        arr.push(item); cursor = next;
      }
      log.debug('Leaving cborRead().');
      return [arr, cursor];
    }
    case 5: {
      const map = new Map();
      for (let i = 0; i < value; i++) {
        const [k, afterKey] = cborRead(buf, cursor, depth + 1);
        const [v, afterValue] = cborRead(buf, afterKey, depth + 1);
        if (map.has(k)) {
          throw new Error('a CBOR map repeats the key ' + JSON.stringify(k));
        }
        map.set(k, v); cursor = afterValue;
      }
      log.debug('Leaving cborRead().');
      return [map, cursor];
    }
    case 7:
      if (info === 20) {
        log.debug('Leaving cborRead().');
        return [false, cursor];
      }
      if (info === 21) {
        log.debug('Leaving cborRead().');
        return [true, cursor];
      }
      if (info === 22) {
        log.debug('Leaving cborRead().');
        return [null, cursor];
      }
      throw new Error('CBOR simple value ' + info + ' is not decoded here');
    default:
      throw new Error('CBOR major type ' + major + ' is not decoded here');
  }
  log.debug('Leaving cborRead().');
}

function cborDecodeFirst(buf, offset) {
  log.debug("Entering cborDecodeFirst().");
  log.debug("Leaving cborDecodeFirst().");
  return cborRead(buf, offset || 0, 0);
}

// --- COSE_Key -> JWK ----------------------------------------------------------

const COSE_CURVES = { 1: 'P-256', 2: 'P-384', 3: 'P-521', 6: 'Ed25519' };
// PS256/384/512 are RFC 8230's RSASSA-PSS, which TPM authenticators commonly
// use (#105). ML-DSA-44/65/87 are RFC 9964's (published May 2026 from
// draft-ietf-cose-dilithium-11): key type AKP (7), the public key at label
// -1. Those six are verified through `common/crypto.js`'s
// `verifyCoseSignature()`, so a copy of this file loaded ON ITS OWN (see the
// header) recognises them and refuses their signatures rather than
// misreading them — it has no RSASSA-PSS salt rule and no ML-DSA.
const COSE_ALGS = {
  '-7': 'ES256', '-35': 'ES384', '-36': 'ES512', '-8': 'EdDSA',
  '-257': 'RS256', '-258': 'RS384', '-259': 'RS512',
  '-37': 'PS256', '-38': 'PS384', '-39': 'PS512',
  '-48': 'ML-DSA-44', '-49': 'ML-DSA-65', '-50': 'ML-DSA-87',
};
// COSE key type AKP (RFC 9964 section 4) and its `pub` label.
const COSE_KTY_AKP = 7;
// The hash each classical algorithm signs with, for the standalone path.
const STANDALONE_HASHES = {
  ES256: 'sha256', ES384: 'sha384', ES512: 'sha512', RS256: 'sha256',
  RS384: 'sha384', RS512: 'sha512',
};
// WebAuthn Level 3 section 7.1: a credential id longer than this SHOULD fail
// the registration, and here it does.
const MAX_CREDENTIAL_ID_BYTES = 1023;

// base64url, from common/crypto.js — see the note beside helpers.js's. This
// was the third copy of the same three lines in this service.
function b64uStandalone(buf) {
  log.debug("Entering b64uStandalone().");
  log.debug("Leaving b64uStandalone().");
  return Buffer.from(buf).toString('base64url');
}

const b64u = stsCrypto ? stsCrypto.b64u : b64uStandalone;

function coseKeyToJwk(coseKey) {
  log.debug('Entering coseKeyToJwk().');
  if (!(coseKey instanceof Map)) {
    throw new Error('the credential public key is not a COSE_Key map');
  }
  const kty = coseKey.get(1);
  const alg = coseKey.get(3);
  let jwk;
  if (kty === 2) {
    const crv = COSE_CURVES[coseKey.get(-1)];
    if (!crv) {
      throw new Error('unsupported COSE curve ' + coseKey.get(-1));
    }
    jwk = { kty: 'EC', crv: crv, x: b64u(coseKey.get(-2)),
            y: b64u(coseKey.get(-3)) };
  } else if (kty === 3) {
    jwk = { kty: 'RSA', n: b64u(coseKey.get(-1)), e: b64u(coseKey.get(-2)) };
  } else if (kty === 1) {
    const crv = COSE_CURVES[coseKey.get(-1)];
    if (!crv) {
      throw new Error('unsupported COSE OKP curve ' + coseKey.get(-1));
    }
    jwk = { kty: 'OKP', crv: crv, x: b64u(coseKey.get(-2)) };
  } else if (kty === COSE_KTY_AKP) {
    // RFC 9964: the algorithm is part of an AKP key, not beside it, so a key
    // whose `alg` is not an ML-DSA identifier is not one this reads.
    if (!/^ML-DSA-/.test(String(COSE_ALGS[String(alg)] || '')) ||
        !Buffer.isBuffer(coseKey.get(-1))) {
      throw new Error('an AKP COSE key needs an ML-DSA alg and a pub; this ' +
                      'one has alg ' + alg);
    }
    jwk = { kty: 'AKP', pub: b64u(coseKey.get(-1)) };
  } else {
    throw new Error('unsupported COSE key type ' + kty);
  }
  // THE ALGORITHM TRAVELS ON THE JWK (#105), because an assertion is checked
  // against the stored JWK and nothing else: ES384's hash is SHA-384 and
  // PS256's padding is PSS, and a key stored without its algorithm was
  // checked with SHA-256 and PKCS#1 v1.5 whatever it was. A key stored
  // before this has none, and is read as it always was (see
  // `coseAlgOfJwk()`).
  if (COSE_ALGS[String(alg)]) {
    jwk.alg = COSE_ALGS[String(alg)];
  }
  log.debug('Leaving coseKeyToJwk(). kty=' + jwk.kty + ' alg=' +
            COSE_ALGS[String(alg)]);
  return { jwk: jwk, alg: COSE_ALGS[String(alg)] || null, coseAlg: alg };
}

// --- authenticator data --------------------------------------------------------

function parseAuthenticatorData(buf) {
  log.debug('Entering parseAuthenticatorData(). bytes=' + buf.length);
  if (buf.length < 37) {
    throw new Error('authenticator data is ' + buf.length + ' bytes; the ' +
        'fixed part alone is 37');
  }
  const flags = buf[32];
  const out = {
    rpIdHash: buf.subarray(0, 32),
    flags: {
      up: !!(flags & 0x01), uv: !!(flags & 0x04), be: !!(flags & 0x08),
      bs: !!(flags & 0x10), at: !!(flags & 0x40), ed: !!(flags & 0x80),
    },
    signCount: buf.readUInt32BE(33),
    aaguid: null, credentialId: null, credentialPublicKey: null,
  };
  let cursor = 37;
  if (out.flags.at) {
    if (buf.length < cursor + 18) {
      throw new Error('the AT flag is set but the attested credential data ' +
                      'does not fit');
    }
    out.aaguid = buf.subarray(cursor, cursor + 16); cursor += 16;
    const idLength = buf.readUInt16BE(cursor); cursor += 2;
    if (buf.length < cursor + idLength) {
      throw new Error('the credential ID claims ' + idLength + ' bytes, past ' +
          'the end');
    }
    out.credentialId = buf.subarray(cursor,
                                    cursor + idLength); cursor += idLength;
    const [key, next] = cborDecodeFirst(buf, cursor);
    out.credentialPublicKey = key;
    cursor = next;
  }
  if (out.flags.ed) {
    const [ext, next] = cborDecodeFirst(buf, cursor);
    out.extensions = ext;
    cursor = next;
  }
  log.debug('Leaving parseAuthenticatorData(). at=' + out.flags.at + ' ' +
      'signCount=' + out.signCount);
  return out;
}

// --- the two ceremonies ----------------------------------------------------------

function parseClientData(buf, expectedType) {
  log.debug("Entering parseClientData().");
  const text = buf.toString('utf8');
  let json;
  try {
    json = JSON.parse(text);
  } catch (e) {
    throw new Error('clientDataJSON is not JSON: ' + e.message);
  }
  log.debug("Leaving parseClientData().");
  return { json: json, text: text, typeMatches: json.type === expectedType };
}

function sha256(buf) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return crypto.createHash('sha256').update(buf).digest();
}

// Every check by name, in order, so a caller can report WHICH one failed. A
// single boolean is what makes people blame the authenticator.
function collect() {
  log.debug('Entering collect().');
  const checks = [];
  log.debug('Leaving collect().');
  return {
    checks: checks,
    add: function (name, ok, detail) {
      log.debug("Entering add().");
      checks.push({ name: name, ok: !!ok, detail: detail || '' });
      log.debug("Leaving add().");
      return !!ok;
    },
    ok: function () {
      log.debug("Entering ok().");
      log.debug("Leaving ok().");
      return checks.every(function (c) { return c.ok; });
    },
    failed: function () {
      log.debug("Entering failed().");
      log.debug("Leaving failed().");
      return checks.filter(function (c) { return !c.ok; })
                   .map(function (c) { return c.name; });
    },
  };
}

// The COSE algorithm a stored JWK is checked with: its own `alg` where it
// carries one, and otherwise what a key stored before #105 was always checked
// with — SHA-256 for RSA and P-256, the curve's own hash for P-384 and P-521
// (which the old code got wrong), EdDSA for an OKP key.
function coseAlgOfJwk(jwk) {
  log.debug("Entering coseAlgOfJwk().");
  const j = jwk || {};
  const named = Object.keys(COSE_ALGS).filter(function (id) {
    return COSE_ALGS[id] === j.alg;
  })[0];
  if (named) {
    log.debug("Leaving coseAlgOfJwk(). " + j.alg);
    return Number(named);
  }
  let alg = -7;
  if (j.kty === 'RSA') {
    alg = -257;
  } else if (j.kty === 'OKP') {
    alg = -8;
  } else if (j.crv === 'P-384') {
    alg = -35;
  } else if (j.crv === 'P-521') {
    alg = -36;
  }
  log.debug("Leaving coseAlgOfJwk(). " + alg + " by key type.");
  return alg;
}

// Does `signature` verify over `data` under the stored `jwk`? Through
// `common/crypto.js` in the service; a copy of this file loaded on its own
// checks the classical algorithms with node and refuses the rest.
function verifyWithJwk(jwk, data, signature) {
  log.debug("Entering verifyWithJwk().");
  const coseAlg = coseAlgOfJwk(jwk);
  if (stsCrypto && typeof stsCrypto.verifyCoseSignature === 'function') {
    const ok = stsCrypto.verifyCoseSignature(coseAlg, jwk, data, signature);
    log.debug("Leaving verifyWithJwk(). " + ok);
    return ok;
  }
  const name = COSE_ALGS[String(coseAlg)];
  const bare = Object.assign({}, jwk);
  delete bare.alg;
  const keyObject = crypto.createPublicKey({ key: bare, format: 'jwk' });
  if (name === 'EdDSA') {
    log.debug("Leaving verifyWithJwk(). Standalone EdDSA.");
    return crypto.verify(null, data, keyObject, signature);
  }
  if (!STANDALONE_HASHES[name]) {
    log.debug("Leaving verifyWithJwk(). Standalone, unsupported.");
    return false;
  }
  // node takes an ECDSA signature in its native DER form, which is how it
  // arrives from the authenticator — no conversion, unlike Web Crypto.
  log.debug("Leaving verifyWithJwk(). Standalone " + name + ".");
  return crypto.verify(STANDALONE_HASHES[name], data, keyObject, signature);
}

// A CBOR value as plain data: a map with text keys becomes an object, an
// array stays an array, a byte string stays a Buffer. What the attestation
// statement is handed over as — a Map with integer keys (a COSE key) is kept
// as a Map, since an object would turn -1 into "-1".
function plainOf(value) {
  log.debug("Entering plainOf().");
  if (value instanceof Map) {
    const textKeys = Array.from(value.keys()).every(function (k) {
      return typeof k === 'string';
    });
    if (!textKeys) {
      log.debug("Leaving plainOf(). A map with other keys.");
      return value;
    }
    const out = {};
    value.forEach(function (v, k) {
      out[k] = plainOf(v);
    });
    log.debug("Leaving plainOf(). An object.");
    return out;
  }
  if (Array.isArray(value)) {
    log.debug("Leaving plainOf(). An array.");
    return value.map(plainOf);
  }
  log.debug("Leaving plainOf().");
  return value;
}

function verifyRegistration(input) {
  log.debug('Entering verifyRegistration().');
  const c = collect();
  const attestationObject = Buffer.from(input.attestationObject, 'base64url');
  const clientDataJSON = Buffer.from(input.clientDataJSON, 'base64url');

  const [decoded] = cborDecodeFirst(attestationObject, 0);
  if (!(decoded instanceof Map)) {
    throw new Error('the attestation object is not a CBOR map');
  }
  const fmt = decoded.get('fmt');
  const authDataBuf = decoded.get('authData');
  const authData = parseAuthenticatorData(authDataBuf);
  const cd = parseClientData(clientDataJSON, 'webauthn.create');

  c.add('clientData.type is webauthn.create', cd.typeMatches,
        'type=' + cd.json.type);
  c.add('challenge matches', cd.json.challenge === input.expectedChallenge,
        'got ' + cd.json.challenge);
  c.add('origin matches', cd.json.origin === input.expectedOrigin,
        'got ' + cd.json.origin + ', expected ' + input.expectedOrigin);
  c.add('rpIdHash is SHA-256 of the RP ID',
        authData.rpIdHash.equals(sha256(Buffer.from(input.expectedRpId,
                                                    'utf8'))),
        'rpId=' + input.expectedRpId);
  c.add('user presence', authData.flags.up, 'UP=' + authData.flags.up);
  if (input.requireUserVerification) {
    c.add('user verification', authData.flags.uv, 'UV=' + authData.flags.uv);
  }
  c.add('attested credential data present', authData.flags.at,
        'AT=' + authData.flags.at);
  // Section 7.1: "If the BE bit of the flags in authData is not set, verify
  // that the BS bit is not set" — a credential backed up that is not backup
  // eligible is an authenticator contradicting itself.
  c.add('backup state only where backup eligible',
        authData.flags.be || !authData.flags.bs,
        'BE=' + authData.flags.be + ' BS=' + authData.flags.bs);

  let key = null;
  if (authData.flags.at) {
    key = coseKeyToJwk(authData.credentialPublicKey);
    // Section 7.1: the credential's "alg" must be one of the
    // pubKeyCredParams this relying party offered (#105). Only where the
    // caller says what it offered: a copy of this file checking somebody
    // else's recorded ceremony has no offer to compare with.
    if (Array.isArray(input.expectedAlgorithms)) {
      c.add('credential algorithm was offered',
            input.expectedAlgorithms.map(Number).indexOf(
              Number(key.coseAlg)) >= 0,
            'alg ' + key.coseAlg + ', offered ' +
              input.expectedAlgorithms.join(', '));
    }
    // Section 7.1: a credential id of more than 1023 bytes SHOULD fail the
    // ceremony (#105).
    c.add('credential ID is at most 1023 bytes',
          authData.credentialId.length <= MAX_CREDENTIAL_ID_BYTES,
          authData.credentialId.length + ' bytes');
  }

  const result = {
    ok: c.ok(),
    checks: c.checks,
    failed: c.failed(),
    fmt: fmt,
    aaguid: authData.aaguid ? authData.aaguid.toString('hex') : null,
    credentialId: authData.credentialId ? b64u(authData.credentialId) : null,
    publicKeyJwk: key ? key.jwk : null,
    algorithm: key ? key.alg : null,
    signCount: authData.signCount,
    // THE FLAGS, AS `verifyAssertion()` BESIDE THIS ALREADY RETURNED THEM
    // (2026-09-10). Registration did not, so a caller that wanted to record
    // whether the authenticator VERIFIED THE PERSON at enrolment — which is
    // what `webauthn.userVerification` is about, and what a relying party
    // reports beside a key — had the byte parsed, checked and then dropped.
    // It is the same object from the same parse; the asymmetry was an
    // oversight rather than a decision.
    flags: authData.flags,
    // WHAT THE ATTESTATION STATEMENT'S VERIFICATION PROCEDURE TAKES (#105):
    // section 7.1 step 22 hands it `attStmt`, the RAW authenticator data and
    // the client data hash, and none of the three was returned, so no caller
    // could have verified the statement even had it tried. This file verifies
    // nothing more for returning them.
    attStmt: plainOf(decoded.get('attStmt')),
    authDataRaw: authDataBuf,
    clientDataHash: sha256(clientDataJSON),
    credentialPublicKeyCose: authData.credentialPublicKey,
    credentialIdRaw: authData.credentialId,
    rpIdHash: authData.rpIdHash,
    coseAlg: key ? key.coseAlg : null,
  };
  log.debug('Leaving verifyRegistration(). ok=' + result.ok);
  return result;
}

function verifyAssertion(input) {
  log.debug('Entering verifyAssertion().');
  const c = collect();
  const authDataBuf = Buffer.from(input.authenticatorData, 'base64url');
  const clientDataJSON = Buffer.from(input.clientDataJSON, 'base64url');
  const signature = Buffer.from(input.signature, 'base64url');
  const authData = parseAuthenticatorData(authDataBuf);
  const cd = parseClientData(clientDataJSON, 'webauthn.get');

  c.add('clientData.type is webauthn.get', cd.typeMatches,
        'type=' + cd.json.type);
  c.add('challenge matches', cd.json.challenge === input.expectedChallenge,
        'got ' + cd.json.challenge);
  c.add('origin matches', cd.json.origin === input.expectedOrigin,
        'got ' + cd.json.origin + ', expected ' + input.expectedOrigin);
  c.add('rpIdHash is SHA-256 of the RP ID',
        authData.rpIdHash.equals(sha256(Buffer.from(input.expectedRpId,
                                                    'utf8'))),
        'rpId=' + input.expectedRpId);
  c.add('user presence', authData.flags.up, 'UP=' + authData.flags.up);
  if (input.requireUserVerification) {
    // Its own check, never folded into the signature: a UV-clear assertion is
    // correctly signed, and calling it a bad signature sends the operator after
    // the wrong thing entirely.
    c.add('user verification', authData.flags.uv, 'UV=' + authData.flags.uv);
  }
  if (typeof input.previousSignCount === 'number') {
    const advanced = authData.signCount === 0 && input.previousSignCount === 0
      ? true : authData.signCount > input.previousSignCount;
    c.add('signature counter advanced', advanced,
          'now ' + authData.signCount + ', was ' + input.previousSignCount);
  }

  // The signed message: raw authenticator data, then the HASH of the client
  // data.
  const signedData = Buffer.concat([authDataBuf, sha256(clientDataJSON)]);
  let signatureValid = false;
  try {
    signatureValid = verifyWithJwk(input.publicKeyJwk, signedData, signature);
  } catch (e) {
    // A key node cannot import, or a signature it cannot parse. Both are
    // verification failures rather than crashes, and the reason belongs in the
    // check's detail where the operator will see it.
    signatureValid = false;
    c.add('signature verifies', false, 'the key or signature could not be ' +
                                       'read: ' + e.message);
  }
  if (!c.checks.some(function (x) {
    return x.name === 'signature verifies';
  })) {
    c.add('signature verifies', signatureValid,
          (input.publicKeyJwk.alg ||
           input.publicKeyJwk.kty) + ' over ' + signedData.length + ' ' +
              'bytes');
  }

  const result = {
    ok: c.ok(),
    checks: c.checks,
    failed: c.failed(),
    signatureValid: signatureValid,
    signCount: authData.signCount,
    flags: authData.flags,
  };
  log.debug('Leaving verifyAssertion(). ok=' + result.ok);
  return result;
}

module.exports = {
  // The COSE tables, for `admin-ui/crypto_metadata.ts`, which reports what
  // this relying party will accept rather than keeping a second copy of it.
  // They are DATA and not behaviour: exporting them cannot change what this
  // file verifies, and the alternative was a list of algorithms typed into a
  // console page that would have drifted the first time one was added here.
  COSE_ALGS,
  COSE_CURVES,
  COSE_KTY_AKP,
  MAX_CREDENTIAL_ID_BYTES,
  coseAlgOfJwk,
  verifyRegistration,
  verifyAssertion,
  parseAuthenticatorData,
  coseKeyToJwk,
  cborDecodeFirst,
};
