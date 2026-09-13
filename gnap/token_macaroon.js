'use strict';
//
// File: token_macaroon.js
//
// ===========================================================================
// THE `macaroon` GNAP TOKEN FORMAT (RFC 9767 SECTION 5.3.2), ON libmacaroons'
// V2 BINARY SERIALISATION (2026-09-12).
//
// A route-free library: it registers nothing and requires `common/helpers.js`,
// `common/error_codes.js`, `gnap/gnap_access.js` and the npm `macaroon`
// package, none of which requires anything back.
//
// ---------------------------------------------------------------------------
// WHAT A MACAROON IS, AND THE ONE THING IT BUYS GNAP.
//
// A macaroon is an identifier and a list of CAVEATS chained under HMAC-SHA256:
// the signature after each caveat is the HMAC of that caveat keyed by the
// signature before it, and the first key is derived from a ROOT KEY only the
// authorization server holds. Anybody holding a macaroon can append a caveat
// and compute the next signature; nobody can REMOVE one, because that means
// running the HMAC backwards. RFC 9767 section 2.2 names that property — "the
// RS [can] derive sub-tokens without having to call the AS" — and it is the
// whole reason this format is in the registry beside JWT: `attenuate()` below
// is a resource server narrowing a token it was handed, offline.
//
// THE COST IS THE OTHER HALF OF THE SAME SENTENCE: a macaroon is verified with
// the ROOT KEY, symmetric, so the verifier is the AS or somebody the AS shares
// that key with. There is no public verification material to publish and
// `describe()` says so.
//
// ---------------------------------------------------------------------------
// THE CAVEAT GRAMMAR. Nothing standardises what a first-party caveat SAYS —
// the macaroon paper leaves it to the target service — so this file defines
// it, and defines it strictly: A CAVEAT THAT DOES NOT PARSE MAKES VERIFICATION
// FAIL. A verifier that skipped caveats it did not understand would turn every
// attenuation somebody else wrote in a slightly different spelling into no
// attenuation at all, which is the failure a caveat exists to prevent.
//
//   identifier   gnap:v1:<jti>
//
//   gnap:iss=<absolute URI>                 the issuing grant endpoint
//   gnap:iat=<integer seconds>
//   gnap:sub=<string>                       optional
//   gnap:client=<instance identifier>
//   gnap:bearer                             exactly one of these two …
//   gnap:cnf=jkt:<b64url SHA-256>           … the key binding, spelt by
//   gnap:cnf=x5t:<b64url SHA-256>             `gnap_access.cnfToString()`
//   gnap:cnf=kid:<key reference>
//   gnap:flags=<flag>[,<flag>]              optional; bearer, durable
//   gnap:label=<string>                     optional
//   gnap:exp<<integer seconds>              valid while now < value
//   gnap:nbf>=<integer seconds>             optional; valid while now >= value
//   gnap:aud=<id>[ <id>]*                   optional; single spaces
//   gnap:access=<b64url JSON array>         RFC 9635 section 8 rights
//
// A string value is one or more characters with no control character. An
// integer is decimal with no sign and no leading zero. `gnap:aud=` and
// `gnap:access=` must be non-empty.
//
// ---------------------------------------------------------------------------
// THE AUTHORITY SECTION AND THE ATTENUATION SECTION — WHY THE ORDER IS PART OF
// THE GRAMMAR.
//
// Anybody holding a macaroon can append ANY caveat, not only narrowing ones.
// `gnap:sub=alice` appended to a token that had no subject is a caveat the HMAC
// chain accepts perfectly, and a verifier that read "the sub caveat" would then
// hand a resource server a subject the AS never asserted. A token model read
// out of caveats must know WHICH caveats the AS wrote.
//
// So the AS writes its caveats in a fixed order and ALWAYS ends with exactly
// one `gnap:access=`, and that caveat is the boundary:
//
//   * THE AUTHORITY SECTION is everything up to and including the first
//     `gnap:access=`. It must hold iss, iat, client, exp and a binding exactly
//     once, and sub, nbf, aud, flags and label at most once. The model is read
//     from here and nowhere else.
//   * THE ATTENUATION SECTION is everything after it, and may hold ONLY the
//     four caveats that can only narrow: `gnap:exp<`, `gnap:nbf>=`,
//     `gnap:aud=` and `gnap:access=`, any number of each. A singular caveat
//     here — a second subject, a binding added to a bearer token, a flag — is
//     refused, because it could only be somebody trying to change a claim.
//
// Verification then enforces EVERY caveat: the earliest exp, the latest nbf,
// every aud list must name the verifying RS, and every access list must cover
// the request's requirement. The model returned is the AUTHORITY's, so a round
// trip is exact; `attenuated: true` beside it says the effective token is
// narrower than the model reads.
//
// ---------------------------------------------------------------------------
// THE ORDER OF VERIFICATION: THE HMAC CHAIN FIRST, THE GRAMMAR SECOND.
//
// The library calls a caveat checker for each caveat WHILE it walks the chain
// and compares the signature only at the end, so a checker that refused an
// unknown caveat would report "unknown caveat" for a token whose real problem
// is that it was forged. The checker here accepts every caveat and records it;
// the grammar runs once the chain has verified. A tampered token is reported as
// tampered.
//
// ---------------------------------------------------------------------------
// THE SERIALISER IS HERE AND NOT IN THE LIBRARY, AND THAT IS A LIBRARY DEFECT
// RATHER THAN A PREFERENCE.
//
// `macaroon@3.0.4`'s `ByteBuffer._grow()` compares against `this._capacity`,
// which nothing ever sets, so EVERY append doubles the buffer. Its
// `exportBinary()` starts at 200 bytes and makes three appends per caveat, so
// a macaroon of five caveats asks for a buffer of gigabytes and fails with
// "Array buffer allocation failed" — and this format's authority section is
// up to twelve caveats. `encodeBinaryV2()` below writes the same bytes from the
// macaroon's public getters (the v2 layout is five field types and a varint),
// and the library's own IMPORTER, which uses a different reader with no such
// bug, is what reads them back — so every mint is checked by the library in
// the direction that works. `tests/gnap_token_formats.js` compares the two
// encoders byte for byte on a macaroon small enough for the library's.
//
// THIRD-PARTY CAVEATS ARE REFUSED before the chain is walked. They need a
// discharge macaroon from another service, this format carries none, and the
// library would fail with a sentence about a missing discharge that names
// nothing an operator could act on.
// ===========================================================================

const macaroon = require('macaroon');
const helpers = require('../common/helpers');
const errorCodes = require('../common/error_codes');
const access = require('./gnap_access');

const log = helpers.log;

const FORMAT = 'macaroon';
const IDENTIFIER_PREFIX = 'gnap:v1:';
const MIN_ROOT_KEY_BYTES = 32;

const INTEGER = '(0|[1-9][0-9]{0,15})';
const STRING = '([^\\x00-\\x1f\\x7f]+)';
const CAVEATS = [
  { kind: 'iss', re: new RegExp('^gnap:iss=' + STRING + '$') },
  { kind: 'iat', re: new RegExp('^gnap:iat=' + INTEGER + '$') },
  { kind: 'sub', re: new RegExp('^gnap:sub=' + STRING + '$') },
  { kind: 'client', re: new RegExp('^gnap:client=' + STRING + '$') },
  { kind: 'bearer', re: /^gnap:bearer$/ },
  { kind: 'cnf', re: new RegExp('^gnap:cnf=' + STRING + '$') },
  { kind: 'flags', re: /^gnap:flags=([a-z]+(?:,[a-z]+)*)$/ },
  { kind: 'label', re: new RegExp('^gnap:label=' + STRING + '$') },
  { kind: 'exp', re: new RegExp('^gnap:exp<' + INTEGER + '$') },
  { kind: 'nbf', re: new RegExp('^gnap:nbf>=' + INTEGER + '$') },
  { kind: 'aud', re: /^gnap:aud=([^\s]+(?: [^\s]+)*)$/ },
  { kind: 'access', re: /^gnap:access=([A-Za-z0-9_-]+)$/ }
];

// The four caveats an attenuation may add, because each can only narrow.
const ATTENUATING = ['exp', 'nbf', 'aud', 'access'];
// Exactly once in the authority section.
const REQUIRED_ONCE = ['iss', 'iat', 'client', 'exp'];
// At most once in the authority section.
const OPTIONAL_ONCE = ['sub', 'nbf', 'aud', 'flags', 'label'];

const VALUE_RE = /^[A-Za-z0-9_-]+$/;

function refusal(code, why) {
  return access.refusal(code, why);
}

// libmacaroons v2 binary: version byte 2; [location] identifier EOS; per caveat
// [location] identifier [vid] EOS; EOS; signature. A field is its type byte, a
// uvarint length and the bytes; EOS is the type byte 0 alone.
const FIELD_EOS = 0;
const FIELD_LOCATION = 1;
const FIELD_IDENTIFIER = 2;
const FIELD_VID = 4;
const FIELD_SIGNATURE = 6;

function encodeBinaryV2(mac) {
  log.debug("Entering encodeBinaryV2().");
  const parts = [Buffer.from([2])];
  function uvarint(n) {
    const out = [];
    let x = n;
    while (x >= 0x80) {
      out.push((x & 0x7f) | 0x80);
      x = Math.floor(x / 128);
    }
    out.push(x);
    return Buffer.from(out);
  }
  function field(type, data) {
    parts.push(Buffer.from([type]));
    if (type !== FIELD_EOS) {
      const bytes = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
      parts.push(uvarint(bytes.length), bytes);
    }
  }
  if (mac.location) {
    field(FIELD_LOCATION, mac.location);
  }
  field(FIELD_IDENTIFIER, mac.identifier);
  field(FIELD_EOS);
  mac.caveats.forEach(function (cav) {
    if (cav.location) {
      field(FIELD_LOCATION, cav.location);
    }
    field(FIELD_IDENTIFIER, cav.identifier);
    if (cav.vid) {
      field(FIELD_VID, cav.vid);
    }
    field(FIELD_EOS);
  });
  field(FIELD_EOS);
  field(FIELD_SIGNATURE, mac.signature);
  const out = Buffer.concat(parts);
  log.debug("Leaving encodeBinaryV2(). " + out.length + " byte(s).");
  return out;
}

function b64uJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

// Strict base64url: the alphabet, no padding, and a round trip to the same
// text — Buffer's decoder is lenient and would accept a value with junk in it.
function b64uBytes(text) {
  if (typeof text !== 'string' || !VALUE_RE.test(text)) {
    return null;
  }
  const bytes = Buffer.from(text, 'base64url');
  return bytes.toString('base64url') === text ? bytes : null;
}

// ---------------------------------------------------------------------------
// One caveat to `{ kind, value }`, or null when it is outside the grammar.
// ---------------------------------------------------------------------------
function parseCaveat(text) {
  log.debug("Entering parseCaveat().");
  for (let i = 0; i < CAVEATS.length; i++) {
    const m = CAVEATS[i].re.exec(text);
    if (!m) {
      continue;
    }
    const kind = CAVEATS[i].kind;
    let value = m[1];
    if (kind === 'iat' || kind === 'exp' || kind === 'nbf') {
      value = Number(value);
      if (!Number.isSafeInteger(value)) {
        log.debug("Leaving parseCaveat(). Integer out of range.");
        return null;
      }
    } else if (kind === 'bearer') {
      value = true;
    } else if (kind === 'cnf') {
      value = access.cnfFromString(value);
      if (!value) {
        log.debug("Leaving parseCaveat(). Malformed confirmation.");
        return null;
      }
    } else if (kind === 'flags' || kind === 'aud') {
      value = value.split(kind === 'flags' ? ',' : ' ');
    } else if (kind === 'access') {
      const bytes = b64uBytes(value);
      let parsed;
      try {
        parsed = bytes ? JSON.parse(bytes.toString('utf8')) : null;
      } catch (e) {
        // Not JSON; null is the refusal, and the caller names the caveat.
        parsed = null;
      }
      const normal = access.normalise(parsed);
      if (!normal.ok) {
        log.debug("Leaving parseCaveat(). Access is not a valid access array.");
        return null;
      }
      value = normal.access;
    }
    log.debug("Leaving parseCaveat(). kind=" + kind);
    return { kind: kind, value: value };
  }
  log.debug("Leaving parseCaveat(). Outside the grammar.");
  return null;
}

// ---------------------------------------------------------------------------
// The caveats a model is written as, in the authority order the header gives.
// Returns `{ ok:true, caveats }` or a refusal when a value cannot be spelt in
// the grammar (whitespace inside an audience, say).
// ---------------------------------------------------------------------------
function caveatsFor(model) {
  log.debug("Entering caveatsFor().");
  const out = [];
  out.push('gnap:iss=' + model.iss);
  out.push('gnap:iat=' + model.iat);
  if (model.sub !== null) {
    out.push('gnap:sub=' + model.sub);
  }
  out.push('gnap:client=' + model.instanceId);
  out.push(model.cnf ? 'gnap:cnf=' + access.cnfToString(model.cnf) : 'gnap:bearer');
  if (model.flags.length) {
    out.push('gnap:flags=' + model.flags.join(','));
  }
  if (model.label !== null) {
    out.push('gnap:label=' + model.label);
  }
  out.push('gnap:exp<' + model.exp);
  if (model.nbf !== null) {
    out.push('gnap:nbf>=' + model.nbf);
  }
  if (model.aud.length) {
    out.push('gnap:aud=' + model.aud.join(' '));
  }
  out.push('gnap:access=' + b64uJson(model.access));
  // The caveats must READ BACK as the model that was meant — through the same
  // reader verify() uses. Merely parsing is not enough: an audience of
  // "https://rs one" writes a caveat that parses perfectly, as TWO audiences.
  // This catches every value the model allows and the grammar cannot carry,
  // rather than listing them twice.
  const read = readCaveats(out, model.jti);
  if (!read.ok || access.canonicalJson(read.model) !== access.canonicalJson(model)) {
    log.debug("Leaving caveatsFor(). Not expressible.");
    return refusal('STS-GNAP-0310', 'the token model cannot be written as macaroon caveats that ' +
                   'read back as the same model (an audience with whitespace in it, a label ' +
                   'with a control character, for example).');
  }
  log.debug("Leaving caveatsFor(). " + out.length + " caveat(s).");
  return { ok: true, caveats: out };
}

function rootKeyOf(keys) {
  const key = keys && keys.rootKey;
  if (!(key instanceof Uint8Array) || key.length < MIN_ROOT_KEY_BYTES) {
    return null;
  }
  return key;
}

// ---------------------------------------------------------------------------
// mint(model, keys): keys = { rootKey: Buffer of 32+ bytes, location }.
// ---------------------------------------------------------------------------
async function mint(model, keys) {
  log.debug("Entering mint().");
  const valid = access.validateModel(model);
  if (!valid.ok) {
    log.debug("Leaving mint(). Model invalid.");
    return valid;
  }
  const rootKey = rootKeyOf(keys);
  if (!rootKey) {
    log.debug("Leaving mint(). Root key unusable.");
    return refusal('STS-GNAP-0310', 'a macaroon root key must be at least ' + MIN_ROOT_KEY_BYTES +
                   ' bytes.');
  }
  const written = caveatsFor(valid.model);
  if (!written.ok) {
    log.debug("Leaving mint(). Not expressible.");
    return written;
  }
  let value;
  try {
    const mac = macaroon.newMacaroon({
      identifier: IDENTIFIER_PREFIX + valid.model.jti,
      location: typeof keys.location === 'string' ? keys.location : valid.model.iss,
      rootKey: rootKey,
      version: 2
    });
    written.caveats.forEach(function (c) { mac.addFirstPartyCaveat(c); });
    value = encodeBinaryV2(mac).toString('base64url');
  } catch (e) {
    log.warn(errorCodes.tag('STS-GNAP-0310') + 'macaroon minting failed in the library: ' + e.message);
    log.debug("Leaving mint(). Library failure.");
    return refusal('STS-GNAP-0310', 'the macaroon library refused to mint: ' + e.message);
  }
  log.debug("Leaving mint(). jti=" + valid.model.jti);
  return { value: value, format: FORMAT, jti: valid.model.jti };
}

// Import without verifying; shared by verify() and attenuate().
function importValue(value) {
  log.debug("Entering importValue().");
  const bytes = b64uBytes(value);
  if (!bytes) {
    log.debug("Leaving importValue(). Not base64url.");
    return refusal('STS-GNAP-0311', 'the token value is not unpadded base64url.');
  }
  let mac;
  try {
    mac = macaroon.importMacaroon(new Uint8Array(bytes));
  } catch (e) {
    // The library's own sentence is the useful part of the refusal.
    log.debug("Leaving importValue(). Import failed: " + e.message);
    return refusal('STS-GNAP-0311', 'the token value is not a libmacaroons v2 binary macaroon: ' +
                   e.message);
  }
  if (mac.caveats.some(function (c) { return c.vid !== undefined; })) {
    log.debug("Leaving importValue(). Third-party caveat.");
    return refusal('STS-GNAP-0313', 'the macaroon carries a third-party caveat, which needs a ' +
                   'discharge macaroon this token format does not carry.');
  }
  log.debug("Leaving importValue(). Imported.");
  return { ok: true, mac: mac };
}

function decodeUtf8(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (e) {
    // Not UTF-8, so not a caveat in this grammar; null is the refusal.
    return null;
  }
}

// ---------------------------------------------------------------------------
// The caveat list to a model and its attenuations. Returns
// `{ ok:true, model, audience:[lists], access:[lists], exp, nbf, attenuated }`
// or a refusal.
// ---------------------------------------------------------------------------
function readCaveats(conditions, jti) {
  log.debug("Entering readCaveats(). count=" + conditions.length);
  const authority = {};
  const lists = { audience: [], access: [], exps: [], nbfs: [] };
  let boundary = -1;
  for (let i = 0; i < conditions.length; i++) {
    const text = conditions[i];
    const parsed = text === null ? null : parseCaveat(text);
    if (!parsed) {
      log.debug("Leaving readCaveats(). Caveat " + i + " outside the grammar.");
      return refusal('STS-GNAP-0315', 'macaroon caveat ' + i + ' is not in this service\'s ' +
                     'caveat grammar, and an unknown caveat is never skipped.');
    }
    const inAuthority = boundary < 0;
    if (!inAuthority && ATTENUATING.indexOf(parsed.kind) < 0) {
      log.debug("Leaving readCaveats(). Singular caveat in attenuation section.");
      return refusal('STS-GNAP-0316', 'macaroon caveat ' + i + ' (gnap:' + parsed.kind + ') ' +
                     'follows the authority section, where only exp, nbf, aud and access may ' +
                     'be added.');
    }
    if (inAuthority) {
      const kind = parsed.kind === 'bearer' ? 'cnf' : parsed.kind;
      if (authority[kind] !== undefined) {
        log.debug("Leaving readCaveats(). Repeated authority caveat.");
        return refusal('STS-GNAP-0316', 'the macaroon\'s authority section repeats gnap:' + kind + '.');
      }
      authority[kind] = parsed.kind === 'bearer' ? null : parsed.value;
      if (parsed.kind === 'access') {
        boundary = i;
      }
    }
    if (parsed.kind === 'aud') {
      lists.audience.push(parsed.value);
    } else if (parsed.kind === 'access') {
      lists.access.push(parsed.value);
    } else if (parsed.kind === 'exp') {
      lists.exps.push(parsed.value);
    } else if (parsed.kind === 'nbf') {
      lists.nbfs.push(parsed.value);
    }
  }
  const missing = REQUIRED_ONCE.concat(['cnf', 'access']).filter(function (k) {
    return authority[k] === undefined;
  });
  if (missing.length) {
    log.debug("Leaving readCaveats(). Missing " + missing.join(','));
    return refusal('STS-GNAP-0316', 'the macaroon\'s authority section lacks gnap:' +
                   missing.join(', gnap:') + '.');
  }
  const model = {
    jti: jti,
    iss: authority.iss,
    sub: authority.sub === undefined ? null : authority.sub,
    aud: authority.aud === undefined ? [] : authority.aud,
    instanceId: authority.client,
    access: authority.access,
    flags: authority.flags === undefined ? [] : authority.flags,
    cnf: authority.cnf,
    iat: authority.iat,
    nbf: authority.nbf === undefined ? null : authority.nbf,
    exp: authority.exp,
    label: authority.label === undefined ? null : authority.label
  };
  const valid = access.validateModel(model);
  if (!valid.ok) {
    log.debug("Leaving readCaveats(). Authority section is not a valid model.");
    return refusal('STS-GNAP-0316', 'the macaroon\'s authority section is not a valid token ' +
                   'model: ' + valid.why);
  }
  log.debug("Leaving readCaveats(). Model read.");
  return {
    ok: true,
    model: valid.model,
    audience: lists.audience,
    access: lists.access,
    exp: Math.min.apply(null, lists.exps),
    nbf: lists.nbfs.length ? Math.max.apply(null, lists.nbfs) : null,
    attenuated: boundary < conditions.length - 1
  };
}

// ---------------------------------------------------------------------------
// verify(value, keys, context) -> { ok:true, model, attenuated } | refusal.
// keys = { rootKey }. OPTIONAL_ONCE is enforced by readCaveats()'s repeat
// check, which covers every authority kind.
// ---------------------------------------------------------------------------
async function verify(value, keys, context) {
  log.debug("Entering verify().");
  const rootKey = rootKeyOf(keys);
  if (!rootKey) {
    log.debug("Leaving verify(). Root key unusable.");
    return refusal('STS-GNAP-0310', 'a macaroon root key must be at least ' + MIN_ROOT_KEY_BYTES +
                   ' bytes.');
  }
  const imported = importValue(value);
  if (!imported.ok) {
    log.debug("Leaving verify(). Import refused.");
    return imported;
  }
  const mac = imported.mac;
  const identifier = decodeUtf8(mac.identifier);
  if (identifier === null || identifier.indexOf(IDENTIFIER_PREFIX) !== 0 ||
      identifier.length === IDENTIFIER_PREFIX.length) {
    log.debug("Leaving verify(). Identifier is not gnap:v1.");
    return refusal('STS-GNAP-0312', 'the macaroon identifier is not "' + IDENTIFIER_PREFIX +
                   '<jti>", so this is not a GNAP macaroon this service minted.');
  }
  try {
    // Accept every caveat while the chain is walked: the grammar runs after
    // the signature is known to be good (see the header).
    mac.verify(rootKey, function () { return null; }, []);
  } catch (e) {
    log.debug("Leaving verify(). HMAC chain failed: " + e.message);
    return refusal('STS-GNAP-0314', 'the macaroon\'s HMAC chain does not verify under this ' +
                   'authorization server\'s root key — it was altered, a caveat was removed, ' +
                   'or another key minted it.');
  }
  const conditions = mac.caveats.map(function (c) { return decodeUtf8(c.identifier); });
  const read = readCaveats(conditions, identifier.slice(IDENTIFIER_PREFIX.length));
  if (!read.ok) {
    log.debug("Leaving verify(). Caveats refused.");
    return read;
  }
  const failed = access.checkPresentation(read.model, context, {
    exp: read.exp, nbf: read.nbf, audience: read.audience, access: read.access
  });
  if (failed) {
    log.debug("Leaving verify(). Presentation refused.");
    return failed;
  }
  log.debug("Leaving verify(). Verified jti=" + read.model.jti);
  return { ok: true, model: read.model, attenuated: read.attenuated };
}

// ---------------------------------------------------------------------------
// attenuate(value, caveats): what a resource server does to derive a narrower
// token without calling the AS (RFC 9767 section 2.2). Each entry is
// `{ exp }`, `{ nbf }`, `{ aud: [ids] }`, `{ access: [rights] }`, or a caveat
// string in the grammar of one of those four. Needs no key — that is the point
// of the format. Returns `{ ok:true, value, format }` or a refusal.
// ---------------------------------------------------------------------------
async function attenuate(value, caveats) {
  log.debug("Entering attenuate().");
  if (!Array.isArray(caveats) || caveats.length === 0) {
    log.debug("Leaving attenuate(). No caveats.");
    return refusal('STS-GNAP-0317', 'an attenuation is a non-empty array of caveats.');
  }
  const texts = [];
  for (let i = 0; i < caveats.length; i++) {
    const c = caveats[i];
    let text = null;
    if (typeof c === 'string') {
      text = c;
    } else if (c && typeof c === 'object' && Object.keys(c).length === 1) {
      if (c.exp !== undefined) {
        text = 'gnap:exp<' + c.exp;
      } else if (c.nbf !== undefined) {
        text = 'gnap:nbf>=' + c.nbf;
      } else if (Array.isArray(c.aud)) {
        text = 'gnap:aud=' + c.aud.join(' ');
      } else if (c.access !== undefined) {
        text = 'gnap:access=' + b64uJson(c.access);
      }
    }
    const parsed = text === null ? null : parseCaveat(text);
    if (!parsed || ATTENUATING.indexOf(parsed.kind) < 0) {
      log.debug("Leaving attenuate(). Caveat " + i + " is not an attenuation.");
      return refusal('STS-GNAP-0317', 'attenuation ' + i + ' is not an exp, nbf, aud or access ' +
                     'caveat in this service\'s grammar.');
    }
    texts.push(text);
  }
  const imported = importValue(value);
  if (!imported.ok) {
    log.debug("Leaving attenuate(). Import refused.");
    return imported;
  }
  let out;
  try {
    const mac = imported.mac.clone();
    texts.forEach(function (t) { mac.addFirstPartyCaveat(t); });
    out = encodeBinaryV2(mac).toString('base64url');
  } catch (e) {
    log.warn(errorCodes.tag('STS-GNAP-0317') + 'macaroon attenuation failed in the library: ' +
             e.message);
    log.debug("Leaving attenuate(). Library failure.");
    return refusal('STS-GNAP-0317', 'the macaroon library refused the attenuation: ' + e.message);
  }
  log.debug("Leaving attenuate(). Added " + texts.length + " caveat(s).");
  return { ok: true, value: out, format: FORMAT };
}

function describe() {
  log.debug("Entering describe().");
  const out = {
    name: FORMAT,
    libraries: [access.libraryInfo('macaroon')],
    algorithms: [
      ['Caveat chain MAC', ['HMAC-SHA256']],
      ['Root key derivation', ['HMAC-SHA256 keyed with "macaroons-key-generator"']],
      ['Root key', ['symmetric, ' + MIN_ROOT_KEY_BYTES + '+ bytes, held by the AS']],
      ['Serialisation', ['libmacaroons v2 binary, unpadded base64url']],
      ['Third-party caveats', ['refused']]
    ],
    carries: ['jti', 'iss', 'sub', 'aud', 'instanceId', 'access', 'flags', 'cnf',
              'iat', 'nbf', 'exp', 'label'],
    cannot: []
  };
  log.debug("Leaving describe().");
  return out;
}

module.exports = {
  FORMAT: FORMAT,
  IDENTIFIER_PREFIX: IDENTIFIER_PREFIX,
  mint: mint,
  verify: verify,
  attenuate: attenuate,
  describe: describe,
  parseCaveat: parseCaveat,
  caveatsFor: caveatsFor,
  encodeBinaryV2: encodeBinaryV2,
  OPTIONAL_ONCE: OPTIONAL_ONCE
};
