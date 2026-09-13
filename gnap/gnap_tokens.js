'use strict';
//
// File: gnap_tokens.js
//
// ---------------------------------------------------------------------------
// THE FIVE ACCESS TOKEN FORMATS OF RFC 9767 SECTION 5.3, BEHIND ONE MINT AND
// ONE VERIFY.
//
// GNAP core leaves the access token opaque to the client (RFC 9635 section
// 3.2.1) and RFC 9767 registers five formats an AS and RS may agree on:
// `jwt-signed`, `jwt-encrypted`, `macaroon`, `biscuit` and `zcap`. Every one of
// them carries the same TOKEN MODEL (RFC 9767 section 2.1 — issuer, audience,
// key binding, flags, access rights, time window, identifier, resource owner,
// client instance, label), so every one of them is minted from the same object
// and verified back into it. That is the contract `GNAP_DESIGN.md` states and
// the format modules keep; this file is the dispatcher and the home of the two
// JWT formats, which REUSE the service's JOSE module rather than a second one:
//
//   * `jwt-signed` is signed through `helpers.signJwt()` — the one signer that
//     records every token in `admin_stats.js`'s registry — so a GNAP JWT shows
//     on /admin/tokens beside every other token this realm issued and a revoke
//     there is seen by `stats.isRevoked()`.
//   * `jwt-encrypted` is that same signed JWT, NESTED (RFC 7519 section 11.2)
//     inside a JWE from `common/crypto.js`'s `encryptJweCompact()`. To WHOM it
//     is encrypted is the one decision here: to the resource server's own
//     registered public key (`gnapJweKey` on its application entry) when the
//     token is for exactly one RS that has one — which is what makes the format
//     worth having, since then only that RS can read it — and otherwise to a
//     key derived from THIS realm's own secret, which means only this AS can
//     open it and an RS reads it through introspection (RFC 9767 section 3.3).
//
// ---------------------------------------------------------------------------
// WHERE EACH FORMAT'S KEY COMES FROM — AND WHY NONE OF THEM IS A NEW KEY STORE.
//
// A signing key nobody vouched for is a key somebody has to rotate by hand, and
// a second place this service keeps private keys is a second answer to "where
// are the keys" (common/CLAUDE.md, rule 3w). So every format uses material the
// realm's key set ALREADY holds, sealed and persisted by `keystore.js`:
//
//   jwt-signed     the realm's RS256 signing key (`STS`), published at /oauth2/jwks.
//   jwt-encrypted  the realm's 64-byte refresh-token secret, through HKDF with a
//                  GNAP-only info string — domain separation, so a GNAP JWE key
//                  and a refresh-token key are never the same bytes.
//   macaroon       the same secret, HKDF'd per RESOURCE SERVER, because a macaroon
//                  is verified with its ROOT KEY and handing every RS one key would
//                  let any of them mint for all of them. The per-RS key is what the
//                  RS's application entry carries (sealed) as `gnapMacaroonKey`.
//   biscuit, zcap  the realm's Ed25519 key from `allSigningKeys()` — selected by
//                  CURVE, because a realm holds an Ed448 EdDSA key beside it and
//                  both formats are Ed25519-only.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const helpers = require('../common/helpers');
const { log, STS, nowSec } = helpers;
const stsCrypto = require('../common/crypto');
const errorCodes = require('../common/error_codes');
const config = require('../common/config');
const stats = require('../common/admin_stats');
const macaroon = require('./token_macaroon');
const biscuit = require('./token_biscuit');
const zcap = require('./token_zcap');
const access = require('./gnap_access');

const FORMATS = ['jwt-signed', 'jwt-encrypted', 'macaroon', 'biscuit', 'zcap'];

const JWT_TYP = 'GNAP';

function refusal(code, why) {
  log.debug("Entering refusal().");
  const out = { ok: false, errorCode: code, why: why };
  log.debug("Leaving refusal().");
  return errorCodes.mark(out, code);
}

// HKDF over the realm secret. `info` is the domain separator and is never
// shared with another feature.
function realmDerived(info, length) {
  log.debug("Entering realmDerived().");
  const secret = helpers.refreshTokenKeysFor().secret;
  log.debug("Leaving realmDerived().");
  return Buffer.from(nodeCrypto.hkdfSync('sha256', secret, Buffer.alloc(0),
                                         Buffer.from(info, 'utf8'),
                                         length || 32));
}

function jweSecret() {
  log.debug("Entering jweSecret().");
  log.debug("Leaving jweSecret().");
  return realmDerived('mock-sts gnap jwt-encrypted A256GCM v1', 32);
}

// The macaroon root key a resource server verifies with. `rsIdentity` is the
// RS application's identifier; '' is the key for tokens with no RS audience,
// which only this AS (introspection, the demonstration RS) can verify.
function macaroonKeyFor(rsIdentity) {
  log.debug("Entering macaroonKeyFor().");
  log.debug("Leaving macaroonKeyFor().");
  return realmDerived('mock-sts gnap macaroon root v1|' +
                      String(rsIdentity || ''), 32);
}

function ed25519Keys() {
  log.debug("Entering ed25519Keys().");
  const found = helpers.allSigningKeys().filter(function (one) {
    return one.alg === 'EdDSA' &&
           (one.publicJwk.crv || 'Ed25519') === 'Ed25519';
  })[0];
  if (!found) {
    log.debug("Leaving ed25519Keys(). None.");
    throw new Error('this realm holds no Ed25519 signing key, which biscuit ' +
                    'and zcap tokens are signed with. That is a defect in ' +
                    'the realm key set.');
  }
  log.debug("Leaving ed25519Keys().");
  return { privateKey: found.privateKey,
           publicKey: nodeCrypto.createPublicKey(found.privateKey),
           publicJwk: found.publicJwk };
}

// The ZCAP controller document lives at the realm's own URL, so the controller
// is built from the base the caller hands in.
function zcapKeys(base) {
  log.debug("Entering zcapKeys().");
  const keys = ed25519Keys();
  const controller = String(base || '') + '/gnap/zcap/controller';
  log.debug("Leaving zcapKeys().");
  return { privateKey: keys.privateKey, publicKey: keys.publicKey,
           controller: controller,
           keyId: controller + '#' + keys.publicJwk.kid };
}

// ---------------------------------------------------------------------------
// THE JWT CLAIMS FOR THE MODEL (RFC 9767 section 2.1's JWT mappings).
// ---------------------------------------------------------------------------
function claimsOf(model) {
  log.debug("Entering claimsOf().");
  const claims = {
    typ: JWT_TYP,
    iss: model.iss,
    jti: model.jti,
    // A time the model does not carry is OMITTED rather than written as null:
    // jsonwebtoken refuses a non-numeric nbf, and a minimal bearer model has
    // none.
    iat: model.iat === null ? undefined : model.iat,
    nbf: model.nbf === null ? undefined : model.nbf,
    exp: model.exp === null ? undefined : model.exp,
    client_id: model.instanceId,
    access: model.access,
    flags: model.flags && model.flags.length ? model.flags : undefined,
    label: model.label || undefined
  };
  if (model.sub) {
    claims.sub = model.sub;
  }
  if (model.aud && model.aud.length) {
    claims.aud = model.aud.length === 1 ? model.aud[0] : model.aud;
  }
  if (model.cnf) {
    claims.cnf = model.cnf;
  }
  Object.keys(claims).forEach(function (name) {
    if (claims[name] === undefined) {
      delete claims[name];
    }
  });
  log.debug("Leaving claimsOf().");
  return claims;
}

function modelOfClaims(claims) {
  log.debug("Entering modelOfClaims().");
  log.debug("Leaving modelOfClaims().");
  return {
    jti: claims.jti || null,
    iss: claims.iss || null,
    sub: claims.sub || null,
    aud: claims.aud === undefined ? [] :
         (Array.isArray(claims.aud) ? claims.aud : [claims.aud]),
    instanceId: claims.client_id || null,
    access: Array.isArray(claims.access) ? claims.access : [],
    flags: Array.isArray(claims.flags) ? claims.flags : [],
    cnf: claims.cnf || null,
    iat: claims.iat || null,
    nbf: claims.nbf || null,
    exp: claims.exp || null,
    label: claims.label || null
  };
}

// The checks every format's verify() makes, applied to a JWT model — through
// `gnap_access.checkPresentation()`, the SAME function the three capability
// formats call, so a jwt-signed token and a biscuit are refused for the same
// reasons under the same codes rather than by two implementations that agree
// until one of them changes.
function checkModel(model, context) {
  log.debug("Entering checkModel().");
  const failed = access.checkPresentation(model, context || {});
  if (failed && failed.ok === false) {
    log.debug("Leaving checkModel(). Refused " + failed.errorCode + ".");
    return failed;
  }
  log.debug("Leaving checkModel().");
  return { ok: true, model: model };
}

// ---------------------------------------------------------------------------
// MINT. `ctx.base` is the realm base URL (the ZCAP controller), `ctx.rs` the
// single resource server the token is for, if exactly one: `{ identity,
// jweKey }`.
// ---------------------------------------------------------------------------
// The three library formats REFUSE by returning `{ ok: false }` where the JWT
// formats throw. Both callers (issuance and rotation) catch a throw, log it
// under their own code and carry on, so a returned refusal is turned into one
// here — otherwise a refused mint reached `store.putToken()` with an undefined
// value and the client was handed a token object with no value in it.
function mintedOrThrow(format, minted) {
  log.debug("Entering mintedOrThrow().");
  if (!minted || minted.ok === false || typeof minted.value !== 'string' ||
      !minted.value) {
    throw new Error('the ' + format + ' library refused to mint: ' +
                    String((minted && minted.why) || 'no value was produced'));
  }
  log.debug("Leaving mintedOrThrow().");
  return minted;
}

async function mint(format, model, ctx) {
  log.debug("Entering mint(). format=" + format);
  const context = ctx || {};
  if (format === 'jwt-signed' || format === 'jwt-encrypted') {
    // THE MODEL IS VALIDATED HERE FOR THE JWT FORMATS, as each library format
    // validates it in its own mint(). Until 2026-09-12 a JWT was signed from
    // whatever it was handed — a model whose exp preceded its iat included.
    const valid = access.validateModel(model);
    if (!valid.ok) {
      log.debug("Leaving mint(). Model invalid.");
      const refused = new Error('the token model is not valid: ' + valid.why);
      refused.errorCode = valid.errorCode;
      throw errorCodes.mark(refused, valid.errorCode);
    }
    const signed = helpers.signJwt(claimsOf(valid.model),
                                   { grant: 'gnap', setId: context.setId ||
                                       null,
                                                           sessionId: context.sessionId || null });
    if (typeof signed !== 'string' || signed.split('.').length !== 3) {
      log.debug("Leaving mint(). The signer produced no JWS.");
      throw new Error('the ' + format + ' access token could not be signed.');
    }
    if (format === 'jwt-signed') {
      log.debug("Leaving mint(). jwt-signed.");
      return { value: signed, format: format, jti: model.jti };
    }
    const rsKey = context.rs && context.rs.jweKey ? context.rs.jweKey : null;
    let options;
    if (rsKey) {
      const alg = rsKey.alg ||
                  (rsKey.kty === 'EC' ? 'ECDH-ES+A256KW' : 'RSA-OAEP-256');
      options = { alg: alg,
                  enc: String(config.value('gnap.jweEnc') || 'A256GCM'),
                  jwk: rsKey,
                  cty: 'JWT', typ: 'JWT' };
    } else {
      options = { alg: 'dir', enc: 'A256GCM', secret: jweSecret(), cty: 'JWT',
                  typ: 'JWT' };
    }
    const value = stsCrypto.encryptJweCompact(signed, options);
    log.debug("Leaving mint(). jwt-encrypted to " + (rsKey ? 'the resource ' +
        'server' : 'this ' +
        'AS') + ".");
    return { value: value, format: format, jti: model.jti,
             encryptedTo: rsKey ? 'resource-server' : 'authorization-server' };
  }
  if (format === 'macaroon') {
    const minted = await macaroon.mint(model, {
      rootKey: macaroonKeyFor(context.rs ? context.rs.identity : ''),
      location: model.iss });
    log.debug("Leaving mint(). macaroon.");
    return mintedOrThrow(format, minted);
  }
  if (format === 'biscuit') {
    const keys = ed25519Keys();
    const minted = await biscuit.mint(model,
                                      { privateKey: keys.privateKey,
                                        publicKey: keys.publicKey });
    log.debug("Leaving mint(). biscuit.");
    return mintedOrThrow(format, minted);
  }
  if (format === 'zcap') {
    const minted = await zcap.mint(model, zcapKeys(context.base));
    log.debug("Leaving mint(). zcap.");
    return mintedOrThrow(format, minted);
  }
  log.debug("Leaving mint(). Unknown format.");
  throw new Error('there is no access token format called "' + format + '".');
}

// Which format a presented value is, read off its shape. Used by the
// demonstration RS, which is handed a value and no format — as a real RS that
// accepts several formats is.
function formatOf(value) {
  log.debug("Entering formatOf().");
  const text = String(value || '');
  const dots = text.split('.').length - 1;
  if (dots === 2) {
    log.debug("Leaving formatOf().");
    return 'jwt-signed';
  }
  if (dots === 4) {
    log.debug("Leaving formatOf().");
    return 'jwt-encrypted';
  }
  if (/^eyJAY29udGV4d|^eyJpZCI6|^eyJ/.test(text)) {
    try {
      const json = JSON.parse(Buffer.from(text, 'base64url').toString('utf8'));
      if (json && json.parentCapability) {
        log.debug("Leaving formatOf().");
        return 'zcap';
      }
    } catch (e) {
      // Not base64url JSON; fall through to the binary formats.
      log.debug("formatOf(): not a ZCAP: " + e.message);
    }
  }
  const bytes = Buffer.from(text, 'base64url');
  if (bytes.length && bytes[0] === 0x02) {
    log.debug("Leaving formatOf().");
    // libmacaroons v2 binary starts with the version byte 2.
    return 'macaroon';
  }
  log.debug("Leaving formatOf().");
  return 'biscuit';
}

// ---------------------------------------------------------------------------
// VERIFY a value as a self-contained token. `ctx` is the format modules'
// context (`now`, `audience`, `presentedKey`, `requiredAccess`) plus `base`,
// `rsIdentity`, and `rsPrivateJwk` for a jwt-encrypted token to an RS key.
// ---------------------------------------------------------------------------
async function verify(format, value, ctx) {
  log.debug("Entering verify(). format=" + format);
  const context = ctx || {};
  if (format === 'jwt-signed' || format === 'jwt-encrypted') {
    let jws = value;
    if (format === 'jwt-encrypted') {
      try {
        const header = JSON.parse(Buffer.from(String(value).split('.')[0],
                                              'base64url').toString('utf8'));
        const opened = header.alg === 'dir'
          ? stsCrypto.decryptJweCompact(value,
                                        { secret: jweSecret(),
                                                 allowedAlg: ['dir'],
                                                 allowedEnc: ['A256GCM'] })
          : (context.rsPrivateKey
            ? stsCrypto.decryptJweCompact(value,
                                          { privateKey: context.rsPrivateKey })
            : null);
        if (!opened) {
          log.debug("Leaving verify(). Encrypted to a resource server key " +
                    "this AS does not hold.");
          return refusal('STS-GNAP-0340', 'the access token is encrypted to ' +
                         'a resource server\'s key; only that resource ' +
                         'server can read it.');
        }
        jws = opened.plaintext.toString('utf8');
      } catch (e) {
        log.debug("Leaving verify(). JWE does not open: " + e.message);
        return refusal('STS-GNAP-0341', 'the encrypted access token does not ' +
                                        'decrypt: ' + e.message);
      }
    }
    let claims;
    try {
      claims = stsCrypto.verifyJws(jws, STS.certPem,
                                   { algorithms: ['RS256'],
                                     clockTolerance: 0 });
    } catch (e) {
      // Expiry is refused below with the model's own sentence, so an expired
      // signature error is re-read without the time check.
      if (e && e.name === 'TokenExpiredError') {
        try {
          claims = stsCrypto.verifyCompactJws(jws, STS.certPem,
                                              { algorithms: ['RS256'] }).claims;
        } catch (e2) {
          log.debug("Leaving verify(). Signature refused: " + e2.message);
          return refusal('STS-GNAP-0342', 'the access token signature does ' +
                                          'not verify: ' + e2.message);
        }
      } else if (e && e.name === 'NotBeforeError') {
        claims = stsCrypto.verifyCompactJws(jws, STS.certPem,
                                            { algorithms: ['RS256'] }).claims;
      } else {
        log.debug("Leaving verify(). Signature refused: " + (e && e.message));
        return refusal('STS-GNAP-0342', 'the access token signature does not ' +
                                        'verify: ' +
                       (e && e.message));
      }
    }
    if (claims.typ !== JWT_TYP) {
      log.debug("Leaving verify(). Not a GNAP JWT.");
      return refusal('STS-GNAP-0343',
                     'the JWT is not a GNAP access token (typ ' + claims.typ +
                     ').');
    }
    const checked = checkModel(modelOfClaims(claims), context);
    log.debug("Leaving verify(). jwt ok=" + checked.ok);
    return checked;
  }
  if (format === 'macaroon') {
    const out = await macaroon.verify(value,
                                      { rootKey: macaroonKeyFor(
                                          context.rsIdentity || ''),
                                               location: null }, context);
    log.debug("Leaving verify(). macaroon ok=" + out.ok);
    return out;
  }
  if (format === 'biscuit') {
    const keys = ed25519Keys();
    const out = await biscuit.verify(value, { publicKey: keys.publicKey },
                                     context);
    log.debug("Leaving verify(). biscuit ok=" + out.ok);
    return out;
  }
  if (format === 'zcap') {
    const out = await zcap.verify(value, zcapKeys(context.base), context);
    log.debug("Leaving verify(). zcap ok=" + out.ok);
    return out;
  }
  log.debug("Leaving verify(). Unknown format.");
  return refusal('STS-GNAP-0344',
                 'there is no access token format called "' + format + '".');
}

// What `GET /gnap/keys` publishes: the material an RS needs to verify the
// self-contained formats without calling this AS. The macaroon root key is NOT
// here — it is a secret, and per resource server.
function publicMaterial(base) {
  log.debug("Entering publicMaterial().");
  const keys = ed25519Keys();
  const raw = Buffer.from(keys.publicJwk.x, 'base64url');
  log.debug("Leaving publicMaterial().");
  return {
    jwt: { jwks_uri: base + '/oauth2/jwks', alg: 'RS256', kid: STS.kid,
           typ: JWT_TYP },
    biscuit: { algorithm: 'ed25519',
               root_public_key: 'ed25519/' + raw.toString('hex'),
               jwk: keys.publicJwk },
    zcap: { controller: base + '/gnap/zcap/controller' },
    macaroon: { root_key: 'per resource server; carried (sealed) on the ' +
                'resource server\'s application entry as gnapMacaroonKey' },
    'jwt-encrypted': { authorization_server: 'dir/A256GCM under a ' +
                                             'realm-derived key (introspect)',
                       resource_server: 'the resource server\'s registered ' +
                                        'gnapJweKey' }
  };
}

function describe() {
  log.debug("Entering describe().");
  log.debug("Leaving describe().");
  return {
    jwt: { signs: 'RS256 with the realm signing key', encrypts: 'dir+A256GCM ' +
           '(realm-derived) or RSA-OAEP-256 / ECDH-ES+A256KW to the resource ' +
           'server\'s gnapJweKey' },
    macaroon: macaroon.describe(),
    biscuit: biscuit.describe(),
    zcap: zcap.describe()
  };
}

module.exports = {
  FORMATS: FORMATS,
  JWT_TYP: JWT_TYP,
  mint: mint,
  verify: verify,
  formatOf: formatOf,
  checkModel: checkModel,
  macaroonKeyFor: macaroonKeyFor,
  zcapKeys: zcapKeys,
  ed25519Keys: ed25519Keys,
  publicMaterial: publicMaterial,
  describe: describe,
  isRevokedJti: function (jti) {
    log.debug("Entering isRevokedJti().");
    log.debug("Leaving isRevokedJti().");
    return stats.isRevoked(jti);
  }
};
