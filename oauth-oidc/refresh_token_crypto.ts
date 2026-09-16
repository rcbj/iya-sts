'use strict';
//
// File: refresh_token_crypto.ts
//
// ===========================================================================
// EVERY REFRESH TOKEN IS A SIGNED JWT ENCRYPTED TO ITS OWN REALM (2026-09-12).
//
// A refresh token is the long-lived half of a grant. It was a signed JWT, and
// a signed JWT is READABLE: anybody who got hold of one — a proxy log, a
// browser's storage, a crash report — could read who it was for, which client
// holds it, the scopes, the resources, the RFC 9449 key binding and the claims
// request. None of that is the client's business either: RFC 6749 section 1.5
// makes a refresh token opaque to the client, so encrypting it takes nothing
// away from any client that follows the specification.
//
// **IT IS A NESTED JWT, RFC 7519 SECTION 11.2 — SIGNED, THEN ENCRYPTED.** The
// JWS `oauth2.ts`'s refreshToken() always made is the JWE's plaintext, and the
// JWE carries `cty: "JWT"` to say so. That order is the whole design rather
// than a detail:
//
//   * **every check the refresh grant makes is unchanged.** `open()` hands back
//     the same JWS the grant always verified, so the signature, `exp`, the
//     revocation set, RFC 9700's rotation and family bookkeeping, the DPoP and
//     certificate bindings and the client check all run on exactly what they
//     ran on before, and none of them was edited;
//   * **the token registry is unchanged** — `signJwt()` records the claims when
//     the JWS is made, before it is sealed, so /admin/tokens, the audit log and
//     a global sign-out see the same jti they always did;
//   * **and a JWE's authentication tag is not the only integrity check.** A key
//     compromise of the ENCRYPTION key alone does not let anybody mint a token,
//     because what comes out still has to verify against the signing key.
//
// **AN UNENCRYPTED REFRESH TOKEN IS REFUSED**, by decision: a plain signed JWT
// carrying `typ: "Refresh"` is one this service no longer issues, so the grant
// answers invalid_grant and introspection answers `active: false`. A client
// holding one from before the change signs in again.
//
// **EVERY ALGORITHM `common/crypto.js` IMPLEMENTS, CHOSEN BY A SETTING.**
// `oauth2.refreshTokenEncryptionAlg` and `…Enc` pick what a NEW token is sealed
// under. The realm holds a key of every kind (`helpers.js`'s
// makeRefreshTokenEncryptionKeys()), and `open()` reads which one to use off
// the token's own header — so changing the setting never strands a token
// already in a client's hands. The one algorithm refused on the way in is
// RSA1_5, which `crypto.js` does not implement at all and argues why.
//
// **THE SYMMETRIC KEY IS DERIVED, NOT STORED PER ALGORITHM.** A128KW needs
// exactly 128 bits, A256KW exactly 256, `dir` exactly the content key's size
// for its `enc`, and none of them has a key derivation of its own (RFC 7518
// section 4.4). So the realm holds one 64-byte secret and each (alg, enc) gets
// an HKDF-SHA256 key of the size it needs, with the pair in the `info` — one
// secret to generate, seal, persist and rotate, and no two algorithms sharing
// key bytes.
//
// **IT IS A LIBRARY (rule 3).** It registers no route and requires `helpers`,
// `config`, `crypto` and `error_codes`, none of which requires it back, so
// `oauth2.ts` and `admin-core/admin_actions.ts` may both require it.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape. `RefreshTokenCrypto` takes the logger, the realm key reader,
// `config`, `crypto` and `error_codes` through its constructor. The module
// still exports `kindOf`, `symmetricBytes`, `symmetricKeyFor`, `configured`,
// `isEncrypted`, `seal`, `open`, `claimsOfIssued` and `describe`, bound to a
// TRANSITIONAL instance built from the real modules at the bottom, which goes
// when the composition root exists. The HKDF `info` label is unchanged byte
// for byte: changing it would strand every refresh token already issued.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');

// A JSON-shaped value: a key set, a JWE header, an options object.
type Json = any;

// The configured (alg, enc) pair.
interface Choice {
  alg: string;
  enc: string;
}

interface RefreshTokenCryptoDeps {
  log: typeof helpers.log;
  refreshTokenKeysFor: typeof helpers.refreshTokenKeysFor;
  config: typeof config;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
}

const DEFAULT_ALG = 'RSA-OAEP-256';
const DEFAULT_ENC = 'A256GCM';

// A PBES2 "password" has no required size; this is what the secret is
// stretched to before PBKDF2 stretches it again.
const PBES2_PASSWORD_BYTES = 32;

class RefreshTokenCrypto {
  static readonly DEFAULT_ALG = DEFAULT_ALG;
  static readonly DEFAULT_ENC = DEFAULT_ENC;

  constructor(private readonly deps: RefreshTokenCryptoDeps) {
    deps.log.debug("Entering RefreshTokenCrypto.constructor().");
    deps.log.debug("Leaving RefreshTokenCrypto.constructor().");
  }

  // A thrown refusal carrying its error code under the Symbol `mark()` uses,
  // so a caller can mark the response with it and nothing that serialises the
  // error sees the code.
  private refusal(code: string, message: string): Error {
    const { log, errorCodes } = this.deps;
    log.debug("Entering RefreshTokenCrypto.refusal().");
    const err = new Error(message);
    err.name = 'RefreshTokenEncryptionError';
    errorCodes.mark(err, code);
    log.debug("Leaving RefreshTokenCrypto.refusal().");
    return err;
  }

  // Which of the realm's three keys an algorithm uses.
  kindOf(alg: string): string {
    const { log } = this.deps;
    log.debug("Entering RefreshTokenCrypto.kindOf().");
    if (/^RSA-OAEP/.test(alg)) {
      log.debug("Leaving RefreshTokenCrypto.kindOf().");
      return 'rsa';
    }
    if (/^ECDH-ES/.test(alg)) {
      log.debug("Leaving RefreshTokenCrypto.kindOf().");
      return 'ec';
    }
    log.debug("Leaving RefreshTokenCrypto.kindOf().");
    return 'secret';
  }

  // The key size a symmetric (alg, enc) pair needs, in bytes.
  symmetricBytes(alg: string, enc: string): number {
    const { log, stsCrypto } = this.deps;
    log.debug('Entering RefreshTokenCrypto.symmetricBytes(). alg=' + alg +
              ', enc=' + enc);
    if (alg === 'dir') {
      const spec = stsCrypto.JWE_ENCS[enc];
      if (!spec) {
        log.debug('Leaving RefreshTokenCrypto.symmetricBytes(). Unknown enc.');
        throw this.refusal('STS-OAUTH-0238',
                           'the content encryption algorithm "' + enc +
          '" is not one this service implements.');
      }
      log.debug('Leaving RefreshTokenCrypto.symmetricBytes(). The content ' +
                'key.');
      return spec.cekBytes;
    }
    if (/^PBES2-/.test(alg)) {
      log.debug('Leaving RefreshTokenCrypto.symmetricBytes(). A password.');
      return PBES2_PASSWORD_BYTES;
    }
    const bits = /^A(128|192|256)(?:GCM)?KW$/.exec(alg);
    if (!bits) {
      log.debug('Leaving RefreshTokenCrypto.symmetricBytes(). Unknown alg.');
      throw this.refusal('STS-OAUTH-0238', 'the key management algorithm "' +
        alg + '" is not one this service implements.');
    }
    log.debug('Leaving RefreshTokenCrypto.symmetricBytes(). ' + bits[1] +
              ' bits.');
    return Number(bits[1]) / 8;
  }

  // The realm secret narrowed to one (alg, enc) pair. HKDF rather than a
  // slice, so two algorithms never share key bytes and the derivation is
  // one-way.
  symmetricKeyFor(secret: Json, alg: string, enc: string): Buffer {
    const { log } = this.deps;
    log.debug("Entering RefreshTokenCrypto.symmetricKeyFor().");
    const length = this.symmetricBytes(alg, enc);
    log.debug("Leaving RefreshTokenCrypto.symmetricKeyFor().");
    return Buffer.from(nodeCrypto.hkdfSync('sha256', Buffer.from(secret),
      Buffer.alloc(0),
      Buffer.from('mock-sts refresh token v1|' + alg + '|' + enc,
                  'utf8'), length));
  }

  // The configured algorithm pair, each checked against the table that
  // performs it. A value the table does not hold falls back to the default
  // with a line naming it, rather than failing every issuance: the settings
  // table's own enum already refuses one at every door, so this is reached
  // only by a hand-edited store, and a service that stopped issuing refresh
  // tokens over it would be the tail wagging the dog.
  configured(): Choice {
    const { log, config, stsCrypto, errorCodes } = this.deps;
    log.debug('Entering RefreshTokenCrypto.configured().');
    let alg = String(config.value('oauth2.refreshTokenEncryptionAlg') ||
                     DEFAULT_ALG);
    let enc = String(config.value('oauth2.refreshTokenEncryptionEnc') ||
                     DEFAULT_ENC);
    if (stsCrypto.JWE_ALGS.indexOf(alg) === -1) {
      log.warn(errorCodes.tag('STS-OAUTH-0241') +
               'oauth2.refreshTokenEncryptionAlg is "' +
               alg + '", which common/crypto.js does not implement; refresh ' +
               'tokens are being encrypted with ' + DEFAULT_ALG +
               ' instead.');
      alg = DEFAULT_ALG;
    }
    if (!stsCrypto.JWE_ENCS[enc]) {
      log.warn(errorCodes.tag('STS-OAUTH-0241') +
               'oauth2.refreshTokenEncryptionEnc is "' +
               enc + '", which common/crypto.js does not implement; refresh ' +
               'tokens are being encrypted with ' + DEFAULT_ENC +
               ' instead.');
      enc = DEFAULT_ENC;
    }
    log.debug('Leaving RefreshTokenCrypto.configured(). ' + alg + ' / ' +
              enc);
    return { alg: alg, enc: enc };
  }

  // Compact JWE: five dot-separated parts. A compact JWS has three.
  isEncrypted(token: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering RefreshTokenCrypto.isEncrypted().");
    log.debug("Leaving RefreshTokenCrypto.isEncrypted().");
    return String(token || '').trim().split('.').length === 5;
  }

  // -------------------------------------------------------------------------
  // seal(jws) — the signed refresh token, encrypted to the ambient realm.
  //
  // `keySet` is optional and is the realm's key set where the caller already
  // has it. Throws on failure, with STS-OAUTH-0240 marked: a refresh token
  // that could not be sealed must not go out in the clear, and the token
  // endpoint answers a throw as a server error.
  // -------------------------------------------------------------------------
  seal(jws: string, keySet?: Json, choice?: Choice): string {
    const { log, refreshTokenKeysFor, stsCrypto, errorCodes } = this.deps;
    log.debug('Entering RefreshTokenCrypto.seal().');
    const pair = choice || this.configured();
    try {
      const keys: Json = refreshTokenKeysFor(keySet);
      const kind = this.kindOf(pair.alg);
      const options: Json = { alg: pair.alg, enc: pair.enc, typ: 'JWT',
                              cty: 'JWT' };
      if (kind === 'secret') {
        options.secret = this.symmetricKeyFor(keys.secret, pair.alg,
                                              pair.enc);
        // Named so that `open()` can tell a token sealed under ANOTHER
        // realm's secret from a corrupt one. `encryptJweCompact()` copies a
        // `jwk.kid` into the header and uses `secret` as the key for these
        // algorithms.
        options.jwk = { kid: keys.secretKid };
      } else {
        options.jwk = keys[kind].publicJwk;
      }
      const compact = stsCrypto.encryptJweCompact(jws, options);
      log.debug('Leaving RefreshTokenCrypto.seal(). ' + pair.alg + ' / ' +
                pair.enc);
      return compact;
    } catch (e) {
      log.debug("Caught in RefreshTokenCrypto.seal(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-OAUTH-0240') + 'a refresh token could ' +
                'not be encrypted ' +
                'with ' + pair.alg + ' / ' + pair.enc + ', so none ' +
                'was issued: ' + e.message);
      log.debug('Leaving RefreshTokenCrypto.seal(). It failed.');
      throw errorCodes.mark(e, 'STS-OAUTH-0240');
    }
  }

  // -------------------------------------------------------------------------
  // open(token) — the signed JWT inside an encrypted refresh token.
  //
  // It DECRYPTS and does not verify: the caller verifies what comes back
  // exactly as it verified a refresh token before this module existed. Every
  // refusal is thrown with its code marked, and its message is written to be
  // the `error_description` the refresh grant sends — it names the condition
  // and never a key.
  // -------------------------------------------------------------------------
  open(token: unknown, keySet?: Json): string {
    const { log, refreshTokenKeysFor, stsCrypto, errorCodes } = this.deps;
    log.debug('Entering RefreshTokenCrypto.open().');
    const text = String(token || '').trim();
    const parts = text.split('.');
    if (parts.length === 3) {
      log.debug('Leaving RefreshTokenCrypto.open(). An unencrypted JWT.');
      throw this.refusal('STS-OAUTH-0237', 'refresh tokens issued by this ' +
        'service are encrypted, and this one is not; sign in again to get a ' +
        'new one.');
    }
    if (parts.length !== 5) {
      log.debug('Leaving RefreshTokenCrypto.open(). Not a JWE.');
      throw this.refusal('STS-OAUTH-0238', 'the refresh token is not a ' +
        'token this service issued.');
    }
    let header: Json;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url')
                                .toString('utf8'));
    } catch (e) {
      log.debug("Caught in RefreshTokenCrypto.open(): " +
                ((e && e.message) || e));
      log.debug('Leaving RefreshTokenCrypto.open(). The header is not JSON.');
      throw this.refusal('STS-OAUTH-0238', 'the refresh token is not a ' +
        'token this service issued.');
    }
    const alg = String(header.alg || '');
    const enc = String(header.enc || '');
    let keys: Json;
    try {
      keys = refreshTokenKeysFor(keySet);
    } catch (e) {
      log.debug("Caught in RefreshTokenCrypto.open(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-OAUTH-0240') + 'the refresh-token ' +
                'encryption keys could not be read: ' + e.message);
      log.debug('Leaving RefreshTokenCrypto.open(). No keys.');
      throw errorCodes.mark(e, 'STS-OAUTH-0240');
    }
    const kind = this.kindOf(alg);
    const expectedKid = kind === 'secret' ? keys.secretKid :
                        keys[kind].publicJwk.kid;
    // A token sealed under a DIFFERENT key names a different kid, and that is
    // the commonest real cause — another realm's token, or one issued before
    // this realm's keys were rotated — so it gets its own sentence rather than
    // the tag failure the decrypt would otherwise report.
    if (header.kid !== expectedKid) {
      log.debug('Leaving RefreshTokenCrypto.open(). Another key.');
      throw this.refusal('STS-OAUTH-0238', 'the refresh token was not ' +
        'issued by this realm, or was issued under keys that have since ' +
        'been rotated.');
    }
    let opened: Json;
    try {
      const options: Json = { expectedKid: expectedKid };
      if (kind === 'secret') {
        options.secret = this.symmetricKeyFor(keys.secret, alg, enc);
      } else {
        options.privateKey = keys[kind].privateKey;
      }
      opened = stsCrypto.decryptJweCompact(text, options);
    } catch (e) {
      log.debug("Caught in RefreshTokenCrypto.open(): " +
                ((e && e.message) || e));
      log.debug('Leaving RefreshTokenCrypto.open(). It did not decrypt: ' +
                e.message);
      throw this.refusal('STS-OAUTH-0238', 'the refresh token could not be ' +
        'decrypted; it has been altered, or was not issued by this realm.');
    }
    if (String(opened.header.cty || '').toUpperCase() !== 'JWT' ||
        String(opened.plaintext).split('.').length !== 3) {
      log.debug('Leaving RefreshTokenCrypto.open(). Not a nested JWT.');
      throw this.refusal('STS-OAUTH-0239', 'the refresh token decrypted to ' +
        'something that is not a signed JWT.');
    }
    log.debug('Leaving RefreshTokenCrypto.open(). ' + alg + ' / ' + enc);
    return String(opened.plaintext);
  }

  // -------------------------------------------------------------------------
  // The claims of a token THIS SERVICE JUST ISSUED, encrypted or not, without
  // verifying — for the two places that read a jti back off a token set they
  // minted a moment ago. Answers null rather than throwing.
  // -------------------------------------------------------------------------
  claimsOfIssued(token: unknown): Json | null {
    const { log } = this.deps;
    log.debug('Entering RefreshTokenCrypto.claimsOfIssued().');
    try {
      const jws = this.isEncrypted(token) ? this.open(token) :
        String(token || '');
      const claims = JSON.parse(Buffer.from(jws.split('.')[1], 'base64url')
                                      .toString('utf8'));
      log.debug('Leaving RefreshTokenCrypto.claimsOfIssued().');
      return claims;
    } catch (e) {
      // Answered as null so the caller's own sentence — which names the token
      // kind it was reading — is the one logged.
      log.debug("Caught in RefreshTokenCrypto.claimsOfIssued(): " +
                ((e && e.message) || e));
      log.debug('Leaving RefreshTokenCrypto.claimsOfIssued(). Not ' +
                'readable: ' + e.message);
      return null;
    }
  }

  // What is in force, for the crypto report and the console. No key material.
  describe(keySet?: Json): Json {
    const { log, refreshTokenKeysFor, stsCrypto } = this.deps;
    log.debug("Entering RefreshTokenCrypto.describe().");
    const pair = this.configured();
    const keys: Json = refreshTokenKeysFor(keySet);
    log.debug("Leaving RefreshTokenCrypto.describe().");
    return {
      alg: pair.alg, enc: pair.enc,
      nested: 'a signed JWT (JWS) encrypted as a compact JWE with cty ' +
              '"JWT", RFC 7519 section 11.2',
      algorithms: stsCrypto.JWE_ALGS.slice(),
      encryptions: Object.keys(stsCrypto.JWE_ENCS),
      keys: { rsa: keys.rsa.publicJwk.kid, ec: keys.ec.publicJwk.kid,
              ecCurve: keys.ec.publicJwk.crv, secret: keys.secretKid },
      unencryptedAccepted: false
    };
  }
}

// THE TRANSITIONAL INSTANCE — see the header. Built from the real modules, as
// the composition root will build one.
const rtc = new RefreshTokenCrypto({
  log: helpers.log,
  refreshTokenKeysFor: helpers.refreshTokenKeysFor,
  config: config,
  stsCrypto: stsCrypto,
  errorCodes: errorCodes
});

export = {
  RefreshTokenCrypto: RefreshTokenCrypto,
  kindOf: rtc.kindOf.bind(rtc) as RefreshTokenCrypto['kindOf'],
  symmetricBytes: rtc.symmetricBytes.bind(rtc) as
    RefreshTokenCrypto['symmetricBytes'],
  symmetricKeyFor: rtc.symmetricKeyFor.bind(rtc) as
    RefreshTokenCrypto['symmetricKeyFor'],
  configured: rtc.configured.bind(rtc) as RefreshTokenCrypto['configured'],
  isEncrypted: rtc.isEncrypted.bind(rtc) as RefreshTokenCrypto['isEncrypted'],
  seal: rtc.seal.bind(rtc) as RefreshTokenCrypto['seal'],
  open: rtc.open.bind(rtc) as RefreshTokenCrypto['open'],
  claimsOfIssued: rtc.claimsOfIssued.bind(rtc) as
    RefreshTokenCrypto['claimsOfIssued'],
  describe: rtc.describe.bind(rtc) as RefreshTokenCrypto['describe']
};
