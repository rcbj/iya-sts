'use strict';
//
// File: gnap_tokens.ts
//
// ---------------------------------------------------------------------------
// THE FIVE ACCESS TOKEN FORMATS OF RFC 9767 SECTION 5.3, BEHIND ONE MINT AND
// ONE VERIFY.
//
// GNAP core leaves the access token opaque to the client (RFC 9635 section
// 3.2.1) and RFC 9767 registers five formats an AS and RS may agree on:
// `jwt-signed`, `jwt-encrypted`, `macaroon`, `biscuit` and `zcap`. Every one
// of them carries the same TOKEN MODEL (RFC 9767 section 2.1 — issuer,
// audience, key binding, flags, access rights, time window, identifier,
// resource owner, client instance, label), so every one of them is minted from
// the same object and verified back into it. That is the contract
// `gnap_access.ts`'s `validateModel()` checks and the format modules keep;
// this file is the dispatcher and the home of the two JWT formats, which REUSE
// the service's JOSE module rather than a second one:
//
//   * `jwt-signed` is signed through `helpers.signJwt()` — the one signer that
//     records every token in `admin_stats.js`'s registry — so a GNAP JWT shows
//     on /admin/tokens beside every other token this realm issued and a revoke
//     there is seen by `stats.isRevoked()`.
//   * `jwt-encrypted` is that same signed JWT, NESTED (RFC 7519 section 11.2)
//     inside a JWE from `common/crypto.js`'s `encryptJweCompact()`. To WHOM it
//     is encrypted is the one decision here: to the resource server's own
//     registered public key (`gnapJweKey` on its application entry) when the
//     token is for exactly one RS that has one — which is what makes the
//     format worth having, since then only that RS can read it — and otherwise
//     to a key derived from THIS realm's own secret, which means only this AS
//     can open it and an RS reads it through introspection (RFC 9767 section
//     3.3).
//
// ---------------------------------------------------------------------------
// WHERE EACH FORMAT'S KEY COMES FROM — AND WHY NONE OF THEM IS A NEW KEY
// STORE.
//
// A signing key nobody vouched for is a key somebody has to rotate by hand,
// and a second place this service keeps private keys is a second answer to
// "where are the keys" (common/CLAUDE.md, rule 3w). So every format uses
// material the realm's key set ALREADY holds, sealed and persisted by
// `keystore.js`:
//
//   jwt-signed     the realm's RS256 signing key (`STS`), published at
//                  /oauth2/jwks.
//   jwt-encrypted  the realm's 64-byte refresh-token secret, through HKDF with
//                  a GNAP-only info string — domain separation, so a GNAP JWE
//                  key and a refresh-token key are never the same bytes.
//   macaroon       the same secret, HKDF'd per RESOURCE SERVER, because a
//                  macaroon is verified with its ROOT KEY and handing every RS
//                  one key would let any of them mint for all of them. The
//                  per-RS key is what the RS's application entry carries
//                  (sealed) as `gnapMacaroonKey`.
//   biscuit, zcap  the realm's Ed25519 key from `allSigningKeys()` — selected
//                  by CURVE, because a realm holds an Ed448 EdDSA key beside it
//                  and biscuit is Ed25519-only. A zcap token is signed with it
//                  under `eddsa-jcs-2022` (the default) and
//                  `Ed25519Signature2020`, and with the realm's ML-DSA-44 or
//                  SLH-DSA-SHA2-128s key — two of the eleven post-quantum keys
//                  it already holds — under the two post-quantum suites
//                  `gnap.zcapCryptosuite` offers (#43).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapTokens` takes `helpers`, the service's signing identity (`STS`),
// `common/crypto.js`, the error-code table, the settings, the token registry
// and the four GNAP token libraries through its constructor. The module still
// exports its old names as FACADES forwarding to the instance the composition
// root builds (#50, R2), for the unconverted modules that require it. A
// process that loads this module without the root builds a default instance
// when the module loads.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import config = require('../common/config');
import stats = require('../common/admin_stats');
import macaroon = require('./token_macaroon');
import biscuit = require('./token_biscuit');
import zcap = require('./token_zcap');
import access = require('./gnap_access');

interface GnapTokensDeps {
  // `helpers` itself: its members are read at call time, as they were.
  helpers: any;
  STS: { certPem: string; kid: string };
  stsCrypto: any;
  errorCodes: { mark<T>(target: T, code: string): T };
  config: { value(key: string): unknown };
  stats: { isRevoked(jti: string): boolean };
  macaroon: any;
  biscuit: any;
  zcap: any;
  access: any;
}

// What a refused verification answers.
interface Refusal {
  ok: false;
  errorCode: string;
  why: string;
}

const FORMATS = ['jwt-signed', 'jwt-encrypted', 'macaroon', 'biscuit', 'zcap'];

const JWT_TYP = 'GNAP';

class GnapTokens {
  static readonly FORMATS = FORMATS;
  static readonly JWT_TYP = JWT_TYP;

  constructor(private readonly deps: GnapTokensDeps) {
    deps.helpers.log.debug("Entering GnapTokens.constructor().");
    deps.helpers.log.debug("Leaving GnapTokens.constructor().");
  }

  // The logger, read off `helpers` at each use. Read at the top of every
  // method, so no Entering/Leaving pair — the hot-path exception, stated as
  // it requires.
  private get log() {
    return this.deps.helpers.log;
  }

  private refusal(code: string, why: string): Refusal {
    const { log } = this;
    const { errorCodes } = this.deps;
    log.debug("Entering GnapTokens.refusal().");
    const out: Refusal = { ok: false, errorCode: code, why: why };
    log.debug("Leaving GnapTokens.refusal().");
    return errorCodes.mark(out, code);
  }

  // HKDF over the realm secret. `info` is the domain separator and is never
  // shared with another feature.
  private realmDerived(info: string, length: number): Buffer {
    const { log } = this;
    const { helpers } = this.deps;
    log.debug("Entering GnapTokens.realmDerived().");
    const secret = helpers.refreshTokenKeysFor().secret;
    log.debug("Leaving GnapTokens.realmDerived().");
    return Buffer.from(nodeCrypto.hkdfSync('sha256', secret, Buffer.alloc(0),
                                           Buffer.from(info, 'utf8'),
                                           length || 32));
  }

  private jweSecret(): Buffer {
    const { log } = this;
    log.debug("Entering GnapTokens.jweSecret().");
    log.debug("Leaving GnapTokens.jweSecret().");
    return this.realmDerived('mock-sts gnap jwt-encrypted A256GCM v1', 32);
  }

  // The macaroon root key a resource server verifies with. `rsIdentity` is the
  // RS application's identifier; '' is the key for tokens with no RS audience,
  // which only this AS (introspection, the demonstration RS) can verify.
  macaroonKeyFor(rsIdentity?: unknown): Buffer {
    const { log } = this;
    log.debug("Entering GnapTokens.macaroonKeyFor().");
    log.debug("Leaving GnapTokens.macaroonKeyFor().");
    return this.realmDerived('mock-sts gnap macaroon root v1|' +
                             String(rsIdentity || ''), 32);
  }

  ed25519Keys() {
    const { log } = this;
    const { helpers } = this.deps;
    log.debug("Entering GnapTokens.ed25519Keys().");
    const found = helpers.allSigningKeys().filter(function (one) {
      return one.alg === 'EdDSA' &&
             (one.publicJwk.crv || 'Ed25519') === 'Ed25519';
    })[0];
    if (!found) {
      log.debug("Leaving GnapTokens.ed25519Keys(). None.");
      throw new Error('this realm holds no Ed25519 signing key, which ' +
                      'biscuit and zcap tokens are signed with. That is a ' +
                      'defect in the realm key set.');
    }
    log.debug("Leaving GnapTokens.ed25519Keys().");
    return { privateKey: found.privateKey,
             publicKey: nodeCrypto.createPublicKey(found.privateKey),
             publicJwk: found.publicJwk };
  }

  // EVERY GENERATION OF THE ED25519 KEY THAT STILL VERIFIES (#49 P5, D6):
  // the current one first, then the realm unit's next key and its retired
  // keys within their grace. The key is the realm's `jose:EdDSA:Ed25519`
  // unit, so the signing rotation already rotates it; what a rotation needs
  // here is only that a biscuit or a capability signed before it still
  // verifies. Public halves only.
  ed25519Generations(): Array<{ publicKey: any; publicJwk: any }> {
    const { log } = this;
    const { helpers } = this.deps;
    log.debug("Entering GnapTokens.ed25519Generations().");
    const current = this.ed25519Keys();
    const out = [{ publicKey: current.publicKey,
                   publicJwk: current.publicJwk }];
    const now = Date.now();
    helpers.standbyOf(helpers.stsKeysFor(), 'jose:EdDSA:Ed25519')
      .forEach(function (one: any): void {
        if (!one.publicJwk ||
            (one.role === 'retired' && Number(one.retiredUntil) > 0 &&
             Number(one.retiredUntil) <= now)) {
          return;
        }
        out.push({ publicKey: nodeCrypto.createPublicKey({
          key: one.publicJwk, format: 'jwk' }), publicJwk: one.publicJwk });
      });
    log.debug("Leaving GnapTokens.ed25519Generations(). " + out.length + ".");
    return out;
  }

  // The proof suite a zcap token is signed and verified with in this realm
  // (#43, `gnap/token_zcap.ts`'s header).
  zcapCryptosuite(): string {
    const { log } = this;
    const { config, zcap } = this.deps;
    log.debug("Entering GnapTokens.zcapCryptosuite().");
    const value = String(config.value('gnap.zcapCryptosuite') ||
                         zcap.DEFAULT_CRYPTOSUITE);
    log.debug("Leaving GnapTokens.zcapCryptosuite(). " + value);
    return value;
  }

  // -------------------------------------------------------------------------
  // THE ZCAP KEYS, for the suite this realm is set to. The controller
  // document lives at the realm's own URL, so the controller is built from
  // the base the caller hands in. `others` are the other live generations of
  // the key, which the published document lists.
  //
  // The two Ed25519 suites use the realm's Ed25519 unit, as biscuits do. The
  // post-quantum ones use the realm's `jose:ML-DSA-44` or
  // `jose:SLH-DSA-SHA2-128s` unit — keys the realm already makes, publishes
  // in its JWKS and rotates (#42), brought into being in the worker pool by
  // `allSigningKeysAsync()` on first use, which is why this is asynchronous.
  // -------------------------------------------------------------------------
  async zcapKeys(base?: string): Promise<any> {
    const { log } = this;
    const { helpers } = this.deps;
    log.debug("Entering GnapTokens.zcapKeys().");
    const cryptosuite = this.zcapCryptosuite();
    const controller = String(base || '') + '/gnap/zcap/controller';
    const pqAlg = cryptosuite === 'mldsa44-jcs-2024' ? 'ML-DSA-44'
      : (cryptosuite === 'slhdsa128-jcs-2024' ? 'SLH-DSA-SHA2-128s' : '');
    if (!pqAlg) {
      const keys = this.ed25519Keys();
      const others = this.ed25519Generations().slice(1)
        .map(function (one: any): any {
          return { publicKey: one.publicKey, publicJwk: one.publicJwk,
                   keyId: controller + '#' + one.publicJwk.kid };
        });
      log.debug("Leaving GnapTokens.zcapKeys(). " + cryptosuite);
      return { cryptosuite: cryptosuite, privateKey: keys.privateKey,
               publicKey: keys.publicKey, publicJwk: keys.publicJwk,
               controller: controller,
               keyId: controller + '#' + keys.publicJwk.kid, others: others };
    }
    const all = await helpers.allSigningKeysAsync();
    const found = all.filter(function (one: any): boolean {
      return one.alg === pqAlg;
    })[0];
    if (!found) {
      log.debug("Leaving GnapTokens.zcapKeys(). No " + pqAlg + " key.");
      throw new Error('this realm holds no ' + pqAlg + ' signing key, ' +
                      'which ' + cryptosuite + ' zcap tokens are signed ' +
                      'with. That is a defect in the realm key set.');
    }
    const now = Date.now();
    const others = helpers.standbyOf(helpers.stsKeysFor(), 'jose:' + pqAlg)
      .filter(function (one: any): boolean {
        return !!one.publicJwk &&
               !(one.role === 'retired' && Number(one.retiredUntil) > 0 &&
                 Number(one.retiredUntil) <= now);
      })
      .map(function (one: any): any {
        return { publicJwk: one.publicJwk,
                 keyId: controller + '#' + one.publicJwk.kid };
      });
    log.debug("Leaving GnapTokens.zcapKeys(). " + cryptosuite);
    return { cryptosuite: cryptosuite, privateKey: found.privateKey,
             publicJwk: found.publicJwk, controller: controller,
             keyId: controller + '#' + found.publicJwk.kid, others: others };
  }

  // -------------------------------------------------------------------------
  // THE JWT CLAIMS FOR THE MODEL (RFC 9767 section 2.1's JWT mappings).
  // -------------------------------------------------------------------------
  private claimsOf(model: any): Record<string, any> {
    const { log } = this;
    log.debug("Entering GnapTokens.claimsOf().");
    const claims: Record<string, any> = {
      typ: JWT_TYP,
      iss: model.iss,
      jti: model.jti,
      // A time the model does not carry is OMITTED rather than written as
      // null: jsonwebtoken refuses a non-numeric nbf, and a minimal bearer
      // model has none.
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
    log.debug("Leaving GnapTokens.claimsOf().");
    return claims;
  }

  private modelOfClaims(claims: any) {
    const { log } = this;
    log.debug("Entering GnapTokens.modelOfClaims().");
    log.debug("Leaving GnapTokens.modelOfClaims().");
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

  // The checks every format's verify() makes, applied to a JWT model —
  // through `gnap_access.checkPresentation()`, the SAME function the three
  // capability formats call, so a jwt-signed token and a biscuit are refused
  // for the same reasons under the same codes rather than by two
  // implementations that agree until one of them changes.
  checkModel(model: any, context?: any): any {
    const { log } = this;
    const { access } = this.deps;
    log.debug("Entering GnapTokens.checkModel().");
    const failed = access.checkPresentation(model, context || {});
    if (failed && failed.ok === false) {
      log.debug("Leaving GnapTokens.checkModel(). Refused " +
                failed.errorCode + ".");
      return failed;
    }
    log.debug("Leaving GnapTokens.checkModel().");
    return { ok: true, model: model };
  }

  // -------------------------------------------------------------------------
  // MINT. `ctx.base` is the realm base URL (the ZCAP controller), `ctx.rs`
  // the single resource server the token is for, if exactly one: `{ identity,
  // jweKey }`.
  // -------------------------------------------------------------------------
  // The three library formats REFUSE by returning `{ ok: false }` where the
  // JWT formats throw. Both callers (issuance and rotation) catch a throw, log
  // it under their own code and carry on, so a returned refusal is turned into
  // one here — otherwise a refused mint reached `store.putToken()` with an
  // undefined value and the client was handed a token object with no value in
  // it.
  private mintedOrThrow(format: string, minted: any): any {
    const { log } = this;
    log.debug("Entering GnapTokens.mintedOrThrow().");
    if (!minted || minted.ok === false || typeof minted.value !== 'string' ||
        !minted.value) {
      log.debug("Leaving GnapTokens.mintedOrThrow(). Refused.");
      throw new Error('the ' + format + ' library refused to mint: ' +
                      String((minted && minted.why) ||
                             'no value was produced'));
    }
    log.debug("Leaving GnapTokens.mintedOrThrow().");
    return minted;
  }

  async mint(format: string, model: any, ctx?: any): Promise<any> {
    const { log } = this;
    const { helpers, stsCrypto, errorCodes, config, macaroon, biscuit, zcap,
            access } = this.deps;
    log.debug("Entering GnapTokens.mint(). format=" + format);
    const context = ctx || {};
    if (format === 'jwt-signed' || format === 'jwt-encrypted') {
      // THE MODEL IS VALIDATED HERE FOR THE JWT FORMATS, as each library
      // format validates it in its own mint(). Until 2026-09-12 a JWT was
      // signed from whatever it was handed — a model whose exp preceded its
      // iat included.
      const valid = access.validateModel(model);
      if (!valid.ok) {
        log.debug("Leaving GnapTokens.mint(). Model invalid.");
        const refused: any =
          new Error('the token model is not valid: ' + valid.why);
        refused.errorCode = valid.errorCode;
        throw errorCodes.mark(refused, valid.errorCode);
      }
      // `gnap.accessTokenCertificateHeader` decides the `x5c` / `x5u`, on the
      // JWS in both JWT formats — never on the JWE around jwt-encrypted, which
      // is encrypted to a resource server's key or to a secret.
      const signed = helpers.signJwt(this.claimsOf(valid.model),
                                     { grant: 'gnap',
                                       setId: context.setId || null,
                                       sessionId: context.sessionId || null },
                                     { certificateHeader:
                                         'gnap-access-token' });
      if (typeof signed !== 'string' || signed.split('.').length !== 3) {
        log.debug("Leaving GnapTokens.mint(). The signer produced no JWS.");
        throw new Error('the ' + format + ' access token could not be ' +
                        'signed.');
      }
      if (format === 'jwt-signed') {
        log.debug("Leaving GnapTokens.mint(). jwt-signed.");
        return { value: signed, format: format, jti: model.jti };
      }
      const rsKey = context.rs && context.rs.jweKey ?
        context.rs.jweKey : null;
      let options;
      if (rsKey) {
        const alg = rsKey.alg ||
                    (rsKey.kty === 'EC' ? 'ECDH-ES+A256KW' : 'RSA-OAEP-256');
        options = { alg: alg,
                    enc: String(config.value('gnap.jweEnc') || 'A256GCM'),
                    jwk: rsKey,
                    cty: 'JWT', typ: 'JWT' };
      } else {
        options = { alg: 'dir', enc: 'A256GCM', secret: this.jweSecret(),
                    cty: 'JWT', typ: 'JWT' };
      }
      const value = stsCrypto.encryptJweCompact(signed, options);
      log.debug("Leaving GnapTokens.mint(). jwt-encrypted to " +
                (rsKey ? 'the resource ' + 'server' : 'this ' + 'AS') + ".");
      return { value: value, format: format, jti: model.jti,
               encryptedTo: rsKey ? 'resource-server' :
                 'authorization-server' };
    }
    if (format === 'macaroon') {
      const minted = await macaroon.mint(model, {
        rootKey: this.macaroonKeyFor(context.rs ? context.rs.identity : ''),
        location: model.iss });
      log.debug("Leaving GnapTokens.mint(). macaroon.");
      return this.mintedOrThrow(format, minted);
    }
    if (format === 'biscuit') {
      const keys = this.ed25519Keys();
      const minted = await biscuit.mint(model,
                                        { privateKey: keys.privateKey,
                                          publicKey: keys.publicKey });
      log.debug("Leaving GnapTokens.mint(). biscuit.");
      return this.mintedOrThrow(format, minted);
    }
    if (format === 'zcap') {
      const minted = await zcap.mint(model,
                                     await this.zcapKeys(context.base));
      log.debug("Leaving GnapTokens.mint(). zcap.");
      return this.mintedOrThrow(format, minted);
    }
    log.debug("Leaving GnapTokens.mint(). Unknown format.");
    throw new Error('there is no access token format called "' + format +
                    '".');
  }

  // Which format a presented value is, read off its shape. Used by the
  // demonstration RS, which is handed a value and no format — as a real RS
  // that accepts several formats is.
  formatOf(value: unknown): string {
    const { log } = this;
    log.debug("Entering GnapTokens.formatOf().");
    const text = String(value || '');
    const dots = text.split('.').length - 1;
    if (dots === 2) {
      log.debug("Leaving GnapTokens.formatOf().");
      return 'jwt-signed';
    }
    if (dots === 4) {
      log.debug("Leaving GnapTokens.formatOf().");
      return 'jwt-encrypted';
    }
    if (/^eyJAY29udGV4d|^eyJpZCI6|^eyJ/.test(text)) {
      try {
        const json = JSON.parse(Buffer.from(text, 'base64url')
                                      .toString('utf8'));
        if (json && json.parentCapability) {
          log.debug("Leaving GnapTokens.formatOf().");
          return 'zcap';
        }
      } catch (e) {
        log.debug("Caught in GnapTokens.formatOf(): " +
                  ((e && e.message) || e));
        // Not base64url JSON; fall through to the binary formats.
        log.debug("formatOf(): not a ZCAP: " + e.message);
      }
    }
    const bytes = Buffer.from(text, 'base64url');
    if (bytes.length && bytes[0] === 0x02) {
      log.debug("Leaving GnapTokens.formatOf().");
      // libmacaroons v2 binary starts with the version byte 2.
      return 'macaroon';
    }
    log.debug("Leaving GnapTokens.formatOf().");
    return 'biscuit';
  }

  // -------------------------------------------------------------------------
  // VERIFY a value as a self-contained token. `ctx` is the format modules'
  // context (`now`, `audience`, `presentedKey`, `requiredAccess`) plus `base`,
  // `rsIdentity`, and `rsPrivateJwk` for a jwt-encrypted token to an RS key.
  // -------------------------------------------------------------------------
  async verify(format: string, value: any, ctx?: any): Promise<any> {
    const { log } = this;
    const { STS, stsCrypto, macaroon, biscuit, zcap } = this.deps;
    log.debug("Entering GnapTokens.verify(). format=" + format);
    const context = ctx || {};
    if (format === 'jwt-signed' || format === 'jwt-encrypted') {
      let jws = value;
      if (format === 'jwt-encrypted') {
        try {
          const header = JSON.parse(Buffer.from(String(value).split('.')[0],
                                                'base64url')
                                          .toString('utf8'));
          const opened = header.alg === 'dir'
            ? stsCrypto.decryptJweCompact(value,
                                          { secret: this.jweSecret(),
                                            allowedAlg: ['dir'],
                                            allowedEnc: ['A256GCM'] })
            : (context.rsPrivateKey
              ? stsCrypto.decryptJweCompact(value,
                                            { privateKey:
                                                context.rsPrivateKey })
              : null);
          if (!opened) {
            log.debug("Leaving GnapTokens.verify(). Encrypted to a resource " +
                      "server key this AS does not hold.");
            return this.refusal('STS-GNAP-0340', 'the access token is ' +
                                'encrypted to a resource server\'s key; ' +
                                'only that resource server can read it.');
          }
          jws = opened.plaintext.toString('utf8');
        } catch (e) {
          log.debug("Caught in GnapTokens.verify(): " +
                    ((e && e.message) || e));
          log.debug("Leaving GnapTokens.verify(). JWE does not open: " +
                    e.message);
          return this.refusal('STS-GNAP-0341', 'the encrypted access token ' +
                              'does not decrypt: ' + e.message);
        }
      }
      let claims;
      try {
        claims = helpers.verifyOwnJws(jws,
                                     { algorithms: ['RS256'],
                                       clockTolerance: 0 });
      } catch (e) {
        log.debug("Caught in GnapTokens.verify(): " +
                  ((e && e.message) || e));
        // Expiry is refused below with the model's own sentence, so an
        // expired signature error is re-read without the time check.
        if (e && e.name === 'TokenExpiredError') {
          try {
            claims = helpers.verifyOwnCompactJws(jws,
                                                { algorithms: ['RS256'] })
                              .claims;
          } catch (e2) {
            log.debug("Caught in GnapTokens.verify(): " +
                      ((e2 && e2.message) || e2));
            log.debug("Leaving GnapTokens.verify(). Signature refused: " +
                      e2.message);
            return this.refusal('STS-GNAP-0342', 'the access token ' +
                                'signature does not verify: ' + e2.message);
          }
        } else if (e && e.name === 'NotBeforeError') {
          claims = helpers.verifyOwnCompactJws(jws,
                                              { algorithms: ['RS256'] })
                            .claims;
        } else {
          log.debug("Leaving GnapTokens.verify(). Signature refused: " +
                    (e && e.message));
          return this.refusal('STS-GNAP-0342', 'the access token ' +
                              'signature does not verify: ' +
                              (e && e.message));
        }
      }
      if (claims.typ !== JWT_TYP) {
        log.debug("Leaving GnapTokens.verify(). Not a GNAP JWT.");
        return this.refusal('STS-GNAP-0343',
                            'the JWT is not a GNAP access token (typ ' +
                            claims.typ + ').');
      }
      const checked = this.checkModel(this.modelOfClaims(claims), context);
      log.debug("Leaving GnapTokens.verify(). jwt ok=" + checked.ok);
      return checked;
    }
    if (format === 'macaroon') {
      const out = await macaroon.verify(value,
                                        { rootKey: this.macaroonKeyFor(
                                            context.rsIdentity || ''),
                                          location: null }, context);
      log.debug("Leaving GnapTokens.verify(). macaroon ok=" + out.ok);
      return out;
    }
    // Against EVERY live generation of the Ed25519 key (#49 P5): the first
    // that verifies answers, and the current key's answer is the one given
    // when none does — the refusal every caller already reads.
    if (format === 'biscuit') {
      const generations = this.ed25519Generations();
      let first: any = null;
      for (let i = 0; i < generations.length; i++) {
        const key = { publicKey: generations[i].publicKey };
        const out = await biscuit.verify(value, key, context);
        if (out.ok) {
          log.debug("Leaving GnapTokens.verify(). biscuit ok, generation " +
                    i + ".");
          return out;
        }
        first = first || out;
      }
      log.debug("Leaving GnapTokens.verify(). biscuit refused.");
      return first;
    }
    if (format === 'zcap') {
      const current = await this.zcapKeys(context.base);
      const generations = [current].concat(current.others.map(
        function (one: any): any {
          return { cryptosuite: current.cryptosuite,
                   publicKey: one.publicKey, publicJwk: one.publicJwk,
                   keyId: one.keyId, controller: current.controller };
        }));
      let first: any = null;
      for (let i = 0; i < generations.length; i++) {
        const out = await zcap.verify(value, generations[i], context);
        if (out.ok) {
          log.debug("Leaving GnapTokens.verify(). zcap ok, generation " + i +
                    ".");
          return out;
        }
        first = first || out;
      }
      log.debug("Leaving GnapTokens.verify(). zcap refused.");
      return first;
    }
    log.debug("Leaving GnapTokens.verify(). Unknown format.");
    return this.refusal('STS-GNAP-0344',
                        'there is no access token format called "' + format +
                        '".');
  }

  // What `GET /gnap/keys` publishes: the material an RS needs to verify the
  // self-contained formats without calling this AS. The macaroon root key is
  // NOT here — it is a secret, and per resource server.
  publicMaterial(base: string) {
    const { log } = this;
    const { helpers, STS } = this.deps;
    log.debug("Entering GnapTokens.publicMaterial().");
    const keys = this.ed25519Keys();
    const raw = Buffer.from(keys.publicJwk.x, 'base64url');
    log.debug("Leaving GnapTokens.publicMaterial().");
    return {
      // The kid a jwt-signed token's header carries, which `keys.kidFormat`
      // decides (common/jose_kid.js) — the one this document names has to be
      // it.
      jwt: { jwks_uri: base + '/oauth2/jwks', alg: 'RS256',
             kid: helpers.publishedKidFor(STS.kid), typ: JWT_TYP },
      biscuit: { algorithm: 'ed25519',
                 root_public_key: 'ed25519/' + raw.toString('hex'),
                 jwk: keys.publicJwk,
                 // Every key a biscuit this realm minted may be signed with
                 // (#49 P5): the current one first, then its next key and the
                 // retired ones still verifying. Non-standard; a verifier
                 // that knows only `root_public_key` sees the current one.
                 root_public_keys: this.ed25519Generations()
                   .map(function (one: any): string {
                     return 'ed25519/' + Buffer.from(one.publicJwk.x,
                                                     'base64url')
                       .toString('hex');
                   }) },
      // `cryptosuite` is the one proof suite this realm signs and accepts
      // zcap tokens with (#43); the controller document publishes the key
      // in the form that suite names.
      zcap: { controller: base + '/gnap/zcap/controller',
              cryptosuite: this.zcapCryptosuite() },
      macaroon: { root_key: 'per resource server; carried (sealed) on the ' +
                  'resource server\'s application entry as ' +
                  'gnapMacaroonKey' },
      'jwt-encrypted': { authorization_server: 'dir/A256GCM under a ' +
                                               'realm-derived key ' +
                                               '(introspect)',
                         resource_server: 'the resource server\'s ' +
                                          'registered gnapJweKey' }
    };
  }

  describe() {
    const { log } = this;
    const { macaroon, biscuit, zcap } = this.deps;
    log.debug("Entering GnapTokens.describe().");
    log.debug("Leaving GnapTokens.describe().");
    return {
      jwt: { signs: 'RS256 with the realm signing key',
             encrypts: 'dir+A256GCM ' +
             '(realm-derived) or RSA-OAEP-256 / ECDH-ES+A256KW to the ' +
             'resource server\'s gnapJweKey' },
      macaroon: macaroon.describe(),
      biscuit: biscuit.describe(),
      zcap: zcap.describe()
    };
  }

  isRevokedJti(jti: string): boolean {
    const { log } = this;
    const { stats } = this.deps;
    log.debug("Entering GnapTokens.isRevokedJti().");
    log.debug("Leaving GnapTokens.isRevokedJti().");
    return stats.isRevoked(jti);
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  static defaultDeps(): GnapTokensDeps {
    helpers.log.debug("Entering GnapTokens.defaultDeps().");
    helpers.log.debug("Leaving GnapTokens.defaultDeps().");
    return {
      helpers: helpers,
      STS: helpers.STS,
      stsCrypto: stsCrypto,
      errorCodes: errorCodes,
      config: config,
      stats: stats,
      macaroon: macaroon,
      biscuit: biscuit,
      zcap: zcap,
      access: access
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
const slot = new InstanceSlot<GnapTokens>(
  'gnap/gnap_tokens',
  () => new GnapTokens(GnapTokens.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  GnapTokens: GnapTokens,
  installInstance: (instance: GnapTokens): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  FORMATS: GnapTokens.FORMATS,
  JWT_TYP: GnapTokens.JWT_TYP,
  mint: slot.forward('mint'),
  verify: slot.forward('verify'),
  formatOf: slot.forward('formatOf'),
  checkModel: slot.forward('checkModel'),
  macaroonKeyFor: slot.forward('macaroonKeyFor'),
  zcapKeys: slot.forward('zcapKeys'),
  ed25519Keys: slot.forward('ed25519Keys'),
  publicMaterial: slot.forward('publicMaterial'),
  describe: slot.forward('describe'),
  isRevokedJti: slot.forward('isRevokedJti')
};
