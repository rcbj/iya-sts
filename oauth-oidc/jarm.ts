'use strict';
//
// File: jarm.ts
//
// ===========================================================================
// JWT SECURED AUTHORIZATION RESPONSE MODE — JARM (#143, built inside #139 at
// rcbj's decision, 2026-09-22).
//
// FAPI 1.0 Advanced allows `response_type=code` only with `response_mode=jwt`
// (Part 2 section 5.2.2 item 2), and JARM is what that means: the parameters
// an authorization response would have carried — `code` and `state`, or
// `error`, `error_description` and `state` — go into ONE signed JWT, with
// `iss`, `aud` (the client) and `exp`, sent as the single `response`
// parameter. It is implemented for every response mode and in every profile,
// because it is a specification of its own (JARM, final) that any client may
// ask for, and a mode offered only under FAPI would be a mode no ordinary
// client could be tested against.
//
// FOUR MODES (JARM section 2.3): `query.jwt`, `fragment.jwt`, `form_post.jwt`,
// and `jwt`, which is `query.jwt` for `code` and `fragment.jwt` for every
// other response type (`none` is a query too). `query.jwt` is refused with a
// response type carrying `token` or `id_token` unless the response is
// encrypted, as section 2.3.1 says.
//
// SIGNED, THEN — WHERE THE CLIENT REGISTERED IT — ENCRYPTED (section 2.2):
// `authorization_signed_response_alg` (RS256 by default, JARM's own default;
// PS256 under FAPI 1.0 Advanced, whose section 8.6 also refuses anything but
// PS256 and ES256), and `authorization_encrypted_response_alg` / `_enc`
// (A128CBC-HS256 when only the alg is named) to the key in the client's
// inline `jwks` — the ID Token's arrangement, `recipientKey()` included. An
// HMAC algorithm is keyed by the client secret. `common/applications.js`'s
// `jarmMetadataProblem()` owns the grammar at registration.
//
// A library (rule 3): it registers nothing and requires `common/` modules,
// `introspection_jwt.ts` (the key selection) and `fapi.js`, none of which
// requires it back. `oauth2.ts`'s `redirectBack()` is the one place that
// sends a JARM response; this decides what it is.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import stsCrypto = require('../common/crypto');
import config = require('../common/config');
import applications = require('../common/applications');
import errorCodes = require('../common/error_codes');
import introspectionJwt = require('./introspection_jwt');
import fapi = require('./fapi');

// A registration document, a response's fields.
type Json = any;

interface JarmDeps {
  log: typeof helpers.log;
  helpers: typeof helpers;
  stsCrypto: typeof stsCrypto;
  config: typeof config;
  applications: typeof applications;
  errorCodes: typeof errorCodes;
  introspectionJwt: typeof introspectionJwt;
  fapi: typeof fapi;
}

const MODES = ['jwt', 'query.jwt', 'fragment.jwt', 'form_post.jwt'];
const DEFAULT_SIGNING_ALG = 'RS256';
const DEFAULT_ENC = 'A128CBC-HS256';
const SIGNING_ALGS = stsCrypto.JWS_SIGNING_ALGS.slice(0);
const ENCRYPTION_ALGS = applications.ID_TOKEN_ENCRYPTION_ALGS;
const ENCRYPTION_ENCS = applications.ID_TOKEN_ENCRYPTION_ENCS;
const ENC_MEMBER = 'authorization_encrypted_response_alg';

class Jarm {
  static readonly MODES = MODES;
  static readonly SIGNING_ALGS = SIGNING_ALGS;
  static readonly ENCRYPTION_ALGS = ENCRYPTION_ALGS;
  static readonly ENCRYPTION_ENCS = ENCRYPTION_ENCS;

  constructor(private readonly deps: JarmDeps) {
    deps.log.debug("Entering Jarm.constructor().");
    deps.log.debug("Leaving Jarm.constructor().");
  }

  static defaultDeps(): JarmDeps {
    helpers.log.debug("Entering Jarm.defaultDeps().");
    helpers.log.debug("Leaving Jarm.defaultDeps().");
    return {
      log: helpers.log,
      helpers: helpers,
      stsCrypto: stsCrypto,
      config: config,
      applications: applications,
      errorCodes: errorCodes,
      introspectionJwt: introspectionJwt,
      fapi: fapi
    };
  }

  // Whether `mode` is one of JARM's.
  isJarm(mode: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering Jarm.isJarm().");
    log.debug("Leaving Jarm.isJarm().");
    return MODES.indexOf(String(mode || '')) >= 0;
  }

  // How the `response` parameter travels: 'query', 'fragment' or
  // 'form_post'. `types` is the response_type, as a string or a list.
  transportOf(mode: Json, types: Json): string {
    const { log } = this.deps;
    log.debug("Entering Jarm.transportOf(). " + mode);
    const asked = String(mode || '');
    if (asked === 'query.jwt') {
      log.debug("Leaving Jarm.transportOf(). query");
      return 'query';
    }
    if (asked === 'fragment.jwt') {
      log.debug("Leaving Jarm.transportOf(). fragment");
      return 'fragment';
    }
    if (asked === 'form_post.jwt') {
      log.debug("Leaving Jarm.transportOf(). form_post");
      return 'form_post';
    }
    const list = (Array.isArray(types) ? types
      : String(types || '').split(/\s+/)).filter(Boolean);
    const queryable = list.every(function (one: string) {
      return one === 'code' || one === 'none';
    });
    log.debug("Leaving Jarm.transportOf(). " +
              (queryable ? 'query' : 'fragment'));
    return queryable ? 'query' : 'fragment';
  }

  // What this client's responses are signed and encrypted with, or a refusal.
  protectionFor(registered: Json): Json {
    const { log, applications, fapi } = this.deps;
    log.debug("Entering Jarm.protectionFor().");
    const doc = registered || {};
    const problem = applications.jarmMetadataProblem(doc);
    if (problem) {
      log.debug("Leaving Jarm.protectionFor(). The registration.");
      return { ok: false, description: problem.description };
    }
    const signAlg = String(doc.authorization_signed_response_alg || '')
      .trim() || fapi.defaultSigningAlg() || DEFAULT_SIGNING_ALG;
    if (!fapi.signingAlgAllowed(signAlg)) {
      log.debug("Leaving Jarm.protectionFor(). FAPI refuses the alg.");
      return { ok: false, description: 'authorization_signed_response_alg ' +
               '"' + signAlg + '" is not PS256 or ES256, which FAPI 1.0 ' +
               'Advanced requires (Part 2 section 8.6).' };
    }
    const alg = String(doc.authorization_encrypted_response_alg || '').trim();
    if (alg && !fapi.encryptionAlgAllowed(alg)) {
      log.debug("Leaving Jarm.protectionFor(). FAPI refuses RSA1_5.");
      return { ok: false, description: ENC_MEMBER + ' "' + alg + '" may ' +
               'not be used under FAPI 1.0 Advanced (Part 2 section 8.6.1).' };
    }
    const enc = alg ? (String(doc.authorization_encrypted_response_enc || '')
      .trim() || DEFAULT_ENC) : '';
    log.debug("Leaving Jarm.protectionFor(). " + signAlg +
              (alg ? ', ' + alg + ' ' + enc : ''));
    return { ok: true, signAlg: signAlg, alg: alg, enc: enc };
  }

  // JARM section 2.3.1: `query.jwt` carries no token in clear.
  modeProblem(mode: Json, types: Json, registered: Json): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering Jarm.modeProblem().");
    if (this.transportOf(mode, types) !== 'query' ||
        String(mode || '') !== 'query.jwt') {
      log.debug("Leaving Jarm.modeProblem(). Not query.jwt.");
      return null;
    }
    const list = (Array.isArray(types) ? types
      : String(types || '').split(/\s+/)).filter(Boolean);
    const bearing = list.some(function (one: string) {
      return one === 'token' || one === 'id_token';
    });
    const protection = this.protectionFor(registered);
    if (bearing && !(protection.ok && protection.alg)) {
      log.debug("Leaving Jarm.modeProblem(). A token in a query.");
      return errorCodes.mark({ errorCode: 'STS-OAUTH-0587',
        error: 'invalid_request',
        description: 'response_mode=query.jwt may not carry a response type ' +
          'with token or id_token unless the response is encrypted (JARM ' +
          'section 2.3.1), and this client registered no ' + ENC_MEMBER +
          '.' }, 'STS-OAUTH-0587');
    }
    log.debug("Leaving Jarm.modeProblem(). Allowed.");
    return null;
  }

  // Whether the client's `jwks` holds a key its responses can be encrypted
  // to — asked at registration, as the ID Token's is.
  registrationKeyProblem(metadata: Json): Json {
    const { log, introspectionJwt, errorCodes } = this.deps;
    log.debug("Entering Jarm.registrationKeyProblem().");
    const protection = this.protectionFor(metadata);
    if (!protection.ok || !protection.alg) {
      log.debug("Leaving Jarm.registrationKeyProblem(). Nothing to check.");
      return null;
    }
    try {
      introspectionJwt.recipientKey(metadata, protection.alg, ENC_MEMBER);
    } catch (e) {
      log.debug("Caught in Jarm.registrationKeyProblem(): " +
                ((e && e.message) || e));
      log.debug("Leaving Jarm.registrationKeyProblem(). No key.");
      return errorCodes.mark({
        errorCode: 'STS-REG-0180', error: 'invalid_client_metadata',
        member: ENC_MEMBER,
        description: ENC_MEMBER + ': ' + ((e && e.message) || e) +
          ' Every JWT-secured authorization response would be encrypted to ' +
          'that key, so the registration is refused.'
      }, 'STS-REG-0180');
    }
    log.debug("Leaving Jarm.registrationKeyProblem(). A key.");
    return null;
  }

  // ---------------------------------------------------------------------------
  // THE RESPONSE (JARM section 2.1): the fields an authorization response
  // would have carried, with `iss`, `aud` and `exp`, signed and — where
  // registered — encrypted. `expires_in` stays a number; everything else is a
  // string, as it would have been in a URL.
  // ---------------------------------------------------------------------------
  async respond(fields: Json, context: Json): Promise<string> {
    const { log, helpers, stsCrypto, config, introspectionJwt,
            errorCodes } = this.deps;
    log.debug("Entering Jarm.respond().");
    const ctx = context || {};
    const registered = ctx.registered || {};
    const protection = this.protectionFor(registered);
    if (!protection.ok) {
      log.debug("Leaving Jarm.respond(). Refused.");
      throw errorCodes.mark(new Error('This client\'s JWT-secured ' +
        'authorization response cannot be made: ' + protection.description),
        'STS-OAUTH-0588');
    }
    const now = Math.floor(Date.now() / 1000);
    const payload: Json = {};
    Object.keys(fields || {}).forEach(function (name) {
      if (fields[name] === undefined || fields[name] === null) {
        return;
      }
      payload[name] = name === 'expires_in' && isFinite(Number(fields[name]))
        ? Number(fields[name]) : String(fields[name]);
    });
    payload.iss = String(ctx.issuer || payload.iss || '');
    payload.aud = String(ctx.clientId || '');
    payload.exp = now + Number(config.value('oauth2.jarmResponseLifetimeS'));
    // certificate-header: none — a JARM response is verified against the
    // issuer's JWKS by `kid` (JARM section 2.4), and names no certificate.
    const signed = await helpers.signJwtAsAsync(payload, protection.signAlg,
      registered.client_secret, {});
    if (!protection.alg) {
      log.debug("Leaving Jarm.respond(). Signed " + protection.signAlg + ".");
      return signed;
    }
    let jwk: Json = null;
    try {
      jwk = introspectionJwt.recipientKey(registered, protection.alg,
                                          ENC_MEMBER);
    } catch (e) {
      log.debug("Caught in Jarm.respond(): " + ((e && e.message) || e));
      log.debug("Leaving Jarm.respond(). No key to encrypt to.");
      throw errorCodes.mark(new Error(String((e && e.message) || e)),
                            'STS-OAUTH-0588');
    }
    const jwe = stsCrypto.encryptJweCompact(signed, {
      alg: protection.alg, enc: protection.enc, jwk: jwk, cty: 'JWT',
      typ: 'JWT'
    });
    log.debug("Leaving Jarm.respond(). Signed " + protection.signAlg +
              ", encrypted " + protection.alg + " " + protection.enc + ".");
    return jwe;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Jarm>(
  'oauth-oidc/jarm',
  () => new Jarm(Jarm.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module always did.
slot.buildNowUnlessDeferred();

export = {
  Jarm: Jarm,
  installInstance: (instance: Jarm): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  MODES: Jarm.MODES,
  SIGNING_ALGS: Jarm.SIGNING_ALGS,
  ENCRYPTION_ALGS: Jarm.ENCRYPTION_ALGS,
  ENCRYPTION_ENCS: Jarm.ENCRYPTION_ENCS,
  isJarm: slot.forward('isJarm'),
  transportOf: slot.forward('transportOf'),
  protectionFor: slot.forward('protectionFor'),
  modeProblem: slot.forward('modeProblem'),
  registrationKeyProblem: slot.forward('registrationKeyProblem'),
  respond: slot.forward('respond')
};
