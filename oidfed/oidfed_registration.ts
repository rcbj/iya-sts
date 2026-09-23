'use strict';
//
// File: oidfed_registration.ts
//
// ===========================================================================
// A RELYING PARTY BECOMES A CLIENT THROUGH THE FEDERATION (OpenID Federation
// for OpenID Connect 1.1, section 12; #134, 2026-09-23).
//
// An OP in a federation registers clients it was never configured with,
// because a Trust Anchor it trusts vouches for them. Two ways:
//
//   AUTOMATIC (12.1)  the RP's first authentication request — at the
//                     authorization endpoint or the PAR endpoint — carries
//                     its Entity Identifier as client_id and proves it holds
//                     the RP's key: a SIGNED request object, or (PAR only) a
//                     private_key_jwt assertion. `wants()` says whether a
//                     request is one; `automatic()` resolves, verifies and
//                     registers, and the endpoint then carries on exactly as
//                     for any registered client.
//   EXPLICIT (12.2)   the RP POSTs its Entity Configuration (or a Trust Chain
//                     beginning with it) to /oidfed/register and is answered
//                     with a signed explicit-registration-response+jwt
//                     carrying the metadata it was registered with.
//
// rcbj's answer 5 on #132: BOTH MODES, AND ONLY THROUGH A CHAIN TO ONE OF THE
// REALM'S TRUST ANCHORS. That is how this sits beside product mode's refusal
// of an unknown client_id, and it is not an exception to it: the client is
// not unknown by the time any endpoint asks — it was registered, from
// metadata a Trust Anchor this realm's administrator configured vouches for,
// by a request proving possession of the key that metadata names. What
// product mode refuses is a client nobody registered; this one was
// registered, by the federation, for the life of its chain (12.3 —
// `applications.clientConfigOf()` answers "unknown" past it). No mode
// predicate: development and product do the same thing here, and a
// predicate that answered alike in both would be decoration.
//
// ---------------------------------------------------------------------------
// WHAT IS VERIFIED BEFORE ANYTHING IS WRITTEN.
//
//   * the RP's Trust Chain, to a configured anchor — walked (bounded, 18.1;
//     `trust_chain.ts`), or the one the request object's `trust_chain` header
//     presents, fully validated either way (12.1.1.1.2: "the OP MUST fully
//     verify the Trust Chain");
//   * its resolved `openid_relying_party` metadata, policy applied;
//   * the proof: the request object or assertion signed by a key of that
//     metadata (`jwks`, `jwks_uri`, or a `signed_jwks_uri` whose JWT verifies
//     against the RP's Federation Entity Keys as its superior attested
//     them), with `aud` this OP ALONE, `iss` (and `client_id`) the RP, no
//     `sub` on a request object (12.1.1.1: so it cannot be replayed as a
//     client assertion), a `jti` and an `exp`;
//   * then the metadata is held to every check an RFC 7591 registration is
//     (`oauth2.registerFederatedClient()`).
//
// A request object's `jti` is NOT spent here: the authorization endpoint's
// own JAR processing verifies the same object again, against the keys now
// registered, and spends it once there — so a replay is refused where every
// other replay is.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import EntityStatement = require('./entity_statement');
import federationKeys = require('./federation_keys');

type Json = any;
type Req = any;

// Token endpoint methods that authenticate with a key the RP holds — the only
// kind Automatic Registration can use, since nothing was provisioned (12.1).
const ASYMMETRIC_METHODS = Object.freeze(['private_key_jwt',
  'self_signed_tls_client_auth', 'tls_client_auth']);
const SECRET_METHODS = Object.freeze(['client_secret_basic',
  'client_secret_post', 'client_secret_jwt']);
// Members of openid_relying_party metadata that are the FEDERATION's, not a
// client registration's, and are not stored on the client.
const FEDERATION_ONLY = Object.freeze(['client_registration_types',
  'signed_jwks_uri', 'organization_name', 'display_name', 'description',
  'keywords', 'information_uri', 'organization_uri']);
const EXPIRE_JOB = 'oidfed.registrations-expire';

interface RegistrationDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  keys: typeof federationKeys;
  // Lazily: the entity, the authorization server, the application register,
  // the outbound requester, the audit log and the scheduler.
  oidfed: () => Json;
  oauth2: () => Json;
  applications: () => Json;
  fedHttp: () => Json;
  audit: () => Json;
  scheduler: () => Json;
  now: () => number;
}

interface Outcome {
  ok: boolean;
  code?: string;
  error?: string;
  description?: string;
  status?: number;
  [key: string]: Json;
}

class OidfedRegistration {
  static readonly EXPIRE_JOB = EXPIRE_JOB;

  constructor(private readonly deps: RegistrationDeps) {
    deps.log.debug("Entering OidfedRegistration.constructor().");
    deps.log.debug("Leaving OidfedRegistration.constructor().");
  }

  static defaultDeps(): RegistrationDeps {
    helpers.log.debug("Entering OidfedRegistration.defaultDeps().");
    helpers.log.debug("Leaving OidfedRegistration.defaultDeps().");
    return {
      log: helpers.log, config: config, errorCodes: errorCodes,
      keys: federationKeys,
      oidfed: function (): Json {
        return require('./oidfed');
      },
      oauth2: function (): Json {
        return require('../oauth-oidc/oauth2');
      },
      applications: function (): Json {
        return require('../common/applications');
      },
      fedHttp: function (): Json {
        return require('../federation/federation_http');
      },
      audit: function (): Json {
        return require('../common/audit');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  private nowSec(): number {
    this.deps.log.debug("Entering OidfedRegistration.nowSec().");
    this.deps.log.debug("Leaving OidfedRegistration.nowSec().");
    return Math.floor(this.deps.now() / 1000);
  }

  private refuse(code: string, error: string, description: string,
                 status?: number): Outcome {
    this.deps.log.debug("Entering OidfedRegistration.refuse(). " + code);
    this.deps.log.debug("Leaving OidfedRegistration.refuse().");
    return { ok: false, code: code, error: error, description: description,
             status: status || 400 };
  }

  private types(): string[] {
    this.deps.log.debug("Entering OidfedRegistration.types().");
    this.deps.log.debug("Leaving OidfedRegistration.types().");
    return this.deps.oidfed().registrationTypes();
  }

  // -------------------------------------------------------------------------
  // IS THIS A REQUEST TO REGISTER AUTOMATICALLY? (12.1.1.1.2: "the incoming
  // Client ID is a valid URL, and the OP does not have the Client ID
  // registered") — and the realm accepts automatic registration. A
  // registration that has ended is no registration (12.3), so the same
  // client registers again.
  // -------------------------------------------------------------------------
  wants(req: Req, clientId: Json): boolean {
    const { log, applications } = this.deps;
    log.debug("Entering OidfedRegistration.wants().");
    const out = typeof clientId === 'string' &&
      EntityStatement.isEntityId(clientId) &&
      this.types().indexOf('automatic') >= 0 &&
      !applications().clientConfigOf(clientId).known;
    log.debug("Leaving OidfedRegistration.wants(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE RP, RESOLVED: its Trust Chain to one of this realm's anchors — the
  // one presented (validated in full), or walked for — and its resolved
  // openid_relying_party metadata. `configuration` is an Explicit
  // Registration's body, which the walk starts from; `audience` the OP it
  // must name.
  // -------------------------------------------------------------------------
  async resolveRp(req: Req, clientId: string, presented: Json,
                  configuration?: string, audience?: string): Promise<Outcome> {
    const { log, oidfed } = this.deps;
    log.debug("Entering OidfedRegistration.resolveRp(). " + clientId);
    const anchors = oidfed().anchors(req);
    const tc = oidfed().chainResolver(req, true);
    let resolved: Json;
    if (Array.isArray(presented)) {
      resolved = tc.validate(presented, anchors, { audience: audience });
      if (resolved.ok && resolved.subject !== clientId) {
        log.debug("Leaving OidfedRegistration.resolveRp(). Somebody " +
                  "else's chain.");
        return this.refuse('STS-OIDFED-0053', 'invalid_trust_chain', 'the ' +
                           'presented Trust Chain is about ' +
                           resolved.subject + ', not ' + clientId + '.');
      }
    } else {
      resolved = await tc.resolve(clientId, anchors,
        { configuration: configuration, audience: audience });
    }
    if (!resolved.ok) {
      log.debug("Leaving OidfedRegistration.resolveRp(). " + resolved.why);
      return this.refuse(String(resolved.code || 'STS-OIDFED-0027'),
                         String(resolved.error || 'invalid_trust_chain'),
                         String(resolved.why));
    }
    const rp = (resolved.metadata || {}).openid_relying_party;
    if (!rp || typeof rp !== 'object') {
      log.debug("Leaving OidfedRegistration.resolveRp(). Not an RP.");
      return this.refuse('STS-OIDFED-0052', 'invalid_metadata', clientId +
                         ' resolves with no openid_relying_party metadata ' +
                         '(Connect 1.1, 5.1.1).');
    }
    log.debug("Leaving OidfedRegistration.resolveRp(). Through " +
              resolved.anchor);
    return { ok: true, resolved: resolved, rp: rp };
  }

  // -------------------------------------------------------------------------
  // THE RP'S KEYS FOR ITS PROTOCOL ROLE (5.2.1): `jwks` by value; or a
  // `signed_jwks_uri` whose jwk-set+jwt verifies against the RP's Federation
  // Entity Keys AS ITS SUPERIOR ATTESTED THEM (the Subordinate Statement's
  // `jwks`, chain[1]); or a `jwks_uri`, fetched when a key is needed as any
  // registered client's is. `{ ok, jwks }` or `{ ok, jwksUri }`.
  // -------------------------------------------------------------------------
  async rpKeys(rp: Json, resolved: Json, clientId: string): Promise<Outcome> {
    const { log, fedHttp, config } = this.deps;
    log.debug("Entering OidfedRegistration.rpKeys().");
    if (rp.jwks) {
      const problem = EntityStatement.jwksProblem(rp.jwks);
      log.debug("Leaving OidfedRegistration.rpKeys(). jwks: " +
                (problem || 'fine'));
      return problem ? this.refuse('STS-OIDFED-0052', 'invalid_metadata',
                                   'openid_relying_party.jwks ' + problem +
                                   '.')
                     : { ok: true, jwks: rp.jwks };
    }
    if (rp.signed_jwks_uri) {
      if (!EntityStatement.isEndpointUrl(rp.signed_jwks_uri)) {
        log.debug("Leaving OidfedRegistration.rpKeys(). Not https.");
        return this.refuse('STS-OIDFED-0052', 'invalid_metadata',
                           'signed_jwks_uri is not an https URL (5.2.1).');
      }
      const got = await fedHttp().fetchPublished(rp.signed_jwks_uri, {
        accept: 'application/jwk-set+jwt',
        timeoutMs: Number(config.value('oidfed.fetchTimeoutMs')),
        maxBytes: Number(config.value('oidfed.fetchMaxBytes')) });
      const chain = resolved.chain || [];
      const federationJwks = (chain[1] || chain[0] || {}).jwks;
      const verified = got.ok && got.status === 200
        ? EntityStatement.verify(String(got.body || '').trim(),
                                 federationJwks, EntityStatement.TYP.JWK_SET)
        : { ok: false, why: 'it answered ' + got.status + ' ' + got.why };
      if (!verified.ok || verified.claims.iss !== clientId ||
          !Array.isArray(verified.claims.keys)) {
        log.debug("Leaving OidfedRegistration.rpKeys(). signed_jwks_uri.");
        return this.refuse('STS-OIDFED-0052', 'invalid_metadata',
                           'the signed_jwks_uri did not yield a JWK Set ' +
                           'signed by ' + clientId + ': ' +
                           (verified.why || 'wrong issuer'));
      }
      const jwks = { keys: verified.claims.keys };
      const problem = EntityStatement.jwksProblem(jwks);
      log.debug("Leaving OidfedRegistration.rpKeys(). signed_jwks_uri: " +
                (problem || 'fine'));
      return problem ? this.refuse('STS-OIDFED-0052', 'invalid_metadata',
                                   'the signed JWK Set ' + problem + '.')
                     : { ok: true, jwks: jwks };
    }
    if (rp.jwks_uri && EntityStatement.isEndpointUrl(rp.jwks_uri)) {
      log.debug("Leaving OidfedRegistration.rpKeys(). jwks_uri.");
      return { ok: true, jwksUri: String(rp.jwks_uri) };
    }
    log.debug("Leaving OidfedRegistration.rpKeys(). None.");
    return this.refuse('STS-OIDFED-0052', 'invalid_metadata', clientId +
                       ' publishes no keys for its relying party role — no ' +
                       'jwks, signed_jwks_uri or jwks_uri — so it cannot ' +
                       'prove a request is its own (12.1).');
  }

  // The keys of `keys` a JWT may be verified with: a jwks as given, or a
  // jwks_uri fetched through the outbound policy.
  private async candidateKeys(keys: Json): Promise<Json[]> {
    const { log, fedHttp, config } = this.deps;
    log.debug("Entering OidfedRegistration.candidateKeys().");
    if (keys.jwks) {
      log.debug("Leaving OidfedRegistration.candidateKeys(). Given.");
      return keys.jwks.keys || [];
    }
    const got = await fedHttp().fetchPublished(keys.jwksUri, {
      accept: 'application/json',
      timeoutMs: Number(config.value('oidfed.fetchTimeoutMs')),
      maxBytes: Number(config.value('oidfed.fetchMaxBytes')) });
    let out: Json[] = [];
    try {
      out = got.ok ? (JSON.parse(got.body.toString('utf8')).keys || []) : [];
    } catch (e: any) {
      log.debug("Caught in OidfedRegistration.candidateKeys(): " +
                ((e && e.message) || e));
      out = [];
    }
    log.debug("Leaving OidfedRegistration.candidateKeys(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE PROOF (12.1.1.1, 12.1.1.2): a request object (`kind` 'request') or a
  // private_key_jwt client assertion (`kind` 'assertion') signed by one of
  // the RP's keys, audienced to THIS OP ALONE, issued by the RP, with a
  // `jti` and an `exp`. A request object names the RP as client_id and
  // carries no `sub`; an assertion's `sub` is the RP.
  // -------------------------------------------------------------------------
  async verifyProof(jwt: string, kind: string, keys: Json, clientId: string,
                    opId: string): Promise<Outcome> {
    const { log, config } = this.deps;
    log.debug("Entering OidfedRegistration.verifyProof(). " + kind);
    const read = EntityStatement.decode(jwt);
    if (!read.ok) {
      log.debug("Leaving OidfedRegistration.verifyProof(). Unreadable.");
      return this.refuse('STS-OIDFED-0054', 'invalid_request', 'the ' + kind +
                         ' is not a signed JWT.');
    }
    const accepted = EntityStatement.acceptedAlgorithms();
    const alg = read.header.alg;
    if (accepted.indexOf(alg) < 0) {
      log.debug("Leaving OidfedRegistration.verifyProof(). Symmetric.");
      return this.refuse('STS-OIDFED-0054', 'invalid_request', 'the ' + kind +
                         ' must be signed with an asymmetric algorithm: ' +
                         'nothing was provisioned to share a secret (12.1).');
    }
    const candidates = (await this.candidateKeys(keys))
      .filter(function (k: Json): boolean {
        return !read.header.kid || k.kid === read.header.kid;
      });
    let verified = false;
    for (let i = 0; i < candidates.length && !verified; i++) {
      try {
        stsCrypto.verifyCompactJws(jwt, candidates[i],
                                   { algorithms: [alg] });
        verified = true;
      } catch (e: any) {
        log.debug("Caught in OidfedRegistration.verifyProof(): " +
                  ((e && e.message) || e));
      }
    }
    if (!verified) {
      log.debug("Leaving OidfedRegistration.verifyProof(). Not the RP's.");
      return this.refuse('STS-OIDFED-0054', 'invalid_request', 'the ' + kind +
                         ' is not signed by a key ' + clientId + ' publishes ' +
                         'for its relying party role (12.1.1.1.2).');
    }
    const c = read.claims;
    const aud = Array.isArray(c.aud) && c.aud.length === 1 ? c.aud[0] : c.aud;
    const skew = Math.max(0, Number(config.value('oidfed.clockSkewS')));
    let problem = '';
    if (aud !== opId) {
      problem = 'aud must be ' + opId + ' and nothing else';
    } else if (c.iss !== clientId) {
      problem = 'iss must be ' + clientId;
    } else if (kind === 'request' && c.client_id !== clientId) {
      problem = 'client_id must be ' + clientId;
    } else if (kind === 'request' && c.sub !== undefined) {
      problem = 'a request object carries no sub (12.1.1.1)';
    } else if (kind === 'assertion' && c.sub !== clientId) {
      problem = 'sub must be ' + clientId;
    } else if (typeof c.jti !== 'string' || !c.jti) {
      problem = 'it has no jti';
    } else if (!Number.isFinite(c.exp) || c.exp <= this.nowSec() - skew) {
      problem = 'it has no exp, or it has passed';
    }
    if (problem) {
      log.debug("Leaving OidfedRegistration.verifyProof(). " + problem);
      return this.refuse('STS-OIDFED-0054', 'invalid_request', 'the ' + kind +
                         ': ' + problem + ' (12.1.1).');
    }
    log.debug("Leaving OidfedRegistration.verifyProof(). Verified.");
    return { ok: true, claims: c };
  }

  // The RP's resolved metadata as a registration: the federation-only members
  // taken off, the keys as resolved, and the token endpoint method checked —
  // automatic registration authenticates with a key or not at all (12.1).
  registrationOf(rp: Json, keys: Json, type: string): Outcome {
    const { log } = this.deps;
    log.debug("Entering OidfedRegistration.registrationOf(). " + type);
    const doc: Json = {};
    Object.keys(rp).forEach(function (k: string): void {
      if (FEDERATION_ONLY.indexOf(k) < 0 && k.indexOf('#') < 0) {
        doc[k] = rp[k];
      }
    });
    delete doc.jwks;
    delete doc.jwks_uri;
    if (keys.jwks) {
      doc.jwks = keys.jwks;
    } else if (keys.jwksUri) {
      doc.jwks_uri = keys.jwksUri;
    }
    const method = doc.token_endpoint_auth_method;
    if (!method) {
      doc.token_endpoint_auth_method = 'private_key_jwt';
    } else if (type === 'automatic' &&
               ASYMMETRIC_METHODS.indexOf(String(method)) < 0) {
      log.debug("Leaving OidfedRegistration.registrationOf(). A secret.");
      return this.refuse('STS-OIDFED-0055', 'invalid_client_metadata',
                         'automatic registration provisions nothing, so the ' +
                         'relying party authenticates with its key: ' +
                         ASYMMETRIC_METHODS.join(', ') + ' — not ' + method +
                         ' (12.1, 12.1.4).');
    }
    log.debug("Leaving OidfedRegistration.registrationOf().");
    return { ok: true, doc: doc };
  }

  // When the registration ends (12.3): the chain's expiry, or
  // oidfed.registrationLifetimeS from now if that comes first.
  private expiryOf(resolved: Json): number {
    const { log, config } = this.deps;
    log.debug("Entering OidfedRegistration.expiryOf().");
    const cap = this.nowSec() + Math.max(60, Number(config.value(
      'oidfed.registrationLifetimeS')));
    log.debug("Leaving OidfedRegistration.expiryOf().");
    return Math.min(Number(resolved.exp), cap);
  }

  private audited(action: string, clientId: string, summary: string,
                  errorCode?: string): void {
    const { log } = this.deps;
    log.debug("Entering OidfedRegistration.audited(). " + action);
    try {
      this.deps.audit().record({
        category: 'application', action: action, actor: clientId,
        target: clientId, outcome: errorCode ? 'refused' : 'success',
        errorCode: errorCode || '', summary: summary });
    } catch (e: any) {
      log.debug("Caught in OidfedRegistration.audited(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving OidfedRegistration.audited().");
  }

  // -------------------------------------------------------------------------
  // AUTOMATIC REGISTRATION (12.1). `proof.request` a request object, or
  // `proof.clientAssertion` a private_key_jwt (PAR only). Resolves, verifies
  // the proof, and registers; `{ ok }` or a refusal the endpoint answers
  // without redirecting.
  // -------------------------------------------------------------------------
  async automatic(req: Req, clientId: string, proof: Json): Promise<Outcome> {
    const { log, oidfed, oauth2 } = this.deps;
    log.debug("Entering OidfedRegistration.automatic(). " + clientId);
    const p = proof || {};
    const jwt = p.request ? String(p.request) : String(p.clientAssertion || '');
    const kind = p.request ? 'request' : 'assertion';
    if (!jwt) {
      this.audited('oidfed.registration-refused', clientId, 'automatic ' +
                   'registration without a proof', 'STS-OIDFED-0054');
      log.debug("Leaving OidfedRegistration.automatic(). No proof.");
      return this.refuse('STS-OIDFED-0054', 'invalid_request', clientId +
                         ' is not registered here, and an automatic ' +
                         'registration proves the relying party holds its ' +
                         'key: a signed request object, or at the PAR ' +
                         'endpoint a private_key_jwt client assertion ' +
                         '(OpenID Federation for OpenID Connect 1.1, 12.1.1).');
    }
    const header = EntityStatement.decode(jwt).header || {};
    const presented = kind === 'request' && Array.isArray(header.trust_chain)
      ? header.trust_chain : null;
    const rp = await this.resolveRp(req, clientId, presented);
    if (!rp.ok) {
      this.audited('oidfed.registration-refused', clientId, String(
        rp.description), rp.code);
      log.debug("Leaving OidfedRegistration.automatic(). Not resolved.");
      return rp;
    }
    const keys = await this.rpKeys(rp.rp, rp.resolved, clientId);
    if (!keys.ok) {
      this.audited('oidfed.registration-refused', clientId, String(
        keys.description), keys.code);
      log.debug("Leaving OidfedRegistration.automatic(). No keys.");
      return keys;
    }
    const opId = oidfed().entityId(req);
    const checked = await this.verifyProof(jwt, kind, keys, clientId, opId);
    if (!checked.ok) {
      this.audited('oidfed.registration-refused', clientId, String(
        checked.description), checked.code);
      log.debug("Leaving OidfedRegistration.automatic(). The proof.");
      return checked;
    }
    const registration = this.registrationOf(rp.rp, keys, 'automatic');
    if (!registration.ok) {
      this.audited('oidfed.registration-refused', clientId, String(
        registration.description), registration.code);
      log.debug("Leaving OidfedRegistration.automatic(). The metadata.");
      return registration;
    }
    const expiresAt = this.expiryOf(rp.resolved);
    const stored = await oauth2().registerFederatedClient(req, clientId,
      registration.doc, { type: 'automatic', expiresAt: expiresAt,
                          trustAnchor: rp.resolved.anchor });
    if (!stored.ok) {
      this.audited('oidfed.registration-refused', clientId,
                   String(stored.description), stored.code);
      log.debug("Leaving OidfedRegistration.automatic(). Refused.");
      return this.refuse(String(stored.code), String(stored.error),
                         String(stored.description));
    }
    this.audited('oidfed.registered', clientId, clientId + ' registered ' +
                 'automatically through ' + rp.resolved.anchor + ' until ' +
                 new Date(expiresAt * 1000).toISOString());
    log.debug("Leaving OidfedRegistration.automatic(). Registered.");
    return { ok: true, expiresAt: expiresAt, anchor: rp.resolved.anchor };
  }

  // -------------------------------------------------------------------------
  // EXPLICIT REGISTRATION (12.2). `contentType` and the raw `body` of the
  // POST: an Entity Configuration (application/entity-statement+jwt), or a
  // Trust Chain beginning with it (application/trust-chain+json). Answers
  // `{ ok, jwt }` — the explicit-registration-response+jwt — or a refusal in
  // section 8.9's and RFC 7591's vocabulary.
  // -------------------------------------------------------------------------
  async explicit(req: Req, contentType: string, body: string):
      Promise<Outcome> {
    const { log, oidfed, oauth2, keys } = this.deps;
    log.debug("Entering OidfedRegistration.explicit().");
    if (this.types().indexOf('explicit') < 0) {
      log.debug("Leaving OidfedRegistration.explicit(). Not offered.");
      return this.refuse('STS-OIDFED-0056', 'invalid_request', 'this realm ' +
                         'does not accept Explicit Registration ' +
                         '(oidfed.clientRegistrationTypes).', 404);
    }
    const type = String(contentType || '').split(';')[0].trim()
      .toLowerCase();
    let configuration = '';
    let chainBody: Json = null;
    if (type === 'application/entity-statement+jwt') {
      configuration = String(body || '').trim();
    } else if (type === 'application/trust-chain+json') {
      try {
        chainBody = JSON.parse(String(body || ''));
      } catch (e: any) {
        log.debug("Caught in OidfedRegistration.explicit(): " +
                  ((e && e.message) || e));
        chainBody = null;
      }
      if (!Array.isArray(chainBody) || typeof chainBody[0] !== 'string') {
        log.debug("Leaving OidfedRegistration.explicit(). Not a chain.");
        return this.refuse('STS-OIDFED-0056', 'invalid_request', 'an ' +
                           'application/trust-chain+json body is a JSON ' +
                           'array of Entity Statements (12.2.1).');
      }
      configuration = chainBody[0];
    } else {
      log.debug("Leaving OidfedRegistration.explicit(). Media type.");
      return this.refuse('STS-OIDFED-0056', 'invalid_request', 'an Explicit ' +
                         'Registration request is application/entity-' +
                         'statement+jwt or application/trust-chain+json ' +
                         '(12.2.1), not "' + type + '".');
    }
    const read = EntityStatement.decode(configuration);
    if (!read.ok || read.header.typ !== EntityStatement.TYP.ENTITY_STATEMENT ||
        read.claims.iss !== read.claims.sub ||
        !EntityStatement.isEntityId(read.claims.iss)) {
      log.debug("Leaving OidfedRegistration.explicit(). Not a " +
                "configuration.");
      return this.refuse('STS-OIDFED-0056', 'invalid_request', 'the request ' +
                         'is not the relying party\'s Entity Configuration ' +
                         '(12.2.1).');
    }
    const clientId = read.claims.iss;
    const opId = oidfed().entityId(req);
    if (!Array.isArray(read.claims.authority_hints) ||
        !read.claims.metadata || !read.claims.metadata.openid_relying_party) {
      log.debug("Leaving OidfedRegistration.explicit(). Claims missing.");
      return this.refuse('STS-OIDFED-0056', 'invalid_request', 'an Explicit ' +
                         'Registration request carries authority_hints and ' +
                         'openid_relying_party metadata (12.2.1).');
    }
    // The chain: the body's; or the request's own configuration followed by
    // the superiors' statements of its trust_chain header (12.2.2 — the
    // header establishes the PATH, and what is registered is the request
    // itself, whose `aud` names this OP); or walked from its
    // authority_hints. Validated against the realm's anchors in each case,
    // with the configuration's `aud` held to this OP.
    let presented: Json = null;
    if (chainBody) {
      presented = chainBody;
    } else if (Array.isArray(read.header.trust_chain) &&
               read.header.trust_chain.length > 1) {
      presented = [configuration].concat(read.header.trust_chain.slice(1));
    }
    const rp = await this.resolveRp(req, clientId, presented,
      presented ? undefined : configuration, opId);
    if (!rp.ok) {
      this.audited('oidfed.registration-refused', clientId, String(
        rp.description), rp.code);
      log.debug("Leaving OidfedRegistration.explicit(). Not resolved.");
      return rp;
    }
    // The peer chain, when given, must begin at THIS OP and end at the same
    // anchor (12.2.2).
    if (Array.isArray(read.header.peer_trust_chain)) {
      const peer = oidfed().chainResolver(req, true).validate(
        read.header.peer_trust_chain, oidfed().anchors(req));
      if (!peer.ok || peer.subject !== opId ||
          peer.anchor !== rp.resolved.anchor) {
        log.debug("Leaving OidfedRegistration.explicit(). The peer chain.");
        return this.refuse('STS-OIDFED-0053', 'invalid_trust_chain', 'the ' +
                           'peer_trust_chain must begin at ' + opId + ' and ' +
                           'end at ' + rp.resolved.anchor + ' (12.2.2).');
      }
    }
    const rpKeys = await this.rpKeys(rp.rp, rp.resolved, clientId);
    if (!rpKeys.ok) {
      log.debug("Leaving OidfedRegistration.explicit(). No keys.");
      return rpKeys;
    }
    const registration = this.registrationOf(rp.rp, rpKeys, 'explicit');
    if (!registration.ok) {
      log.debug("Leaving OidfedRegistration.explicit(). The metadata.");
      return registration;
    }
    const expiresAt = this.expiryOf(rp.resolved);
    const secret = SECRET_METHODS.indexOf(String(
      registration.doc.token_endpoint_auth_method)) >= 0;
    const stored = await oauth2().registerFederatedClient(req, clientId,
      registration.doc, { type: 'explicit', expiresAt: expiresAt,
                          trustAnchor: rp.resolved.anchor },
      { secret: secret });
    if (!stored.ok) {
      this.audited('oidfed.registration-refused', clientId,
                   String(stored.description), stored.code);
      log.debug("Leaving OidfedRegistration.explicit(). Refused.");
      return this.refuse(String(stored.code), String(stored.error),
                         String(stored.description));
    }
    const signer = await keys.signer();
    if (!signer) {
      log.debug("Leaving OidfedRegistration.explicit(). No key.");
      return this.refuse('STS-OIDFED-0043', 'temporarily_unavailable',
                         'this realm holds no Federation Entity Key it can ' +
                         'sign with yet.', 503);
    }
    const registered: Json = {};
    Object.keys(stored.record).forEach(function (k: string): void {
      if (stored.record[k] !== undefined && stored.record[k] !== null) {
        registered[k] = stored.record[k];
      }
    });
    const chain = rp.resolved.chain;
    const response = EntityStatement.sign({
      iss: opId, sub: clientId, aud: clientId, iat: this.nowSec(),
      exp: expiresAt, trust_anchor: rp.resolved.anchor,
      authority_hints: [chain.length > 1 ? chain[1].iss : clientId],
      jwks: read.claims.jwks,
      metadata: { openid_relying_party: registered }
    }, EntityStatement.TYP.EXPLICIT_REGISTRATION_RESPONSE, signer);
    this.audited('oidfed.registered', clientId, clientId + ' registered ' +
                 'explicitly through ' + rp.resolved.anchor + ' until ' +
                 new Date(expiresAt * 1000).toISOString());
    log.debug("Leaving OidfedRegistration.explicit(). Registered.");
    return { ok: true, jwt: response, clientId: clientId };
  }

  // -------------------------------------------------------------------------
  // THE REGISTRATIONS THAT HAVE ENDED, REMOVED (12.3). Housekeeping, not
  // correctness: `clientConfigOf()` already answers an ended one as unknown.
  // A cluster job per realm (`oidfed.registrations-expire`).
  // -------------------------------------------------------------------------
  expireRegistrations(): Json {
    const { log, applications } = this.deps;
    log.debug("Entering OidfedRegistration.expireRegistrations().");
    let removed = 0;
    applications().federatedRegistrations().forEach(function (r: Json) {
      if (r.expired) {
        const gone = applications().deleteApplication(r.identifier,
                                                      { actor: 'oidfed' });
        if (gone && gone.ok) {
          removed += 1;
        }
      }
    });
    log.debug("Leaving OidfedRegistration.expireRegistrations(). " +
              removed);
    return { removed: removed };
  }

  scheduleJobs(): void {
    const { log, scheduler } = this.deps;
    const self = this;
    log.debug("Entering OidfedRegistration.scheduleJobs().");
    const s = scheduler();
    if (s.job(EXPIRE_JOB)) {
      log.debug("Leaving OidfedRegistration.scheduleJobs(). Registered.");
      return;
    }
    s.register({
      id: EXPIRE_JOB,
      title: 'OpenID Federation registrations that ended',
      describe: 'Removes each client registered through an OpenID ' +
                'Federation Trust Chain whose registration has ended ' +
                '(12.3). Every endpoint already answers such a client as ' +
                'unknown; this only stops the entry lingering.',
      owner: 'oidfed/oidfed_registration.ts',
      kind: 'cluster', scope: 'realm', everyMs: function (): number {
        return 3600000;
      },
      manual: true,
      run: function (): Json {
        return self.expireRegistrations();
      }
    });
    log.debug("Leaving OidfedRegistration.scheduleJobs(). On the scheduler.");
  }
}

const slot = new InstanceSlot<OidfedRegistration>(
  'oidfed/oidfed_registration',
  () => new OidfedRegistration(OidfedRegistration.defaultDeps()),
  function (instance: OidfedRegistration): void {
    instance.scheduleJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  OidfedRegistration: OidfedRegistration,
  installInstance: (instance: OidfedRegistration): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  EXPIRE_JOB: EXPIRE_JOB,
  wants: slot.forward('wants'),
  automatic: slot.forward('automatic'),
  explicit: slot.forward('explicit'),
  resolveRp: slot.forward('resolveRp'),
  verifyProof: slot.forward('verifyProof'),
  expireRegistrations: slot.forward('expireRegistrations')
};
