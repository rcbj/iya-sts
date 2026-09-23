'use strict';
//
// File: oidfed_rp.ts
//
// ===========================================================================
// THIS SERVICE AS A FEDERATED RELYING PARTY (OpenID Federation for OpenID
// Connect 1.1, sections 5.1.1 and 12.1; #134, 2026-09-23).
//
// A `federation/` relationship of protocol `oidc` normally configures its OP
// by hand: the endpoints, a key (`fedJwks` / `fedJwksUri`), a client_id and
// perhaps a secret. With `fedTrustAnchor` set it configures TWO THINGS
// instead — the OP's Entity Identifier (`fedPeer`) and one of this realm's
// Trust Anchors — and everything else is DISCOVERED: the OP is resolved
// through its Trust Chain to that anchor, and its endpoints and keys are the
// `openid_provider` metadata the chain vouches for, policy applied. The
// relationship's KEY is still what trust rests on; it is the anchor's key
// now, configured on `/admin/oidfed`, and the OP's own keys are believed
// because a statement signed by it says so (`federation/CLAUDE.md`).
//
// This service then registers AUTOMATICALLY (12.1): its client_id is its
// own Entity Identifier, the authorization request is a request object
// signed by the realm's ES256 protocol key, and the token request is a
// private_key_jwt made with the same key — which the realm's Entity
// Configuration publishes BY VALUE in its `openid_relying_party` metadata,
// so an OP needs no second fetch to find it. Nothing is provisioned, so
// there is no secret to keep. An OP that offers only explicit registration
// is refused by name: sending an Entity Configuration to it would need an
// address this service dials that no administrator typed, and that is an
// argument this module does not make.
//
// WHAT IS DIALLED, AND WHY IT IS STILL THE ADMINISTRATOR'S: the walk to the
// anchor (`trust_chain.ts`'s bounds, `fetchPublished()`), then the OP's
// token endpoint and — where it publishes no `jwks` — its `jwks_uri`, both
// through `federation_http.fetchJson()` under the relationship's existing
// attributes `fedTokenUrl` and `fedJwksUri`. Those two now hold a value a
// verified chain to a configured anchor put there rather than one typed by
// hand; the list of attributes that may be dialled is unchanged.
// ===========================================================================

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import EntityStatement = require('./entity_statement');

type Json = any;
type Req = any;

// The algorithm the RP signs with: ES256, which every OpenID Federation
// implementation verifies (Connect 1.1 lists no mandatory one; the realm's
// federation key's default is the same, for the same reason).
const RP_ALG = 'ES256';

interface RpDeps {
  log: typeof helpers.log;
  baseUrlOf: (req: Req) => string;
  signingKeys: () => Json[];
  publishedKidFor: (kid: string) => string;
  signJwtAsAsync: (payload: Json, alg: string, secret: Json,
                   opts: Json) => Promise<string>;
  // Lazily: the entity, the relationship register and the federation SP.
  oidfed: () => Json;
  federation: () => Json;
  federationSp: () => Json;
  fedHttp: () => Json;
  now: () => number;
}

interface Outcome {
  ok: boolean;
  code?: string;
  why?: string;
  [key: string]: Json;
}

class OidfedRp {
  static readonly RP_ALG = RP_ALG;

  constructor(private readonly deps: RpDeps) {
    deps.log.debug("Entering OidfedRp.constructor().");
    deps.log.debug("Leaving OidfedRp.constructor().");
  }

  static defaultDeps(): RpDeps {
    helpers.log.debug("Entering OidfedRp.defaultDeps().");
    helpers.log.debug("Leaving OidfedRp.defaultDeps().");
    return {
      log: helpers.log, baseUrlOf: helpers.baseUrlOf,
      signingKeys: function (): Json[] {
        return helpers.stsKeysFor().extraKeys || [];
      },
      publishedKidFor: helpers.publishedKidFor,
      signJwtAsAsync: helpers.signJwtAsAsync,
      oidfed: function (): Json {
        return require('./oidfed');
      },
      federation: function (): Json {
        return require('../federation/federation');
      },
      federationSp: function (): Json {
        return require('../federation/federation_sp');
      },
      fedHttp: function (): Json {
        return require('../federation/federation_http');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  private refuse(code: string, why: string): Outcome {
    this.deps.log.debug("Entering OidfedRp.refuse(). " + code);
    this.deps.log.debug("Leaving OidfedRp.refuse().");
    return { ok: false, code: code, why: why };
  }

  // Is this relationship one whose OP is found through a Trust Chain?
  isFederated(record: Json): boolean {
    this.deps.log.debug("Entering OidfedRp.isFederated().");
    this.deps.log.debug("Leaving OidfedRp.isFederated().");
    return !!record && record.fedRole === 'service-provider' &&
           record.fedProtocol === 'oidc' &&
           !!String(record.fedTrustAnchor || '').trim();
  }

  // The realm's ES256 protocol key, as the JWK the RP metadata publishes.
  publicJwk(): Json {
    const { log, signingKeys, publishedKidFor } = this.deps;
    log.debug("Entering OidfedRp.publicJwk().");
    const found = signingKeys().filter(function (k: Json): boolean {
      return k.alg === RP_ALG;
    })[0];
    if (!found) {
      log.debug("Leaving OidfedRp.publicJwk(). No ES256 key.");
      return null;
    }
    const jwk = Object.assign({}, found.publicJwk, {
      kid: publishedKidFor(found.publicJwk.kid), alg: RP_ALG, use: 'sig' });
    log.debug("Leaving OidfedRp.publicJwk(). " + jwk.kid);
    return jwk;
  }

  // -------------------------------------------------------------------------
  // THE REALM'S openid_relying_party METADATA (Connect 1.1, 5.1.1), for its
  // Entity Configuration — or null where no enabled relationship trusts an
  // OP through the federation, since an entity type nothing uses would only
  // invite registrations that lead nowhere. Its redirect_uris are the
  // assertion consumer service of every such relationship.
  // -------------------------------------------------------------------------
  relyingPartyMetadata(req: Req): Json {
    const { log, federation, federationSp, baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering OidfedRp.relyingPartyMetadata().");
    const base = baseUrlOf(req);
    const records = (federation().list() || []).filter(function (r: Json) {
      return self.isFederated(r) && federation().isEnabled(r);
    });
    const jwk = this.publicJwk();
    if (!records.length || !jwk) {
      log.debug("Leaving OidfedRp.relyingPartyMetadata(). None.");
      return null;
    }
    const sp = federationSp();
    const out = {
      redirect_uris: records.map(function (r: Json): string {
        return sp.acsUrl(base, r);
      }),
      response_types: ['code'],
      grant_types: ['authorization_code'],
      application_type: 'web',
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: RP_ALG,
      request_object_signing_alg: RP_ALG,
      client_registration_types: ['automatic'],
      jwks: { keys: [jwk] }
    };
    log.debug("Leaving OidfedRp.relyingPartyMetadata(). " + records.length +
              " relationship(s).");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE RELATIONSHIP AS IT IS USED: the OP resolved through its Trust Chain
  // to `fedTrustAnchor`, and its endpoints, keys and this realm's client_id
  // put where the rest of `federation_sp.ts` reads them. `{ ok, record,
  // anchor }` or a refusal naming what failed.
  // -------------------------------------------------------------------------
  async effectiveRecord(req: Req, record: Json): Promise<Outcome> {
    const { log, oidfed, fedHttp } = this.deps;
    log.debug("Entering OidfedRp.effectiveRecord(). " + record.fedId);
    const peer = String(record.fedPeer || '');
    const anchor = String(record.fedTrustAnchor || '');
    const got = await oidfed().resolve(req, peer, [anchor], true);
    if (!got.ok) {
      log.debug("Leaving OidfedRp.effectiveRecord(). Not resolved.");
      return this.refuse('STS-FED-0148', peer + ' could not be resolved ' +
                         'to the Trust Anchor ' + anchor + ': ' + got.why);
    }
    const op = (got.resolved.metadata || {}).openid_provider;
    let problem = '';
    if (!op) {
      problem = 'it resolves with no openid_provider metadata';
    } else if (op.issuer !== peer) {
      problem = 'its issuer is ' + op.issuer + ', not its Entity ' +
                'Identifier (Connect 1.1, 5.1.2)';
    } else if (!EntityStatement.isEndpointUrl(op.authorization_endpoint) ||
               !EntityStatement.isEndpointUrl(op.token_endpoint)) {
      problem = 'it publishes no https authorization_endpoint and ' +
                'token_endpoint';
    } else if (!Array.isArray(op.client_registration_types_supported) ||
               op.client_registration_types_supported
                 .indexOf('automatic') < 0) {
      problem = 'it does not offer automatic registration, which is the ' +
                'only kind this service makes as a relying party';
    } else if (!op.jwks && !op.signed_jwks_uri && !op.jwks_uri) {
      problem = 'it publishes no keys for its OpenID Provider role';
    }
    if (problem) {
      log.debug("Leaving OidfedRp.effectiveRecord(). " + problem);
      return this.refuse('STS-FED-0149', peer + ' cannot be used as an ' +
                         'OpenID Provider here: ' + problem + '.');
    }
    let jwks = op.jwks ? JSON.stringify(op.jwks) : '';
    if (!jwks && op.signed_jwks_uri) {
      const signed = await fedHttp().fetchPublished(op.signed_jwks_uri,
        { accept: 'application/jwk-set+jwt' });
      const chain = got.resolved.chain || [];
      const verified = signed.ok && signed.status === 200
        ? EntityStatement.verify(String(signed.body || '').trim(),
            (chain[0] || {}).jwks, EntityStatement.TYP.JWK_SET)
        : { ok: false, why: 'it answered ' + signed.status };
      if (!verified.ok || verified.claims.iss !== peer) {
        log.debug("Leaving OidfedRp.effectiveRecord(). signed_jwks_uri.");
        return this.refuse('STS-FED-0149', 'the signed_jwks_uri of ' + peer +
                           ' did not yield a JWK Set it signed: ' +
                           (verified.why || 'wrong issuer'));
      }
      jwks = JSON.stringify({ keys: verified.claims.keys || [] });
    }
    const ourId = oidfed().entityId(req);
    const effective = Object.assign({}, record, {
      fedSsoUrl: String(op.authorization_endpoint),
      fedTokenUrl: String(op.token_endpoint),
      fedUserinfoUrl: String(record.fedUserinfoUrl || op.userinfo_endpoint ||
                             ''),
      fedJwks: jwks,
      fedJwksUri: jwks ? '' : String(op.jwks_uri),
      fedClientId: ourId,
      fedClientSecret: '',
      fedResponseType: 'code',
      fedTokenAuth: 'private_key_jwt',
      fedOpIssuer: String(op.issuer)
    });
    log.debug("Leaving OidfedRp.effectiveRecord(). Through " + anchor);
    return { ok: true, record: effective, anchor: anchor };
  }

  // -------------------------------------------------------------------------
  // THE AUTHORIZATION REQUEST AS A SIGNED REQUEST OBJECT (12.1.1.1): every
  // parameter inside it, `aud` the OP's Entity Identifier alone, `iss` and
  // `client_id` this realm's, no `sub`, a `jti` and an `exp`. The outer
  // query repeats what OpenID Connect requires there. No `trust_chain`
  // header: the OP resolves this realm through its own Entity Configuration,
  // and a URL carrying a whole chain is longer than many servers accept.
  // -------------------------------------------------------------------------
  async authorizationRequestUrl(effective: Json, params: URLSearchParams):
      Promise<string> {
    const { log, now, signJwtAsAsync } = this.deps;
    log.debug("Entering OidfedRp.authorizationRequestUrl().");
    const iat = Math.floor(now() / 1000);
    const claims: Json = { iss: effective.fedClientId, aud:
                           effective.fedOpIssuer, jti:
                           nodeCrypto.randomUUID(), iat: iat,
                           exp: iat + 300 };
    params.forEach(function (value: string, name: string): void {
      claims[name] = value;
    });
    // certificate-header: none — a request object is verified against the
    // key the RP's metadata publishes, through the Trust Chain; no
    // certificate path is part of that.
    const request = await signJwtAsAsync(claims, RP_ALG, null,
      { header: { typ: 'oauth-authz-req+jwt' } });
    const outer = new URLSearchParams();
    ['client_id', 'response_type', 'scope'].forEach(function (n: string) {
      if (params.get(n)) {
        outer.set(n, String(params.get(n)));
      }
    });
    outer.set('request', request);
    const at = String(effective.fedSsoUrl);
    log.debug("Leaving OidfedRp.authorizationRequestUrl().");
    return at + (at.indexOf('?') === -1 ? '?' : '&') + outer.toString();
  }

  // The private_key_jwt for the token request (RFC 7523, 12.1.1.2): `iss`
  // and `sub` this realm's client_id, `aud` the OP's Entity Identifier.
  async clientAssertion(effective: Json): Promise<string> {
    const { log, now, signJwtAsAsync } = this.deps;
    log.debug("Entering OidfedRp.clientAssertion().");
    const iat = Math.floor(now() / 1000);
    log.debug("Leaving OidfedRp.clientAssertion().");
    // certificate-header: none — verified against the key the RP metadata
    // publishes, as the request object is.
    return signJwtAsAsync({ iss: effective.fedClientId,
                            sub: effective.fedClientId,
                            aud: effective.fedOpIssuer,
                            jti: nodeCrypto.randomUUID(), iat: iat,
                            exp: iat + 300 }, RP_ALG, null, {});
  }
}

const slot = new InstanceSlot<OidfedRp>(
  'oidfed/oidfed_rp',
  () => new OidfedRp(OidfedRp.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  OidfedRp: OidfedRp,
  installInstance: (instance: OidfedRp): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  RP_ALG: RP_ALG,
  isFederated: slot.forward('isFederated'),
  publicJwk: slot.forward('publicJwk'),
  relyingPartyMetadata: slot.forward('relyingPartyMetadata'),
  effectiveRecord: slot.forward('effectiveRecord'),
  authorizationRequestUrl: slot.forward('authorizationRequestUrl'),
  clientAssertion: slot.forward('clientAssertion')
};
