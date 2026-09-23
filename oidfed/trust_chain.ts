'use strict';
//
// File: trust_chain.ts
//
// ===========================================================================
// OPENID FEDERATION 1.1 SECTIONS 4, 7.3 AND 10: TRUST CHAINS, AND THE TRUST
// MARKS THEY CARRY (#132, #133, 2026-09-23).
//
// A Trust Chain is how one entity comes to trust another it has never been
// configured with: the other's Entity Configuration, the Subordinate
// Statement its superior made about it, that superior's superior's
// statement, and so on up to a Trust Anchor whose key WAS configured, out of
// band. Each statement is signed by a key the statement above it names, so a
// single pinned key at the top vouches for everything below it. This file
// VALIDATES such a chain (10.2), ASSEMBLES one by walking `authority_hints`
// upwards (10.1), resolves the subject's metadata through it (6, via
// `metadata_policy.ts`) and validates the Trust Marks an entity presents
// (7.3, 7.2.2).
//
// ---------------------------------------------------------------------------
// THE WALK DIALS URLS A CALLER NAMED, AND THIS IS THE ARGUMENT FOR IT (rcbj's
// answer 6 on #132, 2026-09-23 — the root CLAUDE.md's non-goal index).
//
// Resolving an entity fetches its Entity Configuration from its own Entity
// Identifier, then every superior it names in `authority_hints`, then each
// superior's fetch endpoint. Every one of those URLs is chosen by whoever
// published the statement — the caller's kind of URL, which this service
// otherwise refuses to fetch FROM. What makes the walk acceptable is that it
// is walking TOWARDS SOMETHING THE ADMINISTRATOR CONFIGURED: a chain that
// does not end at one of the realm's Trust Anchors is abandoned, and the walk
// is bounded so that an adversary cannot make it large:
//
//   * at most `oidfed.maxAuthorityHints` hints are followed per entity
//     (18.1's first defence — "a large count of false authority_hints");
//   * at most `oidfed.maxChainDepth` statements deep;
//   * at most `oidfed.maxFetchesPerResolution` fetches in one resolution,
//     whatever the hints and depth multiply to;
//   * a statement already fetched is never fetched again, which is also how
//     a LOOP is detected (10.1: "MUST NOT attempt to fetch Entity Statements
//     they already have obtained");
//   * every fetch goes through `federation/federation_http.ts`'s
//     `fetchPublished()` — https with the certificate verified, no redirect,
//     a body cap and a timeout, the outbound kill switch honoured, and in
//     product mode no internal address (`mode.dialsInternalAddresses()`).
//
// And nothing an UNAUTHENTICATED request asks for starts a walk: the resolve
// endpoint answers from what is already resolved (18.1's last paragraph);
// what walks is an administrator's act, the refresh job, and — branch 2 —
// an automatic registration whose client names the entity.
//
// ---------------------------------------------------------------------------
// THIS REALM'S OWN ENTITIES ARE NEVER FETCHED OVER HTTP.
//
// The default topology (rcbj's answer 1) makes every realm of this service a
// Subordinate of the default realm, so a chain from one realm to the Trust
// Anchor passes through entities that are THIS PROCESS. Dialling them would
// be dialling itself — an internal address, refused in product — and would
// depend on the public address routing back in. `deps.local(entityId)`
// answers for those in process, producing exactly the statement the endpoint
// would have served, and the chain is validated exactly as a remote one is:
// the signatures are checked, not assumed.
// ===========================================================================

import helpers = require('../common/helpers');
import EntityStatement = require('./entity_statement');
import MetadataPolicy = require('./metadata_policy');

type Json = any;

// A configured Trust Anchor: its Entity Identifier and the JWK Set that was
// configured for it out of band — the one key material a chain may end on.
interface TrustAnchor {
  entityId: string;
  jwks: Json;
}

// An entity this process answers for itself (a realm of this service). Its
// statements are signed when they are asked for, so either may be a promise.
interface LocalEntity {
  configuration(): string | Promise<string>;
  subordinateStatement(sub: string): string | null | Promise<string | null>;
}

interface Fetched {
  ok: boolean;
  status: number;
  body: string;
  contentType: string;
  why: string;
}

interface Limits {
  maxHints: number;
  maxDepth: number;
  maxFetches: number;
}

interface TrustChainDeps {
  log: Json;
  nowSec: () => number;
  skewSec: () => number;
  limits: () => Limits;
  fetch: (url: string, accept: string) => Promise<Fetched>;
  local: (entityId: string) => LocalEntity | null;
}

interface Validated {
  ok: boolean;
  code?: string;
  why?: string;
  error?: string;
  jwts?: string[];
  chain?: Json[];
  subject?: string;
  anchor?: string;
  exp?: number;
  metadata?: Json;
  policy?: Json;
}

const CODE_CHAIN_SHAPE = 'STS-OIDFED-0020';
const CODE_LINKAGE = 'STS-OIDFED-0021';
const CODE_NO_ANCHOR = 'STS-OIDFED-0022';
const CODE_HINTS = 'STS-OIDFED-0023';
const CODE_CONFIGURATION = 'STS-OIDFED-0024';
const CODE_NO_FETCH_ENDPOINT = 'STS-OIDFED-0025';
const CODE_SUBORDINATE = 'STS-OIDFED-0026';
const CODE_UNRESOLVED = 'STS-OIDFED-0027';
const CODE_BUDGET = 'STS-OIDFED-0028';
const CODE_MARK = 'STS-OIDFED-0029';
const CODE_MARK_ISSUER = 'STS-OIDFED-0030';
const CODE_DELEGATION = 'STS-OIDFED-0031';

class TrustChain {
  static readonly TYP = EntityStatement.TYP;

  constructor(private readonly deps: TrustChainDeps) {
    deps.log.debug("Entering TrustChain.constructor().");
    deps.log.debug("Leaving TrustChain.constructor().");
  }

  static defaultLog(): Json {
    helpers.log.debug("Entering TrustChain.defaultLog().");
    helpers.log.debug("Leaving TrustChain.defaultLog().");
    return helpers.log;
  }

  private refuse(code: string, why: string, error?: string): Validated {
    this.deps.log.debug("Entering TrustChain.refuse(). " + code);
    this.deps.log.debug("Leaving TrustChain.refuse().");
    return { ok: false, code: code, why: why,
             error: error || 'invalid_trust_chain' };
  }

  private anchorFor(anchors: TrustAnchor[], entityId: string):
      TrustAnchor | null {
    this.deps.log.debug("Entering TrustChain.anchorFor().");
    const hit = (anchors || []).filter(function (a: TrustAnchor): boolean {
      return a && a.entityId === entityId;
    })[0] || null;
    this.deps.log.debug("Leaving TrustChain.anchorFor(). " + !!hit);
    return hit;
  }

  // -------------------------------------------------------------------------
  // VALIDATE A TRUST CHAIN (4, 10.2). `jwts` in chain order — the subject's
  // Entity Configuration first, then the Subordinate Statements upwards,
  // then (optionally, 4) the Trust Anchor's Entity Configuration. `anchors`
  // are the configured Trust Anchors. Every check of 10.2, then the
  // constraints (6.2) and the subject's resolved metadata (6.1). Answers the
  // chain's claims, its Trust Anchor, its expiry (10.4: the least `exp`)
  // and the resolved metadata.
  // -------------------------------------------------------------------------
  validate(jwts: Json, anchors: TrustAnchor[]): Validated {
    const { log, nowSec, skewSec } = this.deps;
    log.debug("Entering TrustChain.validate().");
    if (!Array.isArray(jwts) || !jwts.length ||
        !jwts.every(function (one: Json): boolean {
          return typeof one === 'string';
        })) {
      log.debug("Leaving TrustChain.validate(). Not an array of JWTs.");
      return this.refuse(CODE_CHAIN_SHAPE, 'a Trust Chain is a non-empty ' +
                         'array of Entity Statements (4).');
    }
    const now = nowSec();
    const skew = skewSec();
    const claims: Json[] = [];
    for (let j = 0; j < jwts.length; j++) {
      const read = EntityStatement.decode(jwts[j]);
      if (!read.ok) {
        log.debug("Leaving TrustChain.validate(). Statement " + j +
                  " unreadable.");
        return this.refuse(read.code || CODE_CHAIN_SHAPE, 'statement ' + j +
                           ': ' + read.why);
      }
      if (read.header.typ !== EntityStatement.TYP.ENTITY_STATEMENT) {
        log.debug("Leaving TrustChain.validate(). Statement " + j +
                  " is not an Entity Statement.");
        return this.refuse('STS-OIDFED-0011', 'statement ' + j + ' is typed "' +
                           read.header.typ + '", not an Entity Statement.');
      }
      if (read.header.trust_chain !== undefined ||
          read.header.peer_trust_chain !== undefined) {
        log.debug("Leaving TrustChain.validate(). A chain inside a chain.");
        return this.refuse(CODE_CHAIN_SHAPE, 'statement ' + j + ' carries a ' +
                           'trust_chain header, which an Entity Statement ' +
                           'may not (4.3, 4.4).');
      }
      const valid = EntityStatement.validateClaims(read.claims,
        { nowSec: now, skewSec: skew, understood: [] });
      if (!valid.ok) {
        log.debug("Leaving TrustChain.validate(). Statement " + j +
                  " claims.");
        return this.refuse(valid.code || CODE_CHAIN_SHAPE, 'statement ' + j +
                           ': ' + valid.why);
      }
      claims.push(read.claims);
    }
    const last = claims.length - 1;
    if (claims[0].iss !== claims[0].sub) {
      log.debug("Leaving TrustChain.validate(). The first is not an Entity " +
                "Configuration.");
      return this.refuse(CODE_CHAIN_SHAPE, 'a Trust Chain begins with its ' +
                         'subject\'s Entity Configuration (iss == sub, 10.2).');
    }
    for (let j = 1; j < claims.length; j++) {
      // Only the LAST may be an Entity Configuration (the Trust Anchor's).
      if (j < last && claims[j].iss === claims[j].sub) {
        log.debug("Leaving TrustChain.validate(). A configuration mid-chain.");
        return this.refuse(CODE_CHAIN_SHAPE, 'statement ' + j + ' is an ' +
                           'Entity Configuration in the middle of a chain.');
      }
    }
    // The linkage: each statement's issuer is the next one's subject (4).
    for (let j = 0; j < last; j++) {
      if (claims[j].iss !== claims[j + 1].sub) {
        log.debug("Leaving TrustChain.validate(). Linkage at " + j + ".");
        return this.refuse(CODE_LINKAGE, 'statement ' + j + ' was issued by ' +
                           claims[j].iss + ' and the next is about ' +
                           claims[j + 1].sub + ' (10.2).');
      }
    }
    // 3.2: a Subordinate Statement's issuer is one of its subject's
    // `authority_hints`. The subject's own Entity Configuration is in the
    // chain, so it can be checked here for the first link.
    if (last >= 1 && claims[1].iss !== claims[1].sub &&
        (!Array.isArray(claims[0].authority_hints) ||
         claims[0].authority_hints.indexOf(claims[1].iss) < 0)) {
      log.debug("Leaving TrustChain.validate(). Not an authority hint.");
      return this.refuse(CODE_HINTS, claims[1].iss + ' is not among ' +
                         claims[0].sub + '\'s authority_hints (3.2).');
    }
    // THE ANCHOR: the last statement's issuer, and it must be configured.
    const anchorId = claims[last].iss;
    const anchor = this.anchorFor(anchors, anchorId);
    if (!anchor) {
      log.debug("Leaving TrustChain.validate(). Not a configured anchor.");
      return this.refuse(CODE_NO_ANCHOR, 'the chain ends at ' + anchorId +
                         ', which is not a Trust Anchor this realm is ' +
                         'configured with (10.2).', 'invalid_trust_anchor');
    }
    // THE SIGNATURES. ES[0] by its own keys; ES[j] by ES[j+1]'s; the last by
    // the CONFIGURED keys of the anchor — the one key trusted out of band.
    const typ = EntityStatement.TYP.ENTITY_STATEMENT;
    const self0 = EntityStatement.verify(jwts[0], claims[0].jwks, typ);
    if (!self0.ok) {
      log.debug("Leaving TrustChain.validate(). The subject's own " +
                "signature.");
      return this.refuse(self0.code || CODE_CHAIN_SHAPE, claims[0].sub +
                         '\'s Entity Configuration: ' + self0.why);
    }
    for (let j = 0; j < last; j++) {
      const checked = EntityStatement.verify(jwts[j], claims[j + 1].jwks, typ);
      if (!checked.ok) {
        log.debug("Leaving TrustChain.validate(). Signature at " + j + ".");
        return this.refuse(checked.code || CODE_CHAIN_SHAPE, 'statement ' + j +
                           ' against the keys statement ' + (j + 1) +
                           ' names: ' + checked.why);
      }
    }
    const top = EntityStatement.verify(jwts[last], anchor.jwks, typ);
    if (!top.ok) {
      log.debug("Leaving TrustChain.validate(). The anchor's key.");
      return this.refuse(top.code || CODE_CHAIN_SHAPE, 'the last statement ' +
                         'against ' + anchorId + '\'s configured keys: ' +
                         top.why);
    }
    const constrained = MetadataPolicy.checkConstraints(claims);
    if (!constrained.ok) {
      log.debug("Leaving TrustChain.validate(). Constraints.");
      return this.refuse(constrained.code || CODE_CHAIN_SHAPE,
                         String(constrained.why));
    }
    const resolved = MetadataPolicy.resolvedMetadata(claims);
    if (!resolved.ok) {
      log.debug("Leaving TrustChain.validate(). Metadata.");
      return this.refuse(resolved.code || CODE_CHAIN_SHAPE,
                         String(resolved.why), 'invalid_metadata');
    }
    const exp = claims.reduce(function (min: number, one: Json): number {
      return Math.min(min, Number(one.exp));
    }, Number.MAX_SAFE_INTEGER);
    log.debug("Leaving TrustChain.validate(). " + claims.length +
              " statement(s) to " + anchorId + ".");
    return { ok: true, jwts: jwts.slice(), chain: claims,
             subject: claims[0].sub, anchor: anchorId, exp: exp,
             metadata: resolved.metadata, policy: resolved.policy };
  }

  // -------------------------------------------------------------------------
  // AN ENTITY'S CONFIGURATION, VERIFIED BY ITS OWN KEYS (9, 3.2): in process
  // for this service's own realms, fetched otherwise. `seen` is the walk's
  // memory — a statement already obtained is answered from it, which is
  // both the saving and the loop detection of 10.1.
  // -------------------------------------------------------------------------
  async configurationOf(entityId: string, walk: Json): Promise<Json> {
    const { log, nowSec, skewSec } = this.deps;
    log.debug("Entering TrustChain.configurationOf(). " + entityId);
    const key = 'ec ' + entityId;
    if (walk.seen[key]) {
      log.debug("Leaving TrustChain.configurationOf(). Already obtained.");
      return walk.seen[key];
    }
    if (!EntityStatement.isEntityId(entityId)) {
      walk.seen[key] = { ok: false, code: CODE_CONFIGURATION,
        why: '"' + entityId + '" is not an Entity Identifier.' };
      log.debug("Leaving TrustChain.configurationOf(). Not an entity id.");
      return walk.seen[key];
    }
    const got = await this.obtain(EntityStatement.configurationUrlOf(entityId),
      function (local: LocalEntity): string | Promise<string> {
        return local.configuration();
      }, entityId, walk);
    if (!got.ok) {
      walk.seen[key] = got;
      log.debug("Leaving TrustChain.configurationOf(). Not obtained.");
      return got;
    }
    const verified = EntityStatement.verify(got.body,
      (EntityStatement.decode(got.body).claims || {}).jwks,
      EntityStatement.TYP.ENTITY_STATEMENT);
    let out: Json;
    if (!verified.ok) {
      out = { ok: false, code: verified.code, why: entityId + '\'s Entity ' +
              'Configuration: ' + verified.why };
    } else if (verified.claims.iss !== entityId ||
               verified.claims.sub !== entityId) {
      out = { ok: false, code: CODE_CONFIGURATION, why: 'the configuration ' +
              'published for ' + entityId + ' is about ' +
              verified.claims.sub + ', issued by ' + verified.claims.iss +
              '.' };
    } else {
      const valid = EntityStatement.validateClaims(verified.claims,
        { nowSec: nowSec(), skewSec: skewSec(), understood: [] });
      out = valid.ok ? { ok: true, jwt: got.body, claims: verified.claims }
        : { ok: false, code: valid.code, why: entityId + '\'s Entity ' +
            'Configuration: ' + valid.why };
    }
    walk.seen[key] = out;
    log.debug("Leaving TrustChain.configurationOf(). " + out.ok);
    return out;
  }

  // The Subordinate Statement a superior makes about `sub`, from the fetch
  // endpoint its (already verified) configuration names (8.1), verified by
  // the superior's keys and checked for who it is from and about.
  async subordinateStatementOf(superior: Json, sub: string,
                               walk: Json): Promise<Json> {
    const { log, nowSec, skewSec } = this.deps;
    log.debug("Entering TrustChain.subordinateStatementOf(). " +
              superior.claims.iss + " about " + sub);
    const key = 'ss ' + superior.claims.iss + ' ' + sub;
    if (walk.seen[key]) {
      log.debug("Leaving TrustChain.subordinateStatementOf(). Already " +
                "obtained.");
      return walk.seen[key];
    }
    const fe = ((superior.claims.metadata || {}).federation_entity || {});
    const endpoint = fe.federation_fetch_endpoint;
    if (!EntityStatement.isEndpointUrl(endpoint)) {
      walk.seen[key] = { ok: false, code: CODE_NO_FETCH_ENDPOINT,
        why: superior.claims.iss + ' publishes no federation_fetch_endpoint ' +
             '(5.1.1), so it vouches for nobody.' };
      log.debug("Leaving TrustChain.subordinateStatementOf(). No endpoint.");
      return walk.seen[key];
    }
    const url = new URL(endpoint);
    url.searchParams.append('sub', sub);
    const got = await this.obtain(url.toString(),
      function (local: LocalEntity): string | null | Promise<string | null> {
        return local.subordinateStatement(sub);
      }, superior.claims.iss, walk);
    let out: Json;
    if (!got.ok) {
      out = got;
    } else {
      const verified = EntityStatement.verify(got.body, superior.claims.jwks,
        EntityStatement.TYP.ENTITY_STATEMENT);
      if (!verified.ok) {
        out = { ok: false, code: verified.code, why: 'the statement ' +
                superior.claims.iss + ' made about ' + sub + ': ' +
                verified.why };
      } else if (verified.claims.iss !== superior.claims.iss ||
                 verified.claims.sub !== sub) {
        out = { ok: false, code: CODE_SUBORDINATE, why: 'asked ' +
                superior.claims.iss + ' about ' + sub + ' and was answered ' +
                'with a statement by ' + verified.claims.iss + ' about ' +
                verified.claims.sub + '.' };
      } else {
        const valid = EntityStatement.validateClaims(verified.claims,
          { nowSec: nowSec(), skewSec: skewSec(), understood: [] });
        out = valid.ok ? { ok: true, jwt: got.body, claims: verified.claims }
          : { ok: false, code: valid.code, why: 'the statement ' +
              superior.claims.iss + ' made about ' + sub + ': ' + valid.why };
      }
    }
    walk.seen[key] = out;
    log.debug("Leaving TrustChain.subordinateStatementOf(). " + out.ok);
    return out;
  }

  // One statement: in process when `owner` is this service, fetched
  // otherwise — counted against the resolution's budget either way.
  private async obtain(url: string,
                       fromLocal: (local: LocalEntity) =>
                         string | null | Promise<string | null>,
                       owner: string, walk: Json): Promise<Json> {
    const { log, local, fetch, limits } = this.deps;
    log.debug("Entering TrustChain.obtain(). " + url);
    walk.fetches += 1;
    if (walk.fetches > limits().maxFetches) {
      walk.exhausted = true;
      log.debug("Leaving TrustChain.obtain(). Over budget.");
      return { ok: false, code: CODE_BUDGET, why: 'the resolution reached ' +
               'oidfed.maxFetchesPerResolution (' + limits().maxFetches +
               ') and stopped (18.1).' };
    }
    const mine = local(owner);
    if (mine) {
      const jwt = await fromLocal(mine);
      log.debug("Leaving TrustChain.obtain(). In process: " + !!jwt);
      return jwt ? { ok: true, body: jwt }
        : { ok: false, code: CODE_SUBORDINATE, why: owner + ' (this ' +
            'service) holds no such statement.' };
    }
    const accept = 'application/entity-statement+jwt';
    const answer = await fetch(url, accept);
    if (!answer.ok || answer.status !== 200) {
      log.debug("Leaving TrustChain.obtain(). Not fetched.");
      return { ok: false, code: CODE_CONFIGURATION, why: url + ' answered ' +
               (answer.status || 'nothing') + (answer.why ? ': ' + answer.why
                                                          : '') + '.' };
    }
    const type = String(answer.contentType || '').split(';')[0].trim()
      .toLowerCase();
    if (type !== accept) {
      log.debug("Leaving TrustChain.obtain(). The media type.");
      return { ok: false, code: CODE_CONFIGURATION, why: url + ' answered ' +
               'with "' + type + '", not ' + accept + ' (8.1.2, 9.2).' };
    }
    log.debug("Leaving TrustChain.obtain(). Fetched.");
    return { ok: true, body: String(answer.body || '').trim() };
  }

  // -------------------------------------------------------------------------
  // THE WALK (10.1): every chain from `entityId` up to a configured Trust
  // Anchor, as arrays of JWTs beginning with `entityId`'s configuration and
  // ending with the anchor's. `path` is the entities already on THIS branch
  // — a hint back to one of them is a loop and is not followed.
  // -------------------------------------------------------------------------
  private async walkUp(entityId: string, anchors: TrustAnchor[],
                       path: string[], walk: Json): Promise<string[][]> {
    const { log, limits } = this.deps;
    log.debug("Entering TrustChain.walkUp(). " + entityId + ", depth " +
              path.length);
    const ec = await this.configurationOf(entityId, walk);
    if (!ec.ok) {
      walk.problems.push(ec.why);
      log.debug("Leaving TrustChain.walkUp(). No configuration.");
      return [];
    }
    if (this.anchorFor(anchors, entityId)) {
      log.debug("Leaving TrustChain.walkUp(). A Trust Anchor.");
      return [[ec.jwt]];
    }
    if (path.length + 1 >= limits().maxDepth) {
      walk.problems.push('the chain above ' + entityId + ' would be deeper ' +
                         'than oidfed.maxChainDepth (' + limits().maxDepth +
                         ').');
      log.debug("Leaving TrustChain.walkUp(). Too deep.");
      return [];
    }
    const hints: string[] = Array.isArray(ec.claims.authority_hints)
      ? ec.claims.authority_hints : [];
    const max = limits().maxHints;
    if (hints.length > max) {
      walk.problems.push(entityId + ' names ' + hints.length + ' authority ' +
                         'hints; only the first ' + max + ' are followed ' +
                         '(oidfed.maxAuthorityHints, 18.1).');
    }
    const out: string[][] = [];
    const followed = hints.slice(0, max);
    for (let h = 0; h < followed.length; h++) {
      const hint = followed[h];
      if (path.indexOf(hint) >= 0 || hint === entityId) {
        walk.problems.push('a loop at ' + hint + ' is not followed (10.1).');
        continue;
      }
      const superior = await this.configurationOf(hint, walk);
      if (!superior.ok) {
        walk.problems.push(superior.why);
        continue;
      }
      const statement = await this.subordinateStatementOf(superior, entityId,
                                                          walk);
      if (!statement.ok) {
        walk.problems.push(statement.why);
        continue;
      }
      const upper = await this.walkUp(hint, anchors,
                                      path.concat([entityId]), walk);
      // Each chain above begins with the HINT's own configuration, which the
      // statement just obtained replaces — except where the hint is the
      // anchor itself, whose configuration is the chain's last member (4).
      upper.forEach(function (chain: string[]): void {
        out.push([ec.jwt, statement.jwt].concat(chain.length === 1 ? chain
                                                          : chain.slice(1)));
      });
      if (walk.exhausted) {
        break;
      }
    }
    log.debug("Leaving TrustChain.walkUp(). " + out.length + " chain(s).");
    return out;
  }

  // -------------------------------------------------------------------------
  // RESOLVE AN ENTITY (10): walk to every configured anchor reachable,
  // validate each chain found, and choose the SHORTEST valid one (10.3's
  // "one simple rule"; a tie goes to the first anchor in the realm's list).
  // `anchors` may be narrowed by the caller (a resolve request's
  // `trust_anchor`). Answers the chosen chain, validated, or why none was.
  // -------------------------------------------------------------------------
  async resolve(entityId: string, anchors: TrustAnchor[]): Promise<Validated> {
    const { log } = this.deps;
    log.debug("Entering TrustChain.resolve(). " + entityId);
    if (!anchors || !anchors.length) {
      log.debug("Leaving TrustChain.resolve(). No anchors.");
      return this.refuse(CODE_NO_ANCHOR, 'this realm is configured with no ' +
                         'Trust Anchor, so it can trust nobody through a ' +
                         'federation.', 'invalid_trust_anchor');
    }
    const walk = { seen: {}, fetches: 0, exhausted: false,
                   problems: [] as string[] };
    const found = await this.walkUp(entityId, anchors, [], walk);
    const valid: Validated[] = [];
    const self = this;
    found.forEach(function (jwts: string[]): void {
      const checked = self.validate(jwts, anchors);
      if (checked.ok) {
        valid.push(checked);
      } else {
        walk.problems.push(String(checked.why));
      }
    });
    if (!valid.length) {
      const why = entityId + ' could not be resolved to a configured Trust ' +
        'Anchor' + (walk.problems.length ? ': ' +
                    walk.problems.slice(0, 5).join(' / ') : '.');
      log.debug("Leaving TrustChain.resolve(). Unresolved.");
      return this.refuse(walk.exhausted ? CODE_BUDGET : CODE_UNRESOLVED, why);
    }
    const order = anchors.map(function (a: TrustAnchor): string {
      return a.entityId;
    });
    valid.sort(function (a: Validated, b: Validated): number {
      return (a.chain as Json[]).length - (b.chain as Json[]).length ||
             order.indexOf(String(a.anchor)) - order.indexOf(String(b.anchor));
    });
    log.debug("Leaving TrustChain.resolve(). " + valid.length +
              " valid chain(s); " + valid[0].chain!.length + " statements to " +
              valid[0].anchor + " chosen.");
    return valid[0];
  }

  // =========================================================================
  // TRUST MARKS (7)
  // =========================================================================

  // -------------------------------------------------------------------------
  // VALIDATE A TRUST MARK DELEGATION (7.2.2) against the owner named for its
  // type in the Trust Anchor's `trust_mark_owners`.
  // -------------------------------------------------------------------------
  validateDelegation(delegation: Json, mark: Json, owner: Json): Validated {
    const { log, nowSec, skewSec } = this.deps;
    log.debug("Entering TrustChain.validateDelegation().");
    const verified = EntityStatement.verify(delegation, owner && owner.jwks,
      EntityStatement.TYP.TRUST_MARK_DELEGATION);
    if (!verified.ok) {
      log.debug("Leaving TrustChain.validateDelegation(). Not verified.");
      return this.refuse(CODE_DELEGATION, 'the delegation: ' + verified.why);
    }
    const c = verified.claims;
    let problem = '';
    if (c.sub !== mark.iss) {
      problem = 'it delegates to ' + c.sub + ', not to the mark\'s issuer ' +
                mark.iss;
    } else if (c.iss !== owner.sub) {
      problem = 'it was issued by ' + c.iss + ', not the owner ' + owner.sub;
    } else if (c.trust_mark_type !== mark.trust_mark_type) {
      problem = 'it is for the type ' + c.trust_mark_type;
    } else {
      problem = EntityStatement.timeProblem(c, nowSec(), skewSec(), true);
    }
    if (problem) {
      log.debug("Leaving TrustChain.validateDelegation(). " + problem);
      return this.refuse(CODE_DELEGATION, 'the delegation: ' + problem +
                         ' (7.2.2).');
    }
    log.debug("Leaving TrustChain.validateDelegation().");
    return { ok: true };
  }

  // -------------------------------------------------------------------------
  // VALIDATE A TRUST MARK (7.3) presented in `subject`'s configuration.
  // `anchorClaims` is the Trust Anchor's Entity Configuration (its
  // `trust_mark_issuers` and `trust_mark_owners`), `issuerJwks` the issuer's
  // Federation Entity Keys as established through its OWN chain to that
  // anchor — "the trust in the Trust Mark Issuer comes before the trust in
  // the trust mark" — which is why the caller resolves the issuer first.
  // `federationTrusted`: also require the anchor to list the type and allow
  // the issuer (8.3.2, what a resolver may return).
  // -------------------------------------------------------------------------
  validateTrustMark(markJwt: Json, subject: string, anchorClaims: Json,
                    issuerJwks: Json, federationTrusted: boolean): Validated {
    const { log, nowSec, skewSec } = this.deps;
    log.debug("Entering TrustChain.validateTrustMark(). " + subject);
    const verified = EntityStatement.verify(markJwt, issuerJwks,
      EntityStatement.TYP.TRUST_MARK);
    if (!verified.ok) {
      log.debug("Leaving TrustChain.validateTrustMark(). Not verified.");
      return this.refuse(verified.code || CODE_MARK, 'the Trust Mark: ' +
                         verified.why);
    }
    const mark = verified.claims;
    let problem = '';
    if (typeof mark.trust_mark_type !== 'string' || !mark.trust_mark_type) {
      problem = 'it names no trust_mark_type';
    } else if (!EntityStatement.isEntityId(mark.iss)) {
      problem = 'its iss is not an Entity Identifier';
    } else if (mark.sub !== subject) {
      problem = 'it was issued to ' + mark.sub + ', not ' + subject;
    } else {
      problem = EntityStatement.timeProblem(mark, nowSec(), skewSec(), true);
    }
    if (problem) {
      log.debug("Leaving TrustChain.validateTrustMark(). " + problem);
      return this.refuse(CODE_MARK, 'the Trust Mark: ' + problem + ' (7.3).');
    }
    const issuers = (anchorClaims && anchorClaims.trust_mark_issuers) || {};
    if (federationTrusted) {
      const allowed = issuers[mark.trust_mark_type];
      if (!Array.isArray(allowed) ||
          (allowed.length && allowed.indexOf(mark.iss) < 0)) {
        log.debug("Leaving TrustChain.validateTrustMark(). Issuer not " +
                  "trusted for the type.");
        return this.refuse(CODE_MARK_ISSUER, mark.iss + ' is not trusted by ' +
                           'the Trust Anchor to issue ' +
                           mark.trust_mark_type + ' (3.1.2, 7).');
      }
    }
    const owners = (anchorClaims && anchorClaims.trust_mark_owners) || {};
    const owner = owners[mark.trust_mark_type];
    if (owner) {
      if (typeof mark.delegation !== 'string') {
        log.debug("Leaving TrustChain.validateTrustMark(). No delegation.");
        return this.refuse(CODE_DELEGATION, 'the Trust Anchor names an ' +
                           'owner for ' + mark.trust_mark_type + ' and the ' +
                           'mark carries no delegation (7.3).');
      }
      const delegated = this.validateDelegation(mark.delegation, mark, owner);
      if (!delegated.ok) {
        log.debug("Leaving TrustChain.validateTrustMark(). The delegation.");
        return delegated;
      }
    }
    log.debug("Leaving TrustChain.validateTrustMark(). Valid.");
    return { ok: true, chain: [mark],
             exp: Number.isFinite(mark.exp) ? mark.exp : undefined };
  }
}

export = TrustChain;
