'use strict';
//
// File: grant_management.ts
//
// ===========================================================================
// GRANT MANAGEMENT FOR OAUTH 2.0 (#142, 2026-09-24), draft 03 of the FAPI
// working group's text (`oauth-v2-grant-management-03`).
//
// OAuth has always had a GRANT — what a person let a client do — and never a
// name for it: a client could only learn its grant was gone when a refresh
// failed. This specification names it. A client asks, in its authorization
// request, to `create` a grant, or to `merge` more into one it holds, or to
// `replace` one; the token response hands back its `grant_id`; and the Grant
// Management API (`GET` and `DELETE /oauth2/grants/{grant_id}`) lets the
// client read the grant and revoke it.
//
// rcbj's decisions (on #142, 2026-09-24): in full, with a REGISTER OF ITS OWN
// (this file); every action; the API gated by the two scopes, tied to the
// client as #110 ties this service's own scopes; a DELETE revokes the grant's
// tokens; consent records stay what says the person agreed, and the grant is
// the OAuth object over them; a console page and `/admin-api`; on in every
// mode.
//
// ---------------------------------------------------------------------------
// A GRANT IS WRITTEN WHEN ITS TOKENS ARE CLAIMED, NEVER BEFORE.
//
// Section "Lifecycle of the grant": a grant "should be considered active when
// associated tokens have been successfully claimed by the client", and one
// whose tokens were never claimed "should be deleted by the AS after a
// reasonable timeout". So nothing is written at the authorization endpoint:
// the code carries the PLAN (`planFor()` — the action, the id, the
// generation and what the grant will hold), the token endpoint checks it is
// still possible (`redemptionRefusal()`), mints, and only then writes the
// grant (`apply()`). A code nobody redeems leaves nothing behind, so there is
// no timeout to run. A CIBA request carries its plan the same way.
//
// ---------------------------------------------------------------------------
// WHAT REVOKING A GRANT REACHES, ACROSS A CLUSTER.
//
//   * **REFRESH TOKENS, ALWAYS.** Every refresh token minted under a grant
//     carries `grant_id` and `grant_gen` inside its JWE (`oauth2.ts`'s
//     `refreshToken()`), and the refresh grant asks `refreshRefusal()`: a
//     grant gone is refused, and one whose GENERATION moved on — a `merge` or
//     `replace` "shall invalidate existing refresh tokens associated with the
//     updated grant" — is refused too. The register is a persisted store, so
//     every node answers the same.
//   * **ACCESS TOKENS, AS FAR AS THIS SERVICE'S OWN RESOURCES GO** (the
//     draft's SHOULD). Every token minted under a grant is a row here, keyed
//     by its own `jti` (one key per issuance, so two nodes cannot lose each
//     other's rows), and a DELETE revokes each through `admin_stats.revoke()`,
//     the persisted revocation introspection and every resource server here
//     honour. A resource server elsewhere reading the JWT alone still accepts
//     it until it expires — the draft's own security consideration.
//
// ---------------------------------------------------------------------------
// WHAT IS NOT A GRANT MANAGEMENT REQUEST.
//
//   * A PUBLIC CLIENT: "Grant management is restricted to confidential only
//     clients" (STS-OAUTH-0666).
//   * A RESPONSE TYPE THAT RETURNS AN ACCESS TOKEN FROM THE AUTHORIZATION
//     ENDPOINT: the grant_id is returned only in a token response, and a
//     grant only exists once its tokens are claimed there (STS-OAUTH-0667).
//
// ---------------------------------------------------------------------------
// TWO READINGS WHERE THE DRAFT IS AMBIGUOUS, written down:
//
//   * **`last_updated`, not `last_updated_at`.** The grant resource's fields
//     are defined as `last_updated`, `expires_at`, `created_at` and
//     `updated_by`; one example writes `last_updated_at`. The definition is
//     what is served.
//   * **A grant EXPIRES WITH ITS LAST TOKEN** (`expires_at`): the latest
//     `exp` of anything minted under it. Past that it holds nothing a client
//     can use, and the `oauth2.grant-management-purge` job removes it — the
//     draft's "some deployments could purge a grant when all … attached to
//     the grant have expired". A `merge` extends it.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import stats = require('../common/admin_stats');
import stsCrypto = require('../common/crypto');

type Json = any;
type Req = any;
type Res = any;

const ACTIONS = Object.freeze(['create', 'merge', 'replace']);
// What `grant_management_actions_supported` lists: the three request actions
// and the API's two.
const SUPPORTED = Object.freeze(['create', 'merge', 'replace', 'query',
                                 'revoke']);
const QUERY_SCOPE = 'grant_management_query';
const REVOKE_SCOPE = 'grant_management_revoke';
const PATH = '/oauth2/grants';
const PURGE_JOB = 'oauth2.grant-management-purge';

// grant_id -> the grant (see `apply()` for its shape). PERSISTED: every node
// must answer the same grant, and a refresh refused on one node must be
// refused on all.
const grants = realms.map({ persist: 'oauth2.grants' });
// jti -> { grant, gen, kind, forget } — one row per token minted under a
// grant, so a DELETE can revoke each. TOMBSTONED, so a row the purge removed
// is not written back by a node that had not heard.
const issued = realms.map({ persist: 'oauth2.grantIssued', tombstone: true });

interface GrantManagementDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  stats: typeof stats;
  // Lazily: the audit log, the scheduler, the DPoP/Bearer check and the
  // scope policy load around this module.
  audit: () => Json;
  scheduler: () => Json;
  dpop: () => Json;
  scopePolicy: () => Json;
  baseUrlOf: (req: Req) => string;
  now: () => number;
}

interface Refusal {
  code: string;
  error: string;
  description: string;
  status?: number;
}

class GrantManagement {
  static readonly ACTIONS = ACTIONS;
  static readonly SUPPORTED = SUPPORTED;
  static readonly QUERY_SCOPE = QUERY_SCOPE;
  static readonly REVOKE_SCOPE = REVOKE_SCOPE;
  static readonly PATH = PATH;
  static readonly PURGE_JOB = PURGE_JOB;

  constructor(private readonly deps: GrantManagementDeps) {
    deps.log.debug("Entering GrantManagement.constructor().");
    deps.log.debug("Leaving GrantManagement.constructor().");
  }

  static defaultDeps(): GrantManagementDeps {
    helpers.log.debug("Entering GrantManagement.defaultDeps().");
    helpers.log.debug("Leaving GrantManagement.defaultDeps().");
    return {
      log: helpers.log, config: config, errorCodes: errorCodes, stats: stats,
      audit: function (): Json {
        return audit;
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      dpop: function (): Json {
        return require('./dpop');
      },
      scopePolicy: function (): Json {
        return require('../common/scope_policy');
      },
      baseUrlOf: helpers.baseUrlOf,
      now: function (): number {
        return Date.now();
      }
    };
  }

  private refuse(code: string, error: string, description: string,
                 status?: number): Refusal {
    this.deps.log.debug("Entering GrantManagement.refuse(). " + code);
    this.deps.log.debug("Leaving GrantManagement.refuse().");
    return { code: code, error: error, description: description,
             status: status };
  }

  // Space-separated values, each once, in the order first seen.
  static words(...lists: Json[]): string {
    helpers.log.debug("Entering GrantManagement.words().");
    const out: string[] = [];
    lists.forEach(function (list: Json): void {
      String(list || '').split(/\s+/).forEach(function (one: string): void {
        if (one && out.indexOf(one) < 0) {
          out.push(one);
        }
      });
    });
    helpers.log.debug("Leaving GrantManagement.words().");
    return out.join(' ');
  }

  // Values of two arrays, each once — by their canonical JSON, so two
  // authorization_details objects saying the same thing are one.
  static union(a: Json, b: Json): Json[] {
    helpers.log.debug("Entering GrantManagement.union().");
    const out: Json[] = [];
    const seen: Record<string, boolean> = {};
    [].concat(Array.isArray(a) ? a : [], Array.isArray(b) ? b : [])
      .forEach(function (one: Json): void {
        const key = stsCrypto.jcsCanonicalJson(one);
        if (!seen[key]) {
          seen[key] = true;
          out.push(one);
        }
      });
    helpers.log.debug("Leaving GrantManagement.union().");
    return out;
  }

  // Two OIDC Core 5.5 claims requests as one: each member's claims, the
  // later request's wording winning for a claim both name.
  static mergeClaims(a: Json, b: Json): Json {
    helpers.log.debug("Entering GrantManagement.mergeClaims().");
    if (!a && !b) {
      helpers.log.debug("Leaving GrantManagement.mergeClaims(). Neither.");
      return null;
    }
    const out: Json = {};
    [a || {}, b || {}].forEach(function (req: Json): void {
      Object.keys(req).forEach(function (member: string): void {
        if (req[member] && typeof req[member] === 'object') {
          out[member] = Object.assign({}, out[member] || {}, req[member]);
        }
      });
    });
    helpers.log.debug("Leaving GrantManagement.mergeClaims().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE REQUEST, BEFORE ANYBODY SIGNS IN: the parameters' own rules (draft
  // "Authorization Error Response"), the client being confidential, and a
  // response type that ends at the token endpoint. `opts.responseTypes` is
  // the request's list. Null, or a refusal in the authorization endpoint's
  // vocabulary. A request naming neither parameter is no business of this
  // file's.
  // ---------------------------------------------------------------------------
  requestRefusal(params: Json, opts: Json): Refusal | null {
    const { log } = this.deps;
    log.debug("Entering GrantManagement.requestRefusal().");
    const p = params || {};
    const action = String(p.grant_management_action || '');
    const grantId = String(p.grant_id || '');
    if (!action && !grantId) {
      log.debug("Leaving GrantManagement.requestRefusal(). Not asked.");
      return null;
    }
    if (!action) {
      log.debug("Leaving GrantManagement.requestRefusal(). An id alone.");
      return this.refuse('STS-OAUTH-0665', 'invalid_request', 'grant_id ' +
                         'was sent with no grant_management_action.');
    }
    if (ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving GrantManagement.requestRefusal(). Unknown action.");
      return this.refuse('STS-OAUTH-0665', 'invalid_request',
                         'grant_management_action is one of ' +
                         ACTIONS.join(', ') + '; "' + action + '" is not.');
    }
    if (action === 'create' && grantId) {
      log.debug("Leaving GrantManagement.requestRefusal(). create with an " +
                "id.");
      return this.refuse('STS-OAUTH-0665', 'invalid_request', 'a create ' +
                         'makes a new grant and takes no grant_id.');
    }
    if (action !== 'create' && !grantId) {
      log.debug("Leaving GrantManagement.requestRefusal(). No id.");
      return this.refuse('STS-OAUTH-0665', 'invalid_request', 'a ' + action +
                         ' names the grant it applies to in grant_id.');
    }
    const o = opts || {};
    if (!o.confidential) {
      log.debug("Leaving GrantManagement.requestRefusal(). Public.");
      return this.refuse('STS-OAUTH-0666', 'invalid_request', 'grant ' +
                         'management is for confidential clients only, and ' +
                         'this client authenticates with none.');
    }
    if ((o.responseTypes || []).indexOf('token') >= 0) {
      log.debug("Leaving GrantManagement.requestRefusal(). A token from " +
                "the authorization endpoint.");
      return this.refuse('STS-OAUTH-0667', 'invalid_request', 'a grant is ' +
                         'claimed at the token endpoint, and this ' +
                         'response_type returns an access token from the ' +
                         'authorization endpoint.');
    }
    if (grantId) {
      const held = grants.get(grantId);
      if (!held || held.clientId !== String(o.clientId || '')) {
        log.debug("Leaving GrantManagement.requestRefusal(). Unknown id.");
        return this.refuse('STS-OAUTH-0668', 'invalid_grant_id', 'no grant ' +
                           'of this client has that grant_id.');
      }
    }
    log.debug("Leaving GrantManagement.requestRefusal(). Allowed.");
    return null;
  }

  // ---------------------------------------------------------------------------
  // THE PLAN, once the person is known and has agreed: what the grant will
  // be when its tokens are claimed. `asked` is `{ params, clientId, sub,
  // scope, resources, authorizationDetails, claims, stillConsented }`, the
  // last a function that keeps the earlier scopes a merge may carry forward
  // (those the person has not withdrawn). `{ ok, plan }` or a refusal; `plan`
  // is null for a request that asked for no grant management.
  // ---------------------------------------------------------------------------
  planFor(asked: Json): Json {
    const { log } = this.deps;
    log.debug("Entering GrantManagement.planFor().");
    const a = asked || {};
    const p = a.params || {};
    const action = String(p.grant_management_action || '');
    if (!action) {
      log.debug("Leaving GrantManagement.planFor(). None asked.");
      return { ok: true, plan: null };
    }
    const now = this.deps.now();
    if (action === 'create') {
      const plan = {
        action: 'create', id: stsCrypto.randomToken(128), gen: 1,
        clientId: String(a.clientId), sub: String(a.sub),
        scope: String(a.scope || ''), resources: a.resources || [],
        authorizationDetails: a.authorizationDetails || null,
        claims: a.claims || null, createdAt: now
      };
      log.debug("Leaving GrantManagement.planFor(). create.");
      return { ok: true, plan: plan };
    }
    const grantId = String(p.grant_id || '');
    const held = grants.get(grantId);
    // "the logged in user doesn't match a resource owner".
    if (!held || held.clientId !== String(a.clientId) ||
        held.sub !== String(a.sub)) {
      log.debug("Leaving GrantManagement.planFor(). Not this person's.");
      return { ok: false, refusal: this.refuse('STS-OAUTH-0668',
        'invalid_grant_id', 'no grant of this client and this person has ' +
        'that grant_id.') };
    }
    let plan: Json;
    if (action === 'replace') {
      plan = {
        action: 'replace', id: grantId, gen: Number(held.gen || 1) + 1,
        clientId: held.clientId, sub: held.sub,
        scope: String(a.scope || ''), resources: a.resources || [],
        authorizationDetails: a.authorizationDetails || null,
        claims: a.claims || null, createdAt: held.createdAt
      };
    } else {
      const earlier = typeof a.stillConsented === 'function'
        ? a.stillConsented(String(held.scope || '')) : String(held.scope || '');
      const details = GrantManagement.union(held.authorizationDetails,
                                            a.authorizationDetails);
      plan = {
        action: 'merge', id: grantId, gen: Number(held.gen || 1) + 1,
        clientId: held.clientId, sub: held.sub,
        scope: GrantManagement.words(earlier, a.scope),
        resources: GrantManagement.union(held.resources, a.resources),
        authorizationDetails: details.length ? details : null,
        claims: GrantManagement.mergeClaims(held.claims, a.claims),
        createdAt: held.createdAt
      };
    }
    log.debug("Leaving GrantManagement.planFor(). " + action + ".");
    return { ok: true, plan: plan };
  }

  // At the token endpoint, just before the mint: a merge or replace whose
  // grant was revoked since the code was issued is refused. Null, or a
  // refusal in the token endpoint's vocabulary.
  redemptionRefusal(plan: Json): Refusal | null {
    const { log } = this.deps;
    log.debug("Entering GrantManagement.redemptionRefusal().");
    if (!plan || plan.action === 'create') {
      log.debug("Leaving GrantManagement.redemptionRefusal(). Nothing held.");
      return null;
    }
    const held = grants.get(String(plan.id));
    if (!held || held.clientId !== plan.clientId || held.sub !== plan.sub) {
      log.debug("Leaving GrantManagement.redemptionRefusal(). Gone.");
      return this.refuse('STS-OAUTH-0669', 'invalid_grant', 'the grant ' +
                         'this authorization was to ' + plan.action + ' was ' +
                         'revoked before its tokens were claimed.');
    }
    log.debug("Leaving GrantManagement.redemptionRefusal(). Still there.");
    return null;
  }

  // ---------------------------------------------------------------------------
  // THE GRANT WRITTEN, once its tokens were claimed. It expires with the
  // latest exp of what was just minted under it — read off the rows
  // `noteIssued()` wrote while they were minted — and a merge keeps the
  // later of that and what the grant already had.
  // ---------------------------------------------------------------------------
  apply(plan: Json): Json {
    const { log } = this.deps;
    log.debug("Entering GrantManagement.apply(). " + (plan && plan.action));
    if (!plan) {
      log.debug("Leaving GrantManagement.apply(). No plan.");
      return null;
    }
    const now = this.deps.now();
    let expiresAt = 0;
    issued.forEach(function (row: Json): void {
      if (row && row.grant === String(plan.id) &&
          Number(row.gen) === Number(plan.gen)) {
        expiresAt = Math.max(expiresAt, Number(row.exp) || 0);
      }
    });
    const before = grants.get(String(plan.id));
    const record = {
      id: String(plan.id), gen: Number(plan.gen), clientId: plan.clientId,
      sub: plan.sub, scope: plan.scope, resources: plan.resources || [],
      authorizationDetails: plan.authorizationDetails || null,
      claims: plan.claims || null,
      createdAt: Number(plan.createdAt) || now,
      updatedAt: now,
      updatedBy: plan.action === 'create' ? '' : 'client',
      expiresAt: plan.action === 'merge' && before
        ? Math.max(Number(before.expiresAt) || 0, Number(expiresAt) || 0)
        : Number(expiresAt) || 0
    };
    grants.set(record.id, record);
    if (plan.action !== 'create') {
      // THE EARLIER GENERATION'S REFRESH TOKENS ARE INVALIDATED (draft,
      // merge and replace): each one this node knows is revoked, and
      // `refreshRefusal()` refuses the rest by their generation.
      this.revokeIssued(record.id, function (row: Json): boolean {
        return row.kind === 'refresh_token' && Number(row.gen) < record.gen;
      }, 'grant ' + plan.action);
    }
    log.info('oauth2: grant ' + record.id.slice(0, 8) + '… ' +
             (plan.action === 'create' ? 'created' : plan.action + 'd') +
             ' for "' + record.clientId + '" (generation ' + record.gen +
             ', scope "' + record.scope + '").');
    log.debug("Leaving GrantManagement.apply().");
    return record;
  }

  // One token minted under a grant, for a DELETE to reach. Kept until the
  // token expires (`expSec`).
  noteIssued(grantId: string, gen: number, jti: string, kind: string,
             expSec: number): void {
    const { log } = this.deps;
    log.debug("Entering GrantManagement.noteIssued(). " + kind);
    if (!grantId || !jti) {
      log.debug("Leaving GrantManagement.noteIssued(). Nothing to note.");
      return;
    }
    const skewS = Math.max(0, Number(this.deps.config.value(
      'oauth2.clockSkewS')));
    issued.set(String(jti), { grant: String(grantId), gen: Number(gen) || 1,
                              kind: String(kind), exp: Number(expSec),
                              forget: (Number(expSec) + skewS) * 1000 });
    log.debug("Leaving GrantManagement.noteIssued().");
  }

  // The refresh grant's question: may a refresh token carrying
  // `grant_id` / `grant_gen` still be redeemed? Null, or a refusal.
  refreshRefusal(grantId: Json, gen: Json, clientId: Json): Refusal | null {
    const { log } = this.deps;
    log.debug("Entering GrantManagement.refreshRefusal().");
    if (!grantId) {
      log.debug("Leaving GrantManagement.refreshRefusal(). No grant.");
      return null;
    }
    const held = grants.get(String(grantId));
    if (!held || held.clientId !== String(clientId || '')) {
      log.debug("Leaving GrantManagement.refreshRefusal(). Revoked.");
      return this.refuse('STS-OAUTH-0670', 'invalid_grant', 'the grant ' +
                         'this refresh token was issued under has been ' +
                         'revoked.');
    }
    if (Number(gen) !== Number(held.gen)) {
      log.debug("Leaving GrantManagement.refreshRefusal(). An earlier " +
                "generation.");
      return this.refuse('STS-OAUTH-0670', 'invalid_grant', 'the grant ' +
                         'this refresh token was issued under was ' +
                         (held.updatedBy ? 'updated' : 'changed') + ' since, ' +
                         'which invalidates the refresh tokens issued ' +
                         'before (Grant Management, merge and replace).');
    }
    log.debug("Leaving GrantManagement.refreshRefusal(). Current.");
    return null;
  }

  // The grant a refresh extends: its generation, for the tokens the refresh
  // mints. Null when there is none.
  current(grantId: Json): Json {
    this.deps.log.debug("Entering GrantManagement.current().");
    const held = grantId ? grants.get(String(grantId)) : null;
    this.deps.log.debug("Leaving GrantManagement.current(). " + !!held);
    return held || null;
  }

  // Refresh tokens also move the grant's expiry out: a grant lives while
  // anything minted under it does.
  extend(grantId: Json, expSec: number): void {
    const { log } = this.deps;
    log.debug("Entering GrantManagement.extend().");
    const held = grantId ? grants.get(String(grantId)) : null;
    if (held && Number(expSec) > Number(held.expiresAt || 0)) {
      grants.set(held.id, Object.assign({}, held,
                                        { expiresAt: Number(expSec) }));
    }
    log.debug("Leaving GrantManagement.extend().");
  }

  // Revoke what this realm recorded under `grantId` that `which` selects.
  private revokeIssued(grantId: string, which: (row: Json) => boolean,
                       via: string): number {
    const { log, stats } = this.deps;
    log.debug("Entering GrantManagement.revokeIssued().");
    const jtis: string[] = [];
    issued.forEach(function (row: Json, jti: string): void {
      if (row && row.grant === grantId && which(row)) {
        jtis.push(jti);
      }
    });
    let count = 0;
    jtis.forEach(function (jti: string): void {
      if (stats.revoke(jti, via)) {
        count += 1;
      }
    });
    log.debug("Leaving GrantManagement.revokeIssued(). " + count);
    return count;
  }

  // ---------------------------------------------------------------------------
  // REVOKE A GRANT (the API's DELETE, and the console's): gone from the
  // register, so every refresh token under it is refused on every node, and
  // every token this realm recorded under it revoked. `{ ok, revoked }`, or
  // `{ ok: false }` for a grant this realm does not hold.
  // ---------------------------------------------------------------------------
  revoke(grantId: string, actor: string, via: string): Json {
    const { log } = this.deps;
    log.debug("Entering GrantManagement.revoke().");
    const held = grants.get(String(grantId));
    if (!held) {
      log.debug("Leaving GrantManagement.revoke(). Not held.");
      return { ok: false };
    }
    grants.delete(held.id);
    const revoked = this.revokeIssued(held.id, function (): boolean {
      return true;
    }, 'grant revoked (' + via + ')');
    try {
      this.deps.audit().record({
        category: via === 'client' ? 'oauth' : 'admin',
        action: 'oauth2.grant-revoked', actor: String(actor || ''),
        target: held.clientId, outcome: 'success',
        summary: 'Grant ' + held.id.slice(0, 8) + '… of "' + held.clientId +
                 '" revoked by ' + via + ' — ' + revoked + ' token(s) ' +
                 'revoked with it (realm "' + String(realms.current().id) +
                 '").' });
    } catch (e: any) {
      log.debug("Caught in GrantManagement.revoke(): " +
                ((e && e.message) || e));
    }
    log.info('oauth2: grant ' + held.id.slice(0, 8) + '… of "' +
             held.clientId + '" revoked by ' + via + '; ' + revoked +
             ' token(s) revoked with it.');
    log.debug("Leaving GrantManagement.revoke(). " + revoked);
    return { ok: true, revoked: revoked, clientId: held.clientId };
  }

  // ---------------------------------------------------------------------------
  // THE CONSOLE'S AND `/admin-api`'s ONE ACT (rule 7): `revoke-grant`, as a
  // client's DELETE does it, recorded as the administrator's. `{ ok, message,
  // revoked }` or `{ ok: false, errors }` carrying its code.
  // ---------------------------------------------------------------------------
  act(body: Json, ctx: Json): Json {
    const { log, errorCodes } = this.deps;
    const b = body || {};
    const action = String(b.action || '');
    log.debug("Entering GrantManagement.act(). " + action);
    if (action !== 'revoke-grant') {
      log.debug("Leaving GrantManagement.act(). Unknown action.");
      // error-code: none — marked on the result, the next line.
      return errorCodes.mark({ ok: false, errors: ['Unknown action "' +
        action + '". The one is: revoke-grant.'] }, 'STS-OAUTH-0673');
    }
    const grantId = String(b.grantId || b.grant_id || '').trim();
    const done = this.revoke(grantId, String((ctx && ctx.actor) || ''),
                             String((ctx && ctx.via) || 'console'));
    if (!done.ok) {
      log.debug("Leaving GrantManagement.act(). No such grant.");
      return errorCodes.mark({ ok: false, errors: ['No grant has the ' +
        'grant_id "' + grantId + '" in this realm.'] }, 'STS-OAUTH-0673');
    }
    log.debug("Leaving GrantManagement.act(). Revoked.");
    return { ok: true, revoked: done.revoked,
             message: 'The grant of "' + done.clientId + '" was revoked, ' +
                      'and ' + done.revoked + ' token(s) with it.' };
  }

  // The grant resource (draft "Query Status of a Grant").
  resourceOf(record: Json): Json {
    this.deps.log.debug("Entering GrantManagement.resourceOf().");
    const scopes: Json = { scope: String(record.scope || '') };
    if (Array.isArray(record.resources) && record.resources.length) {
      scopes.resource = record.resources.slice(0);
    }
    const out: Json = { scopes: [scopes] };
    const claims: string[] = [];
    Object.keys(record.claims || {}).forEach(function (member: string) {
      Object.keys(record.claims[member] || {}).forEach(function (name) {
        if (claims.indexOf(name) < 0) {
          claims.push(name);
        }
      });
    });
    if (claims.length) {
      out.claims = claims;
    }
    if (Array.isArray(record.authorizationDetails) &&
        record.authorizationDetails.length) {
      out.authorization_details = record.authorizationDetails;
    }
    out.created_at = Math.floor(Number(record.createdAt) / 1000);
    out.last_updated = Math.floor(Number(record.updatedAt) / 1000);
    if (Number(record.expiresAt) > 0) {
      out.expires_at = Number(record.expiresAt);
    }
    if (record.updatedBy) {
      out.updated_by = record.updatedBy;
    }
    this.deps.log.debug("Leaving GrantManagement.resourceOf().");
    return out;
  }

  // The metadata members (draft "Authorization server's metadata").
  metadata(base: string): Json {
    this.deps.log.debug("Entering GrantManagement.metadata().");
    this.deps.log.debug("Leaving GrantManagement.metadata().");
    return { grant_management_actions_supported: SUPPORTED.slice(0),
             grant_management_endpoint: base + PATH };
  }

  // What the console and `/admin-api` list: every grant in the realm, the
  // newest first, optionally one client's. Never a token.
  list(clientId?: string): Json[] {
    const { log } = this.deps;
    log.debug("Entering GrantManagement.list().");
    const out: Json[] = [];
    const self = this;
    grants.forEach(function (record: Json): void {
      if (clientId && record.clientId !== clientId) {
        return;
      }
      let tokens = 0;
      issued.forEach(function (row: Json): void {
        if (row && row.grant === record.id) {
          tokens += 1;
        }
      });
      out.push(Object.assign({ grantId: record.id, clientId: record.clientId,
                               subject: record.sub, generation: record.gen,
                               tokens: tokens },
                             self.resourceOf(record)));
    });
    out.sort(function (a: Json, b: Json): number {
      return Number(b.created_at) - Number(a.created_at);
    });
    log.debug("Leaving GrantManagement.list(). " + out.length);
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE PURGE (#49's rule: ejecting what expired is a job): rows of tokens
  // past their exp, and grants past their last token's.
  // ---------------------------------------------------------------------------
  purge(): Json {
    const { log, now } = this.deps;
    log.debug("Entering GrantManagement.purge().");
    const at = now();
    const rows: string[] = [];
    issued.forEach(function (row: Json, jti: string): void {
      if (!row || Number(row.forget) <= at) {
        rows.push(jti);
      }
    });
    rows.forEach(function (jti: string): void {
      issued.delete(jti);
    });
    const skewS = Math.max(0, Number(this.deps.config.value(
      'oauth2.clockSkewS')));
    const gone: string[] = [];
    grants.forEach(function (record: Json, id: string): void {
      if (Number(record.expiresAt) > 0 &&
          (Number(record.expiresAt) + skewS) * 1000 <= at) {
        gone.push(id);
      }
    });
    gone.forEach(function (id: string): void {
      grants.delete(id);
    });
    log.debug("Leaving GrantManagement.purge(). " + rows.length + " rows, " +
              gone.length + " grants.");
    return { summary: rows.length + ' token row(s) and ' + gone.length +
             ' expired grant(s) removed' };
  }

  scheduleJobs(): void {
    const { log, scheduler } = this.deps;
    const self = this;
    log.debug("Entering GrantManagement.scheduleJobs().");
    const s = scheduler();
    if (s.job(PURGE_JOB)) {
      log.debug("Leaving GrantManagement.scheduleJobs(). Registered.");
      return;
    }
    s.register({
      id: PURGE_JOB,
      title: 'Grant Management: expired grants',
      describe: 'Removes each OAuth grant whose last token has expired, and ' +
                'the record of each token minted under a grant once it ' +
                'expires (#142).',
      owner: 'oauth-oidc/grant_management.ts',
      kind: 'cluster', scope: 'realm', everyMs: function (): number {
        return 3600000;
      },
      manual: true,
      run: function (): Json {
        return self.purge();
      }
    });
    log.debug("Leaving GrantManagement.scheduleJobs(). On the scheduler.");
  }

  // ===========================================================================
  // THE GRANT MANAGEMENT API: GET and DELETE /oauth2/grants/{grant_id}.
  // ===========================================================================

  // An RFC 6750 error, with the challenge a 401 or 403 carries.
  private apiError(res: Res, scheme: string, status: number, error: string,
                   description: string, extra?: string): void {
    const { log } = this.deps;
    log.debug("Entering GrantManagement.apiError(). " + status);
    if (status === 401 || status === 403) {
      res.set('WWW-Authenticate', (scheme === 'dpop' ? 'DPoP' : 'Bearer') +
        ' error="' + error + '", error_description="' +
        description.replace(/[^\x20-\x7E]/g, '').replace(/"/g, "'") + '"' +
        (extra || ''));
    }
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify({ error: error, error_description: description }));
    log.debug("Leaving GrantManagement.apiError().");
  }

  // One API call: the token checked, then the grant, then the act.
  handle(req: Req, res: Res): void {
    const { log, errorCodes, stats } = this.deps;
    log.debug("Entering GrantManagement.handle(). " + req.method);
    res.set('Cache-Control', 'no-store');
    const presented = this.deps.dpop().presentedAccessToken(req, res,
      'the grant management endpoint');
    if (!presented) {
      log.debug("Leaving GrantManagement.handle(). No usable token.");
      return;
    }
    const scheme = String(presented.scheme || 'bearer');
    const claims = presented.claims || {};
    // A token revoked BY THE REVOCATION OF THE GRANT IN THE PATH, asking
    // about that grant, is told the grant is gone (section 6.6's 404) rather
    // than that it is unauthorised. Section 6.6 says the AS SHOULD revoke the
    // access tokens under a grant, and the token a client revoked with is one
    // of them — so the query a client makes next, to see the revocation
    // took, would otherwise meet a 401 that says nothing about the grant.
    // The OpenID conformance suite's query-and-revoke asks exactly that
    // (#176). It answers nothing but "not found" about the one grant the
    // token was minted under, and only once that grant no longer exists; a
    // token revoked for any other reason, or asking about any other grant,
    // is refused as before.
    const grantInPath = String((req.params || {}).grantId || '');
    const mintedUnder = claims.jti ? issued.get(String(claims.jti)) : null;
    if (presented.verified && claims.typ === 'Bearer' &&
        stats.isRevoked(claims.jti) && mintedUnder &&
        mintedUnder.grant === grantInPath && !grants.get(grantInPath)) {
      errorCodes.mark(res, 'STS-OAUTH-0673');
      this.apiError(res, scheme, 404, 'not_found', 'no grant has that ' +
                    'grant_id.');
      log.debug("Leaving GrantManagement.handle(). Revoked with its grant.");
      return;
    }
    if (!presented.verified || claims.typ !== 'Bearer' ||
        stats.isRevoked(claims.jti)) {
      errorCodes.mark(res, 'STS-OAUTH-0671');
      this.apiError(res, scheme, 401, 'invalid_token', 'the grant ' +
                    'management endpoint needs an access token this ' +
                    'service issued, unrevoked.');
      log.debug("Leaving GrantManagement.handle(). The token.");
      return;
    }
    const wanted = req.method === 'DELETE' ? REVOKE_SCOPE : QUERY_SCOPE;
    const clientId = String(claims.client_id || '');
    const scopes = String(claims.scope || '').split(/\s+/);
    // #110: this service's own protected scope, asked again on every call,
    // so a client whose declaration was removed is cut off at once.
    if (scopes.indexOf(wanted) < 0 ||
        !this.deps.scopePolicy().declares(clientId, wanted)) {
      errorCodes.mark(res, 'STS-OAUTH-0672');
      this.apiError(res, scheme, 403, 'insufficient_scope', 'this call ' +
                    'needs an access token with the ' + wanted + ' scope, ' +
                    'issued to a client that declares it.',
                    ', scope="' + wanted + '"');
      log.debug("Leaving GrantManagement.handle(). The scope.");
      return;
    }
    const grantId = String((req.params || {}).grantId || '');
    const held = grants.get(grantId);
    if (!held) {
      errorCodes.mark(res, 'STS-OAUTH-0673');
      this.apiError(res, scheme, 404, 'not_found', 'no grant has that ' +
                    'grant_id.');
      log.debug("Leaving GrantManagement.handle(). Unknown.");
      return;
    }
    if (held.clientId !== clientId) {
      errorCodes.mark(res, 'STS-OAUTH-0672');
      this.apiError(res, scheme, 403, 'insufficient_scope', 'that grant ' +
                    'belongs to another client.');
      log.debug("Leaving GrantManagement.handle(). Another client's.");
      return;
    }
    if (req.method === 'DELETE') {
      this.revoke(grantId, clientId, 'client');
      res.status(204).end();
      log.debug("Leaving GrantManagement.handle(). Revoked.");
      return;
    }
    res.status(200).type('application/json')
       .send(JSON.stringify(this.resourceOf(held)));
    log.debug("Leaving GrantManagement.handle(). Answered.");
  }

  registerRoutes(app: Json): void {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering GrantManagement.registerRoutes().");
    const route = function (req: Req, res: Res): void {
      log.debug("Entering the grant management endpoint.");
      try {
        self.handle(req, res);
      } catch (e: any) {
        log.error(errorCodes.tag('STS-OAUTH-0674') + 'oauth2: the grant ' +
                  'management endpoint failed: ' + ((e && e.stack) || e));
        if (!res.headersSent) {
          errorCodes.mark(res, 'STS-OAUTH-0674');
          res.status(500).type('application/json')
             .send(JSON.stringify({ error: 'server_error' }));
        }
      }
      log.debug("Leaving the grant management endpoint.");
    };
    app.get(PATH + '/:grantId', route);
    app.delete(PATH + '/:grantId', route);
    log.debug("Leaving GrantManagement.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GrantManagement>(
  'oauth-oidc/grant_management',
  () => new GrantManagement(GrantManagement.defaultDeps()),
  function (instance: GrantManagement): void {
    instance.scheduleJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  GrantManagement: GrantManagement,
  installInstance: (instance: GrantManagement): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ACTIONS: ACTIONS,
  SUPPORTED: SUPPORTED,
  QUERY_SCOPE: QUERY_SCOPE,
  REVOKE_SCOPE: REVOKE_SCOPE,
  PATH: PATH,
  PURGE_JOB: PURGE_JOB,
  registerRoutes: slot.forward('registerRoutes'),
  requestRefusal: slot.forward('requestRefusal'),
  planFor: slot.forward('planFor'),
  redemptionRefusal: slot.forward('redemptionRefusal'),
  apply: slot.forward('apply'),
  noteIssued: slot.forward('noteIssued'),
  refreshRefusal: slot.forward('refreshRefusal'),
  current: slot.forward('current'),
  extend: slot.forward('extend'),
  revoke: slot.forward('revoke'),
  resourceOf: slot.forward('resourceOf'),
  metadata: slot.forward('metadata'),
  list: slot.forward('list'),
  act: slot.forward('act'),
  purge: slot.forward('purge')
};
