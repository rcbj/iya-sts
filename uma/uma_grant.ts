// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: uma_grant.ts
//
// ===========================================================================
// THE `urn:ietf:params:oauth:grant-type:uma-ticket` GRANT (#1168 phase 4,
// #1193): what `oauth2.ts`'s token endpoint hands over through
// `common/uma_gate.ts`, and the two other doors that slot carries —
// introspection with a protection API token, and a PCT's revocation.
//
// PROTOCOL FIRST, then policy (3bz's line). The ticket must be found,
// unspent — a CLAIM across the cluster (#46), so two nodes cannot both
// redeem it — within its life, presented by the client that presented it
// first (or by anybody the first time), and an RPT presented for upgrade
// must be this client's, this requesting party's and the same resource
// server's; otherwise `invalid_grant`, audited. Section 3.3.4 is as written:
// the requested scopes of a resource are the ticket's, plus those `scope`
// names that the resource was registered with; a `scope` value matching no
// resource in the ticket is `invalid_scope`.
//
// THEN EVERY (resource, scope) IS ASKED OF `uma_pep.ts`, and the answers are
// read together — rcbj's decisions 3 and 6:
//
//   * any FAULT → `server_error` (500): nobody decided;
//   * else any NEED → `need_info` (403) with `required_claims` naming each
//     missing attribute and a rotated ticket — preferred over a refusal,
//     because a requesting party who is not known yet is asked first;
//   * else the PERMITTED subset: an RPT when it is every permission, or
//     when `uma.partialRpt` is on (the default) and it is not empty;
//     `request_denied` (403) otherwise.
//
// A permission whose owner asked to be asked each time (the approval
// obligation) is not issued here; phase 5 queues it (`request_submitted`).
//
// THE RPT is minted through the endpoint's own `issue()` — the one funnel
// (`tokenSet()`), so the issuance gate's `issue-access-token` (the fourth
// layer), the client's role, device, risk and transfer rules, the sender
// constraint, the status list and `admin_stats`' register all apply. RFC
// 9068, `aud` the resource server, NO `scope`, a `permissions` claim
// (`resource_id`, `resource_scopes`), and `authorization_details` of the
// resource's type where the resource server declares it, so a resource
// server that reads RFC 9396 reads an RPT unchanged. No refresh token unless
// `uma.rptRefreshToken`; a life no longer than `uma.rptLifetimeS`. Every
// permission is indexed in `uma.rpts`, which is how a withdrawn share finds
// the tokens it reaches (decision 11).
//
// UPGRADE: with `rpt`, the old token's permissions go through the same
// layers again, at stage `upgrade`; those that pass are added, the answer
// says `upgraded: true`, and the old RPT is revoked. Nothing is carried
// forward undecided.
//
// INTROSPECTION with a PAT (Federated Authorization section 5): the PAT
// authenticates the resource server, and the answer is RFC 7662's with
// `permissions` and WITHOUT `scope` — for an RPT issued for THAT resource
// server; any other token is `{ active: false }`, as a token not intended
// for the caller is everywhere here.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import applications = require('../common/applications');
import realms = require('../common/realms');
import umaGate = require('../common/uma_gate');
import umaStore = require('./uma_store');
import umaPep = require('./uma_pep');
import umaPat = require('./uma_pat');

const { log } = helpers;

type Json = any;

const ID_TOKEN_FORMAT =
  'http://openid.net/specs/openid-connect-core-1_0.html#IDToken';

interface GrantDeps {
  log: typeof log;
  helpers: typeof helpers;
  config: typeof config;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  applications: Json;
  realms: typeof realms;
  gate: Json;
  store: Json;
  pep: Json;
  pat: Json;
  nowSec(): number;
  loadDirectory(): Json;
  loadOpaque(): Json;
  // Phase 5's hooks, filled by `uma_claims.ts`: the requesting party a
  // pushed claim_token names, and the queue an approval waits in.
  claims: Json;
}

/**
 * The UMA grant, and the introspection and revocation the gate carries.
 */
class UmaGrant {
  static readonly ID_TOKEN_FORMAT = ID_TOKEN_FORMAT;

  /**
   * Builds the grant over its dependencies.
   *
   * @param deps - everything the grant reads and writes through
   */
  constructor(private readonly deps: GrantDeps) {
    deps.log.debug("Entering UmaGrant.constructor().");
    deps.log.debug("Leaving UmaGrant.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): GrantDeps {
    log.debug("Entering UmaGrant.defaultDeps().");
    log.debug("Leaving UmaGrant.defaultDeps().");
    return {
      log: log, helpers: helpers, config: config, errorCodes: errorCodes,
      audit: audit, applications: applications, realms: realms,
      gate: umaGate, store: umaStore, pep: umaPep, pat: umaPat,
      nowSec: helpers.nowSec,
      loadDirectory: function (): Json {
        log.debug("Entering loadDirectory().");
        log.debug("Leaving loadDirectory().");
        return require('../ldap/ldap_server');
      },
      loadOpaque: function (): Json {
        log.debug("Entering loadOpaque().");
        log.debug("Leaving loadOpaque().");
        return require('../oauth-oidc/opaque_access_token');
      },
      claims: null
    };
  }

  /**
   * Fills phase 5's hooks.
   *
   * @param claims - `uma_claims.ts`'s instance, or null
   */
  setClaims(claims: Json): void {
    const { log } = this.deps;
    log.debug("Entering UmaGrant.setClaims().");
    this.deps.claims = claims;
    log.debug("Leaving UmaGrant.setClaims().");
  }

  /**
   * Whether the grant is performed in the ambient realm.
   *
   * @returns `uma.enabled`
   */
  offered(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering UmaGrant.offered().");
    log.debug("Leaving UmaGrant.offered().");
    return config.value('uma.enabled') === true;
  }

  // A refusal of the grant: the endpoint marks the code and answers it.
  static refusal(status: number, code: string, error: string,
                 description: string, extra?: Json): Json {
    log.debug("Entering UmaGrant.refusal(). " + code);
    log.debug("Leaving UmaGrant.refusal().");
    return { status: status, code: code, error: error,
             description: description, extra: extra || null };
  }

  /**
   * Whether a client registered the UMA grant type.
   *
   * @param clientId - the client
   * @returns true when its declared grant types name it
   */
  clientDeclaresGrant(clientId: string): boolean {
    const { log, applications } = this.deps;
    log.debug("Entering UmaGrant.clientDeclaresGrant().");
    let out = false;
    try {
      // The client's DECLARED flows (`oauthGrantType`, RFC 7591's
      // `grant_types`), the list the token endpoint itself reads.
      const flows = applications.declaredFlowsOf(clientId);
      out = !!flows && (flows.grant_types || [])
        .indexOf(umaGate.GRANT_TYPE) >= 0;
    } catch (e) {
      log.debug("Caught in UmaGrant.clientDeclaresGrant(): " +
                ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving UmaGrant.clientDeclaresGrant(). " + out);
    return out;
  }

  /**
   * The requesting party a subject names, as the facts carry it: their
   * subject, kind, direct groups (normalised DNs) and how they became known.
   *
   * @param subject - their `urn:uuid:` subject
   * @param source - session, claim_token or pct
   * @param extra - `acr`, `claimIssuer`, `claimIssuerDeclared`
   * @returns the requesting party, or null when the subject is nobody here
   */
  partyOf(subject: string, source: string, extra?: Json): Json {
    const { log, helpers } = this.deps;
    log.debug("Entering UmaGrant.partyOf().");
    const username = subject ? helpers.nameForSubject(subject) : '';
    if (!username) {
      log.debug("Leaving UmaGrant.partyOf(). Nobody.");
      return null;
    }
    let groups: string[] = [];
    try {
      const directory = this.deps.loadDirectory();
      groups = (directory.groupsOfUser(username).groups || [])
        .map(function (row: Json) {
          return String(directory.normalizeDn(String(row.dn || '')));
        }).filter(Boolean);
    } catch (e) {
      log.debug("Caught in UmaGrant.partyOf(): " + ((e && e.message) || e));
      groups = [];
    }
    const given = extra || {};
    log.debug("Leaving UmaGrant.partyOf(). " + username);
    return { id: subject, kind: 'user', known: true, username: username,
             claimSource: source, claimIssuer: given.claimIssuer || '',
             claimIssuerDeclared: given.claimIssuerDeclared !== false,
             acr: given.acr || '', groups: groups };
  }

  // The jti and exp of a token this realm minted, JWT or opaque handle.
  private claimsOf(token: string): Json {
    const { log, helpers } = this.deps;
    log.debug("Entering UmaGrant.claimsOf().");
    try {
      if (String(token).indexOf('.') >= 0) {
        const out = helpers.verifyOwnJws(String(token));
        log.debug("Leaving UmaGrant.claimsOf(). A JWT.");
        return out;
      }
      const found = this.deps.loadOpaque().lookup(String(token));
      log.debug("Leaving UmaGrant.claimsOf(). A handle.");
      return found && found.kind === 'active' ? found.claims : null;
    } catch (e) {
      log.debug("Caught in UmaGrant.claimsOf(): " + ((e && e.message) || e));
      log.debug("Leaving UmaGrant.claimsOf(). Nothing.");
      return null;
    }
  }

  // The audiences an RPT for a resource server carries: its declared
  // `oauthAudience`, else its client_id, else its identifier.
  private audienceOf(resourceServer: string): string[] {
    const { log, applications } = this.deps;
    log.debug("Entering UmaGrant.audienceOf().");
    let out: string[] = [];
    try {
      const entry = applications.get(resourceServer);
      const fields = (entry && entry.fields) || {};
      out = [].concat(fields.oauthAudience || []).map(String).filter(Boolean);
      if (!out.length) {
        out = [].concat(fields.oauthClientId || []).map(String)
          .filter(Boolean).slice(0, 1);
      }
    } catch (e) {
      log.debug("Caught in UmaGrant.audienceOf(): " + ((e && e.message) || e));
      out = [];
    }
    log.debug("Leaving UmaGrant.audienceOf().");
    return out.length ? out : [resourceServer];
  }

  // The `authorization_details` types a resource server declares.
  private declaredTypes(resourceServer: string): string[] {
    const { log, applications } = this.deps;
    log.debug("Entering UmaGrant.declaredTypes().");
    const out: string[] = [];
    try {
      const entry = applications.get(resourceServer);
      [].concat(((entry && entry.fields) || {})
        .oauthAuthorizationDetailsType || []).forEach(function (v: Json) {
          try {
            const parsed = typeof v === 'string' ? JSON.parse(v) : v;
            if (parsed && parsed.type) {
              out.push(String(parsed.type));
            }
          } catch (e) {
            log.debug("Caught in UmaGrant.declaredTypes(): " +
                      ((e && e.message) || e));
          }
        });
    } catch (e) {
      log.debug("Caught in UmaGrant.declaredTypes(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving UmaGrant.declaredTypes(). " + out.length);
    return out;
  }

  // Section 3.3.4: each resource's requested scopes, or an invalid_scope.
  static requested(permissions: Json[], scopeParam: string,
                   resourceOf: (id: string) => Json): Json {
    log.debug("Entering UmaGrant.requested().");
    const asked = String(scopeParam || '').split(/\s+/).filter(Boolean);
    const used: string[] = [];
    const out = (permissions || []).map(function (p: Json) {
      const row = resourceOf(String(p.resource_id)) || {};
      const registered: string[] = row.resource_scopes || [];
      const scopes = (p.resource_scopes || []).slice();
      asked.forEach(function (s: string) {
        if (registered.indexOf(s) >= 0) {
          used.push(s);
          if (scopes.indexOf(s) < 0) {
            scopes.push(s);
          }
        }
      });
      return { resource_id: String(p.resource_id), resource_scopes: scopes };
    });
    const stray = asked.filter(function (s: string) {
      return used.indexOf(s) < 0;
    });
    log.debug("Leaving UmaGrant.requested(). " + stray.length + " stray.");
    return { permissions: out, stray: stray };
  }

  // A row of the grant's own audit record.
  private recordGrant(kind: string, ctx: Json, ticket: Json, code: string,
                      summary: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering UmaGrant.recordGrant(). " + kind);
    audit.audit({
      action: 'uma.grant', protocol: 'UMA 2.0',
      actor: String((ctx.client && ctx.client.client_id) || ''),
      target: String((ticket && ticket.resourceServer) || ''),
      outcome: kind === 'issued' ? 'success' : 'refused',
      errorCode: code || undefined,
      summary: summary,
      detail: { outcome: kind, owner: String((ticket && ticket.owner) || ''),
                resourceServer: String((ticket && ticket.resourceServer) ||
                                       '') } });
    log.debug("Leaving UmaGrant.recordGrant().");
  }

  /**
   * The grant: a ticket, the requesting party, the questions, the RPT.
   *
   * @param ctx - `body`, `client`, `req`, `dpopJkt`, `base`, `issue(opts)`
   *   (the endpoint's funnel) and `person(username)` (the endpoint's user)
   * @returns `{ body }`, or a refusal
   */
  async grant(ctx: Json): Promise<Json> {
    const self = this;
    const { log, store, config, pep, nowSec } = this.deps;
    log.debug("Entering UmaGrant.grant().");
    const body = ctx.body || {};
    const clientId = String((ctx.client && ctx.client.client_id) || '');
    const ticketValue = String(body.ticket || '');
    if (!ticketValue) {
      log.debug("Leaving UmaGrant.grant(). No ticket.");
      return UmaGrant.refusal(400, 'STS-UMA-0201', 'invalid_request',
        'The UMA grant takes the permission ticket the resource server ' +
        'handed the client, as ticket.');
    }
    const ticket = store.ticket(ticketValue);
    const ended = ['granted', 'denied', 'expired', 'needs-info',
                   'submitted'];
    if (!ticket || ticket.rotated || ended.indexOf(ticket.state) >= 0) {
      self.recordGrant('refused', ctx, ticket, 'STS-UMA-0201',
                       'A UMA ticket that is unknown, expired or ended ' +
                       'was presented.');
      log.debug("Leaving UmaGrant.grant(). No such live ticket.");
      return UmaGrant.refusal(400, 'STS-UMA-0201', 'invalid_grant',
        'That permission ticket is unknown, expired or already used.');
    }
    if (ticket.client && ticket.client !== clientId) {
      self.recordGrant('refused', ctx, ticket, 'STS-UMA-0203',
                       'A UMA ticket was presented by a client other than ' +
                       'the one that presented it first.');
      log.debug("Leaving UmaGrant.grant(). Another client.");
      return UmaGrant.refusal(400, 'STS-UMA-0203', 'invalid_grant',
        'That permission ticket was presented by another client.');
    }
    const ageS = Math.max(0, nowSec() - (Number(ticket.issuedAt) || 0));
    const spent = await store.spend('ticket', ticket.key,
      Math.max(1, (Number(ticket.expiresAt) || 0) - nowSec()),
      'STS-UMA-0202');
    if (!spent.ok) {
      self.recordGrant('refused', ctx, ticket, spent.errorCode,
                       'A UMA ticket already spent was presented again.');
      log.debug("Leaving UmaGrant.grant(). Spent.");
      // error-code: none — spend()'s code, STS-UMA-0202 or STS-UMA-0001.
      return UmaGrant.refusal(400, spent.errorCode, 'invalid_grant',
        'That permission ticket has already been used.');
    }
    ticket.client = clientId;
    ticket.state = 'presented';
    const presented = store.saveTicket(ticket);

    // SECTION 3.3.4.
    const asked = UmaGrant.requested(presented.permissions, body.scope,
      function (id: string): Json {
        return store.resource(id);
      });
    if (asked.stray.length) {
      store.saveTicket(Object.assign(presented, { state: 'denied' }));
      log.debug("Leaving UmaGrant.grant(). A stray scope.");
      return UmaGrant.refusal(400, 'STS-UMA-0205', 'invalid_scope',
        'At least one scope names no scope of a resource in the ticket.');
    }

    // THE REQUESTING PARTY: a PCT, phase 5's claims, or nobody yet.
    let party: Json = null;
    let pctRow: Json = null;
    if (body.pct) {
      pctRow = store.pct(String(body.pct));
      if (!pctRow || pctRow.client !== clientId) {
        store.saveTicket(Object.assign(presented, { state: 'denied' }));
        log.debug("Leaving UmaGrant.grant(). A PCT not this client's.");
        return UmaGrant.refusal(400, 'STS-UMA-0206', 'invalid_grant',
          'That persisted claims token is unknown, expired or another ' +
          'client\'s.');
      }
      party = self.partyOf(String(pctRow.requestingParty), 'pct',
                           { acr: pctRow.acr });
    }
    let gathered: Json = { claims: {}, party: null };
    if (self.deps.claims) {
      gathered = await self.deps.claims.gather(ctx, presented, party);
      if (gathered.refusal) {
        store.saveTicket(Object.assign(presented, { state: 'denied' }));
        log.debug("Leaving UmaGrant.grant(). The claims refused.");
        return gathered.refusal;
      }
      party = gathered.party || party;
    }
    const claims = Object.assign({}, (pctRow && pctRow.claims) || {},
                                 gathered.claims || {});
    if (party) {
      party.isOwner = String(party.id) === String(presented.owner);
    }

    // AN UPGRADE: the old RPT, this client's, this party's, this RS's.
    let old: Json = null;
    if (body.rpt) {
      const oldClaims = self.claimsOf(String(body.rpt));
      old = oldClaims && oldClaims.jti ? store.rpt(String(oldClaims.jti))
                                       : null;
      if (!old || old.client !== clientId ||
          old.resourceServer !== presented.resourceServer ||
          (party && old.requestingParty !== party.id) ||
          (Number(old.exp) > 0 && Number(old.exp) <= nowSec())) {
        store.saveTicket(Object.assign(presented, { state: 'denied' }));
        self.recordGrant('refused', ctx, presented, 'STS-UMA-0204',
                         'An RPT presented for upgrade is not this ' +
                         'client\'s, this requesting party\'s, or this ' +
                         'resource server\'s.');
        log.debug("Leaving UmaGrant.grant(). Not an RPT to upgrade.");
        return UmaGrant.refusal(400, 'STS-UMA-0204', 'invalid_grant',
          'That RPT cannot be upgraded with this ticket.');
      }
    }

    // EVERY (resource, scope), through the layers.
    const questions: Json[] = [];
    asked.permissions.forEach(function (p: Json) {
      p.resource_scopes.forEach(function (s: string) {
        questions.push({ resourceId: p.resource_id, scope: s,
                         stage: 'assess' });
      });
    });
    if (old) {
      (old.permissions || []).forEach(function (p: Json) {
        (p.resource_scopes || []).forEach(function (s: string) {
          if (!questions.some(function (q: Json) {
            return q.resourceId === p.resource_id && q.scope === s;
          })) {
            questions.push({ resourceId: String(p.resource_id), scope: s,
                             stage: 'upgrade' });
          }
        });
      });
    }
    const declares = self.clientDeclaresGrant(clientId);
    const verdicts = questions.map(function (q: Json) {
      const resource = store.resource(q.resourceId);
      if (!resource || resource.owner !== presented.owner) {
        return { q: q, v: { outcome: 'refuse', layer: 'protocol',
                            code: 'STS-UMA-0215', approval: false,
                            missing: [], why: 'the resource is gone' } };
      }
      return { q: q, v: pep.decide({
        resource: resource, scope: q.scope,
        requestingParty: party || { known: false },
        clientId: clientId, clientGrantDeclared: declares,
        claims: claims, ticketAgeS: ageS, rptPresented: !!old,
        stage: q.stage }) };
    });
    const faults = verdicts.filter(function (x: Json) {
      return x.v.outcome === 'fault';
    });
    if (faults.length) {
      store.saveTicket(Object.assign(presented, { state: 'denied' }));
      self.recordGrant('fault', ctx, presented, faults[0].v.code,
                       'A UMA permission could not be decided: ' +
                       faults[0].v.why + '.');
      log.debug("Leaving UmaGrant.grant(). A fault.");
      // error-code: none — the PEP's fault code, STS-UMA-0208/0211/0213.
      return UmaGrant.refusal(500, faults[0].v.code, 'server_error',
        'A permission could not be decided.');
    }
    const needs = verdicts.filter(function (x: Json) {
      return x.v.outcome === 'need';
    });
    if (needs.length) {
      const next = store.rotateTicket(presented, 'needs-info',
        Number(config.value('uma.ticketLifetimeS')));
      const missing: string[] = [];
      needs.forEach(function (x: Json) {
        x.v.missing.forEach(function (m: string) {
          if (missing.indexOf(m) < 0) {
            missing.push(m);
          }
        });
      });
      const issuer = String(self.deps.helpers.baseUrlOf(ctx.req) || '');
      const extra: Json = {
        ticket: next.value,
        required_claims: missing.map(function (m: string) {
          return { name: m, friendly_name: m,
                   claim_token_format: [ID_TOKEN_FORMAT], issuer: [issuer] };
        })
      };
      if (self.deps.claims) {
        Object.assign(extra, self.deps.claims.needInfoExtra(ctx));
      }
      self.recordGrant('need_info', ctx, presented, 'STS-UMA-0209',
                       'A UMA request needs claims about the requesting ' +
                       'party (' + missing.join(', ') + ').');
      log.debug("Leaving UmaGrant.grant(). need_info.");
      return UmaGrant.refusal(403, 'STS-UMA-0209', 'need_info',
        'The authorization server needs claims about the requesting party.',
        extra);
    }
    const awaiting = verdicts.filter(function (x: Json) {
      return x.v.outcome === 'permit' && x.v.approval;
    });
    if (awaiting.length && self.deps.claims) {
      const submitted = self.deps.claims.submit(ctx, presented, party,
        awaiting.map(function (x: Json) {
          return x.q;
        }));
      if (submitted) {
        log.debug("Leaving UmaGrant.grant(). request_submitted.");
        return submitted;
      }
    }
    if (awaiting.length) {
      // No claims module, or it did not queue them: these are not issued.
      self.deps.log.info(self.deps.errorCodes.tag('STS-UMA-0216') + 'uma: ' +
                         awaiting.length + ' permission(s) need the ' +
                         'owner\'s approval and were not issued.');
    }
    const granted = verdicts.filter(function (x: Json) {
      return x.v.outcome === 'permit' && !x.v.approval;
    });
    const all = granted.length === verdicts.length;
    const partial = config.value('uma.partialRpt') !== false;
    if (!granted.length || (!all && !partial)) {
      store.saveTicket(Object.assign(presented, { state: 'denied' }));
      self.recordGrant('denied', ctx, presented, 'STS-UMA-0210',
                       'A UMA request was denied: ' + verdicts.length +
                       ' permission(s) asked, ' + granted.length +
                       ' granted.');
      log.debug("Leaving UmaGrant.grant(). request_denied.");
      return UmaGrant.refusal(403, 'STS-UMA-0210', 'request_denied',
        'The request is denied.');
    }

    // THE RPT, through the endpoint's funnel.
    const byResource: Json = {};
    granted.forEach(function (x: Json) {
      (byResource[x.q.resourceId] = byResource[x.q.resourceId] || [])
        .push(x.q.scope);
    });
    const permissions = Object.keys(byResource).map(function (id: string) {
      return { resource_id: id, resource_scopes: byResource[id] };
    });
    const types = self.declaredTypes(presented.resourceServer);
    const details = permissions.map(function (p: Json) {
      const row = store.resource(p.resource_id) || {};
      return row.type && types.indexOf(row.type) >= 0
        ? { type: row.type, identifier: p.resource_id,
            actions: p.resource_scopes } : null;
    }).filter(Boolean);
    const extraClaims: Json = { permissions: permissions };
    if (details.length) {
      extraClaims.authorization_details = details;
    }
    let tokens: Json;
    try {
      tokens = await ctx.issue({
        jkt: ctx.dpopJkt, user: ctx.person(party.username),
        client_id: clientId, scope: '',
        withRefresh: config.value('uma.rptRefreshToken') === true,
        audience: self.audienceOf(presented.resourceServer),
        assertionClaims: extraClaims,
        lifetimeCapS: Number(config.value('uma.rptLifetimeS')),
        acr: party.acr || undefined,
        grant: umaGate.GRANT_TYPE });
    } catch (e) {
      if (e && e.name === 'IssuanceRefused') {
        store.saveTicket(Object.assign(presented, { state: 'denied' }));
        self.recordGrant('denied', ctx, presented, 'STS-UMA-0217',
                         'The issuance policy refused the RPT: ' +
                         String(e.message || '') + '.');
        log.debug("Leaving UmaGrant.grant(). The issuance gate refused.");
        return UmaGrant.refusal(403, 'STS-UMA-0217', 'request_denied',
          'The request is denied.');
      }
      log.debug("Leaving UmaGrant.grant(). The funnel threw.");
      throw e;
    }
    const minted = self.claimsOf(String(tokens.access_token || '')) || {};
    const owners: string[] = [];
    permissions.forEach(function (p: Json) {
      const row = store.resource(p.resource_id) || {};
      if (row.owner && owners.indexOf(row.owner) < 0) {
        owners.push(String(row.owner));
      }
    });
    store.saveRpt({ jti: String(minted.jti || ''), permissions: permissions,
                    resourceServer: presented.resourceServer, owners: owners,
                    requestingParty: party.id, client: clientId,
                    exp: Number(minted.exp) || 0,
                    upgradedFrom: old ? old.jti : '' });
    if (old) {
      store.revokeRpts([old], 'a UMA RPT upgraded');
      tokens.upgraded = true;
    }
    if (self.deps.claims) {
      const pct = self.deps.claims.pctFor(ctx, party, claims, pctRow);
      if (pct) {
        tokens.pct = pct;
      }
    }
    store.saveTicket(Object.assign(presented, { state: 'granted' }));
    self.recordGrant('issued', ctx, presented, '',
                     'An RPT was issued with ' + permissions.length +
                     ' permission(s)' + (all ? '' : ' (a partial RPT)') +
                     (old ? ', upgrading ' + old.jti : '') + '.');
    log.debug("Leaving UmaGrant.grant(). Issued.");
    return { body: tokens };
  }

  /**
   * An RPT's permissions for the resource server it was issued for, when
   * that resource server introspected it with its own client credentials
   * (#1196, rcbj 2026-10-30). Keycloak's resource server
   * (keycloak-authz-client) introspects an RPT that way rather than with its
   * PAT; the answer is the PAT door's, for the same resource server alone.
   *
   * @param answer - the introspection answer, active
   * @param clientId - the client that authenticated
   * @returns the permissions, or null for any other token or caller
   */
  permissionsFor(answer: Json, clientId: string): Json {
    const { log, store, applications, nowSec } = this.deps;
    log.debug("Entering UmaGrant.permissionsFor().");
    const row = answer && answer.active === true && answer.jti
      ? store.rpt(String(answer.jti)) : null;
    const registered = row && clientId
      ? applications.forClientId(String(clientId)) : null;
    if (!row || !registered ||
        String(registered.identifier || '') !== String(row.resourceServer) ||
        (Number(row.exp) > 0 && Number(row.exp) <= nowSec())) {
      log.debug("Leaving UmaGrant.permissionsFor(). Not its RPT.");
      return null;
    }
    log.debug("Leaving UmaGrant.permissionsFor().");
    return (row.permissions || []).map(function (p: Json) {
      return { resource_id: p.resource_id,
               resource_scopes: (p.resource_scopes || []).slice(),
               exp: Number(row.exp) || undefined };
    });
  }

  /**
   * An introspection presented with a PAT, or undefined for any other.
   *
   * @param ctx - `req`, `res`, `token` and the endpoint's `introspectionOf`
   * @returns the answer, null when a refusal was written, or undefined
   */
  introspect(ctx: Json): Json {
    const { log, store, pat, nowSec } = this.deps;
    log.debug("Entering UmaGrant.introspect().");
    const presented = pat.presented(ctx.req);
    if (!presented.token) {
      log.debug("Leaving UmaGrant.introspect(). No PAT.");
      return undefined;
    }
    const caller = pat.authenticate(ctx.req, ctx.res);
    if (!caller) {
      log.debug("Leaving UmaGrant.introspect(). The PAT was refused.");
      return null;
    }
    const answer = ctx.introspectionOf(String(ctx.token || ''));
    const row = answer && answer.active === true && answer.jti
      ? store.rpt(String(answer.jti)) : null;
    if (!row || row.resourceServer !== caller.resourceServer ||
        (Number(row.exp) > 0 && Number(row.exp) <= nowSec())) {
      log.debug("Leaving UmaGrant.introspect(). Not this RS's RPT.");
      return { active: false };
    }
    const out = Object.assign({}, answer);
    delete out.scope;
    out.permissions = (row.permissions || []).map(function (p: Json) {
      return { resource_id: p.resource_id,
               resource_scopes: (p.resource_scopes || []).slice(),
               exp: Number(row.exp) || undefined };
    });
    log.debug("Leaving UmaGrant.introspect(). An RPT.");
    return out;
  }

  /**
   * A PCT's revocation (RFC 7009, `token_type_hint=pct`).
   *
   * @param token - the token presented
   * @param clientId - the caller
   * @param identified - whether the caller authenticated
   * @returns `{ found: false }`, or `{ found: true, ok }`
   */
  revokePct(token: string, clientId: string, identified: boolean): Json {
    const { log, store } = this.deps;
    log.debug("Entering UmaGrant.revokePct().");
    const row = store.pct(String(token || ''));
    if (!row) {
      log.debug("Leaving UmaGrant.revokePct(). No PCT.");
      return { found: false };
    }
    if (identified && row.client !== clientId) {
      log.debug("Leaving UmaGrant.revokePct(). Another client's.");
      return { found: true, ok: false };
    }
    store.deletePct(String(token));
    log.debug("Leaving UmaGrant.revokePct(). Revoked.");
    return { found: true, ok: true };
  }

  /**
   * Fills `common/uma_gate.ts`'s slot with this instance.
   */
  installHandler(): void {
    const self = this;
    const { log, gate } = this.deps;
    log.debug("Entering UmaGrant.installHandler().");
    gate.setHandler({
      offered: function (): boolean {
        return self.offered();
      },
      grant: function (ctx: Json): Promise<Json> {
        return self.grant(ctx);
      },
      introspect: function (ctx: Json): Json {
        return self.introspect(ctx);
      },
      revokePct: function (token: string, clientId: string,
                           identified: boolean): Json {
        return self.revokePct(token, clientId, identified);
      },
      permissionsFor: function (answer: Json, clientId: string): Json {
        return self.permissionsFor(answer, clientId);
      }
    });
    log.debug("Leaving UmaGrant.installHandler().");
  }
}

const slot = new InstanceSlot<UmaGrant>(
  'uma/uma_grant',
  () => new UmaGrant(UmaGrant.defaultDeps()),
  function (instance: UmaGrant): void {
    instance.installHandler();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The UMA 2.0 grant (#1168 phase 4).
 * @namespace
 */
export = {
  UmaGrant: UmaGrant,
  installInstance: (instance: UmaGrant): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ID_TOKEN_FORMAT: ID_TOKEN_FORMAT,
  requested: UmaGrant.requested,
  grant: slot.forward('grant'),
  introspect: slot.forward('introspect'),
  revokePct: slot.forward('revokePct'),
  partyOf: slot.forward('partyOf'),
  setClaims: slot.forward('setClaims')
};
