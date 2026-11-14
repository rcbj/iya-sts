// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: uma_claims.ts
//
// ===========================================================================
// HOW A STRANGER BECOMES KNOWN, AND HOW AN OWNER IS ASKED (#1168 phase 5,
// #1194).
//
// **CLAIMS INTERACTION, `GET /uma/claims`** (the Grant specification's
// section 3.3.2). A client told `need_info` with `redirect_user` sends the
// requesting party here with `client_id`, `ticket`, `claims_redirect_uri`
// and `state`. The endpoint signs them in through `authn/` — the one
// sign-in, so every factor, policy and step-up the realm demands applies —
// records the session's person on the ticket as the requesting party,
// ROTATES the ticket, and returns `authorization_state=claims_submitted`,
// the new `ticket` and `state` to the `claims_redirect_uri`. That address
// must be one the client registered (`oauthClaimsRedirectUri`), matched
// exactly; an unknown client or an unregistered address is TOLD TO THE
// PERSON and never redirected to — the open-redirect rule every return
// address here keeps. A ticket that cannot be used goes back as
// `authorization_state=not_authorized`.
//
// **A PUSHED `claim_token`** (section 3.3.1), in the ID Token format only:
// an ID Token this realm issued, or one from a DECLARED assertion issuer
// (rule 3x's register, rcbj's decision 6), verified by `crypto.js` through
// the existing verifiers, audienced to the client presenting it, and naming
// a person of this realm. Anything else names nobody, and the policy's own
// missing attribute answers `need_info`. **The policy never sees a claim a
// client merely asserted**: gathered claims reach the PDP as
// `urn:sts:xacml:uma:claim:<name>` only from a verified token.
//
// **`request_submitted` AND THE OWNER'S APPROVAL** (decision 10). A
// permission whose owner's share carries the approval obligation (*Ask me
// each time*) is queued in `uma.pending` (bounded by
// `uma.maxPendingPerOwner`, living `uma.pendingLifetimeS`), the owner is
// mailed where the channel allows it, and the client is told
// `request_submitted` with a rotated ticket and an `interval`. **AN
// APPROVAL WRITES A RULE** — a time-bound share for that requesting party
// into the owner's own document (`uma_owner_policy.ts`'s `approve()`) — so
// the record of what was approved IS the policy, and the client's next poll
// is decided like any other. A refusal, or no answer in time, is
// `request_denied` at the next poll.
//
// **THE PCT** (section 3.3.3): issued when claims were gathered this time
// (the interaction's session or a pushed token), bound to the client and the
// requesting party, living `uma.pctLifetimeS`, re-issued only when the claim
// set grew.
//
// TypeScript, as a class; its wire step hands the grant this instance
// (`uma_grant.ts`'s `setClaims()`), which is what makes the grant ask the
// interaction's ticket, a claim_token and the approval queue.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import applications = require('../common/applications');
import realms = require('../common/realms');
import umaStore = require('./uma_store');
import ownerPolicy = require('./uma_owner_policy');

const { log } = helpers;

type Json = any;
type Req = import('express').Request;
type Res = import('express').Response;
type Handler = (req: Req, res: Res, next?: () => void) => unknown;

interface RouteTable {
  get(path: string, ...handlers: Handler[]): unknown;
}

const CLAIMS_PATH = '/uma/claims';
const ID_TOKEN_FORMAT =
  'http://openid.net/specs/openid-connect-core-1_0.html#IDToken';
// How often a client should poll after request_submitted, in seconds.
const POLL_INTERVAL_S = 5;
// How long an approval the owner gives holds, in seconds.
const APPROVAL_S = 86400;
// The JWT claims that are the token's machinery, never a fact about the
// requesting party a share may test.
const MACHINERY = Object.freeze(['iss', 'sub', 'aud', 'exp', 'iat', 'nbf',
  'jti', 'nonce', 'azp', 'at_hash', 'c_hash', 's_hash', 'auth_time', 'acr',
  'amr', 'sid', 'typ', 'cnf', 'client_id', 'scope']);
const CLAIM_NAME = /^[A-Za-z0-9_.:-]{1,64}$/;

interface ClaimsDeps {
  log: typeof log;
  helpers: typeof helpers;
  config: typeof config;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  applications: Json;
  realms: typeof realms;
  store: Json;
  owner: Json;
  nowSec(): number;
  loadGrant(): Json;
  loadAuthn(): Json;
  loadMail(): Json;
  loadAssertions(): Json;
  loadJwt(): Json;
}

// Whether the routes were registered in this process.
let routed = false;

/**
 * Claims interaction, claim tokens, the owner's approval and the PCT.
 */
class UmaClaims {
  static readonly CLAIMS_PATH = CLAIMS_PATH;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - everything it reads and writes through
   */
  constructor(private readonly deps: ClaimsDeps) {
    deps.log.debug("Entering UmaClaims.constructor().");
    deps.log.debug("Leaving UmaClaims.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): ClaimsDeps {
    log.debug("Entering UmaClaims.defaultDeps().");
    const lazy = function (name: string, path: string): () => Json {
      return function (): Json {
        log.debug("Entering " + name + "().");
        log.debug("Leaving " + name + "().");
        return require(path);
      };
    };
    log.debug("Leaving UmaClaims.defaultDeps().");
    return {
      log: log, helpers: helpers, config: config, errorCodes: errorCodes,
      audit: audit, applications: applications, realms: realms,
      store: umaStore, owner: ownerPolicy, nowSec: helpers.nowSec,
      loadGrant: lazy('loadGrant', './uma_grant'),
      loadAuthn: lazy('loadAuthn', '../authn/authn'),
      loadMail: lazy('loadMail', '../common/mail_uses'),
      loadAssertions: lazy('loadAssertions', '../oauth-oidc/assertion_grant'),
      loadJwt: lazy('loadJwt', '../oauth-oidc/jwt_access_token')
    };
  }

  /**
   * Whether `GET /uma/claims` answers in this process.
   *
   * @returns true once the routes are registered
   */
  static routed(): boolean {
    return routed;
  }

  // A refusal as the grant answers one.
  private static refusal(status: number, code: string, error: string,
                         description: string, extra?: Json): Json {
    log.debug("Entering UmaClaims.refusal(). " + code);
    log.debug("Leaving UmaClaims.refusal().");
    return { status: status, code: code, error: error,
             description: description, extra: extra || null };
  }

  // The facts a verified token may supply: its own claims, less the
  // machinery, each a string or a list of strings.
  static claimsFrom(claims: Json): Json {
    log.debug("Entering UmaClaims.claimsFrom().");
    const out: Json = {};
    Object.keys(claims || {}).forEach(function (name: string) {
      if (MACHINERY.indexOf(name) >= 0 || !CLAIM_NAME.test(name)) {
        return;
      }
      const value = claims[name];
      const list = (Array.isArray(value) ? value : [value])
        .filter(function (one: unknown) {
          return typeof one === 'string' || typeof one === 'number' ||
                 typeof one === 'boolean';
        }).map(String);
      if (list.length) {
        out[name] = list;
      }
    });
    log.debug("Leaving UmaClaims.claimsFrom().");
    return out;
  }

  /**
   * Verifies a pushed claim_token: an ID Token of this realm or of a
   * declared assertion issuer, audienced to the client, naming a person of
   * this realm.
   *
   * @param ctx - the grant's context (`req`, `body`, `client`)
   * @returns `{ subject, claims, issuer, acr }`, or null (logged STS-UMA-0406)
   */
  async verifyClaimToken(ctx: Json): Promise<Json> {
    const { log, helpers, errorCodes, nowSec } = this.deps;
    log.debug("Entering UmaClaims.verifyClaimToken().");
    const body = ctx.body || {};
    const token = String(body.claim_token || '');
    const format = String(body.claim_token_format || '');
    const clientId = String((ctx.client && ctx.client.client_id) || '');
    const refuse = function (why: string): null {
      log.debug("Entering refuse().");
      log.info(errorCodes.tag('STS-UMA-0406') + 'uma: a pushed claim_token ' +
               'from "' + clientId + '" names nobody: ' + why);
      log.debug("Leaving refuse().");
      return null;
    };
    if (format !== ID_TOKEN_FORMAT) {
      log.debug("Leaving UmaClaims.verifyClaimToken(). Not an ID Token.");
      return refuse('its claim_token_format is not the ID Token format');
    }
    let claims: Json = null;
    let issuer = '';
    let own = false;
    try {
      claims = helpers.verifyOwnJws(token);
      own = true;
    } catch (e) {
      log.debug("Caught in UmaClaims.verifyClaimToken(): " +
                ((e && e.message) || e));
      claims = null;
    }
    if (own) {
      const base = String(helpers.baseUrlOf(ctx.req) || '');
      const jwt = this.deps.loadJwt();
      const aud = [].concat(claims.aud || []).map(String);
      if (!jwt.isHostedIssuer(claims.iss, base) ||
          jwt.isAccessTokenType(jwt.typOf(token)) ||
          aud.indexOf(clientId) < 0 ||
          !(Number(claims.exp) > nowSec())) {
        log.debug("Leaving UmaClaims.verifyClaimToken(). Not usable.");
        return refuse('it is not a live ID Token of this realm audienced ' +
                      'to the client');
      }
      issuer = String(claims.iss);
    } else {
      let verified: Json = null;
      try {
        verified = await this.deps.loadAssertions().verify({
          assertion: token, audiences: [clientId],
          requestingClientId: clientId });
      } catch (e) {
        log.debug("Caught in UmaClaims.verifyClaimToken(): " +
                  ((e && e.message) || e));
        verified = null;
      }
      if (!verified || !verified.ok) {
        log.debug("Leaving UmaClaims.verifyClaimToken(). Not declared.");
        return refuse('it was not issued by this realm or a declared ' +
                      'assertion issuer, or it does not verify');
      }
      claims = verified.claims || {};
      issuer = String(verified.issuer || claims.iss || '');
    }
    const sub = String(claims.sub || '');
    const subject = /^urn:uuid:/i.test(sub) ? sub
      : helpers.subjectForName(sub);
    if (!subject || !helpers.nameForSubject(subject)) {
      log.debug("Leaving UmaClaims.verifyClaimToken(). Nobody here.");
      return refuse('its subject is not a person of this realm');
    }
    log.debug("Leaving UmaClaims.verifyClaimToken(). " + subject);
    return { subject: subject, claims: UmaClaims.claimsFrom(claims),
             issuer: issuer, acr: String(claims.acr || '') };
  }

  /**
   * What the grant asks before the policy: the owner's answer to a request
   * already submitted, and who the requesting party is — a pushed
   * claim_token, or the person the claims interaction recorded.
   *
   * @param ctx - the grant's context
   * @param ticket - the presented ticket's record
   * @param party - the requesting party a PCT named, or null
   * @returns `{ party, claims }`, or `{ refusal }`
   */
  async gather(ctx: Json, ticket: Json, party: Json): Promise<Json> {
    const self = this;
    const { log, store, config } = this.deps;
    log.debug("Entering UmaClaims.gather().");
    const grant = self.deps.loadGrant();
    if (ticket.pendingId) {
      const pending = store.pendingOne(String(ticket.pendingId));
      if (!pending || pending.state === 'refused') {
        const code = pending ? 'STS-UMA-0403' : 'STS-UMA-0404';
        if (pending) {
          store.deletePending(String(pending.id));
        }
        log.debug("Leaving UmaClaims.gather(). Not approved.");
        // error-code: none — STS-UMA-0403 or STS-UMA-0404, chosen above.
        return { refusal: UmaClaims.refusal(403, code, 'request_denied',
          'The resource owner did not approve the request.') };
      }
      if (pending.state !== 'approved') {
        const next = store.rotateTicket(ticket, 'submitted',
          Number(config.value('uma.ticketLifetimeS')));
        log.debug("Leaving UmaClaims.gather(). Still waiting.");
        return { refusal: UmaClaims.refusal(403, 'STS-UMA-0405',
          'request_submitted', 'The resource owner has not answered yet.',
          { ticket: next.value, interval: POLL_INTERVAL_S }) };
      }
      store.deletePending(String(pending.id));
    }
    const body = ctx.body || {};
    if (body.claim_token) {
      const pushed = await self.verifyClaimToken(ctx);
      if (pushed) {
        log.debug("Leaving UmaClaims.gather(). A claim_token.");
        return { party: grant.partyOf(pushed.subject, 'claim_token',
                   { acr: pushed.acr, claimIssuer: pushed.issuer,
                     claimIssuerDeclared: true }),
                 claims: pushed.claims };
      }
    }
    if (!party && ticket.requestingParty) {
      log.debug("Leaving UmaClaims.gather(). The interaction's person.");
      return { party: grant.partyOf(String(ticket.requestingParty),
                                    'session', { acr: ticket.acr }),
               claims: {} };
    }
    log.debug("Leaving UmaClaims.gather().");
    return { party: party, claims: {} };
  }

  /**
   * The members a need_info answer adds: the client is advised to send the
   * requesting party to the claims interaction endpoint.
   *
   * @returns `{ redirect_user: true }`
   */
  needInfoExtra(): Json {
    const { log } = this.deps;
    log.debug("Entering UmaClaims.needInfoExtra().");
    log.debug("Leaving UmaClaims.needInfoExtra().");
    return { redirect_user: true };
  }

  /**
   * Queues the permissions an owner asked to be asked about, tells the
   * owner, and answers `request_submitted` with a rotated ticket.
   *
   * @param ctx - the grant's context
   * @param ticket - the presented ticket's record
   * @param party - the requesting party
   * @param questions - `{ resourceId, scope }` awaiting approval
   * @returns the refusal to answer
   */
  submit(ctx: Json, ticket: Json, party: Json, questions: Json[]): Json {
    const self = this;
    const { log, store, config, helpers, nowSec, errorCodes } = this.deps;
    log.debug("Entering UmaClaims.submit().");
    const owner = String(ticket.owner || '');
    const most = Number(config.value('uma.maxPendingPerOwner'));
    if (store.pendingOf(owner).length >= most) {
      store.saveTicket(Object.assign(ticket, { state: 'denied' }));
      log.debug("Leaving UmaClaims.submit(). The queue is full.");
      return UmaClaims.refusal(403, 'STS-UMA-0402', 'request_denied',
        'The resource owner has too many requests waiting.');
    }
    const byResource: Json = {};
    (questions || []).forEach(function (q: Json) {
      (byResource[q.resourceId] = byResource[q.resourceId] || [])
        .push(q.scope);
    });
    const permissions = Object.keys(byResource).map(function (id: string) {
      return { resource_id: id, resource_scopes: byResource[id] };
    });
    const lifetime = Number(config.value('uma.pendingLifetimeS'));
    const clientId = String((ctx.client && ctx.client.client_id) || '');
    const pending = store.savePending({ owner: owner,
      ownerKind: ticket.ownerKind, requestingParty: party.id,
      requester: party.username, client: clientId,
      resourceServer: ticket.resourceServer, permissions: permissions,
      state: 'pending', expiresAt: nowSec() + lifetime });
    const next = store.rotateTicket(Object.assign({}, ticket,
      { pendingId: pending.id }), 'submitted',
      Number(config.value('uma.ticketLifetimeS')));
    const username = ticket.ownerKind === 'application' ? ''
      : helpers.nameForSubject(owner);
    if (username) {
      try {
        const first = store.resource(permissions[0].resource_id) || {};
        self.deps.loadMail().umaApprovalRequested(username, {
          requester: party.username, client: clientId,
          resource: String(first.name || first._id || ''),
          scopes: permissions[0].resource_scopes.join(', '),
          expiresMinutes: String(Math.round(lifetime / 60)),
          dedupKey: 'uma-approval:' + pending.id });
      } catch (e) {
        log.debug("Caught in UmaClaims.submit(): " + ((e && e.message) || e));
        log.warn(errorCodes.tag('STS-MAIL-0180') + 'uma: the approval ' +
                 'notice could not be queued: ' + ((e && e.message) || e));
      }
    }
    self.deps.audit.audit({ action: 'uma.approval.request',
      protocol: 'UMA 2.0', actor: clientId, target: owner,
      errorCode: 'STS-UMA-0405',
      summary: 'A UMA request waits for its resource owner\'s approval (' +
               permissions.length + ' resource(s)).',
      detail: { pending: pending.id, owner: owner,
                requestingParty: String(party.id || '') } });
    log.debug("Leaving UmaClaims.submit().");
    return UmaClaims.refusal(403, 'STS-UMA-0405', 'request_submitted',
      'The request waits for the resource owner\'s approval.',
      { ticket: next.value, interval: POLL_INTERVAL_S });
  }

  /**
   * A PCT for this answer: issued when claims were gathered now, and again
   * only when the set grew.
   *
   * @param ctx - the grant's context
   * @param party - the requesting party
   * @param claims - the claims the decision read
   * @param pctRow - the PCT presented, or null
   * @returns the PCT's value, or null
   */
  pctFor(ctx: Json, party: Json, claims: Json, pctRow: Json): string | null {
    const { log, store, config } = this.deps;
    log.debug("Entering UmaClaims.pctFor().");
    if (!party || ['session', 'claim_token'].indexOf(party.claimSource) < 0) {
      log.debug("Leaving UmaClaims.pctFor(). Nothing gathered now.");
      return null;
    }
    const had = Object.keys((pctRow && pctRow.claims) || {}).length;
    if (pctRow && pctRow.requestingParty === party.id &&
        Object.keys(claims || {}).length <= had) {
      log.debug("Leaving UmaClaims.pctFor(). The set did not grow.");
      return null;
    }
    const made = store.issuePct({ requestingParty: party.id,
      client: String((ctx.client && ctx.client.client_id) || ''),
      claims: claims || {}, acr: party.acr || '' },
      Number(config.value('uma.pctLifetimeS')));
    log.debug("Leaving UmaClaims.pctFor(). Issued.");
    return made.value;
  }

  // -------------------------------------------------------------------------
  // THE OWNER'S ANSWER.
  // -------------------------------------------------------------------------
  /**
   * Approves or refuses one waiting request of an owner's. An approval
   * writes a time-bound share for the requesting party into the owner's
   * document.
   *
   * @param owner - the owner's key
   * @param pendingId - the request
   * @param approve - true to approve
   * @returns `{ ok: true, pending }`, or `{ ok: false, code, why }`
   */
  answer(owner: string, pendingId: string, approve: boolean): Json {
    const { log, store, errorCodes, nowSec } = this.deps;
    log.debug("Entering UmaClaims.answer(). " + approve);
    const pending = store.pendingOne(String(pendingId || ''));
    if (!pending || String(pending.owner) !== String(owner) ||
        pending.state !== 'pending') {
      log.debug("Leaving UmaClaims.answer(). Not theirs to answer.");
      return errorCodes.mark({ ok: false, code: 'STS-UMA-0408',
        why: 'There is no such request waiting for you.' }, 'STS-UMA-0408');
    }
    if (approve) {
      const until = new Date((nowSec() + APPROVAL_S) * 1000).toISOString()
        .replace(/\.\d+Z$/, 'Z');
      const written = this.deps.owner.approve(owner, pending, until);
      if (!written.ok) {
        log.debug("Leaving UmaClaims.answer(). " + written.code);
        return written;
      }
    }
    pending.state = approve ? 'approved' : 'refused';
    store.savePending(pending);
    log.debug("Leaving UmaClaims.answer().");
    return { ok: true, pending: pending };
  }

  // -------------------------------------------------------------------------
  // THE CLAIMS INTERACTION ENDPOINT.
  // -------------------------------------------------------------------------
  // A page told to the person, never a redirect.
  private static told(res: Res, status: number, text: string): void {
    log.debug("Entering UmaClaims.told().");
    res.status(status).type('text/plain').set('Cache-Control', 'no-store')
       .send(text + '\n');
    log.debug("Leaving UmaClaims.told().");
  }

  // The client's return address with the answer's parameters.
  private static back(target: string, params: Json): string {
    log.debug("Entering UmaClaims.back().");
    const url = new URL(target);
    Object.keys(params).forEach(function (k: string) {
      if (params[k]) {
        url.searchParams.set(k, String(params[k]));
      }
    });
    log.debug("Leaving UmaClaims.back().");
    return url.toString();
  }

  /**
   * Answers `GET /uma/claims`.
   *
   * @param req - the request
   * @param res - the response
   */
  interaction(req: Req, res: Res): void {
    const self = this;
    const { log, config, errorCodes, applications, store, helpers } =
      this.deps;
    log.debug("Entering UmaClaims.interaction().");
    const q: Json = req.query || {};
    const one = function (v: unknown): string {
      return Array.isArray(v) ? '' : String(v === undefined ? '' : v);
    };
    const clientId = one(q.client_id);
    const target = one(q.claims_redirect_uri);
    const state = one(q.state);
    if (config.value('uma.enabled') !== true) {
      errorCodes.mark(res, 'STS-UMA-0401');
      UmaClaims.told(res, 501, 'User-Managed Access is turned off in this ' +
                     'realm.');
      log.debug("Leaving UmaClaims.interaction(). Off.");
      return;
    }
    let entry: Json = null;
    try {
      entry = clientId ? applications.forClientId(clientId) : null;
    } catch (e) {
      log.debug("Caught in UmaClaims.interaction(): " +
                ((e && e.message) || e));
      entry = null;
    }
    const registered: string[] = [].concat(((entry && entry.fields) || {})
      .oauthClaimsRedirectUri || []).map(String);
    if (!entry || !target || registered.indexOf(target) < 0) {
      errorCodes.mark(res, 'STS-UMA-0400');
      UmaClaims.told(res, 400, 'This request cannot be completed: the ' +
                     'application is unknown here, or the address it asked ' +
                     'to return you to is not one it registered. You have ' +
                     'not been sent anywhere.');
      log.debug("Leaving UmaClaims.interaction(). No registered address.");
      return;
    }
    const ticket = store.ticket(one(q.ticket));
    const ended = ['granted', 'denied', 'expired', 'submitted'];
    if (!ticket || ticket.rotated || ended.indexOf(ticket.state) >= 0 ||
        (ticket.client && ticket.client !== clientId)) {
      errorCodes.mark(res, ticket && ticket.client &&
                      ticket.client !== clientId ? 'STS-UMA-0409'
                                                 : 'STS-UMA-0407');
      res.set('Cache-Control', 'no-store').redirect(302, UmaClaims.back(
        target, { authorization_state: 'not_authorized', state: state }));
      log.debug("Leaving UmaClaims.interaction(). The ticket is unusable.");
      return;
    }
    const authn = self.deps.loadAuthn();
    const session = authn.sessionOf(req);
    if (!session) {
      const url = String(req.originalUrl || req.url || '');
      const at = url.indexOf('?');
      const where = authn.beginAuthentication({
        returnTo: req.path + (at < 0 ? '' : url.slice(at)),
        application: clientId, protocol: 'UMA 2.0',
        details: [{ label: 'Application', value: String(entry.name ||
                                                        clientId),
                    note: 'asks to reach a resource somebody shares, on ' +
                          'your behalf (UMA 2.0)' }] });
      log.debug("Leaving UmaClaims.interaction(). To the sign-in screen.");
      res.set('Cache-Control', 'no-store').redirect(303, where);
      return;
    }
    const username = String((session.user || {}).username || '');
    const subject = helpers.subjectForName(username);
    const next = store.rotateTicket(Object.assign({}, ticket, {
      requestingParty: subject, acr: String(session.acr || ''),
      client: clientId }), 'needs-info',
      Number(config.value('uma.ticketLifetimeS')));
    self.deps.audit.audit({ action: 'uma.claims.gathered',
      protocol: 'UMA 2.0', actor: username, target: clientId,
      summary: username + ' was signed in at the UMA claims interaction ' +
               'endpoint for "' + clientId + '".',
      detail: { client: clientId, requestingParty: subject,
                acr: String(session.acr || '') } });
    res.set('Cache-Control', 'no-store').redirect(302, UmaClaims.back(target,
      { authorization_state: 'claims_submitted', ticket: next.value,
        state: state }));
    log.debug("Leaving UmaClaims.interaction(). Back to the client.");
  }

  /**
   * Registers `GET /uma/claims`.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering UmaClaims.registerRoutes().");
    app.get(CLAIMS_PATH, function (req, res) {
      log.debug('Entering GET ' + CLAIMS_PATH + '.');
      self.interaction(req, res);
      log.debug('Leaving GET ' + CLAIMS_PATH + '.');
    });
    routed = true;
    log.debug("Leaving UmaClaims.registerRoutes().");
  }
}

const slot = new InstanceSlot<UmaClaims>(
  'uma/uma_claims',
  () => new UmaClaims(UmaClaims.defaultDeps()),
  function (instance: UmaClaims): void {
    require('./uma_grant').setClaims(instance);
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Claims interaction, claim tokens and the owner's approval (#1168 phase 5).
 * @namespace
 */
export = {
  UmaClaims: UmaClaims,
  installInstance: (instance: UmaClaims): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: (target: any): void => slot.get().registerRoutes(target),
  routed: UmaClaims.routed,
  claimsFrom: UmaClaims.claimsFrom,
  CLAIMS_PATH: CLAIMS_PATH,
  answer: slot.forward('answer'),
  gather: slot.forward('gather'),
  verifyClaimToken: slot.forward('verifyClaimToken')
};
