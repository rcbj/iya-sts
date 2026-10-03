// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_approval.ts
//
// ===========================================================================
// WHO APPROVES A GNAP GRANT, AND HOW STRONGLY THEY SIGNED IN (#432 phase 6,
// 2026-10-03).
//
// Two things the approval page could not do until phase 6, in one library
// beside the page rather than in it (`gnap_interact.ts` is edited by phase
// 5 as well, so what phase 6 adds there is two calls into this file):
//
// **STEP-UP (rule 3an).** The access-type catalogue's `acr` reaches the
// issuance policy, whose verdict carries the acr values each right needs
// (`xacml_templates.ts`, `gnap-type-acr`); `gnap_rights.ts` keeps them per
// right on the grant's `requirement`. Before the approval page is drawn the
// person's sign-on session is held to EVERY value the requested rights need
// — not RFC 9470's preference list, where any one answers: a page approving
// two rights of two types approves both, so it must meet both. A session
// that does not is sent to sign in again ONCE, with what `step_up.ts`'s
// `screenDemandFor()` says the screen must demand — the sign-in service then
// offers what the realm's authentication policy (rule 3bd, `authn_policy.ts`)
// allows as a second factor, so a realm's choice of factors is honoured
// without a second reading of it here. Not met on the way back, the request
// is answered `request_denied` (STS-GNAP-0899), recorded as the decision so
// the client hears it at its next continuation, and the finish method is
// enacted — the OAuth authorization endpoint's "one sign-in, then
// unmet_authentication_requirements" in GNAP's vocabulary, which has no
// such error. `grant.ro.acr` records what was achieved; the issue stage
// holds every right to it again (`gnap_rights.ts`, STS-GNAP-0891).
//
// **APPROVAL BY AN ABSENT RESOURCE OWNER (RFC 9635 sections 1.4 and 2.4).**
// A request whose `user` names a person who is not the one interacting —
// or who is not there at all, the client offering no interaction — was
// either refused (`invalid_interaction`, `unknown_user`) or, with
// `gnap.allowCrossUser`, approved by WHOEVER signed in, which let any person
// at the page give away somebody else's access. That setting is RETIRED
// with no replacement switch of the same meaning. With `gnap.ownerApproval`
// on (OFF by default, CIBA's rule: a new way in is something a realm turns
// on) the grant waits for the person it names instead:
//
//   * IT IS LISTED ON `/portal/ciba`, beside the CIBA requests: the page
//     where this service's resource owners already answer requests a client
//     made while they were elsewhere. CIBA's mechanism is REUSED where it
//     fits — the page, its session-is-the-identity rule, its step-up through
//     the portal's own sign-in with acr values, its one answer per request —
//     and not where it does not: the request is a GNAP GRANT, held in
//     GNAP's store and continued by GNAP's continuation, so it is not a row
//     of `oauth2.cibaRequests`, whose shape (scope, `auth_req_id`, the token
//     endpoint's grant type) is OAuth's. The approval is the approval page's:
//     the same rights, the same narrowing checkboxes, the same step-up.
//   * A MAIL NOTICE (`mail_uses.ts`'s `accessRequested()`), a notification
//     the person may decline: the request waits on the portal either way.
//   * THE CLIENT POLLS its continuation; `wait` is stretched so the polls
//     the realm allows (`gnap.maxPolls`) cover the time the owner has
//     (`gnap.ownerApprovalLifetimeS`), and `too_fast` holds as everywhere.
//   * AN APPROVAL NOBODY GAVE IN TIME is finalized `rejected` (phase 7's
//     reason): the owner was asked and did not say yes (STS-GNAP-0894).
//   * BOUNDED: a person has at most `gnap.ownerApprovalMaxPending` such
//     grants waiting (STS-GNAP-0897), so a client cannot fill somebody's
//     page — CIBA's `oauth2.cibaMaxPendingPerPerson`, for its reason.
//   * NO REMEMBERED APPROVAL ANSWERS IT. A remembered approval skips a page
//     for a person who is present and signed in; here nobody is, and
//     answering from the register would be issuing a token about a person
//     with nobody asked — the skip-interaction client's privilege, decided
//     by `gnapSkipInteraction` and the delegation policy, not by a consent
//     row.
//   * CELLS (#98): the grant must be where its owner's portal is, which is
//     their home cell. `gnap_cells.ts` already relays a request naming a
//     person to their home, so the grant is made there; the one case it is
//     not — an instance identifier held in another cell, exception (3) of
//     *Cells* — is REFUSED (STS-GNAP-0898) rather than queued where the
//     owner can never see it.
//
// A LIBRARY (rule 3): no route. `gnap_grants.ts` requires it; it reaches the
// grant engine LAZILY, to record an answer, because the engine requires it.
// The mail channel, the cell index and the step-up module are reached
// lazily too, the first two for the reasons their other callers give.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import realms = require('../common/realms');
import InstanceSlot = require('../common/instance_slot');
import store = require('./gnap_store');
import monitor = require('./gnap_monitor');
import gnapRights = require('./gnap_rights');

type Json = any;

interface GnapApprovalDeps {
  log: typeof helpers.log;
  nowSec: typeof helpers.nowSec;
  config: { value(key: string): any };
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  realms: typeof realms;
  store: Json;
  monitor: Json;
  rights: Json;
  stepUp(): Json;
  grants(): Json;
  mailUses(): Json;
  cells(): Json;
  cellRouting(): Json;
}

/**
 * Who approves a GNAP grant and how strongly they signed in (#432 phase 6):
 * the step-up the approval needs, and approval by an absent resource owner.
 */
class GnapApproval {
  /**
   * Builds the library from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: GnapApprovalDeps) {
    deps.log.debug("Entering GnapApproval.constructor().");
    deps.log.debug("Leaving GnapApproval.constructor().");
  }

  /**
   * Returns the real modules the composition root passes.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): GnapApprovalDeps {
    helpers.log.debug("Entering GnapApproval.defaultDeps().");
    helpers.log.debug("Leaving GnapApproval.defaultDeps().");
    return {
      log: helpers.log, nowSec: helpers.nowSec, config: config,
      errorCodes: errorCodes, audit: audit, realms: realms, store: store,
      monitor: monitor, rights: gnapRights,
      stepUp: function stepUp(): Json {
        helpers.log.debug("Entering stepUp().");
        helpers.log.debug("Leaving stepUp().");
        return require('../oauth-oidc/step_up');
      },
      grants: function grants(): Json {
        helpers.log.debug("Entering grants().");
        helpers.log.debug("Leaving grants().");
        return require('./gnap_grants');
      },
      mailUses: function mailUses(): Json {
        helpers.log.debug("Entering mailUses().");
        helpers.log.debug("Leaving mailUses().");
        return require('../common/mail_uses');
      },
      cells: function cells(): Json {
        helpers.log.debug("Entering cells().");
        helpers.log.debug("Leaving cells().");
        return require('../common/cells');
      },
      cellRouting: function cellRouting(): Json {
        helpers.log.debug("Entering cellRouting().");
        helpers.log.debug("Leaving cellRouting().");
        return require('../common/cell_routing');
      }
    };
  }

  // A refusal in the grant engine's shape, the code marked on it.
  private refusal(code: string, why: string, gnapError: string,
                  status: number): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapApproval.refusal(). " + code);
    log.debug("Leaving GnapApproval.refusal().");
    return errorCodes.mark({ ok: false, why: why, gnapError: gnapError,
                             status: status }, code);
  }

  // -------------------------------------------------------------------------
  // STEP-UP.
  // -------------------------------------------------------------------------
  /**
   * Returns the acr values approving a grant needs: every value any
   * requested right's verdict named, or — given the rights the person left
   * ticked (`t<token>r<right>`) — those rights' values only.
   *
   * @param grant - the grant, carrying `requirement`
   * @param ticked - the ticked rights, or undefined for every right
   * @returns the values, each required
   */
  requiredAcr(grant: Json, ticked?: string[]): string[] {
    const { log } = this.deps;
    log.debug("Entering GnapApproval.requiredAcr().");
    const requirement = (grant && grant.requirement) || {};
    if (!Array.isArray(ticked)) {
      log.debug("Leaving GnapApproval.requiredAcr(). Every right.");
      return Array.isArray(requirement.acr) ? requirement.acr.slice() : [];
    }
    const byRight = requirement.byRight || {};
    const out: string[] = [];
    ticked.forEach(function (one: string): void {
      (Array.isArray(byRight[one]) ? byRight[one] : [])
        .forEach(function (acr: string): void {
          if (out.indexOf(acr) < 0) {
            out.push(acr);
          }
        });
    });
    log.debug("Leaving GnapApproval.requiredAcr(). " + out.length);
    return out;
  }

  /**
   * Holds a session to every acr value required, and says what the sign-in
   * screen must demand where it falls short.
   *
   * @param acrs - the values, each required
   * @param session - the sign-on session (its `acr`, `amr`, events)
   * @returns `{ met, missing, ask, forceMfa, forceKey }` — `ask` the values
   *   to send the sign-in, the strongest first
   */
  assess(acrs: string[], session: Json): Json {
    const { log, rights } = this.deps;
    log.debug("Entering GnapApproval.assess().");
    const missing: string[] = rights.unmetAcr(acrs || [], session || {});
    if (!missing.length) {
      log.debug("Leaving GnapApproval.assess(). Met.");
      return { met: true, missing: [], ask: [], forceMfa: false,
               forceKey: false };
    }
    const stepUp = this.deps.stepUp();
    let forceMfa = false;
    let forceKey = false;
    missing.forEach(function (one: string): void {
      const screen = stepUp.screenDemandFor([one]);
      forceMfa = forceMfa || !!screen.forceMfa;
      forceKey = forceKey || !!screen.forceKey;
    });
    const ask = this.strongestFirst(missing);
    log.debug("Leaving GnapApproval.assess(). Missing " + missing.join(' '));
    return { met: false, missing: missing, ask: ask, forceMfa: forceMfa,
             forceKey: forceKey };
  }

  // The values ordered so that one meeting the first meets the rest where
  // RFC 9470's ordered levels say so: a sign-in asked for `mfa 1` produces
  // `mfa` if it can, which is what both rights need.
  private strongestFirst(acrs: string[]): string[] {
    const { log } = this.deps;
    const stepUp = this.deps.stepUp();
    log.debug("Entering GnapApproval.strongestFirst().");
    const score = function (one: string): number {
      return acrs.filter(function (other: string): boolean {
        return stepUp.meets(other, { acr: one });
      }).length;
    };
    const out = acrs.slice().sort(function (a: string, b: string): number {
      return score(b) - score(a);
    });
    log.debug("Leaving GnapApproval.strongestFirst().");
    return out;
  }

  // -------------------------------------------------------------------------
  // APPROVAL BY AN ABSENT RESOURCE OWNER.
  // -------------------------------------------------------------------------
  /**
   * Tells whether a grant may wait for its resource owner on the portal:
   * `gnap.ownerApproval`, off by default.
   *
   * @returns true when it may
   */
  available(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering GnapApproval.available().");
    log.debug("Leaving GnapApproval.available().");
    return config.value('gnap.ownerApproval') === true;
  }

  // The seconds an owner has to answer.
  private lifetimeS(): number {
    const { log, config } = this.deps;
    log.debug("Entering GnapApproval.lifetimeS().");
    const n = Number(config.value('gnap.ownerApprovalLifetimeS'));
    log.debug("Leaving GnapApproval.lifetimeS().");
    return Number.isFinite(n) && n > 0 ? n : 600;
  }

  // Whether a grant is waiting for its owner now.
  private waiting(grant: Json): boolean {
    const { log, nowSec, store } = this.deps;
    log.debug("Entering GnapApproval.waiting().");
    const owner = grant && grant.ownerApproval;
    log.debug("Leaving GnapApproval.waiting().");
    return !!owner && !owner.answered && grant.state === store.STATE.PENDING &&
      !grant.decision && Number(owner.expiresAt) >= nowSec();
  }

  /**
   * Returns the seconds a client waiting for an owner should wait between
   * polls: the realm's `gnap.continueWaitS`, stretched so `gnap.maxPolls`
   * polls cover the owner's whole time.
   *
   * @param grant - the grant
   * @returns the wait, or null for a grant not waiting for an owner
   */
  waitFor(grant: Json): number | null {
    const { log, config } = this.deps;
    log.debug("Entering GnapApproval.waitFor().");
    if (!grant || !grant.ownerApproval || grant.ownerApproval.answered) {
      log.debug("Leaving GnapApproval.waitFor(). Not waiting.");
      return null;
    }
    const base = Math.max(0, Number(config.value('gnap.continueWaitS')));
    const polls = Number(config.value('gnap.maxPolls')) || 60;
    const stretched = Math.ceil(this.lifetimeS() / Math.max(1, polls - 1));
    log.debug("Leaving GnapApproval.waitFor().");
    return Math.max(Number.isFinite(base) ? base : 5, stretched);
  }

  // How many grants wait for one person.
  private pendingCount(username: string): number {
    const { log, store } = this.deps;
    const self = this;
    log.debug("Entering GnapApproval.pendingCount().");
    const n = store.listGrants().filter(function (grant: Json): boolean {
      return self.waiting(grant) &&
        String(grant.ownerApproval.username) === username;
    }).length;
    log.debug("Leaving GnapApproval.pendingCount(). " + n);
    return n;
  }

  // A sentence naming the rights, for the mail and the audit row.
  private rightsSentence(grant: Json): string {
    const { log } = this.deps;
    log.debug("Entering GnapApproval.rightsSentence().");
    const names: string[] = [];
    ((grant.request && grant.request.tokens) || [])
      .forEach(function (token: Json): void {
        (token.access || []).forEach(function (right: Json): void {
          const name = typeof right === 'string' ? right
            : String(right.type || '') + (Array.isArray(right.actions) &&
              right.actions.length ? ' (' + right.actions.join(', ') + ')'
                                   : '');
          if (names.indexOf(name) < 0) {
            names.push(name);
          }
        });
      });
    const out = names.join('; ').slice(0, 300) || 'access';
    log.debug("Leaving GnapApproval.rightsSentence().");
    return out;
  }

  /**
   * Puts a grant on its resource owner's portal to wait for their answer,
   * and tells them by mail. The caller has checked `available()`.
   *
   * @param grant - the grant, saved
   * @param username - the person the request names
   * @param context - `requestedBy` (who was at the page, or ''), `via`
   * @returns `{ ok: true }`, or a refusal (STS-GNAP-0897, 0898)
   */
  async queue(grant: Json, username: string, context: Json): Promise<Json> {
    const { log, nowSec, config, audit, store, monitor, realms } = this.deps;
    log.debug("Entering GnapApproval.queue(). " + username);
    const ctx = context || {};
    const max = Number(config.value('gnap.ownerApprovalMaxPending')) || 5;
    if (this.pendingCount(username) >= max) {
      log.debug("Leaving GnapApproval.queue(). Too many waiting.");
      return this.refusal('STS-GNAP-0897', 'the resource owner already has ' +
        max + ' requests waiting for their approval ' +
        '(gnap.ownerApprovalMaxPending); try again later (RFC 9635 section ' +
        '1.4).', 'request_denied', 403);
    }
    const cells = this.deps.cells();
    if (cells.isMulti()) {
      const home = await this.deps.cellRouting()
        .homeOf(realms.currentId(), 'name', username);
      if (home && !cells.isHere(home)) {
        log.debug("Leaving GnapApproval.queue(). Homed elsewhere.");
        return this.refusal('STS-GNAP-0898', 'the resource owner is homed ' +
          'in another cell than the one holding this client instance, so ' +
          'a request waiting here could never reach their portal; ask ' +
          'without an instance identifier, or with interaction.',
          'request_denied', 403);
      }
    }
    const lifetime = this.lifetimeS();
    const now = nowSec();
    grant.ownerApproval = { id: store.handle(18), username: username,
                            requestedAt: now, expiresAt: now + lifetime,
                            requestedBy: String(ctx.requestedBy || ''),
                            via: String(ctx.via || ''), answered: false };
    grant.userHint = username;
    grant.state = store.STATE.PENDING;
    grant.expiresAt = now + lifetime;
    store.saveGrant(grant, 'waiting for its resource owner on the portal');
    monitor.record(grant.client.identifier, 'grant.owner_queued', {});
    audit.audit({ action: 'gnap.grant.owner-queued', category: 'protocol',
                  protocol: 'GNAP', channel: 'http', outcome: 'success',
                  actor: grant.client.identifier, target: username,
                  summary: 'A GNAP grant waits for its resource owner\'s ' +
                           'approval on the portal',
                  detail: { grant: grant.id, via: String(ctx.via || ''),
                            requestedBy: String(ctx.requestedBy || ''),
                            expiresAt: now + lifetime } });
    try {
      this.deps.mailUses().accessRequested(username, {
        client: grant.client.identifier,
        rights: this.rightsSentence(grant),
        expiresMinutes: String(Math.max(1, Math.round(lifetime / 60))),
        dedupKey: 'access-request:' + grant.id });
    } catch (e) {
      log.debug("Caught in GnapApproval.queue(): " + ((e && e.message) || e));
      // The grant waits on the portal whether or not it was mailed.
      log.warn(this.deps.errorCodes.tag('STS-GNAP-0900') + 'gnap: the ' +
               'access request notice for grant ' + grant.id + ' could not ' +
               'be queued: ' + ((e && e.message) || e));
    }
    log.debug("Leaving GnapApproval.queue().");
    return { ok: true };
  }

  /**
   * Lists the grants waiting for one person, for the portal.
   *
   * @param username - the signed-in person
   * @returns rows: `{ id, client, display, declared, tokens, subject,
   *   requestedBy, expiresAt, acr }`
   */
  pendingFor(username: string): Json[] {
    const { log, store } = this.deps;
    const self = this;
    log.debug("Entering GnapApproval.pendingFor().");
    const who = String(username || '').toLowerCase();
    const out = store.listGrants().filter(function (grant: Json): boolean {
      return self.waiting(grant) &&
        String(grant.ownerApproval.username).toLowerCase() === who;
    }).map(function (grant: Json): Json {
      const display = grant.client.display || {};
      const subject = grant.request.subject;
      return {
        id: grant.ownerApproval.id,
        client: grant.client.identifier,
        display: display.name || grant.client.identifier,
        declared: Array.isArray(display.declared) &&
          display.declared.indexOf('name') >= 0,
        tokens: grant.request.tokens,
        subject: !!(subject && ((subject.subIdFormats || []).length ||
                                (subject.assertionFormats || []).length)),
        requestedBy: grant.ownerApproval.requestedBy || '',
        expiresAt: grant.ownerApproval.expiresAt,
        acr: self.requiredAcr(grant),
        narrowed: Array.isArray(grant.narrowed) ? grant.narrowed : []
      };
    });
    log.debug("Leaving GnapApproval.pendingFor(). " + out.length);
    return out;
  }

  /**
   * Finds the grant behind one waiting row, for the person it waits for
   * only.
   *
   * @param username - the signed-in person
   * @param id - the row's identifier
   * @returns the grant, or null
   */
  find(username: string, id: string): Json {
    const { log, store } = this.deps;
    const self = this;
    log.debug("Entering GnapApproval.find().");
    const who = String(username || '').toLowerCase();
    const found = id ? store.listGrants().filter(function (grant: Json) {
      return self.waiting(grant) && grant.ownerApproval.id === id &&
        String(grant.ownerApproval.username).toLowerCase() === who;
    })[0] : null;
    // The live record, not the listing's copy: the answer is written to it.
    const live = found ? store.getGrant(found.id) : null;
    log.debug("Leaving GnapApproval.find(). " + !!live);
    return live || null;
  }

  /**
   * Records the owner's answer from the portal: the rights they left
   * ticked, held to the step-up they need, then the grant engine's
   * decision. Once across the cluster.
   *
   * @param username - the signed-in person
   * @param session - their sign-on session
   * @param id - the waiting row
   * @param selection - `{ approve, ticked, subject }`
   * @returns `{ ok: true }`, `{ ok: false, stepUp: true, ask }` when the
   *   session falls short, or `{ ok: false, why, code }`
   */
  async answer(username: string, session: Json, id: string,
               selection: Json): Promise<Json> {
    const { log, nowSec, store } = this.deps;
    log.debug("Entering GnapApproval.answer().");
    const grant = this.find(username, id);
    if (!grant) {
      log.debug("Leaving GnapApproval.answer(). Nothing waiting.");
      return { ok: false, code: 'STS-PORTAL-0243',
               why: 'That request is not waiting for you: it was answered, ' +
                    'it ran out, or it is somebody else\'s.' };
    }
    const ticked: string[] = Array.isArray(selection.ticked)
      ? selection.ticked : [];
    if (selection.approve) {
      const assessed = this.assess(this.requiredAcr(grant, ticked), session);
      if (!assessed.met) {
        log.debug("Leaving GnapApproval.answer(). A stronger sign-in.");
        return { ok: false, stepUp: true, ask: assessed.ask,
                 code: 'STS-PORTAL-0244',
                 why: 'This request needs sign-in level ' +
                      assessed.missing.join(' ') + ', more than this ' +
                      'session proved. Sign in again with it, then approve.' };
      }
    }
    const claimed: Json = await store.spend('owner-decision',
      grant.id + ':' + id, Number(grant.ownerApproval.expiresAt) - nowSec(),
      'STS-GNAP-0717');
    if (!claimed.ok) {
      log.debug("Leaving GnapApproval.answer(). Answered elsewhere.");
      return { ok: false, code: claimed.errorCode || 'STS-GNAP-0717',
               why: 'An answer to this request has already been recorded.' };
    }
    const tokens = grant.request.tokens.map(function (token: Json,
                                                      t: number): Json {
      return { label: token.label, bearer: token.bearer,
               access: token.access.filter(function (right: Json,
                                                     r: number): boolean {
                 return ticked.indexOf('t' + t + 'r' + r) >= 0;
               }) };
    });
    const anything = tokens.some(function (token: Json): boolean {
      return token.access.length > 0;
    }) || !!selection.subject;
    try {
      this.deps.grants().decideAsOwner(grant, session, {
        approve: !!selection.approve && anything, tokens: tokens,
        subject: !!selection.subject });
    } catch (e) {
      log.debug("Caught in GnapApproval.answer(): " + ((e && e.message) || e));
      await store.unspend(claimed.handle);
      throw e;
    }
    log.debug("Leaving GnapApproval.answer(). Answered.");
    return { ok: true, approved: !!selection.approve && anything };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2): see
// `common/instance_slot.ts`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapApproval>(
  'gnap/gnap_approval',
  () => new GnapApproval(GnapApproval.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Who approves a GNAP grant and how strongly they signed in (#432 phase 6).
 * A library that registers no route.
 *
 * @namespace
 */
export = {
  GnapApproval: GnapApproval,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: GnapApproval): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  requiredAcr: slot.forward('requiredAcr'),
  assess: slot.forward('assess'),
  available: slot.forward('available'),
  waitFor: slot.forward('waitFor'),
  queue: slot.forward('queue'),
  pendingFor: slot.forward('pendingFor'),
  find: slot.forward('find'),
  answer: slot.forward('answer')
};
