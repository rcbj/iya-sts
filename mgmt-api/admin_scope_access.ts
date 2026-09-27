// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: admin_scope_access.ts
//
// ===========================================================================
// `admin:read` AND `admin:write` ARE ISSUED FOR A PERSON ONLY AS FAR AS THAT
// PERSON'S CONSOLE ROLES GO (#302, part A of #88, 2026-09-27).
//
// `/admin-api` takes an access token, and `common/roles.js` reads ADMIN_READ
// and ADMIN_WRITE straight off its scopes. Until this file, the only question
// asked before those scopes were ISSUED was the CLIENT's — does it declare
// them in `oauthAllowedScope` (#110, `common/scope_policy.ts`). The PERSON
// was never asked. So a client registered with `admin:write` on the
// authorization code flow handed Admin Write to anybody who could sign in
// through it: the scope was the authorization, which is exactly what #88
// argues a scope must never be. A scope is what was REQUESTED; whether it is
// granted is the principal's authorization, and for these two scopes that is
// the console roster.
//
// **WHAT IS ASKED IS THE CONSOLE'S OWN QUESTION, NOT A RESTATEMENT OF IT.**
// `admin-ui/admin_rbac.ts`'s `rolesOf()` for the person, in the realm the
// token is being issued in — the realm whose `/admin-api` will accept it.
// For the default realm that is the SERVICE roster; for a trust realm, that
// realm's own administrators (#32), whose tokens that realm's authorization
// server issues and whose `/admin-api` is that realm's. `admin:read` goes
// with Admin Read and `admin:write` with Admin Write (which implies Admin
// Read, by the roster's own table). A scope the roles do not cover is taken
// off and the rest are left exactly as they were.
//
// **THE OPEN CONSOLE IS HONOURED HERE, AND THAT IS WHERE THIS DIFFERS FROM
// `debugger/debugger_access.ts`.** In development, until the bootstrap
// administrator claims the console (or while nobody is on the roster where
// none was seeded), `rolesOf()` answers that everybody signed in holds both
// roles, and the console lets them in. Rule 7 makes `/admin-api` the
// console's machine door, so refusing its scopes to somebody the console
// itself admits would make the two disagree about one person. The debugger
// is a network relay that nothing about the bootstrap goes through; the API
// is where the first grant can be made.
//
// **THE BOOTSTRAP ADMINISTRATOR BEFORE ITS CLAIM, IN PRODUCT (#103), IS NOT
// ISSUED THEM.** Its roles are honoured from a password session at the
// console alone. At issuance a subject is a name and nothing here knows how
// it signed in, so — `debugger_access.ts`'s reading — the scopes wait for the
// claim: a federation partner asserting `admin` must not be handed them.
//
// **AN APPLICATION IS NOT ASKED, YET.** A `client_credentials` grant's
// subject is the client (RFC 9068 section 2.2), and today a client declaring
// the scopes is what authorizes them — the seeded `sts-management-api` is the
// machine door every launcher uses. Giving applications a role that
// authorizes a permission is #303 (part B of #88), which moves ADMIN_READ and
// ADMIN_WRITE onto the role → permission relation for both kinds of
// principal. Until then this file leaves an application's scope alone.
//
// **NARROWED, NOT REFUSED — until nothing is left (#88 decision 2).** RFC
// 6749 section 3.3 lets an authorization server issue less than was asked
// for, and the token response's `scope` says what was issued. A request
// that asked for nothing BUT scopes this person may not hold has nothing
// left to issue, and the caller refuses it `invalid_scope` (STS-ADMIN-0822):
// `narrowScope()` reports `emptied` so each caller can answer in its own
// protocol shape.
//
// **AND ASKED AGAIN ON EVERY CALL THE API TAKES (`recheck()`).** A token is
// issued once and honoured until it expires, so a console role revoked after
// a person's token was minted would otherwise go on working at `/admin-api`
// for the token's lifetime — a silent gap between what the roster says and
// what the API does. `mgmt-api/admin_api.ts`'s gate hands every person's
// token here, and a scope the roster no longer authorizes is not honoured;
// `debugger/debugger_server.ts` asks the debugger's question the same way.
// A client's token (`sub` equal to `client_id`, or `urn:sts:client:<id>` in
// RFC 9700 mode — the two forms `oauth2.ts` mints) is left to the client
// declaration the gate already re-checks (#110).
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers nothing, and everything it requires is a
// library too — `admin_rbac` the same way `debugger/debugger_access.ts` and
// `common/cert_enrollment.ts` require it — so `oauth2.ts` at 9 requires it
// without moving a route or closing a cycle. It lives in `mgmt-api/` because
// the scopes are that API's, and `admin_api.ts` requires it for `recheck()`.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50) — `debugger/debugger_access.ts`'s shape: the
// modules it uses arrive through its constructor, the composition root
// builds the instance, and the exports below are facades forwarding to it.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
const { log } = helpers;
import realms = require('../common/realms');
import adminRbac = require('../admin-ui/admin_rbac');
import audit = require('../common/audit');

// The two scopes, and the console role each one needs. `write` implies
// `read` in the roster's table, so `rolesOf().read` is already true for a
// holder of Admin Write and nothing here restates the implication.
const SCOPE_ROLES = Object.freeze({ 'admin:read': 'read',
                                    'admin:write': 'write' });
const ADMIN_SCOPES = Object.freeze(Object.keys(SCOPE_ROLES));

const NARROWED_CODE = 'STS-ADMIN-0821';
const EMPTIED_CODE = 'STS-ADMIN-0822';
const WITHDRAWN_CODE = 'STS-API-0125';

interface AdminScopeAccessDeps {
  log: typeof log;
  realms: typeof realms;
  adminRbac: typeof adminRbac;
  audit: typeof audit;
}

// What `narrowScope()` answers.
interface Narrowed {
  // The scope to grant.
  scope: string;
  // The admin scopes taken off, in the order they were asked for.
  removed: string[];
  // True when something was taken off and nothing at all is left.
  emptied: boolean;
  // Why, for an error_description; '' when nothing was taken off.
  why: string;
}

class AdminScopeAccess {
  constructor(private readonly deps: AdminScopeAccessDeps) {
    deps.log.debug("Entering AdminScopeAccess.constructor().");
    deps.log.debug("Leaving AdminScopeAccess.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): AdminScopeAccessDeps {
    helpers.log.debug("Entering AdminScopeAccess.defaultDeps().");
    helpers.log.debug("Leaving AdminScopeAccess.defaultDeps().");
    return { log: log, realms: realms, adminRbac: adminRbac, audit: audit };
  }

  // The values of a space-delimited scope.
  static split(scope: unknown): string[] {
    helpers.log.debug("Entering AdminScopeAccess.split().");
    helpers.log.debug("Leaving AdminScopeAccess.split().");
    return String(scope == null ? '' : scope).split(/\s+/).filter(Boolean);
  }

  // Whether a scope names either admin scope — the cheap test every grant
  // takes before anything is looked up.
  asksForAdminScope(scope: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering AdminScopeAccess.asksForAdminScope().");
    const asked = AdminScopeAccess.split(scope).some(function (one) {
      return ADMIN_SCOPES.indexOf(one) >= 0;
    });
    log.debug("Leaving AdminScopeAccess.asksForAdminScope(). " + asked);
    return asked;
  }

  // ---------------------------------------------------------------------------
  // heldScopes({ kind, name, authenticated })
  //
  // `{ scopes, why }`: the admin scopes this subject's console roles
  // authorize in the ambient realm, and — when that is not both — why not.
  // Only called for a person; see the header for an application.
  // ---------------------------------------------------------------------------
  heldScopes(subject: any, inRealm?: string): { scopes: string[];
                                                  why: string } {
    const { log, realms, adminRbac } = this.deps;
    log.debug("Entering AdminScopeAccess.heldScopes().");
    const who = subject || {};
    const name = String(who.name || '').trim();
    if (!name) {
      log.debug("Leaving AdminScopeAccess.heldScopes(). Nobody named.");
      return { scopes: [], why: 'nobody is named as the subject' };
    }
    if (who.authenticated === false) {
      log.debug("Leaving AdminScopeAccess.heldScopes(). Not authenticated.");
      return { scopes: [], why: name + ' did not authenticate' };
    }
    const realmId = inRealm || realms.currentId();
    let held = null;
    try {
      held = adminRbac.rolesOf(name, realmId);
    } catch (e) {
      // A roster that cannot be read grants nothing: this is a door to the
      // management API, and it does not open because the directory failed.
      log.debug("Caught in AdminScopeAccess.heldScopes(): " +
                ((e && e.message) || e));
      held = null;
    }
    if (!held) {
      log.debug("Leaving AdminScopeAccess.heldScopes(). No roster.");
      return { scopes: [], why: 'the console roster of the realm "' +
                                realmId + '" could not be read' };
    }
    if (held.claimPending === true) {
      log.debug("Leaving AdminScopeAccess.heldScopes(). The bootstrap " +
                "administrator has not claimed the console.");
      return { scopes: [],
               why: name + ' is the bootstrap administrator and has not yet ' +
                    'claimed the admin console by signing in to it with its ' +
                    'password; until it has, its roles open the console ' +
                    'alone' };
    }
    const scopes = ADMIN_SCOPES.filter(function (scope) {
      return held[SCOPE_ROLES[scope]] === true;
    });
    const why = scopes.length === ADMIN_SCOPES.length ? ''
      : name + ' holds ' + (held.read ? 'Admin Read but not Admin Write'
                                      : 'neither Admin Read nor Admin Write') +
        ' on the console roster of the realm "' + realmId + '"';
    log.debug("Leaving AdminScopeAccess.heldScopes(). " +
              (scopes.join(' ') || 'none'));
    return { scopes: scopes, why: why };
  }

  // Whether an access token's claims are a CLIENT's own (client_credentials):
  // the two spellings of its subject that `oauth2.ts` mints — the bare
  // client_id, and `urn:sts:client:<id>` in RFC 9700 mode.
  isClientToken(claims: any): boolean {
    const { log } = this.deps;
    log.debug("Entering AdminScopeAccess.isClientToken().");
    const c = claims || {};
    const clientId = String(c.client_id || '');
    const sub = String(c.sub || '');
    const answer = !!clientId &&
                   (sub === clientId || sub === 'urn:sts:client:' + clientId);
    log.debug("Leaving AdminScopeAccess.isClientToken(). " + answer);
    return answer;
  }

  // ---------------------------------------------------------------------------
  // recheck(claims, scopes, tokenRealm)
  //
  // `{ kept, withdrawn, why }`: of the scopes a verified `/admin-api` token
  // carries, the ones still honoured. A person's admin scopes are held to
  // their console roles NOW, in the realm that issued the token; a client's
  // token and every other scope pass through. Records nothing — the gate
  // marks its own refusal.
  // ---------------------------------------------------------------------------
  recheck(claims: any, scopes: string[], tokenRealm: string):
      { kept: string[]; withdrawn: string[]; why: string } {
    const { log } = this.deps;
    log.debug("Entering AdminScopeAccess.recheck().");
    const carried = (scopes || []).slice(0);
    const admin = carried.filter(function (one) {
      return ADMIN_SCOPES.indexOf(one) >= 0;
    });
    if (!admin.length || this.isClientToken(claims)) {
      log.debug("Leaving AdminScopeAccess.recheck(). Nothing to ask.");
      return { kept: carried, withdrawn: [], why: '' };
    }
    const c = claims || {};
    const name = String(c.username || c.preferred_username || c.sub || '');
    const answer = this.heldScopes({ kind: 'user', name: name,
                                     authenticated: true }, tokenRealm);
    const withdrawn = admin.filter(function (one) {
      return answer.scopes.indexOf(one) < 0;
    });
    log.debug("Leaving AdminScopeAccess.recheck(). " + withdrawn.length +
              " withdrawn.");
    return { kept: carried.filter(function (one) {
      return withdrawn.indexOf(one) < 0;
    }), withdrawn: withdrawn, why: answer.why };
  }

  // ---------------------------------------------------------------------------
  // narrowScope(scope, subject, context)
  //
  // The scope to GRANT, with every admin scope the subject may not hold taken
  // off and recorded (one audit row, STS-ADMIN-0821). `context` is
  // `{ clientId, grant }`, for the row. An application's scope, and a scope
  // naming neither admin scope, come back unchanged.
  // ---------------------------------------------------------------------------
  narrowScope(scope: unknown, subject: any, context?: any): Narrowed {
    const { log, audit } = this.deps;
    log.debug("Entering AdminScopeAccess.narrowScope().");
    const asked = String(scope == null ? '' : scope);
    const unchanged: Narrowed = { scope: asked, removed: [], emptied: false,
                                  why: '' };
    if (!this.asksForAdminScope(asked)) {
      log.debug("Leaving AdminScopeAccess.narrowScope(). Not asked for.");
      return unchanged;
    }
    const who = subject || {};
    if (who.kind && who.kind !== 'user') {
      log.debug("Leaving AdminScopeAccess.narrowScope(). An application — " +
                "#303 decides those.");
      return unchanged;
    }
    const answer = this.heldScopes(who);
    const values = AdminScopeAccess.split(asked);
    const removed = values.filter(function (one) {
      return ADMIN_SCOPES.indexOf(one) >= 0 && answer.scopes.indexOf(one) < 0;
    });
    if (!removed.length) {
      log.debug("Leaving AdminScopeAccess.narrowScope(). Granted.");
      return unchanged;
    }
    const kept = values.filter(function (one) {
      return removed.indexOf(one) < 0;
    });
    const ctx = context || {};
    const name = String(who.name || '');
    // ONE line in the log, and it is the audit row's: `audit.js` writes a row
    // carrying an errorCode to the log itself.
    audit.failure('STS-ADMIN-0821', {
      actor: name,
      protocol: 'OAuth 2.0 / OIDC',
      channel: 'http',
      target: removed.join(' '),
      outcome: 'refused',
      summary: 'the scope(s) ' + removed.join(', ') + ' were not issued to ' +
               (name || 'an unnamed subject') + ': ' + answer.why,
      detail: { client_id: String(ctx.clientId || ''),
                grant: String(ctx.grant || ''),
                removed: removed.join(' '), why: answer.why }
    });
    log.debug("Leaving AdminScopeAccess.narrowScope(). " + removed.length +
              " taken off.");
    return { scope: kept.join(' '), removed: removed,
             emptied: kept.length === 0,
             why: 'the scope(s) ' + removed.join(', ') + ' cannot be issued: ' +
                  answer.why };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`. The exports below are FACADES for the
// JavaScript that calls this module through `require()`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<AdminScopeAccess>(
  'mgmt-api/admin_scope_access',
  () => new AdminScopeAccess(AdminScopeAccess.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module always did.
slot.buildNowUnlessDeferred();

export = {
  AdminScopeAccess: AdminScopeAccess,
  installInstance: (instance: AdminScopeAccess): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ADMIN_SCOPES: ADMIN_SCOPES,
  NARROWED_CODE: NARROWED_CODE,
  EMPTIED_CODE: EMPTIED_CODE,
  WITHDRAWN_CODE: WITHDRAWN_CODE,
  split: AdminScopeAccess.split,
  asksForAdminScope: slot.forward('asksForAdminScope'),
  heldScopes: slot.forward('heldScopes'),
  isClientToken: slot.forward('isClientToken'),
  recheck: slot.forward('recheck'),
  narrowScope: slot.forward('narrowScope')
};
