// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: debugger_access.ts
//
// ===========================================================================
// WHO MAY USE THE EMBEDDED PROTOCOL DEBUGGER, DECIDED IN ONE PLACE
// (2026-09-13).
//
// The debugger's api dials whatever its caller names — a token endpoint, a
// KDC, a directory, a TLS handshake — so the one question that matters about
// it is who may make it do that. The answer rcbj gave is one sentence: **any
// console administrator, and nobody else.** This file is that sentence, asked
// by `debugger/debugger_server.ts`'s gate on EVERY request it lets through,
// for the user of the relying-party session the request's cookie names — so a
// console role revoked after a person signed in stops working at their next
// request.
//
// **NO PERMISSION, NO RESOURCE SERVER (#1717, 2026-11-13).** Until then the
// debugger's api was a second application, `sts-debugger-api`, exposing one
// delegated permission (`urn:sts:debugger-api:debugger`) that `narrowScope()`
// here took off any grant to somebody who was not an administrator, and the
// gate verified the session's access token for it. That access token was
// also accepted on the request's own `Authorization` header — and the
// debugger sends `Authorization` to its api as PART OF ITS WORK (a UserInfo
// Bearer token, introspection's Basic credentials, SCIM's and GNAP's own), so
// the gate read the debugger's traffic as its own credential. The gate is the
// session alone now, the UI and its api are one client (`sts-debugger-ui`),
// and the only question left is the one below. The retired row's identifier
// is kept as RETIRED_API_IDENTIFIER, for `applications.js`'s retirement of a
// seeded copy.
//
// **WHAT "ADMINISTRATOR" MEANS IS THE CONSOLE'S AND IS NOT RESTATED HERE.**
// `admin-ui/admin_rbac.ts` decides who holds Admin Read or Admin Write, and it
// is asked in the DEFAULT realm, out of that realm's `ou=groups` — so a trust
// realm's own administrators (2026-09-14, #32), who are confined to their
// realm, are not debugger users. Holding EITHER role is enough: the debugger
// changes nothing in this service, so the read/write distinction the console
// draws has no meaning at its door.
//
// **THE EMPTY-ROSTER RULE IS NOT HONOURED HERE, AND THAT IS THE ONE PLACE THE
// DEBUGGER AND THE CONSOLE DISAGREE (rcbj, 2026-09-13).** `admin.openWhenEmpty`
// hands everybody who signs in both roles until the bootstrap administrator
// first signs in — or, where none was seeded, while neither role group has a
// member — because the console is where the first grant is made. The
// debugger needs no bootstrap: nothing about granting the first role goes
// through it. So a role held only BECAUSE nobody holds one is
// refused (`STS-DBG-0024`), and the debugger stays shut until somebody is
// actually a member of Admin Read or Admin Write. "Everybody is an
// administrator because nobody is" is not a reason to open a network relay —
// the same judgement `common/cert_enrollment.ts` makes about issuing
// certificates in somebody else's name.
//
// **SINCE 2026-09-22 (#103) THE WINDOW IS DEVELOPMENT'S ALONE, AND THE
// DEBUGGER AND THE CONSOLE AGREE ABOUT THE REST OF IT.** Product never opens
// the window, and before the bootstrap administrator has claimed the console
// its roles are honoured from a password sign-in only. The console can see
// the session; this module sees a name, so it refuses that account the
// debugger until the claim (`STS-DBG-0033`) — a partner asserting `admin`
// must not be let in.
//
// **AND THE POLICY IS ASKED AS WELL, NEVER INSTEAD.** The roles are put into a
// request to `common/access_gate.ts` under `RESOURCE.DEBUGGER`, so an operator
// can narrow the debugger further with a XACML rule. What the policy cannot do
// is WIDEN it: a subject holding neither role is refused before the policy is
// asked, because `access_gate.js` answers "allowed" when no decider is loaded
// or `xacml.enforceAccess` is off, and a relay must not open because a policy
// subsystem was switched off.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers nothing, and everything it requires is a
// library too — `admin_rbac.js` included, which `common/cert_enrollment.ts`
// already requires the same way — so `oauth2.js` at 9 requires it without
// moving a route or closing a cycle.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `DebuggerAccess` takes the modules it uses through its constructor
// (`DebuggerAccessDeps`). Since #50's R2 the composition root builds the
// instance; the module's old names are FACADES forwarding to it, for the
// callers that are not converted, and a process without the root builds a
// default at load.
// `DebuggerAccess` is exported beside them for that root.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
const { log } = helpers;
import realms = require('../common/realms');
import accessGate = require('../common/access_gate');
import adminRbac = require('../admin-ui/admin_rbac');
import audit = require('../common/audit');

// The one seeded application: the client a person signs in through, which is
// the UI and its api together (#1717). The id is the one it had while there
// were two, so registrations, grants and sessions made before survive.
/**
 * The client_id of the seeded debugger application a person signs in
 * through.
 */
const UI_CLIENT_ID = 'sts-debugger-ui';
/**
 * The identifier of the resource-server application seeded before #1717,
 * which a start removes when it was seeded rather than made by hand.
 */
const RETIRED_API_IDENTIFIER = 'sts-debugger-api';

// The console roles, as `admin_rbac.rolesOf()` names them. Either is enough.
/**
 * The console roles, either of which lets a person use the debugger.
 */
const CONSOLE_ROLES = ['read', 'write'];

// What `DebuggerAccess` needs from the rest of the service: the modules this
// file used to reach for itself, passed in so that the composition root can
// build one and a test can build one with stubs.
interface DebuggerAccessDeps {
  log: typeof log;
  realms: typeof realms;
  accessGate: typeof accessGate;
  adminRbac: typeof adminRbac;
  audit: typeof audit;
}

/**
 * Decides who may use the embedded protocol debugger: any console
 * administrator of the default realm, and nobody else.
 *
 * Asked by the debugger's gate on every request it lets through.
 */
class DebuggerAccess {
  /**
   * Builds the decision over the given modules.
   *
   * @param deps - the logger, realms, the access gate, the console's RBAC and
   *   the audit log
   */
  constructor(private readonly deps: DebuggerAccessDeps) {
    deps.log.debug("Entering DebuggerAccess.constructor().");
    deps.log.debug("Leaving DebuggerAccess.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  /**
   * Returns the dependencies the load-time default instance is built from.
   *
   * @returns the real modules
   */
  static defaultDeps(): DebuggerAccessDeps {
    helpers.log.debug("Entering DebuggerAccess.defaultDeps().");
    helpers.log.debug("Leaving DebuggerAccess.defaultDeps().");
    return {
      log: log,
      realms: realms,
      accessGate: accessGate,
      adminRbac: adminRbac,
      audit: audit
    };
  }

  // ---------------------------------------------------------------------------
  // isAdministrator({ name, authenticated, kind, path })
  //
  // `{ allowed, why, code, roles }`. `kind` is the subject's — an application
  // is never a debugger user, because the debugger is a PERSON's tool and rcbj
  // chose that no machine client uses it.
  // ---------------------------------------------------------------------------
  /**
   * Says whether a subject may use the debugger: a person, authenticated,
   * holding Admin Read or Admin Write in the default realm, and allowed by
   * the access policy.
   *
   * Refused as well while the console is open only because its roster is
   * empty, and for the bootstrap administrator before it claims the console.
   * @param subject - `{ name, authenticated, kind, path, sessionId }`
   * @returns `{ allowed, why, code, roles }`
   */
  isAdministrator(subject) {
    const { log, realms, adminRbac, accessGate } = this.deps;
    log.debug("Entering DebuggerAccess.isAdministrator().");
    const who = subject || {};
    const name = String(who.name || '').trim();
    if (who.kind && who.kind !== 'user') {
      log.debug("Leaving DebuggerAccess.isAdministrator(). Not a person.");
      return { allowed: false, code: 'STS-DBG-0001', roles: [],
               why: 'the subject is an application, and the debugger is ' +
                    'for people only' };
    }
    if (!name) {
      log.debug("Leaving DebuggerAccess.isAdministrator(). Nobody named.");
      return { allowed: false, code: 'STS-DBG-0001', roles: [],
               why: 'nobody is named as the subject' };
    }
    if (who.authenticated === false) {
      log.debug("Leaving DebuggerAccess.isAdministrator(). Not authenticated.");
      return { allowed: false, code: 'STS-DBG-0001', roles: [],
               why: name + ' did not authenticate' };
    }
    let held = null;
    try {
      held = realms.run(realms.get(realms.DEFAULT_ID), function () {
        return adminRbac.rolesOf(name);
      });
    } catch (e) {
      log.debug("Caught in DebuggerAccess.isAdministrator(): " +
                ((e && e.message) || e));
      held = null;
    }
    const roles = held && Array.isArray(held.roles) ? held.roles.slice(0) : [];
    // BEFORE the role test, because under the empty-roster rule every signed-in
    // person holds both roles and would pass it. See the header.
    if (held && held.open === true) {
      log.debug("Leaving DebuggerAccess.isAdministrator(). The roster is " +
                "empty.");
      return { allowed: false, code: 'STS-DBG-0024', roles: [],
               why: name + ' holds no console role and uses the console only ' +
                    'because it is open to everybody — until the bootstrap ' +
                    'administrator first signs in, or while nobody holds a ' +
                    'role — and the debugger does not open that way. Grant a ' +
                    'role on /admin/rbac (or POST /admin-api/rbac/grant) ' +
                    'first' };
    }
    // THE BOOTSTRAP ADMINISTRATOR BEFORE ITS CLAIM, IN PRODUCT (2026-09-22,
    // #103). It holds both roles by membership, and until it has claimed the
    // console with its password those roles are honoured at the console alone,
    // from a password session. Nothing here knows how the subject signed in —
    // the gate hands it the session's user name and no more — so the debugger
    // waits for the claim rather than guessing. A federation partner asserting
    // `admin` would otherwise be let in.
    if (held && held.claimPending === true) {
      log.debug("Leaving DebuggerAccess.isAdministrator(). The bootstrap " +
                "administrator has not claimed the console.");
      return { allowed: false, code: 'STS-DBG-0033', roles: [],
               why: name + ' is the bootstrap administrator and has not yet ' +
                    'claimed the admin console by signing in to it with its ' +
                    'password; until it has, its roles open the console ' +
                    'alone. Sign in to /admin with the password first' };
    }
    const holdsOne = roles.some(function (role) {
      return CONSOLE_ROLES.indexOf(role) >= 0;
    });
    if (!holdsOne) {
      log.debug("Leaving DebuggerAccess.isAdministrator(). Holds no console " +
                "role.");
      return { allowed: false, code: 'STS-DBG-0009', roles: roles,
               why: name + ' holds neither Admin Read nor Admin Write in the ' +
                    'default realm, and the debugger is for console ' +
                    'administrators' };
    }
    const policy = realms.run(realms.get(realms.DEFAULT_ID), function () {
      return accessGate.check({
        resource: accessGate.RESOURCE.DEBUGGER,
        action: accessGate.ACTION.READ,
        requiredRoles: CONSOLE_ROLES.slice(0),
        subject: { name: name, authenticated: true, roles: roles,
                   sessionId: who.sessionId || '' },
        context: { path: String(who.path || '') }
      });
    });
    if (!policy.allowed) {
      log.debug("Leaving DebuggerAccess.isAdministrator(). The policy " +
                "refused.");
      return { allowed: false, code: 'STS-DBG-0009', roles: roles,
               why: policy.why };
    }
    log.debug("Leaving DebuggerAccess.isAdministrator(). Allowed.");
    return { allowed: true, roles: roles, why: '' };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DebuggerAccess>(
  'debugger/debugger_access',
  () => new DebuggerAccess(DebuggerAccess.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * Who may use the embedded protocol debugger, decided in one place.
 *
 * The functions forward to the DebuggerAccess instance the composition root
 * installs.
 * @namespace
 */
export = {
  DebuggerAccess: DebuggerAccess,
  /** Installs the instance the composition root built. */
  installInstance: (instance: DebuggerAccess): void => slot.install(instance),
  /** Says where the installed instance came from. */
  instanceOrigin: (): string => slot.origin(),
  UI_CLIENT_ID: UI_CLIENT_ID,
  RETIRED_API_IDENTIFIER: RETIRED_API_IDENTIFIER,
  CONSOLE_ROLES: CONSOLE_ROLES,
  isAdministrator: slot.forward('isAdministrator')
};
