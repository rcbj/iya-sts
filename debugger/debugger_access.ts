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
// at the two moments it has to be:
//
//   * **WHEN THE SCOPE WOULD BE ISSUED.** The debugger's api is a resource
//     server with one delegated permission, `urn:sts:debugger-api:debugger`.
//     `oauth-oidc/oauth2.ts` hands every scope it is about to grant through
//     `narrowScope()`, and the permission is taken off the grant for anybody
//     who may not hold it. Taken off rather than refused: RFC 6749 section 3.3
//     lets an authorization server issue less than was asked for, and the
//     debugger's own sign-in then reports "not an administrator" rather than
//     an error from a flow the person did nothing wrong in.
//   * **ON EVERY CALL THE GATE FORWARDS.** `debugger/debugger_server.ts` asks
//     `isAdministrator()` again for the token's subject, because a console
//     role revoked after a token was minted must stop working before that
//     token runs out.
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

// THE PERMISSION, AND WHY ITS BASE IS A URN RATHER THAN THE DEBUGGER'S ADDRESS.
//
// `applications.js` joins a resource's `oauthPermissionBaseUri` and a
// permission name into the scope value a client asks for, and that base
// becomes the access token's `aud`. An address would make the scope depend on
// which host name somebody reached the debugger by — `localhost` and
// `127.0.0.1` would be two permissions, one of them matching nothing, and the
// token for the other addressed to a resource that does not exist. A URN is
// the same string everywhere the service is deployed, which is what a
// permission identifier has to be. Microsoft Entra ID's `api://` is the same
// idea.
const PERMISSION_BASE = 'urn:sts:debugger-api:';
const PERMISSION_NAME = 'debugger';
const PERMISSION_ID = PERMISSION_BASE + PERMISSION_NAME;

// The two seeded applications. The UI is the client a person signs in through;
// the api is the resource server that exposes the permission.
const UI_CLIENT_ID = 'sts-debugger-ui';
const API_IDENTIFIER = 'sts-debugger-api';

// The console roles, as `admin_rbac.rolesOf()` names them. Either is enough.
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

class DebuggerAccess {
  constructor(private readonly deps: DebuggerAccessDeps) {
    deps.log.debug("Entering DebuggerAccess.constructor().");
    deps.log.debug("Leaving DebuggerAccess.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
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
  // `{ allowed, why, code, roles }`. `kind` is the issuance subject's — a
  // `client_credentials` grant's subject is an application, and an application
  // is never a debugger user, because the debugger is a PERSON's tool and rcbj
  // chose that no machine client holds the permission.
  // ---------------------------------------------------------------------------
  isAdministrator(subject) {
    const { log, realms, adminRbac, accessGate } = this.deps;
    log.debug("Entering DebuggerAccess.isAdministrator().");
    const who = subject || {};
    const name = String(who.name || '').trim();
    if (who.kind && who.kind !== 'user') {
      log.debug("Leaving DebuggerAccess.isAdministrator(). Not a person.");
      return { allowed: false, code: 'STS-DBG-0001', roles: [],
               why: 'the subject is an application, and the debugger ' +
                    'permission is issued to people only' };
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

  // Whether a space-delimited scope carries the permission.
  asksForPermission(scope) {
    const { log } = this.deps;
    log.debug("Entering DebuggerAccess.asksForPermission().");
    const asked = String(scope || '').split(/\s+/).indexOf(PERMISSION_ID) >= 0;
    log.debug("Leaving DebuggerAccess.asksForPermission(). " + asked);
    return asked;
  }

  // ---------------------------------------------------------------------------
  // narrowScope(scope, subject, context)
  //
  // The scope to GRANT: `scope` unchanged unless it names the debugger
  // permission for somebody who may not hold it, in which case that one value
  // is removed and the rest are left exactly as they were. `context` is
  // `{ clientId, grant }`, for the log and the audit row.
  //
  // **THE REALM IS PART OF THE RULE.** The permission is defined in the default
  // realm only, and the console roster is the default realm's — so in another
  // realm the value is taken off whoever asks. A person in `acme` who shares a
  // name with a default-realm administrator is somebody else.
  // ---------------------------------------------------------------------------
  narrowScope(scope, subject, context) {
    const { log, realms, audit } = this.deps;
    log.debug("Entering DebuggerAccess.narrowScope().");
    if (!this.asksForPermission(scope)) {
      log.debug("Leaving DebuggerAccess.narrowScope(). The permission was " +
                "not asked for.");
      return String(scope == null ? '' : scope);
    }
    const ctx = context || {};
    const inDefault = realms.currentId() === realms.DEFAULT_ID;
    const answer = inDefault
      ? this.isAdministrator(subject)
      : { allowed: false, code: 'STS-DBG-0001',
          why:
            'the debugger permission exists in the default realm only, and ' +
               'this request is in the realm "' + realms.currentId() + '"' };
    if (answer.allowed) {
      log.debug("Leaving DebuggerAccess.narrowScope(). Granted.");
      return String(scope);
    }
    const kept = String(scope).split(/\s+/).filter(function (one) {
      return one && one !== PERMISSION_ID;
    }).join(' ');
    const name = String((subject && subject.name) || '');
    // ONE line in the log, and it is the audit row's: `audit.js` writes a row
    // carrying an errorCode to the log itself, so a tagged log line here too
    // would be the same refusal twice.
    // The empty roster has a code of its own, because what an operator does
    // about it is different: grant somebody a role, rather than find out why
    // this person does not hold one.
    audit.failure(answer.code === 'STS-DBG-0024' ? 'STS-DBG-0024'
                                                 : 'STS-DBG-0001', {
      actor: name,
      protocol: 'OAuth 2.0 / OIDC',
      channel: 'http',
      target: PERMISSION_ID,
      outcome: 'refused',
      summary: 'the debugger permission was not granted to ' +
               (name || 'an unnamed subject') + ': ' + answer.why,
      detail: { client_id: String(ctx.clientId || ''),
                grant: String(ctx.grant || ''), why: answer.why }
    });
    log.debug("Leaving DebuggerAccess.narrowScope(). Taken off.");
    return kept;
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

export = {
  DebuggerAccess: DebuggerAccess,
  installInstance: (instance: DebuggerAccess): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PERMISSION_BASE: PERMISSION_BASE,
  PERMISSION_NAME: PERMISSION_NAME,
  PERMISSION_ID: PERMISSION_ID,
  UI_CLIENT_ID: UI_CLIENT_ID,
  API_IDENTIFIER: API_IDENTIFIER,
  CONSOLE_ROLES: CONSOLE_ROLES,
  isAdministrator: slot.forward('isAdministrator'),
  asksForPermission: slot.forward('asksForPermission'),
  narrowScope: slot.forward('narrowScope')
};
