// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: role_permissions.ts
//
// ===========================================================================
// A SCOPE IS A REQUEST; A ROLE IS WHAT AUTHORIZES IT (#303, part B of #88,
// 2026-09-27).
//
// #88's rule, in one sentence: an OAuth scope never grants authorization by
// itself. It names what a client is ASKING for. Whether it is issued is the
// SUBJECT's authorization — a person's, or an application's own on
// `client_credentials` — and a role is where that authorization is written
// down: `rolePermission` on a role entry names the permissions a holder may
// be issued (`common/roles.js`).
//
// **WHICH PERMISSIONS THIS APPLIES TO IS THE RESOURCE'S CHOICE (#88 decision
// 1).** Two kinds:
//
//   * NATIVE permissions of this service, named in its own convention rather
//     than as base + name (rcbj's decision 1 on #303): `admin:read` and
//     `admin:write`, authorized by the two console roles ADMIN_READ and
//     ADMIN_WRITE. Always gated — the management API is this service's own
//     resource and it opted in by being written this way.
//   * APPLICATION permissions — a resource's `oauthPermissionBaseUri` +
//     `oauthPermission` name — gated only where that resource lists the name
//     in `oauthRoleGatedPermission`. Every other scope, `openid` and a
//     permission nobody gated among them, is issued under the rules it
//     always had.
//
// **NARROWED, NOT REFUSED — until nothing is left (#88 decision 2).** RFC
// 6749 section 3.3 lets an authorization server issue less than was asked
// for, and the token response's `scope` says what was. A gated permission
// the subject's roles do not authorize is taken off and audited
// (STS-ADMIN-0821); a request that asked for nothing else is refused
// `invalid_scope` (STS-ADMIN-0822) by its caller, in its own protocol shape.
//
// **WHICH ROLES A SUBJECT HOLDS is `roles.rolesOf()`'s answer — with one
// exception, the console roles for a PERSON (rcbj's decision 2 on #303).**
// ADMIN_READ and ADMIN_WRITE are held by people through the console roster,
// `admin-ui/admin_rbac.ts`, which is the same answer the console's own gate
// gets: development's open console grants both (the API is the console's
// machine door, rule 7), and the bootstrap administrator before its claim in
// product holds neither — its roles open the console alone, from a password
// session, and at issuance a subject is a name (#103). An APPLICATION holds
// them as it holds any role, by being a member (decision 3): declaring the
// scope is no longer enough.
//
// **AND IT IS ASKED AGAIN WHERE A TOKEN IS USED (decision 4).**
// `mgmt-api/admin_api.ts`'s gate passes the access-control policy the roles
// the token's subject holds NOW, less any role whose permissions the token
// does not carry — held ∩ carried — so a role revoked after the token was
// minted stops working at once rather than when the token expires, and a
// token carrying only `admin:read` does not become Admin Write because its
// subject holds that too (`effectiveRoles()`). The XACML document is
// unchanged: it still asks for ADMIN_READ or ADMIN_WRITE.
//
// **AND THE PIP ASKS IT FOR A SUBJECT NO TOKEN CAME WITH.** A SAML assertion,
// a Kerberos ticket or a client_id carries no scopes; a policy deciding on
// roles for one gets them from `xacml/xacml_pip.ts`, which answers the role
// designator with `configuredRolesOf()` — so the remote PEP decides on the
// same roles issuance does.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers nothing, and everything it requires is a
// library: `roles.js` (a leaf), `applications.js`, `realms.js`, `audit.js`,
// and `admin-ui/admin_rbac.ts`, which `common/cert_enrollment.ts` and
// `debugger/debugger_access.ts` require the same way. So `oauth2.ts` at 9,
// `mgmt-api/admin_api.ts` at 19 and `xacml/xacml_pip.ts` at 23c require it
// without moving a route or closing a cycle.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50) — `debugger/debugger_access.ts`'s shape: the
// modules it uses arrive through its constructor, the composition root
// builds the instance, and the exports below are facades forwarding to it.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
const { log } = helpers;
import realms = require('./realms');
import roles = require('./roles');
import applications = require('./applications');
import audit = require('./audit');
import adminRbac = require('../admin-ui/admin_rbac');

const NARROWED_CODE = 'STS-ADMIN-0821';
const EMPTIED_CODE = 'STS-ADMIN-0822';
const WITHDRAWN_CODE = 'STS-API-0125';

interface RolePermissionsDeps {
  log: typeof log;
  realms: typeof realms;
  roles: typeof roles;
  applications: typeof applications;
  audit: typeof audit;
  adminRbac: typeof adminRbac;
}

// Who a decision is about: `roles.rolesOf()`'s context, less the scopes.
interface Subject {
  kind?: string;
  name?: string;
  authenticated?: boolean;
}

// What `heldRoles()` answers.
interface Held {
  // Every role the subject holds: the built-in ones that apply and the
  // configured ones.
  all: string[];
  // The configured ones alone — what can authorize a permission.
  configured: string[];
  // Why a console role a person might expect is not held; '' otherwise.
  why: string;
}

// What `narrowScope()` answers.
interface Narrowed {
  // The scope to grant.
  scope: string;
  // The gated permissions taken off, in the order they were asked for.
  removed: string[];
  // True when something was taken off and nothing at all is left.
  emptied: boolean;
  // Why, for an error_description; '' when nothing was taken off.
  why: string;
}

class RolePermissions {
  constructor(private readonly deps: RolePermissionsDeps) {
    deps.log.debug("Entering RolePermissions.constructor().");
    deps.log.debug("Leaving RolePermissions.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): RolePermissionsDeps {
    helpers.log.debug("Entering RolePermissions.defaultDeps().");
    helpers.log.debug("Leaving RolePermissions.defaultDeps().");
    return { log: log, realms: realms, roles: roles,
             applications: applications, audit: audit, adminRbac: adminRbac };
  }

  // The values of a space-delimited scope.
  static split(scope: unknown): string[] {
    helpers.log.debug("Entering RolePermissions.split().");
    helpers.log.debug("Leaving RolePermissions.split().");
    return String(scope == null ? '' : scope).split(/\s+/).filter(Boolean);
  }

  // Run `fn` in the named realm, or in the ambient one when none is named or
  // the name is not a realm.
  private inRealm<T>(realmId: string | undefined, fn: () => T): T {
    const { log, realms } = this.deps;
    log.debug("Entering RolePermissions.inRealm().");
    const realm = realmId ? realms.get(realmId) : null;
    log.debug("Leaving RolePermissions.inRealm().");
    return realm ? realms.run(realm, fn) : fn();
  }

  // ---------------------------------------------------------------------------
  // isGated(value) — whether a requested scope value is a permission that
  // needs a role: a native one (a console role's permission), or an
  // application permission its resource listed in `oauthRoleGatedPermission`.
  // Asked in the ambient realm, whose registry defines the permission.
  // ---------------------------------------------------------------------------
  isGated(value: string): boolean {
    const { log, roles, applications } = this.deps;
    log.debug("Entering RolePermissions.isGated().");
    const native = roles.CONSOLE_ROLES.some(function (row) {
      return row.permission === value;
    });
    if (native) {
      log.debug("Leaving RolePermissions.isGated(). Native.");
      return true;
    }
    let found = null;
    try {
      found = applications.roleGatingFor(value);
    } catch (e) {
      // A registry that cannot be read gates nothing new: the permission is
      // then issued under the rules it always had, which is what an ungated
      // one is. Recorded, because a gate silently open is worth seeing.
      log.debug("Caught in RolePermissions.isGated(): " +
                ((e && e.message) || e));
      found = null;
    }
    const gated = !!(found && found.gated);
    log.debug("Leaving RolePermissions.isGated(). " + gated);
    return gated;
  }

  // Whether any value of a scope is gated — the cheap test every grant takes
  // before anything is looked up.
  asksForGated(scope: unknown): boolean {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering RolePermissions.asksForGated().");
    const asked = RolePermissions.split(scope).some(function (one) {
      return self.isGated(one);
    });
    log.debug("Leaving RolePermissions.asksForGated(). " + asked);
    return asked;
  }

  // ---------------------------------------------------------------------------
  // heldRoles(subject, realmId) — the roles the subject holds NOW, in the
  // named realm (the ambient one by default). See the header for the console
  // roles and a person.
  // ---------------------------------------------------------------------------
  heldRoles(subject: Subject, realmId?: string): Held {
    const { log, roles, adminRbac, realms } = this.deps;
    log.debug("Entering RolePermissions.heldRoles().");
    const who = subject || {};
    const name = String(who.name || '').trim();
    const kind = who.kind === 'application' ? 'application' : 'user';
    return this.inRealm(realmId, function () {
      const everything = roles.rolesOf({ kind: kind, name: name,
                                         authenticated: who.authenticated !==
                                                        false });
      const builtIn = everything.filter(function (one) {
        return roles.isBuiltIn(one);
      });
      if (!name || (kind === 'user' && who.authenticated === false)) {
        log.debug("Leaving RolePermissions.heldRoles(). Nobody, or not " +
                  "authenticated: no configured role.");
        return { all: builtIn, configured: [],
                 why: name ? name + ' did not authenticate'
                           : 'nobody is named as the subject' };
      }
      let configured = everything.filter(function (one) {
        return !roles.isBuiltIn(one);
      });
      let why = '';
      if (kind === 'user') {
        // THE CONSOLE ROLES FROM THE ROSTER, replacing whatever the groups
        // alone answered — see the header.
        configured = configured.filter(function (one) {
          return !roles.isConsoleRole(one);
        });
        let roster = null;
        try {
          roster = adminRbac.rolesOf(name, realms.currentId());
        } catch (e) {
          // A roster that cannot be read grants no console role: this is the
          // door to the management API, and it does not open because the
          // directory failed.
          log.debug("Caught in RolePermissions.heldRoles(): " +
                    ((e && e.message) || e));
          roster = null;
        }
        if (roster && roster.claimPending === true) {
          why = name + ' is the bootstrap administrator and has not yet ' +
                'claimed the admin console by signing in to it with its ' +
                'password; until it has, its roles open the console alone';
        } else if (roster) {
          roles.CONSOLE_ROLES.forEach(function (row) {
            if (roster[row.consoleRole] === true) {
              configured.push(row.name);
            }
          });
          if (!roster.read) {
            why = name + ' holds neither Admin Read nor Admin Write on the ' +
                  'console roster of the realm "' + realms.currentId() + '"';
          } else if (!roster.write) {
            why = name + ' holds Admin Read but not Admin Write on the ' +
                  'console roster of the realm "' + realms.currentId() + '"';
          }
        } else {
          why = 'the console roster of the realm "' + realms.currentId() +
                '" could not be read';
        }
      }
      log.debug("Leaving RolePermissions.heldRoles(). " +
                (configured.join(', ') || 'no configured role'));
      return { all: builtIn.concat(configured), configured: configured,
               why: why };
    });
  }

  // The configured roles of a subject, for the PIP's role designator. The
  // built-in ones are left out: they are facts about the REQUEST (who
  // authenticated, over what) that a PIP naming a subject cannot know, and
  // the PEP asserts them where it can.
  configuredRolesOf(subject: Subject, realmId?: string): string[] {
    const { log } = this.deps;
    log.debug("Entering RolePermissions.configuredRolesOf().");
    const held = this.heldRoles(subject, realmId).configured;
    log.debug("Leaving RolePermissions.configuredRolesOf(). " + held.length);
    return held;
  }

  // What each configured role authorizes, by name, in the ambient realm: the
  // register's `rolePermission` (a console role's is fixed there).
  private permissionsByRole(): Record<string, string[]> {
    const { log, roles } = this.deps;
    log.debug("Entering RolePermissions.permissionsByRole().");
    const out: Record<string, string[]> = {};
    roles.all().forEach(function (row) {
      out[row.name] = row.permissions.slice(0);
    });
    // A console role authorizes its permission even in a realm whose entry
    // was deleted by hand: for a person it is held through the roster, and
    // the roster's answer must not depend on the entry being there.
    roles.CONSOLE_ROLES.forEach(function (row) {
      out[row.name] = [row.permission];
    });
    log.debug("Leaving RolePermissions.permissionsByRole().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // narrowScope(scope, subject, context)
  //
  // The scope to GRANT, with every gated permission the subject's roles do
  // not authorize taken off and recorded (one audit row, STS-ADMIN-0821).
  // `context` is `{ clientId, grant }`, for the row. A scope naming nothing
  // gated comes back unchanged.
  // ---------------------------------------------------------------------------
  narrowScope(scope: unknown, subject: Subject, context?: any): Narrowed {
    const { log, audit } = this.deps;
    const self = this;
    log.debug("Entering RolePermissions.narrowScope().");
    const asked = String(scope == null ? '' : scope);
    const unchanged: Narrowed = { scope: asked, removed: [], emptied: false,
                                  why: '' };
    const values = RolePermissions.split(asked);
    const gated = values.filter(function (one) {
      return self.isGated(one);
    });
    if (!gated.length) {
      log.debug("Leaving RolePermissions.narrowScope(). Nothing gated.");
      return unchanged;
    }
    const who = subject || {};
    const held = this.heldRoles(who);
    const authorizes = this.permissionsByRole();
    const removed = gated.filter(function (permission) {
      return !held.configured.some(function (role) {
        return (authorizes[role] || []).indexOf(permission) >= 0;
      });
    });
    if (!removed.length) {
      log.debug("Leaving RolePermissions.narrowScope(). Authorized.");
      return unchanged;
    }
    const kept = values.filter(function (one) {
      return removed.indexOf(one) < 0;
    });
    const ctx = context || {};
    const name = String(who.name || '');
    const reason = held.why ||
      (name || 'an unnamed subject') + ' holds no role authorizing ' +
      removed.join(', ') + (held.configured.length
        ? ' (holds ' + held.configured.join(', ') + ')' : '');
    // ONE line in the log, and it is the audit row's: `audit.js` writes a row
    // carrying an errorCode to the log itself.
    audit.failure('STS-ADMIN-0821', {
      actor: name,
      protocol: 'OAuth 2.0 / OIDC',
      channel: 'http',
      target: removed.join(' '),
      outcome: 'refused',
      summary: 'the permission(s) ' + removed.join(', ') + ' were not ' +
               'issued to ' + (who.kind === 'application' ? 'the ' +
               'application ' : '') + (name || 'an unnamed subject') + ': ' +
               reason,
      detail: { client_id: String(ctx.clientId || ''),
                grant: String(ctx.grant || ''),
                subject_kind: who.kind === 'application' ? 'application'
                                                         : 'user',
                removed: removed.join(' '), why: reason }
    });
    log.debug("Leaving RolePermissions.narrowScope(). " + removed.length +
              " taken off.");
    return { scope: kept.join(' '), removed: removed,
             emptied: kept.length === 0,
             why: 'the permission(s) ' + removed.join(', ') + ' cannot be ' +
                  'issued: ' + reason };
  }

  // Whether an access token's claims are a CLIENT's own (client_credentials):
  // the two spellings of its subject that `oauth2.ts` mints — the bare
  // client_id, and `urn:sts:client:<id>` in RFC 9700 mode.
  isClientToken(claims: any): boolean {
    const { log } = this.deps;
    log.debug("Entering RolePermissions.isClientToken().");
    const c = claims || {};
    const clientId = String(c.client_id || '');
    const sub = String(c.sub || '');
    const answer = !!clientId &&
                   (sub === clientId || sub === 'urn:sts:client:' + clientId);
    log.debug("Leaving RolePermissions.isClientToken(). " + answer);
    return answer;
  }

  // ---------------------------------------------------------------------------
  // effectiveRoles(claims, carried, tokenRealm)
  //
  // `{ roles, withdrawn, why, subject }` for a resource server holding a
  // verified access token — `/admin-api`'s gate. `roles` is what the policy
  // decides on: the built-in roles the subject holds (DEVICE_COMPLIANCE read
  // off `carried`), and each configured role it holds NOW in the realm that
  // issued the token that either authorizes no permission (a role that is
  // only an identity) or authorizes one the token carries. `withdrawn` is
  // every gated permission the token carries that no held role authorizes
  // any longer.
  // ---------------------------------------------------------------------------
  effectiveRoles(claims: any, carried: string[], tokenRealm: string):
      { roles: string[]; withdrawn: string[]; why: string;
        subject: Subject } {
    const { log, roles } = this.deps;
    const self = this;
    log.debug("Entering RolePermissions.effectiveRoles().");
    const c = claims || {};
    const scopes = (carried || []).slice(0);
    const client = this.isClientToken(c);
    const subject: Subject = client
      ? { kind: 'application', name: String(c.client_id || ''),
          authenticated: true }
      : { kind: 'user', authenticated: true,
          name: String(c.username || c.preferred_username || c.sub || '') };
    return this.inRealm(tokenRealm, function () {
      const held = self.heldRoles(subject);
      const builtIn = roles.rolesOf({ kind: subject.kind, name: subject.name,
                                      authenticated: true, scopes: scopes })
        .filter(function (one) {
          return roles.isBuiltIn(one);
        });
      const authorizes = self.permissionsByRole();
      const effective = held.configured.filter(function (role) {
        const permissions = authorizes[role] || [];
        return !permissions.length || permissions.some(function (one) {
          return scopes.indexOf(one) >= 0;
        });
      });
      const withdrawn = scopes.filter(function (one) {
        return self.isGated(one) && !held.configured.some(function (role) {
          return (authorizes[role] || []).indexOf(one) >= 0;
        });
      });
      log.debug("Leaving RolePermissions.effectiveRoles(). " +
                effective.length + " configured, " + withdrawn.length +
                " withdrawn.");
      return { roles: builtIn.concat(effective), withdrawn: withdrawn,
               why: held.why || (subject.name + ' holds no role authorizing ' +
                                 withdrawn.join(', ')),
               subject: subject };
    });
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `common/instance_slot.ts`. The exports below are FACADES for the
// JavaScript that calls this module through `require()`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<RolePermissions>(
  'common/role_permissions',
  () => new RolePermissions(RolePermissions.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module always did.
slot.buildNowUnlessDeferred();

export = {
  RolePermissions: RolePermissions,
  installInstance: (instance: RolePermissions): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  NARROWED_CODE: NARROWED_CODE,
  EMPTIED_CODE: EMPTIED_CODE,
  WITHDRAWN_CODE: WITHDRAWN_CODE,
  split: RolePermissions.split,
  isGated: slot.forward('isGated'),
  asksForGated: slot.forward('asksForGated'),
  heldRoles: slot.forward('heldRoles'),
  configuredRolesOf: slot.forward('configuredRolesOf'),
  narrowScope: slot.forward('narrowScope'),
  isClientToken: slot.forward('isClientToken'),
  effectiveRoles: slot.forward('effectiveRoles')
};
