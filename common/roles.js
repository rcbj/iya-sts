// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: roles.js
//
// ---------------------------------------------------------------------------
// ROLES: THE ONE THING IN THIS SERVICE A USER, A GROUP AND AN APPLICATION ARE
// ALL FIRST-CLASS MEMBERS OF.
//
// A role is a NAME somebody may hold. Three kinds of directory object can be
// mapped into one — a person, a group (so every member of it holds the role),
// and an application (so a client authenticating as itself holds it) — and
// that third one is the part that is unusual and is the point: a
// `client_credentials` grant has no person in it at all, and until an
// application could hold a role there was nothing to decide about one.
//
// WHAT A ROLE IS FOR, in two sentences that are deliberately separate:
//
//   * It is CARRIED. Every access token, ID Token, SAML 2.0 assertion and
//     SAML 1.1 assertion this service issues can name the roles its subject
//     holds, in a claim of its own (`roles.claim`). A relying party reads it.
//   * It is ENFORCED. An application entry names the roles it REQUIRES, and
//     nothing is issued for that application to somebody who holds none of
//     them — a decision made by the XACML PDP through the embedded PEP in
//     `xacml/xacml_role_pep.ts`, never by an `if` in an issuance site.
//
// THOSE ARE TWO DIFFERENT RELATIONS AND THIS FILE KEEPS THEM APART, because
// collapsing them is the mistake that makes the whole feature unreadable:
//
//   MEMBERSHIP   role -> users, groups, applications that HOLD it.
//                Stored on the ROLE entry, edited at /admin/roles.
//   REQUIREMENT  application -> roles it DEMANDS before anything is issued.
//                Stored on the APPLICATION entry (`appRequiredRole`), edited
//                on the application's own page.
//
// An application appears in both and means opposite things in each: in the
// first it HOLDS the role, in the second it DEMANDS it. `app_permissions.js`
// draws the same line between what MAY happen and what DID; this one is
// between what somebody IS and what somebody ASKS OF OTHERS.
//
// ---------------------------------------------------------------------------
// SIX ROLES ARE BUILT IN, COMPUTED, AND IN NO CONTAINER — TEN BY NOW.
//
// They cannot be created, edited or deleted, they have no members to list, and
// every one of them is answered from the CONTEXT of the request being decided
// rather than from a store. The six this file was written with:
//
//   EVERYBODY                        anybody at all, authenticated or not.
//   ALL_AUTHENTICATED_USERS          a person with a live session here.
//   ALL_UNAUTHENTICATED_USERS        a person without one.
//   ALL_APPLICATIONS                 any client, however it turned up.
//   ALL_AUTHENTICATED_APPLICATIONS   a client that proved who it is — a
//                                    secret, a private_key_jwt assertion or a
//                                    verified client certificate.
//   ALL_UNAUTHENTICATED_APPLICATIONS a public client that proved nothing.
//
// **EVERYBODY IS WHAT MAKES THIS FEATURE OFF BY DEFAULT WITHOUT BEING ABSENT.**
// An application that names no required role is treated as requiring
// EVERYBODY, everybody holds EVERYBODY, so the decision is Permit and the
// service behaves exactly as it did before any of this existed. That is a
// better default than "no roles configured means do not ask", because the
// machinery is then always running and always visible: the console shows the
// decision, the audit log records it, and turning enforcement on for an
// application is narrowing a list rather than switching on a subsystem that
// has never run.
//
// The others — REMOTE_PEPS and XACML_USER (held through a named group) — are
// argued at their rows in `BUILT_IN` below. ADMIN_READ and ADMIN_WRITE were
// built-ins read off the scopes until #303 (2026-09-27), and DEVICE_COMPLIANCE
// until #309 (2026-09-28): all three are CONFIGURED roles now, authorizing
// their native permission — see THE NATIVE ROLES, below the table. No role is
// read off a scope any more.
//
// ---------------------------------------------------------------------------
// A ROLE AUTHORIZES PERMISSIONS (#303, part B of #88, 2026-09-27).
//
// A third relation, stored on the ROLE entry beside its members because
// rcbj decided it lives there: `rolePermission` names the permissions a
// holder of the role may be ISSUED. A permission is named the way a client
// asks for it — a generic application permission by its full scope value
// (`https://api.example/write`, base + name), and a NATIVE one of this
// service by its own name (`admin:read`, `admin:write`), which rcbj chose to
// keep rather than re-spell. #88's rule is that a scope never grants
// authorization by itself: it is a REQUEST, and the role is what authorizes
// it. Which permissions need a role at all is the resource application's
// choice (`oauthRoleGatedPermission`, #88 decision 1) — a permission nobody
// gated is issued under the rules it always had — and the question is asked
// in `common/role_permissions.ts`, not here: this file stays the leaf.
//
// The pairs are deliberately NOT complementary by accident — they are
// complementary on purpose, and both halves exist because "everyone who did
// not sign in" is a thing policy authors reach for and cannot express as a
// negation in a XACML target.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3), A LEAF, AND THAT IS LOAD-BEARING.
//
// It registers no route, so its place in the route order is not a place. It
// requires `helpers.js` and `config.js` and NOTHING ELSE in this repository —
// which is what lets `admin_stats.js` require it in the ORDINARY DIRECTION for
// the roles claim, rather than offering it a fifth inverted hook. CLAUDE.md
// rule 3e is explicit that a slot is what you reach for when a require would
// close a cycle or move a route, and that a fifth must not be added by
// analogy with the fourth: here a plain require works, so a plain require is
// what is used. **Do not make this file require `admin_stats.js`.** The moment
// it does, that argument is gone and a slot is the only way back.
//
// The DIRECTORY arrives through a slot pointing the other way, exactly as
// `group_claims.js`, `applications.js` and `xacml_store.js` do it: only
// `ldap/ldap_server.js` can answer what is in `ou=roles`, and it is required
// at 21 in `common/protocol_stack.ts`, so a require reaching it from here
// would drag every `/ldap` route to the front of the router.
// ---------------------------------------------------------------------------

const { log } = require('./helpers');
const config = require('./config');
// The error-code registry. A LEAF that requires nothing here, so this file
// stays one (the header argues why that matters). A refusal's code is marked on
// the RESULT OBJECT as a non-enumerable property — the caller that answers the
// request reads it back with `errorCodes.codeOf()`, and no serialisation of the
// result can carry it to a client.
const errorCodes = require('./error_codes');

// ---------------------------------------------------------------------------
// THE SCHEMA. Published on `/admin/ldap/roles` the way every other container's
// is, because this directory is schemaless and a container of entries carrying
// invented attributes has to say what they mean somewhere.
// ---------------------------------------------------------------------------
/**
 * The `ou=roles` schema published on `/admin/ldap/roles`: the `stsRole`
 * object class and what each of its attributes means.
 */
const SCHEMA = {
  objectClasses: [
    { name: 'stsRole',
      what: 'One ROLE. The entry is named by the role name (`cn=staff`), and ' +
            'everything on it is MEMBERSHIP — who holds the role. What a ' +
            'role is REQUIRED for lives on the application entry that ' +
            'requires it, in `appRequiredRole`, because that is a fact about ' +
            'the application rather than about the role.' }
  ],
  attributes: [
    { name: 'roleName',
      what: 'The role name, which is also the `cn`. Carried explicitly as ' +
            'well so that a reader who has only the attributes has the name.' },
    { name: 'roleMemberUser',
      what: 'A username that holds this role. Multi-valued. The person need ' +
            'not exist yet — this service creates a directory entry for any ' +
            'name on first sight, so a role may be granted before its holder ' +
            'has ever signed in.' },
    { name: 'roleMemberGroup',
      what: 'A group whose every member holds this role. Multi-valued. ' +
            'Resolved at DECISION TIME rather than expanded on write, so an ' +
            '`ldapmodify` adding somebody to the group changes the very next ' +
            'token.' },
    { name: 'roleMemberApplication',
      what: 'An application that holds this role AS ITSELF — what a ' +
            'client_credentials grant is decided on, where there is no ' +
            'person. Multi-valued. NOT the same relation as ' +
            '`appRequiredRole` on the application entry, which is what that ' +
            'application DEMANDS of others.' },
    { name: 'rolePermission',
      what: 'A permission a holder of this role may be ISSUED (#303). ' +
            'Multi-valued. Named as a client asks for it: a generic ' +
            'application permission by its full scope value — the resource ' +
            'application\'s `oauthPermissionBaseUri` followed by the name — ' +
            'and a native permission of this service by its own name ' +
            '(`admin:read`, `admin:write`). It matters only for a permission ' +
            'its resource application GATES (`oauthRoleGatedPermission`); ' +
            'a gated permission is issued only to a subject holding a role ' +
            'that names it, and an ungated one as it always was.' },
    { name: 'roleApplication',
      what: 'The ONE application this role belongs to (#310), by its ' +
            'identifier in ou=applications; absent, the role is realm-wide. ' +
            'An application\'s role is named `<role>@<application>` in the ' +
            'register, so two applications may each have a `reader`; a token ' +
            'or assertion for that application carries it as `<role>`, and ' +
            'no other application\'s token carries it at all. The ' +
            'application\'s `appRequiredRole` may name it by `<role>`.' },
    { name: 'description',
      what: 'What the role is for, for the next person.' }
  ]
};

// ---------------------------------------------------------------------------
// THE BUILT-IN ROLES. SIX WHEN THIS TABLE WAS WRITTEN, SEVEN SINCE 2026-09-06,
// EIGHT SINCE THE XACML SURFACE WAS CLOSED, AND TEN SINCE THE MANAGEMENT
// API'S TWO (2026-09-09).
//
// A table rather than six constants, because three things have to agree about
// them — the console's menus, the resolver below, and the refusal that stops
// somebody creating a role with one of these names — and three copies of a
// list is three chances for one to be missed.
//
// **THE COUNT IS NOT WRITTEN DOWN ANYWHERE THAT MATTERS, AND THAT IS
// DELIBERATE.** `BUILT_IN_NAMES`, `builtInCatalogue()` and `isBuiltIn()` are
// all derived from this array, so adding a row is the whole of adding a role.
// The numbers in the prose around it are the part that goes stale — this
// heading said "six" for the whole of the day REMOTE_PEPS existed.
// ---------------------------------------------------------------------------
/**
 * The built-in roles, computed from the context of a decision rather than
 * stored: each row's `name`, `what` and `holds(context)`.
 *
 * `BUILT_IN_NAMES`, `builtInCatalogue()` and `isBuiltIn()` are derived from
 * this array, so adding a row is the whole of adding a built-in role.
 */
const BUILT_IN = [
  { name: 'EVERYBODY',
    what: 'Anybody at all, authenticated or not, person or application. ' +
          'THIS IS THE DEFAULT REQUIREMENT: an application that names no ' +
          'required role requires this one, everybody holds it, and nothing ' +
          'is refused — which is exactly how this service behaved before ' +
          'roles existed.',
    holds: function () {
      log.debug("Entering holds().");
      log.debug("Leaving holds().");
      return true;
    } },
  { name: 'ALL_AUTHENTICATED_USERS',
    what: 'A person with a live authenticated session in the security ' +
          'context this decision is being made in.',
    holds: function (who) {
      log.debug("Entering holds().");
      log.debug("Leaving holds().");
      return who.kind === 'user' && who.authenticated;
    } },
  { name: 'ALL_UNAUTHENTICATED_USERS',
    what: 'A person who has NOT authenticated. It is not the negation of the ' +
          'role above as far as a policy is concerned — it is a name a ' +
          'target can match, and XACML targets cannot say "not".',
    holds: function (who) {
      log.debug("Entering holds().");
      log.debug("Leaving holds().");
      return who.kind === 'user' && !who.authenticated;
    } },
  { name: 'ALL_APPLICATIONS',
    what: 'Any client, however it turned up.',
    holds: function (who) {
      log.debug("Entering holds().");
      log.debug("Leaving holds().");
      return who.kind === 'application';
    } },
  { name: 'ALL_AUTHENTICATED_APPLICATIONS',
    what: 'A client that PROVED who it is — a secret, a private_key_jwt ' +
          'assertion, or a verified client certificate. A public client that ' +
          'merely sent a client_id is not this.',
    holds: function (who) {
      log.debug("Entering holds().");
      log.debug("Leaving holds().");
      return who.kind === 'application' && who.authenticated;
    } },
  { name: 'ALL_UNAUTHENTICATED_APPLICATIONS',
    what: 'A public client that proved nothing.',
    holds: function (who) {
      log.debug("Entering holds().");
      log.debug("Leaving holds().");
      return who.kind === 'application' && !who.authenticated;
    } },
  // -------------------------------------------------------------------------
  // THE SEVENTH, AND THE FIRST ONE COMPUTED FROM A GROUP (2026-09-06).
  //
  // The six above are computed from what the party IS — a person or a client,
  // authenticated or not — and none of them reads the directory. This one is
  // held by whoever is in one named GROUP, which makes it a hybrid and the
  // hybrid is deliberate:
  //
  //   * it is BUILT IN rather than a row in `ou=roles`, because the surface it
  //     guards (`/xacml/pep/*`) has to be guarded in a realm nobody has
  //     configured. A configured role is absent until somebody makes it, and a
  //     gate that is absent is a gate that is open.
  //   * it is held through a GROUP rather than by name, because the party
  //     holding it is a certificate DN that does not exist until a launcher
  //     mints one — there is no name to write into a role definition in
  //     advance, and there IS a group to put whatever turns up into.
  //
  // **THE GROUP IS THE GRANT AND THE CERTIFICATE IS ONLY THE IDENTITY.** A
  // remote PEP presenting a certificate this service verified is somebody it
  // can NAME; it is not thereby somebody it lets in. Membership of this group
  // is the deliberate act, and a verified certificate whose DN is not in it is
  // refused — which is the whole point of resolving the DN rather than
  // stopping at the handshake.
  // -------------------------------------------------------------------------
  { name: 'REMOTE_PEPS',
    what: 'A remote XACML Policy Enforcement Point: whoever is a member of ' +
          'the group named by `roles.remotePepGroup` (default ' +
          '"remote-peps"). It is what `/xacml/pep/register`, ' +
          '`/xacml/pep/policies` and `/xacml/pep/heartbeat` require, and the ' +
          'party that holds it is normally a client-certificate DN rather ' +
          'than a person — the certificate says WHO, and this group says ' +
          'whether they may.',
    holds: function (who) {
      log.debug("Entering holds().");
      const wanted = remotePepGroupName().toLowerCase();
      if (!wanted) {
        log.debug("Leaving holds().");
        return false;
      }
      log.debug("Leaving holds().");
      return (who.groups || []).some(function (one) {
        return String(one).toLowerCase() === wanted;
      });
    } },
  // -------------------------------------------------------------------------
  // THE EIGHTH, AND THE SECOND COMPUTED FROM A GROUP.
  //
  // **THE ARGUMENT IS MADE AGAIN RATHER THAN CITED, and it comes out in the
  // same place for a different reason.** REMOTE_PEPS is group-derived because
  // the party holding it is a certificate DN that does not exist until a
  // launcher mints one — there is no name to write into a role definition in
  // advance. That reason does NOT apply here: the parties reaching
  // `/xacml/pdp`, `/xacml/policies` and `/xacml/protected` are ordinary
  // callers and some of them are people who already have directory entries.
  //
  // What decides it is the other half of REMOTE_PEPS's argument, and that one
  // does apply, harder: **A CONFIGURED ROLE IS ABSENT UNTIL SOMEBODY MAKES
  // IT.** `ou=roles` is per realm, so a role seeded once in the default realm
  // leaves every realm created afterwards with a XACML surface that either
  // refuses everybody (if the requirement still travels) or admits everybody
  // (if it does not) — and both of those are answers nobody chose. A built-in
  // role is computed, so it exists in a realm nobody has configured, which is
  // the only realm most of them ever are.
  //
  // **SO A GROUP IS THE GRANT AND IT REACHES BOTH THINGS THAT WERE ASKED
  // FOR.** A GROUP is admitted by naming it in `roles.xacmlUserGroup`; a
  // PERSON is admitted by being put in that group, which is one line on
  // `/admin/ldap/directory` and one `ldapmodify` on the raw socket. Neither
  // costs a per-realm entry that can be deleted, and membership is resolved at
  // DECISION TIME, so adding somebody changes the very next request rather
  // than the next restart.
  //
  // **IT IS NOT THE SAME ROLE AS REMOTE_PEPS AND MUST NOT BECOME ONE.** A
  // remote enforcement point pulls the documents this service enforces its own
  // access with; a XACML caller asks a question and reads a demonstration
  // policy. One group granting both would mean admitting somebody to the
  // second silently admits them to the first, which is exactly the collapse
  // the two-register split in this file exists to prevent.
  // -------------------------------------------------------------------------
  { name: 'XACML_USER',
    what: 'A caller of the XACML surface proper: whoever is a member of the ' +
          'group named by `roles.xacmlUserGroup` (default "xacml-users"). ' +
          'It is what `GET /xacml`, `POST /xacml/pdp`, `GET /xacml/policies` ' +
          'and `GET /xacml/protected` require, and the party that holds it ' +
          'is normally a client-certificate DN — the certificate says WHO, ' +
          'and this group says whether they may. It is deliberately NOT ' +
          'REMOTE_PEPS: that role reaches the three /xacml/pep endpoints, ' +
          'which hand out the documents this service enforces its own access ' +
          'with, and one group granting both would make admitting a caller ' +
          'to the demonstration surface silently admit it to those.',
    holds: function (who) {
      log.debug("Entering holds().");
      const wanted = xacmlUserGroupName().toLowerCase();
      if (!wanted) {
        log.debug("Leaving holds().");
        return false;
      }
      log.debug("Leaving holds().");
      return (who.groups || []).some(function (one) {
        return String(one).toLowerCase() === wanted;
      });
    } }
];

// The group that grants REMOTE_PEPS. A setting rather than a constant because
// a deployment that already has a group for its enforcement points should be
// able to name it rather than make a second one — and because naming it '' is
// how somebody turns the role off entirely, which `holds()` above reads as
// "nobody".
function remotePepGroupName() {
  log.debug("Entering remotePepGroupName().");
  log.debug("Leaving remotePepGroupName().");
  return String(config.value('roles.remotePepGroup') || '').trim();
}

// The group that grants XACML_USER, on the same terms and with one extra
// consequence worth stating where somebody will read it before typing: naming
// it '' closes the four XACML endpoints to EVERY caller, including one holding
// a certificate this service verified. That is a supported configuration — it
// is how a deployment turns the surface off without turning `xacml.enabled`
// off and losing the embedded PEPs with it — and it is not a mistake this
// function should second-guess.
function xacmlUserGroupName() {
  log.debug("Entering xacmlUserGroupName().");
  log.debug("Leaving xacmlUserGroupName().");
  return String(config.value('roles.xacmlUserGroup') || '').trim();
}

/**
 * The names of the built-in roles, in table order.
 */
// THE SEPARATOR IN AN APPLICATION ROLE'S NAME (#310): `reader@payroll`.
const APPLICATION_SEPARATOR = '@';

const BUILT_IN_NAMES = BUILT_IN.map(function (one) {
  return one.name;
});

// The default requirement, and the one name in this file that other modules
// hard-code. Exported so that `applications.js`, the console and the XACML PEP
// all mean the same string by "the permissive default".
/**
 * The requirement of an application that names none: EVERYBODY, which
 * everybody holds, so nothing is refused.
 */
const DEFAULT_REQUIRED_ROLE = 'EVERYBODY';

/**
 * Tells whether a role name is one of the built-in, computed roles.
 *
 * @param name - a role name
 * @returns true for a built-in role
 */
function isBuiltIn(name) {
  log.debug("Entering isBuiltIn().");
  log.debug("Leaving isBuiltIn().");
  return BUILT_IN_NAMES.indexOf(String(name)) >= 0;
}

// ---------------------------------------------------------------------------
// THE TWO CONSOLE ROLES (#303, part B of #88, 2026-09-27).
//
// ADMIN_READ and ADMIN_WRITE were BUILT-IN until today and were read off an
// access token's scopes: a token carrying `admin:write` WAS Admin Write. That
// is the pattern #88 exists to remove — a scope granting authorization by
// itself — so they are CONFIGURED roles now, one entry each under
// `ou=roles` in every realm, seeded at startup and when a realm is built,
// and what they AUTHORIZE is the native permission of the same name
// (`rolePermission`). The scope is what a client ASKS for; the role is what
// lets it be issued.
//
// **THEY ARE CONFIGURED ROLES OVER THE CONSOLE'S TWO GROUPS, AND THE CONSOLE
// ROSTER DECIDES WHICH PEOPLE HOLD THEM (rcbj's decision 4 on #88).** Their
// groups are not stored: they are `admin.readGroup` and `admin.writeGroup`,
// read when the entry is read — ADMIN_READ over both, because Admin Write
// implies Admin Read on the roster — so a renamed group cannot leave a stale
// copy here. Membership for a PERSON is answered by the roster
// (`admin-ui/admin_rbac.ts`) in `common/role_permissions.ts`, which is what
// carries development's open console and the bootstrap administrator's claim
// to the API door; this file is a leaf and resolves the groups alone, which
// is the same answer everywhere but those two windows. So `/admin/rbac` is
// the one door for people, and a person or group written onto these entries
// here is refused: two places granting one role would be two answers.
//
// **AN APPLICATION IS AN ORDINARY MEMBER**, and that is what changed for
// machines (decision 3 on #303): a client on `client_credentials` is issued
// `admin:*` only while it holds the role, so declaring the scope in
// `oauthAllowedScope` is no longer enough. `sts-management-api` — the
// machine door every launcher uses — is seeded as a member of both.
//
// They cannot be deleted, and their permission cannot be changed: a realm
// without them could never be administered by a machine, and ADMIN_READ
// authorizing `admin:write` would be the scope-as-authorization mistake
// written into the register instead.
// ---------------------------------------------------------------------------
/**
 * The two console roles, ADMIN_READ and ADMIN_WRITE: configured roles seeded
 * in every realm, each authorizing the native permission of the same name.
 *
 * Their groups are read from the `admin.readGroup` / `admin.writeGroup`
 * settings, never stored; people hold them through the console roster.
 */
const CONSOLE_ROLES = [
  { name: 'ADMIN_READ', consoleRole: 'read', permission: 'admin:read',
    groupSettings: ['admin.readGroup', 'admin.writeGroup'],
    seedApplications: ['sts-management-api'],
    what: 'Admin Read: every READ on /admin-api. Held by the console\'s ' +
          'Admin Read and Admin Write groups (Admin Write implies Admin ' +
          'Read) and by the applications listed here. Authorizes the ' +
          'admin:read permission.' },
  { name: 'ADMIN_WRITE', consoleRole: 'write', permission: 'admin:write',
    groupSettings: ['admin.writeGroup'],
    seedApplications: ['sts-management-api'],
    what: 'Admin Write: every /admin-api operation that CHANGES anything. ' +
          'Held by the console\'s Admin Write group and by the applications ' +
          'listed here. Authorizes the admin:write permission. It does not ' +
          'imply Admin Read on a token: a token may carry either scope, and ' +
          'the policy asks for the one the operation needs.' }
];

// The application the seed puts in both. The management API's own seeded
// client, `common/applications.js`'s `sts-management-api`.
/**
 * The application seeded as a member of both console roles: the management
 * API's own client.
 */
const CONSOLE_ROLE_APPLICATION = 'sts-management-api';

// ---------------------------------------------------------------------------
// THE NATIVE ROLES (#309, a follow-up to #88, 2026-09-28): every role that
// authorizes one of this service's NATIVE permissions — the two console roles
// above, and DEVICE_COMPLIANCE. Each is seeded in every realm, cannot be
// deleted, and authorizes exactly its permission.
//
// **DEVICE_COMPLIANCE WAS THE LAST ROLE READ OFF A SCOPE.** It was built in:
// a token carrying `device:compliance` WAS the MDM feed (#164 phase 3), the
// scope-as-authorization #88 removed for the admin scopes. It is configured
// now, and `device:compliance` is issued to a client on `client_credentials`
// only while that client HOLDS the role. It is an ordinary role otherwise —
// any member kind, edited on /admin/roles — and it is seeded EMPTY (rcbj's
// decision on #309): no client is the MDM feed until an operator adds it,
// and the management API's own client is not, which is the separation #164
// decision 2 made on purpose.
// ---------------------------------------------------------------------------
const NATIVE_ROLES = CONSOLE_ROLES.concat([
  { name: 'DEVICE_COMPLIANCE', consoleRole: '', permission: 'device:compliance',
    groupSettings: [], seedApplications: [],
    what: 'The device compliance feed: an MDM or posture feed reporting a ' +
          'device\'s compliance through POST /admin-api/device-compliance, ' +
          'and nothing else on /admin-api. Authorizes the device:compliance ' +
          'permission. Seeded with no member: add the feed\'s application.' }
]);

function nativeRoleFor(name) {
  log.debug("Entering nativeRoleFor().");
  const wanted = String(name == null ? '' : name);
  log.debug("Leaving nativeRoleFor().");
  return NATIVE_ROLES.filter(function (one) {
    return one.name === wanted;
  })[0] || null;
}

function isNativeRole(name) {
  log.debug("Entering isNativeRole().");
  log.debug("Leaving isNativeRole().");
  return !!nativeRoleFor(name);
}

/**
 * Returns the `CONSOLE_ROLES` row of a role name.
 *
 * @param name - a role name
 * @returns the row, or null when the name is not a console role
 */
function consoleRoleFor(name) {
  log.debug("Entering consoleRoleFor().");
  const wanted = String(name == null ? '' : name);
  log.debug("Leaving consoleRoleFor().");
  return CONSOLE_ROLES.filter(function (one) {
    return one.name === wanted;
  })[0] || null;
}

/**
 * Tells whether a role name is one of the two console roles.
 *
 * @param name - a role name
 * @returns true for ADMIN_READ or ADMIN_WRITE
 */
function isConsoleRole(name) {
  log.debug("Entering isConsoleRole().");
  log.debug("Leaving isConsoleRole().");
  return !!consoleRoleFor(name);
}

// The group names a console role is held through, from the settings.
function consoleRoleGroups(row) {
  log.debug("Entering consoleRoleGroups().");
  const out = [];
  row.groupSettings.forEach(function (key) {
    const group = String(config.value(key) || '').trim();
    if (group && out.indexOf(group) < 0) {
      out.push(group);
    }
  });
  log.debug("Leaving consoleRoleGroups().");
  return out;
}

/**
 * Lists the built-in roles for a menu or a policy author.
 *
 * @returns `{ name, what, builtIn: true }` per built-in role
 */
function builtInCatalogue() {
  log.debug("Entering builtInCatalogue().");
  log.debug("Leaving builtInCatalogue().");
  return BUILT_IN.map(function (one) {
    return { name: one.name, what: one.what, builtIn: true };
  });
}

// ---------------------------------------------------------------------------
// THE DIRECTORY SLOT.
// ---------------------------------------------------------------------------
let directory = null;
let warnedAboutNoDirectory = false;

/**
 * Fills the directory slot through which the register reads and writes
 * `ou=roles`; `ldap/ldap_server.js` fills it.
 *
 * @param hooks - the directory's role hooks (`allRoles`, `writeRole`,
 *   `deleteRole`, `groupsOfUser`), or null
 */
function setDirectory(hooks) {
  log.debug('Entering setDirectory().');
  directory = hooks || null;
  log.debug('Leaving setDirectory(). The role register ' +
            (directory ? 'has its container.' : 'has none.'));
}

// WHAT IS CURRENTLY INSTALLED, so that a test which stubs the slot can put
// back what was there rather than `null` — `xacml_store.js` argues why that
// distinction is not pedantry, and it is the same one process, one reference
// situation here.
/**
 * Returns what the directory slot currently holds, so a test that stubs it
 * can put back what was there.
 *
 * @returns the installed hooks, or null
 */
function directoryInstalled() {
  log.debug("Entering directoryInstalled().");
  log.debug("Leaving directoryInstalled().");
  return directory;
}

function haveDirectory() {
  log.debug("Entering haveDirectory().");
  if (directory && typeof directory.allRoles === 'function') {
    log.debug("Leaving haveDirectory().");
    return true;
  }
  if (!warnedAboutNoDirectory) {
    warnedAboutNoDirectory = true;
    log.warn('roles: the embedded directory was never loaded, so there is no ' +
             'ou=roles to hold a role. The six BUILT-IN roles still answer — ' +
             'they are computed rather than stored — so an application ' +
             'requiring EVERYBODY still admits everybody, which is the ' +
             'default. Only configured roles are missing. There is no ' +
             'fallback store, deliberately: a role register that quietly ' +
             'lived in memory would decide things nobody could find.');
  }
  log.debug("Leaving haveDirectory().");
  return false;
}

// ---------------------------------------------------------------------------
// READING THE REGISTER.
// ---------------------------------------------------------------------------
function firstValue(attributes, name) {
  log.debug("Entering firstValue().");
  const found = attributes[name] || attributes[name.toLowerCase()];
  log.debug("Leaving firstValue().");
  return Array.isArray(found) ? (found[0] || '') : (found || '');
}

function allValues(attributes, name) {
  log.debug("Entering allValues().");
  const found = attributes[name] || attributes[name.toLowerCase()];
  if (!found) {
    log.debug("Leaving allValues().");
    return [];
  }
  log.debug("Leaving allValues().");
  return (Array.isArray(found) ? found : [found]).map(function (one) {
    return String(one).trim();
  }).filter(function (one) {
    return one.length > 0;
  });
}

/**
 * Lists the configured roles in the ambient realm's `ou=roles`, sorted by
 * name.
 *
 * A console role's groups and permission come from the settings and the
 * table, not the entry.
 * @returns one row per role: `name`, `dn`, `description`, `users`, `groups`,
 *   `applications`, `permissions`, `console` and `builtIn: false`; empty
 *   with no directory
 */
function all() {
  log.debug('Entering all().');
  if (!haveDirectory()) {
    log.debug('Leaving all(). No directory.');
    return [];
  }
  const rows = directory.allRoles().map(function (entry) {
    const at = entry.attributes || {};
    const consoleRow = consoleRoleFor(entry.name);
    const nativeRow = nativeRoleFor(entry.name);
    // THE APPLICATION A ROLE BELONGS TO (#310), and its name inside it: the
    // part of `<role>@<application>` before the separator, which is what a
    // token for that application carries and its requirement names.
    const application = firstValue(at, 'roleApplication');
    return {
      name: entry.name,
      application: application,
      localName: application && String(entry.name).endsWith(
        APPLICATION_SEPARATOR + application)
        ? String(entry.name).slice(0, String(entry.name).length -
                                      application.length - 1)
        : entry.name,
      dn: entry.dn,
      description: firstValue(at, 'description'),
      // A console role's people and groups are the roster's, never stored:
      // see THE TWO CONSOLE ROLES.
      users: consoleRow ? [] : allValues(at, 'roleMemberUser'),
      groups: consoleRow ? consoleRoleGroups(consoleRow)
                         : allValues(at, 'roleMemberGroup'),
      applications: allValues(at, 'roleMemberApplication'),
      permissions: nativeRow ? [nativeRow.permission]
                             : allValues(at, 'rolePermission'),
      console: !!consoleRow,
      // Seeded in every realm, undeletable, its permission fixed (#309).
      native: !!nativeRow,
      builtIn: false
    };
  });
  rows.sort(function (a, b) {
    return a.name.localeCompare(b.name);
  });
  log.debug('Leaving all(). ' + rows.length + ' role(s).');
  return rows;
}

/**
 * Returns one configured role by name.
 *
 * @param name - the role name
 * @returns the row as `all()` draws it, or null
 */
function read(name) {
  log.debug('Entering read(). name=' + name);
  const wanted = String(name || '');
  const found = all().filter(function (row) {
    return row.name === wanted;
  })[0] || null;
  log.debug('Leaving read(). ' + (found ? 'Found.' : 'Not here.'));
  return found;
}

// Every role a policy or a console menu may name: the configured ones and the
// built-in ones, in one list, marked. One list because a policy author
// choosing a required role does not care which kind it is — and the mark is
// there because everything else about them differs.
/**
 * Lists every role a policy or console menu may name: the built-in ones and
 * the configured ones, each marked `builtIn`.
 *
 * @returns `{ name, what, builtIn }` per role, with `members` (a count) on a
 *   configured one
 */
function catalogue() {
  log.debug('Entering catalogue().');
  const out = builtInCatalogue().concat(all().map(function (row) {
    return { name: row.name, what: row.description, builtIn: false,
             members: row.users.length + row.groups.length +
                      row.applications.length };
  }));
  log.debug('Leaving catalogue(). ' + out.length + ' role(s).');
  return out;
}

// ---------------------------------------------------------------------------
// WRITING.
// ---------------------------------------------------------------------------
/**
 * Checks a proposed role name: present, not a built-in name, and up to 64
 * characters that can be an LDAP RDN and a claim value.
 *
 * @param name - the proposed name
 * @returns a sentence saying what is wrong, or null when the name is good
 */
function checkName(name) {
  log.debug("Entering checkName().");
  const text = String(name || '').trim();
  if (!text) {
    log.debug("Leaving checkName().");
    return 'A role needs a name.';
  }
  if (isBuiltIn(text)) {
    log.debug("Leaving checkName().");
    return 'There is already a built-in role called "' + text + '", and the ' +
           'built-in ones are COMPUTED rather than stored — a stored role of ' +
           'the same name could never be reached, because the resolver ' +
           'answers the built-in one first. The six are: ' +
           BUILT_IN_NAMES.join(', ') + '.';
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9 ._:@-]{0,63}$/.test(text)) {
    log.debug("Leaving checkName().");
    return 'A role name is up to 64 characters of letters, digits, and ' +
           '. _ : @ - or a space, starting with a letter or a digit. "' +
           text + '" is not, and the name becomes an LDAP RDN and a value in ' +
           'a token claim.';
  }
  log.debug("Leaving checkName().");
  return null;
}

/**
 * Creates or replaces a configured role in the ambient realm's `ou=roles`.
 *
 * A person or a foreign group on a console role is refused: its people are
 * the console roster's. A console role's permission is fixed.
 * @param name - the role name
 * @param record - `{ description, users, groups, applications, permissions }`
 * @returns `{ ok: true, name }`, or `{ ok: false, why }` carrying an error
 *   code
 */
function write(name, record) {
  log.debug('Entering write(). name=' + name);
  const problem = checkName(name);
  if (problem) {
    log.debug('Leaving write(). ' + problem);
    return errorCodes.mark({ ok: false, why: problem }, 'STS-XACML-0055');
  }
  if (!haveDirectory()) {
    log.debug('Leaving write(). No directory.');
    return errorCodes.mark({ ok: false,
             why: 'There is no embedded directory in this process, so there ' +
                  'is nowhere to keep a role. ou=roles IS the register.' },
             'STS-XACML-0026');
  }
  const given = record || {};
  // AN APPLICATION'S ROLE (#310): named `<role>@<application>`, the local
  // part a role name of its own. The application is not looked up here —
  // this file is a leaf and knows no registry — so the caller that creates
  // one says it exists (`admin_actions.ts`).
  const application = String(given.application || '').trim();
  if (application) {
    const local = String(name).slice(0, Math.max(0, String(name).length -
                                                    application.length - 1));
    if (String(name) !== local + APPLICATION_SEPARATOR + application ||
        !local || local.indexOf(APPLICATION_SEPARATOR) >= 0 ||
        checkName(local)) {
      log.debug('Leaving write(). Not a well-formed application role name.');
      return errorCodes.mark({ ok: false,
               why: 'An application\'s role is named <role>' +
                    APPLICATION_SEPARATOR + '<application>, the role part a ' +
                    'role name with no "' + APPLICATION_SEPARATOR + '" in it; "' +
                    name + '" for "' + application + '" is not.' },
               'STS-XACML-0080');
    }
    if (nativeRoleFor(local) || isBuiltIn(local)) {
      log.debug('Leaving write(). A reserved role name for an application.');
      return errorCodes.mark({ ok: false,
               why: '"' + local + '" is a role of this service itself and ' +
                    'cannot be an application\'s role too: a token would ' +
                    'carry one name meaning two things.' }, 'STS-XACML-0080');
    }
  }
  const consoleRow = consoleRoleFor(name);
  if (consoleRow && ((given.users || []).length ||
                     (given.groups || []).some(function (group) {
                       return consoleRoleGroups(consoleRow)
                         .indexOf(String(group)) < 0;
                     }))) {
    log.debug('Leaving write(). A person or group on a console role.');
    return errorCodes.mark({ ok: false,
             why: '"' + name + '" is one of the two console roles, and the ' +
                  'people who hold it are the console roster\'s: add them to ' +
                  'the Admin Read or Admin Write group on /admin/rbac (or ' +
                  'POST /admin-api/rbac/grant). Its groups are the settings ' +
                  'admin.readGroup and admin.writeGroup, and two places ' +
                  'granting one role would be two answers. An application ' +
                  'is added here.' }, 'STS-XACML-0075');
  }
  // THE CLASS THE SCHEMA ABOVE DECLARES, written on the entry (2026-09-23).
  // Until then a role was the one registry entry carrying no objectClass at
  // all — `cn` and the role attributes only — so `(objectClass=stsRole)`
  // matched nothing and a client listing classes saw an entry with none.
  // Taken from SCHEMA, as `applications.js`'s attributesFor() does, so the
  // published schema and the stored entry cannot name different classes.
  // An entry written before this gains it on its next save; it is not
  // rewritten at load (no migrations).
  const attributes = {
    objectClass: ['top'].concat(SCHEMA.objectClasses.map(function (one) {
      return one.name;
    })),
    roleName: String(name),
    description: String(given.description || ''),
    roleMemberUser: (given.users || []).map(String),
    roleMemberGroup: (given.groups || []).map(String),
    roleMemberApplication: (given.applications || []).map(String),
    roleApplication: application ? [application] : [],
    // A native role's permission is fixed (see THE NATIVE ROLES) and
    // written as such, so an ldapsearch shows what the role authorizes.
    rolePermission: nativeRoleFor(name) ? [nativeRoleFor(name).permission]
                                        : (given.permissions || []).map(String)
  };
  if (consoleRow) {
    attributes.roleMemberUser = [];
    attributes.roleMemberGroup = [];
  }
  const written = directory.writeRole(String(name), attributes);
  if (!written) {
    log.debug('Leaving write(). The directory refused.');
    return errorCodes.mark({ ok: false,
             why: 'The directory would not store the role — it is at its ' +
                  'maximum number of entries.' }, 'STS-XACML-0027');
  }
  log.debug('Leaving write(). Stored.');
  return { ok: true, name: String(name) };
}

/**
 * Deletes a configured role; a built-in or console role is refused.
 *
 * @param name - the role name
 * @returns `{ ok: true }`, or `{ ok: false, why }` carrying an error code
 */
function remove(name) {
  log.debug('Entering remove(). name=' + name);
  if (isBuiltIn(name)) {
    log.debug('Leaving remove(). Built in.');
    return errorCodes.mark({ ok: false,
             why: '"' + name + '" is a built-in role. It is computed rather ' +
                  'than stored, so there is nothing to delete — and an ' +
                  'application requiring it would be requiring something ' +
                  'that no longer existed.' }, 'STS-XACML-0056');
  }
  if (isNativeRole(name)) {
    log.debug('Leaving remove(). A native role.');
    return errorCodes.mark({ ok: false,
             why: '"' + name + '" authorizes a permission of this service ' +
                  'itself (' + nativeRoleFor(name).permission + ') and is ' +
                  'kept in every realm: without it nobody could ever be ' +
                  'issued that permission there. Take a member out with ' +
                  'remove-member instead.' }, 'STS-XACML-0076');
  }
  if (!haveDirectory() || !directory.deleteRole(String(name))) {
    log.debug('Leaving remove(). Not here.');
    return errorCodes.mark({ ok: false,
             why: 'There is no role called "' + name + '".' },
                           'STS-XACML-0057');
  }
  log.debug('Leaving remove(). Gone.');
  return { ok: true };
}

// ---------------------------------------------------------------------------
// SEEDING THE NATIVE ROLES (the two console roles, and DEVICE_COMPLIANCE
// since #309), in the AMBIENT realm — `ldap_server.js`
// calls it where it seeds this process's own applications, for the default
// realm at startup and inside each realm's builder. An entry already there
// is left exactly as it is, as `applications.js` leaves its seeded clients:
// an operator who took the management API's client out of a role meant it.
// Returns how many were created.
// ---------------------------------------------------------------------------
/**
 * Creates the two console roles in the ambient realm when they are missing,
 * with the management API's client as a member; an existing entry is left as
 * it is.
 *
 * @returns how many were created
 */
function seedNativeRoles() {
  log.debug('Entering seedNativeRoles().');
  if (!haveDirectory()) {
    log.debug('Leaving seedNativeRoles(). No directory.');
    return 0;
  }
  let made = 0;
  NATIVE_ROLES.forEach(function (row) {
    if (read(row.name)) {
      return;
    }
    const written = write(row.name, {
      description: row.what,
      applications: (row.seedApplications || []).slice(0) });
    if (written.ok) {
      made += 1;
    } else {
      log.warn(errorCodes.tag('STS-XACML-0077') + 'roles: the native role "' +
               row.name + '" was not seeded: ' + written.why + ' Machine ' +
               'clients cannot be issued ' + row.permission + ' in this ' +
               'realm until it exists.');
    }
  });
  log.debug('Leaving seedNativeRoles(). ' + made + ' created.');
  return made;
}

// The configured roles whose `rolePermission` names this permission, exactly
// (a permission identifier is compared as the string a client sends).
/**
 * Lists the configured roles whose `rolePermission` names a permission,
 * compared exactly.
 *
 * @param permission - a permission as a client asks for it
 * @returns the role names
 */
function rolesAuthorizing(permission) {
  log.debug('Entering rolesAuthorizing().');
  const wanted = String(permission == null ? '' : permission);
  const out = all().filter(function (row) {
    return row.permissions.indexOf(wanted) >= 0;
  }).map(function (row) {
    return row.name;
  });
  log.debug('Leaving rolesAuthorizing(). ' + out.length + ' role(s).');
  return out;
}

// ---------------------------------------------------------------------------
// THE RESOLVER: WHICH ROLES DOES THIS PARTY HOLD.
//
// `who` is the SECURITY CONTEXT of one decision:
//
//   { kind: 'user' | 'application',
//     name: the username or the application's client id / handle,
//     authenticated: whether this party proved anything,
//     groups: the group names a person is in (a user only),
//     scopes: an access token's scopes, where there is one — no role is read
//             off them since #309; kept for a caller's context }
//
// THE GROUPS ARE PASSED IN RATHER THAN LOOKED UP HERE where the caller already
// has them, and looked up through the directory slot where it does not. Both,
// because the two callers are genuinely different: the issuance gate is
// deciding about a session it already read the groups for, and the roles claim
// is being built inside a token mint that has only a name.
//
// IT NEVER THROWS. A register this service consults must not be able to fail
// the issuance it was consulted during — the same rule every directory read
// here follows — so a broken lookup answers "the built-in roles only", which
// still contains EVERYBODY and therefore still admits everybody an unedited
// application admits.
// ---------------------------------------------------------------------------
/**
 * Returns every role a party holds in one decision: the built-in roles that
 * apply and the configured ones.
 *
 * It never throws; a register that fails answers the built-in roles only.
 * @param who - the security context `{ kind, name, authenticated, groups,
 *   scopes }`; groups are looked up through the directory when not given
 * @returns the role names
 */
function rolesOf(who) {
  log.debug('Entering rolesOf(). kind=' + (who || {}).kind);
  const context = normalizeContext(who);
  // THE GROUPS ARE RESOLVED BEFORE THE BUILT-INS ARE ASKED, AND THAT IS NEW.
  // Five of the built-in roles are computed from `kind` and `authenticated`
  // alone and never needed this; REMOTE_PEPS and XACML_USER are held through a
  // group, so `holds()` has to be able to see one. It is resolved ONCE and put
  // on the context, which is also what `configuredRolesOf()` below then reads —
  // so this is the same directory walk that was already happening, moved
  // earlier and shared, rather than a second one.
  context.groups = groupsFor(context);
  const held = BUILT_IN.filter(function (one) {
    return one.holds(context);
  }).map(function (one) {
    return one.name;
  });
  let configured = [];
  try {
    configured = configuredRolesOf(context);
  } catch (error) {
    // Swallowed and logged: see the header. A token issued without a role it
    // should have carried is a defect; an issuance that FAILED because the
    // role register threw would be a worse one, and this service's whole job
    // is to keep answering.
    log.error(errorCodes.tag('STS-XACML-0053') +
              'roles: the register threw while resolving roles for "' +
              context.name + '" and was ignored; only the built-in roles ' +
              'were used. ' + error.message);
  }
  const out = held.concat(configured.filter(function (one) {
    return held.indexOf(one) < 0;
  }));
  log.debug('Leaving rolesOf(). ' + out.length + ' role(s): ' +
            out.join(', '));
  return out;
}

function normalizeContext(who) {
  log.debug("Entering normalizeContext().");
  const given = who || {};
  const kind = given.kind === 'application' ? 'application' : 'user';
  log.debug("Leaving normalizeContext().");
  return {
    kind: kind,
    name: String(given.name || ''),
    authenticated: given.authenticated === true,
    groups: Array.isArray(given.groups) ? given.groups.map(String) : null,
    // THE APPLICATION(S) THIS DECISION OR TOKEN IS FOR (#310): a role
    // belonging to one of them is held under its name inside it; any other
    // application's role is not held here at all.
    applications: (Array.isArray(given.applications) ? given.applications
      : (given.application ? [given.application] : []))
      .map(String).filter(Boolean),
    // `ids`: answer every configured role held, an application's by its full
    // `<role>@<application>` — what a permission is authorized by and the
    // PIP answers — rather than by the context's applications.
    ids: given.ids === true,
    // THE SCOPES OF THE ACCESS TOKEN THIS DECISION IS BEING MADE FOR, when
    // there is one. No role is computed from them since #309 — the last,
    // DEVICE_COMPLIANCE, is configured now — so a caller that
    // presented no token is exactly what it was.
    scopes: Array.isArray(given.scopes)
      ? given.scopes.map(String)
      : String(given.scopes || '').split(/\s+/).filter(Boolean)
  };
}

function groupsFor(context) {
  log.debug("Entering groupsFor().");
  if (context.groups) {
    log.debug("Leaving groupsFor().");
    return context.groups;
  }
  if (context.kind !== 'user' || !context.name ||
      !directory || typeof directory.groupsOfUser !== 'function') {
    log.debug("Leaving groupsFor().");
    return [];
  }
  log.debug("Leaving groupsFor().");
  return directory.groupsOfUser(context.name) || [];
}

function configuredRolesOf(context) {
  log.debug("Entering configuredRolesOf().");
  if (!context.name) {
    log.debug("Leaving configuredRolesOf().");
    // AN ANONYMOUS PARTY HOLDS NO CONFIGURED ROLE and every built-in one that
    // applies. Not an error: `ALL_UNAUTHENTICATED_USERS` is a real answer, and
    // it is the whole reason that role exists.
    return [];
  }
  const groups = context.kind === 'user' ? groupsFor(context) : [];
  const lowerGroups = groups.map(function (one) {
    return String(one).toLowerCase();
  });
  log.debug("Leaving configuredRolesOf().");
  return all().filter(function (role) {
    if (context.kind === 'application') {
      return contains(role.applications, context.name);
    }
    if (contains(role.users, context.name)) {
      return true;
    }
    return role.groups.some(function (group) {
      return lowerGroups.indexOf(String(group).toLowerCase()) >= 0;
    });
  }).filter(function (role) {
    return context.ids || !role.application ||
           context.applications.indexOf(role.application) >= 0;
  }).map(function (role) {
    return context.ids || !role.application ? role.name : role.localName;
  });
}

// Case-insensitively, because a username here arrives from a login form, a
// SAML subject, a Kerberos principal and a client_id, and this service has
// always treated those as one identity however they were typed —
// `admin_stats.js`'s `identityKeyOf()` is the same decision one layer up.
function contains(list, wanted) {
  log.debug("Entering contains().");
  const key = String(wanted).toLowerCase();
  log.debug("Leaving contains().");
  return list.some(function (one) {
    return String(one).toLowerCase() === key;
  });
}

// ---------------------------------------------------------------------------
// THE CLAIM.
//
// `admin_stats.js` calls this while building a token or an assertion, through
// a PLAIN REQUIRE in the ordinary direction — see the header for why that is
// worth protecting.
//
// **THE CLAIM IS OMITTED ENTIRELY FOR SOMEBODY WITH NO CONFIGURED ROLE**, and
// the BUILT-IN ones are not in it at all. That second half is the one worth
// arguing: EVERYBODY and ALL_AUTHENTICATED_USERS are true of almost every
// token this service issues, so putting them in the claim would add two
// meaningless members to every token every existing client parses, and would
// tell a relying party nothing it did not already know from holding the token.
// They exist to be REQUIRED, not to be carried.
// ---------------------------------------------------------------------------
/**
 * Builds the roles claim for a token or assertion: the configured roles the
 * party holds, under `roles.claimName`.
 *
 * Built-in roles are never carried, and a party with no configured role gets
 * no claim at all.
 * @param who - the security context, as for `rolesOf()`
 * @returns `{ <claimName>: [roles] }`, or null when the claim is off, empty
 *   or the register failed
 */
function claimFor(who) {
  log.debug('Entering claimFor().');
  if (config.value('roles.claim') === false) {
    log.debug('Leaving claimFor(). The claim is off.');
    return null;
  }
  const context = normalizeContext(who);
  let names = [];
  try {
    names = configuredRolesOf(context);
  } catch (error) {
    log.error(errorCodes.tag('STS-XACML-0054') +
              'roles: the register threw while building the roles claim and ' +
              'was ignored; the token is issued without it. ' + error.message);
    log.debug("Leaving claimFor().");
    return null;
  }
  if (!names.length) {
    log.debug('Leaving claimFor(). No configured role, so no claim.');
    return null;
  }
  const name = String(config.value('roles.claimName') || 'roles');
  const out = {};
  out[name] = names.sort();
  log.debug('Leaving claimFor(). ' + names.length + ' role(s).');
  return out;
}

// ---------------------------------------------------------------------------
// READING THE ROLES OUT OF A TOKEN SOMEBODY PRESENTED.
//
// The other direction, and the one the standard policy template is written
// around: a request may arrive carrying a token, and that token may carry the
// claim this service put in it. Reading it back is what makes a policy about
// roles enforceable at a door where the SUBJECT is a token rather than a
// session.
//
// **WHAT COMES OUT IS NOT TRUSTED MORE THAN THE TOKEN IT CAME FROM**, and this
// service does not verify access tokens it did not issue. So the roles found
// here are UNIONED with the ones the register answers rather than replacing
// them, and the register is what an enforcement decision can rest on. A claim
// naming `admin` in a token this service never minted adds a role to the
// request and the policy may match it — which is the mock's usual bargain, and
// it is written down here rather than discovered.
// ---------------------------------------------------------------------------
/**
 * Reads the roles out of a presented token's claims: an array, a single
 * string, or a space- or comma-separated string.
 *
 * What it returns is trusted no more than the token it came from.
 * @param claims - the token's claims
 * @returns the role names found, or an empty list
 */
function rolesInClaims(claims) {
  log.debug('Entering rolesInClaims().');
  if (!claims || typeof claims !== 'object') {
    log.debug('Leaving rolesInClaims(). Nothing to read.');
    return [];
  }
  const name = String(config.value('roles.claimName') || 'roles');
  const raw = claims[name];
  if (raw === undefined || raw === null) {
    log.debug('Leaving rolesInClaims(). The claim is not there.');
    return [];
  }
  // THREE SHAPES ARE ACCEPTED because three are what real identity providers
  // send: an array, a single string, and a space- or comma-separated string
  // (a `scope`-shaped claim, and what several products emit).
  // Reading only the first would silently find nothing in the other two, and
  // finding nothing looks exactly like holding no roles.
  const values = Array.isArray(raw) ? raw
    : (typeof raw === 'string' ? raw.split(/[\s,]+/) : [raw]);
  const out = values.map(function (one) {
    return String(one).trim();
  }).filter(function (one) {
    return one.length > 0;
  });
  log.debug('Leaving rolesInClaims(). ' + out.length + ' role(s).');
  return out;
}

/**
 * The role register: who holds a role, the built-in computed roles, the two
 * console roles, and the roles claim.
 *
 * A library and a leaf (rule 3): it requires only `helpers`, `config` and
 * `error_codes`, and reaches the directory through a slot.
 * @namespace
 */
module.exports = {
  SCHEMA: SCHEMA,
  BUILT_IN: BUILT_IN,
  BUILT_IN_NAMES: BUILT_IN_NAMES,
  DEFAULT_REQUIRED_ROLE: DEFAULT_REQUIRED_ROLE,
  isBuiltIn: isBuiltIn,
  builtInCatalogue: builtInCatalogue,
  CONSOLE_ROLES: CONSOLE_ROLES,
  CONSOLE_ROLE_APPLICATION: CONSOLE_ROLE_APPLICATION,
  APPLICATION_SEPARATOR: APPLICATION_SEPARATOR,
  consoleRoleFor: consoleRoleFor,
  isConsoleRole: isConsoleRole,
  NATIVE_ROLES: NATIVE_ROLES,
  nativeRoleFor: nativeRoleFor,
  isNativeRole: isNativeRole,
  seedNativeRoles: seedNativeRoles,
  rolesAuthorizing: rolesAuthorizing,
  setDirectory: setDirectory,
  directoryInstalled: directoryInstalled,
  all: all,
  read: read,
  catalogue: catalogue,
  checkName: checkName,
  write: write,
  remove: remove,
  rolesOf: rolesOf,
  claimFor: claimFor,
  rolesInClaims: rolesInClaims
};
