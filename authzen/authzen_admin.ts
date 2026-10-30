// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authzen_admin.ts
//
// ===========================================================================
// WHAT THE AUTHZEN TAB SHOWS AND DOES (#563, phase 3, #1162).
//
// The AuthZEN tab of `/admin/xacml` and `/admin-api/xacml/authzen` (rule 7,
// parity) both call this: `view()` is everything the tab draws and `act()`
// is every change it makes, so the console and the API cannot disagree. A
// LIBRARY: it registers no route (`mgmt-api/authzen_api.ts` carries the
// operations, and the static console draws from them).
//
//   set-attribute     one catalogue row, added — or replacing the row for the
//                     same object and property — on the realm's
//                     `sts-authzen-api` object, through the registry's own
//                     write door, which checks it with the catalogue's
//                     grammar (`authzen_catalogue.ts`)
//   remove-attribute  that row, taken off
//   set-scope         the applications a caller may ask about: a person's or
//                     service account's `stsAuthzenApplication`, or an
//                     application's `appAuthzenApplication`, replaced whole
//   set-callbacks     the callback URLs registered for a caller (#1180):
//                     `stsAuthzenCallbackUri` or `appAuthzenCallbackUri`,
//                     replaced whole — the only URLs an access request's
//                     callback may name
//   approve-access-request, deny-access-request, revoke-access-request,
//   cancel-access-request
//                     an administrator's act on one access request (#1180,
//                     rcbj's decision 3), through
//                     `authzen_access_request.ts`'s `decide()` — the
//                     portal's door too — so the access-control policy is
//                     asked exactly as it is for an approver there
//
// **THE SCOPE IS AN ADMINISTRATOR'S AND NOBODY ELSE'S** (rcbj on #563,
// decision 1), so this is its only writer for a person: `sts*` is refused by
// the person editor, SCIM, federation provisioning and attribute sources,
// and the portal does not offer it. The directory write crosses the slot
// `ldap/ldap_server.js` fills (`setDirectory()`), for `ldap/person_editor.ts`'s
// reason: a require of the directory from here would drag the
// `/admin/ldap/*` routes ahead of the console's.
//
// **WHO IS LISTED IS THE GROUP**: the members of `roles.authzenPepGroup`,
// each with its scope — the people who can ask, which is the question the
// tab is for. A scope on an entry outside the group is inert, and is shown
// when the entry is looked up by name.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import catalogue = require('./authzen_catalogue');

const { log } = helpers;

// The API's own resource object.
const API_OBJECT = 'sts-authzen-api';

// The person attribute and the application attribute that hold a scope.
const PERSON_SCOPE = 'stsAuthzenApplication';
const APPLICATION_SCOPE = 'appAuthzenApplication';

// And the two that hold the callback URLs registered for a caller (#1180).
const PERSON_CALLBACK = 'stsAuthzenCallbackUri';
const APPLICATION_CALLBACK = 'appAuthzenCallbackUri';

// The most callback URLs one caller may have registered.
const MAX_CALLBACKS = 8;

// The most access requests the tab lists.
const MAX_REQUESTS = 200;

// The most members the tab lists, and the most applications one caller may
// be scoped to. Bounds, because both are drawn on one page.
const MAX_MEMBERS = 200;
const MAX_SCOPE = 64;

// The acts.
const ACTIONS = Object.freeze(['set-attribute', 'remove-attribute',
                               'set-scope', 'set-callbacks',
                               'approve-access-request',
                               'deny-access-request',
                               'revoke-access-request',
                               'cancel-access-request']);

// The most holders of REMOTE_PEPS one enable grants (#1210), for
// MAX_MEMBERS' reason: the answer and the tab list each of them.
const MAX_PEP_GRANT = 200;

// What the directory slot carries.
interface DirectoryHooks {
  // An entry by name or DN: `{ dn, person, attributes }`, or null.
  locate(key: string): any;
  // The members of a group, as DNs.
  members(group: string): string[];
  // A person's attribute, replaced whole.
  write(dn: string, name: string, values: string[]): boolean;
  // A member added to a group (#1210): the directory's own door,
  // `addGroupMember()`, idempotent and audited as `group.add-member`.
  addMember(group: string, member: string, options: object): any;
}

let directory: DirectoryHooks | null = null;

interface AdminDeps {
  log: typeof log;
  config: any;
  audit: any;
  errorCodes: any;
  applications: any;
  realms: any;
  loadConsole(): any;
  loadCaller(): any;
  // The Access Request and Approval Profile (#1180), lazily: it requires
  // this module back for the directory and a caller's callbacks.
  loadAccessRequests(): any;
}

/**
 * The AuthZEN tab's view and acts, shared by the console and the API.
 */
class AuthzenAdmin {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the logger, settings, audit log, error codes, the
   *   application registry, realms, and lazy loaders for the console and the
   *   caller checks
   */
  constructor(private readonly deps: AdminDeps) {
    deps.log.debug("Entering AuthzenAdmin.constructor().");
    deps.log.debug("Leaving AuthzenAdmin.constructor().");
  }

  /**
   * The dependencies built from the real modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): AdminDeps {
    log.debug("Entering AuthzenAdmin.defaultDeps().");
    log.debug("Leaving AuthzenAdmin.defaultDeps().");
    return {
      log: log,
      config: require('../common/config'),
      audit: require('../common/audit'),
      errorCodes: require('../common/error_codes'),
      applications: require('../common/applications'),
      realms: require('../common/realms'),
      loadConsole: function (): any {
        log.debug("Entering loadConsole().");
        log.debug("Leaving loadConsole().");
        return require('../admin-ui/admin');
      },
      loadCaller: function (): any {
        log.debug("Entering loadCaller().");
        log.debug("Leaving loadCaller().");
        return require('./authzen_caller');
      },
      loadAccessRequests: function (): any {
        log.debug("Entering loadAccessRequests().");
        log.debug("Leaving loadAccessRequests().");
        return require('./authzen_access_request');
      }
    };
  }

  // A refusal, coded.
  private refused(code: string, message: string): any {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AuthzenAdmin.refused(). " + code);
    log.debug("Leaving AuthzenAdmin.refused().");
    return errorCodes.mark({ ok: false, errors: [message] }, code);
  }

  /**
   * The values of an attribute on a registry view or a directory entry, as a
   * list of strings.
   *
   * @param attributes - the attribute map
   * @param name - the attribute's name, matched without regard to case
   * @returns the values
   */
  static valuesOf(attributes: any, name: string): string[] {
    log.debug("Entering AuthzenAdmin.valuesOf().");
    const wanted = String(name).toLowerCase();
    let found: any = null;
    Object.keys(attributes || {}).forEach(function (key: string) {
      if (key.toLowerCase() === wanted) {
        found = attributes[key];
      }
    });
    log.debug("Leaving AuthzenAdmin.valuesOf().");
    return (Array.isArray(found) ? found : (found ? [found] : []))
      .map(String).filter(Boolean);
  }

  /**
   * One caller as the tab draws it: who, what kind, and its scope.
   *
   * @param key - a name or a DN
   * @returns `{ dn, name, kind, applications, member }`, or null for nobody
   */
  callerOf(key: string): any {
    const self = this;
    const { log, applications, config } = this.deps;
    log.debug("Entering AuthzenAdmin.callerOf().");
    const wanted = String(key || '').trim();
    if (!wanted) {
      log.debug("Leaving AuthzenAdmin.callerOf(). Nothing asked.");
      return null;
    }
    // AN APPLICATION FIRST, by its identifier or its DN.
    let app: any = null;
    try {
      app = applications.get(wanted) || (applications.list() || [])
        .filter(function (one: any) {
          return one && one.dn &&
                 String(one.dn).toLowerCase() === wanted.toLowerCase();
        })[0] || null;
    } catch (e) {
      log.debug("Caught in AuthzenAdmin.callerOf(): " +
                ((e && e.message) || e));
      app = null;
    }
    const group = String(config.value('roles.authzenPepGroup') || '');
    const members = (directory && group ? directory.members(group) : [])
      .map(function (one: string) {
        return String(one).toLowerCase();
      });
    if (app) {
      const full = applications.get(app.identifier) || app;
      log.debug("Leaving AuthzenAdmin.callerOf(). An application.");
      return { dn: String(full.dn || ''), name: String(full.identifier),
               kind: 'application',
               applications: AuthzenAdmin.valuesOf(full.fields,
                                                   APPLICATION_SCOPE),
               callbacks: AuthzenAdmin.valuesOf(full.fields,
                                                APPLICATION_CALLBACK),
               member: !!full.dn &&
                       members.indexOf(String(full.dn).toLowerCase()) >= 0 };
    }
    const entry = directory ? directory.locate(wanted) : null;
    if (!entry || !entry.person) {
      log.debug("Leaving AuthzenAdmin.callerOf(). Nobody.");
      return null;
    }
    log.debug("Leaving AuthzenAdmin.callerOf(). A person.");
    return { dn: String(entry.dn), name: String(entry.name || entry.dn),
             kind: entry.serviceAccount ? 'service-account' : 'person',
             applications: AuthzenAdmin.valuesOf(entry.attributes,
                                                 PERSON_SCOPE),
             callbacks: AuthzenAdmin.valuesOf(entry.attributes,
                                              PERSON_CALLBACK),
             member: members.indexOf(String(entry.dn).toLowerCase()) >= 0 ||
                     self.memberByName(members, entry) };
  }

  // A group's `memberUid`-style value names a person by username rather
  // than DN; one of those is a member too.
  private memberByName(members: string[], entry: any): boolean {
    const { log } = this.deps;
    log.debug("Entering AuthzenAdmin.memberByName().");
    log.debug("Leaving AuthzenAdmin.memberByName().");
    return !!entry.name &&
           members.indexOf(String(entry.name).toLowerCase()) >= 0;
  }

  /**
   * Everything the AuthZEN tab draws: whether the API answers here, how its
   * callers authenticate, its settings, the catalogue, the callers in the
   * group with their scopes, and the vocabulary a row may use.
   *
   * @param query - the request's query; `caller` looks one caller up
   * @returns the view
   */
  view(query?: any): any {
    const self = this;
    const { log, config, applications, realms } = this.deps;
    log.debug("Entering AuthzenAdmin.view().");
    let object: any = null;
    try {
      object = applications.get(API_OBJECT);
    } catch (e) {
      log.debug("Caught in AuthzenAdmin.view(): " + ((e && e.message) || e));
      object = null;
    }
    const read = catalogue.rowsOf(object && object.fields
      ? object.fields.authzenAttribute : null);
    const group = String(config.value('roles.authzenPepGroup') || '');
    const members = directory && group ? directory.members(group) : [];
    const callers = members.slice(0, MAX_MEMBERS).map(function (dn: string) {
      return self.callerOf(dn) ||
        { dn: dn, name: dn, kind: 'unknown', applications: [],
          callbacks: [], member: true };
    });
    const asked = String((query || {}).caller || '').trim();
    const consoleModule = self.deps.loadConsole();
    const caller = self.deps.loadCaller();
    const requests = self.deps.loadAccessRequests();
    const listed = requests.list(MAX_REQUESTS);
    const out = {
      realm: String(realms.currentId() || ''),
      enabled: config.value('authzen.enabled') !== false,
      xacmlEnabled: config.value('xacml.enabled') !== false,
      apiObject: !!object,
      audience: object && object.fields
        ? AuthzenAdmin.valuesOf(object.fields, 'oauthAudience') : [],
      callerAuthentication: String(
        config.value('authzen.callerAuthentication') || 'mtls'),
      doors: caller.DOORS.slice(0),
      role: caller.AUTHZEN_ROLE,
      scope: caller.AUTHZEN_SCOPE,
      group: group,
      settings: consoleModule && consoleModule.configSettingsJson
        ? consoleModule.configSettingsJson('/admin/xacml', ['AuthZEN'])
        : null,
      catalogue: {
        rows: read.rows.map(function (row: any) {
          return Object.assign({ key: catalogue.keyOf(row) }, row);
        }),
        problems: read.problems,
        objects: catalogue.OBJECTS.slice(0),
        categories: Object.keys(catalogue.CATEGORY_NAMES),
        dataTypes: Object.keys(catalogue.TYPE_NAMES),
        multiplicities: catalogue.MULTIPLICITIES.slice(0),
        reservedPrefix: catalogue.RESERVED_PREFIX,
        reservedContext: catalogue.RESERVED_CONTEXT.slice(0)
      },
      callers: callers,
      callersTotal: members.length,
      looked: asked ? (self.callerOf(asked) || { name: asked, kind: 'none',
                                                  applications: [],
                                                  callbacks: [],
                                                  member: false })
                    : null,
      // THE ACCESS REQUESTS (#1180): every one of the realm's, newest
      // first, with what an administrator may do to each.
      accessRequests: {
        enabled: requests.enabled(),
        rows: listed.map(function (row: any) {
          return requests.viewOf(row);
        }),
        maxCallbacks: MAX_CALLBACKS
      }
    };
    log.debug("Leaving AuthzenAdmin.view(). " + out.catalogue.rows.length +
              " row(s), " + callers.length + " caller(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // WHO MIGHT BE A CALLER, FOR THE LIST A REMOTE PEP PULLS (#1189).
  //
  // The members of `roles.authzenPepGroup` — the group whose membership IS
  // the AUTHZEN_PEPS role — each located in the directory, with the
  // attributes its stored certificates are read from. These are CANDIDATES
  // and nothing more: `authzen_caller.ts`'s `edgeCallers()` asks the
  // certificate door who each certificate names and the access-control
  // policy whether that caller may ask, so the list the edge holds is the
  // outcome rather than the membership. A member that locates to no person,
  // service account or application (a DN left behind by a deletion, a nested
  // group) is counted and left out: nothing can present a certificate as it.
  //
  // Bounded at `max`, and the total is answered beside, so a list that was
  // cut is said to be (`STS-AUTHZEN-0061`, logged by the caller).
  // ---------------------------------------------------------------------------
  /**
   * The members of the AuthZEN group, located, for the edge caller list.
   *
   * @param max - the most members read
   * @returns `{ group, total, candidates, unlocated }`; each candidate is
   *   `{ dn, kind, name, attributes }`, kind `person`, `service-account`
   *   or `application`
   */
  edgeCandidates(max: number): any {
    const { log, config } = this.deps;
    log.debug("Entering AuthzenAdmin.edgeCandidates().");
    const group = String(config.value('roles.authzenPepGroup') || '');
    const read = this.locateMembers(group, max);
    log.debug("Leaving AuthzenAdmin.edgeCandidates(). " +
              read.candidates.length + " of " + read.total + ".");
    return { group: group, total: read.total, candidates: read.candidates,
             unlocated: read.unlocated.length };
  }

  // A GROUP'S MEMBERS, LOCATED: each a person's, a service account's or an
  // application's entry, or left in `unlocated` (a DN left behind by a
  // deletion, a nested group, a name nothing holds). What
  // `edgeCandidates()` reads for `roles.authzenPepGroup` and
  // `grantRemotePeps()` for `roles.remotePepGroup` (#1210).
  private locateMembers(group: string, max: number): any {
    const { log, applications } = this.deps;
    log.debug("Entering AuthzenAdmin.locateMembers(). group=" + group);
    const members = directory && group ? directory.members(group) : [];
    // The applications by DN, read once rather than once per member: a
    // member is a person's, a service account's or an application's DN,
    // and `callerOf()`'s per-key search would walk the registry for each.
    const byDn = new Map<string, any>();
    try {
      (applications.list() || []).forEach(function (one: any) {
        if (one && one.dn) {
          byDn.set(String(one.dn).toLowerCase(), one);
        }
      });
    } catch (e) {
      log.debug("Caught in AuthzenAdmin.edgeCandidates(): " +
                ((e && e.message) || e));
    }
    const candidates: any[] = [];
    const unlocated: string[] = [];
    members.slice(0, Math.max(0, max)).forEach(function (member: string) {
      const entry = directory ? directory.locate(String(member)) : null;
      const app = entry ? byDn.get(String(entry.dn).toLowerCase()) : null;
      if (entry && app) {
        candidates.push({ dn: String(entry.dn), kind: 'application',
                          name: String(app.identifier),
                          attributes: entry.attributes || {} });
      } else if (entry && entry.person) {
        candidates.push({ dn: String(entry.dn),
                          kind: entry.serviceAccount ? 'service-account'
                                                     : 'person',
                          name: String(entry.name || entry.dn),
                          attributes: entry.attributes || {} });
      } else {
        unlocated.push(String(member));
      }
    });
    log.debug("Leaving AuthzenAdmin.locateMembers(). " + candidates.length +
              " of " + members.length + ".");
    return { total: members.length, candidates: candidates,
             unlocated: unlocated };
  }

  // ---------------------------------------------------------------------------
  // ENABLING FINE-GRAINED AUTHORIZATION GRANTS THE REALM'S REMOTE PEPS
  // (#1210, rcbj's decision of 2026-10-30).
  //
  // A remote PEP's edge PDP forwards an evaluation about an application
  // that enforces fine-grained authorization to `/access/v1` (#564, P7),
  // where the PEP is an AuthZEN caller like any other: its entry must hold
  // AUTHZEN_PEPS (membership of `roles.authzenPepGroup`) and have the
  // application in its scope. Without both, every forwarded evaluation is
  // a 502 at the edge. So `fga_policies.ts`'s `enable()` calls this, and
  // every holder of REMOTE_PEPS in the realm — the members of
  // `roles.remotePepGroup`, located as `edgeCandidates()` locates the
  // AuthZEN group's, so a person, a service account and an application are
  // each one — is put in the AuthZEN group if it is not there, and has the
  // application added to its scope (`stsAuthzenApplication` on a person or
  // service account, `appAuthzenApplication` on an application) if it is
  // absent.
  //
  // **THIS DELIBERATELY MAKES THE REMOTE_PEPS GROUP A SOURCE OF AUTHZEN
  // PERMISSION, AT THE MOMENT OF THE ENABLE.** The rule beside it still
  // holds: a registration in `ou=peps` is not a permission, and nothing
  // here reads `ou=peps`. What grants is an administrator's act — enabling
  // the application — over a group an administrator filled, and what it
  // writes is ordinary state the AuthZEN tab shows and can take back.
  //
  // * **Through the directory's own doors.** The membership through
  //   `addGroupMember()` (audited there as `group.add-member`), a person's
  //   scope through the same write `set-scope` uses, an application's
  //   through the registry's `updateApplication()`. And one
  //   `admin.authzen.pep.granted` row per entry changed, naming both.
  // * **One holder failing fails nothing else.** Each is answered as
  //   `granted`, `held` (it had both) or `failed` with why and
  //   STS-FGA-0025, and the enable succeeds whatever they say.
  // * **Nothing is ever taken away here.** Disabling removes nothing: a
  //   value an administrator set by hand is indistinguishable from one an
  //   enable added, so removing could revoke a grant somebody chose.
  // * **Not retroactive.** A holder added to the group after the enable is
  //   granted by the next enable (which re-runs this on an application
  //   that already enforces), or by hand on the AuthZEN tab.
  // * **Not by mode.** The same in development and product.
  // ---------------------------------------------------------------------------
  /**
   * Grants every holder of REMOTE_PEPS in the realm what forwarding an
   * application's AuthZEN evaluations needs: membership of
   * `roles.authzenPepGroup`, and the application in its scope.
   *
   * @param application - the application's identifier
   * @param who - `{ actor, via }`, for the audit rows
   * @returns `{ group, authzenGroup, total, truncated, granted, held,
   *   failed }`; each holder is `{ name, kind, dn }`, a granted one with
   *   `member` and `scope` saying what was added, a failed one with `why`
   *   and `code`
   */
  grantRemotePeps(application: string, who?: any): any {
    const self = this;
    const { log, config } = this.deps;
    const id = String(application || '');
    const by = who || {};
    log.debug("Entering AuthzenAdmin.grantRemotePeps(). " + id);
    const group = String(config.value('roles.remotePepGroup') || '').trim();
    const authzenGroup = String(config.value('roles.authzenPepGroup') || '')
      .trim();
    const read = self.locateMembers(group, MAX_PEP_GRANT);
    const out: any = { group: group, authzenGroup: authzenGroup,
                       total: read.total,
                       truncated: read.total > MAX_PEP_GRANT,
                       granted: [], held: [], failed: [] };
    const fail = function (holder: any, why: string): void {
      log.debug("Entering fail().");
      out.failed.push(Object.assign({}, holder,
                                    { why: why, code: 'STS-FGA-0025' }));
      self.auditGrant(id, holder, by, why);
      log.debug("Leaving fail().");
    };
    read.unlocated.forEach(function (member: string) {
      fail({ name: member, kind: 'unknown', dn: member },
           'The member "' + member.slice(0, 200) + '" of ' + group +
           ' names no person, service account or application in this ' +
           'realm, so there is no entry to carry the scope.');
    });
    const authzenMembers = directory && authzenGroup
      ? directory.members(authzenGroup).map(function (one: string) {
        return String(one).toLowerCase();
      }) : [];
    read.candidates.forEach(function (candidate: any) {
      const holder = { name: candidate.name, kind: candidate.kind,
                       dn: candidate.dn };
      if (!authzenGroup) {
        fail(holder, 'roles.authzenPepGroup is empty, so no group grants ' +
                     'AUTHZEN_PEPS in this realm.');
        return;
      }
      const state = self.pepState(id, candidate, authzenMembers);
      if (state.member && state.scoped) {
        out.held.push(holder);
        return;
      }
      if (!state.scoped && state.scope.length >= MAX_SCOPE) {
        fail(holder, 'Its scope already names ' + state.scope.length +
                     ' applications, the most a caller may be scoped to (' +
                     MAX_SCOPE + ').');
        return;
      }
      let addedMember = false;
      if (!state.member) {
        let added: any = null;
        try {
          added = directory ? directory.addMember(authzenGroup, candidate.dn,
            { actor: String(by.actor || ''), protocol: 'AuthZEN',
              channel: by.via === 'api' ? 'api' : 'console' }) : null;
        } catch (e) {
          log.debug("Caught in AuthzenAdmin.grantRemotePeps(): " +
                    ((e && e.message) || e));
          added = { ok: false, errors: [String((e && e.message) || e)] };
        }
        if (!added || !added.ok) {
          fail(holder, 'It could not be added to ' + authzenGroup + ': ' +
                       ((added && (added.errors || []).join(' ')) ||
                        'no directory is loaded.'));
          return;
        }
        addedMember = !!added.changed;
      }
      if (!state.scoped) {
        const why = self.addScope(id, candidate, state.scope);
        if (why) {
          fail(holder, why + (addedMember
            ? ' It was added to ' + authzenGroup + ', which is kept.' : ''));
          return;
        }
      }
      const granted = Object.assign({}, holder,
                                    { member: addedMember,
                                      scope: !state.scoped });
      out.granted.push(granted);
      self.auditGrant(id, granted, by, '');
    });
    log.debug("Leaving AuthzenAdmin.grantRemotePeps(). " +
              out.granted.length + " granted, " + out.held.length +
              " held, " + out.failed.length + " failed.");
    return out;
  }

  // Whether one located holder is in the AuthZEN group and has the
  // application in its scope, with its scope as it stands.
  private pepState(application: string, candidate: any,
                   authzenMembers: string[]): any {
    const { log, applications } = this.deps;
    log.debug("Entering AuthzenAdmin.pepState(). " + candidate.dn);
    const member = authzenMembers
      .indexOf(String(candidate.dn).toLowerCase()) >= 0 ||
      this.memberByName(authzenMembers, candidate);
    let scope: string[] = [];
    let own = false;
    if (candidate.kind === 'application') {
      const full = applications.get(candidate.name);
      scope = AuthzenAdmin.valuesOf(full && full.fields, APPLICATION_SCOPE);
      // AN APPLICATION IS ALWAYS SCOPED TO ITSELF (`authzen_caller.ts`'s
      // `scopeOf()` adds its own identifiers), so nothing is written for
      // a remote PEP that is the enforcing application.
      own = candidate.name === application;
    } else {
      scope = AuthzenAdmin.valuesOf(candidate.attributes, PERSON_SCOPE);
    }
    log.debug("Leaving AuthzenAdmin.pepState().");
    return { member: member, scope: scope,
             scoped: own || scope.indexOf(application) >= 0 };
  }

  // The application added to one holder's scope: '' when written, else why.
  private addScope(application: string, candidate: any,
                   scope: string[]): string {
    const { log, applications } = this.deps;
    log.debug("Entering AuthzenAdmin.addScope(). " + candidate.dn);
    if (candidate.kind === 'application') {
      const added = applications.updateApplication(candidate.name, {
        mode: 'add', attribute: APPLICATION_SCOPE, value: application });
      log.debug("Leaving AuthzenAdmin.addScope(). " + !!added.ok);
      return added.ok ? '' : 'The application ' + candidate.name +
        ' would not take ' + APPLICATION_SCOPE + ': ' +
        ((added.errors || []).join(' ') || 'refused') + '.';
    }
    const written = !!directory &&
      directory.write(candidate.dn, PERSON_SCOPE, scope.concat([application]));
    log.debug("Leaving AuthzenAdmin.addScope(). " + written);
    return written ? '' : PERSON_SCOPE + ' could not be written onto ' +
      candidate.dn + '.';
  }

  // One audit row per holder: what was granted, or why it was not.
  private auditGrant(application: string, holder: any, who: any,
                     why: string): void {
    const { log, audit } = this.deps;
    log.debug("Entering AuthzenAdmin.auditGrant(). " + holder.dn);
    const via = String(who.via || 'console');
    if (why) {
      audit.audit({ action: 'admin.authzen.pep.granted', category: 'admin',
                    errorCode: 'STS-FGA-0025', outcome: 'failure',
                    actor: String(who.actor || ''), protocol: 'AuthZEN',
                    target: String(holder.dn || holder.name),
                    // THE SENTENCE IS THE SUMMARY AND THE FACTS THE
                    // DETAIL: an audit row's `detail` is an object, and a
                    // string there is dropped.
                    summary: 'Enabling fine-grained authorization on "' +
                             application + '" did not grant the remote ' +
                             'PEP ' + holder.name + ': ' + why + ' (via ' +
                             via + ').',
                    detail: { application: application,
                              holder: String(holder.name),
                              kind: String(holder.kind), via: via } });
      log.debug("Leaving AuthzenAdmin.auditGrant(). A failure.");
      return;
    }
    const what: string[] = [];
    if (holder.member) {
      what.push('membership of ' +
                String(this.deps.config.value('roles.authzenPepGroup')));
    }
    if (holder.scope) {
      what.push('"' + application + '" in its ' +
                (holder.kind === 'application' ? APPLICATION_SCOPE
                                               : PERSON_SCOPE));
    }
    audit.audit({ action: 'admin.authzen.pep.granted', category: 'admin',
                  actor: String(who.actor || ''), protocol: 'AuthZEN',
                  target: String(holder.dn),
                  summary: 'Enabling fine-grained authorization on "' +
                           application + '" granted the remote PEP ' +
                           holder.name + ' ' + what.join(' and ') +
                           ', so its edge PDP may forward evaluations ' +
                           'about it (via ' + via + ').',
                  detail: { application: application,
                            holder: String(holder.name),
                            kind: String(holder.kind),
                            member: !!holder.member, scope: !!holder.scope,
                            via: via } });
    log.debug("Leaving AuthzenAdmin.auditGrant().");
  }

  /**
   * What every holder of REMOTE_PEPS in the realm holds of what
   * forwarding an application's AuthZEN evaluations needs, for the
   * application's Fine-grained authorization tab (#1210).
   *
   * @param application - the application's identifier
   * @returns `{ group, authzenGroup, total, truncated, unlocated,
   *   holders }`; each holder `{ name, kind, dn, member, scoped }`
   */
  remotePepsOf(application: string): any {
    const self = this;
    const { log, config } = this.deps;
    const id = String(application || '');
    log.debug("Entering AuthzenAdmin.remotePepsOf(). " + id);
    const group = String(config.value('roles.remotePepGroup') || '').trim();
    const authzenGroup = String(config.value('roles.authzenPepGroup') || '')
      .trim();
    const read = self.locateMembers(group, MAX_PEP_GRANT);
    const authzenMembers = directory && authzenGroup
      ? directory.members(authzenGroup).map(function (one: string) {
        return String(one).toLowerCase();
      }) : [];
    const holders = read.candidates.map(function (candidate: any) {
      const state = self.pepState(id, candidate, authzenMembers);
      return { name: candidate.name, kind: candidate.kind,
               dn: candidate.dn, member: !!authzenGroup && state.member,
               scoped: state.scoped };
    });
    log.debug("Leaving AuthzenAdmin.remotePepsOf(). " + holders.length);
    return { group: group, authzenGroup: authzenGroup, total: read.total,
             truncated: read.total > MAX_PEP_GRANT,
             unlocated: read.unlocated.length, holders: holders };
  }

  /**
   * Performs one act of the AuthZEN tab.
   *
   * @param body - the act's fields, `action` among them
   * @param who - `{ actor, via }`, for the audit row
   * @returns `{ ok: true, ... }`, or a coded refusal
   */
  act(body: any, who?: any): any {
    const self = this;
    const { log } = this.deps;
    const given = body || {};
    const action = String(given.action || '');
    log.debug("Entering AuthzenAdmin.act(). " + action);
    let out: any;
    if (action === 'set-attribute') {
      out = self.setAttribute(given, who || {});
    } else if (action === 'remove-attribute') {
      out = self.removeAttribute(given, who || {});
    } else if (action === 'set-scope') {
      out = self.setScope(given, who || {});
    } else if (action === 'set-callbacks') {
      out = self.setCallbacks(given, who || {});
    } else if (/-access-request$/.test(action) &&
               ACTIONS.indexOf(action) >= 0) {
      out = self.accessRequestAct(action, given, who || {});
    } else {
      // THE SENTENCE EVERY ACTION HANDLER HERE WRITES, which
      // `tests/protocol/sts_admin_api_operations.js` reads to hold the
      // document's actions to the handler's.
      out = self.refused('STS-AUTHZEN-0030', 'Unknown action "' +
                         action.slice(0, 60) + '". The ' + ACTIONS.length +
                         ' are: ' + ACTIONS.join(', ') + '.');
    }
    log.debug("Leaving AuthzenAdmin.act(). " + (out.ok ? 'ok' : 'refused'));
    return out;
  }

  // The stored values of the catalogue, and the one for a key.
  private stored(): { values: string[]; object: any } {
    const { log, applications } = this.deps;
    log.debug("Entering AuthzenAdmin.stored().");
    const object = applications.get(API_OBJECT);
    const raw = object && object.fields ? object.fields.authzenAttribute
      : null;
    log.debug("Leaving AuthzenAdmin.stored().");
    return { object: object,
             values: (Array.isArray(raw) ? raw : (raw ? [raw] : []))
               .map(String) };
  }

  private setAttribute(body: any, who: any): any {
    const self = this;
    const { log, applications, audit, errorCodes } = this.deps;
    log.debug("Entering AuthzenAdmin.setAttribute().");
    const fields: any = {};
    ['object', 'property', 'attributeId', 'category', 'dataType',
     'multiplicity', 'description'].forEach(function (name: string) {
      if (body[name] !== undefined && body[name] !== null &&
          String(body[name]).trim() !== '') {
        fields[name] = String(body[name]).trim();
      }
    });
    const parsed = catalogue.parse(fields);
    if (!parsed.row) {
      log.debug("Leaving AuthzenAdmin.setAttribute(). " + parsed.code);
      return self.refused(parsed.code, parsed.problem);
    }
    const held = self.stored();
    if (!held.object) {
      log.debug("Leaving AuthzenAdmin.setAttribute(). No object.");
      return self.refused('STS-AUTHZEN-0014', 'This realm has no ' +
                          API_OBJECT + ' application to hold the catalogue.');
    }
    const key = catalogue.keyOf(parsed.row);
    const value = catalogue.valueOf(parsed.row);
    const replaced = held.values.filter(function (one: string) {
      const old = catalogue.parse(one);
      return old.row && catalogue.keyOf(old.row) === key;
    });
    for (let i = 0; i < replaced.length; i += 1) {
      const gone = applications.updateApplication(API_OBJECT, {
        mode: 'remove', attribute: 'authzenAttribute', value: replaced[i] });
      if (!gone.ok) {
        log.debug("Leaving AuthzenAdmin.setAttribute(). Remove refused.");
        return gone;
      }
    }
    const added = applications.updateApplication(API_OBJECT, {
      mode: 'add', attribute: 'authzenAttribute', value: value });
    if (!added.ok) {
      log.debug("Leaving AuthzenAdmin.setAttribute(). Add refused.");
      return errorCodes.codeOf(added) ? added
        : self.refused('STS-AUTHZEN-0010', (added.errors || []).join(' '));
    }
    audit.audit({ action: 'admin.authzen.attribute.set',
                  actor: String(who.actor || ''), protocol: 'AuthZEN',
                  detail: (replaced.length ? 'Replaced' : 'Added') +
                          ' the catalogue row ' + parsed.row.object + '.' +
                          parsed.row.property + ' → ' +
                          parsed.row.attributeId + ' (via ' +
                          String(who.via || 'console') + ').' });
    log.debug("Leaving AuthzenAdmin.setAttribute().");
    return { ok: true, changed: true, replaced: replaced.length > 0,
             row: Object.assign({ key: key }, parsed.row) };
  }

  private removeAttribute(body: any, who: any): any {
    const self = this;
    const { log, applications, audit } = this.deps;
    log.debug("Entering AuthzenAdmin.removeAttribute().");
    const key = catalogue.keyOf({ object: String(body.object || '').trim(),
                                  property: String(body.property || '')
                                    .trim() });
    const held = self.stored();
    const mine = held.values.filter(function (one: string) {
      const old = catalogue.parse(one);
      return old.row && catalogue.keyOf(old.row) === key;
    });
    if (!mine.length) {
      log.debug("Leaving AuthzenAdmin.removeAttribute(). Not held.");
      return self.refused('STS-AUTHZEN-0031', 'The catalogue has no row ' +
                          'for ' + key.replace(':', '.').slice(0, 200) + '.');
    }
    for (let i = 0; i < mine.length; i += 1) {
      const gone = applications.updateApplication(API_OBJECT, {
        mode: 'remove', attribute: 'authzenAttribute', value: mine[i] });
      if (!gone.ok) {
        log.debug("Leaving AuthzenAdmin.removeAttribute(). Refused.");
        return gone;
      }
    }
    audit.audit({ action: 'admin.authzen.attribute.removed',
                  actor: String(who.actor || ''), protocol: 'AuthZEN',
                  detail: 'Removed the catalogue row ' +
                          key.replace(':', '.') + ' (via ' +
                          String(who.via || 'console') + ').' });
    log.debug("Leaving AuthzenAdmin.removeAttribute().");
    return { ok: true, changed: true, removed: key };
  }

  private setScope(body: any, who: any): any {
    const self = this;
    const { log, applications, audit } = this.deps;
    log.debug("Entering AuthzenAdmin.setScope().");
    const raw = body.applications;
    const list = (Array.isArray(raw) ? raw
      : String(raw == null ? '' : raw).split(/[\s,]+/))
      .map(function (one: unknown) {
        return String(one).trim();
      }).filter(Boolean)
      .filter(function (one: string, i: number, all: string[]) {
        return all.indexOf(one) === i;
      });
    if (list.length > MAX_SCOPE || list.some(function (one: string) {
      return one.length > 256 || /[\x00-\x1f]/.test(one);
    })) {
      log.debug("Leaving AuthzenAdmin.setScope(). Too many or too long.");
      return self.refused('STS-AUTHZEN-0032', 'A caller may be scoped to at ' +
                          'most ' + MAX_SCOPE + ' applications, each a name ' +
                          'of at most 256 printable characters.');
    }
    const caller = self.callerOf(String(body.caller || ''));
    if (!caller) {
      log.debug("Leaving AuthzenAdmin.setScope(). Nobody.");
      return self.refused('STS-AUTHZEN-0033', 'There is no person, service ' +
                          'account or application called "' +
                          String(body.caller || '').slice(0, 120) +
                          '" in this realm.');
    }
    if (caller.kind === 'application') {
      caller.applications.forEach(function (one: string) {
        applications.updateApplication(caller.name, {
          mode: 'remove', attribute: APPLICATION_SCOPE, value: one });
      });
      for (let i = 0; i < list.length; i += 1) {
        const added = applications.updateApplication(caller.name, {
          mode: 'add', attribute: APPLICATION_SCOPE, value: list[i] });
        if (!added.ok) {
          log.debug("Leaving AuthzenAdmin.setScope(). Refused.");
          return added;
        }
      }
    } else if (!directory || !directory.write(caller.dn, PERSON_SCOPE, list)) {
      log.debug("Leaving AuthzenAdmin.setScope(). Not written.");
      return self.refused('STS-AUTHZEN-0033', 'The scope could not be ' +
                          'written onto ' + caller.dn + '.');
    }
    audit.audit({ action: 'admin.authzen.scope.set',
                  actor: String(who.actor || ''), protocol: 'AuthZEN',
                  detail: 'Scoped the AuthZEN caller ' + caller.name + ' to ' +
                          (list.length ? list.join(', ') : 'no application') +
                          ' (via ' + String(who.via || 'console') + ').' });
    log.debug("Leaving AuthzenAdmin.setScope().");
    return { ok: true, changed: true,
             caller: Object.assign({}, caller, { applications: list }) };
  }

  // THE CALLBACK URLS A CALLER MAY NAME (#1180, rcbj's decision 4): an
  // administrator's, replaced whole, https only — the access request's
  // callback is held to these exactly, and a request can name no other.
  private setCallbacks(body: any, who: any): any {
    const self = this;
    const { log, applications, audit } = this.deps;
    log.debug("Entering AuthzenAdmin.setCallbacks().");
    const raw = body.callbacks;
    const list = (Array.isArray(raw) ? raw
      : String(raw == null ? '' : raw).split(/[\s,]+/))
      .map(function (one: unknown) {
        return String(one).trim();
      }).filter(Boolean)
      .filter(function (one: string, i: number, all: string[]) {
        return all.indexOf(one) === i;
      });
    const bad = list.filter(function (one: string) {
      let url: URL | null = null;
      try {
        url = new URL(one);
      } catch (e) {
        log.debug("Caught in AuthzenAdmin.setCallbacks(): " +
                  ((e && e.message) || e));
        url = null;
      }
      return !url || url.protocol !== 'https:' || one.length > 2048 ||
             !!url.username || !!url.password || !!url.hash;
    });
    if (list.length > MAX_CALLBACKS || bad.length) {
      log.debug("Leaving AuthzenAdmin.setCallbacks(). Refused.");
      return self.refused('STS-AUTHZEN-0094', 'A caller may have at most ' +
                          MAX_CALLBACKS + ' callback URLs, each an https ' +
                          'URL with no credentials and no fragment' +
                          (bad.length ? '; "' + bad[0].slice(0, 120) +
                                        '" is not one' : '') + '.');
    }
    const caller = self.callerOf(String(body.caller || ''));
    if (!caller) {
      log.debug("Leaving AuthzenAdmin.setCallbacks(). Nobody.");
      return self.refused('STS-AUTHZEN-0094', 'There is no person, service ' +
                          'account or application called "' +
                          String(body.caller || '').slice(0, 120) +
                          '" in this realm.');
    }
    if (caller.kind === 'application') {
      caller.callbacks.forEach(function (one: string) {
        applications.updateApplication(caller.name, {
          mode: 'remove', attribute: APPLICATION_CALLBACK, value: one });
      });
      for (let i = 0; i < list.length; i += 1) {
        const added = applications.updateApplication(caller.name, {
          mode: 'add', attribute: APPLICATION_CALLBACK, value: list[i] });
        if (!added.ok) {
          log.debug("Leaving AuthzenAdmin.setCallbacks(). Refused.");
          return added;
        }
      }
    } else if (!directory ||
               !directory.write(caller.dn, PERSON_CALLBACK, list)) {
      log.debug("Leaving AuthzenAdmin.setCallbacks(). Not written.");
      return self.refused('STS-AUTHZEN-0094', 'The callback URLs could not ' +
                          'be written onto ' + caller.dn + '.');
    }
    audit.audit({ action: 'admin.authzen.callbacks.set',
                  actor: String(who.actor || ''), protocol: 'AuthZEN',
                  detail: 'Registered ' + list.length + ' access request ' +
                          'callback URL(s) for the AuthZEN caller ' +
                          caller.name + ' (via ' +
                          String(who.via || 'console') + ').' });
    log.debug("Leaving AuthzenAdmin.setCallbacks().");
    return { ok: true, changed: true,
             caller: Object.assign({}, caller, { callbacks: list }) };
  }

  // AN ADMINISTRATOR'S ACT ON ONE ACCESS REQUEST (#1180): the portal's
  // door, `decide()`, with the management API's verified caller as the
  // approver and its roles — so the access-control policy's fourth rule is
  // asked, and self-approval is refused here as it is there.
  private accessRequestAct(action: string, body: any, who: any): any {
    const { log } = this.deps;
    log.debug("Entering AuthzenAdmin.accessRequestAct(). " + action);
    const requests = this.deps.loadAccessRequests();
    const id = String(body.request || '').trim();
    let out: any;
    if (!id || !String(who.actor || '')) {
      out = this.refused('STS-AUTHZEN-0090', 'An access request act names ' +
                         'the request, and is made by a signed-in caller.');
    } else if (action === 'cancel-access-request') {
      out = requests.cancelByAdministrator(id, String(who.actor));
    } else {
      out = requests.decide(id, action.replace(/-access-request$/, ''),
                            { username: String(who.actor),
                              door: 'admin-api',
                              roles: Array.isArray(who.roles)
                                ? who.roles.map(String) : [] });
    }
    log.debug("Leaving AuthzenAdmin.accessRequestAct(). " + !!out.ok);
    return out;
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
const slot = new InstanceSlot<AuthzenAdmin>(
  'authzen/authzen_admin',
  () => new AuthzenAdmin(AuthzenAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The AuthZEN tab's view and acts (#563), and the directory slot
 * `ldap/ldap_server.js` fills.
 * @namespace
 */
export = {
  AuthzenAdmin: AuthzenAdmin,
  installInstance: (one: AuthzenAdmin): void => slot.install(one),
  instanceOrigin: (): string => slot.origin(),
  ACTIONS: ACTIONS,
  PERSON_SCOPE: PERSON_SCOPE,
  APPLICATION_SCOPE: APPLICATION_SCOPE,
  PERSON_CALLBACK: PERSON_CALLBACK,
  APPLICATION_CALLBACK: APPLICATION_CALLBACK,
  MAX_CALLBACKS: MAX_CALLBACKS,
  /**
   * The directory's slot as it was filled (#1180): the access requests
   * read an approver's entry and a group's members through it.
   *
   * @returns the hooks, or null
   */
  directoryHooks: function (): DirectoryHooks | null {
    log.debug("Entering directoryHooks().");
    log.debug("Leaving directoryHooks().");
    return directory;
  },
  /**
   * Fills the directory's slot; `ldap_server.js` calls it when it loads.
   *
   * @param hooks - `locate`, `members`, `write` and `addMember` (#1210),
   *   all four or none
   */
  setDirectory: function (hooks: DirectoryHooks | null): void {
    log.debug("Entering setDirectory().");
    const whole = !!hooks && typeof hooks.locate === 'function' &&
                  typeof hooks.members === 'function' &&
                  typeof hooks.write === 'function' &&
                  typeof hooks.addMember === 'function';
    // VALIDATED WHOLE (rule 3e): a directory offering a read and no write
    // would leave the tab able to show a scope and unable to set one.
    directory = whole ? hooks : null;
    if (hooks && !whole) {
      log.warn('authzen: the directory offered an incomplete AuthZEN slot, ' +
               'so the tab can neither list callers nor set a scope.');
    }
    log.debug("Leaving setDirectory().");
  },
  view: slot.forward('view'),
  act: slot.forward('act'),
  callerOf: slot.forward('callerOf'),
  edgeCandidates: slot.forward('edgeCandidates'),
  grantRemotePeps: slot.forward('grantRemotePeps'),
  remotePepsOf: slot.forward('remotePepsOf')
};
