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

// The most members the tab lists, and the most applications one caller may
// be scoped to. Bounds, because both are drawn on one page.
const MAX_MEMBERS = 200;
const MAX_SCOPE = 64;

// The three acts.
const ACTIONS = Object.freeze(['set-attribute', 'remove-attribute',
                               'set-scope']);

// What the directory slot carries.
interface DirectoryHooks {
  // An entry by name or DN: `{ dn, person, attributes }`, or null.
  locate(key: string): any;
  // The members of a group, as DNs.
  members(group: string): string[];
  // A person's attribute, replaced whole.
  write(dn: string, name: string, values: string[]): boolean;
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
          member: true };
    });
    const asked = String((query || {}).caller || '').trim();
    const consoleModule = self.deps.loadConsole();
    const caller = self.deps.loadCaller();
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
                                                  member: false })
                    : null
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
    const { log, config, applications } = this.deps;
    log.debug("Entering AuthzenAdmin.edgeCandidates().");
    const group = String(config.value('roles.authzenPepGroup') || '');
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
    let unlocated = 0;
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
        unlocated++;
      }
    });
    log.debug("Leaving AuthzenAdmin.edgeCandidates(). " + candidates.length +
              " of " + members.length + ".");
    return { group: group, total: members.length, candidates: candidates,
             unlocated: unlocated };
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
    } else {
      // THE SENTENCE EVERY ACTION HANDLER HERE WRITES, which
      // `tests/protocol/sts_admin_api_operations.js` reads to hold the
      // document's actions to the handler's.
      out = self.refused('STS-AUTHZEN-0030', 'Unknown action "' +
                         action.slice(0, 60) + '". The three are: ' +
                         ACTIONS.join(', ') + '.');
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
  /**
   * Fills the directory's slot; `ldap_server.js` calls it when it loads.
   *
   * @param hooks - `locate`, `members` and `write`, all three or none
   */
  setDirectory: function (hooks: DirectoryHooks | null): void {
    log.debug("Entering setDirectory().");
    const whole = !!hooks && typeof hooks.locate === 'function' &&
                  typeof hooks.members === 'function' &&
                  typeof hooks.write === 'function';
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
  edgeCandidates: slot.forward('edgeCandidates')
};
