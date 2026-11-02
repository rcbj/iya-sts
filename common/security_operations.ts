// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: security_operations.ts
//
// ---------------------------------------------------------------------------
// WHICH CHANGES ARE THE SECURITY ADMINISTRATOR'S (#645, 2026-11-02).
//
// rcbj: "only a security administrator can modify policy object". The role is
// the third console role (`admin-ui/admin_rbac.ts`, SECURITY_ADMIN in
// `common/roles.js`, the permission `admin:security`), and this file is the
// ONE answer to which requests need it, so the management API's gate, the
// directory socket and SCIM cannot come to disagree about it. rcbj's
// decisions on #645 fix the set, and each kind below names its reason:
//
//   * `policy` — a save, a reset or an act of a Directory → Policies kind,
//     read off `admin-core/policy_kinds.ts`, so a kind registered there
//     tomorrow is covered with no edit here.
//   * `reference` — writing the attribute by which an application, a group
//     or a person NAMES a policy of a kind (rule 3cx): each kind's
//     `REFERENCES`, and every reference `PolicySelection.declareReference()`
//     holds. NAMING a policy decides who it governs, which is the policy
//     decision itself made one step along.
//   * `role` — granting or revoking the Security Administrator's role
//     itself, by any door: the roster, the role's register entry, its group,
//     and `admin.securityGroup` (pointing the setting at another group is a
//     grant). Without it, Admin Write could make itself a Security
//     Administrator in one request and the separation would be cosmetic.
//   * `holder` — acting on the account of a person who HOLDS the role: a
//     password reset, a disable, a deletion, a cleared factor, a certificate
//     issued in their name. Without it, Admin Write could reset a Security
//     Administrator's password and sign in as them.
//
// XACML, ALFA, fine-grained authorization, AuthZEN, delegation policy and the
// `xacml.*` switches are NOT here, by rcbj's decision: they stay Admin
// Write's.
//
// **A REFERENCE IS A CHANGE ONLY WHEN IT CHANGES.** The console's field grids
// post every field they draw, the policy reference among them, on every Save
// — so "the body names `stsAttributePolicy`" would refuse Admin Write every
// edit of a person. What counts is the value the write would leave differing
// from the value the object holds now; `''` and `default` are the same value
// (no named policy). That needs the object's current values, which the CALLER
// reads (`SecurityHooks`): this file reads nothing of the directory itself,
// so it requires no module a socket owner would drag forward and is a leaf.
//
// It decides nothing about WHO may: it answers which kind of change a request
// is, and the caller asks the roster. A GET is never one.
//
// A STATIC UTILITY CLASS (#50) over `helpers` and `policy_selection`, with
// `admin-core/policy_kinds.ts` required LAZILY at the first question: that
// module requires the seven policy modules, which are leaves, but loading
// them into whatever first requires this file would run their load-time
// declarations in the wrong place.
// ---------------------------------------------------------------------------
import helpers = require('./helpers');
import PolicySelection = require('./policy_selection');

const { log } = helpers;

// What the console's grids prefix a field with — `admin-core/admin_actions.ts`
// `FIELD_PREFIX` / `USER_FIELD_PREFIX`, both `field.` — and the box suffix a
// multi-valued attribute's boxes carry (`field.<attribute>.<n>`).
const FIELD_PREFIX = 'field.';

// The value a reference holds when it names no policy of its own.
const NO_POLICY = 'default';

// The setting that names the Security Administrator's group.
const SECURITY_GROUP_SETTING = 'admin.securityGroup';

// The console pages a security change can be a write of — every `case` of
// `classify()`. A caller may skip reading a body for any other page.
const PATHS = Object.freeze(['/admin/policies', '/admin/config',
  '/admin/rbac', '/admin/roles', '/admin/groups', '/admin/applications',
  '/admin/users', '/admin/mfa', '/admin/pki']);

// The role's names at the doors that spell it: the roster's id and the
// register's entry.
const ROSTER_ROLE = 'security';
const REGISTER_ROLE = 'SECURITY_ADMIN';

/**
 * A write as the console page it mirrors: `path` is the `/admin/...` path
 * (realm prefix stripped), `action` the action it names, `body` the parsed
 * body.
 */
interface SecurityOperation {
  method: string;
  path: string;
  action: string;
  body: Record<string, any> | null;
}

/**
 * What the caller reads for this file, in the realm the request is about.
 */
interface SecurityHooks {
  // The cn of the Security Administrator's group (`admin.securityGroup`).
  securityGroup(): string;
  // Whether a person holds the role by membership (never through the open
  // window).
  holdsSecurity(username: string): boolean;
  // The values an object holds now for one attribute; [] when it has none or
  // there is no such object.
  applicationValues(identifier: string, attribute: string): string[];
  personValues(username: string, attribute: string): string[];
  groupValues(group: string, attribute: string): string[];
  // An application write's covered attributes, read the way its handler
  // reads them (`admin_actions.fieldsCoveredBy()`); optional.
  fieldsCoveredBy?(body: Record<string, any>): string[];
}

/**
 * The kind of security change a request is, and the words for a refusal.
 */
interface SecurityChange {
  kind: 'policy' | 'reference' | 'role' | 'holder';
  detail: string;
}

/**
 * Which writes only a Security Administrator may make (#645).
 */
class SecurityOperations {
  static readonly SECURITY_GROUP_SETTING = SECURITY_GROUP_SETTING;
  static readonly PATHS = PATHS;
  static readonly ROSTER_ROLE = ROSTER_ROLE;
  static readonly REGISTER_ROLE = REGISTER_ROLE;

  // ---------------------------------------------------------------------------
  // THE REFERENCE ATTRIBUTES, per holder. Read each time: a kind's module
  // declares its references when it loads, and a test may declare one.
  // ---------------------------------------------------------------------------
  /**
   * Lists the attributes by which a holder names a policy of some kind.
   *
   * @param holder - `application`, `group` or `person`
   * @returns the attribute names, lower-cased
   */
  static referenceAttributes(holder: string): string[] {
    log.debug("Entering SecurityOperations.referenceAttributes(). " + holder);
    const out: string[] = [];
    const note = function (name: unknown): void {
      log.debug("Entering note().");
      const clean = String(name || '').trim().toLowerCase();
      if (clean && out.indexOf(clean) < 0) {
        out.push(clean);
      }
      log.debug("Leaving note().");
    };
    SecurityOperations.policyKinds().list().forEach(function (kind: any) {
      const refs = (kind.module && kind.module.REFERENCES) || {};
      note(refs[holder]);
    });
    if (holder === 'group' || holder === 'person') {
      PolicySelection.referencesOn(holder).forEach(function (row: any) {
        note(row.attribute);
      });
    }
    log.debug("Leaving SecurityOperations.referenceAttributes(). " +
              out.length + ".");
    return out;
  }

  /**
   * Lists the RDNs of the Directory → Policies containers
   * (`ou=passwordpolicies`, …), lower-cased: an entry under one is a policy,
   * which the directory socket asks for (#645).
   *
   * @returns the containers' RDNs
   */
  static policyContainers(): string[] {
    log.debug("Entering SecurityOperations.policyContainers().");
    const out = SecurityOperations.policyKinds().list()
      .map(function (kind: any) {
        return String(kind.container || '').replace(/\s+/g, '').toLowerCase();
      })
      .filter(function (one: string, n: number, all: string[]) {
        return !!one && all.indexOf(one) === n;
      });
    log.debug("Leaving SecurityOperations.policyContainers(). " +
              out.length + ".");
    return out;
  }

  // LAZILY, for the header's reason.
  private static policyKinds(): any {
    log.debug("Entering SecurityOperations.policyKinds().");
    log.debug("Leaving SecurityOperations.policyKinds().");
    return require('../admin-core/policy_kinds');
  }

  /**
   * Answers whether an action is a Directory → Policies kind's save, reset
   * or act.
   *
   * @param action - the action's name
   * @returns the kind's label, or '' when it is not one
   */
  static policyAction(action: string): string {
    log.debug("Entering SecurityOperations.policyAction(). " + action);
    const found = SecurityOperations.policyKinds()
      .forAction(String(action || ''));
    log.debug("Leaving SecurityOperations.policyAction(). " +
              (found ? found.kind.id : 'none'));
    return found ? String(found.kind.label || found.kind.id) : '';
  }

  // The values a reference holds, as a comparable set: trimmed, lower-cased,
  // with '' and `default` (no named policy) dropped, sorted.
  private static normal(values: unknown): string[] {
    log.debug("Entering SecurityOperations.normal().");
    const out = [].concat(values === undefined || values === null ? []
                                                                  : values)
      .map(function (one) {
        return String(one).trim().toLowerCase();
      })
      .filter(function (one, n, all) {
        return one !== '' && one !== NO_POLICY && all.indexOf(one) === n;
      })
      .sort();
    log.debug("Leaving SecurityOperations.normal().");
    return out;
  }

  private static differ(before: unknown, after: unknown): boolean {
    log.debug("Entering SecurityOperations.differ().");
    const a = SecurityOperations.normal(before);
    const b = SecurityOperations.normal(after);
    log.debug("Leaving SecurityOperations.differ().");
    return a.join('\n') !== b.join('\n');
  }

  // ---------------------------------------------------------------------------
  // WHAT A BODY WOULD WRITE TO ONE ATTRIBUTE, read every way this console's
  // writers read a body: a JSON `attributes` or `fields` object, a grid's
  // `field.<attribute>` (and its boxes, `field.<attribute>.<n>`), and the
  // attribute's own name as a key. Undefined when the body says nothing
  // about it — which is NOT the same as an empty value, which clears it.
  // ---------------------------------------------------------------------------
  /**
   * Returns what a body would write to one attribute, or undefined when it
   * names none.
   *
   * @param body - the parsed body
   * @param attribute - the attribute, any case
   * @returns the values, or undefined
   */
  static bodyValues(body: Record<string, any> | null,
                    attribute: string): string[] | undefined {
    log.debug("Entering SecurityOperations.bodyValues(). " + attribute);
    const wanted = String(attribute || '').toLowerCase();
    let found: string[] | undefined;
    const take = function (value: unknown): void {
      log.debug("Entering take().");
      found = (found || []).concat(
        [].concat(value === undefined || value === null ? '' : value)
          .map(String));
      log.debug("Leaving take().");
    };
    const scan = function (object: unknown, prefix: string): void {
      log.debug("Entering scan().");
      if (!object || typeof object !== 'object') {
        log.debug("Leaving scan(). Nothing.");
        return;
      }
      Object.keys(object).forEach(function (key) {
        const lower = key.toLowerCase();
        if (prefix && lower.indexOf(prefix) !== 0) {
          return;
        }
        const name = lower.slice(prefix.length);
        if (name === wanted || name.replace(/\.\d+$/, '') === wanted) {
          take(object[key]);
        }
      });
      log.debug("Leaving scan().");
    };
    if (body) {
      scan(body.attributes, '');
      scan(body.fields, '');
      scan(body, FIELD_PREFIX);
      scan(body, '');
    }
    log.debug("Leaving SecurityOperations.bodyValues(). " +
              (found === undefined ? 'absent' : found.length + ' value(s)'));
    return found;
  }

  // The reference attributes on `holder` whose value this body would change,
  // against what `current(attribute)` says the object holds now.
  private static changedReferences(holder: string,
                                   body: Record<string, any> | null,
                                   current: (attribute: string) => string[],
                                   creating: boolean): string[] {
    log.debug("Entering SecurityOperations.changedReferences(). " + holder);
    const out = SecurityOperations.referenceAttributes(holder)
      .filter(function (attribute) {
        const given = SecurityOperations.bodyValues(body, attribute);
        if (given === undefined) {
          return false;
        }
        return SecurityOperations.differ(creating ? [] : current(attribute),
                                         given);
      });
    log.debug("Leaving SecurityOperations.changedReferences(). " +
              out.length + ".");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE DECISION.
  // ---------------------------------------------------------------------------
  /**
   * Answers whether a write is a Security Administrator's, and which kind.
   *
   * @param op - the write, as the console page it mirrors
   * @param hooks - what the caller reads for this file, in the request's realm
   * @returns the change, or null when Admin Write may make it
   */
  static classify(op: SecurityOperation,
                  hooks: SecurityHooks): SecurityChange | null {
    log.debug("Entering SecurityOperations.classify(). " +
              (op && op.method) + " " + (op && op.path) + " " +
              (op && op.action));
    const method = String((op && op.method) || '').toUpperCase();
    if (!op || method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
      log.debug("Leaving SecurityOperations.classify(). A read.");
      return null;
    }
    const path = String(op.path || '').replace(/\/+$/, '');
    const action = String(op.action || (op.body && op.body.action) || '')
      .trim();
    const body = op.body || {};
    let answer: SecurityChange | null = null;
    switch (path) {
      case '/admin/policies':
        answer = SecurityOperations.policyChange(action);
        break;
      case '/admin/config':
        answer = SecurityOperations.settingChange(body);
        break;
      case '/admin/rbac':
        answer = SecurityOperations.rosterChange(action, body);
        break;
      case '/admin/roles':
        answer = SecurityOperations.registerChange(body);
        break;
      case '/admin/groups':
        answer = SecurityOperations.groupChange(action, body, hooks);
        break;
      case '/admin/applications':
        answer = SecurityOperations.applicationChange(action, body, hooks);
        break;
      case '/admin/users':
        answer = SecurityOperations.personChange(action, body, hooks);
        break;
      case '/admin/mfa':
        answer = SecurityOperations.holderChange(
          String(body.user || body.username || ''), hooks);
        break;
      case '/admin/pki':
        answer = String(body.target || '').trim() === 'person'
          ? SecurityOperations.holderChange(String(body.identifier || ''),
                                            hooks)
          : null;
        break;
      default:
        answer = null;
    }
    log.debug("Leaving SecurityOperations.classify(). " +
              (answer ? answer.kind : 'not one'));
    return answer;
  }

  private static policyChange(action: string): SecurityChange | null {
    log.debug("Entering SecurityOperations.policyChange().");
    const label = SecurityOperations.policyAction(action);
    log.debug("Leaving SecurityOperations.policyChange().");
    return label ? { kind: 'policy',
                     detail: '"' + action + '" changes the ' + label } : null;
  }

  // The setting that names the role's group, by `set`/`reset`'s `key` or as
  // a field of `set-many` — `admin_scope.ts`'s `serviceSettingsIn()` reading.
  private static settingChange(body: Record<string, any>):
      SecurityChange | null {
    log.debug("Entering SecurityOperations.settingChange().");
    const named = Object.keys(body).indexOf(SECURITY_GROUP_SETTING) >= 0 ||
      String(body.key || '').trim() === SECURITY_GROUP_SETTING;
    log.debug("Leaving SecurityOperations.settingChange(). " + named);
    return named ? { kind: 'role', detail: SECURITY_GROUP_SETTING + ' names ' +
                     'the Security Administrator\'s group, so changing it ' +
                     'grants the role' } : null;
  }

  private static rosterChange(action: string, body: Record<string, any>):
      SecurityChange | null {
    log.debug("Entering SecurityOperations.rosterChange().");
    const role = String(body.role || '').trim().toLowerCase();
    const hit = (action === 'grant' || action === 'revoke') &&
                role === ROSTER_ROLE;
    log.debug("Leaving SecurityOperations.rosterChange(). " + hit);
    return hit ? { kind: 'role', detail: 'a ' + action + ' of the Security ' +
                   'Administrator\'s role' } : null;
  }

  private static registerChange(body: Record<string, any>):
      SecurityChange | null {
    log.debug("Entering SecurityOperations.registerChange().");
    const role = String(body.role || body.name || '').trim().toUpperCase();
    log.debug("Leaving SecurityOperations.registerChange().");
    return role === REGISTER_ROLE
      ? { kind: 'role', detail: 'a change to ' + REGISTER_ROLE + ', the ' +
          'Security Administrator\'s role' } : null;
  }

  private static groupChange(action: string, body: Record<string, any>,
                             hooks: SecurityHooks): SecurityChange | null {
    log.debug("Entering SecurityOperations.groupChange(). " + action);
    const group = String(body.group || body.displayName || body.cn || '')
      .trim();
    const securityGroup = String(hooks.securityGroup() || '').trim();
    if (group && securityGroup &&
        group.toLowerCase() === securityGroup.toLowerCase()) {
      log.debug("Leaving SecurityOperations.groupChange(). The role's group.");
      return { kind: 'role', detail: group + ' is the Security ' +
               'Administrator\'s group, so "' + action + '" changes who ' +
               'holds the role' };
    }
    if (action === 'set-policy') {
      const attribute = String(body.attribute || '').trim();
      const refs = SecurityOperations.referenceAttributes('group');
      if (refs.indexOf(attribute.toLowerCase()) >= 0 &&
          SecurityOperations.differ(hooks.groupValues(group, attribute),
                                    [String(body.policy || '')])) {
        log.debug("Leaving SecurityOperations.groupChange(). set-policy.");
        return { kind: 'reference', detail: 'it changes the policy the ' +
                 'group ' + group + ' names in ' + attribute };
      }
      log.debug("Leaving SecurityOperations.groupChange(). set-policy " +
                "changes nothing a Security Administrator decides.");
      return null;
    }
    const changed = SecurityOperations.changedReferences('group', body,
      function (attribute) {
        return hooks.groupValues(group, attribute);
      }, action === 'create');
    log.debug("Leaving SecurityOperations.groupChange(). " + changed.length);
    return changed.length
      ? { kind: 'reference', detail: 'it changes the policy the group ' +
          (group || '(new)') + ' names in ' + changed.join(', ') } : null;
  }

  private static applicationChange(action: string, body: Record<string, any>,
                                   hooks: SecurityHooks):
      SecurityChange | null {
    log.debug("Entering SecurityOperations.applicationChange(). " + action);
    const identifier = String(body.application || body.identifier || '')
      .trim();
    const refs = SecurityOperations.referenceAttributes('application');
    const current = function (attribute: string): string[] {
      log.debug("Entering current().");
      log.debug("Leaving current().");
      return identifier ? hooks.applicationValues(identifier, attribute) : [];
    };
    let changed: string[] = [];
    if (action === 'set' || action === 'add' || action === 'remove') {
      const attribute = String(body.attribute || '').trim();
      if (refs.indexOf(attribute.toLowerCase()) >= 0) {
        const before = current(attribute);
        const value = String(body.value === undefined ? '' : body.value);
        const after = action === 'set' ? [value]
          : (action === 'add' ? before.concat([value])
            : before.filter(function (one) {
              return String(one).trim().toLowerCase() !==
                     value.trim().toLowerCase();
            }));
        if (SecurityOperations.differ(before, after)) {
          changed = [attribute];
        }
      }
    } else if (action === 'import-ldif') {
      // AN LDIF FILE NAMING A POLICY creates an application that names it.
      const file = body.file && typeof body.file === 'object'
        ? String(body.file.text || '')
        : String(body.file || body.ldif || '');
      changed = refs.filter(function (attribute) {
        const line = new RegExp('^' + attribute + '\\s*:{1,2}\\s*(\\S.*)$',
                                'im').exec(file);
        return !!line && SecurityOperations.normal([line[1]]).length > 0;
      });
    } else {
      changed = SecurityOperations.changedReferences('application', body,
        current, action === 'create');
      const covered = typeof hooks.fieldsCoveredBy === 'function'
        ? hooks.fieldsCoveredBy(body).map(function (one) {
          return String(one).toLowerCase();
        }) : [];
      covered.forEach(function (attribute) {
        if (refs.indexOf(attribute) >= 0 && changed.indexOf(attribute) < 0 &&
            SecurityOperations.differ(current(attribute),
              SecurityOperations.bodyValues(body, attribute) || [])) {
          changed.push(attribute);
        }
      });
    }
    log.debug("Leaving SecurityOperations.applicationChange(). " +
              changed.length);
    return changed.length
      ? { kind: 'reference', detail: 'it changes the policy the application ' +
          (identifier || '(new)') + ' names in ' + changed.join(', ') } : null;
  }

  private static personChange(action: string, body: Record<string, any>,
                              hooks: SecurityHooks): SecurityChange | null {
    log.debug("Entering SecurityOperations.personChange(). " + action);
    const who = String(body.user || body.username || '').trim();
    const creating = action === 'create';
    if (!creating) {
      const holder = SecurityOperations.holderChange(who, hooks);
      if (holder) {
        log.debug("Leaving SecurityOperations.personChange(). A holder.");
        return holder;
      }
    }
    const changed = SecurityOperations.changedReferences('person', body,
      function (attribute) {
        return who ? hooks.personValues(who, attribute) : [];
      }, creating);
    log.debug("Leaving SecurityOperations.personChange(). " + changed.length);
    return changed.length
      ? { kind: 'reference', detail: 'it changes the policy ' +
          (who || 'the new person') + ' names in ' + changed.join(', ') }
      : null;
  }

  private static holderChange(who: string, hooks: SecurityHooks):
      SecurityChange | null {
    log.debug("Entering SecurityOperations.holderChange().");
    const name = String(who || '').trim();
    const holds = !!name && hooks.holdsSecurity(name) === true;
    log.debug("Leaving SecurityOperations.holderChange(). " + holds);
    return holds ? { kind: 'holder', detail: name + ' holds the Security ' +
                     'Administrator\'s role, so their account is a Security ' +
                     'Administrator\'s to act on' } : null;
  }
}

export = SecurityOperations;
