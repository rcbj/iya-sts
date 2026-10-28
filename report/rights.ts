// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: rights.ts
//
// ---------------------------------------------------------------------------
// WHO MAY REACH WHAT ON THE REPORT API — ASKED OF THE POLICY, DECIDED NOWHERE
// HERE (#1030, 2026-10-27).
//
// Until #1030 this file DECIDED: who may be issued `report:use` (a member of
// `report.usersGroup`, or a console administrator), who may see a definition
// (its owner, a report administrator, a member of a group it is shared
// with) and who may edit one — each an `if` over the token's scope string
// and a group's member list. That is the arrangement every other access
// decision in this service left behind on 2026-09-05 (rcbj: "All access
// control decisions should be implemented with XACML policy and the
// embedded PEP + PDP"), and it is gone. What is here now:
//
//   * **The roles.** `report:use` and `report:admin` are the permissions
//     of the native roles REPORT_USE and REPORT_ADMIN (`common/roles.js`),
//     held through the seeded groups `report-users` and `report-admins`,
//     as a direct member, or — an application — as a member. Issuance
//     narrows them with every other gated permission
//     (`common/role_permissions.ts`); this file never asks who may be
//     issued what.
//   * **The caller.** `callerOf()` is held ∩ carried, the management API's
//     reading (`role_permissions.effectiveRoles()`): the roles the token's
//     subject holds NOW in the realm that issued it, less any whose
//     permission the token does not carry. A role taken away after the
//     token was minted refuses the call at once (STS-REPORT-0018).
//   * **The decisions.** Every question goes to `common/access_gate.ts` on
//     the resource `report-api`: once for the API (holding a report role,
//     the first rule's any-one), and once per definition or job with the
//     row's OWNER as the question's owner — so the `access-control`
//     document's first rule permits the owner exactly as it permits a
//     person their own portal account — and the row in `reportObject`, for
//     the third rule: a PERSON holding REPORT_ADMIN on any row, a person
//     holding a report role on a row shared with a group they are in, for
//     the actions the realm's policy lists (`read` and `run` by default).
//     An application holding either role is an owner and nothing else
//     (rcbj's decision 4): it reaches, runs, edits and deletes only what it
//     defined. The subject's groups are the PIP's answer
//     (`xacml/xacml_pip.ts`'s owner identity), not a member list read here.
//   * **A scheduled run** asks the same question of the definition's owner
//     (`ownerMayRun()`): the roles that owner holds now, and `run` on the
//     definition.
//   * **A SERVICE ADMINISTRATOR IN ANOTHER REALM (#1038).** The default
//     realm's console roster is the service roster, and rcbj's rule is that
//     its administrators reach every realm's reports, as `/admin-api` lets
//     them reach every realm's console. The report API accepts their
//     default-realm token under another realm's prefix
//     (`report_api.ts`), the caller's roles are the default realm's, and
//     `realm` on the caller says so. `serviceAdministrator()` is the one
//     question that crossing asks — Admin Read or Admin Write on the
//     default realm's roster, now — and a definition or job such a caller
//     makes records `ownerRealm`, so its schedule, its owner's name and its
//     notice are asked in the realm the owner's identity lives in.
//
// A hidden row is answered `not_found` by the API, as before, so a job id
// in a URL is still not permission to read it.
//
// `installOwnerCheck()` is the one seam: a test of the schedule installs an
// answer for `ownerMayRun()` so an in-memory definition store needs no
// directory behind it. Nothing else is injectable.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({ name: 'sts-report-rights' });

/**
 * The two report roles, in the order the API names them.
 */
const REPORT_ROLES = Object.freeze(['REPORT_USE', 'REPORT_ADMIN']);

/**
 * The two report scopes.
 */
const REPORT_SCOPES = Object.freeze(['report:use', 'report:admin']);

/**
 * Who is calling the report API, as every decision sees them.
 */
interface ReportCaller {
  /** The token's `sub`: a `urn:uuid:` person, or a client. */
  subject: string;
  /** The person's username; a client's id for an application. */
  username: string;
  /** `user` or `application`. */
  kind: string;
  /** The roles the decision is on: held ∩ carried, built-ins included. */
  roles: string[];
  /** The token's scope string. */
  scope: string;
  /** The client the token was issued to. */
  clientId: string;
  /**
   * The realm the caller's identity is in, when it is not the realm the
   * request is in: the default realm's id for a service administrator
   * reaching another realm (#1038), '' otherwise.
   */
  realm: string;
}

let ownerCheck: ((definition: any) => any) | null = null;

/**
 * Installs the answer `ownerMayRun()` gives, for a test of the schedule
 * over an in-memory store; null puts the policy back.
 *
 * @param fn - `(definition) => { ok, username }`, or null
 */
function reportInstallOwnerCheck(fn: ((definition: any) => any) | null):
    void {
  log.debug("Entering reportInstallOwnerCheck().");
  ownerCheck = fn;
  log.debug("Leaving reportInstallOwnerCheck().");
}

function reportUsername(subject: string): string {
  log.debug("Entering reportUsername().");
  const helpers = require('../common/helpers');
  const name = String(helpers.nameForSubject(subject) || '');
  log.debug("Leaving reportUsername().");
  return name;
}

/**
 * Runs `fn` in the realm a row's owner lives in (#1038): the named realm
 * when it is defined and is not the ambient one, the ambient realm
 * otherwise.
 *
 * @param ownerRealm - the row's `ownerRealm`, '' for this realm
 * @param fn - what to run
 * @returns what `fn` returns
 */
function reportInOwnerRealm<T>(ownerRealm: string, fn: () => T): T {
  log.debug("Entering reportInOwnerRealm().");
  const realms = require('../common/realms');
  const id = String(ownerRealm || '');
  const realm = id && id !== realms.currentId() ? realms.get(id) : null;
  log.debug("Leaving reportInOwnerRealm(). " + (realm ? id : 'here'));
  return realm ? realms.run(realm, fn) : fn();
}

/**
 * Whether a person is a service administrator now: Admin Read or Admin
 * Write on the DEFAULT realm's console roster (#1038). Asked of a
 * default-realm caller reaching another realm's reports, and of the owner
 * of a definition made that way when its schedule runs.
 *
 * @param username - the person's username in the default realm
 * @returns true for a service administrator
 */
function reportServiceAdministrator(username: string): boolean {
  log.debug("Entering reportServiceAdministrator().");
  const name = String(username || '').trim();
  if (!name) {
    log.debug("Leaving reportServiceAdministrator(). Nobody.");
    return false;
  }
  const realms = require('../common/realms');
  const rolePermissions = require('../common/role_permissions');
  let held: any = { configured: [] };
  try {
    held = rolePermissions.heldRoles({ kind: 'user', name: name,
                                       authenticated: true },
                                     realms.DEFAULT_ID);
  } catch (e) {
    // A roster that cannot be read makes nobody a service administrator:
    // the crossing it would open is the wider one.
    log.debug("Caught in reportServiceAdministrator(): " +
              ((e && e.message) || e));
    held = { configured: [] };
  }
  const configured = (held.configured || []).map(String);
  const yes = configured.indexOf('ADMIN_READ') >= 0 ||
    configured.indexOf('ADMIN_WRITE') >= 0;
  log.debug("Leaving reportServiceAdministrator(). " + yes);
  return yes;
}

// A client's own subject, as `oauth2.ts` mints it: the bare client_id, or
// `urn:sts:client:<id>` in RFC 9700 mode.
function reportClientIdOf(subject: string): string {
  log.debug("Entering reportClientIdOf().");
  const text = String(subject || '');
  const id = text.indexOf('urn:sts:client:') === 0
    ? text.slice('urn:sts:client:'.length) : text;
  log.debug("Leaving reportClientIdOf().");
  return id;
}

function reportGroupDn(cn: string): string {
  log.debug("Entering reportGroupDn().");
  const ldap = require('../ldap/ldap_server');
  log.debug("Leaving reportGroupDn().");
  return 'cn=' + cn + ',' + ldap.groupsDn();
}

/**
 * Whether the group is a real group in this realm. A DN outside
 * `ou=groups`, or one the directory does not have, is not.
 *
 * @param groupDn - the offered DN
 * @returns true when the share may name it
 */
function reportGroupExists(groupDn: string): boolean {
  log.debug("Entering reportGroupExists().");
  const ldap = require('../ldap/ldap_server');
  const parent = String(ldap.groupsDn() || '').toLowerCase();
  const text = String(groupDn || '').trim();
  const lower = text.toLowerCase();
  const under = lower === parent || lower.endsWith(',' + parent);
  if (!under) {
    log.debug("Leaving reportGroupExists(). Outside the container.");
    return false;
  }
  const found = !!ldap.entries.get(text);
  log.debug("Leaving reportGroupExists().");
  return found;
}

/**
 * The caller a verified token is, for every decision: held ∩ carried.
 *
 * @param claims - the token's verified claims
 * @param carried - the scope values it carries
 * @returns `{ ok: true, who }`, or `{ ok: false, code, error, description }`
 *   when a report scope it carries is authorized by no role its subject
 *   holds now (STS-REPORT-0018)
 */
function reportCallerOf(claims: any, carried: string[]): any {
  log.debug("Entering reportCallerOf().");
  const rolePermissions = require('../common/role_permissions');
  const realms = require('../common/realms');
  const c = claims || {};
  const scopes = (carried || []).map(String);
  const effective = rolePermissions.effectiveRoles(c, scopes,
    realms.currentId());
  const withdrawn = (effective.withdrawn || []).filter(function (
      one: string): boolean {
    return REPORT_SCOPES.indexOf(one) >= 0;
  });
  if (withdrawn.length) {
    log.warn(errorCodes.tag('STS-REPORT-0018') +
      'report: the token carries ' + withdrawn.join(', ') + ' and its ' +
      'subject holds no role authorizing it now: ' + effective.why);
    log.debug("Leaving reportCallerOf(). Withdrawn.");
    return {
      ok: false,
      code: 'STS-REPORT-0018',
      error: 'forbidden',
      description: 'This token carries ' + withdrawn.join(' and ') +
        ', and no role its subject holds now authorizes it: ' +
        effective.why + '. REPORT_USE and REPORT_ADMIN are held through ' +
        'the groups report-users and report-admins, as a member, or by ' +
        'an application as a member.'
    };
  }
  const kind = effective.subject.kind === 'application' ? 'application'
                                                        : 'user';
  const who: ReportCaller = {
    subject: String(c.sub || ''),
    username: kind === 'application'
      ? reportClientIdOf(String(c.sub || c.client_id || ''))
      : String(c.username || reportUsername(String(c.sub || '')) || ''),
    kind: kind,
    roles: (effective.roles || []).map(String),
    scope: scopes.join(' '),
    clientId: String(c.client_id || ''),
    realm: ''
  };
  log.debug("Leaving reportCallerOf(). " + kind + ' ' + who.username);
  return { ok: true, who: who };
}

// ONE QUESTION TO THE GATE. `object` is null for the API itself.
function reportDecide(who: ReportCaller, action: string, object: any): any {
  log.debug("Entering reportDecide(). " + action);
  const accessGate = require('../common/access_gate');
  const ownership = require('../common/ownership');
  const row = object ? {
    kind: String(object.kind || 'definition'),
    owner: String(object.owner || ''),
    groups: (Array.isArray(object.groups) ? object.groups : [])
      .map(function (one: any): string {
        return ownership.dnKey(one);
      }).filter(Boolean),
    // The PIP reads the person's groups by USERNAME in the ambient realm,
    // so a caller from another realm (#1038) names nobody here: `admin` in
    // the default realm and `admin` in this one are two people, and the
    // second one's shares are not the first one's.
    person: who.kind === 'user' && !who.realm ? who.username : ''
  } : null;
  const answer = accessGate.check({
    resource: accessGate.RESOURCE.REPORT_API,
    action: action,
    // THE OWNER IS THE FIRST RULE'S COMPARISON: the row's owner against
    // the subject-id, which is the token's `sub` here — a person's
    // `urn:uuid:`, or the client. An empty owner is no owner (a question
    // about the API), and the gate drops it.
    owner: row ? row.owner : '',
    requiredRoles: REPORT_ROLES.slice(0),
    reportObject: row,
    subject: { name: who.subject, label: who.username, kind: who.kind,
               authenticated: true, roles: who.roles, effective: true,
               sessionId: null },
    context: { object: row ? row.kind : 'api' }
  });
  log.debug("Leaving reportDecide(). " + (answer.allowed ? 'allowed'
                                                          : 'refused'));
  return answer;
}

/**
 * Whether the caller may reach the API at all: holding a report role.
 *
 * @param who - the caller
 * @param method - the HTTP method
 * @returns the gate's answer; `allowed` is what a caller branches on
 */
function reportMayReach(who: ReportCaller, method: string): any {
  log.debug("Entering reportMayReach().");
  const action = String(method || 'GET').toUpperCase() === 'GET' ? 'read'
                                                                   : 'write';
  const answer = reportDecide(who, action, null);
  log.debug("Leaving reportMayReach().");
  return answer;
}

/**
 * Whether the caller holds REPORT_ADMIN as a person — what the API answers
 * as `scope: realm`, and what lets a list name another owner.
 *
 * @param who - the caller
 * @returns true for a report administrator
 */
function reportIsAdmin(who: ReportCaller): boolean {
  log.debug("Entering reportIsAdmin().");
  const admin = !!who && who.kind === 'user' &&
    (who.roles || []).indexOf('REPORT_ADMIN') >= 0;
  log.debug("Leaving reportIsAdmin().");
  return admin;
}

function reportDefinitionObject(row: any): any {
  log.debug("Entering reportDefinitionObject().");
  log.debug("Leaving reportDefinitionObject().");
  return { kind: 'definition', owner: row.owner, groups: row.groups };
}

/**
 * Whether the caller may see a definition.
 *
 * @param who - the caller
 * @param row - the definition
 * @returns true when the policy permits `read`
 */
function reportCanSee(who: ReportCaller, row: any): boolean {
  log.debug("Entering reportCanSee().");
  if (!row) {
    log.debug("Leaving reportCanSee(). None.");
    return false;
  }
  const allowed = !!reportDecide(who, 'read',
    reportDefinitionObject(row)).allowed;
  log.debug("Leaving reportCanSee().");
  return allowed;
}

/**
 * Whether the caller may run a saved definition.
 *
 * @param who - the caller
 * @param row - the definition
 * @returns true when the policy permits `run`
 */
function reportCanRun(who: ReportCaller, row: any): boolean {
  log.debug("Entering reportCanRun().");
  if (!row) {
    log.debug("Leaving reportCanRun(). None.");
    return false;
  }
  const allowed = !!reportDecide(who, 'run',
    reportDefinitionObject(row)).allowed;
  log.debug("Leaving reportCanRun().");
  return allowed;
}

/**
 * Whether the caller may change, share or delete a definition — or, for a
 * job, see everything about it and stop it.
 *
 * @param who - the caller
 * @param row - the definition, or a job as `{ kind: 'job', owner }`
 * @returns true when the policy permits `write`
 */
function reportCanEdit(who: ReportCaller, row: any): boolean {
  log.debug("Entering reportCanEdit().");
  if (!row) {
    log.debug("Leaving reportCanEdit(). None.");
    return false;
  }
  const object = row.kind === 'job'
    ? { kind: 'job', owner: row.owner, groups: row.groups }
    : reportDefinitionObject(row);
  const allowed = !!reportDecide(who, 'write', object).allowed;
  log.debug("Leaving reportCanEdit().");
  return allowed;
}

/**
 * Whether the caller may see a job: its owner, a report administrator, or
 * — through the definition it ran — a shared group's member.
 *
 * @param who - the caller
 * @param job - the job
 * @param definition - the job's definition, or null for an ad-hoc query
 * @returns true when the policy permits `read`
 */
function reportCanSeeJob(who: ReportCaller, job: any,
    definition: any): boolean {
  log.debug("Entering reportCanSeeJob().");
  if (!job) {
    log.debug("Leaving reportCanSeeJob(). None.");
    return false;
  }
  const allowed = !!reportDecide(who, 'read', {
    kind: 'job', owner: job.owner,
    groups: definition && Array.isArray(definition.groups)
      ? definition.groups : []
  }).allowed;
  log.debug("Leaving reportCanSeeJob().");
  return allowed;
}

/**
 * Whether a definition's owner may still run it, for the schedule: the
 * roles that owner holds now, and `run` on the definition.
 *
 * It does not ask whether a person owner's account is disabled: that is
 * a read of their entry, which the scheduler and the runner make through the
 * directory's asynchronous door (`sources.ts`'s `reportOwnerDisabled()`,
 * #1042), and this function is synchronous.
 * @param definition - the definition, with `owner` and `ownerKind`
 * @returns `{ ok: true, username }` or a refusal carrying STS-REPORT-0028
 */
function reportOwnerMayRun(definition: any): any {
  log.debug("Entering reportOwnerMayRun().");
  if (ownerCheck) {
    const out = ownerCheck(definition);
    log.debug("Leaving reportOwnerMayRun(). Injected.");
    return out;
  }
  const def = definition || {};
  const kind = def.ownerKind === 'application' ? 'application' : 'user';
  const owner = String(def.owner || '');
  // AN OWNER FROM ANOTHER REALM (#1038) is a service administrator who
  // defined this here: their name and roles are the default realm's, and
  // they keep the crossing only while they are still on its roster.
  const realms = require('../common/realms');
  const ownerRealm = String(def.ownerRealm || '');
  const crossing = !!ownerRealm && ownerRealm !== realms.currentId();
  const name = kind === 'application' ? reportClientIdOf(owner)
    : reportInOwnerRealm(ownerRealm, function (): string {
      return reportUsername(owner);
    });
  const refusal = {
    ok: false,
    code: 'STS-REPORT-0028',
    error: 'forbidden',
    description: 'The owner can no longer run reports.'
  };
  if (!name) {
    log.debug("Leaving reportOwnerMayRun(). Nobody.");
    return refusal;
  }
  if (crossing && (kind !== 'user' ||
      ownerRealm !== realms.DEFAULT_ID ||
      !reportServiceAdministrator(name))) {
    log.debug("Leaving reportOwnerMayRun(). No longer a service " +
              "administrator.");
    return refusal;
  }
  const rolePermissions = require('../common/role_permissions');
  let held: any = { all: [] };
  try {
    held = rolePermissions.heldRoles({ kind: kind, name: name,
                                       authenticated: true },
                                     crossing ? ownerRealm : undefined);
  } catch (e) {
    // A register that cannot be read holds the owner no role: the safe
    // direction, since the run would read what the owner may no longer.
    log.debug("Caught in reportOwnerMayRun(): " + ((e && e.message) || e));
    held = { all: [] };
  }
  const who: ReportCaller = {
    subject: owner, username: name, kind: kind,
    roles: (held.all || []).map(String), scope: '', clientId: '',
    realm: crossing ? ownerRealm : ''
  };
  const answer = reportDecide(who, 'run', reportDefinitionObject(def));
  if (!answer.allowed) {
    log.debug("Leaving reportOwnerMayRun(). Refused.");
    return refusal;
  }
  log.debug("Leaving reportOwnerMayRun().");
  return { ok: true, username: name };
}

export = {
  REPORT_ROLES: REPORT_ROLES,
  REPORT_SCOPES: REPORT_SCOPES,
  installOwnerCheck: reportInstallOwnerCheck,
  callerOf: reportCallerOf,
  mayReach: reportMayReach,
  groupExists: reportGroupExists,
  isAdmin: reportIsAdmin,
  canSee: reportCanSee,
  canRun: reportCanRun,
  canEdit: reportCanEdit,
  canSeeJob: reportCanSeeJob,
  ownerMayRun: reportOwnerMayRun,
  username: reportUsername,
  clientIdOf: reportClientIdOf,
  inOwnerRealm: reportInOwnerRealm,
  serviceAdministrator: reportServiceAdministrator
};
