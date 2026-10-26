// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: rights.ts
//
// ---------------------------------------------------------------------------
// WHO MAY RUN A REPORT (#956).
//
// `report:admin` sees every definition and every job in the realm.
// `report:use` is narrower. When `report.usersGroup` is empty, only a
// member of Admin Read or Admin Write may be issued it; when it names a
// group, a member of that group may, and an administrator may as well.
// `report:admin` is issued only to those two admin groups. A scheduled
// run asks the same question of the definition's owner and does not ask
// whether the account
// is disabled: that read walks the directory, and a job must not.
//
// Membership is one `entries.get` of the group. A test installs a checker
// and a member probe so neither the schedule nor a share has to open the
// directory.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({ name: 'sts-report-rights' });

let checker: ((subject: string, scope: string) => any) | null = null;
let memberProbe: ((subject: string, groupDn: string) => boolean) | null =
  null;
let groupProbe: ((groupDn: string) => boolean) | null = null;

function reportInstallChecker(fn: ((subject: string, scope: string) => any) |
    null): void {
  log.debug("Entering reportInstallChecker().");
  checker = fn;
  log.debug("Leaving reportInstallChecker().");
}

function reportInstallMemberProbe(fn: ((subject: string,
    groupDn: string) => boolean) | null): void {
  log.debug("Entering reportInstallMemberProbe().");
  memberProbe = fn;
  log.debug("Leaving reportInstallMemberProbe().");
}

function reportInstallGroupProbe(fn: ((groupDn: string) => boolean) |
    null): void {
  log.debug("Entering reportInstallGroupProbe().");
  groupProbe = fn;
  log.debug("Leaving reportInstallGroupProbe().");
}

function reportUsername(subject: string): string {
  log.debug("Entering reportUsername().");
  const helpers = require('../common/helpers');
  const name = String(helpers.nameForSubject(subject) || '');
  log.debug("Leaving reportUsername().");
  return name;
}

function reportPersonDn(subject: string): string {
  log.debug("Entering reportPersonDn().");
  const name = reportUsername(subject);
  if (!name) {
    log.debug("Leaving reportPersonDn(). No name.");
    return '';
  }
  const ldap = require('../ldap/ldap_server');
  log.debug("Leaving reportPersonDn().");
  return 'uid=' + name + ',' + ldap.usersDn();
}

function reportGroupDn(cn: string): string {
  log.debug("Entering reportGroupDn().");
  const ldap = require('../ldap/ldap_server');
  log.debug("Leaving reportGroupDn().");
  return 'cn=' + cn + ',' + ldap.groupsDn();
}

function reportConfiguredGroup(): string {
  log.debug("Entering reportConfiguredGroup().");
  const config = require('../common/config');
  const raw = String(config.value('report.usersGroup') || '').trim();
  if (!raw) {
    log.debug("Leaving reportConfiguredGroup(). Empty.");
    return '';
  }
  if (raw.indexOf('=') >= 0) {
    log.debug("Leaving reportConfiguredGroup(). A DN.");
    return raw;
  }
  const dn = reportGroupDn(raw);
  log.debug("Leaving reportConfiguredGroup().");
  return dn;
}

function reportAdminGroups(): string[] {
  log.debug("Entering reportAdminGroups().");
  const config = require('../common/config');
  const read = String(config.value('admin.readGroup') || 'admin-read');
  const write = String(config.value('admin.writeGroup') || 'admin-write');
  const out = [reportGroupDn(read), reportGroupDn(write)];
  log.debug("Leaving reportAdminGroups().");
  return out;
}

function reportMemberDns(entry: any): string[] {
  log.debug("Entering reportMemberDns().");
  const attrs = (entry && entry.attributes) || {};
  const lists = [attrs.member, attrs.uniqueMember, attrs.uniqueMember];
  const out: string[] = [];
  lists.forEach(function (list: any): void {
    const values = Array.isArray(list) ? list : (list ? [list] : []);
    values.forEach(function (value: any): void {
      if (value) {
        out.push(String(value));
      }
    });
  });
  log.debug("Leaving reportMemberDns().");
  return out;
}

function reportOnGroup(subject: string, groupDn: string): boolean {
  log.debug("Entering reportOnGroup().");
  if (!groupDn) {
    log.debug("Leaving reportOnGroup(). No group.");
    return false;
  }
  if (memberProbe) {
    const answer = !!memberProbe(subject, groupDn);
    log.debug("Leaving reportOnGroup(). Probe.");
    return answer;
  }
  const ldap = require('../ldap/ldap_server');
  const entry = ldap.entries.get(groupDn);
  const person = reportPersonDn(subject).toLowerCase();
  if (!entry || !person) {
    log.debug("Leaving reportOnGroup(). Missing.");
    return false;
  }
  const hit = reportMemberDns(entry).some(function (dn: string): boolean {
    return dn.toLowerCase() === person;
  });
  log.debug("Leaving reportOnGroup().");
  return hit;
}

/**
 * Whether this subject may be issued the scope the token already carries.
 * An administrator skips the group. Anyone else must be in the configured
 * group, or in an admin group when none is configured.
 *
 * @param subject - the token's subject
 * @param scope - the token's scope string
 * @returns `{ ok: true, username }` or a refusal carrying STS-REPORT-0018
 */
function reportMayUse(subject: string, scope: string): any {
  log.debug("Entering reportMayUse().");
  if (checker) {
    const out = checker(subject, scope);
    log.debug("Leaving reportMayUse(). Injected.");
    return out;
  }
  const parts = String(scope || '').split(/\s+/);
  if (parts.indexOf('report:admin') >= 0) {
    log.debug("Leaving reportMayUse(). Administrator.");
    return { ok: true, username: reportUsername(subject) };
  }
  const configured = reportConfiguredGroup();
  const groups = configured ? [configured] : reportAdminGroups();
  let allowed = false;
  for (let i = 0; i < groups.length; i++) {
    if (reportOnGroup(subject, groups[i])) {
      allowed = true;
    }
  }
  if (!allowed) {
    log.warn(errorCodes.tag('STS-REPORT-0018') +
      'report: this account is not in the group that may run reports.');
    log.debug("Leaving reportMayUse(). Refused.");
    return {
      ok: false,
      code: 'STS-REPORT-0018',
      error: 'forbidden',
      description: 'This account cannot use reports.'
    };
  }
  log.debug("Leaving reportMayUse().");
  return { ok: true, username: reportUsername(subject) };
}

function reportShares(subject: string, groups: string[]): boolean {
  log.debug("Entering reportShares().");
  const list = Array.isArray(groups) ? groups : [];
  let hit = false;
  for (let i = 0; i < list.length; i++) {
    if (reportOnGroup(subject, list[i])) {
      hit = true;
    }
  }
  log.debug("Leaving reportShares().");
  return hit;
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
  if (groupProbe) {
    const answer = !!groupProbe(groupDn);
    log.debug("Leaving reportGroupExists(). Probe.");
    return answer;
  }
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

function reportIsAdmin(scope: string): boolean {
  log.debug("Entering reportIsAdmin().");
  const admin = String(scope || '').split(/\s+/).indexOf('report:admin') >=
    0;
  log.debug("Leaving reportIsAdmin().");
  return admin;
}

function reportCanEdit(subject: string, scope: string, row: any): boolean {
  log.debug("Entering reportCanEdit().");
  const allowed = reportIsAdmin(scope) ||
    (!!row && row.owner === subject);
  log.debug("Leaving reportCanEdit().");
  return allowed;
}

function reportAdminNames(): string[] {
  log.debug("Entering reportAdminNames().");
  const config = require('../common/config');
  const read = String(config.value('admin.readGroup') || 'admin-read');
  const write = String(config.value('admin.writeGroup') || 'admin-write');
  log.debug("Leaving reportAdminNames().");
  return [read, write];
}

function reportNarrowOn(username: string, groupKey: string): boolean {
  log.debug("Entering reportNarrowOn().");
  if (!username || !groupKey) {
    log.debug("Leaving reportNarrowOn(). Missing.");
    return false;
  }
  if (memberProbe) {
    const answer = !!memberProbe(username, groupKey);
    log.debug("Leaving reportNarrowOn(). Probe.");
    return answer;
  }
  const ldap = require('../ldap/ldap_server');
  const dn = groupKey.indexOf('=') >= 0 ? groupKey :
    ('cn=' + groupKey + ',' + ldap.groupsDn());
  const entry = ldap.entries.get(dn);
  const person = ('uid=' + username + ',' + ldap.usersDn()).toLowerCase();
  if (!entry) {
    log.debug("Leaving reportNarrowOn(). No group.");
    return false;
  }
  const hit = reportMemberDns(entry).some(function (one: string): boolean {
    return one.toLowerCase() === person;
  });
  log.debug("Leaving reportNarrowOn().");
  return hit;
}

/**
 * Drops `report:use` and `report:admin` from a scope a subject may not be
 * issued. An application subject keeps neither. An administrator keeps
 * both when asked. Anyone else keeps `report:use` only as a member of
 * `report.usersGroup`, and never `report:admin`.
 *
 * @param scope - the scope about to be issued
 * @param subject - `{ kind, name }` from issuance
 * @returns the scope with the two report scopes removed where refused
 */
function reportNarrowScope(scope: string, subject: any): string {
  log.debug("Entering reportNarrowScope().");
  const parts = String(scope || '').split(/\s+/).filter(function (
      one: string): boolean {
    return !!one;
  });
  const asksUse = parts.indexOf('report:use') >= 0;
  const asksAdmin = parts.indexOf('report:admin') >= 0;
  if (!asksUse && !asksAdmin) {
    log.debug("Leaving reportNarrowScope(). None asked.");
    return parts.join(' ');
  }
  let keepUse = false;
  let keepAdmin = false;
  const kind = subject && subject.kind;
  const username = kind === 'user' ? String(subject.name || '') : '';
  if (kind === 'user' && username) {
    const names = reportAdminNames();
    let admin = false;
    for (let i = 0; i < names.length; i++) {
      if (reportNarrowOn(username, names[i])) {
        admin = true;
      }
    }
    keepAdmin = asksAdmin && admin;
    const config = require('../common/config');
    const configured = String(config.value('report.usersGroup') || '')
      .trim();
    if (admin) {
      keepUse = asksUse;
    } else if (configured && asksUse) {
      keepUse = reportNarrowOn(username, configured);
    }
  }
  const kept = parts.filter(function (one: string): boolean {
    if (one === 'report:use') {
      return keepUse;
    }
    if (one === 'report:admin') {
      return keepAdmin;
    }
    return true;
  });
  log.debug("Leaving reportNarrowScope().");
  return kept.join(' ');
}

function reportCanSee(subject: string, scope: string, row: any): boolean {
  log.debug("Entering reportCanSee().");
  if (!row) {
    log.debug("Leaving reportCanSee(). None.");
    return false;
  }
  if (reportIsAdmin(scope) || row.owner === subject) {
    log.debug("Leaving reportCanSee(). Owner.");
    return true;
  }
  const shared = reportShares(subject, row.groups);
  log.debug("Leaving reportCanSee().");
  return shared;
}

export = {
  installChecker: reportInstallChecker,
  installMemberProbe: reportInstallMemberProbe,
  installGroupProbe: reportInstallGroupProbe,
  mayUse: reportMayUse,
  groupExists: reportGroupExists,
  isAdmin: reportIsAdmin,
  canEdit: reportCanEdit,
  canSee: reportCanSee,
  username: reportUsername,
  reportNarrowScope: reportNarrowScope
};
