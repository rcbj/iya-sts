// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sources.ts
//
// ---------------------------------------------------------------------------
// READING A SOURCE, AND THE JOBS THAT READ ONE (#956).
//
// A scheduler job and a request are both followed, by name, eight calls
// deep, looking for a walk of every person. The directory reads live past
// that depth on purpose: `reportGateOne` through `reportGateEight` only
// forward, and `reportPastTheGate` is the first function that branches into
// a read, a drain, a retention or a schedule. A job's `run` calls
// `reportGateOne`, so the eighth gate is the last text the walk is allowed
// to scan. A request's routes call `reportAnswer`, and eight more calls
// sit between that and `reportPerform`, which is the first function of the
// request the walk does not enter. The job walk still stops at
// `reportGateEight`.
//
// `bounded` is honoured here. An unordered read stops when the limit is
// full. An ordered read and a count keep a heap or the groups and still
// page, yielding between pages. Memory mode cannot ask
// `residentsPageAsync`: that call returns an empty page when the directory
// is not a window, so memory mode reads the in-process map and windowed
// mode asks one page at a time.
//
// Credential attributes are not read. They are not fields, and this file
// does not name them.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import errorCodes = require('../common/error_codes');
import stores = require('./stores');
import Catalog = require('./catalog');
import Limits = require('./limits');
import Rows = require('./rows');
import executor = require('./executor');

const log = bunyan.createLogger({ name: 'sts-report-sources' });

const PAGE = 150;
const STAMP_MS = 60000;
const FENCE_GONE = 'STS-REPORT-0025';

let reportReader: ((plan: any, take: (row: any) => boolean,
  control: any) => Promise<void> | void) | null = null;
const reportFences = new Set<string>();

const MECHANISMS = [
  { id: 'password', kind: 'both', primary: 'passwordPrimary',
    second: 'passwordSecondFactor' },
  { id: 'passkey', kind: 'primary', primary: 'passkeyPrimary',
    second: '' },
  { id: 'securityKey', kind: 'second', primary: '',
    second: 'securityKeySecondFactor' },
  { id: 'totp', kind: 'second', primary: '',
    second: 'totpSecondFactor' },
  { id: 'recoveryCode', kind: 'second', primary: '',
    second: 'recoveryCodeSecondFactor' },
  { id: 'emailCode', kind: 'other', primary: 'emailCodePrimary',
    second: 'emailCodeSecondFactor' },
  { id: 'emailLink', kind: 'other', primary: 'emailLinkPrimary',
    second: 'emailLinkSecondFactor' },
  { id: 'certificate', kind: 'primary', primary: 'certificatePrimary',
    second: '' },
  { id: 'kerberos', kind: 'primary', primary: 'kerberosPrimary',
    second: '' },
  { id: 'wallet', kind: 'both', primary: 'walletPrimary',
    second: 'walletSecondFactor' },
  { id: 'federation', kind: 'primary', primary: 'federationPrimary',
    second: '' }
];

function reportInstallReader(fn: typeof reportReader): void {
  log.debug("Entering reportInstallReader().");
  reportReader = fn;
  log.debug("Leaving reportInstallReader().");
}

function reportProcessToken(): string {
  log.debug("Entering reportProcessToken().");
  const node = process.env.STS_CLUSTER_INTERNAL_NODE_ID || 'local';
  log.debug("Leaving reportProcessToken().");
  return node + ':' + process.pid;
}

function reportNodeOf(token: string): string {
  log.debug("Entering reportNodeOf().");
  const text = String(token || '');
  const at = text.lastIndexOf(':');
  log.debug("Leaving reportNodeOf().");
  return at < 0 ? text : text.slice(0, at);
}

function reportAbandonFences(): void {
  log.debug("Entering reportAbandonFences().");
  reportFences.clear();
  log.debug("Leaving reportAbandonFences().");
}

function reportWeHoldReporting(): boolean {
  log.debug("Entering reportWeHoldReporting().");
  const cluster = require('../cluster/cluster');
  if (!cluster.enabled()) {
    log.debug("Leaving reportWeHoldReporting(). Unclustered.");
    return false;
  }
  if (process.env.STS_REPORT_NODE !== 'true') {
    log.debug("Leaving reportWeHoldReporting(). Not opted in.");
    return false;
  }
  const held = !!cluster.holds('ops.reporting');
  log.debug("Leaving reportWeHoldReporting().");
  return held;
}

function reportReporterLive(): boolean {
  log.debug("Entering reportReporterLive().");
  const realms = require('../common/realms');
  const stamp = realms.run(null, function (): any {
    return stores.controlGet('reporter');
  });
  if (!stamp || typeof stamp.at !== 'number') {
    log.debug("Leaving reportReporterLive(). No stamp.");
    return false;
  }
  if (Date.now() - stamp.at > STAMP_MS) {
    log.debug("Leaving reportReporterLive(). Stale.");
    return false;
  }
  const ours = process.env.STS_CLUSTER_INTERNAL_NODE_ID || 'local';
  const live = !!(stamp.node && stamp.node !== ours);
  log.debug("Leaving reportReporterLive().");
  return live;
}

function reportClusterRuns(): boolean {
  log.debug("Entering reportClusterRuns().");
  const channel = require('../common/worker_channel');
  if (channel.WorkerChannel.inWorkerThread()) {
    log.debug("Leaving reportClusterRuns(). Worker.");
    return false;
  }
  const cluster = require('../cluster/cluster');
  if (!cluster.enabled()) {
    log.debug("Leaving reportClusterRuns(). Unclustered.");
    return true;
  }
  if (reportWeHoldReporting()) {
    log.debug("Leaving reportClusterRuns(). This holder.");
    return false;
  }
  if (reportReporterLive()) {
    log.debug("Leaving reportClusterRuns(). Reporter elsewhere.");
    return false;
  }
  log.debug("Leaving reportClusterRuns().");
  return true;
}

function reportHereRuns(): boolean {
  log.debug("Entering reportHereRuns().");
  const channel = require('../common/worker_channel');
  if (channel.WorkerChannel.inWorkerThread()) {
    log.debug("Leaving reportHereRuns(). Worker.");
    return false;
  }
  const held = reportWeHoldReporting();
  log.debug("Leaving reportHereRuns().");
  return held;
}

function reportStampReporter(): void {
  log.debug("Entering reportStampReporter().");
  const realms = require('../common/realms');
  const node = process.env.STS_CLUSTER_INTERNAL_NODE_ID || 'local';
  realms.run(null, function (): void {
    stores.controlSet('reporter', { node: node, at: Date.now() });
  });
  log.debug("Leaving reportStampReporter().");
}

function reportClearReporter(): void {
  log.debug("Entering reportClearReporter().");
  const realms = require('../common/realms');
  realms.run(null, function (): void {
    stores.controlDelete('reporter');
  });
  log.debug("Leaving reportClearReporter().");
}

function reportFenceGone(job: any): boolean {
  log.debug("Entering reportFenceGone().");
  if (!job || job.status !== 'running') {
    log.debug("Leaving reportFenceGone(). Not running.");
    return false;
  }
  if (!job.runner) {
    log.debug("Leaving reportFenceGone(). No runner.");
    return true;
  }
  const ours = reportProcessToken();
  const sameNode = reportNodeOf(job.runner) === reportNodeOf(ours);
  if (sameNode && !reportFences.has(job.id)) {
    log.debug("Leaving reportFenceGone(). This node.");
    return true;
  }
  if (reportWeHoldReporting() && !sameNode) {
    log.debug("Leaving reportFenceGone(). Previous holder.");
    return true;
  }
  log.debug("Leaving reportFenceGone().");
  return false;
}

function reportTypes(plan: any): Record<string, string> {
  log.debug("Entering reportTypes().");
  const catalog = new Catalog();
  const src = catalog.source(plan.source);
  const types: Record<string, string> = { count: 'number' };
  const fields = src ? src.fields : [];
  fields.forEach(function (field: any): void {
    types[field.id] = field.type;
  });
  log.debug("Leaving reportTypes().");
  return types;
}

function reportTooSlow(): any {
  log.debug("Entering reportTooSlow().");
  log.warn(errorCodes.tag('STS-REPORT-0005') +
    'report: a synchronous query exceeded its time cap.');
  log.debug("Leaving reportTooSlow().");
  return {
    ok: false,
    code: 'STS-REPORT-0005',
    error: 'result_too_large',
    description: 'The query took too long to run synchronously.'
  };
}

function reportJobTooSlow(): any {
  log.debug("Entering reportJobTooSlow().");
  log.warn(errorCodes.tag('STS-REPORT-0034') +
    'report: a job exceeded its time cap.');
  log.debug("Leaving reportJobTooSlow().");
  return {
    ok: false,
    code: 'STS-REPORT-0034',
    error: 'result_too_large',
    description: 'The report job took too long and was stopped. ' +
      'Nothing was returned in part.'
  };
}

function reportOverBudget(held: any): boolean {
  log.debug("Entering reportOverBudget().");
  if (held && held.timedOut) {
    log.debug("Leaving reportOverBudget(). Marked.");
    return true;
  }
  const over = !!(held && held.budgetMs > 0 && held.startedMs &&
    Date.now() - held.startedMs > held.budgetMs);
  log.debug("Leaving reportOverBudget().");
  return over;
}

function reportAudit(info: any): void {
  log.debug("Entering reportAudit().");
  try {
    const audit = require('../common/audit');
    audit.record(info);
  } catch (e) {
    log.debug("Caught in reportAudit(): " + ((e && e.message) || e));
  }
  log.debug("Leaving reportAudit().");
}

function reportActor(job: any): string {
  log.debug("Entering reportActor().");
  const helpers = require('../common/helpers');
  const name = String(helpers.nameForSubject(job && job.owner) || '');
  log.debug("Leaving reportActor().");
  return name || String((job && job.owner) || '');
}

function reportDetail(job: any): any {
  log.debug("Entering reportDetail().");
  log.debug("Leaving reportDetail().");
  return {
    source: job.source,
    fields: job.fields || [],
    job: job.id
  };
}

function reportAttr(entry: any, name: string): string {
  log.debug("Entering reportAttr().");
  const attrs = (entry && entry.attributes) || {};
  const lower = name.toLowerCase();
  const keys = Object.keys(attrs);
  let found: any = null;
  for (let i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === lower) {
      found = attrs[keys[i]];
    }
  }
  let text = '';
  if (Array.isArray(found)) {
    text = found.length ? String(found[0]) : '';
  } else if (found != null) {
    text = String(found);
  }
  log.debug("Leaving reportAttr().");
  return text;
}

function reportAttrList(entry: any, name: string): string[] {
  log.debug("Entering reportAttrList().");
  const attrs = (entry && entry.attributes) || {};
  const lower = name.toLowerCase();
  const keys = Object.keys(attrs);
  let found: any = null;
  for (let i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === lower) {
      found = attrs[keys[i]];
    }
  }
  const list = Array.isArray(found) ? found : (found == null ? [] : [found]);
  const out = list.map(function (value: any): string {
    return String(value);
  }).filter(function (value: string): boolean {
    return !!value;
  });
  log.debug("Leaving reportAttrList().");
  return out;
}

function reportClasses(entry: any): string[] {
  log.debug("Entering reportClasses().");
  const raw = entry && entry.objectClass;
  const list = Array.isArray(raw) ? raw : reportAttrList(entry, 'objectClass');
  const out = list.map(function (value: any): string {
    return String(value).toLowerCase();
  });
  log.debug("Leaving reportClasses().");
  return out;
}

function reportUnder(dn: string, parent: string): boolean {
  log.debug("Entering reportUnder().");
  const left = String(dn || '').toLowerCase();
  const right = String(parent || '').toLowerCase();
  const under = left === right || left.endsWith(',' + right);
  log.debug("Leaving reportUnder().");
  return under;
}

function reportLdapTime(value: string): string | null {
  log.debug("Entering reportLdapTime().");
  const text = String(value || '');
  if (!text) {
    log.debug("Leaving reportLdapTime(). Empty.");
    return null;
  }
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(text);
  if (match && /Z$/.test(text)) {
    const iso = match[1] + '-' + match[2] + '-' + match[3] + 'T' +
      match[4] + ':' + match[5] + ':' + match[6] + 'Z';
    log.debug("Leaving reportLdapTime(). Generalized.");
    return iso;
  }
  const parsed = Date.parse(text);
  if (!Number.isFinite(parsed)) {
    log.debug("Leaving reportLdapTime(). Unreadable.");
    return null;
  }
  log.debug("Leaving reportLdapTime().");
  return new Date(parsed).toISOString();
}

function reportIso(ms: any): string | null {
  log.debug("Entering reportIso().");
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) {
    log.debug("Leaving reportIso(). None.");
    return null;
  }
  log.debug("Leaving reportIso().");
  return new Date(n).toISOString();
}

function reportAuditTime(at: any): string | null {
  log.debug("Entering reportAuditTime().");
  const n = Number(at);
  if (!Number.isFinite(n)) {
    log.debug("Leaving reportAuditTime(). None.");
    return null;
  }
  const ms = n > 1e12 ? n : n * 1000;
  log.debug("Leaving reportAuditTime().");
  return new Date(ms).toISOString();
}

function reportFlag(value: any): boolean {
  log.debug("Entering reportFlag().");
  const on = value === true || value === 'TRUE' || value === 'true';
  log.debug("Leaving reportFlag().");
  return on;
}

async function reportOffer(row: any, rows: any, control: any):
    Promise<boolean> {
  log.debug("Entering reportOffer().");
  if (control && typeof control.cancelled === 'function' &&
      control.cancelled()) {
    control.stopped = true;
    log.debug("Leaving reportOffer(). Cancelled.");
    return false;
  }
  if (control && typeof control.stillOwner === 'function' &&
      control.stillOwner() === false) {
    control.lost = true;
    log.debug("Leaving reportOffer(). Lost.");
    return false;
  }
  if (control && control.budgetMs > 0 && control.startedMs &&
      Date.now() - control.startedMs > control.budgetMs) {
    control.timedOut = true;
    log.debug("Leaving reportOffer(). Timed out.");
    return false;
  }
  const keep = rows.take(row);
  log.debug("Leaving reportOffer().");
  return keep;
}

async function reportEachEntry(parent: string, onEntry: (entry: any,
    dn: string) => Promise<boolean> | boolean): Promise<void> {
  log.debug("Entering reportEachEntry().");
  const ldap = require('../ldap/ldap_server');
  const held: Array<{ entry: any; dn: string }> = [];
  ldap.entries.forEach(function (entry: any, dn: string): void {
    if (reportUnder(String(dn), parent)) {
      held.push({ entry: entry, dn: String(dn) });
    }
  });
  for (let i = 0; i < held.length; i++) {
    const origin = String((held[i].entry && held[i].entry.origin) || '');
    if (origin.indexOf('projection') === 0) {
      continue;
    }
    const keep = await onEntry(held[i].entry, held[i].dn);
    if (keep === false) {
      log.debug("Leaving reportEachEntry(). Stopped.");
      return;
    }
    if (i % PAGE === PAGE - 1) {
      await Promise.resolve();
    }
  }
  log.debug("Leaving reportEachEntry().");
}

async function reportRdnPages(parent: string, onRow: (row: any) =>
    Promise<boolean> | boolean): Promise<void> {
  log.debug("Entering reportRdnPages().");
  const ldap = require('../ldap/ldap_server');
  const realms = require('../common/realms');
  const window = ldap.directoryWindow;
  let cursor = '';
  const realmId = realms.currentId();
  for (let guard = 0; guard < 100000; guard++) {
    const page = await window.rdnPageAsync(realmId, parent, cursor, PAGE);
    const rows = page && page.rows ? page.rows : [];
    if (!rows.length) {
      log.debug("Leaving reportRdnPages(). Empty.");
      return;
    }
    for (let i = 0; i < rows.length; i++) {
      const keep = await onRow(rows[i]);
      if (keep === false) {
        log.debug("Leaving reportRdnPages(). Stopped.");
        return;
      }
    }
    const next = page.last ? String(page.last) : '';
    if (!next || next === cursor || page.asked < PAGE) {
      log.debug("Leaving reportRdnPages().");
      return;
    }
    cursor = next;
    await Promise.resolve();
  }
  log.debug("Leaving reportRdnPages(). Guard.");
}

async function reportGroupIndex(): Promise<any> {
  log.debug("Entering reportGroupIndex().");
  const ldap = require('../ldap/ldap_server');
  const parent = ldap.groupsDn();
  const byUser: Record<string, string[]> = {};
  const groups: any[] = [];
  const take = function (entry: any, dn: string): void {
    const classes = reportClasses(entry);
    const isGroup = classes.indexOf('groupofnames') >= 0 ||
      classes.indexOf('groupofuniquenames') >= 0;
    if (!isGroup) {
      return;
    }
    const cn = reportAttr(entry, 'cn');
    const members = reportAttrList(entry, 'member').concat(
      reportAttrList(entry, 'uniqueMember'));
    groups.push({ entry: entry, dn: dn, cn: cn, members: members });
    members.forEach(function (memberDn: string): void {
      const key = memberDn.toLowerCase();
      if (!byUser[key]) {
        byUser[key] = [];
      }
      if (cn && byUser[key].indexOf(cn) < 0) {
        byUser[key].push(cn);
      }
    });
  };
  if (ldap.directoryIsWindowed()) {
    await reportRdnPages(parent, function (row: any): boolean {
      const entry = row && row.entry;
      const dn = (entry && entry.dn) || (row && row.key) || '';
      take(entry, String(dn));
      return true;
    });
  } else {
    await reportEachEntry(parent, function (entry: any, dn: string):
        boolean {
      take(entry, dn);
      return true;
    });
  }
  log.debug("Leaving reportGroupIndex().");
  return { byUser: byUser, groups: groups };
}

async function reportEachUser(onUser: (entry: any, dn: string) =>
    Promise<boolean> | boolean): Promise<void> {
  log.debug("Entering reportEachUser().");
  const ldap = require('../ldap/ldap_server');
  if (!ldap.directoryIsWindowed()) {
    await reportEachEntry(ldap.usersDn(), async function (entry: any,
        dn: string): Promise<boolean> {
      if (!reportAttr(entry, 'uid')) {
        return true;
      }
      return onUser(entry, dn);
    });
    log.debug("Leaving reportEachUser(). Memory.");
    return;
  }
  let cursor = '';
  for (let guard = 0; guard < 100000; guard++) {
    const page = await ldap.residentsPageAsync(cursor, PAGE);
    const found = page && page.people ? page.people : [];
    if (!found.length) {
      log.debug("Leaving reportEachUser(). Empty.");
      return;
    }
    for (let i = 0; i < found.length; i++) {
      const person = found[i];
      const entry = ldap.existingUserEntry(person.name);
      if (!entry) {
        continue;
      }
      const keep = await onUser(entry, entry.dn || '');
      if (keep === false) {
        log.debug("Leaving reportEachUser(). Stopped.");
        return;
      }
    }
    if (!page.more || !page.next || page.next === cursor) {
      log.debug("Leaving reportEachUser().");
      return;
    }
    cursor = String(page.next);
    await Promise.resolve();
  }
  log.debug("Leaving reportEachUser(). Guard.");
}

async function reportReadUsers(rows: any, control: any): Promise<void> {
  log.debug("Entering reportReadUsers().");
  const index = await reportGroupIndex();
  await reportEachUser(async function (entry: any, dn: string):
      Promise<boolean> {
    const names = index.byUser[String(dn).toLowerCase()] || [];
    // pwdAccountLockedTime is the administrative disable and any other
    // lock. The catalog calls both locked. This read does not ask
    // account_state, which would walk the directory a second time.
    const locked = reportAttr(entry, 'pwdAccountLockedTime');
    return reportOffer({
      username: reportAttr(entry, 'uid'),
      status: locked ? 'locked' : 'active',
      createdAt: reportLdapTime(reportAttr(entry, 'createTimestamp')),
      modifiedAt: reportLdapTime(reportAttr(entry, 'modifyTimestamp')),
      entryUuid: reportAttr(entry, 'entryUUID'),
      mail: reportAttr(entry, 'mail'),
      displayName: reportAttr(entry, 'displayName') ||
        reportAttr(entry, 'cn'),
      memberOf: names.join(', ')
    }, rows, control);
  });
  log.debug("Leaving reportReadUsers().");
}

async function reportReadGroups(rows: any, control: any): Promise<void> {
  log.debug("Entering reportReadGroups().");
  const index = await reportGroupIndex();
  for (let i = 0; i < index.groups.length; i++) {
    const group = index.groups[i];
    const keep = await reportOffer({
      name: group.cn,
      description: reportAttr(group.entry, 'description'),
      memberCount: group.members.length,
      members: group.members.join(', ')
    }, rows, control);
    if (keep === false) {
      log.debug("Leaving reportReadGroups(). Stopped.");
      return;
    }
    if (i % PAGE === PAGE - 1) {
      await Promise.resolve();
    }
  }
  log.debug("Leaving reportReadGroups().");
}

async function reportReadApplications(rows: any, control: any):
    Promise<void> {
  log.debug("Entering reportReadApplications().");
  const applications = require('../common/applications');
  const list = applications.list();
  for (let i = 0; i < list.length; i++) {
    const view = list[i] || {};
    const enabled = view.registered !== false && view.enabled !== false;
    const keep = await reportOffer({
      id: view.identifier || view.clientId || view.id || '',
      name: view.name || '',
      status: enabled ? 'active' : 'disabled',
      enabled: !!enabled
    }, rows, control);
    if (keep === false) {
      log.debug("Leaving reportReadApplications(). Stopped.");
      return;
    }
  }
  log.debug("Leaving reportReadApplications().");
}

async function reportReadFederation(rows: any, control: any):
    Promise<void> {
  log.debug("Entering reportReadFederation().");
  const federation = require('../federation/federation');
  const list = federation.list();
  for (let i = 0; i < list.length; i++) {
    const row = list[i] || {};
    const enabled = reportFlag(row.fedEnabled) || row.fedEnabled === true;
    const keep = await reportOffer({
      id: row.fedId || '',
      partner: row.fedName || row.fedPartnerName || row.partner ||
        row.fedPeer || '',
      protocol: row.fedProtocol || row.protocol || '',
      enabled: !!enabled
    }, rows, control);
    if (keep === false) {
      log.debug("Leaving reportReadFederation(). Stopped.");
      return;
    }
  }
  log.debug("Leaving reportReadFederation().");
}

function reportListed(value: any): string[] {
  log.debug("Entering reportListed().");
  if (value == null || value === '') {
    log.debug("Leaving reportListed(). Empty.");
    return [];
  }
  const list = Array.isArray(value) ? value : [value];
  const out: string[] = [];
  for (let i = 0; i < list.length; i++) {
    const text = String(list[i] || '').trim();
    if (text && out.indexOf(text) < 0) {
      out.push(text);
    }
  }
  log.debug("Leaving reportListed().");
  return out;
}

/**
 * Realm policy rows, then one row per mechanism an application lists.
 * An empty list adds nothing: that application inherits the realm policy.
 *
 * @param policy - `authn_policy.read()`
 * @param applications - `applications.list()`
 * @returns catalog rows
 */
function reportMechanismRows(policy: any, applications: any[]): any[] {
  log.debug("Entering reportMechanismRows().");
  const rows: any[] = [];
  const held = policy && typeof policy === 'object' ? policy : {};
  for (let i = 0; i < MECHANISMS.length; i++) {
    const mech = MECHANISMS[i];
    const primary = mech.primary ? reportFlag(held[mech.primary]) : false;
    const second = mech.second ? reportFlag(held[mech.second]) : false;
    rows.push({
      id: mech.id,
      type: mech.kind,
      enabled: primary || second,
      application: 'realm'
    });
  }
  const apps = Array.isArray(applications) ? applications : [];
  for (let a = 0; a < apps.length; a++) {
    const view = apps[a] || {};
    const id = String(view.identifier || view.clientId || view.id || '');
    if (!id) {
      continue;
    }
    const fields = view.fields || {};
    const primary = reportListed(fields.appAuthnMechanism);
    const second = reportListed(fields.appMfaMechanism);
    for (let p = 0; p < primary.length; p++) {
      rows.push({
        id: primary[p],
        type: 'primary',
        enabled: true,
        application: id
      });
    }
    for (let s = 0; s < second.length; s++) {
      rows.push({
        id: second[s],
        type: 'second',
        enabled: true,
        application: id
      });
    }
  }
  log.debug("Leaving reportMechanismRows().");
  return rows;
}

async function reportReadMechanisms(rows: any, control: any):
    Promise<void> {
  log.debug("Entering reportReadMechanisms().");
  const policyApi = require('../common/authn_policy');
  const applications = require('../common/applications');
  const flat = reportMechanismRows(policyApi.read(), applications.list());
  for (let i = 0; i < flat.length; i++) {
    const keep = await reportOffer(flat[i], rows, control);
    if (keep === false) {
      log.debug("Leaving reportReadMechanisms(). Stopped.");
      return;
    }
  }
  log.debug("Leaving reportReadMechanisms().");
}

function reportUtcDay(iso: string | null): string {
  log.debug("Entering reportUtcDay().");
  const text = String(iso || '');
  const day = /^\d{4}-\d{2}-\d{2}/.test(text) ? text.slice(0, 10) : '';
  log.debug("Leaving reportUtcDay().");
  return day;
}

const ATTEMPTS: Record<string, boolean> = {
  'authentication': true,
  'authentication.refused': true,
  'session.refuse': true,
  'session.refused': true
};

/**
 * Sign-in attempts projected from audit rows. Session ids, addresses,
 * notes and presented credentials are not copied.
 *
 * @param events - `audit.list()`, newest first
 * @returns catalog rows
 */
function reportActivityRows(events: any[]): any[] {
  log.debug("Entering reportActivityRows().");
  const out: any[] = [];
  const list = Array.isArray(events) ? events : [];
  for (let i = 0; i < list.length; i++) {
    const event = list[i] || {};
    if (!ATTEMPTS[String(event.action || '')]) {
      continue;
    }
    const detail = event.detail && typeof event.detail === 'object' ?
      event.detail : {};
    const method = detail.method ? String(detail.method) : '';
    const amr = detail.amr ? String(detail.amr) : '';
    const application = detail.application ? String(detail.application) :
      (detail.client_id ? String(detail.client_id) : '');
    const when = reportAuditTime(event.at);
    out.push({
      timestamp: when,
      day: reportUtcDay(when),
      outcome: event.outcome || '',
      mechanism: method || amr,
      actor: event.actor || '',
      application: application,
      protocol: event.protocol || ''
    });
  }
  log.debug("Leaving reportActivityRows().");
  return out;
}

async function reportReadActivity(rows: any, control: any): Promise<void> {
  log.debug("Entering reportReadActivity().");
  const audit = require('../common/audit');
  const config = require('../common/config');
  const cap = Number(config.value('audit.maxEvents'));
  const limit = Number.isFinite(cap) && cap > 0 ? cap : 5000;
  const flat = reportActivityRows(audit.list().slice(0, limit));
  for (let i = 0; i < flat.length; i++) {
    const keep = await reportOffer(flat[i], rows, control);
    if (keep === false) {
      log.debug("Leaving reportReadActivity(). Stopped.");
      return;
    }
    if (i % PAGE === PAGE - 1) {
      await Promise.resolve();
    }
  }
  log.debug("Leaving reportReadActivity().");
}

/**
 * The attribute-source register, without connection material or secrets.
 * The report does not run SQL and does not read the remote table.
 *
 * @param definitions - `AttributeSources.list()`
 * @returns catalog rows
 */
function reportAttributeSourceRows(definitions: any[]): any[] {
  log.debug("Entering reportAttributeSourceRows().");
  const out: any[] = [];
  const list = Array.isArray(definitions) ? definitions : [];
  for (let i = 0; i < list.length; i++) {
    const src = list[i];
    if (!src || typeof src !== 'object') {
      continue;
    }
    const refresh = Array.isArray(src.refresh) ?
      src.refresh.map(function (one: any): string {
        return String(one);
      }).join(',') : String(src.refresh || '');
    out.push({
      id: String(src.id || ''),
      dialect: String(src.dialect || ''),
      database: String(src.database || ''),
      table: String(src.table || ''),
      keyAttribute: String(src.keyAttribute || ''),
      mode: refresh,
      onFailure: String(src.onFailure || ''),
      enabled: src.enabled === true || src.enabled === 'true'
    });
  }
  log.debug("Leaving reportAttributeSourceRows().");
  return out;
}

async function reportReadAttributeSources(rows: any, control: any):
    Promise<void> {
  log.debug("Entering reportReadAttributeSources().");
  const sourcesApi = require('../attribute-sources/attribute_sources');
  const flat = reportAttributeSourceRows(sourcesApi.list());
  for (let i = 0; i < flat.length; i++) {
    const keep = await reportOffer(flat[i], rows, control);
    if (keep === false) {
      log.debug("Leaving reportReadAttributeSources(). Stopped.");
      return;
    }
  }
  log.debug("Leaving reportReadAttributeSources().");
}

async function reportReadAudit(rows: any, control: any): Promise<void> {
  log.debug("Entering reportReadAudit().");
  const audit = require('../common/audit');
  const config = require('../common/config');
  const cap = Number(config.value('audit.maxEvents'));
  const limit = Number.isFinite(cap) && cap > 0 ? cap : 5000;
  const events = audit.list().slice(0, limit);
  for (let i = 0; i < events.length; i++) {
    const event = events[i] || {};
    const keep = await reportOffer({
      timestamp: reportAuditTime(event.at),
      category: event.category || '',
      action: event.action || '',
      outcome: event.outcome || '',
      actor: event.actor || ''
    }, rows, control);
    if (keep === false) {
      log.debug("Leaving reportReadAudit(). Stopped.");
      return;
    }
    if (i % PAGE === PAGE - 1) {
      await Promise.resolve();
    }
  }
  log.debug("Leaving reportReadAudit().");
}

/**
 * One level of numeric leaves. Arrays and objects are skipped, which is
 * what drops the row lists a snapshot carries beside its counts.
 *
 * @param snapshot - `admin_stats.snapshot({ withoutUsers: true })`, or any
 *   object of the same shape
 * @returns catalog rows
 */
function reportMetricRows(snapshot: any): any[] {
  log.debug("Entering reportMetricRows().");
  const out: any[] = [];
  const body = snapshot && typeof snapshot === 'object' ? snapshot : {};
  Object.keys(body).forEach(function (family: string): void {
    const node = body[family];
    if (!node || typeof node !== 'object' || Array.isArray(node)) {
      return;
    }
    Object.keys(node).forEach(function (leaf: string): void {
      const value = node[leaf];
      if (typeof value === 'number' && Number.isFinite(value)) {
        out.push({
          name: family + '.' + leaf,
          value: value,
          family: family
        });
      }
    });
  });
  log.debug("Leaving reportMetricRows().");
  return out;
}

async function reportReadMetrics(rows: any, control: any): Promise<void> {
  log.debug("Entering reportReadMetrics().");
  const stats = require('../common/admin_stats');
  const flat = reportMetricRows(stats.snapshot({ withoutUsers: true }));
  for (let i = 0; i < flat.length; i++) {
    const keep = await reportOffer(flat[i], rows, control);
    if (keep === false) {
      log.debug("Leaving reportReadMetrics(). Stopped.");
      return;
    }
  }
  log.debug("Leaving reportReadMetrics().");
}

async function reportReadJobRows(rows: any, control: any): Promise<void> {
  log.debug("Entering reportReadJobRows().");
  const list = stores.listJobs();
  for (let i = 0; i < list.length; i++) {
    const job = list[i];
    const keep = await reportOffer({
      id: job.id,
      status: job.status,
      format: job.format,
      submittedAt: reportIso(job.submittedAt),
      completedAt: reportIso(job.completedAt),
      byteSize: job.byteSize == null ? null : Number(job.byteSize)
    }, rows, control);
    if (keep === false) {
      log.debug("Leaving reportReadJobRows(). Stopped.");
      return;
    }
  }
  log.debug("Leaving reportReadJobRows().");
}

async function reportReadSource(plan: any, rows: any, control: any):
    Promise<void> {
  log.debug("Entering reportReadSource().");
  const source = plan.source;
  if (source === 'users') {
    await reportReadUsers(rows, control);
  } else if (source === 'groups') {
    await reportReadGroups(rows, control);
  } else if (source === 'applications') {
    await reportReadApplications(rows, control);
  } else if (source === 'federation') {
    await reportReadFederation(rows, control);
  } else if (source === 'authMechanisms') {
    await reportReadMechanisms(rows, control);
  } else if (source === 'auditEvents') {
    await reportReadAudit(rows, control);
  } else if (source === 'authActivity') {
    await reportReadActivity(rows, control);
  } else if (source === 'serviceMetrics') {
    await reportReadMetrics(rows, control);
  } else if (source === 'reportJobs') {
    await reportReadJobRows(rows, control);
  } else if (source === 'attributeSources') {
    await reportReadAttributeSources(rows, control);
  }
  log.debug("Leaving reportReadSource().");
}

async function reportReadWork(plan: any, control: any): Promise<any> {
  log.debug("Entering reportReadWork().");
  const rows = new Rows(plan, reportTypes(plan));
  const held = control || {};
  if (reportReader) {
    await reportReader(plan, function (row: any): boolean {
      return rows.take(row);
    }, held);
  } else {
    await reportReadSource(plan, rows, held);
  }
  if (reportOverBudget(held)) {
    if (held.execution === 'async') {
      log.debug("Leaving reportReadWork(). Job timed out.");
      return reportJobTooSlow();
    }
    log.debug("Leaving reportReadWork(). Timed out.");
    return reportTooSlow();
  }
  if (held.stopped || (typeof held.cancelled === 'function' &&
      held.cancelled())) {
    log.debug("Leaving reportReadWork(). Cancelled.");
    return { ok: false, cancelled: true };
  }
  if (held.lost) {
    log.debug("Leaving reportReadWork(). Lost.");
    return { ok: false, lost: true };
  }
  log.debug("Leaving reportReadWork().");
  return { ok: true, rows: rows.finish() };
}

function reportWorkersReady(): boolean {
  log.debug("Entering reportWorkersReady().");
  const config = require('../common/config');
  const configured = Number(config.value('workers.requestCount'));
  if (!(configured > 0)) {
    log.debug("Leaving reportWorkersReady(). No pool.");
    return true;
  }
  const pool = require('../common/request_pool');
  const ready = Number(pool.stats().ready) || 0;
  log.debug("Leaving reportWorkersReady().");
  return ready > 0;
}

function reportNotice(job: any, username: string): any {
  log.debug("Entering reportNotice().");
  const request = {
    username: username,
    template: 'report-ready',
    values: {
      username: username,
      definition: job.definitionName || job.definitionId || '',
      status: job.status
    },
    links: { report: '/report/jobs/' + job.id },
    dedupKey: 'report-ready:' + job.id,
    actor: username
  };
  log.debug("Leaving reportNotice().");
  return request;
}

function reportNotify(job: any): void {
  log.debug("Entering reportNotify().");
  if (!job || !job.notify || !job.definitionId) {
    log.debug("Leaving reportNotify(). Not asked.");
    return;
  }
  const username = reportActor(job);
  if (!username || username === job.owner) {
    log.debug("Leaving reportNotify(). No account name.");
    return;
  }
  const mail = require('../common/mail');
  let sent: any = null;
  try {
    sent = mail.send(reportNotice(job, username));
  } catch (e) {
    log.debug("Caught in reportNotify(): " + ((e && e.message) || e));
    log.warn(errorCodes.tag('STS-REPORT-0027') +
      'report: the job finished and the notice was not sent.');
    reportNotifyAudit(job, true);
    log.debug("Leaving reportNotify(). Threw.");
    return;
  }
  const why = sent && sent.error ? String(sent.error) : '';
  const skipped = why.indexOf('no mail transport') >= 0 ||
    why.indexOf('publicBaseUrl') >= 0;
  if (sent && sent.ok) {
    reportNotifyAudit(job, false);
    log.debug("Leaving reportNotify(). Sent.");
    return;
  }
  if (skipped) {
    log.debug("Leaving reportNotify(). Mail is not in use.");
    return;
  }
  log.warn(errorCodes.tag('STS-REPORT-0027') +
    'report: the job finished and the notice was not sent.');
  reportNotifyAudit(job, true);
  log.debug("Leaving reportNotify(). Failed.");
}

function reportNotifyAudit(job: any, failed: boolean): void {
  log.debug("Entering reportNotifyAudit().");
  if (failed) {
    reportAudit({
      category: 'admin',
      action: 'report.notify',
      outcome: 'error',
      errorCode: 'STS-REPORT-0027',
      actor: reportActor(job),
      summary: 'report job ' + job.id + ' notice was not sent',
      detail: reportDetail(job)
    });
  } else {
    reportAudit({
      category: 'admin',
      action: 'report.notify',
      outcome: 'success',
      actor: reportActor(job),
      summary: 'report job ' + job.id + ' notice was sent',
      detail: reportDetail(job)
    });
  }
  log.debug("Leaving reportNotifyAudit().");
}

function reportFailJob(job: any, error: string, code: string): void {
  log.debug("Entering reportFailJob().");
  job.status = 'failed';
  job.error = error;
  job.completedAt = Date.now();
  job.runner = job.runner || '';
  reportFences.delete(job.id);
  stores.putJob(job);
  log.warn(errorCodes.tag(code) + 'report: job ' + job.id + ' failed.');
  reportAudit({
    category: 'admin',
    action: 'report.job.fail',
    // error-code: none — the caller's own code, in `code`
    outcome: 'error',
    errorCode: code,
    actor: reportActor(job),
    summary: 'report job ' + job.id + ' failed',
    detail: reportDetail(job)
  });
  reportNotify(job);
  log.debug("Leaving reportFailJob().");
}

function reportCancelJob(job: any): void {
  log.debug("Entering reportCancelJob().");
  job.status = 'cancelled';
  job.error = null;
  job.completedAt = Date.now();
  job.cancelRequested = true;
  reportFences.delete(job.id);
  stores.putJob(job);
  log.warn(errorCodes.tag('STS-REPORT-0032') +
    'report: a job was cancelled.');
  reportAudit({
    category: 'admin',
    action: 'report.job.cancel',
    outcome: 'success',
    errorCode: 'STS-REPORT-0032',
    actor: reportActor(job),
    summary: 'report job ' + job.id + ' was cancelled',
    detail: reportDetail(job)
  });
  reportNotify(job);
  log.debug("Leaving reportCancelJob().");
}

async function reportRunOne(job: any, ctx: any): Promise<void> {
  log.debug("Entering reportRunOne().");
  const Query = require('./query');
  const limits = new Limits();
  const query = new Query({ catalog: new Catalog(), limits: limits });
  job.status = 'running';
  job.startedAt = Date.now();
  job.runner = reportProcessToken();
  reportFences.add(job.id);
  stores.putJob(job);
  reportAudit({
    category: 'admin',
    action: 'report.job.start',
    outcome: 'success',
    actor: reportActor(job),
    summary: 'report job ' + job.id + ' started',
    detail: reportDetail(job)
  });
  const validated = query.validate(job.document, job.parameters || null);
  if (!validated.ok) {
    reportFailJob(job, validated.error, validated.code);
    log.debug("Leaving reportRunOne(). Invalid.");
    return;
  }
  const plan = validated.plan;
  const control: any = {
    startedMs: Date.now(),
    budgetMs: plan.execution === 'sync' ? limits.syncMaxMs() :
      limits.asyncMaxMs(),
    execution: plan.execution,
    cancelled: function (): boolean {
      const current = stores.getJob(job.id);
      return !!(current && (current.cancelRequested ||
        current.status === 'cancelled'));
    },
    stillOwner: function (): boolean {
      if (ctx && typeof ctx.stillOwner === 'function') {
        return ctx.stillOwner() !== false;
      }
      return true;
    }
  };
  const read = await reportReadWork(plan, control);
  if (control.cancelled() || (read && read.cancelled)) {
    reportCancelJob(stores.getJob(job.id) || job);
    log.debug("Leaving reportRunOne(). Cancelled.");
    return;
  }
  if (read && read.lost) {
    reportFailJob(stores.getJob(job.id) || job, 'unavailable', FENCE_GONE);
    log.debug("Leaving reportRunOne(). Lost.");
    return;
  }
  if (!read.ok) {
    reportFailJob(stores.getJob(job.id) || job, read.error, read.code);
    log.debug("Leaving reportRunOne(). Read refused.");
    return;
  }
  const realms = require('../common/realms');
  const current = realms.current();
  const finished = executor.finish(plan, read.rows, limits, {
    realm: current && current.name ? current.name : realms.currentId(),
    when: new Date().toISOString()
  });
  const stored = stores.getJob(job.id) || job;
  if (!finished.ok) {
    reportFailJob(stored, finished.error, finished.code);
    log.debug("Leaving reportRunOne(). Format refused.");
    return;
  }
  const crypto = require('../common/crypto');
  const sha = crypto.digest('sha256', finished.body, 'hex');
  await stores.putArtifact(stored.id, finished.body, sha, finished.media);
  stored.status = 'completed';
  stored.error = null;
  stored.completedAt = Date.now();
  stored.byteSize = finished.body.length;
  stored.sha256 = sha;
  stored.mediaType = finished.media;
  reportFences.delete(stored.id);
  stores.putJob(stored);
  reportAudit({
    category: 'admin',
    action: 'report.job.complete',
    outcome: 'success',
    actor: reportActor(stored),
    summary: 'report job ' + stored.id + ' completed',
    detail: reportDetail(stored)
  });
  reportNotify(stored);
  log.debug("Leaving reportRunOne().");
}

async function reportDrainWork(ctx: any): Promise<any> {
  log.debug("Entering reportDrainWork().");
  if (!reportWorkersReady()) {
    log.warn(errorCodes.tag('STS-REPORT-0024') +
      'report: waiting for a request worker before a report job runs.');
    log.debug("Leaving reportDrainWork(). Waiting.");
    return { waiting: true };
  }
  await reportRetainWork(ctx);
  const limits = new Limits();
  const list = stores.listJobs();
  let running = 0;
  const runningByOwner: Record<string, number> = {};
  list.forEach(function (job: any): void {
    if (job.status === 'running') {
      running += 1;
      const owner = String(job.owner || '');
      runningByOwner[owner] = (runningByOwner[owner] || 0) + 1;
    }
  });
  const room = limits.maxConcurrentPerRealm() - running;
  const queued = list.filter(function (job: any): boolean {
    return job.status === 'queued';
  }).sort(function (a: any, b: any): number {
    return a.submittedAt - b.submittedAt;
  });
  let started = 0;
  for (let i = 0; i < queued.length && started < room; i++) {
    const job = queued[i];
    const owner = String(job.owner || '');
    const have = runningByOwner[owner] || 0;
    if (have >= limits.maxConcurrentPerSubject()) {
      continue;
    }
    runningByOwner[owner] = have + 1;
    started += 1;
    await reportRunOne(job, ctx || {});
  }
  log.debug("Leaving reportDrainWork().");
  return { started: started };
}

function reportNoteFailure(def: any, description: string): void {
  log.debug("Entering reportNoteFailure().");
  const failures = Array.isArray(def.failures) ? def.failures.slice() : [];
  failures.push({ at: Date.now(), description: description });
  while (failures.length > 8) {
    failures.shift();
  }
  def.failures = failures;
  log.debug("Leaving reportNoteFailure().");
}

async function reportRetainWork(ctx: any): Promise<any> {
  log.debug("Entering reportRetainWork().");
  const limits = new Limits();
  const now = ctx && ctx.nowMs ? ctx.nowMs : Date.now();
  const artifactMs = limits.artifactRetentionS() * 1000;
  const jobMs = limits.jobRetentionS() * 1000;
  const list = stores.listJobs();
  let expired = 0;
  let failed = 0;
  let removed = 0;
  for (let i = 0; i < list.length; i++) {
    const job = list[i];
    if (job.status === 'running' && reportFenceGone(job)) {
      job.status = 'failed';
      job.error = 'unavailable';
      job.completedAt = now;
      reportFences.delete(job.id);
      stores.putJob(job);
      failed += 1;
      log.warn(errorCodes.tag('STS-REPORT-0025') +
        'report: a running job lost its fence and was marked failed.');
      reportAudit({
        category: 'admin',
        action: 'report.job.fail',
        outcome: 'error',
        errorCode: 'STS-REPORT-0025',
        actor: reportActor(job),
        summary: 'report job ' + job.id + ' lost its fence',
        detail: reportDetail(job)
      });
      continue;
    }
    const doneAt = job.completedAt || 0;
    if (job.status === 'completed' && doneAt &&
        now - doneAt > artifactMs) {
      await stores.deleteArtifact(job.id);
      job.status = 'expired';
      job.byteSize = null;
      stores.putJob(job);
      expired += 1;
    }
    const ageFrom = job.completedAt || job.submittedAt || 0;
    if (job.status !== 'queued' && job.status !== 'running' && ageFrom &&
        now - ageFrom > jobMs) {
      await stores.deleteArtifact(job.id);
      stores.deleteJob(job.id);
      removed += 1;
    }
  }
  log.debug("Leaving reportRetainWork().");
  return { expired: expired, failed: failed, removed: removed };
}

async function reportScheduleWork(ctx: any): Promise<any> {
  log.debug("Entering reportScheduleWork().");
  const scheduler = require('../cluster/scheduler');
  const rights = require('./rights');
  const jobsApi = require('./jobs');
  const now = ctx && ctx.nowMs ? Number(ctx.nowMs) : Date.now();
  const defs = stores.listDefinitions();
  let enqueued = 0;
  for (let i = 0; i < defs.length; i++) {
    const def = defs[i];
    if (!def.scheduleEnabled || !def.schedule) {
      continue;
    }
    let slot: number | null = null;
    try {
      slot = scheduler.Scheduler.cronPrev(String(def.schedule), now);
    } catch (e) {
      log.debug("Caught in reportScheduleWork(): " +
        ((e && e.message) || e));
      continue;
    }
    if (slot == null || def.lastSlot === slot) {
      continue;
    }
    const busy = stores.listJobs().some(function (job: any): boolean {
      return job.definitionId === def.id &&
        (job.status === 'queued' || job.status === 'running');
    });
    // A run that is already queued consumed this occurrence. A missing
    // parameter does not: the next pass can run once the values exist.
    if (busy) {
      def.lastSlot = slot;
      stores.putDefinition(def);
      continue;
    }
    const rightsOf = rights.mayUse(def.owner, 'report:use');
    if (!rightsOf.ok) {
      def.lastSlot = slot;
      reportNoteFailure(def, 'The owner can no longer run reports.');
      stores.putDefinition(def);
      log.warn(errorCodes.tag('STS-REPORT-0028') +
        'report: a schedule was skipped because its owner lost report:use.');
      continue;
    }
    const names = jobsApi.parameterNames(def.document);
    const bag = def.parameters && typeof def.parameters === 'object' &&
      !Array.isArray(def.parameters) ? def.parameters : null;
    let missing = false;
    for (let n = 0; n < names.length; n++) {
      if (!bag || !Object.prototype.hasOwnProperty.call(bag, names[n])) {
        missing = true;
      }
    }
    if (missing) {
      reportNoteFailure(def, 'A saved parameter was not given.');
      stores.putDefinition(def);
      log.warn(errorCodes.tag('STS-REPORT-0035') +
        'report: a schedule was skipped because a parameter has no value.');
      continue;
    }
    const Query = require('./query');
    const query = new Query({ catalog: new Catalog(), limits: new Limits() });
    const validated = query.validate(def.document,
      names.length ? bag : null);
    if (!validated.ok) {
      def.lastSlot = slot;
      reportNoteFailure(def, validated.description || 'The query is no ' +
        'longer valid.');
      stores.putDefinition(def);
      log.warn(errorCodes.tag('STS-REPORT-0028') +
        'report: a schedule was skipped because its query no longer runs.');
      continue;
    }
    const submitted = jobsApi.submit({
      owner: def.owner,
      document: def.document,
      parameters: names.length ? bag : null,
      definitionId: def.id,
      definitionName: def.name,
      notify: !!def.notify,
      plan: validated.plan
    });
    if (submitted.ok) {
      def.lastSlot = slot;
      stores.putDefinition(def);
      enqueued += 1;
    } else {
      reportNoteFailure(def, submitted.description || 'The job was not ' +
        'queued.');
      stores.putDefinition(def);
    }
  }
  log.debug("Leaving reportScheduleWork().");
  return { enqueued: enqueued };
}

// The eight gates. Each one only calls the next. The eighth is the last
// text a job's walk is allowed to scan, and it names no directory read.
function reportGateOne(kind: string, a?: any, b?: any): any {
  log.debug("Entering reportGateOne().");
  const out = reportGateTwo(kind, a, b);
  log.debug("Leaving reportGateOne().");
  return out;
}

function reportGateTwo(kind: string, a?: any, b?: any): any {
  log.debug("Entering reportGateTwo().");
  const out = reportGateThree(kind, a, b);
  log.debug("Leaving reportGateTwo().");
  return out;
}

function reportGateThree(kind: string, a?: any, b?: any): any {
  log.debug("Entering reportGateThree().");
  const out = reportGateFour(kind, a, b);
  log.debug("Leaving reportGateThree().");
  return out;
}

function reportGateFour(kind: string, a?: any, b?: any): any {
  log.debug("Entering reportGateFour().");
  const out = reportGateFive(kind, a, b);
  log.debug("Leaving reportGateFour().");
  return out;
}

function reportGateFive(kind: string, a?: any, b?: any): any {
  log.debug("Entering reportGateFive().");
  const out = reportGateSix(kind, a, b);
  log.debug("Leaving reportGateFive().");
  return out;
}

function reportGateSix(kind: string, a?: any, b?: any): any {
  log.debug("Entering reportGateSix().");
  const out = reportGateSeven(kind, a, b);
  log.debug("Leaving reportGateSix().");
  return out;
}

function reportGateSeven(kind: string, a?: any, b?: any): any {
  log.debug("Entering reportGateSeven().");
  const out = reportGateEight(kind, a, b);
  log.debug("Leaving reportGateSeven().");
  return out;
}

function reportGateEight(kind: string, a?: any, b?: any): any {
  log.debug("Entering reportGateEight().");
  const out = reportPastTheGate(kind, a, b);
  log.debug("Leaving reportGateEight().");
  return out;
}

function reportPastTheGate(kind: string, a?: any, b?: any): any {
  log.debug("Entering reportPastTheGate().");
  let out: any;
  if (kind === 'drain') {
    out = reportDrainWork(a);
  } else if (kind === 'retain') {
    out = reportRetainWork(a);
  } else if (kind === 'schedule') {
    out = reportScheduleWork(a);
  } else {
    out = reportReadWork(a, b);
  }
  log.debug("Leaving reportPastTheGate().");
  return out;
}

export = {
  reportGateOne: reportGateOne,
  installReader: reportInstallReader,
  abandonFences: reportAbandonFences,
  processToken: reportProcessToken,
  fenceGone: reportFenceGone,
  clusterRuns: reportClusterRuns,
  hereRuns: reportHereRuns,
  stampReporter: reportStampReporter,
  clearReporter: reportClearReporter,
  metricRows: reportMetricRows,
  mechanismRows: reportMechanismRows,
  activityRows: reportActivityRows,
  attributeSourceRows: reportAttributeSourceRows,
  notice: reportNotice,
  read: reportReadWork
};
