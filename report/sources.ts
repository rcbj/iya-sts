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
//
// A FILTER THE STORE CAN ANSWER IS ASKED OF THE STORE (#985). On the 8081
// installation, fifty million people, `username equals rcbj` walked every
// one of them — the group index first, then every page of `ou=users`, one
// `existingUserEntry()` per person, the filter applied only in
// `Rows.take()`, which keeps paging past a row that does not match — and
// met the ten-second cap every time; a job would have met the two-minute
// one. The directory already answers the question the walk was asking: the
// keyed digests `name_keys`, `mail_keys` and `uuid_keys` and the trigram
// index over the RDN value (`persistence/directory_queries.js`), which
// sign-in and `/portal/delegate` use. So `reportReadUsers()` reads the
// plan's `where` first (`reportIndexedLookups()`): a leaf on an indexed
// field and operator (the catalog's `indexed` list), one arm of an `and`,
// or every arm of an `or` names the CANDIDATES, resolved through the
// directory's own lookups (`reportCandidates()`), and only those rows are
// offered — every other term still applies in `Rows.take()`, so the answer
// is the walk's. `contains` and `startsWith` on `username` are the trigram
// index's superset (lower-cased, three characters or more), narrowed in
// process; a needle the store answers at its cap is not trusted to be
// whole and falls back. A filter the store cannot answer, with the
// directory windowed and the read synchronous, is REFUSED before the walk
// starts (`STS-REPORT-0036`, `reportUnboundedFilter()`), and `mode: auto`
// turns that refusal into a job (`report_api.ts`); a walk that the limit
// bounds — no filter, no order, no count — still runs. The memory directory
// is in process and small by construction, so it walks as it always did.
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

// The directory this file reads: `ldap/ldap_server.js`, required when first
// asked, or the double a test installs (#985). Nothing else installs one.
let reportDirectory: any = null;

// How many store questions one filter may become (an `or` of lookups), the
// shortest substring the trigram index is asked, how many rows a substring
// or a mail lookup is asked for — an answer that fills it is not whole, and
// the read falls back — and the one refusal this file adds.
const INDEX_LOOKUP_CAP = 16;
const NEEDLE_MIN = 3;
const CANDIDATE_CAP = 1000;
const UNBOUNDED_FILTER = 'STS-REPORT-0036';
const TOO_MANY_HOLDERS = 'STS-REPORT-0039';

// `op` is `eq` (the values, exact), `contains` (one lower-cased substring),
// or `range` (#1028: `values[0]` the first epoch millisecond taken, or '',
// `values[1]` the first left out, or '').
interface Lookup {
  field: string;
  op: string;
  values: string[];
}

// The lock attribute the users source's `status equals locked` reads the
// holders of (#1028): an asked name since schema version 28.
const LOCK_ATTRIBUTE = 'pwdAccountLockedTime';
// What a users row reads off an entry, lower-cased as `holdersAsync()` picks.
const USER_FIELDS = ['uid', 'cn', 'displayname', 'mail', 'entryuuid',
  'createtimestamp', 'modifytimestamp', 'pwdaccountlockedtime', 'memberof',
  'userpassword', 'stswebauthncredential', 'ststotpcredential',
  'stsmailfactor', 'authnmethod', 'mfalastauthtime'];

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

function reportInstallDirectory(directory: any): void {
  log.debug("Entering reportInstallDirectory().");
  reportDirectory = directory || null;
  log.debug("Leaving reportInstallDirectory().");
}

function reportLdap(): any {
  log.debug("Entering reportLdap().");
  const ldap = reportDirectory || require('../ldap/ldap_server');
  log.debug("Leaving reportLdap().");
  return ldap;
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

function reportOnWorker(): boolean {
  log.debug("Entering reportOnWorker().");
  // worker_channel.ts ends with `export = WorkerChannel`, so this
  // require is the class. `.WorkerChannel` is undefined, and reading
  // `inWorkerThread` there threw before a job could decide to run.
  const WorkerChannel = require('../common/worker_channel');
  const onWorker = WorkerChannel.inWorkerThread();
  log.debug("Leaving reportOnWorker().");
  return onWorker;
}

function reportClusterRuns(): boolean {
  log.debug("Entering reportClusterRuns().");
  if (reportOnWorker()) {
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
  if (reportOnWorker()) {
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
  const ldap = reportLdap();
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
  const ldap = reportLdap();
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
  const ldap = reportLdap();
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
  const ldap = reportLdap();
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

// How many second-factor credentials an entry holds (#1019): passkeys
// enrolled in the mfa role, authenticator apps and mail factors, each
// credential counted once. Recovery codes and app passwords are not
// factors; a primary passkey is not a second one.
function reportSecondFactors(entry: any): number {
  log.debug("Entering reportSecondFactors().");
  const keys = reportAttrList(entry, 'stsWebauthnCredential');
  let n = 0;
  if (keys.length) {
    const credentials = require('../common/credentials');
    credentials.keysOfValues(keys, reportAttr(entry, 'uid')).forEach(
      function (key: any): void {
        if (String(key.role || 'mfa') === 'mfa') {
          n += 1;
        }
      });
  }
  n += reportAttrList(entry, 'stsTotpCredential').length;
  n += reportAttrList(entry, 'stsMailFactor').length;
  log.debug("Leaving reportSecondFactors(). " + n + '.');
  return n;
}

function reportUserRow(entry: any, names: string[]): any {
  log.debug("Entering reportUserRow().");
  // pwdAccountLockedTime is the administrative disable and any other
  // lock. The catalog calls both locked. This read does not ask
  // account_state, which would walk the directory a second time.
  const locked = reportAttr(entry, 'pwdAccountLockedTime');
  const row = {
    username: reportAttr(entry, 'uid'),
    status: locked ? 'locked' : 'active',
    createdAt: reportLdapTime(reportAttr(entry, 'createTimestamp')),
    modifiedAt: reportLdapTime(reportAttr(entry, 'modifyTimestamp')),
    entryUuid: reportAttr(entry, 'entryUUID'),
    mail: reportAttr(entry, 'mail'),
    displayName: reportAttr(entry, 'displayName') ||
      reportAttr(entry, 'cn'),
    memberOf: names.join(', '),
    // WHAT THE PERSON CAN SIGN IN WITH, AND HAS (#1019, rcbj: account for
    // username/password): whether a password is set, how many second
    // factors the entry holds (`reportSecondFactors()`), the RFC 8176
    // methods they have used and their last multi-factor sign-in — the
    // credentialHolders source's common columns, on the person's own row,
    // so `hasPassword equals true` and `factors equals 0` is "password
    // only". None is indexed: a job on a large directory.
    hasPassword: reportAttrList(entry, 'userPassword').length > 0,
    factors: reportSecondFactors(entry),
    methodsUsed: reportAttrList(entry, 'authnMethod').join(', '),
    mfaLastAuthTime: reportLdapTime(reportAttr(entry, 'mfaLastAuthTime')) ||
      reportIso(Date.parse(reportAttr(entry, 'mfaLastAuthTime')))
  };
  log.debug("Leaving reportUserRow().");
  return row;
}

// ---------------------------------------------------------------------------
// THE INDEXED LOOKUPS OF A FILTER (#985): the store questions whose union
// holds every row the filter can match, or null when none can be named. A
// leaf on an indexed field and operator is one lookup (`eq` and `in` are an
// exact lookup over the values; `contains` and `startsWith` on `username`
// are the trigram index's substring, lower-cased, which is a SUPERSET of
// either — `Rows.take()` still applies the leaf). An `and` is the lookups
// of any ONE of its arms, since every match satisfies every arm, and an
// exact arm is preferred to a substring one. An `or` is the lookups of
// EVERY arm, or null if one arm has none. A `not`, an `isNull`, a `ne`, a
// filter on a sealed field, a needle under three characters: null. Bounded
// in lookups, so no filter becomes an unbounded number of questions. The
// same shape `ldap_server.js`'s `indexedLookupsOf()` gives an LDAP search.
// ---------------------------------------------------------------------------
function reportLeafLookup(node: any, indexedOf: (field: string) => string[]):
    Lookup | null {
  log.debug("Entering reportLeafLookup().");
  const field = String(node.field || '');
  const op = String(node.op || '');
  const allowed = indexedOf(field);
  if (allowed.indexOf(op) < 0) {
    log.debug("Leaving reportLeafLookup(). Not indexed.");
    return null;
  }
  if (op === 'eq' || op === 'in') {
    const list = op === 'in' ? (Array.isArray(node.value) ? node.value :
      []) : [node.value];
    const values: string[] = [];
    for (let i = 0; i < list.length; i++) {
      if (typeof list[i] !== 'string' || !list[i].trim()) {
        log.debug("Leaving reportLeafLookup(). Not a name.");
        return null;
      }
      values.push(list[i]);
    }
    if (!values.length) {
      log.debug("Leaving reportLeafLookup(). Empty.");
      return null;
    }
    // THE LOCK IS INDEXED, ITS ABSENCE IS NOT (#1028): `status equals
    // locked` is the holders of pwdAccountLockedTime; `active` is everybody
    // else and anchors nothing.
    if (field === 'status' && values.some(function (v: string): boolean {
      return v !== 'locked';
    })) {
      log.debug("Leaving reportLeafLookup(). Not the lock.");
      return null;
    }
    log.debug("Leaving reportLeafLookup(). Exact.");
    return { field: field, op: 'eq', values: values };
  }
  if (op === 'lt' || op === 'le' || op === 'gt' || op === 'ge') {
    // A DATE BOUND (#1028): one side of a span, in epoch milliseconds; `le`
    // and `gt` move by a second, the columns' resolution, to the exclusive
    // and inclusive sides the statement takes.
    const at = typeof node.value === 'number' ? node.value
      : Date.parse(String(node.value || ''));
    if (!Number.isFinite(at)) {
      log.debug("Leaving reportLeafLookup(). Not a time.");
      return null;
    }
    const lo = op === 'ge' ? at : (op === 'gt' ? at + 1000 : 0);
    const hi = op === 'lt' ? at : (op === 'le' ? at + 1000 : 0);
    log.debug("Leaving reportLeafLookup(). A bound.");
    return { field: field, op: 'range',
             values: [lo ? String(lo) : '', hi ? String(hi) : ''] };
  }
  if (op === 'contains' || op === 'startsWith') {
    const needle = typeof node.value === 'string' ?
      node.value.trim().toLowerCase() : '';
    if (needle.length < NEEDLE_MIN) {
      log.debug("Leaving reportLeafLookup(). Short.");
      return null;
    }
    log.debug("Leaving reportLeafLookup(). Substring.");
    return { field: field, op: 'contains', values: [needle] };
  }
  log.debug("Leaving reportLeafLookup(). Operator.");
  return null;
}

function reportExactOnly(lookups: Lookup[]): boolean {
  log.debug("Entering reportExactOnly().");
  const exact = lookups.every(function (one: Lookup): boolean {
    return one.op === 'eq';
  });
  log.debug("Leaving reportExactOnly().");
  return exact;
}

function reportIndexedLookups(node: any,
    indexedOf: (field: string) => string[], depth: number):
    Lookup[] | null {
  log.debug("Entering reportIndexedLookups().");
  if (!node || typeof node !== 'object' || depth > 4) {
    log.debug("Leaving reportIndexedLookups(). None.");
    return null;
  }
  if (node.op === 'and') {
    const args = Array.isArray(node.args) ? node.args : [];
    let best: Lookup[] | null = null;
    const ranges: Lookup[] = [];
    for (let i = 0; i < args.length; i++) {
      const arm = reportIndexedLookups(args[i], indexedOf, depth + 1);
      if (arm && arm.length === 1 && arm[0].op === 'range') {
        ranges.push(arm[0]);
      }
      if (arm && (!best || (reportExactOnly(arm) &&
          !reportExactOnly(best)))) {
        best = arm;
      }
    }
    // TWO BOUNDS ON ONE DATE ARE ONE RANGE (#1028): `createdAt ge A and
    // createdAt lt B` is read as the span [A, B), not as everything from A
    // narrowed afterwards.
    if (best && best.length === 1 && best[0].op === 'range' &&
        ranges.length > 1) {
      const merged: Lookup = { field: best[0].field, op: 'range',
                               values: ['', ''] };
      ranges.forEach(function (one: Lookup): void {
        if (one.field !== merged.field) {
          return;
        }
        if (one.values[0] && (!merged.values[0] ||
            Number(one.values[0]) > Number(merged.values[0]))) {
          merged.values[0] = one.values[0];
        }
        if (one.values[1] && (!merged.values[1] ||
            Number(one.values[1]) < Number(merged.values[1]))) {
          merged.values[1] = one.values[1];
        }
      });
      log.debug("Leaving reportIndexedLookups(). A merged span.");
      return [merged];
    }
    log.debug("Leaving reportIndexedLookups(). And.");
    return best;
  }
  if (node.op === 'or') {
    const args = Array.isArray(node.args) ? node.args : [];
    let all: Lookup[] = [];
    for (let i = 0; i < args.length; i++) {
      const arm = reportIndexedLookups(args[i], indexedOf, depth + 1);
      if (!arm) {
        log.debug("Leaving reportIndexedLookups(). Or, an arm walks.");
        return null;
      }
      all = all.concat(arm);
    }
    if (!all.length || all.length > INDEX_LOOKUP_CAP) {
      log.debug("Leaving reportIndexedLookups(). Or, too many.");
      return null;
    }
    log.debug("Leaving reportIndexedLookups(). Or.");
    return all;
  }
  if (node.op === 'not') {
    log.debug("Leaving reportIndexedLookups(). Not.");
    return null;
  }
  const leaf = reportLeafLookup(node, indexedOf);
  log.debug("Leaving reportIndexedLookups().");
  return leaf ? [leaf] : null;
}

// The entries one lookup names, through the directory's own doors — the
// same ones a sign-in and a SCIM read use, so the answer is theirs: a name
// through `existingUserEntriesAsync()` (`byName`, or the in-memory
// username index), a UUID through `entriesByUuidsAsync()`, an address
// through the window's `byMail`, a substring through the trigram index.
// Null means the store could not answer it whole — a memory directory asked
// a substring or an address (it has no index for either, and is small), or
// an answer that filled the cap — and the caller walks instead.
async function reportLookupEntries(lookup: Lookup, ldap: any):
    Promise<any[] | null> {
  log.debug("Entering reportLookupEntries(). " + lookup.field + ' ' +
    lookup.op);
  const found: any[] = [];
  if (lookup.field === 'username' && lookup.op === 'eq') {
    const entries = await ldap.existingUserEntriesAsync(lookup.values);
    (entries || []).forEach(function (entry: any): void {
      if (entry) {
        found.push(entry);
      }
    });
    log.debug("Leaving reportLookupEntries(). By name.");
    return found;
  }
  if (lookup.op === 'range') {
    // THE SPAN (#1028): the directory's B-tree over created_at or
    // modified_at; null in memory or past the cap, and the caller walks.
    const column = lookup.field === 'modifiedAt' ? 'modified' : 'created';
    const inSpan = await ldap.entriesByTimeRangeAsync(column,
      Number(lookup.values[0]) || 0, Number(lookup.values[1]) || 0,
      CANDIDATE_CAP);
    if (inSpan === null) {
      log.debug("Leaving reportLookupEntries(). Span not whole.");
      return null;
    }
    inSpan.forEach(function (entry: any): void {
      if (entry) {
        found.push(entry);
      }
    });
    log.debug("Leaving reportLookupEntries(). " + found.length +
      ' in the span.');
    return found;
  }
  if (lookup.field === 'status' && lookup.op === 'eq') {
    // THE LOCKED (#1028): the holders of the lock attribute through the
    // asked-names index, every users field picked.
    const locked = await ldap.holdersAsync('person', LOCK_ATTRIBUTE,
      USER_FIELDS);
    (locked || []).forEach(function (holder: any): void {
      found.push(reportHolderEntry(holder));
    });
    log.debug("Leaving reportLookupEntries(). " + found.length +
      ' locked.');
    return found;
  }
  if (lookup.field === 'memberOf' && lookup.op === 'eq') {
    // A GROUP'S MEMBER LIST IS AN INDEX (rcbj, 2026-10-27): the group is
    // read by its name and its members fetched by theirs, so a filter on
    // memberOf costs the group's size and never the population.
    const names: string[] = [];
    lookup.values.forEach(function (selector: string): void {
      reportGroupMemberNames(selector, ldap).forEach(
        function (name: string): void {
          if (names.indexOf(name) < 0) {
            names.push(name);
          }
        });
    });
    const members = names.length
      ? await ldap.existingUserEntriesAsync(names) : [];
    (members || []).forEach(function (entry: any): void {
      if (entry) {
        found.push(entry);
      }
    });
    log.debug("Leaving reportLookupEntries(). " + found.length +
      ' member(s).');
    return found;
  }
  if (lookup.field === 'entryUuid' && lookup.op === 'eq') {
    const map = await ldap.entriesByUuidsAsync(lookup.values);
    if (map && typeof map.forEach === 'function') {
      map.forEach(function (entry: any): void {
        if (entry) {
          found.push(entry);
        }
      });
    }
    log.debug("Leaving reportLookupEntries(). By UUID.");
    return found;
  }
  if (!ldap.directoryIsWindowed() || !ldap.directoryWindow) {
    log.debug("Leaving reportLookupEntries(). No index in memory.");
    return null;
  }
  const realms = require('../common/realms');
  const realmId = realms.currentId();
  if (lookup.field === 'mail' && lookup.op === 'eq') {
    for (let i = 0; i < lookup.values.length; i++) {
      const wanted = lookup.values[i].trim().toLowerCase();
      const hits = await ldap.directoryWindow.findWindowedAsync(realmId,
        'byMail', [realmId, wanted, CANDIDATE_CAP],
        function (entry: any): boolean {
          return reportAttrList(entry, 'mail').some(function (one: string):
              boolean {
            return one.toLowerCase() === wanted;
          });
        });
      if (hits.length >= CANDIDATE_CAP) {
        log.debug("Leaving reportLookupEntries(). Mail at the cap.");
        return null;
      }
      hits.forEach(function (hit: any): void {
        found.push(hit.entry);
      });
    }
    log.debug("Leaving reportLookupEntries(). By mail.");
    return found;
  }
  if (lookup.field === 'username' && lookup.op === 'contains') {
    const parent = String(ldap.usersDn() || '').toLowerCase();
    const page = await ldap.directoryWindow.uidContainsAsync(realmId,
      parent, lookup.values[0], CANDIDATE_CAP);
    if (!page || page.asked >= CANDIDATE_CAP) {
      log.debug("Leaving reportLookupEntries(). Substring at the cap.");
      return null;
    }
    page.rows.forEach(function (row: any): void {
      if (row && row.entry) {
        found.push(row.entry);
      }
    });
    log.debug("Leaving reportLookupEntries(). By substring.");
    return found;
  }
  log.debug("Leaving reportLookupEntries(). Unknown.");
  return null;
}

// The candidates of a filter: every lookup's entries, each person once,
// projections and entries with no `uid` left out as the walk leaves them.
// Null when any lookup could not be answered whole.
async function reportCandidates(lookups: Lookup[], ldap: any):
    Promise<any[] | null> {
  log.debug("Entering reportCandidates(). " + lookups.length +
    ' lookup(s).');
  const parent = String(ldap.usersDn() || '').toLowerCase();
  const seen = new Set<string>();
  const out: any[] = [];
  for (let i = 0; i < lookups.length; i++) {
    const entries = await reportLookupEntries(lookups[i], ldap);
    if (!entries) {
      log.debug("Leaving reportCandidates(). Not whole.");
      return null;
    }
    for (let k = 0; k < entries.length; k++) {
      const entry = entries[k];
      const dn = String((entry && entry.dn) || '').toLowerCase();
      const origin = String((entry && entry.origin) || '');
      if (!dn || seen.has(dn) || origin.indexOf('projection') === 0 ||
          !reportAttr(entry, 'uid') || !reportUnder(dn, parent)) {
        continue;
      }
      seen.add(dn);
      out.push(entry);
    }
  }
  log.debug("Leaving reportCandidates(). " + out.length + '.');
  return out;
}

// The names of the groups that LIST this person, from the directory's own
// group index (`groupsOfUser()`, what every token's groups claim reads)
// rather than from a pass over every group: a candidate's row needs its
// groups, not the realm's. A group the person only claims through their
// own `memberOf` is left out, as the walk's index leaves it out.
function reportGroupNamesOf(ldap: any, entry: any): string[] {
  log.debug("Entering reportGroupNamesOf().");
  const names: string[] = [];
  const username = reportAttr(entry, 'uid');
  if (username && typeof ldap.groupsOfUser === 'function') {
    const answer = ldap.groupsOfUser(username) || {};
    (answer.groups || []).forEach(function (group: any): void {
      const listed = Array.isArray(group.via) ? group.via.length > 0 :
        !group.viaMemberOf;
      if (listed && group.cn && names.indexOf(group.cn) < 0) {
        names.push(group.cn);
      }
    });
  }
  log.debug("Leaving reportGroupNamesOf().");
  return names;
}

// Whether the plan has to see every person to answer: a filter the store
// did not narrow (the limit cannot stop a walk that finds nothing), an
// order (the heap needs the last row), or a count. A plain unordered read
// with no filter stops at its limit, and may walk.
function reportMustVisitEverybody(plan: any): boolean {
  log.debug("Entering reportMustVisitEverybody().");
  const must = !!(plan && (plan.where != null ||
    (Array.isArray(plan.orderBy) && plan.orderBy.length) ||
    plan.aggregate === 'count'));
  log.debug("Leaving reportMustVisitEverybody().");
  return must;
}

function reportUnboundedFilter(catalog: any, sourceId?: string): any {
  log.debug("Entering reportUnboundedFilter().");
  const src = catalog.source(sourceId || 'users') || { fields: [] };
  const named = (src.fields || []).filter(function (field: any): boolean {
    return Array.isArray(field.indexed) && field.indexed.length > 0;
  }).map(function (field: any): string {
    return field.id + ' (' + field.indexed.join(', ') + ')';
  });
  log.warn(errorCodes.tag(UNBOUNDED_FILTER) +
    'report: a synchronous users query names no filter the directory ' +
    'can answer with an index, and the directory is windowed; refused ' +
    'rather than read row by row.');
  log.debug("Leaving reportUnboundedFilter().");
  return {
    ok: false,
    code: UNBOUNDED_FILTER,
    error: 'result_too_large',
    unbounded: true,
    description: 'This query would read every person. Filter on ' +
      named.join(', ') + ', or run it as a job.'
  };
}

function reportTooManyCandidates(catalog: any): any {
  log.debug("Entering reportTooManyCandidates().");
  log.warn(errorCodes.tag('STS-REPORT-0041') +
    'report: an indexed filter matched more people than one read may take ' +
    '(' + CANDIDATE_CAP + '); refused rather than read person by person.');
  log.debug("Leaving reportTooManyCandidates().");
  return {
    ok: false,
    code: 'STS-REPORT-0041',
    error: 'result_too_large',
    description: 'The filter matches more than ' + CANDIDATE_CAP +
      ' people. Narrow it: a shorter date span, a longer name, or add a ' +
      'group (memberOf).'
  };
}

async function reportReadUsers(rows: any, control: any): Promise<void> {
  log.debug("Entering reportReadUsers().");
  const ldap = reportLdap();
  const plan = (rows && rows.plan) || {};
  const catalog = new Catalog();
  const lookups = reportIndexedLookups(plan.where, function (field: string):
      string[] {
    return catalog.indexedFor('users', field);
  }, 0);
  const candidates = lookups ? await reportCandidates(lookups, ldap) : null;
  // A LOOKUP TOO LARGE TO ANSWER WHOLE NEVER BECOMES A WALK (#1028, rcbj:
  // "users shouldn't run into queries that require full table scans"): on
  // a windowed directory, an indexed filter whose answer filled the
  // candidate cap (a date span of more than a thousand people, say) is
  // refused as too large, asking for a narrower filter, rather than read
  // by paging every person.
  if (lookups && !candidates && ldap.directoryIsWindowed()) {
    control.unbounded = reportTooManyCandidates(catalog);
    log.debug("Leaving reportReadUsers(). Lookup not whole.");
    return;
  }
  if (candidates) {
    for (let i = 0; i < candidates.length; i++) {
      const entry = candidates[i];
      const keep = await reportOffer(reportUserRow(entry,
        reportGroupNamesOf(ldap, entry)), rows, control);
      if (keep === false) {
        log.debug("Leaving reportReadUsers(). Stopped.");
        return;
      }
      if (i % PAGE === PAGE - 1) {
        await Promise.resolve();
      }
    }
    log.debug("Leaving reportReadUsers(). Indexed.");
    return;
  }
  if (control && control.execution === 'sync' &&
      ldap.directoryIsWindowed() && reportMustVisitEverybody(plan)) {
    control.unbounded = reportUnboundedFilter(catalog);
    log.debug("Leaving reportReadUsers(). Unbounded.");
    return;
  }
  const index = await reportGroupIndex();
  await reportEachUser(async function (entry: any, dn: string):
      Promise<boolean> {
    const names = index.byUser[String(dn).toLowerCase()] || [];
    return reportOffer(reportUserRow(entry, names), rows, control);
  });
  log.debug("Leaving reportReadUsers().");
}

// ---------------------------------------------------------------------------
// WHO HOLDS WHICH CREDENTIAL (#1002, rcbj: who has a passkey as a primary
// mechanism, who as a second factor, with what algorithm, how many — and the
// same question for other mechanisms and other communities, without a scan
// and without changing what is sealed). One row per person, per mechanism,
// per role. Everything read is what the directory already keeps:
//
//   * THE HOLDERS OF A MECHANISM are the holders of its attribute, through
//     the store's asked-names index (`holdersAsync()`, bounded by the
//     holders and never by the population); the entries opened are theirs.
//   * THE MEMBERS OF A GROUP are read from the group entry and fetched by
//     name (`existingUserEntriesAsync()`), bounded by the group.
//   * A PASSKEY'S ROLE is the key's own `role`, `primary` or `mfa`, chosen
//     at enrolment and enforced at sign-in (`common/credentials.ts`,
//     `Credentials.ROLES`); its algorithm and lane are what every page
//     shows (`keyAlgorithm()`, `keyLane()`). The other mechanisms have one
//     role each, stated in `MECHANISM_TABLE`.
//   * THE PERSON'S HISTORY is `authnMethod` (every RFC 8176 method used
//     here) and `mfaLastAuthTime`, written at the authentication funnel.
//
// A filter on `mechanism` or `memberOf` is the indexed read; a query naming
// neither reads every mechanism's holders, which is bounded by holders and
// not people but still unbounded in the catalog's sense, so synchronously on
// a windowed directory it is refused as the users source is, and as a job
// it runs. Recovery codes and app passwords are not here: their attributes
// are not in the asked-names index, so their holders would be a scan.
// ---------------------------------------------------------------------------
const MECHANISM_TABLE = [
  { id: 'passkey', attribute: 'stsWebauthnCredential', role: '' },
  { id: 'totp', attribute: 'stsTotpCredential', role: 'mfa' },
  { id: 'emailFactor', attribute: 'stsMailFactor', role: 'mfa' },
  { id: 'certificate', attribute: 'stsEnrolledCertificate', role: 'primary' },
  { id: 'kerberos', attribute: 'stsKrb5Keys', role: 'primary' },
  // The password (#1019, rcbj: "what about username password
  // authentication"): a primary mechanism like the others, but the one the
  // store does not index by holder — nearly everyone has one — so its count
  // comes from the realm's counter (`holderCountAsync`) and a list of its
  // holders is the population, refused unless narrowed by memberOf. Its
  // row never carries the hash: the scheme is the algorithm.
  { id: 'password', attribute: 'userPassword', role: 'primary' },
  // Recovery codes (#1024): a set of single-use codes, stored as hashes,
  // one attribute value per person. The asked-names index carries the name
  // since schema version 27, so the holders are an indexed read like the
  // others. A row is the set, its codes counted and never shown.
  { id: 'recoveryCodes', attribute: 'stsBackupCodes', role: 'recovery' },
  // THE WALLET MECHANISMS (#1021, rcbj: credentials from a web wallet, from
  // a native wallet, and self-issued subjects, by algorithm). A self-issued
  // subject is a DID or key the person proved with a wallet (SIOPv2), on
  // the entry as `stsSelfIssuedSubject` — an asked name, so an indexed read
  // like the others. A verifiable credential this realm issued is NOT on
  // the entry: it is a row of `oid4vc/vc_issued.ts`'s register, so the
  // holders come from the register (`register: true`, `reportIssuedRows()`),
  // bounded by the credentials issued and never by the population.
  { id: 'selfIssued', attribute: 'stsSelfIssuedSubject', role: 'primary' },
  { id: 'verifiableCredential', attribute: '', role: 'primary',
    register: true }
];

// The issued-credential register, for a test to replace (#1021): what the
// report reads is `rowsForSubject(null)` — every live row of the realm —
// and `nameForSubject(subject)`, the directory's name for a `urn:uuid:`.
let reportIssuedRegister: any = null;

function reportInstallIssuedRegister(register: any): void {
  log.debug("Entering reportInstallIssuedRegister().");
  reportIssuedRegister = register || null;
  log.debug("Leaving reportInstallIssuedRegister().");
}

function reportRegister(): any {
  log.debug("Entering reportRegister().");
  const register = reportIssuedRegister || require('../oid4vc/vc_issued');
  log.debug("Leaving reportRegister().");
  return register;
}

// Every live row of the register, filed by subject (#1021): one read per
// report, bounded by the credentials this realm has issued and still
// remembers, which is what a wallet-credential census is about.
function reportIssuedRows(): { bySubject: Map<string, any[]> } {
  log.debug("Entering reportIssuedRows().");
  const register = reportRegister();
  const bySubject = new Map<string, any[]>();
  const rows = typeof register.rowsForSubject === 'function'
    ? register.rowsForSubject(null) || [] : [];
  rows.forEach(function (row: any): void {
    const subject = String((row && row.subject) || '');
    if (!subject) {
      return;
    }
    bySubject.set(subject, (bySubject.get(subject) || []).concat([row]));
  });
  log.debug("Leaving reportIssuedRows(). " + bySubject.size +
    ' subject(s).');
  return { bySubject: bySubject };
}

// The directory's name for a register subject (`urn:uuid:<entryUUID>`), or
// '' — the test's register may answer it itself.
function reportNameForSubject(subject: string): string {
  log.debug("Entering reportNameForSubject().");
  const register = reportRegister();
  let name = '';
  if (register && typeof register.nameForSubject === 'function') {
    name = String(register.nameForSubject(subject) || '');
  } else {
    const helpers = require('../common/helpers');
    name = String(helpers.nameForSubject(subject) || '');
  }
  log.debug("Leaving reportNameForSubject(). " + (name ? 'named' : 'none'));
  return name;
}

// A wallet key's algorithm and lane (#1021): from the name the passkey
// report gives a key, or from a DID that spells its key (did:jwk, did:key).
function reportKeyLane(algorithm: string): string {
  log.debug("Entering reportKeyLane().");
  const lane = !algorithm ? '' :
    (/ML-DSA|SLH-DSA|ML-KEM/i.test(algorithm) ? 'pqc' : 'classical');
  log.debug("Leaving reportKeyLane(). " + lane);
  return lane;
}

function reportDidAlgorithm(subject: string): string {
  log.debug("Entering reportDidAlgorithm().");
  let name = '';
  try {
    const di = require('../oid4vc/vc_data_integrity');
    const credentials = require('../common/credentials');
    let jwk: any = null;
    if (/^did:jwk:/.test(subject)) {
      jwk = di.jwkOfDidJwk(subject);
    } else if (/^did:key:/.test(subject)) {
      jwk = di.jwkOfMultikey(subject.slice('did:key:'.length));
    }
    name = jwk ? String(credentials.Credentials.keyAlgorithm(
      { publicKeyJwk: jwk }).name || '') : '';
  } catch (e) {
    // A DID that does not decode, or a key the namer does not know: the
    // row says nothing rather than something wrong.
    log.debug("Caught in reportDidAlgorithm(): " + ((e && e.message) || e));
    name = '';
  }
  log.debug("Leaving reportDidAlgorithm(). " + name);
  return name;
}
// `entryuuid` is here for the register read (#1021): a credential's subject
// is `urn:uuid:<entryUUID>`, and an entry the asked-names read handed back
// without it would show none of the person's wallet credentials when
// another mechanism's read found the entry first.
const HOLDER_FIELDS = ['uid', 'displayname', 'cn', 'authnmethod',
  'mfalastauthtime', 'pwdchangedtime', 'entryuuid'];
const GROUP_MEMBERS_MAX = 50000;

function reportParsedValues(values: string[]): any[] {
  log.debug("Entering reportParsedValues().");
  const out: any[] = [];
  values.forEach(function (value: string): void {
    try {
      const parsed = JSON.parse(value);
      out.push(parsed && typeof parsed === 'object' ? parsed : {});
    } catch (e) {
      // Not JSON this service wrote (a certificate's PEM, say): a
      // credential with no dates and no algorithm to read.
      log.debug("Caught in reportParsedValues(): " + ((e && e.message) || e));
      out.push({});
    }
  });
  log.debug("Leaving reportParsedValues().");
  return out;
}

function reportMaxIso(stamps: any[]): string | null {
  log.debug("Entering reportMaxIso().");
  let best = 0;
  stamps.forEach(function (one: any): void {
    const n = Number(one) || 0;
    if (n > best) {
      best = n;
    }
  });
  log.debug("Leaving reportMaxIso().");
  return best ? reportIso(best) : null;
}

function reportMinIso(stamps: any[]): string | null {
  log.debug("Entering reportMinIso().");
  let best = 0;
  stamps.forEach(function (one: any): void {
    const n = Number(one) || 0;
    if (n > 0 && (!best || n < best)) {
      best = n;
    }
  });
  log.debug("Leaving reportMinIso().");
  return best ? reportIso(best) : null;
}

// The rows one person contributes for one mechanism: a passkey holder has
// one per role held; every other mechanism one row.
// What every row of a person says, whatever the mechanism (#1002, #1021).
function reportHolderCommon(entry: any, mechanism: any, ldap: any): any {
  log.debug("Entering reportHolderCommon().");
  const common = {
    username: reportAttr(entry, 'uid'),
    displayName: reportAttr(entry, 'displayName') || reportAttr(entry, 'cn'),
    mechanism: mechanism.id,
    methodsUsed: reportAttrList(entry, 'authnMethod').join(', '),
    mfaLastAuthTime: reportLdapTime(reportAttr(entry, 'mfaLastAuthTime')) ||
      reportIso(Date.parse(reportAttr(entry, 'mfaLastAuthTime'))),
    memberOf: reportGroupNamesOf(ldap, entry).join(', '),
    mail: reportAttr(entry, 'mail'),
    entryUuid: reportAttr(entry, 'entryUUID'),
    channel: '',
    format: ''
  };
  log.debug("Leaving reportHolderCommon().");
  return common;
}

// THE VERIFIABLE CREDENTIALS A PERSON HOLDS (#1021): the register's rows
// for their subject, ONE REPORT ROW PER KIND OF COPY — the copies that
// share a credential type, format, holder-key algorithm, lane and channel
// are one row with `credentials` their number (rcbj, 2026-10-27: a batch
// issuance bound four keys to four copies of one credential, and four rows
// each saying "4" told nobody anything; one row saying 4 does). Copies that
// differ in any of those are separate rows, so a count by algorithm or
// channel still counts copies. The row's dates are the group's earliest
// issuance and latest wallet report; `credentialId` names the credential
// type (the configuration id). A copy the holder removed on /portal/wallet
// is left out.
function reportIssuedRowsFor(entry: any, mechanism: any, ldap: any,
                             context: any): any[] {
  log.debug("Entering reportIssuedRowsFor().");
  const subject = 'urn:uuid:' + reportAttr(entry, 'entryUUID');
  const bySubject: Map<string, any[]> = (context &&
    context.issuedBySubject) || new Map();
  const rows = bySubject.get(subject) || [];
  const copies: any[] = [];
  rows.forEach(function (row: any): void {
    [].concat(row.credentials || []).forEach(function (one: any): void {
      if (one && !one.removedAt) {
        copies.push({ row: row, one: one });
      }
    });
  });
  const common = reportHolderCommon(entry, mechanism, ldap);
  const groups = new Map<string, any[]>();
  copies.forEach(function (copy: any): void {
    const alg = String(copy.one.holderAlg || '');
    const kind = [String(copy.row.configId || ''),
      String(copy.row.format || ''), alg, reportKeyLane(alg),
      String(copy.one.channel || '')].join('\u0000');
    groups.set(kind, (groups.get(kind) || []).concat([copy]));
  });
  const out: any[] = [];
  groups.forEach(function (held: any[], kind: string): void {
    const parts = kind.split('\u0000');
    out.push(Object.assign({}, common, {
      role: mechanism.role,
      credentials: held.length,
      credentialId: parts[0],
      algorithm: parts[2],
      lane: parts[3],
      channel: parts[4],
      format: parts[1],
      enrolledAt: reportMinIso(held.map(function (copy: any): any {
        return copy.one.issuedAt;
      })),
      lastUsedAt: reportMaxIso(held.map(function (copy: any): any {
        return copy.one.walletEventAt;
      }))
    }));
  });
  log.debug("Leaving reportIssuedRowsFor(). " + out.length + '.');
  return out;
}

function reportHolderRows(entry: any, mechanism: any, ldap: any,
                          context?: any): any[] {
  log.debug("Entering reportHolderRows(). " + mechanism.id);
  if (mechanism.register) {
    const issued = reportIssuedRowsFor(entry, mechanism, ldap, context);
    log.debug("Leaving reportHolderRows(). Register.");
    return issued;
  }
  const values = reportAttrList(entry, mechanism.attribute);
  if (!values.length) {
    log.debug("Leaving reportHolderRows(). None.");
    return [];
  }
  const username = reportAttr(entry, 'uid');
  const common = reportHolderCommon(entry, mechanism, ldap);
  const out: any[] = [];
  if (mechanism.id === 'selfIssued') {
    // A SELF-ISSUED SUBJECT (#1021): one row per enrolled DID or key, the
    // channel the enrolment recorded (`location.kind`, #693; `admin` for
    // one an administrator entered), the key's algorithm — what the DID
    // spells, else what the proof was signed with — and when it was proved
    // or entered.
    reportParsedValues(values).forEach(function (one: any): void {
      const subject = String(one.subject || '');
      const location = one.location && typeof one.location === 'object'
        ? one.location : null;
      const channel = location && location.kind ? String(location.kind)
        : (one.proof === 'admin' ? 'admin' : '');
      const alg = reportDidAlgorithm(subject) || String(one.keyAlg || '');
      out.push(Object.assign({}, common, {
        role: mechanism.role,
        credentials: values.length,
        credentialId: subject,
        algorithm: alg,
        lane: reportKeyLane(alg),
        channel: channel,
        enrolledAt: reportMinIso([Date.parse(String(one.provedAt ||
          one.enrolledAt || ''))]),
        lastUsedAt: null
      }));
    });
    log.debug("Leaving reportHolderRows(). " + out.length + ' subject(s).');
    return out;
  }
  // ONE ROW PER CREDENTIAL (#1011, rcbj: "a separate row for each passkey
  // + algorithm; the reports we need require this granular data"). Until
  // then a row was a person's credentials of one mechanism and role, with
  // the algorithms joined into one string, so a count by algorithm counted
  // people and a mixed holder was one row. Now each credential is a row
  // with its own algorithm, lane, id and dates; `credentials` is still the
  // person's count of that mechanism and role, the same on each of their
  // rows, so a count grouped by username is still how many each holds.
  if (mechanism.id === 'passkey') {
    const credentials = require('../common/credentials');
    const keys = credentials.keysOfValues(values, username);
    const byRole: Record<string, any[]> = {};
    keys.forEach(function (key: any): void {
      const role = String(key.role || 'mfa');
      byRole[role] = (byRole[role] || []).concat([key]);
    });
    Object.keys(byRole).sort().forEach(function (role: string): void {
      const held = byRole[role];
      held.forEach(function (key: any): void {
        const alg = credentials.Credentials.keyAlgorithm(key);
        out.push(Object.assign({}, common, {
          role: role,
          credentials: held.length,
          credentialId: String(key.credentialId || ''),
          algorithm: String(alg.name || ''),
          lane: String(alg.lane || ''),
          enrolledAt: reportMinIso([key.enrolledAt]),
          lastUsedAt: reportMaxIso([key.lastUsedAt])
        }));
      });
    });
    log.debug("Leaving reportHolderRows(). Passkeys, " + out.length +
      ' role(s).');
    return out;
  }
  if (mechanism.id === 'recoveryCodes') {
    // THE RECOVERY CODE SET IS ONE ROW (#1024): how many codes remain
    // (the stored count when the set is sealed under a key this process
    // cannot open, the unused codes otherwise), the hash scheme as the
    // algorithm (scrypt since 2026-09-11, plain before), the set's
    // generation as its enrolment and its last use. No code or hash
    // reaches the row.
    reportParsedValues(values).forEach(function (set: any, i: number): void {
      const codes: any[] = Array.isArray(set.codes) ? set.codes : [];
      const unused = codes.filter(function (one: any): boolean {
        return one && typeof one === 'object' && !one.usedAt;
      }).length;
      const hashed = codes.some(function (one: any): boolean {
        return one && typeof one.hash === 'string' &&
          one.hash.indexOf('$scrypt$') === 0;
      });
      out.push(Object.assign({}, common, {
        role: mechanism.role,
        credentials: codes.length ? unused : Number(set.remaining || 0),
        credentialId: String(set.generatedAt || (i + 1)),
        // A set sealed under the key-encryption key (product mode) keeps
        // its codes in `vault`, not `codes`; they are scrypt hashes since
        // 2026-09-11, and the count is the stored `remaining`.
        algorithm: codes.length ? (hashed ? 'scrypt' : 'plain') :
          (set.vault || set.sealed ? 'scrypt' : ''),
        lane: '',
        enrolledAt: reportMinIso([set.generatedAt]),
        lastUsedAt: reportMaxIso([set.lastUsedAt])
      }));
    });
    log.debug("Leaving reportHolderRows(). " + out.length + ' code set(s).');
    return out;
  }
  if (mechanism.id === 'password') {
    // THE PASSWORD ROW CARRIES NO HASH (#1019): the stored value is the
    // hash and only its scheme is read, as the algorithm — this service's
    // own `$scrypt$…` and `$argon2id$…` (`common/crypto.js`'s
    // `encodeStoredSecret`, `encodeArgon2Secret`), or an imported
    // `{SCHEME}…`; the enrolment is the directory's pwdChangedTime.
    values.forEach(function (value: string, i: number): void {
      const text = String(value || '');
      const dollar = /^\$([a-z0-9-]+)\$/i.exec(text);
      const braced = /^\{([^}]+)\}/.exec(text);
      out.push(Object.assign({}, common, {
        role: mechanism.role,
        credentials: values.length,
        credentialId: String(i + 1),
        algorithm: dollar ? dollar[1] : (braced ? braced[1] : ''),
        lane: '',
        enrolledAt: reportLdapTime(reportAttr(entry, 'pwdChangedTime')) ||
          null,
        lastUsedAt: null
      }));
    });
    log.debug("Leaving reportHolderRows(). " + out.length + ' password.');
    return out;
  }
  // Every other mechanism: one row per attribute value, which is one
  // credential (an authenticator app, an enrolled certificate, a mail
  // factor, a Kerberos key set), with what the value records.
  const parsed = reportParsedValues(values);
  parsed.forEach(function (one: any, i: number): void {
    out.push(Object.assign({}, common, {
      role: mechanism.role,
      credentials: values.length,
      credentialId: String(one.id || one.credentialId || one.serial ||
        one.kvno || (i + 1)),
      algorithm: String(one.algorithm || one.enctype || ''),
      lane: '',
      enrolledAt: reportMinIso([one.enrolledAt]),
      lastUsedAt: reportMaxIso([one.lastUsedAt])
    }));
  });
  log.debug("Leaving reportHolderRows(). " + out.length + ' row(s).');
  return out;
}

// A holder as `holdersAsync()` hands one back, as an entry the row builder
// can read: its raw attributes are already keyed by the names asked for.
function reportHolderEntry(holder: any): any {
  log.debug("Entering reportHolderEntry().");
  const entry = { dn: String((holder && holder.dn) || ''),
                  attributes: (holder && holder.attributes) || {} };
  log.debug("Leaving reportHolderEntry().");
  return entry;
}

async function reportMechanismHolders(mechanism: any, ldap: any,
                                      stop?: () => string): Promise<any[]> {
  log.debug("Entering reportMechanismHolders(). " + mechanism.id);
  // Unguarded, as the other doors above are: a directory without the door
  // throws, and the run fails out loud rather than listing nobody. EVERY
  // mechanism's attribute is asked for, not just this one's: a person
  // holding two mechanisms is opened once (the reader keeps one entry per
  // DN), and that entry has to carry both or the second mechanism's rows
  // are lost.
  const holders = await ldap.holdersAsync('person', mechanism.attribute,
    MECHANISM_TABLE.map(function (m: any): string {
      return String(m.attribute).toLowerCase();
    }).filter(function (name: string): boolean {
      return name !== '';
    }).concat(HOLDER_FIELDS), stop ? { stop: stop } : undefined);
  const entries = (holders || []).map(reportHolderEntry);
  log.debug("Leaving reportMechanismHolders(). " + entries.length + '.');
  return entries;
}

// The members of a group, by name: the group's member DNs, the person's name
// read off each `uid=` RDN. A member named otherwise (a group, a
// certificate's `cn=` entry) is left out: the row needs a person. The group
// is named by its `cn`, as the row's `memberOf` names it — the same spelling
// the filter is then checked against in `Rows.take()`; a DN here would find
// the members and match no row.
function reportGroupMemberNames(selector: string, ldap: any): string[] {
  log.debug("Entering reportGroupMemberNames(). " + selector);
  const wanted = String(selector || '').trim();
  const dn = wanted ? ldap.groupDnFor(wanted) : '';
  const group = dn ? ldap.readGroupEntry(dn) : null;
  if (!group) {
    log.debug("Leaving reportGroupMemberNames(). No such group.");
    return [];
  }
  const names: string[] = [];
  (group.members || []).slice(0, GROUP_MEMBERS_MAX).forEach(
    function (member: any): void {
      const value = String((member && (member.dn || member.value)) || '');
      const matched = /^uid=([^,]+),/i.exec(value);
      if (matched && names.indexOf(matched[1]) < 0) {
        names.push(matched[1]);
      }
    });
  log.debug("Leaving reportGroupMemberNames(). " + names.length + '.');
  return names;
}

// THE READ IS REFUSED BEFORE ITS FIRST PAGE WHEN IT CANNOT FIT (#1002, found
// on 8081): every person with a password there holds `stsKrb5Keys`, so the
// Kerberos mechanism's holders ARE the population — a million entries — and
// a query naming it, or naming no mechanism, read them all, and went on
// reading them a page at a time for minutes after the client gave up. The
// store counts the holders of an attribute through the same index that
// lists them (`holderCountAsync`, nothing opened), so the count comes first,
// AND IT IS BOUNDED: the store counts no further than the cap plus one (a
// whole count of 8081's million took a minute, and the question is only
// "more than the cap?"). Over the execution's row cap (`report.syncMaxRows`,
// `report.asyncMaxRows`) the read is refused as `result_too_large` —
// synchronously as an UNBOUNDED refusal, which `auto` mode turns into a job,
// and the job counts again against its own, larger cap. The same cap bounds
// a group's members. And the read that does start carries `stop`, so the
// store's paging ends with the budget or a cancellation rather than with
// the last holder.
function reportTooManyHolders(n: number, cap: number, execution: string,
                              what: string): any {
  log.debug("Entering reportTooManyHolders().");
  const said = n > cap ? 'more than ' + cap : String(n);
  log.warn(errorCodes.tag(TOO_MANY_HOLDERS) +
    'report: a credentialHolders query would read ' + said + ' ' + what +
    ', over the ' + execution + ' cap of ' + cap + '; refused before the ' +
    'first page was read.');
  const sync = execution === 'sync';
  log.debug("Leaving reportTooManyHolders().");
  return {
    ok: false,
    code: TOO_MANY_HOLDERS,
    error: 'result_too_large',
    unbounded: sync,
    description: 'This query would read ' + said + ' ' + what + ', more ' +
      'than ' + (sync ? 'a synchronous query' : 'a job') + ' may read (' +
      cap + '). ' + (sync ? 'Run it as a job, or n' : 'N') +
      'arrow it: filter on a mechanism fewer people hold, or on memberOf.'
  };
}

function reportHoldersStop(control: any): () => string {
  log.debug("Entering reportHoldersStop().");
  const stop = function (): string {
    if (control && typeof control.cancelled === 'function' &&
        control.cancelled()) {
      return 'cancelled';
    }
    return reportOverBudget(control) ? 'budget' : '';
  };
  log.debug("Leaving reportHoldersStop().");
  return stop;
}

async function reportReadCredentialHolders(rows: any, control: any):
    Promise<void> {
  log.debug("Entering reportReadCredentialHolders().");
  const ldap = reportLdap();
  const plan = (rows && rows.plan) || {};
  const catalog = new Catalog();
  const lookups = reportIndexedLookups(plan.where, function (field: string):
      string[] {
    return catalog.indexedFor('credentialHolders', field);
  }, 0) || [];
  const groups = lookups.filter(function (one: Lookup): boolean {
    return one.field === 'memberOf';
  });
  // THE PERSON NAMED (rcbj, 2026-10-27: `username equals rcbj` was refused
  // as too large, because the reader knew only mechanism and memberOf and
  // read every mechanism's holders). A username, mail or entryUuid lookup
  // names the entries through the users source's doors
  // (`reportCandidates()`), and every mechanism of those people is read.
  const people = lookups.filter(function (one: Lookup): boolean {
    return one.field === 'username' || one.field === 'mail' ||
      one.field === 'entryUuid';
  });
  const mechanisms = lookups.filter(function (one: Lookup): boolean {
    return one.field === 'mechanism';
  });
  const wantedIds: string[] = [];
  mechanisms.forEach(function (one: Lookup): void {
    one.values.forEach(function (id: string): void {
      if (wantedIds.indexOf(id) < 0) {
        wantedIds.push(id);
      }
    });
  });
  const table = wantedIds.length ? MECHANISM_TABLE.filter(function (m: any):
      boolean {
    return wantedIds.indexOf(m.id) >= 0;
  }) : MECHANISM_TABLE;
  if (!groups.length && !mechanisms.length && !people.length && control &&
      control.execution === 'sync' && ldap.directoryIsWindowed()) {
    control.unbounded = reportUnboundedFilter(catalog, 'credentialHolders');
    log.debug("Leaving reportReadCredentialHolders(). Unbounded.");
    return;
  }
  const limits = new Limits();
  const execution = control && control.execution === 'async' ? 'async' :
    'sync';
  const cap = execution === 'sync' ? limits.syncMaxRows() :
    limits.asyncMaxRows();
  let entries: any[] = [];
  const seen = new Set<string>();
  const take = function (entry: any): void {
    const key = String((entry && entry.dn) || '').toLowerCase();
    if (key && !seen.has(key)) {
      seen.add(key);
      entries.push(entry);
    }
  };
  // The register's rows, read once when a wallet-credential mechanism is
  // asked for (#1021): the row builder reads a person's credentials off
  // them, and the holders read lists their subjects' entries.
  const wantsRegister = table.some(function (m: any): boolean {
    return !!m.register;
  });
  const context = { issuedBySubject: wantsRegister
    ? reportIssuedRows().bySubject : new Map<string, any[]>() };
  // The people named come first: the narrowest read there is. A lookup the
  // store could not answer whole (a substring on a memory directory, an
  // answer that filled the candidate cap) is null, and the read goes on to
  // the group or the mechanisms, or is refused as unbounded when it has
  // neither to go on to.
  const named = people.length ? await reportCandidates(people, ldap) : null;
  if (people.length && named === null && !groups.length &&
      !mechanisms.length) {
    control.unbounded = reportUnboundedFilter(catalog, 'credentialHolders');
    log.debug("Leaving reportReadCredentialHolders(). Not whole.");
    return;
  }
  if (named) {
    if (named.length > cap) {
      control.unbounded = reportTooManyHolders(named.length, cap, execution,
        'people');
      log.debug("Leaving reportReadCredentialHolders(). Too many people.");
      return;
    }
    named.forEach(take);
  } else if (groups.length) {
    // The community first: its members by name, counted against the cap
    // before any is read, then each one's mechanisms.
    let names: string[] = [];
    groups.forEach(function (one: Lookup): void {
      one.values.forEach(function (selector: string): void {
        reportGroupMemberNames(selector, ldap).forEach(
          function (name: string): void {
            if (names.indexOf(name) < 0) {
              names.push(name);
            }
          });
      });
    });
    if (names.length > cap) {
      control.unbounded = reportTooManyHolders(names.length, cap, execution,
        'group members');
      log.debug("Leaving reportReadCredentialHolders(). Too many members.");
      return;
    }
    const found = names.length ? await ldap.existingUserEntriesAsync(names) :
      [];
    (found || []).forEach(function (entry: any): void {
      if (entry) {
        take(entry);
      }
    });
  } else {
    // The holders, counted first where the store can count (a windowed
    // directory; in memory the answer is null and the walk is the count),
    // each mechanism no further than one past the cap.
    let holders = 0;
    let counted = false;
    for (let m = 0; m < table.length && holders <= cap; m++) {
      if (table[m].register) {
        // The register's subjects are its holders: counted in hand.
        counted = true;
        holders += context.issuedBySubject.size;
        continue;
      }
      const n = await ldap.holderCountAsync('person', table[m].attribute,
        cap + 1);
      if (typeof n === 'number') {
        counted = true;
        holders += n;
      }
    }
    if (counted && holders > cap) {
      control.unbounded = reportTooManyHolders(holders, cap, execution,
        'credential holders');
      log.debug("Leaving reportReadCredentialHolders(). Too many holders.");
      return;
    }
    const stop = reportHoldersStop(control);
    try {
      for (let m = 0; m < table.length; m++) {
        if (table[m].register) {
          // The register's subjects, named and fetched as a group's
          // members are (#1021).
          const names: string[] = [];
          context.issuedBySubject.forEach(function (rows: any[],
                                                    subject: string): void {
            const name = reportNameForSubject(subject);
            if (name && names.indexOf(name) < 0) {
              names.push(name);
            }
          });
          const found = names.length
            ? await ldap.existingUserEntriesAsync(names) : [];
          (found || []).forEach(function (entry: any): void {
            if (entry) {
              take(entry);
            }
          });
          continue;
        }
        (await reportMechanismHolders(table[m], ldap, stop)).forEach(take);
      }
    } catch (e: any) {
      if (!(e && e.stopped)) {
        log.debug("Caught in reportReadCredentialHolders(): " +
          ((e && e.message) || e));
        throw e;
      }
      // The budget (or a cancellation) ended the store's paging; the
      // caller reads the budget off `control` as it does for a row-by-row
      // read that ran out of time.
      log.debug("Caught in reportReadCredentialHolders(): " + e.message);
      if (stop() === 'budget') {
        control.timedOut = true;
      }
      log.debug("Leaving reportReadCredentialHolders(). Stopped.");
      return;
    }
  }
  for (let i = 0; i < entries.length; i++) {
    for (let m = 0; m < table.length; m++) {
      const made = reportHolderRows(entries[i], table[m], ldap, context);
      for (let r = 0; r < made.length; r++) {
        const keep = await reportOffer(made[r], rows, control);
        if (keep === false) {
          log.debug("Leaving reportReadCredentialHolders(). Stopped.");
          return;
        }
      }
    }
    if (i % PAGE === PAGE - 1) {
      await Promise.resolve();
    }
  }
  log.debug("Leaving reportReadCredentialHolders().");
}

async function reportReadGroups(rows: any, control: any): Promise<void> {
  log.debug("Entering reportReadGroups().");
  // A GROUP NAMED IS ONE READ (rcbj, 2026-10-27, "every index available on
  // every source"): `name equals` or `in` reads each group by its DN and
  // offers it, without listing the realm's groups.
  const plan = (rows && rows.plan) || {};
  const catalog = new Catalog();
  const lookups = reportIndexedLookups(plan.where, function (field: string):
      string[] {
    return catalog.indexedFor('groups', field);
  }, 0) || [];
  if (lookups.length) {
    const ldap = reportLdap();
    const seen: string[] = [];
    for (let l = 0; l < lookups.length; l++) {
      for (let v = 0; v < lookups[l].values.length; v++) {
        const wanted = String(lookups[l].values[v] || '').trim();
        if (!wanted || seen.indexOf(wanted.toLowerCase()) >= 0) {
          continue;
        }
        seen.push(wanted.toLowerCase());
        const dn = ldap.groupDnFor(wanted);
        const group = dn ? ldap.readGroupEntry(dn) : null;
        if (!group) {
          continue;
        }
        const members = reportGroupMemberNames(wanted, ldap);
        const keep = await reportOffer({
          name: wanted,
          description: reportAttr(group, 'description'),
          memberCount: members.length,
          members: members.join(', ')
        }, rows, control);
        if (keep === false) {
          log.debug("Leaving reportReadGroups(). Stopped.");
          return;
        }
      }
    }
    log.debug("Leaving reportReadGroups(). " + seen.length + ' named.');
    return;
  }
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
  } else if (source === 'credentialHolders') {
    await reportReadCredentialHolders(rows, control);
  }
  log.debug("Leaving reportReadSource().");
}

// THE ANCHOR RULE (rcbj, 2026-10-27: "if there aren't indexes of fields we
// could search on … these shouldn't be exposed as valid search parameters
// because the queries will never work given the constraints we've
// defined"). On a directory held in a database, a filter on `users` or
// `credentialHolders` that names no indexed field would read every person:
// synchronously that was `result_too_large` after a long wait, as a job it
// ran into the time cap. It is now refused at acceptance, in every mode,
// as `invalid_query` with the indexed fields named — the same planner
// (`reportIndexedLookups()`) decides, so what it refuses is exactly what the
// reader could not have narrowed. A memory directory is small by
// construction and is not held to it; a query with no filter still stops at
// its limit. The page offers only the indexed fields in a first filter row.
function reportAnchorRefusal(plan: any): any {
  log.debug("Entering reportAnchorRefusal().");
  const catalog = new Catalog();
  const src = plan && plan.source ? catalog.source(plan.source) : null;
  if (!src || !src.anchored || !plan.where) {
    log.debug("Leaving reportAnchorRefusal(). Not anchored, or no filter.");
    return null;
  }
  const ldap = reportLdap();
  if (!ldap.directoryIsWindowed()) {
    log.debug("Leaving reportAnchorRefusal(). In memory.");
    return null;
  }
  const lookups = reportIndexedLookups(plan.where, function (field: string):
      string[] {
    return catalog.indexedFor(String(plan.source), field);
  }, 0);
  if (lookups && lookups.length) {
    log.debug("Leaving reportAnchorRefusal(). Anchored.");
    return null;
  }
  const named = (src.fields || []).filter(function (field: any): boolean {
    return Array.isArray(field.indexed) && field.indexed.length > 0;
  }).map(function (field: any): string {
    return field.id + ' (' + field.indexed.join(', ') + ')';
  });
  log.warn(errorCodes.tag('STS-REPORT-0040') +
    'report: a ' + plan.source + ' filter names no indexed field; refused ' +
    'rather than read person by person.');
  log.debug("Leaving reportAnchorRefusal(). Refused.");
  return {
    ok: false,
    code: 'STS-REPORT-0040',
    error: 'invalid_query',
    description: 'A filter on ' + plan.source + ' has to name an indexed ' +
      'field, as a condition of an "and" or in every arm of an "or": ' +
      named.join(', ') + '. The other fields narrow that read.'
  };
}

async function reportReadWork(plan: any, control: any): Promise<any> {
  log.debug("Entering reportReadWork().");
  const anchor = reportAnchorRefusal(plan);
  if (anchor) {
    log.debug("Leaving reportReadWork(). Not anchored.");
    return anchor;
  }
  const rows = new Rows(plan, reportTypes(plan));
  const held = control || {};
  if (reportReader) {
    await reportReader(plan, function (row: any): boolean {
      return rows.take(row);
    }, held);
  } else {
    await reportReadSource(plan, rows, held);
  }
  if (held.unbounded) {
    log.debug("Leaving reportReadWork(). Unbounded.");
    return held.unbounded;
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

// ---------------------------------------------------------------------------
// THE GROUPS A RESULT IS SENT TO (#989). A definition's share list — the
// groups whose members may run it and read its result — is also who is
// emailed when a job of it completes with Notify on, at each group's OWN
// `mail` attribute (set on the group page, `POST /admin-api/groups/set-mail`,
// or at its create). `reportGroupRecipients()` splits the list into the
// groups with an address and the groups without: the first are sent the
// notice through the mail channel's group recipient (`groupDn`, so the
// address is the directory's and never a request's); each of the second is
// an error of its own, STS-REPORT-0037, logged and written on the audit
// row, and the other recipients are still sent to. The owner's notice is
// unchanged. The group search the definition page draws its pane from
// (`reportGroupSearch()`) reads the same resident groups, five a page.
// ---------------------------------------------------------------------------
const GROUP_PAGE = 5;

function reportGroupRows(ldap: any): any[] {
  log.debug("Entering reportGroupRows().");
  const list = typeof ldap.allGroupEntries === 'function' ?
    (ldap.allGroupEntries() || []) : [];
  const rows = list.map(function (group: any): any {
    const cn = reportAttr(group, 'cn');
    return {
      dn: String(group.dn || ''),
      name: cn || String(group.dn || ''),
      mail: reportAttr(group, 'mail')
    };
  }).filter(function (row: any): boolean {
    return !!row.dn;
  });
  log.debug("Leaving reportGroupRows(). " + rows.length + '.');
  return rows;
}

function reportGroupSearch(q: any, page: any): any {
  log.debug("Entering reportGroupSearch().");
  const ldap = reportLdap();
  const needle = String(q == null ? '' : q).trim().toLowerCase();
  const all = reportGroupRows(ldap).filter(function (row: any): boolean {
    return !needle || row.name.toLowerCase().indexOf(needle) >= 0 ||
      row.dn.toLowerCase().indexOf(needle) >= 0;
  });
  all.sort(function (a: any, b: any): number {
    return a.name.toLowerCase() < b.name.toLowerCase() ? -1 :
      (a.name.toLowerCase() > b.name.toLowerCase() ? 1 : 0);
  });
  const pages = Math.max(1, Math.ceil(all.length / GROUP_PAGE));
  const asked = Math.floor(Number(page) || 1);
  const at = Math.min(pages, Math.max(1, asked));
  const out = {
    q: needle,
    page: at,
    pages: pages,
    per: GROUP_PAGE,
    total: all.length,
    groups: all.slice((at - 1) * GROUP_PAGE, at * GROUP_PAGE)
  };
  log.debug("Leaving reportGroupSearch(). " + out.total + ' matched.');
  return out;
}

function reportGroupRecipients(groups: any, ldap: any): any {
  log.debug("Entering reportGroupRecipients().");
  const known = reportGroupRows(ldap);
  const byDn: Record<string, any> = {};
  known.forEach(function (row: any): void {
    byDn[row.dn.toLowerCase()] = row;
  });
  const addressed: any[] = [];
  const missing: any[] = [];
  (Array.isArray(groups) ? groups : []).forEach(function (dn: any): void {
    const key = String(dn || '').trim().toLowerCase();
    if (!key) {
      return;
    }
    const row = byDn[key] || { dn: String(dn), name: String(dn), mail: '' };
    if (row.mail) {
      addressed.push(row);
    } else {
      missing.push(row);
    }
  });
  log.debug("Leaving reportGroupRecipients(). " + addressed.length +
    ' addressed, ' + missing.length + ' without an address.');
  return { addressed: addressed, missing: missing };
}

function reportGroupNotice(job: any, group: any): any {
  log.debug("Entering reportGroupNotice().");
  const request = {
    groupDn: group.dn,
    template: 'report-ready',
    values: {
      username: group.name,
      definition: job.definitionName || job.definitionId || '',
      status: job.status
    },
    links: { report: '/report/jobs/' + job.id },
    dedupKey: 'report-ready:' + job.id + ':' + group.dn,
    actor: reportActor(job)
  };
  log.debug("Leaving reportGroupNotice().");
  return request;
}

function reportNotifyGroups(job: any): void {
  log.debug("Entering reportNotifyGroups().");
  const def = stores.getDefinition(job.definitionId);
  const groups = def && Array.isArray(def.groups) ? def.groups : [];
  if (!groups.length) {
    log.debug("Leaving reportNotifyGroups(). None.");
    return;
  }
  const split = reportGroupRecipients(groups, reportLdap());
  split.missing.forEach(function (group: any): void {
    log.error(errorCodes.tag('STS-REPORT-0037') + 'report: job ' + job.id +
      ' finished with Notify on, and the group ' + group.dn +
      ' it is shared with has no mail attribute, so that group was not ' +
      'sent the notice.');
    reportAudit({
      category: 'admin',
      action: 'report.notify',
      outcome: 'error',
      errorCode: 'STS-REPORT-0037',
      actor: reportActor(job),
      summary: 'report job ' + job.id + ': the group ' + group.dn +
        ' has no mail attribute',
      detail: Object.assign({ group: group.dn }, reportDetail(job))
    });
  });
  if (!split.addressed.length) {
    log.debug("Leaving reportNotifyGroups(). Nobody addressed.");
    return;
  }
  const mail = require('../common/mail');
  split.addressed.forEach(function (group: any): void {
    let sent: any = null;
    try {
      sent = mail.send(reportGroupNotice(job, group));
    } catch (e) {
      log.debug("Caught in reportNotifyGroups(): " +
        ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-REPORT-0027') +
        'report: the job finished and the notice to ' + group.dn +
        ' was not sent.');
      reportNotifyAudit(job, true);
      return;
    }
    const why = sent && sent.error ? String(sent.error) : '';
    const skipped = why.indexOf('no mail transport') >= 0 ||
      why.indexOf('publicBaseUrl') >= 0;
    if (sent && sent.ok) {
      reportNotifyAudit(job, false);
    } else if (!skipped) {
      log.warn(errorCodes.tag('STS-REPORT-0027') +
        'report: the job finished and the notice to ' + group.dn +
        ' was not sent.');
      reportNotifyAudit(job, true);
    }
  });
  log.debug("Leaving reportNotifyGroups().");
}

function reportNotify(job: any): void {
  log.debug("Entering reportNotify().");
  if (!job || !job.notify || !job.definitionId) {
    log.debug("Leaving reportNotify(). Not asked.");
    return;
  }
  // The shared groups first (#989); a throw there is caught per group, so
  // the owner's notice below is never lost to a group's.
  reportNotifyGroups(job);
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
  try {
    await stores.putArtifact(stored.id, finished.body, sha, finished.media);
  } catch (e: any) {
    // NOT STORED UNSEALED (#1033): a report that could not be sealed is a
    // failed job, said with the store's code, never a clear-text row.
    log.debug("Caught in reportRunOne(): " + ((e && e.message) || e));
    reportFailJob(stored, 'unavailable',
      String((e && e.code) || 'STS-REPORT-0042'));
    log.debug("Leaving reportRunOne(). Not stored.");
    return;
  }
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
    // THE OWNER'S OWN QUESTION, TO THE POLICY (#1030): the roles the owner
    // holds now, and `run` on this definition.
    const rightsOf = rights.ownerMayRun(def);
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
      ownerKind: def.ownerKind,
      document: def.document,
      parameters: names.length ? bag : null,
      definitionId: def.id,
      definitionName: def.name,
      notify: !!def.notify,
      because: 'schedule',
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
  installDirectory: reportInstallDirectory,
  // The issued-credential register a test installs (#1021).
  installIssuedRegister: reportInstallIssuedRegister,
  // The mechanism ids, for the test that holds the catalog's enumeration
  // (#1007) equal to the table (the catalog cannot require this module).
  mechanismIds: function (): string[] {
    log.debug("Entering mechanismIds().");
    const ids = MECHANISM_TABLE.map(function (m: any): string {
      return String(m.id);
    });
    log.debug("Leaving mechanismIds().");
    return ids;
  },
  indexedLookups: reportIndexedLookups,
  groupSearch: reportGroupSearch,
  groupRecipients: reportGroupRecipients,
  notify: reportNotify,
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
