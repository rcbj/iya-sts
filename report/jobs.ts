// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: jobs.ts
//
// ---------------------------------------------------------------------------
// DEFINITIONS, JOBS AND THE SIX SCHEDULER ROWS (#956).
//
// A definition stores the same document a query posts, plus a name, an
// owner, the groups it is shared with, an optional cron schedule in UTC,
// and the parameter values a schedule runs with. The schedule sits beside
// the document: the document's validator rejects a key it does not know,
// and a schedule is not a filter. A save may still be checked with a
// dummy of a missing parameter's type. That dummy is not stored, and a
// schedule does not run on it.
//
// Three cluster jobs do the work when this process is not clustered, or
// when no reporting node holds `ops.reporting`. Three per-process twins do
// it when this process opted in with STS_REPORT_NODE and holds that lease.
// Both sets are registered at load, so every process lists the same jobs.
// The run calls `reportGateOne` by that name: the walk test follows the
// text of `run`, and a name it cannot see is a walk it cannot vouch for.
//
// An enqueue is refused when the subject already has more queued and
// running jobs than max(8, maxConcurrentPerSubject * 4), or the realm more
// than max(32, maxConcurrentPerRealm * 8). The caps on jobs actually
// running are the settings themselves, applied when a job is claimed.
// When both ceilings are full the refusal is the realm's.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import errorCodes = require('../common/error_codes');
import schedulerMod = require('../cluster/scheduler');
import stores = require('./stores');
import rights = require('./rights');
import sources = require('./sources');
import Catalog = require('./catalog');
import Limits = require('./limits');
import Query = require('./query');

const log = bunyan.createLogger({ name: 'sts-report-jobs' });

const reportGateOne = sources.reportGateOne;
const reportClusterRuns = sources.clusterRuns;
const reportHereRuns = sources.hereRuns;
const reportStampReporter = sources.stampReporter;

const ON_FRONT = 'The fence is a set in this process; a worker does not ' +
  'share it.';

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

function reportQuery(): any {
  log.debug("Entering reportQuery().");
  const query = new Query({ catalog: new Catalog(), limits: new Limits() });
  log.debug("Leaving reportQuery().");
  return query;
}

function reportRefuse(code: string, error: string, description: string):
    any {
  log.debug("Entering reportRefuse().");
  log.warn(errorCodes.tag(code) + 'report: ' + description);
  log.debug("Leaving reportRefuse().");
  return { ok: false, code: code, error: error, description: description };
}

function reportActive(owner: string | null): { subject: number;
    realm: number } {
  log.debug("Entering reportActive().");
  let subject = 0;
  let realm = 0;
  stores.listJobs().forEach(function (job: any): void {
    if (job.status !== 'queued' && job.status !== 'running') {
      return;
    }
    realm += 1;
    if (owner && job.owner === owner) {
      subject += 1;
    }
  });
  log.debug("Leaving reportActive().");
  return { subject: subject, realm: realm };
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

function reportActor(subject: string): string {
  log.debug("Entering reportActor().");
  const name = rights.username(subject);
  log.debug("Leaving reportActor().");
  return name || subject || '';
}

/**
 * Queues a job. The document is copied as posted; the plan is not stored,
 * and the drain validates again so a catalog change still refuses.
 *
 * @param spec - owner, document, parameters, definition fields and the plan
 * @returns the job, or a refusal
 */
function reportSubmit(spec: any): any {
  log.debug("Entering reportSubmit().");
  const limits = new Limits();
  const active = reportActive(spec.owner);
  const subjectCap = Math.max(8, limits.maxConcurrentPerSubject() * 4);
  const realmCap = Math.max(32, limits.maxConcurrentPerRealm() * 8);
  if (active.realm >= realmCap ||
      (active.subject >= subjectCap && active.realm >= realmCap)) {
    log.debug("Leaving reportSubmit(). Realm ceiling.");
    return reportRefuse('STS-REPORT-0023', 'too_many_jobs',
      'This realm already has as many report jobs as it may queue.');
  }
  if (active.subject >= subjectCap) {
    log.debug("Leaving reportSubmit(). Subject ceiling.");
    return reportRefuse('STS-REPORT-0023', 'too_many_jobs',
      'This account already has as many report jobs as it may queue.');
  }
  const plan = spec.plan;
  const now = Date.now();
  const job = {
    id: stores.newId(),
    owner: spec.owner,
    // `user` or `application` (#1030): which kind of subject owns it, so
    // the policy and the schedule can resolve the owner's roles.
    ownerKind: spec.ownerKind === 'application' ? 'application' : 'user',
    // The realm the owner's identity is in when it is not this one: the
    // default realm's for a service administrator (#1038), '' otherwise.
    ownerRealm: String(spec.ownerRealm || ''),
    document: stores.copy(spec.document),
    parameters: spec.parameters ? stores.copy(spec.parameters) : null,
    definitionId: spec.definitionId || null,
    definitionName: spec.definitionName || null,
    notify: !!spec.notify,
    source: plan.source,
    fields: (plan.fields || []).slice(),
    format: plan.format,
    // WHY THIS IS A JOB (#986): `every-person` (an auto-mode query the
    // reader refused to run synchronously, #985), `asked` (mode async,
    // or POST /jobs), `limit` (auto over report.syncMaxRows), `source` (a
    // source that cannot be read synchronously), `run` (a saved
    // definition run by hand) or `schedule`. The job page says it.
    queuedBecause: String(spec.because || 'asked'),
    status: 'queued',
    submittedAt: now,
    startedAt: null,
    completedAt: null,
    byteSize: null,
    sha256: null,
    mediaType: null,
    error: null,
    cancelRequested: false,
    runner: null
  };
  stores.putJob(job);
  reportAudit({
    category: 'admin',
    action: 'report.job.submit',
    outcome: 'success',
    actor: reportActor(spec.owner),
    summary: 'report job ' + job.id + ' queued for ' + plan.source,
    detail: { source: plan.source, fields: job.fields, job: job.id }
  });
  log.debug("Leaving reportSubmit().");
  return { ok: true, job: stores.getJob(job.id) };
}

function reportParams(node: any, into: any[]): void {
  log.debug("Entering reportParams().");
  if (!node || typeof node !== 'object') {
    log.debug("Leaving reportParams(). None.");
    return;
  }
  if (node.op === 'and' || node.op === 'or') {
    const args = Array.isArray(node.args) ? node.args : [];
    args.forEach(function (child: any): void {
      reportParams(child, into);
    });
    log.debug("Leaving reportParams(). Logical.");
    return;
  }
  if (node.op === 'not') {
    reportParams(node.arg, into);
    log.debug("Leaving reportParams(). Not.");
    return;
  }
  if (Object.prototype.hasOwnProperty.call(node, 'param')) {
    into.push({
      name: String(node.param),
      field: String(node.field || '')
    });
  }
  log.debug("Leaving reportParams().");
}

function reportParameterNames(document: any): string[] {
  log.debug("Entering reportParameterNames().");
  const found: any[] = [];
  reportParams(document && document.where, found);
  const names: string[] = [];
  found.forEach(function (item: any): void {
    if (names.indexOf(item.name) < 0) {
      names.push(item.name);
    }
  });
  log.debug("Leaving reportParameterNames().");
  return names;
}

function reportParamValue(value: any): boolean {
  log.debug("Entering reportParamValue().");
  if (value == null || typeof value === 'boolean') {
    log.debug("Leaving reportParamValue(). Scalar.");
    return true;
  }
  if (typeof value === 'number') {
    log.debug("Leaving reportParamValue(). Number.");
    return Number.isFinite(value);
  }
  if (typeof value === 'string') {
    log.debug("Leaving reportParamValue(). String.");
    return value.length <= 200;
  }
  if (!Array.isArray(value) || value.length < 1 || value.length > 32) {
    log.debug("Leaving reportParamValue(). Not a list.");
    return false;
  }
  for (let i = 0; i < value.length; i++) {
    const one = value[i];
    if (one != null && typeof one !== 'string' && typeof one !== 'number' &&
        typeof one !== 'boolean') {
      log.debug("Leaving reportParamValue(). Nested.");
      return false;
    }
    if (typeof one === 'string' && one.length > 200) {
      log.debug("Leaving reportParamValue(). Long.");
      return false;
    }
    if (typeof one === 'number' && !Number.isFinite(one)) {
      log.debug("Leaving reportParamValue(). Not finite.");
      return false;
    }
  }
  log.debug("Leaving reportParamValue().");
  return true;
}

// The caller's values, or false when the bag is not one this service stores.
// A dummy used only to type-check a save is not this function.
function reportStoredParameters(given: any): any {
  log.debug("Entering reportStoredParameters().");
  if (given == null) {
    log.debug("Leaving reportStoredParameters(). None.");
    return null;
  }
  if (typeof given !== 'object' || Array.isArray(given)) {
    log.debug("Leaving reportStoredParameters(). Not a bag.");
    return false;
  }
  const keys = Object.keys(given);
  if (keys.length > 32) {
    log.debug("Leaving reportStoredParameters(). Too many.");
    return false;
  }
  const bag: any = {};
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (!key || key.length > 64 || !reportParamValue(given[key])) {
      log.debug("Leaving reportStoredParameters(). Value.");
      return false;
    }
    bag[key] = stores.copy(given[key]);
  }
  log.debug("Leaving reportStoredParameters().");
  return bag;
}

function reportDummy(type: string): any {
  log.debug("Entering reportDummy().");
  let value: any = 'x';
  if (type === 'number' || type === 'timestamp') {
    value = 0;
  } else if (type === 'boolean') {
    value = true;
  }
  log.debug("Leaving reportDummy().");
  return value;
}

function reportBag(document: any, parameters: any): any {
  log.debug("Entering reportBag().");
  const found: any[] = [];
  reportParams(document && document.where, found);
  if (!found.length) {
    log.debug("Leaving reportBag(). No parameters.");
    return null;
  }
  const bag: any = {};
  if (parameters && typeof parameters === 'object') {
    Object.keys(parameters).forEach(function (key: string): void {
      bag[key] = parameters[key];
    });
  }
  const catalog = new Catalog();
  found.forEach(function (item: any): void {
    if (Object.prototype.hasOwnProperty.call(bag, item.name)) {
      return;
    }
    const field = catalog.field(String(document.source || ''), item.field);
    bag[item.name] = reportDummy(field ? field.type : 'string');
  });
  log.debug("Leaving reportBag().");
  return bag;
}

// WHEN A SCHEDULE RUNS NEXT, AND WHICH OCCURRENCE IT LAST TOOK (#989's
// follow-up, rcbj: a schedule set and no job seen). The page draws both,
// so a reader can tell "not due yet" from "skipped", and the failure notes
// say why a skip happened. Null where the schedule is off or has no
// occurrence; `cronNext` is croner's, in UTC, as the job's `cronPrev` is.
function reportScheduleTimes(def: any, nowMs?: number): any {
  log.debug("Entering reportScheduleTimes().");
  const out = { nextRunAt: null as string | null,
                lastSlotAt: null as string | null };
  if (def && typeof def.lastSlot === 'number') {
    out.lastSlotAt = reportIso(def.lastSlot);
  }
  if (!def || !def.scheduleEnabled || !def.schedule) {
    log.debug("Leaving reportScheduleTimes(). Off.");
    return out;
  }
  try {
    const scheduler = require('../cluster/scheduler');
    const next = scheduler.Scheduler.cronNext(String(def.schedule),
      typeof nowMs === 'number' ? nowMs : Date.now());
    out.nextRunAt = next == null ? null : reportIso(next);
  } catch (e) {
    // An expression croner cannot read has no next run; the save refused
    // it already, so this is a row written by hand.
    log.debug("Caught in reportScheduleTimes(): " + ((e && e.message) || e));
    out.nextRunAt = null;
  }
  log.debug("Leaving reportScheduleTimes().");
  return out;
}

function reportCronOk(expr: string): boolean {
  log.debug("Entering reportCronOk().");
  if (!expr) {
    log.debug("Leaving reportCronOk(). None.");
    return true;
  }
  try {
    const next = schedulerMod.Scheduler.cronNext(String(expr), Date.now());
    log.debug("Leaving reportCronOk().");
    return typeof next === 'number';
  } catch (e) {
    log.debug("Caught in reportCronOk(): " + ((e && e.message) || e));
    log.debug("Leaving reportCronOk(). Unreadable.");
    return false;
  }
}

/**
 * Creates or replaces a definition. Parameters in the document are checked
 * against the caller's values or a dummy of the field's type. The dummy
 * is not stored. The stored document still names the parameter, and
 * `parameters` on the row is the bag a schedule will run with.
 *
 * @param spec - the posted definition
 * @returns the stored row, or a refusal
 */
function reportSave(spec: any): any {
  log.debug("Entering reportSave().");
  const name = String(spec.name || '').trim();
  if (!name || name.length > 120) {
    log.debug("Leaving reportSave(). Name.");
    return reportRefuse('STS-REPORT-0030', 'invalid_query',
      'A definition needs a name.');
  }
  if (!spec.document || typeof spec.document !== 'object' ||
      Array.isArray(spec.document)) {
    log.debug("Leaving reportSave(). Document.");
    return reportRefuse('STS-REPORT-0030', 'invalid_query',
      'A definition needs a query document.');
  }
  const schedule = spec.schedule ? String(spec.schedule) : '';
  if (!reportCronOk(schedule)) {
    log.debug("Leaving reportSave(). Schedule.");
    return reportRefuse('STS-REPORT-0030', 'invalid_query',
      'The schedule is not a UTC cron expression.');
  }
  const bag = reportBag(spec.document, spec.parameters);
  const validated = reportQuery().validate(spec.document, bag);
  if (!validated.ok) {
    log.warn(errorCodes.tag('STS-REPORT-0030') +
      'report: a definition was rejected.');
    log.debug("Leaving reportSave(). Query.");
    return {
      ok: false,
      code: 'STS-REPORT-0030',
      error: validated.error,
      description: validated.description
    };
  }
  const now = Date.now();
  const previous = spec.id ? stores.getDefinition(spec.id) : null;
  // Undefined keeps the values already stored. Null clears them. A bag is
  // stored as given. The dummy bag above is only the type check.
  let parameters: any = null;
  if (spec.parameters === undefined) {
    parameters = previous && previous.parameters ?
      stores.copy(previous.parameters) : null;
  } else {
    parameters = reportStoredParameters(spec.parameters);
    if (parameters === false) {
      log.debug("Leaving reportSave(). Parameters.");
      return reportRefuse('STS-REPORT-0030', 'invalid_query',
        'Parameters are names and values.');
    }
  }
  const row = {
    id: previous ? previous.id : stores.newId(),
    name: name,
    owner: previous ? previous.owner : spec.owner,
    ownerKind: previous ? (previous.ownerKind || 'user')
      : (spec.ownerKind === 'application' ? 'application' : 'user'),
    ownerRealm: previous ? String(previous.ownerRealm || '')
      : String(spec.ownerRealm || ''),
    document: stores.copy(spec.document),
    parameters: parameters,
    schedule: schedule,
    scheduleEnabled: !!spec.scheduleEnabled,
    notify: !!spec.notify,
    groups: previous && Array.isArray(previous.groups) ?
      previous.groups.slice() : [],
    lastSlot: previous ? previous.lastSlot : null,
    failures: previous && Array.isArray(previous.failures) ?
      previous.failures.slice() : [],
    createdAt: previous ? previous.createdAt : now,
    modifiedAt: now
  };
  stores.putDefinition(row);
  reportAudit({
    category: 'admin',
    action: previous ? 'report.definition.update' :
      'report.definition.create',
    outcome: 'success',
    actor: reportActor(row.owner),
    summary: 'report definition ' + row.name,
    detail: {
      source: validated.plan.source,
      fields: validated.plan.fields,
      definition: row.id
    }
  });
  log.debug("Leaving reportSave().");
  return { ok: true, definition: stores.getDefinition(row.id) };
}

/**
 * Replaces the groups a definition is shared with. Each DN has to be a
 * group in this realm. A share can run and retrieve; it cannot edit.
 *
 * @param spec - definition id and the group DNs
 * @returns the stored row, or a refusal
 */
function reportShare(spec: any): any {
  log.debug("Entering reportShare().");
  const row = stores.getDefinition(spec.id);
  if (!row) {
    log.debug("Leaving reportShare(). Missing.");
    return reportRefuse('STS-REPORT-0019', 'not_found',
      'No such definition.');
  }
  const groups = Array.isArray(spec.groups) ? spec.groups : null;
  if (!groups) {
    log.debug("Leaving reportShare(). Not a list.");
    return reportRefuse('STS-REPORT-0031', 'invalid_query',
      'Name the groups to share this definition with.');
  }
  for (let i = 0; i < groups.length; i++) {
    const dn = String(groups[i] || '').trim();
    if (!dn || !rights.groupExists(dn)) {
      log.debug("Leaving reportShare(). Unknown group.");
      return reportRefuse('STS-REPORT-0031', 'invalid_query',
        'A share names a group this realm does not have.');
    }
    groups[i] = dn;
  }
  row.groups = groups;
  row.modifiedAt = Date.now();
  stores.putDefinition(row);
  reportAudit({
    category: 'admin',
    action: 'report.definition.share',
    outcome: 'success',
    actor: reportActor(spec.actor || row.owner),
    summary: 'report definition ' + row.name + ' shared',
    detail: { definition: row.id, source: row.document &&
      row.document.source, fields: (row.document &&
      row.document.select) || [] }
  });
  log.debug("Leaving reportShare().");
  return { ok: true, definition: stores.getDefinition(row.id) };
}

function reportRemove(id: string, actor: string): any {
  log.debug("Entering reportRemove().");
  const row = stores.getDefinition(id);
  if (!row) {
    log.debug("Leaving reportRemove(). Missing.");
    return reportRefuse('STS-REPORT-0019', 'not_found',
      'No such definition.');
  }
  stores.deleteDefinition(id);
  reportAudit({
    category: 'admin',
    action: 'report.definition.delete',
    outcome: 'success',
    actor: reportActor(actor),
    summary: 'report definition ' + row.name + ' deleted',
    detail: { definition: id, source: row.document && row.document.source,
      fields: (row.document && row.document.select) || [] }
  });
  log.debug("Leaving reportRemove().");
  return { ok: true };
}

function reportJobView(job: any, full: boolean): any {
  log.debug("Entering reportJobView().");
  const view: any = {
    id: job.id,
    status: job.status,
    format: job.format,
    submittedAt: reportIso(job.submittedAt),
    completedAt: reportIso(job.completedAt),
    byteSize: job.byteSize == null ? null : job.byteSize,
    error: job.error || null,
    definitionId: job.definitionId || null,
    definitionName: job.definitionName || null,
    source: job.source,
    fields: (job.fields || []).slice(),
    queuedBecause: job.queuedBecause || null
  };
  if (full) {
    view.query = stores.copy(job.document);
  }
  log.debug("Leaving reportJobView().");
  return view;
}

function reportCancel(job: any, actor: string): any {
  log.debug("Entering reportCancel().");
  if (!job) {
    log.debug("Leaving reportCancel(). Missing.");
    return reportRefuse('STS-REPORT-0020', 'job_not_found',
      'No such job.');
  }
  if (job.status === 'completed' || job.status === 'failed' ||
      job.status === 'cancelled' || job.status === 'expired') {
    log.debug("Leaving reportCancel(). Already finished.");
    return { ok: true, job: job };
  }
  if (job.status === 'queued') {
    job.status = 'cancelled';
    job.completedAt = Date.now();
    job.cancelRequested = true;
    stores.putJob(job);
    log.warn(errorCodes.tag('STS-REPORT-0032') +
      'report: a queued job was cancelled.');
    reportAudit({
      category: 'admin',
      action: 'report.job.cancel',
      outcome: 'success',
      errorCode: 'STS-REPORT-0032',
      actor: reportActor(actor),
      summary: 'report job ' + job.id + ' was cancelled',
      detail: { source: job.source, fields: job.fields, job: job.id }
    });
    log.debug("Leaving reportCancel(). Queued.");
    return { ok: true, job: stores.getJob(job.id) };
  }
  job.cancelRequested = true;
  stores.putJob(job);
  log.debug("Leaving reportCancel(). Running.");
  return { ok: true, job: stores.getJob(job.id) };
}

function reportDrainNow(ctx?: any): Promise<any> {
  log.debug("Entering reportDrainNow().");
  const out = reportGateOne('drain', ctx || {
    stillOwner: function (): boolean { return true; }
  });
  log.debug("Leaving reportDrainNow().");
  return Promise.resolve(out);
}

function reportRetainNow(ctx?: any): Promise<any> {
  log.debug("Entering reportRetainNow().");
  const out = reportGateOne('retain', ctx || {});
  log.debug("Leaving reportRetainNow().");
  return Promise.resolve(out);
}

function reportScheduleNow(nowMs?: number): Promise<any> {
  log.debug("Entering reportScheduleNow().");
  const out = reportGateOne('schedule', {
    nowMs: nowMs || Date.now(),
    stillOwner: function (): boolean { return true; }
  });
  log.debug("Leaving reportScheduleNow().");
  return Promise.resolve(out);
}

function reportAbandonFences(): void {
  log.debug("Entering reportAbandonFences().");
  sources.abandonFences();
  log.debug("Leaving reportAbandonFences().");
}

function reportEveryDrain(): number {
  log.debug("Entering reportEveryDrain().");
  log.debug("Leaving reportEveryDrain().");
  return 2000;
}

function reportEverySlow(): number {
  log.debug("Entering reportEverySlow().");
  log.debug("Leaving reportEverySlow().");
  return 60000;
}

function reportSkipped(label: string): Promise<any> {
  log.debug("Entering reportSkipped().");
  log.debug("Leaving " + label + ".");
  return Promise.resolve({ skipped: true });
}

function reportRegister(): void {
  log.debug("Entering reportRegister().");
  if (schedulerMod.job('report.drain')) {
    log.debug("Leaving reportRegister(). Already registered.");
    return;
  }
  schedulerMod.register({
    id: 'report.drain',
    title: 'Report jobs',
    describe: 'Claims queued report jobs for this realm, up to the ' +
      'concurrency caps, and writes each artifact.',
    owner: 'report/jobs.ts',
    kind: 'cluster',
    scope: 'realm',
    nice: 10,
    everyMs: reportEveryDrain,
    onFront: ON_FRONT,
    run: function (ctx: any): Promise<any> {
      log.debug("Entering report.drain run().");
      if (!reportClusterRuns()) {
        return reportSkipped('report.drain run()');
      }
      const out = reportGateOne('drain', ctx);
      log.debug("Leaving report.drain run().");
      return Promise.resolve(out);
    }
  });
  schedulerMod.register({
    id: 'report.retention',
    title: 'Report retention',
    describe: 'Deletes report artifacts past their retention, drops ' +
      'finished job rows past theirs, and fails a running job whose ' +
      'fence is gone.',
    owner: 'report/jobs.ts',
    kind: 'cluster',
    scope: 'realm',
    nice: 12,
    everyMs: reportEverySlow,
    onFront: ON_FRONT,
    run: function (ctx: any): Promise<any> {
      log.debug("Entering report.retention run().");
      if (!reportClusterRuns()) {
        return reportSkipped('report.retention run()');
      }
      const out = reportGateOne('retain', ctx);
      log.debug("Leaving report.retention run().");
      return Promise.resolve(out);
    }
  });
  schedulerMod.register({
    id: 'report.schedule',
    title: 'Report schedules',
    describe: 'Enqueues a job for each due report definition, as its ' +
      'owner, while that owner can still run the query. Stored ' +
      'parameter defaults are used. A missing one keeps the slot.',
    owner: 'report/jobs.ts',
    kind: 'cluster',
    scope: 'realm',
    nice: 8,
    everyMs: reportEverySlow,
    onFront: ON_FRONT,
    run: function (ctx: any): Promise<any> {
      log.debug("Entering report.schedule run().");
      if (!reportClusterRuns()) {
        return reportSkipped('report.schedule run()');
      }
      const out = reportGateOne('schedule', ctx);
      log.debug("Leaving report.schedule run().");
      return Promise.resolve(out);
    }
  });
  schedulerMod.register({
    id: 'report.drain.here',
    title: 'Report jobs on this node',
    describe: 'The reporting node\'s copy of report.drain. It does ' +
      'nothing unless this process holds ops.reporting.',
    owner: 'report/jobs.ts',
    kind: 'per-process',
    scope: 'realm',
    quiet: true,
    nice: 10,
    everyMs: reportEveryDrain,
    run: function (ctx: any): Promise<any> {
      log.debug("Entering report.drain.here run().");
      if (!reportHereRuns()) {
        return reportSkipped('report.drain.here run()');
      }
      reportStampReporter();
      const out = reportGateOne('drain', ctx);
      log.debug("Leaving report.drain.here run().");
      return Promise.resolve(out);
    }
  });
  schedulerMod.register({
    id: 'report.retention.here',
    title: 'Report retention on this node',
    describe: 'The reporting node\'s copy of report.retention. It does ' +
      'nothing unless this process holds ops.reporting.',
    owner: 'report/jobs.ts',
    kind: 'per-process',
    scope: 'realm',
    quiet: true,
    nice: 12,
    everyMs: reportEverySlow,
    run: function (ctx: any): Promise<any> {
      log.debug("Entering report.retention.here run().");
      if (!reportHereRuns()) {
        return reportSkipped('report.retention.here run()');
      }
      reportStampReporter();
      const out = reportGateOne('retain', ctx);
      log.debug("Leaving report.retention.here run().");
      return Promise.resolve(out);
    }
  });
  schedulerMod.register({
    id: 'report.schedule.here',
    title: 'Report schedules on this node',
    describe: 'The reporting node\'s copy of report.schedule. It does ' +
      'nothing unless this process holds ops.reporting.',
    owner: 'report/jobs.ts',
    kind: 'per-process',
    scope: 'realm',
    quiet: true,
    nice: 8,
    everyMs: reportEverySlow,
    run: function (ctx: any): Promise<any> {
      log.debug("Entering report.schedule.here run().");
      if (!reportHereRuns()) {
        return reportSkipped('report.schedule.here run()');
      }
      reportStampReporter();
      const out = reportGateOne('schedule', ctx);
      log.debug("Leaving report.schedule.here run().");
      return Promise.resolve(out);
    }
  });
  log.debug("Leaving reportRegister().");
}

function reportOfferLease(): void {
  log.debug("Entering reportOfferLease().");
  if (process.env.STS_REPORT_NODE !== 'true') {
    log.debug("Leaving reportOfferLease(). Not opted in.");
    return;
  }
  const cluster = require('../cluster/cluster');
  cluster.lead('ops.reporting', {
    onGain: function (): void {
      reportStampReporter();
    },
    onLose: function (): void {
      sources.clearReporter();
    }
  });
  log.debug("Leaving reportOfferLease().");
}

reportRegister();
reportOfferLease();

export = {
  submit: reportSubmit,
  scheduleTimes: reportScheduleTimes,
  save: reportSave,
  share: reportShare,
  remove: reportRemove,
  cancel: reportCancel,
  jobView: reportJobView,
  drainNow: reportDrainNow,
  retainNow: reportRetainNow,
  scheduleNow: reportScheduleNow,
  abandonFences: reportAbandonFences,
  iso: reportIso,
  parameterNames: reportParameterNames
};
