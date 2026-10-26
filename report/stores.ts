// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: stores.ts
//
// ---------------------------------------------------------------------------
// WHERE A REPORT LIVES (#956).
//
// A definition and a job are JSON rows on the realm's own map, the same
// shape every other realm-scoped register uses. The bytes of a finished
// report are not: they are an artifact, and an artifact is not a minted
// credential, so they do not go in `sts_minted`. The postgres driver keeps
// them in `sts_report_artifacts` when it has the three methods; a driver
// that does not — memory mode, and any store opened before the table
// existed — keeps them in a map in this process. The probe is the whole
// decision. Nothing is truncated to fit a column that is not there.
//
// The reporting node's heartbeat is one key, `reporter`, written on the
// default realm so a caller in another realm still sees the same stamp.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import realms = require('../common/realms');
import helpers = require('../common/helpers');

const log = bunyan.createLogger({ name: 'sts-report-stores' });

const definitions = realms.map({ persist: 'report.definitions' });
const jobs = realms.map({ persist: 'report.jobs' });
const control = realms.map({ persist: 'report.control' });

// Bytes, keyed by realm and job, when the driver has no artifact table.
const memoryArtifacts = new Map<string, any>();
let driver: any = null;

function reportCopy(value: any): any {
  log.debug("Entering reportCopy().");
  if (value == null) {
    log.debug("Leaving reportCopy(). Empty.");
    return value;
  }
  const copy = JSON.parse(JSON.stringify(value));
  log.debug("Leaving reportCopy().");
  return copy;
}

function reportList(store: any): any[] {
  log.debug("Entering reportList().");
  const out: any[] = [];
  store.forEach(function (value: any): void {
    if (value && typeof value === 'object') {
      out.push(reportCopy(value));
    }
  });
  log.debug("Leaving reportList().");
  return out;
}

function artifactKey(realm: string, jobId: string): string {
  log.debug("Entering artifactKey().");
  log.debug("Leaving artifactKey().");
  return realm + '\n' + jobId;
}

function reportRealm(): string {
  log.debug("Entering reportRealm().");
  log.debug("Leaving reportRealm().");
  return String(realms.currentId() || 'default');
}

/**
 * Takes the store `persistence.js` opened. A driver without the three
 * artifact methods leaves the bytes in this process.
 *
 * @param theDriver - the store's driver
 * @param activeMode - the store's mode
 */
function reportSetDriver(theDriver: any, activeMode: string): void {
  log.debug("Entering reportSetDriver(). mode=" + activeMode);
  const names = ['putReportArtifact', 'getReportArtifact',
    'deleteReportArtifact'];
  const complete = !!theDriver && names.every(function (name: string):
      boolean {
    return typeof theDriver[name] === 'function';
  });
  driver = complete ? theDriver : null;
  log.info('report: ' + (complete
    ? 'the ' + activeMode + ' store holds report artifacts.'
    : 'the ' + activeMode + ' store has no report artifact table; ' +
      'artifacts are held in this process.'));
  log.debug("Leaving reportSetDriver().");
}

/**
 * Gives the store back when `persistence.js` closes it. Bytes already held
 * in this process stay, so a test that never opened a driver still reads
 * what it wrote.
 */
function reportClearDriver(): void {
  log.debug("Entering reportClearDriver().");
  driver = null;
  log.debug("Leaving reportClearDriver().");
}

function reportPutDefinition(row: any): any {
  log.debug("Entering reportPutDefinition().");
  const copy = reportCopy(row);
  definitions.set(copy.id, copy);
  log.debug("Leaving reportPutDefinition().");
  return reportCopy(copy);
}

function reportGetDefinition(id: string): any {
  log.debug("Entering reportGetDefinition().");
  const found = definitions.get(id);
  log.debug("Leaving reportGetDefinition().");
  return found ? reportCopy(found) : null;
}

function reportListDefinitions(): any[] {
  log.debug("Entering reportListDefinitions().");
  const out = reportList(definitions);
  log.debug("Leaving reportListDefinitions().");
  return out;
}

function reportDeleteDefinition(id: string): void {
  log.debug("Entering reportDeleteDefinition().");
  definitions.delete(id);
  log.debug("Leaving reportDeleteDefinition().");
}

function reportPutJob(row: any): any {
  log.debug("Entering reportPutJob().");
  const copy = reportCopy(row);
  jobs.set(copy.id, copy);
  log.debug("Leaving reportPutJob().");
  return reportCopy(copy);
}

function reportGetJob(id: string): any {
  log.debug("Entering reportGetJob().");
  const found = jobs.get(id);
  log.debug("Leaving reportGetJob().");
  return found ? reportCopy(found) : null;
}

function reportListJobs(): any[] {
  log.debug("Entering reportListJobs().");
  const out = reportList(jobs);
  log.debug("Leaving reportListJobs().");
  return out;
}

function reportDeleteJob(id: string): void {
  log.debug("Entering reportDeleteJob().");
  jobs.delete(id);
  log.debug("Leaving reportDeleteJob().");
}

function reportControlGet(key: string): any {
  log.debug("Entering reportControlGet().");
  const found = control.get(key);
  log.debug("Leaving reportControlGet().");
  return found ? reportCopy(found) : null;
}

function reportControlSet(key: string, value: any): void {
  log.debug("Entering reportControlSet().");
  control.set(key, reportCopy(value));
  log.debug("Leaving reportControlSet().");
}

function reportControlDelete(key: string): void {
  log.debug("Entering reportControlDelete().");
  control.delete(key);
  log.debug("Leaving reportControlDelete().");
}

function reportPutArtifact(jobId: string, bytes: Buffer, sha256: string,
                           mediaType: string): Promise<void> {
  log.debug("Entering reportPutArtifact().");
  const realm = reportRealm();
  const createdAt = Date.now();
  const row = {
    realm: realm,
    jobId: jobId,
    bytes: bytes,
    sha256: sha256,
    mediaType: mediaType,
    createdAt: createdAt
  };
  let out: Promise<void>;
  if (driver) {
    out = Promise.resolve(driver.putReportArtifact(row)).then(function ():
        void {
      log.debug("Leaving reportPutArtifact(). Stored.");
    });
  } else {
    memoryArtifacts.set(artifactKey(realm, jobId), {
      bytes: Buffer.from(bytes),
      sha256: sha256,
      mediaType: mediaType,
      createdAt: createdAt
    });
    log.debug("Leaving reportPutArtifact(). Memory.");
    out = Promise.resolve();
  }
  return out;
}

function reportGetArtifact(jobId: string): Promise<any> {
  log.debug("Entering reportGetArtifact().");
  const realm = reportRealm();
  if (!driver) {
    const found = memoryArtifacts.get(artifactKey(realm, jobId)) || null;
    log.debug("Leaving reportGetArtifact(). Memory.");
    return Promise.resolve(found ? {
      bytes: Buffer.from(found.bytes),
      sha256: found.sha256,
      mediaType: found.mediaType,
      createdAt: found.createdAt
    } : null);
  }
  return Promise.resolve(driver.getReportArtifact({
    realm: realm,
    jobId: jobId
  })).then(function (found: any): any {
    log.debug("Leaving reportGetArtifact(). Stored.");
    if (!found) {
      return null;
    }
    return {
      bytes: Buffer.from(found.bytes),
      sha256: found.sha256,
      mediaType: found.mediaType,
      createdAt: Number(found.createdAt)
    };
  });
}

function reportDeleteArtifact(jobId: string): Promise<void> {
  log.debug("Entering reportDeleteArtifact().");
  const realm = reportRealm();
  memoryArtifacts.delete(artifactKey(realm, jobId));
  if (!driver) {
    log.debug("Leaving reportDeleteArtifact(). Memory.");
    return Promise.resolve();
  }
  return Promise.resolve(driver.deleteReportArtifact({
    realm: realm,
    jobId: jobId
  })).then(function (): void {
    log.debug("Leaving reportDeleteArtifact(). Stored.");
  });
}

/**
 * A new id. The same generator every other register uses, so a job id is
 * not a guessable counter.
 *
 * @returns the id
 */
function reportNewId(): string {
  log.debug("Entering reportNewId().");
  const id = helpers.randomId(18);
  log.debug("Leaving reportNewId().");
  return id;
}

/**
 * Drops this realm's definitions, jobs and artifacts. For tests.
 */
function reportResetForTests(): void {
  log.debug("Entering reportResetForTests().");
  const realm = reportRealm();
  definitions.clear();
  jobs.clear();
  control.clear();
  Array.from(memoryArtifacts.keys()).forEach(function (key: string): void {
    if (key.indexOf(realm + '\n') === 0) {
      memoryArtifacts.delete(key);
    }
  });
  log.debug("Leaving reportResetForTests().");
}

export = {
  setDriver: reportSetDriver,
  clearDriver: reportClearDriver,
  putDefinition: reportPutDefinition,
  getDefinition: reportGetDefinition,
  listDefinitions: reportListDefinitions,
  deleteDefinition: reportDeleteDefinition,
  putJob: reportPutJob,
  getJob: reportGetJob,
  listJobs: reportListJobs,
  deleteJob: reportDeleteJob,
  controlGet: reportControlGet,
  controlSet: reportControlSet,
  controlDelete: reportControlDelete,
  putArtifact: reportPutArtifact,
  getArtifact: reportGetArtifact,
  deleteArtifact: reportDeleteArtifact,
  newId: reportNewId,
  resetForTests: reportResetForTests,
  copy: reportCopy
};
