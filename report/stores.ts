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
//
// SINCE #1045 A JOB'S ARTIFACT IS STORED IN PIECES. It comes from a build
// file in the staging directory (`staging.ts`), read a piece at a time.
// Each piece is sealed on its own and written in one transaction to
// `sts_report_artifact_pieces`, when the driver has the two piece methods.
// The `sts_report_artifacts` row then holds a marker naming the count and
// the size. A download opens the pieces one at a time (`openArtifact()`),
// so no step holds more than a piece or two of a report. A row written
// before #1045 holds the whole body, sealed or in the clear. It is still
// read, as one piece, until its retention ends: no migration, by rcbj's
// rule for 8081.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import realms = require('../common/realms');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import Staging = require('./staging');

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

// A FINISHED REPORT IS STORED SEALED (#1033, rcbj: "reports need to be
// stored encrypted"). A report can list people, their credentials and
// their groups, so its bytes are sealed exactly as the minted stores' rows
// are: `keystore.seal()` under the realm's data key of class
// `report-artifact`, itself wrapped under the key-encryption key, which
// never reaches the database. The column is `bytea`, so the sealed envelope
// (`$aesgcm$2$…`, text) is stored as its UTF-8 bytes; the base64 of the
// report is what is sealed. Without a key-encryption key nothing can be
// sealed, and the report is REFUSED rather than written in the clear
// (STS-REPORT-0042); the job fails and says so. The copy a process keeps
// in memory when no database is attached is never written anywhere.
const SEALED_LABEL = 'report-artifact';
const SEALED_PREFIX = '$aesgcm$';

function reportSealBytes(bytes: Buffer): Buffer | null {
  log.debug("Entering reportSealBytes().");
  const keystore = require('../common/keystore');
  if (!keystore.sealed()) {
    log.debug("Leaving reportSealBytes(). No key-encryption key.");
    return null;
  }
  const sealed = keystore.seal(Buffer.from(bytes).toString('base64'),
    SEALED_LABEL);
  log.debug("Leaving reportSealBytes(). " + (sealed ? 'sealed' : 'refused'));
  return sealed ? Buffer.from(String(sealed), 'utf8') : null;
}

// The report's bytes from a stored row: opened when sealed; null when the
// envelope will not open under the keys this process holds.
function reportOpenBytes(stored: any): Buffer | null {
  log.debug("Entering reportOpenBytes().");
  const raw = Buffer.from(stored);
  const head = raw.subarray(0, SEALED_PREFIX.length).toString('utf8');
  if (head !== SEALED_PREFIX) {
    // A row written before #1033: in the clear until its retention ends.
    log.debug("Leaving reportOpenBytes(). Not sealed.");
    return raw;
  }
  const keystore = require('../common/keystore');
  const opened = keystore.open(raw.toString('utf8'), SEALED_LABEL);
  if (opened === null || opened === undefined) {
    log.error(errorCodes.tag('STS-REPORT-0043') +
      'report: a stored report would not open under the keys this ' +
      'process holds; it is answered as gone.');
    log.debug("Leaving reportOpenBytes(). Would not open.");
    return null;
  }
  log.debug("Leaving reportOpenBytes(). Opened.");
  return Buffer.from(String(opened), 'base64');
}

// THE MARKER A PIECED ARTIFACT'S ROW HOLDS (#1045): the piece count and
// the size, in the clear, because neither says anything about what the
// report lists. A sealed body starts `$aesgcm$`, a clear one (before
// #1033) with the report itself, which no format starts with `$pieces$`.
const PIECES_PREFIX = '$pieces$1:';

// A piece names its job and its place: the plaintext sealed is
// `{"j":<job>,"s":<number>,"b":<base64>}`. A piece moved to another job's
// rows, or to another place in its own, opens and is refused.
function reportSealPiece(jobId: string, seq: number, bytes: Buffer):
    Buffer | null {
  log.debug("Entering reportSealPiece().");
  const keystore = require('../common/keystore');
  if (!keystore.sealed()) {
    log.debug("Leaving reportSealPiece(). No key-encryption key.");
    return null;
  }
  const sealed = keystore.seal(JSON.stringify({ j: jobId, s: seq,
    b: bytes.toString('base64') }), SEALED_LABEL);
  log.debug("Leaving reportSealPiece().");
  return sealed ? Buffer.from(String(sealed), 'utf8') : null;
}

function reportOpenPiece(jobId: string, seq: number, stored: any): Buffer {
  log.debug("Entering reportOpenPiece().");
  const keystore = require('../common/keystore');
  const opened = stored ? keystore.open(Buffer.from(stored).toString('utf8'),
    SEALED_LABEL) : null;
  let piece: any = null;
  try {
    piece = opened === null || opened === undefined ? null :
      JSON.parse(String(opened));
  } catch (e: any) {
    log.debug("Caught in reportOpenPiece(): " + ((e && e.message) || e));
    // Not a piece's plaintext: refused below like any other.
    piece = null;
  }
  if (!piece || piece.j !== jobId || piece.s !== seq ||
      typeof piece.b !== 'string') {
    const refused: any = new Error('A stored piece of the report is ' +
      'missing or would not open.');
    refused.code = 'STS-REPORT-0051';
    log.debug("Leaving reportOpenPiece(). Refused.");
    throw refused;
  }
  log.debug("Leaving reportOpenPiece().");
  return Buffer.from(piece.b, 'base64');
}

function reportPiecedDriver(): boolean {
  log.debug("Entering reportPiecedDriver().");
  const pieced = !!driver &&
    typeof driver.putReportArtifactPieces === 'function' &&
    typeof driver.getReportArtifactPiece === 'function';
  log.debug("Leaving reportPiecedDriver(). " + pieced);
  return pieced;
}

function reportNotSealed(): Error {
  log.debug("Entering reportNotSealed().");
  log.error(errorCodes.tag('STS-REPORT-0042') +
    'report: a finished report could not be sealed (no key-encryption ' +
    'key); it is not written in the clear.');
  const refused: any = new Error('The report could not be stored ' +
    'encrypted, so it was not stored.');
  refused.code = 'STS-REPORT-0042';
  log.debug("Leaving reportNotSealed().");
  return refused;
}

/**
 * Stores a finished build file (#1045). With a pieced driver it is read and
 * sealed a piece at a time; otherwise it is read whole, for the driver
 * without the piece methods and for the memory map. The file stays the
 * caller's to remove.
 *
 * @param jobId - the job
 * @param file - the finished build file
 * @param sha256 - its digest
 * @param mediaType - its media type
 */
async function reportPutArtifactFile(jobId: string,
    file: InstanceType<typeof Staging.StagedReport>, sha256: string,
    mediaType: string): Promise<void> {
  log.debug("Entering reportPutArtifactFile().");
  if (!reportPiecedDriver()) {
    const whole = await file.whole();
    await reportPutArtifact(jobId, whole, sha256, mediaType);
    log.debug("Leaving reportPutArtifactFile(). Whole.");
    return;
  }
  const keystore = require('../common/keystore');
  if (!keystore.sealed()) {
    log.debug("Leaving reportPutArtifactFile(). Not sealed.");
    throw reportNotSealed();
  }
  const realm = reportRealm();
  const sealedPieces = async function* (): AsyncGenerator<Buffer> {
    log.debug("Entering sealedPieces().");
    let seq = 0;
    for await (const piece of file.pieces()) {
      const sealed = reportSealPiece(jobId, seq, piece);
      if (!sealed) {
        throw reportNotSealed();
      }
      seq += 1;
      yield sealed;
    }
    log.debug("Leaving sealedPieces(). " + seq + " pieces.");
  };
  await driver.putReportArtifactPieces({
    realm: realm,
    jobId: jobId,
    sha256: sha256,
    mediaType: mediaType,
    size: file.bytes,
    createdAt: Date.now(),
    prefix: PIECES_PREFIX
  }, sealedPieces());
  log.debug("Leaving reportPutArtifactFile(). Pieces.");
}

/**
 * A stored artifact, ready to be read a piece at a time (#1045): its digest,
 * its media type, its size where it is known, and `pieces()`, which opens
 * each in turn and throws (STS-REPORT-0051) on one that is missing or will
 * not open. Null when there is no artifact, or a whole one will not open.
 *
 * @param jobId - the job
 * @returns the artifact, or null
 */
async function reportOpenArtifact(jobId: string): Promise<any> {
  log.debug("Entering reportOpenArtifact().");
  const realm = reportRealm();
  const one = function (bytes: Buffer): () => AsyncGenerator<Buffer> {
    return async function* (): AsyncGenerator<Buffer> {
      yield bytes;
    };
  };
  if (!driver) {
    const found = memoryArtifacts.get(artifactKey(realm, jobId)) || null;
    log.debug("Leaving reportOpenArtifact(). Memory.");
    return found ? {
      sha256: found.sha256,
      mediaType: found.mediaType,
      createdAt: found.createdAt,
      size: found.bytes.length,
      pieces: one(Buffer.from(found.bytes))
    } : null;
  }
  const found = await driver.getReportArtifact({ realm: realm,
    jobId: jobId });
  if (!found) {
    log.debug("Leaving reportOpenArtifact(). None.");
    return null;
  }
  const raw = Buffer.from(found.bytes);
  const head = raw.subarray(0, PIECES_PREFIX.length).toString('utf8');
  if (head !== PIECES_PREFIX) {
    const opened = reportOpenBytes(raw);
    log.debug("Leaving reportOpenArtifact(). Whole.");
    return opened ? {
      sha256: found.sha256,
      mediaType: found.mediaType,
      createdAt: Number(found.createdAt),
      size: opened.length,
      pieces: one(opened)
    } : null;
  }
  const fields = raw.subarray(PIECES_PREFIX.length).toString('utf8')
    .split(':');
  const count = Number(fields[0]);
  const size = Number(fields[1]);
  if (!Number.isInteger(count) || count < 0 || !Number.isFinite(size) ||
      !reportPiecedDriver()) {
    log.error(errorCodes.tag('STS-REPORT-0051') + 'report: a stored ' +
      'report\'s piece marker cannot be read here; it is answered as gone.');
    log.debug("Leaving reportOpenArtifact(). Marker.");
    return null;
  }
  const reader = driver;
  log.debug("Leaving reportOpenArtifact(). " + count + " pieces.");
  return {
    sha256: found.sha256,
    mediaType: found.mediaType,
    createdAt: Number(found.createdAt),
    size: size,
    pieces: async function* (): AsyncGenerator<Buffer> {
      log.debug("Entering reportOpenArtifact().pieces().");
      for (let seq = 0; seq < count; seq++) {
        const stored = await reader.getReportArtifactPiece({ realm: realm,
          jobId: jobId, seq: seq });
        yield reportOpenPiece(jobId, seq, stored);
      }
      log.debug("Leaving reportOpenArtifact().pieces().");
    }
  };
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
    const sealed = reportSealBytes(bytes);
    if (!sealed) {
      log.debug("Leaving reportPutArtifact(). Not sealed.");
      return Promise.reject(reportNotSealed());
    }
    row.bytes = sealed;
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

/**
 * A stored artifact whole: `openArtifact()` with its pieces put together.
 * For tests and small reports; a download reads the pieces.
 *
 * @param jobId - the job
 * @returns `{ bytes, sha256, mediaType, createdAt }`, or null
 */
async function reportGetArtifact(jobId: string): Promise<any> {
  log.debug("Entering reportGetArtifact().");
  const opened = await reportOpenArtifact(jobId);
  if (!opened) {
    log.debug("Leaving reportGetArtifact(). None.");
    return null;
  }
  const parts: Buffer[] = [];
  try {
    for await (const piece of opened.pieces()) {
      parts.push(piece);
    }
  } catch (e: any) {
    log.debug("Caught in reportGetArtifact(): " + ((e && e.message) || e));
    // A piece missing or unopenable: answered as gone, as a whole row
    // that will not open is.
    log.error(errorCodes.tag('STS-REPORT-0051') + 'report: a stored ' +
      'report has a piece that is missing or would not open; it is ' +
      'answered as gone.');
    log.debug("Leaving reportGetArtifact(). A piece failed.");
    return null;
  }
  log.debug("Leaving reportGetArtifact().");
  return {
    bytes: Buffer.concat(parts),
    sha256: opened.sha256,
    mediaType: opened.mediaType,
    createdAt: opened.createdAt
  };
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
  putArtifactFile: reportPutArtifactFile,
  openArtifact: reportOpenArtifact,
  getArtifact: reportGetArtifact,
  deleteArtifact: reportDeleteArtifact,
  newId: reportNewId,
  resetForTests: reportResetForTests,
  copy: reportCopy
};
