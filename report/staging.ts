// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: staging.ts
//
// ---------------------------------------------------------------------------
// A REPORT IS BUILT ON DISK, NOT IN MEMORY (#1045, rcbj: "large data sets
// will eat up too much memory").
//
// Until #1045 a finished job's body was one Buffer. It was then copied as
// base64, as a sealed envelope and as that envelope's bytes, and written as
// one row. A report at the 32 MB cap was several copies of itself in the
// heap of the process running `report.drain`. Now:
//
//   1. **THE STAGING DIRECTORY IS THE RISK UPLOADS'**
//      (`common/staging_directory.ts`, `risk.uploadDirectory`). A
//      deployment mounts one volume for temporary files and sizes it once.
//      The cloud cluster gives a node 10 GB.
//   2. **ROOM IS ASKED FOR FIRST.** The job's byte cap plus the reserve an
//      upload keeps must be free (statfs) before the file is opened, or
//      the job fails (STS-REPORT-0049). A directory that cannot be made
//      or written fails it too (STS-REPORT-0050), as does a write that
//      fails part-way: ENOSPC from a disk another writer filled.
//   3. **THE RENDER IS STREAMED INTO THE FILE**, hashed on the way, in
//      pieces of PIECE_BYTES. The byte cap stops the render where it is
//      passed rather than after the whole body exists.
//   4. **THE FILE IS STORED IN SEALED PIECES OF THE SAME SIZE**, read back
//      from disk a piece at a time (`report/stores.ts`).
//   5. **THE FILE IS DELETED WHEN THE JOB ENDS**, however it ends
//      (`sources.ts`' `reportRunOne()`, in a `finally`).
//   6. **A CRASH'S LEFTOVERS ARE A SCHEDULER JOB'S**, not a timer's:
//      `report.build-cleanup`, per process and quiet, on
//      `risk.uploadSweepS`, in the shape of `risk.upload-cleanup`. It
//      touches the files this process holds. It removes this process's
//      own files that are no longer held, and another process's files
//      untouched for `report.asyncMaxMs` plus STALE_GRACE_MS. It never
//      touches a file whose name is not a report build's, because the
//      directory may be a volume an operator also uses.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import fs = require('fs');
import path = require('path');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import StagingDirectory = require('../common/staging_directory');
import Limits = require('./limits');

const log = bunyan.createLogger({ name: 'sts-report-staging' });

/**
 * This process's mark on the build files it writes, so the clean-up job
 * can tell its files from another process's.
 */
const PROCESS_TAG = String(process.pid) + 'x' +
  stsCrypto.randomBytes(4).toString('hex');
const FILE_NAME = /^report-build-([a-z0-9]+)-[0-9a-f-]{36}\.part$/;

/** The id of the per-process build-file clean-up job. */
const CLEANUP_JOB = 'report.build-cleanup';

// A write to the file, and a piece of the stored artifact, in bytes. One
// MiB keeps a 32 MB report to thirty-odd rows and the heap to a piece or
// two whatever the report's size.
const PIECE_BYTES = 1024 * 1024;

// Beyond the longest a job may run: what a live build cannot reach before
// it is touched again, so only a stopped process's file grows this old.
const STALE_GRACE_MS = 15 * 60 * 1000;

// The files this process is writing or storing now, by path.
const held = new Set<string>();

interface OpenOptions {
  // For tests: the directory's free bytes, in place of statfs.
  freeBytes?: (dir: string) => Promise<number>;
}

type Opened = { ok: true; file: StagedReport } |
  { ok: false; code: string; error: string; description: string };

/**
 * One report being built: a file in the staging directory this process
 * holds until `remove()`.
 */
class StagedReport {
  /** The file's path. */
  readonly path: string;
  /** The byte cap the render may not pass. */
  readonly cap: number;
  private handle: fs.promises.FileHandle | null;
  private readonly digest: any;
  private pending: Buffer[] = [];
  private pendingBytes = 0;
  private written = 0;
  private done = false;

  constructor(file: string, handle: fs.promises.FileHandle, cap: number) {
    log.debug("Entering StagedReport.constructor().");
    this.path = file;
    this.handle = handle;
    this.cap = cap;
    this.digest = stsCrypto.sha256Digester();
    log.debug("Leaving StagedReport.constructor().");
  }

  /** Bytes produced so far, written or waiting. */
  get bytes(): number {
    return this.written + this.pendingBytes;
  }

  // A HOT PATH: one call per row of a report. No Entering/Leaving pair —
  // a hundred thousand rows would drown the log.
  /**
   * Adds text to the file. Resolves false, writing nothing more, once the
   * cap is passed; the caller refuses the report.
   *
   * @param text - the next piece of the rendered report
   * @returns whether the report is still within its cap
   */
  async write(text: string): Promise<boolean> {
    const chunk = Buffer.from(text, 'utf8');
    if (this.bytes + chunk.length > this.cap) {
      this.pending = [];
      this.pendingBytes = 0;
      return false;
    }
    this.digest.update(chunk);
    this.pending.push(chunk);
    this.pendingBytes += chunk.length;
    if (this.pendingBytes >= PIECE_BYTES) {
      await this.flushPending();
    }
    return true;
  }

  // What is waiting, to the file.
  private async flushPending(): Promise<void> {
    log.debug("Entering StagedReport.flushPending().");
    if (!this.pendingBytes || !this.handle) {
      log.debug("Leaving StagedReport.flushPending(). Nothing.");
      return;
    }
    const chunk = Buffer.concat(this.pending, this.pendingBytes);
    this.pending = [];
    this.pendingBytes = 0;
    await this.handle.write(chunk, 0, chunk.length, null);
    this.written += chunk.length;
    log.debug("Leaving StagedReport.flushPending().");
  }

  /**
   * Writes what is waiting and closes the file.
   *
   * @returns the size and the SHA-256 of what was written
   */
  async finish(): Promise<{ bytes: number; sha256: string }> {
    log.debug("Entering StagedReport.finish().");
    await this.flushPending();
    if (this.handle) {
      const handle = this.handle;
      this.handle = null;
      await handle.close();
    }
    this.done = true;
    log.debug("Leaving StagedReport.finish(). " + this.written + " bytes.");
    return { bytes: this.written, sha256: this.digest.hex() };
  }

  /**
   * The finished file a piece at a time, PIECE_BYTES each but the last.
   *
   * @returns the pieces, in order
   */
  async *pieces(): AsyncGenerator<Buffer> {
    log.debug("Entering StagedReport.pieces().");
    if (!this.done) {
      throw new Error('The report file is not finished.');
    }
    const handle = await fs.promises.open(this.path, 'r');
    try {
      const buffer = Buffer.alloc(PIECE_BYTES);
      for (;;) {
        const read = await handle.read(buffer, 0, PIECE_BYTES, null);
        if (!read.bytesRead) {
          break;
        }
        yield Buffer.from(buffer.subarray(0, read.bytesRead));
      }
    } finally {
      await handle.close();
    }
    log.debug("Leaving StagedReport.pieces().");
  }

  /**
   * The finished file, whole. Only where nothing smaller can take it: a
   * process with no database holds its reports in memory anyway.
   *
   * @returns the bytes
   */
  async whole(): Promise<Buffer> {
    log.debug("Entering StagedReport.whole().");
    const bytes = await fs.promises.readFile(this.path);
    log.debug("Leaving StagedReport.whole().");
    return bytes;
  }

  /**
   * Closes the file if it is open and deletes it. Never rejects: a file
   * that will not go is logged, and the clean-up job tries again.
   */
  async remove(): Promise<void> {
    log.debug("Entering StagedReport.remove().");
    this.pending = [];
    this.pendingBytes = 0;
    if (this.handle) {
      const handle = this.handle;
      this.handle = null;
      await handle.close().catch(function (e: any): void {
        log.debug("Caught closing a report build file: " +
          ((e && e.message) || e));
        // Closed or broken already; the removal below is what matters.
      });
    }
    const file = this.path;
    await fs.promises.rm(file, { force: true }).catch(function (e: any):
        void {
      log.warn(errorCodes.tag('STS-REPORT-0052') + 'report: the build ' +
        'file ' + path.basename(file) + ' could not be removed; the ' +
        CLEANUP_JOB + ' job will try again: ' + ((e && e.message) || e));
    });
    held.delete(file);
    log.debug("Leaving StagedReport.remove().");
  }
}

/**
 * Where a report is built before it is stored, and the clean-up job.
 *
 * A static utility class over the process's set of held files.
 */
class ReportStaging {
  static readonly PROCESS_TAG = PROCESS_TAG;
  static readonly FILE_NAME = FILE_NAME;
  static readonly CLEANUP_JOB = CLEANUP_JOB;
  static readonly PIECE_BYTES = PIECE_BYTES;
  static readonly STALE_GRACE_MS = STALE_GRACE_MS;

  /**
   * The staging directory, resolved.
   *
   * @returns the absolute path
   */
  static directory(): string {
    log.debug("Entering ReportStaging.directory().");
    const dir = StagingDirectory.directory(config);
    log.debug("Leaving ReportStaging.directory().");
    return dir;
  }

  /**
   * Opens a new build file once the directory is known to be writable and
   * to have room for the cap and the reserve.
   *
   * @param cap - the most the report may be, in bytes
   * @param options - test seams
   * @returns the open file, or a refusal with its code
   */
  static async open(cap: number, options?: OpenOptions): Promise<Opened> {
    log.debug("Entering ReportStaging.open().");
    const dir = ReportStaging.directory();
    try {
      await StagingDirectory.prepare(dir);
    } catch (e: any) {
      log.error(errorCodes.tag('STS-REPORT-0050') + 'report: the staging ' +
        'directory ' + dir + ' (risk.uploadDirectory) cannot be written: ' +
        ((e && e.message) || e));
      log.debug("Leaving ReportStaging.open(). Directory.");
      return ReportStaging.unwritable(e);
    }
    const need = cap + StagingDirectory.RESERVE_BYTES;
    const reading = options && options.freeBytes ? options.freeBytes :
      StagingDirectory.freeBytes;
    let free = -1;
    try {
      free = await reading(dir);
    } catch (e: any) {
      log.debug("Caught in ReportStaging.open(): " + ((e && e.message) || e));
      // A filesystem that will not say how full it is: the render is
      // still bounded by the cap, and a disk that fills fails the write
      // (STS-REPORT-0050), so the build goes on rather than be refused on
      // a guess — the risk upload's rule.
      free = -1;
    }
    if (free >= 0 && free < need) {
      log.warn(errorCodes.tag('STS-REPORT-0049') + 'report: a job was ' +
        'refused room to build: ' + dir + ' has ' + free + ' bytes free ' +
        'and a report of up to ' + cap + ' bytes needs ' + need + '.');
      log.debug("Leaving ReportStaging.open(). No room.");
      return {
        ok: false,
        code: 'STS-REPORT-0049',
        error: 'unavailable',
        description: 'There is no room to build the report now. Try ' +
          'again later.'
      };
    }
    const file = path.join(dir, 'report-build-' + PROCESS_TAG + '-' +
      stsCrypto.randomUuid() + '.part');
    let handle: fs.promises.FileHandle;
    try {
      handle = await fs.promises.open(file, 'wx', 0o600);
    } catch (e: any) {
      log.error(errorCodes.tag('STS-REPORT-0050') + 'report: a build file ' +
        'could not be created in ' + dir + ': ' + ((e && e.message) || e));
      log.debug("Leaving ReportStaging.open(). Not created.");
      return ReportStaging.unwritable(e);
    }
    held.add(file);
    log.debug("Leaving ReportStaging.open().");
    return { ok: true, file: new StagedReport(file, handle, cap) };
  }

  /**
   * The refusal for a directory or a file that cannot be written.
   *
   * @param e - what the filesystem said, for the log only
   * @returns the refusal
   */
  static unwritable(e?: any): Opened & { ok: false } {
    log.debug("Entering ReportStaging.unwritable(). " +
      String((e && e.code) || ''));
    log.debug("Leaving ReportStaging.unwritable().");
    return {
      ok: false,
      code: 'STS-REPORT-0050',
      error: 'unavailable',
      description: 'The report could not be built now. Try again later.'
    };
  }

  /**
   * The files this process holds, for tests and the clean-up job.
   *
   * @returns the paths
   */
  static heldFiles(): string[] {
    log.debug("Entering ReportStaging.heldFiles().");
    log.debug("Leaving ReportStaging.heldFiles().");
    return Array.from(held);
  }

  /**
   * Runs the per-process clean-up: touches the files this process holds
   * and removes leftover builds — this process's that it no longer holds,
   * and another's untouched for `report.asyncMaxMs` plus the grace.
   *
   * @param nowMs - the instant, for tests
   * @returns `{ held, removed }`
   */
  static async sweep(nowMs?: number): Promise<{ held: number;
      removed: number }> {
    log.debug("Entering ReportStaging.sweep().");
    const dir = ReportStaging.directory();
    const out = { held: 0, removed: 0 };
    let names: string[] = [];
    try {
      names = await fs.promises.readdir(dir);
    } catch (e: any) {
      log.debug("Caught in ReportStaging.sweep(): " + ((e && e.message) || e));
      // No directory yet: nothing was ever built here.
      log.debug("Leaving ReportStaging.sweep(). No directory.");
      return out;
    }
    const at = nowMs === undefined ? Date.now() : nowMs;
    const staleMs = new Limits().asyncMaxMs() + STALE_GRACE_MS;
    for (const name of names) {
      const m = FILE_NAME.exec(name);
      if (!m) {
        continue;
      }
      const file = path.join(dir, name);
      if (held.has(file)) {
        out.held += 1;
        await fs.promises.utimes(file, at / 1000, at / 1000)
          .catch(function (e: any): void {
            log.debug("Caught touching a held report build: " +
              ((e && e.message) || e));
            // Touched again at the next run; a file a job is writing is
            // never removed by its own process in any case.
          });
        continue;
      }
      let old = m[1] === PROCESS_TAG;
      if (!old) {
        const st = await fs.promises.stat(file).catch(function (e: any):
            null {
          log.debug("Caught reading a report build's age: " +
            ((e && e.message) || e));
          // Gone already — another process's sweep, or its own job.
          return null;
        });
        old = !!st && at - st.mtimeMs > staleMs;
      }
      if (!old) {
        continue;
      }
      const removed = await fs.promises.rm(file, { force: true })
        .then(function (): boolean {
          return true;
        }, function (e: any): boolean {
          log.warn(errorCodes.tag('STS-REPORT-0052') + 'report: a ' +
            'leftover build ' + name + ' could not be removed: ' +
            ((e && e.message) || e));
          return false;
        });
      if (removed) {
        out.removed += 1;
        log.warn(errorCodes.tag('STS-REPORT-0052') + 'report: removed the ' +
          'leftover build ' + name + ', which ' +
          (m[1] === PROCESS_TAG ? 'this process no longer holds' :
            'no live process has touched for report.asyncMaxMs and ' +
            'fifteen minutes') + '.');
      }
    }
    log.debug("Leaving ReportStaging.sweep(). " + out.removed + " removed.");
    return out;
  }

  /**
   * Registers the per-process clean-up job with the scheduler.
   *
   * @param scheduler - the scheduler module
   * @returns true when it was registered, false when there was nothing to do
   */
  static registerJobs(scheduler: any): boolean {
    log.debug("Entering ReportStaging.registerJobs().");
    if (!scheduler || typeof scheduler.register !== 'function' ||
        scheduler.job(CLEANUP_JOB)) {
      log.debug("Leaving ReportStaging.registerJobs(). Nothing to do.");
      return false;
    }
    scheduler.register({
      id: CLEANUP_JOB,
      title: 'Report build clean-up',
      describe: 'In every process: keeps the report files this process is ' +
        'building fresh, and deletes from risk.uploadDirectory a report ' +
        'build no live process has touched for report.asyncMaxMs and ' +
        'fifteen minutes — what a process that stopped mid-build left ' +
        'behind.',
      owner: 'report/staging.ts',
      kind: 'per-process', quiet: true,
      everySetting: 'risk.uploadSweepS', everySettingUnit: 's',
      manual: true,
      run: function (): Promise<any> {
        return ReportStaging.sweep();
      }
    });
    log.debug("Leaving ReportStaging.registerJobs().");
    return true;
  }
}

export = { ReportStaging: ReportStaging, StagedReport: StagedReport };
