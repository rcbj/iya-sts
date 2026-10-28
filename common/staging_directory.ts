// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: staging_directory.ts
//
// ---------------------------------------------------------------------------
// THE ONE DIRECTORY A FILE IS STAGED IN BEFORE IT REACHES THE DATABASE
// (#1045, rcbj).
//
// Two things write a file to local disk on the way to the store: an
// uploaded risk dataset (`risk/risk_upload.ts`, #215) and a report being
// built (`report/staging.ts`, #1045). Both go to the directory
// `risk.uploadDirectory` names, so that a deployment mounts ONE volume for
// temporary files and sizes it once. The cloud cluster gives a node 10 GB.
// The setting kept its name: renaming it would break every deployment that
// sets it.
//
// What is shared is the resolution, the free-space reserve, the check
// that the directory can be written, and the free-space reading. What is
// NOT shared is the files themselves. Each user names its own files and
// sweeps only those, since the directory may be a volume an operator also
// uses.
//
// A STATIC UTILITY CLASS (rcbj's rule on #50): no state, no dependencies to
// build. It lives in `common/` and requires only `config`, so `report/` can
// reach it without requiring `risk/`. A risk library required before the
// composition root builds it is the trap `risk/CLAUDE.md` describes.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import fs = require('fs');
import path = require('path');
import config = require('./config');

const log = bunyan.createLogger({ name: 'sts-staging-directory' });

// The package root, which a relative directory is resolved against — as
// `persistence.dataDir` is, for its reason: the working directory is
// whatever the process was started in.
const ROOT = path.join(__dirname, '..');

// The setting's own default, should the setting answer nothing.
const DEFAULT_DIRECTORY = './data/risk-uploads';

// Free space the directory must keep beyond the file itself: a disk left
// with nothing is a disk the next log line cannot be written to.
const RESERVE_BYTES = 16 * 1024 * 1024;

/**
 * Where a file is staged on its way to the store, and whether it fits.
 *
 * A static utility class; it holds no state.
 */
export = class StagingDirectory {
  /** Free space kept beyond the file itself, in bytes. */
  static readonly RESERVE_BYTES = RESERVE_BYTES;

  /**
   * Returns the staging directory, resolved against the package root.
   *
   * @param reader - a settings reader with `value(key)`; `config` when absent
   * @returns the absolute path
   */
  static directory(reader?: { value(key: string): unknown }): string {
    log.debug("Entering StagingDirectory.directory().");
    const settings = reader || config;
    const dir = String(settings.value('risk.uploadDirectory') || '');
    log.debug("Leaving StagingDirectory.directory().");
    return path.resolve(ROOT, dir || DEFAULT_DIRECTORY);
  }

  /**
   * Makes the directory (owner only) if it is missing and checks that this
   * process may write to it. Rejects with the filesystem's error otherwise.
   *
   * @param dir - the resolved directory
   */
  static async prepare(dir: string): Promise<void> {
    log.debug("Entering StagingDirectory.prepare().");
    await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
    await fs.promises.access(dir, fs.constants.W_OK);
    log.debug("Leaving StagingDirectory.prepare().");
  }

  /**
   * The directory's free bytes, as an unprivileged writer may use them:
   * `statfs()`'s `bavail * bsize`.
   *
   * @param dir - the resolved directory
   * @returns the free bytes
   */
  static async freeBytes(dir: string): Promise<number> {
    log.debug("Entering StagingDirectory.freeBytes().");
    const s: any = await fs.promises.statfs(dir);
    log.debug("Leaving StagingDirectory.freeBytes().");
    return Number(s.bavail) * Number(s.bsize);
  }
};
