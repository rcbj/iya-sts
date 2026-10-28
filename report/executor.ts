// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: executor.ts
//
// ---------------------------------------------------------------------------
// THE BYTES A FINISHED QUERY BECOMES (#956).
//
// The reader has already stopped at the limit. This step only renders, and
// it refuses rather than keeping a body that does not fit: a PDF past the
// page cap, or any format past the byte cap. The refusal names CSV when the
// PDF is what did not fit. Nothing here reads the directory.
//
// A JOB'S REPORT IS RENDERED INTO A FILE (#1045): `finishToFile()` streams
// the format's pieces into a build file in the staging directory
// (`staging.ts`) and stops where the byte cap is passed. The synchronous
// answer keeps `finish()`: it is at most `report.syncMaxBytes` and is
// written to the response, never stored.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import errorCodes = require('../common/error_codes');
import Formats = require('./formats');
import Staging = require('./staging');

const log = bunyan.createLogger({ name: 'sts-report-executor' });

function mediaOf(format: string): string {
  log.debug("Entering mediaOf().");
  let media = 'application/json';
  if (format === 'csv') {
    media = 'text/csv; charset=utf-8';
  } else if (format === 'pdf') {
    media = 'application/pdf';
  }
  log.debug("Leaving mediaOf().");
  return media;
}

/**
 * Renders rows the reader already accepted.
 *
 * @param plan - a plan `Query.validate` accepted
 * @param rows - the output rows
 * @param limits - the caps
 * @param meta - realm name and generation time, for the PDF header
 * @returns the body, or a refusal that keeps no bytes
 */
function reportFinish(plan: any, rows: any[], limits: any, meta: any): any {
  log.debug("Entering reportFinish().");
  const format = plan && plan.format ? plan.format : 'json';
  const cap = plan && plan.execution === 'sync' ?
    limits.syncMaxBytes() : limits.asyncMaxBytes();
  let body: Buffer;
  if (format === 'csv') {
    body = Formats.csv(plan, rows || []);
  } else if (format === 'pdf') {
    const pdf = Formats.pdf(plan, rows || [], meta || { realm: '',
      when: '' }, limits.pdfMaxPages());
    if (!pdf.ok) {
      log.warn(errorCodes.tag('STS-REPORT-0005') +
        'report: a PDF cannot hold this many pages. Ask for CSV.');
      log.debug("Leaving reportFinish(). Pages.");
      return {
        ok: false,
        code: 'STS-REPORT-0005',
        error: 'result_too_large',
        description: 'A PDF cannot hold this many pages. Ask for CSV.'
      };
    }
    body = pdf.body;
  } else {
    body = Formats.json(plan, rows || []);
  }
  if (body.length > cap) {
    log.warn(errorCodes.tag('STS-REPORT-0005') +
      'report: the result is above the byte cap.');
    log.debug("Leaving reportFinish(). Bytes.");
    return {
      ok: false,
      code: 'STS-REPORT-0005',
      error: 'result_too_large',
      description: 'The result is above the byte cap.'
    };
  }
  log.debug("Leaving reportFinish().");
  return { ok: true, body: body, media: mediaOf(format) };
}

function reportTooLarge(): any {
  log.debug("Entering reportTooLarge().");
  log.warn(errorCodes.tag('STS-REPORT-0005') +
    'report: the result is above the byte cap.');
  log.debug("Leaving reportTooLarge().");
  return {
    ok: false,
    code: 'STS-REPORT-0005',
    error: 'result_too_large',
    description: 'The result is above the byte cap.'
  };
}

/**
 * Renders a job's rows into a build file in the staging directory (#1045).
 * The file is the caller's to store and then remove; on a refusal it has
 * already been removed.
 *
 * @param plan - a plan `Query.validate` accepted
 * @param rows - the output rows
 * @param limits - the caps
 * @param meta - realm name and generation time, for the PDF header
 * @param options - the staging test seams
 * @returns `{ ok, file, bytes, sha256, media }`, or a refusal
 */
async function reportFinishToFile(plan: any, rows: any[], limits: any,
    meta: any, options?: any): Promise<any> {
  log.debug("Entering reportFinishToFile().");
  const format = plan && plan.format ? plan.format : 'json';
  let parts: Iterable<string>;
  if (format === 'csv') {
    parts = Formats.csvParts(plan, rows || []);
  } else if (format === 'pdf') {
    const pdf = Formats.pdfParts(plan, rows || [], meta || { realm: '',
      when: '' }, limits.pdfMaxPages());
    if (!('parts' in pdf)) {
      log.warn(errorCodes.tag('STS-REPORT-0005') +
        'report: a PDF cannot hold this many pages. Ask for CSV.');
      log.debug("Leaving reportFinishToFile(). Pages.");
      return {
        ok: false,
        code: 'STS-REPORT-0005',
        error: 'result_too_large',
        description: 'A PDF cannot hold this many pages. Ask for CSV.'
      };
    }
    parts = pdf.parts;
  } else {
    parts = Formats.jsonParts(plan, rows || []);
  }
  const opened = await Staging.ReportStaging.open(limits.asyncMaxBytes(),
    options);
  if (!opened.ok) {
    log.debug("Leaving reportFinishToFile(). No file.");
    return opened;
  }
  const file = opened.file;
  try {
    for (const part of parts) {
      if (!(await file.write(part))) {
        await file.remove();
        log.debug("Leaving reportFinishToFile(). Bytes.");
        return reportTooLarge();
      }
    }
    const done = await file.finish();
    log.debug("Leaving reportFinishToFile().");
    return { ok: true, file: file, bytes: done.bytes, sha256: done.sha256,
      media: mediaOf(format) };
  } catch (e: any) {
    // A WRITE THAT FAILED PART-WAY: ENOSPC from a disk another writer
    // filled, or the directory taken away. The job fails and says so; the
    // partial file goes with it.
    log.error(errorCodes.tag('STS-REPORT-0050') + 'report: a build file ' +
      'could not be written: ' + ((e && e.message) || e));
    await file.remove();
    log.debug("Leaving reportFinishToFile(). Write failed.");
    return Staging.ReportStaging.unwritable(e);
  }
}

export = {
  finish: reportFinish,
  finishToFile: reportFinishToFile,
  mediaOf: mediaOf
};
