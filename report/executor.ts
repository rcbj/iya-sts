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
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import errorCodes = require('../common/error_codes');
import Formats = require('./formats');

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

export = {
  finish: reportFinish,
  mediaOf: mediaOf
};
