#!/usr/bin/env node
// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model-gap-scan.js
//
// ---------------------------------------------------------------------------
// A MODEL GAP IN A SERVICE LOG FAILS THE MODE (#1579's review, 2026-11-13).
//
//   node tests/tools/model-gap-scan.js <service log> [<service log> ...]
//
// prints, for each log, every model-gap code it holds with how many times
// and its FIRST line, and exits 1 when any log holds one (or cannot be
// read), 0 when none does.
//
// #1579 brought every protocol family into the model, and rcbj accepted that
// the model HOLDS an answer rather than refusing it: a member the model does
// not name, a value of the wrong type, an error code it does not declare is
// logged under the family's code and the answer is sent as it was built
// (OAuth2Server.holdToModel(), XmlModel.hold(), GnapModel, SsfModel,
// SpiffeModel, AuthzenModel, the enrollment families). So the SERVICE never
// fails on a gap — and until this file nothing else did either: #1655
// shipped a GNAP model that logged STS-GNAP-0910 on every approval view, and
// every stack run stayed green until #1686 found it by reading a log. The
// service stays advisory (rcbj's decision); the HARNESS is where a gap is a
// failure. `./run-tests.sh` runs this over the service logs it captured for
// each mode (`modelGapCheck()`), and `tests/schema-validation/in-container.sh`
// over each stage's node logs.
//
// THE CODES ARE `MODEL_GAP_CODES`, BELOW, AND THE LIST IS HELD, NOT TRUSTED.
// `tests/model_gap_scan.js` derives the same set twice and fails on any
// difference: from `common/error_codes.js` (every code recorded only, whose
// summary names a `models/` file and #1579), and from the source (every
// `errorCodes.tag()` whose log line speaks of a model, and every literal code
// handed to an XML model's `hold()`). A new family's hold() site with a new
// code therefore fails that test until the code is listed here.
//
// ONLY THE TAG IS MATCHED: `[STS-…-NNNN]`, the form `errorCodes.tag()` puts
// at the front of a log line. A comment, an audit row's `errorCode` member or
// a sentence naming a code is not a gap and is not counted.
//
// A LEAF that requires only node's own modules, because the launcher runs it
// on the host after the stack is down. Its `log` is console-backed and goes
// to STDERR, so stdout is the report and nothing else.
// ---------------------------------------------------------------------------

const fs = require('fs');

var DEBUG = false;
var LOG_TAG = '[model-gap-scan]';
var log = {
  debug: function (...args) {
    if (!DEBUG) return;
    console.error(LOG_TAG, ...args);
  }
};

// Every code a model's holding records a gap under, in subsystem order. A
// code here is "the model describes the wire and does not reshape it, so
// this is a model gap to close" in its summary.
const MODEL_GAP_CODES = Object.freeze([
  'STS-ACME-0100',
  'STS-ACME-0101',
  'STS-EST-0037',
  'STS-OAUTH-1005',
  'STS-OAUTH-1006',
  'STS-SAML-0121',
  'STS-WSTRUST-0071',
  'STS-WSFED-0032',
  'STS-SPIFFE-0154',
  'STS-SPIFFE-0155',
  'STS-SSF-0159',
  'STS-SSF-0160',
  'STS-SSF-0161',
  'STS-SSF-0162',
  'STS-GNAP-0910',
  'STS-GNAP-0911',
  'STS-AUTHZEN-0116'
]);

// The longest line quoted for a first occurrence; a held SAML document's
// problems can make one very long.
const QUOTE_MAX = 400;

/**
 * The pattern a tagged log line carries for one of the codes.
 *
 * @param {ReadonlyArray<string>} codes - the codes
 * @returns {RegExp} `[CODE]` for any of them, global
 */
function tagPattern(codes) {
  log.debug("Entering tagPattern().");
  const alternatives = codes.map(function (code) {
    return code.replace(/[^A-Z0-9-]/g, '');
  }).join('|');
  log.debug("Leaving tagPattern().");
  return new RegExp('\\[(' + alternatives + ')\\]', 'g');
}

/**
 * Every model-gap code a log's text holds, each with its count and its first
 * line (1-based), ordered by that first line.
 *
 * @param {string} text - the log
 * @param {ReadonlyArray<string>} [codes] - the codes, MODEL_GAP_CODES by
 *   default
 * @returns {Array<{ code: string, count: number, line: number,
 *   text: string }>} the findings, empty when there is none
 */
function scanText(text, codes) {
  log.debug("Entering scanText().");
  const pattern = tagPattern(codes || MODEL_GAP_CODES);
  /** @type {Map<string, { code: string, count: number, line: number,
   *   text: string }>} */
  const found = new Map();
  const lines = String(text || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    pattern.lastIndex = 0;
    let m;
    while ((m = pattern.exec(lines[i])) !== null) {
      const code = m[1];
      const seen = found.get(code);
      if (seen) {
        seen.count += 1;
      } else {
        found.set(code, {
          code: code,
          count: 1,
          line: i + 1,
          text: lines[i].length > QUOTE_MAX ?
            lines[i].slice(0, QUOTE_MAX) + '…' : lines[i]
        });
      }
    }
  }
  const out = Array.from(found.values()).sort(function (a, b) {
    return a.line - b.line;
  });
  log.debug("Leaving scanText(). " + out.length);
  return out;
}

/**
 * Scans one log file.
 *
 * @param {string} file - its path
 * @returns {{ file: string, readable: boolean, problem: string,
 *   findings: ReturnType<typeof scanText> }} what it holds
 */
function scanFile(file) {
  log.debug("Entering scanFile(). " + file);
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    log.debug("Caught in scanFile(): " + ((e && e.message) || e));
    // A log that cannot be read is NOT a clean log: the check could not
    // run, and a check that could not run must not read as passed.
    log.debug("Leaving scanFile(). unreadable");
    return { file: file, readable: false,
             problem: String((e && e.message) || e), findings: [] };
  }
  const findings = scanText(text);
  log.debug("Leaving scanFile(). " + findings.length);
  return { file: file, readable: true, problem: '', findings: findings };
}

/**
 * The report for a set of scanned files, as lines, and whether it passes.
 *
 * @param {Array<ReturnType<typeof scanFile>>} results - each file's scan
 * @returns {{ ok: boolean, lines: string[] }} the verdict and its report
 */
function report(results) {
  log.debug("Entering report().");
  const lines = [];
  let ok = results.length > 0;
  if (results.length === 0) {
    lines.push('model gaps: no service log was named, so nothing was ' +
               'checked.');
  }
  results.forEach(function (one) {
    if (!one.readable) {
      ok = false;
      lines.push('model gaps: ' + one.file + ' could not be read (' +
                 one.problem + '), so it was not checked.');
      return;
    }
    if (one.findings.length === 0) {
      lines.push('model gaps: none in ' + one.file + '.');
      return;
    }
    ok = false;
    const total = one.findings.reduce(function (sum, f) {
      return sum + f.count;
    }, 0);
    lines.push('model gaps: ' + total + ' line(s) under ' +
               one.findings.length + ' code(s) in ' + one.file +
               ' — each is an answer that is not its model\'s (#1579):');
    one.findings.forEach(function (f) {
      lines.push('  ' + f.code + ' x' + f.count + ', first at line ' +
                 f.line + ': ' + f.text);
    });
  });
  log.debug("Leaving report(). " + ok);
  return { ok: ok, lines: lines };
}

/**
 * The command line: scan each named log, print the report, and answer the
 * exit status (0 clean, 1 a gap or a log that could not be read).
 *
 * @param {string[]} argv - the arguments after the script
 * @returns {number} the exit status
 */
function main(argv) {
  log.debug("Entering main().");
  const files = argv.filter(function (arg) {
    return arg !== '--debug';
  });
  if (argv.indexOf('--debug') >= 0) {
    DEBUG = true;
  }
  const verdict = report(files.map(scanFile));
  process.stdout.write(verdict.lines.join('\n') + '\n');
  log.debug("Leaving main().");
  return verdict.ok ? 0 : 1;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = {
  MODEL_GAP_CODES: MODEL_GAP_CODES,
  scanText: scanText,
  scanFile: scanFile,
  report: report,
  main: main
};
