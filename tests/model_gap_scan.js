// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: model_gap_scan.js
//
// ===========================================================================
// A MODEL GAP IN A SERVICE LOG FAILS A MODE, AND NO FAMILY'S CODE IS MISSED
// (#1579's review, 2026-11-13).
//
// The model HOLDS what the service answers and never refuses it (rcbj's
// decision on #1579), so a gap is a log line and nothing else; #1655 shipped
// a GNAP model that logged STS-GNAP-0910 on every approval view with every
// stack run green. `tests/tools/model-gap-scan.js` is what `./run-tests.sh`
// and the schema-validation container now run over each node's log. This
// file holds:
//
//   A. the scanner over sample logs — the bracketed tag of a listed code is a
//      finding with its count and first line; a code named any other way, or
//      a code that is not a gap, is not;
//   B. its command line — 0 for clean logs, 1 for a gap, an unreadable log
//      or no log at all, and what it prints;
//   C. MODEL_GAP_CODES against the error table: every code recorded only,
//      whose summary names a `models/` file and #1579, and no other;
//   D. MODEL_GAP_CODES against the SOURCE: every `errorCodes.tag()` whose log
//      statement speaks of a model, and every literal code handed to an XML
//      model's `hold()` — so a new family's holding site with a new code
//      fails here until the code is listed — less the named exceptions,
//      each of which must still be found;
//   E. the wiring, as source: the launcher runs the scan over every node log
//      it captured and fails the mode on it; the container's verdict does.
//
// WHY IN PROCESS: every claim is about files in this repository and a
// script's behaviour on logs this file writes, which no running service
// could be asked; running ./run-tests.sh to prove a check in it is the cost
// this file exists to avoid.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');

const scan = require('./tools/model-gap-scan');

const log = require('bunyan').createLogger({ name: 'model_gap_scan',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const TOOL = path.join(__dirname, 'tools', 'model-gap-scan.js');

// Codes a log statement that speaks of a model is tagged with that are NOT a
// protocol family's model gap. Each must still be found by section D, so a
// row here cannot outlive the line it excuses.
const NOT_A_GAP = {
  'STS-REG-0006': 'an attribute outside the application schema was not ' +
    'written; the line points at models/directory, and nothing was answered',
  'STS-CORE-0028': 'a realm\'s keys are still being made; the line names ' +
    'the hybrid-groups signer MODEL, a key arrangement, not the wire model',
  'STS-REPORT-0060': 'a report definition STORED before #1579 bounded it; ' +
    'stored data the service answers around, not an answer it built'
};

// The directories under the root a service source is never in.
const NOT_SOURCE = /^(node_modules|tests|docs|models|rust|deploy|types|apidocs|coverage|\.git|\.claude|debugger)$/;

/**
 * Every service source file: `.ts`, and `.js` where no `.ts` beside it was
 * compiled into it.
 *
 * @returns {string[]} absolute paths
 */
function sourceFiles() {
  log.debug("Entering sourceFiles().");
  const out = [];
  const walk = function (dir, top) {
    fs.readdirSync(dir).forEach(function (name) {
      if (top && NOT_SOURCE.test(name)) {
        return;
      }
      if (name === 'node_modules' || name.startsWith('.')) {
        return;
      }
      const full = path.join(dir, name);
      const stat = fs.lstatSync(full);
      if (stat.isSymbolicLink()) {
        return;
      }
      if (stat.isDirectory()) {
        walk(full, false);
        return;
      }
      if (/\.d\.ts$/.test(name)) {
        return;
      }
      if (/\.ts$/.test(name)) {
        out.push(full);
        return;
      }
      if (/\.js$/.test(name) &&
          !fs.existsSync(full.replace(/\.js$/, '.ts'))) {
        out.push(full);
      }
    });
  };
  walk(ROOT, true);
  log.debug("Leaving sourceFiles(). " + out.length);
  return out;
}

/**
 * The codes the source records model gaps under, read as statements: an
 * `errorCodes.tag('CODE')` whose statement mentions a model, and a literal
 * code passed to a `.hold(` call.
 *
 * @returns {Map<string, string[]>} code to the files it was found in
 */
function sourceGapCodes() {
  log.debug("Entering sourceGapCodes().");
  const found = new Map();
  const note = function (code, file) {
    const files = found.get(code) || [];
    files.push(path.relative(ROOT, file));
    found.set(code, files);
  };
  sourceFiles().forEach(function (file) {
    const text = fs.readFileSync(file, 'utf8');
    const tagged = /errorCodes\.tag\(\s*'(STS-[A-Z0-9]+-\d{4})'\s*\)/g;
    let m;
    while ((m = tagged.exec(text)) !== null) {
      const end = text.indexOf(';', m.index);
      const statement = text.slice(m.index, end < 0 ? text.length : end);
      if (/model/i.test(statement)) {
        note(m[1], file);
      }
    }
    const held = /\.hold\([^;]*?'(STS-[A-Z0-9]+-\d{4})'/g;
    while ((m = held.exec(text)) !== null) {
      note(m[1], file);
    }
  });
  log.debug("Leaving sourceGapCodes(). " + found.size);
  return found;
}

/**
 * The codes the error table describes as a protocol family's model gap.
 *
 * @returns {string[]} the codes, in table order
 */
function tableGapCodes() {
  log.debug("Entering tableGapCodes().");
  const errorCodes = require('../common/error_codes');
  const out = errorCodes.CODES.filter(function (row) {
    return !row.retired &&
      /^none \(recorded only/.test(String(row.spec || '')) &&
      /#1579/.test(String(row.summary || '')) &&
      /models\//.test(String(row.summary || ''));
  }).map(function (row) {
    return row.code;
  });
  log.debug("Leaving tableGapCodes(). " + out.length);
  return out;
}

/**
 * The two sets' differences, as a sentence, '' when they are equal.
 *
 * @param {string[]} want - the expected set
 * @param {string[]} got - the set compared
 * @returns {string} what one has that the other lacks
 */
function difference(want, got) {
  log.debug("Entering difference().");
  const missing = want.filter(function (c) {
    return got.indexOf(c) < 0;
  });
  const extra = got.filter(function (c) {
    return want.indexOf(c) < 0;
  });
  const parts = [];
  if (missing.length) {
    parts.push('missing ' + missing.join(', '));
  }
  if (extra.length) {
    parts.push('not listed ' + extra.join(', '));
  }
  log.debug("Leaving difference().");
  return parts.join('; ');
}

/**
 * Runs the scanner's command line.
 *
 * @param {string[]} args - its arguments
 * @returns {{ status: number|null, stdout: string }} what it did
 */
function runTool(args) {
  log.debug("Entering runTool().");
  const result = cp.spawnSync(process.execPath, [TOOL].concat(args),
                              { encoding: 'utf8', timeout: 30000 });
  log.debug("Leaving runTool(). " + result.status);
  return { status: result.status, stdout: String(result.stdout || '') };
}

// A service log as `docker compose logs --no-color sts` writes it: bunyan
// JSON behind the compose prefix.
function line(level, msg) {
  log.debug("Entering line().");
  log.debug("Leaving line().");
  return 'sts-1  | ' + JSON.stringify({ name: 'sts', hostname: 'a',
    pid: 1, level: level, msg: msg, time: '2026-11-13T00:00:00.000Z',
    v: 0 });
}

const CLEAN = [
  line(30, 'IYA STS listening on 8081'),
  // A code that is not a gap, tagged.
  line(50, '[STS-OAUTH-1007] dynamic registration refused grant_types'),
  line(50, '[STS-API-0139] An answer is not its model\'s'),
  // A gap code named, not tagged: a sentence, and an audit row's member.
  line(20, 'none recorded under STS-GNAP-0910 for this view'),
  'sts-1  | {"action":"gnap.grant","errorCode":"STS-GNAP-0910","v":0}'
].join('\n') + '\n';

const DIRTY = [
  line(30, 'IYA STS listening on 8081'),
  line(50, '[STS-GNAP-0910] the approval answer is not its model\'s ' +
           '(gnap-api-view): preferredLanguage is not a string'),
  line(50, '[STS-SAML-0121] saml2: the Response does not match its model'),
  line(50, '[STS-GNAP-0910] the approval answer is not its model\'s ' +
           '(gnap-api-view): again'),
  line(40, '[STS-SSF-0162] the transmitter-metadata received is not the ' +
           'shape models/ssf/ssf.tsp gives it')
].join('\r\n') + '\r\n';

function run(t) {
  log.debug("Entering run().");

  t.log.info('=== A. the scanner over sample logs ===');
  t.equal(scan.scanText(CLEAN).length, 0,
          'A1 a log with no gap tag — a non-gap tag, a code in a sentence, ' +
          'an audit row\'s errorCode — has no finding');
  const findings = scan.scanText(DIRTY);
  t.equal(findings.map(function (f) {
    return f.code;
  }).join(','), 'STS-GNAP-0910,STS-SAML-0121,STS-SSF-0162',
  'A2 each gap code once, in the order of its first line (CRLF lines)');
  const none = { count: 0, line: 0, text: '' };
  const first = findings[0] || none;
  t.equal(first.count, 2, 'A3 a repeated code is counted');
  t.equal(first.line, 2, 'A4 its first line is the first occurrence');
  t.check(/preferredLanguage is not a string/.test(first.text),
       'A5 the first occurrence quoted is the first line, not a later one');
  t.equal((findings[2] || none).line, 5,
          'A6 a warning-level gap is a finding too');
  t.equal(scan.scanText('x[STS-GNAP-0910]y\n[STS-ACME-0100][STS-ACME-0100]')
    .map(function (f) {
      return f.code + 'x' + f.count + '@' + f.line;
    }).join(','), 'STS-GNAP-0910x1@1,STS-ACME-0100x2@2',
  'A7 a tag anywhere in a line counts, twice on one line counts twice');
  const long = scan.scanText('[STS-EST-0037] ' + 'x'.repeat(2000));
  t.check(long[0].text.length < 500,
       'A8 a very long first line is quoted cut short');

  t.log.info('=== B. the command line ===');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'model-gap-scan-'));
  try {
    const clean = path.join(dir, '00-iya-sts-service.log');
    const dirty = path.join(dir, '00-iya-sts-service-node-b.log');
    fs.writeFileSync(clean, CLEAN);
    fs.writeFileSync(dirty, DIRTY);
    const ok = runTool([clean]);
    t.equal(ok.status, 0, 'B1 a clean log exits 0');
    t.check(/none in .*00-iya-sts-service\.log/.test(ok.stdout),
         'B2 and says it found none in that log', ok.stdout);
    const bad = runTool([clean, dirty]);
    t.equal(bad.status, 1, 'B3 one log with a gap among clean ones exits 1');
    t.check(/STS-GNAP-0910 x2, first at line 2: /.test(bad.stdout) &&
         /STS-SAML-0121 x1, first at line 3: /.test(bad.stdout) &&
         /4 line\(s\) under 3 code\(s\) in .*node-b\.log/.test(bad.stdout),
         'B4 naming each code, its count and its first line, under its log',
         bad.stdout);
    const missing = runTool([path.join(dir, 'absent.log')]);
    t.equal(missing.status, 1, 'B5 a log that cannot be read exits 1');
    t.check(/could not be read/.test(missing.stdout),
         'B6 and says it was not checked', missing.stdout);
    t.equal(runTool([]).status, 1,
            'B7 no log named exits 1: nothing checked is not a pass');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  t.log.info('=== C. the list against the error table ===');
  const listed = scan.MODEL_GAP_CODES.slice();
  const table = tableGapCodes();
  const tableDrift = difference(table, listed);
  t.check(tableDrift === '',
          'C1 MODEL_GAP_CODES is exactly the error table\'s model gaps ' +
          '(recorded only, naming a models/ file and #1579)', tableDrift);
  t.equal(new Set(listed).size, listed.length, 'C2 no code listed twice');

  t.log.info('=== D. the list against every holding site ===');
  const found = sourceGapCodes();
  const sites = Array.from(found.keys()).filter(function (code) {
    return !Object.prototype.hasOwnProperty.call(NOT_A_GAP, code);
  }).sort();
  const drift = difference(listed.slice().sort(), sites);
  t.check(drift === '',
          'D1 every code a holding site logs is listed, and every listed ' +
          'code is logged by one',
          drift + ' ' + JSON.stringify(Object.fromEntries(found)));
  Object.keys(NOT_A_GAP).forEach(function (code) {
    t.check(found.has(code), 'D2 the exception ' + code + ' is still found (' +
         NOT_A_GAP[code] + ')');
  });
  t.check(found.has('STS-SAML-0121') && found.has('STS-WSTRUST-0071') &&
       found.has('STS-WSFED-0032'),
       'D3 the XML families\' codes are read off their hold() calls');

  t.log.info('=== E. the wiring ===');
  const launcher = fs.readFileSync(path.join(ROOT, 'run-tests.sh'), 'utf8');
  const capture = launcher.indexOf('  captureContainerLogs "${MODE}"\n' +
                                   '  LOGS_TAKEN=1\n');
  const check = launcher.indexOf('if ! modelGapCheck "${MODE}";');
  t.check(capture > 0 && check > capture && check - capture < 400,
       'E1 run-tests.sh runs modelGapCheck right after it takes a mode\'s ' +
       'logs');
  t.check(/modelGapCheck "\$\{MODE\}";\s*then\s*if \[ "\$\{MODE_RC\}" -eq 0 \];\s*then\s*MODES_FAILED\+=\("\$\{MODE\}"\)\s*MODE_RC=1/
    .test(launcher.slice(check, check + 300)),
       'E2 and a failed check fails the mode');
  const body = launcher.slice(launcher.indexOf('captureContainerLogs()\n{'),
                              launcher.indexOf('\n}\n',
                                launcher.indexOf('captureContainerLogs()\n{')));
  t.equal((body.match(/CAPTURED_SERVICE_LOGS\+=\("\$\{LAST_CAPTURED_LOG\}"\)/g)
           || []).length, 3,
          'E3 every node log it captures (node A, node B, cell B) is scanned');
  t.check(/node "\$\(hostPath "\$\{CURRENT_DIR\}\/tests\/tools\/model-gap-scan\.js"\)"/
    .test(launcher), 'E4 the check runs tests/tools/model-gap-scan.js');
  const container = fs.readFileSync(path.join(ROOT, 'tests',
    'schema-validation', 'in-container.sh'), 'utf8');
  t.check(/node tests\/tools\/model-gap-scan\.js "\$\{dir\}"\/service-\*\.log/
    .test(container) && /ok=0\s*gaps=FAIL/.test(container),
       'E5 the schema-validation verdict fails on a gap in any node log');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'model_gap_scan',
  describe: 'a protocol family\'s model gap in a service log fails a mode, ' +
            'and the gap codes are every holding site\'s',
  run: run
};
