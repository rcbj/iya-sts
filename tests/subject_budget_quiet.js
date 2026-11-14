// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: subject_budget_quiet.js
//
// ===========================================================================
// A SPENT DIRECTORY BUDGET IS NOT LOGGED, OR ASKED AGAIN, ONCE PER SUBJECT
// (2026-10-21).
//
// A console page resolving the subjects of a large register met the
// request's spent directory budget (STS-LDAP-0175) once per subject and
// logged each at error — 360,000 STS-CORE-0091 lines in six minutes on
// 8081 — and a batch refused on it asked every subject again on its own.
//
//   Q1. nameForSubject() and subjectForName() refused on the budget answer
//       '' and log nothing at error;
//   Q2. namesForSubjects() refused on the budget answers every subject ''
//       without asking any of them alone;
//   Q3. any other resolver failure is still logged at error, and a refused
//       batch is still asked one subject at a time.
//
// In a child process: it installs its own subject resolver.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'subject_budget_quiet',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.SBQ_OUT;
  const ROOT = process.env.SBQ_ROOT;
  try {
    const helpers = require(ROOT + '/common/helpers');
    const errorCodes = require(ROOT + '/common/error_codes');
    const errors = [];
    const realError = helpers.log.error;
    helpers.log.error = function (msg) {
      errors.push(String(msg));
      return realError.apply(this, arguments);
    };
    let kind = 'budget';
    let alone = 0;
    const fail = function () {
      if (kind === 'budget') {
        return errorCodes.mark(new Error('the budget is spent'),
                               'STS-LDAP-0175');
      }
      return new Error('the directory is on fire');
    };
    helpers.setSubjectResolver({
      nameFor: function () {
        alone++;
        throw fail();
      },
      subjectFor: function () {
        throw fail();
      },
      namesFor: function () {
        throw fail();
      }
    });
    const subjects = [];
    for (let i = 0; i < 50; i++) {
      subjects.push('urn:uuid:00000000-0000-4000-8000-' +
                    String(i).padStart(12, '0'));
    }
    const one = helpers.nameForSubject(subjects[0]);
    const sub = helpers.subjectForName('sbq-person');
    note(one === '' && sub === '' && errors.length === 0,
         'Q1. a lookup refused on the spent budget answers \'\' and logs ' +
         'nothing at error', JSON.stringify({ one: one, sub: sub,
                                              errors: errors.length }));
    alone = 0;
    const many = helpers.namesForSubjects(subjects);
    const answered = subjects.every(function (s) {
      return many.get(s.replace(/^urn:uuid:/, '')) === '' ||
             many.get(s) === '';
    });
    note(answered && alone === 0 && errors.length === 0,
         'Q2. a batch refused on the spent budget answers every subject \'\' ' +
         'and asks none of them alone', JSON.stringify({ alone: alone,
           errors: errors.length, size: many.size }));
    kind = 'other';
    alone = 0;
    helpers.nameForSubject(subjects[1]);
    helpers.namesForSubjects(subjects.slice(0, 5));
    note(errors.length >= 2 && alone === 1 + 5,
         'Q3. any other failure is still logged at error, and a refused ' +
         'batch is still asked one subject at a time',
         JSON.stringify({ errors: errors.length, alone: alone }));
  } catch (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-sbq-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { SBQ_OUT: out, SBQ_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'subject_budget_quiet',
  describe: 'a spent directory budget is not logged, or asked again, once ' +
            'per subject',
  run: run
};
