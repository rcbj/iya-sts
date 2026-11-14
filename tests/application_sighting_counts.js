// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: application_sighting_counts.js
//
// ===========================================================================
// A SIGHTING COUNTS AN APPLICATION'S SESSIONS AND USERS WITHOUT A LIST OF
// THEM (2026-10-21).
//
// `applications.seen()` sized `record.sessions` and `record.users` to the
// counts as sparse arrays, so that `attributesFor()` could write their
// length — on 8081, two arrays of 345,000 holes at every sign-in for the
// load test's one client, and a copy of each in every `copyRecord()`.
//
//   S1. a sighting with a session and a user counts both;
//   S2. the record carries no list sized to the count;
//   S3. the entry written for it carries the counts;
//   S4. a record read back from an entry, which has the counts and empty
//       lists, still writes its counts.
//
// In a child process: it registers an application.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'application_sighting_counts',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.ASC_OUT;
  const ROOT = process.env.ASC_ROOT;
  try {
    const applications = require(ROOT + '/common/applications');
    const ID = 'asc-client';
    let record = null;
    for (let i = 0; i < 3; i++) {
      record = applications.seen({ identifier: ID, kind: 'oauth2',
                                   protocol: 'OAuth 2.0',
                                   sessionId: 'asc-session-' + i,
                                   user: 'asc-user-' + i }) || record;
    }
    note(record && record.sessionCount >= 1 && record.userCount >= 1,
         'S1. a sighting with a session and a user counts both', JSON.stringify(record && { sessions: record.sessionCount,
                                             users: record.userCount }));
    note(record && (record.sessions || []).length === 0 &&
         (record.users || []).length === 0,
         'S2. the record carries no list sized to the count',
         JSON.stringify(record && { sessions: (record.sessions || []).length,
                                    users: (record.users || []).length }));
    const attrs = applications.attributesFor(record);
    note(attrs && attrs.appSessions &&
         attrs.appSessions[0] === String(record.sessionCount) &&
         attrs.appUsers && attrs.appUsers[0] === String(record.userCount),
         'S3. the entry written for it carries the counts',
         JSON.stringify(attrs && { s: attrs.appSessions, u: attrs.appUsers }));
    const readBack = Object.assign({}, record, { sessions: [], users: [],
                                                 sessionCount: 7,
                                                 userCount: 5 });
    const again = applications.attributesFor(readBack);
    note(again.appSessions[0] === '7' && again.appUsers[0] === '5',
         'S4. a record read back with counts and empty lists writes its ' +
         'counts', JSON.stringify({ s: again.appSessions, u: again.appUsers }));
  } catch (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-asc-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { ASC_OUT: out, ASC_ROOT: root, LOG_LEVEL: 'fatal',
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
  name: 'application_sighting_counts',
  describe: 'a sighting counts an application\'s sessions and users without ' +
            'a list of them',
  run: run
};
