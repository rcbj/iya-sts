// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: console_signout_scale.js
//
// ===========================================================================
// SIGNING ONE PERSON OUT READS THAT PERSON'S SESSIONS FROM THE INDEX, NOT
// EVERY SESSION (2026-10-22, #820).
//
// On 8081 the inventory of ONE person — `GET /admin-api/logout?user=` and
// every `terminate()` — walked every sealed session body, about 470,000
// synchronous reads on a request worker.
//
//   S1. with the session window on, `heldIdsFor()` asks the index once per
//       key and never walks; a `urn:uuid:` key is its own subject;
//   S2. the wallet rows are read by subject, and a key with no subject
//       reads none;
//   S3. an unread index THROWS — never "nobody";
//   S4. with the window off, the walk is what it was.
//
// In a child process, with stand-ins for the session reads.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'console_signout_scale',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.CSS_OUT;
  const ROOT = process.env.CSS_ROOT;
  (async function () {
    const authn = require(ROOT + '/authn/authn');
    const logout = require(ROOT + '/logout/logout');
    const vcIssued = require(ROOT + '/oid4vc/vc_issued');

    const realOn = authn.sessionWindowOn;
    const realHeld = authn.sessionsHeldUnder;
    const realMatching = authn.sessionsMatching;
    const realRows = vcIssued.rowsForSubject;
    const SUBJECT = 'urn:uuid:0b1f2c3d-4e5f-4061-8273-94a5b6c7d8e9';
    const sessionFor = function (id, username, sub) {
      return { id: id, user: { username: username, sub: sub },
               authenticated: true, chosen: true, authTime: Date.now(),
               created: Date.now(), expires: Date.now() + 3600e3,
               relyingParties: [], events: [] };
    };
    let walks = 0;
    let held = [];
    let rowAsks = [];
    let unread = false;
    try {
      authn.sessionsMatching = function () {
        walks += 1;
        return [sessionFor('w1', 'alice-x', '')];
      };
      authn.sessionsHeldUnder = function (name, subject) {
        held.push([name, subject]);
        if (unread) {
          return null;
        }
        if (name === 'alice-x') {
          return [sessionFor('a1', 'alice-x', ''),
                  sessionFor('a2', 'carol-x', '')];
        }
        return [];
      };
      vcIssued.rowsForSubject = function (subject) {
        rowAsks.push(subject);
        return [];
      };

      authn.sessionWindowOn = function () { return true; };
      const ids = logout.heldIdsFor(['alice-x', 'bob-x', SUBJECT]);
      note(walks === 0, 'S1. with the window on no session is walked',
           'walks=' + walks);
      note(held.length === 3 &&
           held.some(function (h) { return h[0] === 'alice-x'; }) &&
           held.some(function (h) { return h[0] === 'bob-x'; }),
           'S1. the index is asked once per key',
           JSON.stringify(held));
      const forUuid = held.find(function (h) { return h[0] === SUBJECT; });
      note(forUuid && forUuid[1] === SUBJECT,
           'S1. a urn:uuid: key is its own subject', JSON.stringify(forUuid));
      const alice = (ids.get('alice-x') || []).map(function (id) {
        return String(id).replace(/^session:/, '');
      });
      note(alice.indexOf('a1') !== -1 && alice.indexOf('a2') === -1,
           'S1. only the key\'s own sessions are kept',
           JSON.stringify(alice));
      note(rowAsks.indexOf(SUBJECT) !== -1 && rowAsks.indexOf('') === -1,
           'S2. wallet rows are read by subject, never for an empty one',
           JSON.stringify(rowAsks));

      unread = true;
      let threw = false;
      try {
        logout.heldIdsFor(['alice-x']);
      } catch (e) {
        threw = /could not be read/.test(String(e && e.message));
      }
      note(threw, 'S3. an unread index throws rather than answer nobody');
      unread = false;

      authn.sessionWindowOn = function () { return false; };
      held = [];
      walks = 0;
      // Two keys: one key is read through the index in either window
      // (#774's single-person read), so the batch is what walks.
      const off = logout.heldIdsFor(['alice-x', 'bob-x']);
      note(walks === 1 && held.length === 0,
           'S4. with the window off the walk is what it was',
           'walks=' + walks + ' held=' + held.length);
      note((off.get('alice-x') || []).indexOf('session:w1') !== -1,
           'S4. the walk still finds the key\'s session',
           JSON.stringify(off.get('alice-x')));
    } finally {
      authn.sessionWindowOn = realOn;
      authn.sessionsHeldUnder = realHeld;
      authn.sessionsMatching = realMatching;
      vcIssued.rowsForSubject = realRows;
    }
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-css-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { CSS_OUT: out, CSS_ROOT: root, LOG_LEVEL: 'fatal',
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
  name: 'console_signout_scale',
  describe: 'signing one person out reads their sessions from the index, ' +
            'not every session (#820)',
  run: run
};
