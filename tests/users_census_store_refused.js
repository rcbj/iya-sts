// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: users_census_store_refused.js
//
// ===========================================================================
// A USERS-LIST CENSUS THE STORE REFUSED IS NOT ASKED AGAIN PERSON BY PERSON,
// AND NO LIST READS RECOVERY CODES (#786).
//
// On 8081 the census failed on the request's directory budget and the list
// fell back to `mechanismsFor()` for ~165,000 names — keys, authenticator
// and recovery codes, every read refused and logged — and a request worker
// was held for minutes.
//
//   R1. a census refused by the store (STS-LDAP-0175) answers every name
//       unknown and asks nobody on their own — synchronously and not;
//   R2. a census that threw for any other reason is still answered one name
//       at a time;
//   R3. that one-at-a-time path reads no recovery codes;
//   R4. a row none of whose names the census answered has no factors
//       (unknown), not "no credential".
//
// In a child process: it replaces the directory's census hooks.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'users_census_store_refused', level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.UCR_OUT;
  const ROOT = process.env.UCR_ROOT;
  const finish = function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  (async function () {
    require(ROOT + '/ldap/ldap_server');
    const credentials = require(ROOT + '/common/credentials');
    const errorCodes = require(ROOT + '/common/error_codes');
    const views = require(ROOT + '/admin-core/admin_views');
    const proto = credentials.Credentials.prototype;
    const counts = { mechanisms: 0, recovery: 0 };
    const realMechanisms = proto.mechanismsFor;
    const realRecovery = proto.backupCodeStatus;
    proto.mechanismsFor = function () {
      counts.mechanisms++;
      return realMechanisms.apply(this, arguments);
    };
    proto.backupCodeStatus = function () {
      counts.recovery++;
      return realRecovery.apply(this, arguments);
    };
    const names = ['ucr-a', 'ucr-b', 'ucr-c'];
    const refused = function () {
      return errorCodes.mark(new Error('this request has already waited ' +
        '5000 ms for the store'), 'STS-LDAP-0175');
    };

    credentials.addDirectoryHooks({
      credentialCensus: function () {
        throw refused();
      },
      credentialCensusAsync: function () {
        return Promise.reject(refused());
      }
    });
    const syncFacts = credentials.factorCensus(names);
    const asyncFacts = await credentials.factorCensusAsync(names);
    note(syncFacts.size === 0 && asyncFacts.size === 0 &&
         counts.mechanisms === 0 && counts.recovery === 0,
         'R1. a census the store refused answers every name unknown and asks ' +
         'nobody on their own, synchronously and not',
         JSON.stringify({ sync: syncFacts.size, async: asyncFacts.size,
                          counts: counts }));

    credentials.addDirectoryHooks({
      credentialCensus: function () {
        throw new Error('something else went wrong');
      }
    });
    const other = credentials.factorCensus(names);
    note(other.size === 3 && counts.mechanisms === 3,
         'R2. a census that threw for another reason is still answered one ' +
         'name at a time', JSON.stringify({ size: other.size,
                                            counts: counts }));
    note(counts.recovery === 0,
         'R3. and that one-at-a-time path reads no recovery codes',
         JSON.stringify(counts));

    // R4: the view's merge, over a census that answered nobody.
    const instance = new views.AdminViews(views.AdminViews.defaultDeps());
    const population = { spellings: new Map([
      ['ucr-a', [{ username: 'ucr-a' }]],
      ['ucr-b', [{ username: 'ucr-b' }]]]) };
    const rows = [{ key: 'ucr-a' }, { key: 'ucr-b' }];
    const merged = instance.peopleCensusOf(population, rows, new Map([
      ['ucr-b', { password: true, usable: true, primaryKeys: 0, mfaKeys: 0 }]
    ]));
    note(merged.get('ucr-a') === null && merged.get('ucr-b') &&
         merged.get('ucr-b').password === true,
         'R4. a row the census did not answer has no factors (unknown); one ' +
         'it answered keeps its facts', JSON.stringify([merged.get('ucr-a'),
           merged.get('ucr-b') && merged.get('ucr-b').password]));
    finish();
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
    finish();
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ucr-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { UCR_OUT: out, UCR_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 64 * 1024 * 1024 });
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
  name: 'users_census_store_refused',
  describe: 'a users-list census the store refused is not asked again person ' +
            'by person, and no list reads recovery codes (#786)',
  run: run
};
