// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// ===========================================================================
// A WRITE THAT ENDS WHAT A REFRESH TOKEN RESTS ON IS SAID ON ITS ANSWER (the
// review of #879, 2026-11-13).
//
// `tests/request_ryw_session.js` R16 holds the pool: a ticket filed under
// REVOKE_KEY holds a refresh grant on another worker until it is announced.
// What is here is the worker's half, which the pool test drives with a stub
// that sets the header itself:
//
//  V1. the header is spelled the same in the pool, the worker and
//      `common/revoking_writes.ts`, in lower case — the three share no
//      memory, so a rename is caught only by holding them side by side;
//  V2. `note()` does nothing with no marker, calls the one installed, and
//      contains a marker that throws;
//  V3. the worker's marker sets the header on the answer in flight, does
//      nothing with no answer (a cluster job's body), and does not touch an
//      answer whose headers have gone;
//  V4. `admin_stats.revoke()` says a revocation, and does NOT say a token
//      superseded by its successor — otherwise every refresh would wait for
//      every other;
//  V5. `oauth2_bcp.revokeFamily()` says it before it returns;
//  V6. the other funnels say it (as source: each needs a session, an entry
//      or a grant this file would have to build through half the service),
//      and a worker installs the marker once its stack is loaded.
//
// In process: no answer here is a request a running service could be asked
// to make with its headers already sent, or a marker it could be shown.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const realms = require('../common/realms');
const stats = require('../common/admin_stats');
const pool = require('../common/request_pool');
const worker = require('../common/request_worker');
const RevokingWrites = require('../common/revoking_writes');

const log = require('bunyan').createLogger({ name: 'revoking_writes',
  level: process.env.LOG_LEVEL || 'info' });

// Create a realm, hand it to `fn` inside it, and remove it however that goes
// — `revoked_jti_expiry.js`'s `inRealm()`.
async function inRealm(t, id, fn) {
  log.debug("Entering inRealm().");
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving inRealm().");
    return undefined;
  }
  try {
    log.debug("Leaving inRealm().");
    return await realms.run(made.realm, fn);
  } finally {
    realms.remove(id);
  }
}

// Runs `fn` with a marker that records what it is told, and puts the
// process back as it was (no marker: this is not a worker).
async function recording(fn) {
  log.debug("Entering recording().");
  const said = [];
  RevokingWrites.install(function (what) {
    said.push(what);
  });
  try {
    await fn(said);
  } finally {
    RevokingWrites.install(null);
  }
  log.debug("Leaving recording().");
  return said;
}

function sectionV1(t) {
  log.debug("Entering sectionV1().");
  const names = [pool.REVOKING_HEADER, worker.REVOKING_HEADER,
                 RevokingWrites.HEADER];
  t.check(names.every(function (n) {
    return !!n && n === names[0] && n === String(n).toLowerCase();
  }), 'V1. the pool, the worker and the leaf spell the header the same, ' +
      'in lower case', names.join(' '));
  log.debug("Leaving sectionV1().");
}

async function sectionV2(t) {
  log.debug("Entering sectionV2().");
  RevokingWrites.install(null);
  t.check(!RevokingWrites.installed(), 'V2. no marker in a process that is ' +
          'not a worker', '');
  RevokingWrites.note('nothing to tell');
  t.ok(true, 'V2. note() with no marker does nothing and does not throw');
  const said = await recording(function () {
    RevokingWrites.note('a session ended');
  });
  t.equal(said.join(','), 'a session ended',
          'V2. note() calls the marker installed, with what was ended');
  RevokingWrites.install(function () {
    throw new Error('a marker that throws');
  });
  let threw = false;
  try {
    RevokingWrites.note('contained');
  } catch (e) {
    log.debug("Caught in sectionV2(): " + ((e && e.message) || e));
    threw = true;
  }
  RevokingWrites.install(null);
  t.check(!threw, 'V2. a marker that throws does not reach the revocation',
          '');
  log.debug("Leaving sectionV2().");
}

function sectionV3(t) {
  log.debug("Entering sectionV3().");
  const answer = function (sent) {
    const headers = {};
    return {
      headersSent: sent,
      headers: headers,
      setHeader: function (name, value) {
        headers[name] = value;
      }
    };
  };
  const open = answer(false);
  t.check(worker.markRevokingAnswer(open, 'a session ended') === true &&
          open.headers[worker.REVOKING_HEADER] === '1',
          'V3. the answer in flight is marked', JSON.stringify(open.headers));
  t.check(worker.markRevokingAnswer(undefined, 'a job\'s sweep') === false,
          'V3. with no answer in flight (a cluster job) nothing is marked', '');
  const gone = answer(true);
  t.check(worker.markRevokingAnswer(gone, 'too late') === false &&
          Object.keys(gone.headers).length === 0,
          'V3. an answer whose headers have gone is not touched',
          JSON.stringify(gone.headers));
  log.debug("Leaving sectionV3().");
}

async function sectionV4(t) {
  log.debug("Entering sectionV4().");
  await inRealm(t, 'revoking-writes-v4', async function () {
    const ended = await recording(function () {
      stats.revoke('jti-ended-' + Date.now(), 'the test', undefined,
                   Math.floor(Date.now() / 1000) + 600);
    });
    t.equal(ended.length, 1, 'V4. a revocation is said');
    const rotated = await recording(function () {
      stats.revoke('jti-rotated-' + Date.now(),
                   'RFC 9700 section 2.2.2: rotated on use',
                   { superseded: true },
                   Math.floor(Date.now() / 1000) + 600);
    });
    t.equal(rotated.length, 0, 'V4. a token superseded on rotation is not');
  });
  log.debug("Leaving sectionV4().");
}

async function sectionV5(t) {
  log.debug("Entering sectionV5().");
  const bcp = require('../oauth-oidc/oauth2_bcp');
  await inRealm(t, 'revoking-writes-v5', async function () {
    let pending = null;
    const said = await recording(function () {
      pending = bcp.revokeFamily('family-' + Date.now(), 'client-v5');
    });
    t.equal(said.length, 1, 'V5. a family revoked is said before ' +
            'revokeFamily() returns');
    await pending;
    const none = await recording(function () {
      return bcp.revokeFamily('', 'client-v5');
    });
    t.equal(none.length, 0, 'V5. no family, nothing said');
  });
  log.debug("Leaving sectionV5().");
}

// The body a declaration `opening` begins, as source: up to the first line
// back at the declaration's own indent (its closing brace).
function bodyOf(file, opening) {
  log.debug("Entering bodyOf().");
  const text = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
  const at = text.indexOf(opening);
  if (at < 0) {
    log.debug("Leaving bodyOf(). Not found.");
    return '';
  }
  const indent = opening.replace(/^\n/, '').match(/^ */)[0];
  const rest = text.slice(at + opening.length);
  const end = rest.search(new RegExp('\\n' + indent + '[a-zA-Z}]'));
  log.debug("Leaving bodyOf().");
  return end < 0 ? rest : rest.slice(0, end);
}

function sectionV6(t) {
  log.debug("Entering sectionV6().");
  const sites = [
    ['authn/authn.ts', '\n  private dropSession(', 'RevokingWrites.note('],
    ['common/account_state.ts', '\n  setDisabled(', 'RevokingWrites.note('],
    ['oauth-oidc/grant_management.ts', '\n  revoke(grantId',
     'RevokingWrites.note(']
  ];
  sites.forEach(function (site) {
    const body = bodyOf(site[0], site[1]);
    t.check(body.length > 0 && body.indexOf(site[2]) >= 0,
            'V6. ' + site[0] + ' says a revocation in ' +
            site[1].trim().replace(/\($/, '()'), String(body.length));
  });
  const begin = fs.readFileSync(path.join(__dirname, '..', 'common',
                                          'request_worker.ts'), 'utf8');
  const mirror = begin.indexOf('this.installDirectoryMirror(message');
  const marker = begin.indexOf('this.installRevokingMarker();');
  t.check(mirror > 0 && marker > mirror,
          'V6. a worker installs the marker once its stack is loaded, ' +
          'beside the directory mirror', mirror + ' ' + marker);
  log.debug("Leaving sectionV6().");
}

async function run(t) {
  log.debug("Entering run().");
  sectionV1(t);
  await sectionV2(t);
  sectionV3(t);
  await sectionV4(t);
  await sectionV5(t);
  sectionV6(t);
  RevokingWrites.install(null);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'revoking_writes',
  describe: 'a write that ends what a refresh token rests on is said on its ' +
            'answer, so the pool files it for the refresh grant (the review ' +
            'of #879)',
  run: run
};
