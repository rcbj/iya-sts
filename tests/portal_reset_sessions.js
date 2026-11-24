// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: portal_reset_sessions.js
//
// ===========================================================================
// A SELF-SERVICE PASSWORD RESET ENDS EVERY SESSION (#2123, ASVS 5.0.0 7.4.3;
// rcbj's decision 2026-11-24).
//
// `portal/account_reset.ts` set the new password and answered "done", and a
// session somebody opened with the old password lived on. Now the spend ends
// every session of the person, as an administrator's reset does:
//
//   A. `endEverySession()` asks the sign-out model to end EVERY session (an
//      empty selection) of the person's identity key, attributed to them;
//   B. a sign-out model that throws is said and answered as 0, and does not
//      undo the reset (the spend still answers done);
//   C. `spend()` asks it once the password is set, after the link is spent;
//   D. the done card tells the person every session was signed out.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'portal_reset_sessions',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function run(t) {
  log.debug("Entering run().");
  const mod = require('../portal/account_reset');
  const calls = [];
  const deps = Object.assign(mod.AccountReset.defaultDeps(), {
    logout: function () {
      return { terminate: function (key, selection, opts) {
        calls.push({ key: key, selection: selection, opts: opts });
        return { terminated: [{ sid: 'a' }, { sid: 'b' }] };
      } };
    },
    stats: function () {
      return { identityKeyOf: function (name) {
        return 'key:' + name;
      } };
    }
  });
  const reset = new mod.AccountReset(deps);

  t.log.info('=== A. every session of the person ===');
  const ended = reset.endEverySession('ann');
  t.equal(ended, 2, 'A1. the count of sessions ended is answered');
  t.check(calls.length === 1 && calls[0].key === 'key:ann' &&
          Array.isArray(calls[0].selection) &&
          calls[0].selection.length === 0,
          'A2. the sign-out model is asked for EVERY session (an empty ' +
          'selection) of the person\'s identity key', JSON.stringify(calls));
  t.check(calls[0].opts.initiatingEntity === 'user' &&
          calls[0].opts.actor === 'ann' && /reset link/.test(
            calls[0].opts.by),
          'A3. attributed to the person and the reset link',
          JSON.stringify(calls[0].opts));

  t.log.info('=== B. a failing sign-out does not undo the reset ===');
  const failing = new mod.AccountReset(Object.assign({}, deps, {
    logout: function () {
      return { terminate: function () {
        throw new Error('no logout model');
      } };
    }
  }));
  let answered;
  let threw = '';
  try {
    answered = failing.endEverySession('ann');
  } catch (e) {
    threw = e.message;
  }
  t.check(!threw && answered === 0,
          'B1. a sign-out that throws is answered as 0 and does not throw',
          threw);

  t.log.info('=== C. spend() asks it after the password is set ===');
  const source = fs.readFileSync(path.join(ROOT, 'portal',
                                           'account_reset.ts'), 'utf8');
  const set = source.indexOf("set a new password from a reset ");
  const asked = source.indexOf('this.endEverySession(username)');
  const answer = source.indexOf('view: { done: true, signIn:');
  t.check(set > 0 && asked > set && answer > asked,
          'C1. the spend ends every session after the password is set and ' +
          'before it answers done', JSON.stringify({ set, asked, answer }));

  t.log.info('=== D. the done card says so ===');
  const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, 'common',
    'locales', 'portal', 'en.json'), 'utf8'));
  const page = fs.readFileSync(path.join(ROOT, 'portal', 'web_reset.ts'),
                               'utf8');
  t.check(/signed out/.test(String(catalog['resetDone.signedOut'] || '')) &&
          page.indexOf("'portal.resetDone.signedOut'") > 0,
          'D1. the done card tells the person every session was signed out');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal_reset_sessions',
  describe: 'a self-service password reset ends every session of the ' +
            'person, as an administrator\'s does (#2123, ASVS 7.4.3)',
  run: run
};
