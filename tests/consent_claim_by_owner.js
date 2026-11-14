// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: consent_claim_by_owner.js
//
// ---------------------------------------------------------------------------
// A PENDING CONSENT IS CLAIMED ONLY BY THE PERSON IT WAS ASKED OF (2026-11-11).
//
// In product a consent is tied to the browser that first asks about it
// (#1454, `authn_api.ts` calling `ConsentScreen.claimForBrowser()`). Until
// this date the first asker claimed it whoever its session belonged to, so
// somebody else holding the id, refused at the door, had claimed it on the
// way, and the person it was asked of was then refused their own consent
// ("started in another browser") — `sts_consent`'s last check, in run 16's
// single-node mode.
//
//   A. Another person's session is refused and claims nothing.
//   B. The person's own session claims it, and is answered again after.
//   C. Once claimed, another session of the same person is refused (the
//      browser binding #1454 exists for), and so is the other person.
//   D. A caller that names no request (the binding without a person check)
//      still claims, as before.
//
// The session lookup is stubbed (`authn.sessionOf`), so this is the claim's
// own rule and not the sign-in that leads to it; it runs in a child because
// the module keeps its pending records in process state.
// ---------------------------------------------------------------------------

const path = require('path');
const childProcess = require('child_process');
const log = require('bunyan').createLogger({ name: 'consent_claim_by_owner',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const FLAG = 'CCO_CHILD';

function childMain() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  try {
    delete process.env.CONFIG_FILE;
    const helpers = require(ROOT + '/common/helpers');
    const screens = require(ROOT + '/oauth-oidc/consent_screen');
    const authn = {
      hintAccount: function () {
        return null;
      },
      sessionOf: function (req) {
        return (req && req.stubSession) || null;
      }
    };
    const consent = {
      identityOf: function (value) {
        return String(value || '').trim().toLowerCase();
      }
    };
    const screen = new screens.ConsentScreen({
      log: helpers.log, xmlEscape: helpers.xmlEscape,
      parseBody: helpers.parseBody, randomId: helpers.randomId,
      oauthError: helpers.oauthError, baseUrlOf: helpers.baseUrlOf,
      config: require(ROOT + '/common/config'), consent: consent,
      applications: {}, audit: { record: function () {
        return null;
      } }, errorCodes: require(ROOT + '/common/error_codes'),
      validation: {}, authn: authn, authorizationDetails: {} });
    const where = screen.beginConsent({ returnTo: '/oauth2/authorize?a=1',
      username: 'Alice', clientId: 'cco-client', scopes: [] });
    const id = decodeURIComponent((/consent=([^&#]+)/.exec(String(where)) ||
                                   [])[1] || '');
    note(!!id, '0. a consent is pending for alice', where);
    const asBob = { stubSession: { user: { username: 'bob' } } };
    const asAlice = { stubSession: { user: { username: 'alice' } } };
    note(screen.claimForBrowser(id, 'sid-bob', asBob) === false,
         'A1. bob\'s session is refused');
    note(!screen.pendingFor(id).browserSession,
         'A2. and claims nothing', JSON.stringify(screen.pendingFor(id)));
    note(screen.claimForBrowser(id, 'sid-alice', asAlice) === true,
         'B1. alice\'s own session claims it');
    note(screen.claimForBrowser(id, 'sid-alice', asAlice) === true,
         'B2. and is answered again after');
    note(screen.claimForBrowser(id, 'sid-alice-2', asAlice) === false,
         'C1. another browser of alice\'s is refused once it is claimed');
    note(screen.claimForBrowser(id, 'sid-bob', asBob) === false,
         'C2. and so is bob');
    const where2 = screen.beginConsent({ returnTo: '/oauth2/authorize?b=1',
      username: 'alice', clientId: 'cco-client', scopes: [] });
    const id2 = decodeURIComponent((/consent=([^&#]+)/.exec(String(where2))
                                    || [])[1] || '');
    note(screen.claimForBrowser(id2, 'sid-any') === true &&
         screen.pendingFor(id2).browserSession === 'sid-any',
         'D1. a caller naming no request still claims, as before');
  } catch (e) {
    note(false, 'the child ran to the end', (e && e.stack) || e);
  }
  process.stdout.write('CCOFINDINGS ' + JSON.stringify(findings) + '\n');
}

function run(t) {
  log.debug('Entering run().');
  const env = Object.assign({}, process.env, { LOG_LEVEL: 'fatal' });
  env[FLAG] = '1';
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: env, encoding: 'utf8', timeout: 120000,
    maxBuffer: 16 * 1024 * 1024 });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('CCOFINDINGS ') === 0;
  })[0];
  if (!line) {
    t.bad('the child reported its findings', 'exit ' + result.status + ': ' +
          String(result.stderr || '').slice(-1500));
    log.debug('Leaving run(). No findings.');
    return;
  }
  JSON.parse(line.slice('CCOFINDINGS '.length)).forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug('Leaving run().');
}

if (process.env[FLAG] === '1') {
  childMain();
} else {
  module.exports = {
    name: 'consent_claim_by_owner',
    describe: 'a pending consent is claimed only by the person it was ' +
              'asked of (#1454, run 16)',
    run: run
  };
}
