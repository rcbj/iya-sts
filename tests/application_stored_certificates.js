// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: application_stored_certificates.js
//
// ===========================================================================
// A CERTIFICATE STORED ON AN APPLICATION'S ENTRY, THROUGH THE ADMIN DOORS
// (#1227).
//
// #1061 made a certificate from an outside authority, stored byte for byte
// in `userCertificate` on exactly one entry, that entry's identity at every
// door that reads a client certificate — an application's entry included —
// but only the PERSON's doors wrote one. This file holds the application's
// half: `applicationsAction()`'s `add-certificate` and `remove-certificate`
// (`POST /admin-api/applications/{action}`), `credentials.stored` on the
// `?application=` answer, the Stored certificates block of the console's
// Credentials tab, and the Shared Signals door taking the stored
// certificate as the application.
//
//   A. THE ACTIONS: add stores it (audited `certificate.stored` naming the
//      application, a CAEP credential-change of type x509 under the
//      APPLICATION, mailing nobody); add again changes nothing; not one
//      certificate is STS-ADMIN-0897; an identifier the registry does not
//      hold is STS-ADMIN-0906 and nothing is made; no identifier is
//      STS-ADMIN-0529; a certificate stored on a person's entry is
//      STS-ADMIN-0899; removing one not stored is STS-ADMIN-0900.
//   G. THE VIEW: `credentials.stored` of `applicationsJson()` lists it by
//      its SHA-256 with its subject; and the console's Credentials tab
//      draws it with a Remove form and the Store form, or neither without
//      Admin Write.
//   S. SHARED SIGNALS: a self-signed certificate on the connection, before
//      it is stored, is STS-SSF-0151; stored on the application's entry it
//      is that application, read under its SSF_READ role; removed, it is
//      0151 again (and audited `certificate.unstored`, CAEP delete).
//
// IN A CHILD PROCESS, for `wstrust_client_certificate.js`'s reason: it loads
// the stack and builds a certificate authority, both process state `run.js`
// shares with every other file. The socket is the one thing faked, in the
// shape `revocation_status.fromSocket()` reads from a real one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_APPLICATION_STORED_CERTS_CHILD';
const MARK = 'APP-STORED-CERTS-CHILD ';
const APP = 'ascapp';
const PERSON = 'ascbob';

const log = require('bunyan').createLogger({
  name: 'application_stored_certificates',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

// A connection that presented `pem` and verified, as a worker's shim
// carries it: no `isSessionReused`, so no chain is remembered.
function socketFor(pem) {
  log.debug("Entering socketFor().");
  const raw = new nodeCrypto.X509Certificate(pem).raw;
  log.debug("Leaving socketFor().");
  return { authorized: true,
           getPeerCertificate: function () {
             return { raw: raw };
           } };
}

function ssfRequest(pem) {
  log.debug("Entering ssfRequest().");
  log.debug("Leaving ssfRequest().");
  return { headers: {}, url: '/ssf/stream', originalUrl: '/ssf/stream',
           socket: socketFor(pem) };
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  // The console's English catalogs, for the drawn tab.
  require(ROOT + '/common/i18n');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const audit = require(ROOT + '/common/audit');
  const errorCodes = require(ROOT + '/common/error_codes');
  const applications = require(ROOT + '/common/applications');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const adminActions = require(ROOT + '/admin-core/admin_actions');
  const adminViews = require(ROOT + '/admin-core/admin_views');
  const page = require(ROOT + '/admin-ui/web_applications');
  const kit = require(ROOT + '/admin-ui/web_kit');
  const accountSignals = require(ROOT + '/ssf/account_signals');
  const ssfAuthModule = require(ROOT + '/ssf/ssf_auth');
  const testCa = require('./protocol/outbound_test_ca');

  await keystore.start();
  await pki.start({ realmIds: [''],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });

  // WHAT SHARED SIGNALS IS TOLD, caught at the facade the admin layer
  // calls through.
  const signals = [];
  const realSignal = accountSignals.certificateChanged;
  accountSignals.certificateChanged = function (notice) {
    signals.push(notice);
    return Promise.resolve({ sent: 0, streams: 0 });
  };
  const ctx = { actor: 'asctester', via: 'test' };
  const act = function (body) {
    log.debug("Entering act().");
    log.debug("Leaving act().");
    return adminActions.applicationsAction(body, [], ctx);
  };
  const audited = function (action) {
    log.debug("Entering audited(). " + action);
    log.debug("Leaving audited().");
    return audit.list().filter(function (row) {
      return row && row.action === action && row.target === APP;
    });
  };

  const made = applications.createApplication({ identifier: APP,
    protocols: ['oauth2', 'ssf'],
    fields: { oauthClientId: APP, oauthAllowedScope: ['ssf.read'] } });
  ldap.createUser(PERSON, { invent: false });
  const member = adminActions.rolesAction({ action: 'add-member',
    role: 'SSF_READ', kind: 'application', member: APP },
  { actor: 'test', via: 'test' });
  t.check(made && made.ok && member.ok,
          'precondition: the application exists and holds SSF_READ',
          JSON.stringify([made, member]));

  const mine = await testCa.selfSignedCertificate('ascapp.example');
  const bobs = await testCa.selfSignedCertificate('ascbob.example');
  const sha = nodeCrypto.createHash('sha256')
    .update(new nodeCrypto.X509Certificate(mine.cert).raw).digest('hex');

  // -------------------------------------------------------------------------
  // S, BEFORE: the self-signed certificate is stored on no entry.
  // -------------------------------------------------------------------------
  const gate = new ssfAuthModule.SsfAuth(ssfAuthModule.SsfAuth.defaultDeps());
  let decided = gate.authenticate(ssfRequest(mine.cert), 'read');
  t.check(!decided.ok && decided.errorCode === 'STS-SSF-0151',
          'S1. before it is stored, the self-signed certificate is ' +
          'STS-SSF-0151 at the Shared Signals door', JSON.stringify(decided));

  // -------------------------------------------------------------------------
  // A. THE ACTIONS
  // -------------------------------------------------------------------------
  const stored = act({ action: 'add-certificate', application: APP,
                       certificate: mine.cert });
  t.check(stored.ok && stored.changed === true && stored.application === APP &&
          stored.certificates.length === 1 &&
          stored.certificates[0].sha256 === sha,
          'A1. add-certificate stores it on the application\'s entry, and ' +
          'the answer lists it by its SHA-256', JSON.stringify(stored));
  const row = audited('certificate.stored')[0];
  t.check(row && row.actor === 'asctester' && row.detail &&
          row.detail.application === APP && row.detail.sha256 === sha,
          'A2. it is audited certificate.stored, naming the application ' +
          'and the actor', JSON.stringify(row || null));
  const created = signals.filter(function (one) {
    return one.changeType === 'create';
  })[0];
  t.check(created && created.application === APP && !created.username &&
          /BEGIN CERTIFICATE/.test(created.pem || '') &&
          accountSignals.AccountSignals.notPersonal(created),
          'A3. a CAEP credential-change (x509, create) goes under the ' +
          'APPLICATION\'s subject, and mails nobody', JSON.stringify(created));
  const again = act({ action: 'add-certificate', application: APP,
                      certificate: mine.cert });
  t.check(again.ok && again.changed === false &&
          again.certificates.length === 1 && signals.length === 1,
          'A4. storing it again changes nothing and signals nothing',
          JSON.stringify(again));
  const garbage = act({ action: 'add-certificate', application: APP,
                        certificate: 'not a certificate' });
  t.check(!garbage.ok && errorCodes.codeOf(garbage) === 'STS-ADMIN-0897',
          'A5. what is not one certificate is STS-ADMIN-0897',
          JSON.stringify(garbage));
  const two = act({ action: 'add-certificate', application: APP,
                    certificate: mine.cert + bobs.cert });
  t.check(!two.ok && errorCodes.codeOf(two) === 'STS-ADMIN-0897',
          'A6. two PEM blocks are STS-ADMIN-0897 too: the leaf only',
          JSON.stringify(two));
  const nobody = act({ action: 'add-certificate', application: 'ascnoapp',
                       certificate: bobs.cert });
  t.check(!nobody.ok && errorCodes.codeOf(nobody) === 'STS-ADMIN-0906' &&
          !applications.get('ascnoapp'),
          'A7. an identifier the registry does not hold is STS-ADMIN-0906, ' +
          'and no application is made', JSON.stringify(nobody));
  const nothing = act({ action: 'remove-certificate', sha256: sha });
  t.check(!nothing.ok && errorCodes.codeOf(nothing) === 'STS-ADMIN-0529',
          'A8. no application named is STS-ADMIN-0529',
          JSON.stringify(nothing));
  const onBob = adminActions.usersAction({ action: 'add-certificate',
    user: PERSON, certificate: bobs.cert }, { actor: 'test', via: 'test' });
  const elsewhere = act({ action: 'add-certificate', application: APP,
                          certificate: bobs.cert });
  t.check(onBob.ok && !elsewhere.ok &&
          errorCodes.codeOf(elsewhere) === 'STS-ADMIN-0899',
          'A9. a certificate stored on a person\'s entry is STS-ADMIN-0899 ' +
          'on the application', JSON.stringify(elsewhere));
  const notHeld = act({ action: 'remove-certificate', application: APP,
                        sha256: 'ab'.repeat(32) });
  t.check(!notHeld.ok && errorCodes.codeOf(notHeld) === 'STS-ADMIN-0900',
          'A10. removing one the entry does not store is STS-ADMIN-0900',
          JSON.stringify(notHeld));
  const listedNobody = adminActions.applicationStoredCertificatesOf(
    'ascnoapp');
  t.check(!listedNobody.ok &&
          errorCodes.codeOf(listedNobody) === 'STS-ADMIN-0906',
          'A11. the list of an application the registry does not hold is ' +
          'STS-ADMIN-0906', JSON.stringify(listedNobody));

  // -------------------------------------------------------------------------
  // G. THE VIEW AND THE CONSOLE
  // -------------------------------------------------------------------------
  const json = adminViews.applicationsJson({
    query: { application: APP }, headers: { host: '127.0.0.1' },
    protocol: 'http',
    get: function () {
      return '';
    } });
  const listed = ((json.credentials || {}).stored) || {};
  t.check(listed.ok && listed.application === APP &&
          listed.certificates.length === 1 &&
          listed.certificates[0].sha256 === sha &&
          /ascapp\.example/.test(listed.certificates[0].subject),
          'G1. credentials.stored of GET /admin-api/applications' +
          '?application= lists it, with its subject',
          JSON.stringify(listed));
  const tabOf = function (write) {
    log.debug("Entering tabOf().");
    const html = page.detail(kit.context({ application: APP }, write), json);
    const at = html.indexOf('id="credentials-stored"');
    log.debug("Leaving tabOf().");
    return at < 0 ? '' : html.slice(at, at + 6000);
  };
  const drawn = tabOf(true);
  t.check(drawn.indexOf('Stored certificates') >= 0 &&
          drawn.indexOf(sha) >= 0 &&
          drawn.indexOf('value="remove-certificate"') >= 0 &&
          drawn.indexOf('value="add-certificate"') >= 0 &&
          drawn.indexOf('name="certificate"') >= 0,
          'G2. the Credentials tab draws it with a Remove form, and the ' +
          'Store form', drawn.slice(0, 600));
  const readOnly = tabOf(false);
  t.check(readOnly.indexOf(sha) >= 0 &&
          readOnly.indexOf('value="remove-certificate"') < 0 &&
          readOnly.indexOf('value="add-certificate"') < 0 &&
          readOnly.indexOf('Admin Write') >= 0,
          'G3. without Admin Write it is listed with neither form',
          readOnly.slice(0, 600));

  // -------------------------------------------------------------------------
  // S, STORED, THEN REMOVED
  // -------------------------------------------------------------------------
  decided = gate.authenticate(ssfRequest(mine.cert), 'read');
  t.check(decided.ok && decided.scheme === 'clientcert' &&
          decided.principal === APP,
          'S2. stored on the application\'s entry, the self-signed ' +
          'certificate is the application at the Shared Signals door',
          JSON.stringify(decided));
  const removed = act({ action: 'remove-certificate', application: APP,
                        sha256: sha.toUpperCase().match(/../g).join(':') });
  t.check(removed.ok && removed.changed === true &&
          removed.certificates.length === 0 &&
          audited('certificate.unstored').length === 1 &&
          signals.some(function (one) {
            return one.changeType === 'delete' && one.application === APP;
          }),
          'A12. remove-certificate (the SHA-256 colon-separated, in either ' +
          'case) takes it off, audited certificate.unstored, CAEP delete',
          JSON.stringify(removed));
  decided = gate.authenticate(ssfRequest(mine.cert), 'read');
  t.check(!decided.ok && decided.errorCode === 'STS-SSF-0151',
          'S3. removed, it is STS-SSF-0151 again', JSON.stringify(decided));

  accountSignals.certificateChanged = realSignal;
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 240000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  const got = spawnChild();
  if (got.error) {
    log.debug("Leaving run(). The child failed.");
    throw new Error(got.error);
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (process.env[CHILD_FLAG] === '1' && require.main === module) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'application_stored_certificates',
  describe: 'An application\'s stored certificates through the admin ' +
            'doors (#1227): add and remove with every refusal, the ' +
            'audit rows and the CAEP event under the application, ' +
            'credentials.stored and the console block, and the Shared ' +
            'Signals door taking the stored certificate as the application',
  run: run
};
