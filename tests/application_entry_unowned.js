// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: application_entry_unowned.js
//
// ===========================================================================
// A REGISTRY WRITE KEEPS WHAT THE REGISTRY DOES NOT MODEL (#1230).
//
// `applications.js`'s save() hands `ldap_server.js`'s writeApplication() the
// attributes of a record, and writeApplication() REPLACED the entry with
// them. The record carries only what the registry's SCHEMA lists, so every
// other attribute on an application's entry — a certificate stored by
// `add-certificate` (#1227), an attribute an operator added with ldapmodify —
// was erased by the next sighting, with no audit row. On a product stack a
// Shared Signals receiver's stored certificate was gone after its first
// `POST /ssf/stream`, and its next certificate-authenticated call was
// refused STS-SSF-0151.
//
//   K. KEPT: a certificate stored on the application's entry, a bare
//      `userCertificate` value, and two attributes added over LDAP that the
//      registry does not model (`seeAlso`, `l`) survive an ssf-receiver
//      sighting, a SAML 2.0 service-provider sighting and a `set` of a
//      modelled attribute through the admin doors; the stored certificate
//      still authenticates at the Shared Signals door after each.
//   M. MODELLED: a redirect URI deleted with an LDAP modify stays deleted
//      after those writes, and a modelled attribute written over LDAP
//      (`appCertificateHostName`, certificate enrollment's) is kept by the
//      record as it always was.
//   O. OWNED: `ownedAttributeNames()` is lower-cased base names, holds the
//      SCHEMA's and `objectclass`, and holds no `usercertificate`.
//
// IN A CHILD PROCESS, for `application_stored_certificates.js`'s reason: it
// loads the stack and builds a certificate authority, both process state
// `run.js` shares with every other file.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_APPLICATION_ENTRY_UNOWNED_CHILD';
const MARK = 'APP-ENTRY-UNOWNED-CHILD ';
const APP = 'aeuapp';
const KEPT_URI = 'https://aeuapp.example/kept';
const GONE_URI = 'https://aeuapp.example/gone';

const log = require('bunyan').createLogger({
  name: 'application_entry_unowned',
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
// carries it — `application_stored_certificates.js`'s.
function ssfRequest(pem) {
  log.debug("Entering ssfRequest().");
  const raw = new nodeCrypto.X509Certificate(pem).raw;
  log.debug("Leaving ssfRequest().");
  return { headers: {}, url: '/ssf/stream', originalUrl: '/ssf/stream',
           socket: { authorized: true,
                     getPeerCertificate: function () {
                       return { raw: raw };
                     } } };
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const applications = require(ROOT + '/common/applications');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const adminActions = require(ROOT + '/admin-core/admin_actions');
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
  const realSignal = accountSignals.certificateChanged;
  accountSignals.certificateChanged = function () {
    return Promise.resolve({ sent: 0, streams: 0 });
  };
  const ctx = { actor: 'aeutester', via: 'test' };
  const dn = 'cn=' + applications.labelFor(APP) + ',' + ldap.applicationsDn();
  const ADMIN_DN = 'uid=admin,ou=users,' + ldap.baseDn();
  const entryNow = function () {
    log.debug("Entering entryNow().");
    const stored = ldap.entries.get(ldap.normalizeDn(dn));
    log.debug("Leaving entryNow().");
    return stored ? stored.attributes : {};
  };
  const modify = function (changes) {
    log.debug("Entering modify().");
    log.debug("Leaving modify().");
    return Promise.resolve(ldap.performOperation('modify',
      { dn: dn, boundDn: ADMIN_DN, channel: 'ldaps', changes: changes }));
  };

  // -------------------------------------------------------------------------
  // O. OWNED
  // -------------------------------------------------------------------------
  const owned = applications.ownedAttributeNames();
  t.check(Array.isArray(owned) && owned.indexOf('objectclass') >= 0 &&
          owned.indexOf('oauthredirecturi') >= 0 &&
          owned.indexOf('appcertificatehostname') >= 0 &&
          owned.indexOf('krb5servicekeys') >= 0 &&
          owned.indexOf('usercertificate') < 0 &&
          owned.indexOf('seealso') < 0 &&
          owned.every(function (name) {
            return name === name.toLowerCase() && name.indexOf(';') < 0;
          }),
          'O1. ownedAttributeNames() is the SCHEMA\'s and objectclass, ' +
          'lower-cased base names, and not userCertificate or seeAlso',
          JSON.stringify(owned.length));

  // -------------------------------------------------------------------------
  // The application, its role, its stored certificate, and LDAP's edits.
  // -------------------------------------------------------------------------
  const made = applications.createApplication({ identifier: APP,
    protocols: ['oauth2', 'ssf'],
    fields: { oauthClientId: APP, oauthAllowedScope: ['ssf.read'],
              oauthRedirectUri: [KEPT_URI, GONE_URI] } });
  const member = adminActions.rolesAction({ action: 'add-member',
    role: 'SSF_READ', kind: 'application', member: APP },
  { actor: 'test', via: 'test' });
  const mine = await testCa.selfSignedCertificate('aeuapp.example');
  const other = await testCa.selfSignedCertificate('aeuapp-bare.example');
  const sha = nodeCrypto.createHash('sha256')
    .update(new nodeCrypto.X509Certificate(mine.cert).raw).digest('hex');
  const stored = adminActions.applicationsAction({ action: 'add-certificate',
    application: APP, certificate: mine.cert }, [], ctx);
  const edited = await modify([
    { operation: 'add', modification: { type: 'seeAlso',
      values: ['cn=aeu-elsewhere,' + ldap.baseDn()] } },
    { operation: 'add', modification: { type: 'l', values: ['Lisbon'] } },
    { operation: 'add', modification: { type: 'userCertificate',
      values: [other.cert] } },
    { operation: 'add', modification: { type: 'appCertificateHostName',
      values: ['aeuapp.example'] } },
    { operation: 'delete', modification: { type: 'oauthRedirectUri',
      values: [GONE_URI] } }]);
  const before = entryNow();
  t.check(made && made.ok && member.ok && stored.ok &&
          edited.ok !== false &&
          (before['usercertificate;binary'] || []).length === 1 &&
          (before.usercertificate || []).length === 1 &&
          (before.seealso || []).length === 1 &&
          (before.oauthredirecturi || []).join() === KEPT_URI,
          'precondition: the application holds SSF_READ, a stored ' +
          'certificate, a bare userCertificate, seeAlso and l, and one ' +
          'redirect URI', JSON.stringify([made, member, stored.ok, edited,
            Object.keys(before)]));

  const gate = new ssfAuthModule.SsfAuth(ssfAuthModule.SsfAuth.defaultDeps());
  const checkAfter = function (label, n) {
    log.debug("Entering checkAfter(). " + label);
    const now = entryNow();
    const listed = ldap.storedCertificatesOf('application', APP);
    const shas = ((listed && listed.certificates) || []).map(function (one) {
      return one.sha256;
    });
    t.check(shas.length === 2 && shas.indexOf(sha) >= 0 &&
            (now['usercertificate;binary'] || []).length === 1 &&
            (now.usercertificate || []).length === 1,
            'K' + n + '. after ' + label + ', both stored certificates ' +
            'are still on the entry', JSON.stringify(Object.keys(now)));
    t.check((now.seealso || []).length === 1 &&
            (now.l || []).join() === 'Lisbon',
            'K' + n + 'a. after ' + label + ', seeAlso and l (added over ' +
            'LDAP, not modelled) are still on the entry',
            JSON.stringify([now.seealso, now.l]));
    t.check((now.oauthredirecturi || []).join() === KEPT_URI &&
            (now.appcertificatehostname || []).join() === 'aeuapp.example',
            'M' + n + '. after ' + label + ', the redirect URI deleted over ' +
            'LDAP stays deleted, and the modelled host name written over ' +
            'LDAP is kept', JSON.stringify([now.oauthredirecturi,
              now.appcertificatehostname]));
    const decided = gate.authenticate(ssfRequest(mine.cert), 'read');
    t.check(decided.ok && decided.scheme === 'clientcert' &&
            decided.principal === APP,
            'S' + n + '. after ' + label + ', the stored certificate is ' +
            'still the application at the Shared Signals door',
            JSON.stringify(decided));
    log.debug("Leaving checkAfter().");
  };

  // -------------------------------------------------------------------------
  // K, M, S: three registry writes, each a save().
  // -------------------------------------------------------------------------
  const ssfSeen = applications.seen({ identifier: APP,
    kind: 'ssf-receiver', protocol: 'SSF',
    fields: { ssfReceiverId: APP } });
  t.check(!!ssfSeen, 'precondition: the ssf-receiver sighting was recorded',
          JSON.stringify(!!ssfSeen));
  checkAfter('an ssf-receiver sighting (POST /ssf/stream\'s)', 1);

  const samlSeen = applications.seen({ identifier: APP,
    kind: 'saml2-service-provider', protocol: 'SAML 2.0', counts: true,
    note: 'was sent a Response',
    fields: { samlAssertionConsumerService: 'https://aeuapp.example/acs' } });
  t.check(!!samlSeen,
          'precondition: the SAML 2.0 service-provider sighting was recorded',
          JSON.stringify(!!samlSeen));
  checkAfter('a SAML 2.0 service-provider sighting', 2);

  const set = adminActions.applicationsAction({ action: 'set',
    application: APP, attribute: 'appName', value: 'AEU renamed' }, [], ctx);
  t.check(set.ok && (entryNow().appname || []).join() === 'AEU renamed',
          'precondition: set of appName through the admin doors wrote it',
          JSON.stringify(set));
  checkAfter('a set of a modelled attribute through the admin doors', 3);

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
  name: 'application_entry_unowned',
  describe: 'A registry write keeps what the registry does not model ' +
            '(#1230): a stored certificate, a bare userCertificate and ' +
            'attributes added over LDAP survive an ssf-receiver sighting, ' +
            'a SAML 2.0 sighting and a set, the certificate still ' +
            'authenticates at the Shared Signals door, and a modelled ' +
            'value removed over LDAP stays removed',
  run: run
};
