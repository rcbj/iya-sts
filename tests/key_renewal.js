// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: key_renewal.js
//
// ===========================================================================
// THE CERTIFICATE AND SIGNING-KEY RENEWALS OF #2220, IN PROCESS.
//
//   A. A CA certificate is renewed over the SAME key and subject: due only
//      inside its lead, the Root first; the certificate it signed before
//      still verifies against the renewed one; the Root it replaced is
//      published as `root-previous`; a renewed-away Intermediate's serial
//      stays in the Root's register (paranoid PKI mode's OCSP answer).
//   B. The listener certificate is due at a third of its validity or
//      inside its lead, and renewing it changes the certificate and not the
//      key; the switch turns the job off.
//   C. A Kerberos service key is due from its own age, never while the
//      version the last rotation kept is in its window; only this service's
//      own acceptor key is rotated, one with a keytab outstanding is
//      reported.
//   D. The credential signers' and request-decryption keys' schedule counts
//      from FIRST SIGHT, so the run after an upgrade rotates nothing.
//   E. The request-decryption keys are replaced and the replaced key still
//      opens a request object encrypted to it, through the real decrypt
//      site, until its overlap ends.
//
// A and E change the process's own hierarchy and key set, which every later
// file in the same process inherits, so each puts things back
// (`pki_anchor_drift.js`'s reason).
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'key_renewal',
  level: process.env.LOG_LEVEL || 'info' });

const DAY_MS = 86400000;

function spkiOf(pem) {
  log.debug("Entering spkiOf().");
  log.debug("Leaving spkiOf().");
  return new nodeCrypto.X509Certificate(pem).publicKey
    .export({ type: 'spki', format: 'der' }).toString('base64');
}

function signedBy(childPem, parentPem) {
  log.debug("Entering signedBy().");
  log.debug("Leaving signedBy().");
  return new nodeCrypto.X509Certificate(childPem)
    .verify(new nodeCrypto.X509Certificate(parentPem).publicKey);
}

async function caRenewal(t) {
  log.debug("Entering caRenewal().");
  const pki = require('../common/pki');
  const revocation = require('../common/pki_revocation');
  await pki.start();
  const root = pki.serviceRoot();
  const row = pki.rawRowFor('');
  t.check(root && row && row.intermediate, 'A0. a hierarchy to renew');

  const now = Date.now();
  t.check(!pki.caTierDue(root, null, now).due,
          'A1. a Root built now is not due');
  const late = new Date(root.notAfter).getTime() - 100 * DAY_MS;
  const verdict = pki.caTierDue(root, null, late);
  t.check(verdict.due, 'A2. inside its lead it is due', verdict.why);
  const plan = pki.caRenewalPlan(late);
  t.check(plan[0] && plan[0].tier === 'root',
          'A3. the plan is top down: the Root first');

  const done = await pki.renewCaCertificate(pki.SERVICE_SCOPE, 'root', null,
                                            late);
  t.check(done.ok && done.renewed, 'A4. the Root is renewed',
          JSON.stringify(done.errors || done.why || ''));
  const renewed = pki.serviceRoot();
  t.check(renewed.certificatePem !== root.certificatePem &&
          renewed.serialHex !== root.serialHex,
          'A5. a new certificate, with a new serial');
  t.equal(spkiOf(renewed.certificatePem), spkiOf(root.certificatePem),
          'A6. OVER THE SAME KEY, so a pin on the key holds');
  t.equal(new nodeCrypto.X509Certificate(renewed.certificatePem).subject,
          new nodeCrypto.X509Certificate(root.certificatePem).subject,
          'A7. and with the same subject');
  t.check(signedBy(row.intermediate.certificatePem, renewed.certificatePem),
          'A8. the Intermediate signed by the OLD Root certificate verifies ' +
          'against the renewed one');
  t.check(new Date(renewed.notAfter).getTime() >
          new Date(root.notAfter).getTime(),
          'A9. and the renewal moved the expiry out');
  const previous = pki.previousRootCertificates();
  t.check(previous.length === 1 &&
          previous[0].certificatePem === root.certificatePem,
          'A10. THE ROOT IT REPLACED IS STILL PUBLISHED (root-previous), ' +
          'never silently swapped away');

  // The Intermediate, under the renewed Root, later on.
  const intermediate = pki.rawRowFor('').intermediate;
  const iLate = new Date(intermediate.notAfter).getTime() - 100 * DAY_MS;
  const iDone = await pki.renewCaCertificate('', 'intermediate', null, iLate);
  t.check(iDone.ok && iDone.renewed, 'A11. the Intermediate is renewed',
          JSON.stringify(iDone.errors || iDone.why || ''));
  const iRenewed = pki.rawRowFor('').intermediate;
  t.equal(spkiOf(iRenewed.certificatePem),
          spkiOf(intermediate.certificatePem),
          'A12. over the same key');
  const issuing = pki.rawRowFor('').issuing.jose;
  t.check(signedBy(issuing.certificatePem, iRenewed.certificatePem),
          'A13. the Issuing CA it signed before verifies against it');
  t.check(revocation.issuedHere(pki.SERVICE_SCOPE, 'root',
                                intermediate.serialHex),
          'A14. THE RENEWED-AWAY INTERMEDIATE\'S SERIAL STAYS IN THE ROOT\'S ' +
          'REGISTER, so OCSP answers good rather than unknown for a chain a ' +
          'client still holds');
  t.check(revocation.issuedHere(pki.SERVICE_SCOPE, 'root',
                                iRenewed.serialHex),
          'A15. beside the renewed one');

  // An imported tier, and one its parent clips.
  t.check(!pki.caTierDue(Object.assign({}, issuing, { imported: true }),
                         iRenewed, iLate).due,
          'A16. an imported CA is never renewed');
  const clipped = pki.caTierDue(issuing,
    Object.assign({}, iRenewed, { notAfter: issuing.notAfter }),
    new Date(issuing.notAfter).getTime() - 10 * DAY_MS);
  t.check(!clipped.due && /parent/.test(clipped.why),
          'A17. a CA its parent would clip waits for the parent',
          clipped.why);

  // PUT THE HIERARCHY BACK: the renewals above are dated in the future.
  await pki.buildRoot({ organisation: 'iya-sts' });
  for (const scope of [pki.PROCESS_SCOPE, '']) {
    await pki.buildScope(scope, {});
  }
  await pki.certifyRegistered();
  t.check(pki.previousRootCertificates().length === 0,
          'A18. and a Root REPLACED (a new key) publishes no previous one');
  log.debug("Leaving caRenewal().");
}

async function listenerRenewal(t) {
  log.debug("Entering listenerRenewal().");
  const config = require('../common/config');
  const tls = require('../tls/tls_server');
  const pki = require('../common/pki');
  await pki.start();
  await pki.certifyRegistered();
  const before = tls.serverCertificate();
  t.check(before.chainPem.length > 0, 'B0. a certified listener');
  t.equal(tls.listenerCertificatesDue(Date.now()).length, 0,
          'B1. a fresh listener certificate is not due');
  const notAfter = new Date(new nodeCrypto.X509Certificate(before.certPem)
                              .validTo).getTime();
  t.check(tls.listenerCertificatesDue(notAfter - DAY_MS).length > 0,
          'B2. past two thirds of its validity it is due');
  t.equal(tls.listenerRenewalOffReason(), '',
          'B3. the job is on in a front process');
  config.setOverride('tls.serverCertificateRenewal', 'false');
  t.check(/serverCertificateRenewal/.test(tls.listenerRenewalOffReason()),
          'B4. the switch turns it off');
  config.clearOverride('tls.serverCertificateRenewal');
  const idle = await tls.renewListenerCertificate();
  t.check(!idle.renewed && idle.why === 'not due',
          'B5. a run with nothing due changes nothing');
  config.setOverride('tls.serverCertificateRenewLeadDays', '3650');
  const done = await tls.renewListenerCertificate();
  config.clearOverride('tls.serverCertificateRenewLeadDays');
  const after = tls.serverCertificate();
  t.check(done.renewed, 'B6. inside the lead it is renewed', done.why);
  t.check(after.certPem !== before.certPem,
          'B7. the socket presents a new certificate');
  t.equal(spkiOf(after.certPem), spkiOf(before.certPem),
          'B8. OVER THE SAME KEY');
  log.debug("Leaving listenerRenewal().");
}

async function serviceKeys(t) {
  log.debug("Entering serviceKeys().");
  const krb = require('../kerberos/krb5_krbtgt_rotation');
  const realms = require('../common/realms');
  const now = Date.now();
  const rotated = [];
  const old = new Date(now - 200 * DAY_MS).toISOString();
  const rows = [
    { principal: 'HTTP/sts@EX', spn: 'HTTP/sts', kvno: 1, held: true,
      createdAt: old, rotatedAt: '', retained: [], ownAcceptor: true },
    { principal: 'HTTP/app@EX', spn: 'HTTP/app', kvno: 3, held: true,
      createdAt: old, rotatedAt: '', retained: [], ownAcceptor: false },
    { principal: 'HTTP/new@EX', spn: 'HTTP/new', kvno: 1, held: true,
      createdAt: new Date(now - DAY_MS).toISOString(), rotatedAt: '',
      retained: [], ownAcceptor: true },
    { principal: 'HTTP/open@EX', spn: 'HTTP/open', kvno: 2, held: true,
      createdAt: old, rotatedAt: old,
      retained: [{ kvno: 1, expiresAt: new Date(now + DAY_MS)
                                         .toISOString() }],
      ownAcceptor: true }
  ];
  const deps = krb.KrbtgtRotation.defaultDeps();
  deps.mode = function () {
    return { rotatesKerberosKeys: function () {
      return true;
    } };
  };
  deps.principals = function () {
    return { kerberosRealmOf: function () {
      return { enabled: true, active: true };
    } };
  };
  deps.keys = function () {
    return {
      servicesForRotation: function () {
        return rows;
      },
      rotateServicePrincipal: function (spn, ctx) {
        rotated.push(spn + ' via ' + ctx.via);
        return { ok: true, kvno: 9 };
      }
    };
  };
  deps.now = function () {
    return now;
  };
  const r = new krb.KrbtgtRotation(deps);
  const interval = 180 * DAY_MS;
  t.check(r.serviceDecide(rows[0], now, interval).due,
          'C1. a key 200 days old is due at 180');
  t.check(!r.serviceDecide(rows[2], now, interval).due,
          'C2. a key a day old is not');
  t.check(!r.serviceDecide(rows[3], now, interval).due,
          'C3. never while the version the last rotation kept is still in ' +
          'its window');
  const out = await realms.run(realms.DEFAULT_REALM, function () {
    return r.rotateServicesDue('', { nowMs: function () {
      return now;
    } });
  });
  t.equal(rotated.join(','), 'HTTP/sts via scheduler',
          'C4. ONLY THIS SERVICE\'S OWN ACCEPTOR KEY IS ROTATED');
  t.check(out.due.length === 1 && out.due[0].principal === 'HTTP/app@EX',
          'C5. a key whose keytab was handed out is reported as due, not ' +
          'rotated', JSON.stringify(out.due));
  log.debug("Leaving serviceKeys().");
}

async function firstSight(t) {
  log.debug("Entering firstSight().");
  const renewal = require('../common/key_renewal');
  const realms = require('../common/realms');
  const store = new Map();
  let now = Date.now();
  const calls = [];
  const deps = renewal.KeyRenewal.defaultDeps();
  deps.clock = store;
  deps.now = function () {
    return now;
  };
  deps.mode = function () {
    return { rotatesSigningKeys: function () {
      return true;
    } };
  };
  const held = [{ kind: 'ro', kid: 'ro-1' }, { kind: 'vci', kid: 'vci-1' }];
  deps.keys = function () {
    return {
      stsKeysFor: { of: function () {
        return {};
      } },
      encryptionKeysHeld: function () {
        return held;
      },
      rotateEncryptionKeys: function (realmId, kinds) {
        calls.push(kinds.join(','));
        return Promise.resolve({ ok: true, generation: 2,
          rotated: kinds.map(function (k) {
            return { kind: k, from: k + '-1', to: k + '-2' };
          }) });
      }
    };
  };
  deps.audit = function () {
    return { record: function () {
      // The audit log is not what this section holds.
    } };
  };
  const r = new renewal.KeyRenewal(deps);
  const ctx = { nowMs: function () {
    return now;
  } };
  await realms.run(realms.DEFAULT_REALM, function () {
    return r.rotateEncryptionKeysDue('', ctx);
  });
  t.equal(calls.length, 0,
          'D1. THE FIRST RUN AFTER AN UPGRADE ROTATES NOTHING: it enters ' +
          'every key it sees');
  t.check(store.has('enc:ro:ro-1') && store.has('enc:vci:vci-1'),
          'D2. and each key is entered on the clock');
  now += 181 * DAY_MS;
  await realms.run(realms.DEFAULT_REALM, function () {
    return r.rotateEncryptionKeysDue('', ctx);
  });
  t.equal(calls.join(';'), 'ro,vci',
          'D3. a whole interval later both kinds are replaced');
  t.check(store.has('enc:ro:ro-2'),
          'D4. and the new key is entered at its rotation');
  log.debug("Leaving firstSight().");
}

async function requestKeys(t) {
  log.debug("Entering requestKeys().");
  const helpers = require('../common/helpers');
  const stsCrypto = require('../common/crypto');
  const ro = require('../oauth-oidc/request_object');
  // The default realm by its id, as the scheduler names it.
  const REALM = require('../common/realms').DEFAULT_ID;
  const keys = helpers.stsKeysFor.of(REALM);
  const before = helpers.requestObjectKeysFor(keys);
  const oldKid = before.rsa.publicJwk.kid;
  const compact = stsCrypto.encryptJweCompact('a.b.c', {
    alg: 'RSA-OAEP-256', enc: 'A256GCM', jwk: before.rsa.publicJwk });
  const done = await helpers.rotateEncryptionKeys(REALM, ['ro', 'vci'],
                                                  30 * DAY_MS, 'a test');
  t.check(done.ok && done.rotated.length === 2,
          'E1. the request object and OpenID4VCI keys are replaced',
          JSON.stringify(done));
  const after = helpers.requestObjectKeysFor(helpers.stsKeysFor.of(REALM));
  t.check(after.rsa.publicJwk.kid !== oldKid,
          'E2. a new key is the one published');
  const retired = helpers.retiredEncryptionKeysFor('ro',
    helpers.stsKeysFor.of(REALM));
  t.check(retired.length >= 1 && retired[0].rsa.publicJwk.kid === oldKid,
          'E3. the replaced key is retired, not dropped');
  const inst = new ro.RequestObject(ro.RequestObject.defaultDeps());
  const opened = await inst.decrypt(compact, {}, null,
    helpers.stsKeysFor.of(REALM));
  t.check(opened.ok && opened.jws === 'a.b.c',
          'E4. A REQUEST OBJECT ENCRYPTED TO THE OLD KEY STILL OPENS, ' +
          'through the real decrypt site', JSON.stringify(opened.errors ||
                                                  opened.error || ''));
  const gone = await helpers.rotateEncryptionKeys(REALM, ['ro'], 0, 'a test');
  t.check(gone.ok, 'E5. a rotation with no overlap');
  const stale = helpers.retiredEncryptionKeysFor('ro',
    helpers.stsKeysFor.of(REALM))
    .filter(function (one) {
      return one.rsa.publicJwk.kid === after.rsa.publicJwk.kid;
    });
  t.equal(stale.length, 0,
          'E6. a key past its overlap opens nothing');
  log.debug("Leaving requestKeys().");
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== A. CA certificates renewed over the same key ===');
  await caRenewal(t);
  t.log.info('=== B. the listener certificate without a restart ===');
  await listenerRenewal(t);
  t.log.info('=== C. Kerberos service principal keys ===');
  await serviceKeys(t);
  t.log.info('=== D. counted from first sight ===');
  await firstSight(t);
  t.log.info('=== E. the request-decryption keys ===');
  await requestKeys(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'key_renewal',
  describe: 'the certificate and signing-key renewals of #2220: CA ' +
            'certificates over the same key, the listener without a ' +
            'restart, Kerberos service keys, and the credential signers\' ' +
            'and request-decryption keys\' schedules',
  run: run
};
