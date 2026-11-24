// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: token_entries.js
//
// HARDWARE TOKENS ON THE PERSON'S ENTRY (#2051): the entry is the master and
// the register and inventories its indexes. A token recorded is on its
// holder's `stsHardwareToken` before the register row is written; a lost
// report and a forgotten credential change the entry; a register row whose
// entry write failed is marked pending and the entries job writes it; the
// backfill copies a row recorded before entries held tokens; the rebuild
// makes the register row again from the entries; an OATH and a YubiKey OTP
// value carry no secret; and the directory slot is refused half-filled.

const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
const tokens = require('../common/hardware_tokens');
const entries = require('../common/token_entries');
const oath = require('../common/oath_tokens');
const yubi = require('../common/yubiotp_store');

const log = require('bunyan').createLogger({ name: 'token_entries',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = Date.now().toString(36);
const ANA = 'tke-ana-' + RUN;

function valuesOn(name, attribute) {
  log.debug("Entering valuesOn().");
  const stored = ldap.existingUserEntry(name);
  const out = ((stored && stored.attributes &&
                stored.attributes[attribute.toLowerCase()]) || [])
    .map(entries.read).filter(Boolean);
  log.debug("Leaving valuesOn().");
  return out;
}

async function run(t) {
  log.debug("Entering run().");
  const realm = realms.currentId();
  ldap.createUser(ANA, { invent: false, attributes: {} });
  const key = 'yubico/tke-' + RUN;
  t.check(!entries.setDirectory({ locate: function locate() {
    log.debug("Entering locate().");
    log.debug("Leaving locate().");
    return null;
  } }), '1a. a directory offering part of the slot is refused whole');
  const made = tokens.recordAttested({
    username: ANA, vendor: 'Yubico AB', serial: 'tke-' + RUN,
    model: 'YubiKey 5 NFC', credential: { kind: 'fido', ref: 'c-' + RUN },
    evidence: { source: 'fido-enterprise-attestation' } });
  t.check(made.ok, 'precondition: a token is recorded', JSON.stringify(made));
  const first = valuesOn(ANA, 'stsHardwareToken');
  t.check(first.length === 1 && first[0].key === key && first[0].holder ===
          true && first[0].model === 'YubiKey 5 NFC' &&
          first[0].credentials.length === 1 &&
          first[0].status === 'active',
          '1b. the token is on its holder\'s entry, with their credential',
          JSON.stringify(first));
  await tokens.markLost({ key: key, actor: 'admin', via: 'test' });
  const lost = valuesOn(ANA, 'stsHardwareToken');
  t.check(lost.length === 1 && lost[0].status === 'lost' && lost[0].lost,
          '1c. a lost report is on the entry', JSON.stringify(lost));
  // THE BACKFILL: the entry loses its value, as one written before #2051
  // never had it, and the job's first run puts it back.
  ldap.existingUserEntry(ANA).attributes.stshardwaretoken = [];
  entries.forgetForTests();
  const filled = await entries.syncEntries(realm);
  t.check(filled.ok && filled.backfill && valuesOn(ANA,
          'stsHardwareToken').length === 1,
          '1d. the backfill copies a register row onto its holder',
          JSON.stringify(filled));
  const again = await entries.syncEntries(realm);
  t.check(again.ok && !again.backfill && again.written === 0,
          '1e. a later run reads the pending rows only, and there are none',
          JSON.stringify(again));
  // THE REBUILD: the register loses the row, and the entries make it again.
  const before = tokens.byKey(key);
  tokens.forgetForTests();
  t.check(tokens.byKey(key) === null, 'precondition: the register lost it');
  const rebuilt = await entries.rebuildIndexes(realm);
  const after = tokens.byKey(key);
  t.check(rebuilt.ok && after && after.status === 'lost' &&
          after.holder === before.holder && after.credentials.length ===
          before.credentials.length,
          '1f. the register row is rebuilt from the entry, the master',
          JSON.stringify({ rebuilt: rebuilt, after: after }));
  // A WRITE THAT CANNOT REACH THE ENTRY is pending, and the job writes it.
  const real = entries.installedDirectory();
  entries.setDirectory(Object.assign({}, real, {
    write: function write() {
      log.debug("Entering write().");
      log.debug("Leaving write(). Refused.");
      return false;
    } }));
  const second = tokens.recordAttested({
    username: ANA, vendor: 'Yubico AB', serial: 'tkf-' + RUN,
    credential: { kind: 'fido', ref: 'd-' + RUN },
    evidence: { source: 'fido-enterprise-attestation' } });
  t.check(second.ok && !valuesOn(ANA, 'stsHardwareToken').some(function (v) {
    return v.key === 'yubico/tkf-' + RUN;
  }), '1g. a token whose entry write failed is still recorded');
  entries.setDirectory(real);
  const retried = await entries.syncEntries(realm);
  t.check(retried.ok && retried.written === 1 &&
          valuesOn(ANA, 'stsHardwareToken').some(function (v) {
            return v.key === 'yubico/tkf-' + RUN;
          }), '1h. the entries job writes the pending row onto the entry',
          JSON.stringify(retried));
  // THE OATH AND YUBIKEY OTP VALUES CARRY NO SECRET.
  const ov = oath.entryValueOf('v/s/1', { kind: 'hotp', serial: 's',
    secret: 'SEALED', status: 'assigned', holder: 'x' });
  const yv = yubi.entryValueOf('123', { publicId: 'cccc', secret: 'SEALED',
    status: 'assigned', holder: ANA });
  t.check(ov.key === 'v/s/1' && ov.status === 'assigned' &&
          !('secret' in ov) && !('holder' in ov),
          '1i. an OATH token\'s value carries its description, no secret');
  t.check(yv.serial === '123' && yv.publicId === 'cccc' &&
          !('secret' in yv), '1j. a YubiKey OTP\'s value carries no AES key');
  await checkObserver(t, realm);
  tokens.forgetForTests();
  entries.forgetForTests();
  log.debug("Leaving run().");
}

// Gives the promise jobs a handler started time to finish.
async function settled(test) {
  log.debug("Entering settled().");
  for (let i = 0; i < 200; i++) {
    if (await test()) {
      log.debug("Leaving settled(). Held.");
      return true;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 10);
    });
  }
  log.debug("Leaving settled(). Never held.");
  return false;
}

// The entry's attributes, with one attribute's values replaced, written
// back through `writePerson()` — a directory write by another door, which
// reaches `noteAccountChange()` as an LDAP modify does.
function rewrite(name, attribute, values) {
  log.debug("Entering rewrite().");
  const view = ldap.objectFor(name);
  const attrs = Object.assign({}, view.entry.attributes || view.entry);
  Object.keys(attrs).forEach(function (key) {
    if (key.toLowerCase() === attribute.toLowerCase()) {
      delete attrs[key];
    }
  });
  if (values) {
    attrs[attribute] = values;
  }
  const out = ldap.writePerson(view.dn, attrs);
  log.debug("Leaving rewrite().");
  return out;
}

// THE ONE OBSERVER (#2051): all five credential kinds are handed over by
// `common/entry_observer.ts`, and a directory write by another door keeps
// the index right without the manual rebuild.
async function checkObserver(t, realm) {
  log.debug("Entering checkObserver().");
  require('../common/ssh_issued');
  require('../common/openpgp_keys');
  const observer = require('../common/entry_observer');
  const five = ['stsHardwareToken', 'stsOathToken', 'stsSshUserCertificate',
                'stsYubiOtpToken', 'userSMIMECertificate'];
  t.equal(observer.registered().join(','), five.join(','),
          '2a. one observer holds the handlers of all five credential kinds');
  const told = observer.entryChanged({ kind: 'updated', realm: realm,
    dn: 'uid=nobody-' + RUN + ',ou=users', username: 'nobody-' + RUN,
    subject: '', before: {},
    after: { stshardwaretoken: ['{}'], stsoathtoken: ['{}'],
             stsyubiotptoken: ['{}'], stssshusercertificate: ['{}'],
             'usersmimecertificate;binary': ['x'] } });
  t.equal(told.slice().sort().join(','), five.join(','),
          '2b. a write moving each of the five is handed to each owner');
  const BEA = 'tke-bea-' + RUN;
  ldap.createUser(BEA, { invent: false, attributes: {} });
  const key = 'yubico/tkb-' + RUN;
  const made = tokens.recordAttested({
    username: BEA, vendor: 'Yubico AB', serial: 'tkb-' + RUN,
    credential: { kind: 'fido', ref: 'b-' + RUN },
    evidence: { source: 'fido-enterprise-attestation' } });
  t.check(made.ok && valuesOn(BEA, 'stsHardwareToken').length === 1,
          'precondition: a token on the entry of ' + BEA);
  // Through /admin-api's source: the token subject is the writer named.
  const audit = require('../common/audit');
  audit.withSource({ req: { headers: {}, socket: {},
    res: { locals: { apiCaller: { name: 'api-admin-' + RUN } } } } },
  function () {
    return rewrite(BEA, 'stsHardwareToken', null);
  });
  t.check(await settled(async function () {
    return tokens.byKey(key) === null;
  }), '2c. a directory write removing the token updates the register at ' +
      'once, with no rebuild: nobody holds it, so it is gone',
          JSON.stringify(tokens.byKey(key)));
  const removedRow = audit.list().filter(function (e) {
    return e.action === 'hardware-token.entry-removed' && e.detail &&
      e.detail.key === key;
  })[0] || null;
  t.equal(removedRow && removedRow.actor, 'api-admin-' + RUN,
          '2e. and the audit row names the API caller who removed it');
  const invented = entries.stored({ key: 'yubico/invented-' + RUN,
    vendor: 'yubico', serial: 'invented-' + RUN, holder: true,
    status: 'active', credentials: [{ kind: 'fido', ref: 'z' }] });
  // Through SCIM's source: the SCIM client is the writer named.
  audit.withSource({ req: { headers: {}, socket: {}, res: { locals: {} },
    scimAuth: { principal: 'scim-client-' + RUN } } }, function () {
    return rewrite(BEA, 'stsHardwareToken', [invented]);
  });
  t.check(await settled(async function () {
    return valuesOn(BEA, 'stsHardwareToken').length === 0;
  }) && tokens.byKey('yubico/invented-' + RUN) === null,
          '2d. a token written onto the entry by another door is taken off ' +
          'again and makes no register row: a serial comes only from ' +
          'attestation');
  const refusedRow = audit.list().filter(function (e) {
    return e.action === 'hardware-token.entry-refused' && e.detail &&
      e.detail.key === 'yubico/invented-' + RUN;
  })[0] || null;
  t.equal(refusedRow && refusedRow.actor, 'scim-client-' + RUN,
          '2f. and the refusal\'s audit row names the SCIM client');
  log.debug("Leaving checkObserver().");
}

module.exports = {
  name: 'token_entries',
  describe: 'hardware, OATH and YubiKey OTP tokens on the person\'s entry, ' +
            'the master the register and inventories index (#2051)',
  run: run
};
