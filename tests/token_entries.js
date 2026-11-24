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
  tokens.forgetForTests();
  entries.forgetForTests();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'token_entries',
  describe: 'hardware, OATH and YubiKey OTP tokens on the person\'s entry, ' +
            'the master the register and inventories index (#2051)',
  run: run
};
