// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: tests/oath_tokens.js
//
// ===========================================================================
// THE OATH TOKEN INVENTORY (#1955 P4): `common/oath_tokens.ts`.
//
//   1. IMPORT: RFC 6030's Figure 6 under its pre-shared key becomes one
//      UNASSIGNED token keyed by vendor, serial and key id; a page's view
//      carries no secret; the same key again is skipped (STS-OATH-0030);
//      a failed import is refused whole.
//   2. ASSIGNMENT BY AN ADMINISTRATOR: the token becomes the person's HOTP
//      credential, the hardware token register records it with evidence
//      `pskc-import`, the row drops its secret, and a code from it EARNS
//      `hwk` (design X3) — a QR-enrolled secret's never does. Assigning it
//      again is refused (STS-OATH-0041), as is a name with no entry.
//   3. THE PERSON'S CLAIM: a wrong serial and a wrong code are one refusal;
//      the right pair assigns the token with that code SPENT, for an HOTP
//      token (Figure 7, by its password) and a TOTP token (made in the run).
//   4. THE LOST KEY (design X2): reporting the register's token lost runs
//      the `hotp` retirer this module installs — the credential leaves the
//      entry, the inventory row is retired, and no `hwk` is earned again.
//   5. REMOVAL: an unassigned token may be removed; an assigned one may not
//      (STS-OATH-0049).
//   6. REALM ISOLATION: a token imported in one realm can be neither
//      assigned nor claimed in another.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const credentials = require('../common/credentials');
const hotp = require('../common/hotp');
const totp = require('../common/totp');
const tokens = require('../common/oath_tokens');
const register = require('../common/hardware_tokens');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const counters = require('../cluster/cluster_counters');
const ldap = require('../ldap/ldap_server');
const fixtures = require('./pskc');

const log = require('bunyan').createLogger({
  name: 'oath_tokens', level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const ADMIN = 'oath-admin-' + RUN;
const ANN = 'oath-ann-' + RUN;
const BEN = 'oath-ben-' + RUN;
const CAT = 'oath-cat-' + RUN;
const RFC_B32 = totp.base32Encode(Buffer.from('12345678901234567890'));
const FIGURE6_TOKEN = 'manufacturer/987654321/12345678';
const FIGURE7_TOKEN = 'tokenvendoracme/987654321/123456';

function codeOf(result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return errorCodes.codeOf(result) || '';
}

async function checkImport(t) {
  log.debug("Entering checkImport().");
  t.log.info('=== 1. import ===');
  const refused = await tokens.importPskc({ pskc: fixtures.FIGURES.fig6,
    preSharedKey: '00112233445566778899aabbccddeeff', actor: ADMIN });
  t.check(!refused.ok && codeOf(refused) === 'STS-OATH-0026',
          'a file opened with the wrong key imports nothing');
  const done = await tokens.importPskc({ pskc: fixtures.FIGURES.fig6,
    preSharedKey: fixtures.FIGURE6_KEY, actor: ADMIN, via: 'test' });
  t.check(done.ok && done.imported.length === 1 &&
          done.imported[0].key === FIGURE6_TOKEN &&
          done.imported[0].status === 'unassigned' &&
          done.protection === 'pre-shared',
          'Figure 6 is one UNASSIGNED token keyed by vendor, serial and key ' +
          'id', JSON.stringify(done.imported));
  t.check(!('secret' in done.imported[0]) &&
          JSON.stringify(done).indexOf(RFC_B32) < 0,
          'NO ANSWER CARRIES THE SECRET');
  const again = await tokens.importPskc({ pskc: fixtures.FIGURES.fig3,
                                          actor: ADMIN });
  t.check(again.ok && again.imported.length === 0 &&
          again.skipped[0].errorCode === 'STS-OATH-0030',
          'Figure 3 is the same device and key, and is skipped as already ' +
          'held', JSON.stringify(again.skipped));
  const listed = await tokens.list({ status: 'unassigned', q: '987654321' });
  t.check(listed.ok && listed.tokens.some(function (r) {
    return r.key === FIGURE6_TOKEN;
  }), 'the inventory lists it by its serial');
  log.debug("Leaving checkImport().");
}

async function checkAssign(t) {
  log.debug("Entering checkAssign().");
  t.log.info('=== 2. assignment by an administrator ===');
  t.equal(codeOf(await tokens.assign({ key: FIGURE6_TOKEN,
    username: 'nobody-' + RUN, actor: ADMIN })), 'STS-OATH-0042',
          'a name with no entry is refused');
  const given = await tokens.assign({ key: FIGURE6_TOKEN, username: ANN,
                                      actor: ADMIN, via: 'api' });
  t.check(given.ok && given.token.status === 'assigned' &&
          given.token.holder === ANN, 'the token is assigned to Ann',
          JSON.stringify(given.token || given.errors));
  const held = credentials.mechanismsFor(ANN);
  t.check(held.hotp && held.hotpDetail.source === 'pskc-import' &&
          held.hotpDetail.token === FIGURE6_TOKEN &&
          held.hotpDetail.digits === 8,
          'it is her HOTP credential, eight digits, naming its token');
  const inRegister = await register.tokensOf(ANN);
  const row = inRegister.filter(function (r) {
    return r.key === 'manufacturer/987654321';
  })[0];
  t.check(!!row && row.credentials.some(function (c) {
    return c.kind === 'hotp' && c.ref === FIGURE6_TOKEN &&
           c.source === 'pskc-import';
  }), 'THE HARDWARE TOKEN REGISTER RECORDS IT, evidence pskc-import',
          JSON.stringify(row || inRegister));
  const first = await credentials.verifyTotpAsync(ANN,
    fixtures.EIGHT_DIGIT[0]);
  t.check(first.ok && first.kind === 'hotp' && first.hardware === true,
          'A CODE FROM THE IMPORTED TOKEN EARNS hwk (design X3)',
          JSON.stringify(first));
  t.equal(codeOf(await tokens.assign({ key: FIGURE6_TOKEN, username: BEN,
                                       actor: ADMIN })), 'STS-OATH-0041',
          'an assigned token cannot be assigned again');
  const listed = await tokens.list({ q: FIGURE6_TOKEN.split('/')[1] });
  t.check(listed.tokens.some(function (r) {
    return r.key === FIGURE6_TOKEN && r.status === 'assigned';
  }), 'the inventory shows it assigned');

  // A QR-enrolled secret, for the contrast X3 draws.
  const begun = credentials.beginHotpEnrolment(CAT,
                                               { base: 'https://localhost' });
  await credentials.confirmHotpEnrolment(CAT,
    hotp.codeAt(begun.secret, 0, { digits: begun.digits }));
  const qr = await credentials.verifyTotpAsync(CAT,
    hotp.codeAt(begun.secret, 1, { digits: begun.digits }));
  t.check(qr.ok && qr.kind === 'hotp' && qr.hardware === false,
          'A SECRET ENROLLED FROM A QR CODE NEVER EARNS hwk',
          JSON.stringify(qr));
  log.debug("Leaving checkAssign().");
}

async function checkClaim(t) {
  log.debug("Entering checkClaim().");
  t.log.info('=== 3. the person\'s claim ===');
  const seven = await tokens.importPskc({ pskc: fixtures.FIGURES.fig7,
    password: fixtures.FIGURE7_PASSWORD, actor: ADMIN });
  t.check(seven.ok && seven.imported.length === 1 &&
          seven.imported[0].key === FIGURE7_TOKEN,
          'Figure 7 is imported by its password', JSON.stringify(seven));
  const wrongSerial = await tokens.claim({ username: BEN,
    serial: '111111111', code: fixtures.EIGHT_DIGIT[0] });
  const wrongCode = await tokens.claim({ username: BEN,
    serial: '987654321', code: '12345678' });
  t.check(codeOf(wrongSerial) === 'STS-OATH-0043' &&
          codeOf(wrongCode) === 'STS-OATH-0043' &&
          wrongSerial.error === wrongCode.error,
          'A WRONG SERIAL AND A WRONG CODE ARE ONE REFUSAL, so a claim ' +
          'cannot tell which serials are in stock');
  const claimed = await tokens.claim({ username: BEN, serial: '987654321',
                                       code: fixtures.EIGHT_DIGIT[0] });
  t.check(claimed.ok && claimed.token.key === FIGURE7_TOKEN &&
          claimed.token.assignedVia === 'claim',
          'the serial and a current code claim it', JSON.stringify(claimed));
  t.check(!(await credentials.verifyTotpAsync(BEN,
          fixtures.EIGHT_DIGIT[0])).ok,
          'THE CLAIM\'S CODE IS SPENT: it cannot also sign in');
  t.check((await credentials.verifyTotpAsync(BEN,
          fixtures.EIGHT_DIGIT[1])).ok, 'the next one does');

  t.log.info('--- a TOTP token ---');
  const made = fixtures.generatedContainer({ serial: 'TOTP-' + RUN,
                                             period: 30 });
  const imported = await tokens.importPskc({ pskc: made.xml,
    preSharedKey: made.key.toString('hex'), actor: ADMIN });
  t.check(imported.ok && imported.imported[0].kind === 'totp',
          'a TOTP token is imported');
  const record = { secret: totp.base32Encode(made.secret), digits: 6,
                   period: 30, algorithm: 'SHA256' };
  const now = totp.codeAt(record.secret, Date.now(), record);
  const got = await tokens.claim({ username: CAT, serial: 'TOTP-' + RUN,
                                   code: now });
  t.check(got.ok && credentials.totpOf(CAT).source === 'pskc-import',
          'claimed, it is her authenticator, from the import',
          JSON.stringify(got));
  t.check(!(await credentials.verifyTotpAsync(CAT, now)).ok,
          'and the claim spent the step it was claimed with');
  log.debug("Leaving checkClaim().");
}

async function checkLost(t) {
  log.debug("Entering checkLost().");
  t.log.info('=== 4. the lost key ===');
  t.check(register.retirerKinds().indexOf('hotp') >= 0 &&
          register.retirerKinds().indexOf('totp') >= 0,
          'the hotp and totp retirers are installed in the register');
  const lost = await register.markLost({ key: 'manufacturer/987654321',
    actor: ADMIN, via: 'api', initiatingEntity: 'admin' });
  t.check(lost.ok && lost.retired.some(function (r) {
    return r.kind === 'hotp' && r.ref === FIGURE6_TOKEN;
  }) && !lost.notRetired.length,
          'REPORTING THE TOKEN LOST RETIRES ITS HOTP SECRET',
          JSON.stringify(lost.retired || lost.errors) + ' ' +
          JSON.stringify(lost.notRetired));
  t.check(!credentials.mechanismsFor(ANN).hotp,
          'the credential has left Ann\'s entry');
  const listed = await tokens.list({ q: '987654321', status: 'retired' });
  t.check(listed.tokens.some(function (r) {
    return r.key === FIGURE6_TOKEN;
  }), 'and the inventory row is retired');
  t.equal(codeOf(await tokens.assign({ key: FIGURE6_TOKEN, username: ANN,
                                       actor: ADMIN })), 'STS-OATH-0041',
          'A RETIRED TOKEN IS NOT ASSIGNED AGAIN: its secret may be with ' +
          'whoever found it');
  log.debug("Leaving checkLost().");
}

async function checkRemove(t) {
  log.debug("Entering checkRemove().");
  t.log.info('=== 5. removal ===');
  const made = fixtures.generatedContainer({ serial: 'GONE-' + RUN });
  const imported = await tokens.importPskc({ pskc: made.xml,
    preSharedKey: made.key.toString('hex'), actor: ADMIN });
  const key = imported.imported[0].key;
  t.check((await tokens.remove({ key: key, actor: ADMIN })).ok,
          'an unassigned token is removed');
  t.equal(codeOf(await tokens.remove({ key: FIGURE7_TOKEN, actor: ADMIN })),
          'STS-OATH-0049', 'an assigned one is not');
  log.debug("Leaving checkRemove().");
}

async function checkIsolation(t) {
  log.debug("Entering checkIsolation().");
  t.log.info('=== 6. realm isolation ===');
  const made = fixtures.generatedContainer({ serial: 'HOME-' + RUN });
  const imported = await tokens.importPskc({ pskc: made.xml,
    preSharedKey: made.key.toString('hex'), actor: ADMIN });
  const key = imported.imported[0].key;
  const id = 'oath-' + RUN;
  const created = realms.create({ id: id, name: id,
                                  description: 'Created by ' + __filename });
  if (!created.ok) {
    t.bad('could not create the realm "' + id + '"',
          (created.errors || []).join(' '));
    log.debug("Leaving checkIsolation().");
    return;
  }
  try {
    const seen = await realms.run(created.realm, async function () {
      ldap.createUser(ANN, { invent: false, attributes: {} });
      const record = { secret: totp.base32Encode(made.secret), digits: 6,
                       period: 60, algorithm: 'SHA256' };
      return {
        assign: await tokens.assign({ key: key, username: ANN,
                                      actor: ADMIN }),
        claim: await tokens.claim({ username: ANN, serial: 'HOME-' + RUN,
          code: totp.codeAt(record.secret, Date.now(), record) }),
        list: await tokens.list({ q: 'HOME-' + RUN })
      };
    });
    t.check(codeOf(seen.assign) === 'STS-OATH-0040' &&
            codeOf(seen.claim) === 'STS-OATH-0043' &&
            seen.list.tokens.length === 0,
            'A TOKEN IMPORTED IN ONE REALM IS UNKNOWN TO ANOTHER: not ' +
            'assigned, not claimed, not listed',
            codeOf(seen.assign) + ' ' + codeOf(seen.claim));
  } finally {
    realms.remove(id);
  }
  const home = await tokens.list({ q: 'HOME-' + RUN });
  t.check(home.tokens.length === 1, 'and it is still in its own realm\'s');
  log.debug("Leaving checkIsolation().");
}

async function run(t) {
  log.debug("Entering run().");
  counters.reset();
  [ADMIN, ANN, BEN, CAT].forEach(function (name) {
    ldap.createUser(name, { invent: false, attributes: {} });
  });
  await checkImport(t);
  await checkAssign(t);
  await checkClaim(t);
  await checkLost(t);
  await checkRemove(t);
  await checkIsolation(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oath_tokens',
  describe: 'issue #1955 P4: imported OATH tokens — PSKC import into an ' +
            'unassigned inventory, assignment and a person\'s claim, ' +
            'pskc-import evidence earning hwk, the lost-key retirer and ' +
            'realm isolation',
  run: run
};
