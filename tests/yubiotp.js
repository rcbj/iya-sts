// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: tests/yubiotp.js
//
// ===========================================================================
// YUBICO OTP, CHECKED ON THIS SERVICE (#1955 P5, design S4, decision D4).
//
//   1. The published AES block and the published HMAC-SHA1, through
//      `crypto.yubiotpDecrypt()` and `crypto.yubiotpHmacSha1()`. The
//      32-character vector has no public identity, so it is not opened
//      as an OTP.
//   2. `yubiotp.open()`: a public identity in front of that block, a
//      ciphertext with no public identity refused, and a composite of
//      zero refused before any counter is stored.
//   3. Enrolment's two steps. The programming line is not logged. The
//      confirmation OTP is spent. The next one signs in as `yubiotp`,
//      `hardware` false, and the same one again is a replay. A person
//      who holds only this credential and types anything else is told
//      the shape. `secondFactor` stays the one-time-code step.
//   4. YK-VAL 2.0 through `ykval.verify()`: off, the status is
//      OPERATION_NOT_ALLOWED and unsigned. On, a signed OTP is OK, the
//      same OTP is REPLAYED_OTP, and a bad HMAC is BAD_SIGNATURE and
//      unsigned.
//
// Every secret here is a published test vector or one generated in the
// run. The programming line is never written to the log or to an
// assertion's detail.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const crypto = require('../common/crypto');
const config = require('../common/config');
const yubiotp = require('../common/yubiotp');
const authnPolicy = require('../common/authn_policy');
const yubiStore = require('../common/yubiotp_store');
const credentials = require('../common/credentials');
const errorCodes = require('../common/error_codes');
const ldap = require('../ldap/ldap_server');
const counters = require('../cluster/cluster_counters');
const ykval = require('../authn/ykval');

const log = require('bunyan').createLogger({
  name: 'yubiotp', level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');

// developers.yubico.com: AES-128-ECB of one block, no padding.
const YUBICO_KEY = 'ecde18dbe76fbd0c33330f1c354871db';
const YUBICO_CIPHER = '69b6481c8baba2b60e8f22179b58cd56';

// The same site's 32-character modhex block. It has no public identity.
const MODHEX_KEY = '000102030405060708090a0b0c0d0e0f';
const MODHEX_OTP = 'dvgtiblfkbgturecfllberrvkinnctnn';
const MODHEX_PRIVATE = '010203040506';

// YK-VAL 2.0's published HMAC-SHA1, base64, over the sorted parameters.
const HMAC_SECRET = 'mG5be6ZJU1qBGz24yPh/ESM3UdU=';
const HMAC_MESSAGE = 'id=1&nonce=jrFwbaYFhn0HoxZIsd9LQ6w2ceU&' +
  'otp=vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft';
const HMAC_DIGEST = '+ja8S3IjbX593/LAgTBixwPNGX4=';

function codeOf(result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return errorCodes.codeOf(result) || '';
}

function person(label) {
  log.debug("Entering person().");
  const name = 'yubi-' + label + '-' + RUN;
  ldap.createUser(name, { invent: false, attributes: {} });
  log.debug("Leaving person().");
  return name;
}

function nonce() {
  log.debug("Entering nonce().");
  const out = nodeCrypto.randomBytes(12).toString('hex');
  log.debug("Leaving nonce().");
  return out;
}

function checkVectors(t) {
  log.debug("Entering checkVectors().");
  t.log.info('=== 1. the published block and the published HMAC ===');
  const block = crypto.yubiotpDecrypt(YUBICO_KEY, YUBICO_CIPHER);
  t.check(block.ok && block.fields.privateId === '8792ebfe26cc' &&
          block.fields.use === 19 && block.fields.session === 17 &&
          block.fields.random === 0x9fc8 && block.fields.crc === 0xc823 &&
          block.fields.crcOk,
          'the published AES block decrypts, and its CRC residual is ' +
          '0xf0b8',
          JSON.stringify(block.ok ? {
            use: block.fields.use, session: block.fields.session,
            crcOk: block.fields.crcOk } : block));
  const modhex = crypto.yubiotpDecrypt(MODHEX_KEY, MODHEX_OTP);
  t.check(modhex.ok && modhex.fields.privateId === MODHEX_PRIVATE &&
          modhex.fields.use === 1 && modhex.fields.session === 1 &&
          modhex.fields.crcOk,
          'the 32-character modhex block decrypts to use 1, session 1');
  t.equal(crypto.yubiotpHmacSha1(HMAC_SECRET, HMAC_MESSAGE), HMAC_DIGEST,
          'YK-VAL\'s published HMAC-SHA1 matches, padding included');
  t.equal(yubiotp.composite(1, 1), 257, 'use 1 and session 1 is 257');
  t.check(yubiotp.composite(2, 0) > yubiotp.composite(1, 255),
          'a wrapped session counter is strictly greater than the ' +
          'previous use\'s last session');
  log.debug("Leaving checkVectors().");
}

function checkOpen(t) {
  log.debug("Entering checkOpen().");
  t.log.info('=== 2. open: a public identity, and a zero counter ===');
  const pub = 'cccccccccccc';
  const opened = yubiotp.open({
    k: MODHEX_KEY, p: MODHEX_PRIVATE, publicId: pub
  }, pub + MODHEX_OTP);
  t.check(opened.ok && opened.fields.use === 1 &&
          opened.fields.session === 1 && opened.fields.composite === 257 &&
          opened.fields.publicId === pub,
          'a public identity in front of the published block opens',
          opened.ok ? '' : (opened.reason + ' ' + codeOf(opened)));
  const bare = yubiotp.open({
    k: MODHEX_KEY, p: MODHEX_PRIVATE, publicId: pub
  }, MODHEX_OTP);
  t.check(!bare.ok && bare.reason === 'shape' &&
          codeOf(bare) === 'STS-YUBIOTP-0001',
          '32 modhex characters and no public identity is refused by ' +
          'shape', codeOf(bare));
  const minted = yubiotp.generate();
  const secret = { k: minted.k, p: minted.p, publicId: minted.publicId };
  const zero = yubiotp.open(secret, yubiotp.otpFor(secret, 0, 0));
  t.check(!zero.ok && zero.reason === 'shape' &&
          codeOf(zero) === 'STS-YUBIOTP-0025',
          'a composite of zero is refused before it can be stored',
          codeOf(zero));
  log.debug("Leaving checkOpen().");
}

async function checkPerson(t) {
  log.debug("Entering checkPerson().");
  t.log.info('=== 3. enrolment, and the one-time code door ===');
  const off = await ykval.verify({
    id: '1', otp: 'x', nonce: nonce(), h: 'aa' });
  t.check(off.status === 'OPERATION_NOT_ALLOWED' &&
          off.code === 'STS-YUBIOTP-0012' && off.key === '',
          'YK-VAL answers OPERATION_NOT_ALLOWED, unsigned, while it is ' +
          'off', off.status + ' ' + off.code);
  const name = person('one');
  const refused = credentials.beginYubiEnrolment(name);
  t.check(!refused.ok && codeOf(refused) === 'STS-YUBIOTP-0007',
          'enrolment is off until yubiotp.offered is on',
          codeOf(refused));
  config.setOverride('yubiotp.offered', true);
  const begun = credentials.beginYubiEnrolment(name);
  const line = String(begun.ykman || '');
  t.check(begun.ok && begun.publicId &&
          line.indexOf('ykman otp yubiotp 1 --public-id ') === 0 &&
          line.indexOf(begun.publicId) > 0,
          'an enrolment returns a slot-1 programming line and nothing ' +
          'is stored yet');
  t.check(!credentials.mechanismsFor(name).yubi,
          'NOTHING IS WRITTEN until an OTP confirms it');
  const pending = credentials.pendingYubiFor(name);
  const secret = {
    k: pending.k, p: pending.p, publicId: pending.publicId };
  const first = yubiotp.otpFor(secret, 1, 1);
  const confirmed = await credentials.confirmYubiEnrolment(name, first);
  t.check(confirmed.ok && confirmed.kind === 'yubiotp',
          'use 1 session 1 confirms the enrolment',
          confirmed.ok ? '' : codeOf(confirmed));
  const held = credentials.mechanismsFor(name);
  t.check(held.yubi && held.oneTimeCode && !held.totp && !held.hotp &&
          held.secondFactor === 'totp' && held.mfaRequired,
          'the person holds a one-time code (the code step), and the ' +
          'step stays totp',
          JSON.stringify({ yubi: held.yubi, totp: held.totp,
                           hotp: held.hotp, secondFactor: held.secondFactor,
                           oneTimeCode: held.oneTimeCode }));
  const demand = credentials.secondFactorDemand(name);
  t.check(demand.yubi && demand.totp && !demand.hotp,
          'the KDC is told a one-time code may be asked for, and that ' +
          'it is a YubiKey OTP');
  const again = await credentials.verifyTotpAsync(name, first);
  t.check(!again.ok && again.reason === 'replay' &&
          codeOf(again) === 'STS-YUBIOTP-0004',
          'THE CONFIRMATION\'S OTP IS SPENT: it cannot also sign in',
          codeOf(again));
  const second = yubiotp.otpFor(secret, 1, 2);
  const signed = await credentials.verifyTotpAsync(name, second);
  t.check(signed.ok && signed.kind === 'yubiotp' &&
          signed.hardware === false && signed.composite === 258,
          'the next OTP signs in as yubiotp, and hardware stays false',
          signed.ok ? String(signed.hardware) : codeOf(signed));
  const replay = await credentials.verifyTotpAsync(name, second);
  t.check(!replay.ok && replay.reason === 'replay' &&
          codeOf(replay) === 'STS-YUBIOTP-0004',
          'the same OTP again is refused', codeOf(replay));
  const shape = await credentials.verifyTotpAsync(name, '123456');
  t.check(!shape.ok && shape.reason === 'shape' &&
          codeOf(shape) === 'STS-YUBIOTP-0001',
          'a person who holds only a YubiKey OTP and types anything ' +
          'else is told the shape', codeOf(shape));
  log.debug("Leaving checkPerson().");
  return { name: name, secret: secret };
}

async function checkYkval(t, secret) {
  log.debug("Entering checkYkval().");
  t.log.info('=== 4. YK-VAL 2.0 ===');
  config.setOverride('yubiotp.ykval', true);
  const id = String(100000 + nodeCrypto.randomBytes(2).readUInt16BE(0));
  const added = yubiStore.addClient({ id: id });
  t.check(added.ok && added.id === id && added.key,
          'a YK-VAL client is created and its key is answered once');
  const otp = yubiotp.otpFor(secret, 2, 0);
  const n1 = nonce();
  const params = { id: id, otp: otp, nonce: n1 };
  params.h = yubiotp.sign(added.key, params);
  const ok = await ykval.verify(params);
  t.check(ok.status === 'OK' && ok.code === '' && ok.fields &&
          ok.fields.sl === '100' && ok.key === added.key,
          'a signed OTP is OK', ok.status + ' ' + ok.code);
  const n2 = nonce();
  const againParams = { id: id, otp: otp, nonce: n2 };
  againParams.h = yubiotp.sign(added.key, againParams);
  const replayed = await ykval.verify(againParams);
  t.check(replayed.status === 'REPLAYED_OTP' &&
          replayed.code === 'STS-YUBIOTP-0018',
          'the same OTP through YK-VAL is REPLAYED_OTP',
          replayed.status + ' ' + replayed.code);
  const bad = await ykval.verify({
    id: id, otp: otp, nonce: nonce(), h: 'not-a-signature' });
  t.check(bad.status === 'BAD_SIGNATURE' &&
          bad.code === 'STS-YUBIOTP-0014' && bad.key === '',
          'a bad HMAC is BAD_SIGNATURE and unsigned',
          bad.status + ' ' + bad.code + ' key=' + (bad.key ? 'set' : ''));
  log.debug("Leaving checkYkval().");
}

// The policy's `yubico-otp` row (#1955 P5): off stops enrolment even when
// `yubiotp.offered` is on, and a save that leaves the row out keeps it.
function checkPolicy(t) {
  log.debug("Entering checkPolicy().");
  t.log.info('=== 5. the authentication policy\'s yubico-otp row ===');
  const before = authnPolicy.read('default');
  const values = {};
  Object.keys(before).forEach(function (key) {
    if (/Primary$|SecondFactor$|^require|^email|^remembered/.test(key)) {
      values[key] = before[key];
    }
  });
  config.setOverride('yubiotp.offered', true);
  try {
    const off = authnPolicy.save('default', Object.assign({}, values,
                                 { yubicoOtpSecondFactor: false }));
    t.check(off.ok &&
            authnPolicy.read('default').yubicoOtpSecondFactor === false &&
            !yubiotp.offered(),
            'the row turns YubiKey OTP enrolment off even when ' +
            'yubiotp.offered is on',
            JSON.stringify(off.errors || []));
    const older = Object.assign({}, values);
    delete older.yubicoOtpSecondFactor;
    const kept = authnPolicy.save('default', older);
    t.check(kept.ok &&
            authnPolicy.read('default').yubicoOtpSecondFactor === false,
            'A SAVE THAT LEAVES IT OUT KEEPS IT AS IT WAS, rather than ' +
            'being refused or turning it back on',
            JSON.stringify(kept.errors || []));
  } finally {
    authnPolicy.reset('default');
    config.clearOverride('yubiotp.offered');
  }
  t.check(authnPolicy.read('default').yubicoOtpSecondFactor === true &&
          !yubiotp.offered(),
          'reset, the policy allows it and yubiotp.offered still gates ' +
          'enrolment');
  log.debug("Leaving checkPolicy().");
}

async function run(t) {
  log.debug("Entering run().");
  counters.reset();
  try {
    checkPolicy(t);
    checkVectors(t);
    checkOpen(t);
    const enrolled = await checkPerson(t);
    await checkYkval(t, enrolled.secret);
  } finally {
    config.clearOverride('yubiotp.offered');
    config.clearOverride('yubiotp.ykval');
    authnPolicy.reset('default');
    counters.reset();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'yubiotp',
  describe: 'issue #1955 P5: Yubico OTP checked locally — the published ' +
            'AES block and HMAC, a public identity, a zero counter, ' +
            'enrolment through the one-time code door, the authentication ' +
            'policy\'s yubico-otp row, and YK-VAL 2.0 off, OK, replayed ' +
            'and unsigned',
  run: run
};
