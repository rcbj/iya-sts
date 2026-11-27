// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: tests/hotp.js
//
// ===========================================================================
// COUNTER-BASED ONE-TIME CODES, RFC 4226 (#1955 P4).
//
//   1. The ten codes of RFC 4226 Appendix D, from `crypto.hotpCode()` and
//      from `hotp.codeAt()` over the base32 secret.
//   2. `hotp.verify()`: the look-ahead window (section 7.4), a code behind
//      the counter refused, zero a legal window, the shape refused.
//   3. `hotp.resync()`: two consecutive codes over the larger window, a
//      non-consecutive pair refused.
//   4. A person's HOTP credential through `credentials.verifyTotpAsync()`,
//      the one-time code door every sign-in path uses: accepted by kind,
//      spent, a skipped press forgiven, out of the window refused and
//      brought back by a resync, the enrolment's two steps.
//   5. DESIGN X5: one code verified twice AT ONCE against a shared store
//      (two nodes or two workers) is accepted exactly once, and an entry
//      whose counter a stale write took backwards does not reopen it.
//   6. A person holding an authenticator app AND a token: either code is
//      accepted, each under its own kind, at the same door.
//   7. The authentication policy's `hotp` row is off by default. Saving
//      it on offers enrolment, and a save that does not name it (an older
//      client) keeps its current value.
//
// Every secret here is RFC 4226's published test key or one generated in
// the run.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const crypto = require('../common/crypto');
const totp = require('../common/totp');
const hotp = require('../common/hotp');
const credentials = require('../common/credentials');
const errorCodes = require('../common/error_codes');
const persistence = require('../persistence/persistence');
const counters = require('../cluster/cluster_counters');
const ldap = require('../ldap/ldap_server');
const authnPolicy = require('../common/authn_policy');

const log = require('bunyan').createLogger({
  name: 'hotp', level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');

// RFC 4226 Appendix D: the secret "12345678901234567890" (ASCII) and the
// HOTP values for counters 0 to 9.
const RFC_SECRET_ASCII = '12345678901234567890';
const RFC_CODES = ['755224', '287082', '359152', '969429', '338314',
                   '254676', '287922', '162583', '399871', '520489'];

function codeOf(result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return errorCodes.codeOf(result) || '';
}

// A store two nodes share, as `tests/cluster_single_use_credentials.js`
// stands it up: every answer arrives on a later turn of the loop, so two
// verifications really do interleave between their reads and their writes.
function sharedStore() {
  log.debug("Entering sharedStore().");
  const table = new Map();
  const store = {
    advanceCounter: function (scope, realm, key, value) {
      log.debug("Entering advanceCounter().");
      log.debug("Leaving advanceCounter().");
      return new Promise(function (resolve) {
        setImmediate(function () {
          const k = scope + ' ' + realm + ' ' + key;
          if (!table.has(k) || table.get(k) < value) {
            table.set(k, value);
            resolve({ advanced: true, highest: value });
            return;
          }
          resolve({ advanced: false, highest: table.get(k) });
        });
      });
    }
  };
  log.debug("Leaving sharedStore().");
  return store;
}

function person(label) {
  log.debug("Entering person().");
  const name = 'hotp-' + label + '-' + RUN;
  ldap.createUser(name, { invent: false, attributes: {} });
  log.debug("Leaving person().");
  return name;
}

function storedAttributes(name) {
  log.debug("Entering storedAttributes().");
  const located = ldap.existingUserEntry(name);
  const stored = located && (located.stored || located);
  log.debug("Leaving storedAttributes().");
  return stored ? stored.attributes : null;
}

// The RFC's key as a person's token: installed as an imported token is,
// which is the door that takes a secret it did not mint.
async function giveRfcToken(name, counter) {
  log.debug("Entering giveRfcToken().");
  const out = await credentials.installImportedOath(name, {
    key: 'test/' + name + '/1', kind: 'hotp',
    secret: totp.base32Encode(Buffer.from(RFC_SECRET_ASCII, 'ascii')),
    algorithm: 'SHA1', digits: 6, counter: counter || 0,
    vendor: 'test', serial: name, model: 'RFC 4226' });
  log.debug("Leaving giveRfcToken().");
  return out;
}

function checkVectors(t) {
  log.debug("Entering checkVectors().");
  t.log.info('=== 1. RFC 4226 Appendix D ===');
  const key = Buffer.from(RFC_SECRET_ASCII, 'ascii');
  const fromPrimitive = RFC_CODES.map(function (code, counter) {
    return crypto.hotpCode(key, counter, { digits: 6, algorithm: 'SHA1' });
  });
  t.equal(fromPrimitive.join(','), RFC_CODES.join(','),
          'crypto.hotpCode() gives the ten published values');
  const b32 = totp.base32Encode(key);
  t.equal(hotp.codeAt(b32, 9), '520489',
          'hotp.codeAt() over the base32 secret gives counter 9\'s value');
  log.debug("Leaving checkVectors().");
}

function checkVerify(t) {
  log.debug("Entering checkVerify().");
  t.log.info('=== 2. the look-ahead ===');
  const record = { secret: totp.base32Encode(Buffer.from(RFC_SECRET_ASCII)),
                   digits: 6, algorithm: 'SHA1', counter: 3 };
  const atBase = hotp.verify(record, RFC_CODES[3], { window: 0 });
  t.check(atBase.ok && atBase.counter === 3 && atBase.next === 4,
          'the code AT the counter is accepted and the next counter is 4',
          JSON.stringify(atBase));
  const ahead = hotp.verify(record, RFC_CODES[7], { window: 4 });
  t.check(ahead.ok && ahead.counter === 7 && ahead.ahead === 4,
          'a code four presses ahead is accepted inside a window of four');
  const outside = hotp.verify(record, RFC_CODES[8], { window: 4 });
  t.check(!outside.ok && outside.reason === 'mismatch' &&
          codeOf(outside) === 'STS-OATH-0003',
          'five presses ahead is outside a window of four',
          JSON.stringify(outside));
  const behind = hotp.verify(record, RFC_CODES[2], { window: 10 });
  t.check(!behind.ok && behind.reason === 'mismatch',
          'A CODE BEHIND THE COUNTER IS NEVER ACCEPTED, whatever the window ' +
          '(RFC 4226 section 7.2)');
  const zero = hotp.verify(record, RFC_CODES[4], { window: 0 });
  t.check(!zero.ok, 'ZERO IS A LEGAL WINDOW: only the next code itself');
  const shape = hotp.verify(record, '12345', {});
  t.check(!shape.ok && shape.reason === 'shape' &&
          codeOf(shape) === 'STS-OATH-0001', 'five digits is refused by ' +
          'shape');
  t.check(hotp.verify(record, '969 429', { window: 0 }).ok,
          'spaces a token\'s display groups by are forgiven');
  t.equal(hotp.settings().window, 10, 'the default look-ahead is ten');
  log.debug("Leaving checkVerify().");
}

function checkResync(t) {
  log.debug("Entering checkResync().");
  t.log.info('=== 3. resynchronisation ===');
  const record = { secret: totp.base32Encode(Buffer.from(RFC_SECRET_ASCII)),
                   digits: 6, counter: 0 };
  const found = hotp.resync(record, RFC_CODES[6], RFC_CODES[7],
                            { window: 9 });
  t.check(found.ok && found.counter === 7 && found.next === 8,
          'two consecutive codes are found and the counter moves past BOTH',
          JSON.stringify(found));
  const apart = hotp.resync(record, RFC_CODES[5], RFC_CODES[7],
                            { window: 9 });
  t.check(!apart.ok && codeOf(apart) === 'STS-OATH-0004',
          'two codes that are not consecutive are refused');
  const edge = hotp.resync(record, RFC_CODES[8], RFC_CODES[9],
                           { window: 9 });
  t.check(edge.ok && edge.next === 10, 'the pair at the window\'s edge is ' +
          'found');
  log.debug("Leaving checkResync().");
}

async function checkPerson(t) {
  log.debug("Entering checkPerson().");
  t.log.info('=== 4. a person\'s token through the one-time code door ===');
  const name = person('one');
  t.check((await giveRfcToken(name, 0)).ok, 'the RFC\'s token is installed');
  const held = credentials.mechanismsFor(name);
  t.check(held.hotp && held.oneTimeCode && !held.totp &&
          held.secondFactor === 'totp' && held.mfaRequired,
          'the person holds a one-time code (the code step), not an app',
          JSON.stringify({ hotp: held.hotp, totp: held.totp,
                           secondFactor: held.secondFactor }));
  t.check(credentials.secondFactorDemand(name).totp &&
          credentials.secondFactorDemand(name).hotp,
          'the KDC is told a one-time code may be asked for (FAST OTP)');
  const first = await credentials.verifyTotpAsync(name, RFC_CODES[0]);
  t.check(first.ok && first.kind === 'hotp' && first.counter === 0 &&
          first.hardware === false, 'counter 0\'s code is accepted, as ' +
          'HOTP (no hardware evidence without a register row)',
          JSON.stringify(first));
  const again = await credentials.verifyTotpAsync(name, RFC_CODES[0]);
  t.check(!again.ok, 'the same code again is refused');
  const skipped = await credentials.verifyTotpAsync(name, RFC_CODES[3]);
  t.check(skipped.ok && skipped.counter === 3,
          'two presses that never arrived are forgiven');
  t.check(!(await credentials.verifyTotpAsync(name, RFC_CODES[2])).ok,
          'and a code from before them is now spent');
  // Out of the default window of ten: counter 4 is next; 15 is eleven on.
  const secret = totp.base32Encode(Buffer.from(RFC_SECRET_ASCII));
  const far = hotp.codeAt(secret, 15);
  t.check(!(await credentials.verifyTotpAsync(name, far)).ok,
          'eleven presses ahead is outside the default look-ahead');
  const resynced = await credentials.resyncHotpAsync(name, far,
    hotp.codeAt(secret, 16));
  t.check(resynced.ok && resynced.counter === 16,
          'TWO CONSECUTIVE CODES RESYNCHRONISE IT', JSON.stringify(resynced));
  t.check((await credentials.verifyTotpAsync(name,
          hotp.codeAt(secret, 17))).ok, 'and the next code signs in');
  t.check(!(await credentials.resyncHotpAsync(name, far,
          hotp.codeAt(secret, 16))).ok,
          'a resync pair cannot be presented twice');
  const removed = credentials.removeHotp(name);
  t.check(removed.ok && !credentials.mechanismsFor(name).hotp,
          'the credential is removed');

  t.log.info('--- the enrolment\'s two steps ---');
  const allowed = authnPolicy.save('default', Object.assign({},
    authnPolicy.DEFAULTS, { hotpSecondFactor: true }));
  t.check(allowed.ok && hotp.offered(),
          'the hotp row, off by default, is on for this enrolment',
          JSON.stringify((allowed && allowed.errors) || []));
  const who = person('enrol');
  const begun = credentials.beginHotpEnrolment(who,
                                               { base: 'https://localhost' });
  t.check(begun.ok && /^otpauth:\/\/hotp\//.test(begun.uri) &&
          /counter=0/.test(begun.uri) && /^ykman otp hotp /.test(begun.ykman),
          'an enrolment shows an otpauth://hotp URI with its counter, and ' +
          'the ykman command', begun.uri);
  t.check(!credentials.mechanismsFor(who).hotp,
          'NOTHING IS WRITTEN until a code confirms it');
  const confirmed = await credentials.confirmHotpEnrolment(who,
    hotp.codeAt(begun.secret, 1, { digits: begun.digits }));
  t.check(confirmed.ok && credentials.mechanismsFor(who).hotp,
          'a code a press ahead confirms it', JSON.stringify(confirmed));
  t.check(!(await credentials.verifyTotpAsync(who,
          hotp.codeAt(begun.secret, 1, { digits: begun.digits }))).ok,
          'THE CONFIRMATION\'S CODE IS SPENT: it cannot also sign in');
  t.check((await credentials.verifyTotpAsync(who,
          hotp.codeAt(begun.secret, 2, { digits: begun.digits }))).ok,
          'the next one does');
  log.debug("Leaving checkPerson().");
}

async function checkRace(t) {
  log.debug("Entering checkRace().");
  t.log.info('=== 5. design X5: one code at two nodes at once ===');
  const store = sharedStore();
  const real = persistence.clusterStore;
  persistence.clusterStore = function () {
    return store;
  };
  counters.reset();
  try {
    const name = person('race');
    t.check((await giveRfcToken(name, 0)).ok, 'the RFC\'s token is ' +
            'installed against the shared store');
    const stale = JSON.parse(JSON.stringify(
      storedAttributes(name).stshotpcredential));
    const both = await Promise.all([
      credentials.verifyTotpAsync(name, RFC_CODES[1]),
      credentials.verifyTotpAsync(name, RFC_CODES[1])
    ]);
    const accepted = both.filter(function (one) {
      return one.ok;
    });
    const refused = both.filter(function (one) {
      return !one.ok;
    });
    t.equal(accepted.length, 1,
            'ONE CODE VERIFIED TWICE AT ONCE IS ACCEPTED EXACTLY ONCE — ' +
            'both matched on the entry, and the compare-and-set decided');
    t.check(refused.length === 1 && refused[0].reason === 'replay' &&
            codeOf(refused[0]) === 'STS-OATH-0005',
            'and the other is refused as a replay',
            JSON.stringify(refused[0]) + ' ' + codeOf(refused[0]));
    storedAttributes(name).stshotpcredential = stale;
    const backwards = await credentials.verifyTotpAsync(name, RFC_CODES[1]);
    t.check(!backwards.ok && backwards.reason === 'replay',
            'AN ENTRY WHOSE COUNTER A STALE WRITE TOOK BACKWARDS DOES NOT ' +
            'REOPEN THE CODE: the entry matches and the store refuses',
            JSON.stringify(backwards));
    t.check((await credentials.verifyTotpAsync(name, RFC_CODES[2])).ok,
            'the next code is still accepted');
  } finally {
    persistence.clusterStore = real;
    counters.reset();
  }
  log.debug("Leaving checkRace().");
}

async function checkBoth(t) {
  log.debug("Entering checkBoth().");
  t.log.info('=== 6. an authenticator app and a token, one door ===');
  const name = person('both');
  const begun = credentials.beginTotpEnrolment(name,
                                               { base: 'https://localhost' });
  t.check(credentials.confirmTotpEnrolment(name,
    totp.codeAt(begun.secret, Date.now(), begun)).ok,
          'an authenticator app is enrolled');
  t.check((await giveRfcToken(name, 0)).ok, 'and a token is installed');
  const app = await credentials.verifyTotpAsync(name,
    totp.codeAt(begun.secret, Date.now() + 30000, begun));
  t.check(app.ok && app.kind === 'totp', 'the app\'s code is accepted as ' +
          'TOTP', JSON.stringify(app));
  const token = await credentials.verifyTotpAsync(name, RFC_CODES[0]);
  t.check(token.ok && token.kind === 'hotp', 'the token\'s as HOTP',
          JSON.stringify(token));
  const neither = await credentials.verifyTotpAsync(name, '000000');
  t.check(!neither.ok && neither.reason === 'mismatch',
          'a code neither produced is refused as not right');
  log.debug("Leaving checkBoth().");
}

// The policy's `hotp` row (#1955 P4) is off by default. A save that leaves
// it out keeps the profile's current value, so a client written before it
// changes nothing.
function checkPolicy(t) {
  log.debug("Entering checkPolicy().");
  t.log.info('=== 7. the authentication policy\'s hotp row ===');
  t.check(authnPolicy.read('default').hotpSecondFactor === false &&
          !hotp.offered(),
          'the row is off by default, so a new enrolment is refused');
  const before = authnPolicy.read('default');
  const values = {};
  Object.keys(before).forEach(function (key) {
    if (/Primary$|SecondFactor$|^require|^email|^remembered/.test(key)) {
      values[key] = before[key];
    }
  });
  try {
    const on = authnPolicy.save('default', Object.assign({}, values,
                                { hotpSecondFactor: true }));
    t.check(on.ok && authnPolicy.read('default').hotpSecondFactor === true &&
            hotp.offered(), 'saving the row on turns HOTP enrolment on',
            JSON.stringify(on.errors || []));
    const older = Object.assign({}, values);
    delete older.hotpSecondFactor;
    const kept = authnPolicy.save('default', older);
    t.check(kept.ok && authnPolicy.read('default').hotpSecondFactor === true,
            'A SAVE THAT LEAVES IT OUT (a client written before it) KEEPS ' +
            'THE CURRENT VALUE, rather than the built-in off or a refusal',
            JSON.stringify(kept.errors || []));
  } finally {
    authnPolicy.reset('default');
  }
  t.check(!hotp.offered() &&
          authnPolicy.read('default').hotpSecondFactor === false,
          'and reset, it is off by default');
  log.debug("Leaving checkPolicy().");
}

async function run(t) {
  log.debug("Entering run().");
  counters.reset();
  try {
    checkPolicy(t);
    checkVectors(t);
    checkVerify(t);
    checkResync(t);
    await checkPerson(t);
    await checkRace(t);
    await checkBoth(t);
  } finally {
    authnPolicy.reset('default');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'hotp',
  describe: 'issue #1955 P4: RFC 4226 HOTP — the Appendix D vectors, the ' +
            'look-ahead and resynchronisation, a person\'s token at the ' +
            'one-time code door, and one code accepted once across two ' +
            'nodes by compare-and-set',
  run: run
};
