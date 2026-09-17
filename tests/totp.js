'use strict';
//
// File: totp.js
//
// ===========================================================================
// RFC 4226 AND RFC 6238, AGAINST THE SPECIFICATIONS' OWN TEST VECTORS.
//
// **THIS FILE IS THE REASON IT WAS WORTH IMPLEMENTING TOTP RATHER THAN TAKING
// A LIBRARY**, and it is the only test in this repository that can say that:
// both RFCs publish test vectors, so there is an external answer to check
// against rather than a second copy of the same reasoning.
//
// The arithmetic is fiddly in exactly the way that produces code which is
// wrong and looks right. RFC 4226 section 5.3's dynamic truncation is four
// steps — the low four bits of the last byte are an offset, four bytes are read
// from there, the top bit of the first is masked off because the reference
// implementation is Java and Java has no unsigned int, and the result is taken
// modulo 10^digits — and every one of the four has been got wrong by somebody.
// A wrong implementation still produces six plausible digits. Nothing about it
// looks broken until an authenticator app disagrees with it, at which point
// the person holding the phone is told their code is not right.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// The vectors are the whole point and they are not reachable over HTTP. RFC
// 6238's Appendix B is a table of (time, mode, code) — it needs a CHOSEN
// INSTANT, and this service will never let a caller name the moment a code is
// computed at, because a verifier that took the time from the request would be
// a verifier with no clock. Nothing over the wire can ask *what would the code
// have been at 1970-01-01T00:00:59Z*, and nothing should be able to.
//
// The over-HTTP half of this feature is `tests/vendored/sts_portal_totp.js`,
// which drives the enrolment and the sign-in with a code it computes itself.
// The two are not substitutes: this one says the arithmetic is right, and that
// one says the doors are wired up. Neither implies the other, and the vectors
// below are what makes the second one's independent implementation trustworthy
// enough to be worth having.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const crypto = require('../common/crypto');
const totp = require('../common/totp');
const credentials = require('../common/credentials');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'totp',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// RFC 4226 APPENDIX D. The shared secret is the ASCII string
// "12345678901234567890" and the counters are 0 to 9.
// ---------------------------------------------------------------------------
const HOTP_SECRET = Buffer.from('12345678901234567890', 'utf8');
const HOTP_VECTORS = ['755224', '287082', '359152', '969429', '338314',
                      '254676', '287922', '162583', '399871', '520489'];

// ---------------------------------------------------------------------------
// RFC 6238 APPENDIX B. Three secrets — the specification's own erratum is
// worth knowing about here, because it is the commonest way this table is got
// wrong: the RFC's prose says the seed is the same twenty-byte ASCII string
// for all three modes, and the values in the table are only reproducible if
// the SHA-256 seed is 32 bytes and the SHA-512 seed is 64 bytes, each formed
// by repeating "1234567890" and truncating. Errata 2866 says so. A test that
// used the twenty-byte seed for all three would fail against a CORRECT
// implementation, which is how this table gets abandoned.
// ---------------------------------------------------------------------------
function seedOf(bytes) {
  log.debug("Entering seedOf().");
  let s = '';
  while (s.length < bytes) {
    s += '1234567890';
  }
  log.debug("Leaving seedOf().");
  return Buffer.from(s.slice(0, bytes), 'utf8');
}

const TOTP_SEEDS = {
  SHA1: seedOf(20),
  SHA256: seedOf(32),
  SHA512: seedOf(64)
};

// (unix seconds, SHA1, SHA256, SHA512) — eight digits, thirty-second step.
const TOTP_VECTORS = [
  [59,          '94287082', '46119246', '90693936'],
  [1111111109,  '07081804', '68084774', '25091201'],
  [1111111111,  '14050471', '67062674', '99943326'],
  [1234567890,  '89005924', '91819424', '93441116'],
  [2000000000,  '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826']
];

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== RFC 4226 Appendix D: the HOTP vectors ===');
  HOTP_VECTORS.forEach(function (expected, counter) {
    t.equal(crypto.hotpCode(HOTP_SECRET, counter, { digits: 6 }), expected,
            'HOTP counter ' + counter);
  });
  t.check(crypto.hotpCode(HOTP_SECRET, 0, { digits: 8 }).length === 8,
          'and the digit count is honoured rather than fixed at six',
          crypto.hotpCode(HOTP_SECRET, 0, { digits: 8 }));
  // THE LEADING ZERO. One code in ten has one, and every implementation that
  // formats the value as a NUMBER loses it — which produces a five-digit code
  // that a person types in full and this service then refuses. Counter 8 of
  // the table above is `399871`, so the zero case needs finding rather than
  // assuming; this checks the property instead.
  t.check(HOTP_VECTORS.every(function (code) { return code.length === 6; }),
          'every vector is padded to its full width — the leading-zero case ' +
          'that a numeric formatter silently loses');

  t.log.info('=== RFC 6238 Appendix B: the TOTP vectors, all three digests ' +
             '===');
  const modes = ['SHA1', 'SHA256', 'SHA512'];
  TOTP_VECTORS.forEach(function (row) {
    const seconds = row[0];
    modes.forEach(function (mode, i) {
      const secret = totp.base32Encode(TOTP_SEEDS[mode]);
      const got = totp.codeAt(secret, seconds * 1000,
                              { digits: 8, period: 30, algorithm: mode });
      t.equal(got, row[i + 1], 'TOTP ' + mode + ' at t=' + seconds);
    });
  });

  t.log.info('=== base32 (RFC 4648 section 6), which node does not have ===');
  const bytes = Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad,
                             0xbe, 0xef]);
  t.equal(totp.base32Encode(bytes), 'JBSWY3DPEHPK3PXP',
          'the canonical "Hello!\\xde\\xad\\xbe\\xef" vector every base32 ' +
          'implementation is checked against');
  t.check(totp.base32Decode(totp.base32Encode(bytes)).equals(bytes),
          'and it round-trips');
  // THE THREE FORGIVENESSES ON INPUT, each of which is a real paste somebody
  // makes: the padding an RFC 4648 encoder adds and the otpauth convention
  // omits, the spaces this service itself prints so the secret can be
  // transcribed, and lower case.
  const secret = totp.base32Encode(bytes);
  t.check(totp.base32Decode(secret + '======').equals(bytes),
          'padding is tolerated on input — otpauth omits it and several apps ' +
          'split a URI on "=" rather than parsing it');
  t.check(totp.base32Decode(totp.grouped(secret)).equals(bytes),
          'and so are the spaces this service prints for manual entry',
          totp.grouped(secret));
  t.check(totp.base32Decode(secret.toLowerCase()).equals(bytes),
          'and lower case');
  let threw = false;
  try {
    totp.base32Decode('NOT!VALID');
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    threw = true;
  }
  t.check(threw,
          'a character outside the alphabet THROWS rather than being skipped ' +
          '— skipping produces a secret that is wrong rather than refused, ' +
          'and it fails later as "your code is not right"');

  t.log.info('=== the skew window, and that it is symmetric ===');
  const s = totp.generateSecret();
  const now = Date.now();
  const record = { secret: s, digits: 6, period: 30, algorithm: 'SHA1' };
  const at = function (offsetSeconds) {
    log.debug("Entering at().");
    log.debug("Leaving at().");
    return totp.codeAt(s, now + offsetSeconds * 1000,
                       { digits: 6, period: 30, algorithm: 'SHA1' });
  };
  t.check(totp.verify(record, at(0), { at: now, window: 1 }).ok,
          'the current step verifies');
  t.check(totp.verify(record, at(-30), { at: now, window: 1 }).ok,
          'so does the one before it — a phone whose clock is a little slow');
  t.check(totp.verify(record, at(30), { at: now, window: 1 }).ok,
          'and the one after it, which is what makes the window SYMMETRIC ' +
          'rather than a grace period');
  t.check(!totp.verify(record, at(60), { at: now, window: 1 }).ok,
          'two steps away is refused at the default window of 1, which RFC ' +
          '6238 section 5.2 recommends as the maximum');
  t.check(totp.verify(record, at(60), { at: now, window: 2 }).ok,
          'and accepted at a window of 2, so the setting really is the bound');
  t.check(!totp.verify(record, at(-30), { at: now, window: 0 }).ok &&
          totp.verify(record, at(0), { at: now, window: 0 }).ok,
          'a window of 0 demands a synchronised clock exactly');

  // THE SAME ZERO, THROUGH THE SETTING (2026-09-12). Every check above hands
  // `verify()` its window directly, which is why `settings()` reading
  // `totp.window` as `|| 1` survived: a documented zero became one and nothing
  // here ever asked for the window the way a sign-in does.
  const config = require('../common/config');
  try {
    config.setOverride('totp.window', '0');
    t.equal(totp.settings().window, 0,
            'totp.window=0 is honoured as zero rather than read as absent ' +
            'and replaced with the default of one');
    t.check(!totp.verify(record, at(-30), { at: now }).ok,
            'and a sign-in with no window of its own then refuses the ' +
            'previous step, which is what the setting promises');
  } finally {
    config.clearOverride('totp.window');
  }
  t.equal(totp.settings().window, 1, 'and cleared, the window is one again');

  t.log.info('=== RFC 6238 section 5.2: a code is accepted ONCE ===');
  const first = totp.verify(record, at(0), { at: now });
  t.check(first.ok, 'the code verifies the first time');
  const spent = Object.assign({ lastCounter: first.counter }, record);
  const again = totp.verify(spent, at(0), { at: now });
  t.check(!again.ok, 'and is refused the second time');
  t.equal(again.reason, 'replay',
          'REFUSED AS A REPLAY AND NOT AS A WRONG CODE — the difference is ' +
          'what a person is told: wait thirty seconds, or your authenticator ' +
          'is broken');
  t.check(totp.verify(spent, at(30), { at: now }).ok,
          'and the NEXT step still works, so spending one code does not ' +
          'strand the person');
  // THE STEP BEFORE THE SPENT ONE IS ALSO REFUSED, which is the half of the
  // requirement that a naive "not equal to the last counter" check misses: the
  // window reaches backwards, so a code from the previous step is still
  // computable and would otherwise be accepted after a later one was spent.
  t.check(!totp.verify(spent, at(-30), { at: now }).ok,
          'and so is the step BEFORE the one that was spent — the window ' +
          'reaches backwards, so "at or below" is the test rather than ' +
          '"not equal to"');

  t.log.info('=== the shape refusal, which is not a comparison ===');
  t.equal(totp.verify(record, '12345', { at: now }).reason, 'shape',
          'five digits is refused for its shape');
  t.equal(totp.verify(record, 'abcdef', { at: now }).reason, 'shape',
          'and so is something that is not digits at all');
  t.check(totp.verify(record, totp.grouped(at(0)).replace(/(\d{3})/, '$1 '),
                      { at: now }).ok,
          'but spaces inside a typed code are stripped rather than refused');

  t.log.info('=== the otpauth URI, which no RFC defines ===');
  const uri = totp.otpauthUri({ issuer: 'mock STS (acme)', account: 'alice',
                                secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1',
                                digits: 6, period: 30 });
  t.check(uri.indexOf('otpauth://totp/') === 0, 'it is an otpauth totp URI',
          uri);
  t.check(uri.indexOf('mock%20STS%20(acme):alice') > 0,
          'the issuer is a PREFIX on the label, for the apps that read only ' +
          'that');
  t.check(/[?&]issuer=mock%20STS%20\(acme\)/.test(uri),
          'AND a parameter, for the apps that read only that — saying it ' +
          'twice is the convention rather than a mistake');
  t.check(uri.indexOf('=') === uri.lastIndexOf('secret=JBSWY3DPEHPK3PXP') - 7 ||
          !/secret=[A-Z2-7]+=/.test(uri),
          'the secret carries no padding — "=" separates a parameter from ' +
          'its value and several apps split rather than parse');
  t.check(/algorithm=SHA1/.test(uri) && /digits=6/.test(uri) &&
          /period=30/.test(uri),
          'and all three parameters are written out even at their defaults, ' +
          'so an app that reads them is told exactly what will be checked');

  t.log.info('=== it is a SECOND factor and the store says so ===');
  // The claim `common/totp.ts` is built on, asserted against the credential
  // store rather than against the prose: an authenticator app must never make
  // an account usable on its own, and must never count as activated.
  const mechanisms = credentials.mechanismsFor('nobody-at-all');
  t.check(mechanisms.usable === false && mechanisms.activated === false,
          'somebody with no credential at all is neither usable nor activated');
  t.check(Object.prototype.hasOwnProperty.call(mechanisms, 'totp') &&
          Object.prototype.hasOwnProperty.call(mechanisms, 'secondFactor'),
          'mechanismsFor() reports the authenticator app and WHICH factor a ' +
          'sign-in will ask for — the two fields authn.js reads to demand one');
  t.check(credentials.ROLES.indexOf('totp') < 0,
          'and there is no TOTP entry in the security key ROLES — a shared ' +
          'secret this service also holds is not something to hang an ' +
          'account on, which is why it has no `primary` reading at all',
          credentials.ROLES.join(', '));

  t.log.info('=== the algorithm report the crypto page reads ===');
  const report = totp.report();
  t.equal(report.algorithms.length, 3,
          'three digests, read from the module that performs them');
  t.check(report.algorithms.filter(function (one) { return one.inUse; })
            .length === 1,
          'exactly one is marked in use, off the live setting — so the ' +
          'report says what THIS deployment does rather than what the module ' +
          'can do');
  t.check(report.algorithms[0].id === 'SHA1',
          'SHA-1 is first and is the default, which is the one place in this ' +
          'service the oldest algorithm is the recommended one: this is a ' +
          'keyed MAC over a counter, and every authenticator app assumes it');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'totp',
  describe: 'RFC 4226 and RFC 6238 against the specifications\' own test ' +
            'vectors, the skew window, the accept-once rule, and that a code ' +
            'can never be a first factor',
  run: run
};
