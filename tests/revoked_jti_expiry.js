// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: revoked_jti_expiry.js
//
// ===========================================================================
// A REVOKED JTI IS KEPT UNTIL ITS TOKEN WOULD HAVE EXPIRED, AND THE REGISTER
// IS BOUNDED (#345, 2026-09-29).
//
// `common/admin_stats.js`'s `revokedJtis` held `true` per jti, and the hourly
// purge could date a revocation only through the token register's record —
// which that register's 5,000 cap forgets long before most tokens expire. So
// a revocation whose record had gone was kept for ever. It now carries the
// token's `exp`, the purge drops it at `exp` plus the clock skew, and
// `oauth2.maxRevokedJtis` bounds it at insert.
//
//   A. a revoked, unexpired token is refused (`isRevoked()`), before and
//      after a purge;
//   B. once its `exp` has passed, the purge drops the revocation although no
//      record of the token exists — and keeps one nobody dated;
//   C. at the cap an expired revocation goes first; with none, the one whose
//      token expires SOONEST is forgotten, an undated one last.
//
// WHY IN PROCESS: the purge's clock and the cap are what is asserted, and
// neither can be reached over HTTP without waiting an hour or revoking a
// hundred thousand tokens. Each section runs in a realm of its own, so the
// revocations other files in this run leave in the default realm cannot
// decide the order the cap chooses.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const stats = require('../common/admin_stats');

const log = require('bunyan').createLogger({ name: 'revoked_jti_expiry',
  level: process.env.LOG_LEVEL || 'info' });

function nowSec() {
  log.debug("Entering nowSec().");
  log.debug("Leaving nowSec().");
  return Math.floor(Date.now() / 1000);
}

// Create a realm, hand it to `fn` inside it, and remove it however that
// goes — `realm_isolation.js`'s `withRealm()`.
function inRealm(t, id, fn) {
  log.debug("Entering inRealm().");
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving inRealm().");
    return undefined;
  }
  try {
    log.debug("Leaving inRealm().");
    return realms.run(made.realm, fn);
  } finally {
    realms.remove(id);
  }
}

function withSetting(key, value, fn) {
  log.debug("Entering withSetting().");
  config.setOverride(key, String(value));
  try {
    log.debug("Leaving withSetting().");
    return fn();
  } finally {
    config.clearOverride(key);
  }
}

function sectionAB(t) {
  log.debug("Entering sectionAB().");
  t.log.info('A/B. refused while unexpired, dropped once expired');
  inRealm(t, 'rj-expiry', function () {
    const skewS = Number(config.value('oauth2.clockSkewS'));
    const now = nowSec();
    t.equal(stats.revoke('rj-live', 'this test', {}, now + 3600), true,
            'a token is newly revoked');
    t.equal(stats.revoke('rj-short', 'this test', {}, now + 60), true,
            'and a second, which expires in a minute');
    stats.revoke('rj-undated', 'this test');
    t.check(stats.isRevoked('rj-live') && stats.isRevoked('rj-short'),
            'a revoked, unexpired token is refused');
    // A purge now drops nothing: neither token has expired.
    const early = stats.purgeExpiredTokens(Date.now());
    t.check(stats.isRevoked('rj-live') && stats.isRevoked('rj-short') &&
            stats.isRevoked('rj-undated'),
            'and a purge before either expires keeps all three',
            JSON.stringify(early));
    // Two minutes on, plus the skew: rj-short's token is past exp + skew.
    const later = stats.purgeExpiredTokens((now + 120 + skewS) * 1000);
    t.check(!stats.isRevoked('rj-short'),
            'once its exp and the clock skew have passed, the purge drops ' +
            'the revocation — with no record of the token in the register, ' +
            'which is the case that was kept for ever before #345',
            JSON.stringify(later));
    t.check(stats.isRevoked('rj-live'),
            'and still refuses the token that has not expired');
    t.check(stats.isRevoked('rj-undated'),
            'and keeps a revocation nobody dated — only the cap drops it');
    // A later door that knows the exp dates an undated revocation.
    stats.revoke('rj-undated', 'this test, again', {}, now + 30);
    stats.purgeExpiredTokens((now + 120 + skewS) * 1000);
    t.check(!stats.isRevoked('rj-undated'),
            'a revocation re-stated WITH an exp is dated by it and dropped');
    // An exp of 0 or garbage is "not stated", never "expired in 1970".
    stats.revoke('rj-garbage', 'this test', {}, 'not a number');
    stats.purgeExpiredTokens((now + 120 + skewS) * 1000);
    t.check(stats.isRevoked('rj-garbage'),
            'an exp that is not a number is read as not stated, and kept');
  });
  log.debug("Leaving sectionAB().");
}

function sectionC(t) {
  log.debug("Entering sectionC().");
  t.log.info('C. the cap forgets the soonest to expire, undated last');
  inRealm(t, 'rj-cap', function () {
    const now = nowSec();
    t.equal(stats.revokedCount(), 0, 'a new realm starts with none');
    withSetting('oauth2.maxRevokedJtis', 4, function () {
      stats.revoke('c-300', 'this test', {}, now + 300);
      stats.revoke('c-100', 'this test', {}, now + 100);
      stats.revoke('c-undated', 'this test');
      stats.revoke('c-500', 'this test', {}, now + 500);
      t.equal(stats.revokedCount(), 4, 'four revocations fill the cap');
      stats.revoke('c-900', 'this test', {}, now + 900);
      t.equal(stats.revokedCount(), 4, 'a fifth keeps the register at four');
      t.check(!stats.isRevoked('c-100') && stats.isRevoked('c-300') &&
              stats.isRevoked('c-500') && stats.isRevoked('c-undated') &&
              stats.isRevoked('c-900'),
              'the revocation forgotten is the one whose token expires ' +
              'soonest');
      stats.revoke('c-700', 'this test', {}, now + 700);
      stats.revoke('c-800', 'this test', {}, now + 800);
      stats.revoke('c-1000', 'this test', {}, now + 1000);
      t.check(stats.isRevoked('c-undated') && stats.isRevoked('c-1000') &&
              stats.isRevoked('c-900') && stats.isRevoked('c-800') &&
              !stats.isRevoked('c-700') && !stats.isRevoked('c-500'),
              'an undated revocation outlasts every dated one — forgetting ' +
              'it would re-open its token for good');
      stats.revoke('c-1000', 'this test, again', {}, now + 1000);
      t.equal(stats.revokedCount(), 4,
              'revoking a jti already revoked is not an insert and forgets ' +
              'nothing');
    });
    // An EXPIRED revocation is dropped first, and when that makes room
    // nothing that still matters is forgotten. Cap 5 for a moment, to hold
    // one that has already expired beside the four.
    withSetting('oauth2.maxRevokedJtis', 5, function () {
      stats.revoke('c-old', 'this test', {}, now - 3600);
      t.equal(stats.revokedCount(), 5, 'an expired revocation makes five');
      stats.revoke('c-new', 'this test', {}, now + 50);
      t.check(!stats.isRevoked('c-old') && stats.isRevoked('c-new') &&
              stats.isRevoked('c-800') && stats.isRevoked('c-900') &&
              stats.isRevoked('c-1000') && stats.isRevoked('c-undated'),
              'at the cap the expired revocation is dropped, and the one ' +
              'expiring soonest is kept because that made room');
    });
    // A cap LOWERED below the register's size is met at the next insert,
    // not one revocation per insert.
    withSetting('oauth2.maxRevokedJtis', 2, function () {
      stats.revoke('c-2000', 'this test', {}, now + 2000);
      t.equal(stats.revokedCount(), 2,
              'a cap lowered to two holds two after the next revocation');
      t.check(stats.isRevoked('c-undated') && stats.isRevoked('c-2000'),
              'the undated one and the newest are what is left');
    });
  });
  log.debug("Leaving sectionC().");
}

function run(t) {
  log.debug("Entering run().");
  sectionAB(t);
  sectionC(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'revoked_jti_expiry',
  describe: 'a revoked jti carries its token\'s exp, is refused until then, ' +
            'is dropped by the purge after it with or without its record, ' +
            'and oauth2.maxRevokedJtis forgets the soonest to expire first',
  run: run
};
