// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_profile_scopes.js
//
// ===========================================================================
// THE CAEP PROFILE NAMES, AND THE RETIRED WRITE NAME (#334).
//
// `common/ssf_scopes.ts` is the vocabulary, and `common/scope_policy.ts` is
// the issuance gate. Both are asked here, in process, because the collision
// cases are settings (`ssf.authScopeRead` set to `ssf.manage`, the write
// setting set back to `ssf:write`, both settings set to one custom name)
// and because both modes have to agree. The wire half — a manage-only
// token driving a stream — is `tests/vendored/sts_ssf_caep_scopes.js`.
//
// What is held:
//
//   1. With the defaults, discovery's list is `ssf:read`, `ssf.manage`,
//      `ssf.read`. `ssf.manage` covers a read and a write. `ssf:write` is
//      not a Shared Signals scope.
//   2. The three fixed names keep their classes when a setting is pointed
//      at one of them. Setting the write setting to `ssf:write` makes that
//      name write, and it does not include read. A custom name used for
//      both settings is write, and it does not gain manage's inclusion of
//      read.
//   3. Issuance is per class, in both modes. Declaring any write name
//      authorizes any write name and no read name. Declaring any read name
//      authorizes any read name and no write name. Declaring only
//      `ssf:write` authorizes neither. Renaming the read setting adds that
//      name and unprotects none of the three. `ssf:write` is not protected
//      at the defaults: development issues it, product refuses it
//      `STS-OAUTH-0578` when the client's list does not name it.
//   4. `stillDeclared` looks at the token. A manage-only token's read lives
//      while `ssf.manage` stays declared, and dies when only a read name,
//      or only `ssf:write`, does. A token that only says `ssf:write`
//      authorizes nothing. A token holding both a read name and
//      `ssf.manage` keeps the read while either class stays.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const applications = require('../common/applications');
// Fills the directory slots the application register writes through.
require('../ldap/ldap_server');
const scopePolicy = require('../common/scope_policy');
const ssfScopes = require('../common/ssf_scopes');

const log = require('bunyan').createLogger({ name: 'ssf_profile_scopes',
  level: process.env.LOG_LEVEL || 'info' });

const READ = 'ssf-prof-read';
const WRITE = 'ssf-prof-write';
const MANAGE = 'ssf-prof-manage';
const DOTREAD = 'ssf-prof-dotread';
const CUSTOM = 'ssf-prof-custom';

function codeOf(refusal) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return refusal ? refusal.code : null;
}

function same(t, got, want, what) {
  log.debug("Entering same().");
  t.equal(JSON.stringify(got), JSON.stringify(want), what + ' — got ' +
          JSON.stringify(got));
  log.debug("Leaving same().");
}

function makeApplications(t) {
  log.debug("Entering makeApplications().");
  const rows = [
    [READ, ['ssf:read']],
    [WRITE, ['ssf:write']],
    [MANAGE, ['ssf.manage']],
    [DOTREAD, ['ssf.read']],
    [CUSTOM, ['custom:read']]
  ];
  const made = rows.map(function (row) {
    return applications.createApplication({ identifier: row[0],
      protocols: ['oauth2'],
      fields: { oauthClientId: row[0], oauthAllowedScope: row[1] } });
  });
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the five applications were created',
          JSON.stringify(made));
  log.debug("Leaving makeApplications().");
}

function vocabulary(t) {
  log.debug("Entering vocabulary().");
  t.log.info('=== 1. the default names ===');
  t.equal(ssfScopes.configuredWrite(), 'ssf.manage',
          'the default write scope is ssf.manage');
  same(t, ssfScopes.published(),
       ['ssf:read', 'ssf.manage', 'ssf.read'],
       'published order is the two settings, then the profile read name');
  t.equal(ssfScopes.classOf('ssf.read'), 'read', 'ssf.read is read');
  t.equal(ssfScopes.classOf('ssf:read'), 'read', 'ssf:read is read');
  t.equal(ssfScopes.classOf('ssf.manage'), 'write', 'ssf.manage is write');
  t.equal(ssfScopes.classOf('ssf:write'), null,
          'ssf:write is not a Shared Signals scope');
  t.check(ssfScopes.covers('ssf.manage', 'read') &&
          ssfScopes.covers('ssf.manage', 'write'),
          'ssf.manage covers a read and a write');
  t.check(!ssfScopes.covers('ssf:write', 'write') &&
          !ssfScopes.covers('ssf:write', 'read'),
          'ssf:write covers neither');
  t.check(ssfScopes.covers('ssf.read', 'read') &&
          !ssfScopes.covers('ssf.read', 'write'),
          'ssf.read covers a read and not a write');
  t.check(ssfScopes.covers('ssf:read ssf.manage', 'read') &&
          ssfScopes.covers('ssf:read ssf.manage', 'write'),
          'a token holding the read name and ssf.manage covers both');
  t.check(!ssfScopes.declarationCovers(['ssf:write'], 'ssf.read') &&
          !ssfScopes.declarationCovers(['ssf:write'], 'ssf.manage') &&
          !ssfScopes.declarationCovers(['ssf.manage'], 'ssf:write'),
          'declaring ssf:write authorizes nothing, and ssf.manage does ' +
          'not authorize the retired name');
  t.check(ssfScopes.declarationCovers(['ssf.read'], 'ssf:read') &&
          !ssfScopes.declarationCovers(['ssf.read'], 'ssf.manage') &&
          !ssfScopes.declarationCovers(['ssf:read'], 'ssf.manage'),
          'a read declaration authorizes either read spelling and no ' +
          'write spelling');
  t.check(!scopePolicy.isProtected('ssf:write'),
          'ssf:write is not protected at the defaults');
  log.debug("Leaving vocabulary().");
}

function collisions(t) {
  log.debug("Entering collisions().");
  t.log.info('=== 2. a setting cannot move a fixed name ===');
  config.setOverride('ssf.authScopeRead', 'ssf.manage');
  try {
    t.equal(ssfScopes.classOf('ssf.manage'), 'write',
            'ssf.manage stays write when the read setting names it');
    t.check(ssfScopes.readNames().indexOf('ssf.manage') < 0,
            'and it is not listed as a read name');
    t.check(ssfScopes.covers('ssf.manage', 'read'),
            'it still covers a read, because manage includes read');
  } finally {
    config.clearOverride('ssf.authScopeRead');
  }
  config.setOverride('ssf.authScopeWrite', 'ssf.read');
  try {
    t.equal(ssfScopes.classOf('ssf.read'), 'read',
            'ssf.read stays read when the write setting names it');
    t.check(ssfScopes.writeNames().indexOf('ssf.read') < 0,
            'and it is not listed as a write name');
    t.check(ssfScopes.writeNames().indexOf('ssf.manage') >= 0,
            'ssf.manage stays the write name');
  } finally {
    config.clearOverride('ssf.authScopeWrite');
  }
  config.setOverride('ssf.authScopeWrite', 'ssf:write');
  try {
    t.equal(ssfScopes.classOf('ssf:write'), 'write',
            'setting the write scope back to ssf:write makes it write');
    t.check(ssfScopes.covers('ssf:write', 'write') &&
            !ssfScopes.covers('ssf:write', 'read'),
            'and that name does not include read');
    t.equal(ssfScopes.classOf('ssf.manage'), 'write',
            'ssf.manage stays write');
    t.check(ssfScopes.covers('ssf.manage', 'read'),
            'and still includes read');
    t.check(ssfScopes.declarationCovers(['ssf:write'], 'ssf.manage') &&
            ssfScopes.declarationCovers(['ssf.manage'], 'ssf:write'),
            'the two write names authorize each other');
    t.check(ssfScopes.isPublished('ssf:write'),
            'ssf:write is published while it is the configured name');
  } finally {
    config.clearOverride('ssf.authScopeWrite');
  }
  t.check(!ssfScopes.isPublished('ssf:write'),
          'and is not published once the setting is the default again');
  config.setOverride('ssf.authScopeRead', 'custom:both');
  config.setOverride('ssf.authScopeWrite', 'custom:both');
  try {
    t.equal(ssfScopes.classOf('custom:both'), 'write',
            'one custom name on both settings is write');
    t.check(!ssfScopes.covers('custom:both', 'read') &&
            ssfScopes.covers('custom:both', 'write'),
            'and that name does not include read');
    t.check(ssfScopes.declarationCovers(['custom:both'], 'ssf.manage') &&
            ssfScopes.declarationCovers(['ssf.manage'], 'custom:both'),
            'the custom write name and ssf.manage authorize each other');
    t.check(ssfScopes.isPublished('custom:both') &&
            ssfScopes.isPublished('ssf:read') &&
            ssfScopes.isPublished('ssf.read') &&
            ssfScopes.isPublished('ssf.manage') &&
            !ssfScopes.isPublished('ssf:write'),
            'the three fixed names stay published, and ssf:write does not');
  } finally {
    config.clearOverride('ssf.authScopeRead');
    config.clearOverride('ssf.authScopeWrite');
  }
  log.debug("Leaving collisions().");
}

function recheck(t) {
  log.debug("Entering recheck().");
  t.log.info('=== 3. the re-check looks at the token ===');
  t.check(ssfScopes.stillDeclared('ssf.manage', ['ssf.manage'], 'read'),
          'a manage-only token may read while ssf.manage stays declared');
  t.check(!ssfScopes.stillDeclared('ssf.manage', ['ssf:write'], 'read'),
          'and may not while only the retired name is declared');
  t.check(!ssfScopes.stillDeclared('ssf.manage', ['ssf:read'], 'read'),
          'and may not when only a read name is still declared');
  t.check(!ssfScopes.stillDeclared('ssf.manage', ['ssf:read'], 'write'),
          'nor write, once the write declaration is gone');
  t.check(ssfScopes.stillDeclared('ssf.read ssf.manage', ['ssf:read'],
                                  'read'),
          'a token holding both keeps the read from the read name');
  t.check(!ssfScopes.stillDeclared('ssf.read ssf.manage', ['ssf:read'],
                                   'write'),
          'and loses the write');
  t.check(!ssfScopes.stillDeclared('ssf:write', ['ssf.manage'], 'write') &&
          !ssfScopes.stillDeclared('ssf:write', ['ssf.manage'], 'read'),
          'a token that only says ssf:write authorizes nothing');
  t.check(!ssfScopes.stillDeclared('ssf:read', ['ssf.manage'], 'read'),
          'a read token is not kept alive by a write declaration');
  same(t, ssfScopes.authorities('ssf.manage', 'read'), ['write'],
       'manage\'s read rests on the write class');
  same(t, ssfScopes.authorities('ssf.read ssf.manage', 'read'),
       ['read', 'write'],
       'a token holding both contributes both classes to a read');
  same(t, ssfScopes.authorities('ssf:write', 'read'), [],
       'ssf:write contributes nothing to a read');
  same(t, ssfScopes.authorities('ssf:write', 'write'), [],
       'nor to a write, once it is not a write name');
  log.debug("Leaving recheck().");
}

function issuance(t) {
  log.debug("Entering issuance().");
  t.log.info('=== 4. issuance, per class, in both modes ===');
  ['development', 'product'].forEach(function (m) {
    config.setOverride('global.mode', m);
    try {
      t.equal(codeOf(scopePolicy.refusal('ssf.manage', WRITE)),
              'STS-OAUTH-0577',
              m + ': declaring only ssf:write does not issue ssf.manage');
      t.equal(codeOf(scopePolicy.refusal('ssf.read', WRITE)),
              'STS-OAUTH-0577',
              m + ': and does not issue ssf.read');
      t.equal(codeOf(scopePolicy.refusal('ssf:read', DOTREAD)), null,
              m + ': declaring ssf.read issues ssf:read');
      t.equal(codeOf(scopePolicy.refusal('ssf.manage', READ)),
              'STS-OAUTH-0577',
              m + ': declaring ssf:read does not issue ssf.manage');
      t.equal(codeOf(scopePolicy.refusal('ssf.read', READ)), null,
              m + ': and does issue ssf.read');
      t.equal(codeOf(scopePolicy.refusal('ssf.read', '')), 'STS-OAUTH-0577',
              m + ': ssf.read to a request naming no client is refused');
      t.equal(codeOf(scopePolicy.refusal('ssf:write', MANAGE)),
              m === 'development' ? null : 'STS-OAUTH-0578',
              m + ': ssf:write is an ordinary scope, issued in ' +
              'development and refused in product when the list omits it');
      t.check(!scopePolicy.declares(WRITE, 'ssf.manage') &&
              !scopePolicy.declares(WRITE, 'ssf.read'),
              m + ': declares() : ssf:write is neither class');
      t.check(scopePolicy.declares(MANAGE, 'ssf.manage') &&
              !scopePolicy.declares(MANAGE, 'ssf.read'),
              m + ': declares() asks the class, and write is not read');
    } finally {
      config.clearOverride('global.mode');
    }
  });
  config.setOverride('ssf.authScopeRead', 'custom:read');
  try {
    t.check(scopePolicy.isProtected('custom:read') &&
            scopePolicy.isProtected('ssf:read') &&
            scopePolicy.isProtected('ssf.read') &&
            scopePolicy.isProtected('ssf.manage') &&
            !scopePolicy.isProtected('ssf:write'),
            'the renamed read setting is protected, and so are the three ' +
            'fixed names, and ssf:write is not');
    t.equal(codeOf(scopePolicy.refusal('ssf.read', CUSTOM)), null,
            'a client declaring the renamed read name is issued ssf.read');
    t.equal(codeOf(scopePolicy.refusal('ssf.manage', CUSTOM)),
            'STS-OAUTH-0577',
            'and is not issued a write name');
  } finally {
    config.clearOverride('ssf.authScopeRead');
  }
  log.debug("Leaving issuance().");
}

function run(t) {
  log.debug("Entering run().");
  makeApplications(t);
  vocabulary(t);
  collisions(t);
  recheck(t);
  issuance(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_profile_scopes',
  describe: 'CAEP profile scope names: ssf.manage is the write scope and ' +
            'includes read, and ssf:write is not a Shared Signals scope ' +
            'unless the write setting names it (#334)',
  run: run
};
