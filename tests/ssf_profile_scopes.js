// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_profile_scopes.js
//
// ===========================================================================
// THE CAEP PROFILE NAMES, AND WRITE INCLUDES READ (#334).
//
// `common/ssf_scopes.ts` is the vocabulary, and `common/scope_policy.ts` is
// the issuance gate. Both are asked here, in process, because the collision
// cases are settings (`ssf.authScopeRead` set to `ssf.manage`, the write
// setting renamed, both settings set to one custom name) and because both
// modes have to agree. The wire half — a manage-only token driving a
// stream — is `tests/protocol/sts_ssf_caep_scopes.js`.
//
// What is held:
//
//   1. With the defaults, the names are `ssf.read` and `ssf.manage`, in that
//      order. `ssf.manage` grants read and write, `ssf.read` grants read.
//      `ssf:read` and `ssf:write` are not Shared Signals scopes: not
//      published, not protected, and they grant nothing (rcbj, #334,
//      2026-10-19: no alias).
//   2. A setting cannot move a fixed name. A renamed write scope grants read
//      and write, as `ssf.manage` does, and so does one custom name on both
//      settings.
//   3. THE ONE RULE, as a table: under four settings and for every name,
//      `covers()`, `declarationCovers()` and `stillDeclared()` each agree
//      with `permissionsOf()`. So a client declaring only a renamed write
//      scope gets read by "write includes read" and by nothing else.
//   4. The re-check: a manage-only token whose client now declares only
//      `ssf.read` keeps its read and loses its write; a read token is kept
//      alive by a write declaration; `ssf:read` keeps nothing alive.
//   5. Issuance through `scope_policy`, in both modes: declaring
//      `ssf.manage` issues `ssf.read`; declaring only `ssf.read` does not
//      issue `ssf.manage`; declaring `ssf:read` issues neither, and
//      `ssf:read` itself is an ordinary scope.
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

const LEGACY = 'ssf-prof-legacy';
const MANAGE = 'ssf-prof-manage';
const DOTREAD = 'ssf-prof-dotread';
const CUSTOM = 'ssf-prof-custom';
const CUSTOMW = 'ssf-prof-customw';

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

// Runs `body` with the given settings overridden, and clears them after.
function withSettings(settings, body) {
  log.debug("Entering withSettings().");
  Object.keys(settings).forEach(function (key) {
    config.setOverride(key, settings[key]);
  });
  try {
    body();
  } finally {
    Object.keys(settings).forEach(function (key) {
      config.clearOverride(key);
    });
  }
  log.debug("Leaving withSettings().");
}

function makeApplications(t) {
  log.debug("Entering makeApplications().");
  const rows = [
    [LEGACY, ['ssf:read']],
    [MANAGE, ['ssf.manage']],
    [DOTREAD, ['ssf.read']],
    [CUSTOM, ['custom:read']],
    [CUSTOMW, ['custom:write']]
  ];
  const made = rows.map(function (row) {
    return applications.createApplication({ identifier: row[0],
      protocols: ['oauth2'],
      fields: { oauthClientId: row[0], oauthAllowedScope: row[1] } });
  });
  t.check(made.every(function (one) {
    return one && one.ok;
  }),
          'precondition: the five applications were created',
          JSON.stringify(made));
  log.debug("Leaving makeApplications().");
}

function vocabulary(t) {
  log.debug("Entering vocabulary().");
  t.log.info('=== 1. the default names ===');
  t.equal(ssfScopes.configuredRead(), 'ssf.read',
          'the default read scope is ssf.read');
  t.equal(ssfScopes.configuredWrite(), 'ssf.manage',
          'the default write scope is ssf.manage');
  same(t, ssfScopes.published(), ['ssf.read', 'ssf.manage'],
       'the published names are the two profile names, read first');
  same(t, ssfScopes.permissionsOf('ssf.read'), ['read'],
       'ssf.read grants read');
  same(t, ssfScopes.permissionsOf('ssf.manage'), ['read', 'write'],
       'ssf.manage grants read and write');
  same(t, ssfScopes.permissionsOf('ssf:read'), [],
       'ssf:read grants nothing');
  same(t, ssfScopes.permissionsOf('ssf:write'), [],
       'ssf:write grants nothing');
  t.check(ssfScopes.HISTORICAL_READ === undefined,
          'no historical read name is exported');
  t.check(!ssfScopes.isPublished('ssf:read') &&
          !ssfScopes.isPublished('ssf:write'),
          'neither colon name is published');
  t.check(!scopePolicy.isProtected('ssf:read') &&
          !scopePolicy.isProtected('ssf:write') &&
          scopePolicy.isProtected('ssf.read') &&
          scopePolicy.isProtected('ssf.manage'),
          'the profile names are protected, and the colon names are not');
  t.check(ssfScopes.covers('ssf.manage', 'read') &&
          ssfScopes.covers('ssf.manage', 'write'),
          'ssf.manage covers a read and a write');
  t.check(ssfScopes.covers('ssf.read', 'read') &&
          !ssfScopes.covers('ssf.read', 'write'),
          'ssf.read covers a read and not a write');
  t.check(!ssfScopes.covers('ssf:read', 'read') &&
          !ssfScopes.covers('ssf:write', 'write'),
          'a token that says only ssf:read or ssf:write covers nothing');
  same(t, ssfScopes.namesGranting('read'), ['ssf.read', 'ssf.manage'],
       'a read accepts ssf.read and ssf.manage');
  same(t, ssfScopes.namesGranting('write'), ['ssf.manage'],
       'a write accepts ssf.manage');
  log.debug("Leaving vocabulary().");
}

function collisions(t) {
  log.debug("Entering collisions().");
  t.log.info('=== 2. a setting cannot move a fixed name ===');
  withSettings({ 'ssf.authScopeRead': 'ssf.manage' }, function () {
    same(t, ssfScopes.permissionsOf('ssf.manage'), ['read', 'write'],
         'ssf.manage stays a write name when the read setting names it');
    same(t, ssfScopes.published(), ['ssf.manage', 'ssf.read'],
         'and is published once');
  });
  withSettings({ 'ssf.authScopeWrite': 'ssf.read' }, function () {
    same(t, ssfScopes.permissionsOf('ssf.read'), ['read'],
         'ssf.read stays a read name when the write setting names it');
    same(t, ssfScopes.namesGranting('write'), ['ssf.manage'],
         'and ssf.manage stays the only write name');
  });
  withSettings({ 'ssf.authScopeWrite': 'custom:write' }, function () {
    same(t, ssfScopes.permissionsOf('custom:write'), ['read', 'write'],
         'a renamed write scope grants read and write: write includes read');
    same(t, ssfScopes.permissionsOf('ssf.manage'), ['read', 'write'],
         'ssf.manage stays a write name beside it');
    t.check(ssfScopes.isPublished('custom:write') &&
            ssfScopes.isPublished('ssf.manage'),
            'both are published');
  });
  t.check(!ssfScopes.isPublished('custom:write'),
          'the renamed name is not published once the setting is default');
  withSettings({ 'ssf.authScopeRead': 'custom:both',
                 'ssf.authScopeWrite': 'custom:both' }, function () {
    same(t, ssfScopes.permissionsOf('custom:both'), ['read', 'write'],
         'one custom name on both settings grants read as well as write');
    t.check(ssfScopes.covers('custom:both', 'read') &&
            ssfScopes.covers('custom:both', 'write'),
            'and a token holding it covers both');
    same(t, ssfScopes.published(), ['custom:both', 'ssf.read', 'ssf.manage'],
         'the custom name is published once, beside the profile names');
  });
  log.debug("Leaving collisions().");
}

// THE ONE RULE. Every question the vocabulary answers is `permissionsOf()`
// read a particular way; this asks each of them of every name, under each
// settings arrangement, and fails on the first disagreement.
function oneRule(t) {
  log.debug("Entering oneRule().");
  t.log.info('=== 3. one rule: write includes read ===');
  const arrangements = [
    {},
    { 'ssf.authScopeWrite': 'custom:write' },
    { 'ssf.authScopeRead': 'custom:read' },
    { 'ssf.authScopeRead': 'custom:both',
      'ssf.authScopeWrite': 'custom:both' }
  ];
  const names = ['ssf.read', 'ssf.manage', 'ssf:read', 'ssf:write',
                 'custom:read', 'custom:write', 'custom:both', 'openid'];
  const broken = [];
  arrangements.forEach(function (settings) {
    withSettings(settings, function () {
      names.forEach(function (name) {
        const has = ssfScopes.permissionsOf(name);
        ['read', 'write'].forEach(function (p) {
          const want = has.indexOf(p) >= 0;
          const where = JSON.stringify(settings) + ' ' + name + ' ' + p;
          if (ssfScopes.covers([name], p) !== want) {
            broken.push('covers ' + where);
          }
          if (ssfScopes.stillDeclared([name], [name], p) !== want) {
            broken.push('stillDeclared(token) ' + where);
          }
          if (ssfScopes.stillDeclared(
            [p === 'read' ? 'ssf.read' : 'ssf.manage'], [name], p) !== want) {
            broken.push('stillDeclared(declaration) ' + where);
          }
        });
        if (ssfScopes.declarationCovers([name], 'ssf.read') !==
            (has.indexOf('read') >= 0)) {
          broken.push('declarationCovers(ssf.read) ' +
                      JSON.stringify(settings) + ' ' + name);
        }
        if (ssfScopes.declarationCovers([name], 'ssf.manage') !==
            (has.indexOf('write') >= 0)) {
          broken.push('declarationCovers(ssf.manage) ' +
                      JSON.stringify(settings) + ' ' + name);
        }
      });
    });
  });
  t.check(broken.length === 0,
          'under four arrangements of the settings, covers(), ' +
          'declarationCovers() and stillDeclared() all agree with ' +
          'permissionsOf() for every name', JSON.stringify(broken));
  withSettings({ 'ssf.authScopeWrite': 'custom:write' }, function () {
    t.check(ssfScopes.declarationCovers(['custom:write'], 'ssf.read') &&
            ssfScopes.stillDeclared('ssf.read', ['custom:write'], 'read'),
            'a client declaring only a renamed write scope may be issued ' +
            'ssf.read and keeps it, because write includes read');
    t.check(!ssfScopes.declarationCovers(['ssf.read'], 'custom:write') &&
            !ssfScopes.stillDeclared('custom:write', ['ssf.read'], 'write'),
            'and a read declaration never reaches the renamed write scope');
  });
  t.check(!ssfScopes.declarationCovers(['custom:write'], 'ssf.read'),
          'once the setting is the default, custom:write grants nothing');
  log.debug("Leaving oneRule().");
}

function recheck(t) {
  log.debug("Entering recheck().");
  t.log.info('=== 4. the re-check ===');
  t.check(ssfScopes.stillDeclared('ssf.manage', ['ssf.manage'], 'read') &&
          ssfScopes.stillDeclared('ssf.manage', ['ssf.manage'], 'write'),
          'a manage-only token reads and writes while ssf.manage is declared');
  t.check(ssfScopes.stillDeclared('ssf.manage', ['ssf.read'], 'read') &&
          !ssfScopes.stillDeclared('ssf.manage', ['ssf.read'], 'write'),
          'with only ssf.read declared it keeps the read and loses the write');
  t.check(ssfScopes.stillDeclared('ssf.read', ['ssf.manage'], 'read'),
          'a read token is kept alive by a write declaration');
  t.check(!ssfScopes.stillDeclared('ssf.manage', ['ssf:read'], 'read') &&
          !ssfScopes.stillDeclared('ssf:read', ['ssf.manage'], 'read'),
          'ssf:read keeps nothing alive, as a declaration or in a token');
  t.check(!ssfScopes.stillDeclared('ssf.manage', null, 'read') &&
          !ssfScopes.stillDeclared('ssf.manage', [], 'read'),
          'no declaration keeps nothing alive');
  t.check(ssfScopes.stillDeclared('', null, 'none'),
          'an operation that needs no scope is not asked');
  log.debug("Leaving recheck().");
}

function issuance(t) {
  log.debug("Entering issuance().");
  t.log.info('=== 5. issuance, in both modes ===');
  ['development', 'product'].forEach(function (m) {
    withSettings({ 'global.mode': m }, function () {
      t.equal(codeOf(scopePolicy.refusal('ssf.read', MANAGE)), null,
              m + ': declaring ssf.manage issues ssf.read');
      t.equal(codeOf(scopePolicy.refusal('ssf.read ssf.manage', MANAGE)),
              null, m + ': and both together');
      t.equal(codeOf(scopePolicy.refusal('ssf.manage', DOTREAD)),
              'STS-OAUTH-0577',
              m + ': declaring only ssf.read does not issue ssf.manage');
      t.equal(codeOf(scopePolicy.refusal('ssf.read', DOTREAD)), null,
              m + ': and does issue ssf.read');
      t.equal(codeOf(scopePolicy.refusal('ssf.read', LEGACY)),
              'STS-OAUTH-0577',
              m + ': declaring ssf:read does not issue ssf.read');
      t.equal(codeOf(scopePolicy.refusal('ssf.manage', LEGACY)),
              'STS-OAUTH-0577',
              m + ': nor ssf.manage');
      t.equal(codeOf(scopePolicy.refusal('ssf.read', '')), 'STS-OAUTH-0577',
              m + ': ssf.read to a request naming no client is refused');
      t.equal(codeOf(scopePolicy.refusal('ssf:read', MANAGE)),
              m === 'development' ? null : 'STS-OAUTH-0578',
              m + ': ssf:read is an ordinary scope, issued in development ' +
              'and refused in product when the list omits it');
      t.check(scopePolicy.declares(MANAGE, 'ssf.manage') &&
              scopePolicy.declares(MANAGE, 'ssf.read'),
              m + ': declares(): a write declaration declares read');
      t.check(scopePolicy.declares(DOTREAD, 'ssf.read') &&
              !scopePolicy.declares(DOTREAD, 'ssf.manage'),
              m + ': declares(): a read declaration does not declare write');
      t.check(!scopePolicy.declares(LEGACY, 'ssf.read'),
              m + ': declares(): ssf:read declares nothing');
    });
  });
  withSettings({ 'ssf.authScopeWrite': 'custom:write' }, function () {
    t.equal(codeOf(scopePolicy.refusal('ssf.read', CUSTOMW)), null,
            'a client declaring only the renamed write scope is issued ' +
            'ssf.read');
    t.equal(codeOf(scopePolicy.refusal('ssf.manage', CUSTOMW)), null,
            'and ssf.manage, which grants nothing it does not declare');
  });
  t.equal(codeOf(scopePolicy.refusal('ssf.read', CUSTOMW)), 'STS-OAUTH-0577',
          'with the write setting default again, custom:write issues nothing');
  withSettings({ 'ssf.authScopeRead': 'custom:read' }, function () {
    t.check(scopePolicy.isProtected('custom:read') &&
            scopePolicy.isProtected('ssf.read') &&
            scopePolicy.isProtected('ssf.manage'),
            'the renamed read setting is protected, and so are both ' +
            'profile names');
    t.equal(codeOf(scopePolicy.refusal('ssf.read', CUSTOM)), null,
            'a client declaring the renamed read name is issued ssf.read');
    t.equal(codeOf(scopePolicy.refusal('ssf.manage', CUSTOM)),
            'STS-OAUTH-0577',
            'and is not issued a write name');
  });
  log.debug("Leaving issuance().");
}

function run(t) {
  log.debug("Entering run().");
  makeApplications(t);
  vocabulary(t);
  collisions(t);
  oneRule(t);
  recheck(t);
  issuance(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_profile_scopes',
  describe: 'CAEP profile scope names: ssf.read and ssf.manage, write ' +
            'includes read, and ssf:read and ssf:write are not Shared ' +
            'Signals scopes (#334)',
  run: run
};
