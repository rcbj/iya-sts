// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sign_in_registry_reads.js
//
// ===========================================================================
// A SIGN-IN DOES NOT REBUILD THE APPLICATION REGISTRY PER QUESTION (#758).
//
// Under a sign-in load on 8081 a request worker spent about 15% rebuilding
// application views and parsing entries: `declaredTypes()` built a view of
// every application per call (asked by `asMetadata()` on every
// authorization), and `load()` read and parsed one entry per call (asked a
// few dozen times per sign-in, through `clientConfigOf()` and the rest).
// Both are kept by the registry's clock now, `applications.listingVersion()`.
//
//   A. `load()`, through `clientConfigOf()`: twenty questions about one
//      client read the directory once; a write to it is seen by the very
//      next question; the record each caller gets is its own.
//   B. `declaredTypes()`: asked twenty times, the registry is listed once; a
//      write under ou=applications rebuilds it; the kept answer is frozen.
//
// In process, development mode, the directory in memory — whose subtree
// clock moves exactly as a windowed one's does for a local write. What
// another process's write does to the clock is `ldap/CLAUDE.md`'s (the
// change-log applier calls `touchDirectory()` with the DN).
// ===========================================================================

delete process.env.CONFIG_FILE;

const ldapServer = require('../ldap/ldap_server');
const applications = require('../common/applications');
const cacheRegistry = require('../common/cache_registry');
const authorizationDetails = require('../oauth-oidc/authorization_details');

const log = require('bunyan').createLogger({ name: 'sign_in_registry_reads',
  level: process.env.LOG_LEVEL || 'info' });

const CLIENT = 'registry-reads-' + Date.now().toString(36);

function loadCounts() {
  log.debug("Entering loadCounts().");
  const d = cacheRegistry.detail('applications.load');
  const s = (d && d.summary) || {};
  log.debug("Leaving loadCounts().");
  return { hits: Number(s.hits || 0), misses: Number(s.misses || 0) };
}

// A sighting: what every authentication records, and a write under
// ou=applications that moves the registry's clock.
function sighting() {
  log.debug("Entering sighting().");
  log.debug("Leaving sighting().");
  return applications.seen({ identifier: CLIENT, kinds: ['oauth2-client'],
                             protocol: 'oauth2', user: 'registry-reader' });
}

function loadIsKept(t) {
  log.debug("Entering loadIsKept().");
  t.log.info('=== A. load(), through clientConfigOf(), is kept by the ' +
             'registry clock ===');
  t.check(!!ldapServer && cacheRegistry.has('applications.load'),
          'A0. the kept answers are described to /admin/caches');
  sighting();
  const before = loadCounts();
  let config = null;
  for (let i = 0; i < 20; i++) {
    config = applications.clientConfigOf(CLIENT);
  }
  const after = loadCounts();
  t.check(config && config.known === true,
          'A1. the client is known', JSON.stringify(config && config.known));
  t.equal(after.misses - before.misses, 1,
          'A2. twenty questions read the directory once');
  t.equal(after.hits - before.hits, 19,
          'A3. and the other nineteen were answered from that read');

  const authBefore = applications.list().filter(function (one) {
    return one.identifier === CLIENT;
  })[0];
  sighting();
  const again = loadCounts();
  applications.clientConfigOf(CLIENT);
  const read = loadCounts();
  t.equal(read.misses - again.misses, 1,
          'A4. a write to the registry is seen by the very next question ' +
          '(it reads the directory again)');
  const authAfter = applications.list().filter(function (one) {
    return one.identifier === CLIENT;
  })[0];
  t.check(!!authBefore && !!authAfter &&
          authAfter.authentications === authBefore.authentications + 1,
          'A5. and what it reads is the write',
          JSON.stringify([authBefore && authBefore.authentications,
                          authAfter && authAfter.authentications]));

  const first = applications.clientConfigOf(CLIENT);
  first.redirect_uris.push('https://changed.example/cb');
  const second = applications.clientConfigOf(CLIENT);
  t.check(second.redirect_uris.indexOf('https://changed.example/cb') < 0,
          'A6. each caller gets an answer of its own: changing one does ' +
          'not change the next');
  log.debug("Leaving loadIsKept().");
}

function declaredTypesAreKept(t) {
  log.debug("Entering declaredTypesAreKept().");
  t.log.info('=== B. declaredTypes() is kept by the registry clock ===');
  const realList = applications.list;
  let listed = 0;
  applications.list = function () {
    listed += 1;
    return realList.apply(applications, arguments);
  };
  try {
    sighting();
    let types = null;
    for (let i = 0; i < 20; i++) {
      types = authorizationDetails.declaredTypes();
    }
    t.equal(listed, 1, 'B1. asked twenty times, the registry is listed once');
    t.check(Object.isFrozen(types),
            'B2. the kept answer is frozen: a caller cannot change it for ' +
            'the next');
    sighting();
    authorizationDetails.declaredTypes();
    t.equal(listed, 2, 'B3. a write under ou=applications rebuilds it');
  } finally {
    applications.list = realList;
  }
  log.debug("Leaving declaredTypesAreKept().");
}

function run(t) {
  log.debug("Entering run().");
  loadIsKept(t);
  declaredTypesAreKept(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'sign_in_registry_reads',
  describe: 'a sign-in does not rebuild the application registry per ' +
            'question (#758): load() and declaredTypes() are kept by the ' +
            'registry clock, and a write is seen at once',
  run: run
};
