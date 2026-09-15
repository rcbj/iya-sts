'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'mode_hardcoded_foundation',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: mode_hardcoded_foundation.js
//
// ---------------------------------------------------------------------------
// THE SHARED HALF OF THE 2026-09-12 SWEEP FOR HARD-CODED VALUES.
//
// An audit of the protocol code found development-mode behaviour written as
// literals with no mode check — a persona surname in every ID Token, a bind
// address ignored by five listeners, a base URL any Host header could choose.
// The per-family fixes are tested beside their families; this file holds the
// pieces every family was handed:
//
//   1. the four new `common/mode.js` predicates, and that each is the OPPOSITE
//      of product mode — a predicate answering `isProduct()` where it should
//      answer its negation would turn every demo seed on in product and off
//      in development, with every page still rendering;
//   2. `userFor()` inventing nothing in product mode and exactly what it
//      always invented in development — the second half is what keeps the
//      parent project's suite green;
//   3. `global.publicBaseUrl` pinning `baseUrlOf()` whatever Host a request
//      carried, and reading the request exactly as before when empty;
//   4. `listenHost()` / `loopbackHost()` / `hostForUrl()`;
//   5. `pki.crlLifetimeMinutes` honouring its own declared floor of one
//      minute rather than a second, silent floor of sixty.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

function fakeRequest(host) {
  log.debug("Entering fakeRequest().");
  log.debug("Leaving fakeRequest().");
  return {
    protocol: 'https',
    headers: { host: host },
    get: function (name) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return String(name).toLowerCase() === 'host' ? host : undefined;
    }
  };
}

function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const mode = require('../common/mode');
  const helpers = require('../common/helpers');

  // --- 1. the predicates -------------------------------------------------
  const predicates = ['seedsDemoData', 'inventsClaimValues',
                      'acceptsUnregisteredAddresses', 'opensTestControls'];
  try {
    config.setOverride('global.mode', 'development');
    predicates.forEach(function (name) {
      t.equal(mode[name](), true, name + '() answers true in development');
    });
    config.setOverride('global.mode', 'product');
    predicates.forEach(function (name) {
      t.equal(mode[name](), false, name + '() answers false in product');
    });
    const ids = mode.report().requirements.map(function (r) { return r.id; });
    ['demo-data', 'claim-values', 'return-addresses', 'test-controls']
      .forEach(function (id) {
        t.check(ids.indexOf(id) >= 0,
                'mode.report() names the "' + id + '" requirement, so ' +
                '/admin/mode and the API say what product mode changed', ids);
      });

    // --- 2. userFor() ------------------------------------------------------
    const product = helpers.userFor('alice');
    // THE SUBJECT IS THE DIRECTORY'S, NOT THE MODE'S (2026-09-14):
    // `urn:uuid:<entryUUID>` where a directory is loaded, and '' in a process
    // with none. Asserted against the resolver rather than as a literal,
    // because `run.js` runs every file in one process and whether an earlier
    // file loaded the directory is not this file's to decide.
    t.equal(product.sub, helpers.subjectForName('alice'),
            'product mode gives the subject the directory gives');
    t.check(product.sub === '' || /^urn:uuid:/.test(product.sub),
            'and it is never the retired name-derived form', product.sub);
    t.equal(product.preferred_username, 'alice',
            'and the name that authenticated');
    ['name', 'given_name', 'family_name', 'email', 'email_verified']
      .forEach(function (field) {
        t.check(!(field in product),
                'product mode does not invent `' + field + '`', product[field]);
      });

    config.setOverride('global.mode', 'development');
    const dev = helpers.userFor('alice');
    t.equal(dev.sub, product.sub, 'development gives the same subject — ' +
            'the mode decides invented claims, not who somebody is');
    t.equal(dev.family_name, 'Mock', 'development keeps the persona surname');
    t.equal(dev.email, 'alice@sts.example',
            'development keeps the persona address');
    t.equal(dev.email_verified, true,
            'development keeps email_verified exactly as it always was');
    t.equal(dev.name, 'alice (mock)', 'development keeps the persona name');
  } finally {
    config.clearOverride('global.mode');
  }

  // --- 3. the base URL pin -------------------------------------------------
  try {
    config.clearOverride('global.publicBaseUrl');
    t.equal(helpers.baseUrlOf(fakeRequest('evil.example')),
            'https://evil.example',
            'unpinned, the base is read off the request as it always was');
    config.setOverride('global.publicBaseUrl', 'https://idp.example.com/');
    t.equal(helpers.baseUrlOf(fakeRequest('evil.example')),
            'https://idp.example.com',
            'pinned, an invented Host header cannot choose the base (and a ' +
            'trailing slash on the setting is not doubled)');
    t.equal(helpers.pinnedBaseUrl(), 'https://idp.example.com',
            'pinnedBaseUrl() reports the pin');
  } finally {
    config.clearOverride('global.publicBaseUrl');
  }

  // --- 4. the host helpers -----------------------------------------------
  t.equal(helpers.listenHost(), String(config.value('global.host')),
          'listenHost() is global.host');
  t.equal(helpers.hostForUrl('::1'), '[::1]', 'an IPv6 literal is bracketed');
  t.equal(helpers.hostForUrl('[::1]'), '[::1]', 'and not bracketed twice');
  t.equal(helpers.hostForUrl('127.0.0.1'), '127.0.0.1',
          'an IPv4 address is left alone');
  if (String(config.value('global.host')) === '0.0.0.0') {
    t.equal(helpers.loopbackHost(), '127.0.0.1',
            'a wildcard IPv4 bind is dialled on IPv4 loopback');
  }

  // --- 4b. a sighting cannot register a return address in product ----------
  // Product mode checks a SAML ACS URL or a wreply against the entry, so an
  // entry that LEARNT the address from the request being checked would make
  // the check circular. The entry must already exist in product (nothing is
  // created on sight), so it is created first, as a registration would.
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const suffix = String(Date.now());
  const acsOf = function (id) {
    log.debug("Entering acsOf().");
    const got = applications.get(id);
    log.debug("Leaving acsOf().");
    return got ?
           [].concat((got.fields || {}).samlAssertionConsumerService || []) :
           [];
  };
  try {
    config.setOverride('global.mode', 'development');
    const devId = 'urn:test:mhf-dev-' + suffix;
    applications.seen({ identifier: devId, kind: 'saml2-service-provider',
      counts: false,
      fields: { samlAssertionConsumerService: 'https://dev.test/acs' } });
    t.check(acsOf(devId).indexOf('https://dev.test/acs') >= 0,
            'development still records the ACS URL a request named',
            acsOf(devId));

    const prodId = 'urn:test:mhf-prod-' + suffix;
    const created = applications.createApplication({
      identifier: prodId, kind: 'saml2-service-provider',
      fields: { samlEntityId: prodId,
                samlAssertionConsumerService:
                  ['https://registered.test/acs'] } });
    t.check(created && created.ok !== false,
            'a product-mode fixture entry was registered',
            JSON.stringify((created && created.errors) || []));
    config.setOverride('global.mode', 'product');
    applications.seen({ identifier: prodId, kind: 'saml2-service-provider',
      counts: false,
      fields: { samlAssertionConsumerService: 'https://evil.test/acs' } });
    const held = acsOf(prodId);
    t.check(held.indexOf('https://evil.test/acs') < 0,
            'product mode does NOT let a sighting add an ACS URL', held);
    t.check(held.indexOf('https://registered.test/acs') >= 0,
            'and the registered one is still there', held);
  } finally {
    config.clearOverride('global.mode');
  }

  // --- 5. the CRL lifetime floor -------------------------------------------
  const revocation = require('../common/pki_revocation');
  if (typeof revocation.crlLifetimeMs === 'function') {
    try {
      config.setOverride('pki.crlLifetimeMinutes', 5);
      t.equal(revocation.crlLifetimeMs(), 5 * 60000,
              'a five-minute CRL lifetime is five minutes, not an hour');
    } finally {
      config.clearOverride('pki.crlLifetimeMinutes');
    }
  } else {
    t.check(true, 'crlLifetimeMs() is not exported; the floor is covered by ' +
                  'reading the source instead');
    const fs = require('fs');
    const path = require('path');
    const source = fs.readFileSync(
      path.join(__dirname, '..', 'common', 'pki_revocation.js'), 'utf8');
    t.check(!/Math\.max\(60,\s*Number\(config\.value\('pki\.crlLifetimeMinutes'\)/
      .test(source),
            'pki_revocation.js no longer floors pki.crlLifetimeMinutes at 60');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'mode and hard-coded foundation',
  describe: 'the four product-mode predicates, userFor() in both modes, the ' +
            'public base URL pin, the bind/loopback host helpers',
  run: run
};
