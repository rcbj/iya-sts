'use strict';

// ===========================================================================
// tests/cache_registry.js — MONITORING → CACHES (#74, 2026-09-17).
//
// `common/cache_registry.js` is where every cache describes itself, and
// `admin-ui/caches_admin.ts` draws what it says. Six claims:
//
//   1. A descriptor missing a member is refused WHOLE, with its code.
//   2. The figures are right: size, the valid/expired split against a held
//      clock (a row past its deadline is expired, a row with no deadline is
//      valid unless its owner says otherwise), hits, misses and the ratio —
//      null before any lookup rather than a zero that reads as "useless".
//   3. A row carries five named members and NOTHING ELSE, whatever its
//      descriptor handed back — so a cache of key material cannot put a
//      value on the page. And a descriptor that throws costs its rows and
//      not the report.
//   4. Every cache the design names is registered by its owner once those
//      modules are loaded, and a real lookup moves a real counter.
//   5. The view model pages one cache's entries soonest deadline first, and
//      an unknown name is `found: false` with the names that exist.
//   6. The page draws the list with a link per cache, and a drill-down with
//      the trail back, paging links that keep `cache=`, the entries' keys and
//      none of their values; an unknown name is a 200 page marked
//      STS-ADMIN-0021.
//
// In process: the registry is a library, and the page's handler is called
// below the console gate with a request carrying only a query, as
// `kerberos_principals_paging.js` does.
// ===========================================================================

delete process.env.CONFIG_FILE;

const registry = require('../common/cache_registry');
const errorCodes = require('../common/error_codes');
const app = require('../common/app');
// Loading a module registers nothing since #50's R1, so the page's route is
// registered here. The console shell comes first, as in the composition root.
require('../admin-ui/admin').registerRoutes(app);
const cachesAdmin = require('../admin-ui/caches_admin');
cachesAdmin.registerRoutes(app);

const log = require('bunyan').createLogger({
  name: 'cache_registry',
  level: process.env.LOG_LEVEL || 'info' });

// Every store `docs/caches.md` names that this process holds in memory, by
// the module that registers it — the caches and the replay stores alike.
const OWNERS = {
  '../common/tls_client_certificates': ['tls.client-certificate-identities'],
  '../common/worker_pool': ['workers.crypto-affinity'],
  '../common/request_pool': ['workers.request-affinity'],
  '../persistence/persistence': ['persistence.write-shadow'],
  '../common/used_assertions': ['oauth2.used-assertions'],
  '../ssf/ssf_streams': ['ssf.dead-letter-counts'],
  '../saml/saml11_sso': ['saml11.assertions'],
  '../oauth-oidc/dpop': ['dpop.proof-ids', 'dpop.nonces'],
  '../gnap/gnap_store': ['gnap.signatures'],
  '../acme/acme_store': ['acme.nonces'],
  '../scim/scim_auth': ['scim.digest-nonces', 'scim.digest-nonce-counts',
    'scim.hoba-challenges', 'scim.hoba-signatures'],
  '../oid4vc/vc_issuer': ['oid4vci.nonces'],
  '../common/revocation_status': ['revocation.crl', 'revocation.ocsp',
    'revocation.ca-certificates', 'revocation.failures',
    'revocation.parsed-tiers', 'revocation.pem-files'],
  '../common/jose_kid': ['jose.kid-thumbprint-uris'],
  '../common/jose_certificate_header': ['jose.x5c-key-match',
    'jose.x5c-chain-under-root'],
  '../common/helpers': ['keys.signing-sets', 'keys.post-quantum-sets'],
  '../common/keystore': ['keys.plaintext', 'keys.ca-hierarchies'],
  '../common/applications': ['applications.ssf-allowed-events'],
  '../oauth-oidc/oauth2': ['oauth2.signed-metadata',
    'oauth2.redeemed-codes'],
  '../oauth-oidc/request_object': ['oauth2.request-uri'],
  '../oauth-oidc/authorization_details': [
    'oauth2.authorization-details-types'],
  '../xacml/xacml_store': ['xacml.parsed-policies'],
  '../federation/federation': ['federation.release-index'],
  '../ldap/ldap_server': ['ldap.username-index', 'ldap.group-index',
    'ldap.entryuuid-index', 'ldap.subtree-listings'],
  '../kerberos/krb5_principals': ['krb5.long-term-keys',
    'krb5.authenticator-replay'],
  '../spiffe/spiffe_ca': ['spiffe.x509-authorities'],
  '../debugger/debugger_server': ['debugger.static-files']
};

// A marker no row may ever carry.
const SECRET = 'cache-registry-test-VALUE-must-not-appear';
const NOW = 1800000000000;

function testDescriptor(name, rows) {
  log.debug("Entering testDescriptor().");
  log.debug("Leaving testDescriptor().");
  return {
    name: name,
    title: 'Test cache ' + name,
    description: 'A cache registered by tests/cache_registry.js.',
    owner: 'tests/cache_registry.js',
    scope: 'realm',
    settings: ['test.setting'],
    maxEntries: function () {
      return 10;
    },
    lifetime: function () {
      return 'As long as the test says.';
    },
    entries: function () {
      return rows;
    }
  };
}

function handler() {
  log.debug("Entering handler().");
  const layer = (app._router.stack || []).filter(function (one) {
    return one.route && one.route.path === '/admin/caches' &&
           one.route.methods.get;
  })[0];
  log.debug("Leaving handler(). " + (layer ? "Found." : "Not found."));
  return layer ? layer.route.stack[0].handle : null;
}

function draw(query) {
  log.debug("Entering draw().");
  const out = { body: '', res: null };
  const res = {
    set: function () {
      return this;
    },
    status: function () {
      return this;
    },
    type: function () {
      return this;
    },
    send: function (text) {
      out.body = String(text);
      return this;
    },
    json: function (value) {
      out.body = JSON.stringify(value);
      return this;
    },
    get: function () {
      return undefined;
    },
    getHeader: function () {
      return undefined;
    },
    setHeader: function () {
      return undefined;
    },
    locals: {}
  };
  out.res = res;
  const req = { query: query, headers: {}, method: 'GET', cookies: {},
                url: '/admin/caches', originalUrl: '/admin/caches',
                path: '/admin/caches',
                get: function () {
                  return '';
                } };
  handler()(req, res, function (e) {
    log.debug("The caches handler called next(): " + ((e && e.message) || e));
  });
  log.debug("Leaving draw(). " + out.body.length + " character(s).");
  return out;
}

function claimOne(t) {
  log.debug("Entering claimOne().");
  t.log.info('=== 1. an incomplete descriptor is refused whole ===');
  let thrown = null;
  try {
    registry.register({ name: 'test.incomplete', title: 'x',
                        description: 'x', owner: 'x', scope: 'galaxy',
                        maxEntries: function () {
                          return 1;
                        } });
  } catch (e) {
    log.debug("Caught in claimOne(): " + ((e && e.message) || e));
    thrown = e;
  }
  t.check(!!thrown && /STS-CORE-0094/.test(thrown.message) &&
          /lifetime/.test(thrown.message) && /entries/.test(thrown.message) &&
          /scope/.test(thrown.message),
          'a descriptor with a bad scope and no lifetime or entries is ' +
          'refused, naming all three, under STS-CORE-0094',
          thrown ? thrown.message : 'nothing was thrown');
  t.check(!registry.has('test.incomplete'),
          'and nothing of it was registered');
  log.debug("Leaving claimOne().");
}

function claimTwoAndThree(t) {
  log.debug("Entering claimTwoAndThree().");
  t.log.info('=== 2. size, valid, expired, hits and the ratio ===');
  const count = registry.register(testDescriptor('test.figures', [
    { realm: 'default', key: 'live', validUntil: NOW + 5000,
      value: SECRET },
    { realm: 'acme', key: 'dead', validUntil: NOW - 1000 },
    { key: 'forever', validUntil: null },
    { key: 'stale', validUntil: null, valid: false, basis: 'thing' }
  ]));
  let row = registry.report(NOW).filter(function (c) {
    return c.name === 'test.figures';
  })[0];
  t.equal(row.hitRatio, null,
          'before any lookup the hit ratio is null, not zero');
  t.check(row.size === 4 && row.valid === 2 && row.expired === 2,
          'four held: the future deadline and the undated row are valid, ' +
          'the past deadline and the one its owner calls stale are expired',
          JSON.stringify(row));
  count.hit();
  count.hit();
  count.hit();
  count.miss();
  row = registry.report(NOW).filter(function (c) {
    return c.name === 'test.figures';
  })[0];
  t.check(row.hits === 3 && row.misses === 1 && row.hitRatio === 0.75,
          'three hits and a miss are a ratio of 0.75',
          JSON.stringify([row.hits, row.misses, row.hitRatio]));
  t.check(row.maxEntries === 10 && row.scope === 'realm' &&
          row.settings[0] === 'test.setting' && row.problem === null,
          'the bound, scope and settings are the descriptor\'s');
  registry.counter('test.figures').miss();
  t.equal(registry.detail('test.figures', NOW).summary.misses, 2,
          'counter() by name reaches the same cache\'s counts');

  t.log.info('=== 3. five members a row, and a throwing descriptor ===');
  const detail = registry.detail('test.figures', NOW);
  const members = Object.keys(detail.rows[0]).sort().join(',');
  t.equal(members, 'basis,key,realm,valid,validUntil',
          'a row carries exactly the five named members');
  t.check(JSON.stringify(detail).indexOf(SECRET) < 0,
          'and the value a descriptor handed back is not in it');
  const bad = testDescriptor('test.throws', []);
  bad.entries = function () {
    throw new Error('the owner broke');
  };
  registry.register(bad);
  const report = registry.report(NOW);
  const broken = report.filter(function (c) {
    return c.name === 'test.throws';
  })[0];
  t.check(!!broken && broken.size === 0 &&
          /the owner broke/.test(String(broken.problem)) &&
          report.length >= 2,
          'a descriptor that throws is reported with no rows and its ' +
          'problem, and the report still lists everything else');
  registry.forget('test.throws');
  log.debug("Leaving claimTwoAndThree().");
}

function claimFour(t) {
  log.debug("Entering claimFour().");
  t.log.info('=== 4. every cache the design names is registered ===');
  const missing = [];
  Object.keys(OWNERS).forEach(function (path) {
    require(path);
    OWNERS[path].forEach(function (name) {
      if (!registry.has(name)) {
        missing.push(name + ' (' + path + ')');
      }
    });
  });
  t.check(missing.length === 0,
          'all ' + Object.keys(OWNERS).reduce(function (n, k) {
            return n + OWNERS[k].length;
          }, 0) + ' caches are registered by their owners',
          missing.join(', '));
  const real = registry.report(Date.now()).filter(function (c) {
    return c.name.indexOf('test.') !== 0;
  });
  t.check(real.every(function (c) {
    return c.owner && c.description && c.lifetime &&
           (c.maxEntries === null || c.maxEntries > 0) && !c.problem;
  }), 'every real cache describes itself and lists its entries without ' +
      'failing', JSON.stringify(real.filter(function (c) {
    return c.problem;
  }).map(function (c) {
    return c.name + ': ' + c.problem;
  })));

  const byName = {};
  real.forEach(function (c) {
    byName[c.name] = c;
  });
  const replays = real.filter(function (c) {
    return c.kind === 'replay';
  }).map(function (c) {
    return c.name;
  });
  t.check(replays.indexOf('oauth2.used-assertions') >= 0 &&
          replays.indexOf('dpop.proof-ids') >= 0 &&
          replays.indexOf('krb5.authenticator-replay') >= 0 &&
          replays.indexOf('xacml.parsed-policies') < 0,
          'the replay stores are the replay kind and the caches are not',
          replays.join(', '));
  const krb = byName['krb5.authenticator-replay'];
  t.check(!!krb && krb.counted === false && krb.hits === null &&
          krb.hitRatio === null,
          'the Kerberos authenticator store, whose lookup is in a locked ' +
          'file, is listed and not counted');

  const joseKid = require('../common/jose_kid');
  const before = registry.detail('jose.kid-thumbprint-uris').summary;
  const jwk = { kty: 'oct', k: 'Y2FjaGUtcmVnaXN0cnk' };
  joseKid.thumbprintUriFor('cache-registry-test-kid', jwk);
  joseKid.thumbprintUriFor('cache-registry-test-kid', jwk);
  const after = registry.detail('jose.kid-thumbprint-uris');
  t.check(after.summary.misses === before.misses + 1 &&
          after.summary.hits === before.hits + 1,
          'computing a kid\'s URI once and asking again is one miss and ' +
          'one hit on the real cache',
          JSON.stringify([before.hits, before.misses, after.summary.hits,
                          after.summary.misses]));
  t.check(after.rows.some(function (r) {
    return r.key === 'cache-registry-test-kid' && r.valid &&
           r.validUntil === null;
  }), 'and its entry is listed by kid, valid, with no deadline');
  log.debug("Leaving claimFour().");
}

function claimFive(t) {
  log.debug("Entering claimFive().");
  t.log.info('=== 5. the view model pages one cache ===');
  const rows = [];
  for (let n = 0; n < 7; n++) {
    // Registered out of order, so the sort is what puts them in order.
    rows.push({ realm: 'default', key: 'entry-' + n,
                validUntil: Date.now() + (7 - n) * 60000, value: SECRET });
  }
  rows.push({ realm: 'default', key: 'entry-undated', validUntil: null });
  registry.register(testDescriptor('test.paged', rows));
  const third = cachesAdmin.cachesView({ cache: 'test.paged', per: '3',
                                         page: '3' });
  t.check(third.found === true && third.entriesPaging.page === 3 &&
          third.entriesPaging.pages === 3 && third.entriesPaging.total === 8,
          'eight entries at three a page: page 3 of 3',
          JSON.stringify(third.entriesPaging));
  t.equal(third.entries.map(function (e) {
    return e.key;
  }).join(','), 'entry-0,entry-undated',
          'soonest deadline first — entry-6 leads page 1 — and the undated ' +
          'entry last');
  t.check(third.entries[0].remainingSeconds > 0 &&
          /min/.test(third.entries[0].remaining) &&
          /no expiry/.test(third.entries[1].remaining),
          'each entry says how long it is still valid',
          JSON.stringify(third.entries.map(function (e) {
            return e.remaining;
          })));
  t.check(third.paging === undefined && JSON.stringify(third)
    .indexOf(SECRET) < 0,
          'the public reply carries no drawing state and no value');
  const past = cachesAdmin.cachesView({ cache: 'test.paged', per: '3',
                                        page: '99' });
  t.equal(past.entriesPaging.page, 3, 'a page past the end is clamped');
  const unknown = cachesAdmin.cachesView({ cache: 'no.such.cache' });
  t.check(unknown.found === false && unknown.known.indexOf('test.paged') >= 0,
          'an unknown cache is found: false, with the names that exist');
  const list = cachesAdmin.cachesView({});
  t.check(Array.isArray(list.caches) && list.totals.caches ===
          list.caches.length && list.notListed.length === 6 &&
          typeof list.pid === 'number',
          'with no cache named, the reply is the list, its totals and the ' +
          'six things deliberately left out');
  const repeated = cachesAdmin.cachesView({ cache: ['test.paged', 'x'] });
  t.equal(repeated.cache, 'test.paged',
          'a repeated `cache` takes the first value');
  const nested = cachesAdmin.cachesView({ cache: { a: 'b' } });
  t.check(nested.cache === undefined && Array.isArray(nested.caches),
          'an object where a name belongs is no name at all');
  log.debug("Leaving claimFive().");
}

function claimSix(t) {
  log.debug("Entering claimSix().");
  t.log.info('=== 6. the page ===');
  t.check(typeof handler() === 'function', 'GET /admin/caches is registered');
  const list = draw({});
  t.check(list.body.indexOf('href="/admin/caches?cache=test.paged"') >= 0 &&
          list.body.indexOf('Hit ratio') >= 0 &&
          list.body.indexOf('client_address.js') >= 0,
          'the list links every cache and names what it leaves out');
  const one = draw({ cache: 'test.paged', per: '3', page: '2' });
  t.check(one.body.indexOf('entry-2') >= 0 &&
          one.body.indexOf('entry-6') < 0,
          'the drill-down draws the page it was asked for');
  const pager = one.body.match(/href="\/admin\/caches\?[^"#]*#list-page"/g) ||
    [];
  t.check(pager.length > 0 && pager.every(function (href) {
    return href.indexOf('cache=test.paged') >= 0;
  }), 'every paging link keeps `cache=`', pager.slice(0, 2).join(' '));
  t.check(/<a href="\/admin\/caches"[ >]/.test(one.body),
          'the trail leads back to the list');
  t.check(one.body.indexOf(SECRET) < 0, 'no cached value is drawn');
  t.check(errorCodes.codeOf(one.res) === '',
          'a known cache is not marked');
  const missing = draw({ cache: 'no.such.cache' });
  t.check(missing.body.indexOf('There is no cache called') >= 0 &&
          /<a href="\/admin\/caches"[ >]/.test(missing.body),
          'an unknown cache is a page saying so, with the trail back');
  t.equal(errorCodes.codeOf(missing.res), 'STS-ADMIN-0021',
          'and it is marked STS-ADMIN-0021');
  const json = draw({ cache: 'test.paged', format: 'json' });
  let parsed = null;
  try {
    parsed = JSON.parse(json.body);
  } catch (e) {
    log.debug("Caught in claimSix(): " + ((e && e.message) || e));
    parsed = null;
  }
  t.check(!!parsed && parsed.found === true && parsed.paging === undefined,
          '?format=json answers the public view', json.body.slice(0, 120));
  log.debug("Leaving claimSix().");
}

function run(t) {
  log.debug("Entering run().");
  try {
    claimOne(t);
    claimTwoAndThree(t);
    claimFour(t);
    claimFive(t);
    claimSix(t);
  } finally {
    // The test caches go, so a later file in this process does not list them
    // (and the throwing one does not log an error on every report).
    ['test.figures', 'test.throws', 'test.paged'].forEach(function (name) {
      registry.forget(name);
    });
  }
  t.check(registry.names().every(function (name) {
    return name.indexOf('test.') !== 0;
  }), 'forget() removes the test caches again');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cache_registry',
  describe: 'Monitoring → Caches (#74): the cache registry\'s figures and ' +
            'row shape, every named cache registered by its owner, and the ' +
            'page and view model that draw them.',
  run: run
};
