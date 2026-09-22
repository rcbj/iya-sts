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
//   7. EVERY STORE IS BOUNDED (2026-09-18): every real cache reports a finite
//      bound and says whether it is enforced or structural; `makeRoom()`
//      drops the oldest, or refuses and logs STS-CORE-0097 once, and counts
//      either; a descriptor reporting no bound is a row with STS-CORE-0096 on
//      it; a per-realm store's fullest realm is what the bound is compared
//      with; the cluster snapshot survives its round trip; and a real
//      replay store — GNAP's — refuses rather than forgets at its bound.
//   8. THE OTHER NODES (2026-09-18): the page draws every published snapshot
//      that is not its own process's — another node's, and this node's front
//      process's when a worker answers — and nothing from a node that left;
//      and `cluster.js` puts the snapshot on the membership row, off the
//      heartbeat's own path (asserted as SOURCE: a node's row is written by a
//      store driver no in-process test opens).
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
    'revocation.parsed-tiers', 'revocation.pem-files',
    'revocation.presented-chains'],
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
  '../debugger/debugger_server': ['debugger.static-files'],
  // The three single-value memos the page listed as held and not reported
  // until 2026-09-18 — the version stamp is described from the page's own
  // module, because `common/version.js` may require nothing of this service.
  '../common/client_address': ['global.trusted-proxies'],
  '../persistence/persistence_minted': ['persistence.observational-stores'],
  '../admin-ui/caches_admin': ['version.stamp']
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
    return c.owner && c.description && c.lifetime && !c.problem;
  }), 'every real cache describes itself and lists its entries without ' +
      'failing', JSON.stringify(real.filter(function (c) {
    return c.problem;
  }).map(function (c) {
    return c.name + ': ' + c.problem;
  })));
  // THE BOUND (2026-09-18): a finite number above zero on every store, and a
  // sentence saying whether it is enforced or structural. Twenty-four stores
  // answered null until that day.
  const unbounded = real.filter(function (c) {
    return !(typeof c.maxEntries === 'number' && isFinite(c.maxEntries) &&
             c.maxEntries > 0) || !/^(Enforced|Structural):/.test(c.bound);
  }).map(function (c) {
    return c.name + ' (' + c.maxEntries + ', "' + c.bound + '")';
  });
  t.check(unbounded.length === 0,
          'every real cache reports a finite bound and says whether it is ' +
          'enforced or structural', unbounded.join('; '));

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
          list.caches.length && list.notListed.length === 3 &&
          Array.isArray(list.otherProcesses) &&
          typeof list.pid === 'number',
          'with no cache named, the reply is the list, its totals, the ' +
          'three things this process does not hold, and the other ' +
          'processes\' figures');
  t.check(list.notListed.every(function (n) {
    return !/client_address|version\.js|persistence_minted/.test(n.where);
  }), 'no memo that is now a registered cache is still listed as left out');
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
          list.body.indexOf('common/secrets.js') >= 0 &&
          list.body.indexOf('Other cluster nodes') >= 0,
          'the list links every cache, names what it leaves out and has a ' +
          'section for the other nodes');
  t.check(list.body.indexOf('10 per realm') >= 0 &&
          list.body.indexOf('fullest realm') >= 0 &&
          />unbounded</.test(list.body) === false,
          'a per-realm bound is drawn "per realm" with its fullest realm, ' +
          'and no row says unbounded');
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

function claimSeven(t) {
  log.debug("Entering claimSeven().");
  t.log.info('=== 7. every store is bounded ===');
  const counted = registry.register(testDescriptor('test.bounded', []));

  // Drop the oldest: insertion order, and the counter hears it.
  const m = new Map([['a', 1], ['b', 2], ['c', 3]]);
  const room = registry.makeRoom(m, 3, { counter: counted });
  t.check(room.ok && room.evicted === 1 && !m.has('a') && m.size === 2,
          'at the bound the OLDEST entry is dropped to make room for one',
          JSON.stringify(Array.from(m.keys())));
  // The expired go first, so a store with dead entries drops nothing live.
  const aged = new Map([['old', 0], ['live1', 9], ['live2', 9]]);
  const aged2 = registry.makeRoom(aged, 3, {
    counter: counted,
    expired: function (v) {
      return v === 0;
    }
  });
  t.check(aged2.ok && aged2.evicted === 0 && aged.has('live1') &&
          aged.has('live2') && !aged.has('old'),
          'an expired entry is dropped before any live one is');
  // Refuse: nothing dropped, a refusal counted, and logged once a minute.
  const replay = new Map([['x', 1], ['y', 1]]);
  const lines = [];
  const logger = require('bunyan').createLogger({ name: 'sts-cache-registry' });
  const original = logger.constructor.prototype.warn;
  logger.constructor.prototype.warn = function (msg) {
    lines.push(String(msg));
    return original.apply(this, arguments);
  };
  let first = null;
  let second = null;
  try {
    first = registry.makeRoom(replay, 2, { policy: 'refuse',
                                           counter: counted,
                                           name: 'test.bounded' });
    second = registry.makeRoom(replay, 2, { policy: 'refuse',
                                            counter: counted,
                                            name: 'test.bounded' });
  } finally {
    logger.constructor.prototype.warn = original;
  }
  t.check(!first.ok && !second.ok && replay.size === 2 && replay.has('x'),
          'a store that decides a replay REFUSES at its bound and forgets ' +
          'nothing live');
  t.equal(lines.filter(function (l) {
    return /STS-CORE-0097/.test(l);
  }).length, 1, 'and says so once, with STS-CORE-0097, not once per refusal');
  const summary = registry.report(NOW).filter(function (c) {
    return c.name === 'test.bounded';
  })[0];
  t.check(summary.evictions === 1 && summary.refusals === 2,
          'the drops and the refusals are counted on the row',
          JSON.stringify([summary.evictions, summary.refusals]));
  registry.forget('test.bounded');

  // A per-realm bound is compared with the fullest realm.
  registry.register(testDescriptor('test.per-realm', [
    { realm: 'a', key: '1' }, { realm: 'a', key: '2' },
    { realm: 'b', key: '1' }, { realm: 'c', key: '1' }
  ]));
  const per = registry.report(NOW).filter(function (c) {
    return c.name === 'test.per-realm';
  })[0];
  t.check(per.size === 4 && per.largestRealm === 2 && per.atBound === false,
          'a per-realm store counts every realm in its size and compares ' +
          'its fullest realm with the bound',
          JSON.stringify([per.size, per.largestRealm, per.atBound]));
  registry.forget('test.per-realm');

  // A descriptor that reports no bound is a regression, shown on its row.
  const none = testDescriptor('test.no-bound', []);
  none.maxEntries = function () {
    return null;
  };
  registry.register(none);
  const flagged = registry.report(NOW).filter(function (c) {
    return c.name === 'test.no-bound';
  })[0];
  t.check(flagged.maxEntries === null &&
          /STS-CORE-0096/.test(String(flagged.problem)),
          'a store answering no bound is shown with STS-CORE-0096');
  registry.forget('test.no-bound');

  // The compact form another cluster node reads.
  const snap = registry.snapshot(NOW);
  const row = snap.caches.map(registry.unpackSnapshotRow).filter(function (c) {
    return c.name === 'jose.kid-thumbprint-uris';
  })[0];
  const full = registry.report(NOW).filter(function (c) {
    return c.name === 'jose.kid-thumbprint-uris';
  })[0];
  t.check(snap.pid === process.pid && !!row && row.size === full.size &&
          row.maxEntries === full.maxEntries && row.hits === full.hits &&
          JSON.stringify(snap).indexOf('cache-registry-test-kid') < 0,
          'the cluster snapshot carries every store\'s figures and no row');

  // A REAL replay store at its bound: GNAP's, built with a bound of two.
  const gnapStore = require('../gnap/gnap_store');
  const deps = gnapStore.GnapStore.defaultDeps();
  const stores = Object.assign({}, deps.stores, { replay: new Map() });
  const small = new gnapStore.GnapStore(Object.assign({}, deps, {
    stores: stores,
    replayBound: function () {
      return 2;
    }
  }));
  const outcomes = [small.rememberOutcome('one', 60),
                    small.rememberOutcome('two', 60),
                    small.rememberOutcome('three', 60),
                    small.rememberOutcome('one', 60)];
  t.equal(outcomes.join(','), 'new,new,full,seen',
          'GNAP\'s signature history refuses a third signature at a bound ' +
          'of two, and still recognises the first as a replay');
  log.debug("Leaving claimSeven().");
}

function claimEight(t) {
  log.debug("Entering claimEight().");
  t.log.info('=== 8. the other nodes ===');
  const fs = require('fs');
  const path = require('path');
  const cluster = require('../cluster/cluster');
  const snap = registry.snapshot(NOW - 12000);
  const node = function (id, name, pid, extra) {
    return Object.assign({ nodeId: id, name: name, leftAt: 0,
                           info: { host: name + '-host', pid: pid,
                                   caches: Object.assign({}, snap,
                                                         { pid: pid }) } },
                         extra || {});
  };
  const stub = Object.assign({}, cluster, {
    nodeId: function () {
      return 'self-node';
    },
    snapshot: function () {
      return { state: { nodes: [
        node('self-node', 'self', process.pid),
        node('self-node', 'self', process.pid + 1),
        node('other-node', 'other', 4242),
        node('gone-node', 'gone', 4343, { leftAt: NOW - 1 }),
        { nodeId: 'quiet-node', name: 'quiet', leftAt: 0, info: {} }
      ] }, ageMs: 10 };
    }
  });
  const deps = Object.assign(cachesAdmin.CachesAdmin.defaultDeps(),
                             { cluster: stub, now: function () {
                               return NOW;
                             } });
  const view = new cachesAdmin.CachesAdmin(deps);
  const others = view.cachesView({}).otherProcesses;
  t.equal(others.map(function (o) {
    return o.name + ':' + o.pid + ':' + o.thisNode;
  }).join(','), 'self:' + (process.pid + 1) + ':true,other:4242:false',
          'the other node and this node\'s front process are drawn; this ' +
          'process, a node that left and a node with no report are not');
  const other = others[1];
  t.check(other.ageSeconds === 12 &&
          other.caches.length === snap.caches.length &&
          other.caches.every(function (c) {
            return typeof c.maxEntries === 'number';
          }),
          'each carries every store\'s figures and how old they are');
  // The drawing of that section, by the same instance (`private` is a
  // compile-time word; the method is there at run time).
  const html = view['otherProcessesHtml'](others);
  t.check(html.indexOf('Node other') >= 0 &&
          /This node(&apos;|&#39;|&#x27;|')s front process/.test(html) &&
          html.indexOf('gone-host') < 0,
          'the page draws a folded table per other process and none for a ' +
          'node that left', html.replace(/<[^>]+>/g, ' ').slice(0, 300));
  // cluster.js, as source: the snapshot rides on the row, taken by a
  // scheduler job of its own.
  const src = fs.readFileSync(path.join(__dirname, '..', 'cluster',
                                        'cluster.js'), 'utf8');
  const info = /function nodeInfo\(\)[\s\S]*?\n}/.exec(src);
  t.check(!!info && /caches: cacheReport/.test(info[0]) &&
          !/snapshot\(/.test(info[0]),
          'nodeInfo() attaches the last snapshot and takes none itself — the ' +
          'walk is off the heartbeat\'s path');
  t.check(/scheduleCacheReport\(\)/.test(src) &&
          /CACHE_REPORT_JOB = 'cluster\.cache-report'/.test(src) &&
          /cacheReport = cacheRegistry\.snapshot\(\)/.test(src),
          'a joined node puts its report on the scheduler (the job ' +
          'cluster.cache-report, #49 P5), and the report is the registry\'s ' +
          'snapshot');
  log.debug("Leaving claimEight().");
}

function run(t) {
  log.debug("Entering run().");
  try {
    claimOne(t);
    claimTwoAndThree(t);
    claimFour(t);
    claimFive(t);
    claimSix(t);
    claimSeven(t);
    claimEight(t);
  } finally {
    // The test caches go, so a later file in this process does not list them
    // (and the throwing one does not log an error on every report).
    ['test.figures', 'test.throws', 'test.paged', 'test.bounded',
     'test.per-realm', 'test.no-bound'].forEach(function (name) {
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
