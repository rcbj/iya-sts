'use strict';
//
// File: used_assertions.js
//
// ===========================================================================
// AN RFC 7523 OR RFC 7522 ASSERTION IS ACCEPTED ONCE, EVER (2026-09-13).
//
// `common/used_assertions.js` replaced three replay caches that each refused a
// second use inside one process and forgot everything at a restart, never
// persisted in the ldif store, converged rather than agreed across processes,
// and let one JWT be spent twice — once as a client assertion, once as a
// grant. This file holds the in-process half of what replaced them:
//
//   A. one history, keyed by the DOCUMENT and not by what it was presented as;
//   B. an assertion is spent only when the response it was presented on
//      finishes 2xx, and released otherwise;
//   C. the ldif store keeps it across a restart, and keeps nothing released;
//   D. the postgres driver's claim is ONE atomic statement (its SQL shape,
//      against a fake `pg` — the live half is run by hand and recorded in
//      `common/CLAUDE.md`, because no in-process job has a database);
//   E. the token endpoint's two questions about one client assertion — the
//      RFC 9700 policy and the observation — get ONE answer per request,
//      which is the double-spend the history would otherwise have turned into
//      every `private_key_jwt` client being refused in product mode;
//   F. the three verifiers hold no cache of their own any more.
//
// What an over-HTTP job holds instead is the whole path through the token
// endpoint: `tests/vendored/sts_jwt_bearer_grant.js` and
// `tests/vendored/sts_saml2_bearer_grant.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');

const config = require('../common/config');
const realms = require('../common/realms');
const usedAssertions = require('../common/used_assertions');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({ name: 'used_assertions',
  level: process.env.LOG_LEVEL || 'info' });

// A realm of this file's own, so rows other files left in the default realm
// cannot fill the cap under an assertion here. `realms.run()` takes a realm
// RECORD, and it has to carry `overrides`: once an earlier file in the same
// process has defined a realm, `config.value()` reads the ambient record's
// overrides, and a record without them throws inside the setting read.
function realmRecord(prefix) {
  log.debug("Entering realmRecord().");
  log.debug("Leaving realmRecord().");
  return { id: prefix + Date.now().toString(36), overrides: {} };
}
const REALM = realmRecord('ua-probe-');
const OTHER = realmRecord('ua-other-');

function inRealm(realm, fn) {
  log.debug("Entering inRealm().");
  log.debug("Leaving inRealm().");
  return realms.run(realm, fn);
}

// A request whose response can be finished with a status, or closed first.
function fakeRequest() {
  log.debug("Entering fakeRequest().");
  const res = new EventEmitter();
  res.statusCode = 200;
  const req = { res: res };
  log.debug("Leaving fakeRequest().");
  return req;
}

function finish(req, status) {
  log.debug("Entering finish(). status=" + status);
  req.res.statusCode = status;
  req.res.emit('finish');
  req.res.emit('close');
  log.debug("Leaving finish().");
}

function later(ms) {
  log.debug("Entering later().");
  log.debug("Leaving later().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms || 20);
  });
}

function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(typeof value === 'string' ? value : JSON.stringify(value))
    .toString('base64url');
}

function hs256(secret, claims) {
  log.debug("Entering hs256().");
  const head = b64u({ alg: 'HS256', typ: 'JWT' });
  const body = b64u(claims);
  const sig = crypto.createHmac('sha256', secret).update(head + '.' + body)
    .digest('base64url');
  log.debug("Leaving hs256().");
  return head + '.' + body + '.' + sig;
}

function claimOf(overrides) {
  log.debug("Entering claimOf().");
  log.debug("Leaving claimOf().");
  return Object.assign({
    format: 'jwt', use: 'authorization-grant', issuer: 'ua-issuer',
    identifier: 'jti-' + crypto.randomBytes(6).toString('hex'),
    clientId: 'ua-client', subject: 'ua-alice',
    expiresAt: Date.now() + 120000
  }, overrides || {});
}

async function oneHistory(t) {
  log.debug("Entering oneHistory().");
  t.log.info('=== A. one history, keyed by the document ===');
  await inRealm(REALM, async function () {
    const first = claimOf();
    const a = await usedAssertions.claim(first);
    t.check(a.ok, 'an assertion nobody has used is accepted', a);
    const again = await usedAssertions.claim(first);
    t.check(!again.ok && again.reason === 'replay',
            'the same issuer and jti a second time is a replay', again);
    t.equal(again.existing && again.existing.use, 'authorization-grant',
            'and the refusal says what it was spent AS');

    const asClient = await usedAssertions.claim(Object.assign({}, first,
      { use: 'client-authentication' }));
    t.check(!asClient.ok && asClient.reason === 'replay',
            'ONCE EVER, NOT ONCE PER USE: a JWT spent as a grant is refused ' +
            'as a client assertion. Two caches keyed two ways was the fourth ' +
            'way "once" was not true', asClient);
    t.check(/grant/.test(usedAssertions.usedAs(asClient.existing)),
            'and the phrase a verifier puts in its refusal names the other ' +
            'use', usedAssertions.usedAs(asClient.existing));

    const asSaml = await usedAssertions.claim(Object.assign({}, first,
      { format: 'saml' }));
    t.check(asSaml.ok,
            'a SAML assertion whose ID equals a JWT\'s jti from the same ' +
            'issuer is a DIFFERENT document: the format is in the key, so ' +
            'the two namespaces cannot spend each other', asSaml);

    const otherIssuer = await usedAssertions.claim(Object.assign({}, first,
      { issuer: 'ua-someone-else' }));
    t.check(otherIssuer.ok, 'and a jti is the issuer\'s name for a document, ' +
            'so another issuer\'s identical jti is another document',
            otherIssuer);

    // An expired row is not a live one, and a later document may reuse a jti.
    const reused = claimOf({ expiresAt: Date.now() + 5 });
    await usedAssertions.claim(reused);
    await later(30);
    const fresh = await usedAssertions.claim(Object.assign({}, reused,
      { expiresAt: Date.now() + 60000 }));
    t.check(fresh.ok, 'a row is kept only until the assertion would have ' +
            'expired: after that the jti is free again', fresh);
  });

  await inRealm(OTHER, async function () {
    const leaked = await usedAssertions.list({});
    t.equal(leaked.matched, 0, 'the history is per trust realm: another ' +
            'realm lists none of this one\'s rows');
  });

  await inRealm(realmRecord('ua-full-'),
    async function () {
      config.setOverride('oauth2.assertionReplayCacheSize', 10);
      try {
        let refused = null;
        let accepted = 0;
        for (let i = 0; i < 12 && !refused; i++) {
          const got = await usedAssertions.claim(claimOf());
          if (got.ok) {
            accepted += 1;
          } else {
            refused = got;
          }
        }
        t.check(accepted === 10 && refused && refused.reason === 'full',
                'A FULL HISTORY REFUSES RATHER THAN FORGETS: ten live rows at ' +
                'a cap of ten, and the eleventh is refused', { accepted: accepted,
                  refused: refused });
      } finally {
        config.clearOverride('oauth2.assertionReplayCacheSize');
      }
    });
  log.debug("Leaving oneHistory().");
}

async function spentOnlyOnSuccess(t) {
  log.debug("Entering spentOnlyOnSuccess().");
  t.log.info('=== B. spent only when tokens are issued ===');
  await inRealm(REALM, async function () {
    const req = fakeRequest();
    const grant = claimOf();
    const held = await usedAssertions.claim(Object.assign({ request: req },
                                                          grant));
    t.check(held.ok && held.claim.state === 'reserved',
            'a claim made on a request is RESERVED until its response ' +
            'finishes', held);
    const racing = await usedAssertions.claim(grant);
    t.check(!racing.ok && racing.reason === 'replay' &&
            racing.existing.state === 'reserved',
            'and a replay racing that request is refused on the reservation ' +
            'exactly as on a spent row', racing);
    finish(req, 400);
    await later();
    const retry = await usedAssertions.claim(grant);
    t.check(retry.ok,
            'A RESPONSE THAT WAS NOT A 2xx RELEASES IT: the token request ' +
            'failed for another reason and the assertion bought nothing, so ' +
            'it has not been used', retry);

    const req2 = fakeRequest();
    const second = claimOf();
    await usedAssertions.claim(Object.assign({ request: req2 }, second));
    finish(req2, 200);
    await later();
    const listed = await usedAssertions.list({ q: second.identifier });
    t.equal(listed.rows.length && listed.rows[0].state, 'spent',
            'a 2xx makes the reservation permanent');
    const replay = await usedAssertions.claim(second);
    t.check(!replay.ok && replay.reason === 'replay',
            'and after it the assertion is refused for the rest of its life',
            replay);

    const req3 = fakeRequest();
    const third = claimOf();
    await usedAssertions.claim(Object.assign({ request: req3 }, third));
    req3.res.emit('close');
    await later();
    const afterAbort = await usedAssertions.claim(third);
    t.check(afterAbort.ok, 'a response closed before it finished — the ' +
            'client went away — releases the claim too', afterAbort);
  });
  log.debug("Leaving spentOnlyOnSuccess().");
}

async function survivesARestart(t) {
  log.debug("Entering survivesARestart().");
  t.log.info('=== C. the ldif store keeps it across a restart ===');
  const ldif = require('../persistence/persistence_ldif');
  const quiet = { debug: function () {}, info: function () {},
                  warn: function () {}, error: function () {} };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-used-assertions-'));
  const realm = realmRecord('ua-ldif-');
  try {
    // THE CLAIM ALONE, THEN A RESTART, AND NOTHING ELSE WRITTEN IN BETWEEN.
    // The first version of this section claimed three assertions before the
    // restart, and a claim that was never written survived it: the RELEASE of
    // the second rewrote the whole file, which carried the first along. So the
    // first assertion is claimed with no other write after it, and read back
    // by a new driver before anything else happens.
    const kept = claimOf();
    const first = ldif.create({ dir: dir, log: quiet });
    await first.open();
    await usedAssertions.setStore(first, 'ldif');
    await inRealm(realm, async function () {
      const spent = await usedAssertions.claim(kept);
      t.check(spent.ok, 'a claim against the file store is accepted', spent);
    });
    await usedAssertions.clearStore();
    const reopened = ldif.create({ dir: dir, log: quiet });
    await reopened.open();
    await usedAssertions.setStore(reopened, 'ldif');
    await inRealm(realm, async function () {
      const early = await usedAssertions.claim(kept);
      t.check(!early.ok && early.reason === 'replay',
              'a claim is on disk BEFORE it returns: restarted with no other ' +
              'write after it, the assertion is still spent', early);
    });

    const released = claimOf();
    const expiring = claimOf({ expiresAt: Date.now() + 150 });
    await inRealm(realm, async function () {
      const req = fakeRequest();
      await usedAssertions.claim(Object.assign({ request: req }, released));
      finish(req, 500);
      await usedAssertions.claim(expiring);
    });
    await later(50);
    const file = path.join(dir, 'used-assertions-' + realm.id + '.json');
    t.check(fs.existsSync(file), 'the realm has a file of its own', file);
    const onDisk = JSON.parse(fs.readFileSync(file, 'utf8')).rows;
    t.check(!JSON.stringify(onDisk).includes('eyJ'),
            'and no row carries an assertion — only its issuer and identifier');

    await usedAssertions.clearStore();
    await later(200);
    const second = ldif.create({ dir: dir, log: quiet });
    await second.open();
    await usedAssertions.setStore(second, 'ldif');
    await inRealm(realm, async function () {
      const after = await usedAssertions.claim(kept);
      t.check(!after.ok && after.reason === 'replay',
              'AFTER A RESTART THE ASSERTION IS STILL SPENT. This is the ' +
              'first of the four ways the old caches were not "once ever": ' +
              'a client\'s key survives a restart, so its assertion does too',
              after);
      const retried = await usedAssertions.claim(released);
      t.check(retried.ok, 'a claim its response released was not written ' +
              'down as used', retried);
      const reusedExpired = await usedAssertions.claim(Object.assign({},
        expiring, { expiresAt: Date.now() + 60000 }));
      t.check(reusedExpired.ok, 'and a row that expired before the restart ' +
              'is not restored', reusedExpired);
    });
    t.equal(usedAssertions.summary().persistent, true,
            'the summary says the history is persistent on this store');
  } finally {
    await usedAssertions.clearStore();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  t.equal(usedAssertions.summary().kind, 'memory',
          'and back in memory once the store is cleared, as memory mode is');
  log.debug("Leaving survivesARestart().");
}

async function postgresClaimIsOneStatement(t) {
  log.debug("Entering postgresClaimIsOneStatement().");
  t.log.info('=== D. the postgres claim is one atomic statement ===');
  const postgres = require('../persistence/persistence_postgres');
  const names = postgres.SCHEMA_OBJECTS.map(function (o) { return o.name; });
  t.check(names.indexOf('sts_used_assertions') >= 0 &&
          names.indexOf('sts_used_assertions_expiry') >= 0,
          'the driver declares the table and its expiry index', names);
  const table = postgres.SCHEMA_OBJECTS.filter(function (o) {
    return o.name === 'sts_used_assertions';
  })[0].statement;
  t.check(/PRIMARY KEY \(realm, key\)/.test(table),
          'and (realm, key) is its primary key — the lock the claim rests on');

  const statements = [];
  const pgPath = require.resolve('pg');
  const previous = require.cache[pgPath];
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.query = function (sql, params) {
    statements.push({ sql: String(sql), params: params || [] });
    return Promise.resolve({ rows: [], rowCount: /^INSERT/.test(sql) ? 1 : 0 });
  };
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
    exports: { Pool: FakePool, Client: function () {} } };
  let driver;
  try {
    driver = postgres.create({ url: 'postgres://sts_app@localhost:5432/sts',
      log: { debug: function () {}, info: function () {},
             warn: function () {}, error: function () {} } });
  } finally {
    if (previous) {
      require.cache[pgPath] = previous;
    } else {
      delete require.cache[pgPath];
    }
  }
  const row = { realm: 'r', key: 'k', format: 'jwt', use: 'authorization-grant',
                issuer: 'i', identifier: 'j', clientId: '', subject: '',
                state: 'reserved', reservation: 'z', origin: 'o', usedAt: 1,
                spentAt: 0, expiresAt: 2 };
  const answer = await driver.claimUsedAssertion(row, { cap: 10, now: 1 });
  t.check(answer.claimed && statements.length === 1,
          'an accepted claim costs ONE round trip', statements.length);
  const sql = statements[0].sql;
  t.check(/^INSERT INTO sts_used_assertions/.test(sql) &&
          /ON CONFLICT \(realm, key\) DO UPDATE/.test(sql) &&
          /WHERE sts_used_assertions\.expires_at < \$15/.test(sql),
          'and it is an INSERT … ON CONFLICT whose update touches only an ' +
          'EXPIRED row, so a live one is never overwritten and two ' +
          'processes cannot both claim one key', sql);
  t.check(/count\(\*\) FROM sts_used_assertions/.test(sql) &&
          /< \$16::bigint/.test(sql),
          'with the cap in the same statement', sql);

  const settled = [];
  statements.length = 0;
  await driver.settleUsedAssertion('r', 'k', 'z', false, 5);
  await driver.settleUsedAssertion('r', 'k', 'z', true, 5);
  statements.forEach(function (s) { settled.push(s.sql); });
  t.check(/^DELETE FROM sts_used_assertions .*reservation = \$3 AND state = 'reserved'/
            .test(settled[0]) &&
          /^UPDATE sts_used_assertions SET state = 'spent'.*reservation = \$3/
            .test(settled[1]),
          'a release deletes and a confirmation updates, both pinned to the ' +
          'claim\'s own reservation', settled);
  t.check(usedAssertions.DATABASE_GROUP.every(function (fn) {
    return typeof driver[fn] === 'function';
  }), 'and the driver carries every function of the database group, which ' +
      'is what setStore() tests for by name');
  log.debug("Leaving postgresClaimIsOneStatement().");
}

async function oneVerificationPerRequest(t) {
  log.debug("Entering oneVerificationPerRequest().");
  t.log.info('=== E. one verification of one client assertion per request ===');
  const clientAuth = require('../oauth-oidc/client_auth');
  const AUD = 'https://ua.example/oauth2/token';
  const SECRET = 'ua-client-assertion-secret-0123456789';
  const now = Math.floor(Date.now() / 1000);
  const assertion = hs256(SECRET, { iss: 'ua-assert', sub: 'ua-assert',
    aud: AUD, iat: now, exp: now + 60,
    jti: 'ua-' + crypto.randomBytes(8).toString('hex') });
  const ask = function (request) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return clientAuth.verify({
      method: 'client_secret_jwt', clientId: 'ua-assert', clientSecret: SECRET,
      assertionType: clientAuth.ASSERTION_TYPE, audiences: [AUD],
      assertion: assertion, request: request
    });
  };
  await inRealm(REALM, async function () {
    const req = fakeRequest();
    const policy = await ask(req);
    const observation = await ask(req);
    t.check(policy.ok && observation.ok,
            'THE TOKEN ENDPOINT ASKS TWICE ABOUT ONE REQUEST — the RFC 9700 ' +
            'check, then the observation — and both answers are yes. Before, ' +
            'the second was a replay of the request\'s own assertion, and in ' +
            'product mode that client was refused invalid_client',
            { policy: policy, observation: observation });
    finish(req, 200);
    await later();
    const elsewhere = await ask(fakeRequest());
    t.check(!elsewhere.ok && elsewhere.errorCode === 'STS-OAUTH-0012',
            'and on ANOTHER request the same assertion is a replay', elsewhere);
    t.check(/as a client assertion/.test(elsewhere.description || ''),
            'naming what it was spent as', elsewhere.description);

    // ONE HISTORY ACROSS THE TWO VERIFIERS. The client assertion was spent by
    // `client_auth.js`; the grant verifier would present the same document
    // with its `iss` and `jti`, and must find it. A client_auth that keyed its
    // claims any other way — by client, by use — would still refuse its OWN
    // replays above and let the JWT be spent a second time as a grant.
    const asGrant = await usedAssertions.claim({
      format: 'jwt', use: 'authorization-grant', issuer: 'ua-assert',
      identifier: JSON.parse(Buffer.from(assertion.split('.')[1],
                                         'base64url')).jti,
      expiresAt: Date.now() + 60000
    });
    t.check(!asGrant.ok && asGrant.reason === 'replay',
            'and the same JWT presented to the GRANT verifier — keyed as that ' +
            'verifier keys it, by `iss` and `jti` — is a replay too', asGrant);
  });
  log.debug("Leaving oneVerificationPerRequest().");
}

function noCachesLeft(t) {
  log.debug("Entering noCachesLeft().");
  t.log.info('=== F. the verifiers hold no cache of their own ===');
  ['oauth-oidc/client_auth.js', 'oauth-oidc/assertion_grant.js',
   'oauth-oidc/saml_assertion_grant.js'].forEach(function (file) {
    const source = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
    t.check(!/seenAssertions/.test(source) &&
            /usedAssertions\.claim\(/.test(source),
            file + ' spends against the shared history and keeps no replay ' +
            'cache of its own — a second cache is a second answer to "has ' +
            'this been used", and one of them is the one that forgets');
  });
  // THE TWO JWT VERIFIERS KEY A DOCUMENT THE SAME WAY, read as source because
  // the grant verifier needs a declared issuer and a registry to reach its
  // claim in process: `client_auth.js` spends under the client_id, which the
  // library has already required to equal `iss`, and `assertion_grant.js`
  // spends under `iss`. A prefix on either would make one JWT two documents.
  const grantSource = fs.readFileSync(path.join(__dirname, '..',
    'oauth-oidc/assertion_grant.js'), 'utf8');
  const clientSource = fs.readFileSync(path.join(__dirname, '..',
    'oauth-oidc/client_auth.js'), 'utf8');
  t.check(/format: 'jwt', use: 'authorization-grant',\s+issuer: iss, identifier: String\(claims\.jti\)/
            .test(grantSource) &&
          /format: 'jwt', use: 'client-authentication',\s+issuer: clientId, identifier: String\(claims\.jti\)/
            .test(clientSource),
          'the grant spends a JWT under its `iss` and client authentication ' +
          'under the client_id that `iss` was checked to be, so both reach ' +
          'one row');
  ['STS-OAUTH-0243', 'STS-STORE-0044', 'STS-STORE-0045', 'STS-STORE-0046',
   'STS-STORE-0047', 'STS-STORE-0048'].forEach(function (code) {
    t.check(errorCodes.isKnown(code), code + ' is registered');
  });
  log.debug("Leaving noCachesLeft().");
}

async function run(t) {
  log.debug("Entering run().");
  await oneHistory(t);
  await spentOnlyOnSuccess(t);
  await survivesARestart(t);
  await postgresClaimIsOneStatement(t);
  await oneVerificationPerRequest(t);
  noCachesLeft(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'used_assertions',
  describe: 'An RFC 7523 or RFC 7522 assertion is accepted once, ever: one ' +
            'history keyed by the document whatever it is presented as, ' +
            'spent only when the response finishes 2xx, kept across a ' +
            'restart by the ldif store, claimed atomically by the postgres ' +
            'driver, and verified once per request at the token endpoint',
  run: run
};
