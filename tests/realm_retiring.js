'use strict';
//
// File: realm_retiring.js
//
// ===========================================================================
// A REALM BEING RETIRED STARTS NOTHING NEW (#262, 2026-09-26).
//
// `realms.retire()` (#232) ends every session in a realm and announces its
// removal, then waits — bounded by realms.removalDeliveryTimeoutS — for that
// to be delivered before the purge. A sign-in made in that window SUCCEEDED
// and started a session the purge then dropped with no `session-revoked`.
// Now `retire()` marks the realm retiring FIRST, and while it is:
//
//   A. in the process that runs the removal, held open mid-wait by a
//      retirement hook of this test's own:
//        1. the realm reports itself retiring, and another realm does not;
//        2. the `mark` hooks run before anything is announced, and the realm
//           is already retiring when the announce phase runs;
//        3. `authn.startSession()` refuses, with STS-CORE-0121 — while the
//           control realm still starts one;
//        4. the issuance gate refuses every kind, first, with `retiring` on
//           the answer and STS-CORE-0121;
//        5. the token endpoint answers `invalid_grant` for a
//           client_credentials grant there (and 200 in the control realm);
//        6. OpenID4VCI's credential endpoint answers
//           `credential_request_denied`;
//        7. certificate enrollment's one issue funnel refuses with 503;
//        8. the SPIFFE authority refuses a JWT-SVID (and mints one in the
//           control realm);
//        9. and when the hook lets go, the realm is removed and nothing is
//           retiring any more.
//   B. the mark crosses processes as a REPLICATED realm update only, and is
//      one-way: an ordinary update cannot set it, and a second mark does not
//      move the first.
//   C. over a PostgreSQL double: `persistence.js` writes the mark
//      (`retiring_at`) and its change-log row BEFORE the realm's row is
//      deleted, and a row another node marked is applied here, so this
//      process refuses too.
//
// Each part in a CHILD PROCESS: A loads the whole protocol stack and listens
// on a port; C puts a `pg` double in the require cache.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'realm_retiring',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// A and B: the protocol stack, in memory.
// ---------------------------------------------------------------------------
function stackChild() {
  /* eslint-disable no-console */
  const ROOT = process.env.RTG_ROOT;
  const OUT = process.env.RTG_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const post = function (base, pathName, form) {
    return new Promise(function (resolve) {
      const body = new URLSearchParams(form || {}).toString();
      const req = http.request(base + pathName, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded',
                   'Content-Length': Buffer.byteLength(body) }
      }, function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            json = { unparsed: text.slice(0, 300), error: e.message };
          }
          resolve({ status: res.statusCode, json: json });
        });
      });
      req.on('error', function (e) {
        resolve({ status: 0, json: { error: e.message } });
      });
      req.end(body);
    });
  };

  (async function () {
    const config = require(ROOT + '/common/config');
    config.setOverride('realms.removalDeliveryTimeoutS', '60');
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const realms = require(ROOT + '/common/realms');
    const authn = require(ROOT + '/authn/authn');
    const gate = require(ROOT + '/common/issuance_gate');
    const errorCodes = require(ROOT + '/common/error_codes');
    const enrollment = require(ROOT + '/common/cert_enrollment');
    const ca = require(ROOT + '/spiffe/spiffe_ca');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const base = 'http://127.0.0.1:' + server.address().port;

    // A retirement hook of the test's own: it records the phase order and
    // holds the removal open in `deliver` until the checks are done.
    const order = [];
    let letGo = null;
    const held = new Promise(function (r) { letGo = r; });
    realms.onRetire({
      name: 'realm_retiring.js',
      mark: function (id) {
        order.push('mark:' + realms.isRetiring(id));
        return null;
      },
      announce: function (id) {
        order.push('announce:' + realms.isRetiring(id));
      },
      deliver: function () {
        order.push('deliver');
        return held;
      }
    });

    ['rtg-a', 'rtg-b'].forEach(function (id) {
      const made = realms.create({ id: id, name: id,
                                   description: 'realm_retiring.js' });
      if (!made.ok) {
        throw new Error('could not create ' + id + ': ' +
                        (made.errors || []).join(' '));
      }
    });
    const inRealm = function (id, fn) {
      return realms.run(realms.get(id), fn);
    };
    const signIn = function (id) {
      return inRealm(id, function () {
        const detail = { application: '' };
        const session = authn.startSession({ set: function () {},
                                             req: null },
                                           'rtg-alice', ['pwd'], '1',
                                           'OAuth 2.0 / OIDC', detail);
        return { session: session, detail: detail };
      });
    };
    note(!!signIn('rtg-a').session,
         'A0. (before the removal, a session starts in the realm)');

    // The SPIFFE authority of each realm, built before the window opens so
    // the mints below are about the mark and not about a slow first build.
    const svidIn = async function (id) {
      try {
        return await inRealm(id, function () {
          return ca.mintJwtSvid('spiffe://' + ca.trustDomain(id) + '/rtg',
                                ['rtg-audience'], { realm: id });
        });
      } catch (e) {
        return { error: (e && e.message) || String(e) };
      }
    };
    const svidBefore = await svidIn('rtg-b');

    // --- A. the window ----------------------------------------------------
    const retiring = realms.retire('rtg-a');
    // The mark is set synchronously, before retire()'s first await.
    note(realms.isRetiring('rtg-a') && !realms.isRetiring('rtg-b') &&
         !realms.isRetiring(realms.DEFAULT_ID),
         'A1. the realm reports itself retiring at once, and neither the ' +
         'control realm nor the default realm does');
    // Let the mark and announce phases run up to the held deliver.
    for (let i = 0; i < 50 && order.indexOf('deliver') < 0; i++) {
      await new Promise(function (r) { setTimeout(r, 20); });
    }
    note(order.join(',') === 'mark:true,announce:true,deliver',
         'A2. the mark hooks run first and the realm is retiring when the ' +
         'announce phase runs', order.join(','));

    const refused = signIn('rtg-a');
    const control = signIn('rtg-b');
    note(refused.session === null &&
         refused.detail.refusedWith === 'STS-CORE-0121',
         'A3. startSession() refuses in the retiring realm with ' +
         'STS-CORE-0121', JSON.stringify(refused.detail));
    note(!!control.session,
         'A3b. (a control: a session still starts in another realm)');

    const kinds = gate.KINDS.map(function (kind) {
      const answer = inRealm('rtg-a', function () {
        return gate.check({ application: 'rtg-client', kind: kind,
                            subject: { kind: 'user', name: 'rtg-alice',
                                       authenticated: true } });
      });
      return { kind: kind, allowed: answer.allowed,
               retiring: answer.retiring === true,
               code: errorCodes.codeOf(answer) };
    });
    note(kinds.every(function (one) {
      return !one.allowed && one.retiring && one.code === 'STS-CORE-0121';
    }), 'A4. the issuance gate refuses every kind of issuance, with ' +
        '`retiring` on the answer and STS-CORE-0121', JSON.stringify(kinds));
    const controlGate = inRealm('rtg-b', function () {
      return gate.check({ application: 'rtg-client',
                          kind: gate.ISSUANCE.ACCESS_TOKEN,
                          subject: { kind: 'user', name: 'rtg-alice',
                                     authenticated: true } });
    });
    note(controlGate.allowed && !controlGate.retiring,
         'A4b. (a control: the gate allows in another realm)',
         JSON.stringify(controlGate));

    const grant = { grant_type: 'client_credentials',
                    client_id: 'rtg-client', client_secret: 'x' };
    const tokenA = await post(base, '/realm/rtg-a/oauth2/token', grant);
    const tokenB = await post(base, '/realm/rtg-b/oauth2/token', grant);
    note(tokenA.status === 400 && tokenA.json.error === 'invalid_grant',
         'A5. the token endpoint answers invalid_grant in the retiring realm',
         JSON.stringify(tokenA));
    note(tokenB.status === 200 && !!tokenB.json.access_token,
         'A5b. (a control: the same grant is answered in another realm)',
         JSON.stringify(tokenB).slice(0, 300));

    const vc = await post(base, '/realm/rtg-a/oid4vci/credential', {});
    note(vc.status === 400 && vc.json.error === 'credential_request_denied',
         'A6. OpenID4VCI\'s credential endpoint answers ' +
         'credential_request_denied', JSON.stringify(vc));

    const cert = await inRealm('rtg-a', function () {
      return enrollment.issue({ family: 'est', profile: 'tls-client' });
    });
    note(cert && cert.ok === false && cert.status === 503 &&
         errorCodes.codeOf(cert) === 'STS-CORE-0121',
         'A7. certificate enrollment refuses with 503 and STS-CORE-0121',
         JSON.stringify(cert));

    const svidA = await svidIn('rtg-a');
    const svidB = await svidIn('rtg-b');
    note(!!svidA.error && /being removed/.test(svidA.error),
         'A8. the SPIFFE authority refuses a JWT-SVID in the retiring realm',
         JSON.stringify(svidA).slice(0, 300));
    note(!svidB.error && !svidBefore.error,
         'A8b. (a control: it mints one in another realm)',
         JSON.stringify(svidB).slice(0, 300));

    letGo();
    const done = await retiring;
    note(done.ok && !realms.get('rtg-a') && !realms.isRetiring('rtg-a'),
         'A9. once the hook lets go the realm is removed, and nothing is ' +
         'retiring any more', JSON.stringify({ ok: done.ok,
                                               errors: done.errors }));

    // --- B. the mark crosses processes as a replicated update only ------
    realms.create({ id: 'rtg-c', name: 'rtg-c' });
    realms.update('rtg-c', { retiringSince: 1234 });
    note(!realms.isRetiring('rtg-c'),
         'B1. an ordinary update cannot mark a realm retiring');
    realms.update('rtg-c', { retiringSince: 1234, replicated: true });
    realms.update('rtg-c', { retiringSince: 5678, replicated: true });
    note(realms.isRetiring('rtg-c') &&
         realms.get('rtg-c').retiringSince === 1234,
         'B2. a replicated update marks it, and a second mark does not move ' +
         'the first', String(realms.get('rtg-c').retiringSince));
    realms.update('rtg-c', { retiringSince: null, replicated: true });
    note(realms.isRetiring('rtg-c'),
         'B3. and nothing unmarks it but the removal');
    realms.remove('rtg-c');
    realms.create({ id: 'rtg-c', name: 'rtg-c again' });
    note(!realms.isRetiring('rtg-c'),
         'B4. the same id defined again is a new realm, not retiring');

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the stack child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

// ---------------------------------------------------------------------------
// C: persistence.js over a PostgreSQL double.
// ---------------------------------------------------------------------------
function storeChild() {
  const ROOT = process.env.RTG_ROOT;
  const OUT = process.env.RTG_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const db = { realms: new Map(), log: [], statements: [] };
  const rows = function (list) {
    return Promise.resolve({ rows: list, rowCount: list.length });
  };
  const json = function (value) {
    return typeof value === 'string' ? JSON.parse(value) : value;
  };
  db.query = function (sql, params) {
    const text = String(sql).replace(/\s+/g, ' ').trim();
    const p = params || [];
    if (/^SELECT to_regclass/.test(text)) {
      const row = {};
      for (let i = 0; i < 200; i++) {
        row['o' + i] = 'present';
      }
      return rows([row]);
    }
    if (/^INSERT INTO sts_changes/.test(text)) {
      for (let i = 0; i + 3 < p.length; i += 4) {
        db.log.push({ seq: db.log.length + 1, origin: p[i], kind: p[i + 1],
                      realm: p[i + 2], key: p[i + 3] });
        db.statements.push('change:' + p[i + 1]);
      }
      return rows([]);
    }
    if (/SELECT COALESCE\(MAX\(seq\), 0\) AS seq FROM sts_changes/
          .test(text)) {
      return rows([{ seq: db.log.length }]);
    }
    if (/^SELECT seq, origin, kind, realm, key FROM sts_changes WHERE seq > /
          .test(text)) {
      return rows(db.log.filter(function (row) {
        return row.seq > Number(p[0]);
      }).slice(0, Number(p[1]) || 500));
    }
    if (/^SELECT id, name, description, created_at, overrides, domain, retiring_at FROM sts_realms/
          .test(text)) {
      return rows(Array.from(db.realms.values()));
    }
    if (/^DELETE FROM sts_realms WHERE id = \$1/.test(text)) {
      db.statements.push('delete:' + p[0]);
      db.realms.delete(p[0]);
      return rows([]);
    }
    if (/^INSERT INTO sts_realms/.test(text)) {
      const had = db.realms.get(p[0]);
      db.statements.push('upsert:' + p[0] + ':' + p[11] + ':' +
                         /retiring_at = COALESCE\(sts_realms.retiring_at/
                           .test(text));
      db.realms.set(p[0], { id: p[0], name: p[1], description: p[2],
                            created_at: p[3], overrides: json(p[4]),
                            domain: p[10],
                            retiring_at: (had && had.retiring_at) ||
                              (p[11] === null ? null : String(p[11])) });
      return rows([]);
    }
    return rows([]);
  };
  function FakeClient() {}
  FakeClient.prototype.query = function (sql, params) {
    return db.query(sql, params);
  };
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () { return Promise.resolve(); };
  FakeClient.prototype.end = function () { return Promise.resolve(); };
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = FakeClient.prototype.query;
  FakePool.prototype.end = function () { return Promise.resolve(); };
  const pgPath = require.resolve('pg', { paths: [ROOT] });
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: { Pool: FakePool, Client: FakeClient } };

  (async function () {
    process.env.STS_PERSISTENCE_MODE = 'postgres';
    process.env.STS_PERSISTENCE_COORDINATE = 'true';
    const realms = require(ROOT + '/common/realms');
    const persistence = require(ROOT + '/persistence/persistence');
    persistence.setDirectory({
      realmEntries: function () { return []; },
      replaceRealm: function () {},
      entryAt: function () { return null; },
      applyEntry: function () {},
      removeEntry: function () {}
    });
    await persistence.start();
    note(persistence.activeMode() === 'postgres',
         'C0. (the store opened over the double)',
         JSON.stringify(persistence.status().lastError || ''));
    await persistence.coordinate();

    realms.create({ id: 'rtg-p', name: 'rtg-p' });
    await persistence.flush();
    const created = db.realms.get('rtg-p');
    note(!!created && created.retiring_at === null,
         'C1. a realm is written down with no mark', JSON.stringify(created));

    db.statements.length = 0;
    const done = await realms.retire('rtg-p');
    await persistence.flush();
    const trail = db.statements.slice();
    const marked = trail.findIndex(function (s) {
      return /^upsert:rtg-p:\d+:true$/.test(s);
    });
    const deleted = trail.indexOf('delete:rtg-p');
    note(done.ok && marked >= 0 && deleted > marked &&
         trail.indexOf('change:realms', marked) > marked &&
         trail.indexOf('change:realms', marked) < deleted,
         'C2. retire() writes retiring_at and its change-log row BEFORE the ' +
         'realm\'s row is deleted, and the upsert never clears a mark ' +
         '(COALESCE)', JSON.stringify(trail));

    // ANOTHER NODE marks a realm this process holds.
    realms.create({ id: 'rtg-q', name: 'rtg-q' });
    await persistence.flush();
    db.realms.get('rtg-q').retiring_at = '1700000000000';
    db.log.push({ seq: db.log.length + 1, origin: 'node-b', kind: 'realms',
                  realm: '', key: '' });
    await persistence.syncNow();
    note(realms.isRetiring('rtg-q') &&
         realms.get('rtg-q').retiringSince === 1700000000000,
         'C3. a realm another node marked is retiring here too, from the ' +
         'change log', JSON.stringify(realms.get('rtg-q')));
    await persistence.flush();
    note(db.realms.get('rtg-q').retiring_at === '1700000000000',
         'C4. and writing it back down here keeps the mark',
         JSON.stringify(db.realms.get('rtg-q')));

    await persistence.stop();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the store child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t, main, label) {
  log.debug("Entering inAChild(). " + label);
  const out = path.join(os.tmpdir(), 'realm-retiring-' + label + '-' +
                        process.pid + '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + main.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', RTG_ROOT: ROOT,
                           RTG_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the ' + label + ' child process ' +
                                        'reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t, stackChild, 'stack');
  inAChild(t, storeChild, 'store');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'realm_retiring',
  describe: 'A trust realm being removed (#262): retire() marks it first, ' +
            'every process refuses new sign-ins and issuance in it with ' +
            'STS-CORE-0121 — sessions, the gate, the token endpoint, ' +
            'OpenID4VCI, enrollment, SPIFFE — and the mark is written down ' +
            'and replicated before anything is ended',
  run: run
};
