// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: knex_store.js
//
// ===========================================================================
// KNEX IS THE ONE DOOR TO POSTGRESQL (#326, 2026-10-19).
//
// `persistence/knex_store.js` makes every connection this service makes to
// its store. This holds the done condition and the rules it carried over
// from `pg-pool`:
//
//   A. as SOURCE: nothing outside the layer requires `pg`, and nothing but
//      the layer and phase 1's attribute-source driver requires `knex`;
//   B. against a Knex double: the pool is Knex's, made on demand, bounded by
//      the connect timeout both ways; a statement's `$n` text and values
//      reach the connection Knex holds UNCHANGED (a `?` operator included —
//      `knex.raw()` would read it as a binding); a connection given back
//      broken is never handed out again; an idle connection's error reaches
//      the pool's listeners and a held one's does not; a dedicated
//      connection is the pool's Knex instance's, outside the pool, its
//      listeners attached at connect; `timedOutWaiting()` knows Knex's
//      timeout; a missing package is STS-STORE-0028;
//   C. against a real PostgreSQL when `STS_TEST_POSTGRES_URL` names one: a
//      jsonb `?` and a jsonpath filter through the pool, LISTEN/NOTIFY on a
//      dedicated connection, and the pool's numbers.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const sourceFile = require('./tools/source_file');

const log = require('bunyan').createLogger({ name: 'knex_store',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const LAYER = require.resolve('../persistence/knex_store');

// What is not the service's own source, or not this repository's.
const SKIP = /(^|\/)(node_modules|node-ldapjs|coverage|debugger\/embedded|common\/vendored|deploy|xacml-pep|docs|\.claude|types|rust|apidocs|\.git)(\/|$)/;

// The requires a file may make of `pg` or `knex`, and why. No file may
// require `pg`: even the layer does not name it — Knex's dialect loads it.
// `pg`'s own connection-string reader, which two tests read a URL back
// through because it is what will really parse the string the layer hands
// Knex's dialect. It dials nothing.
const PG_PARSER = /^pg\/lib\/connection-parameters(\.js)?$/;
const KNEX_ALLOWED = {
  'persistence/knex_store.js': 'the one door to the service\'s store',
  'attribute-sources/attribute_source_drivers.ts': 'phase 1 of #94: an ' +
    'operator\'s database, per dialect — not this service\'s store'
};

function walk(dir, out) {
  log.debug("Entering walk(). " + dir);
  const names = fs.readdirSync(dir);
  names.forEach(function (name) {
    const full = path.join(dir, name);
    const rel = path.relative(ROOT, full).split(path.sep).join('/');
    if (SKIP.test(rel)) {
      return;
    }
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      walk(full, out);
    } else if (sourceFile.isSourceFile(name, names)) {
      out.push(rel);
    }
  });
  log.debug("Leaving walk().");
  return out;
}

// Every module name a file requires or imports, comments blanked first.
function requiresOf(text) {
  log.debug("Entering requiresOf().");
  const code = text.replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"\\])\/\/[^\n]*/g, '$1');
  const out = [];
  const re = /(?:require\s*\(\s*|import\s+\w+\s*=\s*require\s*\(\s*|from\s+)(['"])([^'"]+)\1/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    out.push(m[2]);
  }
  log.debug("Leaving requiresOf().");
  return out;
}

function source(t) {
  log.debug("Entering source().");
  t.log.info('=== A. the import boundary ===');
  const files = walk(ROOT, []);
  const pgOutside = [];
  const knexOutside = [];
  files.forEach(function (rel) {
    const names = requiresOf(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
    names.forEach(function (name) {
      if ((name === 'pg' || /^pg\//.test(name)) &&
          !(PG_PARSER.test(name) && /^tests\//.test(rel))) {
        pgOutside.push(rel + ' requires ' + name);
      }
      if ((name === 'knex' || /^knex\//.test(name)) && !KNEX_ALLOWED[rel]) {
        knexOutside.push(rel + ' requires ' + name);
      }
    });
  });
  t.check(files.length > 500, 'A0. the walk read the tree',
          files.length + ' files');
  t.check(pgOutside.length === 0,
          'A1. NOTHING REQUIRES `pg` — Knex\'s dialect is the one place it ' +
          'is loaded (a test may read a URL back through pg\'s parser)',
          pgOutside.join('; '));
  t.check(knexOutside.length === 0,
          'A2. nothing but the layer (and phase 1\'s attribute sources) ' +
          'requires `knex`', knexOutside.join('; '));
  const layer = fs.readFileSync(LAYER, 'utf8');
  t.check(!/^(const|let|var) [^\n]*require\('knex'\)/m.test(layer) &&
          /function loadKnex\(\)[\s\S]*require\('knex'\)/.test(layer),
          'A3. the layer loads Knex lazily, inside loadKnex()');
  log.debug("Leaving source().");
}

// ---------------------------------------------------------------------------
// A Knex double: the configuration it was built with, a tarn-shaped pool of
// fake connections, and the dialect calls the layer makes.
// ---------------------------------------------------------------------------
function fakeKnex(state) {
  log.debug("Entering fakeKnex().");
  const EventEmitter = require('events');
  function connection(id) {
    const c = new EventEmitter();
    c.id = id;
    c.sent = [];
    c.query = function (text, values) {
      c.sent.push({ text: text, values: values });
      if (/^FAIL/.test(String(text))) {
        return Promise.reject(Object.assign(new Error('refused'),
                                            { code: '42601' }));
      }
      return Promise.resolve({ rows: [{ ok: true }], rowCount: 1 });
    };
    // Knex's dialect listens on every connection it makes.
    c.on('error', function (err) {
      c.__knex__disposed = err;
    });
    return c;
  }
  function knex(config) {
    state.configs.push(config);
    const free = [];
    const used = new Set();
    let made = 0;
    const client = {
      pool: {
        numUsed: function () { return used.size; },
        numFree: function () { return free.length; },
        numPendingCreates: function () { return 0; },
        numPendingAcquires: function () { return state.waiting || 0; }
      },
      acquireConnection: function () {
        if (state.exhausted) {
          const e = new Error('Knex: Timeout acquiring a connection. The ' +
                              'pool is probably full.');
          e.name = 'KnexTimeoutError';
          return Promise.reject(e);
        }
        let c = free.shift();
        while (c && c.__knex__disposed) {
          state.destroyed.push(c.id);
          c = free.shift();
        }
        if (!c) {
          c = connection('pooled-' + (++made));
          config.pool.afterCreate(c, function () {});
        }
        used.add(c);
        return Promise.resolve(c);
      },
      releaseConnection: function (c) {
        used.delete(c);
        free.push(c);
        return Promise.resolve();
      },
      acquireRawConnection: function () {
        const c = connection('raw-' + (++made));
        state.raw.push(c);
        return Promise.resolve(c);
      },
      destroyRawConnection: function (c) {
        state.destroyedRaw.push(c.id);
        return Promise.resolve();
      }
    };
    return {
      client: client,
      destroy: function () {
        state.destroyedPools += 1;
        return Promise.resolve();
      },
      free: free
    };
  }
  log.debug("Leaving fakeKnex().");
  return { knex: knex };
}

// The layer, fresh, over a Knex double (or over nothing, for the refusal).
function layerOver(fake) {
  log.debug("Entering layerOver().");
  const knexPath = require.resolve('knex', { paths: [ROOT] });
  const previous = require.cache[knexPath];
  delete require.cache[LAYER];
  if (fake) {
    require.cache[knexPath] = /** @type {any} */ ({
      id: knexPath, filename: knexPath, loaded: true, exports: fake });
  }
  const layer = require(LAYER);
  log.debug("Leaving layerOver().");
  return {
    layer: layer,
    restore: function () {
      if (previous) {
        require.cache[knexPath] = previous;
      } else {
        delete require.cache[knexPath];
      }
      delete require.cache[LAYER];
    }
  };
}

async function againstADouble(t) {
  log.debug("Entering againstADouble().");
  t.log.info('=== B. the layer over a Knex double ===');
  const state = { configs: [], raw: [], destroyed: [], destroyedRaw: [],
                  destroyedPools: 0, exhausted: false, waiting: 0 };
  const over = layerOver(fakeKnex(state));
  try {
    const layer = over.layer;
    t.equal(state.configs.length, 0,
            'B0. requiring the layer builds no Knex instance');
    const pool = layer.openPool({ connectionString: 'postgres://db/sts',
                                  ssl: { rejectUnauthorized: true },
                                  connectionTimeoutMillis: 5000 },
                                { max: 4, idleTimeoutMillis: 30000 });
    const config = state.configs[0];
    t.check(config && config.client === 'pg' &&
            config.connection.connectionString === 'postgres://db/sts' &&
            config.connection.ssl.rejectUnauthorized === true &&
            config.connection.connectionTimeoutMillis === 5000,
            'B1. a Knex instance over pg, dialled with the options given ' +
            '(the TLS dialOptions() decided, unchanged)',
            JSON.stringify(config && config.connection));
    t.check(config.pool.min === 0 && config.pool.max === 4 &&
            config.pool.idleTimeoutMillis === 30000 &&
            config.pool.acquireTimeoutMillis === 5000 &&
            config.pool.createTimeoutMillis > 5000 &&
            config.pool.propagateCreateError === true,
            'B2. its pool is made on demand, waits no longer than the ' +
            'connect timeout for a slot, and lets pg\'s own connect ' +
            'timeout be the error a dial reports',
            JSON.stringify(config.pool));

    const text = 'SELECT 1 FROM sts_ldap_entries WHERE attr_names ? $1 AND ' +
      'class_keys ?| $2::text[]';
    const values = ['userpassword', ['groupofnames']];
    await pool.query(text, values);
    // The connection that answered is the one Knex hands out next.
    const answered = await pool.connect();
    t.check(answered.connection.sent.length === 1 &&
            answered.connection.sent[0].text === text &&
            answered.connection.sent[0].values === values,
            'B3. A STATEMENT\'S `$n` TEXT AND VALUES REACH THE CONNECTION ' +
            'UNCHANGED, `?` and `?|` included (knex.raw() would have read ' +
            'them as bindings)',
            JSON.stringify(answered.connection.sent));
    answered.release();
    answered.release();
    t.equal(state.configs.length, 1,
            'B4. one Knex instance per pool, however many statements');

    await pool.query('FAIL here').then(function () {
      t.bad('B5. a failed statement rejects');
    }, function (e) {
      t.check(e && e.code === '42601', 'B5. a failed statement rejects ' +
              'with the database\'s error', e && e.message);
    });
    const after = await pool.connect();
    t.check(state.destroyed.length === 1 && after.connection.id !==
            answered.connection.id,
            'B6. the connection it failed on is not handed out again',
            JSON.stringify(state.destroyed));
    after.release(new Error('not reset'));
    const third = await pool.connect();
    t.check(state.destroyed.length === 2 &&
            third.connection.id !== after.connection.id,
            'B7. nor is one released with an error (pg-pool\'s ' +
            'release(err))', JSON.stringify(state.destroyed));

    const idle = [];
    pool.on('error', function (err) {
      idle.push(err.message);
    });
    third.connection.emit('error', new Error('held one died'));
    t.equal(idle.length, 0, 'B8. a HELD connection\'s error is the ' +
            'borrower\'s (guardClient()), not the pool\'s idle report');
    third.release(new Error('it died'));
    const fourth = await pool.connect();
    fourth.release();
    fourth.connection.emit('error', new Error('idle one died'));
    t.check(idle.length === 1 && idle[0] === 'idle one died',
            'B9. an IDLE connection\'s error reaches the pool\'s listeners, ' +
            'as pg-pool emitted it', JSON.stringify(idle));
    t.check(fourth.connection.__knex__disposed instanceof Error,
            'B10. and Knex has marked it disposed, so it is not handed out ' +
            'again');

    const stats = pool.stats();
    t.check(stats.max === 4 && typeof stats.total === 'number' &&
            stats.waiting === 0,
            'B11. the pool\'s own numbers for /admin/database',
            JSON.stringify(stats));

    const listener = pool.dedicated();
    const notes = [];
    listener.on('notification', function (m) {
      notes.push(m.payload);
    });
    t.check(state.raw.length === 0,
            'B12. a dedicated connection dials nothing until connect()');
    await listener.connect();
    state.raw[0].emit('notification', { payload: 'hello' });
    t.check(state.raw.length === 1 && notes[0] === 'hello' &&
            state.configs.length === 1,
            'B13. it is the POOL\'S Knex instance\'s raw connection, ' +
            'outside the pool, with the listeners given before connect',
            JSON.stringify(notes));
    await listener.query('LISTEN sts_ldap_change');
    t.equal(state.raw[0].sent[0].text, 'LISTEN sts_ldap_change',
            'B14. its statements go to that connection');
    await listener.end();
    await listener.end();
    t.check(state.destroyedRaw.length === 1 && state.destroyedPools === 0,
            'B15. ending it destroys the connection once, and not the pool',
            JSON.stringify(state.destroyedRaw));
    const refused = await listener.query('SELECT 1').then(function () {
      return null;
    }, function (e) {
      return e;
    });
    t.check(!!refused, 'B16. an ended connection refuses a statement');

    const one = layer.openConnection({ connectionString: 'postgres://x/y' });
    await one.connect();
    await one.end();
    t.check(state.configs.length === 2 && state.configs[1].pool.max === 1 &&
            state.destroyedPools === 1,
            'B17. openConnection() is a pool of its own, ended with it');

    state.exhausted = true;
    const waited = await pool.query('SELECT 1').then(function () {
      return null;
    }, function (e) {
      return e;
    });
    t.check(waited && layer.timedOutWaiting(waited) &&
            !layer.timedOutWaiting(new Error('syntax error')) &&
            !layer.timedOutWaiting(new Error('Connection terminated due ' +
                                             'to connection timeout')),
            'B18. timedOutWaiting() is Knex\'s wait for a slot, and not a ' +
            'dial the database did not answer', waited && waited.message);
    state.exhausted = false;
    await pool.end();
    t.equal(state.destroyedPools, 2, 'B19. end() destroys the Knex instance');
  } finally {
    over.restore();
  }

  const missing = layerOver(function () {
    throw new Error('Knex: run\n$ npm install pg --save');
  });
  try {
    let refusal = null;
    try {
      missing.layer.openPool({ connectionString: 'postgres://db/sts' }, {});
    } catch (e) {
      log.debug("Caught in againstADouble(): " + ((e && e.message) || e));
      refusal = e;
    }
    t.check(refusal && /STS-STORE-0028/.test(refusal.message) &&
            /"pg"/.test(refusal.message),
            'B20. a Knex that cannot load pg is STS-STORE-0028, naming both ' +
            'packages', refusal && refusal.message);
  } finally {
    missing.restore();
  }
  log.debug("Leaving againstADouble().");
}

async function againstADatabase(t) {
  log.debug("Entering againstADatabase().");
  const url = process.env.STS_TEST_POSTGRES_URL || '';
  if (!url) {
    t.log.info('=== C. skipped: STS_TEST_POSTGRES_URL names no database ' +
               '(the in-process suite has none) ===');
    log.debug("Leaving againstADatabase(). Skipped.");
    return;
  }
  t.log.info('=== C. against ' + url.replace(/:[^:@/]*@/, ':***@') + ' ===');
  const layer = require(LAYER);
  const settings = { connectionString: url };
  const pool = layer.openPool(settings, { max: 2 });
  const listener = pool.dedicated();
  try {
    const r = await pool.query(
      'SELECT $1::text AS a, \'{"userpassword":1}\'::jsonb ? $2 AS has, ' +
      '\'["a","b"]\'::jsonb ?| ARRAY[\'b\'] AS any, ' +
      'jsonb_path_query_array(\'["x","y"]\'::jsonb, ' +
      '\'$[*] ? (@ == "y")\') AS asked', ['one', 'userpassword']);
    const row = r.rows[0] || {};
    t.check(row.a === 'one' && row.has === true && row.any === true &&
            JSON.stringify(row.asked) === '["y"]',
            'C1. `$n` bindings beside the jsonb `?`, `?|` and a jsonpath ' +
            'filter, through Knex\'s pool', JSON.stringify(row));
    const notes = [];
    listener.on('notification', function (m) {
      notes.push(m.payload);
    });
    await listener.connect();
    await listener.query('LISTEN knex_store_probe');
    await pool.query('SELECT pg_notify($1, $2)', ['knex_store_probe', 'hi']);
    for (let i = 0; i < 50 && !notes.length; i++) {
      await new Promise(function (resolve) {
        setTimeout(resolve, 20);
      });
    }
    t.check(notes[0] === 'hi',
            'C2. LISTEN on a dedicated connection hears a NOTIFY sent ' +
            'through the pool', JSON.stringify(notes));
    const held = await pool.connect();
    await held.query('BEGIN');
    await held.query('SET LOCAL jit = off');
    const jit = await held.query('SHOW jit');
    await held.query('COMMIT');
    held.release();
    t.check(jit.rows[0] && jit.rows[0].jit === 'off',
            'C3. a transaction is BEGIN/COMMIT on one held connection');
    const stats = pool.stats();
    t.check(stats.total >= 1 && stats.idle >= 1 && stats.max === 2,
            'C4. the pool reports what it holds', JSON.stringify(stats));
  } finally {
    await listener.end();
    await pool.end();
  }
  log.debug("Leaving againstADatabase().");
}

async function run(t) {
  log.debug("Entering run().");
  source(t);
  await againstADouble(t);
  await againstADatabase(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'knex_store',
  describe: 'Knex is the one door to PostgreSQL: nothing else requires pg, ' +
            'and the pool keeps pg-pool\'s rules',
  run: run
};
