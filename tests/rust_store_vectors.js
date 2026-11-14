// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: rust_store_vectors.js
//
// ---------------------------------------------------------------------------
// THE NODE HALF OF THE STORE SLICE'S OTHER DIRECTION (#444 phase 2b): what
// the Rust crates `sts-store`, `sts-cluster`, `sts-http` and `sts-core`'s
// realm registry answered for the vectors `tests/tools/crypto-vectors.js`
// wrote (their `*_vectors.rs` tests with `STS_WRITE_VECTORS=1`), held to
// Node — run again here where the answer is a function of its input, read
// by Node's own reader where it is something written, and compared with
// Node's recorded answer where the answer needs the whole world the builder
// made:
//
//   merge            directory_merge.js run again on every case
//   realms           validateId(), normalizeDomain() and validateDomain()
//                    run again over the realms the builder made
//   ldif             Rust's files read by Node's ldif driver
//   scheduler        span(), cronPrev()/cronNext() and whyOf() run again;
//                    the jobs held to Node's
//   scheduler-history, realm-lifecycle
//                    held to Node's answers
//   scheduler-tick   Rust's claims, reads, drops and run rows per scenario
//                    held to Node's; leastLoaded() run again on Rust's loads
//   cache-registry   Rust's report, detail, snapshot and ejection held to
//                    Node's, and Rust's snapshot rows read back by Node's
//                    unpackSnapshotRow()
//   http             the two CSP builders run again; the answers held to
//                    Node's
//   keystore         every value Rust sealed opened by Node's keystore over
//                    the rows Rust stored, and every digest Node's
//
// The files are in STS_CRYPTO_VECTORS (default `tests/vectors/sts-crypto`),
// never committed. A set with no `-rust.json` is said and skipped.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'rust_store_vectors',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const VECTORS = process.env.STS_CRYPTO_VECTORS ||
  path.join(__dirname, 'vectors', 'sts-crypto');

/**
 * One vector file, or null when it is not there.
 *
 * @param {string} name - the file
 * @returns {any} its contents
 */
function read(name) {
  log.debug("Entering read().");
  const file = path.join(VECTORS, name);
  const out = fs.existsSync(file) ?
    JSON.parse(fs.readFileSync(file, 'utf8')) : null;
  log.debug("Leaving read().");
  return out;
}

/**
 * JSON with object keys sorted, for answers whose key order is not part of
 * the comparison (a report built in another language).
 *
 * @param {any} v - the value
 * @returns {string} its canonical text
 */
function canonical(v) {
  log.debug("Entering canonical().");
  let out;
  if (Array.isArray(v)) {
    out = '[' + v.map(canonical).join(',') + ']';
  } else if (v && typeof v === 'object') {
    // A member that is undefined is left out, as JSON.stringify leaves it.
    out = '{' + Object.keys(v).filter(function (k) {
      return v[k] !== undefined;
    }).sort().map(function (k) {
      return JSON.stringify(k) + ':' + canonical(v[k]);
    }).join(',') + '}';
  } else {
    out = JSON.stringify(v === undefined ? null : v);
  }
  log.debug("Leaving canonical().");
  return out;
}

/**
 * @param {any} t - the runner's check collector
 * @param {any} node - merge-node.json
 * @param {any} rust - merge-rust.json
 */
function merge(t, node, rust) {
  log.debug("Entering merge().");
  const m = require('../persistence/directory_merge');
  const pool = function (i) {
    const one = node.pool[i];
    return one === null ? null : JSON.parse(JSON.stringify(one));
  };
  let differ = 0;
  rust.cases.forEach(function (c) {
    const mine = m.mergeEntry(pool(c.base), pool(c.mine), pool(c.theirs));
    if (JSON.stringify(mine) !== JSON.stringify(c.result)) {
      differ += 1;
      t.check(false, 'merge ' + c.base + '/' + c.mine + '/' + c.theirs,
              JSON.stringify(c.result));
    }
  });
  rust.values.forEach(function (c) {
    const u = function (x) {
      return x === null ? undefined : x;
    };
    const mine = m.mergeValues(u(c.base), u(c.mine), u(c.theirs)) || null;
    if (JSON.stringify(mine) !== JSON.stringify(c.merged)) {
      differ += 1;
      t.check(false, 'mergeValues', JSON.stringify(c));
    }
  });
  rust.canonical.forEach(function (text, i) {
    const one = pool(i);
    if (JSON.stringify(m.canonicalJson(one)) !== JSON.stringify(text)) {
      differ += 1;
      t.check(false, 'canonicalJson of pool entry ' + i, text);
    }
  });
  t.check(differ === 0, 'every one of Rust\'s ' + (rust.cases.length +
          rust.values.length + rust.canonical.length) + ' merge answers ' +
          'is directory_merge.js\'s');
  log.debug("Leaving merge().");
}

/**
 * @param {any} t - the runner's check collector
 * @param {any} node - realms-node.json
 * @param {any} rust - realms-rust.json
 */
function realmsSet(t, node, rust) {
  log.debug("Entering realmsSet().");
  const realms = require('../common/realms');
  // The realms the builder made, so a domain in use is in use here too.
  [{ id: 'acme', name: 'Acme', domain: 'Acme.Example.COM.' },
   { id: 'dev', name: 'Dev', domain: 'dev.acme.example.com' },
   { id: 'x1', name: 'X1' }].forEach(function (spec) {
    if (!realms.get(spec.id)) {
      realms.create(spec);
    }
  });
  rust.ids.forEach(function (row) {
    t.equal(JSON.stringify(row.errors),
            JSON.stringify(realms.validateId(row.id)),
            'validateId(' + JSON.stringify(row.id) + ') is Node\'s');
  });
  rust.domains.forEach(function (row) {
    const n = realms.normalizeDomain(row.raw);
    t.check(n === row.normalized &&
            JSON.stringify(realms.validateDomain(n, 'new')) ===
              JSON.stringify(row.errors),
            'normalizeDomain() and validateDomain() of ' +
            JSON.stringify(row.raw) + ' are Node\'s', JSON.stringify(row));
  });
  ['baseDns', 'mail', 'bySegment'].forEach(function (k) {
    t.check(canonical(rust[k]) === canonical(node[k]),
            'Rust\'s ' + k + ' are Node\'s');
  });
  ['acme', 'dev', 'x1'].forEach(function (id) {
    realms.remove(id);
  });
  log.debug("Leaving realmsSet().");
}

/**
 * @param {any} t - the runner's check collector
 * @param {any} node - ldif-node.json
 * @param {any} rust - ldif-rust.json
 */
async function ldif(t, node, rust) {
  log.debug("Entering ldif().");
  Object.keys(node.files).forEach(function (name) {
    t.check(rust.files[name] === node.files[name],
            'the ' + name + ' Rust writes is the one Node writes');
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rust-ldif-'));
  Object.keys(rust.files).forEach(function (name) {
    fs.writeFileSync(path.join(dir, name), rust.files[name]);
  });
  const driverModule = require('../persistence/persistence_ldif');
  const quiet = bunyan.createLogger({ name: 'rust-ldif', level: 'fatal' });
  const driver = driverModule.create({ dir: dir, log: quiet });
  await driver.open();
  const reread = await driver.loadDirectory();
  t.check(canonical(reread) === canonical(node.reread),
          'Node\'s ldif driver reads Rust\'s files back to Node\'s entries');
  const realmsBack = await driver.loadRealms();
  t.check(!!realmsBack && realmsBack[0] && realmsBack[0].id === 'acme',
          'and Rust\'s realms.json');
  fs.rmSync(dir, { recursive: true, force: true });
  rust.parsed.forEach(function (one, i) {
    t.check(canonical(one) === canonical(node.parsed[i]),
            'Rust parses foreign LDIF ' + i + ' as fromLdif() does');
  });
  log.debug("Leaving ldif().");
}

/**
 * @param {any} t - the runner's check collector
 * @param {any} node - scheduler-node.json
 * @param {any} rust - scheduler-rust.json
 */
function scheduler(t, node, rust) {
  log.debug("Entering scheduler().");
  const S = require('../cluster/scheduler').Scheduler;
  rust.spans.forEach(function (one) {
    t.equal(one.text, S.span(one.ms), 'span(' + one.ms + ') is Node\'s');
  });
  let cronDiffer = 0;
  rust.cron.forEach(function (one) {
    one.at.forEach(function (a) {
      ['prev', 'next'].forEach(function (k) {
        let mine;
        try {
          mine = (k === 'prev' ? S.cronPrev : S.cronNext)(one.expr, a.t);
        } catch (e) {
          // croner throws for a leap day's earlier occurrences (the
          // forward test pins it); Rust answers there.
          log.debug("Caught in scheduler(): " + ((e && e.message) || e));
          return;
        }
        if (mine !== a[k]) {
          cronDiffer += 1;
          t.check(false, 'cron ' + one.expr + ' ' + k + ' at ' + a.t,
                  a[k] + ' vs ' + mine);
        }
      });
    });
  });
  t.check(cronDiffer === 0, 'every cron occurrence Rust found is croner\'s');
  rust.whys.forEach(function (one) {
    t.equal(one.why, S.whyOf(one.result),
            'whyOf(' + JSON.stringify(one.result).slice(0, 40) + ')');
  });
  rust.jobs.forEach(function (job, i) {
    const n = node.jobs[i];
    const want = { id: n.id, interval: n.interval, text: n.text, off: n.off,
                   timeout: n.timeout, nice: n.nice, onFront: n.onFront,
                   runIds: n.runIds };
    t.check(canonical(job) === canonical(want),
            'the job ' + job.id + ' is Node\'s', canonical(job));
  });
  log.debug("Leaving scheduler().");
}

/**
 * @param {any} t - the runner's check collector
 * @param {any} node - http-node.json
 * @param {any} rust - http-rust.json
 */
function http(t, node, rust) {
  log.debug("Entering http().");
  const app = require('../common/app');
  rust.csp.forEach(function (one) {
    t.equal(one.value, app.contentSecurityPolicy(one.overrides),
            'contentSecurityPolicy(' + JSON.stringify(one.overrides) + ')');
  });
  rust.framed.forEach(function (one) {
    t.equal(one.value, app.framedContentSecurityPolicy(one.origins,
                                                       one.overrides),
            'framedContentSecurityPolicy(' + JSON.stringify(one.origins) +
            ', ' + JSON.stringify(one.overrides) + ')');
  });
  rust.answers.forEach(function (one, i) {
    t.check(canonical(one) === canonical(node.answers[i]),
            'the answer to ' + one.path + ' is Node\'s', canonical(one));
  });
  log.debug("Leaving http().");
}

/**
 * The values Rust sealed, opened by Node's keystore over the rows Rust
 * stored — in a child process, because the key settings are read from the
 * environment once per process.
 *
 * @param {any} t - the runner's check collector
 * @param {any} node - keystore-node.json
 * @param {any} rust - keystore-rust.json
 */
function keystore(t, node, rust) {
  log.debug("Entering keystore().");
  const program = [
    "'use strict';",
    'const path = require("path");',
    'const fs = require("fs");',
    'const ROOT = process.argv[1];',
    'const rust = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));',
    'const keystore = require(path.join(ROOT, "common", "keystore.js"));',
    'const rows = new Map(rust.rows.map(function (r) {',
    '  return [r.realm, r.material];',
    '}));',
    'keystore.setStore({',
    '  loadKeys: function () {',
    '    return Promise.resolve(Array.from(rows, function (e) {',
    '      return { realm: e[0], material: e[1] };',
    '    }));',
    '  },',
    '  saveKeys: function (realm, material) {',
    '    rows.set(realm, material);',
    '    return Promise.resolve();',
    '  }',
    '});',
    'keystore.start().then(function () {',
    '  const out = {',
    '    opened: rust.sealed.map(function (one) {',
    '      return keystore.open(one.cipher, one.label) === one.text;',
    '    }),',
    '    digests: rust.digests.map(function (one) {',
    '      return keystore.keyedDigest(one.label, one.text) === one.digest;',
    '    })',
    '  };',
    '  fs.writeFileSync(process.argv[3], JSON.stringify(out));',
    '  process.exit(0);',
    '}).catch(function (e) { console.error(e); process.exit(1); });'
  ].join('\n');
  const answerFile = path.join(os.tmpdir(), 'rust-keystore-' + process.pid +
                               '.json');
  try {
    childProcess.execFileSync(process.execPath,
      ['-e', program, ROOT, path.join(VECTORS, 'keystore-rust.json'),
       answerFile],
      { env: Object.assign({}, process.env, {
        STS_LOG_LEVEL: 'fatal', STS_KEYS_SOURCE: 'persisted',
        STS_KEYS_KEK_PROVIDER: 'file',
        STS_KEYS_KEK_FILE: path.join(VECTORS, node.kekFile) }),
      stdio: ['ignore', 'ignore', 'inherit'] });
    const answer = JSON.parse(fs.readFileSync(answerFile, 'utf8'));
    answer.opened.forEach(function (ok, i) {
      t.check(ok, 'a "' + rust.sealed[i].label + '" value Rust sealed in "' +
              rust.sealed[i].realm + '" opens in Node');
    });
    answer.digests.forEach(function (ok, i) {
      t.check(ok, 'the "' + rust.digests[i].label + '" digest Rust made is ' +
              'Node\'s');
    });
  } catch (e) {
    log.debug("Caught in keystore(): " + ((e && e.message) || e));
    t.check(false, 'Node\'s keystore starts over the rows Rust stored',
            (e && e.message) || String(e));
  } finally {
    fs.rmSync(answerFile, { force: true });
  }
  log.debug("Leaving keystore().");
}

/**
 * @param {any} t - the runner's check collector
 * @returns {Promise<void>}
 */
async function run(t) {
  log.debug("Entering run().");
  const sets = [
    ['merge', merge], ['realms', realmsSet], ['ldif', ldif],
    ['scheduler', scheduler], ['http', http], ['keystore', keystore]
  ];
  for (const one of sets) {
    const node = read(one[0] + '-node.json');
    const rust = read(one[0] + '-rust.json');
    if (!node || !rust) {
      log.info('rust_store_vectors: no ' + one[0] + '-rust.json in ' +
               VECTORS + ', so it is not checked.');
      continue;
    }
    await one[1](t, node, rust);
  }
  // Held to Node's recorded answers: these need the world the builder made.
  const history = read('scheduler-history-node.json');
  const historyRust = read('scheduler-history-rust.json');
  if (history && historyRust) {
    ['status', 'acme', 'purged', 'pinned'].forEach(function (k) {
      t.check(canonical(historyRust[k]) === canonical(history[k]),
              'Rust\'s scheduler ' + k + ' is Node\'s');
    });
  }
  const tick = read('scheduler-tick-node.json');
  const tickRust = read('scheduler-tick-rust.json');
  if (tick && tickRust) {
    const S = require('../cluster/scheduler').Scheduler;
    // Which of two claims one tick asks first is not the behaviour, and the
    // rows are in no order: both sides are put in one.
    const tidy = function (ticks) {
      return ticks.map(function (events) {
        const claims = events.filter(function (e) {
          return e.claim;
        }).map(function (e) {
          return JSON.stringify(e);
        }).sort().map(function (e) {
          return JSON.parse(e);
        });
        return events.filter(function (e) {
          return !e.claim;
        }).concat(claims);
      });
    };
    const byRun = function (rows) {
      return rows.slice().sort(function (a, b) {
        const x = a.realm + a.runId;
        const y = b.realm + b.runId;
        return x < y ? -1 : (x > y ? 1 : 0);
      });
    };
    tick.scenarios.forEach(function (one, i) {
      const mine = tickRust.scenarios[i] || {};
      t.check(canonical(tidy(mine.ticks || [])) ===
              canonical(tidy(one.ticks)),
              'Rust\'s ticks of ' + one.name + ' are Node\'s',
              canonical(mine.ticks));
      t.check(canonical(byRun(mine.rows || [])) ===
              canonical(byRun(one.rows)),
              'Rust\'s run rows of ' + one.name + ' are Node\'s');
    });
    tickRust.leastLoaded.forEach(function (one) {
      t.equal(one.id, S.leastLoaded(one.loads),
              'leastLoaded(' + canonical(one.loads) + ') is Node\'s');
    });
  }
  const caches = read('cache-registry-node.json');
  const cachesRust = read('cache-registry-rust.json');
  if (caches && cachesRust) {
    const registry = require('../common/cache_registry');
    ['report', 'detail', 'ejected', 'after'].forEach(function (k) {
      t.check(canonical(cachesRust[k]) === canonical(caches[k]),
              'Rust\'s cache ' + k + ' is Node\'s');
    });
    ['snapshot', 'snapshotAsync'].forEach(function (k) {
      const unpack = function (s) {
        return s.caches.map(registry.unpackSnapshotRow);
      };
      t.check(canonical(unpack(cachesRust[k])) ===
              canonical(unpack(caches[k])) &&
              cachesRust[k].at === caches[k].at,
              'Node reads Rust\'s ' + k + ' as its own');
    });
  }
  const life = read('realm-lifecycle-node.json');
  const lifeRust = read('realm-lifecycle-rust.json');
  if (life && lifeRust) {
    life.steps.forEach(function (step, i) {
      t.check(canonical(lifeRust.results[i]) === canonical(step.result),
              'Rust answers ' + step.op + ' ' + step.id + ' as Node does',
              canonical(lifeRust.results[i]));
    });
    t.check(canonical(lifeRust.after) === canonical(life.after),
            'and its realms afterwards are Node\'s');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rust_store_vectors',
  describe: 'what the Rust store, scheduler, HTTP layer and realm registry ' +
            'answered for the store slice\'s vectors, held to Node: merges, ' +
            'realm names, LDIF files read back, schedules, CSPs, sealed ' +
            'values opened and digests',
  run: run
};
