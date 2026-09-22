// @ts-check
'use strict';
//
// File: cache_registry.js
//
// ===========================================================================
// THE CACHE REGISTRY: ONE PLACE WHERE EVERY CACHE THIS SERVICE HOLDS SAYS
// WHAT IT IS, HOW BIG IT IS, AND HOW OFTEN IT WAS USEFUL (#74, rule 3ap).
//
// TWO KINDS, and `docs/caches.md` is the list of both — a store it names is a
// store registered here, and the page is how an operator checks the document
// against the running process:
//
//   * `cache` — something held in memory that could be REBUILT from
//     somewhere else (a fetch, a parse, the directory, the key store) and is
//     consulted before rebuilding. A hit is a lookup answered from it.
//   * `replay` — a store that makes a one-time value work once: used
//     assertions, authenticators, DPoP proofs, nonces, redeemed codes. Its
//     entries CANNOT be rebuilt, which is why it is a kind of its own rather
//     than a cache with a flag: a hit there is a value found already held —
//     for a replay history a replay REFUSED, for a nonce store a nonce
//     honoured — and each descriptor says which in `hitMeaning`.
//
// Registers that are the RECORD of something — sessions, tokens, the audit
// log, consent, the directory — are neither, and are not registered.
//
// There was no shared cache class before this file and there still is not
// one. Each cache stays the `Map`, `realms.map()` or `realms.keyed()` it was,
// in the module that owns it, and DESCRIBES itself here once, beside its
// declaration:
//
//   * `register(descriptor)` — a name, a title, a description, the owning
//     file, a scope (`process` or `realm`), a `maxEntries()`, a `lifetime()`
//     sentence, and an `entries()` that answers the rows held NOW, each
//     `{ realm, key, validUntil, valid, basis }`. The functions are called
//     when the page is drawn and never before, so a descriptor costs nothing
//     on a request.
//   * `maxEntries()` IS A FINITE NUMBER, ALWAYS (2026-09-18). It was allowed
//     to answer `null` for "unbounded", and twenty-four stores did — so the
//     page said *unbounded* two dozen times about a service meant to run for
//     months. Every store has a bound now, of one of two kinds, and the
//     descriptor's `bound` member says which in a sentence:
//       - ENFORCED: the owner makes room before it inserts, through
//         `makeRoom()` below, and either drops the oldest entry or refuses
//         the insert — which one is the owner's call and is argued there
//         (a store that decides a REPLAY refuses, because forgetting a live
//         entry reopens the replay; a store of things this service handed
//         out, or could rebuild, drops the oldest).
//       - STRUCTURAL: the store cannot outgrow something else that is
//         bounded — one key set per realm, one index per realm over a
//         directory `ldap.maxEntries` caps, one row per setting that names a
//         file. Nothing is evicted because nothing can grow.
//     A descriptor answering anything but a finite number is shown with the
//     problem `STS-CORE-0096`, and `tests/cache_registry.js` fails on it.
//   * FOR A `realm` SCOPE THE BOUND IS PER REALM. `size` counts every
//     realm's rows; `largestRealm` is the one partition to compare with the
//     bound, and the page draws both.
//   * `counter(name)` — `{ hit(), miss(), evicted(n), refused() }`, called
//     at the ONE place each cache is looked up (and, for the last two, by
//     `makeRoom()`). Two integers per cache, process-wide, cumulative
//     since the process started. A store whose lookup is in a file this
//     repository may not edit (the parent project's Kerberos modules)
//     registers with `counted: false`, and the page says "not counted" rather
//     than a ratio of nothing.
//
// **A ROW NEVER CARRIES A VALUE.** `entries()` answers a key and how long it
// has left, and `rowsOf()` below copies only the five named members, so a
// descriptor that handed back a whole cached object — a decrypted key, a
// signed document — still could not put it on the page.
// `tests/cache_registry.js` holds that.
//
// **A LEAF (rule 3), AND JAVASCRIPT ON PURPOSE.** Several owners —
// `helpers.js`, `keystore.js`, `revocation_status.js`, `krb5_principals.js` —
// are in the parent project's Kerberos COPY closure and are loaded there by
// plain node, so this file cannot be TypeScript, and it requires nothing of
// this service but `config` (for the logger, as `client_address.js` does), so
// it can close no cycle. Requiring it from those modules OWES the parent one
// COPY line; `kerberos/CLAUDE.md` records it.
//
// **THE FIGURES ARE THE ANSWERING PROCESS'S.** A request worker and a cluster
// node each hold caches of their own; nothing here is coordinated, because a
// cache is exactly the thing a store is not (root CLAUDE.md, *One front
// process*). The page says so. What crosses to another node is `snapshot()`
// below — sizes and counters, never a row — which `cluster/cluster.js` puts
// on the node's membership row (2026-09-18).
// ===========================================================================

const nodeCrypto = require('crypto');
const bunyan = require('bunyan');
const config = require('./config');
const errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-cache-registry' });
config.registerLogger(log);

const SCOPES = ['process', 'realm'];
const KINDS = ['cache', 'replay'];

/** @type {Map<string, any>} */
const descriptors = new Map();

/**
 * @type {Map<string, {hits: number, misses: number, evictions: number,
 *   refusals: number}>}
 */
const counts = new Map();

function countsFor(name) {
  log.debug("Entering countsFor().");
  if (!counts.has(name)) {
    counts.set(name, { hits: 0, misses: 0, evictions: 0, refusals: 0 });
  }
  log.debug("Leaving countsFor().");
  return counts.get(name);
}

// A descriptor is checked WHOLE when it is registered, for the reason rule 3e
// gives for a slot: one registered with half its members draws a row that
// looks right and fails when its drill-down is opened.
function register(descriptor) {
  log.debug("Entering register().");
  const d = descriptor || {};
  const missing = ['name', 'title', 'description', 'owner']
    .filter(function (k) {
      return typeof d[k] !== 'string' || !d[k];
    })
    .concat(['maxEntries', 'lifetime', 'entries'].filter(function (k) {
      return typeof d[k] !== 'function';
    }));
  if (SCOPES.indexOf(d.scope) < 0) {
    missing.push('scope');
  }
  if (d.kind !== undefined && KINDS.indexOf(d.kind) < 0) {
    missing.push('kind');
  }
  if (d.eject !== undefined && typeof d.eject !== 'function') {
    missing.push('eject as a function');
  }
  if (missing.length) {
    log.debug("Leaving register(). Incomplete.");
    throw new Error(errorCodes.tag('STS-CORE-0094') +
                    'A cache descriptor (' + String(d.name) +
                    ') is missing: ' + missing.join(', ') + '.');
  }
  // A second registration of the same name REPLACES the first: a test that
  // reloads a module, or a module whose instance the composition root
  // rebuilds, must not leave two rows for one cache.
  descriptors.set(d.name, d);
  countsFor(d.name);
  log.debug("Leaving register().");
  return counter(d.name);
}

// Hot path: called on every lookup of every registered cache, so no
// Entering/Leaving pair here — it would drown the log with two lines per
// cached read.
function counter(name) {
  const c = countsFor(name);
  return {
    hit: function () {
      c.hits += 1;
    },
    miss: function () {
      c.misses += 1;
    },
    evicted: function (n) {
      c.evictions += Math.max(0, Number(n) || 0);
    },
    refused: function () {
      c.refusals += 1;
    }
  };
}

// ---------------------------------------------------------------------------
// MAKING ROOM BEFORE AN INSERT (2026-09-18) — the one way an owner enforces
// its bound, so every enforced bound on the page behaves the same way.
//
// Called before a NEW key is set (an update of a key already held needs no
// room). `store` is a Map, or a `realms.map()` (whose methods act on the
// ambient realm's partition, which is what a per-realm bound means), and
// `max` the bound. In order:
//
//   1. `options.expired(value, key)`, when given, drops what is already past
//      its deadline. Owners that already prune on the same path pass nothing.
//   2. Below the bound: room, nothing else happens.
//   3. At the bound, `options.policy`:
//        * 'evict-oldest' (the default) — the entry INSERTED first goes (a
//          Map iterates in insertion order), repeatedly, until there is room.
//          Returns `{ ok: true, evicted: n }`.
//        * 'refuse' — nothing is dropped and `{ ok: false }` is returned; the
//          owner refuses the request in its own protocol's words.
//
// `options.counter`, the object `register()` returned, has the eviction or
// the refusal added to the figures the page draws. A refusal is also LOGGED,
// once per store per minute at most — a full replay store refusing traffic is
// a state an operator has to hear about, and a line per refused request is
// the flood `no per-event failure logs` forbids.
// ---------------------------------------------------------------------------
/** @type {Map<string, number>} */
const lastRefusalLog = new Map();

// Hot path: called before every insert into a bounded store, so no
// Entering/Leaving pair — it would add two log lines per cached write.
function makeRoom(store, max, options) {
  const o = options || {};
  const limit = Number(max);
  if (typeof o.expired === 'function' && store.size >= limit) {
    const stale = [];
    store.forEach(function (value, key) {
      if (o.expired(value, key)) {
        stale.push(key);
      }
    });
    stale.forEach(function (key) {
      store.delete(key);
    });
  }
  if (!(isFinite(limit) && limit > 0) || store.size < limit) {
    return { ok: true, evicted: 0 };
  }
  if (o.policy === 'refuse') {
    if (o.counter && typeof o.counter.refused === 'function') {
      o.counter.refused();
    }
    const name = String(o.name || 'a bounded store');
    const now = Date.now();
    if (!(now - (lastRefusalLog.get(name) || 0) < 60000)) {
      lastRefusalLog.set(name, now);
      log.warn(errorCodes.tag('STS-CORE-0097') + 'Cache ' + name + ' is ' +
               'full (' + store.size + ' of ' + limit + ' live entries) and ' +
               'refuses new ones rather than forgetting a live one. ' +
               (o.setting ? 'Raise ' + o.setting + ' if this load is ' +
                'legitimate. ' : '') + 'Logged at most once a minute.');
    }
    return { ok: false, evicted: 0 };
  }
  let evicted = 0;
  while (store.size >= limit) {
    const first = store.keys().next();
    if (first.done) {
      break;
    }
    store.delete(first.value);
    evicted += 1;
  }
  if (evicted && o.counter && typeof o.counter.evicted === 'function') {
    o.counter.evicted(evicted);
  }
  return { ok: true, evicted: evicted };
}

function names() {
  log.debug("Entering names().");
  log.debug("Leaving names().");
  return Array.from(descriptors.keys()).sort();
}

function has(name) {
  log.debug("Entering has().");
  log.debug("Leaving has().");
  return descriptors.has(String(name));
}

// The five members a row may carry, and nothing else (see the header).
function rowsOf(d, now) {
  log.debug("Entering rowsOf().");
  let raw;
  try {
    raw = d.entries(now) || [];
  } catch (e) {
    // A descriptor that throws must not take the page with it; the page
    // shows the cache with no rows and says why.
    log.debug("Caught in rowsOf(): " + ((e && e.message) || e));
    log.error(errorCodes.tag('STS-CORE-0095') + 'Cache ' + d.name +
              ' could not list its entries: ' + ((e && e.message) || e));
    log.debug("Leaving rowsOf(). The descriptor threw.");
    return { rows: [], problem: String((e && e.message) || e) };
  }
  const rows = raw.map(function (r) {
    const until = typeof r.validUntil === 'number' &&
      isFinite(r.validUntil) ? r.validUntil : null;
    const valid = typeof r.valid === 'boolean'
      ? r.valid
      : (until === null || until > now);
    return {
      realm: r.realm === undefined || r.realm === null
        ? null : String(r.realm),
      key: String(r.key),
      validUntil: until,
      valid: valid,
      basis: r.basis ? String(r.basis) : (until === null
        ? 'no expiry' : 'time')
    };
  });
  log.debug("Leaving rowsOf().");
  return { rows: rows, problem: null };
}

function numberOrNull(f) {
  log.debug("Entering numberOrNull().");
  let v = null;
  try {
    v = f();
  } catch (e) {
    log.debug("Caught in numberOrNull(): " + ((e && e.message) || e));
    v = null;
  }
  log.debug("Leaving numberOrNull().");
  return typeof v === 'number' && isFinite(v) ? v : null;
}

function textOf(f) {
  log.debug("Entering textOf().");
  let v = '';
  try {
    v = f();
  } catch (e) {
    log.debug("Caught in textOf(): " + ((e && e.message) || e));
    v = '';
  }
  log.debug("Leaving textOf().");
  return String(v || '');
}

// The rows of the fullest realm, for a per-realm bound (see the header).
function largestRealmOf(rows) {
  log.debug("Entering largestRealmOf().");
  const per = new Map();
  rows.forEach(function (r) {
    const id = r.realm === null ? '' : r.realm;
    per.set(id, (per.get(id) || 0) + 1);
  });
  let most = 0;
  per.forEach(function (n) {
    most = Math.max(most, n);
  });
  log.debug("Leaving largestRealmOf().");
  return most;
}

function summaryOf(d, held) {
  log.debug("Entering summaryOf().");
  const c = countsFor(d.name);
  const lookups = c.hits + c.misses;
  const valid = held.rows.filter(function (r) {
    return r.valid;
  }).length;
  const max = numberOrNull(d.maxEntries);
  let problem = held.problem;
  if (max === null) {
    // Every store has a bound (see the header). One that reports none is a
    // regression, shown on its row rather than drawn as "unbounded".
    log.error(errorCodes.tag('STS-CORE-0096') + 'Cache ' + d.name +
              ' reports no bound: its maxEntries() answered no finite ' +
              'number.');
    problem = (problem ? problem + ' ' : '') + 'It reports no bound ' +
      '(STS-CORE-0096).';
  }
  const largest = d.scope === 'realm' ? largestRealmOf(held.rows)
    : held.rows.length;
  const out = {
    name: d.name,
    title: d.title,
    description: d.description,
    owner: d.owner,
    scope: d.scope,
    kind: d.kind || 'cache',
    persisted: !!d.persisted,
    size: held.rows.length,
    largestRealm: largest,
    valid: valid,
    expired: held.rows.length - valid,
    maxEntries: max,
    bound: typeof d.bound === 'function' ? textOf(d.bound)
      : String(d.bound || ''),
    atBound: max !== null && largest >= max,
    lifetime: textOf(d.lifetime),
    settings: Array.isArray(d.settings) ? d.settings.slice() : [],
    counted: d.counted !== false,
    notCountedWhy: d.counted === false
      ? String(d.notCountedWhy || 'the lookup is in a file this ' +
               'repository does not edit') : '',
    hitMeaning: String(d.hitMeaning ||
                       'a lookup answered from the cache'),
    hits: d.counted === false ? null : c.hits,
    misses: d.counted === false ? null : c.misses,
    hitRatio: d.counted === false || !lookups ? null : c.hits / lookups,
    evictions: c.evictions,
    refusals: c.refusals,
    problem: problem
  };
  log.debug("Leaving summaryOf().");
  return out;
}

// Every cache, summarised. `now` is a parameter so a test can hold the clock.
function report(now) {
  log.debug("Entering report().");
  const at = typeof now === 'number' ? now : Date.now();
  const out = names().map(function (n) {
    const d = descriptors.get(n);
    return summaryOf(d, rowsOf(d, at));
  });
  log.debug("Leaving report().");
  return out;
}

// THE COMPACT FORM ANOTHER CLUSTER NODE READS (2026-09-18). `cluster.js`
// puts it in this node's membership row, which is the only channel between
// nodes (`cluster/CLAUDE.md`), so it is small on purpose: per store the name,
// the size, the fullest realm, the valid count, the bound and the four
// counters — about sixty bytes a store and nothing that grows with the store.
// Titles, descriptions and rows stay here; the page takes those from its own
// registry, which lists the same stores on every node of one build.
function snapshot(now) {
  log.debug("Entering snapshot().");
  const at = typeof now === 'number' ? now : Date.now();
  const out = report(at).map(function (c) {
    return [c.name, c.size, c.largestRealm, c.valid, c.maxEntries,
            c.hits, c.misses, c.evictions, c.refusals];
  });
  log.debug("Leaving snapshot().");
  return { at: at, pid: process.pid, caches: out };
}

// The reverse of `snapshot()`'s rows, for the page.
function unpackSnapshotRow(row) {
  log.debug("Entering unpackSnapshotRow().");
  const r = Array.isArray(row) ? row : [];
  const num = function (v) {
    return typeof v === 'number' && isFinite(v) ? v : null;
  };
  log.debug("Leaving unpackSnapshotRow().");
  return { name: String(r[0] || ''), size: num(r[1]) || 0,
           largestRealm: num(r[2]) || 0, valid: num(r[3]) || 0,
           maxEntries: num(r[4]), hits: num(r[5]), misses: num(r[6]),
           evictions: num(r[7]) || 0, refusals: num(r[8]) || 0 };
}

// One cache: its summary and every row it holds now, oldest deadline first
// (rows with no deadline last), so the rows about to go are on page one.
function detail(name, now) {
  log.debug("Entering detail().");
  const at = typeof now === 'number' ? now : Date.now();
  const d = descriptors.get(String(name));
  if (!d) {
    log.debug("Leaving detail(). Unknown.");
    return null;
  }
  const held = rowsOf(d, at);
  const rows = held.rows.slice().sort(function (a, b) {
    const x = a.validUntil === null ? Infinity : a.validUntil;
    const y = b.validUntil === null ? Infinity : b.validUntil;
    if (x !== y) {
      return x < y ? -1 : 1;
    }
    return (a.realm || '').localeCompare(b.realm || '') ||
      a.key.localeCompare(b.key);
  });
  log.debug("Leaving detail().");
  return { summary: summaryOf(d, held), rows: rows };
}

// For tests only: drop one cache's descriptor and counts.
function forget(name) {
  log.debug("Entering forget().");
  const gone = descriptors.delete(String(name));
  counts.delete(String(name));
  log.debug("Leaving forget().");
  return gone;
}

// For tests only: zero the counters, keep the descriptors.
function resetCounts() {
  log.debug("Entering resetCounts().");
  counts.forEach(function (c) {
    c.hits = 0;
    c.misses = 0;
    c.evictions = 0;
    c.refusals = 0;
  });
  log.debug("Leaving resetCounts().");
}

// A key clipped for display. A cache key can be a whole claims document or a
// URL with a long query; the page shows the front and the length.
function clipKey(text, max) {
  log.debug("Entering clipKey().");
  const s = String(text);
  const limit = max || 160;
  log.debug("Leaving clipKey().");
  return s.length <= limit
    ? s
    : s.slice(0, limit) + '… (' + s.length + ' characters)';
}

// The rows of a per-realm Map (`realms.map()`), every realm's partition.
// `ids` is the realm ids to walk and `mapOf(id)` one realm's Map — passed in,
// because this file requires `realms.js` no more than anything else here.
// `rowOf(value, key)` answers one row's other members.
function realmRows(ids, mapOf, rowOf) {
  log.debug("Entering realmRows().");
  const out = [];
  ids.forEach(function (id) {
    const held = mapOf(id);
    if (!held) {
      return;
    }
    held.forEach(function (value, key) {
      out.push(Object.assign({ realm: id }, rowOf(value, key)));
    });
  });
  log.debug("Leaving realmRows().");
  return out;
}

// A key that is itself a credential — a session id, a flow's state value, an
// authorization code — shown as the part before its first colon (a kind, where
// the owner uses one) and the first twelve hex characters of its SHA-256, so
// two rows can be told apart and neither can be used.
function digestKey(text) {
  log.debug("Entering digestKey().");
  const s = String(text);
  const colon = s.indexOf(':');
  const kind = colon > 0 && colon <= 16 ? s.slice(0, colon + 1) : '';
  log.debug("Leaving digestKey().");
  return kind + 'sha256:' + nodeCrypto.createHash('sha256').update(s)
    .digest('hex').slice(0, 12) + '…';
}

// The same for a `realms.map()` store, walked over every realm the owner's
// `realms` module lists. The owner passes its module in, for `realmRows()`'s
// reason.
function realmMapRows(realmsModule, store, rowOf) {
  log.debug("Entering realmMapRows().");
  const ids = realmsModule.list().map(function (r) {
    return r.id;
  });
  log.debug("Leaving realmMapRows().");
  return realmRows(ids, function (id) {
    return store.realmMap(id);
  }, rowOf);
}

// ---------------------------------------------------------------------------
// EJECTING WHAT HAS EXPIRED (#49 P5, rcbj's directive of 2026-09-21: "cache
// and store clean-up is included"). A descriptor whose entries expire carries
// `eject(nowMs)`, which deletes them and answers how many; the scheduler job
// `caches.eject-expired` (`admin-ui/caches_admin.ts`) calls `ejectExpired()`
// in every process, because every process holds its own copy.
//
// **IT IS HOUSEKEEPING AND NEVER CORRECTNESS.** Every owner still refuses an
// expired entry where it READS it, whenever the job last ran, and still
// bounds its store where it INSERTS (`makeRoom()`); ejection only stops an
// idle store holding dead rows until its next lookup. So an ejector must
// delete nothing its reader would still honour, and an entry exactly at its
// boundary is left to the reader. The two helpers below take the owner's own
// expiry test, the same one its reader applies.
// ---------------------------------------------------------------------------
function ejectExpired(now) {
  log.debug("Entering ejectExpired().");
  const at = Number(now) || Date.now();
  const byCache = {};
  const failed = [];
  let total = 0;
  descriptors.forEach(function (d, name) {
    if (typeof d.eject !== 'function') {
      return;
    }
    let n = 0;
    try {
      n = Number(d.eject(at)) || 0;
    } catch (e) {
      log.debug("Caught in ejectExpired(): " + ((e && e.message) || e));
      failed.push(name + ': ' + ((e && e.message) || e));
      return;
    }
    if (n > 0) {
      byCache[name] = n;
      total += n;
      countsFor(name).evictions += n;
    }
  });
  log.debug("Leaving ejectExpired(). " + total + " ejected.");
  return { ejected: total, byCache: byCache, failed: failed };
}

// The names of the stores that eject, for the page and the test.
function ejecting() {
  log.debug("Entering ejecting().");
  const out = [];
  descriptors.forEach(function (d, name) {
    if (typeof d.eject === 'function') {
      out.push(name);
    }
  });
  log.debug("Leaving ejecting().");
  return out.sort();
}

// An `eject` for a plain Map: deletes each entry for which
// `expired(value, key, now)` is true. Collected first and deleted after, so
// the walk never sees a map it is changing.
function mapEjector(map, expired) {
  log.debug("Entering mapEjector().");
  log.debug("Leaving mapEjector().");
  return function (now) {
    const gone = [];
    map.forEach(function (value, key) {
      if (expired(value, key, now)) {
        gone.push(key);
      }
    });
    gone.forEach(function (key) {
      map.delete(key);
    });
    return gone.length;
  };
}

// The same for a `realms.map()` store: every realm's partition, each deleted
// through the store's own map so a persisted store records the deletion, and
// each ASKED INSIDE ITS REALM (`realms.run()`), because an owner's lifetime is
// usually a setting and a setting is the realm's.
function realmMapEjector(realmsModule, store, expired) {
  log.debug("Entering realmMapEjector().");
  log.debug("Leaving realmMapEjector().");
  return function (now) {
    let total = 0;
    realmsModule.list().forEach(function (r) {
      const map = store.realmMap(r.id);
      if (map) {
        total += realmsModule.run(r, function () {
          return mapEjector(map, expired)(now);
        });
      }
    });
    return total;
  };
}

module.exports = {
  register: register,
  makeRoom: makeRoom,
  snapshot: snapshot,
  unpackSnapshotRow: unpackSnapshotRow,
  digestKey: digestKey,
  realmMapRows: realmMapRows,
  realmRows: realmRows,
  ejectExpired: ejectExpired,
  ejecting: ejecting,
  mapEjector: mapEjector,
  realmMapEjector: realmMapEjector,
  counter: counter,
  names: names,
  has: has,
  report: report,
  detail: detail,
  resetCounts: resetCounts,
  forget: forget,
  clipKey: clipKey,
  SCOPES: SCOPES,
  KINDS: KINDS
};
