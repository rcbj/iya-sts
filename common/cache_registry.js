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
//     file, a scope (`process` or `realm`), a `maxEntries()` (a number, or
//     `null` for unbounded), a `lifetime()` sentence, and an `entries()` that
//     answers the rows held NOW, each `{ realm, key, validUntil, valid,
//     basis }`. The functions are called when the page is drawn and never
//     before, so a descriptor costs nothing on a request.
//   * `counter(name)` — `{ hit(), miss() }`, called at the ONE place each
//     cache is looked up. Two integers per cache, process-wide, cumulative
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
// process*). The page says so.
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

/** @type {Map<string, {hits: number, misses: number}>} */
const counts = new Map();

function countsFor(name) {
  log.debug("Entering countsFor().");
  if (!counts.has(name)) {
    counts.set(name, { hits: 0, misses: 0 });
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
    }
  };
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

function summaryOf(d, held) {
  log.debug("Entering summaryOf().");
  const c = countsFor(d.name);
  const lookups = c.hits + c.misses;
  const valid = held.rows.filter(function (r) {
    return r.valid;
  }).length;
  const out = {
    name: d.name,
    title: d.title,
    description: d.description,
    owner: d.owner,
    scope: d.scope,
    kind: d.kind || 'cache',
    persisted: !!d.persisted,
    size: held.rows.length,
    valid: valid,
    expired: held.rows.length - valid,
    maxEntries: numberOrNull(d.maxEntries),
    lifetime: textOf(d.lifetime),
    settings: Array.isArray(d.settings) ? d.settings.slice() : [],
    counted: d.counted !== false,
    hitMeaning: String(d.hitMeaning ||
                       'a lookup answered from the cache'),
    hits: d.counted === false ? null : c.hits,
    misses: d.counted === false ? null : c.misses,
    hitRatio: d.counted === false || !lookups ? null : c.hits / lookups,
    problem: held.problem
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

module.exports = {
  register: register,
  digestKey: digestKey,
  realmMapRows: realmMapRows,
  realmRows: realmRows,
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
