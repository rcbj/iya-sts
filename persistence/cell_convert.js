// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cell_convert.js
//
// ===========================================================================
// A SINGLE-CELL STORE BECOMES A CELL, ONCE (#98, 2026-09-28).
//
//   node persistence/cell_convert.js [--dry-run]
//
// run inside the service's image, configured EXACTLY LIKE THE CELL IT WILL
// BECOME: `cells.id` (STS_CELL_ID) names the cell, the CELL database is
// `persistence.databaseUrl` with its password provider — the database of the
// single-cell deployment being converted, restored from its snapshot — the
// GLOBAL database is `persistence.globalDatabaseUrl` with its own provider,
// built empty at the current schema, and the SERVICE key-encryption key is
// `keys.kek*`. Every one of those is read through the service's own code
// (`persistence.databaseConnection()`, `globalDatabaseConnection()`,
// `persistence_postgres.dialOptions()`, `keystore.start()`), never a copy of
// it, so the tool cannot dial a database the service would not.
//
// **WHAT IT DOES IS WHAT THE TIERED DRIVER WOULD HAVE WRITTEN.** A cell's
// store is two databases (`persistence/CLAUDE.md`, *Tiers*); a store that
// grew up as one database holds both tiers' rows in it. This moves the
// global tier's rows into the global database, row for row and byte for
// byte, and leaves the rest where it is:
//
//   GLOBAL   `sts_realms`, `sts_appconfig`, `sts_keys` (realm key sets and
//            the `pki:` certificate authorities), `sts_used_assertions`,
//            `sts_cluster_secrets` — every row, because every driver method
//            that touches them is in the tiered driver's GLOBAL_METHODS;
//            every directory entry `tiers.directoryTierOf()` calls global;
//            the GLOBAL HALF of every group (`tiers.splitGroup()`), whose
//            cell row is rewritten to its cell half — or deleted when that
//            is empty, as `splitChange()` deletes it; every `sts_minted` row
//            whose handle `tiers.mintedTierOf()` calls global (tombstones
//            included, since a tombstone is a row of its store); and any
//            claim under `scheduler.run.global` (`tiers.claimTierOf()`) —
//            none in a single-cell store, which never claims that scope.
//   CELL     the people and their devices, the person half of each group,
//            every cell-tier minted row (and any unclassified one, which the
//            tiered driver also keeps where it was made), the audit log, ALL
//            of `sts_risk_*` — untouched, never read but to count — and the
//            cluster's membership, leases, claims, counters and windows.
//
// AND THE ROUTING INDEX IS BACKFILLED: every person in the cell database is
// claimed in the global `sts_cell_routing` under their login name and
// entryUUID, as keyed digests under the service key — the rows the flush's
// `indexPeople()` writes, made by the SAME digest (`persistence.
// routingDigest()`) from the same two values (`persistence_tiered.
// loginNameOf()` and `uuidOf()`).
//
// **COPY, VERIFY, THEN DELETE — AND EVERY STEP CAN BE RUN AGAIN.** The copy
// is one transaction on the global database; it is read back and compared
// row by row; only then is the cell database changed, in one transaction of
// its own. So a failure anywhere leaves the source rows in place, and the
// states a crash can leave are exactly three, each of which a re-run
// recognises:
//
//   not started  the global database is empty: convert.
//   copied       the global database holds exactly the cell's realms and
//                keys (the copy committed and the clean-up did not): copy
//                again (the same rows, upserted), verify, clean up.
//   converted    the cell database holds no realm and no key: nothing is
//                moved; the routing index is checked for every person here
//                and a missing row claimed (none, on a re-run), and the exit
//                is 0.
//
// **IT REFUSES A SECOND SOURCE**: a global database holding realms or keys
// that are not this cell database's, or an index naming another cell, is a
// service that already exists — converting into it would put two sets of
// realm keys behind one name. And a cell database with nothing to convert
// beside an empty global database is refused too: there is nothing to do,
// and "done" would be a lie.
//
// **NOTHING IS RE-SEALED.** A row sealed in a single-cell store is sealed
// under the service scope's data encryption keys (#391), whose wrapped rows
// are in `sts_keys` and so in the GLOBAL tier every cell reads; the cell rows
// keep them too — `keystore.open()` finds the data encryption key a value
// names whatever its scope, so they open where they are and are sealed under
// the cell's own keys when next written.
//
// **THE CHANGE LOGS ARE NOT COPIED.** `sts_changes` is a list of pointers to
// rows, read by processes that are running; nothing is running across a
// conversion, and every process that starts after it restores the TABLES and
// begins following each log at its current end. So the global database's
// log and `sts_change_readers` start EMPTY — its first row is the first write
// a cell makes there — and the cell database keeps its own. The old
// deployment's readers and nodes there need nothing done: a reader whose
// node is no longer a live member is dropped at the next trim
// (`purgeChangeLog()`), and its membership rows expire and are purged like
// any dead node's.
//
// A TOOL, NOT A PART OF THE SERVICE: no route, and only the command line
// requires the service's settings graph, so a test can drive `convert()`
// over two doubles.
// ===========================================================================

const bunyan = require('bunyan');
const tiers = require('./tiers');
const tiered = require('./persistence_tiered');
const errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({ name: 'sts-cell-convert',
                                  level: process.env.STS_LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// THE TABLES THIS TOUCHES, AS `postgres/schema.sql` HAS THEM. `json` columns
// are jsonb and travel as parsed values; `time` columns are timestamptz and
// travel as ISO text in UTC, which round-trips to the microsecond. A bigint
// comes back from `pg` as a string and goes back in as one, unchanged.
// Every identifier in a statement below comes from this table and from
// nowhere else.
// ---------------------------------------------------------------------------
const TABLES = {
  sts_realms: {
    key: ['id'],
    columns: ['id', 'name', 'description', 'created_at', 'overrides',
              'domain', 'retiring_at'],
    json: ['overrides'], time: [] },
  sts_appconfig: {
    key: ['key'], columns: ['key', 'value'], json: ['value'], time: [] },
  sts_keys: {
    key: ['realm'], columns: ['realm', 'material', 'written_at'],
    json: [], time: ['written_at'] },
  sts_used_assertions: {
    key: ['realm', 'key'],
    columns: ['realm', 'key', 'format', 'used_as', 'issuer', 'identifier',
              'client_id', 'subject', 'state', 'reservation', 'origin',
              'used_at', 'spent_at', 'expires_at'],
    json: [], time: [] },
  sts_cluster_secrets: {
    key: ['name'], columns: ['name', 'material', 'created_by', 'created_at'],
    json: [], time: [] },
  sts_ldap_entries: {
    key: ['realm', 'dn_key'],
    // The six lookup columns the service writes beside the sealed `attrs`
    // since #391 phase 6 (they were generated).
    columns: ['realm', 'dn_key', 'dn', 'attrs', 'origin', 'created_at',
              'modified_at', 'name_keys', 'mail_keys', 'uuid_keys',
              'class_keys', 'value_keys', 'attr_names'],
    json: ['attrs', 'name_keys', 'mail_keys', 'uuid_keys', 'class_keys',
           'value_keys', 'attr_names'], time: [] },
  sts_minted: {
    key: ['handle', 'realm', 'key'],
    // `key_sealed`: the row's name, sealed beside its digest key (#222).
    columns: ['handle', 'realm', 'key', 'body', 'written_at', 'key_sealed'],
    json: [], time: ['written_at'] },
  sts_cluster_claims: {
    key: ['scope', 'realm', 'key'],
    columns: ['scope', 'realm', 'key', 'reservation', 'origin', 'claimed_at',
              'expires_at'],
    json: [], time: [] },
  sts_cell_routing: {
    key: ['realm', 'kind', 'digest'],
    columns: ['realm', 'kind', 'digest', 'cell', 'written_at'],
    json: [], time: [] }
};

// The tables every row of which is the global tier's.
const WHOLE_TABLES = ['sts_realms', 'sts_appconfig', 'sts_keys',
                      'sts_used_assertions', 'sts_cluster_secrets'];
// The tables an EMPTY global database has nothing in.
const GLOBAL_TABLES = WHOLE_TABLES.concat(['sts_ldap_entries', 'sts_minted',
                                           'sts_cell_routing']);

// A value in one spelling whatever produced it, so that a row read from one
// database compares equal to the same row read from the other: object keys
// sorted (jsonb reorders them), and every scalar but null as a string.
function canonical(value) {
  log.debug("Entering canonical().");
  let out;
  if (value === null || value === undefined) {
    out = 'null';
  } else if (Array.isArray(value)) {
    out = '[' + value.map(canonical).join(',') + ']';
  } else if (typeof value === 'object') {
    out = '{' + Object.keys(value).sort().map(function (k) {
      return JSON.stringify(k) + ':' + canonical(value[k]);
    }).join(',') + '}';
  } else {
    out = JSON.stringify(String(value));
  }
  log.debug("Leaving canonical().");
  return out;
}

// A row's primary key as one string.
function keyOf(table, row) {
  log.debug("Entering keyOf().");
  const out = TABLES[table].key.map(function (col) {
    return String(row[col] === null || row[col] === undefined ? ''
                                                               : row[col]);
  }).join('\u0000');
  log.debug("Leaving keyOf().");
  return out;
}

// A row's whole content as one string.
function contentOf(table, row) {
  log.debug("Entering contentOf().");
  const spec = TABLES[table];
  const out = spec.columns.map(function (col) {
    return canonical(row[col]);
  }).join('\u0001');
  log.debug("Leaving contentOf().");
  return out;
}

// ---------------------------------------------------------------------------
// ONE DATABASE, OVER `pg`. The store the conversion is driven through: the
// real one here, a double in `tests/cell_convert.js`. Six operations and a
// transaction, each a statement built from `TABLES` with every value a
// parameter.
// ---------------------------------------------------------------------------
/**
 * Builds the store of one database over `pg`.
 *
 * @param options - `url` (the connection string, password included),
 *   `verifyTls`, and `name` ('cell' or 'global', for the log)
 * @returns the store
 */
function sqlStore(options) {
  log.debug("Entering sqlStore().");
  const dial = require('./persistence_postgres')
    .dialOptions(options.url, options.verifyTls);
  if (dial.notUrl) {
    log.debug('cell_convert: the ' + options.name + ' connection string is ' +
              'not a URL, so its sslmode was left as it is.');
  }
  const Pool = /** @type {any} */ (require('pg')).Pool;
  const pool = new Pool({ connectionString: dial.connectionString,
                          ssl: dial.ssl, max: 2,
                          connectionTimeoutMillis: 10000 });
  pool.on('error', function (err) {
    log.warn('cell_convert: an idle connection to the ' + options.name +
             ' database errored: ' + ((err && err.message) || err));
  });

  // What a column is SELECTed as.
  function selectOf(table, col) {
    log.debug("Entering selectOf().");
    const spec = TABLES[table];
    log.debug("Leaving selectOf().");
    return spec.time.indexOf(col) >= 0
      ? 'to_char(' + col + ' AT TIME ZONE \'UTC\', ' +
        '\'YYYY-MM-DD"T"HH24:MI:SS.US"Z"\') AS ' + col
      : col;
  }

  // What a column's parameter is cast to on the way in.
  function castOf(table, col, n) {
    log.debug("Entering castOf().");
    const spec = TABLES[table];
    log.debug("Leaving castOf().");
    if (spec.json.indexOf(col) >= 0) {
      return '$' + n + '::jsonb';
    }
    return spec.time.indexOf(col) >= 0 ? '$' + n + '::timestamptz' : '$' + n;
  }

  // A parameter's value on the way in.
  function paramOf(table, col, value) {
    log.debug("Entering paramOf().");
    const spec = TABLES[table];
    log.debug("Leaving paramOf().");
    if (spec.json.indexOf(col) >= 0) {
      return JSON.stringify(value === undefined ? null : value);
    }
    return value === undefined ? null : value;
  }

  // `{ col: value | [values] }` as a WHERE clause from `at` onwards.
  function whereOf(filter, params) {
    log.debug("Entering whereOf().");
    const parts = Object.keys(filter || {}).map(function (col) {
      const v = filter[col];
      params.push(Array.isArray(v) ? v.map(String) : v);
      return Array.isArray(v) ? col + ' = ANY($' + params.length + '::text[])'
                              : col + ' = $' + params.length;
    });
    log.debug("Leaving whereOf().");
    return parts.length ? ' WHERE ' + parts.join(' AND ') : '';
  }

  function transactionOps(client) {
    log.debug("Entering transactionOps().");
    const ops = {
      upsert: async function (table, rows) {
        log.debug("Entering upsert(). " + table);
        const spec = TABLES[table];
        const cols = spec.columns;
        const rest = cols.filter(function (c) {
          return spec.key.indexOf(c) < 0;
        });
        const sql = 'INSERT INTO ' + table + ' (' + cols.join(', ') + ') ' +
          'VALUES (' + cols.map(function (c, i) {
            return castOf(table, c, i + 1);
          }).join(', ') + ') ON CONFLICT (' + spec.key.join(', ') + ') ' +
          (rest.length ? 'DO UPDATE SET ' + rest.map(function (c) {
            return c + ' = EXCLUDED.' + c;
          }).join(', ') : 'DO NOTHING');
        for (const row of rows) {
          await client.query(sql, cols.map(function (c) {
            return paramOf(table, c, row[c]);
          }));
        }
        log.debug("Leaving upsert().");
      },
      insertAbsent: async function (table, rows) {
        log.debug("Entering insertAbsent(). " + table);
        const spec = TABLES[table];
        const cols = spec.columns;
        const sql = 'INSERT INTO ' + table + ' (' + cols.join(', ') + ') ' +
          'VALUES (' + cols.map(function (c, i) {
            return castOf(table, c, i + 1);
          }).join(', ') + ') ON CONFLICT (' + spec.key.join(', ') + ') ' +
          'DO NOTHING';
        let inserted = 0;
        for (const row of rows) {
          const r = await client.query(sql, cols.map(function (c) {
            return paramOf(table, c, row[c]);
          }));
          inserted += (r && r.rowCount) || 0;
        }
        log.debug("Leaving insertAbsent().");
        return inserted;
      },
      remove: async function (table, rows) {
        log.debug("Entering remove(). " + table);
        const spec = TABLES[table];
        const sql = 'DELETE FROM ' + table + ' WHERE ' +
          spec.key.map(function (c, i) {
            return c + ' = $' + (i + 1);
          }).join(' AND ');
        let removed = 0;
        for (const row of rows) {
          const r = await client.query(sql, spec.key.map(function (c) {
            return row[c];
          }));
          removed += (r && r.rowCount) || 0;
        }
        log.debug("Leaving remove().");
        return removed;
      },
      // THE OLD DEPLOYMENT'S MEMBERSHIP (2026-09-30): a restored database
      // carries the membership rows of the nodes that wrote it, every one of
      // them dead — the conversion runs while the cell's nodes are held at
      // zero — and the new cell's Cluster page drew them as nodes that had
      // "left or expired" (testidpna: testidp's ten, beside its own three).
      // Only a row whose lifetime has passed, by the database's clock, is
      // deleted, so a node somebody started early is never touched. Leases
      // are kept: a released lease is never deleted, or its fencing token
      // would go back to 1 (cluster/CLAUDE.md).
      forgetDeadMembers: async function () {
        log.debug("Entering forgetDeadMembers().");
        const r = await client.query(
          'DELETE FROM sts_cluster_nodes WHERE left_at <> 0 OR expires_at < ' +
          '(extract(epoch from clock_timestamp()) * 1000)::bigint');
        log.debug("Leaving forgetDeadMembers().");
        return (r && r.rowCount) || 0;
      }
    };
    log.debug("Leaving transactionOps().");
    return ops;
  }

  const store = {
    name: options.name,
    schemaVersion: async function () {
      log.debug("Entering schemaVersion().");
      const r = await pool.query('SELECT max(version) AS v FROM sts_schema');
      const row = (r.rows || [])[0];
      log.debug("Leaving schemaVersion().");
      return row && row.v !== null ? Number(row.v) : null;
    },
    rows: async function (table, filter) {
      log.debug("Entering rows(). " + table);
      const params = [];
      const sql = 'SELECT ' + TABLES[table].columns.map(function (c) {
        return selectOf(table, c);
      }).join(', ') + ' FROM ' + table + whereOf(filter, params);
      const r = await pool.query(sql, params);
      log.debug("Leaving rows().");
      return r.rows || [];
    },
    count: async function (table) {
      log.debug("Entering count(). " + table);
      const r = await pool.query('SELECT count(*)::bigint AS n FROM ' + table);
      log.debug("Leaving count().");
      return Number(((r.rows || [])[0] || {}).n) || 0;
    },
    countBy: async function (table, col) {
      log.debug("Entering countBy(). " + table);
      const r = await pool.query('SELECT ' + col + ' AS v, count(*)::bigint ' +
                                 'AS n FROM ' + table + ' GROUP BY ' + col);
      const out = {};
      (r.rows || []).forEach(function (row) {
        out[String(row.v)] = Number(row.n) || 0;
      });
      log.debug("Leaving countBy().");
      return out;
    },
    // Every `sts_risk_*` table and its row count, read from the catalogue so
    // that a table a later schema adds is counted without an edit here.
    riskCounts: async function () {
      log.debug("Entering riskCounts().");
      const t = await pool.query(
        'SELECT table_name FROM information_schema.tables WHERE ' +
        'table_schema = current_schema() AND table_name LIKE $1 ' +
        'ORDER BY table_name', ['sts\\_risk\\_%']);
      const out = {};
      for (const row of (t.rows || [])) {
        const name = String(row.table_name);
        // The name comes from the catalogue and matched the pattern above;
        // quoted as an identifier all the same.
        const r = await pool.query('SELECT count(*)::bigint AS n FROM "' +
                                   name.replace(/"/g, '""') + '"');
        out[name] = Number(((r.rows || [])[0] || {}).n) || 0;
      }
      log.debug("Leaving riskCounts().");
      return out;
    },
    transaction: async function (fn) {
      log.debug("Entering transaction().");
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const out = await fn(transactionOps(client));
        await client.query('COMMIT');
        log.debug("Leaving transaction().");
        return out;
      } catch (e) {
        log.debug("Caught in transaction(): " + ((e && e.message) || e));
        await client.query('ROLLBACK').catch(function (r) {
          log.debug("Caught in transaction()'s rollback: " +
                    ((r && r.message) || r));
        });
        log.debug("Leaving transaction(). Rolled back.");
        throw e;
      } finally {
        client.release();
      }
    },
    close: function () {
      log.debug("Entering close().");
      log.debug("Leaving close().");
      return pool.end();
    }
  };
  log.debug("Leaving sqlStore().");
  return store;
}

// A failure, tagged, as the Error the command line reports.
// ---------------------------------------------------------------------------
// A DIRECTORY ENTRY IS SEALED (#391 phase 6), and a conversion READS one: it
// decides an entry's tier from its object classes and splits a group's
// members between the tiers. So the source entries are OPENED as they are
// read (`openSourceEntries()`), planned in the clear, and SEALED for the
// tier they are written to (`sealPlannedEntries()`) — the global tier's under
// the service's data keys, a cell's under its own — with the lookup columns
// computed beside them. The plan is sealed in place before anything is
// written, so `verifyGlobal()` compares what was written with itself.
// ---------------------------------------------------------------------------
function openSourceEntries(rows) {
  log.debug("Entering openSourceEntries().");
  const codec = require('./directory_codec').create('cell');
  const out = (rows || []).map(function (row) {
    const attrs = codec.openAttributes(row.dn_key, row.attrs);
    if (attrs === null) {
      throw refusal('STS-CELL-0210', 'the directory entry ' + row.dn_key +
                    ' in the "' + row.realm + '" realm is sealed and does ' +
                    'not open here; nothing was converted.');
    }
    return Object.assign({}, row, { attrs: attrs });
  });
  log.debug("Leaving openSourceEntries(). " + out.length + ".");
  return out;
}

function sealPlannedEntries(rows, tier) {
  log.debug("Entering sealPlannedEntries(). " + tier);
  const codec = require('./directory_codec').create(tier);
  (rows || []).forEach(function (row) {
    const attrs = row.attrs || {};
    const index = codec.index(attrs);
    row.attrs = codec.sealAttributes(row.realm, row.dn_key, attrs);
    row.name_keys = index.nameKeys;
    row.mail_keys = index.mailKeys;
    row.uuid_keys = index.uuidKeys;
    row.class_keys = index.classKeys;
    row.value_keys = index.valueKeys;
    row.attr_names = index.attrNames;
  });
  log.debug("Leaving sealPlannedEntries().");
}

function refusal(code, message) {
  log.debug("Entering refusal().");
  const err = /** @type {any} */ (new Error(errorCodes.tag(code) +
                                            'cell_convert: ' + message));
  err.code = code;
  log.debug("Leaving refusal().");
  return err;
}

// ---------------------------------------------------------------------------
// THE PLAN: what the tiered driver would have written, decided row by row
// from what the cell database holds. Pure, so a dry run and a real one are
// the same decision.
// ---------------------------------------------------------------------------
function planOf(source, cellId, digest, now) {
  log.debug("Entering planOf().");
  const plan = {
    global: /** @type {Object<string, any[]>} */ ({}),
    cellRemove: /** @type {Object<string, any[]>} */ ({}),
    cellUpdate: /** @type {Object<string, any[]>} */ ({ sts_ldap_entries: [] }),
    routing: /** @type {any[]} */ ([]),
    people: 0,
    counts: { directoryGlobal: 0, directoryCell: 0, people: 0, devices: 0,
              groupsSplit: 0, groupHalvesKept: 0, projections: 0 }
  };
  WHOLE_TABLES.forEach(function (table) {
    plan.global[table] = source[table].slice();
    plan.cellRemove[table] = source[table].slice();
  });
  plan.global.sts_minted = source.sts_minted.slice();
  plan.cellRemove.sts_minted = source.sts_minted.slice();
  plan.global.sts_cluster_claims = source.sts_cluster_claims.slice();
  plan.cellRemove.sts_cluster_claims = source.sts_cluster_claims.slice();
  plan.global.sts_ldap_entries = [];
  plan.cellRemove.sts_ldap_entries = [];
  const routes = new Map();
  source.sts_ldap_entries.forEach(function (row) {
    const attrs = row.attrs || {};
    const key = String(row.dn_key);
    // A projection is never written by the tiered driver; a single-cell
    // store has none, and one found is left where it is.
    if (String(row.origin || '').indexOf('projection') === 0) {
      plan.counts.projections += 1;
      return;
    }
    const tier = tiers.directoryTierOf(key, attrs);
    if (tier === 'global') {
      plan.global.sts_ldap_entries.push(row);
      plan.cellRemove.sts_ldap_entries.push(row);
      plan.counts.directoryGlobal += 1;
      return;
    }
    if (tier === 'split') {
      const halves = tiers.splitGroup(attrs);
      plan.global.sts_ldap_entries.push(
        Object.assign({}, row, { attrs: halves.global }));
      plan.counts.groupsSplit += 1;
      if (Object.keys(halves.cell).length) {
        plan.cellUpdate.sts_ldap_entries.push(
          Object.assign({}, row, { attrs: halves.cell }));
        plan.counts.groupHalvesKept += 1;
      } else {
        plan.cellRemove.sts_ldap_entries.push(row);
      }
      return;
    }
    plan.counts.directoryCell += 1;
    if (!tiers.isPersonDn(key)) {
      plan.counts.devices += 1;
      return;
    }
    plan.counts.people += 1;
    routesOf(row, cellId, digest, now).forEach(function (one) {
      routes.set(keyOf('sts_cell_routing', one), one);
    });
  });
  plan.routing = Array.from(routes.values());
  log.debug("Leaving planOf().");
  return plan;
}

// The routing index rows of one person's entry — `indexPeople()`'s two
// claims, made from the same two values under the same digest.
function routesOf(row, cellId, digest, now) {
  log.debug("Entering routesOf().");
  const attrs = row.attrs || {};
  const name = tiered.loginNameOf(row.dn_key, attrs);
  const uuid = tiered.uuidOf(attrs);
  const out = [];
  [['name', name], ['uuid', uuid]].forEach(function (pair) {
    if (!pair[1]) {
      return;
    }
    const made = digest(row.realm, pair[0], pair[1]);
    if (!made) {
      throw refusal('STS-CELL-0207', 'the routing index\'s digest could not ' +
                    'be made: no service key-encryption key is held.');
    }
    out.push({ realm: String(row.realm), kind: pair[0], digest: made,
               cell: cellId, written_at: String(now) });
  });
  log.debug("Leaving routesOf().");
  return out;
}

// What the global database already holds that is not the cell database's:
// realms or keys it lacks or holds differently, or an index row naming
// another cell. Empty when the two are one source.
function differencesOf(source, held, cellId) {
  log.debug("Entering differencesOf().");
  const out = [];
  ['sts_realms', 'sts_keys'].forEach(function (table) {
    const mine = new Map();
    source[table].forEach(function (row) {
      mine.set(keyOf(table, row), contentOf(table, row));
    });
    const theirs = new Map();
    held[table].forEach(function (row) {
      theirs.set(keyOf(table, row), contentOf(table, row));
    });
    theirs.forEach(function (content, key) {
      if (!mine.has(key)) {
        out.push(table + ' "' + key + '" is in the global database and not ' +
                 'in this cell\'s');
      } else if (mine.get(key) !== content) {
        out.push(table + ' "' + key + '" differs between the two');
      }
    });
    mine.forEach(function (content, key) {
      if (!theirs.has(key)) {
        out.push(table + ' "' + key + '" is in this cell\'s database and ' +
                 'not in the global one');
      }
    });
  });
  const others = held.sts_cell_routing.filter(function (row) {
    return String(row.cell) !== cellId;
  });
  if (others.length) {
    out.push(others.length + ' routing index row(s) name another cell ("' +
             others[0].cell + '")');
  }
  log.debug("Leaving differencesOf(). " + out.length);
  return out;
}

// Every planned global row, read back and compared. Answers the rows that
// are missing or differ.
async function verifyGlobal(globalStore, plan, handles, cellId) {
  log.debug("Entering verifyGlobal().");
  const problems = [];
  const tables = Object.keys(plan.global);
  for (const table of tables) {
    const planned = plan.global[table];
    if (!planned.length) {
      continue;
    }
    const filter = table === 'sts_minted' ? { handle: handles }
      : (table === 'sts_cluster_claims'
        ? { scope: tiers.GLOBAL_RUN_SCOPE } : null);
    const found = new Map();
    (await globalStore.rows(table, filter)).forEach(function (row) {
      found.set(keyOf(table, row), contentOf(table, row));
    });
    planned.forEach(function (row) {
      const key = keyOf(table, row);
      if (!found.has(key)) {
        problems.push(table + ' "' + key + '" is missing');
      } else if (found.get(key) !== contentOf(table, row)) {
        problems.push(table + ' "' + key + '" differs from what was copied');
      }
    });
  }
  if (plan.routing.length) {
    const index = new Map();
    (await globalStore.rows('sts_cell_routing')).forEach(function (row) {
      index.set(keyOf('sts_cell_routing', row), String(row.cell));
    });
    plan.routing.forEach(function (row) {
      const at = index.get(keyOf('sts_cell_routing', row));
      if (at === undefined) {
        problems.push('a routing index row is missing');
      } else if (at !== cellId) {
        problems.push('a person here is indexed in cell "' + at + '"');
      }
    });
  }
  log.debug("Leaving verifyGlobal(). " + problems.length);
  return problems;
}

// The counts of the summary line, as text.
function summaryOf(verb, cellId, plan, riskCounts, extra) {
  log.debug("Entering summaryOf().");
  const g = plan.global;
  const risk = Object.keys(riskCounts).map(function (t) {
    return t + ' ' + riskCounts[t];
  }).join(', ');
  const out = 'cell_convert: ' + verb + ' cell "' + cellId + '": GLOBAL ' +
    WHOLE_TABLES.concat(['sts_cluster_claims']).map(function (t) {
      return t + ' ' + g[t].length;
    }).join(', ') + ', sts_ldap_entries ' + g.sts_ldap_entries.length +
    ' (' + plan.counts.directoryGlobal + ' entries, ' +
    plan.counts.groupsSplit + ' group halves), sts_minted ' +
    g.sts_minted.length + ', sts_cell_routing ' + plan.routing.length +
    ' (' + plan.counts.people + ' people); CELL keeps sts_ldap_entries ' +
    (plan.counts.directoryCell + plan.counts.groupHalvesKept) + ' (' +
    plan.counts.people + ' people, ' + plan.counts.devices + ' devices, ' +
    plan.counts.groupHalvesKept + ' group halves' +
    (plan.counts.projections ? ', ' + plan.counts.projections +
      ' projections' : '') + '), sts_minted ' + extra.cellMinted +
    (extra.unclassified ? ' (' + extra.unclassified + ' unclassified)' : '') +
    '; sts_risk_* untouched: ' + (risk || 'none') +
    (extra.deadMembers ? '; ' + extra.deadMembers + ' dead cluster ' +
      'member row(s) of the old deployment forgotten' : '') + '.';
  log.debug("Leaving summaryOf().");
  return out;
}

// ---------------------------------------------------------------------------
// THE CONVERSION. `options`: `cell` and `global` (two stores, `sqlStore()`'s
// shape), `cellId`, `digest(realm, kind, value)`, `dryRun`, `schemaVersion`
// (what both databases must be at), and `now` (the index rows' time, ms).
// Answers `{ state, summary, plan }`, where state is 'converted',
// 'already-converted' or 'dry-run'; rejects with a tagged Error.
// ---------------------------------------------------------------------------
/**
 * Converts a single-cell store into the named cell of a service deployed as
 * cells.
 *
 * @param options - see the block above
 * @returns a promise of `{ state, summary, plan, routingAdded }`
 */
async function convert(options) {
  log.debug("Entering convert().");
  const cell = options.cell;
  const globalStore = options.global;
  const cellId = String(options.cellId || '').trim();
  const digest = options.digest;
  const dryRun = !!options.dryRun;
  const now = Number(options.now) || Date.now();
  if (!cellId) {
    throw refusal('STS-CELL-0200', 'cells.id is empty: name the cell this ' +
                  'store becomes (STS_CELL_ID).');
  }

  // 1. BOTH SCHEMAS AT THIS SERVICE'S VERSION.
  const want = Number(options.schemaVersion);
  let versions;
  try {
    versions = [await cell.schemaVersion(), await globalStore.schemaVersion()];
  } catch (e) {
    log.debug("Caught in convert(): " + ((e && e.message) || e));
    throw refusal('STS-CELL-0208', 'the databases could not be read: ' +
                  ((e && e.message) || e));
  }
  if (versions[0] !== want || versions[1] !== want) {
    throw refusal('STS-CELL-0201', 'the cell database is at schema version ' +
                  versions[0] + ' and the global database at ' + versions[1] +
                  '; this service is at ' + want + '. Run ' +
                  'postgres/schema.sql against both first.');
  }

  // 2. WHAT EACH HOLDS.
  const handles = Object.keys(tiers.GLOBAL_MINTED);
  const source = {};
  const held = {};
  let riskBefore;
  let cellMintedBy;
  try {
    for (const table of WHOLE_TABLES.concat(['sts_ldap_entries'])) {
      source[table] = await cell.rows(table);
    }
    // Opened to be planned (see openSourceEntries()).
    source.sts_ldap_entries = openSourceEntries(source.sts_ldap_entries);
    source.sts_minted = await cell.rows('sts_minted', { handle: handles });
    source.sts_cluster_claims = await cell.rows('sts_cluster_claims',
      { scope: tiers.GLOBAL_RUN_SCOPE });
    for (const table of ['sts_realms', 'sts_keys', 'sts_cell_routing']) {
      held[table] = await globalStore.rows(table);
    }
    held.total = 0;
    for (const table of GLOBAL_TABLES) {
      held.total += await globalStore.count(table);
    }
    riskBefore = await cell.riskCounts();
    cellMintedBy = await cell.countBy('sts_minted', 'handle');
  } catch (e) {
    log.debug("Caught in convert(): " + ((e && e.message) || e));
    throw refusal('STS-CELL-0208', 'the databases could not be read: ' +
                  ((e && e.message) || e));
  }
  let unclassified = 0;
  let cellMinted = 0;
  Object.keys(cellMintedBy).forEach(function (handle) {
    if (!tiers.isClassified(handle)) {
      unclassified += cellMintedBy[handle];
    }
    if (!tiers.isClassified(handle) || tiers.mintedTierOf(handle) === 'cell') {
      cellMinted += cellMintedBy[handle];
    }
  });
  const extra = { cellMinted: cellMinted, unclassified: unclassified,
                  deadMembers: 0 };
  const hasSource = source.sts_realms.length + source.sts_keys.length > 0;

  // 3. WHICH OF THE THREE STATES.
  if (!hasSource) {
    if (!held.total) {
      throw refusal('STS-CELL-0202', 'there is nothing to convert: the cell ' +
                    'database holds no realm and no key, and the global ' +
                    'database is empty. Point persistence.databaseUrl at ' +
                    'the single-cell deployment\'s database.');
    }
    const result = await alreadyConverted(options, source, cellId, digest,
                                          now, dryRun);
    const summary = summaryOf(dryRun ? 'already converted (dry run)'
                                     : 'already converted', cellId,
                              result.plan, riskBefore, extra) +
      ' Routing rows added: ' + result.added + '.';
    log.info(summary);
    log.debug("Leaving convert(). Already converted.");
    return { state: 'already-converted', summary: summary, plan: result.plan,
             routingAdded: result.added };
  }
  if (held.total) {
    const differences = differencesOf(source, held, cellId);
    if (differences.length) {
      throw refusal('STS-CELL-0203', 'the global database already holds ' +
                    'another source\'s data, so this is not the first cell ' +
                    'of a new service: ' + differences.slice(0, 5).join('; ') +
                    (differences.length > 5 ? '; and ' +
                      (differences.length - 5) + ' more' : '') + '. Nothing ' +
                    'was changed.');
    }
    log.info('cell_convert: the global database already holds this cell ' +
             'database\'s realms and keys — an earlier run copied them and ' +
             'did not finish. The copy is made again and the clean-up ' +
             'completed.');
  }

  const plan = planOf(source, cellId, digest, now);
  if (dryRun) {
    const summary = summaryOf('would convert (dry run)', cellId, plan,
                              riskBefore, extra);
    log.info(summary);
    log.debug("Leaving convert(). Dry run.");
    return { state: 'dry-run', summary: summary, plan: plan,
             routingAdded: 0 };
  }

  // Sealed for the tier each is written to (see sealPlannedEntries()).
  sealPlannedEntries(plan.global.sts_ldap_entries, 'service');
  sealPlannedEntries(plan.cellUpdate.sts_ldap_entries, 'cell');

  // 4. COPY — one transaction on the global database.
  try {
    await globalStore.transaction(async function (tx) {
      for (const table of Object.keys(plan.global)) {
        if (plan.global[table].length) {
          await tx.upsert(table, plan.global[table]);
        }
      }
      await tx.insertAbsent('sts_cell_routing', plan.routing);
    });
  } catch (e) {
    log.debug("Caught in convert(): " + ((e && e.message) || e));
    throw refusal('STS-CELL-0204', 'the copy into the global database ' +
                  'failed and was rolled back; the cell database is ' +
                  'unchanged. Run this again once the cause is fixed: ' +
                  ((e && e.message) || e));
  }

  // 5. VERIFY — read back, before anything is taken from the cell.
  let problems;
  try {
    problems = await verifyGlobal(globalStore, plan, handles, cellId);
  } catch (e) {
    log.debug("Caught in convert(): " + ((e && e.message) || e));
    problems = ['the global database could not be read back: ' +
                ((e && e.message) || e)];
  }
  if (problems.length) {
    throw refusal('STS-CELL-0205', 'the global database does not hold what ' +
                  'was copied into it: ' + problems.slice(0, 5).join('; ') +
                  (problems.length > 5 ? '; and ' + (problems.length - 5) +
                    ' more' : '') + '. The cell database is unchanged.');
  }

  // 6. THE CLEAN-UP — one transaction on the cell database, last.
  try {
    await cell.transaction(async function (tx) {
      for (const table of Object.keys(plan.cellRemove)) {
        if (plan.cellRemove[table].length) {
          await tx.remove(table, plan.cellRemove[table]);
        }
      }
      if (plan.cellUpdate.sts_ldap_entries.length) {
        await tx.upsert('sts_ldap_entries', plan.cellUpdate.sts_ldap_entries);
      }
      extra.deadMembers = await tx.forgetDeadMembers();
    });
  } catch (e) {
    log.debug("Caught in convert(): " + ((e && e.message) || e));
    throw refusal('STS-CELL-0206', 'the global database holds the copy, ' +
                  'and taking the global rows out of the cell database ' +
                  'failed and was rolled back. Run this again: it finds the ' +
                  'copy, makes it again and finishes. ' +
                  ((e && e.message) || e));
  }

  let riskAfter = riskBefore;
  try {
    riskAfter = await cell.riskCounts();
  } catch (e) {
    log.debug("Caught in convert(): " + ((e && e.message) || e));
  }
  if (canonical(riskAfter) !== canonical(riskBefore)) {
    // Nothing above writes a risk table; a count that moved means something
    // else wrote the database while this ran, which is said.
    log.warn(errorCodes.tag('STS-CELL-0209') + 'cell_convert: the ' +
             'sts_risk_* row counts changed while the conversion ran (' +
             canonical(riskBefore) + ' before, ' + canonical(riskAfter) +
             ' after). This tool writes none of them; is a service still ' +
             'running against the cell database?');
  }
  const summary = summaryOf('converted', cellId, plan, riskAfter, extra);
  log.info(summary);
  log.debug("Leaving convert(). Converted.");
  return { state: 'converted', summary: summary, plan: plan,
           routingAdded: plan.routing.length };
}

// ---------------------------------------------------------------------------
// A STORE ALREADY CONVERTED: nothing moves. Every person the cell database
// holds is looked for in the index, and one missing is claimed — none on a
// re-run, and the one repair this state can need, since the index is kept at
// the flush on a best-effort basis. A person indexed in ANOTHER cell is
// reported and left alone: a re-home in flight writes the index that way.
// ---------------------------------------------------------------------------
async function alreadyConverted(options, source, cellId, digest, now,
                                dryRun) {
  log.debug("Entering alreadyConverted().");
  const plan = planOf(Object.assign({}, source, {
    sts_minted: [], sts_cluster_claims: []
  }), cellId, digest, now);
  // Nothing global is moved from a converted store — what `planOf()` made of
  // its directory is only its people, whose index rows are checked below.
  // Its groups are the cell halves already, which `planOf()` splits again
  // to no effect. A GLOBAL entry found in a converted cell database is
  // counted and left: the tiered driver never writes one there.
  const leftover = plan.counts.directoryGlobal;
  plan.counts.directoryGlobal = 0;
  plan.counts.groupsSplit = 0;
  if (leftover) {
    log.warn(errorCodes.tag('STS-CELL-0209') + 'cell_convert: the ' +
             'converted cell database holds ' + leftover + ' global-tier ' +
             'directory row(s); they are left as they are.');
  }
  plan.global = { sts_realms: [], sts_appconfig: [], sts_keys: [],
                  sts_used_assertions: [], sts_cluster_secrets: [],
                  sts_cluster_claims: [], sts_ldap_entries: [],
                  sts_minted: [] };
  const index = new Map();
  (await options.global.rows('sts_cell_routing')).forEach(function (row) {
    index.set(keyOf('sts_cell_routing', row), String(row.cell));
  });
  const missing = [];
  let elsewhere = 0;
  plan.routing.forEach(function (row) {
    const at = index.get(keyOf('sts_cell_routing', row));
    if (at === undefined) {
      missing.push(row);
    } else if (at !== cellId) {
      elsewhere += 1;
    }
  });
  if (elsewhere) {
    log.warn(errorCodes.tag('STS-CELL-0209') + 'cell_convert: ' + elsewhere +
             ' routing index row(s) of people this cell database holds name ' +
             'another cell; left as they are (a re-home in flight writes ' +
             'them so).');
  }
  let added = 0;
  if (missing.length && !dryRun) {
    try {
      added = await options.global.transaction(function (tx) {
        return tx.insertAbsent('sts_cell_routing', missing);
      });
    } catch (e) {
      log.debug("Caught in alreadyConverted(): " + ((e && e.message) || e));
      throw refusal('STS-CELL-0204', 'the missing routing index rows could ' +
                    'not be written: ' + ((e && e.message) || e));
    }
  }
  log.debug("Leaving alreadyConverted().");
  return { plan: plan, added: dryRun ? 0 : added, missing: missing.length };
}

// ---------------------------------------------------------------------------
// THE COMMAND LINE: the cell's own settings, read the service's way.
// ---------------------------------------------------------------------------
function optionsOf(argv) {
  log.debug("Entering optionsOf().");
  const out = { dryRun: false };
  for (const arg of argv) {
    if (arg === '--dry-run') {
      out.dryRun = true;
    } else {
      process.stderr.write(errorCodes.tag('STS-CELL-0200') +
                           'cell_convert: unknown argument "' + arg + '". ' +
                           'Usage: node persistence/cell_convert.js ' +
                           '[--dry-run]\n');
      log.debug("Leaving optionsOf(). Refused.");
      return null;
    }
  }
  log.debug("Leaving optionsOf().");
  return out;
}

// The cell's settings, checked as a cell's start checks them.
function checkSettings() {
  log.debug("Entering checkSettings().");
  const config = require('../common/config');
  const cells = require('../common/cells');
  const keystore = require('../common/keystore');
  const secrets = require('../common/secrets');
  if (!cells.isMulti()) {
    throw refusal('STS-CELL-0200', 'cells.id is empty. Configure this ' +
                  'exactly as the cell the store becomes: STS_CELL_ID, the ' +
                  'cell\'s database and the global database.');
  }
  try {
    cells.validate();
  } catch (e) {
    log.debug("Caught in checkSettings(): " + ((e && e.message) || e));
    throw refusal('STS-CELL-0200', 'the cell settings are refused: ' +
                  ((e && e.message) || e));
  }
  if (config.value('persistence.mode') !== 'postgres') {
    throw refusal('STS-CELL-0200', 'persistence.mode is "' +
                  config.value('persistence.mode') + '": a cell\'s store is ' +
                  'two postgres databases.');
  }
  if (!String(config.value('persistence.globalDatabaseUrl') || '').trim()) {
    throw refusal('STS-CELL-0200', 'persistence.globalDatabaseUrl is empty.');
  }
  if (!keystore.persists() || !secrets.configuredFor(secrets.KEK)) {
    throw refusal('STS-CELL-0200', 'the signing keys are not persisted or ' +
                  'no operator key-encryption key is configured ' +
                  '(keys.source, keys.kekProvider); the routing index is ' +
                  'keyed under that key and a cell refuses to start ' +
                  'without it (STS-CELL-0004).');
  }
  log.debug("Leaving checkSettings().");
  return cells.id();
}

// The service key-encryption key, read by the keystore itself, and CHECKED
// by it against the stored key sets: a digest under the wrong key would
// route nobody, with nothing failing.
async function holdKek(cellStore, globalStore) {
  log.debug("Entering holdKek().");
  const keystore = require('../common/keystore');
  let rows = await cellStore.rows('sts_keys');
  if (!rows.length) {
    rows = await globalStore.rows('sts_keys');
  }
  keystore.setStore({
    loadKeys: function () {
      log.debug("Entering loadKeys().");
      log.debug("Leaving loadKeys().");
      return Promise.resolve(rows.map(function (row) {
        return { realm: row.realm, material: row.material };
      }));
    },
    saveKeys: function () {
      log.debug("Entering saveKeys().");
      log.debug("Leaving saveKeys().");
      return Promise.reject(new Error('cell_convert writes no key'));
    }
  });
  try {
    await keystore.start();
  } catch (e) {
    log.debug("Caught in holdKek(): " + ((e && e.message) || e));
    throw refusal('STS-CELL-0207', 'the service key-encryption key could ' +
                  'not be read, or does not open the stored keys: ' +
                  ((e && e.message) || e));
  }
  log.debug("Leaving holdKek().");
}

/**
 * Runs the command line: the settings, the two connections, the key, and
 * the conversion.
 *
 * @param argv - the arguments after the script
 * @returns a promise of the exit code
 */
async function main(argv) {
  log.debug("Entering main().");
  const options = optionsOf(argv);
  if (!options) {
    log.debug("Leaving main(). Usage.");
    return 2;
  }
  let cellStore = null;
  let globalStore = null;
  try {
    const cellId = checkSettings();
    const persistence = require('./persistence');
    let cellConnection;
    let globalConnection;
    try {
      cellConnection = await persistence.databaseConnection();
      globalConnection = await persistence.globalDatabaseConnection();
    } catch (e) {
      log.debug("Caught in main(): " + ((e && e.message) || e));
      throw refusal('STS-CELL-0208', 'the database connections could ' +
                    'not ' +
                    'be made the way the service makes them: ' +
                    ((e && e.message) || e));
    }
    cellStore = sqlStore({ url: cellConnection.url, name: 'cell',
                           verifyTls: cellConnection.verifyTls });
    globalStore = sqlStore({ url: globalConnection.url, name: 'global',
                             verifyTls: globalConnection.verifyTls });
    try {
      await holdKek(cellStore, globalStore);
    } catch (e) {
      log.debug("Caught in main(): " + ((e && e.message) || e));
      if (e && e.code) {
        throw e;
      }
      throw refusal('STS-CELL-0208', 'the databases could not be read: ' +
                    ((e && e.message) || e));
    }
    await convert({
      cell: cellStore, global: globalStore, cellId: cellId,
      digest: persistence.routingDigest, dryRun: options.dryRun,
      schemaVersion: require('./persistence_postgres').SCHEMA_VERSION
    });
    log.debug("Leaving main().");
    return 0;
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    const message = String((e && e.message) || e);
    log.error(/^STS-/.test(message) ? message
              : errorCodes.tag('STS-CELL-0208') + 'cell_convert: ' + message);
    log.debug("Leaving main(). Failed.");
    return 1;
  } finally {
    for (const one of [cellStore, globalStore]) {
      if (one) {
        await one.close().catch(function (e) {
          log.debug("Caught in main()'s close: " + ((e && e.message) || e));
        });
      }
    }
  }
}

// Run when invoked, and export the pieces for the tests.
if (require.main === module) {
  main(process.argv.slice(2)).then(function (code) {
    process.exit(code);
  }, function (e) {
    log.error(errorCodes.tag('STS-CELL-0208') + 'cell_convert: ' +
              ((e && e.stack) || e));
    process.exit(1);
  });
}

/**
 * The one-time conversion of a single-cell store into a cell of a service
 * deployed as cells (#98). A tool: no route.
 * @namespace
 */
module.exports = {
  convert: convert,
  main: main,
  planOf: planOf,
  sqlStore: sqlStore,
  TABLES: TABLES,
  WHOLE_TABLES: WHOLE_TABLES,
  canonical: canonical
};
