// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: store_portable.js
//
// ---------------------------------------------------------------------------
// THE STORE'S SMALLER TABLES WITHOUT POSTGRESQL'S FEATURES (#677, phase 3).
//
// The realm registry and the process-wide settings, the signing keys, the
// change log's own statements, the node snapshots, the used-assertion
// history and the report artifacts: every statement the postgres driver
// sends for them is written here a second time, in builder statements the
// Knex compiler spells for either engine `sql_dialect.js` knows, with each
// native statement's contract re-stated beside it. The driver uses these
// when the engine is not PostgreSQL, OR when `persistence.sqlDialect` is
// `portable`: every statement here runs unchanged against PostgreSQL's
// schema (`tests/store_portable.js` section B proves it), so the
// `cluster-portable` test mode proves them on the reference engine as well.
// The one exception is `replicaLagMs()`, which the driver asks here only on
// an engine that is not PostgreSQL (see it).
//
// THE CONTRACTS ARE THE NATIVE STATEMENTS', AND EACH SAYS HOW IT KEEPS ITS
// OWN:
//
//   * A MERGE INTO A STORED ROW IS A READ UNDER THE ROW'S LOCK, THE MERGE IN
//     JAVASCRIPT, AND A WRITE, in the caller's transaction. PostgreSQL does
//     `saveRealms()`'s override delta (`(stored - cleared) || set`) and its
//     one-way columns inside `ON CONFLICT … DO UPDATE`; MariaDB has no jsonb
//     operators, and `INSERT … ON DUPLICATE KEY UPDATE` reading JSON would
//     be the engine's JSON functions, whose object merge is not jsonb's. The
//     row is locked FOR UPDATE first, so no writer can change it between the
//     read and the write; a row that is not there yet is INSERTed with
//     first-writer-wins, and the loser goes round again and finds it.
//   * A "ONCE" IS AN INSERT THAT DOES NOTHING ON A DUPLICATE KEY (`INSERT
//     IGNORE` on MariaDB, `ON CONFLICT DO NOTHING` on PostgreSQL), and a row
//     written is the race won. `INSERT IGNORE` also turns a value too long
//     for its column into a TRUNCATED one with a warning, so every keyed
//     value is measured first and refused (STS-STORE-0100): a truncated key
//     would be somebody else's key.
//   * AN ASSERTION IS ACCEPTED EXACTLY ONCE because the primary key decides
//     it: an expired row with the key is deleted (only an expired one, so a
//     live claim is never removed), and then the INSERT IGNORE either wrote
//     the row or found one. Twenty-five concurrent claims of one assertion:
//     one accepted (section C).
//   * A DATA-MODIFYING CTE OR `DELETE … RETURNING` IS SEVERAL STATEMENTS IN
//     ONE TRANSACTION: the two report deletes; a snapshot purge, whose rows
//     are read FOR UPDATE and then deleted by name, so what is answered is
//     exactly what was deleted.
//   * A CHANGE ROW IS WRITTEN WHERE THE DRIVER'S WAS, on the connection the
//     caller holds — the directory and minted flushes' transactions
//     included — by `insertChanges()`, which the driver's `recordChanges()`
//     calls for each chunk; the counting, the classification and the nudge
//     stay the driver's. `seq` is AUTO_INCREMENT on MariaDB: one multi-row
//     INSERT is a "simple insert", which `innodb_autoinc_lock_mode` 1 (the
//     default) numbers consecutively, so a transaction's rows are dense
//     exactly as `bigserial`'s are, and as there a rolled-back transaction
//     leaves its numbers unused and a later number can commit first —
//     `persistence_replication.js`'s holes are the answer to both.
//   * A DEADLOCK ON MARIADB IS RUN AGAIN. InnoDB answers concurrent inserts
//     of one key with a deadlock where PostgreSQL waits, and the driver's
//     `withTransaction()` retries PostgreSQL's codes only; every transaction
//     here is safe to run twice, because a rolled-back attempt left nothing.
//
// A LIBRARY: handed the dialect, the pools and the driver's transaction
// helpers; it requires only the error-code table and bunyan, and holds no
// state.
// ---------------------------------------------------------------------------

const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'sts-store-portable',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

// How many times a transaction MariaDB refused with a deadlock or a lock
// timeout is run again.
const TRANSACTION_RETRIES = 8;

// THE KEYED COLUMNS' WIDTHS ON MARIADB (`mariadb/CLAUDE.md`, *Size limits*).
// A value longer than its column is refused there by strict mode, except
// under `INSERT IGNORE`, which truncates it; measured here so that neither
// happens silently.
const WIDTH = {
  realm: 64,
  appconfigKey: 255,
  assertionKey: 512,
  snapshotName: 255,
  jobId: 255
};

// The used-assertion columns a row is read with.
const USED_COLUMNS = ['format', 'used_as', 'issuer', 'identifier',
                      'client_id', 'subject', 'state', 'origin', 'used_at',
                      'spent_at', 'expires_at'];

/**
 * Builds the portable statements over one driver's connections.
 *
 * @param deps - `{ dialect, pool, readPool, withTransaction,
 *   transactionOnce, recordChanges, processId }`: the dialect, the write
 *   and read pools, the driver's fenced transaction helpers and its change
 *   recorder, and a function answering this process's origin
 * @returns the portable operations, each answering what the driver's
 *   PostgreSQL statement answers
 */
function create(deps) {
  log.debug("Entering create().");
  const dialect = deps.dialect;
  const kx = dialect.kx;
  const pool = deps.pool;
  const readPool = deps.readPool || deps.pool;
  const mariadb = dialect.engine !== 'postgres';

  /**
   * Sends one built statement.
   *
   * @param runner - a pool or a held connection
   * @param name - the statement's name
   * @param built - a Knex builder
   * @returns the connection's answer
   */
  function run(runner, name, built) {
    log.debug("Entering run(). " + name);
    log.debug("Leaving run().");
    return dialect.run(runner, 'store.' + name, built);
  }

  /**
   * The rows of an answer.
   *
   * @param result - a connection's answer
   * @returns its rows
   */
  function rows(result) {
    log.debug("Entering rows().");
    log.debug("Leaving rows().");
    return dialect.rowsOf(result);
  }

  /**
   * A JSON column's value as an object: `pg` parses jsonb, and MariaDB's
   * JSON is LONGTEXT, which arrives as its text.
   *
   * @param value - the column as read
   * @returns the value parsed, or null
   */
  function parsed(value) {
    log.debug("Entering parsed().");
    if (typeof value !== 'string') {
      log.debug("Leaving parsed(). Already a value.");
      return value === undefined ? null : value;
    }
    log.debug("Leaving parsed().");
    return JSON.parse(value);
  }

  /**
   * A bigint column as a number, or null where it is NULL.
   *
   * @param value - the column as read (a string from either driver)
   * @returns a number or null
   */
  function numberOrNull(value) {
    log.debug("Entering numberOrNull().");
    log.debug("Leaving numberOrNull().");
    return value === null || value === undefined ? null : Number(value);
  }

  /**
   * Refuses a value too long for its MariaDB column (STS-STORE-0100),
   * rather than let `INSERT IGNORE` truncate it into another row's key.
   * PostgreSQL's columns are `text`, so nothing is measured there.
   *
   * @param what - the table and column, for the message
   * @param value - the value
   * @param width - the column's width in characters
   * @returns the value as a string
   */
  function bounded(what, value, width) {
    log.debug("Entering bounded(). " + what);
    const text = String(value === undefined || value === null ? '' : value);
    if (mariadb && Array.from(text).length > width) {
      log.debug("Leaving bounded(). Too long.");
      throw new Error(errorCodes.tag('STS-STORE-0100') + 'persistence: a ' +
                      'value of ' + Array.from(text).length + ' characters ' +
                      'is longer than ' + what + ' (' + width + ') on ' +
                      'MariaDB, and is refused rather than truncated.');
    }
    log.debug("Leaving bounded().");
    return text;
  }

  /**
   * Runs `attempt()` again when MariaDB refused it with a deadlock or a lock
   * timeout (see the header). A fenced refusal is never run again, and on
   * PostgreSQL the driver's own retry has already run.
   *
   * @param what - a name for the line that says so
   * @param attempt - answers a promise; safe to run twice
   * @returns what `attempt()` answered
   */
  function retrying(what, attempt) {
    log.debug("Entering retrying(). " + what);
    const go = function (left) {
      return attempt().catch(function (err) {
        if (!mariadb || left <= 0 || (err && err.fenced) ||
            !dialect.isRetryable(err)) {
          throw err;
        }
        log.debug("Caught in retrying(): " + ((err && err.message) || err) +
                  "; " + what + " again.");
        return new Promise(function (resolve) {
          setTimeout(resolve, 5 + require('../common/crypto').randomInt(0, 20));
        }).then(function () {
          return go(left - 1);
        });
      });
    };
    log.debug("Leaving retrying().");
    return go(TRANSACTION_RETRIES);
  }

  /**
   * The driver's fenced transaction, run again on a MariaDB deadlock.
   *
   * @param what - a name for the log
   * @param fn - given the held connection
   * @returns what `fn` answered
   */
  function fenced(what, fn) {
    log.debug("Entering fenced(). " + what);
    log.debug("Leaving fenced().");
    return retrying(what, function () {
      return deps.withTransaction(fn);
    });
  }

  /**
   * An UNFENCED transaction on a connection held from the write pool, for
   * what the native driver sent as one statement outside a transaction (a
   * snapshot purge, a report's delete): its atomicity, kept, and no fence
   * it never had.
   *
   * @param what - a name for the log
   * @param fn - given the held connection; answers a promise
   * @returns what `fn` answered
   */
  function unfenced(what, fn) {
    log.debug("Entering unfenced(). " + what);
    log.debug("Leaving unfenced().");
    return retrying(what, function () {
      return pool.connect().then(function (client) {
        return client.query('BEGIN').then(function () {
          return fn(client);
        }).then(function (result) {
          return client.query('COMMIT').then(function () {
            client.release();
            return result;
          });
        }, function (err) {
          return client.query('ROLLBACK').then(function () {
            client.release();
            throw err;
          }, function (rollbackErr) {
            log.warn(errorCodes.tag('STS-STORE-0032') + 'persistence: a ' +
                     'rollback failed (' + ((rollbackErr &&
                     rollbackErr.message) || rollbackErr) + '); the ' +
                     'connection is being discarded.');
            client.release(rollbackErr);
            throw err;
          });
        });
      });
    });
  }

  /**
   * The statement's own clock for a timestamp column (`written_at`): the
   * transaction's start on either engine, as PostgreSQL's `now()` is.
   *
   * @returns a fragment
   */
  function stamp() {
    log.debug("Entering stamp().");
    log.debug("Leaving stamp().");
    return kx.fn.now(6);
  }

  // ===================================================================
  // THE REALM REGISTRY AND THE PROCESS-WIDE SETTINGS
  // ===================================================================

  /**
   * Every realm, oldest first with the never-dated ones before them.
   *
   * @returns the realms, or null for an empty table
   */
  function loadRealms() {
    log.debug("Entering loadRealms().");
    log.debug("Leaving loadRealms().");
    // `NULLS FIRST` written out: Knex's MySQL spelling of
    // `orderBy(col, 'asc', 'first')` drops the column itself and orders
    // by its NULL-ness alone. `(x IS NULL) DESC` reads the same on both.
    return run(readPool, 'loadRealms',
      kx('sts_realms')
        .select('id', 'name', 'description', 'created_at', 'overrides',
                'domain', 'retiring_at')
        .orderByRaw('(?? IS NULL) DESC, ?? ASC, ?? ASC',
                    ['created_at', 'created_at', 'id'])
    ).then(function (result) {
      const found = rows(result);
      if (!found.length) {
        return null;
      }
      return found.map(function (row) {
        return {
          id: row.id,
          name: row.name,
          description: row.description,
          domain: row.domain || '',
          createdAt: numberOrNull(row.created_at),
          overrides: parsed(row.overrides) || {},
          retiringSince: numberOrNull(row.retiring_at)
        };
      });
    });
  }

  /**
   * One realm's row written under its lock, as the native upsert's
   * `ON CONFLICT … DO UPDATE` writes it: the retiring mark, the domain and
   * the creation time kept once set; the name and description replaced
   * only when the delta says so; the overrides replaced whole, or the
   * cleared keys removed and the set ones merged over what is stored.
   *
   * @param client - the transaction's connection
   * @param one - `{ row, name, description, set, cleared, whole }`
   * @returns nothing
   */
  function writeRealm(client, one) {
    log.debug("Entering writeRealm().");
    const row = one.row;
    const id = bounded('sts_realms.id', row.id, WIDTH.realm);
    const retiring = Number(row.retiringSince) > 0
      ? Number(row.retiringSince) : null;
    const attempt = function (left) {
      return run(client, 'saveRealms.lock',
        kx('sts_realms')
          .select('name', 'description', 'created_at', 'overrides',
                  'domain', 'retiring_at')
          .where({ id: id }).forUpdate()
      ).then(function (result) {
        const stored = rows(result)[0];
        if (stored) {
          let overrides;
          if (one.whole) {
            overrides = row.overrides || {};
          } else {
            overrides = Object.assign({}, parsed(stored.overrides) || {});
            (one.cleared || []).forEach(function (key) {
              delete overrides[String(key)];
            });
            Object.assign(overrides, one.set || {});
          }
          /** @type {Object<string, any>} */
          const update = { overrides: dialect.json(overrides) };
          if (one.name) {
            update.name = row.name;
          }
          if (one.description) {
            update.description = row.description;
          }
          if (stored.created_at === null) {
            update.created_at = row.createdAt;
          }
          if (stored.domain === null) {
            update.domain = row.domain || null;
          }
          if (stored.retiring_at === null) {
            update.retiring_at = retiring;
          }
          return run(client, 'saveRealms.update',
            kx('sts_realms').update(update).where({ id: id }));
        }
        return run(client, 'saveRealms.insert',
          kx('sts_realms').insert({
            id: id, name: row.name, description: row.description,
            created_at: row.createdAt,
            overrides: dialect.json(row.overrides || {}),
            domain: row.domain || null, retiring_at: retiring
          }).onConflict('id').ignore()
        ).then(function (inserted) {
          if (dialect.affected(inserted) > 0) {
            return null;
          }
          // Another writer inserted it while this one looked: round again,
          // where the row now exists and is locked.
          if (left <= 0) {
            throw new Error(errorCodes.tag('STS-STORE-0101') + 'the "' + id +
                            '" row of sts_realms was inserted and removed ' +
                            'by other writers while this one waited, ' +
                            'twice; nothing was written.');
          }
          return attempt(left - 1);
        });
      });
    };
    log.debug("Leaving writeRealm().");
    return attempt(1);
  }

  /**
   * `saveRealms()`'s contract: the removed rows deleted and the upserts
   * written, in the order given, with one change row, in one fenced
   * transaction.
   *
   * @param upserts - the delta's upserts
   * @param removed - the ids removed
   * @returns nothing
   */
  function saveRealms(upserts, removed) {
    log.debug("Entering saveRealms().");
    log.debug("Leaving saveRealms().");
    return fenced('saveRealms', function (client) {
      let chain = Promise.resolve();
      removed.forEach(function (id) {
        chain = chain.then(function () {
          return run(client, 'saveRealms.remove',
            kx('sts_realms').where({ id: String(id) }).del());
        });
      });
      upserts.forEach(function (one) {
        chain = chain.then(function () {
          return writeRealm(client, one);
        });
      });
      return chain.then(function () {
        if (!upserts.length && !removed.length) {
          return null;
        }
        return deps.recordChanges(client, [{ kind: 'realms' }]);
      });
    });
  }

  /**
   * Every process-wide override, unwrapped from its `{ raw }`.
   *
   * @returns the map, or null for an empty table
   */
  function loadOverrides() {
    log.debug("Entering loadOverrides().");
    log.debug("Leaving loadOverrides().");
    return run(readPool, 'loadOverrides',
      kx('sts_appconfig').select('key', 'value')
    ).then(function (result) {
      const found = rows(result);
      if (!found.length) {
        return null;
      }
      const out = {};
      found.forEach(function (row) {
        const value = parsed(row.value);
        out[row.key] = value && typeof value === 'object' && 'raw' in value
          ? value.raw : value;
      });
      return out;
    });
  }

  /**
   * `saveOverrides()`'s contract: the cleared keys deleted, the set ones
   * upserted, one change row, one fenced transaction.
   *
   * @param set - the keys set
   * @param cleared - the keys cleared
   * @returns nothing
   */
  function saveOverrides(set, cleared) {
    log.debug("Entering saveOverrides().");
    log.debug("Leaving saveOverrides().");
    return fenced('saveOverrides', function (client) {
      let chain = Promise.resolve();
      if (cleared.length) {
        chain = chain.then(function () {
          return run(client, 'saveOverrides.clear',
            kx('sts_appconfig').whereIn('key', cleared.map(String)).del());
        });
      }
      Object.keys(set).forEach(function (key) {
        chain = chain.then(function () {
          return run(client, 'saveOverrides.set',
            kx('sts_appconfig').insert({
              key: bounded('sts_appconfig.key', key, WIDTH.appconfigKey),
              value: dialect.json({ raw: set[key] })
            }).onConflict('key').merge(['value']));
        });
      });
      return chain.then(function () {
        if (!cleared.length && !Object.keys(set).length) {
          return null;
        }
        return deps.recordChanges(client, [{ kind: 'appconfig' }]);
      });
    });
  }

  // ===================================================================
  // THE KEYS
  // ===================================================================

  /**
   * Every realm's sealed key material.
   *
   * @returns `[{ realm, material }]`
   */
  function loadKeys() {
    log.debug("Entering loadKeys().");
    log.debug("Leaving loadKeys().");
    return run(readPool, 'loadKeys',
      kx('sts_keys').select('realm', 'material')
    ).then(function (result) {
      return rows(result).map(function (row) {
        return { realm: row.realm, material: row.material };
      });
    });
  }

  /**
   * The data-key rows alone, for `keystore.refreshDekRows()`: the whole
   * table is every realm's key set and hierarchy, and that runs before every
   * key-row write (the postgres driver's `loadDekRows()` argues it). A
   * case-insensitive collation may match more than the prefix; the keystore
   * keeps only `dek:` rows either way.
   *
   * @returns `[{ realm, material }]`
   */
  function loadDekRows() {
    log.debug("Entering loadDekRows().");
    log.debug("Leaving loadDekRows().");
    return run(readPool, 'loadDekRows',
      kx('sts_keys').select('realm', 'material')
        .where('realm', 'like', 'dek:%')
    ).then(function (result) {
      return rows(result).map(function (row) {
        return { realm: row.realm, material: row.material };
      });
    });
  }

  /**
   * One realm's sealed key material, or null.
   *
   * @param realmId - the realm
   * @returns the material or null
   */
  function loadKey(realmId) {
    log.debug("Entering loadKey().");
    log.debug("Leaving loadKey().");
    return run(readPool, 'loadKey',
      kx('sts_keys').select('material').where({ realm: String(realmId) })
    ).then(function (result) {
      const row = rows(result)[0];
      return row ? row.material : null;
    });
  }

  /**
   * One realm's key material upserted, with its change row.
   *
   * @param realmId - the realm
   * @param ciphertext - the sealed material
   * @returns nothing
   */
  function saveKeys(realmId, ciphertext) {
    log.debug("Entering saveKeys().");
    log.debug("Leaving saveKeys().");
    return fenced('saveKeys', function (client) {
      return run(client, 'saveKeys',
        kx('sts_keys').insert({
          realm: bounded('sts_keys.realm', realmId, WIDTH.realm),
          material: String(ciphertext), written_at: stamp()
        }).onConflict('realm').merge(['material', 'written_at'])
      ).then(function () {
        return deps.recordChanges(client, [{ kind: 'keys',
                                             realm: realmId }]);
      });
    });
  }

  /**
   * One realm's key material deleted, with a change row when there was
   * one.
   *
   * @param realmId - the realm
   * @returns nothing
   */
  function deleteKeys(realmId) {
    log.debug("Entering deleteKeys().");
    log.debug("Leaving deleteKeys().");
    return fenced('deleteKeys', function (client) {
      return run(client, 'deleteKeys',
        kx('sts_keys').where({ realm: String(realmId) }).del()
      ).then(function (result) {
        if (!dialect.affected(result)) {
          return null;
        }
        return deps.recordChanges(client, [{ kind: 'keys',
                                             realm: realmId }]);
      });
    });
  }

  /**
   * `mergeKeys()`'s contract: the row locked FOR UPDATE, the caller's
   * merge deciding what is written, and a change row only when something
   * moved; a row that is not there is inserted first-writer-wins and the
   * loser goes round again.
   *
   * @param realmId - the realm
   * @param merge - `(current) → next`; `next` equal to `current` or empty
   *   writes nothing
   * @returns `{ written, inserted, material }`
   */
  function mergeKeys(realmId, merge) {
    log.debug("Entering mergeKeys().");
    const id = bounded('sts_keys.realm', realmId, WIDTH.realm);
    log.debug("Leaving mergeKeys().");
    return fenced('mergeKeys', function (client) {
      const lockAndMerge = function () {
        return run(client, 'mergeKeys.lock',
          kx('sts_keys').select('material').where({ realm: id }).forUpdate()
        ).then(function (result) {
          const row = rows(result)[0] || null;
          const current = row ? row.material : null;
          const next = merge(current);
          if (!next || next === current) {
            return { written: false, inserted: false, material: current };
          }
          if (row) {
            return run(client, 'mergeKeys.update',
              kx('sts_keys').update({ material: String(next),
                                      written_at: stamp() })
                .where({ realm: id })
            ).then(function () {
              return deps.recordChanges(client, [{ kind: 'keys',
                                                   realm: id }]);
            }).then(function () {
              return { written: true, inserted: false, material: next };
            });
          }
          return run(client, 'mergeKeys.insert',
            kx('sts_keys').insert({ realm: id, material: String(next),
                                    written_at: stamp() })
              .onConflict('realm').ignore()
          ).then(function (inserted) {
            if (!dialect.affected(inserted)) {
              return null;
            }
            return deps.recordChanges(client, [{ kind: 'keys', realm: id }])
              .then(function () {
                return { written: true, inserted: true, material: next };
              });
          });
        });
      };
      return lockAndMerge().then(function (first) {
        return first || lockAndMerge();
      }).then(function (second) {
        if (!second) {
          throw new Error(errorCodes.tag('STS-STORE-0050') + 'the "' + id +
                          '" row of sts_keys was inserted and removed by ' +
                          'other writers while this one waited, twice; ' +
                          'nothing was written.');
        }
        return second;
      });
    });
  }

  // ===================================================================
  // THE CHANGE LOG
  // ===================================================================

  /**
   * One chunk of change rows, as ONE multi-row INSERT on the caller's
   * connection — inside whatever transaction it holds.
   *
   * @param client - the connection the caller holds
   * @param origin - this process's origin
   * @param chunk - `[{ kind, realm, key }]`
   * @returns the connection's answer
   */
  function insertChanges(client, origin, chunk) {
    log.debug("Entering insertChanges(). rows=" + chunk.length);
    log.debug("Leaving insertChanges().");
    return run(client, 'recordChanges',
      kx('sts_changes').insert(chunk.map(function (row) {
        return { origin: String(origin), kind: String(row.kind),
                 realm: String(row.realm || ''), key: String(row.key || '') };
      })));
  }

  /**
   * The newest change another process wrote that a barrier waits for.
   *
   * @returns the sequence number, 0 for none
   */
  function latestBlockingChangeSeq() {
    log.debug("Entering latestBlockingChangeSeq().");
    log.debug("Leaving latestBlockingChangeSeq().");
    return run(pool, 'latestBlockingChangeSeq',
      kx('sts_changes')
        .select(kx.raw('COALESCE(MAX(??), 0) AS ??', ['seq', 'seq']))
        .whereNot('kind', 'minted-own')
        .whereNot('origin', String(deps.processId()))
    ).then(function (result) {
      return Number((rows(result)[0] || {}).seq) || 0;
    });
  }

  /**
   * The rows below a sequence number, deleted.
   *
   * @param beforeSeq - the bound
   * @returns how many went
   */
  function purgeChanges(beforeSeq) {
    log.debug("Entering purgeChanges().");
    log.debug("Leaving purgeChanges().");
    return run(pool, 'purgeChanges',
      kx('sts_changes').where('seq', '<', Number(beforeSeq) || 0).del()
    ).then(function (result) {
      return dialect.affected(result);
    });
  }

  /**
   * A replica's lag, on MariaDB: null, which is the method's answer for
   * "not a replica, or the question cannot be asked". The engine's answer
   * is `SHOW REPLICA STATUS`, which needs the REPLICA MONITOR privilege the
   * service's least-privileged account does not hold (`mariadb/schema.sql`),
   * and no deployment of this engine has a replica tier.
   *
   * @returns null
   */
  function replicaLagMs() {
    log.debug("Entering replicaLagMs().");
    log.debug("Leaving replicaLagMs(). Not asked on this engine.");
    return Promise.resolve(null);
  }

  // ===================================================================
  // NODE SNAPSHOTS
  // ===================================================================

  /**
   * This node's snapshot, upserted at the database's clock.
   *
   * @param name - the snapshot's name
   * @param nodeId - the node
   * @param body - the snapshot
   * @returns `{ written: true }`
   */
  function putNodeSnapshot(name, nodeId, body) {
    log.debug("Entering putNodeSnapshot().");
    log.debug("Leaving putNodeSnapshot().");
    return run(pool, 'putNodeSnapshot',
      kx('sts_node_snapshots').insert({
        name: bounded('sts_node_snapshots.name', name, WIDTH.snapshotName),
        node_id: String(nodeId || ''), taken_at: dialect.now(),
        body: dialect.json(body || {})
      }).onConflict('name').merge(['node_id', 'taken_at', 'body'])
    ).then(function () {
      return { written: true };
    });
  }

  /**
   * Every snapshot older than `olderThanMs` whose name is not kept, deleted
   * and answered: read FOR UPDATE and deleted by name in one transaction,
   * `DELETE … RETURNING`'s answer.
   *
   * @param olderThanMs - the age
   * @param keep - the names kept (never empty: the driver refuses that)
   * @returns `[{ name, takenAt }]`
   */
  function purgeNodeSnapshots(olderThanMs, keep) {
    log.debug("Entering purgeNodeSnapshots().");
    log.debug("Leaving purgeNodeSnapshots().");
    return unfenced('purgeNodeSnapshots', function (client) {
      return run(client, 'purgeNodeSnapshots.read',
        kx('sts_node_snapshots').select('name', 'taken_at')
          .where('taken_at', '<', dialect.now(Number(olderThanMs), '-'))
          .whereNotIn('name', keep).orderBy('name').forUpdate()
      ).then(function (result) {
        const found = rows(result);
        if (!found.length) {
          return [];
        }
        return run(client, 'purgeNodeSnapshots.delete',
          kx('sts_node_snapshots').whereIn('name', found.map(function (row) {
            return row.name;
          })).del()
        ).then(function () {
          return found.map(function (row) {
            return { name: row.name, takenAt: Number(row.taken_at) };
          });
        });
      });
    });
  }

  /**
   * Every node's latest snapshot, at most 64, with the database's clock.
   *
   * @returns `{ now, rows }`
   */
  function nodeSnapshots() {
    log.debug("Entering nodeSnapshots().");
    log.debug("Leaving nodeSnapshots().");
    return Promise.all([
      run(pool, 'nodeSnapshots',
        kx('sts_node_snapshots').select('name', 'node_id', 'taken_at', 'body')
          .orderBy('name').limit(64)),
      run(pool, 'nodeSnapshots.now',
        kx.select(kx.raw(dialect.nowText + ' AS ??', ['now'])))
    ]).then(function (answers) {
      return {
        now: Number((rows(answers[1])[0] || {}).now) || 0,
        rows: rows(answers[0]).map(function (row) {
          return { name: row.name, nodeId: row.node_id,
                   takenAt: Number(row.taken_at),
                   body: parsed(row.body) || {} };
        })
      };
    });
  }

  // ===================================================================
  // THE USED-ASSERTION HISTORY
  // ===================================================================

  /**
   * One stored row in the shape the caller reads.
   *
   * @param row - the row
   * @returns the record
   */
  function usedRowFrom(row) {
    log.debug("Entering usedRowFrom().");
    log.debug("Leaving usedRowFrom().");
    return {
      format: row.format, use: row.used_as, issuer: row.issuer,
      identifier: row.identifier, clientId: row.client_id,
      subject: row.subject, state: row.state, origin: row.origin,
      usedAt: Number(row.used_at) || 0, spentAt: Number(row.spent_at) || 0,
      expiresAt: Number(row.expires_at) || 0
    };
  }

  /**
   * The realm's live rows, counted.
   *
   * @param realm - the realm
   * @param now - the caller's clock
   * @returns a promise of the count
   */
  function liveCount(realm, now) {
    log.debug("Entering liveCount().");
    log.debug("Leaving liveCount().");
    return run(pool, 'usedAssertions.live',
      kx('sts_used_assertions').count({ live: '*' })
        .where({ realm: String(realm) }).where('expires_at', '>=', now)
    ).then(function (result) {
      return Number((rows(result)[0] || {}).live) || 0;
    });
  }

  /**
   * THE CLAIM, `claimUsedAssertion()`'s contract (see the header): an
   * expired row with this key deleted, the realm's live rows counted
   * against the cap, then an insert that does nothing on a duplicate key —
   * the primary key's lock is what makes it exactly once. The cap's count
   * is not under a lock, as the native statement's is not: it bounds a
   * table, and the key bounds a replay. Where the native statement would
   * leave an expired row in place because the cap refused, this has
   * already deleted it, which the sweep would have.
   *
   * @param row - the row to claim
   * @param opts - `{ now, cap }`
   * @returns `{ claimed: true }` or `{ claimed: false, live, existing }`
   */
  function claimUsedAssertion(row, opts) {
    log.debug("Entering claimUsedAssertion().");
    const now = Number(opts.now);
    const cap = Number(opts.cap);
    const realm = bounded('sts_used_assertions.realm', row.realm,
                          WIDTH.realm);
    const key = bounded('sts_used_assertions.key', row.key,
                        WIDTH.assertionKey);
    const refusal = function () {
      return Promise.all([
        run(pool, 'claimUsedAssertion.existing',
          kx('sts_used_assertions').select(USED_COLUMNS)
            .where({ realm: realm, key: key }).where('expires_at', '>=', now)),
        liveCount(realm, now)
      ]).then(function (answers) {
        const found = rows(answers[0])[0];
        return { claimed: false, live: answers[1],
                 existing: found ? usedRowFrom(found) : null };
      });
    };
    log.debug("Leaving claimUsedAssertion().");
    return run(pool, 'claimUsedAssertion.expired',
      kx('sts_used_assertions').where({ realm: realm, key: key })
        .where('expires_at', '<', now).del()
    ).then(function () {
      return liveCount(realm, now);
    }).then(function (live) {
      if (live >= cap) {
        return null;
      }
      return run(pool, 'claimUsedAssertion.insert',
        kx('sts_used_assertions').insert({
          realm: realm, key: key, format: String(row.format),
          used_as: String(row.use), issuer: String(row.issuer),
          identifier: String(row.identifier),
          client_id: String(row.clientId || ''),
          subject: String(row.subject || ''), state: String(row.state),
          reservation: String(row.reservation),
          origin: String(row.origin || ''), used_at: Number(row.usedAt),
          spent_at: Number(row.spentAt) || 0,
          expires_at: Number(row.expiresAt)
        }).onConflict(['realm', 'key']).ignore());
    }).then(function (inserted) {
      if (inserted && dialect.affected(inserted) > 0) {
        return { claimed: true };
      }
      return refusal();
    });
  }

  /**
   * A reservation settled: `spent`, or deleted while still `reserved`,
   * both pinned to the reservation.
   *
   * @returns how many rows it touched
   */
  function settleUsedAssertion(realm, key, reservation, spent, at) {
    log.debug("Entering settleUsedAssertion().");
    const where = { realm: String(realm), key: String(key),
                    reservation: String(reservation) };
    log.debug("Leaving settleUsedAssertion().");
    return (spent
      ? run(pool, 'settleUsedAssertion.spent',
          kx('sts_used_assertions')
            .update({ state: 'spent', spent_at: Number(at) }).where(where))
      : run(pool, 'settleUsedAssertion.released',
          kx('sts_used_assertions').where(where)
            .where({ state: 'reserved' }).del())
    ).then(function (result) {
      return dialect.affected(result);
    });
  }

  /**
   * One live row by its key, or null.
   *
   * @returns the record or null
   */
  function findUsedAssertion(realm, key, nowMs) {
    log.debug("Entering findUsedAssertion().");
    log.debug("Leaving findUsedAssertion().");
    return run(pool, 'findUsedAssertion',
      kx('sts_used_assertions').select(USED_COLUMNS)
        .where({ realm: String(realm), key: String(key) })
        .where('expires_at', '>=', Number(nowMs))
    ).then(function (result) {
      const row = rows(result)[0];
      return row ? usedRowFrom(row) : null;
    });
  }

  /**
   * The list's filter, applied to a builder: an empty filter is no
   * condition (the native `($n = '' OR …)`), and the search is a
   * case-blind SUBSTRING by `POSITION`, which both engines have, so that a
   * `%` or `_` in a jti is a character and not a pattern (the native
   * statement's `strpos`, which MariaDB lacks).
   *
   * @param built - the builder
   * @param realm - the realm
   * @param o - the options
   * @returns the builder
   */
  function listFilter(built, realm, o) {
    log.debug("Entering listFilter().");
    built.where({ realm: String(realm) })
      .where('expires_at', '>=', Number(o.now));
    if (o.format) {
      built.where({ format: String(o.format) });
    }
    if (o.use) {
      built.where({ used_as: String(o.use) });
    }
    if (o.state) {
      built.where({ state: String(o.state) });
    }
    if (o.q) {
      built.whereRaw('POSITION(LOWER(?) IN LOWER(CONCAT_WS(\' \', ??, ??, ' +
                     '??, ??))) > 0',
                     [String(o.q), 'issuer', 'identifier', 'client_id',
                      'subject']);
    }
    log.debug("Leaving listFilter().");
    return built;
  }

  /**
   * One page of a realm's unexpired rows, newest first, with the count that
   * matched and the realm's live total.
   *
   * @returns `{ rows, total, live }`
   */
  function listUsedAssertions(realm, opts) {
    log.debug("Entering listUsedAssertions().");
    const o = opts || {};
    log.debug("Leaving listUsedAssertions().");
    return Promise.all([
      run(pool, 'listUsedAssertions.rows',
        listFilter(kx('sts_used_assertions').select(USED_COLUMNS), realm, o)
          .orderBy('used_at', 'desc').limit(Number(o.limit) || 50)
          .offset(Number(o.offset) || 0)),
      run(pool, 'listUsedAssertions.total',
        listFilter(kx('sts_used_assertions').count({ total: '*' }), realm,
                   o)),
      liveCount(realm, Number(o.now))
    ]).then(function (answers) {
      return {
        rows: rows(answers[0]).map(usedRowFrom),
        total: Number((rows(answers[1])[0] || {}).total) || 0,
        live: answers[2]
      };
    });
  }

  /**
   * The expired rows, deleted.
   *
   * @returns how many went
   */
  function purgeUsedAssertions(nowMs) {
    log.debug("Entering purgeUsedAssertions().");
    log.debug("Leaving purgeUsedAssertions().");
    return run(pool, 'purgeUsedAssertions',
      kx('sts_used_assertions').where('expires_at', '<', Number(nowMs)).del()
    ).then(function (result) {
      return dialect.affected(result);
    });
  }

  /**
   * A realm's rows, deleted.
   *
   * @returns how many went
   */
  function removeUsedAssertions(realm) {
    log.debug("Entering removeUsedAssertions().");
    log.debug("Leaving removeUsedAssertions().");
    return run(pool, 'removeUsedAssertions',
      kx('sts_used_assertions').where({ realm: String(realm) }).del()
    ).then(function (result) {
      return dialect.affected(result);
    });
  }

  // ===================================================================
  // REPORT ARTIFACTS (bytea on PostgreSQL, LONGBLOB on MariaDB)
  // ===================================================================

  /**
   * The artifact row as a builder: an upsert, so a retry of a job replaces
   * its artifact.
   *
   * @param row - `{ realm, jobId, sha256, mediaType, createdAt }`
   * @param bytes - the bytes stored in the row
   * @returns the builder
   */
  function artifactUpsert(row, bytes) {
    log.debug("Entering artifactUpsert().");
    log.debug("Leaving artifactUpsert().");
    return kx('sts_report_artifacts').insert({
      realm: bounded('sts_report_artifacts.realm', row.realm, WIDTH.realm),
      job_id: bounded('sts_report_artifacts.job_id', row.jobId, WIDTH.jobId),
      bytes: bytes, sha256: String(row.sha256),
      media_type: String(row.mediaType), created_at: Number(row.createdAt)
    }).onConflict(['realm', 'job_id'])
      .merge(['bytes', 'sha256', 'media_type', 'created_at']);
  }

  /**
   * A finished report's bytes, upserted.
   *
   * @returns the connection's answer
   */
  function putReportArtifact(row) {
    log.debug("Entering putReportArtifact().");
    log.debug("Leaving putReportArtifact().");
    return run(pool, 'putReportArtifact', artifactUpsert(row, row.bytes));
  }

  /**
   * A finished report's pieces and the row that counts them, in ONE fenced
   * transaction run once (the pieces are an async iterable, read once).
   *
   * @returns how many pieces were written
   */
  function putReportArtifactPieces(row, pieces) {
    log.debug("Entering putReportArtifactPieces().");
    const where = { realm: String(row.realm), job_id: String(row.jobId) };
    log.debug("Leaving putReportArtifactPieces().");
    return deps.transactionOnce(async function (client) {
      await run(client, 'putReportArtifactPieces.clear',
        kx('sts_report_artifact_pieces').where(where).del());
      let seq = 0;
      for await (const piece of pieces) {
        await run(client, 'putReportArtifactPieces.piece',
          kx('sts_report_artifact_pieces').insert(Object.assign({}, where, {
            seq: seq, bytes: piece
          })));
        seq += 1;
      }
      const marker = Buffer.from(String(row.prefix) + seq + ':' +
        Number(row.size), 'utf8');
      await run(client, 'putReportArtifactPieces.row',
        artifactUpsert(row, marker));
      return seq;
    });
  }

  /**
   * One piece's bytes, or null.
   *
   * @returns a Buffer or null
   */
  function getReportArtifactPiece(key) {
    log.debug("Entering getReportArtifactPiece().");
    log.debug("Leaving getReportArtifactPiece().");
    return run(pool, 'getReportArtifactPiece',
      kx('sts_report_artifact_pieces').select('bytes')
        .where({ realm: String(key.realm), job_id: String(key.jobId),
                 seq: Number(key.seq) })
    ).then(function (result) {
      const found = rows(result)[0];
      return found ? found.bytes : null;
    });
  }

  /**
   * The artifact row, or null.
   *
   * @returns `{ bytes, sha256, mediaType, createdAt }` or null
   */
  function getReportArtifact(key) {
    log.debug("Entering getReportArtifact().");
    log.debug("Leaving getReportArtifact().");
    return run(pool, 'getReportArtifact',
      kx('sts_report_artifacts')
        .select('bytes', 'sha256', 'media_type', 'created_at')
        .where({ realm: String(key.realm), job_id: String(key.jobId) })
    ).then(function (result) {
      const found = rows(result)[0];
      if (!found) {
        return null;
      }
      return { bytes: found.bytes, sha256: found.sha256,
               mediaType: found.media_type,
               createdAt: Number(found.created_at) };
    });
  }

  /**
   * The pieces and the row deleted together: the native data-modifying CTE
   * as two deletes in one transaction, so neither is left without the
   * other.
   *
   * @returns the row delete's answer
   */
  function deleteReportArtifact(key) {
    log.debug("Entering deleteReportArtifact().");
    const where = { realm: String(key.realm), job_id: String(key.jobId) };
    log.debug("Leaving deleteReportArtifact().");
    return unfenced('deleteReportArtifact', function (client) {
      return run(client, 'deleteReportArtifact.pieces',
        kx('sts_report_artifact_pieces').where(where).del()
      ).then(function () {
        return run(client, 'deleteReportArtifact.row',
          kx('sts_report_artifacts').where(where).del());
      });
    });
  }

  log.debug("Leaving create().");
  return {
    loadRealms: loadRealms,
    saveRealms: saveRealms,
    loadOverrides: loadOverrides,
    saveOverrides: saveOverrides,
    loadKeys: loadKeys,
    loadDekRows: loadDekRows,
    loadKey: loadKey,
    saveKeys: saveKeys,
    deleteKeys: deleteKeys,
    mergeKeys: mergeKeys,
    insertChanges: insertChanges,
    latestBlockingChangeSeq: latestBlockingChangeSeq,
    purgeChanges: purgeChanges,
    replicaLagMs: replicaLagMs,
    putNodeSnapshot: putNodeSnapshot,
    purgeNodeSnapshots: purgeNodeSnapshots,
    nodeSnapshots: nodeSnapshots,
    claimUsedAssertion: claimUsedAssertion,
    settleUsedAssertion: settleUsedAssertion,
    findUsedAssertion: findUsedAssertion,
    listUsedAssertions: listUsedAssertions,
    purgeUsedAssertions: purgeUsedAssertions,
    removeUsedAssertions: removeUsedAssertions,
    putReportArtifact: putReportArtifact,
    putReportArtifactPieces: putReportArtifactPieces,
    getReportArtifactPiece: getReportArtifactPiece,
    getReportArtifact: getReportArtifact,
    deleteReportArtifact: deleteReportArtifact
  };
}

module.exports = {
  create: create,
  // The same factory under a name that does not read as a call of the
  // driver's own `create()` (`tests/no_periodic_timers.js` treats a
  // function that calls its own name as one that repeats).
  forDriver: create,
  WIDTH: WIDTH
};
