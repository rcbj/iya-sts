// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cluster_portable.js
//
// ---------------------------------------------------------------------------
// THE CLUSTER'S STATEMENTS WITHOUT POSTGRESQL'S FEATURES (#677, phase 2).
//
// Every coordination statement the postgres driver sends that leans on
// something only PostgreSQL has — `INSERT … ON CONFLICT … DO UPDATE … WHERE`
// with `RETURNING`, data-modifying CTEs, `pg_advisory_xact_lock`,
// `split_part`, `xmax`, `unnest` — has its contract written down here a
// second time, in statements the Knex builder compiles for any engine
// `sql_dialect.js` knows. The postgres driver uses these when the engine is
// not PostgreSQL, OR when `persistence.sqlDialect` is `portable`: that is
// how the suite proves MariaDB's code on the reference engine before a
// second database exists (rcbj on #677, 2026-11-03).
//
// THE CONTRACTS ARE THE SAME, AND EACH ONE SAYS HOW IT KEEPS ITS OWN:
//
//   * A "ONCE" IS AN INSERT THAT DOES NOTHING ON A DUPLICATE KEY. `INSERT …
//     ON CONFLICT DO NOTHING` (PostgreSQL) and `INSERT IGNORE` (MariaDB) both
//     answer how many rows they wrote and neither aborts the transaction, so
//     a claim is "delete my scope's row if it has expired, then insert or do
//     nothing", and a row written is a claim won. The delete takes only an
//     EXPIRED row, so it can never remove a claim somebody else just won.
//   * A VALUE THAT ONLY RISES (counters, change readers) is an UPDATE guarded
//     by the comparison, then an insert-or-nothing, then the UPDATE again for
//     the writer that raced the insert. Three statements at most, each
//     atomic on its own row.
//   * A COUNT THAT MUST BE DISTINCT PER CALLER (the rate-limit windows, the
//     budgets) is a transaction: the UPDATE takes the row lock, and the
//     read in the same transaction sees its own write and nobody else's
//     until COMMIT. Forty concurrent failures against a limit of five still
//     get counts one to forty.
//   * AN ASSIGNMENT LIST IS WRITTEN IN AN ORDER BOTH ENGINES READ THE SAME.
//     PostgreSQL evaluates every `SET` expression against the old row;
//     MariaDB evaluates them left to right and a later one sees an earlier
//     one's NEW value. So a column a CASE reads is assigned AFTER the CASE
//     (a lease's `holder` last).
//   * THE JOIN LOCK IS A ROW (`sts_cluster_locks`), locked FOR UPDATE in the
//     joining transaction. A transaction-scoped advisory lock is what
//     PostgreSQL offers; MariaDB's `GET_LOCK()` belongs to the session and
//     outlives a rolled-back transaction, which is the wrong shape. A row
//     lock ends with its transaction on every engine, and a process that dies
//     holding one releases it with its connection.
//
// NOTHING HERE STARTS A TRANSACTION ON THE LIVENESS CONNECTION. It is one
// connection that the heartbeat, the leases and the origin renewal share,
// and a BEGIN on it would sweep another caller's statement into this one's
// transaction. Every statement sent there is a single autocommit statement.
//
// A LIBRARY: handed the dialect, the pools and the driver's helpers; it
// requires only the error-code table and bunyan, and holds no state.
// ---------------------------------------------------------------------------

const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'sts-cluster-portable',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

// How many times a value that only rises re-asks after losing a race to an
// insert. Two is enough: the second UPDATE finds the row the race made.
const RACE_RETRIES = 3;
// How many times a transaction the engine refused with a deadlock or a lock
// timeout is run again (see inTransaction()).
const TRANSACTION_RETRIES = 8;

/**
 * Builds the portable statements over one driver's connections.
 *
 * @param deps - `{ dialect, pool, tallyPool, live, processId, originScope }`:
 *   the dialect, the write pool, the tally pool, the liveness runner, a
 *   function answering this process's origin, and the origin claims' scope
 * @returns the portable operations, each answering what the driver's
 *   PostgreSQL statement answers
 */
function create(deps) {
  log.debug("Entering create().");
  const dialect = deps.dialect;
  const kx = dialect.kx;
  const pool = deps.pool;
  const tallyPool = deps.tallyPool || deps.pool;
  const live = deps.live;
  // This process's origin, ASKED each time: `adoptOrigin()` replaces it.
  const processId = deps.processId;
  const originScope = deps.originScope;

  /**
   * Sends one built statement.
   *
   * @param runner - a pool, a held connection or the liveness runner
   * @param name - the statement's name
   * @param built - a Knex builder
   * @returns the connection's answer
   */
  function run(runner, name, built) {
    log.debug("Entering run(). " + name);
    log.debug("Leaving run().");
    return dialect.run(runner, 'portable.' + name, built);
  }

  /**
   * Runs `fn(client)` inside BEGIN/COMMIT on a connection held from `from`,
   * rolling back on any failure. Not fenced: what runs here is a claim or a
   * count, which the driver never fenced either.
   *
   * @param from - a pool with `connect()`
   * @param fn - given the held connection; answers a promise
   * @returns what `fn` answered
   */
  function inTransaction(from, fn) {
    log.debug("Entering inTransaction().");
    // A DEADLOCK OR A LOCK TIMEOUT IS RUN AGAIN, a few times with a jittered
    // pause (#677): InnoDB answers concurrent inserts of one key that way
    // where PostgreSQL waits, and the engine's own advice is to restart the
    // transaction. Everything a portable transaction does is safe to run
    // twice, because a rolled-back attempt left nothing.
    const attempt = function (left) {
      return once().catch(function (err) {
        if (left <= 0 || !dialect.isRetryable(err)) {
          throw err;
        }
        log.debug("Caught in inTransaction(): " + ((err && err.message) ||
                  err) + "; again.");
        return new Promise(function (resolve) {
          setTimeout(resolve, 5 + require('../common/crypto').randomInt(0, 20));
        }).then(function () {
          return attempt(left - 1);
        });
      });
    };
    const once = function () {
      return oneTransaction(from, fn);
    };
    log.debug("Leaving inTransaction().");
    return attempt(TRANSACTION_RETRIES);
  }

  /**
   * One attempt of a transaction on a held connection.
   *
   * @param from - a pool with `connect()`
   * @param fn - given the held connection; answers a promise
   * @returns what `fn` answered
   */
  function oneTransaction(from, fn) {
    log.debug("Entering oneTransaction().");
    log.debug("Leaving oneTransaction().");
    return from.connect().then(function (client) {
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
  }

  /**
   * The first row of an answer, or null.
   *
   * @param result - a connection's answer
   * @returns a row or null
   */
  function first(result) {
    log.debug("Entering first().");
    log.debug("Leaving first().");
    return dialect.rowsOf(result)[0] || null;
  }

  /**
   * The key columns of a scoped row.
   *
   * @param scope - the row's scope
   * @param realmId - its realm, '' for none
   * @param key - its key
   * @returns the where-object
   */
  function at(scope, realmId, key) {
    log.debug("Entering at().");
    log.debug("Leaving at().");
    return { scope: String(scope), realm: String(realmId || ''),
             key: String(key) };
  }

  // ===================================================================
  // CLAIMS
  // ===================================================================

  /**
   * One claim on one key: `claimOnce()`'s contract.
   *
   * @param scope - the claim's scope
   * @param realmId - its realm
   * @param key - its key
   * @param opts - `{ ttlMs, reservation, origin }`
   * @returns `{ claimed, claimedAt, expiresAt }` or `{ claimed: false,
   *   existing }`
   */
  function claimOnce(scope, realmId, key, opts) {
    log.debug("Entering claimOnce(). scope=" + scope);
    const o = opts || {};
    const ttlMs = Math.max(1, Math.floor(Number(o.ttlMs) || 0));
    const reservation = String(o.reservation || '');
    const claimant = o.origin ? String(o.origin) : processId();
    const where = at(scope, realmId, key);
    log.debug("Leaving claimOnce().");
    return run(pool, 'claimOnce.expired',
      kx('sts_cluster_claims').where(where)
        .where('expires_at', '<=', dialect.now()).del()
    ).then(function () {
      return run(pool, 'claimOnce.insert',
        kx('sts_cluster_claims').insert(Object.assign({}, where, {
          reservation: reservation, origin: claimant,
          claimed_at: dialect.now(), expires_at: dialect.now(ttlMs)
        })).onConflict(['scope', 'realm', 'key']).ignore());
    }).then(function (inserted) {
      const won = dialect.affected(inserted) > 0;
      return run(pool, 'claimOnce.read',
        kx('sts_cluster_claims')
          .select('origin', 'reservation', 'claimed_at', 'expires_at')
          .where(where)
      ).then(function (found) {
        const row = first(found);
        if (won && row && row.reservation === reservation) {
          return { claimed: true, claimedAt: Number(row.claimed_at),
                   expiresAt: Number(row.expires_at) };
        }
        return { claimed: false, existing: row ? {
          origin: row.origin,
          claimedAt: Number(row.claimed_at),
          expiresAt: Number(row.expires_at)
        } : null };
      });
    });
  }

  /**
   * Several claims under one reservation, all or none: `claimMany()`'s
   * contract. In (scope, key) order, which every claimant uses, inside one
   * transaction; a key held live by another is written as nothing, and if
   * any was, the whole transaction is rolled back.
   *
   * @param rows - `[{ scope, key }]`
   * @param realmId - their realm
   * @param opts - `{ ttlMs, reservation, origin }`
   * @returns `{ claimed: true, claimedAt }`, or `{ claimed: false, refused,
   *   partial? }` with `refused` the index in `rows` of the first refused
   */
  function claimMany(rows, realmId, opts) {
    log.debug("Entering claimMany(). rows=" + (rows || []).length);
    const o = opts || {};
    const ttlMs = Math.max(1, Math.floor(Number(o.ttlMs) || 0));
    const reservation = String(o.reservation || '');
    const claimant = o.origin ? String(o.origin) : processId();
    const list = (rows || []).map(function (row, index) {
      return { scope: String(row.scope), key: String(row.key), index: index };
    });
    const ordered = list.slice().sort(function (a, b) {
      return a.scope < b.scope ? -1 : a.scope > b.scope ? 1
        : a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
    });
    // A refusal marker that rolls the transaction back and carries what it
    // learnt out of it.
    const PARTIAL = new Error('sts_cluster_claims: a portable claim was ' +
                              'refused');
    let taken = 0;
    let refused = -1;
    log.debug("Leaving claimMany().");
    return inTransaction(pool, function (client) {
      let chain = Promise.resolve();
      ordered.forEach(function (row) {
        chain = chain.then(function () {
          const where = at(row.scope, realmId, row.key);
          return run(client, 'claimMany.expired',
            kx('sts_cluster_claims').where(where)
              .where('expires_at', '<=', dialect.now()).del()
          ).then(function () {
            return run(client, 'claimMany.insert',
              kx('sts_cluster_claims').insert(Object.assign({}, where, {
                reservation: reservation, origin: claimant,
                claimed_at: dialect.now(), expires_at: dialect.now(ttlMs)
              })).onConflict(['scope', 'realm', 'key']).ignore());
          }).then(function (inserted) {
            if (dialect.affected(inserted) > 0) {
              taken += 1;
            } else if (refused < 0 || row.index < refused) {
              refused = row.index;
            }
          });
        });
      });
      return chain.then(function () {
        if (refused >= 0) {
          throw PARTIAL;
        }
        return run(client, 'claimMany.when',
          kx('sts_cluster_claims').max({ claimed_at: 'claimed_at' })
            .where({ realm: String(realmId || ''),
                     reservation: reservation }));
      });
    }).then(function (answer) {
      const row = first(answer) || {};
      return { claimed: true, claimedAt: Number(row.claimed_at) || 0 };
    }, function (err) {
      if (err !== PARTIAL) {
        throw err;
      }
      log.debug("Caught in claimMany(): refused at " + refused);
      return taken > 0
        ? { claimed: false, partial: true, refused: refused }
        : { claimed: false, refused: refused };
    });
  }

  /**
   * Several claims given back, each pinned to its reservation.
   *
   * @param runner - the pool, or the flush's held connection
   * @param rows - `[{ scope, realm, key, reservation }]`
   * @returns the connection's answer
   */
  function releaseClaims(runner, rows) {
    log.debug("Entering releaseClaims(). rows=" + (rows || []).length);
    const tuples = (rows || []).map(function (row) {
      return [String(row.scope), String(row.realm || ''), String(row.key),
              String(row.reservation)];
    });
    log.debug("Leaving releaseClaims().");
    if (!tuples.length) {
      return Promise.resolve({ rows: [], rowCount: 0 });
    }
    return run(runner, 'releaseClaims',
      kx('sts_cluster_claims')
        .whereIn(['scope', 'realm', 'key', 'reservation'], tuples).del());
  }

  /**
   * An origin claim taken over from a membership that has gone:
   * `takeOverFromGone()`'s contract, the origin's `@<node>` parsed here.
   *
   * @param key - the origin
   * @param reservation - this process's new reservation
   * @param holder - this process's origin text (`<origin>@<node>`)
   * @param nodeId - this process's membership
   * @param ttlMs - the claim's lifetime
   * @returns true when this process now holds the claim
   */
  function takeOverFromGone(key, reservation, holder, nodeId, ttlMs) {
    log.debug("Entering takeOverFromGone().");
    const where = at(originScope, '', key);
    log.debug("Leaving takeOverFromGone().");
    return inTransaction(pool, function (client) {
      return run(client, 'takeOver.read',
        kx('sts_cluster_claims').select('origin', 'reservation')
          .where(where).forUpdate()
      ).then(function (found) {
        const row = first(found);
        const origin = row ? String(row.origin || '') : '';
        const sign = origin.indexOf('@');
        const named = sign >= 0 ? origin.slice(sign + 1) : '';
        if (!row || !named || named === String(nodeId)) {
          return false;
        }
        return run(client, 'takeOver.gone',
          kx('sts_cluster_nodes').select(kx.raw('1 AS gone'))
            .where({ node_id: named })
            .where(function () {
              this.where('left_at', '>', 0)
                .orWhere('expires_at', '<=', dialect.now());
            })
        ).then(function (gone) {
          if (!first(gone)) {
            return false;
          }
          return run(client, 'takeOver.write',
            kx('sts_cluster_claims').update({
              reservation: String(reservation), origin: String(holder),
              claimed_at: dialect.now(),
              expires_at: dialect.now(Math.max(1000, Number(ttlMs) ||
                                               30000))
            }).where(where).where({ reservation: row.reservation })
          ).then(function (r) {
            return dialect.affected(r) > 0;
          });
        });
      });
    });
  }

  // ===================================================================
  // THE FENCES, inside every write transaction (a held connection)
  // ===================================================================

  /**
   * The origin claim, still this process's and live, under a shared lock.
   *
   * @param client - the write's held connection
   * @param held - `{ key, reservation }`
   * @returns true when it holds
   */
  function originFence(client, held) {
    log.debug("Entering originFence().");
    log.debug("Leaving originFence().");
    return run(client, 'originFence',
      kx('sts_cluster_claims').select(kx.raw('1 AS held'))
        .where(at(originScope, '', held.key))
        .where({ reservation: held.reservation })
        .where('expires_at', '>', dialect.now()).forShare()
    ).then(function (r) {
      return !!first(r);
    });
  }

  /**
   * This node's membership, live.
   *
   * @param client - the write's held connection
   * @param nodeId - the node
   * @returns true when it is live
   */
  function nodeFence(client, nodeId) {
    log.debug("Entering nodeFence().");
    log.debug("Leaving nodeFence().");
    return run(client, 'nodeFence',
      kx('sts_cluster_nodes').select(kx.raw('1 AS live'))
        .where({ node_id: nodeId, left_at: 0 })
        .where('expires_at', '>', dialect.now())
    ).then(function (r) {
      return !!first(r);
    });
  }

  /**
   * The leases a write needs, still this node's, under a shared lock.
   *
   * @param client - the write's held connection
   * @param nodeId - the node
   * @param leases - `[{ name, token }]`
   * @returns the names that still hold
   */
  function leaseFence(client, nodeId, leases) {
    log.debug("Entering leaseFence().");
    const tuples = leases.map(function (one) {
      return [String(one.name), Number(one.token)];
    });
    log.debug("Leaving leaseFence().");
    return run(client, 'leaseFence',
      kx('sts_cluster_leases').select('name')
        .whereIn(['name', 'token'], tuples)
        .where({ holder: nodeId })
        .where('expires_at', '>', dialect.now()).forShare()
    ).then(function (r) {
      return dialect.rowsOf(r).map(function (row) {
        return row.name;
      });
    });
  }

  // ===================================================================
  // MEMBERSHIP AND LEASES (the liveness connection: no transactions)
  // ===================================================================

  /**
   * The join lock: a row of `sts_cluster_locks`, locked in the joining
   * transaction.
   *
   * @param client - the join's held connection
   * @param name - the lock's name
   * @returns a promise settled once the lock is held
   */
  function serialize(client, name) {
    log.debug("Entering serialize(). " + name);
    log.debug("Leaving serialize().");
    return run(client, 'lock.ensure',
      kx('sts_cluster_locks').insert({ name: String(name) })
        .onConflict('name').ignore()
    ).then(function () {
      return run(client, 'lock.take',
        kx('sts_cluster_locks').select('name')
          .where({ name: String(name) }).forUpdate());
    });
  }

  /**
   * The heartbeat: this node's membership and every lease it holds renewed.
   *
   * @param nodeId - the node
   * @param ttlMs - the new lifetime
   * @param info - the node's info, or null to keep it
   * @returns `{ alive, leases: [{ name, token }] }`
   */
  function heartbeat(nodeId, ttlMs, info) {
    log.debug("Entering heartbeat(). node=" + nodeId);
    const set = { heartbeat_at: dialect.now(),
                  expires_at: dialect.now(Number(ttlMs)) };
    if (info) {
      set.info = dialect.json(info);
    }
    log.debug("Leaving heartbeat().");
    return run(live, 'heartbeat.node',
      kx('sts_cluster_nodes').update(set)
        .where({ node_id: nodeId, left_at: 0 })
        .where('expires_at', '>', dialect.now())
    ).then(function (r) {
      if (dialect.affected(r) === 0) {
        return { alive: false, leases: [] };
      }
      return run(live, 'heartbeat.leases',
        kx('sts_cluster_leases')
          .update({ expires_at: dialect.now(Number(ttlMs)) })
          .where({ holder: nodeId })
          .where('expires_at', '>', dialect.now())
      ).then(function () {
        return run(live, 'heartbeat.held',
          kx('sts_cluster_leases').select('name', 'token')
            .where({ holder: nodeId })
            .where('expires_at', '>', dialect.now()));
      }).then(function (held) {
        return { alive: true, leases: dialect.rowsOf(held).map(function (row) {
          return { name: row.name, token: Number(row.token) };
        }) };
      });
    });
  }

  /**
   * Leaving: the membership ended and every lease given up.
   *
   * @param nodeId - the node
   * @returns true
   */
  function leaveCluster(nodeId) {
    log.debug("Entering leaveCluster(). node=" + nodeId);
    log.debug("Leaving leaveCluster().");
    return run(live, 'leave.node',
      kx('sts_cluster_nodes').update({
        // `expires_at` before `left_at`: MariaDB reads a later assignment's
        // new value, and neither expression reads the other column.
        expires_at: kx.raw('LEAST(??, ' + dialect.nowText + ')',
                           ['expires_at']),
        left_at: dialect.now()
      }).where({ node_id: nodeId })
    ).then(function () {
      return run(live, 'leave.leases',
        kx('sts_cluster_leases').update({ expires_at: 0 })
          .where({ holder: nodeId }));
    }).then(function () {
      return true;
    });
  }

  /**
   * A lease asked for: taken when free or expired, renewed when this node's.
   *
   * @param name - the lease
   * @param nodeId - the asking node
   * @param ttlMs - its lifetime
   * @returns `{ held: true, token, expiresAt }` or `{ held: false, holder,
   *   token, expiresAt }`
   */
  function acquireLease(name, nodeId, ttlMs) {
    log.debug("Entering acquireLease(). name=" + name);
    const nodeLive = function (q) {
      return q.select(kx.raw('1')).from('sts_cluster_nodes')
        .where({ node_id: nodeId, left_at: 0 })
        .where('expires_at', '>', dialect.now());
    };
    // Kept by the same holder within its lifetime; otherwise a new token.
    const kept = '?? = ? AND ?? > ' + dialect.nowText;
    log.debug("Leaving acquireLease().");
    return run(live, 'acquireLease.renew',
      kx('sts_cluster_leases').update({
        token: kx.raw('CASE WHEN ' + kept + ' THEN ?? ELSE ?? + 1 END',
                      ['holder', nodeId, 'expires_at', 'token', 'token']),
        acquired_at: kx.raw('CASE WHEN ' + kept + ' THEN ?? ELSE ' +
                            dialect.nowText + ' END',
                            ['holder', nodeId, 'expires_at', 'acquired_at']),
        expires_at: dialect.now(Number(ttlMs)),
        // LAST: the two CASEs above read the holder it replaces.
        holder: nodeId
      }).where({ name: name })
        .where(function () {
          this.where('expires_at', '<=', dialect.now())
            .orWhere({ holder: nodeId });
        })
        .whereExists(function () {
          nodeLive(this);
        })
    ).then(function (r) {
      if (dialect.affected(r) > 0) {
        return null;
      }
      return run(live, 'acquireLease.nodeLive',
        nodeLive(kx.queryBuilder())
      ).then(function (alive) {
        if (!first(alive)) {
          return null;
        }
        return run(live, 'acquireLease.insert',
          kx('sts_cluster_leases').insert({
            name: name, holder: nodeId, token: 1,
            acquired_at: dialect.now(), expires_at: dialect.now(Number(ttlMs))
          }).onConflict('name').ignore());
      });
    }).then(function () {
      return run(live, 'acquireLease.holder',
        kx('sts_cluster_leases').select('holder', 'token', 'expires_at')
          .where({ name: name }));
    }).then(function (found) {
      const row = first(found);
      if (row && row.holder === nodeId) {
        return { held: true, token: Number(row.token),
                 expiresAt: Number(row.expires_at) };
      }
      return { held: false, holder: row ? row.holder : '',
               token: row ? Number(row.token) : 0,
               expiresAt: row ? Number(row.expires_at) : 0 };
    });
  }

  // ===================================================================
  // VALUES THAT ONLY RISE, AND COUNTS
  // ===================================================================

  /**
   * A counter raised to `value` if it is below it.
   *
   * @param scope - the counter's scope
   * @param realmId - its realm
   * @param key - its key
   * @param value - the value asked for
   * @returns `{ advanced, highest }`
   */
  function advanceCounter(scope, realmId, key, value) {
    log.debug("Entering advanceCounter(). scope=" + scope);
    const wanted = Math.max(0, Math.floor(Number(value) || 0));
    const where = at(scope, realmId, key);
    const raise = function () {
      return run(pool, 'advanceCounter.raise',
        kx('sts_cluster_counters')
          .update({ value: wanted, origin: processId(),
                    updated_at: dialect.now() })
          .where(where).where('value', '<', wanted));
    };
    const attempt = function (left) {
      return raise().then(function (r) {
        if (dialect.affected(r) > 0) {
          return true;
        }
        return run(pool, 'advanceCounter.insert',
          kx('sts_cluster_counters').insert(Object.assign({}, where, {
            value: wanted, origin: processId(), updated_at: dialect.now()
          })).onConflict(['scope', 'realm', 'key']).ignore()
        ).then(function (inserted) {
          if (dialect.affected(inserted) > 0) {
            return true;
          }
          // The row exists: at or above `wanted` (refused), or below it
          // because it was inserted after our UPDATE looked.
          return left > 0 ? raise().then(function (again) {
            return dialect.affected(again) > 0;
          }) : false;
        });
      });
    };
    log.debug("Leaving advanceCounter().");
    return attempt(RACE_RETRIES).then(function (advanced) {
      if (advanced) {
        return { advanced: true, highest: wanted };
      }
      return run(pool, 'advanceCounter.highest',
        kx('sts_cluster_counters').select('value').where(where)
      ).then(function (found) {
        const row = first(found);
        return { advanced: false, highest: row ? Number(row.value) : 0 };
      });
    });
  }

  /**
   * One more in a fixed window, a new window when the old one has ended.
   *
   * @param scope - the window's scope
   * @param realmId - its realm
   * @param key - its key
   * @param windowMs - the window's span
   * @returns `{ count, remainingMs }`, the count distinct per caller
   */
  function countWindow(scope, realmId, key, windowMs) {
    log.debug("Entering countWindow(). scope=" + scope);
    const span = Math.max(1, Math.floor(Number(windowMs) || 0));
    const where = at(scope, realmId, key);
    const ended = '?? <= ' + dialect.nowText;
    log.debug("Leaving countWindow().");
    // THE ROW FIRST, OUTSIDE THE TRANSACTION, as an ENDED window (count 0,
    // ends now): then the transaction below only ever updates a row that
    // exists, and takes that row's lock and no gap lock — concurrent first
    // counts of one key deadlocked InnoDB when each inserted inside its own
    // transaction. The bump turns an ended window into a new one at 1.
    return run(tallyPool, 'countWindow.ensure',
      kx('sts_cluster_windows').insert(Object.assign({}, where, {
        count: 0, window_ends_at: dialect.now(), origin: processId()
      })).onConflict(['scope', 'realm', 'key']).ignore()
    ).then(function () {
      return inTransaction(tallyPool, function (client) {
      const bump = function () {
        return run(client, 'countWindow.bump',
          kx('sts_cluster_windows').update({
            // `count` first: it reads the window's OLD end, which the next
            // assignment replaces.
            count: kx.raw('CASE WHEN ' + ended + ' THEN 1 ELSE ?? + 1 END',
                          ['window_ends_at', 'count']),
            window_ends_at: kx.raw('CASE WHEN ' + ended + ' THEN (' +
                                   dialect.nowText + ' + ?) ELSE ?? END',
                                   ['window_ends_at', span, 'window_ends_at']),
            origin: processId()
          }).where(where));
      };
      return bump().then(function () {
        return run(client, 'countWindow.read',
          kx('sts_cluster_windows')
            .select('count', kx.raw('?? - ' + dialect.nowText +
                                    ' AS remaining', ['window_ends_at']))
            .where(where));
      });
      });
    }).then(function (answer) {
      const row = first(answer) || {};
      return { count: Number(row.count) || 0,
               remainingMs: Math.max(0, Number(row.remaining) || 0) };
    });
  }

  /**
   * A spend against a budget's limits: `spendBudget()`'s contract — the
   * row added to in its period, reset in a newer one, never for an older
   * one, and written only within the limits. Amounts are decimal strings of
   * whole millionths, compared as BigInt.
   *
   * @returns `{ amount, count }`, or null for a refusal
   */
  function spendBudget(scope, realmId, key, period, amount, count,
                       limitAmount, limitCount, expiresAtMs) {
    log.debug("Entering spendBudget(). scope=" + scope);
    const where = at(scope, realmId, key);
    const p = Math.floor(Number(period) || 0);
    const add = BigInt(String(amount));
    const times = Math.floor(Number(count) || 0);
    const capA = limitAmount === null || limitAmount === undefined ? null
      : BigInt(String(limitAmount));
    const capC = limitCount === null || limitCount === undefined ? null
      : Math.floor(Number(limitCount));
    const ends = Math.floor(Number(expiresAtMs) || 0);
    const within = function (a, c) {
      return (capA === null || a <= capA) && (capC === null || c <= capC);
    };
    const attempt = function (left) {
      return inTransaction(pool, function (client) {
        return run(client, 'spendBudget.read',
          kx('sts_cluster_budgets')
            .select('period', 'amount', 'count', 'expires_at')
            .where(where).forUpdate()
        ).then(function (found) {
          const row = first(found);
          if (!row) {
            if (!within(add, times)) {
              return null;
            }
            return run(client, 'spendBudget.insert',
              kx('sts_cluster_budgets').insert(Object.assign({}, where, {
                period: p, amount: add.toString(), count: times,
                origin: processId(), expires_at: ends,
                updated_at: dialect.now()
              })).onConflict(['scope', 'realm', 'key']).ignore()
            ).then(function (inserted) {
              return dialect.affected(inserted) > 0
                ? { amount: add.toString(), count: times } : 'raced';
            });
          }
          const stored = Number(row.period);
          if (p < stored) {
            return null;
          }
          const same = p === stored;
          const total = same ? BigInt(String(row.amount)) + add : add;
          const n = same ? Number(row.count) + times : times;
          if (!within(total, n)) {
            return null;
          }
          return run(client, 'spendBudget.write',
            kx('sts_cluster_budgets').update({
              amount: total.toString(), count: n, period: p,
              origin: processId(),
              expires_at: Math.max(Number(row.expires_at) || 0, ends),
              updated_at: dialect.now()
            }).where(where)
          ).then(function () {
            return { amount: total.toString(), count: n };
          });
        });
      }).then(function (answer) {
        return answer === 'raced' && left > 0 ? attempt(left - 1)
          : answer === 'raced' ? null : answer;
      });
    };
    log.debug("Leaving spendBudget().");
    return attempt(RACE_RETRIES);
  }

  // ===================================================================
  // THE CHANGE LOG'S READERS AND ITS TRIM
  // ===================================================================

  /**
   * This process's low-water mark, never moved backwards.
   *
   * @param applied - the mark
   * @param nodeId - this process's node, '' for none
   * @returns `{ inserted }`: true when the row had to be made (or remade)
   */
  function reportChangeReader(applied, nodeId) {
    log.debug("Entering reportChangeReader().");
    const mark = Math.max(0, Number(applied) || 0);
    const update = function () {
      return run(pool, 'reportChangeReader.update',
        kx('sts_change_readers').update({
          node_id: String(nodeId || ''),
          applied: kx.raw('GREATEST(??, ?)', ['applied', mark]),
          reported_at: dialect.now()
        }).where({ origin: processId() }));
    };
    log.debug("Leaving reportChangeReader().");
    return update().then(function (r) {
      if (dialect.affected(r) > 0) {
        return { inserted: false };
      }
      return run(pool, 'reportChangeReader.insert',
        kx('sts_change_readers').insert({
          origin: processId(), node_id: String(nodeId || ''), applied: mark,
          started_at: dialect.now(), reported_at: dialect.now()
        }).onConflict('origin').ignore()
      ).then(function (inserted) {
        if (dialect.affected(inserted) > 0) {
          return { inserted: true };
        }
        return update().then(function () {
          return { inserted: false };
        });
      });
    });
  }

  /**
   * The trim: readers that are gone removed, then every change below the
   * lowest remaining mark and older than the retention.
   *
   * @param opts - `{ readerTtlMs, retentionMs, nodeLiveness }`
   * @returns `{ readersGone, readers, bound, trimmed }`
   */
  function purgeChangeLog(opts) {
    log.debug("Entering purgeChangeLog().");
    const o = opts || {};
    const readerTtlMs = Math.max(1, Math.floor(Number(o.readerTtlMs) || 0));
    const retentionMs = Math.max(0, Math.floor(Number(o.retentionMs) || 0));
    const byMembership = o.nodeLiveness !== false;
    const gone = kx('sts_change_readers').where(function () {
      this.where('reported_at', '<', dialect.now(readerTtlMs, '-'));
      if (byMembership) {
        this.orWhere(function () {
          this.whereNot({ node_id: '' }).whereNotExists(function () {
            this.select(kx.raw('1')).from({ n: 'sts_cluster_nodes' })
              .whereRaw('?? = ??', ['n.node_id',
                                    'sts_change_readers.node_id'])
              .where('n.left_at', 0)
              .where('n.expires_at', '>', dialect.now());
          });
        });
      }
    }).del();
    let readersGone = 0;
    log.debug("Leaving purgeChangeLog().");
    return run(pool, 'purgeChangeLog.readers', gone).then(function (r) {
      readersGone = dialect.affected(r);
      return run(pool, 'purgeChangeLog.low',
        kx('sts_change_readers').min({ low: 'applied' })
          .count({ readers: '*' }));
    }).then(function (answer) {
      const row = first(answer) || {};
      const readers = Number(row.readers) || 0;
      const low = row.low === null || row.low === undefined ? null
        : Number(row.low);
      if (!readers || low === null) {
        return { readersGone: readersGone, readers: readers, bound: low,
                 trimmed: 0 };
      }
      return run(pool, 'purgeChangeLog.trim',
        kx('sts_changes').where('seq', '<', low)
          .where('at', '<', dialect.ago(retentionMs)).del()
      ).then(function (trim) {
        return { readersGone: readersGone, readers: readers, bound: low,
                 trimmed: dialect.affected(trim) };
      });
    });
  }

  log.debug("Leaving create().");
  return {
    claimOnce: claimOnce,
    claimMany: claimMany,
    releaseClaims: releaseClaims,
    takeOverFromGone: takeOverFromGone,
    originFence: originFence,
    nodeFence: nodeFence,
    leaseFence: leaseFence,
    serialize: serialize,
    heartbeat: heartbeat,
    leaveCluster: leaveCluster,
    acquireLease: acquireLease,
    advanceCounter: advanceCounter,
    countWindow: countWindow,
    spendBudget: spendBudget,
    reportChangeReader: reportChangeReader,
    purgeChangeLog: purgeChangeLog
  };
}

module.exports = {
  create: create,
  // The same factory under a name that does not read as a call of the
  // driver's own `create()` (`tests/no_periodic_timers.js` treats a
  // function that calls its own name as one that repeats).
  forDriver: create
};
