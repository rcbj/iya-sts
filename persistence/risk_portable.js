// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: risk_portable.js
//
// ---------------------------------------------------------------------------
// THE RISK ENGINE'S STORE ON MARIADB (#677, phase 3).
//
// Every `risk*` method of the postgres driver — the datasets by version and
// their rows, the range and FIDO lookups, the failure history, the model's
// counts, the assessments, each person's standing, the session contexts,
// the purges and the terms acceptances — written a second time for MariaDB,
// in builder statements and, where MariaDB has a feature PostgreSQL spells
// differently, MariaDB's own text. The driver uses these when the engine is
// not PostgreSQL, and ONLY then: the MariaDB schema keeps an address as
// INET6 (an IPv4 one as `::ffff:a.b.c.d`), a prefix as text and a list as a
// JSON array (`mariadb/CLAUDE.md`), and statements written for those types
// are not statements for PostgreSQL's `inet`, `cidr` and `text[]` — so
// `persistence.sqlDialect=portable` on PostgreSQL leaves this family on its
// native text. PostgreSQL's statements are unchanged.
//
// THE CONTRACTS ARE THE NATIVE STATEMENTS', AND EACH SAYS HOW IT KEEPS ITS
// OWN:
//
//   * A RANGE LOOKUP IS ONE DESCENDING SEEK OF THE PRIMARY KEY, as on
//     PostgreSQL: the row with the greatest start not above the address,
//     kept only if its end is not below it. INET6 sorts the IPv4 block
//     (`::ffff:0.0.0.0` to `::ffff:255.255.255.255`) in the MIDDLE of IPv6,
//     where `inet` sorts all IPv4 before all IPv6, so the seek is bounded to
//     the address's own family: an IPv4 address seeks within the block, an
//     IPv6 one outside it (two intervals of one index, read from the top,
//     first row wins — still `range` access, never a scan). An IPv4 address
//     finds only IPv4 ranges and an IPv6 one only IPv6 ranges, as there. An
//     address written `::ffff:a.b.c.d` is IPv4 here, as it is in the memory
//     store (`RiskStore.addressNumber()`); an IPv6 RANGE inside
//     `::ffff:0:0/96` cannot be told from an IPv4 one on this engine.
//   * A BATCH OF DATASET ROWS IS ONE `INSERT IGNORE` (or a few, for FIDO
//     models carrying metadata statements, by size, in one transaction),
//     because `ON CONFLICT DO NOTHING` answers how many rows it wrote and
//     `INSERT IGNORE` is the MariaDB statement that does. IGNORE also turns
//     what strict mode refuses into a substitute — a truncated key, an
//     address that is not one stored as `::`, a NULL as '' — so every value
//     is checked first and the batch refused whole, as PostgreSQL refuses a
//     statement with one bad value: a key too long for its column
//     (STS-STORE-0100), an address that is not one or a number that is not
//     an integer (STS-STORE-0160).
//   * A JSONB MERGE (`parameters || $n`) IS THE ROW LOCKED FOR UPDATE AND
//     MERGED IN JAVASCRIPT for a version's outcome; an import's progress
//     (two numbers, fixed keys) is `JSON_SET()` in the one UPDATE, which is
//     the shallow merge for scalars. MariaDB's `JSON_MERGE_PATCH()` is RFC
//     7396's and deletes on a null, which jsonb's `||` does not.
//   * `UPDATE … RETURNING` (the stalled imports) is the rows read FOR UPDATE
//     and updated by key in one transaction; locked, they cannot change
//     between, so what is answered is what was refused.
//   * AN ACTION IS CLAIMED EXACTLY ONCE because the claim is still ONE
//     conditional UPDATE: `JSON_SET()` of the reaction's key where its value
//     is not already this assessment (`NOT (… <=> ?)`, PostgreSQL's `IS
//     DISTINCT FROM`). InnoDB re-reads a locked row before it applies the
//     WHERE, so the second of two concurrent claims matches nothing.
//     Durable at commit, on the write pool, as the native one.
//   * A PERSON'S STANDING (the upsert that answered the level it replaced)
//     is a transaction on the tally pool: the row read FOR UPDATE, then
//     UPDATE or INSERT; a concurrent first standing is a duplicate key,
//     after which the row is there and is read again. The change of level
//     is announced after COMMIT, as the native one does.
//   * A COUNT GOES UP BY ONE PER ROW IN ONE STATEMENT
//     (`INSERT … ON DUPLICATE KEY UPDATE count = count + 1`), rows sorted by
//     key so two nodes counting the same sign-in lock in one order; a
//     deadlock InnoDB still answers is run again (the statement is
//     autocommit and left nothing).
//   * A FIRST-WRITER-WINS INSERT (a version begun, an assessment) is a plain
//     INSERT whose duplicate-key refusal reads as "already recorded": not
//     IGNORE, so strict mode still refuses a bad value outright.
//   * A ctid BATCH DELETE IS `DELETE … LIMIT n`, the same bound, on the
//     same index prefix (the version's rows by their primary key, the
//     failures and assessments by `at`).
//   * `FILTER (WHERE …)` IS `SUM(CASE …)`, `unnest … WITH ORDINALITY` a
//     select list of one scalar subquery per ask, `jsonb_array_elements()`
//     `JSON_TABLE()`, `percentile_disc(array)` one window
//     `PERCENTILE_DISC()` per fraction in one statement, integer division
//     `DIV`, and `GROUPING SETS` one `WITH ROLLUP` whose extra level is
//     dropped (every grouped column is NOT NULL, so a NULL is a rolled-up
//     column, which is what `GROUPING()` said). On an empty window ROLLUP
//     answers no row where the grouping sets answered the world's, so that
//     row is supplied. `DISTINCT ON (session_id)` is `ROW_NUMBER()`.
//   * A `real` IS READ AS `CAST(score AS DOUBLE)` and written back at its
//     shortest single-precision spelling, which is what PostgreSQL prints;
//     MariaDB's FLOAT on its own answers six digits.
//   * BOOLEANS AND JSON are made into `pg`'s shapes as they are read:
//     MariaDB answers a BOOLEAN as 0/1 and JSON as its text.
//
// A LIBRARY: handed the dialect, the pools, the driver's transaction helper,
// its change recorder and its row shapes; it requires only `net`, the
// error-code table and bunyan (and `common/crypto` lazily, for a retry's
// jitter), and holds no state.
// ---------------------------------------------------------------------------

const net = require('net');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'sts-risk-portable',
  level: process.env.STS_LOG_LEVEL || process.env.LOG_LEVEL || 'info'
});

// How many times a statement or transaction MariaDB refused with a deadlock
// or a lock timeout is run again.
const RETRIES = 8;

// THE KEYED COLUMNS' WIDTHS ON MARIADB (`mariadb/CLAUDE.md`, *Size limits*).
const WIDTH = {
  realm: 64,
  dataset: 128,
  version: 128,
  provider: 128,
  keyKind: 32,
  authenticatorKey: 255,
  id: 255,
  subject: 255,
  sessionId: 255,
  nameHmac: 255,
  feature: 64,
  value: 255,
  prefix: 50
};

// The IPv4 block inside INET6's order (see the header).
const V4_LOW = '::ffff:0.0.0.0';
const V4_HIGH = '::ffff:255.255.255.255';

// The most bytes one INSERT of FIDO models carries: a model's metadata
// statement is kilobytes, and `max_allowed_packet` bounds a statement.
const FIDO_STATEMENT_BYTES = 4 * 1024 * 1024;

const RANGE_TABLES = { geo: 'sts_risk_geo_ranges',
                       asn: 'sts_risk_asn_ranges',
                       iplist: 'sts_risk_ip_lists' };

const ROW_TABLES = Object.assign({ fido: 'sts_risk_fido_authenticators' },
                                 RANGE_TABLES);

/**
 * Builds the risk statements over one driver's connections.
 *
 * @param deps - `{ dialect, pool, tallyPool, withTransaction, recordChanges,
 *   processId, shapes }`: the dialect, the write and tally pools, the
 *   driver's fenced transaction, its change recorder, a function answering
 *   this process's origin, and the driver's row shapes (`dataset`,
 *   `version`, `range`, `failure`)
 * @returns the operations, each answering what the driver's PostgreSQL
 *   statement answers
 */
function create(deps) {
  log.debug("Entering create().");
  const dialect = deps.dialect;
  const kx = dialect.kx;
  const pool = deps.pool;
  const tallyPool = deps.tallyPool || deps.pool;
  const shapes = deps.shapes;

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
    return dialect.run(runner, 'risk.' + name, built);
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
   * A JSON column's value: MariaDB's JSON is LONGTEXT and arrives as text.
   *
   * @param value - the column as read
   * @param empty - what a NULL reads as
   * @returns the value parsed
   */
  function parsed(value, empty) {
    log.debug("Entering parsed().");
    if (value === null || value === undefined) {
      log.debug("Leaving parsed(). Empty.");
      return empty;
    }
    if (typeof value !== 'string') {
      log.debug("Leaving parsed(). Already a value.");
      return Buffer.isBuffer(value) ? JSON.parse(value.toString('utf8'))
        : value;
    }
    log.debug("Leaving parsed().");
    return JSON.parse(value);
  }

  /**
   * A BOOLEAN column as `pg` answers it: MariaDB's is 0/1, and NULL stays
   * NULL.
   *
   * @param value - the column as read
   * @returns true, false or null
   */
  function bool(value) {
    log.debug("Entering bool().");
    log.debug("Leaving bool().");
    return value === null || value === undefined ? null
      : value === true || Number(value) === 1;
  }

  /**
   * A single-precision value read through DOUBLE, at the shortest spelling
   * that is still that float — what PostgreSQL prints for a `real`.
   *
   * @param value - the column as read
   * @returns a number, or null
   */
  function real(value) {
    log.debug("Entering real().");
    if (value === null || value === undefined) {
      log.debug("Leaving real(). NULL.");
      return null;
    }
    const exact = Math.fround(Number(value));
    for (let digits = 1; digits <= 9; digits++) {
      const shorter = Number(exact.toPrecision(digits));
      if (Math.fround(shorter) === exact) {
        log.debug("Leaving real().");
        return shorter;
      }
    }
    log.debug("Leaving real(). Nine digits.");
    return Number(exact.toPrecision(9));
  }

  /**
   * Refuses a value too long for its MariaDB column (STS-STORE-0100), as
   * `store_portable.js` does: strict mode would refuse it with the server's
   * words, and `INSERT IGNORE` would truncate it into another row's key.
   *
   * @param what - the table and column
   * @param value - the value
   * @param width - the column's width in characters
   * @returns the value as a string
   */
  function bounded(what, value, width) {
    log.debug("Entering bounded(). " + what);
    const text = String(value === undefined || value === null ? '' : value);
    // Characters, not UTF-16 units: a column's width is in characters. The
    // length check first, so the common short value costs no array.
    if (text.length > width && Array.from(text).length > width) {
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
   * A refusal of a value its MariaDB column cannot hold (STS-STORE-0160).
   *
   * @param what - the column
   * @param value - the value
   * @returns an Error
   */
  function refusal(what, value) {
    log.debug("Entering refusal(). " + what);
    log.debug("Leaving refusal().");
    return new Error(errorCodes.tag('STS-STORE-0160') + 'persistence: ' +
                     JSON.stringify(String(value)).slice(0, 80) + ' is not ' +
                     'a value ' + what + ' holds, and is refused on MariaDB ' +
                     'rather than stored as a substitute.');
  }

  /**
   * An address in the form an INET6 column holds, with its family: an IPv4
   * address (or one written `::ffff:a.b.c.d`) as its mapped form.
   *
   * @param value - the address's text
   * @param what - the column, for a refusal
   * @returns `{ text, v4 }`
   */
  function inet(value, what) {
    log.debug("Entering inet().");
    let text = String(value === null || value === undefined ? ''
      : value).trim();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(text);
    if (mapped) {
      text = mapped[1];
    }
    const family = net.isIP(text);
    if (family === 4) {
      log.debug("Leaving inet(). IPv4.");
      return { text: '::ffff:' + text, v4: true };
    }
    if (family !== 6) {
      log.debug("Leaving inet(). Not an address.");
      throw refusal(what, value);
    }
    log.debug("Leaving inet(). IPv6.");
    return { text: text.toLowerCase(), v4: false };
  }

  /**
   * An INET6 value as `inet` prints it: an IPv4 address bare.
   *
   * @param value - the column as read
   * @returns the text
   */
  function inetText(value) {
    log.debug("Entering inetText().");
    const text = String(value);
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(text);
    log.debug("Leaving inetText().");
    return mapped ? mapped[1] : text;
  }

  /**
   * A number an integer column holds, or a refusal.
   *
   * @param value - the value
   * @param what - the column
   * @returns the integer
   */
  function integer(value, what) {
    log.debug("Entering integer().");
    const n = Number(value);
    if (!Number.isSafeInteger(n)) {
      log.debug("Leaving integer(). Not an integer.");
      throw refusal(what, value);
    }
    log.debug("Leaving integer().");
    return n;
  }

  /**
   * Runs `attempt()` again when MariaDB refused it with a deadlock or a
   * lock timeout; safe because a refused attempt left nothing. A fenced
   * refusal is never run again.
   *
   * @param what - a name for the log
   * @param attempt - answers a promise
   * @returns what `attempt()` answered
   */
  function retrying(what, attempt) {
    log.debug("Entering retrying(). " + what);
    const go = function (left) {
      return attempt().catch(function (err) {
        if (left <= 0 || (err && err.fenced) || !dialect.isRetryable(err)) {
          throw err;
        }
        log.debug("Caught in retrying(): " + ((err && err.message) || err) +
                  "; " + what + " again.");
        return new Promise(function (resolve) {
          // node's generator, as every random value here is
          // (tests/random_values.js); a jitter needs no more.
          const jitter = require('../common/crypto').randomInt(0, 20);
          setTimeout(resolve, 5 + jitter);
        }).then(function () {
          return go(left - 1);
        });
      });
    };
    log.debug("Leaving retrying().");
    return go(RETRIES);
  }

  /**
   * An UNFENCED transaction on a connection held from `from`, for what the
   * native driver sent as one statement outside a transaction.
   *
   * @param from - the pool
   * @param what - a name for the log
   * @param fn - given the held connection; answers a promise
   * @returns what `fn` answered
   */
  function unfenced(from, what, fn) {
    log.debug("Entering unfenced(). " + what);
    log.debug("Leaving unfenced().");
    return retrying(what, function () {
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
    });
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

  // ===================================================================
  // THE DATASETS AND THEIR VERSIONS
  // ===================================================================

  /**
   * A version's row in `pg`'s shapes.
   *
   * @param r - the row as read
   * @returns the row with `parameters` parsed
   */
  function versionRow(r) {
    log.debug("Entering versionRow().");
    log.debug("Leaving versionRow().");
    return Object.assign({}, r, { parameters: parsed(r.parameters, {}) });
  }

  /**
   * Every dataset's live version and state, for every realm.
   *
   * @returns the datasets
   */
  function riskListDatasets() {
    log.debug("Entering riskListDatasets().");
    log.debug("Leaving riskListDatasets().");
    return run(pool, 'listDatasets',
      kx('sts_risk_datasets')
        .select('realm', 'dataset', 'kind', 'active_version',
                'previous_version', 'state', 'updated_at')
        .orderBy([{ column: 'realm' }, { column: 'dataset' }])
    ).then(function (result) {
      return rows(result).map(shapes.dataset);
    });
  }

  /**
   * Every version of one dataset (or of every dataset, for ''), newest
   * first.
   *
   * @returns the versions
   */
  function riskListVersions(realm, dataset) {
    log.debug("Entering riskListVersions(). dataset=" + dataset);
    const built = kx('sts_risk_dataset_versions').select('*')
      .where('realm', String(realm || ''));
    if (String(dataset || '')) {
      built.where('dataset', String(dataset));
    }
    log.debug("Leaving riskListVersions().");
    return run(pool, 'listVersions',
      built.orderBy([{ column: 'fetched_at', order: 'desc' },
                     { column: 'version', order: 'desc' }])
    ).then(function (result) {
      return rows(result).map(function (r) {
        return shapes.version(versionRow(r));
      });
    });
  }

  /**
   * A version begun: its row in `loading`, or false when that version is
   * already recorded. With `reloadDeleted`, a `deleted` record is begun
   * again in place: an UPDATE guarded by the state (only a `deleted` row is
   * touched, under its row lock), and where it touched nothing, the insert.
   * A concurrent insert of the same version is a duplicate key, which is
   * "already recorded", as the native `ON CONFLICT` reads it.
   *
   * @returns true when this call began it
   */
  function riskBeginVersion(v, reloadDeleted) {
    log.debug("Entering riskBeginVersion(). " + v.dataset + " " + v.version);
    const key = {
      realm: bounded('sts_risk_dataset_versions.realm', v.realm || '',
                     WIDTH.realm),
      dataset: bounded('sts_risk_dataset_versions.dataset', v.dataset,
                       WIDTH.dataset),
      version: bounded('sts_risk_dataset_versions.version', v.version,
                       WIDTH.version)
    };
    const provenance = {
      format: v.format, provider: v.provider, licence: v.licence,
      attribution: v.attribution || '', source: v.source,
      source_uri: v.sourceUri || '', sha256: v.sha256,
      byte_count: Number(v.byteCount) || 0,
      parameters: JSON.stringify(v.parameters || {}),
      verification: v.verification,
      published_at: Number(v.publishedAt) || 0,
      next_update_at: Number(v.nextUpdateAt) || 0,
      fetched_at: Number(v.fetchedAt) || 0,
      state: 'loading', origin: deps.processId()
    };
    const insert = function () {
      return run(pool, 'beginVersion.insert',
        kx('sts_risk_dataset_versions')
          .insert(Object.assign({}, key, provenance))
      ).then(function () {
        return true;
      }, function (err) {
        if (dialect.isUniqueViolation(err)) {
          log.debug("Caught in riskBeginVersion(): already recorded.");
          return false;
        }
        throw err;
      });
    };
    if (!reloadDeleted) {
      log.debug("Leaving riskBeginVersion(). Insert.");
      return insert();
    }
    log.debug("Leaving riskBeginVersion(). Reload or insert.");
    return run(pool, 'beginVersion.reload',
      kx('sts_risk_dataset_versions')
        .update(Object.assign({}, provenance, {
          row_count: 0, loaded_at: 0, activated_at: 0, superseded_at: 0,
          rows_deleted_at: 0, refusal: '', error_code: ''
        }))
        .where(key).where('state', 'deleted')
    ).then(function (result) {
      if (dialect.affected(result) > 0) {
        return true;
      }
      return insert();
    });
  }

  /**
   * One batch of a version's rows as columns, every value checked first
   * (see the header: `INSERT IGNORE` would substitute what it cannot
   * store).
   *
   * @returns the column objects
   */
  function datasetRows(kind, realm, dataset, version, batch) {
    log.debug("Entering datasetRows(). kind=" + kind);
    const head = {
      dataset: bounded(ROW_TABLES[kind] + '.dataset', dataset, WIDTH.dataset),
      version: bounded(ROW_TABLES[kind] + '.version', version, WIDTH.version)
    };
    if (kind === 'iplist') {
      head.realm = bounded('sts_risk_ip_lists.realm', realm || '',
                           WIDTH.realm);
    }
    const text = function (value) {
      return value === undefined || value === null ? '' : String(value);
    };
    const coordinate = function (value, what) {
      if (value === undefined || value === null) {
        return null;
      }
      const n = Number(value);
      if (!isFinite(n)) {
        throw refusal(what, value);
      }
      return n;
    };
    const out = batch.map(function (row) {
      if (kind === 'fido') {
        return Object.assign({}, head, {
          key_kind: bounded('sts_risk_fido_authenticators.key_kind',
                            text(row.keyKind), WIDTH.keyKind),
          authenticator_key: bounded(
            'sts_risk_fido_authenticators.authenticator_key', text(row.key),
            WIDTH.authenticatorKey),
          description: text(row.description),
          protocol_family: text(row.protocolFamily),
          certification_level: text(row.certificationLevel),
          latest_status: text(row.latestStatus),
          latest_status_at: integer(row.latestStatusAt || 0,
            'sts_risk_fido_authenticators.latest_status_at'),
          compromised: !!row.compromised,
          status_reports: JSON.stringify(row.statusReports || []),
          metadata_statement: JSON.stringify(row.metadataStatement || {})
        });
      }
      const ends = {
        range_start: inet(row.start, ROW_TABLES[kind] + '.range_start').text,
        range_end: inet(row.end, ROW_TABLES[kind] + '.range_end').text
      };
      if (kind === 'geo') {
        return Object.assign({}, head, ends, {
          location_id: integer(row.locationId || 0,
                               'sts_risk_geo_ranges.location_id'),
          continent: text(row.continent), country: text(row.country),
          subdivision: text(row.subdivision), city: text(row.city),
          registered_country: text(row.registeredCountry),
          latitude: coordinate(row.latitude, 'sts_risk_geo_ranges.latitude'),
          longitude: coordinate(row.longitude,
                                'sts_risk_geo_ranges.longitude'),
          accuracy_km: integer(row.accuracyKm || 0,
                               'sts_risk_geo_ranges.accuracy_km'),
          anonymous_proxy: !!row.anonymousProxy, satellite: !!row.satellite
        });
      }
      if (kind === 'asn') {
        return Object.assign({}, head, ends, {
          asn: integer(row.asn || 0, 'sts_risk_asn_ranges.asn'),
          as_org: text(row.asOrg), as_domain: text(row.asDomain)
        });
      }
      return Object.assign({}, head, ends, {
        category: text(row.category), note: text(row.note)
      });
    });
    log.debug("Leaving datasetRows().");
    return out;
  }

  /**
   * Rows of a version, in batches; a row whose key is there already is
   * left as it is (`INSERT IGNORE`, every value checked first).
   *
   * @returns the number inserted
   */
  function riskInsertRows(kind, realm, dataset, version, batch) {
    log.debug("Entering riskInsertRows(). kind=" + kind + " rows=" +
              batch.length);
    const table = ROW_TABLES[kind];
    if (!table) {
      log.debug("Leaving riskInsertRows(). Unknown kind.");
      return Promise.reject(new Error(errorCodes.tag('STS-RISK-0006') +
        'no risk dataset table holds rows of kind "' + kind + '".'));
    }
    if (!batch.length) {
      log.debug("Leaving riskInsertRows(). Nothing.");
      return Promise.resolve(0);
    }
    let columns;
    try {
      columns = datasetRows(kind, realm, dataset, version, batch);
    } catch (err) {
      log.debug("Caught in riskInsertRows(): " + ((err && err.message) ||
                err));
      log.debug("Leaving riskInsertRows(). Refused.");
      return Promise.reject(err);
    }
    // FIDO models split by size (see FIDO_STATEMENT_BYTES); ranges are a
    // few hundred bytes a row, and a batch is one statement.
    const statements = [];
    let current = [];
    let bytes = 0;
    columns.forEach(function (one) {
      const size = kind === 'fido'
        ? one.status_reports.length + one.metadata_statement.length + 512
        : 0;
      if (current.length && bytes + size > FIDO_STATEMENT_BYTES) {
        statements.push(current);
        current = [];
        bytes = 0;
      }
      current.push(one);
      bytes += size;
    });
    statements.push(current);
    const send = function (runner) {
      let total = 0;
      let chain = Promise.resolve();
      statements.forEach(function (part) {
        chain = chain.then(function () {
          return run(runner, 'insertRows.' + kind,
            kx(table).insert(part).onConflict().ignore());
        }).then(function (result) {
          total += dialect.affected(result);
        });
      });
      return chain.then(function () {
        return total;
      });
    };
    if (statements.length === 1) {
      log.debug("Leaving riskInsertRows(). One statement.");
      return send(pool);
    }
    log.debug("Leaving riskInsertRows(). " + statements.length +
              " statements in one transaction.");
    return unfenced(pool, 'insertRows', send);
  }

  /**
   * A version's outcome; its parameters merged over what is stored
   * (jsonb's `||`: shallow), under the row's lock.
   *
   * @returns true when the version exists
   */
  function riskFinishVersion(realm, dataset, version, patch) {
    log.debug("Entering riskFinishVersion(). " + dataset + " " + version +
              " " + patch.state);
    const key = { realm: String(realm || ''), dataset: String(dataset),
                  version: String(version) };
    log.debug("Leaving riskFinishVersion().");
    return unfenced(pool, 'finishVersion', function (client) {
      return run(client, 'finishVersion.lock',
        kx('sts_risk_dataset_versions').select('parameters').where(key)
          .forUpdate()
      ).then(function (result) {
        const stored = rows(result)[0];
        if (!stored) {
          return false;
        }
        const merged = Object.assign({}, parsed(stored.parameters, {}) || {},
                                     patch.parameters || {});
        return run(client, 'finishVersion.update',
          kx('sts_risk_dataset_versions').update({
            state: patch.state, row_count: Number(patch.rowCount) || 0,
            loaded_at: Number(patch.loadedAt) || 0,
            refusal: String(patch.refusal || ''),
            error_code: String(patch.errorCode || ''),
            parameters: JSON.stringify(merged)
          }).where(key)
        ).then(function (written) {
          return dialect.affected(written) > 0;
        });
      });
    });
  }

  /**
   * An import's progress, only while it is still `loading`: two numbers
   * set in the stored parameters by `JSON_SET()`.
   *
   * @returns true when the version is still loading
   */
  function riskTouchVersion(realm, dataset, version, at, count) {
    log.debug("Entering riskTouchVersion(). " + dataset + " " + version);
    log.debug("Leaving riskTouchVersion().");
    return run(pool, 'touchVersion',
      kx('sts_risk_dataset_versions').update({
        parameters: kx.raw('JSON_SET(??, \'$.progressAt\', ?, ' +
                           '\'$.progressRows\', ?)',
                           ['parameters', Number(at) || 0,
                            Number(count) || 0])
      }).where({ realm: String(realm || ''), dataset: String(dataset),
                 version: String(version), state: 'loading' })
    ).then(function (result) {
      return dialect.affected(result) > 0;
    });
  }

  /**
   * The versions a stopped process left `loading`: read FOR UPDATE and
   * refused by key in one transaction, so two nodes asking at once refuse
   * each once, and what is answered is what was refused.
   *
   * @returns `[{ realm, dataset, version }]`
   */
  function riskAbandonStalled(before, at, why, code) {
    log.debug("Entering riskAbandonStalled().");
    log.debug("Leaving riskAbandonStalled().");
    return unfenced(pool, 'abandonStalled', function (client) {
      return run(client, 'abandonStalled.lock',
        kx('sts_risk_dataset_versions').select('realm', 'dataset', 'version')
          .where('state', 'loading')
          .whereRaw('GREATEST(??, COALESCE(CAST(JSON_VALUE(??, ' +
                    '\'$.progressAt\') AS SIGNED), 0)) < ?',
                    ['fetched_at', 'parameters', Number(before) || 0])
          .forUpdate()
      ).then(function (result) {
        const found = rows(result).map(function (row) {
          return { realm: row.realm, dataset: row.dataset,
                   version: row.version };
        });
        if (!found.length) {
          return found;
        }
        return run(client, 'abandonStalled.update',
          kx('sts_risk_dataset_versions').update({
            state: 'refused', loaded_at: Number(at) || 0,
            refusal: String(why || ''), error_code: String(code || '')
          }).where('state', 'loading')
            .whereIn(['realm', 'dataset', 'version'], found.map(function (f) {
              return [f.realm, f.dataset, f.version];
            }))
        ).then(function () {
          return found;
        });
      });
    });
  }

  /**
   * A version activated, in the driver's fenced transaction with its change
   * row; the native statements one for one (the upsert is `ON DUPLICATE KEY
   * UPDATE`).
   *
   * @returns `{ activated, previous?, unchanged?, state? }`
   */
  function riskActivate(realm, dataset, kind, version, now) {
    log.debug("Entering riskActivate(). " + dataset + " " + version);
    const r0 = bounded('sts_risk_datasets.realm', realm || '', WIDTH.realm);
    const d0 = bounded('sts_risk_datasets.dataset', dataset, WIDTH.dataset);
    log.debug("Leaving riskActivate().");
    return fenced('activate', function (client) {
      return run(client, 'activate.version',
        kx('sts_risk_dataset_versions').select('state')
          .where({ realm: r0, dataset: d0, version: String(version) })
          .forUpdate()
      ).then(function (r) {
        const found = rows(r)[0];
        const state = found ? found.state : '';
        if (state !== 'ready' && state !== 'superseded' &&
            state !== 'active') {
          return { activated: false, state: state };
        }
        return run(client, 'activate.dataset',
          kx('sts_risk_datasets').select('active_version')
            .where({ realm: r0, dataset: d0 }).forUpdate()
        ).then(function (d) {
          const held = rows(d)[0];
          const previous = held ? held.active_version : '';
          if (previous === version) {
            return { activated: true, previous: previous, unchanged: true };
          }
          return run(client, 'activate.upsert',
            kx('sts_risk_datasets').insert({
              realm: r0, dataset: d0, kind: kind,
              active_version: String(version), previous_version: previous,
              state: 'active', updated_at: Number(now)
            }).onConflict(['realm', 'dataset']).merge({
              active_version: String(version), previous_version: previous,
              kind: kind, state: 'active', updated_at: Number(now)
            })
          ).then(function () {
            return run(client, 'activate.supersede',
              kx('sts_risk_dataset_versions')
                .update({ state: 'superseded', superseded_at: Number(now) })
                .where({ realm: r0, dataset: d0, state: 'active' })
                .whereNot('version', String(version)));
          }).then(function () {
            return run(client, 'activate.activate',
              kx('sts_risk_dataset_versions')
                .update({ state: 'active', activated_at: Number(now),
                          superseded_at: 0 })
                .where({ realm: r0, dataset: d0,
                         version: String(version) }));
          }).then(function () {
            return deps.recordChanges(client, [{ kind: 'risk-dataset',
                                                 realm: r0, key: d0 }]);
          }).then(function () {
            return { activated: true, previous: previous };
          });
        });
      });
    });
  }

  /**
   * A version's rows, deleted a batch at a time: `DELETE … LIMIT n` on the
   * primary key's prefix.
   *
   * @returns the count deleted
   */
  function riskDeleteRows(kind, realm, dataset, version, limit) {
    log.debug("Entering riskDeleteRows(). kind=" + kind + " " + dataset +
              " " + version);
    const table = ROW_TABLES[kind];
    if (!table) {
      log.debug("Leaving riskDeleteRows(). Unknown kind.");
      return Promise.resolve(0);
    }
    const where = { dataset: String(dataset), version: String(version) };
    if (kind === 'iplist') {
      where.realm = String(realm || '');
    }
    log.debug("Leaving riskDeleteRows().");
    return run(pool, 'deleteRows.' + kind,
      kx(table).where(where).del().limit(Number(limit) || 10000)
    ).then(function (result) {
      return dialect.affected(result);
    });
  }

  /**
   * The active version removed, in the driver's fenced transaction with its
   * change row, only while it is still the active one.
   *
   * @returns `{ deactivated }`
   */
  function riskDeactivate(realm, dataset, version, now) {
    log.debug("Entering riskDeactivate(). " + dataset + " " + version);
    const r0 = String(realm || '');
    const d0 = String(dataset);
    log.debug("Leaving riskDeactivate().");
    return fenced('deactivate', function (client) {
      return run(client, 'deactivate.dataset',
        kx('sts_risk_datasets').select('active_version')
          .where({ realm: r0, dataset: d0 }).forUpdate()
      ).then(function (d) {
        const held = rows(d)[0];
        const active = held ? held.active_version : '';
        if (!active || active !== version) {
          return { deactivated: false };
        }
        return run(client, 'deactivate.empty',
          kx('sts_risk_datasets')
            .update({ active_version: '', state: 'empty',
                      updated_at: Number(now) })
            .where({ realm: r0, dataset: d0 })
        ).then(function () {
          return run(client, 'deactivate.version',
            kx('sts_risk_dataset_versions')
              .update({ state: 'superseded', superseded_at: Number(now) })
              .where({ realm: r0, dataset: d0, version: String(version),
                       state: 'active' }));
        }).then(function () {
          return deps.recordChanges(client, [{ kind: 'risk-dataset',
                                               realm: r0, key: d0 }]);
        }).then(function () {
          return { deactivated: true };
        });
      });
    });
  }

  /**
   * The version's rows are gone; its row stays, as the record.
   *
   * @returns true when it was marked
   */
  function riskMarkRowsDeleted(realm, dataset, version, now) {
    log.debug("Entering riskMarkRowsDeleted(). " + dataset + " " + version);
    log.debug("Leaving riskMarkRowsDeleted().");
    return run(pool, 'markRowsDeleted',
      kx('sts_risk_dataset_versions')
        .update({ state: 'deleted', rows_deleted_at: Number(now) })
        .where({ realm: String(realm || ''), dataset: String(dataset),
                 version: String(version) })
        .whereNot('state', 'active')
    ).then(function (result) {
      return dialect.affected(result) > 0;
    });
  }

  /**
   * One authenticator model of a FIDO MDS3 version, or null.
   *
   * @returns the model
   */
  function riskLookupFido(dataset, version, keyKind, key) {
    log.debug("Entering riskLookupFido(). " + keyKind);
    log.debug("Leaving riskLookupFido().");
    return run(pool, 'lookupFido',
      kx('sts_risk_fido_authenticators')
        .select('key_kind', 'authenticator_key', 'description',
                'protocol_family', 'certification_level', 'latest_status',
                'latest_status_at', 'compromised', 'status_reports',
                'metadata_statement')
        .where({ dataset: String(dataset), version: String(version),
                 key_kind: String(keyKind),
                 authenticator_key: String(key || '').toLowerCase() })
    ).then(function (result) {
      const row = rows(result)[0];
      return row ? { keyKind: row.key_kind, key: row.authenticator_key,
                     description: row.description,
                     protocolFamily: row.protocol_family,
                     certificationLevel: row.certification_level,
                     latestStatus: row.latest_status,
                     latestStatusAt: Number(row.latest_status_at) || 0,
                     compromised: !!bool(row.compromised),
                     statusReports: parsed(row.status_reports, []) || [],
                     metadataStatement:
                       parsed(row.metadata_statement, {}) || {} }
                 : null;
    });
  }

  /**
   * The range of one version that holds an address: one descending seek
   * of the primary key within the address's family (see the header).
   *
   * @returns the range, or null
   */
  function riskLookupRange(kind, realm, dataset, version, address) {
    log.debug("Entering riskLookupRange(). kind=" + kind);
    const table = RANGE_TABLES[kind];
    if (!table) {
      log.debug("Leaving riskLookupRange(). Unknown kind.");
      return Promise.resolve(null);
    }
    let probe;
    try {
      probe = inet(address, 'an address');
    } catch (err) {
      log.debug("Caught in riskLookupRange(): " + ((err && err.message) ||
                err));
      log.debug("Leaving riskLookupRange(). Not an address.");
      return Promise.reject(err);
    }
    const as6 = function (text) {
      return kx.raw('CAST(? AS INET6)', [text]);
    };
    const inner = kx(table).select('*').where({ dataset: String(dataset),
                                                version: String(version) });
    if (kind === 'iplist') {
      inner.where('realm', String(realm || ''));
    }
    inner.where('range_start', '<=', as6(probe.text));
    if (probe.v4) {
      inner.where('range_start', '>=', as6(V4_LOW));
    } else {
      inner.where(function () {
        this.where('range_start', '<', as6(V4_LOW))
          .orWhere('range_start', '>', as6(V4_HIGH));
      });
    }
    inner.orderBy('range_start', 'desc').limit(1);
    log.debug("Leaving riskLookupRange().");
    return run(pool, 'lookupRange.' + kind,
      kx.select('*').from(inner.as('s'))
        .where('s.range_end', '>=', as6(probe.text))
    ).then(function (result) {
      const row = rows(result)[0];
      if (!row) {
        return null;
      }
      return shapes.range(kind, Object.assign({}, row, {
        range_start: inetText(row.range_start),
        range_end: inetText(row.range_end),
        anonymous_proxy: bool(row.anonymous_proxy),
        satellite: bool(row.satellite)
      }));
    });
  }

  // ===================================================================
  // THE FAILURE HISTORY
  // ===================================================================

  /**
   * One attributable failure, on the tally pool.
   *
   * @returns its id
   */
  function riskRecordFailure(row) {
    log.debug("Entering riskRecordFailure(). door=" + row.door);
    let values;
    try {
      values = {
        realm: bounded('sts_risk_failures.realm', row.realm || '',
                       WIDTH.realm),
        at: Number(row.at), door: row.door,
        subject: bounded('sts_risk_failures.subject', row.subject || '',
                         WIDTH.subject),
        name_hmac: bounded('sts_risk_failures.name_hmac', row.nameHmac || '',
                           WIDTH.nameHmac),
        address_sealed: row.addressSealed || '',
        address_prefix: bounded('sts_risk_failures.address_prefix',
                                row.addressPrefix, WIDTH.prefix),
        asn: Number(row.asn) || 0, error_code: row.errorCode,
        origin: deps.processId()
      };
    } catch (err) {
      log.debug("Caught in riskRecordFailure(): " + ((err && err.message) ||
                err));
      log.debug("Leaving riskRecordFailure(). Refused.");
      return Promise.reject(err);
    }
    log.debug("Leaving riskRecordFailure().");
    return run(tallyPool, 'recordFailure',
      kx('sts_risk_failures').insert(values)
    ).then(function (result) {
      return result && result.insertId !== undefined &&
        result.insertId !== null ? String(result.insertId) : '';
    });
  }

  /**
   * The failures' filter, on a builder.
   *
   * @returns the builder
   */
  function failureWhere(built, realm, o) {
    log.debug("Entering failureWhere().");
    built.where('realm', String(realm || ''))
      .where('at', '>=', Number(o.since) || 0);
    if (o.subject) {
      built.where('subject', String(o.subject));
    }
    if (o.nameHmac) {
      built.where('name_hmac', String(o.nameHmac));
    }
    // A prefix is compared as the text this service wrote: every prefix is
    // `RiskStore.prefixOf()`'s, which is how `inet` prints one.
    if (o.prefix) {
      built.where('address_prefix', String(o.prefix));
    }
    if (o.door) {
      built.where('door', String(o.door));
    }
    const excluded = [].concat(o.excludeDoor || []).map(String);
    if (excluded.length) {
      built.whereNotIn('door', excluded);
    }
    log.debug("Leaving failureWhere().");
    return built;
  }

  /**
   * A page of one realm's failures, newest first, with the matching count.
   *
   * @returns `{ rows, total }`
   */
  function riskListFailures(realm, opts) {
    log.debug("Entering riskListFailures(). realm=" + realm);
    const o = opts || {};
    log.debug("Leaving riskListFailures().");
    return Promise.all([
      run(pool, 'listFailures.rows',
        failureWhere(kx('sts_risk_failures').select(
          'id', 'realm', 'at', 'door', 'subject', 'name_hmac',
          'address_sealed', 'address_prefix', 'asn', 'error_code', 'origin'),
        realm, o)
          .orderBy([{ column: 'at', order: 'desc' },
                    { column: 'id', order: 'desc' }])
          .limit(Number(o.limit) || 50).offset(Number(o.offset) || 0)),
      run(pool, 'listFailures.total',
        failureWhere(kx('sts_risk_failures').count('* as total'), realm, o))
    ]).then(function (answers) {
      return { rows: rows(answers[0]).map(shapes.failure),
               total: Number((rows(answers[1])[0] || {}).total) || 0 };
    });
  }

  /**
   * Failures older than `beforeMs`, a batch at a time.
   *
   * @returns the count deleted
   */
  function riskPurgeFailures(beforeMs, limit) {
    log.debug("Entering riskPurgeFailures().");
    log.debug("Leaving riskPurgeFailures().");
    return run(pool, 'purgeFailures',
      kx('sts_risk_failures').where('at', '<', Number(beforeMs)).del()
        .limit(Number(limit) || 10000)
    ).then(function (result) {
      return dialect.affected(result);
    });
  }

  // ===================================================================
  // THE MODEL'S HISTORY
  // ===================================================================

  /**
   * The counts of the given (feature, value) pairs for one subject; a pair
   * never seen is left out.
   *
   * @returns `[{ feature, value, count }]`
   */
  function riskFeatureCounts(realm, subject, pairs) {
    log.debug("Entering riskFeatureCounts(). pairs=" + pairs.length);
    if (!pairs.length) {
      log.debug("Leaving riskFeatureCounts(). No pairs.");
      return Promise.resolve([]);
    }
    log.debug("Leaving riskFeatureCounts().");
    return run(pool, 'featureCounts',
      kx('sts_risk_feature_counts').select('feature', 'value', 'count')
        .where({ realm: String(realm || ''), subject: String(subject) })
        .whereIn(['feature', 'value'], pairs.map(function (p) {
          return [String(p.feature), String(p.value)];
        }))
    ).then(function (result) {
      return rows(result).map(function (row) {
        return { feature: row.feature, value: row.value,
                 count: Number(row.count) || 0 };
      });
    });
  }

  /**
   * A counts query narrowed to one feature, and to the values beginning
   * with `prefix` when there is one (`starts_with()`: a LIKE whose pattern
   * escapes its own wildcards with `!`, a character the session does not
   * treat as an escape anywhere else).
   *
   * @returns the builder
   */
  function distinctOf(realm, subject, feature, prefix) {
    log.debug("Entering distinctOf().");
    const built = kx('sts_risk_feature_counts').count('* as n')
      .where({ realm: String(realm || ''), subject: String(subject),
               feature: String(feature) });
    if (String(prefix || '')) {
      built.whereRaw('?? LIKE ? ESCAPE \'!\'',
                     ['value', String(prefix).replace(/[!%_]/g, '!$&') + '%']);
    }
    log.debug("Leaving distinctOf().");
    return built;
  }

  /**
   * How many distinct values a feature has for one subject.
   *
   * @returns the count
   */
  function riskDistinctValues(realm, subject, feature, prefix) {
    log.debug("Entering riskDistinctValues(). " + feature);
    log.debug("Leaving riskDistinctValues().");
    return run(pool, 'distinctValues',
      distinctOf(realm, subject, feature, prefix)
    ).then(function (result) {
      return Number((rows(result)[0] || {}).n) || 0;
    });
  }

  /**
   * Every distinct-value count one assessment asks, in ONE statement: a
   * select list of one scalar subquery per ask, in order.
   *
   * @returns the counts in the order asked
   */
  function riskDistinctValuesMany(realm, subject, asks) {
    log.debug("Entering riskDistinctValuesMany(). asks=" + asks.length);
    if (!asks.length) {
      log.debug("Leaving riskDistinctValuesMany(). Nothing asked.");
      return Promise.resolve([]);
    }
    log.debug("Leaving riskDistinctValuesMany().");
    return run(pool, 'distinctValuesMany',
      kx.select(asks.map(function (one, i) {
        return distinctOf(realm, subject, one.feature, one.prefix)
          .as('n' + i);
      }))
    ).then(function (result) {
      const row = rows(result)[0] || {};
      return asks.map(function (one, i) {
        return Number(row['n' + i]) || 0;
      });
    });
  }

  /**
   * One sign-in counted: each (subject, feature, value) up by one in ONE
   * statement, its rows in key order, on the tally pool.
   *
   * @returns the rows counted
   */
  function riskIncrementCounts(realm, moves, at) {
    log.debug("Entering riskIncrementCounts(). rows=" + moves.length);
    if (!moves.length) {
      log.debug("Leaving riskIncrementCounts(). Nothing.");
      return Promise.resolve(0);
    }
    let values;
    try {
      const r0 = bounded('sts_risk_feature_counts.realm', realm || '',
                         WIDTH.realm);
      values = moves.map(function (m) {
        return {
          realm: r0,
          subject: bounded('sts_risk_feature_counts.subject', m.subject,
                           WIDTH.subject),
          feature: bounded('sts_risk_feature_counts.feature', m.feature,
                           WIDTH.feature),
          value: bounded('sts_risk_feature_counts.value', m.value,
                         WIDTH.value),
          count: 1, first_at: Number(at), last_at: Number(at)
        };
      }).sort(function (a, b) {
        const ka = a.subject + '\u0000' + a.feature + '\u0000' + a.value;
        const kb = b.subject + '\u0000' + b.feature + '\u0000' + b.value;
        return ka < kb ? -1 : ka > kb ? 1 : 0;
      });
    } catch (err) {
      log.debug("Caught in riskIncrementCounts(): " + ((err &&
                err.message) || err));
      log.debug("Leaving riskIncrementCounts(). Refused.");
      return Promise.reject(err);
    }
    log.debug("Leaving riskIncrementCounts().");
    return retrying('incrementCounts', function () {
      return run(tallyPool, 'incrementCounts',
        kx('sts_risk_feature_counts').insert(values)
          .onConflict(['realm', 'subject', 'feature', 'value']).merge({
            count: kx.raw('?? + 1', ['sts_risk_feature_counts.count']),
            last_at: Number(at)
          }));
    }).then(function () {
      // MariaDB counts an updated row twice; every row was either inserted
      // or counted, which is what PostgreSQL's rowCount says.
      return values.length;
    });
  }

  // ===================================================================
  // THE ASSESSMENTS
  // ===================================================================

  /**
   * One assessment, first writer wins, on the tally pool.
   *
   * @returns true when it was written
   */
  function riskRecordAssessment(a) {
    log.debug("Entering riskRecordAssessment(). " + a.id);
    const optional = function (value) {
      return value === null || value === undefined ? null : Number(value);
    };
    let values;
    try {
      values = {
        realm: bounded('sts_risk_assessments.realm', a.realm || '',
                       WIDTH.realm),
        id: bounded('sts_risk_assessments.id', a.id, WIDTH.id),
        at: Number(a.at), phase: a.phase, door: a.door,
        subject: bounded('sts_risk_assessments.subject', a.subject || '',
                         WIDTH.subject),
        session_id: bounded('sts_risk_assessments.session_id',
                            a.sessionId || '', WIDTH.sessionId),
        client_id: a.clientId || '', address_sealed: a.addressSealed || '',
        address_prefix: bounded('sts_risk_assessments.address_prefix',
                                a.addressPrefix, WIDTH.prefix),
        asn: Number(a.asn) || 0, as_org: a.asOrg || '',
        country: a.country || '', subdivision: a.subdivision || '',
        city: a.city || '', latitude: optional(a.latitude),
        longitude: optional(a.longitude),
        accuracy_km: Number(a.accuracyKm) || 0,
        ip_lists: JSON.stringify((a.ipLists || []).map(String)),
        ua_hash: a.uaHash || '', ua_family: a.uaFamily || '',
        ua_os: a.uaOs || '', ua_platform: a.uaPlatform || '', bot: !!a.bot,
        ja4: a.ja4 || '', credential_kind: a.credentialKind || '',
        credential_hash: a.credentialHash || '', aaguid: a.aaguid || '',
        authenticator_cert: a.authenticatorCert || '',
        backup_eligible: typeof a.backupEligible === 'boolean'
          ? a.backupEligible : null,
        backup_state: typeof a.backupState === 'boolean'
          ? a.backupState : null,
        jkt: a.jkt || '', cert_fingerprint: a.certFingerprint || '',
        datasets: JSON.stringify(a.datasets || {}),
        signals: JSON.stringify(a.signals || []),
        score: Number(a.score), level: a.level, decision: a.decision,
        policy_id: a.policyId || '', error_code: a.errorCode || '',
        origin: deps.processId()
      };
    } catch (err) {
      log.debug("Caught in riskRecordAssessment(): " + ((err &&
                err.message) || err));
      log.debug("Leaving riskRecordAssessment(). Refused.");
      return Promise.reject(err);
    }
    log.debug("Leaving riskRecordAssessment().");
    return run(tallyPool, 'recordAssessment',
      kx('sts_risk_assessments').insert(values)
    ).then(function () {
      return true;
    }, function (err) {
      if (dialect.isUniqueViolation(err)) {
        log.debug("Caught in riskRecordAssessment(): already written.");
        return false;
      }
      throw err;
    });
  }

  /**
   * The assessments' filter, on a builder.
   *
   * @returns the builder
   */
  function assessmentWhere(built, realm, o) {
    log.debug("Entering assessmentWhere().");
    built.where('realm', String(realm || ''))
      .where('at', '>=', Number(o.since) || 0);
    if (o.subject) {
      built.where('subject', String(o.subject));
    }
    if (o.level) {
      built.where('level', String(o.level));
    }
    log.debug("Leaving assessmentWhere().");
    return built;
  }

  /**
   * A page of one realm's assessments, newest first, with the matching
   * count. Never the sealed address.
   *
   * @returns `{ total, rows }`
   */
  function riskListAssessments(realm, opts) {
    log.debug("Entering riskListAssessments(). realm=" + realm);
    const o = opts || {};
    log.debug("Leaving riskListAssessments().");
    return Promise.all([
      run(pool, 'listAssessments.rows',
        assessmentWhere(kx('sts_risk_assessments').select(
          'id', 'at', 'phase', 'door', 'subject', 'session_id', 'client_id',
          'address_prefix', 'asn', 'as_org', 'country', 'subdivision',
          'city', 'ip_lists', 'ua_family', 'ua_os', 'ua_platform', 'bot',
          'ja4', 'credential_kind', 'aaguid', 'backup_eligible',
          'backup_state', 'datasets', 'signals',
          kx.raw('CAST(?? AS DOUBLE) AS ??', ['score', 'score']),
          'level', 'decision', 'feedback', 'feedback_at'), realm, o)
          .orderBy([{ column: 'at', order: 'desc' },
                    { column: 'id', order: 'desc' }])
          .limit(Number(o.limit) || 50).offset(Number(o.offset) || 0)),
      run(pool, 'listAssessments.total',
        assessmentWhere(kx('sts_risk_assessments').count('* as total'),
                        realm, o))
    ]).then(function (answers) {
      return {
        total: Number((rows(answers[1])[0] || {}).total) || 0,
        rows: rows(answers[0]).map(function (r) {
          return { id: r.id, at: Number(r.at), phase: r.phase,
                   door: r.door, subject: r.subject,
                   sessionId: r.session_id, clientId: r.client_id,
                   addressPrefix: String(r.address_prefix),
                   asn: Number(r.asn) || 0, asOrg: r.as_org,
                   country: r.country, subdivision: r.subdivision,
                   city: r.city, ipLists: parsed(r.ip_lists, []) || [],
                   uaFamily: r.ua_family, uaOs: r.ua_os,
                   uaPlatform: r.ua_platform, bot: !!bool(r.bot), ja4: r.ja4,
                   credentialKind: r.credential_kind, aaguid: r.aaguid,
                   backupEligible: bool(r.backup_eligible),
                   backupState: bool(r.backup_state),
                   datasets: parsed(r.datasets, {}) || {},
                   signals: parsed(r.signals, []) || [],
                   score: real(r.score), level: r.level,
                   decision: r.decision, feedback: r.feedback || '',
                   feedbackAt: Number(r.feedback_at) || 0 };
        })
      };
    });
  }

  /**
   * What the person said about one of their own sign-ins: only that
   * subject's, and only once.
   *
   * @returns true when it was recorded
   */
  function riskSetFeedback(realm, id, subject, feedback, at) {
    log.debug("Entering riskSetFeedback(). " + id);
    log.debug("Leaving riskSetFeedback().");
    return run(pool, 'setFeedback',
      kx('sts_risk_assessments')
        .update({ feedback: feedback, feedback_at: Number(at) })
        .where({ realm: String(realm || ''), id: String(id),
                 subject: String(subject), feedback: '' })
    ).then(function (result) {
      return dialect.affected(result) > 0;
    });
  }

  /**
   * What was decided on an assessment; a session id only filled in, never
   * cleared (the native CASE, decided here: an empty one is not set).
   *
   * @returns true when the assessment exists
   */
  function riskSettleAssessment(a) {
    log.debug("Entering riskSettleAssessment(). " + a.id);
    const update = { decision: a.decision || '', policy_id: a.policyId || '',
                     error_code: a.errorCode || '' };
    if (a.sessionId) {
      update.session_id = bounded('sts_risk_assessments.session_id',
                                  a.sessionId, WIDTH.sessionId);
    }
    log.debug("Leaving riskSettleAssessment().");
    return run(tallyPool, 'settleAssessment',
      kx('sts_risk_assessments').update(update)
        .where({ realm: String(a.realm || ''), id: String(a.id) })
    ).then(function (result) {
      return dialect.affected(result) > 0;
    });
  }

  /**
   * An assessment's signals, score and level rewritten with its device.
   *
   * @returns true when the assessment exists
   */
  function riskAmendAssessment(a) {
    log.debug("Entering riskAmendAssessment(). " + a.id);
    log.debug("Leaving riskAmendAssessment().");
    return run(tallyPool, 'amendAssessment',
      kx('sts_risk_assessments').update({
        signals: JSON.stringify(a.signals || []), score: Number(a.score),
        level: a.level || ''
      }).where({ realm: String(a.realm || ''), id: String(a.id) })
    ).then(function (result) {
      return dialect.affected(result) > 0;
    });
  }

  // ===================================================================
  // EACH PERSON'S STANDING
  // ===================================================================

  /**
   * A reaction claimed once: one conditional UPDATE (see the header), on
   * the write pool, durable at commit.
   *
   * @returns true for the one caller that claimed it
   */
  function riskClaimAction(realm, subject, reaction, assessmentId) {
    log.debug("Entering riskClaimAction(). " + reaction);
    // The member's path, its name a quoted JSON string, so any name is one
    // member and never a path. Built here, not with the engine's
    // `JSON_QUOTE()`, whose answer is `utf8mb4_bin` and cannot be
    // concatenated with the session's `utf8mb4_nopad_bin` literal.
    const path = '$.' + JSON.stringify(String(reaction));
    log.debug("Leaving riskClaimAction().");
    return run(pool, 'claimAction',
      kx('sts_risk_subjects').update({
        actions: kx.raw('JSON_SET(??, ?, ?)',
                        ['actions', path, String(assessmentId || '')])
      }).where({ realm: String(realm || ''), subject: String(subject || '') })
        .whereRaw('NOT (JSON_VALUE(??, ?) <=> ?)',
                  ['actions', path, String(assessmentId || '')])
    ).then(function (result) {
      return dialect.affected(result) > 0;
    });
  }

  /**
   * A standing row as `risk/risk_store.ts` works in it.
   *
   * @param row - the row as read
   * @returns the standing
   */
  function subjectFrom(row) {
    log.debug("Entering subjectFrom().");
    log.debug("Leaving subjectFrom().");
    return { subject: row.subject, score: real(row.score), level: row.level,
             previousLevel: row.previous_level, reason: row.reason,
             lastAssessment: row.last_assessment,
             crossedAt: Number(row.crossed_at) || 0,
             updatedAt: Number(row.updated_at) || 0 };
  }

  const SUBJECT_COLUMNS = ['subject',
                           kx.raw('CAST(?? AS DOUBLE) AS ??',
                                  ['score', 'score']),
                           'level', 'previous_level', 'reason',
                           'last_assessment', 'crossed_at', 'updated_at'];

  /**
   * One person's standing, or null.
   *
   * @returns the standing
   */
  function riskSubjectOf(realm, subject) {
    log.debug("Entering riskSubjectOf(). realm=" + realm);
    log.debug("Leaving riskSubjectOf().");
    return run(pool, 'subjectOf',
      kx('sts_risk_subjects').select(SUBJECT_COLUMNS)
        .where({ realm: String(realm || ''), subject: String(subject || '') })
    ).then(function (result) {
      const row = rows(result)[0];
      return row ? subjectFrom(row) : null;
    });
  }

  /**
   * A person's standing replaced whole, the level it replaced read under
   * the row's lock in the same transaction (on the tally pool, as the
   * native upsert); a change of level is a `risk-standing` change row,
   * recorded after COMMIT as there.
   *
   * @returns true
   */
  function riskUpsertSubject(s) {
    log.debug("Entering riskUpsertSubject().");
    let key;
    try {
      key = {
        realm: bounded('sts_risk_subjects.realm', s.realm || '',
                       WIDTH.realm),
        subject: bounded('sts_risk_subjects.subject', s.subject,
                         WIDTH.subject)
      };
    } catch (err) {
      log.debug("Caught in riskUpsertSubject(): " + ((err && err.message) ||
                err));
      log.debug("Leaving riskUpsertSubject(). Refused.");
      return Promise.reject(err);
    }
    const level = String(s.level);
    const at = Number(s.updatedAt);
    const write = function (client, left) {
      return run(client, 'upsertSubject.lock',
        kx('sts_risk_subjects').select('level', 'crossed_at').where(key)
          .forUpdate()
      ).then(function (result) {
        const stored = rows(result)[0];
        if (stored) {
          const before = String(stored.level);
          return run(client, 'upsertSubject.update',
            kx('sts_risk_subjects').update({
              score: Number(s.score), level: level, previous_level: before,
              reason: s.reason || '', last_assessment: s.lastAssessment || '',
              crossed_at: before !== level ? at
                : Number(stored.crossed_at) || 0,
              updated_at: at
            }).where(key)
          ).then(function () {
            return before;
          });
        }
        return run(client, 'upsertSubject.insert',
          kx('sts_risk_subjects').insert(Object.assign({}, key, {
            score: Number(s.score), level: level, previous_level: '',
            reason: s.reason || '', last_assessment: s.lastAssessment || '',
            crossed_at: at, actions: '{}', feedback: '', updated_at: at
          }))
        ).then(function () {
          return '';
        }, function (err) {
          // A first standing written by somebody else meanwhile: it is
          // committed now (InnoDB waited for it), so it is read again.
          if (left > 0 && dialect.isUniqueViolation(err)) {
            log.debug("Caught in riskUpsertSubject(): written meanwhile.");
            return write(client, left - 1);
          }
          throw err;
        });
      });
    };
    log.debug("Leaving riskUpsertSubject().");
    return unfenced(tallyPool, 'upsertSubject', function (client) {
      return write(client, 2);
    }).then(function (before) {
      if (!before || before === level) {
        return true;
      }
      return deps.recordChanges(tallyPool, [{ kind: 'risk-standing',
                                              realm: key.realm,
                                              key: key.subject }])
        .then(function () {
          return true;
        }, function (e) {
          log.debug("Caught in riskUpsertSubject(): " +
                    ((e && e.message) || e));
          // The standing is written; only the word to the other processes
          // is lost, as in the driver's own statement.
          log.warn(errorCodes.tag('STS-RISK-0054') + 'risk: a change of ' +
                   'standing could not be announced to the other ' +
                   'processes: ' + ((e && e.message) || e));
          return true;
        });
    });
  }

  /**
   * A page of the realm's people by current standing, with the count.
   *
   * @returns `{ total, rows }`
   */
  function riskListSubjects(realm, opts) {
    log.debug("Entering riskListSubjects(). realm=" + realm);
    const o = opts || {};
    log.debug("Leaving riskListSubjects().");
    return Promise.all([
      run(pool, 'listSubjects.rows',
        kx('sts_risk_subjects').select(SUBJECT_COLUMNS)
          .where('realm', String(realm || ''))
          .orderBy([{ column: 'sts_risk_subjects.score', order: 'desc' },
                    { column: 'updated_at', order: 'desc' },
                    { column: 'subject' }])
          .limit(Number(o.limit) || 50).offset(Number(o.offset) || 0)),
      run(pool, 'listSubjects.total',
        kx('sts_risk_subjects').count('* as total')
          .where('realm', String(realm || '')))
    ]).then(function (answers) {
      return {
        total: Number((rows(answers[1])[0] || {}).total) || 0,
        rows: rows(answers[0]).map(subjectFrom)
      };
    });
  }

  /**
   * How many of one realm's people stand at each level now.
   *
   * @returns level -> count
   */
  function riskSubjectLevels(realm) {
    log.debug("Entering riskSubjectLevels(). realm=" + realm);
    log.debug("Leaving riskSubjectLevels().");
    return run(pool, 'subjectLevels',
      kx('sts_risk_subjects').select('level').count('* as n')
        .where('realm', String(realm || '')).groupBy('level')
    ).then(function (result) {
      const out = {};
      rows(result).forEach(function (row) {
        out[row.level || 'UNSCORED'] = Number(row.n);
      });
      return out;
    });
  }

  // ===================================================================
  // MONITORING: THE COUNTED WINDOW AND THE GEOGRAPHY
  // ===================================================================

  /**
   * A window of one realm's assessments counted (the driver's statement
   * argues the shapes; the header here, the MariaDB forms).
   *
   * @returns `{ quantiles, totals, groups, series }`
   */
  function riskAssessmentMetrics(realm, opts) {
    log.debug("Entering riskAssessmentMetrics(). realm=" + realm);
    const o = opts || {};
    const r0 = String(realm || '');
    const since = Number(o.since) || 0;
    const window = function (built) {
      return built.where('realm', r0).where('at', '>=', since);
    };
    const band = 'CASE WHEN score < 0.01 THEN \'< 0.01\' ' +
      'WHEN score < 0.1 THEN \'0.01 – 0.1\' ' +
      'WHEN score < 1 THEN \'0.1 – 1\' ' +
      'WHEN score < 10 THEN \'1 – 10\' ' +
      'WHEN score < 100 THEN \'10 – 100\' ELSE \'≥ 100\' END';
    const plain = function (k, expression, extra) {
      const built = window(kx('sts_risk_assessments')
        .select(kx.raw('? AS k', [k]), kx.raw(expression + ' AS v')));
      return extra ? extra(built) : built;
    };
    const answered = function (built) {
      return built.whereNot('feedback', '');
    };
    // A signal per element of the assessment's array, its `signal` member
    // as text (NULL where it has none, as `->>` answers).
    const perSignal = function (k, expression, extra) {
      const built = window(kx('sts_risk_assessments')
        .select(kx.raw('? AS k', [k]), kx.raw(expression + ' AS v'))
        .joinRaw(', JSON_TABLE(??, \'$[*]\' COLUMNS (sig LONGTEXT PATH ' +
                 '\'$.signal\')) AS s', ['signals']));
      return extra ? extra(built) : built;
    };
    const parts = [
      plain('level', 'level'), plain('door', 'door'),
      plain('decision', 'decision'), plain('phase', 'phase'),
      plain('country', 'country'), plain('band', band),
      plain('feedback', 'feedback', answered),
      perSignal('signal', 's.sig'),
      perSignal('signal-level', 'CONCAT(s.sig, CHAR(1 USING utf8mb4), level)'),
      perSignal('signal-feedback',
                'CONCAT(s.sig, CHAR(1 USING utf8mb4), feedback)', answered)
    ];
    const grouped = kx.select('k', 'v').count('* as n')
      .from(kx.unionAll(parts, true).as('grouped')).groupBy('k', 'v');
    const bucketMs = Math.max(60000, Number(o.bucketMs) || 3600000);
    const quantiles = (o.quantiles || []).map(Number);
    log.debug("Leaving riskAssessmentMetrics().");
    return Promise.all([
      run(pool, 'assessmentMetrics.totals',
        window(kx('sts_risk_assessments').select(
          kx.raw('count(*) AS total'),
          kx.raw('count(DISTINCT subject) AS subjects'),
          kx.raw('coalesce(sum(CASE WHEN bot THEN 1 ELSE 0 END), 0) AS bots'),
          kx.raw('coalesce(avg(CAST(score AS DOUBLE)), 0) AS mean_score'),
          kx.raw('coalesce(max(CAST(score AS DOUBLE)), 0) AS max_score')))),
      run(pool, 'assessmentMetrics.groups', grouped),
      run(pool, 'assessmentMetrics.series',
        window(kx('sts_risk_assessments').select(
          kx.raw('(at DIV ?) * ? AS bucket', [bucketMs, bucketMs]), 'level')
          .count('* as n')).groupBy('bucket', 'level')),
      quantiles.length
        ? run(pool, 'assessmentMetrics.quantiles',
          window(kx('sts_risk_assessments').select(quantiles.map(
            function (f, i) {
              return kx.raw('PERCENTILE_DISC(?) WITHIN GROUP (ORDER BY ' +
                            'CAST(score AS DOUBLE)) OVER () AS ??',
                            [f, 'q' + i]);
            }))).limit(1))
        : Promise.resolve({ rows: [] })
    ]).then(function (answers) {
      const t = rows(answers[0])[0] || {};
      const got = rows(answers[3])[0] || {};
      const byFraction = {};
      quantiles.forEach(function (f, i) {
        const q = got['q' + i];
        if (q !== null && q !== undefined) {
          byFraction[String(f)] = real(q);
        }
      });
      return {
        quantiles: byFraction,
        totals: { total: Number(t.total) || 0,
                  subjects: Number(t.subjects) || 0,
                  bots: Number(t.bots) || 0,
                  meanScore: Number(t.mean_score) || 0,
                  maxScore: real(t.max_score) || 0 },
        groups: rows(answers[1]).map(function (r) {
          return { k: r.k, v: r.v === null ? '' : String(r.v),
                   n: Number(r.n) };
        }),
        series: rows(answers[2]).map(function (r) {
          return { bucket: Number(r.bucket), level: r.level,
                   n: Number(r.n) };
        })
      };
    });
  }

  /**
   * Where a window's people were: one ROLLUP over the four columns, its
   * extra level (a subdivision without its city) dropped, and the world's
   * row supplied for an empty window (see the header).
   *
   * @returns `{ rows }`
   */
  function riskGeography(realm, opts) {
    log.debug("Entering riskGeography(). realm=" + realm);
    const o = opts || {};
    const r0 = String(realm || '');
    const since = Number(o.since) || 0;
    const countries = (o.countries || []).map(String);
    const continents = (o.continents || []).map(String);
    // The page's code-to-continent table as one CASE: '' for a code it
    // does not name, as the native LEFT JOIN's coalesce answers.
    let continent = '\'\'';
    const pairs = [];
    countries.forEach(function (code, i) {
      pairs.push(code, continents[i] === undefined ? null : continents[i]);
    });
    if (countries.length) {
      continent = 'coalesce(CASE country ' + countries.map(function () {
        return 'WHEN ? THEN ?';
      }).join(' ') + ' END, \'\')';
    }
    let source;
    if (Array.isArray(o.sessionIds)) {
      // Each live session's latest assessment only: DISTINCT ON, as a
      // ROW_NUMBER() over the session's rows, newest first.
      const ranked = kx('sts_risk_assessments')
        .select('*', kx.raw('ROW_NUMBER() OVER (PARTITION BY session_id ' +
                            'ORDER BY at DESC) AS sts_rank'))
        .where('realm', r0).where('at', '>=', since).whereNot('subject', '')
        .whereIn('session_id', o.sessionIds.map(String));
      source = kx.select('*').from(ranked.as('r')).where('sts_rank', 1);
    } else {
      source = kx('sts_risk_assessments').select('*').where('realm', r0)
        .where('at', '>=', since).whereNot('subject', '');
    }
    const a = kx.select('subject', 'phase', 'country', 'subdivision', 'city',
                        'latitude', 'longitude', 'at',
                        kx.raw(continent + ' AS continent', pairs))
      .from(source.as('s'));
    const built = kx.select('continent', 'country', 'subdivision', 'city',
      kx.raw('count(DISTINCT subject) AS people'),
      kx.raw('coalesce(sum(CASE WHEN phase = \'user\' THEN 1 ELSE 0 END), ' +
             '0) AS sign_ins'),
      kx.raw('count(*) AS assessments'),
      kx.raw('avg(latitude) AS latitude'),
      kx.raw('avg(longitude) AS longitude'), kx.raw('max(at) AS last_at'))
      .from(a.as('a'))
      .groupByRaw('continent, country, subdivision, city WITH ROLLUP');
    log.debug("Leaving riskGeography().");
    return run(pool, 'geography', built).then(function (result) {
      const out = [];
      rows(result).forEach(function (row) {
        let level;
        if (row.continent === null) {
          level = 'world';
        } else if (row.country === null) {
          level = 'continent';
        } else if (row.subdivision === null) {
          level = 'country';
        } else if (row.city === null) {
          // ROLLUP's (continent, country, subdivision) level, which the
          // native grouping sets do not have.
          return;
        } else {
          level = 'city';
        }
        out.push({
          level: level, continent: row.continent || '',
          country: row.country || '', subdivision: row.subdivision || '',
          city: row.city || '', people: Number(row.people) || 0,
          signIns: Number(row.sign_ins) || 0,
          assessments: Number(row.assessments) || 0,
          latitude: row.latitude === null ? null : Number(row.latitude),
          longitude: row.longitude === null ? null : Number(row.longitude),
          lastAt: Number(row.last_at) || 0
        });
      });
      if (!out.length) {
        out.push({ level: 'world', continent: '', country: '',
                   subdivision: '', city: '', people: 0, signIns: 0,
                   assessments: 0, latitude: null, longitude: null,
                   lastAt: 0 });
      }
      return { rows: out };
    });
  }

  // ===================================================================
  // SESSION CONTEXTS, RETENTION AND THE TERMS
  // ===================================================================

  /**
   * The last context a live session was assessed in, replaced whole, in
   * one statement on the tally pool.
   *
   * @returns true
   */
  function riskUpsertSessionContext(c) {
    log.debug("Entering riskUpsertSessionContext().");
    let values;
    try {
      values = {
        realm: bounded('sts_risk_session_context.realm', c.realm || '',
                       WIDTH.realm),
        session_id: bounded('sts_risk_session_context.session_id',
                            c.sessionId, WIDTH.sessionId),
        subject: String(c.subject),
        address_prefix: bounded('sts_risk_session_context.address_prefix',
                                c.addressPrefix, WIDTH.prefix),
        asn: Number(c.asn) || 0, country: c.country || '',
        ua_hash: c.uaHash || '', ja4: c.ja4 || '', jkt: c.jkt || '',
        score: Number(c.score), level: c.level,
        updated_at: Number(c.updatedAt)
      };
    } catch (err) {
      log.debug("Caught in riskUpsertSessionContext(): " + ((err &&
                err.message) || err));
      log.debug("Leaving riskUpsertSessionContext(). Refused.");
      return Promise.reject(err);
    }
    const replaced = Object.assign({}, values);
    delete replaced.realm;
    delete replaced.session_id;
    log.debug("Leaving riskUpsertSessionContext().");
    return retrying('upsertSessionContext', function () {
      return run(tallyPool, 'upsertSessionContext',
        kx('sts_risk_session_context').insert(values)
          .onConflict(['realm', 'session_id']).merge(replaced));
    }).then(function (result) {
      return dialect.affected(result) > 0;
    });
  }

  /**
   * Assessments, feature counts and session contexts past their retention,
   * a batch at a time.
   *
   * @returns the count deleted
   */
  function riskPurgeHistory(table, beforeMs, limit) {
    log.debug("Entering riskPurgeHistory(). " + table);
    const column = { assessments: 'at', counts: 'last_at',
                     sessions: 'updated_at' }[table];
    const name = { assessments: 'sts_risk_assessments',
                   counts: 'sts_risk_feature_counts',
                   sessions: 'sts_risk_session_context' }[table];
    if (!column) {
      log.debug("Leaving riskPurgeHistory(). Unknown table.");
      return Promise.resolve(0);
    }
    log.debug("Leaving riskPurgeHistory().");
    return run(pool, 'purgeHistory.' + table,
      kx(name).where(column, '<', Number(beforeMs)).del()
        .limit(Number(limit) || 10000)
    ).then(function (result) {
      return dialect.affected(result);
    });
  }

  /**
   * One acceptance, appended.
   *
   * @returns its id
   */
  function riskRecordAcceptance(a) {
    log.debug("Entering riskRecordAcceptance(). " + a.provider);
    let provider;
    try {
      provider = bounded('sts_risk_terms_acceptances.provider', a.provider,
                         WIDTH.provider);
    } catch (err) {
      log.debug("Caught in riskRecordAcceptance(): " + ((err &&
                err.message) || err));
      log.debug("Leaving riskRecordAcceptance(). Refused.");
      return Promise.reject(err);
    }
    log.debug("Leaving riskRecordAcceptance().");
    return run(pool, 'recordAcceptance',
      kx('sts_risk_terms_acceptances').insert({
        provider: provider, terms_digest: a.termsDigest,
        terms_text: a.termsText, accepted_by: a.acceptedBy,
        accepted_via: a.acceptedVia, deployment: a.deployment || '',
        page_digest: a.pageDigest || '', accepted_at: Number(a.acceptedAt),
        origin: deps.processId()
      })
    ).then(function (result) {
      return result && result.insertId !== undefined &&
        result.insertId !== null ? String(result.insertId) : '';
    });
  }

  /**
   * Every acceptance, newest first.
   *
   * @returns the acceptances
   */
  function riskListAcceptances() {
    log.debug("Entering riskListAcceptances().");
    log.debug("Leaving riskListAcceptances().");
    return run(pool, 'listAcceptances',
      kx('sts_risk_terms_acceptances')
        .select('id', 'provider', 'terms_digest', 'terms_text',
                'accepted_by', 'accepted_via', 'deployment', 'page_digest',
                'accepted_at')
        .orderBy([{ column: 'accepted_at', order: 'desc' },
                  { column: 'id', order: 'desc' }])
    ).then(function (result) {
      return rows(result).map(function (row) {
        return { id: String(row.id), provider: row.provider,
                 termsDigest: row.terms_digest, termsText: row.terms_text,
                 acceptedBy: row.accepted_by,
                 acceptedVia: row.accepted_via,
                 deployment: row.deployment, pageDigest: row.page_digest,
                 acceptedAt: Number(row.accepted_at) || 0 };
      });
    });
  }

  /**
   * An operation whose synchronous refusal (a value measured before
   * anything is sent) is a rejected promise, as a refused statement is.
   *
   * @param fn - the operation
   * @returns the operation, answering a promise always
   */
  function promised(fn) {
    log.debug("Entering promised().");
    log.debug("Leaving promised().");
    return function () {
      try {
        return Promise.resolve(fn.apply(null, arguments));
      } catch (err) {
        log.debug("Caught in promised(): " + ((err && err.message) || err));
        return Promise.reject(err);
      }
    };
  }

  const operations = {
    riskListDatasets: riskListDatasets,
    riskListVersions: riskListVersions,
    riskBeginVersion: riskBeginVersion,
    riskInsertRows: riskInsertRows,
    riskFinishVersion: riskFinishVersion,
    riskTouchVersion: riskTouchVersion,
    riskAbandonStalled: riskAbandonStalled,
    riskActivate: riskActivate,
    riskDeleteRows: riskDeleteRows,
    riskDeactivate: riskDeactivate,
    riskMarkRowsDeleted: riskMarkRowsDeleted,
    riskLookupFido: riskLookupFido,
    riskLookupRange: riskLookupRange,
    riskRecordFailure: riskRecordFailure,
    riskListFailures: riskListFailures,
    riskPurgeFailures: riskPurgeFailures,
    riskFeatureCounts: riskFeatureCounts,
    riskDistinctValues: riskDistinctValues,
    riskDistinctValuesMany: riskDistinctValuesMany,
    riskIncrementCounts: riskIncrementCounts,
    riskRecordAssessment: riskRecordAssessment,
    riskListAssessments: riskListAssessments,
    riskSetFeedback: riskSetFeedback,
    riskSettleAssessment: riskSettleAssessment,
    riskAmendAssessment: riskAmendAssessment,
    riskClaimAction: riskClaimAction,
    riskSubjectOf: riskSubjectOf,
    riskUpsertSubject: riskUpsertSubject,
    riskListSubjects: riskListSubjects,
    riskAssessmentMetrics: riskAssessmentMetrics,
    riskSubjectLevels: riskSubjectLevels,
    riskGeography: riskGeography,
    riskUpsertSessionContext: riskUpsertSessionContext,
    riskPurgeHistory: riskPurgeHistory,
    riskRecordAcceptance: riskRecordAcceptance,
    riskListAcceptances: riskListAcceptances
  };
  Object.keys(operations).forEach(function (name) {
    operations[name] = promised(operations[name]);
  });
  log.debug("Leaving create().");
  return operations;
}

module.exports = {
  create: create,
  // The same factory under a name that does not read as a call of the
  // driver's own `create()` (`tests/no_periodic_timers.js` treats a
  // function that calls its own name as one that repeats).
  forDriver: create,
  WIDTH: WIDTH
};
