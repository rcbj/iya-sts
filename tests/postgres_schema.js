// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: postgres_schema.js
//
// ===========================================================================
// THE SCHEMA IS WRITTEN DOWN TWICE ON PURPOSE, AND THIS IS WHAT PAYS FOR IT.
//
// Since 2026-09-06 the tables and indexes (five and one that day; more now)
// exist in two places:
//
//   * `persistence/persistence_postgres.js`, which creates what is MISSING so
//     that `node server.js` against an empty local database still works; and
//   * `postgres/schema.sql`, which an OWNER runs once so that the role this
//     service dials with never needs to create anything at all.
//
// The second exists because "read and write the rows, and do not change the
// shape" is not something a role can be granted after the fact: `CREATE TABLE
// IF NOT EXISTS` checks CREATE on the schema BEFORE it checks whether the
// table is there, so a service whose role lacked CREATE was refused on every
// start by statements that had nothing to do. The driver probes now, and the
// script is what it finds already built.
//
// **THE COST OF THAT IS A SECOND COPY OF THE DDL, AND A SECOND COPY OF
// ANYTHING IS A THING THAT WILL DISAGREE.** The failure it produces is
// particularly bad: a column added to the driver and not to the script gives a
// database that is one column short and a service that is not allowed to add
// it — which arrives at a person as `permission denied for schema sts`, naming
// neither the column nor the file.
//
// So this file compares them, and it is in `tests/` rather than in the parent
// project's suite for the reason `tests/CLAUDE.md` gives: it is a comparison
// between two FILES in this repository, and no running service could be asked
// it. It is the same shape as `tests/xacml_pep.js`'s check that
// `xacml-pep/Dockerfile`'s COPY set is the engine's module list.
//
// ---------------------------------------------------------------------------
// IT ALSO ASSERTS THE PRIVILEGE, WHICH IS THE POINT OF THE SPLIT.
//
// A script that built the schema and then granted the application role
// everything would pass a DDL comparison perfectly and give back exactly what
// this change removed. So the grants are read too: the four verbs and no
// fifth, and a REVOKE of CREATE that is not merely an absence of a GRANT —
// PUBLIC holds CREATE on `public` on servers before PostgreSQL 15, so a role
// that was never granted it can still have it.
//
// AND THE ROLE NAME IN THREE FILES. The connection string in
// docker-compose.yml cannot be built out of the variables beside it — it is
// one string — so `sts_app` is spelt in the compose file twice and in
// `postgres/apply-schema.sh` once. Changing one of them produces a stack whose
// database has a role nobody dials and a service dialling a role that does not
// exist, which is a container that restart-loops on a password failure.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const driver = require('../persistence/persistence_postgres');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'postgres_schema',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SCHEMA_SQL = path.join(ROOT, 'postgres', 'schema.sql');
const APPLY_SH = path.join(ROOT, 'postgres', 'apply-schema.sh');
const COMPOSE = path.join(ROOT, 'docker-compose.yml');
// THE TWO OTHER FILES THAT START THIS DATABASE (#633): the quick start from
// published images, and the containerized suite (whose cells layer `extends`
// its postgres, so it is covered by this one).
const OTHER_COMPOSE = [
  path.join(ROOT, 'docker-compose-quick.yml'),
  path.join(ROOT, 'docker-compose-run-tests.yml')
];

// The default the script, the wrapper and the compose file all have to agree
// on. Spelt once here so that a deliberate rename is one edit in four files
// and a typo is a failure rather than a restart loop.
const APP_ROLE = 'sts_app';

// WHITESPACE ONLY. The driver writes its statements as concatenated string
// literals and the script writes them as formatted SQL, so they cannot be
// compared byte for byte — and they should not be: what has to match is the
// columns, their types and their constraints, not the indentation somebody
// chose. Anything else differing is a real disagreement.
function normalize(statement) {
  log.debug("Entering normalize().");
  log.debug("Leaving normalize().");
  return statement.replace(/\s+/g, ' ').trim();
}

// THE STATEMENTS, with psql's own meta-commands and the comments taken out
// first — and taking them out is not optional: this file is more comment than
// SQL, so a split on `;` over the raw text hands back chunks that begin with a
// paragraph of prose and match no `^GRANT` or `^REVOKE` anywhere. That was the
// first thing this test got wrong.
//
// `--` is only honoured at the start of a line: no value in this file contains
// one, and a naive strip of everything after `--` anywhere would silently eat
// part of a statement the day one does.
function statementsIn(sql) {
  log.debug("Entering statementsIn().");
  const body = sql.split('\n').filter(function (line) {
    return !/^\s*--/.test(line) && !/^\s*\\/.test(line);
  }).join('\n');
  log.debug("Leaving statementsIn().");
  return body.split(';').map(normalize).filter(function (statement) {
    return statement.length > 0;
  });
}

function scriptStatements(sql) {
  log.debug("Entering scriptStatements().");
  log.debug("Leaving scriptStatements().");
  return statementsIn(sql).filter(function (statement) {
    return /^CREATE (TABLE|INDEX)/i.test(statement);
  });
}

function checkTheDdlAgrees(t, sql) {
  log.debug("Entering checkTheDdlAgrees().");
  const fromScript = scriptStatements(sql);
  const fromDriver = driver.SCHEMA.map(normalize);

  t.equal(fromScript.length, fromDriver.length,
          'postgres/schema.sql holds as many CREATE statements as the ' +
          'driver (' + fromDriver.length + ')');

  const scriptSet = new Set(fromScript);
  fromDriver.forEach(function (statement) {
    t.check(scriptSet.has(statement),
            'postgres/schema.sql carries the driver\'s ' +
            statement.slice(0, 60) + '…',
            statement);
  });

  const driverSet = new Set(fromDriver);
  fromScript.forEach(function (statement) {
    t.check(driverSet.has(statement),
            'the driver carries the script\'s ' + statement.slice(0, 60) + '…',
            statement);
  });

  // A COLUMN ADDED TO A TABLE THAT ALREADY EXISTED (2026-09-18) is an
  // `ALTER … ADD COLUMN IF NOT EXISTS` in both, since `CREATE TABLE IF NOT
  // EXISTS` reaches only a new database — the driver's and the script's have
  // to be the same statement, or re-running the script leaves an old database
  // a column short of what the driver reads.
  // ADD COLUMN only: since #630 the script also sets storage parameters
  // and swaps two keys, which are SCHEMA_UPGRADES' (checkTheUpgradesAgree).
  const alters = statementsIn(sql).filter(function (statement) {
    return /^ALTER TABLE \S+ ADD COLUMN/i.test(statement);
  });
  const columns = (driver.SCHEMA_COLUMNS || []).map(function (one) {
    return normalize(one.statement);
  });
  t.equal(alters.length, columns.length,
          'postgres/schema.sql adds as many columns as the driver (' +
          columns.length + ')');
  columns.forEach(function (statement) {
    t.check(alters.indexOf(statement) >= 0,
            'postgres/schema.sql carries the driver\'s ' + statement,
            JSON.stringify(alters));
  });
  log.debug("Leaving checkTheDdlAgrees().");
}

// Statements split on `;` OUTSIDE a dollar-quoted body (#618): a plpgsql
// function holds semicolons of its own, which `statementsIn()` cuts through
// — harmless there, since it compares only tables and indexes.
function quotedAwareStatements(sql) {
  log.debug("Entering quotedAwareStatements().");
  const body = sql.split('\n').filter(function (line) {
    return !/^\s*--/.test(line) && !/^\s*\\/.test(line);
  }).join('\n');
  const out = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < body.length; i++) {
    if (body.slice(i, i + 2) === '$$') {
      quoted = !quoted;
      current += '$$';
      i += 1;
      continue;
    }
    if (body[i] === ';' && !quoted) {
      out.push(normalize(current));
      current = '';
      continue;
    }
    current += body[i];
  }
  out.push(normalize(current));
  log.debug("Leaving quotedAwareStatements().");
  return out.filter(function (statement) {
    return statement.length > 0;
  });
}

// THE COUNTS' FUNCTIONS AND TRIGGERS (#618) are the driver's, statement for
// statement, and the script starts the counters with the driver's one count.
function checkTheRoutinesAgree(t, sql) {
  log.debug("Entering checkTheRoutinesAgree().");
  const all = quotedAwareStatements(sql);
  const fromScript = all.filter(function (statement) {
    return /^CREATE (OR REPLACE |CONSTRAINT )*(FUNCTION|TRIGGER)/i
      .test(statement);
  });
  const fromDriver = (driver.SCHEMA_ROUTINES || []).map(function (one) {
    return normalize(one.statement);
  });
  t.equal(fromScript.length, fromDriver.length,
          'postgres/schema.sql holds as many functions and triggers as the ' +
          'driver (' + fromDriver.length + ')');
  fromDriver.forEach(function (statement) {
    t.check(fromScript.indexOf(statement) >= 0,
            'postgres/schema.sql carries the driver\'s ' +
            statement.slice(0, 70) + '…', statement);
  });
  t.check(all.indexOf(normalize(driver.COUNTS_BACKFILL)) >= 0,
          'and starts the counters with the driver\'s one count');
  t.check(all.indexOf(normalize(driver.LOCK_FOR_BACKFILL)) >= 0 &&
          all.indexOf(normalize(driver.LOCK_FOR_BACKFILL)) <
            all.indexOf(normalize(driver.COUNTS_BACKFILL)),
          'under the lock that keeps every writer out, taken first');
  t.check(all.indexOf(normalize(driver.DEK_COUNTS_BACKFILL)) >
            all.indexOf(normalize(driver.LOCK_FOR_BACKFILL)),
          'and starts the per-data-key counters with the driver\'s ' +
          'statement, under the same lock (#623)');
  log.debug("Leaving checkTheRoutinesAgree().");
}

// WHAT AN OLDER STORE IS OWED BEYOND AN OBJECT OR A COLUMN (#630, schema
// version 19): every statement of every SCHEMA_UPGRADES step, and the
// condition it runs under where the script has one, is in the script — so
// an owner's run of it and the driver's own open() bring a store to the
// same shape. And the shapes this version is for, named: the counters'
// keys hold `shard`, the folds add to it, readers sum it; `sts_minted`'s
// `written_at` index is a BRIN (no btree left to block HOT) at fillfactor
// 80; and the change log and the directory carry their autovacuum
// parameters.
function checkTheUpgradesAgree(t, sql) {
  log.debug("Entering checkTheUpgradesAgree().");
  const text = normalize(sql.split('\n').filter(function (line) {
    return !/^\s*--/.test(line) && !/^\s*\\/.test(line);
  }).join('\n'));
  const steps = driver.SCHEMA_UPGRADES || [];
  t.check(steps.length > 0, 'the driver declares SCHEMA_UPGRADES');
  steps.forEach(function (step) {
    step.statements.forEach(function (statement) {
      t.check(text.indexOf(normalize(statement)) >= 0,
              'postgres/schema.sql carries ' + step.name + ': ' +
              normalize(statement).slice(0, 70), statement);
    });
    if (/KEY|shard_key/i.test(step.name)) {
      t.check(text.indexOf('IF ' + normalize(step.when) + ' THEN') >= 0,
              'and runs ' + step.name + ' under the driver\'s condition',
              step.when);
    }
  });
  const named = function (re, what) {
    t.check(re.test(text), what, String(re));
  };
  named(/PRIMARY KEY \(realm, base_key, attribute, shard\)\)/,
        'sts_ldap_counts is created with shard in its key');
  named(/PRIMARY KEY \(dek_id, shard\)\)/,
        'sts_ldap_dek_counts is created with shard in its key');
  named(/ON CONFLICT \(realm, base_key, attribute, shard\)/,
        'the count fold adds to a shard');
  named(/ON CONFLICT \(dek_id, shard\)/, 'the data-key fold adds to a shard');
  named(/USING brin \(written_at\)/,
        'sts_minted.written_at is indexed by a BRIN, which leaves HOT alone');
  t.check(!/ON sts_minted \(written_at\)/.test(text) &&
          !driver.SCHEMA.some(function (statement) {
            return /ON sts_minted \(written_at\)/.test(statement);
          }), 'and by no btree, in the script or the driver');
  named(/DROP INDEX IF EXISTS sts_minted_written;/,
        'the btree an older store has is dropped');
  named(/ALTER TABLE sts_minted SET \(fillfactor=80\)/,
        'sts_minted is at fillfactor 80 — the minted-HOT reloption');
  named(/ALTER TABLE sts_changes SET \(autovacuum_vacuum_scale_factor=0\.02, autovacuum_vacuum_cost_limit=2000\)/,
        'sts_changes carries its autovacuum parameters');
  named(/ALTER TABLE sts_ldap_entries SET \(autovacuum_vacuum_insert_scale_factor=0\.01\)/,
        'sts_ldap_entries carries its insert-vacuum parameter');
  // #639, schema version 20: the parents' count said, not sampled, and the
  // one column analyzed so it takes effect at once.
  named(/ALTER TABLE sts_ldap_entries ALTER COLUMN parent_key SET \(n_distinct=100000\); ANALYZE sts_ldap_entries \(parent_key\);/,
        'sts_ldap_entries.parent_key\'s n_distinct is set, then analyzed');
  const parents = steps.filter(function (step) {
    return step.name === 'sts_ldap_entries_parent_ndistinct';
  })[0];
  t.check(!!parents && parents.advisory === true &&
          /pg_attribute/.test(parents.when) &&
          /a\.attname = 'parent_key'/.test(parents.when),
          'and the driver owes it as an advisory step, probed in the ' +
          'column\'s attoptions', parents && parents.when);
  named(/DROP TRIGGER IF EXISTS sts_ldap_count_deltas_fold ON sts_ldap_count_deltas; DROP FUNCTION IF EXISTS sts_ldap_count_fold\(\);/,
        'the unsharded count fold is dropped before the sharded one arrives');
  named(/DROP TRIGGER IF EXISTS sts_ldap_dek_deltas_fold ON sts_ldap_dek_deltas; DROP FUNCTION IF EXISTS sts_ldap_dek_fold\(\);/,
        'and so is the unsharded data-key fold');
  // The driver's reloption probes name the parameters its statements set.
  steps.filter(function (step) {
    return /SET \(/.test(step.statements.join(' '));
  }).forEach(function (step) {
    const set = /SET \((.*)\)/.exec(step.statements[0])[1].split(/,\s*/);
    set.forEach(function (one) {
      t.check(step.when.indexOf('\'' + one + '\'') >= 0,
              step.name + ' probes for ' + one + ', as it sets it',
              step.when);
    });
  });
  // AND THE OTHER WAY ROUND: every storage parameter the script sets, and
  // every index or routine it drops, is a step the driver takes too — or a
  // store the driver brings level is slower than one the script did.
  const driverStatements = [].concat.apply([], steps.map(function (step) {
    return step.statements.map(normalize);
  }));
  statementsIn(sql).filter(function (statement) {
    return /^ALTER TABLE \S+ SET \(/.test(statement) ||
      /^DROP (INDEX|FUNCTION) IF EXISTS sts_(minted_written|ldap_count_fold|ldap_dek_fold)\b/
        .test(statement);
  }).forEach(function (statement) {
    t.check(driverStatements.indexOf(statement) >= 0,
            'the driver takes the script\'s ' + statement.slice(0, 70),
            JSON.stringify(driverStatements));
  });
  t.check(text.indexOf('CREATE EXTENSION IF NOT EXISTS pg_stat_statements') >=
            0, 'the script creates pg_stat_statements');
  log.debug("Leaving checkTheUpgradesAgree().");
}

// WHAT A LATER VERSION REPLACED (#618 phase 2, schema version 18): the
// script drops every index the driver retired, and nothing else — an index
// left behind is still written on every insert, which is the cost the
// version exists to remove — and drops each only AFTER the index that
// replaces it is built, so no question is ever without one.
function checkTheRetiredAgree(t, sql) {
  log.debug("Entering checkTheRetiredAgree().");
  const all = statementsIn(sql);
  const drops = all.filter(function (statement) {
    return /^DROP INDEX/i.test(statement);
  });
  const retired = (driver.SCHEMA_RETIRED || []).map(function (one) {
    return normalize(one.statement);
  });
  t.check(retired.length === 2 &&
          retired.indexOf('DROP INDEX IF EXISTS ' +
                          'sts_ldap_entries_attr_names') >= 0 &&
          retired.indexOf('DROP INDEX IF EXISTS sts_ldap_entries_classes') >=
            0,
          'the driver retires the two indexes version 18 replaced',
          JSON.stringify(retired));
  // And the advisory drop of #630's SCHEMA_UPGRADES (the minted btree), a
  // retirement a role that does not own the table may skip.
  const upgraded = [].concat.apply([], (driver.SCHEMA_UPGRADES || [])
    .map(function (step) {
      return step.statements.filter(function (statement) {
        return /^DROP INDEX/i.test(statement);
      }).map(normalize);
    }));
  t.equal(JSON.stringify(drops.slice().sort()),
          JSON.stringify(retired.concat(upgraded).sort()),
          'postgres/schema.sql drops exactly the indexes the driver retired');
  const at = function (pattern) {
    return all.findIndex(function (statement) {
      return pattern.test(statement);
    });
  };
  const askedAt = at(/^CREATE INDEX IF NOT EXISTS sts_ldap_entries_asked_names /);
  const groupsAt = at(/^CREATE INDEX IF NOT EXISTS sts_ldap_entries_group_classes /);
  t.check(askedAt >= 0 && groupsAt >= 0 &&
          at(/sts_ldap_entries_attr_names$/) > askedAt &&
          at(/sts_ldap_entries_classes$/) > groupsAt,
          'and drops each after the index that replaces it is built');
  log.debug("Leaving checkTheRetiredAgree().");
}

// THE DIRECTORY'S GIN INDEXES TAKE EVERY INSERT DIRECTLY (#618, version 18):
// each is created `WITH (fastupdate = off)`, an existing one is switched by
// the driver's SCHEMA_RELOPTIONS — the same statements in the script, after
// the CREATE — and its pending list flushed once, after the switch.
function checkTheReloptionsAgree(t, sql) {
  log.debug("Entering checkTheReloptionsAgree().");
  const all = statementsIn(sql);
  const wanted = driver.SCHEMA_RELOPTIONS || [];
  t.equal(wanted.map(function (one) { return one.name; }).sort().join(','),
          ['sts_ldap_entries_asked_names', 'sts_ldap_entries_group_classes',
           'sts_ldap_entries_mails', 'sts_ldap_entries_names',
           'sts_ldap_entries_uuids', 'sts_ldap_entries_values'].join(','),
          'the driver turns the pending list off on the directory\'s six ' +
          'GIN indexes');
  wanted.forEach(function (one) {
    const createAt = all.findIndex(function (statement) {
      return statement.indexOf('CREATE INDEX IF NOT EXISTS ' + one.name +
                               ' ') === 0;
    });
    const alterAt = all.indexOf(normalize(one.statement));
    const flushAt = all.indexOf(normalize(one.flush));
    t.check(createAt >= 0 &&
            all[createAt].indexOf(' WITH (fastupdate = off)') > 0 &&
            alterAt > createAt && flushAt > alterAt &&
            one.option === 'fastupdate=off',
            one.name + ' is created with fastupdate off, switched on an ' +
            'existing store and its pending list flushed, in that order',
            JSON.stringify({ createAt: createAt, alterAt: alterAt,
                             flushAt: flushAt }));
  });
  const gins = driver.SCHEMA.filter(function (statement) {
    return /ON sts_ldap_entries USING gin/.test(statement) &&
      !/sts_ldap_entries_dek_keys /.test(statement);
  });
  t.check(gins.length === 7 && gins.every(function (statement) {
    return statement.indexOf('WITH (fastupdate = off)') > 0;
  }), 'every directory GIN index but the data keys\' is created with it',
          String(gins.length));
  log.debug("Leaving checkTheReloptionsAgree().");
}

function checkTheVersionAgrees(t, sql) {
  log.debug("Entering checkTheVersionAgrees().");
  // The script writes the version row so that a database built by an owner
  // reports its schema version without this service ever having connected.
  // A script that wrote a different number would be a store claiming to be a
  // schema it is not.
  const match = /INSERT\s+INTO\s+sts_schema\s*\(\s*version\s*\)\s*VALUES\s*\(\s*(\d+)\s*\)/i
    .exec(sql);
  t.check(!!match, 'postgres/schema.sql writes a row into sts_schema');
  if (match) {
    t.equal(Number(match[1]), driver.SCHEMA_VERSION,
            'and the version it writes is the driver\'s SCHEMA_VERSION');
  }
  log.debug("Leaving checkTheVersionAgrees().");
}

// Schema 21 (#350): `sts_sessions` beside `sts_minted`, six partial indexes,
// a nullable `expires_at`, and the primary key `(realm, key)`. Schema 22
// (#754) adds the seventh, `sts_sessions_surface`.
function checkTheSessionIndex(t, sql) {
  log.debug("Entering checkTheSessionIndex().");
  t.equal(driver.SCHEMA_VERSION, 29,
          'the driver\'s schema version is 29 (#350, #754, the uid ' +
          'trigram index, #820\'s on-demand index and its sort_at, #956, ' +
          '#1024\'s asked-names rebuild, #1028\'s date B-trees, #1045\'s ' +
          'report pieces)');
  // #820: the on-demand stores' index, in the driver and in the script,
  // and (version 25) the partial index `minted.newest` walks.
  ['sts_minted_index', 'sts_minted_index_key',
   'sts_minted_index_sort'].forEach(function (name) {
    t.check((driver.SCHEMA_OBJECTS || []).some(function (one) {
      return one.name === name;
    }) && statementsIn(sql).some(function (statement) {
      return statement.indexOf(name) >= 0;
    }), name + ' is in the driver\'s schema and in the script');
  });
  const names = ['sts_sessions_subject', 'sts_sessions_username',
                 'sts_sessions_expires', 'sts_sessions_parent',
                 'sts_sessions_credential', 'sts_sessions_partner',
                 'sts_sessions_surface'];
  const predicates = [
    'WHERE chosen AND subject_key <> \'\'',
    'WHERE username_key <> \'\'',
    'WHERE expires_at IS NOT NULL',
    'WHERE parent_key <> \'\'',
    'WHERE credential_key <> \'\'',
    'WHERE partner_relationship <> \'\'',
    'WHERE rp_surface <> \'\''
  ];
  const script = statementsIn(sql);
  names.forEach(function (name, i) {
    const fromDriver = (driver.SCHEMA_OBJECTS || []).filter(function (one) {
      return one.name === name;
    })[0];
    t.check(!!fromDriver &&
            fromDriver.statement.indexOf(predicates[i]) >= 0,
            name + ' is partial: ' + predicates[i],
            fromDriver && fromDriver.statement);
    t.check(script.some(function (statement) {
      return statement.indexOf(name) >= 0 &&
             statement.indexOf(predicates[i]) >= 0;
    }), 'postgres/schema.sql carries ' + name);
  });
  const table = (driver.SCHEMA_OBJECTS || []).filter(function (one) {
    return one.name === 'sts_sessions';
  })[0];
  t.check(!!table && /expires_at\s+bigint,/.test(table.statement) &&
          !/expires_at\s+bigint\s+NOT NULL/.test(table.statement) &&
          /PRIMARY KEY \(realm, key\)/.test(table.statement),
          'sts_sessions.expires_at is nullable and the primary key is ' +
          '(realm, key)', table && table.statement);
  log.debug("Leaving checkTheSessionIndex().");
}

// Schema 23 (2026-10-20, `/portal/delegate`): the uid trigram index, a GIN
// with `pg_trgm`'s operator class over `rdn_value`, partial on the children
// of a realm's `ou=users` — the predicate `uidContains` repeats, or the
// planner cannot use it — and the extension created before it, in the
// script and in the driver.
function checkTheUidTrigramIndex(t, sql) {
  log.debug("Entering checkTheUidTrigramIndex().");
  const queries = require('../persistence/directory_queries');
  const object = (driver.SCHEMA_OBJECTS || []).filter(function (one) {
    return one.name === 'sts_ldap_entries_uid_trgm';
  })[0];
  t.check(!!object && object.extension === 'pg_trgm' &&
          object.afterColumns === true &&
          /USING gin \(rdn_value gin_trgm_ops\)/.test(object.statement) &&
          object.statement.indexOf('WHERE ' + queries.USERS_PARENT) > 0,
          'the driver declares the uid trigram index, partial on ' +
          queries.USERS_PARENT + ', after pg_trgm',
          object && object.statement);
  const statement = queries.uidContains('r', 'ou=users,dc=x', 'abc', 5);
  t.check(statement.text.indexOf(queries.USERS_PARENT) > 0,
          'uidContains repeats the index\'s predicate', statement.text);
  const all = statementsIn(sql);
  const extensionAt = all.indexOf('CREATE EXTENSION IF NOT EXISTS pg_trgm');
  const indexAt = all.findIndex(function (one) {
    return one.indexOf('CREATE INDEX IF NOT EXISTS ' +
                       'sts_ldap_entries_uid_trgm ') === 0;
  });
  t.check(extensionAt >= 0 && indexAt > extensionAt,
          'the script creates pg_trgm before the index',
          JSON.stringify({ extensionAt: extensionAt, indexAt: indexAt }));
  log.debug("Leaving checkTheUidTrigramIndex().");
}

function checkThePrivilegeIsNarrow(t, sql) {
  log.debug("Entering checkThePrivilegeIsNarrow().");
  // ---------------------------------------------------------------------
  // THE FOUR VERBS AND NO FIFTH.
  //
  // Matched on the statement rather than on the file, so that a second GRANT
  // added later cannot hide behind the first one passing.
  // ---------------------------------------------------------------------
  const grants = statementsIn(sql).filter(function (statement) {
    return /^GRANT/i.test(statement) &&
           /sts_app_role/.test(statement);
  });
  t.check(grants.length > 0,
          'postgres/schema.sql grants the application role something');

  const tableGrant = grants.filter(function (statement) {
    return /ON ALL TABLES/i.test(statement);
  })[0];
  t.check(!!tableGrant, 'it grants on the tables in the schema');
  if (tableGrant) {
    t.check(/GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES/i
              .test(tableGrant),
            'and the grant is exactly SELECT, INSERT, UPDATE, DELETE',
            tableGrant);
  }

  grants.forEach(function (statement) {
    // TRUNCATE empties a table with no WHERE clause to get wrong; REFERENCES
    // and TRIGGER change the schema from the side; ALL is all of them. None
    // of the four is anything this driver does.
    t.check(!/\bGRANT ALL\b/i.test(statement),
            'no GRANT ALL to the application role', statement);
    t.check(!/\bTRUNCATE\b|\bREFERENCES\b|\bTRIGGER\b/i.test(statement),
            'no TRUNCATE, REFERENCES or TRIGGER granted to it', statement);
    t.check(!/\bCREATE\b/i.test(statement),
            'and no CREATE — which is the whole point of the file',
            statement);
  });

  // ---------------------------------------------------------------------
  // AND THE REVOCATIONS, WHICH ARE NOT THE SAME AS NOT GRANTING.
  //
  // Before PostgreSQL 15, PUBLIC holds CREATE on `public` — so on any server
  // older than the one in this repository's compose file, a role that was
  // never granted CREATE can still create a table. Both schemas are named
  // because a role stopped from creating in one and free to create in the
  // other has not been stopped.
  // ---------------------------------------------------------------------
  const revokes = statementsIn(sql).filter(function (statement) {
    return /^REVOKE/i.test(statement);
  });
  t.check(revokes.some(function (s) {
    return /REVOKE CREATE ON SCHEMA :"sts_schema" FROM PUBLIC/i.test(s);
  }), 'CREATE on this service\'s schema is revoked from PUBLIC');
  t.check(revokes.some(function (s) {
    return /REVOKE CREATE ON SCHEMA public FROM PUBLIC/i.test(s);
  }), 'CREATE on `public` is revoked from PUBLIC — the pre-15 default');
  t.check(revokes.some(function (s) {
    return /REVOKE CREATE ON SCHEMA :"sts_schema" FROM :"sts_app_role"/i
      .test(s);
  }), 'and from the application role by name');
  log.debug("Leaving checkThePrivilegeIsNarrow().");
}

function checkTheRoleNameAgrees(t) {
  log.debug("Entering checkTheRoleNameAgrees().");
  const apply = fs.readFileSync(APPLY_SH, 'utf8');
  const compose = fs.readFileSync(COMPOSE, 'utf8');

  t.check(new RegExp('STS_DB_APP_USER:-' + APP_ROLE + '\\}').test(apply),
          'postgres/apply-schema.sh defaults the role to ' + APP_ROLE);
  t.check(new RegExp('STS_DB_APP_USER=\\$\\{STS_DB_APP_USER:-' + APP_ROLE +
                     '\\}').test(compose),
          'and docker-compose.yml passes the database the same default');

  // THE CONNECTION STRING IS THE THIRD PLACE, and the one that fails loudest:
  // a stack whose database made `sts_app` and whose service dials `sts` gets a
  // container that restart-loops on a password failure.
  const url = /STS_DATABASE_URL=\$\{STS_DATABASE_URL:-([^}]+)\}/.exec(compose);
  t.check(!!url, 'docker-compose.yml has a default STS_DATABASE_URL');
  if (url) {
    // THE PASSWORD IS NO LONGER IN THIS STRING AND THAT IS THE POINT. Since
    // 2026-09-12 the compose stack reads it from OpenBao and
    // `persistence.js`'s `resolveDatabaseUrl()` injects it, so the default
    // reads `sts_app@postgres` where it used to read `sts_app:sts_app@`. What
    // this assertion is about is the ROLE, so it accepts either spelling —
    // pinning the colon would have made "the password left the compose file"
    // look like "the service dials as the schema owner".
    t.check(new RegExp('://' + APP_ROLE + '[:@]').test(url[1]),
            'and it dials as ' + APP_ROLE + ' rather than as the schema owner',
            url[1]);
    // verify-full since 2026-10-12: TLS, which the database still
    // requires, and the server authenticated against the certificate the
    // stack shares (persistence.databaseTlsCaFile).
    t.check(url[1].indexOf('sslmode=verify-full') > 0,
            'and asks for TLS with the server verified, chain and host name',
            url[1]);
    t.check(/STS_DATABASE_TLS_CA_FILE=\$\{STS_DATABASE_TLS_CA_FILE:-\/run\/secrets\/database-ca\/postgres\.crt\}/
              .test(compose) &&
            /- sts-db-ca:\/run\/secrets\/database-ca:ro/.test(compose),
            'and names the certificate the postgres service shares, mounted ' +
            'read-only, as its trust anchor');
    t.check(/POSTGRES_TLS_PUBLIC_DIR=\/run\/sts-db-ca/.test(compose) &&
            !/sts-db:\/run\/secrets/.test(compose),
            'which the postgres service writes without its key: the data ' +
            'volume, where the key is, never reaches sts');
  }
  log.debug("Leaving checkTheRoleNameAgrees().");
}

// THE SERVER'S SETTINGS ARE THE SAME IN EVERY FILE THAT STARTS IT (#633).
// #630 measured them under a bulk load and put them in docker-compose.yml
// alone, so the quick start and the suite ran the defaults it had measured
// against — 128 MB of buffers, no statement statistics, and (the quick start)
// the default 100 connections that 200 had replaced. Read as `-c name=value`
// pairs from the postgres command; every name and value has to match,
// shared_buffers' substitution included.
function serverSettings(text) {
  log.debug("Entering serverSettings().");
  const at = text.indexOf('exec docker-entrypoint.sh postgres');
  const settings = {};
  if (at < 0) {
    log.debug("Leaving serverSettings().");
    return null;
  }
  const end = text.indexOf('healthcheck:', at);
  const command = text.slice(at, end < 0 ? undefined : end);
  const pair = /-c\s+([a-z_.]+)=([^\s']+)/g;
  let m;
  while ((m = pair.exec(command)) !== null) {
    settings[m[1]] = m[2];
  }
  log.debug("Leaving serverSettings().");
  return settings;
}

function checkTheServerSettingsAgree(t) {
  log.debug("Entering checkTheServerSettingsAgree().");
  const want = serverSettings(fs.readFileSync(COMPOSE, 'utf8'));
  t.check(!!want && Object.keys(want).length > 0,
          'docker-compose.yml starts postgres with settings on its command');
  t.check(!!want && /pg_stat_statements/.test(
            want.shared_preload_libraries || ''),
          'and preloads pg_stat_statements, the extension schema.sql makes');
  for (const file of OTHER_COMPOSE) {
    const name = path.basename(file);
    const got = serverSettings(fs.readFileSync(file, 'utf8'));
    t.check(!!got, name + ' starts postgres through docker-entrypoint.sh');
    if (!want || !got) {
      continue;
    }
    for (const key of Object.keys(want)) {
      t.check(got[key] === want[key],
              name + ' sets ' + key + ' as docker-compose.yml does',
              key + '=' + got[key] + ', want ' + want[key]);
    }
    for (const key of Object.keys(got)) {
      t.check(key in want,
              name + ' sets nothing docker-compose.yml does not: ' + key);
    }
  }
  log.debug("Leaving checkTheServerSettingsAgree().");
}

// AND THE QUICK START IS PRINTED, WHOLE, IN docs/getting-started.md (#633),
// for a reader with no checkout. The copy had drifted from nothing until the
// file gained the settings above, and a reader who pastes the page gets the
// page, so the first yaml block there is held to the file, its two SPDX
// lines aside.
function checkTheQuickStartPageAgrees(t) {
  log.debug("Entering checkTheQuickStartPageAgrees().");
  const page = fs.readFileSync(path.join(ROOT, 'docs', 'getting-started.md'),
                               'utf8');
  const block = /```yaml\n([\s\S]*?)```/.exec(page);
  const file = fs.readFileSync(OTHER_COMPOSE[0], 'utf8')
    .split('\n').slice(2).join('\n');
  t.check(!!block && block[1] === file,
          'docs/getting-started.md prints docker-compose-quick.yml as it is');
  log.debug("Leaving checkTheQuickStartPageAgrees().");
}

function run(t) {
  log.debug("Entering run().");
  const sql = fs.readFileSync(SCHEMA_SQL, 'utf8');
  checkTheDdlAgrees(t, sql);
  checkTheRoutinesAgree(t, sql);
  checkTheUpgradesAgree(t, sql);
  checkTheRetiredAgree(t, sql);
  checkTheReloptionsAgree(t, sql);
  checkTheVersionAgrees(t, sql);
  checkTheSessionIndex(t, sql);
  checkTheUidTrigramIndex(t, sql);
  checkThePrivilegeIsNarrow(t, sql);
  checkTheRoleNameAgrees(t);
  checkTheServerSettingsAgree(t);
  checkTheQuickStartPageAgrees(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'postgres_schema',
  describe: 'postgres/schema.sql is the driver\'s schema, and grants the ' +
            'service\'s role no way to change it',
  run: run
};
