'use strict';
//
// File: postgres_schema.js
//
// ===========================================================================
// THE SCHEMA IS WRITTEN DOWN TWICE ON PURPOSE, AND THIS IS WHAT PAYS FOR IT.
//
// Since 2026-09-06 the five tables and one index exist in two places:
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

const ROOT = path.join(__dirname, '..');
const SCHEMA_SQL = path.join(ROOT, 'postgres', 'schema.sql');
const APPLY_SH = path.join(ROOT, 'postgres', 'apply-schema.sh');
const COMPOSE = path.join(ROOT, 'docker-compose.yml');

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
  const body = sql.split('\n').filter(function (line) {
    return !/^\s*--/.test(line) && !/^\s*\\/.test(line);
  }).join('\n');
  return body.split(';').map(normalize).filter(function (statement) {
    return statement.length > 0;
  });
}

function scriptStatements(sql) {
  return statementsIn(sql).filter(function (statement) {
    return /^CREATE (TABLE|INDEX)/i.test(statement);
  });
}

function checkTheDdlAgrees(t, sql) {
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
}

function checkTheVersionAgrees(t, sql) {
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
}

function checkThePrivilegeIsNarrow(t, sql) {
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
}

function checkTheRoleNameAgrees(t) {
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
    t.check(url[1].indexOf('sslmode=require') > 0,
            'and still asks for TLS, which the database still requires',
            url[1]);
  }
}

function run(t) {
  const sql = fs.readFileSync(SCHEMA_SQL, 'utf8');
  checkTheDdlAgrees(t, sql);
  checkTheVersionAgrees(t, sql);
  checkThePrivilegeIsNarrow(t, sql);
  checkTheRoleNameAgrees(t);
}

module.exports = {
  name: 'postgres_schema',
  describe: 'postgres/schema.sql is the driver\'s schema, and grants the ' +
            'service\'s role no way to change it',
  run: run
};
