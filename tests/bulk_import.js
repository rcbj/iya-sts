// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: bulk_import.js
//
// ===========================================================================
// THE BULK DIRECTORY IMPORT (#629): people from an LDIF file into a realm's
// `ou=users`, offline, exactly as the normal doors would have left them.
//
//   A. A RECORD: what is accepted and what is refused (STS-LDAP-0155, 0156)
//      — a DN outside ou=users, an RDN that is not a plain uid, uid values
//      missing the RDN value, a credential, an operational or sts attribute,
//      a group's class, a URL value, two records in one block, a changetype
//      other than add; the stored entry's attributes in `putEntry()`'s
//      order; `normalizeDn()`.
//   B. THE STREAM: records, their ordinals and lines, folded and base64
//      values through the service's own codec, a URL line marked; the
//      generator's people read back as candidates.
//   C. THE STATEMENTS: the insert is guarded by the DN and by both of
//      `byName()`'s name lookups; the classification asks the same.
//   D. AGAINST A REAL POSTGRES, when STS_TEST_POSTGRES_URL names one the test
//      may create a database in (an owner; STS_TEST_POSTGRES_CA for its CA):
//      a database of its own, the service started once in a child to seed
//      it (development mode, keys persisted under a file KEK, so the
//      directory is SEALED), then the import, in a child, as an operator
//      runs it:
//        D1 every person present, sealed, opening to the expected entry;
//        D2 the counters equal a fresh count, and the per-data-key counters
//           a fresh sum;
//        D3 a username held in the store (alice, seeded) and one held
//           earlier in the file are not imported (STS-LDAP-0160), a DN
//           repeated is present, refused records are counted by code;
//        D4 a re-run adds nothing and seals nothing new;
//        D5 the service, started again with a WINDOWED directory, finds the
//           people through `existingUserEntry()`, `byName`, `entryByUuid()`
//           (SCIM's id) and an LDAP search by uid on its own listener;
//        D6 a running service (a fresh change reader) is refused
//           (STS-LDAP-0153); `ldap.maxEntries` stops the import
//           (STS-LDAP-0157) and a re-run with a raised ceiling resumes.
//      The database is dropped afterwards. Skipped (and said) otherwise.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'bulk_import',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const CHILD = 'STS_TEST_BULK_IMPORT_CHILD';
const BASE = 'dc=example,dc=com';
const USERS = 'ou=users,' + BASE;

function importer() {
  log.debug("Entering importer().");
  log.debug("Leaving importer().");
  return require('../persistence/bulk_import');
}

function person(uid, extra) {
  log.debug("Entering person().");
  const out = { dn: 'uid=' + uid + ',' + USERS, attributes: Object.assign({
    objectclass: ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
    uid: [uid], cn: ['C ' + uid], sn: ['S'], mail: [uid + '@load.example']
  }, extra || {}) };
  log.debug("Leaving person().");
  return out;
}

function recordOf(entry) {
  log.debug("Entering recordOf().");
  log.debug("Leaving recordOf().");
  return { ordinal: 1, line: 1, entry: entry, url: false, extra: false };
}

// ---------------------------------------------------------------------------
// A.
// ---------------------------------------------------------------------------
function records(t) {
  log.debug("Entering records().");
  t.log.info('=== A. a record ===');
  const bi = importer();
  const key = bi.normalizeDn(USERS);
  const ok = bi.candidateOf(recordOf(person('Ann')), key);
  t.check(ok.ok && ok.dnKey === 'uid=ann,' + USERS &&
          JSON.stringify(ok.names) === '["ann"]',
          'A1. a person directly under ou=users is a candidate, named by ' +
          'the RDN value and its uid, lower-cased', JSON.stringify(ok));
  const refused = [
    ['STS-LDAP-0155', Object.assign(person('a'),
      { dn: 'uid=a,ou=groups,' + BASE }), 'a DN outside ou=users'],
    ['STS-LDAP-0155', Object.assign(person('a'),
      { dn: 'uid=a,ou=x,' + USERS }), 'a DN two levels under ou=users'],
    ['STS-LDAP-0155', Object.assign(person('a'),
      { dn: 'cn=a,' + USERS }), 'an RDN that is not uid'],
    ['STS-LDAP-0155', Object.assign(person('a+b'),
      { dn: 'uid=a+cn=b,' + USERS }), 'a multi-valued RDN'],
    ['STS-LDAP-0155', Object.assign(person('a'),
      { dn: 'uid=a\\2cb,' + USERS }), 'an escaped RDN'],
    ['STS-LDAP-0155', person('a', { uid: ['b'] }),
     'uid values without the RDN value'],
    ['STS-LDAP-0156', person('a', { userpassword: ['x'] }), 'userPassword'],
    ['STS-LDAP-0156', person('a', { ststotpcredential: ['x'] }),
     'an sts credential attribute'],
    ['STS-LDAP-0156', person('a', { entryuuid: ['x'] }),
     'an operational attribute'],
    ['STS-LDAP-0156', person('a', { createtimestamp: ['x'] }),
     'a timestamp'],
    ['STS-LDAP-0156', person('a', { usercertificate: ['x'] }),
     'a certificate'],
    ['STS-LDAP-0156', person('a', { member: ['x'] }), 'a group\'s member'],
    ['STS-LDAP-0156', person('a', { objectclass: ['groupOfNames'] }),
     'a group\'s class'],
    ['STS-LDAP-0156', person('a', { objectclass: [] }), 'no class'],
    ['STS-LDAP-0156', person('a', { cn: [''] }), 'an empty value'],
    ['STS-LDAP-0156', person('a', { cn: ['x\u0000y'] }), 'a NUL byte'],
    ['STS-LDAP-0156', person('a', { changetype: ['modify'] }),
     'changetype modify']
  ];
  refused.forEach(function (one) {
    const got = bi.candidateOf(recordOf(one[1]), key);
    t.check(!got.ok && got.code === one[0],
            'A2. refused (' + one[0] + '): ' + one[2], JSON.stringify(got));
  });
  t.check(!bi.candidateOf(Object.assign(recordOf(person('a')),
                                        { url: true }), key).ok,
          'A2. refused: a URL value');
  t.check(!bi.candidateOf(Object.assign(recordOf(person('a')),
                                        { extra: true }), key).ok,
          'A2. refused: two records in one block');
  t.check(bi.candidateOf(recordOf(person('a', { changetype: ['add'] })),
                         key).ok,
          'A3. changetype add is an add, and is not stored');
  const two = bi.candidateOf(recordOf(person('a', { uid: ['a', 'Alias'] })),
                             key);
  t.equal(JSON.stringify(two.names), '["a","alias"]',
          'A4. every uid value is a name the record proposes');
  const stored = bi.storedOf(ok, '20261014000000Z', 'fr', 'u-1');
  t.equal(Object.keys(stored.attributes).join(','),
          'objectclass,uid,cn,sn,mail,createtimestamp,modifytimestamp,' +
          'preferredlanguage,stspreferredlanguagepopulated,entryuuid,' +
          'stsmailverified',
          'A5. the stored attributes are putEntry()\'s, in its order');
  t.check(stored.origin === 'bulk import' &&
          stored.createdAt === '20261014000000Z' &&
          stored.attributes.stsmailverified[0] === 'Ann@load.example' &&
          stored.attributes.entryuuid[0] === 'u-1',
          'A6. origin, timestamps, entryUUID and the verified address',
          JSON.stringify(stored));
  const own = bi.storedOf(bi.candidateOf(recordOf(person('b',
    { preferredlanguage: ['de'] })), key), 'x', 'fr', 'u');
  t.check(own.attributes.preferredlanguage[0] === 'de' &&
          !own.attributes.stspreferredlanguagepopulated,
          'A7. a record\'s own preferredLanguage is kept, and nothing is ' +
          'marked populated');
  t.check(!bi.storedOf(ok, 'x', '', 'u').attributes.preferredlanguage,
          'A8. no language where the policy populates none');
  [' UID=Ann , OU=Users,DC=Example,DC=Com ', 'uid=a,ou=users',
   'cn=x\\,y,ou=users'].forEach(function (dn) {
    t.equal(bi.normalizeDn(dn), dn.trim().split(',').map(function (p) {
      return p.trim().toLowerCase();
    }).join(','), 'A9. normalizeDn(' + JSON.stringify(dn) + ')');
  });
  log.debug("Leaving records().");
}

// ---------------------------------------------------------------------------
// B.
// ---------------------------------------------------------------------------
async function streamed(t, dir) {
  log.debug("Entering streamed().");
  t.log.info('=== B. the stream ===');
  const file = path.join(dir, 'b.ldif');
  const ldif = require('../persistence/persistence_ldif');
  fs.writeFileSync(file, [
    '# a comment', 'version: 1', '',
    'dn: uid=one,' + USERS, 'objectClass: inetOrgPerson', 'uid: one',
    ldif.ldifLine('description', 'x'.repeat(200)),
    'cn:: ' + Buffer.from('Zoë', 'utf8').toString('base64'), '', '',
    'dn: uid=two,' + USERS, 'uid: two', 'jpegPhoto:< file:///etc/passwd', '',
    'dn: uid=three,' + USERS, 'uid: three',
    'dn: uid=four,' + USERS, 'uid: four'
  ].join('\n'));
  const got = [];
  for await (const one of require('../persistence/ldif_stream')
    .records(file)) {
    got.push(one);
  }
  t.equal(got.length, 3, 'B1. three records (version and comments are not)');
  t.check(got[0].ordinal === 1 && got[0].line === 4 &&
          got[0].entry.attributes.description[0] === 'x'.repeat(200) &&
          got[0].entry.attributes.cn[0] === 'Zoë',
          'B2. a folded value and a base64 value read through the service\'s ' +
          'own codec', JSON.stringify(got[0]));
  t.check(got[1].url && !got[0].url && got[1].ordinal === 2,
          'B3. a URL line marks its record');
  t.check(got[2].extra && got[2].ordinal === 3,
          'B4. a block with two dn: is marked, not split by guesswork');
  const gen = require('./tools/generate-people-ldif');
  const opts = gen.optionsOf(['--count=3', '--stamp=abc', '--start=7']);
  const genFile = path.join(dir, 'gen.ldif');
  const sink = fs.createWriteStream(genFile);
  await gen.generate(opts, sink);
  await new Promise(function (resolve) {
    sink.end(resolve);
  });
  const people = [];
  for await (const one of require('../persistence/ldif_stream')
    .records(genFile)) {
    people.push(importer().candidateOf(one,
                                       importer().normalizeDn(USERS)));
  }
  t.check(people.length === 3 && people.every(function (c) {
    return c.ok;
  }) && people[0].dn === 'uid=load-abc-7,' + USERS &&
          people[2].attributes.mail[0] === 'load-abc-9@load.example' &&
          people[0].attributes.displayname[0] === 'Load User 7',
          'B5. the generator\'s people are the loader\'s shape and import',
          JSON.stringify(people[0]));
  t.check(gen.optionsOf(['--count=x']) === null &&
          gen.optionsOf(['--base=ou=x']) === null &&
          gen.optionsOf(['--nope=1']) === null,
          'B6. the generator refuses a bad count, base or argument');
  const bi = importer();
  t.check(bi.optionsOf(['--file=a', '--batch=0']) === null &&
          bi.optionsOf(['--file=a', '--batch=50001']) === null &&
          bi.optionsOf(['--batch=5']) === null &&
          bi.optionsOf(['--file=a', '--x=1']) === null &&
          bi.optionsOf(['--file=a', '--skip=-1']) === null &&
          bi.optionsOf(['--file=a', '--skip=3', '--batch=7']).skip === 3,
          'B7. the import\'s arguments are checked (STS-LDAP-0150)');
  log.debug("Leaving streamed().");
}

// ---------------------------------------------------------------------------
// C.
// ---------------------------------------------------------------------------
function statements(t) {
  log.debug("Entering statements().");
  t.log.info('=== C. the statements ===');
  const s = importer().STATEMENTS;
  t.check(/WHERE NOT EXISTS \(SELECT 1 FROM sts_ldap_entries e WHERE e\.realm = \$1 AND e\.dn_key = s\.k\)/
    .test(s.INSERT), 'C1. the insert is guarded by the DN');
  t.check(/e\.parent_key = \$2 AND e\.name_keys @> jsonb_build_array\(d\.d::text\)/
    .test(s.INSERT) && /e\.parent_key = \$2 AND e\.rdn_value = n\.n/
    .test(s.INSERT), 'C2. and by both of byName()\'s lookups, for every ' +
          'name the record proposes');
  t.check(/ON CONFLICT \(realm, dn_key\) DO NOTHING RETURNING dn_key/
    .test(s.INSERT) && !/parent_key,|rdn_value,/.test(
    s.INSERT.split('SELECT')[0]),
          'C3. it returns what it inserted, and never writes a generated ' +
          'column');
  const byName = require('../persistence/directory_queries')
    .byName('r', 'p', 'n').text;
  t.check(/name_keys @> \$3::jsonb OR rdn_value = \$4/.test(byName) &&
          /e\.name_keys @> jsonb_build_array\(n\.d::text\)/.test(
            s.CLASSIFY) && /e\.rdn_value = n\.n/.test(s.CLASSIFY),
          'C4. the classification asks what byName() asks');
  log.debug("Leaving statements().");
}

// ---------------------------------------------------------------------------
// D. A real database.
// ---------------------------------------------------------------------------
function dialOf(url) {
  log.debug("Entering dialOf().");
  const ca = process.env.STS_TEST_POSTGRES_CA || '';
  const dial = require('../persistence/persistence_postgres')
    .dialOptions(url, !!ca, ca ? fs.readFileSync(ca, 'utf8') : '');
  log.debug("Leaving dialOf().");
  return dial;
}

async function clientOf(url) {
  log.debug("Entering clientOf().");
  const pg = require('pg');
  const dial = dialOf(url);
  const client = new pg.Client({ connectionString: dial.connectionString,
                                 ssl: dial.ssl });
  await client.connect();
  log.debug("Leaving clientOf().");
  return client;
}

// The environment a child runs the service (or the import) in.
function childEnv(dbUrl, kekFile, extra) {
  log.debug("Entering childEnv().");
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, {
    LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal', STS_MODE: 'development',
    STS_HOST: '127.0.0.1', STS_PERSISTENCE_MODE: 'postgres',
    STS_DATABASE_URL: dbUrl, STS_KEYS_SOURCE: 'persisted',
    STS_KEYS_KEK_PROVIDER: 'file', STS_KEYS_KEK_FILE: kekFile,
    LDAP_PORT: '0', LDAPS_PORT: '0', LDAP_MAX_ENTRIES: '1000000',
    STS_RISK_BREACH_CHECK: 'off'
  }, extra || {});
  if (process.env.STS_TEST_POSTGRES_CA) {
    env.STS_DATABASE_TLS_CA_FILE = process.env.STS_TEST_POSTGRES_CA;
  } else {
    env.STS_DATABASE_TLS_REJECT_UNAUTHORIZED = 'false';
  }
  log.debug("Leaving childEnv().");
  return env;
}

function runChild(part, env, args) {
  log.debug("Entering runChild(). " + part);
  const out = path.join(os.tmpdir(), 'bulk-import-' + process.pid + '-' +
                        part + '-' + Date.now() + '.json');
  const childEnvironment = Object.assign({}, env, { BI_OUT: out });
  // The import's own refusals are what a failure here is read by.
  if (part === 'import') {
    childEnvironment.STS_LOG_LEVEL = 'error';
  }
  childEnvironment[CHILD] = part;
  const argv = part === 'import'
    ? [path.join(ROOT, 'persistence/bulk_import.js')].concat(args || [])
    : [__filename];
  const result = childProcess.spawnSync(process.execPath, argv, {
    env: childEnvironment, encoding: 'utf8', timeout: 600000, cwd: ROOT,
    maxBuffer: 64 * 1024 * 1024 });
  let report = null;
  try {
    report = part === 'import'
      ? JSON.parse(fs.readFileSync(String(args.filter(function (a) {
        return /^--report=/.test(a);
      })[0] || '').slice('--report='.length), 'utf8'))
      : JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
    report = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in runChild()'s clean-up: " + ((e && e.message) || e));
  }
  log.debug("Leaving runChild(). " + result.status);
  return { status: result.status, report: report,
           stderr: String(result.stderr || '') + String(result.stdout || '') };
}

// What the store holds, counted afresh and as the counters say.
async function tallies(db) {
  log.debug("Entering tallies().");
  const fresh = await db.query(
    'SELECT e.realm, b.base_key, count(*)::bigint AS n, count(*) FILTER ' +
    '(WHERE e.attr_names ? \'userpassword\')::bigint AS h FROM ' +
    'sts_ldap_entries e CROSS JOIN LATERAL sts_ldap_count_bases(e.parent_key)' +
    ' AS b(base_key) GROUP BY 1, 2 ORDER BY 1, 2');
  const kept = await db.query('SELECT realm, base_key, attribute, n FROM ' +
                              'sts_ldap_counts WHERE n <> 0 ORDER BY 1, 2, 3');
  const want = [];
  fresh.rows.forEach(function (r) {
    want.push([r.realm, r.base_key, '', String(r.n)].join('|'));
    if (Number(r.h)) {
      want.push([r.realm, r.base_key, 'userpassword', String(r.h)]
        .join('|'));
    }
  });
  want.sort();
  const have = kept.rows.map(function (r) {
    return [r.realm, r.base_key, r.attribute, String(r.n)].join('|');
  }).sort();
  const dekFresh = await db.query(
    'SELECT d.key AS k, sum(d.value::bigint)::bigint AS n FROM ' +
    'sts_ldap_entries e CROSS JOIN LATERAL jsonb_each_text(CASE WHEN ' +
    'jsonb_typeof(e.dek_keys) = \'object\' THEN e.dek_keys END) AS d GROUP ' +
    'BY 1 ORDER BY 1');
  const dekKept = await db.query('SELECT dek_id AS k, n FROM ' +
                                 'sts_ldap_dek_counts WHERE n <> 0 ORDER BY 1');
  const deltas = await db.query('SELECT (SELECT count(*) FROM ' +
    'sts_ldap_count_deltas)::int AS a, (SELECT count(*) FROM ' +
    'sts_ldap_dek_deltas)::int AS b');
  log.debug("Leaving tallies().");
  return {
    counts: { want: want, have: have },
    deks: { want: dekFresh.rows.map(function (r) {
      return r.k + '|' + r.n;
    }), have: dekKept.rows.map(function (r) {
      return r.k + '|' + r.n;
    }) },
    deltasLeft: deltas.rows[0].a + deltas.rows[0].b
  };
}

function sameTallies(t, label, got) {
  log.debug("Entering sameTallies().");
  t.check(got.counts.want.length > 0 &&
          JSON.stringify(got.counts.want) ===
            JSON.stringify(got.counts.have),
          label + ': every #618 counter equals a fresh count',
          JSON.stringify(got.counts));
  t.check(got.deks.want.length > 0 &&
          JSON.stringify(got.deks.want) === JSON.stringify(got.deks.have),
          label + ': every #623 data-key counter equals a fresh sum',
          JSON.stringify(got.deks));
  t.equal(got.deltasLeft, 0, label + ': and no delta is left behind');
  log.debug("Leaving sameTallies().");
}

// The LDIF the import is run over: N generated people, then the cases.
function writeFile(file, n, stamp) {
  log.debug("Entering writeFile().");
  const gen = require('./tools/generate-people-ldif');
  const parts = ['version: 1', ''];
  for (let i = 1; i <= n; i++) {
    parts.push(gen.recordOf(stamp, i, BASE));
  }
  const p = function (uid, extra) {
    return 'dn: uid=' + uid + ',' + USERS + '\nobjectClass: inetOrgPerson\n' +
      'uid: ' + uid + '\ncn: ' + uid + '\nsn: x\n' + (extra || '') + '\n';
  };
  // alice is seeded, and a second person proposes her name; load-<stamp>-1
  // is earlier in the file under its own DN; load-<stamp>-2 is repeated.
  parts.push(p('alice-' + stamp, 'uid: alice\n'));
  parts.push(p('dup-' + stamp, 'uid: load-' + stamp + '-1\n'));
  parts.push(p('load-' + stamp + '-2'));
  parts.push(p('bad-' + stamp, 'userPassword: secret\n'));
  parts.push('dn: uid=out-' + stamp + ',ou=groups,' + BASE + '\nuid: out-' +
             stamp + '\nobjectClass: inetOrgPerson\n\n');
  parts.push(p('last-' + stamp, 'mail: last-' + stamp + '@load.example\n'));
  fs.writeFileSync(file, parts.join('\n'));
  log.debug("Leaving writeFile().");
}

async function realDatabase(t, dir) {
  log.debug("Entering realDatabase().");
  const url = process.env.STS_TEST_POSTGRES_URL || '';
  if (!url) {
    t.log.info('=== D. skipped: STS_TEST_POSTGRES_URL names no database ' +
               '(the in-process suite has none) ===');
    log.debug("Leaving realDatabase(). Skipped.");
    return;
  }
  const n = Math.max(10, Number(process.env.STS_TEST_BULK_IMPORT_N) || 3000);
  t.log.info('=== D. against ' + url.replace(/:[^:@/]*@/, ':***@') +
             ', ' + n + ' people ===');
  const dbName = 'bulk_import_' + process.pid;
  const admin = await clientOf(url);
  const dbUrl = url.replace(/\/[^/?]*(\?|$)/, '/' + dbName + '$1');
  let db = null;
  try {
    await admin.query('CREATE DATABASE ' + dbName);
    db = await clientOf(dbUrl);
    const kekFile = path.join(dir, 'kek');
    fs.writeFileSync(kekFile, require('crypto').randomBytes(32)
      .toString('base64'));
    const env = childEnv(dbUrl, kekFile);

    // SEEDED BY A WHOLE-DIRECTORY PROCESS: a windowed one on an empty store
    // was seen to write the people of the seed and not its containers.
    const seeded = runChild('seed', Object.assign({}, env, {
      LDAP_WORKER_DIRECTORY: 'memory' }));
    if (!t.check(seeded.report && seeded.report.ok, 'D0. the service ' +
                 'started once in a child and seeded the realm\'s tree',
                 JSON.stringify(seeded.report) + ' ' +
                 seeded.stderr.slice(-3000))) {
      return;
    }
    await db.query('DELETE FROM sts_change_readers');
    const before = (await db.query('SELECT count(*)::int AS n FROM ' +
                                   'sts_ldap_entries')).rows[0].n;
    const stamp = 't' + process.pid;
    const file = path.join(dir, 'people.ldif');
    writeFile(file, n, stamp);
    const reportFile = path.join(dir, 'report.json');
    const first = runChild('import', env, ['--file=' + file,
                                           '--batch=700',
                                           '--report=' + reportFile]);
    const r = first.report || {};
    t.check(first.status === 3 && r.imported === n + 1,
            'D1. the import imported every person (and last-), and exits 3 ' +
            'for the records it did not import', 'status ' + first.status +
            ' ' + JSON.stringify(r).slice(0, 3000) + ' ' +
            first.stderr.slice(-3000));
    t.check(r.taken === 2 && r.present === 1 && r.refused === 2 &&
            r.refusals['STS-LDAP-0160'] === 2 &&
            r.refusals['STS-LDAP-0156'] === 1 &&
            r.refusals['STS-LDAP-0155'] === 1,
            'D3. a second alice (seeded) and a uid held earlier in the file are ' +
            'taken (STS-LDAP-0160), a repeated DN is present, the password ' +
            'and the DN outside ou=users are refused',
            JSON.stringify(r.examples));
    t.check((r.examples || []).some(function (e) {
      return e.reason.indexOf('uid=dup-' + stamp + ',') >= 0 &&
        e.reason.indexOf('held by uid=load-' + stamp + '-1,') >= 0;
    }) && (r.examples || []).some(function (e) {
      return e.reason.indexOf('uid=alice-' + stamp + ',') >= 0 &&
        e.reason.indexOf('held by uid=alice,ou=users,') >= 0;
    }), 'D3. the report names who holds the name', JSON.stringify(
      r.examples));
    const after = (await db.query('SELECT count(*)::int AS n FROM ' +
                                  'sts_ldap_entries')).rows[0].n;
    t.equal(after - before, n + 1, 'D1. that many rows are in the table');
    const rows = (await db.query(
      'SELECT dn_key, dn, attrs, origin, created_at, modified_at, ' +
      'name_keys, mail_keys, uuid_keys, class_keys, value_keys, attr_names, ' +
      'dek_keys, parent_key, rdn_value FROM sts_ldap_entries WHERE origin = ' +
      '\'bulk import\' AND dn_key LIKE \'uid=load-%\' ORDER BY dn_key ' +
      'LIMIT 50')).rows;
    t.check(rows.length === 50 && rows.every(function (row) {
      return typeof row.attrs === 'string' && /^\$aes/.test(row.attrs) &&
        row.parent_key === USERS && row.dek_keys &&
        Object.keys(row.dek_keys).length === 1 &&
        row.name_keys.length === 1 && !/\n/.test(row.name_keys[0]);
    }), 'D1. every row is SEALED, keyed (digests, not values), with its ' +
            'data key recorded and its generated columns',
            JSON.stringify(rows[0]).slice(0, 800));
    const opened = runChild('open', Object.assign({}, env, {
      BI_KEYS: JSON.stringify(rows.slice(0, 5).map(function (row) {
        return { key: row.dn_key, attrs: row.attrs, nameKeys: row.name_keys,
                 mailKeys: row.mail_keys, uuidKeys: row.uuid_keys,
                 classKeys: row.class_keys, valueKeys: row.value_keys,
                 attrNames: row.attr_names, dekKeys: row.dek_keys };
      })) }));
    const o = opened.report || {};
    t.check(o.ok && o.entries.length === 5 && o.entries.every(function (e) {
      return e.opened && e.indexMatches && e.dekMatches;
    }), 'D1. the sealed values OPEN under the service\'s keys, and the ' +
            'lookup columns and data keys are what the codec computes from ' +
            'what opened', JSON.stringify(o).slice(0, 2000) + ' ' +
            opened.stderr.slice(-2000));
    const a = (o.entries || [])[0] || {};
    const attrs = a.attributes || {};
    t.check(Object.keys(attrs).join(',') ===
            'objectclass,uid,cn,sn,givenname,displayname,mail,' +
            'createtimestamp,modifytimestamp,preferredlanguage,' +
            'stspreferredlanguagepopulated,entryuuid,stsmailverified' &&
            attrs.preferredlanguage[0] === 'en' &&
            /^[0-9a-f-]{36}$/.test(attrs.entryuuid[0]) &&
            attrs.stsmailverified[0] === attrs.mail[0],
            'D1. an opened entry is putEntry()\'s shape: the locale policy\'s ' +
            'language, a v4 entryUUID, the verified address',
            JSON.stringify(attrs));
    sameTallies(t, 'D2', await tallies(db));

    const deks = (await db.query('SELECT material FROM sts_keys WHERE realm ' +
                                 'LIKE \'dek:%\'')).rows.map(function (row) {
      return row.material;
    }).join('|');
    const second = runChild('import', env, ['--file=' + file,
                                            '--report=' + reportFile]);
    const r2 = second.report || {};
    t.check(r2.imported === 0 && r2.present === n + 2 && r2.taken === 2 &&
            (await db.query('SELECT count(*)::int AS n FROM ' +
                            'sts_ldap_entries')).rows[0].n === after,
            'D4. a re-run adds nothing: every person is present', JSON
              .stringify(r2).slice(0, 2000) + ' ' + second.stderr.slice(-2000));
    t.equal((await db.query('SELECT material FROM sts_keys WHERE realm LIKE ' +
                            '\'dek:%\'')).rows.map(function (row) {
      return row.material;
    }).join('|'), deks, 'D4. and makes no new data key');
    sameTallies(t, 'D4', await tallies(db));

    const read = runChild('read', Object.assign({}, env, {
      BI_NAMES: JSON.stringify(['load-' + stamp + '-1', 'LOAD-' + stamp +
                                '-' + n, 'last-' + stamp, 'dup-' + stamp]) }));
    const rr = read.report || {};
    const found = rr.found || {};
    t.check(rr.windowed === true, 'D5. the service started again with a ' +
            'windowed directory', JSON.stringify(rr).slice(0, 1500) + ' ' +
            read.stderr.slice(-2000));
    ['load-' + stamp + '-1', 'LOAD-' + stamp + '-' + n, 'last-' + stamp]
      .forEach(function (name) {
        const f = found[name] || {};
        t.check(f.existing && f.byName && f.byUuid && f.search &&
                f.search.mail === name.toLowerCase() + '@load.example' &&
                f.existing === f.search.dn.toLowerCase(),
                'D5. ' + name + ' is found by existingUserEntry(), byName, ' +
                'entryByUuid() (SCIM\'s id) and an LDAP search by uid',
                JSON.stringify(f));
      });
    t.check(found['dup-' + stamp] && !found['dup-' + stamp].existing &&
            !found['dup-' + stamp].search,
            'D5. and the person whose uid was taken is nobody',
            JSON.stringify(found['dup-' + stamp]));
    await db.query('DELETE FROM sts_change_readers');

    // D6. A running service, then the ceiling.
    await db.query('INSERT INTO sts_change_readers (origin, node_id, ' +
                   'applied, started_at, reported_at) VALUES (\'test\', ' +
                   '\'\', 0, 0, (extract(epoch from clock_timestamp()) * ' +
                   '1000)::bigint)');
    const running = runChild('import', env, ['--file=' + file,
                                             '--report=' + reportFile]);
    t.check(running.status === 1 && /STS-LDAP-0153/.test(running.stderr),
            'D6. a service that is running is refused (STS-LDAP-0153)',
            'status ' + running.status + ' ' + running.stderr.slice(-1500));
    await db.query('DELETE FROM sts_change_readers');
    const more = path.join(dir, 'more.ldif');
    const gen = require('./tools/generate-people-ldif');
    const moreSink = fs.createWriteStream(more);
    await gen.generate({ count: 50, stamp: 'm' + stamp, start: 1,
                         base: BASE }, moreSink);
    await new Promise(function (resolve) {
      moreSink.end(resolve);
    });
    // Counted afresh: the service started for D5 may have written entries
    // of its own (a CRL container, an application) since `after`.
    const base = (await db.query('SELECT count(*)::int AS n FROM ' +
                                 'sts_ldap_entries')).rows[0].n;
    const ceiling = base + 20;
    const capped = runChild('import', Object.assign({}, env, {
      LDAP_MAX_ENTRIES: String(ceiling) }), ['--file=' + more,
                                             '--batch=15',
                                             '--report=' + reportFile]);
    const rc = capped.report || {};
    const atCap = (await db.query('SELECT count(*)::int AS n FROM ' +
                                  'sts_ldap_entries')).rows[0].n;
    t.check(capped.status === 1 && rc.stopped === 'STS-LDAP-0157' &&
            atCap === ceiling && rc.imported === 20 &&
            rc.committedThrough === 15,
            'D6. ldap.maxEntries stops the import at the ceiling ' +
            '(STS-LDAP-0157), committed through the last whole batch',
            'status ' + capped.status + ' count ' + atCap + ' ' +
            JSON.stringify(rc).slice(0, 1500));
    const resumed = runChild('import', env, ['--file=' + more,
                                             '--skip=' + rc.committedThrough,
                                             '--report=' + reportFile]);
    const rs = resumed.report || {};
    t.check(resumed.status === 0 && rs.skipped === 15 &&
            rs.present === 5 && rs.imported === 30 &&
            (await db.query('SELECT count(*)::int AS n FROM ' +
                            'sts_ldap_entries')).rows[0].n === base + 50,
            'D6. raised, a run with --skip resumes: the five past the ' +
            'resume point already in are present, the rest imported',
            JSON.stringify(rs).slice(0, 1500) + ' ' +
            resumed.stderr.slice(-1500));
    sameTallies(t, 'D6', await tallies(db));
  } finally {
    if (db) {
      await db.end().catch(function (e) {
        log.debug("Caught in realDatabase()'s end: " + ((e && e.message) ||
                                                        e));
      });
    }
    await admin.query('DROP DATABASE IF EXISTS ' + dbName + ' WITH (FORCE)')
      .catch(function (e) {
        t.bad('D. the test database could not be dropped', String(
          (e && e.message) || e));
      });
    await admin.end();
  }
  log.debug("Leaving realDatabase().");
}

// ---------------------------------------------------------------------------
// The children.
// ---------------------------------------------------------------------------

// The service, as server.js starts it, without its listeners.
async function boot() {
  log.debug("Entering boot().");
  require('../common/protocol_stack');
  await require('../common/service_state').start();
  log.debug("Leaving boot().");
}

async function seedChild() {
  log.debug("Entering seedChild().");
  await boot();
  const persistence = require('../persistence/persistence');
  await persistence.flush();
  await require('../common/keystore').settleAll();
  await persistence.stop();
  log.debug("Leaving seedChild().");
  return { ok: true };
}

async function openChild() {
  log.debug("Entering openChild().");
  const keystore = require('../common/keystore');
  const persistence = require('../persistence/persistence');
  const postgres = require('../persistence/persistence_postgres');
  const connection = await persistence.databaseConnection();
  const driver = postgres.create({ url: connection.url, log: log,
                                   verifyTls: connection.verifyTls,
                                   tlsCa: connection.tlsCa });
  keystore.setStore({
    loadKeys: function () {
      log.debug("Entering loadKeys().");
      log.debug("Leaving loadKeys().");
      return driver.loadKeys();
    },
    saveKeys: function () {
      log.debug("Entering saveKeys().");
      log.debug("Leaving saveKeys().");
      return Promise.reject(new Error('the open child writes no key'));
    }
  });
  await keystore.start();
  const codec = require('../persistence/directory_codec').create('cell');
  const entries = JSON.parse(process.env.BI_KEYS || '[]').map(function (row) {
    const attrs = codec.openAttributes(row.key, row.attrs);
    const index = attrs ? codec.index(attrs) : {};
    return {
      key: row.key, opened: !!attrs, attributes: attrs,
      indexMatches: !!attrs && JSON.stringify([index.nameKeys,
        index.mailKeys, index.uuidKeys, index.classKeys, index.valueKeys,
        index.attrNames]) === JSON.stringify([row.nameKeys, row.mailKeys,
        row.uuidKeys, row.classKeys, row.valueKeys, row.attrNames]),
      dekMatches: !!attrs && JSON.stringify(codec.dekKeys(attrs, row.attrs)) ===
        JSON.stringify(row.dekKeys)
    };
  });
  await driver.close();
  log.debug("Leaving openChild().");
  return { ok: true, entries: entries };
}

function searchOne(port, name) {
  log.debug("Entering searchOne().");
  const ldapjs = require('ldapjs');
  log.debug("Leaving searchOne().");
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: 'ldap://127.0.0.1:' + port });
    client.on('error', function (e) {
      resolve({ error: String((e && e.message) || e) });
    });
    client.bind('cn=admin,' + BASE, 'x', function (bindErr) {
      if (bindErr) {
        client.unbind();
        resolve({ error: 'bind: ' + bindErr.message });
        return;
      }
      const found = [];
      client.search(USERS, { scope: 'one', filter: '(uid=' + name + ')',
                             attributes: ['mail', 'entryUUID'] },
      function (err, res) {
        if (err) {
          client.unbind();
          resolve({ error: err.message });
          return;
        }
        res.on('searchEntry', function (entry) {
          const mail = (entry.attributes || []).filter(function (a) {
            return a.type.toLowerCase() === 'mail';
          })[0];
          found.push({ dn: String(entry.objectName || entry.dn),
                       mail: mail ? mail.values[0] : '' });
        });
        res.on('error', function (e) {
          client.unbind();
          resolve({ error: e.message });
        });
        res.on('end', function () {
          client.unbind();
          resolve(found.length === 1 ? found[0] : null);
        });
      });
    });
  });
}

async function readChild() {
  log.debug("Entering readChild().");
  await boot();
  const ldap = require('../ldap/ldap_server');
  const realms = require('../common/realms');
  const window = ldap.directoryWindow;
  const ready = await ldap.listen().whenReady;
  const found = {};
  for (const name of JSON.parse(process.env.BI_NAMES || '[]')) {
    const existing = realms.run(realms.DEFAULT_REALM, function () {
      return ldap.existingUserEntry(name);
    });
    const rows = window ? await window.askAsync('byName', ['default',
      USERS, name]) : [];
    const uuid = existing ? (existing.attributes.entryuuid || [])[0] : '';
    const byUuid = uuid ? realms.run(realms.DEFAULT_REALM, function () {
      return ldap.entryByUuid(uuid);
    }) : null;
    // The search in lower case: the directory's own matching of a uid
    // value, which is not this test's subject.
    const search = await searchOne(ready.port, name.toLowerCase());
    found[name] = {
      existing: existing ? String(existing.dn).toLowerCase() : '',
      byName: (rows || []).length === 1 &&
        String(rows[0].key) === String(existing && existing.dn).toLowerCase(),
      byUuid: !!byUuid && byUuid.dn === (existing && existing.dn),
      search: search && !search.error ? search : (search ? search : null)
    };
  }
  await require('../persistence/persistence').stop();
  log.debug("Leaving readChild().");
  return { windowed: !!(window && window.attached()), found: found };
}

async function childMain() {
  log.debug("Entering childMain().");
  let report = null;
  try {
    const part = process.env[CHILD];
    report = part === 'seed' ? await seedChild()
      : part === 'open' ? await openChild() : await readChild();
  } catch (e) {
    log.debug("Caught in childMain(): " + ((e && e.message) || e));
    report = { error: String((e && e.stack) || e) };
  }
  fs.writeFileSync(process.env.BI_OUT, JSON.stringify(report));
  log.debug("Leaving childMain().");
  process.exit(0);
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-bulk-import-'));
  try {
    records(t);
    await streamed(t, dir);
    statements(t);
    await realDatabase(t, dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD]) {
  childMain();
}

module.exports = {
  name: 'bulk_import',
  describe: 'the bulk directory import (#629): records, the stream, the ' +
            'statements, and against a real postgres when one is named — ' +
            'every row sealed and found, counters exact, duplicates and ' +
            're-runs, a running service and the ceiling refused',
  run: run
};
