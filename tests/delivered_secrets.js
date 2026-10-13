// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: delivered_secrets.js
//
// ===========================================================================
// A SECRET DELIVERED AS A FILE IS READ ONCE, DELETED, AND NEVER AN
// ENVIRONMENT VARIABLE OF THE PROCESS; AND NOTHING IN /run/secrets OPENS
// /admin-api (#254, 2026-10-06).
//
// 1–4 drive `common/delivered_secrets.ts` in a CHILD process each, because
// what it holds is config.js's process-wide environment layer and a test run
// is one process: a delivered `adminApi.clientSecret` here would be every
// later test's. 1 delivers a file (the value at the environment layer, the
// file gone, `<ENV>_FILE` forgotten, `process.env` untouched, the workers'
// share); 2 a file above a variable of the same setting; 3 and 4 the two
// refusals that stop the service (STS-CORE-0150, 0151).
//
// 5 holds the three lists of start-up secrets to one another — the
// service's settings, the start-up helper's fields and variables, and the
// seeder's fields — because a field the seeder writes and the helper does
// not deliver is a secret that silently never arrives.
//
// 6 and 7 read the compose files as TEXT, as `tests/stack_network.js` does:
// the `sts` service of both starts as root, drops to uid 10001 through
// `setpriv`, sets the unprivileged-port sysctl, hands over on a tmpfs, mounts
// no `sts-secrets` volume, and has neither the management API secret nor
// the Kerberos passwords in its environment; the seeder revokes root by
// keeping no `root.token`; `request_pool.js` hands the workers their share.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const delivered = require('../common/delivered_secrets');
const config = require('../common/config');

const log = require('bunyan').createLogger({ name: 'delivered_secrets_test',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child: load() over the environment it was given, and a JSON answer.
const CHILD = [
  "'use strict';",
  "const out = {};",
  "try {",
  "  const d = require('./common/delivered_secrets');",
  "  const config = require('./common/config');",
  "  out.keys = d.load();",
  "  out.value = config.value('adminApi.clientSecret');",
  "  out.source = config.sourceOf('adminApi.clientSecret');",
  "  out.fileVar = process.env.ADMIN_API_CLIENT_SECRET_FILE === undefined",
  "    ? null : process.env.ADMIN_API_CLIENT_SECRET_FILE;",
  "  out.envVar = process.env.ADMIN_API_CLIENT_SECRET === undefined",
  "    ? null : process.env.ADMIN_API_CLIENT_SECRET;",
  "  out.workers = d.workerEnvironment();",
  "} catch (e) {",
  "  out.error = String((e && e.message) || e);",
  "}",
  "process.stdout.write('\\nRESULT ' + JSON.stringify(out) + '\\n');"
].join('\n');

function child(env) {
  log.debug("Entering child().");
  const merged = Object.assign({}, process.env, { LOG_LEVEL: 'fatal',
                                                 STS_LOG_LEVEL: 'fatal' });
  delete merged.ADMIN_API_CLIENT_SECRET;
  delete merged.ADMIN_API_CLIENT_SECRET_FILE;
  Object.keys(env).forEach(function (k) {
    merged[k] = env[k];
  });
  const text = childProcess.execFileSync(process.execPath, ['-e', CHILD],
    { cwd: ROOT, env: merged, encoding: 'utf8', timeout: 60000 });
  // The child's own loggers write to stdout too; the answer is the line
  // after the marker.
  const line = text.split('\n').filter(function (one) {
    return one.indexOf('RESULT ') === 0;
  })[0] || 'RESULT {"error":"the child printed no result"}';
  log.debug("Leaving child().");
  return JSON.parse(line.slice('RESULT '.length));
}

function checkADeliveredFile(t, dir) {
  log.debug("Entering checkADeliveredFile().");
  t.log.info('=== 1. a file is read once, deleted, and held at the ' +
             'environment layer ===');
  const file = path.join(dir, 'ADMIN_API_CLIENT_SECRET');
  fs.writeFileSync(file, '  the-delivered-secret\n', { mode: 0o400 });
  const got = child({ ADMIN_API_CLIENT_SECRET_FILE: file });
  t.check(!got.error, 'load() delivered without an error', got.error || '');
  t.check(got.value === 'the-delivered-secret',
          'adminApi.clientSecret is the file\'s value, trimmed',
          JSON.stringify(got.value));
  t.check(got.source === 'env', 'its source reads as the environment',
          got.source);
  t.check(!fs.existsSync(file), 'the file is deleted once it is read',
          file);
  t.check(got.fileVar === null,
          'ADMIN_API_CLIENT_SECRET_FILE is forgotten after the read',
          String(got.fileVar));
  t.check(got.envVar === null,
          'the value is never put in process.env',
          String(got.envVar));
  t.check(got.workers &&
          got.workers.ADMIN_API_CLIENT_SECRET === 'the-delivered-secret',
          'a request worker\'s thread is handed it as a variable of its own',
          JSON.stringify(Object.keys(got.workers || {})));
  log.debug("Leaving checkADeliveredFile().");
}

function checkFileAboveVariable(t, dir) {
  log.debug("Entering checkFileAboveVariable().");
  t.log.info('=== 2. a file and a variable for one setting: the file ===');
  const file = path.join(dir, 'ADMIN_API_CLIENT_SECRET-2');
  fs.writeFileSync(file, 'from-the-file');
  const got = child({ ADMIN_API_CLIENT_SECRET_FILE: file,
                      ADMIN_API_CLIENT_SECRET: 'from-the-variable' });
  t.check(got.value === 'from-the-file',
          'the delivered file wins over the variable of the same setting',
          JSON.stringify(got.value));
  log.debug("Leaving checkFileAboveVariable().");
}

function checkTheRefusals(t, dir) {
  log.debug("Entering checkTheRefusals().");
  t.log.info('=== 3, 4. an unreadable or empty file stops the service ===');
  const missing = child({ ADMIN_API_CLIENT_SECRET_FILE:
                            path.join(dir, 'not-there') });
  t.check(/STS-CORE-0150/.test(missing.error || ''),
          'a file that cannot be read is STS-CORE-0150',
          missing.error || '(no error)');
  const empty = path.join(dir, 'empty');
  fs.writeFileSync(empty, '\n');
  const got = child({ ADMIN_API_CLIENT_SECRET_FILE: empty });
  t.check(/STS-CORE-0151/.test(got.error || ''),
          'an empty file is STS-CORE-0151', got.error || '(no error)');
  log.debug("Leaving checkTheRefusals().");
}

// The quoted strings of one array literal in a source file.
function quotedIn(text, member) {
  log.debug("Entering quotedIn(). " + member);
  const re = new RegExp(member + ":\\s*'([^']+)'", 'g');
  const out = [];
  let m = re.exec(text);
  while (m) {
    out.push(m[1]);
    m = re.exec(text);
  }
  log.debug("Leaving quotedIn(). " + out.length);
  return out.sort();
}

function checkTheThreeLists(t) {
  log.debug("Entering checkTheThreeLists().");
  t.log.info('=== 5. the settings, the helper and the seeder agree ===');
  const envs = delivered.keys().map(function (key) {
    return config.SETTINGS.filter(function (row) {
      return row.key === key;
    })[0].env;
  }).sort();
  const helper = fs.readFileSync(path.join(ROOT, 'openbao',
                                           'startup-secrets.js'), 'utf8');
  const seeder = fs.readFileSync(path.join(ROOT, 'openbao', 'seed.js'),
                                 'utf8');
  t.check(JSON.stringify(quotedIn(helper, 'env')) === JSON.stringify(envs),
          'startup-secrets.js delivers exactly the settings ' +
          'delivered_secrets.ts accepts', JSON.stringify(envs));
  const seederFields = quotedIn(seeder.slice(seeder.indexOf('ADMIN_FIELDS')),
                                'field');
  t.check(JSON.stringify(quotedIn(helper, 'field')) ===
          JSON.stringify(seederFields),
          'startup-secrets.js reads exactly the fields seed.js writes',
          JSON.stringify(seederFields));
  log.debug("Leaving checkTheThreeLists().");
}

// The text of one service's block in a compose file: from its name to the
// next service at the same indent.
function serviceBlock(text, name) {
  log.debug("Entering serviceBlock(). " + name);
  const start = text.indexOf('\n  ' + name + ':\n');
  if (start < 0) {
    log.debug("Leaving serviceBlock(). Absent.");
    return '';
  }
  const rest = text.slice(start + 1);
  const next = rest.slice(3).search(/\n {2}[a-z0-9][a-z0-9-]*:\n/);
  log.debug("Leaving serviceBlock().");
  return next < 0 ? rest : rest.slice(0, next + 3);
}

function checkTheComposeFiles(t) {
  log.debug("Entering checkTheComposeFiles().");
  t.log.info('=== 6. the compose files: root only until setpriv, nothing ' +
             'secret in the environment ===');
  ['docker-compose.yml', 'docker-compose-run-tests.yml'].forEach(function (f) {
    const text = fs.readFileSync(path.join(ROOT, f), 'utf8');
    const sts = serviceBlock(text, 'sts');
    const lines = sts.split('\n').filter(function (line) {
      return !/^\s*#/.test(line);
    }).join('\n');
    t.check(/\n {4}user: "0"\n/.test(lines),
            f + ': the sts command starts as root', '');
    t.check(/exec setpriv --reuid=10001 --regid=10001 --clear-groups/
              .test(lines) && /--bounding-set=-all --no-new-privs node /
              .test(lines),
            f + ': node is exec\'d as uid 10001 with no capabilities', '');
    t.check(/net\.ipv4\.ip_unprivileged_port_start=0/.test(lines),
            f + ': the low ports are opened by the sysctl', '');
    t.check(/\/run\/sts-startup:mode=0700,uid=10001,gid=10001/.test(lines),
            f + ': the hand-over is a tmpfs of uid 10001\'s', '');
    t.check(!/sts-secrets/.test(lines),
            f + ': no sts-secrets volume is mounted', '');
    const named = /^\s+- (ADMIN_API_CLIENT_SECRET|KRB5_KRBTGT_PASSWORD|KRB5_SERVICE_PASSWORD)\b/m;
    t.check(!named.test(lines),
            f + ': no start-up secret is in the sts environment', '');
    t.check(/sts-bao-client:\/run\/secrets\/openbao:ro/.test(lines),
            f + ': the client credential is mounted read-only', '');
    const healthy = /seed\/seeder\.token/.test(text) &&
                    !/seed\/root\.token/.test(text);
    t.check(healthy, f + ': the store\'s probe names the seeder token and no ' +
            'root token', '');
  });
  log.debug("Leaving checkTheComposeFiles().");
}

function checkTheWorkers(t) {
  log.debug("Entering checkTheWorkers().");
  t.log.info('=== 7. the workers are handed their share ===');
  const pool = fs.readFileSync(path.join(ROOT, 'common', 'request_pool.js'),
                               'utf8');
  t.check(/require\('\.\/delivered_secrets'\)\.workerEnvironment\(\)/
            .test(pool),
          'request_pool.js starts each worker thread with ' +
          'workerEnvironment()', '');
  const seeder = fs.readFileSync(path.join(ROOT, 'openbao', 'seed.js'),
                                 'utf8');
  t.check(!/writeFileSync\([^)]*root/i.test(seeder.replace(/\n/g, ' ')
            .replace(/\s+/g, ' ')),
          'seed.js writes no root token anywhere', '');
  log.debug("Leaving checkTheWorkers().");
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-delivered-'));
  try {
    checkADeliveredFile(t, dir);
    checkFileAboveVariable(t, dir);
    checkTheRefusals(t, dir);
    checkTheThreeLists(t);
    checkTheComposeFiles(t);
    checkTheWorkers(t);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'delivered_secrets',
  describe: 'that a secret named by <ENV>_FILE is read once, deleted, held ' +
            'at the environment layer and never put in process.env, that ' +
            'the start-up helper, the seeder and the service agree on the ' +
            'start-up secrets, and that the compose stacks run node as uid ' +
            '10001 with no secret in its environment (#254)',
  run: run
};
