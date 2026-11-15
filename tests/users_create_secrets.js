// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/users_create_secrets.js
//
// ---------------------------------------------------------------------------
// `POST /admin-api/users/create` ANSWERS NO STORED CREDENTIAL (2026-11-14).
//
// The answer's `entry` was the entry as the directory holds it, read AFTER
// the credential step had written to it, so it carried the new person's
// `userPassword` scrypt hash, and with `credential: activation` the
// activation token's hash. #444's Rust port found it. The answer now masks
// every attribute `SECRET_ATTRIBUTES` names with `ldap/directory_secrets.ts`,
// the function every `GET /admin-api/ldap/*` answer uses.
//
// What the administrator hands over is NOT a stored secret and stays (rcbj,
// 2026-11-14): a generated password is answered once in `password`, and an
// activation link in `activationUrl`. `pwdChangedTime` is not a secret and
// stays as it was.
//
// The claims, over HTTP against the whole protocol stack in a child process,
// in a throwaway development-mode realm:
//
//   U1. `credential: generate` answers the generated password, and it is
//       the one the stored hash verifies.
//   U2. that answer carries neither the stored `userPassword` hash nor any
//       other value of a secret attribute the entry holds; every secret
//       attribute it names is masked.
//   U3. `pwdChangedTime`, where the entry holds one, is answered unmasked.
//   U4. `credential: activation` answers the link, and not the stored
//       token hash or any other secret value.
//
// A CHILD PROCESS, as tests/enrollment_model_wire.js runs one: the stack and
// a listener are loaded once, fresh, and nothing leaks into the runner.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'users_create_secrets',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  const ROOT_DIR = process.env.UCS_ROOT;
  const OUT = process.env.UCS_OUT;
  const http = require('http');
  const fs = require('fs');
  const record = { rows: [], problems: [] };

  function note(ok, what, detail) {
    record.rows.push({ ok: !!ok, what: what,
                       detail: detail === undefined ? '' : String(detail) });
  }

  // Every string in a value, however deep.
  function stringsIn(value, out) {
    if (typeof value === 'string') {
      out.push(value);
    } else if (Array.isArray(value)) {
      value.forEach(function (one) {
        stringsIn(one, out);
      });
    } else if (value && typeof value === 'object') {
      Object.keys(value).forEach(function (key) {
        stringsIn(value[key], out);
      });
    }
    return out;
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const realms = require(ROOT_DIR + '/common/realms');
    const ldapServer = require(ROOT_DIR + '/ldap/ldap_server');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const DirectorySecrets = require(ROOT_DIR + '/ldap/directory_secrets');
    const server = http.createServer(app);
    await new Promise(function (resolve) {
      server.listen(0, '127.0.0.1', resolve);
    });
    const base = 'http://127.0.0.1:' + server.address().port;
    const REALM = 'ucsecrets';
    realms.create({ id: REALM, name: 'Users create secrets' });

    async function create(body) {
      const r = await fetch(base + '/realm/' + REALM +
                            '/admin-api/users/create', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body) });
      const text = await r.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch (e) {
        json = { raw: text.slice(0, 300) };
      }
      if (r.status !== 200) {
        record.problems.push('users/create answered ' + r.status + ': ' +
                             text.slice(0, 300));
      }
      return json;
    }

    // The values the entry STORES for every secret attribute, read from the
    // directory itself rather than from any answer.
    function storedSecrets(username) {
      return realms.run(REALM, function () {
        const located = ldapServer.locateEntry(username);
        const attrs = (located && located.stored &&
                       located.stored.attributes) || {};
        const out = { values: [], names: [], attrs: attrs };
        Object.keys(attrs).forEach(function (name) {
          if (DirectorySecrets.isSecret(name)) {
            out.names.push(name.toLowerCase());
            [].concat(attrs[name]).forEach(function (one) {
              if (one !== undefined && one !== null && one !== '') {
                out.values.push(String(one));
              }
            });
          }
        });
        return out;
      });
    }

    // Whether every secret attribute the answer's entry names is masked.
    function allMasked(answer) {
      const attrs = (answer.entry && answer.entry.attributes) || {};
      return Object.keys(attrs).filter(function (name) {
        return DirectorySecrets.isSecret(name);
      }).every(function (name) {
        return [].concat(attrs[name]).every(function (one) {
          return one === DirectorySecrets.MASK || one === '' ||
                 one === null || one === undefined;
        });
      });
    }

    function leaked(answer, stored) {
      const strings = stringsIn(answer, []);
      return stored.values.filter(function (secret) {
        return strings.some(function (one) {
          return one.indexOf(secret) >= 0;
        });
      });
    }

    const GEN = 'ucsgen';
    const generated = await create({ username: GEN, invent: false,
      credential: 'generate',
      attributes: { cn: 'Ucs Gen', sn: 'Gen', givenName: 'Ucs',
                    mail: GEN + '@example.test' } });
    const genStored = storedSecrets(GEN);
    const verified = typeof generated.password === 'string' &&
      generated.password.length > 0 &&
      await realms.run(REALM, function () {
        const checked = credentials.verify(GEN, generated.password);
        return !!(checked && checked.ok);
      });
    note(generated.ok === true && generated.passwordSet === true &&
         verified && genStored.names.indexOf('userpassword') >= 0,
         'U1. credential generate answers the generated password once, ' +
         'and the stored hash verifies it',
         JSON.stringify({ ok: generated.ok, passwordSet: generated.passwordSet,
                          hasPassword: typeof generated.password, verified:
                          !!verified, storedSecrets: genStored.names }));
    const genLeaks = leaked(generated, genStored);
    note(genStored.values.length > 0 && genLeaks.length === 0 &&
         allMasked(generated),
         'U2. the answer carries no stored hash or other secret value, ' +
         'and every secret attribute it names is masked',
         JSON.stringify({ stored: genStored.names, leaked: genLeaks.length,
                          entry: generated.entry }).slice(0, 1500));
    const changed = genStored.attrs.pwdchangedtime ||
                    genStored.attrs.pwdChangedTime;
    const shown = generated.entry && generated.entry.attributes
      ? (generated.entry.attributes.pwdchangedtime ||
         generated.entry.attributes.pwdChangedTime) : undefined;
    note(!changed || JSON.stringify(shown) === JSON.stringify(changed),
         'U3. pwdChangedTime is not a secret and is answered as stored',
         JSON.stringify({ stored: changed, answered: shown }));

    const ACT = 'ucsact';
    const activated = await create({ username: ACT, invent: false,
      credential: 'activation',
      attributes: { cn: 'Ucs Act', sn: 'Act', givenName: 'Ucs',
                    mail: ACT + '@example.test' } });
    const actStored = storedSecrets(ACT);
    const actLeaks = leaked(activated, actStored);
    note(activated.ok === true &&
         /#token=/.test(String(activated.activationUrl || '')) &&
         actStored.names.indexOf('stsactivationtoken') >= 0 &&
         actLeaks.length === 0 && allMasked(activated),
         'U4. credential activation answers the link and no stored token ' +
         'hash or other secret value',
         JSON.stringify({ ok: activated.ok, link: !!activated.activationUrl,
                          stored: actStored.names, leaked: actLeaks.length,
                          entry: activated.entry }).slice(0, 1500));

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  })().catch(function (e) {
    record.problems.push(e && e.stack ? e.stack : String(e));
    fs.writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  });
}

function capture() {
  log.debug("Entering capture().");
  const out = path.join(os.tmpdir(), 'users-create-secrets-' + process.pid +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|ACME_|CONFIG_FILE$)/
      .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  ADMIN_API_AUTH_REQUIRED: 'false',
                                  UCS_ROOT: ROOT, UCS_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let record = null;
  try {
    record = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in capture(): " + ((e && e.message) || e));
    log.debug("Leaving capture(). No record: exit " + result.status + " " +
              String(result.stderr || '').slice(-800));
    return null;
  }
  log.debug("Leaving capture().");
  return record;
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== POST /admin-api/users/create answers no stored ' +
             'credential ===');
  const got = capture();
  if (!t.check(!!got, 'the child process reported')) {
    log.debug("Leaving run(). No child.");
    return;
  }
  t.check(got.problems.length === 0, 'the child ran to the end',
          got.problems.join('\n'));
  t.check(got.rows.length === 4, 'all four claims were checked',
          got.rows.length);
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'users_create_secrets',
  describe: 'POST /admin-api/users/create answers the generated password ' +
            'and the activation link, and no stored credential: every ' +
            'secret attribute of the entry it answers is masked',
  run: run
};
