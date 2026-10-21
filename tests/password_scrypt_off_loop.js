// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/password_scrypt_off_loop.js
// ===========================================================================
// A SIGN-IN'S PASSWORD CHECK AND AN LDAP PASSWORD WRITE RUN SCRYPT ON
// LIBUV'S THREAD POOL (#756).
//
// Under a sustained load on 8081 more than half of a request worker was
// `scryptSync`: the sign-in screen's `credentials.verify()` and an LDAP
// write's `preparePassword()` each held the worker's event loop for about
// 70 ms. The asynchronous doors give the same answers; this holds that the
// two paths take them.
//
// The stack in a child process (the sign-in needs the whole router):
//
//   A. THE SIGN-IN SCREEN: a password sign-in through `/authn-api` calls
//      `credentials.verifyAsync()` and never `credentials.verify()`, and a
//      refused password is still refused.
//   B. AN LDAP ADD AND MODIFY carrying a clear `userPassword` hash it with
//      `crypto.hashSecretAsync()` and never `crypto.hashSecret()`; each hash
//      made is a scrypt hash of that password (it verifies), two people
//      given one password get two different hashes (a salt each), and each
//      entry stores the one made for it (an LDAP compare, which development
//      mode answers for `userPassword`).
//
// Development mode, where `verify()` checks no password: what is held is
// WHICH door each path takes, and the stored form; the cost of the hash is
// the same function either way (`common/crypto.js`).
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'password_scrypt_off_loop',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.PS_ROOT;
  const OUT = process.env.PS_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  // Counts the calls to `name` on `obj` from here on, still calling it.
  function counted(obj, name) {
    const original = obj[name];
    const tally = { n: 0, answers: [] };
    obj[name] = function () {
      tally.n += 1;
      const answer = original.apply(this, arguments);
      Promise.resolve(answer).then(function (value) {
        tally.answers.push(value);
      }, function () {
        tally.answers.push(null);
      });
      return answer;
    };
    return tally;
  }
  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const authn = require(ROOT_DIR + '/authn/authn');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const stsCrypto = require(ROOT_DIR + '/common/crypto');
    const ldapServer = require(ROOT_DIR + '/ldap/ldap_server');
    const ldap = require('ldapjs');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;

    // --- A. the sign-in screen ----------------------------------------
    const sync = counted(credentials, 'verify');
    const async = counted(credentials, 'verifyAsync');
    let at = authn.beginAuthentication({ returnTo: '/ps/after',
      protocol: 'ps-probe', application: '' });
    let jar = {};
    let r = await screen.submit({ port: port, jar: jar, at: at,
      fields: { action: 'login', username: 'ps-ann', password: 'invalid' } });
    note(r.next === 'refused',
         'A1. a refused password is still refused', r.text);
    r = await screen.submit({ port: port, jar: jar, at: at,
      fields: { action: 'login', username: 'ps-ann', password: 'right' } });
    note(r.next === 'redirect' && r.location === '/ps/after',
         'A2. and a password signs in', r.text);
    note(async.n === 2 && sync.n === 0,
         'A3. the screen asked credentials.verifyAsync() twice and ' +
         'credentials.verify() never',
         'verifyAsync ' + async.n + ', verify ' + sync.n);

    // --- B. an LDAP add and modify --------------------------------------
    const hashSync = counted(stsCrypto, 'hashSecret');
    const hashAsync = counted(stsCrypto, 'hashSecretAsync');
    const USERS = 'ou=users,dc=example,dc=com';
    const operation = function (name, fields) {
      const req = {
        connection: { encrypted: true,
                      ldap: { bindDN: 'cn=admin,dc=example,dc=com',
                              id: 'password-scrypt-off-loop' },
                      remoteAddress: '127.0.0.1', remotePort: 40000 }
      };
      req.dn = ldap.parseDN(fields.dn);
      if (fields.attributes) {
        req.attributes = fields.attributes;
      }
      if (fields.changes) {
        req.changes = fields.changes;
      }
      if (fields.attribute) {
        req.attribute = fields.attribute;
        req.value = fields.value;
      }
      const shape = ldapServer.operationRequest(name, req);
      return Promise.resolve(ldapServer.performOperation(name,
        JSON.parse(JSON.stringify(shape))));
    };
    const password = 'Ps-Off-Loop-' + Date.now() + '!q';
    const person = function (uid, withPassword) {
      const out = [{ type: 'objectClass', values: ['top', 'inetOrgPerson'] },
                   { type: 'uid', values: [uid] },
                   { type: 'cn', values: [uid] },
                   { type: 'sn', values: [uid] }];
      if (withPassword) {
        out.push({ type: 'userPassword', values: [password] });
      }
      return out;
    };
    const stores = async function (dn, value) {
      const answer = await operation('compare', { dn: dn,
        attribute: 'userPassword', value: String(value || '') });
      return answer.ok === true && answer.endArg === true;
    };
    const one = 'uid=ps-one,' + USERS;
    const two = 'uid=ps-two,' + USERS;
    r = await operation('add', { dn: one, attributes: person('ps-one', true) });
    note(r.ok === true, 'B1. an add carrying a clear userPassword succeeds',
         r.error || '');
    r = await operation('add', { dn: two, attributes: person('ps-two',
                                                              false) });
    note(r.ok === true, 'B2. a second person is added without one',
         r.error || '');
    r = await operation('modify', { dn: two, changes: [new ldap.Change({
      operation: 'replace',
      modification: new ldap.Attribute({ type: 'userPassword',
                                         values: [password] })
    })] });
    note(r.ok === true, 'B3. a modify setting a clear userPassword succeeds',
         r.error || '');
    note(hashAsync.n === 2 && hashSync.n === 0,
         'B4. both hashed on the thread pool (crypto.hashSecretAsync() ' +
         'twice) and never with crypto.hashSecret()',
         'hashSecretAsync ' + hashAsync.n + ', hashSecret ' + hashSync.n);
    const hashOne = String(hashAsync.answers[0] || '');
    const hashTwo = String(hashAsync.answers[1] || '');
    note(stsCrypto.isHashedSecret(hashOne) &&
         stsCrypto.isHashedSecret(hashTwo) &&
         stsCrypto.verifySecret(password, hashOne) &&
         stsCrypto.verifySecret(password, hashTwo),
         'B5. each hash made is a scrypt hash of the password sent',
         hashOne.slice(0, 12) + ' ' + hashTwo.slice(0, 12));
    note(hashOne !== hashTwo,
         'B6. one password for two people is two hashes (a salt each)');
    note(await stores(one, hashOne) && await stores(two, hashTwo) &&
         !(await stores(one, password)),
         'B7. each entry stores the hash made for it, not the password');
    await operation('del', { dn: one });
    await operation('del', { dn: two });

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(1);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'ps-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  PS_ROOT: ROOT, PS_OUT: out,
                                  STS_AUTHN_MULTIPLE_ACCOUNTS: 'false' }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'password_scrypt_off_loop',
  describe: 'a sign-in\'s password check and an LDAP password write run ' +
            'scrypt on libuv\'s thread pool (#756): the asynchronous doors, ' +
            'and the same stored form',
  run: run
};
