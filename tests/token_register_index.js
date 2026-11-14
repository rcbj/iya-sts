// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: token_register_index.js
//
// ===========================================================================
// A PERSON'S LIVE TOKENS ARE FOUND BY AN INDEX, NOT A WALK (#766).
//
// `admin_stats.holdsLiveIssuance()` is asked before every CAEP
// token-claims-change and walked the whole token register to answer: 9% of
// a request worker under a password-write load on 8081. `realms.map()`
// offers an index (`indexBy`, `lookup()`) kept by the partition Map in its
// own set, delete and clear, and the register files every record by
// `username` and by `sub`.
//
//   I. THE INDEX: a record is filed on set, moved when an overwrite changes
//      what it is filed under, gone on delete and on clear, kept through the
//      journalling view (`realmMap()`), and per realm.
//   L. THE QUESTION: across sixty people with live, expired, revoked and
//      ID tokens, found by username and by sub, holdsLiveIssuance() answers
//      exactly what each was given.
//
// In a child process: it fills module-wide stores.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'token_register_index',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: fills the stores and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.TI_ROOT;
  const OUT = process.env.TI_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    const realms = require(ROOT_DIR + '/common/realms');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const stats = require(ROOT_DIR + '/common/admin_stats');

    // --- I. the index ---------------------------------------------------
    const store = realms.map({
      indexBy: function (v) {
        return v && v.owner ? ['o:' + v.owner] : [];
      }
    });
    store.set('k1', { owner: 'ann' });
    store.set('k2', { owner: 'ann' });
    store.set('k3', { owner: 'bob' });
    note(JSON.stringify(store.lookup('o:ann').sort()) === '["k1","k2"]',
         'I1. a record is filed on set', JSON.stringify(store.lookup('o:ann')));
    store.set('k2', { owner: 'bob' });
    note(JSON.stringify(store.lookup('o:ann')) === '["k1"]' &&
         JSON.stringify(store.lookup('o:bob').sort()) === '["k2","k3"]',
         'I2. an overwrite moves it to what it is filed under now');
    store.delete('k1');
    note(store.lookup('o:ann').length === 0, 'I3. a delete takes it out');
    store.realmMap().set('k4', { owner: 'cat' });
    note(JSON.stringify(store.lookup('o:cat')) === '["k4"]',
         'I4. a write through the journalling view is filed too');
    store.realmMap().delete('k4');
    note(store.lookup('o:cat').length === 0,
         'I5. and a delete through it is taken out');
    store.clear();
    note(store.lookup('o:bob').length === 0, 'I6. clear empties the index');
    const plain = realms.map({});
    plain.set('x', { owner: 'ann' });
    note(Array.isArray(plain.lookup('o:ann')) &&
         plain.lookup('o:ann').length === 0,
         'I7. a store with no index answers an empty lookup');

    // --- L. the question ------------------------------------------------
    const now = helpers.nowSec();
    const expected = {};
    for (let i = 0; i < 60; i++) {
      const who = 'ti-' + i;
      const sub = 'urn:uuid:ti-' + i;
      const kind = i % 6;
      // 0 live access token by username; 1 live refresh by sub only;
      // 2 expired; 3 revoked; 4 an ID token (live); 5 nothing.
      if (kind === 0) {
        helpers.signJwt({ iss: 'https://sts.example', sub: sub, aud: 'c',
          typ: 'Bearer', jti: 'ti-a-' + i, username: who, iat: now,
          exp: now + 600 }, {});
        expected[i] = true;
      } else if (kind === 1) {
        helpers.signJwt({ iss: 'https://sts.example', sub: sub, aud: 'c',
          typ: 'Refresh', jti: 'ti-r-' + i, iat: now, exp: now + 600 }, {});
        expected[i] = true;
      } else if (kind === 2) {
        helpers.signJwt({ iss: 'https://sts.example', sub: sub, aud: 'c',
          typ: 'Bearer', jti: 'ti-e-' + i, username: who, iat: now - 7200,
          exp: now - 3600 }, {});
        expected[i] = false;
      } else if (kind === 3) {
        helpers.signJwt({ iss: 'https://sts.example', sub: sub, aud: 'c',
          typ: 'Bearer', jti: 'ti-v-' + i, username: who, iat: now,
          exp: now + 600 }, {});
        stats.revoke('ti-v-' + i, 'token_register_index');
        expected[i] = false;
      } else if (kind === 4) {
        helpers.signJwt({ iss: 'https://sts.example', sub: sub, aud: 'c',
          jti: 'ti-i-' + i, username: who, iat: now, exp: now + 600 },
          {}, { kind: 'id_token' });
        expected[i] = null;
      } else {
        expected[i] = false;
      }
    }
    const wrong = [];
    for (let i = 0; i < 60; i++) {
      if (expected[i] === null) {
        continue;
      }
      const got = stats.holdsLiveIssuance('ti-' + i, 'urn:uuid:ti-' + i);
      if (got !== expected[i]) {
        wrong.push(i + ':' + got);
      }
    }
    note(wrong.length === 0,
         'L1. live access and refresh tokens count, by username and by ' +
         'sub; expired and revoked ones and nothing do not', wrong.join(' '));
    note(stats.holdsLiveIssuance('ti-1', '') === false &&
         stats.holdsLiveIssuance('', 'urn:uuid:ti-1') === true,
         'L2. a token naming only a sub is found by the sub and not by a ' +
         'name it does not carry');
    note(stats.holdsLiveIssuance('', '') === false,
         'L3. nobody named holds nothing');
  } catch (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }
  fs.writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'ti-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  TI_ROOT: ROOT, TI_OUT: out }),
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
  name: 'token_register_index',
  describe: 'a person\'s live tokens are found by an index, not a walk ' +
            '(#766): realms.map()\'s indexBy kept by the partition, and ' +
            'holdsLiveIssuance() answering as the walk did',
  run: run
};
