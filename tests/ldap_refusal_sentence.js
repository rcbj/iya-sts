// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap_refusal_sentence.js
//
// ===========================================================================
// A DIRECTORY REFUSAL'S SENTENCE REACHES A CLIENT AS ITS diagnosticMessage,
// AND ITS CODE DOES NOT (#1813's follow-up, 2026-11-15).
//
// `tests/protocol/sts_service_accounts.js` section m failed in run #300: an
// LDAP modify deleting `stsServiceAccount` was refused with 19 and the
// service logged STS-SVCACCT-0064, but the job read "Constraint Violation"
// where it expected `serviceAccountWriteRefusal()`'s sentence. Nothing had
// lost the sentence. node-ldapjs's client builds the error it hands back
// with the result code's NAME as its `message` — `getError()` reads the
// decoded result's `errorMessage`, which a decoded result never has — and
// carries what the server sent as its own `diagnosticMessage` property
// (`ldap/CLAUDE.md`, *A REFUSAL'S TEXT REACHES THE CLIENT*, #261). The job
// read `message`; every other job asserting a sentence reads
// `diagnosticMessage`. This file holds the service end of that, which until
// now was held only by a stub server (`tests/ldap_diagnostic_message.js`)
// and by jobs over LDAPS that a memory-mode run does not reach first:
//
//   A. ON THE DIRECTORY'S OWN 389, `ldap/ldap_server.js` started as
//      `server.js` starts it: a modify making a person a service account is
//      accepted, and a modify deleting the flag is answered 19 with
//      EXACTLY the sentence as its diagnosticMessage — no error code in it,
//      since a code is recorded and never sent — while the client's
//      `message` is the code's name, which is what the job had read.
//   B. THE SAME REFUSAL DISPATCHED: `performOperation()` (what a request
//      worker runs) answers the sentence as the error, and
//      `ldapErrorNamed()` (what the front process rebuilds it with) keeps
//      it, so a memory-mode run's dispatched modify sends the same text.
//   C. AND THE CODE WAS RECORDED: an STS-SVCACCT-0064 row was written for
//      each refusal.
//
// The directory runs in a CHILD PROCESS, `tests/ldap_malformed_pdu.js`'s
// arrangement, because it binds a listener.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_LDAP_REFUSAL_SENTENCE_CHILD';
const CHILD_TIMEOUT_MS = 120000;
const ANSWER_MS = 10000;

// `serviceAccountWriteRefusal()`'s sentence for STS-SVCACCT-0064, as the
// client must receive it.
const SENTENCE = 'a service account cannot be made an ordinary person ' +
  'again: stsServiceAccount may not be removed or changed; delete the ' +
  'entry to end the account';

const log = require('bunyan').createLogger({
  name: 'ldap_refusal_sentence',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? ''
                    : String(detail).slice(0, 2000) });
      log.debug("Leaving check().");
      return !!ok;
    }
  };
}

// One connection to `port`: a bind as `bindDn`, then a modify of `dn` with
// `changes` (each [operation, type, values]). Answers the bind's code and
// the modify's code, `message` and `diagnosticMessage`.
function bindAndModify(port, bindDn, dn, changes) {
  log.debug("Entering bindAndModify(). " + dn);
  const ldapjs = require('ldapjs');
  log.debug("Leaving bindAndModify().");
  return new Promise(function (resolve) {
    const result = { bind: null, modify: null, message: '',
                     diagnostic: '' };
    const client = ldapjs.createClient({
      url: 'ldap://127.0.0.1:' + port, reconnect: false,
      timeout: ANSWER_MS, connectTimeout: ANSWER_MS });
    let done = false;
    const finish = function () {
      log.debug("Entering finish().");
      if (done) {
        log.debug("Leaving finish(). Already finished.");
        return;
      }
      done = true;
      clearTimeout(timer);
      client.destroy();
      resolve(result);
      log.debug("Leaving finish().");
    };
    const timer = setTimeout(function () {
      result.timeout = true;
      finish();
    }, ANSWER_MS * 2);
    client.on('error', function (e) {
      log.debug("Caught in bindAndModify(): " + ((e && e.message) || e));
      result.error = (e && e.message) || String(e);
      finish();
    });
    client.bind(bindDn, 'anything-in-development', function (e) {
      result.bind = e ? e.code : 0;
      if (e) {
        finish();
        return;
      }
      client.modify(dn, changes.map(function (one) {
        return new ldapjs.Change({ operation: one[0],
          modification: new ldapjs.Attribute({ type: one[1],
                                               values: one[2] }) });
      }), function (err) {
        result.modify = err ? err.code : 0;
        result.message = err ? String(err.message || '') : '';
        result.diagnostic = err ? String(err.diagnosticMessage || '') : '';
        finish();
      });
    });
  });
}

// How many audit rows carry `code` now.
function rowsWith(audit, code) {
  log.debug("Entering rowsWith().");
  const out = audit.list().filter(function (row) {
    return row.errorCode === code;
  }).length;
  log.debug("Leaving rowsWith().");
  return out;
}

// ---------------------------------------------------------------------------
// THE CHILD: the stack, two people, 389, and the assertions.
// ---------------------------------------------------------------------------
async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const keystore = require(ROOT + '/common/keystore');
  const audit = require(ROOT + '/common/audit');
  const ldap = require(ROOT + '/ldap/ldap_server');
  await keystore.start();
  ldap.createUser('lrsaccount', { invent: false });
  ldap.createUser('lrsowner', { invent: false });
  const accountDn = ldap.existingUserEntry('lrsaccount').dn;
  const ownerDn = ldap.existingUserEntry('lrsowner').dn;

  const ready = await ldap.listen().whenReady;
  const port = ready.port;
  if (!t.check(!!port, 'precondition: 389 is listening',
               JSON.stringify(ready))) {
    log.debug("Leaving childBody(). Not listening.");
    return t.rows;
  }

  const made = await bindAndModify(port, ownerDn, accountDn, [
    ['replace', 'stsServiceAccount', ['TRUE']],
    ['replace', 'stsServiceAccountOwner', [ownerDn]]]);
  if (!t.check(made.bind === 0 && made.modify === 0,
               'A0. a modify on 389 makes a person a service account ' +
               'with an owner', JSON.stringify(made))) {
    log.debug("Leaving childBody(). Not a service account.");
    return t.rows;
  }

  const before = rowsWith(audit, 'STS-SVCACCT-0064');
  const refused = await bindAndModify(port, ownerDn, accountDn, [
    ['delete', 'stsServiceAccount', []]]);
  t.check(refused.bind === 0 && refused.modify === 19,
          'A1. a modify deleting the flag is answered constraintViolation ' +
          '(19)', JSON.stringify(refused));
  t.check(refused.diagnostic === SENTENCE,
          'A2. and its diagnosticMessage is exactly the refusal\'s sentence',
          JSON.stringify(refused));
  t.check(!/STS-[A-Z0-9]+-\d{4}/.test(refused.diagnostic + refused.message),
          'A3. which carries no error code: a code is recorded, never sent',
          JSON.stringify(refused));
  t.check(refused.message === 'Constraint Violation',
          'A4. while the client error\'s `message` is the code\'s name, ' +
          'which is why a job must read diagnosticMessage',
          JSON.stringify(refused));

  const dispatched = await Promise.resolve(ldap.performOperation('modify', {
    dn: accountDn, boundDn: ownerDn, channel: 'ldap',
    changes: [{ operation: 'delete',
                modification: { type: 'stsServiceAccount', values: [] } }]
  }));
  t.check(dispatched && dispatched.ok === false &&
          dispatched.errorName === 'ConstraintViolationError' &&
          dispatched.error === SENTENCE,
          'B1. the operation a request worker runs answers the sentence',
          JSON.stringify(dispatched));
  const rebuilt = ldap.ldapErrorNamed(dispatched && dispatched.errorName,
                                      dispatched && dispatched.error);
  t.check(rebuilt.code === 19 && rebuilt.message === SENTENCE,
          'B2. and the front process rebuilds it with the sentence, which ' +
          'is what it sends', JSON.stringify({ code: rebuilt.code,
                                               message: rebuilt.message }));

  t.check(rowsWith(audit, 'STS-SVCACCT-0064') === before + 2,
          'C. each refusal recorded STS-SVCACCT-0064',
          String(rowsWith(audit, 'STS-SVCACCT-0064') - before));
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const stamp = process.pid + '-' + Date.now();
  const out = path.join(os.tmpdir(), 'lrs-' + stamp + '.json');
  Object.assign(clean, { LRS_OUT: out,
                         LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                         STS_HOST: '127.0.0.1',
                         LDAP_PORT: '0', LDAPS_PORT: '0' });
  clean[CHILD_FLAG] = '1';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: CHILD_TIMEOUT_MS,
    killSignal: 'SIGKILL', maxBuffer: 64 * 1024 * 1024
  });
  let rows = null;
  try {
    rows = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in spawnChild(): " + ((e && e.message) || e));
    rows = null;
  }
  if (!rows) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    ', signal ' + result.signal + '): ' +
                    String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: rows };
}

function run(t) {
  log.debug("Entering run().");
  const got = spawnChild();
  if (!t.check(!got.error, 'the child ran to the end', got.error)) {
    log.debug("Leaving run(). The child failed.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (process.env[CHILD_FLAG] === '1' && require.main === module) {
  childBody().then(function (rows) {
    fs.writeFileSync(process.env.LRS_OUT, JSON.stringify(rows));
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'ldap_refusal_sentence',
  describe: 'LDAP: a service-account refusal on the directory\'s own ' +
            'listener arrives as 19 with its sentence, and no code, as the ' +
            'diagnosticMessage; dispatched, it keeps the sentence',
  run: run
};
