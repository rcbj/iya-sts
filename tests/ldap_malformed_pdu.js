// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap_malformed_pdu.js
//
// ===========================================================================
// ONE MALFORMED PDU ON 389 MUST NOT STOP THE PROCESS (2026-11-14).
//
// The Rust port of the LDAP wire codec (#444, `rust/crates/sts-ldap`) found
// four corpus PDUs that sent node-ldapjs into a loop it never left. The
// parser runs on the event loop, so the process stopped answering EVERY
// protocol, not just the connection that sent the PDU, and none of them
// needs a bind:
//
//   1. a bind whose name is `cn=#4142 ,dc=example,dc=com` — the DN parser
//      waited for a separator after a hex-string value and never moved
//      past the space;
//   2. a search whose control list runs past the end of its sequence;
//   3. a search whose substring filter's initial is longer than the filter;
//   4. a search whose extensible-match value is longer than the filter.
//
// 2-4 are one defect in the @ldapjs packages: a BerReader read that cannot
// be satisfied answers null without moving the offset, and every loop over a
// SEQUENCE OF went round on the same bytes for ever. The fix is in the
// `rcbj/node-ldapjs` fork, which carries those packages since this change
// (`ldap/CLAUDE.md`, *THE @ldapjs PACKAGES ARE THE FORK'S*); the fork's own
// `test/malformed_ber.test.js` holds every loop it guarded. This file holds
// the service: `ldap/ldap_server.js` started as `server.js` starts it, the
// four PDUs on 389, each on its own connection, and then a client that
// binds and searches as an ordinary client does.
//
//   A. CONTROL: before anything malformed is sent, a bind and a base search
//      of a person's entry, with a control, are answered.
//   B. Each PDU: the connection is closed or answered (the bind name is a
//      legal DN since the fix, so case 1 is answered) within five seconds,
//      and a timer in the process still fires.
//   C. After all four: the same bind and search are answered, and so is a
//      bind as a name that is NOT a DN, with invalidDNSyntax (34).
//
// The directory runs in a CHILD PROCESS, killed with SIGKILL if it has not
// finished in two minutes: a regression is a busy loop on the child's event
// loop, which no SIGTERM handler would ever get to run, and which would
// otherwise take the runner with it. The child records each step as it
// starts, so a hang is reported as the PDU it hung on.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_LDAP_MALFORMED_PDU_CHILD';
const CHILD_TIMEOUT_MS = 120000;
const ANSWER_MS = 5000;

const log = require('bunyan').createLogger({
  name: 'ldap_malformed_pdu',
  level: process.env.LOG_LEVEL || 'info' });

// The four PDUs exactly as the Rust port's corpus has them
// (`tests/tools/ldap-wire-vectors.js` on feature/444, and the `hang` events
// of its `ldap-wire-node.json`).
const PDUS = [
  { name: 'a bind name with a hex value then a space',
    hex: '30290201086024020103041b636e3d2334313432202c64633d6578616d706c652c' +
         '64633d636f6d80027077',
    answered: true },
  { name: 'a search whose control list runs past its sequence',
    hex: '302f02011e6327041164633d6578616d706c652c64633d636f6d0a01020a0100' +
         '0201000201000101008701783000a00330' },
  { name: 'a search with a substring initial longer than the filter',
    hex: '303502011e6330041164633d6578616d706c652c64633d636f6d0a01020a0100' +
         '020100020100010100a40a0402636e30048021616c3000' },
  { name: 'a search with an extensible-match value longer than the filter',
    hex: '304302011e633e041164633d6578616d706c652c64633d636f6d0a01020a0100' +
         '020100020100010100a9188108322e352e31332e358202636e8384416c696365' +
         '8401ff3000' }
];

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

// Writes one PDU on a fresh connection. Answers `closed` when the server
// closes it, `answered` when any bytes come back, and `timeout` when neither
// happens within ANSWER_MS.
function sendRaw(port, pdu) {
  log.debug("Entering sendRaw().");
  log.debug("Leaving sendRaw().");
  return new Promise(function (resolve) {
    const socket = net.connect(port, '127.0.0.1');
    let done = false;
    const finish = function (outcome) {
      log.debug("Entering finish(). " + outcome);
      if (done) {
        log.debug("Leaving finish(). Already finished.");
        return;
      }
      done = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(outcome);
      log.debug("Leaving finish().");
    };
    const timer = setTimeout(function () {
      finish('timeout');
    }, ANSWER_MS);
    socket.on('data', function () {
      finish('answered');
    });
    socket.on('close', function () {
      finish('closed');
    });
    socket.on('error', function (e) {
      log.debug("Caught in sendRaw(): " + ((e && e.message) || e));
      finish('closed');
    });
    socket.write(Buffer.from(pdu, 'hex'));
  });
}

// A timer in this process fires: the event loop is still turning.
function timerFires() {
  log.debug("Entering timerFires().");
  log.debug("Leaving timerFires().");
  return new Promise(function (resolve) {
    setTimeout(function () {
      resolve(true);
    }, 10);
  });
}

// A bind, then a base search of `base` for `uid`, with node-ldapjs's own
// client, bounded by ANSWER_MS. The search carries a control (ManageDsaIT,
// RFC 3296, not critical) because the fork's `controls` package reads a
// control's criticality with its own copy of `@ldapjs/asn1` 1.x, and an
// install that loses that copy destroys every request carrying one
// (`ldap/CLAUDE.md`, *THE @ldapjs PACKAGES ARE THE FORK'S*).
function bindAndSearch(port, bindDn, base) {
  log.debug("Entering bindAndSearch(). " + bindDn);
  const ldapjs = require('ldapjs');
  log.debug("Leaving bindAndSearch().");
  return new Promise(function (resolve) {
    const result = { bind: null, entries: [], search: null };
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
      log.debug("Caught in bindAndSearch(): " + ((e && e.message) || e));
      result.error = (e && e.message) || String(e);
      finish();
    });
    client.bind(bindDn, 'secret', function (e) {
      result.bind = e ? e.code : 0;
      if (e || !base) {
        finish();
        return;
      }
      const manageDsaIt = new ldapjs.Control({
        type: '2.16.840.1.113730.3.4.2', criticality: false });
      client.search(base, { scope: 'base', attributes: ['uid'] },
        [manageDsaIt], function (err, res) {
          if (err) {
            result.search = err.code;
            finish();
            return;
          }
          res.on('searchEntry', function (entry) {
            result.entries.push(String(entry.objectName));
          });
          res.on('error', function (e2) {
            result.search = e2.code;
            finish();
          });
          res.on('end', function (r) {
            result.search = r ? r.status : null;
            finish();
          });
        });
    });
  });
}

// ---------------------------------------------------------------------------
// THE CHILD: the stack, a person, 389, and the assertions.
// ---------------------------------------------------------------------------
async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  const progress = process.env.LMP_PROGRESS;
  const step = function (what) {
    log.debug("Entering step(). " + what);
    fs.appendFileSync(progress, what + '\n');
    log.debug("Leaving step().");
  };
  step('loading the protocol stack');
  require(ROOT + '/common/protocol_stack');
  const keystore = require(ROOT + '/common/keystore');
  const ldap = require(ROOT + '/ldap/ldap_server');
  await keystore.start();
  ldap.createUser('lmpalice', { invent: false });
  const aliceDn = ldap.existingUserEntry('lmpalice').dn;

  step('binding 389');
  const ready = await ldap.listen().whenReady;
  const port = ready.port;
  if (!t.check(!!port, 'precondition: 389 is listening',
               JSON.stringify(ready))) {
    log.debug("Leaving childBody(). Not listening.");
    return t.rows;
  }

  const ordinary = async function (label) {
    log.debug("Entering ordinary(). " + label);
    const got = await bindAndSearch(port, aliceDn, aliceDn);
    t.check(got.bind === 0 && got.search === 0 &&
            got.entries.length === 1 &&
            got.entries[0].toLowerCase() === aliceDn.toLowerCase(),
            label + ': a bind and a base search of a person are answered',
            JSON.stringify(got));
    log.debug("Leaving ordinary().");
  };

  step('A: the control');
  await ordinary('A');

  for (const one of PDUS) {
    step('B: ' + one.name);
    const outcome = await sendRaw(port, one.hex);
    t.check(outcome !== 'timeout' &&
            (outcome === 'closed' || one.answered === true),
            'B: ' + one.name + ': the connection is ' +
            (one.answered ? 'answered or closed' : 'closed'), outcome);
    t.check(await timerFires(),
            'B: ' + one.name + ': the process still runs timers');
  }

  step('C: afterwards');
  await ordinary('C');
  const notADn = await bindAndSearch(port, 'cn=#4142 x,' + ready.baseDn,
                                     null);
  t.check(notADn.bind === 34,
          'C: a bind as a name that is not a DN is answered ' +
          'invalidDNSyntax (34)', JSON.stringify(notADn));
  step('done');
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
  const out = path.join(os.tmpdir(), 'lmp-' + stamp + '.json');
  const progress = path.join(os.tmpdir(), 'lmp-' + stamp + '.progress');
  Object.assign(clean, { LMP_OUT: out, LMP_PROGRESS: progress,
                         LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                         STS_HOST: '127.0.0.1',
                         LDAP_PORT: '0', LDAPS_PORT: '0' });
  clean[CHILD_FLAG] = '1';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: CHILD_TIMEOUT_MS,
    killSignal: 'SIGKILL', maxBuffer: 64 * 1024 * 1024
  });
  let steps = [];
  try {
    steps = fs.readFileSync(progress, 'utf8').trim().split('\n');
    fs.unlinkSync(progress);
  } catch (e) {
    log.debug("Caught in spawnChild(): " + ((e && e.message) || e));
  }
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
                    ', signal ' + result.signal + '); its last step was "' +
                    (steps[steps.length - 1] || 'none') + '": ' +
                    String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: rows };
}

function run(t) {
  log.debug("Entering run().");
  const got = spawnChild();
  if (!t.check(!got.error, 'the child ran to the end, so nothing hung it',
               got.error)) {
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
    fs.writeFileSync(process.env.LMP_OUT, JSON.stringify(rows));
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'ldap_malformed_pdu',
  describe: 'LDAP: the four PDUs the Rust port found hanging node-ldapjs ' +
            'end their connection, and the directory still answers a bind ' +
            'and a search afterwards',
  run: run
};
