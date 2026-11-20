// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/xacml_pep_heartbeat_values.js
//
// ===========================================================================
// A REMOTE PEP'S HEARTBEAT WITH VALUES IT CANNOT HOLD (fuzz run #595).
//
// The fuzz gate's pep-control-plane profile sent `POST /xacml/pep/heartbeat`
// a body (schemathesis case S1VvpM, and m0o6pP and O8iT0O, the same body)
// of out-of-range and wrong-typed numbers — `"refused":
// -50380761491719199916032`, negative ages, a string where an age goes —
// and strings carrying control characters, and the service answered
// express's HTML "Internal Server Error": a throw past the fault boundary,
// in all three fuzz realms.
//
// In a CHILD PROCESS with the whole stack, over real handshakes
// (`xacml_pep_proxy.js`'s arrangement):
//
//   V0. what threw: a stream's `lastSuccessAgeMs` of 2^53 - 1, a safe
//       integer whose instant is before the earliest a Date holds, so
//       `signalsOf()`'s `toISOString()` threw a RangeError past the fault
//       boundary. Alone in an otherwise valid heartbeat it is held as no
//       time (200, `lastSuccessAt` null) — within `signals` a value is held
//       to its member, `xacml_pep_proxy.js` B5's rule — and `signalsOf()`
//       itself answers null for it rather than throwing;
//   V1. the reproducing body, as the fuzz gate sent it, is answered 400 with
//       a coded refusal — not a 500 — and writes nothing;
//   V2. each kind of value the PEP's entry would store is answered 400 the
//       same way: a counter beyond Number.MAX_SAFE_INTEGER, a negative or
//       fractional counter, a counter that is a string, a text member
//       carrying a control character, and signals or listeners that are not
//       an object;
//   V3. a valid heartbeat afterwards still succeeds, and its counters are
//       the ones stored.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const https = require('https');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_XACML_PEP_HEARTBEAT_VALUES_CHILD';
const MARK = 'XACML-PEP-HEARTBEAT-VALUES-CHILD ';
const REALM = 'pephbvalues';
const PREFIX = '/realm/' + REALM;

const CA_PEM = { value: '' };

const log = require('bunyan').createLogger({
  name: 'xacml_pep_heartbeat_values',
  level: process.env.LOG_LEVEL || 'info' });

// THE REPRODUCING BODY, case S1VvpM, as the job log printed it, with the
// members its `[Filtered]` placeholders replaced dropped (they were secrets
// in the gate's eyes only because of their names). Kept whole: the finding
// is that this body reached a throw, and a trimmed one might not.
function reproducingBody() {
  log.debug("Entering reproducingBody().");
  const stream = function (extra) {
    log.debug("Entering stream().");
    log.debug("Leaving stream().");
    return Object.assign({ healthy: true, failedPolls: -500801,
      lastPollAgeMs: '5', clientId: '',
      setsRefused: -306338696552956588988563456, startedAgeMs: null,
      setsAccepted: 14706, lastSuccessAgeMs: 176488,
      consecutiveFailures: 28487371035123, running: false,
      polls: -566419, streamId: '2' }, extra || {});
  };
  const body = {
    name: '9\u0095\u00b5St\u00c0',
    refused: -50380761491719199916032,
    signals: {
      stale: 9, oldestSuccessAgeMs: -803, staleAfterMs: -189,
      setsAccepted: 8914, pollIntervalMs: -1252, setsRefused: 21315,
      receivers: 725467, mostConsecutiveFailures: 9693847,
      healthy: 112184,
      streams: [
        stream(),
        stream({ clientId: 'F7', lastPollAgeMs: '\ud89d\udd3c',
                 setsAccepted: -1648877887705424699850752,
                 failedPolls: -10000000001, streamId: 'jkU0' }),
        stream({ clientId: 'Z8', polls: 2664691809383159547185572154966016,
                 lastPollAgeMs: '\u009a\u0001\u00be\ud941\udd87Pw' }),
        // THE ONE THAT THREW: 2^53 - 1, a safe integer, as an age puts the
        // instant before the earliest a Date holds (`signalsOf()`).
        stream({ clientId: 'pWw_Naj_V~Dht:S/yx', streamId: '.',
                 polls: -1198, consecutiveFailures: -2819,
                 failedPolls: -217, setsRefused: -1607159183957,
                 lastPollAgeMs: '', healthy: false, running: true,
                 setsAccepted: -34359738369,
                 lastSuccessAgeMs: 9007199254740991 })
      ]
    },
    listeners: {
      memory: { virtualBytes: -3942, threads: -20104082811386,
                rssBytes: -13477, dataBytes: -2509 },
      listeners: [
        { port: -4775, renew: -8268972564680, source: 'environment',
          id: 'vezBHKWOYDe0Z0peMs-kSxT', certificate: null,
          purpose: 'proxy', protocol: 'https', reason: 'proxy-off',
          address: '\u00af{N\ud95d\udf79\t\u0089\u00db', state: 'waiting' },
        { address: 'm\u0000\u00dd\u00fb', port: 194483, reason: 'other',
          id: 'EIP3ZeK4hEp', source: 'service', purpose: 'crl',
          protocol: 'http', state: 'listening', renew: -25436,
          certificate: { issuer: '\u001b\u00a3\u00cf@l', subjectAltName: '',
                         validFrom: '\u0000', fingerprint256: '\u00e1]J',
                         serialHex: '\u00b5)', subject: 'k',
                         validTo: '\u00bf' } },
        { address: '\u009e\u00fc', source: 'environment',
          reason: 'address-unavailable', protocol: 'https', port: -4159,
          renew: 11087447181788760621711360, purpose: 'proxy',
          stats: { http2: 66719, refused: -4500571335,
                   handshakeFailures: -201664804,
                   pool: { min: -8546376, busy: -862, queued: 8748,
                           completed: 463189355, current: 1077,
                           idle: 5593071895, max: 131071 } },
          certificate: null, state: 'off', id: '04' },
        { state: 'waiting', source: 'service', address: 'NULL',
          protocol: 'https', stats: {}, id: 'W5j', certificate: null,
          renew: 187, purpose: 'api', reason: 'permission-denied',
          port: 450480 }
      ]
    },
    resource: 'N\ud8b7\udece\u00ff\u0007',
    policyCount: -6500,
    version: 'F\udafe\udc65\u00cfs\u00c42\ud8e0\udfad\u00c8_\u00bc\u0012'
  };
  log.debug("Leaving reproducingBody().");
  return body;
}

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

function request(port, method, urlPath, cred, body) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const text = body === undefined ? ''
      : (typeof body === 'string' ? body : JSON.stringify(body));
    const sent = { 'content-type': 'application/json',
                   'content-length': Buffer.byteLength(text) };
    const req = https.request({ host: '127.0.0.1', port: port,
      path: urlPath, method: method, headers: sent, ca: CA_PEM.value,
      cert: cred ? cred.certPem : undefined,
      key: cred ? cred.keyPem : undefined, agent: false }, function (res) {
      let raw = '';
      res.on('data', function (chunk) {
        raw += chunk;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in request(): " + e.message);
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: raw,
                  json: json });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in request(): " + e.message);
      resolve({ status: 0, headers: {}, text: '', json: null,
                error: e.message });
    });
    req.end(text);
  });
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const app = require(ROOT + '/common/app');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const realms = require(ROOT + '/common/realms');
  const config = require(ROOT + '/common/config');
  const errorCodes = require(ROOT + '/common/error_codes');
  const tls = require(ROOT + '/tls/tls_server');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const adminActions = require(ROOT + '/admin-core/admin_actions');
  const peps = require(ROOT + '/xacml/xacml_pep_registry');
  const testCa = require('./protocol/outbound_test_ca');
  const outsideCa = require('./tools/pep-credential.js');

  const marks = [];
  const mark = errorCodes.mark;
  errorCodes.mark = function (res, code) {
    marks.push(code);
    return mark.apply(this, arguments);
  };

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(REALM), fn);
  };
  const pepCred = await outsideCa.mint({ subject: 'CN=hbvpep,O=Outside',
                                         crlBase: '' });
  tls.addAnchors(pepCred.anchorPem);
  inRealm(function () {
    ldap.createUser('hbvpep', { invent: false });
    ldap.changeStoredCertificate('person', 'hbvpep',
      { add: new nodeCrypto.X509Certificate(pepCred.leaf.pem).raw });
    ldap.createUser('hbvadmin', { invent: false });
    ldap.createGroup(String(config.value('admin.writeGroup')));
    adminActions.groupsAction({ action: 'add-member',
      group: String(config.value('admin.writeGroup')), member: 'hbvadmin' });
    adminActions.groupsAction({ action: 'add-member',
      group: String(config.value('roles.remotePepGroup')),
      member: 'hbvpep' });
  });
  const serverCa = await testCa.makeCa();
  const serverLeaf = await testCa.listenerCertificate(serverCa, '127.0.0.1');
  CA_PEM.value = serverCa.certPem;
  const listener = https.createServer(Object.assign({
    cert: serverLeaf.cert, key: serverLeaf.key,
    ca: tls.clientTruststoreOptions().ca,
    requestCert: true, rejectUnauthorized: false
  }, tls.protocolOptions()), app);
  tls.trustClientCertificatesOn(listener,
    'the xacml_pep_heartbeat_values listener', function () {
      log.debug("Entering the listener's certificateOf().");
      log.debug("Leaving the listener's certificateOf().");
      return { key: serverLeaf.key, cert: serverLeaf.cert };
    });
  await new Promise(function (ok) {
    listener.listen(0, '127.0.0.1', ok);
  });
  const port = listener.address().port;
  const brief = function (r) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return r.status + ' ' + String(r.text || '').slice(0, 400);
  };
  const BEAT = PREFIX + '/xacml/pep/heartbeat';
  // The PEP authenticates by its certificate: an operator's opt-in since
  // xacml.pepAuthentication defaults to `token` (`xacml_pep_proxy.js` B).
  config.setOverride('xacml.pepAuthentication', 'either');
  let r = await request(port, 'POST', PREFIX + '/xacml/pep/register',
                        pepCred, { version: 'test' });
  t.check(r.status === 201 || r.status === 200, 'setup: the PEP registers',
          brief(r));
  const NAME = r.json ? r.json.name : '';
  r = await request(port, 'POST', BEAT, pepCred,
                    { decisions: 3, allowed: 2, refused: 1 });
  t.check(r.status === 200, 'setup: a valid heartbeat succeeds', brief(r));
  const readRow = function () {
    log.debug("Entering readRow().");
    log.debug("Leaving readRow().");
    return inRealm(function () {
      return peps.read(NAME);
    });
  };

  // V0. WHAT THREW, alone, at the door and in the normaliser.
  r = await request(port, 'POST', BEAT, pepCred, { decisions: 4,
    signals: { receivers: 1, healthy: 1, stale: 0, streams: [{
      clientId: 'c', streamId: 's', running: true, healthy: true,
      lastPollAgeMs: 5, lastSuccessAgeMs: 9007199254740991 }] } });
  const aged = readRow();
  const agedStream = aged && aged.signals && aged.signals.streams &&
    aged.signals.streams[0];
  t.check(r.status === 200 && aged.decisions === 4 && agedStream &&
          agedStream.lastSuccessAt === null &&
          typeof agedStream.lastPollAt === 'string',
          'V0. a stream age of 2^53 - 1 is held as no time, not a 500',
          brief(r) + ' ' + JSON.stringify(aged && aged.signals));
  let normalised = null;
  let thrown = '';
  try {
    normalised = peps.signalsOf({ streams: [{ clientId: 'c',
      lastSuccessAgeMs: 9007199254740991, lastPollAgeMs: 5 }] },
      new Date().toISOString());
  } catch (e) {
    log.debug("Caught in childBody(): " + ((e && e.message) || e));
    thrown = String((e && e.stack) || e);
  }
  t.check(!thrown && normalised && normalised.streams &&
          normalised.streams[0].lastSuccessAt === null &&
          typeof normalised.streams[0].lastPollAt === 'string',
          'V0. signalsOf() answers null for an age older than the epoch ' +
          'and keeps the age beside it', thrown ||
          JSON.stringify(normalised));

  // V1. THE REPRODUCING BODY.
  const before = readRow();
  const since = marks.length;
  r = await request(port, 'POST', BEAT, pepCred, reproducingBody());
  const after = readRow();
  t.check(r.status === 400 && r.json && r.json.error === 'invalid_request' &&
          marks.slice(since).indexOf('STS-XACML-0331') >= 0 &&
          !/STS-/.test(r.text),
          'V1. the fuzz gate\'s body (case S1VvpM) is refused 400 with a ' +
          'coded refusal (STS-XACML-0331, recorded, not sent), not a 500',
          brief(r));
  t.check(after && before && after.refused === before.refused &&
          after.version === before.version &&
          JSON.stringify(after.signals) === JSON.stringify(before.signals),
          'V1. and writes nothing', JSON.stringify(after).slice(0, 300));

  // V2. EACH KIND ALONE.
  const alone = [
    ['a counter beyond Number.MAX_SAFE_INTEGER',
     { refused: -50380761491719199916032 }],
    ['a counter of 2^53', { decisions: 9007199254740992 }],
    ['a negative counter', { policyCount: -6500 }],
    ['a fractional counter', { allowed: 1.5 }],
    ['a counter that is a string', { decisions: '12' }],
    ['a version carrying a control character',
     { version: 'v1\u0012' }],
    ['a resource carrying a control character',
     { resource: 'N\u0007' }],
    ['signals that are not an object', { signals: [1, 2] }],
    ['listeners that are not an object', { listeners: 'up' }]
  ];
  for (const one of alone) {
    r = await request(port, 'POST', BEAT, pepCred, one[1]);
    t.check(r.status === 400 && r.json &&
            r.json.error === 'invalid_request',
            'V2. ' + one[0] + ' is refused 400', brief(r));
  }

  // V3. A VALID HEARTBEAT STILL SUCCEEDS.
  r = await request(port, 'POST', BEAT, pepCred,
                    { decisions: 10, allowed: 7, refused: 3,
                      policyCount: 0, version: 'test-2' });
  const last = readRow();
  t.check(r.status === 200 && r.json && r.json.acknowledged === true &&
          last && last.decisions === 10 && last.allowed === 7 &&
          last.refused === 3 && last.version === 'test-2',
          'V3. a valid heartbeat afterwards succeeds and is stored',
          brief(r) + ' ' + JSON.stringify(last).slice(0, 300));

  await new Promise(function (ok) {
    listener.close(ok);
  });
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
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)),
           stderr: String(result.stderr || '') };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== a remote PEP heartbeat with values it cannot hold ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  // A throw that reached express's default handler prints its stack on the
  // child's stderr; none may.
  t.check(!/Error: |at .*\(\/.*\.js:\d+:\d+\)/.test(got.stderr),
          'no throw reached express\'s default handler',
          got.stderr.slice(-1500));
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'xacml_pep_heartbeat_values',
  describe: 'a remote PEP heartbeat with values it cannot hold (fuzz run ' +
            '#595): refused 400 with a code, never a 500, and a valid one ' +
            'still succeeds',
  run: run
};
