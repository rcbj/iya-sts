// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/asvs_session_limits.js
// ===========================================================================
// WHAT A SIGN-OUT ENDS, AND WHAT SLOWS A GUESSER (#1448, #1449; ASVS 5.0.0
// 6.3.1, 7.4.1).
//
//   1. THE DELAY doubles from 250 ms, is capped at 4 s, is forgotten on
//      success and after a quiet period, and never refuses anybody.
//   2. BOTH password doors wait, note the failure and forget it.
//   3. A SIGN-OUT in product revokes the access tokens issued on that session
//      and leaves another session's alone; an ID Token stays usable as a hint.
//   4. DEVELOPMENT leaves access tokens as they were.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'asvs_session_limits',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.SL_ROOT;
  const OUT = process.env.SL_OUT;
  const fs = require('fs');
  const path = require('path');
  const findings = [];
  const t = {
    equal: function (got, want, what) {
      findings.push({ ok: got === want, what: what,
                      detail: 'expected ' + want + ', got ' + got });
    }
  };
  const ROOT = ROOT_DIR;
  (async function () {
  require(ROOT_DIR + '/common/protocol_stack');
  const authn = require(ROOT_DIR + '/authn/authn');
  const config = require(ROOT_DIR + '/common/config');
  const stats = require(ROOT_DIR + '/common/admin_stats');
  const websecurity = require(ROOT_DIR + '/common/websecurity');
  const realms = require(ROOT_DIR + '/common/realms');

  // --- 1. the delay ---------------------------------------------------------
  const who = 'asvs-delay-' + process.pid;
  t.equal(websecurity.failureDelayMs(who), 0, 'nothing failed, no wait');
  const seen = [];
  for (let i = 0; i < 7; i++) {
    websecurity.noteFailure(who);
    seen.push(websecurity.failureDelayMs(who));
  }
  t.equal(seen.join(','), '250,500,1000,2000,4000,4000,4000',
          'the wait doubles and is capped');
  websecurity.forgetFailures(who);
  t.equal(websecurity.failureDelayMs(who), 0, 'a success forgets it');
  websecurity.noteFailure(who);
  const realNow = Date.now;
  Date.now = function () {
    return realNow() + 16 * 60 * 1000;
  };
  t.equal(websecurity.failureDelayMs(who), 0, 'and so do 15 quiet minutes');
  Date.now = realNow;
  websecurity.forgetFailures(who);

  // --- 1b. a sign-in step belongs to one browser (#1454) --------------------
  t.equal(authn.claimStepForBrowser('no-such-step', 'a'), true,
          'a step that does not exist is nothing to claim');
  const apiText = fs.readFileSync(ROOT + '/authn/authn_api.ts', 'utf8');
  t.equal(/claimStepForBrowser\(req\.params\.id, sid, kind\)/.test(apiText) &&
          /email-link\\\/open/.test(apiText), true,
          'the API claims each step, and an emailed link is exempt');
  // --- 1c. the doors a program uses count failures, never successes ---------
  const mode = require(ROOT_DIR + '/common/mode');
  const door = 'asvs-door-' + process.pid;
  const realVerifies = mode.verifiesCredentials;
  t.equal(websecurity.doorBlocked('asvs', null, door), null,
          'development counts nothing at a program\'s door');
  mode.verifiesCredentials = function () {
    return true;
  };
  for (let i = 0; i < 40; i++) {
    websecurity.doorFailed('asvs', null, door);
  }
  t.equal(!!websecurity.doorBlocked('asvs', null, door), true,
          'product refuses an identity after too many failures');
  t.equal(websecurity.doorBlocked('asvs', null, door + '-other'), null,
          'and no other identity');
  // AN ADDRESS WITH NO REQUEST IN HAND, AND THE SHARED WINDOW (#1482).
  const audit = require(ROOT_DIR + '/common/audit');
  config.setOverride('security.rateLimitPerAddress', '3');
  audit.withSource({ address: '203.0.113.77' }, function () {
    ['a', 'b', 'c', 'd'].forEach(function (one) {
      websecurity.doorFailed('asvs-addr', null, 'stuffing-' + one);
    });
  });
  t.equal(!!audit.withSource({ address: '203.0.113.77' }, function () {
    return websecurity.doorBlocked('asvs-addr', null, 'stuffing-new');
  }), true, 'one guess each at many names is refused by address');
  t.equal(audit.withSource({ address: '203.0.113.78' }, function () {
    return websecurity.doorBlocked('asvs-addr', null, 'stuffing-new');
  }), null, 'and another address is not');
  config.clearOverride('security.rateLimitPerAddress');
  const counters = require(ROOT_DIR + '/cluster/cluster_counters');
  const realShares = counters.sharesWindows;
  const realCount = counters.countInWindow;
  const counted = [];
  counters.sharesWindows = function () {
    return true;
  };
  counters.countInWindow = function (o) {
    counted.push(o.key);
    return Promise.resolve({ ok: true, count: 9999, remainingMs: 30000 });
  };
  try {
    websecurity.doorFailed('asvs-shared', null, 'clustered');
    await new Promise(function (resolve) {
      setImmediate(resolve);
    });
    t.equal(counted.length > 0, true, 'a door\'s failure reaches the shared ' +
            'window');
    t.equal(!!websecurity.doorBlocked('asvs-shared', null, 'clustered'), true,
            'and a cluster-wide refusal holds at this door from then on');
  } finally {
    counters.sharesWindows = realShares;
    counters.countInWindow = realCount;
  }
  // WHOSE CERTIFICATE VERIFIES A CLIENT'S ASSERTION (#1488), through the door.
  const nodeCrypto = require('crypto');
  const clientAuth = require(ROOT_DIR + '/oauth-oidc/client_auth');
  const assertionGrant = require(ROOT_DIR + '/oauth-oidc/assertion_grant');
  const errorCodes = require(ROOT_DIR + '/common/error_codes');
  const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const b64 = function (value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  };
  const assertionFor = function (clientId) {
    const body = b64({ alg: 'RS256', x5c: ['AA'] }) + '.' + b64({
      iss: clientId, sub: clientId, aud: ['https://as.example/token'],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60,
      jti: nodeCrypto.randomBytes(8).toString('hex') });
    return body + '.' + nodeCrypto.sign('RSA-SHA256', Buffer.from(body),
                                        pair.privateKey).toString('base64url');
  };
  const realKeyFromChain = assertionGrant.keyFromChain;
  const presenting = async function (subjectName) {
    assertionGrant.keyFromChain = function () {
      return Promise.resolve({ key: pair.publicKey.export(
        { type: 'spki', format: 'pem' }), subjectKind: 'application',
      subjectName: subjectName });
    };
    return clientAuth.verify({ method: 'private_key_jwt',
      clientId: 'asvs-client', assertion: assertionFor('asvs-client'),
      assertionType:
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      audiences: ['https://as.example/token'] });
  };
  try {
    const stolen = await presenting('another-application');
    t.equal(JSON.stringify({ ok: !!stolen.ok, code: stolen.errorCode ||
                             errorCodes.codeOf(stolen),
                             why: stolen.ok ? '' : stolen.description }),
            JSON.stringify({ ok: false, code: 'STS-OAUTH-1000',
                             why: 'the certificate in x5c was not issued to ' +
                                  'this client.' }),
            'a certificate issued to another application authenticates nobody');
    const own = await presenting('asvs-client');
    t.equal(own.errorCode === 'STS-OAUTH-1000' ||
            errorCodes.codeOf(own) === 'STS-OAUTH-1000', false,
            'and the client\'s own passes that check');
  } finally {
    assertionGrant.keyFromChain = realKeyFromChain;
  }
  mode.verifiesCredentials = realVerifies;
  const doors = { 'ws-trust/wstrust.ts': 'wstrust',
                  'scim/scim_auth.ts': 'scim-basic',
                  'ssf/ssf_auth.ts': 'ssf-basic',
                  'kerberos/krb5_kdc.js': 'krb5-preauth' };
  Object.keys(doors).forEach(function (file) {
    const text = fs.readFileSync(ROOT + '/' + file, 'utf8');
    t.equal(text.indexOf("doorBlocked('" + doors[file]) >= 0 &&
            text.indexOf("doorFailed('" + doors[file]) >= 0, true,
            file + ' checks the limit and counts a failure');
  });

  // --- 2. both doors --------------------------------------------------------
  const source = fs.readFileSync(path.join(ROOT, 'authn/authn.ts'), 'utf8');
  t.equal((source.match(/websecurity\.waitAfterFailures\(/g) || []).length, 2,
          'both password doors wait');
  t.equal((source.match(/websecurity\.noteFailure\(/g) || []).length, 2,
          'both record a refusal');
  t.equal((source.match(/websecurity\.forgetFailures\(/g) || []).length, 2,
          'both forget on success');

  t.equal(/this\.isOwnersBrowser\(req, username\)/.test(source), true,
          'a flood does not refuse the owner\'s own browser');
  const ws = fs.readFileSync(ROOT + '/ws-trust/wstrust.ts', 'utf8');
  t.equal(/textByLocal\(ut, 'Password'\)/.test(ws), false,
          'WS-Trust no longer trims a password (#1466)');
  const oauth = fs.readFileSync(ROOT + '/oauth-oidc/oauth2.ts', 'utf8');
  t.equal(/bcp\.revokeFamily\(done\.family/.test(oauth), true,
          'a replayed code revokes its refresh family (#1467)');
  const cfg = require(ROOT_DIR + '/common/config');
  const selfWrite = String(cfg.SETTINGS.filter(function (row) {
    return row.key === 'ldap.selfWritableAttributes';
  })[0].dflt);
  t.equal(selfWrite.indexOf('userPassword'), -1,
          'LDAP does not let a person replace their password unproved (#1465)');
  t.equal(fs.existsSync(ROOT + '/node-ldapjs/.git'), false,
          'no nested .git reached this image (#1468)');
  ['pending', 'password-change', 'consent'].forEach(function (kind) {
    t.equal(fs.readFileSync(ROOT + '/authn/authn_api.ts', 'utf8')
      .indexOf("'" + kind + "'") >= 0, true,
            'the API binds ' + kind + ' steps to one browser');
  });
  t.equal(authn.claimStepForBrowser('none', 'a', 'pending'), true,
          'a step that does not exist is nothing to claim');

  // --- 2b. clearing storage never touches another signed-in person ---------
  const headersSet = function (cookie) {
    const set = {};
    authn.clearSiteDataAfterSignOut({ headers: { cookie: cookie } },
      { setHeader: function (name, value) {
        set[name] = value;
      } });
    return set['Clear-Site-Data'];
  };
  await realms.run(realms.get(realms.DEFAULT_ID), async function () {
    t.equal(headersSet(''), '"storage"',
            'the last account here clears this origin\'s storage');
    t.equal(headersSet('sts_accounts_other=x'), undefined,
            'but not while the browser holds an account in another realm');
    t.equal(headersSet('sts_accounts=x'), '"storage"',
            'and this realm\'s own emptied set does not count');
  });

  // --- 3 and 4. the sign-out ------------------------------------------------
  const res = { set: function () {
    return res;
  }, append: function () {
    return res;
  }, setHeader: function () {}, getHeader: function () {}, req: null };
  const tokensFor = function (session, tag) {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    ['Bearer', 'ID'].forEach(function (typ) {
      stats.recordJwt({ jti: tag + '-' + typ, typ: typ, sub: 'x', iat: 1,
                        exp: exp, client_id: 'asvs-client' }, 'a.b.c',
                      { sessionId: session.id });
    });
  };
  const sessionOf = function (name) {
    require(ROOT_DIR + '/ldap/ldap_server').createUser(name, {});
    const started = authn.startSession(res, name, ['pwd'], '1', 'password', {});
    if (!started) {
      throw new Error('no session for ' + name + ': ' + JSON.stringify(res));
    }
    return { id: started.id || (started.session && started.session.id) };
  };
  const tag = 'asvs-' + process.pid;
  await realms.run(realms.get(realms.DEFAULT_ID), async function () {
  const dev = sessionOf(tag + '-dev');
  tokensFor(dev, tag + '-dev');
  authn.endSessionById(dev.id, 'a test');
  t.equal(stats.isRevoked(tag + '-dev-Bearer'), false,
          'development leaves the access token');

  // Made first: product requires a verified credential to start one, and what
  // is under test is what ending one does.
  const one = sessionOf(tag + '-one');
  const two = sessionOf(tag + '-two');
  tokensFor(one, tag + '-one');
  tokensFor(two, tag + '-two');
  config.setOverride('global.mode', 'product');
  authn.endSessionById(one.id, 'a test');
  t.equal(stats.isRevoked(tag + '-one-Bearer'), true,
          'product revokes the access token issued on that session');
  t.equal(stats.isRevoked(tag + '-two-Bearer'), false,
          'and not another session\'s');
  t.equal(stats.isRevoked(tag + '-one-ID'), false,
          'an ID Token stays usable as an id_token_hint');
  config.clearOverride('global.mode');
  });
  fs.writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the probe ran',
                    detail: String((e && e.stack) || e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * Runs the child and reports what it found.
 *
 * @param {object} t - the runner's checker
 * @returns {Promise<void>}
 */
async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sl-' + process.pid + '-' + Date.now() +
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
                                  SL_ROOT: ROOT, SL_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
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
  name: 'asvs_session_limits',
  describe: 'a growing wait on the password doors, and a sign-out revoking ' +
            'the access tokens of its session in product (ASVS 5.0.0)',
  run: run
};
