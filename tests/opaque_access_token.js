// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: opaque_access_token.js
//
// ===========================================================================
// AN OPAQUE ACCESS TOKEN IS A HANDLE, AND THE DEFAULT STAYS A JWT (#501).
//
// `oauth-oidc/opaque_access_token.ts` argues the design. What is held here:
//
//   1. the default does not issue opaque tokens, and a dotted string or an
//      empty string is not a handle;
//   2. a minted handle is 256 bits of base64url, with no `.`, and the store
//      holds the SHA-256 digest rather than the handle;
//   3. a one-character change is the same answer as any other miss, and
//      neither answer contains the handle or says the guess was close;
//   4. an expired row is deleted on read; a revoked row stays and answers
//      revoked, including a revocation that exists only in the token
//      register;
//   5. misses from one address are counted, and the one past the limit is
//      refused without a different shape;
//   6. clearing the setting leaves an outstanding handle resolvable;
//   7. a full store refuses the next mint (STS-OAUTH-0979);
//   8. `accessToken()` in a child, then the opaque module's `jtiOf()` and
//      `lifetimeSeconds()`. Loading the protocol stack in this process
//      would register every route on the shared app. `OAuth2Server`'s
//      readers of the same names are not on `oauth2`'s export.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'opaque_access_token',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const config = require('../common/config');
const stsCrypto = require('../common/crypto');
const errorCodes = require('../common/error_codes');
const websecurity = require('../common/websecurity');
const adminStats = require('../common/admin_stats');
const opaque = require('../oauth-oidc/opaque_access_token');

const FAKE_REQ = { socket: { remoteAddress: '203.0.113.50' }, headers: {} };

function nowSec() {
  log.debug("Entering nowSec().");
  log.debug("Leaving nowSec().");
  return Math.floor(Date.now() / 1000);
}

function claimsFor(jti, iat, exp) {
  log.debug("Entering claimsFor().");
  log.debug("Leaving claimsFor().");
  return {
    typ: 'Bearer', jti: jti, iat: iat, exp: exp, sub: 'ada',
    client_id: 'sts-api-client', scope: 'openid'
  };
}

function freshJti() {
  log.debug("Entering freshJti().");
  const jti = 'opaque-' + nodeCrypto.randomBytes(8).toString('hex');
  log.debug("Leaving freshJti().");
  return jti;
}

function mutate(handle) {
  log.debug("Entering mutate().");
  const last = handle.charAt(handle.length - 1);
  const flipped = handle.slice(0, -1) + (last === 'A' ? 'B' : 'A');
  log.debug("Leaving mutate().");
  return flipped;
}

function remember(held, handle) {
  log.debug("Entering remember().");
  held.push(handle);
  log.debug("Leaving remember().");
}

function release(held) {
  log.debug("Entering release().");
  held.forEach(function (handle) {
    opaque.discard(handle);
  });
  held.length = 0;
  log.debug("Leaving release().");
}

function codeOfThrow(fn) {
  log.debug("Entering codeOfThrow().");
  try {
    fn();
    log.debug("Leaving codeOfThrow(). Nothing thrown.");
    return '';
  } catch (e) {
    // The assertion is the error code. The message is not the contract.
    log.debug("Caught in codeOfThrow(): " + ((e && e.message) || e));
    const code = errorCodes.codeOf(e) || '';
    log.debug("Leaving codeOfThrow(). " + code);
    return code;
  }
}

function libraryChecks(t, held) {
  log.debug("Entering libraryChecks().");
  const now = nowSec();
  t.check(opaque.issuesOpaque() === false,
          'the default format does not issue opaque tokens');
  t.equal(opaque.lookup('').kind, 'not-opaque',
          'an empty string is not a handle');
  t.equal(opaque.lookup('a.b.c').kind, 'not-opaque',
          'a string with a dot is not a handle');

  config.setOverride('oauth2.accessTokenFormat', 'opaque');
  t.check(opaque.issuesOpaque() === true,
          'oauth2.accessTokenFormat=opaque issues opaque tokens');

  const jti = freshJti();
  const handle = opaque.mint(claimsFor(jti, now, now + 3600), {});
  remember(held, handle);
  const text = String(handle);
  t.check(text.indexOf('.') < 0, 'the handle has no dot');
  t.equal(text.length, 43, 'the handle is 43 characters');
  t.check(/^[A-Za-z0-9_-]+$/.test(text),
          'the handle is unpadded base64url');
  const row = opaque.rowOf(text);
  t.check(!!row && JSON.stringify(row).indexOf(text) < 0,
          'the stored row does not contain the handle');
  const keys = opaque.keysForJti(jti);
  t.equal(keys.length, 1, 'the jti indexes one row');
  t.equal(keys[0], stsCrypto.credentialDigest(text),
          'the store key is the SHA-256 of the handle');

  const missHandle = opaque.lookup(mutate(text));
  const missOther = opaque.lookup(
    'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz');
  t.equal(JSON.stringify(missHandle), JSON.stringify(missOther),
          'a one-character change answers like any other miss');
  const rendered = JSON.stringify(missHandle) + JSON.stringify(missOther);
  t.check(rendered.indexOf(text) < 0 && rendered.indexOf('close') < 0,
          'a miss does not echo the handle or say the guess was close');

  const expiredJti = freshJti();
  const expired = opaque.mint(claimsFor(expiredJti, now - 120, now - 30),
                              {});
  const expiredFound = opaque.lookup(expired);
  t.equal(expiredFound.kind, 'inactive', 'an expired handle is inactive');
  t.equal(expiredFound.why, 'expired', 'and the reason is expiry');
  t.equal(opaque.rowOf(expired), null,
          'reading an expired handle deletes the row');

  const revokedJti = freshJti();
  const revoked = opaque.mint(claimsFor(revokedJti, now, now + 3600), {});
  remember(held, revoked);
  t.check(opaque.markRevoked(revoked) === true, 'markRevoked updates a row');
  const revokedFound = opaque.lookup(revoked);
  t.equal(revokedFound.kind, 'inactive', 'a revoked handle is inactive');
  t.equal(revokedFound.why, 'revoked', 'and the reason is revocation');
  t.check(opaque.rowOf(revoked) !== null,
          'a revoked row stays until it expires');

  const registerJti = freshJti();
  const registered = opaque.mint(claimsFor(registerJti, now, now + 3600),
                                 {});
  remember(held, registered);
  adminStats.revoke(registerJti, 'test', { how: 'test' }, now + 3600);
  const fromRegister = opaque.lookup(registered);
  t.equal(fromRegister.kind, 'inactive',
          'a jti revoked only in the token register is inactive');
  t.equal(fromRegister.why, 'revoked',
          'and that revocation is the reason');

  config.setOverride('security.rateLimitPerAddress', 2);
  websecurity.reset();
  const first = opaque.resolve('miss-one-not-stored', FAKE_REQ);
  const second = opaque.resolve('miss-two-not-stored', FAKE_REQ);
  const third = opaque.resolve('miss-three-not-stored', FAKE_REQ);
  t.equal(first.kind, 'unknown', 'the first miss is unknown');
  t.equal(second.kind, 'unknown', 'the second miss is still unknown');
  t.equal(third.kind, 'limited',
          'the miss past the address limit is refused');
  t.check(JSON.stringify(first) === JSON.stringify(second) &&
          JSON.stringify(first).indexOf('close') < 0,
          'the two misses that were allowed have one shape');
  t.equal(opaque.lookup(text).kind, 'active',
          'a known handle is not consumed by the miss limit');

  config.clearOverride('oauth2.accessTokenFormat');
  t.check(opaque.issuesOpaque() === false,
          'clearing the setting stops new opaque tokens');
  t.equal(opaque.lookup(text).kind, 'active',
          'a handle minted while it was on still resolves');
  t.equal(opaque.noteMiss(FAKE_REQ), null,
          'a miss is not counted once the realm issues JWTs again');

  config.setOverride('oauth2.accessTokenFormat', 'opaque');
  release(held);
  // The setting's minimum is 16, so an override of 1 is refused and the
  // cap stays at its default. Fill the legal minimum, then ask for one more.
  const capWrite = config.setOverride('oauth2.maxOpaqueAccessTokens', 16);
  t.check(!!(capWrite && capWrite.ok),
          'a cap of 16, the setting\'s minimum, is accepted');
  let filled = 0;
  while (filled < 16) {
    filled += 1;
    remember(held, opaque.mint(claimsFor(freshJti(), now, now + 3600),
                               {}));
  }
  const refused = codeOfThrow(function () {
    opaque.mint(claimsFor(freshJti(), now, now + 3600), {});
  });
  t.equal(refused, 'STS-OAUTH-0979',
          'a full store refuses the mint instead of evicting a live token');
  log.debug("Leaving libraryChecks().");
}

// The body runs in a `node -e` child. No Entering/Leaving pair: the child
// has no logger, and the findings file is the record.
function childMain() {
  const ROOT_DIR = process.env.OPAQUE_ROOT;
  const OUT = process.env.OPAQUE_OUT;
  const fsChild = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function headerTyp(token) {
    try {
      const seg = String(token).split('.')[0];
      const header = JSON.parse(Buffer.from(seg, 'base64url')
                                       .toString('utf8'));
      return String(header.typ || '');
    } catch (e) {
      return 'unreadable';
    }
  }
  try {
    require(ROOT_DIR + '/common/protocol_stack');
    const configChild = require(ROOT_DIR + '/common/config');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const opaqueChild = require(ROOT_DIR +
                                '/oauth-oidc/opaque_access_token');
    configChild.setOverride('oauth2.accessTokenFormat', 'opaque');
    const base = 'https://opaque.example';
    const opts = { client_id: 'sts-api-client', username: 'ada',
                   scope: 'openid' };
    const handle = String(oauth2.accessToken(base, opts) || '');
    note(handle.indexOf('.') < 0 && handle.length === 43 &&
         /^[A-Za-z0-9_-]+$/.test(handle),
         'accessToken under the override returns a 43-character handle');
    const jti = String(opaqueChild.jtiOf(handle) || '');
    const life = Number(opaqueChild.lifetimeSeconds(handle));
    note(jti.length > 0, 'the stored handle has a jti');
    note(life > 1, 'the stored handle has a positive lifetime',
         String(life));
    configChild.clearOverride('oauth2.accessTokenFormat');
    const jwt = String(oauth2.accessToken(base, opts) || '');
    note(jwt.split('.').length === 3,
         'with the override cleared, accessToken returns a JWT');
    note(headerTyp(jwt) === 'at+jwt', 'and its typ is at+jwt',
         headerTyp(jwt));
  } catch (e) {
    note(false, 'the child minted an access token',
         (e && e.stack) || (e && e.message) || String(e));
  }
  fsChild.writeFileSync(OUT, JSON.stringify(findings));
}

function runChild(t) {
  log.debug("Entering runChild().");
  const out = path.join(os.tmpdir(), 'opaque-at-' + process.pid + '-' +
                        nodeCrypto.randomBytes(8).toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', OPAQUE_ROOT: ROOT,
                                  OPAQUE_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
    // The child died before writing a report. The status is the detail.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
    // Never written, which the read above has already reported.
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving runChild(). No report.");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving runChild().");
}

function run(t) {
  log.debug("Entering run().");
  const held = [];
  try {
    libraryChecks(t, held);
    runChild(t);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    log.debug("Leaving run().");
    throw e;
  } finally {
    release(held);
    config.clearOverride('oauth2.accessTokenFormat');
    config.clearOverride('oauth2.maxOpaqueAccessTokens');
    config.clearOverride('security.rateLimitPerAddress');
    websecurity.reset();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'opaque_access_token',
  describe: 'opaque OAuth access tokens are 256-bit handles, off by default',
  run: run
};
