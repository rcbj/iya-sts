// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sign_jwt_async.js
//
// ===========================================================================
// TOKENS SIGNED ON LIBUV'S THREAD POOL (2026-10-21, #820, rcbj's decision).
//
// `helpers.signJwtAsync()` is `signJwt()` with the signature made by node's
// asynchronous `crypto.sign()`: a refresh signed two or three RS256 tokens
// on the event loop, each holding every other request on the worker.
//
//   A1. it signs with the same key and the same header `signJwt()` would,
//       and the token verifies as this service's own;
//   A2. it is recorded, as every token this service issues is;
//   A3. the token issuers a caller can wait for sign through it: the
//       access token (`accessTokenAsync()`), the refresh token
//       (`refreshTokenAsync()`, which `tokenSet()` uses) and the ID Token.
//
// In a child process: it replaces the JWT recorder.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'sign_jwt_async',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.SJA_OUT;
  const ROOT = process.env.SJA_ROOT;
  (async function () {
    const helpers = require(ROOT + '/common/helpers');
    const recorded = [];
    helpers.setJwtRecorder(function (payload, signed, context) {
      recorded.push({ jti: payload.jti, signed: signed, context: context });
    });
    const payload = { iss: 'https://sts.test', sub: 'alice', jti: 'a-1',
                      iat: 1, exp: 4102444800, typ: 'Bearer' };
    const sync = helpers.signJwt(payload, { kind: 'access_token' },
                                 { header: { typ: 'at+jwt' } });
    const later = await helpers.signJwtAsync(Object.assign({}, payload,
      { jti: 'a-2' }), { kind: 'access_token' },
      { header: { typ: 'at+jwt' } });
    const headerOf = function (jws) {
      return JSON.parse(Buffer.from(jws.split('.')[0], 'base64url')
        .toString('utf8'));
    };
    let verified = null;
    try {
      verified = helpers.verifyOwnJws(later);
    } catch (e) {
      verified = String((e && e.message) || e);
    }
    const a = headerOf(sync);
    const b = headerOf(later);
    note(b.alg === a.alg && b.kid === a.kid && b.typ === 'at+jwt' &&
         verified && typeof verified === 'object' && verified.jti === 'a-2',
         'A1. the same key and header as signJwt(), and it verifies as ' +
         'this service\'s own', JSON.stringify({ sync: a, async: b,
           verified: typeof verified === 'object' ? 'ok' : verified }));
    note(recorded.length === 2 && recorded[1].jti === 'a-2' &&
         recorded[1].signed === later &&
         recorded[1].context && recorded[1].context.kind === 'access_token',
         'A2. it is recorded as every issued token is',
         JSON.stringify(recorded.map(function (one) {
           return one.jti;
         })));
    const source = require('fs').readFileSync(ROOT + '/oauth-oidc/oauth2.ts',
                                              'utf8');
    const bodyOf = function (marker) {
      const at = source.indexOf(marker);
      return at < 0 ? '' : source.slice(at, source.indexOf('\n  }\n', at));
    };
    note(/signJwtAsync\(/.test(bodyOf('async accessTokenAsync(')) &&
         /signJwtAsync\(/.test(bodyOf('private async refreshTokenAsync(')) &&
         /await self\.refreshTokenAsync\(/.test(bodyOf('async tokenSet(')) &&
         /signJwtAsync\(/.test(bodyOf('async idToken(')),
         'A3. the access token, the refresh token and the ID Token a ' +
         'caller can wait for are signed through it');
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-sja-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { SJA_OUT: out, SJA_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'sign_jwt_async',
  describe: 'tokens a caller can wait for are signed on libuv\'s thread ' +
            'pool, with the same key, header and recording (#820)',
  run: run
};
