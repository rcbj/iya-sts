// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/sender_constraint_issuance.js — AN OPTION TO ISSUE ONLY
// SENDER-CONSTRAINED ACCESS TOKENS (#2183, ASVS 5.0.0 10.3.5, 10.4.14).
//
// `oauth2.accessTokenRequireSenderConstraint`, OFF by default (rcbj: a policy
// option, never the default). The decisions: off refuses nothing; on refuses
// a request that binds nothing and lets either binding through; the browser's
// token is refused on. Then the token endpoint itself, in a child (requiring
// the stack registers its routes on the shared app): a client-credentials
// request with no binding is issued a token while the option is off, and
// refused invalid_dpop_proof while it is on.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'sender_constraint_issuance',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD = 'STS_SENDER_CONSTRAINT_ISSUANCE_CHILD';
const SETTING = 'oauth2.accessTokenRequireSenderConstraint';

async function child() {
  log.debug("Entering child().");
  const http = require('http');
  require('../common/protocol_stack');
  const app = require('../common/app');
  const config = require('../common/config');
  const applications = require('../common/applications');
  const CLIENT = 'sc-issuance-client';
  const SECRET = 'sc-issuance-secret-0123456789abcdef0123456789abcdef';
  applications.createApplication({ identifier: CLIENT, protocols: ['oauth2'],
    fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: 'client_secret_basic',
              oauthGrantType: ['client_credentials'] } });
  const server = http.createServer(app);
  await new Promise(function (r) {
    server.listen(0, '127.0.0.1', r);
  });
  const port = server.address().port;
  const token = function () {
    return new Promise(function (resolve, reject) {
      const body = 'grant_type=client_credentials';
      const req = http.request({ host: '127.0.0.1', port: port,
        path: '/oauth2/token', method: 'POST', headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'content-length': Buffer.byteLength(body),
          authorization: 'Basic ' +
            Buffer.from(CLIENT + ':' + SECRET).toString('base64') } },
      function (res) {
        const chunks = [];
        res.on('data', function (c) {
          chunks.push(c);
        });
        res.on('end', function () {
          let parsed = {};
          try {
            parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          } catch (e) {
            log.debug("Caught in token(): " + ((e && e.message) || e));
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      });
      req.on('error', reject);
      req.end(body);
    });
  };
  const off = await token();
  config.setOverride(SETTING, 'true');
  const on = await token();
  config.clearOverride(SETTING);
  server.close();
  process.stdout.write('RESULT ' + JSON.stringify({
    offStatus: off.status, offToken: !!off.body.access_token,
    onStatus: on.status, onError: on.body.error || '',
    onDescription: on.body.error_description || '' }) + '\n');
  log.debug("Leaving child().");
}

if (process.env[CHILD]) {
  child().then(function () {
    process.exit(0);
  }, function (e) {
    process.stderr.write(String(e && e.stack) + '\n');
    process.exit(2);
  });
}

module.exports = {
  name: 'sender_constraint_issuance',
  describe: 'oauth2.accessTokenRequireSenderConstraint: off by default; on, ' +
            'no unbound access token is minted (#2183)',
  run: async function (t) {
    const config = require('../common/config');
    const sc = require('../oauth-oidc/sender_constraints');
    const row = config.SETTINGS.filter(function (one) {
      return one.key === SETTING;
    })[0];
    t.check(row && row.dflt === false && row.runtime === true,
            'the option exists, off by default, per realm');
    t.check(sc.accessTokenIssuanceRefusal({ grant: 'client_credentials' }) ===
            null && sc.browserAccessTokenRefusal() === null,
            'off, nothing is refused');
    config.setOverride(SETTING, 'true');
    try {
      const unbound = sc.accessTokenIssuanceRefusal(
        { grant: 'client_credentials' });
      t.check(unbound && unbound.errorCode === 'STS-OAUTH-1013' &&
              unbound.error === 'invalid_dpop_proof' &&
              unbound.setting === SETTING,
              'on, a request that binds nothing is refused',
              JSON.stringify(unbound));
      t.check(sc.accessTokenIssuanceRefusal({ dpopJkt: 'abc' }) === null,
              'on, a DPoP proof is enough');
      t.check(sc.accessTokenIssuanceRefusal({ certificateBound: true }) ===
              null, 'on, a client certificate is enough');
      const browser = sc.browserAccessTokenRefusal();
      t.check(browser && browser.errorCode === 'STS-OAUTH-1014' &&
              browser.error === 'unsupported_response_type',
              'on, a token in the browser is refused', JSON.stringify(browser));
      t.check(sc.anythingRequired(), 'the console\'s warning block knows');
    } finally {
      config.clearOverride(SETTING);
    }
    const run = childProcess.spawnSync(process.execPath, [__filename], {
      env: Object.assign({}, process.env, { [CHILD]: '1',
                                            LOG_LEVEL: 'fatal' }),
      cwd: path.join(__dirname, '..'), encoding: 'utf8', timeout: 180000 });
    const line = String(run.stdout || '').split('\n').filter(function (one) {
      return one.indexOf('RESULT ') === 0;
    })[0];
    t.check(!!line, 'the child answered',
            String(run.stderr || '').slice(-400));
    if (!line) {
      return;
    }
    const got = JSON.parse(line.slice(7));
    t.check(got.offStatus === 200 && got.offToken,
            'off, the token endpoint issues an unbound token as before',
            JSON.stringify(got));
    t.check(got.onStatus === 400 && got.onError === 'invalid_dpop_proof' &&
            got.onDescription.indexOf('sender-constrained') >= 0,
            'on, the token endpoint refuses it with invalid_dpop_proof',
            JSON.stringify(got));
  }
};
