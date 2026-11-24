// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/authorization_details_par.js — AN OPTION TO ACCEPT
// authorization_details ONLY IN A PUSHED REQUEST (#2185, ASVS 5.0.0 10.4.15).
//
// `oauth2.authorizationDetailsRequirePar`, OFF by default (rcbj: a policy
// option, never the default). Against the real authorization endpoint, in a
// child (requiring the stack registers its routes on the shared app): off, a
// request carrying authorization_details is not refused for it; on, it is
// refused as a 400 on this server naming the setting, and a request carrying
// none is not.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'authorization_details_par',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD = 'STS_AUTHORIZATION_DETAILS_PAR_CHILD';
const SETTING = 'oauth2.authorizationDetailsRequirePar';

async function child() {
  log.debug("Entering child().");
  const http = require('http');
  require('../common/protocol_stack');
  const app = require('../common/app');
  const config = require('../common/config');
  const applications = require('../common/applications');
  const CLIENT = 'ad-par-client';
  const REDIRECT = 'https://rp.example.net/callback';
  applications.createApplication({ identifier: CLIENT, protocols: ['oauth2'],
    fields: { oauthClientId: CLIENT, oauthRedirectUri: [REDIRECT],
              oauthTokenEndpointAuthMethod: 'none',
              oauthGrantType: ['authorization_code'],
              oauthResponseType: ['code'] } });
  const server = http.createServer(app);
  await new Promise(function (r) {
    server.listen(0, '127.0.0.1', r);
  });
  const port = server.address().port;
  const PARAMS = { client_id: CLIENT, response_type: 'code',
    redirect_uri: REDIRECT, scope: 'openid', state: 's1',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256' };
  // An unsigned request object (RFC 9101 by value), which development
  // accepts: its authorization_details is a JSON array, not a string.
  const unsigned = function (claims) {
    const b64 = function (o) {
      return Buffer.from(JSON.stringify(o)).toString('base64url');
    };
    return b64({ alg: 'none', typ: 'oauth-authz-req+jwt' }) + '.' +
           b64(claims) + '.';
  };
  const authorize = function (details, byValue) {
    const q = new URLSearchParams(PARAMS);
    if (details && !byValue) {
      q.set('authorization_details',
            JSON.stringify([{ type: 'payment_initiation' }]));
    }
    if (byValue) {
      q.set('request', unsigned(Object.assign({}, PARAMS,
        { authorization_details: [{ type: 'payment_initiation' }] })));
    }
    return new Promise(function (resolve, reject) {
      http.get({ host: '127.0.0.1', port: port,
                 path: '/oauth2/authorize?' + q.toString(),
                 headers: { accept: 'text/html' } }, function (res) {
        const chunks = [];
        res.on('data', function (c) {
          chunks.push(c);
        });
        res.on('end', function () {
          resolve({ status: res.statusCode,
                    body: Buffer.concat(chunks).toString('utf8') });
        });
      }).on('error', reject);
    });
  };
  const named = function (r) {
    return r.body.indexOf(SETTING) >= 0;
  };
  const offDetails = await authorize(true);
  config.setOverride(SETTING, 'true');
  const onDetails = await authorize(true);
  const onPlain = await authorize(false);
  const onByValue = await authorize(true, true);
  config.clearOverride(SETTING);
  server.close();
  process.stdout.write('RESULT ' + JSON.stringify({
    off: { status: offDetails.status, named: named(offDetails) },
    on: { status: onDetails.status, named: named(onDetails) },
    plain: { status: onPlain.status, named: named(onPlain) },
    byValue: { status: onByValue.status, named: named(onByValue),
               body: onByValue.body.slice(0, 300) } }) + '\n');
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
  name: 'authorization_details_par',
  describe: 'oauth2.authorizationDetailsRequirePar: off by default; on, ' +
            'authorization_details only in a pushed request (#2185)',
  run: async function (t) {
    const config = require('../common/config');
    const row = config.SETTINGS.filter(function (one) {
      return one.key === SETTING;
    })[0];
    t.check(row && row.dflt === false && row.runtime === true,
            'the option exists, off by default, per realm');
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
    t.check(!got.off.named, 'off, authorization_details in the query is ' +
            'not refused for it', JSON.stringify(got.off));
    t.check(got.on.status === 400 && got.on.named,
            'on, it is refused as a 400 on this server naming the setting',
            JSON.stringify(got.on));
    t.check(!got.plain.named, 'on, a request with no authorization_details ' +
            'is not refused for it', JSON.stringify(got.plain));
    t.check(got.byValue.status === 400 && got.byValue.named,
            'on, authorization_details inside a request object passed by ' +
            'value is refused too: it travels in the browser as well',
            JSON.stringify(got.byValue));
  }
};
