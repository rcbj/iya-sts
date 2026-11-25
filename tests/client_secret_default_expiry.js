// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/client_secret_default_expiry.js — CLIENT SECRETS EXPIRE BY DEFAULT
// (#2178, ASVS 5.0.0 13.3.4).
//
// `oauth2.clientSecretLifetimeDays` defaults to 365 (it was 0, never). The
// row, env/defaults.js and a new secret say so; a secret record that already
// carries an expiry, never included, keeps it, which is what makes the change
// compatible; and 0 is still never. In a child, because requiring the stack
// registers its routes on the shared app.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'client_secret_default_expiry',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD = 'STS_CLIENT_SECRET_DEFAULT_EXPIRY_CHILD';
const DAY_S = 86400;

async function child() {
  log.debug("Entering child().");
  require('../common/protocol_stack');
  const applications = require('../common/applications');
  const config = require('../common/config');
  const out = {};
  const nowS = Math.floor(Date.now() / 1000);
  const secretsOf = function (id) {
    return (applications.clientConfigOf(id) || {}).client_secrets || [];
  };
  applications.createApplication({ identifier: 'cs-default-new',
    protocols: ['oauth2'], fields: { oauthClientId: 'cs-default-new',
      oauthClientSecret: 'cs-default-new-secret-0123456789abcdef',
      oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
  out.newExpires = (secretsOf('cs-default-new')[0] || {}).expiresAt;
  // A record written before #2178, handed in whole with no expiry.
  applications.createApplication({ identifier: 'cs-default-old',
    protocols: ['oauth2'], fields: { oauthClientId: 'cs-default-old',
      oauthClientSecret: JSON.stringify({ id: 'old-one',
        secret: 'cs-default-old-secret-0123456789abcdef',
        created: nowS - 30 * DAY_S, expires: 0 }),
      oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
  out.oldExpires = (secretsOf('cs-default-old')[0] || {}).expiresAt;
  config.setOverride('oauth2.clientSecretLifetimeDays', 0);
  applications.createApplication({ identifier: 'cs-default-never',
    protocols: ['oauth2'], fields: { oauthClientId: 'cs-default-never',
      oauthClientSecret: 'cs-default-never-secret-0123456789abcdef',
      oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
  out.neverExpires = (secretsOf('cs-default-never')[0] || {}).expiresAt;
  config.clearOverride('oauth2.clientSecretLifetimeDays');
  out.nowS = nowS;
  process.stdout.write('RESULT ' + JSON.stringify(out) + '\n');
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
  name: 'client_secret_default_expiry',
  describe: 'client secrets expire after 365 days by default (#2178); one ' +
            'that already says never keeps it',
  run: async function (t) {
    const config = require('../common/config');
    const defaults = require('../env/defaults.js');
    const row = config.SETTINGS.filter(function (one) {
      return one.key === 'oauth2.clientSecretLifetimeDays';
    })[0];
    t.equal(row && row.dflt, 365, 'the row defaults to 365 days');
    t.equal(defaults.oauth2.clientSecretLifetimeDays, 365,
            'env/defaults.js says 365');
    const run = childProcess.spawnSync(process.execPath, [__filename], {
      env: Object.assign({}, process.env, { [CHILD]: '1',
                                            LOG_LEVEL: 'fatal' }),
      cwd: path.join(__dirname, '..'), encoding: 'utf8', timeout: 180000 });
    const line = String(run.stdout || '').split('\n').filter(function (one) {
      return one.indexOf('RESULT ') === 0;
    })[0];
    t.check(!!line, 'the child answered', String(run.stderr || '')
      .slice(-400));
    if (!line) {
      return;
    }
    const got = JSON.parse(line.slice(7));
    const want = got.nowS + 365 * DAY_S;
    t.check(Math.abs(Number(got.newExpires) - want) <= 120,
            'a new secret expires 365 days out',
            'expiresAt ' + got.newExpires + ', want about ' + want);
    t.equal(got.oldExpires, 0, 'a record that already says never keeps it');
    t.equal(got.neverExpires, 0, '0 is still never');
  }
};
