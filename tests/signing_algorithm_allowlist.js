// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: signing_algorithm_allowlist.js
//
// ===========================================================================
// ONE REALM'S SIGNING ALGORITHMS, NAMED ONE BY ONE (#1348, 2026-11-05).
// `keys.signingAlgorithms` (`common/CLAUDE.md`, the section of that name), held
// in a CHILD PROCESS that loads the whole stack and listens on a loopback port:
//
//   A. the row, its closed set against `stsCrypto.JWS_SIGNING_ALGS`, and the
//      write rule: a list without RS256 is refused and a list with it is not.
//   B. empty changes nothing: the helpers answer their input, and every
//      algorithm stays signable.
//   C. a list naming only RS256: the helpers narrow; an encryption key stays;
//      a signature with another algorithm, HS256 included, is refused
//      STS-KEYS-0166 synchronously and asynchronously; RS256 still signs; an
//      unlisted configured access-token algorithm signs with RS256.
//   D. over HTTP, in a realm with that list beside the default realm: the JWK
//      Set and discovery; what it accepts from clients is unchanged; a
//      registration naming ES256 for its ID Tokens is refused there and
//      accepted in the default realm.
//
// **IN A CHILD** for `tests/jose_kid.js`'s reason: loading the whole protocol
// stack into `run.js`'s one process changes what later files see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'signing_algorithm_allowlist',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SAA_ROOT;
  const OUT = process.env.SAA_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function get(port, urlPath) {
    return new Promise(function (resolve, reject) {
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: 'GET' }, function (res) {
        let text = '';
        res.on('data', function (c) {
          text += c;
        });
        res.on('error', reject);
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            // No logger in a `node -e` child; the reason travels on the
            // result.
            json = { unreadable: e.message };
          }
          resolve({ status: res.statusCode, json: json });
        });
      });
      req.on('error', reject);
      req.end();
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    await require(ROOT + '/common/service_state').start();
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const helpers = require(ROOT + '/common/helpers');
    const stsCrypto = require(ROOT + '/common/crypto');
    const errorCodes = require(ROOT + '/common/error_codes');
    const applications = require(ROOT + '/common/applications');
    const oauth2 = require(ROOT + '/oauth-oidc/oauth2');
    const KEY = 'keys.signingAlgorithms';

    // ==== A. the row and the write rule ===================================
    const row = config.SETTINGS.filter(function (one) {
      return one.key === KEY;
    })[0] || {};
    note(row.type === 'csv' && row.dflt === '' && row.runtime === true &&
         row.group === 'Key material' && !row.perProcess,
         'A1. the setting is a csv, empty by default, runtime, per realm, in ' +
         'the Key material group', JSON.stringify(row));
    note(JSON.stringify((row.csvValues || []).slice().sort()) ===
         JSON.stringify(stsCrypto.JWS_SIGNING_ALGS.slice().sort()),
         'A2. its closed set is every JWS signing algorithm this service ' +
         'speaks', JSON.stringify(row.csvValues));
    const without = config.checkOverride(KEY, 'ES256');
    note(/must include RS256/.test(String(without)),
         'A3. a list without RS256 is refused', String(without));
    note(!config.checkOverride(KEY, 'RS256') &&
         !config.checkOverride(KEY, 'RS256,ES256') &&
         !config.checkOverride(KEY, ''),
         'A4. a list with RS256, and an empty one, are accepted');
    note(/./.test(String(config.checkOverride(KEY, 'RS256,nonsense'))),
         'A5. a name outside the closed set is refused');

    // ==== B. empty changes nothing ========================================
    const keys = [{ kty: 'RSA', use: 'sig', kid: 'r' },
      { kty: 'RSA', use: 'sig', kid: 'p', alg: 'PS256' },
      { kty: 'EC', use: 'sig', kid: 'e', crv: 'P-256', alg: 'ES256' },
      { kty: 'EC', use: 'sig', kid: 'n', crv: 'P-384' },
      { kty: 'EC', use: 'enc', kid: 'ee', crv: 'P-256' },
      { kty: 'RSA', use: 'enc', kid: 're' }];
    const doc = function () {
      return { id_token_signing_alg_values_supported: ['HS256', 'RS256',
        'ES256'],
      userinfo_signing_alg_values_supported: ['RS256', 'ES256', 'none'],
      token_endpoint_auth_signing_alg_values_supported: ['RS256', 'ES256'] };
    };
    note(helpers.signingAlgAllowlist() === null &&
         helpers.withoutUnlistedSigningKeys(keys) === keys &&
         helpers.signingAlgListed('ES256') &&
         JSON.stringify(helpers.withoutUnlistedSigningAlgs(doc())) ===
         JSON.stringify(doc()) &&
         helpers.signableJwsAlgs().indexOf('ES256') >= 0,
         'B1. empty: the helpers answer their input and ES256 stays signable');

    // ==== C. a list naming only RS256 =====================================
    config.setOverride(KEY, 'RS256');
    const kept = helpers.withoutUnlistedSigningKeys(keys).map(function (k) {
      return k.kid;
    });
    note(JSON.stringify(kept) === JSON.stringify(['r', 'ee', 're']),
         'C1. the key filter keeps an RSA key naming no algorithm and the ' +
         'encryption keys, and drops PS256, ES256 and a P-384 key naming none',
         JSON.stringify(kept));
    const narrowed = helpers.withoutUnlistedSigningAlgs(doc());
    note(JSON.stringify(narrowed.id_token_signing_alg_values_supported) ===
         '["RS256"]' &&
         JSON.stringify(narrowed.userinfo_signing_alg_values_supported) ===
         '["RS256","none"]' &&
         narrowed.token_endpoint_auth_signing_alg_values_supported.length === 2,
         'C2. what it signs is narrowed, `none` stays on UserInfo, and what ' +
         'it accepts is untouched', JSON.stringify(narrowed));
    note(JSON.stringify(helpers.signableJwsAlgs()) === '["RS256"]',
         'C3. RS256 alone is signable',
         JSON.stringify(helpers.signableJwsAlgs()));
    const refusedAs = function (alg, secret) {
      try {
        helpers.signJwtAs({ sub: 'saa' }, alg, secret, {});
        return 'signed';
      } catch (e) {
        return errorCodes.of ? errorCodes.of(e) : e.message;
      }
    };
    const es = refusedAs('ES256', null);
    const hs = refusedAs('HS256', 'a-client-secret-long-enough-for-hs256-use');
    note(es !== 'signed' && hs !== 'signed',
         'C4. ES256 and HS256 are refused by signJwtAs()', es + ' / ' + hs);
    let asyncRefusal = '';
    try {
      await helpers.signJwtAsAsync({ sub: 'saa' }, 'ES384', null, {});
      asyncRefusal = 'signed';
    } catch (e) {
      asyncRefusal = e.message;
    }
    note(/keys\.signingAlgorithms/.test(asyncRefusal),
         'C5. and ES384 by signJwtAsAsync(), naming the setting', asyncRefusal);
    note(/^eyJ/.test(String(helpers.signJwtAs({ sub: 'saa' }, 'RS256', null,
                                              {}))),
         'C6. RS256 still signs');
    config.setOverride('oauth2.accessTokenSigningAlg', 'ES256');
    const tokenAlg = async function () {
      const token = await oauth2.accessTokenAsync('https://sts.test',
        { client_id: 'saa-client', username: 'saa-person', scope: 'openid' });
      return JSON.parse(Buffer.from(String(token).split('.')[0], 'base64url')
        .toString('utf8')).alg;
    };
    const unlistedAlg = await tokenAlg();
    note(unlistedAlg === 'RS256',
         'C7. an unlisted configured access-token algorithm signs with RS256',
         unlistedAlg);
    config.clearOverride(KEY);
    const configuredAlg = await tokenAlg();
    note(configuredAlg === 'ES256',
         'C7a. and with no list that same setting signs with ES256',
         configuredAlg);
    config.clearOverride('oauth2.accessTokenSigningAlg');
    config.setOverride(KEY, 'RS256,ES256');
    note(helpers.signingAlgListed('ES256') &&
         /^eyJ/.test(String(helpers.signJwtAs({ sub: 'saa' }, 'ES256', null,
                                              {}))),
         'C8. a listed second algorithm signs');
    config.clearOverride(KEY);

    // ==== D. over HTTP, beside the default realm ==========================
    const REALM = 'saaonly';
    realms.create({ id: REALM });
    realms.run(realms.get(REALM), function () {
      config.setOverride(KEY, 'RS256');
    });
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const prefix = '/realm/' + REALM;
    const signing = function (list) {
      return (list || []).filter(function (k) {
        return k.use !== 'enc';
      });
    };
    const allJwks = await get(port, '/oauth2/jwks');
    const oneJwks = await get(port, prefix + '/oauth2/jwks');
    note(signing(allJwks.json.keys).some(function (k) {
      return k.kty === 'EC';
    }),
    'D1. the default realm still publishes its EC signing keys',
    allJwks.status);
    note(oneJwks.status === 200 && signing(oneJwks.json.keys).length > 0 &&
         signing(oneJwks.json.keys).every(function (k) {
           return k.kty === 'RSA';
         }),
         'D2. the realm with the list publishes only RSA signing keys',
         JSON.stringify(signing(oneJwks.json.keys).map(function (k) {
           return k.kty + '/' + (k.alg || '');
         })));
    const allDisc = (await get(port,
                               '/.well-known/openid-configuration')).json;
    const oneDisc = (await get(port, prefix +
                               '/.well-known/openid-configuration')).json;
    note(JSON.stringify(oneDisc.id_token_signing_alg_values_supported) ===
         '["RS256"]' &&
         JSON.stringify(oneDisc.userinfo_signing_alg_values_supported) ===
         '["RS256","none"]' &&
         JSON.stringify(oneDisc.introspection_signing_alg_values_supported) ===
         '["RS256"]' &&
         JSON.stringify(oneDisc.authorization_signing_alg_values_supported) ===
         '["RS256"]',
         'D3. its discovery names RS256 alone for what it signs',
         JSON.stringify(oneDisc.id_token_signing_alg_values_supported));
    note(oneDisc.token_endpoint_auth_signing_alg_values_supported
      .indexOf('ES256') >= 0,
    'D4. and still accepts an ES256 client assertion');
    note(allDisc.id_token_signing_alg_values_supported.indexOf('ES256') >= 0,
         'D5. the default realm\'s discovery still names ES256');
    const asked = { id_token_signed_response_alg: 'ES256' };
    const here = applications.clientResponseMetadataProblem(asked);
    const there = realms.run(realms.get(REALM), function () {
      return applications.clientResponseMetadataProblem(asked);
    });
    note(!here && there && there.error === 'invalid_client_metadata',
         'D6. a registration naming ES256 for its ID Tokens is accepted in ' +
         'the default realm and refused in the realm with the list',
         JSON.stringify([here, there]));

    realms.run(realms.get(REALM), function () {
      config.clearOverride(KEY);
    });
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'saa-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SAA_ROOT: ROOT, SAA_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one; reported below.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'signing_algorithm_allowlist',
  describe: 'keys.signingAlgorithms (#1348): a realm limited to named ' +
            'signing algorithms publishes, advertises and signs only those, accepts ' +
            'what it always did from clients, and empty changes nothing',
  run: run
};
