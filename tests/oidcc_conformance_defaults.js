// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: oidcc_conformance_defaults.js
//
// ===========================================================================
// THE DEFAULTS THAT PASS OPENID CONNECT CONFORMANCE (#1292, 2026-11-03).
// rcbj, applying for OpenID Foundation certification: "Make the default be
// whatever passes OIDC conformance." Three changes, held in a CHILD PROCESS
// that loads the whole stack and listens on a loopback port:
//
//   E. `keys.eddsaSigning`, off by default (`common/CLAUDE.md`, *EdDSA JOSE
//      SIGNING AS A PER-REALM SWITCH*): the row; the four helpers on and off
//      (no OKP signing key, an OKP `use: "enc"` key kept, only the four
//      own-signing members narrowed, an accepted list untouched);
//      `signJwtAs('EdDSA')` and, since #1368, `signJwt()` refused STS-KEYS-0165
//      off and signing on; over HTTP the default
//      realm's JWKS without an OKP signing key and its discovery without
//      EdDSA in the ID Token list but with it in the client-assertion list,
//      and a realm that turned it on publishing both; a registration naming
//      EdDSA for its ID Tokens refused in the one and accepted in the other.
//   T. `session_expiry` and `tenant` (Enterprise Extensions, #148): absent
//      from an ID Token by default; `tenant` present when the claims
//      request's `id_token` member names it; both of the realm's with
//      `oauth2.enterpriseClaimsAlways` on.
//   P. the `profile` scope: an implicit ID Token for a person with nothing
//      typed carries all fourteen claims in development (invented, as the
//      rest always were), and a person whose entry holds the five new
//      attributes is answered from them — `schacGender` 1 as `male`.
//
// **IN A CHILD** for `tests/jose_kid.js`'s reason: loading the whole
// protocol stack into `run.js`'s one process changes what later files see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'oidcc_conformance_defaults',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.OCD_ROOT;
  const OUT = process.env.OCD_OUT;
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
  function claimsOf(token) {
    return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url')
                            .toString('utf8'));
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    await require(ROOT + '/common/service_state').start();
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const helpers = require(ROOT + '/common/helpers');
    const errorCodes = require(ROOT + '/common/error_codes');
    const applications = require(ROOT + '/common/applications');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const oauth2 = require(ROOT + '/oauth-oidc/oauth2');

    // ==== E. EdDSA signing ================================================
    const row = config.SETTINGS.filter(function (one) {
      return one.key === 'keys.eddsaSigning';
    })[0] || {};
    note(row.type === 'bool' && row.dflt === false && row.runtime === true &&
         row.group === 'Key material' && !row.perProcess,
         'E1. keys.eddsaSigning is a bool, OFF by default, runtime, per ' +
         'realm, in the Key material group', JSON.stringify(row));
    note(helpers.isEddsaJwsAlg('EdDSA') && helpers.isEddsaJwsAlg('Ed25519') &&
         helpers.isEddsaJwsAlg('Ed448') && !helpers.isEddsaJwsAlg('ES256') &&
         !helpers.isEddsaJwsAlg('ML-DSA-44-Ed25519'),
         'E2. isEddsaJwsAlg() names EdDSA, Ed25519 and Ed448 and nothing ' +
         'else');
    const keys = [{ kty: 'RSA', use: 'sig', kid: 'r' },
                  { kty: 'OKP', crv: 'Ed25519', use: 'sig', kid: 'e1' },
                  { kty: 'OKP', crv: 'Ed448', kid: 'e2' },
                  { kty: 'OKP', crv: 'X25519', use: 'enc', kid: 'x' },
                  { kty: 'EC', crv: 'P-256', use: 'sig', kid: 'p' }];
    const doc = function () {
      return {
        id_token_signing_alg_values_supported: ['RS256', 'EdDSA'],
        userinfo_signing_alg_values_supported: ['EdDSA', 'none'],
        introspection_signing_alg_values_supported: ['EdDSA', 'ES256'],
        authorization_signing_alg_values_supported: ['PS256', 'EdDSA'],
        token_endpoint_auth_signing_alg_values_supported: ['RS256', 'EdDSA'],
        dpop_signing_alg_values_supported: ['EdDSA']
      };
    };
    const narrowed = helpers.withoutEddsaSigningAlgs(doc());
    note(JSON.stringify(narrowed) === JSON.stringify({
      id_token_signing_alg_values_supported: ['RS256'],
      userinfo_signing_alg_values_supported: ['none'],
      introspection_signing_alg_values_supported: ['ES256'],
      authorization_signing_alg_values_supported: ['PS256'],
      token_endpoint_auth_signing_alg_values_supported: ['RS256', 'EdDSA'],
      dpop_signing_alg_values_supported: ['EdDSA']
    }), 'E3. off, the four lists of what the realm signs lose EdDSA and ' +
        'the lists of what it accepts keep it', JSON.stringify(narrowed));
    note(helpers.withoutEddsaSigningKeys(keys).map(function (k) {
      return k.kid;
    }).join(',') === 'r,x,p',
         'E4. off, the OKP signing keys leave the key set and an OKP ' +
         'use: enc key stays');
    note(helpers.signableJwsAlgs().indexOf('EdDSA') < 0 &&
         helpers.signableJwsAlgs().indexOf('ES256') >= 0 &&
         helpers.offeredJwsAlgs().indexOf('EdDSA') >= 0,
         'E5. off, signableJwsAlgs() leaves EdDSA out and offeredJwsAlgs() ' +
         'does not');
    let refused = null;
    try {
      helpers.signJwtAs({ sub: 'ocd' }, 'EdDSA', null, {});
    } catch (e) {
      refused = e;
    }
    note(refused && errorCodes.codeOf(refused) === 'STS-KEYS-0165' &&
         !/STS-/.test(String(refused.message)),
         'E6. off, signJwtAs(EdDSA) is refused STS-KEYS-0165, the code not ' +
         'in the message', refused ? errorCodes.codeOf(refused) + ' ' +
         refused.message : 'it signed');
    let asyncRefused = null;
    await helpers.signJwtAsAsync({ sub: 'ocd' }, 'EdDSA', null, {})
      .then(function () {
        asyncRefused = null;
      }, function (e) {
        asyncRefused = e;
      });
    note(asyncRefused && errorCodes.codeOf(asyncRefused) === 'STS-KEYS-0165',
         'E7. and so is signJwtAsAsync(EdDSA)',
         asyncRefused ? asyncRefused.message : 'it signed');
    // E8, REVERSED ON PURPOSE (#1368): a signature with a key nobody can fetch
    // helps nobody, so signJwt() answers as signJwtAs() does, and a setting
    // that still names EdDSA is replaced rather than refused.
    let configured = null;
    try {
      configured = helpers.signJwt({ sub: 'ocd', iat: 1 }, {},
                                   { algorithm: 'EdDSA' });
    } catch (e) {
      configured = e;
    }
    note(configured instanceof Error &&
         errorCodes.codeOf(configured) === 'STS-KEYS-0165',
         'E8. signJwt(EdDSA) is refused too, with EdDSA signing off',
         String(configured).slice(0, 80));
    note(helpers.usableSigningAlg('EdDSA') === 'RS256',
         'E8b. a setting that names EdDSA signs with RS256 instead');
    config.setOverride('keys.eddsaSigning', true);
    let signed = null;
    try {
      signed = helpers.signJwtAs({ sub: 'ocd' }, 'EdDSA', null, {});
    } catch (e) {
      signed = 'threw: ' + e.message;
    }
    note(/^eyJ/.test(String(signed)) &&
         helpers.withoutEddsaSigningKeys(keys).length === keys.length &&
         helpers.signableJwsAlgs().indexOf('EdDSA') >= 0,
         'E9. on, EdDSA signs, every key is kept and EdDSA is signable',
         String(signed).slice(0, 80));
    config.clearOverride('keys.eddsaSigning');

    const REALM = 'ocdeddsa';
    realms.create({ id: REALM });
    realms.run(realms.get(REALM), function () {
      config.setOverride('keys.eddsaSigning', true);
    });
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const prefix = '/realm/' + REALM;
    const okpSigning = function (list) {
      return (list || []).filter(function (k) {
        return k.kty === 'OKP' && k.use !== 'enc';
      });
    };
    const offJwks = await get(port, '/oauth2/jwks');
    const onJwks = await get(port, prefix + '/oauth2/jwks');
    note(offJwks.status === 200 && okpSigning(offJwks.json.keys).length === 0 &&
         offJwks.json.keys[0].kty === 'RSA',
         'E10. the default realm\'s JWKS carries no OKP signing key, its RSA ' +
         'key still first', JSON.stringify((offJwks.json.keys || [])
           .map(function (k) {
             return k.kty + '/' + (k.crv || '') + '/' + (k.use || '');
           })));
    note(onJwks.status === 200 && okpSigning(onJwks.json.keys).length > 0,
         'E11. a realm with keys.eddsaSigning on publishes its OKP keys',
         onJwks.status + ' ' + okpSigning(onJwks.json.keys).length);
    const offDisc = (await get(port,
                               '/.well-known/openid-configuration')).json;
    const onDisc = (await get(port, prefix +
                              '/.well-known/openid-configuration')).json;
    note(offDisc.id_token_signing_alg_values_supported.indexOf('EdDSA') < 0 &&
         offDisc.userinfo_signing_alg_values_supported.indexOf('EdDSA') < 0 &&
         offDisc.token_endpoint_auth_signing_alg_values_supported
           .indexOf('EdDSA') >= 0,
         'E12. the default realm\'s discovery: no EdDSA among what it signs, ' +
         'EdDSA still among the client assertions it accepts',
         JSON.stringify(offDisc.id_token_signing_alg_values_supported));
    note(onDisc.id_token_signing_alg_values_supported.indexOf('EdDSA') >= 0,
         'E13. and the realm with it on lists EdDSA for its ID Tokens',
         JSON.stringify(onDisc.id_token_signing_alg_values_supported));
    const asked = { id_token_signed_response_alg: 'EdDSA' };
    const off = applications.clientResponseMetadataProblem(asked);
    const on = realms.run(realms.get(REALM), function () {
      return applications.clientResponseMetadataProblem(asked);
    });
    note(off && off.error === 'invalid_client_metadata' && !on,
         'E14. a registration naming EdDSA for its ID Tokens is refused by ' +
         'default and accepted with the switch on',
         JSON.stringify([off, on]));

    // ==== T. session_expiry and tenant =====================================
    const base = 'https://sts.test';
    const PERSON = 'ocd-alice';
    ldap.createUser(PERSON, { invent: false });
    applications.createApplication({ identifier: 'ocd-web',
      protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: 'ocd-web',
                oauthTokenEndpointAuthMethod: 'none',
                oauthAllowedScope: ['openid', 'profile'],
                oauthGrantType: ['password'],
                oauthRedirectUri: 'https://ocd-web.example/cb' } });
    const user = helpers.userFor(PERSON);
    const plain = claimsOf(await oauth2.idToken(base, {
      client_id: 'ocd-web', username: PERSON, user: user, scope: 'openid' }));
    note(plain.sub && plain.tenant === undefined &&
         plain.session_expiry === undefined,
         'T1. by default an ID Token carries neither tenant nor ' +
         'session_expiry', JSON.stringify(plain));
    const named = claimsOf(await oauth2.idToken(base, {
      client_id: 'ocd-web', username: PERSON, user: user, scope: 'openid',
      claims: { id_token: { tenant: null } } }));
    note(named.tenant === realms.current().id &&
         named.session_expiry === undefined,
         'T2. a claims request naming tenant puts the realm\'s id there, ' +
         'and nothing else', JSON.stringify(named));
    config.setOverride('oauth2.enterpriseClaimsAlways', true);
    const always = claimsOf(await oauth2.idToken(base, {
      client_id: 'ocd-web', username: PERSON, user: user, scope: 'openid' }));
    config.clearOverride('oauth2.enterpriseClaimsAlways');
    note(always.tenant === realms.current().id,
         'T3. oauth2.enterpriseClaimsAlways puts tenant in every ID Token',
         JSON.stringify(always));

    // ==== P. the profile scope ============================================
    const PROFILE = ['name', 'family_name', 'given_name', 'middle_name',
                     'nickname', 'preferred_username', 'profile', 'picture',
                     'website', 'gender', 'birthdate', 'zoneinfo', 'locale',
                     'updated_at'];
    const invented = claimsOf(await oauth2.idToken(base, {
      client_id: 'ocd-web', username: PERSON, user: user,
      scope: 'openid profile', scopeClaims: true }));
    const missing = PROFILE.filter(function (c) {
      return invented[c] === undefined;
    });
    note(!missing.length,
         'P1. an implicit ID Token for a person with nothing typed carries ' +
         'all fourteen profile claims in development', missing.join(', '));
    const TYPED = 'ocd-bob';
    const made = ldap.createUser(TYPED, { invent: false, attributes: {
      cn: 'Bob Typed', sn: 'Typed', givenName: 'Bob', middleName: 'Quincy',
      schacGender: '1', timeZone: 'Europe/Stockholm',
      pictureUrl: 'https://bob.example/photo.jpg',
      profileUrl: 'https://bob.example/' } });
    const typed = claimsOf(await oauth2.idToken(base, {
      client_id: 'ocd-web', username: TYPED, user: helpers.userFor(TYPED),
      scope: 'openid profile', scopeClaims: true }));
    note(made && made.ok !== false && typed.middle_name === 'Quincy' &&
         typed.gender === 'male' && typed.zoneinfo === 'Europe/Stockholm' &&
         typed.picture === 'https://bob.example/photo.jpg' &&
         typed.profile === 'https://bob.example/',
         'P2. a person\'s own five attributes answer the five claims, ' +
         'schacGender 1 as male', JSON.stringify([made, typed]));
    const scopeless = claimsOf(await oauth2.idToken(base, {
      client_id: 'ocd-web', username: TYPED, user: helpers.userFor(TYPED),
      scope: 'openid', scopeClaims: true }));
    note(scopeless.middle_name === undefined && scopeless.gender === undefined,
         'P3. and none of them without the profile scope',
         JSON.stringify(scopeless));

    realms.run(realms.get(REALM), function () {
      config.clearOverride('keys.eddsaSigning');
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
  const out = path.join(os.tmpdir(), 'ocd-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', OCD_ROOT: ROOT, OCD_OUT: out }),
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
  name: 'oidcc_conformance_defaults',
  describe: 'the defaults that pass OpenID Connect conformance (#1292): ' +
            'keys.eddsaSigning off (no OKP signing key published or ' +
            'advertised, EdDSA still accepted), session_expiry and tenant ' +
            'only when asked for, and every profile scope claim answered',
  run: run
};
