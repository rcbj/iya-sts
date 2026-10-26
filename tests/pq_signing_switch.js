// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pq_signing_switch.js
//
// ===========================================================================
// POST-QUANTUM JOSE SIGNING AS A PER-REALM SWITCH (2026-10-23, rcbj):
// `keys.postQuantumSigning`, on by default. The row in `common/config.js`
// says what it does and does not change; the conformance jobs' `-cl` twins
// (`tests/CLAUDE.md`, *The classical twins*) are what it exists for. Held:
//
//   A. THE ROW AND THE LIBRARY, in this process: a bool, on by default,
//      runtime and not per-process (so a realm carries it), in the Key
//      material group; `helpers.offeredJwsAlgs()`, `withoutPqSigningAlgs()`
//      and `withoutPqSigningKeys()` with it on (untouched) and off (no
//      post-quantum algorithm or signing key, the ML-KEM `use: "enc"` key
//      kept, a COSE integer kept, a list that held only post-quantum
//      algorithms left out, and the input's nested objects NOT edited);
//      an ML-DSA-44 JWS verifying with it on and refused with it off, marked
//      STS-KEYS-0157 and never with the code in its message; and
//      `signingKeyFor('ML-DSA-44')` refused with it off, STS-KEYS-0158.
//   B. THE WHOLE PATH, IN A CHILD PROCESS on an ephemeral port, the default
//      realm (on) beside a realm that turned it off: the JWKS carries AKP
//      signing keys in the one and none in the other; the RFC 8414 document,
//      OpenID Connect Discovery and the OpenID4VCI issuer metadata list
//      post-quantum algorithms in the one and none in any algorithm list of
//      the other; a registration naming ML-DSA-44 as its ID Token algorithm
//      passes the check in the one and is refused in the other.
//
// **B IS IN A CHILD** for `tests/jose_kid.js`'s reason: loading the whole
// protocol stack into `run.js`'s one process changes what later files see.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'pq_signing_switch_test',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SETTING = 'keys.postQuantumSigning';

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.PQSW_ROOT;
  const OUT = process.env.PQSW_OUT;
  const fs = require('fs');
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
        const chunks = [];
        res.on('data', function (c) {
          chunks.push(c);
        });
        res.on('error', reject);
        res.on('end', function () {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            // The caller asserts on the status; the reason travels on the
            // body, because this runs in a `node -e` child with no logger.
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
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const stsCrypto = require(ROOT_DIR + '/common/crypto');
    const applications = require(ROOT_DIR + '/common/applications');

    // Every `member:alg` of a document whose algorithm list names a
    // post-quantum JWS algorithm, at any depth.
    const pqListed = function (doc) {
      const out = [];
      const walk = function (name, value) {
        if (Array.isArray(value)) {
          value.forEach(function (one) {
            if (/(?:^|_)alg_values(?:_supported)?$/.test(name) &&
                typeof one === 'string' && stsCrypto.isPqJwsAlg(one)) {
              out.push(name + ':' + one);
            } else {
              walk('', one);
            }
          });
        } else if (value && typeof value === 'object') {
          Object.keys(value).forEach(function (key) {
            walk(key, value[key]);
          });
        }
      };
      walk('', doc);
      return out;
    };
    const akpSigning = function (keys) {
      return (keys || []).filter(function (k) {
        return k.kty === 'AKP' && k.use !== 'enc';
      });
    };

    const REALM = 'pqswrealm';
    realms.create({ id: REALM });
    realms.run(realms.get(REALM), function () {
      config.setOverride('keys.postQuantumSigning', false);
    });
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const prefix = '/realm/' + REALM;

    // ---- the JWKS --------------------------------------------------------
    let on = await get(port, '/oauth2/jwks');
    let off = await get(port, prefix + '/oauth2/jwks');
    note(on.status === 200 && akpSigning(on.json.keys).length > 0,
         'B1. the default realm\'s JWKS carries post-quantum signing keys ' +
         '(kty AKP)', on.status + ' ' + akpSigning(on.json.keys).length);
    note(off.status === 200 && (off.json.keys || []).length > 0 &&
         akpSigning(off.json.keys).length === 0,
         'B2. a realm with keys.postQuantumSigning off publishes none, and ' +
         'still publishes its classical keys',
         off.status + ' ' + JSON.stringify((off.json.keys || [])
           .map(function (k) {
             return k.kty + '/' + (k.alg || '') + '/' + (k.use || '');
           })));
    note(off.json.keys && off.json.keys[0] && off.json.keys[0].kty === 'RSA',
         'B3. and its RSA key is still first',
         off.json.keys && off.json.keys[0] && off.json.keys[0].kty);

    // ---- the metadata documents ------------------------------------------
    const documents = [
      ['RFC 8414', '/.well-known/oauth-authorization-server'],
      ['OpenID Connect Discovery', '/.well-known/openid-configuration'],
      ['OpenID4VCI issuer metadata', '/.well-known/openid-credential-issuer']
    ];
    for (let i = 0; i < documents.length; i++) {
      on = await get(port, documents[i][1]);
      off = await get(port, prefix + documents[i][1]);
      note(on.status === 200 && pqListed(on.json).length > 0,
           'B4.' + (i + 1) + '. the default realm\'s ' + documents[i][0] +
           ' lists post-quantum algorithms', on.status + ' ' +
           pqListed(on.json).slice(0, 4).join(', '));
      note(off.status === 200 && pqListed(off.json).length === 0,
           'B5.' + (i + 1) + '. the realm\'s ' + documents[i][0] + ' lists ' +
           'none in any algorithm list', off.status + ' ' +
           pqListed(off.json).slice(0, 4).join(', '));
    }
    off = await get(port, prefix + '/.well-known/openid-configuration');
    note(off.json && Array.isArray(off.json
      .id_token_signing_alg_values_supported) &&
         off.json.id_token_signing_alg_values_supported.indexOf('RS256') >= 0,
         'B6. and its lists keep the classical algorithms',
         off.json && JSON.stringify(off.json
           .id_token_signing_alg_values_supported));

    // ---- a registration naming one ---------------------------------------
    const asked = { id_token_signed_response_alg: 'ML-DSA-44' };
    note(!applications.clientResponseMetadataProblem(asked),
         'B7. the default realm accepts a registration naming ML-DSA-44 ' +
         'for its ID Tokens');
    const refused = realms.run(realms.get(REALM), function () {
      return applications.clientResponseMetadataProblem(asked);
    });
    note(refused && refused.error === 'invalid_client_metadata',
         'B8. the realm refuses it as an algorithm it does not sign with',
         JSON.stringify(refused));

    realms.run(realms.get(REALM), function () {
      config.clearOverride('keys.postQuantumSigning');
    });
    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw', detail: e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function libraryChecks(t) {
  log.debug("Entering libraryChecks().");
  const config = require('../common/config');
  const stsCrypto = require('../common/crypto');
  const helpers = require('../common/helpers');
  const errorCodes = require('../common/error_codes');
  const pqJose = require('../common/pq_jose');

  const row = config.SETTINGS.filter(function (one) {
    return one.key === SETTING;
  })[0] || {};
  t.equal(JSON.stringify({ type: row.type, dflt: row.dflt,
                           runtime: row.runtime, group: row.group,
                           perProcess: !!row.perProcess }),
          JSON.stringify({ type: 'bool', dflt: true, runtime: true,
                           group: 'Key material', perProcess: false }),
          'keys.postQuantumSigning is a bool, on by default, runtime and ' +
          'not per-process, in the Key material group');

  const doc = {
    id_token_signing_alg_values_supported: ['RS256', 'ML-DSA-44',
                                             'SLH-DSA-SHA2-128s'],
    only_pq_alg_values_supported: ['ML-DSA-65-ES256'],
    response_types_supported: ['code'],
    nested: { 'kb-jwt_alg_values': ['ES256', 'ML-DSA-87'],
              proof: { proof_signing_alg_values_supported: ['EdDSA',
                                                            'ML-DSA-44'] },
              cose_alg_values_supported: [-7, -48] },
    vp: [{ alg_values: ['PS256', 'ML-DSA-44-Ed25519'] }]
  };
  const before = JSON.stringify(doc);
  const nested = doc.nested;
  const jwks = [{ kty: 'RSA', use: 'sig', kid: 'r' },
                { kty: 'AKP', alg: 'ML-DSA-44', use: 'sig', kid: 'p' },
                { kty: 'AKP', alg: 'ML-DSA-65-ES256', kid: 'c' },
                { kty: 'AKP', alg: 'ML-KEM-768', use: 'enc', kid: 'k' },
                { kty: 'EC', crv: 'P-256', use: 'sig', kid: 'e' }];
  try {
    t.check(helpers.offeredJwsAlgs().indexOf('ML-DSA-44') >= 0 &&
            helpers.withoutPqSigningAlgs(doc) === doc &&
            JSON.stringify(doc) === before &&
            helpers.withoutPqSigningKeys(jwks).length === jwks.length,
            'with it on (the default), every list, document and key set is ' +
            'untouched', JSON.stringify(doc));
    const token = (function () {
      const pair = pqJose.generate('ML-DSA-44');
      return { jws: stsCrypto.signJws({ sub: 'pqsw', iat: 1 }, pair.priv,
                                      { algorithm: 'ML-DSA-44' }),
               jwk: pqJose.akpPublicJwk('ML-DSA-44', pair.pub) };
    })();
    let verified = null;
    try {
      verified = stsCrypto.verifyCompactJws(token.jws, token.jwk,
                                            { algorithms: ['ML-DSA-44'] });
    } catch (e) {
      log.debug("Caught in libraryChecks(): " + ((e && e.message) || e));
      verified = null;
    }
    t.check(verified && verified.claims && verified.claims.sub === 'pqsw',
            'an ML-DSA-44 JWS verifies with it on', verified);

    config.setOverride(SETTING, false);
    const offered = helpers.offeredJwsAlgs();
    t.check(offered.indexOf('RS256') >= 0 && offered.indexOf('ES256') >= 0 &&
            !offered.some(function (alg) {
              return stsCrypto.isPqJwsAlg(alg);
            }),
            'with it off, offeredJwsAlgs() keeps the classical algorithms ' +
            'and no post-quantum one', offered.join(', '));
    helpers.withoutPqSigningAlgs(doc);
    t.equal(JSON.stringify(doc), JSON.stringify({
      id_token_signing_alg_values_supported: ['RS256'],
      response_types_supported: ['code'],
      nested: { 'kb-jwt_alg_values': ['ES256'],
                proof: { proof_signing_alg_values_supported: ['EdDSA'] },
                cose_alg_values_supported: [-7, -48] },
      vp: [{ alg_values: ['PS256'] }]
    }), 'and withoutPqSigningAlgs() narrows every algorithm list at any ' +
        'depth, keeps a COSE integer and every other member, and leaves out ' +
        'a list that held only post-quantum algorithms');
    t.equal(JSON.stringify(nested['kb-jwt_alg_values']),
            JSON.stringify(['ES256', 'ML-DSA-87']),
            'without editing the nested objects it was given');
    t.equal(helpers.withoutPqSigningKeys(jwks).map(function (k) {
      return k.kid;
    }).join(','), 'r,k,e',
            'withoutPqSigningKeys() drops the ML-DSA and composite keys and ' +
            'keeps the RSA, EC and ML-KEM (use: enc) ones');

    let refusal = null;
    try {
      stsCrypto.verifyCompactJws(token.jws, token.jwk,
                                 { algorithms: ['ML-DSA-44'] });
    } catch (e) {
      log.debug("Caught in libraryChecks(): " + ((e && e.message) || e));
      refusal = e;
    }
    t.check(refusal && errorCodes.codeOf(refusal) === 'STS-KEYS-0157' &&
            !/STS-/.test(String(refusal.message)),
            'and the same ML-DSA-44 JWS is refused at verification, marked ' +
            'STS-KEYS-0157 with no code in its message',
            refusal ? errorCodes.codeOf(refusal) + ' ' + refusal.message
                    : 'it verified');
    let unsigned = null;
    try {
      helpers.signingKeyFor('ML-DSA-44');
    } catch (e) {
      log.debug("Caught in libraryChecks(): " + ((e && e.message) || e));
      unsigned = e;
    }
    t.check(unsigned && errorCodes.codeOf(unsigned) === 'STS-KEYS-0158',
            'and signingKeyFor(\'ML-DSA-44\') is refused, STS-KEYS-0158, ' +
            'rather than signing with a key the realm no longer publishes',
            unsigned ? unsigned.message : 'a key was answered');
  } finally {
    config.clearOverride(SETTING);
  }
  log.debug("Leaving libraryChecks().");
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== A. the row and the library ===');
  libraryChecks(t);

  t.log.info('=== B. the whole path, in a child process ===');
  const out = path.join(os.tmpdir(), 'pqsw-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', PQSW_ROOT: ROOT,
                           PQSW_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
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
  name: 'pq_signing_switch',
  describe: 'keys.postQuantumSigning, per realm and on by default: off, no ' +
            'post-quantum signing key in the JWKS, no post-quantum algorithm ' +
            'in any metadata list, a post-quantum JWS refused at ' +
            'verification and its signature refused at signing',
  run: run
};
