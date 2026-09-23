'use strict';
//
// File: fapi2_units.js
//
// ===========================================================================
// THE FAPI 2.0 SECURITY PROFILE (#140, 2026-09-22), in process:
//
//   A. `oauth2.fapi=2-security` is a profile of its own: not FAPI 1.0, RFC
//      9700 mode implied, and its own requirement table.
//   B. The authorization request: code only, PKCE S256 always, http only to
//      a loopback address, no FAPI 1.0 nonce or state rule.
//   C. Confidential clients by mTLS or private_key_jwt only.
//   D. Registration: response types, algorithms (EdDSA allowed), EC keys of
//      224 bits.
//   E. An iat or nbf more than 60 seconds in the future.
//   F. Refresh token rotation off, unless oauth2.refreshTokenRotation forces
//      it — and ON under FAPI 1.0, which implies RFC 9700 mode.
//   G. Codes of 60 seconds and request_uris under 600.
//   H. The ordinary consent rules (rcbj's decision on #140).
//   I. The metadata: code, PAR required, the 5.4.1 algorithms (DPoP's too).
//   J. PAR's client authentication and the assertion's string aud.
//
// `tests/vendored/sts_fapi2.js` holds it over the wire.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'fapi2_units',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

// IN A CHILD PROCESS, for `oidc_core_units.js`'s reason.
function childMain() {
  const ROOT = process.env.F2U_ROOT;
  const OUT = process.env.F2U_OUT;
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    return !!ok;
  }
  function eq(got, want, what) {
    return note(got === want, what, 'expected ' + JSON.stringify(want) +
                ', got ' + JSON.stringify(got));
  }
  function codeOf(refusal) {
    return refusal ? refusal.errorCode : null;
  }
  const main = async function () {
    require(ROOT + '/common/protocol_stack');
    const config = require(ROOT + '/common/config');
    const fapi = require(ROOT + '/oauth-oidc/fapi');
    const bcp = require(ROOT + '/oauth-oidc/oauth2_bcp');
    const senderConstraints = require(ROOT + '/oauth-oidc/sender_constraints');
    const consent = require(ROOT + '/common/consent');
    const par = require(ROOT + '/oauth-oidc/par');
    const oauth2 = require(ROOT + '/oauth-oidc/oauth2');

    const two = function (fn) {
      return fapi.withProfile('2-security', fn);
    };

    // --- A ----------------------------------------------------------------
    eq(two(function () {
      return [fapi.fapi2(), fapi.v1(), fapi.advanced(), fapi.enabled(),
              bcp.enabled()].join('/');
    }), 'true/false/false/true/true', 'A. 2-security is FAPI 2.0, not 1.0, ' +
       'and implies RFC 9700 mode');
    const view = two(function () {
      return fapi.state();
    });
    note(/FAPI 2.0 Security Profile/.test(view.specification) &&
         view.requirements.every(function (row) {
           return /^FAPI 2.0 /.test(row.section);
         }) && view.requirements.some(function (row) {
           return row.id === 'no-rotation';
         }), 'A. its report lists the FAPI 2.0 table alone',
         view.specification);

    // --- B ----------------------------------------------------------------
    const good = { redirect_uri: 'https://rp.example/cb',
                   response_type: 'code', scope: 'openid',
                   code_challenge: 'x'.repeat(43),
                   code_challenge_method: 'S256' };
    const vet = function (overrides) {
      return two(function () {
        return codeOf(fapi.authorizationRefusal(Object.assign({}, good,
                                                              overrides),
                                                { pushed: true }));
      });
    };
    eq(vet({}), null, 'B. code with PKCE, no nonce and no state, is allowed');
    eq(vet({ response_type: 'code id_token' }), 'STS-OAUTH-0582',
       'B. code id_token is refused (5.3.2.2 item 1)');
    eq(vet({ code_challenge: undefined }), 'STS-OAUTH-0573',
       'B. PKCE is required (item 5)');
    eq(vet({ redirect_uri: undefined }), 'STS-OAUTH-0574',
       'B. redirect_uri is required (item 6)');
    eq(vet({ redirect_uri: 'http://127.0.0.1:8123/cb' }), null,
       'B. http to a loopback address is allowed (item 8)');
    eq(vet({ redirect_uri: 'http://rp.example/cb' }), 'STS-OAUTH-0574',
       'B. http anywhere else is not');

    // --- C ----------------------------------------------------------------
    ['tls_client_auth', 'self_signed_tls_client_auth', 'private_key_jwt']
      .forEach(function (method) {
        eq(two(function () {
          return codeOf(fapi.clientAuthenticationRefusal(method));
        }), null, 'C. ' + method + ' is allowed');
      });
    ['none', 'client_secret_jwt', 'client_secret_basic']
      .forEach(function (method) {
        eq(two(function () {
          return codeOf(fapi.clientAuthenticationRefusal(method));
        }), 'STS-OAUTH-0580', 'C. ' + method + ' is refused');
      });

    // --- D ----------------------------------------------------------------
    const register = function (meta) {
      return two(function () {
        return codeOf(fapi.registrationRefusal(Object.assign({
          token_endpoint_auth_method: 'private_key_jwt',
          redirect_uris: ['https://rp.example/cb'],
          response_types: ['code'] }, meta)));
      });
    };
    eq(register({ id_token_signed_response_alg: 'EdDSA' }), null,
       'D. EdDSA is allowed (5.4.1)');
    eq(register({ id_token_signed_response_alg: 'RS256' }), 'STS-REG-0177',
       'D. RS256 is not');
    eq(register({ response_types: ['code id_token'] }), 'STS-REG-0178',
       'D. a response type other than code');
    eq(register({ jwks: { keys: [{ kty: 'EC', crv: 'P-256', x: 'a',
                                   y: 'b' }] } }), null,
       'D. a P-256 key is 256 bits, over 224');
    const rsa1024 = nodeCrypto.generateKeyPairSync('rsa',
      { modulusLength: 1024 }).publicKey.export({ format: 'jwk' });
    eq(register({ jwks: { keys: [rsa1024] } }), 'STS-REG-0175',
       'D. a 1024-bit RSA key is refused');
    eq(register({ redirect_uris: ['http://localhost:9000/cb'] }), null,
       'D. a loopback http redirect URI registers');

    // --- E ----------------------------------------------------------------
    const now = Math.floor(Date.now() / 1000);
    eq(two(function () {
      return codeOf(fapi.futureTimestampRefusal({ iat: now + 10,
                                                  nbf: now + 5 }, 'x', now));
    }), null, 'E. 10 seconds ahead is accepted (5.3.2.1 item 13)');
    eq(two(function () {
      return codeOf(fapi.futureTimestampRefusal({ iat: now + 61 }, 'x', now));
    }), 'STS-OAUTH-0590', 'E. 61 seconds ahead is refused');
    eq(two(function () {
      return codeOf(fapi.futureTimestampRefusal({ nbf: now + 120 }, 'x', now));
    }), 'STS-OAUTH-0590', 'E. an nbf too');
    eq(codeOf(fapi.futureTimestampRefusal({ iat: now + 120 }, 'x', now)), null,
       'E. and nothing is asked outside the profile');

    // --- F ----------------------------------------------------------------
    config.setOverride('oauth2.refreshTokenRotation', 'false');
    eq(two(function () {
      return senderConstraints.rotationRequired();
    }), false, 'F. no refresh token rotation under FAPI 2.0 (item 9)');
    config.setOverride('oauth2.refreshTokenRotation', 'true');
    eq(two(function () {
      return senderConstraints.rotationRequired();
    }), true, 'F. unless oauth2.refreshTokenRotation forces it');
    config.setOverride('oauth2.refreshTokenRotation', 'false');
    eq(fapi.withProfile('1-baseline', function () {
      return senderConstraints.rotationRequired();
    }), true, 'F. while FAPI 1.0 rotates, as the RFC 9700 mode it implies ' +
       'does');

    // --- G ----------------------------------------------------------------
    const server = new oauth2.OAuth2Server(oauth2.OAuth2Server.defaultDeps());
    eq(two(function () {
      return server.authCodeTtlMs();
    }), 60000, 'G. a code lives 60 seconds at most (item 11)');
    eq(server.authCodeTtlMs() > 60000, true,
       'G. and longer outside the profile');
    config.setOverride('oauth2.parRequestUriLifetimeS', '600');
    eq(two(function () {
      return par.lifetimeS();
    }), 599, 'G. a request_uri expires in under 600 seconds (5.3.2.2 item ' +
       '12)');

    // --- H ----------------------------------------------------------------
    config.setOverride('oauth2.consentRequired', 'false');
    eq(two(function () {
      return consent.required() + '/' + fapi.honoursGlobalConsent();
    }), 'false/true', 'H. the ordinary consent rules (rcbj, #140)');
    eq(fapi.withProfile('1-baseline', function () {
      return consent.required() + '/' + fapi.honoursGlobalConsent();
    }), 'true/false', 'H. where FAPI 1.0 keeps its own');

    // --- I ----------------------------------------------------------------
    const meta = two(function () {
      return fapi.applyToMetadata({
        response_types_supported: ['code', 'code id_token', 'id_token'],
        id_token_signing_alg_values_supported: ['RS256', 'PS256', 'ES256',
                                                'EdDSA', 'ES512'],
        dpop_signing_alg_values_supported: ['RS256', 'ES256', 'EdDSA'],
        token_endpoint_auth_methods_supported: ['none',
          'client_secret_jwt', 'private_key_jwt', 'tls_client_auth'] });
    });
    eq(JSON.stringify(meta.response_types_supported), '["code"]',
       'I. code alone');
    eq(JSON.stringify(meta.id_token_signing_alg_values_supported),
       '["PS256","ES256","EdDSA"]', 'I. the 5.4.1 algorithms');
    eq(JSON.stringify(meta.dpop_signing_alg_values_supported),
       '["ES256","EdDSA"]', 'I. DPoP\'s list too');
    eq(JSON.stringify(meta.token_endpoint_auth_methods_supported),
       '["private_key_jwt","tls_client_auth"]', 'I. the client methods');
    eq(meta.require_pushed_authorization_requests, true,
       'I. and PAR required');
    eq(meta.require_signed_request_object, undefined,
       'I. with no signed request object (that is FAPI 1.0 Advanced)');

    // --- J ----------------------------------------------------------------
    eq(two(function () {
      return codeOf(fapi.parAuthenticationRefusal(false));
    }), 'STS-OAUTH-0589', 'J. an unauthenticated push is refused (item 4)');
    eq(two(function () {
      return fapi.strictAssertionAudience();
    }), true, 'J. the assertion\'s aud is the issuer, as a string (item 8)');
  };
  main().catch(function (e) {
    note(false, 'the test itself threw', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'fapi2-units-' + process.pid +
                        '-' + Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', F2U_ROOT: ROOT, F2U_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
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
  name: 'fapi2_units',
  describe: 'The FAPI 2.0 Security Profile (#140): its requirements, ' +
            'rotation off, code and request_uri lifetimes, consent, the ' +
            'metadata and PAR\'s client authentication',
  run: run
};
