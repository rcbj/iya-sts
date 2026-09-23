'use strict';
//
// File: fapi_advanced_units.js
//
// ===========================================================================
// FAPI 1.0 PART 2 ADVANCED AND JARM (#139, #143, 2026-09-22), in process:
//
//   A. `fapi.js` under `1-advanced`: Baseline's rules still apply, with
//      PKCE relaxed to pushed requests; the response types; the client
//      methods and no public client; the registration's response types,
//      algorithms and RSA1_5; the metadata narrowing; the request object's
//      exp, nbf and aud; the sender constraint with and without
//      `oauth2.fapiRequireMtls`; the PS256 default and the 8.6 list.
//   B. `helpers.signJwt()` with an algorithm, and `verifyOwnJws()` /
//      `verifyOwnCompactJws()` verifying this realm's own PS256, ES256 and
//      EdDSA tokens — and refusing an HMAC one keyed by the public key.
//   C. `jarm.ts`: the transports, the query.jwt rule, the registration
//      grammar, a signed response verified against this realm's key, one
//      encrypted to a client's key and opened, and PS256 under Advanced.
//   D. The access-token algorithm: the setting, a named server's own member
//      (and its refusal), and FAPI's default.
//
// `tests/vendored/sts_fapi_advanced.js` holds it over the wire.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'fapi_advanced_units',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

// IN A CHILD PROCESS, for `oidc_core_units.js`'s reason: requiring
// `common/protocol_stack` installs every module's instance.
function childMain() {
  const ROOT = process.env.FAU_ROOT;
  const OUT = process.env.FAU_OUT;
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
  function decode(jwt) {
    const parts = String(jwt).split('.');
    return { header: JSON.parse(Buffer.from(parts[0], 'base64url')
                                  .toString('utf8')),
             claims: JSON.parse(Buffer.from(parts[1], 'base64url')
                                  .toString('utf8')) };
  }
  const main = async function () {
    require(ROOT + '/common/protocol_stack');
    const config = require(ROOT + '/common/config');
    const fapi = require(ROOT + '/oauth-oidc/fapi');
    const bcp = require(ROOT + '/oauth-oidc/oauth2_bcp');
    const jarm = require(ROOT + '/oauth-oidc/jarm');
    const helpers = require(ROOT + '/common/helpers');
    const stsCrypto = require(ROOT + '/common/crypto');
    const applications = require(ROOT + '/common/applications');
    const errorCodes = require(ROOT + '/common/error_codes');
    const authorizationServers =
      require(ROOT + '/oauth-oidc/authorization_servers');
    const oauth2 = require(ROOT + '/oauth-oidc/oauth2');

    const adv = function (fn) {
      return fapi.withProfile('1-advanced', fn);
    };
    const good = { redirect_uri: 'https://rp.example/cb',
                   response_type: 'code id_token', scope: 'openid',
                   nonce: 'n-1', state: 's-1' };
    const vet = function (overrides, ctx) {
      return adv(function () {
        return codeOf(fapi.authorizationRefusal(Object.assign({}, good,
                                                              overrides),
                                                ctx));
      });
    };

    // --- A ----------------------------------------------------------------
    eq(adv(function () {
      return fapi.advanced() + '/' + fapi.enabled() + '/' + bcp.enabled();
    }), 'true/true/true', 'A. 1-advanced is a profile, and implies RFC 9700 ' +
       'mode');
    eq(fapi.withProfile('1-baseline', function () {
      return fapi.advanced();
    }), false, 'A. Baseline is not Advanced');
    eq(vet({}), null, 'A. code id_token without PKCE is allowed when not ' +
       'pushed (Part 2 5.2.2, item 7 exempted)');
    eq(vet({}, { pushed: true }), 'STS-OAUTH-0573',
       'A. a pushed request needs PKCE (item 18)');
    eq(vet({ code_challenge: 'x'.repeat(43), code_challenge_method: 'plain' }),
       'STS-OAUTH-0573', 'A. a challenge that is sent is held to S256');
    eq(vet({ response_type: 'code' }), 'STS-OAUTH-0582',
       'A. code without JARM is refused (item 2)');
    eq(vet({ response_type: 'code', response_mode: 'jwt' }), null,
       'A. code with response_mode=jwt is allowed');
    eq(vet({ response_type: 'id_token code' }), null,
       'A. code id_token in either order');
    eq(vet({ response_type: 'code id_token token' }), 'STS-OAUTH-0582',
       'A. a response type carrying a token is refused');
    eq(vet({ nonce: '' }), 'STS-OAUTH-0575',
       'A. Baseline\'s nonce rule still applies');
    eq(vet({ redirect_uri: 'http://rp.example/cb' }), 'STS-OAUTH-0574',
       'A. and the https redirect rule');
    ['tls_client_auth', 'self_signed_tls_client_auth', 'private_key_jwt']
      .forEach(function (method) {
        eq(adv(function () {
          return codeOf(fapi.clientAuthenticationRefusal(method));
        }), null, 'A. ' + method + ' is allowed');
      });
    ['client_secret_jwt', 'client_secret_basic', 'none']
      .forEach(function (method) {
        eq(adv(function () {
          return codeOf(fapi.clientAuthenticationRefusal(method));
        }), 'STS-OAUTH-0580', 'A. ' + method + ' is refused (items 14, 16)');
      });
    eq(fapi.withProfile('1-baseline', function () {
      return codeOf(fapi.clientAuthenticationRefusal('client_secret_jwt'));
    }), null, 'A. while Baseline still takes client_secret_jwt');
    const register = function (meta) {
      return adv(function () {
        return codeOf(fapi.registrationRefusal(Object.assign({
          token_endpoint_auth_method: 'private_key_jwt',
          redirect_uris: ['https://rp.example/cb'] }, meta)));
      });
    };
    eq(register({ response_types: ['code', 'code id_token'],
                  id_token_signed_response_alg: 'PS256' }), null,
       'A. a conforming registration is allowed');
    eq(register({ token_endpoint_auth_method: 'none' }), 'STS-REG-0174',
       'A. a public client is refused at registration');
    eq(register({ response_types: ['code token'] }), 'STS-REG-0178',
       'A. a response type Advanced does not allow');
    eq(register({ id_token_signed_response_alg: 'RS256' }), 'STS-REG-0177',
       'A. an RS256 ID Token (8.6)');
    eq(register({ authorization_signed_response_alg: 'ES512' }),
       'STS-REG-0177', 'A. an ES512 JARM response');
    eq(register({ id_token_encrypted_response_alg: 'RSA1_5' }),
       'STS-REG-0177', 'A. RSA1_5 (8.6.1)');
    const meta = adv(function () {
      return fapi.applyToMetadata({
        response_types_supported: ['code', 'code id_token', 'token',
                                   'code id_token token'],
        id_token_signing_alg_values_supported: ['RS256', 'PS256', 'ES256',
                                                'EdDSA'],
        request_object_encryption_alg_values_supported: ['RSA1_5',
                                                         'RSA-OAEP'],
        token_endpoint_auth_methods_supported: ['client_secret_jwt',
          'private_key_jwt', 'tls_client_auth', 'none'] });
    });
    eq(JSON.stringify(meta.response_types_supported),
       '["code","code id_token"]', 'A. the metadata\'s response types');
    eq(JSON.stringify(meta.id_token_signing_alg_values_supported),
       '["PS256","ES256"]', 'A. its signing algorithms');
    eq(JSON.stringify(meta.request_object_encryption_alg_values_supported),
       '["RSA-OAEP"]', 'A. no RSA1_5');
    eq(JSON.stringify(meta.token_endpoint_auth_methods_supported),
       '["private_key_jwt","tls_client_auth"]', 'A. its client methods');
    eq(meta.require_signed_request_object, true,
       'A. and a signed request object is required');
    const now = Math.floor(Date.now() / 1000);
    const iss = 'https://as.example';
    const obj = function (claims) {
      return adv(function () {
        return codeOf(fapi.requestObjectRefusal(Object.assign({
          aud: iss, nbf: now, exp: now + 300 }, claims), iss, now));
      });
    };
    eq(obj({}), null, 'A. a request object with exp, nbf and aud is allowed');
    eq(obj({ nbf: undefined }), 'STS-OAUTH-0584', 'A. no nbf (item 17)');
    eq(obj({ exp: undefined }), 'STS-OAUTH-0584', 'A. no exp (item 13)');
    eq(obj({ exp: now + 3601 }), 'STS-OAUTH-0584',
       'A. exp more than 60 minutes after nbf');
    eq(obj({ nbf: now - 3601, exp: now + 60 }), 'STS-OAUTH-0584',
       'A. nbf more than 60 minutes old');
    eq(obj({ aud: 'https://other.example' }), 'STS-OAUTH-0585',
       'A. an aud that is not the issuer (item 15)');
    eq(obj({ aud: ['https://other.example', iss] }), null,
       'A. an aud array containing the issuer');
    eq(adv(function () {
      return codeOf(fapi.senderConstraintRefusal({}));
    }), 'STS-OAUTH-0583', 'A. an unbound token is refused (item 5)');
    eq(adv(function () {
      return codeOf(fapi.senderConstraintRefusal({ dpop: true }));
    }), null, 'A. DPoP satisfies it by default (rcbj, #139)');
    config.setOverride('oauth2.fapiRequireMtls', 'true');
    eq(adv(function () {
      return codeOf(fapi.senderConstraintRefusal({ dpop: true }));
    }), 'STS-OAUTH-0583', 'A. not with oauth2.fapiRequireMtls on');
    eq(adv(function () {
      return codeOf(fapi.senderConstraintRefusal({ mtls: true }));
    }), null, 'A. where a client certificate does');
    config.setOverride('oauth2.fapiRequireMtls', 'false');
    eq(fapi.defaultSigningAlg(), '', 'A. no default algorithm with no profile');
    eq(adv(function () {
      return fapi.defaultSigningAlg();
    }), 'PS256', 'A. PS256 under Advanced (8.6)');
    eq(adv(function () {
      return codeOf(fapi.signingAlgRefusal('RS256', 'x'));
    }), 'STS-OAUTH-0586', 'A. RS256 from a client is refused');
    eq(adv(function () {
      return codeOf(fapi.signingAlgRefusal('ES256', 'x'));
    }), null, 'A. ES256 is not');
    const view = adv(function () {
      return fapi.state();
    });
    note(view.requirements.some(function (row) {
      return row.id === 'pkce-s256' && row.enforced === 'relaxed';
    }) && view.requirements.some(function (row) {
      return row.id === 'sender-constrained';
    }), 'A. the report lists Advanced\'s rows and Baseline\'s PKCE as relaxed');

    // --- B ----------------------------------------------------------------
    ['PS256', 'ES256', 'EdDSA', 'RS256'].forEach(function (alg) {
      const token = helpers.signJwt({ iss: iss, sub: 'b', jti: 'b-' + alg,
        iat: now, exp: now + 60 }, {}, { algorithm: alg });
      eq(decode(token).header.alg, alg, 'B. signJwt signs ' + alg);
      let claims = null;
      try {
        claims = helpers.verifyOwnJws(token);
      } catch (e) {
        claims = { error: e.message };
      }
      eq(claims && claims.sub, 'b', 'B. verifyOwnJws verifies it ' +
         JSON.stringify(claims && claims.error || ''));
      let compact = null;
      try {
        compact = helpers.verifyOwnCompactJws(token, { algorithms: [alg] });
      } catch (e) {
        compact = { error: e.message };
      }
      note(compact && compact.claims && compact.claims.sub === 'b',
           'B. verifyOwnCompactJws verifies ' + alg, JSON.stringify(compact));
    });
    let forged = null;
    try {
      const rsaPub = helpers.ownRsaCertificates('jose')[0].certPem;
      const hs = stsCrypto.signJws({ sub: 'x', iat: now, exp: now + 60 },
        Buffer.from(rsaPub), { algorithm: 'HS256' });
      forged = helpers.verifyOwnJws(hs);
    } catch (e) {
      forged = null;
    }
    eq(forged, null, 'B. an HS256 token keyed by the public certificate is ' +
       'refused (RFC 8725 section 3.1)');

    // --- C ----------------------------------------------------------------
    eq(jarm.transportOf('jwt', 'code'), 'query', 'C. jwt is a query for code');
    eq(jarm.transportOf('jwt', 'code id_token'), 'fragment',
       'C. and a fragment for anything else');
    eq(jarm.transportOf('form_post.jwt', 'code'), 'form_post',
       'C. form_post.jwt is a POST');
    eq(codeOf(jarm.modeProblem('query.jwt', 'code id_token', {})),
       'STS-OAUTH-0587', 'C. query.jwt with an id_token in clear is refused');
    eq(jarm.modeProblem('query.jwt', 'code', {}), null,
       'C. query.jwt with code alone is not');
    eq(codeOf(applications.jarmMetadataProblem({
      authorization_signed_response_alg: 'none' })), 'STS-REG-0179',
       'C. none is not a JARM algorithm (section 3)');
    eq(codeOf(applications.jarmMetadataProblem({
      authorization_encrypted_response_enc: 'A256GCM' })), 'STS-REG-0179',
       'C. an enc without an alg');
    const signed = await jarm.respond({ code: 'c-1', state: 's-1',
                                         iss: iss },
                                       { clientId: 'client-c', issuer: iss,
                                         registered: {} });
    const decoded = decode(signed);
    eq(decoded.header.alg, 'RS256', 'C. RS256 by default (JARM section 3)');
    let opened = null;
    try {
      opened = helpers.verifyOwnJws(signed);
    } catch (e) {
      opened = { error: e.message };
    }
    note(opened && opened.code === 'c-1' && opened.state === 's-1' &&
         opened.aud === 'client-c' && opened.iss === iss &&
         opened.exp - opened.iat <= 600 && opened.exp > now,
         'C. a response carries code, state, iss, aud and exp, and ' +
         'verifies against this realm\'s key', JSON.stringify(opened));
    const pair = nodeCrypto.generateKeyPairSync('rsa',
                                                { modulusLength: 2048 });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    jwk.kid = 'enc-c';
    jwk.use = 'enc';
    const encrypted = await jarm.respond({ code: 'c-2', state: 's-2' },
      { clientId: 'client-c', issuer: iss, registered: {
        authorization_encrypted_response_alg: 'RSA-OAEP-256',
        jwks: { keys: [jwk] } } });
    eq(String(encrypted).split('.').length, 5,
       'C. with encryption registered the response is a JWE');
    let inner = null;
    try {
      inner = stsCrypto.decryptJweCompact(encrypted, {
        privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'pem' })
      }).plaintext.toString('utf8');
    } catch (e) {
      inner = 'error: ' + e.message;
    }
    note(/\./.test(String(inner)) && decode(inner).claims.code === 'c-2',
         'C. which opens to the signed response', String(inner).slice(0, 80));
    const advSigned = await adv(function () {
      return jarm.respond({ code: 'c-3' }, { clientId: 'client-c',
                                           issuer: iss, registered: {} });
    });
    eq(decode(advSigned).header.alg, 'PS256',
       'C. PS256 under FAPI 1.0 Advanced');
    let refused = null;
    try {
      await adv(function () {
        return jarm.respond({ code: 'c-4' }, { clientId: 'client-c',
          issuer: iss,
          registered: { authorization_signed_response_alg: 'RS256' } });
      });
    } catch (e) {
      refused = e;
    }
    eq(errorCodes.codeOf(refused), 'STS-OAUTH-0588',
       'C. and a registered RS256 cannot be honoured there');

    // --- D ----------------------------------------------------------------
    const server = new oauth2.OAuth2Server(oauth2.OAuth2Server.defaultDeps());
    eq(server.accessTokenAlg(), 'RS256', 'D. RS256 by default');
    config.setOverride('oauth2.accessTokenSigningAlg', 'ES256');
    eq(server.accessTokenAlg(), 'ES256', 'D. the setting chooses');
    eq(adv(function () {
      return server.accessTokenAlg();
    }), 'ES256', 'D. an allowed choice holds under Advanced');
    config.setOverride('oauth2.accessTokenSigningAlg', 'RS256');
    eq(adv(function () {
      return server.accessTokenAlg();
    }), 'PS256', 'D. a disallowed one is replaced by PS256');
    config.setOverride('oauth2.accessTokenSigningAlg', 'default');
    eq(adv(function () {
      return server.accessTokenAlg();
    }), 'PS256', 'D. default is PS256 under Advanced');
    authorizationServers.create({ id: 'alg-units' });
    eq(errorCodes.codeOf(authorizationServers.setMember('alg-units',
         'access_token_signing_alg', 'HS256')), 'STS-ADMIN-0799',
       'D. a named server\'s member refuses an algorithm it cannot use');
    authorizationServers.setMember('alg-units', 'access_token_signing_alg',
                                   'EdDSA');
    eq(server.accessTokenAlg({ __asProfile: 'alg-units' }), 'EdDSA',
       'D. and its own value wins for its requests');
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
  const out = path.join(os.tmpdir(), 'fapi-advanced-units-' + process.pid +
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
                         { LOG_LEVEL: 'fatal', FAU_ROOT: ROOT, FAU_OUT: out }),
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
  name: 'fapi_advanced_units',
  describe: 'FAPI 1.0 Advanced and JARM (#139, #143): the profile\'s ' +
            'rules, own-token signing and verification by algorithm, the ' +
            'JWT-secured authorization response, and the access-token ' +
            'algorithm',
  run: run
};
