'use strict';
//
// File: fapi_baseline_units.js
//
// ===========================================================================
// FAPI 1.0 PART 1 BASELINE (#138, 2026-09-22), in process:
//
//   A. `oauth-oidc/fapi.js`'s switch: off by default, the realm's setting, a
//      named authorization server's own value (ambient) that may opt out,
//      and RFC 9700 mode implied by any profile.
//   B. The authorization request: redirect_uri sent and https, S256 PKCE for
//      every client, nonce with openid, state without it.
//   C. Item 19: one client however many ways a request names it.
//   D. Item 4: the confidential client authentication methods.
//   E. Items 4, 5, 6 and 20 at registration.
//   F. Item 21: an unbound access token lives at most 600 seconds.
//   G. The metadata: S256 only and no secret methods.
//   H. Item 12: consent is required, and a global consent is not the user's.
//   I. A named authorization server's `fapi` member: only a profile or
//      `off` may be set.
//   J. The hosted surfaces (rcbj's decision on #138): seeded as
//      private_key_jwt with no secret, and `oidc_rp.ts` signs an RFC 7523
//      assertion with a key this realm's CA issues it — issued once through a
//      claim, reused while it is good, issued again before it runs out, and
//      waited for when another process holds the claim.
//
// `tests/vendored/sts_fapi_baseline.js` holds the same rules over the wire.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'fapi_baseline_units',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

// IN A CHILD PROCESS, for `oidc_core_units.js`'s reason: requiring
// `common/protocol_stack` installs every module's instance.
function childMain() {
  const ROOT = process.env.FBU_ROOT;
  const OUT = process.env.FBU_OUT;
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
    const consent = require(ROOT + '/common/consent');
    const applications = require(ROOT + '/common/applications');
    const errorCodes = require(ROOT + '/common/error_codes');
    const authorizationServers =
      require(ROOT + '/oauth-oidc/authorization_servers');
    const oidcRp = require(ROOT + '/common/oidc_rp');

    // --- A ----------------------------------------------------------------
    config.setOverride('oauth2.rfc9700', 'false');
    eq(fapi.enabled(), false, 'A. no profile by default');
    eq(bcp.enabled(), false, 'A. and RFC 9700 mode is off with it');
    // A REALM carries the profile: the setting is restart-only for the
    // process (it decides whether the main port is HTTPS) and realm-runtime.
    const realms = require(ROOT + '/common/realms');
    const made = realms.create({ id: 'fapi-units', name: 'fapi-units',
                                 description: 'fapi_baseline_units.js',
                                 overrides: { 'oauth2.fapi': '1-baseline' } });
    if (note(made.ok, 'A. a realm may carry oauth2.fapi',
             JSON.stringify(made.errors || ''))) {
      eq(realms.run(made.realm, function () {
        return fapi.profile();
      }), '1-baseline', 'A. oauth2.fapi turns Baseline on');
      eq(realms.run(made.realm, function () {
        return bcp.enabled();
      }), true, 'A. and any profile implies RFC 9700 mode');
      eq(realms.run(made.realm, function () {
        return fapi.withProfile('off', function () {
          return fapi.enabled() + '/' + bcp.enabled();
        });
      }), 'false/false', 'A. a named server with fapi=off opts out of its ' +
         'realm\'s profile, RFC 9700 mode included');
    }
    eq(fapi.profile(), '', 'A. while the process outside the realm has none');
    eq(fapi.withProfile('1-baseline', function () {
      return fapi.profile();
    }), '1-baseline', 'A. a named server carries a profile its realm does ' +
       'not');
    eq(fapi.withProfile('', function () {
      return fapi.enabled();
    }), false, 'A. a server with no value of its own follows its realm');
    eq(fapi.withProfile('3-imaginary', function () {
      return fapi.enabled();
    }), false, 'A. a value that is not a profile is no profile');
    note(fapi.known('1-baseline') && fapi.known('off') &&
         !fapi.known('baseline'), 'A. known() accepts the profiles and off');

    const on = function (fn) {
      return fapi.withProfile('1-baseline', fn);
    };
    const good = { redirect_uri: 'https://rp.example/cb',
                   code_challenge: 'x'.repeat(43),
                   code_challenge_method: 'S256',
                   scope: 'openid', nonce: 'n-1', state: 's-1' };
    const vet = function (overrides) {
      return on(function () {
        return codeOf(fapi.authorizationRefusal(Object.assign({}, good,
                                                              overrides)));
      });
    };

    // --- B ----------------------------------------------------------------
    eq(vet({}), null, 'B. a complete request is allowed');
    eq(fapi.authorizationRefusal({}), null,
       'B. and nothing is asked with no profile');
    eq(vet({ redirect_uri: '' }), 'STS-OAUTH-0574',
       'B. redirect_uri must be sent (item 9)');
    eq(vet({ redirect_uri: 'http://127.0.0.1/cb' }), 'STS-OAUTH-0574',
       'B. and be https, the loopback included (item 20)');
    eq(vet({ code_challenge: '' }), 'STS-OAUTH-0573',
       'B. PKCE is required of every client (item 7)');
    eq(vet({ code_challenge_method: 'plain' }), 'STS-OAUTH-0573',
       'B. with S256');
    eq(vet({ nonce: '' }), 'STS-OAUTH-0575',
       'B. nonce is required with openid (5.2.2.2)');
    eq(vet({ scope: 'accounts', nonce: '', state: '' }), 'STS-OAUTH-0576',
       'B. state is required without openid (5.2.2.3)');
    eq(vet({ scope: 'accounts', nonce: '' }), null,
       'B. and a request without openid needs no nonce');

    // --- C ----------------------------------------------------------------
    eq(on(function () {
      return codeOf(fapi.clientIdentifierRefusal(['a', 'a', '']));
    }), null, 'C. one client named three ways is one client');
    eq(on(function () {
      return codeOf(fapi.clientIdentifierRefusal(['a', 'b']));
    }), 'STS-OAUTH-0581', 'C. two is invalid_client (item 19)');
    eq(codeOf(fapi.clientIdentifierRefusal(['a', 'b'])), null,
       'C. and is not asked with no profile');

    // --- D ----------------------------------------------------------------
    ['tls_client_auth', 'self_signed_tls_client_auth', 'private_key_jwt',
     'client_secret_jwt', 'none'].forEach(function (method) {
      eq(on(function () {
        return codeOf(fapi.clientAuthenticationRefusal(method));
      }), null, 'D. ' + method + ' is allowed');
    });
    ['client_secret_basic', 'client_secret_post'].forEach(function (method) {
      eq(on(function () {
        return codeOf(fapi.clientAuthenticationRefusal(method));
      }), 'STS-OAUTH-0580', 'D. ' + method + ' is refused (item 4)');
    });

    // --- E ----------------------------------------------------------------
    const rsa = function (bits) {
      return nodeCrypto.generateKeyPairSync('rsa', { modulusLength: bits })
        .publicKey.export({ format: 'jwk' });
    };
    eq(fapi.keyBits(rsa(2048)), 2048, 'E. keyBits reads an RSA modulus');
    eq(fapi.keyBits({ kty: 'EC', crv: 'P-384' }), 384,
       'E. and an EC curve');
    const register = function (meta) {
      return on(function () {
        return codeOf(fapi.registrationRefusal(meta));
      });
    };
    eq(register({ token_endpoint_auth_method: 'private_key_jwt',
                  redirect_uris: ['https://rp.example/cb'],
                  jwks: { keys: [rsa(2048)] } }), null,
       'E. a conforming registration is allowed');
    eq(register({ token_endpoint_auth_method: 'client_secret_basic' }),
       'STS-REG-0174', 'E. a secret method is refused at registration');
    eq(register({ redirect_uris: ['http://rp.example/cb'] }), 'STS-REG-0176',
       'E. an http redirect URI is refused');
    eq(register({ jwks: { keys: [rsa(1024)] } }), 'STS-REG-0175',
       'E. a 1024-bit RSA key is refused (item 5)');
    eq(fapi.registrationRefusal({ token_endpoint_auth_method:
                                    'client_secret_basic' }), null,
       'E. and nothing is refused with no profile');
    eq(on(function () {
      return codeOf(bcp.checkClientRegistration({
        token_endpoint_auth_method: 'client_secret_post',
        redirect_uris: ['https://rp.example/cb'],
        grant_types: ['authorization_code'], response_types: ['code'] }));
    }), 'STS-REG-0174',
       'E. RFC 9700 mode\'s registration check asks FAPI\'s');

    // --- F ----------------------------------------------------------------
    eq(on(function () {
      return fapi.accessTokenLifetime(3600, false);
    }), 600, 'F. an unbound access token lives 600 s at most (item 21)');
    eq(on(function () {
      return fapi.accessTokenLifetime(3600, true);
    }), 3600, 'F. a sender-constrained one as long as configured');
    eq(fapi.accessTokenLifetime(3600, false), 3600,
       'F. and nothing is capped with no profile');

    // --- G ----------------------------------------------------------------
    const meta = on(function () {
      return fapi.applyToMetadata({
        code_challenge_methods_supported: ['plain', 'S256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic',
          'client_secret_post', 'private_key_jwt', 'none'] });
    });
    eq(JSON.stringify(meta.code_challenge_methods_supported), '["S256"]',
       'G. the metadata advertises S256 only');
    eq(JSON.stringify(meta.token_endpoint_auth_methods_supported),
       '["private_key_jwt","none"]',
       'G. and no secret method');

    // --- H ----------------------------------------------------------------
    config.setOverride('oauth2.consentRequired', 'false');
    eq(consent.required(), false, 'H. consent follows the setting with no ' +
       'profile');
    eq(on(function () {
      return consent.required();
    }), true, 'H. and is required under a profile (item 12)');
    eq(on(function () {
      return fapi.honoursGlobalConsent();
    }), false, 'H. where a global consent is not the user\'s approval');

    // --- I ----------------------------------------------------------------
    authorizationServers.create({ id: 'fapi-units' });
    const bad = authorizationServers.setMember('fapi-units', 'fapi',
                                               'baseline');
    eq(errorCodes.codeOf(bad), 'STS-ADMIN-0795',
       'I. a named server\'s fapi takes only a profile or off');
    const set = authorizationServers.setMember('fapi-units', 'fapi',
                                               '1-baseline');
    note(set && set.ok !== false, 'I. and a profile is set',
         JSON.stringify(set));
    eq(authorizationServers.capabilitiesOf('fapi-units', {}, 'server').fapi,
       '1-baseline', 'I. and read back as the server\'s own');
    note(fapi.REQUIREMENTS.every(function (row, i) {
      return fapi.REQUIREMENTS.findIndex(function (other) {
        return other.id === row.id;
      }) === i && ['yes', 'inherited', 'already', 'no']
        .indexOf(row.enforced) >= 0;
    }), 'I. every requirement row has a unique id and a known enforcement');

    // --- J ----------------------------------------------------------------
    ['sts-admin-console', 'sts-user-portal'].forEach(function (id) {
      const entry = applications.clientConfigOf(id);
      if (note(!!(entry && entry.registered),
               'J. ' + id + ' is seeded', JSON.stringify(entry))) {
        eq(entry.token_endpoint_auth_method, 'private_key_jwt',
           'J. ' + id + ' authenticates by private_key_jwt');
        eq(entry.client_secret || '', '',
           'J. and holds no client secret');
      }
    });

    // A relying party over stand-ins for the registry, the CA and the claim
    // store, so the key's life can be driven without a certificate authority.
    const surface = oidcRp.SURFACES.admin;
    const fields = {};
    let issues = 0;
    let claimAnswer = { ok: true };
    let pkiFails = false;
    const generalized = function (ms) {
      return new Date(ms).toISOString().replace(/[-:T]/g, '')
        .replace(/\.\d+Z$/, 'Z');
    };
    const fakeApplications = Object.assign({}, applications, {
      get: function () {
        return { fields: Object.assign({}, fields) };
      },
      storeIssuedJwtKeyPair: function (id, record) {
        applications.issuedJwtKeyPairValues(record).forEach(function (pair) {
          fields[pair[0]] = pair[1];
        });
        return { ok: true };
      }
    });
    const issueKey = function (days) {
      issues += 1;
      const pair = nodeCrypto.generateKeyPairSync('ec',
                                                  { namedCurve: 'P-256' });
      const jwk = pair.publicKey.export({ format: 'jwk' });
      jwk.kid = 'surface-' + issues;
      return { ok: true, issued: {
        jwks: { keys: [jwk] }, certificatePem: '', chainPem: [],
        privateKeyPem: pair.privateKey.export({ type: 'pkcs8',
                                                format: 'pem' }),
        kid: jwk.kid, notAfter: Date.now() + days * 86400000,
        publicKey: pair.publicKey } };
    };
    let lastIssued = null;
    let issueDays = 365;
    const fakePki = {
      hasRoot: function () {
        return true;
      },
      ensureScope: async function () {
        return { ok: true };
      },
      issueSigningKeyPair: async function (realmId, opts) {
        if (pkiFails) {
          return { ok: false, errors: ['no certificate authority'] };
        }
        lastIssued = issueKey(issueDays);
        lastIssued.opts = opts;
        return lastIssued;
      }
    };
    const rp = new oidcRp.OidcRelyingParty(Object.assign(
      oidcRp.OidcRelyingParty.defaultDeps(), {
        applications: fakeApplications,
        loadPki: function () {
          return fakePki;
        },
        clusterClaims: {
          claim: async function () {
            return claimAnswer;
          }
        },
        audit: { audit: function () {} }
      }));
    const client = { token_endpoint_auth_method: 'private_key_jwt' };
    const authenticate = async function () {
      const form = new URLSearchParams();
      const answer = await rp.clientAuthentication(surface, client, form,
                                                   'sts.example:9443');
      return { answer: answer, form: form };
    };

    let got = await authenticate();
    note(got.answer.ok && issues === 1,
         'J. the first token request issues the surface a key',
         JSON.stringify(got.answer));
    eq(lastIssued.opts.purpose + '/' + lastIssued.opts.keyAlg +
       '/' + lastIssued.opts.identifier,
       'jwt/ec-p256/' + surface.clientId,
       'J. an RFC 7523 key, P-256, for the surface\'s own client');
    eq(fields.oauthAssertionKid, 'surface-1', 'J. and it is on the entry');
    eq(got.form.get('client_assertion_type'),
       'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
       'J. the request carries a JWT client assertion');
    eq(got.form.get('client_secret'), null, 'J. and no secret');
    eq(Object.keys(got.answer.headers || {}).length, 0,
       'J. nor a Basic header');
    const assertion = String(got.form.get('client_assertion') || '');
    const parts = assertion.split('.');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    eq(header.alg + '/' + header.kid, 'ES256/surface-1',
       'J. signed ES256 under the issued kid');
    note(nodeCrypto.verify('sha256', Buffer.from(parts[0] + '.' + parts[1]),
         { key: lastIssued.issued.publicKey, dsaEncoding: 'ieee-p1363' },
         Buffer.from(parts[2], 'base64url')),
         'J. and it verifies against the issued key');
    const scheme = config.value('global.https') ? 'https' : 'http';
    eq(claims.iss + '|' + claims.sub + '|' + claims.aud,
       surface.clientId + '|' + surface.clientId + '|' + scheme +
       '://sts.example:9443',
       'J. iss and sub are the client, aud the issuer the token endpoint ' +
       'answers as');
    note(claims.jti && claims.exp - claims.iat === 60,
         'J. with a jti and a minute to live', JSON.stringify(claims));
    eq(got.form.get('client_id'), surface.clientId,
       'J. and the body names the same client (item 19)');

    got = await authenticate();
    eq(issues, 1, 'J. a second request reuses the key');
    const second = JSON.parse(Buffer.from(String(got.form.get(
      'client_assertion')).split('.')[1], 'base64url').toString());
    note(second.jti !== claims.jti, 'J. with a fresh jti');

    fields.oauthAssertionExpiresAt = generalized(Date.now() +
                                                 10 * 86400000);
    got = await authenticate();
    eq(issues, 2, 'J. a key within 30 days of expiry is replaced');

    Object.keys(fields).forEach(function (name) {
      delete fields[name];
    });
    claimAnswer = { ok: false, reason: 'used' };
    const before = issues;
    setTimeout(function () {
      fakeApplications.storeIssuedJwtKeyPair(surface.clientId,
                                             issueKey(365).issued);
    }, 300);
    got = await authenticate();
    note(got.answer.ok && issues === before + 1 &&
         fields.oauthAssertionKid === 'surface-' + issues,
         'J. a process that loses the claim waits for the winner\'s key ' +
         'and issues none of its own', JSON.stringify(got.answer));

    Object.keys(fields).forEach(function (name) {
      delete fields[name];
    });
    claimAnswer = { ok: true };
    pkiFails = true;
    got = await authenticate();
    eq(errorCodes.codeOf(got.answer), 'STS-AUTHN-0207',
       'J. no key can be issued: the token request is not made');

    got = { answer: await rp.clientAuthentication(surface,
      { token_endpoint_auth_method: 'client_secret_jwt' },
      new URLSearchParams(), 'sts.example') };
    eq(errorCodes.codeOf(got.answer), 'STS-AUTHN-0209',
       'J. a method the surface does not implement is refused by name');
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
  const out = path.join(os.tmpdir(), 'fapi-baseline-units-' + process.pid +
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
                         { LOG_LEVEL: 'fatal', FBU_ROOT: ROOT, FBU_OUT: out }),
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
  name: 'fapi_baseline_units',
  describe: 'FAPI 1.0 Baseline (#138): the switch and its per-server value, ' +
            'the authorization, client and registration rules, the token ' +
            'lifetime cap, consent, and the hosted surfaces\' ' +
            'private_key_jwt key',
  run: run
};
