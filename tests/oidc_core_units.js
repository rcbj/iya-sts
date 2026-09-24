'use strict';
//
// File: oidc_core_units.js
//
// ===========================================================================
// THE PURE HALVES OF #118 (OpenID Connect Core, 2026-09-22), in process:
//
//   A. `common/crypto.js`'s idTokenHashFor() / idTokenHalfHash(): the hash of
//      every algorithm in the table, and this service's choice where Core is
//      silent — checked against node's own digests, not against itself.
//   B. `applications.oidcSubjectMetadataProblem()`: subject_type,
//      sector_identifier_uri and token_endpoint_auth_signing_alg.
//   C. `step_up.ts`'s essentialAcrValuesOf(): only an ESSENTIAL acr is a
//      requirement.
//   D. `oauth2.ts`'s usesFragment(): the default response mode, for a success
//      and an error alike.
//   E. The hosted surfaces and `offline_access`: `applications.js`'s
//      HOSTED_SURFACE_CLIENT_IDS is `oidc_rp.ts`'s SURFACES, and every
//      surface asks for the scope its session outliving the sign-on session
//      depends on (Core section 11).
//   F. GNAP's `id_token` subject assertion recognises an ID Token by what it
//      carries now — no `typ` member — and still refuses an access token.
//   G. The token register files an ID Token as `id_token` from the kind its
//      issuer states, since the token names none, and ignores a kind it
//      does not know.
//
// `sts_oidc_core.js` holds the same behaviours over the wire; this is what
// a mistake in one of these functions looks like with nothing else in the way.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'oidc_core_units',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

// IN A CHILD PROCESS, because requiring `common/protocol_stack` installs every
// module's instance, and a second stack in the runner's own process would
// find slots already filled by whichever file ran first (the arrangement
// `account_disable.js` and the other stack-loading files use).
function childMain() {
  const ROOT = process.env.OCU_ROOT;
  const OUT = process.env.OCU_OUT;
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
  try {
    require(ROOT + '/common/protocol_stack');
    const stsCrypto = require(ROOT + '/common/crypto');
    const applications = require(ROOT + '/common/applications');
    const stepUp = require(ROOT + '/oauth-oidc/step_up');
    const oauth2 = require(ROOT + '/oauth-oidc/oauth2');
    const oidcRp = require(ROOT + '/common/oidc_rp');

    // --- A ----------------------------------------------------------------
    const half = function (value, name, length) {
      const digest = (length
        ? nodeCrypto.createHash(name, { outputLength: length })
        : nodeCrypto.createHash(name)).update(value, 'ascii').digest();
      return digest.subarray(0, digest.length / 2).toString('base64url');
    };
    const expected = {
      RS256: ['sha256'], RS384: ['sha384'], RS512: ['sha512'],
      PS256: ['sha256'], PS384: ['sha384'], PS512: ['sha512'],
      ES256: ['sha256'], ES384: ['sha384'], ES512: ['sha512'],
      ES256K: ['sha256'], HS256: ['sha256'], HS384: ['sha384'],
      HS512: ['sha512'], EdDSA: ['sha512'],
      'ML-DSA-44': ['sha256'], 'ML-DSA-65': ['sha384'],
      'ML-DSA-87': ['sha512'], 'SLH-DSA-SHA2-128s': ['sha256'],
      'SLH-DSA-SHAKE-128s': ['sha256'], 'ML-DSA-44-ES256': ['sha256'],
      'ML-DSA-65-ES256': ['sha256'], 'ML-DSA-87-ES384': ['sha384'],
      'ML-DSA-44-Ed25519': ['sha512'], 'ML-DSA-65-Ed25519': ['sha512'],
      'ML-DSA-87-Ed448': ['shake256', 114]
    };
    note(Object.keys(expected).length === stsCrypto.JWS_SIGNING_ALGS.length &&
         stsCrypto.JWS_SIGNING_ALGS.every(function (alg) {
           return !!expected[alg];
         }),
         'A. every signing algorithm in the table has a stated hash ' +
         'here — a new algorithm has to be given one on purpose',
         JSON.stringify(stsCrypto.JWS_SIGNING_ALGS.filter(function (alg) {
           return !expected[alg];
         })));
    Object.keys(expected).forEach(function (alg) {
      const want = half('the-token-value', expected[alg][0], expected[alg][1]);
      eq(stsCrypto.idTokenHalfHash('the-token-value', alg), want,
         'A. ' + alg + ' hashes with ' + expected[alg][0] +
         (expected[alg][1] ? '/' + expected[alg][1] : ''));
    });

    // --- B ----------------------------------------------------------------
    const problem = function (meta) {
      const p = applications.oidcSubjectMetadataProblem(meta);
      return p ? p.description : '';
    };
    eq(problem({ subject_type: 'pairwise',
                 redirect_uris: ['https://a.example/cb',
                                 'https://a.example/other'] }), '',
       'B. pairwise with every redirect URI on one host is accepted');
    note(/sector_identifier_uri/.test(problem({ subject_type: 'pairwise',
         redirect_uris: ['https://a.example/cb', 'https://b.example/cb'] })),
         'B. pairwise across two hosts with no sector_identifier_uri is ' +
         'refused, naming the member');
    note(!!problem({ subject_type: 'ephemeral' }),
         'B. an unknown subject_type is refused');
    note(!!problem({ sector_identifier_uri: 'http://a.example/s.json' }),
         'B. an http sector_identifier_uri is refused');
    note(!!problem({ token_endpoint_auth_signing_alg: 'none' }),
         'B. token_endpoint_auth_signing_alg none is refused');
    note(!!problem({ token_endpoint_auth_method: 'private_key_jwt',
                     token_endpoint_auth_signing_alg: 'HS256' }),
         'B. an HMAC for private_key_jwt is refused');
    note(!!problem({ token_endpoint_auth_method: 'client_secret_jwt',
                     token_endpoint_auth_signing_alg: 'ES256' }),
         'B. and an asymmetric alg for client_secret_jwt');
    eq(problem({ token_endpoint_auth_method: 'private_key_jwt',
                 token_endpoint_auth_signing_alg: 'ML-DSA-65' }), '',
       'B. while a post-quantum alg for private_key_jwt is accepted');

    // --- C ----------------------------------------------------------------
    eq(JSON.stringify(stepUp.requirementOf({ claims: JSON.stringify({
      id_token: { acr: { essential: true, values: ['mfa', '1'] } } }) })
      .acrValues), '["mfa","1"]',
      'C. an essential acr with values is a requirement');
    eq(stepUp.requirementOf({ claims: JSON.stringify({
      id_token: { acr: { values: ['mfa'] } } }) }).present, false,
      'C. a voluntary one is not');
    eq(JSON.stringify(stepUp.requirementOf({ acr_values: 'mfa',
      claims: { userinfo: { acr: { essential: true, value: '1' } } } })
      .acrValues), '["mfa","1"]',
      'C. and it joins acr_values after them, from either member');

    // --- D ----------------------------------------------------------------
    const server = oauth2.OAuth2Server
      ? new oauth2.OAuth2Server(oauth2.OAuth2Server.defaultDeps()) : null;
    if (note(!!server, 'D. the authorization server can be built here')) {
      eq(server.usesFragment(['code']), false,
         'D. code alone answers in the query');
      eq(server.usesFragment(['code', 'id_token']), true,
         'D. a hybrid type in the fragment');
      eq(server.usesFragment(['id_token'], 'query'), true,
         'D. an explicit query is not honoured for a type carrying a ' +
         'token');
      eq(server.usesFragment(['code'], 'fragment'), true,
         'D. while an explicit fragment is, for code too');
    }

    // --- E ----------------------------------------------------------------
    const surfaces = Object.keys(oidcRp.SURFACES).map(function (id) {
      return oidcRp.SURFACES[id];
    });
    eq(JSON.stringify(surfaces.map(function (one) {
      return one.clientId;
    }).sort()), JSON.stringify(applications.HOSTED_SURFACE_CLIENT_IDS.slice()
      .sort()),
      'E. the hosted surfaces\' clients are the list sign-out revokes for');
    surfaces.forEach(function (one) {
      note(one.scopes.indexOf('offline_access') >= 0,
           'E. ' + one.id + ' asks for offline_access');
    });

    // --- F ----------------------------------------------------------------
    const helpers = require(ROOT + '/common/helpers');
    const gnapSubject = require(ROOT + '/gnap/gnap_subject');
    const idToken = helpers.signJwt({ iss: 'https://sts.example',
      sub: 'urn:uuid:00000000-0000-4000-8000-000000000001', aud: 'client-f',
      iat: helpers.nowSec(), exp: helpers.nowSec() + 60,
      preferred_username: 'alice' }, {});
    const asId = gnapSubject.resolveUser({ assertions: [
      { format: 'id_token', value: idToken }] }, {});
    note(asId.ok && asId.username === 'alice',
         'F. an ID Token as issued since #118 is a GNAP subject assertion',
         JSON.stringify(asId));
    const accessToken = helpers.signJwt({ iss: 'https://sts.example',
      sub: 'urn:uuid:00000000-0000-4000-8000-000000000001', aud: 'client-f',
      typ: 'Bearer', iat: helpers.nowSec(), exp: helpers.nowSec() + 60,
      preferred_username: 'alice' }, {});
    const asAccess = gnapSubject.resolveUser({ assertions: [
      { format: 'id_token', value: accessToken }] }, {});
    note(!asAccess.ok,
         'F. while an access token presented as one is refused',
         JSON.stringify(asAccess));

    // --- G ----------------------------------------------------------------
    const adminStats = require(ROOT + '/common/admin_stats');
    const kindOf = function (jti) {
      const row = adminStats.tokenList().filter(function (one) {
        return one.key === jti;
      })[0];
      return row ? row.kind : '(not recorded)';
    };
    helpers.signJwt({ iss: 'https://sts.example', sub: 'urn:uuid:g',
      aud: 'client-g', jti: 'g-id-token', iat: helpers.nowSec(),
      exp: helpers.nowSec() + 60 }, { kind: 'id_token' });
    eq(kindOf('g-id-token'), 'id_token',
       'G. an ID Token is recorded as id_token from the kind its issuer ' +
       'states');
    helpers.signJwt({ iss: 'https://sts.example', sub: 'urn:uuid:g',
      aud: 'client-g', jti: 'g-bogus', typ: 'Bearer', iat: helpers.nowSec(),
      exp: helpers.nowSec() + 60 }, { kind: 'not-a-kind' });
    eq(kindOf('g-bogus'), 'access_token',
       'G. a kind the register does not know is ignored for the typ');
    note(adminStats.TOKEN_KINDS.indexOf('id_token') >= 0,
         'G. id_token is still one of the kinds the tokens page filters by',
         JSON.stringify(adminStats.TOKEN_KINDS));
  } catch (e) {
    note(false, 'the test itself threw', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'oidc-core-units-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', OCU_ROOT: ROOT, OCU_OUT: out }),
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
  name: 'oidc_core_units',
  describe: 'OIDC Core (#118): the ID Token hash for every algorithm, ' +
            'pairwise and signing-alg registration metadata, an essential ' +
            'acr as a requirement, and the default response mode',
  run: run
};
