// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: federation_fapi_client.js
//
// ===========================================================================
// THIS SERVICE AS A FAPI CLIENT (#931), IN PROCESS.
//
// `federation/fapi_client.ts` decides the profile and signs the proofs. The
// dialling lives in `federation_sp.ts` and is pinned over HTTP by
// `tests/federation_oidc_rp.js`. This file holds what a partner never sees
// as a status code: which relationship is a FAPI client, what each profile
// forces, the shape of a DPoP proof, a `private_key_jwt` and a request
// object, and that `use_dpop_nonce` is retried once.
//
// IN A CHILD PROCESS, for `fapi2_units.js`'s reason: the signing key exists
// only after the stack has loaded.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({
  name: 'federation_fapi_client',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

// IN A CHILD PROCESS. Serialized with `toString()`, so it closes over
// nothing from this file.
function childMain() {
  const ROOT_DIR = process.env.FFC_ROOT;
  const OUT = process.env.FFC_OUT;
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
  function partsOf(jwt) {
    const parts = String(jwt || '').split('.');
    if (parts.length !== 3) {
      return null;
    }
    return {
      header: JSON.parse(Buffer.from(parts[0], 'base64url').toString()),
      claims: JSON.parse(Buffer.from(parts[1], 'base64url').toString())
    };
  }
  const main = async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const nodeCrypto = require('crypto');
    const Fapi = require(ROOT_DIR + '/federation/fapi_client');
    const oidc = function (profile, extra) {
      return Object.assign({ fedProtocol: 'oidc', fedFapi: profile,
        fedClientId: 'client-1',
        fedPeer: 'https://issuer.example/op' }, extra || {});
    };

    // --- which relationship is a FAPI client -----------------------------
    eq(Fapi.profileOf(null), '', 'an empty record is not a FAPI client');
    eq(Fapi.profileOf({ fedProtocol: 'oidc' }), '',
       'an empty fedFapi is today\'s relying party');
    eq(Fapi.profileOf(oidc('no-such')), '',
       'an unknown profile is not a FAPI client');
    eq(Fapi.profileOf({ fedProtocol: 'saml2', fedFapi: '2-security' }), '',
       'a protocol other than OpenID Connect is not a FAPI client');
    eq(Fapi.profileOf(oidc('2-security',
                           { fedTrustAnchor: 'https://ta.example' })), '',
       'an OpenID Federation OP is not this client');
    eq(Fapi.profileOf(oidc('1-advanced')), '1-advanced', '1-advanced');
    eq(Fapi.profileOf(oidc('2-security')), '2-security', '2-security');
    eq(Fapi.profileOf(oidc('2-message-signing')), '2-message-signing',
       '2-message-signing');
    eq(Fapi.usesPar('1-advanced'), false, '1-advanced does not push');
    eq(Fapi.usesPar('2-security'), true, '2-security pushes');
    eq(Fapi.usesPar('2-message-signing'), true, 'message signing pushes');
    eq(Fapi.usesDpop('1-advanced'), false, '1-advanced sends no DPoP');
    eq(Fapi.usesDpop('2-security'), true, '2-security uses DPoP');
    eq(Fapi.usesJarm('2-security'), false, '2-security asks for no JARM');
    eq(Fapi.usesJarm('2-message-signing'), true, 'message signing uses JARM');
    eq(Fapi.sendsRequestByValue('1-advanced'), true,
       '1-advanced sends the request object by value');
    eq(Fapi.sendsRequestByValue('2-message-signing'), false,
       'message signing does not put the request object on the browser URL');
    eq(Fapi.needsDiscovery('1-advanced'), false,
       '1-advanced can use configured endpoints');
    eq(Fapi.needsDiscovery('2-security'), true,
       '2-security needs the discovery document');

    // --- what a profile forces on the authorization request ---------------
    const plain = oidc('');
    eq(Fapi.shapedRecord(plain) === plain, true,
       'no profile returns the same record');
    const advanced = Fapi.shapedRecord(oidc('1-advanced', {
      fedScope: 'profile', fedResponseType: 'code',
      fedResponseMode: 'query' }));
    eq(advanced.fedResponseType, 'code id_token',
       '1-advanced forces code id_token');
    eq(advanced.fedResponseMode, '',
       '1-advanced clears a query mode, so the hybrid answer is form_post');
    eq(advanced.fedScope, 'openid profile',
       '1-advanced keeps openid in the scope');
    const fragment = Fapi.shapedRecord(oidc('1-advanced',
      { fedResponseMode: 'fragment' }));
    eq(fragment.fedResponseMode, 'fragment',
       '1-advanced leaves a fragment mode as the operator set it');
    const security = Fapi.shapedRecord(oidc('2-security', {
      fedResponseType: 'code id_token', fedResponseMode: 'form_post',
      fedScope: 'openid' }));
    eq(security.fedResponseType, 'code', '2-security forces code');
    eq(security.fedResponseMode, '',
       '2-security clears form_post, so the code comes back on the query');
    const signing = Fapi.shapedRecord(oidc('2-message-signing',
      { fedResponseMode: 'query' }));
    eq(signing.fedResponseType, 'code', 'message signing forces code');
    eq(signing.fedResponseMode, 'jwt', 'message signing forces JARM');

    // --- a DPoP proof -------------------------------------------------------
    const key = Fapi.newKey();
    note(key && key.pem && key.jwk && key.jwk.kty === 'EC' &&
         key.jwk.crv === 'P-256' && key.jwk.x && key.jwk.y && !key.jwk.d &&
         !key.jwk.alg, 'a sign-in key is a public P-256 JWK and its PEM',
         JSON.stringify(key && key.jwk));
    const proof = partsOf(Fapi.proof(key, 'get',
      'https://op.example/token?x=1', 'nn', 'access-token'));
    const ath = nodeCrypto.createHash('sha256').update('access-token')
      .digest('base64url');
    note(proof && proof.header.typ === 'dpop+jwt' &&
         proof.header.alg === 'ES256' &&
         proof.header.jwk && proof.header.jwk.x === key.jwk.x &&
         !proof.header.jwk.d &&
         proof.claims.htm === 'GET' &&
         proof.claims.htu === 'https://op.example/token' &&
         proof.claims.nonce === 'nn' && proof.claims.ath === ath &&
         proof.claims.jti, 'a proof names the method, the URL without its ' +
         'query, the nonce and the access-token hash',
         JSON.stringify(proof));
    const bare = partsOf(Fapi.proof(key, 'POST', 'https://op.example/par',
                                    '', ''));
    note(bare && bare.claims.htm === 'POST' && !('nonce' in bare.claims) &&
         !('ath' in bare.claims),
         'a proof with no nonce and no access token omits both claims',
         JSON.stringify(bare && bare.claims));

    // --- private_key_jwt and the request object ----------------------------
    const assertion = partsOf(Fapi.clientAssertion(oidc('2-security')));
    const now = Math.floor(Date.now() / 1000);
    note(assertion && assertion.header.alg === 'PS256' &&
         assertion.claims.iss === 'client-1' &&
         assertion.claims.sub === 'client-1' &&
         assertion.claims.aud === 'https://issuer.example/op' &&
         assertion.claims.exp - assertion.claims.iat === 60 &&
         Math.abs(assertion.claims.iat - now) < 5 &&
         assertion.claims.jti,
         'a private_key_jwt is PS256, aud the issuer, and lives 60 seconds',
         JSON.stringify(assertion));
    const params = new URLSearchParams({ response_type: 'code',
      client_id: 'client-1', scope: 'openid' });
    const request = partsOf(Fapi.requestObject(oidc('1-advanced'), params));
    note(request && request.header.alg === 'PS256' &&
         request.header.typ === 'oauth-authz-req+jwt' &&
         request.claims.response_type === 'code' &&
         request.claims.client_id === 'client-1' &&
         request.claims.iss === 'client-1' &&
         request.claims.aud === 'https://issuer.example/op' &&
         request.claims.nbf === request.claims.iat &&
         request.claims.exp - request.claims.iat === 60,
         'a request object is PS256, typ oauth-authz-req+jwt, and lives ' +
         '60 seconds', JSON.stringify(request));

    // --- a JARM payload -----------------------------------------------------
    eq(Fapi.jarmProblem({}), 'it carries no state',
       'a JARM payload with no state cannot be used');
    eq(Fapi.jarmProblem({ state: 's' }),
       'it carries neither a code nor an error',
       'a JARM payload with no code and no error cannot be used');
    eq(Fapi.jarmProblem({ state: 's', code: 'c' }), '',
       'a JARM payload with a state and a code can be used');
    eq(Fapi.jarmProblem({ state: 's', error: 'access_denied' }), '',
       'a JARM payload with a state and an error can be used');
    eq(Fapi.jarmExpiryProblem({ state: 's', code: 'c' }),
       'it carries no exp (as a number)',
       'a JARM payload with no exp cannot be used (JARM 4.4)');
    eq(Fapi.jarmExpiryProblem({ exp: '1999999999' }),
       'it carries no exp (as a number)',
       'a JARM payload whose exp is a string cannot be used');
    eq(Fapi.jarmExpiryProblem({ exp: 1999999999 }), '',
       'a JARM payload with a numeric exp can be used');

    // --- what each profile holds the answer to (#931's review) ------------
    eq(['', '1-advanced', '2-security', '2-message-signing']
      .map(function (p) {
        return [Fapi.requiresStateHash(p) ? 's' : '-',
                Fapi.requiresIssuerParameter(p) ? 'i' : '-'].join('');
      }).join(','), '--,s-,-i,-i',
       's_hash is 1-advanced\'s alone, iss the 2.x profiles\', and no ' +
       'profile asks for either');
    eq(Fapi.tokenTypeProblem('2-security', { token_type: 'Bearer' }),
       'its token_type is "Bearer", not DPoP',
       'a 2.x token response answered Bearer cannot be used');
    eq(Fapi.tokenTypeProblem('2-message-signing', {}),
       'its token_type is "", not DPoP',
       'a 2.x token response with no token_type cannot be used');
    eq(Fapi.tokenTypeProblem('2-security', { token_type: 'dPoP' }), '',
       'token_type is compared without case');
    eq(Fapi.tokenTypeProblem('1-advanced', { token_type: 'Bearer' }) +
       Fapi.tokenTypeProblem('', { token_type: 'Bearer' }), '',
       '1-advanced and no profile are not asked for DPoP');

    // --- use_dpop_nonce, once ------------------------------------------------
    const seen = [];
    const retried = await Fapi.withNonce(function (nonce) {
      seen.push(String(nonce));
      const next = seen.length === 1 ? 'n2' : 'n3';
      return Promise.resolve({ ok: false, status: 400,
        json: { error: 'use_dpop_nonce' },
        headers: { 'dpop-nonce': next } });
    }, '');
    eq(seen.join(','), ',n2',
       'use_dpop_nonce is sent again with the new nonce, and not a third time');
    eq(retried.status, 400, 'the second answer is the one kept');
    let once = 0;
    await Fapi.withNonce(function () {
      once += 1;
      return Promise.resolve({ ok: false, status: 400,
        json: { error: 'use_dpop_nonce' },
        headers: { 'dpop-nonce': 'same' } });
    }, 'same');
    eq(once, 1, 'a repeat of the nonce just sent is not retried');
    let okCount = 0;
    const kept = await Fapi.withNonce(function () {
      okCount += 1;
      return Promise.resolve({ ok: true, status: 201, json: {},
        headers: { 'dpop-nonce': 'later' } });
    }, '');
    eq(okCount, 1, 'a success is not sent again');
    eq(kept.status, 201, 'the successful answer is kept');
    let bareCount = 0;
    await Fapi.withNonce(function () {
      bareCount += 1;
      return Promise.resolve({ ok: false, status: 500,
        json: { error: 'use_dpop_nonce' } });
    }, '');
    eq(bareCount, 1, 'a refusal that carries no DPoP-Nonce is not retried');
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
  const out = path.join(os.tmpdir(), 'federation-fapi-client-' +
                        process.pid + '-' +
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
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', FFC_ROOT: ROOT,
                                  FFC_OUT: out }),
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
  name: 'federation_fapi_client',
  describe: 'A FAPI client on an inbound OpenID Connect relationship ' +
            '(#931): the three profiles, a DPoP proof, private_key_jwt, ' +
            'a request object, and one DPoP-Nonce retry',
  run: run
};
