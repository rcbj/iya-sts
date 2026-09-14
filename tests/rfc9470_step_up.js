'use strict';
//
// File: rfc9470_step_up.js
//
// ===========================================================================
// RFC 9470 — OAUTH 2.0 STEP UP AUTHENTICATION CHALLENGE PROTOCOL (2026-09-13).
//
// `oauth-oidc/step_up.js` argues the design. What is held here, every feature
// with the request that must work and the requests that must not:
//
//   1. THE LIBRARY: the parse, the ordered levels and the three key aliases,
//      the preference order the token's acr is chosen by, when the sign-in
//      screen must demand a second factor, the session assessment with and
//      without the round-trip marker, the resource server's refusal, the
//      challenge header and the three authorization-endpoint refusals;
//   2. THE REGISTRY: the two attributes' grammar at both write doors, the
//      requirement read off an entry (and a hand-written bad value ignored),
//      which audiences name an entry, and the acr pattern held equal to the
//      library's;
//   3. THE ENDPOINTS, in a child process on an ephemeral loopback port:
//        a. discovery — acr_values_supported in both documents;
//        b. acr and auth_time in the access token and in introspection
//           (section 6);
//        c. the stand-in resource — 401 insufficient_user_authentication with
//           acr_values and max_age, and what it refuses before asking: no
//           token, an unknown application, a token for another audience, a
//           token this service did not sign;
//        d. STEP-UP FOR A SECOND FACTOR, end to end — a one-factor session
//           sent to sign in again, the screen demanding the factor, the code,
//           the marker on the return, a token carrying acr "mfa", the
//           resource answering 200, and the refresh token keeping the acr;
//        e. the hierarchy at the authorization endpoint — an mfa session
//           answering acr_values=1 without a sign-in, with "1" in the token;
//        f. max_age — 0 sends a live session to sign in and the fresh sign-in
//           is accepted, a generous one is met by the session, and the ID
//           Token's auth_time moves;
//        g. prompt=none answers login_required;
//        h. a requirement the sign-in cannot meet is refused
//           unmet_authentication_requirements on the return, and a forged
//           marker on a first request gets the refusal and not a pass;
//        i. an acr value that cannot be one is invalid_request, and a push
//           carrying the marker has it stripped;
//        j. this service's own resource server — UserInfo challenged under
//           oauth2.stepUpAcrValues and oauth2.stepUpMaxAgeS, and met;
//        k. the counters and the monitoring view.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'rfc9470',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// 1. THE LIBRARY.
// ---------------------------------------------------------------------------
function library(t) {
  log.debug("Entering library().");
  t.log.info('=== 1. the library ===');
  const stepUp = require('../oauth-oidc/step_up');
  const errorCodes = require('../common/error_codes');

  let parsed = stepUp.parseAcrValues('  mfa 1 mfa  urn:x:gold ');
  t.check(JSON.stringify(parsed.values) === '["mfa","1","urn:x:gold"]' &&
          !parsed.invalid.length,
          '1a. acr_values parse in order of preference, a repeat dropped',
          JSON.stringify(parsed));
  parsed = stepUp.parseAcrValues('mfa a"b c\\d');
  t.check(JSON.stringify(parsed.values) === '["mfa"]' &&
          parsed.invalid.length === 2,
          '1b. a value with a quote or a backslash is reported, not kept',
          JSON.stringify(parsed));
  t.check(stepUp.parseMaxAge('0') === 0 && stepUp.parseMaxAge('300') === 300 &&
          stepUp.parseMaxAge(undefined) === null &&
          stepUp.parseMaxAge('-1') === null && stepUp.parseMaxAge('x') === null,
          '1c. max_age is a whole number of seconds, zero included');
  t.check(!stepUp.requirementOf({}).present &&
          stepUp.requirementOf({ max_age: '0' }).present &&
          stepUp.requirementOf({ acr_values: 'mfa' }).present,
          '1d. a request asks for nothing unless it names one of the two');

  const one = { acr: '1', amr: ['pwd'] };
  const totpMfa = { acr: 'mfa', amr: ['pwd', 'otp'] };
  const keyMfa = { acr: 'mfa', amr: ['pwd', 'hwk'] };
  const anon = { acr: '0', amr: [] };
  const partner = { acr: 'urn:partner:gold', amr: ['pwd'] };
  t.check(stepUp.meets('1', totpMfa) && stepUp.meets('0', one) &&
          !stepUp.meets('mfa', one) && !stepUp.meets('1', anon),
          '1e. the levels are ordered: a stronger authentication meets a ' +
          'weaker request and not the reverse');
  t.check(stepUp.meets('hwk', keyMfa) && !stepUp.meets('hwk', totpMfa) &&
          !stepUp.meets('phr', { acr: '1', amr: ['hwk'] }),
          '1f. hwk is met by two factors including a key — not by a code, ' +
          'and not by a key alone');
  t.check(stepUp.meets('urn:partner:gold', partner) &&
          !stepUp.meets('urn:partner:gold', keyMfa) &&
          !stepUp.meets('urn:partner:silver', partner),
          '1g. any other value is met only by that exact acr');
  t.check(stepUp.satisfiedAcr(['1', 'mfa'], totpMfa) === '1' &&
          stepUp.satisfiedAcr(['mfa', '1'], totpMfa) === 'mfa' &&
          stepUp.satisfiedAcr(['mfa', '1'], one) === '1' &&
          stepUp.satisfiedAcr(['mfa'], one) === null &&
          stepUp.satisfiedAcr([], one) === '1',
          '1h. the token carries the MOST PREFERRED REQUESTED value met, and ' +
          'the session\'s own acr when nothing was requested');
  t.check(stepUp.demandsSecondFactor(['mfa']) &&
          stepUp.demandsSecondFactor(['hwk']) &&
          stepUp.demandsSecondFactor(['urn:x', 'mfa']) &&
          !stepUp.demandsSecondFactor(['mfa', '1']) &&
          !stepUp.demandsSecondFactor(['urn:x']) &&
          !stepUp.demandsSecondFactor([]),
          '1i. the screen demands two factors only when every value it can ' +
          'produce needs them');

  const now = 1000000;
  let a = stepUp.assessSession({ acrValues: [], maxAge: 60 },
                               { authTime: now - 120, acr: '1' },
                               { now: now, windowS: 600 });
  t.check(!a.met && a.reason === 'max_age' && a.retry,
          '1j. an elapsed max_age sends the person to sign in',
          JSON.stringify(a));
  a = stepUp.assessSession({ acrValues: [], maxAge: 0 },
                           { authTime: now - 30, acr: '1' },
                           { now: now, windowS: 600, honoured: true });
  t.check(a.met, '1k. on the return leg max_age is held to the sign-in ' +
          'window, so max_age=0 does not loop', JSON.stringify(a));
  a = stepUp.assessSession({ acrValues: [], maxAge: 0 },
                           { authTime: now - 900, acr: '1' },
                           { now: now, windowS: 600, honoured: true });
  t.check(!a.met && !a.retry && a.reason === 'max_age',
          '1l. and a session older than that window is refused, not sent ' +
          'round again', JSON.stringify(a));
  a = stepUp.assessSession({ acrValues: ['mfa'], maxAge: null },
                           { authTime: now, acr: '1' },
                           { now: now, windowS: 600, honoured: true });
  t.check(!a.met && !a.retry && a.reason === 'acr',
          '1m. an acr the sign-in did not meet is refused on the return',
          JSON.stringify(a));
  a = stepUp.assessSession({ acrValues: ['1', 'mfa'], maxAge: 300 },
                           { authTime: now - 10, acr: 'mfa', amr: ['pwd'] },
                           { now: now });
  t.check(a.met && a.acr === '1',
          '1n. both met, and the preferred requested value is chosen',
          JSON.stringify(a));

  let refusal = stepUp.unmetRefusal({ acrValues: ['mfa'], maxAge: null },
                                    { reason: 'acr' }, false);
  t.check(refusal.error === 'unmet_authentication_requirements' &&
          errorCodes.codeOf(refusal) === 'STS-OAUTH-0500',
          '1o. an unmet acr is unmet_authentication_requirements (0500)');
  refusal = stepUp.unmetRefusal({ acrValues: [], maxAge: 0 },
                                { reason: 'max_age', elapsed: 900 }, false);
  t.check(refusal.error === 'unmet_authentication_requirements' &&
          errorCodes.codeOf(refusal) === 'STS-OAUTH-0501',
          '1p. an unmet max_age after the sign-in is 0501');
  refusal = stepUp.unmetRefusal({ acrValues: ['mfa'], maxAge: null },
                                { reason: 'acr' }, true);
  t.check(refusal.error === 'login_required' &&
          errorCodes.codeOf(refusal) === 'STS-OAUTH-0502',
          '1q. under prompt=none it is login_required (0502)');

  const need = { acrValues: ['mfa'], maxAge: 300, present: true };
  t.check(stepUp.tokenRefusal({ acrValues: [], maxAge: null, present: false },
                              {}) === null,
          '1r. a resource requiring nothing refuses nothing');
  refusal = stepUp.tokenRefusal(need, { acr: 'mfa' }, { now: now });
  t.check(refusal && refusal.reason === 'max_age' &&
          errorCodes.codeOf(refusal) === 'STS-OAUTH-0504',
          '1s. a token with no auth_time does not meet a max_age (0504)');
  refusal = stepUp.tokenRefusal(need, { acr: 'mfa', auth_time: now - 301 },
                                { now: now });
  t.check(refusal && refusal.reason === 'max_age',
          '1t. nor does one a second too old — no clock skew on the age');
  refusal = stepUp.tokenRefusal(need, { acr: '1', auth_time: now - 10 },
                                { now: now });
  t.check(refusal && refusal.reason === 'acr' &&
          refusal.error === 'insufficient_user_authentication' &&
          errorCodes.codeOf(refusal) === 'STS-OAUTH-0503',
          '1u. an acr that meets none is insufficient_user_authentication ' +
          '(0503)');
  t.check(stepUp.tokenRefusal({ acrValues: ['1'], maxAge: null,
                                present: true },
                              { acr: 'mfa', auth_time: now }, { now: now })
            === null,
          '1v. and an mfa token meets a resource requiring "1"');
  t.equal(stepUp.challengeHeader('Bearer', need, 'say "no"'),
          'Bearer error="insufficient_user_authentication", ' +
          'error_description="say \'no\'", acr_values="mfa", max_age="300"',
          '1w. section 3\'s challenge: both auth-params, the description ' +
          'unable to end its quoted-string');
  t.check(/^DPoP error="insufficient_user_authentication"$/.test(
            stepUp.challengeHeader('DPoP', { acrValues: [], maxAge: null })),
          '1x. under the DPoP scheme for a bound token');
  log.debug("Leaving library().");
}

// ---------------------------------------------------------------------------
// 2. THE REGISTRY.
// ---------------------------------------------------------------------------
function registry(t) {
  log.debug("Entering registry().");
  t.log.info('=== 2. the two application attributes ===');
  const applications = require('../common/applications');
  const stepUp = require('../oauth-oidc/step_up');

  t.check(applications.stepUpAttributeProblem('oauthStepUpAcrValues',
                                              'mfa 1') === null &&
          applications.stepUpAttributeProblem('oauthStepUpMaxAge', '0') ===
            null &&
          applications.stepUpAttributeProblem('oauthStepUpAcrValues', '') ===
            null,
          '2a. a usable value, zero seconds and a clear are accepted');
  let p = applications.stepUpAttributeProblem('oauthStepUpAcrValues',
                                              'mfa a"b');
  t.check(p && p.code === 'STS-REG-0140', '2b. an acr value with a quote is ' +
          'refused (0140)', JSON.stringify(p));
  p = applications.stepUpAttributeProblem('oauthStepUpMaxAge', '-5');
  t.check(p && p.code === 'STS-REG-0141', '2c. a negative age is refused ' +
          '(0141)', JSON.stringify(p));
  const req = applications.stepUpRequirementOf({ identifier: 'x', fields: {
    oauthStepUpAcrValues: 'mfa bad"one 1', oauthStepUpMaxAge: 'soon' } });
  t.check(JSON.stringify(req.acrValues) === '["mfa","1"]' &&
          req.maxAge === null && req.present,
          '2d. a value an ldapmodify left that cannot be one is ignored, ' +
          'the rest kept', JSON.stringify(req));
  const entry = { identifier: 'api1', fields: {
    oauthClientId: 'api1-client', oauthAudience: ['https://aud.example'],
    oauthPermissionBaseUri: 'https://api1.example' } };
  t.check(applications.audienceNamesEntry(entry, 'api1') &&
          applications.audienceNamesEntry(entry, ['x', 'api1-client']) &&
          applications.audienceNamesEntry(entry, 'https://aud.example') &&
          applications.audienceNamesEntry(entry, 'https://api1.example/') &&
          !applications.audienceNamesEntry(entry, 'https://other.example') &&
          !applications.audienceNamesEntry(null, 'api1'),
          '2e. an aud names an entry by identifier, client_id, audience or ' +
          'permission base — and nothing else');
  const source = fs.readFileSync(path.join(ROOT, 'common', 'applications.js'),
                                 'utf8');
  const held = /const STEP_UP_ACR_VALUE = (\/.*\/);/.exec(source);
  t.check(held && held[1] === String(stepUp.ACR_VALUE),
          '2f. the registry\'s acr pattern is the library\'s',
          held && held[1] + ' vs ' + String(stepUp.ACR_VALUE));
  log.debug("Leaving registry().");
}

// ---------------------------------------------------------------------------
// 3. THE ENDPOINTS.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SU_ROOT;
  const OUT = process.env.SU_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const claimsOf = function (jwt) {
    try {
      return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
        .toString('utf8'));
    } catch (e) {
      return { parseError: e.message };
    }
  };

  // One browser: a cookie jar and a request function. Two people are two
  // browsers, so a sign-in as one never lands on the other's session.
  function browser(port) {
    const jar = {};
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = Object.assign({}, o.headers || {});
        if (!o.noCookies && Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: '127.0.0.1', port: port,
                                   path: String(urlPath).replace(
                                     /^https?:\/\/[^/]+/, ''),
                                   method: method, headers: headers },
                                 function (res) {
          let text = '';
          (res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            jar[pair.slice(0, eq)] = pair.slice(eq + 1);
          });
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            let parsed = null;
            try {
              parsed = JSON.parse(text);
            } catch (e) {
              parsed = { parseError: e.message };
            }
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text, json: parsed });
          });
        });
        req.end(body);
      });
    };
    return { go: go, jar: jar };
  }
  const hiddenFields = function (html) {
    const form = {};
    (html.match(/<input type="hidden"[^>]*>/g) || []).forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
      }
    });
    return form;
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const credentials = require(ROOT + '/common/credentials');
    const totp = require(ROOT + '/common/totp');
    const monitor = require(ROOT + '/oauth-oidc/oauth2_monitor');
    const monitorConsole = require(ROOT + '/oauth-oidc/oauth2_monitor_console');
    const par = require(ROOT + '/oauth-oidc/par');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    config.setOverride('oauth2.consentRequired', false);

    const SECRET = 'step-up-client-secret-0123456789abcdef012345';
    const REDIRECT = 'https://rp.stepup.example/cb';
    const API = 'https://api.stepup.example/';
    const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    applications.createApplication({ identifier: 'su-client',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'su-client', oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code', 'refresh_token'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    const made = applications.createApplication({ identifier: 'su-api',
      protocols: ['oauth2'],
      fields: { oauthAudience: [API], oauthStepUpAcrValues: 'mfa',
                oauthStepUpMaxAge: '600' } });
    note(made && made.ok !== false, '3.0 a resource application declaring a ' +
         'step-up requirement is created', JSON.stringify(made).slice(0, 200));
    // The two write doors ask the grammar, not only the function the library
    // half calls: a create and a console `set` with an unusable value refused
    // by code, and nothing written.
    const errorCodes = require(ROOT + '/common/error_codes');
    const badCreate = applications.createApplication({ identifier: 'su-bad',
      protocols: ['oauth2'], fields: { oauthStepUpAcrValues: 'mfa a"b' } });
    note(badCreate && badCreate.ok === false &&
         errorCodes.codeOf(badCreate) === 'STS-REG-0140',
         '3.0b a create carrying an unusable acr value is refused (0140)',
         JSON.stringify(badCreate).slice(0, 200));
    const badSet = applications.updateApplication('su-api', {
      attribute: 'oauthStepUpMaxAge', mode: 'set', value: '-5' });
    const apiEntry = applications.get('su-api');
    note(badSet && badSet.ok === false &&
         errorCodes.codeOf(badSet) === 'STS-REG-0141' &&
         String(((apiEntry || {}).fields || {}).oauthStepUpMaxAge) === '600',
         '3.0c a console set of a negative age is refused (0141) and the ' +
         'stored 600 stands', JSON.stringify(badSet).slice(0, 200));
    const basic = 'Basic ' + Buffer.from('su-client:' + SECRET)
      .toString('base64');

    const authorizeQuery = function (extra) {
      return '/oauth2/authorize?' + new URLSearchParams(Object.assign({
        client_id: 'su-client', response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid', state: 'st', nonce: 'n-' +
          crypto.randomBytes(4).toString('hex'),
        code_challenge: CHALLENGE, code_challenge_method: 'S256' },
        extra || {})).toString();
    };
    const toSignIn = function (r) {
      return r.status === 302 &&
             /\/authn\/login/.test(String(r.headers.location || ''));
    };
    const codeOf = function (r) {
      const loc = String((r && r.headers && r.headers.location) || '');
      return r && r.status === 302 && loc.indexOf(REDIRECT) === 0
        ? new URL(loc).searchParams : null;
    };
    // The sign-in screen as a person uses it: the hidden fields it drew, a
    // name and a password, and — when `code` is given — the one-time code
    // screen after it. Answers every hop, so a test can look at the screens.
    const signIn = async function (b, first, username, code) {
      const page = await b.go('GET', first.headers.location);
      const form = hiddenFields(page.text);
      form.username = username;
      form.password = 'anything';
      form.action = 'login';
      const screen = String(first.headers.location).split('?')[0]
        .replace(/^https?:\/\/[^/]+/, '');
      let posted = await b.go('POST', screen, { form: form });
      let totpPage = null;
      if (code && posted.status === 200 && /name="mfa_id"/.test(posted.text)) {
        totpPage = posted;
        const mfaId = (posted.text.match(/name="mfa_id" value="([^"]+)"/) ||
                       [])[1];
        posted = await b.go('POST', '/authn/totp',
                            { form: { mfa_id: mfaId, code: code } });
      }
      const back = String(posted.headers.location || '')
        .replace(/^https?:\/\/[^/]+/, '');
      const final = back ? await b.go('GET', back) : posted;
      return { page: page, posted: posted, totpPage: totpPage, back: back,
               final: final };
    };
    const redeem = async function (b, params) {
      return b.go('POST', '/oauth2/token', {
        headers: { authorization: basic }, noCookies: true,
        form: { grant_type: 'authorization_code', code: params.get('code'),
                redirect_uri: REDIRECT, code_verifier: VERIFIER } });
    };
    const resource = function (b, token, app) {
      return b.go('GET', '/oauth2/step-up/resource/' + (app || 'su-api'), {
        noCookies: true,
        headers: token ? { authorization: 'Bearer ' + token } : {} });
    };

    // --- a. discovery --------------------------------------------------------
    const anon = browser(port);
    let r = await anon.go('GET', '/.well-known/oauth-authorization-server');
    note(JSON.stringify(r.json.acr_values_supported) === '["0","1","mfa"]',
         '3a1. RFC 8414 metadata publishes acr_values_supported 0, 1, mfa',
         JSON.stringify(r.json.acr_values_supported));
    r = await anon.go('GET', '/.well-known/openid-configuration');
    note(JSON.stringify(r.json.acr_values_supported) === '["0","1","mfa"]',
         '3a2. and so does the OpenID Provider Configuration');

    // --- b. a one-factor sign-in, and what its token says --------------------
    const alice = browser(port);
    let first = await alice.go('GET', authorizeQuery({ resource: API }));
    note(toSignIn(first), '3b1. no session: to the sign-in screen',
         first.status + ' ' + first.headers.location);
    let done = await signIn(alice, first, 'su-alice');
    let params = codeOf(done.final);
    note(!!params, '3b2. a password sign-in issues a code',
         done.final.status + ' ' + done.final.headers.location);
    r = await redeem(alice, params);
    const oneFactorToken = r.json.access_token;
    let at = claimsOf(oneFactorToken);
    note(r.status === 200 && at.acr === '1' &&
         typeof at.auth_time === 'number' &&
         at.aud === API,
         '3b3. section 6.1: the access token carries acr "1" and auth_time, ' +
         'addressed to the API', r.status + ' ' + JSON.stringify(at));
    r = await anon.go('POST', '/oauth2/introspect', {
      headers: { authorization: basic }, noCookies: true,
      form: { token: oneFactorToken } });
    note(r.status === 200 && r.json.active === true && r.json.acr === '1' &&
         r.json.auth_time === at.auth_time,
         '3b4. section 6.2: introspection carries acr and auth_time',
         r.status + ' ' + r.text.slice(0, 300));

    // --- c. the stand-in resource --------------------------------------------
    r = await resource(anon, oneFactorToken);
    const challenge = String(r.headers['www-authenticate'] || '');
    note(r.status === 401 &&
         /^Bearer error="insufficient_user_authentication"/.test(challenge) &&
         /acr_values="mfa"/.test(challenge) &&
         /max_age="600"/.test(challenge) &&
         r.json.error === 'insufficient_user_authentication',
         '3c1. section 3: a one-factor token is challenged 401 with ' +
         'acr_values and max_age', r.status + ' ' + challenge + ' ' +
         r.text.slice(0, 200));
    r = await resource(anon, null);
    note(r.status === 401 && r.json.error === 'invalid_token',
         '3c2. no token is 401 invalid_token, not a step-up challenge',
         r.status + ' ' + r.text.slice(0, 120));
    r = await resource(anon, oneFactorToken, 'su-nobody');
    note(r.status === 404, '3c3. an application the realm has no entry for ' +
         'is 404', r.status);
    const forged = Buffer.from(JSON.stringify({ alg: 'none', typ: 'at+jwt' }))
      .toString('base64url') + '.' + Buffer.from(JSON.stringify(
        { aud: API, acr: 'mfa', auth_time: Math.floor(Date.now() / 1000) }))
      .toString('base64url') + '.';
    r = await resource(anon, forged);
    note(r.status === 401 && r.json.error === 'invalid_token' &&
         /verify/.test(r.json.error_description || ''),
         '3c4. a token this service did not sign is refused before its acr ' +
         'is believed', r.status + ' ' + r.text.slice(0, 200));

    // A token for this service's own resource server, not for the API.
    first = await alice.go('GET', authorizeQuery());
    params = codeOf(first);
    note(!!params, '3c5. (a second request answered from the session)',
         first.status + ' ' + first.headers.location);
    r = await redeem(alice, params);
    const ownToken = r.json.access_token;
    r = await resource(anon, ownToken);
    note(r.status === 401 && r.json.error === 'invalid_token' &&
         /answers for the application "su-api"/.test(
           r.json.error_description || ''),
         '3c6. a token addressed to another audience is invalid_token, not ' +
         'a step-up challenge', r.status + ' ' + r.text.slice(0, 200));

    // --- d. step-up for a second factor, end to end --------------------------
    const began = credentials.beginTotpEnrolment('su-alice');
    const confirmed = began.ok
      ? credentials.confirmTotpEnrolment('su-alice',
                                         totp.codeAt(began.secret, Date.now()))
      : began;
    note(began.ok && confirmed.ok, '3d0. (su-alice enrols an authenticator ' +
         'app)', JSON.stringify(confirmed).slice(0, 200));
    first = await alice.go('GET', authorizeQuery({ resource: API,
                                                   acr_values: 'mfa' }));
    note(toSignIn(first), '3d1. a one-factor session is SENT TO SIGN IN ' +
         'AGAIN ' +
         'for acr_values=mfa, rather than answered',
         first.status + ' ' + first.headers.location);
    done = await signIn(alice, first, 'su-alice',
                        totp.codeAt(began.secret, Date.now() + 30000));
    note(/id="use_webauthn"[^>]*checked disabled/.test(done.page.text),
         '3d2. the sign-in screen demands the second factor');
    note(done.totpPage !== null, '3d3. and asks for the one-time code',
         done.posted.status);
    note(/step_up_honoured=1/.test(done.back),
         '3d4. the return address carries the marker', done.back);
    params = codeOf(done.final);
    note(!!params, '3d5. the stepped-up sign-in issues a code',
         done.final.status + ' ' + done.final.headers.location);
    r = await redeem(alice, params);
    const mfaToken = r.json.access_token;
    const mfaRefresh = r.json.refresh_token;
    at = claimsOf(mfaToken);
    const idt = claimsOf(r.json.id_token);
    note(at.acr === 'mfa' && idt.acr === 'mfa',
         '3d6. the access token and the ID Token carry acr "mfa"',
         JSON.stringify([at.acr, idt.acr]));
    r = await resource(anon, mfaToken);
    note(r.status === 200 && r.json.met === true &&
         r.json.token.acr === 'mfa' && r.json.requirement.acr_values === 'mfa',
         '3d7. the resource that challenged answers the stepped-up token 200',
         r.status + ' ' + r.text.slice(0, 300));
    r = await anon.go('POST', '/oauth2/token', {
      headers: { authorization: basic }, noCookies: true,
      form: { grant_type: 'refresh_token', refresh_token: mfaRefresh } });
    at = claimsOf(r.json.access_token);
    note(r.status === 200 && at.acr === 'mfa',
         '3d8. a refreshed access token keeps acr "mfa"',
         r.status + ' ' + JSON.stringify(at).slice(0, 200));

    // --- e. the hierarchy at the authorization endpoint ----------------------
    first = await alice.go('GET', authorizeQuery({ acr_values: '1' }));
    params = codeOf(first);
    note(!!params, '3e1. an mfa session answers acr_values=1 without a ' +
         'sign-in', first.status + ' ' + first.headers.location);
    if (params) {
      r = await redeem(alice, params);
      note(claimsOf(r.json.access_token).acr === '1' &&
           claimsOf(r.json.id_token).acr === '1',
           '3e2. and the tokens carry the REQUESTED "1", not "mfa"',
           claimsOf(r.json.access_token).acr);
    }

    // --- f. max_age ----------------------------------------------------------
    const bob = browser(port);
    first = await bob.go('GET', authorizeQuery());
    done = await signIn(bob, first, 'su-bob');
    params = codeOf(done.final);
    r = await redeem(bob, params);
    const bobAuthTime = claimsOf(r.json.id_token).auth_time;
    const bobToken = r.json.access_token;
    await new Promise(function (resolve) { setTimeout(resolve, 1100); });
    first = await bob.go('GET', authorizeQuery({ max_age: '3600' }));
    note(!!codeOf(first), '3f1. max_age=3600 is met by a session a second old',
         first.status + ' ' + first.headers.location);
    first = await bob.go('GET', authorizeQuery({ max_age: '0' }));
    note(toSignIn(first), '3f2. max_age=0 sends a live session to sign in ' +
         'again (OpenID Connect Core 3.1.2.1)',
         first.status + ' ' + first.headers.location);
    done = await signIn(bob, first, 'su-bob');
    params = codeOf(done.final);
    note(!!params, '3f3. and the fresh sign-in is accepted on the return, ' +
         'without looping', done.final.status + ' ' +
         done.final.headers.location);
    if (params) {
      r = await redeem(bob, params);
      note(claimsOf(r.json.id_token).auth_time > bobAuthTime,
           '3f4. the ID Token\'s auth_time moved',
           claimsOf(r.json.id_token).auth_time + ' > ' + bobAuthTime);
    }

    // --- g. prompt=none ------------------------------------------------------
    first = await bob.go('GET', authorizeQuery({ acr_values: 'mfa',
                                                 prompt: 'none' }));
    params = codeOf(first);
    note(params && params.get('error') === 'login_required',
         '3g1. prompt=none with a requirement the session does not meet is ' +
         'login_required', first.status + ' ' + first.headers.location);

    // --- h. a requirement the sign-in cannot meet ----------------------------
    first = await bob.go('GET', authorizeQuery({
      acr_values: 'urn:example:gold' }));
    note(toSignIn(first), '3h1. a value this sign-in does not produce still ' +
         'gets one attempt — a partner might produce it',
         first.status + ' ' + first.headers.location);
    done = await signIn(bob, first, 'su-bob');
    params = codeOf(done.final);
    note(params && params.get('error') === 'unmet_authentication_requirements',
         '3h2. section 5: refused unmet_authentication_requirements on the ' +
         'return', done.final.status + ' ' + done.final.headers.location);
    first = await bob.go('GET', authorizeQuery({ acr_values: 'mfa',
                                                 step_up_honoured: '1' }));
    params = codeOf(first);
    note(params && params.get('error') === 'unmet_authentication_requirements',
         '3h3. a marker a client put on its own first request buys a ' +
         'refusal, never a one-factor token',
         first.status + ' ' + first.headers.location);

    // The screen's demand is read off the pending record, not off the hidden
    // field it draws: a POST without `use_webauthn` is asked for the factor
    // (su-bob holds none, so the security-key step) rather than signed in with
    // one and refused on the way back.
    first = await bob.go('GET', authorizeQuery({ acr_values: 'mfa' }));
    if (toSignIn(first)) {
      const page = await bob.go('GET', first.headers.location);
      const form = hiddenFields(page.text);
      delete form.use_webauthn;
      form.username = 'su-bob';
      form.password = 'anything';
      form.action = 'login';
      const posted = await bob.go('POST', String(first.headers.location)
        .split('?')[0].replace(/^https?:\/\/[^/]+/, ''), { form: form });
      note(posted.status === 200 && /webauthn/i.test(posted.text) &&
           !posted.headers.location,
           '3h4. a sign-in POST that drops the hidden second-factor field is ' +
           'still asked for the factor', posted.status + ' ' +
           String(posted.headers.location || '') + ' ' +
           posted.text.slice(0, 160));
    } else {
      note(false, '3h4. (acr_values=mfa on a one-factor session goes to sign ' +
           'in)', first.status + ' ' + first.headers.location);
    }

    // --- i. what is refused or stripped before any of it ---------------------
    first = await bob.go('GET', authorizeQuery({ acr_values: 'mfa a"b' }));
    params = codeOf(first);
    note(params && params.get('error') === 'invalid_request' &&
         /acr_values/.test(params.get('error_description') || ''),
         '3i1. an acr value with a quote in it is invalid_request',
         first.status + ' ' + first.headers.location);
    r = await anon.go('POST', '/oauth2/par', {
      headers: { authorization: basic }, noCookies: true,
      form: { response_type: 'code', redirect_uri: REDIRECT, scope: 'openid',
              code_challenge: CHALLENGE, code_challenge_method: 'S256',
              acr_values: 'mfa', step_up_honoured: '1' } });
    const pushed = r.status === 201 ? par.get(r.json.request_uri) : null;
    note(pushed && pushed.parameters.acr_values === 'mfa' &&
         pushed.parameters.step_up_honoured === undefined,
         '3i2. a push keeps acr_values and has the marker stripped',
         r.status + ' ' + JSON.stringify(pushed && pushed.parameters));

    // --- j. this service's own resource server -------------------------------
    r = await anon.go('GET', '/oauth2/userinfo', { noCookies: true,
      headers: { authorization: 'Bearer ' + bobToken } });
    note(r.status === 200, '3j0. (UserInfo answers with nothing required)',
         r.status);
    config.setOverride('oauth2.stepUpAcrValues', 'mfa');
    r = await anon.go('GET', '/oauth2/userinfo', { noCookies: true,
      headers: { authorization: 'Bearer ' + bobToken } });
    note(r.status === 401 &&
         /insufficient_user_authentication/.test(
           r.headers['www-authenticate'] || '') &&
         /acr_values="mfa"/.test(r.headers['www-authenticate'] || ''),
         '3j1. oauth2.stepUpAcrValues makes UserInfo challenge a one-factor ' +
         'token', r.status + ' ' + r.headers['www-authenticate']);
    first = await alice.go('GET', authorizeQuery({ acr_values: 'mfa' }));
    params = codeOf(first);
    r = params ? await redeem(alice, params) : { json: {} };
    const aliceOwn = r.json.access_token;
    r = await anon.go('GET', '/oauth2/userinfo', { noCookies: true,
      headers: { authorization: 'Bearer ' + aliceOwn } });
    note(r.status === 200, '3j2. and answers an mfa token',
         r.status + ' ' + r.text.slice(0, 160));
    config.clearOverride('oauth2.stepUpAcrValues');
    config.setOverride('oauth2.stepUpMaxAgeS', 0);
    await new Promise(function (resolve) { setTimeout(resolve, 1100); });
    r = await anon.go('GET', '/oauth2/userinfo', { noCookies: true,
      headers: { authorization: 'Bearer ' + aliceOwn } });
    note(r.status === 401 &&
         /max_age="0"/.test(r.headers['www-authenticate'] || ''),
         '3j3. oauth2.stepUpMaxAgeS=0 is a real requirement, not "off"',
         r.status + ' ' + r.headers['www-authenticate']);
    config.clearOverride('oauth2.stepUpMaxAgeS');
    r = await anon.go('GET', '/oauth2/userinfo', { noCookies: true,
      headers: { authorization: 'Bearer ' + aliceOwn } });
    note(r.status === 200, '3j4. and -1, the default, requires nothing',
         r.status);

    // --- k. the counters and the view ----------------------------------------
    const row = monitor.snapshot().rows['su-client'] || {};
    // EXACT, because this child's service has seen nothing but this file, and
    // a count of at least two would pass with two events swapped: sent to sign
    // in for acr at 3d1, 3h1 and 3h4, for max_age at 3f2; met after a sign-in
    // at 3d5 and 3f3, by the session at 3e1, 3f1 and 3j2; unmet at 3h2 and 3h3;
    // login_required at 3g1; challenged at 3c1, 3j1 and 3j3.
    const expected = { stepUpReauthAcr: 3, stepUpReauthMaxAge: 1,
                       stepUpMetAfterSignIn: 2, stepUpMetBySession: 3,
                       stepUpUnmet: 2, stepUpLoginRequired: 1,
                       stepUpChallenged: 3, stepUpSignIn: 0 };
    note(Object.keys(expected).every(function (k) {
      return row[k] === expected[k];
    }), '3k1. every event is counted against the client, once each',
         JSON.stringify(row));
    const view = monitorConsole.monitorView({ query: {} });
    const section = view.sections.filter(function (one) {
      return one.id === 'stepup';
    })[0];
    note(section && section.clientsParam === 'stepUpClientsPage' &&
         section.ownResourceRequirement.max_age === null &&
         section.events.length === 8 &&
         section.clients.some(function (c) {
           return c.client_id === 'su-client';
         }),
         '3k2. the monitoring view carries the step-up section, paged under ' +
         'its own parameter', JSON.stringify(section).slice(0, 300));

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  t.log.info('=== 3. the endpoints, in a child process ===');
  const out = path.join(os.tmpdir(), 'rfc9470-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SU_ROOT: ROOT, SU_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  library(t);
  registry(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rfc9470 step-up authentication',
  describe: 'RFC 9470: the levels and the challenge, the two application ' +
            'attributes, re-authentication for acr_values and max_age, ' +
            'unmet_authentication_requirements, acr and auth_time in tokens ' +
            'and introspection, the stand-in resource, UserInfo under the ' +
            'two settings, and the counters',
  run: run
};
