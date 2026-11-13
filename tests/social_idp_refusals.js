// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/social_idp_refusals.js
//
// ===========================================================================
// THE DUMMY SOCIAL PROVIDERS REFUSE WHAT A PROVIDER WOULD (#1689's review,
// 2026-11-13).
//
// `tests/social_idp_signins.js` signs in through each dummy, which holds
// what the dummies ACCEPT. The review found two things they accepted that a
// real provider refuses, and that matters as soon as a dummy is a negative
// fixture:
//
//   A. A token request whose `redirect_uri` is not the one its code was
//      issued to (RFC 6749 section 4.1.3), or names none, is invalid_grant
//      and spends the code; the right one still redeems. A code-grant dummy
//      (GitHub, client_secret_post) and Bluesky (pushed, DPoP-bound).
//   B. Steam's `check_authentication` confirms a nonce ONCE: a replayed
//      assertion is not valid (OpenID 2.0 section 11.4.2.1). A check that
//      fails (another claimed id) does not forget the nonce, so the right
//      check after it still confirms.
//
// In process, against the module on a loopback port, as the sign-in file
// serves it; nothing of the service is loaded.
// ===========================================================================

const crypto = require('crypto');
const http = require('http');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'social_idp_refusals',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const { SocialIdps } = require(path.join(ROOT, 'companion', 'social_idps'));

const SECRET = 'companion-secret';
const DPOP_NONCE = 'companion-dpop-nonce';
const RP = 'http://rp.example/federation/acs/one';

/**
 * One request to the dummy.
 *
 * @param {number} port - the dummy's port
 * @param {string} method - GET or POST
 * @param {string} target - the path and query
 * @param {object} [form] - a body, form-encoded
 * @param {object} [headers] - more headers
 * @returns {Promise<object>} `{ status, headers, text, json }`
 */
function ask(port, method, target, form, headers) {
  log.debug("Entering ask(). " + method + " " + target.split('?')[0]);
  const body = form ? new URLSearchParams(form).toString() : '';
  const all = Object.assign({}, headers || {});
  if (form) {
    all['content-type'] = 'application/x-www-form-urlencoded';
    all['content-length'] = Buffer.byteLength(body);
  }
  log.debug("Leaving ask().");
  return new Promise(function (resolve, reject) {
    const req = http.request({ host: '127.0.0.1', port: port,
                               method: method, path: target,
                               headers: all }, function (res) {
      let text = '';
      res.on('data', function (chunk) {
        text += chunk;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in ask(): " + ((e && e.message) || e));
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers,
                  text: text, json: json });
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

/**
 * The S256 challenge of a verifier.
 *
 * @param {string} verifier - the PKCE verifier
 * @returns {string} its challenge
 */
function challengeOf(verifier) {
  log.debug("Entering challengeOf().");
  log.debug("Leaving challengeOf().");
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

/**
 * A DPoP proof (RFC 9449) for a POST to `htu`, with the dummy's nonce.
 *
 * @param {object} keys - an ES256 key pair
 * @param {string} htu - the URL the proof names
 * @returns {string} the proof
 */
function dpopProof(keys, htu) {
  log.debug("Entering dpopProof().");
  const jwk = keys.publicKey.export({ format: 'jwk' });
  const header = { typ: 'dpop+jwt', alg: 'ES256',
                   jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
  const payload = { htm: 'POST', htu: htu, jti: crypto.randomUUID(),
                    iat: Math.floor(Date.now() / 1000), nonce: DPOP_NONCE };
  const input = Buffer.from(JSON.stringify(header)).toString('base64url') +
    '.' + Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.sign('sha256', Buffer.from(input),
    { key: keys.privateKey, dsaEncoding: 'ieee-p1363' });
  log.debug("Leaving dpopProof().");
  return input + '.' + sig.toString('base64url');
}

/**
 * A code from GitHub's dummy, issued to `RP`.
 *
 * @param {number} port - the dummy's port
 * @param {string} verifier - the PKCE verifier
 * @returns {Promise<string>} the code, or '' when none came back
 */
async function githubCode(port, verifier) {
  log.debug("Entering githubCode().");
  const query = new URLSearchParams({
    client_id: 'companion-github', redirect_uri: RP, response_type: 'code',
    code_challenge: challengeOf(verifier), code_challenge_method: 'S256',
    state: 's1'
  });
  const got = await ask(port, 'GET', '/social/github/authorize?' + query);
  let code = '';
  try {
    code = new URL(String(got.headers.location || '')).searchParams
      .get('code') || '';
  } catch (e) {
    log.debug("Caught in githubCode(): " + ((e && e.message) || e));
    code = '';
  }
  log.debug("Leaving githubCode().");
  return code;
}

/**
 * GitHub's token request with a chosen `redirect_uri` (none when null).
 *
 * @param {number} port - the dummy's port
 * @param {string} code - the code
 * @param {string} verifier - the PKCE verifier
 * @param {string|null} redirect - the redirect_uri to send
 * @returns {Promise<object>} the answer
 */
function githubToken(port, code, verifier, redirect) {
  log.debug("Entering githubToken().");
  const form = { grant_type: 'authorization_code', code: code,
                 client_id: 'companion-github', client_secret: SECRET,
                 code_verifier: verifier };
  if (redirect !== null) {
    form.redirect_uri = redirect;
  }
  log.debug("Leaving githubToken().");
  return ask(port, 'POST', '/social/github/token', form);
}

async function run(t) {
  log.debug("Entering run().");
  const social = new SocialIdps({ publicUrl: 'http://127.0.0.1' });
  const server = http.createServer(function (req, res) {
    social.handle(req, res);
  });
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const base = 'http://127.0.0.1:' + port;
  social.setPublicUrl(base);
  try {
    // -----------------------------------------------------------------
    // A. THE TOKEN REQUEST'S redirect_uri.
    // -----------------------------------------------------------------
    const verifier = crypto.randomBytes(32).toString('base64url');
    const code = await githubCode(port, verifier);
    const other = await githubToken(port, code, verifier,
                                    'http://rp.example/elsewhere');
    t.check(code && other.status === 400 && other.json &&
            other.json.error === 'invalid_grant' &&
            !(other.json && other.json.access_token),
            'A. GitHub\'s dummy refuses a token request whose redirect_uri ' +
            'is not the one the code was issued to (invalid_grant)',
            other.status + ' ' + other.text);
    const after = await githubToken(port, code, verifier, RP);
    t.check(after.status === 400 && after.json &&
            after.json.error === 'invalid_grant',
            'and that refusal spent the code: the right redirect_uri ' +
            'cannot redeem it afterwards', after.status + ' ' + after.text);
    const code2 = await githubCode(port, verifier);
    const none = await githubToken(port, code2, verifier, null);
    t.check(code2 && none.status === 400 && none.json &&
            none.json.error === 'invalid_grant',
            'a token request naming no redirect_uri is refused too',
            none.status + ' ' + none.text);
    const code3 = await githubCode(port, verifier);
    const good = await githubToken(port, code3, verifier, RP);
    t.check(code3 && good.status === 200 && good.json &&
            /^at-/.test(String(good.json.access_token || '')),
            'and the redirect_uri the code was issued to redeems it',
            good.status + ' ' + good.text);

    const keys = crypto.generateKeyPairSync('ec',
                                            { namedCurve: 'prime256v1' });
    const blueskyCode = async function () {
      log.debug("Entering blueskyCode().");
      const pushed = await ask(port, 'POST', '/social/bluesky/par', {
        response_type: 'code', redirect_uri: RP, state: 'b1',
        code_challenge: challengeOf(verifier),
        code_challenge_method: 'S256'
      }, { dpop: dpopProof(keys, base + '/social/bluesky/par') });
      const uri = (pushed.json && pushed.json.request_uri) || '';
      const got = await ask(port, 'GET', '/social/bluesky/authorize?' +
        new URLSearchParams({ request_uri: uri }));
      let found = '';
      try {
        found = new URL(String(got.headers.location || '')).searchParams
          .get('code') || '';
      } catch (e) {
        log.debug("Caught in run(): " + ((e && e.message) || e));
        found = '';
      }
      log.debug("Leaving blueskyCode().");
      return found;
    };
    const blueskyToken = function (found, redirect) {
      log.debug("Entering blueskyToken().");
      log.debug("Leaving blueskyToken().");
      return ask(port, 'POST', '/social/bluesky/token', {
        grant_type: 'authorization_code', code: found,
        redirect_uri: redirect, code_verifier: verifier
      }, { dpop: dpopProof(keys, base + '/social/bluesky/token') });
    };
    const bsCode = await blueskyCode();
    const bsOther = await blueskyToken(bsCode,
                                       'http://rp.example/elsewhere');
    const bsAfter = await blueskyToken(bsCode, RP);
    t.check(bsCode && bsOther.status === 400 && bsOther.json &&
            bsOther.json.error === 'invalid_grant' &&
            bsAfter.status === 400,
            'Bluesky\'s dummy refuses another redirect_uri than the ' +
            'pushed request\'s, and the code is spent',
            bsOther.status + ' ' + bsOther.text + ' / ' + bsAfter.status);
    const bsCode2 = await blueskyCode();
    const bsGood = await blueskyToken(bsCode2, RP);
    t.check(bsCode2 && bsGood.status === 200 && bsGood.json &&
            bsGood.json.token_type === 'DPoP',
            'and redeems a code with the pushed redirect_uri',
            bsGood.status + ' ' + bsGood.text);

    // -----------------------------------------------------------------
    // B. STEAM'S check_authentication CONFIRMS A NONCE ONCE.
    // -----------------------------------------------------------------
    const login = await ask(port, 'GET', '/social/steam/login?' +
      new URLSearchParams({ 'openid.mode': 'checkid_setup',
                            'openid.return_to': RP }));
    let assertion = null;
    try {
      assertion = new URL(String(login.headers.location || '')).searchParams;
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      assertion = null;
    }
    const check = function (overrides) {
      log.debug("Entering check().");
      const form = {};
      (assertion || new URLSearchParams()).forEach(function (value, name) {
        form[name] = value;
      });
      form['openid.mode'] = 'check_authentication';
      log.debug("Leaving check().");
      return ask(port, 'POST', '/social/steam/login',
                 Object.assign(form, overrides || {}));
    };
    const wrong = await check({ 'openid.claimed_id':
      'https://steamcommunity.com/openid/id/1' });
    const first = await check();
    const replay = await check();
    t.check(!!assertion && /is_valid:false/.test(wrong.text),
            'B. Steam\'s dummy answers is_valid:false for another claimed ' +
            'id', wrong.text);
    t.check(/is_valid:true/.test(first.text),
            'and that failed check did not forget the nonce: the right ' +
            'check confirms it', first.text);
    t.check(/is_valid:false/.test(replay.text),
            'and the same assertion checked again is not valid: a ' +
            'replayed nonce is refused', replay.text);
  } finally {
    server.close();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'social_idp_refusals',
  describe: 'the dummy social providers refuse a token request with ' +
            'another redirect_uri (spending the code), and Steam\'s ' +
            'check_authentication refuses a replayed nonce (#1689\'s ' +
            'review)',
  run: run
};
