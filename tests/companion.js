// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/companion.js
//
// ===========================================================================
// THE DEVELOPMENT COMPANION'S OWN PAGES (#594), against a stand-in for the
// service.
//
// `companion/` is a second container that plays the OpenID4VC
// demonstration's issuer and verifier in front of the service, as an outside
// party (`companion/CLAUDE.md`). What this holds of it, with its one door
// into the service — `sts_client.js` — replaced by a stand-in that records
// what was asked and answers what the service would:
//
//   1. the start page lists the demonstration; every page carries the
//      companion's policy (no script at all) and the browser gets one
//      HttpOnly SameSite=Lax session cookie;
//   2. the issuer's page lists what the issuer's metadata offers and sends a
//      pre-authorized offer to the service's own `/portal/wallet`;
//   3. its offer is the authorization_code grant with NO issuer_state,
//      naming the issuer and the configuration, drawn as an SVG QR code; a
//      configuration the issuer does not offer is refused;
//   4. a start without the form's token, or from another origin, is refused
//      and asks the service nothing;
//   5. a same-device start names the companion's completion page as
//      `redirect_uri` and sends the browser to the wallet; a cross-device
//      one names none and waits on a refreshed QR page;
//   6. the completion page shows what the Verifier decided — to the browser
//      that started it, and to no other.
//
// In process: the companion requires nothing of the service, so nothing
// here loads the protocol stack.
// ===========================================================================

const http = require('http');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'companion',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const STS = 'https://sts.example:8081';
const PUBLIC = 'http://companion.test:9700';

/**
 * A stand-in for the companion's client of the service.
 *
 * @returns {object} the stand-in, its `calls` and its `verdicts`
 */
function standIn() {
  log.debug("Entering standIn().");
  const calls = [];
  const verdicts = {};
  let n = 0;
  const sts = {
    publicBase: STS,
    calls: calls,
    verdicts: verdicts,
    issuerMetadata: async function () {
      return { credential_issuer: STS,
               credential_configurations_supported: {
                 IdentityCredential: { format: 'dc+sd-jwt',
                   credential_metadata: { display: [{ name: 'Diploma' }] } }
               } };
    },
    adminApi: async function (method, where, json) {
      calls.push({ method: method, where: where, json: json });
      if (method === 'GET' && where === '/verifier-request') {
        return { status: 200, json: { format: 'dc+sd-jwt',
          formats: [{ id: 'dc+sd-jwt', label: 'SD-JWT VC' }],
          requested: ['given_name'] } };
      }
      if (method === 'POST' && where === '/verifications/start') {
        n += 1;
        const state = 'state-' + n;
        const query = 'client_id=x&state=' + state;
        return { status: 200, json: { ok: true, state: state,
          wallet: 'https://wallet.example/present',
          walletUrl: 'https://wallet.example/present?' + query,
          requestUri: 'openid4vp://?' + query,
          redirectUri: (json && json.redirect_uri) || '' } };
      }
      const m = /^\/verifications\?state=(.*)$/.exec(where);
      if (method === 'GET' && m) {
        const state = decodeURIComponent(m[1]);
        const verdict = verdicts[state] || null;
        return { status: 200, json: { found: true, state: state,
          received: !!verdict, verdict: verdict } };
      }
      return { status: 404, json: null, text: 'no' };
    }
  };
  log.debug("Leaving standIn().");
  return sts;
}

/**
 * One request to the companion, as a browser with a jar.
 *
 * @param {number} port - the companion's port
 * @param {string} method - the method
 * @param {string} where - the path
 * @param {object} [opts] - `jar`, `form`, `origin`
 * @returns {Promise<object>} `{ status, headers, text }`
 */
function hit(port, method, where, opts) {
  log.debug("Entering hit(). " + method + " " + where);
  const o = opts || {};
  const headers = {};
  const jar = o.jar || {};
  const cookie = Object.keys(jar).map(function (k) {
    return k + '=' + jar[k];
  }).join('; ');
  if (cookie) {
    headers.cookie = cookie;
  }
  let body = '';
  if (o.form) {
    body = new URLSearchParams(o.form).toString();
    headers['content-type'] = 'application/x-www-form-urlencoded';
    headers['content-length'] = Buffer.byteLength(body);
  }
  if (o.origin) {
    headers.origin = o.origin;
  }
  log.debug("Leaving hit().");
  return new Promise(function (resolve, reject) {
    const req = http.request({ host: '127.0.0.1', port: port, path: where,
                               method: method, headers: headers },
                             function (res) {
      let text = '';
      res.on('data', function (c) {
        text += c;
      });
      res.on('end', function () {
        [].concat(res.headers['set-cookie'] || []).forEach(function (line) {
          const pair = String(line).split(';')[0];
          const at = pair.indexOf('=');
          jar[pair.slice(0, at)] = pair.slice(at + 1);
        });
        resolve({ status: res.statusCode, headers: res.headers, text: text });
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

/**
 * The form token a page carries.
 *
 * @param {string} html - the page
 * @returns {string} the token, or ''
 */
function csrfOf(html) {
  log.debug("Entering csrfOf().");
  const m = /name="csrf" value="([^"]+)"/.exec(String(html));
  log.debug("Leaving csrfOf().");
  return m ? m[1] : '';
}

async function run(t) {
  log.debug("Entering run().");
  const { Companion } = require(path.join(ROOT, 'companion', 'companion.js'));
  const sts = standIn();
  const companion = new Companion({ port: 0, publicUrl: PUBLIC,
                                    walletUrl: '' }, { sts: sts });
  const server = await companion.listen();
  const port = server.address().port;
  try {
    // --- 1 -----------------------------------------------------------------
    const jar = {};
    let r = await hit(port, 'GET', '/', { jar: jar });
    const policy = String(r.headers['content-security-policy'] || '');
    const set = [].concat(r.headers['set-cookie'] || []).join(' ');
    t.check(r.status === 200 && /href="\/issuer"/.test(r.text) &&
            /href="\/verifier"/.test(r.text) &&
            /default-src 'none'/.test(policy) &&
            /frame-ancestors 'none'/.test(policy) &&
            !/script-src/.test(policy) && !/<script/i.test(r.text) &&
            /companion_sid=[^;]+; Path=\/; HttpOnly; SameSite=Lax/.test(set),
            '1. the start page lists the demonstration, carries no script ' +
            'and the companion\'s policy, and sets one session cookie',
            r.status + ' ' + policy + ' ' + set);

    // --- 2 -----------------------------------------------------------------
    r = await hit(port, 'GET', '/issuer', { jar: jar });
    t.check(r.status === 200 && /Diploma/.test(r.text) &&
            /href="\/issuer\/offer\?configuration=IdentityCredential"/
              .test(r.text) &&
            r.text.indexOf('href="' + STS + '/portal/wallet"') >= 0,
            '2. the issuer\'s page lists the issuer\'s configurations and ' +
            'sends a pre-authorized offer to the portal', r.status);

    // --- 3 -----------------------------------------------------------------
    r = await hit(port, 'GET', '/issuer/offer?configuration=IdentityCredential',
                  { jar: jar });
    const m = /id="offer-uri">([^<]+)</.exec(r.text);
    let offer = null;
    if (m) {
      const uri = m[1].replace(/&amp;/g, '&');
      offer = JSON.parse(new URL(uri.replace('openid-credential-offer://',
        'https://x.invalid/')).searchParams.get('credential_offer'));
    }
    t.check(r.status === 200 && offer && offer.credential_issuer === STS &&
            JSON.stringify(offer.credential_configuration_ids) ===
              '["IdentityCredential"]' &&
            offer.grants && offer.grants.authorization_code &&
            !('issuer_state' in offer.grants.authorization_code) &&
            !offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_' +
                          'code'] &&
            /<svg[\s\S]*<\/svg>/.test(r.text),
            '3a. the offer is the authorization code grant with no ' +
            'issuer_state, drawn as an SVG QR code', JSON.stringify(offer));
    r = await hit(port, 'GET', '/issuer/offer?configuration=Nope',
                  { jar: jar });
    t.check(r.status === 400,
            '3b. a configuration the issuer does not offer is refused',
            r.status);

    // --- 4 -----------------------------------------------------------------
    r = await hit(port, 'GET', '/verifier', { jar: jar });
    const csrf = csrfOf(r.text);
    t.check(r.status === 200 && !!csrf && /given_name/.test(r.text),
            '4a. the bar door says what it asks for and carries the form\'s ' +
            'token', r.status);
    const before = sts.calls.length;
    r = await hit(port, 'POST', '/verifier/start', { jar: jar,
      form: { mode: 'same-device' } });
    const noToken = r.status;
    r = await hit(port, 'POST', '/verifier/start', { jar: jar,
      origin: 'https://evil.example', form: { mode: 'same-device',
                                               csrf: csrf } });
    const foreign = r.status;
    r = await hit(port, 'POST', '/verifier/start', { jar: {},
      form: { mode: 'same-device', csrf: csrf } });
    t.check(noToken === 403 && foreign === 403 && r.status === 403 &&
            sts.calls.length === before,
            '4b. a start without the token, from another origin, or from ' +
            'another browser is refused and asks the service nothing',
            [noToken, foreign, r.status].join(','));

    // --- 5 -----------------------------------------------------------------
    r = await hit(port, 'POST', '/verifier/start', { jar: jar,
      origin: PUBLIC, form: { mode: 'same-device', csrf: csrf,
                              format: 'dc+sd-jwt', by: 'reference' } });
    let asked = sts.calls[sts.calls.length - 1];
    t.check(r.status === 303 &&
            r.headers.location === 'https://wallet.example/present?' +
              'client_id=x&state=state-1' &&
            asked.where === '/verifications/start' &&
            asked.json.redirect_uri === PUBLIC + '/verifier/done' &&
            asked.json.format === 'dc+sd-jwt' && asked.json.by === 'reference',
            '5a. a same-device start names the companion\'s completion page ' +
            'and sends the browser to the wallet',
            r.status + ' ' + JSON.stringify(asked.json));
    r = await hit(port, 'POST', '/verifier/start', { jar: jar,
      form: { mode: 'cross-device', csrf: csrf } });
    asked = sts.calls[sts.calls.length - 1];
    const waited = await hit(port, 'GET', '/verifier/wait', { jar: jar });
    t.check(r.status === 303 && r.headers.location === '/verifier/wait' &&
            !('redirect_uri' in asked.json) && waited.status === 200 &&
            /<meta http-equiv="refresh"/.test(waited.text) &&
            /<svg/.test(waited.text) &&
            waited.text.indexOf('openid4vp://?client_id=x&amp;state=' +
                                'state-2') >= 0,
            '5b. a cross-device start names no page and waits on a ' +
            'refreshed QR page', r.status + ' ' + JSON.stringify(asked.json));

    // --- 6 -----------------------------------------------------------------
    sts.verdicts['state-2'] = { ok: true, claims: { given_name: 'Ada' },
                                checks: [] };
    r = await hit(port, 'GET', '/verifier/done', { jar: jar });
    const other = await hit(port, 'GET', '/verifier/done', { jar: {} });
    t.check(r.status === 200 && /id="accepted"/.test(r.text) &&
            /Ada/.test(r.text) && other.status === 200 &&
            /id="nothing"/.test(other.text) && !/Ada/.test(other.text),
            '6. the completion page shows the verdict to the browser that ' +
            'started it, and to no other', r.status + ' ' + other.status);
    r = await hit(port, 'GET', '/healthz');
    t.check(r.status === 200 && JSON.parse(r.text).demos[0] === 'oid4vc',
            '7. /healthz says the companion is up and what it plays', r.text);
  } finally {
    server.close();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'companion',
  describe: 'the development companion (#594) plays the OpenID4VC issuer and ' +
            'verifier in front of the service, as an outside party',
  run: run
};
