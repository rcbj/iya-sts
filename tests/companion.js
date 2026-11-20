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
//   8. THE KERBEROS AND SPNEGO DEMONSTRATION (#595), its acceptor (MIT's
//      GSS-API in the image) replaced by a stand-in and `sts_client.js`'s
//      own keytab provisioning driven over a stubbed `/admin-api`: the
//      principal asked for, created — or, already held, rotated — and its
//      keytab written where only the process reads it and named to MIT as
//      KRB5_KTNAME; `/spnego` and its JSON; `/spnego/protected`'s RFC 4559
//      exchange — the bare challenge, a wrong scheme, an accepted token
//      answered with the acceptor's token, a refused one; the TCP service —
//      the AP-REP framed back, a clean close without mutual authentication,
//      and a refusal as a KRB-ERROR the service's own vendored codec reads
//      with the code MIT's message names; `/krb5/service`.
//   7. `/healthz` lists the demonstrations, the OpenID4VC one first, and
//      the social dummies among them (#1689).
//   7b. a token POST under `/social` with no session cookie is the dummy's
//      `invalid_grant`, not the CSRF page: the service posts there.
//   9. THE REMOTE PEP'S UPSTREAM APPLICATION (#1760), `/pep-app`: each page
//      echoes the method, the RAW path (a dot segment as sent), the query
//      and every header as JSON, sets no session cookie, and counts the
//      request on `/pep-app/_hits` (which counts nothing itself); a POST
//      to `/pep-app/api/items` is a 201 carrying the body's length and
//      SHA-256 with no form token; `/pep-app/public/hop` answers
//      `Connection: x-upstream-secret` with that header beside an
//      end-to-end one; `/pep-app/slow` waits what it was asked, bounded.
//  10. AND THE IDENTITY IT READS (#1760, D11): `_setup` taking the audience,
//      a signing key and a JWKS; a Bearer JWT decoded and verified against
//      the JWKS, a changed one echoed as not verified; the ACS accepting a
//      signed response for its audience and setting `pep_app_saml`, the
//      next echo carrying that session, and a tampered, foreign-audience or
//      unsigned response refused with no cookie.
//
// In process: the companion requires nothing of the service, so nothing
// here loads the protocol stack.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const net = require('net');
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
 * One length-prefixed message to a TCP service, and what came back before
 * the connection closed or a framed reply arrived.
 *
 * @param {number} port - the port
 * @param {Buffer} message - the message, unframed
 * @returns {Promise<object>} `{ reply (Buffer|null), closed }`
 */
function tcpExchange(port, message) {
  log.debug("Entering tcpExchange().");
  log.debug("Leaving tcpExchange().");
  return new Promise(function (resolve, reject) {
    const socket = net.connect(port, '127.0.0.1');
    let got = Buffer.alloc(0);
    socket.on('data', function (chunk) {
      got = Buffer.concat([got, chunk]);
      if (got.length >= 4 && got.length >= 4 + got.readUInt32BE(0)) {
        socket.destroy();
        resolve({ reply: got.subarray(4, 4 + got.readUInt32BE(0)),
                  closed: false });
      }
    });
    socket.on('end', function () {
      resolve({ reply: got.length ? got : null, closed: true });
    });
    socket.on('close', function () {
      resolve({ reply: got.length ? got : null, closed: true });
    });
    socket.on('error', reject);
    const framed = Buffer.alloc(4 + message.length);
    framed.writeUInt32BE(message.length, 0);
    message.copy(framed, 4);
    socket.write(framed);
  });
}

/**
 * The Kerberos demonstration (#595), against a stand-in acceptor and a
 * stubbed `/admin-api`.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {Promise<void>} when done
 */
async function kerberosDemonstration(t) {
  log.debug("Entering kerberosDemonstration().");
  const { Companion } = require(path.join(ROOT, 'companion', 'companion.js'));
  const { StsClient } = require(path.join(ROOT, 'companion',
                                          'sts_client.js'));
  const { tokenKind } = require(path.join(ROOT, 'companion',
                                          'demo_kerberos.js'));
  const msgs = require(path.join(ROOT, 'kerberos', 'krb5_messages.js'));
  // `sts_client.js` itself, with only the door into the service stubbed:
  // the provisioning logic is what is under test.
  const sts = new StsClient({ stsUrl: STS, clientId: 'c',
                              clientSecret: 's' });
  const asked = [];
  const KEYTAB = Buffer.from('0502000000ff', 'hex');
  sts.adminApi = async function (method, where, json) {
    asked.push({ method: method, where: where, json: json });
    if (where === '/kerberos/principals/create-service') {
      // Held from an earlier start: the companion keeps nothing.
      return { status: 400, json: { ok: false }, text: 'already holds' };
    }
    if (where === '/kerberos/principals/rotate-service') {
      return { status: 200, text: '', json: { ok: true,
        principal: json.spn + '@EXAMPLE.COM', kvno: 4, etypes: [18, 17],
        keytabKvnos: [4, 3], keytab: KEYTAB.toString('base64') } };
    }
    return { status: 404, json: null, text: 'no' };
  };
  // The acceptor: a token whose first byte names what happens.
  const seen = [];
  const gss = {
    accept: async function (token) {
      seen.push(token);
      if (token[1] === 0x01) {
        return { ok: true, client: 'alice@EXAMPLE.COM<b>',
                 response: Buffer.from('a1-acceptor-token'), error: '' };
      }
      if (token[1] === 0x02) {
        return { ok: true, client: 'bob@EXAMPLE.COM', response: null,
                 error: '' };
      }
      return { ok: false, client: '', response: null,
               error: 'Unspecified GSS failure.  Minor code may provide ' +
                      'more information: Clock skew too great <x>' };
    }
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'companion-krb5-test-'));
  const before = process.env.KRB5_KTNAME;
  const companion = new Companion({ port: 0, publicUrl: PUBLIC,
                                    walletUrl: '', krb5Spn: '',
                                    krb5ServicePort: 0,
                                    krb5KeytabDir: dir },
                                  { sts: sts, gss: gss });
  const server = await companion.listen();
  const port = server.address().port;
  const kerberos = companion.demos.filter(function (d) {
    return d.describe().id === 'kerberos';
  })[0];
  try {
    // --- 8a. the principal and its keytab ---------------------------------
    let r = await hit(port, 'GET', '/spnego');
    const file = path.join(dir, 'companion.keytab');
    const mode = fs.statSync(file).mode & 0o777;
    t.check(r.status === 200 &&
            r.text.indexOf('HTTP/companion.test@EXAMPLE.COM') >= 0 &&
            asked.length === 2 &&
            asked[0].where === '/kerberos/principals/create-service' &&
            asked[0].json.spn === 'HTTP/companion.test' &&
            asked[1].where === '/kerberos/principals/rotate-service' &&
            fs.readFileSync(file).equals(KEYTAB) && mode === 0o600 &&
            process.env.KRB5_KTNAME === 'FILE:' + file &&
            !/<script/i.test(r.text),
            '8a. the principal is HTTP/<the public host>; one already held ' +
            'is rotated rather than created, and its keytab is written ' +
            'where only this process reads it and named to MIT',
            r.status + ' ' + JSON.stringify(asked) + ' mode=' +
            mode.toString(8));
    r = await hit(port, 'GET', '/spnego?format=json');
    let j = JSON.parse(r.text);
    t.check(r.status === 200 && j.protectedResource === '/spnego/protected' &&
            j.servicePrincipalName === 'HTTP/companion.test@EXAMPLE.COM' &&
            j.realm === 'EXAMPLE.COM' && j.kvno === 4 &&
            j.signInResource === STS + '/authn/spnego' &&
            asked.length === 2,
            '8b. /spnego?format=json is the advertisement, and the keytab is ' +
            'asked for once', r.text.slice(0, 300));

    // --- 8c. the RFC 4559 exchange ----------------------------------------
    r = await hit(port, 'GET', '/spnego/protected');
    t.check(r.status === 401 && r.headers['www-authenticate'] ===
              'Negotiate' && r.headers['cache-control'] === 'no-store' &&
            !/<script/i.test(r.text),
            '8c. without a ticket: 401 and a bare Negotiate challenge',
            r.status + ' ' + r.headers['www-authenticate']);
    const asBasic = await new Promise(function (resolve, reject) {
      http.get({ host: '127.0.0.1', port: port, path: '/spnego/protected',
                 headers: { authorization: 'Basic eDp5' } }, function (res) {
        let text = '';
        res.on('data', function (c) {
          text += c;
        });
        res.on('end', function () {
          resolve({ status: res.statusCode, headers: res.headers,
                    text: text });
        });
      }).on('error', reject);
    });
    t.check(asBasic.status === 401 &&
            asBasic.headers['www-authenticate'] === 'Negotiate' &&
            /<code>Basic<\/code>/.test(asBasic.text),
            '8d. a wrong scheme: 401 Negotiate, and the page names it',
            asBasic.status);
    const negotiate = function (token) {
      return new Promise(function (resolve, reject) {
        http.get({ host: '127.0.0.1', port: port, path: '/spnego/protected',
                   headers: { authorization: 'Negotiate ' +
                              token.toString('base64') } }, function (res) {
          let text = '';
          res.on('data', function (c) {
            text += c;
          });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        }).on('error', reject);
      });
    };
    const accepted = Buffer.from('6001060100', 'hex');
    r = await negotiate(accepted);
    t.check(r.status === 200 && r.headers['www-authenticate'] ===
              'Negotiate ' + Buffer.from('a1-acceptor-token')
                .toString('base64') &&
            r.text.indexOf('alice@EXAMPLE.COM&lt;b&gt;') >= 0 &&
            seen[seen.length - 1].equals(accepted),
            '8e. an accepted token: 200, the acceptor\'s token back in ' +
            'WWW-Authenticate, the client named (escaped)', r.status + ' ' +
            r.headers['www-authenticate']);
    r = await negotiate(Buffer.from('6003060100', 'hex'));
    t.check(r.status === 401 && r.headers['www-authenticate'] ===
              'Negotiate' &&
            /Clock skew too great &lt;x&gt;/.test(r.text),
            '8f. a refused token: 401 Negotiate, and MIT\'s reason on the ' +
            'page (escaped)', r.status);

    // --- 8g. the TCP service ----------------------------------------------
    const tcp = kerberos.socket.port;
    let x = await tcpExchange(tcp, Buffer.from('6001060100', 'hex'));
    t.check(!!x.reply && x.reply.equals(Buffer.from('a1-acceptor-token')),
            '8g. the TCP service frames the acceptor\'s AP-REP back',
            x.reply && x.reply.toString('hex'));
    x = await tcpExchange(tcp, Buffer.from('6002060100', 'hex'));
    t.check(x.closed && !x.reply,
            '8h. accepted with no mutual authentication: closed, nothing ' +
            'sent', JSON.stringify(x));
    x = await tcpExchange(tcp, Buffer.from('6003060100', 'hex'));
    let error = null;
    try {
      error = msgs.readKrbError(new Uint8Array(x.reply));
    } catch (e) {
      log.debug("Caught in kerberosDemonstration(): " +
                ((e && e.message) || e));
      error = { problem: String(e && e.message) };
    }
    t.check(error && error.pvno === 5 && error.msgType === 30 &&
            error.errorCode === 37 && error.realm === 'EXAMPLE.COM' &&
            error.sname && error.sname.name.join('/') ===
              'HTTP/companion.test' &&
            /Clock skew too great/.test(error.eText),
            '8i. a refusal is a KRB-ERROR the service\'s own codec reads: ' +
            'KRB_AP_ERR_SKEW, as MIT\'s message names it', JSON.stringify(
              error));
    r = await hit(port, 'GET', '/krb5/service');
    j = JSON.parse(r.text);
    t.check(r.status === 200 && j.listening === true && j.port === tcp &&
            j.principal === 'HTTP/companion.test@EXAMPLE.COM' &&
            j.lastExchange && j.lastExchange.ok === false,
            '8j. /krb5/service describes the socket and its last exchange',
            r.text.slice(0, 300));
    t.check(tokenKind(Buffer.concat([Buffer.from('6082000006062b0601050502',
                                                 'hex'),
                                     Buffer.alloc(8)])) === 'SPNEGO' &&
            tokenKind(Buffer.concat([Buffer.from('6082000006092a864886f7' +
                                                 '12010202', 'hex'),
                                     Buffer.alloc(8)])) === 'Kerberos' &&
            tokenKind(Buffer.from('NTLMSSP\0\x01\0\0\0', 'latin1')) ===
              'NTLM',
            '8k. a token is told apart by its mechanism OID');
    r = await hit(port, 'GET', '/healthz');
    t.check(JSON.parse(r.text).demos.indexOf('kerberos') >= 0,
            '8l. /healthz lists the Kerberos demonstration', r.text);
  } finally {
    server.close();
    if (before === undefined) {
      delete process.env.KRB5_KTNAME;
    } else {
      process.env.KRB5_KTNAME = before;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving kerberosDemonstration().");
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

async function urlAndKeytabFailure(t) {
  log.debug("Entering urlAndKeytabFailure().");
  const util = require(path.join(ROOT, 'companion', 'companion_util.js'));
  const slash = '/' + '/'.repeat(20000);
  t.check(util.stripTrailingSlashes('http://companion.test:9700' + slash) ===
            'http://companion.test:9700' &&
          util.stripTrailingSlashes('') === '' &&
          util.stripTrailingSlashes(null) === '',
          'trailing slashes are dropped without a regular expression');
  const query = '/spnego' + '?'.repeat(20000) + 'x';
  t.check(util.stripQuery('/spnego?format=json') === '/spnego' &&
          util.stripQuery('/spnego') === '/spnego' &&
          util.stripQuery(query) === '/spnego' &&
          util.stripQuery(undefined) === 'undefined',
          'a query string is cut at the first ?');
  const { settingsFrom } = require(path.join(ROOT, 'companion',
                                              'companion.js'));
  const settings = settingsFrom({
    COMPANION_PUBLIC_URL: 'http://companion.test:9700///',
    COMPANION_PORT: '1'
  });
  t.check(settings.publicUrl === 'http://companion.test:9700',
          'COMPANION_PUBLIC_URL loses its trailing slashes');
  const { KerberosDemo } = require(path.join(ROOT, 'companion',
                                              'demo_kerberos.js'));
  const demo = new KerberosDemo({
    sts: { publicBase: STS }, publicUrl: PUBLIC + '///',
    servicePort: null, gss: {}
  });
  t.check(demo.publicUrl === PUBLIC,
          'the Kerberos demonstration drops a trailing slash');
  demo.ensureKeytab = async function () {
    const err = new Error('secret detail from the keytab');
    err.stack = 'Error: secret detail from the keytab\n    at hidden';
    throw err;
  };
  const res = {
    status: 0, body: '',
    writeHead: function (status) {
      this.status = status;
    },
    end: function (body) {
      this.body = String(body || '');
    }
  };
  await demo.advertPage(res, { query: { get: function () {
    return 'json';
  } } });
  const json = JSON.parse(res.body);
  t.check(res.status === 503 &&
          json.problem === 'the keytab could not be prepared' &&
          res.body.indexOf('secret detail') < 0 &&
          res.body.indexOf('at hidden') < 0,
          'a keytab failure is a fixed sentence; the exception stays in ' +
          'the log', res.body);
  res.body = '';
  await demo.advertPage(res, { query: { get: function () {
    return '';
  } } });
  t.check(res.status === 503 && res.body.indexOf('secret detail') < 0 &&
          res.body.indexOf('the keytab could not be prepared') >= 0,
          'the HTML page says the same fixed sentence', res.body.slice(0, 400));
  log.debug("Leaving urlAndKeytabFailure().");
}

async function run(t) {
  log.debug("Entering run().");
  await urlAndKeytabFailure(t);
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
            // not no-referrer, under which a browser posts Origin: null and
            // the start refuses the companion's own form
            r.headers['referrer-policy'] === 'same-origin' &&
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
    const demos = JSON.parse(r.text).demos;
    t.check(r.status === 200 && demos[0] === 'oid4vc' &&
            demos.indexOf('social') >= 0,
            '7. /healthz says the companion is up and what it plays', r.text);
    // No jar: the request carries no session cookie. The dummy answers
    // the missing code before it looks at the client, which is how a
    // probe with no session is told apart from the CSRF page.
    r = await hit(port, 'POST', '/social/discord/token', {
      form: { grant_type: 'authorization_code', code: 'nope' } });
    let tokenError = '';
    try {
      tokenError = JSON.parse(r.text).error;
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      tokenError = '';
    }
    t.check(r.status === 400 && tokenError === 'invalid_grant' &&
            r.text.indexOf('<') < 0,
            '7b. a token post under /social is the dummy, not the CSRF page',
            r.status + ' ' + r.text.slice(0, 200));
  } finally {
    server.close();
  }
  await kerberosDemonstration(t);
  await pepApplication(t);
  await pepApplicationIdentity(t);
  log.debug("Leaving run().");
}

/**
 * One raw request to the companion: a path sent as written, headers, and a
 * body. `http.request` keeps the path's dot segments, which `fetch` would
 * resolve away.
 *
 * @param {number} port - the companion's port
 * @param {string} method - the method
 * @param {string} where - the raw path
 * @param {object} [headers] - the headers
 * @param {Buffer|string} [body] - the body
 * @returns {Promise<object>} `{ status, headers, text, json }`
 */
function raw(port, method, where, headers, body) {
  log.debug("Entering raw(). " + method + " " + where);
  log.debug("Leaving raw().");
  return new Promise(function (resolve, reject) {
    const req = http.request({ host: '127.0.0.1', port: port, path: where,
                               method: method, headers: headers || {} },
                             function (res) {
      let text = '';
      res.on('data', function (c) {
        text += c;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in raw(): " + ((e && e.message) || e));
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: text,
                  json: json });
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

// 9. The remote PEP's upstream application (#1760).
async function pepApplication(t) {
  log.debug("Entering pepApplication().");
  const { Companion } = require(path.join(ROOT, 'companion', 'companion.js'));
  const companion = new Companion({ port: 0, publicUrl: PUBLIC,
                                    walletUrl: '' }, { sts: standIn() });
  const server = await companion.listen();
  const port = server.address().port;
  try {
    let r = await raw(port, 'GET', '/pep-app/protected/x?a=1&a=2&b=3',
                      { 'x-remote-user': 'pep-admin-person',
                        authorization: 'Bearer abc' });
    const e = r.json || {};
    t.check(r.status === 200 && e.app === 'pep-app' &&
            e.page === 'protected' && e.method === 'GET' &&
            e.path === '/pep-app/protected/x' &&
            JSON.stringify(e.query) === JSON.stringify({ a: ['1', '2'],
                                                        b: '3' }) &&
            !!e.headers && e.headers['x-remote-user'] === 'pep-admin-person' &&
            e.headers.authorization === 'Bearer abc' && !e.body &&
            !r.headers['set-cookie'],
            '9a. a /pep-app page echoes the method, path, query and every ' +
            'header it received, and sets no session cookie', r.text);
    r = await raw(port, 'GET', '/pep-app/public/../protected');
    t.check(r.status === 200 && !!r.json &&
            r.json.path === '/pep-app/public/../protected' &&
            r.json.page === 'public',
            '9b. the path echoed is the raw one, dot segments as sent',
            r.text);
    const body = Buffer.from('{"name":"widget"}');
    r = await raw(port, 'POST', '/pep-app/api/items',
                  { 'content-type': 'application/json',
                    'content-length': body.length }, body);
    const digest = require('crypto').createHash('sha256').update(body)
      .digest('hex');
    t.check(r.status === 201 && !!r.json && r.json.page === 'item-created' &&
            !!r.json.body && r.json.body.length === body.length &&
            r.json.body.sha256 === digest,
            '9c. a POST to /pep-app/api/items needs no form token and ' +
            'echoes the body\'s length and SHA-256', r.text);
    r = await raw(port, 'GET', '/pep-app/public/hop');
    t.check(r.status === 200 &&
            /x-upstream-secret/i.test(String(r.headers.connection)) &&
            r.headers['x-upstream-secret'] === 'only-for-the-next-hop' &&
            r.headers['x-upstream-visible'] === 'end-to-end',
            '9d. /pep-app/public/hop answers a hop-by-hop header named by ' +
            'Connection beside an end-to-end one', JSON.stringify(r.headers));
    const started = Date.now();
    r = await raw(port, 'GET', '/pep-app/slow?ms=300');
    const took = Date.now() - started;
    t.check(r.status === 200 && !!r.json && r.json.waitedMs === 300 &&
            took >= 280,
            '9e. /pep-app/slow waits what it was asked', took + 'ms');
    // 9g (2026-11-16): /pep-app/whoami names the identity the proxy
    // forwarded and the listener it came through, off the proxy's own
    // X-Forwarded-Host and X-Forwarded-Proto. Before the counter's read, so
    // the counter's total below counts it.
    r = await raw(port, 'GET', '/pep-app/whoami/x', {
      'x-remote-user': 'alice', 'x-iya-user': 'urn:uuid:1',
      'x-iya-auth': 'basic', 'x-forwarded-host': 'pep-1:9643',
      'x-forwarded-proto': 'https' });
    const who = (r.json && r.json.whoami) || {};
    t.check(r.status === 200 && r.json.page === 'whoami' &&
            who.user === 'alice' && who.subject === 'urn:uuid:1' &&
            who.mechanism === 'basic' && who.via.host === 'pep-1' &&
            who.via.port === 9643 && who.via.proto === 'https',
            '9g. /pep-app/whoami names the forwarded identity and the ' +
            'listener it came through', r.text);
    r = await raw(port, 'GET', '/pep-app/_hits');
    const hits = (r.json && r.json.byPath) || {};
    t.check(r.status === 200 && hits['/pep-app/protected/x'] === 1 &&
            hits['/pep-app/api/items'] === 1 && r.json.total === 6 &&
            !('/pep-app/_hits' in hits),
            '9f. /pep-app/_hits counts each path that reached the ' +
            'application and not itself', r.text);
  } finally {
    server.close();
  }
  log.debug("Leaving pepApplication().");
}

// A compact JWS, RS256, by node's crypto.
function rs256(privateKey, kid, payload) {
  log.debug("Entering rs256().");
  const enc = function (obj) {
    log.debug("Entering enc().");
    log.debug("Leaving enc().");
    return Buffer.from(JSON.stringify(obj)).toString('base64url');
  };
  const input = enc({ alg: 'RS256', typ: 'at+jwt', kid: kid }) + '.' +
                enc(payload);
  const signature = require('crypto').sign('sha256', Buffer.from(input),
                                           privateKey).toString('base64url');
  log.debug("Leaving rs256().");
  return input + '.' + signature;
}

// A SAML 2.0 Response whose Assertion is signed (enveloped, exclusive
// c14n, RSA-SHA256) by xml-crypto — the library the companion verifies
// with, which is the weakness of this half: the job's run against the
// service's own signer is the independent check.
function signedResponse(privatePem, audience, nameId) {
  log.debug("Entering signedResponse().");
  const { SignedXml } = require('xml-crypto');
  const now = Date.now();
  const iso = function (ms) {
    log.debug("Entering iso().");
    log.debug("Leaving iso().");
    return new Date(ms).toISOString();
  };
  const xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:' +
    'protocol" ID="_r1" Version="2.0" IssueInstant="' + iso(now) + '">' +
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
    'ID="_a1" Version="2.0" IssueInstant="' + iso(now) + '">' +
    '<saml:Issuer>https://idp.test/realm/x</saml:Issuer>' +
    '<saml:Subject><saml:NameID>' + nameId + '</saml:NameID></saml:Subject>' +
    '<saml:Conditions NotBefore="' + iso(now - 60000) + '" NotOnOrAfter="' +
    iso(now + 300000) + '"><saml:AudienceRestriction><saml:Audience>' +
    audience + '</saml:Audience></saml:AudienceRestriction>' +
    '</saml:Conditions><saml:AuthnStatement AuthnInstant="' + iso(now) +
    '" SessionIndex="_s1"/><saml:AttributeStatement><saml:Attribute ' +
    'Name="mail"><saml:AttributeValue>' + nameId + '@example.test' +
    '</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>' +
    '</saml:Assertion></samlp:Response>';
  const EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  const sig = new SignedXml({ privateKey: privatePem,
    canonicalizationAlgorithm: EXC,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' });
  sig.addReference({ xpath: "//*[local-name(.)='Assertion']",
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                 EXC],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256' });
  sig.computeSignature(xml, { location: {
    reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
    action: 'after' } });
  log.debug("Leaving signedResponse().");
  return sig.getSignedXml();
}

// 10. The identity `/pep-app` reads (#1760, D11): a Bearer JWT decoded and
// checked against a JWKS, and the ACS.
async function pepApplicationIdentity(t) {
  log.debug("Entering pepApplicationIdentity().");
  const nodeCrypto = require('crypto');
  const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
                            { kid: 'k1', alg: 'RS256', use: 'sig' });
  const jwks = http.createServer(function (req, res) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise(function (resolve) {
    jwks.listen(0, '127.0.0.1', resolve);
  });
  const { Companion } = require(path.join(ROOT, 'companion', 'companion.js'));
  const companion = new Companion({ port: 0, publicUrl: PUBLIC,
                                    walletUrl: '' }, { sts: standIn() });
  const server = await companion.listen();
  const port = server.address().port;
  const AUD = 'https://sp.example.test/saml';
  const privatePem = pair.privateKey.export({ format: 'pem',
                                              type: 'pkcs8' });
  const publicPem = pair.publicKey.export({ format: 'pem', type: 'spki' });
  try {
    let r = await raw(port, 'POST', '/pep-app/saml/_setup',
      { 'content-type': 'application/json' }, JSON.stringify({
        audience: AUD, certificates: [publicPem],
        jwksUrl: 'http://127.0.0.1:' + jwks.address().port + '/jwks' }));
    t.check(r.status === 200 && !!r.json && r.json.certificates === 1,
            '10a. /pep-app/saml/_setup takes the audience, the signing ' +
            'certificate and the JWKS', r.text);
    const token = rs256(pair.privateKey, 'k1',
      { iss: 'https://idp.test', sub: 'urn:uuid:1', aud: 'https://api.test',
        exp: Math.floor(Date.now() / 1000) + 300 });
    r = await raw(port, 'GET', '/pep-app/api/items',
                  { authorization: 'Bearer ' + token });
    const jwt = (r.json || {}).jwt || {};
    t.check(r.status === 200 && jwt.verified === true &&
            jwt.payload.sub === 'urn:uuid:1' && jwt.header.kid === 'k1' &&
            jwt.expired === false,
            '10b. a Bearer JWT is decoded and verified against the JWKS',
            r.text);
    const parts = token.split('.');
    const forged = parts[0] + '.' + Buffer.from(JSON.stringify(
      { iss: 'https://idp.test', sub: 'urn:uuid:2' })).toString('base64url') +
      '.' + parts[2];
    r = await raw(port, 'GET', '/pep-app/api/items',
                  { authorization: 'Bearer ' + forged });
    t.check(r.status === 200 && !!r.json && !!r.json.jwt &&
            r.json.jwt.verified === false &&
            r.json.jwt.payload.sub === 'urn:uuid:2',
            '10c. a JWT whose payload was changed is echoed as not verified',
            r.text);
    const good = signedResponse(privatePem, AUD, 'alice');
    const post = function (xml) {
      log.debug("Entering post().");
      const form = 'SAMLResponse=' + encodeURIComponent(
        Buffer.from(xml).toString('base64'));
      log.debug("Leaving post().");
      return raw(port, 'POST', '/pep-app/saml/acs',
                 { 'content-type': 'application/x-www-form-urlencoded',
                   'content-length': Buffer.byteLength(form) }, form);
    };
    r = await post(good);
    const set = [].concat(r.headers['set-cookie'] || []).join(' ');
    t.check(r.status === 200 && !!r.json && r.json.ok === true &&
            r.json.saml.nameId === 'alice' &&
            r.json.saml.attributes.mail[0] === 'alice@example.test' &&
            /pep_app_saml=[^;]+; Path=\/pep-app; HttpOnly/.test(set),
            '10d. the ACS accepts a signed response for its audience and ' +
            'sets pep_app_saml', r.status + ' ' + r.text + ' ' + set);
    const cookie = set.split(';')[0];
    r = await raw(port, 'GET', '/pep-app/protected', { cookie: cookie });
    t.check(r.status === 200 && !!r.json && !!r.json.saml &&
            r.json.saml.nameId === 'alice',
            '10e. every echo carries the SAML session its cookie names',
            r.text);
    r = await post(good.split('alice').join('mallo'));
    const tampered = r.status;
    r = await post(signedResponse(privatePem, 'https://other.test', 'alice'));
    const elsewhere = r.status;
    r = await post('<x/>');
    t.check(tampered === 403 && elsewhere === 403 && r.status === 403 &&
            !r.headers['set-cookie'],
            '10f. a tampered response, one for another audience and an ' +
            'unsigned one are refused and open no session',
            [tampered, elsewhere, r.status].join(','));
  } finally {
    server.close();
    jwks.close();
  }
  log.debug("Leaving pepApplicationIdentity().");
}

module.exports = {
  name: 'companion',
  describe: 'the development companion (#594) plays the OpenID4VC issuer and ' +
            'verifier, and (#595) a Kerberos-protected page and TCP ' +
            'service, in front of the service, as an outside party',
  run: run
};
