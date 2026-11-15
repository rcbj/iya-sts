// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/rust-signin-e2e.js
//
// ---------------------------------------------------------------------------
// THE SIGN-IN OVER THE WIRE (#444, phase 5's first milestone check): the
// driver tests/tools/rust-signin-e2e.sh runs on the host, against whichever
// runtime is listening on the address it is given — Node first, which
// writes the store, then Rust on that store, then Node again.
//
//   setup  <base> <secret> <out>   two people through /admin-api (a password
//                                  each), the second given an authenticator
//                                  app by signing in at /authn-api (product
//                                  asks everybody to set one up); its secret
//                                  is written to <out>. Then
//                                  authn.allowOptionalSecondFactor, so the
//                                  first signs in with a password alone.
//   begin  <base> <out>            two sign-ins begun at /oauth2/authorize
//                                  (the user portal's public client, PKCE),
//                                  their pending ids written to <out>.
//   browser <base> <id> <user> <password> [<totp secret>]
//                                  headless Chrome on the UNCHANGED sign-in
//                                  bundle: the screen, the password, the
//                                  code where one is asked; prints the
//                                  `sts_session` cookie the answer set.
//   passkeys <base> <id,id,id> <user> <password>
//                                  the passkey person, in one browser with a
//                                  virtual authenticator (CDP's WebAuthn
//                                  domain): a passkey registered at sign-in
//                                  (the security-key box), then the second
//                                  factor, then with no username; prints the
//                                  three sessions.
//   honours <base> <cookie>        Node reads the session the cookie names:
//                                  the sign-out page's view, for the person.
//   signout <base> <cookie>        headless Chrome holding that cookie on the
//                                  UNCHANGED sign-out bundle (#444, the
//                                  logout slice): /logout, the inventory
//                                  drawn from /authn-api/logout, the Global
//                                  logout button pressed, the result drawn;
//                                  prints what the page said and whether the
//                                  browser still holds the cookie.
//
// `ws` is the main checkout's tests/node_modules (NODE_PATH); Chrome is the
// host's. Every certificate is the runtime's own and is not verified.
// ---------------------------------------------------------------------------

const https = require('https');
const crypto = require('crypto');
const childProcess = require('child_process');
const fs = require('fs');

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
           '(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36';

/**
 * One request, keeping the jar.
 *
 * @param {string} base - the service
 * @param {object} o - method, path, headers, body, jar
 * @returns {Promise<object>} status, headers, text, json
 */
function call(base, o) {
  return new Promise(function (resolve, reject) {
    const url = new URL(o.path, base);
    const headers = Object.assign({ 'user-agent': UA }, o.headers || {});
    const jar = o.jar || {};
    if (Object.keys(jar).length) {
      headers.cookie = Object.keys(jar).map(function (k) {
        return k + '=' + jar[k];
      }).join('; ');
    }
    const body = o.body === undefined ? '' : String(o.body);
    if (o.method !== 'GET') {
      headers['content-length'] = Buffer.byteLength(body);
    }
    const req = https.request({ host: url.hostname, port: url.port,
      path: url.pathname + url.search, method: o.method || 'GET',
      headers: headers, rejectUnauthorized: false }, function (res) {
      let text = '';
      (res.headers['set-cookie'] || []).forEach(function (line) {
        const pair = line.split(';')[0];
        const eq = pair.indexOf('=');
        if (pair.slice(eq + 1) === '') {
          delete jar[pair.slice(0, eq)];
        } else {
          jar[pair.slice(0, eq)] = pair.slice(eq + 1);
        }
      });
      res.on('data', function (c) {
        text += c;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
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

/**
 * A `/admin-api` token for the API client.
 *
 * @param {string} base - the service
 * @param {string} secret - the client's secret
 * @returns {Promise<string>} the token
 */
async function adminToken(base, secret) {
  const form = new URLSearchParams({ grant_type: 'client_credentials',
    scope: 'admin:read admin:write', resource: base + '/admin-api' });
  const r = await call(base, { method: 'POST', path: '/oauth2/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded',
      authorization: 'Basic ' + Buffer.from('sts-api-client:' + secret)
        .toString('base64') }, body: form.toString() });
  if (!r.json || !r.json.access_token) {
    throw new Error('no admin token: ' + r.status + ' ' + r.text.slice(0, 300));
  }
  return r.json.access_token;
}

async function api(base, token, path, body) {
  const r = await call(base, { method: 'POST', path: path,
    headers: { authorization: 'Bearer ' + token,
               'content-type': 'application/json' },
    body: JSON.stringify(body) });
  if (r.status !== 200) {
    throw new Error(path + ': ' + r.status + ' ' + r.text.slice(0, 400));
  }
  return r.json;
}

/**
 * A sign-in begun the way the portal begins one: the pending id the
 * authorization endpoint sends the browser to the screen with.
 *
 * @param {string} base - the service
 * @param {object} jar - the cookie jar
 * @returns {Promise<string>} the id
 */
async function begin(base, jar) {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier)
    .digest('base64url');
  const q = new URLSearchParams({ response_type: 'code',
    client_id: 'sts-user-portal', redirect_uri: base + '/portal/callback',
    scope: 'openid account:manage', state: 's' + Date.now(),
    nonce: 'n' + Date.now(), code_challenge: challenge,
    code_challenge_method: 'S256', resource: base + '/account-api' });
  const r = await call(base, { method: 'GET',
    path: '/oauth2/authorize?' + q.toString(), jar: jar });
  const at = String(r.headers.location || '');
  const m = /[?#&]authn=([^&]+)/.exec(at);
  if (!m) {
    throw new Error('no sign-in was begun: ' + r.status + ' ' + at + ' ' +
                    r.text.slice(0, 300));
  }
  return decodeURIComponent(m[1]);
}

/**
 * `/authn-api`'s act, bound as the bundle binds it (the id in X-Step-Id).
 */
async function act(base, jar, kind, id, rest, body, csrf) {
  return call(base, { method: 'POST',
    path: '/authn-api/' + kind + '/-' + rest, jar: jar,
    headers: { 'content-type': 'application/json', origin: base,
               'x-csrf-token': csrf, 'x-step-id': id },
    body: JSON.stringify(body || {}) });
}

async function view(base, jar, kind, id, query) {
  return call(base, { method: 'GET',
    path: '/authn-api/' + kind + '/-' + (query || ''), jar: jar,
    headers: { 'x-step-id': id } });
}

/**
 * RFC 6238 with SHA-1, 6 digits, 30 s, as an authenticator app shows it.
 *
 * @param {string} secret - base32
 * @param {number} at - ms
 * @returns {string} the code
 */
function totpCode(secret, at) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(secret).replace(/[\s=]/g, '').toUpperCase();
  let bits = '';
  for (const c of clean) {
    bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor((at || Date.now()) / 30000)));
  const mac = crypto.createHmac('sha1', Buffer.from(bytes)).update(counter)
    .digest();
  const off = mac[mac.length - 1] & 15;
  const n = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) |
            (mac[off + 2] << 8) | mac[off + 3];
  return String(n % 1000000).padStart(6, '0');
}

/**
 * One sign-in at the screen as its page drives it, through the forced
 * password change an administrator-made password asks for (the new one is
 * kept) and, where product asks for a second factor, an authenticator
 * app's enrolment (its secret is kept).
 */
async function firstSignIn(base, person, name, stopAtEnrol) {
  const jar = {};
  const id = await begin(base, jar);
  await call(base, { method: 'GET', path: '/authn/login', jar: jar });
  let r = await view(base, jar, 'pending', id);
  let csrf = r.json.csrf;
  r = await act(base, jar, 'pending', id, '/password',
                { username: name, password: person.password }, csrf);
  if (r.json && r.json.next === 'password-change') {
    const chosen = 'E2e-' + crypto.randomBytes(12).toString('base64url') +
                   '-9q';
    r = await act(base, jar, 'password-change', r.json.id, '',
                  { new_password: chosen, confirm_password: chosen }, csrf);
    person.password = chosen;
  }
  if (stopAtEnrol) {
    // THE PASSKEY PERSON: the password chosen, and the set-up step left
    // for the Rust runtime to finish with a passkey.
    if (!r.json || r.json.next !== 'mfa' || r.json.step !== 'enrol') {
      throw new Error(name + ' was not asked to set up a second factor: ' +
                      r.text);
    }
    return;
  }
  if (r.json && r.json.next === 'mfa' && r.json.step === 'enrol') {
    let mfa = r.json.id;
    r = await act(base, jar, 'mfa', mfa, '/setup/totp', {}, csrf);
    mfa = (r.json && r.json.id) || mfa;
    r = await view(base, jar, 'mfa', mfa, '?page=setup');
    const secret = String(r.json.view.setup.totp.secret).replace(/\s/g, '');
    csrf = r.json.csrf || csrf;
    r = await act(base, jar, 'mfa', mfa, '/setup/confirm',
                  { code: totpCode(secret) }, csrf);
    person.secret = secret;
  }
  if (!r.json || r.json.ok !== true || r.json.next !== 'redirect') {
    throw new Error(name + "'s first sign-in did not finish: " + r.text);
  }
}

async function setup(base, secret, out) {
  const token = await adminToken(base, secret);
  const people = {};
  for (const name of ['e2e.pwd', 'e2e.totp', 'e2e.key', 'e2e.key2']) {
    const made = await api(base, token, '/admin-api/users/create', {
      username: name, invent: false, credential: 'generate',
      attributes: { cn: name, sn: 'E2E', givenName: 'E2E',
                    mail: name + '@example.net' } });
    people[name] = { password: made.password };
  }
  // The authenticator app, enrolled where product asks everybody for one;
  // then a second factor made optional, so the first person signs in with
  // a password alone.
  await firstSignIn(base, people['e2e.totp'], 'e2e.totp');
  await firstSignIn(base, people['e2e.key'], 'e2e.key', true);
  await firstSignIn(base, people['e2e.key2'], 'e2e.key2', true);
  await api(base, token, '/admin-api/config/set',
            { key: 'authn.allowOptionalSecondFactor', value: true });
  await firstSignIn(base, people['e2e.pwd'], 'e2e.pwd');
  if (!people['e2e.totp'].secret) {
    throw new Error('e2e.totp was not asked to set up a second factor');
  }
  fs.writeFileSync(out, JSON.stringify(people));
  console.log('setup: four people, the second with an authenticator app, ' +
              'the last two with a password and no second factor (the ' +
              'passkey people, one for each runtime)');
}

async function beginTwo(base, out) {
  const ids = { pwd: await begin(base, {}), totp: await begin(base, {}),
                key: [await begin(base, {}), await begin(base, {}),
                      await begin(base, {})].join(',') };
  fs.writeFileSync(out, JSON.stringify(ids));
  console.log('begin: two sign-ins pending');
}

/**
 * Headless Chrome over the DevTools protocol.
 */
async function openChrome() {
  const WebSocket = require('ws');
  let port = 0;
  const dir = fs.mkdtempSync(require('os').tmpdir() + '/e2e-chrome-');
  const chrome = childProcess.spawn('google-chrome', ['--headless=new',
    '--disable-gpu', '--no-sandbox', '--ignore-certificate-errors',
    '--user-data-dir=' + dir, '--remote-debugging-port=0',
    '--user-agent=' + UA, 'about:blank'], { stdio: 'ignore' });
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };
  const close = function () {
    chrome.kill('SIGKILL');
    try {
      // Chrome may still be writing its profile as it dies.
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10,
                       retryDelay: 200 });
    } catch (e) {
      console.error('the browser profile ' + dir + ' was left: ' +
                    String((e && e.message) || e));
    }
  };
  try {
    let target = null;
    for (let i = 0; i < 150 && !target; i++) {
      await sleep(200);
      try {
        port = Number(fs.readFileSync(dir + '/DevToolsActivePort', 'utf8')
          .split('\n')[0]);
        const list = await new Promise(function (res, rej) {
          require('http').get('http://127.0.0.1:' + port + '/json/list',
            function (r) {
              let t = '';
              r.on('data', function (c) { t += c; });
              r.on('end', function () { res(JSON.parse(t)); });
            }).on('error', rej);
        });
        target = list.find(function (t) { return t.type === 'page'; });
      } catch (e) {
        target = null;
      }
    }
    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise(function (r) { ws.on('open', r); });
    let seq = 0;
    const pending = {};
    ws.on('message', function (m) {
      const msg = JSON.parse(m);
      if (msg.id && pending[msg.id]) {
        pending[msg.id](msg);
        delete pending[msg.id];
      }
    });
    const send = function (method, params) {
      return new Promise(function (r) {
        seq += 1;
        pending[seq] = r;
        ws.send(JSON.stringify({ id: seq, method: method,
                                 params: params || {} }));
      });
    };
    const evaluate = async function (expr) {
      const r = await send('Runtime.evaluate',
        { expression: expr, returnByValue: true, awaitPromise: true });
      return r.result && r.result.result ? r.result.result.value : undefined;
    };
    const waitFor = async function (expr, ms) {
      for (let i = 0; i < (ms || 15000) / 250; i++) {
        if (await evaluate(expr)) {
          return true;
        }
        await sleep(250);
      }
      return false;
    };
    const sessionCookie = async function () {
      const cookies = (await send('Network.getAllCookies')).result.cookies;
      const session = cookies.find(function (c) {
        return /sts_session$/.test(c.name);
      });
      return { cookie: session ? session.name + '=' + session.value : '',
               names: cookies.map(function (c) { return c.name; }) };
    };
    await send('Network.enable');
    return { send: send, evaluate: evaluate, waitFor: waitFor,
             sessionCookie: sessionCookie,
             close: function () { ws.close(); close(); } };
  } catch (e) {
    close();
    throw e;
  }
}

/**
 * Headless Chrome over the DevTools protocol.
 */
async function browser(base, id, user, password, secret) {
  const c = await openChrome();
  try {
    await c.send('Page.navigate', { url: base + '/authn/login#authn=' +
                                         encodeURIComponent(id) });
    if (!await c.waitFor("!!document.getElementById('kc-login')")) {
      throw new Error('the screen was not drawn: ' +
        await c.evaluate('document.body.innerText.slice(0, 400)'));
    }
    await c.evaluate("(function(){var u=document.getElementById('username');" +
      "u.value=" + JSON.stringify(user) + ";var p=document.getElementById(" +
      "'password');p.value=" + JSON.stringify(password) + ";document." +
      "getElementById('kc-login').click();return 1;})()");
    let steps = ['the screen'];
    if (secret) {
      if (!await c.waitFor("!!document.getElementById('totp-submit')")) {
        throw new Error('the code was not asked for: ' +
          await c.evaluate('location.href + " " + ' +
                           'document.body.innerText.slice(0, 400)'));
      }
      steps.push('the one-time code page');
      await c.evaluate("(function(){document.getElementById('code').value=" +
        JSON.stringify(totpCode(secret, Date.now())) + ";document." +
        "getElementById('totp-submit').click();return 1;})()");
    }
    await c.waitFor("/\\/oauth2\\/authorize|\\/portal/.test(location.href)",
                    15000);
    const href = await c.evaluate('location.href');
    const held = await c.sessionCookie();
    console.log(JSON.stringify({ steps: steps, location: href,
      cookie: held.cookie, names: held.names }));
  } finally {
    c.close();
  }
}

/**
 * THE PASSKEY PERSON (#444, the `passkeys` slice), in ONE browser with a
 * virtual authenticator (CDP's WebAuthn domain: CTAP2, internal, resident
 * keys, user verification), so the passkey registered by the first
 * sign-in is the one the next two use:
 *
 *   1. `enrol` — the password with the screen's security-key box, and
 *      the passkey page's registration;
 *   2. `second` — the password, then the passkey as the second factor;
 *   3. `usernameless` — the screen's *Sign in with a passkey* button, no
 *      username typed.
 *
 * The cookies are cleared between them; the authenticator is kept.
 *
 * @param {string} base - the service
 * @param {string} ids - the three pending ids, comma-separated
 * @param {string} user - the person
 * @param {string} password - their password
 * @returns {Promise<void>} prints `{ enrol, second, usernameless }`
 */
async function passkeys(base, ids, user, password) {
  const c = await openChrome();
  const out = {};
  const finished = "/\\/oauth2\\/authorize|\\/portal/.test(location.href)";
  const click = function (id) {
    return c.evaluate("(function(){var b=document.getElementById(" +
      JSON.stringify(id) + ");if(!b){return 0;}b.click();return 1;})()");
  };
  const page = function () {
    return c.evaluate('location.href + " " + ' +
                      'document.body.innerText.slice(0, 600)');
  };
  try {
    await c.send('WebAuthn.enable', { enableUI: false });
    const added = await c.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', ctap2Version: 'ctap2_1',
                 transport: 'internal', hasResidentKey: true,
                 hasUserVerification: true, isUserVerified: true,
                 automaticPresenceSimulation: true } });
    if (!added.result || !added.result.authenticatorId) {
      throw new Error('no virtual authenticator: ' + JSON.stringify(added));
    }
    // NO AUTOFILL: the screen arms conditional mediation as it loads, and
    // a virtual authenticator holding a discoverable credential answers it
    // unasked — every screen would be a usernameless sign-in. Each sign-in
    // here is the one its step names, so the page is told the browser has
    // none; the button's own ceremony is unaffected.
    await c.send('Page.enable');
    await c.send('Page.addScriptToEvaluateOnNewDocument', { source:
      'if (window.PublicKeyCredential) { PublicKeyCredential.' +
      'isConditionalMediationAvailable = function () { return ' +
      'Promise.resolve(false); }; }' });
    const [enrolId, secondId, discoverId] = String(ids).split(',');
    const screen = async function (id) {
      await c.send('Network.clearBrowserCookies');
      await c.send('Page.navigate', { url: base + '/authn/login#authn=' +
                                           encodeURIComponent(id) });
      if (!await c.waitFor("!!document.getElementById('kc-login')")) {
        throw new Error('the screen was not drawn: ' + await page());
      }
    };
    const withPassword = async function () {
      await c.evaluate("(function(){var u=document.getElementById(" +
        "'username');u.value=" + JSON.stringify(user) + ";var p=document." +
        "getElementById('password');p.value=" + JSON.stringify(password) +
        ";document.getElementById('kc-login').click();return 1;})()");
    };
    const settle = async function (what, steps) {
      if (!await c.waitFor(finished, 20000)) {
        throw new Error(what + ' did not finish: ' + await page());
      }
      const held = await c.sessionCookie();
      out[what] = { steps: steps, location: await c.evaluate('location.href'),
                    cookie: held.cookie };
    };
    // 1. Registered at sign-in: the password with the screen's "use a
    //    security key" box, which a person holding none answers with the
    //    passkey page's registration (the set-up step's own door is proved
    //    by the vectors: product with authn.allowOptionalSecondFactor
    //    offers it to nobody here).
    await screen(enrolId);
    if (!await c.evaluate("(function(){var b=document.getElementById(" +
        "'use_webauthn');if(!b){return 0;}b.checked=true;return 1;})()")) {
      throw new Error('the screen offered no security key box: ' +
                      await page());
    }
    await withPassword();
    if (!await c.waitFor("!!document.getElementById('wa-go')")) {
      throw new Error('the passkey page was not drawn: ' + await page());
    }
    await click('wa-go');
    await settle('enrol', ['the screen with a security key',
                           'the passkey registered']);
    // 2. The passkey as the second factor. The authenticator answers
    //    nothing while the screen is drawn (an autofill the page armed
    //    anyway would sign in with no username), and the passkey page's
    //    own ceremony once its button is pressed.
    const presence = function (on) {
      return c.send('WebAuthn.setAutomaticPresenceSimulation',
        { authenticatorId: added.result.authenticatorId, enabled: on });
    };
    await presence(false);
    await screen(secondId);
    await withPassword();
    if (!await c.waitFor("!!document.getElementById('wa-go')")) {
      throw new Error('the passkey was not asked for: ' + await page());
    }
    await presence(true);
    await click('wa-go');
    await settle('second', ['the screen', 'the passkey as the second ' +
                            'factor']);
    // 3. No username: the passkey names the account.
    await screen(discoverId);
    if (!await c.waitFor("!!document.getElementById('wa-passkey-go')")) {
      throw new Error('the screen offered no passkey: ' + await page());
    }
    // The button, unless the screen's autofill answered first: either is
    // a sign-in with no username.
    await click('wa-passkey-go');
    await settle('usernameless', ['the screen', 'a passkey and no ' +
                                  'username']);
    const creds = await c.send('WebAuthn.getCredentials',
      { authenticatorId: added.result.authenticatorId });
    out.credentials = ((creds.result && creds.result.credentials) || [])
      .map(function (one) {
        return { residentKey: one.isResidentCredential,
                 signCount: one.signCount };
      });
    console.log(JSON.stringify(out));
  } finally {
    c.close();
  }
}

/**
 * Headless Chrome, as browser() starts it, for the sign-out.
 */
async function signout(base, cookie) {
  const WebSocket = require('ws');
  const dir = fs.mkdtempSync(require('os').tmpdir() + '/e2e-chrome-');
  const chrome = childProcess.spawn('google-chrome', ['--headless=new',
    '--disable-gpu', '--no-sandbox', '--ignore-certificate-errors',
    '--user-data-dir=' + dir, '--remote-debugging-port=0',
    '--user-agent=' + UA, 'about:blank'], { stdio: 'ignore' });
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };
  try {
    let target = null;
    for (let i = 0; i < 150 && !target; i++) {
      await sleep(200);
      try {
        const port = Number(fs.readFileSync(dir + '/DevToolsActivePort',
          'utf8').split('\n')[0]);
        const list = await new Promise(function (res, rej) {
          require('http').get('http://127.0.0.1:' + port + '/json/list',
            function (r) {
              let t = '';
              r.on('data', function (c) { t += c; });
              r.on('end', function () { res(JSON.parse(t)); });
            }).on('error', rej);
        });
        target = list.find(function (t) { return t.type === 'page'; });
      } catch (e) {
        target = null;
      }
    }
    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise(function (r) { ws.on('open', r); });
    let seq = 0;
    const pending = {};
    ws.on('message', function (m) {
      const msg = JSON.parse(m);
      if (msg.id && pending[msg.id]) {
        pending[msg.id](msg);
        delete pending[msg.id];
      }
    });
    const send = function (method, params) {
      return new Promise(function (r) {
        seq += 1;
        pending[seq] = r;
        ws.send(JSON.stringify({ id: seq, method: method,
                                 params: params || {} }));
      });
    };
    const evaluate = async function (expr) {
      const r = await send('Runtime.evaluate',
        { expression: expr, returnByValue: true, awaitPromise: true });
      return r.result && r.result.result ? r.result.result.value : undefined;
    };
    const waitFor = async function (expr, ms) {
      for (let i = 0; i < (ms || 15000) / 250; i++) {
        if (await evaluate(expr)) {
          return true;
        }
        await sleep(250);
      }
      return false;
    };
    await send('Network.enable');
    const eq = cookie.indexOf('=');
    await send('Network.setCookie', { name: cookie.slice(0, eq),
      value: cookie.slice(eq + 1), url: base + '/', secure: true,
      httpOnly: true, sameSite: 'Lax' });
    await send('Page.navigate', { url: base + '/logout' });
    if (!await waitFor("!!document.querySelector('button.global')")) {
      throw new Error('the inventory was not drawn: ' +
        await evaluate('location.href + " " + ' +
                       'document.body.innerText.slice(0, 400)'));
    }
    const inventory = await evaluate('document.body.innerText.slice(0, 600)');
    await evaluate("(function(){document.querySelector('button.global')" +
      ".click();return 1;})()");
    const drawn = await waitFor("/Signed out/.test((document.querySelector" +
      "('h1')||{}).textContent||'')", 15000);
    const heading = await evaluate("(document.querySelector('h1')||{})" +
      ".textContent||''");
    const cookies = (await send('Network.getAllCookies')).result.cookies;
    const still = cookies.find(function (c) {
      return c.name === cookie.slice(0, eq);
    });
    console.log(JSON.stringify({ drawn: drawn, heading: heading,
      location: await evaluate('location.href'),
      inventory: inventory, cookieKept: !!still,
      names: cookies.map(function (c) { return c.name; }) }));
    ws.close();
  } finally {
    chrome.kill('SIGKILL');
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function honours(base, cookie) {
  const eq = cookie.indexOf('=');
  const jar = {};
  jar[cookie.slice(0, eq)] = cookie.slice(eq + 1);
  const r = await call(base, { method: 'GET', path: '/authn-api/logout',
                               jar: jar });
  console.log(JSON.stringify({ status: r.status,
    username: (r.json && r.json.view && r.json.view.username) || '',
    state: (r.json && r.json.view && r.json.view.state) || '' }));
}

const [cmd, ...args] = process.argv.slice(2);
const run = { setup: setup, begin: beginTwo, browser: browser,
              passkeys: passkeys, honours: honours, signout: signout }[cmd];
run.apply(null, args).catch(function (e) {
  console.error(String(e && e.stack || e));
  process.exit(1);
});
