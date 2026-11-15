// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/rust-console-e2e.js
//
// ---------------------------------------------------------------------------
// PHASE 5'S MILESTONE OVER THE WIRE (#444, the `oauth2` slice): the
// UNCHANGED admin console and user portal bundles sign in against whichever
// runtime is listening — the code flow with PKCE S256, `resource`, a
// DPoP-bound token and the refresh grant — the driver
// tests/tools/rust-console-e2e.sh runs on the host.
//
//   setup  <base> <secret> <admin password> <out>
//                                  the bootstrap administrator's first
//                                  sign-in (the password change and the
//                                  authenticator app product asks for) and
//                                  a person's, through /authn-api; their
//                                  passwords and secrets written to <out>.
//   surface <base> <path> <user> <password> <totp secret>
//                                  headless Chrome opens <path> (/admin or
//                                  /portal), signs in at the screen the
//                                  bundle is sent to, and reports where it
//                                  landed: the token request's answer (its
//                                  token_type, whether a refresh token
//                                  came), the API calls the page then made
//                                  and their statuses, and the page's text.
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

async function firstSignIn(base, person, name) {
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


async function setup(base, secret, adminPassword, out) {
  const token = await adminToken(base, secret);
  const people = { admin: { password: adminPassword } };
  await firstSignIn(base, people.admin, 'admin');
  const made = await api(base, token, '/admin-api/users/create', {
    username: 'e2e.ann', invent: false, credential: 'generate',
    attributes: { cn: 'e2e.ann', sn: 'E2E', givenName: 'Ann',
                  mail: 'e2e.ann@example.net' } });
  people['e2e.ann'] = { password: made.password };
  await firstSignIn(base, people['e2e.ann'], 'e2e.ann');
  fs.writeFileSync(out, JSON.stringify(people));
  console.log('setup: the bootstrap administrator and e2e.ann, each ' +
              (people.admin.secret ? 'with' : 'without') +
              ' an authenticator app');
}

async function surface(base, path, user, password, secret) {
  const WebSocket = require('ws');
  // Port 0: Chrome picks a free one and names it in DevToolsActivePort —
  // a fixed port may be another session's listener.
  let port = 0;
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
    await send('Network.enable');
    const seen = [];
    const bodies = {};
    ws.on('message', function (m) {
      const msg = JSON.parse(m);
      if (msg.method === 'Network.responseReceived') {
        const u = msg.params.response.url;
        if (/\/(oauth2|admin-api|account-api|authn-api)\//.test(u) ||
            /\/\.well-known\//.test(u)) {
          seen.push({ url: u.replace(base, ''),
                      status: msg.params.response.status,
                      id: msg.params.requestId });
        }
      }
    });
    await send('Page.navigate', { url: base + path });
    const steps = [];
    if (!await waitFor("!!document.getElementById('kc-login')", 30000)) {
      throw new Error('the sign-in screen was not reached: ' +
        await evaluate('location.href + " " + ' +
                       'document.body.innerText.slice(0, 400)'));
    }
    steps.push('sent to ' + (await evaluate('location.pathname')));
    await evaluate("(function(){var u=document.getElementById('username');" +
      "u.value=" + JSON.stringify(user) + ";var p=document.getElementById(" +
      "'password');p.value=" + JSON.stringify(password) + ";document." +
      "getElementById('kc-login').click();return 1;})()");
    steps.push('the password');
    if (secret) {
      if (await waitFor("!!document.getElementById('totp-submit')", 15000)) {
        steps.push('the one-time code');
        await evaluate("(function(){document.getElementById('code').value=" +
          JSON.stringify(totpCode(secret, Date.now())) + ";document." +
          "getElementById('totp-submit').click();return 1;})()");
      }
    }
    await waitFor("location.pathname.indexOf(" + JSON.stringify(path) +
                  ") === 0 && !/callback/.test(location.pathname)", 30000);
    await sleep(4000);
    const token = seen.filter(function (s) {
      return s.url.indexOf('/oauth2/token') === 0;
    });
    for (const t of token) {
      const r = await send('Network.getResponseBody', { requestId: t.id });
      try {
        const j = JSON.parse(r.result.body);
        bodies[t.id] = { token_type: j.token_type, scope: j.scope,
          refresh: !!j.refresh_token, id_token: !!j.id_token,
          error: j.error, error_description: j.error_description,
          aud: j.access_token ? JSON.parse(Buffer.from(
            j.access_token.split('.')[1], 'base64url')).aud : undefined,
          cnf: j.access_token ? JSON.parse(Buffer.from(
            j.access_token.split('.')[1], 'base64url')).cnf : undefined };
      } catch (e) {
        bodies[t.id] = { unreadable: String(e && e.message) };
      }
    }
    console.log(JSON.stringify({ steps: steps,
      location: await evaluate('location.href'),
      calls: seen.map(function (s) {
        return { url: s.url.split('?')[0], status: s.status,
                 answer: bodies[s.id] };
      }),
      text: await evaluate('document.body.innerText.slice(0, 600)') }));
    ws.close();
  } finally {
    chrome.kill('SIGKILL');
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const [cmd, ...args] = process.argv.slice(2);
const run = { setup: setup, surface: surface }[cmd];
run.apply(null, args).catch(function (e) {
  console.error(String(e && e.stack || e));
  process.exit(1);
});
