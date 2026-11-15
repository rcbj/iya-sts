// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authn-api-vectors.js
//
// ---------------------------------------------------------------------------
// `/authn-api` AND THE SIGN-IN SHELLS (#444, phase 5, the `authnapi` slice),
// for the Rust crate `sts-authn-api` to answer identically. Called by
// `tests/tools/crypto-vectors.js`'s `authn-api-node.json` row.
//
// THE WHOLE NODE STACK, IN A CHILD PROCESS, OVER HTTP (tests/authn_api.js's
// method): `common/protocol_stack` built, the app listening on 127.0.0.1, and
// a script of browser requests sent to it — each case one browser (a cookie
// jar), one person or none, and one pending sign-in `beginAuthentication()`
// made. What is recorded per step is what the browser sees: the status, the
// JSON body, the `Set-Cookie` lines and the error code marked on the
// response (read off the server's response object by a `writeHead` hook —
// a code is never sent, so the harness is the only reader).
//
// WHAT THE RUST TEST NEEDS TO REPLAY IT is recorded beside the steps: the
// person's directory entry (`existingUserEntry()`'s stored form, its
// password hash and authenticator app's JSON as the directory holds them),
// the pending record Node made, the base URL and the origin. Every random
// value — a step id, a CSRF token, a cookie value — is a PLACEHOLDER in a
// later request (`{mfa}`, `{change}`, `{csrf}`) and is replaced by the
// value the replaying side's own earlier answer gave; a TOTP code is
// `{totp}` (or `{totpnext}`, the next step's), made at the moment of the
// request from the person's secret.
//
// THE MODE IS DEVELOPMENT, THE DEFAULT, so the screen checks no password
// but the reserved `invalid`; the authenticator app's code is checked for
// real in every mode. The product checks are proved over the wire
// (tests/tools/rust-signin-e2e.sh).
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

/**
 * The child: builds the stack, runs the cases, writes the recording.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.AV_ROOT;
  const OUT = process.env.AV_OUT;
  const http = require('http');
  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const authn = require(ROOT_DIR + '/authn/authn');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const totp = require(ROOT_DIR + '/common/totp');
    const errorCodes = require(ROOT_DIR + '/common/error_codes');
    const server = http.createServer(function (req, res) {
      const writeHead = res.writeHead;
      res.writeHead = function () {
        const code = errorCodes.codeOf(res);
        if (code && !res.headersSent) {
          res.setHeader('x-vector-code', code);
        }
        return writeHead.apply(this, arguments);
      };
      app(req, res);
    });
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;

    const call = function (o) {
      return new Promise(function (resolve, reject) {
        const headers = Object.assign({}, o.headers || {});
        const names = Object.keys(o.jar);
        if (names.length) {
          headers.cookie = names.map(function (k) {
            return k + '=' + o.jar[k];
          }).join('; ');
        }
        const body = o.body === undefined ? '' : String(o.body);
        if (o.method !== 'GET') {
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: '127.0.0.1', port: port,
          path: o.path, method: o.method, headers: headers }, function (res) {
          let text = '';
          const cookies = res.headers['set-cookie'] || [];
          cookies.forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            if (pair.slice(eq + 1) === '') {
              delete o.jar[pair.slice(0, eq)];
            } else {
              o.jar[pair.slice(0, eq)] = pair.slice(eq + 1);
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
            resolve({ status: res.statusCode, json: json, text: text,
                      cookies: cookies,
                      code: String(res.headers['x-vector-code'] || ''),
                      type: String(res.headers['content-type'] || ''),
                      csp: String(res.headers['content-security-policy'] ||
                                  '') });
          });
        });
        req.on('error', reject);
        req.end(body);
      });
    };

    const cases = [];
    const person = async function (name, opts) {
      ldap.createUser(name, { invent: false });
      let secret = '';
      if (opts.totp) {
        const begun = credentials.beginTotpEnrolment(name, {});
        credentials.confirmTotpEnrolment(name, totp.codeAt(begun.secret));
        secret = begun.secret;
      }
      if (opts.reset) {
        credentials.setPasswordResetRequired(name, true);
      }
      // A COPY: the directory's attributes object is live, and a later
      // sign-in writes on it.
      const stored = JSON.parse(JSON.stringify(ldap.existingUserEntry(name) ||
                                               null));
      return { name: name, secret: secret,
               entry: stored ? { dn: stored.dn,
                                 attributes: stored.attributes } : null };
    };
    // A request's placeholders, from what this side's own answers bound.
    const fill = function (text, bound, who) {
      return String(text).replace(/\{(mfa|change|csrf|authn|totp|totpnext)\}/g,
        function (all, name) {
          if (name === 'totp') {
            return totp.codeAt(who.secret);
          }
          // The next step's code, inside the window: the current one was
          // spent by the enrolment's confirmation.
          if (name === 'totpnext') {
            return totp.codeAt(who.secret, Date.now() + 30000);
          }
          return bound[name] || '';
        });
    };
    const run = async function (name, who, steps, begin) {
      const target = authn.beginAuthentication(Object.assign({
        returnTo: '/av/after?x=1', protocol: 'av-probe', application: '' },
        begin || {}));
      const id = new URLSearchParams(String(target).split(/[?#]/)[1] || '')
        .get('authn') || '';
      const record = JSON.parse(JSON.stringify(authn.pendingFor(id) || null));
      const jar = {};
      const bound = { authn: id };
      const recorded = [];
      for (const step of steps) {
        const headers = {};
        Object.keys(step.headers || {}).forEach(function (h) {
          headers[h] = fill(step.headers[h], bound, who || {});
        });
        if (step.origin !== false && step.method === 'POST') {
          headers.origin = base;
        }
        if (step.json !== false && step.method === 'POST') {
          headers['content-type'] = 'application/json';
        }
        if (step.csrf !== false && step.method === 'POST' &&
            !headers['x-csrf-token']) {
          headers['x-csrf-token'] = bound.csrf || '';
        }
        const body = step.body === undefined ? undefined
          : fill(JSON.stringify(step.body), bound, who || {});
        const r = await call({ jar: jar, method: step.method,
          path: fill(step.path, bound, who || {}), headers: headers,
          body: body });
        if (r.json && r.json.csrf) {
          bound.csrf = r.json.csrf;
        }
        if (r.json && r.json.next === 'mfa') {
          bound.mfa = r.json.id;
        }
        if (r.json && r.json.next === 'password-change') {
          bound.change = r.json.id;
        }
        recorded.push({ request: step, status: r.status, code: r.code,
                        type: r.type.split(';')[0],
                        csp: r.csp,
                        body: r.json === null ? null : r.json,
                        cookies: r.cookies });
      }
      cases.push({ name: name, person: who || null, record: record,
                   steps: recorded });
    };

    const GET = function (p, extra) {
      return Object.assign({ method: 'GET', path: p }, extra || {});
    };
    const POST = function (p, body, extra) {
      return Object.assign({ method: 'POST', path: p, body: body },
                           extra || {});
    };
    const screen = '/authn-api/pending/{authn}';

    await run('index and document', null, [
      GET('/authn-api'), GET('/authn-api/openapi.json')]);

    const pwd = await person('av-pwd', {});
    await run('a password sign-in', pwd, [
      GET('/authn/login?authn={authn}'),
      GET(screen),
      POST(screen + '/password', { username: 'av-pwd', password: 'x' },
           { json: false }),
      POST(screen + '/password', { username: 'av-pwd', password: 'x' },
           { origin: false }),
      POST(screen + '/password', { username: 'av-pwd', password: 'x' },
           { headers: { 'x-csrf-token': 'not-the-token' } }),
      POST('/authn-api/pending/not*an*id/password', { username: 'av-pwd' }),
      POST('/authn-api/pending/nosuchsignin/password', { username: 'av-pwd' }),
      POST(screen + '/password', { username: 'av-pwd', zzz: '1' }),
      POST(screen + '/password', { username: 'x'.repeat(300) }),
      POST(screen + '/password', { username: '' }),
      POST(screen + '/password', { username: 'av-pwd+ml-dsa',
                                   password: 'x' }),
      POST(screen + '/password', { username: 'av-pwd',
                                   password: 'invalid' }),
      GET(screen),
      GET(screen + '?zzz=1'),
      GET(screen, { headers: { 'x-made-up': '1' } }),
      POST(screen + '/password', { username: 'av-pwd',
                                   password: 'Correct-Horse-1',
                                   remember_browser: '' }),
      GET(screen),
      GET('/authn-api/accounts')]);

    await run('cancel and anonymous', null, [
      GET('/authn/login?authn={authn}'),
      GET(screen),
      POST(screen + '/anonymous', {}),
      POST(screen + '/cancel', { extra: '1' }),
      POST(screen + '/cancel', {}),
      GET(screen),
      GET('/authn/login?authn={authn}')]);

    const tom = await person('av-tom', { totp: true });
    await run('a password and an authenticator app', tom, [
      GET('/authn/login?authn={authn}'),
      GET(screen),
      POST(screen + '/password', { username: 'av-tom', password: 'p' }),
      GET('/authn/totp?mfa={mfa}'),
      GET('/authn-api/mfa/{mfa}'),
      GET('/authn-api/mfa/{mfa}?page=totp'),
      GET('/authn-api/mfa/{mfa}?page=nonsense'),
      GET('/authn-api/mfa/{mfa}?page=backup-code'),
      GET('/authn-api/mfa/nosuchstep?page=totp'),
      POST('/authn-api/mfa/{mfa}/totp', { code: '000000' }),
      POST('/authn-api/mfa/{mfa}/totp', { code: '1', more: 'x' }),
      POST('/authn-api/mfa/{mfa}/totp', { code: '{totp}' }),
      POST('/authn-api/mfa/{mfa}/totp', { code: '{totpnext}' }),
      GET('/authn-api/mfa/{mfa}?page=totp'),
      GET('/authn-api/accounts')]);

    const tess = await person('av-tess', { totp: true });
    await run('a step started over', tess, [
      GET('/authn/login?authn={authn}'),
      GET(screen),
      POST(screen + '/password', { username: 'av-tess', password: 'p' }),
      POST('/authn-api/mfa/{mfa}/start-over', {}),
      POST('/authn-api/mfa/{mfa}/start-over', {}),
      GET(screen)]);

    const pat = await person('av-pat', { reset: true });
    await run('a forced password change', pat, [
      GET('/authn/login?authn={authn}'),
      GET(screen),
      POST(screen + '/password', { username: 'av-pat', password: 'p' }),
      GET('/authn/password-change?change={change}'),
      GET('/authn-api/password-change/{change}'),
      GET('/authn-api/password-change/nosuchchange'),
      POST('/authn-api/password-change/{change}',
           { new_password: 'One-New-Password-1',
             confirm_password: 'Another-1' }),
      POST('/authn-api/password-change/{change}',
           { new_password: '', confirm_password: '' }),
      POST('/authn-api/password-change/{change}',
           { new_password: 'One-New-Password-1',
             confirm_password: 'One-New-Password-1' })]);

    await run('unrouted and unknown', null, [
      GET('/authn-api/nothing-here'),
      GET('/authn/login?authn=nosuchsignin'),
      GET('/authn/login?authn=bad*id'),
      GET('/authn/totp?mfa=nosuchstep')]);

    fs.writeFileSync(OUT, JSON.stringify({ base: base, origin: base,
                                           cases: cases }));
    server.close();
    process.exit(0);
  })().catch(function (e) {
    fs.writeFileSync(OUT, JSON.stringify({ error: String(e && e.stack) }));
    process.exit(1);
  });
}

/**
 * Builds the recording in a child process of its own.
 *
 * @param {string} ROOT - the repository's root
 * @returns {object} the vector document
 */
function build(ROOT) {
  const out = path.join(os.tmpdir(), 'av-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  AV_ROOT: ROOT, AV_OUT: out,
                                  STS_CSRF_SECRET: 'authn-api-vectors' }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let doc = null;
  try {
    doc = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    throw new Error('authn-api-vectors: the child wrote nothing (exit ' +
                    result.status + '): ' +
                    String(result.stderr || '').slice(-2000));
  }
  if (doc.error) {
    throw new Error('authn-api-vectors: ' + doc.error);
  }
  return doc;
}

module.exports = { build: build };
