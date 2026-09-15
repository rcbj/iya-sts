'use strict';
//
// File: token_exchange_jti.js
//
// ===========================================================================
// A TOKEN EXCHANGE THAT MINTS NO ID TOKEN LOGS NO ERROR ABOUT ONE
// (2026-09-14).
//
// `oauth-oidc/oauth2.js`'s token exchange records a delegation act naming the
// identifiers of what it produced, read back off the tokens with `jtiOf()` —
// for `exchanged.access_token`, `exchanged.id_token` and
// `exchanged.refresh_token`, whether or not the last two exist. `jtiOf()` read
// `String(undefined || '').split('.')[1]`, which is `undefined`, and
// `b64uDecode()` base64-decoded the WORD "undefined" into six bytes that are
// not JSON. So every exchange with no `openid` in its scope logged
//
//   [STS-OAUTH-0182] a token just issued could not be re-read for its jti:
//   Unexpected token '�', "�w^~)�" is not valid JSON
//
// at ERROR — once per suite mode, from `oauth2_sts_endpoints`' exchange —
// about a token that was never issued. The act itself was right, because it
// drops an absent token; the log line was the defect, and a log line is the
// one thing no HTTP client can see, which is why this is in process.
//
// Three claims, in a CHILD PROCESS that serves the stack on a loopback port
// and reads its own stdout:
//   1. an exchange with no `openid` answers 200 with no ID Token and logs no
//      STS-OAUTH-0182;
//   2. an exchange WITH `openid` answers an ID Token and logs none either;
//   3. the delegation act still names the exchanged access token's jti, so
//      the fix did not silence the reader by making it read nothing.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'token_exchange_jti',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const ROOT = process.env.TXJ_ROOT;
  const OUT = process.env.TXJ_OUT;
  const http = require('http');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const flagged = [];
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = function (chunk) {
    if (String(chunk).indexOf('STS-OAUTH-0182') >= 0) {
      flagged.push(String(chunk).slice(0, 400));
    }
    return write.apply(null, arguments);
  };
  const post = function (port, form) {
    return new Promise(function (resolve) {
      const body = new URLSearchParams(form).toString();
      const req = http.request({ host: '127.0.0.1', port: port,
        path: '/oauth2/token', method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded',
                   'content-length': Buffer.byteLength(body) } },
      function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let json = {};
          try {
            json = JSON.parse(text);
          } catch (e) {
            // A page rather than JSON; kept as text for the finding.
            json = { parseError: e.message };
          }
          resolve({ status: res.statusCode, json: json, text: text });
        });
      });
      req.end(body);
    });
  };
  const claims = function (jwt) {
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
                            .toString('utf8'));
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const delegation = require(ROOT + '/common/delegation');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const client = { client_id: 'txj-client' };

    const subject = await post(port, Object.assign({
      grant_type: 'password', username: 'txj-alice', password: 'anything',
      scope: 'openid profile' }, client));
    note(subject.status === 200 && subject.json.access_token,
         'precondition: a subject token was issued',
         subject.status + ' ' + subject.text.slice(0, 200));

    // 1. No openid: no ID Token, and no error about one.
    flagged.length = 0;
    const plain = await post(port, Object.assign({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: subject.json.access_token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      audience: 'https://txj-api.example', scope: 'profile' }, client));
    note(plain.status === 200 && plain.json.access_token &&
         !plain.json.id_token,
         '1a. an exchange with no openid answers an access token and no ID ' +
         'Token', plain.status + ' ' + plain.text.slice(0, 200));
    note(flagged.length === 0,
         '1b. AND LOGS NO STS-OAUTH-0182 ABOUT THE ID TOKEN IT NEVER MINTED ' +
         '— it logged one per exchange, reading the word "undefined" as ' +
         'base64', flagged.join(' | '));

    // 2. With openid: an ID Token, still no error.
    flagged.length = 0;
    const withId = await post(port, Object.assign({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: subject.json.access_token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      audience: 'https://txj-api.example', scope: 'openid profile' },
    client));
    note(withId.status === 200 && withId.json.id_token,
         '2a. an exchange with openid answers an ID Token',
         withId.status + ' ' + withId.text.slice(0, 200));
    note(flagged.length === 0, '2b. and logs no STS-OAUTH-0182 either',
         flagged.join(' | '));

    // 3. The act still names what was produced.
    if (plain.json.access_token) {
      const jti = claims(plain.json.access_token).jti;
      const acts = delegation.list();
      const found = (acts.rows || acts || []).some(function (row) {
        return (row.produced || []).some(function (p) {
          return p.kind === 'access_token' && p.identifier === jti;
        });
      });
      note(jti && found,
           '3. the delegation act still names the exchanged access token\'s ' +
           'jti — the reader was not silenced by making it read nothing',
           jti);
    }
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-txj-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { TXJ_OUT: out, TXJ_ROOT: root,
    STS_HTTPS: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 256 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) { t.check(one.ok, one.what, one.detail); });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'token_exchange_jti',
  describe: 'a token exchange that mints no ID Token logs no STS-OAUTH-0182 ' +
            'about one',
  run: run
};
