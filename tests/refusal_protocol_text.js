// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: refusal_protocol_text.js
//
// ===========================================================================
// A REFUSAL'S SENTENCE NEVER REACHES A PROTOCOL ANSWER AS ANYTHING BUT ITS
// ENGLISH TEXT (#2006, the merger's review).
//
// `common/sentence.ts` made the issuance gate's refusals catalog sentences,
// so a sign-in page draws them in its language. The same `why` is what the
// authorization endpoint redirects with and what the token endpoint answers
// as `error_description`, where RFC 6749 section 5.2 allows only
// %x20-21 / %x23-5B / %x5D-7E — and `oauth21.js`'s `sanitizeDescription()`
// passed a non-string through unchanged, so a sentence's quotes and dashes
// reached the wire. Held here:
//
//   A. `sanitizeDescription()` makes a sentence text and holds it to the
//      character set.
//   B. The gate's exported checks answer `why` as English text and the
//      sentence beside it as `said`: a disabled account's refusal.
//   C. A role refusal at the authorization endpoint redirects with an
//      `error_description` inside the character set.
//   D. The same refusal at the token endpoint answers inside it.
//   E. A retiring realm's refusal at the token endpoint answers inside it.
//
// A CHILD PROCESS, as `tests/fga_issuance.js` runs one: the whole protocol
// stack, a listener and a throwaway realm, nothing leaking into the runner.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'refusal_protocol_text',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.RPT_ROOT;
  const OUT = process.env.RPT_OUT;
  const fs = require('fs');
  const urls = require(ROOT + '/tests/protocol/url_match.js');
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  // RFC 6749 section 5.2's error_description.
  const inCharset = function (text) {
    return typeof text === 'string' && text.length > 0 &&
      /^[\x20\x21\x23-\x5B\x5D-\x7E]*$/.test(text);
  };

  let jar = {};
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.form ? new URLSearchParams(o.form).toString() : '';
      const headers = Object.assign({}, o.headers || {});
      if (o.cookies && Object.keys(jar).length) {
        headers.cookie = Object.keys(jar).map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
      }
      if (method !== 'GET') {
        headers['content-type'] = 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        (res.headers['set-cookie'] || []).forEach(function (line) {
          const pair = line.split(';')[0];
          const eq = pair.indexOf('=');
          jar[pair.slice(0, eq)] = pair.slice(eq + 1);
        });
        res.on('data', function (c) {
          text += c;
        });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(body);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const screen = require(ROOT + '/tests/tools/authn_screen');
    const applications = require(ROOT + '/common/applications');
    const realms = require(ROOT + '/common/realms');
    const gate = require(ROOT + '/common/issuance_gate');
    const accountState = require(ROOT + '/common/account_state');
    const oauth21 = require(ROOT + '/oauth-oidc/oauth21');
    const Sentence = require(ROOT + '/common/sentence');

    // A.
    const quoted = Sentence.say('refusals.account.disabledNoIssue',
                                { account: 'rpt-bob' });
    const cleaned = oauth21.sanitizeDescription(quoted);
    note(inCharset(cleaned) && cleaned.indexOf('rpt-bob') >= 0,
         'A. sanitizeDescription() makes a sentence text inside RFC 6749 ' +
         'section 5.2', JSON.stringify(cleaned));

    // B.
    const wasDisabled = accountState.isDisabled;
    accountState.isDisabled = function () {
      return true;
    };
    let disabled = null;
    try {
      disabled = gate.check({ application: 'rpt', kind: 'issue-access-token',
                              subject: { kind: 'user', name: 'rpt-bob' } });
    } finally {
      accountState.isDisabled = wasDisabled;
    }
    note(disabled && disabled.allowed === false &&
         typeof disabled.why === 'string' &&
         disabled.why === String(quoted) && Sentence.is(disabled.said) &&
         disabled.said.key === 'refusals.account.disabledNoIssue',
         'B. the gate answers a disabled account\'s refusal as English text, ' +
         'the sentence beside it as said',
         JSON.stringify(disabled && {
           why: disabled.why, said: disabled.said && disabled.said.key }));

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const SECRET = 'rpt-client-secret-0123456789abcdef0123456789ab';
    const REDIRECT = 'https://rp.rpt.example/cb';
    const BASIC = 'Basic ' + Buffer.from('rpt:' + SECRET).toString('base64');
    const REALM = 'rpt' + crypto.randomBytes(3).toString('hex');
    const PREFIX = '/realm/' + REALM;
    const made = realms.create({ id: REALM, name: REALM,
                                 description: 'refusal_protocol_text.js' });
    note(made.ok, 'a throwaway trust realm',
         JSON.stringify(made.errors || ''));
    realms.run(made.realm, function () {
      applications.createApplication({ identifier: 'rpt',
        protocols: ['oauth2'], fields: { oauthClientId: 'rpt',
          oauthClientSecret: SECRET, oauthRedirectUri: [REDIRECT],
          oauthTokenEndpointAuthMethod: 'client_secret_basic',
          oauthGrantType: ['authorization_code', 'client_credentials'] } });
    });

    // A ROLE REFUSAL, as the XACML role PEP writes it: the catalog sentence
    // with the quotes the RFC's character set does not allow. Only the
    // issuances are refused, so the sign-in itself goes through.
    const roleWhy = Sentence.say('refusals.policy.roleRequired', {
      application: 'rpt', anyRequired: 'yes', required: 'staff',
      named: 'yes', who: 'rpt-alice', anyHeld: 'yes', held: 'EVERYBODY' });
    gate.setDecider(function (question) {
      const kind = String((question && question.kind) || '');
      if (kind === 'issue-authorization-code' ||
          kind === 'issue-access-token') {
        return { allowed: false, decision: 'Deny', why: roleWhy, roles: [],
                 required: ['staff'], policy: 'rpt-test' };
      }
      return { allowed: true, decision: 'Permit', why: 'test', roles: [],
               required: [], policy: 'rpt-test' };
    });

    // C.
    const local = function (location) {
      return String(location || '').replace(/^https?:\/\/[^/]+/, '');
    };
    jar = {};
    let r = await request(port, 'GET', PREFIX + '/oauth2/authorize?' +
      new URLSearchParams({ response_type: 'code', client_id: 'rpt',
        redirect_uri: REDIRECT, scope: 'openid', state: 'st-rpt' })
        .toString(), { cookies: true });
    for (let hop = 0; hop < 12; hop++) {
      const where = String(r.headers.location || '');
      if ((r.status !== 302 && r.status !== 303) ||
          urls.isAt(where, REDIRECT)) {
        break;
      }
      if (/\/authn\/login/.test(where)) {
        r = await screen.submit({ port: port, jar: jar, at: local(where),
          fields: { action: 'login', username: 'rpt-alice',
                    password: 'anything' } });
        continue;
      }
      if (/\/oauth2\/consent/.test(where)) {
        const page = await screen.openConsent({ port: port, jar: jar,
                                                at: local(where) });
        r = await screen.answerConsent({ port: port, jar: jar,
          at: local(where), opened: page, decision: 'allow' });
        continue;
      }
      r = await request(port, 'GET', local(where), { cookies: true });
    }
    const back = String(r.headers.location || '');
    const query = back.indexOf('?') >= 0
      ? new URLSearchParams(back.split('?')[1])
      : new URLSearchParams(back.split('#')[1] || '');
    const authzDescription = query.get('error_description');
    note(query.get('error') === 'access_denied' &&
         inCharset(authzDescription) &&
         authzDescription.indexOf('staff') >= 0,
         'C. a role refusal at the authorization endpoint redirects with an ' +
         'error_description inside RFC 6749 section 5.2',
         r.status + ' ' + back.slice(0, 400));

    // D.
    const cc = await request(port, 'POST', PREFIX + '/oauth2/token', {
      form: { grant_type: 'client_credentials' },
      headers: { authorization: BASIC } });
    const ccDescription = cc.json && cc.json.error_description;
    note(cc.status >= 400 && inCharset(ccDescription) &&
         ccDescription.indexOf('staff') >= 0,
         'D. a role refusal at the token endpoint answers an ' +
         'error_description inside RFC 6749 section 5.2',
         cc.status + ' ' + cc.text.slice(0, 400));

    // E.
    gate.setDecider(function () {
      return { allowed: true, decision: 'Permit', why: 'test', roles: [],
               required: [], policy: 'rpt-test' };
    });
    const live = realms.get ? realms.get(REALM) : null;
    [made.realm, live].forEach(function (record) {
      if (record && typeof record === 'object') {
        record.retiringSince = Date.now();
      }
    });
    const retiring = await request(port, 'POST', PREFIX + '/oauth2/token', {
      form: { grant_type: 'client_credentials' },
      headers: { authorization: BASIC } });
    const retiringDescription = retiring.json &&
      retiring.json.error_description;
    note(retiring.status >= 400 && inCharset(retiringDescription) &&
         retiringDescription.indexOf(REALM) >= 0,
         'E. a retiring realm\'s refusal at the token endpoint answers an ' +
         'error_description inside RFC 6749 section 5.2',
         retiring.status + ' ' + retiring.text.slice(0, 400));

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'refusal_protocol_text-' + process.pid +
                        '-' + Date.now() + '.json');
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      cwd: ROOT,
      env: Object.assign({}, process.env, { RPT_ROOT: ROOT, RPT_OUT: out,
                                            CONFIG_FILE: '' }),
      encoding: 'utf8', timeout: 240000, maxBuffer: 64 * 1024 * 1024
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported',
               String(result.stderr || '').slice(-1500))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (f) {
    t.check(f.ok, f.what, f.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'refusal_protocol_text',
  describe: 'a refusal\'s catalog sentence reaches an OAuth ' +
            'error_description only as its English, inside RFC 6749 ' +
            'section 5.2\'s character set: a role refusal at both ' +
            'endpoints, a disabled account at ' +
            'the gate and a retiring realm at the token endpoint (#2006)',
  run: run
};
