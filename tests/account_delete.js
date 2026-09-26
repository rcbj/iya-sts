'use strict';
//
// File: account_delete.js
//
// ===========================================================================
// A DELETED PERSON'S SESSIONS END WITH THEM (#241, 2026-09-26).
//
// Deleting a person — SCIM's DELETE, an LDAP delete, anything that reaches the
// directory's `deletePerson()` — sent RISC `account-purged` and ended
// nothing. `noteAccountChange()` skipped account_state for a delete on the
// belief that "a deleted entry takes its sessions with it by other means",
// and nothing did: `authn.sessionOf()` asked only whether the account was
// DISABLED, and a missing entry read as not disabled. So a deleted person's
// browser went on signing in to every relying party until the session ran
// out, receivers heard no session-revoked until that expiry (labelled
// `policy`), and no back-channel Logout Token went at delete time.
//
// What is asserted:
//
//   A. a SCIM DELETE ends the person's sign-on session: the old cookie no
//      longer signs in, the session is gone from the store, the relying
//      party is POSTed its Logout Token, and the session observer is told
//      `revoked`;
//   B. the catch-up: a delete whose consequence never ran here (a delete on
//      another node reaches this one as an entry going away and nothing
//      else) — the next request presenting the session ends it through
//      `dropSession()`, with the same event;
//   C. what is ended is what the person held AT THE DELETE: a person made
//      again under the same name before the deferred consequence runs keeps
//      the session they have.
//
// In a child process on an ephemeral loopback port, with a relying party of
// its own for the Logout Tokens — `account_disable.js`'s arrangement.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'account_delete',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.ADEL_ROOT;
  const OUT = process.env.ADEL_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };

  function browser(port) {
    const jar = {};
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.json ? JSON.stringify(o.json)
          : (o.form ? new URLSearchParams(o.form).toString() : '');
        const headers = Object.assign({}, o.headers || {});
        if (!o.noCookies && Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = o.json ? 'application/json'
            : 'application/x-www-form-urlencoded';
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
    const authn = require(ROOT + '/authn/authn');
    const accountState = require(ROOT + '/common/account_state');
    const ldap = require(ROOT + '/ldap/ldap_server');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    const posted = [];
    const rp = http.createServer(function (req, res) {
      let text = '';
      req.on('data', function (c) { text += c; });
      req.on('end', function () {
        posted.push({ path: req.url, body: text });
        res.writeHead(200).end();
      });
    });
    await new Promise(function (r) { rp.listen(0, '127.0.0.1', r); });
    const rpBase = 'http://127.0.0.1:' + rp.address().port;

    config.setOverride('oauth2.consentRequired', false);
    config.setOverride('federation.outboundAllowHttp', true);
    config.setOverride('oauth2.backchannelLogoutBackoffMs', 0);

    // What a Shared Signals transmitter would be told. The notice is the
    // whole input to the event, so recording it is recording the event.
    const notices = [];
    authn.setSessionObserver(function (notice) {
      notices.push(notice);
      return null;
    });
    const revokedFor = function (sessionId) {
      return notices.filter(function (n) {
        return n.kind === 'revoked' && n.session &&
               n.session.id === sessionId;
      });
    };

    const SECRET = 'account-delete-secret-0123456789abcdef';
    const REDIRECT = 'https://rp.delete.example/cb';
    const CLIENT = 'adel-client';
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code', 'refresh_token'],
                oauthAllowedScope: ['openid'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic',
                oauthBackchannelLogoutUri: rpBase + '/bc' } });

    // A sign-in through the code flow; answers whether a code came back
    // WITHOUT the screen, which is what an honoured session does.
    const authorize = function (b) {
      return b.go('GET', '/oauth2/authorize?' + new URLSearchParams({
        client_id: CLIENT, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid', state: 's',
        nonce: 'n' + crypto.randomBytes(3).toString('hex') }).toString());
    };
    const signIn = async function (b, username) {
      let r = await authorize(b);
      if (r.status === 302 &&
          /\/authn\/login/.test(String(r.headers.location || ''))) {
        const page = await b.go('GET', r.headers.location);
        const form = hiddenFields(page.text);
        form.username = username;
        form.password = 'anything';
        form.action = 'login';
        const screen = String(r.headers.location).split('?')[0]
          .replace(/^https?:\/\/[^/]+/, '');
        const sent = await b.go('POST', screen, { form: form });
        r = await b.go('GET', String(sent.headers.location || ''));
      }
      const loc = String(r.headers.location || '');
      const code = r.status === 302 && loc.indexOf(REDIRECT) === 0
        ? new URL(loc).searchParams.get('code') : null;
      if (code) {
        // Redeemed, so the session has a relying party with a back-channel
        // address to tell.
        await b.go('POST', '/oauth2/token', {
          noCookies: true,
          headers: { authorization: 'Basic ' +
            Buffer.from(CLIENT + ':' + SECRET).toString('base64') },
          form: { grant_type: 'authorization_code', code: code,
                  redirect_uri: REDIRECT, scope: 'openid' } });
      }
      return !!code;
    };
    const honoured = async function (b) {
      const r = await authorize(b);
      return r.status === 302 &&
        String(r.headers.location || '').indexOf(REDIRECT) === 0;
    };

    const scimHeaders = { authorization: 'Basic ' +
      Buffer.from('adel-scim-caller:anything').toString('base64') };
    ldap.createUser('adel-scim-caller', { invent: false });
    const scim = browser(port);
    const scimCreate = async function (userName) {
      const made = await scim.go('POST', '/scim/v2/Users', {
        headers: scimHeaders,
        json: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
                userName: userName } });
      return made.json && made.json.id;
    };
    const scimDelete = function (id) {
      return scim.go('DELETE', '/scim/v2/Users/' + id,
                     { headers: scimHeaders });
    };

    // --- A. a SCIM DELETE ends the session -----------------------------------
    const aliceId = await scimCreate('adel-alice');
    const alice = browser(port);
    note(await signIn(alice, 'adel-alice'),
         'A0. adel-alice signs in (the code flow answers a code)');
    const aliceSessions = authn.sessionsOf('adel-alice');
    const aliceSid = aliceSessions.length ? aliceSessions[0].id : '';
    note(await honoured(alice),
         'A1. and her session is honoured without the screen — single ' +
         'sign-on, before the delete');
    const postedBefore = posted.length;
    const deleted = await scimDelete(aliceId);
    await sleep(400);
    note(deleted.status === 204, 'A2. the SCIM DELETE is answered 204',
         deleted.status);
    note(authn.sessionsOf('adel-alice').length === 0,
         'A3. and her sign-on session is ENDED — it used to live until it ' +
         'ran out', authn.sessionsOf('adel-alice').length);
    note(!(await honoured(alice)),
         'A4. the old session cookie no longer signs in: the authorization ' +
         'endpoint sends the browser to the screen');
    note(revokedFor(aliceSid).length === 1 &&
         revokedFor(aliceSid)[0].initiatingEntity === 'admin',
         'A5. the session observer was told `revoked` once, initiated by an ' +
         'ADMINISTRATOR — CAEP session-revoked at delete time rather than ' +
         'at an expiry labelled `policy`',
         JSON.stringify(revokedFor(aliceSid).map(function (n) {
           return [n.via, n.initiatingEntity];
         })));
    await sleep(200);
    const tokens = posted.slice(postedBefore).filter(function (one) {
      return one.path === '/bc' && /logout_token=/.test(one.body);
    });
    note(tokens.length >= 1,
         'A6. and the relying party was POSTed a back-channel Logout Token',
         posted.length - postedBefore);

    // --- B. the catch-up, for a delete whose consequence did not run here ---
    // The directory reaches account_state through its exports at the moment
    // of the delete, so replacing the one function stands in for a node that
    // only ever saw the entry go.
    const realDeleted = accountState.directoryDeleted;
    const lost = [];
    accountState.directoryDeleted = function (change) {
      lost.push(change);
    };
    const bobId = await scimCreate('adel-bob');
    const bob = browser(port);
    await signIn(bob, 'adel-bob');
    const bobSid = (authn.sessionsOf('adel-bob')[0] || {}).id || '';
    await scimDelete(bobId);
    await sleep(200);
    note(authn.sessionsOf('adel-bob').length === 1 && lost.length === 1,
         'B1. (with the delete\'s consequence lost, as on a node the delete ' +
         'was not made on, the session is still in the store)',
         authn.sessionsOf('adel-bob').length + ' ' + lost.length);
    note(!(await honoured(bob)),
         'B2. the next request presenting it is sent to the screen: ' +
         'sessionOf() treats a session whose person has no entry as ended');
    note(authn.sessionsOf('adel-bob').length === 0 &&
         revokedFor(bobSid).length === 1 &&
         revokedFor(bobSid)[0].initiatingEntity === 'admin',
         'B3. and ends it through dropSession(), with its `revoked` notice',
         authn.sessionsOf('adel-bob').length + ' ' +
         revokedFor(bobSid).length);

    // --- C. what is ended is what they held at the delete --------------------
    // An AccountState of this test's own, whose deferred step waits for the
    // test to run it, so a person can be made again in between.
    const deferred = [];
    const held = new accountState.AccountState(Object.assign(
      accountState.AccountState.defaultDeps(), { later: function (fn) {
        deferred.push(fn);
      } }));
    accountState.directoryDeleted = function (change) {
      return held.directoryDeleted(change);
    };
    const carolId = await scimCreate('adel-carol');
    const carolOld = browser(port);
    await signIn(carolOld, 'adel-carol');
    await scimDelete(carolId);
    await scimCreate('adel-carol');
    const carolNew = browser(port);
    await signIn(carolNew, 'adel-carol');
    const before = authn.sessionsOf('adel-carol').length;
    deferred.splice(0).forEach(function (fn) {
      fn();
    });
    await sleep(200);
    note(before === 2 && authn.sessionsOf('adel-carol').length === 1 &&
         await honoured(carolNew),
         'C1. a person made again under the same name keeps the session ' +
         'they signed in with; only the deleted person\'s was ended',
         before + ' then ' + authn.sessionsOf('adel-carol').length);
    accountState.directoryDeleted = realDeleted;

    server.close();
    rp.close();
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
  const out = path.join(os.tmpdir(), 'account-delete-' + process.pid + '-' +
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
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', ADEL_ROOT: ROOT,
                           ADEL_OUT: out }),
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
               String(result.stderr || '').slice(-1200))) {
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
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'account_delete',
  describe: 'A deleted person (#241): a SCIM DELETE ends their sign-on ' +
            'session — the cookie no longer signs in, the relying party is ' +
            'sent a Logout Token, session-revoked is due — the next ' +
            'request ends a session whose person has no entry, and a ' +
            'person made again under the name keeps theirs',
  run: run
};
