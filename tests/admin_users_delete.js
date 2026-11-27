// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_users_delete.js
//
// ===========================================================================
// AN ADMINISTRATOR DELETES A PERSON THROUGH THE MANAGEMENT API (rcbj,
// 2026-11-16: "Add a user delete endpoint to the admin api").
//
// `POST /admin-api/users/delete` (`deleteUser`) is `usersAction()`'s
// `delete`, which hands the entry to the directory's `deletePerson()` — the
// function SCIM's DELETE calls, on the path an LDAP delete takes — behind two
// refusals of its own. In a CHILD PROCESS with the whole stack on an
// ephemeral port (`admin_api_actor.js`'s arrangement), a person holding
// Admin Write and the console's DPoP-bound token minted for them:
//
//   A. THE DELETE: a person in a group and a role, signed in at a relying
//      party, is deleted over HTTP: 200 with `username` and `dn`; the entry
//      is gone; the group and the role let them go; their sign-on session
//      ends and no longer signs in; their refresh token is refused and their
//      access token introspects inactive; one `user.delete` row names the
//      administrator; made again under the name, they are in neither the
//      group nor the role.
//   B. THE REFUSALS, each 400 with `errors` and its code on the audit row:
//      nobody named; nobody of that name (STS-LDAP-0013); the caller's own
//      entry (STS-ADMIN-0943); the bootstrap administrator (STS-LDAP-0077,
//      and 403 at the gate first: it holds the Security Administrator's
//      role);
//      and the last person a realm's roster lists for Admin Write
//      (STS-ADMIN-0944), which a second holder lifts.
//   C. THE GATES: a person holding the Security Administrator's role is not
//      deleted by Admin Write alone (403); a stale sign-in is asked to sign
//      in again (401 `insufficient_user_authentication`) where
//      `account.recentAuthMinutes` asks for one.
//   D. REALM CONFINEMENT: a name only the default realm holds is nobody under
//      a trust realm's prefix, and stays; a trust realm's namesake of the
//      administrator is not "themselves" there.
//   E. THE CONSOLE: the person page's Delete tab draws the form with a
//      required, unnamed confirmation, and none for a reader; the answer
//      lands on the list without the person.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_users_delete',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AUD_ROOT;
  // An address compared by parsing it (`protocol/url_match.js`),
  // required here: this function runs in a child of its own.
  const urls = require(ROOT_DIR + '/tests/protocol/url_match.js');
  const OUT = process.env.AUD_OUT;
  const http = require('http');
  const crypto = require('crypto');
  let dpopKit = null;
  const DPOP = {
    get jkt() {
      dpopKit = dpopKit || require(ROOT_DIR + '/tests/tools/console_dpop')
        .consoleDpop(ROOT_DIR);
      return dpopKit.jkt;
    },
    headers: function (method, url, token) {
      dpopKit = dpopKit || require(ROOT_DIR + '/tests/tools/console_dpop')
        .consoleDpop(ROOT_DIR);
      return dpopKit.headers(method, url, token);
    }
  };
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };

  // One API call, with the console token's proof where one is given.
  function call(port, method, urlPath, token, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null : JSON.stringify(body);
      const headers = { accept: 'application/json' };
      if (token) {
        Object.assign(headers, DPOP.headers(method, 'http://127.0.0.1:' +
                                            port + urlPath.split('?')[0],
                                            token));
      }
      if (text) {
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(text);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: headers }, function (res) {
        let raw = '';
        res.on('data', function (d) { raw += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers,
                    text: raw, json: json });
        });
      });
      req.on('error', reject);
      if (text) {
        req.write(text);
      }
      req.end();
    });
  }

  // A browser with a cookie jar, for the relying party's code flow.
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

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const applications = require(ROOT_DIR + '/common/applications');
    const roles = require(ROOT_DIR + '/common/roles');
    const audit = require(ROOT_DIR + '/common/audit');
    const errorCodes = require(ROOT_DIR + '/common/error_codes');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const authn = require(ROOT_DIR + '/authn/authn');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const adminActions = require(ROOT_DIR + '/admin-core/admin_actions');

    config.setOverride('oauth2.consentRequired', false);
    config.setOverride('oauth2.backchannelLogoutBackoffMs', 0);

    const stamp = String(process.pid);
    const WRITER = 'aud-writer-' + stamp;
    const VICTIM = 'aud-victim-' + stamp;
    const GROUP = 'aud-group-' + stamp;
    const ROLE = 'aud-role-' + stamp;
    const GUARD = 'aud-guard-' + stamp;
    const ONLY_DEFAULT = 'aud-only-default-' + stamp;
    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    const entryOf = function (name) {
      const found = ldap.locateEntry(name);
      return found && found.stored && ldap.isPersonEntry(found.stored)
        ? found.stored : null;
    };
    const subjectOf = function (name) {
      const stored = entryOf(name);
      return stored ? 'urn:uuid:' +
        String([].concat(stored.attributes.entryuuid)[0]).toLowerCase() : '';
    };
    // The rows of one action about one target, newest first.
    const rows = function (target) {
      return audit.list().filter(function (event) {
        return event.action === 'user.delete' &&
               String(event.target || '').indexOf(target) >= 0;
      });
    };

    [WRITER, VICTIM, GUARD, ONLY_DEFAULT].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    inDefault(function () {
      // The bootstrap administrator, as server.js seeds it, so B4 has an
      // entry to be refused; and a second Admin Write holder.
      rbac.seedBootstrapAdministrator();
      rbac.grant(WRITER, 'write', { via: 'test' });
    });

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const mint = function (username, extra) {
      return inDefault(function () {
        return oauth2.accessTokenAsync(base, Object.assign({
          jkt: DPOP.jkt, audience: base + '/admin-api',
          scope: 'admin:read admin:write', client_id: 'sts-admin-console',
          username: username, sub: subjectOf(username) }, extra || {}));
      });
    };
    const token = await mint(WRITER);
    note(!!token, 'precondition: the administrator\'s console token was ' +
         'minted');
    const del = function (body, as) {
      return call(port, 'POST', '/admin-api/users/delete', as || token,
                  body);
    };

    // --- A. the delete --------------------------------------------------
    const SECRET = 'admin-users-delete-secret-0123456789abcdef';
    const REDIRECT = 'https://rp.users-delete.example/cb';
    const CLIENT = 'aud-client-' + stamp;
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT, oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code', 'refresh_token'],
                oauthAllowedScope: ['openid', 'offline_access'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    const basic = 'Basic ' + Buffer.from(CLIENT + ':' + SECRET)
      .toString('base64');
    const authorize = function (b) {
      return b.go('GET', '/oauth2/authorize?' + new URLSearchParams({
        client_id: CLIENT, response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid offline_access', state: 's',
        nonce: 'n' + crypto.randomBytes(3).toString('hex') }).toString());
    };
    const honoured = async function (b) {
      const r = await authorize(b);
      return r.status === 302 &&
        urls.isAt(String(r.headers.location || ''), REDIRECT);
    };
    const authnScreen = require(ROOT_DIR + '/tests/tools/authn_screen');
    const signIn = async function (b, username) {
      let r = await authorize(b);
      if (r.status === 302 &&
          /\/authn\/login/.test(String(r.headers.location || ''))) {
        const sent = await authnScreen.submit({ port: port, jar: b.jar,
          at: String(r.headers.location),
          fields: { action: 'login', username: username,
                    password: 'anything' } });
        if (sent.next !== 'redirect') {
          return null;
        }
        r = await b.go('GET', String(sent.location || ''));
      }
      const loc = String(r.headers.location || '');
      const code = r.status === 302 && urls.isAt(loc, REDIRECT)
        ? new URL(loc).searchParams.get('code') : null;
      if (!code) {
        return null;
      }
      const redeemed = await b.go('POST', '/oauth2/token', {
        noCookies: true, headers: { authorization: basic },
        form: { grant_type: 'authorization_code', code: code,
                redirect_uri: REDIRECT } });
      return redeemed.json;
    };
    const introspect = async function (b, value) {
      const r = await b.go('POST', '/oauth2/introspect', {
        noCookies: true, headers: { authorization: basic },
        form: { token: value } });
      return r.json || {};
    };

    const victimDn = entryOf(VICTIM).dn;
    const madeGroup = ldap.createGroup(GROUP, { members: [victimDn] });
    const groupDn = madeGroup && madeGroup.dn;
    adminActions.rolesAction({ action: 'create-role', role: ROLE },
                             { actor: 'test', via: 'test' });
    adminActions.rolesAction({ action: 'add-member', role: ROLE,
                               kind: 'user', member: VICTIM },
                             { actor: 'test', via: 'test' });
    const inRole = function () {
      return ((roles.read(ROLE) || {}).users || []).map(function (one) {
        return String(one).toLowerCase();
      }).indexOf(VICTIM) >= 0;
    };
    const inGroup = function () {
      const entry = ldap.readGroupEntry(groupDn);
      return !!entry && (entry.members || []).some(function (m) {
        return String(m.dn || m.value || '').toLowerCase()
          .indexOf('uid=' + VICTIM) === 0;
      });
    };
    const victim = browser(port);
    const issued = await signIn(victim, VICTIM);
    note(!!issued && !!issued.access_token && inGroup() && inRole() &&
         authn.sessionsOf(VICTIM).length === 1,
         'A0. precondition: the person is in a group and a role, signed in ' +
         'with a session, an access token and a refresh token',
         JSON.stringify({ issued: !!issued, refresh: !!(issued &&
           issued.refresh_token), group: inGroup(), role: inRole(),
           sessions: authn.sessionsOf(VICTIM).length }));
    const activeBefore = issued
      ? (await introspect(victim, issued.access_token)).active : null;

    let r = await del({ user: VICTIM });
    note(r.status === 200 && r.json && r.json.ok === true &&
         r.json.changed === true && r.json.username === VICTIM &&
         String(r.json.dn).toLowerCase() === String(victimDn).toLowerCase() &&
         /deleted/.test(String(r.json.message || '')),
         'A1. POST /admin-api/users/delete answers 200 with the username ' +
         'and the DN', r.status + ' ' + r.text.slice(0, 300));
    note(!entryOf(VICTIM), 'A2. the entry is gone from the directory');
    note(!inGroup() && !inRole(),
         'A3. the group and the role let them go (#1612/#1613)',
         'group ' + inGroup() + ' role ' + inRole());
    await sleep(400);
    note(authn.sessionsOf(VICTIM).length === 0 && !(await honoured(victim)),
         'A4. their sign-on session is ended and no longer signs in',
         authn.sessionsOf(VICTIM).length);
    if (issued && issued.refresh_token) {
      const refreshed = await victim.go('POST', '/oauth2/token', {
        noCookies: true, headers: { authorization: basic },
        form: { grant_type: 'refresh_token',
                refresh_token: issued.refresh_token } });
      note(refreshed.status === 400 && refreshed.json &&
           refreshed.json.error === 'invalid_grant',
           'A5. their refresh token is refused (invalid_grant)',
           refreshed.status + ' ' + refreshed.text.slice(0, 200));
    } else {
      note(false, 'A5. a refresh token was issued to try',
           JSON.stringify(issued));
    }
    const activeAfter = issued
      ? (await introspect(victim, issued.access_token)).active : null;
    note(activeBefore === true && activeAfter === false,
         'A6. their access token introspected active before the delete ' +
         'and inactive after', activeBefore + ' then ' + activeAfter);
    const done = rows(victimDn).filter(function (row) {
      return row.outcome === 'success';
    });
    note(done.length === 1 && done[0].actor === WRITER &&
         done[0].category === 'directory',
         'A7. one user.delete row, success, naming the administrator',
         JSON.stringify(done.map(function (row) {
           return [row.actor, row.outcome, row.category];
         })));
    ldap.createUser(VICTIM, { invent: false });
    note(!!entryOf(VICTIM) && !inGroup() && !inRole(),
         'A8. made again under the name, they inherit neither the group ' +
         'nor the role', 'group ' + inGroup() + ' role ' + inRole());

    // --- B. the refusals --------------------------------------------------
    const refusedWith = async function (body, pattern, code, target, as) {
      const before = audit.list().length;
      const answer = await del(body, as);
      const fresh = audit.list().slice(0, audit.list().length - before)
        .filter(function (row) {
          return row.action === 'user.delete';
        });
      return { answer: answer,
               ok: answer.status === 400 && answer.json &&
                   answer.json.ok === false &&
                   pattern.test((answer.json.errors || []).join(' ')) &&
                   !/STS-/.test(answer.text) &&
                   (!code || fresh.some(function (row) {
                     return row.errorCode === code &&
                            row.outcome === 'refused' &&
                            String(row.target).indexOf(target) >= 0;
                   })),
               rows: fresh };
    };
    let x = await refusedWith({ user: '' }, /Name the person/, '', '');
    note(x.ok, 'B1. nobody named: 400', x.answer.status + ' ' +
         x.answer.text.slice(0, 200));
    x = await refusedWith({ user: 'aud-nobody-' + stamp }, /Nobody called/,
                          'STS-LDAP-0013', 'aud-nobody-' + stamp);
    note(x.ok, 'B2. nobody of that name: 400, STS-LDAP-0013 on the row ' +
         'and no code in the answer', x.answer.status + ' ' +
         x.answer.text.slice(0, 200) + ' ' + JSON.stringify(x.rows));
    const writerDn = entryOf(WRITER).dn;
    x = await refusedWith({ user: WRITER }, /your own entry/,
                          'STS-ADMIN-0943', writerDn);
    note(x.ok && !!entryOf(WRITER),
         'B3. the caller\'s own entry: 400, STS-ADMIN-0943, and they stay',
         x.answer.status + ' ' + x.answer.text.slice(0, 200));
    const bootName = inDefault(function () {
      return rbac.bootstrapState().username;
    });
    const bootEntry = entryOf(bootName);
    // Over HTTP the seeded account is the Security Administrator's to act on
    // (it holds that role too), so Admin Write is turned away at the gate;
    // the act itself, as a Security Administrator's call reaches it, meets
    // the directory's own refusal.
    r = await del({ user: bootName });
    const bootAct = adminActions.usersAction({ action: 'delete',
                                              user: bootName },
                                            { via: 'api', actor: WRITER });
    const bootRows = rows(bootEntry ? bootEntry.dn : '?').filter(
      function (row) {
        return row.errorCode === 'STS-LDAP-0077' && row.outcome === 'refused';
      });
    note(!!bootEntry && r.status === 403 && bootAct.ok === false &&
         errorCodes.codeOf(bootAct) === 'STS-LDAP-0077' &&
         /bootstrap administrator/.test(bootAct.errors.join(' ')) &&
         bootRows.length === 1 && !!entryOf(bootName),
         'B4. the bootstrap administrator: Admin Write is refused 403 (it ' +
         'holds the Security Administrator\'s role), the act itself ' +
         'STS-LDAP-0077, and it stays',
         bootName + ' ' + r.status + ' ' + JSON.stringify(bootAct) + ' ' +
         bootRows.length);

    // The last holder, in a realm of its own: its seeded administrator
    // revoked, so the one person granted Admin Write is the last.
    const lastId = 'aud-last-' + crypto.randomBytes(3).toString('hex');
    const made = realms.create({ id: lastId, name: lastId,
                                 description: 'admin_users_delete',
                                 overrides: {} });
    await realms.run(made.realm, async function () {
      const LAST = 'aud-last';
      const SECOND = 'aud-second';
      ldap.createUser(LAST, { invent: false });
      ldap.createUser(SECOND, { invent: false });
      rbac.grant(LAST, 'write', { via: 'test', realm: lastId });
      const boot = rbac.bootstrapState(lastId).username;
      rbac.revoke(boot, 'write', { via: 'test', realm: lastId });
      const roster = (rbac.rosterFor('write', lastId) || {}).members || [];
      const act = function (who) {
        return adminActions.usersAction({ action: 'delete', user: who },
                                        { via: 'api', actor: 'test' });
      };
      let answer = act(LAST);
      note(answer.ok === false &&
           errorCodes.codeOf(answer) === 'STS-ADMIN-0944' &&
           /last person holding Admin Write/.test(answer.errors.join(' ')) &&
           !!entryOf(LAST),
           'B5. the last person the realm\'s roster lists for Admin Write: ' +
           'refused, STS-ADMIN-0944, and they stay',
           JSON.stringify(answer) + ' roster ' + JSON.stringify(
             roster.map(function (m) { return m.dn; })));
      rbac.grant(SECOND, 'write', { via: 'test', realm: lastId });
      answer = act(LAST);
      note(answer.ok === true && !entryOf(LAST),
           'B6. with a second holder, the same delete goes through',
           JSON.stringify(answer));

      // --- D (half). The default realm's administrator is not the trust
      // realm's namesake.
      ldap.createUser(WRITER, { invent: false });
      answer = adminActions.usersAction({ action: 'delete', user: WRITER },
        { via: 'api', actor: WRITER,
          admin: { username: WRITER, sub: subjectOf(WRITER),
                   realm: realms.DEFAULT_ID } });
      note(answer.ok === true && !entryOf(WRITER),
           'D2. in a trust realm, the default realm\'s administrator ' +
           'deletes that realm\'s namesake: it is not themselves',
           JSON.stringify(answer));
      answer = adminActions.usersAction({ action: 'delete', user: SECOND },
        { via: 'api', actor: SECOND,
          admin: { username: SECOND, sub: subjectOf(SECOND),
                   realm: lastId } });
      note(answer.ok === false &&
           errorCodes.codeOf(answer) === 'STS-ADMIN-0943',
           'D3. while the realm\'s own administrator is themselves there',
           JSON.stringify(answer));
    });

    // --- C. the gates -------------------------------------------------------
    inDefault(function () {
      rbac.grant(GUARD, 'security', { via: 'test' });
    });
    r = await del({ user: GUARD });
    note(r.status === 403 && !!entryOf(GUARD),
         'C1. a Security Administrator is not deleted by Admin Write ' +
         'alone: 403, and they stay', r.status + ' ' + r.text.slice(0, 200));
    config.setOverride('account.recentAuthMinutes', 15);
    const stale = await mint(WRITER, { auth_time: Math.floor(Date.now() /
                                                   1000) - 3600 });
    r = await del({ user: ONLY_DEFAULT }, stale);
    config.clearOverride('account.recentAuthMinutes');
    note(r.status === 401 &&
         /insufficient_user_authentication/.test(String(
           r.headers['www-authenticate'] || '')) && !!entryOf(ONLY_DEFAULT),
         'C2. a sign-in an hour old is asked to sign in again (RFC 9470), ' +
         'and nothing is deleted', r.status + ' ' +
         r.headers['www-authenticate']);

    // --- D. realm confinement over HTTP ---------------------------------
    config.setOverride('adminApi.authRequired', false);
    r = await call(port, 'POST', '/realm/' + lastId +
                   '/admin-api/users/delete', '', { user: ONLY_DEFAULT });
    config.clearOverride('adminApi.authRequired');
    note(r.status === 400 && /Nobody called/.test(r.text) &&
         !!entryOf(ONLY_DEFAULT),
         'D1. under a trust realm\'s prefix, a name only the default realm ' +
         'holds is nobody, and the default realm\'s person stays',
         r.status + ' ' + r.text.slice(0, 200));
    realms.remove(lastId);

    // --- E. the console ---------------------------------------------------
    const users = require(ROOT_DIR + '/admin-ui/web_users');
    const UsersPage = users.UsersPage || users;
    const answers = require(ROOT_DIR + '/admin-ui/web_answers');
    const WebAnswers = answers.WebAnswers || answers;
    const t = { html: function (k) { return k; },
                text: function (k) { return k; } };
    const drawn = UsersPage.userDeleteSection(t, 'bob', { write: true },
                                              '/admin/users?user=bob');
    const readOnly = UsersPage.userDeleteSection(t, 'bob', { write: false },
                                                 '/admin/users?user=bob');
    note(/value="delete"/.test(drawn) && /name="user" value="bob"/
           .test(drawn) &&
         /<input type="checkbox" id="user-delete-confirm" required>/
           .test(drawn) && readOnly.indexOf('<form') < 0,
         'E1. the Delete tab posts `delete` for the person behind a ' +
         'required, unnamed confirmation; a reader gets no form',
         drawn.slice(0, 400));
    const landed = WebAnswers.landing('/admin/users', 'delete', { ok: true },
                                      '/admin/users?user=bob&q=b', {});
    note(landed === '/admin/users?q=b',
         'E2. the answer lands on the list without the person', landed);

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'aud-' + process.pid + '-' +
                        Date.now() + '.json');
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
                                  AUD_ROOT: ROOT, AUD_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
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
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_users_delete',
  describe: 'POST /admin-api/users/delete deletes a person through the ' +
            'directory\'s one person delete — groups, roles, sessions and ' +
            'tokens with them — and refuses nobody, the caller themselves, ' +
            'the bootstrap administrator and the last Admin Write holder ' +
            '(rcbj, 2026-11-16)',
  run: run
};
