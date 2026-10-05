// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/console_runtime.js
//
// ---------------------------------------------------------------------------
// THE STATIC CONSOLE'S RUNTIME, DRIVEN IN NODE AGAINST THE REAL SERVICE
// (#446, step 5).
//
// `admin-ui/web_runtime.ts` takes every browser object through its
// constructor, so here it is given node's own `fetch` and WebCrypto, and
// stand-ins for the location, the history, the document and sessionStorage,
// and pointed at this service over HTTP — in a CHILD PROCESS with the whole
// stack, where the seeded console is declared a PUBLIC client (as the
// cutover will seed it) and allowed the password grant, so a token can be
// had without the sign-in screen. What is held:
//
//   1. Signing in begins with PKCE (S256), the realm's own authorize
//      endpoint, `resource` naming its `/admin-api`, and the verifier and the
//      state kept for the callback — and a callback whose state does not
//      match is refused, not redeemed.
//   2. The runtime's own DPoP proofs are accepted: a token it asks for is
//      DPoP-bound to its key, and `/admin-api/me` answers it as the person.
//   3. A `use_dpop_nonce` refusal is retried once, with the nonce the server
//      sent in the proof.
//   4. A console path is drawn in the frame, from its operation's answer.
//   5. A POST form goes to the operation that mirrors it, and the page is
//      drawn again with the answer in the strip; a form no operation
//      mirrors is refused without a request.
//   6. A drill-down's way up names its section and keeps the list's state.
//   7. A tab survives: a page drawn at an address with a fragment makes it
//      the `:target` again (a panel drawn after the navigation is not), and
//      an act returns to the tab its form was on.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'console_runtime',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AG_ROOT;
  const OUT = process.env.AG_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function claimsOf(jwt) {
    try {
      return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
        .toString('utf8'));
    } catch (e) {
      // Not a JWT; the finding that reads it reports that.
      return { unreadable: String((e && e.message) || e) };
    }
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const applications = require(ROOT_DIR + '/common/applications');
    const ConsoleRuntime = require(ROOT_DIR + '/admin-ui/web_runtime');

    const stamp = String(process.pid);
    const WRITER = 'cr-writer-' + stamp;
    const CONSOLE = 'sts-admin-console';
    ldap.createUser(WRITER, { invent: false });
    realms.run(realms.DEFAULT_REALM, function () {
      rbac.grant(WRITER, 'write', { via: 'test' });
    });
    // The console as the cutover seeds it: public, DPoP-bound — and, here
    // alone, allowed the password grant so no sign-in screen is needed.
    const document = Object.assign({}, applications.registrationOf(CONSOLE), {
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token', 'password'] });
    delete document.client_secret;
    delete document.client_secret_expires_at;
    applications.updateRegistration(CONSOLE, document);
    applications.updateApplication(CONSOLE, {
      attribute: 'oauthTokenEndpointAuthMethod', mode: 'remove',
      value: 'private_key_jwt' });

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const origin = 'http://127.0.0.1:' + port;

    // THE BROWSER'S OBJECTS, AS STAND-INS where node has none.
    const makeEnv = function (pathname, search, fetchImpl) {
      const assigned = [];
      const replaced = [];
      const store = {};
      const location = {
        origin: origin, pathname: pathname, search: search || '', hash: '',
        get href() {
          return origin + this.pathname + this.search + this.hash;
        },
        assign: function (url) {
          assigned.push(url);
        },
        // A navigation in place, as the browser's: recorded, and the
        // address it names is where the location now is.
        replace: function (url) {
          replaced.push(url);
          const u = new URL(url, origin);
          location.pathname = u.pathname;
          location.search = u.search;
          location.hash = u.hash;
        }
      };
      const move = function (_s, _t, url) {
        const u = new URL(url, origin);
        location.pathname = u.pathname;
        location.search = u.search;
        location.hash = u.hash;
      };
      const doc = { title: '', body: { innerHTML: '' },
                    querySelectorAll: function () { return []; },
                    addEventListener: function () {} };
      return {
        assigned: assigned, replaced: replaced, store: store,
        env: {
          fetch: fetchImpl || fetch, crypto: globalThis.crypto,
          location: location,
          history: { pushState: move, replaceState: move },
          document: doc,
          sessionStorage: {
            getItem: function (k) {
              return Object.prototype.hasOwnProperty.call(store, k)
                ? store[k] : null;
            },
            setItem: function (k, v) { store[k] = String(v); },
            removeItem: function (k) { delete store[k]; }
          },
          formDataOf: function (form) {
            const data = new FormData();
            Object.keys(form.fields).forEach(function (name) {
              data.append(name, form.fields[name]);
            });
            return data;
          }
        }
      };
    };
    const signedIn = async function (runtime) {
      const answer = await runtime.tokenRequest({
        grant_type: 'password', username: WRITER, password: 'anything',
        scope: 'openid admin:read admin:write', client_id: CONSOLE,
        resource: runtime.resource() });
      if (answer.status === 200) {
        runtime.keepTokens(answer.json);
      }
      return answer;
    };

    // --- 1. sign-in begins, and a callback that is not ours is refused ---
    let one = makeEnv('/admin/users', '?q=a');
    let runtime = new ConsoleRuntime(one.env);
    await runtime.route();
    const to = new URL(one.assigned[0] || 'http://x/', origin);
    const saved = JSON.parse(one.store['sts-console-signin'] || '{}');
    note(to.pathname === '/oauth2/authorize' &&
         to.searchParams.get('client_id') === CONSOLE &&
         to.searchParams.get('code_challenge_method') === 'S256' &&
         !!to.searchParams.get('code_challenge') &&
         to.searchParams.get('resource') === origin + '/admin-api' &&
         to.searchParams.get('redirect_uri') === origin + '/admin/callback' &&
         to.searchParams.get('state') === saved.state && !!saved.verifier &&
         saved.returnTo === '/admin/users?q=a',
         '1a. with no token, a page begins a sign-in: PKCE S256, the ' +
         'realm\'s authorize endpoint, resource its /admin-api, and the ' +
         'verifier and state kept for the callback', one.assigned[0]);
    one.env.location.pathname = '/admin/callback';
    one.env.location.search = '?code=abc&state=not-the-state';
    runtime = new ConsoleRuntime(one.env);
    await runtime.route();
    note(/cannot be finished/.test(one.env.document.body.innerHTML) &&
         !one.store['sts-console-signin'],
         '1b. a callback whose state is not the one kept is refused, and ' +
         'the kept values are spent', one.env.document.body.innerHTML
           .slice(0, 160));

    // --- 2. its proofs are accepted ---
    const two = makeEnv('/admin', '');
    runtime = new ConsoleRuntime(two.env);
    const issued = await signedIn(runtime);
    const claims = claimsOf((issued.json || {}).access_token);
    const me = await runtime.apiJson('GET', '/admin-api/me');
    note(issued.status === 200 &&
         String(issued.json.token_type || '').toLowerCase() === 'dpop' &&
         !!(claims.cnf && claims.cnf.jkt) && me && me.status === 200 &&
         me.json.caller && me.json.caller.name === WRITER &&
         me.json.write === true,
         '2. a token the runtime asks for is DPoP-bound to its key, and ' +
         '/admin-api/me answers its proof as the person',
         issued.status + ' ' + JSON.stringify(claims.cnf || null) + ' ' +
         (me ? me.status + ' ' + JSON.stringify(me.json).slice(0, 160)
             : 'no answer'));

    // --- 3. a nonce is asked for once, and sent ---
    let refused = false;
    const proofs = [];
    const nonceFetch = async function (url, init) {
      if (String(url).indexOf('/admin-api/') >= 0) {
        proofs.push(init.headers.DPoP);
        if (!refused) {
          refused = true;
          return new Response('', { status: 401, headers: {
            'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
            'DPoP-Nonce': 'nonce-from-the-server' } });
        }
      }
      return fetch(url, init);
    };
    const three = makeEnv('/admin', '', nonceFetch);
    runtime = new ConsoleRuntime(three.env);
    await signedIn(runtime);
    const again = await runtime.apiJson('GET', '/admin-api/me');
    note(again && again.status === 200 && proofs.length === 2 &&
         !claimsOf(proofs[0]).nonce &&
         claimsOf(proofs[1]).nonce === 'nonce-from-the-server',
         '3. a use_dpop_nonce refusal is retried once, with the nonce the ' +
         'server sent in the proof',
         (again ? again.status : 'none') + ' ' + proofs.length + ' ' +
         JSON.stringify(proofs.map(function (p) {
           return claimsOf(p).nonce || null;
         })));

    // --- 4. a page is drawn in the frame ---
    const four = makeEnv('/admin/users', '');
    runtime = new ConsoleRuntime(four.env);
    await signedIn(runtime);
    await runtime.route();
    const html = four.env.document.body.innerHTML;
    note(/^<div class="shell">/.test(html) && /<h1>Users<\/h1>/.test(html) &&
         html.indexOf('IYA STS admin') >= 0 &&
         html.indexOf(WRITER) >= 0,
         '4. /admin/users is drawn in the console\'s frame from ' +
         'GET /admin-api/users', html.slice(0, 200));

    // --- 5. a form goes to its operation; one with none is refused ---
    await runtime.submit({ getAttribute: function (name) {
      return name === 'action' ? '/admin/users' : '';
    }, fields: { action: 'clear-email-factor', user: WRITER } }, null);
    const after = four.env.location.search;
    note(/^\?(notice|error)=/.test(after) &&
         after.indexOf('no%20%2Fadmin-api%20operation') < 0 &&
         /<h1>Users<\/h1>/.test(four.env.document.body.innerHTML),
         '5a. a POST form is sent to the operation that mirrors it, and ' +
         'the page is drawn again with the answer in the strip',
         decodeURIComponent(after).slice(0, 200));
    let asked = 0;
    const counting = async function (url, init) {
      if (init && init.method === 'POST' &&
          String(url).indexOf('/admin-api/') >= 0) {
        asked++;
      }
      return fetch(url, init);
    };
    const five = makeEnv('/admin/users', '', counting);
    runtime = new ConsoleRuntime(five.env);
    await signedIn(runtime);
    await runtime.route();
    await runtime.submit({ getAttribute: function (name) {
      return name === 'action' ? '/admin/users' : '';
    }, fields: { action: 'no-such-act' } }, null);
    note(asked === 0 &&
         /no %2Fadmin-api operation|no%20%2Fadmin-api%20operation/
           .test(five.env.location.search),
         '5b. a form no operation mirrors is refused, and nothing is sent',
         asked + ' ' + decodeURIComponent(five.env.location.search)
           .slice(0, 200));

    // --- 6. a drill-down's way up ---
    const six = makeEnv('/admin/users', '?user=' + WRITER + '&q=cr');
    runtime = new ConsoleRuntime(six.env);
    await signedIn(runtime);
    await runtime.route();
    const drilled = six.env.document.body.innerHTML;
    note(drilled.indexOf('href="/admin/users?q=cr"') >= 0 &&
         drilled.indexOf('<h1>Users ' + WRITER + '</h1>') >= 0,
         '6. a drill-down is titled for its item and its trail goes back ' +
         'to the list as it was filtered', drilled.slice(0, 300));

    // --- 7. a tab survives the drawing and the act ---
    const seven = makeEnv('/admin/users', '');
    seven.env.location.hash = '#tab-config';
    runtime = new ConsoleRuntime(seven.env);
    await signedIn(runtime);
    await runtime.route();
    note(seven.replaced.length === 1 &&
         seven.replaced[0] === '/admin/users#tab-config',
         '7a. a page drawn at an address with a fragment navigates to it ' +
         'again, so the tab\'s panel is the :target of the page drawn',
         JSON.stringify(seven.replaced));
    await runtime.submit({ getAttribute: function (name) {
      return name === 'action' ? '/admin/users' : '';
    }, fields: { action: 'clear-email-factor', user: WRITER } }, null);
    note(seven.env.location.hash === '#tab-config' &&
         /^\?(notice|error)=/.test(seven.env.location.search) &&
         seven.replaced[seven.replaced.length - 1] ===
           '/admin/users' + seven.env.location.search + '#tab-config',
         '7b. an act returns to the tab its form was on, with its answer ' +
         'in the strip', JSON.stringify(seven.replaced) + ' ' +
           seven.env.location.href);

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
  const out = path.join(os.tmpdir(), 'cr-' + process.pid + '-' + Date.now() +
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
                                  AG_ROOT: ROOT, AG_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
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
    // Already gone, or never written; the check below says which.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  t.check(Array.isArray(findings) && findings.length > 0,
          'the child process wrote its findings',
          (result.stderr || '').slice(-600));
  (findings || []).forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'console runtime',
  describe: 'the static console\'s runtime, driven in node against the ' +
            'service: PKCE sign-in, its DPoP proofs and nonce retry, a page ' +
            'drawn in its frame, forms sent to their operations',
  run: run
};
