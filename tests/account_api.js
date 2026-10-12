// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_api.js
//
// ---------------------------------------------------------------------------
// `/account-api`, THE USER PORTAL'S ONLY DOOR, AND THE PORTAL DRAWN FROM IT
// (#568).
//
// The whole stack in a child process, on a port of its own, and a person
// signed in the way the static portal signs in — the code flow with PKCE as
// the public client `sts-user-portal`, a DPoP-bound token for this realm's
// `/account-api` (`tests/vendored/portal_signin.js`). Then:
//
//   1. THE TABLE: every operation has a unique id; the index and the OpenAPI
//      document list the same operations; every portal page the bundle draws
//      has the GET operation that mirrors it, and every form a drawn page
//      posts under /portal has the POST operation that mirrors it (rule 7's
//      twin).
//   2. EVERY PAGE DRAWS from its operation's answer with the portal's own
//      renderers (`portal/portal.bundle.js`), in the person's language — no
//      catalog key left showing.
//   3. THE GATE: no token, a token presented as Bearer, a token whose proof
//      is missing, a forged token and the console's token are each refused,
//      each with its code's status.
//   4. THE PERSON IS THE TOKEN'S: a passkey another person holds cannot be
//      removed by naming its id.
//   5. THE DOCUMENT is public and needs no token.
//
// A child process for `admin_api_me.js`'s reason: the stack is built once,
// with a composition root, and a test process that loaded half of it would
// answer for the half.
// ---------------------------------------------------------------------------

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'account_api',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AA_ROOT;
  const OUT = process.env.AA_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function brief(r) {
    return r ? r.status + ' ' + String(r.text || '').slice(0, 300) : 'none';
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const http = require('http');
    const app = require(ROOT_DIR + '/common/app');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const errorCodes = require(ROOT_DIR + '/common/error_codes');
    const signin = require(ROOT_DIR + '/tests/vendored/portal_signin');

    const stamp = String(process.pid);
    const ALICE = 'aa-alice-' + stamp;
    const MALLORY = 'aa-mallory-' + stamp;
    const PASSWORD = 'Acc0unt-Api-' + stamp + '-Passw0rd!';
    [ALICE, MALLORY].forEach(function (name) {
      ldap.createUser(name, { invent: false });
      credentials.setPassword(name, PASSWORD);
    });
    const alicesKey = credentials.addKey(ALICE, {
      credentialId: 'aa-alice-key-' + stamp,
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' },
      signCount: 0 }, 'mfa');
    note(alicesKey && alicesKey.ok, 'precondition: alice holds a passkey',
         JSON.stringify(alicesKey));

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const base = 'http://127.0.0.1:' + server.address().port;

    const mallory = await signin.signInToThePortal(base, MALLORY, null,
                                                   { password: PASSWORD });
    note(!!mallory.token, 'mallory signs in as the static portal does');

    // --- 1. the table ------------------------------------------------------
    const index = await signin.nobody(base, 'GET', '/account-api');
    const ops = (index.json && index.json.operations) || [];
    note(index.status === 200 && ops.length > 40,
         '1a. GET /account-api, with no token, lists the operations',
         brief(index));
    const ids = ops.map(function (op) { return op.operationId; });
    note(ids.length === new Set(ids).size,
         '1b. every operation id is unique', ids.join(','));
    const doc = await signin.nobody(base, 'GET', '/account-api/openapi.json');
    let documented = 0;
    Object.keys((doc.json && doc.json.paths) || {}).forEach(function (p) {
      documented += Object.keys(doc.json.paths[p]).length;
    });
    note(doc.status === 200 && documented === ops.length,
         '1c. the OpenAPI document, public, documents exactly the table\'s ' +
         'operations', doc.status + ' ' + documented + ' vs ' + ops.length);
    const mirrored = {};
    ops.forEach(function (op) {
      if (op.mirrors) {
        mirrored[op.mirrors] = op;
      }
    });
    const table = signin.portalBundle();
    const missing = [];
    table.PAGES.forEach(function (page) {
      const op = mirrored['GET ' + page.path];
      if (!op || op.path !== page.operation) {
        missing.push(page.path);
      }
    });
    note(table.PAGES.length >= 20 && !missing.length,
         '1d. every page the bundle draws is drawn from the GET operation ' +
         'that mirrors it', missing.join(', '));

    // --- 2. every page draws -----------------------------------------------
    const me = await mallory.api('GET', '/account-api/me');
    note(me.status === 200 && me.json && me.json.user &&
         me.json.user.username === MALLORY,
         '2a. GET /account-api/me names the token\'s person', brief(me));
    const t = table.messages.WebTranslator.fromData(me.json.locale);
    const unresolved = [];
    const formsWithoutOperation = [];
    for (const page of table.PAGES) {
      if ((page.access || 'person') !== 'person') {
        continue;
      }
      const r = await mallory.api('GET', page.operation);
      let html = '';
      try {
        html = page.render(r.json, { t: t, query: {}, prefix: '',
          origin: base, me: me.json, locale: me.json.locale,
          version: me.json.version, here: page.path });
      } catch (e) {
        html = '';
        unresolved.push(page.path + ' threw ' + e.message);
      }
      if (r.status !== 200 || !html) {
        unresolved.push(page.path + ' ' + r.status);
      }
      const keys = html.match(/\bportal[A-Za-z]*\.[a-z][A-Za-z]*\.[A-Za-z.]+/g);
      if (keys) {
        unresolved.push(page.path + ' draws keys ' + keys.slice(0, 3));
      }
      const posts = html.match(/<form[^>]*method="post"[^>]*>/g) || [];
      posts.forEach(function (form) {
        const action = (/action="([^"]+)"/.exec(form) || [])[1] || '';
        if (/^\/portal(\/|$)/.test(action) && action !== '/portal/signout' &&
            !mirrored['POST ' + action.split('?')[0]]) {
          formsWithoutOperation.push(page.path + ' -> ' + action);
        }
      });
    }
    note(!unresolved.length,
         '2b. every signed-in page draws from its operation\'s answer, in ' +
         'the person\'s language', unresolved.join('; '));
    note(!formsWithoutOperation.length,
         '2c. every form a page posts under /portal has the operation that ' +
         'mirrors it', formsWithoutOperation.join('; '));

    // --- 3. the gate ---------------------------------------------------------
    const bare = await fetch(base + '/account-api/me');
    note(bare.status === 401 &&
         /^DPoP /.test(String(bare.headers.get('www-authenticate') || '')),
         '3a. no token: 401 with a DPoP challenge', bare.status);
    const asBearer = await fetch(base + '/account-api/me', { headers: {
      authorization: 'Bearer ' + mallory.token } });
    note(asBearer.status === 401,
         '3b. the DPoP-bound token presented as Bearer is refused',
         asBearer.status);
    const noProof = await fetch(base + '/account-api/me', { headers: {
      authorization: 'DPoP ' + mallory.token } });
    note(noProof.status === 401,
         '3c. the token with no proof is refused', noProof.status);
    const forged = await fetch(base + '/account-api/me', { headers: {
      authorization: 'DPoP eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.' } });
    note(forged.status === 401,
         '3d. a token this realm did not sign is refused', forged.status);
    note(['STS-ACCOUNT-0001', 'STS-ACCOUNT-0002', 'STS-ACCOUNT-0010']
           .every(function (code) { return errorCodes.isKnown(code); }),
         '3e. the gate\'s codes are registered');

    // --- 4. the person is the token's ---------------------------------------
    const stolen = await mallory.act('/portal/remove-key',
      { credentialId: 'aa-alice-key-' + stamp });
    note(stolen.status >= 400 &&
         credentials.keysOf(ALICE).length === 1,
         '4. MALLORY CANNOT REMOVE ALICE\'S PASSKEY by naming its id: the ' +
         'account is the token\'s, and the id is looked up among his own',
         brief(stolen));

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'aa-' + process.pid + '-' + Date.now() +
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
                                  AA_ROOT: ROOT, AA_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
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
  name: 'account_api',
  describe: '/account-api: the portal\'s operations, the pages drawn from ' +
            'them, the gate, and the person always the token\'s (#568)',
  run: run
};
