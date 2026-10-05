// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/admin_api_delegation_map.js
// ===========================================================================
// `GET /admin-api/delegation/map` — THE DELEGATION PICTURE AS ONE ANSWER
// (#446, 2026-10-05).
//
// `/admin/delegation/map` had no operation, because it has no form. A
// console that is a static client of `/admin-api` needs one: what each box
// IS comes from the directory and the application registry, and where each
// box GOES is laid out on the server. The operation answers the page's own
// JSON with `looks`, `summary` and `svg` added.
//
// In a CHILD PROCESS with the whole stack on an ephemeral port, one act of
// delegation recorded through the register's own door, and an Admin Read
// token:
//
//   1. the answer is the graph of that act, with a look for every node, the
//      counts, and a drawing that laid out;
//   2. `format=svg` answers the SVG document alone, as `image/svg+xml`, with
//      no links in it;
//   3. the filter narrows it: text matching nobody leaves no act;
//   4. a filter value outside its closed set is refused, as on
//      `/admin-api/delegation`;
//   5. and the index lists the operation as the mirror of the console page.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_api_delegation_map',
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
  // A request with a form body (the token endpoint) or none.
  function request(port, method, urlPath, form, headers) {
    return new Promise(function (resolve, reject) {
      const body = form ? new URLSearchParams(form).toString() : '';
      const all = Object.assign({ accept: 'application/json' }, headers || {});
      if (form) {
        all['content-type'] = 'application/x-www-form-urlencoded';
        all['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: all }, function (res) {
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
          resolve({ status: res.statusCode, text: raw, json: json,
                    headers: res.headers });
        });
      });
      req.on('error', reject);
      req.end(body);
    });
  }
  function settle() {
    // The HTTP row is written when the response has finished.
    return new Promise(function (res) { setTimeout(res, 40); });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const delegation = require(ROOT_DIR + '/common/delegation');

    const stamp = String(process.pid);
    const READER = 'dm-reader-' + stamp;
    const ALICE = 'dm-alice-' + stamp;
    const FRONT = 'dm-frontend-' + stamp;
    const API = 'dm-api-' + stamp;
    [READER, ALICE].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    inDefault(function () {
      rbac.grant(READER, 'read', { via: 'test' });
    });
    const kind = delegation.TYPES[0];
    const act = inDefault(function () {
      return delegation.record({
        protocol: kind.protocol, type: kind.type,
        outcome: delegation.OUTCOMES[0],
        initial: { presented: ALICE },
        intermediary: { presented: FRONT, application: FRONT },
        target: { presented: API, application: API },
        authorizedBy: 'a test', note: 'recorded by a test' });
    });
    note(!!act, 'precondition: one act of delegation was recorded (' +
         kind.type + ')', JSON.stringify(act).slice(0, 200));

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const token = await inDefault(function () {
      return oauth2.accessTokenAsync(base, {
        audience: base + '/admin-api', scope: 'admin:read',
        client_id: 'sts-admin-console', username: READER, sub: READER });
    });
    const get = function (urlPath) {
      return request(port, 'GET', urlPath, null,
                     { authorization: 'Bearer ' + token });
    };
    const MAP = '/admin-api/delegation/map';

    // --- 1. the picture ------------------------------------------------------
    let r = await get(MAP);
    const j = r.json || {};
    const nodes = Array.isArray(j.nodes) ? j.nodes : [];
    const looks = j.looks || {};
    note(r.status === 200 && nodes.length >= 3 &&
         JSON.stringify(nodes).indexOf(ALICE) >= 0 &&
         Array.isArray(j.edges) && j.edges.length >= 1,
         '1a. the answer is the graph of the act: its parties and the ' +
         'lines between them', r.status + ' ' + nodes.length + ' node(s) ' +
         r.text.slice(0, 160));
    note(nodes.length > 0 && nodes.every(function (node) {
           return looks[node.id] && typeof looks[node.id].label === 'string' &&
                  looks[node.id].label !== '';
         }),
         '1b. every node has a look, with a label',
         JSON.stringify(Object.keys(looks)).slice(0, 200));
    note(String(j.svg || '').indexOf('<svg') === 0 && j.drawing &&
         j.drawing.width > 0 && j.drawing.height > 0 &&
         j.drawing.failed === null,
         '1c. the drawing is SVG, and it laid out',
         JSON.stringify(j.drawing) + ' ' + String(j.svg || '').slice(0, 60));
    note(j.matched >= 1 && j.held >= 1 && j.summary &&
         typeof j.summary.byType === 'object',
         '1d. the counts the filter shows are in it',
         JSON.stringify({ matched: j.matched, held: j.held }));

    // --- 2. the document alone -----------------------------------------------
    r = await get(MAP + '?format=svg');
    note(r.status === 200 &&
         /^image\/svg\+xml/.test(String(r.headers['content-type'] || '')) &&
         r.text.indexOf('<svg') === 0 && r.text.indexOf('<a ') < 0 &&
         r.text.indexOf('href=') < 0,
         '2. format=svg answers the SVG document alone, with no links in it',
         r.status + ' ' + r.headers['content-type'] + ' ' +
         r.text.slice(0, 60));

    // --- 3. the filter -------------------------------------------------------
    r = await get(MAP + '?q=' + encodeURIComponent('dm-nobody-' + stamp));
    note(r.status === 200 && r.json && r.json.matched === 0 &&
         JSON.stringify(r.json.nodes || []).indexOf(ALICE) < 0,
         '3. text matching nobody leaves no act in the picture',
         r.status + ' ' + JSON.stringify({ matched: (r.json || {}).matched }));

    // --- 4. a closed set -----------------------------------------------------
    r = await get(MAP + '?type=not-a-mechanism');
    note(r.status === 400,
         '4. a mechanism outside its closed set is refused',
         r.status + ' ' + r.text.slice(0, 160));

    // --- 5. the index --------------------------------------------------------
    r = await get('/admin-api');
    const listed = ((r.json || {}).operations || []).filter(function (one) {
      return one.path === MAP;
    })[0] || null;
    note(!!listed && listed.method === 'GET' &&
         listed.mirrors === 'GET /admin/delegation/map',
         '5. the index lists it as the mirror of the console page',
         JSON.stringify(listed));

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
  const out = path.join(os.tmpdir(), 'dm-' + process.pid + '-' + Date.now() +
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
  name: 'admin_api_delegation_map',
  describe: 'GET /admin-api/delegation/map answers the delegation picture: ' +
            'the graph, each box\'s look and the drawing (#446)',
  run: run
};
