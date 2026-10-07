// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/hosted_applications.js
// ===========================================================================
// EVERY ROUTE BELONGS TO A HOSTED APPLICATION (#472, 2026-10-07).
//
// An administrator maps hosted applications to listeners
// (`common/listener_map.js`), and `common/app.js` answers a path only on the
// listeners its application is on. A route that no application claims would
// answer on EVERY listener — the console moved to a listener of its own and
// a new page of it still reachable on the main port — so the catalogue in
// `common/hosted_applications.js` is held to the router here, in a CHILD
// PROCESS that loads the whole stack:
//
//   1. every path the express router holds is classified (the catch-all
//      CORS preflight `*` and the regular-expression routes excepted, which
//      are listed by name);
//   2. `/healthcheck` is answered everywhere and no application owns it;
//   3. a handful of paths are where a reader expects: the console's,
//      the API's, a named authorization server's, an EST label's;
//   4. no two applications claim one prefix, and every catalogue entry
//      claims at least one route, so an entry cannot outlive what it named.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'hosted_applications',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.HA_ROOT;
  const OUT = process.env.HA_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const apps = require(ROOT_DIR + '/common/hosted_applications');
    const router = app._router || app.router;
    const paths = [];
    (router.stack || []).forEach(function (layer) {
      const p = layer.route && layer.route.path;
      if (!p) {
        return;
      }
      (Array.isArray(p) ? p : [p]).forEach(function (one) {
        if (typeof one === 'string' && paths.indexOf(one) < 0) {
          paths.push(one);
        }
      });
    });
    note(paths.length > 100, 'the router holds the whole stack',
         paths.length);
    const unclaimed = paths.filter(function (one) {
      return one !== '*' && !apps.classify(one);
    });
    note(unclaimed.length === 0, '1. every route belongs to a hosted ' +
         'application', unclaimed.join(', '));
    note(apps.classify('/healthcheck') === apps.EVERYWHERE,
         '2. /healthcheck is answered everywhere');
    const expected = {
      '/admin': 'admin-console',
      '/admin/listeners': 'admin-console',
      '/admin-api/listeners': 'management-api',
      '/authn/login': 'authn',
      '/logout': 'authn',
      '/tls/sign-in': 'authn',
      '/tls/trust': 'tls',
      '/portal/keys': 'portal',
      '/oauth2/token': 'oauth-oidc',
      '/finance/oauth2/token': 'oauth-oidc',
      '/finance/.well-known/openid-configuration': 'oauth-oidc',
      '/.well-known/oauth-authorization-server/finance': 'oauth-oidc',
      '/finance/gnap': 'gnap',
      '/.well-known/est/tls/simpleenroll': 'est',
      '/enroll/acme/directory': 'acme',
      '/crypto/metadata.json': 'pki',
      '/': 'home'
    };
    const wrong = Object.keys(expected).filter(function (p) {
      return apps.classify(p) !== expected[p];
    }).map(function (p) {
      return p + ' -> ' + apps.classify(p);
    });
    note(wrong.length === 0, '3. the paths a reader expects are where a ' +
         'reader expects them', wrong.join(', '));
    const owners = {};
    const twice = [];
    apps.list().forEach(function (one) {
      one.prefixes.concat(one.exact).forEach(function (p) {
        if (owners[p]) {
          twice.push(p + ' (' + owners[p] + ', ' + one.id + ')');
        }
        owners[p] = one.id;
      });
    });
    note(twice.length === 0, '4a. no path is claimed by two applications',
         twice.join(', '));
    const idle = apps.list().filter(function (one) {
      return !paths.some(function (p) {
        return apps.classify(p) === one.id;
      });
    }).map(function (one) {
      return one.id;
    });
    note(idle.length === 0, '4b. every application claims a route',
         idle.join(', '));
  } catch (e) {
    note(false, 'the child process ran to the end', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'hosted-applications-' + process.pid +
                        '-' + Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  HA_ROOT: ROOT, HA_OUT: out }),
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
  name: 'hosted_applications',
  describe: 'every route belongs to a hosted application, so no route ' +
            'answers on a listener its application was moved off (#472)',
  run: run
};
