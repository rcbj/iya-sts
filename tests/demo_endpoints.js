// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: demo_endpoints.js
//
// ===========================================================================
// A DEMONSTRATION IS SERVED AND LISTED ONLY IN DEVELOPMENT (#585, rcbj
// 2026-10-12).
//
// Every demonstration, mock and test-control endpoint carries
// `common/app.js`'s mark — `demoOnly`, or `processDemoOnly` for a door to
// something the whole process shares — and in a product realm it answers
// EXACTLY as a path nothing is registered on: Express's own `Cannot GET …`
// 404. The lists read the same mark off the router. So:
//
//   A. The mark and the description agree: every marked route's
//      `sts_metadata.ts` row is flagged `demo`, every flagged row's route is
//      marked, and the inventory below is what is marked — a new
//      demonstration, or one that lost its mark, fails here by name.
//   B. In a PRODUCT realm every marked path, by every method it has,
//      answers Express's own 404; in the DEVELOPMENT default realm none
//      does (each reaches its handler).
//   C. With the PROCESS in product, a development realm keeps `demoOnly`'s
//      routes (no route carries `processDemoOnly` since #597, which deleted
//      the truststore's two open doors).
//   D. The lists in a product realm: `/admin/sts-metadata` has no demo row,
//      no drift and no mismatch; the Protocols pages list no demonstration;
//      the hosted-applications catalogue offers no demo prefix or
//      application; and the four checks hold in development too.
//
// IN A CHILD, `protocol_endpoints.js`'s arrangement: it loads the whole
// stack, and one loaded into the runner would be shared with every later
// file.
// ===========================================================================

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');
const log = require('bunyan').createLogger({ name: 'demo_endpoints',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// The child. Everything it needs is required inside, so the function can be
// shipped as source with `node -e`; it has no logger, so its reasons travel
// on its findings.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.DE_ROOT;
  const OUT = process.env.DE_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  // THE INVENTORY (#585's table, and what its build found beside it): every
  // path a demonstration mark is on, with which mark.
  // The two that carried `processDemoOnly`, `POST /tls/trust` and `POST
  // /tls/trust/clear`, were deleted by #597; the mark stays for the
  // process's sockets (the protected Kerberos service's), which no route
  // carries.
  const PROCESS_MARKED = [];
  const REALM_MARKED = [
    // The SAML and WS-Federation mock relying parties were deleted (#592),
    // and the commands mock relying party moved to the test peer and
    // /xacml/protected to the remote PEP (#596).
    '/issuer', '/issuer/offer', '/oid4vp/verifier', '/oid4vp/start',
    '/oid4vp/done', '/oid4vp/result/:state', '/spnego', '/spnego/protected',
    '/krb5/service', '/krb5/principals',
    '/vc-api/issuers',
    '/vc-api/issuers/:issuer/credentials/issue', '/vc-api/credentials/verify',
    '/vc-api/presentations/verify',
    '/vc-api/holders/:holder/presentations/prove',
    '/vc-api/credentials/derive', '/vc-api/credentials/status',
    '/vc-api/resolve', '/vc-api/dereference',
    '/oid4vci/status-lists/bitstring/:purpose/publish',
    '/oid4vci/last_request', '/oid4vci/notification/:id', '/did/generate',
    // The demonstration issuer's and verifier's static surface (#582): its
    // script and the API its five pages are drawn from.
    '/issuer/demo.js', '/vc-demo-api', '/vc-demo-api/issuer',
    '/vc-demo-api/offer', '/vc-demo-api/verifier', '/vc-demo-api/start',
    '/vc-demo-api/done',
    // `/dpop/nonce-mode` (a setting now), `/devices/test/compliance` (the
    // MDM feed is the door), `/tls`, `/tls/forwarded` and `/tls/pages.js`
    // (Monitoring → TLS connection) left with #597.
    // The SPNEGO diagnostic surface's script (#583), a demonstration like
    // the pages it draws.
    '/spnego/pages.js'];
  // A concrete path for a pattern.
  function concrete(p) {
    return p.replace(/:([A-Za-z_]+)/g, 'probe');
  }
  function ask(port, method, urlPath) {
    return new Promise(function (resolve) {
      const req = http.request({ host: '127.0.0.1', port: port,
                                 method: method, path: urlPath,
                                 headers: { accept: 'application/json' } },
        function (res) {
          const chunks = [];
          res.on('data', function (c) {
            chunks.push(c);
          });
          res.on('end', function () {
            resolve({ status: res.statusCode,
                      body: Buffer.concat(chunks).toString('utf8') });
          });
        });
      // A handler that never answers is a finding, not a hang.
      req.setTimeout(20000, function () {
        req.destroy(new Error('timed out'));
      });
      req.on('error', function (e) {
        resolve({ status: 0, body: 'error: ' + e.message });
      });
      req.end();
    });
  }
  function unrouted(answer, method) {
    return answer.status === 404 &&
      new RegExp('Cannot ' + method + ' ').test(
        answer.body.replace(/<[^>]*>/g, ''));
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const realms = require(ROOT_DIR + '/common/realms');
    const config = require(ROOT_DIR + '/common/config');
    const mode = require(ROOT_DIR + '/common/mode');
    const metadata = require(ROOT_DIR + '/sts_metadata');
    const table = require(ROOT_DIR + '/admin-core/protocol_endpoints');
    const hosted = require(ROOT_DIR + '/common/hosted_applications');

    // --- A. the mark and the description agree ------------------------------
    const router = app._router || app.router;
    const marks = {};
    const methods = {};
    router.stack.forEach(function (layer) {
      if (!layer.route) {
        return;
      }
      const p = String(layer.route.path);
      const mark = app.demoMarkOf(layer.route);
      if (mark) {
        marks[p] = mark.stsDemo;
        methods[p] = (methods[p] || []).concat(
          Object.keys(layer.route.methods).filter(function (m) {
            return m !== '_all';
          }).map(function (m) {
            return m.toUpperCase();
          }));
      }
    });
    const expected = {};
    REALM_MARKED.forEach(function (p) {
      expected[p] = 'realm';
    });
    PROCESS_MARKED.forEach(function (p) {
      expected[p] = 'process';
    });
    const wrong = Object.keys(expected).filter(function (p) {
      return marks[p] !== expected[p];
    }).concat(Object.keys(marks).filter(function (p) {
      return !expected[p];
    }));
    note(wrong.length === 0, 'A1. the routes marked are the inventory, ' +
         'each with its mark', wrong.map(function (p) {
           return p + ' ' + (marks[p] || 'unmarked') + ' want ' +
             (expected[p] || 'unmarked');
         }).join(', ') || Object.keys(marks).length + ' marked');
    const flagged = {};
    metadata.ENDPOINTS.forEach(function (row) {
      if (row.demo) {
        flagged[row.path] = true;
      }
    });
    const disagree = Object.keys(flagged).filter(function (p) {
      return !marks[p];
    }).concat(Object.keys(marks).filter(function (p) {
      return !flagged[p];
    }));
    note(disagree.length === 0, 'A2. every marked route\'s row is flagged ' +
         'demo, and every flagged row\'s route is marked',
         disagree.join(', ') || 'agree');
    const developmentReport = metadata.describeEndpoints();
    note((developmentReport.demoMismatch || []).length === 0 &&
         developmentReport.undocumented.length === 0 &&
         developmentReport.stale.length === 0 &&
         (developmentReport.hiddenSpecs || []).length === 0,
         'A3. in development the page lists every demonstration, with no ' +
         'drift', JSON.stringify({
           mismatch: developmentReport.demoMismatch,
           undocumented: developmentReport.undocumented,
           stale: developmentReport.stale }));

    const server = http.createServer(app);
    await new Promise(function (resolve) {
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;

    // --- B. a product realm answers as unrouted; development answers --------
    const PRODUCT = 'demoproduct';
    realms.create({ id: PRODUCT, name: PRODUCT,
                    overrides: { 'global.mode': 'product' } });
    const answeredInProduct = [];
    const missingInDevelopment = [];
    for (const p of Object.keys(marks)) {
      for (const m of methods[p]) {
        const inProduct = await ask(port, m,
                                    '/realm/' + PRODUCT + concrete(p));
        if (!unrouted(inProduct, m)) {
          answeredInProduct.push(m + ' ' + p + ' ' + inProduct.status);
        }
        const inDevelopment = await ask(port, m, concrete(p));
        if (unrouted(inDevelopment, m) || inDevelopment.status === 0) {
          missingInDevelopment.push(m + ' ' + p + ' ' + inDevelopment.status +
                                    ' ' + inDevelopment.body.slice(0, 60));
        }
      }
    }
    note(answeredInProduct.length === 0, 'B1. in a product realm every ' +
         'demonstration, by every method, answers Express\'s own 404',
         answeredInProduct.join(', ') || 'all unrouted');
    note(missingInDevelopment.length === 0, 'B2. in the development ' +
         'default realm every demonstration reaches its handler',
         missingInDevelopment.join(', ') || 'all served');
    const unregistered = await ask(port, 'GET',
                                   '/realm/' + PRODUCT + '/spnego');
    const nothing = await ask(port, 'GET', '/realm/' + PRODUCT +
                              '/no-such-path-anywhere');
    note(unregistered.body.replace(/\/spnego/, '/X') ===
         nothing.body.replace(/\/no-such-path-anywhere/, '/X'),
         'B3. and the 404 is the unrouted one, body for body',
         unregistered.body.slice(0, 80));

    // --- C. the process's doors ---------------------------------------------
    const DEVELOPMENT = 'demodevelopment';
    realms.create({ id: DEVELOPMENT, name: DEVELOPMENT,
                    overrides: { 'global.mode': 'development' } });
    config.setOverride('global.mode', 'product');
    try {
      const realmDemo = await ask(port, 'GET', '/realm/' + DEVELOPMENT +
                                  '/spnego');
      const defaultRealm = await ask(port, 'GET', '/spnego');
      note(!unrouted(realmDemo, 'GET') && unrouted(defaultRealm, 'GET'),
           'C1. with the process in product, a development realm keeps ' +
           'demoOnly\'s routes and the default realm does not (no route ' +
           'carries processDemoOnly since #597)',
           realmDemo.status + ' ' + defaultRealm.status);
    } finally {
      config.clearOverride('global.mode');
    }

    // --- D. the lists in a product realm ------------------------------------
    // How many prefixes the catalogue offers a product realm, for D6.
    let productPrefixes = 0;
    realms.run(realms.get(PRODUCT), function () {
      note(mode.servesDemoEndpoints() === false,
           'D0. the product realm says it serves no demonstration');
      const report = metadata.describeEndpoints();
      const listed = report.rows.filter(function (row) {
        return row.demo || marks[row.path];
      }).map(function (row) {
        return row.path;
      });
      note(listed.length === 0 && report.undocumented.length === 0 &&
           report.stale.length === 0 &&
           (report.demoMismatch || []).length === 0 &&
           report.unknownProtocolGroups.length === 0 &&
           report.unclaimedGroups.length === 0,
           'D1. /admin/sts-metadata lists no demonstration in a product ' +
           'realm, with no drift either way',
           JSON.stringify({ listed: listed, undocumented: report.undocumented,
                            stale: report.stale,
                            groups: report.unknownProtocolGroups }));
      const cited = new Set();
      report.rows.forEach(function (row) {
        (row.specs || []).forEach(function (id) {
          cited.add(id);
        });
      });
      const hidden = report.hiddenSpecs || [];
      const idle = metadata.SPECS.filter(function (spec) {
        return hidden.indexOf(spec.id) < 0 && !cited.has(spec.id);
      }).map(function (spec) {
        return spec.id;
      });
      const cardIdle = [];
      report.protocols.forEach(function (card) {
        card.specs.forEach(function (id) {
          if (hidden.indexOf(id) >= 0) {
            cardIdle.push(card.name + ' ' + id);
          }
        });
        if (!card.groups.length && !card.sockets) {
          cardIdle.push(card.name + ' (no group, no socket)');
        }
      });
      note(idle.length === 0 && cardIdle.length === 0 &&
           hidden.indexOf('vc-api') >= 0,
           'D2. a specification only a demonstration cited leaves the page ' +
           'and the cards (the VC-API among them), and no other is idle',
           JSON.stringify({ hidden: hidden, idle: idle, cards: cardIdle }));
      const shown = [];
      table.pages().forEach(function (page) {
        const req = { path: page, originalUrl: page, query: {},
                      protocol: 'https', headers: { host: 'demo.test' },
                      get: function (name) {
                        return String(name).toLowerCase() === 'host' ?
                          'demo.test' : undefined;
                      } };
        (table.forPage(req, page) || []).forEach(function (row) {
          if ((row.route && marks[row.route]) ||
              /protected Kerberos service/.test(row.name || '')) {
            shown.push(page + ' ' + (row.route || row.url));
          }
        });
      });
      note(shown.length === 0, 'D3. no Protocols page lists a ' +
           'demonstration in a product realm', shown.join(', ') || 'none');
      const catalogue = hosted.list();
      productPrefixes = catalogue.reduce(function (n, one) {
        return n + one.prefixes.length;
      }, 0);
      const offered = [];
      catalogue.forEach(function (one) {
        one.prefixes.forEach(function (prefix) {
          if (['/vc-api', '/issuer', '/did', '/spnego', '/vc-demo-api']
              .indexOf(prefix) >= 0) {
            offered.push(prefix);
          }
        });
      });
      note(offered.length === 0, 'D4. the hosted-applications catalogue ' +
           'offers no demonstration prefix or application in a product realm',
           offered.join(', ') || 'none');
      note(app.demoPathHidden('/spnego') &&
           !app.demoPathHidden('/saml2/sso') &&
           !app.demoPathHidden('/no-such-path'),
           'D5. a link to a demonstration is hidden, and to anything else ' +
           'not');
    });
    note(hosted.list().reduce(function (n, one) {
      return n + one.prefixes.length;
    }, 0) > productPrefixes && !app.demoPathHidden('/spnego'),
         'D6. and in development the catalogue and the links keep them');

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: e && e.stack ? e.stack : String(e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * Runs the child and reports its findings.
 *
 * @param t - the runner's check object
 */
function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'de-' + process.pid + '-' +
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
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  DE_ROOT: ROOT, DE_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one; reported below.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
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
  name: 'demo_endpoints',
  describe: 'every demonstration, mock and test-control endpoint carries ' +
            'the mark, is answered as an unrouted path in a product realm ' +
            'and by its handler in development, and is listed nowhere in a ' +
            'product realm (#585)',
  run: run
};
