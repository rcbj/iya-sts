// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: demo_endpoints.js
//
// ===========================================================================
// THE RUNTIME SHIPS NO DEMONSTRATION ENDPOINT (#591, #599 — rcbj
// 2026-10-12).
//
// #585 made every demonstration, mock and test-control endpoint
// development-only, behind a mark on its route (`common/app.js`), a
// predicate in `common/mode.js` and a flag on its `sts_metadata.ts` row.
// #591 then moved each one out of the runtime — into the test peer
// (`tests/peer/`), the development companion (`companion/`), the remote PEP,
// a console page, a setting or an `/admin-api` operation — or deleted it,
// and #599 removed the mechanism with nothing left to mark. This file is the
// GUARD that keeps it so:
//
//   A. The mechanism is gone: the app carries no mark and no reader of one,
//      the mode has no demonstration predicate, no `demo-endpoints`
//      requirement and no refusal sentence for one.
//   B. No route carries a demonstration mark of any shape (a handler with
//      `stsDemo`, or one named after the old marks), and no path a
//      demonstration was registered on is registered again.
//   C. `/admin/sts-metadata` describes no demonstration: no `ENDPOINTS` row
//      carries `demo`, no card a `whatWithoutDemos`, the report no
//      demonstration member, and the drift checks hold.
//   D. The hosted-applications catalogue holds no demonstration
//      application or prefix.
//   E. No service source names one of the mechanism's symbols, so a
//      demonstration route cannot come back by copying a pattern from an old
//      branch without this failing by name.
//
// A, B, C and D IN A CHILD, `protocol_endpoints.js`'s arrangement: they load
// the whole stack, and one loaded into the runner would be shared with every
// later file. E reads files and runs here.
// ===========================================================================

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');
const log = require('bunyan').createLogger({ name: 'demo_endpoints',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// THE MECHANISM'S SYMBOLS (#585), every one removed by #599. A source that
// names one is either a demonstration coming back or a reader of a mark that
// no longer exists.
const SYMBOLS = ['demoOnly', 'processDemoOnly', 'demoMarkOf',
                 'demoPathHidden', 'servesDemoEndpoints', 'servesRealmDemos',
                 'servesProcessDemos', 'demoPrefixes', 'whatWithoutDemos',
                 'withoutDemos', 'demoMarkMismatches', 'stsDemo'];

// What E does not read: not the service's source (tests, tooling, the
// companion and the test peer, which are not in the runtime), a copy this
// repository may not edit, or a build output.
const SKIP_DIRECTORIES = ['node_modules', 'node-ldapjs', 'tests', 'docs',
                          'companion', 'embedded', 'vendored', 'rust',
                          'deploy', 'apidocs', 'coverage', '.git', 'types'];

// ---------------------------------------------------------------------------
// The child. Everything it needs is required inside, so the function can be
// shipped as source with `node -e`; it has no logger, so its reasons travel
// on its findings.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.DE_ROOT;
  const OUT = process.env.DE_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  // EVERY PATH A DEMONSTRATION WAS REGISTERED ON (#585's inventory, and the
  // scripts the static demonstration pages carried), with where each went.
  // None may be registered again: a path is the one thing a returning
  // demonstration cannot change and still be the same demonstration.
  const RETIRED = [
    // #592: the SAML and WS-Federation relying parties (the test peer's).
    '/wsfed/rp', '/saml2/sp', '/saml11/rp',
    // #593: the step-up stand-in resource and the GNAP demonstration
    // resource server (the test peer's), the Shared Signals receiver.
    '/oauth2/step-up/resource/:application', '/gnap/rs/resource',
    '/gnap/rs/spend', '/ssf/receive', '/ssf/received',
    // #594: the OpenID4VC demonstration (the companion's), the issuer's
    // readbacks (`/admin-api` now) and `/did/generate` (deleted).
    '/issuer', '/issuer/offer', '/issuer/demo.js', '/oid4vp/verifier',
    '/oid4vp/start', '/oid4vp/done', '/oid4vp/result/:state',
    '/oid4vci/last_request', '/oid4vci/notification/:id', '/did/generate',
    // #595: Kerberos and SPNEGO (the companion's); `/krb5/principals` is
    // `GET /admin-api/kerberos/principals`.
    '/spnego', '/spnego/protected', '/spnego/pages.js', '/krb5/service',
    '/krb5/principals',
    // #596: the commands relying party (the test peer's) and
    // `/xacml/protected` (the remote PEP's).
    '/oauth2/commands/mock-rp', '/xacml/protected',
    // #597: the test controls, now a setting, the MDM feed, a console page
    // and `/admin-api`.
    '/dpop/nonce-mode', '/devices/test/compliance', '/tls', '/tls/forwarded',
    '/tls/pages.js', '/tls/trust', '/tls/trust/clear',
    // #598: the VC API's status-list publish hook
    // (`POST /admin-api/vc-status/publish`); the VC API itself stays, a
    // product surface.
    '/oid4vci/status-lists/bitstring/:purpose/publish'
  ];
  const OLD_MARKS = ['demoOnly', 'processDemoOnly'];

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    await require(ROOT_DIR + '/common/service_state').start();
    const mode = require(ROOT_DIR + '/common/mode');
    const metadata = require(ROOT_DIR + '/sts_metadata');
    const hosted = require(ROOT_DIR + '/common/hosted_applications');

    // --- A. the mechanism is gone -------------------------------------------
    const leftOnApp = OLD_MARKS.concat(['demoMarkOf', 'demoPathHidden'])
      .filter(function (name) {
        return app[name] !== undefined;
      });
    note(leftOnApp.length === 0, 'A1. the app carries no demonstration ' +
         'mark and no reader of one', leftOnApp.join(', ') || 'none');
    note(mode.servesDemoEndpoints === undefined,
         'A2. the mode has no demonstration predicate',
         typeof mode.servesDemoEndpoints);
    const rows = (mode.REQUIREMENTS || []).filter(function (row) {
      return /demo-endpoints/.test(row.id) ||
        /demonstration and test-control endpoints/i.test(row.what || '');
    });
    note(Array.isArray(mode.REQUIREMENTS) && rows.length === 0,
         'A3. no requirement on /admin/mode describes demonstration ' +
         'endpoints', rows.map(function (row) {
           return row.id;
         }).join(', ') || 'none');
    note(mode.writeRefusalReason('servesDemoEndpoints') ===
         mode.writeRefusalReason('noSuchPredicateAnywhere'),
         'A4. no setting\'s refusal names the demonstration predicate',
         mode.writeRefusalReason('servesDemoEndpoints'));

    // --- B. no route is a demonstration -------------------------------------
    const router = app._router || app.router;
    const marked = [];
    const back = [];
    router.stack.forEach(function (layer) {
      if (!layer.route) {
        return;
      }
      const p = String(layer.route.path);
      (layer.route.stack || []).forEach(function (one) {
        const handle = one && one.handle;
        if (handle && (handle.stsDemo ||
                       OLD_MARKS.indexOf(handle.name) >= 0)) {
          marked.push(p);
        }
      });
      if (RETIRED.indexOf(p) >= 0) {
        back.push(Object.keys(layer.route.methods).join(',')
                    .toUpperCase() + ' ' + p);
      }
    });
    note(marked.length === 0, 'B1. no route carries a demonstration mark',
         marked.join(', ') || 'none');
    note(back.length === 0, 'B2. no path a demonstration was registered on ' +
         'is registered again', back.join(', ') || 'none');

    // --- C. /admin/sts-metadata describes none ------------------------------
    const flagged = metadata.ENDPOINTS.filter(function (row) {
      return Object.prototype.hasOwnProperty.call(row, 'demo');
    }).map(function (row) {
      return row.path;
    });
    note(flagged.length === 0, 'C1. no ENDPOINTS row carries a ' +
         'demonstration flag', flagged.join(', ') || 'none');
    const cards = metadata.PROTOCOLS.filter(function (card) {
      return Object.prototype.hasOwnProperty.call(card, 'whatWithoutDemos');
    }).map(function (card) {
      return card.name;
    });
    note(cards.length === 0, 'C2. no protocol card says anything ' +
         'different where demonstrations are not served',
         cards.join(', ') || 'none');
    const report = metadata.describeEndpoints();
    const members = ['demoMismatch', 'hiddenSpecs'].filter(function (name) {
      return Object.prototype.hasOwnProperty.call(report, name);
    });
    const routeMembers = metadata.registeredRoutes().filter(function (row) {
      return Object.prototype.hasOwnProperty.call(row, 'demo') ||
        Object.prototype.hasOwnProperty.call(row, 'served');
    }).map(function (row) {
      return row.path;
    });
    note(members.length === 0 && routeMembers.length === 0,
         'C3. neither the report nor the router\'s list carries a ' +
         'demonstration member', members.concat(routeMembers).join(', ') ||
         'none');
    note(report.undocumented.length === 0 && report.stale.length === 0 &&
         report.unknownProtocolGroups.length === 0 &&
         report.unclaimedGroups.length === 0,
         'C4. and the page has no drift either way',
         JSON.stringify({ undocumented: report.undocumented,
                          stale: report.stale,
                          groups: report.unknownProtocolGroups,
                          unclaimed: report.unclaimedGroups }));

    // --- D. the hosted applications -----------------------------------------
    const offered = [];
    hosted.list().forEach(function (one) {
      if (one.demo || one.demoPrefixes) {
        offered.push(one.id);
      }
      one.prefixes.concat(one.exact).forEach(function (prefix) {
        if (RETIRED.indexOf(prefix) >= 0 ||
            ['/vc-demo-api', '/krb5'].indexOf(prefix) >= 0) {
          offered.push(one.id + ' ' + prefix);
        }
      });
    });
    note(offered.length === 0, 'D1. the hosted-applications catalogue ' +
         'holds no demonstration application or prefix',
         offered.join(', ') || 'none');

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
 * Lists the service's own `.js` and `.ts` files, for E.
 *
 * @param directory - where to start
 * @param out - the list being built
 * @returns the list
 */
function sourcesUnder(directory, out) {
  log.debug("Entering sourcesUnder().");
  fs.readdirSync(directory, { withFileTypes: true }).forEach(function (one) {
    const full = path.join(directory, one.name);
    if (one.isDirectory()) {
      if (SKIP_DIRECTORIES.indexOf(one.name) < 0) {
        sourcesUnder(full, out);
      }
      return;
    }
    if (/\.(js|ts)$/.test(one.name) && !/\.bundle\.js$/.test(one.name) &&
        !/-spa\.js$/.test(one.name) && !/\.d\.ts$/.test(one.name)) {
      out.push(full);
    }
  });
  log.debug("Leaving sourcesUnder().");
  return out;
}

/**
 * E: no service source names one of the mechanism's symbols.
 *
 * @param t - the runner's check object
 */
function checkSources(t) {
  log.debug("Entering checkSources().");
  const pattern = new RegExp('\\b(' + SYMBOLS.join('|') + ')\\b');
  const found = [];
  sourcesUnder(ROOT, []).forEach(function (file) {
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    lines.forEach(function (line, i) {
      const match = pattern.exec(line);
      if (match) {
        found.push(path.relative(ROOT, file) + ':' + (i + 1) + ' ' +
                   match[1]);
      }
    });
  });
  t.check(found.length === 0, 'E1. no service source names one of the ' +
          'demonstration mechanism\'s symbols', found.slice(0, 20)
            .join(', ') || 'none');
  log.debug("Leaving checkSources().");
}

/**
 * Reads the sources, then runs the child and reports its findings.
 *
 * @param t - the runner's check object
 */
function run(t) {
  log.debug("Entering run().");
  checkSources(t);
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
  describe: 'the runtime ships no demonstration endpoint: the mark, the ' +
            'predicate and the metadata flag are gone, no route carries a ' +
            'mark or a retired demonstration path, and no source names the ' +
            'mechanism (#591, #599)',
  run: run
};
