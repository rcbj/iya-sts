// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: build_detail.js
//
// ===========================================================================
// IN PRODUCT, ONLY AN ADMINISTRATOR IS TOLD WHICH BUILD THIS IS (#2142,
// ASVS 5.0.0 13.4.6).
//
// Every page's footer, the shells' `data-sts-version` and `data-sts-build`,
// the sign-in and portal APIs' answers and OpenAPI documents, the front
// page's view, the catalog index and the outbound User-Agent named the exact
// version, build number, build instant or commit, to anybody. Now
// `mode.publishesBuildDetail()` (`security.publishBuildInfo`, `auto`
// following the mode) decides, and the console keeps the build through its
// shell ANSWER. What is held here, in a child process that builds the stack
// and listens on 127.0.0.1, as page_footer.js does:
//
//   A. The predicate: development yes, product no, `on` and `off` forcing.
//   B. Development keeps the build on the front page's shell and footer, the
//      console's shell, `/authn-api/openapi.json`, the front view and the
//      User-Agent — what every surface did before.
//   C. Product: no shell (the front page's, the console's, the portal's,
//      the sign-in screen's) and no error page names the version, the build
//      line, the build instant or the commit; the footer has no version
//      line; `data-sts-build` is the stamped random key;
//      `/authn-api/openapi.json` names `1`; the front view, the portal's
//      language answer and the catalog index carry an empty version; every
//      outbound requester's User-Agent is `sts (<component>)`.
//   D. The console keeps it: its runtime draws the footer with the version
//      its shell answer gave over a shell that carried none, and that answer
//      and /admin-api read no predicate.
//   E. `security.publishBuildInfo=on` puts it back in product.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'build_detail',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.BD_ROOT;
  const OUT = process.env.BD_OUT;
  const http = require('http');
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const mode = require(ROOT_DIR + '/common/mode');
    const version = require(ROOT_DIR + '/common/version');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');
    const WebFooter = require(ROOT_DIR + '/common/web_footer');
    const PageLocale = require(ROOT_DIR + '/common/page_locale');
    const ErrorPage = require(ROOT_DIR + '/common/error_page');
    const record = version.load();
    const v = { version: String(record.version),
                buildInfo: String(version.buildInfo(record)),
                build: String(record.build || ''),
                instant: String(record.builtAt || '').replace(/[^0-9]/g, ''),
                commit: String(record.commit || '') };

    // What a page must not carry in product: each of the four, where the
    // record has it.
    function leaks(text) {
      const s = String(text || '');
      return [v.version, v.buildInfo, v.build, v.instant, v.commit]
        .filter(function (one) {
          return one && s.indexOf(one) >= 0;
        });
    }

    // The requesters whose User-Agent is asked per request.
    function agents() {
      const fed = require(ROOT_DIR + '/federation/federation_http');
      const ssf = require(ROOT_DIR + '/ssf/ssf_http');
      const pep = require(ROOT_DIR + '/xacml/xacml_pep_http');
      const prm = require(ROOT_DIR +
                          '/oauth-oidc/protected_resource_metadata');
      const gnap = require(ROOT_DIR + '/gnap/gnap_http');
      return {
        federation: fed.FederationHttp.defaultDeps().userAgent,
        'ssf-transmitter': ssf.SsfHttp.defaultDeps().userAgent,
        'xacml-pdp-notify': pep.PepNotifier.defaultDeps().userAgent,
        'protected-resource-metadata':
          prm.ProtectedResourceMetadata.defaultDeps().USER_AGENT,
        'gnap-push-finish': gnap.GnapHttp.userAgent()
      };
    }

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const get = function (p, headers) {
      return screen.call({ port: port, jar: {}, method: 'GET', path: p,
                           headers: headers || {} });
    };
    const html = { accept: 'text/html' };

    // A. The predicate.
    const inMode = function (m, forced, fn) {
      config.setOverride('global.mode', m);
      if (forced) {
        config.setOverride('security.publishBuildInfo', forced);
      }
      try {
        return fn();
      } finally {
        config.clearOverride('security.publishBuildInfo');
        config.clearOverride('global.mode');
      }
    };
    note(mode.publishesBuildDetail() === true &&
         inMode('product', '', mode.publishesBuildDetail) === false &&
         inMode('product', 'on', mode.publishesBuildDetail) === true &&
         inMode('development', 'off', mode.publishesBuildDetail) === false,
         'A. publishesBuildDetail(): development yes, product no, on and ' +
         'off force it in either mode');
    note(mode.REQUIREMENTS.some(function (row) {
      return row.id === 'build-detail';
    }), 'A. /admin/mode lists the requirement (build-detail)');

    // B. Development keeps the build.
    const devHome = await get('/', html);
    const devAdmin = await get('/admin', html);
    const devDoc = await get('/authn-api/openapi.json');
    const devFront = await get('/home-api/front');
    note(devHome.text.indexOf(' data-sts-version="' + v.version + '"') > 0 &&
         devHome.text.indexOf('data-sts-footer-version="' + v.version +
                              '"') > 0 &&
         devHome.text.indexOf(v.version + '</div></footer>') > 0,
         'B. development: the front page\'s shell and footer name ' +
         v.version);
    note(devAdmin.text.indexOf(v.version + '</div></footer>') > 0,
         'B. development: so does the console\'s shell');
    note(devDoc.json && devDoc.json.info &&
         devDoc.json.info.version === v.version,
         'B. development: /authn-api/openapi.json names the build',
         devDoc.json && JSON.stringify(devDoc.json.info));
    note(devFront.json && devFront.json.view &&
         devFront.json.view.version === v.version,
         'B. development: the front view carries the build');
    const devAgents = agents();
    note(Object.keys(devAgents).every(function (c) {
      return devAgents[c] === 'sts/' + v.version + ' (' + c + ')';
    }), 'B. development: every outbound User-Agent names the build',
    JSON.stringify(devAgents));
    note(version.userAgent('x') === 'sts/' + v.version + ' (x)' &&
         version.userAgent('x', true) === 'sts/' + v.version + ' (x)' &&
         version.userAgent('x', false) === 'sts (x)' &&
         version.userAgent(undefined, false) === 'sts',
         'B. userAgent(): the build unless the caller says it may not be ' +
         'shown');

    // C. Product. The image build stamps a random key (STS_BUILD_KEY); the
    // tests image is not stamped, so the record is given one here, as the
    // stamp would.
    record.key = '0123456789abcdef0123456789abcdef';
    config.setOverride('global.mode', 'product');
    try {
      const SURFACES = ['/', '/admin', '/portal', '/authn/login'];
      for (const p of SURFACES) {
        const r = await get(p, html);
        const found = leaks(r.text);
        note(r.status === 200 && found.length === 0,
             'C. product: ' + p + '\'s shell names no version, build line, ' +
             'build instant or commit', r.status + ' ' + found.join(', '));
        note(r.text.indexOf('class="sts-footer-version"') < 0 &&
             r.text.indexOf('data-sts-footer-version=""') > 0 &&
             r.text.indexOf(' data-sts-version=') < 0,
             'C. product: ' + p + '\'s footer has no version line and its ' +
             'shell no data-sts-version');
        // The console and the portal carry no data-sts-build: their
        // language comes from their API answers.
        note(['/', '/authn/login'].indexOf(p) < 0 ||
             r.text.indexOf(' data-sts-build="' + record.key + '"') > 0,
             'C. product: ' + p + '\'s cached files are keyed by the ' +
             'stamped random key');
      }
      const tEn = PageLocale.translatorFor({ headers: {} }, {});
      const page = ErrorPage.document({ t: tEn, chooser: '', status: 400,
        title: 'Refused', error: 'invalid_request', message: 'No.',
        diagnostics: [] }, 7, new Date());
      note(leaks(page).length === 0 &&
           page.indexOf('class="sts-footer"') > 0,
           'C. product: the error page keeps its footer and names no build',
           leaks(page).join(', '));
      const doc = await get('/authn-api/openapi.json');
      note(doc.json && doc.json.info && doc.json.info.version === '1' &&
           leaks(JSON.stringify(doc.json)).length === 0,
           'C. product: /authn-api/openapi.json names the API\'s own ' +
           'version, 1', doc.json && JSON.stringify(doc.json.info));
      const front = await get('/home-api/front');
      note(front.json && front.json.view &&
           front.json.view.version === '' && front.json.view.build === '',
           'C. product: the front view carries an empty version');
      const locale = await get('/account-api/locale');
      note(locale.status === 200 && locale.json &&
           JSON.stringify(locale.json.version) ===
             JSON.stringify({ version: '', buildInfo: '' }),
           'C. product: the portal\'s language answer carries no build',
           locale.status + ' ' + JSON.stringify(locale.json &&
                                                locale.json.version));
      const index = await get('/web/locales/catalogs.json');
      note(index.json && index.json.version === '',
           'C. product: the catalog index carries an empty version');
      const cached = await get('/web/locales/catalogs.json?v=' + record.key);
      note(/immutable/.test(String(cached.headers['cache-control'])),
           'C. product: and is cached for good under the random key',
           cached.headers['cache-control']);
      const prodAgents = agents();
      note(Object.keys(prodAgents).every(function (c) {
        return prodAgents[c] === 'sts (' + c + ')';
      }), 'C. product: every outbound User-Agent is the product name ' +
          'alone', JSON.stringify(prodAgents));

      // D. The console keeps it.
      const shellFacts = { 'data-sts-footer-version': '',
                           'data-sts-footer-build': '',
                           'data-sts-footer-year': '2026' };
      const shellDoc = { querySelector: function () {
        return { getAttribute: function (n) {
          return shellFacts[n];
        } };
      } };
      const plain = WebFooter.drawnIn(shellDoc, null);
      const signedIn = WebFooter.drawnIn(shellDoc, null,
        { version: v.version, buildInfo: v.buildInfo });
      note(plain.indexOf('class="sts-footer-version"') < 0 &&
           signedIn.indexOf('Version ' + v.version + '</div></footer>') > 0,
           'D. the console runtime draws the version its shell answer ' +
           'gave over a shell that carried none');

      // E. Forced back on.
      config.setOverride('security.publishBuildInfo', 'on');
      const forced = await get('/', html);
      note(forced.text.indexOf(v.version + '</div></footer>') > 0 &&
           version.userAgent('x', mode.publishesBuildDetail()) ===
             'sts/' + v.version + ' (x)',
           'E. security.publishBuildInfo=on shows the build in product');
      config.clearOverride('security.publishBuildInfo');
    } finally {
      config.clearOverride('global.mode');
      delete record.key;
    }

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: String((e && e.stack) || e) });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * D, as source: the console's paths read no predicate, and its runtime
 * hands its shell answer's version to the footer.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {void}
 */
function sourceChecks(t) {
  log.debug("Entering sourceChecks().");
  const read = function (rel) {
    return fs.readFileSync(path.join(ROOT, rel), 'utf8');
  };
  t.check(/WebFooter\.drawnIn\(this\.env\.document, this\.t,\s*shell\.version\)/
            .test(read('admin-ui/web_runtime.ts')),
          'D. the console runtime draws its page footer with its shell ' +
          'answer\'s version');
  t.check(/version: \{ version: APP_VERSION\.version,/
            .test(read('admin-ui/admin.ts')) &&
          read('admin-ui/admin.ts').indexOf('publishesBuildDetail') < 0 &&
          read('mgmt-api/admin_api.ts').indexOf('publishesBuildDetail') < 0,
          'D. the console\'s shell answer and /admin-api carry the build ' +
          'and ask no predicate');
  const requesters = ['federation/federation_http.ts', 'ssf/ssf_http.ts',
                      'xacml/xacml_pep_http.ts', 'gnap/gnap_http.ts',
                      'oauth-oidc/protected_resource_metadata.ts',
                      'oauth-oidc/request_object.ts', 'saml/sp_metadata.ts',
                      'common/revocation_status.js'];
  const unasked = requesters.filter(function (rel) {
    const src = read(rel).replace(/\s+/g, ' ');
    return !/userAgent\('[a-z-]+', mode\.publishesBuildDetail\(\)\)/
      .test(src);
  });
  t.equal(unasked.join(', '), '',
          'every outbound requester to a partner asks the predicate for its ' +
          'User-Agent');
  log.debug("Leaving sourceChecks().");
}

/**
 * Runs the child and reports its findings.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {Promise<void>} when done
 */
async function run(t) {
  log.debug("Entering run().");
  sourceChecks(t);
  const out = path.join(os.tmpdir(), 'bd-' + process.pid + '-' + Date.now() +
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
                                  BD_ROOT: ROOT, BD_OUT: out }),
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
  name: 'build_detail',
  describe: 'in product only an administrator is told the build: no ' +
            'version on a page, an anonymous API answer or document, or ' +
            'an outbound User-Agent; development and the console keep it',
  run: run
};
