// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/home_static_surface.js
// ===========================================================================
// THE FRONT DOOR IS A STATIC SURFACE (#579, 2026-10-12).
//
// `GET /` was a server-drawn card until #579; it is now the shell of the
// first public surface on #570's foundation, and this asks the whole stack,
// over HTTP in process:
//
//   1. THE SHELL: `GET /` answers 200, `no-store`, the one document
//      `ShellDocument` draws — `/web/card.css` and `/home.css`, the
//      deferred `/home.js`, the `<noscript>` notice, the language attributes
//      (the chooser's cookie read back canonical) — and NOT the card the
//      server drew before; its policy keeps `frame-ancestors` and allows
//      the bundle and the stylesheets from 'self' with no inline style.
//   2. IN A REALM, the shell carries the realm's prefix, and its script and
//      stylesheets are under it.
//   3. THE BUNDLE AND THE STYLESHEET are served, the bundle built (this runs
//      in the tests image, where the build wrote it) and precompressed.
//   4. THE API: the index lists the view's operation as the door of `GET /`,
//      and the view answers everything the old page showed — the version
//      this build reports, the mode's two facts as `common/mode.js` answers
//      them, the logo, and the five links by id.
//   5. DRAWN FROM THE LIVE ANSWER: the renderers' bundle draws the view this
//      process answered, after the wire, into the card the old page was —
//      the name, the version, the sign-in sentence of this mode, every link.
//   6. THE OLD RENDERER IS GONE: the class has no `homePage()`.
//
// The round trip from a view alone is `tests/web_surfaces.js`'s, from the
// row in `tests/tools/web_surfaces.js`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'home_static_surface',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.HS_ROOT;
  const OUT = process.env.HS_OUT;
  const http = require('http');
  const zlib = require('zlib');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, urlPath, headers) {
    return new Promise(function (resolve, reject) {
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: 'GET',
                                 headers: headers || {} }, function (res) {
        const chunks = [];
        res.on('data', function (d) {
          chunks.push(d);
        });
        res.on('end', function () {
          const raw = Buffer.concat(chunks);
          let json = null;
          try {
            json = JSON.parse(raw.toString('utf8'));
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers,
                    raw: raw, text: raw.toString('utf8'), json: json });
        });
      });
      req.on('error', reject);
      req.end();
    });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const mode = require(ROOT_DIR + '/common/mode');
    const version = require(ROOT_DIR + '/common/version');
    const home = require(ROOT_DIR + '/home/home');
    const harness = require(ROOT_DIR + '/tests/tools/web_round_trip');
    const messages = require(ROOT_DIR + '/common/web_messages');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;

    // --- 1. the shell -------------------------------------------------------
    let r = await call(port, '/', { cookie: 'sts_lang=fr-ca' });
    const csp = String(r.headers['content-security-policy'] || '');
    note(r.status === 200 && /text\/html/.test(r.headers['content-type']) &&
         /no-store/.test(String(r.headers['cache-control'])),
         '1a. GET / answers 200, HTML, no-store',
         r.status + ' ' + r.headers['content-type'] + ' ' +
         r.headers['cache-control']);
    note(/^<!DOCTYPE html>\n<html lang="en"/.test(r.text) &&
         r.text.indexOf('<link rel="stylesheet" href="/web/card.css">') > 0 &&
         r.text.indexOf('<link rel="stylesheet" href="/home.css">') > 0 &&
         r.text.indexOf('<script src="/home.js" defer></script>') > 0 &&
         r.text.indexOf('<noscript>') > 0,
         '1b. it is the shell: the card\'s and the page\'s stylesheets, the ' +
         'deferred script and the notice', r.text.slice(0, 600));
    note(r.text.indexOf(' data-sts-version="' + version.load().version +
                        '"') > 0 &&
         r.text.indexOf(' data-sts-lang="fr-CA"') > 0 &&
         / data-sts-locale-default="[^"]+"/.test(r.text) &&
         r.text.indexOf('data-sts-prefix') < 0 &&
         r.text.indexOf('data-sts-authn') < 0,
         '1c. with the language attributes, the chooser\'s cookie read back ' +
         'canonical, and no prefix or other listener in the default realm',
         r.text.slice(0, 400));
    note(r.text.indexOf('The admin console on this instance') < 0 &&
         r.text.indexOf('href="/admin"') < 0 &&
         r.text.indexOf('<style>') < 0,
         '1d. and not the card the server drew before #579: no link row and ' +
         'no inline style', r.text.slice(0, 300));
    note(/frame-ancestors 'none'/.test(csp) && /base-uri /.test(csp) &&
         /script-src 'self'(;|$)/.test(csp) &&
         /style-src 'self'(;|$)/.test(csp) &&
         /connect-src 'self'(;|$)/.test(csp) && !/unsafe-inline/.test(csp),
         '1e. its policy keeps frame-ancestors and base-uri, and allows the ' +
         'script, the stylesheets and the API from \'self\' only', csp);

    // --- 2. in a realm ------------------------------------------------------
    const R = 'hs' + process.pid;
    realms.create({ id: R, name: 'The front door in a realm' });
    const prefix = realms.prefixOf(realms.get(R));
    r = await call(port, prefix + '/');
    note(r.status === 200 &&
         r.text.indexOf(' data-sts-prefix="' + prefix + '"') > 0 &&
         r.text.indexOf('<script src="' + prefix + '/home.js" defer>') > 0 &&
         r.text.indexOf('href="' + prefix + '/web/card.css"') > 0 &&
         r.text.indexOf('href="' + prefix + '/home.css"') > 0,
         '2. in a realm the shell carries the prefix, and its files are ' +
         'under it', prefix + ' ' + r.text.slice(0, 600));
    const inRealm = await call(port, prefix + '/home-api/front');
    note(inRealm.status === 200 && inRealm.json && inRealm.json.view &&
         inRealm.json.view.links.length === 5,
         '2b. and the realm answers its own view', inRealm.text.slice(0, 200));

    // --- 3. the bundle and the stylesheet --------------------------------
    r = await call(port, '/home.js');
    note(r.status === 200 && /javascript/.test(r.headers['content-type']) &&
         r.raw.length > 1000 && r.text.indexOf('was not built') < 0,
         '3a. GET /home.js answers the built bundle',
         r.status + ' ' + r.headers['content-type'] + ' ' + r.raw.length +
         ' ' + r.text.slice(0, 120));
    const plain = r.raw;
    r = await call(port, '/home.js', { 'accept-encoding': 'br' });
    let unpacked = null;
    try {
      unpacked = zlib.brotliDecompressSync(r.raw);
    } catch (e) {
      // Not brotli; the finding says so.
      unpacked = null;
    }
    note(r.headers['content-encoding'] === 'br' && unpacked &&
         unpacked.equals(plain),
         '3b. and as brotli where the request takes it, the same bytes',
         String(r.headers['content-encoding']));
    r = await call(port, '/home.css');
    note(r.status === 200 && /text\/css/.test(r.headers['content-type']) &&
         r.text.indexOf('.hero{') >= 0 && r.text.indexOf('.note{') >= 0,
         '3c. GET /home.css answers the page\'s own rules',
         r.status + ' ' + r.text.slice(0, 120));
    r = await call(port, '/web/card.css');
    note(r.status === 200, '3d. and /web/card.css, which the shell links, ' +
         'answers', r.status);

    // --- 4. the API ----------------------------------------------------------
    r = await call(port, '/home-api');
    const ops = (r.json && r.json.operations) || [];
    const door = ops.filter(function (op) {
      return op.mirrors === 'GET /';
    });
    note(r.status === 200 && door.length === 1 &&
         door[0].path === '/home-api/front' && door[0].method === 'GET' &&
         ops.every(function (op) {
           return op.method === 'GET';
         }),
         '4a. the index lists the view as the door of GET /, and nothing ' +
         'that posts', r.text.slice(0, 400));
    r = await call(port, '/home-api/front');
    const view = (r.json && r.json.view) || {};
    const ids = (view.links || []).map(function (one) {
      return one.id;
    });
    note(r.status === 200 && r.json.ok === true &&
         /no-store/.test(String(r.headers['cache-control'])),
         '4b. the view answers 200, no-store', r.status);
    note(view.name === 'IYA STS' &&
         view.version === String(version.load().version) &&
         view.build === version.buildInfo(version.load()),
         '4c. it carries the name, and the version and build this build ' +
         'reports', JSON.stringify([view.version, view.build]));
    note(view.mode &&
         view.mode.verifiesCredentials === !!mode.verifiesCredentials() &&
         view.mode.gatesConsole === !!mode.gatesConsole(),
         '4d. and the mode\'s two facts as common/mode.js answers them',
         JSON.stringify(view.mode));
    note(view.logo && view.logo.src === '/logo.png' &&
         view.logo.width === 906 && view.logo.height === 269,
         '4e. and the logo', JSON.stringify(view.logo));
    note(JSON.stringify(ids) ===
           JSON.stringify(['repo', 'issues', 'docs', 'console', 'portal']) &&
         view.links[3].href === '/admin' && view.links[4].href === '/portal' &&
         view.links[0].external === true && view.links[3].external === false,
         '4f. and the five links by id, the console and the portal ' +
         'relative where this listener answers them',
         JSON.stringify(view.links));
    note(JSON.stringify(view).indexOf('sign in') < 0 &&
         JSON.stringify(view).indexOf('GitHub') < 0,
         '4g. and no words: the view is language-free',
         JSON.stringify(view).slice(0, 300));
    r = await call(port, '/logo.png');
    note(r.status === 200 && /image\/png/.test(r.headers['content-type']),
         '4h. the one image still answers', r.status);

    // --- 5. drawn from the live answer --------------------------------------
    const loaded = harness.loadBundle(ROOT_DIR + '/home/home.bundle.js',
                                      'StsHome');
    const own = JSON.parse(fs.readFileSync(ROOT_DIR +
                                           '/common/locales/home/en.json'));
    const flat = {};
    Object.keys(own).forEach(function (key) {
      flat['home.' + key] = own[key];
    });
    const t = messages.WebTranslator.fromData({ catalogs: { en: flat },
      negotiated: { locale: 'en', chain: ['en'], catalog: 'en',
                    direction: 'ltr', matched: true } });
    const ctx = { t: t, query: {}, prefix: '', origin: 'http://x', here: '/' };
    const wire = JSON.parse(JSON.stringify(view));
    const drawn = loaded.value ? loaded.value.render('/', wire, ctx) : '';
    const framed = loaded.value
      ? loaded.value.frame('<p>chooser</p>', Object.assign({ view: wire },
                                                            ctx)) : '';
    const sentence = mode.verifiesCredentials() ? own.signInProduct
                                                : own.signInDevelopment;
    note(drawn.indexOf('<h1>IYA STS</h1>') === 0 &&
         drawn.indexOf('version ' + view.version) > 0 &&
         drawn.indexOf(own.warn) > 0 && drawn.indexOf(sentence) > 0 &&
         view.links.every(function (one) {
           return drawn.indexOf('href="' + one.href + '"') > 0;
         }) && drawn.split('<li>').length === 6,
         '5a. the bundle draws the live view, after the wire, as the card ' +
         'it was: the name, the version, this mode\'s sentence, five links',
         loaded.problem + ' ' + drawn.slice(0, 600));
    note(framed.indexOf('<div class="card"><div class="hero"><img ' +
                        'src="/logo.png"') === 0 &&
         framed.indexOf('<div class="body"><p>chooser</p></div>') > 0,
         '5b. and its frame puts the band above the chooser and the body',
         framed.slice(0, 300));

    // --- 6. the old renderer ---------------------------------------------
    note(typeof home.Home.prototype.homePage === 'undefined' &&
         typeof home.Home.prototype.frontView === 'function',
         '6. the server no longer draws the card');

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * Runs the child and reports its findings.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {Promise<void>} when done
 */
async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'hs-' + process.pid + '-' + Date.now() +
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
                                  HS_ROOT: ROOT, HS_OUT: out }),
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
  name: 'home_static_surface',
  describe: 'GET / is the front door\'s static shell with its policy, the ' +
            'bundle and stylesheet are served, and /home-api/front answers ' +
            'what the old page showed, drawn by the bundle (#579)',
  run: run
};
