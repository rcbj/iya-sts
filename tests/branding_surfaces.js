// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/branding_surfaces.js
// ===========================================================================
// THE THREE SURFACES WITH STYLESHEETS OF THEIR OWN TAKE A REALM'S SIGN-IN
// APPEARANCE (#717, rcbj's D4): the user portal, the front door and the
// sign-out page. The card family takes it from `/web/card.css` and
// `ShellDocument` (`tests/branding.js`); these three link their own
// stylesheets, so each says `branded` itself and reads the custom
// properties itself, and this asks the whole stack over HTTP, in process:
//
//   1. A REALM THAT SET NOTHING (the default realm) gets nothing: no theme
//      stylesheet and no brand attribute on any of the three shells, and the
//      front door's own image in its view.
//   2. A REALM THAT SET ITS APPEARANCE AND A LOGO: each shell links the
//      realm's `/web/theme.css` after its own stylesheet, under the realm's
//      prefix, and carries the layout, the name and the logo's address on
//      `<html>`; the front door's view drops its own image, so the realm's
//      logo is the only one, and its card draws no band.
//   3. THE STYLESHEETS read every themable colour through a custom property
//      falling back to the literal it replaced, so with no theme linked
//      they draw what they did; the portal's two buttons that are not in
//      the accent keep their white text; the brand rules are there.
//   4. THE PORTAL'S RUNTIME draws the brand header above the page and the
//      name in the title, with the logo's address under the realm's prefix,
//      and draws neither where the shell carries no brand.
//
// In a child process, as `home_static_surface.js` is, so the realm this
// creates and the stack it builds go with it.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'branding_surfaces',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, gives a realm an appearance,
 * listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.BS_ROOT;
  const OUT = process.env.BS_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, urlPath) {
    return new Promise(function (resolve, reject) {
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: 'GET',
                                 headers: { accept: 'text/html' } },
      function (res) {
        const chunks = [];
        res.on('data', function (d) {
          chunks.push(d);
        });
        res.on('end', function () {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers,
                    text: text, json: json });
        });
      });
      req.on('error', reject);
      req.end();
    });
  }
  // A PNG's signature and IHDR sides, all the check reads.
  function png(width, height) {
    const b = Buffer.alloc(64);
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b, 0);
    b.writeUInt32BE(13, 8);
    b.write('IHDR', 12, 'latin1');
    b.writeUInt32BE(width, 16);
    b.writeUInt32BE(height, 20);
    return b;
  }
  function attr(html, name) {
    const m = new RegExp(' ' + name + '="([^"]*)"').exec(html);
    return m ? m[1] : null;
  }
  // A document as much as `put()` reads: the root's attributes, a title and
  // a body.
  function fakeDocument(attrs) {
    return {
      title: '',
      body: { innerHTML: '' },
      documentElement: {
        getAttribute: function (name) {
          return Object.prototype.hasOwnProperty.call(attrs, name)
            ? attrs[name] : null;
        }
      }
    };
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const Branding = require(ROOT_DIR + '/common/branding');
    const kit = require(ROOT_DIR + '/portal/web_portal_kit');
    const PortalRuntime = require(ROOT_DIR + '/portal/web_portal_runtime');
    const WebHomeFront = require(ROOT_DIR + '/home/web_home_front');
    const REALM = 'brand-surfaces';
    const made = realms.create({ id: REALM, name: REALM,
                                 description: 'Created by branding_surfaces' });
    note(made.ok, '(the test realm is created)',
         JSON.stringify(made.errors || []));
    let theme = null;
    realms.run(made.realm, function () {
      const saved = Branding.saveSettings({
        'branding.layout': 'banner', 'branding.displayName': 'Acme <Corp>',
        'branding.accentColor': '#0a5c36' });
      note(saved.ok, '(the realm\'s appearance is saved)',
           JSON.stringify(saved));
      const logo = Branding.setLogo(png(120, 40),
                                    { alt: 'Acme', actor: 'test' });
      note(logo.ok, '(the realm\'s logo is stored)', JSON.stringify(logo));
      theme = Branding.theme();
    });
    const PREFIX = '/realm/' + REALM;
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;

    // --- 1. a realm that set nothing ----------------------------------------
    let r = await call(port, '/');
    note(r.status === 200 && r.text.indexOf('theme.css') < 0 &&
         r.text.indexOf('data-sts-layout') < 0 &&
         r.text.indexOf('data-sts-brand') < 0,
         '1a. the default realm\'s front door links no theme and carries no ' +
         'brand', r.text.slice(0, 600));
    r = await call(port, '/home-api/front');
    let view = (r.json && r.json.view) || {};
    note(r.status === 200 && view.logo && view.logo.src === '/logo.png',
         '1b. and its view draws the service\'s own image',
         JSON.stringify(r.json));
    const plainPortal = realms.run(realms.get(realms.DEFAULT_ID), function () {
      return require(ROOT_DIR + '/portal/portal').shellDocument(null, {});
    });
    note(plainPortal.indexOf('theme.css') < 0 &&
         plainPortal.indexOf('data-sts-layout') < 0 &&
         plainPortal.indexOf('<link rel="stylesheet" ' +
                             'href="/portal/portal.css">') > 0,
         '1c. the default realm\'s portal shell links its own stylesheet ' +
         'and no theme', plainPortal.slice(0, 600));
    r = await call(port, '/logout?username=bs-ann');
    note(r.status === 200 && r.text.indexOf('theme.css') < 0 &&
         r.text.indexOf('data-sts-layout') < 0,
         '1d. the default realm\'s sign-out shell links no theme',
         r.status + ' ' + r.text.slice(0, 600));

    // --- 2. a realm with an appearance and a logo -------------------------
    const themeHref = PREFIX + '/web/theme.css?v=' + theme.digest;
    r = await call(port, PREFIX + '/');
    const cardAt = r.text.indexOf(PREFIX + '/web/card.css');
    const homeAt = r.text.indexOf(PREFIX + '/home.css');
    const themeAt = r.text.indexOf(themeHref);
    note(r.status === 200 && cardAt > 0 && themeAt > cardAt &&
         homeAt > 0 && attr(r.text, 'data-sts-layout') === 'banner' &&
         attr(r.text, 'data-sts-brand-name') === 'Acme &lt;Corp&gt;' &&
         /^\/web\/branding\/logo\?v=[0-9a-f]{16}$/.test(
           attr(r.text, 'data-sts-brand-logo') || ''),
         '2a. the realm\'s front door links its theme after the card, under ' +
         'the realm\'s prefix, and carries the layout, the name and the logo',
         r.text.slice(0, 900));
    r = await call(port, PREFIX + '/home-api/front');
    view = (r.json && r.json.view) || {};
    note(r.status === 200 && view.name && view.logo === null,
         '2b. its view drops the service\'s image, so the realm\'s logo in ' +
         'the brand header is the only one', JSON.stringify(r.json));
    const framed = WebHomeFront.frame('<p>body</p>',
      { view: view, t: { text: function (k) {
        return k;
      } } });
    note(framed.indexOf('class="hero"') < 0 &&
         framed.indexOf('/logo.png') < 0,
         '2c. and the card draws no band', framed);
    r = await call(port, PREFIX + '/portal');
    const portalCss = r.text.indexOf(PREFIX + '/portal/portal.css');
    const portalTheme = r.text.indexOf(themeHref);
    note(r.status === 200 && portalCss > 0 && portalTheme > portalCss &&
         attr(r.text, 'data-sts-layout') === 'banner' &&
         attr(r.text, 'data-sts-brand-alt') === 'Acme',
         '2d. the realm\'s portal shell links the theme after its own ' +
         'stylesheet and carries the brand facts', r.status + ' ' +
         r.text.slice(0, 900));
    r = await call(port, PREFIX + '/logout?username=bs-ann');
    const signoutCss = r.text.indexOf(PREFIX + '/logout/signout.css');
    note(r.status === 200 && signoutCss > 0 &&
         r.text.indexOf(themeHref) > signoutCss &&
         attr(r.text, 'data-sts-brand-name') === 'Acme &lt;Corp&gt;',
         '2e. the realm\'s sign-out shell links the theme after its own ' +
         'stylesheet and carries the brand facts', r.status + ' ' +
         r.text.slice(0, 900));
    r = await call(port, PREFIX + '/web/theme.css?v=' + theme.digest);
    note(r.status === 200 && /--sts-accent:#0a5c36/.test(r.text),
         '2f. and the theme it links carries the realm\'s accent', r.text);

    // --- 3. the stylesheets -------------------------------------------------
    const literals = function (css) {
      return css.replace(/var\(--sts-[a-z-]+,#[0-9a-f]+\)/g, '');
    };
    const portal = kit.STYLE;
    note(!/#2c5cc5/.test(literals(portal)) &&
         /background:var\(--sts-page,#f4f4f7\)/.test(portal) &&
         /\.card\{background:var\(--sts-card,#fff\)/.test(portal) &&
         /color:var\(--sts-on-accent,#fff\)/.test(portal),
         '3a. the portal names its accent, page, card and button text only ' +
         'through custom properties falling back to its own literals');
    note(/button\.danger\{background:#b00020;color:#ffffff\}/.test(portal) &&
         /button\.secondary\{background:#5a5a68;color:#ffffff\}/
           .test(portal),
         '3b. its two buttons not in the accent keep their white text');
    note(/\.sts-brand\{/.test(portal) &&
         /html\[data-sts-layout=banner\] \.sts-brand/.test(portal),
         '3c. and it carries the brand header\'s rules');
    r = await call(port, '/portal/portal.css');
    note(r.status === 200 && r.text === portal,
         '3d. /portal/portal.css serves exactly that');
    r = await call(port, '/home.css');
    note(r.status === 200 && !/#12107c/.test(literals(r.text)) &&
         /html\[data-sts-layout=banner\] \.sts-brand/.test(r.text),
         '3e. the front door\'s stylesheet names the accent only through ' +
         'the custom property, and lays the brand band out', r.text);
    r = await call(port, '/logout/signout.css');
    note(r.status === 200 && /color:var\(--sts-text,#111\)/.test(r.text) &&
         /html\[data-sts-layout\] body\{background:var\(--sts-card,#fff\)/
           .test(r.text) && /\.sts-brand\{/.test(r.text) &&
         !/#12107c/.test(literals(r.text)),
         '3f. the sign-out stylesheet reads the realm\'s text and card, ' +
         'gives a realm\'s page a card, and carries the header\'s rules',
         r.text.slice(0, 400));

    // --- 4. the portal's runtime ------------------------------------------
    const branded = { env: { document: fakeDocument({
                          'data-sts-brand-name': 'Acme <Corp>',
                          'data-sts-brand-logo': '/web/branding/logo?v=1',
                          'data-sts-brand-alt': 'Acme',
                          'data-sts-brand-link': '' }),
                        location: { pathname: PREFIX + '/portal',
                                    search: '' } },
                      prefix: PREFIX, wire: function () {},
                      targetFragment: function () {} };
    PortalRuntime.prototype.put.call(branded, 'Your account',
                                     '<div class="wrap">page</div>');
    const body = branded.env.document.body.innerHTML;
    note(branded.env.document.title === 'Your account — Acme <Corp>' &&
         body.indexOf('<header class="sts-brand"') === 0 &&
         body.indexOf('src="' + PREFIX + '/web/branding/logo?v=1"') > 0 &&
         body.indexOf('Acme &lt;Corp&gt;') > 0 &&
         body.indexOf('<div class="wrap">page</div>') > 0,
         '4a. the portal draws the realm\'s header above the page, the logo ' +
         'under the realm\'s prefix and the name escaped, and ends the title ' +
         'with the name', body + ' | ' + branded.env.document.title);
    const plain = { env: { document: fakeDocument({}),
                           location: { pathname: '/portal', search: '' } },
                    prefix: '', wire: function () {},
                    targetFragment: function () {} };
    PortalRuntime.prototype.put.call(plain, 'Your account',
                                     '<div class="wrap">page</div>');
    note(plain.env.document.title === 'Your account — IYA STS' &&
         plain.env.document.body.innerHTML === '<div class="wrap">page</div>',
         '4b. and draws neither where the shell carries no brand',
         plain.env.document.body.innerHTML);

    server.close();
    realms.remove(REALM);
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
  const out = path.join(os.tmpdir(), 'bs-' + process.pid + '-' + Date.now() +
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
                                  BS_ROOT: ROOT, BS_OUT: out }),
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
  name: 'branding_surfaces',
  describe: 'the user portal, the front door and the sign-out page take a ' +
            'realm\'s sign-in appearance and logo, and are unchanged in a ' +
            'realm that set none (#717)',
  run: run
};
