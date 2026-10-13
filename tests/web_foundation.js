// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/web_foundation.js
// ===========================================================================
// THE FOUNDATION THE STATIC PUBLIC SURFACES STAND ON (#570, 2026-10-12).
//
// #570 moved what the console and the portal share into `common/`, and added
// what a public surface needs that neither had. Each half is held here:
//
//   A. ONE SHELL WRITER, THE SAME BYTES. The console's and the portal's
//      shells, drawn through `ShellDocument.document()`, are to the byte the
//      documents each drew by hand before #570 — the hand-drawn builders
//      are copied below as they were, for every combination of a refused
//      callback, the bases of other listeners, and values that need
//      escaping. And the policy a shell is sent with is the one the hand
//      code set, `frame-ancestors` undroppable.
//   B. ONE LOCALE ORDER AND ONE NEGOTIATION. The browser's negotiation —
//      `web_locale.ts` over the catalog index as `/web/locales/catalogs.json`
//      serves it — answers what the server's does for every preference
//      list tried; the request's order is #539's; and the chooser a runtime
//      draws from the served index is the server's chooser, which is the
//      chooser drawn by hand before #570 (copied below).
//   C. THE SHARED FILES, OVER HTTP: the card, the index and a catalog file,
//      cached for good under this build's version and revalidated
//      otherwise, compressed where asked, and a 404 (STS-I18N-0012) for a
//      namespace, a catalog or a file name that is not one — nothing read
//      by a requested name. `/web` is answered on every listener and in
//      every cell.
//   D. THE CARD IS ONE STYLESHEET: `WebCardCss.CARD_CSS` is the sign-in
//      screen's, byte for byte.
//   E. A PUBLIC SURFACE'S RUNTIME, DRIVEN IN NODE: `WebSurface` draws a page
//      from its operation's JSON in the language negotiated in the browser
//      (`ui_locales` first), with the chooser; links into the realm; sends a
//      POST form as JSON to the operation that mirrors it and draws the
//      message; refuses a form no operation mirrors; and sends the chooser
//      to `/authn/language` and draws the page again in the language chosen.
//
// A child process, for `admin_api_me.js`'s reason: the stack is built once,
// with its composition root.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'web_foundation',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.WF_ROOT;
  const OUT = process.env.WF_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const app = require(ROOT_DIR + '/common/app');
    const admin = require(ROOT_DIR + '/admin-ui/admin');
    const portal = require(ROOT_DIR + '/portal/portal');
    const kit = require(ROOT_DIR + '/portal/web_portal_kit');
    const i18n = require(ROOT_DIR + '/common/i18n');
    const PageLocale = require(ROOT_DIR + '/common/page_locale');
    const WebLocale = require(ROOT_DIR + '/common/web_locale');
    const ShellDocument = require(ROOT_DIR + '/common/shell_document');
    const publicAssets = require(ROOT_DIR + '/common/public_assets');
    const WebCardCss = require(ROOT_DIR + '/common/web_card_css');
    const WebSurface = require(ROOT_DIR + '/common/web_surface');
    const authn = require(ROOT_DIR + '/authn/authn');
    const hosted = require(ROOT_DIR + '/common/hosted_applications');
    const placement = require(ROOT_DIR + '/common/cell_placement');
    const version = require(ROOT_DIR + '/common/version');

    // --- A. one shell writer, the same bytes -------------------------------
    // THE CONSOLE'S SHELL AS `AdminConsole.shellDocument()` DREW IT BY HAND
    // BEFORE #570, copied as it was.
    const adminBefore = function (registered, elsewhere) {
      const esc = function (v) {
        return helpers.xmlEscape(v == null ? '' : String(v));
      };
      const refused = registered && registered.ok === false;
      const there = elsewhere || {};
      const data = (there.oauth ? ' data-sts-oauth="' + esc(there.oauth) +
                                  '"' : '') +
                   (there.api ? ' data-sts-api="' + esc(there.api) + '"'
                              : '') +
                   (there.authn ? ' data-sts-authn="' + esc(there.authn) +
                                  '"' : '');
      return '<!DOCTYPE html>\n<html lang="en"' + data + '><head><meta ' +
        'charset="utf-8"><meta name="viewport" content="width=device-width, ' +
        'initial-scale=1"><title>IYA STS admin</title>' +
        '<link rel="stylesheet" href="/admin/console.css">' +
        (refused ? '' : '<script src="/admin/console.js" defer></script>') +
        '</head><body><div class="shell"><div class="main"><div ' +
        'class="card"><h1>IYA STS admin</h1>' +
        (refused
          ? admin.warn(esc(registered.why || 'This console cannot sign ' +
                           'in at this address.'),
                       'This console cannot sign in here')
          : '<noscript>' + admin.warn('This console is a script that runs ' +
              'in your browser and draws every page from <code>/admin-api' +
              '</code>; with scripts blocked there is nothing it can show.',
              'Scripts are blocked') + '</noscript><p class="lede">' +
            'Signing in&hellip;</p>') +
        '</div></div></div></body></html>\n';
    };
    // THE PORTAL'S, AS `Portal.shellDocument()` DREW IT BEFORE #570.
    const portalBefore = function (registered, elsewhere) {
      const BASE = '/portal';
      const refused = registered && registered.ok === false;
      const there = elsewhere || {};
      // `data-sts-api` since #607: the management API, which an owner's
      // pages call, where it is on another listener — between the two the
      // shell always had, in the order the console draws the same three.
      const data = (there.oauth ? ' data-sts-oauth="' + kit.esc(there.oauth) +
                                  '"' : '') +
                   (there.api ? ' data-sts-api="' + kit.esc(there.api) +
                                '"' : '') +
                   (there.authn ? ' data-sts-authn="' + kit.esc(there.authn) +
                                  '"' : '');
      return '<!DOCTYPE html>\n<html lang="en"' + data + '><head>' +
        '<meta charset="utf-8"><meta name="viewport" ' +
        'content="width=device-width,initial-scale=1"><title>Your account — ' +
        'IYA STS</title><link rel="stylesheet" href="' + BASE +
        '/portal.css">' +
        (refused ? '' : '<script src="' + BASE +
                        '/portal.js" defer></script>') +
        '</head><body><div class="wrap"><div class="card">' +
        '<h1>Your account</h1>' +
        (refused
          ? '<div class="err">' + kit.esc(registered.why ||
              'The portal cannot sign in at this address.') + '</div>'
          : '<noscript><div class="err">This portal is a script that runs ' +
            'in your browser and draws every page from <code>/account-api' +
            '</code>; with scripts blocked there is nothing it can show.' +
            '</div></noscript><p class="sub">Loading&hellip;</p>') +
        '</div></div></body></html>\n';
    };
    const odd = 'https://h.example:8443/realm/a?x=1&y="q"\'<b>';
    const shellCases = [
      [{ ok: true }, {}], [null, undefined],
      [{ ok: true }, { oauth: 'https://as.example:8443/realm/acme',
                       api: 'https://api.example', authn: odd }],
      [{ ok: true }, { oauth: '', api: odd, authn: '' }],
      [{ ok: false, why: 'No <callback> here & "there"' }, {}],
      [{ ok: false }, { oauth: odd }]
    ];
    const shellDiffers = [];
    shellCases.forEach(function (one, at) {
      const a = admin.shellDocument(one[0], one[1]);
      const b = adminBefore(one[0], one[1]);
      if (a !== b) {
        shellDiffers.push('console case ' + at + ': ' +
                          JSON.stringify([a.length, b.length]));
      }
      const c = portal.shellDocument(one[0], one[1]);
      const d = portalBefore(one[0], one[1]);
      if (c !== d) {
        shellDiffers.push('portal case ' + at + ': ' +
                          JSON.stringify([c.length, d.length]));
      }
    });
    note(shellDiffers.length === 0,
         'A1. the console\'s and the portal\'s shells, drawn through ' +
         'ShellDocument, are to the byte what each drew by hand (' +
         shellCases.length + ' cases each)', shellDiffers.join('; '));
    const consoleBefore = app.contentSecurityPolicy({
      'script-src': "'self'",
      'connect-src': "'self' https://as.example",
      'style-src': "'self' 'unsafe-inline'" });
    const portalPolicy = app.contentSecurityPolicy({
      'script-src': "'self'",
      'connect-src': "'self' https://as.example",
      'style-src': "'self' 'unsafe-inline'",
      'img-src': "'self' data:" });
    const tried = ShellDocument.policy(app, {
      connect: ShellDocument.originsOf(['https://as.example/realm/a',
                                        '', 'https://as.example:443/x']),
      csp: { 'frame-ancestors': '*', 'base-uri': '*' } });
    note(ShellDocument.policy(app, {
           connect: ShellDocument.originsOf(['https://as.example/realm/a',
                                             'https://as.example/b']) }) ===
           consoleBefore &&
         ShellDocument.policy(app, {
           connect: ['https://as.example'],
           csp: { 'img-src': "'self' data:" } }) === portalPolicy &&
         /frame-ancestors 'none'/.test(tried) &&
         /base-uri 'none'/.test(tried) && !/frame-ancestors \*/.test(tried),
         'A2. a shell\'s policy is the one the hand code set, through ' +
         'app.contentSecurityPolicy(), and frame-ancestors and base-uri ' +
         'cannot be relaxed through it', tried);
    const adminSrc = fs.readFileSync(ROOT_DIR + '/admin-ui/admin.ts',
                                     'utf8');
    const portalSrc = fs.readFileSync(ROOT_DIR + '/portal/portal.ts', 'utf8');
    // The shell method's own body, from its signature to its Leaving line:
    // another page of the module (the console's realm chooser) may still
    // draw a document of its own.
    const bodyOf = function (src, cls) {
      const from = src.indexOf('  shellDocument(registered');
      const to = src.indexOf('Leaving ' + cls + '.shellDocument()', from);
      return from > 0 && to > from ? src.slice(from, to) : '';
    };
    note([[adminSrc, 'AdminConsole'], [portalSrc, 'Portal']].every(
      function (one) {
        const body = bodyOf(one[0], one[1]);
        return body.indexOf('ShellDocument.document(') > 0 &&
          body.indexOf('<!DOCTYPE') < 0 &&
          one[0].indexOf('ShellDocument.serve(') > 0;
      }), 'A3. both draw and send their shells through ShellDocument, and ' +
        'neither shell writes a doctype of its own');

    // --- B. one locale order and one negotiation ---------------------------
    const index = JSON.parse(JSON.stringify(publicAssets.index()));
    const parts = WebLocale.catalogParts(index.catalogs);
    const lists = [[], ['fr'], ['fr-CA'], ['fr-BE', 'en'], ['es-AR'],
                   ['es-ES'], ['zh-TW'], ['zh-HK', 'zh'], ['zh'], ['tl'],
                   ['de', 'sv'], ['de'], ['x-bogus', 'fil'], ['*', 'en-GB'],
                   ['ar']];
    const negotiationDiffers = [];
    lists.forEach(function (prefs) {
      ['', 'fr', 'de'].forEach(function (last) {
        const server = i18n.negotiate(prefs, last || undefined);
        const browser = WebLocale.negotiate(prefs, last || undefined, parts);
        if (JSON.stringify(server) !== JSON.stringify(browser)) {
          negotiationDiffers.push(JSON.stringify([prefs, last, server,
                                                  browser]));
        }
      });
    });
    note(negotiationDiffers.length === 0 && index.catalogs.length > 1 &&
         parts.length === index.catalogs.length,
         'B1. the browser\'s negotiation over the served index answers what ' +
         'the server\'s does (' + lists.length * 3 + ' lists)',
         negotiationDiffers.slice(0, 3).join('; '));
    const req = { headers: { cookie: 'a=b; sts_lang=fr; c=d',
                             'accept-language': 'es;q=0.5, sv, *;q=0.1' } };
    const order = PageLocale.preferences(req, { uiLocales: 'fil zz-' });
    note(JSON.stringify(order) === JSON.stringify(['fil', 'fr', 'sv', 'es']) &&
         JSON.stringify(WebLocale.preferences({ uiLocales: 'fil zz-',
           chooser: 'fr', acceptLanguage: 'es;q=0.5, sv, *;q=0.1' })) ===
           JSON.stringify(order) &&
         JSON.stringify(WebLocale.preferences({
           own: { value: 'de', populated: true }, chooser: '',
           acceptLanguage: 'sv' })) === JSON.stringify(['sv', 'de']) &&
         JSON.stringify(WebLocale.preferences({
           own: { value: 'de', populated: false }, chooser: 'fr',
           acceptLanguage: 'sv' })) === JSON.stringify(['de', 'fr', 'sv']),
         'B2. the order is #539\'s — ui_locales, the person\'s own, the ' +
         'chooser, the browser, a populated preferredLanguage last — the ' +
         'same from a request and from a browser\'s inputs',
         JSON.stringify(order));
    // THE CHOOSER AS `PageLocale.chooser()` DREW IT BEFORE #570.
    const chooserBefore = function (t, returnTo) {
      const esc = function (value) {
        return String(value == null ? '' : value)
          .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
      };
      const here = PageLocale.safeReturn(returnTo);
      const current = t.locale.toLowerCase();
      const offered = i18n.offered();
      const exact = offered.filter(function (one) {
        return one.tag.toLowerCase() === current;
      })[0];
      const sameCatalog = offered.filter(function (one) {
        return i18n.negotiate([one.tag]).catalog === t.negotiated.catalog;
      })[0];
      const selected = (exact || sameCatalog || offered[0] || { tag: '' }).tag;
      const drawn = offered.map(function (one) {
        return '<option value="' + esc(one.tag) + '" lang="' +
          esc(one.tag) + '"' +
          (one.tag === selected ? ' selected' : '') + '>' +
          esc(one.name) + '</option>';
      }).join('');
      return '<form class="language-chooser" method="post" action="' +
        esc('/authn/language') + '">' +
        '<input type="hidden" name="return" value="' + esc(here) +
        '"><label for="sts-language">' + t.html('chooser.label') +
        '</label> <select id="sts-language" name="lang">' + drawn +
        '</select> <button type="submit">' + t.html('chooser.change') +
        '</button></form>';
    };
    const chooserDiffers = [];
    ['en', 'fr', 'fr-CA', 'es-AR', 'zh-TW', 'de'].forEach(function (tag) {
      ['/authn/x?y=1&z="2"', '//evil.example', '/realm/a/portal'].forEach(
        function (back) {
          const t = i18n.translator([tag]);
          const server = PageLocale.chooser(t, '', back);
          const browser = WebLocale.chooserHtml(t, index.offered, parts,
                                                back);
          if (server !== browser || server !== chooserBefore(t, back)) {
            chooserDiffers.push(tag + ' ' + back);
          }
        });
    });
    note(chooserDiffers.length === 0 && index.offered.length > 1,
         'B3. the chooser a runtime draws from the served index is the ' +
         'server\'s, which is the chooser drawn by hand before #570',
         chooserDiffers.join(', '));
    const attrs = PageLocale.shellAttributes(
      { headers: { cookie: 'sts_lang=FR-ca' } }, 'no-such-application');
    note(JSON.stringify(attrs) === JSON.stringify([
           ['data-sts-version', String(version.load().version)],
           ['data-sts-lang', 'fr-CA'], ['data-sts-locale-default', 'en']]) &&
         PageLocale.shellAttributes({ headers: { cookie:
           'sts_lang="><script>' } }, '')[1][1] === '',
         'B4. a shell carries the build, the chooser\'s choice canonical ' +
         '(never as the request sent it), and the policy\'s default',
         JSON.stringify(attrs));

    // --- C. the shared files, over HTTP ------------------------------------
    const express = require(ROOT_DIR + '/node_modules/express');
    const server = express();
    new publicAssets.PublicAssets(publicAssets.PublicAssets.defaultDeps())
      .registerRoutes(server);
    const listener = await new Promise(function (resolve) {
      const one = server.listen(0, '127.0.0.1', function () {
        resolve(one);
      });
    });
    const base = 'http://127.0.0.1:' + listener.address().port;
    const get = async function (p, headers) {
      const res = await fetch(base + p, { headers: headers || {} });
      return { status: res.status, text: await res.text(),
               cache: res.headers.get('cache-control') || '',
               encoding: res.headers.get('content-encoding') || '',
               type: res.headers.get('content-type') || '' };
    };
    const v = encodeURIComponent(String(version.load().version));
    const idx = await get('/web/locales/catalogs.json');
    const idxV = await get('/web/locales/catalogs.json?v=' + v);
    const idxOld = await get('/web/locales/catalogs.json?v=0.0.1');
    let idxJson = null;
    try {
      idxJson = JSON.parse(idx.text);
    } catch (e) {
      idxJson = null;
    }
    note(idx.status === 200 && /json/.test(idx.type) && !!idxJson &&
         idxJson.catalogs.length === i18n.catalogs().length &&
         idxJson.offered.length === i18n.offered().length &&
         idx.cache === 'no-cache' && idxOld.cache === 'no-cache' &&
         idxV.cache === 'public, max-age=31536000, immutable',
         'C1. the index is the catalogs and the chooser\'s locales, ' +
         'cached for good only under this build\'s version',
         JSON.stringify([idx.status, idx.cache, idxV.cache, idxOld.cache]));
    const en = await get('/web/locales/authn/en.json?v=' + v,
                         { 'accept-encoding': 'gzip' });
    const overlay = await get('/web/locales/consoleKit/fr-CA.json');
    note(en.status === 200 && en.encoding === 'gzip' &&
         en.text === JSON.stringify(i18n.messagesOf('authn', 'en')) &&
         overlay.status === 200 &&
         overlay.text === JSON.stringify(i18n.messagesOf('consoleKit',
                                                         'fr-CA')),
         'C2. a catalog file is what i18n loaded, compressed where asked, ' +
         'and a known pair with no file is what it holds ({} or its ' +
         'overlay)', JSON.stringify([en.status, en.encoding, overlay.status,
                                     overlay.text.slice(0, 40)]));
    const refused = [];
    for (const p of ['/web/locales/nope/en.json', '/web/locales/authn/xx.json',
                     '/web/locales/authn/en.txt',
                     '/web/locales/authn/..%2Fcatalogs.json',
                     '/web/locales/..%2F..%2Fpackage/en.json']) {
      const one = await get(p);
      if (one.status !== 404 || one.cache !== 'no-store') {
        refused.push(p + ' ' + one.status);
      }
    }
    note(refused.length === 0,
         'C3. an unknown namespace, catalog or file name is a 404, and ' +
         'nothing is read by a requested name', refused.join(', '));
    const card = await get('/web/card.css', { 'accept-encoding': 'br' });
    note(card.status === 200 && /text\/css/.test(card.type) &&
         card.encoding === 'br' && card.text === WebCardCss.CARD_CSS,
         'C4. /web/card.css is the card', JSON.stringify([card.status,
                                                         card.type]));
    listener.close();
    note(hosted.classify('/web/card.css') === hosted.EVERYWHERE &&
         hosted.classify('/web/locales/authn/en.json') === hosted.EVERYWHERE &&
         hosted.classify('/webx') !== hosted.EVERYWHERE &&
         placement.ROWS.some(function (row) {
           return row.prefix === '/web' && row.strategy === 'local';
         }),
         'C5. /web is answered on every listener and in every cell');

    // --- D. the card is one stylesheet -------------------------------------
    note(WebCardCss.CARD_CSS === authn.CARD_CSS &&
         WebCardCss.CARD_CSS.indexOf(WebCardCss.CHOOSER_CSS) > 0,
         'D1. the card is the sign-in screen\'s stylesheet, chooser rules ' +
         'included');

    // --- E. a public surface's runtime, driven in node ----------------------
    const posted = [];
    const drive = async function (where, attributes) {
      const loc = new URL('https://sts.example' + where);
      const attrs = Object.assign({}, attributes || {});
      const location = {
        get pathname() {
          return loc.pathname;
        },
        get search() {
          return loc.search;
        },
        get hash() {
          return loc.hash;
        },
        get href() {
          return loc.href;
        },
        origin: 'https://sts.example',
        assign: function (to) {
          location.assigned = to;
        },
        replace: function () {
          return undefined;
        }
      };
      const env = {
        location: location,
        history: {
          pushState: function (s, title, to) {
            const next = new URL(to, loc.href);
            loc.pathname = next.pathname;
            loc.search = next.search;
            loc.hash = next.hash;
          },
          replaceState: function () {
            return undefined;
          }
        },
        document: {
          title: '', body: { innerHTML: '' },
          documentElement: {
            getAttribute: function (n) {
              return n in attrs ? attrs[n] : null;
            },
            setAttribute: function (n, value) {
              attrs[n] = value;
            }
          },
          addEventListener: function () {
            return undefined;
          }
        },
        navigator: { languages: ['sv', 'en'] },
        formDataOf: function (form) {
          const data = new FormData();
          form.fields.forEach(function (one) {
            data.append(one[0], one[1]);
          });
          return data;
        },
        fetch: async function (url, init) {
          const u = new URL(url);
          const answer = function (status, body, extra) {
            return Object.assign({ status: status, type: 'basic',
              headers: { get: function () {
                return null;
              } },
              json: async function () {
                if (body === null) {
                  throw new Error('not JSON');
                }
                return JSON.parse(JSON.stringify(body));
              } }, extra || {});
          };
          const p = u.pathname.replace(/^\/realm\/acme/, '');
          const m = /^\/web\/locales\/([^/]+)\/([^/]+)$/.exec(p);
          if (p === '/web/locales/catalogs.json') {
            return answer(200, publicAssets.index());
          }
          if (m) {
            const found = publicAssets.catalog(decodeURIComponent(m[1]),
                                               decodeURIComponent(m[2]));
            return found ? answer(200, found) : answer(404, null);
          }
          if (p === '/demo-api') {
            return answer(200, { operations: [{ method: 'POST',
              path: '/demo-api/act', mirrors: 'POST /demo' }] });
          }
          if (p === '/demo-api/page') {
            return answer(200, { view: { name: '<b>x</b>' } });
          }
          if (p === '/demo-api/act') {
            posted.push({ url: url, body: JSON.parse(init.body) });
            return answer(200, { ok: true, message: 'done' });
          }
          if (p === '/authn/language') {
            posted.push({ url: url, body: String(init.body),
                          redirect: init.redirect });
            return answer(0, null, { type: 'opaqueredirect' });
          }
          return answer(404, null);
        }
      };
      const surface = new WebSurface(env, {
        base: '/demo', api: '/demo-api', namespaces: ['chooser'],
        pages: [{ path: '/demo', operation: '/demo-api/page',
          title: function () {
            return 'Demo';
          },
          render: function (json, ctx) {
            return '<p>' + ctx.t.html('chooser.change') + ' ' +
              WebSurface.esc(json.name) + '</p><a href="/demo?x=1">x</a>' +
              '<form method="post" action="/demo"><button>Go</button></form>';
          } }]
      });
      await surface.start();
      return { surface: surface, env: env, attrs: attrs };
    };
    const fr = i18n.translator(['fr']);
    const sv = i18n.translator(['sv']);
    const one = await drive('/demo?ui_locales=fr',
                            { 'data-sts-version': String(version.load()
                                                         .version) });
    const body1 = one.env.document.body.innerHTML;
    note(body1.indexOf('<p>' + fr.html('chooser.change') +
                       ' &lt;b&gt;x&lt;/b&gt;</p>') >= 0 &&
         body1.indexOf('<form class="language-chooser"') === 0 &&
         one.attrs.lang === 'fr' && one.env.document.title ===
           'Demo — IYA STS',
         'E1. a surface draws its page from the operation\'s JSON in the ' +
         'language negotiated in the browser (ui_locales first), with the ' +
         'chooser', body1.slice(0, 300));
    await one.surface.submit({ fields: [['a', '1'], ['csrf_token', 'z'],
                                        ['a', '2']],
      getAttribute: function (n) {
        return n === 'action' ? '/demo' : null;
      }
    }, null);
    const act = posted.filter(function (p) {
      return /\/demo-api\/act$/.test(p.url);
    })[0];
    note(!!act && JSON.stringify(act.body) === JSON.stringify({ a: ['1', '2'] })
         && one.env.document.body.innerHTML.indexOf(
           '<div class="ok">done</div>') >= 0,
         'E2. a POST form goes as JSON to the operation that mirrors it, ' +
         'without the CSRF field, and its message is drawn',
         JSON.stringify(act || null));
    await one.surface.submit({ fields: [],
      getAttribute: function (n) {
        return n === 'action' ? '/demo/other' : null;
      }
    }, null);
    note(one.env.document.body.innerHTML.indexOf('has no API operation') >= 0,
         'E3. a form no operation mirrors is refused, not guessed');
    const two = await drive('/realm/acme/demo',
                            { 'data-sts-prefix': '/realm/acme' });
    const body2 = two.env.document.body.innerHTML;
    note(body2.indexOf('href="/realm/acme/demo?x=1"') >= 0 &&
         body2.indexOf('action="/realm/acme/authn/language"') >= 0 &&
         two.attrs.lang === 'sv' &&
         body2.indexOf(sv.html('chooser.change')) >= 0,
         'E4. in a realm the page links into it, and with no ui_locales ' +
         'the browser\'s languages decide', body2.slice(0, 300));
    const chose = await two.surface.i18n.choose('fr', '/realm/acme/demo');
    await two.surface.route();
    const sent = posted.filter(function (p) {
      return /\/authn\/language$/.test(p.url);
    })[0];
    note(chose && !!sent && sent.redirect === 'manual' &&
         sent.url === 'https://sts.example/realm/acme/authn/language' &&
         sent.body === 'lang=fr&return=%2Frealm%2Facme%2Fdemo' &&
         two.attrs.lang === 'fr',
         'E5. the chooser is sent to /authn/language, and the page is drawn ' +
         'again in the language chosen', JSON.stringify(sent || null));

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
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
  const out = path.join(os.tmpdir(), 'wf-' + process.pid + '-' + Date.now() +
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
                                  WF_ROOT: ROOT, WF_OUT: out }),
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
  name: 'web_foundation',
  describe: 'the shared foundation of the static surfaces: one shell ' +
            'writer with the same bytes, one locale order and negotiation ' +
            'for the server and the browser, the /web files, the card, and ' +
            'a public surface\'s runtime driven in node (#570)',
  run: run
};
