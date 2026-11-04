// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: branding_api.js
//
// ===========================================================================
// THE SIGN-IN APPEARANCE'S MANAGEMENT API AND CONSOLE PAGE (#717):
// `mgmt-api/branding_api.ts` and `admin-ui/web_sign_in_appearance.ts`. In
// process; every write is in a realm this file creates and removes, so the
// default realm is only read. `tests/branding.js` holds `common/branding.ts`
// itself; this holds the two doors onto it.
//
//   A. THE TABLE: GET /admin-api/branding, POST /branding/logo ABOVE
//      /branding/:action (or `logo` would be an unknown action), the two
//      acts with their examples, every row mirroring the page, the save
//      schema naming exactly SAVED_KEYS, and the console's forms resolving
//      to the three operations (`web_forms.ts`).
//   B. THE VIEW is the ambient realm's: its id, its preview's address
//      under its own prefix, the settings block.
//   C. SAVE writes what it names and refuses as the core refuses, with the
//      core's codes (STS-AUTHN-0544, STS-CORE-0004); `action` and the
//      gate's `actor` are not settings.
//   D. AN UNKNOWN ACTION names all three, `logo` among them (STS-API-0038).
//   E. THE LOGO: the bytes from the raw parser and from beside the text
//      parser's string, the alternative text required (0548), a file that
//      is no image 415 (0545), one over the cap 413 (0546), and the stored
//      logo's address under the realm's prefix.
//   F. REMOVE-LOGO, twice: the second has nothing to remove.
//   G. THE PAGE: four tabs, the colour inputs named for the settings, the
//      contrast drawn against AA, the upload a multipart form, the preview
//      a GET form to the realm's preview in a new tab, the logo drawn by
//      attributes, and nothing writable for a reader without Admin Write.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'branding_api',
  level: process.env.LOG_LEVEL || 'info' });

const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const Branding = require('../common/branding');
const brandingApi = require('../mgmt-api/branding_api');
const SignInAppearancePage = require('../admin-ui/web_sign_in_appearance');
const WebForms = require('../admin-ui/web_forms');
const kit = require('../admin-ui/web_kit');
const webMessages = require('../common/web_messages');

const REALM = 'brand-api-test';
const PAGE = '/admin/sign-in-appearance';

// A PNG's first 24 bytes are all the check reads (`tests/branding.js`).
function png(width, height, length) {
  log.debug("Entering png().");
  const b = Buffer.alloc(length || 64);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b, 0);
  b.writeUInt32BE(13, 8);
  b.write('IHDR', 12, 'latin1');
  b.writeUInt32BE(width, 16);
  b.writeUInt32BE(height, 20);
  log.debug("Leaving png().");
  return b;
}

// A response that records what a handler did to it.
function response(caller) {
  log.debug("Entering response().");
  const res = { statusCode: 200, headers: {}, body: null,
                locals: caller ? { apiCaller: { name: caller } } : {} };
  res.status = function (code) {
    res.statusCode = code;
    return res;
  };
  res.type = function (t) {
    res.headers['content-type'] = t;
    return res;
  };
  res.set = function (name, value) {
    res.headers[String(name).toLowerCase()] = value;
    return res;
  };
  res.send = function (body) {
    res.body = body;
    return res;
  };
  log.debug("Leaving response().");
  return res;
}

// The API built with the real core and realms, and a console that answers
// an empty settings block: loading the whole console here would load every
// family's module for one member of the view.
function api() {
  log.debug("Entering api().");
  const deps = brandingApi.BrandingApi.defaultDeps();
  deps.loadAdmin = function () {
    return {
      configSettingsJson: function (page) {
        return { page: page, groups: [] };
      }
    };
  };
  const made = new brandingApi.BrandingApi(deps);
  log.debug("Leaving api().");
  return made;
}

// One call to a row's handler, answered synchronously.
function call(row, req, caller) {
  log.debug("Entering call().");
  const res = response(caller);
  row.handler(Object.assign({ query: {}, params: {},
                              headers: { 'content-type': 'application/json' }
                            }, req), res);
  let body = res.body;
  try {
    body = JSON.parse(String(res.body));
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
  }
  log.debug("Leaving call().");
  return { status: res.statusCode, body: body, code: errorCodes.codeOf(res) };
}

// A translator over the page's English catalog.
function translator() {
  log.debug("Entering translator().");
  const english = JSON.parse(fs.readFileSync(path.join(__dirname,
    '../common/locales/consoleSignInAppearance/en.json'), 'utf8'));
  const flat = {};
  Object.keys(english).forEach(function (key) {
    flat['consoleSignInAppearance.' + key] = english[key];
  });
  log.debug("Leaving translator().");
  return webMessages.WebTranslator.fromData({
    negotiated: { locale: 'en', chain: ['en'], catalog: 'en',
                  direction: 'ltr', matched: true },
    catalogs: { en: flat } });
}

function sectionA(t, rows) {
  log.debug("Entering sectionA().");
  const keys = rows.map(function (row) {
    return row.method + ' ' + (row.route || row.path);
  });
  t.equal(keys.join(' | '), 'GET /admin-api/branding | POST ' +
          '/admin-api/branding/logo | POST /admin-api/branding/:action',
          'A1. three rows, the logo above the action route');
  t.check(rows.every(function (row) {
    return String(row.mirrors) === row.method + ' ' + PAGE;
  }), 'A2. every row mirrors the page', rows.map(function (row) {
    return row.mirrors;
  }).join(', '));
  const actions = rows[2].actions || [];
  t.equal(actions.map(function (one) {
    return one.action;
  }).join(','), 'save,remove-logo', 'A3. the two acts');
  t.check(actions.every(function (one) {
    return one.requestBody && Array.isArray(one.requestBody.examples) &&
      one.requestBody.examples.length === 1;
  }), 'A4. each act carries one example for the operations walk');
  t.equal(Object.keys(actions[0].requestBody.properties).join(','),
          brandingApi.SAVED_KEYS.join(','),
          'A5. the save schema names exactly the settings a save takes');
  t.check(rows[1].handlerOwnsBody === true &&
          rows[1].requestBodyTypes.indexOf('image/png') >= 0 &&
          rows[1].requestBodyTypes.indexOf('application/octet-stream') >= 0,
          'A6. the logo owns its body, and takes the image types');
  // The console's index lists an action route once per action, its path
  // ending in the action's name; `WebForms` resolves a form from it.
  const index = [];
  rows.forEach(function (row) {
    if (row.actions) {
      row.actions.forEach(function (one) {
        index.push({ method: 'POST', mirrors: row.mirrors,
                     path: String(row.route).replace(':action', one.action) });
      });
      return;
    }
    index.push({ method: row.method, mirrors: row.mirrors,
                 path: row.path });
  });
  const table = WebForms.table(index);
  t.equal([WebForms.resolve(table, PAGE, 'save'),
           WebForms.resolve(table, PAGE, 'logo'),
           WebForms.resolve(table, PAGE, 'remove-logo')].join(' '),
          '/admin-api/branding/save /admin-api/branding/logo ' +
          '/admin-api/branding/remove-logo',
          'A7. the page\'s three forms resolve to the three operations');
  log.debug("Leaving sectionA().");
}

function sectionB(t, rows) {
  log.debug("Entering sectionB().");
  const got = call(rows[0], {});
  t.check(got.status === 200 && got.body.realm === REALM &&
          got.body.previewUrl === '/realm/' + REALM +
            '/web/branding/preview' &&
          got.body.logo === null && got.body.layout === 'centered' &&
          got.body.settings && got.body.settings.page === PAGE,
          'B1. the view is the realm\'s, its preview under its prefix',
          JSON.stringify(got.body).slice(0, 300));
  log.debug("Leaving sectionB().");
}

function sectionC(t, rows) {
  log.debug("Entering sectionC().");
  const saved = call(rows[2], { params: { action: 'save' }, body:
    JSON.stringify({ 'branding.layout': 'split',
                     'branding.accentColor': '#0B5394',
                     'branding.displayName': 'Example Corp',
                     actor: 'carol' }) });
  const after = call(rows[0], {}).body;
  t.check(saved.status === 200 && saved.body.ok === true &&
          after.layout === 'split' && after.colours.accent === '#0b5394' &&
          after.displayName === 'Example Corp' && after.customised === true,
          'C1. a save writes what it names, in this realm, and the gate\'s ' +
          'actor is not a setting', JSON.stringify(saved.body));
  const low = call(rows[2], { params: { action: 'save' }, body:
    JSON.stringify({ 'branding.textColor': '#eeeeee' }) });
  t.check(low.status === 400 && low.code === 'STS-AUTHN-0544' &&
          call(rows[0], {}).body.colours.text === '#222222',
          'C2. text below AA is refused with the core\'s code, and kept',
          low.code + ' ' + JSON.stringify(low.body));
  const other = call(rows[2], { params: { action: 'save' }, body:
    JSON.stringify({ 'oauth2.issuer': 'x' }) });
  t.check(other.status === 400 && other.code === 'STS-CORE-0004',
          'C3. a setting that is not an appearance setting is refused',
          other.code);
  realms.run(realms.get(realms.DEFAULT_ID), function () {
    t.equal(Branding.describe().displayName, '',
            'C4. the default realm is untouched');
  });
  log.debug("Leaving sectionC().");
}

function sectionD(t, rows) {
  log.debug("Entering sectionD().");
  const got = call(rows[2], { params: { action: 'nonsense' }, body: '{}' });
  const said = ((got.body && got.body.errors) || []).join(' ');
  t.check(got.status === 400 && got.code === 'STS-API-0038' &&
          /Unknown action "nonsense"\. The three are: save, logo, remove-logo\./
            .test(said),
          'D1. an unknown action names all three', said);
  log.debug("Leaving sectionD().");
}

function sectionE(t, rows) {
  log.debug("Entering sectionE().");
  const noAlt = call(rows[1], { body: png(32, 32) });
  t.check(noAlt.status === 400 && noAlt.code === 'STS-AUTHN-0548',
          'E1. a first logo with no alternative text is refused',
          noAlt.code);
  const raw = call(rows[1], { body: png(32, 32), query: { alt: 'Example' } },
                   'carol');
  t.check(raw.status === 200 && raw.body.logo &&
          raw.body.logo.type === 'image/png',
          'E2. the raw parser\'s bytes are stored, with the text',
          JSON.stringify(raw.body).slice(0, 300));
  const kept = call(rows[1], { body: '�PNG', rawBody: png(48, 24) });
  const view = call(rows[0], {}).body;
  t.check(kept.status === 200 && view.logo && view.logo.width === 48 &&
          view.logoAlt === 'Example' &&
          String(view.logo.src).indexOf('/realm/' + REALM +
                                        '/web/branding/logo?v=') === 0,
          'E3. the bytes beside the text parser\'s string are the image, ' +
          'and the logo\'s address is under the realm\'s prefix',
          JSON.stringify(view.logo));
  const html = call(rows[1], { body: Buffer.from('<html></html>') });
  t.check(html.status === 415 && html.code === 'STS-AUTHN-0545',
          'E4. a file that is no image is 415', html.code);
  const big = call(rows[1], { body: png(32, 32, Number(view.logoMaxBytes) +
                                                1) });
  t.check(big.status === 413 && big.code === 'STS-AUTHN-0546',
          'E5. a file over branding.logoMaxBytes is 413', big.code);
  const none = call(rows[1], { body: { not: 'bytes' } });
  t.check(none.status === 400 && none.code === 'STS-AUTHN-0546',
          'E6. a body that is no bytes is no image sent', none.code);
  log.debug("Leaving sectionE().");
}

function sectionF(t, rows) {
  log.debug("Entering sectionF().");
  const first = call(rows[2], { params: { action: 'remove-logo' },
                                body: '{}' });
  const second = call(rows[2], { params: { action: 'remove-logo' },
                                 body: '{}' });
  t.check(first.status === 200 && first.body.removed === true &&
          second.status === 200 && second.body.removed === false &&
          call(rows[0], {}).body.logo === null,
          'F1. the logo is removed, and a second removal finds none',
          JSON.stringify([first.body, second.body]));
  log.debug("Leaving sectionF().");
}

function sectionG(t) {
  log.debug("Entering sectionG().");
  const tr = translator();
  const view = {
    realm: REALM, layout: 'banner', layouts: ['centered', 'split', 'banner'],
    colours: { accent: '#0b5394', page: '#f4f4f7', card: '#ffffff',
               text: '#222222' },
    derived: { onAccent: '#ffffff', muted: '#666666', faint: '#777777',
               dim: '#555555', border: '#d5d5dd', rule: '#eeeeee' },
    contrast: { text: 15.9, accent: 7.6, buttonText: 3.1, required: 4.5 },
    displayName: 'Example <Corp>', logoAlt: 'Example', logoLinkUrl: '',
    logoMaxBytes: 262144, customised: true,
    logo: { type: 'image/png', width: 128, height: 32, bytes: 900,
            sha256: 'ab'.repeat(32), url: '/web/branding/logo?v=abab',
            src: '/realm/' + REALM + '/web/branding/logo?v=abab',
            updatedAt: '2026-11-04T00:00:00.000Z', updatedBy: 'carol' },
    preview: '/web/branding/preview',
    previewUrl: '/realm/' + REALM + '/web/branding/preview',
    settings: { groups: [] }
  };
  const html = SignInAppearancePage.render(view, kit.context({}, true, tr));
  const tabs = (html.match(/data-tab="[a-z]+"/g) || []).join(',');
  t.equal(tabs, 'data-tab="colours",data-tab="layout",data-tab="preview"',
          'G1. three drawn tabs before the settings block');
  t.check(['accentColor', 'pageColor', 'cardColor', 'textColor']
    .every(function (name) {
      return new RegExp('type="color" id="sia-[a-z]+" name="branding\\.' +
                        name + '"').test(html);
    }), 'G2. a colour input per setting');
  t.check(/3\.10:1<\/td><td><span class="state-invalid">Fails/.test(html) &&
          /15\.90:1<\/td><td><span class="state-valid">Passes/.test(html),
          'G3. each contrast drawn against AA');
  t.check(/<form method="post" action="\/admin\/sign-in-appearance" id="sia-upload" enctype="multipart\/form-data"><input type="hidden" name="action" value="logo">/
            .test(html) &&
          /name="action" value="remove-logo"/.test(html),
          'G4. the upload is multipart with action=logo, and a logo held ' +
          'can be removed');
  t.check(html.indexOf('<form method="get" action="/realm/' + REALM +
                       '/web/branding/preview" target="_blank"') >= 0 &&
          /name="layout"><option value="centered">centered<\/option>/
            .test(html) &&
          /<option value="banner" selected>/.test(html),
          'G5. the preview is a GET form to the realm\'s preview, in a ' +
          'new tab');
  t.check(/<img class="sia-logo" id="sia-logo" src="\/realm\/brand-api-test\/web\/branding\/logo\?v=abab" alt="Example" width="128" height="32">/
            .test(html),
          'G6. the logo is drawn by attributes, at most 64 high');
  t.check(html.indexOf('Example &lt;Corp&gt;') >= 0 &&
          html.indexOf('Example <Corp>') < 0,
          'G7. the display name is escaped');
  const reader = SignInAppearancePage.render(Object.assign({}, view,
    { logo: null }), kit.context({}, false, tr));
  t.check(/Changing the sign-in appearance needs Admin Write/.test(reader) &&
          !/name="action" value="remove-logo"/.test(reader) &&
          (reader.match(/<button type="submit" disabled>/g) || []).length ===
            3 &&
          /This realm has no logo/.test(reader),
          'G8. a reader sees every write disabled, and no logo');
  log.debug("Leaving sectionG().");
}

async function run(t) {
  log.debug("Entering run().");
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!t.check(made.ok, 'the test realm is created',
               (made.errors || []).join(' '))) {
    log.debug("Leaving run().");
    return;
  }
  const rows = api().buildRoutes();
  sectionA(t, rows);
  try {
    realms.run(made.realm, function () {
      sectionB(t, rows);
      sectionC(t, rows);
      sectionD(t, rows);
      sectionE(t, rows);
      sectionF(t, rows);
    });
  } finally {
    realms.remove(REALM);
  }
  sectionG(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'branding_api',
  describe: 'the sign-in appearance\'s management API and console page ' +
            '(#717): the three operations in the ambient realm, the core\'s ' +
            'refusals and codes, the logo\'s bytes, and the page\'s tabs',
  run: run
};
