// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ordered_choice_setting.js
//
// ===========================================================================
// AN ORDERED CHOICE FROM A CLOSED LIST, ON THE CONSOLE (2026-10-01).
//
// rcbj: "expose functionality that allows an administrator to explicitly
// choose (by checkboxes) which webauthn / ctap algorithms are supported
// (requested) and an order of preference". `webauthn.algorithms` is marked
// `ordered` in `common/config.js`, so `/admin/webauthn` draws it as a table —
// a checkbox and an order number per algorithm — and the `/admin/config`
// route folds those fields back into the setting's one value before the
// save is checked.
//
// Through the two route handlers themselves, called with a request this
// file builds (`kerberos_principals_paging.js`'s arrangement — the console's
// gate is middleware in front of them and is not what is tested):
//
//   1. the setting describes itself as ordered, with a note per value;
//   2. the page draws one checkbox and one number per value, the chosen ones
//      first in their order, the marker field, and no text box for it;
//   3. a save ticking three and numbering them 3, 1, 2 stores them in that
//      order, and the page then draws them first in it;
//   4. a tie keeps the posted order and a number that is not one goes last;
//   5. a save ticking nothing is refused (STS-ADMIN-0840) and changes
//      nothing;
//   6. a value outside the list is refused by the setting's own check;
//   7. a form-encoded post, the shape a browser sends, folds the same way.
//
// The setting is reset in a `finally`: it is process-wide.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const app = require('../common/app');
require('../admin-ui/admin').registerRoutes(app);

const log = require('bunyan').createLogger({
  name: 'ordered_choice_setting',
  level: process.env.LOG_LEVEL || 'info' });

const KEY = 'webauthn.algorithms';

function handlerFor(method, path) {
  log.debug("Entering handlerFor(). " + method + " " + path);
  const layer = (app._router.stack || []).filter(function (one) {
    return one.route && one.route.path === path && one.route.methods[method];
  })[0];
  log.debug("Leaving handlerFor(). " + (layer ? "Found." : "Not found."));
  return layer ? layer.route.stack[layer.route.stack.length - 1].handle :
                 null;
}

function fakeRes() {
  log.debug("Entering fakeRes().");
  const out = { status: 200, body: '', headers: {} };
  const res = {
    out: out,
    set: function (k, v) {
      if (typeof k === 'string') {
        out.headers[k.toLowerCase()] = v;
      }
      return this;
    },
    status: function (n) {
      out.status = n;
      return this;
    },
    type: function () {
      return this;
    },
    send: function (text) {
      out.body = String(text);
      return this;
    },
    end: function () {
      return this;
    },
    redirect: function (code, where) {
      out.status = typeof code === 'number' ? code : 302;
      out.headers.location = typeof code === 'number' ? where : code;
      return this;
    },
    get: function () {
      return undefined;
    },
    getHeader: function () {
      return undefined;
    },
    setHeader: function (k, v) {
      out.headers[String(k).toLowerCase()] = v;
      return undefined;
    },
    locals: {}
  };
  log.debug("Leaving fakeRes().");
  return res;
}

function fakeReq(method, path, body, type) {
  log.debug("Entering fakeReq().");
  log.debug("Leaving fakeReq().");
  return { method: method, url: path, originalUrl: path, path: path,
           query: {}, cookies: {}, body: body,
           headers: type ? { 'content-type': type } : {},
           get: function () {
             return '';
           } };
}

// The protocol pages answer after a promise (a row may `prepare`), so the
// draw waits until the body has been sent, a bounded number of turns.
async function drawPage() {
  log.debug("Entering drawPage().");
  const res = fakeRes();
  handlerFor('get', '/admin/webauthn')(fakeReq('GET', '/admin/webauthn'),
    res, function (e) {
      log.debug("The page handler called next(): " + ((e && e.message) || e));
    });
  for (let i = 0; i < 200 && !res.out.body; i++) {
    await new Promise(function (resolve) {
      setImmediate(resolve);
    });
  }
  log.debug("Leaving drawPage(). " + res.out.body.length + " character(s).");
  return res.out.body;
}

function post(fields, form) {
  log.debug("Entering post().");
  const res = fakeRes();
  const body = form
    ? new URLSearchParams(fields).toString()
    : JSON.stringify(fields);
  handlerFor('post', '/admin/config')(
    fakeReq('POST', '/admin/config', body,
            form ? 'application/x-www-form-urlencoded' : 'application/json'),
    res, function (e) {
      log.debug("The save handler called next(): " + ((e && e.message) || e));
    });
  log.debug("Leaving post(). " + res.out.status);
  return res.out;
}

// The fields the drawn table posts for `chosen` (value -> number), every
// other value unticked and numbered on, as the browser would send them.
function fieldsFor(chosen, extra) {
  log.debug("Entering fieldsFor().");
  const fields = Object.assign({ action: 'set-many', from: '/admin/webauthn' },
                               extra || {});
  fields[KEY + '.ordered'] = '1';
  Object.keys(chosen).forEach(function (value) {
    fields[KEY + '.pick.' + value] = '1';
    fields[KEY + '.rank.' + value] = String(chosen[value]);
  });
  log.debug("Leaving fieldsFor().");
  return fields;
}

// The algorithm names in the order the page draws their rows.
function drawnOrder(html) {
  log.debug("Entering drawnOrder().");
  const names = [];
  const re = new RegExp('name="' + KEY.replace('.', '\\.') +
                        '\\.pick\\.([^"]+)"([^>]*)>', 'g');
  let m;
  while ((m = re.exec(html)) !== null) {
    names.push({ value: m[1], checked: / checked/.test(m[2]) });
  }
  log.debug("Leaving drawnOrder(). " + names.length);
  return names;
}

async function runBody(t) {
  log.debug("Entering runBody().");
  const row = config.SETTINGS.filter(function (one) {
    return one.key === KEY;
  })[0];
  const described = config.describe(row);

  t.log.info('=== 1. the setting describes itself as ordered ===');
  t.check(described.ordered === true &&
          described.csvValues.every(function (value) {
            return !!(described.csvValueNotes || {})[value];
          }),
          '1. webauthn.algorithms is ordered, with a note for every value',
          JSON.stringify(described.csvValueNotes || null).slice(0, 200));
  const other = config.describe(config.SETTINGS.filter(function (one) {
    return one.key === 'webauthn.userVerification';
  })[0]);
  t.check(other.ordered === undefined && other.csvValueNotes === undefined,
          '1. a setting that is not an ordered choice describes neither');

  t.log.info('=== 2. the page draws a checkbox and a number per value ===');
  const page = await drawPage();
  const drawn = drawnOrder(page);
  const current = config.text(KEY).split(',');
  t.equal(drawn.length, described.csvValues.length,
          '2. one checkbox per value of the closed list');
  t.check(current.every(function (value, n) {
    return drawn[n] && drawn[n].value === value && drawn[n].checked;
  }) && drawn.slice(current.length).every(function (one) {
    return !one.checked;
  }), '2. the chosen values come first, ticked, in their current order',
  drawn.map(function (one) { return one.value; }).join(','));
  t.check(page.indexOf('name="' + KEY + '.ordered"') >= 0 &&
          page.indexOf('name="' + KEY + '.rank.ES256"') >= 0 &&
          page.indexOf('<input type="text" name="' + KEY + '"') < 0,
          '2. a number per value and the marker, and no text box for it');
  t.check(page.indexOf('post-quantum, RFC 9964') >= 0,
          '2. each value is drawn with its note');

  try {
    t.log.info('=== 3. a save stores the ticked values in number order ===');
    const saved = post(fieldsFor({ 'ES256': 3, 'ML-DSA-65': 1,
                                   'Ed25519': 2 }));
    t.check(saved.status === 200,
            '3. the save is accepted', saved.status + ' ' +
            saved.body.slice(0, 200));
    t.equal(config.text(KEY), 'ML-DSA-65,Ed25519,ES256',
            '3. the setting holds the three in the order they were numbered');
    const after = drawnOrder(await drawPage());
    t.check(after[0].value === 'ML-DSA-65' && after[1].value === 'Ed25519' &&
            after[2].value === 'ES256' && after[2].checked &&
            !after[3].checked,
            '3. and the page draws them first, in that order, the rest ' +
            'unticked',
            after.slice(0, 4).map(function (one) {
              return one.value + (one.checked ? '+' : '-');
            }).join(','));

    t.log.info('=== 4. ties and numbers that are not numbers ===');
    post(fieldsFor({ 'RS256': 'x', 'ES384': 1, 'ES256': 1 }));
    t.equal(config.text(KEY), 'ES384,ES256,RS256',
            '4. a tie keeps the posted order; a number that is not one ' +
            'goes last');

    t.log.info('=== 5. ticking nothing is refused ===');
    const before = config.text(KEY);
    const empty = post(fieldsFor({}));
    t.check(empty.status === 400 &&
            /choose at least one/.test(empty.body) &&
            config.text(KEY) === before,
            '5. a save ticking nothing is refused and changes nothing',
            empty.status + ' ' + empty.body.slice(0, 200));

    t.log.info('=== 6. a value outside the list is refused ===');
    const outside = post(fieldsFor({ 'ES256': 1, 'NOT-AN-ALG': 2 }));
    t.check(outside.status === 400 && config.text(KEY) === before,
            '6. a value outside the closed list is refused by the ' +
            'setting\'s own check, and nothing changes',
            outside.status + ' ' + outside.body.slice(0, 200));

    t.log.info('=== 7. the shape a browser posts ===');
    const browser = post(fieldsFor({ 'PS256': 2, 'ML-DSA-44': 1 }), true);
    t.check(browser.status === 303 &&
            config.text(KEY) === 'ML-DSA-44,PS256',
            '7. a form-encoded save folds the same way and redirects back',
            browser.status + ' ' + config.text(KEY));
    t.check(String(browser.headers.location || '').indexOf('/admin/webauthn')
            === 0,
            '7. back to /admin/webauthn', browser.headers.location);
  } finally {
    config.clearOverride(KEY);
  }
  log.debug("Leaving runBody().");
}

module.exports = {
  name: 'ordered_choice_setting',
  describe: 'webauthn.algorithms as checkboxes and an order of preference ' +
            'on /admin/webauthn, folded into the setting on save',
  run: runBody
};
