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
// THE PAGE AND ITS FORM AS THE STATIC CONSOLE DRAWS AND SENDS THEM (#446):
// `GET /admin-api/protocol-settings`-style answer drawn by its renderer, and
// the form sent to the operation that mirrors it (`web_forms.ts`).
const consolePage = require('./tools/console_page')
  .consolePage(require('path').join(__dirname, '..'));
const WebForms = require('../admin-ui/web_forms');
const adminApi = require('../mgmt-api/admin_api');

const log = require('bunyan').createLogger({
  name: 'ordered_choice_setting',
  level: process.env.LOG_LEVEL || 'info' });

const KEY = 'webauthn.algorithms';

async function drawPage() {
  log.debug("Entering drawPage().");
  const drawn = await consolePage.draw('/admin/webauthn', {});
  log.debug("Leaving drawPage(). " + drawn.html.length + " character(s).");
  return drawn.html;
}

async function post(fields) {
  log.debug("Entering post().");
  const operation = WebForms.resolve(
    WebForms.table(adminApi.operationSummaries()), '/admin/config',
    fields.action);
  const answer = await consolePage.act(operation, fields);
  log.debug("Leaving post(). " + answer.status);
  return { status: answer.status,
           body: answer.text || JSON.stringify(answer.json || {}) };
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
    const saved = await post(fieldsFor({ 'ES256': 3, 'ML-DSA-65': 1,
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
    await post(fieldsFor({ 'RS256': 'x', 'ES384': 1, 'ES256': 1 }));
    t.equal(config.text(KEY), 'ES384,ES256,RS256',
            '4. a tie keeps the posted order; a number that is not one ' +
            'goes last');

    t.log.info('=== 5. ticking nothing is refused ===');
    const before = config.text(KEY);
    const empty = await post(fieldsFor({}));
    t.check(empty.status === 400 &&
            /choose at least one/.test(empty.body) &&
            config.text(KEY) === before,
            '5. a save ticking nothing is refused and changes nothing',
            empty.status + ' ' + empty.body.slice(0, 200));

    t.log.info('=== 6. a value outside the list is refused ===');
    const outside = await post(fieldsFor({ 'ES256': 1, 'NOT-AN-ALG': 2 }));
    t.check(outside.status === 400 && config.text(KEY) === before,
            '6. a value outside the closed list is refused by the ' +
            'setting\'s own check, and nothing changes',
            outside.status + ' ' + outside.body.slice(0, 200));

    // 7 WAS THE FORM-ENCODED BODY A BROWSER POSTED TO /admin/config AND
    // THE REDIRECT BACK: the static console sends every form as JSON to its
    // operation and draws the answer itself (#446), so there is no such
    // post or redirect to hold.
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
