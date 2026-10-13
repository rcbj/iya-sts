// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: portal_copy_codes.js
// ===========================================================================
// THE RECOVERY CODES' COPY BUTTON (#224), in process.
// rcbj: "Right now, the user must select and copy the displayed text. The
// resulting formatting is messed up." Since #568 the card is drawn in the
// browser by `portal/web_mfa.ts`, and the button is the portal runtime's —
// `/portal/copy.js` went with the server-rendered page. What is held here,
// against the card drawn for a freshly generated set:
//   A. THE BOX: the codes ONE PER LINE, in order, as the grid draws them, in
//      a read-only box — what a selection copies as drawn, and what is left
//      when the button cannot work.
//   B. THE BUTTON: hidden until the runtime reveals it, naming the box, and
//      no script on the card at all.
//   C. NO SET, NO BOX: a card with no fresh set has neither.
//   D. THE RUNTIME reveals the button and copies the named box's value and
//      nothing else (`PortalRuntime.wire()`, with stand-ins).
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'portal_copy_codes',
  level: process.env.LOG_LEVEL || 'info' });

// A translator that answers each key as itself: what is asserted here is the
// markup's shape, not its words.
const T = {
  html: function (key) {
    return key;
  },
  text: function (key) {
    return key;
  },
  has: function () {
    return true;
  },
  date: String,
  locale: 'en', lang: 'en', dir: 'ltr'
};

module.exports = {
  name: 'portal copy codes',
  describe: 'The recovery codes card (#224, #568): the codes one per line in ' +
            'a read-only box, a Copy button the portal runtime reveals, and ' +
            'no box without a fresh set',
  run: async function (t) {
    log.debug('Entering run().');
    const MfaPages = require('../portal/web_mfa');
    const PortalRuntime = require('../portal/web_portal_runtime');
    const codes = ['ABCD-2345-EFGH', 'JKMN-6789-PQRS', 'TUVW-2345-XYZA'];
    const card = MfaPages.codesCard({
      codes: { present: false, remaining: 0, total: 0, enabled: true },
      fresh: { codes: codes, handle: 'pcc-handle' } }, T);

    const box = (card.match(
      /<textarea id="recovery-codes-text" readonly[^>]*>([^<]*)<\/textarea>/) ||
      [])[1];
    t.check(box !== undefined &&
            JSON.stringify(box.split('\n')) === JSON.stringify(codes),
            'A1. the codes are in a read-only box, one per line, as drawn',
            JSON.stringify(box));
    t.check(/<button type="button" class="copybtn[^"]*" hidden data-copy-from="recovery-codes-text">/
              .test(card),
            'B1. a Copy button names the box, hidden until the runtime ' +
            'reveals it');
    t.check(!/<script\b/.test(card),
            'B2. there is no script on the card: the runtime is the script');

    const none = MfaPages.codesCard({
      codes: { present: true, usable: true, remaining: 5, total: 10,
               enabled: true } }, T);
    t.check(!/recovery-codes-text/.test(none) && !/data-copy/.test(none),
            'C1. a card with no fresh set has no box and no button');

    // D: the runtime's wiring, with a document of one box and one button.
    const listeners = {};
    const button = {
      hidden: true,
      getAttribute: function (name) {
        return name === 'data-copy-from' ? 'recovery-codes-text' : null;
      },
      addEventListener: function (type, fn) {
        listeners[type] = fn;
      }
    };
    const area = { value: codes.join('\n'), textContent: '' };
    let written = null;
    const runtime = new PortalRuntime({
      location: { pathname: '/portal/mfa', search: '', href:
                  'http://portal.test/portal/mfa', origin: 'http://portal.test' },
      navigator: { clipboard: { writeText: function (text) {
        written = text;
        return Promise.resolve();
      } } },
      window: {},
      document: {
        documentElement: { getAttribute: function () {
          return '';
        } },
        querySelectorAll: function () {
          return [button];
        },
        getElementById: function (id) {
          return id === 'recovery-codes-text' ? area : null;
        }
      }
    });
    runtime.wire();
    t.check(button.hidden === false && typeof listeners.click === 'function',
            'D1. the runtime reveals the button and listens to it');
    listeners.click({ preventDefault: function () {
      return undefined;
    } });
    t.equal(written, codes.join('\n'),
            'D2. a press copies the named box\'s value, and nothing else');
    log.debug('Leaving run().');
  }
};
