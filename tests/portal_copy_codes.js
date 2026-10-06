// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal_copy_codes.js
//
// ===========================================================================
// THE RECOVERY CODES' COPY BUTTON (#224), in process.
//
// rcbj: "Right now, the user must select and copy the displayed text. The
// resulting formatting is messed up." `portal/portal.ts` argues the design
// (the COPY_SCRIPT header). What is held here, against the card the portal
// draws for a freshly generated set:
//
//   A. THE BOX: the codes ONE PER LINE, in order, as the grid draws them, in
//      a read-only box — what a selection copies as drawn.
//   B. THE BUTTON: hidden until its script runs, naming the box, and the one
//      script loaded is /portal/copy.js.
//   C. NO SET, NO SCRIPT: a card with no fresh set has neither.
//   D. THE SCRIPT copies the named box's value and nothing else, and is
//      registered as one of the portal's paths (`sts_metadata.ts` reads it).
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'portal_copy_codes',
  level: process.env.LOG_LEVEL || 'info' });

module.exports = {
  name: 'portal copy codes',
  describe: 'The recovery codes card (#224): the codes one per line in a ' +
            'read-only box, a Copy button that script reveals, and no ' +
            'script without a fresh set',
  run: async function (t) {
    log.debug('Entering run().');
    const portalModule = require('../portal/portal');
    const backupCodes = require('../common/backup_codes');
    const Portal = portalModule.Portal;
    const portal = new Portal(Portal.defaultDeps());
    const session = { id: 'pcc-session', user: { username: 'pcc-user' } };
    const codes = ['abcd2345efgh', 'jkmn6789pqrs', 'tuvw2345xyza'];
    const card = portal.backupCodesCard(session,
      { ok: true, codes: codes, handle: 'pcc-handle' }, null,
      { backupCodes: { present: false, remaining: 0, total: 0 } });

    const box = (card.match(
      /<textarea id="recovery-codes-text" readonly[^>]*>([^<]*)<\/textarea>/) ||
      [])[1];
    const expected = codes.map(function (code) {
      return backupCodes.formatted(code);
    });
    t.check(box !== undefined &&
            JSON.stringify(box.split('\n')) === JSON.stringify(expected),
            'A1. the codes are in a read-only box, one per line, as drawn',
            JSON.stringify(box));
    t.check(/<button type="button" class="copybtn[^"]*" hidden data-copy-target="recovery-codes-text">Copy all codes<\/button>/
              .test(card),
            'B1. a Copy all codes button names the box, hidden until its ' +
            'script runs');
    t.check((card.match(/<script\b/g) || []).length === 1 &&
            /<script src="\/portal\/copy\.js"><\/script>/.test(card),
            'B2. the one script on the card is /portal/copy.js');

    const none = portal.backupCodesCard(session, null, null,
      { backupCodes: { present: true, remaining: 5, total: 10 } });
    t.check(!/<script\b/.test(none) && !/recovery-codes-text/.test(none),
            'C1. a card with no fresh set has no box and no script');

    let parses = true;
    try {
      // Parsed, never run: it reads a browser's document.
      new Function(portalModule.COPY_SCRIPT); // eslint-disable-line no-new-func
    } catch (e) {
      log.debug('Caught in run(): ' + e.message);
      parses = false;
    }
    t.check(parses && /getElementById/.test(portalModule.COPY_SCRIPT) &&
            /navigator\.clipboard/.test(portalModule.COPY_SCRIPT) &&
            !/fetch\(|XMLHttpRequest|sendBeacon/.test(portalModule.COPY_SCRIPT),
            'D1. the script parses, copies the named box, and sends nothing');
    t.check(portal.paths().indexOf('/portal/copy.js') >= 0,
            'D2. /portal/copy.js is one of the portal\'s registered paths');
    log.debug('Leaving run().');
  }
};
