// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/console_shell_parity.js
//
// ---------------------------------------------------------------------------
// THE CONSOLE'S FRAME, DRAWN FROM THE SHELL ANSWER, IS THE FRAME IT WAS
// (#446, 2026-10-05).
//
// `AdminConsole.page()` draws its frame through `web_shell.ts` from
// `shellJson()`, passed through JSON, so the static console can draw the same
// frame from `GET /admin-api/console`. `pageLegacy()` is the frame as it was
// drawn before, kept for exactly this comparison and deleted with the
// server-rendered console. What is held:
//
//   1. For every gate the frame has a sentence for — none, open, nobody
//      signed in, signed in with roles, a realm administrator, the window
//      closed — and with and without a drill-down's way up, the document is
//      byte for byte what `pageLegacy()` drew.
//   2. The same with a second trust realm, so the realm chooser is drawn.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const admin = require('../admin-ui/admin');
const realms = require('../common/realms');

const log = require('bunyan').createLogger({
  name: 'console_shell_parity',
  level: process.env.LOG_LEVEL || 'info' });

function fakeReq(url) {
  log.debug("Entering fakeReq().");
  const path = String(url || '/admin');
  const query = {};
  const cut = path.indexOf('?');
  if (cut >= 0) {
    new URLSearchParams(path.slice(cut + 1)).forEach(function (v, k) {
      query[k] = v;
    });
  }
  log.debug("Leaving fakeReq().");
  return { query: query, headers: { host: '127.0.0.1:8081' },
           method: 'GET', path: path.split('?')[0], url: path,
           originalUrl: path, protocol: 'http',
           get: function () { return ''; } };
}

const GATES = {
  'none given': undefined,
  'null': null,
  'the gate off': { enforced: false },
  'nobody signed in': { enforced: true, session: false },
  'signed in, both roles': { enforced: true, session: true,
                             username: 'alice', roles: ['read', 'write'],
                             write: true, authority: 'service' },
  'signed in, no role': { enforced: true, session: true, username: 'bob',
                          roles: [], write: false },
  'a realm administrator': { enforced: true, session: true,
                             username: 'carol', roles: ['read'],
                             authority: 'realm', identityRealm: 'default' },
  'open, roster empty': { enforced: true, session: true, username: 'dave',
                          open: true, readGroup: 'admins-read',
                          writeGroup: 'admins-write' },
  'closed': { enforced: true, session: true, username: 'erin',
              closed: true, windowOpens: false }
};

function compare(t, label) {
  log.debug("Entering compare().");
  const differing = [];
  let drawn = 0;
  Object.keys(GATES).forEach(function (name) {
    [null, { href: '/admin/users?q=a', label: 'Users', leaf: 'alice',
             filtered: true }].forEach(function (up) {
      ['/admin', '/admin/users?user=alice&notice=done'].forEach(function (url) {
        const req = fakeReq(url);
        const gate = GATES[name];
        const args = ['A page', url.split('?')[0], '<p>the body</p>', up,
                      gate, req];
        const a = admin.page.apply(null, args);
        const b = admin.pageLegacy.apply(null, args);
        drawn++;
        if (a !== b) {
          let at = 0;
          while (at < a.length && a[at] === b[at]) {
            at++;
          }
          differing.push(name + (up ? ' (drill-down)' : '') + ' ' + url +
                         ' at ' + at + ': …' + a.slice(at - 40, at + 60) +
                         ' | …' + b.slice(at - 40, at + 60));
        }
      });
    });
  });
  t.check(differing.length === 0,
          label + ' (' + drawn + ' frames)', differing.slice(0, 3).join(' ;; '));
  log.debug("Leaving compare().");
}

function run(t) {
  log.debug("Entering run().");
  compare(t, '1. the frame drawn from the shell answer is the frame it was');
  const id = 'shellparity' + process.pid;
  realms.create({ id: id, name: 'Shell parity' });
  compare(t, '2. and with a second realm, whose chooser is drawn');
  realms.remove(id);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'console shell parity',
  describe: 'AdminConsole.page() draws its frame through web_shell.ts from ' +
            'shellJson(), byte for byte the frame pageLegacy() draws',
  run: run
};
