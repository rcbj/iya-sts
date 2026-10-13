// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/portal_refresh.js
//
// ---------------------------------------------------------------------------
// THE PORTAL'S REFRESH BUTTON (#538), beside Sign out on every signed-in page.
// Since #568 the frame is drawn in the browser (`portal/web_portal_shell.ts`)
// and Refresh is a GET form the runtime answers by asking the page's
// operation again. What it carries is still decided by one rule:
//   1. THE PAGE'S OWN PATH with its paging parameters, so a paged list comes
//      back on the same page.
//   2. LESS `done` — and there is no `done` any more: a write's message is
//      held by the runtime and drawn once, never on the URL.
//   3. (A page drawn in answer to a POST no longer exists: an act's answer is
//      drawn in place, and the page's own query is what Refresh carries.)
//   5. A VALUE IS ESCAPED: a query a link put on the page cannot break out of
//      the attribute it is drawn into.
//   6. THE FRAME DRAWS IT beside Sign out, as a GET form, with no script.
//   7. ONLY THE PARAMETERS A PAGE READS are carried — paging and the step
//      markers — so `?user=somebody` on the URL is not drawn back
//      (sts_portal_sessions' cross-account check).
//   8. THE LANGUAGE CHOOSER (#539) RETURNS WITH THE SAME PARAMETERS, not the
//      URL's whole query.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const PortalShell = require('../portal/web_portal_shell');

const log = require('bunyan').createLogger({ name: 'portal_refresh',
  level: process.env.LOG_LEVEL || 'info' });

const PAGE = '/portal/consents';

// A translator that answers each key as itself, and English for the two
// words the assertions read.
const T = {
  html: function (key) {
    return key === 'portal.shell.refresh' ? 'Refresh'
      : (key === 'portal.shell.signOut' ? 'Sign out' : key);
  },
  text: function (key) {
    return key;
  },
  has: function () {
    return true;
  },
  locale: 'en', lang: 'en', dir: 'ltr'
};

function queryOf(search) {
  log.debug('Entering queryOf().');
  const out = {};
  new URLSearchParams(search).forEach(function (value, name) {
    out[name] = value;
  });
  log.debug('Leaving queryOf().');
  return out;
}

function hidden(html) {
  log.debug('Entering hidden().');
  const out = {};
  const re = /<input type="hidden" name="([^"]*)" value="([^"]*)">/g;
  let m;
  while ((m = re.exec(html)) !== null) {
    out[m[1]] = m[2];
  }
  log.debug('Leaving hidden().');
  return out;
}

function run(t) {
  log.debug('Entering run().');
  const paged = PortalShell.refreshForm(PAGE, queryOf('page=3'), T);
  t.check(/<form method="get" action="\/portal\/consents">/.test(paged) &&
          hidden(paged).page === '3' &&
          />Refresh<\/button><\/form>$/.test(paged),
          '1. Refresh reloads the page with its paging query', paged);
  const done = PortalShell.refreshForm(PAGE,
    queryOf('page=2&done=Withdrawn%3A%20x'), T);
  t.check(hidden(done).page === '2' && !('done' in hidden(done)),
          '2. a `done` on the URL is not carried', done);
  const hostile = PortalShell.refreshForm(PAGE,
    queryOf('stepup=%22%3E%3Cscript%3E'), T);
  t.check(hidden(hostile).stepup === '&quot;&gt;&lt;script&gt;' &&
          !/<script>/.test(hostile),
          '5. a value from the query is escaped', hostile);
  const foreign = PortalShell.refreshForm(PAGE,
    queryOf('page=2&user=somebody-else&q=x&grantsPage=4'), T);
  t.check(hidden(foreign).page === '2' &&
          hidden(foreign).grantsPage === '4' &&
          !('user' in hidden(foreign)) && !('q' in hidden(foreign)) &&
          foreign.indexOf('somebody-else') < 0,
          '7. a parameter no portal page reads is not carried, so a name ' +
          'a link put on the URL is not drawn back', foreign);
  const me = { user: { username: 'refresh-tester' },
               locale: { offered: [{ tag: 'en', name: 'English' }] },
               version: { version: '0.0.0', buildInfo: '' } };
  const page = PortalShell.frame(me, { active: PAGE,
    query: queryOf('page=2&user=somebody-else'), message: '', error: '',
    cards: '<div class="card"></div>', prefix: '', t: T });
  const back = (/name="return" value="([^"]*)"/.exec(page) || [])[1];
  t.check(back === PAGE + '?page=2' && page.indexOf('somebody-else') < 0,
          '8. the language chooser returns with the same parameters, and ' +
          'never with one no page reads', String(back));
  t.check(/<div class="acts"><form method="get"[^]*Refresh<\/button><\/form>/
            .test(page) &&
          /Refresh<\/button><\/form><form method="post"[^>]*\/signout"/
            .test(page) &&
          !/<script/i.test(page),
          '6. the frame draws Refresh beside Sign out, with no script',
          page.slice(0, 600));
  log.debug('Leaving run().');
}

module.exports = {
  name: 'portal_refresh',
  describe: 'the portal\'s Refresh button (#538, #568): a GET form ' +
            'reloading the page with the parameters it reads, and nothing ' +
            'else',
  run: run
};
