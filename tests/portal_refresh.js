// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/portal_refresh.js
//
// ---------------------------------------------------------------------------
// THE PORTAL'S REFRESH BUTTON (#538), beside Sign out on every signed-in page.
// The portal runs no script, so it is a GET form, and `refreshForm()` decides
// what it reloads:
//
//   1. A GET OF THE PAGE'S OWN PATH reloads that path with the same query,
//      so a paged list comes back on the same page.
//   2. LESS `done`, the one-time message a redirect after a write carries.
//   3. A PAGE DRAWN IN ANSWER TO A POST loads its own path afresh, carrying
//      nothing of the request: repeating a write is what a Refresh button
//      must not do.
//   4. A REQUEST FOR ANOTHER PATH (a page drawn under a different name) and
//      NO REQUEST AT ALL load the page's path, with nothing carried.
//   5. A VALUE IS ESCAPED: a query a link put on the page cannot break out of
//      the attribute it is drawn into.
//   6. THE SHELL DRAWS IT beside Sign out, as a GET form and not a script.
//
// In process, through the portal's instance and `audit.withSource()`, which is
// how the request is ambient when a page is drawn.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const audit = require('../common/audit');
const portal = require('../portal/portal');

const log = require('bunyan').createLogger({ name: 'portal_refresh',
  level: process.env.LOG_LEVEL || 'info' });

const PAGE = portal.BASE + '/consents';

function drawn(method, url, active) {
  log.debug('Entering drawn(). ' + method + ' ' + url);
  const instance = new portal.Portal(portal.Portal.defaultDeps());
  const draw = function () {
    return instance.refreshForm(active || PAGE);
  };
  const html = method
    ? audit.withSource({ req: { method: method, url: url } }, draw)
    : draw();
  log.debug('Leaving drawn().');
  return html;
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
  const paged = drawn('GET', PAGE + '?page=3');
  t.check(/<form method="get" action="\/portal\/consents">/.test(paged) &&
          hidden(paged).page === '3' &&
          />Refresh<\/button><\/form>$/.test(paged),
          '1. a GET of the page reloads it with the same query', paged);
  const done = drawn('GET', PAGE + '?page=2&done=Withdrawn%3A%20x');
  t.check(hidden(done).page === '2' && !('done' in hidden(done)),
          '2. less done, the one-time message after a write', done);
  const post = drawn('POST', PAGE + '?page=4');
  t.check(Object.keys(hidden(post)).length === 0 &&
          /action="\/portal\/consents"/.test(post),
          '3. a page drawn for a POST loads its own path afresh', post);
  const other = drawn('GET', portal.BASE + '/keys?page=9');
  const none = drawn(null, '');
  t.check(Object.keys(hidden(other)).length === 0 &&
          Object.keys(hidden(none)).length === 0 &&
          /action="\/portal\/consents"/.test(none),
          '4. another path, or no request, loads the page\'s path with ' +
          'nothing carried', JSON.stringify([other, none]));
  const hostile = drawn('GET', PAGE + '?q=%22%3E%3Cscript%3E');
  t.check(hidden(hostile).q === '&quot;&gt;&lt;script&gt;' &&
          !/<script>/.test(hostile),
          '5. a value from the query is escaped', hostile);
  const instance = new portal.Portal(portal.Portal.defaultDeps());
  const page = audit.withSource({ req: { method: 'GET', url: PAGE } },
    function () {
      return instance.shell(PAGE, { id: 'portal-refresh-test',
                                    user: { username: 'refresh-tester' } },
                            null, null, '<div class="card"></div>');
    });
  t.check(/<div class="acts"><form method="get"[^]*Refresh<\/button><\/form>/
            .test(page) &&
          /Refresh<\/button><\/form><form method="post"[^>]*\/signout"/
            .test(page) &&
          !/<script/i.test(page),
          '6. the shell draws Refresh beside Sign out, with no script',
          page.slice(0, 600));
  log.debug('Leaving run().');
}

module.exports = {
  name: 'portal_refresh',
  describe: 'the portal\'s Refresh button (#538): a GET form reloading the ' +
            'page with its query, less done, and never repeating a POST',
  run: run
};
