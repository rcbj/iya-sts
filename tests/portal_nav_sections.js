// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/portal_nav_sections.js
//
// ---------------------------------------------------------------------------
// THE PORTAL'S NAVIGATION COLUMN BEHAVES AS THE CONSOLE'S SIDEBAR (#1229).
// The console's half is `tests/console_answers.js` G; this is the same set
// of claims about `portal/web_portal_shell.ts` and
// `portal/web_portal_runtime.ts`, and one that both draw a section from the
// one shared module, `common/web_nav_sections.ts`:
//   1. Every section is a `<details>` of one named group, its heading the
//      `<summary>`, and a caller that names no section draws all closed.
//   2. The section holding the page is marked `current` while closed, and
//      the page's own entry is still `aria-current`; a page UNDER a listed
//      one marks the section of the page it is under.
//   3. The section the reader opened is the one drawn open, on a page in
//      another section.
//   4. A runtime has chosen nothing until it draws; its first drawing opens
//      the section holding the page; a section the reader closed stays
//      closed, one they opened stays open on a page in another section,
//      and opening one closes the other where the browser does not.
//   5. The console and the portal draw a section with the same markup.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const PortalShell = require('../portal/web_portal_shell');
const PortalRuntime = require('../portal/web_portal_runtime');
const kit = require('../portal/web_portal_kit');
const WebShell = require('../admin-ui/web_shell');
const WebNavSections = require('../common/web_nav_sections');

const log = require('bunyan').createLogger({ name: 'portal_nav_sections',
  level: process.env.LOG_LEVEL || 'info' });

// A translator that answers each key as itself.
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
  locale: 'en', lang: 'en', dir: 'ltr'
};

const ME = { user: { username: 'nav-tester' }, locale: { offered: [] },
             version: { version: '0.0.0', buildInfo: '' } };

// Every `<details ...>` opening tag of the column, by its section's key.
function navSections(html) {
  log.debug('Entering navSections().');
  const found = {};
  const re = /<details class="navsec([^"]*)" name="([^"]*)" data-section="([^"]*)"([^>]*)>/g;
  let m = re.exec(html);
  while (m) {
    found[m[3]] = { current: / current/.test(m[1]), name: m[2],
                    open: / open/.test(m[4]) };
    m = re.exec(html);
  }
  log.debug('Leaving navSections().');
  return found;
}

// A stand-in for one section's `<details>`, enough for onNavToggle().
function fakeSection(key, open) {
  log.debug('Entering fakeSection().');
  const section = {
    open: open,
    classList: { contains: function (name) {
      return name === 'navsec';
    } },
    getAttribute: function (name) {
      return name === 'data-section' ? key : null;
    }
  };
  log.debug('Leaving fakeSection().');
  return section;
}

// The section keys in `NAV`, and a page in the first and in the last.
function layout() {
  log.debug('Entering layout().');
  const keys = kit.NAV.map(function (section) {
    return section.key;
  });
  const first = kit.NAV[0];
  const last = kit.NAV[kit.NAV.length - 1];
  const out = { keys: keys, first: first.key, last: last.key,
                firstPage: first.items[0].path,
                lastPage: last.items[0].path };
  log.debug('Leaving layout().');
  return out;
}

function frameOf(active, openSection) {
  log.debug('Entering frameOf().');
  const html = PortalShell.frame(ME, { active: active, query: {},
    message: '', error: '', cards: '<div class="card"></div>', prefix: '',
    t: T, openSection: openSection });
  log.debug('Leaving frameOf().');
  return html;
}

// A runtime over a document that records what is drawn and answers every
// query with nothing, and a view of the page at `path`.
function runtimeAt(path, open) {
  log.debug('Entering runtimeAt().');
  const body = {};
  const doc = {
    body: body,
    title: '',
    querySelectorAll: function (selector) {
      return selector === PortalShell.OPEN_SECTIONS
        ? open.filter(function (one) {
          return one.open;
        }) : [];
    },
    querySelector: function () {
      return null;
    },
    getElementById: function () {
      return null;
    }
  };
  const rt = new PortalRuntime({
    location: { pathname: path, search: '', hash: '', origin: 'https://x' },
    document: doc
  });
  rt.t = T;
  rt.me = ME;
  rt.view = { page: { path: path, render: function () {
    return '<div class="card"></div>';
  } }, json: {}, query: {} };
  log.debug('Leaving runtimeAt().');
  return { rt: rt, body: body };
}

function run(t) {
  log.debug('Entering run().');
  const l = layout();
  t.check(l.keys.length > 1, 'the portal has more than one section',
          l.keys.join(','));
  const fresh = frameOf(l.firstPage);
  const drawn = navSections(fresh);
  t.check(Object.keys(drawn).join(',') === l.keys.join(',') &&
          l.keys.every(function (key) {
            return drawn[key].name === PortalShell.NAV_GROUP &&
                   !drawn[key].open;
          }) && !/<p class="navhead"/.test(fresh) &&
          (fresh.match(/<summary class="navhead"/g) || []).length ===
            l.keys.length,
          '1. every section is a <details> of one named group, its heading ' +
          'the <summary>, and with none named none is open',
          JSON.stringify(drawn));
  t.check(drawn[l.first].current &&
          l.keys.filter(function (key) {
            return drawn[key].current;
          }).length === 1 &&
          /<span class="here" aria-current="page">/.test(fresh),
          '2. the closed section holding the page is marked current, and ' +
          'the page\'s own entry inside it still is', JSON.stringify(drawn));
  const under = navSections(frameOf(l.lastPage + '/somewhere'));
  t.check(l.lastPage === kit.BASE || under[l.last].current,
          '2a. a page under a listed one marks that page\'s section',
          JSON.stringify(under));
  t.check(PortalShell.sectionKeyOf(l.lastPage) === l.last &&
          PortalShell.sectionKeyOf('/elsewhere') === '',
          '2b. the section key is the one holding the page, and a page in ' +
          'none has none');
  const opened = navSections(frameOf(l.firstPage, l.last));
  t.check(opened[l.last].open && !opened[l.first].open &&
          opened[l.first].current && !opened[l.last].current,
          '3. the section the reader opened is the one drawn open, on a ' +
          'page in another section', JSON.stringify(opened));
  // THE RUNTIME'S HALF.
  const first = fakeSection(l.first, false);
  const last = fakeSection(l.last, false);
  const at = runtimeAt(l.firstPage, [first, last]);
  t.check(at.rt.openSection === null,
          '4. a runtime has not chosen a section yet',
          String(at.rt.openSection));
  at.rt.drawView();
  const reloaded = navSections(at.body.innerHTML);
  t.check(at.rt.openSection === l.first && reloaded[l.first].open &&
          !reloaded[l.last].open,
          '4a. the first drawing opens the section that holds the page',
          at.rt.openSection + ' ' + JSON.stringify(reloaded));
  at.rt.onNavToggle(fakeSection(l.first, false));
  at.rt.drawView();
  const stayed = navSections(at.body.innerHTML);
  t.check(at.rt.openSection === '' && !stayed[l.first].open &&
          !stayed[l.last].open,
          '4b. a section the reader closed stays closed on the next drawing',
          JSON.stringify(stayed));
  first.open = true;
  last.open = true;
  at.rt.onNavToggle(last);
  t.check(at.rt.openSection === l.last && !first.open && last.open,
          '4c. opening a section records it and closes the other where the ' +
          'browser did not', at.rt.openSection);
  at.rt.onNavToggle({ classList: { contains: function () {
    return false;
  } }, getAttribute: function () {
    return 'x';
  }, open: true });
  at.rt.drawView();
  const kept = navSections(at.body.innerHTML);
  t.check(at.rt.openSection === l.last && kept[l.last].open &&
          !kept[l.first].open && kept[l.first].current,
          '4d. a toggle of anything else changes nothing, and the open ' +
          'section stays open on a page in another', JSON.stringify(kept));
  // ONE MARKUP FOR BOTH.
  const shell = { gate: { session: true, username: 'alice' },
    sections: [{ title: 'Directory', what: 'People.',
                 items: [{ path: '/admin/users', label: 'Users' }] }],
    realm: { id: '', name: 'Default' }, navLabels: {}, version: {},
    persistence: {}, portalHref: '/portal', navAuthority: 'realm' };
  const consoleNav = WebShell.navBar(shell, { active: '/admin/users',
    openSection: 'directory' }, T);
  const shared = WebNavSections.section({ group: WebShell.NAV_GROUP,
    key: 'directory', current: true, open: true, what: 'People.',
    title: (/<summary[^>]*>([^<]*)<\/summary>/.exec(consoleNav) || [])[1],
    items: (/<ul>([^]*)<\/ul><\/details>/.exec(consoleNav) || [])[1] });
  const portalItems = (new RegExp('data-section="' + l.first +
    '"[^>]*>[^]*?<ul>([^]*?)</ul></details>').exec(fresh) || [])[1];
  const portalShared = WebNavSections.section({ group: PortalShell.NAV_GROUP,
    key: l.first, current: true, open: false,
    what: 'portal.section.' + l.first + '.what',
    title: 'portal.section.' + l.first + '.title', items: portalItems });
  t.check(consoleNav.indexOf(shared) > 0 && fresh.indexOf(portalShared) > 0,
          '5. the console and the portal both draw a section with the ' +
          'shared module\'s markup', consoleNav);
  log.debug('Leaving run().');
}

module.exports = {
  name: 'portal_nav_sections',
  describe: 'the portal\'s navigation column behaves as the console\'s ' +
            'sidebar (#1229): collapsible sections, one open at a time, ' +
            'the page\'s section opened on a fresh load, the reader\'s ' +
            'choice kept, from one shared module',
  run: run
};
