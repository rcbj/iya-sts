// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/self_issued_off_note.js
//
// ===========================================================================
// /portal/self-issued, WITH THE SELF-ISSUED SIGN-IN OFF, SAYS HOW TO TURN IT
// ON (#655). It said only that it was off.
//
//   1. THE VIEW (`PortalSelfIssued.view()`, over its own dependencies):
//      with the sign-in on, `turnOn` is null and nobody's roles are asked;
//      off, it names `oid4vp.signInSelfIssued` and the environment variable
//      `config.js`'s row declares, and says whether the person may change
//      it — with the console tab only where they may; a roster that throws,
//      or no roster at all, is "may not".
//   2. THE PAGE, through the English catalog: an administrator is shown the
//      setting, the variable and a link to `/admin/vc#vc-tab-oid4vp`;
//      anybody else is told to ask an administrator and is given no link;
//      with the sign-in on neither is drawn; what the view carries is
//      escaped.
//   3. THE ROSTER, in a CHILD with the whole stack (`admin_api_me.js`'s
//      reason: it writes rosters and realms every other file in `run.js`'s
//      process would meet): the production `mayConfigure()` answers Admin
//      Write in the realm the request is in — a writer yes, a reader and a
//      stranger no, a realm's own administrator yes in that realm and the
//      default realm's writer no there — and a realm administrator may
//      write this setting at all (`admin_scope.ts`).
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'self_issued_off_note',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const KEY = 'oid4vp.signInSelfIssued';
const PAGE = '/admin/vc#vc-tab-oid4vp';

// The environment variable `config.js`'s row declares for the setting, read
// from the source so the view cannot name one the row does not.
function declaredEnv() {
  log.debug("Entering declaredEnv().");
  const source = fs.readFileSync(path.join(ROOT, 'common', 'config.js'),
                                 'utf8');
  const m = /key: 'oid4vp\.signInSelfIssued'[\s\S]*?env: '([A-Z0-9_]+)'/
    .exec(source);
  log.debug("Leaving declaredEnv().");
  return m ? m[1] : null;
}

// A translator over the English portalSelfIssued catalog, built as the
// browser's `WebI18n` builds one (`report_query.js`'s arrangement).
function englishTranslator() {
  log.debug("Entering englishTranslator().");
  const messages = require('../common/web_messages');
  const own = JSON.parse(fs.readFileSync(path.join(ROOT, 'common', 'locales',
    'portalSelfIssued', 'en.json'), 'utf8'));
  const flat = {};
  Object.keys(own).forEach(function (key) {
    flat['portalSelfIssued.' + key] = own[key];
  });
  log.debug("Leaving englishTranslator().");
  return messages.WebTranslator.fromData({ catalogs: { en: flat },
    negotiated: { locale: 'en', chain: ['en'], catalog: 'en',
                  direction: 'ltr', matched: true } });
}

// The page's class over stubs: the sign-in `on` or not, and `mayConfigure`
// as given (left out when undefined). `asked` counts the roster's calls.
function pageOver(on, mayConfigure, asked) {
  log.debug("Entering pageOver().");
  const PortalSelfIssued =
    require('../portal/portal_self_issued').PortalSelfIssued;
  const deps = {
    log: { debug: function () {} },
    config: { value: function (key) {
      return key === KEY ? on : false;
    } },
    siop: { PROOF_ADMIN: 'admin', locationOf: function () {
      return null;
    }, list: function () {
      return [];
    } }
  };
  if (mayConfigure !== undefined) {
    deps.mayConfigure = function (name) {
      asked.push(name);
      return mayConfigure(name);
    };
  }
  log.debug("Leaving pageOver().");
  return new PortalSelfIssued(deps);
}

// ---------------------------------------------------------------------------
// 1. THE VIEW.
// ---------------------------------------------------------------------------
function viewSections(t) {
  log.debug("Entering viewSections().");
  const env = declaredEnv();
  t.check(env === 'OID4VP_SIGN_IN_SELF_ISSUED',
          '1a. config.js declares the setting\'s environment variable', env);

  let asked = [];
  const on = pageOver(true, function () {
    return true;
  }, asked).view('alice');
  t.check(on.enabled === true && on.turnOn === null && asked.length === 0,
          '1b. with the sign-in on, turnOn is null and no roster is asked',
          JSON.stringify(on.turnOn) + ' asked ' + asked.length);

  asked = [];
  const admin = pageOver(false, function (name) {
    return name === 'alice';
  }, asked).view('alice');
  t.check(admin.enabled === false && admin.turnOn &&
          admin.turnOn.setting === KEY && admin.turnOn.env === env &&
          admin.turnOn.administrator === true && admin.turnOn.page === PAGE &&
          asked.length === 1 && asked[0] === 'alice',
          '1c. off, for a person who may change it: the setting, its ' +
          'variable, and the console tab', JSON.stringify(admin.turnOn));

  asked = [];
  const other = pageOver(false, function (name) {
    return name === 'alice';
  }, asked).view('bob');
  t.check(other.turnOn && other.turnOn.setting === KEY &&
          other.turnOn.env === env && other.turnOn.administrator === false &&
          other.turnOn.page === null,
          '1d. off, for anybody else: the setting, and no console page',
          JSON.stringify(other.turnOn));

  const throws = pageOver(false, function () {
    throw new Error('the roster is not readable');
  }, []).view('alice');
  t.check(throws.turnOn && throws.turnOn.administrator === false &&
          throws.turnOn.page === null,
          '1e. a roster that throws is "may not"',
          JSON.stringify(throws.turnOn));

  const none = pageOver(false, undefined, []).view('alice');
  t.check(none.turnOn && none.turnOn.administrator === false &&
          none.turnOn.page === null,
          '1f. no roster at all is "may not"', JSON.stringify(none.turnOn));
  log.debug("Leaving viewSections().");
}

// ---------------------------------------------------------------------------
// 2. THE PAGE.
// ---------------------------------------------------------------------------
function pageSections(t) {
  log.debug("Entering pageSections().");
  const SelfIssuedPages = require('../portal/web_self_issued');
  const tr = englishTranslator();
  const ctx = { t: tr, query: {} };
  const env = declaredEnv();
  const off = tr.text('portalSelfIssued.off');

  const admin = SelfIssuedPages.render({ enabled: false, subjects: [],
    turnOn: { setting: KEY, env: env, administrator: true, page: PAGE } },
    ctx);
  t.check(admin.indexOf('id="siop-off"') >= 0 &&
          admin.indexOf('id="siop-turn-on"') >= 0 &&
          admin.indexOf('<code>' + KEY + '</code>') >= 0 &&
          admin.indexOf('<code>' + env + '</code>') >= 0 &&
          admin.indexOf('<a href="' + PAGE + '">') >= 0 &&
          admin.indexOf("Open the console's OpenID4VP settings.") >= 0 &&
          admin.indexOf('id="siop-ask-admin"') < 0,
          '2a. an administrator is shown the setting, the variable and the ' +
          'link to the OpenID4VP settings tab', admin);

  const other = SelfIssuedPages.render({ enabled: false, subjects: [],
    turnOn: { setting: KEY, env: env, administrator: false, page: null } },
    ctx);
  t.check(other.indexOf('id="siop-ask-admin"') >= 0 &&
          other.indexOf('ask an administrator') >= 0 &&
          other.indexOf('<code>' + KEY + '</code>') >= 0 &&
          other.indexOf('/admin/') < 0 &&
          other.indexOf('id="siop-turn-on"') < 0,
          '2b. anybody else is told to ask an administrator, with no link',
          other);

  const lying = SelfIssuedPages.render({ enabled: false, subjects: [],
    turnOn: { setting: KEY, env: env, administrator: false, page: PAGE } },
    ctx);
  t.check(lying.indexOf('/admin/') < 0,
          '2c. a page without `administrator` draws no link, whatever ' +
          '`page` says', lying);

  const on = SelfIssuedPages.render({ enabled: true, subjects: [],
                                      turnOn: null }, ctx);
  t.check(on.indexOf('id="siop-off"') < 0 &&
          on.indexOf('id="siop-turn-on"') < 0 &&
          on.indexOf('id="siop-ask-admin"') < 0 &&
          on.indexOf('id="siop-enrol"') >= 0,
          '2d. with the sign-in on, neither note is drawn', on);

  const before = SelfIssuedPages.render({ enabled: false, subjects: [] },
                                        ctx);
  t.check(before.indexOf(off.slice(0, 30)) >= 0 &&
          before.indexOf('siop-turn-on') < 0 &&
          before.indexOf('siop-ask-admin') < 0,
          '2e. a view without `turnOn` still says it is off, and no more',
          before);

  const hostile = SelfIssuedPages.render({ enabled: false, subjects: [],
    turnOn: { setting: '<b>x</b>', env: '"><i>', administrator: true,
              page: '"><script>x</script>' } }, ctx);
  t.check(hostile.indexOf('<b>x</b>') < 0 &&
          hostile.indexOf('<script>') < 0 && hostile.indexOf('<i>') < 0,
          '2f. what the view carries is escaped', hostile);
  log.debug("Leaving pageSections().");
}

// ---------------------------------------------------------------------------
// 3. THE ROSTER, in a child.
// ---------------------------------------------------------------------------
function childMain() {
  const ROOT_DIR = process.env.SO_ROOT;
  const OUT = process.env.SO_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const adminScope = require(ROOT_DIR + '/admin-ui/admin_scope');
    const PortalSelfIssued =
      require(ROOT_DIR + '/portal/portal_self_issued').PortalSelfIssued;
    const may = PortalSelfIssued.defaultDeps().mayConfigure;

    const stamp = String(process.pid);
    const WRITER = 'so-writer-' + stamp;
    const READER = 'so-reader-' + stamp;
    const BOSS = 'so-boss-' + stamp;
    const R = 'so' + stamp;
    [WRITER, READER].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    inDefault(function () {
      rbac.grant(WRITER, 'write', { via: 'test' });
      rbac.grant(READER, 'read', { via: 'test' });
    });
    realms.create({ id: R, name: 'The self-issued note' });
    // The realm's administrator is a person IN THAT REALM (2026-11-11): a
    // console role is granted only to somebody with an entry there
    // (STS-ADMIN-0920).
    realms.run(realms.get(R), function () {
      ldap.createUser(BOSS, { invent: false });
    });
    const bossGrant = rbac.grant(BOSS, 'write', { via: 'test', realm: R });
    note(bossGrant && bossGrant.ok, 'precondition: a realm with an ' +
         'administrator of its own', JSON.stringify(bossGrant));

    note(typeof may === 'function',
         '3a. the production dependencies carry mayConfigure');
    note(inDefault(function () {
      return may(WRITER);
    }) === true, '3b. Admin Write in the realm: may');
    note(inDefault(function () {
      return may(READER);
    }) === false, '3c. Admin Read only: may not');
    note(inDefault(function () {
      return may('so-nobody-' + stamp);
    }) === false, '3d. a person holding no role: may not');
    const inR = function (fn) {
      return realms.run(realms.get(R), fn);
    };
    note(inR(function () {
      return may(BOSS);
    }) === true, '3e. a realm\'s own administrator, in that realm: may');
    note(inR(function () {
      return may(WRITER);
    }) === false, '3f. the default realm\'s writer, in another realm: ' +
         'may not (that realm\'s roster is asked)');
    const serviceOnly =
      adminScope.settingIsServiceOnly('oid4vp.signInSelfIssued');
    note(serviceOnly === false, '3g. a realm administrator may write ' +
         'oid4vp.signInSelfIssued', String(serviceOnly));

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && (e.stack || e.message));
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function rosterSections(t) {
  log.debug("Entering rosterSections().");
  const out = path.join(os.tmpdir(), 'so-' + process.pid + '-' + Date.now() +
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
                                  SO_ROOT: ROOT, SO_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in rosterSections(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in rosterSections(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving rosterSections().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving rosterSections().");
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== 1. the view ===');
  viewSections(t);
  t.log.info('=== 2. the page ===');
  pageSections(t);
  t.log.info('=== 3. the roster ===');
  rosterSections(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'self_issued_off_note',
  describe: '/portal/self-issued with the self-issued sign-in off names ' +
            'the setting, links an administrator to the console tab that ' +
            'turns it on, and tells anybody else to ask one (#655)',
  run: run
};
