// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'fga_pep_grant',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: fga_pep_grant.js
//
// ===========================================================================
// ENABLING FINE-GRAINED AUTHORIZATION GRANTS THE REALM'S REMOTE PEPS
// (#1210, rcbj's decision of 2026-10-30).
//
// A remote PEP's edge PDP forwards an evaluation about an application that
// enforces FGA to `/access/v1` (#564, P7), as an AuthZEN caller: its entry
// needs AUTHZEN_PEPS (membership of `roles.authzenPepGroup`) and the
// application in its scope. Enabling grants both, where missing, to every
// holder of REMOTE_PEPS (the members of `roles.remotePepGroup`). What this
// file holds, each a lettered section:
//
//   E. THE ENABLE, through the console's and the API's one door
//      (`applicationsAction`, `fga-enable`): a person, a service account
//      and an application holding REMOTE_PEPS are granted — membership and
//      scope, each read back the way the AuthZEN checks read it; a holder
//      that had both is `held` and nothing is doubled; a holder whose
//      write the directory refuses, and a member naming no entry, are
//      `failed` with STS-FGA-0025 while the enable succeeds and the others
//      are granted; the answer's message says all of it.
//   A. THE AUDIT: one `admin.authzen.pep.granted` row per holder changed,
//      and one carrying STS-FGA-0025 per holder that was not.
//   D. DISABLE removes nothing.
//   L. A LATER HOLDER is not granted retroactively; the tab's view shows it
//      without; re-enabling grants it, and so does enable on an
//      application that already enforces.
//   T. THE TAB draws each holder, and the re-grant only while enforcing.
//
// In process, in a THROWAWAY REALM, as `fga_console.js` is.
// ===========================================================================

delete process.env.CONFIG_FILE;

const APP = 'fgag-rs';

function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  require('../common/app');
  const ldap = require('../ldap/ldap_server');
  // A renderer given no translator draws node's default, which
  // common/i18n.ts installs (#539) — English.
  require('../common/i18n');
  const realms = require('../common/realms');
  const errorCodes = require('../common/error_codes');
  const applications = require('../common/applications');
  const audit = require('../common/audit');
  const serviceAccounts = require('../common/service_accounts');
  const authzenAdmin = require('../authzen/authzen_admin');
  // Loading it builds its default instance and fills the lifecycle slot.
  const fga = require('../xacml/fga_policies');
  const adminActions = require('../admin-core/admin_actions');

  const id = 'fgag-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'a trust realm to work in', (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving run(). No realm.");
    return;
  }
  const k = {
    config: config, ldap: ldap, errorCodes: errorCodes,
    applications: applications, audit: audit, fga: fga,
    serviceAccounts: serviceAccounts, authzenAdmin: authzenAdmin,
    remoteGroup: String(config.value('roles.remotePepGroup')),
    authzenGroup: String(config.value('roles.authzenPepGroup')),
    inRealm: function (fn) {
      log.debug("Entering inRealm().");
      log.debug("Leaving inRealm().");
      return realms.run(made.realm, fn);
    },
    act: function (action) {
      log.debug("Entering act().");
      log.debug("Leaving act().");
      return realms.run(made.realm, function () {
        return adminActions.applicationsAction({ action: action,
                                                 application: APP,
                                                 actor: 'test' });
      });
    }
  };
  try {
    k.inRealm(function () {
      log.debug("Entering setUp().");
      setUp(t, k);
      log.debug("Leaving setUp().");
    });
    sectionE(t, k);
    sectionA(t, k);
    sectionD(t, k);
    sectionL(t, k);
    sectionT(t, k);
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

// The holders: a person, a service account, an application, one that holds
// both already, one whose write will be refused, and a dangling member.
function setUp(t, k) {
  log.debug("Entering setUp().");
  const { ldap, applications, serviceAccounts } = k;
  const groupDn = ldap.groupDnFor(k.remoteGroup);
  if (!ldap.readGroupEntry(groupDn)) {
    ldap.createGroup(k.remoteGroup, {});
  }
  if (!ldap.readGroupEntry(ldap.groupDnFor(k.authzenGroup))) {
    ldap.createGroup(k.authzenGroup, {});
  }
  ['fgag-person', 'fgag-svc', 'fgag-held', 'fgag-refused']
    .forEach(function (name) {
      ldap.createUser(name, { invent: false });
      ldap.addGroupMember(k.remoteGroup, name, { actor: 'test' });
    });
  serviceAccounts.set('fgag-svc', { serviceAccount: true,
                                    owners: ['fgag-person'] });
  const created = applications.createApplication({
    identifier: APP, name: 'FGA grant resource', protocols: ['oauth2'] });
  t.check(created.ok, 'the enforcing application is created',
          (created.errors || []).join(' '));
  applications.createApplication({ identifier: 'fgag-pep-app',
                                   protocols: ['oauth2'] });
  const pepApp = applications.get('fgag-pep-app');
  ldap.addGroupMember(k.remoteGroup, pepApp.dn, { actor: 'test' });
  // ONE THAT HOLDS BOTH ALREADY, its scope naming another application too,
  // which the grant must neither double nor drop.
  ldap.addGroupMember(k.authzenGroup, 'fgag-held', { actor: 'test' });
  k.authzenAdmin.act({ action: 'set-scope', caller: 'fgag-held',
                       applications: ['other-app', APP] },
                     { actor: 'test', via: 'test' });
  ldap.addGroupMember(k.remoteGroup,
                      'cn=fgag-ghost,' + ldap.usersDn(), { actor: 'test' });
  log.debug("Leaving setUp().");
}

// The names in one list of the answer that this file made: in development
// mode the realm also seeds `cn=remote-pep-1` into the group, and it is
// granted beside them.
function namesOf(list) {
  log.debug("Entering namesOf().");
  log.debug("Leaving namesOf().");
  return (list || []).map(function (one) {
    return String(one.name);
  }).filter(function (name) {
    return /^fgag-/.test(name);
  }).sort();
}

// E. The enable.
function sectionE(t, k) {
  log.debug("Entering sectionE().");
  t.log.info('=== E. enable grants the realm\'s remote PEPs ===');
  // A DIRECTORY THAT REFUSES ONE HOLDER'S WRITE: the slot's own hooks,
  // wrapped for one DN and put back after.
  const hooks = k.authzenAdmin.directoryHooks();
  const refusedDn = k.inRealm(function () {
    return k.ldap.locateEntry('fgag-refused').stored.dn;
  });
  const write = hooks.write;
  hooks.write = function (dn, name, values) {
    if (String(dn).toLowerCase() === String(refusedDn).toLowerCase()) {
      return false;
    }
    return write(dn, name, values);
  };
  let r = null;
  try {
    r = k.act('fga-enable');
  } finally {
    hooks.write = write;
  }
  t.check(r && r.ok && r.enforced === true,
          'E1. the enable succeeds although two holders could not be granted',
          JSON.stringify(r && (r.errors || r.peps)));
  const peps = (r && r.peps) || {};
  t.equal(namesOf(peps.granted).join(),
          ['fgag-pep-app', 'fgag-person', 'fgag-svc'].join(),
          'E2. a person, a service account and an application are granted');
  t.check((peps.granted || []).every(function (one) {
    return one.member === true && one.scope === true;
  }), 'E3. each was given both: membership and the scope',
          JSON.stringify(peps.granted));
  t.check((peps.granted || []).some(function (one) {
    return one.name === 'fgag-svc' && one.kind === 'service-account';
  }) && (peps.granted || []).some(function (one) {
    return one.name === 'fgag-pep-app' && one.kind === 'application';
  }), 'E4. each holder is answered with its kind',
          JSON.stringify(peps.granted));
  t.equal(namesOf(peps.held).join(), 'fgag-held',
          'E5. the holder that had both is held');
  const failed = (peps.failed || []).filter(function (one) {
    return /fgag-/.test(String(one.name));
  });
  t.check(failed.length === 2 && failed.every(function (one) {
    return one.code === 'STS-FGA-0025' && !!one.why;
  }) && failed.some(function (one) {
    return one.name === 'fgag-refused' &&
           /could not be written/.test(one.why) &&
           /which is kept/.test(one.why);
  }) && failed.some(function (one) {
    return /fgag-ghost/.test(one.name) &&
           /names no person, service account or application/.test(one.why);
  }), 'E6. the refused write and the dangling member are failed, each ' +
     'with STS-FGA-0025 and why', JSON.stringify(failed));
  t.check(/Granted the remote PEP\(s\)/.test(r.message) &&
          /Already held: fgag-held/.test(r.message) &&
          /Not granted: fgag-refused \(STS-FGA-0025\)/.test(r.message),
          'E7. the answer\'s message names who was granted, who held it ' +
          'and who could not be', r && r.message);

  const read = k.inRealm(function () {
    return {
      person: k.authzenAdmin.callerOf('fgag-person'),
      svc: k.authzenAdmin.callerOf('fgag-svc'),
      app: k.authzenAdmin.callerOf('fgag-pep-app'),
      held: k.authzenAdmin.callerOf('fgag-held'),
      refused: k.authzenAdmin.callerOf('fgag-refused')
    };
  });
  t.check(['person', 'svc', 'app'].every(function (key) {
    const one = read[key] || {};
    return one.member === true && one.applications.indexOf(APP) >= 0;
  }), 'E8. read back as the AuthZEN tab reads a caller: each granted ' +
     'holder is in the group with the application in its scope ' +
     '(stsAuthzenApplication, appAuthzenApplication)', JSON.stringify(read));
  t.equal((read.held || {}).applications.join(), ['other-app', APP].join(),
          'E9. the held holder\'s scope is neither doubled nor narrowed');
  t.check((read.refused || {}).member === true &&
          (read.refused || {}).applications.indexOf(APP) < 0,
          'E10. the refused holder kept the membership it was given and ' +
          'has no scope', JSON.stringify(read.refused));
  // The class itself, over its real dependencies: the module exports no
  // instance, and scopeOf() is what a request's scope check calls.
  const Caller = require('../authzen/authzen_caller').AuthzenCaller;
  const caller = new Caller(Caller.defaultDeps());
  const scope = k.inRealm(function () {
    return caller.scopeOf({ kind: 'entry',
                            name: read.person ? read.person.dn : '',
                            identifier: '', clientId: '', roles: [] });
  });
  t.check(scope.indexOf(APP) >= 0,
          'E11. and the AuthZEN caller check reads the person\'s scope ' +
          'with the application in it', JSON.stringify(scope));
  log.debug("Leaving sectionE().");
}

// A. The audit rows.
function sectionA(t, k) {
  log.debug("Entering sectionA().");
  t.log.info('=== A. one audit row per holder ===');
  const rows = k.inRealm(function () {
    return k.audit.list().filter(function (event) {
      return event.action === 'admin.authzen.pep.granted' &&
             // THE HOLDER'S OWN RDN, since the realm's suffix carries the
             // prefix too: the seeded cn=remote-pep-1 is left out.
             /^(uid|cn)=fgag-/.test(String(event.target || ''));
    });
  });
  const ok = rows.filter(function (row) {
    return !row.errorCode;
  });
  const bad = rows.filter(function (row) {
    return row.errorCode === 'STS-FGA-0025';
  });
  t.check(ok.length === 3 && ok.every(function (row) {
    return /granted the remote PEP/.test(JSON.stringify(row)) &&
           JSON.stringify(row).indexOf(APP) >= 0;
  }), 'A1. one admin.authzen.pep.granted row per holder changed, naming ' +
     'the application', ok.length + ' row(s): ' + ok.map(function (row) {
       return row.target;
     }).join(' | '));
  t.equal(bad.length, 2,
          'A2. and one carrying STS-FGA-0025 per holder that was not');
  log.debug("Leaving sectionA().");
}

// D. Disable removes nothing.
function sectionD(t, k) {
  log.debug("Entering sectionD().");
  t.log.info('=== D. disable removes nothing ===');
  const r = k.act('fga-disable');
  t.check(r.ok && r.enforced === false, 'D1. disable is done',
          JSON.stringify(r.errors));
  const person = k.inRealm(function () {
    return k.authzenAdmin.callerOf('fgag-person');
  }) || {};
  t.check(person.member === true && person.applications.indexOf(APP) >= 0,
          'D2. the granted membership and scope are kept',
          JSON.stringify(person));
  log.debug("Leaving sectionD().");
}

// L. A later holder.
function sectionL(t, k) {
  log.debug("Entering sectionL().");
  t.log.info('=== L. a later holder, granted by the next enable ===');
  k.inRealm(function () {
    k.ldap.createUser('fgag-later', { invent: false });
    k.ldap.addGroupMember(k.remoteGroup, 'fgag-later', { actor: 'test' });
  });
  const later = function () {
    log.debug("Entering later().");
    log.debug("Leaving later().");
    return k.inRealm(function () {
      return k.authzenAdmin.callerOf('fgag-later');
    }) || {};
  };
  t.check(later().member === false && later().applications.length === 0,
          'L1. not granted retroactively', JSON.stringify(later()));
  const view = k.inRealm(function () {
    return k.fga.state(APP).peps;
  }) || {};
  const row = (view.holders || []).filter(function (one) {
    return one.name === 'fgag-later';
  })[0] || {};
  t.check(row.member === false && row.scoped === false &&
          view.group === k.remoteGroup &&
          view.authzenGroup === k.authzenGroup && view.unlocated === 1,
          'L2. the tab\'s view lists it without either, beside the groups ' +
          'and the dangling member', JSON.stringify(view));
  const again = k.act('fga-enable');
  // The holder whose write was refused in E is granted now too: the
  // directory takes its write this time, and re-enabling is the retry.
  t.check(again.ok &&
          namesOf(again.peps.granted).join() ===
            ['fgag-later', 'fgag-refused'].join() &&
          later().member === true &&
          later().applications.indexOf(APP) >= 0,
          'L3. re-enabling grants it, and retries the holder that failed ' +
          'in E, and nobody else',
          JSON.stringify(again.peps));
  t.check(namesOf(again.peps.held).indexOf('fgag-person') >= 0,
          'L4. those granted before are held now');
  k.inRealm(function () {
    k.ldap.createUser('fgag-later-2', { invent: false });
    k.ldap.addGroupMember(k.remoteGroup, 'fgag-later-2', { actor: 'test' });
  });
  const enforcing = k.act('fga-enable');
  t.check(enforcing.ok && enforcing.enforced === true &&
          namesOf(enforcing.peps.granted).join() === 'fgag-later-2',
          'L5. enable on an application that already enforces re-runs the ' +
          'grant', JSON.stringify(enforcing.peps));
  log.debug("Leaving sectionL().");
}

// T. The tab.
function sectionT(t, k) {
  log.debug("Entering sectionT().");
  t.log.info('=== T. the tab draws the remote PEPs ===');
  const kit = require('../admin-ui/web_kit');
  const page = require('../admin-ui/web_applications');
  const ctx = kit.context({}, true);
  const peps = k.inRealm(function () {
    return k.fga.state(APP).peps;
  });
  const html = page.applicationFgaPeps(ctx, peps, '<form>regrant</form>');
  t.check(html.indexOf('id="fga-peps"') >= 0 &&
          html.indexOf('fgag-person') >= 0 &&
          html.indexOf('fgag-pep-app') >= 0 &&
          html.indexOf('<form>regrant</form>') >= 0 &&
          html.indexOf('href="/admin/xacml/authzen"') >= 0,
          'T1. each holder is drawn, linked to the AuthZEN tab, with the ' +
          're-grant', html.slice(0, 400));
  t.check(page.applicationFgaPeps(ctx, null, '')
    .indexOf('id="fga-peps"') >= 0,
          'T2. a view that could not be read is drawn as unknown');
  log.debug("Leaving sectionT().");
}

module.exports = {
  name: 'fga pep grant',
  describe: 'enabling fine-grained authorization grants the realm\'s ' +
            'remote PEPs AUTHZEN_PEPS and the application in their scope ' +
            '(#1210): holder kinds, held, failures, audit, disable keeps, ' +
            're-enable grants a later holder, the tab',
  run: run
};
