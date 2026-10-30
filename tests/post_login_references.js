// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/post_login_references.js
//
// ===========================================================================
// A GROUP AND AN APPLICATION NAME THEIR POST-LOGIN POLICY (#1239, part of
// #1234; rule 3cx).
//
// `stsPostLoginSelectGroup` is gone: a named post-login profile keeps its
// rows and a precedence, a GROUP names its profile in `stsPostLoginPolicy`
// and an APPLICATION in `appPostLoginPolicy`. At a sign-in the profile the
// application names ranks with the profiles the person's groups name; a
// question asked of a person outside a sign-in — a started activity's mail,
// the progress report — knows no application and ranks the groups alone.
// In process, over the real directory, registry, policy and readers:
//
//   A. THE REFERENCES: `appPostLoginPolicy` takes `default` or a named
//      profile and refuses any other (STS-REG-0203), its choices those; a
//      group's `stsPostLoginPolicy` through the group page's act, refused
//      for a name the realm does not hold (STS-LDAP-0195); a named profile
//      saves with a precedence and nothing that selects.
//   B. THE SIGN-IN (`post_login.dueFor(username, application)`): a profile
//      with `enabled` off that the application names EXCLUDES a sign-in to
//      it, by identifier or client_id; a sign-in to another application is
//      asked; the profile a member's group names wins on a lower
//      precedence, and loses on a higher one.
//   C. OUTSIDE A SIGN-IN: the started activities' decision
//      (`post_login_activities.decide()`) finds the person due whom only
//      the application excludes, and not the person a group excludes; the
//      progress report's `profile`, for a row with none recorded, is the
//      one the groups select.
//   D. A NAME THE REALM DOES NOT HOLD selects nothing (STS-AUTHN-0539).
//   E. THE DELETE: a profile an application or a group names is not deleted
//      (STS-AUTHN-0540); once nothing names it, it is.
//   F. THE CONSOLE: the kind is tabbed (Default / Named policies / New
//      policy), a named profile says what names it and carries no group
//      box, the view's `selectors` and `references`, and the group page's
//      picker.
// ===========================================================================

delete process.env.CONFIG_FILE;

const ROOT = require('path').join(__dirname, '..');

const log = require('bunyan').createLogger({
  name: 'post_login_references',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'plr' + process.pid;
const APP = TAG + '-app';
const CLIENT = TAG + '-Client';
const LONE = TAG + '-lone';
const PQC = 'pqc-passkey-migration';

/**
 * Saves a post-login profile: on, inviting a person with no passkey, so a
 * person holding none is due wherever it applies; these values over it.
 *
 * @param policy - the post-login policy module
 * @param name - the profile's name
 * @param values - any row, and `precedence`
 * @returns the save's answer
 */
function save(policy, name, values) {
  log.debug('Entering save().');
  log.debug('Leaving save().');
  return policy.save(name, Object.assign({}, policy.DEFAULTS,
    { enabled: true, noPasskey: 'invite' }, values || {}));
}

/**
 * A request for an admin view.
 *
 * @returns the request
 */
function request() {
  log.debug('Entering request().');
  log.debug('Leaving request().');
  return { query: {}, headers: { host: 'localhost:8081' }, protocol: 'https',
           get: function () { return ''; } };
}

/**
 * Validates a report document against the catalog.
 *
 * @param document - the query document
 * @returns the validation
 */
function ask(document) {
  log.debug('Entering ask().');
  const Catalog = require('../report/catalog');
  const Limits = require('../report/limits');
  const Query = require('../report/query');
  const limits = Limits.fixed({ syncMaxRows: 1000, asyncMaxRows: 5000,
                                pdfMaxRows: 100 });
  const query = new Query({ catalog: new Catalog(), limits: limits });
  const out = query.validate(document);
  log.debug('Leaving ask().');
  return out;
}

async function run(t) {
  log.debug('Entering run().');
  const ldap = require('../ldap/ldap_server');
  const policy = require('../common/post_login_policy');
  const postLogin = require('../common/post_login');
  const activities = require('../common/post_login_activities');
  const applications = require('../common/applications');
  const errorCodes = require('../common/error_codes');
  const adminActions = require('../admin-core/admin_actions');
  const adminViews = require('../admin-core/admin_views');
  require('../common/i18n');

  const names = { appOff: TAG + '-appoff', groupOn: TAG + '-groupon',
                  groupOff: TAG + '-groupoff', gone: TAG + '-gone' };
  const groups = { on: TAG + '-on', off: TAG + '-off' };
  const people = { member: TAG + '-member', barred: TAG + '-barred',
                   outsider: TAG + '-outsider' };
  Object.keys(people).forEach(function (k) {
    ldap.createUser(people[k], { invent: false });
  });
  ldap.createGroup(groups.on);
  ldap.createGroup(groups.off);
  ldap.addGroupMember(groups.on, people.member);
  ldap.addGroupMember(groups.off, people.barred);
  const created = adminActions.applicationsAction({
    action: 'create', identifier: APP, 'field.oauthClientId': CLIENT
  }, ['oauth2']);
  adminActions.applicationsAction({ action: 'create', identifier: LONE }, []);
  t.check(created && created.ok === true, 'the application is created',
          JSON.stringify(created && created.errors));

  const point = function (identifier, value) {
    return adminActions.applicationsAction({ action: 'set',
      application: identifier, attribute: 'appPostLoginPolicy',
      value: value }, [], {});
  };
  const pointGroup = function (group, value) {
    return adminActions.groupsAction({ action: 'set-policy', group: group,
      attribute: 'stsPostLoginPolicy', policy: value });
  };
  const installed = policy.directoryInstalled();
  try {
    // A. The references.
    const saves = [
      save(policy, 'default', { snoozeDays: 2 }),
      save(policy, names.appOff, { enabled: false, precedence: 20 }),
      save(policy, names.groupOn, { snoozeDays: 4, precedence: 10 }),
      save(policy, names.groupOff, { enabled: false, precedence: 5 })
    ];
    t.check(saves.every(function (one) {
      return one.ok;
    }) && saves[1].profile.precedence === 20 &&
            saves[1].profile.selectGroups === undefined,
            'A1. named profiles save with a precedence and nothing that ' +
            'selects', JSON.stringify(saves.map(function (one) {
              return one.errors;
            })));
    const good = point(APP, names.appOff);
    const ghost = point(LONE, TAG + '-ghost');
    const row = applications.applicationFields().filter(function (one) {
      return one.attribute === 'appPostLoginPolicy';
    })[0];
    t.check(good.ok && !ghost.ok &&
            errorCodes.codeOf(ghost) === 'STS-REG-0203' &&
            !!row && row.choices[0] === 'default' &&
            row.choices.indexOf(names.appOff) > 0 &&
            row.choices.indexOf(names.groupOn) > 0,
            'A2. appPostLoginPolicy takes default or a named profile, and ' +
            'refuses one the realm does not hold (STS-REG-0203)',
            JSON.stringify([good.errors, ghost.errors, row && row.choices]));
    const grouped = pointGroup(groups.on, names.groupOn);
    const barred = pointGroup(groups.off, names.groupOff);
    const badValue = pointGroup(groups.on, TAG + '-ghost');
    t.check(grouped.ok && barred.ok && !badValue.ok &&
            errorCodes.codeOf(badValue) === 'STS-LDAP-0195' &&
            JSON.stringify(policy.namedBy(names.groupOn).groups) ===
              JSON.stringify([groups.on]) &&
            JSON.stringify(policy.namedBy(names.appOff).applications) ===
              JSON.stringify([APP]),
            'A3. a group names a profile in stsPostLoginPolicy, a name the ' +
            'realm does not hold is refused, and namedBy() answers both ' +
            'holders', JSON.stringify([grouped, badValue.errors]));

    // B. The sign-in: the real reader, with the application in hand.
    const outApp = postLogin.dueFor(people.outsider, APP);
    const outClient = postLogin.dueFor(people.outsider, CLIENT);
    const outLone = postLogin.dueFor(people.outsider, LONE);
    t.check(outApp === null && outClient === null && !!outLone &&
            outLone.profile === 'default' && outLone.snoozeDays === 2,
            'B1. a disabled profile the application names excludes a ' +
            'sign-in to it, by identifier or client_id; a sign-in to ' +
            'another application gets default',
            JSON.stringify([outApp, outClient, outLone]));
    const memberApp = postLogin.dueFor(people.member, APP);
    t.check(!!memberApp && memberApp.profile === names.groupOn &&
            memberApp.snoozeDays === 4 && memberApp.askedBy === 'policy',
            'B2. the profile a member\'s group names wins on a lower ' +
            'precedence than the application\'s', JSON.stringify(memberApp));
    save(policy, names.groupOn, { snoozeDays: 4, precedence: 30 });
    t.check(postLogin.dueFor(people.member, APP) === null &&
            postLogin.dueFor(people.member, LONE).profile === names.groupOn &&
            postLogin.dueFor(people.barred, LONE) === null,
            'B3. on a higher precedence the application\'s exclusion wins; ' +
            'elsewhere the group\'s profile applies, and a group naming a ' +
            'disabled profile excludes its members');

    // C. Outside a sign-in: no application.
    const record = { id: TAG + '-started', activity: PQC, groups: [],
                     intervalDays: 7, maxMails: 3 };
    const mailOutsider = activities.decide(record, people.outsider);
    const mailBarred = activities.decide(record, people.barred);
    t.check(mailOutsider.verdict === 'due' &&
            mailOutsider.due.profile === 'default' &&
            mailBarred.verdict === 'not-due',
            'C1. the started activity\'s mail decision knows no ' +
            'application: the person only the application excludes is ' +
            'due, the one a group excludes is not',
            JSON.stringify([mailOutsider, mailBarred]));
    const PostLogin = postLogin.PostLogin;
    const store = new Map();
    store.set(people.member + '|' + PQC,
              { invitedAt: Date.now(), asks: 1, skips: 0, doneAt: 0,
                snoozedUntil: 0 });
    const progress = new PostLogin(Object.assign(PostLogin.defaultDeps(),
      { progress: store }));
    const sources = require('../report/sources');
    sources.installPostLogin(progress);
    let answer = null;
    try {
      const asked = ask({ source: 'postLoginProgress',
                          select: ['username', 'profile'], limit: 10 });
      answer = asked.ok ? await sources.read(asked.plan, {
        startedMs: Date.now(), budgetMs: 5000, execution: 'sync' }) : asked;
    } finally {
      sources.installPostLogin(null);
    }
    const reported = ((answer && answer.rows) || []).filter(function (r) {
      return r.username === people.member;
    })[0];
    t.check(!!reported && reported.profile === names.groupOn,
            'C2. the progress report\'s profile, for a row with none ' +
            'recorded, is the one the person\'s groups select',
            JSON.stringify(answer));

    // D. A profile gone from under its reference.
    save(policy, names.gone, { enabled: false, precedence: 1 });
    point(LONE, names.gone);
    policy.setDirectory(Object.assign({}, installed, {
      allPostLoginPolicies: function () {
        return installed.allPostLoginPolicies().filter(function (one) {
          return String(one.name).toLowerCase() !== names.gone;
        });
      }
    }));
    const dangling = postLogin.dueFor(people.outsider, LONE);
    policy.setDirectory(installed);
    t.check(!!dangling && dangling.profile === 'default',
            'D. a name the realm does not hold selects nothing ' +
            '(STS-AUTHN-0539): default applies', JSON.stringify(dangling));
    point(LONE, 'default');

    // F. The console (before the deletes, while the references stand).
    const policies = require(ROOT + '/admin-ui/web_policies');
    const kit = require(ROOT + '/admin-ui/web_kit');
    const view = adminViews.policiesView({});
    const html = policies.body(kit.context(), view);
    const at = function (needle) {
      return html.indexOf(needle);
    };
    t.check(at('id="postLogin-sub-default"') > 0 &&
            at('id="postLogin-sub-named"') > at('id="postLogin-sub-default"') &&
            at('id="postLogin-sub-new"') > at('id="postLogin-sub-named"'),
            'F1. the post-login policy tab is three sub-tabs');
    const named = html.slice(at('id="postLogin-sub-named"'),
                             at('id="postLogin-sub-new"'));
    t.check(named.indexOf('id="postLogin-profile-' + names.appOff + '"') >=
              0 &&
            named.indexOf('<code>' + APP + '</code>') >= 0 &&
            named.indexOf('<code>' + groups.on + '</code>') >= 0 &&
            named.indexOf('name="selectGroups"') < 0,
            'F2. a named profile says the applications and groups naming ' +
            'it, and has no group box');
    const kind = view.postLogin || {};
    t.check(JSON.stringify(kind.selectors) === '["precedence"]' &&
            kind.references.application === 'appPostLoginPolicy' &&
            kind.references.group === 'stsPostLoginPolicy',
            'F3. the view says the kind ranks by precedence and what names ' +
            'it', JSON.stringify([kind.selectors, kind.references]));
    const detail = adminViews.groupDetailJson(request(),
                                              ldap.groupDnFor(groups.on));
    const mine = (detail.json.policyReferences || []).filter(function (one) {
      return one.attribute === 'stsPostLoginPolicy';
    })[0];
    t.check(!!mine && mine.value === names.groupOn &&
            mine.choices.indexOf(names.appOff) >= 0,
            'F4. the group page offers a post-login picker, the profile the ' +
            'group names selected', JSON.stringify(mine));

    // E. The delete.
    const byApp = policy.reset(names.appOff);
    const byGroup = policy.reset(names.groupOn);
    t.check(!byApp.ok && errorCodes.codeOf(byApp) === 'STS-AUTHN-0540' &&
            String(byApp.errors).indexOf(APP) >= 0 &&
            !byGroup.ok && errorCodes.codeOf(byGroup) === 'STS-AUTHN-0540' &&
            String(byGroup.errors).indexOf(groups.on) >= 0,
            'E1. a profile an application or a group names is not deleted ' +
            '(STS-AUTHN-0540)', JSON.stringify([byApp.errors,
                                                byGroup.errors]));
    point(APP, 'default');
    pointGroup(groups.on, '');
    const gone = policy.reset(names.appOff);
    const gone2 = policy.reset(names.groupOn);
    t.check(gone.ok && gone.removed === true && gone2.ok &&
            gone2.removed === true,
            'E2. once nothing names it, it is deleted',
            JSON.stringify([gone, gone2]));
  } finally {
    policy.setDirectory(installed);
    point(APP, 'default');
    point(LONE, 'default');
    pointGroup(groups.on, '');
    pointGroup(groups.off, '');
    [names.appOff, names.groupOn, names.groupOff, names.gone, 'default']
      .forEach(function (one) {
        policy.reset(one);
      });
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'post_login_references',
  describe: 'A group and an application name their post-login policy ' +
            '(stsPostLoginPolicy, appPostLoginPolicy, #1239): the sign-in ' +
            'ranks both, the mail decision and the progress report the ' +
            'groups alone; a dangling reference, the refused delete, the ' +
            'console',
  run: run
};
