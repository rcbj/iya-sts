// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_started.js
//
// ===========================================================================
// A STARTED POST-LOGIN ACTIVITY ASKS ITS GROUPS AT SIGN-IN (#1126).
//
// rcbj's option (a): a RUNNING started activity turns the sign-in invitation
// on for its population — the union of its groups, or the whole realm where
// it names none — under the rules of the profile the post-login policy
// selects for the person, only `enabled` overridden. In process, over the
// REAL `PostLogin`, the REAL `PostLoginPolicy` on a directory double and
// the REAL `PostLoginActivities` on Maps, with credentials and the WebAuthn
// policy as doubles that can always make an ML-DSA passkey:
//
//   A. The policy off and nothing started: nobody is due (the cheap
//      question, no group read).
//   B. A member of a running activity's group, the policy off, is due, and
//      `askedBy` names the started activity; a non-member is not.
//   C. The union of two groups: a member of either is due.
//   D. A named profile with `enabled` off that reaches a member excludes
//      them; `default` off excludes nobody.
//   E. The rules are the selected profile's: a named profile's own
//      snoozeDays, graceDays and method, `enabled` alone overridden.
//   F. A person the policy itself enables is asked by the policy
//      (`askedBy: policy`).
//   G. Paused, then ended: the activity asks nobody; the policy still asks
//      whom it enables.
//   H. No group named: everybody in the realm.
//   I. The progress row records `askedBy` at the ask, and a mail leaves it.
//   J. The mail job's decision follows: with the policy off a member is
//      `due`, so a running activity mails its people.
//   K. The person's groups are asked of the directory once a question.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'post_login_started',
  level: process.env.LOG_LEVEL || 'info' });

const PQC = 'pqc-passkey-migration';

// The directory double: profile entries as `ou=postLoginPolicies` holds
// them, and each person's groups.
function directoryDouble() {
  log.debug("Entering directoryDouble().");
  const out = {
    entries: [],
    memberOf: {
      ann: ['cn=staff,ou=groups'],
      bob: ['cn=ops,ou=groups'],
      cat: [],
      dan: ['cn=staff,ou=groups', 'cn=excluded,ou=groups'],
      eve: ['cn=staff,ou=groups', 'cn=pilot,ou=groups']
    },
    groupCalls: 0,
    allPostLoginPolicies: function () {
      return out.entries;
    },
    writePostLoginPolicy: function () {
      return null;
    },
    deletePostLoginPolicy: function () {
      return null;
    },
    personGroups: function (u) {
      out.groupCalls += 1;
      return (out.memberOf[u] || []).map(function (dn) {
        return { cn: dn.split(',')[0].slice(3), dn: dn };
      });
    }
  };
  log.debug("Leaving directoryDouble().");
  return out;
}

// One profile entry, its attributes as the directory names them.
function entry(name, values) {
  log.debug("Entering entry().");
  const attributes = {};
  Object.keys(values).forEach(function (key) {
    attributes[key.toLowerCase()] = [].concat(values[key]).map(String);
  });
  log.debug("Leaving entry().");
  return { name: name, dn: 'cn=' + name + ',ou=postLoginPolicies',
           attributes: attributes };
}

function build() {
  log.debug("Entering build().");
  const helpers = require('../common/helpers');
  const PostLogin = require('../common/post_login').PostLogin;
  const PostLoginPolicy = require('../common/post_login_policy')
    .PostLoginPolicy;
  const Activities = require('../common/post_login_activities')
    .PostLoginActivities;
  const directory = directoryDouble();
  const policy = new PostLoginPolicy(PostLoginPolicy.defaultDeps());
  policy.setDirectory(directory);
  const clock = { now: Date.parse('2026-10-01T00:00:00.000Z') };
  let ids = 0;
  let postLogin = null;
  const activities = new Activities({
    log: helpers.log, errorCodes: require('../common/error_codes'),
    audit: { audit: function () {
      return null;
    } },
    realms: { currentId: function () {
      return 'default';
    } },
    started: new Map(), runs: new Map(),
    directory: function () {
      return { groupsNamed: function (names) {
        return [].concat(names).map(function (g) {
          const dn = 'cn=' + g + ',ou=groups';
          return { asked: g, dn: dn, cn: g, found: true };
        });
      } };
    },
    postLogin: function () {
      return postLogin;
    },
    mailUses: function () {
      return {};
    },
    mail: function () {
      return { available: function () {
        return true;
      } };
    },
    scheduler: function () {
      return {};
    },
    randomId: function () {
      ids += 1;
      return 'started' + ids;
    },
    now: function () {
      clock.now += 1000;
      return clock.now;
    }
  });
  // Everybody holds one classical passkey (no role since #1135); the realm
  // can always make an ML-DSA one, in one lane.
  const credentials = {
    keysOf: function (u) {
      return [{ credentialId: u + '-ec' }];
    },
    keyAlgorithm: function () {
      return { postQuantum: false, name: 'ES256' };
    },
    attestationAlgorithms: function () {
      return {};
    }
  };
  const ok = function () {
    return { ok: true };
  };
  const webauthnPolicy = {
    offered: function () {
      return true;
    },
    upgradeRefusal: ok, useAllowed: ok, enrolmentAllowed: ok,
    laneRefusal: ok,
    offersPostQuantum: function () {
      return true;
    },
    upgradeAlgorithms: function () {
      return ['ML-DSA-65'];
    },
    alongsideClassical: function () {
      return false;
    }
  };
  postLogin = new PostLogin({ log: helpers.log, credentials: credentials,
    passkeyPolicy: { select: function () {
      return null;
    } },
    postLoginPolicy: policy, webauthnPolicy: webauthnPolicy,
    progress: new Map(),
    now: function () {
      return clock.now;
    },
    started: function () {
      return activities;
    } });
  log.debug("Leaving build().");
  return { directory: directory, policy: policy, activities: activities,
           postLogin: postLogin };
}

async function run(t) {
  log.debug("Entering run().");
  const b = build();
  const pl = b.postLogin;
  const ctx = { actor: 'admin', via: 'api' };

  // A. Off, nothing started.
  t.equal(pl.dueFor('ann'), null,
    'A. the policy off and nothing started: nobody is due');
  t.equal(b.directory.groupCalls, 0,
    'and no group was read to say so');

  // B. One group, the policy off.
  const staff = await b.activities.start({ activity: PQC,
    groups: ['staff'] }, ctx);
  t.equal(staff.ok, true, 'a started activity for staff', staff.errors);
  const staffId = staff.started && staff.started.id;
  const ann = pl.dueFor('ann');
  t.check(!!ann, 'B. a member of its group is due with the policy off');
  t.equal(ann && ann.askedBy, staffId, 'askedBy names the started activity');
  t.equal(ann && ann.profile, 'default',
    'under the profile the policy selects for her');
  t.equal(ann && ann.reason, 'classical',
    'because her passkey is classical (in no role since #1135)');
  t.equal(pl.dueFor('bob'), null, 'a non-member is not');
  t.equal(pl.dueFor('cat'), null, 'nor a person in no group');

  // C. The union of two groups.
  const both = await b.activities.start({ activity: PQC,
    groups: ['ops', 'pilot'] }, ctx);
  t.equal(both.ok, true, 'a second, for ops and pilot', both.errors);
  const bothId = both.started && both.started.id;
  const bob = pl.dueFor('bob');
  t.equal(bob && bob.askedBy, bothId,
    'C. a member of either of its groups is due (ops)');
  const eve = pl.dueFor('eve');
  t.equal(eve && eve.askedBy, staffId,
    'a member of both activities is asked by the older one');

  // D. Exclusion.
  b.directory.entries = [
    entry('excluded', { stsPostLoginEnabled: 'FALSE',
                        stsPostLoginSelectGroup: 'cn=excluded,ou=groups',
                        stsPostLoginPrecedence: '10' })
  ];
  t.equal(pl.dueFor('dan'), null,
    'D. a named profile with enabled off excludes its members');
  t.check(!!pl.dueFor('ann'),
    'and default off excludes nobody: a member it does not reach is due');

  // E. The rules are the selected profile's.
  b.directory.entries.push(entry('pilot', {
    stsPostLoginEnabled: 'FALSE',
    stsPostLoginSelectGroup: 'cn=pilot,ou=groups',
    stsPostLoginPrecedence: '50' }));
  t.equal(pl.dueFor('eve'), null,
    'E1. a named profile off that reaches a member excludes her from ' +
    'every started activity');
  b.directory.entries = [b.directory.entries[0], entry('staffrules', {
    stsPostLoginEnabled: 'FALSE',
    stsPostLoginSelectGroup: 'cn=staff,ou=groups',
    stsPostLoginPrecedence: '200',
    stsPostLoginSnoozeDays: '3', stsPostLoginGraceDays: '14',
    stsPostLoginMethod: 'alongside' })];
  // The named profile is OFF and is ann's selection: she is excluded.
  t.equal(pl.dueFor('ann'), null,
    'E2. a named profile off is an exclusion even at a high precedence ' +
    'when no enabling one reaches her');
  b.directory.entries = [b.directory.entries[0], entry('staffrules', {
    stsPostLoginEnabled: 'TRUE',
    stsPostLoginSelectGroup: 'cn=staff,ou=groups',
    stsPostLoginPrecedence: '200',
    stsPostLoginSnoozeDays: '3', stsPostLoginGraceDays: '14',
    stsPostLoginMethod: 'alongside' })];
  const ruled = pl.dueFor('ann');
  t.equal(ruled && ruled.askedBy, 'policy',
    'F. a person the policy itself enables is asked by the policy');
  t.check(!!ruled && ruled.snoozeDays === 3 && ruled.graceDays === 14 &&
    ruled.method === 'alongside' && ruled.profile === 'staffrules',
    'with that profile\'s snooze, allotted time and method',
    JSON.stringify(ruled));
  // The default profile off, carrying rules of its own: a started activity
  // takes them, `enabled` alone overridden.
  b.directory.entries = [b.directory.entries[0], entry('default', {
    stsPostLoginEnabled: 'FALSE', stsPostLoginSnoozeDays: '5',
    stsPostLoginGraceDays: '9', stsPostLoginMethod: 'alongside' })];
  const fromDefault = pl.dueFor('ann');
  t.check(!!fromDefault && fromDefault.askedBy === staffId &&
    fromDefault.profile === 'default' && fromDefault.snoozeDays === 5 &&
    fromDefault.graceDays === 9 && fromDefault.method === 'alongside',
    'E3. a started activity takes default\'s rules, enabled alone ' +
    'overridden', JSON.stringify(fromDefault));
  b.directory.entries = [b.directory.entries[0]];

  // G. Paused, then ended.
  const paused = b.activities.move('pause', staffId, ctx);
  t.equal(paused.ok, true, 'paused', paused.errors);
  t.equal(pl.dueFor('ann'), null,
    'G1. a paused activity asks nobody at sign-in');
  t.check(!!pl.dueFor('bob'), 'and the other still asks its own');
  b.activities.move('resume', staffId, ctx);
  t.check(!!pl.dueFor('ann'), 'resumed, it asks again');
  b.activities.move('end', staffId, ctx);
  t.equal(pl.dueFor('ann'), null, 'G2. ended, it asks nobody');
  b.directory.entries.push(entry('staffrules', {
    stsPostLoginEnabled: 'TRUE',
    stsPostLoginSelectGroup: 'cn=staff,ou=groups',
    stsPostLoginPrecedence: '200' }));
  const byPolicy = pl.dueFor('ann');
  t.equal(byPolicy && byPolicy.askedBy, 'policy',
    'G3. a person the policy itself enables is still asked');
  b.directory.entries.pop();

  // H. No group: the realm.
  const realm = await b.activities.start({ activity: PQC }, ctx);
  t.equal(realm.ok, true, 'a started activity for the realm', realm.errors);
  const cat = pl.dueFor('cat');
  t.equal(cat && cat.askedBy, realm.started && realm.started.id,
    'H. with no group it reaches a person in no group');
  t.equal(pl.dueFor('dan'), null,
    'and the named profile off still excludes its members');

  // I. The row records who asked; a mail leaves it.
  const asked = pl.noteAsked('cat', cat);
  t.equal(asked.askedBy, realm.started && realm.started.id,
    'I1. the progress row records which started activity asked');
  pl.noteMailed('cat', Object.assign({}, cat, { askedBy: 'other' }),
                bothId);
  t.equal(pl.stateOf('cat').askedBy, realm.started && realm.started.id,
    'I2. a mail is not an ask: it leaves askedBy as it was');
  const skipped = pl.noteSkipped('cat', cat);
  t.check(skipped.ok && pl.stateOf('cat').snoozedUntil > 0,
    'I3. Skip still puts it off');

  // J. The mail job's decision with the policy off.
  const record = b.activities.get(bothId);
  const decided = b.activities.decide(record, 'bob');
  t.equal(decided.verdict, 'due',
    'J. with the policy off the job finds a member due, so it mails');

  // K. One directory read a question.
  const before = b.directory.groupCalls;
  b.directory.entries = [b.directory.entries[0]];
  pl.dueFor('bob');
  t.equal(b.directory.groupCalls - before, 1,
    'K. the person\'s groups are read once for the profile and the ' +
    'started activities');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'post_login_started',
  describe: 'a running started post-login activity asks its groups at ' +
    'sign-in (#1126): the union, the exclusion, the selected profile\'s ' +
    'rules, paused and ended, askedBy on the row, the mail decision',
  run: run
};
