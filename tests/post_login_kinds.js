// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_kinds.js
//
// ===========================================================================
// SEVERAL POST-LOGIN ACTIVITIES (#2009 P1, design X1 and X3).
//
// `common/post_login_kinds.ts` is the one list of activities, and
// `common/post_login.ts` asks each through the same four questions. In
// process, over the REAL `PostLogin` with its passkey activity
// (`passkeyKind()`) and two test activities handed through its deps, the
// post-login policy, credentials and the WebAuthn policy as doubles:
//
//   A. The table: the passkey migration is its first row; a module's
//      answer is refused unless it is whole; the exposure order.
//   B. The passkey activity alone answers as `dueFor()` did before #2009.
//   C. Several due: decrypt-later before forgery, and a REQUIRED one first
//      of all.
//   D. `nextDue()`: an activity already asked at this sign-in is not asked
//      again; once one that could be skipped was asked, only required ones.
//   E. `dueFor()` naming an activity answers that one.
//   F. An activity that throws leaves the others asked.
//   G. The cheap question: every profile off and nothing started asks no
//      activity anything.
//   H. A deleted person's progress goes for every activity in the table.
//   I. Without a test's list, the table's activities are asked; the started
//      activities offer the same list.
//   J. A row whose module does not load is not asked, logged once under
//      STS-AUTHN-0581, and tried again: once it loads it is asked.
//   K. An activity that throws is logged at error level under
//      STS-AUTHN-0582, once in the process.
// ===========================================================================

const log = require('bunyan').createLogger({ name: 'post_login_kinds',
  level: process.env.LOG_LEVEL || 'info' });

const DAY = 24 * 60 * 60 * 1000;
const PQC = 'pqc-passkey-migration';

// A test activity: due to whoever `who` holds, with its own switch on the
// profile (`<id>On`), its own Skip and allotted time.
function testKind(id, exposure, who, calls) {
  log.debug("Entering testKind().");
  const out = {
    id: id, exposure: exposure,
    enabledIn: function enabledIn(profile) {
      log.debug("Entering testKind().enabledIn().");
      log.debug("Leaving testKind().enabledIn().");
      return profile[id + 'On'] === true;
    },
    turnedOn: function turnedOn(profile) {
      log.debug("Entering testKind().turnedOn().");
      const on = Object.assign({}, profile);
      on[id + 'On'] = true;
      log.debug("Leaving testKind().turnedOn().");
      return on;
    },
    timing: function timing() {
      log.debug("Entering testKind().timing().");
      log.debug("Leaving testKind().timing().");
      return { snoozeDays: 3, graceDays: 10 };
    },
    due: function due(username) {
      log.debug("Entering testKind().due().");
      calls.push(id + ':' + username);
      if (who === 'throw') {
        log.debug("Leaving testKind().due(). Throwing.");
        throw new Error('this activity cannot be asked');
      }
      log.debug("Leaving testKind().due().");
      return who.indexOf(username) >= 0
        ? { reason: 'classical', enforceable: true, method: 'register',
            fallback: 'none', extra: id }
        : null;
    }
  };
  log.debug("Leaving testKind().");
  return out;
}

function build(profile, withKinds, calls, logger) {
  log.debug("Entering build().");
  const helpers = require('../common/helpers');
  const PostLogin = require('../common/post_login').PostLogin;
  const clock = { now: Date.parse('2026-11-01T00:00:00.000Z') };
  const progress = new Map();
  const policy = {
    DEFAULT_PROFILE: 'default',
    anyEnabledAsked: 0,
    anyEnabled: function (isOn) {
      policy.anyEnabledAsked += 1;
      return typeof isOn === 'function' ? isOn(profile)
                                        : profile.enabled === true;
    },
    personGroups: function () {
      return [];
    },
    forPerson: function () {
      return profile;
    }
  };
  // Everybody holds one classical passkey; the realm can always make an
  // ML-DSA one, in one lane.
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
  const deps = { log: logger || helpers.log, credentials: credentials,
    passkeyPolicy: { select: function () {
      return null;
    } },
    postLoginPolicy: policy, webauthnPolicy: webauthnPolicy,
    progress: progress,
    now: function () {
      return clock.now;
    } };
  if (withKinds) {
    deps.kinds = function (self) {
      return [self.passkeyKind()].concat(withKinds(calls));
    };
  }
  const postLogin = new PostLogin(deps);
  log.debug("Leaving build().");
  return { postLogin: postLogin, progress: progress, clock: clock,
           policy: policy };
}

function run(t) {
  log.debug("Entering run().");
  const Kinds = require('../common/post_login_kinds');

  // A. The table.
  t.equal(Kinds.ids()[0], PQC, 'A. the passkey migration is the first row');
  t.equal(Kinds.rowOf(PQC).exposure, 'forgery',
    'its credential is exposed to forgery, not to later decryption');
  t.equal(Kinds.rowOf('no-such-activity'), null,
    'an activity not in the table has no row');
  const row = { id: 'x', exposure: 'decrypt-later', module: './x' };
  t.check(/no kind/.test(Kinds.problemWith(row, null)),
    'a module exporting no kind is refused');
  t.check(/not "x"/.test(Kinds.problemWith(row, { id: 'y' })),
    'one answering for another activity is refused');
  t.check(/exposure/.test(Kinds.problemWith(row, { id: 'x',
      exposure: 'forgery' })),
    'one giving another exposure is refused');
  t.check(/has no timing, due/.test(Kinds.problemWith(row, { id: 'x',
      exposure: 'decrypt-later', enabledIn: function () {
        return true;
      }, turnedOn: function () {
        return {};
      } })),
    'a half-made one is refused whole, naming what it lacks');
  t.equal(Kinds.problemWith(row, testKind('x', 'decrypt-later', [], [])), '',
    'a whole one is accepted');
  t.check(Kinds.exposureRank('decrypt-later') < Kinds.exposureRank('forgery') &&
          Kinds.exposureRank('forgery') < Kinds.exposureRank('other') &&
          Kinds.exposureRank('other') < Kinds.exposureRank('unheard-of'),
    'decrypt-later is asked before forgery, forgery before other, and an ' +
    'exposure not listed last');

  // B. The passkey activity alone.
  const on = { name: 'default', enabled: true, activity: PQC,
    snoozeDays: 7, graceDays: 0, noPasskey: 'leave', method: 'automatic',
    attestation: 'any', noPasskeyFallback: 'none' };
  const alone = build(on, null, []);
  const list = alone.postLogin.dueListFor('ann');
  t.equal(list.length, 1, 'B. the passkey activity alone: one due');
  const first = list[0] || {};
  t.check(first.activity === PQC && first.reason === 'classical' &&
          first.method === 'upgrade' && first.fallback === 'none' &&
          first.snoozeDays === 7 && first.graceDays === 0 &&
          first.required === false && first.enforceable === true &&
          first.askedBy === 'policy' && first.profile === 'default',
    'answered as before #2009: classical, an upgrade in one lane, the ' +
    'profile\'s own Skip, asked by the policy', JSON.stringify(first));
  t.equal(JSON.stringify(alone.postLogin.dueFor('ann')),
    JSON.stringify(first), 'and dueFor() is the first of the list');

  // C. Several due, in order.
  const calls = [];
  const several = Object.assign({}, on, { mailOn: true, otherOn: true });
  const b = build(several, function (c) {
    return [testKind('other', 'other', ['ann'], c),
            testKind('mail', 'decrypt-later', ['ann', 'bob'], c)];
  }, calls);
  const order = b.postLogin.dueListFor('ann').map(function (one) {
    return one.activity;
  });
  t.equal(order.join(','), 'mail,' + PQC + ',other',
    'C. decrypt-later first, then forgery, then the rest');
  const mail = b.postLogin.dueListFor('ann')[0];
  t.check(mail.snoozeDays === 3 && mail.graceDays === 10 &&
          mail.extra === 'mail' && mail.askedBy === 'policy',
    'an activity\'s own Skip and allotted time, and its own facts, on its ' +
    'due', JSON.stringify(mail));
  // Ann was first asked the passkey migration long ago, with an allotted
  // time that has passed: it is now REQUIRED, and asked first of all.
  const graced = Object.assign({}, several, { graceDays: 30 });
  const c = build(graced, function (cc) {
    return [testKind('other', 'other', ['ann'], cc),
            testKind('mail', 'decrypt-later', ['ann'], cc)];
  }, []);
  c.progress.set('ann|' + PQC, { invitedAt: c.clock.now - 40 * DAY,
                                 snoozedUntil: c.clock.now + DAY });
  const requiredFirst = c.postLogin.dueListFor('ann');
  t.check(requiredFirst[0].activity === PQC && requiredFirst[0].required,
    'a required activity comes first of all, its snooze no longer counting',
    JSON.stringify(requiredFirst.map(function (one) {
      return one.activity + (one.required ? '!' : '');
    })));

  // D. nextDue().
  t.equal((b.postLogin.nextDue('ann', '', [], false) || {}).activity, 'mail',
    'D. the first asked is the first due');
  t.equal(b.postLogin.nextDue('ann', '', ['mail'], true), null,
    'after one that could be skipped, nothing more that could be');
  t.equal((b.postLogin.nextDue('ann', '', ['mail'], false) || {}).activity,
    PQC, 'an activity already asked is never asked again');
  t.equal((c.postLogin.nextDue('ann', '', [PQC], true) || {}).activity,
    undefined, 'with the required one done and a skippable one asked, the ' +
    'sign-in goes on');
  t.equal((c.postLogin.nextDue('ann', '', [], true) || {}).activity, PQC,
    'but a required one is asked even after a skippable one');

  // E. dueFor() naming an activity.
  t.equal((b.postLogin.dueFor('ann', '', 'other') || {}).activity, 'other',
    'E. dueFor() naming an activity answers that one');
  t.equal(b.postLogin.dueFor('bob', '', 'other'), null,
    'and nothing where that one is not due, whatever else is');

  // F. A throwing activity.
  const f = build(several, function (cc) {
    return [testKind('other', 'other', 'throw', cc),
            testKind('mail', 'decrypt-later', ['ann'], cc)];
  }, []);
  t.equal(f.postLogin.dueListFor('ann').map(function (one) {
    return one.activity;
  }).join(','), 'mail,' + PQC,
  'F. an activity that throws leaves the others asked');

  // G. The cheap question.
  const offCalls = [];
  const off = build({ name: 'default', enabled: false, activity: PQC },
    function (cc) {
      return [testKind('mail', 'decrypt-later', ['ann'], cc)];
    }, offCalls);
  t.equal(off.postLogin.dueListFor('ann').length, 0,
    'G. every profile off and nothing started: nothing is due');
  t.check(off.policy.anyEnabledAsked === 1 && offCalls.length === 0,
    'asked once whether anything is on, and no activity asked about ann');
  // A named profile with one activity on and another off: only the one.
  const named = build({ name: 'mailers', enabled: false, activity: PQC,
                        mailOn: true },
    function (cc) {
      return [testKind('mail', 'decrypt-later', ['ann'], cc)];
    }, []);
  t.equal(named.postLogin.dueListFor('ann').map(function (one) {
    return one.activity;
  }).join(','), 'mail',
  'a named profile with one activity on asks that one, and its passkey ' +
  'migration off excludes the person from that one');

  // H. A deleted person.
  b.progress.set('ann|' + PQC, { asks: 1 });
  t.equal(b.postLogin.forgetPerson('ann'), 1,
    'H. a deleted person\'s progress goes, for each activity in the table');
  t.equal(b.progress.has('ann|' + PQC), false, 'and the row is gone');

  // I. The table's activities.
  const table = build(on, null, []);
  t.equal(table.postLogin.kindsAsked().map(function (one) {
    return one.id;
  }).join(','), Kinds.ids().join(','),
  'I. without a test\'s list the table\'s activities are asked');
  t.equal(require('../common/post_login_activities').ACTIVITIES.join(','),
    Kinds.startableIds().join(','),
    'and an administrator may start the ones the table marks startable');
  t.equal(Kinds.startableIds().join(','), PQC,
    'which is the passkey migration alone until #2009 P4');

  // J. A module that does not load, then does.
  const errors = [];
  const helpers = require('../common/helpers');
  const recording = { debug: function () {
    return helpers.log.debug.apply(helpers.log, arguments);
  }, info: function () {
    return helpers.log.info.apply(helpers.log, arguments);
  }, warn: function () {
    return helpers.log.warn.apply(helpers.log, arguments);
  }, error: function (line) {
    errors.push(String(line));
  } };
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const file = path.join(os.tmpdir(), 'sts-plk-' + process.pid + '-' +
                                      Date.now() + '.js');
  const realKinds = Kinds.KINDS;
  Kinds.KINDS = realKinds.concat([{ id: 'probe', exposure: 'other',
                                    module: file }]);
  try {
    const j = build(Object.assign({}, on, { probeOn: true }), null, [],
                    recording);
    const before = j.postLogin.dueListFor('ann').map(function (one) {
      return one.activity;
    }).join(',');
    j.postLogin.dueListFor('ann');
    const logged = errors.filter(function (line) {
      return /STS-AUTHN-0581/.test(line);
    }).length;
    fs.writeFileSync(file, '"use strict";\nmodule.exports = { kind: {\n' +
      '  id: "probe", exposure: "other",\n' +
      '  enabledIn: function (p) { return p.probeOn === true; },\n' +
      '  turnedOn: function (p) { return Object.assign({}, p, ' +
      '{ probeOn: true }); },\n' +
      '  timing: function () { return { snoozeDays: 1, graceDays: 0 }; },\n' +
      '  due: function (u) { return u === "ann" ? { reason: "probe", ' +
      'enforceable: false, method: "", fallback: "none" } : null; }\n' +
      '} };\n');
    const after = j.postLogin.dueListFor('ann').map(function (one) {
      return one.activity;
    }).join(',');
    t.check(before === PQC && logged === 1,
      'J. a row whose module does not load is not asked, and is logged ' +
      'once under STS-AUTHN-0581 over two sign-ins', before + ' ' + logged);
    t.equal(after, PQC + ',probe',
      'and it is tried again: once the module loads, its activity is asked');
  } finally {
    Kinds.KINDS = realKinds;
    try {
      fs.rmSync(file, { force: true });
    } catch (e) {
      // A temporary file left behind is not a failed assertion.
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }

  // K. An activity that throws, logged once.
  errors.length = 0;
  const k = build(several, function (cc) {
    return [testKind('other', 'other', 'throw', cc)];
  }, [], recording);
  k.postLogin.dueListFor('ann');
  k.postLogin.dueListFor('bob');
  const thrown = errors.filter(function (line) {
    return /STS-AUTHN-0582/.test(line) && /"other"/.test(line);
  }).length;
  t.equal(thrown, 1, 'K. an activity that throws is an error under ' +
    'STS-AUTHN-0582, logged once in the process');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'post_login_kinds',
  describe: 'several post-login activities (#2009 P1): the one table, the ' +
    'passkey migration behind it unchanged, the asking order, the next ' +
    'activity at a sign-in, an activity that throws, the cheap question',
  run: run
};
