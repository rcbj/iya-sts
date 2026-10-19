// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: realm_count_limit.js
//
// ===========================================================================
// realms.maxCount (#368): a creation cap, set only in the default realm.
//
// The row's default is 10 and the count includes the built-in default realm.
// A create past the cap is STS-CORE-0161; a realm handed back with
// `restored: true` is not refused, because a restart of a registry that is
// already over the cap must still come up. Lowering the cap removes nothing.
// A write or a clear while another realm is ambient is STS-CORE-0162, and
// the row describes that as `editRefusal` rather than a restart. Setting the
// key ON a realm stays STS-CORE-0014. `realms.enabled` is still written
// process-wide from inside a realm — that door is documented and this file
// puts the value back.
//
// The cap is on AGREEMENT_SETTINGS. The suite raises STS_REALMS_MAX_COUNT
// before any module reads a setting (`tests/run.js`); this file asserts the
// TABLE default, not the value that raise produces, and it restores whatever
// override it found.
// ===========================================================================

const crypto = require('crypto');
const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const cluster = require('../cluster/cluster');

const log = require('bunyan').createLogger({
  name: 'realm_count_limit',
  level: process.env.LOG_LEVEL || 'info'
});

function settingRow(key) {
  log.debug("Entering settingRow().");
  const found = config.SETTINGS.filter(function (row) {
    return row.key === key;
  })[0];
  log.debug("Leaving settingRow().");
  return found || null;
}

function described(key) {
  log.debug("Entering described().");
  const row = settingRow(key);
  const out = row ? config.describe(row) : null;
  log.debug("Leaving described().");
  return out;
}

function freshId(suffix) {
  log.debug("Entering freshId().");
  const body = crypto.randomBytes(4).toString('hex');
  log.debug("Leaving freshId().");
  return 'rcl' + body + (suffix || '');
}

function run(t) {
  log.debug("Entering run().");
  const row = settingRow('realms.maxCount');
  if (!t.check(!!row, 'realms.maxCount is a setting')) {
    log.debug("Leaving run().");
    return;
  }
  t.equal(row.dflt, 10, 'the shipped default is 10');
  t.equal(row.min, 1, 'the minimum is 1, the default realm');
  t.equal(row.max, 100000, 'the maximum a write may name is 100000');
  t.equal(row.env, 'STS_REALMS_MAX_COUNT',
          'the environment variable is STS_REALMS_MAX_COUNT');
  t.equal(row.runtime, true, 'a service administrator changes it live');
  t.check(cluster.AGREEMENT_SETTINGS.indexOf('realms.maxCount') >= 0,
          'the cap is a setting every node must agree');

  const made = [];
  const before = described('realms.maxCount');
  const capBefore = config.text('realms.maxCount');
  const wasOverride = !!(before && before.overridden);
  const enabledBefore = described('realms.enabled');
  const enabledWas = !!(enabledBefore && enabledBefore.overridden);
  const enabledText = config.text('realms.enabled');
  try {
    // Room for the realm this file enters, even when the process is already
    // sitting on the cap from files that ran before it.
    const opened = config.setOverride('realms.maxCount',
                                      String(realms.count() + 1));
    if (!t.check(opened.ok,
                 'the cap can be raised from the default realm',
                 (opened.errors || []).join(' '))) {
      log.debug("Leaving run(). The cap could not be raised.");
      return;
    }
    const id = freshId('');
    const created = realms.create({ id: id, name: 'Count limit' });
    if (!t.check(created.ok, 'a realm under the cap is created',
                 (created.errors || []).join(' '))) {
      log.debug("Leaving run(). The realm was not created.");
      return;
    }
    made.push(id);
    const held = realms.count();

    const capped = config.setOverride('realms.maxCount', String(held));
    t.check(capped.ok, 'the cap can be set to the live count',
            (capped.errors || []).join(' '));
    const refused = realms.create({ id: freshId('b'), name: 'Over' });
    t.check(!refused.ok, 'the next create is refused');
    t.equal(errorCodes.codeOf(refused), 'STS-CORE-0161',
            'the refusal is STS-CORE-0161');
    t.check(/realms\.maxCount/.test((refused.errors || []).join(' ')) &&
            (refused.errors || []).join(' ').indexOf(String(held)) >= 0,
            'the sentence names the limit and the live count',
            (refused.errors || []).join(' '));
    t.equal(realms.count(), held, 'a refused create adds no realm');

    const restored = realms.create({
      id: freshId('r'), name: 'Restored', restored: true
    });
    t.check(restored.ok, 'a restore is not refused for the cap',
            (restored.errors || []).join(' '));
    if (restored.ok) {
      made.push(restored.realm.id);
    }
    const afterRestore = realms.count();
    t.check(afterRestore > held, 'the restored realm is in the count');

    const lowered = config.setOverride('realms.maxCount', '1');
    t.check(lowered.ok, 'the cap can be lowered below the live count',
            (lowered.errors || []).join(' '));
    t.equal(realms.count(), afterRestore,
            'lowering the cap removes nothing');
    const still = realms.create({ id: freshId('c'), name: 'Still over' });
    t.equal(errorCodes.codeOf(still), 'STS-CORE-0161',
            'creates stay refused until the count is under the cap');

    const room = realms.count() + 1;
    const raised = config.setOverride('realms.maxCount', String(room));
    t.check(raised.ok, 'the cap can be raised by one above the live count',
            (raised.errors || []).join(' '));
    const againId = freshId('d');
    const again = realms.create({ id: againId, name: 'Under again' });
    t.check(again.ok, 'a create under the new cap succeeds',
            (again.errors || []).join(' '));
    if (again.ok) {
      made.push(againId);
    }

    const onRealm = realms.setOverride(id, 'realms.maxCount', '20');
    t.equal(errorCodes.codeOf(onRealm), 'STS-CORE-0014',
            'the cap cannot be set ON a realm');

    // realmContext() answers null while realms are off, even inside
    // realms.run(), so the lock below is invisible unless the feature is
    // on. A file that ran earlier may have left it off.
    if (config.value('realms.enabled') !== true) {
      const turned = config.setOverride('realms.enabled', 'true');
      if (!t.check(turned.ok, 'realms can be switched on for the lock',
                   (turned.errors || []).join(' '))) {
        log.debug("Leaving run(). Realms could not be switched on.");
        return;
      }
    }

    const realm = realms.get(id);
    realms.run(realm, function () {
      log.debug("Entering the non-default realm.");
      const problem = config.checkOverride('realms.maxCount', '30');
      t.check(!!problem, 'checkOverride refuses from inside a realm',
              problem || '');
      const wrote = config.setOverride('realms.maxCount', '30');
      t.equal(errorCodes.codeOf(wrote), 'STS-CORE-0162',
              'setOverride from inside a realm is STS-CORE-0162');
      const cleared = config.clearOverride('realms.maxCount');
      t.equal(errorCodes.codeOf(cleared), 'STS-CORE-0162',
              'clearOverride from inside a realm is STS-CORE-0162');
      const view = described('realms.maxCount');
      t.equal(view && view.editable, false,
              'the row is not editable from inside a realm');
      t.check(!!(view && view.editRefusal), 'the row says why',
              (view && view.editRefusal) || '');
      t.equal(view && view.restartReason, undefined,
              'the lock is not reported as a restart');
      const enabled = config.setOverride('realms.enabled', enabledText);
      t.check(enabled.ok,
              'realms.enabled is still set process-wide from inside a realm',
              (enabled.errors || []).join(' '));
      if (enabled.ok && !enabledWas) {
        config.clearOverride('realms.enabled');
      }
      log.debug("Leaving the non-default realm.");
    });

    const outside = described('realms.maxCount');
    t.equal(outside && outside.editable, true,
            'the row is editable in the default realm');
    t.equal(outside && outside.editRefusal, undefined,
            'the default realm is not given a refusal');

    realms.run(realms.current(), function () {
      log.debug("Entering the default realm.");
      const wrote = config.setOverride('realms.maxCount', String(room));
      t.check(wrote.ok, 'the default realm may set the cap',
              (wrote.errors || []).join(' '));
      const view = described('realms.maxCount');
      t.equal(view && view.editable, true,
              'the default realm still describes the row as editable');
      log.debug("Leaving the default realm.");
    });
  } finally {
    made.forEach(function (one) {
      try {
        realms.remove(one);
      } catch (e) {
        log.debug("Caught in run(): " + ((e && e.message) || e));
      }
    });
    if (wasOverride) {
      config.setOverride('realms.maxCount', capBefore);
    } else {
      config.clearOverride('realms.maxCount');
    }
    if (enabledWas) {
      if (config.text('realms.enabled') !== enabledText) {
        config.setOverride('realms.enabled', enabledText);
      }
    } else if (config.describe(settingRow('realms.enabled')).source ===
               'override') {
      config.clearOverride('realms.enabled');
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'realm_count_limit',
  describe: 'realms.maxCount caps creates and is set only in the default ' +
            'realm',
  run: run
};
