// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: unstorable_text.js
//
// ===========================================================================
// A VALUE THE STORE CAN NEVER HOLD (#1463).
//
// A NUL in a setting stopped every store write in the process: the fuzz run
// on 4e9585b6a stored one in `saml11.nameIdFormat` and every later flush
// failed with 22P05. This file holds the two halves of the fix:
//
//   A. every door refuses the text, naming the setting and never the value;
//   B. a permanent data error in a realm or settings save drops only what
//      cannot be stored, and a non-permanent one is still thrown.
//
// WHY IN PROCESS: the door is the registry's, and the backstop is reachable
// only by a value the door refuses, so it is driven directly. The SQLSTATEs
// the save stands in for were read from PostgreSQL 18: `\u0000` is 22P05 and
// a lone surrogate 22P02.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const persistence = require('../persistence/persistence');

const log = require('bunyan').createLogger({ name: 'unstorable_text',
  level: process.env.LOG_LEVEL || 'info' });

const KEY = 'saml11.nameIdFormat';
const NUL = 'a\u0000b';
const LONE = 'a\ud800b';
const STAMP = Date.now().toString(36);
const ID = 'ut-' + STAMP;

function theSettingDoor(t) {
  log.debug("Entering theSettingDoor().");
  [NUL, LONE, '\udc00'].forEach(function (value) {
    const problem = config.checkOverride(KEY, value, true);
    t.check(!!problem, 'the setting door refuses ' + JSON.stringify(value));
    t.check(String(problem).indexOf(value) < 0,
             'the refusal does not quote the value');
    t.check(config.checkOverrideCode(KEY, value, true) === 'STS-CORE-0171',
             'the refusal is STS-CORE-0171');
  });
  t.check(config.checkOverride(KEY, 'a😀b', true) === null,
           'a whole surrogate pair is still accepted');
  t.check(config.unstorableText({ a: ['x', { b: NUL }] }),
           'a NUL at depth is found');
  t.check(config.unstorableText({ [NUL]: 'x' }), 'a NUL in a key is found');
  t.check(!config.unstorableText({ a: ['x', 1, null, true] }),
           'clean values are not');
  log.debug("Leaving theSettingDoor().");
}

function theRealmDoors(t) {
  log.debug("Entering theRealmDoors().");
  const bad = realms.create({ id: ID + '-x', name: NUL });
  t.check(!bad.ok && errorCodes.codeOf(bad) === 'STS-CORE-0171',
           'a realm created with a NUL in its name is refused');
  t.check(!realms.get(ID + '-x'), 'and is not made');
  const made = realms.create({ id: ID, name: 'plain' });
  t.check(made.ok, 'a clean realm is made');
  const set = realms.setOverride(ID, KEY, NUL);
  t.check(!set.ok && errorCodes.codeOf(set) === 'STS-CORE-0171',
           'a realm override with a NUL is refused');
  const upd = realms.update(ID, { description: LONE });
  t.check(!upd.ok && errorCodes.codeOf(upd) === 'STS-CORE-0171',
           'a description with a lone surrogate is refused');
  t.check(realms.get(ID).description === '', 'and nothing was changed');
  const whole = realms.update(ID, { overrides: { [KEY]: NUL } });
  t.check(!whole.ok, 'a whole override object with a NUL is refused');
  log.debug("Leaving theRealmDoors().");
}

// PostgreSQL's answer, for a part holding text a `jsonb` cannot.
function refusing(sent) {
  log.debug("Entering refusing().");
  log.debug("Leaving refusing().");
  return function (part) {
    if (config.unstorableText(part.set || part.upserts)) {
      const err = new Error('unsupported Unicode escape sequence');
      err.code = '22P05';
      return Promise.reject(err);
    }
    sent.push(part);
    return Promise.resolve();
  };
}

async function theRealmBackstop(t) {
  log.debug("Entering theRealmBackstop().");
  const sent = [];
  const cause = Object.assign(new Error('x'), { code: '22P05' });
  const row = { id: 'r1', name: 'ok', description: NUL,
                overrides: { good: 'y', bad: NUL } };
  await persistence.saveRealmsIsolated({
    removed: ['gone'],
    upserts: [
      { row: row, name: true, description: true,
        set: { good: 'y', bad: NUL }, cleared: ['c'] },
      { row: { id: 'r2', name: 'two', description: '', overrides: { k: 'v' } },
        name: true, description: false, set: { k: 'v' }, cleared: [] }
    ]
  }, refusing(sent), cause);
  t.check(sent.length === 3, 'the removal and both realms were each written');
  t.check(sent[0].removed[0] === 'gone', 'the removal is not lost');
  const first = sent[1].upserts[0];
  t.check(first.set.good === 'y' && !('bad' in first.set),
           'the poison key is dropped and the good key beside it kept');
  t.check(first.row.overrides.good === 'y' && !('bad' in first.row.overrides),
           'the row carries no poison either');
  t.check(first.description === false && first.row.description === '',
           'a poison description is not written');
  t.check(first.cleared[0] === 'c', 'a cleared key is kept');
  t.check(sent[2].upserts[0].row.id === 'r2', 'the next realm still commits');

  const stubborn = [];
  await persistence.saveRealmsIsolated({ removed: [], upserts: [
    { row: { id: 'a', name: 'a', description: '', overrides: {} },
      name: true, description: false, set: {}, cleared: [] },
    { row: { id: 'b', name: 'b', description: '', overrides: {} },
      name: true, description: false, set: {}, cleared: [] }
  ] }, function (part) {
    if (part.upserts[0].row.id === 'a') {
      return Promise.reject(Object.assign(new Error('too long'),
                                          { code: '22001' }));
    }
    stubborn.push(part);
    return Promise.resolve();
  }, cause);
  t.check(stubborn.length === 1,
           'a realm failing for another class-22 reason costs only itself');

  let thrown = null;
  await persistence.saveRealmsIsolated({ removed: [], upserts: [
    { row: { id: 'a', name: 'a', description: '', overrides: {} },
      name: true, description: false, set: {}, cleared: [] }
  ] }, function () {
    return Promise.reject(Object.assign(new Error('deadlock'),
                                        { code: '40P01' }));
  }, cause).catch(function (e) {
    thrown = e;
  });
  t.check(thrown && thrown.code === '40P01',
           'a deadlock is thrown, for the flush to retry');
  log.debug("Leaving theRealmBackstop().");
}

async function theSettingsBackstop(t) {
  log.debug("Entering theSettingsBackstop().");
  const sent = [];
  const cause = Object.assign(new Error('x'), { code: '22P05' });
  await persistence.saveOverridesIsolated(
    { set: { a: '1', b: NUL, c: '3' }, cleared: ['z'], live: {} },
    refusing(sent), cause);
  t.check(sent.length === 3, 'the clear and the two good keys are written');
  t.check(sent[0].cleared[0] === 'z', 'the clear is not lost');
  t.check(sent[1].set.a === '1' && sent[2].set.c === '3',
           'the keys on both sides of the poison are written');
  let thrown = null;
  await persistence.saveOverridesIsolated(
    { set: { a: '1' }, cleared: [], live: {} },
    function () {
      return Promise.reject(Object.assign(new Error('gone'),
                                          { code: '57P01' }));
    }, cause).catch(function (e) {
    thrown = e;
  });
  t.check(thrown && thrown.code === '57P01', 'an outage is thrown');
  log.debug("Leaving theSettingsBackstop().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    theSettingDoor(t);
    theRealmDoors(t);
    await theRealmBackstop(t);
    await theSettingsBackstop(t);
  } finally {
    if (realms.get(ID)) {
      realms.remove(ID);
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'unstorable_text',
  describe: 'a value the store can never hold is refused at every door, and ' +
            'one that reaches a realm or settings save costs only itself',
  run: run
};
