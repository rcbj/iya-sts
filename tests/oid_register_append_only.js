// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: oid_register_append_only.js
//
// ===========================================================================
// THE OID REGISTER IS APPEND-ONLY (#1579's review, 2026-11-13).
//
// `models/directory/oid_register.json` numbers this service's own attribute
// types and object classes under `<root>.1.1.n` and `<root>.1.2.n`, and
// `models/CLAUDE.md` says a number "is assigned once and never reused". Nothing
// held that: two branches both took 746 for different names during #1579, and
// a renumber of a released attribute would change the OID every published
// schema, every exported LDIF and every RFC 4512 definition a consumer loaded
// names it by — silently, since every test compares the register with itself.
//
// `models/directory/oid_register.released.json` is the frozen copy: what
// v1.0.0 shipped (attributes 1-745, classes 1-23) and what develop had
// assigned when the check was written (746-749). This file holds:
//
//   A. every released name is still in the register, with the SAME number,
//      and the root is the released root;
//   B. no number in the register is held by two names (the 746 case: two
//      branches each appending "the next one");
//   C. a name not yet released takes a number above every released one, so
//      a gap a release left can never be filled by a different name;
//   D. where the repository's history is at hand (a checkout, not the tests
//      image), the frozen copy itself holds every assignment the `v1.0.0`
//      tag's register made — so the frozen copy cannot be edited to agree
//      with a renumber.
//
// WHY IN PROCESS: every claim is a comparison between files in this
// repository, as `tests/model_directory.js`'s are.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const log = require('bunyan').createLogger({ name: 'oid_register_append_only',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const DIR = path.join(ROOT, 'models', 'directory');
const KINDS = ['attributes', 'classes'];

/**
 * Reads a register-shaped JSON file.
 *
 * @param {string} file - the path
 * @returns {object} the parsed register
 */
function readJson(file) {
  log.debug("Entering readJson().");
  const out = JSON.parse(fs.readFileSync(file, 'utf8'));
  log.debug("Leaving readJson().");
  return out;
}

/**
 * Every way `current` breaks the rules `released` sets, as sentences.
 *
 * @param {object} released - the frozen assignments
 * @param {object} current - the register
 * @returns {string[]} the problems, empty when it holds
 */
function problemsOf(released, current) {
  log.debug("Entering problemsOf().");
  const out = [];
  if (released.root !== current.root) {
    out.push('the root moved from ' + released.root + ' to ' + current.root);
  }
  KINDS.forEach(function (kind) {
    const was = released[kind] || {};
    const now = current[kind] || {};
    let highest = 0;
    Object.keys(was).forEach(function (name) {
      highest = Math.max(highest, Number(was[name]));
      if (!Object.prototype.hasOwnProperty.call(now, name)) {
        out.push(kind + ': released ' + name + ' (' + was[name] +
                 ') is gone');
      } else if (now[name] !== was[name]) {
        out.push(kind + ': released ' + name + ' was ' + was[name] +
                 ' and is now ' + now[name]);
      }
    });
    const holders = new Map();
    Object.keys(now).forEach(function (name) {
      const n = now[name];
      holders.set(n, (holders.get(n) || []).concat(name));
      if (!Object.prototype.hasOwnProperty.call(was, name) &&
          !(Number(n) > highest)) {
        out.push(kind + ': unreleased ' + name + ' took ' + n +
                 ', not above the highest released number ' + highest);
      }
    });
    holders.forEach(function (names, n) {
      if (names.length > 1) {
        out.push(kind + ': ' + n + ' is held by ' + names.join(' and '));
      }
    });
  });
  log.debug("Leaving problemsOf(). " + out.length);
  return out;
}

/**
 * The `v1.0.0` tag's register, where the repository's history can be asked.
 *
 * @returns {object|null} the register, or null where there is no history
 */
function taggedRegister() {
  log.debug("Entering taggedRegister().");
  const shown = cp.spawnSync('git', ['show',
    'v1.0.0:models/directory/oid_register.json'],
  { cwd: ROOT, encoding: 'utf8', timeout: 20000 });
  if (shown.status !== 0 || !shown.stdout) {
    log.debug("Leaving taggedRegister(). No history.");
    return null;
  }
  let out = null;
  try {
    out = JSON.parse(shown.stdout);
  } catch (e) {
    log.debug("Caught in taggedRegister(): " + ((e && e.message) || e));
    out = null;
  }
  log.debug("Leaving taggedRegister().");
  return out;
}

function run(t) {
  log.debug("Entering run().");
  const released = readJson(path.join(DIR, 'oid_register.released.json'));
  const current = readJson(path.join(DIR, 'oid_register.json'));

  t.log.info('=== A-C. the register against the released assignments ===');
  const problems = problemsOf(released, current);
  t.check(problems.length === 0,
          'A-C every released OID is unchanged, no number has two names, ' +
          'and every new name is numbered above the released ones',
          problems.join('; '));
  t.check(Object.keys(released.attributes).length >= 745 &&
          Object.keys(released.classes).length >= 23,
          'the frozen copy holds at least what v1.0.0 shipped');

  t.log.info('=== the check refuses what it is for ===');
  const copy = function () {
    return JSON.parse(JSON.stringify(current));
  };
  const renumbered = copy();
  renumbered.attributes.acmeAllowedProfiles = 900;
  t.check(/acmeAllowedProfiles was 1 and is now 900/.test(
    problemsOf(released, renumbered).join(';')),
  'a released attribute renumbered is refused');
  const removed = copy();
  delete removed.classes.xacmlPolicy;
  t.check(/released xacmlPolicy \(23\) is gone/.test(
    problemsOf(released, removed).join(';')),
  'a released class removed is refused (its number would be free)');
  const twice = copy();
  twice.attributes.someNewName = 746;
  t.check(/746 is held by stsAuthzenApplication and someNewName/.test(
    problemsOf(released, twice).join(';')),
  'two names on one number (the 746 case) are refused');
  const gap = copy();
  gap.attributes.someNewName = 3;
  t.check(/unreleased someNewName took 3/.test(
    problemsOf(released, gap).join(';')),
  'a new name below the released numbers is refused');
  // THE NEXT NUMBER IS THE REGISTER'S, not a constant: a branch that
  // numbers a new attribute (#931 took 750) moves it.
  const next = copy();
  const highest = Math.max.apply(null, Object.keys(next.attributes)
    .map(function (name) {
      return Number(next.attributes[name]) || 0;
    }));
  next.attributes.someNewName = highest + 1;
  t.equal(problemsOf(released, next).join(';'), '',
          'a new name on the next number is accepted');
  const moved = copy();
  moved.root = '1.3.6.1.4.1.32473';
  t.check(/root moved/.test(problemsOf(released, moved).join(';')),
          'the root moving is refused');

  t.log.info('=== D. the frozen copy against the v1.0.0 tag ===');
  const tagged = taggedRegister();
  if (!tagged) {
    t.log.info('no repository history here (the tests image has none): ' +
               'the v1.0.0 comparison is made on a checkout');
  } else {
    const missing = [];
    KINDS.forEach(function (kind) {
      Object.keys(tagged[kind] || {}).forEach(function (name) {
        if (released[kind][name] !== tagged[kind][name]) {
          missing.push(kind + ' ' + name + ' ' + tagged[kind][name]);
        }
      });
    });
    t.check(missing.length === 0,
            'D the frozen copy holds every v1.0.0 assignment unchanged',
            missing.slice(0, 20).join('; '));
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oid_register_append_only',
  describe: 'the OID register is append-only: no released number moves or ' +
            'is reused (#1579\'s review)',
  run: run
};
