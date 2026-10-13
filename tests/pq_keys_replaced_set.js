// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pq_keys_replaced_set.js
//
// ---------------------------------------------------------------------------
// A REALM'S POST-QUANTUM KEYS SURVIVE ITS SET BEING REPLACED WHILE THEY ARE
// MADE (2026-09-27, CI run 36369109378).
//
// The cluster suite's FAPI 1.0 Advanced job failed because another node
// wrote the realm's next key generation while this process was making the
// realm's eleven post-quantum keys: `keystore.onAdopt()` dropped the set that
// had asked for them, the finished keys landed on that dropped set, and the
// rebuilt one — with neither the keys nor the promise of them — started a
// second generation on the next JWKS fetch, which ran past the portal's
// ten-second back-channel bound. `helpers.js`'s block above
// `pqKeysForAsync()` argues the fix.
//
// What this holds, in one process and against a throwaway realm, doing
// exactly what `onAdopt()` does to the cache:
//
//   1. a set rebuilt while the generation runs JOINS it — both sets end with
//      the same eleven keys, which a second generation could not give them;
//   2. a set rebuilt and never asked still ends up holding the keys;
//   3. the JWKS list a caller was promised before the replacement is the
//      realm's CURRENT set's curve keys, not the dropped set's.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const helpers = require('../common/helpers');

const log = require('bunyan').createLogger({ name: 'pq_keys_replaced_set',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = Date.now().toString(36);

// What `keystore.onAdopt()`'s listener in helpers.js does when another
// node's keys win: the cached set is dropped, and the next read rebuilds.
function replaceSet(id) {
  log.debug("Entering replaceSet().");
  helpers.stsKeysFor.existing().delete(id);
  const rebuilt = helpers.stsKeysFor.of(id);
  log.debug("Leaving replaceSet().");
  return rebuilt;
}

function kidsOf(list) {
  log.debug("Entering kidsOf().");
  log.debug("Leaving kidsOf().");
  return (list || []).map(function (k) {
    return k && k.kid;
  }).sort().join(',');
}

async function joined(t, id) {
  log.debug("Entering joined().");
  const first = helpers.stsKeysFor.of(id);
  if (first.pqKeys) {
    t.check(false, '0. the new realm holds no post-quantum keys yet',
            'it already had ' + first.pqKeys.length);
    log.debug("Leaving joined(). Already made.");
    return;
  }
  const promised = realms.run(realms.get(id), function () {
    return helpers.allSigningKeysAsync();
  });
  const second = replaceSet(id);
  t.check(second !== first && !second.pqKeys,
          '0. the replaced set is a new object with no post-quantum keys');
  const again = realms.run(realms.get(id), function () {
    return helpers.allSigningKeysAsync();
  });
  const lists = await Promise.all([promised, again]);
  t.check(!!second.pqKeys && second.pqKeys === first.pqKeys,
          '1. the rebuilt set joined the generation in flight: both hold ' +
          'the same eleven keys',
          'first=' + kidsOf(first.pqKeys) + ' second=' +
          kidsOf(second.pqKeys));
  const current = helpers.stsKeysFor.of(id);
  const want = kidsOf((current.extraKeys || []).concat(current.pqKeys));
  t.check(kidsOf(lists[0]) === want && kidsOf(lists[1]) === want,
          '3. both callers were answered with the current set\'s keys',
          'want=' + want + ' got=' + kidsOf(lists[0]) + ' / ' +
          kidsOf(lists[1]));
  log.debug("Leaving joined().");
}

async function landed(t, id) {
  log.debug("Entering landed().");
  const first = helpers.stsKeysFor.of(id);
  const promised = realms.run(realms.get(id), function () {
    return helpers.allSigningKeysAsync();
  });
  const second = replaceSet(id);
  await promised;
  t.check(!!second.pqKeys && second.pqKeys.length > 0 &&
          second.pqKeys === first.pqKeys,
          '2. a set rebuilt and never asked holds the keys the dropped set ' +
          'asked for',
          'second=' + kidsOf(second.pqKeys));
  log.debug("Leaving landed().");
}

async function run(t) {
  log.debug("Entering run().");
  const a = 'pqr-a-' + RUN;
  const b = 'pqr-b-' + RUN;
  realms.create({ id: a, name: 'Post-quantum keys, replaced set (joined)' });
  realms.create({ id: b, name: 'Post-quantum keys, replaced set (landed)' });
  try {
    await joined(t, a);
    await landed(t, b);
  } finally {
    realms.remove(a);
    realms.remove(b);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pq_keys_replaced_set',
  describe: 'a realm\'s post-quantum keys land on the set it holds when ' +
            'they finish, and a set rebuilt meanwhile joins the generation ' +
            'rather than starting a second (CI run 36369109378)',
  run: run
};
