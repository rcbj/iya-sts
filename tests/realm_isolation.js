'use strict';
//
// File: realm_isolation.js
//
// ===========================================================================
// A REALM'S IDENTITY REGISTER AND ITS REVOCATION SET ARE ITS OWN.
//
// Both were process-wide until 2026-08-25, both were process-wide ON PURPOSE,
// and the purpose stopped being true the day the embedded directory became a
// SUBTREE PER REALM (`ldap/CLAUDE.md`). The argument, in `admin_stats.js`'s own
// words, was that "the identity register mirrors the embedded directory, which
// is shared by every realm" — correct when it was written, and a leak the
// moment the second half of it stopped holding.
//
// What it produced was not an error anywhere. `/admin/users` under
// `/realm/acme` listed everybody who had ever signed in to the DEFAULT realm,
// and the realm's own directory reader then reported each of those people's
// entries as missing — because in that realm they genuinely were. Two pages of
// one console disagreeing, each of them sure. And on the metrics page one
// realm's `tokens.revoked` appeared under every realm, beside a `tokens.held`
// that was correctly partitioned.
//
// The revocation set had a second edge that is a REFUSAL rather than a
// disagreement: `POST /realm/acme/oauth2/revoke` could kill a jti issued by the
// default realm, which is a cross-realm write in the one protocol family whose
// realm support is published as `full`.
//
// WHY THIS IS HERE AND NOT IN THE PARENT PROJECT'S SUITE. The rule in
// tests/CLAUDE.md is "can it be asserted by driving the running service over
// HTTP?", and the leak itself can — two sign-ins and two `?format=json` reads
// show it. Three things put this file here anyway:
//
//   * The parent project's `sts/` gitlink is pinned at a commit from before
//     this repository was reorganised, so a guard written over there today
//     does not run against this code at all. See the root CLAUDE.md.
//   * What is actually being guarded is a MODULE CONTRACT — "a store that
//     holds per-realm state is declared `realms.map()` and not `new Map()`" —
//     and the assertions below are about that declaration rather than about
//     any endpoint. The two stores are reached directly; no route, no port.
//   * The purge case at the end is invisible over HTTP: it asserts that
//     removing a realm takes its register with it, and an HTTP caller cannot
//     tell "purged" from "a realm that never had anything".
//
// If a THIRD store is ever found to have been left process-wide for the same
// retired reason, it belongs in this file rather than in one of its own.
//
// ---------------------------------------------------------------------------
// THE THIRD ONE TURNED UP ON 2026-09-06 AND IS THE SCIM COUNTERS.
//
// `admin_stats.js`'s `scimCounts` was a plain object beside a file in which
// every other store — the endpoint calls, the token registry, the artifact
// list, the identity register, the revocation set, the claim sets — is
// `realms.map()`, `realms.arr()` or `realms.obj()`. Same shape of leak and the
// same retired reason: `/scim/v2` is realm-prefixed like every other endpoint
// here and writes into a directory that has been a SUBTREE PER REALM since
// 2026-08-25, so a provisioning client working in `/realm/acme` created
// entries in acme and was counted in the default realm's totals. One page
// reporting traffic that happened somewhere else, beside a directory count
// that was correctly partitioned — which is exactly what the register did.
//
// It surfaced when `/admin/scim/monitor` was written, because that page draws
// the counters and the directory side by side and the disagreement stops being
// something a reader has to notice across two tabs.
//
// What is asserted here is the DECLARATION, as it is for the other two: a
// store that holds per-realm state is `realms.obj()` and not `{}`. The
// counters' own contract — a refused caller is not a client, an absent
// measurement is null, a counter cannot throw — is `tests/scim_monitor.js`.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: a
// developer with CONFIG_FILE exported would otherwise be asserting against
// their own appconfig rather than against the service as it ships.
delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const stats = require('../common/admin_stats');

// ---------------------------------------------------------------------------
// Create a realm, hand it to `fn`, and remove it however that goes. The realm
// table is process-wide, so a realm left
// behind changes what a later test in the same run resolves. Same shape as
// config_realm_layer.js's, deliberately — two spellings of "clean up after
// yourself" is how one of them comes to be the one nobody follows.
// ---------------------------------------------------------------------------
function withRealm(t, id, fn) {
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    return undefined;
  }
  try {
    return fn(made.realm);
  } finally {
    realms.remove(id);
  }
}

// Every identity the register lists in whatever realm is ambient when this is
// called. `userRows()` is what `/admin/users` and `/admin/metrics` are both
// built from, so asserting on it is asserting on both pages at once.
function keysHere() {
  return stats.userRows().map(function (row) { return row.key; });
}

function has(list, key) {
  return list.indexOf(key) >= 0;
}

// ---------------------------------------------------------------------------
// 1. THE IDENTITY REGISTER.
//
// Recorded in a realm, invisible outside it; recorded outside, invisible in it.
// Both directions are asserted because the store is one Map per realm and a
// half-done conversion — say, writing through the facade and reading a stale
// module-level binding — would pass one of them.
// ---------------------------------------------------------------------------
function checkRegister(t) {
  t.log.info('the identity register — who a realm has SEEN');

  const before = keysHere();
  t.check(!has(before, 'iso-inside') && !has(before, 'iso-outside'),
          'the default realm starts without either of this test\'s names',
          before.join(', ') || '(nobody)');

  withRealm(t, 'iso-register', function (realm) {
    realms.run(realm, function () {
      stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                   presented: 'iso-inside' });
    });
    stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                 presented: 'iso-outside' });

    const inside = realms.run(realm, keysHere);
    const outside = keysHere();

    t.check(has(inside, 'iso-inside'),
            'the realm lists the person who authenticated in it',
            inside.join(', ') || '(nobody)');
    t.check(!has(inside, 'iso-outside'),
            'and does NOT list the person who authenticated in the default realm',
            inside.join(', ') || '(nobody)');
    t.check(has(outside, 'iso-outside'),
            'the default realm lists its own person',
            outside.join(', ') || '(nobody)');
    t.check(!has(outside, 'iso-inside'),
            'and does NOT list the realm\'s',
            outside.join(', ') || '(nobody)');

    // The number the metrics page prints, from the same rows. Asserted
    // separately because it is read from `snapshot()` rather than from
    // `userRows()`, and a partition that reached one and not the other is
    // exactly the kind of half-fix that reads as working.
    const insideKnown = realms.run(realm, function () {
      return stats.snapshot().users.known;
    });
    t.equal(insideKnown, inside.length,
            'the realm\'s metrics count agrees with the realm\'s list');
  });
}

// ---------------------------------------------------------------------------
// 2. ONE NAME, TWO REALMS, TWO PEOPLE.
//
// The register is keyed on the local name and this service checks no password,
// so `alice` in two realms is two entries in two directory subtrees. The
// counts have to be separate as well as the rows: a shared record found by key
// would pass the row assertions above and still show one realm the other's
// authentication count.
// ---------------------------------------------------------------------------
function checkSameName(t) {
  t.log.info('one name in two realms');

  withRealm(t, 'iso-samename', function (realm) {
    stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                 presented: 'iso-shared' });
    stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                 presented: 'iso-shared' });
    realms.run(realm, function () {
      stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                   presented: 'iso-shared' });
    });

    // `userDetail()` answers { user, tokens, artifacts } — the row is inside
    // it, and reading `.authentications` off the wrapper gives `undefined`,
    // which `equal()` reports honestly and which is how this line came to be
    // written twice.
    const outside = stats.userDetail('iso-shared');
    const inside = realms.run(realm, function () {
      return stats.userDetail('iso-shared');
    });

    t.check(!!outside && !!inside,
            'both realms know somebody by that name',
            'default=' + !!outside + ', realm=' + !!inside);
    if (outside && inside) {
      t.equal(outside.user.authentications, 2,
              'the default realm counted its own two authentications');
      t.equal(inside.user.authentications, 1,
              'and the realm counted its own one');
    }
  });
}

// ---------------------------------------------------------------------------
// 3. THE REVOCATION SET.
//
// A jti is unique across realms, so nothing legitimate ever crossed this line
// and every assertion below was true before the partition EXCEPT the negative
// one — which is the whole point, and the reason the negative is written
// first.
// ---------------------------------------------------------------------------
function checkRevocation(t) {
  t.log.info('the revocation set');

  withRealm(t, 'iso-revoke', function (realm) {
    const jti = 'iso-jti-' + Date.now();
    realms.run(realm, function () { stats.revoke(jti, 'this test'); });

    t.check(!stats.isRevoked(jti),
            'a jti revoked inside a realm is NOT revoked in the default realm',
            jti);
    t.check(realms.run(realm, function () { return stats.isRevoked(jti); }),
            'and IS revoked inside the realm that revoked it',
            jti);

    // The count beside `tokens.held` on the metrics page.
    const outsideCount = stats.revokedCount();
    const insideCount = realms.run(realm, function () {
      return stats.revokedCount();
    });
    t.check(insideCount > outsideCount,
            'the realm\'s revocation count is its own',
            'realm=' + insideCount + ', default=' + outsideCount);

    // Restoring is per realm too, and it is worth its own line: `restore()`
    // deletes from the set and clears a flag on the token record, and a
    // partition that reached the set and not the lookup would leave a jti
    // reported revoked after it had been restored.
    realms.run(realm, function () { stats.restore(jti); });
    t.check(!realms.run(realm, function () { return stats.isRevoked(jti); }),
            'restoring inside the realm un-revokes it there', jti);
  });
}

// ---------------------------------------------------------------------------
// 4. REMOVING A REALM TAKES ITS REGISTER WITH IT.
//
// `realms.map()` registers a purge; a plain Map cannot. This is the assertion
// no HTTP caller could make — after the realm is gone its pages are gone too,
// so "purged" and "never existed" look identical from outside. In process the
// id can be created a second time and asked what it remembers, which must be
// nothing.
// ---------------------------------------------------------------------------
function checkPurge(t) {
  t.log.info('removing a realm');

  withRealm(t, 'iso-purge', function (realm) {
    realms.run(realm, function () {
      stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                                   presented: 'iso-ghost' });
      stats.revoke('iso-ghost-jti', 'this test');
    });
    const seen = realms.run(realm, keysHere);
    t.check(has(seen, 'iso-ghost'), 'the realm has somebody to forget',
            seen.join(', ') || '(nobody)');
  });

  // Same id, second life. `withRealm` above removed the first one.
  withRealm(t, 'iso-purge', function (realm) {
    const seen = realms.run(realm, keysHere);
    t.check(!has(seen, 'iso-ghost'),
            'a realm created again with the same id remembers none of the ' +
            'first one\'s people',
            seen.join(', ') || '(nobody)');
    t.check(!realms.run(realm, function () {
              return stats.isRevoked('iso-ghost-jti');
            }),
            'and none of its revocations', 'iso-ghost-jti');
  });
}

// ---------------------------------------------------------------------------
// 5. THE SCIM COUNTERS. The third store, added 2026-09-06.
//
// Two directions, because a store that is per realm in one direction only is
// the leak with extra steps: what happens inside a realm must not be visible
// outside it, and what happened outside must not appear inside. The register
// above is asserted both ways for the same reason.
// ---------------------------------------------------------------------------
function checkScimCounters(t) {
  t.log.info('the SCIM traffic counters');

  // A known state to measure from. This is the counters' own reset — there is
  // deliberately no console control that calls it — and it clears THIS
  // REALM'S, which is the whole property under test.
  stats.resetScimForTests();
  stats.recordScim({ operation: 'create', resourceType: 'User', status: 201,
                     ok: true, authScheme: 'basic', principal: 'iso-outside',
                     ms: 1, bytes: 1 });
  const outsideBefore = stats.scimMonitorSnapshot();
  t.equal(outsideBefore.calls, 1,
          'the default realm has taken one SCIM call');

  withRealm(t, 'iso-scim', function (realm) {
    const inside = realms.run(realm, function () {
      stats.recordScim({ operation: 'delete', resourceType: 'Group',
                         status: 204, ok: true, authScheme: 'bearer',
                         principal: 'iso-inside', isClient: true,
                         ms: 2, bytes: 2 });
      return stats.scimMonitorSnapshot();
    });

    t.equal(inside.calls, 1,
            'THE REALM COUNTS ITS OWN CALL AND NOT THE ONE OUTSIDE IT. This ' +
            'was 2 until the counters were declared realms.obj(), which is ' +
            'the whole of the leak: a client provisioning under /realm/acme ' +
            'was counted in the default realm\'s totals, beside a directory ' +
            'count that was correctly partitioned');
    t.equal(inside.realm.id, 'iso-scim',
            'and the snapshot says which realm it is for, so a reader cannot ' +
            'mistake one for the other');
    t.check(inside.clients.length === 1 &&
            inside.clients[0].principal === 'iso-inside',
            'the client list is the realm\'s own too — the register above ' +
            'leaked in exactly this way, and a client table is the same kind ' +
            'of claim about who has been here',
            'clients: ' + inside.clients.map(function (row) {
              return row.principal;
            }).join(', '));

    const outsideAfter = stats.scimMonitorSnapshot();
    t.equal(outsideAfter.calls, 1,
            'AND THE OTHER DIRECTION: the realm\'s call did not appear in ' +
            'the default realm either. A store that partitions one way only ' +
            'is the leak with extra steps');
    t.check(!outsideAfter.clients.some(function (row) {
              return row.principal === 'iso-inside';
            }),
            'nor did its client', 'iso-inside');
  });

  // A removed realm takes its counters with it, which is what `realms.obj()`
  // means and is the case an HTTP caller cannot see: "purged" and "a realm
  // that never had any traffic" answer identically from outside.
  const ghost = realms.create({ id: 'iso-scim-ghost', name: 'iso-scim-ghost',
                                description: 'Created by ' + __filename });
  if (ghost.ok) {
    realms.run(ghost.realm, function () {
      stats.recordScim({ operation: 'list', resourceType: 'User', status: 200,
                         ok: true, authScheme: 'basic', principal: 'iso-ghost',
                         ms: 1, bytes: 1 });
    });
    realms.remove('iso-scim-ghost');
    const remade = realms.create({ id: 'iso-scim-ghost',
                                   name: 'iso-scim-ghost',
                                   description: 'Created by ' + __filename });
    if (remade.ok) {
      const back = realms.run(remade.realm, function () {
        return stats.scimMonitorSnapshot();
      });
      t.equal(back.calls, 0,
              'a realm removed and remade has none of the old one\'s ' +
              'traffic — the counters went with it');
      realms.remove('iso-scim-ghost');
    } else {
      t.bad('the throwaway realm could not be remade',
            (remade.errors || []).join(' '));
    }
  } else {
    t.bad('the throwaway realm could not be created',
          (ghost.errors || []).join(' '));
  }

  // Left as it was found, so that a later file in the same run is not looking
  // at this one's traffic.
  stats.resetScimForTests();
}

// ---------------------------------------------------------------------------
// 6. WITH NO REALM DEFINED, NOTHING ABOVE IS OBSERVABLE.
//
// The property the whole realm design rests on, asserted here for the two
// stores this file is about: in a service with no realms defined there is
// exactly one partition, so the register and the revocation set behave as the
// plain Map and Set they replaced. Every realm this file creates is removed by
// `withRealm`, which is what makes the assertion meaningful at this point in
// the run rather than merely true.
// ---------------------------------------------------------------------------
function checkDefaultUnchanged(t) {
  t.log.info('a service with no realms defined');

  t.equal(realms.count(), 1,
          'this test cleaned up after itself — only the default realm is left');
  t.check(!realms.active(),
          'and with none defined the realm layer reports itself inactive');

  const jti = 'iso-plain-' + Date.now();
  stats.revoke(jti, 'this test');
  t.check(stats.isRevoked(jti),
          'a revocation in the default realm reads back in the default realm',
          jti);
  stats.restore(jti);

  stats.recordAuthentication({ protocol: 'Test', method: 'in process',
                               presented: 'iso-plain' });
  t.check(has(keysHere(), 'iso-plain'),
          'and an authentication in the default realm reads back there',
          'iso-plain');
}

function run(t) {
  checkRegister(t);
  checkSameName(t);
  checkRevocation(t);
  checkPurge(t);
  checkScimCounters(t);
  checkDefaultUnchanged(t);
}

module.exports = {
  name: 'realm_isolation',
  describe: 'a realm\'s identity register and revocation set are its own',
  run: run
};
