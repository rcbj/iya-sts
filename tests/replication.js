'use strict';
//
// File: replication.js
//
// ===========================================================================
// SEVERAL PROCESSES AGAINST ONE STORE, AND THE FOUR WAYS THAT GOES WRONG
// SILENTLY.
//
// Until 2026-09-06 this service said, in `persistence/CLAUDE.md` and in
// `persistence.js`'s header, that **persistence is not coordination**: two
// processes each held their own copy and neither saw the other's writes. This
// is the test for the phase that closed it.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Every failure below is invisible from outside and three of them are
// invisible from inside too, for a while:
//
//   * **APPLYING YOUR OWN WRITES.** A process that does not skip its own rows
//     re-applies its own work, journals it again, and writes it back — and
//     with two processes that is an exchange that never ends. Both services
//     answer correctly the whole time; what shows is a database doing
//     thousands of writes a second while nothing is happening.
//   * **APPLYING OUT OF ORDER.** Two writes to one key applied in the wrong
//     order means the loser of a race wins on the reader. Nothing errors. The
//     wrong value is a perfectly good value.
//   * **ADVANCING PAST A FAILURE.** A high-water mark moved before the apply
//     succeeded skips changes for ever. The gap is permanent and there is
//     nothing anywhere that names it.
//   * **ONE BAD ROW WEDGING THE PAGE.** The opposite mistake: a single row
//     that will not apply stops every later change, and the process silently
//     stops converging while reporting that it is coordinating.
//
// None of those can be asked of a running service over HTTP, and reproducing
// them against a real database would mean two containers and a race. Here they
// are a stub driver and a list.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const replication = require('../persistence/persistence_replication');

// ---------------------------------------------------------------------------
// A DRIVER THAT IS A CHANGE LOG AND NOTHING ELSE. `changesSince()` does the
// two things the real one does and that everything here depends on: it filters
// out this process's own rows, and it pages.
// ---------------------------------------------------------------------------
function fakeDriver(me) {
  const rows = [];
  let seq = 0;
  return {
    rows: rows,
    origin: function () { return me; },
    // A row from somebody else, as `recordChanges()` would have written it.
    write: function (origin, kind, realm, key) {
      seq++;
      rows.push({ seq: seq, origin: origin, kind: kind,
                  realm: realm || '', key: key || '' });
      return seq;
    },
    latestChangeSeq: function () { return Promise.resolve(seq); },
    // -----------------------------------------------------------------------
    // **IT DOES NOT FILTER BY ORIGIN, DELIBERATELY**, and the first version of
    // this file did. The real driver filters in SQL (`origin <> $2`), so a
    // stub that filtered too would have made the "a process skips its own
    // rows" assertions below a test OF THE STUB — green whatever
    // `persistence_replication.js` did. Handing over everything is what makes
    // them a test of the module's own skip, which is the second of the two
    // places that protection lives.
    // -----------------------------------------------------------------------
    changesSince: function (after, limit) {
      return Promise.resolve(rows.filter(function (row) {
        return row.seq > after;
      }).slice(0, limit));
    },
    // No `watchChanges`: the nudge is deliberately absent here, because the
    // whole claim under test is that the POLL is the contract and everything
    // below has to hold without a notification ever arriving.
    changeCeiling: function () { return Promise.resolve(seq); }
  };
}

// ---------------------------------------------------------------------------
// `persistence.coordinate` IS RESTART-ONLY, so it is varied through the
// ENVIRONMENT and not through `setOverride()` — which refuses a restart-only
// row, correctly, and would leave every assertion below running against the
// default. That is `tests/keystore.js`'s reasoning beside its own three
// variables, and `config.js` reads `process.env` per call, so this takes
// effect immediately.
//
// It was `setOverride()` in the first version and the last two assertions in
// this file failed because of it — which is the useful half: the refusal is
// SILENT to a caller that does not check, so a test written this way passes
// wherever the default happens to be the value it wanted.
// ---------------------------------------------------------------------------
function coordinate(on) {
  if (on === null) {
    delete process.env.STS_PERSISTENCE_COORDINATE;
    return;
  }
  process.env.STS_PERSISTENCE_COORDINATE = on ? 'true' : 'false';
}

async function run(t) {
  coordinate(true);

  // -------------------------------------------------------------------------
  // 1. A PROCESS DOES NOT APPLY ITS OWN WRITES.
  // -------------------------------------------------------------------------
  t.log.info('=== a process skips its own rows ===');
  replication.reset();
  const driver = fakeDriver('me');
  const applied = [];
  driver.write('me', 'directory', '', 'cn=mine');
  driver.write('them', 'directory', '', 'cn=theirs');

  await replication.start(driver, {
    directory: function (change) { applied.push(change.key); }
  });
  await replication.pull();

  t.equal(applied.join(','), '',
          'NOTHING WAS APPLIED YET — the high-water mark is taken at start(), ' +
          'so a process that has just restored the whole store treats ' +
          'everything already committed as seen rather than replaying the ' +
          'entire history of the deployment on the way up');

  driver.write('me', 'directory', '', 'cn=mine-again');
  driver.write('them', 'directory', '', 'cn=theirs-again');
  await replication.pull();

  t.equal(applied.join(','), 'cn=theirs-again',
          'ANOTHER PROCESS\'S WRITE IS APPLIED AND THIS PROCESS\'S IS NOT. ' +
          'Without the second half, two processes exchange one row for ever: ' +
          'each applies its own write, journals it, flushes it, and wakes the ' +
          'other');

  // -------------------------------------------------------------------------
  // 2. IN COMMIT ORDER.
  // -------------------------------------------------------------------------
  t.log.info('=== in the order they were committed ===');
  replication.reset();
  const ordered = fakeDriver('me');
  const order = [];
  await replication.start(ordered, {
    minted: function (change) { order.push(change.key); }
  });
  ordered.write('them', 'minted', '', 'first');
  ordered.write('them', 'minted', '', 'second');
  ordered.write('them', 'minted', '', 'third');
  await replication.pull();
  t.equal(order.join(','), 'first,second,third',
          'changes arrive in `seq` order — which is COMMIT order, because ' +
          'seq is a bigserial assigned inside the transaction rather than a ' +
          'timestamp taken by whichever process happened to be writing');

  // -------------------------------------------------------------------------
  // 3. THE SAME KEY TWICE IN ONE PAGE IS READ ONCE.
  // -------------------------------------------------------------------------
  t.log.info('=== a key named twice is read once ===');
  replication.reset();
  const noisy = fakeDriver('me');
  let reads = 0;
  await replication.start(noisy, {
    directory: function () { reads++; }
  });
  noisy.write('them', 'directory', '', 'cn=busy');
  noisy.write('them', 'directory', '', 'cn=busy');
  noisy.write('them', 'directory', '', 'cn=busy');
  await replication.pull();
  t.equal(reads, 1,
          'THE PAGE IS COALESCED. A pointer says "look at this key", so ten ' +
          'mentions of one key are one read of the latest state — and the ' +
          'LAST one is also the correct one');

  // -------------------------------------------------------------------------
  // 4. THE HIGH-WATER MARK DOES NOT ADVANCE PAST A FAILURE.
  // -------------------------------------------------------------------------
  t.log.info('=== a failed pull loses nothing ===');
  replication.reset();
  const flaky = fakeDriver('me');
  let attempts = 0;
  const got = [];
  await replication.start(flaky, {
    directory: function (change) { got.push(change.key); }
  });
  flaky.write('them', 'directory', '', 'cn=one');
  const realChanges = flaky.changesSince;
  flaky.changesSince = function () {
    attempts++;
    return Promise.reject(new Error('the database went away'));
  };
  await replication.pull();
  t.equal(got.length, 0, 'a pull that could not read applied nothing');
  t.check(replication.status().lastError.indexOf('went away') >= 0,
          'and the failure is REPORTED rather than swallowed — a process that ' +
          'is behind and says it is coordinating is worse than one that ' +
          'admits it',
          replication.status().lastError);

  flaky.changesSince = realChanges;
  await replication.pull();
  t.equal(got.join(','), 'cn=one',
          'AND THE SAME CHANGE IS APPLIED WHEN THE DATABASE COMES BACK. The ' +
          'mark was not advanced, so nothing was skipped — a gap here would ' +
          'be permanent and nothing anywhere would name it');

  // -------------------------------------------------------------------------
  // 5. ONE BAD ROW DOES NOT WEDGE THE PAGE.
  // -------------------------------------------------------------------------
  t.log.info('=== one bad row is not the whole page ===');
  replication.reset();
  const mixed = fakeDriver('me');
  const survived = [];
  await replication.start(mixed, {
    directory: function (change) {
      if (change.key === 'cn=poison') {
        throw new Error('this row cannot be applied here');
      }
      survived.push(change.key);
    }
  });
  mixed.write('them', 'directory', '', 'cn=poison');
  mixed.write('them', 'directory', '', 'cn=fine');
  await replication.pull();
  t.equal(survived.join(','), 'cn=fine',
          'THE ROW AFTER THE BAD ONE IS STILL APPLIED. The opposite mistake ' +
          'to the one above, and just as silent: a row that can never be ' +
          'applied would otherwise stop this process at that seq for ever ' +
          'while it went on reporting that it was coordinating');

  // -------------------------------------------------------------------------
  // 6. AN UNKNOWN KIND IS SKIPPED RATHER THAN FATAL.
  // -------------------------------------------------------------------------
  t.log.info('=== an unknown kind during a rolling upgrade ===');
  replication.reset();
  const future = fakeDriver('me');
  let known = 0;
  await replication.start(future, { directory: function () { known++; } });
  future.write('them', 'something-this-build-has-never-heard-of', '', 'x');
  future.write('them', 'directory', '', 'cn=known');
  await replication.pull();
  t.equal(known, 1,
          'A KIND THIS BUILD DOES NOT KNOW IS SKIPPED AND THE REST OF THE ' +
          'PAGE IS APPLIED — which is the ordinary case during a rolling ' +
          'upgrade, where an older process must not fall over because a ' +
          'newer one wrote something it has never seen');

  // -------------------------------------------------------------------------
  // 7. THE APPLY HAPPENS INSIDE THE RIGHT REALM.
  //
  // This is the single most likely bug in the whole feature. The realm is
  // AMBIENT in this service — `realms.map()` hands out the current realm's
  // partition — so an apply that ran outside a realm context would put realm
  // `acme`'s session into the default realm, silently, and the only symptom
  // would be somebody signed in to the wrong place.
  // -------------------------------------------------------------------------
  t.log.info('=== the apply runs inside the change\'s realm ===');
  realms.create({ id: 'repl-test', name: 'Replication test' });
  replication.reset();
  const realmed = fakeDriver('me');
  let sawRealm = null;
  await replication.start(realmed, {
    minted: function () { sawRealm = realms.currentId(); }
  });
  realmed.write('them', 'minted', 'repl-test', 'h\u0000k');
  await replication.pull();
  t.equal(sawRealm, 'repl-test',
          'AN APPLIER RUNS WITH THE CHANGE\'S REALM AMBIENT. Without this ' +
          'every replicated row lands in the default realm\'s partition, ' +
          'which is a wrong answer that looks exactly like a right one');

  // -------------------------------------------------------------------------
  // 8. TURNING IT OFF IS WHAT THIS SERVICE DID BEFORE.
  // -------------------------------------------------------------------------
  t.log.info('=== persistence.coordinate off ===');
  replication.reset();
  coordinate(false);
  const ignored = fakeDriver('me');
  let touched = 0;
  const off = await replication.start(ignored,
                                      { directory: function () { touched++; } });
  ignored.write('them', 'directory', '', 'cn=nobody-is-listening');
  await replication.pull();
  t.equal(off.coordinating, false, 'start() reports that it is not coordinating');
  t.equal(touched, 0,
          'AND NOTHING IS APPLIED — a process alone with its own copy, which ' +
          'is exactly what this service was before 2026-09-06 and is still a ' +
          'supported configuration rather than a degraded one');

  // -------------------------------------------------------------------------
  // 9. THE ldif STORE CANNOT COORDINATE AND SAYS SO.
  // -------------------------------------------------------------------------
  t.log.info('=== a driver that cannot coordinate ===');
  t.equal(replication.supports({ open: function () {} }), false,
          'a driver with no change log is refused — the ldif store writes ' +
          'whole files and a change log needs a transaction and a sequence');

  // Leave the process as it was found: run.js runs every file in one process.
  coordinate(null);
  replication.reset();
  realms.remove('repl-test');
}

module.exports = {
  name: 'replication',
  describe: 'several processes against one store: order, skipping your own, ' +
            'and the failures that are silent',
  run: run
};
