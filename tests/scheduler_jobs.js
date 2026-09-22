'use strict';
//
// File: scheduler_jobs.js
//
// ===========================================================================
// THE FIRST TWO JOBS ON THE SCHEDULER (#49, 2026-09-22) — the plan's T3.
//
// `tests/scheduler.js` and `tests/scheduler_cluster.js` hold the scheduler to
// its promises with jobs of their own. This file holds the two REAL jobs P1
// moved onto it to theirs, in process, against the real modules:
//
//   A. `authn.session-expiry`: registered by `authn/authn.ts` as a cluster job
//      whose interval is `authn.sessionSweepS`, 0 meaning off. Its run ends
//      every expired session in the store ONCE — one `session.end` audit row
//      and one CAEP `session-revoked` notice each, with the policy as the
//      initiating entity — and a second run (a second node's, a second
//      slot's) ends nothing. A session that is looked up after it expired and
//      before the job ran is refused at once and ended there, and the job
//      then finds nothing left to end: the lazy check stays;
//   B. `pki.crl-directory-refresh`: registered by `pki_revocation.js` when
//      `pki.start()` asks it to keep the directory current, OFF (and saying
//      why) with `pki.publishCrlToDirectory` off or no directory in the
//      process, and its run publishes every authority's list through the
//      directory it was handed.
//
// Once per slot for the whole cluster is the scheduler's promise and is
// asserted there; what is asserted here is that each job's run is the ONE
// path its effects come from.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const audit = require('../common/audit');
const authn = require('../authn/authn');
const scheduler = require('../cluster/scheduler');
const revocation = require('../common/pki_revocation');

const log = require('bunyan').createLogger({ name: 'scheduler_jobs',
  level: process.env.LOG_LEVEL || 'info' });

// A context of the shape the scheduler hands a run.
function ctxFor(runId) {
  log.debug('Entering ctxFor().');
  log.debug('Leaving ctxFor().');
  return { realm: 'default', runId: runId, trigger: 'manual', params: null,
           stillOwner: function () { return true; },
           nowMs: function () { return Date.now(); }, log: log };
}

// A sign-in, without a response object — caep_initiating_entity.js's shape.
function signIn(username) {
  log.debug('Entering signIn().');
  const written = [];
  const session = authn.startSession({ set: function (name, value) {
    written.push(String(value));
  }, req: null }, username, ['pwd'], '1', 'OAuth 2.0 / OIDC');
  log.debug('Leaving signIn().');
  return { session: session, cookie: (written[0] || '').split(';')[0] };
}

function endRowsFor(sessionId) {
  log.debug('Entering endRowsFor().');
  const rows = audit.list().filter(function (row) {
    return row.action === 'session.end' &&
           JSON.stringify(row).indexOf(String(sessionId)) >= 0;
  });
  log.debug('Leaving endRowsFor(). ' + rows.length + '.');
  return rows;
}

async function run(t) {
  log.debug('Entering run().');
  // -------------------------------------------------------------------------
  t.log.info('=== A. authn.session-expiry ===');
  const job = scheduler.job('authn.session-expiry');
  t.check(job && job.kind === 'cluster' && job.scope === 'service' &&
          job.everySetting === 'authn.sessionSweepS' &&
          job.owner === 'authn/authn.ts',
          'authn/authn.ts registers the sweep as a service-wide cluster job ' +
          'whose interval is authn.sessionSweepS',
          JSON.stringify(job && { kind: job.kind, scope: job.scope,
                                  every: job.everySetting }));
  const seen = [];
  authn.setSessionObserver(function (notice) {
    seen.push(notice);
    return null;
  });
  const one = signIn('sched-expiry-one');
  const two = signIn('sched-expiry-two');
  const kept = signIn('sched-expiry-kept');
  one.session.expires = Date.now() - 1000;
  two.session.expires = Date.now() - 1000;
  seen.length = 0;
  const first = await job.run(ctxFor('t-1'));
  const revoked = seen.filter(function (n) {
    return n && n.kind === 'revoked';
  });
  t.check(first && first.ended === 2,
          'one run ends the two expired sessions and not the live one',
          JSON.stringify(first));
  t.check(revoked.length === 2 && revoked.every(function (n) {
    return n.initiatingEntity === 'policy' && n.expired;
  }), 'each is one CAEP session-revoked notice, initiated by the POLICY — ' +
      'nobody signed out', JSON.stringify(revoked.map(function (n) {
    return [n.initiatingEntity, n.expired];
  })));
  t.check(endRowsFor(one.session.id).length === 1 &&
          endRowsFor(two.session.id).length === 1,
          'and one session.end audit row each',
          JSON.stringify([endRowsFor(one.session.id).length,
                          endRowsFor(two.session.id).length]));
  seen.length = 0;
  const second = await job.run(ctxFor('t-2'));
  t.check(second && second.ended === 0 && seen.length === 0 &&
          endRowsFor(one.session.id).length === 1,
          'a second run — another node\'s, or the next slot\'s — ends ' +
          'nothing and reports nothing again',
          JSON.stringify({ second: second, notices: seen.length }));
  t.check(!!authn.sessionById(kept.session.id),
          'and the live session is untouched', kept.session.id);

  const lazy = signIn('sched-expiry-lazy');
  lazy.session.expires = Date.now() - 1000;
  seen.length = 0;
  t.equal(authn.sessionOf({ headers: { cookie: lazy.cookie } }), null,
          'a session presented after it expired, before the job ran, is ' +
          'refused at once — the lazy check stays');
  const afterLazy = await job.run(ctxFor('t-3'));
  t.check(afterLazy.ended === 0 && endRowsFor(lazy.session.id).length === 1 &&
          seen.filter(function (n) { return n.kind === 'revoked'; })
            .length === 1,
          'and it was ended there, once: the job finds nothing left to end',
          JSON.stringify({ job: afterLazy,
                           rows: endRowsFor(lazy.session.id).length }));
  config.setOverride('authn.sessionSweepS', 0);
  t.check(/authn\.sessionSweepS is 0/.test(
    scheduler.scheduler.offReason(job)),
          'authn.sessionSweepS at 0 switches the job off, and the scheduler ' +
          'says so', scheduler.scheduler.offReason(job));
  config.clearOverride('authn.sessionSweepS');

  // -------------------------------------------------------------------------
  t.log.info('=== B. pki.crl-directory-refresh ===');
  revocation.keepDirectoryCurrent();
  const crl = scheduler.job('pki.crl-directory-refresh');
  t.check(crl && crl.kind === 'cluster' &&
          crl.owner === 'common/pki_revocation.js' &&
          scheduler.scheduler.intervalMs(crl) >= 60000,
          'pki_revocation registers the refresh as a cluster job, at half ' +
          'a list\'s lifetime and never under a minute',
          JSON.stringify(crl && { kind: crl.kind,
            every: scheduler.scheduler.intervalMs(crl) }));
  t.check(revocation.keepDirectoryCurrent() === false,
          'asking again registers nothing: once per process');
  config.setOverride('pki.publishCrlToDirectory', false);
  t.check(/pki\.publishCrlToDirectory is off/.test(
    scheduler.scheduler.offReason(crl)),
          'with pki.publishCrlToDirectory off the job is off, and says why',
          scheduler.scheduler.offReason(crl));
  config.clearOverride('pki.publishCrlToDirectory');
  const published = [];
  const before = revocation.currentDirectory();
  revocation.setDirectory({
    publishCrl: function (scopeId, caId, der) {
      published.push({ scope: scopeId, ca: caId, bytes: der && der.length });
      return true;
    },
    baseDnFor: function () { return 'dc=example,dc=com'; }
  });
  t.equal(scheduler.scheduler.offReason(crl), '',
          'with a directory in the process the job is on');
  const answer = await crl.run(ctxFor('t-crl'));
  t.check(answer && answer.published === published.length &&
          published.every(function (p) { return p.bytes > 0; }),
          'and its run publishes every authority\'s list through the ' +
          'directory, and says how many', JSON.stringify({
            answer: answer, published: published.length }));
  revocation.restoreDirectory(before);
  log.debug('Leaving run().');
}

module.exports = {
  name: 'scheduler_jobs',
  describe: 'the two jobs P1 moved onto the scheduler: the session-expiry ' +
            'sweep ends each expired session once, and the CRL directory ' +
            'refresh says why it is off and publishes when it runs',
  run: run
};
