'use strict';
//
// File: ssf_allowed_events_cache.js
//
// ===========================================================================
// A STREAM OWNER'S `ssfAllowedEvents` IS CACHED UNTIL ou=applications CHANGES,
// AND NOT A MOMENT LONGER (2026-09-14).
//
// `ssf/ssf_streams.js` asks what a stream's owner is allowed for every event on
// every stream. It built a whole view of every application to do it, and a
// session sweep that expired 2,412 sessions blocked a postgres-mode service for
// 58 seconds — long enough for an LDAP modify in `sts_directory_bulk_load_ldap`
// to time out. `applications.ssfAllowedEventsFor()` reads raw attributes and
// keeps its answer per realm until the directory's `applicationsVersion()`
// moves. A cache that outlived a change would let a stream go on receiving
// what its owner's entry has just stopped allowing, so what is asserted is the
// change being seen at once, by both matches:
//
//   1. by application identifier — tightened, loosened, and cleared;
//   2. by `ssfReceiverId`, including the receiver id being taken away;
//   3. a change through the LDAP modify handler, which edits in place and
//      touches the directory with no location, is seen too;
//   4. a name no application answers to is cached as "unrestricted" and stops
//      being so when an application starts answering to it.
//
// In a CHILD PROCESS: it requires the directory, which registers routes.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_allowed_events_cache',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  const OUT = process.env.SSF_CACHE_CHILD_OUT;
  const ROOT = process.env.SSF_CACHE_CHILD_ROOT;
  try {
    require(ROOT + '/common/app');
    require(ROOT + '/admin-ui/admin');
    const directory = require(ROOT + '/ldap/ldap_server');
    const applications = require(ROOT + '/common/applications');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/' +
                 'session-revoked';
    const RISC = 'https://schemas.openid.net/secevent/risc/event-type/' +
                 'account-disabled';
    const record = function (owner) {
      return { createdBy: owner, events_delivered: [CAEP, RISC] };
    };
    const change = function (identifier, attribute, mode, value) {
      const made = applications.updateApplication(identifier,
        { attribute: attribute, mode: mode, value: value });
      if (!made.ok) {
        note(false, mode + ' ' + attribute + ' on ' + identifier,
             JSON.stringify(made.errors));
      }
    };

    const created = applications.createApplication({
      identifier: 'cache-owner', kinds: ['ssf-receiver'], protocols: ['ssf'],
      fields: { ssfReceiverId: ['cache-receiver'] } });
    note(created.ok, 'an SSF application is created',
         JSON.stringify(created.errors));

    // 1. BY IDENTIFIER.
    note(streams.deliversEvent(record('cache-owner'), CAEP) &&
         streams.deliversEvent(record('cache-owner'), RISC),
         'with no ssfAllowedEvents the owner is unrestricted');
    change('cache-owner', 'ssfAllowedEvents', 'add', 'caep');
    note(streams.deliversEvent(record('cache-owner'), CAEP) &&
         !streams.deliversEvent(record('cache-owner'), RISC),
         'TIGHTENED TO caep, THE NEXT LOOKUP REFUSES RISC — the cached ' +
         '"unrestricted" answer did not outlive the write');
    change('cache-owner', 'ssfAllowedEvents', 'add', 'risc');
    change('cache-owner', 'ssfAllowedEvents', 'remove', 'caep');
    note(!streams.deliversEvent(record('cache-owner'), CAEP) &&
         streams.deliversEvent(record('cache-owner'), RISC),
         'and moved to risc, the next lookup follows');

    // 2. BY ssfReceiverId.
    note(!streams.deliversEvent(record('cache-receiver'), CAEP),
         'the same limit applies to a stream owned by the receiver id');
    change('cache-owner', 'ssfReceiverId', 'remove', 'cache-receiver');
    note(streams.deliversEvent(record('cache-receiver'), CAEP),
         'TAKING THE RECEIVER ID AWAY IS SEEN AT ONCE — that name no longer ' +
         'belongs to a restricted application');

    // 3. THE LDAP MODIFY HANDLER, through the function a worker runs it with.
    // The owner is asked FIRST, so the answer the modify must invalidate is
    // really in the cache.
    note(!streams.deliversEvent(record('cache-owner'), CAEP),
         'before the modify the owner is limited to risc (and that answer is ' +
         'now cached)');
    const dn = (applications.list().filter(function (one) {
      return one.identifier === 'cache-owner';
    })[0] || {}).dn;
    return Promise.resolve(directory.performOperation('modify', {
      dn: dn, boundDn: '', channel: 'ldap',
      changes: [{ operation: 'replace',
                  modification: { type: 'ssfAllowedEvents',
                                  values: ['caep'] } }]
    })).then(function (result) {
      note(result && !result.error,
           'an LDAP modify of ssfAllowedEvents is accepted',
           JSON.stringify(result).slice(0, 300));
      note(streams.deliversEvent(record('cache-owner'), CAEP) &&
           !streams.deliversEvent(record('cache-owner'), RISC),
           'A CHANGE MADE OVER THE LDAP SOCKET\'S HANDLER IS SEEN AT ONCE — it ' +
           'writes in place and touches the directory with no location');

    // 4. A NAME NOBODY ANSWERS TO, THEN SOMEBODY DOES.
    note(streams.deliversEvent(record('cache-late'), RISC),
         'a name no application answers to is unrestricted');
    change('cache-owner', 'ssfReceiverId', 'add', 'cache-late');
    note(!streams.deliversEvent(record('cache-late'), RISC),
         'AND STOPS BEING SO the moment an application lists it as a receiver');
    }).catch(function (e) {
      note(false, 'the child ran to the end', e && e.stack);
    }).then(function () {
      require('fs').writeFileSync(OUT, JSON.stringify(findings));
      process.exit(0);
    });
  } catch (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ssf-cache-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    SSF_CACHE_CHILD_OUT: out, SSF_CACHE_CHILD_ROOT: root,
    LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) { t.check(one.ok, one.what, one.detail); });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_allowed_events_cache',
  describe: 'a stream owner\'s ssfAllowedEvents is cached until ' +
            'ou=applications changes, and every change is seen at once',
  run: run
};
