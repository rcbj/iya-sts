'use strict';
//
// File: risc_acts_units.js
//
// ===========================================================================
// RISC ON ITS OWN (#146, 2026-09-22), the register's halves, in process:
//
//   A. the subject of an ordinary RISC event is `iss_sub` by default — the
//      RFC 9493 name, never silently `issuer_subject_id` (item 1, fixed by
//      #144 and held here because nothing did);
//   B. account-disabled's `reason` is the administrator's, and none is
//      invented: hijacking and bulk-account pass, nothing else does;
//   C. identifier-recycled: an address a purged account held, taken by
//      another account within risc.recycleWindowDays, is the act, its subject
//      the address — and outside the window it is not;
//   D. a PHONE number moving is filed as the phone, and its old value is
//      released, where every move used to be filed as the email;
//   E. section 2.8's opt-out: the moves offered from each state, the delay
//      stamp, and optOutsDue() once risc.optOutDelayHours has passed;
//   F. credential-compromise from observeAct() carries credential_type.
//   G. THE TRANSMITTED PATH (noteTransmitted -> applyToState) releases a
//      purged account's identifiers and files a phone change as the phone —
//      the first version released only on the not-sent path, which an
//      HTTP run with the console's own streams listening found.
//
// In a child process, because it loads the protocol stack.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'risc_acts_units',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

function childMain() {
  const ROOT = process.env.RAU_ROOT;
  const OUT = process.env.RAU_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    return !!ok;
  }
  function eq(got, want, what) {
    return note(JSON.stringify(got) === JSON.stringify(want), what,
                'expected ' + JSON.stringify(want) + ', got ' +
                JSON.stringify(got));
  }
  try {
    require(ROOT + '/common/protocol_stack');
    const risc = require(ROOT + '/ssf/risc');
    const config = require(ROOT + '/common/config');
    const P = 'https://schemas.openid.net/secevent/risc/event-type/';
    const ISS = 'https://sts.example';
    const typesOf = function (due) {
      return due.map(function (one) { return one.uri.slice(P.length); });
    };
    // Every due event applied as the no-stream path does.
    const settle = function (due) {
      due.forEach(function (one) { risc.applyDue(one); });
      return due;
    };

    // --- A -------------------------------------------------------------
    const subject = risc.subjectFor({ accountId: 'a-user', sub: 'a-user',
                                      iss: ISS }, P + 'account-purged');
    eq(subject && subject.format, 'iss_sub',
       'A. a RISC subject is iss_sub by default, not issuer_subject_id');

    // --- B -------------------------------------------------------------
    const locked = { pwdaccountlockedtime: ['000001010000Z'], uid: ['b'] };
    const open = { uid: ['b'] };
    eq(risc.actsFor(open, locked, { reason: 'hijacking' })[0].values,
       { reason: 'hijacking' }, 'B. a reason the administrator gave is sent');
    eq(risc.actsFor(open, locked, {})[0].values, {},
       'B. and none is invented when none was given');
    eq(risc.actsFor(open, locked, { reason: 'left the company' })[0].values,
       {}, 'B. and free text is not a RISC reason');

    // --- C -------------------------------------------------------------
    settle(risc.observe({ kind: 'created', username: 'c-old', issuer: ISS,
      before: {}, after: { uid: ['c-old'], mail: ['shared@c.test'] } }));
    settle(risc.observe({ kind: 'deleted:c-old', issuer: ISS,
      before: { uid: ['c-old'], mail: ['shared@c.test'] }, after: {} }));
    const taken = settle(risc.observe({ kind: 'created', username: 'c-new',
      issuer: ISS, before: {},
      after: { uid: ['c-new'], mail: ['shared@c.test'] } }));
    const recycled = taken.filter(function (one) {
      return one.uri === P + 'identifier-recycled';
    })[0];
    note(!!recycled && recycled.subject.format === 'email' &&
         recycled.subject.email === 'shared@c.test',
         'C. an address a purged account held is recycled, the subject the ' +
         'address', JSON.stringify(typesOf(taken)));
    config.setOverride('risc.recycleWindowDays', '0');
    settle(risc.observe({ kind: 'created', username: 'c-old2', issuer: ISS,
      before: {}, after: { uid: ['c-old2'], mail: ['gone@c.test'] } }));
    settle(risc.observe({ kind: 'deleted:c-old2', issuer: ISS,
      before: { uid: ['c-old2'], mail: ['gone@c.test'] }, after: {} }));
    const late = risc.observe({ kind: 'created', username: 'c-new2',
      issuer: ISS, before: {},
      after: { uid: ['c-new2'], mail: ['gone@c.test'] } });
    note(typesOf(late).indexOf('identifier-recycled') < 0,
         'C. and outside the window it is not', JSON.stringify(typesOf(late)));
    config.clearOverride('risc.recycleWindowDays');

    // --- D -------------------------------------------------------------
    settle(risc.observe({ kind: 'created', username: 'd-user', issuer: ISS,
      before: {}, after: { uid: ['d-user'], mail: ['d@d.test'],
                           telephonenumber: ['+15550100'] } }));
    settle(risc.observe({ kind: 'updated', username: 'd-user', issuer: ISS,
      before: { uid: ['d-user'], mail: ['d@d.test'],
                telephonenumber: ['+15550100'] },
      after: { uid: ['d-user'], mail: ['d@d.test'],
               telephonenumber: ['+15550199'] } }));
    const row = risc.get('d-user');
    note(row && row.phone === '+15550199' && row.email === 'd@d.test' &&
         row.releasedIdentifiers.some(function (one) {
           return one.value === '+15550100' && one.format === 'phone_number';
         }),
         'D. a phone move is filed as the phone and its old value released',
         JSON.stringify(row && { email: row.email, phone: row.phone,
                                 released: row.releasedIdentifiers }));

    // --- E -------------------------------------------------------------
    eq(risc.optOutOf('e-user').moves, ['optOutInitiated'],
       'E. from opt-in the one move is to opt out');
    settle(risc.observeAct({ username: 'e-user', act: 'optOutInitiated',
                             issuer: ISS }));
    const initiated = risc.optOutOf('e-user');
    note(initiated.state === 'opt-out-initiated' && !!initiated.since &&
         JSON.stringify(initiated.moves) === '["optOutCancelled"]',
         'E. opting out waits in opt-out-initiated, stamped, and may only ' +
         'be cancelled', JSON.stringify(initiated));
    config.setOverride('risc.optOutDelayHours', '1');
    note(risc.optOutsDue().indexOf('e-user') < 0,
         'E. it is not due before the delay');
    config.setOverride('risc.optOutDelayHours', '0');
    note(risc.optOutsDue().indexOf('e-user') >= 0,
         'E. and it is once the delay has passed');
    note(risc.optOutsDue().indexOf('e-user') < 0,
         'E. and it is handed over ONCE: a second run before the event is ' +
         'delivered does not send it again');
    config.clearOverride('risc.optOutDelayHours');
    note(!risc.optOutMoveAllowed('e-user', 'optIn'),
         'E. opting straight back in from opt-out-initiated is not offered');
    settle(risc.observeAct({ username: 'e-user', act: 'optOutEffective',
                             issuer: ISS }));
    eq(risc.optOutOf('e-user').state, 'opt-out',
       'E. opt-out-effective moves it to opt-out');
    eq(risc.optOutOf('e-user').moves, ['optIn'],
       'E. from where the one move is to opt back in');

    // --- F -------------------------------------------------------------
    const compromised = risc.observeAct({ username: 'f-user',
      act: 'credentialCompromise', issuer: ISS,
      values: { credential_type: 'password' } });
    const f = compromised[0];
    note(!!f && f.uri === P + 'credential-compromise' &&
         f.payload.credential_type === 'password',
         'F. credential-compromise carries credential_type',
         JSON.stringify(f && f.payload));

    // --- G -------------------------------------------------------------
    settle(risc.observe({ kind: 'created', username: 'g-user', issuer: ISS,
      before: {}, after: { uid: ['g-user'], mail: ['g@g.test'],
                           telephonenumber: ['+15550200'] } }));
    risc.noteTransmitted({ stream_id: 'unit' }, { iss: ISS, jti: 'g-1',
      events: { [P + 'identifier-changed']: { 'new-value': '+15550299' } },
      sub_id: { format: 'phone_number', phone_number: '+15550200' } });
    const g1 = risc.get('g-user');
    note(g1 && g1.phone === '+15550299' && g1.email === 'g@g.test',
         'G. a transmitted phone change is filed as the phone',
         JSON.stringify(g1 && { email: g1.email, phone: g1.phone }));
    risc.noteTransmitted({ stream_id: 'unit' }, { iss: ISS, jti: 'g-2',
      events: { [P + 'account-purged']: {} },
      sub_id: { format: 'iss_sub', iss: ISS, sub: 'g-user' } });
    const g2 = risc.get('g-user');
    note(g2 && g2.lifecycle === 'purged' &&
         g2.releasedIdentifiers.some(function (one) {
           return one.value === 'g@g.test';
         }),
         'G. a transmitted purge releases what the account held',
         JSON.stringify(g2 && g2.releasedIdentifiers));
  } catch (e) {
    note(false, 'the test itself threw', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'risc-acts-units-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', RAU_ROOT: ROOT, RAU_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'risc_acts_units',
  describe: 'RISC on its own (#146): the iss_sub default, the disable ' +
            'reason, identifier-recycled, a phone move, section 2.8\'s ' +
            'opt-out moves and delay, credential-compromise',
  run: run
};
