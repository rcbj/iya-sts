'use strict';
//
// File: risc_identifiers_recovery.js
//
// ===========================================================================
// RISC'S IDENTIFIER EVENTS AS SETS, AND THE RECOVERY ADDRESS (#234, #235),
// the register's half, in process:
//
//   A. #234 — every value of `mail`, `telephoneNumber` and `mobile` compared
//      as a set, before against after:
//        1. an address REMOVED is identifier-changed with no `new-value`,
//           and is released;
//        2. so an account taking it within risc.recycleWindowDays is
//           identifier-recycled — the case RISC section 2.6 exists for;
//        3. a `mobile` changed while a `telephoneNumber` is set is seen, and
//           the row keeps the first number;
//        4. a SECOND `mail` value changed is seen, and the row keeps the
//           first address;
//        5. a number moving between `telephoneNumber` and `mobile`, or an
//           address changing only its case, is no change;
//        6. every value that arrived is checked for recycling, not only the
//           first;
//        7. a purge releases every value the entry held.
//   B. #235 — the recovery channel (the first `mail` and whether
//      `stsMailVerified` names it) moving is recovery-information-changed:
//        1. a first address added;
//        2. an address changed: identifier-changed AND
//           recovery-information-changed, in that order;
//        3. the address verified;
//        4. an address removed;
//        5. but not a create with an address, and not a second address;
//        6. and the directory hands a write of `stsMailVerified` to the
//           account observer, which it did not before #235.
//
// In a child process, because it loads the protocol stack. The HTTP half is
// `tests/vendored/sts_risc_register_recovery.js`.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({
  name: 'risc_identifiers_recovery', level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

// Runs in the child, as a string: data, exempt from the Entering/Leaving
// rule for the reason tests/CLAUDE.md gives for `node -e` programs.
function childMain() {
  const ROOT = process.env.RIR_ROOT;
  const OUT = process.env.RIR_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    return !!ok;
  }
  try {
    require(ROOT + '/common/protocol_stack');
    const risc = require(ROOT + '/ssf/risc');
    const config = require(ROOT + '/common/config');
    config.setOverride('ssf.enabled', 'true');
    config.setOverride('risc.enabled', 'true');
    config.setOverride('risc.autoEmit', 'true');
    const P = 'https://schemas.openid.net/secevent/risc/event-type/';
    const ISS = 'https://sts.example';
    const typesOf = function (due) {
      return due.map(function (one) { return one.uri.slice(P.length); });
    };
    const settle = function (due) {
      due.forEach(function (one) { risc.applyDue(one); });
      return due;
    };
    const create = function (who, attrs) {
      return settle(risc.observe({ kind: 'created', username: who,
        issuer: ISS, before: {},
        after: Object.assign({ uid: [who] }, attrs) }));
    };
    const update = function (who, before, after) {
      return settle(risc.observe({ kind: 'updated', username: who,
        issuer: ISS, before: Object.assign({ uid: [who] }, before),
        after: Object.assign({ uid: [who] }, after) }));
    };
    const released = function (who, value) {
      const row = risc.get(who);
      return !!row && (row.releasedIdentifiers || []).some(function (one) {
        return one.value === value;
      });
    };

    // --- A1 ----------------------------------------------------------------
    create('a1', { mail: ['gone@a.test'] });
    const removed = update('a1', { mail: ['gone@a.test'] }, {});
    const changed = removed.filter(function (one) {
      return one.uri === P + 'identifier-changed';
    })[0];
    note(!!changed && changed.subject.email === 'gone@a.test' &&
         !('new-value' in changed.payload),
         'A1. an address REMOVED is identifier-changed, its subject the old ' +
         'address and no new-value (section 2.5 makes it optional)',
         JSON.stringify(changed && { sub: changed.subject,
                                     payload: changed.payload }));
    note(released('a1', 'gone@a.test') && risc.get('a1').email === '',
         'A1. and it is released, and the row holds no address',
         JSON.stringify(risc.get('a1')));

    // --- A2 ----------------------------------------------------------------
    const retaken = create('a2', { mail: ['gone@a.test'] });
    note(typesOf(retaken).indexOf('identifier-recycled') >= 0,
         'A2. so an account taking it within the window is ' +
         'identifier-recycled', JSON.stringify(typesOf(retaken)));

    // --- A3 ----------------------------------------------------------------
    create('a3', { telephonenumber: ['+15550100'], mobile: ['+15550111'] });
    const mobile = update('a3',
      { telephonenumber: ['+15550100'], mobile: ['+15550111'] },
      { telephonenumber: ['+15550100'], mobile: ['+15550122'] });
    const moved = mobile.filter(function (one) {
      return one.uri === P + 'identifier-changed';
    });
    note(moved.length === 1 &&
         moved[0].subject.phone_number === '+15550111' &&
         moved[0].payload['new-value'] === '+15550122',
         'A3. a mobile changed beside a telephoneNumber is seen',
         JSON.stringify(moved.map(function (one) {
           return [one.subject, one.payload];
         })));
    note(risc.get('a3').phone === '+15550100' &&
         released('a3', '+15550111') && !released('a3', '+15550100'),
         'A3. the row keeps the first number, and only the old mobile is ' +
         'released', JSON.stringify(risc.get('a3')));

    // --- A4 ----------------------------------------------------------------
    create('a4', { mail: ['first@a.test', 'second@a.test'] });
    const second = update('a4', { mail: ['first@a.test', 'second@a.test'] },
                          { mail: ['first@a.test', 'third@a.test'] });
    const secondMove = second.filter(function (one) {
      return one.uri === P + 'identifier-changed';
    });
    note(secondMove.length === 1 &&
         secondMove[0].subject.email === 'second@a.test' &&
         secondMove[0].payload['new-value'] === 'third@a.test' &&
         risc.get('a4').email === 'first@a.test',
         'A4. a SECOND mail value changed is seen, and the row keeps the ' +
         'first address', JSON.stringify([typesOf(second),
                                          risc.get('a4').email]));

    // --- A5 ----------------------------------------------------------------
    create('a5', { mail: ['Case@a.test'], telephonenumber: ['+15550200'] });
    const shuffled = update('a5',
      { mail: ['Case@a.test'], telephonenumber: ['+15550200'] },
      { mail: ['case@a.test'], mobile: ['+15550200'] });
    note(typesOf(shuffled).indexOf('identifier-changed') < 0 &&
         !released('a5', '+15550200'),
         'A5. a number moving between telephoneNumber and mobile, and an ' +
         'address changing only its case, is no change',
         JSON.stringify(typesOf(shuffled)));

    // --- A6 ----------------------------------------------------------------
    create('a6-old', { mail: ['x@a.test', 'spare@a.test'] });
    settle(risc.observe({ kind: 'deleted:a6-old', issuer: ISS,
      before: { uid: ['a6-old'], mail: ['x@a.test', 'spare@a.test'] },
      after: {} }));
    note(released('a6-old', 'x@a.test') && released('a6-old', 'spare@a.test'),
         'A7. a purge releases every value the entry held, not the first',
         JSON.stringify(risc.get('a6-old').releasedIdentifiers));
    create('a6', { mail: ['own@a.test'] });
    const extra = update('a6', { mail: ['own@a.test'] },
                         { mail: ['own@a.test', 'spare@a.test'] });
    const recycled = extra.filter(function (one) {
      return one.uri === P + 'identifier-recycled';
    })[0];
    note(!!recycled && recycled.subject.email === 'spare@a.test',
         'A6. a SECOND address arriving is checked for recycling',
         JSON.stringify(typesOf(extra)));

    // --- B1 ----------------------------------------------------------------
    const noAddress = create('b1', { cn: ['b1'] });
    note(typesOf(noAddress).indexOf('recovery-information-changed') < 0,
         'B5. a create is no recovery change');
    const added = update('b1', { cn: ['b1'] },
                         { cn: ['b1'], mail: ['b1@b.test'] });
    note(JSON.stringify(typesOf(added)) ===
         '["recovery-information-changed"]',
         'B1. a first address added is recovery-information-changed',
         JSON.stringify(typesOf(added)));

    // --- B2 ----------------------------------------------------------------
    const changedAddress = update('b1', { mail: ['b1@b.test'] },
                                  { mail: ['b1-new@b.test'] });
    note(JSON.stringify(typesOf(changedAddress)) ===
         '["identifier-changed","recovery-information-changed"]',
         'B2. an address changed is identifier-changed AND ' +
         'recovery-information-changed, in that order',
         JSON.stringify(typesOf(changedAddress)));

    // --- B3 ----------------------------------------------------------------
    const verified = update('b1', { mail: ['b1-new@b.test'] },
      { mail: ['b1-new@b.test'], stsmailverified: ['B1-NEW@b.test'] });
    note(JSON.stringify(typesOf(verified)) ===
         '["recovery-information-changed"]',
         'B3. the address verified is recovery-information-changed',
         JSON.stringify(typesOf(verified)));
    const again = update('b1',
      { mail: ['b1-new@b.test'], stsmailverified: ['b1-new@b.test'] },
      { mail: ['b1-new@b.test'], stsmailverified: ['b1-new@b.test'],
        cn: ['renamed'] });
    note(typesOf(again).length === 0,
         'B3. and a write that changes neither is nothing',
         JSON.stringify(typesOf(again)));

    // --- B4 ----------------------------------------------------------------
    const cleared = update('b1', { mail: ['b1-new@b.test'] }, {});
    note(typesOf(cleared).indexOf('recovery-information-changed') >= 0 &&
         typesOf(cleared).indexOf('identifier-changed') >= 0,
         'B4. the address removed is both as well (section 2.10: "a ' +
         'recovery email address was added or removed")',
         JSON.stringify(typesOf(cleared)));

    // --- B5 ----------------------------------------------------------------
    const created = create('b5', { mail: ['b5@b.test'] });
    note(typesOf(created).indexOf('recovery-information-changed') < 0,
         'B5. a create WITH an address is no recovery change',
         JSON.stringify(typesOf(created)));
    const secondAddress = update('b5', { mail: ['b5@b.test'] },
                                 { mail: ['b5@b.test', 'b5-2@b.test'] });
    note(typesOf(secondAddress).indexOf('recovery-information-changed') < 0,
         'B5. nor is a second address added: recovery mails the first',
         JSON.stringify(typesOf(secondAddress)));

    // --- B6 ----------------------------------------------------------------
    const ldap = require(ROOT + '/ldap/ldap_server');
    const mail = require(ROOT + '/common/mail');
    const seen = [];
    ldap.addAccountObserver(function (change) {
      seen.push(change);
    });
    const made = ldap.createUser('rir-b6', { invent: false,
      attributes: { mail: 'rir-b6@b.test' }, mailSource: 'ldap-self' });
    note(made && made.ok !== false, 'B6. a person is created',
         JSON.stringify(made));
    seen.length = 0;
    const wrote = mail.directory().writeMailFlag('rir-b6', 'stsMailVerified',
                                                 'rir-b6@b.test');
    const told = seen.filter(function (one) {
      return one.username === 'rir-b6' &&
             !(one.before.stsmailverified || []).length &&
             (one.after.stsmailverified || [])[0] === 'rir-b6@b.test';
    });
    note(wrote && told.length === 1,
         'B6. the directory hands a write of stsMailVerified to the account ' +
         'observer, before and after, so the verification is heard',
         JSON.stringify(seen.map(function (one) {
           return { u: one.username, before: one.before.stsmailverified,
                    after: one.after.stsmailverified };
         })));
    const row = risc.get('rir-b6');
    note(!!row && (row.notes || []).join(' ')
      .indexOf('Recovery information changed') >= 0,
         'B6. and the register records recovery-information-changed for it',
         JSON.stringify(row && row.notes));
  } catch (e) {
    note(false, 'the test itself threw', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'risc-identifiers-recovery-' +
                        process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', RIR_ROOT: ROOT, RIR_OUT: out }),
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
  name: 'risc_identifiers_recovery',
  describe: 'RISC identifier events over every value of mail, ' +
            'telephoneNumber and mobile (#234), and the recovery address ' +
            'as recovery-information-changed (#235)',
  run: run
};
