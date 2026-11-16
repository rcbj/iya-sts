// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: deleted_person_inherits_nothing.js
//
// ===========================================================================
// A DELETED PERSON LEAVES NOTHING FOR A NAMESAKE (2026-11-16).
//
// rcbj, 2026-11-16: "address all those things a recreated user inherits" —
// the rule of #1612/#1613, a person deleted and made again under the same
// name inherits nothing. A person made again under the username has the same
// name and DN and a new `entryUUID`, and every store keyed by the name or the
// DN handed the deleted person's rows over. `ldap_server.js`'s
// `forgetPersonHoldings()`, reached from `removePersonEntry()` (every door's
// person delete), forgets them; `risc.retireNamesake()` moves the RISC
// register's row out of the name when it is taken again. Asserted, for each
// store, after the person is seeded, deleted and made again:
//
//   A. THE MANAGEMENT API'S DOOR (`usersAction()`'s `delete`):
//      A1 devices (removed, so not listed for the namesake);
//      A2 post-login progress (`doneAt`);
//      A3 mail preferences (a declined category);
//      A4 a federation relationship's block;
//      A5 GNAP approvals;
//      A6 the `/admin/users` register row;
//      A7 the pending authenticator-app, security-key and administrator's
//         enrolments;
//      A8 a rich authorization Allow;
//      A9 the RISC register: the namesake starts with no opt-out, and the
//         deleted account's row is kept under its old `urn:uuid:` subject.
//   B. SCIM'S DOOR (`deletePerson()` by the SCIM id): the same stores.
//   C. A RE-HOMING (`moved`) IS NOT A DELETE: what is keyed by the name stays.
//   D. The codes are in the table.
//
// In a CHILD PROCESS, for `deleted_certificates.js`'s reason: it loads the
// whole stack, process state `run.js` shares with every other file.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_DELETED_PERSON_INHERITS_NOTHING_CHILD';
const MARK = 'INHERITS-NOTHING-CHILD ';

const log = require('bunyan').createLogger({
  name: 'deleted_person_inherits_nothing',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const realms = require(ROOT + '/common/realms');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const devices = require(ROOT + '/common/devices');
  const postLogin = require(ROOT + '/common/post_login');
  const mail = require(ROOT + '/common/mail');
  const federation = require(ROOT + '/federation/federation');
  const fedBlocks = require(ROOT + '/federation/federation_blocks');
  const gnapSignals = require(ROOT + '/gnap/gnap_signals');
  const adminStats = require(ROOT + '/common/admin_stats');
  const credentials = require(ROOT + '/common/credentials');
  const details = require(ROOT + '/oauth-oidc/authorization_details');
  const risc = require(ROOT + '/ssf/risc');
  const adminActions = require(ROOT + '/admin-core/admin_actions');
  const errorCodes = require(ROOT + '/common/error_codes');
  const passkeyPolicy = require(ROOT + '/common/passkey_policy');

  await keystore.start();
  await pki.start({ realmIds: [''],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  await pki.ensureScope(realms.currentId());

  const FED = 'dpin-partner';
  const madeFed = federation.create({ fedId: FED,
    fedRole: 'service-provider', fedProtocol: 'oidc',
    fedPeer: 'https://partner.dpin.test' });
  t.check(madeFed && madeFed.ok !== false,
          'precondition: a federation relationship exists',
          JSON.stringify(madeFed));
  const GNAP_APP = 'dpin-gnap-app';
  const ADMIN = 'dpin-admin';
  ldap.createUser(ADMIN, { invent: false });
  // An administrator may enrol a passkey for somebody (#945), so the
  // administrator's ceremony can be seeded.
  passkeyPolicy.save('default', Object.assign({}, passkeyPolicy.DEFAULTS,
                                              { adminEnrolment: 'on' }));
  const PQC = { activity: 'pqc-passkey-migration', profile: '',
                enforceable: false, graceDays: 0, askedBy: '' };

  const dnOf = function (name) {
    log.debug("Entering dnOf().");
    const found = ldap.objectFor(name);
    log.debug("Leaving dnOf().");
    return found && found.entry ? found.entry.dn : '';
  };

  // Everything a person can hold under their name or DN, written.
  const seed = function (name) {
    log.debug("Entering seed().");
    const out = {};
    out.device = devices.create({ owner: name, label: name + ' laptop',
                                  platform: 'linux' }, ADMIN);
    out.done = postLogin.noteDone(name, PQC);
    out.declined = mail.setDeclined(name, 'notification', true, name);
    out.blocked = fedBlocks.block(FED, name, { event: 'test' });
    gnapSignals.noteApprover(GNAP_APP, name);
    out.signedIn = adminStats.recordAuthentication({ presented: name,
      protocol: 'OIDC', method: 'pwd', sessionId: 'dpin-' + name });
    out.totp = credentials.beginTotpEnrolment(name);
    out.key = credentials.beginKeyEnrolment(name, {});
    out.adminKey = credentials.beginAdminKeyEnrolment(name,
      { username: ADMIN, sub: '' }, {});
    details.noteConsented(name, 'dpin-client', 'digest-' + name, null);
    const subject = String(helpers.subjectForName(name) || '');
    const row = risc.rowFor(name, { username: name });
    row.subject = subject;
    row.optOut = 'opt-out';
    row.credentialStanding = 'compromised';
    out.subject = subject;
    log.debug("Leaving seed().");
    return out;
  };

  // What of it a person under the name holds now; true means "held".
  const held = function (name) {
    log.debug("Entering held().");
    const row = risc.get(name);
    const out = {
      devices: devices.listFor(name).length > 0,
      postLogin: Number(postLogin.stateOf(name).doneAt) > 0,
      mail: mail.declined(name).indexOf('notification') >= 0,
      fedBlock: !!fedBlocks.blockOf(FED, name),
      gnap: gnapSignals.approvedBy(GNAP_APP, name),
      // Making the entry files a record with no sign-in on it
      // (`noteKnownIdentity()`); the deleted person's had one.
      users: Number((adminStats.noteKnownIdentity(name, 'created') || {})
        .authentications) > 0,
      totp: !!credentials.pendingTotpFor(name),
      key: !!credentials.pendingKeyEnrolmentFor(name),
      adminKey: !!credentials.pendingAdminKeyEnrolment(ADMIN, name),
      risc: !!row && (row.optOut !== 'opt-in' ||
                      row.credentialStanding === 'compromised')
    };
    log.debug("Leaving held().");
    return out;
  };
  // Spent by asking, so asked last and separately.
  const allowHeld = function (name) {
    log.debug("Entering allowHeld().");
    log.debug("Leaving allowHeld().");
    return details.consumeConsented(name, 'dpin-client', 'digest-' + name);
  };
  const allHeld = function (h) {
    log.debug("Entering allHeld().");
    log.debug("Leaving allHeld().");
    return Object.keys(h).every(function (k) {
      return h[k];
    });
  };
  const LABELS = [
    ['devices', 'devices (removed, not owned by the namesake)'],
    ['postLogin', 'post-login progress'],
    ['mail', 'mail preferences'],
    ['fedBlock', 'a federation relationship\'s block'],
    ['gnap', 'GNAP approvals'],
    ['users', 'the /admin/users register row\'s sign-ins'],
    ['totp', 'a pending authenticator-app enrolment'],
    ['key', 'a pending security-key enrolment'],
    ['adminKey', 'an administrator\'s pending enrolment for them']
  ];

  const scenario = function (letter, name, remove) {
    log.debug("Entering scenario(). " + letter);
    ldap.createUser(name, { invent: false });
    const seeded = seed(name);
    const before = held(name);
    t.check(allHeld(before) && !!seeded.subject,
            letter + '0. everything is seeded for ' + name,
            JSON.stringify({ held: before, seeded: seeded }));
    const gone = remove(name);
    t.check(gone && gone.ok && !dnOf(name),
            letter + '0. ' + name + ' is deleted', JSON.stringify(gone));
    ldap.createUser(name, { invent: false });
    const subject = String(helpers.subjectForName(name) || '');
    const after = held(name);
    LABELS.forEach(function (one, i) {
      t.check(!after[one[0]], letter + (i + 1) + '. made again, ' + name +
              ' inherits none of ' + one[1], JSON.stringify(after));
    });
    t.check(!allowHeld(name), letter + (LABELS.length + 1) + '. nor a ' +
            'rich authorization Allow');
    const kept = risc.get(seeded.subject);
    t.check(!after.risc && subject !== seeded.subject && !!kept &&
            kept.optOut === 'opt-out',
            letter + (LABELS.length + 2) + '. the RISC register: the ' +
            'namesake starts with no opt-out, and the deleted account\'s ' +
            'row is kept under its old subject',
            JSON.stringify({ now: risc.get(name), kept: kept }));
    log.debug("Leaving scenario().");
  };

  // -------------------------------------------------------------------------
  // A. THE MANAGEMENT API'S DOOR
  // -------------------------------------------------------------------------
  scenario('A', 'dpin-alice', function (name) {
    log.debug("Entering remove() A.");
    log.debug("Leaving remove() A.");
    return adminActions.usersAction({ action: 'delete', user: name },
                                    { actor: ADMIN, via: 'test' });
  });

  // -------------------------------------------------------------------------
  // B. SCIM'S DOOR
  // -------------------------------------------------------------------------
  scenario('B', 'dpin-bob', function (name) {
    log.debug("Entering remove() B.");
    const scimId = String(helpers.subjectForName(name) || '')
      .replace(/^urn:uuid:/, '') || dnOf(name);
    log.debug("Leaving remove() B.");
    return ldap.deletePerson(scimId);
  });

  // -------------------------------------------------------------------------
  // C. A RE-HOMING IS NOT A DELETE
  // -------------------------------------------------------------------------
  const DAN = 'dpin-dan';
  ldap.createUser(DAN, { invent: false });
  seed(DAN);
  const moved = ldap.deletePerson(dnOf(DAN), { door: 'a re-homing',
                                               moved: true });
  const kept = held(DAN);
  t.check(moved.ok && kept.postLogin && kept.mail && kept.fedBlock &&
          kept.gnap && kept.totp && kept.key && kept.adminKey,
          'C1. a re-homing keeps what is kept under the name',
          JSON.stringify({ moved: moved, held: kept }));

  // -------------------------------------------------------------------------
  // D. THE CODES
  // -------------------------------------------------------------------------
  t.check(['STS-LDAP-0222', 'STS-DEVICE-0053'].every(function (code) {
    return !!errorCodes.describe(code);
  }), 'D1. STS-LDAP-0222 and STS-DEVICE-0053 are in the table');
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 240000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  const got = spawnChild();
  if (got.error) {
    log.debug("Leaving run(). The child failed.");
    throw new Error(got.error);
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (process.env[CHILD_FLAG] === '1' && require.main === module) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'deleted_person_inherits_nothing',
  describe: 'A deleted person leaves nothing under their name or DN for a ' +
            'person made again under the name; a re-homing keeps it',
  run: run
};
