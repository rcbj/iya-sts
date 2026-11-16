// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: kerberos_namesake_rid.js
//
// ===========================================================================
// A DELETED PERSON'S RID — THEIR SID — IS NEVER A NAMESAKE'S (2026-11-16).
//
// rcbj's rule (#1612/#1613): a person deleted and made again under the same
// name inherits nothing. The principal record under `name@REALM` outlived the
// delete, because it carries the sign-out stamp (#111), and the next person
// under the name was given its RID. `krb5_principals.js`, *A PERSON'S RID IS
// THE ENTRY'S*, is the design. Asserted:
//
//   A. DEVELOPMENT MODE, in this process (a record made on demand):
//      A1 the delete retires the record and keeps its sign-out stamp;
//      A2 the next person under the name gets a different RID, the stamp
//         merged and the retired RID carried;
//      A3 a third gets a RID that is neither;
//      A4 another name whose slot a retired RID holds is probed past it;
//      A5 a name nobody held still gets the RID it always would (the digest
//         is unchanged), and a live record keeps its RID.
//   B. PRODUCT MODE, in a child (a directory person, through the key source):
//      B1 a new record is bound to the entry's entryUUID;
//      B2 a record from before 2026-11-16 (no binding) keeps its RID and is
//         bound at its first lookup — the lazy migration;
//      B3 a record bound to another entry (a namesake the delete's
//         retirement never reached) gives the namesake a new RID, keeping the
//         stamp;
//      B4 an alias of the entry (a create race) is the same entry;
//      B5 `certificatePerson()` (PKINIT, no keys) does the same.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_KERBEROS_NAMESAKE_RID_CHILD';
const MARK = 'NAMESAKE-RID-CHILD ';

const log = require('bunyan').createLogger({
  name: 'kerberos_namesake_rid', level: process.env.LOG_LEVEL || 'info' });

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

// The RID a name nobody held was always given, computed here the way
// `autoRidFor()` computed it before 2026-11-16, before any probe.
function historicSlot(key, base, limit) {
  log.debug("Entering historicSlot().");
  const digest = nodeCrypto.createHash('sha256')
    .update('sts-krb5-auto-rid:' + key).digest();
  log.debug("Leaving historicSlot().");
  return base + (digest.readUIntBE(0, 6) % (limit - base));
}

// ---------------------------------------------------------------------------
// A. DEVELOPMENT MODE
// ---------------------------------------------------------------------------
function developmentMode(t) {
  log.debug("Entering developmentMode().");
  const realms = require('../common/realms');
  const principals = require('../kerberos/krb5_principals.js');
  realms.run(realms.DEFAULT_REALM, function () {
    const suffix = String(process.pid) +
      nodeCrypto.randomBytes(3).toString('hex');
    const name = 'ns-rid-' + suffix;
    const first = principals.findOrCreateUser([name]);
    const rid1 = first && first.pac.rid;
    principals.signOut([name]);
    const stamp = first && String(first.signedOutAt);
    const retired = principals.retirePerson(name);
    const held = principals.all().filter(function (one) {
      return one.name.join('/') === name;
    })[0];
    t.check(retired && held && held.retired &&
            (held.retiredRids || []).indexOf(rid1) >= 0 &&
            String(held.signedOutAt) === stamp,
            'A1. the delete retires the record and keeps its sign-out stamp',
            JSON.stringify({ retired: retired, held: held }));

    const second = principals.findOrCreateUser([name]);
    const rid2 = second && second.pac.rid;
    t.check(second && !second.retired && rid2 !== rid1 &&
            (second.retiredRids || []).indexOf(rid1) >= 0 &&
            String(second.signedOutAt) === stamp,
            'A2. the next person under the name gets a NEW RID, so a new ' +
            'SID; the stamp is merged and the retired RID carried',
            JSON.stringify({ rid1: rid1, second: second }));
    t.check(principals.findOrCreateUser([name]).pac.rid === rid2,
            'A2. and keeps it while they exist');

    principals.retirePerson(name);
    const third = principals.findOrCreateUser([name]);
    t.check(third && [rid1, rid2].indexOf(third.pac.rid) === -1,
            'A3. a third person under the name gets a RID that is neither',
            JSON.stringify({ rid1: rid1, rid2: rid2,
                             rid3: third && third.pac.rid }));

    // A4: a retired RID lies on the slot another name hashes to.
    const other = 'ns-rid-other-' + suffix;
    const slot = principals.autoRidFor([other]);
    const lone = principals.findOrCreateUser(['ns-rid-holder-' + suffix]);
    const wasRid = lone.pac.rid;
    lone.pac.rid = slot;
    principals.retirePerson('ns-rid-holder-' + suffix);
    const probed = principals.autoRidFor([other]);
    t.check(probed !== slot,
            'A4. a RID a deleted holder had is probed past by another name',
            JSON.stringify({ slot: slot, probed: probed }));
    lone.pac.rid = wasRid;

    const fresh = 'ns-rid-fresh-' + suffix;
    const expected = historicSlot(fresh + '@' + principals.REALM,
                                  principals.AUTO_RID_BASE,
                                  principals.AUTO_RID_LIMIT);
    const got = principals.autoRidFor([fresh]);
    t.check(got === expected,
            'A5. a name nobody held gets the RID it always would',
            JSON.stringify({ expected: expected, got: got }));
    const live = principals.findOrCreateUser([fresh]);
    const liveRid = live.pac.rid;
    t.check(principals.findOrCreateUser([fresh]).pac.rid === liveRid,
            'A5. and a live record keeps its RID');
  });
  log.debug("Leaving developmentMode().");
}

// ---------------------------------------------------------------------------
// B. PRODUCT MODE, in the child
// ---------------------------------------------------------------------------
function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  const p = require(ROOT + '/kerberos/krb5_principals.js');
  const people = {};
  const keyOf = function () {
    return [[18, Buffer.alloc(32, 7)]];
  };
  p.setKeySource({
    personKeys: function (name) {
      const person = people[name];
      if (!person) {
        return { state: 'unknown' };
      }
      if (person.keyless) {
        return { state: 'none', entryUuids: person.uuids };
      }
      return { state: 'ok', kvno: 1, salt: p.REALM + name, keys: keyOf(),
               retained: [], entryUuids: person.uuids };
    },
    serviceKeys: function () {
      return null;
    }
  });
  const lookup = function (name) {
    const answer = p.lookupUser([name]);
    return answer && answer.principal;
  };
  const U1 = '11111111-2222-4333-8444-555555555555';
  const U2 = '66666666-7777-4888-9999-aaaaaaaaaaaa';

  people.carla = { uuids: [U1] };
  const made = lookup('carla');
  t.check(made && made.entryUuid === U1,
          'B1. a new record is bound to the entry\'s entryUUID',
          JSON.stringify(made));

  // B2: as a record from before this change was stored: no binding.
  people.dora = { uuids: [U2] };
  const old = lookup('dora');
  const oldRid = old.pac.rid;
  delete old.entryUuid;
  const migrated = lookup('dora');
  t.check(migrated && migrated.pac.rid === oldRid &&
          migrated.entryUuid === U2,
          'B2. a record from before 2026-11-16 keeps its RID — the SID does ' +
          'not change — and is bound to its entry at its first lookup',
          JSON.stringify({ oldRid: oldRid, migrated: migrated }));

  // B3: the entry under the name is another one now.
  p.signOut(['carla']);
  const stamp = String(made.signedOutAt);
  const ridBefore = made.pac.rid;
  people.carla = { uuids: ['bbbbbbbb-cccc-4ddd-8eee-ffffffffffff'] };
  const namesake = lookup('carla');
  t.check(namesake && namesake.pac.rid !== ridBefore &&
          (namesake.retiredRids || []).indexOf(ridBefore) >= 0 &&
          namesake.entryUuid === 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff' &&
          String(namesake.signedOutAt) === stamp,
          'B3. a namesake the delete\'s retirement never reached still gets ' +
          'a NEW RID; the deleted person\'s stamp is kept',
          JSON.stringify({ ridBefore: ridBefore, namesake: namesake }));

  // B4: a create race reconciled — the record's UUID is now an alias.
  people.dora = { uuids: ['00000000-0000-4000-8000-000000000001', U2] };
  t.check(lookup('dora').pac.rid === oldRid,
          'B4. an alias of the entry is the same entry: the RID is kept');

  // B5: PKINIT's keyless person.
  people.erin = { uuids: [U1], keyless: true };
  const keyless = p.certificatePerson(['erin']);
  const keylessRid = keyless && keyless.pac.rid;
  people.erin = { uuids: [U2], keyless: true };
  const keylessNamesake = p.certificatePerson(['erin']);
  t.check(keyless && keyless.entryUuid === U1 && keylessNamesake &&
          keylessNamesake.pac.rid !== keylessRid,
          'B5. a keyless (PKINIT) person is bound the same way, and a ' +
          'namesake gets a new RID',
          JSON.stringify({ keylessRid: keylessRid,
                           now: keylessNamesake && keylessNamesake.pac.rid }));
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
  clean.STS_MODE = 'product';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 120000,
    maxBuffer: 16 * 1024 * 1024
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
  developmentMode(t);
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
  let rows = null;
  try {
    rows = childBody();
  } catch (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  }
  process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
  process.exit(0);
}

module.exports = {
  name: 'kerberos_namesake_rid',
  describe: 'a person deleted and made again under the same name gets a RID ' +
            '(a SID) of their own; an existing person keeps theirs',
  run: run
};
