// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: credential_facts.js
//
// ===========================================================================
// ONE PARSE OF A PERSON'S VALUES, AND ONE WRITE OF A KEY (#929).
//
// `factorHolderRowFromValues()` and `factsFromValues()` used to parse the
// keys, the authenticator and the mailed factor separately and then compute
// the same eight facts. The Users page builds a row per person it shows
// (#820), so that second parse is the cost. `interpretValues()` reads them
// once. The census (`factorCensus()` → `factsFromValues()`) must stay one
// parse per name and must not start reading recovery codes.
//
// The five key writers used to repeat the same read-find-maybe-write. A
// mark that was already stored must not be written again (#910): that write
// is what sent CAEP credential-change a second time. `noteKeyUsed()` runs
// on every passkey sign-in, so the helper adds no store read.
//
// Asserted, in a realm of its own:
//
//   1. a grid — password, primary key, mfa key, authenticator (clear,
//      unreadable, sealed-unusable), recovery codes (held and unreadable),
//      an emailed factor, a disabled account, a name with no entry — has
//      `factorHolderRowsAsync()`'s shared members equal to `mechanismsFor()`
//      and to `factorCensus()`. The census's keys are exactly those eight,
//      and while it runs the recovery codes are not read. A roster row
//      parses each of the three once.
//   2. the five writers, over a `keysOf` fixture and a recording
//      `replaceWebauthn` on the directory the stack already installed:
//      no store (and no read), a missing key, nothing changed, a real
//      change, and a throw. `noteKeyUsed` reads keys once and returns the
//      store's own answer.
//
// The 3,000-person file stays about call counts. This one is the grid and
// the writers. WHY IN PROCESS: both claims are about which functions run.
// ===========================================================================

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const credentials = require('../common/credentials');
const errorCodes = require('../common/error_codes');
const ldap = require('../ldap/ldap_server');

const log = require('bunyan').createLogger({
  name: 'credential_facts',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);
const REALM = 'cf' + STAMP.slice(-6);
const RAW = '  ada  ';
const TRIM = 'ada';

const SHARED = ['password', 'primaryKeys', 'mfaKeys', 'totp', 'totpUsable',
                'mfaRequired', 'secondFactor', 'usable'];
const ROW_KEYS = ['username', 'inDirectory', 'known', 'password',
                  'primaryKeys', 'mfaKeys', 'totp', 'totpUsable',
                  'totpDetail', 'backupCodes', 'recoveryAdvised',
                  'mfaRequired', 'secondFactor', 'usable'];

function keyJson(id, role) {
  log.debug("Entering keyJson().");
  const out = JSON.stringify({
    credentialId: id, role: role, signCount: 0,
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' } });
  log.debug("Leaving keyJson().");
  return out;
}

function totpJson(secret, sealed, enrolledAt) {
  log.debug("Entering totpJson().");
  const out = JSON.stringify({
    secret: secret, sealed: sealed, algorithm: 'SHA1', digits: 6,
    period: 30, enrolledAt: enrolledAt, lastUsedAt: 0 });
  log.debug("Leaving totpJson().");
  return out;
}

function specs() {
  log.debug("Entering specs().");
  const clear = totpJson('JBSWY3DPEHPK3PXP', false, 1000);
  const sealed = totpJson('not-an-envelope', true, 2000);
  const codes = JSON.stringify({
    version: 2, total: 0, remaining: 0, generatedAt: 1000,
    lastUsedAt: 0, sealed: false, hashed: true, vault: '[]' });
  const out = [
    { slug: 'none' },
    { slug: 'password', password: true },
    { slug: 'primary', keys: [['p', 'primary']] },
    { slug: 'mfa', keys: [['m', 'mfa']] },
    { slug: 'both-keys', keys: [['p', 'primary'], ['m', 'mfa']] },
    { slug: 'totp', totp: clear },
    { slug: 'totp-bad', totp: 'not json' },
    { slug: 'totp-sealed', totp: sealed },
    { slug: 'password-totp', password: true, totp: clear },
    { slug: 'mfa-codes', keys: [['m', 'mfa']], codes: codes },
    { slug: 'mfa-totp', keys: [['m', 'mfa']], totp: clear },
    { slug: 'mail', mail: true },
    { slug: 'disabled', password: true, keys: [['m', 'mfa']],
      disabled: true },
    { slug: 'bad-key', keys: [['p', 'primary']], badKey: true },
    { slug: 'bad-codes', totp: clear, codes: 'not json codes' },
    { slug: 'all', password: true, mail: true, totp: clear, codes: codes,
      keys: [['p', 'primary'], ['m', 'mfa']] }
  ];
  log.debug("Leaving specs().");
  return out;
}

function nameOf(slug) {
  log.debug("Entering nameOf().");
  const out = 'cf-' + STAMP + '-' + slug;
  log.debug("Leaving nameOf().");
  return out;
}

function seedOne(t, spec) {
  log.debug("Entering seedOne().");
  const name = nameOf(spec.slug);
  const made = ldap.createUser(name, { invent: false, origin: 'test' });
  if (!made || !made.ok) {
    t.bad('seeding ' + name, JSON.stringify(made && made.errors));
    log.debug("Leaving seedOne(). A create failed.");
    return null;
  }
  const entry = ldap.existingUserEntry(name);
  if (!entry) {
    t.bad('no entry after creating ' + name);
    log.debug("Leaving seedOne(). No entry.");
    return null;
  }
  const a = entry.attributes;
  if (spec.password) {
    a.userpassword = ['$scrypt$seeded-presence-only'];
  }
  if (spec.keys || spec.badKey) {
    const values = [];
    if (spec.badKey) {
      values.push('not json a client wrote');
    }
    (spec.keys || []).forEach(function (pair) {
      values.push(keyJson(spec.slug + '-' + pair[0], pair[1]));
    });
    a.stswebauthncredential = values;
  }
  if (spec.totp) {
    a.ststotpcredential = [spec.totp];
  }
  if (spec.codes) {
    a.stsbackupcodes = [spec.codes];
  }
  if (spec.mail) {
    a.mail = [name + '@example.org'];
    a.stsmailverified = [name + '@example.org'];
    a.stsmailfactor = ['code'];
  }
  if (spec.disabled) {
    a.pwdaccountlockedtime = ['000001010000Z'];
  }
  log.debug("Leaving seedOne().");
  return { username: name, inDirectory: true, known: true,
           disabled: !!spec.disabled };
}

function seed(t) {
  log.debug("Entering seed().");
  const people = [];
  const list = specs();
  for (let i = 0; i < list.length; i++) {
    const one = seedOne(t, list[i]);
    if (!one) {
      log.debug("Leaving seed(). A create failed.");
      return null;
    }
    people.push(one);
  }
  people.push({ username: nameOf('ghost'), inDirectory: false,
                known: false, disabled: false });
  log.debug("Leaving seed().");
  return people;
}

function installParseSpies() {
  log.debug("Entering installParseSpies().");
  const proto = credentials.Credentials.prototype;
  const real = {
    keys: proto.keysFromValues,
    totp: proto.totpStatusFromValue,
    backup: proto.backupCodesFromValue
  };
  const counts = { keys: 0, totp: 0, backup: 0 };
  proto.keysFromValues = function () {
    counts.keys += 1;
    return real.keys.apply(this, arguments);
  };
  proto.totpStatusFromValue = function () {
    counts.totp += 1;
    return real.totp.apply(this, arguments);
  };
  proto.backupCodesFromValue = function () {
    counts.backup += 1;
    return real.backup.apply(this, arguments);
  };
  log.debug("Leaving installParseSpies().");
  return {
    counts: counts,
    restore: function restore() {
      log.debug("Entering restore().");
      proto.keysFromValues = real.keys;
      proto.totpStatusFromValue = real.totp;
      proto.backupCodesFromValue = real.backup;
      log.debug("Leaving restore().");
    }
  };
}

function zero(counts) {
  log.debug("Entering zero().");
  counts.keys = 0;
  counts.totp = 0;
  counts.backup = 0;
  log.debug("Leaving zero().");
}

function sharedOf(obj) {
  log.debug("Entering sharedOf().");
  const out = {};
  SHARED.forEach(function (key) {
    out[key] = obj[key];
  });
  log.debug("Leaving sharedOf().");
  return out;
}

function compare(t, people, rows, census) {
  log.debug("Entering compare().");
  people.forEach(function (person, index) {
    const name = person.username;
    const row = rows[index];
    const facts = census.get(name);
    const mechanisms = credentials.mechanismsFor(name);
    const what = name;
    t.check(row && facts, what + ' has a row and census facts',
            'row=' + !!row + ' facts=' + !!facts);
    if (!row || !facts) {
      return;
    }
    t.equal(JSON.stringify(Object.keys(facts)), JSON.stringify(SHARED),
            what + ' census members, in order');
    t.equal(JSON.stringify(Object.keys(row)), JSON.stringify(ROW_KEYS),
            what + ' roster members, in order');
    t.equal(JSON.stringify(sharedOf(row)),
            JSON.stringify(sharedOf(mechanisms)),
            what + ' row matches mechanismsFor');
    t.equal(JSON.stringify(sharedOf(row)), JSON.stringify(sharedOf(facts)),
            what + ' row matches factorCensus');
    t.equal(JSON.stringify(row.totpDetail),
            JSON.stringify(mechanisms.totpDetail),
            what + ' totpDetail');
    t.equal(JSON.stringify(row.backupCodes),
            JSON.stringify(mechanisms.backupCodes),
            what + ' backupCodes');
    t.equal(row.recoveryAdvised, mechanisms.recoveryAdvised,
            what + ' recoveryAdvised');
    t.equal(row.username, name, what + ' username');
    t.equal(row.inDirectory, person.inDirectory, what + ' inDirectory');
    t.equal(row.known, person.known, what + ' known');
    if (person.disabled) {
      t.equal(credentials.accountDisabled(name), true,
              what + ' is disabled');
      t.equal(mechanisms.disabled, true,
              what + ' mechanismsFor reports the lock');
      t.equal(facts.usable, true,
              what + ' a lock is not a missing way in');
    }
  });
  log.debug("Leaving compare().");
}

async function grid(t) {
  log.debug("Entering grid().");
  const people = seed(t);
  if (!people) {
    log.debug("Leaving grid(). Seeding failed.");
    return;
  }
  const spies = installParseSpies();
  let census = null;
  let rows = null;
  try {
    zero(spies.counts);
    census = credentials.factorCensus(people.map(function (person) {
      return person.username;
    }));
    t.equal(spies.counts.keys, people.length,
            'census parses keys once per name');
    t.equal(spies.counts.totp, people.length,
            'census parses the authenticator once per name');
    t.equal(spies.counts.backup, 0,
            'census does not read recovery codes');
    zero(spies.counts);
    rows = await credentials.factorHolderRowsAsync(people.map(
      function (person) {
        return { username: person.username,
                 inDirectory: person.inDirectory, known: person.known };
      }));
    t.equal(spies.counts.keys, people.length,
            'a roster row parses keys once');
    t.equal(spies.counts.totp, people.length,
            'a roster row parses the authenticator once');
    t.equal(spies.counts.backup, people.length,
            'a roster row reads recovery codes once');
  } finally {
    spies.restore();
  }
  if (census && Array.isArray(rows)) {
    compare(t, people, rows, census);
  }
  log.debug("Leaving grid().");
}

// The writers' directory. `keysOf` is replaced for the call and records the
// argument it was given; the lookup then falls back to the trimmed name, so
// a writer that started trimming before the read fails the argument check
// while a fixture stored under the trimmed name still answers. The write is
// kept only when `replaceWebauthn` returns: a throw must not look, on the
// next call, like a mark already stored. The answer is the string
// 'stored-row', so a writer that coerces it with `!!` cannot pass as
// `noteKeyUsed`.
function clone(value) {
  log.debug("Entering clone().");
  const out = JSON.parse(JSON.stringify(value));
  log.debug("Leaving clone().");
  return out;
}

function deviceKey(id, role, extra) {
  log.debug("Entering deviceKey().");
  const key = {
    credentialId: id, role: role, signCount: 1, label: 'Desk',
    attachment: 'platform',
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' }
  };
  Object.keys(extra || {}).forEach(function (name) {
    key[name] = extra[name];
  });
  log.debug("Leaving deviceKey().");
  return key;
}

function heldKeys(extra) {
  log.debug("Entering heldKeys().");
  const out = {};
  out[TRIM] = [
    deviceKey('k1', 'mfa', extra),
    deviceKey('k2', 'primary', { label: 'Other' })
  ];
  log.debug("Leaving heldKeys().");
  return out;
}

function clearState(state) {
  log.debug("Entering clearState().");
  state.keysOfCalls = [];
  state.writes = [];
  state.commits = 0;
  state.throwNext = false;
  log.debug("Leaving clearState().");
}

function withRecording(t, initial, fn) {
  log.debug("Entering withRecording().");
  const proto = credentials.Credentials.prototype;
  const realKeysOf = proto.keysOf;
  const directory = credentials.directoryInstalled();
  const realReplace = directory.replaceWebauthn;
  const state = {
    keysOfCalls: [], writes: [], commits: 0, throwNext: false, saved: {}
  };
  Object.keys(initial).forEach(function (key) {
    state.saved[key] = initial[key].map(clone);
  });
  proto.keysOf = function (username) {
    state.keysOfCalls.push(username);
    const exact = Object.prototype.hasOwnProperty.call(state.saved,
                                                        username);
    const key = exact ? username : String(username || '').trim();
    const list = state.saved[key] || [];
    return list.map(clone);
  };
  directory.replaceWebauthn = function (name, values) {
    state.writes.push({ name: name, values: values.slice() });
    if (state.throwNext) {
      state.throwNext = false;
      throw new Error('store refused');
    }
    const parsed = values.map(function (one) {
      return JSON.parse(one);
    });
    let found = false;
    Object.keys(state.saved).forEach(function (key) {
      if (String(key).trim() === name) {
        state.saved[key] = parsed.map(clone);
        found = true;
      }
    });
    if (!found) {
      state.saved[name] = parsed.map(clone);
    }
    state.commits += 1;
    // Absent means the truthy string. A caller can set `false`: rename
    // still succeeds, which is the old door ignoring the boolean.
    if (Object.prototype.hasOwnProperty.call(state, 'answer')) {
      return state.answer;
    }
    return 'stored-row';
  };
  let failed = null;
  try {
    fn(state);
  } catch (e) {
    log.debug("Caught in withRecording(): " + ((e && e.message) || e));
    // A throw here is the test's own bug. Put the directory back first.
    failed = e;
  } finally {
    proto.keysOf = realKeysOf;
    directory.replaceWebauthn = realReplace;
  }
  if (failed) {
    t.bad('writer fixture threw', (failed && failed.message) || failed);
  }
  log.debug("Leaving withRecording().");
}

function withoutStore(t, fn) {
  log.debug("Entering withoutStore().");
  const proto = credentials.Credentials.prototype;
  const realKeysOf = proto.keysOf;
  const directory = credentials.directoryInstalled();
  const calls = [];
  let installed = false;
  try {
    proto.keysOf = function (username) {
      calls.push(username);
      return [];
    };
    // No `replaceWebauthn`: the slot stays filled enough for `setDirectory`
    // to accept it, which is the "no store" the five writers already meant.
    // The same object comes back afterwards, so the census hooks still name
    // the directory they were offered beside.
    installed = credentials.setDirectory({
      readPassword: function () {
        return '';
      },
      writePassword: function () {
        return true;
      }
    });
    if (!installed) {
      t.bad('setDirectory refused the store-less hooks');
    } else {
      fn(calls);
    }
  } finally {
    proto.keysOf = realKeysOf;
    if (directory) {
      credentials.setDirectory(directory);
    }
  }
  log.debug("Leaving withoutStore().");
}

function readOnce(t, state, argument, what) {
  log.debug("Entering readOnce().");
  t.equal(state.keysOfCalls.length, 1, what + ' reads keys once');
  t.equal(state.keysOfCalls[0], argument, what + ' keysOf argument');
  log.debug("Leaving readOnce().");
}

function didNotWrite(t, state, what) {
  log.debug("Entering didNotWrite().");
  t.equal(state.writes.length, 0, what + ' does not write');
  log.debug("Leaving didNotWrite().");
}

function committed(t, state, what) {
  log.debug("Entering committed().");
  const once = state.writes.length === 1 && state.commits === 1 &&
               state.writes[0].name === TRIM;
  t.check(once, what + ' writes the trimmed name once',
          JSON.stringify({ writes: state.writes.length,
                           commits: state.commits,
                           name: state.writes[0] && state.writes[0].name }));
  const values = once ? state.writes[0].values.map(function (one) {
    return JSON.parse(one);
  }) : [];
  log.debug("Leaving committed().");
  return values;
}

function siblingUntouched(t, values, what) {
  log.debug("Entering siblingUntouched().");
  t.equal(values.length, 2, what + ' writes both keys');
  if (values.length === 2) {
    t.equal(values[1].credentialId, 'k2', what + ' sibling id');
    t.equal(values[1].label, 'Other', what + ' sibling label');
    t.equal(values[1].signCount, 1, what + ' sibling counter');
  }
  log.debug("Leaving siblingUntouched().");
}

function refused(t, answer, code, what) {
  log.debug("Entering refused().");
  t.equal(!!(answer && answer.ok), false, what + ' refuses');
  const found = answer && typeof answer === 'object' ?
    errorCodes.codeOf(answer) : '';
  t.equal(found, code, what);
  log.debug("Leaving refused().");
}

function noStore(t) {
  log.debug("Entering noStore().");
  withoutStore(t, function (calls) {
    const answers = [
      credentials.untrustKeyAttestation(RAW, 'k1',
                                        { status: 'REVOKED' }),
      credentials.noteKeyAttestationRefused(RAW, 'k1', 'STS-X', 'why'),
      credentials.noteKeyPolicyRefused(RAW, 'k1', 'post-quantum', 'STS-X',
                                       'why'),
      credentials.noteKeyUsed(RAW, 'k1', 3, { bs: true, be: false })
    ];
    answers.forEach(function (answer, i) {
      t.equal(answer, false, 'no store, writer ' + i + ' returns false');
    });
    refused(t, credentials.renameKey(RAW, 'k1', 'n'.repeat(61)),
            'STS-AUTHN-0059', 'no store is reported before a bad label');
    refused(t, credentials.renameKey(RAW, 'k1', 'Fine'), 'STS-AUTHN-0059',
            'no store refuses a rename');
    t.equal(calls.length, 0, 'no store reads no keys');
  });
  log.debug("Leaving noStore().");
}

function missingKey(t) {
  log.debug("Entering missingKey().");
  withRecording(t, heldKeys({}), function (state) {
    clearState(state);
    t.equal(credentials.untrustKeyAttestation(RAW, 'missing', {}), false,
            'untrust of a missing key returns false');
    readOnce(t, state, RAW, 'untrust of a missing key');
    didNotWrite(t, state, 'untrust of a missing key');
    clearState(state);
    t.equal(credentials.noteKeyAttestationRefused(RAW, 'missing', 'STS-X',
                                                  'why'), false,
            'attestation refusal of a missing key returns false');
    readOnce(t, state, RAW, 'attestation refusal of a missing key');
    didNotWrite(t, state, 'attestation refusal of a missing key');
    clearState(state);
    t.equal(credentials.noteKeyPolicyRefused(RAW, 'missing', 'post-quantum',
                                            'STS-X', 'why'), false,
            'policy refusal of a missing key returns false');
    readOnce(t, state, RAW, 'policy refusal of a missing key');
    didNotWrite(t, state, 'policy refusal of a missing key');
    clearState(state);
    t.equal(credentials.noteKeyUsed(RAW, 'missing', 4, null), false,
            'noteKeyUsed of a missing key returns false');
    readOnce(t, state, RAW, 'noteKeyUsed of a missing key');
    didNotWrite(t, state, 'noteKeyUsed of a missing key');
    clearState(state);
    refused(t, credentials.renameKey(RAW, 'missing', 'Window'),
            'STS-AUTHN-0299', 'rename of a key that is not theirs');
    readOnce(t, state, TRIM, 'rename of a key that is not theirs');
    didNotWrite(t, state, 'rename of a key that is not theirs');
  });
  log.debug("Leaving missingKey().");
}

function attestation(t) {
  log.debug("Entering attestation().");
  const why = 'w'.repeat(600);
  withRecording(t, heldKeys({}), function (state) {
    clearState(state);
    const first = credentials.noteKeyAttestationRefused(RAW, 'k1', 'STS-X',
                                                        why);
    t.equal(first, true, 'a new attestation refusal is recorded');
    readOnce(t, state, RAW, 'attestation refusal');
    const values = committed(t, state, 'attestation refusal');
    if (values[0]) {
      t.equal(values[0].attestationRefused.why, why.slice(0, 500),
              'the refusal is stored truncated');
      t.equal(values[0].attestationRefused.code, 'STS-X',
              'the refusal keeps its code');
      siblingUntouched(t, values, 'attestation refusal');
    }
    clearState(state);
    const second = credentials.noteKeyAttestationRefused(RAW, 'k1', 'STS-X',
                                                         why);
    t.equal(second, false, 'the same refusal does not write again');
    readOnce(t, state, RAW, 'repeated attestation refusal');
    didNotWrite(t, state, 'repeated attestation refusal');
    clearState(state);
    state.throwNext = true;
    const threw = credentials.noteKeyAttestationRefused(RAW, 'k1', 'STS-X',
                                                        'other');
    t.equal(threw, false, 'a thrown attestation write returns false');
    readOnce(t, state, RAW, 'thrown attestation write');
    t.equal(state.writes.length, 1, 'the thrown write was attempted');
    t.equal(state.commits, 0, 'a thrown attestation write is not kept');
    t.equal(state.saved[TRIM][0].attestationRefused.why, why.slice(0, 500),
            'a thrown write leaves the stored refusal');
  });
  log.debug("Leaving attestation().");
}

function policy(t) {
  log.debug("Entering policy().");
  const why = 'p'.repeat(600);
  withRecording(t, heldKeys({}), function (state) {
    clearState(state);
    const empty = credentials.noteKeyPolicyRefused(RAW, 'k1', '', 'STS-X',
                                                   why);
    t.equal(empty, false, 'an empty policy reason is nothing new');
    readOnce(t, state, RAW, 'empty policy reason');
    didNotWrite(t, state, 'empty policy reason');
    clearState(state);
    const first = credentials.noteKeyPolicyRefused(RAW, 'k1',
                                                  'post-quantum', 'STS-X',
                                                  why);
    t.equal(first, true, 'a new policy refusal is recorded');
    readOnce(t, state, RAW, 'policy refusal');
    const values = committed(t, state, 'policy refusal');
    if (values[0]) {
      t.equal(values[0].policyRefused['post-quantum'].why,
              why.slice(0, 500), 'the policy refusal is stored truncated');
      siblingUntouched(t, values, 'policy refusal');
    }
    clearState(state);
    const second = credentials.noteKeyPolicyRefused(RAW, 'k1',
                                                   'post-quantum', 'STS-X',
                                                   why);
    t.equal(second, false, 'the same policy refusal does not write again');
    readOnce(t, state, RAW, 'repeated policy refusal');
    didNotWrite(t, state, 'repeated policy refusal');
    clearState(state);
    state.throwNext = true;
    const threw = credentials.noteKeyPolicyRefused(RAW, 'k1', 'other',
                                                  'STS-Y', 'newly');
    t.equal(threw, false, 'a thrown policy write returns false');
    readOnce(t, state, RAW, 'thrown policy write');
    t.equal(state.writes.length, 1, 'the thrown policy write was attempted');
    t.equal(state.commits, 0, 'a thrown policy write is not kept');
  });
  log.debug("Leaving policy().");
}

function untrust(t) {
  log.debug("Entering untrust().");
  withRecording(t, heldKeys({
    attestation: { trusted: false, anchor: 'old' }
  }), function (state) {
    clearState(state);
    t.equal(credentials.untrustKeyAttestation(RAW, 'k1',
                                             { status: 'REVOKED' }), false,
            'an already-untrusted key is nothing to do');
    readOnce(t, state, RAW, 'already-untrusted key');
    didNotWrite(t, state, 'already-untrusted key');
  });
  withRecording(t, heldKeys({}), function (state) {
    clearState(state);
    t.equal(credentials.untrustKeyAttestation(RAW, 'k1',
                                             { status: 'REVOKED' }), false,
            'a key with no attestation is nothing to do');
    readOnce(t, state, RAW, 'key with no attestation');
    didNotWrite(t, state, 'key with no attestation');
  });
  withRecording(t, heldKeys({
    attestation: { trusted: true, anchor: 'google',
                   androidRevocation: { status: 'good' } }
  }), function (state) {
    clearState(state);
    const first = credentials.untrustKeyAttestation(RAW, 'k1',
      { status: 'REVOKED', listVersion: 'v9' });
    t.equal(first, true, 'untrust returns true, not the store answer');
    readOnce(t, state, RAW, 'untrust');
    const values = committed(t, state, 'untrust');
    if (values[0]) {
      t.equal(values[0].attestation.trusted, false, 'trusted is cleared');
      t.equal(values[0].attestation.anchor, '', 'the anchor is cleared');
      t.equal(values[0].attestation.androidRevocation.status, 'REVOKED',
              'the revocation status is merged');
      t.equal(values[0].attestation.androidRevocation.listVersion, 'v9',
              'the revocation version is merged');
      siblingUntouched(t, values, 'untrust');
    }
    clearState(state);
    const second = credentials.untrustKeyAttestation(RAW, 'k1',
      { status: 'REVOKED', listVersion: 'v9' });
    t.equal(second, false, 'untrust of an untrusted key does not write');
    readOnce(t, state, RAW, 'second untrust');
    didNotWrite(t, state, 'second untrust');
    clearState(state);
    state.throwNext = true;
    // The successful untrust left it untrusted, so a second call would
    // not write. Put the mark back: this call is a real change again, the
    // throw is the failure, and the key stays trusted because nothing
    // was kept.
    state.saved[TRIM][0].attestation.trusted = true;
    const threw = credentials.untrustKeyAttestation(RAW, 'k1',
      { status: 'REVOKED' });
    t.equal(threw, false, 'a thrown untrust returns false');
    readOnce(t, state, RAW, 'thrown untrust');
    t.equal(state.writes.length, 1, 'the thrown untrust was attempted');
    t.equal(state.commits, 0, 'a thrown untrust is not kept');
  });
  log.debug("Leaving untrust().");
}

function used(t) {
  log.debug("Entering used().");
  withRecording(t, heldKeys({}), function (state) {
    clearState(state);
    const before = Date.now();
    const answer = credentials.noteKeyUsed(RAW, 'k1', 9,
                                          { bs: true, be: true });
    t.equal(answer, 'stored-row',
            'noteKeyUsed returns the store answer, not !! of it');
    readOnce(t, state, RAW, 'noteKeyUsed');
    const values = committed(t, state, 'noteKeyUsed');
    if (values[0]) {
      t.equal(values[0].signCount, 9, 'the counter is recorded');
      t.check(values[0].lastUsedAt >= before, 'lastUsedAt moves forward');
      t.equal(values[0].backupState, true, 'BS is kept');
      t.equal(values[0].backupEligible, true,
              'BE is kept when the key had none');
      siblingUntouched(t, values, 'noteKeyUsed');
    }
    clearState(state);
    const again = credentials.noteKeyUsed(RAW, 'k1', 10,
                                         { bs: false, be: false });
    t.equal(again, 'stored-row', 'a later assertion is recorded too');
    readOnce(t, state, RAW, 'second noteKeyUsed');
    const next = committed(t, state, 'second noteKeyUsed');
    if (next[0]) {
      t.equal(next[0].signCount, 10, 'the counter advances');
      t.equal(next[0].backupState, false, 'BS follows the assertion');
      t.equal(next[0].backupEligible, true,
              'BE does not overwrite a boolean already stored');
    }
    clearState(state);
    state.throwNext = true;
    const threw = credentials.noteKeyUsed(RAW, 'k1', 11, null);
    t.equal(threw, false, 'a thrown counter write returns false');
    readOnce(t, state, RAW, 'thrown noteKeyUsed');
    t.equal(state.writes.length, 1, 'the thrown counter write was attempted');
    t.equal(state.commits, 0, 'a thrown counter write is not kept');
    t.equal(state.saved[TRIM][0].signCount, 10,
            'the stored counter stays the one that was kept');
  });
  log.debug("Leaving used().");
}

function rename(t) {
  log.debug("Entering rename().");
  withRecording(t, heldKeys({}), function (state) {
    // The store's false is not a refusal. The old door ignored it.
    state.answer = false;
    clearState(state);
    refused(t, credentials.renameKey(RAW, 'k1', 'n'.repeat(61)),
            'STS-AUTHN-0300', 'a name over 60 characters');
    t.equal(state.keysOfCalls.length, 0, 'a bad name reads no keys');
    didNotWrite(t, state, 'a bad name');
    clearState(state);
    refused(t, credentials.renameKey(RAW, 'k1', 'bad\u0007name'),
            'STS-AUTHN-0300', 'a name with a control character');
    t.equal(state.keysOfCalls.length, 0,
            'a control character reads no keys');
    didNotWrite(t, state, 'a control character');
    clearState(state);
    const sixty = 'n'.repeat(60);
    const boundary = credentials.renameKey(RAW, 'k1', sixty);
    t.equal(boundary.ok, true, '60 characters is a name');
    t.equal(boundary.label, sixty, 'the 60-character name is kept');
    t.equal(boundary.previous, 'Desk', 'the previous name is the label');
    readOnce(t, state, TRIM, 'rename');
    const values = committed(t, state, 'rename');
    if (values[0]) {
      t.equal(values[0].label, sixty, 'the written label');
      siblingUntouched(t, values, 'rename');
    }
    clearState(state);
    const same = credentials.renameKey(RAW, 'k1', sixty);
    t.equal(same.ok, true, 'the same name is still written');
    t.equal(same.previous, sixty, 'previous is that same name');
    readOnce(t, state, TRIM, 'rename to the stored name');
    committed(t, state, 'rename to the stored name');
    clearState(state);
    const cleared = credentials.renameKey(RAW, 'k1', '');
    t.equal(cleared.ok, true, 'an empty name restores the default');
    t.equal(cleared.label, 'Passkey', 'the default for a device key');
    t.equal(cleared.previous, sixty, 'previous is the name it had');
    readOnce(t, state, TRIM, 'empty rename');
    const restored = committed(t, state, 'empty rename');
    if (restored[0]) {
      t.equal(restored[0].label, 'Passkey', 'the written default');
    }
    clearState(state);
    state.throwNext = true;
    const threw = credentials.renameKey(RAW, 'k1', 'Window');
    refused(t, threw, 'STS-AUTHN-0068', 'a thrown rename');
    const message = threw && threw.errors && threw.errors[0];
    t.check(String(message || '').indexOf('store refused') >= 0,
            'the throw names the store', message);
    readOnce(t, state, TRIM, 'thrown rename');
    t.equal(state.writes.length, 1, 'the thrown rename was attempted');
    t.equal(state.commits, 0, 'a thrown rename is not kept');
    t.equal(state.saved[TRIM][0].label, 'Passkey',
            'a thrown rename leaves the stored name');
  });
  log.debug("Leaving rename().");
}

function writers(t) {
  log.debug("Entering writers().");
  const directory = credentials.directoryInstalled();
  if (!directory || typeof directory.replaceWebauthn !== 'function') {
    t.bad('the directory slot has no replaceWebauthn to record');
    log.debug("Leaving writers(). No store.");
    return;
  }
  noStore(t);
  missingKey(t);
  attestation(t);
  policy(t);
  untrust(t);
  used(t);
  rename(t);
  log.debug("Leaving writers().");
}

async function run(t) {
  log.debug("Entering run().");
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm', (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  try {
    await realms.run(made.realm, async function () {
      await grid(t);
      writers(t);
    });
  } finally {
    realms.remove(REALM);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'credential_facts',
  describe: 'one parse of a person\'s credential values, and one write of ' +
            'a key (#929)',
  run: run
};
