// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: credentials-vectors.js
//
// ---------------------------------------------------------------------------
// THE CREDENTIALS' VECTORS (#444 phase 5, the `sts-credentials` crate): what
// the credential doors and their mechanisms answer today, for the crate to
// answer identically. Written by `tests/tools/crypto-vectors.js` as
// `credentials-node.json` (`STS_ONLY=credentials`); read by
// `rust/crates/sts-credentials/tests/node_vectors.rs`, which writes
// `credentials-rust.json` back under `STS_WRITE_VECTORS=1`, and
// `tests/rust_crypto_vectors.js` holds THAT to Node through `checkRust()`.
//
// THE CASES ARE RECORDED, NOT DESCRIBED, as `policy-vectors.js`'s are. The
// mechanisms (`common/totp.ts`, `common/backup_codes.ts`,
// `common/app_passwords.ts`) and the doors (`common/credentials.ts`) are
// built from their own `defaultDeps()` with every dependency that reaches
// outside them replaced by one that answers from the case and writes the
// question and its answer on the case's TAPE: the settings, the mode
// predicates, the policies, the keystore, the service-account register, the
// console roles, the clock, the random source, and the directory's hooks —
// each READ keyed by a generation that moves on at every WRITE, and each
// write recorded with its answer on the case's MUTATIONS. Every hash made
// (`crypto.hashSecret()`, `crypto.hashPassword()`) is recorded with its
// plaintext, so a write holding a hash is compared by what it verifies.
//
//   totp       `Totp`'s settings, base32, codes, verify, issuer, otpauth
//   backup     `BackupCodes`' settings, generation, shape, comparisons
//   apps       `AppPasswords`' settings, scope, names, shape, generation
//   phishing   `PhishingResistance` over authentication events and URIs
//   scenarios  `Credentials`' doors, one or more steps over one world
//   webauthn   `authn/webauthn.js` and the attestation statements, over
//              registrations and assertions software authenticators made
//              here (`credentials-webauthn.js`)
//
// It needs the compiled tree: run it in the tests image.
// ---------------------------------------------------------------------------

const path = require('path');

// What a later step of a scenario reads of an earlier one: the secret an
// enrolment began with, a pending set's handle and codes, the app password
// shown once. Set as the steps run; the step's arguments are recorded as
// they were, so the crate needs none of this.
const PENDING = { secret: '', handle: '', codes: [] };
const PRINTED = { alice: '' };

function clone(value) {
  return value === undefined ? null : JSON.parse(JSON.stringify(value));
}

// A seeded random source (xorshift32), so a run is the same run each time
// and the crate answers the same draws from the tape.
function seeded(seed) {
  let x = seed >>> 0 || 1;
  return function () {
    x ^= x << 13; x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5; x >>>= 0;
    return x;
  };
}

async function build(ROOT) {
  delete process.env.CONFIG_FILE;
  const req = function (rel) {
    return require(path.join(ROOT, rel));
  };
  const config = req('common/config');
  const realms = req('common/realms');
  const errorCodes = req('common/error_codes');
  const stsCrypto = req('common/crypto');
  const totpModule = req('common/totp');
  const backupModule = req('common/backup_codes');
  const appsModule = req('common/app_passwords');
  const credentialsModule = req('common/credentials');
  const PhishingResistance = req('common/phishing_resistance');
  const riskFailures = req('risk/risk_failures');
  const bootstrapName = req('common/bootstrap_name');

  // -------------------------------------------------------------------------
  // THE TAPE, and the case being recorded.
  // -------------------------------------------------------------------------
  let CASE = null;
  let TAPE = null;
  let MUTATIONS = null;
  let RANDOM = null;
  let HASHES = null;
  let OBSERVED = null;
  let GEN = 0;
  let RNG = seeded(1);
  const rec = function (key, value) {
    if (TAPE) {
      TAPE[JSON.stringify(key)] = clone(value);
    }
    return value;
  };
  const settingOf = function (key) {
    const held = CASE && CASE.settings &&
      Object.prototype.hasOwnProperty.call(CASE.settings, key);
    const out = held ? CASE.settings[key] : config.value(key);
    return rec(['setting', key], out);
  };
  const fakeConfig = { value: settingOf };
  const predicate = function (name) {
    return function () {
      const table = (CASE && CASE.mode) || {};
      const out = Object.prototype.hasOwnProperty.call(table, name)
        ? !!table[name] : DEFAULT_MODE[name];
      return rec(['predicate', name], out);
    };
  };
  const DEFAULT_MODE = {
    verifiesCredentials: true,
    acceptsPasswordAloneFromSecondFactorAccounts: false,
    autoCreates: false
  };
  const fakeMode = {};
  Object.keys(DEFAULT_MODE).forEach(function (name) {
    fakeMode[name] = predicate(name);
  });
  const randomBytes = function (n) {
    const out = Buffer.alloc(n);
    for (let i = 0; i < n; i++) {
      out[i] = RNG() & 0xff;
    }
    if (RANDOM) {
      RANDOM.push({ kind: 'bytes', n: n, hex: out.toString('hex') });
    }
    return out;
  };
  const randomInt = function (min, max) {
    const value = min + (RNG() % (max - min));
    if (RANDOM) {
      RANDOM.push({ kind: 'int', min: min, max: max, value: value });
    }
    return value;
  };
  const policy = function () {
    return (CASE && CASE.policy) || {};
  };
  const fakeAuthnPolicy = {
    allows: function (mechanism, role) {
      const off = policy().off || [];
      return rec(['policy.allows', mechanism, role],
                 off.indexOf(mechanism + '/' + role) < 0);
    },
    requireSecondFactor: function () {
      return rec(['policy.requireSecondFactor'],
                 policy().requireSecondFactor || 'if-held');
    },
    configuredSecondFactor: function () {
      return rec(['policy.configuredSecondFactor'],
                 policy().configuredSecondFactor || 'if-held');
    },
    requireSecondFactorForAdministrators: function () {
      return rec(['policy.requireSecondFactorForAdministrators'],
                 policy().forAdministrators || 'if-held');
    }
  };
  const fakeWebauthnPolicy = {
    useAllowed: function (use) {
      const off = policy().keyUsesOff || [];
      return { ok: rec(['policy.keyUse', use], off.indexOf(use) < 0) };
    }
  };
  const fakePasswordPolicy = {
    profileFor: function (name) {
      return rec(['policy.passwordProfile', String(name)],
                 policy().passwordProfile || { name: 'default' });
    },
    hashSpec: function (profile) {
      const spec = policy().hashSpec ||
        { algorithm: 'scrypt', logN: 15, r: 8, p: 1 };
      return rec(['policy.hashSpec', clone(profile)],
                 stsCrypto.passwordHashSpec(spec));
    }
  };
  const svc = function () {
    return (CASE && CASE.serviceAccounts) || {};
  };
  const fakeServiceAccounts = {
    isServiceAccountName: function (name) {
      return rec(['svc.is', String(name)], !!svc()[name]);
    },
    previousPassword: function (name) {
      const held = svc()[name] || (CASE && CASE.previous || {})[name];
      const hash = held && held.previous ? held.previous : null;
      rec(['svc.previous', String(name)], hash);
      return hash ? { hash: hash } : null;
    }
  };
  const fakeServiceAccountPolicy = {
    profileFor: function (name) {
      return String(name);
    },
    allowsDoor: function (door, profile) {
      const doors = (svc()[profile] || {}).doors || [];
      return !rec(['svc.refusesDoor', profile, door],
                  doors.indexOf(door) < 0);
    },
    exemptFromSecondFactor: function (profile) {
      return rec(['svc.exempt', String(profile)],
                 !!(svc()[profile] || {}).exempt);
    }
  };
  // A keystore that seals reversibly and visibly, so the crate can be held
  // to the very value Node wrote.
  const fakeKeystore = {
    persists: function () {
      return rec(['keystore.persists'], !!(CASE && CASE.persists));
    },
    seal: function (plain, label, scope) {
      const out = CASE && CASE.sealFails ? null
        : 'sealed:' + label + ':' + Buffer.from(String(plain), 'utf8')
          .toString('base64');
      return rec(['keystore.seal', String(plain), label, scope], out);
    },
    open: function (sealed, label) {
      const text = String(sealed || '');
      const prefix = 'sealed:' + label + ':';
      const out = text.indexOf(prefix) === 0 && !(CASE && CASE.openFails)
        ? Buffer.from(text.slice(prefix.length), 'base64').toString('utf8')
        : null;
      return rec(['keystore.open', text, label], out);
    },
    kekEpoch: function () {
      return -1;
    }
  };
  const recordedCrypto = Object.assign(Object.create(stsCrypto), {
    randomBytes: randomBytes,
    hashSecret: function (plain) {
      const out = stsCrypto.hashSecret(plain);
      if (HASHES) {
        HASHES[out] = String(plain);
      }
      return out;
    },
    hashPassword: function (plain, spec) {
      const out = stsCrypto.hashPassword(plain, spec);
      if (HASHES) {
        HASHES[out] = String(plain);
      }
      return out;
    }
  });
  const realmIdOf = function () {
    return rec(['realm'], String(realms.currentId()));
  };
  const fakeRealms = Object.assign(Object.create(realms), {
    currentId: realmIdOf,
    current: function () {
      return { id: realmIdOf() };
    }
  });

  // The mechanisms and the doors, from their own defaults.
  const totp = new totpModule.Totp(Object.assign(
    totpModule.Totp.defaultDeps(),
    { config: fakeConfig, crypto: recordedCrypto, realms: fakeRealms,
      authnPolicy: fakeAuthnPolicy, randomBytes: randomBytes }));
  const backup = new backupModule.BackupCodes(Object.assign(
    backupModule.BackupCodes.defaultDeps(),
    { config: fakeConfig, crypto: recordedCrypto,
      authnPolicy: fakeAuthnPolicy, randomInt: randomInt }));
  const apps = new appsModule.AppPasswords(Object.assign(
    appsModule.AppPasswords.defaultDeps(),
    { config: fakeConfig, crypto: recordedCrypto, randomInt: randomInt }));
  const Credentials = credentialsModule.Credentials;
  const credentials = new Credentials(Object.assign(
    Credentials.defaultDeps(),
    { config: fakeConfig, crypto: recordedCrypto, mode: fakeMode,
      realms: fakeRealms, keystore: fakeKeystore, totp: totp,
      backupCodes: backup,
      // The module's export carries the statics beside the instance's
      // methods, and the doors read both.
      appPasswords: Object.assign(Object.create(apps), {
        DOORS: appsModule.DOORS, DOOR_IDS: appsModule.DOOR_IDS,
        MAX_NAME: appsModule.MAX_NAME }),
      passwordPolicy: fakePasswordPolicy, authnPolicy: fakeAuthnPolicy,
      serviceAccounts: fakeServiceAccounts,
      serviceAccountPolicy: fakeServiceAccountPolicy,
      webauthnPolicy: fakeWebauthnPolicy,
      consoleRolesOf: function (name) {
        const held = ((CASE && CASE.roles) || {})[name] || [false, false];
        rec(['people.roles', String(name)], held);
        return { read: !!held[0], write: !!held[1] };
      } }));
  bootstrapName.current = function () {
    return rec(['people.bootstrap'], (CASE && CASE.bootstrap) || 'admin');
  };
  riskFailures.recordFailure = function (username, via, code) {
    if (OBSERVED) {
      OBSERVED.push({ kind: 'failure', username: String(username),
                      via: String(via), code: String(code) });
    }
  };
  credentials.setPasswordObserver(function (name, password, facts) {
    if (OBSERVED) {
      OBSERVED.push({ kind: 'password', name: name, password: password,
                      facts: clone(facts) });
    }
  });

  // THE DIRECTORY: the case's entries, every hook recorded.
  const ENTRY_FIELDS = {
    readPassword: 'password', readPasswordReset: 'pwdReset',
    readPasswordHistory: 'history', isPerson: 'person',
    personExists: 'exists', readAccountDisabled: 'disabled',
    readMfaRequired: 'mfaRequired', readTotp: 'totp',
    readBackupCodes: 'backup', readAppPasswords: 'apps',
    readWebauthn: 'webauthn'
  };
  const WRITES = { writePassword: 'password', writeTotp: 'totp',
                   writeBackupCodes: 'backup', writeAppPasswords: 'apps' };
  const DEFAULTS = { person: true, exists: true, disabled: false,
                     mfaRequired: false, pwdReset: false, history: [],
                     webauthn: [] };
  const directory = {};
  Object.keys(ENTRY_FIELDS).forEach(function (hook) {
    directory[hook] = function (name) {
      const entries = (CASE && CASE.entries) || {};
      const entry = entries[name];
      const field = ENTRY_FIELDS[hook];
      const key = ['dir.' + hook, GEN, String(name)];
      if (entry && entry.throws && entry.throws.indexOf(hook) >= 0) {
        rec(key, { threw: 'the directory is unreachable' });
        throw new Error('the directory is unreachable');
      }
      let out;
      if (!entry) {
        out = field === 'person' || field === 'exists' ? false
          : (DEFAULTS[field] !== undefined ? DEFAULTS[field] : null);
      } else if (entry[field] === undefined) {
        out = DEFAULTS[field] !== undefined ? DEFAULTS[field] : null;
      } else {
        out = entry[field];
      }
      rec(key, { value: out });
      return clone(out);
    };
  });
  Object.keys(WRITES).forEach(function (hook) {
    directory[hook] = function (name, value) {
      const entries = (CASE && CASE.entries) || {};
      const entry = entries[name];
      let outcome;
      if (entry && entry.throws && entry.throws.indexOf(hook) >= 0) {
        outcome = { threw: 'the directory refused the write' };
      } else if (!entry || (entry.refuses || []).indexOf(hook) >= 0) {
        outcome = { value: false };
      } else {
        entry[WRITES[hook]] = value === undefined ? null : value;
        outcome = { value: true };
      }
      if (MUTATIONS) {
        MUTATIONS.push({ hook: hook, name: String(name),
                         value: value === undefined ? null : value,
                         outcome: outcome });
      }
      GEN += 1;
      if (outcome.threw) {
        throw new Error(outcome.threw);
      }
      return outcome.value;
    };
  });
  credentials.setDirectory(directory);

  // -------------------------------------------------------------------------
  // A RECORDED RUN: `fn` under a case, its tape collected.
  // -------------------------------------------------------------------------
  const realNow = Date.now;
  const recorded = function (spec, fn) {
    CASE = spec;
    TAPE = {};
    MUTATIONS = [];
    RANDOM = [];
    HASHES = {};
    OBSERVED = [];
    GEN = 0;
    RNG = seeded(spec.seed || 7);
    Date.now = function () {
      return spec.now || 1767225600000;
    };
    let out;
    try {
      out = realms.run(spec.realm || 'default', fn);
    } finally {
      Date.now = realNow;
    }
    const taped = { tape: TAPE, mutations: MUTATIONS, random: RANDOM,
                    hashes: HASHES, observed: OBSERVED };
    CASE = null;
    TAPE = null;
    MUTATIONS = null;
    RANDOM = null;
    HASHES = null;
    OBSERVED = null;
    return { out: out, taped: taped };
  };
  const verdict = function (fn) {
    let value;
    let threw = null;
    try {
      value = fn();
    } catch (e) {
      threw = String((e && e.message) || e);
    }
    return { value: clone(value), code: errorCodes.codeOf(value) || '',
             threw: threw };
  };

  // -------------------------------------------------------------------------
  // THE MECHANISMS: each case one method of one mechanism, its arguments
  // as given, so the crate replays the very call.
  // -------------------------------------------------------------------------
  const NOW = 1767225600000;
  const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
  const TARGETS = { totp: totp, backup: backup, apps: apps };
  const mechanism = function (list, target, method, args, spec) {
    const run = recorded(Object.assign({ now: NOW }, spec || {}), function () {
      return verdict(function () {
        let out = TARGETS[target][method].apply(TARGETS[target], args);
        if (Buffer.isBuffer(out)) {
          out = out.toString('hex');
        }
        return out;
      });
    });
    list.push(Object.assign({ method: method, args: clone(args),
                              spec: clone(spec || {}) },
                            run.out, run.taped));
  };
  const hex = function (text) {
    return Buffer.from(text, 'utf8');
  };
  const totpCases = [];
  [{}, { 'totp.digits': 4, 'totp.period': 1000, 'totp.window': 0 },
   { 'totp.digits': '8', 'totp.window': '', 'totp.algorithm': 'sha256' },
   { 'totp.algorithm': 'MD5', 'totp.window': 99, 'totp.secretBytes': 3,
     'totp.issuer': '  Acme  ', 'totp.enrolmentTtlMinutes': 0 },
   { 'totp.window': 'x', 'totp.period': 'abc' }]
    .forEach(function (settings) {
      mechanism(totpCases, 'totp', 'settings', [], { settings: settings });
    });
  mechanism(totpCases, 'totp', 'settings', [],
            { policy: { off: ['totp/second-factor'] } });
  ['', 'f', 'foobar', 'éè kerberos'].forEach(function (text) {
    mechanism(totpCases, 'totp', 'base32Encode', [hex(text)]);
  });
  ['mzxw 6ytb-oi======', 'MZXW1', 'abc$', '', SECRET]
    .forEach(function (text) {
      mechanism(totpCases, 'totp', 'base32Decode', [text]);
    });
  [SECRET, 'ABCDE', ''].forEach(function (text) {
    mechanism(totpCases, 'totp', 'grouped', [text]);
  });
  mechanism(totpCases, 'totp', 'generateSecret', []);
  mechanism(totpCases, 'totp', 'generateSecret', [{ bytes: 32 }]);
  [{}, { 'totp.issuer': 'Acme Corp' }].forEach(function (settings) {
    ['https://sts.example.com:8443/realm/x', 'HTTP://h', '', 'plain']
      .forEach(function (base) {
        mechanism(totpCases, 'totp', 'issuerFor', [base],
                  { settings: settings });
      });
  });
  mechanism(totpCases, 'totp', 'issuerFor', ['https://h/'],
            { realm: 'acme' });
  mechanism(totpCases, 'totp', 'otpauthUri', [{ issuer: 'Acme & Co (x)',
    account: 'a b@c', secret: SECRET + '==', algorithm: 'SHA256',
    digits: 8, period: 60 }]);
  mechanism(totpCases, 'totp', 'otpauthUri', [{}]);
  // verify: the code an app shows, around the window, and every refusal.
  const at = NOW;
  const codeAt = function (secret, when, opts) {
    return totp.codeAt(secret, when, opts);
  };
  [[SECRET, at, {}], [SECRET, at, { digits: 8, algorithm: 'SHA512',
                                    period: 60 }],
   [SECRET, 0, {}]].forEach(function (row) {
    mechanism(totpCases, 'totp', 'codeAt', row);
  });
  const records = {
    plain: { secret: SECRET },
    eight: { secret: SECRET, digits: 8, algorithm: 'SHA512', period: 60 },
    spent: { secret: SECRET, lastCounter: Math.floor(at / 30000) },
    old: { secret: SECRET, lastCounter: Math.floor(at / 30000) - 5 },
    bad: { secret: 'not*base32' },
    empty: { secret: '' },
    md5: { secret: SECRET, algorithm: 'MD5' },
    strings: { secret: SECRET, digits: '6', period: '30' }
  };
  Object.keys(records).forEach(function (which) {
    const record = records[which];
    const period = Number(record.period || 30);
    [0, -1, 1, 2].forEach(function (offset) {
      const code = codeAt(SECRET, at + offset * period * 1000,
        { period: period, digits: record.digits || 6,
          algorithm: record.algorithm === 'SHA512' ? 'SHA512' : 'SHA1' });
      [undefined, 0, 2].forEach(function (window) {
        const opts = window === undefined ? { at: at }
          : { at: at, window: window };
        mechanism(totpCases, 'totp', 'verify', [record, code, opts]);
      });
    });
  });
  [null, '', '12 34-56', '1234567', 'abcdef', 123456, '٣٣٣٣٣٣']
    .forEach(function (code) {
      mechanism(totpCases, 'totp', 'verify', [records.plain, code,
                                              { at: at }]);
    });
  mechanism(totpCases, 'totp', 'verify', [{ secret: SECRET },
    codeAt(SECRET, at, { digits: 8, algorithm: 'SHA256' }), { at: at }],
    { settings: { 'totp.digits': 8, 'totp.window': 0,
                  'totp.algorithm': 'SHA256' } });

  const backupCases = [];
  [{}, { 'backupCodes.count': 0, 'backupCodes.length': 4,
         'backupCodes.groupSize': 0 },
   { 'backupCodes.count': '60', 'backupCodes.length': 99,
     'backupCodes.groupSize': '' },
   { 'backupCodes.groupSize': 3 }].forEach(function (settings) {
    mechanism(backupCases, 'backup', 'settings', [],
              { settings: settings });
    [['ABCDEFGHIJ'], ['ABCDEFGHIJ', 4], ['ABC', 0], ['', 2]]
      .forEach(function (args) {
        mechanism(backupCases, 'backup', 'formatted', args,
                  { settings: settings });
      });
  });
  mechanism(backupCases, 'backup', 'generate', []);
  mechanism(backupCases, 'backup', 'generate', [{ count: 3, length: 12 }]);
  mechanism(backupCases, 'backup', 'generate', [{ count: 2, length: 3 }]);
  mechanism(backupCases, 'backup', 'generateCode', [9]);
  ['abcde-fghij', ' ABCDE FGHIJ ', 'ABC0E', '', 'éé', 'A1B']
    .forEach(function (one) {
      mechanism(backupCases, 'backup', 'normalise', [one]);
      mechanism(backupCases, 'backup', 'wellFormed', [one]);
      mechanism(backupCases, 'backup', 'matches', [one, 'ABCDEFGHIJ']);
      mechanism(backupCases, 'backup', 'isHash', [one]);
    });
  const codeHash = stsCrypto.hashSecret('ABCDEFGHIJ');
  [['abcde-fghij', codeHash], ['ABCDEFGHIK', codeHash], ['x', 'plain']]
    .forEach(function (args) {
      mechanism(backupCases, 'backup', 'matchesHash', args);
    });
  mechanism(backupCases, 'backup', 'isHash', [codeHash]);

  const appCases = [];
  [{}, { 'appPasswords.enabled': false, 'appPasswords.maxPerPerson': 70 },
   { 'appPasswords.maxPerPerson': '0.5' },
   { 'appPasswords.maxPerPerson': 3.7 }].forEach(function (settings) {
    mechanism(appCases, 'apps', 'settings', [], { settings: settings });
  });
  [[], ['LDAP', ' scim '], 'ldap,wstrust', 'ssf, nope ,est', null,
   ['est', 'ldap', 'ldap'], '', ['', null]].forEach(function (doors) {
    mechanism(appCases, 'apps', 'scopeOf', [doors]);
  });
  [{ 'authn.passwordAloneDoors': 'LDAP, scim,nope' },
   { 'authn.passwordAloneDoors': ['est', 'x'] },
   { 'authn.passwordAloneDoors': '' }].forEach(function (settings) {
    mechanism(appCases, 'apps', 'passwordAloneDoors', [],
              { settings: settings });
  });
  ['  mail client ', '', 'x'.repeat(64), 'x'.repeat(65), 'tab\there',
   null].forEach(function (n) {
    mechanism(appCases, 'apps', 'nameOf', [n]);
  });
  ['ABCD-EFGH-IJKL-MNOP-QRST-UVWX', 'abcdefghijklmnopqrstuvwx', 'ABCD',
   'ABCD-EFGH-IJKL-MNOP-QRST-UVW1'].forEach(function (p) {
    mechanism(appCases, 'apps', 'wellFormed', [p]);
    mechanism(appCases, 'apps', 'idOf', [p]);
    mechanism(appCases, 'apps', 'normalise', [p]);
  });
  mechanism(appCases, 'apps', 'printed', ['ABCDEFGHIJKLMNOPQRSTUVWX']);
  ['ldap', 'est', 'nope'].forEach(function (d) {
    mechanism(appCases, 'apps', 'isDoor', [d]);
    mechanism(appCases, 'apps', 'doorLabel', [d]);
  });
  mechanism(appCases, 'apps', 'generate', []);
  mechanism(appCases, 'apps', 'generate', [['HHDF']]);

  // -------------------------------------------------------------------------
  // PHISHING RESISTANCE.
  // -------------------------------------------------------------------------
  const local = function (credential, more) {
    return Object.assign({ authority: { kind: 'local' },
                           context: { credential: credential } }, more);
  };
  const EVENTS = [
    null, {}, { authenticated: false, authority: { kind: 'local' } },
    { authority: { kind: 'federation' }, acr: 'phrh' },
    { authority: { kind: 'federation' }, acr: 'phr' },
    { authority: { kind: 'federation' }, acr: 'urn:x' },
    { authority: { kind: 'kerberos' } },
    local({ kind: 'certificate' }), local({ kind: 'password' }),
    local({ kind: 'webauthn', ceremony: 'registration' }),
    local({ kind: 'webauthn', attestationTrusted: true,
            backupEligible: false }),
    local({ kind: 'webauthn', attestationTrusted: true,
            backupEligible: true }),
    local({ kind: 'webauthn', attestationTrusted: false,
            backupEligible: false }),
    local({ kind: 'webauthn' }), local(null)
  ];
  const URIS = [undefined, '', PhishingResistance.URI_PHR,
                [PhishingResistance.URI_PHRH],
                PhishingResistance.URI_PHR + ' ' + PhishingResistance.URI_PHRH,
                [PhishingResistance.URI_PHR + ',urn:other'],
                ['  ' + PhishingResistance.URI_PHRH + '  ', null]];
  const phishing = EVENTS.map(function (event) {
    const session = { events: [event, { authenticated: false }] };
    return {
      event: clone(event),
      ofEvent: PhishingResistance.ofEvent(event),
      ofSession: PhishingResistance.ofSession(session),
      shortfall: PhishingResistance.hardwareShortfallOf(session),
      factOf: PhishingResistance.factOf(PhishingResistance.ofEvent(event)),
      demands: URIS.map(function (uris) {
        return { uris: clone(uris),
                 list: PhishingResistance.uriList(uris),
                 signIn: PhishingResistance.signInFor(uris),
                 met: PhishingResistance.eapDemandMet(session, uris),
                 assertion: PhishingResistance.assertionUri(session, uris) };
      })
    };
  });
  const phishingKeys = [{}, { attestation: { trusted: true },
                              backupEligible: false },
                        { attestation: { trusted: true },
                          backupEligible: true },
                        { attestation: { trusted: 'yes' },
                          backupEligible: false }].map(function (key) {
    return { key: key,
             earns: PhishingResistance.storedKeyEarnsHardware(key) };
  });

  // -------------------------------------------------------------------------
  // THE DOORS: scenarios of one or more steps over one world.
  // -------------------------------------------------------------------------
  const scenarios = [];
  const scenario = function (name, spec, steps) {
    const world = clone(spec);
    const run = recorded(Object.assign({ now: NOW }, world), function () {
      return steps.map(function (step) {
        const args = typeof step.args === 'function' ? step.args(world)
          : step.args;
        const answer = verdict(function () {
          return credentials[step.method].apply(credentials, args);
        });
        const v = answer.value || {};
        if (v.ok && step.method === 'beginTotpEnrolment') {
          PENDING.secret = v.secret;
        }
        if (v.ok && step.method === 'beginBackupCodes') {
          PENDING.handle = v.handle;
          PENDING.codes = v.codes;
        }
        if (v.ok && step.method === 'createAppPassword' &&
            !PRINTED.alice) {
          PRINTED.alice = v.password;
        }
        return { method: step.method, args: clone(args), answer: answer };
      });
    });
    scenarios.push(Object.assign({ name: name, spec: clone(spec),
                                   steps: run.out }, run.taped));
  };
  const hashOf = function (plain) {
    return stsCrypto.hashSecret(plain);
  };
  const PASSWORD = 'Correct horse 9!';
  const stored = hashOf(PASSWORD);
  const weak = stsCrypto.hashPassword(PASSWORD,
    { algorithm: 'scrypt', logN: 14, r: 8, p: 1 });
  const verifyStep = function (name, password, opts) {
    return { method: 'verify', args: [name, password, opts || {}] };
  };
  scenario('the reserved refusal, in development', { mode:
    { verifiesCredentials: false }, entries: { alice: {} } },
  [verifyStep('alice', 'invalid', { via: 'ldap bind' })]);
  scenario('development mode', { mode: { verifiesCredentials: false },
                                 entries: { alice: {} } },
  [verifyStep('alice', 'anything', { via: 'sign-in screen' }),
   verifyStep('', 'anything')]);
  scenario('disabled, in development', { mode: { verifiesCredentials: false },
    entries: { alice: { disabled: true } } },
  [verifyStep(' alice ', 'x', { via: 'the token endpoint' }),
   verifyStep('alice', 'x')]);
  scenario('the right password', { entries: { alice: { password: stored } } },
  [verifyStep('alice', PASSWORD, { via: 'sign-in screen' })]);
  scenario('the wrong password', { entries: { alice: { password: stored } } },
  [verifyStep('alice', 'wrong', { via: 'ldap bind', door: 'ldap' })]);
  scenario('no username', { entries: {} }, [verifyStep('  ', 'x')]);
  scenario('no credential', { entries: { alice: {} } },
  [verifyStep('alice', 'x')]);
  scenario('an unreadable credential', { entries: { alice: {
    password: '{SSHA}abc' } } }, [verifyStep('alice', 'x')]);
  scenario('a store error', { entries: { alice: {
    throws: ['readPassword'] } } }, [verifyStep('alice', 'x')]);
  scenario('pwdReset', { entries: { alice: { password: stored,
                                             pwdReset: true } } },
  [verifyStep('alice', PASSWORD, { via: 'scim' }),
   verifyStep('alice', PASSWORD, { allowPasswordReset: true })]);
  scenario('a weaker hash, upgraded', { entries: { alice: {
    password: weak } } }, [verifyStep('alice', PASSWORD),
                           verifyStep('alice', PASSWORD)]);
  scenario('a weaker hash, the write refused', { entries: { alice: {
    password: weak, refuses: ['writePassword'] } } },
  [verifyStep('alice', PASSWORD)]);
  scenario('a service account at a door its policy shuts', {
    serviceAccounts: { 'svc-build': { doors: ['ldap'] } },
    entries: { 'svc-build': { password: stored } } },
  [verifyStep('svc-build', PASSWORD, { via: 'scim', door: 'scim' }),
   verifyStep('svc-build', PASSWORD, { via: 'ldap', door: 'ldap' }),
   verifyStep('svc-build', PASSWORD, { via: 'sign-in screen',
                                       secondFactor: 'asked-next' })]);
  scenario('a service account inside its rotation overlap', {
    serviceAccounts: { 'svc-sync': { doors: ['ldap'], previous: stored } },
    entries: { 'svc-sync': { password: hashOf('the new one 12345') } } },
  [verifyStep('svc-sync', PASSWORD, { via: 'ldap', door: 'ldap' }),
   verifyStep('svc-sync', 'the new one 12345', { via: 'ldap',
                                                 door: 'ldap' })]);
  const totpEnrolled = JSON.stringify({ secret: SECRET, sealed: false,
    algorithm: 'SHA1', digits: 6, period: 30, enrolledAt: NOW - 86400000,
    lastCounter: 1, label: 'authenticator app' });
  scenario('a second-factor person at a password-only door', {
    entries: { alice: { password: stored, totp: totpEnrolled } } },
  [verifyStep('alice', PASSWORD, { via: 'ldap bind', door: 'ldap' }),
   verifyStep('alice', PASSWORD, { via: 'sign-in screen',
                                   secondFactor: 'asked-next' })]);
  scenario('a second factor required on the entry', {
    entries: { alice: { password: stored, mfaRequired: true } } },
  [verifyStep('alice', PASSWORD, { via: 'scim', door: 'scim' })]);
  scenario('a second factor required by the realm', {
    policy: { requireSecondFactor: 'always' },
    entries: { alice: { password: stored } } },
  [verifyStep('alice', PASSWORD, { via: 'est', door: 'est' })]);
  scenario('a password-alone door', {
    settings: { 'authn.passwordAloneDoors': 'ldap' },
    entries: { alice: { password: stored, mfaRequired: true } } },
  [verifyStep('alice', PASSWORD, { via: 'ldap', door: 'ldap' })]);
  scenario('the mode accepts a password alone', {
    mode: { acceptsPasswordAloneFromSecondFactorAccounts: true },
    entries: { alice: { password: stored, mfaRequired: true } } },
  [verifyStep('alice', PASSWORD, { via: 'ldap', door: 'ldap' }),
   { method: 'passwordOnlyDoors', args: ['alice'] }]);
  scenario('an administrator, by the policy for administrators', {
    policy: { forAdministrators: 'always' }, roles: { ops: [true, false],
                                                      admin: [true, true] },
    entries: { ops: { password: stored }, admin: { password: stored } } },
  [verifyStep('ops', PASSWORD, { via: 'ldap', door: 'ldap' }),
   verifyStep('admin', PASSWORD, { via: 'ldap', door: 'ldap' }),
   { method: 'mfaRequirementFor', args: ['ops'] },
   { method: 'mfaRequirementFor', args: ['admin'] }]);
  scenario('an exempt service account', {
    serviceAccounts: { 'svc-x': { doors: ['ldap', 'scim'], exempt: true } },
    policy: { requireSecondFactor: 'always',
              configuredSecondFactor: 'always' },
    entries: { 'svc-x': { password: stored } } },
  [verifyStep('svc-x', PASSWORD, { via: 'ldap', door: 'ldap' }),
   { method: 'mfaRequirementFor', args: ['svc-x'] },
   { method: 'secondFactorDemand', args: ['svc-x'] }]);
  scenario('not a person', { entries: { app1: { password: stored,
                                                person: false,
                                                mfaRequired: true } } },
  [verifyStep('app1', PASSWORD, { door: 'ldap' }),
   { method: 'secondFactorDemand', args: ['app1'] },
   { method: 'passwordOnlyDoors', args: ['app1'] }]);
  const keyValue = JSON.stringify({ credentialId: 'AAAA',
                                    publicKeyJwk: { kty: 'OKP' },
                                    role: 'mfa' });
  scenario('a key holder, and the uses the policy allows', {
    policy: { keyUsesOff: ['primary'] },
    entries: { alice: { password: stored,
                        webauthn: [keyValue, 'not json',
                                   JSON.stringify({ credentialId: 'B' })] },
               bob: { password: stored, webauthn: [keyValue] } } },
  [{ method: 'keysOf', args: ['alice'] },
   { method: 'secondFactorDemand', args: ['alice'] },
   { method: 'passwordOnlyDoors', args: ['bob'] }]);
  // App passwords.
  scenario('app passwords: made, used, refused, revoked', {
    entries: { alice: { password: stored, totp: totpEnrolled },
               bob: { person: false } } },
  [{ method: 'createAppPassword', args: ['alice', { name: ' mail ',
                                                    doors: 'ldap,scim' }] },
   { method: 'appPasswordsOf', args: ['alice'] },
   { method: 'createAppPassword', args: ['alice', { name: 'mail',
                                                    doors: ['ldap'] }] },
   { method: 'createAppPassword', args: ['alice', { name: '',
                                                    doors: ['ldap'] }] },
   { method: 'createAppPassword', args: ['alice', { name: 'x',
                                                    doors: 'nope,ldap' }] },
   { method: 'createAppPassword', args: ['alice', { name: 'x',
                                                    doors: [] }] },
   { method: 'createAppPassword', args: ['bob', { name: 'x',
                                                  doors: ['ldap'] }] },
   { method: 'createAppPassword', args: ['carol', { name: 'x',
                                                    doors: ['ldap'] }] },
   { method: 'verify', args: function () {
     return ['alice', PRINTED.alice, { via: 'ldap bind', door: 'ldap' }];
   } },
   { method: 'verify', args: function () {
     return ['alice', PRINTED.alice, { via: 'est', door: 'est' }];
   } },
   { method: 'verify', args: function () {
     return ['alice', PRINTED.alice.toLowerCase(),
             { via: 'scim', door: 'scim' }];
   } },
   { method: 'verify', args: function () {
     return ['alice', PRINTED.alice.slice(0, 5) + 'AAAAAAAAAAAAAAAAAAA',
             { via: 'ldap', door: 'ldap' }];
   } },
   { method: 'revokeAppPassword', args: ['alice', 'zzzz'] },
   { method: 'revokeAppPassword', args: function () {
     return ['alice', PRINTED.alice.slice(0, 4).toLowerCase()];
   } },
   { method: 'appPasswordsOf', args: ['alice'] }]);
  scenario('app passwords: off, full, unreadable', {
    settings: { 'appPasswords.maxPerPerson': 1 },
    entries: { alice: { apps: JSON.stringify({ version: 1, passwords: [
      { id: 'ABCD', name: 'one', doors: ['ldap'], hash: 'x', createdAt: 5 }
    ] }) }, bob: { apps: '{"nope":1}' } } },
  [{ method: 'createAppPassword', args: ['alice', { name: 'two',
                                                    doors: ['ldap'] }] },
   { method: 'createAppPassword', args: ['bob', { name: 'two',
                                                  doors: ['ldap'] }] },
   { method: 'appPasswordsOf', args: ['bob'] },
   { method: 'revokeAppPassword', args: ['bob', 'ABCD'] }]);
  scenario('app passwords: turned off', {
    settings: { 'appPasswords.enabled': false },
    entries: { alice: {} } },
  [{ method: 'createAppPassword', args: ['alice', { name: 'two',
                                                    doors: ['ldap'] }] }]);
  // The authenticator app.
  const enrolCode = function (world) {
    return [world.name, codeAt(PENDING.secret, NOW)];
  };
  scenario('an authenticator app enrolled', {
    persists: true, entries: { dora: {} } },
  [{ method: 'beginTotpEnrolment', args: ['dora',
                                          { base: 'https://sts.example' }] },
   { method: 'confirmTotpEnrolment', args: ['dora', '000000'] },
   { method: 'confirmTotpEnrolment', args: function () {
     return enrolCode({ name: 'dora' });
   } },
   { method: 'confirmTotpEnrolment', args: ['dora', '123456'] },
   { method: 'verifyTotp', args: function () {
     return ['dora', codeAt(PENDING.secret, NOW)];
   } },
   { method: 'verifyTotp', args: function () {
     return ['dora', codeAt(PENDING.secret, NOW + 30000),
             { at: NOW + 30000 }];
   } },
   { method: 'totpOf', args: ['dora'] }]);
  scenario('authenticator enrolment refusals', {
    policy: { off: ['totp/second-factor'] }, entries: {} },
  [{ method: 'beginTotpEnrolment', args: ['erin'] }]);
  scenario('authenticator enrolment refusals, on', { entries: {} },
  [{ method: 'beginTotpEnrolment', args: [''] },
   { method: 'beginTotpEnrolment', args: ['a\u0001b'] },
   { method: 'beginTotpEnrolment', args: ['nobody'] }]);
  scenario('authenticator enrolment in development', {
    mode: { autoCreates: true }, settings: { 'totp.issuer': 'Acme' },
    entries: { fay: { refuses: ['writeTotp'] } } },
  [{ method: 'beginTotpEnrolment', args: ['Fay'] },
   { method: 'confirmTotpEnrolment', args: function () {
     return ['fay', codeAt(PENDING.secret, NOW)];
   } }]);
  scenario('authenticator: the seal fails', {
    persists: true, sealFails: true, entries: { gil: {} } },
  [{ method: 'beginTotpEnrolment', args: ['gil'] },
   { method: 'confirmTotpEnrolment', args: function () {
     return ['gil', codeAt(PENDING.secret, NOW)];
   } }]);
  const sealedTotp = JSON.stringify({ secret: 'sealed:totp-secret:' +
    Buffer.from(SECRET).toString('base64'), sealed: true, algorithm: 'SHA1',
    digits: 6, period: 30, enrolledAt: 1, lastCounter: 0 });
  scenario('authenticator: verify refusals', {
    entries: { hal: {}, ivy: { totp: '{not json' },
               joe: { totp: sealedTotp }, kim: { totp: totpEnrolled },
               lee: { totp: totpEnrolled, refuses: ['writeTotp'] },
               max: { throws: ['readTotp'] } } },
  [{ method: 'verifyTotp', args: ['hal', '123456'] },
   { method: 'verifyTotp', args: ['ivy', '123456'] },
   { method: 'verifyTotp', args: function () {
     return ['joe', codeAt(SECRET, NOW)];
   } },
   { method: 'verifyTotp', args: ['kim', 'abc'] },
   { method: 'verifyTotp', args: ['kim', '000000', { window: 0 }] },
   { method: 'verifyTotp', args: function () {
     return ['lee', codeAt(SECRET, NOW)];
   } },
   { method: 'verifyTotp', args: ['max', '123456'] },
   { method: 'totpOf', args: ['ivy'] }]);
  scenario('authenticator: a sealed secret that will not open', {
    openFails: true, entries: { joe: { totp: sealedTotp } } },
  [{ method: 'verifyTotp', args: ['joe', '123456'] },
   { method: 'totpOf', args: ['joe'] }]);
  scenario('authenticator: replay', {
    entries: { kim: { totp: JSON.stringify({ secret: SECRET,
      lastCounter: Math.floor(NOW / 30000) }) } } },
  [{ method: 'verifyTotp', args: function () {
    return ['kim', codeAt(SECRET, NOW)];
  } }]);
  // Recovery codes.
  scenario('recovery codes issued, confirmed and spent', {
    settings: { 'backupCodes.count': 3, 'backupCodes.length': 8 },
    entries: { nia: { totp: totpEnrolled } } },
  [{ method: 'backupCodeStatus', args: ['nia'] },
   { method: 'beginBackupCodes', args: ['nia'] },
   { method: 'confirmBackupCodes', args: ['nia', 'not the handle'] },
   { method: 'confirmBackupCodes', args: function () {
     return ['nia', PENDING.handle];
   } },
   { method: 'backupCodeStatus', args: ['nia'] },
   { method: 'verifyBackupCode', args: ['nia', 'not a code!'] },
   { method: 'verifyBackupCode', args: ['nia', 'AAAAAAAA'] },
   { method: 'verifyBackupCode', args: function () {
     return ['nia', PENDING.codes[1].toLowerCase()];
   } },
   { method: 'verifyBackupCode', args: function () {
     return ['nia', PENDING.codes[1]];
   } },
   { method: 'backupCodeStatus', args: ['nia'] },
   { method: 'confirmBackupCodes', args: function () {
     return ['nia', PENDING.handle];
   } }]);
  scenario('recovery codes refused', {
    policy: { off: ['recoveryCode/second-factor'] }, entries: {} },
  [{ method: 'beginBackupCodes', args: ['ola'] }]);
  const legacy = JSON.stringify({ version: 1, total: 2, remaining: 2,
    generatedAt: 10, sealed: false,
    vault: JSON.stringify([{ code: 'LEGACYCODE' }, { code: 'OTHERCODE2' }]) });
  const sealedSet = JSON.stringify({ version: 2, total: 1, remaining: 1,
    sealed: true, vault: 'sealed:recovery-codes:' +
      Buffer.from(JSON.stringify([{ hash: codeHash, usedAt: 0 }]))
        .toString('base64') });
  scenario('recovery codes: legacy, sealed, unreadable', {
    persists: true,
    entries: { pam: { backup: legacy }, quin: { backup: sealedSet },
               rex: { backup: 'nope' }, sam: {},
               tia: { backup: JSON.stringify({ vault: '{"a":1}' }) },
               uma: { backup: legacy, refuses: ['writeBackupCodes'] } } },
  [{ method: 'backupCodeStatus', args: ['pam'] },
   { method: 'verifyBackupCode', args: ['pam', 'legacy-code'] },
   { method: 'backupCodeStatus', args: ['pam'] },
   { method: 'verifyBackupCode', args: ['quin', 'ABCDE FGHIJ'] },
   { method: 'verifyBackupCode', args: ['rex', 'ABCDE'] },
   { method: 'backupCodeStatus', args: ['rex'] },
   { method: 'verifyBackupCode', args: ['sam', 'ABCDE'] },
   { method: 'backupCodeStatus', args: ['tia'] },
   { method: 'verifyBackupCode', args: ['uma', 'LEGACYCODE'] }]);
  scenario('recovery codes: a sealed set that will not open', {
    openFails: true, entries: { quin: { backup: sealedSet } } },
  [{ method: 'backupCodeStatus', args: ['quin'] },
   { method: 'verifyBackupCode', args: ['quin', 'ABCDEFGHIJ'] }]);

  // The handles and secrets a later step uses are what an earlier step of
  // the same scenario answered: filled in as the steps run.
  return { totp: totpCases, backup: backupCases, apps: appCases,
           phishing: phishing, phishingKeys: phishingKeys,
           scenarios: scenarios,
           webauthn: await req('tests/tools/credentials-webauthn.js')
             .build(ROOT) };
}

module.exports = { build: build, PENDING: PENDING, PRINTED: PRINTED };
