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

// The instant a `pwdHistory` value is stamped with, held still.
const NOW_DATE = new Date(1767225600000);

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
  const realPasswordPolicy = req('common/password_policy');
  const fakePasswordPolicy = {
    profileFor: function (name, application) {
      return rec(['policy.passwordProfile', String(name),
                  String(application || '')],
                 policy().passwordProfile || { name: 'default' });
    },
    problemsWith: function (password, profile) {
      return rec(['policy.problems', String(password), clone(profile)],
                 realPasswordPolicy.problemsWith(password, profile));
    },
    historyValue: function (hash) {
      return rec(['policy.historyValue', String(hash)],
                 realPasswordPolicy.historyValue(hash, NOW_DATE));
    },
    hashOfHistoryValue: realPasswordPolicy.hashOfHistoryValue,
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

  // WHAT startSession() ASKS OF THE CREDENTIALS (#536, #718, #724, #943):
  // `authn.ts`'s own methods, over this recorded store and a passkey
  // policy that answers from the case.
  const Authn = req('authn/authn').Authn;
  const observe = function (kind, field) {
    return function (value) {
      if (OBSERVED) {
        const row = { kind: kind };
        row[field] = clone(value);
        OBSERVED.push(row);
      }
    };
  };
  const passkeyOf = function () {
    return (CASE && CASE.passkey) || {};
  };
  const authnSelf = { deps: {
    log: req('common/helpers').log,
    credentials: Object.assign(Object.create(credentials), {
      keyAlgorithm: Credentials.keyAlgorithm, keyLane: Credentials.keyLane,
      Credentials: Credentials }),
    passkeyPolicy: {
      refusalFor: function (at, facts) {
        const out = passkeyOf().refuse ? Object.assign({},
          passkeyOf().refuse) : null;
        return rec(['passkey.refusalFor', at, clone(facts)], out);
      },
      recoveryRefusal: function (ask) {
        const out = passkeyOf().recoveryRefuse ? Object.assign({},
          passkeyOf().recoveryRefuse) : null;
        return rec(['passkey.recoveryRefusal', clone(ask)], out);
      },
      requiresPostQuantum: function (at) {
        return rec(['passkey.requiresPostQuantum', at],
                   !!passkeyOf().pqc);
      },
      RECOVERY_CREDENTIALS: req('common/passkey_policy')
        .PasskeyPolicy.RECOVERY_CREDENTIALS
    },
    webauthnCeremonies: { algorithmMismatch: observe('mismatch', 'row') },
    accountSignals: Object.assign(Object.create(req('ssf/account_signals')
      .AccountSignals || req('ssf/account_signals')),
    { credentialChanged: observe('changed', 'facts'),
      keyCredentialType: req('ssf/account_signals').keyCredentialType }),
    audit: { audit: observe('audit', 'row') }
  } };

  // THE DIRECTORY: the case's entries, every hook recorded.
  const ENTRY_FIELDS = {
    readPassword: 'password', readPasswordReset: 'pwdReset',
    readPasswordHistory: 'history', isPerson: 'person',
    personExists: 'exists', readAccountDisabled: 'disabled',
    readMfaRequired: 'mfaRequired', readTotp: 'totp',
    readBackupCodes: 'backup', readAppPasswords: 'apps',
    readWebauthn: 'webauthn', readRecoveryPending: 'recovery'
  };
  const WRITES = { writePassword: 'password', writeTotp: 'totp',
                   writeBackupCodes: 'backup', writeAppPasswords: 'apps',
                   replaceWebauthn: 'webauthn',
                   writeRecoveryPending: 'recovery' };
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
                         options: clone(arguments[2]), outcome: outcome });
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
  const breached = req('common/breached_passwords');
  breached.enabled = function () {
    return rec(['breach.enabled'], !!(CASE && CASE.breach));
  };
  breached.verdictOf = function (password) {
    const held = (CASE && CASE.breach) || {};
    const out = Object.prototype.hasOwnProperty.call(held, password)
      ? { breached: !!held[password] } : null;
    return rec(['breach.verdict', String(password)], out);
  };
  credentials.rotatesThroughDestination = function (name) {
    return rec(['svc.rotates', String(name)], !!(svc()[name] || {}).rotates);
  };
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
          if (step.method.indexOf('authn.') === 0) {
            const out = Authn.prototype[step.method.slice(6)].apply(
              authnSelf, args);
            return out === undefined ? null : out;
          }
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
  // Setting a password: the policy, the breach screen, the history.
  const history = [realPasswordPolicy.historyValue(hashOf('an old one 12'),
                                                   NOW_DATE)];
  scenario('a password set, and each refusal', {
    passwordProfile: undefined,
    breach: { 'p4ssw0rd-breached': true, 'Fine and new 77!': false },
    serviceAccounts: { 'svc-rot': { rotates: true } },
    policy: { passwordProfile: { name: 'strict', minLength: 12,
                                 history: 2 } },
    entries: { alice: { password: stored, history: history },
               'svc-rot': {}, ghost: { refuses: ['writePassword'] },
               boom: { throws: ['writePassword'] } } },
  [{ method: 'setPassword', args: ['', 'x'] },
   { method: 'setPassword', args: ['alice', ''] },
   { method: 'setPassword', args: ['alice', 'short'] },
   { method: 'setPassword', args: ['alice', 'p4ssw0rd-breached'] },
   { method: 'setPassword', args: ['alice', PASSWORD + 'xx',
                                   { generated: true }] },
   { method: 'setPassword', args: ['alice', 'an old one 12'] },
   { method: 'setPassword', args: ['alice', PASSWORD] },
   { method: 'setPassword', args: ['alice', 'Fine and new 77!',
                                   { via: 'portal' }] },
   { method: 'setPassword', args: ['alice', 'Not screened 99!',
                                   { via: 'scim' }] },
   { method: 'setPassword', args: ['svc-rot', 'Rotating one 1234'] },
   { method: 'setPassword', args: ['ghost', 'Rotating one 1234'] },
   { method: 'setPassword', args: ['boom', 'Rotating one 1234'] },
   { method: 'passwordProblem', args: ['short', 'alice'] },
   { method: 'passwordProblem', args: ['long enough, this', 'alice'] }]);
  scenario('a password set in development', {
    mode: { verifiesCredentials: false },
    policy: { passwordProfile: { name: 'default', minLength: 12,
                                 history: 3 } },
    entries: { alice: { password: stored } } },
  [{ method: 'setPassword', args: ['alice', 'x'] },
   { method: 'passwordProblem', args: ['x', 'alice'] }]);

  // What startSession() asks.
  const key1 = { credentialId: 'K1', publicKeyJwk: { kty: 'EC', crv: 'P-256',
                 x: 'a', y: 'b' }, minPinLength: 6, aaguid:
                 'adce000235bcc60a648b0b25f1f05503', label: 'my key' };
  const key2 = { credentialId: 'K2', publicKeyJwk: { kty: 'AKP', pub: 'x',
                 alg: 'ML-DSA-65' }, coseAlg: -49, algorithm: 'ML-DSA-65',
                 lane: 'pqc', attachment: 'platform',
                 policyRefused: { pqc: { code: 'C', why: 'old', at: 1 } } };
  const refusal = { code: 'STS-AUTHN-0399', why: 'a post-quantum passkey ' +
                    'is required', reason: 'pqc' };
  scenario('the passkey questions at a session', {
    passkey: { refuse: refusal, pqc: true },
    entries: { pia: { webauthn: [JSON.stringify(key1),
                                 JSON.stringify(key2)] } } },
  [{ method: 'authn.passkeySignInRefusal', args: ['pia', { kind: 'totp' }] },
   { method: 'authn.passkeySignInRefusal', args: ['pia', {
     kind: 'webauthn', id: 'K1', backupEligible: true }] },
   { method: 'authn.passkeySignInRefusal', args: ['pia', {
     kind: 'webauthn', id: 'nope', algorithm: 'ES256' }] },
   { method: 'authn.passkeySignInRefusal', args: ['pia', {
     kind: 'webauthn', id: 'nope' }] },
   { method: 'authn.noteAlgorithmMismatch', args: ['pia', {
     kind: 'webauthn', id: 'K1' }, 'sign-in screen'] },
   { method: 'authn.noteAlgorithmMismatch', args: ['pia', {
     kind: 'webauthn', id: 'x', algorithm: 'RS256' }, null] },
   { method: 'authn.notePasskeyStanding', args: ['pia', { id: 'K1' },
                                                 refusal] },
   { method: 'authn.notePasskeyStanding', args: ['pia', { id: 'K1' },
                                                 refusal] },
   { method: 'authn.notePasskeyStanding', args: ['pia', { id: 'K2' },
     { code: 'C', why: 'old', reason: 'pqc' }] },
   { method: 'authn.notePasskeyStanding', args: ['pia', { id: 'K2' },
     { code: 'C2', why: 'new', reason: 'pqc' }] },
   { method: 'authn.notePasskeyStanding', args: ['pia', { id: 'none' },
                                                 refusal] }]);
  scenario('the recovery questions at a session', {
    passkey: { recoveryRefuse: { code: 'STS-AUTHN-0381', why: 'not weaker',
                                 reason: 'not-weaker' } },
    entries: { quo: { webauthn: [JSON.stringify(key1)],
                      recovery: 'email-link 2026-11-01T00:00:00.000Z' },
               ray: {}, sue: { recovery: 'recovery-code 2026-11-02T00:00:00Z',
                               refuses: ['writeRecoveryPending'] } } },
  [{ method: 'authn.recoveryRefusalAtSession', args: ['ray',
     { kind: 'password' }] },
   { method: 'authn.recoveryRefusalAtSession', args: ['ray',
     { kind: 'backup-code' }] },
   { method: 'authn.recoveryRefusalAtSession', args: ['quo',
     { kind: 'webauthn', ceremony: 'registration' }] },
   { method: 'authn.recoveryRefusalAtSession', args: ['quo', null] },
   { method: 'authn.recoveryCompleted', args: ['quo', { credential: {
     kind: 'webauthn', ceremony: 'registration' } }] },
   { method: 'authn.recoveryCompleted', args: ['quo', { credential: {
     kind: 'totp' } }] },
   { method: 'authn.recoveryCompleted', args: ['ray', { credential: {
     kind: 'webauthn' } }] },
   { method: 'authn.recoveryCompleted', args: ['quo', { credential: {
     kind: 'webauthn' }, application: 'app1' }] },
   { method: 'authn.recoveryCompleted', args: ['quo', { credential: {
     kind: 'webauthn' } }] },
   { method: 'authn.recoveryCompleted', args: ['sue', { credential: {
     kind: 'webauthn', ceremony: 'assertion' } }] },
   { method: 'authn.recoveryCompleted', args: ['quo', null] }]);

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

  // THE EMAILED FACTOR (3be): `MailFactor` over a recorded world — the
  // person's values as `entryOf()` reads them, the flags it writes, the
  // policy, and what it audits, signals and sends.
  const mailModule = req('common/mail_factor');
  const accountSignals = req('ssf/account_signals');
  const signalled = function (kind) {
    return function (facts) {
      if (OBSERVED) {
        OBSERVED.push({ kind: kind, facts: clone(facts) });
      }
    };
  };
  accountSignals.credentialChanged = signalled('changed');
  accountSignals.credentialCompromised = signalled('compromised');
  const mailFactor = new mailModule.MailFactor(Object.assign(
    mailModule.MailFactor.defaultDeps(), {
      crypto: recordedCrypto,
      randomInt: randomInt, randomBytes: randomBytes,
      audit: { audit: function (row) {
        if (OBSERVED) {
          OBSERVED.push({ kind: 'audit', row: clone(row) });
        }
      } },
      authnPolicy: {
        allows: fakeAuthnPolicy.allows,
        active: function (mechanism, role) {
          const off = (policy().inactive || []);
          return rec(['policy.active', mechanism, role],
                     off.indexOf(mechanism) < 0 &&
                     (policy().off || []).indexOf(mechanism + '/' + role) <
                     0);
        },
        emailSettings: function () {
          return { failureLimit: rec(['policy.failureLimit'],
                                     policy().failureLimit || 5),
                   ttlS: 600, attempts: 3, resendS: 30, maxSends: 5 };
        }
      },
      mail: function () {
        return {
          directory: function () {
            return {
              personEntry: function (name) {
                const people = (CASE && CASE.people) || {};
                return people[name] ? { attributes: people[name] } : null;
              },
              writeMailFlag: function (name, attr, value) {
                const people = (CASE && CASE.people) || {};
                const ok = !!people[name] &&
                  !(CASE.refusesFlags || []).includes(attr);
                if (ok) {
                  people[name][attr] = value === '' ? [] : [value];
                }
                if (MUTATIONS) {
                  MUTATIONS.push({ hook: 'writeMailFlag', name: name,
                                   value: [attr, value],
                                   outcome: { value: ok } });
                }
                return ok;
              }
            };
          },
          send: function (message) {
            if (OBSERVED) {
              OBSERVED.push({ kind: 'send', message: clone(message) });
            }
            return { ok: true };
          }
        };
      }
    }));
  const entryOf = mailFactor.entryOf;
  mailFactor.entryOf = function (name) {
    const out = entryOf.call(mailFactor, name);
    return rec(['mail.person', GEN, String(name)], out);
  };
  const mailCases = [];
  const mailScenario = function (name, spec, steps) {
    const world = clone(spec);
    const run = recorded(Object.assign({ now: NOW }, world), function () {
      return steps.map(function (step) {
        return { method: step[0], args: clone(step[1]),
                 answer: verdict(function () {
                   const out = mailFactor[step[0]].apply(mailFactor,
                                                         step[1]);
                   GEN += step[0] === 'status' ? 0 : 1;
                   return out;
                 }) };
      });
    });
    mailCases.push(Object.assign({ name: name, spec: clone(spec),
                                   steps: run.out }, run.taped));
  };
  const person = function (factor, failures, verified) {
    return { mail: ['dee@example.com'],
             stsMailVerified: [verified === false ? '' : 'DEE@example.com'],
             stsMailFactor: factor ? [factor] : [],
             stsMailFactorFailures: failures ? [String(failures)] : [] };
  };
  mailScenario('opted in, usable', { people: { dee: person('code') } },
    [['status', ['dee']], ['held', ['dee']], ['status', ['nobody']]]);
  mailScenario('opt in, each refusal', {
    people: { dee: person(''), eve: person('', 0, false) },
    policy: { off: ['emailLink/second-factor'], inactive: ['emailCode'] } },
    [['optIn', ['dee', 'sms', 'dee', 'portal']],
     ['optIn', ['dee', 'link', 'dee', 'portal']],
     ['optIn', ['dee', 'code', 'dee', 'portal']],
     ['status', ['dee']]]);
  mailScenario('opt in, verified and not', {
    people: { dee: person(''), eve: person('', 0, false) } },
    [['optIn', ['eve', 'code', 'eve', 'portal']],
     ['optIn', ['dee', 'code', 'dee', 'portal']],
     ['optIn', ['dee', 'link', 'admin', 'console']],
     ['optIn', ['dee', 'link', 'admin', 'console']],
     ['clear', ['dee', 'dee', 'portal']],
     ['clear', ['dee', 'dee', 'portal']]]);
  mailScenario('opt in, the write refused', {
    people: { dee: person('') }, refusesFlags: ['stsMailFactorFailures'] },
    [['optIn', ['dee', 'code', 'dee', 'portal']]]);
  mailScenario('failures up to the limit', {
    people: { dee: person('code', 2) }, policy: { failureLimit: 4 } },
    [['noteFailure', ['dee']], ['noteSuccess', ['dee']],
     ['noteFailure', ['dee']], ['noteFailure', ['dee']],
     ['noteFailure', ['dee']], ['noteFailure', ['dee']],
     ['status', ['dee']]]);
  mailScenario('the secrets', {}, [['mintCode', []], ['mintToken', []],
    ['normalizeCode', ['12 34-56']], ['normalizeCode', ['12345']],
    ['normalizeCode', ['１２３４５６']], ['normalizeCode', [null]],
    ['masked', ['dee@example.com']], ['masked', ['@x']],
    ['masked', ['nobody']], ['masked', ['é@x.org']]]);

  // THE RATE LIMIT AND THE FAILURE DELAY: `WebSecurity`'s local buckets,
  // a fresh table per scenario, each step at its own instant.
  const WebSecurity = req('common/websecurity').WebSecurity;
  const limitCases = [];
  const limitScenario = function (name, spec, steps) {
    const table = new Map();
    const sec = new WebSecurity(Object.assign(WebSecurity.defaultDeps(), {
      config: fakeConfig, mode: fakeMode, buckets: table,
      clientAddress: { clientAddressOf: function (r) {
        return String((r && r.address) || '');
      } } }));
    const out = [];
    const run = recorded(Object.assign({ now: NOW }, spec), function () {
      steps.forEach(function (step) {
        const at = NOW + (step[2] || 0);
        Date.now = function () {
          return at;
        };
        const args = step[1].slice();
        if (['attempt', 'blocked', 'succeeded'].indexOf(step[0]) >= 0) {
          args[1] = { address: args[1] };
        }
        const answer = verdict(function () {
          const v = sec[step[0]].apply(sec, args);
          return v === undefined ? null : v;
        });
        const rows = {};
        table.forEach(function (row, key) {
          rows[key] = clone(row);
        });
        out.push({ method: step[0], args: clone(step[1]), at: at,
                   answer: answer, buckets: rows });
      });
    });
    limitCases.push(Object.assign({ name: name, spec: clone(spec),
                                   steps: out }, run.taped));
  };
  const ip = '198.51.100.7';
  limitScenario('five a minute, by identity and address', {},
    [['attempt', ['sign-in', ip, 'Alice']], ['attempt', ['sign-in', ip,
      'alice'], 1000], ['attempt', ['sign-in', ip, 'alice'], 2000],
     ['attempt', ['sign-in', ip, 'alice'], 3000],
     ['attempt', ['sign-in', ip, 'alice'], 4000],
     ['blocked', ['sign-in', ip, 'alice'], 4500],
     ['attempt', ['sign-in', ip, 'alice'], 5000],
     ['attempt', ['sign-in', '203.0.113.9', 'alice'], 5500],
     ['attempt', ['sign-in', ip, 'bob'], 6000],
     ['attempt', ['sign-in', ip, 'alice'], 61000],
     ['succeeded', ['sign-in', ip, 'alice', { keepAddress: true }], 62000],
     ['blocked', ['sign-in', ip, 'alice'], 62000],
     ['succeeded', ['sign-in', ip, 'alice'], 63000]]);
  limitScenario('limits by setting and by door', {
    settings: { 'security.rateLimitWindowS': 10,
                'security.rateLimitPerIdentity': 2,
                'security.rateLimitPerAddress': '3' } },
    [['attempt', ['mfa-code', ip, 'carol']],
     ['attempt', ['mfa-code', ip, 'carol'], 100],
     ['attempt', ['mfa-code', ip, 'carol'], 200],
     ['blocked', ['mfa-code', ip, 'carol'], 300],
     ['attempt', ['mfa-code', ip, ''], 400],
     ['attempt', ['mfa-code', ip, ''], 500],
     ['blocked', ['mfa-code', ip, ''], 600],
     ['attempt', ['kerberos', '', 'dave', { address: 9007199254740991 }],
      700],
     ['attempt', ['x', ip, 'erin', 1], 800],
     ['attempt', ['x', ip, 'erin', 1], 900],
     ['attempt', ['y', ip, 'erin', { identity: 3.7, address: -1 }], 950],
     ['blocked', ['mfa-code', ip, 'carol'], 10300]]);
  limitScenario('the failure delay', {},
    [['failureDelayMs', ['Fred']], ['noteFailure', ['Fred']],
     ['failureDelayMs', ['fred'], 1], ['noteFailure', ['fred'], 2],
     ['noteFailure', ['fred'], 3], ['noteFailure', ['fred'], 4],
     ['noteFailure', ['fred'], 5], ['noteFailure', ['fred'], 6],
     ['failureDelayMs', ['fred'], 7],
     ['failureDelayMs', ['fred'], 900007],
     ['noteFailure', ['fred'], 900008],
     ['failureDelayMs', ['fred'], 900009],
     ['forgetFailures', ['fred'], 900010],
     ['failureDelayMs', ['fred'], 900011]]);

  // WHAT A CREDENTIAL EARNS: authn.ts's own readers of an `amr`, a step's
  // first factor, an AAGUID and a key's lane.
  const helpers = req('common/helpers');
  const self = { deps: { log: helpers.log } };
  const evidence = {
    phrases: [[], ['pwd'], ['hwk'], ['pwd', 'hwk'], ['otp'], ['pwd', 'otp'],
              ['pop', 'pwd'], ['hwk', 'user'], ['swk'], ['otp', 'hwk']]
      .map(function (amr) {
        return { amr: amr, phrase: Authn.prototype.methodPhraseFor.call(
          self, amr) };
      }),
    first: [{}, { firstAmr: [] }, { firstAmr: ['pop'] },
            { firstAmr: ['otp', 'pwd'] }, { firstAmr: 'pwd' }, null]
      .map(function (step) {
        return { step: step, amr: Authn.prototype.firstAmrOf.call(self,
                                                                   step) };
      }),
    aaguids: ['', null, '00000000000000000000000000000000',
              'ADCE0002-35BC-C60A-648B-0B25F1F05503',
              'adce000235bcc60a648b0b25f1f05503', 'xyz', 'adce0002']
      .map(function (one) {
        return { value: one, uuid: Credentials.aaguidString(one) };
      }),
    lanes: [{}, { lane: 'pqc' }, { lane: 'PQC' }, null].map(function (key) {
      return { key: key, lane: Credentials.keyLane(key) };
    })
  };

  // -------------------------------------------------------------------------
  // THE KEY DOORS (#444 phase 5, webauthn): beginKeyEnrolment(),
  // confirmKeyEnrolment(), addKey() and addKeyClaimed(), spendAssertion()
  // and noteKeyUsed(), on a SECOND Credentials over the same recorded world,
  // whose WebAuthn policy, passkey policy, claims, counters and attestation
  // answer from the case — and over the module-level reaches the doors
  // make (the ceremony log, the client rules, the metadata service's state,
  // the signals a cloned key raises), each swapped for a recorder while
  // these scenarios run and put back after. The credential each confirm
  // posts is made by a software authenticator over the challenge its begin
  // minted: the begin is deterministic (a seeded random source, a held
  // clock), so each scenario is run once per confirm to learn it.
  // -------------------------------------------------------------------------
  const kit = req('tests/webauthn_attestation_kit');
  const nodeCrypto = require('crypto');
  const webauthnModule = req('authn/webauthn');
  const WebauthnPolicyModule = req('authn/webauthn_policy');
  const Attestation = req('authn/webauthn_attestation').WebauthnAttestation;
  const passkeyClients = req('common/passkey_clients');
  const ceremoniesModule = req('authn/webauthn_ceremonies');
  const datasetsModule = req('risk/risk_datasets');
  const signalsModule = req('ssf/account_signals');
  const riskEngineModule = req('risk/risk_engine');
  const androidModule = req('common/attestation_revocation');
  // The claims and counters ANSWER BY STATE, so each question carries its
  // place in the case's sequence of them: one key, one answer.
  const KEYS = { claims: null, counters: null, seq: 0 };
  const keyCase = function () {
    return (CASE && CASE.keys) || {};
  };
  const marked = function (key, given) {
    const answer = given || { value: { ok: true }, code: '' };
    rec(key, answer);
    const out = clone(answer.value);
    return answer.code ? errorCodes.mark(out, answer.code) : out;
  };
  const ML_DSA = [-48, -49, -50];
  const keyWebauthnPolicy = Object.assign(Object.create(fakeWebauthnPolicy), {
    enrolmentAllowed: function () {
      return marked(['webauthn.enrolmentAllowed'], keyCase().enrolment);
    },
    enrolmentLane: function (asked) {
      return rec(['webauthn.enrolmentLane', String(asked)],
                 keyCase().lane || String(asked || '') || 'classical');
    },
    classicalRetryRefusal: function (at) {
      return marked(['webauthn.classicalRetryRefusal', String(at || '')],
                    keyCase().retry);
    },
    classicalRetryLane: function (lane) {
      return rec(['webauthn.classicalRetryLane', String(lane)], 'classical');
    },
    laneRefusal: function (lane) {
      return marked(['webauthn.laneRefusal', String(lane)],
                    (keyCase().lanes || {})[lane]);
    },
    settings: function () {
      return { maxKeysPerPerson: rec(['webauthn.maxKeys'],
                                     keyCase().max || 5) };
    },
    authenticatorKinds: function () {
      return rec(['webauthn.kinds'], ['passkey', 'security-key']);
    },
    algorithmIds: function (lane, classicalOnly) {
      const lists = keyCase().algorithms ||
        { classical: [-49, -7, -8, -257], pqc: [-49] };
      const out = (lists[lane] || lists.classical).filter(function (id) {
        return !classicalOnly || ML_DSA.indexOf(id) < 0;
      });
      return rec(['webauthn.algorithmIds', String(lane), !!classicalOnly],
                 out);
    },
    heldToOffer: WebauthnPolicyModule.heldToOffer,
    failureCodeFor: WebauthnPolicyModule.failureCodeFor,
    requireUserVerification: function () {
      return rec(['webauthn.requireUv'], !!keyCase().uv);
    },
    asksPostQuantum: function (lane) {
      return rec(['webauthn.asksPostQuantum', String(lane)],
                 keyCase().asksPq !== false);
    },
    alongsideClassical: function () {
      return rec(['webauthn.alongsideClassical'], !!keyCase().alongside);
    }
  });
  const keyPasskeyPolicy = {
    hasSelection: function () {
      return rec(['passkey.hasSelection'], false);
    },
    select: function (name) {
      if (OBSERVED) {
        OBSERVED.push({ kind: 'select', name: String(name) });
      }
    },
    adminEnrolmentAllowed: function () {
      return rec(['passkey.adminEnrolment'], !!keyCase().adminEnrolment);
    },
    credentialLabelFor: function (provider, kind) {
      return rec(['passkey.label', String(provider), String(kind)],
                 keyCase().label || '');
    },
    clientRuleFor: function (client) {
      return rec(['passkey.clientRule', String(client)],
                 keyCase().clientRule || '');
    },
    refusalFor: function (at, facts) {
      const given = keyCase().refuse || null;
      return rec(['passkey.refusalFor', at, clone(facts)],
                 given ? Object.assign({}, given) : null);
    }
  };
  const ATT_SETTINGS = {
    configured: 'off', policy: 'off', trustAnchorsPem: '', allowedAaguids: [],
    minCertificationLevel: 'none', requireFips: false, allowSafetynet: false,
    androidSoftwareKeys: false, enterpriseSerialAttribute: '',
    attestationAlgorithms: [], conveyance: 'direct', enterpriseRpIds: [],
    demandsTrust: false };
  const attDeps = Object.assign(Attestation.defaultDeps(), {
    now: function () {
      return Date.now();
    },
    policy: Object.assign(Object.create(Attestation.defaultDeps().policy), {
      attestationSettings: function () {
        return rec(['attestation.settings'], Object.assign({}, ATT_SETTINGS,
          keyCase().attestation || {}));
      },
      insecureAlgorithmsAllowed: function () {
        return rec(['attestation.insecure'], false);
      }
    }),
    metadata: function () {
      return { lookupAuthenticatorBy: async function (kind, key) {
        return rec(['attestation.metadata', kind,
                    String(key || '').toLowerCase()], null);
      } };
    },
    revocation: function () {
      return { verdictFor: async function () {
        return rec(['attestation.revocation'],
                   { refused: false, status: 'good' });
      } };
    }
  });
  const keyCredentials = new Credentials(Object.assign(
    Credentials.defaultDeps(),
    { config: fakeConfig, crypto: Object.assign(Object.create(recordedCrypto),
        { randomToken: function (bits) {
          return randomBytes(Math.ceil(Number(bits) / 8))
            .toString('base64url');
        } }),
      mode: fakeMode, realms: fakeRealms, keystore: fakeKeystore, totp: totp,
      backupCodes: backup,
      appPasswords: Object.assign(Object.create(apps), {
        DOORS: appsModule.DOORS, DOOR_IDS: appsModule.DOOR_IDS,
        MAX_NAME: appsModule.MAX_NAME }),
      passwordPolicy: fakePasswordPolicy, authnPolicy: fakeAuthnPolicy,
      serviceAccounts: fakeServiceAccounts,
      serviceAccountPolicy: fakeServiceAccountPolicy,
      webauthnPolicy: keyWebauthnPolicy, passkeyPolicy: keyPasskeyPolicy,
      webauthnVerifier: webauthnModule,
      webauthnAttestation: new Attestation(attDeps),
      claims: {
        claim: function (spec) {
          const key = ['claims.claim', spec.scope, String(spec.value),
                       spec.ttlMs, String(spec.realm), KEYS.seq++];
          const forced = keyCase().claim;
          const k = spec.scope + '\u0000' + spec.value;
          let answer;
          if (forced) {
            answer = forced;
          } else if (KEYS.claims[k]) {
            answer = { ok: false, reason: 'used' };
          } else {
            KEYS.claims[k] = true;
            answer = { ok: true, handle: { scope: spec.scope,
                                           value: String(spec.value) } };
          }
          return Promise.resolve(clone(rec(key, answer)));
        },
        release: function (handle) {
          if (OBSERVED) {
            OBSERVED.push({ kind: 'release', handle: clone(handle) });
          }
          if (handle) {
            delete KEYS.claims[handle.scope + '\u0000' + handle.value];
          }
          return Promise.resolve();
        }
      },
      counters: {
        advance: function (spec) {
          const key = ['counters.advance', spec.scope, String(spec.key),
                       spec.value, String(spec.realm), KEYS.seq++];
          const k = spec.scope + '\u0000' + spec.key;
          const highest = KEYS.counters[k];
          let answer;
          if (keyCase().counterFails) {
            answer = { ok: false, reason: 'store', why: 'the store is down' };
          } else if (highest !== undefined && !(spec.value > highest ||
                     (spec.value === 0 && highest === 0))) {
            answer = { ok: false, reason: 'behind', highest: highest };
          } else {
            KEYS.counters[k] = spec.value;
            answer = { ok: true, advanced: highest === undefined ||
                                           spec.value > highest };
          }
          return Promise.resolve(clone(rec(key, answer)));
        }
      } }));
  const keyDirectory = Object.assign({}, directory, {
    writeWebauthn: function (name, value) {
      const entry = ((CASE && CASE.entries) || {})[name];
      let outcome;
      if (entry && (entry.refuses || []).indexOf('writeWebauthn') >= 0) {
        outcome = { value: false };
      } else if (entry && entry.throws &&
                 entry.throws.indexOf('writeWebauthn') >= 0) {
        outcome = { threw: 'the directory refused the write' };
      } else if (!entry) {
        outcome = { value: false };
      } else {
        entry.webauthn = (entry.webauthn || []).concat([value]);
        outcome = { value: true };
      }
      if (MUTATIONS) {
        MUTATIONS.push({ hook: 'writeWebauthn', name: String(name),
                         value: value, options: null, outcome: outcome });
      }
      GEN += 1;
      if (outcome.threw) {
        throw new Error(outcome.threw);
      }
      return outcome.value;
    },
    readWebauthnUserHandle: function (name, lane) {
      const entry = ((CASE && CASE.entries) || {})[name];
      const out = entry ? String((lane === 'pqc' ? entry.pqcHandle
                                                 : entry.handle) || '') : '';
      rec(['dir.readWebauthnUserHandle', GEN, String(name), String(lane)],
          { value: out });
      return out;
    },
    writeWebauthnUserHandle: function (name, value, lane) {
      const entry = ((CASE && CASE.entries) || {})[name];
      const outcome = entry ? { value: true } : { value: false };
      if (entry) {
        entry[lane === 'pqc' ? 'pqcHandle' : 'handle'] = value;
      }
      if (MUTATIONS) {
        MUTATIONS.push({ hook: 'writeWebauthnUserHandle', name: String(name),
                         value: [value, String(lane)], options: null,
                         outcome: outcome });
      }
      GEN += 1;
      return outcome.value;
    }
  });
  keyCredentials.setDirectory(keyDirectory);
  const clientsInstance = new passkeyClients.PasskeyClients(Object.assign(
    passkeyClients.PasskeyClients.defaultDeps(), {
      config: fakeConfig, passkeyPolicy: keyPasskeyPolicy,
      audit: { currentRequest: function () {
        return null;
      } },
      clientOf: function () {
        return rec(['client.name'], keyCase().client || '');
      },
      webauthnPolicy: function () {
        return keyWebauthnPolicy;
      },
      store: { get: function (client) {
        return rec(['client.entry', String(client)],
                   (keyCase().learned || {})[client] || null);
      } } }));
  const observeAs = function (kind, field) {
    return function (value) {
      if (OBSERVED) {
        const row = { kind: kind };
        row[field] = clone(value);
        OBSERVED.push(row);
      }
    };
  };
  const PATCHES = [
    [passkeyClients, 'offerFor', function (input) {
      return clientsInstance.offerFor(input);
    }],
    [ceremoniesModule, 'record', observeAs('ceremony', 'row')],
    [ceremoniesModule, 'possiblyReplaced', observeAs('replaced', 'facts')],
    [datasetsModule, 'mdsState', function () {
      return Promise.resolve(rec(['mds.state'],
        { active: !!keyCase().mds, stale: false }));
    }],
    [datasetsModule, 'lookupAuthenticator', function (id) {
      return Promise.resolve(rec(['mds.lookup', String(id)],
        (keyCase().mds || {})[id] || null));
    }],
    [signalsModule, 'credentialCompromised', observeAs('compromised',
                                                       'facts')],
    [riskEngineModule, 'noteAuthenticatorCompromise', function (facts) {
      const shown = Object.assign({}, facts);
      delete shown.subject;
      observeAs('risk', 'facts')(shown);
      return Promise.resolve();
    }],
    [androidModule, 'noteRegistration', observeAs('android', 'what')]
  ];
  const recordedAsync = async function (spec, fn) {
    CASE = spec;
    TAPE = {};
    MUTATIONS = [];
    RANDOM = [];
    HASHES = {};
    OBSERVED = [];
    GEN = 0;
    RNG = seeded(spec.seed || 7);
    KEYS.claims = {};
    KEYS.counters = {};
    KEYS.seq = 0;
    Object.keys(spec.entries || {}).concat(['ghost']).forEach(function (n) {
      realms.run(spec.realm || 'default', function () {
        keyCredentials.abandonKeyEnrolment(n);
      });
    });
    Date.now = function () {
      return spec.now || 1767225600000;
    };
    let out;
    try {
      out = await realms.run(spec.realm || 'default', fn);
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
  const sha256 = function (data) {
    return nodeCrypto.createHash('sha256').update(data).digest();
  };
  // A registration over a begun enrolment: the ceremony's credential, its
  // statement made after the challenge is known.
  const posted = async function (c, begun, made, extra) {
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.create', challenge: begun.challenge,
      origin: 'https://localhost:8081', crossOrigin: false }));
    c.clientDataJSON = clientDataJSON;
    c.clientDataHash = sha256(clientDataJSON);
    const statement = await made(c);
    return Object.assign({ id: c.credential.id.toString('base64url'),
      type: 'public-key', authenticatorAttachment: 'cross-platform',
      response: {
        attestationObject: kit.cbor(new Map([
          ['fmt', statement.fmt], ['attStmt', statement.attStmt],
          ['authData', c.authData]])).toString('base64url'),
        clientDataJSON: clientDataJSON.toString('base64url'),
        transports: ['usb', 'nfc', 'Bad Transport'] },
      clientExtensionResults: { credProps: { rk: true } } }, extra || {});
  };
  // An assertion by the ceremony's credential, for the reverse direction.
  const assertionOf = function (c) {
    const count = Buffer.alloc(4);
    count.writeUInt32BE(9, 0);
    const authData = Buffer.concat([sha256(Buffer.from('localhost')),
                                    Buffer.from([0x05]), count]);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get',
      challenge: 'reverse', origin: 'https://localhost:8081' }));
    return { authenticatorData: authData.toString('base64url'),
             clientDataJSON: clientDataJSON.toString('base64url'),
             signature: Buffer.from(c.credential.sign(Buffer.concat([
               authData, sha256(clientDataJSON)]))).toString('base64url'),
             expectedChallenge: 'reverse',
             expectedOrigin: 'https://localhost:8081',
             expectedRpId: 'localhost', requireUserVerification: false };
  };
  const OPTS = { origin: 'https://localhost:8081', rpId: 'localhost',
                 door: 'portal', application: 'sts-user-portal' };
  const keyScenarios = [];
  const runKeySteps = async function (spec, steps, posts) {
    const world = clone(spec);
    const begun = [];
    let stopAt = -1;
    const run = await recordedAsync(Object.assign({ now: NOW }, world),
      async function () {
        const out = [];
        for (let i = 0; i < steps.length; i++) {
          const st = steps[i];
          let args;
          if (st.post !== undefined && posts[i] === undefined) {
            stopAt = i;
            break;
          }
          if (st.method === 'confirmKeyEnrolment') {
            const last = begun[begun.length - 1] || {};
            args = [st.user, st.id === undefined ? last.enrolmentId : st.id,
                    posts[i] !== undefined ? posts[i] : st.credential,
                    Object.assign({}, OPTS, st.opts || {})];
          } else {
            args = clone(st.args);
          }
          let value;
          let threw = null;
          try {
            if (st.method === 'clonedKeyVerdict') {
              value = Credentials.clonedKeyVerdict(args[0]);
            } else {
              value = await keyCredentials[st.method].apply(keyCredentials,
                                                             args);
            }
          } catch (e) {
            threw = String((e && e.message) || e);
          }
          if (st.method === 'beginKeyEnrolment' && value && value.ok) {
            begun.push(value);
          }
          out.push({ method: st.method, args: clone(args),
                     answer: { value: clone(value === undefined ? null
                                                                : value),
                               code: errorCodes.codeOf(value) || '',
                               threw: threw } });
        }
        return out;
      });
    return { run: run, begun: begun, stopAt: stopAt };
  };
  const keyScenario = async function (name, spec, steps) {
    const posts = {};
    const reverse = [];
    for (let guard = 0; guard < 10; guard++) {
      const pass = await runKeySteps(spec, steps, posts);
      if (pass.stopAt < 0) {
        keyScenarios.push(Object.assign({ name: name, spec: clone(spec),
          steps: pass.run.out, reverse: reverse }, pass.run.taped));
        return;
      }
      const st = steps[pass.stopAt];
      const begun = pass.begun[pass.begun.length - 1] || { challenge: 'x' };
      const c = await kit.ceremony(Object.assign({ alg: -7 },
                                                 st.ceremony || {}));
      posts[pass.stopAt] = await posted(c, begun, st.post, st.extra);
      reverse.push({ step: pass.stopAt, assertion: assertionOf(c) });
    }
    throw new Error('key scenario ' + name + ' did not settle');
  };
  const saved = PATCHES.map(function (p) {
    return [p[0], p[1], p[0][p[1]]];
  });
  PATCHES.forEach(function (p) {
    p[0][p[1]] = p[2];
  });
  const none = function () {
    return kit.none();
  };
  const HANDLE = 'H'.repeat(86);
  try {
    const kim = function (extra) {
      return { entries: Object.assign({ kim: { password: stored,
        handle: HANDLE } }, extra || {}) };
    };
    const begin = function (opts) {
      return { method: 'beginKeyEnrolment', args: ['kim', opts || {}] };
    };
    const confirm = function (made, more) {
      return Object.assign({ method: 'confirmKeyEnrolment', user: 'kim',
                             post: made || none }, more || {});
    };
    await keyScenario('enrol a passkey, and use it', kim(), [
      begin({ kind: 'passkey' }), confirm(),
      { method: 'keysOf', args: ['kim'] },
      { method: 'pendingKeyEnrolmentFor', args: ['kim'] }]);
    await keyScenario('enrol two, the second excluding the first', kim(), [
      begin(), confirm(), begin({ kind: 'security-key' }), confirm(),
      { method: 'keysOf', args: ['kim'] }]);
    await keyScenario('no key may be enrolled',
      Object.assign(kim(), { keys: { enrolment: { value: { ok: false,
        why: 'Passkeys are turned off in this realm.' },
        code: 'STS-AUTHN-0044' } } }), [begin()]);
    await keyScenario('the lane refused',
      Object.assign(kim(), { keys: { lane: 'pqc', lanes: { pqc: {
        value: { ok: false, why: 'The post-quantum lane is not offered.' },
        code: 'STS-AUTHN-0351' } } } }), [begin({ lane: 'pqc' })]);
    await keyScenario('the classical retry refused',
      Object.assign(kim(), { keys: { retry: { value: { ok: false,
        reason: 'pq-only', why: 'This realm makes post-quantum passkeys ' +
        'only.' }, code: 'STS-AUTHN-0420' } } }),
      [begin({ classicalOnly: true })]);
    await keyScenario('the classical retry', kim(),
      [begin({ classicalOnly: true }), confirm()]);
    await keyScenario('a configured client rule',
      Object.assign(kim(), { keys: { client: 'Firefox 140 on Linux',
        clientRule: 'Firefox * on Linux' } }), [begin(), confirm()]);
    await keyScenario('a learned client, not applied',
      Object.assign(kim(), { settings: { 'webauthn.clientLearning': true },
        keys: { client: 'Safari 18 on iOS 18',
          learned: { 'Safari 18 on iOS 18': { learnedAt: 5 } },
          retry: { value: { ok: false, reason: 'pq-only', why: 'no' },
                   code: 'STS-AUTHN-0420' } } }), [begin()]);
    await keyScenario('product mode, nobody there', {
      entries: {}, mode: { autoCreates: false } }, [
      { method: 'beginKeyEnrolment', args: ['ghost', {}] }]);
    await keyScenario('at the cap', Object.assign(kim(), { keys: { max: 1 } }),
      [begin(), confirm(), begin()]);
    await keyScenario('nothing pending', kim(), [
      confirm(undefined, { post: undefined, id: 'nope',
                           credential: { response: {} } })]);
    await keyScenario('another enrolment id', kim(), [
      begin(), confirm(undefined, { id: 'another' })]);
    await keyScenario('the browser sent nothing', kim(), [
      begin(), confirm(undefined, { post: undefined,
        credential: { error: 'NotAllowedError', message: 'cancelled' } })]);
    await keyScenario('the wrong origin', kim(), [
      begin(), confirm(undefined, { opts: { origin: 'https://evil.example',
                                            door: 'activation' } })]);
    await keyScenario('an algorithm not offered',
      Object.assign(kim(), { keys: { algorithms: { classical: [-257] } } }),
      [begin(), confirm()]);
    await keyScenario('UV required, not given',
      Object.assign(kim(), { keys: { uv: true } }), [begin(), confirm()]);
    await keyScenario('a packed statement, trusted',
      Object.assign(kim(), { keys: { attestation: { configured:
        'verify-if-present', policy: 'verify-if-present' } } }),
      [begin(), confirm(function (c) {
        return kit.packedSelf(c);
      })]);
    await keyScenario('refused on its attestation',
      Object.assign(kim(), { keys: { attestation: { configured:
        'require-trusted', policy: 'require-trusted', demandsTrust: true } } }),
      [begin(), confirm()]);
    await keyScenario('the passkey policy refuses it',
      Object.assign(kim(), { keys: { refuse: { code: 'STS-AUTHN-0312',
        reason: 'backup-eligible', why: 'Synced passkeys are not ' +
        'accepted here.' } } }), [begin(), confirm()]);
    await keyScenario('named by the metadata service',
      Object.assign(kim(), { keys: { mds: {} } }),
      [begin(), confirm(undefined, { ceremony: { aaguid:
        Buffer.from('fbfc3007154e4ecc8c0b6e020557d7bd', 'hex') } })]);
    await keyScenario('named by the table, and labelled by the policy',
      Object.assign(kim(), { keys: { label: 'My {provider}' } }),
      [begin(), confirm(undefined, { ceremony: { aaguid:
        Buffer.from('fbfc3007154e4ecc8c0b6e020557d7bd', 'hex') } })]);
    await keyScenario('the claim is taken',
      Object.assign(kim(), { keys: { claim: { ok: false,
                                               reason: 'used' } } }),
      [begin(), confirm()]);
    await keyScenario('the claim cannot be asked',
      Object.assign(kim(), { keys: { claim: { ok: false, reason: 'store',
                                               why: 'down' } } }),
      [begin(), confirm()]);
    await keyScenario('the write refused', kim({ kim: { password: stored,
      handle: HANDLE, refuses: ['writeWebauthn'] } }), [begin(), confirm(),
      { method: 'pendingKeyEnrolmentFor', args: ['kim'] }]);
    await keyScenario('a first handle minted', { entries: { kim: {} } }, [
      begin(), confirm(), { method: 'userHandleOf', args: ['kim', {}] }]);
    await keyScenario('the post-quantum handle beside the classical',
      Object.assign(kim(), { keys: { lane: 'pqc' } }), [
        { method: 'userHandleOf', args: ['kim', { mint: true,
                                                  lane: 'pqc' }] }]);
    // addKey by value, every refusal.
    const value = { credentialId: 'Q1', publicKeyJwk: { kty: 'EC',
      crv: 'P-256', x: 'AAAA', y: 'BBBB' }, signCount: 3, label: '  Desk  ',
      attachment: 'platform', aaguid: '0102030405060708090a0b0c0d0e0f10',
      backupEligible: true, backupState: false, transports: ['internal'],
      discoverable: false, userVerified: true, minPinLength: 6,
      userHandle: HANDLE, lane: 'classical' };
    await keyScenario('addKey by value', kim(), [
      { method: 'addKey', args: ['kim', value] },
      { method: 'addKey', args: ['kim', value] },
      { method: 'addKeyClaimed', args: ['kim', Object.assign({}, value,
        { credentialId: 'Q2', enrolledBy: { username: 'root', sub: 's',
                                             at: 5.5 } })] },
      { method: 'keysOf', args: ['kim'] }]);
    await keyScenario('addKey, an administrator allowed',
      Object.assign(kim(), { keys: { adminEnrolment: true } }), [
        { method: 'addKey', args: ['kim', Object.assign({}, value,
          { enrolledBy: { username: ' root\u0001 ', at: 7 } })] }]);
    await keyScenario('addKey, the write throws', kim({ kim: {
      throws: ['writeWebauthn'] } }), [
      { method: 'addKey', args: ['kim', value] }]);
    await keyScenario('addKey, a possibly replaced key', kim({ kim: {
      webauthn: [JSON.stringify(Object.assign({}, value,
        { credentialId: 'OLD', aaguid: '01020304-0506-0708-090a-0b0c0d0e0f10',
          discoverable: true, publicKeyJwk: value.publicKeyJwk }))] } }), [
      { method: 'addKey', args: ['kim', Object.assign({}, value,
        { discoverable: true })] },
      { method: 'keysOf', args: ['kim'] }]);
    // The counter, across the cluster.
    const keyRow = JSON.stringify(Object.assign({}, value,
      { possiblyReplacedBy: 'X', possiblyReplacedAt: 4,
        backupEligible: undefined }));
    await keyScenario('assertions spent', kim({ kim: { webauthn: [keyRow] } }),
      [{ method: 'spendAssertion', args: [{ username: 'kim',
          credentialId: 'Q1', challenge: 'c1', signCount: 7,
          flags: { be: true, bs: true } }] },
       { method: 'spendAssertion', args: [{ username: 'kim',
          credentialId: 'Q1', challenge: 'c1', signCount: 8 }] },
       { method: 'spendAssertion', args: [{ username: 'kim',
          credentialId: 'Q1', challenge: 'c2', signCount: 6.7 }] },
       { method: 'spendAssertion', args: [{ username: 'kim',
          credentialId: 'Q1', challenge: 'c2', signCount: 9 }] },
       { method: 'spendAssertion', args: [{ username: 'kim',
          credentialId: '', challenge: 'c3', signCount: 9 }] },
       { method: 'keysOf', args: ['kim'] }]);
    await keyScenario('the counter store is down', Object.assign(kim({ kim: {
      webauthn: [keyRow] } }), { keys: { counterFails: true } }), [
      { method: 'spendAssertion', args: [{ username: 'kim',
        credentialId: 'Q1', challenge: 'c1', signCount: 1 }] }]);
    await keyScenario('noteKeyUsed', kim({ kim: { webauthn: [keyRow] } }), [
      { method: 'noteKeyUsed', args: ['kim', 'Q1', 12, { bs: false }] },
      { method: 'noteKeyUsed', args: ['kim', 'nope', 12] },
      { method: 'noteKeyCloned', args: ['kim', 'Q1', 'counter 1'] }]);
    await keyScenario('noteKeyUsed, the write throws', kim({ kim: {
      webauthn: [keyRow], throws: ['replaceWebauthn'] } }), [
      { method: 'noteKeyUsed', args: ['kim', 'Q1', 12] }]);
    await keyScenario('cloned-key verdicts', {}, [
      { method: 'clonedKeyVerdict', args: [{ ok: false,
        failed: ['signature counter advanced'] }] },
      { method: 'clonedKeyVerdict', args: [{ ok: false,
        failed: ['signature counter advanced', 'signature verifies'] }] },
      { method: 'clonedKeyVerdict', args: [{ ok: true, failed: [] }] }]);
  } finally {
    saved.forEach(function (p) {
      p[0][p[1]] = p[2];
    });
  }

  // The handles and secrets a later step uses are what an earlier step of
  // the same scenario answered: filled in as the steps run.
  return { totp: totpCases, backup: backupCases, apps: appCases,
           phishing: phishing, phishingKeys: phishingKeys,
           evidence: evidence, mail: mailCases, limits: limitCases,
           scenarios: scenarios, keys: keyScenarios,
           webauthn: await req('tests/tools/credentials-webauthn.js')
             .build(ROOT) };
}

/**
 * The other direction: what the crate STORED, held to Node. Every hash
 * Rust wrote where Node wrote one is verified by Node's
 * `crypto.verifySecret()` against the plaintext Node hashed; every stored
 * JSON value Rust wrote is read back by Node's parser; and Node verifies
 * an assertion with each public key Rust read out of a registration
 * (`credentials-webauthn.js`).
 *
 * @param {string} ROOT - the repository root
 * @param {any} rust - `credentials-rust.json`
 * @param {any} node - `credentials-node.json`
 * @param {Function} check - the runner's check collector
 */
function checkRust(ROOT, rust, node, check) {
  const stsCrypto = require(path.join(ROOT, 'common', 'crypto'));
  const nodeCases = [].concat(node.totp, node.backup, node.apps,
                              node.scenarios, node.limits, node.mail,
                              node.keys || []);
  const rustCases = rust.cases || [];
  let hashes = 0;
  const wrong = [];
  // Walks Node's and Rust's stored value side by side, JSON inside a
  // string included, and verifies each hash Rust put where Node put one.
  const walk = function (a, b, plain, where) {
    if (typeof a === 'string' && typeof b === 'string') {
      if (plain[a] !== undefined) {
        hashes += 1;
        if (!stsCrypto.verifySecret(plain[a], b)) {
          wrong.push(where + ': a hash Rust stored does not verify');
        }
        return;
      }
      let x = null;
      let y = null;
      try {
        x = JSON.parse(a);
        y = JSON.parse(b);
      } catch (e) {
        x = null;
      }
      if (x && typeof x === 'object' && y && typeof y === 'object') {
        walk(x, y, plain, where);
      }
      return;
    }
    if (a && b && typeof a === 'object' && typeof b === 'object') {
      Object.keys(a).forEach(function (k) {
        walk(a[k], b[k], plain, where + '.' + k);
      });
    }
  };
  rustCases.forEach(function (row, n) {
    const mine = nodeCases[n];
    (row.mutations || []).forEach(function (m, i) {
      const theirs = (mine && mine.mutations || [])[i];
      if (!theirs) {
        wrong.push(row.label + ': a write Node did not make');
        return;
      }
      walk(theirs.value, m.value, (mine && mine.hashes) || {},
           row.label + ' write ' + i);
    });
  });
  check(rustCases.length === nodeCases.length && wrong.length === 0 &&
          hashes > 0,
        'credentials: every one of ' + nodeCases.length + ' cases Rust ' +
        'replayed is in its place, and Node verifies each of the ' + hashes +
        ' hashes Rust stored',
        wrong.slice(0, 5).join('; '));
  require('./credentials-webauthn.js').checkRust(ROOT, rust.webauthn,
                                                 node.webauthn, check);
  // THE KEYS RUST STORED (#444 phase 5, webauthn): every `writeWebauthn`
  // value a key scenario's replay wrote is read by Node as `keysOf()` reads
  // a row, and Node verifies an assertion the scenario's software
  // authenticator made with the public key Rust stored.
  const webauthn = require(path.join(ROOT, 'authn', 'webauthn'));
  const Credentials = require(path.join(ROOT, 'common', 'credentials'))
    .Credentials;
  const offset = rustCases.length - (node.keys || []).length;
  let verified = 0;
  const bad = [];
  (node.keys || []).forEach(function (mine, i) {
    const theirs = rustCases[offset + i] || {};
    const rows = (theirs.mutations || []).filter(function (m) {
      return m.hook === 'writeWebauthn';
    }).map(function (m) {
      return JSON.parse(m.value);
    });
    (mine.reverse || []).forEach(function (r) {
      const id = Buffer.from(r.assertion.authenticatorData, 'base64url') &&
        rows.filter(function (row) {
          return row && row.credentialId && row.publicKeyJwk &&
                 webauthn.verifyAssertion(Object.assign({}, r.assertion,
                   { publicKeyJwk: row.publicKeyJwk })).ok;
        });
      const wrote = (mine.mutations || []).some(function (m) {
        return m.hook === 'writeWebauthn';
      });
      if (!wrote) {
        return;
      }
      if (id.length) {
        verified += 1;
        if (!Credentials.keyAlgorithm(id[0]).name) {
          bad.push(mine.name + ': Node names no algorithm for the row');
        }
      } else {
        bad.push(mine.name + ': no key Rust stored verifies the assertion');
      }
    });
  });
  check(bad.length === 0 && verified > 0,
        'credentials: Node verifies an assertion with every one of the ' +
        verified + ' passkeys Rust enrolled and stored',
        bad.slice(0, 5).join('; '));
}

module.exports = { build: build, checkRust: checkRust, PENDING: PENDING,
                   PRINTED: PRINTED };
