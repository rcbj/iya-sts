#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: settings-mode-probes.js
//
// ---------------------------------------------------------------------------
// THE NODE HALF OF THE SETTINGS AND MODE PARITY PROOF (#444, rust/DESIGN.md
// section 4.4).
//
// `sts-core::settings` and `sts-core::mode` are ports of `common/config.js`
// and `common/mode.js`, and what they port is BEHAVIOUR — a coercion, a
// sentence, a code — that no table export can carry. So this asks the Node
// modules, row by row, and writes what they answered; `sts-core`'s
// `tests/settings_mode_vectors.rs` asks the Rust ones the same questions
// and fails on the first answer that differs. It was a throwaway tool once
// (27,485 probes, for the first port) and was not kept, so the port drifted
// for two months with nothing saying so. This one is kept.
//
// What is asked, in BOTH modes:
//
//   * every row with nothing set but the operator's appconfig file this
//     tool writes (one row in three carries a value there, of every raw
//     type a file can hold): the value, its source and its text, and the
//     value in force;
//   * every row with each of a set of raw values in the ambient trust
//     realm's overrides — the generic edge cases of every type, and the
//     row's own enum values, bounds, steps and marked values: the value
//     and its source, whether the mode allows it and what is in force,
//     and checkOverride() and checkWrite() with their codes, inside the
//     realm and outside any;
//   * every row with an environment variable, with a few string values in
//     it: the value and its source;
//   * every replaced key, and one that never was: checkOverride() and
//     checkWrite(), whose refusal names what replaced it;
//   * a list of scenarios — realm and process modes apart, the opt-outs
//     on, the neighbours of the derived defaults moved — with every
//     derived default, every predicate's answer and the whole `/admin/mode`
//     report.
//
//   * the LAYERS a write goes through (phase 3): a secret delivered as a
//     file over its variable (#254), setOverride() landing in the ambient
//     realm and refused by the mode there, clearOverride()'s refusals and
//     the pinned-signer one (#263), a rule reading its companion through
//     withWriteBatch()'s beside() (#1114), and the management API's base
//     advertised by a custom listener (#472) — `layers`;
//   * APPCONFIG FILES, each loaded as the CONFIG_FILE of a child of its own
//     (`settings-files-node.json`): the shipped `env/*.js` and `env/*.json`
//     and a set of written ones in every form an operator might use, with
//     what the module exported, every row's value, source and text, what
//     config.js wrote to stderr when it refused to start (STS-CORE-0001,
//     0105, 0108) and the warnings it logged (STS-CORE-0176, the drift
//     audit). sts-core's `tests/appconfig_vectors.rs` loads each file
//     through its own evaluator and asks the same.
//
// The strings are written once, in a table, and referred to by index:
// the restart reasons alone would otherwise be most of the file.
//
// **THE OUTPUT IS NEVER COMMITTED.** It is `tests/vectors/sts-core/` by
// default — gitignored with the other vectors — or `STS_CORE_VECTORS`:
//
//   node tests/tools/settings-mode-probes.js [directory]
//   STS_CORE_VECTORS=<dir> cargo test -p sts-core --test settings_mode_vectors
//
// It runs itself again as a child with an EMPTY environment (PATH and
// CONFIG_FILE only), so a variable of the host's cannot become a layer the
// Rust side does not know about.
//
// TWO MODULES ARE STUBBED, because the Rust side has no counterpart yet and
// says so: `oauth-oidc/oauth2_bcp`, which `mode.report()` requires lazily
// for the RFC 9700 waivers (TypeScript underneath, so it cannot load on a
// checkout; `sts-core::mode` takes them from a slot, and each scenario
// hands both sides the same list), and `common/listener_map`, which
// `managementApiBaseUrl()` asks for a custom listener's advertised base
// (`sts-core` has no listener map; none is configured here, so the stub's
// empty answer is the real one).
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
const OUT = path.resolve(process.argv[2] || process.env.STS_CORE_VECTORS ||
  path.join(ROOT, 'tests', 'vectors', 'sts-core'));
const CHILD = process.env.STS_PROBE_CHILD === '1';

const MODES = ['development', 'product'];

// ---------------------------------------------------------------------------
// The parent: the appconfig file, then the child.
// ---------------------------------------------------------------------------

// The value the operator's file carries for the row at `index`, or
// undefined for none: one row in three, cycling through the raw types a
// file can hold. Every value passes the row's own check, because config.js
// refuses to start on one that does not (refuseMalformedSettings()).
function fileValue(row, index) {
  if (index % 3 !== 0 || (row.path || row.key) === 'logLevel' ||
      row.key === 'global.mode') {
    return undefined;
  }
  const turn = (index / 3) % 3;
  switch (row.type) {
    case 'int': {
      const n = typeof row.min === 'number' ? row.min :
        typeof row.max === 'number' ? row.max : 7;
      return turn === 0 ? n : turn === 1 ? ' ' + n + ' ' : String(n);
    }
    case 'port':
      return turn === 0 ? 8443 : ' 0';
    case 'bool':
      return [true, 'OFF', ' yes '][turn];
    case 'csv':
      if (Array.isArray(row.csvValues) && row.csvValues.length) {
        return turn === 0 ? row.csvValues.slice(0, 2) :
          ' ' + row.csvValues.slice(0, 2).join(' , ') + ' ,';
      }
      return turn === 0 ? ['a ', '', 'b'] : turn === 1 ? 'x, y' : [];
    case 'enum': {
      const values = row.enumValues || [];
      const one = values[turn % values.length];
      return turn === 1 ? ' ' + one + ' ' : one;
    }
    case 'color':
      return turn === 0 ? '#ABC' : ' #a1b2c3 ';
    default:
      if (row.absoluteUri) {
        return 'urn:probe:' + index;
      }
      if (typeof row.maxLength === 'number') {
        return 'p'.repeat(Math.min(row.maxLength, 3));
      }
      return turn === 0 ? 'probe ' + index : turn === 1 ? '' : ' padded ';
  }
}

function writeAppconfig() {
  const config = require(path.join(ROOT, 'common', 'config.js'));
  const file = { logLevel: 'fatal' };
  config.SETTINGS.forEach(function (row, index) {
    const value = fileValue(row, index);
    if (value === undefined) {
      return;
    }
    const parts = (row.path || row.key).split('.');
    let node = file;
    parts.slice(0, -1).forEach(function (part) {
      node[part] = node[part] || {};
      node = node[part];
    });
    node[parts[parts.length - 1]] = value;
  });
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, 'appconfig.json'),
                   JSON.stringify(file, null, 1) + '\n');
  fs.writeFileSync(path.join(OUT, 'appconfig.js'),
                   'module.exports = ' + JSON.stringify(file, null, 1) +
                   ';\n');
}

// ---------------------------------------------------------------------------
// The appconfig files (phase 3). Each case is a CONFIG_FILE as an operator
// would set it and the variables beside it; the child loads config.js on it
// and says what it made of it.
// ---------------------------------------------------------------------------
const FILE_CHILD = process.env.STS_PROBE_FILE_CHILD === '1';

const WRITTEN = {
  'forms-base.json': '\ufeff{ "global": { "port": 9443 }, "list": [1, "a"] }\n',
  'forms.js': [
    '#!/usr/bin/env node',
    '// Every form an operator might write in a file of this service.',
    "'use strict';",
    "const base = require('./forms-base.json');",
    'const shared = { https: true };',
    'const host = `0.0.0.0`;',
    'module.exports = Object.assign({}, base, {',
    "  logLevel: 'warn',",
    '  global: { ...base.global, ...shared, host: host,',
    "    domain: process.env.STS_APPCONFIG_PROBE || 'example.org',",
    '    get trustProxy() { return false; } },',
    "  ['saml' + '2']: { attributes: [ 'uid', 'mail' ] },",
    '  oauth2: { refreshIdleSeconds: 2 ** 10, issuer: "\\u00e9t\\u00e9",',
    '            clientAssertionSkewS: 6e1, breakIdTokenNonce: undefined },',
    '  tls: { note: { deeper: { ignored: true } } },',
    "  krb5: { realm: 'EXAMPLE.ORG', clockOffset: -0 }",
    '});',
    'module.exports.persistence = { writeDelay: 0.5e4 };',
    ''
  ].join('\n'),
  'exports.js': "logLevel = undefined;\nexports.logLevel = 'warn';\n" +
    "this.global = { port: '7070' };\nexports.ldap = { autocreateUsers: " +
    "'yes' };\n",
  'cycle-a.js': "exports.logLevel = 'warn';\nconst b = require('./cycle-b');" +
    "\nexports.global = { domain: b.domain };\n",
  'cycle-b.js': "const a = require('./cycle-a.js');\nmodule.exports = { " +
    "domain: a.logLevel === 'warn' ? 'cycle.example' : 'wrong' };\n",
  'index-dir/index.js': "module.exports = { logLevel: 'warn', global: " +
    "{ domain: 'dir.example' } };\n",
  'requires-dir.js': "module.exports = require('./index-dir');\n",
  'replaced.js': "module.exports = { logLevel: 'warn', saml: { issuer: " +
    "'urn:old' }, wstrust: { issuer: 'urn:old' } };\n",
  'malformed.js': "module.exports = { logLevel: 'warn', ldap: " +
    "{ autocreateUsers: 'treu' }, pki: { keyAlgorithm: 'RSA-2048' }, " +
    "webauthn: { algorithms: 'ES256,NOSUCHALG' }, global: { port: 70000 } " +
    "};\n",
  'absolute-uri.js': "module.exports = { logLevel: 'warn', saml2: " +
    "{ nameIdFormat: ',]' } };\n",
  'drift.js': "module.exports = { logLevel: 'warn', global: { domain: " +
    "'drift.example', domian: 'x' }, oauth2: { rfc9700: false }, " +
    "nosuchgroup: { a: 1 }, toplevelthing: 3 };\n",
  'theirs.js': "module.exports = { logLevel: 'warn', theirOwn: { x: 1 } };\n",
  'syntax.js': "module.exports = {\n",
  'throws.js': "throw new Error('the file refused to load');\n",
  'throws-value.js': "throw 'a plain string';\n",
  'missing-require.js': "module.exports = require('./not-here');\n",
  'not-an-object.js': "module.exports = 'just a string';\n",
  'empty.js': ''
};

// `file`: relative to the package root as an operator writes it, or a
// written file; `env`: the variables beside CONFIG_FILE.
const FILE_CASES = [
  { file: './env/local.js' }, { file: './env/test.js' },
  { file: './env/docker-tests.js' }, { file: './env/npm-tests.js' },
  { file: './env/defaults.js' }, { file: './env/local.json' },
  { file: './env/test.json' }, { file: './env/docker-tests.json' },
  { file: null },
  { file: './env/local.js', env: { STS_ISSUER: 'urn:old',
                                   SAML2_ENTITY_ID: 'urn:old' } },
  { file: './env/local.js', env: { LDAP_AUTOCREATE_USERS: 'treu',
                                   STS_PORT: ' 99999 ' } },
  { file: './env/local.js', env: { STS_SAML2_NAME_ID_FORMAT: 'urn:a b' } },
  { file: './env/does-not-exist.js' },
  { file: 'some-package-name' }
].concat(Object.keys(WRITTEN).filter(function (name) {
  return /\.js$/.test(name) && !/^cycle-b|^index-dir/.test(name);
}).map(function (name) {
  return { file: 'WRITTEN/' + name, env: name === 'forms.js' ?
           { STS_APPCONFIG_PROBE: 'from.env.example' } : {} };
}));

function fileCases() {
  const dir = path.join(OUT, 'files');
  Object.keys(WRITTEN).forEach(function (name) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), WRITTEN[name]);
  });
  const answers = FILE_CASES.map(function (one) {
    const given = one.file === null ? null :
      one.file.replace(/^WRITTEN\//, path.join(dir, '/'));
    const answer = path.join(OUT, 'file-answer.json');
    try {
      fs.unlinkSync(answer);
    } catch (e) {
      // Nothing to remove: the first case, or a case that wrote nothing.
    }
    const env = Object.assign({ PATH: process.env.PATH,
                                STS_PROBE_FILE_CHILD: '1',
                                STS_PROBE_ANSWER: answer },
                              one.env || {});
    if (given !== null) {
      env.CONFIG_FILE = given;
    }
    const run = childProcess.spawnSync(process.execPath, [__filename, OUT], {
      env: env, cwd: ROOT, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024
    });
    const warnings = String(run.stdout || '').split('\n')
      .filter(function (line) {
        return /^\{/.test(line);
      }).map(function (line) {
        return JSON.parse(line);
      }).filter(function (line) {
        return line.level >= 40;
      }).map(function (line) {
        return line.msg;
      });
    let loaded = null;
    if (fs.existsSync(answer)) {
      loaded = JSON.parse(fs.readFileSync(answer, 'utf8'));
    }
    return { file: one.file, given: given, env: one.env || {},
             status: run.status, stderr: String(run.stderr || ''),
             warnings: warnings, loaded: loaded };
  });
  fs.writeFileSync(path.join(OUT, 'settings-files-node.json'),
                   JSON.stringify({ root: ROOT, cases: answers }));
  console.log('wrote ' + path.join(OUT, 'settings-files-node.json') + ': ' +
              answers.length + ' appconfig files');
}

if (FILE_CHILD) {
  // config.js runs every startup check as it loads, and exits on a refusal
  // with the sentence on stderr — which is what the parent records.
  const config = require(path.join(ROOT, 'common', 'config.js'));
  const operator = process.env.CONFIG_FILE ?
    require(process.env.CONFIG_FILE) : null;
  fs.writeFileSync(process.env.STS_PROBE_ANSWER, JSON.stringify({
    configFile: process.env.CONFIG_FILE || null,
    exports: operator === undefined ? null : operator,
    baseline: config.SETTINGS.map(function (row) {
      return [config.sourceOf(row.key), config.value(row.key),
              config.text(row.key)];
    })
  }));
  return;
}

if (!CHILD) {
  fileCases();
  writeAppconfig();
  const run = childProcess.spawnSync(process.execPath, [__filename, OUT], {
    env: { PATH: process.env.PATH, STS_PROBE_CHILD: '1',
           CONFIG_FILE: path.join(OUT, 'appconfig.js') },
    stdio: ['ignore', 'ignore', 'inherit']
  });
  if (run.status !== 0) {
    console.error('settings-mode-probes: the probe run failed (' +
                  run.status + ')');
    process.exit(1);
  }
  const written = JSON.parse(fs.readFileSync(
    path.join(OUT, 'settings-mode-node.json'), 'utf8'));
  console.log('wrote ' + path.join(OUT, 'settings-mode-node.json') + ': ' +
              written.counts.probes + ' probes, ' +
              written.scenarios.length + ' scenarios');
  return;
}

// ---------------------------------------------------------------------------
// The child: the probes.
// ---------------------------------------------------------------------------

const Module = require('module');

// The two stubs (see the header). `bcpWaivers` is the scenario's list.
let bcpWaivers = [];
function stub(relative, exports) {
  const file = require.resolve(path.join(ROOT, relative));
  const held = new Module(file);
  held.filename = file;
  held.loaded = true;
  held.exports = exports;
  require.cache[file] = held;
}
stub('oauth-oidc/oauth2_bcp.js', { waivers: function () {
  return bcpWaivers;
} });
let advertised = '';
stub('common/listener_map.js', { advertisedBase: function () {
  return advertised;
} });
// The certificate authority, for the pinned-signer refusals: config.js reads
// it out of `require.cache`, and `pins` is what it answers.
let pins = [];
stub('common/pki.js', { pinsBlockingSignersOff: function (realm, processWide) {
  return pins.map(function (one) {
    return Object.assign({ realm: processWide ? 'default' : realm }, one);
  });
} });
const errorCodes = require(path.join(ROOT, 'common', 'error_codes.js'));

const config = require(path.join(ROOT, 'common', 'config.js'));
const mode = require(path.join(ROOT, 'common', 'mode.js'));
const modeTable = require(path.join(ROOT, 'rust', 'crates', 'sts-core',
                                    'tables', 'mode.json'));

// The ambient realm: null, or `{ id, overrides }` as realms.js holds one.
let ambient = null;
config.setRealmContext(function () {
  return ambient;
});

// The string table.
const strings = [];
const stringIndex = new Map();
function S(text) {
  if (text === null || text === undefined || text === '') {
    return text === '' ? '' : null;
  }
  const key = String(text);
  if (!stringIndex.has(key)) {
    stringIndex.set(key, strings.length);
    strings.push(key);
  }
  return stringIndex.get(key);
}

// A refusal as [problem, code], or null.
function refusal(problem, code) {
  return problem ? [S(problem), code || ''] : null;
}

// The environment every probe starts from: the mode and nothing else.
function baseEnv(m) {
  Object.keys(process.env).forEach(function (name) {
    if (name !== 'PATH' && name !== 'CONFIG_FILE' &&
        name !== 'STS_PROBE_CHILD') {
      delete process.env[name];
    }
  });
  process.env.STS_MODE = m;
}

// The generic raw values, every type's edge cases. No lone surrogate: a
// JSON reader in Rust refuses one where the body is read.
const GENERIC = [
  '', ' ', '0', '1', '-1', '-0', '+5', ' 42 ', '12abc', 'abc', '1.5', '1e3',
  'true', 'false', 'TRUE', ' yes ', 'off', 'No', 'on ', '﻿1',
  '\u0085true', '65535', '65536', '9007199254740993',
  '123456789012345678901234', 'a,b', ' a , ,b ,', '#ABC', '#a1b2c3', '#abcd',
  'x:y', 'urn:a b', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  'a\u0000b', 'capture', null, true, false, 0, 1, -5, 1.5, 70000, 3000000000,
  1e21, 0.0000001, [], ['x ', ''], [1, null, 'a'], { a: 1 }
];

// The row's own values: its enum and csv sets, its bounds and steps, its
// default and the values its marker names.
function ownValues(row) {
  const out = [];
  (row.enumValues || []).slice(0, 8).forEach(function (one) {
    out.push(one);
  });
  if (row.enumValues && row.enumValues.length) {
    out.push(' ' + row.enumValues[row.enumValues.length - 1] + ' ');
  }
  if (Array.isArray(row.csvValues) && row.csvValues.length) {
    out.push(row.csvValues.slice(0, 3).join(','));
    out.push(row.csvValues.slice(0, 2).concat(['nope']).join(', '));
    out.push(row.csvValues.slice(0, 2));
  }
  ['min', 'max'].forEach(function (bound) {
    if (typeof row[bound] === 'number') {
      out.push(row[bound], String(row[bound] - 1), String(row[bound] + 1));
    }
  });
  if (typeof row.step === 'number') {
    const from = typeof row.min === 'number' ? row.min : 0;
    out.push(from + row.step, String(from + row.step + 1));
  }
  if (typeof row.maxLength === 'number') {
    out.push('m'.repeat(row.maxLength), 'm'.repeat(row.maxLength + 1));
  }
  if (typeof row.dflt !== 'function') {
    out.push(row.dflt);
  }
  (row.onlyWhileValues || []).forEach(function (one) {
    out.push(one);
  });
  if (Array.isArray(row.onlyWhileValues)) {
    out.push(row.onlyWhileValues.slice(0, 2).join(','),
             '18,' + row.onlyWhileValues[0]);
  }
  if (row.onlyWhileValuesUnless) {
    out.push(row.onlyWhileValuesUnless.values.join(','));
  }
  return out;
}

// The environment's raw values: strings, as a variable is.
const ENV_VALUES = ['', ' 7 ', 'true', 'no', 'a, b', 'product', '#FFF'];

let probes = 0;

// Every row with nothing set: the file's value, or the default.
function baseline() {
  return config.SETTINGS.map(function (row) {
    probes += 1;
    const value = config.value(row.key);
    return [config.sourceOf(row.key), value, S(config.text(row.key)),
            mode.valueInForce(row.key)];
  });
}

// Every row with each raw value in the realm's overrides.
function inRealm(row) {
  return GENERIC.concat(ownValues(row)).map(function (raw) {
    probes += 1;
    ambient = { id: 'acme', overrides: {} };
    ambient.overrides[row.key] = raw;
    const value = config.value(row.key);
    const answer = {
      raw: raw,
      source: config.sourceOf(row.key),
      value: value,
      allows: mode.allowsValue(row.key, value),
      inForce: mode.inForce(row.key, value, 'probe'),
      realm: refusal(config.checkOverride(row.key, raw),
                     config.checkOverrideCode(row.key, raw)),
      realmAsProcess: refusal(config.checkOverride(row.key, raw, false),
                              config.checkOverrideCode(row.key, raw, false)),
      realmWrite: refusal(config.checkWrite(row.key, raw),
                          config.checkWriteCode(row.key, raw))
    };
    ambient = null;
    answer.process = refusal(config.checkOverride(row.key, raw),
                             config.checkOverrideCode(row.key, raw));
    answer.processWrite = refusal(config.checkWrite(row.key, raw),
                                  config.checkWriteCode(row.key, raw));
    answer.mode = refusal(config.modeWriteProblem(row.key, raw),
                          config.modeWriteCode(row.key, raw));
    return answer;
  });
}

// Every row with a variable, with each string in it (and its legacy one).
function inEnv(row, m) {
  const out = [];
  [row.env, row.legacyEnv].forEach(function (name) {
    if (!name) {
      return;
    }
    ENV_VALUES.forEach(function (raw) {
      probes += 1;
      baseEnv(m);
      process.env[name] = raw;
      out.push([name, raw, config.sourceOf(row.key), config.value(row.key)]);
    });
  });
  baseEnv(m);
  return out;
}

// The settings each scenario may move, and what is asked in one.
const DERIVED = config.SETTINGS.filter(function (row) {
  return typeof row.dflt === 'function';
}).map(function (row) {
  return row.key;
});

const OPT_KEYS = ['oauth2.allowUndeclaredGrants', 'scep.allowInProduct',
  'admin.allowDefaultUsername', 'crypto.allowLegacyHashes',
  'security.allowUnscopedPeople', 'authn.allowOptionalSecondFactor',
  'federation.allowUntypedLogoutToken',
  'persistence.allowDefaultDatabasePassword', 'secrets.allowLocalSecrets',
  'audit.allowPlainSyslog', 'federation.allowAssertionWithoutAudience',
  'malwareScan.allowCleartext', 'oauth2.allowConfidentialWithoutPkce',
  'crypto.allowCbcJwe', 'devices.androidRevocationRequired',
  'ssf.receiveRequireSignature', 'ssf.actOnSignalsInDevelopment'];

const WAIVER = [{ requirement: 'no-implicit', section: 'RFC 9700 2.1.2',
                  level: 'SHOULD NOT',
                  setting: 'oauth2.allowImplicitTokenResponses',
                  perApplication: true }];

function allOn(keys) {
  const out = {};
  keys.forEach(function (key) {
    out[key] = true;
  });
  return out;
}

// `env`: variables beside STS_MODE; `realm`: the ambient realm's overrides
// (null for none); `process`: runtime overrides, set through setOverride().
const SCENARIOS = [
  { name: 'plain' },
  { name: 'opt-outs on in the realm', realm: allOn(OPT_KEYS) },
  { name: 'opt-outs on as strings', realm: { 'scep.allowInProduct': 'yes',
    'oauth2.allowUndeclaredGrants': 'true' } },
  { name: 'the realm is in product', realm: { 'global.mode': 'product' } },
  { name: 'the realm is in development',
    realm: { 'global.mode': 'development' } },
  { name: 'the process override is product',
    process: { 'global.mode': 'product' } },
  { name: 'debugger on', env: { STS_DEBUGGER_ENABLED: 'on' } },
  { name: 'debugger off', env: { STS_DEBUGGER_ENABLED: 'off' } },
  { name: 'waivers', bcpWaivers: WAIVER,
    realm: { 'xacml.enforceAccess': false, 'roles.enforceIssuance': 'off',
             'tls.certificateFile': '/etc/x.pem' } },
  { name: 'one access switch off', realm: { 'xacml.enforceAccess': 'no' } },
  { name: 'GNAP grace set', realm: { 'gnap.assertionMaxAgeS': 45 } },
  { name: 'GNAP grace in the environment',
    env: { STS_GNAP_ASSERTION_MAX_AGE_S: '60' } },
  { name: 'development-only values stored',
    realm: { 'saml2.signAssertion': false, 'krb5.enctypes': '18,17,23,1',
             'oauth2.breakIdTokenNonce': 'true', 'krb5.clockOffset': 30,
             'oid4vp.requireStatusReference': 'off',
             'pki.signatureAlgorithm': 'sha1-rsa',
             'webauthn.attestationPolicy': 'off' } },
  { name: 'only marked enctypes', realm: { 'krb5.enctypes': '23,17' } },
  { name: 'sha1 enctypes allowed',
    realm: { 'krb5.allowSha1Enctypes': true, 'krb5.enctypes': '17,23' } },
  { name: 'RFC 9700 in the environment', env: { STS_OAUTH2_RFC9700: 'true' } },
  { name: 'OAuth 2.1 in the environment', env: { STS_OAUTH2_OAUTH21: '1' } },
  { name: 'FAPI in the environment', env: { STS_OAUTH2_FAPI: '1-advanced' } },
  { name: 'RFC 9700 in the realm', realm: { 'oauth2.rfc9700': true } },
  { name: 'a port and a host', env: { STS_PORT: '443', STS_HTTPS: 'true',
                                      STS_HOST: '::1' } },
  { name: 'port 80, a named host', env: { STS_PORT: '80',
                                          STS_HOST: 'sts.example' } },
  { name: 'a bracketed host', env: { STS_HOST: '[fe80::1]' } },
  { name: 'a public base URL',
    env: { STS_PUBLIC_BASE_URL: ' https://sts.example/base// ' } },
  { name: 'a Kerberos realm', env: { KRB5_REALM: 'ACME.Example' } },
  { name: 'a web wallet', realm: { 'oid4vci.walletUrl': 'https://w.example' } }
];

function scenario(one, m) {
  baseEnv(m);
  Object.keys(one.env || {}).forEach(function (name) {
    process.env[name] = one.env[name];
  });
  bcpWaivers = one.bcpWaivers || [];
  const set = Object.keys(one.process || {});
  set.forEach(function (key) {
    const done = config.setOverride(key, one.process[key]);
    if (!done.ok) {
      throw new Error('probe: ' + key + ': ' + done.errors.join(' '));
    }
  });
  ambient = one.realm ? { id: 'acme', overrides: Object.assign({},
    one.realm) } : null;
  const derived = {};
  DERIVED.forEach(function (key) {
    derived[key] = [config.sourceOf(key), config.value(key),
                    S(config.text(key))];
  });
  const predicates = {};
  modeTable.predicates.forEach(function (name) {
    predicates[name] = mode[name]();
  });
  const answer = {
    name: one.name,
    mode: m,
    env: Object.assign({ STS_MODE: m }, one.env || {}),
    realm: one.realm || null,
    process: one.process || {},
    bcpWaivers: bcpWaivers,
    derived: derived,
    managementApiBaseUrl: config.managementApiBaseUrl(),
    predicates: predicates,
    cleartextWithHttps: mode.cleartextStartupProblem(true),
    report: mode.report()
  };
  ambient = null;
  set.forEach(function (key) {
    config.clearOverride(key);
  });
  bcpWaivers = [];
  return answer;
}

const out = { strings: strings, appconfig: 'appconfig.json', modes: {},
              scenarios: [] };
MODES.forEach(function (m) {
  baseEnv(m);
  out.modes[m] = {
    baseline: baseline(),
    realm: config.SETTINGS.map(inRealm),
    env: config.SETTINGS.map(function (row) {
      return inEnv(row, m);
    })
  };
  SCENARIOS.forEach(function (one) {
    out.scenarios.push(scenario(one, m));
  });
});
// The keys that are not rows: every replaced one, refused by name with what
// replaced it, and one nobody ever had.
out.notRows = config.REPLACED_SETTINGS.map(function (one) {
  return one.key;
}).concat(['no.such.setting']).map(function (key) {
  probes += 1;
  return [key, refusal(config.checkOverride(key, 'x'),
                       config.checkOverrideCode(key, 'x')),
          refusal(config.checkWrite(key, 'x'),
                  config.checkWriteCode(key, 'x'))];
});
// ---------------------------------------------------------------------------
// THE LAYERS A WRITE GOES THROUGH (phase 3), as one sequence over one
// process: a delivered value cannot be taken back, so this runs last, and
// the Rust half replays the same steps in the same order.
// ---------------------------------------------------------------------------
function done(result) {
  return { ok: !!result.ok, errors: (result.errors || []).map(S),
           code: errorCodes.codeOf(result) || '',
           realm: result.realm === undefined ? null : result.realm };
}

// A rule between two settings that reads its companion through `beside`:
// an organization name of `needs-display` only beside a display name.
config.addWriteRule(function (key, parsed, inRealm, beside) {
  if (key === 'saml.organizationName' && parsed === 'needs-display' &&
      beside('saml.organizationDisplayName') !== 'present') {
    return { problem: 'needs a display name beside it', code: 'STS-CORE-0006' };
  }
  return null;
});

const LAYER_STEPS = [
  { op: 'read', key: 'adminApi.clientSecret' },
  { op: 'deliver', key: 'adminApi.clientSecret', raw: 'from-file' },
  { op: 'read', key: 'adminApi.clientSecret' },
  { op: 'set', key: 'adminApi.clientSecret', raw: 'overridden' },
  { op: 'read', key: 'adminApi.clientSecret' },
  { op: 'reset', key: 'adminApi.clientSecret' },
  { op: 'read', key: 'adminApi.clientSecret' },
  { op: 'deliver', key: 'no.such.setting', raw: 'x' },
  { op: 'deliver', key: 'krb5.servicePassword', raw: 'kpw' },
  { op: 'read', key: 'krb5.servicePassword' },
  { op: 'reset', key: 'no.such.setting' },
  { op: 'reset', key: 'saml.organizationName' },
  { op: 'set', key: 'saml.organizationName', raw: 'Org' },
  { op: 'read', key: 'saml.organizationName' },
  { op: 'reset', key: 'saml.organizationName' },
  { op: 'reset', key: 'saml.organizationName' },
  { op: 'set', key: 'global.port', raw: 1 },
  { op: 'set', key: 'global.mode', raw: 'prod' },
  { op: 'realm', overrides: { 'global.mode': 'product' } },
  { op: 'set', key: 'saml2.signAssertion', raw: false },
  { op: 'set', key: 'oauth2.breakIdTokenNonce', raw: 'true' },
  { op: 'set', key: 'mail.transport', raw: 'capture' },
  { op: 'set', key: 'saml.organizationName', raw: 'Realm Org' },
  { op: 'read', key: 'saml.organizationName' },
  { op: 'set', key: 'oauth2.rfc9700', raw: true },
  { op: 'read', key: 'oauth2.rfc9700' },
  { op: 'set', key: 'realms.maxCount', raw: 20 },
  { op: 'reset', key: 'realms.maxCount' },
  { op: 'reset', key: 'saml.organizationName' },
  { op: 'read', key: 'saml.organizationName' },
  { op: 'reset', key: 'saml.organizationName' },
  { op: 'reset', key: 'global.mode' },
  { op: 'realm', overrides: null },
  { op: 'set', key: 'realms.maxCount', raw: 20 },
  { op: 'read', key: 'realms.maxCount' },
  { op: 'reset', key: 'realms.maxCount' },
  { op: 'set', key: 'saml.organizationName', raw: 'needs-display' },
  { op: 'batch', values: { 'saml.organizationName': 'needs-display',
                           'saml.organizationDisplayName': 'present' },
    key: 'saml.organizationName', raw: 'needs-display' },
  { op: 'batch', values: { 'saml.organizationName': 'needs-display',
                           'saml.organizationDisplayName': 'absent' },
    key: 'saml.organizationName', raw: 'needs-display' },
  { op: 'batch', values: { 'saml.organizationDisplayName': 'present' },
    key: 'saml.organizationName', raw: 'needs-display', set: true },
  { op: 'read', key: 'saml.organizationName' },
  { op: 'reset', key: 'saml.organizationName' },
  { op: 'set', key: 'pki.pinnedSigners', raw: true },
  { op: 'pins', pins: [{ unit: 'oauth2.jwt', kid: 'k1', role: 'active' },
                       { unit: 'saml2', kid: 'k2', role: 'pending' }] },
  { op: 'set', key: 'pki.pinnedSigners', raw: 'off' },
  { op: 'reset', key: 'pki.pinnedSigners' },
  { op: 'realm', overrides: { 'pki.pinnedSigners': true } },
  { op: 'reset', key: 'pki.pinnedSigners' },
  { op: 'realm', overrides: null },
  { op: 'pins', pins: [] },
  { op: 'reset', key: 'pki.pinnedSigners' },
  // The process off, a realm on, a pin live: the realm's reset would leave
  // it reading the process's false, and is refused.
  { op: 'set', key: 'pki.pinnedSigners', raw: false },
  { op: 'pins', pins: [{ unit: 'oauth2.jwt', kid: 'k3', role: 'active' }] },
  { op: 'realm', overrides: { 'pki.pinnedSigners': true } },
  { op: 'reset', key: 'pki.pinnedSigners' },
  { op: 'realm', overrides: null },
  { op: 'pins', pins: [] },
  { op: 'reset', key: 'pki.pinnedSigners' },
  { op: 'base' },
  { op: 'advertise', base: ' https://edge.example/x// ' },
  { op: 'base' },
  { op: 'read', key: 'adminApi.audience' },
  { op: 'advertise', base: '' },
  { op: 'base' },
  { op: 'set', key: 'global.logLevel', raw: 'fatal' },
  { op: 'read', key: 'global.logLevel' },
  { op: 'reset', key: 'global.logLevel' }
];

function layerSequence(m) {
  baseEnv(m);
  process.env.ADMIN_API_CLIENT_SECRET = 'from-env';
  const env = { STS_MODE: m, ADMIN_API_CLIENT_SECRET: 'from-env' };
  const answers = LAYER_STEPS.map(function (step) {
    probes += 1;
    switch (step.op) {
      case 'read':
        return [config.sourceOf(step.key), config.value(step.key)];
      case 'deliver':
        try {
          config.setDelivered(step.key, step.raw);
          return 'ok';
        } catch (e) {
          return S(e.message);
        }
      case 'set':
        return [done(config.setOverride(step.key, step.raw)),
                ambient ? Object.assign({}, ambient.overrides) : null];
      case 'reset':
        return [done(config.clearOverride(step.key)),
                ambient ? Object.assign({}, ambient.overrides) : null];
      case 'realm':
        ambient = step.overrides ? { id: 'acme',
          overrides: Object.assign({}, step.overrides) } : null;
        return null;
      case 'batch':
        return config.withWriteBatch(step.values, function () {
          if (step.set) {
            return done(config.setOverride(step.key, step.raw));
          }
          return refusal(config.checkOverride(step.key, step.raw),
                         config.checkOverrideCode(step.key, step.raw));
        });
      case 'pins':
        pins = step.pins;
        return null;
      case 'advertise':
        advertised = step.base;
        return null;
      case 'base':
        return config.managementApiBaseUrl();
      default:
        throw new Error('probe: no step ' + step.op);
    }
  });
  ambient = null;
  return { mode: m, env: env, steps: LAYER_STEPS, answers: answers };
}
// The delivered map and the rule stay for the rest of the process: one
// sequence, in development (the realm step moves the realm to product).
out.layers = layerSequence('development');

out.keys = config.SETTINGS.map(function (row) {
  return row.key;
});
out.counts = { probes: probes };
fs.writeFileSync(path.join(OUT, 'settings-mode-node.json'),
                 JSON.stringify(out));
