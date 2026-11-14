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

if (!CHILD) {
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
stub('common/listener_map.js', { advertisedBase: function () {
  return '';
} });

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
out.keys = config.SETTINGS.map(function (row) {
  return row.key;
});
out.counts = { probes: probes };
fs.writeFileSync(path.join(OUT, 'settings-mode-node.json'),
                 JSON.stringify(out));
