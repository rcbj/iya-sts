// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: spiffe_pattern_settings.js
//
// ===========================================================================
// SPIFFE'S TWO PATTERN SETTINGS ARE HELD TO THE BACKTRACKING BOUND AT A SAVE
// (#2220).
//
// `spiffe.httpChallengeAllowedDnsPatterns` (each entry a regular
// expression) and `spiffe.dockerSigstoreAllowedIdentities` (`issuer=subject`,
// a half a pattern only when it holds a regex character) carry
// `csvPatterns` in `common/config.js`:
//
//   A. A save (`checkOverride()`) refuses a nested quantifier, a
//      backreference, an entry over 256 characters and one that does not
//      compile, naming the entry, and `checkOverrideCode()` / `parseAs()`
//      answer STS-CORE-0183. Ordinary patterns, exact pairs and anchored
//      pairs are accepted.
//   B. A STORED override read back (`checkStoredOverride()`) is not held to
//      it, so a value written before #2220 survives a restart.
//   C. At startup, a value from the environment that a save would refuse
//      is WARNED about (STS-CORE-0184) and the process starts, in a child.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const config = require('../common/config');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'spiffe_pattern_settings',
  level: process.env.LOG_LEVEL || 'info' });

const DNS = 'spiffe.httpChallengeAllowedDnsPatterns';
const IDS = 'spiffe.dockerSigstoreAllowedIdentities';

function saves(t) {
  log.debug("Entering saves().");
  [[DNS, '^(a+)+\\.example\\.com$', /exponential/],
   [DNS, '^[a-z]+\\.example\\.com$,(x|xy)*', /exponential/],
   [DNS, '(a)\\1', /backreference/],
   [DNS, 'a'.repeat(257), /characters long/],
   [DNS, '([a-z', /does not compile/],
   [IDS, 'https://issuer.example=^(a|aa)*@example\\.com$', /exponential/],
   [IDS, '^https://(x+)+$=someone@example.com', /exponential/]]
    .forEach(function (row, i) {
      const problem = config.checkOverride(row[0], row[1]);
      t.check(!!problem && row[2].test(problem) &&
              config.checkOverrideCode(row[0], row[1]) === 'STS-CORE-0183',
              'A' + i + ': ' + row[0] + ' = "' + row[1].slice(0, 40) +
              '" is refused STS-CORE-0183', problem);
    });
  const parsed = config.parseAs(DNS, '(a+)+');
  t.check(!parsed.ok && errorCodes.codeOf(parsed) === 'STS-CORE-0183',
          'A: parseAs() marks the refusal STS-CORE-0183',
          JSON.stringify(parsed));
  [[DNS, '^[a-z0-9-]+\\.example\\.com$,^agent[0-9]+\\.internal$'],
   [IDS, 'https://token.actions.githubusercontent.com=' +
         'https://github.com/acme/app/.github/workflows/build.yml@' +
         'refs/heads/main'],
   [IDS, 'https://accounts.example=^[a-z]+@example\\.com$'],
   [DNS, ''], [IDS, '']].forEach(function (row, i) {
    t.equal(config.checkOverride(row[0], row[1]), null,
            'A-ok' + i + ': ' + row[0] + ' = "' + row[1].slice(0, 40) +
            '" is accepted');
  });
  log.debug("Leaving saves().");
}

function storedValues(t) {
  log.debug("Entering storedValues().");
  t.equal(config.checkStoredOverride(DNS, '^(a+)+\\.example$'), null,
          'B: a stored override holding (a+)+ is still restored');
  t.equal(config.checkStoredOverride(IDS, 'https://i=(a|aa)*'), null,
          'B: ... for the sigstore identities too');
  log.debug("Leaving storedValues().");
}

function startup(t) {
  log.debug("Entering startup().");
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  env.STS_SPIFFE_HTTP_CHALLENGE_ALLOWED_DNS_PATTERNS = '^(a+)+\\.example$';
  const child = childProcess.spawnSync(process.execPath, ['-e',
    'const c = require("./common/config"); ' +
    'process.stdout.write("\\nVALUE=" + JSON.stringify(c.value(' +
    '"spiffe.httpChallengeAllowedDnsPatterns")) + "\\n");'], {
    cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
    timeout: 60000 });
  const out = String(child.stdout || '') + String(child.stderr || '');
  t.check(child.status === 0 && /STS-CORE-0184/.test(out) &&
          /VALUE=\["\^\(a\+\)\+\\\\\.example\$"\]/.test(out),
          'C: the environment\'s value is warned about (STS-CORE-0184), ' +
          'the process starts, and the value is used as configured',
          'exit ' + child.status + ': ' + out.slice(-1500));
  log.debug("Leaving startup().");
}

function run(t) {
  log.debug("Entering run().");
  saves(t);
  storedValues(t);
  startup(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_pattern_settings',
  describe: 'SPIFFE: the http_challenge DNS patterns and the sigstore ' +
            'identities refuse a nested quantifier, a backreference, an ' +
            'overlong or uncompilable pattern at a save (STS-CORE-0183), ' +
            'keep a stored one, and warn at startup (#2220)',
  run: run
};
