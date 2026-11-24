#!/usr/bin/env node
// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: sdk/select.js
// ---------------------------------------------------------------------------
// WHICH OF THE PINNED SDKs AN IMAGE BUILD INSTALLS (#2141, ASVS 5.0.0 15.2.4).
//
// The image's optional SDKs (node-vault always, and whatever the
// `STS_CLOUD_SDKS` build argument names) were installed with a bare
// `npm install <name>`: no version, no lockfile, install scripts on. They are
// now one npm WORKSPACE each under `sdk/packages/`, every one pinned to an
// exact version, and `sdk/package-lock.json` pins every package beneath them.
// `npm ci --workspace=…` installs the named workspaces' trees from that one
// lockfile and nothing else, so a build is exactly what the lockfile says,
// and the build argument keeps taking PACKAGE NAMES as it always did.
//
// This script is the translation, run in the Dockerfile's `dependencies`
// stage from /opt/sts-sdk, where `sdk/` is copied:
//
//   node select.js <spec>...           prints the `--workspace=` arguments
//   node select.js --prune <spec>...   removes every workspace NOT selected
//
// A spec is a package name, optionally with `@<version or range>` (the form
// `npm install` took). The version installed is ALWAYS the lockfile's; a spec
// whose range the locked version does not satisfy fails the build rather than
// silently installing something other than what was asked for. A name with
// no workspace fails the build too, naming the file to add it to: an SDK
// that is not pinned is not installed.
//
// `--prune` exists for `npm sbom`, which reads every workspace the root
// declares and fails (ESBOMPROBLEMS) on the trees of the ones not installed.
//
// It runs at build time with no bunyan, so the console-backed `log` of
// bunyan's shape that tests/tools/dependency-windows.js uses.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const log = {
  debug: function (message) {
    if (process.env.STS_LOG_LEVEL === 'debug') {
      console.error(message);
    }
  }
};

// Always installed: the compose stack's secret store (the Dockerfile argues
// why the image needs it and a checkout does not).
const ALWAYS = ['node-vault'];

// npm's own semver, which every official node image carries. Without it a
// version in a spec must equal the locked one exactly.
const NPM_SEMVER = '/usr/local/lib/node_modules/npm/node_modules/semver';

/**
 * The workspace directory that pins a package.
 *
 * @param {string} name - a package name, scoped or not
 * @returns {string} e.g. `sts-sdk-aws-sdk-client-kms`
 */
function workspaceOf(name) {
  log.debug("Entering workspaceOf().");
  const slug = 'sts-sdk-' + name.replace(/^@/, '').replace('/', '-');
  log.debug("Leaving workspaceOf().");
  return slug;
}

/**
 * Splits `name@range` into its two halves.
 *
 * @param {string} spec - `mysql2`, `pkcs11js@2.1.7`, `@aws-sdk/client-kms@^3`
 * @returns {{name: string, range: string}} range is '' when none was given
 */
function parseSpec(spec) {
  log.debug("Entering parseSpec().");
  const match = /^(@?[^@]+)(?:@(.*))?$/.exec(String(spec).trim());
  if (!match) {
    log.debug("Leaving parseSpec(). Not a package spec.");
    return { name: String(spec), range: '' };
  }
  log.debug("Leaving parseSpec().");
  return { name: match[1], range: match[2] || '' };
}

/**
 * The exact-match fallback for `satisfies`.
 *
 * @param {string} version - the locked version
 * @param {string} range - what the spec asked for
 * @returns {boolean} whether they are the same string
 */
function sameVersion(version, range) {
  log.debug("Entering sameVersion().");
  log.debug("Leaving sameVersion().");
  return version === range;
}

/**
 * npm's semver `satisfies()`, or an exact comparison where it is missing.
 *
 * @returns {function(string, string): boolean} the comparison
 */
function defaultSatisfies() {
  log.debug("Entering defaultSatisfies().");
  try {
    const semver = require(NPM_SEMVER);
    log.debug("Leaving defaultSatisfies(). npm's semver.");
    return function (version, range) {
      return semver.satisfies(version, range);
    };
  } catch (e) {
    // Not an official node image (a test, a host): exact versions only,
    // which is stricter and never installs what was not asked for.
    log.debug("Caught in defaultSatisfies(): " + ((e && e.message) || e));
    log.debug("Leaving defaultSatisfies(). Exact match only.");
    return sameVersion;
  }
}

/**
 * Decides which workspaces a list of specs selects.
 *
 * @param {Array<string>} specs - the build argument's words
 * @param {string} dir - the directory holding package-lock.json and packages/
 * @param {function(string, string): boolean} [satisfies] - version check
 * @returns {{workspaces: Array<string>, errors: Array<string>}} the
 *   selected workspace directories (node-vault's first), and why any spec
 *   was refused
 */
function select(specs, dir, satisfies) {
  log.debug("Entering select().");
  const check = satisfies || defaultSatisfies();
  const lock = JSON.parse(fs.readFileSync(path.join(dir, 'package-lock.json'),
                                          'utf8'));
  const workspaces = [];
  const errors = [];
  ALWAYS.concat(specs.filter(function (one) {
    return String(one).trim() !== '';
  })).forEach(function (spec) {
    const parsed = parseSpec(spec);
    const workspace = workspaceOf(parsed.name);
    if (!fs.existsSync(path.join(dir, 'packages', workspace,
                                 'package.json'))) {
      errors.push(spec + ' is not one of the pinned SDKs: add ' +
                  'sdk/packages/' + workspace + '/package.json and run ' +
                  '`npm install --package-lock-only --ignore-scripts` in sdk/');
      return;
    }
    const locked = (lock.packages || {})['node_modules/' + parsed.name] || {};
    if (!locked.version) {
      errors.push(spec + ' has a workspace but no entry in ' +
                  'sdk/package-lock.json: run `npm install ' +
                  '--package-lock-only --ignore-scripts` in sdk/');
      return;
    }
    if (parsed.range !== '' && !check(locked.version, parsed.range)) {
      errors.push(spec + ' asks for a version the lockfile does not hold ' +
                  '(it pins ' + locked.version + '): change ' +
                  'sdk/packages/' + workspace + '/package.json and the ' +
                  'lockfile, not the build argument');
      return;
    }
    if (workspaces.indexOf(workspace) < 0) {
      workspaces.push(workspace);
    }
  });
  log.debug("Leaving select(). " + workspaces.length + " selected, " +
            errors.length + " refused.");
  return { workspaces: workspaces, errors: errors };
}

/**
 * Removes the workspace directories a build did not select.
 *
 * @param {string} dir - the directory holding packages/
 * @param {Array<string>} keep - the selected workspace directories
 * @returns {Array<string>} the ones removed
 */
function prune(dir, keep) {
  log.debug("Entering prune().");
  const removed = [];
  fs.readdirSync(path.join(dir, 'packages')).forEach(function (name) {
    if (keep.indexOf(name) < 0) {
      fs.rmSync(path.join(dir, 'packages', name),
                { recursive: true, force: true });
      removed.push(name);
    }
  });
  log.debug("Leaving prune(). " + removed.length + " removed.");
  return removed;
}

/**
 * The command line: prints the arguments, or prunes; exits 1 on a refusal.
 *
 * @param {Array<string>} argv - the arguments after the script's name
 * @returns {number} the exit status
 */
function main(argv) {
  log.debug("Entering main().");
  const pruning = argv[0] === '--prune';
  const specs = (pruning ? argv.slice(1) : argv).join(' ').split(/\s+/);
  const chosen = select(specs, process.cwd());
  if (chosen.errors.length > 0) {
    chosen.errors.forEach(function (one) {
      console.error('STS_CLOUD_SDKS: ' + one);
    });
    log.debug("Leaving main(). Refused.");
    return 1;
  }
  if (pruning) {
    prune(process.cwd(), chosen.workspaces);
  } else {
    console.log(chosen.workspaces.map(function (one) {
      return '--workspace=packages/' + one;
    }).join(' '));
  }
  log.debug("Leaving main().");
  return 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { ALWAYS, workspaceOf, parseSpec, select, prune, main };
