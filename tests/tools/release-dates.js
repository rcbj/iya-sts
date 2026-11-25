#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/tools/release-dates.js
// ---------------------------------------------------------------------------
// THE LAST RELEASE OF EVERY PACKAGE THE IMAGES INSTALL, WRITTEN DOWN (#2220,
// ASVS 5.0.0 15.1.4).
//
// tests/long_unreleased_packages.js fails when a package the images install
// has had no release for more than three years and
// docs/v1.2.0/risky-components.md does not list it with the reason it is
// kept. That test runs in process with no network, so the dates it reads are
// in a committed file, tests/package_release_dates.json, which this script
// writes: for every registry package in the two lockfiles the images install
// from (the root's and sdk/'s, devDependencies left out as the image leaves
// them out), the publication date of its newest version and that version,
// from the npm registry. It also records the node-ldapjs submodule's pin and
// that commit's date, read with git, because the fork has no registry
// release to date, and `asOf`, the day it read them, which is the day the
// test measures three years from.
//
// Run it after a lockfile changes, and now and then besides:
//
//   node tests/tools/release-dates.js
//
// It needs the network and git, and nothing installed: like
// dependency-windows.js it carries a console-backed `log` of bunyan's shape.
// A package whose registry document cannot be read fails the run, because a
// date left out would make the test fail on a package it has never seen,
// and a date guessed would make it pass.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const https = require('https');
const path = require('path');

const log = {
  debug: function (message) {
    if (process.env.STS_LOG_LEVEL === 'debug') {
      console.error(message);
    }
  }
};

const ROOT = path.join(__dirname, '..', '..');
const OUT = path.join(ROOT, 'tests', 'package_release_dates.json');
// The lockfiles the images install from (dependency-windows.js's LOCKFILES).
const LOCKFILES = ['package-lock.json', 'sdk/package-lock.json'];
const REGISTRY = 'https://registry.npmjs.org/';
// Requests in flight at once: some registry documents are megabytes.
const PARALLEL = 6;

/**
 * The registry packages a lockfile installs, by their registry name.
 *
 * The name is read from `resolved`, not from the path, so an alias
 * (`ldapjs-asn1-v1` is `@ldapjs/asn1`) is dated as the package it is.
 * Links and `file:` packages (the node-ldapjs fork) have no `resolved` on
 * the registry and are left out: the fork is dated by its commit instead.
 *
 * @param {string} rel - the lockfile, relative to the repository root
 * @returns {Array<{name: string, version: string, path: string}>} each
 *   installed copy
 */
function lockedPackages(rel) {
  log.debug("Entering lockedPackages().");
  const lock = JSON.parse(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
  const out = [];
  Object.keys(lock.packages || {}).forEach(function (key) {
    const one = lock.packages[key];
    const resolved = String(one.resolved || '');
    if (!key || one.dev || one.link || resolved.indexOf(REGISTRY) !== 0) {
      return;
    }
    const tail = resolved.slice(REGISTRY.length).split('/-/')[0];
    out.push({ name: decodeURIComponent(tail), version: String(one.version),
               path: rel + ':' + key });
  });
  log.debug("Leaving lockedPackages().");
  return out;
}

/**
 * Every registry package name both lockfiles install, sorted.
 *
 * @returns {Array<string>} the names
 */
function lockedNames() {
  log.debug("Entering lockedNames().");
  const names = {};
  LOCKFILES.forEach(function (rel) {
    lockedPackages(rel).forEach(function (one) {
      names[one.name] = true;
    });
  });
  log.debug("Leaving lockedNames().");
  return Object.keys(names).sort();
}

/**
 * The newest version of a package and the day it was published.
 *
 * Only versions still in the document count, so an unpublished one does
 * not make a package look alive.
 *
 * @param {string} name - the registry name
 * @returns {Promise<{lastRelease: string, version: string}>} the date
 *   (YYYY-MM-DD) and the version
 */
function lastRelease(name) {
  log.debug("Entering lastRelease().");
  const url = REGISTRY + name.replace('/', '%2F');
  return new Promise(function (resolve, reject) {
    https.get(url, { headers: { 'User-Agent': 'iya-sts-release-dates',
                                Accept: 'application/json' } },
              function (res) {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', function (d) {
        text += d;
      });
      res.on('end', function () {
        try {
          if (res.statusCode !== 200) {
            throw new Error('HTTP ' + res.statusCode);
          }
          const doc = JSON.parse(text);
          const time = doc.time || {};
          let best = '';
          let version = '';
          Object.keys(doc.versions || {}).forEach(function (v) {
            if (time[v] && time[v] > best) {
              best = time[v];
              version = v;
            }
          });
          if (!best) {
            throw new Error('no dated version');
          }
          resolve({ lastRelease: best.slice(0, 10), version: version });
        } catch (e) {
          log.debug("Caught in lastRelease(): " + ((e && e.message) || e));
          reject(new Error(name + ': ' + ((e && e.message) || e)));
        }
      });
    }).on('error', function (e) {
      log.debug("Caught in lastRelease(): " + ((e && e.message) || e));
      reject(new Error(name + ': ' + ((e && e.message) || e)));
    });
    log.debug("Leaving lastRelease().");
  });
}

/**
 * The node-ldapjs submodule's pin and its commit date, from git.
 *
 * @returns {{path: string, commit: string, committed: string,
 *   version: string}} the pin
 */
function forkPin() {
  log.debug("Entering forkPin().");
  const tree = childProcess.execFileSync('git',
    ['ls-tree', 'HEAD', 'node-ldapjs'], { cwd: ROOT, encoding: 'utf8' });
  const commit = tree.split(/\s+/)[2];
  const committed = childProcess.execFileSync('git',
    ['-C', 'node-ldapjs', 'log', '-1', '--format=%cI', commit],
    { cwd: ROOT, encoding: 'utf8' }).trim().slice(0, 10);
  const manifest = JSON.parse(fs.readFileSync(
    path.join(ROOT, 'node-ldapjs', 'package.json'), 'utf8'));
  log.debug("Leaving forkPin().");
  return { path: 'node-ldapjs', commit: commit, committed: committed,
           version: String(manifest.version) };
}

/**
 * Dates every package and writes the file.
 *
 * @returns {Promise<number>} the exit status
 */
async function main() {
  log.debug("Entering main().");
  const names = lockedNames();
  const packages = {};
  const failures = [];
  let next = 0;
  const worker = async function () {
    while (next < names.length) {
      const name = names[next];
      next += 1;
      try {
        packages[name] = await lastRelease(name);
      } catch (e) {
        log.debug("Caught in main(): " + ((e && e.message) || e));
        failures.push(String((e && e.message) || e));
      }
    }
  };
  const workers = [];
  for (let i = 0; i < PARALLEL; i += 1) {
    workers.push(worker());
  }
  await Promise.all(workers);
  if (failures.length) {
    failures.forEach(function (one) {
      console.error('release-dates: ' + one);
    });
    log.debug("Leaving main().");
    return 1;
  }
  const sorted = {};
  Object.keys(packages).sort().forEach(function (name) {
    sorted[name] = packages[name];
  });
  const doc = {
    '//': 'Written by tests/tools/release-dates.js; read by ' +
          'tests/long_unreleased_packages.js. Do not edit by hand.',
    // The day these dates were read. The test measures three years from
    // HERE, not from the day it runs, so its verdict changes only when
    // somebody refreshes this file on purpose.
    asOf: new Date().toISOString().slice(0, 10),
    lockfiles: LOCKFILES,
    fork: forkPin(),
    packages: sorted
  };
  fs.writeFileSync(OUT, JSON.stringify(doc, null, 2) + '\n');
  console.log('release-dates: ' + names.length + ' package(s) dated into ' +
              path.relative(ROOT, OUT));
  log.debug("Leaving main().");
  return 0;
}

if (require.main === module) {
  main().then(function (status) {
    process.exit(status);
  }, function (e) {
    console.error('release-dates: ' + ((e && e.stack) || e));
    process.exit(1);
  });
}

module.exports = { LOCKFILES: LOCKFILES, OUT: OUT,
                   lockedPackages: lockedPackages, lockedNames: lockedNames };
