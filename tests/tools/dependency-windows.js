#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/tools/dependency-windows.js
// ---------------------------------------------------------------------------
// THE ADVISORY WINDOWS OF SECURITY.md, ENFORCED (#1458, ASVS 5.0.0 15.2.1).
//
// `npm audit` says what is vulnerable and not since when, and the windows run
// from the day an advisory was published, so each advisory's date is asked of
// the GitHub Advisory Database. An advisory whose date cannot be learned is
// overdue: a check that cannot tell must not pass. Exits 1 when any is overdue.
//
// It runs in CI with no `npm install`, so bunyan is not there: a console-backed
// `log` of bunyan's shape, the arrangement mgmt-api/admin_api_explorer.js uses.
//
// `--updates` (#1485) also holds SECURITY.md's 90-day review: a direct dependency
// with a release newer than the pinned one, the first of them more than 90 days old,
// fails unless `.github/dependency-reviews.json` records a review of that
// version in the last 90 days and why it stays. `--image-report=<file>`, given
// once per image scanned (the service's, the remote PEP's, the ICAP adapter's
// and ClamAV's since #2220), also reads a Trivy JSON report, which covers
// what `npm audit` cannot see: the operating system's packages, the Node
// runtime and every tree shipped. A finding with
// no fixed version is listed and cannot fail: nothing can be upgraded to.
//
// **TWO LOCKFILES, ONE SET OF RULES (#2159).** The root `package-lock.json`
// and `sdk/package-lock.json`, which pins the optional SDKs every image
// installs under /opt/sts-sdk (#2141), are each audited, dated and held to
// the same windows, and every line names the lockfile it came from. An SDK an
// image installs only when `STS_CLOUD_SDKS` names it is still shipped by the
// images that name it, so a finding there is not "optional" and is not
// discounted. `--updates` reads the SDK workspaces' pins as direct
// dependencies too. A lockfile whose audit cannot be read fails the run.
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

// Days from publication, per SECURITY.md. A `low` advisory has no window.
const WINDOW_DAYS = { critical: 7, high: 30, moderate: 90 };
const DAY_MS = 86400000;
// SECURITY.md's review interval.
const REVIEW_DAYS = 90;
// Trivy's severities in SECURITY.md's words; the others have no window.
const TRIVY_SEVERITY = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'moderate' };
const REVIEWS_FILE = '.github/dependency-reviews.json';
// Every lockfile the images install from, relative to the repository root
// (#2159): `dir` is where `npm audit` runs.
const LOCKFILES = [
  { dir: '.', name: 'package-lock.json' },
  { dir: 'sdk', name: 'sdk/package-lock.json' }
];

/**
 * Picks the advisories that are past their window.
 *
 * @param {Array<{id: string, severity: string, published: string}>} advisories
 * @param {number} now - milliseconds since the epoch
 * @returns {Array<object>} the overdue advisories
 */
function overdue(advisories, now) {
  log.debug("Entering overdue().");
  const late = advisories.filter(function (one) {
    const window = WINDOW_DAYS[one.severity];
    if (window === undefined) {
      return false;
    }
    const published = Date.parse(one.published);
    return isNaN(published) || now - published > window * DAY_MS;
  });
  log.debug("Leaving overdue().");
  return late;
}

/**
 * Reads a Trivy JSON report into advisories of `overdue()`'s shape.
 *
 * @param {object} report - the parsed report
 * @returns {Array<object>} one row per vulnerability and package
 */
function imageFindings(report) {
  log.debug("Entering imageFindings().");
  const found = {};
  ((report && report.Results) || []).forEach(function (result) {
    (result.Vulnerabilities || []).forEach(function (one) {
      found[one.VulnerabilityID + '|' + one.PkgName] = {
        id: String(one.VulnerabilityID),
        severity: TRIVY_SEVERITY[one.Severity] || 'low',
        package: String(one.PkgName),
        published: String(one.PublishedDate || ''),
        fixed: String(one.FixedVersion || '')
      };
    });
  });
  log.debug("Leaving imageFindings().");
  return Object.keys(found).map(function (key) {
    return found[key];
  });
}

/**
 * Picks the direct dependencies whose update has waited too long unreviewed.
 *
 * @param {Array<object>} rows - `{ package, locked, latest, lockedPublished,
 *   latestPublished }`
 * @param {object} reviews - package name to `{ reviewed, reason }`
 * @param {number} now - milliseconds since the epoch
 * @returns {Array<object>} the rows past the review interval
 */
function updatesOverdue(rows, reviews, now) {
  log.debug("Entering updatesOverdue().");
  const span = REVIEW_DAYS * DAY_MS;
  const late = rows.filter(function (row) {
    // THE OLDEST NEWER RELEASE, not the newest: a package far behind must not
    // pass because its latest release happens to be a week old.
    const waiting = Date.parse(row.oldestNewerPublished);
    if (!row.oldestNewerPublished || now - waiting <= span) {
      return false;
    }
    const review = reviews[row.package] || {};
    const reviewed = Date.parse(review.reviewed);
    return !(String(review.reason || '').trim() && reviewed <= now &&
             now - reviewed <= span && review.version === row.locked);
  });
  log.debug("Leaving updatesOverdue().");
  return late;
}

/**
 * The publication date of the first release after the pinned one, up to the
 * one the registry calls latest: a higher version a publisher has not tagged
 * latest is not an update anybody is offered.
 *
 * @param {object} times - version to date, from the registry
 * @param {string} locked - the pinned version
 * @param {string} latest - the registry's `latest` tag
 * @returns {string} the date, or '' when nothing newer has been released
 */
function oldestNewer(times, locked, latest) {
  log.debug("Entering oldestNewer().");
  const pinned = Date.parse(times[locked]);
  const newest = Date.parse(times[latest]);
  const newer = Object.keys(times).filter(function (version) {
    const when = Date.parse(times[version]);
    return /^\d+\.\d+\.\d+$/.test(version) && when > pinned && when <= newest;
  }).map(function (version) {
    return times[version];
  }).sort(function (x, y) {
    return Date.parse(x) - Date.parse(y);
  });
  log.debug("Leaving oldestNewer().");
  return newer[0] || '';
}

/**
 * The direct dependencies of a lockfile's manifest: the root's own, or, for
 * a manifest of npm workspaces (sdk/), each workspace's.
 *
 * @param {string} dir - the directory holding package.json
 * @returns {Array<string>} package names
 */
function directDependencies(dir) {
  log.debug("Entering directDependencies().");
  const read = function (file) {
    return JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
  };
  const manifests = [read('package.json')];
  if (Array.isArray(manifests[0].workspaces)) {
    const base = path.join(dir, 'packages');
    fs.readdirSync(base).sort().forEach(function (one) {
      manifests.push(read(path.join('packages', one, 'package.json')));
    });
  }
  const names = {};
  manifests.forEach(function (one) {
    Object.keys(Object.assign({}, one.dependencies, one.optionalDependencies))
      .forEach(function (name) {
        names[name] = true;
      });
  });
  log.debug("Leaving directDependencies().");
  return Object.keys(names).sort();
}

/**
 * Asks the registry about every direct dependency a lockfile pins.
 *
 * @param {{dir: string, name: string}} lockfile - one of LOCKFILES
 * @returns {Array<object>} rows for `updatesOverdue()`
 */
function dependencyUpdates(lockfile) {
  log.debug("Entering dependencyUpdates().");
  const lock = JSON.parse(fs.readFileSync(path.join(lockfile.dir,
    'package-lock.json'), 'utf8'));
  const rows = [];
  directDependencies(lockfile.dir)
    .forEach(function (name) {
      const pinned = lock.packages['node_modules/' + name] || {};
      if (!pinned.version || pinned.link ||
          !/^https:\/\/registry\./.test(String(pinned.resolved || ''))) {
        return;
      }
      const ran = childProcess.spawnSync('npm', ['view', name,
        'dist-tags.latest', 'time', '--json'],
      { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
      const view = JSON.parse(ran.stdout || '{}');
      rows.push({ package: name, locked: pinned.version,
                  lockfile: lockfile.name,
                  oldestNewerPublished: oldestNewer(view.time || {},
                    pinned.version, view['dist-tags.latest']) });
    });
  log.debug("Leaving dependencyUpdates().");
  return rows;
}

/**
 * Collects the distinct advisories an `npm audit --json` report names.
 *
 * @param {object} report - the parsed report
 * @param {string} lockfile - the lockfile's name, carried on every row
 * @returns {Array<{id: string, severity: string, package: string,
 *   lockfile: string}>} advisories
 */
function auditFindings(report, lockfile) {
  log.debug("Entering auditFindings().");
  const found = {};
  Object.keys(report.vulnerabilities || {}).forEach(function (name) {
    (report.vulnerabilities[name].via || []).forEach(function (via) {
      const match = via && via.url && /GHSA-[a-z0-9-]+/i.exec(via.url);
      if (match) {
        found[match[0]] = { id: match[0], severity: via.severity,
                            package: via.name, lockfile: lockfile };
      }
    });
  });
  log.debug("Leaving auditFindings().");
  return Object.keys(found).map(function (id) {
    return found[id];
  });
}

/**
 * Runs `npm audit` over one lockfile and collects its advisories.
 *
 * @param {{dir: string, name: string}} lockfile - one of LOCKFILES
 * @returns {Array<object>} advisories, each naming the lockfile
 */
function audited(lockfile) {
  log.debug("Entering audited().");
  const ran = childProcess.spawnSync('npm',
    ['audit', '--omit=dev', '--json'],
    { cwd: lockfile.dir, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  let report;
  try {
    report = JSON.parse(ran.stdout);
  } catch (e) {
    // A CHECK THAT CANNOT TELL MUST NOT PASS: an unreadable audit of either
    // lockfile is the run's failure, not an empty list.
    log.debug("Caught in audited(): " + ((e && e.message) || e));
    log.debug("Leaving audited().");
    throw new Error('npm audit of ' + lockfile.name + ' gave no report: ' +
                    String(ran.stderr || '').trim());
  }
  if (report.error) {
    log.debug("Leaving audited().");
    throw new Error('npm audit of ' + lockfile.name + ' failed: ' +
                    JSON.stringify(report.error));
  }
  const found = auditFindings(report, lockfile.name);
  log.debug("Leaving audited().");
  return found;
}

/**
 * Asks the GitHub Advisory Database when an advisory was published.
 *
 * @param {string} id - the GHSA identifier
 * @returns {Promise<string>} the date, or '' when it could not be learned
 */
function publishedOn(id) {
  log.debug("Entering publishedOn().");
  const headers = { 'User-Agent': 'iya-sts-dependency-windows',
                    Accept: 'application/vnd.github+json' };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = 'Bearer ' + process.env.GITHUB_TOKEN;
  }
  return new Promise(function (resolve) {
    const req = https.get({ host: 'api.github.com', headers: headers,
                            path: '/advisories/' + id }, function (res) {
      let text = '';
      res.on('data', function (d) {
        text += d;
      });
      res.on('end', function () {
        try {
          resolve(String(JSON.parse(text).published_at || ''));
        } catch (e) {
          log.debug("Caught in publishedOn(): " + ((e && e.message) || e));
          resolve('');
        }
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in publishedOn(): " + ((e && e.message) || e));
      resolve('');
    });
    log.debug("Leaving publishedOn().");
  });
}

/**
 * Audits, dates and reports.
 *
 * @returns {Promise<number>} the exit status
 */
async function main() {
  log.debug("Entering main().");
  let failed = 0;
  for (const lockfile of LOCKFILES) {
    const advisories = audited(lockfile);
    for (const one of advisories) {
      one.published = await publishedOn(one.id);
    }
    const late = overdue(advisories, Date.now());
    advisories.forEach(function (one) {
      console.log([late.indexOf(one) >= 0 ? 'OVERDUE' : 'within',
                   one.lockfile, one.severity, one.package, one.id,
                   one.published || '(no date)'].join('  '));
    });
    console.log(lockfile.name + ': ' + advisories.length +
                ' advisory(ies), ' + late.length +
                ' past the window SECURITY.md gives.');
    failed += late.length;
  }
  // One report per image the daily run scans (#2220: the service, the
  // remote PEP, the ICAP adapter and ClamAV), each named on its lines.
  const named = process.argv.filter(function (one) {
    return one.indexOf('--image-report=') === 0;
  });
  named.forEach(function (flag) {
    const file = flag.slice('--image-report='.length);
    const findings = imageFindings(JSON.parse(fs.readFileSync(file, 'utf8')));
    const fixable = findings.filter(function (one) {
      return one.fixed;
    });
    const lateInImage = overdue(fixable, Date.now());
    lateInImage.forEach(function (one) {
      console.log(['OVERDUE', file, one.severity, one.package, one.id,
                   one.published, 'fixed in ' + one.fixed].join('  '));
    });
    console.log(file + ': ' + findings.length + ' finding(s), ' +
                (findings.length - fixable.length) + ' with no fix yet, ' +
                lateInImage.length + ' past the window.');
    failed += lateInImage.length;
  });
  if (process.argv.indexOf('--updates') >= 0) {
    const reviews = JSON.parse(fs.readFileSync(REVIEWS_FILE, 'utf8'));
    let rows = [];
    LOCKFILES.forEach(function (lockfile) {
      rows = rows.concat(dependencyUpdates(lockfile));
    });
    const waiting = updatesOverdue(rows, reviews, Date.now());
    waiting.forEach(function (one) {
      console.log(['UNREVIEWED', one.lockfile, one.package, one.locked,
                   'newer since', one.oldestNewerPublished].join('  '));
    });
    console.log(waiting.length + ' package(s) past the ' +
                REVIEW_DAYS + '-day review.');
    failed += waiting.length;
  }
  log.debug("Leaving main().");
  return failed ? 1 : 0;
}

if (require.main === module) {
  main().then(function (status) {
    process.exit(status);
  }, function (e) {
    console.error('dependency-windows: ' + ((e && e.stack) || e));
    process.exit(1);
  });
}

module.exports = { overdue: overdue, WINDOW_DAYS: WINDOW_DAYS,
                   LOCKFILES: LOCKFILES, auditFindings: auditFindings,
                   directDependencies: directDependencies,
                   imageFindings: imageFindings,
                   updatesOverdue: updatesOverdue,
                   oldestNewer: oldestNewer };
