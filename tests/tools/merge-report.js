#!/usr/bin/env node
'use strict';
//
// File: tests/tools/merge-report.js
//
// ===========================================================================
// FOLDS ONE RUN'S JOBS INTO ANOTHER RUN'S REPORT (2026-09-18).
//
//   node tests/tools/merge-report.js --into=<run dir> --from=<run dir>
//                                    [--label=<word>]
//
// A run against an AWS environment is made of two runs of run-report.js:
// the jobs that can be driven from a developer's machine, run there, and the
// two that need the service to call them back, run in a task inside the VPC
// (deploy/aws/run-suite.sh, deploy/aws/suite-callbacks/). One question —
// "did the suite pass against this environment" — deserves one report, so the
// second run's jobs are added to the first's: their logs are copied in under
// `logs/`, renumbered after the first run's and marked with the label, and
// report.html, report.xml and summary.json are drawn again from both.
//
// **THE ASSERTIONS ARE READ BACK OUT OF THE LOGS WITH run-report.js's OWN
// `assertionOf()`, AND THE PAGES ARE DRAWN WITH ITS OWN WRITERS.** summary.json
// carries counts, not assertions, and a merged page drawn by a second renderer
// would be a second opinion about what a run looked like. So a merged report
// is exactly the report one run of both halves would have written.
//
// A job in `--from` whose name is already in `--into` REPLACES it, so a job the
// first run listed as not run is shown with the result of the run that ran it.
//
// Its `log` is console-backed and bunyan-shaped, the arrangement the root
// CLAUDE.md names for a tool outside the service.
// ===========================================================================
const fs = require('fs');
const path = require('path');

const log = {
  debug: function (message) {
    if (process.env.LOG_LEVEL === 'debug') {
      process.stderr.write(message + '\n');
    }
  },
  info: function (message) {
    process.stdout.write(message + '\n');
  }
};

const report = require('./run-report.js');

function parseArgs(argv) {
  log.debug('Entering parseArgs().');
  const opts = { into: '', from: '', label: 'merged' };
  argv.forEach(function (a) {
    const m = /^--(into|from|label)=(.*)$/.exec(a);
    if (m) {
      opts[m[1]] = m[2];
    }
  });
  log.debug('Leaving parseArgs().');
  return opts;
}

// One run directory, read back into the shape run-report.js's writers take.
// A run dir may be given as its `latest` link.
function loadRun(dir) {
  log.debug('Entering loadRun(). dir=' + dir);
  const runDir = fs.realpathSync(dir);
  const summary = JSON.parse(fs.readFileSync(path.join(runDir,
                                                       'summary.json'),
                                             'utf8'));
  const results = summary.jobs.map(function (j) {
    const assertions = [];
    if (j.log) {
      let text = '';
      try {
        text = fs.readFileSync(path.join(runDir, 'logs', j.log), 'utf8');
      } catch (e) {
        // A job that never started has no log (run-report.js says why in
        // its runner log); its summary row still stands.
        log.debug('Caught in loadRun(): ' + ((e && e.message) || e));
      }
      text.split('\n').forEach(function (line) {
        const a = report.assertionOf(line);
        if (a) {
          assertions.push(a);
        }
      });
    }
    return Object.assign({}, j, { logName: j.log || '',
                                  assertions: assertions,
                                  failures: j.failures || [] });
  });
  log.debug('Leaving loadRun(). ' + results.length + ' job(s).');
  return { runDir: runDir, meta: summary.meta || {}, results: results };
}

function merge(opts) {
  log.debug('Entering merge().');
  if (!opts.into || !opts.from) {
    log.debug('Leaving merge(). Missing an argument.');
    throw new Error('usage: merge-report.js --into=<run dir> ' +
                    '--from=<run dir> [--label=<word>]');
  }
  const into = loadRun(opts.into);
  const from = loadRun(opts.from);
  const logsDir = path.join(into.runDir, 'logs');
  fs.mkdirSync(logsDir, { recursive: true });

  const fromNames = new Set(from.results.map(function (j) {
    return j.name;
  }));
  const kept = into.results.filter(function (j) {
    return !fromNames.has(j.name);
  });
  let n = into.results.length;
  const added = from.results.map(function (j) {
    n++;
    let logName = '';
    if (j.logName) {
      logName = String(n).padStart(2, '0') + '-' + report.slug(opts.label) +
                '-' + report.slug(j.name) + '.log';
      fs.copyFileSync(path.join(from.runDir, 'logs', j.logName),
                      path.join(logsDir, logName));
    }
    return Object.assign({}, j, { logName: logName,
                                  describe: 'run by ' + opts.label });
  });
  // The other run's own service and runner logs, kept beside the jobs'.
  ['00-test-runner.log', '00-mock-sts-service.log'].forEach(function (name) {
    const src = path.join(from.runDir, 'logs', name);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(logsDir, '00-' + report.slug(opts.label) +
                                     '-' + name.slice(3)));
    }
  });

  const results = kept.concat(added);
  const meta = Object.assign({}, into.meta, {
    merged: (into.meta.merged || []).concat([{
      label: opts.label, runId: from.meta.runId || '',
      serviceUrl: from.meta.serviceUrl || '',
      jobs: added.map(function (j) { return j.name; })
    }])
  });
  report.writeHtml(into.runDir, results, meta);
  report.writeXml(into.runDir, results, meta);
  fs.writeFileSync(path.join(into.runDir, 'summary.json'),
    JSON.stringify({ meta: meta, jobs: results.map(function (j) {
      return { suite: j.suite, name: j.name, status: j.status, ms: j.ms,
               code: j.code, assertions: j.assertions.length,
               assertionsFailed: j.assertions.filter(function (a) {
                 return !a.ok;
               }).length,
               failures: j.failures, why: j.why || '', log: j.logName };
    }) }, null, 2) + '\n');
  const failed = results.filter(function (j) {
    return j.status === 'failed';
  }).length;
  log.info('merge-report: ' + added.length + ' job(s) from ' + from.runDir +
           ' added to ' + into.runDir + '; ' + results.length + ' job(s), ' +
           failed + ' failed.');
  log.debug('Leaving merge().');
  return failed;
}

if (require.main === module) {
  try {
    const failed = merge(parseArgs(process.argv.slice(2)));
    process.exit(failed ? 1 : 0);
  } catch (e) {
    process.stderr.write('merge-report: ' +
                         ((e && e.stack) || String(e)) + '\n');
    process.exit(2);
  }
}

module.exports = { merge: merge, loadRun: loadRun };
