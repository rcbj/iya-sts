// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/suite_444_switch.js
//
// ===========================================================================
// THE #444 SWITCH (rcbj, 2026-11-15): "put a flag around all #444 related
// tests", so that the integrator's runs test the TypeScript implementation
// while the #444 session keeps its own.
//
// The jobs #444 CREATED carry `optIn: '444'` in tests/protocol/MANIFEST.js
// (in-process files would be named in run-report.js's UNIT_OPT_IN, which is
// empty for 444), and STS_TEST_444 decides whether they run: `off`, the
// default, reports each SKIPPED with the reason; `on` runs it. What is held:
//
//   A. the marker is used consistently — every `optIn` a known switch, the
//      444 set not empty, every name in UNIT_OPT_IN an existing in-process
//      file and no protocol job;
//   B. the switch's reading — off by default, on, off, and a typo refused;
//   C. the selection, by run-report.js itself in a child (`--list`, which
//      starts nothing): off marks EXACTLY the tagged set skipped, on marks
//      none, and an --only naming a tagged job says so;
//   D. --only naming only tagged jobs while off fails, naming the switch and
//      how to turn it on, before any service is started — a run of skips
//      must not pass;
//   E. the skip reason reaching the summary line and the JUnit `<skipped>`;
//   F. the plumbing, as source: the launcher's --with-444, its default, its
//      --plan line and COMPOSE_ENV row; the compose file's tests service;
//      the workflow's input and its STS_TEST_444.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const runner = require('./tools/run-report');
const manifest = require('./protocol/MANIFEST.js');

const log = require('bunyan').createLogger({ name: 'suite_444_switch',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const RUN_REPORT = path.join(__dirname, 'tools', 'run-report.js');
const REASON = '#444 tests switched off (STS_TEST_444=off)';

function read(rel) {
  log.debug('Entering read().');
  const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
  log.debug('Leaving read().');
  return text;
}

// run-report.js in a child, with STS_TEST_444 as given (undefined: unset).
function runner444(args, value) {
  log.debug('Entering runner444().');
  const env = Object.assign({}, process.env, { LOG_LEVEL: 'warn' });
  delete env.STS_TEST_444;
  if (value !== undefined) {
    env.STS_TEST_444 = value;
  }
  const out = spawnSync(process.execPath, [RUN_REPORT].concat(args),
                        { cwd: ROOT, env: env, encoding: 'utf8',
                          timeout: 120000 });
  log.debug('Leaving runner444().');
  return { code: out.status, text: (out.stdout || '') + (out.stderr || '') };
}

// The protocol names --list printed, split by whether they were marked.
function listed(text) {
  log.debug('Entering listed().');
  const marked = [];
  const plain = [];
  text.split('\n').forEach(function (line) {
    const m = /^protocol {2}(\S+)(.*)$/.exec(line);
    if (!m) {
      return;
    }
    (m[2].indexOf('[SKIPPED: ' + REASON + ']') >= 0 ? marked : plain)
      .push(m[1]);
  });
  log.debug('Leaving listed().');
  return { marked: marked.sort(), plain: plain.sort() };
}

function run(t) {
  log.debug('Entering run().');
  // ---- A. the marker -------------------------------------------------------
  const known = Object.keys(manifest.OPT_IN_SWITCHES);
  t.check(known.length === 1 && known[0] === '444' &&
          manifest.OPT_IN_SWITCHES['444'].env === 'STS_TEST_444' &&
          manifest.OPT_IN_SWITCHES['444'].defaultValue === 'off',
          'A1. MANIFEST.js names one switch, 444, read from STS_TEST_444 ' +
          'and off by default', JSON.stringify(manifest.OPT_IN_SWITCHES));
  const unknown = manifest.JOBS.filter(function (e) {
    return e.optIn !== undefined && known.indexOf(String(e.optIn)) < 0;
  }).map(function (e) { return e.file + '=' + e.optIn; });
  t.check(unknown.length === 0, 'A2. every optIn on a job is a known switch',
          unknown.join(', ') || 'none');
  const tagged = manifest.JOBS.filter(function (e) {
    return e.optIn === '444';
  }).map(function (e) { return e.file.replace(/\.js$/, ''); }).sort();
  t.check(tagged.length > 0, 'A3. the 444 set is not empty',
          String(tagged.length));
  t.check(manifest.JOBS.every(function (e) {
    return e.file !== 'sts_xacml_remote_pep.js' || !e.optIn;
  }), 'A4. the remote PEP\'s job is not behind the switch');
  const unitKeys = Object.keys(runner.UNIT_OPT_IN);
  t.check(unitKeys.every(function (k) { return known.indexOf(k) >= 0; }) &&
          Array.isArray(runner.UNIT_OPT_IN['444']),
          'A5. UNIT_OPT_IN exists and names only known switches',
          unitKeys.join(','));
  const jobNames = manifest.JOBS.map(function (e) {
    return e.file.replace(/\.js$/, '');
  });
  const badUnit = [];
  unitKeys.forEach(function (k) {
    runner.UNIT_OPT_IN[k].forEach(function (name) {
      if (!fs.existsSync(path.join(__dirname, name + '.js')) ||
          jobNames.indexOf(name) >= 0) {
        badUnit.push(k + ':' + name);
      }
    });
  });
  t.check(badUnit.length === 0,
          'A6. every in-process name behind a switch is an existing file ' +
          'here and no protocol job', badUnit.join(', ') || 'none');

  // ---- B. the switch's reading -------------------------------------------
  const unset = runner.optInSwitches({});
  t.check(!unset.problem && unset.state['444'].on === false &&
          unset.state['444'].value === 'off',
          'B1. unset is off', JSON.stringify(unset));
  t.check(runner.optInSwitches({ STS_TEST_444: 'on' }).state['444'].on,
          'B2. on is on');
  t.check(!runner.optInSwitches({ STS_TEST_444: 'off' }).state['444'].on,
          'B3. off is off');
  t.check(/STS_TEST_444 must be on or off/.test(
            runner.optInSwitches({ STS_TEST_444: 'yes' }).problem),
          'B4. any other value is refused');
  const off = runner.optInSwitches({});
  const on = runner.optInSwitches({ STS_TEST_444: 'on' });
  t.equal(runner.switchedOffWhy({ optIn: '444' }, off), REASON,
          'B5. a tagged job off gives the reason');
  t.equal(runner.switchedOffWhy({ optIn: '444' }, on), '',
          'B6. a tagged job on runs');
  t.equal(runner.switchedOffWhy({ optIn: '' }, off), '',
          'B7. an untagged job runs with the switch off');

  // ---- C. the selection, by the runner ----------------------------------
  const listOff = runner444(['--protocol=only', '--list']);
  const off1 = listed(listOff.text);
  t.check(listOff.code === 0 &&
          JSON.stringify(off1.marked) === JSON.stringify(tagged),
          'C1. off (unset) marks exactly the tagged set skipped',
          listOff.code + ' marked=' + off1.marked.length + ' tagged=' +
          tagged.length);
  t.check(off1.plain.length > 0 && off1.plain.every(function (n) {
    return tagged.indexOf(n) < 0;
  }), 'C2. and every other job is listed to run',
          String(off1.plain.length));
  const listOn = runner444(['--protocol=only', '--list'], 'on');
  const on1 = listed(listOn.text);
  t.check(listOn.code === 0 && on1.marked.length === 0 &&
          on1.plain.length === off1.plain.length + tagged.length,
          'C3. on marks none and lists every job to run',
          listOn.code + ' marked=' + on1.marked.length);
  const one = tagged[0];
  const mixed = runner444(['--protocol=only', '--list',
                           '--only=' + one + ',sts_dpop']);
  const mixed1 = listed(mixed.text);
  t.check(mixed1.marked.indexOf(one) >= 0 &&
          mixed1.plain.indexOf('sts_dpop') >= 0,
          'C4. --only naming a tagged and an untagged job: the tagged one ' +
          'marked skipped, the other to run', mixed.text.slice(0, 300));
  const typo = runner444(['--protocol=only', '--list'], 'yes');
  t.check(typo.code === 2 && /STS_TEST_444 must be on or off/.test(typo.text),
          'C5. a typo in STS_TEST_444 stops the runner', typo.code + '');

  // ---- D. --only of tagged jobs alone, off --------------------------------
  const loneDir = path.join(os.tmpdir(), 'suite-444-none-' + process.pid);
  const lone = runner444(['--protocol=only', '--only=' + one,
                          '--report-dir=' + loneDir]);
  t.check(lone.code === 1 && /switched off/.test(lone.text) &&
          /STS_TEST_444=on/.test(lone.text) && /--with-444/.test(lone.text) &&
          /Nothing was checked/.test(lone.text),
          'D1. --only of a tagged job while off fails, naming ' +
          'STS_TEST_444=on and --with-444', lone.code + ' ' + lone.text.slice(-400));
  t.check(!fs.existsSync(loneDir),
          'D2. and it wrote no report and started nothing');
  fs.rmSync(loneDir, { recursive: true, force: true });

  // ---- E. the reason in the summary and the JUnit -------------------------
  const result = runner.switchedOffResult({ suite: 'protocol', name: one,
                                            file: one + '.js' }, REASON);
  t.check(result.status === 'skipped' && result.why === REASON &&
          result.assertions.length === 0 && result.failures.length === 0,
          'E1. a switched-off job is a skip carrying the reason');
  t.equal(runner.skippedLine(result), 'SKIPPED: ' + one + ' — ' + REASON,
          'E2. the summary\'s SKIPPED line carries it');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'suite-444-'));
  try {
    runner.writeXml(dir, [result], { runId: 'x', wallMs: 0 });
    const xml = fs.readFileSync(path.join(dir, 'report.xml'), 'utf8');
    t.check(xml.indexOf('<skipped message="' + REASON + '"/>') >= 0,
            'E3. the JUnit has <skipped> with the reason', xml.slice(0, 400));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // A whole run, of a tagged job and one cheap in-process file: the tagged
  // job is skipped by runOne() with the reason, everywhere the report says
  // it, and the run passes on the file that did run. No service is started,
  // because no protocol job is left to run.
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'suite-444-run-'));
  try {
    const whole = runner444(['--only=' + one + ',upgrade_script_release',
                             '--report-dir=' + runDir, '--quiet']);
    const summary = JSON.parse(fs.readFileSync(
      path.join(runDir, 'latest', 'summary.json'), 'utf8'));
    const byName = {};
    summary.jobs.forEach(function (j) { byName[j.name] = j; });
    t.check(whole.code === 0 && byName[one] &&
            byName[one].status === 'skipped' && byName[one].why === REASON &&
            byName.upgrade_script_release &&
            byName.upgrade_script_release.status === 'passed',
            'E4. a run skips the tagged job with the reason and passes on ' +
            'the job that ran', whole.code + ' ' +
            JSON.stringify(summary.jobs));
    t.check(whole.text.indexOf('SKIPPED: ' + one + ' — ' + REASON) >= 0,
            'E5. the run\'s summary prints the SKIPPED line',
            whole.text.slice(-400));
    const xml = fs.readFileSync(path.join(runDir, 'latest', 'report.xml'),
                                'utf8');
    t.check(xml.indexOf('<skipped message="' + REASON + '"/>') >= 0,
            'E6. and its JUnit has the <skipped>');
  } catch (e) {
    log.debug('Caught in run(): ' + ((e && e.message) || e));
    t.bad('E4. a run with a tagged job wrote no readable report',
          (e && e.message) || String(e));
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
  }

  // ---- F. the plumbing, as source -----------------------------------------
  const launcher = read('run-tests.sh');
  t.check(/--with-444\)\s+STS_TEST_444=on ;;/.test(launcher) &&
          /STS_TEST_444="\$\{STS_TEST_444:-off\}"/.test(launcher),
          'F1. run-tests.sh: --with-444 sets it, and it defaults to off');
  t.check(/"STS_TEST_444=\$\{STS_TEST_444\}"/.test(launcher),
          'F2. run-tests.sh carries it in COMPOSE_ENV');
  t.check(/#444 jobs: OFF/.test(launcher) && /#444 jobs: ON/.test(launcher),
          'F3. --plan shows the switch');
  const compose = read('docker-compose-run-tests.yml');
  t.check(/- STS_TEST_444=\$\{STS_TEST_444:-off\}/.test(compose),
          'F4. the tests service is handed it, off by default');
  const workflow = read('.github/workflows/tests.yml');
  t.check(/with444:\s*\n\s*description:[^\n]*\n\s*type: boolean\s*\n\s*default: false/
            .test(workflow),
          'F5. tests.yml has a with444 boolean input, false by default');
  t.check(/^ {2}STS_TEST_444: \$\{\{ inputs\.with444 && 'on' \|\| 'off' \}\}$/m
            .test(workflow) && /-e STS_TEST_444 \\/.test(workflow),
          'F6. tests.yml sets STS_TEST_444 for every job and the unit ' +
          'job\'s container takes it');
  log.debug('Leaving run().');
}

module.exports = {
  name: 'suite_444_switch',
  describe: 'the jobs #444 created run only under STS_TEST_444=on, and ' +
            'are otherwise reported skipped with the reason',
  run: run
};
