'use strict';
//
// File: tests/unit_job_environment.js
//
// ===========================================================================
// A UNIT JOB DOES NOT INHERIT THE STACK'S DEPLOYMENT VARIABLES, AND THIS IS
// THE RECORD OF THE DAY IT DID.
//
// `tests/tools/modes.sh` defines the three modes the suite runs in as blocks
// of `NAME=value` lines, and both launchers EXPORT them — they have to, since
// that is how the compose stack and a host-mode service are handed the mode.
// The runner's unit jobs are children of that same shell, so they inherited
// them, which was harmless for exactly as long as no mode set a variable a
// MODULE reads.
//
// On 2026-09-12 `dispatch` mode started setting `STS_KEYS_SOURCE=persisted` —
// the point of that mode's third axis, the OpenBao container — and EIGHT unit
// jobs went red in a run where the same eight passed in the other two modes:
// `pki`, `pki_hierarchy`, `pki_revocation`, `spiffe_pki` and
// `tls_trust_anchor` at `keystore.start()`'s refusal (*key material is
// configured to persist … and no persistence store is open*, which is correct
// and is product mode's own rule), and `backup_codes`, `encryption_report`
// and `rfc7523_person_issuer` further in, at the seal.
//
// **NOT ONE OF THE EIGHT FAILURES WAS ABOUT THE SERVICE**, which is what makes
// this worth a file of its own: the unit half asserts module contracts in a
// process with no store, no listener and no container, and how the service
// under the PROTOCOL jobs was deployed is not its configuration.
//
// WHAT IS ASSERTED IS THE SEAM AND NOT THE SYMPTOM. A test that set
// `STS_KEYS_SOURCE` and watched `pki.js` refuse would be a test of the
// refusal, which `tests/keystore.js` already owns. What can break again is the
// LIST: a mode grows a fourth variable, the scrub does not know about it, and
// the next unit job to read it fails for a reason three files away. So the
// list is read from `modes.sh` here as well, by an expression written
// independently of the runner's, and the two have to agree.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const runner = require('./tools/run-report');

const ROOT = path.join(__dirname, '..');
const MODES_SH = path.join(__dirname, 'tools', 'modes.sh');
const RUN_REPORT = path.join(__dirname, 'tools', 'run-report.js');

// The heredoc lines of `stsModeEnv()`, read a second way: every `NAME=value`
// that is not the bash array at the top of the file, grouped by the mode whose
// block it is in. `case "$1" in` arms are what separate the blocks.
function modesFromTheShell() {
  const lines = fs.readFileSync(MODES_SH, 'utf8').split('\n');
  const byMode = {};
  let current = null;
  lines.forEach(function (line) {
    const arm = /^\s{4}(memory|postgres|dispatch)\)\s*$/.exec(line);
    if (arm) {
      current = arm[1];
      byMode[current] = [];
      return;
    }
    if (/^\s*;;\s*$/.test(line)) {
      current = null;
      return;
    }
    const set = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (current && set && set[2].charAt(0) !== '(') {
      byMode[current].push(set[1]);
    }
  });
  return byMode;
}

function run(t) {
  const byMode = modesFromTheShell();
  const modes = Object.keys(byMode);
  t.check(modes.length === 3,
          'modes.sh defines three modes, each as a block of NAME=value lines',
          modes.join(', '));

  // ---------------------------------------------------------------------
  // EVERY MODE NAMES EVERY VARIABLE, which is modes.sh's own stated rule and
  // was checked by nothing. A mode that leaves one out does not get "off" —
  // it gets whatever the previous mode in the same shell exported, or what
  // docker-compose.yml decides, and the run reports that a mode passed which
  // never ran in the configuration it names.
  // ---------------------------------------------------------------------
  const union = [];
  modes.forEach(function (mode) {
    byMode[mode].forEach(function (name) {
      if (union.indexOf(name) < 0) {
        union.push(name);
      }
    });
  });
  modes.forEach(function (mode) {
    const missing = union.filter(function (name) {
      return byMode[mode].indexOf(name) < 0;
    });
    t.check(missing.length === 0,
            'and ' + mode + ' names every variable any mode names — an ' +
            'unnamed one is inherited rather than off',
            missing.join(', ') || 'none missing');
  });

  // ---------------------------------------------------------------------
  // THE RUNNER READS THE SAME FILE AND HAS TO SEE THE SAME NAMES.
  // ---------------------------------------------------------------------
  const scrubbed = runner.stackDeploymentVariables();
  const notScrubbed = union.filter(function (name) {
    return scrubbed.indexOf(name) < 0;
  });
  t.check(notScrubbed.length === 0,
          'the runner takes every one of them off a unit job\'s environment',
          notScrubbed.join(', ') || union.join(', '));
  t.check(scrubbed.indexOf('STS_KEYS_SOURCE') >= 0,
          'including STS_KEYS_SOURCE, which is the one that cost eight jobs — ' +
          'a keystore turned on in a process that has no store to open');
  t.check(scrubbed.indexOf('STS_ALL_MODES') < 0,
          'and not STS_ALL_MODES, which is a bash array of the mode names and ' +
          'was never an environment variable at all');

  // ---------------------------------------------------------------------
  // AND THE UNIT BRANCH ACTUALLY DELETES THEM. Source-coupled on purpose:
  // the list being right is worth nothing if nothing applies it, and the
  // apply is three lines in a branch this file cannot call without running a
  // whole report.
  // ---------------------------------------------------------------------
  const source = fs.readFileSync(RUN_REPORT, 'utf8');
  const unitBranch = /job\.suite === 'unit'\)\s*\{([\s\S]*?)\n    \} else \{/
    .exec(source);
  t.check(!!unitBranch, 'run-report.js still has a unit branch to scrub in');
  if (unitBranch) {
    t.check(/STACK_ENV\.forEach\([\s\S]*?delete job\.env\[/.test(unitBranch[1]),
            'and it deletes every STACK_ENV name from the job\'s environment');
  }

  // ---------------------------------------------------------------------
  // THE UNIT HALF OWNS ITS OWN CONFIGURATION, which is what makes the scrub
  // safe rather than merely correct: every unit file that needs one of these
  // sets it itself. Asserted as a property of the files rather than trusted —
  // a file that READ one without setting it would be a file the scrub has
  // just changed the behaviour of.
  // ---------------------------------------------------------------------
  const offenders = [];
  fs.readdirSync(__dirname).filter(function (f) {
    return /\.js$/.test(f) && f !== 'run.js' && f !== path.basename(__filename);
  }).forEach(function (f) {
    const text = fs.readFileSync(path.join(__dirname, f), 'utf8');
    scrubbed.forEach(function (name) {
      const reads = new RegExp('process\\.env\\.' + name + '(?!\\s*=)');
      const writes = new RegExp('process\\.env\\.' + name + '\\s*=|' +
                                'delete process\\.env\\.' + name);
      if (reads.test(text) && !writes.test(text)) {
        offenders.push(f + ' reads ' + name);
      }
    });
  });
  t.check(offenders.length === 0,
          'and no unit file reads one of them without setting it first',
          offenders.join('; ') || 'none');

  t.check(fs.existsSync(path.join(ROOT, 'tests', 'tools', 'modes.sh')),
          'modes.sh is still the one place the modes are defined');
}

module.exports = {
  name: 'unit_job_environment',
  describe: 'a unit job runs in a process with no store, so it does not ' +
            'inherit the variables that say how the service stack was deployed',
  run: run
};
