// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: teardown_bounds.js
//
// ===========================================================================
// A STACK THAT WILL NOT COME DOWN IS NOT A VERDICT ON THE TREE.
//
// On 2026-09-10 CI's `tests` job was reported as a FAILURE for a tree that had
// nothing wrong with it. All three modes ran, the last of them finished `78
// job(s), 78 passed, 0 failed, 0 skipped, 1441 assertion(s)`, the report was
// written and the runner container exited 0 — and then `up
// --abort-on-container-exit`, which stops the rest of the stack once the
// runner is done, printed
//
//     Container sts-postgres-docker-tests  Stopping
//
// and sat there for TWENTY-THREE MINUTES, until the job hit its 45-minute wall
// clock and the whole run was cancelled: no summary, no exit code, and the
// report artifact uploaded by a step that only ran because it was
// `if: always()`. Modes one and two had stopped that same container in 0.17s
// and 0.48s; the run the day before stopped it three times out of three.
//
// **NOTHING IN THIS REPOSITORY COULD HAVE PREVENTED THE HANG AND THAT IS NOT
// WHAT THIS FILE IS ABOUT.** compose already asks with the container's stop
// signal, already waits ten seconds, and already follows with SIGKILL — the
// `xacml-pep` container spends all ten of those on every single run and dies
// on the kill. A stop that outlives SIGKILL is a wedged daemon or a process
// the kernel will not interrupt. What this repository decides is what happens
// NEXT, and until that day the answer was "wait forever, then lose the run".
//
// ---------------------------------------------------------------------------
// THE THREE CLAIMS, AND WHY THE MIDDLE ONE IS THE LOAD-BEARING ONE.
//
//   1. every teardown has a wall clock on it,
//   2. a bound that is REACHED is not turned into a test failure — the mode's
//      real verdict is recovered from the runner container, which has already
//      exited and which docker has already recorded the exit code of,
//   3. and the CI job's own timeout stays comfortably above the sum of ours,
//      so the bound that fires first is always the one that can explain
//      itself.
//
// Without (2) the bound would be a NEW way to throw a green suite away —
// arriving sooner than the CI timeout did, and just as wrong. It is the whole
// reason `up --abort-on-container-exit --exit-code-from tests` can be bounded
// at all: that one call does two separable things, the suite and then the
// stop, and only the first of them decides anything. By the time the second
// can hang, the answer exists on a stopped container.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Every claim here is a comparison between FILES — the two launchers, the
// compose helper they share and the workflow that runs one of them — which no
// running service could be asked. It is `admin_api_token_wiring.js`'s shape
// exactly, and for the same reason: a launcher is not something a job can
// look at, so the only run that would have caught this is the one that had
// already lost.
// ===========================================================================

const fs = require('fs');
const path = require('path');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'teardown_bounds',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// How a launcher names its compose files on one call: the array every call in
// ./run-tests.sh has used since the `cluster` mode layered a second
// file (2026-09-14), or the single `-f` it used before.
const FILES = '(?:"\\$\\{COMPOSE_FILE_ARGS\\[@\\]\\}"|-f "\\$\\{COMPOSE_FILE\\}")';

function read(rel) {
  log.debug("Entering read().");
  log.debug("Leaving read().");
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

// ---------------------------------------------------------------------------
// THE HELPER BOTH LAUNCHERS SHARE. It is in tests/tools/compose.sh for the
// reason resolveCompose() and docker_compose() are: two launchers needing one
// answer, and two copies of a timeout is two places for the timeout to differ
// — which is the argument waitForStsHealthy() already makes about itself.
// ---------------------------------------------------------------------------
function checkTheBoundedHelperExists(t) {
  log.debug("Entering checkTheBoundedHelperExists().");
  t.log.info('=== one bounded compose call, shared by both launchers ===');
  const helper = read('tests/tools/compose.sh');

  t.check(/docker_compose_bounded\s*\(\)/.test(helper),
          'tests/tools/compose.sh defines docker_compose_bounded()',
          'both launchers reach docker through this file; a bound written ' +
          'into one of them would leave the other with the behaviour that ' +
          'lost the 2026-09-10 run');

  t.check(/--kill-after/.test(helper),
          'and it follows the ask with a deadline of its own',
          'SIGTERM asks compose to stop the stack, which is the very thing ' +
          'that is stuck — so a bound with no --kill-after is a bound that ' +
          'hands the hang straight back');

  // `timeout NAME=value cmd` asks the kernel to execute a program called
  // `NAME=value`. That is the trap compose.sh's `docker_compose()` avoids by
  // putting `env` in front of those words, one layer along, and it is how
  // every mode of this launcher failed on its first run.
  t.check(/timeoutCmd\}"?\s+--kill-after=30s\s+"\$\{seconds\}"\s*\\?\s*\n?\s*env\s/
    .test(helper) ||
          /--kill-after=30s "\$\{seconds\}" \\\n\s*env /.test(helper),
          'the compose variables go through `env` and not as bare words',
          'a NAME=value word after `timeout` is a program name to the ' +
          'kernel, so this is the difference between a bounded compose call ' +
          'and no compose call at all');

  // `timeout` makes compose a BACKGROUND job on a terminal (2026-09-14): its
  // shortcut menu reads the keyboard, the kernel stops it with SIGTTIN, and
  // `up` sits after `Created` with no output until the bound kills the mode.
  // Both bounded calls must keep it off the terminal. Asserted per call — the
  // sudo one and the plain one — because a fix made to one of two copies is
  // the shape this file exists to catch.
  const boundedCalls = helper.split('--kill-after=30s').slice(1)
    .map(function (rest) { return rest.split('return $?')[0]; });
  t.check(boundedCalls.length === 2 && boundedCalls.every(function (call) {
    return /COMPOSE_MENU=false/.test(call) && /<\s*\/dev\/null/.test(call);
  }),
          'every bounded compose call has COMPOSE_MENU=false and stdin from ' +
          '/dev/null',
          'without them `run-tests.sh` run from a terminal stops ' +
          'compose `up` after `Created` and prints nothing until the mode ' +
          'timeout; found ' + boundedCalls.length + ' bounded call(s)');

  // A machine without coreutils `timeout` must behave exactly as it did
  // before this existed. A bound is a safety net, never a requirement.
  t.check(/command -v timeout/.test(helper) &&
          /docker_compose "\$@"/.test(helper),
          'and a machine with no `timeout` degrades to the unbounded call',
          'this is a net under a launcher, not a new dependency for one');
  log.debug("Leaving checkTheBoundedHelperExists().");
}

// ---------------------------------------------------------------------------
// EVERY PLACE THE CONTAINERIZED LAUNCHER WAITS ON DOCKER AFTER THE SUITE HAS
// SPOKEN. There are five: the pre-run cleanup, the mode's `up`, the two `logs`
// calls that collect the container logs, the between-modes `down` and the EXIT
// trap. The last of those is the one the incident actually reached.
// ---------------------------------------------------------------------------
function checkTheLauncherIsBounded(t) {
  log.debug("Entering checkTheLauncherIsBounded().");
  t.log.info('=== run-tests.sh bounds every wait on docker ===');
  const launcher = read('run-tests.sh');

  t.check(/STS_MODE_TIMEOUT="\$\{STS_MODE_TIMEOUT:-\d+\}"/.test(launcher) &&
          /STS_TEARDOWN_TIMEOUT="\$\{STS_TEARDOWN_TIMEOUT:-\d+\}"/
            .test(launcher),
          'both bounds have a default and both are overridable',
          'a machine slower than any CI runner is a machine somebody will ' +
          'run this on, and a bound with no way past it is a bound that ' +
          'fails a run for being slow');

  // The mode's `up` — the suite itself, and the call that hung.
  //
  // THE FILES ARE `"${COMPOSE_FILE_ARGS[@]}"` SINCE 2026-09-14, when the
  // `cluster` mode began layering a second file over the first; `FILES`
  // accepts that and the older `-f "${COMPOSE_FILE}"`, so the three checks
  // below go on matching the calls they were written about rather than
  // passing because nothing is spelt the old way any more.
  t.check(new RegExp('docker_compose_bounded "\\$\\{STS_MODE_TIMEOUT\\}" ' +
                     FILES + ' up').test(launcher),
          'the mode\'s `up` runs under STS_MODE_TIMEOUT',
          'that single call runs the suite AND stops the stack afterwards, ' +
          'and it is the second half that wedged');

  // THE ONE-SHOT SERVICES ARE NOT ATTACHED TO IT (2026-09-14). Every service
  // the compose file marks `restart: "no"` exits 0 by design, that `up`
  // starts it again, and `--abort-on-container-exit` stops the stack on any
  // ATTACHED container's exit — so each mode stopped `sts` seconds in and the
  // runner never ran. Read off the compose file rather than listed here, so a
  // third one-shot service added there is a failure here until it is added.
  const composeFile = read('docker-compose-run-tests.yml');
  const oneShots = composeFile.split(/\n(?=  [a-z][a-z0-9-]*:\n)/)
    .filter(function (block) { return /\n    restart: "no"/.test(block); })
    .map(function (block) { return block.match(/^\s*([a-z][a-z0-9-]*):/)[1]; });
  // `FILES` for the reason the check above uses it: this check arrived from
  // develop spelling the files `-f "${COMPOSE_FILE}"`, and the cluster mode's
  // `"${COMPOSE_FILE_ARGS[@]}"` made it match nothing and fail for a launcher
  // that does exactly what it asks.
  const runnerUp = (launcher.match(new RegExp(
    'docker_compose_bounded "\\$\\{STS_MODE_TIMEOUT\\}" ' + FILES +
    ' up[\\s\\S]*?--exit-code-from tests')) || [''])[0];
  // The list is the `UP_NO_ATTACH` array since #176, which the conformance
  // suite's modes add their three to; the `up` must expand it, and the
  // array's first assignment — every mode's — must name each one-shot.
  const noAttach = runnerUp.indexOf('"${UP_NO_ATTACH[@]}"') >= 0
    ? ((launcher.match(/\n\s*UP_NO_ATTACH=\(([^)]*)\)/) || ['', ''])[1])
    : runnerUp;
  // A one-shot service under a compose PROFILE (#187's `conformance-tls`)
  // exists only in the modes that activate the profile, so it is named in
  // the `UP_NO_ATTACH+=(...)` those modes add rather than in every mode's
  // list — `--no-attach` of a service the project does not have is an
  // error, not a no-op.
  const profiled = composeFile.split(/\n(?=  [a-z][a-z0-9-]*:\n)/)
    .filter(function (block) { return /\n    profiles: /.test(block); })
    .map(function (block) { return block.match(/^\s*([a-z][a-z0-9-]*):/)[1]; });
  const added = (launcher.match(/\n\s*UP_NO_ATTACH\+=\(([^)]*)\)/g) || [])
    .join(' ');
  t.check(oneShots.length >= 2 && oneShots.every(function (name) {
    return noAttach.indexOf('--no-attach ' + name) >= 0 ||
      (profiled.indexOf(name) >= 0 &&
       added.indexOf('--no-attach ' + name) >= 0);
  }),
          'the mode\'s `up` does not attach the one-shot services (' +
          oneShots.join(', ') + ')',
          'an attached one-shot container finishing is an exit ' +
          '`--abort-on-container-exit` stops the whole stack for, before the ' +
          'runner starts');

  // AND A MODE WITH NO REPORT IS NOT GREEN, whatever compose returned.
  t.check(/! modeWroteReport "\$\{MODE\}"/.test(launcher) &&
          /MODE_RC=1/.test(launcher.split('! modeWroteReport')[1] || ''),
          'a mode whose runner wrote no report is failed',
          'the stack stopping before the runner started can come back as 0, ' +
          'and a green mode that ran no job is the verdict this launcher ' +
          'must never give');

  // NO unbounded `down` may remain. This is the check that a later edit
  // trips: adding a teardown is easy and adding a bounded one is a decision.
  const unbounded = launcher.split('\n').filter(function (line) {
    return new RegExp('docker_compose\\s+' + FILES + ' down').test(line);
  });
  t.check(unbounded.length === 0,
          'no unbounded `down` is left in the launcher',
          'there are three of them — the pre-run cleanup, the one between ' +
          'modes and the EXIT trap — and the trap is the one that held the ' +
          'run open after everything it was asked to do had finished; found: ' +
          unbounded.join(' | '));

  // The container logs are collected from a stack that has just been stopped,
  // which is precisely the stack whose stop may not have gone well.
  t.check(!new RegExp('docker_compose\\s+' + FILES + ' logs').test(launcher),
          'and the log capture is bounded too',
          'it runs against the stopped stack, so the case worth having a ' +
          'log for is the case where this call is the one that hangs');

  // There was a second launcher here, ./local-run-tests.sh, with the same
  // three `down` calls and its own bound. It was removed on 2026-09-16 (#50):
  // ./run-tests.sh is the one way the whole suite runs.
  log.debug("Leaving checkTheLauncherIsBounded().");
}

// ---------------------------------------------------------------------------
// THE RECOVERY. This is claim (2), and it is what makes the bound above safe
// to add at all.
// ---------------------------------------------------------------------------
function checkTheVerdictIsRecovered(t) {
  log.debug("Entering checkTheVerdictIsRecovered().");
  t.log.info('=== a reached bound asks docker what the runner did ===');
  const launcher = read('run-tests.sh');

  t.check(/recoverModeVerdict\s*\(\)/.test(launcher),
          'the launcher has a recoverModeVerdict()',
          'without it a bound is a faster way to lose a green suite than ' +
          'the CI timeout was');

  // 124 is `timeout`'s own code; 137 is what a container killed on the way
  // out reports. Anything below is a real answer from the suite.
  t.check(/MODE_RC\}" -ge 124/.test(launcher) &&
          /MODE_RC="\$\(recoverModeVerdict/.test(launcher),
          'and it is consulted exactly when the bound was reached',
          'a suite that answered is never second-guessed; 124 is timeout\'s ' +
          'own code and 137 is a container killed on the way out');

  // The two cases, told apart by ASKING rather than by assuming either one.
  t.check(/State\.Status/.test(launcher) && /State\.ExitCode/.test(launcher),
          'it reads the runner container\'s status AND its exit code',
          'a runner still running means the SUITE did not finish, which is ' +
          'a failure of the mode; a runner that has exited means the stop ' +
          'phase hung and its code is the verdict --exit-code-from would ' +
          'have reported');

  // `docker inspect` and not `compose ps`: this has to answer while compose
  // is the thing that is stuck.
  t.check(/docker inspect -f '\{\{\.State\.Status\}\}' \\\n\s*"\$\{STS_TESTS_CONTAINER_NAME\}"/
    .test(launcher),
          'it asks docker directly, by the container name this file pins',
          'compose is the process that has wedged, so asking compose is ' +
          'asking the patient to take its own pulse — and the name is ' +
          'already pinned here for the healthcheck loop');

  // A verdict nobody can read is not a pass. Both unreadable cases keep the
  // bound's own code rather than falling through to 0.
  t.check(/''\|\*\[!0-9\]\*\)/.test(launcher),
          'and an unreadable exit code is a failure, not a pass',
          'the whole point is to recover an answer that EXISTS; inventing ' +
          'one when it does not is the opposite of that');

  // ------------------------------------------------------------------------
  // AND THE BRANCH THE FIRST VERSION OF THIS DID NOT HAVE, WHICH A REAL RUN
  // FOUND (2026-09-10, STS_MODE_TIMEOUT=100 against the memory mode).
  //
  // Reaching the bound SIGTERMs compose, and compose answers a SIGTERM by
  // stopping the stack — so a suite that was STILL GOING is a container that
  // has exited by the time the recovery looks, killed 137 by a teardown this
  // launcher caused. Read as a verdict, that mode fails for the wrong reason
  // and the launcher announces "THE SUITE FINISHED" about a run four minutes
  // from finishing. It is the one case where the recovery can be confidently,
  // articulately wrong, which is worse than the bound it was added to fix.
  // ------------------------------------------------------------------------
  t.check(/code\}" -ge 128/.test(launcher),
          'a signalled runner (128+N) is not read as a verdict',
          'the stop that the bound triggers is what kills it, so its code is ' +
          'this launcher\'s own doing rather than the suite\'s answer — and ' +
          'reporting it as the answer makes the recovery lie in exactly the ' +
          'case it cannot otherwise be checked in');
  log.debug("Leaving checkTheVerdictIsRecovered().");
}

// ---------------------------------------------------------------------------
// THE OUTER BOUND, WHICH MUST NEVER BE THE ONE THAT FIRES.
//
// GitHub's job timeout cancels: no summary, no exit code, no report upload
// except the one that was written `if: always()`. This launcher's own bounds
// explain themselves, capture the logs, keep the report and give the mode a
// verdict. So the job's number has to sit above the sum of ours with room —
// otherwise the useful bound never gets to run.
//
// THE JOB GRAPH THIS READS IS 2026-11-14's (tests.yml's header): a `build`
// job builds every image once, a `unit` job runs the in-process half once,
// a `mode` matrix runs the protocol half one mode per runner with
// --no-build, and the two conformance jobs load the same images. Until then
// a `tests` job ran two whole modes and built its own images, and this file
// sliced it out by name; the arithmetic is the same, per job.
// ---------------------------------------------------------------------------

// One job of the workflow, from its `  name:` line to the next job's. A job
// that is not there is the empty string, which every check below reads as
// a failure rather than as nothing to check.
function jobBlock(workflow, name) {
  log.debug("Entering jobBlock().");
  const at = workflow.indexOf('\n  ' + name + ':\n');
  if (at === -1) {
    log.debug("Leaving jobBlock(). No such job.");
    return '';
  }
  const rest = workflow.slice(at + 1);
  const next = rest.slice(1).search(/\n  [a-z][a-z0-9-]*:\n/);
  log.debug("Leaving jobBlock().");
  return next === -1 ? rest : rest.slice(0, next + 1);
}

// Whether a mode is in a comma list in modes.sh's spelling, as the
// launcher's `printf ',%s,' | grep` asks it.
function inModeList(list, mode) {
  log.debug("Entering inModeList().");
  log.debug("Leaving inModeList().");
  return (',' + list + ',').indexOf(',' + mode + ',') >= 0;
}

function checkTheJobTimeoutIsAboveOurs(t) {
  log.debug("Entering checkTheJobTimeoutIsAboveOurs().");
  t.log.info('=== the CI job\'s timeout is the backstop, not the mechanism ' +
             '===');
  const launcher = read('run-tests.sh');
  const workflow = read('.github/workflows/tests.yml');
  const modes = read('tests/tools/modes.sh');

  const sharedBound = Number(
    /STS_MODE_TIMEOUT="\$\{STS_MODE_TIMEOUT:-(\d+)\}"/.exec(launcher)[1]);
  // A mode that runs the OpenID conformance suite (#176, `memory` by
  // default) has STS_CONFORMANCE_TIMEOUT added to its bound by the launcher.
  const conformanceBound = Number(
    (/STS_CONFORMANCE_TIMEOUT="\$\{STS_CONFORMANCE_TIMEOUT:-(\d+)\}"/
      .exec(launcher) || [])[1]) || 0;
  // And one that brings up the SAML interoperability peers (#189-#192,
  // `memory` and `single-node` by default) has STS_SAML_PEERS_TIMEOUT added.
  const peersBound = Number(
    (/STS_SAML_PEERS_TIMEOUT="\$\{STS_SAML_PEERS_TIMEOUT:-(\d+)\}"/
      .exec(launcher) || [])[1]) || 0;
  const peersModes = (/STS_TEST_SAML_PEERS_MODES="\$\{STS_TEST_SAML_PEERS_MODES-([^}]*)\}"/
    .exec(launcher) || ['', ''])[1];
  const teardownBound = Number(
    /STS_TEARDOWN_TIMEOUT="\$\{STS_TEARDOWN_TIMEOUT:-(\d+)\}"/
      .exec(launcher)[1]);
  // THE IMAGE BUILD, WHICH NO MODE BOUND COVERS (2026-09-27). A runner with
  // no layer cache took nineteen minutes for it, then 20-29; the `cluster`
  // job's 115 minutes were above its mode's bound plus teardowns and were
  // still spent before the mode's own bound could fire. Since 2026-11-14 it
  // is the `build` job's alone, and the jobs that --no-build pay instead for
  // the artifact's download and `docker load`, measured at three to five
  // minutes for three to four gigabytes and allowed ten.
  const buildAllowance = 1800;
  const loadAllowance = 600;

  // The modes a full run does, read from the file that defines them rather
  // than written down here, for the reason that file gives about itself: a
  // fourth mode must not leave this arithmetic quietly stale.
  const declared = /STS_ALL_MODES=\(([^)]*)\)/.exec(modes);
  const allModes = declared
    ? declared[1].split(/\s+/).filter(function (w) { return w.trim(); })
    : [];
  t.check(allModes.length >= 1,
          'the mode list is readable from tests/tools/modes.sh (' +
            allModes.join(', ') + ')',
          'the matrix below must cover it, so this file must not be the ' +
          'place that goes stale');
  // Each mode's own bound in modes.sh, the launcher's shared one otherwise.
  function defaultBoundOf(mode) {
    log.debug("Entering defaultBoundOf().");
    const own = new RegExp('\\n\\s*' + mode.replace(/-/g, '\\-') +
      '\\)\\s*echo "\\$\\{([A-Z_]+):-(\\d+)\\}"').exec(modes);
    log.debug("Leaving defaultBoundOf().");
    return own ? { variable: own[1], seconds: Number(own[2]) }
               : { variable: 'STS_MODE_TIMEOUT', seconds: sharedBound };
  }

  // ---- THE BUILD, ONCE -------------------------------------------------
  const buildJob = jobBlock(workflow, 'build');
  const buildMinutes = Number(
    (/timeout-minutes:\s*(\d+)/.exec(buildJob) || [])[1]);
  t.check(/\.\/run-tests\.sh --build-only\b/.test(buildJob) &&
          /stack-images\.sh save\b/.test(buildJob) &&
          /actions\/upload-artifact@/.test(buildJob),
          'a `build` job builds every image with ./run-tests.sh ' +
          '--build-only and saves them as an artifact',
          'every other job runs --no-build, so without it they would run ' +
          'against images nobody built');
  t.check(buildMinutes * 60 > buildAllowance && buildMinutes <= 90,
          'the `build` job\'s timeout (' + buildMinutes + 'm) is above the ' +
            'cold build (' + buildAllowance / 60 + 'm) and still an outer ' +
            'bound',
          'a cold runner took 20-29 minutes to build, before the save and ' +
          'the upload');

  // ---- NO OTHER JOB BUILDS ---------------------------------------------
  // Every job that runs the launcher but `build` loads the artifact. A job
  // that built again would be a second build's disk on a runner that ran
  // out of it, and a second chance at the network flakes the build met.
  const launcherCalls = workflow.split('\n').filter(function (line) {
    return /\.\/run-(tests|coverage)\.sh\b/.test(line) &&
      !/^\s*#/.test(line);
  });
  const building = launcherCalls.filter(function (line) {
    return !/--no-build\b/.test(line) && !/--build-only\b/.test(line);
  });
  t.check(launcherCalls.length > 0 && building.length === 0,
          'every launcher call but the `build` job\'s passes --no-build',
          'found: ' + building.join(' | '));

  // ---- THE IN-PROCESS HALF, ONCE ---------------------------------------
  // The mode jobs run --protocol=only, so the tests/*.js files run here or
  // nowhere.
  const unitJob = jobBlock(workflow, 'unit');
  const unitMinutes = Number(
    (/timeout-minutes:\s*(\d+)/.exec(unitJob) || [])[1]);
  t.check(/run-report\.js --no-protocol\b/.test(unitJob) &&
          /--unit-concurrency=\d+/.test(unitJob),
          'a `unit` job runs the in-process half, with a concurrency of its ' +
          'own',
          'run-report.js defaults to a quarter of the CPUs, which is one ' +
          'file at a time on a 4-vCPU runner and was the long pole of every ' +
          'mode until 2026-11-14');
  t.check(unitMinutes > 0 && unitMinutes <= 240,
          'the `unit` job\'s timeout (' + unitMinutes + 'm) is an outer ' +
            'bound',
          'without a number a stuck job holds a runner for six hours');

  // ---- THE PROTOCOL HALF, ONE MODE PER RUNNER --------------------------
  const modeJob = jobBlock(workflow, 'mode');
  t.check(/timeout-minutes:\s*\$\{\{\s*matrix\.minutes\s*\}\}/
            .test(modeJob) &&
          /fail-fast:\s*false/.test(modeJob) &&
          /\.\/run-tests\.sh --no-build --modes=\$\{\{ matrix\.mode \}\} --protocol=only/
            .test(modeJob),
          'the `mode` matrix runs ./run-tests.sh --no-build ' +
          '--modes=<mode> --protocol=only, each with its own timeout, ' +
          'fail-fast off',
          'one mode per runner is what fits a runner, and one mode\'s ' +
          'failure says nothing about another\'s');
  // The bound reaches the launcher through every variable a mode reads; a
  // missing one leaves that mode on its default, which is above its job.
  const boundVariables = ['STS_MODE_TIMEOUT'].concat(allModes.map(
    function (mode) { return defaultBoundOf(mode).variable; }))
    .filter(function (v, i, all) { return all.indexOf(v) === i; });
  const unwired = boundVariables.filter(function (v) {
    return !new RegExp('\\n\\s*' + v + ':\\s*\\$\\{\\{\\s*matrix\\.bound' +
                       '\\s*\\}\\}').test(modeJob);
  });
  t.check(unwired.length === 0,
          'the matrix hands its bound to the launcher (' +
            boundVariables.join(', ') + ')',
          'not handed: ' + unwired.join(', '));
  const modeRunsConformance =
    !/STS_TEST_CONFORMANCE_MODES:\s*""/.test(modeJob);
  const modePeers = /STS_TEST_SAML_PEERS_MODES:\s*""/.test(modeJob)
    ? '' : peersModes;
  const entries = [];
  const entryRe = /-\s*mode:\s*([a-z-]+)\s*\n\s*minutes:\s*(\d+)\s*\n\s*bound:\s*(\d+)/g;
  let m;
  while ((m = entryRe.exec(modeJob)) !== null) {
    entries.push({ mode: m[1], minutes: Number(m[2]),
                   bound: Number(m[3]) });
  }
  const covered = entries.map(function (e) { return e.mode; });
  t.check(allModes.length > 0 && allModes.every(function (mode) {
    return covered.indexOf(mode) >= 0;
  }),
          'the matrix runs every mode of STS_ALL_MODES (' +
            covered.join(', ') + ')',
          'a mode the matrix leaves out is a mode CI never runs; a cluster ' +
          'defect would be found by nobody');
  entries.forEach(function (entry) {
    const modeBound = entry.bound +
      (inModeList(modePeers, entry.mode) ? peersBound : 0) +
      (modeRunsConformance ? conformanceBound : 0);
    const worst = loadAllowance + modeBound + teardownBound * 2;
    // At most 330 minutes, half an hour inside GitHub's six (2026-11-14):
    // `fuzz` measured 126-155 minutes on the development laptop and the
    // protocol half runs about 1.5 times slower on a hosted runner.
    t.check(entry.minutes * 60 > worst && entry.minutes <= 330,
            'the `' + entry.mode + '` job timeout (' + entry.minutes +
              'm) is above loading the images, its mode\'s bound and two ' +
              'teardowns (' + Math.ceil(worst / 60) + 'm), and at most 330m',
            'if the job\'s number is the smaller one then the bound that ' +
            'fires is the one that cannot explain itself, which is exactly ' +
            'the 2026-09-10 outcome with extra machinery in front of it');
  });

  // ---- THE CONFORMANCE PLANS -------------------------------------------
  // The mode jobs empty STS_TEST_CONFORMANCE_MODES (#187), so the plans run
  // in these two jobs or nowhere. SINCE #930 THEY ARE SPLIT BY LANE:
  // `openid-conformance` runs every lane but the OpenID Provider job's and
  // `openid-conformance-oidcc` that lane alone, so the browser jobs could
  // join without either outgrowing six hours.
  [{ name: 'openid-conformance', lanes: /--not-lanes=conformance\b/ },
   { name: 'openid-conformance-oidcc', lanes: /--lanes=conformance\b/ }]
    .forEach(function (job) {
      const text = jobBlock(workflow, job.name);
      t.check(modeRunsConformance || text !== '',
              'the workflow has an `' + job.name + '` job',
              'the mode jobs leave the plans out, so without it its lanes ' +
              'run nowhere');
      if (!text) {
        return;
      }
      const minutes = Number(
        (/timeout-minutes:\s*(\d+)/.exec(text) || [])[1]);
      // The SAML peers' bound too, unless the job empties their modes.
      const peers = /STS_TEST_SAML_PEERS_MODES:\s*""/.test(text) ? 0
                                                               : peersBound;
      const worst = loadAllowance + sharedBound + conformanceBound + peers +
        teardownBound * 2;
      t.check(/--modes=memory\b/.test(text) &&
              /--conformance-only\b/.test(text) &&
              job.lanes.test(text) &&
              !/--no-browser\b/.test(text),
              'the `' + job.name + '` job runs the memory mode\'s ' +
              'conformance jobs of its lanes, by the manifest flag, with ' +
              'the browser jobs',
              'the launcher runs the suite only in the modes ' +
              'STS_TEST_CONFORMANCE_MODES names, `memory` by default; the ' +
              'two jobs split the lanes; and rcbj asked for the ' +
              'Chrome-driven conformance jobs in CI (#930)');
      t.check(minutes * 60 > worst && minutes <= 360,
              'the `' + job.name + '` job timeout (' + minutes +
                'm) is above loading the images, its mode\'s bound and two ' +
                'teardowns (' + Math.ceil(worst / 60) + 'm) and within six ' +
                'hours',
              'the launcher\'s bound must be the one that fires, and ' +
              'GitHub cancels any job at six hours whatever it says');
    });

  // ---- CI PUBLISHES NOTHING (rcbj's hold, 2026-11-14) ------------------
  // tests.yml pushed what a run built to ghcr.io until that day, four of the
  // packages public. Only the `mirror` job may write a package, and it
  // writes the private mirror.
  const writers = workflow.split(/\n(?=  [a-z][a-z0-9-]*:\n)/)
    .filter(function (block) {
      return /\n[ \t]+packages:[ \t]*write/.test(block);
    })
    .map(function (block) {
      return (block.match(/^\s*([a-z][a-z0-9-]*):/) || ['', '?'])[1];
    });
  t.check(writers.length === 1 && writers[0] === 'mirror' &&
          !/\bdocker push\b|push-stack-images/.test(workflow),
          'nothing in tests.yml pushes an image, and only `mirror` may ' +
          'write a package',
          'packages: write in: ' + writers.join(', '));
  log.debug("Leaving checkTheJobTimeoutIsAboveOurs().");
}

function run(t) {
  log.debug("Entering run().");
  checkTheBoundedHelperExists(t);
  checkTheLauncherIsBounded(t);
  checkTheVerdictIsRecovered(t);
  checkTheJobTimeoutIsAboveOurs(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'teardown_bounds',
  describe: 'that a stack which will not come down costs a warning rather ' +
            'than the verdict of a suite that has already finished',
  run: run
};
