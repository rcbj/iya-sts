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
  t.check(oneShots.length >= 2 && oneShots.every(function (name) {
    return runnerUp.indexOf('--no-attach ' + name) >= 0;
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
// ---------------------------------------------------------------------------
function checkTheJobTimeoutIsAboveOurs(t) {
  log.debug("Entering checkTheJobTimeoutIsAboveOurs().");
  t.log.info('=== the CI job\'s timeout is the backstop, not the mechanism ' +
             '===');
  const launcher = read('run-tests.sh');
  const workflow = read('.github/workflows/tests.yml');
  const modes = read('tests/tools/modes.sh');

  const modeBound = Number(
    /STS_MODE_TIMEOUT="\$\{STS_MODE_TIMEOUT:-(\d+)\}"/.exec(launcher)[1]);
  const teardownBound = Number(
    /STS_TEARDOWN_TIMEOUT="\$\{STS_TEARDOWN_TIMEOUT:-(\d+)\}"/
      .exec(launcher)[1]);

  // How many modes a full run does. Read from the file that defines them
  // rather than written down here, for the reason that file gives about
  // itself: a fourth mode must not leave this arithmetic quietly stale.
  const declared = /STS_ALL_MODES=\(([^)]*)\)/.exec(modes);
  const modeCount = declared
    ? declared[1].split(/\s+/).filter(function (w) { return w.trim(); }).length
    : 3;
  t.check(modeCount >= 1,
          'the mode list is readable from tests/tools/modes.sh (' +
            modeCount + ' mode(s))',
          'the budget below is per mode, so a fourth mode changes it and ' +
          'this file must not be the place that goes stale');

  // The `tests` job, which is the one that runs this launcher. The coverage
  // job runs ./run-coverage.sh, has a number of its own and is not this.
  const testsJob = workflow.slice(workflow.indexOf('\n  tests:'),
                                  workflow.indexOf('\n  coverage:'));
  const jobMinutes = Number(/timeout-minutes:\s*(\d+)/.exec(testsJob)[1]);

  // One wedged mode is the case worth surviving: the run reaches its bound,
  // says so, and the remaining modes still run. Every mode wedging is a
  // wedged machine, which is what the job timeout is for.
  const worstSeconds = modeBound + teardownBound * (modeCount + 1);
  t.check(jobMinutes * 60 > worstSeconds,
          'the job timeout (' + jobMinutes + 'm) is above one wedged mode ' +
            'plus every teardown (' + Math.ceil(worstSeconds / 60) + 'm)',
          'if the job\'s number is the smaller one then the bound that ' +
          'fires is the one that cannot explain itself, which is exactly ' +
          'the 2026-09-10 outcome with extra machinery in front of it');

  // And it must not be so large that a genuinely wedged runner is held for a
  // shift. The workflow's own header makes this argument about six hours.
  t.check(jobMinutes <= 120,
          'and it is still an outer bound rather than a licence (' +
            jobMinutes + 'm)',
          'without a number here a stuck job holds a runner for six hours, ' +
          'which is what the workflow header says this setting is for');

  // THE `cluster` JOB (2026-09-15) runs the same launcher for ONE mode, so the
  // same arithmetic holds with a count of one: its bound plus a teardown for
  // the mode and one for the stack before it. It is the last job in the file,
  // which is why its block runs to the end.
  const clusterAt = workflow.indexOf('\n  cluster:');
  t.check(clusterAt !== -1,
          'the workflow has a `cluster` job',
          'the fourth mode is in no bare run, so without that job nothing in ' +
          'CI runs two nodes behind a balancer at all');
  if (clusterAt !== -1) {
    const clusterJob = workflow.slice(clusterAt);
    t.check(/run-tests\.sh --modes=cluster\b/.test(clusterJob),
            'the `cluster` job runs ./run-tests.sh --modes=cluster',
            'a job of that name running anything else would leave the mode ' +
            'as unrun as having no job');
    const clusterMinutes = Number(
      (/timeout-minutes:\s*(\d+)/.exec(clusterJob) || [])[1]);
    const clusterWorst = modeBound + teardownBound * 2;
    t.check(clusterMinutes * 60 > clusterWorst,
            'the `cluster` job timeout (' + clusterMinutes + 'm) is above ' +
              'its one mode plus its teardowns (' +
              Math.ceil(clusterWorst / 60) + 'm)',
            'the tests job\'s argument for one mode: the bound that fires ' +
            'must be the one that can explain itself');
    t.check(clusterMinutes <= 120,
            'and the `cluster` job\'s is still an outer bound (' +
              clusterMinutes + 'm)',
            'the six-hour argument again, for the second job running this ' +
            'launcher');
  }
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
