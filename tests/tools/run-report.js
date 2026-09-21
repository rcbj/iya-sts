#!/usr/bin/env node
'use strict';
//
// File: tests/tools/run-report.js
//
// ===========================================================================
// THE REPORT GENERATOR. `./run-tests.sh` runs it in the tests container
// (tests/run-tests-in-container.sh), and `./run-coverage.sh` runs it too;
// `./local-run-tests.sh` ran it on the host until it was removed (2026-09-16).
// Since #50 a host run of it meets common/compiled_tree.js's refusal
// (STS-CORE-0093), because the TypeScript is compiled only inside an image.
//
// `npm test` (tests/run.js) runs every test in ONE process and prints bunyan
// lines. That is the right shape for the thing it is — under two seconds, no
// port, no dependency — and it is the wrong shape for three questions somebody
// asks the moment a run is longer than the terminal:
//
//   * which FILE was slow, and which one failed;
//   * what did the failing one actually print, without scrolling past nine
//     others that passed;
//   * what did the run look like LAST time.
//
// So this runner answers those and changes nothing about the other one. It
// writes tests/report/<timestamp>/ containing:
//
//   report.html          the run, per job and per assertion
//   report.xml           JUnit XML, one <testcase> per ASSERTION
//   summary.json         the same numbers for anything that wants to read them
//   logs/NN-<job>.log    the complete output of one job
//
// and points tests/report/latest at it.
//
// TWO MORE FILES IN logs/ ARE WRITTEN BY THE LAUNCHERS RATHER THAN BY THIS
// FILE, and they are the account of everything a per-job log cannot hold:
//
//   logs/00-mock-sts-service.log   the service's own — written here in host
//                                  mode (this file starts that service), and
//                                  by the launcher when the service is a
//                                  container, out of `docker compose logs sts`
//   logs/00-test-runner.log        THIS RUNNER'S own output — the jobs it
//                                  chose, the ones it could not start and why,
//                                  the reason a job was SKIPPED, the summary.
//                                  ./run-tests.sh takes it out of
//                                  `docker compose logs tests` (the
//                                  removed ./local-run-tests.sh tee'd it)
//
// A JOB THAT NEVER STARTED HAS NO logs/NN- FILE, which is the whole reason the
// second one exists: what it says about that job is said in the runner's
// output and used to be said in a terminal and nowhere else.
//
// ---------------------------------------------------------------------------
// A PROCESS PER TEST FILE, WHICH IS THE ONE REAL DIFFERENCE FROM run.js.
//
// It runs `node tests/run.js --only=<file>` per file rather than requiring the
// modules itself, and that is worth the ~60ms of process start each time:
//
//   * a test that HANGS is a job that times out and a report that says which,
//     where in one process it is a suite that never finishes;
//   * a test that takes the process down (an uncaught rejection, an exit) is
//     one red job rather than a run with no report at all;
//   * the process-wide state rule in tests/CLAUDE.md — restore the realm
//     table, restore process.env — stops being able to make ANOTHER file fail,
//     which is exactly the failure that is hardest to read. The rule still
//     holds, because `npm test` still runs them together and is what CI runs.
//
// The assertion detail comes from PARSING what the harness already prints —
// bunyan JSON on stdout, one record per `✓` or `✗`. No new protocol, no change
// to harness.js, and a test file written before this existed reports in full.
//
// ---------------------------------------------------------------------------
// THE SECOND HALF: THE PROTOCOL JOBS, AGAINST THE WORKING TREE.
//
// These drive a RUNNING service over HTTP. Some are copies of the parent
// project's — a protocol test is written in ../id-proto-debugger/tests/ by the
// decision the root CLAUDE.md argues, and over there it drives the `sts/`
// gitlink, which is pinned — and most are this repository's own (`local:
// true`). So this runner drives THIS WORKING TREE instead: a container a
// launcher built from it, or a throwaway copy it starts on ports of its own —
// the same jobs, the code you just edited, no submodule bump.
//
// WHICH jobs is LISTED, in tests/vendored/MANIFEST.js. It was DERIVED from the
// parent's own runner until the jobs were vendored on 2026-08-28; that
// manifest's header says why a derivation stopped being possible.
//
// A copied job may be AHEAD of this tree — their suite is developed against
// their own checkout — and it then fails here naming a feature this tree does
// not have. That is information rather than a fault in this runner, and the
// report says which side each job came from so it can be read that way.
//
// ---------------------------------------------------------------------------
// THE DEFAULT IS THE WHOLE SET, SINCE 2026-08-28, AND THAT REVERSES WHAT THIS
// FILE DID FOR ITS FIRST THREE DAYS.
//
// The protocol half used to be off unless `--protocol` was passed, on the
// argument that it needs the parent checkout beside this one and a run that
// needs nothing installed is a better default. That argument was wrong in the
// way that costs the most: the in-process half was then TEN FILES about the
// realm layer, the LDIF codec, the two map renderers and the crypto module, and
// it finished in under three seconds. So the default run answered in five
// seconds, said "Tests passed", and had exercised NO protocol endpoint, NO
// admin console and NO browser — which reads as a green suite and is a green
// tenth of one. Somebody has to already know about a flag to find that out,
// and a default that hides the other thirteen jobs behind one is a default
// that will be trusted wrongly.
//
// So the whole set runs unless it is turned off. What that costs is about a
// minute instead of three seconds, and — until the same day — a parent
// checkout beside this one. THAT SECOND COST IS GONE: the protocol jobs are
// VENDORED into tests/vendored/ and are this repository's own files
// now, so there is no checkout that can be missing and no job that can
// silently not run. See tests/vendored/MANIFEST.js for what is copied, what is
// this repository's own, and why the copies are not edited here.
//
// `--no-protocol` is the way back to the old default, and the report says so
// in its own banner rather than leaving a green page to be read as more than
// it is.
//
// Usage:
//   node tests/tools/run-report.js [options]
//
//   --only=<substr>[,...]  only these test files / job names
//   --list                 name the jobs that would run; run none
//   --protocol[=on|off|only]
//                          also (or only) run the protocol jobs under
//                          tests/vendored/ against a service. DEFAULT ON, as
//                          of 2026-08-28 — see THE DEFAULT IS THE WHOLE SET
//                          above. `--protocol=off` (or --no-protocol) leaves
//                          them out.
//   --no-protocol          the same as --protocol=off.
//   --parent=<dir>         ACCEPTED AND IGNORED. It named the checkout the
//                          protocol jobs were read out of, and since they are
//                          vendored into tests/vendored/ there is no such
//                          checkout. It is still parsed so that a script or a
//                          habit passing it does not die on an unknown option;
//                          tools/vendor-check.js is what takes it now.
//   --service-url=<url>    DRIVE A SERVICE SOMEBODY ELSE STARTED, at this URL,
//                          instead of starting a throwaway one. This is how
//                          ./local-run-tests.sh handed over the CONTAINER it
//                          brought up with docker-compose.yml, until it was
//                          removed (2026-09-16) — see THE SERVICE UNDER THE
//                          PROTOCOL JOBS below. The URL is
//                          checked before any job runs, and a service that
//                          does not answer FAILS the protocol jobs rather
//                          than skipping them, exactly as a throwaway one
//                          that would not start does.
//   --report-dir=<dir>     where to write (default tests/report)
//   --timeout=<ms>         per-job watchdog (default 300000; 0 disables). A
//                          job may RAISE it for itself with `timeoutMs` in
//                          MANIFEST.js and may never lower it; see runJob().
//                          `./run-coverage.sh` passes one of its own —
//                          see STS_COVERAGE_JOB_TIMEOUT_MS there — because
//                          instrumentation is what makes a job slow and
//                          the launcher is what knows a run is instrumented.
//   --quiet                do not echo each job's output as it runs
//   --help
//
// ---------------------------------------------------------------------------
// THE SERVICE UNDER THE PROTOCOL JOBS COMES FROM ONE OF TWO PLACES, AND THIS
// RUNNER STARTS ONLY THE SECOND.
//
//   A CONTAINER, brought up by a launcher and handed here as --service-url
//   (or STS_TEST_SERVICE_URL). ./run-tests.sh's is the `sts` service of
//   docker-compose-run-tests.yml; ./local-run-tests.sh's, from 2026-08-28
//   until that launcher was removed on 2026-09-16, was docker-compose.yml's.
//   What it buys is that
//   the thing under test is the IMAGE — the same Dockerfile, the same
//   `npm install --omit=dev`, the same node — rather than whatever the
//   developer's own `node_modules` and node version happen to be. Several
//   things this service does are properties of its image and not of its
//   source, and a suite that never builds one cannot see them.
//
//   A THROWAWAY PROCESS, started by tools/service.js on a block of ports of
//   its own. Still here, and still what a COVERAGE run uses (it was also
//   ./local-run-tests.sh --no-docker's) — because V8 writes its coverage
//   from inside the process being measured, and this runner cannot reach
//   inside a container to collect it.
//
// The lifetime rule is the same one that governs everything else here: WHOEVER
// STARTED IT STOPS IT. A service handed in through --service-url is never
// stopped by this file, because the launcher's teardown owns it and two owners
// of one container is how a run ends by killing a stack somebody was reading.
// ---------------------------------------------------------------------------
//
// Environment:
//   LOG_LEVEL       this runner's and the unit jobs' bunyan level.
//   STS_TEST_SERVICE_URL
//                   the same thing --service-url says, for a caller that would
//                   rather export than pass an argument. The option wins.
//   STS_LOG_LEVEL   the throwaway service's level. Unset means its appconfig
//                   file decides, and that is `info` since 2026-09-12;
//                   `debug` is every request and every signed artifact
//                   written down, which is what a failing protocol job is read
//                   from, and about half of that service's CPU.
//   STS_TEST_CONFIG_FILE
//                   the appconfig file that service reads (default
//                   ./env/local.js, resolved by tests/tools/service.js). It is
//                   the OTHER half of the log level: the vendored modules
//                   under common/vendored/ build their loggers from this file
//                   and never see STS_LOG_LEVEL, so a quiet run needs both.
//                   ./run-coverage.sh sets it from the level.
//   COVERAGE=true   collect V8 coverage from every job AND from the throwaway
//                   service, then render it. `./run-coverage.sh` is the way in.
//   COVERAGE_DIR    where the raw data and the rendered report go
//                   (default ./coverage).
// ===========================================================================

const { spawn, spawnSync, execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const bunyan = require('bunyan');

const service = require('./service');
const trust = require('./trust');
const manifest = require('../vendored/MANIFEST.js');
const coverage = require('./coverage-report');
const adminApiToken = require('./admin-api-token');

const { testFiles } = require('../run');

const log = bunyan.createLogger({ name: 'run-report',
                                  level: process.env.LOG_LEVEL || 'info' });

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const TESTS_DIR = path.join(REPO_ROOT, 'tests');
const VENDORED_DIR = path.join(TESTS_DIR, 'vendored');
// A filesystem-safe ISO stamp, the parent project's shape: 2026-08-28T17-45-00.
const RUN_ID = new Date().toISOString().replace(/:/g, '-').replace(/\..+$/, '');

// ---------------------------------------------------------------------------
// Arguments. Hand-parsed, like tests/run.js's, and for the same reason: this
// directory takes no dependency to run.
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  log.debug('Entering parseArgs().');
  const opts = { only: [], list: false, protocol: 'on', parent: '',
                 reportDir: path.join(TESTS_DIR, 'report'),
                 timeoutMs: 300000, quiet: false, help: false,
                 browser: true,
                 // The environment is the FALLBACK and the option is the
                 // answer, which is the same precedence every other setting
                 // in this repository has.
                 serviceUrl: process.env.STS_TEST_SERVICE_URL || '',
                 unknown: [] };
  argv.forEach(function (a) {
    if (a === '--list') {
      opts.list = true;
    } else if (a === '--help' || a === '-h') {
      opts.help = true;
    } else if (a === '--quiet') {
      opts.quiet = true;
    } else if (a === '--no-browser') {
      opts.browser = false;
    } else if (a === '--protocol') {
      opts.protocol = 'on';
    } else if (a === '--no-protocol') {
      opts.protocol = 'off';
    } else if (a.indexOf('--protocol=') === 0) {
      opts.protocol = a.slice('--protocol='.length);
    } else if (a.indexOf('--parent=') === 0) {
      // Accepted and ignored — see the usage note above.
      opts.parent = a.slice('--parent='.length);
    } else if (a.indexOf('--service-url=') === 0) {
      // Trailing slashes are stripped because every job appends an absolute
      // path to this and `http://host:1/` + `/oauth2/token` is a 404 whose
      // message names a path that looks right.
      opts.serviceUrl = a.slice('--service-url='.length).replace(/\/+$/, '');
    } else if (a.indexOf('--report-dir=') === 0) {
      opts.reportDir = path.resolve(a.slice('--report-dir='.length));
    } else if (a.indexOf('--timeout=') === 0) {
      opts.timeoutMs = Number(a.slice('--timeout='.length));
    } else if (a.indexOf('--only=') === 0) {
      a.slice('--only='.length).split(',').forEach(function (p) {
        if (p.trim()) {
          opts.only.push(p.trim());
        }
      });
    } else if (a.indexOf('-') === 0) {
      opts.unknown.push(a);
    } else {
      opts.only.push(a);
    }
  });
  log.debug('Leaving parseArgs().');
  return opts;
}


// The environments of the OTHER services in the parent's stack. A job naming
// any of them needs more than a lone mock, so it is not one of ours.
const OTHER_SERVICE_ENV =
  /process\.env\.(WALTID[A-Z_]*|KEYCLOAK[A-Z_]*|DEBUGGER_BASE_URL|API_[A-Z_]*|WSFED_[A-Z_]*|STS_TEST_POSTGRES_URL|MOCK_STS_DIR)/;
// A job that drives a BROWSER, and — separately — one that drives the
// DEBUGGER'S OWN SITE.
//
// **NONE OF THE FOUR PATTERNS HERE IS READ ANY MORE.** They were how the jobs
// were DERIVED from the parent's runner; since the jobs were vendored,
// MANIFEST.js lists them and marks a browser job `browser: true`, and
// vendoredJobs() reads that. What follows is the record of the derivation.
//
// Until 2026-08-28 the first of these was used as the second, and it was right
// by accident: every browser job in that suite drove the debugger's pages, so
// "requires selenium" and "needs more than a lone mock" picked out the same
// set. sts_admin_console.js broke that — it became a browser job that
// drives THIS SERVICE'S OWN CONSOLE and needs a Chrome and nothing else — and
// dropping the selenium exclusion on its own let all twenty-three of the
// others back in, where they failed against a stack that is not running.
//
// So the two questions were asked separately. A browser job ran unless
// --no-browser; a job that named the debugger's client (port 3000) was not ours
// whether it needed a browser or not. The port is the discriminator because it
// is what those jobs actually reach for: each declares `var baseUrl =
// "http://localhost:3000"` and drives pages under it, while a job of ours
// locates the mock through WSTRUST_STS_URL / OID4VCI_ISSUER_URL and never
// mentions 3000.
// ---------------------------------------------------------------------------
// THE STACK'S DEPLOYMENT VARIABLES, WHICH A UNIT JOB MUST NOT INHERIT.
//
// `tests/tools/modes.sh` defines the modes as a block of `NAME=value`
// lines, and both launchers EXPORT them into the shell this runner is started
// from — they have to, because that is how `docker compose` and a host-mode
// service are handed the mode. A unit job is a child of this process, so it
// inherited them too, and that was silently wrong for as long as no mode set
// anything a module reads at require time.
//
// **`dispatch` MODE STARTED SETTING ONE ON 2026-09-12 AND IT COST EIGHT JOBS.**
// `STS_KEYS_SOURCE=persisted` turns the keystore on, and a keystore with no
// persistence store is a refusal by design — so `pki`, `pki_hierarchy`,
// `pki_revocation`, `spiffe_pki` and `tls_trust_anchor` died at
// `pki.start()` with *key material is configured to persist … and no
// persistence store is open*, and `backup_codes`, `encryption_report` and
// `rfc7523_person_issuer` failed further in, at the seal. Every one of them
// was passing in `memory` and `postgres` the same minute. The unit half asserts
// MODULE CONTRACTS in a process with no store, no listener and no container;
// how the service under the protocol jobs was deployed is not its
// configuration, and the eight failures said nothing about the service.
//
// THE NAMES ARE READ OUT OF `modes.sh` RATHER THAN WRITTEN HERE, because that
// file says it is the one place the modes are defined and a list copied into
// this one would drift in the direction nobody notices: a mode grows a fourth
// variable, the copy here does not, and the next unit job to read it fails for
// a reason three files away. A unit test that needs one of these sets it
// itself — every one that does already does, and `tests/database_metrics.js`
// deletes one — which is what makes stripping them safe as well as correct.
// ---------------------------------------------------------------------------
function stackDeploymentVariables() {
  log.debug('Entering stackDeploymentVariables().');
  const names = [];
  let text = '';
  try {
    text = fs.readFileSync(path.join(__dirname, 'modes.sh'), 'utf8');
  } catch (e) {
    // Not fatal: a unit job with the stack's variables is what this repository
    // did until 2026-09-12, so the degraded state is the old behaviour. It is
    // said out loud because silence here is eight failures nothing explains.
    log.warn('could not read tests/tools/modes.sh (' + e.message + '), so ' +
             'unit jobs will inherit whatever the launcher exported.');
    log.debug('Leaving stackDeploymentVariables(). Unreadable.');
    return names;
  }
  text.split('\n').forEach(function (line) {
    // NOT `STS_ALL_MODES`, which is the bash ARRAY of mode names at the top
    // of that file and is never an environment variable at all. A value
    // opening with `(` is the discriminator, because it is the only thing
    // that tells an array apart from a heredoc line here.
    const m = /^(STS_[A-Z0-9_]+)=([^(]|$)/.exec(line);
    if (m && names.indexOf(m[1]) < 0) {
      names.push(m[1]);
    }
  });
  if (!names.length) {
    log.warn('tests/tools/modes.sh named no STS_* variables, which means its ' +
             'shape has changed — unit jobs will inherit the launcher\'s ' +
             'environment as they did before 2026-09-12.');
  }
  log.debug('Leaving stackDeploymentVariables(). n=' + names.length);
  return names;
}

const STACK_ENV = stackDeploymentVariables();

const SELENIUM_REQUIRE = /require\(\s*["']selenium-webdriver/;
const DEBUGGER_SITE = /localhost:3000|127\.0\.0\.1:3000/;
const NEEDS_THE_MOCK = /WSTRUST_STS_URL|OID4VCI_ISSUER_URL/;

// ---------------------------------------------------------------------------
// The protocol jobs, as tests/vendored/MANIFEST.js lists them — the copies of
// the parent's and this repository's own — less the browser jobs when
// --no-browser asked for that.
// ---------------------------------------------------------------------------
function vendoredJobs(options) {
  log.debug('Entering vendoredJobs().');
  // A caller with no options gets the default, which is that browser jobs RUN.
  // This function is exported, so a second caller passing nothing must not
  // silently mean "leave the console's only coverage out".
  const opts = options || { browser: true };
  const skippedBrowserJobs = [];
  const jobs = [];
  manifest.JOBS.forEach(function (entry) {
    if (entry.browser && !opts.browser) {
      skippedBrowserJobs.push(entry.file);
      return;
    }
    jobs.push({ suite: 'protocol', name: entry.file.replace(/\.js$/, ''),
                file: entry.file, dir: VENDORED_DIR, browser: !!entry.browser,
                docker: !!entry.docker,
                // A job may raise its own watchdog and may not lower it; see
                // runJob(), where that rule is enforced rather than trusted.
                timeoutMs: Number(entry.timeoutMs) || 0 });
  });
  const browserJobs = jobs.filter(function (j) { return j.browser; });
  if (browserJobs.length) {
    log.info(browserJobs.length + ' of these need a BROWSER (' +
             browserJobs.map(function (j) { return j.name; }).join(', ') +
             '). They are run ONE AT A TIME like every other job here — this ' +
             'runner is serial — and they are the slowest jobs in the run. ' +
             '--no-browser leaves them out.');
  }
  if (skippedBrowserJobs.length) {
    log.warn('SKIPPING ' + skippedBrowserJobs.length + ' browser job(s) on ' +
             '--no-browser: ' + skippedBrowserJobs.join(', ') + '. The admin ' +
             'console has NO other coverage against this working tree, so ' +
             'this run says nothing about /admin.');
  }
  log.debug('Leaving vendoredJobs(). ' + jobs.length + ' job(s).');
  return jobs;
}

// ---------------------------------------------------------------------------
// THE TEST DEPENDENCIES, and why their absence is a FAILURE rather than a skip.
//
// The vendored jobs need `commander` and `selenium-webdriver`, which live in
// tests/package.json rather than the root one — see that file for the .npmrc
// reason. A checkout that has not run `npm install --prefix tests` therefore
// has jobs that cannot LOAD, and node reports that as MODULE_NOT_FOUND at
// startup: a non-zero exit, so the runner already calls it a failure.
//
// This check exists to make that failure READABLE. Every vendored job dying
// with a stack trace about `commander` is a wall of noise that names a package
// and not a command; one line naming the command, before anything is spawned,
// is the difference between a five-second fix and an afternoon.
//
// It does NOT skip the jobs and does not stop the run. They are still spawned,
// they still fail, and the report still counts every one of them — because a
// run that quietly declined to check anything is the exact thing this file was
// changed on 2026-08-28 to stop doing.
// ---------------------------------------------------------------------------
function checkTestDependencies() {
  log.debug('Entering checkTestDependencies().');
  const missing = [];
  ['commander', 'selenium-webdriver'].forEach(function (m) {
    if (!fs.existsSync(path.join(TESTS_DIR, 'node_modules', m))) {
      missing.push(m);
    }
  });
  if (missing.length) {
    log.error('the vendored protocol jobs need ' + missing.join(' and ') +
              ', which is not installed. They will FAIL to load. Fix it ' +
              'with:\n\n    npm install --prefix tests\n\n(those packages ' +
              'are in tests/package.json and not the root one because .npmrc ' +
              'carries omit=dev — see tests/package.json.)');
  }
  log.debug('Leaving checkTestDependencies(). ' + missing.length + ' missing.');
  return missing;
}

// ---------------------------------------------------------------------------
// IS THERE A DOCKER DAEMON THIS RUNNER CAN USE?
//
// Asked ONCE, and only when a job marked `docker: true` in
// `tests/vendored/MANIFEST.js` is actually scheduled — there is exactly one,
// and probing for a daemon nobody is going to ask for would be a second of
// somebody's run spent on nothing.
//
// **THE ANSWER PRODUCES A SKIP AND NOT A FAILURE, AND THAT IS THE ONE PLACE
// THIS FILE MAKES THAT CHOICE.** Everywhere else here an intended job that did
// not run is a FAILURE, for the reason the run loop states at length: the
// throwaway service failing to start once left thirteen jobs marked `skipped`,
// which the summary counted as passing, so a run in which nothing was checked
// exited zero. The difference is that this is a DELIBERATE exclusion, the same
// kind as `--no-browser`: `docker-compose-run-tests.yml` puts the suite in a
// container with no docker socket on purpose and says so where it excludes the
// parent suite's postgres job for the same reason. A skip here names the job,
// the reason and what is therefore unchecked — in the summary, in the report
// and in the JUnit — which is the honest report of a stack that cannot run it.
// ---------------------------------------------------------------------------
function haveDocker() {
  log.debug('Entering haveDocker().');
  const probe = spawnSync('docker', ['version', '--format',
                                     '{{.Server.Version}}'],
                          { encoding: 'utf8' });
  if (probe.error || probe.status !== 0) {
    const why = probe.error ? probe.error.message
      : String(probe.stderr || probe.stdout || '').trim().split('\n')[0];
    log.debug('Leaving haveDocker(). No: ' + why);
    return { ok: false, why: why || 'docker did not answer' };
  }
  log.debug('Leaving haveDocker(). ' + probe.stdout.trim());
  return { ok: true, version: String(probe.stdout || '').trim() };
}

// ---------------------------------------------------------------------------
// RE-ESTABLISH THE ANCHOR, IF THE SERVICE HAS ROTATED IT (2026-09-12).
//
// Called before every protocol job. It re-fetches `/tls/server-certificate`
// and, when the bundle differs from the one on disk, writes the new one to the
// SAME path and recomputes the SPKI pin — so the two variables a job is handed
// keep naming the certificate the service is actually serving.
//
// **THE PATH DOES NOT CHANGE AND THAT IS DELIBERATE.** `NODE_EXTRA_CA_CERTS`
// is read by node once per child, so a rewritten file is picked up by the next
// job and by nothing already running; a second path would leave the report
// directory holding several certificates with nothing saying which was live.
// What IS kept is the record: every rotation is announced at `warn` naming the
// job boundary it happened at, because "the certificate changed between job 40
// and job 41" is the sentence that makes a batch of handshake failures
// readable.
//
// It answers `null` when nothing changed and when the fetch failed, which are
// the same instruction to the caller: go on using what you have.
// ---------------------------------------------------------------------------
async function refreshTrust(url, current) {
  log.debug('Entering refreshTrust().');
  let pem = '';
  let read = null;
  try {
    // readTrust() rather than fetchCertificate() since 2026-09-14: the same
    // one fetch in every mode but `cluster`, where it gathers every node's
    // leaf — see its header in tools/trust.js.
    read = await trust.readTrust(url);
    pem = read.pem;
  } catch (e) {
    // NOT fatal and named rather than swallowed: the service may be mid-restart
    // or simply gone, and the job about to run will say so far more usefully
    // than a runner that stopped here.
    log.warn('could not re-read the mock STS\'s certificate from ' + url +
             trust.CERTIFICATE_PATH + ' (' + e.message + '); the next job ' +
             'runs with the anchor this run already had.');
    log.debug('Leaving refreshTrust(). Not fetched.');
    return null;
  }
  let was = '';
  try {
    was = fs.readFileSync(current.pemPath, 'utf8');
  } catch (e) {
    // The file is ours and was written moments ago; an unreadable one is worth
    // hearing about, and rewriting it is the right answer either way.
    log.warn('the anchor this run wrote could not be read back (' + e.message +
             '); rewriting it.');
  }
  if (was === pem) {
    log.debug('Leaving refreshTrust(). Unchanged.');
    return null;
  }
  const pin = read.pin;
  fs.writeFileSync(current.pemPath, pem);
  // **THE PIN IS USUALLY UNCHANGED AND THE BUNDLE IS NOT, WHICH IS THE WHOLE
  // POINT OF SAYING BOTH.** A rebuild re-certifies the listener over the key
  // it already had, so the SPKI pin the browser job uses survives it and the
  // node jobs' anchor does not — the Root above the leaf is a different
  // certificate and OpenSSL has nothing to terminate a path at. A message
  // reporting only the pin would say "nothing changed" about the one event
  // that breaks every node-driven job in the run.
  log.warn('THE SERVICE HAS ROTATED ITS TLS CERTIFICATE since the last job — ' +
           'most likely a PKI action on /admin/pki or /admin-api/pki, which ' +
           'rebuilds the Root and re-issues this listener\'s leaf. The ' +
           'anchor at ' + current.pemPath + ' has been replaced; every job ' +
           'from here on is handed the new one. SPKI pin ' + pin +
           (pin === current.pin
             ? ' (UNCHANGED — the re-issue was over the same key, so it is ' +
               'the anchor above it that moved)'
             : ' (was ' + current.pin + ')') + '.');
  log.debug('Leaving refreshTrust(). Rotated.');
  return Object.assign({}, current, {
    pin: pin,
    variables: Object.assign({}, current.variables, { STS_SPKI_PIN: pin })
  });
}

// ---------------------------------------------------------------------------
// One job, in a process of its own. Its output is TEED — written to the log
// file as it arrives and echoed to the console unless --quiet — so a long job
// is watchable and a finished one is readable.
// ---------------------------------------------------------------------------
function runJob(job, opts) {
  log.debug('Entering runJob(). job=' + job.name);
  log.debug("Leaving runJob().");
  return new Promise(function (resolve) {
    const started = Date.now();
    const stream = fs.createWriteStream(job.logFile, { flags: 'a' });
    stream.write('# ' + job.name + '\n# ' + job.cmd.join(' ') +
                 '\n# cwd=' + job.cwd + '\n\n');
    const child = spawn(job.cmd[0], job.cmd.slice(1), {
      cwd: job.cwd,
      env: job.env,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let buffered = '';
    const assertions = [];
    function onData(chunk) {
      log.debug("Entering onData().");
      const text = chunk.toString();
      stream.write(text);
      if (!opts.quiet) {
        process.stdout.write(text);
      }
      buffered += text;
      // Whole lines only: a bunyan record split across two reads is not JSON
      // yet, and half of one parsed as a failure would be a fiction.
      const lines = buffered.split('\n');
      buffered = lines.pop();
      lines.forEach(function (line) {
        const a = assertionOf(line);
        if (a) {
          assertions.push(a);
        }
      });
      log.debug("Leaving onData().");
    }
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    let timer = null;
    let timedOut = false;
    // ONE JOB MAY ASK FOR MORE TIME THAN THE RUN'S DEFAULT, AND NONE MAY ASK
    // FOR LESS (2026-09-06).
    //
    // The watchdog is here to turn a hang into a named failure, and 300s is
    // right for every job that drives a few hundred requests. It is wrong for
    // the three `sts_directory_bulk_load_*.js` jobs, which make ten thousand
    // sequential writes EACH on purpose: killed at five minutes one would be
    // reported as a hang, which is the one thing a watchdog must not do to a
    // job that is working.
    //
    // **`--timeout=` STILL WINS WHEN IT IS LARGER, AND A MANIFEST ENTRY MAY
    // ONLY RAISE.** `Math.max` rather than `||` is what makes that true: a job
    // cannot shorten its own leash and so cannot make itself flaky on a slow
    // machine, and `--timeout=0` — which disables the watchdog for the whole
    // run — is still zero here, because the branch below tests the option and
    // not this number.
    const jobTimeoutMs = opts.timeoutMs > 0
      ? Math.max(opts.timeoutMs, Number(job.timeoutMs) || 0)
      : 0;
    if (opts.timeoutMs > 0) {
      timer = setTimeout(function () {
        timedOut = true;
        // SIGKILL rather than SIGTERM: a job that has already ignored its
        // watchdog is not the one to trust with a clean shutdown.
        try {
          child.kill('SIGKILL');
        } catch (e) {
          // It finished between the timer firing and this line. Nothing to do.
          log.debug("Caught in a callback in runJob(): " +
                    ((e && e.message) || e));
        }
      }, jobTimeoutMs);
    }
    child.on('error', function (e) {
      if (timer) {
        clearTimeout(timer);
      }
      stream.end('\n# could not spawn: ' + e.message + '\n');
      log.debug('Leaving runJob(). Could not spawn.');
      resolve(Object.assign({}, job, {
        status: 'failed', ms: Date.now() - started, code: null,
        assertions: assertions,
        failures: ['could not spawn ' + job.cmd[0] + ': ' + e.message]
      }));
    });
    child.on('close', function (code, signal) {
      if (timer) {
        clearTimeout(timer);
      }
      if (buffered) {
        const a = assertionOf(buffered);
        if (a) {
          assertions.push(a);
        }
      }
      const ms = Date.now() - started;
      const failures = assertions.filter(function (a) { return !a.ok; })
        .map(function (a) { return a.what; });
      if (timedOut) {
        failures.push('the job did not finish within ' + jobTimeoutMs +
                      'ms and was killed');
      } else if (code !== 0 && !failures.length) {
        // The exit code is the only evidence there is: a parent-project job
        // reports through `assert` rather than through this repository's
        // harness, so a red one usually leaves no ✗ line to have parsed.
        failures.push('exited ' + (signal ? 'on ' + signal : 'with code ' +
                      code) + '; see ' + path.basename(job.logFile));
      }
      stream.end('\n# exit code ' + code + (signal ? ' (' + signal + ')' : '') +
                 ' after ' + ms + 'ms\n');
      log.debug('Leaving runJob(). ' + job.name + ' exited ' + code + '.');
      resolve(Object.assign({}, job, {
        status: (code === 0 && !timedOut && !failures.length) ? 'passed'
                                                             : 'failed',
        ms: ms, code: code, signal: signal || null,
        assertions: assertions, failures: failures
      }));
    });
  });
}

// ---------------------------------------------------------------------------
// THE FUNCTIONS BELOW WERE WRITTEN WITH NO `Entering`/`Leaving` PAIR, AND
// CARRY ONE NOW. `assertionOf()` is called once per LINE of every job's
// output, which is tens of thousands of times in an ordinary run, and the HTML
// helpers are called once per row; a debug line each would bury the log those
// lines exist to make readable. The 2026-09-12 style sweep added the pairs all
// the same, so a run of this file at LOG_LEVEL=debug is that buried log (the
// root CLAUDE.md's hot-path exception is the way to take them off again).
//
// One line of a job's output, read for an assertion. The harness prints bunyan
// JSON whose `msg` begins with two spaces and a tick or a cross (harness.js),
// so this reads what is already there rather than asking the tests to report
// twice — which is what keeps every test file written before this existed
// fully reported by it.
// ---------------------------------------------------------------------------
function assertionOf(line) {
  log.debug("Entering assertionOf().");
  const trimmed = line.trim();
  if (!trimmed || trimmed[0] !== '{') {
    log.debug("Leaving assertionOf().");
    return null;
  }
  let rec;
  try {
    rec = JSON.parse(trimmed);
  } catch (e) {
    log.debug("Caught in assertionOf(): " + ((e && e.message) || e));
    log.debug("Leaving assertionOf().");
    // Not a bunyan record. The service modules under test print plenty that
    // is not, and a parse failure here is the ordinary case rather than a
    // problem.
    return null;
  }
  if (!rec || typeof rec.msg !== 'string') {
    log.debug("Leaving assertionOf().");
    return null;
  }
  const m = /^\s*([✓✗])\s+([\s\S]*)$/.exec(rec.msg);
  if (!m) {
    log.debug("Leaving assertionOf().");
    return null;
  }
  log.debug("Leaving assertionOf().");
  return { ok: m[1] === '✓', what: m[2], test: rec.name || '' };
}

function escapeHtml(s) {
  log.debug("Entering escapeHtml().");
  log.debug("Leaving escapeHtml().");
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeXml(s) {
  log.debug("Entering escapeXml().");
  log.debug("Leaving escapeXml().");
  return escapeHtml(s).replace(/'/g, '&apos;')
    // Control characters are not legal in XML 1.0 at all, and a stack trace
    // carrying one makes the whole document unparseable for a CI dashboard —
    // which is the one consumer this file has.
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '');
}

function slug(s) {
  log.debug("Entering slug().");
  log.debug("Leaving slug().");
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '').slice(0, 60);
}

// ---------------------------------------------------------------------------
// What this run was OF, which is most of what makes an old report worth
// keeping: a green report against a tree with uncommitted changes is a
// different claim from a green report against a commit.
// ---------------------------------------------------------------------------
function describeTree(dir) {
  log.debug('Entering describeTree(). dir=' + dir);
  const out = { commit: '', subject: '', dirty: null };
  function git(args) {
    log.debug("Entering git().");
    log.debug("Leaving git().");
    return execFileSync('git', args, { cwd: dir, encoding: 'utf8',
                                       stdio: ['ignore', 'pipe', 'ignore'] })
      .trim();
  }
  try {
    out.commit = git(['rev-parse', '--short', 'HEAD']);
    out.subject = git(['log', '-1', '--pretty=%s']);
    out.dirty = git(['status', '--porcelain']).length > 0;
  } catch (e) {
    // Not a checkout, or no git. The report then says the commit is unknown,
    // which is honest and costs nothing else.
    log.debug('describeTree() could not read git: ' + e.message);
  }
  log.debug('Leaving describeTree().');
  return out;
}

// ---------------------------------------------------------------------------
// THE HTML. Self-contained and with NO SCRIPT on it, which is not an accident
// carried over from the console's rule (app.js sets `script-src 'none'` and
// seven pages argue their way past it one at a time): a report is read from a
// file:// URL, from a CI artifact server, and from whatever a person pastes it
// into, and `<details>` folds every long list without needing any of them to
// allow one.
// ---------------------------------------------------------------------------
const STYLE = [
  ':root{color-scheme:light dark;--fg:#1a1a1a;--bg:#fbfbfa;--muted:#6b6b6b;',
  '--line:#e3e3e0;--card:#fff;--pass:#1a7f37;--fail:#b3261e;--skip:#8a6d00;}',
  '@media (prefers-color-scheme:dark){:root{--fg:#e6e6e6;--bg:#171717;',
  '--muted:#a0a0a0;--line:#333;--card:#1f1f1f;--pass:#4ac26b;--fail:#ff7b72;',
  '--skip:#d4a72c;}}',
  'body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ' +
  '-apple-system,',
  'BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}',
  '.wrap{max-width:1100px;margin:0 auto;padding:24px 20px 64px;}',
  'h1{font-size:20px;margin:0 0 4px;} h2{font-size:16px;margin:32px 0 8px;}',
  '.sub{color:var(--muted);margin:0 0 20px;}',
  '.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0 8px;}',
  '.card{background:var(--card);border:1px solid ' +
  'var(--line);border-radius:8px;',
  'padding:10px 14px;min-width:110px;}',
  '.card .n{font-size:22px;font-weight:600;} .card ' +
  '.l{color:var(--muted);font-size:12px;}',
  'table{border-collapse:collapse;width:100%;background:var(--card);',
  'border:1px solid var(--line);border-radius:8px;overflow:hidden;}',
  'th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);',
  'vertical-align:top;} th{font-size:12px;color:var(--muted);font-weight:600;}',
  'tr:last-child td{border-bottom:none;} td.num{text-align:right;',
  'font-variant-numeric:tabular-nums;white-space:nowrap;}',
  '.pass{color:var(--pass);} .fail{color:var(--fail);} ' +
  '.skip{color:var(--skip);}',
  'code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;',
  'font-size:12px;}',
  'pre{background:var(--card);border:1px solid var(--line);border-radius:6px;',
  'padding:10px;overflow-x:auto;}',
  'details{margin:6px 0;} summary{cursor:pointer;}',
  'ul.assertions{list-style:none;margin:6px 0 12px;padding:0 0 0 4px;}',
  'ul.assertions li{padding:2px 0;border-bottom:1px dotted var(--line);}',
  '.detail{color:var(--muted);}',
  '.banner{padding:10px 14px;border-radius:8px;border:1px solid var(--line);',
  'background:var(--card);margin:16px 0;}'
].join('');

function jobRow(j) {
  log.debug("Entering jobRow().");
  const status = j.status === 'passed'
    ? '<span class="pass">passed</span>'
    : (j.status === 'skipped' ? '<span class="skip">skipped</span>'
                              : '<span class="fail">FAILED</span>');
  const ok = j.assertions.filter(function (a) { return a.ok; }).length;
  const bad = j.assertions.length - ok;
  const counts = j.assertions.length
    ? ok + ' ✓' + (bad ? ' / <span class="fail">' + bad + ' ✗</span>' : '')
    : '<span class="detail">—</span>';
  log.debug("Leaving jobRow().");
  return '<tr><td><code>' + escapeHtml(j.name) + '</code>' +
    (j.describe ? '<div class="detail">' + escapeHtml(j.describe) + '</div>'
                : '') +
    (j.why ? '<div class="detail">' + escapeHtml(j.why) + '</div>' : '') +
    '</td><td>' + status + '</td><td class="num">' + counts +
    '</td><td class="num">' + (j.status === 'skipped' ? '—' : j.ms + ' ms') +
    '</td><td>' + (j.logName
      ? '<a href="logs/' + escapeHtml(j.logName) + '">log</a>' : '') +
    '</td></tr>';
}

function assertionList(j) {
  log.debug("Entering assertionList().");
  if (!j.assertions.length) {
    log.debug("Leaving assertionList().");
    return '';
  }
  const items = j.assertions.map(function (a) {
    return '<li>' + (a.ok ? '<span class="pass">✓</span> '
                          : '<span class="fail">✗</span> ') +
      escapeHtml(a.what) + '</li>';
  }).join('');
  log.debug("Leaving assertionList().");
  return '<details><summary>' + j.assertions.length + ' assertion(s) — ' +
    escapeHtml(j.name) + '</summary><ul class="assertions">' + items +
    '</ul></details>';
}

function writeHtml(runDir, results, meta) {
  log.debug('Entering writeHtml().');
  const failed = results.filter(function (j) { return j.status === 'failed'; });
  const skipped =
      results.filter(function (j) { return j.status === 'skipped'; });
  const passed = results.filter(function (j) { return j.status === 'passed'; });
  const asserted = results.reduce(function (n, j) {
    return n + j.assertions.length;
  }, 0);
  const assertFailed = results.reduce(function (n, j) {
    return n + j.assertions.filter(function (a) { return !a.ok; }).length;
  }, 0);
  const bySuite = {};
  results.forEach(function (j) {
    bySuite[j.suite] = bySuite[j.suite] || [];
    bySuite[j.suite].push(j);
  });
  const SUITE_TITLE = {
    unit: 'In-process module contracts (this repository\'s tests/)',
    protocol: 'Protocol jobs from the parent project, against this working ' +
              'tree'
  };
  let html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>mock STS tests — ' + escapeHtml(meta.runId) + '</title>' +
    '<style>' + STYLE + '</style></head><body><div class="wrap">';
  html += '<h1>mock STS test report</h1>';
  html += '<p class="sub">' + escapeHtml(meta.runId) + ' · ' +
    escapeHtml(meta.host) + ' · node ' + escapeHtml(meta.node) + ' · ' +
    (meta.wallMs / 1000).toFixed(1) + 's wall</p>';
  html += '<div class="cards">' +
    '<div class="card"><div class="n ' +
      (failed.length ? 'fail' : 'pass') + '">' +
      (failed.length ? 'FAILED' : 'passed') + '</div>' +
      '<div class="l">overall</div></div>' +
    '<div class="card"><div class="n">' + results.length + '</div>' +
      '<div class="l">jobs</div></div>' +
    '<div class="card"><div class="n pass">' + passed.length + '</div>' +
      '<div class="l">passed</div></div>' +
    '<div class="card"><div class="n ' + (failed.length ? 'fail' : '') + '">' +
      failed.length + '</div><div class="l">failed</div></div>' +
    (skipped.length ? '<div class="card"><div class="n skip">' +
      skipped.length + '</div><div class="l">skipped</div></div>' : '') +
    '<div class="card"><div class="n">' + asserted + '</div>' +
      '<div class="l">assertions</div></div>' +
    (assertFailed ? '<div class="card"><div class="n fail">' + assertFailed +
      '</div><div class="l">assertions failed</div></div>' : '') +
    '</div>';

  html += '<div class="banner"><strong>What was under test.</strong> ' +
    'This tree at <code>' + escapeHtml(meta.tree.commit || 'unknown') +
    '</code>' + (meta.tree.subject ? ' — ' + escapeHtml(meta.tree.subject)
                                   : '') +
    (meta.tree.dirty ? ', <span class="fail">with uncommitted changes</span>'
                     : ', clean') + '.';
  if (meta.vendored) {
    html += ' Protocol jobs are the VENDORED copies in <code>' +
      escapeHtml(meta.vendored) + '</code> — this tree\'s own files, at the ' +
      'commit above — driven against ' +
      (meta.serviceKind === 'container'
        ? 'a CONTAINER built from this tree by <code>docker-compose.yml</code>'
        : 'a throwaway in-process instance') +
      ' on <code>' +
      escapeHtml(meta.serviceUrl || '?') + '</code>. They are byte-identical ' +
      'copies of the parent project\'s jobs and are not edited here; ' +
      '<code>node tests/tools/vendor-check.js</code> reports drift when ' +
      'both checkouts are present.';
  } else if (meta.protocolWhy) {
    html += ' Protocol jobs were not run: ' + escapeHtml(meta.protocolWhy) +
      '.';
  } else {
    html += ' Protocol jobs were TURNED OFF for this run ' +
      '(<code>--no-protocol</code>), so nothing here says anything about ' +
      'this service\'s protocol surface or its admin console.';
  }
  html += '</div>';

  if (failed.length) {
    html += '<h2 class="fail">Failures</h2><table><tr><th>job</th>' +
      '<th>what failed</th></tr>';
    failed.forEach(function (j) {
      html += '<tr><td><code>' + escapeHtml(j.name) + '</code><div>' +
        (j.logName ? '<a href="logs/' + escapeHtml(j.logName) + '">log</a>'
                   : '') + '</div></td><td><ul class="assertions">' +
        j.failures.map(function (f) {
          return '<li class="fail">' + escapeHtml(f) + '</li>';
        }).join('') + '</ul></td></tr>';
    });
    html += '</table>';
  }

  Object.keys(bySuite).forEach(function (suite) {
    html += '<h2>' + escapeHtml(SUITE_TITLE[suite] || suite) + '</h2>';
    html += '<table><tr><th>job</th><th>result</th><th>assertions</th>' +
      '<th>time</th><th></th></tr>';
    bySuite[suite].forEach(function (j) {
      html += jobRow(j);
    });
    html += '</table>';
    const withAssertions = bySuite[suite].filter(function (j) {
      return j.assertions.length;
    });
    if (withAssertions.length) {
      html += '<h3 style="font-size:14px;margin:16px 0 4px;">Every assertion' +
        '</h3>';
      withAssertions.forEach(function (j) {
        html += assertionList(j);
      });
    }
  });

  if (meta.coverage) {
    html += '<h2>Coverage</h2><p>' +
      '<a href="' + escapeHtml(meta.coverage) + '">' +
      escapeHtml(meta.coverage) + '</a></p>';
  }

  html += '<h2>How this was run</h2><pre>' +
    escapeHtml(meta.commandLine) + '</pre>';
  html += '</div></body></html>';
  fs.writeFileSync(path.join(runDir, 'report.html'), html);
  log.debug('Leaving writeHtml().');
}

// ---------------------------------------------------------------------------
// JUnit XML, one <testcase> per ASSERTION where there are assertions to have,
// and one per job where there are not. Per assertion because that is what this
// suite actually knows — a CI dashboard then names the check that broke rather
// than the file it was in.
// ---------------------------------------------------------------------------
function writeXml(runDir, results, meta) {
  log.debug('Entering writeXml().');
  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites ' +
    'name="mock-sts" time="' + (meta.wallMs / 1000).toFixed(3) + '">\n';
  results.forEach(function (j) {
    const cases = [];
    if (j.assertions.length) {
      j.assertions.forEach(function (a) {
        cases.push('    <testcase classname="' +
          escapeXml(j.suite + '.' + j.name) +
          '" name="' + escapeXml(a.what) + '">' +
          (a.ok ? '' : '<failure message="' + escapeXml(a.what) + '"/>') +
          '</testcase>\n');
      });
    }
    if (!cases.length || j.status !== 'passed') {
      const body = j.status === 'skipped'
        ? '<skipped message="' + escapeXml(j.why || '') + '"/>'
        : (j.status === 'failed'
            ? '<failure message="' + escapeXml(j.failures.join('; ')) + '"/>'
            : '');
      cases.push('    <testcase classname="' +
        escapeXml(j.suite + '.' + j.name) +
        '" name="' + escapeXml(j.name + ' (the job)') + '" time="' +
        (j.ms / 1000).toFixed(3) + '">' + body + '</testcase>\n');
    }
    const failures = j.assertions.filter(function (
        a) { return !a.ok; }).length +
      (j.status === 'failed' ? 1 : 0);
    xml += '  <testsuite name="' + escapeXml(j.suite + '.' + j.name) +
      '" tests="' + cases.length + '" failures="' + failures +
      '" skipped="' + (j.status === 'skipped' ? 1 : 0) + '" time="' +
      (j.ms / 1000).toFixed(3) + '">\n' + cases.join('') + '  </testsuite>\n';
  });
  xml += '</testsuites>\n';
  fs.writeFileSync(path.join(runDir, 'report.xml'), xml);
  log.debug('Leaving writeXml().');
}

// ---------------------------------------------------------------------------
// tests/report/latest, so the launcher and a person both have one path that
// does not change. A symlink where the platform allows it, and a file naming
// the run where it does not — Windows without developer mode being the case
// that made a plain symlink throw here.
// ---------------------------------------------------------------------------
function pointLatestAt(reportDir, runDir) {
  log.debug('Entering pointLatestAt().');
  const link = path.join(reportDir, 'latest');
  try {
    if (fs.existsSync(link) || fs.lstatSync(link)) {
      fs.rmSync(link, { recursive: true, force: true });
    }
  } catch (e) {
    // Nothing there. That is the ordinary first run.
    log.debug("Caught in pointLatestAt(): " + ((e && e.message) || e));
  }
  try {
    fs.symlinkSync(path.basename(runDir), link, 'dir');
  } catch (e) {
    fs.writeFileSync(link + '.txt', path.basename(runDir) + '\n');
    log.debug('pointLatestAt() could not symlink: ' + e.message);
  }
  log.debug('Leaving pointLatestAt().');
}

// The usage is the header of this file, read back rather than kept a second
// time in a string — which is the only way the two cannot drift apart. From
// the `Usage:` line to the end of the comment block, and no further: an
// earlier attempt filtered by indentation and printed half the design notes.
const USAGE = (function () {
  const lines = fs.readFileSync(__filename, 'utf8').split('\n');
  const from = lines.findIndex(function (l) { return /^\/\/ Usage:/.test(l); });
  if (from < 0) {
    return 'see the header of ' + __filename;
  }
  const out = [];
  for (let i = from; i < lines.length; i++) {
    if (lines[i].indexOf('//') !== 0) {
      break;
    }
    if (/^\/\/ =====/.test(lines[i])) {
      break;
    }
    out.push(lines[i].replace(/^\/\/ ?/, ''));
  }
  return out.join('\n');
})();

// ---------------------------------------------------------------------------
// LIVENESS, OVER EITHER SCHEME, WITH THE CERTIFICATE UNJUDGED.
//
// It was `fetch(url + '/')` until 2026-08-30, and that stopped working the day
// the mock's main port became TLS in every stack here: the certificate — then
// self-signed, a leaf of the service Root since 2026-09-11 — is regenerated on
// every start with its anchor, so the very first request this
// runner makes to a service it has not yet learned the key of would fail
// verification — and the wait below would spend its whole thirty seconds on it
// and report a service that "did not answer", naming a certificate error the
// caller cannot act on because the fix is the fetch this runner is about to
// make.
//
// `rejectUnauthorized: false` is right HERE and nowhere else in this suite: the
// question is whether the port answers, not whether it is trustworthy. The jobs
// themselves get a real anchor — see tests/tools/trust.js — so an assertion
// about a certificate is still made against one.
//
// The status is what comes back rather than a boolean, because the caller
// distinguishes "answered with something" from "nothing there" and 0 is how
// the second says so.
function probe(url) {
  log.debug("Entering probe().");
  log.debug("Leaving probe().");
  return new Promise(function (resolve) {
    let target;
    try {
      target = new URL(url);
    } catch (e) {
      log.debug("Caught in a callback in probe(): " + ((e && e.message) || e));
      resolve(0);
      return;
    }
    const mod = target.protocol === 'https:' ? require('https') :
                require('http');
    const req = mod.get({
      host: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      path: target.pathname + target.search,
      rejectUnauthorized: false,
      timeout: 5000
    }, function (res) {
      res.resume();
      resolve(res.statusCode || 0);
    });
    req.on('error', function () {
      resolve(0);
    });
    req.on('timeout', function () {
      req.destroy();
      resolve(0);
    });
  });
}

// ---------------------------------------------------------------------------
// IS THE SERVICE SOMEBODY ELSE STARTED ACTUALLY ANSWERING?
//
// The launcher already waited for its container to answer before it got here,
// so this ordinarily returns on its first request — and it is not therefore
// decoration. It answers a DIFFERENT question from the one the launcher asked,
// and the difference has cost the parent project a whole run: the launcher
// asked whether something answers on that port, and this asks whether it is
// still answering NOW, from this process, with the environment these jobs will
// actually use. A container that aborted between the two, a URL typed by hand
// into --service-url, a stale STS_TEST_SERVICE_URL exported in a shell weeks
// ago and forgotten — each of those reaches the jobs as a wall of failures
// about tokens and metadata, and reaches this as one line naming the URL.
//
// A NON-200 IS AS GOOD AS AN ANSWER, deliberately. /healthcheck is what a
// caller usually points at and it answers 200, but the URL handed in is the
// service's ROOT and this asks for `/`, which any of the redirects and shells
// this service serves may answer with. What is being distinguished here is a
// socket that answers from one that does not.
async function waitForExternalService(url, log, timeoutMs) {
  log.debug('Entering waitForExternalService().');
  const deadline = Date.now() + (timeoutMs || 30000);
  while (Date.now() < deadline) {
    /* eslint-disable no-await-in-loop */
    const status = await probe(url + '/');
    /* eslint-enable no-await-in-loop */
    if (status > 0) {
      log.debug('Leaving waitForExternalService(). Answering.');
      return true;
    }
    /* eslint-disable no-await-in-loop */
    await new Promise(function (r) { setTimeout(r, 500); });
    /* eslint-enable no-await-in-loop */
  }
  log.debug('Leaving waitForExternalService(). It did not answer.');
  // THE OTHER SCHEME IS THE ONE DIAGNOSIS WORTH MAKING BY HAND, and it is the
  // failure this whole file's 2026-08-30 change could produce: the mock serves
  // TLS on the port a permissive one served plain HTTP on, so a stale
  // STS_TEST_SERVICE_URL exported in somebody's shell weeks ago reaches this
  // runner as a closed socket that names nothing. A bare "did not answer"
  // would send them to look at the service.
  //
  // The probe above no longer collects an error MESSAGE, and that is not a
  // loss: with `rejectUnauthorized: false` every remaining cause is "nothing
  // is listening on that scheme, host and port", which is what the sentence
  // now says instead of quoting an ECONNREFUSED.
  const swapped = /^https:/i.test(url)
    ? url.replace(/^https:/i, 'http:')
    : url.replace(/^http:/i, 'https:');
  let hint = '';
  if (swapped !== url && (await probe(swapped + '/')) > 0) {
    hint = ' SOMETHING IS ANSWERING AT ' + swapped + ' INSTEAD: in this ' +
           'service the scheme is a property of the LISTENER (global.https, ' +
           'which every appconfig file here now sets and STS_HTTPS ' +
           'overrides), so this is a URL that names the wrong one.';
  }
  log.debug("Leaving waitForExternalService().");
  throw new Error('nothing answered at ' + url + '.' + hint +
                  ' It was handed to this runner with --service-url, so ' +
                  'nothing here started it and nothing here can restart it.');
}

// ---------------------------------------------------------------------------
// THE PORTS THE THROWAWAY SERVICE ACTUALLY BOUND, HANDED TO EVERY JOB.
//
// `tests/tools/service.js` picks a free BLOCK — eight since 2026-09-16 — and
// passes each to the service under the environment variable that service
// reads for it — so the
// name of a port in `instance.ports` is already the name a job would look it
// up by. Handing the whole block over is therefore one line of policy rather
// than a list that has to be extended every time a job learns to dial another
// listener.
//
// **IT IS A LIST THAT WAS BEING EXTENDED ONE FAILURE AT A TIME, WHICH IS WHY
// THIS IS A LOOP.** `STS_LDAP_URL` was added on 2026-09-06 for the bulk-load
// job. On 2026-09-09 the same run showed `sts_global_logout` dialling 389 for
// its directory bind and 9443 for its mutual-TLS sign-in, getting ECONNREFUSED
// from both, NOTING each and passing — two protocols' worth of sign-in that no
// run starting its own service had ever exercised. Any listener added to that
// block from now on is covered without anybody remembering to add it.
// (That job's certificate sign-in is `GET /tls/sign-in` on the MAIN port since
// 2026-09-16, when 8443 and 9443 were deleted, so it needs nothing from this
// map at all any more. The failure it records is what the loop is for.)
//
// **A LAUNCHER'S ANSWER ALWAYS WINS**, the same precedence `STS_LDAP_URL`
// above uses: a variable already in this process's environment was put there
// by a launcher — ./run-tests.sh now, ./local-run-tests.sh until
// 2026-09-16 — which arranged the socket itself and knows where it is. This
// only answers for the service THIS runner started, and answers nothing at
// all when it started none — the compose stacks reach this with no
// `instance`, and their defaults stand.
// ---------------------------------------------------------------------------
function chosenPorts(instance) {
  log.debug("Entering chosenPorts().");
  const out = {};
  const ports = (instance && instance.ports) || {};
  Object.keys(ports).forEach(function (name) {
    if (process.env[name]) {
      return;
    }
    out[name] = String(ports[name]);
  });
  log.debug("Leaving chosenPorts().");
  return out;
}

// ---------------------------------------------------------------------------
// THE MANAGEMENT API'S CREDENTIAL, WHEN THIS RUNNER IS THE ONE STARTING THE
// SERVICE (2026-09-09).
//
// `/admin-api` requires an OAuth 2.0 access token, and twenty-three jobs drive
// it. Both docker launchers mint one before any job runs and hand it here as
// `STS_ADMIN_API_TOKEN` — but there are three paths on which NO launcher does
// that, and all three share one trait: the service is a throwaway this runner
// started itself.
//
//   * `./run-coverage.sh`, which never passes --service-url because V8
//     collects from inside the process it measures
//   * `./local-run-tests.sh --no-docker`, where STS_URL was only ever
//     assigned inside composeUp() (that launcher was removed on 2026-09-16)
//   * a bare `node tests/tools/run-report.js`
//
// Until this existed all three ran the whole protocol half against a gated API
// with no credential, and the report named nineteen broken tests instead of
// one missing token. The coverage job in CI is where that was found.
//
// **THE SECRET HAS TO BE PINNED BEFORE THE SERVICE STARTS, WHICH IS WHY THIS
// IS TWO FUNCTIONS AND NOT ONE.** `applications.js` seeds `sts-management-api`
// with a secret minted at every start, readable only THROUGH the API it
// unlocks — so a secret chosen after the child is up is a secret nobody can
// use. `adminApi.clientSecret` exists for exactly this, and its environment
// variable is what `service.js` inherits along with the rest of process.env.
//
// A FRESH ONE PER RUN rather than a constant, for the launchers' stated
// reason: it lives as long as one throwaway service, it never reaches a
// repository, and two runs on one machine cannot lend each other a token.
// ---------------------------------------------------------------------------
function pinTheManagementApiSecret() {
  log.debug('Entering pinTheManagementApiSecret().');
  // A caller who set either name already MEANS it — `./run-tests.sh`
  // exports the first before it brings its stack up (as `./local-run-tests.sh`
  // did until 2026-09-16), and a person debugging a stack by hand sets the
  // second. Overwriting one here would mint a token
  // against a secret the running service has never heard of.
  if (process.env.ADMIN_API_CLIENT_SECRET ||
      process.env.STS_ADMIN_API_CLIENT_SECRET) {
    log.debug('Leaving pinTheManagementApiSecret(). One was handed in.');
    return;
  }
  const secret = crypto.randomBytes(24).toString('base64')
    .replace(/[/+=]/g, '').slice(0, 24);
  // BOTH NAMES, and they are read by different processes. The service reads
  // ADMIN_API_CLIENT_SECRET (config.js's `adminApi.clientSecret`) and inherits
  // it through service.js's copy of process.env; `admin-api-token.js` and the
  // one job that mints tokens of its own read STS_ADMIN_API_CLIENT_SECRET.
  // Setting one and not the other is a service that pinned a secret nothing
  // can present, or a minter presenting one the service did not pin.
  process.env.ADMIN_API_CLIENT_SECRET = secret;
  process.env.STS_ADMIN_API_CLIENT_SECRET = secret;
  log.debug('Leaving pinTheManagementApiSecret(). Pinned one for this run.');
}

// The token itself, once that service is answering. Handed to every job by the
// same two lines a launcher's token goes through, so there is one mechanism.
//
// **IT IS NOT FATAL, WHICH IS THE OPPOSITE OF WHAT THE LAUNCHERS DO, AND THE
// DIFFERENCE IS WHAT HAS ALREADY HAPPENED BY THIS POINT.** A launcher fails
// here having run nothing: exiting costs a report that does not exist yet.
// This runner has started a service and is about to run every job in the
// manifest, most of which never touch that API — so aborting would throw away
// the unit half and the coverage to protect the nineteen. The failure is not
// silent either way: `sts_admin_api_auth.js` is a job whose whole purpose is
// to name a missing token, and this logs at error naming the same thing.
async function mintTheManagementApiToken(url) {
  log.debug('Entering mintTheManagementApiToken().');
  try {
    process.env.STS_ADMIN_API_TOKEN = await adminApiToken.tokenFor(url);
    log.info('minted an /admin-api access token (admin:read admin:write, ' +
             'audience ' + adminApiToken.audienceFor(url) + ')');
  } catch (e) {
    log.error('could not mint an /admin-api access token from ' + url + ': ' +
              e.message + '. Every job that drives that API will answer 401. ' +
              'adminApi.authRequired=false restores the open API if that is ' +
              'what you want.');
  }
  log.debug('Leaving mintTheManagementApiToken().');
}

// ---------------------------------------------------------------------------
// A TOKEN THAT WOULD EXPIRE DURING THE NEXT JOB IS REPLACED BEFORE IT
// (2026-09-15, issue #51).
//
// The token is minted once and every job is handed it at spawn, so a run
// longer than the token's lifetime (an hour by default) sends every later job
// in with an expired one. Against a local stack a run rarely lasts that long;
// against the AWS cluster, where every request crosses the internet on a new
// connection, the first run did — and from the 61st minute twenty jobs failed
// at once on `GET /admin-api/status answered 401`, reading like twenty defects.
//
// So before each job, if this runner can mint (the client secret is in its
// environment) and the current token's own `exp` is closer than this job's
// watchdog plus five minutes, a fresh one replaces it. The deadline is read
// off the token rather than remembered, so a token a launcher handed in is
// judged the same way. A failure keeps the old token: the job then fails on
// it, which says the same thing more loudly.
// ---------------------------------------------------------------------------
async function refreshAdminApiToken(instance, jobTimeoutMs) {
  log.debug('Entering refreshAdminApiToken().');
  const token = process.env.STS_ADMIN_API_TOKEN || '';
  const canMint = !!(process.env.STS_ADMIN_API_CLIENT_SECRET ||
                     process.env.ADMIN_API_CLIENT_SECRET);
  if (!instance || !token || !canMint) {
    log.debug('Leaving refreshAdminApiToken(). Nothing to refresh with.');
    return;
  }
  let expMs = 0;
  try {
    const payload = JSON.parse(Buffer.from(String(token).split('.')[1] || '',
                                           'base64url').toString('utf8'));
    expMs = Number(payload.exp) * 1000 || 0;
  } catch (e) {
    // Not a JWT this runner can read; judged by nothing, so left alone.
    log.debug('Caught in refreshAdminApiToken(): ' + ((e && e.message) || e));
    log.debug('Leaving refreshAdminApiToken(). Unreadable token.');
    return;
  }
  const needMs = (Number(jobTimeoutMs) || 300000) + 5 * 60 * 1000;
  if (!expMs || expMs - Date.now() > needMs) {
    log.debug('Leaving refreshAdminApiToken(). Still good.');
    return;
  }
  if (!process.env.STS_ADMIN_API_CLIENT_SECRET) {
    process.env.STS_ADMIN_API_CLIENT_SECRET =
      process.env.ADMIN_API_CLIENT_SECRET;
  }
  try {
    process.env.STS_ADMIN_API_TOKEN =
      await adminApiToken.tokenFor(instance.url);
    log.info('replaced the /admin-api access token, which had ' +
             Math.max(0, Math.round((expMs - Date.now()) / 60000)) +
             ' minute(s) left — less than the next job may take');
  } catch (e) {
    log.warn('could not replace the /admin-api access token before it ' +
             'expires: ' + e.message + '. Jobs from here on may answer 401.');
  }
  log.debug('Leaving refreshAdminApiToken().');
}

async function main() {
  log.debug('Entering main().');
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || opts.unknown.length) {
    if (opts.unknown.length) {
      process.stdout.write('Unknown option(s): ' + opts.unknown.join(' ') +
                           '\n');
    }
    process.stdout.write(USAGE + '\n');
    process.exit(opts.unknown.length ? 2 : 0);
  }
  const wantUnit = opts.protocol !== 'only';
  const wantProtocol = opts.protocol === 'on' || opts.protocol === 'only';

  // ---- the jobs ---------------------------------------------------------
  const jobs = [];
  if (wantUnit) {
    testFiles(opts.only).forEach(function (file) {
      jobs.push({ suite: 'unit', name: file.replace(/\.js$/, ''), file: file,
                  dir: TESTS_DIR });
    });
  }
  // THE PROTOCOL JOBS ARE VENDORED HERE SINCE 2026-08-28 and are no longer
  // read out of a parent checkout, so there is no longer any way for them to
  // be absent: the files are in this repository. What used to be a warning
  // that thirteen jobs would be skipped is gone with the condition that
  // produced it.
  let missingDeps = [];
  if (wantProtocol) {
    let theirs = vendoredJobs(opts);
    if (opts.only.length) {
      theirs = theirs.filter(function (j) {
        return opts.only.some(function (p) { return j.file.indexOf(p) >= 0; });
      });
    }
    jobs.push.apply(jobs, theirs);
    if (theirs.length && !opts.list) {
      missingDeps = checkTestDependencies();
    }
  }
  if (!jobs.length) {
    // An empty run must never read as a pass — the same rule tests/run.js
    // holds, for the same reason.
    log.error('No jobs to run' + (opts.only.length
      ? ' matching ' + opts.only.join(', ') : '') + '. Nothing was checked.');
    process.exit(1);
  }
  if (opts.list) {
    jobs.forEach(function (j) {
      process.stdout.write(j.suite + '  ' + j.name + '\n');
    });
    process.exit(0);
  }

  // ---- where it is written ----------------------------------------------
  const runDir = path.join(opts.reportDir, RUN_ID);
  const logsDir = path.join(runDir, 'logs');
  fs.mkdirSync(logsDir, { recursive: true });

  // ---- coverage, if it was asked for ------------------------------------
  const wantCoverage = String(process.env.COVERAGE || '') === 'true';

  const coverageDir = path.resolve(process.env.COVERAGE_DIR ||
                                   path.join(REPO_ROOT, 'coverage'));
  const rawUnit = path.join(coverageDir, 'raw', 'unit');
  const rawProtocol = path.join(coverageDir, 'raw', 'protocol');
  if (wantCoverage) {
    // Emptied rather than added to: V8 names each file with a pid and a
    // timestamp, so an old run's files would merge into this one's report and
    // nothing would say they had.
    fs.rmSync(path.join(coverageDir, 'raw'), { recursive: true, force: true });
    fs.mkdirSync(rawUnit, { recursive: true });
    fs.mkdirSync(rawProtocol, { recursive: true });
    log.info('collecting V8 coverage into ' + path.join(coverageDir, 'raw'));
  }

  // ---- the service the protocol jobs drive ------------------------------
  //
  // Two shapes, and only the second is started here — see THE SERVICE UNDER
  // THE PROTOCOL JOBS in the header. `external` is what the rest of this
  // function reads to decide who stops it and what the report should say the
  // jobs ran against, because "a container the launcher owns" and "a process
  // this runner owns" are different sentences to a person reading a failure.
  let instance = null;
  let protocolWhy = '';
  const haveProtocolJobs = jobs.some(function (j) {
    return j.suite === 'protocol';
  });
  if (haveProtocolJobs && opts.serviceUrl) {
    // COVERAGE CANNOT COME OUT OF A SERVICE THIS RUNNER ONLY SPEAKS HTTP TO,
    // and saying so here is the whole handling. V8 writes its data from INSIDE
    // the process being measured, to a directory that process can write — so an
    // instrumented run has to be one this runner started. `./run-coverage.sh`
    // never passes --service-url for exactly this reason; somebody who set
    // STS_TEST_SERVICE_URL in their shell and then asked for coverage would
    // otherwise get a report whose protocol column was silently empty, which
    // reads as "the protocols are untested" rather than as "this run could not
    // look".
    //
    // IT IS NOT A STATEMENT ABOUT CONTAINERS, which is a distinction
    // ./run-coverage.sh's own containerized mode rests on: that run puts THIS
    // RUNNER in a container and lets it start the service as a child process
    // in there, so everything measured is again something this process
    // started. What cannot be measured is the service container NEXT DOOR.
    if (wantCoverage) {
      log.warn('coverage was asked for AND a service was handed in with ' +
               '--service-url. The protocol half of the coverage will be ' +
               'EMPTY: V8 collects from inside the process it measures, and ' +
               'this runner cannot reach into a container. Drop ' +
               '--service-url (or use ./run-coverage.sh, which does not pass ' +
               'it) for a coverage run.');
    }
    try {
      await waitForExternalService(opts.serviceUrl, log,
                                   Number(process.env.STS_TEST_SERVICE_WAIT_MS ||
                                          30000));
      instance = { url: opts.serviceUrl, external: true };
      log.info('driving the mock STS at ' + opts.serviceUrl +
               ' (started elsewhere; this runner will not stop it)');
    } catch (e) {
      log.error(e.message);
      protocolWhy = e.message;
      instance = null;
    }
  } else if (haveProtocolJobs) {
    // BEFORE the child starts, and that ordering is the whole of it — see
    // pinTheManagementApiSecret(). The seeded client's secret is minted at
    // startup and readable only through the API it unlocks, so this is the
    // last moment at which a run can choose one it will be able to present.
    pinTheManagementApiSecret();
    try {
      instance = await service.start({
        log: log,
        logFile: path.join(logsDir, '00-mock-sts-service.log'),
        logLevel: process.env.STS_LOG_LEVEL || '',
        // The appconfig file that service reads, when the caller named one.
        // STS_LOG_LEVEL alone does NOT quieten a run: the eight vendored
        // modules under common/vendored/ each build their own bunyan logger at
        // load from the CONFIG_FILE's logLevel, so a `debug` file goes on
        // writing every canonicalization however low this level is.
        // ./run-coverage.sh picks the file from the level and exports it
        // under this name.
        configFile: process.env.STS_TEST_CONFIG_FILE || '',
        coverageDir: wantCoverage ? rawProtocol : '',
        portBase: process.env.STS_TEST_PORT_BASE || ''
      });
    } catch (e) {
      log.error('could not start a mock STS for the protocol jobs: ' +
                e.message);
      protocolWhy = e.message;
      instance = null;
    }
  }

  // ---- the certificate the jobs will meet -------------------------------
  //
  // SINCE 2026-08-30 THE MOCK'S MAIN PORT IS TLS ON EVERY STACK HERE, and its
  // certificate and the Root above it are regenerated on every start in
  // development mode — so this is the
  // first moment at which the key can be known and the last one before a job
  // meets it. Both shapes of instance go through here: a container the launcher
  // brought up and a throwaway this runner started have exactly the same
  // problem, and having one of them trusted by the launcher's shell and the
  // other here would be two mechanisms to keep in agreement.
  //
  // A FAILURE TO FETCH IT IS NOT FATAL, deliberately. The jobs then run and
  // fail on the certificate, which is a worse message than this one — so this
  // one is logged at warn and says what it was doing. It is not made fatal
  // because the alternative failure mode is worse than the one it prevents: a
  // run aborted here reports nothing at all about a service that is answering
  // perfectly, and `STS_HTTPS=false` is a supported configuration in which
  // there is nothing to fetch and this whole block is a no-op.
  let trusted = { variables: {} };
  if (instance) {
    try {
      trusted = await trust.trustTheService(instance.url, runDir, log);
    } catch (e) {
      log.warn('could not fetch the mock STS\'s certificate from ' +
               instance.url + trust.CERTIFICATE_PATH + ' (' + e.message +
               '). The protocol jobs will run WITHOUT an anchor for it, so a ' +
               'failure naming DEPTH_ZERO_SELF_SIGNED_CERT or a browser ' +
               'interstitial is this and not the service.');
    }
  }

  // ---- the token the jobs will drive /admin-api with ---------------------
  //
  // ONLY FOR A SERVICE THIS RUNNER STARTED, and only when nobody handed one
  // in. A launcher that brought a container up minted its own before calling
  // this file — that is the ordinary path and this must not step on it.
  //
  // AN EXTERNAL SERVICE WITH NO TOKEN IS WARNED ABOUT RATHER THAN FIXED, and
  // the reason is the same ordering as above: that service chose its own
  // client secret while starting, this runner cannot know it, and reading it
  // back goes through the API that is asking for the token. Whoever started
  // the service is who can mint against it.
  if (instance && !instance.external && !process.env.STS_ADMIN_API_TOKEN) {
    await mintTheManagementApiToken(instance.url);
  } else if (instance && instance.external &&
             !process.env.STS_ADMIN_API_TOKEN) {
    log.warn('a service was handed in with --service-url and no ' +
             'STS_ADMIN_API_TOKEN came with it. /admin-api requires an ' +
             'access token, so every job that drives it will answer 401. ' +
             'Both launchers mint one; a stack started by hand needs ' +
             'tests/tools/admin-api-token.js run against it, or ' +
             'adminApi.authRequired=false.');
  }

  // ---- can the container-driven job(s) run? -------------------------------
  //
  // TWO WAYS, AND THE FIRST ONE IS THE ORDINARY ONE. A launcher that brought a
  // remote PEP up as part of its stack hands the job `XACML_PEP_URL`, and the
  // job then shells out to nothing at all — which is what makes this work in
  // the containerized stack, where the runner is itself a container with no
  // docker in it. Only a run with NO such container needs a daemon, because
  // then the job builds an image and starts one of its own.
  //
  // So the probe is skipped entirely when a PEP was provided. That ordering
  // matters: `haveDocker()` would answer NO inside the tests container and the
  // job would be skipped for the lack of something it was never going to use.
  const wantDocker = jobs.some(function (j) { return j.docker; });
  const pepProvided = !!process.env.XACML_PEP_URL;
  const dockerHere = (!wantDocker || pepProvided)
    ? { ok: true, provided: pepProvided }
    : haveDocker();
  if (wantDocker && pepProvided) {
    log.info('a remote PEP was provided at ' + process.env.XACML_PEP_URL +
             ' (realm ' + (process.env.XACML_PEP_REALM || '?') + '), so the ' +
             'container-driven job(s) drive it and need no docker here.');
  } else if (wantDocker && dockerHere.ok) {
    log.info('no remote PEP was provided, and docker ' + dockerHere.version +
             ' is answering — the container-driven job(s) will start one of ' +
             'their own.');
  }
  // ---- run them ---------------------------------------------------------
  const started = Date.now();
  const results = [];
  let n = 0;
  for (const job of jobs) {
    n++;
    const logName = String(n).padStart(2, '0') + '-' + slug(job.name) + '.log';
    job.logFile = path.join(logsDir, logName);
    job.logName = logName;
    // A JOB THAT COULD NOT BE RUN IS A FAILURE, NOT A SKIP, and this used to
    // be the other way round. The throwaway service failing to start left
    // thirteen jobs marked `skipped`, which the summary counts as passing —
    // so a run in which NOTHING was checked exited zero and said so in small
    // grey text. A skip is for something deliberately left out (--no-browser,
    // --only); an intended job that did not run is a failure, because the
    // thing it was going to check is unchecked either way and only one of
    // those two words makes somebody look.
    if (job.docker && !dockerHere.ok) {
      // A DELIBERATE EXCLUSION — see haveDocker() above for why this one is a
      // skip where everything else here is a failure. The reason travels with
      // it into the report, the JUnit and the summary, and it names what is
      // therefore unchecked rather than only what did not run.
      const why = 'no launcher provided a remote PEP (XACML_PEP_URL), so ' +
                  'this job would have to build an image and start a ' +
                  'container of its own — and no docker daemon answered (' +
                  dockerHere.why + '). ./run-tests.sh brings one up ' +
                  'as part of its stack and never takes this branch; a ' +
                  'run with no such stack — a bare run-report.js, or a ' +
                  'coverage run — is what does. The ' +
                  'remote XACML PEP therefore has NO end-to-end coverage in ' +
                  'this run: what stands is tests/xacml_pep.js, which loads ' +
                  'that container\'s modules in a child process and makes no ' +
                  'HTTP request, and sts_xacml_endpoints.js, where the TEST ' +
                  'impersonates a PEP and nothing evaluates what it pulled.';
      log.warn('[' + n + '/' + jobs.length + '] SKIPPING ' + job.name + ' — ' +
               why);
      results.push(Object.assign({}, job, {
        status: 'skipped', ms: 0, code: null, assertions: [],
        failures: [], why: why
      }));
      continue;
    }
    if (job.suite === 'protocol' && !instance) {
      const why = protocolWhy || 'no service to drive';
      results.push(Object.assign({}, job, {
        status: 'failed', ms: 0, code: null, assertions: [],
        failures: ['did not run: ' + why],
        why: why
      }));
      continue;
    }
    if (job.suite === 'unit') {
      job.cwd = REPO_ROOT;
      job.cmd = [process.execPath, path.join(TESTS_DIR, 'run.js'),
                 '--only=' + job.file];
      job.env = Object.assign({}, process.env);
      // The mode's own variables, taken back off — see STACK_ENV above. This
      // is what makes the unit half run identically in every mode rather
      // than accidentally so.
      STACK_ENV.forEach(function (name) {
        delete job.env[name];
      });
      if (wantCoverage) {
        job.env.NODE_V8_COVERAGE = rawUnit;
      }
    } else {
      // -------------------------------------------------------------------
      // **THE ANCHOR IS RE-READ BEFORE EVERY PROTOCOL JOB (2026-09-12), AND
      // IT IS NOT A PRECAUTION — IT IS THE FIX FOR A WHOLE RUN.**
      //
      // The certificate was fetched ONCE above, at the last moment before the
      // first job, which was right for as long as this service's certificate
      // could only change when the service restarted. It stopped being right
      // on 2026-09-11, when `/admin/pki` gave an operator a Root CA to
      // rebuild: `POST /admin-api/pki/build-root` replaces the Root, every
      // Intermediate and Issuing CA under it, AND the leaf this listener is
      // already serving — so a truststore pinned before that request is stale
      // the moment it returns.
      //
      // `sts_admin_api_operations.js` drives every declared operation of that
      // API, `build-root` among them. On 2026-09-12 that made the twenty-nine
      // jobs after it in the `memory` and `postgres` modes fail at the TLS
      // handshake with `unable to get local issuer certificate` — an error
      // that names a certificate and says nothing about the cause, on a
      // service that was answering perfectly the whole time.
      //
      // **RE-READING RATHER THAN ACCUMULATING.** The bundle is REPLACED, not
      // appended to: a truststore that kept every anchor this run has ever
      // seen would go on trusting a hierarchy the service has thrown away,
      // and this suite contains assertions about certificates being REFUSED.
      // One live certificate, exactly as trust.js's header argues.
      //
      // A failure here is not fatal for the reason the first fetch is not:
      // the job then runs and fails on the certificate, which is a worse
      // message than this one but is not a worse outcome than not running.
      // -------------------------------------------------------------------
      if (trusted.tls) {
        const fresh = await refreshTrust(instance.url, trusted);
        if (fresh) {
          trusted = fresh;
        }
      }
      await refreshAdminApiToken(instance,
        Math.max(opts.timeoutMs, Number(job.timeoutMs) || 0));
      job.cwd = job.dir;
      job.cmd = [process.execPath, path.join(job.dir, job.file)];
      job.env = Object.assign({}, process.env, {
        // These jobs read an appconfig file of their own for a log level, and
        // `./env/local.js` resolves against the cwd above — which is
        // tests/vendored/, where the vendored copy of that file sits.
        CONFIG_FILE: process.env.PARENT_CONFIG_FILE || './env/local.js',
        // THE MOCK UNDER TEST IS THIS REPOSITORY, WHICH IS THE ONE THING
        // VENDORING CHANGED FOR THESE JOBS.
        //
        // Several of them load the service's own modules in process rather than
        // driving them over HTTP — vc_did.js and the two ldp_vc jobs read the
        // DID and credential modules, sts_jws_verification.js the crypto one.
        // `module_paths.js` finds those by looking for an `sts/` directory
        // BESIDE the tests, because over there this repository is a submodule
        // at that path. Vendored here, there is no such directory: the modules
        // are at the repository root, one level up from tests/.
        //
        // `MOCK_STS_DIR` is that module's own documented override and takes
        // precedence over the submodule search, so this needs no edit to a
        // vendored file — which matters, because an edit here is overwritten
        // by the next --vendor-sync and would come back as four jobs failing
        // at load with a message about a gitlink.
        //
        // It warns that a run with this set "reflects a working copy rather
        // than the commit the gitlink points at". That sentence is written for
        // the parent's stack and reads oddly here, where a working copy is
        // exactly what is under test — ignore it rather than editing it out.
        MOCK_STS_DIR: REPO_ROOT,
        WSTRUST_STS_URL: instance.url,
        OID4VCI_ISSUER_URL: instance.url,
        // ---------------------------------------------------------------
        // WHERE THE DIRECTORY'S OWN SOCKET IS, FOR THE ONE JOB THAT DRIVES IT
        // (2026-09-06). `sts_directory_bulk_load_ldap.js` writes five
        // thousand entries over RFC 4511, and 389 is not published by
        // docker-compose.yml.
        //
        // THREE WAYS IT CAN BE ANSWERED AND THIS LINE IS THE THIRD.
        // ./run-tests.sh puts `ldap://sts:389` in the runner
        // container's environment (the runner is on the bridge, nothing is
        // published); ./local-run-tests.sh picked a free host port, layered
        // tests/docker-compose-ldap.yml and exported STS_LDAP_URL, until it
        // was removed on 2026-09-16. A launcher's answer arrives here as an
        // INHERITED variable, and the `||` below is what lets it win: this
        // object is assigned OVER process.env, so a bare assignment here
        // would overwrite the launcher's answer with a guess about a service
        // the launcher did not start.
        //
        // What it adds is the THROWAWAY case: every coverage run, and a bare
        // run with no --service-url. There the service is a child of this
        // process on a block of ports this runner chose, so nothing outside
        // knows where its directory is listening and only this line can say.
        // The port comes from `instance.ports` by NAME rather than as an
        // offset from `instance.base`, so a listener added to or removed from
        // the middle of that block cannot silently move it.
        STS_LDAP_URL: process.env.STS_LDAP_URL ||
          (instance.ports && instance.ports.LDAP_PORT
            ? 'ldap://localhost:' + instance.ports.LDAP_PORT
            : ''),
        // ---------------------------------------------------------------
        // THE DIRECTORY'S PORT UNDER THE NAME A JOB LOOKS IT UP BY, AND THAT
        // IS NOT THE NAME THE SERVICE READS IT FROM.
        //
        // The service takes `LDAP_PORT` (README.md's *Configuration* table is
        // the authority, and `service.js`'s PORT_VARS uses those spellings);
        // `sts_global_logout.js` reads **`STS_LDAP_PORT`**. Every other
        // listener in that block is spelt the same on both sides, so the loop
        // below covers it — this one has to be said, and saying it is what the
        // loop cannot do for itself.
        //
        // It matters because the failure is SILENT: the job dialled 389, the
        // bind was refused, it noted "LDAP bind did not sign in" and PASSED.
        // The assertion that a sign-out reaches a directory connection was
        // therefore not being made in any run that starts its own service.
        // ---------------------------------------------------------------
        STS_LDAP_PORT: process.env.STS_LDAP_PORT ||
          (instance.ports && instance.ports.LDAP_PORT
            ? String(instance.ports.LDAP_PORT)
            : '')
      // AND THE REST OF THE BLOCK, under the names they already share. See
      // chosenPorts(): a job that dials a DEFAULT port on the throwaway path
      // is a job driving nothing.
      }, chosenPorts(instance), {
      // THE TWO TRUST VARIABLES, AND THEY GO LAST SO NOTHING ABOVE CAN SHADOW
      // THEM. `NODE_EXTRA_CA_CERTS` is read by node ONCE at child start, which
      // is why it can only be handed to a job and never set for this runner;
      // `STS_SPKI_PIN` is read by tests/vendored/browser_flags.js and becomes
      // Chrome's --ignore-certificate-errors-spki-list, so the browser jobs
      // are covered by the same two lines as the node ones. An empty
      // object on a plain-http run, which adds nothing rather than adding an
      // empty variable — see tests/tools/trust.js.
      }, trusted.variables);
      // -------------------------------------------------------------------
      // THE MANAGEMENT API'S TOKEN, AND THE SHIM THAT PRESENTS IT.
      //
      // `/admin-api` requires an access token since 2026-09-09. A launcher
      // mints one and hands it here; `tools/attach-admin-token.js` is
      // preloaded into every job so that the ones that drive that API
      // authenticate without each growing an HTTP client of its own. That file
      // argues why it is a preload and what it deliberately leaves alone.
      //
      // APPENDED to any NODE_OPTIONS already set rather than replacing it: a
      // coverage run sets its own, and losing that would silently measure
      // nothing.
      // -------------------------------------------------------------------
      //
      // A TOKEN OF ITS OWN PER JOB SINCE 2026-09-17, and that is about
      // revocation. `/admin-api` refuses a REVOKED token since #36's
      // follow-ups, and three jobs drive `revoke-all` — the control they
      // exist to test — which revokes the run's token along with everything
      // else. One token for the whole run therefore died partway through and
      // every management-API job after it answered 401. Minting per job keeps
      // one job's revocation inside that job; the job that revokes refreshes
      // its own through `globalThis.stsAdminApiToken.refresh()`. A mint that
      // fails falls back to the run's token, which is what this line was.
      if (process.env.STS_ADMIN_API_TOKEN) {
        let mine = '';
        try {
          mine = await adminApiToken.tokenFor(instance.url || '');
        } catch (e) {
          log.debug('Caught while minting a token for ' + job.name + ': ' +
                    ((e && e.message) || e));
          mine = '';
        }
        job.env.STS_ADMIN_API_TOKEN = mine || process.env.STS_ADMIN_API_TOKEN;
        const preload = '--require ' +
          path.join(__dirname, 'attach-admin-token.js');
        job.env.NODE_OPTIONS = job.env.NODE_OPTIONS
          ? job.env.NODE_OPTIONS + ' ' + preload : preload;
      }
      // ------------------------------------------------------------------
      // A NEW CONNECTION PER REQUEST, IN THE `cluster` MODE (2026-09-14).
      //
      // That mode's load balancer picks a node per CONNECTION, and a job
      // whose client keeps its connection alive would talk to one node for
      // its whole run. `tools/fresh-connections.js` argues it; the launchers
      // set the variable for that mode and no other, so every other mode's
      // jobs start exactly as they did. Appended for the reason the token's
      // preload above is.
      // ------------------------------------------------------------------
      if (process.env.STS_TEST_FRESH_CONNECTIONS === '1') {
        const fresh = '--require ' +
          path.join(__dirname, 'fresh-connections.js');
        job.env.NODE_OPTIONS = job.env.NODE_OPTIONS
          ? job.env.NODE_OPTIONS + ' ' + fresh : fresh;
      }
      // ------------------------------------------------------------------
      // AND THE CLIENT SECRET, FOR THE ONE JOB THAT MINTS TOKENS OF ITS OWN.
      //
      // `sts_admin_api_auth.js` asserts the gate's refusals, which means
      // asking the token endpoint for a token with ONE scope, and for one
      // audienced at somebody else. The run's own token cannot be narrowed
      // after the fact — that is what a signature is for — so that job needs
      // the credential the token is minted with.
      //
      // **IT IS NOT AN ESCALATION AND THAT IS WHY IT IS HANDED TO EVERY JOB
      // RATHER THAN TO ONE.** Every job already receives a token carrying
      // both scopes, which is everything this API can do; the secret mints
      // more of those and nothing else. Passing it to one named job would
      // mean this file knowing which job is which, which is exactly the
      // coupling the manifest exists to avoid.
      //
      // It is per RUN and lives as long as one stack — both launchers
      // generate it — so it is not a value that outlives the thing it opens.
      // ------------------------------------------------------------------
      if (process.env.ADMIN_API_CLIENT_SECRET ||
          process.env.STS_ADMIN_API_CLIENT_SECRET) {
        job.env.STS_ADMIN_API_CLIENT_SECRET =
          process.env.STS_ADMIN_API_CLIENT_SECRET ||
          process.env.ADMIN_API_CLIENT_SECRET;
      }
      // Not on a protocol job: NODE_V8_COVERAGE there would collect the
      // coverage of the job's own test code, which is not what this report is
      // about. The service is the instrumented process there.
      delete job.env.NODE_V8_COVERAGE;
    }
    log.info('[' + n + '/' + jobs.length + '] ' + job.suite + ' — ' + job.name);
    /* eslint-disable no-await-in-loop */
    const result = await runJob(job, opts);
    /* eslint-enable no-await-in-loop */
    results.push(result);
    log.info('    ' + (result.status === 'passed' ? 'passed' : 'FAILED') +
             ' in ' + result.ms + 'ms' +
             (result.assertions.length ? ', ' + result.assertions.length +
              ' assertion(s)' : ''));
  }
  const wallMs = Date.now() - started;

  // The service goes down BEFORE the coverage is rendered, because under
  // coverage it writes its data as it exits and rendering before that would
  // report a protocol half that had not been written yet.
  //
  // AN EXTERNAL ONE IS NOT STOPPED HERE. Whoever started it stops it — the
  // launcher's own teardown, which also collects the container's log into
  // this run's logs directory. A second owner is how a run ends by taking
  // down a stack somebody had asked to keep (`--keep-stack`), and the
  // coverage ordering this comment is about does not apply to it anyway,
  // since nothing instrumented is inside it.
  if (instance && !instance.external) {
    await service.stop(instance, log);
  }

  // ---- coverage ---------------------------------------------------------
  let coverageLink = '';
  if (wantCoverage) {
    try {
      const rendered = coverage.render({
        log: log,
        inputs: [{ label: 'unit', dir: rawUnit },
                 { label: 'protocol', dir: rawProtocol }],
        outDir: coverageDir,
        root: REPO_ROOT
      });
      coverageLink = path.relative(runDir, rendered.htmlFile);
      log.info('coverage: ' + rendered.htmlFile);
    } catch (e) {
      // Never fatal. Coverage is a picture OF a run, and a run that passed
      // did not stop being a run that passed because the picture failed.
      log.error('could not render coverage: ' +
                (e && e.stack ? e.stack : e));
    }
  }

  // ---- the reports ------------------------------------------------------
  const meta = {
    runId: RUN_ID,
    host: os.hostname(),
    node: process.version,
    wallMs: wallMs,
    tree: describeTree(REPO_ROOT),
    // The protocol jobs are VENDORED COPIES in tests/vendored/ since
    // 2026-08-28, so they are at this tree's commit like everything else and
    // there is no second checkout to describe. `parentDir` and `parentTree`
    // are kept as empty strings rather than removed, so that an older
    // summary.json and this one have the same shape for anything reading both.
    parentDir: '',
    parentTree: { commit: '' },
    vendored: instance ? path.relative(REPO_ROOT, VENDORED_DIR) : '',
    serviceUrl: instance ? instance.url : '',
    // WHICH OF THE TWO SHAPES ran, so that a report read a week later says
    // what the jobs were actually pointed at rather than leaving it to be
    // inferred from a port number.
    serviceKind: instance ? (instance.external ? 'container' : 'in-process')
                          : '',
    protocolWhy: protocolWhy,
    coverage: coverageLink,
    commandLine: [path.basename(process.argv[0])].concat(
      process.argv.slice(1).map(function (a) {
        return a.indexOf(REPO_ROOT) === 0 ? path.relative(REPO_ROOT, a) : a;
      })).join(' ')
  };
  writeHtml(runDir, results, meta);
  writeXml(runDir, results, meta);
  fs.writeFileSync(path.join(runDir, 'summary.json'),
    JSON.stringify({ meta: meta, jobs: results.map(function (j) {
      return { suite: j.suite, name: j.name, status: j.status, ms: j.ms,
               code: j.code, assertions: j.assertions.length,
               assertionsFailed: j.assertions.filter(function (a) {
                 return !a.ok;
               }).length,
               failures: j.failures, why: j.why || '', log: j.logName };
    }) }, null, 2) + '\n');
  pointLatestAt(opts.reportDir, runDir);

  // ---- say what happened ------------------------------------------------
  const failed = results.filter(function (j) { return j.status === 'failed'; });
  const skipped =
      results.filter(function (j) { return j.status === 'skipped'; });
  const asserted = results.reduce(function (s, j) {
    return s + j.assertions.length;
  }, 0);
  log.info('---------------------------------------------------------------');
  log.info(results.length + ' job(s), ' + (results.length - failed.length -
           skipped.length) + ' passed, ' + failed.length + ' failed, ' +
           skipped.length + ' skipped, ' + asserted +
           ' assertion(s), ' + (wallMs / 1000).toFixed(1) + 's.');
  failed.forEach(function (j) {
    log.error('FAILED: ' + j.name + ' — ' + j.failures.join('; '));
  });
  skipped.forEach(function (j) {
    log.warn('SKIPPED: ' + j.name + ' — ' + j.why);
  });
  log.info('report: ' + path.join(runDir, 'report.html'));
  log.debug('Leaving main().');
  process.exit(failed.length ? 1 : 0);
  log.debug("Leaving main().");
}

if (require.main === module) {
  main().catch(function (e) {
    log.error(e && e.stack ? e.stack : String(e));
    process.exit(2);
  });
}

module.exports = { vendoredJobs: vendoredJobs, assertionOf: assertionOf,
                   // EXPORTED FOR tools/merge-report.js (2026-09-18), which
                   // folds a second run's jobs into this one's report and
                   // must draw it with the same writers rather than a copy.
                   writeHtml: writeHtml, writeXml: writeXml, slug: slug,
                   // EXPORTED FOR tests/unit_job_environment.js AND FOR
                   // NOTHING ELSE. The list it returns is what a unit job
                   // must not inherit, and a test that computed it for
                   // itself would pass while this file read modes.sh
                   // differently — which is the only way this can break.
                   stackDeploymentVariables: stackDeploymentVariables };
