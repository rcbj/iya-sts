// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: version.js
//
// ===========================================================================
// THE VERSION, M.N.O.<build> — AND THE THINGS ABOUT IT THAT WOULD FAIL
// SILENTLY.
//
// **THE RELEASE IS M.N.O, read whole from VERSION (1.0.0, #1298), AND THE
// BUILD NUMBER FOLLOWS IT (#1317)**: the UTC build instant as YYYYMMDDHHMMSS
// by default, or — for a build flagged `STS_RELEASE=true` — the BUILD_NUMBER
// it names, so the 1.0.0 release built with BUILD_NUMBER=0 is `1.0.0.0`. A
// release flag without a valid number is refused at the stamp, and without
// the flag BUILD_NUMBER is ignored. This file holds all of it, and that the
// stamp — number, commit and instant — survives a restart.
//
// `common/version.js` is a small module and the temptation is to leave it
// untested. What makes it worth a file is that every one of its failure modes
// is QUIET: a version that is wrong still renders, still serves, still answers
// 200. Nothing anywhere goes red — a reader is simply told the wrong thing
// about which build they are looking at, which is the one question a version
// exists to answer.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Two of the three claims here need to CHOOSE HOW THE PROCESS WAS STARTED,
// which is that file's rule for what belongs in this directory rather than in
// the parent project's suite:
//
//   * **A stamp is preferred over a computed record.** Demonstrating it means a
//     directory with a `version.json` in it and a directory without, twice,
//     which over HTTP would mean building two images.
//   * **The manifests are in step with VERSION.** That is a property of the
//     SOURCE TREE, not of a running service — no endpoint reports it and none
//     should.
//
// The third — that every surface reports the SAME version — is asserted here
// rather than over HTTP for a reason worth stating, because it is the one that
// looks like it belongs in the other suite: what would go wrong is not a page
// saying the wrong number but a page reading a DIFFERENT SOURCE for it, which
// is exactly what was true before this existed (the home page and the
// management API both read `package.json`, whose patch component is a
// placeholder, so every build ever made reported `0.9.0`). A test that fetched
// two pages and compared two strings would have passed on that. This one
// compares the SOURCE.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');

const version = require('../common/version');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'version',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The source of a module with its FULL-LINE COMMENTS removed.
//
// **THIS EXISTS BECAUSE THE TEST FAILED ON ITSELF THE FIRST TIME IT RAN**, and
// the failure is worth keeping written down: `home/home.ts` and
// `mgmt-api/admin_api.ts` both explain, in a comment, that they USED to read
// `require('../package.json').version` and why that was wrong. A check that
// greps the raw file for the old pattern therefore fails on the two files that
// document having stopped doing it — which would leave a maintainer with the
// choice of deleting the explanation or deleting the check.
//
// Only lines whose first non-whitespace is `//` are dropped, and nothing else
// is touched. A cleverer stripper would have to know about strings, and the
// strings in this repository are full of `https://` — cutting at the first
// `//` on a line would truncate half of them and make this check quietly
// weaker rather than louder.
function codeOf(rel) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return fs.readFileSync(path.join(ROOT, rel), 'utf8')
    .split('\n')
    .filter(function (line) { return !/^\s*\/\//.test(line); })
    .join('\n');
}

function withTempDir(fn) {
  log.debug("Entering withTempDir().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-version-'));
  try {
    log.debug("Leaving withTempDir().");
    return fn(dir);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // A directory that could not be removed is not a failed assertion. Said
      // rather than swallowed silently.
      process.stderr.write('version test: could not remove ' + dir + ': ' +
                           e.message + '\n');
    }
  }
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the VERSION file is the single source of M.N.O ===');

  // -----------------------------------------------------------------------
  // 1. M.N.O COMES OFF THE FILE AT THE REPO ROOT, WHOLE, and the file has the
  //    shape the module's regular expression requires. A VERSION file with a
  //    `v` prefix, a trailing comment, a pre-release suffix or the old
  //    two-component `0.1` is ignored with a message on stderr and the
  //    version silently becomes 0.0.0 — which is the module's deliberate
  //    never-fail-a-build behaviour and is exactly why the FILE has to be
  //    checked rather than only the parser.
  // -----------------------------------------------------------------------
  const raw = fs.readFileSync(path.join(ROOT, version.VERSION_FILE), 'utf8');
  t.check(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\s*$/.test(raw),
          'the repo-root VERSION file is M.N.O and nothing else',
          'read ' + JSON.stringify(raw));
  t.equal(raw.trim(), '1.0.0',
          'and it says 1.0.0, the release rcbj named on #1298 — change this ' +
          'line with the file when the release is bumped');

  const record = version.resolve();
  t.equal([record.major, record.minor, record.patch].join('.'), raw.trim(),
          'resolve() breaks the release out as major, minor and patch, ' +
          'exactly as that file carries it');
  t.check(/^\d{14}$/.test(String(record.build)),
          'the build number of a record computed now is the UTC instant as ' +
          'YYYYMMDDHHMMSS (#1317)', record.build);
  t.equal(record.version, raw.trim() + '.' + record.build,
          'and the version is the release followed by that build number');
  t.equal(record.build, record.builtAt.replace(/[^0-9]/g, ''),
          'the build number is the build instant, the same second as ' +
          '`builtAt`');
  t.equal(record.release, false,
          'a record computed from a checkout is never a release');
  t.equal(record.stamped, false,
          'a computed record says it was NOT stamped, which is the ' +
          'difference between an artifact and a checkout being run');

  // -----------------------------------------------------------------------
  // 1b. A MALFORMED VERSION FILE IS 0.0.0, NEVER A FAILURE. Shown against a
  //     copy of the module in a directory of its own, because the module
  //     finds its VERSION beside itself or one level up and reads it at
  //     resolve() — the same arrangement the remote PEP's image relies on.
  // -----------------------------------------------------------------------
  t.log.info('=== a malformed VERSION falls back ===');
  withTempDir(function (top) {
    // One level down, so the parent the module probes first is this test's
    // own empty directory; and VERSION written BEFORE the require, because
    // the module settles on its root when it is loaded.
    const dir = path.join(top, 'pep');
    fs.mkdirSync(dir);
    fs.writeFileSync(path.join(dir, version.VERSION_FILE), '2.7.1\n');
    const copy = path.join(dir, 'version.js');
    fs.copyFileSync(path.join(ROOT, 'common', 'version.js'), copy);
    const loaded = require(copy);
    const results = [];
    ['0.1', 'v1.0.0', '1.0.0-rc.1', '01.0.0', '1.0.0.0', '1.0'].forEach(
      function (bad) {
        fs.writeFileSync(path.join(dir, version.VERSION_FILE), bad + '\n');
        const quiet = console.error;
        console.error = function () {
          // The module's STS-CORE-0039/0040 lines, expected here and kept off
          // the run's output; restored on the next line whatever happens.
        };
        try {
          results.push(bad + ' -> ' + loaded.resolve().version);
        } finally {
          console.error = quiet;
        }
      });
    t.check(results.every(function (r) {
      return / -> 0\.0\.0\.\d{14}$/.test(r);
    }),
            'a VERSION that is not exactly M.N.O is reported as 0.0.0 and ' +
            'nothing throws — a version may never stop the service starting',
            results.join('; '));
    fs.writeFileSync(path.join(dir, version.VERSION_FILE), '2.7.1\n');
    t.check(/^2\.7\.1\.\d{14}$/.test(loaded.resolve().version),
            'and a well-formed one beside the module is read whole',
            loaded.resolve().version);
    delete require.cache[require.resolve(copy)];
  });

  // -----------------------------------------------------------------------
  // 2. THE BUILD NUMBER'S RULE (#1317), AND GIT_COMMIT IS STILL THE COMMIT.
  //
  //    The date and time by default; a RELEASE build names its own; a release
  //    flag with no valid number is REFUSED; and without the flag BUILD_NUMBER
  //    is IGNORED, so a CI system's variable of that name cannot pass an
  //    ordinary build off as a release. Each is asked of stamp() with an
  //    environment of its own, because stamp() is the one reader of the flag.
  // -----------------------------------------------------------------------
  t.log.info('=== the build number: date and time, or a release\'s own ===');
  withTempDir(function (dir) {
    const ordinary = version.stamp(dir, {});
    t.check(/^\d{14}$/.test(ordinary.build) && ordinary.release === false &&
            ordinary.version === raw.trim() + '.' + ordinary.build,
            'a stamp with no flag is a date-and-time build: ' +
            'M.N.O.YYYYMMDDHHMMSS, not a release', ordinary.version);

    const stray = version.stamp(dir, { BUILD_NUMBER: '4242' });
    t.check(/^\d{14}$/.test(stray.build) && stray.release === false &&
            stray.version.indexOf('4242') < 0,
            'BUILD_NUMBER WITHOUT the release flag is ignored: the build ' +
            'number is still the instant', stray.version);
    const notRelease = version.stamp(dir, { STS_RELEASE: 'false',
                                            BUILD_NUMBER: '7' });
    t.check(notRelease.release === false && notRelease.build !== '7',
            'and so with STS_RELEASE=false', notRelease.version);

    const release = version.stamp(dir, { STS_RELEASE: 'true',
                                         BUILD_NUMBER: '0' });
    t.equal(release.version, raw.trim() + '.0',
            'a release build with BUILD_NUMBER=0 is ' + raw.trim() + '.0');
    t.check(release.build === '0' && release.release === true &&
            release.stamped === true,
            'and records build "0" and release true',
            JSON.stringify(release));
    const onDisk = JSON.parse(
      fs.readFileSync(path.join(dir, version.STAMP_FILE), 'utf8'));
    t.check(['version', 'major', 'minor', 'patch', 'build', 'release',
             'commit', 'builtAt', 'stamped'].every(function (k) {
               return k in onDisk;
             }) && onDisk.version === raw.trim() + '.0' &&
            onDisk.release === true,
            'version.json holds version, major, minor, patch, build, ' +
            'release, commit, builtAt and stamped', JSON.stringify(onDisk));
    t.equal(version.stamp(dir, { STS_RELEASE: 'TRUE', BUILD_NUMBER: ' 12 ' })
              .version, raw.trim() + '.12',
            'the flag is read without case and the number trimmed');

    // Every refusal: the flag with no number, an empty one, a leading zero,
    // a negative, not a number, and a flag that is neither true nor false.
    // Each throws STS-CORE-0164 naming both variables and writes nothing.
    fs.rmSync(path.join(dir, version.STAMP_FILE));
    const refusals = [
      { STS_RELEASE: 'true' },
      { STS_RELEASE: 'true', BUILD_NUMBER: '' },
      { STS_RELEASE: 'true', BUILD_NUMBER: '01' },
      { STS_RELEASE: 'true', BUILD_NUMBER: '-1' },
      { STS_RELEASE: 'true', BUILD_NUMBER: '1.0' },
      { STS_RELEASE: 'true', BUILD_NUMBER: 'abc' },
      { STS_RELEASE: 'yes', BUILD_NUMBER: '0' }
    ].map(function (env) {
      try {
        version.stamp(dir, env);
        return JSON.stringify(env) + ' -> stamped';
      } catch (e) {
        log.debug("Caught in run(): " + ((e && e.message) || e));
        const named = e.errorCode === 'STS-CORE-0164' &&
          /STS_RELEASE/.test(e.message) &&
          (/BUILD_NUMBER/.test(e.message));
        return JSON.stringify(env) + (named ? ' -> refused' : ' -> ' +
                                      e.message);
      }
    });
    t.check(refusals.every(function (r) { return / -> refused$/.test(r); }),
            'a release flag without a valid BUILD_NUMBER — or a flag that is ' +
            'neither true nor false — is REFUSED with STS-CORE-0164, naming ' +
            'both variables', refusals.join('; '));
    t.check(!fs.existsSync(path.join(dir, version.STAMP_FILE)),
            'and a refused stamp writes nothing');
  });

  // The command line the Dockerfiles run, in a child: a refusal is a
  // NON-ZERO EXIT, which is what fails the image build at its RUN.
  withTempDir(function (dir) {
    const cp = require('child_process');
    const cli = path.join(ROOT, 'common', 'version.js');
    const env = Object.assign({}, process.env, { STS_RELEASE: 'true' });
    delete env.BUILD_NUMBER;
    const refused = cp.spawnSync(process.execPath, [cli, '--stamp', dir],
                                 { env: env, encoding: 'utf8' });
    t.check(refused.status !== 0 && /STS-CORE-0164/.test(refused.stderr) &&
            /BUILD_NUMBER/.test(refused.stderr),
            '`--stamp` with STS_RELEASE=true and no BUILD_NUMBER exits ' +
            'non-zero naming the variables',
            'status ' + refused.status + ': ' + refused.stderr.trim());
    env.BUILD_NUMBER = '0';
    const released = cp.spawnSync(process.execPath, [cli, '--stamp', dir],
                                  { env: env, encoding: 'utf8' });
    t.check(released.status === 0 &&
            released.stdout.trim() === raw.trim() + '.0',
            'and with BUILD_NUMBER=0 it exits 0 printing ' + raw.trim() + '.0',
            'status ' + released.status + ': ' + released.stdout.trim());
  });

  t.log.info('=== GIT_COMMIT, buildInfo() and buildId() ===');
  const savedBuild = process.env.BUILD_NUMBER;
  const savedCommit = process.env.GIT_COMMIT;
  try {
    process.env.BUILD_NUMBER = '4242';
    process.env.GIT_COMMIT = 'deadbeefcafe0000000000';
    const forced = version.resolve();
    t.check(forced.build !== '4242' && forced.release === false,
            'resolve() reads no BUILD_NUMBER: a checkout is never a release',
            forced.version);
    t.equal(forced.commit, 'deadbeefcafe',
            'GIT_COMMIT is taken as the commit and trimmed to twelve ' +
            'characters — the container build context carries no .git, so ' +
            'this is the only way an image can know one');
    t.check(version.buildInfo(forced).indexOf('deadbeefcafe') >= 0 &&
            version.buildInfo(forced).indexOf(forced.builtAt) >= 0 &&
            version.buildInfo(forced).indexOf('Build ' + forced.build) === 0,
            'buildInfo() names the build number, the build instant and the ' +
            'commit', version.buildInfo(forced));
    const asRelease = Object.assign({}, forced,
                                    { build: '0', release: true });
    t.check(version.buildInfo(asRelease).indexOf('Release build 0') === 0,
            'and says when the build is a release',
            version.buildInfo(asRelease));
    t.equal(version.buildId(forced),
            forced.builtAt.replace(/[^0-9]/g, '') + '-deadbeefcafe',
            'buildId() is the build instant and the commit, for keying a ' +
            'cache by build — two release builds both numbered 0 still ' +
            'differ there');
  } finally {
    if (savedBuild === undefined) {
      delete process.env.BUILD_NUMBER;
    } else {
      process.env.BUILD_NUMBER = savedBuild;
    }
    if (savedCommit === undefined) {
      delete process.env.GIT_COMMIT;
    } else {
      process.env.GIT_COMMIT = savedCommit;
    }
  }

  // -----------------------------------------------------------------------
  // 3. THE STAMP IS PREFERRED, AND IT IS THE WHOLE REASON THE STAMP EXISTS.
  //
  //    A service that recomputed its version at startup would report a
  //    different build number every time its container restarted — which makes
  //    "which build is this" unanswerable in exactly the situation where it is
  //    asked, because a restart is what somebody does when they suspect the
  //    build. The assertion is therefore not "load() returns something" but
  //    "load() returns the SAME thing twice across what looks like a restart".
  // -----------------------------------------------------------------------
  t.log.info('=== the stamp survives a restart ===');
  withTempDir(function (dir) {
    const unstamped = version.load(dir);
    t.equal(unstamped.stamped, false,
            'with no stamp in the directory, load() computes a record and ' +
            'says so');

    const stamped = version.stamp(dir, { STS_RELEASE: 'true',
                                         BUILD_NUMBER: '3' });
    t.check(fs.existsSync(path.join(dir, version.STAMP_FILE)),
            'stamp() writes ' + version.STAMP_FILE + ' into the directory',
            dir);
    t.equal(stamped.stamped, true, 'the record it returns says it is stamped');

    // TWO loads, which is what a restart is from this module's point of view.
    const first = version.load(dir);
    const second = version.load(dir);
    t.equal(first.version, stamped.version,
            'load() reports the version that was stamped rather than a fresh ' +
            'one');
    t.equal(second.version, first.version,
            'and it reports the same one again');
    t.check(first.builtAt === stamped.builtAt &&
            second.builtAt === stamped.builtAt &&
            first.commit === stamped.commit &&
            first.build === '3' && second.build === '3' &&
            first.release === true,
            'and the same BUILD — the stamped number, release flag, instant ' +
            'and commit, so restarting a container does not invent a new ' +
            'build', first.version + ' ' + first.builtAt + ' ' + first.commit);
    t.equal(first.stamped, true,
            'a loaded record says it came off a stamp');

    // A stamp written by an older copy of this module has no `stamped` member.
    // It still came off a file, so it is one — that is a fact about where the
    // record was read from rather than about what the writer knew to say.
    const older = JSON.parse(
      fs.readFileSync(path.join(dir, version.STAMP_FILE), 'utf8'));
    t.check(older.build === '3' && older.version === raw.trim() + '.3' &&
            !!older.builtAt,
            'the stamp on disk is the full version with its build number',
            JSON.stringify(older));
    delete older.stamped;
    fs.writeFileSync(path.join(dir, version.STAMP_FILE),
                     JSON.stringify(older, null, 2) + '\n');
    t.equal(version.load(dir).stamped, true,
            'a stamp written without the `stamped` member is still a stamp');

    // A STAMP A #1298 BUILD WROTE: the bare release, no `build`, no
    // `release`. It is still read, reporting the version it was written
    // with, and is not a release.
    fs.writeFileSync(path.join(dir, version.STAMP_FILE), JSON.stringify({
      version: raw.trim(), major: record.major, minor: record.minor,
      patch: record.patch, commit: 'abc', builtAt: '2026-11-03T00:00:00Z',
      stamped: true }, null, 2) + '\n');
    const v1298 = version.load(dir);
    t.check(v1298.version === raw.trim() && !v1298.build &&
            v1298.release === false && v1298.stamped === true,
            'a stamp from a #1298 build (no `build`) is still read, ' +
            'reporting the plain M.N.O', JSON.stringify(v1298));
    t.check(version.buildInfo(v1298).indexOf('Built ') === 0,
            'and buildInfo() says it as it was, with no build number',
            version.buildInfo(v1298));

    // A CORRUPT stamp must not stop the service. This module is read at
    // require time by five modules including the console's shell, so a throw
    // here is a service that does not start — over a file whose entire job is
    // to be reported in a footer.
    fs.writeFileSync(path.join(dir, version.STAMP_FILE), 'not json at all');
    const recovered = version.load(dir);
    t.check(!!recovered.version && recovered.stamped === false,
            'an unreadable stamp falls back to a computed record rather than ' +
            'throwing — nothing about the version may stop this service ' +
            'starting',
            recovered.version);
  });

  // -----------------------------------------------------------------------
  // 3b. ONE RECORD PER PROCESS, WHICH IS NOT THE SAME CLAIM AS ONE SOURCE.
  //
  //     This is the assertion for a defect that was real and shipped for the
  //     length of one test run. Six modules call `load()` at require time and
  //     a CHECKOUT has no stamp, so each of them computed its own record —
  //     stamping the instant it happened to be required. The front page said
  //     `0.1.20260907060910` and `/admin-api` said `0.1.20260907060911`,
  //     because `home/home.ts` is required at 6a and `mgmt-api/admin_api.ts`
  //     at 19 and the modules in between took a second to load.
  //
  //     A container never showed it: every module there reads one stamped
  //     file. So the check has to be made against the UNSTAMPED path, which is
  //     the one this test process is on.
  // -----------------------------------------------------------------------
  t.log.info('=== one record per process ===');
  t.check(version.load() === version.load(),
          'load() with no directory returns the SAME record every time — six ' +
          'modules read it at require time and two of them a second apart ' +
          'must not report two builds',
          version.load().version);
  t.equal(version.userAgent('x'),
          version.PRODUCT + '/' + version.load().version + ' (x)',
          'and the outbound User-Agent is built from that same record rather ' +
          'than from a fresh one');

  // -----------------------------------------------------------------------
  // 4. EVERY package.json IN THIS TREE CARRIES THE SAME M.N.O (#1298; it
  //    was M.N.0 while the version's third component was a build number) —
  //    the release, never the build number (#1317).
  //
  //    A bump that edited VERSION and nothing else leaves them stale, and
  //    nothing at runtime would notice: no surface reports a manifest version
  //    any more. This is the check that makes `--sync-manifests` a step
  //    somebody is TOLD to run rather than one they have to remember.
  // -----------------------------------------------------------------------
  t.log.info('=== the package.json manifests ===');
  const manifests = version.checkManifests();
  t.check(manifests.length >= 1,
          'checkManifests() found the manifests it names',
          manifests.map(function (m) { return m.path; }).join(', '));
  t.equal(version.manifestVersion(), raw.trim(),
          'the version a manifest must carry is VERSION\'s, exactly');
  manifests.forEach(function (m) {
    t.check(m.ok, m.path + ' carries ' + version.manifestVersion(),
            'it says ' + m.actual + ' — run: node common/version.js ' +
            '--sync-manifests');
  });

  // -----------------------------------------------------------------------
  // 5. ONE SOURCE FOR EVERY SURFACE.
  //
  //    This is the assertion that would have caught the state this module
  //    replaced. Five modules draw a version — the front page, the console's
  //    shell, the portal's shell, the management API and the service metadata
  //    page — and until this existed two of them read `package.json`, whose
  //    third component is a placeholder. The check is on the SOURCE and not on
  //    the rendered string, because two pages reading two different sources
  //    agree perfectly right up until the moment they stop.
  // -----------------------------------------------------------------------
  t.log.info('=== one source for every surface ===');
  // The portal's version is `/account-api`'s to answer since #568.
  const drawers = ['home/home.ts', 'admin-ui/admin.ts',
                   'account-api/account_api.ts',
                   'mgmt-api/admin_api.ts', 'sts_metadata.ts',
                   'report/report_api.ts'];
  drawers.forEach(function (rel) {
    const src = codeOf(rel);
    t.check(/require\((['"])[^'"]*common\/version\1\)/.test(src),
            rel + ' takes its version from common/version.js');
    // The old source, and it must not come back. `package.json`'s version is
    // M.N.0 — a valid semver whose patch is a placeholder — so a surface
    // reading it reports a release and never a build.
    t.check(!/require\((['"])\.\.?\/?[^'"]*package\.json\1\)\s*\.version/
              .test(src),
            rel + ' does not read the version out of package.json');
  });

  // The three outbound requesters say who is calling and which build. Same
  // argument as above: the string is built in one place, so the check is that
  // each site uses that place rather than that three strings happen to match.
  t.log.info('=== the outbound User-Agent ===');
  const ua = version.userAgent('federation');
  t.equal(ua, version.PRODUCT + '/' + version.load().version + ' (federation)',
          'userAgent() is RFC 9110 product form with the component in a ' +
          'comment');
  t.check(version.userAgent().indexOf('(') < 0,
          'and with no component it is the bare product token',
          version.userAgent());
  ['federation/federation_http.ts', 'ssf/ssf_http.ts',
   'xacml/xacml_pep_http.ts'].forEach(function (rel) {
    const src = codeOf(rel);
    t.check(/version'\)\.userAgent\(/.test(src) ||
            /userAgent\(/.test(src),
            rel + ' builds its User-Agent from common/version.js');
    t.check(!/'User-Agent':\s*'(mock-)?sts[ \/]/.test(src),
            rel + ' does not carry a hand-written product token');
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'version',
  describe: 'M.N.O.<build>: the VERSION file read whole, the date-and-time ' +
            'or release build number, the stamp surviving a restart, and ' +
            'one source for every surface that draws it',
  run: run
};
