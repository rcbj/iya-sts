'use strict';
//
// File: version.js
//
// ===========================================================================
// THE VERSION, M.N.O — AND THE THREE THINGS ABOUT IT THAT WOULD FAIL SILENTLY.
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

const ROOT = path.join(__dirname, '..');

// The source of a module with its FULL-LINE COMMENTS removed.
//
// **THIS EXISTS BECAUSE THE TEST FAILED ON ITSELF THE FIRST TIME IT RAN**, and
// the failure is worth keeping written down: `home/home.js` and
// `mgmt-api/admin_api.js` both explain, in a comment, that they USED to read
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
  return fs.readFileSync(path.join(ROOT, rel), 'utf8')
    .split('\n')
    .filter(function (line) { return !/^\s*\/\//.test(line); })
    .join('\n');
}

function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-version-'));
  try {
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
  t.log.info('=== the VERSION file is the single source of M.N ===');

  // -----------------------------------------------------------------------
  // 1. M.N COMES OFF THE FILE AT THE REPO ROOT, and the file has the shape the
  //    module's regular expression requires. A VERSION file with a stray
  //    third component, a `v` prefix or a trailing comment is ignored with a
  //    message on stderr and the version silently becomes 0.0 — which is the
  //    module's deliberate never-fail-a-build behaviour and is exactly why the
  //    FILE has to be checked rather than only the parser.
  // -----------------------------------------------------------------------
  const raw = fs.readFileSync(path.join(ROOT, version.VERSION_FILE), 'utf8');
  t.check(/^\d+\.\d+\s*$/.test(raw),
          'the repo-root VERSION file is M.N and nothing else',
          'read ' + JSON.stringify(raw));

  const record = version.resolve();
  t.equal(record.major + '.' + record.minor, raw.trim(),
          'resolve() reports the major.minor that file carries');
  t.check(record.version === record.major + '.' + record.minor + '.' +
          record.build,
          'the version is major.minor.build joined by dots',
          record.version);
  t.check(/^\d{14}$/.test(record.build) || !!process.env.BUILD_NUMBER,
          'the default build number is a 14-digit UTC instant',
          record.build);
  t.equal(record.stamped, false,
          'a computed record says it was NOT stamped, which is the ' +
          'difference between an artifact and a checkout being run');

  // -----------------------------------------------------------------------
  // 2. BUILD_NUMBER OVERRIDES THE INSTANT. This is what a CI system sets, and
  //    a service that ignored it would report a number nobody could match back
  //    to a build.
  // -----------------------------------------------------------------------
  t.log.info('=== BUILD_NUMBER ===');
  const savedBuild = process.env.BUILD_NUMBER;
  const savedCommit = process.env.GIT_COMMIT;
  try {
    process.env.BUILD_NUMBER = '4242';
    process.env.GIT_COMMIT = 'deadbeefcafe0000000000';
    const forced = version.resolve();
    t.equal(forced.build, '4242',
            'BUILD_NUMBER replaces the UTC build instant');
    t.equal(forced.version, raw.trim() + '.4242',
            'and it is the O of M.N.O');
    t.equal(forced.commit, 'deadbeefcafe',
            'GIT_COMMIT is taken as the commit and trimmed to twelve ' +
            'characters — the container build context carries no .git, so ' +
            'this is the only way an image can know one');
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

    const stamped = version.stamp(dir);
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
            'and it reports the same one again — restarting a container does ' +
            'not invent a new build number');
    t.equal(first.stamped, true,
            'a loaded record says it came off a stamp');

    // A stamp written by an older copy of this module has no `stamped` member.
    // It still came off a file, so it is one — that is a fact about where the
    // record was read from rather than about what the writer knew to say.
    const older = JSON.parse(
      fs.readFileSync(path.join(dir, version.STAMP_FILE), 'utf8'));
    delete older.stamped;
    fs.writeFileSync(path.join(dir, version.STAMP_FILE),
                     JSON.stringify(older, null, 2) + '\n');
    t.equal(version.load(dir).stamped, true,
            'a stamp written without the `stamped` member is still a stamp');

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
  //     because `home/home.js` is required at 6a and `mgmt-api/admin_api.js`
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
          'must not report two build numbers',
          version.load().version);
  t.equal(version.userAgent('x'),
          version.PRODUCT + '/' + version.load().version + ' (x)',
          'and the outbound User-Agent is built from that same record rather ' +
          'than from a fresh one');

  // -----------------------------------------------------------------------
  // 4. EVERY package.json IN THIS TREE CARRIES THE SAME M.N.
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
  const drawers = ['home/home.js', 'admin-ui/admin.js', 'portal/portal.js',
                   'mgmt-api/admin_api.js', 'sts_metadata.js'];
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
  ['federation/federation_http.js', 'ssf/ssf_http.js',
   'xacml/xacml_pep_http.js'].forEach(function (rel) {
    const src = codeOf(rel);
    t.check(/version'\)\.userAgent\(/.test(src) ||
            /userAgent\(/.test(src),
            rel + ' builds its User-Agent from common/version.js');
    t.check(!/'User-Agent':\s*'(mock-)?sts[ \/]/.test(src),
            rel + ' does not carry a hand-written product token');
  });
}

module.exports = {
  name: 'version',
  describe: 'M.N.O: the VERSION file, the build stamp, and one source for ' +
            'every surface that draws it',
  run: run
};
