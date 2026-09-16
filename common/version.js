#!/usr/bin/env node
// @ts-check
'use strict';
//
// File: common/version.js
//
// ===========================================================================
// THE APPLICATION VERSION, M.N.O — THE SAME SCHEME THE PARENT PROJECT USES.
//
// This is a port of `id-proto-debugger/client/version.js` rather than an
// invention, and that is the point: this service is a submodule of that
// project, its container is built beside that project's two, and a reader who
// has learnt to read one version string should not have to learn a second.
// What changed in the port is written down below, under "What is different
// here"; everything else is deliberately the same code doing the same thing.
//
//   M.N  major.minor, declared in the repo-root VERSION file (currently 0.1).
//        Bump it there — it is the single source of truth.
//   O    the build number: a value that identifies THIS build and no other.
//        By default it is the UTC build instant as YYYYMMDDHHMMSS, which is
//        unique per build, monotonically increasing, and self-describing (the
//        version alone tells you when the artifact was produced). Set
//        BUILD_NUMBER to override it — e.g. with a CI run number — in which
//        case keeping it unique and increasing is the caller's responsibility.
//
// **THE NUMBER IS FIXED WHEN AN ARTIFACT IS BUILT, NOT WHEN IT RUNS.** The
// image build stamps it into a `version.json` that ships with the artifact, so
// every page of a given deployment reports the same build and RESTARTING A
// CONTAINER DOES NOT INVENT A NEW ONE. That last is the whole reason the stamp
// exists rather than the version being computed at startup: a service that
// renumbered itself on every restart would report a build number that means
// nothing, and "which build is this" is the one question a version answers.
//
//   Dockerfile   runs `node common/version.js --stamp .` during the image
//                build, after the source is copied; server.js reads that file
//                through load() at startup.
//
// A bare `node server.js` from a checkout has no stamp and computes one, so a
// development run still reports something usable — it just reports the instant
// the PROCESS started rather than the instant an artifact was built, and
// nothing was built.
//
// ---------------------------------------------------------------------------
// WHAT IS DIFFERENT HERE, AND WHY
//
// 1. **IT LIVES IN `common/` AND NOT AT THE PACKAGE ROOT.** The root CLAUDE.md
//    says there are exactly two modules there and both earn it — `server.js`,
//    the shell, and `sts_metadata.js`, which must be required last. A third
//    would be a precedent rather than a file. So the MODULE is in `common/`
//    with every other thing more than one family reads, and the VERSION FILE
//    stays at the root, where a person bumping a release looks for it and
//    where the parent project's is.
//
// 2. **IT IS A LEAF AND MUST STAY ONE (rule 3).** It registers no route and
//    requires nothing from this repository — not `helpers.js`, not `config.js`
//    — so it can never close a require cycle and its position in the require
//    order is not a position. That matters more here than it did in the parent:
//    `home/home.ts` (6a), `admin-ui/admin.js` (18), `mgmt-api/admin_api.js`
//    (19), `portal/portal.ts`, `sts_metadata.js` (24), `server.js` itself and
//    every module that sends an outbound request all read it — modules spread
//    across the whole require order — and a version module that could drag a
//    route would be a version module that decided where routes go.
//
// 3. **THE `log` IS CONSOLE-BACKED, NOT bunyan.** The parent's reason was that
//    this file can run before any install has happened; here there is a second
//    one that is stronger — `helpers.js` owns the logger and requiring it from
//    here would break (2). The Entering/Leaving convention (see CLAUDE.md,
//    *Code style*) still applies, so this is the same call shape over
//    `console`. Debug output is off by default, so an ordinary run stays
//    quiet; flip DEBUG to follow a call through. The methods below are the one
//    place the convention cannot apply — a log line inside log.debug() is
//    infinite recursion.
//
// 4. **THE MANIFEST LIST IS TWO PATHS, NOT FOUR PROJECT NAMES.** The parent
//    holds four sibling projects under one root and keeps their package.json
//    versions in step. This repository is one package plus `xacml-pep/`, which
//    is a SECOND CONTAINER built from this same tree — so it ships with this
//    service and carries this service's M.N, for the same reason the parent's
//    `tests/` does.
//
// **AND ONE THING THAT IS DELIBERATELY NOT RECONCILED**, because it cannot be
// from inside this repository: the parent's `client/version.js` carries `sts`
// in its own MANIFESTS list and its `--sync-manifests` rewrites
// `sts/package.json` to the PARENT's M.N.0. That checkout is this repository,
// so after a parent sync its `package.json` says the parent's version and this
// one's says `0.1.0`. The two numbers answer different questions — "which
// release of the debugger is this submodule pinned into" against "which release
// of the mock STS is this" — and this file has no business editing the parent
// to settle it. `--check-manifests` here checks THIS tree only, and the sibling
// checkout at `../id-proto-debugger/sts` is read-only forever.
//
// Run directly to print or stamp:
//   node common/version.js                 -> 0.1.20260906143205
//   node common/version.js --json          -> the full record
//   node common/version.js --stamp <dir>   -> writes <dir>/version.json, prints it
//   node common/version.js --check-manifests  -> non-zero if a package.json is stale
//   node common/version.js --sync-manifests   -> rewrites stale package.json versions
// ===========================================================================

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

var DEBUG = false;
var LOG_TAG = "[version]";
// Rest parameters rather than `arguments` (#50, 2026-09-16): the type checker
// reads a function that names no parameter as taking none. What is printed is
// unchanged.
var log = {
  debug: function (...args) {
    if (!DEBUG) return;
    console.log(LOG_TAG, ...args);
  },
  info: function (...args) {
    console.log(LOG_TAG, ...args);
  },
  warn: function (...args) {
    console.warn(LOG_TAG, ...args);
  },
  error: function (...args) {
    console.error(LOG_TAG, ...args);
  }
};

const VERSION_FILE = 'VERSION';

// THE ERROR CODES BELOW ARE WRITTEN OUT AS `[STS-CORE-nnnn] ` RATHER THAN
// THROUGH `common/error_codes.js`'s `tag()`, and that is (2) above holding:
// this file requires nothing from the repository, and it is copied ALONE to the
// root of the `xacml-pep/` image, where a require of the registry would throw
// at load. The bracketed prefix is exactly what `tag()` produces, so a search
// for `[STS-` finds these lines with every other one.
const STAMP_FILE = 'version.json';

// THE PACKAGE ROOT: the directory the VERSION file is in. Every path below is
// resolved against it rather than against the working directory, because this
// module is read from modules in a dozen directories and by a
// `node common/version.js` run from anywhere.
//
// **IT IS FOUND RATHER THAN ASSUMED, AND THAT IS WHAT MAKES ONE COPY OF THIS
// FILE SERVE TWO IMAGES.** In this repository it is one level above `common/`.
// In the `xacml-pep/` image this file is copied to the container root as
// `version.js`, with `VERSION` beside it, so the root is this file's OWN
// directory — and a hard-coded `__dirname/..` there would be `/usr/src`, where
// `--stamp` would write a version.json nothing reads and `load()` would find
// none. Probing for the file that defines the root is the only arrangement in
// which the same module is correct in both layouts.
//
// The fallback when neither carries one is `__dirname/..`, so a tree with no
// VERSION file behaves exactly as before and readMajorMinor() reports the 0.0
// it is written to report.
function findRoot() {
  log.debug("Entering findRoot().");
  const candidates = [path.join(__dirname, '..'), __dirname];
  for (const dir of candidates) {
    try {
      fs.accessSync(path.join(dir, VERSION_FILE), fs.constants.R_OK);
      log.debug("Leaving findRoot().");
      return dir;
    } catch (e) {
      // Not this one. The first miss is normal in the container layout.
      log.debug("Caught in findRoot(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving findRoot().");
  return path.join(__dirname, '..');
}
const ROOT = findRoot();

// The VERSION file, in the root findRoot() settled on.
function readMajorMinor() {
  log.debug("Entering readMajorMinor().");
  const file = path.join(ROOT, VERSION_FILE);
  try {
    const raw = fs.readFileSync(file, 'utf8').trim();
    const m = raw.match(/^(\d+)\.(\d+)$/);
    if (m) {
      log.debug("Leaving readMajorMinor().");
      return { major: m[1], minor: m[2] };
    }
    // A file that is there and is not M.N. Said out loud rather than silently
    // becoming 0.0 — a `v0.1`, a trailing comment or a third component is the
    // likeliest way somebody breaks this, and the number would otherwise just
    // be wrong everywhere with nothing to say why.
    if (raw) {
      console.error('[STS-CORE-0039] [version] ignoring malformed ' + file +
          ': ' +
          '"' + raw +
                    '" (want M.N)');
    }
  } catch (e) {
    // No VERSION file in either candidate root. Falls through to 0.0 below.
    log.debug("Caught in readMajorMinor(): " + ((e && e.message) || e));
  }
  // NEVER FAIL A BUILD — OR A START — OVER THIS. An unknown major.minor is
  // still reportable, and a service that would not answer a Token Request
  // because it could not read a two-byte text file would be the worst trade in
  // the repository. Contrast the signing key, which IS fatal to lose: a wrong
  // version misinforms a reader, a wrong key invalidates every token this
  // service ever issued.
  console.error('[STS-CORE-0040] [version] no readable ' + VERSION_FILE +
                '; falling back to 0.0');
  log.debug("Leaving readMajorMinor().");
  return { major: '0', minor: '0' };
}

function utcStamp(d) {
  log.debug("Entering utcStamp().");
  const p = (n, w) => {
    log.debug("Entering p().");
    log.debug("Leaving p().");
    return String(n).padStart(w || 2, '0');
  };
  log.debug("Leaving utcStamp().");
  return '' + d.getUTCFullYear() + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) +
    p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds());
}

// Best-effort commit id, for the tooltip under every version string. Absent
// inside the container image (.git is in .dockerignore, so there is no history
// in the build context) unless GIT_COMMIT is passed in as a build argument.
function gitCommit() {
  log.debug("Entering gitCommit().");
  if (process.env.GIT_COMMIT) {
    log.debug("Leaving gitCommit().");
    return String(process.env.GIT_COMMIT).trim().substring(0, 12);
  }
  try {
    const out = execFileSync('git', ['rev-parse', '--short=12', 'HEAD'],
      { cwd: ROOT, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
    log.debug("Leaving gitCommit().");
    return out;
  } catch (e) {
    log.debug("Caught in gitCommit(): " + ((e && e.message) || e));
    // No git, no history, or a detached weirdness. The commit is provenance for
    // a tooltip and nothing depends on it, so an empty string is the answer
    // rather than a thrown error.
    log.debug("Leaving gitCommit().");
    return '';
  }
}

// Compute a fresh version record for a build happening now.
function resolve() {
  log.debug("Entering resolve().");
  const { major, minor } = readMajorMinor();
  const now = new Date();
  const build = (process.env.BUILD_NUMBER &&
      String(process.env.BUILD_NUMBER).trim())
    || utcStamp(now);
  const commit = gitCommit();
  log.debug("Leaving resolve().");
  return {
    version: major + '.' + minor + '.' + build,
    major: major,
    minor: minor,
    build: build,
    commit: commit,
    builtAt: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    // Whether this record came off a stamp or was computed just now. The two
    // mean different things — "this is the build that was made" against "this
    // is a checkout being run" — and every surface that draws the version says
    // which, because a reader comparing two instances needs to know that one of
    // them is not an artifact at all. load() overwrites this; see below.
    stamped: false
  };
}

// Human-readable provenance, for the tooltip beside the version.
function buildInfo(v) {
  log.debug("Entering buildInfo().");
  log.debug("Leaving buildInfo().");
  return 'Build ' + v.build + ' — ' + (v.stamped ? 'built ' : 'started ') +
    v.builtAt + (v.commit ? ' — commit ' + v.commit : '') +
    (v.stamped ? '' : ' — not a stamped build (running from a checkout)');
}

// Write the record next to the artifact so it ships with it.
function stamp(dir) {
  log.debug("Entering stamp().");
  const v = resolve();
  v.stamped = true;
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, STAMP_FILE), JSON.stringify(v, null, 2) +
                     '\n');
  } catch (e) {
    console.error('[STS-CORE-0041] [version] could not write ' +
                  path.join(dir, STAMP_FILE) +
                  ': ' + e.message);
  }
  log.debug("Leaving stamp().");
  return v;
}

// THE ONE RECORD THIS PROCESS REPORTS. Computed at most once.
//
// **THIS CACHE IS NOT AN OPTIMISATION AND IT WAS ADDED BECAUSE A TEST CAUGHT
// THE BUG IT PREVENTS.** Several modules call `load()` at require time, and
// in a CHECKOUT there is no stamp — so each of them computed its own record,
// stamping the instant IT was required. `tests/vendored/admin_api.js` found
// the front page reporting `0.1.20260907060910` while `/admin-api` reported
// `0.1.20260907060911`: one second apart, because `home/home.ts` is required
// at 6a and `mgmt-api/admin_api.js` at 19, and the modules between them took a
// second to load.
//
// A container never showed it — every module there reads the same stamped FILE
// — so this is the shape of defect that is invisible in the environment that
// matters most and routine in the one people develop in. And "one source" was
// never the property wanted: the property is ONE RECORD. Two modules reading
// the same source and computing separately agree right up until they do not.
//
// It is keyed on nothing because there is nothing to key on: the version
// cannot change while the process runs. Only the DEFAULT root is cached —
// `load(dir)` with an explicit directory is what `tests/version.js` uses to
// demonstrate the stamped and the unstamped case in one process, and caching
// that would make the second call a lie.
let cachedDefault = null;

// Read the record stamped at build time; compute one only if the artifact was
// never stamped (a bare `node server.js` from a checkout), so a served page
// always reports the build it came from. `dir` defaults to the package root,
// which is where the Dockerfile stamps — every caller in this service wants
// that, so none of them has to say it.
function load(dir) {
  log.debug("Entering load().");
  if (!dir && cachedDefault) {
    log.debug("Leaving load(). Cached.");
    return cachedDefault;
  }
  const where = dir || ROOT;
  try {
    const v = JSON.parse(fs.readFileSync(path.join(where, STAMP_FILE), 'utf8'));
    if (v && v.version) {
      // An older stamp has no `stamped` field. It came off a file, so it is
      // one — this is not the same question as whether the writer knew to say
      // so.
      v.stamped = true;
      if (!dir) {
        cachedDefault = v;
      }
      log.debug("Leaving load().");
      return v;
    }
  } catch (e) {
    // Not stamped. Entirely normal in a checkout, and the whole reason
    // resolve() exists as a fallback rather than this being an error.
    log.debug("Caught in load(): " + ((e && e.message) || e));
  }
  const computed = resolve();
  if (!dir) {
    cachedDefault = computed;
  }
  log.debug("Leaving load(). Computed.");
  return computed;
}

// --- the outbound User-Agent ------------------------------------------------
//
// This service makes several kinds of outbound request, each argued where it
// lives, and most of them reach somebody else's server: federation's, SSF's
// RFC 8935 push, XACML's change nudge, GNAP's push finish, an RFC 9101
// request_uri, an RFC 9728 metadata import, a SAML service provider's metadata
// and a CRL or OCSP fetch. Every one of them should say what dialled it and
// which build of it, because the person reading that access log is debugging
// an integration with a mock they did not install.
//
// **RFC 9110 product form**, `sts/<M.N.O> (<component>)`: one product token
// with a version, and the component in a comment. The version is not decoration
// there — "sts called my endpoint and sent the wrong thing" is answerable
// only if the request said which build did it.
//
// It is HERE rather than a string in each of those modules for the reason the
// rest of this file exists: one copy of the product token, so a rename or a
// version change cannot reach some of them and not the others.
//
// **THE TOKEN WAS `mock-sts` UNTIL 2026-09-12**, when the product name in
// every identifier this service stores and emits became `sts`. That was the
// rename this constant exists to make a one-line change, and it was. The
// package is still called mock-sts (the repository became iya-sts on
// 2026-09-15); this is the name on the wire, which is a different thing.
const PRODUCT = 'sts';

function userAgent(component) {
  log.debug("Entering userAgent(). component=" + component);
  const v = load();
  log.debug("Leaving userAgent().");
  return PRODUCT + '/' + v.version + (component ? ' (' + component + ')' : '');
}

// --- package.json manifests -------------------------------------------------
// Every package in this tree carries the same M.N in its package.json version,
// with the semver patch component pinned to 0 (the real build number lives in
// VERSION / version.json, and package.json must hold a valid semver). These
// helpers keep them in step with VERSION — a bump that updated only VERSION
// would otherwise leave them silently stale, which is exactly the drift this
// repository's endpoint and crypto reports exist to prevent one layer up.
//
// `xacml-pep/package.json` is here because that directory is a SECOND
// CONTAINER built from this same tree: it ships with this service, its engine
// is copied out of `xacml/` at image build time, and a version of its own would
// be a second release number for one release.
//
// **AND THAT CONTAINER IS STAMPED TOO, WHICH IT WAS NOT WHEN THIS FEATURE
// FIRST LANDED.** The argument against was that stamping it would mean putting
// THIS FILE — which reads files and shells out to git — inside
// `xacml-pep/common/`, the thirty-line shim whose entire value is that it makes
// "the XACML engine is a library with no I/O" a CHECKED claim rather than a
// comment. That argument was right about the shim and wrong about the
// conclusion: the PEP ALREADY DREW A VERSION on the PDP's console, and it was
// the hand-written label `'mock-sts xacml-pep, phase five'`. So "no stamp" was
// never "no version" — it was "a version that could not be true".
//
// The PLACEMENT is what resolves it, and it costs the shim nothing.
// `xacml-pep/Dockerfile` copies this file to the CONTAINER ROOT as
// `version.js`, with `VERSION` beside it, and stamps there. `./common/` in that
// image still holds exactly `helpers.js`, and `tests/xacml_pep.js` pins it:
// exactly one COPY may write into that directory. The shim's emptiness is
// still the evidence, and the PEP reports a real build.
const MANIFESTS = ['package.json', 'xacml-pep/package.json'];

function manifestVersion() {
  log.debug("Entering manifestVersion().");
  const { major, minor } = readMajorMinor();
  log.debug("Leaving manifestVersion().");
  return major + '.' + minor + '.0';
}

// [{ path, actual, expected, ok }] for each manifest present in the tree. In
// the service image `xacml-pep/` has been removed by the Dockerfile, so this is
// one entry there rather than two — absence is not drift.
function checkManifests() {
  log.debug("Entering checkManifests().");
  const want = manifestVersion();
  const out = [];
  for (const rel of MANIFESTS) {
    const file = path.join(ROOT, rel);
    let actual;
    try {
      actual = JSON.parse(fs.readFileSync(file, 'utf8')).version;
    } catch (e) {
      log.debug("Caught in checkManifests(): " + ((e && e.message) || e));
      continue;
    }
    out.push({ path: rel, actual: actual, expected: want,
               ok: actual === want });
  }
  log.debug("Leaving checkManifests(). " + out.length + " manifest(s).");
  return out;
}

// Rewrite any stale manifest (and its lock's root entry) in place.
function syncManifests() {
  log.debug("Entering syncManifests().");
  const want = manifestVersion();
  const changed = [];
  for (const entry of checkManifests()) {
    if (entry.ok) {
      continue;
    }
    const file = path.join(ROOT, entry.path);
    const text = fs.readFileSync(file, 'utf8');
    fs.writeFileSync(file, text.replace(/("version":\s*)"[^"]*"/, '$1"' + want +
                     '"'));
    const lockFile = file.replace(/package\.json$/, 'package-lock.json');
    try {
      const lock = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
      lock.version = want;
      if (lock.packages && lock.packages['']) {
        lock.packages[''].version = want;
      }
      fs.writeFileSync(lockFile, JSON.stringify(lock, null, 2) + '\n');
    } catch (e) {
      // No lock, or unreadable. The manifest is what matters — npm regenerates
      // the lock's root entry on the next install.
      log.debug("Caught in syncManifests(): " + ((e && e.message) || e));
    }
    changed.push(entry.path + ': ' + entry.actual + ' -> ' + want);
  }
  log.debug("Leaving syncManifests(). " + changed.length + " changed.");
  return changed;
}

module.exports = { resolve, stamp, load, buildInfo, userAgent, checkManifests,
    syncManifests, manifestVersion, PRODUCT, STAMP_FILE, VERSION_FILE,
    MANIFESTS };

if (require.main === module) {
  const args = process.argv.slice(2);
  const i = args.indexOf('--stamp');
  if (i >= 0) {
    const dir = args[i + 1] || ROOT;
    const v = stamp(path.isAbsolute(dir) ? dir : path.join(ROOT, dir));
    console.log(v.version);
  } else if (args.indexOf('--check-manifests') >= 0) {
    const stale = checkManifests().filter((m) => !m.ok);
    stale.forEach((m) => console.error('[version] ' + m.path + ' is ' +
                  m.actual + ', expected ' + m.expected));
    if (stale.length) {
      console.error('[version] run: node common/version.js --sync-manifests');
      process.exit(1);
    }
    console.log('all package.json versions match ' + manifestVersion());
  } else if (args.indexOf('--sync-manifests') >= 0) {
    const changed = syncManifests();
    changed.forEach((c) => console.log('[version] ' + c));
    console.log(changed.length ? 'synced ' + changed.length +
                ' manifest(s)' : 'already in sync');
  } else if (args.indexOf('--json') >= 0) {
    console.log(JSON.stringify(resolve(), null, 2));
  } else {
    console.log(resolve().version);
  }
}
