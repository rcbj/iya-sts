#!/usr/bin/env node
// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: common/version.js
//
// ===========================================================================
// THE APPLICATION VERSION, M.N.O.<build> — A RELEASE AND A BUILD NUMBER
// (#1298, #1317).
//
//   M.N.O  major.minor.patch, declared WHOLE in the repo-root VERSION file
//          (1.0.0 since 2026-11-04, rcbj's decision on #1298). Bump it there
//          — it is the single source of truth for the RELEASE, and
//          package.json carries exactly it.
//   build  the build number, appended as a fourth component: the version
//          every surface draws is `M.N.O.<build>`.
//
// **THE BUILD NUMBER (#1317).** rcbj, 2026-11-04: "there continues to be the
// usual build number based on date + time by default, unless it is flagged
// as a release version, which the build number will be specified." So:
//
//   * BY DEFAULT it is the UTC build instant as YYYYMMDDHHMMSS — unique per
//     build, increasing and self-describing, the parent project's rule and
//     this file's until #1298: `1.0.0.20261104151200`.
//   * A RELEASE build is FLAGGED (`STS_RELEASE=true`) and NAMES its number
//     (`BUILD_NUMBER`, a non-negative integer with no leading zero): the
//     1.0.0 release is `BUILD_NUMBER=0`, so `1.0.0.0`. A release flag with
//     no valid number is REFUSED (`STS-CORE-0164`): `--stamp` exits non-zero
//     and the image does not build, because a "release" carrying a date is
//     exactly the artifact nobody can name afterwards.
//   * **WITHOUT THE FLAG, BUILD_NUMBER IS IGNORED**, and the stamp says so
//     on stdout. Until #1298 it overrode the date on its own, and a CI system
//     may export a variable of that name for its own purposes: a stray one
//     must not make an ordinary build look like a release, nor let two
//     builds share a number.
//
// #1298 retired the build number for a day (the version was the bare
// release); #1317 brought it back as a FOURTH component, so the release
// itself stays M.N.O, untouched, and a release build reads as the release
// followed by the number it was given.
//
// **THE NUMBER IS FIXED WHEN AN ARTIFACT IS BUILT, NOT WHEN IT RUNS.** The
// image build stamps it into a `version.json` that ships with the artifact,
// beside the commit (GIT_COMMIT, or the checkout's HEAD), the build instant
// (`builtAt`) and whether it is a release, so every page of a deployment
// reports the same build and RESTARTING A CONTAINER DOES NOT INVENT A NEW
// ONE. `buildId()` joins the commit and the instant into the one opaque
// string a cache can be keyed by — the static surfaces' catalogs are — and
// it differs between two builds even when both are `1.0.0.0`.
//
//   Dockerfile   runs `node common/version.js --stamp .` during the image
//                build, after the source is copied, with STS_RELEASE and
//                BUILD_NUMBER passed through as build arguments; server.js
//                reads that file through load() at startup.
//
// A bare `node server.js` from a checkout has no stamp and computes one, so a
// development run still reports something usable — its build number and
// `builtAt` are the instant the PROCESS started rather than the instant an
// artifact was built, it is never a release (only `--stamp` reads the flag),
// and `stamped: false` says so.
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
//    `home/home.ts` (6a), `admin-ui/admin.ts` (18), `mgmt-api/admin_api.ts`
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
// 4. **THE MANIFEST LIST IS ONE PATH, NOT FOUR PROJECT NAMES.** The parent
//    holds four sibling projects under one root and keeps their package.json
//    versions in step. This repository is one package; `xacml-pep/` is a
//    SECOND CONTAINER built from this same tree and reads the same VERSION
//    (see MANIFESTS below).
//
// 5. **THE RELEASE IS M.N.O AND THE BUILD NUMBER A FOURTH COMPONENT (#1298,
//    #1317).** The parent's scheme is M.N plus a build number; this
//    service's release is a whole semantic version read from VERSION, and
//    the build number follows it, decided as above.
//
// **AND ONE THING THAT IS DELIBERATELY NOT RECONCILED**, because it cannot be
// from inside this repository: the parent's `client/version.js` carries `sts`
// in its own MANIFESTS list and its `--sync-manifests` rewrites
// `sts/package.json` to the PARENT's M.N.0. That checkout is this repository,
// so after a parent sync its `package.json` says the parent's version and this
// one's says this service's. The two numbers answer different questions —
// "which release of the debugger is this submodule pinned into" against "which
// release of IYA STS is this" — and this file has no business editing the
// parent to settle it. `--check-manifests` here checks THIS tree only, and the sibling
// checkout at `../id-proto-debugger/sts` is read-only forever.
//
// Run directly to print or stamp:
//   node common/version.js                 -> 1.0.0.20261104151200
//   node common/version.js --json          -> the full record
//   node common/version.js --stamp <dir>   -> writes <dir>/version.json, prints
//                                             the version
//   STS_RELEASE=true BUILD_NUMBER=0 node common/version.js --stamp <dir>
//                                          -> 1.0.0.0, a release build; exits
//                                             non-zero with no valid number
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

/**
 * The name of the file at the package root that declares M.N.O.
 */
const VERSION_FILE = 'VERSION';

// THE ERROR CODES BELOW ARE WRITTEN OUT AS `[STS-CORE-nnnn] ` RATHER THAN
// THROUGH `common/error_codes.js`'s `tag()`, and that is (2) above holding:
// this file requires nothing from the repository, and it is copied ALONE to the
// root of the `xacml-pep/` image, where a require of the registry would throw
// at load. The bracketed prefix is exactly what `tag()` produces, so a search
// for `[STS-` finds these lines with every other one.
/**
 * The name of the file a build stamps its version record into.
 */
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
// VERSION file behaves exactly as before and readRelease() reports the 0.0.0
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

// A SEMANTIC VERSION, M.N.O and nothing else: three non-negative integers,
// none with a leading zero (Semantic Versioning 2.0.0, section 2). A
// pre-release or build-metadata suffix is NOT accepted, because nothing here
// needs one and every reader of the version — the User-Agent, the catalogs'
// addresses, the PEP's comparison with the PDP — would have to be taught what
// it means.
const RELEASE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

// The VERSION file, in the root findRoot() settled on.
function readRelease() {
  log.debug("Entering readRelease().");
  const file = path.join(ROOT, VERSION_FILE);
  try {
    const raw = fs.readFileSync(file, 'utf8').trim();
    const m = raw.match(RELEASE);
    if (m) {
      log.debug("Leaving readRelease().");
      return { major: m[1], minor: m[2], patch: m[3] };
    }
    // A file that is there and is not M.N.O. Said out loud rather than
    // silently becoming 0.0.0 — a `v1.0.0`, a trailing comment, the old
    // two-component `0.1` or a `-rc1` suffix is the likeliest way somebody
    // breaks this, and the number would otherwise just be wrong everywhere
    // with nothing to say why.
    if (raw) {
      console.error('[STS-CORE-0039] [version] ignoring malformed ' + file +
          ': ' +
          '"' + raw +
                    '" (want M.N.O)');
    }
  } catch (e) {
    // No VERSION file in either candidate root. Falls through to 0.0.0 below.
    log.debug("Caught in readRelease(): " + ((e && e.message) || e));
  }
  // NEVER FAIL A BUILD — OR A START — OVER THIS. An unknown release is
  // still reportable, and a service that would not answer a Token Request
  // because it could not read a six-byte text file would be the worst trade in
  // the repository. Contrast the signing key, which IS fatal to lose: a wrong
  // version misinforms a reader, a wrong key invalidates every token this
  // service ever issued.
  console.error('[STS-CORE-0040] [version] no readable ' + VERSION_FILE +
                '; falling back to 0.0.0');
  log.debug("Leaving readRelease().");
  return { major: '0', minor: '0', patch: '0' };
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

// The UTC instant as YYYYMMDDHHMMSS — the default build number (#1317).
function utcStamp(d) {
  log.debug("Entering utcStamp().");
  const p = (n) => {
    log.debug("Entering p().");
    log.debug("Leaving p().");
    return String(n).padStart(2, '0');
  };
  log.debug("Leaving utcStamp().");
  return '' + d.getUTCFullYear() + p(d.getUTCMonth() + 1) +
    p(d.getUTCDate()) + p(d.getUTCHours()) + p(d.getUTCMinutes()) +
    p(d.getUTCSeconds());
}

// A RELEASE'S BUILD NUMBER: a non-negative integer, written the way Semantic
// Versioning writes a component — digits, no leading zero except `0` itself
// — so `1.0.0.0` and `1.0.0.7` are the only spellings and `1.0.0.007` is
// not a third one.
const BUILD_NUMBER = /^(0|[1-9]\d*)$/;

// THE RELEASE FLAG'S TWO VALUES. Anything else is refused rather than read
// as one of them: `STS_RELEASE=1` or `=yes` may well mean "release", and
// guessing either way would build the wrong artifact without a word.
const RELEASE_FLAG = { 'true': true, 'false': false, '': false };

/**
 * Decides a STAMPED build's number from the environment (#1317): the UTC
 * build instant by default, or — when `STS_RELEASE` is `true` — the
 * `BUILD_NUMBER` the release names.
 *
 * Without the release flag BUILD_NUMBER is IGNORED, so a stray CI variable
 * cannot pass an ordinary build off as a release.
 * @param env - the environment to read, `process.env` when omitted
 * @param now - the build instant
 * @returns `{ ok: true, build, release, ignored }`, where `ignored` is the
 *   BUILD_NUMBER that was set and not used, or `{ ok: false, problem }`
 *   naming both variables
 */
function buildNumberFrom(env, now) {
  log.debug("Entering buildNumberFrom().");
  const e = env || process.env;
  const flag = String(e.STS_RELEASE == null ? '' : e.STS_RELEASE).trim()
    .toLowerCase();
  const given = String(e.BUILD_NUMBER == null ? '' : e.BUILD_NUMBER).trim();
  if (!Object.prototype.hasOwnProperty.call(RELEASE_FLAG, flag)) {
    log.debug("Leaving buildNumberFrom(). Bad flag.");
    return { ok: false,
      problem: 'STS_RELEASE is "' + flag + '"; it must be true (a release ' +
        'build, which names its BUILD_NUMBER) or false (the default: the ' +
        'build number is the UTC build instant)' };
  }
  if (RELEASE_FLAG[flag]) {
    if (!BUILD_NUMBER.test(given)) {
      log.debug("Leaving buildNumberFrom(). No release number.");
      return { ok: false,
        problem: 'STS_RELEASE=true marks a release build, and a release ' +
          'names its build number: BUILD_NUMBER must be a non-negative ' +
          'integer with no leading zero (e.g. BUILD_NUMBER=0), and it is ' +
          (given ? '"' + given + '"' : 'not set') };
    }
    log.debug("Leaving buildNumberFrom(). Release.");
    return { ok: true, build: given, release: true, ignored: '' };
  }
  log.debug("Leaving buildNumberFrom(). Date and time.");
  return { ok: true, build: utcStamp(now), release: false, ignored: given };
}

/**
 * Computes a fresh version record for a build happening now.
 *
 * The version is VERSION's M.N.O followed by the build number — the UTC
 * instant as YYYYMMDDHHMMSS unless `options` names a release's. Only
 * stamp() passes options; a record computed at startup from a checkout is
 * never a release. The record is marked `stamped: false`.
 * @param options - optional; `{ build, release, now }` decided by stamp()
 * @returns `{ version, major, minor, patch, build, release, commit, builtAt,
 *   stamped }`
 */
function resolve(options) {
  log.debug("Entering resolve().");
  const o = options || {};
  const { major, minor, patch } = readRelease();
  const now = o.now || new Date();
  const build = o.build || utcStamp(now);
  const commit = gitCommit();
  log.debug("Leaving resolve().");
  return {
    version: major + '.' + minor + '.' + patch + '.' + build,
    major: major,
    minor: minor,
    patch: patch,
    build: build,
    release: o.release === true,
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

/**
 * Describes a version record's provenance in one line, for the tooltip
 * beside a drawn version.
 *
 * @param v - a version record from load() or resolve()
 * @returns the build number and whether it is a release, when it was built
 *   or started, the commit, and whether the record is a stamped build
 */
function buildInfo(v) {
  log.debug("Entering buildInfo().");
  // A stamp written by a #1298 build has no `build`: it is said as it was.
  const head = v.build
    ? (v.release ? 'Release build ' : 'Build ') + v.build + ' — '
    : '';
  log.debug("Leaving buildInfo().");
  return head + (v.stamped ? 'Built ' : 'Started ') + v.builtAt +
    (v.commit ? ' — commit ' + v.commit : '') +
    (v.stamped ? '' : ' — not a stamped build (running from a checkout)');
}

// ONE OPAQUE STRING FOR ONE BUILD, for what has to be KEYED by the build
// rather than by the release: the static surfaces' catalogs are served
// `immutable` under `?v=<this>` (`common/public_assets.ts`), and two builds of
// 1.0.0 carrying different words must not share an address a browser keeps
// for a year. It is the commit and the build instant, which are already the
// record's own fields; it is never drawn as a version and nobody should parse
// it.
/**
 * Joins a record's build instant and commit into one opaque identifier of
 * that build, for keying a cache by build rather than by release.
 *
 * @param v - optional; a version record, this process's when omitted
 * @returns the identifier, e.g. `20261104120000-0123456789ab`
 */
function buildId(v) {
  log.debug("Entering buildId().");
  const r = v || load();
  const at = String(r.builtAt || '').replace(/[^0-9]/g, '');
  log.debug("Leaving buildId().");
  return (at || '0') + (r.commit ? '-' + r.commit : '');
}

// Write the record next to the artifact so it ships with it.
/**
 * Computes a version record, marks it stamped and writes it as version.json
 * into a directory, so it ships with the artifact.
 *
 * The build number is buildNumberFrom()'s: the build instant, or a
 * release's own number. A release flag without a valid number THROWS
 * (`STS-CORE-0164`) and writes nothing — that refusal is what stops an
 * image building; a failure to write is logged, not thrown, as it always
 * was.
 * @param dir - the directory to write into, created if missing
 * @param env - optional; the environment to read STS_RELEASE and
 *   BUILD_NUMBER from, `process.env` when omitted
 * @returns the record written
 */
function stamp(dir, env) {
  log.debug("Entering stamp().");
  const now = new Date();
  const decided = buildNumberFrom(env, now);
  if (!decided.ok) {
    const refusal = new Error('[STS-CORE-0164] [version] refusing to stamp ' +
                              'a build: ' + decided.problem);
    /** @type {any} */ (refusal).errorCode = 'STS-CORE-0164';
    log.debug("Leaving stamp(). Refused.");
    throw refusal;
  }
  if (decided.ignored) {
    // Said, not refused: BUILD_NUMBER is a common CI variable, and an
    // ordinary build that happens to inherit one is still an ordinary build.
    log.info('BUILD_NUMBER=' + decided.ignored + ' is ignored: this is not ' +
             'a release build (STS_RELEASE is not true), so the build ' +
             'number is the UTC build instant');
  }
  const v = resolve({ build: decided.build, release: decided.release,
                      now: now });
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
// stamping the instant IT was required. `tests/protocol/admin_api.js` found
// the front page reporting `0.1.20260907060910` while `/admin-api` reported
// `0.1.20260907060911`: one second apart, because `home/home.ts` is required
// at 6a and `mgmt-api/admin_api.ts` at 19, and the modules between them took a
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
/**
 * Returns the version this process reports: the stamped record if the
 * artifact has one, otherwise one computed now.
 *
 * With no directory the result is cached for the life of the process, so
 * every module reports the same record.
 * @param dir - optional; the directory to read version.json from, the
 *   package root when omitted
 * @returns the version record
 */
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
      // Nor a `release` (#1317): a stamp written before it — a #1298 build,
      // whose version is the bare M.N.O and which has no `build` — was never
      // a release build, and reports its version as it was written.
      v.release = v.release === true;
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
// **RFC 9110 product form**, `sts/<M.N.O.build> (<component>)`: one product
// token
// with the full version (#1317), and the component in a comment. The version
// is not decoration
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
// package is called iya-sts (the repository became iya-sts on 2026-09-15,
// the package on 2026-10-01); this is the name on the wire, which is a
// different thing.
/**
 * The product token this service names itself by on the wire.
 */
const PRODUCT = 'sts';

/**
 * Builds the outbound User-Agent, `sts/<M.N.O.build> (<component>)` in
 * RFC 9110 product form.
 *
 * @param component - optional; what is making the request, put in the comment
 * @returns the User-Agent header value
 */
function userAgent(component) {
  log.debug("Entering userAgent(). component=" + component);
  const v = load();
  log.debug("Leaving userAgent().");
  return PRODUCT + '/' + v.version + (component ? ' (' + component + ')' : '');
}

// --- package.json manifests -------------------------------------------------
// Every package in this tree carries VERSION's M.N.O as its package.json
// version, exactly (#1298; until then it was M.N.0, the patch a placeholder
// for a build number package.json had nowhere to put). The build number is
// not in it (#1317): npm's semver has three components, and the release is
// what a package names. These helpers keep
// them in step with VERSION — a bump that updated only VERSION
// would otherwise leave them silently stale, which is exactly the drift this
// repository's endpoint and crypto reports exist to prevent one layer up.
//
// `xacml-pep/package.json` WAS here until #444 (2026-10-05): that container
// is a Rust binary now, built from the workspace in `rust/`, and it stamps its
// own `version.json` with `sts-core::version` — a port of this file, reading
// the same `VERSION` — so it reports this service's release and no second
// number. Its crates carry their own `version` in `Cargo.toml`, which nothing
// reads at runtime and nothing here keeps in step: a crate's version is
// Cargo's, the container's is VERSION's.
/**
 * The package.json files, relative to the package root, whose version must
 * follow VERSION.
 */
const MANIFESTS = ['package.json'];

/**
 * Returns the version every package.json should carry: VERSION's M.N.O.
 *
 * @returns the semver string
 */
function manifestVersion() {
  log.debug("Entering manifestVersion().");
  const { major, minor, patch } = readRelease();
  log.debug("Leaving manifestVersion().");
  return major + '.' + minor + '.' + patch;
}

// [{ path, actual, expected, ok }] for each manifest present in the tree. In
// the service image `xacml-pep/` has been removed by the Dockerfile, so this is
// one entry there rather than two — absence is not drift.
/**
 * Compares each manifest present in the tree against manifestVersion().
 *
 * A manifest that is absent or unreadable is left out rather than reported.
 * @returns one `{ path, actual, expected, ok }` per manifest found
 */
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
/**
 * Rewrites any stale manifest's version in place, and its lock file's root
 * entry where there is one.
 *
 * @returns one line per manifest changed, `path: old -> new`
 */
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

/**
 * The application version, M.N.O.<build>: the release read whole from the
 * VERSION file, and the build number — the UTC build instant, or a release
 * build's own (#1317).
 *
 * The build number, the commit and the build instant are fixed when an
 * artifact is built and stamped into version.json beside it. Every surface
 * that draws a version reads it here. Run directly it stamps, checks or
 * syncs the manifests.
 * @namespace
 */
module.exports = { resolve, stamp, load, buildInfo, buildId, userAgent,
    buildNumberFrom, checkManifests,
    syncManifests, manifestVersion, PRODUCT, STAMP_FILE, VERSION_FILE,
    MANIFESTS };

if (require.main === module) {
  const args = process.argv.slice(2);
  const i = args.indexOf('--stamp');
  if (i >= 0) {
    const dir = args[i + 1] || ROOT;
    try {
      const v = stamp(path.isAbsolute(dir) ? dir : path.join(ROOT, dir));
      console.log(v.version);
    } catch (e) {
      // A release flag without a valid BUILD_NUMBER (#1317): the message
      // names both variables, and the non-zero exit is what fails the image
      // build at its `RUN`.
      log.debug("Caught in --stamp: " + ((e && e.message) || e));
      console.error((e && e.message) || e);
      process.exit(1);
    }
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
