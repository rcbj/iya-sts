// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: host_platform.js
//
// ===========================================================================
// THE SCRIPTS A PERSON RUNS ON THEIR OWN MACHINE RUN UNDER CYGWIN TOO (#512).
//
// tests/tools/host-platform.sh is the one place a launcher learns whether it
// is on Linux or on Windows, and what follows from that: hostPath() for every
// host path a native docker.exe or node.exe is handed, HOST_USER_ARGS for
// `--user`, and a directory of shims, first on PATH, that run the Windows
// programs with the CR of each CRLF removed. Its header argues each one.
//
// WHAT THIS FILE PINS:
//
//   1. on LINUX the helper changes nothing: hostPath() is the identity,
//      HOST_USER_ARGS is the `--user uid:gid` the launchers always passed,
//      and PATH is untouched — so every run on the machines that run the
//      suite today is the run it was;
//   2. under CYGWIN (a fake `uname` and `cygpath`, since no Windows machine
//      runs this suite) hostPath() converts, HOST_USER_ARGS is empty, the
//      shims are first on PATH exactly once however often the helper is
//      sourced, and MSYS's argument rewriting is off;
//   3. a shim finds the real program rather than itself, strips the CR from
//      every line, keeps the program's exit status, reaches a `.cmd`-only
//      program through cmd.exe, and leaves a byte stream (`docker save`)
//      alone;
//   4. every host launcher sources the helper, and none of them hands docker
//      a host path in a bind mount without hostPath() — the regression a
//      new `-v "${DIR}:/x"` would be;
//   5. .gitattributes turns end-of-line conversion off for the whole tree, and
//      no shell script here carries a CR, which is what a Windows checkout
//      with core.autocrlf=true would otherwise give every image built from it.
//
// WHY IN PROCESS. Nothing here is a service's behaviour; it is a shell's,
// and the only run that would otherwise notice is somebody's on Windows.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'host_platform',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const HELPER = path.join(ROOT, 'tests', 'tools', 'host-platform.sh');
const SHIMS = path.join(ROOT, 'tests', 'tools', 'windows');

// Every script that runs on a person's machine. clean.sh and utilities/ are
// in .dockerignore, so in the tests image they are absent and skipped; on a
// checkout they are checked like the rest.
const HOST_SCRIPTS = [
  'run-tests.sh',
  'run-coverage.sh',
  'run-jsdoc.sh',
  'docker-npm-test.sh',
  'clean.sh',
  'deploy/aws/terraform-local.sh',
  'deploy/gcp/terraform-local.sh',
  'deploy/azure/terraform-local.sh',
  'deploy/multicloud/terraform-local.sh',
  'deploy/aws/bootstrap-state.sh',
  'deploy/gcp/bootstrap-state.sh',
  'deploy/azure/bootstrap-state.sh',
  'deploy/aws/run-suite.sh',
  'deploy/aws/convert-to-cells.sh',
  'tests/tools/rehearse-cell-conversion.sh',
  'tests/tools/build-corpora-image.sh',
  'tests/eudi-wallet-poc/create-wallet-user.sh',
  'utilities/run.sh',
  'utilities/bulk-import.sh',
  'utilities/sessions-1m/run-sessions.sh',
  'utilities/sessions-1m/run-set-passwords.sh',
  'utilities/sessions-1m/run-setup.sh',
  'utilities/sessions-1m/run-teardown.sh',
  'utilities/sessions-1m/soak-check.sh'
];

function write(file, text) {
  log.debug("Entering write().");
  fs.writeFileSync(file, text, { mode: 0o755 });
  log.debug("Leaving write().");
}

// A bash -c, with PATH as given, answering stdout, stderr and the status.
function bash(script, pathValue) {
  log.debug("Entering bash().");
  const env = Object.assign({}, process.env, { PATH: pathValue });
  delete env.MSYS_NO_PATHCONV;
  delete env.MSYS2_ARG_CONV_EXCL;
  const r = childProcess.spawnSync('bash', ['-c', script],
    { env: env, encoding: 'latin1', stdio: ['ignore', 'pipe', 'pipe'] });
  log.debug("Leaving bash().");
  return { out: r.stdout || '', err: r.stderr || '', status: r.status };
}

// A directory that pretends to be Cygwin: a `uname` that says so, a
// `cygpath` that maps /x to C:/cygwin64/x (and -w/-u to themselves, which is
// enough for the shim's .cmd path), the "real" Windows programs the shims
// are to find — each printing CRLF — and a cmd.exe that runs the batch file
// it is given.
function fakeCygwin() {
  log.debug("Entering fakeCygwin().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'host-platform-'));
  write(path.join(dir, 'uname'),
        '#!/bin/sh\necho CYGWIN_NT-10.0-19045\n');
  write(path.join(dir, 'cygpath'),
        '#!/bin/bash\nmode="$1"; shift\n[ "$1" = "--" ] && shift\n' +
        'case "$mode" in\n  -m) printf "C:/cygwin64%s\\n" "$1" ;;\n' +
        '  *) printf "%s\\n" "$1" ;;\nesac\n');
  // docker: CRLF lines, then the status a caller must see.
  write(path.join(dir, 'docker'),
        '#!/bin/bash\nif [ "$1" = "save" ]; then printf "tar\\r\\n"; ' +
        'exit 0; fi\nprintf "healthy\\r\\nsecond\\r\\n"; exit 3\n');
  // A program that exists ONLY as a batch file, as Windows installs gcloud
  // and az. Under a name of its own, so this machine's real gcloud, if it has
  // one, is not what the shim finds.
  write(path.join(dir, 'iya-batch-512.cmd'),
        '#!/bin/bash\nprintf "project-%s\\r\\n" "$*"\n');
  write(path.join(dir, 'cmd.exe'),
        '#!/bin/bash\n[ "$1" = "/d" ] && [ "$2" = "/c" ] || exit 9\n' +
        'shift 2\nexec bash "$@"\n');
  log.debug("Leaving fakeCygwin().");
  return dir;
}

// ---------------------------------------------------------------------------
// 1. LINUX: NOTHING CHANGES.
// ---------------------------------------------------------------------------
function checkLinuxIsUntouched(t) {
  log.debug("Entering checkLinuxIsUntouched().");
  t.log.info('=== on Linux the helper changes nothing ===');
  const before = process.env.PATH;
  const r = bash('. "' + HELPER + '"; ' +
                 'printf "%s|%s|%s|%s" "$HOST_WINDOWS" ' +
                 '"$(hostPath /a/b)" "${HOST_USER_ARGS[*]}" "$PATH"', before);
  const parts = r.out.split('|');
  t.check(r.status === 0 && parts[0] === '0',
          'HOST_WINDOWS is 0 on Linux',
          'every Windows branch in the launchers keys on it; a 1 here would ' +
          'drop --user and the chown-back on the machines that need them ' +
          '(stderr: ' + r.err.trim() + ')');
  t.check(parts[1] === '/a/b',
          'hostPath() hands its argument back unchanged',
          'it wraps every bind-mount source the launchers pass; anything ' +
          'else here moves a Linux run\'s mounts');
  t.check(parts[2] === '--user ' + process.getuid() + ':' + process.getgid(),
          'HOST_USER_ARGS is the --user uid:gid the launchers always passed',
          'without it the PEP credential and the API pages are written as ' +
          'root into the checkout, and the next run cannot delete them ' +
          '(#254)');
  t.check(parts[3] === before,
          'PATH is left alone',
          'the shims are for docker.exe; on Linux they would be a detour ' +
          'through sed for every docker call');
  log.debug("Leaving checkLinuxIsUntouched().");
}

// ---------------------------------------------------------------------------
// 2 and 3. CYGWIN, FAKED: THE HELPER, AND THE SHIMS IT PUTS FIRST ON PATH.
// ---------------------------------------------------------------------------
function checkCygwin(t) {
  log.debug("Entering checkCygwin().");
  t.log.info('=== under Cygwin: converted paths, no --user, the shims ===');
  const fake = fakeCygwin();
  const pathValue = fake + ':' + process.env.PATH;
  try {
    let r = bash('. "' + HELPER + '"; . "' + HELPER + '"; ' +
                 'printf "%s|%s|%s|%s|%s" "$HOST_WINDOWS" ' +
                 '"$(hostPath /home/me/repo)" "${#HOST_USER_ARGS[@]}" ' +
                 '"$MSYS_NO_PATHCONV" "$PATH"', pathValue);
    const parts = r.out.split('|');
    t.check(r.status === 0 && parts[0] === '1',
            'a CYGWIN_NT uname makes HOST_WINDOWS 1',
            'the same match clean.sh made first (stderr: ' +
            r.err.trim() + ')');
    t.check(parts[1] === 'C:/cygwin64/home/me/repo',
            'hostPath() is cygpath -m',
            'Docker Desktop, compose and node.exe read C:/..., and a ' +
            '/cygdrive or /home path names nothing to them');
    t.check(parts[2] === '0',
            'HOST_USER_ARGS is empty',
            'Docker Desktop does not carry ownership across the mount, and ' +
            'Cygwin\'s uid is a user no image has');
    t.check(parts[3] === '1',
            'MSYS argument rewriting is turned off',
            'Git Bash would otherwise turn `-w /usr/src/sts` into a path ' +
            'under its own install before docker saw it');
    const entries = (parts[4] || '').split(':');
    t.check(entries[0] === SHIMS &&
            entries.filter(function (e) { return e === SHIMS; }).length === 1,
            'the shims are first on PATH, once, after sourcing twice',
            'a launcher that runs another would otherwise grow PATH a level ' +
            'at a time, and a shim not first is a shim never reached');

    // The shim, reached by name as every launcher reaches docker.
    r = bash('. "' + HELPER + '"; out="$(docker inspect x)"; rc=$?; ' +
             'printf "%s|%s" "$out" "$rc"', pathValue);
    t.check(r.out === 'healthy\nsecond|3',
            'docker through the shim: every CR gone, the program\'s status kept',
            'a captured `healthy\\r` equals nothing it is compared with, and ' +
            'a shim answering sed\'s status would turn every failure into a ' +
            'success (got ' + JSON.stringify(r.out) + ', stderr: ' +
            r.err.trim() + ')');

    r = bash('. "' + HELPER + '"; out="$(timeout 10 docker ps)"; ' +
             'printf "%s" "$out"', pathValue);
    t.check(r.out === 'healthy\nsecond',
            'and through `timeout`, which a shell function would not reach',
            'run-tests.sh captures `timeout 60 docker exec ...` and ' +
            'compose.sh runs `env ... docker compose`; both execute docker ' +
            'from PATH');

    r = bash('. "' + HELPER + '"; docker save img | od -c | head -1',
             pathValue);
    t.check(/\\r/.test(r.out),
            'a byte stream (`docker save`) is passed through unfiltered',
            'tar through a line edit is a corrupt archive');

    r = bash('. "' + HELPER + '"; printf "%s" "$("' +
             path.join(SHIMS, 'run-native') + '" iya-batch-512 config ' +
             'get-value project)"', pathValue);
    t.check(r.out === 'project-config get-value project',
            'a program installed only as a .cmd is run through cmd.exe, ' +
            'with its arguments and without its CR',
            'gcloud and az are batch files on Windows, which Cygwin cannot ' +
            'execute by name (got ' + JSON.stringify(r.out) + ', stderr: ' +
            r.err.trim() + ')');

    // By a name no machine has, so the answer does not depend on whether
    // this one has the AWS CLI.
    r = bash('"' + path.join(SHIMS, 'run-native') + '" no-such-program-512',
             pathValue);
    t.check(r.status === 127 && /not found on PATH/.test(r.err),
            'a program that is not installed is said to be missing',
            'a shim that found only itself would recurse until the shell ' +
            'gave up, naming nothing');
  } finally {
    fs.rmSync(fake, { recursive: true, force: true });
  }
  log.debug("Leaving checkCygwin().");
}

// ---------------------------------------------------------------------------
// 4. EVERY HOST LAUNCHER SOURCES IT, AND HANDS DOCKER NO RAW HOST PATH.
// ---------------------------------------------------------------------------
function checkTheLaunchersUseIt(t) {
  log.debug("Entering checkTheLaunchersUseIt().");
  t.log.info('=== every host launcher sources the helper ===');
  // A bind mount whose source is a shell variable, not wrapped in
  // hostPath(): `-v "${DIR}:/x"`, `-v "$D:/x"`, `--env-file "${FILE}"`.
  const raw = /(?:^|\s)(?:-v|--volume|--env-file)\s+"\$\{?[A-Za-z_]/;
  HOST_SCRIPTS.forEach(function (rel) {
    const file = path.join(ROOT, rel);
    if (!fs.existsSync(file)) {
      t.log.info(rel + ' is not in this tree (.dockerignore); skipped');
      return;
    }
    const text = fs.readFileSync(file, 'utf8');
    t.check(/^\s*\.\s+.*host-platform\.sh"?\s*$/m.test(text),
            rel + ' sources tests/tools/host-platform.sh',
            'without it, under Cygwin, its docker output carries CRs and ' +
            'its paths name nothing to docker.exe');
    const bad = text.split('\n').filter(function (line) {
      return raw.test(line) && line.indexOf('hostPath') < 0;
    });
    t.check(bad.length === 0,
            rel + ' wraps every host path it mounts in hostPath()',
            'Docker Desktop cannot mount /cygdrive/c/...: ' +
            JSON.stringify(bad));
  });
  log.debug("Leaving checkTheLaunchersUseIt().");
}

// Every *.sh under the tree, but never node_modules or the submodule.
function shellScripts(dir, found) {
  log.debug("Entering shellScripts().");
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (['node_modules', 'node-ldapjs', '.git', 'report', 'vectors']
            .indexOf(entry.name) < 0) {
        shellScripts(full, found);
      }
    } else if (entry.isFile() && /\.sh$/.test(entry.name)) {
      found.push(full);
    }
  });
  log.debug("Leaving shellScripts().");
  return found;
}

// ---------------------------------------------------------------------------
// 5. NO CHECKOUT REWRITES A LINE ENDING.
// ---------------------------------------------------------------------------
function checkLineEndings(t) {
  log.debug("Entering checkLineEndings().");
  t.log.info('=== .gitattributes, and LF in every shell script ===');
  const attributes = path.join(ROOT, '.gitattributes');
  const text = fs.existsSync(attributes) ?
    fs.readFileSync(attributes, 'utf8') : '';
  t.check(/^\*\s+-text\s*$/m.test(text),
          '.gitattributes turns end-of-line conversion off for every path',
          'Git for Windows defaults to core.autocrlf=true, which would give ' +
          'every script a CR on each line — and every image built from that ' +
          'checkout an entrypoint whose #! names no interpreter');
  const crlf = shellScripts(ROOT, []).filter(function (file) {
    return fs.readFileSync(file).indexOf(13) >= 0;
  }).map(function (file) {
    return path.relative(ROOT, file);
  });
  t.check(crlf.length === 0,
          'no shell script in the tree carries a CR',
          'bash reads the CR as part of each command: ' +
          JSON.stringify(crlf));
  log.debug("Leaving checkLineEndings().");
}

function run(t) {
  log.debug("Entering run().");
  checkLinuxIsUntouched(t);
  checkCygwin(t);
  checkTheLaunchersUseIt(t);
  checkLineEndings(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'host_platform',
  describe: 'that the scripts run on a person\'s machine work under Windows ' +
            'and Cygwin as they do on Linux (#512)',
  run: run
};
