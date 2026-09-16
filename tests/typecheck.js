'use strict';
//
// File: typecheck.js
//
// ===========================================================================
// THE TYPE CHECKER, AS A TEST (#50, 2026-09-16).
//
// The TypeScript conversion's first step: `tsconfig.json` at the package root
// checks every JavaScript file that carries `// @ts-check`, with the shared
// shapes in `types/`. This file runs `tsc` over it and fails on any error, so
// a file that has opted in stays clean — a new error anywhere checked fails
// `npm test` like any other broken assertion.
//
// **`checkJs` IS OFF AND EACH FILE OPTS IN**, which is how checking is turned
// on one directory at a time: a directory-wide `checkJs` would also check
// every file those modules `require`, i.e. the whole service at once.
//
// Two more things are held here, because each is how the step would quietly
// stop meaning anything:
//
//   * every non-vendored file in a directory that has opted in carries the
//     marker, so a NEW file is checked from its first commit, and
//     `tsconfig.json` includes every such directory;
//   * `tsc` is really there. It is a dependency of `tests/package.json` — the
//     root package omits devDependencies (see `.npmrc`) — and a missing
//     compiler FAILS naming that file rather than passing an empty check.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'typecheck',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const TSC = path.join(__dirname, 'node_modules', 'typescript', 'bin', 'tsc');

// The directories whose own files have opted in — every directory the
// service runs from since 2026-09-16 — and the two root modules. The files
// under them that are not this repository's to change stay unchecked: the
// root CLAUDE.md names `common/vendored/` (a directory, never listed here
// because it is not read) and the eight Kerberos codec copies.
const CHECKED_DIRS = ['acme', 'admin-core', 'admin-ui', 'authn', 'cluster',
                      'common', 'debugger', 'est', 'federation', 'gnap',
                      'home', 'kerberos', 'ldap', 'logout', 'mgmt-api',
                      'oauth-oidc', 'oid4vc', 'persistence', 'pki', 'portal',
                      'saml', 'scep', 'scim', 'spiffe', 'ssf', 'tls',
                      'ws-federation', 'ws-trust', 'xacml'];
const CHECKED_FILES = ['server.js', 'sts_metadata.js'];
const NOT_OURS = ['kerberos/krb5_primitives.js', 'kerberos/krb5_asn1.js',
                  'kerberos/krb5_crypto.js', 'kerberos/krb5_messages.js',
                  'kerberos/krb5_ndr.js', 'kerberos/krb5_pac.js',
                  'kerberos/krb5_gss.js', 'kerberos/krb5_spnego.js'];

// The `// @ts-check` marker must come before any code; a `#!` line, which
// must be the first line of a file, may precede it.
function carriesMarker(text) {
  log.debug("Entering carriesMarker().");
  const lines = String(text).split('\n');
  const first = lines[0].indexOf('#!') === 0 ? lines[1] : lines[0];
  log.debug("Leaving carriesMarker().");
  return String(first || '').trim() === '// @ts-check';
}

function unmarkedFiles() {
  log.debug("Entering unmarkedFiles().");
  const out = [];
  CHECKED_FILES.forEach(function (rel) {
    const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    if (!carriesMarker(text)) {
      out.push(rel);
    }
  });
  CHECKED_DIRS.forEach(function (dir) {
    fs.readdirSync(path.join(ROOT, dir)).forEach(function (name) {
      const rel = dir + '/' + name;
      if (!/\.js$/.test(name) || NOT_OURS.indexOf(rel) >= 0) {
        return;
      }
      const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
      if (!carriesMarker(text)) {
        out.push(rel);
      }
    });
  });
  log.debug("Leaving unmarkedFiles(). " + out.length + " unmarked.");
  return out;
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the opted-in directories carry the marker ===');
  const unmarked = unmarkedFiles();
  t.equal(unmarked.join(', '), '',
          'every file in the ' + CHECKED_DIRS.length + ' checked ' +
          'directories (vendored copies aside) and ' +
          CHECKED_FILES.join(' and ') +
          ' starts with // @ts-check');

  // AND THE COMPILER IS TOLD ABOUT EVERY ONE OF THEM. A directory whose
  // files carry the marker but which `tsconfig.json` does not include is
  // checked by nothing, and this is the test that would say so.
  const tsconfig = JSON.parse(fs.readFileSync(path.join(ROOT,
                                                        'tsconfig.json'),
                                              'utf8'));
  const included = (tsconfig.include || []);
  const missing = CHECKED_DIRS.map(function (dir) {
    return dir + '/*.js';
  }).concat(CHECKED_FILES).filter(function (pattern) {
    return included.indexOf(pattern) < 0;
  });
  t.equal(missing.join(', '), '',
          'and tsconfig.json includes every one of them');

  t.log.info('=== tsc finds no error ===');
  if (!fs.existsSync(TSC)) {
    t.bad('the TypeScript compiler is installed',
          TSC + ' is missing. It is a dependency of tests/package.json; run ' +
          '`npm install --prefix tests`.');
    log.debug("Leaving run(). No compiler.");
    return;
  }
  const started = Date.now();
  const result = childProcess.spawnSync(process.execPath,
    [TSC, '-p', path.join(ROOT, 'tsconfig.json'), '--pretty', 'false'],
    { cwd: ROOT, encoding: 'utf8', timeout: 600000 });
  const output = String(result.stdout || '') + String(result.stderr || '');
  const errors = output.split('\n').filter(function (line) {
    return / error TS\d+:/.test(line);
  });
  t.equal(result.status, 0,
          'tsc -p tsconfig.json exits 0 (' + (Date.now() - started) + 'ms)',
          output.slice(0, 4000));
  t.equal(errors.length, 0, 'and reports no error',
          errors.slice(0, 20).join('\n'));
  log.debug("Leaving run().");
}

module.exports = { run: run };
