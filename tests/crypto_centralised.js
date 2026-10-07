// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/crypto_centralised.js
//
// ---------------------------------------------------------------------------
// EVERY CRYPTOGRAPHIC OPERATION IS `common/crypto.js`'S (#453, 2026-10-07).
//
// rcbj's rule, restated on 2026-10-05 during #178: "All crypto operations
// across all protocols and use cases are to be centralized in a common
// module." Signing and verifying, MACs and constant-time compares, digests,
// key derivation, ciphers, key import and export, certificate parsing, key
// generation and random values: a feature module asks `common/crypto.js`, and
// never node's `crypto` itself. #453 moved 130 files onto it, and this file is
// what keeps the 131st from appearing.
//
// Three claims:
//
//   1. no file this repository runs `require`s node's `crypto` (or imports
//      it for a value) except `common/crypto.js` and the two post-quantum
//      engines it is built on (`pq_native.js`, `pq_jose.js`), and the
//      parent project's copies that may not be edited here — `common/
//      vendored/` and the eight Kerberos codec files (#431 decides those
//      case by case). A TYPE-only import (`import type … from 'crypto'`,
//      a JSDoc `import('crypto')`) loads nothing and is allowed;
//   2. the libraries that compute a token format's cryptography — GNAP's
//      macaroon, zcap and Biscuit engines (rcbj's decision of 2026-10-05 on
//      #453) — are required by `common/crypto.js` and nothing else, so it
//      alone holds their keys and decides their algorithms;
//   3. PENDING, the list of files still allowed while a decision about them
//      is open, may only SHRINK: an entry whose file no longer requires the
//      module fails, so a fixed file cannot leave its permission behind;
//   4. a STANDALONE tool — one that runs outside the service's module
//      graph, where crypto.js cannot load — is required by no module the
//      service runs (the tests are not walked, and may).
//
// It reads every line that is not a comment, so a comment QUOTING the
// require — this one, `crypto.js`'s header — is not a use. It walks the file
// system rather than `git ls-files`, because it runs in the tests image,
// which has no .git, and skips the compiled x.js beside every x.ts: the
// source is what is checked.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({
  name: 'crypto_centralised',
  level: process.env.STS_LOG_LEVEL || 'info'
});

const ROOT = path.resolve(__dirname, '..');

// Directories never walked: generated, somebody else's, not this service's
// runtime (the tests, the deployment trees, the documentation, the Rust
// conversion), or the parent project's copies.
const SKIP_DIRS = new Set(['node_modules', '.git', '.terraform', 'coverage',
                           '__pycache__']);
const SKIP_PATHS = ['.claude', 'node-ldapjs', 'debugger/embedded', 'tests',
                    'deploy', 'docs', 'rust', 'data', 'apidocs',
                    'common/vendored'];

// The files that ARE the common module.
const THE_MODULE = ['common/crypto.js', 'common/pq_native.js',
                    'common/pq_jose.js'];

// The parent project's byte-identical Kerberos codec copies (#431).
const KERBEROS_COPIES = ['kerberos/krb5_primitives.js',
                         'kerberos/krb5_asn1.js', 'kerberos/krb5_crypto.js',
                         'kerberos/krb5_messages.js', 'kerberos/krb5_ndr.js',
                         'kerberos/krb5_pac.js', 'kerberos/krb5_gss.js',
                         'kerberos/krb5_spnego.js'];

// Files still allowed while a decision about them is open, each with the
// reason. It may only shrink (claim 3).
const PENDING = {
  // The parent project's tests/webauthn_cross_impl.js stages this ONE file
  // on its own, without common/crypto.js beside it, and checks it against
  // the wallet's independent decoder. In the service every digest and
  // signature check goes through crypto.js; `standaloneNodeCrypto()`, a
  // lazy require, is reached only in that standalone copy. Whether to keep
  // the standalone path or change the parent's test is rcbj's decision
  // (#453, as #431 decides the vendored copies).
  'authn/webauthn.js': 'the parent project\'s standalone copy'
};

// Tools that run OUTSIDE the service's module graph and cannot load
// `common/crypto.js`, each with the reason. No module the service runs may
// require one (claim 4), so what they compute decides nothing at runtime.
const STANDALONE = {
  // The XACML conformance suite's integrity manifest: SHA-256 digests of
  // the vendored OASIS files, recomputed by `node xacml/conformance/
  // MANIFEST.js --check` in a bare checkout, before CONFIG_FILE is set —
  // where crypto.js cannot load (it requires config.js, and a .ts compiled
  // only in an image). Read by tests/xacml_conformance.js and nothing else.
  'xacml/conformance/MANIFEST.js': 'a checkout-time integrity tool'
};

// Node's module, by either spelling, required or imported for a value.
const NODE_CRYPTO = [
  /\brequire\(\s*['"](?:node:)?crypto['"]\s*\)/,
  /^\s*import\s+(?!type\b)[^;]*\bfrom\s+['"](?:node:)?crypto['"]/,
  /^\s*import\s+\w+\s*=\s*require\(\s*['"](?:node:)?crypto['"]\s*\)/
];

// The token-format libraries only `common/crypto.js` may hold (claim 2).
// Matched on the SPECIFIER of a require or a dynamic import, never on a bare
// string: gnap/token_biscuit.ts and token_zcap.ts still NAME their packages,
// for the version they report on the console. The `@digitalbazaar` packages
// are the zcap and Ed25519 ones; the BBS suite is common/vendored's
// (bbs2023.js), which is not walked.
const TOKEN_LIBRARIES = [
  new RegExp('(?:require|import)\\s*\\(\\s*[\'"](?:macaroon|' +
    'jsonld-signatures|@digitalbazaar/(?:zcap|zcap-context|' +
    'ed25519-[a-z0-9-]+|security-context)|@biscuit-auth/biscuit-wasm)' +
    '(?:/[^\'"]*)?[\'"]'),
  /^\s*import\s+\w+\s*=\s*require\(\s*['"](?:macaroon|jsonld-signatures)['"]/,
  /\bWebAssembly\.(?:instantiate|compile)\b/
];

// Every .js and .ts under the root, less the skipped directories, and less
// a compiled x.js beside its x.ts.
function walk() {
  log.debug("Entering walk().");
  const out = [];
  const stack = [''];
  while (stack.length) {
    const dir = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true });
    } catch (e) {
      log.debug("Caught in walk(): " + ((e && e.message) || e));
      continue;
    }
    entries.forEach(function (entry) {
      const rel = dir ? dir + '/' + entry.name : entry.name;
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && SKIP_PATHS.indexOf(rel) < 0) {
          stack.push(rel);
        }
        return;
      }
      if (!entry.isFile() || !/\.(js|ts|cjs|mjs)$/.test(rel) ||
          /\.d\.ts$/.test(rel)) {
        return;
      }
      if (/\.js$/.test(rel) &&
          fs.existsSync(path.join(ROOT, rel.replace(/\.js$/, '.ts')))) {
        return;
      }
      out.push(rel);
    });
  }
  log.debug("Leaving walk().");
  return out.sort();
}

// The lines of a file that are not comments: a line whose first characters
// are `//`, `/*` or `*` is prose. A require is never written after code on
// a comment line in this tree, so this is enough, and it keeps the test from
// failing on a header that quotes what it forbids.
function codeLines(rel) {
  log.debug("Entering codeLines().");
  const lines = fs.readFileSync(path.join(ROOT, rel), 'utf8').split('\n');
  const out = lines.filter(function (line) {
    return !/^\s*(\/\/|\/\*|\*)/.test(line);
  });
  log.debug("Leaving codeLines().");
  return out;
}

// Whether any code line of a file matches any of the patterns.
function uses(rel, patterns) {
  log.debug("Entering uses().");
  const answer = codeLines(rel).some(function (line) {
    return patterns.some(function (re) {
      return re.test(line);
    });
  });
  log.debug("Leaving uses().");
  return answer;
}

module.exports = {
  name: 'crypto_centralised',
  describe: 'only common/crypto.js (and its two post-quantum engines and ' +
    'the vendored copies) requires node\'s crypto or a token-format ' +
    'library; every other module asks crypto.js (#453)',
  run: function run(t) {
    const files = walk();
    t.check(files.length > 500, 'the walk found the source files it checks',
      files.length + ' file(s)');
    t.check(files.indexOf('common/crypto.js') >= 0,
      'the walk reached common/crypto.js', '');

    const outside = files.filter(function (rel) {
      return THE_MODULE.indexOf(rel) < 0 &&
        KERBEROS_COPIES.indexOf(rel) < 0 &&
        !Object.prototype.hasOwnProperty.call(PENDING, rel) &&
        !Object.prototype.hasOwnProperty.call(STANDALONE, rel) &&
        uses(rel, NODE_CRYPTO);
    });
    t.check(outside.length === 0,
      'no module but common/crypto.js requires node\'s crypto ' +
      '(ask crypto.js; add a named function there if it has none)',
      outside.join(', '));

    t.check(uses('common/crypto.js', NODE_CRYPTO),
      'common/crypto.js itself is still where node\'s crypto is required',
      '');

    const holders = files.filter(function (rel) {
      return rel !== 'common/crypto.js' && uses(rel, TOKEN_LIBRARIES);
    });
    t.check(holders.length === 0,
      'no module but common/crypto.js requires the macaroon, zcap or ' +
      'Biscuit library',
      holders.join(', '));

    Object.keys(PENDING).forEach(function (rel) {
      t.check(files.indexOf(rel) >= 0 && uses(rel, NODE_CRYPTO),
        'a PENDING entry still requires node\'s crypto (the list may only ' +
        'shrink: delete the entry once the file is moved)', rel);
    });

    Object.keys(STANDALONE).forEach(function (rel) {
      const base = path.basename(rel).replace(/\.[jt]s$/, '');
      const pattern = new RegExp('\\brequire\\(\\s*[\'"][^\'"]*' +
        rel.replace(/\.[jt]s$/, '').split('/').slice(-2).join('/')
          .replace(/[.]/g, '\\.') + '(?:\\.js)?[\'"]');
      const requirers = files.filter(function (other) {
        return other !== rel && uses(other, [pattern]);
      });
      t.check(requirers.length === 0,
        'no module the service runs requires the standalone tool ' + base,
        requirers.join(', '));
    });

    KERBEROS_COPIES.forEach(function (rel) {
      t.check(fs.existsSync(path.join(ROOT, rel)),
        'each Kerberos copy the guard exempts still exists', rel);
    });
  }
};
