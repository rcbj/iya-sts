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
// conversion, the development companion container of #591 — a separate
// party that reaches this service only over its doors, and ships in no
// image of it), or common/crypto_impl/ — the engines common/crypto.js itself
// rests on, which is what they are whoever wrote them (this service's own
// since #1280; they were skipped as the parent project's copies before).
const SKIP_DIRS = new Set(['node_modules', '.git', '.terraform', 'coverage',
                           '__pycache__']);
const SKIP_PATHS = ['.claude', 'node-ldapjs', 'debugger/embedded', 'tests',
                    'deploy', 'docs', 'rust', 'data', 'apidocs',
                    'common/crypto_impl', 'companion'];

// The files that ARE the common module.
const THE_MODULE = ['common/crypto.js', 'common/pq_native.js',
                    'common/pq_jose.js'];

// The Kerberos codec modules (#431), exempt for the same reason as
// common/crypto_impl/: they are the RFC 3961/3962/8009 engines the KDC runs
// on, not callers that could ask crypto.js. This service's own since #1280.
const KERBEROS_COPIES = ['kerberos/krb5_primitives.js',
                         'kerberos/krb5_asn1.js', 'kerberos/krb5_crypto.js',
                         'kerberos/krb5_messages.js', 'kerberos/krb5_ndr.js',
                         'kerberos/krb5_pac.js', 'kerberos/krb5_gss.js',
                         'kerberos/krb5_spnego.js'];

// Files still allowed while a decision about them is open, each with the
// reason. It may only shrink (claim 3).
// Empty since #1280: `authn/webauthn.js` was the last entry, kept for the
// parent project's standalone copy of it until rcbj ended that (#453).
const PENDING = {};

// Tools that run OUTSIDE the service's module graph and cannot load
// `common/crypto.js`, each with the reason. No module the service runs may
// require one (claim 4), so what they compute decides nothing at runtime.
const STANDALONE = {
  // The XACML conformance suite's integrity manifest: SHA-256 digests of
  // the vendored OASIS files, recomputed by `node xacml/conformance/
  // MANIFEST.js --check` in a bare checkout, before CONFIG_FILE is set —
  // where crypto.js cannot load (it requires config.js, and a .ts compiled
  // only in an image). Read by tests/xacml_conformance.js and nothing else.
  'xacml/conformance/MANIFEST.js': 'a checkout-time integrity tool',
  // The SPIFFE workload agent (#324): a sidecar of its own, a LEAF by
  // design (its header), that requires bunyan, gRPC, pkijs and
  // error_codes.js and none of the service's configuration — crypto.js
  // requires config.js, so the sidecar would load the service to sign one
  // certificate request. It verifies the server's JWT-SVIDs and makes its
  // own CSR key; nothing in the service requires it.
  'spiffe/workload_agent.ts': 'the Workload API sidecar, a separate process'
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
// are the zcap and Ed25519 ones; the BBS suite is common/crypto_impl's
// (bbs2023.js), which is not walked.
// jsonwebtoken and node-forge, which only common/crypto.js and the engines
// under it may hold (#1368). Empty, and so it stays.
const JOSE_LIBRARIES = [
  /(?:require)\s*\(\s*['"](?:jsonwebtoken|node-forge)['"]\s*\)/
];
const LIBRARY_PENDING = {};

// The post-quantum engine's signature calls, the BBS suite, and the X.509
// engine's (#1368). `PqJose.generate` and the key readers stay open: they sign
// nothing.
const PQ_ENGINE_CALLS = [/\bpqJose\.(?:sign|verify|signAsync|verifyAsync)\s*\(/];
const BBS_SUITE = [/require\(\s*['"][^'"]*crypto_impl\/bbs2023(?:\.js)?['"]\s*\)/];
const X509_ENGINE_CALLS = [
  /\bx509\.(?:issueCertificate|signCertificate|verifyChain|verifyBytes)\s*\(/,
  /getCrypto\([^)]*\)\s*\.verifyWithPublicKey\s*\(/
];
// Empty since #1368's X.509 moves, and it stays empty.
const X509_PENDING = {};

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
    'the crypto engines it rests on) requires node\'s crypto or a ' +
    'token-format library; every other module asks crypto.js (#453)',
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

    // The two libraries (#1368): a feature module reads a token through
    // `decodeJws()` and a key through `rsaPublicJwkOf()`, and asks for a
    // digest. The crypto engines under common/crypto_impl are the crypto
    // module's own.
    const libraryHolders = files.filter(function (rel) {
      return rel !== 'common/crypto.js' &&
        rel.indexOf('common/crypto_impl/') !== 0 &&
        !Object.prototype.hasOwnProperty.call(LIBRARY_PENDING, rel) &&
        uses(rel, JOSE_LIBRARIES);
    });
    t.check(libraryHolders.length === 0,
      'no module but common/crypto.js requires jsonwebtoken or node-forge',
      libraryHolders.join(', '));
    Object.keys(LIBRARY_PENDING).forEach(function (rel) {
      t.check(files.indexOf(rel) >= 0 && uses(rel, JOSE_LIBRARIES),
        'a LIBRARY_PENDING entry still requires one (the list may only ' +
        'shrink: delete the entry once the file is moved)', rel);
    });

    // The doors section 2 of #1368 closed. A signature goes through crypto.js:
    // nobody else calls the post-quantum engine's sign or verify, or holds the
    // BBS suite. The file it replaced in vc_status_codec.ts cannot come back.
    const pqCallers = files.filter(function (rel) {
      return THE_MODULE.indexOf(rel) < 0 && uses(rel, PQ_ENGINE_CALLS);
    });
    t.check(pqCallers.length === 0,
      'no module but crypto.js calls pq_jose.js to sign or verify',
      pqCallers.join(', '));
    const bbsHolders = files.filter(function (rel) {
      return THE_MODULE.indexOf(rel) < 0 && uses(rel, BBS_SUITE);
    });
    t.check(bbsHolders.length === 0,
      'no module but crypto.js requires the BBS suite', bbsHolders.join(', '));
    const x509Callers = files.filter(function (rel) {
      return rel !== 'common/crypto.js' && rel !== 'common/pki.js' &&
        rel !== 'common/pki_revocation.js' &&
        // The Certificate Workbench's model, part of the PKI layer (rule 3aa).
        rel !== 'common/pki_authoring.ts' &&
        // Runs in the secret store's container, which holds no service to load
        // crypto.js or pki.js from, to mint that store's listener certificate.
        rel !== 'openbao/generate-tls.js' &&
        rel.indexOf('common/crypto_impl/') !== 0 &&
        !Object.prototype.hasOwnProperty.call(X509_PENDING, rel) &&
        uses(rel, X509_ENGINE_CALLS);
    });
    t.check(x509Callers.length === 0,
      'no module but crypto.js and pki.js calls the X.509 engine to issue or ' +
      'verify', x509Callers.join(', '));
    Object.keys(X509_PENDING).forEach(function (rel) {
      t.check(files.indexOf(rel) >= 0 && uses(rel, X509_ENGINE_CALLS),
        'an X509_PENDING entry still calls it (the list may only shrink)', rel);
    });

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
