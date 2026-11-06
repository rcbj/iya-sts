// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/certificate_trust_callers.js — A SITE CALLS THE DOOR, NOT WHAT IS
// BEHIND IT (#1360).
//
// A source test in `tests/crypto_centralised.js`'s shape: a direct call of a
// path function, or of node's `checkIssued()`, anywhere but `common/pki.js`,
// `common/crypto.js`, the door and the engines is a site the door does not see.
// `ALLOWED` is every such call the 2026-11-06 audit found, with how many. **IT
// ONLY SHRINKS**: each phase of #1360 removed the rows it wired, and a row with
// no call left, or a count that fell, fails here too, so it cannot go stale.
// Phase 5 emptied it. A new call is not added here: it goes through the door.
//
// MUTATION RECORD: a direct `verifyLeaf()` added to `home/home.ts` went red, and
// a row left behind after its call was removed went red; a row's name taken out
// of `spiffe/spiffe_attestor_x509pop.ts` went red.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// Who may hold the functions themselves, or only draws what they read.
const OWNERS = ['common/pki.js', 'common/crypto.js',
                'common/certificate_trust.ts'];
const SKIP_DIRS = ['node_modules', '.git', '.claude', 'tests', 'node-ldapjs',
                   'docs', 'rust', 'crypto_impl', 'deploy', 'utilities', 'data',
                   'apidocs', 'companion', 'embedded'];
const CALL = /\b(verifyPathToAnchors|verifyIssuedDirectly|verifySignerChain|peerChainProblem|verifyLeaf)\s*\(|\.(checkIssued)\s*\(/;

// EMPTY SINCE PHASE 5: every site that relies on a certificate calls the door.
const ALLOWED = {};

// THE CALLS THAT ARE NOT A DECISION TO RELY ON A CERTIFICATE, each for its own
// reason, so that `ALLOWED` can be empty. A row with no call left fails too.
const PERMANENT = {
  // Is this CSR's certificate its own issuer: a shape, read to name the error.
  'acme/acme.ts': { checkIssued: 1 },
  // Draws "self-signed" on a metadata page; nothing is trusted because of it.
  'admin-ui/crypto_metadata.ts': { checkIssued: 1 },
  // The door's own hold on an outbound socket, asked of what OpenSSL built;
  // `installGate()` is what calls it, and `tests/outbound_gate.js` holds it.
  'common/outbound_tls.ts': { peerChainProblem: 2 },
  // Who signed a CRL or an OCSP answer, the question revocation itself asks;
  // the door requires this module, and `revocationSignerHeld()` holds the
  // signer's fields.
  'common/revocation_status.js': { checkIssued: 1 },
  // A shape again: HAIP 1.0 section 4.4.1 refuses a self-signed attester
  // before any path, and the path is the door's.
  'oauth-oidc/client_attestation.ts': { checkIssued: 1 },
  // Admission to the truststore and display on the console: `pki.anchorProblem`
  // decides the former, and the rest draw what a certificate says.
  'tls/tls_server.js': { checkIssued: 4 }
};

// One count per file and function, whichever list holds it.
function holds(file, name) {
  return ((ALLOWED[file] || {})[name] || 0) +
         ((PERMANENT[file] || {})[name] || 0);
}

// Every source file: a `.ts`, or a `.js` with no `.ts` beside it (the compiled
// twin says nothing the source does not), and no browser bundle.
function sources(dir, found) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.indexOf(entry.name) === -1) {
        sources(full, found);
      }
      return;
    }
    const isTs = /\.ts$/.test(entry.name) && !/\.d\.ts$/.test(entry.name);
    const isJs = /\.js$/.test(entry.name) &&
      !fs.existsSync(full.replace(/\.js$/, '.ts')) &&
      !/-spa\.js$|\/console\.js$/.test(full);
    if (isTs || isJs) {
      found.push(full);
    }
  });
  return found;
}

module.exports = {
  name: 'certificate_trust_callers',
  describe: 'no site reaches past the validation door, beyond the calls the ' +
            'audit recorded, and that list only shrinks',
  run: function (t) {
    const counted = {};
    sources(ROOT, []).forEach(function (file) {
      const relative = path.relative(ROOT, file).split(path.sep).join('/');
      if (OWNERS.indexOf(relative) !== -1) {
        return;
      }
      fs.readFileSync(file, 'utf8').split('\n').forEach(function (line) {
        if (/^\s*(\/\/|\*)/.test(line)) {
          return;
        }
        const hit = CALL.exec(line);
        if (hit) {
          const name = hit[1] || hit[2];
          counted[relative] = counted[relative] || {};
          counted[relative][name] = (counted[relative][name] || 0) + 1;
        }
      });
    });
    const unexpected = [];
    Object.keys(counted).forEach(function (file) {
      Object.keys(counted[file]).forEach(function (name) {
        if (counted[file][name] > holds(file, name)) {
          unexpected.push(file + ': ' + name + ' x' + counted[file][name]);
        }
      });
    });
    t.check(unexpected.length === 0,
            'every direct call of a path function goes through the door: a ' +
            'new one calls common/certificate_trust.ts instead',
            unexpected.join('; '));
    const stale = [];
    [ALLOWED, PERMANENT].forEach(function (list) {
      Object.keys(list).forEach(function (file) {
        Object.keys(list[file]).forEach(function (name) {
          if (((counted[file] || {})[name] || 0) < holds(file, name)) {
            stale.push(file + ': ' + name);
          }
        });
      });
    });
    t.check(stale.length === 0,
            'the list holds nothing the tree no longer does: take these out ' +
            'of ALLOWED or PERMANENT', stale.join('; '));
    // EVERY ROW'S SITES ASK FOR THAT ROW. A row whose site asks another purpose,
    // or nothing, is a setting that governs nothing and still reads as a
    // control. A site may reach it through a helper named for that purpose.
    const trust = require('../common/certificate_trust');
    const THROUGH = {
      'tls-client': /holdConnectionsOn|settledRequest/,
      'jose-bare-key': /\.bareKey\(/,
      'anchor-admission': /anchorProblem/
    };
    const unwired = [];
    trust.PURPOSES.forEach(function (purpose) {
      purpose.sites.forEach(function (site) {
        const file = site.split(' ')[0];
        const text = fs.existsSync(path.join(ROOT, file)) ?
          fs.readFileSync(path.join(ROOT, file), 'utf8') : '';
        if (text.indexOf("'" + purpose.id + "'") === -1 &&
            !(THROUGH[purpose.id] && THROUGH[purpose.id].test(text))) {
          unwired.push(purpose.id + ' at ' + file);
        }
      });
    });
    t.check(unwired.length === 0,
            'every site the table names asks for its own row',
            unwired.join('; '));
    t.check(Object.keys(counted).length >= 1,
            'the scan found the tree it was asked about', '');
  }
};
