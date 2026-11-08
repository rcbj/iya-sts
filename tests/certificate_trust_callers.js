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
// ONLY SHRINKS**: each phase of #1360 removes the rows it wires, and a row with
// no call left, or a count that fell, fails here too, so it cannot go stale.
// Phase 6 empties it. A new call is not added here: it goes through the door.
//
// MUTATION RECORD: a direct `verifyLeaf()` added to `home/home.ts` went red, and
// a row left behind after its call was removed went red.
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

const ALLOWED = {
  'acme/acme.ts': { checkIssued: 1 },
  'admin-ui/crypto_metadata.ts': { checkIssued: 1 },
  'authn/webauthn_attestation.ts': { verifyPathToAnchors: 1 },
  'common/cert_enrollment.ts': { verifyLeaf: 1 },
  'common/device_attestation.ts': { verifyPathToAnchors: 1 },
  'common/outbound_tls.ts': { peerChainProblem: 2 },
  'common/revocation_status.js': { checkIssued: 1 },
  'kerberos/krb5_pkinit.ts': { verifyPathToAnchors: 1 },
  'oauth-oidc/assertion_grant.js': { verifyLeaf: 1 },
  'oauth-oidc/client_attestation.ts': { checkIssued: 1,
                                        verifyPathToAnchors: 1 },
  'oid4vc/vc_issuer.ts': { verifyIssuedDirectly: 1 },
  'oid4vc/vc_mdoc.ts': { verifyPathToAnchors: 1 },
  'spiffe/spiffe_attestor_azure_imds.ts': { verifyPathToAnchors: 1 },
  'spiffe/spiffe_attestor_tpm_devid.ts': { verifyPathToAnchors: 2 },
  'spiffe/spiffe_attestor_x509pop.ts': { verifyPathToAnchors: 1 },
  'spiffe/spiffe_auth.ts': { verifyIssuedDirectly: 1 },
  'spiffe/spiffe_sigstore.ts': { verifyPathToAnchors: 1 },
  'tls/tls_server.js': { checkIssued: 4 }
};

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
        const allowed = (ALLOWED[file] || {})[name] || 0;
        if (counted[file][name] > allowed) {
          unexpected.push(file + ': ' + name + ' x' + counted[file][name]);
        }
      });
    });
    t.check(unexpected.length === 0,
            'every direct call of a path function goes through the door: a ' +
            'new one calls common/certificate_trust.ts instead',
            unexpected.join('; '));
    const stale = [];
    Object.keys(ALLOWED).forEach(function (file) {
      Object.keys(ALLOWED[file]).forEach(function (name) {
        if (((counted[file] || {})[name] || 0) < ALLOWED[file][name]) {
          stale.push(file + ': ' + name);
        }
      });
    });
    t.check(stale.length === 0,
            'the list holds nothing the tree no longer does: take these out ' +
            'of ALLOWED', stale.join('; '));
    t.check(Object.keys(counted).length >= 1 || !Object.keys(ALLOWED).length,
            'the scan found the tree it was asked about', '');
  }
};
