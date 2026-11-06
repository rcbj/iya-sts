// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/signer_truststore.js — THE SIGNER TRUSTSTORE (#1360).
//
// Admission, each refusal by name; kinds and purposes; per-realm isolation; the
// file layer, whose fatal cases are a child process's to die of; the caps; and
// the slot validated whole. The directory is `trust_kit.js`'s double except in
// the last section, which holds the real directory to the same three functions
// in a child, because requiring `ldap/ldap_server` registers its routes on the
// shared app.
//
// MUTATION RECORD, each applied to a scratch build, seen red and put back:
//   * `anchorFieldsOf()` admitting a leaf                     — 5 red (A, B, G)
//   * `anchorProblem()` skipping the self-signature           — 1 red (A); it
//     needed its own fixture, a certificate named as its own issuer and signed
//     by another key, or every self-issued fixture passed either way
//   * `rowsOf()` reading one realm for all                    — 13 red
//   * `setDirectory()` accepting a partial object             — 2 red (F)
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const signers = require('../common/signer_truststore');
const pki = require('../common/pki');
const kit = require('./tools/trust_kit');
const keys = require('../common/crypto_impl/key_material');

const log = require('bunyan').createLogger({ name: 'signer_truststore_test',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD = 'STS_SIGNER_TRUSTSTORE_CHILD';
const STORE = signers.SignerTruststore;

async function fileChild() {
  log.debug("Entering fileChild().");
  const fresh = new STORE(STORE.defaultDeps());
  const count = await fresh.loadFile();
  process.stdout.write('LOADED ' + count + '\n');
  log.debug("Leaving fileChild().");
}

async function directoryChild() {
  log.debug("Entering directoryChild().");
  require('../ldap/ldap_server');
  const root = await kit.mint({ cn: 'directory root', ca: true });
  const issuing = await kit.mint({ cn: 'directory issuing', ca: true,
                                   pathLen: 0, issuer: root });
  const id = 'sts-directory-' + process.pid;
  realms.create({ id: id, name: id, domain: id + '.example.net' });
  const added = await signers.add(id, root.pem, { addedBy: 'alice' });
  const second = await signers.add(id, issuing.pem,
                                   { purposes: ['saml-signer', 'jose-signer'] });
  const listed = signers.list(id);
  const other = signers.list('default');
  const removed = signers.remove(id, added.added[0].fingerprint256);
  process.stdout.write('DIRECTORY ' + JSON.stringify({
    added: added.added.length, second: second.added.length,
    kinds: listed.map(function (one) {
      return one.kind;
    }).sort(),
    purposes: listed.filter(function (one) {
      return one.kind === 'intermediate';
    })[0].purposes.sort(),
    addedBy: listed.filter(function (one) {
      return one.kind === 'anchor';
    })[0].addedBy,
    other: other.length, removed: removed.removed,
    after: signers.list(id).length
  }) + '\n');
  log.debug("Leaving directoryChild().");
}

if (process.env[CHILD]) {
  const job = process.env[CHILD] === 'directory' ? directoryChild : fileChild;
  job().then(function () {
    process.exit(0);
  }, function (e) {
    process.stderr.write(String(e && e.stack) + '\n');
    process.exit(2);
  });
}

function spawn(kind, env) {
  log.debug("Entering spawn(). " + kind);
  const out = childProcess.spawnSync(process.execPath, [__filename], {
    env: Object.assign({}, process.env, { [CHILD]: kind, LOG_LEVEL: 'fatal' },
                       env), encoding: 'utf8', timeout: 120000 });
  log.debug("Leaving spawn().");
  return out;
}

module.exports = {
  name: 'signer_truststore',
  describe: 'the signer truststore: admission, kinds, purposes, realms, the ' +
            'file layer, the caps and the slot',
  run: async function (t) {
    const previous = signers.installedDirectory();
    const double = kit.signerStoreDouble();
    signers.setDirectory(double);
    const stamp = Date.now();
    const realmA = 'sts-a-' + stamp;
    const realmB = 'sts-b-' + stamp;
    try {
      // A. ADMISSION, each refusal by name.
      t.log.info('A. admission');
      const now = Date.now();
      const root = await kit.mint({ cn: 'store root', ca: true });
      const issuing = await kit.mint({ cn: 'store issuing', ca: true,
                                       pathLen: 0, issuer: root });
      const leaf = await kit.mint({ cn: 'store leaf', issuer: root });
      const selfLeaf = await kit.mint({ cn: 'self leaf' });
      const expired = await kit.mint({ cn: 'old root', ca: true,
        notBefore: now - 3 * kit.DAY, notAfter: now - kit.DAY });
      const noSign = await kit.mint({ cn: 'no keyCertSign', ca: true,
                                      usages: ['cRLSign'] });
      const weak = await kit.mint({ cn: 'sha1 root', ca: true,
                                    signatureAlg: 'sha1-rsa' });
      const stranger = await kit.mint({ cn: 'other root', ca: true });
      const orphan = await kit.mint({ cn: 'orphan issuing', ca: true,
                                      pathLen: 0, issuer: stranger });
      const refused = async function (cert, code, what, options) {
        log.debug("Entering refused(). " + what);
        const problem = await pki.anchorProblem(cert.pem || cert, options);
        t.equal(problem && problem.code, code, 'A. ' + what);
        log.debug("Leaving refused().");
      };
      await refused(leaf, 'STS-PKI-0234', 'a leaf is refused');
      await refused(selfLeaf, 'STS-PKI-0234',
                    'a self-signed leaf is refused too');
      await refused(expired, 'STS-PKI-0231', 'an expired CA');
      await refused(noSign, 'STS-PKI-0230', 'no keyCertSign');
      await refused(weak, 'STS-PKI-0232', 'a SHA-1 signature');
      await refused(orphan, 'STS-PKI-0233', 'an intermediate reaching nothing',
                    { heldAnchors: [root.pem] });
      await refused(issuing, 'STS-PKI-0228', 'an intermediate as an anchor',
                    { role: 'anchor' });
      // Named as its own issuer and signed by another key: self-issued, and
      // not self-signed. Only the signature can tell.
      const otherKey = await keys.generateKeyPair('rsa-2048');
      const sameName = await kit.mint({ cn: 'forged root', ca: true,
                                        pair: otherKey });
      const forged = await kit.mint({ cn: 'forged root', ca: true,
                                      issuer: sameName });
      await refused(forged, 'STS-PKI-0228', 'a self-signature that does not ' +
                    'verify');
      await refused('not a certificate', 'STS-PKI-0238', 'not X.509');
      t.equal(await pki.anchorProblem(root.pem), null, 'A. a Root is admitted');
      t.equal(await pki.anchorProblem(issuing.pem,
                                      { heldAnchors: [root.pem] }), null,
              'A. an intermediate that chains is admitted');
      t.equal(pki.anchorProblemSync(leaf.pem).code, 'STS-PKI-0234',
              'A. the synchronous door refuses what the other does');
      t.equal(pki.anchorProblemSync(root.pem), null,
              'A. and admits what the other does');
      t.equal(pki.anchorProblemSync(issuing.pem,
                                    { heldAnchors: [root.pem] }), null,
              'A. the synchronous intermediate');
      t.equal(pki.anchorProblemSync(orphan.pem,
                                    { heldAnchors: [root.pem] }).code,
              'STS-PKI-0233', 'A. and the synchronous orphan');

      // B. WHAT add() ANSWERS.
      t.log.info('B. add, kinds and purposes');
      realms.create({ id: realmA, name: 'A', domain: realmA + '.example.net' });
      realms.create({ id: realmB, name: 'B', domain: realmB + '.example.net' });
      const bundle = issuing.pem + '\n' + root.pem + '\n' + leaf.pem + '\n';
      const added = await signers.add(realmA, bundle, { addedBy: 'alice' });
      t.equal(added.added.length, 2,
              'B. a bundle: its Root and its intermediate, in either order');
      t.equal(added.refused.length, 1, 'B. and its leaf refused by name');
      t.check(/is a leaf/.test(added.refused[0].why),
              'B. the refusal says why', added.refused[0].why);
      t.equal(errorCodes.codeOf(added), 'STS-PKI-0234',
              'B. under the rule\'s code');
      const kinds = added.added.map(function (one) {
        return one.kind;
      }).sort().join(' ');
      t.equal(kinds, 'anchor intermediate', 'B. each kind inferred');
      t.equal(added.added[0].addedBy, 'alice', 'B. who added it');
      const again = await signers.add(realmA, root.pem, {});
      t.equal(again.duplicates, 1, 'B. a duplicate is counted');
      t.equal(again.added.length, 0, 'B. and not added twice');
      const none = await signers.add(realmA, 'no certificate', {});
      t.equal(none.refused[0].code, 'STS-PKI-0238',
              'B. nothing PEM is refused');
      const scoped = await signers.add(realmB, root.pem,
                                       { purposes: ['saml-signer'] });
      t.equal(scoped.added[0].purposes[0], 'saml-signer',
              'B. a purpose restriction is kept');
      t.equal(signers.anchorsFor(realmB, 'saml-signer').anchors.length, 1,
              'B. it serves the use case named');
      t.equal(signers.anchorsFor(realmB, 'jose-signer').anchors.length, 0,
              'B. and no other');
      t.equal(signers.anchorsFor(realmB).anchors.length, 1,
              'B. a caller naming no use case sees it');

      // C. EVERY REALM ITS OWN.
      t.log.info('C. realms');
      t.equal(signers.list(realmA).length, 2, 'C. A holds its two');
      t.equal(signers.list(realmB).length, 1, 'C. B holds its one');
      t.equal(signers.list('default').length, 0,
              'C. the default realm holds nothing it was not given');
      await realms.run(realms.get(realmA), async function () {
        t.equal(signers.list().length, 2,
                'C. no realm named is the ambient one');
      });

      // D. REMOVE.
      t.log.info('D. remove');
      const fp = signers.list(realmB)[0].fingerprint256;
      const colons = fp.match(/../g).join(':').toLowerCase();
      t.check(!signers.remove(realmA, 'AB'.repeat(32)).removed,
              'D. a fingerprint not held removes nothing', '');
      t.check(signers.remove(realmB, colons).removed,
              'D. the colon spelling finds its entry', '');
      t.equal(signers.list(realmB).length, 0, 'D. and it has gone');

      // E. THE CAPS.
      t.log.info('E. the caps');
      const held = double.rows(realmB);
      for (let i = 0; i < STORE.MAX_ANCHORS; i++) {
        held.set('F' + i, { fingerprint: 'F' + i, pem: root.pem,
                            kind: 'anchor', purposes: [], source: 'runtime' });
      }
      const another = await kit.mint({ cn: 'one too many', ca: true });
      const full = await signers.add(realmB, another.pem, {});
      t.equal(full.refused[0] && full.refused[0].code, 'STS-PKI-0236',
              'E. thirty-two anchors is a full store');
      held.clear();

      // F. THE SLOT, VALIDATED WHOLE.
      t.log.info('F. the slot');
      t.equal(signers.setDirectory({ list: function () {
        return [];
      } }), false, 'F. part of a directory is refused');
      t.equal(signers.installedDirectory(), double,
              'F. and the one installed stays');
      const bare = new STORE(STORE.defaultDeps());
      const unfilled = await bare.add('default', root.pem, {});
      t.equal(unfilled.refused[0].code, 'STS-PKI-0235',
              'F. no directory refuses an add rather than losing it');

      // G. THE FILE LAYER.
      t.log.info('G. the file layer');
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-signer-'));
      try {
        const named = spawn('file', {
          STS_PKI_SIGNER_TRUST_ANCHORS_FILE: path.join(dir, 'absent.pem') });
        t.equal(named.status, 1, 'G. named and unreadable stops the process');
        const empty = path.join(dir, 'empty.pem');
        fs.writeFileSync(empty, 'nothing here\n');
        const blank = spawn('file',
                            { STS_PKI_SIGNER_TRUST_ANCHORS_FILE: empty });
        t.equal(blank.status, 1, 'G. holding no certificate stops it too');
        const good = path.join(dir, 'good.pem');
        fs.writeFileSync(good, issuing.pem + root.pem + leaf.pem);
        const loaded = spawn('file',
                             { STS_PKI_SIGNER_TRUST_ANCHORS_FILE: good });
        t.check(loaded.status === 0 && /LOADED 2/.test(loaded.stdout),
                'G. a file: its CAs loaded and its leaf left out by name',
                loaded.stdout + loaded.stderr);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }

      // H. THE REAL DIRECTORY.
      t.log.info('H. the real directory, in a child');
      const real = spawn('directory', {});
      const line = /DIRECTORY (.*)/.exec(real.stdout || '');
      const report = line ? JSON.parse(line[1]) : {};
      t.check(report.added === 1 && report.second === 1,
              'H. written through the slot', (real.stderr || '').slice(0, 400));
      t.equal((report.kinds || []).join(' '), 'anchor intermediate',
              'H. each kind read back');
      t.equal((report.purposes || []).join(' '), 'jose-signer saml-signer',
              'H. every purpose read back');
      t.equal(report.addedBy, 'alice', 'H. who added it read back');
      t.equal(report.other, 0, 'H. the default realm does not see it');
      t.check(report.removed && report.after === 1,
              'H. removed through the slot', JSON.stringify(report));
    } finally {
      [realmA, realmB].forEach(function (id) {
        if (realms.get(id)) {
          realms.remove(id);
        }
      });
      if (previous) {
        signers.setDirectory(previous);
      }
    }
  }
};
