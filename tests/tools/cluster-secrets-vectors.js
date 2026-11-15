// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/cluster-secrets-vectors.js
//
// THE SECRETS EVERY NODE AGREES ON, AS NODE STORES THEM (#444, phase 5, the
// `oauth5` slice): `cluster-secrets-node.json` and the check of what Rust
// wrote, `cluster-secrets-rust.json`.
//
// A COMPATIBLE UPGRADE (D11) needs the `oidc-pairwise` row of
// `sts_cluster_secrets` read by Rust exactly as Node sealed it, or every
// pairwise `sub` a client was given changes at the cutover. So the builder
// runs Node's own `ClusterSecrets.start()` against Node's own keystore —
// a durable key-encryption key from a file, the data-key rows it stores
// held in memory — and a store whose `ensureSharedSecret()` keeps the first
// offer, as postgres does; then derives pairwise subjects with Node's own
// `PairwiseSubjects.subjectFor()`. The file carries the key rows, the
// secret rows and the subjects: the Rust half (`sts-store`'s
// `cluster_secrets_vectors.rs`) opens the rows and must derive the same
// subjects.
//
// The other way round, Rust's file carries the rows Rust's `start()` wrote
// on an empty store under the same key-encryption key, and the subjects it
// derived; `checkRust()` hands those rows to Node's keystore and Node's
// `start()` (which must keep Rust's offer rather than its own) and derives
// again.
//
// The same file carries the post-quantum half of a key set (`pqKeys`),
// each key with a signature: Rust must verify Node's signatures, sign with
// Node's private halves and derive Node's `kid`s, and Rust's keys go back
// the same way.
//
// Both halves run in a child process: the keystore and the secrets are
// process-wide, and the child's log shares stdout.
//

const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'cluster-secrets-vectors',
  level: process.env.STS_LOG_LEVEL || 'info' });

// The clients a subject is derived for: two sectors, and a sector URI.
const CLIENTS = {
  'pw-one': { subject_type: 'pairwise',
              redirect_uris: ['https://rp.example/cb'] },
  'pw-two': { subject_type: 'pairwise',
              redirect_uris: ['https://other.example:8443/a',
                              'https://other.example:8443/b'] },
  'pw-sector': { subject_type: 'pairwise',
                 sector_identifier_uri: 'https://sector.example/s.json',
                 redirect_uris: ['https://a.example/cb',
                                 'https://b.example/cb'] }
};
const LOCALS = ['urn:uuid:0b6b9b7e-6f53-4d6c-9a3c-0f1f2f3f4f5f',
                'urn:uuid:d0c4a0a2-1b1b-4c4c-8d8d-123456789abc'];
const REALMS = ['', 'acme'];
// What every post-quantum key signs, as a JWS signing input would be.
const MESSAGE = 'eyJhbGciOiJNTC1EU0EtNDQifQ.eyJzdWIiOiJ2ZWN0b3IifQ';

// THE POST-QUANTUM HALF OF A KEY SET, run IN THE CHILD (its source is
// copied there, so it requires everything itself and logs nothing — code in
// a `node -e` child is exempt from the Entering/Leaving rule): `pqKeys` as
// `keystore.serialise()` stores them, made by `helpers.pqKeyFrom()`, each
// with a signature over the message; or Rust's, verified and signed with.
function pqPart(ROOT, input) {
  const path = require('path');
  const out = {};
  if (!input.pqMake && !input.pqCheck) {
    return out;
  }
  const helpers = require(path.join(ROOT, 'common', 'helpers.js'));
  const pqJose = require(path.join(ROOT, 'common', 'pq_jose.js'));
  const MSG = input.message;
  if (input.pqMake) {
    out.keys = pqJose.PQ_ALGS.map(function (alg) {
      const k = helpers.pqKeyFrom(alg, pqJose.generate(alg));
      return { alg: alg,
        privateKey: Buffer.from(k.privateKey).toString('base64'),
        publicJwk: k.publicJwk,
        signature: Buffer.from(pqJose.sign(alg, k.privateKey, MSG))
          .toString('base64url') };
    });
  }
  if (input.pqCheck) {
    out.checked = input.pqCheck.map(function (one) {
      const pub = Buffer.from(one.publicJwk.pub, 'base64url');
      const priv = Buffer.from(one.privateKey, 'base64');
      return { alg: one.alg,
        theirs: pqJose.verify(one.alg, pub, MSG,
          Buffer.from(one.signature, 'base64url')),
        mine: pqJose.verify(one.alg, pub, MSG,
          pqJose.sign(one.alg, priv, MSG)),
        kid: helpers.pqKeyFrom(one.alg, { pub: pub, priv: priv })
          .publicJwk.kid === one.publicJwk.kid };
    });
  }
  return out;
}

// The child: Node's keystore and cluster secrets over `input`'s rows, and
// the subjects. Its answer goes to a file.
const CHILD = [
  "'use strict';",
  'const path = require("path");',
  'const fs = require("fs");',
  'const ROOT = process.argv[1];',
  'const input = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));',
  'const keystore = require(path.join(ROOT, "common", "keystore.js"));',
  'const realms = require(path.join(ROOT, "common", "realms.js"));',
  'const CS = require(path.join(ROOT, "cluster", "cluster_secrets.js"))',
  '  .ClusterSecrets;',
  'const PS = require(path.join(ROOT, "oauth-oidc",',
  '                             "pairwise_subjects.js")).PairwiseSubjects;',
  '(async function () {',
  '  const rows = new Map(input.keyRows.map(function (r) {',
  '    return [r.realm, r.material];',
  '  }));',
  '  const secrets = new Map(input.secretRows.map(function (r) {',
  '    return [r.name, r];',
  '  }));',
  '  keystore.setStore({',
  '    loadKeys: function () {',
  '      return Promise.resolve(Array.from(rows, function (e) {',
  '        return { realm: e[0], material: e[1] };',
  '      }));',
  '    },',
  '    saveKeys: function (realm, material) {',
  '      rows.set(realm, material);',
  '      return Promise.resolve();',
  '    }',
  '  });',
  '  await keystore.start();',
  '  const store = {',
  '    ensureSharedSecret: function (name, material) {',
  '      const offered = !secrets.has(name);',
  '      if (offered) {',
  '        secrets.set(name, { name: name, material: material,',
  '                            createdBy: "node", createdAt: Date.now() });',
  '      }',
  '      const row = secrets.get(name);',
  '      return Promise.resolve({ material: row.material,',
  '        createdBy: row.createdBy, createdAt: row.createdAt,',
  '        offered: offered });',
  '    }',
  '  };',
  '  const cs = new CS(Object.assign(CS.defaultDeps(), {',
  '    env: {}, clusterStore: function () { return store; },',
  '    isActiveActive: function () { return false; } }));',
  '  const started = await cs.start(keystore);',
  '  const ps = new PS(Object.assign(PS.defaultDeps(), {',
  '    clusterSecrets: cs,',
  '    applications: { clientConfigOf: function (id) {',
  '      return input.clients[id] || {}; } } }));',
  '  const subjects = [];',
  '  input.realms.forEach(function (realm) {',
  '    Object.keys(input.clients).forEach(function (client) {',
  '      input.locals.forEach(function (local) {',
  '        realms.run(realm || undefined, function () {',
  '          subjects.push({ realm: realm, client: client, local: local,',
  '                          sub: ps.subjectFor(client, local, "") });',
  '        });',
  '      });',
  '    });',
  '  });',
  '  const pq = pqPart(ROOT, input);',
  '  await keystore.settleDeks();',
  '  fs.writeFileSync(process.argv[3], JSON.stringify({',
  '    pq: pq,',
  '    started: started,',
  '    describe: cs.describe(),',
  '    keyRows: Array.from(rows, function (e) {',
  '      return { realm: e[0], material: e[1] };',
  '    }),',
  '    secretRows: Array.from(secrets.values()),',
  '    subjects: subjects }));',
  '  keystore.reset();',
  '})().catch(function (e) { console.error(e); process.exitCode = 1; });',
  'function pqPart(ROOT, input) {',
  '  return (' + pqPart.toString() + ')(ROOT, input);',
  '}'
].join('\n');

/**
 * Runs the child over `input` with the key-encryption key in `kekFile`.
 *
 * @param {string} root - the repository root
 * @param {string} out - a scratch directory
 * @param {string} kekFile - the key-encryption key's file
 * @param {any} input - `{ keyRows, secretRows, clients, locals, realms }`
 * @returns {any} the child's answer
 */
function runChild(root, out, kekFile, input) {
  log.debug("Entering runChild().");
  const inFile = path.join(out, 'cluster-secrets-in.json');
  const answerFile = path.join(out, 'cluster-secrets-answer.json');
  fs.writeFileSync(inFile, JSON.stringify(input), { mode: 0o600 });
  try {
    childProcess.execFileSync(process.execPath,
      ['-e', CHILD, root, inFile, answerFile],
      { env: Object.assign({}, process.env, {
          STS_LOG_LEVEL: 'fatal', STS_KEYS_SOURCE: 'persisted',
          STS_KEYS_KEK_PROVIDER: 'file', STS_KEYS_KEK_FILE: kekFile }),
        stdio: ['ignore', 'ignore', 'inherit'] });
    const answer = JSON.parse(fs.readFileSync(answerFile, 'utf8'));
    log.debug("Leaving runChild().");
    return answer;
  } finally {
    [inFile, answerFile].forEach(function (f) {
      if (fs.existsSync(f)) {
        fs.unlinkSync(f);
      }
    });
  }
}

/**
 * Builds `cluster-secrets-node.json`.
 *
 * @param {string} root - the repository root
 * @param {string} out - the vector directory
 * @returns {any} the vectors
 */
function build(root, out) {
  log.debug("Entering build().");
  const kekFile = path.join(out, 'cluster-secrets-kek.txt');
  fs.writeFileSync(kekFile,
                   nodeCrypto.randomBytes(32).toString('base64') + '\n',
                   { mode: 0o600 });
  const answer = runChild(root, out, kekFile, {
    keyRows: [], secretRows: [], clients: CLIENTS, locals: LOCALS,
    realms: REALMS, pqMake: true, message: MESSAGE });
  log.debug("Leaving build().");
  return { kekFile: path.basename(kekFile), clients: CLIENTS,
           locals: LOCALS, realms: REALMS, started: answer.started,
           keyRows: answer.keyRows, secretRows: answer.secretRows,
           subjects: answer.subjects, message: MESSAGE,
           pqKeys: answer.pq.keys };
}

/**
 * Checks `cluster-secrets-rust.json`: Rust's rows, opened and kept by Node,
 * must give Node the subjects Rust derived.
 *
 * @param {string} root - the repository root
 * @param {string} dir - the vector directory
 * @param {any} v - the Rust vectors
 * @param {function(boolean, string, string=): void} check - the collector
 */
function checkRust(root, dir, v, check) {
  log.debug("Entering checkRust().");
  let answer = null;
  try {
    answer = runChild(root, dir, path.join(dir, v.kekFile), {
      keyRows: v.keyRows, secretRows: v.secretRows, clients: CLIENTS,
      locals: LOCALS, realms: REALMS, message: MESSAGE,
      pqCheck: v.pqKeys || [] });
  } catch (e) {
    log.debug("Caught in checkRust(): " + ((e && e.message) || e));
    check(false, 'cluster secrets: Node opens the rows Rust wrote',
          String((e && e.message) || e));
    log.debug("Leaving checkRust(). The child failed.");
    return;
  }
  check(!!(answer.started && answer.started.shared),
        'cluster secrets: Node shares through Rust\'s store',
        JSON.stringify(answer.started));
  const kept = (answer.secretRows || []).filter(function (row) {
    const theirs = (v.secretRows || []).find(function (r) {
      return r.name === row.name;
    });
    return theirs && theirs.material === row.material;
  }).length;
  check(kept === (v.secretRows || []).length && kept > 0,
        'cluster secrets: Node keeps every row Rust offered first',
        kept + ' of ' + (v.secretRows || []).length);
  (v.subjects || []).forEach(function (one) {
    const mine = (answer.subjects || []).find(function (s) {
      return s.realm === one.realm && s.client === one.client &&
             s.local === one.local;
    });
    check(!!mine && mine.sub === one.sub,
          'cluster secrets: the pairwise sub Rust derived for ' +
          one.client + ' in [' + one.realm + ']',
          JSON.stringify({ rust: one.sub, node: mine && mine.sub }));
  });
  // The post-quantum keys Rust made, in the stored shape: each signature
  // Rust made verifies here, each private half signs here, and each `kid`
  // is the one Node would derive.
  check((v.pqKeys || []).length === 11,
        'post-quantum keys: Rust made all eleven of PQ_ALGS',
        String((v.pqKeys || []).length));
  ((answer.pq && answer.pq.checked) || []).forEach(function (one) {
    check(one.theirs && one.mine && one.kid,
          'post-quantum keys: Rust\'s ' + one.alg + ' key signs, verifies ' +
          'and is named as Node\'s', JSON.stringify(one));
  });
  log.debug("Leaving checkRust().");
}

module.exports = {
  build: build,
  checkRust: checkRust
};
