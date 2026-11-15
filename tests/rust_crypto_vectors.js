// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: rust_crypto_vectors.js
//
// ---------------------------------------------------------------------------
// THE NODE HALF OF THE OTHER DIRECTION OF THE PARITY PROOF (#444,
// rust/DESIGN.md sections 6 and 10.2): what the Rust crate `sts-crypto`
// signed, with keys it generated, verified by the Node service's own
// verifier.
//
// The vectors are written by that crate's test (`STS_WRITE_VECTORS=1`) into
// a directory that is NEVER COMMITTED — they carry private keys, and this
// repository commits no key material (`tests/tools/crypto-vectors.js` says
// how to make them). With none there this test says so and checks nothing:
// the Rust toolchain is not in the tests image yet. The first direction —
// every Node vector verified in Rust — is the crate's
// `tests/node_vectors.rs`.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const bunyan = require('bunyan');
const crypto = require('../common/crypto');

const log = bunyan.createLogger({ name: 'rust_crypto_vectors',
  level: process.env.STS_LOG_LEVEL || 'info' });

const VECTORS = process.env.STS_CRYPTO_VECTORS ||
  path.join(__dirname, 'vectors', 'sts-crypto');

/**
 * @param {string} name - the vector file
 * @returns {Array<any>} its rows
 */
function read(name) {
  log.debug("Entering read().");
  const rows = JSON.parse(fs.readFileSync(path.join(VECTORS, name), 'utf8'));
  log.debug("Leaving read().");
  return rows;
}

/**
 * The audit log's and the mail channel's checks, then the Kerberos codec's
 * (none needs another Rust vector), then the signing and encryption ones.
 *
 * @param {any} t - the runner's check collector
 * @returns {Promise<void>|undefined} when the asynchronous checks are done
 */
function run(t) {
  log.debug("Entering run().");
  log.debug("Leaving run(). The audit and mail checks are asynchronous.");
  // The audit log's and the mail channel's (#444, phase 4) first: each
  // half checks only what Rust wrote (tests/tools/auditmail-vectors.js).
  return require('./tools/auditmail-vectors.js').fromRust(t, VECTORS)
    .then(function () {
      return runKerberos(t);
    });
}

/**
 * The Kerberos codec's checks, then the rest.
 *
 * @param {any} t - the runner's check collector
 * @returns {Promise<void>|undefined} when the asynchronous checks are done
 */
function runKerberos(t) {
  log.debug("Entering runKerberos().");
  // The named policies' (#444 phase 4), which need no key and so no other
  // set: `tests/tools/policy-vectors.js` holds what the sts-policy crate
  // answered to Node's answers, and its generated passwords to Node's
  // password policy.
  if (fs.existsSync(path.join(VECTORS, 'policy-rust.json')) &&
      fs.existsSync(path.join(VECTORS, 'policy-node.json'))) {
    require('./tools/policy-vectors.js').checkRust(
      path.join(__dirname, '..'), read('policy-rust.json'),
      read('policy-node.json'), function (ok, what, detail) {
        t.check(ok, what, detail);
      });
  }
  // The credentials' (#444 phase 5): what sts-credentials stored, verified
  // by Node, and the public keys it read, verified with by Node.
  if (fs.existsSync(path.join(VECTORS, 'credentials-rust.json')) &&
      fs.existsSync(path.join(VECTORS, 'credentials-node.json'))) {
    require('./tools/credentials-vectors.js').checkRust(
      path.join(__dirname, '..'), read('credentials-rust.json'),
      read('credentials-node.json'), function (ok, what, detail) {
        t.check(ok, what, detail);
      });
  }
  // The session core's minted sessions (#444, phase 5), which need no
  // other set: tests/tools/session-vectors.js reads them back.
  if (fs.existsSync(path.join(VECTORS, 'session-rust.json'))) {
    require('./tools/session-vectors.js').checkRust(
      path.join(__dirname, '..'), read('session-rust.json'),
      function (ok, what, detail) {
        t.check(ok, what, detail);
      });
  }
  // Browsers' account sets (#561; #444, phase 5): the sets, cookies and
  // sessions sts-authn wrote, read back by tests/tools/account-set-vectors.js.
  if (fs.existsSync(path.join(VECTORS, 'account-sets-rust.json'))) {
    require('./tools/account-set-vectors.js').checkRust(
      path.join(__dirname, '..'), read('account-sets-rust.json'),
      function (ok, what, detail) {
        t.check(ok, what, detail);
      });
  }
  // The registers' role entries (#444, phase 4), which need no other set.
  if (fs.existsSync(path.join(VECTORS, 'registers-rust.json'))) {
    registersFromRust(t, JSON.parse(fs.readFileSync(path.join(VECTORS,
      'registers-rust.json'), 'utf8')));
  }
  // The directory's wire layer (sts-ldap): synchronous, and it needs no
  // other Rust vector.
  if (fs.existsSync(path.join(VECTORS, 'ldap-wire-rust.json'))) {
    require('./tools/ldap-wire-vectors.js').checkRust(
      path.join(__dirname, '..'), read('ldap-wire-rust.json'),
      function (/** @type {boolean} */ ok, /** @type {string} */ what) {
        t.check(ok, what);
      });
  }
  // The management API (sts-mgmt-api, #444 phase 4): synchronous, and it
  // needs no other Rust vector.
  if (fs.existsSync(path.join(VECTORS, 'mgmt-api-rust.json')) &&
      fs.existsSync(path.join(VECTORS, 'mgmt-api-node.json'))) {
    require('./tools/mgmt-api-vectors.js').checkRust(
      path.join(__dirname, '..'), read('mgmt-api-rust.json'),
      read('mgmt-api-node.json'),
      function (/** @type {boolean} */ ok, /** @type {string} */ what,
                /** @type {string} */ detail) {
        t.check(ok, what, detail);
      });
  }
  // The directory's model and operations (sts-directory): what it ended
  // with, read by Node's DomainMap. Synchronous too.
  if (fs.existsSync(path.join(VECTORS, 'directory-rust.json'))) {
    require('./tools/directory-vectors.js').checkRust(t,
      read('directory-rust.json'));
  }
  // The application register (sts-registers, #444 phase 4): the entries
  // Rust's register wrote, read back through Node's own register.
  // Synchronous.
  if (fs.existsSync(path.join(VECTORS, 'applications-rust.json'))) {
    require('./tools/applications-vectors.js').checkRust(t,
      read('applications-rust.json'));
  }
  // The authorization server's core (sts-oauth, #444 phase 5): a refresh
  // token Rust sealed and an access token Rust signed, read by Node.
  if (fs.existsSync(path.join(VECTORS, 'oauth-rust.json'))) {
    require('./tools/oauth-vectors.js').checkRust(path.join(__dirname, '..'),
      read('oauth-rust.json'), function (ok, what, detail) {
        t.check(ok, what, detail);
      });
  }
  if (!fs.existsSync(path.join(VECTORS, 'krb5-codec-rust.json'))) {
    log.debug("Leaving runKerberos(). No Kerberos vectors.");
    return runSigned(t);
  }
  log.debug("Leaving runKerberos(). The Kerberos checks are " +
            "asynchronous.");
  return krb5CodecFromRust(t, read('krb5-codec-rust.json'))
    .then(function () {
      return runSigned(t);
    });
}

/**
 * THE ROLE ENTRIES `sts-registers` WROTE (#444, phase 4), read back by
 * Node's own role register: each entry is handed to `common/roles.js` as
 * the whole of `ou=roles`, and Node's row for it must be the row Rust read
 * from it — so an entry the Rust runtime writes is one the Node service
 * (and an upgrade's either side) reads the same.
 *
 * @param {any} t - the runner's check collector
 * @param {any} v - registers-rust.json
 */
function registersFromRust(t, v) {
  log.debug("Entering registersFromRust().");
  const roles = require('../common/roles');
  const before = roles.directoryInstalled();
  try {
    (v.roles || []).forEach(function (one) {
      roles.setDirectory({
        allRoles: function () {
          return [one.entry];
        },
        writeRole: function () {
          return true;
        },
        deleteRole: function () {
          return false;
        },
        resolveOwner: function () {
          return { kind: '', dn: '', name: '' };
        },
        groupsOfUser: function () {
          return [];
        },
        ensureGroup: function () {
          return { ok: true };
        }
      });
      const row = roles.read(one.entry.name);
      t.check(JSON.stringify(row) === JSON.stringify(one.row),
              'the role entry sts-registers wrote for "' + one.entry.name +
              '" reads back in Node as Rust read it');
    });
  } finally {
    roles.setDirectory(before);
  }
  log.debug("Leaving registersFromRust().");
}

/**
 * @param {any} t - the runner's check collector
 * @returns {Promise<void>|undefined} when the asynchronous checks are done
 */
function runSigned(t) {
  log.debug("Entering runSigned().");
  // The XACML engine's (#444), which needs no key and so no other set:
  // `tests/tools/xacml-vectors.js` holds what the sts-xacml crate wrote to
  // Node's engine.
  if (fs.existsSync(path.join(VECTORS, 'xacml-rust.json')) &&
      fs.existsSync(path.join(VECTORS, 'xacml-node.json'))) {
    require('./tools/xacml-vectors.js').checkRust(
      path.join(__dirname, '..'), read('xacml-rust.json'),
      read('xacml-node.json'), function (ok, what, detail) {
        t.check(ok, what, detail);
      });
  }
  if (!fs.existsSync(path.join(VECTORS, 'jws-rust.json'))) {
    log.info('rust_crypto_vectors: no Rust vectors in ' + VECTORS + ', so ' +
             'nothing is checked (tests/tools/crypto-vectors.js says how ' +
             'to make them).');
    log.debug("Leaving runSigned(). No vectors.");
    return;
  }
  const rows = read('jws-rust.json');
  t.check(rows.length === crypto.JWS_SIGNING_ALGS.length,
          'there is one Rust JWS vector per algorithm Node speaks',
          rows.length + ' / ' + crypto.JWS_SIGNING_ALGS.length);
  rows.forEach(function (row) {
    // An HMAC key is its octets; every other key is handed over as the JWK
    // a verifier is given in practice.
    const key = row.jwk.kty === 'oct' ? Buffer.from(row.jwk.k, 'base64url')
      : row.jwk;
    let verified = null;
    let why = '';
    try {
      verified = crypto.verifyCompactJws(row.token, key,
                                         { algorithms: [row.alg] });
    } catch (e) {
      log.debug("Caught in runSigned(): " + ((e && e.message) || e));
      why = (e && e.message) || String(e);
    }
    t.check(!!verified && verified.claims.sub === 'alice' &&
            verified.header.kid === 'rust-1',
            row.alg + ': a token Rust signed with a key Rust generated ' +
            'verifies in Node', why);
  });
  log.debug("Leaving runSigned(). The JWE checks are asynchronous.");
  return jwesFromRust(t, read('jwe-rust.json')).then(function () {
    return afterJwes(t);
  });
}

// JWE: every JWE Rust encrypted decrypts in Node, through the door Node's
// own callers use — `decryptJweCompactAsync()`, which derives a PBES2 key
// off the event loop and is `decryptJweCompact()` for every other alg.
/**
 * @param {any} t - the runner's check collector
 * @param {any} jwes - jwe-rust.json
 * @returns {Promise<void>} when every row is checked
 */
async function jwesFromRust(t, jwes) {
  log.debug("Entering jwesFromRust().");
  t.check(jwes.length >= crypto.JWE_ALGS.length,
          'there is a Rust JWE vector for every alg Node speaks',
          jwes.length + ' / ' + crypto.JWE_ALGS.length);
  for (const row of jwes) {
    const options = {};
    if (row.secret) {
      options.secret = Buffer.from(row.secret, 'base64url');
    }
    if (row.privatePem) {
      options.privateKey = nodeCrypto.createPrivateKey(row.privatePem);
    }
    if (row.privateJwk) {
      options.privateJwk = row.privateJwk;
    }
    let opened = null;
    let why = '';
    try {
      opened = await crypto.decryptJweCompactAsync(row.compact, options);
    } catch (e) {
      log.debug("Caught in jwesFromRust(): " + ((e && e.message) || e));
      why = (e && e.message) || String(e);
    }
    t.check(!!opened && opened.plaintext === '{"sub":"alice"}',
            row.alg + ' ' + row.enc + ': a JWE Rust encrypted decrypts in ' +
            'Node', why);
  }
  log.debug("Leaving jwesFromRust().");
}

/**
 * The checks after the JWE ones.
 *
 * @param {any} t - the runner's check collector
 * @returns {Promise<void>|undefined} when the asynchronous checks are done
 */
function afterJwes(t) {
  log.debug("Entering afterJwes().");
  if (fs.existsSync(path.join(VECTORS, 'xmldsig-rust.json'))) {
    xmlSignatures(t, read('xmldsig-rust.json'));
  }
  if (fs.existsSync(path.join(VECTORS, 'pq-x509-rust.json'))) {
    log.debug("Leaving afterJwes(). The post-quantum checks are " +
              "asynchronous.");
    return pqX509FromRust(t, read('pq-x509-rust.json')).then(function () {
      return restOfRun(t);
    });
  }
  log.debug("Leaving afterJwes().");
  return restOfRun(t);
}

/**
 * The checks after the post-quantum X.509 ones.
 *
 * @param {any} t - the runner's check collector
 * @returns {Promise<void>|undefined} when the asynchronous checks are done
 */
function restOfRun(t) {
  log.debug("Entering restOfRun().");
  if (fs.existsSync(path.join(VECTORS, 'secrets-rust.json'))) {
    secretsFromRust(t, read('secrets-rust.json'));
  }
  if (fs.existsSync(path.join(VECTORS, 'xmlenc-rust.json')) &&
      fs.existsSync(path.join(VECTORS, 'xmlenc-node.json'))) {
    xmlEncryption(t, read('xmlenc-rust.json'), read('xmlenc-node.json'));
  }
  const pending = [];
  if (fs.existsSync(path.join(VECTORS, 'webauthn-rust.json')) &&
      fs.existsSync(path.join(VECTORS, 'webauthn-node.json'))) {
    coseSign1FromRust(t, read('webauthn-rust.json'),
                      read('webauthn-node.json'));
  }
  if (fs.existsSync(path.join(VECTORS, 'raw-sig-rust.json'))) {
    pending.push(function () {
      return rawSignaturesFromRust(t, read('raw-sig-rust.json'));
    });
  }
  if (fs.existsSync(path.join(VECTORS, 'sigstore-rust.json'))) {
    pending.push(function () {
      return sigstoreFromRust(t, read('sigstore-rust.json'));
    });
  }
  if (fs.existsSync(path.join(VECTORS, 'x509-rust.json'))) {
    pending.push(function () {
      return x509FromRust(t, read('x509-rust.json'));
    });
  }
  if (fs.existsSync(path.join(VECTORS, 'x509-door-rust.json'))) {
    x509DoorFromRust(t, read('x509-door-rust.json'));
  }
  log.debug("Leaving restOfRun(). " + pending.length + " asynchronous.");
  return pending.reduce(function (chain, next) {
    return chain.then(next);
  }, Promise.resolve());
}

// X.509: every certificate Rust issued is described by Node exactly as Rust
// describes it (a post-quantum key aside, which Node calls "Ed25519"), and
// every link of its chain verifies in Node as it does in Rust; every
// PKCS#10 request Rust made parses, and its proof of possession verifies
// where pkijs can check one.
/**
 * @param {any} t - the runner's check collector
 * @param {any} rows - x509-rust.json
 * @returns {Promise<void>} when every row is checked
 */
async function x509FromRust(t, rows) {
  log.debug("Entering x509FromRust().");
  const x509 = require('../common/crypto_impl/x509.js');
  const pkijs = require('pkijs');
  const bytes = require('../common/crypto_impl/crypto_bytes.js');
  const strip = function (link) {
    const out = Object.assign({}, link);
    delete out.error;
    return out;
  };
  for (const row of rows) {
    if (row.csr) {
      let ok = false;
      let why = '';
      try {
        const req = pkijs.CertificationRequest.fromBER(
          bytes.pemToDer(row.csr));
        const oid = req.signatureAlgorithm.algorithmId;
        ok = oid === '1.3.101.112' || /^2\.16\.840\.1\.101\.3\.4\.3\./.test(oid)
          ? true : await req.verify();
      } catch (e) {
        log.debug("Caught in x509FromRust(): " + ((e && e.message) || e));
        why = (e && e.message) || String(e);
      }
      t.check(ok, row.name + ': a request Rust made parses in Node, and ' +
              'verifies where pkijs can check it', why);
      continue;
    }
    const described = await x509.describeCertificate(row.pem);
    const mine = Object.assign({}, row.describe);
    if (described.publicKey === 'Ed25519' && mine.publicKey !== 'Ed25519') {
      described.publicKey = mine.publicKey;
    }
    t.check(JSON.stringify(described) === JSON.stringify(mine),
            row.name + ': Node describes a certificate Rust issued as Rust ' +
            'does', JSON.stringify(described));
    const links = (await x509.verifyChain(row.chain)).map(strip);
    t.check(JSON.stringify(links) === JSON.stringify(row.links.map(strip)) &&
            links[0].signatureValid === true,
            row.name + ': its chain verifies in Node as in Rust',
            JSON.stringify(links));
  }
  log.debug("Leaving x509FromRust().");
}

// THE PURE HALF OF THE ONE VALIDATION DOOR (#1360): every certificate Rust
// issued has, in Node, the facts and the field problems `sts-pki` gave it
// under every option set.
/**
 * @param {any} t - the runner's check collector
 * @param {any} v - x509-door-rust.json
 */
function x509DoorFromRust(t, v) {
  log.debug("Entering x509DoorFromRust().");
  const util = require('util');
  const attempt = function (f) {
    try {
      return f();
    } catch (e) {
      log.debug("Caught in x509DoorFromRust(): " + ((e && e.message) || e));
      return { error: e.message };
    }
  };
  for (const row of v.certificates) {
    const facts = attempt(function () {
      return crypto.certificateFacts(row.pem);
    });
    t.check(util.isDeepStrictEqual(facts, row.facts),
            row.name + ': Node reads a certificate Rust issued as Rust ' +
            'does', JSON.stringify(facts));
    v.options.forEach(function (o, i) {
      const problems = attempt(function () {
        return crypto.certificateFieldProblems(row.pem,
          Object.assign({ now: v.now }, o));
      });
      t.check(util.isDeepStrictEqual(problems, row.problems[i]),
              row.name + ': its field problems under ' + JSON.stringify(o) +
              ' are Rust\'s', JSON.stringify(problems));
    });
  }
  log.debug("Leaving x509DoorFromRust().");
}

// SIGSTORE AND TUF: Rust's two canonical forms are Node's strings, every TUF
// signature Rust made — Ed25519, ECDSA, RSA and ML-DSA — counts towards the
// role's threshold here, and Rust's Rekor SET verifies (and, its log index
// changed, does not).
/**
 * @param {any} t - the runner's check collector
 * @param {any} v - sigstore-rust.json
 * @returns {Promise<void>} when every check is made
 */
async function sigstoreFromRust(t, v) {
  log.debug("Entering sigstoreFromRust().");
  t.check(crypto.olpcCanonicalJson(v.signed) === v.olpc,
          'Rust\'s OLPC canonical JSON is Node\'s');
  t.check(crypto.jcsCanonicalJson(v.rekor.payload) === v.rekor.jcs,
          'Rust\'s JCS canonical JSON is Node\'s');
  const verdict = await crypto.verifyThresholdSignatures(v.signed,
                                                         v.signatures,
                                                         v.keys, v.role);
  t.check(verdict.ok && verdict.valid === 4,
          'all four TUF signatures Rust made verify in Node',
          JSON.stringify(verdict));
  const logs = v.rekor.logs.map(function (l) {
    return { logIdHex: l.logIdHex, spki: Buffer.from(l.spki, 'base64') };
  });
  const set = Buffer.from(v.rekor.set, 'base64');
  t.check(await crypto.verifyRekorSet(v.rekor.payload, set, logs) === '',
          'a Rekor SET Rust signed verifies in Node');
  const changed = Object.assign({}, v.rekor.payload,
                                { logIndex: v.rekor.payload.logIndex + 1 });
  t.check(await crypto.verifyRekorSet(changed, set, logs) ===
          'unable to verify SET', 'and not over another log index');
  log.debug("Leaving sigstoreFromRust().");
}

// COSE_SIGN1 (#1368): every COSE_Sign1 Rust signed with Node's key, in each
// algorithm coseSign1Sign() signs with, verifies with coseSign1Verify() over
// the same protected header, payload and external AAD.
/**
 * @param {any} t - the runner's check collector
 * @param {any} vectors - webauthn-rust.json
 * @param {any} node - webauthn-node.json, for the message
 */
function coseSign1FromRust(t, vectors, node) {
  log.debug("Entering coseSign1FromRust().");
  const message = node.coseSign1;
  vectors.coseSign1.forEach(function (row) {
    let ok = false;
    try {
      ok = crypto.coseSign1Verify(row.alg, row.publicJwk,
        Buffer.from(message.protected, 'base64'),
        Buffer.from(message.payload, 'base64'),
        Buffer.from(row.signature, 'base64'),
        { external: Buffer.from(message.external, 'base64') });
    } catch (e) {
      log.debug("Caught in coseSign1FromRust(): " + ((e && e.message) || e));
    }
    t.check(ok, 'COSE ' + row.alg + ': a COSE_Sign1 Rust signed verifies ' +
            'in Node');
  });
  log.debug("Leaving coseSign1FromRust().");
}

// RAW SIGNATURES, THE PQ FAMILY WITH THE ALGORITHM NAMED (#1368): every
// signature Rust made under Node's raw AKP private key verifies with
// verifyRawSignature() against the raw public key.
/**
 * @param {any} t - the runner's check collector
 * @param {any} vectors - raw-sig-rust.json
 * @returns {Promise<void>} when every row is checked
 */
async function rawSignaturesFromRust(t, vectors) {
  log.debug("Entering rawSignaturesFromRust().");
  const data = Buffer.from('a challenge the attestor signs');
  for (const row of vectors.named) {
    const ok = await crypto.verifyRawSignature(
      { family: 'pq', alg: row.alg }, Buffer.from(row.pub, 'base64'), data,
      Buffer.from(row.signature, 'base64'));
    t.check(ok, row.alg + ': a raw post-quantum signature Rust made, the ' +
            'algorithm named, verifies in Node');
  }
  log.debug("Leaving rawSignaturesFromRust().");
}

// POST-QUANTUM KEYS IN X.509: every signature Rust made verifies with
// pqc_x509.js, the engine every post-quantum certificate here is checked by
// — the P-521 composite too, since #445 made that engine's ECDSA half DER.
/**
 * @param {any} t - the runner's check collector
 * @param {any} rows - pq-x509-rust.json
 * @returns {Promise<void>} when every row is checked
 */
async function pqX509FromRust(t, rows) {
  log.debug("Entering pqX509FromRust().");
  const pqcX509 = require('../common/crypto_impl/pqc_x509.js');
  for (const row of rows) {
    let ok = false;
    try {
      ok = await pqcX509.verify(row.id, Buffer.from(row.signature, 'base64'),
                                Buffer.from(row.message, 'base64'),
                                Buffer.from(row.pub, 'base64'));
    } catch (e) {
      log.debug("Caught in pqX509FromRust(): " + ((e && e.message) || e));
    }
    t.check(ok, row.id + ': a signature Rust made verifies in Node');
  }
  log.debug("Leaving pqX509FromRust().");
}

// SECRETS: every scrypt hash Rust made verifies here (and a wrong secret
// does not), so does every password hash it made under a password policy's
// spec — argon2id and scrypt (#847, #872) — every envelope Rust sealed opens under its data key, and every
// data key Rust wrapped unwraps under the key-encryption key and AAD.
/**
 * @param {any} t - the runner's check collector
 * @param {any} vectors - secrets-rust.json
 */
function secretsFromRust(t, vectors) {
  log.debug("Entering secretsFromRust().");
  vectors.hashes.forEach(function (row) {
    t.check(crypto.verifySecret(row.plain, row.stored) &&
            !crypto.verifySecret(row.plain + 'x', row.stored),
            'a scrypt hash Rust made verifies in Node, and only for its ' +
            'secret');
  });
  (vectors.passwords || []).forEach(function (row) {
    t.check(crypto.verifySecret(row.plain, row.stored) &&
            !crypto.verifySecret(row.plain + 'x', row.stored) &&
            crypto.storedSecretMatchesSpec(row.stored, row.ask),
            'a password hash Rust made under ' + JSON.stringify(row.ask) +
            ' verifies in Node, only for its password, and is what Node ' +
            'would write under that spec');
  });
  vectors.envelopes.forEach(function (row) {
    let opened = null;
    try {
      opened = crypto.decryptWithDek(Buffer.from(row.key, 'base64'),
                                     row.sealed, 'vectors');
    } catch (e) {
      log.debug("Caught in secretsFromRust(): " + ((e && e.message) || e));
    }
    t.check(opened === row.plain, row.alg + ': an envelope Rust sealed ' +
            'opens in Node');
  });
  vectors.wraps.forEach(function (row) {
    let dek = null;
    try {
      dek = crypto.unwrapDek(row.kek, row.wrapped, row.aad);
    } catch (e) {
      log.debug("Caught in secretsFromRust(): " + ((e && e.message) || e));
    }
    t.check(!!dek && dek.toString('base64') === row.dek,
            'a data key Rust wrapped unwraps in Node');
  });
  log.debug("Leaving secretsFromRust().");
}

// XML ENCRYPTION: every element Rust encrypted — an RSA recipient in each
// cipher and key transport, an EC one in each curve, key wrap and cipher —
// decrypts with crypto.decryptElement() to the plaintext it was given, with
// the recipient key Node generated (xmlenc-node.json). A row Rust made under
// a scenario's settings (product mode, #1455 and #1469) is read under the
// same settings, and gets the verdict Node gave its own encryption there:
// an AES-CBC element product writes when asked is one it refuses to read.
/**
 * @param {any} t - the runner's check collector
 * @param {any} vectors - xmlenc-rust.json
 * @param {any} node - xmlenc-node.json, for the recipients' keys
 */
function xmlEncryption(t, vectors, node) {
  log.debug("Entering xmlEncryption().");
  const config = require('../common/config');
  const nodeVerdicts = {};
  (node.policies || []).forEach(function (scenario) {
    scenario.cases.forEach(function (c) {
      nodeVerdicts[scenario.name + ': ' + c.name] = c.verdict;
    });
  });
  vectors.cases.forEach(function (row) {
    const settings = row.settings || [];
    let opened;
    try {
      settings.forEach(function (one) {
        config.setOverride(one[0], one[1]);
      });
      opened = crypto.decryptElement(row.xml,
        node.recipients[row.recipient].privateKeyPem, {});
    } finally {
      settings.slice().reverse().forEach(function (one) {
        config.clearOverride(one[0]);
      });
    }
    const want = nodeVerdicts[row.name];
    if (settings.length && want && !want.ok) {
      t.check(!opened.ok && require('../common/error_codes').codeOf(opened) ===
              want.code, row.name + ': an element Rust encrypted gets ' +
              'Node\'s refusal in Node (' + want.code + ')', opened.why || '');
      return;
    }
    t.check(!!opened.ok && opened.xml === row.plain,
            row.name + ': an element Rust encrypted decrypts in Node',
            opened.why || '');
  });
  log.debug("Leaving xmlEncryption().");
}

// XML SIGNATURE: every document Rust signed, in each of the ten methods
// saml.signatureAlgorithm offers, gets the verdict from
// crypto.verifyXmlSignature() here that Node's own signature of the same
// document got (`ok`, carried in the vector) — a WithComments signature over
// a document with a comment fails in both, because signEnveloped() digests
// without comments; and every Redirect binding signature verifies against
// the signer's public key.
/**
 * @param {any} t - the runner's check collector
 * @param {any} vectors - xmldsig-rust.json
 */
function xmlSignatures(t, vectors) {
  log.debug("Entering xmlSignatures().");
  vectors.signed.forEach(function (row) {
    const verdict = crypto.verifyXmlSignature(row.signed, {
      element: row.element, publicKeyPem: row.publicKeyPem });
    t.check(!!verdict.ok === !!row.ok,
            row.name + ': the XML Rust signed gets Node\'s verdict on its ' +
            'own (' + (row.ok ? 'verifies' : 'refused') + ')', verdict.why);
  });
  vectors.queries.forEach(function (row) {
    const method = crypto.xmlSignatureAlgorithms().verified
      .filter(function (m) { return m.uri === row.sigAlg; })[0];
    let ok = false;
    try {
      ok = !!method && crypto.verifyXmlSignatureValue(row.sigAlg,
        nodeCrypto.createPublicKey(row.publicKeyPem),
        Buffer.from(row.query, 'utf8'),
        Buffer.from(row.signature, 'base64'), null);
    } catch (e) {
      log.debug("Caught in xmlSignatures(): " + ((e && e.message) || e));
    }
    t.check(ok, row.name + ': a Redirect binding signature Rust made ' +
            'verifies in Node');
  });
  log.debug("Leaving xmlSignatures().");
}

// THE KERBEROS CODEC (#444, phase 2b): what `sts-kerberos` made — keys from
// passwords, ciphertexts under its own random confounders, checksums,
// messages of every kind it encodes, MIC and Wrap tokens, SPNEGO tokens,
// a 0x8003 checksum, a keytab and the MS-KKDCP envelope — read by kerberos/'s codec
// here: the same key, the plaintext back, the checksum verified, and each
// message decoded to the JSON Rust decoded it to and re-encoded to Rust's
// bytes.
/**
 * @param {any} t - the runner's check collector
 * @param {any} v - krb5-codec-rust.json
 * @returns {Promise<void>} when every check has run
 */
async function krb5CodecFromRust(t, v) {
  log.debug("Entering krb5CodecFromRust().");
  const K = path.join(__dirname, '..', 'kerberos');
  const asn1 = require(path.join(K, 'krb5_asn1.js'));
  const kc = require(path.join(K, 'krb5_crypto.js'));
  const m = require(path.join(K, 'krb5_messages.js'));
  const gss = require(path.join(K, 'krb5_gss.js'));
  const sp = require(path.join(K, 'krb5_spnego.js'));
  const fc = require(path.join(K, 'krb5_fast_codec'));
  const pc = require(path.join(K, 'krb5_pkinit_codec'));
  const hex = function (/** @type {any} */ b) {
    return Buffer.from(b).toString('hex');
  };
  const unhex = function (/** @type {string} */ s) {
    return new Uint8Array(Buffer.from(s, 'hex'));
  };
  // Node's answer as the JSON Rust serializes to, keys sorted so that two
  // answers compare as text.
  /** @type {(v: any) => any} */
  const canon = function (v) {
    if (v === null || v === undefined) {
      return v === null ? null : undefined;
    }
    if (v instanceof Uint8Array) {
      return hex(v);
    }
    if (v instanceof Date) {
      return v.toISOString();
    }
    if (Array.isArray(v)) {
      return v.map(canon);
    }
    if (typeof v === 'object') {
      /** @type {any} */
      const out = {};
      Object.keys(v).sort().forEach(function (k) {
        const n = canon(v[k]);
        if (n !== undefined) {
          out[k] = n;
        }
      });
      return out;
    }
    return v;
  };
  const same = function (/** @type {any} */ a, /** @type {any} */ b) {
    return JSON.stringify(canon(a)) === JSON.stringify(canon(b));
  };
  const tlvOf = function (/** @type {Uint8Array} */ b) {
    return asn1.readTlv(b, 0);
  };
  /** @type {Object<string, Array<Function>>} */
  const KINDS = {
    Ticket: [m.readTicket, m.encTicket],
    EncTicketPart: [m.readEncTicketPart, m.encEncTicketPart],
    KdcReq: [m.readKdcReq, m.encKdcReq],
    KdcRep: [m.readKdcRep, m.encKdcRep],
    EncKdcRepPart: [m.readEncKdcRepPart, function (/** @type {any} */ p) {
      return m.encEncKdcRepPart(p, p.taggedAs === 'EncTGSRepPart' ? 26 : 25);
    }],
    Authenticator: [m.readAuthenticator, m.encAuthenticator],
    ApReq: [m.readApReq, m.encApReq],
    ApRep: [m.readApRep, m.encApRep],
    EncApRepPart: [m.readEncApRepPart, m.encEncApRepPart],
    KrbError: [m.readKrbError, m.encKrbError],
    PaEncTsEnc: [m.readPaEncTsEnc, function (/** @type {any} */ p) {
      return m.encPaEncTsEnc(p.patimestamp, p.pausec);
    }],
    PaForUser: [m.readPaForUser, m.encPaForUser],
    PaPacOptions: [m.readPaPacOptions, function (/** @type {any} */ p) {
      return m.encPaPacOptions(p.flags);
    }],
    EncKrbCredPart: [m.readEncKrbCredPart, m.encEncKrbCredPart],
    KrbCred: [m.readKrbCred, m.encKrbCred],
    'fast.FastReq': [fc.readFastReq, fc.encFastReq],
    'fast.FastRequest': [fc.readFastRequest, fc.encFastRequest],
    'fast.FastReply': [fc.readFastReply, fc.encFastReply],
    'fast.FastResponse': [fc.readFastResponse, fc.encFastResponse],
    'fast.OtpChallenge': [fc.readOtpChallenge, fc.encOtpChallenge],
    'fast.OtpRequest': [fc.readOtpRequest, fc.encOtpRequest],
    'fast.Cammac': [fc.readCammac, fc.encCammac],
    'fast.Indicators': [fc.readIndicators, fc.encIndicators],
    'pkinit.Krb5PrincipalName': [pc.readKrb5PrincipalName,
      function (/** @type {any} */ p) {
        return pc.encKrb5PrincipalName(p.realm, p.name);
      }],
    'pkinit.PaPkAsReq': [pc.readPaPkAsReq, pc.encPaPkAsReq],
    'pkinit.AuthPack': [pc.readAuthPack, pc.encAuthPack],
    'pkinit.PaPkAsRep': [pc.readPaPkAsRep, pc.encPaPkAsRep],
    'pkinit.KdcDhKeyInfo': [pc.readKdcDhKeyInfo, pc.encKdcDhKeyInfo]
  };
  for (const row of v.stringToKey) {
    const key = await kc.ETYPES[row.etype].stringToKey(row.password,
      unhex(row.salt), row.params ? unhex(row.params) : null);
    t.check(hex(key) === row.key, 'etype ' + row.etype + ': Node derives ' +
            'from the password the key Rust derived');
  }
  let opened = 0;
  for (const row of v.encryptions) {
    let plain = null;
    try {
      plain = await kc.ETYPES[row.etype].decrypt(unhex(row.key), row.usage,
                                                 unhex(row.cipher));
    } catch (e) {
      log.debug("Caught in krb5CodecFromRust(): " + ((e && e.message) || e));
    }
    if (plain && hex(plain) === row.plain) {
      opened++;
    }
  }
  t.check(opened === v.encryptions.length, 'every ciphertext Rust made ' +
          'under each enctype and usage decrypts in Node',
          opened + ' / ' + v.encryptions.length);
  let verified = 0;
  for (const row of v.checksums) {
    if (await kc.ETYPES[row.etype].verifyChecksum(unhex(row.key), row.usage,
        unhex(row.message), unhex(row.checksum))) {
      verified++;
    }
  }
  t.check(verified === v.checksums.length, 'every checksum Rust made ' +
          'verifies in Node', verified + ' / ' + v.checksums.length);
  v.messages.forEach(function (/** @type {any} */ row) {
    const pair = KINDS[row.kind];
    let decoded = null;
    let again = '';
    let why = '';
    try {
      decoded = pair[0](unhex(row.bytes));
      again = hex(pair[1](decoded));
    } catch (e) {
      log.debug("Caught in krb5CodecFromRust(): " + ((e && e.message) || e));
      why = (e && e.message) || String(e);
    }
    t.check(!!decoded && same(decoded, row.decoded), row.kind + ': a ' +
            'message Rust encoded decodes in Node to what Rust read', why);
    t.check(again === row.bytes, row.kind + ': Node re-encodes it to ' +
            'Rust\'s bytes', why);
  });
  for (const row of v.tokens) {
    const key = unhex(row.key);
    const message = unhex(row.message);
    const verdict = await gss.verifyMic({ key: key, etype: row.etype,
      token: unhex(row.mic), message: message });
    t.check(verdict.ok, 'etype ' + row.etype + ': a MIC token Rust made ' +
            'verifies in Node');
    const unwrapped = await gss.unwrap({ key: key, etype: row.etype,
                                        token: unhex(row.wrap) });
    t.check(hex(unwrapped.message) === row.message, 'etype ' + row.etype +
            ': a Wrap token Rust sealed unwraps in Node');
  }
  v.spnego.forEach(function (/** @type {any} */ row) {
    const decoded = sp.decodeNegotiationToken(unhex(row.bytes));
    t.check(same(decoded, row.decoded), decoded.kind + ': a SPNEGO token ' +
            'Rust encoded decodes in Node to what Rust read');
  });
  t.check(same(gss.parseGssChecksum(unhex(v.gssChecksum.bytes)),
               v.gssChecksum.parsed), 'a 0x8003 checksum Rust built ' +
          'parses in Node as Rust parses it');
  const kt = require(path.join(K, 'krb5_keytab'));
  t.check(same(kt.readKeytab(unhex(v.keytab.bytes)), v.keytab.entries),
          'a keytab Rust wrote reads in Node as Rust reads it');
  // The /KdcProxy reading (krb5_kdc.js) of both envelopes Rust built, and
  // the reply envelope Node itself would build.
  [v.kkdcp.envelope, v.kkdcp.client].forEach(function (/** @type {any} */ e) {
    const outer = asn1.readTlv(unhex(e), 0);
    const framed = asn1.decOctetString(asn1.readTaggedSequence(
      outer.value)[0]);
    const declared = (framed[0] << 24 | framed[1] << 16 | framed[2] << 8 |
                      framed[3]) >>> 0;
    t.check(hex(framed.subarray(4, 4 + declared)) === v.kkdcp.message,
            'a KDC-PROXY-MESSAGE Rust built carries its message to Node');
  });
  const reply = unhex(v.kkdcp.message);
  const framedReply = new Uint8Array(4 + reply.length);
  new DataView(framedReply.buffer).setUint32(0, reply.length);
  framedReply.set(reply, 4);
  t.check(hex(asn1.encSequence([asn1.encContext(0,
    asn1.encOctetString(framedReply))])) === v.kkdcp.envelope,
          'Rust\'s /KdcProxy reply envelope is the one Node builds');
  log.debug("Leaving krb5CodecFromRust().");
}

module.exports = {
  name: 'rust_crypto_vectors',
  describe: 'what the Rust sts-crypto crate signed verifies, and what it ' +
            'encrypted decrypts, in the Node service — every JWS and JWE ' +
            'algorithm, every XML signature method this service signs ' +
            'with, and every XML Encryption cipher, transport and ' +
            'agreement — and what sts-kerberos made is read by the ' +
            'Kerberos codec, and what sts-ldap made is answered by ' +
            'node-ldapjs as by Rust, and what sts-directory ended with ' +
            'is read by Node\'s DomainMap',
  run: run
};
