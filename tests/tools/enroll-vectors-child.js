// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: enroll-vectors-child.js
//
// ---------------------------------------------------------------------------
// THE PROCESS `enroll-vectors.js` RUNS, once to build the Node half and once
// to check the Rust half: `node enroll-vectors-child.js ROOT build OUT` or
// `node enroll-vectors-child.js ROOT check OUT RUST`. A child of its own
// because `common/cert_enrollment.js` reads the configuration when it is
// first required, and the vector runner's process has its own.
//
// What it builds, for `rust/crates/sts-enroll/tests/node_vectors.rs`:
//
// * `csrs`: a PKCS#10 request per key family with every kind of name, as
//   `x509.certificationRequest()` builds it, and `parseCsr()`'s reading of
//   it; four requests it refuses, with the code and the sentence.
// * `model`: bodies and queries the enrollment model reads, and zod's
//   answer — the parsed value, or the first issue's path and message.
// * `est`: `certsOnly()`, `csrAttrs()` and `decodeBody()`, byte for byte.
// * `scep`: an RA and a requester; a PKCSReq per content cipher, as
//   `tests/protocol/scep_client.js` builds one; `ScepCms.certsOnly()`
//   byte for byte; and a CertRep Node's RA signs and envelopes to the
//   requester.
// * `rows`: the directory attributes the core wrote for an EAB key, a SCEP
//   challenge and an EST certificate on one person — the store half, since
//   every record the core keeps is an attribute of the holder's entry.
//
// What it checks of the Rust half: Rust's CertRep read by the same client
// code a SCEP device test uses — the RA's signature, the digest, the echoed
// nonce and transactionID, and the envelope opened with the requester's key
// to Rust's certs-only bytes, which must be Node's for the same
// certificates. And the rows Rust wrote on another person, read by Node's
// core: its EAB key found, its challenge accepted, its certificates listed.
// (`findEnrolled()` starts at the authority's register of what a CA issued,
// sts-pki's rows, which `pki-authority-vectors.js` proves both ways.)
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const ROOT = process.argv[2];
const MODE = process.argv[3];
const OUT = process.argv[4];
const RUST = process.argv[5];

delete process.env.CONFIG_FILE;

const log = require(require.resolve('bunyan', { paths: [ROOT] }))
  .createLogger({ name: 'enroll-vectors', level: 'fatal' });
const keyMaterial = require(path.join(ROOT, 'common', 'crypto_impl',
                                      'key_material'));
const x509 = require(path.join(ROOT, 'common', 'crypto_impl', 'x509'));
const errorCodes = require(path.join(ROOT, 'common', 'error_codes'));
const core = require(path.join(ROOT, 'common', 'cert_enrollment'));
const helpers = require(path.join(ROOT, 'common', 'helpers'));
const pki = require(path.join(ROOT, 'common', 'pki'));
const realms = require(path.join(ROOT, 'common', 'realms'));
const model = require(path.join(ROOT, 'common', 'enrollment_model'));
const estCodec = require(path.join(ROOT, 'est', 'est_codec'));
const scepCms = require(path.join(ROOT, 'scep', 'scep_cms'));
const client = require(path.join(ROOT, 'tests', 'protocol', 'scep_client'));

const NAMES = [{ kind: 'dns', value: 'Host.Example.COM' },
               { kind: 'ip', value: '192.0.2.7' },
               { kind: 'ip', value: '2001:db8::1' },
               { kind: 'email', value: 'a@example.com' },
               { kind: 'uri', value: 'urn:sts:person:someone' },
               { kind: 'upn', value: 'someone@example.com' }];

// The cases the model is asked, each `[family, id, value]`. A query's values
// are strings, as express hands them over.
const MODEL = [
  ['acme', 'flattened', { protected: 'a', payload: '', signature: 's' }],
  ['acme', 'flattened', { protected: 'a', signature: 's' }],
  ['acme', 'flattened', { protected: '', payload: '', signature: 's' }],
  ['acme', 'flattened', { protected: 'a', payload: '', signature: 's',
                          header: {} }],
  ['acme', 'flattened', { protected: 1, payload: '', signature: 's' }],
  ['acme', 'protected-header', { alg: 'ES256', url: 'u', extra: true }],
  ['acme', 'protected-header', { alg: 'ES256', url: 'u', jwk: {} }],
  ['acme', 'protected-header', { alg: 'ES256', url: 'u', jwk: 'x' }],
  ['acme', 'eab-header', { alg: 'HS256', kid: 'k', url: 'u', x: 1 }],
  ['acme', 'new-account', { contact: ['mailto:a@b'], extra: 1 }],
  ['acme', 'new-account', { contact: 'mailto:a@b' }],
  ['acme', 'new-account', { contact: [''] }],
  ['acme', 'new-account', { termsOfServiceAgreed: 'yes' }],
  ['acme', 'new-order', { identifiers: [] }],
  ['acme', 'new-order', { identifiers: [{ type: 'dns', value: 'a' }] }],
  ['acme', 'new-order', { identifiers: [{ type: 'dns', value: 'a',
                                          extra: 1 }] }],
  ['acme', 'new-order', { identifiers: [{ type: 'dns' }] }],
  ['acme', 'new-order', {}],
  ['acme', 'revoke', { certificate: 'c', reason: 1.5 }],
  ['acme', 'revoke', { certificate: 'c', reason: 2000 }],
  ['acme', 'revoke', { certificate: 'c', reason: 4 }],
  ['acme', 'authz-update', { status: 'valid' }],
  ['acme', 'authz-update', { status: 'deactivated' }],
  ['acme', 'key-change-inner', { account: 'a', oldKey: { kty: 'EC' } }],
  ['acme', 'key-change-inner', { account: 'a', oldKey: { } }],
  ['acme', 'orders-query', { page: '2' }],
  ['acme', 'orders-query', { page: '0' }],
  ['acme', 'orders-query', { page: 'x' }],
  ['acme', 'orders-query', { page: '' }],
  ['est', 'query', {}],
  ['est', 'query', { x: '1' }],
  ['est', 'nonce-request', { len: 7 }],
  ['est', 'nonce-request', { len: 65 }],
  ['est', 'nonce-request', { len: 8, reqTypeInfo: { type: '1.2.3' } }],
  ['est', 'nonce-request', { reqTypeInfo: { type: 'not an oid' } }],
  ['est', 'nonce-request', { reqTypeInfo: { type: '1.2', more: 1 } }],
  ['scep', 'query', { operation: 'GetCACaps' }],
  ['scep', 'query', { operation: 'Nope' }],
  ['scep', 'query', {}],
  ['scep', 'query', { operation: 'PKIOperation', message: 'AAAA',
                      extra: 'stripped' }]
];

// `decodeBody()`'s cases, each the body as text.
const DECODE = ['MIIB', 'MI IB\r\n', '', '   ', 'MIIB=', 'MII*', 'MIIBAA==',
                'MIIBAB==', 'MII=', 'M===', 'TWFu\nTWE=\n'];

/**
 * Hex of a buffer.
 *
 * @param {Buffer|Uint8Array} bytes - the bytes
 * @returns {string} the hex
 */
function hex(bytes) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return Buffer.from(bytes).toString('hex');
}

/**
 * A request over a key of the family, naming `names`.
 *
 * @param {string} alg - `/admin/pki`'s name of the key
 * @param {any[]} names - the subjectAltName entries
 * @param {string} [signWith] - another key family to sign with (a forgery)
 * @returns {Promise<Buffer>} the DER
 */
async function requestFor(alg, names, signWith) {
  log.debug("Entering requestFor(). alg=" + alg);
  const pair = await keyMaterial.generateKeyPair(alg);
  const signer = signWith ? await keyMaterial.generateKeyPair(signWith) : pair;
  const csr = await x509.certificationRequest({
    subject: 'CN=enrollment vector,O=Iya',
    publicKeyPem: pair.publicPem,
    privateKeyPem: signer.privatePem,
    subjectAltName: names
  });
  log.debug("Leaving requestFor().");
  return Buffer.from(csr.der);
}

/**
 * `parseCsr()`'s reading, as JSON: what it read, or its code and sentence.
 *
 * @param {Buffer} der - the request
 * @returns {Promise<any>} the reading
 */
async function readingOf(der) {
  log.debug("Entering readingOf().");
  const parsed = await core.parseCsr(der);
  if (!parsed.ok) {
    log.debug("Leaving readingOf(). Refused.");
    return { ok: false, code: errorCodes.codeOf(parsed) || '',
             status: parsed.status, why: parsed.why };
  }
  log.debug("Leaving readingOf().");
  return { ok: true, keyAlg: parsed.keyAlg, keyKind: parsed.keyKind,
           subject: parsed.subject, commonName: parsed.commonName,
           challengePassword: parsed.challengePassword,
           attributeTypes: parsed.attributeTypes,
           publicKeyPem: parsed.publicKeyPem,
           requested: parsed.requested };
}

/**
 * The CSRs and their readings.
 *
 * @returns {Promise<any>} the `csrs` member
 */
async function csrs() {
  log.debug("Entering csrs().");
  const out = [];
  for (const alg of ['rsa-2048', 'ec-p256', 'ec-p384', 'ed25519',
                     'ml-dsa-44']) {
    const der = await requestFor(alg, NAMES);
    out.push({ what: alg, der: hex(der), reading: await readingOf(der) });
  }
  const good = await requestFor('ec-p256', []);
  const negatives = [
    ['forged', await requestFor('ec-p256', [], 'ec-p256')],
    ['not DER', Buffer.from('not a certificate request')],
    ['trailing byte', Buffer.concat([good, Buffer.from([0])])],
    ['empty', Buffer.alloc(0)]
  ];
  for (const [what, der] of negatives) {
    out.push({ what: what, der: hex(der), reading: await readingOf(der) });
  }
  log.debug("Leaving csrs().");
  return out;
}

/**
 * The model's answers.
 *
 * @returns {any[]} the `model` member
 */
function modelCases() {
  log.debug("Entering modelCases().");
  const out = MODEL.map(function (one) {
    const parsed = model.body(one[0], one[1]).safeParse(one[2]);
    if (parsed.success) {
      return { family: one[0], id: one[1], value: one[2], ok: true,
               data: parsed.data };
    }
    const issue = parsed.error.issues[0];
    return { family: one[0], id: one[1], value: one[2], ok: false,
             path: issue.path.map(String), message: issue.message };
  });
  log.debug("Leaving modelCases().");
  return out;
}

/**
 * EST's codec, byte for byte.
 *
 * @param {string[]} pems - certificates for `certsOnly()`
 * @returns {any} the `est` member
 */
function est(pems) {
  log.debug("Entering est().");
  const items = [
    { oid: '1.2.840.113549.1.9.7' },
    { type: '1.2.840.10045.2.1', values: [{ oid: '1.2.840.10045.3.1.7' }] },
    { type: '1.2.840.113549.1.9.14', values: [{ oid: '2.5.29.17' }] },
    { type: '2.5.4.3', values: [{ utf8: 'enrollment vector' }] },
    { oid: '1.2.840.10045.4.3.2' }
  ];
  const decoded = DECODE.map(function (text) {
    const answer = estCodec.decodeBody(Buffer.from(text, 'latin1'));
    return { text: text, ok: !!answer.ok,
             der: answer.ok ? hex(answer.der) : null };
  });
  log.debug("Leaving est().");
  return { pems: pems, certsOnly: hex(estCodec.certsOnly(pems)),
           items: items, csrAttrs: hex(estCodec.csrAttrs(items)),
           decoded: decoded };
}

/**
 * The SCEP half: the RA, the requester, PKCSReqs and a CertRep.
 *
 * @param {string[]} pems - certificates for the certs-only content
 * @returns {Promise<any>} the `scep` member
 */
async function scep(pems) {
  log.debug("Entering scep().");
  const raKey = client.rsaKey(2048);
  const raCert = client.selfSigned(raKey, 'enrollment vector RA');
  const deviceKey = client.rsaKey(2048);
  const deviceCert = client.selfSigned(deviceKey, 'enrollment vector device');
  const csr = client.csr(deviceKey, { challenge: 'p.challenge-value',
                                      commonName: 'device' });
  const messages = ['aes128', 'aes256', 'des3'].map(function (cipher, i) {
    const nonce = nodeCrypto.randomBytes(16);
    const der = client.signedMessage({
      content: client.envelope(csr, raCert, cipher),
      signerCertPem: deviceCert,
      signerKeyPem: deviceKey.privateKeyPem,
      messageType: '19',
      transactionID: 'vector-' + i,
      senderNonce: nonce
    });
    // Node's own reading of it, which Rust's must be: 3DES is refused.
    const parsed = scepCms.parsePkiMessage(der);
    const opened = parsed.ok
      ? scepCms.openEnvelope(parsed.content, raCert, raKey.privateKeyPem)
      : parsed;
    return { cipher: cipher, der: hex(der), nonce: hex(nonce),
             transactionID: 'vector-' + i,
             opened: opened.ok ? { ok: true, cipher: opened.cipher }
                               : { ok: false, code: opened.code,
                                   why: opened.why,
                                   failInfo: opened.failInfo } };
  });
  const certsOnly = scepCms.certsOnly(pems);
  const nonce = nodeCrypto.randomBytes(16);
  const rep = scepCms.certRep({
    raCertificatePem: raCert, raPrivateKeyPem: raKey.privateKeyPem,
    transactionID: 'vector-rep', recipientNonce: nonce,
    pkiStatus: '0',
    content: scepCms.envelope(certsOnly, deviceCert, '2.16.840.1.101.3.4.1.42')
  });
  const failure = scepCms.certRep({
    raCertificatePem: raCert, raPrivateKeyPem: raKey.privateKeyPem,
    transactionID: 'vector-fail', recipientNonce: nonce,
    pkiStatus: '2', failInfo: '4'
  });
  log.debug("Leaving scep().");
  return { ra: { certificatePem: raCert, privateKeyPem: raKey.privateKeyPem },
           device: { certificatePem: deviceCert,
                     privateKeyPem: deviceKey.privateKeyPem },
           csr: hex(csr), messages: messages,
           certsOnly: hex(certsOnly), certRep: hex(rep),
           failure: hex(failure), recipientNonce: hex(nonce) };
}

// THE DIRECTORY ROWS (the store interop, both ways). Every record the core
// keeps is an attribute of the holder's entry — the enrolled certificates,
// the EAB keys, the SCEP challenges — so a 1.x directory read by the Rust
// runtime, and an entry Rust wrote read by Node, are these values. The slot
// is an in-memory map, and a person's subject is `urn:uuid:` and the name,
// as the Rust test's directory answers it.
const ENTRIES = new Map();

/**
 * The directory slot and the subject resolver, over `ENTRIES`.
 */
function installDirectory() {
  log.debug("Entering installDirectory().");
  const key = function (kind, id) {
    return kind + '|' + id;
  };
  core.setDirectory({
    read: function (kind, id) {
      const held = ENTRIES.get(key(kind, id));
      return held ? { dn: 'uid=' + id + ',ou=users,dc=test',
                      attributes: Object.assign({}, held) } : null;
    },
    write: function (kind, id, name, values) {
      const held = ENTRIES.get(key(kind, id));
      if (!held) {
        return false;
      }
      if (values.length) {
        held[name] = values.slice();
      } else {
        delete held[name];
      }
      return true;
    },
    holders: function (kind, name) {
      const out = [];
      ENTRIES.forEach(function (held, k) {
        if (k.startsWith(kind + '|') && held[name]) {
          out.push(k.slice(kind.length + 1));
        }
      });
      return out;
    }
  });
  helpers.setSubjectResolver({
    subjectFor: function (name) {
      return ENTRIES.has(key('person', name)) ? 'urn:uuid:' + name : '';
    },
    nameFor: function (subject) {
      return String(subject).replace(/^urn:uuid:/, '');
    }
  });
  log.debug("Leaving installDirectory().");
}

/**
 * Node's rows: an EAB key, a SCEP challenge and an EST certificate on one
 * person, as the core wrote them.
 *
 * @returns {Promise<any>} the `rows` member
 */
async function rows() {
  log.debug("Entering rows().");
  installDirectory();
  await pki.start({});
  await pki.ensureScope(realms.currentId());
  ENTRIES.set('person|alicew', { uid: ['alicew'],
                                 mail: ['alicew@example.test'] });
  const target = { kind: 'person', id: 'alicew' };
  const eab = core.createEab({ target: target, createdBy: 'vector' });
  const challenge = core.createScepChallenge({ target: target,
                                               createdBy: 'vector' });
  const pair = await keyMaterial.generateKeyPair('ec-p256');
  const issued = await core.issue({
    family: 'est', profile: 'tls-client',
    principal: { kind: 'person', id: 'alicew', admin: false,
                 hasEntry: true, via: 'vector' },
    target: target, publicKeyPem: pair.publicPem, requested: {},
    via: 'vector'
  });
  if (!eab.ok || !challenge.ok || !issued.ok) {
    throw new Error('rows: ' + JSON.stringify([eab, challenge, issued]));
  }
  log.debug("Leaving rows().");
  return { attributes: ENTRIES.get('person|alicew'), kid: eab.kid,
           hmacKey: eab.hmacKey, challenge: challenge.challenge,
           challengeProfile: challenge.profile, record: issued.record,
           enrolled: core.enrolledOf(target) };
}

/**
 * What Node reads of the rows Rust wrote on `bobw`.
 *
 * @param {any} r - enroll-rust.json's `rows`
 * @param {Function} say - `(ok, what, detail)`
 */
function rowsFromRust(r, say) {
  log.debug("Entering rowsFromRust().");
  installDirectory();
  ENTRIES.set('person|bobw', Object.assign({}, r.attributes));
  const target = { kind: 'person', id: 'bobw' };
  const found = core.findEab(r.kid);
  // findEab() answers the MAC key as its bytes; createEab() showed it as
  // base64url.
  say(found && Buffer.from(found.hmacKey).toString('base64url') ===
      r.hmacKey && found.entry &&
      found.entry.id === 'bobw', "Node finds Rust's EAB key on its entry",
      JSON.stringify(found));
  const peek = core.redeemScepChallenge(r.challenge, { peek: true });
  say(peek.ok && peek.profile === r.challengeProfile &&
      peek.entry.id === 'bobw', "Node accepts Rust's SCEP challenge",
      JSON.stringify(peek));
  const enrolled = core.enrolledOf(target);
  say(JSON.stringify(enrolled) === JSON.stringify(r.enrolled),
      "Node reads Rust's enrolled certificates as Rust does",
      JSON.stringify(enrolled));
  log.debug("Leaving rowsFromRust().");
}

/**
 * The Node half.
 *
 * @returns {Promise<any>} every member
 */
async function build() {
  log.debug("Entering build().");
  const pems = ['one', 'two'].map(function (name) {
    return client.selfSigned(client.rsaKey(2048), 'enrollment vector ' + name);
  });
  const answer = { csrs: await csrs(), model: modelCases(), est: est(pems),
                   scep: await scep(pems), rows: await rows() };
  log.debug("Leaving build().");
  return answer;
}

/**
 * What Node reads of Rust's CertReps.
 *
 * @param {any} v - enroll-rust.json
 * @returns {any[]} `{ ok, what, detail }` per check
 */
function check(v) {
  log.debug("Entering check().");
  const out = [];
  const say = function (ok, what, detail) {
    out.push({ ok: !!ok, what: 'sts-enroll: ' + what, detail: detail || '' });
  };
  const ra = v.ra.certificatePem;
  const rep = client.readCertRep(Buffer.from(v.certRep, 'hex'), ra);
  say(rep.signatureVerifies, "Rust's CertRep verifies under its RA's key");
  say(rep.digestMatches, "Rust's CertRep's messageDigest is its content's");
  say(rep.messageType === '3' && rep.pkiStatus === '0',
      "Rust's CertRep is a SUCCESS CertRep",
      rep.messageType + '/' + rep.pkiStatus);
  say(rep.transactionID === v.transactionID,
      "Rust's CertRep echoes the transactionID", rep.transactionID);
  say(Buffer.from(rep.recipientNonce || '').equals(
    Buffer.from(v.recipientNonce, 'hex')),
      "Rust's CertRep echoes the sender's nonce as its recipientNonce");
  say(rep.certificates.length === 1 && rep.certificates[0].replace(/\s/g, '') ===
      ra.replace(/\s/g, ''), "Rust's CertRep carries its RA certificate");
  let opened = null;
  try {
    opened = client.openReply(rep.content, { privateKeyPem: v.device.privateKeyPem },
                              v.device.certificatePem);
  } catch (e) {
    log.debug("Caught in check(): " + ((e && e.message) || e));
    // The failure is the finding; the check below reports it.
  }
  say(opened && hex(opened.inner) === v.certsOnly,
      "Rust's envelope opens to the requester and holds its certs-only " +
      'content', opened ? opened.cipher : 'not opened');
  say(v.certsOnly === hex(scepCms.certsOnly(v.pems)),
      "Rust's certs-only is Node's, byte for byte, for the same certificates");
  say(v.estCertsOnly === hex(estCodec.certsOnly(v.pems)),
      "Rust's EST certs-only is Node's, byte for byte");
  const failure = client.readCertRep(Buffer.from(v.failure, 'hex'), ra);
  say(failure.signatureVerifies && failure.pkiStatus === '2' &&
      failure.failInfo === '2' && failure.failInfoName === 'badRequest',
      "Rust's FAILURE CertRep verifies and names badRequest",
      failure.pkiStatus + '/' + failure.failInfo);
  rowsFromRust(v.rows, say);
  log.debug("Leaving check().");
  return out;
}

/**
 * The child's whole run.
 */
async function main() {
  log.debug("Entering main().");
  const answer = MODE === 'check'
    ? check(JSON.parse(fs.readFileSync(RUST, 'utf8'))) : await build();
  fs.writeFileSync(OUT, JSON.stringify(answer));
  log.debug("Leaving main().");
}

main().then(function () {
  process.exit(0);
}, function (e) {
  log.debug("Caught in main(): " + ((e && e.message) || e));
  // The parent reads no answer file and fails with this on stderr.
  process.stderr.write(String((e && e.stack) || e) + '\n');
  process.exit(1);
});
