// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pki-authority-vectors.js
//
// ---------------------------------------------------------------------------
// THE CERTIFICATE AUTHORITY (#444, phase 6, the `pki` slice): what
// `common/pki.js` and `common/pki_revocation.js` build, issue, revoke, list
// and answer, for the Rust crate `sts-pki` (`src/authority/`) to read and
// reproduce. Called by `tests/tools/crypto-vectors.js`'s
// `pki-authority-node.json` row.
//
// ONE CHILD PROCESS, IN PRODUCT KEY HANDLING, OVER A STORE OF ITS OWN: the
// keystore reads a key-encryption key from a file and seals every `pki:` row
// into an in-memory driver, exactly as a 1.x product install seals them into
// postgres. The child builds the service Root, the process branch and the
// default realm's branch; issues two enrolled certificates under the ACME
// Issuing CA (`issueEnrolled()`, the enrolment core's door); revokes one for
// keyCompromise and puts an unknown serial on hold; signs four CRLs; and
// answers four OCSP requests (revoked, good with a nonce, unknown, another
// issuer's). Everything goes out: the sealed rows and the KEK (the store
// half), the rows opened (the authority half), the DERs with the moments and
// numbers they were made with, and the addresses every certificate names.
//
// THE RUST HALF (`rust/crates/sts-pki/tests/pki_authority_vectors.rs`) holds
// the rows as Node left them, ensures the Root and the branches — and must
// build NOTHING — issues under Node's ACME CA, re-signs Node's CRLs and OCSP
// answers at Node's moments and numbers (byte for byte: the hierarchy is
// RSA, whose PKCS#1 v1.5 signature is deterministic), and with
// STS_WRITE_VECTORS=1 writes a hierarchy of its own, a leaf, a CRL and an
// OCSP answer. `checkRust()` below hands those to Node, in a child again: the
// rows are held by Node's keystore, Node issues under Rust's ACME CA, and
// pkijs parses and verifies Rust's CRL and OCSP answer against Rust's CA.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');
const nodeCrypto = require('crypto');

// The program the child runs, for the Node half.
const BUILD = [
  "'use strict';",
  'const path = require("path");',
  'const ROOT = process.argv[1];',
  'const nodeCrypto = require("crypto");',
  'const keystore = require(path.join(ROOT, "common", "keystore.js"));',
  'const pkijs = require(require.resolve("pkijs", { paths: [ROOT] }));',
  'const asn1js = require(require.resolve("asn1js", { paths: [ROOT] }));',
  'function der(pem) {',
  '  return Buffer.from(String(pem).replace(/-----[^-]+-----/g, "")',
  '    .replace(/\\s+/g, ""), "base64");',
  '}',
  'function ab(buf) {',
  '  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length);',
  '}',
  'async function request(issuerPem, serialHex, nonce, hashName) {',
  '  const issuer = pkijs.Certificate.fromBER(ab(der(issuerPem)));',
  '  const certId = new pkijs.CertID();',
  '  const nameDer = Buffer.from(issuer.subject.toSchema().toBER(false));',
  '  const keyDer = Buffer.from(issuer.subjectPublicKeyInfo',
  '    .subjectPublicKey.valueBlock.valueHexView);',
  '  const h = hashName === "SHA-256" ? "sha256" : "sha1";',
  '  certId.hashAlgorithm = new pkijs.AlgorithmIdentifier({',
  '    algorithmId: h === "sha256" ? "2.16.840.1.101.3.4.2.1"',
  '                                : "1.3.14.3.2.26",',
  '    algorithmParams: new asn1js.Null() });',
  '  certId.issuerNameHash = new asn1js.OctetString({ valueHex:',
  '    nodeCrypto.createHash(h).update(nameDer).digest() });',
  '  certId.issuerKeyHash = new asn1js.OctetString({ valueHex:',
  '    nodeCrypto.createHash(h).update(keyDer).digest() });',
  '  let hex = serialHex.length % 2 ? "0" + serialHex : serialHex;',
  '  if (parseInt(hex.slice(0, 2), 16) & 0x80) { hex = "00" + hex; }',
  '  certId.serialNumber = new asn1js.Integer({ valueHex:',
  '    ab(Buffer.from(hex, "hex")) });',
  '  const req = new pkijs.OCSPRequest();',
  '  req.tbsRequest.requestList = [new pkijs.Request({ reqCert: certId })];',
  '  if (nonce) {',
  '    req.tbsRequest.requestExtensions = [new pkijs.Extension({',
  '      extnID: "1.3.6.1.5.5.7.48.1.2", critical: false,',
  '      extnValue: new asn1js.OctetString({ valueHex: nonce }).toBER() })];',
  '  }',
  '  return Buffer.from(req.toSchema(true).toBER(false));',
  '}',
  '(async function () {',
  '  const rows = new Map();',
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
  '  const config = require(path.join(ROOT, "common", "config.js"));',
  '  const pki = require(path.join(ROOT, "common", "pki.js"));',
  '  const rev = require(path.join(ROOT, "common", "pki_revocation.js"));',
  '  const built = await pki.ensureRoot({',
  '    organisation: config.value("pki.organisation") });',
  '  if (!built.ok) { throw new Error(JSON.stringify(built)); }',
  '  await pki.ensureScope(pki.PROCESS_SCOPE);',
  '  await pki.ensureScope("default");',
  '  const pair = nodeCrypto.generateKeyPairSync("rsa",',
  '    { modulusLength: 2048 });',
  '  const publicPem = pair.publicKey.export({ type: "spki",',
  '                                           format: "pem" });',
  '  const enrolled = [];',
  '  for (const who of ["alice", "bob"]) {',
  '    const one = await pki.issueEnrolled("default", "acme", {',
  '      subject: [{ name: "CN", value: who }],',
  '      publicKeyPem: publicPem, profile: "digital-signature", days: 30,',
  '      subjectAltName: [{ kind: "uri",',
  '                         value: "urn:sts:person:" + who }],',
  '      identifier: who, subjectKind: "person", holderSubject: "" });',
  '    if (!one.ok) { throw new Error(JSON.stringify(one)); }',
  '    enrolled.push({ who: who, serialHex: one.serialHex,',
  '                    certificatePem: one.certificatePem,',
  '                    chainPem: one.chainPem });',
  '  }',
  '  const revoked = rev.revoke("default", "acme",',
  '    { serialHex: enrolled[0].serialHex, reason: "keyCompromise",',
  '      subject: "CN=alice" });',
  '  if (!revoked.ok) { throw new Error(JSON.stringify(revoked)); }',
  '  rev.revoke("default", "intermediate",',
  '    { serialHex: "7a7a7a7a", reason: "certificateHold" });',
  '  const crls = [];',
  '  for (const [scope, ca] of [["*service", "root"],',
  '                            ["default", "intermediate"],',
  '                            ["default", "acme"],',
  '                            ["*process", "tls"]]) {',
  '    const made = await rev.buildCrl(scope, ca);',
  '    if (!made.ok) { throw new Error(JSON.stringify(made)); }',
  '    crls.push({ scope: scope, ca: ca, der: made.der.toString("base64"),',
  '                count: made.count, crlNumber: made.crlNumber,',
  '                thisUpdate: made.thisUpdate,',
  '                nextUpdate: made.nextUpdate });',
  '  }',
  '  const acme = pki.rawRowFor("default").issuing.acme.certificatePem;',
  '  const tls = pki.rawRowFor(pki.PROCESS_SCOPE).issuing.tls',
  '    .certificatePem;',
  '  const asks = [',
  '    ["revoked", "acme", acme, enrolled[0].serialHex, null, "SHA-1"],',
  '    ["good with a nonce", "acme", acme, enrolled[1].serialHex,',
  '     nodeCrypto.randomBytes(16), "SHA-256"],',
  '    ["unknown", "acme", acme, "0123456789", null, "SHA-1"],',
  '    ["another issuer", "acme", tls, enrolled[1].serialHex, null,',
  '     "SHA-1"]];',
  '  const ocsp = [];',
  '  for (const [name, ca, issuer, serial, nonce, hash] of asks) {',
  '    const asked = await request(issuer, serial, nonce, hash);',
  '    const made = await rev.answerOcsp("default", ca, asked);',
  '    ocsp.push({ name: name, scope: "default", ca: ca,',
  '                request: asked.toString("base64"),',
  '                der: made.der.toString("base64"), status: made.status,',
  '                thisUpdate: made.thisUpdate || null,',
  '                answers: made.answers || [] });',
  '  }',
  '  ocsp.push({ name: "malformed", scope: "default", ca: "acme",',
  '              request: Buffer.from("not der").toString("base64"),',
  '              der: (await rev.answerOcsp("default", "acme",',
  '                Buffer.from("not der"))).der.toString("base64"),',
  '              status: "malformedRequest", thisUpdate: null,',
  '              answers: [] });',
  '  const points = [];',
  '  for (const [scope, ca] of [["*service", "root"],',
  '                            ["*process", "intermediate"],',
  '                            ["default", "acme"]]) {',
  '    points.push(Object.assign({ scope: scope, ca: ca },',
  '                              rev.distributionPoints(scope, ca)));',
  '  }',
  '  await keystore.settleDeks();',
  '  await keystore.settleAll();',
  '  const plain = {};',
  '  ["*service", "*process", "default"].forEach(function (scope) {',
  '    plain[scope] = keystore.pkiFor(scope);',
  '  });',
  '  const answer = {',
  '    persisted: keystore.persists(),',
  '    rows: Array.from(rows, function (e) {',
  '      return { realm: e[0], material: e[1] };',
  '    }),',
  '    plain: plain, enrolled: enrolled, crls: crls, ocsp: ocsp,',
  '    points: points, publicKeyPem: publicPem,',
  '    config: { httpBase: rev.httpBase(),',
  '              baseDn: rev.directoryBaseFor("default"),',
  '              crlLifetimeMinutes: Number(config.value(',
  '                "pki.crlLifetimeMinutes")),',
  '              leafLifetimeDays: Number(config.value(',
  '                "pki.leafLifetimeDays")) } };',
  '  keystore.reset();',
  '  require("fs").writeFileSync(process.argv[2], JSON.stringify(answer));',
  '})().catch(function (e) { console.error(e); process.exitCode = 1; });'
].join('\n');

/**
 * Runs a program in a child node with the KEK file, and reads its answer.
 *
 * @param {string} ROOT - the repository
 * @param {string} OUT - where the answer and the KEK go
 * @param {string} program - the program
 * @param {string[]} args - more arguments after ROOT and the answer file
 * @returns {any} what the child wrote
 */
function child(ROOT, OUT, program, args) {
  const kekFile = path.join(OUT, 'pki-authority-kek.txt');
  const answerFile = path.join(OUT, 'pki-authority-answer.json');
  childProcess.execFileSync(process.execPath,
    ['-e', program, ROOT, answerFile].concat(args || []),
    { env: Object.assign({}, process.env, {
        STS_LOG_LEVEL: 'fatal', STS_KEYS_SOURCE: 'persisted',
        STS_KEYS_KEK_PROVIDER: 'file', STS_KEYS_KEK_FILE: kekFile }),
      stdio: ['ignore', 'ignore', 'inherit'] });
  const answer = JSON.parse(fs.readFileSync(answerFile, 'utf8'));
  fs.unlinkSync(answerFile);
  return answer;
}

/**
 * The Node half.
 *
 * @param {string} ROOT - the repository
 * @param {string} OUT - the vector directory
 * @returns {any} pki-authority-node.json
 */
function build(ROOT, OUT) {
  const kekText = nodeCrypto.randomBytes(32).toString('base64');
  fs.writeFileSync(path.join(OUT, 'pki-authority-kek.txt'), kekText + '\n',
                   { mode: 0o600 });
  const answer = child(ROOT, OUT, BUILD);
  answer.kekFile = 'pki-authority-kek.txt';
  answer.kekText = kekText;
  return answer;
}

// What the child checks of Rust's half: its rows held by Node's keystore
// (development, as the hierarchy is when nothing persists), a certificate
// Node issues under Rust's ACME CA and chains to Rust's Root, Rust's leaf
// chained by Node, and Rust's CRL and OCSP answer parsed and verified by
// pkijs against the CA that signed them.
const CHECK = [
  "'use strict';",
  'const path = require("path");',
  'const fs = require("fs");',
  'const ROOT = process.argv[1];',
  'const v = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));',
  'const nodeCrypto = require("crypto");',
  'const keystore = require(path.join(ROOT, "common", "keystore.js"));',
  'const pkijs = require(require.resolve("pkijs", { paths: [ROOT] }));',
  'const stsCrypto = require(path.join(ROOT, "common", "crypto.js"));',
  'stsCrypto.installPkijsWebCrypto(pkijs);',
  'function der(pem) {',
  '  const b = Buffer.from(String(pem).replace(/-----[^-]+-----/g, "")',
  '    .replace(/\\s+/g, ""), "base64");',
  '  return b.buffer.slice(b.byteOffset, b.byteOffset + b.length);',
  '}',
  'function ab(b64) {',
  '  const b = Buffer.from(b64, "base64");',
  '  return b.buffer.slice(b.byteOffset, b.byteOffset + b.length);',
  '}',
  'const out = [];',
  'function check(ok, what, detail) {',
  '  out.push({ ok: !!ok, what: what, detail: detail || "" });',
  '}',
  'async function verifies(certPem, issuerPem) {',
  '  const c = pkijs.Certificate.fromBER(der(certPem));',
  '  return c.verify(pkijs.Certificate.fromBER(der(issuerPem)));',
  '}',
  '(async function () {',
  '  Object.keys(v.rows).forEach(function (scope) {',
  '    keystore.attachPki(scope, v.rows[scope]);',
  '  });',
  '  const pki = require(path.join(ROOT, "common", "pki.js"));',
  '  const rev = require(path.join(ROOT, "common", "pki_revocation.js"));',
  '  const root = pki.serviceRoot();',
  '  check(root && root.serialHex === v.rows["*service"].root.serialHex,',
  '        "pki-authority-rust: Node holds the Root sts-pki built");',
  '  const ensured = await pki.ensureScope("default");',
  '  check(ensured.ok && ensured.existing,',
  '        "pki-authority-rust: Node finds the default branch sts-pki built " +',
  '        "complete, and builds nothing", JSON.stringify(ensured));',
  '  check(pki.scopeChainsToRoot("default") &&',
  '        pki.scopeChainsToRoot(pki.PROCESS_SCOPE),',
  '        "pki-authority-rust: both branches chain to the Root by signature");',
  '  const pair = nodeCrypto.generateKeyPairSync("ec",',
  '    { namedCurve: "P-256" });',
  '  const issued = await pki.issueEnrolled("default", "acme", {',
  '    subject: [{ name: "CN", value: "carol" }],',
  '    publicKeyPem: pair.publicKey.export({ type: "spki",',
  '                                          format: "pem" }),',
  '    profile: "digital-signature", days: 10,',
  '    subjectAltName: [{ kind: "uri", value: "urn:sts:person:carol" }],',
  '    identifier: "carol", subjectKind: "person", holderSubject: "" });',
  '  check(issued.ok, "pki-authority-rust: Node issues under the ACME " +',
  '        "Issuing CA sts-pki built", JSON.stringify(issued.errors || ""));',
  '  if (issued.ok) {',
  '    const chain = issued.chainPem.concat([root.certificatePem]);',
  '    let all = true;',
  '    for (let i = 0; i + 1 < chain.length; i++) {',
  '      all = all && await verifies(chain[i], chain[i + 1]);',
  '    }',
  '    check(all, "pki-authority-rust: Node\'s leaf chains through Rust\'s " +',
  '          "Issuing CA and Intermediate to Rust\'s Root");',
  '  }',
  '  const leaf = v.issued.chainPem.concat([root.certificatePem]);',
  '  let chained = true;',
  '  for (let i = 0; i + 1 < leaf.length; i++) {',
  '    chained = chained && await verifies(leaf[i], leaf[i + 1]);',
  '  }',
  '  check(chained, "pki-authority-rust: the leaf sts-pki issued chains, " +',
  '        "in pkijs, to its Root");',
  '  const acme = v.rows.default.issuing.acme;',
  '  const issuer = pkijs.Certificate.fromBER(der(acme.certificatePem));',
  '  const crl = pkijs.CertificateRevocationList.fromBER(ab(v.crl.der));',
  '  check(await crl.verify({ issuerCertificate: issuer }),',
  '        "pki-authority-rust: pkijs verifies the CRL sts-pki signed");',
  '  const serials = (crl.revokedCertificates || []).map(function (one) {',
  '    return Buffer.from(one.userCertificate.valueBlock.valueHexView)',
  '      .toString("hex").replace(/^0+/, "");',
  '  });',
  '  check(serials.indexOf(rev.normalSerial(v.crl.revoked)) >= 0,',
  '        "pki-authority-rust: the revoked serial is on the CRL",',
  '        JSON.stringify(serials));',
  '  const resp = pkijs.OCSPResponse.fromBER(ab(v.ocsp.der));',
  '  const basic = pkijs.BasicOCSPResponse.fromBER(resp.responseBytes',
  '    .response.valueBlock.valueHexView.slice().buffer);',
  '  const chain = [v.rows.default.intermediate.certificatePem,',
  '                 root.certificatePem].map(function (pem) {',
  '    return pkijs.Certificate.fromBER(der(pem));',
  '  });',
  '  let verified = false;',
  '  let why = "";',
  '  try {',
  '    verified = await basic.verify({ trustedCerts: chain });',
  '  } catch (e) {',
  '    why = String((e && e.message) || e);',
  '  }',
  '  check(verified, "pki-authority-rust: pkijs verifies the OCSP answer " +',
  '        "sts-pki signed, its signer chained to the Root", why);',
  '  const status = basic.tbsResponseData.responses[0].certStatus;',
  '  check(status.idBlock.tagNumber === 1,',
  '        "pki-authority-rust: the OCSP answer says revoked");',
  '  const again = await rev.answerOcsp("default", "acme",',
  '    Buffer.from(v.ocsp.request, "base64"));',
  '  check(again.status === "successful" && again.answers[0].status ===',
  '        "revoked", "pki-authority-rust: Node answers the same request " +',
  '        "over Rust\'s rows: revoked", JSON.stringify(again.answers));',
  '  fs.writeFileSync(process.argv[2], JSON.stringify(out));',
  '})().catch(function (e) { console.error(e); process.exitCode = 1; });'
].join('\n');

/**
 * The Rust half, checked in Node.
 *
 * @param {string} ROOT - the repository
 * @param {string} file - pki-authority-rust.json
 * @param {Function} check - `(ok, what, detail)`
 */
function checkRust(ROOT, file, check) {
  const answerFile = file + '.answer.json';
  childProcess.execFileSync(process.execPath,
    ['-e', CHECK, ROOT, answerFile, file],
    { env: Object.assign({}, process.env, { STS_LOG_LEVEL: 'fatal',
                                            STS_KEYS_SOURCE: 'generated' }),
      stdio: ['ignore', 'ignore', 'inherit'] });
  const answers = JSON.parse(fs.readFileSync(answerFile, 'utf8'));
  fs.unlinkSync(answerFile);
  answers.forEach(function (one) {
    check(one.ok, one.what, one.detail);
  });
}

module.exports = { build: build, checkRust: checkRust };
