// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_stored_certificate_doors.js
//
// ---------------------------------------------------------------------------
// A CERTIFICATE STORED ON AN ENTRY, THROUGH THE ADMINISTRATOR'S DOORS, AND
// THE CERTIFICATE DETAILS VIEW, OVER THE WIRE.
//
// D12 (#444): carries over what a client can see of
// `tests/application_stored_certificates.js` (#1227),
// `tests/stored_certificates.js` (#1061), `tests/application_entry_unowned.js`
// (#1230) and `tests/certificate_details.js`, in a throwaway realm through
// `/admin-api` alone, every refusal's code read off the realm's audit log:
//
//   A. an application: `add-certificate` stores a self-signed leaf (answered
//      by its SHA-256, audited `certificate.stored` naming the application),
//      again changes nothing; refused: not one certificate and two PEM blocks
//      (STS-ADMIN-0897), an application the registry does not hold, and none
//      is made (0906), none named (0529), a certificate already stored on a
//      person (0899), removing one the entry does not store (0900); the
//      application's `credentials.stored` lists it, with its subject; the
//      certificate survives an administrator's `set` of the application's
//      name (application_entry_unowned's registry write); and it is
//      removed;
//   B. a person: the same two acts at `/admin-api/users`, the refusal of an
//      unreadable certificate (0897) and of removing one not stored (0900);
//   C. the certificate details view, `GET /admin-api/certificates
//      ?certificate=`: a certificate the realm lists, by its fingerprint,
//      a value that is no fingerprint
//      (400, STS-ADMIN-0640) and a fingerprint nobody holds (404, 0641).
//
// NOT carried, and why: the mapping at a real handshake (`identityOf()` with
// a stored certificate, the sign-in screen's `Continue with your
// certificate` and its refusals STS-AUTHN-0468/0469, /tls/sign-in's
// STS-TLS-0055, SCIM's 0084/0085, the Shared Signals door's STS-SSF-0151)
// needs a client certificate presented on a listener that asks for one, and
// is owed with `sts_tls_client_certificates.js` and
// `sts_authn_certificate_signin.js`; the message-signing certificate's
// refusals (0902, 0904, 0905, PKI-0220, 0221) belong to the signing
// certificate's own job; the CAEP credential-change signal is
// `sts_caep_credential_changes.js`'s; the LDAP writes beside the registry's
// (seeAlso, l) need the LDAP socket and are owed with phase 4's directory
// jobs; the details model's comparison with `openssl x509 -text`, the
// impostor Root no request can make the service hold, and the renderer are
// class (d).
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const forge = require("node-forge");
const K = require("./oauth_wire_kit.js").kit("sts_stored_certificate_doors");
const log = K.log;

const FLOOR = 20;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

// A self-signed leaf over a fresh RSA key, as an outside authority's
// certificate would reach an administrator.
function selfSigned(commonName) {
  log.debug("Entering selfSigned(). " + commonName);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  const attrs = [{ name: "commonName", value: commonName }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const pem = forge.pki.certificateToPem(cert);
  const sha = new nodeCrypto.X509Certificate(pem).fingerprint256
    .replace(/:/g, "").toLowerCase();
  log.debug("Leaving selfSigned().");
  return { pem: pem, sha256: sha };
}

// One act; its answer and how many rows of `code` it added.
async function act(realm, path, body, code) {
  log.debug("Entering act(). " + path);
  const url = K.rb(realm) + "/admin-api" + path;
  if (!code) {
    const r = await K.send(url, { json: body });
    log.debug("Leaving act().");
    return { answer: r, rose: 0 };
  }
  const out = await K.coded(realm, code, function () {
    return K.send(url, { json: body });
  });
  log.debug("Leaving act(). " + out.rose);
  return out;
}

function refused(what, out, code, status) {
  log.debug("Entering refused(). " + code);
  check(what + " (" + code + ")", function () {
    assert.strictEqual(out.answer.status, status || 400,
                       K.shown(out.answer));
    assert.ok(out.rose >= 1, code + " rows: " + out.rose);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(out.answer.text), "a code was sent");
  });
  log.debug("Leaving refused().");
}

async function application(realm, app, person) {
  log.debug("Entering application().");
  log.info("=== A. an application's stored certificates ===");
  const mine = selfSigned(app + ".example.test");
  const theirs = selfSigned(person + ".example.test");
  const stored = await act(realm, "/applications/add-certificate",
    { application: app, certificate: mine.pem });
  check("A1. add-certificate stores it on the application's entry, answered " +
        "by its SHA-256", function () {
    const j = stored.answer.json || {};
    assert.strictEqual(stored.answer.status, 200, K.shown(stored.answer));
    assert.strictEqual(j.changed, true, K.shown(stored.answer));
    assert.deepStrictEqual((j.certificates || []).map(function (c) {
      return c.sha256;
    }), [mine.sha256]);
  });
  const audit = await K.send(K.rb(realm) +
    "/admin-api/audit?per=200");
  check("A2. it is audited certificate.stored, naming the application",
        function () {
    const rows = ((audit.json && audit.json.events) || []).filter(function (e) {
      const one = JSON.stringify(e);
      return one.indexOf("certificate.stored") >= 0 &&
             one.indexOf(mine.sha256) >= 0;
    });
    assert.ok(rows.length >= 1, K.shown(audit));
    assert.ok(JSON.stringify(rows[0]).indexOf(app) >= 0,
              JSON.stringify(rows[0]).slice(0, 300));
  });
  const again = await act(realm, "/applications/add-certificate",
    { application: app, certificate: mine.pem });
  check("A3. storing it again changes nothing", function () {
    assert.strictEqual(again.answer.status, 200, K.shown(again.answer));
    assert.strictEqual(again.answer.json.changed, false);
    assert.strictEqual(again.answer.json.certificates.length, 1);
  });
  refused("A4. what is not one certificate is refused",
    await act(realm, "/applications/add-certificate",
              { application: app, certificate: "not a certificate" },
              "STS-ADMIN-0897"), "STS-ADMIN-0897");
  refused("A5. two PEM blocks are refused too: the leaf only",
    await act(realm, "/applications/add-certificate",
              { application: app, certificate: mine.pem + theirs.pem },
              "STS-ADMIN-0897"), "STS-ADMIN-0897");
  const ghost = "ghost-" + K.STAMP;
  refused("A6. an application the registry does not hold is refused",
    await act(realm, "/applications/add-certificate",
              { application: ghost, certificate: theirs.pem },
              "STS-ADMIN-0906"), "STS-ADMIN-0906");
  const ghostView = await K.send(K.rb(realm) +
    "/admin-api/applications?application=" + ghost);
  check("A6. and no application is made", function () {
    assert.ok(ghostView.status === 404 || !(ghostView.json &&
              ghostView.json.application), K.shown(ghostView));
  });
  refused("A7. an act naming no application is refused",
    await act(realm, "/applications/remove-certificate",
              { sha256: mine.sha256 }, "STS-ADMIN-0529"), "STS-ADMIN-0529");
  const onPerson = await act(realm, "/users/add-certificate",
    { user: person, certificate: theirs.pem });
  check("B0. a person's add-certificate stores theirs", function () {
    assert.strictEqual(onPerson.answer.status, 200, K.shown(onPerson.answer));
  });
  refused("A8. a certificate stored on a person is refused on the " +
          "application",
    await act(realm, "/applications/add-certificate",
              { application: app, certificate: theirs.pem },
              "STS-ADMIN-0899"), "STS-ADMIN-0899");
  refused("A9. removing a certificate the entry does not store is refused",
    await act(realm, "/applications/remove-certificate",
              { application: app, sha256: "ab".repeat(32) },
              "STS-ADMIN-0900"), "STS-ADMIN-0900");
  const view = await K.send(K.rb(realm) +
    "/admin-api/applications?application=" + encodeURIComponent(app));
  check("A10. credentials.stored of GET /admin-api/applications?application= " +
        "lists it, with its subject", function () {
    const listed = (((view.json || {}).credentials || {}).stored) || {};
    assert.ok(listed.ok, K.shown(view));
    assert.strictEqual(listed.certificates.length, 1, K.shown(view));
    assert.strictEqual(listed.certificates[0].sha256, mine.sha256);
    assert.ok(/example\.test/.test(listed.certificates[0].subject),
              JSON.stringify(listed.certificates[0]));
  });
  await K.ok(K.rb(realm) + "/admin-api/applications/set",
             { application: app, attribute: "appName",
               value: "Renamed " + K.STAMP }, "renamed the application");
  const after = await K.send(K.rb(realm) +
    "/admin-api/applications?application=" + encodeURIComponent(app));
  check("A11. an administrator's set of the application's name keeps the " +
        "stored certificate (the registry keeps what it does not model)",
        function () {
    const listed = (((after.json || {}).credentials || {}).stored) || {};
    assert.strictEqual((listed.certificates || []).length, 1,
                       K.shown(after));
  });
  const removed = await act(realm, "/applications/remove-certificate",
    { application: app, sha256: mine.sha256 });
  check("A12. remove-certificate takes it off", function () {
    assert.strictEqual(removed.answer.status, 200, K.shown(removed.answer));
    assert.strictEqual(removed.answer.json.certificates.length, 0);
  });
  log.debug("Leaving application().");
  return theirs;
}

async function people(realm, person, theirs) {
  log.debug("Entering people().");
  log.info("=== B. a person's stored certificates ===");
  refused("B1. a person's add-certificate refuses what is not a certificate",
    await act(realm, "/users/add-certificate",
              { user: person, certificate: "-----BEGIN CERTIFICATE-----\n" +
                "AAAA\n-----END CERTIFICATE-----\n" }, "STS-ADMIN-0897"),
    "STS-ADMIN-0897");
  refused("B2. and removing one the person does not store",
    await act(realm, "/users/remove-certificate",
              { user: person, sha256: "cd".repeat(32) }, "STS-ADMIN-0900"),
    "STS-ADMIN-0900");
  const gone = await act(realm, "/users/remove-certificate",
    { user: person, sha256: theirs.sha256 });
  check("B3. a person's remove-certificate takes theirs off", function () {
    assert.strictEqual(gone.answer.status, 200, K.shown(gone.answer));
  });
  log.debug("Leaving people().");
}

async function details(realm) {
  log.debug("Entering details().");
  log.info("=== C. the certificate details view ===");
  const list = await K.send(K.rb(realm) + "/admin-api/certificates?per=50");
  const rows = (list.json && (list.json.certificates || list.json.rows ||
                list.json.items)) || [];
  const row = rows.filter(function (r) {
    return r && r.fingerprint;
  })[0];
  assert.ok(row, "the realm lists no certificate: " + K.shown(list));
  const fp = String(row.fingerprint);
  const one = await K.send(K.rb(realm) + "/admin-api/certificates" +
    "?certificate=" + encodeURIComponent(fp));
  check("C1. a certificate the realm lists is shown by its fingerprint",
        function () {
    assert.strictEqual(one.status, 200, K.shown(one));
    const body = JSON.stringify(one.json).toLowerCase();
    assert.ok(body.indexOf(fp.replace(/:/g, "").toLowerCase()) >= 0 ||
              body.indexOf(fp.toLowerCase()) >= 0, body.slice(0, 300));
  });
  const notFp = await K.coded(realm, "STS-ADMIN-0640", function () {
    return K.send(K.rb(realm) + "/admin-api/certificates" +
                  "?certificate=not-a-fingerprint");
  });
  refused("C2. a value that is no fingerprint is refused", notFp,
          "STS-ADMIN-0640");
  log.debug("Leaving details().");
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("storedcert");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Stored" },
             "built the CA");
  const app = "scapp-" + K.STAMP;
  const person = "scp-" + K.STAMP;
  await K.app(realm, app, { oauthClientId: [app] });
  await K.ok(K.rb(realm) + "/admin-api/users/create", { username: person,
    invent: false, credential: "none", attributes: { cn: person,
      givenName: person, sn: person, mail: person + "@sc.example.test" } },
    "created " + person);
  const theirs = await application(realm, app, person);
  await people(realm, person, theirs);
  await details(realm);
  const nobody = await K.coded(realm, "STS-ADMIN-0641", function () {
    return K.send(K.rb(realm) + "/admin-api/certificates?certificate=" +
                  "ef".repeat(32));
  });
  refused("C3. a fingerprint nobody holds is not found", nobody,
          "STS-ADMIN-0641", 404);
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
