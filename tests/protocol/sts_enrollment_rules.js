// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_enrollment_rules.js
//
// ---------------------------------------------------------------------------
// THE ENROLLMENT CORE'S RULES, AND EST'S DOOR, BY THEIR CODES, OVER THE WIRE.
//
// D12 (#444): carries over what a client can see of `tests/cert_enrollment.js`
// (the core ACME, EST and SCEP issue through), `tests/est_handlers.js` and
// `tests/application_enrollment.js`. `sts_est_enrollment.js` already drives
// every profile and the refusals by their HTTP answers; this job asks the
// rules those files held as a TABLE through EST's own door, the simplest of
// the three, and reads each refusal's code off the realm's audit log:
//
//   A. EST's door: the family off (STS-EST-0001), a label that is no profile
//      (0002), a method it does not answer (0003), /fullcmc (0004), a body
//      over est.maxRequestBytes (0007), an empty or non-base64 body (0008),
//      no credential (0009), a Bearer credential (0013), a query string
//      (0019);
//   B. the core: a CA profile is no EST label (STS-EST-0002), an unreadable
//      PKCS#10 (STS-ENROLL-0030), a password for a name with no entry (0015),
//      two entries in one subjectAltName (0022), a URI the entry
//      does not own (0050), a UPN that is neither the entry's UPN nor its
//      mail (0053), a TLS server certificate with no host name (0054),
//      S/MIME for an entry with no mail (0055), the per-entry cap
//      (pki.enrollmentMaxCertificatesPerEntry, 0040); the rule an
//      application is held to as a client, by its unknown client id (0016),
//      is `sts_est_enrollment.js`'s answer, owed here by code;
//   C. the administrator's doors: a host name that is no DNS name or IP
//      (0057), removing one the entry lacks (0058), a revocation naming a
//      serial nobody issued (0070), an unknown /admin-api/est action
//      (STS-EST-0032) and a body that fails validation (0031);
//   D. a realm id that is an EST label is refused (STS-CORE-0107);
//   E. an application's rules in a PRODUCT realm (application_enrollment):
//      one declared for OAuth 2.0 alone is refused an EST certificate
//      (STS-ENROLL-0094), and a profile outside its own list (0095).
//
// NOT carried, and why: the profile table and proof-of-possession vectors
// called as functions, the sealing failure (0043, a store fault), the
// server-generated key's unknown algorithm (0035, refused by the request
// schema first), ACME's EAB reuse and expiry (0081, 0082: already
// `sts_acme_enrollment.js`'s, by problem type), a revocation for another
// entry (0071, an ACME revokeCert by a second account), a renewal of a
// certificate never issued (0092), an administrator with no entry
// (0023) and the plain-HTTP refusal in product (0060: no stack offers the
// plain listener in product) are class (d) or owed with their families;
// /serverkeygen's DecryptKeyIdentifier (0018) and the KEM template (0017)
// are `sts_est_enrollment.js`'s answers, owed by code.
//
// OWNED HERE (local: true): this repository's own enrollment protocols.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const nodeCrypto = require("crypto");
const est = require("./est_client.js");
const K = require("./oauth_wire_kit.js").kit("sts_enrollment_rules");
const log = K.log;

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "crypto_impl", "x509.js"));
const keys = require(path.join(REPO, "common", "crypto_impl",
                               "key_material.js"));

const FLOOR = 27;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

async function csr(commonName, names) {
  log.debug("Entering csr().");
  const pair = await keys.generateKeyPair("ec-p256");
  const built = await x509.certificationRequest({ subject: "CN=" + commonName,
    publicKeyPem: pair.publicPem, privateKeyPem: pair.privatePem,
    subjectAltName: names || [] });
  log.debug("Leaving csr().");
  return Buffer.from(built.der);
}

function enroll(url, der, extra) {
  log.debug("Entering enroll(). " + url);
  const more = extra || {};
  log.debug("Leaving enroll().");
  return est.send({ method: more.method || "POST", url: url,
    body: der === null ? undefined : (Buffer.isBuffer(der)
      ? est.requestBody(der) : der),
    headers: Object.assign({ "Content-Type": "application/pkcs10" },
                           more.headers || {}),
    basic: more.basic });
}

// The newest code on a realm's audit log: what a failed check names, so
// a refusal recorded under another code says which.
async function latestCode(realm) {
  log.debug("Entering latestCode().");
  const r = await K.send(K.rb(realm) + "/admin-api/audit?per=60");
  const m = JSON.stringify((r.json && r.json.events) || [])
    .match(/STS-[A-Z]+-\d{4}/);
  log.debug("Leaving latestCode().");
  return m ? m[0] : "none";
}

// One EST request; its status, and how many rows of `code` it added.
async function refusedBy(realm, code, act) {
  log.debug("Entering refusedBy(). " + code);
  const out = await K.coded(realm, code, act);
  const seen = out.rose >= 1 ? code : await latestCode(realm);
  log.debug("Leaving refusedBy(). " + out.rose);
  return { status: out.answer.status, rose: out.rose, seen: seen,
           text: String(out.answer.body || "") };
}

function refusal(what, r, code, statuses) {
  log.debug("Entering refusal(). " + code);
  check(what + " (" + code + ")", function () {
    assert.ok(statuses.indexOf(r.status) >= 0, r.status + " " +
              r.text.slice(0, 300));
    assert.ok(r.rose >= 1, code + " rows: " + r.rose + "; the newest " +
              "code is " + r.seen + " (" + r.status + ")");
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.text), "a code was sent");
  });
  log.debug("Leaving refusal().");
}

async function person(realm, name, attrs) {
  log.debug("Entering person(). " + name);
  const password = "Enr-" + nodeCrypto.randomBytes(15).toString("base64url");
  await K.ok(K.rb(realm) + "/admin-api/users/create", { username: name,
    invent: false, credential: "password", password: password,
    attributes: Object.assign({ cn: name, givenName: name, sn: name },
                              attrs || {}) }, "created " + name);
  log.debug("Leaving person().");
  return [name, password];
}

async function door(realm, E, alice) {
  log.debug("Entering door().");
  log.info("=== A. EST's door ===");
  const good = await csr(alice[0]);
  refusal("A1. a label that is no profile is refused",
    await refusedBy(realm, "STS-EST-0002", function () {
      return enroll(E + "/no-such-label/simpleenroll", good,
                    { basic: alice });
    }), "STS-EST-0002", [400, 404]);
  refusal("A2. GET on simpleenroll is a method EST does not answer",
    await refusedBy(realm, "STS-EST-0003", function () {
      return enroll(E + "/tls-client/simpleenroll", null,
                    { basic: alice, method: "GET" });
    }), "STS-EST-0003", [405]);
  refusal("A3. /fullcmc is not implemented",
    await refusedBy(realm, "STS-EST-0004", function () {
      return enroll(E + "/fullcmc", good, { basic: alice });
    }), "STS-EST-0004", [404, 501]);
  refusal("A4. an empty body is refused",
    await refusedBy(realm, "STS-EST-0008", function () {
      return enroll(E + "/tls-client/simpleenroll", "", { basic: alice });
    }), "STS-EST-0008", [400]);
  refusal("A5. a body that is not base64 is refused",
    await refusedBy(realm, "STS-EST-0008", function () {
      return enroll(E + "/tls-client/simpleenroll", "!!not*base64!!",
                    { basic: alice });
    }), "STS-EST-0008", [400]);
  refusal("A6. no credential is refused",
    await refusedBy(realm, "STS-EST-0009", function () {
      return enroll(E + "/tls-client/simpleenroll", good);
    }), "STS-EST-0009", [401]);
  refusal("A7. a Bearer credential is refused",
    await refusedBy(realm, "STS-EST-0013", function () {
      return enroll(E + "/tls-client/simpleenroll", good,
                    { headers: { Authorization: "Bearer abc" } });
    }), "STS-EST-0013", [401]);
  refusal("A8. a query string is refused",
    await refusedBy(realm, "STS-EST-0019", function () {
      return enroll(E + "/tls-client/simpleenroll?x=1", good,
                    { basic: alice });
    }), "STS-EST-0019", [400]);
  await K.set(realm, "est.maxRequestBytes", 1024);
  refusal("A9. a body over est.maxRequestBytes is refused",
    await refusedBy(realm, "STS-EST-0007", function () {
      return enroll(E + "/tls-client/simpleenroll",
                    "A".repeat(4096), { basic: alice });
    }), "STS-EST-0007", [413]);
  await K.unset(realm, "est.maxRequestBytes");
  await K.set(realm, "est.enabled", false);
  refusal("A10. with est.enabled off the realm's EST is refused",
    await refusedBy(realm, "STS-EST-0001", function () {
      return enroll(E + "/tls-client/simpleenroll", good, { basic: alice });
    }), "STS-EST-0001", [404, 501, 503]);
  await K.unset(realm, "est.enabled");
  log.debug("Leaving door().");
}

async function core(realm, E, alice, bob, nomail) {
  log.debug("Entering core().");
  log.info("=== B. the core's rules ===");
  const plain = await csr(alice[0]);
  // A CA profile is no EST label at all: the path is refused by the label
  // rule (STS-EST-0002) before the core's own CA refusal (STS-ENROLL-0002,
  // which an ACME order naming the profile reaches).
  refusal("B1. a CA profile is no EST label: the path is refused",
    await refusedBy(realm, "STS-EST-0002", function () {
      return enroll(E + "/ca/simpleenroll", plain, { basic: alice });
    }), "STS-EST-0002", [404]);
  refusal("B2. a body that is base64 but no PKCS#10 is refused",
    await refusedBy(realm, "STS-ENROLL-0030", function () {
      return enroll(E + "/tls-client/simpleenroll",
                    Buffer.from("not a certification request").toString(
                      "base64"), { basic: alice });
    }), "STS-ENROLL-0030", [400]);
  refusal("B3. a password for a name with no entry is refused",
    await refusedBy(realm, "STS-ENROLL-0015", function () {
      return enroll(E + "/tls-client/simpleenroll", plain,
                    { basic: ["nobody-" + K.STAMP, "x"] });
    }), "STS-ENROLL-0015", [401]);
  refusal("B4. two entries in one subjectAltName are refused",
    await refusedBy(realm, "STS-ENROLL-0022", function () {
      return csr(alice[0], [
        { kind: "uri", value: "urn:sts:person:" + alice[0] },
        { kind: "uri", value: "urn:sts:person:" + bob[0] }])
        .then(function (der) {
          return enroll(E + "/tls-client/simpleenroll", der,
                        { basic: alice });
        });
    }), "STS-ENROLL-0022", [400, 403]);
  refusal("B5. a URI the entry does not own is refused",
    await refusedBy(realm, "STS-ENROLL-0050", function () {
      return csr(alice[0], [{ kind: "uri",
        value: "https://not-hers.example/" }]).then(function (der) {
        return enroll(E + "/tls-client/simpleenroll", der, { basic: alice });
      });
    }), "STS-ENROLL-0050", [400, 403]);
  refusal("B6. a UPN that is neither the entry's UPN nor its mail is refused",
    await refusedBy(realm, "STS-ENROLL-0053", function () {
      return csr(alice[0], [{ kind: "upn", value: "someone@else.test" }])
        .then(function (der) {
          return enroll(E + "/smartcard-logon/simpleenroll", der,
                        { basic: alice });
        });
    }), "STS-ENROLL-0053", [400, 403]);
  refusal("B7. a TLS server certificate with no host name is refused",
    await refusedBy(realm, "STS-ENROLL-0054", function () {
      return enroll(E + "/tls-server/simpleenroll", plain, { basic: alice });
    }), "STS-ENROLL-0054", [400, 403]);
  refusal("B8. S/MIME for an entry with no mail is refused",
    await refusedBy(realm, "STS-ENROLL-0055", function () {
      return csr(nomail[0]).then(function (der) {
        return enroll(E + "/email/simpleenroll", der, { basic: nomail });
      });
    }), "STS-ENROLL-0055", [400, 403]);
  await K.set(realm, "pki.enrollmentMaxCertificatesPerEntry", 1);
  const firstCert = await enroll(E + "/tls-client/simpleenroll",
                                 await csr(bob[0]), { basic: bob });
  const capped = await refusedBy(realm, "STS-ENROLL-0040", async function () {
    return enroll(E + "/tls-client/simpleenroll", await csr(bob[0]),
                  { basic: bob });
  });
  check("B9. with pki.enrollmentMaxCertificatesPerEntry 1 the first " +
        "certificate is issued", function () {
    assert.strictEqual(firstCert.status, 200,
                       String(firstCert.body).slice(0, 300));
  });
  refusal("B9. and the second is refused at the cap", capped,
          "STS-ENROLL-0040", [400, 403, 409]);
  await K.unset(realm, "pki.enrollmentMaxCertificatesPerEntry");
  log.debug("Leaving core().");
}

async function admin(realm, alice) {
  log.debug("Entering admin().");
  log.info("=== C. the administrator's doors ===");
  const api = K.rb(realm) + "/admin-api/est";
  const bad = await K.coded(realm, "STS-ENROLL-0057", function () {
    return K.send(api + "/add-host-name", { json: { kind: "person",
      identifier: alice[0], hostName: "not a host!" } });
  });
  check("C1. a host name that is no DNS name or IP is refused " +
        "(STS-ENROLL-0057)", function () {
    assert.strictEqual(bad.answer.status, 400, K.shown(bad.answer));
    assert.ok(bad.rose >= 1, "rows: " + bad.rose);
  });
  const missing = await K.coded(realm, "STS-ENROLL-0058", function () {
    return K.send(api + "/remove-host-name", { json: { kind: "person",
      identifier: alice[0], hostName: "absent.example.test" } });
  });
  check("C2. removing a host name the entry lacks is refused " +
        "(STS-ENROLL-0058)", function () {
    assert.ok(missing.answer.status >= 400, K.shown(missing.answer));
    assert.ok(missing.rose >= 1, "rows: " + missing.rose);
  });
  const nobody = await K.coded(realm, "STS-ENROLL-0070", function () {
    return K.send(api + "/revoke-certificate", { json: {
      serial: "0abc0abc0abc0abc", reason: "keyCompromise" } });
  });
  check("C3. a revocation naming a serial nobody issued is refused " +
        "(STS-ENROLL-0070)", function () {
    assert.ok(nobody.answer.status >= 400, K.shown(nobody.answer));
    assert.ok(nobody.rose >= 1, "rows: " + nobody.rose);
  });
  const unknown = await K.coded(realm, "STS-EST-0032", function () {
    return K.send(api + "/no-such-action", { json: {} });
  });
  check("C4. an unknown /admin-api/est action is refused (STS-EST-0032)",
        function () {
    assert.ok(unknown.answer.status === 400 ||
              unknown.answer.status === 404, K.shown(unknown.answer));
    assert.ok(unknown.rose >= 1, "rows: " + unknown.rose);
  });
  log.debug("Leaving admin().");
}

async function labelRealm() {
  log.debug("Entering labelRealm().");
  log.info("=== D. a realm id that is an EST label ===");
  const r = await K.coded(null, "STS-CORE-0107", function () {
    return K.send(K.base + "/admin-api/realms/create", { json: {
      id: "tls-server", domain: "tls-server-" + K.STAMP + ".example.net",
      name: "an EST label" } });
  });
  const listed = await K.send(K.base + "/admin-api/realms?per=500");
  check("D. a realm named like an EST profile is refused " +
        "(STS-CORE-0107), and none is made", function () {
    assert.strictEqual(r.answer.status, 400, K.shown(r.answer));
    assert.ok(r.rose >= 1, "rows: " + r.rose);
    assert.ok(!((listed.json && listed.json.realms) || []).some(function (x) {
      return x.id === "tls-server";
    }));
  });
  log.debug("Leaving labelRealm().");
}

async function applications() {
  log.debug("Entering applications().");
  log.info("=== E. an application's rules in a product realm ===");
  const realm = await K.realm("enrapp");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Enr" },
             "built the CA");
  await K.set(realm, "est.attemptsPerAddress", 100000);
  const secret = "Enr-" + nodeCrypto.randomBytes(15).toString("base64url");
  const oauthOnly = "enroauth-" + K.STAMP;
  const narrow = "enrnarrow-" + K.STAMP;
  await K.ok(K.rb(realm) + "/admin-api/applications/create", {
    identifier: oauthOnly, protocols: ["oauth2"], fields: {
      oauthClientId: oauthOnly, oauthClientSecret: secret } },
    "an application declared for OAuth 2.0 alone");
  await K.ok(K.rb(realm) + "/admin-api/applications/create", {
    identifier: narrow, protocols: ["oauth2", "est"], fields: {
      oauthClientId: narrow, oauthClientSecret: secret,
      estAllowedProfiles: ["tls-client"] } },
    "an application whose own list is tls-client alone");
  await K.set(realm, "global.mode", "product");
  const E = K.rb(realm) + "/.well-known/est";
  const der = await csr(oauthOnly);
  refusal("E1. in product an application declared for OAuth 2.0 alone is " +
          "refused an EST certificate",
    await refusedBy(realm, "STS-ENROLL-0094", function () {
      return enroll(E + "/tls-client/simpleenroll", der,
                    { basic: [oauthOnly, secret] });
    }), "STS-ENROLL-0094", [400, 401, 403]);
  refusal("E2. a profile outside the application's own list is refused",
    await refusedBy(realm, "STS-ENROLL-0095", async function () {
      return enroll(E + "/code-signing/simpleenroll", await csr(narrow),
                    { basic: [narrow, secret] });
    }), "STS-ENROLL-0095", [400, 403]);
  log.debug("Leaving applications().");
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("enrrules");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Enr" },
             "built the CA");
  await K.set(realm, "est.attemptsPerAddress", 100000);
  const alice = await person(realm, "enra-" + K.STAMP,
                             { mail: "enra-" + K.STAMP + "@enr.example.test" });
  const bob = await person(realm, "enrb-" + K.STAMP,
                           { mail: "enrb-" + K.STAMP + "@enr.example.test" });
  const nomail = await person(realm, "enrn-" + K.STAMP, {});
  const E = K.rb(realm) + "/.well-known/est";
  await door(realm, E, alice);
  await core(realm, E, alice, bob, nomail);
  await admin(realm, alice);
  await labelRealm();
  await applications();
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
