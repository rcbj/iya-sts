// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_certificate_holder_rename.js
//
// ---------------------------------------------------------------------------
// A PERSON'S CERTIFICATE FOLLOWS THEIR ENTRY, NOT THEIR NAME, OVER A REAL
// HANDSHAKE.
//
// D12 (#444): carries over `tests/certificate_holder_rename.js`. A
// `tls-client` certificate enrolled over EST with the person's password is
// presented at `GET /tls/sign-in` on the main port, in a throwaway
// development realm:
//
//   1. it signs in its holder;
//   2. after the entry is renamed over LDAP (modifyDN), it signs in the
//      RENAMED person, not a name, and makes no entry under the OLD name
//      (#33, 2026-11-15; until then it made one, `origin: authentication`,
//      which this job pinned);
//   3. after that person is deleted (over LDAP) and somebody new is
//      created under the
//      old name, it signs nobody in: the holder is gone, and the newcomer
//      under the same name is not the holder.
//
// NOT carried, and why: `stillHeld()` and `findEnrolled()` as functions and
// the mutants' internals are class (d); RFC 8705's still-held rule at the
// token endpoint is `sts_rfc8705_mtls.js`'s door.
//
// OWNED HERE (local: true): this repository's own certificate sign-in.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const path = require("path");
const nodeCrypto = require("crypto");
const ldapjs = require("ldapjs");
const est = require("./est_client.js");
const K = require("./oauth_wire_kit.js").kit("sts_certificate_holder_rename");
const log = K.log;

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "crypto_impl", "x509.js"));
const keys = require(path.join(REPO, "common", "crypto_impl",
                               "key_material.js"));

const FLOOR = 6;
const PW = "Chr-" + nodeCrypto.randomBytes(15).toString("base64url");

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

async function enrol(realm, who) {
  log.debug("Entering enrol(). " + who);
  const rb = K.rb(realm);
  const pair = await keys.generateKeyPair("ec-p256");
  const csr = await x509.certificationRequest({ subject: "CN=" + who,
    publicKeyPem: pair.publicPem, privateKeyPem: pair.privatePem });
  const r = await est.send({ method: "POST",
    url: rb + "/.well-known/est/tls-client/simpleenroll",
    headers: { "Content-Type": "application/pkcs10" },
    body: est.requestBody(csr.der), basic: [who, PW] });
  assert.strictEqual(r.status, 200, "EST enrolment: " + r.status + " " +
                     String(r.body).slice(0, 200));
  const pem = est.parseCertsOnly(est.base64Body(r.body)).certificates[0];
  const ca = await est.send({ method: "GET",
    url: rb + "/.well-known/est/tls-client/cacerts" });
  const chain = est.parseCertsOnly(est.base64Body(ca.body)).certificates;
  log.debug("Leaving enrol().");
  return { cert: pem + chain.join(""), key: pair.privatePem };
}

function signIn(realm, tls) {
  log.debug("Entering signIn().");
  const u = new URL(K.rb(realm) + "/tls/sign-in");
  return new Promise(function (resolve, reject) {
    const req = https.request({ host: u.hostname, port: u.port,
      path: u.pathname, method: "GET", agent: false,
      headers: { accept: "application/json" },
      cert: tls.cert, key: tls.key }, function (res) {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", function (c) {
        text += c;
      });
      res.on("end", function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in signIn(): " + ((e && e.message) || e));
          // Not JSON: the caller reads the text.
          json = null;
        }
        log.debug("Leaving signIn(). " + res.statusCode);
        resolve({ status: res.statusCode, json: json, text: text });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

// The DN of a person's entry, as the management API reports it.
async function dnOf(realm, user) {
  log.debug("Entering dnOf(). " + user);
  const r = await K.send(K.rb(realm) + "/admin-api/users?user=" +
                         encodeURIComponent(user));
  const dn = String((((r.json || {}).ldap || {}).entry || {}).dn || "");
  assert.ok(dn, "no DN for " + user + ": " + K.shown(r));
  log.debug("Leaving dnOf(). " + dn);
  return dn;
}

// Over LDAP, bound as `binderDn`: with `to`, the entry at `dn` renamed (its
// RDN, and cn) to `to`; without, the entry deleted.
function ldapOp(binderDn, dn, to) {
  log.debug("Entering ldapOp().");
  const url = "ldap://" + new URL(K.base).hostname + ":" +
              (process.env.STS_LDAP_PORT || "389");
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: url });
    const done = function (e) {
      client.unbind();
      log.debug("Leaving ldapOp().");
      resolve(e ? { ok: false, message: e.message } : { ok: true });
    };
    client.on("error", function (e) {
      log.debug("Caught in ldapOp(): " + e.message);
      resolve({ ok: false, message: e.message });
    });
    client.bind(binderDn, "x-" + K.STAMP, function (b) {
      if (b) {
        done(b);
        return;
      }
      if (!to) {
        client.del(dn, done);
        return;
      }
      const attr = dn.split("=")[0];
      const parent = dn.slice(dn.indexOf(",") + 1);
      client.modifyDN(dn, attr + "=" + to, function (e) {
        if (e) {
          done(e);
          return;
        }
        // Its cn and uid too, which name the person as the RDN does.
        client.modify(attr + "=" + to + "," + parent, [
          new ldapjs.Change({ operation: "replace", modification:
            new ldapjs.Attribute({ type: "cn", values: [to] }) }),
          new ldapjs.Change({ operation: "replace", modification:
            new ldapjs.Attribute({ type: "uid", values: [to] }) })], done);
      });
    });
  });
}

function said(r) {
  log.debug("Entering said().");
  log.debug("Leaving said().");
  return JSON.stringify(r.json || r.text);
}

async function person(realm, name) {
  log.debug("Entering person(). " + name);
  log.debug("Leaving person().");
  return K.ok(K.rb(realm) + "/admin-api/users/create", { username: name,
    invent: false, credential: "password", password: PW,
    attributes: { cn: name, givenName: name, sn: name,
                  mail: name + "@chr.example.test" } }, "created " + name);
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("certrename");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Rename" },
             "built the CA");
  await K.set(realm, "est.attemptsPerAddress", 100000);
  const who = "chr-" + K.STAMP;
  const renamed = "chrn-" + K.STAMP;
  await person(realm, who);
  const tls = await enrol(realm, who);
  const first = await signIn(realm, tls);
  check("1. the certificate signs in its holder", function () {
    assert.strictEqual(first.json && first.json.signedIn, true, said(first));
    assert.ok(said(first).indexOf(who) >= 0, said(first));
  });
  const binder = "chrb-" + K.STAMP;
  await person(realm, binder);
  const binderDn = await dnOf(realm, binder);
  const moved = await ldapOp(binderDn, await dnOf(realm, who), renamed);
  assert.ok(moved.ok, "the rename over LDAP: " + moved.message);
  const oldName = await K.send(K.rb(realm) + "/admin-api/users?user=" + who);
  check("2a. after the rename nobody is called by the old name",
        function () {
    assert.ok(!(((oldName.json || {}).ldap || {}).entry), K.shown(oldName));
  });
  const second = await signIn(realm, tls);
  const afterSign = await K.send(K.rb(realm) + "/admin-api/users?user=" + who);
  const phantom = ((afterSign.json || {}).ldap || {}).entry || null;
  // NO ENTRY UNDER THE OLD NAME (#33, 2026-11-15): the handshake's
  // sighting is filed on the entry the certificate's holder subject names
  // now. Until #33 the same sign-in made a new entry under the OLD name
  // (the certificate's CN), `origin: authentication`, so nobody could be
  // created under that name afterwards by an administrator; this job pinned
  // it.
  check("2b. the sign-in makes no entry under the old name (#33)",
        function () {
    assert.strictEqual(phantom, null, JSON.stringify(phantom).slice(0, 300));
  });
  check("2. after a rename it signs in the RENAMED person", function () {
    assert.strictEqual(second.json && second.json.signedIn, true,
                       said(second));
    assert.ok(said(second).indexOf(renamed) >= 0, said(second));
  });
  const gone = await ldapOp(binderDn, await dnOf(realm, renamed), null);
  assert.ok(gone.ok, "the delete over LDAP: " + gone.message);
  await person(realm, who);
  const third = await signIn(realm, tls);
  check("3. once its holder is deleted it signs nobody in, though somebody " +
        "new holds the old name", function () {
    assert.notStrictEqual(third.json && third.json.signedIn, true,
                          said(third));
  });
  check("3. and the answer names neither person as signed in", function () {
    const session = (third.json && third.json.session) || {};
    assert.notStrictEqual(session.started, true, said(third));
  });
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
