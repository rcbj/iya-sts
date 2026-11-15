// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_paranoid_pki_own_ca.js
//
// ---------------------------------------------------------------------------
// PARANOID PKI MODE AGAINST CERTIFICATES THIS SERVICE'S OWN CA ISSUED AND
// REVOKED — AT THE MAIN PORT'S HANDSHAKE AND AT AN OUTBOUND DIAL (#1360).
//
// D12 (#444): carries over the wire half of `tests/listener_path_rules.js`
// (C: a revoked client is demoted) and `tests/outbound_gate.js` (I: the
// certificates the shipped stack generates, through the gate).
// `sts_paranoid_pki_tls.js` and `sts_paranoid_pki_outbound.js` hold the
// same doors with chains the job mints; here every certificate is the
// SERVICE's — issued over EST by a throwaway realm's CA and revoked through
// `/admin-api/est/revoke-certificate`, so the list that names it is the
// service's own:
//
//   A. THE MAIN PORT (`GET /admin-api/tls-connection` asked over the
//      connection presenting it): with `pki.paranoid` off a revoked client
//      certificate still verifies (OpenSSL reads no list); with it on the
//      view still reports the handshake's verdict, which carries no
//      revocation on this port by design, and the DOOR refuses it:
//      /tls/sign-in starts no session, refusedOnRevocation, STS-PKI-0118
//      on the realm's audit log (#38);
//      an unrevoked one verifies;
//   B. AN OUTBOUND DIAL (the RFC 9728 import, `load-resource-metadata`, at a
//      listener this job runs on OUTBOUND_TEST_HOST with a `tls-server`
//      certificate the realm issued for that host): with paranoid on the
//      unrevoked certificate is reached, and the revoked one is refused and
//      asked nothing.
//
// EXCLUSIVE: `pki.paranoid` on the DEFAULT realm is what the main port's
// handshake reads, which every concurrent job meets; it is put back with
// `config/reset` in a `finally`.
//
// NOT carried, and why: the other transports the gate stands on (SMTP,
// node-postgres, grpc-js, the cloud SDKs), a staple answering revoked, and
// the resumption internals are class (d) — no stack carries those servers.
//
// OWNED HERE (local: true): this repository's own listeners and dialers.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const path = require("path");
const nodeCrypto = require("crypto");
const est = require("./est_client.js");
const K = require("./oauth_wire_kit.js").kit("sts_paranoid_pki_own_ca");
const log = K.log;

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "crypto_impl", "x509.js"));
const keys = require(path.join(REPO, "common", "crypto_impl",
                               "key_material.js"));

const FLOOR = 6;
const HOST = process.env.OUTBOUND_TEST_HOST || process.env.GNAP_PUSH_HOST ||
             "localhost";
const PW = "Ppo-" + nodeCrypto.randomBytes(15).toString("base64url");

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

async function enrol(realm, who, profile, names) {
  log.debug("Entering enrol(). " + profile);
  const E = K.rb(realm) + "/.well-known/est";
  const pair = await keys.generateKeyPair("ec-p256");
  const csr = await x509.certificationRequest({ subject: "CN=" + who,
    publicKeyPem: pair.publicPem, privateKeyPem: pair.privatePem,
    subjectAltName: names || [] });
  const r = await est.send({ method: "POST",
    url: E + "/" + profile + "/simpleenroll",
    headers: { "Content-Type": "application/pkcs10" },
    body: est.requestBody(Buffer.from(csr.der)), basic: [who, PW] });
  assert.strictEqual(r.status, 200, profile + ": " + r.status + " " +
                     String(r.body).slice(0, 200));
  const pem = est.parseCertsOnly(est.base64Body(r.body)).certificates[0];
  const ca = await est.send({ method: "GET",
    url: E + "/" + profile + "/cacerts" });
  const chain = est.parseCertsOnly(est.base64Body(ca.body)).certificates;
  log.debug("Leaving enrol().");
  return { pem: pem, chain: pem + chain.join(""), key: pair.privatePem,
           serial: new nodeCrypto.X509Certificate(pem).serialNumber };
}

function connection(tls) {
  log.debug("Entering connection().");
  const u = new URL(K.base + "/admin-api/tls-connection");
  return new Promise(function (resolve, reject) {
    const req = https.request({ host: u.hostname, port: u.port,
      path: u.pathname, method: "GET", agent: false,
      headers: { accept: "application/json",
                 authorization: "Bearer " + process.env.STS_ADMIN_API_TOKEN },
      cert: tls.chain, key: tls.key }, function (res) {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", function (c) {
        text += c;
      });
      res.on("end", function () {
        let json = {};
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in connection(): " + ((e && e.message) || e));
          // Not JSON: the check below reports the text.
          json = { raw: text };
        }
        log.debug("Leaving connection().");
        resolve(json);
      });
    });
    req.on("error", reject);
    req.end();
  });
}

function signIn(realm, tls) {
  log.debug("Entering signIn().");
  const u = new URL(K.rb(realm) + "/tls/sign-in");
  return new Promise(function (resolve, reject) {
    const req = https.request({ host: u.hostname, port: u.port,
      path: u.pathname, method: "GET", agent: false,
      headers: { accept: "application/json" },
      cert: tls.chain, key: tls.key }, function (res) {
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
          // Not JSON: the check reports the text.
          json = null;
        }
        log.debug("Leaving signIn().");
        resolve({ status: res.statusCode, json: json, text: text });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

function verified(view) {
  log.debug("Entering verified().");
  log.debug("Leaving verified().");
  return !!(view && view.clientCertificate && view.clientCertificate.verified);
}

// The view, asked until it says `want` or a few seconds pass: a setting is
// applied to the listener's context, and the next handshake reads it.
async function settle(tls, want) {
  log.debug("Entering settle().");
  let view = await connection(tls);
  for (let i = 0; i < 20 && verified(view) !== want; i += 1) {
    await K.sleep(300);
    view = await connection(tls);
  }
  log.debug("Leaving settle().");
  return view;
}

async function listener(cert) {
  log.debug("Entering listener().");
  const out = { asked: 0 };
  out.server = https.createServer({ key: cert.key, cert: cert.chain },
    function (req, res) {
      out.asked += 1;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ resource: "https://api.own-ca.example",
                               authorization_servers: [K.base] }));
    });
  await new Promise(function (resolve) {
    out.server.listen(0, "0.0.0.0", resolve);
  });
  out.url = "https://" + HOST + ":" + out.server.address().port +
            "/.well-known/oauth-protected-resource";
  log.debug("Leaving listener().");
  return out;
}

async function revoke(realm, cert) {
  log.debug("Entering revoke().");
  await K.ok(K.rb(realm) + "/admin-api/est/revoke-certificate",
             { serial: cert.serial.toLowerCase(), reason: "keyCompromise" },
             "revoked " + cert.serial);
  log.debug("Leaving revoke().");
}

async function test(realm) {
  log.debug("Entering test().");
  const who = "ppo-" + K.STAMP;
  await K.ok(K.rb(realm) + "/admin-api/users/create", { username: who,
    invent: false, credential: "password", password: PW,
    attributes: { cn: who, givenName: who, sn: who,
                  mail: who + "@ppo.example.test" } }, "created " + who);
  await K.ok(K.rb(realm) + "/admin-api/est/add-host-name", { kind: "person",
    identifier: who, hostName: HOST }, "registered " + HOST);

  log.info("=== A. the main port ===");
  const good = await enrol(realm, who, "tls-client");
  const bad = await enrol(realm, who, "tls-client");
  await revoke(realm, bad);
  const off = await settle(bad, true);
  check("A1. with pki.paranoid off a revoked client certificate of the " +
        "realm's CA still verifies at the handshake", function () {
    assert.strictEqual(verified(off), true, JSON.stringify(off));
  });
  // Revocation is consulted only where pki.revocationCheck asks it to;
  // development's `auto` asks nothing, so hard-fail beside paranoid.
  for (const one of [["pki.paranoid", "on"],
                     ["pki.revocationCheck", "hard-fail"]]) {
    await K.ok(K.base + "/admin-api/config/set",
               { key: one[0], value: one[1] }, one[0] + " (default)");
    await K.set(realm, one[0], one[1]);
  }
  const on = await settle(bad, false);
  // THE MAIN PORT'S HANDSHAKE VERDICT DOES NOT CARRY REVOCATION, BY DESIGN
  // (tls/tls_server.js `observeConnectionsOn()` / `resumedProblem()`'s
  // "revocation by the request's verdict"): `socket.authorized`, which the
  // view reports, is OpenSSL's answer held to the path rules. Revocation is
  // the DOOR's verdict, through `checkedSocket()`. Revocation before the
  // first byte (listener_path_rules C) is `holdConnectionsOn()`'s, for LDAPS,
  // the debugger and the cells' channel — not this port.
  check("A2. with it on, the main port's view still reports the handshake's " +
        "verdict (revocation is not part of it)", function () {
    assert.strictEqual(verified(on), true, JSON.stringify(on));
  });
  const realmBefore = await K.codeCount(realm, "STS-PKI-0118");
  const defBefore = await K.codeCount(null, "STS-PKI-0118");
  const door = await signIn(realm, bad);
  // The door's refusal is on the REALM's audit log (#38, 2026-11-15); the
  // handshake's own row stays the default realm's, a handshake having no
  // realm. Until #38 only that row existed, so this job summed both.
  let realmRows = 0;
  for (let i = 0; i < 20 && realmRows < 1; i += 1) {
    realmRows = (await K.codeCount(realm, "STS-PKI-0118")) - realmBefore;
    if (realmRows < 1) {
      await K.sleep(150);
    }
  }
  const rows = realmRows +
               (await K.codeCount(null, "STS-PKI-0118")) - defBefore;
  check("A2b. and the door refuses it: /tls/sign-in starts no session, " +
        "refusedOnRevocation off the service's own register, recorded " +
        "STS-PKI-0118", function () {
    const j = door.json || {};
    assert.strictEqual(j.signedIn, false, door.text.slice(0, 300));
    assert.strictEqual(j.session && j.session.refusedOnRevocation, true,
                       door.text.slice(0, 300));
    assert.ok(/REVOKED/.test(j.session.why), door.text.slice(0, 300));
    assert.ok(realmRows >= 1, "STS-PKI-0118 rows in the realm: " +
              realmRows + " (both realms: " + rows + ")");
  });
  const onGood = await settle(good, true);
  check("A3. and an unrevoked one from the same CA still verifies",
        function () {
    assert.strictEqual(verified(onGood), true, JSON.stringify(onGood));
  });

  log.info("=== B. an outbound dial ===");
  const name = [{ kind: "dns", value: HOST }];
  const srvGood = await enrol(realm, who, "tls-server", name);
  const srvBad = await enrol(realm, who, "tls-server", name);
  await revoke(realm, srvBad);
  // The service Root, which every chain here ends in, named once in the
  // realm's signer truststore: an outbound dial trusts no anchor implicitly.
  const rootAnswer = await fetch(K.base + "/pki/ca/service/root.cer");
  const rootDer = Buffer.from(await rootAnswer.arrayBuffer());
  const rootPem = /-----BEGIN/.test(rootDer.toString("latin1"))
    ? rootDer.toString("latin1")
    : "-----BEGIN CERTIFICATE-----\n" + rootDer.toString("base64")
      .replace(/(.{64})/g, "$1\n") + "\n-----END CERTIFICATE-----\n";
  await K.ok(K.rb(realm) + "/admin-api/pki/trust/add",
             { certificates: rootPem }, "trusted the service Root");
  const reach = await listener(srvGood);
  const dark = await listener(srvBad);
  try {
    const reached = await K.send(K.rb(realm) +
      "/admin-api/applications/load-resource-metadata",
      { json: { url: reach.url } });
    check("B1. with paranoid on a server certified by the realm's own CA " +
          "is reached", function () {
      assert.ok(reach.asked >= 1, "asked " + reach.asked + "; " +
                K.shown(reached));
    });
    const refused = await K.send(K.rb(realm) +
      "/admin-api/applications/load-resource-metadata",
      { json: { url: dark.url } });
    check("B2. a server whose certificate the realm revoked is refused, " +
          "and asked nothing", function () {
      assert.strictEqual(dark.asked, 0, "asked " + dark.asked);
      assert.ok(refused.status >= 400, K.shown(refused));
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(refused.text));
    });
  } finally {
    reach.server.close();
    dark.server.close();
  }
  log.debug("Leaving test().");
}

async function guarded() {
  log.debug("Entering guarded().");
  const realm = await K.realm("ppoown");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Own" },
             "built the CA");
  await K.set(realm, "est.attemptsPerAddress", 100000);
  try {
    await test(realm);
  } finally {
    for (const key of ["pki.paranoid", "pki.revocationCheck"]) {
      const r = await K.send(K.base + "/admin-api/config/reset",
                             { json: { key: key } });
      log.info("put " + key + " back (" + r.status + ")");
    }
  }
  log.debug("Leaving guarded().");
}

K.main(guarded, FLOOR);
