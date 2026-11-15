// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_client_certificate_mapping.js
//
// ---------------------------------------------------------------------------
// A CERTIFICATE FROM AN OUTSIDE AUTHORITY IS THE ONE ENTRY STORING IT, AT
// EVERY DOOR THAT TAKES A CLIENT CERTIFICATE, OVER REAL HANDSHAKES (#1061).
//
// D12 (#444): carries over the doors of `tests/stored_certificates.js` and
// the Shared Signals half of `tests/application_stored_certificates.js`. An
// outside chain is minted here (`tools/pep-credential.js`), its Root put in
// the client truststore through the gated door (recorded first, removed at
// the end, #335/#1307), and its leaf presented on the main port in a
// throwaway development realm. Each refusal's code is read off the realm's
// audit log:
//
//   A. STORED NOWHERE (though its CN names a person who exists): the sign-in
//      screen's "Continue with your certificate" is refused
//      (STS-AUTHN-0468), SCIM does not take it (STS-SCIM-0084), the Shared
//      Signals door does not (STS-SSF-0151), and GET /xacml resolves it to
//      nobody (STS-XACML-0177);
//   B. STORED ON TWO ENTRIES (one through `/admin-api/users/add-certificate`,
//      the second over LDAP, the door that does not refuse it): the screen
//      is refused (STS-AUTHN-0469), `/tls/sign-in` answers that it started
//      no session, `refusedAsStored: STORED_TWICE` (STS-TLS-0055), SCIM does not take it (STS-SCIM-0085), and
//      GET /xacml is refused (STS-XACML-0178);
//   C. STORED ON ONE ENTRY, after the second copy is removed over LDAP:
//      `/tls/sign-in` starts that person's session.
//
// NOT carried, and why: a remote PEP's door refusing it (STS-XACML-0180)
// needs a certificate holding REMOTE_PEPS as well, owed with phase 8's
// XACML jobs; the codec's index key and a renewed certificate (same
// subject, new key) as a lookup are class (d).
//
// OWNED HERE (local: true): this repository's own doors.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const ldapjs = require("ldapjs");
const anchors = require("../tools/pep-credential.js");
const authnSignin = require("./authn_signin.js");
const K = require("./oauth_wire_kit.js").kit("sts_client_certificate_mapping");
const log = K.log;

const FLOOR = 10;
const added = [];

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

// One request on its own connection, presenting `tls` when given.
function tlsCall(method, url, o) {
  log.debug("Entering tlsCall(). " + method + " " + url);
  const opts = o || {};
  return new Promise(function (resolve, reject) {
    const u = new URL(url);
    const body = opts.body === undefined ? "" : JSON.stringify(opts.body);
    const headers = Object.assign({ accept: "application/json" },
                                  opts.headers || {});
    if (method !== "GET") {
      headers["content-type"] = "application/json";
      headers["content-length"] = Buffer.byteLength(body);
    }
    const req = https.request({ host: u.hostname, port: u.port,
      path: u.pathname + u.search, method: method, headers: headers,
      agent: false, cert: opts.tls ? opts.tls.cert : undefined,
      key: opts.tls ? opts.tls.key : undefined }, function (res) {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        text += chunk;
      });
      res.on("end", function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in tlsCall(): " + ((e && e.message) || e));
          // Not JSON: the caller reads the text.
          json = null;
        }
        log.debug("Leaving tlsCall(). " + res.statusCode);
        resolve({ status: res.statusCode, json: json, text: text,
                  location: res.headers.location || "",
                  setCookies: [].concat(res.headers["set-cookie"] || []) });
      });
    });
    req.on("error", function (e) {
      log.debug("Caught in tlsCall(): " + e.message);
      reject(e);
    });
    req.end(body || undefined);
  });
}

// A call that the truststore may not have applied yet: retried on a reset
// (the install races the next handshake, tests/CLAUDE.md, #335).
async function settled(method, url, o) {
  log.debug("Entering settled().");
  let last = null;
  for (let i = 0; i < 10; i += 1) {
    try {
      const r = await tlsCall(method, url, o);
      log.debug("Leaving settled().");
      return r;
    } catch (e) {
      log.debug("Caught in settled(): " + ((e && e.message) || e));
      // A handshake refused while the anchor is being applied; again.
      last = e;
      await K.sleep(300);
    }
  }
  throw last;
}

async function coded(realm, code, act) {
  log.debug("Entering coded(). " + code);
  const out = await K.coded(realm, code, act);
  log.debug("Leaving coded(). " + out.rose);
  return out;
}

function refused(what, out, code) {
  log.debug("Entering refused(). " + code);
  check(what + " (" + code + ")", function () {
    assert.ok(out.answer.status >= 300, out.answer.status + " " +
              String(out.answer.text).slice(0, 200));
    assert.ok(out.rose >= 1, code + " rows: " + out.rose + " (" +
              out.answer.status + " " + String(out.answer.text)
                .slice(0, 200) + ")");
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(out.answer.text), "a code was sent");
  });
  log.debug("Leaving refused().");
}

// The sign-in screen, opened and acted on over a connection presenting tls.
async function certificateSignIn(realm, client, tls) {
  log.debug("Entering certificateSignIn().");
  const rb = K.rb(realm);
  const r = await fetch(rb + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: client,
    redirect_uri: "https://rp.example.test/cb", scope: "openid",
    state: "s", nonce: "n", code_challenge: "x".repeat(43),
    code_challenge_method: "S256" }).toString(), { redirect: "manual" });
  await r.text();
  const at = new URL(String(r.headers.get("location")), rb).toString();
  const id = authnSignin.pendingIdOf(at);
  const shell = await settled("GET", at, { tls: tls });
  const cookie = shell.setCookies.map(function (one) {
    return one.split(";")[0];
  }).join("; ");
  const view = await settled("GET", rb + "/authn-api/pending/" +
    encodeURIComponent(id), { tls: tls, headers: { cookie: cookie } });
  const csrf = (view.json && view.json.csrf) || "";
  const acted = await settled("POST", rb + "/authn-api/pending/" +
    encodeURIComponent(id) + "/certificate", { tls: tls, body: {},
    headers: { cookie: cookie, origin: new URL(rb).origin,
               "x-csrf-token": csrf } });
  log.debug("Leaving certificateSignIn().");
  return acted;
}

function suffixOf(realm) {
  log.debug("Entering suffixOf().");
  log.debug("Leaving suffixOf().");
  return (realm + ".example.net").split(".").map(function (label) {
    return "dc=" + label;
  }).join(",");
}

// An LDAP modify of one person's userCertificate;binary.
function ldapCertificate(realm, uid, der, operation) {
  log.debug("Entering ldapCertificate(). " + operation);
  const url = "ldap://" + new URL(K.base).hostname + ":" +
              (process.env.STS_LDAP_PORT || "389");
  const users = "ou=users," + suffixOf(realm);
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: url });
    function done(error) {
      client.unbind();
      log.debug("Leaving ldapCertificate().");
      resolve(error ? { ok: false, message: error.message } : { ok: true });
    }
    client.on("error", function (e) {
      log.debug("Caught in ldapCertificate(): " + e.message);
      resolve({ ok: false, message: String(e && e.message) });
    });
    client.bind("uid=" + uid + "," + users, "x-" + K.STAMP,
                function (bindError) {
      if (bindError) {
        done(bindError);
        return;
      }
      client.modify("uid=" + uid + "," + users, new ldapjs.Change({
        operation: operation, modification: new ldapjs.Attribute({
          type: "userCertificate;binary", values: [der] }) }), done);
    });
  });
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("certmap");
  const alice = "cma-" + K.STAMP;
  const bob = "cmb-" + K.STAMP;
  for (const who of [alice, bob]) {
    await K.ok(K.rb(realm) + "/admin-api/users/create", { username: who,
      invent: false, credential: "none", attributes: { cn: who,
        givenName: who, sn: who, mail: who + "@cm.example.test" } },
      "created " + who);
  }
  const client = "cmrp-" + K.STAMP;
  await K.app(realm, client, { oauthClientId: [client],
    oauthRedirectUri: ["https://rp.example.test/cb"],
    oauthTokenEndpointAuthMethod: "none",
    oauthGrantType: ["authorization_code"], oauthAllowedScope: ["openid"] });
  const minted = await anchors.mint({ subject: "CN=" + alice +
                                      ",O=outside authority" });
  const installed = await anchors.trustRecorded(K.base, minted.anchorPem,
                                                added);
  assert.ok(installed.ok, "the outside Root was not admitted: " +
            String(installed.why || installed.status));
  const tls = { cert: minted.certPem, key: minted.keyPem };
  const leafDer = new nodeCrypto.X509Certificate(minted.leaf.pem).raw;
  const rb = K.rb(realm);

  log.info("=== A. stored nowhere ===");
  refused("A1. the sign-in screen refuses a certificate no account stores, " +
          "though its CN names one",
    await coded(realm, "STS-AUTHN-0468", function () {
      return certificateSignIn(realm, client, tls);
    }), "STS-AUTHN-0468");
  refused("A2. SCIM does not take it",
    await coded(realm, "STS-SCIM-0084", function () {
      return settled("GET", rb + "/scim/v2/Users", { tls: tls });
    }), "STS-SCIM-0084");
  refused("A3. the Shared Signals door does not take it alone",
    await coded(realm, "STS-SSF-0151", function () {
      return settled("GET", rb + "/ssf/stream", { tls: tls });
    }), "STS-SSF-0151");
  refused("A4. GET /xacml resolves it to nobody",
    await coded(realm, "STS-XACML-0177", function () {
      return settled("GET", rb + "/xacml", { tls: tls });
    }), "STS-XACML-0177");

  log.info("=== B. stored on two entries ===");
  await K.ok(rb + "/admin-api/users/add-certificate", { user: alice,
    certificate: minted.leaf.pem }, "stored it on " + alice);
  const second = await ldapCertificate(realm, bob, leafDer, "add");
  check("B0. the second copy is written over LDAP", function () {
    assert.ok(second.ok, second.message);
  });
  refused("B1. the sign-in screen refuses a certificate two accounts store",
    await coded(realm, "STS-AUTHN-0469", function () {
      return certificateSignIn(realm, client, tls);
    }), "STS-AUTHN-0469");
  const twice = await coded(realm, "STS-TLS-0055", function () {
    return settled("GET", rb + "/tls/sign-in", { tls: tls });
  });
  check("B2. /tls/sign-in starts no session for it: 200, signedIn false, " +
        "STORED_TWICE, recorded STS-TLS-0055", function () {
    const j = twice.answer.json || {};
    assert.strictEqual(twice.answer.status, 200, twice.answer.text);
    assert.strictEqual(j.signedIn, false, twice.answer.text);
    assert.strictEqual(j.session && j.session.refusedAsStored,
                       "STORED_TWICE", twice.answer.text);
    assert.ok(twice.rose >= 1, "STS-TLS-0055 rows: " + twice.rose);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(twice.answer.text));
  });
  refused("B3. SCIM does not take it",
    await coded(realm, "STS-SCIM-0085", function () {
      return settled("GET", rb + "/scim/v2/Users", { tls: tls });
    }), "STS-SCIM-0085");
  refused("B4. GET /xacml refuses it",
    await coded(realm, "STS-XACML-0178", function () {
      return settled("GET", rb + "/xacml", { tls: tls });
    }), "STS-XACML-0178");

  log.info("=== C. stored on one entry ===");
  const off = await ldapCertificate(realm, bob, leafDer, "delete");
  assert.ok(off.ok, off.message);
  const signedIn = await settled("GET", rb + "/tls/sign-in", { tls: tls });
  check("C1. stored on one entry again, /tls/sign-in starts that person's " +
        "session", function () {
    assert.ok(signedIn.status < 400, signedIn.status + " " +
              signedIn.text.slice(0, 200));
    assert.ok(signedIn.setCookies.some(function (c) {
      return /sts_session|__Host-sts_session/.test(c);
    }), JSON.stringify(signedIn.setCookies));
  });
  log.debug("Leaving test().");
}

async function guarded() {
  log.debug("Entering guarded().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in guarded(): " + ((e && e.message) || e));
    // Rethrown after the anchor is removed.
    failure = e;
  }
  await anchors.settleAnchors(K.base, added, failure);
  log.debug("Leaving guarded().");
}

K.main(guarded, FLOOR);
