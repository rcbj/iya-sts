// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_cert_sign_in_profiles.js
//
// ---------------------------------------------------------------------------
// A CERTIFICATE SIGN-IN PROFILE AND RFC 9440 FROM A NAMED PROXY, OVER REAL
// HANDSHAKES (#2012).
//
// `tests/certificate_binding.js` holds the logic in process; this holds what
// a running service does with it, which is the only kind of check an AWS
// target and product mode can run. An outside chain (Root → Issuing CA →
// leaf, `tools/pep-credential.js`) is minted and its Root admitted to the
// client truststore through the gated door (recorded first, removed at the
// end, #335/#1307); a second chain plays the TLS-terminating proxy. Every
// setting is written on a throwaway development realm:
//
//   A. NO PROFILE: the leaf, stored on nobody, signs nobody in at
//      `/tls/sign-in` (#1061's rule, as before; STS-TLS-0054).
//   B. A PROFILE covering the Root, binding by issuer and serial: with the
//      binding recorded on alice (`users/add-attribute`), `/tls/sign-in`
//      starts her session; the same binding given to bob is refused.
//   C. OUTSIDE THE PROFILE: the profile asking extendedKeyUsage
//      emailProtection, which the leaf does not carry, signs nobody in.
//   D. LOW AFFINITY WITHOUT OPTING IN: a profile naming `upn` without
//      `lowAffinity` is refused when written (STS-TLS-0065).
//   B3. TWO METHODS, TWO PEOPLE: issuer-serial on alice and the leaf's key
//      (spki-sha256) on bob sign nobody in (STORED_TWICE).
//   E. RFC 9440: from the named proxy (its certificate and an address range
//      holding every address), the forwarded leaf signs alice in; the same
//      headers on a connection presenting no certificate sign nobody in;
//      from the proxy, a leaf whose root the truststore does not hold, and
//      bytes that are not a certificate, present no certificate; and from
//      the proxy's certificate outside the address range the headers are
//      removed and the proxy's own certificate, stored on nobody, is what
//      the door sees.
//   F. REVOCATION REQUIRED: with certSignIn.requireRevocation on and
//      revocation not consulted (pki.revocationCheck off), the bound leaf
//      signs nobody in.
//
// NOT CARRIED, and why: the certificate handoff to a second listener needs a
// custom listener bound by the stack (owed with the listener jobs); a
// policy-mapped Federal PKI path, a forged intermediate sent after the leaf,
// a profile mixing high- and low-affinity methods (a UPN in the leaf) and a
// serverAuth-only forwarded leaf all need certificate fields this minting
// tool does not write, and are held in process (tests/certificate_binding.js
// sections 3, 4 and 6).
//
// OWNED HERE (local: true): this repository's own doors.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const anchors = require("../tools/pep-credential.js");
const K = require("./oauth_wire_kit.js").kit("sts_cert_sign_in_profiles");
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
    const headers = Object.assign({ accept: "application/json" },
                                  opts.headers || {});
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
                  setCookies: [].concat(res.headers["set-cookie"] || []) });
      });
    });
    req.on("error", function (e) {
      log.debug("Caught in tlsCall(): " + e.message);
      reject(e);
    });
    req.end();
  });
}

// A call the truststore may not have applied yet: retried on a reset (the
// install races the next handshake, tests/CLAUDE.md, #335).
async function settled(url, o) {
  log.debug("Entering settled().");
  let last = null;
  for (let i = 0; i < 10; i += 1) {
    try {
      const r = await tlsCall("GET", url, o);
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

// The SHA-256 of a certificate's SubjectPublicKeyInfo, as a profile's
// `issuers` and an issuer-scoped binding name a CA.
function spkiSha256(pem) {
  log.debug("Entering spkiSha256().");
  const spki = new nodeCrypto.X509Certificate(pem).publicKey
    .export({ type: "spki", format: "der" });
  log.debug("Leaving spkiSha256().");
  return nodeCrypto.createHash("sha256").update(spki).digest("hex");
}

function derOf(pem) {
  log.debug("Entering derOf().");
  log.debug("Leaving derOf().");
  return new nodeCrypto.X509Certificate(pem).raw;
}

function started(r) {
  log.debug("Entering started().");
  log.debug("Leaving started().");
  return !!(r.json && r.json.signedIn === true);
}

// THE PROXY SETTINGS ARE READ IN THE FRONT PROCESS, WHICH A WORKER'S WRITE
// REACHES THROUGH THE CHANGE LOG (run 45236493306). `/admin-api/realms/set`
// is answered by a request worker, and `common/forwarded_client_certificate.ts`
// decides in the front process before dispatch, on its own copy of the realm,
// which the store's change log brings up to date a moment later. The read
// barrier (`workers.readYourWrite`) is a worker's and covers the writer's own
// session; the proxy's request is neither. So in single-node and mariadb E3's
// request, sent at once, met the range it had replaced and signed alice in.
// A request is therefore asked again until the answer is the one the
// setting means, for at most ten seconds: the check is still that the
// setting takes effect, and a setting that never did still fails.
async function settledUntil(url, o, wanted) {
  log.debug("Entering settledUntil().");
  const deadline = Date.now() + 10000;
  let r = await settled(url, o);
  while (!wanted(r) && Date.now() < deadline) {
    await K.sleep(250);
    r = await settled(url, o);
  }
  log.debug("Leaving settledUntil(). " + wanted(r));
  return r;
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("certprof");
  const rb = K.rb(realm);
  const alice = "cpa-" + K.STAMP;
  const bob = "cpb-" + K.STAMP;
  for (const who of [alice, bob]) {
    await K.ok(rb + "/admin-api/users/create", { username: who,
      invent: false, credential: "none", attributes: { cn: who,
        givenName: who, sn: who, mail: who + "@cp.example.test" } },
      "created " + who);
  }
  const card = await anchors.mint({ subject: "CN=SMITH.JANE." + K.STAMP +
                                    ",O=outside authority" });
  const proxy = await anchors.mint({ subject: "CN=proxy " + K.STAMP +
                                     ",O=outside authority",
                                     rootSubject: "CN=proxy Root " +
                                       K.STAMP });
  for (const one of [card, proxy]) {
    const installed = await anchors.trustRecorded(K.base, one.anchorPem,
                                                  added);
    assert.ok(installed.ok, "an outside Root was not admitted: " +
              String(installed.why || installed.status));
  }
  const tls = { cert: card.certPem, key: card.keyPem };
  const binding = "issuer-serial:" + spkiSha256(card.issuing.pem) + ":" +
    String(card.leaf.serialHex).toLowerCase();
  const profile = { id: "outside", issuers: [spkiSha256(card.anchorPem)],
                    keyUsage: ["digitalSignature"],
                    extendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
                    bindings: ["issuer-serial"] };

  log.info("=== A. no profile ===");
  const none = await settled(rb + "/tls/sign-in", { tls: tls });
  check("A1. with no profile the leaf, stored on nobody, signs nobody in " +
        "(NOT_STORED)", function () {
    assert.ok(!started(none), none.text.slice(0, 300));
    assert.strictEqual(none.json && none.json.session &&
                       none.json.session.refusedAsStored, "NOT_STORED",
                       none.text.slice(0, 300));
  });

  log.info("=== B. a profile binding by issuer and serial ===");
  await K.set(realm, "certSignIn.profiles", JSON.stringify([profile]));
  await K.ok(rb + "/admin-api/users/add-attribute", { user: alice,
    attribute: "stsCertificateBinding", value: binding.toUpperCase()
      .replace(/^ISSUER-SERIAL/, "Issuer-Serial") },
    "bound the leaf to " + alice);
  const bound = await settled(rb + "/tls/sign-in", { tls: tls });
  check("B1. the profile binds the leaf to alice: /tls/sign-in starts her " +
        "session", function () {
    assert.ok(started(bound), bound.text.slice(0, 300));
    assert.ok(bound.setCookies.some(function (c) {
      return /sts_session/.test(c);
    }), JSON.stringify(bound.setCookies));
  });
  const twice = await K.send(rb + "/admin-api/users/add-attribute", { json: {
    user: bob, attribute: "stsCertificateBinding", value: binding } });
  check("B2. the same binding given to bob is refused, and no code is sent",
        function () {
    assert.ok(twice.status >= 400, twice.status + " " + twice.text);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(twice.text), twice.text);
  });
  const keyBinding = "spki-sha256:" + spkiSha256(card.leaf.pem);
  await K.ok(rb + "/admin-api/users/add-attribute", { user: bob,
    attribute: "stsCertificateBinding", value: keyBinding },
    "bound the leaf's key to " + bob);
  await K.set(realm, "certSignIn.profiles", JSON.stringify([Object.assign(
    {}, profile, { bindings: ["issuer-serial", "spki-sha256"] })]));
  const split = await settled(rb + "/tls/sign-in", { tls: tls });
  check("B3. two methods naming different people sign nobody in " +
        "(STORED_TWICE)", function () {
    assert.ok(!started(split), split.text.slice(0, 300));
    assert.strictEqual(split.json && split.json.session &&
                       split.json.session.refusedAsStored, "STORED_TWICE",
                       split.text.slice(0, 300));
  });
  await K.ok(rb + "/admin-api/users/remove-attribute", { user: bob,
    attribute: "stsCertificateBinding", value: keyBinding },
    "took the key binding off " + bob);
  await K.set(realm, "certSignIn.profiles", JSON.stringify([profile]));

  log.info("=== C. outside the profile ===");
  await K.set(realm, "certSignIn.profiles", JSON.stringify([Object.assign(
    {}, profile, { extendedKeyUsage: ["1.3.6.1.5.5.7.3.4"] })]));
  const outside = await settled(rb + "/tls/sign-in", { tls: tls });
  check("C1. a leaf outside its profile's extendedKeyUsage signs nobody in, " +
        "however it is bound", function () {
    assert.ok(!started(outside), outside.text.slice(0, 300));
    assert.strictEqual(outside.json && outside.json.session &&
                       outside.json.session.refusedAsStored, "NOT_STORED",
                       outside.text.slice(0, 300));
  });

  log.info("=== D. low affinity without opting in ===");
  const low = await K.send(K.base + "/admin-api/realms/set", { json: {
    id: realm, key: "certSignIn.profiles", value: JSON.stringify([
      Object.assign({}, profile, { bindings: ["upn"] })]) } });
  check("D1. a name binding without lowAffinity is refused when written",
        function () {
    assert.ok(low.status >= 400, low.status + " " + low.text);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(low.text), low.text);
  });
  await K.set(realm, "certSignIn.profiles", JSON.stringify([profile]));

  log.info("=== E. RFC 9440 from the named proxy ===");
  const forwarded = {
    "client-cert": ":" + derOf(card.leaf.pem).toString("base64") + ":",
    "client-cert-chain": ":" + derOf(card.issuing.pem).toString("base64") +
                         ":"
  };
  const proxyTls = { cert: proxy.certPem, key: proxy.keyPem };
  const proxySha = nodeCrypto.createHash("sha256")
    .update(derOf(proxy.leaf.pem)).digest("hex");
  await K.set(realm, "tls.trustedProxyCertificates", proxySha);
  await K.set(realm, "tls.trustedProxyAddresses", "0.0.0.0/0,::/0");
  const viaProxy = await settledUntil(rb + "/tls/sign-in",
                                      { tls: proxyTls, headers: forwarded },
                                      started);
  check("E1. from the named proxy, the forwarded leaf signs alice in",
        function () {
    assert.ok(started(viaProxy), viaProxy.text.slice(0, 300));
  });
  const direct = await settled(rb + "/tls/sign-in", { headers: forwarded });
  check("E2. the same headers on a connection presenting no certificate " +
        "sign nobody in", function () {
    assert.ok(!started(direct), direct.text.slice(0, 300));
    assert.ok(!(direct.json && direct.json.clientCertificate &&
                direct.json.clientCertificate.presented),
              direct.text.slice(0, 300));
  });
  const unheld = await anchors.mint({ subject: "CN=unheld " + K.STAMP +
                                      ",O=nobody's",
                                      rootSubject: "CN=unheld Root " +
                                        K.STAMP });
  const strange = await settled(rb + "/tls/sign-in", { tls: proxyTls,
    headers: { "client-cert": ":" + derOf(unheld.leaf.pem)
      .toString("base64") + ":", "client-cert-chain": ":" +
      derOf(unheld.issuing.pem).toString("base64") + ":" } });
  check("E2-ii. from the proxy, a leaf whose root the truststore does not " +
        "hold presents no certificate", function () {
    assert.ok(!started(strange), strange.text.slice(0, 300));
    assert.ok(!(strange.json && strange.json.clientCertificate &&
                strange.json.clientCertificate.presented),
              strange.text.slice(0, 300));
  });
  const garbled = await settled(rb + "/tls/sign-in", { tls: proxyTls,
    headers: { "client-cert": ":bm90IGEgY2VydGlmaWNhdGU=:" } });
  check("E2-iii. from the proxy, bytes that are not a certificate present " +
        "no certificate", function () {
    assert.ok(!started(garbled), garbled.text.slice(0, 300));
    assert.ok(!(garbled.json && garbled.json.clientCertificate &&
                garbled.json.clientCertificate.presented),
              garbled.text.slice(0, 300));
  });
  await K.set(realm, "tls.trustedProxyAddresses", "192.0.2.0/24");
  const elsewhere = await settledUntil(rb + "/tls/sign-in",
                                       { tls: proxyTls, headers: forwarded },
                                       function (r) {
                                         return !started(r);
                                       });
  check("E3. from the proxy's certificate outside its address range the " +
        "headers are removed, and the proxy's own certificate signs nobody " +
        "in", function () {
    assert.ok(!started(elsewhere), elsewhere.text.slice(0, 300));
    assert.strictEqual(elsewhere.json && elsewhere.json.session &&
                       elsewhere.json.session.refusedAsStored, "NOT_STORED",
                       elsewhere.text.slice(0, 300));
  });
  await K.unset(realm, "tls.trustedProxyAddresses");
  await K.unset(realm, "tls.trustedProxyCertificates");

  log.info("=== F. a verified revocation status required ===");
  await K.set(realm, "certSignIn.requireRevocation", "on");
  await K.set(realm, "pki.revocationCheck", "off");
  const unchecked = await settled(rb + "/tls/sign-in", { tls: tls });
  check("F1. with revocation not consulted and a verified status required, " +
        "the bound leaf signs nobody in", function () {
    assert.ok(!started(unchecked), unchecked.text.slice(0, 300));
    const session = (unchecked.json && unchecked.json.session) || {};
    assert.ok(session.refusedOnRevocation === true &&
              session.revocationRequired === true,
              unchecked.text.slice(0, 300));
  });
  await K.unset(realm, "pki.revocationCheck");
  await K.unset(realm, "certSignIn.requireRevocation");
  log.debug("Leaving test().");
}

async function guarded() {
  log.debug("Entering guarded().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in guarded(): " + ((e && e.message) || e));
    // Rethrown after the anchors are removed.
    failure = e;
  }
  await anchors.settleAnchors(K.base, added, failure);
  log.debug("Leaving guarded().");
}

K.main(guarded, FLOOR);
