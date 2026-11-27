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
//   G. EVERY BINDING METHOD (#2081): issuer-serial, certificate-sha256,
//      issuer-ski, spki-sha256, and with lowAffinity email, issuer-subject
//      and subject, one per profile, each value worked out by openssl as
//      docs/v1.2.0/configure-tls.md says: bound to nobody it signs nobody
//      in, bound to alice it signs her in, and with her account disabled it
//      signs nobody in.
//   H. RENEWAL (#2081): the Issuing CA certifying alice's key again, then a
//      new key. issuer-serial and certificate-sha256 must be recorded again
//      for the renewal; spki-sha256 and issuer-ski carry over while the key
//      does, and not past a new one.
//   I. AN EXPIRED LEAF (#2081), bound to alice, signs nobody in: the
//      handshake does not verify it.
//   J. REVOCATION IN DEVELOPMENT (#2089): a leaf its CA's CRL lists is
//      refused on revocation; one whose CRL cannot be fetched signs in
//      under `auto` (soft fail) and not under `on`; a status verified good
//      meets `on`.
//   K. PRODUCT MODE (#2089): in a product-mode realm, under the default
//      `auto`, the good chain is accepted (the screen offers to continue as
//      its holder), and the listed and the unfetchable leaves are refused
//      on revocation.
//
// The handoff to a second listener is `sts_cert_handoff.js` (#2081), an
// exclusive job of its own. NOT CARRIED, and why: a policy-mapped Federal
// PKI path, a forged intermediate sent after the leaf,
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
const { execFileSync } = require("child_process");
const anchors = require("../tools/pep-credential.js");
const authnSignin = require("./authn_signin");
const K = require("./oauth_wire_kit.js").kit("sts_cert_sign_in_profiles");
const log = K.log;

const FLOOR = 48;
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
                  location: String(res.headers.location || ""),
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
// SINCE THE FRONT CATCHES UP ON A SETTINGS ANSWER (rcbj, 2026-11-23, "catch
// up on change": `persistence/persistence.js`, THE SETTINGS GENERATION) the
// first answer is already right on ONE node — the front holds the write's
// answer until its own copy has the setting. The retry stays for the
// cluster mode, where the balancer may send the proxy's request to the
// OTHER node, whose front hears the write only by the change log's own
// nudge (NOTIFY on PostgreSQL) a moment later.
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

  await everyMethod(realm, rb, { alice: alice, card: card, profile: profile,
                                 serialBinding: binding });
  await renewals(realm, rb, { alice: alice, card: card, profile: profile });
  await expired(realm, rb, { alice: alice, card: card, profile: profile });
  const revocation = await revocationCards();
  await revocationInDevelopment(realm, rb, { alice: alice, card: card,
                                             profile: profile },
                                revocation);
  await productMode(revocation, { card: card, profile: profile });
  log.debug("Leaving test().");
}

// ---------------------------------------------------------------------------
// THE VALUES AN ADMINISTRATOR RECORDS, WORKED OUT THE WAY THE DOCUMENTATION
// SAYS (#2081): `docs/v1.2.0/configure-tls.md`, *Working out the values*, by
// openssl, never by this service's own parser. A value the service then
// fails to match is a gap between the page and the code.
// ---------------------------------------------------------------------------
function openssl(args, pem, binary) {
  log.debug("Entering openssl(). " + args.join(" "));
  const out = execFileSync("openssl", args, { input: pem });
  log.debug("Leaving openssl().");
  return binary ? out : out.toString("utf8").trim();
}

function sha256Hex(bytes) {
  log.debug("Entering sha256Hex().");
  log.debug("Leaving sha256Hex().");
  return nodeCrypto.createHash("sha256").update(bytes).digest("hex");
}

// `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256`.
function opensslSpki(pem) {
  log.debug("Entering opensslSpki().");
  const pub = openssl(["x509", "-pubkey", "-noout"], pem);
  log.debug("Leaving opensslSpki().");
  return sha256Hex(openssl(["pkey", "-pubin", "-outform", "der"], pub, true));
}

// Every value of `who`'s leaf for `method`, as the documentation spells it.
function valueFor(method, leafPem, issuingPem) {
  log.debug("Entering valueFor(). " + method);
  const issuer = opensslSpki(issuingPem);
  let value = "";
  if (method === "certificate-sha256") {
    value = method + ":" + sha256Hex(openssl(["x509", "-outform", "der"],
                                             leafPem, true));
  } else if (method === "spki-sha256") {
    value = method + ":" + opensslSpki(leafPem);
  } else if (method === "issuer-ski") {
    // "X509v3 Subject Key Identifier: \n    AB:CD:..."
    const printed = openssl(["x509", "-noout", "-ext",
                             "subjectKeyIdentifier"], leafPem);
    value = method + ":" + issuer + ":" + printed.split("\n").pop().trim();
  } else if (method === "issuer-subject" || method === "subject") {
    const dn = openssl(["x509", "-noout", "-subject", "-nameopt", "RFC2253"],
                       leafPem).replace(/^subject=\s*/, "");
    value = method === "subject" ? "subject:" + dn
      : method + ":" + issuer + ":" + dn;
  }
  log.debug("Leaving valueFor().");
  return value;
}

const LOW = ["email", "issuer-subject", "subject"];

// ---------------------------------------------------------------------------
// G. EVERY STORED METHOD OVER A REAL HANDSHAKE, AND A DISABLED ACCOUNT UNDER
// EACH (#2081). One method per profile, so the match is that method's alone:
// bound to nobody it signs nobody in, bound to alice it signs her in, and
// with her account disabled it signs nobody in, whatever names her. email
// needs a leaf with an rfc822Name, reissued under the same Issuing CA; its
// value is the address already on alice's entry (`mail`).
// ---------------------------------------------------------------------------
async function everyMethod(realm, rb, o) {
  log.debug("Entering everyMethod().");
  log.info("=== G. every binding method, and a disabled account ===");
  const mail = o.alice + "@cp.example.test";
  const mailed = await anchors.reissue(o.card, { san: [{ kind: "email",
                                                         value: mail }] });
  const methods = ["issuer-serial", "certificate-sha256", "issuer-ski",
                   "spki-sha256", "email", "issuer-subject", "subject"];
  for (const method of methods) {
    const credential = method === "email" ? mailed : o.card;
    const tls = { cert: credential.certPem, key: credential.keyPem };
    const value = method === "issuer-serial" ? o.serialBinding
      : (method === "email" ? "" : valueFor(method, credential.leaf.pem,
                                            credential.issuing.pem));
    await K.set(realm, "certSignIn.profiles", JSON.stringify([Object.assign(
      {}, o.profile, { bindings: [method],
                       lowAffinity: LOW.indexOf(method) >= 0 })]));
    if (method !== "issuer-serial" && method !== "email") {
      const before = await settled(rb + "/tls/sign-in", { tls: tls });
      check("G-" + method + "-1. bound to nobody, " + method + " signs " +
            "nobody in (NOT_STORED)", function () {
        assert.ok(!started(before), before.text.slice(0, 300));
        assert.strictEqual(before.json && before.json.session &&
                           before.json.session.refusedAsStored, "NOT_STORED",
                           before.text.slice(0, 300));
      });
      await K.ok(rb + "/admin-api/users/add-attribute", { user: o.alice,
        attribute: "stsCertificateBinding", value: value },
        "bound alice by " + method + " (" + value + ")");
    }
    const bound = await settled(rb + "/tls/sign-in", { tls: tls });
    check("G-" + method + "-2. " + method + ", worked out as the " +
          "documentation says, signs alice in", function () {
      assert.ok(started(bound), value + ": " + bound.text.slice(0, 300));
    });
    await K.ok(rb + "/admin-api/users/disable", { user: o.alice,
      reason: "#2081: a disabled account under " + method },
      "disabled alice");
    const disabled = await settled(rb + "/tls/sign-in", { tls: tls });
    check("G-" + method + "-3. with alice's account disabled, " + method +
          " signs nobody in and sets no session cookie", function () {
      assert.ok(!started(disabled), disabled.text.slice(0, 300));
      assert.ok(!disabled.setCookies.some(function (c) {
        return /^sts_session=[^;]+/.test(c) && !/^sts_session=;/.test(c);
      }), JSON.stringify(disabled.setCookies));
    });
    await K.ok(rb + "/admin-api/users/enable", { user: o.alice },
               "enabled alice");
    if (method !== "issuer-serial" && method !== "email") {
      await K.ok(rb + "/admin-api/users/remove-attribute", { user: o.alice,
        attribute: "stsCertificateBinding", value: value },
        "took the " + method + " binding off alice");
    }
  }
  await K.set(realm, "certSignIn.profiles", JSON.stringify([o.profile]));
  log.debug("Leaving everyMethod().");
}

// ---------------------------------------------------------------------------
// H. RENEWAL OVER A REAL HANDSHAKE (#2081). The same Issuing CA certifies
// alice's key again (a new serial and a new certificate, the same
// SubjectPublicKeyInfo and the subjectKeyIdentifier derived from it), and
// then a new key. A certificate-specific binding (issuer-serial,
// certificate-sha256) must be recorded again for the renewal; a key-based
// one (spki-sha256, issuer-ski) carries over while the key does, and not
// past a new key.
// ---------------------------------------------------------------------------
async function renewals(realm, rb, o) {
  log.debug("Entering renewals().");
  log.info("=== H. renewal ===");
  const renewed = await anchors.reissue(o.card, { sameKey: true });
  const rekeyed = await anchors.reissue(o.card, {});
  const asTls = function (one) {
    return { cert: one.certPem, key: one.keyPem };
  };
  const rows = [["issuer-serial", false], ["certificate-sha256", false],
                ["spki-sha256", true], ["issuer-ski", true]];
  for (const row of rows) {
    const method = row[0];
    const carries = row[1];
    const value = method === "issuer-serial"
      ? "issuer-serial:" + opensslSpki(o.card.issuing.pem) + ":" +
        String(o.card.leaf.serialHex).toLowerCase()
      : valueFor(method, o.card.leaf.pem, o.card.issuing.pem);
    await K.set(realm, "certSignIn.profiles", JSON.stringify([Object.assign(
      {}, o.profile, { bindings: [method] })]));
    if (method !== "issuer-serial") {
      await K.ok(rb + "/admin-api/users/add-attribute", { user: o.alice,
        attribute: "stsCertificateBinding", value: value },
        "bound alice's first certificate by " + method);
    }
    const again = await settled(rb + "/tls/sign-in", { tls: asTls(renewed) });
    check("H-" + method + "-1. the renewal under the same key " +
          (carries ? "carries " + method + " over and signs alice in"
                   : "is not bound by " + method + " until it is recorded"),
          function () {
      assert.strictEqual(started(again), carries, again.text.slice(0, 300));
    });
    if (carries) {
      const fresh = await settled(rb + "/tls/sign-in",
                                  { tls: asTls(rekeyed) });
      check("H-" + method + "-2. a renewal under a new key does not carry " +
            method + " over", function () {
        assert.ok(!started(fresh), fresh.text.slice(0, 300));
      });
    } else {
      const replaced = valueFor(method === "issuer-serial"
        ? "certificate-sha256" : method, renewed.leaf.pem,
                                renewed.issuing.pem);
      const recorded = method === "issuer-serial"
        ? "issuer-serial:" + opensslSpki(renewed.issuing.pem) + ":" +
          String(renewed.leaf.serialHex).toLowerCase()
        : replaced;
      await K.ok(rb + "/admin-api/users/add-attribute", { user: o.alice,
        attribute: "stsCertificateBinding", value: recorded },
        "recorded the renewal by " + method);
      const after = await settled(rb + "/tls/sign-in",
                                  { tls: asTls(renewed) });
      check("H-" + method + "-2. once the renewal is recorded on alice, " +
            method + " signs her in with it", function () {
        assert.ok(started(after), after.text.slice(0, 300));
      });
      await K.ok(rb + "/admin-api/users/remove-attribute", { user: o.alice,
        attribute: "stsCertificateBinding", value: recorded },
        "took the renewal's binding off alice");
    }
    if (method !== "issuer-serial") {
      await K.ok(rb + "/admin-api/users/remove-attribute", { user: o.alice,
        attribute: "stsCertificateBinding", value: value },
        "took the " + method + " binding off alice");
    }
  }
  await K.set(realm, "certSignIn.profiles", JSON.stringify([o.profile]));
  log.debug("Leaving renewals().");
}

// ---------------------------------------------------------------------------
// I. AN EXPIRED CERTIFICATE (#2081): one the Issuing CA made with a validity
// that ended an hour ago, bound to alice by its own issuer and serial so the
// profile would otherwise sign her in. The handshake's verification refuses
// it, so the door sees no verified certificate.
// ---------------------------------------------------------------------------
async function expired(realm, rb, o) {
  log.debug("Entering expired().");
  log.info("=== I. an expired certificate ===");
  const old = await anchors.reissue(o.card, { expiredSince: 3600 * 1000 });
  const value = "issuer-serial:" + opensslSpki(old.issuing.pem) + ":" +
    String(old.leaf.serialHex).toLowerCase();
  await K.ok(rb + "/admin-api/users/add-attribute", { user: o.alice,
    attribute: "stsCertificateBinding", value: value },
    "bound the expired certificate to alice");
  const r = await settled(rb + "/tls/sign-in",
                          { tls: { cert: old.certPem, key: old.keyPem } });
  check("I1. an expired certificate bound to alice under the profile signs " +
        "nobody in: the handshake does not verify it", function () {
    assert.ok(!started(r), r.text.slice(0, 300));
    assert.ok(!(r.json && r.json.clientCertificate &&
                r.json.clientCertificate.verified === true),
              r.text.slice(0, 300));
  });
  await K.ok(rb + "/admin-api/users/remove-attribute", { user: o.alice,
    attribute: "stsCertificateBinding", value: value },
    "took the expired certificate's binding off alice");
  log.debug("Leaving expired().");
}

// ---------------------------------------------------------------------------
// TWO MORE OUTSIDE CHAINS FOR REVOCATION (#2089), each of its own so that no
// list the service has already fetched and kept answers for it: one whose
// Issuing CA's CRL lists the leaf (`revokeLeaf`), and one whose Issuing CA's
// CRL is never published, so its address answers 404 and the leaf's status
// cannot be established (`crlMissing`). Their Roots join the truststore, and
// are removed with the others at the end.
// ---------------------------------------------------------------------------
async function revocationCards() {
  log.debug("Entering revocationCards().");
  const revoked = await anchors.mint({ revokeLeaf: true,
    subject: "CN=REVOKED.JANE." + K.STAMP + ",O=outside authority",
    rootSubject: "CN=revoked Root " + K.STAMP });
  const missing = await anchors.mint({ crlMissing: true,
    subject: "CN=UNLISTED.JANE." + K.STAMP + ",O=outside authority",
    rootSubject: "CN=unlisted Root " + K.STAMP });
  for (const one of [revoked, missing]) {
    const installed = await anchors.trustRecorded(K.base, one.anchorPem,
                                                  added);
    assert.ok(installed.ok, "an outside Root was not admitted: " +
              String(installed.why || installed.status));
  }
  log.debug("Leaving revocationCards().");
  return { revoked: revoked, missing: missing };
}

function serialBindingOf(credential) {
  log.debug("Entering serialBindingOf().");
  log.debug("Leaving serialBindingOf().");
  return "issuer-serial:" + opensslSpki(credential.issuing.pem) + ":" +
    String(credential.leaf.serialHex).toLowerCase();
}

// The one profile covering the first chain and both revocation chains.
function coveringAll(o, r) {
  log.debug("Entering coveringAll().");
  log.debug("Leaving coveringAll().");
  return JSON.stringify([Object.assign({}, o.profile, {
    issuers: [opensslSpki(o.card.anchorPem), opensslSpki(r.revoked.anchorPem),
              opensslSpki(r.missing.anchorPem)] })]);
}

function asTls(credential) {
  log.debug("Entering asTls().");
  log.debug("Leaving asTls().");
  return { cert: credential.certPem, key: credential.keyPem };
}

function refusedOnRevocation(r) {
  log.debug("Entering refusedOnRevocation().");
  const session = (r.json && r.json.session) || {};
  log.debug("Leaving refusedOnRevocation().");
  return !started(r) && session.refusedOnRevocation === true;
}

// ---------------------------------------------------------------------------
// J. REVOCATION, END TO END, IN DEVELOPMENT MODE (#2089). Each leaf is bound
// to alice by its own issuer and serial, so only its status decides:
//
//   * listed on its CA's CRL, it signs nobody in, refused on revocation,
//     whatever certSignIn.requireRevocation says;
//   * its CRL unavailable, it signs alice in under `auto` (development
//     leaves an unknown status to pki.revocationCheck's soft fail, as
//     documented) and signs nobody in under `on` (STS-TLS-0071);
//   * the first chain, whose CRL is served and empty, signs alice in under
//     `on`: the requirement is met by a status verified good.
// ---------------------------------------------------------------------------
async function revocationInDevelopment(realm, rb, o, r) {
  log.debug("Entering revocationInDevelopment().");
  log.info("=== J. revocation, in development mode ===");
  await K.set(realm, "certSignIn.profiles", coveringAll(o, r));
  for (const one of [r.revoked, r.missing]) {
    await K.ok(rb + "/admin-api/users/add-attribute", { user: o.alice,
      attribute: "stsCertificateBinding", value: serialBindingOf(one) },
      "bound " + one.leaf.subject + " to alice");
  }
  const revoked = await settled(rb + "/tls/sign-in",
                                { tls: asTls(r.revoked) });
  check("J1. a leaf its CA's CRL lists, bound to alice, signs nobody in: " +
        "refused on revocation", function () {
    assert.ok(refusedOnRevocation(revoked), revoked.text.slice(0, 400));
  });
  const soft = await settled(rb + "/tls/sign-in", { tls: asTls(r.missing) });
  check("J2. a leaf whose CRL cannot be fetched signs alice in under " +
        "certSignIn.requireRevocation auto in development (the revocation " +
        "policy's soft fail)", function () {
    assert.ok(started(soft), soft.text.slice(0, 400));
  });
  await K.set(realm, "certSignIn.requireRevocation", "on");
  const hard = await settled(rb + "/tls/sign-in", { tls: asTls(r.missing) });
  check("J3. under certSignIn.requireRevocation on, the same leaf signs " +
        "nobody in: no verified status (STS-TLS-0071)", function () {
    assert.ok(refusedOnRevocation(hard), hard.text.slice(0, 400));
    assert.strictEqual(hard.json.session.revocationRequired, true,
                       hard.text.slice(0, 400));
  });
  const good = await settled(rb + "/tls/sign-in", { tls: asTls(o.card) });
  check("J4. under on, the first chain, its CRL served and empty, signs " +
        "alice in: a status verified good meets the requirement",
        function () {
    assert.ok(started(good), good.text.slice(0, 400));
  });
  const stillRevoked = await settled(rb + "/tls/sign-in",
                                     { tls: asTls(r.revoked) });
  check("J5. and the listed leaf is refused on revocation under on too",
        function () {
    assert.ok(refusedOnRevocation(stillRevoked),
              stillRevoked.text.slice(0, 400));
  });
  await K.unset(realm, "certSignIn.requireRevocation");
  for (const one of [r.revoked, r.missing]) {
    await K.ok(rb + "/admin-api/users/remove-attribute", { user: o.alice,
      attribute: "stsCertificateBinding", value: serialBindingOf(one) },
      "took " + one.leaf.subject + " off alice");
  }
  await K.set(realm, "certSignIn.profiles", JSON.stringify([o.profile]));
  log.debug("Leaving revocationInDevelopment().");
}

// The sign-in screen's certificate offer for a connection presenting `tls`
// (#2089): an authorization request with no certificate, the screen's shell
// and its view over connections presenting it. `{ name }` when the
// certificate passed the profile, the binding and revocation.
async function screenOffer(rb, client, redirectUri, tls) {
  log.debug("Entering screenOffer().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const r = await tlsCall("GET", rb + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: client,
      redirect_uri: redirectUri, scope: "openid", state: "s", nonce: "n",
      code_challenge: nodeCrypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256" }).toString());
  const location = new URL(String(r.location || ""), rb).toString();
  const id = authnSignin.pendingIdOf(location);
  const shell = await tlsCall("GET", location, { tls: tls });
  const cookie = shell.setCookies.map(function (one) {
    return one.split(";")[0];
  }).join("; ");
  const view = await tlsCall("GET", rb + "/authn-api/pending/" +
    encodeURIComponent(id), { tls: tls, headers: { cookie: cookie } });
  log.debug("Leaving screenOffer().");
  return (view.json && view.json.view && view.json.view.certificate) ||
    { status: view.status, location: location };
}

// ---------------------------------------------------------------------------
// K. PRODUCT MODE (#2089): a second throwaway realm, created in product
// mode, where certSignIn.requireRevocation's default, `auto`, REQUIRES a
// verified status. The person, the profile and the three bindings are its
// own. A browser's certificate sign-in in product asks for a second factor
// too (rcbj, 2026-11-09), so a sign-in that passes every certificate check
// answers that, not a session: what is asserted is that the certificate
// was accepted as carol for the good chain (no refusal on revocation or as
// stored, and the sign-in screen offering to continue as her), and refused
// on revocation for the other two.
// ---------------------------------------------------------------------------
async function productMode(r, o) {
  log.debug("Entering productMode().");
  log.info("=== K. product mode ===");
  const realm = await K.realm("certprodk", "product");
  const rb = K.rb(realm);
  const carol = "cpk-" + K.STAMP;
  await K.ok(rb + "/admin-api/users/create", { username: carol,
    invent: false, credential: "none", attributes: { cn: carol,
      givenName: carol, sn: carol, mail: carol + "@cpk.example.test" } },
    "created " + carol);
  await K.set(realm, "certSignIn.profiles", coveringAll(o, r));
  for (const one of [o.card, r.revoked, r.missing]) {
    await K.ok(rb + "/admin-api/users/add-attribute", { user: carol,
      attribute: "stsCertificateBinding", value: serialBindingOf(one) },
      "bound " + one.leaf.subject + " to carol");
  }
  const good = await settled(rb + "/tls/sign-in", { tls: asTls(o.card) });
  const goodSession = (good.json && good.json.session) || {};
  const client = "cpkc-" + K.STAMP;
  await K.app(realm, client, { oauthClientId: [client],
    oauthRedirectUri: ["https://rp.cpk.example.test/cb"],
    oauthTokenEndpointAuthMethod: "none",
    oauthGrantType: ["authorization_code"], oauthAllowedScope: ["openid"] });
  const offer = await screenOffer(rb, client,
                                  "https://rp.cpk.example.test/cb",
                                  asTls(o.card));
  check("K1. in product, the chain whose CRL is served and empty is " +
        "accepted as carol: /tls/sign-in is neither refused on revocation " +
        "nor as stored (it asks for the second factor product requires), " +
        "and the sign-in screen offers to continue as carol", function () {
    assert.strictEqual(good.json && good.json.revocation &&
                       good.json.revocation.status, "good",
                       good.text.slice(0, 400));
    assert.ok(!goodSession.refusedOnRevocation &&
              !goodSession.refusedAsStored && !goodSession.refusedAsIdentity,
              good.text.slice(0, 400));
    assert.strictEqual(offer.name, carol, JSON.stringify(offer));
  });
  const missing = await settled(rb + "/tls/sign-in",
                                { tls: asTls(r.missing) });
  check("K2. in product, under the default auto, a leaf whose CRL cannot " +
        "be fetched signs nobody in: a verified status is required",
        function () {
    assert.ok(refusedOnRevocation(missing), missing.text.slice(0, 400));
  });
  const revoked = await settled(rb + "/tls/sign-in",
                                { tls: asTls(r.revoked) });
  check("K3. in product, a leaf its CA's CRL lists signs nobody in",
        function () {
    assert.ok(refusedOnRevocation(revoked), revoked.text.slice(0, 400));
  });
  log.debug("Leaving productMode().");
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
