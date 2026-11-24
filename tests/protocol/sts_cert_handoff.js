// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_cert_handoff.js
//
// ---------------------------------------------------------------------------
// THE CERTIFICATE SIGN-IN HANDOFF OVER A REAL SECOND LISTENER (#2081, the
// gap #2012 left: "the certificate handoff to a second listener needs a
// custom listener bound by the stack").
//
// `tests/certificate_binding.js` section 7 holds the handoff's logic over
// stand-ins for the session and the door; this holds what a running service
// does with it. A throwaway development realm gets a listener of its own on
// STS_TEST_REALM_LISTENER_PORT (8099, the stack's port for a realm listener,
// as `sts_realm_listener.js` uses it) whose `clientAuth` asks for a
// certificate, the `certificate-sign-in` hosted application mapped to it, a
// certificate sign-in profile covering an outside Root, and alice bound to
// the leaf by issuer and serial. Then, as a browser walks it:
//
//   A. the sign-in screen, reached from the authorization endpoint over the
//      main port with NO certificate, offers the handoff: a link to
//      `/authn/certificate/continue` on the realm's listener, and no name;
//   B. that link, followed on the listener with the browser's cookie and the
//      card's certificate, sends the browser back to the screen (303), which
//      now offers "continue as alice"; the act, on the main port and with
//      no certificate on its connection, starts her session, and the
//      authorization endpoint answers the client a code;
//   C. the refusals: the used link again (400, STS-TLS-0074); a live link
//      followed without the browser's cookie, or with another browser's
//      (403, STS-TLS-0075); a certificate bound to nobody presented at the
//      listener, which goes back to the screen that names nobody, says what
//      was refused and offers a fresh link, the act signing nobody in; and,
//      with `certSignIn.handoff` off, no link offered.
//
//   D. the deployment the requirements describe (#2089): with
//      `tls.mainPortDisableOptionalClientCertificate` on (a process setting,
//      put back at the end), a certificate offered on the main port never
//      arrives there, a password sign-in completes, and the card still signs
//      in through the handoff listener.
//
// NOT carried, and why: the browser's own certificate chooser and PIN prompt
// are the operating system's (rcbj tests those with a physical card).
//
// EXCLUSIVE: the realm listener's port is the stack's one port for a realm
// listener, which `sts_realm_listener.js` binds too, and section D changes
// how the main port answers every connection. In the `cells` mode a
// custom listener is refused (STS-CORE-0148), and that refusal is all this
// job asserts there.
//
// OWNED HERE (local: true): this repository's own sign-in screen.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const anchors = require("../tools/pep-credential.js");
const authnSignin = require("./authn_signin");
const K = require("./oauth_wire_kit.js").kit("sts_cert_handoff");
const log = K.log;

const FLOOR = 12;
const PORT = Number(process.env.STS_TEST_REALM_LISTENER_PORT || 8099);
const LISTENER = "hand" + K.STAMP.slice(-8);
const RP = "https://rp.handoff.example.test";
// THE SERVICE'S host name, not `K.HOST` (the runner's, which the service
// dials back): the listener must share the main port's host name for the
// sign-on cookie to reach it, or the mapping is refused (STS-CORE-0155).
const SERVICE_HOST = new URL(K.base).hostname;
const added = [];

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

// The `cells` mode, read as `cells_kit.js` reads it.
function cellsMode() {
  log.debug("Entering cellsMode().");
  const a = String(process.env.STS_TEST_CELL_A_URL || "").trim();
  const b = String(process.env.STS_TEST_CELL_B_URL || "").trim();
  log.debug("Leaving cellsMode(). " + !!(a && b));
  return !!(a && b);
}

// One request on its own connection, presenting `tls` (cert, key) where
// given; redirects are the caller's.
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
                  location: String(res.headers.location || ""),
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

// A call the listener or the truststore may not have applied yet: retried
// on a reset or a refused connection (tests/CLAUDE.md, #335).
async function settled(method, url, o) {
  log.debug("Entering settled().");
  let last = null;
  for (let i = 0; i < 20; i += 1) {
    try {
      const r = await tlsCall(method, url, o);
      log.debug("Leaving settled().");
      return r;
    } catch (e) {
      log.debug("Caught in settled(): " + ((e && e.message) || e));
      // Not bound yet, or a handshake refused while an anchor is applied.
      last = e;
      await K.sleep(500);
    }
  }
  throw last;
}

function spkiSha256(pem) {
  log.debug("Entering spkiSha256().");
  const spki = new nodeCrypto.X509Certificate(pem).publicKey
    .export({ type: "spki", format: "der" });
  log.debug("Leaving spkiSha256().");
  return nodeCrypto.createHash("sha256").update(spki).digest("hex");
}

// The authorization request a client sends: answers the screen's address
// and the pending sign-in's id.
async function authz(rb, client) {
  log.debug("Entering authz().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const r = await tlsCall("GET", rb + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: client,
      redirect_uri: RP + "/cb", scope: "openid", state: "s1", nonce: "n1",
      code_challenge: nodeCrypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256" }).toString());
  const location = new URL(r.location, rb).toString();
  log.debug("Leaving authz().");
  return { verifier: verifier, location: location,
           id: authnSignin.pendingIdOf(location) };
}

// The screen's shell, then its view, on a connection presenting nothing:
// `{ view, csrf, cookie }`. `cookie` is the browser's, when it has one.
async function screen(rb, at, cookie) {
  log.debug("Entering screen().");
  let jar = cookie || "";
  if (!jar) {
    const shell = await tlsCall("GET", at.location);
    jar = shell.setCookies.map(function (one) {
      return one.split(";")[0];
    }).join("; ");
  }
  const v = await tlsCall("GET", rb + "/authn-api/pending/" +
    encodeURIComponent(at.id), { headers: { cookie: jar } });
  log.debug("Leaving screen().");
  return { status: v.status, view: (v.json && v.json.view) || {},
           csrf: (v.json && v.json.csrf) || "", cookie: jar, text: v.text };
}

function act(rb, at, opened) {
  log.debug("Entering act().");
  log.debug("Leaving act().");
  return tlsCall("POST", rb + "/authn-api/pending/" +
    encodeURIComponent(at.id) + "/certificate", { body: {},
    headers: { cookie: opened.cookie, origin: new URL(rb).origin,
               "x-csrf-token": opened.csrf } });
}

async function listenerApi(rb, what, value) {
  log.debug("Entering listenerApi(). " + what);
  const r = await K.send(rb + "/admin-api/listeners/" + what,
                         { json: { value: value } });
  log.debug("Leaving listenerApi(). " + r.status);
  return r;
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("handoff");
  const rb = K.rb(realm);
  if (cellsMode()) {
    const refused = await listenerApi(rb, "set-listeners", [{ id: LISTENER,
      port: PORT, publicBaseUrl: "https://" + SERVICE_HOST + ":" + PORT }]);
    check("in the cells mode a custom listener is refused, so there is no " +
          "handoff to test", function () {
      assert.strictEqual(refused.status, 400, refused.text.slice(0, 300));
    });
    log.debug("Leaving test(). Cells.");
    return false;
  }
  await K.set(realm, "security.rateLimitPerAddress", 10000);
  const alice = "cha-" + K.STAMP;
  await K.ok(rb + "/admin-api/users/create", { username: alice,
    invent: false, credential: "none", attributes: { cn: alice,
      givenName: alice, sn: alice, mail: alice + "@ch.example.test" } },
    "created " + alice);
  const client = "cho-" + K.STAMP;
  await K.app(realm, client, { oauthClientId: [client],
    oauthRedirectUri: [RP + "/cb"], oauthTokenEndpointAuthMethod: "none",
    oauthGrantType: ["authorization_code"], oauthAllowedScope: ["openid"] });
  const card = await anchors.mint({ subject: "CN=SMITH.JANE." + K.STAMP +
                                    ",O=handoff authority",
                                    rootSubject: "CN=handoff Root " +
                                      K.STAMP });
  const installed = await anchors.trustRecorded(K.base, card.anchorPem,
                                                added);
  assert.ok(installed.ok, "the outside Root was not admitted: " +
            String(installed.why || installed.status));
  const tls = { cert: card.certPem, key: card.keyPem };
  const stranger = await anchors.reissue(card, {});
  const strangerTls = { cert: stranger.certPem, key: stranger.keyPem };
  await K.set(realm, "certSignIn.profiles", JSON.stringify([{
    id: "handoff", issuers: [spkiSha256(card.anchorPem)],
    keyUsage: ["digitalSignature"], extendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
    bindings: ["issuer-serial"] }]));
  await K.ok(rb + "/admin-api/users/add-attribute", { user: alice,
    attribute: "stsCertificateBinding", value: "issuer-serial:" +
      spkiSha256(card.issuing.pem) + ":" +
      String(card.leaf.serialHex).toLowerCase() },
    "bound the leaf to " + alice);

  const ownBase = "https://" + SERVICE_HOST + ":" + PORT;
  const defined = await listenerApi(rb, "set-listeners", [{ id: LISTENER,
    port: PORT, publicBaseUrl: ownBase, clientAuth: "optional" }]);
  assert.strictEqual(defined.status, 200, defined.text.slice(0, 400));
  const mapped = await listenerApi(rb, "set-applications", {
    "certificate-sign-in": { listeners: [LISTENER] } });
  assert.strictEqual(mapped.status, 200, mapped.text.slice(0, 400));
  await K.set(realm, "certSignIn.handoff", true);
  log.debug("Leaving test(). Set up.");
  return { realm: realm, rb: rb, alice: alice, client: client, tls: tls,
           strangerTls: strangerTls, ownBase: ownBase };
}

async function walk(s) {
  log.debug("Entering walk().");
  log.info("=== A. the screen offers the handoff ===");
  const at = await authz(s.rb, s.client);
  const offered = await screen(s.rb, at, "");
  const href = String((offered.view.certificate || {}).handoff || "");
  check("A1. with no certificate on the screen's connection, the screen " +
        "offers a link to /authn/certificate/continue on the realm's own " +
        "listener, and no name", function () {
    assert.strictEqual(offered.status, 200, offered.text.slice(0, 300));
    assert.ok(href.indexOf(s.ownBase + "/realm/" + s.realm +
                           "/authn/certificate/continue?h=") === 0 ||
              href.indexOf(s.ownBase + "/authn/certificate/continue?h=") ===
              0, JSON.stringify(offered.view.certificate));
    assert.ok(!offered.view.certificate.name,
              JSON.stringify(offered.view.certificate));
  });

  log.info("=== B. the listener, then the screen ===");
  const there = await settled("GET", href, { tls: s.tls,
    headers: { cookie: offered.cookie } });
  check("B1. the link on the listener, with the browser's cookie and the " +
        "card's certificate, sends the browser back to this sign-in's " +
        "screen (303)", function () {
    assert.strictEqual(there.status, 303, there.status + " " +
                       there.text.slice(0, 300));
    assert.ok(/\/authn\/login\?authn=/.test(there.location) &&
              there.location.indexOf(encodeURIComponent(at.id)) >= 0,
              there.location);
  });
  const back = await screen(s.rb, at, offered.cookie);
  check("B2. back on the main port, with no certificate on its connection, " +
        "the screen offers to continue as alice", function () {
    assert.strictEqual((back.view.certificate || {}).name, s.alice,
                       JSON.stringify(back.view.certificate));
  });
  const done = await act(s.rb, at, back);
  check("B3. the act starts alice's session: next redirect, a session " +
        "cookie", function () {
    assert.strictEqual(done.status, 200, done.text.slice(0, 300));
    assert.strictEqual(done.json && done.json.next, "redirect", done.text);
    assert.ok(done.setCookies.some(function (c) {
      return /^sts_session=[^;]+/.test(c);
    }), JSON.stringify(done.setCookies));
  });
  const cookie = authnSignin.foldCookies(back.cookie, done.setCookies);
  const answered = await tlsCall("GET", new URL(done.json.location, s.rb)
    .toString(), { headers: { cookie: cookie } });
  const code = new URL(answered.location || "x:", s.rb).searchParams
    .get("code");
  check("B4. and the authorization endpoint answers the client a code",
        function () {
    assert.ok(code && answered.location.indexOf(RP + "/cb") === 0,
              answered.status + " " + answered.location);
  });

  log.info("=== C. the refusals ===");
  const again = await settled("GET", href, { tls: s.tls,
    headers: { cookie: offered.cookie } });
  check("C1. the used link again is refused 400, and no code is sent",
        function () {
    assert.strictEqual(again.status, 400, again.text.slice(0, 300));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(again.text), again.text);
  });
  const at2 = await authz(s.rb, s.client);
  const fresh = await screen(s.rb, at2, "");
  const href2 = String((fresh.view.certificate || {}).handoff || "");
  const bare = await settled("GET", href2, { tls: s.tls });
  const other = await screen(s.rb, await authz(s.rb, s.client), "");
  const foreign = await settled("GET", href2, { tls: s.tls,
    headers: { cookie: other.cookie } });
  check("C2. a live link followed without the browser's cookie, or with " +
        "another browser's, is refused 403", function () {
    assert.ok(href2, JSON.stringify(fresh.view.certificate));
    assert.strictEqual(bare.status, 403, bare.text.slice(0, 300));
    assert.strictEqual(foreign.status, 403, foreign.text.slice(0, 300));
  });
  // THE SCREEN SAYS WHY AND OFFERS THE CARD AGAIN (`authn.ts`'s
  // `certificateOption()`): the listener's refusal is kept on the handoff,
  // drawn as `refused` beside a fresh link, so a person who chose the wrong
  // certificate can choose another. The act, with no certificate handed off
  // and none on its own connection, signs nobody in (STS-AUTHN-0463).
  const unbound = await settled("GET", href2, { tls: s.strangerTls,
    headers: { cookie: fresh.cookie } });
  const after = await screen(s.rb, at2, fresh.cookie);
  const again2 = String((after.view.certificate || {}).handoff || "");
  const refused = await act(s.rb, at2, after);
  check("C3. a certificate bound to nobody, presented at the listener, " +
        "goes back to the screen, which names no one, says what was " +
        "refused and offers a fresh link; the act signs nobody in",
        function () {
    assert.strictEqual(unbound.status, 303, unbound.text.slice(0, 300));
    const offer = after.view.certificate || {};
    assert.ok(!offer.name, JSON.stringify(offer));
    assert.ok(String(offer.refused || "").length > 0, JSON.stringify(offer));
    assert.ok(again2 && again2 !== href2, JSON.stringify(offer));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(JSON.stringify(offer)),
              JSON.stringify(offer));
    assert.strictEqual(refused.status, 400, refused.text.slice(0, 300));
    assert.ok(!refused.setCookies.some(function (c) {
      return /^sts_session=[^;]+/.test(c);
    }), JSON.stringify(refused.setCookies));
  });
  await K.set(s.realm, "certSignIn.handoff", false);
  const off = await screen(s.rb, await authz(s.rb, s.client), "");
  check("C4. with certSignIn.handoff off the screen offers no link",
        function () {
    assert.ok(!(off.view.certificate && off.view.certificate.handoff),
              JSON.stringify(off.view.certificate));
  });
  log.debug("Leaving walk().");
}

// Whether a certificate offered on a connection to the MAIN port arrived:
// the management API's description of that very connection, asked over it
// (`sts_listener_tls_policy.js`'s `presented()`). Asked again for up to ten
// seconds until `wanted`, because the setting is applied per process and a
// cluster's other node hears the write a moment later.
async function presentedOnMain(tls, wanted) {
  log.debug("Entering presentedOnMain().");
  const deadline = Date.now() + 10000;
  let view = {};
  do {
    const r = await settled("GET", K.base + "/admin-api/tls-connection",
                            { tls: tls });
    assert.strictEqual(r.status, 200, "GET /admin-api/tls-connection: " +
                       r.status + " " + r.text.slice(0, 200));
    view = (r.json && r.json.clientCertificate) || {};
    if (view.presented === wanted) {
      break;
    }
    await K.sleep(250);
  } while (Date.now() < deadline);
  log.debug("Leaving presentedOnMain(). " + view.presented);
  return view;
}

// ---------------------------------------------------------------------------
// D. THE DEPLOYMENT THE REQUIREMENTS DESCRIBE (#2089): the main port asks
// no connection for a certificate
// (`tls.mainPortDisableOptionalClientCertificate`, a process setting, put
// back in `guarded()`), so a browser with a card in
// the reader is never prompted while it signs in another way, and the card
// is asked for on the handoff listener alone:
//
//   D1. a certificate offered on the main port never arrives there (no
//       CertificateRequest is sent);
//   D2. a password sign-in completes, and the client gets its code;
//   D3. the card still signs alice in through the handoff listener.
// ---------------------------------------------------------------------------
async function noPromptOnMain(s) {
  log.debug("Entering noPromptOnMain().");
  log.info("=== D. the main port asks for no certificate ===");
  const before = await presentedOnMain(s.tls, true);
  await K.setProcess("tls.mainPortDisableOptionalClientCertificate", true);
  s.mainPortTouched = true;
  const after = await presentedOnMain(s.tls, false);
  check("D1. with tls.mainPortDisableOptionalClientCertificate on, a " +
        "certificate offered on the main port never arrives: no " +
        "CertificateRequest, so no browser prompt", function () {
    assert.strictEqual(before.presented, true, JSON.stringify(before));
    assert.strictEqual(after.presented, false, JSON.stringify(after));
  });
  const who = "chp-" + K.STAMP;
  const password = "Pw-" + nodeCrypto.randomBytes(9).toString("base64url");
  await K.person(s.realm, who, password);
  const b = K.browser();
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const first = await b.go(s.rb + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: s.client,
      redirect_uri: RP + "/cb", scope: "openid", state: "s2", nonce: "n2",
      code_challenge: nodeCrypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256" }).toString());
  const signedIn = await K.signIn(s.realm, b, first, who, password);
  check("D2. a password sign-in completes on the main port, and the client " +
        "gets its code", function () {
    assert.ok((signedIn.status === 302 || signedIn.status === 303) &&
              String(signedIn.location || "").indexOf(RP + "/cb?") === 0 &&
              /[?&]code=/.test(String(signedIn.location)),
              K.shown(signedIn));
  });
  await K.set(s.realm, "certSignIn.handoff", true);
  const at = await authz(s.rb, s.client);
  const offered = await screen(s.rb, at, "");
  const href = String((offered.view.certificate || {}).handoff || "");
  const there = href ? await settled("GET", href, { tls: s.tls,
    headers: { cookie: offered.cookie } }) : { status: 0, text: "" };
  const back = await screen(s.rb, at, offered.cookie);
  const done = await act(s.rb, at, back);
  check("D3. and the card still signs alice in through the handoff " +
        "listener", function () {
    assert.ok(href, JSON.stringify(offered.view.certificate));
    assert.strictEqual(there.status, 303, there.text.slice(0, 300));
    assert.strictEqual((back.view.certificate || {}).name, s.alice,
                       JSON.stringify(back.view.certificate));
    assert.strictEqual(done.json && done.json.next, "redirect",
                       done.text.slice(0, 300));
  });
  log.debug("Leaving noPromptOnMain().");
}

async function guarded() {
  log.debug("Entering guarded().");
  let failure = null;
  let s = null;
  try {
    s = await test();
    if (s) {
      await walk(s);
      await noPromptOnMain(s);
    }
  } catch (e) {
    log.debug("Caught in guarded(): " + ((e && e.message) || e));
    // Rethrown after the listener and the anchor are removed.
    failure = e;
  }
  if (s && s.mainPortTouched) {
    const reset = await K.send(K.base + "/admin-api/config/reset", { json: {
      key: "tls.mainPortDisableOptionalClientCertificate" } });
    if (reset.status !== 200) {
      log.warn("Could not reset the main port's certificate request: " +
               reset.status + " " + reset.text.slice(0, 200));
    }
  }
  if (s) {
    // The mapping first: a listener a mapping names cannot be removed.
    const unmapped = await listenerApi(s.rb, "set-applications", "");
    const unbound = await listenerApi(s.rb, "set-listeners", "");
    if (unmapped.status !== 200 || unbound.status !== 200) {
      log.warn("Could not remove the realm listener: " + unmapped.status +
               " " + unbound.status + " " + unbound.text.slice(0, 200));
    }
  }
  await anchors.settleAnchors(K.base, added, failure);
  log.debug("Leaving guarded().");
}

K.main(guarded, FLOOR);
