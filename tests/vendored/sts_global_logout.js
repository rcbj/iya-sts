// ===========================================================================
// ONE PERSON, EVERY PROTOCOL THAT SIGNS ONE IN, AND ONE GLOBAL SIGN-OUT.
//
// **THE QUESTION THIS FILE ASKS IS THE ONLY ONE A SIGN-OUT REALLY HAS:** after
// it, is there anything left? Every other job in this suite drives one family
// and proves that family works. This one drives ten at once, on purpose, and
// then tries to find something that survived.
//
// It is the test that could not be written until 2026-09-05, and three things
// had to be built before it could be:
//
//   1. **WS-TRUST HAD TO START A SESSION.** It issued assertions and called
//      `startSession()` zero times, so an assertion minted five minutes ago
//      belonged to nobody who was signed in.
//   2. **A CLIENT CERTIFICATE HAD TO BE A LOGIN.** `tls/CLAUDE.md` argued at
//      length that it was not. What that cost was a live way in that nothing
//      on `/admin/sessions` could see and no sign-out could end.
//   3. **AN ASSERTION AND A TICKET HAD TO BE REVOCABLE.** Not honoured
//      anywhere — that is impossible and is asserted below as impossible —
//      but marked, so that this service has a POSITION on what it issued.
//
// ---------------------------------------------------------------------------
// TWO SCENARIOS, AND THE SECOND IS NOT THE FIRST AGAIN.
//
//   A. ONE APPLICATION that every protocol authenticates against. This is the
//      single-sign-on shape: one relying party a person reaches ten ways.
//   B. ONE APPLICATION PER PROTOCOL. This is the portfolio shape: ten relying
//      parties, one person, one sign-out.
//
// They can fail differently and that is why both are here. A sign-out keyed
// accidentally on the APPLICATION rather than on the IDENTITY passes A
// completely and fails B on nine of ten rows; one that swept by identity but
// collected rows per application would do the reverse. Neither would be found
// by running either scenario alone.
//
// ---------------------------------------------------------------------------
// WHY THERE IS NO BROWSER HERE, WHICH IS THE FIRST THING TO CHECK.
//
// Every sign-in below is a form POST and a redirect, and **not one of these
// pages runs a line of JavaScript** — `app.js` sets `script-src 'none'` for
// the whole service and the six exceptions are all autopost forms with a real
// submit button. So a cookie jar and `fetch` drive them exactly as a browser
// would, deterministically, in about a second, with no driver to install and
// no headless flake.
//
// Selenium is still right where the DOM is the thing under test — that is
// `sts_admin_console.js` and `sts_xacml_editor.js`, and both stay — and the
// debugger's own suite uses it for its client UI. It would buy nothing here:
// what is under test is which SESSIONS exist and whether a sign-out ends them,
// and neither of those is visible in a rendered page.
//
// ---------------------------------------------------------------------------
// IT RUNS IN THE DEFAULT REALM, WHICH EVERY OTHER JOB LIKE IT AVOIDS.
//
// That is forced and it is worth knowing why rather than reading it as
// carelessness. **The TLS listeners and the Kerberos KDC are SHARED ACROSS
// TRUST REALMS** — the root CLAUDE.md lists them among the three socket
// families with no path to put a realm segment in and no name inside the
// protocol to put one in either. A throwaway realm therefore cannot have an
// X.509 sign-in or a TGT of its own, and two of the ten protocols would drop
// out of a test whose whole point is that none of them does.
//
// What makes that safe is that **a global sign-out is keyed on an IDENTITY**.
// The username here is unique per run, so the sweep cannot reach any other
// job's session however many are open beside it — which is the same property
// a throwaway realm would have bought, obtained a different way.
//
// ---------------------------------------------------------------------------
// WHAT MUST DIE, AND WHAT CANNOT — THE TWO LISTS THIS FILE KEEPS APART.
//
// MUST DIE, and any survivor fails the test: every browser sign-on session,
// every access token, ID Token and refresh token, the bound LDAP connection,
// and the Kerberos TGT's ability to obtain anything further.
//
// CANNOT DIE, and a test that demanded it would be permanently red: an
// already-issued SAML assertion still verifies, and an already-issued Kerberos
// service ticket still decrypts with the key its service holds. Nothing
// consults this service when either is presented and nothing can be made to.
// **So this file asserts that they are DISOWNED and that they still WORK**,
// which is the honest pair — and it asserts the second as loudly as the first,
// because a future change that quietly pretended to recall one would be a mock
// teaching a client something false about every identity provider it will meet.
// ===========================================================================

"use strict";

const assert = require("assert");
const zlib = require("zlib");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const krb5 = require("./krb5_drive.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_global_logout",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// The Kerberos realm the KDC serves. Shared across trust realms, like the
// socket it answers on.
const KRB_REALM = process.env.KRB5_REALM || "EXAMPLE.COM";
// Every seeded principal here has this one password — see kerberos/CLAUDE.md
// on why the KDC's permissiveness lives in its account policy.
const KRB_PASSWORD = "password!";

var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.debug("check passed: " + what);
}

function api(path) { return base + "/admin-api" + path; }

// ---------------------------------------------------------------------------
// A COOKIE JAR PER SIGN-IN, which is the whole reason this file can say
// anything about a GLOBAL sign-out.
//
// Five of these protocols share one browser session by design — that IS single
// sign-on — so driving them from one jar would produce ONE session and prove
// only that a sign-out can end one session. A jar each produces one session
// each, so the sweep has to be per-identity to pass.
// ---------------------------------------------------------------------------
function jar() {
  const store = {};
  return {
    header: function () {
      return Object.keys(store).map(function (k) {
        return k + "=" + store[k];
      }).join("; ");
    },
    take: function (res) {
      (res.headers.getSetCookie ? res.headers.getSetCookie() : []).forEach(
        function (line) {
          const pair = line.split(";")[0];
          const i = pair.indexOf("=");
          store[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
        });
    },
    has: function () { return Object.keys(store).length > 0; },
    value: function () { return store.sts_mock_session || ""; }
  };
}

// One request, one body read. The double-read is the trap a hand-rolled driver
// falls into every time, so it is closed here rather than at each call site.
async function hop(cookies, url, options) {
  const o = Object.assign({ redirect: "manual", headers: {} }, options || {});
  if (cookies && cookies.has()) o.headers.cookie = cookies.header();
  const r = await fetch(url, o);
  if (cookies) cookies.take(r);
  const body = r.status >= 300 && r.status < 400 ? "" : await r.text();
  return { status: r.status, headers: r.headers, body: body, url: url };
}

// Follow redirects until the browser would LEAVE this service, which is where
// every one of these flows ends: at the relying party's own address, carrying
// whatever the protocol hands over.
async function follow(cookies, url, options) {
  let r = await hop(cookies, url, options);
  for (let n = 0; r.status >= 300 && r.status < 400 && n < 12; n += 1) {
    const loc = r.headers.get("location");
    if (!loc) break;
    const next = new URL(loc, r.url).toString();
    if (next.indexOf(base) !== 0) return { r: r, landed: next };
    r = await hop(cookies, next);
  }
  return { r: r, landed: r.url };
}

function hiddenFields(html) {
  const body = new URLSearchParams();
  [...html.matchAll(/<input[^>]*type="hidden"[^>]*>/g)].forEach(function (m) {
    const n = m[0].match(/name="([^"]+)"/);
    const v = m[0].match(/value="([^"]*)"/);
    if (n) body.set(n[1], v ? v[1] : "");
  });
  return body;
}

// THE SIGN-IN SCREEN AND THE CONSENT SCREEN, answered wherever they appear.
// Both are ordinary forms; the loop is bounded because a flow that kept
// redrawing one would otherwise hang rather than fail.
async function throughTheScreens(cookies, started, username) {
  let r = started.r;
  let landed = started.landed;
  for (let step = 0; step < 4 && r.status === 200; step += 1) {
    if (/name="authn_id"/.test(r.body)) {
      const b = hiddenFields(r.body);
      b.set("username", username);
      b.set("password", "any-password-this-service-checks-none");
      b.set("action", "login");
      ({ r, landed } = await follow(cookies, base + "/authn/login", {
        method: "POST", body: b.toString(),
        headers: { "content-type": "application/x-www-form-urlencoded" } }));
    } else if (/\/oauth2\/consent/.test(r.body)) {
      const b = hiddenFields(r.body);
      b.set("action", "allow");
      b.set("decision", "allow");
      ({ r, landed } = await follow(cookies, base + "/oauth2/consent", {
        method: "POST", body: b.toString(),
        headers: { "content-type": "application/x-www-form-urlencoded" } }));
    } else {
      break;
    }
  }
  return { r: r, landed: landed };
}

// ---------------------------------------------------------------------------
// THE TEN SIGN-INS. Each returns what the assertions afterwards need to name
// what it made — a session cookie, a token, an artifact — and each takes the
// application to authenticate against, which is the ONLY difference between
// the two scenarios.
// ---------------------------------------------------------------------------

async function oidcAuthorizationCode(username, application) {
  const cookies = jar();
  const started = await follow(cookies, base + "/oauth2/authorize" +
    "?response_type=code&scope=" + encodeURIComponent("openid profile") +
    "&client_id=" + encodeURIComponent(application) +
    "&redirect_uri=" + encodeURIComponent("http://" + application + ".example.com/cb") +
    "&nonce=n-" + Date.now() + "&state=st");
  const done = await throughTheScreens(cookies, started, username);
  const code = new URL(done.landed).searchParams.get("code");
  assert.ok(code, "the OIDC authorization code flow should end at the client's " +
    "redirect URI carrying a code; it landed on " + done.landed.slice(0, 160));
  const tok = await fetch(base + "/oauth2/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code: code, client_id: application,
      redirect_uri: "http://" + application + ".example.com/cb" }).toString() });
  const body = await tok.json();
  assert.strictEqual(tok.status, 200,
    "the code should redeem; the token endpoint answered " + tok.status + " " +
    JSON.stringify(body).slice(0, 200));
  return { protocol: "OIDC authorization code", cookies: cookies,
           accessToken: body.access_token, refreshToken: body.refresh_token,
           idToken: body.id_token };
}

async function oauth2AuthorizationCode(username, application) {
  // NO `openid` SCOPE, which is what makes this a different protocol from the
  // one above rather than the same flow twice: plain OAuth 2.0 issues no ID
  // Token, so the set it produces is a different shape.
  const cookies = jar();
  const started = await follow(cookies, base + "/oauth2/authorize" +
    "?response_type=code&scope=" + encodeURIComponent("api") +
    "&client_id=" + encodeURIComponent(application) +
    "&redirect_uri=" + encodeURIComponent("http://" + application + ".example.com/cb") +
    "&state=st");
  const done = await throughTheScreens(cookies, started, username);
  const code = new URL(done.landed).searchParams.get("code");
  assert.ok(code, "the OAuth 2.0 authorization code flow should end carrying a " +
    "code; it landed on " + done.landed.slice(0, 160));
  const tok = await fetch(base + "/oauth2/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code: code, client_id: application,
      redirect_uri: "http://" + application + ".example.com/cb" }).toString() });
  const body = await tok.json();
  assert.strictEqual(tok.status, 200, "the code should redeem; got " + tok.status);
  return { protocol: "OAuth 2.0 authorization code", cookies: cookies,
           accessToken: body.access_token, refreshToken: body.refresh_token };
}

// A SAML 2.0 AuthnRequest on the HTTP Redirect binding: DEFLATE with no
// zlib header (raw), then base64, then URL-encode. Getting the deflate wrong
// is the classic SAML mistake and it fails as "the request does not parse",
// which names neither the compression nor the binding.
function authnRequest(application) {
  const xml = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
    'ID="_gl' + Date.now() + '" Version="2.0" ' +
    'IssueInstant="' + new Date().toISOString() + '" ' +
    'AssertionConsumerServiceURL="http://' + application + '.example.com/acs" ' +
    'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">' +
    '<saml:Issuer>' + application + '</saml:Issuer>' +
    '</samlp:AuthnRequest>';
  return zlib.deflateRawSync(Buffer.from(xml, "utf8")).toString("base64");
}

async function saml2Sso(username, application) {
  const cookies = jar();
  const started = await follow(cookies, base + "/saml2/sso?SAMLRequest=" +
    encodeURIComponent(authnRequest(application)) + "&RelayState=gl");
  const done = await throughTheScreens(cookies, started, username);
  assert.ok(/SAMLResponse/.test(done.r.body || ""),
    "SAML 2.0 Web Browser SSO should end on the self-submitting POST form " +
    "carrying a SAMLResponse; it answered " + done.r.status + " with " +
    String(done.r.body || "").replace(/\s+/g, " ").slice(0, 200));
  return { protocol: "SAML 2.0", cookies: cookies };
}

async function saml11Sso(username, application) {
  // SAML 1.1 HAS NO REQUEST MESSAGE — the inter-site transfer service is
  // entered with a TARGET and the relying party is named by `providerId`.
  // That is the single biggest difference from the profile above and is why
  // this service implements the two separately.
  const cookies = jar();
  const started = await follow(cookies, base + "/saml11/sso" +
    "?TARGET=" + encodeURIComponent("http://" + application + ".example.com/target") +
    "&providerId=" + encodeURIComponent(application));
  const done = await throughTheScreens(cookies, started, username);
  assert.ok(/SAMLResponse/.test(done.r.body || ""),
    "the SAML 1.1 Browser/POST profile should end on the self-submitting form " +
    "carrying a SAMLResponse; it answered " + done.r.status + " with " +
    String(done.r.body || "").replace(/\s+/g, " ").slice(0, 200));
  return { protocol: "SAML 1.1", cookies: cookies };
}

async function wsFederation(username, application) {
  const cookies = jar();
  const started = await follow(cookies, base + "/wsfed?wa=wsignin1.0&wtrealm=" +
    encodeURIComponent(application));
  const done = await throughTheScreens(cookies, started, username);
  assert.ok(/wresult|RequestSecurityTokenResponse/.test(done.r.body || ""),
    "the WS-Federation passive requestor profile should end on the form " +
    "carrying wresult; it answered " + done.r.status + " with " +
    String(done.r.body || "").replace(/\s+/g, " ").slice(0, 200));
  return { protocol: "WS-Federation", cookies: cookies };
}

async function wsTrust(username, application) {
  // THE SESSION HERE IS NEW (2026-09-05). Before it, this exchange issued an
  // assertion and signed nobody in, so the credential belonged to nobody a
  // sign-out could find.
  const cookies = jar();
  const rst = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
    '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/' +
    '2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:UsernameToken><wsse:Username>' + username + '</wsse:Username>' +
    '<wsse:Password>whatever</wsse:Password></wsse:UsernameToken>' +
    '</wsse:Security></soap:Header><soap:Body>' +
    '<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/' +
    'ws-trust/200512"><wst:RequestType>http://docs.oasis-open.org/ws-sx/' +
    'ws-trust/200512/Issue</wst:RequestType>' +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">' +
    '<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">' +
    '<wsa:Address>' + application + '</wsa:Address></wsa:EndpointReference>' +
    '</wsp:AppliesTo></wst:RequestSecurityToken></soap:Body></soap:Envelope>';
  const r = await hop(cookies, base + "/sts", {
    method: "POST", headers: { "content-type": "application/soap+xml" },
    body: rst });
  assert.strictEqual(r.status, 200,
    "the WS-Trust endpoint should issue; it answered " + r.status + " " +
    String(r.body).slice(0, 200));
  assert.ok(/Assertion/.test(r.body), "and the RSTR should carry an assertion.");
  return { protocol: "WS-Trust", cookies: cookies };
}

async function kerberos(username) {
  const got = await krb5.getTgt(base, KRB_REALM, username, KRB_PASSWORD);
  assert.ok(got.ok, "the KDC should issue a TGT for " + username);
  return { protocol: "Kerberos", tgt: true };
}

// ---------------------------------------------------------------------------
// X.509 CLIENT CERTIFICATE. A CA and a leaf are made here rather than
// committed, for the reason every key in this repository is generated on
// start: a certificate in a repository is a private key in a repository.
//
// THE COMMON NAME IS THE USERNAME and that is the whole point of the section:
// `tls_server.js` signs in the CN, so a certificate naming this person signs in
// the SAME person the other nine protocols did — one identity, ten doors —
// which is what makes a single global sign-out the right question to ask.
// ---------------------------------------------------------------------------
function makeCertificate(username) {
  const forge = require("node-forge");
  const caKeys = forge.pki.rsa.generateKeyPair(2048);
  const ca = forge.pki.createCertificate();
  ca.publicKey = caKeys.publicKey;
  ca.serialNumber = "01";
  ca.validity.notBefore = new Date(Date.now() - 60000);
  ca.validity.notAfter = new Date(Date.now() + 3600 * 1000);
  const caName = [{ name: "commonName", value: "global-logout test CA" }];
  ca.setSubject(caName);
  ca.setIssuer(caName);
  ca.setExtensions([{ name: "basicConstraints", cA: true }]);
  ca.sign(caKeys.privateKey, forge.md.sha256.create());

  const leafKeys = forge.pki.rsa.generateKeyPair(2048);
  const leaf = forge.pki.createCertificate();
  leaf.publicKey = leafKeys.publicKey;
  leaf.serialNumber = "02";
  leaf.validity.notBefore = new Date(Date.now() - 60000);
  leaf.validity.notAfter = new Date(Date.now() + 3600 * 1000);
  leaf.setSubject([{ name: "commonName", value: username },
                   { name: "organizationName", value: "mock-sts global logout test" }]);
  leaf.setIssuer(caName);
  leaf.setExtensions([{ name: "basicConstraints", cA: false },
                      { name: "extKeyUsage", clientAuth: true }]);
  leaf.sign(caKeys.privateKey, forge.md.sha256.create());

  return { caPem: forge.pki.certificateToPem(ca),
           certPem: forge.pki.certificateToPem(leaf),
           keyPem: forge.pki.privateKeyToPem(leafKeys.privateKey) };
}

async function x509(username) {
  const https = require("https");
  const pki = makeCertificate(username);

  // The anchor goes in over the MAIN port, which is what `/tls/trust` is for.
  // As TEXT: the endpoint takes a PEM body directly, and a JSON envelope round
  // trip escapes the newlines out of it — which it then accepts as a "PEM"
  // that no handshake can verify against.
  const installed = await fetch(base + "/tls/trust", {
    method: "POST", headers: { "content-type": "text/plain" },
    body: pki.caPem });
  assert.strictEqual(installed.status, 200,
    "the test CA should be accepted at /tls/trust; it answered " +
    installed.status);

  const port = Number(process.env.STS_MTLS_PORT || 9443);
  const host = new URL(base).hostname;
  // **THE TRUSTSTORE IS APPLIED WITH `setSecureContext()` AND THE NEXT
  // HANDSHAKE IS JUDGED AGAINST IT** — which is not quite the same as "the
  // anchor is usable the instant the POST returns". A connection opened in the
  // same tick as the install is refused during the handshake, and node reports
  // that as a bare `socket hang up` with nothing in it about certificates. So
  // the connection is retried rather than the anchor being assumed live, and
  // the assertion below is then about the SIGN-IN rather than about a race.
  const connect = function () {
    return new Promise(function (resolve, reject) {
      const req = https.request({
        host: host, port: port, path: "/", method: "GET",
        cert: pki.certPem, key: pki.keyPem,
        // The SERVER's certificate is self-signed and regenerated on every
        // start — that is this service's design, not a misconfiguration — so
        // it is not verified here. What is under test is the CLIENT
        // certificate.
        rejectUnauthorized: false
      }, function (res) {
        let body = "";
        res.on("data", function (d) { body += d; });
        res.on("end", function () {
          resolve({ status: res.statusCode,
                    cookie: (res.headers["set-cookie"] || []).join("; ") });
        });
      });
      req.on("error", reject);
      req.end();
    });
  };
  let reply = null;
  let lastError = null;
  for (let attempt = 0; attempt < 4 && !reply; attempt += 1) {
    try {
      reply = await connect();
    } catch (e) {
      lastError = e;
      await new Promise(function (r) { setTimeout(r, 250); });
    }
  }
  assert.ok(reply, "the mutual-TLS listener refused every attempt: " +
    (lastError && lastError.message) + ". That listener requires a client " +
    "certificate that verifies against an anchor at /tls/trust, and this " +
    "test installed one — so a refusal here is the anchor not taking rather " +
    "than the certificate being wrong.");
  assert.strictEqual(reply.status, 200,
    "the mutual-TLS listener should answer a connection carrying a verified " +
    "certificate; it answered " + reply.status);
  const match = /sts_mock_session=([A-Za-z0-9_-]+)/.exec(reply.cookie || "");
  assert.ok(match,
    "A VERIFIED CLIENT CERTIFICATE MUST START A SESSION (2026-09-05). The " +
    "listener answered 200 and set no session cookie, so either the sign-in " +
    "did not happen or the cookie was written on a response object that " +
    "could not carry it — which is exactly the half-state setCookieHeader() " +
    "was added to close. Set-Cookie was: " + (reply.cookie || "(none)"));
  return { protocol: "X.509 client certificate", sessionId: match[1] };
}

// ---------------------------------------------------------------------------
// AN LDAP BIND. The session here is the CONNECTION — RFC 4511 section 4.2: a
// Bind sets the authorization state of a connection, and it lasts until the
// next Bind, an Unbind, or the socket closing. So "ending it" means the server
// closing the socket, which is what the assertion after the sign-out watches
// for.
// ---------------------------------------------------------------------------
function ldapBind(username) {
  return new Promise(function (resolve, reject) {
    let ldap;
    try {
      ldap = require("ldapjs");
    } catch (e) {
      reject(new Error("ldapjs is not resolvable from this job: " + e.message));
      return;
    }
    const port = Number(process.env.STS_LDAP_PORT || 389);
    const host = new URL(base).hostname;
    const client = ldap.createClient({ url: "ldap://" + host + ":" + port,
                                       reconnect: false });
    let closed = false;
    // An error handler is not optional: without one, a socket the server
    // closes throws out of the client and takes the job down instead of
    // failing an assertion.
    client.on("error", function () {});
    client.on("close", function () { closed = true; });
    const dn = "uid=" + username + ",ou=users," +
               (process.env.STS_LDAP_BASE_DN || "dc=example,dc=com");
    client.bind(dn, "any-password-this-service-checks-none", function (err) {
      if (err) {
        reject(new Error("the bind was refused, and this directory refuses " +
                         "none: " + err.message));
        return;
      }
      resolve({ protocol: "LDAP", client: client, dn: dn,
                wasClosed: function () { return closed; } });
    });
  });
}

// ---------------------------------------------------------------------------
// READING THE WORLD BACK. Three questions, each asked at the door that would
// answer it for a real client rather than at the console's own list — which is
// the rule `sts_admin_api_operations.js` states for revocation and which
// matters more here, because the console is the thing performing the act.
// ---------------------------------------------------------------------------

// Is this token alive? Asked at RFC 7662 introspection, which is where a
// resource server would ask.
async function introspectActive(token) {
  if (!token) return false;
  const r = await fetch(base + "/oauth2/introspect", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "token=" + encodeURIComponent(token) });
  const body = await r.json();
  return body.active === true;
}

// Is this browser session alive? Asked by USING it: a request to the
// authorization endpoint that comes back with a code rather than a login
// screen is a session that still works. That is a stronger question than
// reading /admin-api/sessions, which is the console's own opinion.
async function sessionStillSignsIn(cookies, application) {
  const started = await follow(cookies, base + "/oauth2/authorize" +
    "?response_type=code&scope=" + encodeURIComponent("openid") +
    "&client_id=" + encodeURIComponent(application) +
    "&redirect_uri=" + encodeURIComponent("http://" + application + ".example.com/cb") +
    "&prompt=none&state=probe");
  // `prompt=none` is what makes this a QUESTION rather than a second sign-in:
  // OIDC Core section 3.1.2.1 says the server must not display any
  // authentication UI, so a live session answers with a code and a dead one
  // answers `login_required` instead of drawing the screen.
  const landed = String(started.landed || "");
  if (landed.indexOf("code=") >= 0) return true;
  if (/login_required|interaction_required/.test(landed)) return false;
  // A login screen drawn in the body is the same answer as login_required and
  // arrives when the flow did not redirect at all.
  return !/name="authn_id"/.test(started.r.body || "");
}

async function issuedFor(username) {
  const r = await fetch(api("/tokens?per=500"));
  const body = await r.json();
  const key = String(username).toLowerCase();
  return (body.issued || []).filter(function (row) {
    return String(row.username || "").toLowerCase() === key ||
           String(row.sub || "").toLowerCase().indexOf(key) >= 0 ||
           String(row.subject || "").toLowerCase().indexOf(key) >= 0;
  });
}

async function liveSessionsFor(username) {
  const r = await fetch(api("/sessions?per=500"));
  const body = await r.json();
  const rows = body.sessions || body.rows || [];
  const key = String(username).toLowerCase();
  return rows.filter(function (row) {
    return String(row.username || row.key || "").toLowerCase().indexOf(key) >= 0;
  });
}

// ---------------------------------------------------------------------------
// SETTING THE WORLD UP. Everything is configured BEFORE anybody authenticates,
// which is the shape this test was asked for and is also the only shape that
// can fail honestly: an application created on first sight would mean a
// sign-in that failed for a missing entry looked the same as one that failed
// for a missing session.
// ---------------------------------------------------------------------------
async function postJson(url, payload) {
  const r = await fetch(url, { method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload || {}) });
  const text = await r.text();
  let body = null;
  try { body = JSON.parse(text); } catch (e) { body = null; }
  return { status: r.status, body: body, text: text };
}

async function createUser(username) {
  const r = await postJson(api("/users/create"), { username: username });
  assert.ok(r.status === 200 || /already/i.test(r.text),
    "the person should be created before anybody signs in; POST /users/create " +
    "answered " + r.status + " " + r.text.slice(0, 200));
}

// THE DEFAULT ROLE, which is EVERYBODY — and it is applied by setting NOTHING.
// An application that names no required role requires EVERYBODY, everybody
// holds it and nothing is refused, which is exactly how this service behaved
// before roles existed. Writing the name onto the entry would be a different
// test: it would be asserting that a CONFIGURED requirement admits people,
// where this one needs the unconfigured default so that a refusal below can
// only be the sign-out.
async function createApplication(identifier, protocols) {
  const r = await postJson(api("/applications/create"),
    { identifier: identifier, name: identifier, protocols: protocols });
  assert.ok(r.status === 200 || /already/i.test(r.text),
    "the application should be created before anybody authenticates against " +
    "it; POST /applications/create answered " + r.status + " " +
    r.text.slice(0, 200));
  // `oauthRedirectUri`, SINGULAR — the registry's own attribute name, and a
  // plural one is refused as an attribute this registry does not know rather
  // than being recorded and ignored.
  const attrs = await postJson(api("/applications/add"),
    { application: identifier, attribute: "oauthRedirectUri",
      value: "http://" + identifier + ".example.com/cb" });
  assert.ok(attrs.status === 200,
    "and take its redirect URI; POST /applications/add answered " +
    attrs.status + " " + attrs.text.slice(0, 200));
}

// EVERY PROTOCOL FAMILY THIS SERVICE WILL AUTHENTICATE A PERSON WITH, as the
// application registry names them. Declared on the entry so that
// /admin/applications shows one application answering to ten protocols, which
// is the thing scenario A is about.
// `mtls` and not `tls` — the registry's own name for the family, and the one
// the create refuses anything else with. It is a list the registry publishes
// rather than one written here, so a name that drifts is caught at setup.
const ALL_PROTOCOLS = ["oauth2", "oidc", "saml2", "saml11", "wsfed",
                       "wstrust", "krb5", "ldap", "mtls"];

// ---------------------------------------------------------------------------
// ONE SCENARIO. `applicationFor` is the only thing that differs between the
// two: a function of the protocol name that answers either the one shared
// application or that protocol's own.
// ---------------------------------------------------------------------------
async function runScenario(label, username, applicationFor) {
  log.info("=== " + label + " ===");
  await createUser(username);

  const signIns = [];
  const failures = [];

  // Each sign-in is attempted independently and a failure is COLLECTED rather
  // than thrown, so one protocol being unavailable in this stack does not hide
  // what the other nine would have said. The floor below is what makes that
  // safe: a run where most of them quietly failed cannot pass.
  async function attempt(what, fn) {
    try {
      const out = await fn();
      signIns.push(out);
      log.info("  [" + label + "] signed in through " + out.protocol);
    } catch (e) {
      failures.push(what + ": " + (e.message || e));
      log.warn("  [" + label + "] " + what + " did not sign in: " + e.message);
    }
  }

  await attempt("OIDC authorization code",
    function () { return oidcAuthorizationCode(username, applicationFor("oidc")); });
  await attempt("OAuth 2.0 authorization code",
    function () { return oauth2AuthorizationCode(username, applicationFor("oauth2")); });
  await attempt("SAML 2.0 Web Browser SSO",
    function () { return saml2Sso(username, applicationFor("saml2")); });
  await attempt("SAML 1.1 Browser/POST",
    function () { return saml11Sso(username, applicationFor("saml11")); });
  await attempt("WS-Federation",
    function () { return wsFederation(username, applicationFor("wsfed")); });
  await attempt("WS-Trust",
    function () { return wsTrust(username, applicationFor("wstrust")); });
  await attempt("Kerberos", function () { return kerberos(username); });
  await attempt("X.509 client certificate", function () { return x509(username); });
  await attempt("LDAP bind", function () { return ldapBind(username); });

  // THE FLOOR. A test whose sign-ins nearly all failed would sweep an empty
  // world and report a clean global logout, which is this suite's classic way
  // of passing while asserting nothing.
  check(label + ": most protocols really signed this person in", function () {
    assert.ok(signIns.length >= 7,
      "only " + signIns.length + " of 9 sign-ins succeeded, so a global " +
      "sign-out here would be sweeping a world that was never built and the " +
      "result would mean nothing. What failed: " + failures.join(" | "));
  });

  // WHAT EXISTS NOW, read before the sweep so the after-picture has something
  // to be compared against.
  const before = { sessions: await liveSessionsFor(username),
                   issued: await issuedFor(username) };
  check(label + ": several distinct sessions are live for one person", function () {
    assert.ok(before.sessions.length >= 4,
      "this person signed in through " + signIns.length + " protocols in " +
      signIns.length + " separate cookie jars, so several DISTINCT sessions " +
      "should be live — that is what makes the sweep below a test of a GLOBAL " +
      "sign-out rather than of one session ending. /admin-api/sessions holds " +
      before.sessions.length + " for them.");
  });
  check(label + ": credentials were issued", function () {
    assert.ok(before.issued.length >= 4,
      "only " + before.issued.length + " credential(s) are held for this " +
      "person; the assertions after the sweep would have almost nothing to " +
      "look at.");
  });
  log.info("  [" + label + "] before the sweep: " + before.sessions.length +
           " session(s), " + before.issued.length + " credential(s)");

  // THE ACT.
  const swept = await postJson(api("/logout/global"), { user: username });
  check(label + ": the global sign-out was accepted", function () {
    assert.strictEqual(swept.status, 200,
      "POST /admin-api/logout/global answered " + swept.status + " " +
      swept.text.slice(0, 300));
    assert.ok(swept.body && swept.body.ok !== false,
      "and reported success; it said " + JSON.stringify(swept.body).slice(0, 300));
  });

  // -----------------------------------------------------------------------
  // WHAT MUST BE DEAD. Every one of these is asked at a door a real client
  // would use, not at the console's own list.
  // -----------------------------------------------------------------------
  const after = { sessions: await liveSessionsFor(username),
                  issued: await issuedFor(username) };

  check(label + ": NO SESSION SURVIVES", function () {
    assert.deepStrictEqual(after.sessions.map(function (r) {
      return (r.protocol || "?") + " " + (r.id || "");
    }), [],
      "A GLOBAL SIGN-OUT THAT LEAVES A SESSION BEHIND HAS NOT HAPPENED. " +
      before.sessions.length + " were live and " + after.sessions.length +
      " still are. The survivor is a live way in that the operator has been " +
      "told is closed, which is worse than never having offered the button.");
  });

  for (const one of signIns) {
    if (!one.cookies || !one.cookies.value()) continue;
    const stillIn = await sessionStillSignsIn(one.cookies,
                                              applicationFor("oidc"));
    check(label + ": the " + one.protocol + " cookie no longer signs anybody in",
      function () {
        assert.strictEqual(stillIn, false,
          "the browser session established through " + one.protocol + " still " +
          "authorises a request at /oauth2/authorize with prompt=none, so it " +
          "is alive. This is the assertion that cannot be satisfied by the " +
          "console forgetting a row: it asks the AUTHORIZATION ENDPOINT, " +
          "which is where a real client would find out.");
      });
  }

  for (const one of signIns) {
    if (one.accessToken) {
      const alive = await introspectActive(one.accessToken);
      check(label + ": the " + one.protocol + " access token is inactive",
        function () {
          assert.strictEqual(alive, false,
            "the access token issued through " + one.protocol + " still " +
            "introspects as ACTIVE after a global sign-out. There is one " +
            "revocation set in this service serving both /oauth2/revoke and " +
            "this sweep; a token alive here is a resource server still " +
            "letting somebody in.");
        });
    }
    if (one.refreshToken) {
      const refreshed = await fetch(base + "/oauth2/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: "grant_type=refresh_token&refresh_token=" +
              encodeURIComponent(one.refreshToken) + "&client_id=" +
              encodeURIComponent(applicationFor("oidc")) });
      check(label + ": the " + one.protocol + " refresh token will not refresh",
        function () {
          assert.notStrictEqual(refreshed.status, 200,
            "THE REFRESH TOKEN IS THE ONE THAT MATTERS MOST and it still " +
            "works. It is the credential nobody thinks about, it outlives " +
            "every other member of its set, and it mints a new access token " +
            "on request — so a sign-out that killed the short-lived " +
            "credentials and left this alive ended nothing at all. The " +
            "refresh grant answered " + refreshed.status + ".");
        });
    }
  }

  const ldapRow = signIns.filter(function (o) { return o.protocol === "LDAP"; })[0];
  if (ldapRow) {
    // The server closes the socket; give the event a moment to arrive, which is
    // the one place this test waits on anything.
    await new Promise(function (r) { setTimeout(r, 500); });
    check(label + ": the LDAP connection was closed by the server", function () {
      assert.ok(ldapRow.wasClosed(),
        "the bound LDAP connection is still open. A Bind sets the " +
        "authorization state of a CONNECTION, so the only way to end one is " +
        "to close the socket — and a connection left open is a session this " +
        "sign-out reported ending and did not.");
    });
    try { ldapRow.client.destroy(); } catch (e) { /* already gone */ }
  }

  const krbRow = signIns.filter(function (o) { return o.protocol === "Kerberos"; })[0];
  if (krbRow) {
    let refused = false;
    let why = "";
    try {
      await krb5.getTgt(base, KRB_REALM, username, KRB_PASSWORD);
    } catch (e) {
      refused = true;
      why = e.message;
    }
    // A FRESH AS-REQ IS STILL ANSWERED and that is CORRECT: the sign-out
    // instant refuses tickets authenticated BEFORE it, and this one is after.
    // What the instant kills is the ticket already in a cache, which cannot be
    // asked about from here without replaying it. So the assertion is about the
    // RECORD, below, and this line exists to say the KDC was not broken.
    check(label + ": the KDC still answers a NEW request", function () {
      assert.strictEqual(refused, false,
        "a global sign-out must not stop this person authenticating again — " +
        "it signs them out, it does not lock them out. The KDC refused a " +
        "fresh AS-REQ: " + why);
    });
  }

  // -----------------------------------------------------------------------
  // WHAT IS DISOWNED BUT NOT DEAD. The pair that keeps this test honest.
  // -----------------------------------------------------------------------
  const disownable = before.issued.filter(function (row) {
    return row.revocationReach === "record-only";
  });
  if (disownable.length) {
    const stillListed = after.issued.filter(function (row) {
      return row.revocationReach === "record-only";
    });
    check(label + ": every assertion, ticket and SVID is DISOWNED", function () {
      const alive = stillListed.filter(function (row) {
        return row.state === "valid";
      }).map(function (row) { return row.kind + " " + (row.identifier || ""); });
      assert.deepStrictEqual(alive, [],
        "these credentials are still marked valid in this service's own " +
        "register after a global sign-out: " + alive.join(", ") + ". The " +
        "mark is the ONLY thing a sign-out can do about them, so failing to " +
        "make it is failing at the one available act.");
    });
    check(label + ": and the register says the holder was NOT told", function () {
      stillListed.forEach(function (row) {
        assert.strictEqual(row.revocationReach, "record-only",
          "a " + row.kind + " reports `revocationReach: " +
          row.revocationReach + "`. THIS MUST STAY `record-only`. Nothing " +
          "consults this service when one is presented — an assertion " +
          "verifies by its signature, a ticket decrypts with a key its " +
          "service already holds, an SVID chains to a bundle — so a row " +
          "claiming the revocation reached a protocol would be this mock " +
          "teaching a client something false about every identity provider " +
          "it will ever meet.");
      });
    });
  }

  log.info("  [" + label + "] after the sweep: " + after.sessions.length +
           " session(s) live, " + disownable.length + " credential(s) disowned " +
           "and still verifiable by their holders.");
  return { signIns: signIns.length, before: before, after: after };
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the global sign-out checks against " + base);

  // ONE USERNAME PER SCENARIO, and both unique per run. The sweep is keyed on
  // an identity, so a name of its own is what keeps this job from ending
  // another job's sessions in the shared default realm — see the header.
  const sharedUser = names.usernameFor("gl-shared");
  const perAppUser = names.usernameFor("gl-perapp");

  // SCENARIO A: ONE APPLICATION, EVERY PROTOCOL.
  const shared = ("gl-all-" + names.runStamp()).toLowerCase()
      .replace(/[^a-z0-9-]/g, "").slice(0, 40);
  await createApplication(shared, ALL_PROTOCOLS);
  const a = await runScenario("one application, every protocol", sharedUser,
                              function () { return shared; });

  // SCENARIO B: ONE APPLICATION PER PROTOCOL.
  const perProtocol = {};
  for (const protocol of ALL_PROTOCOLS) {
    const id = ("gl-" + protocol + "-" + names.runStamp()).toLowerCase()
        .replace(/[^a-z0-9-]/g, "").slice(0, 40);
    perProtocol[protocol] = id;
    await createApplication(id, [protocol]);
  }
  const b = await runScenario("one application per protocol", perAppUser,
    function (protocol) { return perProtocol[protocol] || perProtocol.oauth2; });
  // `tls` is what the sign-in functions above call the certificate family and
  // `mtls` is what the registry calls it; the map is keyed on the registry's
  // name, so the alias is stated once here rather than at the call site.

  // THE TWO SCENARIOS MUST HAVE BEEN THE SAME TEST. If B established markedly
  // fewer sessions than A, the per-application fixture is what failed rather
  // than the sign-out, and every green assertion in B is about a smaller world.
  check("both scenarios built comparable worlds", function () {
    assert.ok(Math.abs(a.signIns - b.signIns) <= 1,
      "scenario A signed in through " + a.signIns + " protocols and B " +
      "through " + b.signIns + ". They are meant to differ only in how many " +
      "applications the person authenticated AGAINST, so a gap here means " +
      "the per-application fixture failed and B asserted against a world " +
      "that was never built.");
  });

  // A FLOOR ON THE COUNT, for the reason sts_admin_console.js gives: a section
  // that stops being called takes its assertions with it and the run still
  // says "passed".
  assert.ok(checks >= 20,
    "only " + checks + " checks ran. This file makes about thirty against a " +
    "healthy service, so a count this low means a SECTION STOPPED BEING " +
    "CALLED rather than that the feature got simpler.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_global_logout")
  .description("Sign one person in through every protocol the mock STS " +
      "authenticates people with — OIDC and OAuth 2.0 authorization code, " +
      "SAML 2.0, SAML 1.1, WS-Federation, WS-Trust, Kerberos, an X.509 " +
      "client certificate and an LDAP bind, each in a cookie jar of its own " +
      "— then perform ONE global sign-out and look for anything that " +
      "survived. Run twice: against one application that speaks every " +
      "protocol, and against one application per protocol.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
