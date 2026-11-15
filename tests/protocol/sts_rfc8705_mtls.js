// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_rfc8705_mtls.js
//
// ---------------------------------------------------------------------------
// RFC 8705, BOTH HALVES, OVER REAL HANDSHAKES WITH THE MAIN PORT.
//
// D12 (#444): carries over the endpoint half of `tests/rfc8705_mtls.js` that
// `sts_client_authentication.js` does not already hold (that job has the
// implicit mapping's bound token, no certificate, another application's,
// a revoked one, and self_signed_tls_client_auth by x5c). In a development
// realm of its own — RFC 8705 is verified in every mode — with the main
// port, which asks every connection for a certificate and requires none:
//
//   a. discovery advertises both methods and bound tokens;
//   b. the Credentials door issues a clientAuth certificate naming the
//      application (urn:sts:application:<id>, CN, EKU), its key encrypted
//      under the password and a PKCS#12 built, and the application's page
//      lists it valid with no private key anywhere;
//   c. the door's refusals: a password typed differently twice
//      (STS-ADMIN-0721), an application that does not exist (0722), past
//      `pki.applicationTlsClientCertificateMax` (STS-PKI-0180), another
//      application's serial (0181); a second revoke keeps the earlier entry;
//   d. THE EXPLICIT MAPPING, against a foreign CA `openssl` makes here and
//      posts as a client trust anchor (recorded first and removed at the end,
//      tests/CLAUDE.md, #1307): a leaf by subject DN spelt differently and by
//      each of the four subjectAltNames, refused for a subject that does not
//      match (0485, quoting the one presented), for nothing registered
//      (0486), for a matching subject whose chain did not verify (0480);
//      the registry refuses a second parameter at /admin-api (STS-REG-0135),
//      a bad value (0134) and a flag that is not TRUE or FALSE (0136); and
//      two parameters left by an `ldapmodify` are refused at use (0482);
//   e. self_signed_tls_client_auth by the registered thumbprint;
//   f. a pushed authorization request from a tls_client_auth client with no
//      certificate is refused (STS-OAUTH-0014);
//   g. section 3.4: a client that declared bound tokens is refused a token
//      with no certificate (0487) and bound with one;
//   h. section 3.1 at UserInfo: answered with the certificate, refused with
//      none (0091) and with another (0092); section 3.2's cnf at
//      introspection;
//   i. section 7.1: a public bound client's refresh refused on another
//      certificate (0092); a certificate client's refresh on a NEW
//      certificate rebinds; another client presenting that refresh token is
//      refused (STS-OAUTH-0141);
//   j. RFC 7591 registration of a subject parameter and the flag, echoed,
//      and authenticating with the foreign certificate; two parameters
//      refused (STS-REG-0131), a DN that is not one (0130), a flag that is
//      not a boolean (0132);
//   k. /admin-api as a resource server: a token asked for over a
//      certificate is bound to it, answered with it and refused without
//      (STS-API-0110);
//   m. #1050: a client declaring tls_client_auth beside a secret is refused
//      an /admin-api token without a certificate (0489), given a bound one
//      with it, an unbound one for another resource; a bound-token client
//      refused one with no certificate (0487); the Credentials say
//      adminApiBound; an implicit response carrying an /admin-api token is
//      refused (STS-OAUTH-0490) while one for another resource is issued;
//   l. an application's certificate at GET /tls/sign-in starts no browser
//      session in the application's name.
//
// NOT carried (class (d)): sections 1 and 2 of the in-process file as
// functions (the subject library and the registry's checks — 2's codes are
// asserted here at the doors); a certificate the record no longer lists
// (0483: no door forgets one short of revoking it); a leaf whose CN and
// urn:sts:application: disagree (0481: no door issues one); an unbound
// /admin-api token minted past the funnel (STS-API-0137, 3m5-3m7: no door
// mints one); bound tokens refused on a plain main port (STS-REG-0133: the
// main port is TLS for the whole process).
//
// Every refusal's code is read back off the realm's /admin-api/audit.
// Nothing here is committed key material: openssl makes every key at run
// time, in a directory removed at the end.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

const childProcess = require("child_process");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");
const authnSignin = require("./authn_signin");
const anchors = require("../tools/pep-credential.js");
const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_rfc8705_mtls",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — an empty answer or a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers,
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

function postForm(url, fields, headers) {
  log.debug("Entering postForm().");
  log.debug("Leaving postForm().");
  return send(url, { method: "POST",
    headers: Object.assign({ "Content-Type":
                               "application/x-www-form-urlencoded" },
                           headers || {}),
    body: form(fields) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// How many rows of a realm's audit log carry `code`, waited for until there
// are more than `above` (default 0): the row is written as the refusal is
// sent, and a code is recorded, never sent.
async function codeCount(realm, code, above) {
  log.debug("Entering codeCount(). " + code);
  const floor = Number(above || 0);
  let n = 0;
  for (let i = 0; i < 20; i += 1) {
    const r = await send(base + (realm === "default" ? "" : "/realm/" +
                         realm) + "/admin-api/audit" +
                         "?per=500&code=" + encodeURIComponent(code));
    n = Number((r.body && r.body.matched) || 0);
    if (n > floor) {
      break;
    }
    await sleep(150);
  }
  log.debug("Leaving codeCount(). " + n);
  return n;
}

async function createRealm(id, mode, what) {
  log.debug("Entering createRealm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: what + " " + STAMP },
    "created the realm " + id);
  if (mode) {
    await ok(base + "/admin-api/realms/set", { id: id, key: "global.mode",
                                               value: mode },
             "put " + id + " in " + mode + " mode");
  }
  log.debug("Leaving createRealm().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made — each id
// carries the run's STAMP — is removed at the end, pass or fail. A suite run
// leaves them standing (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  const listed = await send(base + "/admin-api/realms?per=500");
  const mine = ((listed.body && listed.body.realms) || []).filter(
    function (one) {
      return one.id !== "default" && one.id.indexOf(STAMP) >= 0;
    });
  for (const one of mine) {
    const r = await postJson(base + "/admin-api/realms/remove",
                             { id: one.id });
    log.info("removed the realm " + one.id + " (" + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realms are removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // A failed removal is not the job's verdict.
    log.info("could not remove the realms: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

// One browser, with a cookie jar, following nothing by itself.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

// Follows redirects inside this service, signing `who` in on the screen
// over `/authn-api` and allowing a consent screen, until the answer leaves
// the service or is a page.
async function follow(realm, b, first, who, password) {
  log.debug("Entering follow().");
  let r = first;
  for (let i = 0; i < 12; i++) {
    if (!(r.status === 302 || r.status === 303)) {
      break;
    }
    const where = absolute(r.location);
    if (where.indexOf(base) !== 0) {
      break;
    }
    if (/\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(where) && who) {
      const posted = await authnSignin.signInWithJar(base + "/realm/" +
        realm, where, { action: "login", username: who,
                        password: password }, b.jar);
      assert.ok(posted.answer.view, "the sign-in screen: " +
                posted.answer.status + " " +
                JSON.stringify(posted.answer.json));
      r = posted;
      continue;
    }
    if (authnSignin.isConsent(where)) {
      r = await authnSignin.consentWithJar(where, "allow", b.jar);
      continue;
    }
    r = await b.go("GET", where);
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier,
           challenge: nodeCrypto.createHash("sha256").update(verifier)
             .digest("base64url") };
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
                      .toString("utf8"));
}

const REALM = "mtls-" + STAMP;
const RB = base + "/realm/" + REALM;
const API = RB + "/admin-api";
const PASSWORD = "correct horse battery " + STAMP;
const ALICE = names.usernameFor("mtls-alice");
const addedAnchors = [];

function openssl(dir, args) {
  log.debug("Entering openssl().");
  childProcess.execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
  log.debug("Leaving openssl().");
}

// THE CERTIFICATES NOBODY HERE ISSUED: a foreign CA, a leaf it signs with
// every subjectAltName kind, and two self-signed certificates.
function makeMaterial() {
  log.debug("Entering makeMaterial().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sts-rfc8705-"));
  const ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
              "-nodes"];
  openssl(dir, ["req", "-x509"].concat(ec, ["-keyout", "ca.key", "-out",
    "ca.pem", "-days", "2", "-subj", "/CN=RFC 8705 Test Foreign CA " + STAMP,
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign"]));
  fs.writeFileSync(path.join(dir, "ext.cnf"),
    "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n" +
    "extendedKeyUsage=clientAuth\nsubjectAltName=@alt\n[alt]\n" +
    "DNS.1=ext.example.com\nURI.1=https://client.example.com/id\n" +
    "IP.1=192.0.2.10\nIP.2=2001:db8::7\nemail.1=Ops@example.com\n");
  openssl(dir, ["req"].concat(ec, ["-keyout", "ext.key", "-out", "ext.csr",
    "-subj", "/C=US/O=Example Corp, Inc./CN=ext-client"]));
  openssl(dir, ["x509", "-req", "-in", "ext.csr", "-CA", "ca.pem", "-CAkey",
    "ca.key", "-CAcreateserial", "-out", "ext.pem", "-days", "1",
    "-extfile", "ext.cnf"]);
  ["self", "self2"].forEach(function (name) {
    openssl(dir, ["req", "-x509"].concat(ec, ["-keyout", name + ".key",
      "-out", name + ".pem", "-days", "1", "-subj",
      "/CN=" + (name === "self" ? "self-client" : "self-client-two"),
      "-addext", "extendedKeyUsage=clientAuth"]));
  });
  const read = function (file) {
    return fs.readFileSync(path.join(dir, file), "utf8");
  };
  log.debug("Leaving makeMaterial().");
  return { dir: dir, caPem: read("ca.pem"),
           ext: { cert: read("ext.pem") + read("ca.pem"),
                  key: read("ext.key"), leaf: read("ext.pem") },
           self: { cert: read("self.pem"), key: read("self.key"),
                   leaf: read("self.pem") },
           self2: { cert: read("self2.pem"), key: read("self2.key"),
                    leaf: read("self2.pem") } };
}

function thumb(pem) {
  log.debug("Entering thumb().");
  log.debug("Leaving thumb().");
  return nodeCrypto.createHash("sha256")
    .update(new nodeCrypto.X509Certificate(pem).raw).digest("base64url");
}

function cnfOf(jwt) {
  log.debug("Entering cnfOf().");
  let out = {};
  try {
    out = claimsOf(jwt).cnf || {};
  } catch (e) {
    log.debug("Caught in cnfOf(): " + ((e && e.message) || e));
    // Not a JWT: no binding to read.
    out = {};
  }
  log.debug("Leaving cnfOf().");
  return out;
}

// A request on its own connection, presenting `o.tls` (cert, key) when
// given — fetch() cannot present a client certificate.
function tlsRequest(method, url, o) {
  log.debug("Entering tlsRequest(). " + method + " " + url);
  const opts = o || {};
  return new Promise(function (resolve) {
    const u = new URL(url);
    const body = opts.json !== undefined ? JSON.stringify(opts.json)
      : (opts.form ? new URLSearchParams(opts.form).toString() : "");
    const headers = Object.assign({}, opts.headers || {});
    if (method !== "GET") {
      headers["content-type"] = opts.json !== undefined
        ? "application/json" : "application/x-www-form-urlencoded";
      headers["content-length"] = Buffer.byteLength(body);
    }
    const req = https.request({ host: u.hostname, port: u.port,
      path: u.pathname + u.search, method: method, headers: headers,
      cert: opts.tls ? opts.tls.cert : undefined,
      key: opts.tls ? opts.tls.key : undefined, agent: false },
    function (res) {
      let text = "";
      res.on("data", function (c) {
        text += c;
      });
      res.on("end", function () {
        let parsed = null;
        try {
          parsed = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in tlsRequest(): " + ((e && e.message) || e));
          // Not JSON: the caller reads `text`.
          parsed = {};
        }
        log.debug("Leaving tlsRequest(). " + res.statusCode);
        resolve({ status: res.statusCode, json: parsed || {}, text: text,
                  headers: res.headers });
      });
    });
    req.on("error", function (e) {
      log.debug("Leaving tlsRequest(). " + e.message);
      resolve({ status: 0, json: { error: e.message }, text: e.message,
                headers: {} });
    });
    req.end(body);
  });
}

function token(fields, tls, headers) {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return tlsRequest("POST", RB + "/oauth2/token",
                    { form: fields, tls: tls, headers: headers });
}

// The request `fn` makes, and whether `code` was recorded for it: the count
// before and after, so an older row cannot answer for a new one.
async function raises(code, fn, realm) {
  log.debug("Entering raises(). " + code);
  const where = realm || REALM;
  const before = await codeCount(where, code);
  const answer = await fn();
  const after = await codeCount(where, code, before);
  answer.coded = after > before;
  log.debug("Leaving raises(). " + answer.coded);
  return answer;
}

function refusedAs(r, status, error) {
  log.debug("Entering refusedAs().");
  log.debug("Leaving refusedAs().");
  return r.status === status && r.json && r.json.error === error;
}

async function create(id, fields, extra) {
  log.debug("Entering create(). " + id);
  await ok(API + "/applications/create", Object.assign({ identifier: id,
    protocols: ["oauth2"],
    fields: Object.assign({ oauthClientId: id }, fields || {}) },
    extra || {}), "created " + id);
  log.debug("Leaving create().");
}

async function issueTo(id, extra) {
  log.debug("Entering issueTo(). " + id);
  const r = await postJson(API + "/applications/issue-tls-client-certificate",
    Object.assign({ application: id, password: PASSWORD, keyAlg: "ec-p256" },
                  extra || {}));
  if (r.status !== 200 || !r.body || !r.body.files) {
    log.debug("Leaving issueTo(). Refused.");
    return { response: r };
  }
  const key = nodeCrypto.createPrivateKey({ key: r.body.files.key.text,
    format: "pem", passphrase: PASSWORD })
    .export({ type: "pkcs8", format: "pem" });
  log.debug("Leaving issueTo().");
  return { response: r, tls: { cert: r.body.files.chain.text, key: key },
           leaf: r.body.certificate.certificatePem,
           serialHex: r.body.certificate.serialHex };
}

function ldapAdd(filter, type, value) {
  log.debug("Entering ldapAdd().");
  const ldap = require("ldapjs");
  const suffix = (REALM + ".example.net").split(".").map(function (label) {
    return "dc=" + label;
  }).join(",");
  return new Promise(function (resolve, reject) {
    const client = ldap.createClient({ url: "ldap://" +
      new URL(base).hostname + ":" + (process.env.STS_LDAP_PORT || "389"),
      reconnect: false });
    // An error handler is not optional: a socket the server closes would
    // otherwise throw out of the client and take the job down.
    client.on("error", function (e) {
      log.debug("ldap client error: " + ((e && e.message) || e));
    });
    const fail = function (e) {
      client.unbind();
      log.debug("Leaving ldapAdd(). Failed.");
      reject(e);
    };
    client.bind("uid=" + ALICE + ",ou=users," + suffix, PASSWORD,
                function (err) {
      if (err) {
        fail(err);
        return;
      }
      const found = [];
      client.search("ou=applications," + suffix, { scope: "sub",
        filter: filter, attributes: ["dn"] }, function (e2, res) {
        if (e2) {
          fail(e2);
          return;
        }
        res.on("searchEntry", function (entry) {
          found.push(String(entry.objectName || entry.dn));
        });
        res.on("error", fail);
        res.on("end", function () {
          if (found.length !== 1) {
            fail(new Error(found.length + " entries for " + filter));
            return;
          }
          client.modify(found[0], new ldap.Change({ operation: "add",
            modification: { type: type, values: [value] } }),
          function (e3) {
            if (e3) {
              fail(e3);
              return;
            }
            client.unbind();
            log.debug("Leaving ldapAdd().");
            resolve(found[0]);
          });
        });
      });
    });
  });
}

async function credentialsOf(id) {
  log.debug("Entering credentialsOf(). " + id);
  const r = await send(API + "/applications?application=" + id);
  log.debug("Leaving credentialsOf().");
  return { view: r, mtls: (r.body && r.body.credentials &&
                           r.body.credentials.mtls) || {} };
}

async function endpoints(M) {
  log.debug("Entering endpoints().");
  log.info("=== a. discovery ===");
  const meta = await send(RB + "/.well-known/oauth-authorization-server");
  const methods = (meta.body &&
                   meta.body.token_endpoint_auth_methods_supported) || [];
  check("a. discovery advertises bound tokens and both RFC 8705 methods",
        function () {
    assert.strictEqual(meta.body.tls_client_certificate_bound_access_tokens,
                       true);
    assert.ok(methods.indexOf("tls_client_auth") >= 0, methods.join(" "));
    assert.ok(methods.indexOf("self_signed_tls_client_auth") >= 0);
  });

  log.info("=== b. the Credentials door ===");
  await create("mtls-impl", { oauthTokenEndpointAuthMethod:
                                "tls_client_auth" });
  await create("mtls-other", { oauthTokenEndpointAuthMethod:
                                 "tls_client_auth" });
  const impl = await issueTo("mtls-impl", { label: "instance 1" });
  const leaf = impl.leaf ? new nodeCrypto.X509Certificate(impl.leaf) : null;
  check("b1. the door issues a clientAuth certificate naming the " +
        "application, and hands back its files once", function () {
    assert.ok(impl.tls, JSON.stringify(impl.response.body).slice(0, 300));
    assert.strictEqual(impl.response.body.certificate.implicitName,
                       "urn:sts:application:mtls-impl");
    assert.ok(String(leaf.subjectAltName)
      .indexOf("URI:urn:sts:application:mtls-impl") >= 0);
    assert.ok((leaf.keyUsage || []).indexOf("1.3.6.1.5.5.7.3.2") >= 0);
    assert.ok(/CN=mtls-impl/.test(leaf.subject), leaf.subject);
  });
  check("b2. the key file is encrypted under the password and a PKCS#12 is " +
        "built", function () {
    assert.ok(/ENCRYPTED PRIVATE KEY/.test(impl.response.body.files.key
      .text));
    assert.ok(impl.response.body.files.pkcs12.base64.length > 100);
  });
  let creds = await credentialsOf("mtls-impl");
  check("b3. the application's page lists the certificate, valid, and no " +
        "private key anywhere", function () {
    assert.strictEqual(creds.mtls.certificates.length, 1,
                       JSON.stringify(creds.mtls).slice(0, 300));
    assert.strictEqual(creds.mtls.certificates[0].state, "valid");
    assert.strictEqual(creds.mtls.certificateMethod, true);
    assert.ok(creds.view.raw.indexOf("PRIVATE KEY") < 0);
  });

  log.info("=== c. the door's refusals ===");
  let r = await raises("STS-ADMIN-0721", function () {
    return postJson(API + "/applications/issue-tls-client-certificate",
                    { application: "mtls-impl", password: PASSWORD,
                      confirm: "another password entirely" });
  });
  check("c5. a file password typed differently twice is refused, " +
        "STS-ADMIN-0721", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(r.coded);
  });
  r = await raises("STS-ADMIN-0722", function () {
    return postJson(API + "/applications/issue-tls-client-certificate",
                    { application: "mtls-nobody", password: PASSWORD });
  });
  check("c6. and an application that does not exist, STS-ADMIN-0722",
        function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(r.coded);
  });
  await ok(base + "/admin-api/realms/set", { id: REALM,
    key: "pki.applicationTlsClientCertificateMax", value: "1" },
    "capped an application's certificates at one");
  r = await raises("STS-PKI-0180", function () {
    return postJson(API + "/applications/issue-tls-client-certificate",
                    { application: "mtls-impl", password: PASSWORD });
  });
  await ok(base + "/admin-api/realms/set", { id: REALM,
    key: "pki.applicationTlsClientCertificateMax", value: "5" },
    "put the cap back at five");
  check("c7. past pki.applicationTlsClientCertificateMax, STS-PKI-0180",
        function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(r.coded);
  });
  const otherIssued = await issueTo("mtls-other");
  r = await raises("STS-PKI-0181", function () {
    return postJson(API + "/applications/revoke-tls-client-certificate",
                    { application: "mtls-impl",
                      serialHex: otherIssued.serialHex });
  });
  check("c8. one application cannot revoke another's, STS-PKI-0181",
        function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(r.coded);
  });
  const doomed = await issueTo("mtls-other", { label: "doomed" });
  const revoke = function () {
    return postJson(API + "/applications/revoke-tls-client-certificate",
                    { application: "mtls-other", serialHex: doomed.serialHex,
                      reason: "keyCompromise" });
  };
  const once = await revoke();
  const twice = await revoke();
  check("c9. a revoke, and the same revoke again keeps the earlier entry",
        function () {
    assert.strictEqual(once.status, 200, once.raw.slice(0, 300));
    assert.strictEqual(twice.status, 200, twice.raw.slice(0, 300));
    assert.strictEqual(twice.body.already, true, twice.raw.slice(0, 300));
  });

  log.info("=== d. the explicit mapping ===");
  const explicit = [
    ["mtls-dn", "oauthTlsClientAuthSubjectDn",
     "cn=EXT-CLIENT, o=Example Corp\\, Inc., c=US"],
    ["mtls-dns", "oauthTlsClientAuthSanDns", "ext.example.com"],
    ["mtls-uri", "oauthTlsClientAuthSanUri", "https://client.example.com/id"],
    ["mtls-ip", "oauthTlsClientAuthSanIp", "2001:db8::7"],
    ["mtls-email", "oauthTlsClientAuthSanEmail", "Ops@example.com"]
  ];
  for (const row of explicit) {
    const fields = { oauthTokenEndpointAuthMethod: "tls_client_auth" };
    fields[row[1]] = row[2];
    await create(row[0], fields);
    r = await token({ grant_type: "client_credentials", client_id: row[0] },
                    M.ext);
    check("d1. a foreign CA's certificate authenticates a client that " +
          "registered " + row[1] + " \"" + row[2] + "\", bound to it",
          function () {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
      assert.strictEqual(cnfOf(r.json.access_token)["x5t#S256"],
                         thumb(M.ext.leaf));
    });
  }
  await create("mtls-dn-wrong", { oauthTokenEndpointAuthMethod:
    "tls_client_auth",
    oauthTlsClientAuthSubjectDn: "CN=someone-else,O=Example Corp\\, " +
                                 "Inc.,C=US" });
  r = await raises("STS-OAUTH-0485", function () {
    return token({ grant_type: "client_credentials",
                   client_id: "mtls-dn-wrong" }, M.ext);
  });
  check("d2. a subject that does not match is refused, quoting the one " +
        "presented, STS-OAUTH-0485", function () {
    assert.ok(refusedAs(r, 401, "invalid_client"), r.text.slice(0, 300));
    assert.ok(r.coded);
    assert.ok(/CN=ext-client/.test(r.json.error_description || ""),
              r.text.slice(0, 300));
  });
  await create("mtls-none", { oauthTokenEndpointAuthMethod:
                                "tls_client_auth" });
  r = await raises("STS-OAUTH-0486", function () {
    return token({ grant_type: "client_credentials",
                   client_id: "mtls-none" }, M.ext);
  });
  check("d3. a foreign certificate with nothing registered, STS-OAUTH-0486",
        function () {
    assert.ok(refusedAs(r, 401, "invalid_client"), r.text.slice(0, 300));
    assert.ok(r.coded);
  });
  await create("mtls-selfdn", { oauthTokenEndpointAuthMethod:
                                  "tls_client_auth",
                                oauthTlsClientAuthSubjectDn:
                                  "CN=self-client" });
  r = await raises("STS-OAUTH-0480", function () {
    return token({ grant_type: "client_credentials",
                   client_id: "mtls-selfdn" }, M.self);
  });
  check("d4. a matching subject on a certificate whose chain did not " +
        "verify is refused, STS-OAUTH-0480", function () {
    assert.ok(refusedAs(r, 401, "invalid_client"), r.text.slice(0, 300));
    assert.ok(r.coded);
  });
  await create("mtls-two", { oauthTokenEndpointAuthMethod: "tls_client_auth",
                             oauthTlsClientAuthSanDns: "ext.example.com" });
  r = await raises("STS-REG-0135", function () {
    return postJson(API + "/applications/set", { application: "mtls-two",
      attribute: "oauthTlsClientAuthSanEmail", value: "Ops@example.com" });
  });
  check("d5. the registry refuses a second subject parameter, naming the " +
        "one to clear, STS-REG-0135", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(r.coded);
  });
  r = await postJson(API + "/applications/set", { application: "mtls-two",
    attribute: "oauthTlsClientAuthSanDns", value: "other.example.com" });
  check("d5b. replacing the parameter already held is not refused",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  });
  await postJson(API + "/applications/set", { application: "mtls-two",
    attribute: "oauthTlsClientAuthSanDns", value: "ext.example.com" });
  r = await raises("STS-REG-0134", function () {
    return postJson(API + "/applications/set", { application: "mtls-none",
      attribute: "oauthTlsClientAuthSanEmail", value: "x" });
  });
  check("d5c. a bad value is refused, STS-REG-0134", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(r.coded);
  });
  r = await raises("STS-REG-0136", function () {
    return postJson(API + "/applications/set", { application: "mtls-none",
      attribute: "oauthTlsClientCertificateBoundAccessTokens",
      value: "yes" });
  });
  check("d5d. a section 3.4 flag that is not TRUE or FALSE, STS-REG-0136",
        function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(r.coded);
  });
  await ldapAdd("(oauthClientId=mtls-two)", "oauthTlsClientAuthSanEmail",
                "Ops@example.com");
  r = await raises("STS-OAUTH-0482", function () {
    return token({ grant_type: "client_credentials", client_id: "mtls-two" },
                 M.ext);
  });
  check("d6. two parameters an ldapmodify left are refused at use, " +
        "STS-OAUTH-0482", function () {
    assert.ok(refusedAs(r, 401, "invalid_client"), r.text.slice(0, 300));
    assert.ok(r.coded);
  });

  log.info("=== e. self_signed_tls_client_auth by thumbprint ===");
  await create("mtls-self-thumb", {
    oauthTokenEndpointAuthMethod: "self_signed_tls_client_auth",
    oauthTlsClientCertificateThumbprint: thumb(M.self.leaf) });
  r = await token({ grant_type: "client_credentials",
                    client_id: "mtls-self-thumb" }, M.self);
  check("e2. a self-signed certificate authenticates its client by the " +
        "registered thumbprint", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(cnfOf(r.json.access_token)["x5t#S256"],
                       thumb(M.self.leaf));
  });

  log.info("=== f. the declaration at PAR ===");
  r = await raises("STS-OAUTH-0014", function () {
    return tlsRequest("POST", RB + "/oauth2/par", { form: {
      client_id: "mtls-impl", response_type: "code",
      redirect_uri: "https://mtls.example/cb",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256" } });
  });
  check("f. a pushed authorization request from a tls_client_auth client " +
        "with no certificate is refused, STS-OAUTH-0014", function () {
    assert.ok(refusedAs(r, 401, "invalid_client"), r.text.slice(0, 300));
    assert.ok(r.coded);
  });

  log.info("=== g. section 3.4 ===");
  await create("mtls-bound-public", { oauthTokenEndpointAuthMethod: "none",
    oauthTlsClientCertificateBoundAccessTokens: "TRUE" });
  const pw = { grant_type: "password", client_id: "mtls-bound-public",
               username: ALICE, password: PASSWORD, scope: "openid" };
  r = await raises("STS-OAUTH-0487", function () {
    return token(pw);
  });
  check("g1. a client that declared bound tokens is refused a token with no " +
        "certificate, STS-OAUTH-0487", function () {
    assert.ok(refusedAs(r, 400, "invalid_request"), r.text.slice(0, 300));
    assert.ok(r.coded);
  });
  r = await token(pw, M.self);
  const publicAccess = r.json.access_token;
  const publicRefresh = r.json.refresh_token;
  check("g2. and bound to the certificate when it presents one — a public " +
        "client, section 4", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(cnfOf(publicAccess)["x5t#S256"], thumb(M.self.leaf));
  });

  log.info("=== h. the resource server and introspection ===");
  const userinfo = function (access, tls) {
    return tlsRequest("GET", RB + "/oauth2/userinfo", {
      headers: { authorization: "Bearer " + access }, tls: tls });
  };
  r = await userinfo(publicAccess, M.self);
  check("h1. UserInfo answers a bound token on a connection made with its " +
        "certificate", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  r = await raises("STS-OAUTH-0091", function () {
    return userinfo(publicAccess);
  });
  check("h2. and refuses it with no certificate: 401 invalid_token, " +
        "STS-OAUTH-0091", function () {
    assert.strictEqual(r.status, 401, r.text.slice(0, 300));
    assert.ok(/invalid_token/.test(String(r.headers["www-authenticate"])));
    assert.ok(r.coded);
  });
  r = await raises("STS-OAUTH-0092", function () {
    return userinfo(publicAccess, M.self2);
  });
  check("h3. and with another certificate, STS-OAUTH-0092", function () {
    assert.strictEqual(r.status, 401, r.text.slice(0, 300));
    assert.ok(r.coded);
  });
  r = await tlsRequest("POST", RB + "/oauth2/introspect",
                       { form: { token: publicAccess } });
  check("h4. introspection carries the cnf x5t#S256 (section 3.2)",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.active, true);
    assert.strictEqual((r.json.cnf || {})["x5t#S256"], thumb(M.self.leaf));
  });

  log.info("=== i. section 7.1 ===");
  r = await raises("STS-OAUTH-0092", function () {
    return token({ grant_type: "refresh_token",
                   client_id: "mtls-bound-public",
                   refresh_token: publicRefresh }, M.self2);
  });
  check("i1. a public client's refresh token is refused on another " +
        "certificate, STS-OAUTH-0092", function () {
    assert.ok(refusedAs(r, 400, "invalid_grant"), r.text.slice(0, 300));
    assert.ok(r.coded);
  });
  r = await token({ grant_type: "password", client_id: "mtls-impl",
                    username: ALICE, password: PASSWORD, scope: "openid" },
                  impl.tls);
  const implRefresh = r.json.refresh_token;
  check("i2. a certificate client gets a bound access token and a refresh " +
        "token", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(implRefresh, r.text.slice(0, 300));
    assert.strictEqual(cnfOf(r.json.access_token)["x5t#S256"],
                       thumb(impl.leaf));
  });
  const renewed = await issueTo("mtls-impl", { label: "renewed" });
  r = await token({ grant_type: "refresh_token", client_id: "mtls-impl",
                    refresh_token: implRefresh }, renewed.tls);
  check("i3. its refresh on a NEW certificate succeeds, the access token " +
        "bound to the new one (sections 6.3 and 7.1)", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(cnfOf(r.json.access_token)["x5t#S256"],
                       thumb(renewed.leaf));
  });
  r = await raises("STS-OAUTH-0141", function () {
    return token({ grant_type: "refresh_token", client_id: "mtls-other",
                   refresh_token: implRefresh }, otherIssued.tls);
  });
  check("i4. another certificate client presenting that refresh token is " +
        "refused, STS-OAUTH-0141 (RFC 6749 section 6)", function () {
    assert.ok(refusedAs(r, 400, "invalid_grant"), r.text.slice(0, 300));
    assert.ok(r.coded);
  });

  log.info("=== j. RFC 7591 registration ===");
  const register = function (metadata) {
    return tlsRequest("POST", RB + "/oauth2/register", { json: metadata });
  };
  r = await register({ redirect_uris: ["https://mtls.example/cb"],
    grant_types: ["authorization_code", "client_credentials"],
    token_endpoint_auth_method: "tls_client_auth",
    tls_client_auth_san_dns: "ext.example.com",
    tls_client_certificate_bound_access_tokens: true });
  const regId = r.json.client_id;
  check("j1. a registration carrying a subject parameter and the flag is " +
        "accepted and echoed", function () {
    assert.strictEqual(r.status, 201, r.text.slice(0, 300));
    assert.strictEqual(r.json.tls_client_auth_san_dns, "ext.example.com");
    assert.strictEqual(r.json.tls_client_certificate_bound_access_tokens,
                       true);
  });
  creds = await send(API + "/applications?application=" + regId);
  check("j2. and written to the entry the token endpoint reads",
        function () {
    const fields = (creds.body && creds.body.fields) || {};
    assert.ok([].concat(fields.oauthTlsClientAuthSanDns || [])
      .indexOf("ext.example.com") >= 0, JSON.stringify(fields)
      .slice(0, 300));
  });
  r = await token({ grant_type: "client_credentials", client_id: regId },
                  M.ext);
  check("j3. that registered client authenticates with the foreign " +
        "certificate", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  for (const row of [
    ["STS-REG-0131", { tls_client_auth_subject_dn: "CN=a",
                       tls_client_auth_san_dns: "a.b" },
     "two subject parameters"],
    ["STS-REG-0130", { tls_client_auth_subject_dn: "CN=a," },
     "a DN that is not one"],
    ["STS-REG-0132", { tls_client_certificate_bound_access_tokens: "true" },
     "a section 3.4 flag that is not a boolean"]]) {
    r = await raises(row[0], function () {
      return register(Object.assign({ redirect_uris:
        ["https://mtls.example/cb"],
        token_endpoint_auth_method: "tls_client_auth" }, row[1]));
    });
    check("j4. " + row[2] + " is refused invalid_client_metadata, " + row[0],
          function () {
      assert.ok(refusedAs(r, 400, "invalid_client_metadata"),
                r.text.slice(0, 300));
      assert.ok(r.coded);
    });
  }

  log.info("=== k. /admin-api as a resource server ===");
  const adminBasic = "Basic " + Buffer.from("sts-api-client:" +
    process.env.STS_ADMIN_API_CLIENT_SECRET).toString("base64");
  r = await tlsRequest("POST", base + "/oauth2/token", {
    headers: { authorization: adminBasic },
    form: { grant_type: "client_credentials", scope: "admin:read",
            resource: base + "/admin-api" }, tls: M.self });
  const adminToken = r.json.access_token;
  check("k1. an /admin-api access token asked for over a certificate is " +
        "bound to it", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(cnfOf(adminToken)["x5t#S256"], thumb(M.self.leaf));
  });
  r = await tlsRequest("GET", base + "/admin-api/status", {
    headers: { authorization: "Bearer " + adminToken }, tls: M.self });
  check("k2. /admin-api answers it on a connection made with that " +
        "certificate", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  r = await raises("STS-API-0110", function () {
    return tlsRequest("GET", base + "/admin-api/status", {
      headers: { authorization: "Bearer " + adminToken } });
  }, "default");
  check("k3. and refuses it without the certificate: 401 invalid_token, " +
        "STS-API-0110", function () {
    assert.strictEqual(r.status, 401, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "invalid_token");
    assert.ok(r.coded);
  });

  log.info("=== m. /admin-api tokens for a certificate client (#1050) ===");
  const mixedSecret = "mixed-" + nodeCrypto.randomBytes(12).toString("hex");
  await create("mtls-mixed", {
    oauthTokenEndpointAuthMethod: ["tls_client_auth", "client_secret_basic"],
    oauthClientSecret: mixedSecret });
  const mixedBasic = "Basic " + Buffer.from("mtls-mixed:" + mixedSecret)
    .toString("base64");
  const mixedToken = function (fields, tls) {
    return token(Object.assign({ grant_type: "client_credentials" }, fields),
                 tls, { authorization: mixedBasic });
  };
  r = await raises("STS-OAUTH-0489", function () {
    return mixedToken({ resource: RB + "/admin-api" });
  });
  check("m1. a client declaring tls_client_auth beside a secret, sending " +
        "the secret with no certificate, is refused an /admin-api token, " +
        "STS-OAUTH-0489", function () {
    assert.ok(refusedAs(r, 400, "invalid_request"), r.text.slice(0, 300));
    assert.ok(/management API/.test(r.json.error_description || ""),
              r.text.slice(0, 300));
    assert.ok(r.coded);
  });
  r = await mixedToken({ resource: RB + "/admin-api" }, M.self);
  check("m2. and given one bound to the certificate when it presents one",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(cnfOf(r.json.access_token)["x5t#S256"],
                       thumb(M.self.leaf));
  });
  r = await mixedToken({});
  check("m3. a token for any other resource is still issued to it unbound",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(!cnfOf(r.json.access_token)["x5t#S256"]);
  });
  r = await raises("STS-OAUTH-0487", function () {
    return token(Object.assign({}, pw, { resource: RB + "/admin-api" }));
  });
  check("m4. a client that declared bound tokens is refused an /admin-api " +
        "token with no certificate, STS-OAUTH-0487", function () {
    assert.ok(refusedAs(r, 400, "invalid_request"), r.text.slice(0, 300));
    assert.ok(r.coded);
  });
  const mixed = await credentialsOf("mtls-mixed");
  const wrongDn = await credentialsOf("mtls-dn-wrong");
  check("m9. the application's Credentials say its /admin-api tokens are " +
        "certificate-bound (rule 7)", function () {
    assert.strictEqual(mixed.mtls.adminApiBound, true,
                       JSON.stringify(mixed.mtls).slice(0, 300));
    assert.strictEqual(wrongDn.mtls.adminApiBound, true);
  });
  await implicitResponses();

  log.info("=== l. an application's certificate at /tls/sign-in ===");
  r = await tlsRequest("GET", RB + "/tls/sign-in", { tls: otherIssued.tls });
  check("l. an application's TLS client certificate at GET /tls/sign-in " +
        "verifies and starts NO browser session in its name", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.signedIn, false, r.text.slice(0, 300));
    assert.strictEqual(r.json.session.started, false);
    assert.strictEqual(r.json.session.application, "mtls-other");
  });
  log.debug("Leaving endpoints().");
}

// #1050's implicit half: a token minted on the browser's connection, which
// no certificate of the client's is on.
async function implicitResponses() {
  log.debug("Entering implicitResponses().");
  const CB = "https://mtls-implicit.example/cb";
  await create("mtls-implicit", { oauthTokenEndpointAuthMethod:
                                    "tls_client_auth",
                                  oauthRedirectUri: [CB] },
               { protocols: ["oauth2", "oidc"] });
  await ok(API + "/applications/create", { identifier: "mtls-implicit-api",
    kind: "oauth2-resource-server", protocols: ["oauth2"],
    fields: { oauthAudience: ["https://mtls-implicit.example/api"] } },
    "registered the other resource");
  const b = browser();
  const ask = function (resource) {
    return RB + "/oauth2/authorize?" + new URLSearchParams({
      client_id: "mtls-implicit", response_type: "token", redirect_uri: CB,
      state: "st-" + nodeCrypto.randomBytes(5).toString("hex"),
      resource: resource }).toString();
  };
  const before = await codeCount(REALM, "STS-OAUTH-0490");
  let landed = await follow(REALM, b, await b.go("GET",
    ask(RB + "/admin-api")), ALICE, PASSWORD);
  const after = await codeCount(REALM, "STS-OAUTH-0490", before);
  check("m10. an implicit response carrying an /admin-api token for a " +
        "tls_client_auth client is refused invalid_request, STS-OAUTH-0490",
        function () {
    assert.ok(String(landed.location).indexOf(CB) === 0, landed.status +
              " " + String(landed.location).slice(0, 300));
    assert.ok(/error=invalid_request/.test(landed.location), landed.location);
    assert.ok(!/access_token=/.test(landed.location));
    assert.ok(after > before, before + " -> " + after);
  });
  landed = await follow(REALM, b, await b.go("GET",
    ask("https://mtls-implicit.example/api")), ALICE, PASSWORD);
  check("m11. and the same client's implicit token for another resource is " +
        "still issued", function () {
    assert.ok(/access_token=/.test(landed.location), landed.status + " " +
              String(landed.location).slice(0, 300));
  });
  log.debug("Leaving implicitResponses().");
}

async function test() {
  log.debug("Entering test().");
  log.info("RFC 8705 over real handshakes at " + RB);
  const M = makeMaterial();
  let failure = null;
  try {
    await createRealm(REALM, "development", "RFC 8705");
    await ok(base + "/admin-api/realms/set", { id: REALM,
      key: "oauth2.openRegistration", value: "true" },
      "opened dynamic registration");
    await ok(base + "/admin-api/realms/set", { id: REALM,
      key: "oauth2.consentRequired", value: "false" },
      "turned consent off in the realm");
    await ok(API + "/users/create", { username: ALICE, invent: false,
      credential: "password", password: PASSWORD,
      attributes: { cn: "mtls alice", sn: "alice", givenName: "Mtls",
                    mail: ALICE + "@mtls.example" } }, "created " + ALICE);
    // The foreign CA, recorded before it is posted (#1307).
    const installed = await anchors.trustRecorded(base, M.caPem,
                                                  addedAnchors);
    assert.ok(installed.ok, "the foreign CA should be accepted as a client " +
              "trust anchor: " + JSON.stringify(installed).slice(0, 300));
    // THE NEXT HANDSHAKE IS JUDGED AGAINST THE NEW TRUSTSTORE, not one in
    // the same tick: wait until a leaf of that CA is verified.
    let seen = null;
    for (let i = 0; i < 40; i += 1) {
      seen = await tlsRequest("GET", base + "/admin-api/tls-connection",
        { tls: M.ext, headers: { authorization: "Bearer " +
                                   process.env.STS_ADMIN_API_TOKEN } });
      if (/"verified":\s*true/.test(seen.text)) {
        break;
      }
      await sleep(250);
    }
    log.info("the foreign CA is live: " + /"verified":\s*true/.test(
      (seen && seen.text) || ""));
    await endpoints(M);
  } catch (e) {
    log.debug("Caught in test(): " + ((e && e.message) || e));
    // Reported after the anchor and the files are gone.
    failure = e;
  }
  await anchors.settleAnchors(base, addedAnchors, failure);
  fs.rmSync(M.dir, { recursive: true, force: true });
  if (failure) {
    log.debug("Leaving test(). Failed.");
    throw failure;
  }
  assert.ok(checks >= 51, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.debug("Leaving test().");
}

main();
