"use strict";
//
// File: sts_ldaps.js
//
// ---------------------------------------------------------------------------
// THE DIRECTORY OVER LDAPS, AT THE ADDRESS THE SERVICE IS REACHED AT
// (2026-09-18).
//
// The embedded directory answers LDAP on 389 and LDAPS on 636. The bulk loads
// drive 389 in earnest; nothing drove 636 at all except a CRL fetch, so a
// deployment whose TLS listener for the directory was broken — a certificate
// that did not verify, a handshake that never completed behind a load
// balancer, a bind policy that disagreed between the two sockets — said
// nothing to this suite. This job connects over LDAPS the way a directory
// client does and asserts what each mode promises about it:
//
//   1. THE HANDSHAKE VERIFIES, with the trust this runner has for the rest of
//      the service, and 636 presents the SAME certificate as the HTTPS port —
//      `ldap/ldap_server.js` builds its secure listener from the record every
//      socket in the process shares, so two certificates would mean two
//      listeners disagreeing about who this service is.
//   2. A PERSON BINDS with their password over it, and searches their own
//      entry.
//   3. THE BIND POLICY. Product mode refuses an anonymous bind (48), a wrong
//      password (49) and a simple bind on the PLAIN listener (13,
//      confidentialityRequired — which is what makes 636 the door and not an
//      alternative), refuses a search on an unbound connection (50) with the
//      root DSE as the one exception, and never returns a credential
//      attribute. Development refuses none of it, and that is asserted too:
//      a job that only ever met a strict directory would not notice the mode
//      had stopped deciding anything.
//
// The person is created first through `/admin-api` with a real password, as
// product mode requires of everybody it signs in. The /admin-api token is
// attached by the runner (tests/tools/attach-admin-token.js).
//
// A LOCAL JOB (tests/vendored/MANIFEST.js): this repository's own directory
// and its own sockets.
// ---------------------------------------------------------------------------
const assert = require("assert");
const crypto = require("crypto");
const tls = require("tls");
const { Command, Option } = require("commander");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");
const facts = require("./service_facts.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // No appconfig file: the log level falls back to info, and the reason is
  // reported once the logger exists.
  appconfigProblem = e.message;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_ldaps",
  level: appconfig.logLevel || appconfig.LOG_LEVEL ||
         process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("No appconfig file was read: " + appconfigProblem);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const PERSON = ("ldaps-" + names.runStamp()).toLowerCase();
const PASSWORD = "Ldaps-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check(). " + what);
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function hostOf(url) {
  log.debug("Entering hostOf().");
  log.debug("Leaving hostOf().");
  return new URL(url).hostname;
}

// Where each socket is: the launcher's variable when it set one (a stack
// whose published address differs from the service URL's host), otherwise
// the service's own host on the standard port.
function ldapsUrl() {
  log.debug("Entering ldapsUrl().");
  log.debug("Leaving ldapsUrl().");
  return process.env.STS_LDAPS_URL ||
    ("ldaps://" + hostOf(base) + ":" + (process.env.STS_LDAPS_PORT || 636));
}

function ldapUrl() {
  log.debug("Entering ldapUrl().");
  log.debug("Leaving ldapUrl().");
  return process.env.STS_LDAP_URL ||
    ("ldap://" + hostOf(base) + ":" + (process.env.STS_LDAP_PORT || 389));
}

// One client per question, because in LDAP the connection IS the session
// (RFC 4511 section 4.2): a bind that failed or a bind that succeeded changes
// what the next operation on that connection is, so every check that is
// about the state of a connection starts from a new one.
function connect(url) {
  log.debug("Entering connect(). url=" + url);
  const client = ldapjs.createClient({
    url: url, reconnect: false, timeout: 20000, connectTimeout: 15000,
    // VERIFIED: the handshake is asserted against the trust this runner has
    // for the service (NODE_EXTRA_CA_CERTS for a stack's own Root; the
    // system store for a public certificate). An unverified connection would
    // make assertion 1 say nothing.
    tlsOptions: { rejectUnauthorized: true, servername: hostOf(url) }
  });
  client.on("error", function (e) {
    // ldapjs emits on the client as well as calling back, and an unhandled
    // 'error' is a process-level throw. The operation in flight reports it.
    log.debug("The LDAP client emitted an error: " + e.message);
  });
  log.debug("Leaving connect().");
  return client;
}

// A bind that settles either way: { ok, code, message }.
function bind(client, dn, password) {
  log.debug("Entering bind(). dn=" + dn);
  log.debug("Leaving bind().");
  return new Promise(function (resolve) {
    client.bind(dn, password, function (e) {
      resolve(e ? { ok: false, code: e.code, message: e.message }
                : { ok: true, code: 0, message: "" });
    });
  });
}

// A search that settles either way. ldapjs emits `error` and NEVER `end`
// for a search refused with a non-success code (tests/CLAUDE.md records the
// hang that taught this), so both settle it, and a deadline of its own
// stops a silent server from hanging the job.
function search(client, dn, options) {
  log.debug("Entering search(). dn=" + dn);
  log.debug("Leaving search().");
  return new Promise(function (resolve) {
    const entries = [];
    let settled = false;
    const done = function (outcome) {
      if (!settled) {
        settled = true;
        clearTimeout(deadline);
        resolve(outcome);
      }
    };
    const deadline = setTimeout(function () {
      done({ ok: false, code: -1, message: "no answer in 20s", entries: [] });
    }, 20000);
    client.search(dn, options, function (e, res) {
      if (e) {
        done({ ok: false, code: e.code, message: e.message, entries: [] });
        return;
      }
      res.on("searchEntry", function (entry) {
        entries.push(entry.pojo || entry.object || entry);
      });
      res.on("error", function (err) {
        done({ ok: false, code: err.code, message: err.message,
               entries: entries });
      });
      res.on("end", function (result) {
        const status = result ? result.status : 0;
        done({ ok: status === 0, code: status, message: "",
               entries: entries });
      });
    });
  });
}

function unbind(client) {
  log.debug("Entering unbind().");
  log.debug("Leaving unbind().");
  return new Promise(function (resolve) {
    try {
      client.unbind(function () {
        resolve(true);
      });
    } catch (e) {
      log.debug("Caught in unbind(): " + ((e && e.message) || e));
      // A connection the server already closed cannot be unbound, and that
      // is not what any check here is about.
      resolve(false);
    }
  });
}

// The attribute names an entry came back with, lower-cased. ldapjs 3 hands
// back `{ objectName, attributes: [{ type, values }] }`.
function attributeNames(entry) {
  log.debug("Entering attributeNames().");
  log.debug("Leaving attributeNames().");
  return ((entry && entry.attributes) || []).map(function (a) {
    return String(a.type || "").toLowerCase();
  });
}

function valuesOf(entry, name) {
  log.debug("Entering valuesOf(). " + name);
  const found = ((entry && entry.attributes) || []).filter(function (a) {
    return String(a.type || "").toLowerCase() === name.toLowerCase();
  })[0];
  log.debug("Leaving valuesOf().");
  return found ? [].concat(found.values || []) : [];
}

// The SHA-256 fingerprint of the certificate a TLS listener presents, read
// by a plain TLS handshake on its own.
function presentedFingerprint(host, port) {
  log.debug("Entering presentedFingerprint(). " + host + ":" + port);
  log.debug("Leaving presentedFingerprint().");
  return new Promise(function (resolve, reject) {
    const socket = tls.connect({ host: host, port: port, servername: host,
                                 rejectUnauthorized: true }, function () {
      const certificate = socket.getPeerCertificate();
      socket.end();
      resolve(certificate && certificate.fingerprint256);
    });
    socket.setTimeout(15000, function () {
      socket.destroy();
      reject(new Error("no TLS handshake from " + host + ":" + port));
    });
    socket.on("error", reject);
  });
}

async function createThePerson() {
  log.debug("Entering createThePerson().");
  const r = await fetch(base + "/admin-api/users/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: PERSON, invent: false,
      credential: "password", password: PASSWORD,
      attributes: { cn: "LDAPS " + PERSON, givenName: "LDAPS", sn: PERSON,
                    displayName: "LDAPS " + PERSON,
                    mail: PERSON + "@ldaps.test" } }) });
  const body = await r.json();
  assert.ok(r.status === 200 && body && body.ok && body.dn,
    "POST /admin-api/users/create should create " + PERSON + " with a " +
    "password and name its DN; it answered " + r.status + " " +
    JSON.stringify(body).slice(0, 300));
  log.debug("Leaving createThePerson(). " + body.dn);
  return String(body.dn);
}

async function test() {
  log.debug("Entering test().");
  const product = await facts.isProduct(base + "/admin-api");
  log.info("LDAPS at " + ldapsUrl() + ", LDAP at " + ldapUrl() + ", the " +
           "service in " + (product ? "PRODUCT" : "development") + " mode.");
  const dn = await createThePerson();

  // --- 1. the handshake, and the certificate it presents -----------------
  const httpsPort = Number(new URL(base).port || 443);
  const ldapsHost = hostOf(ldapsUrl());
  const ldapsPort = Number(new URL(ldapsUrl()).port || 636);
  const onHttps = await presentedFingerprint(hostOf(base), httpsPort);
  const onLdaps = await presentedFingerprint(ldapsHost, ldapsPort);
  check("the LDAPS handshake VERIFIES with this runner's trust", function () {
    assert.ok(onLdaps, "no certificate was presented on " + ldapsUrl());
  });
  check("and 636 presents the same certificate as the HTTPS port", function () {
    assert.strictEqual(onLdaps, onHttps,
      "the directory's TLS listener and the HTTPS port present different " +
      "certificates (" + onLdaps + " against " + onHttps + "); they are " +
      "built from one record, so two means two listeners disagreeing about " +
      "who this service is.");
  });

  // --- 2. a person binds and reads their own entry -----------------------
  let client = connect(ldapsUrl());
  const bound = await bind(client, dn, PASSWORD);
  check("a person binds over LDAPS with their password", function () {
    assert.ok(bound.ok, "binding as " + dn + " answered " + bound.code +
              " " + bound.message);
  });
  const own = await search(client, dn, { scope: "base",
                                         filter: "(objectClass=*)",
                                         attributes: ["*"] });
  check("and searches their own entry", function () {
    assert.ok(own.ok && own.entries.length === 1,
      "a base search of " + dn + " answered " + own.code + " " + own.message +
      " with " + own.entries.length + " entr(ies).");
    assert.deepStrictEqual(valuesOf(own.entries[0], "uid"), [PERSON],
      "the entry should be the person's own; it carried uid " +
      JSON.stringify(valuesOf(own.entries[0], "uid")));
    assert.deepStrictEqual(valuesOf(own.entries[0], "mail"),
                           [PERSON + "@ldaps.test"],
      "and the attributes the management API wrote.");
  });
  if (product) {
    check("PRODUCT: no credential attribute comes back, even to its owner",
          function () {
      const held = attributeNames(own.entries[0]);
      assert.ok(held.indexOf("userpassword") < 0 &&
                held.indexOf("pwdhistory") < 0,
        "a search returned a credential attribute: " + held.join(", "));
    });
  }
  await unbind(client);

  // --- 3. the bind policy ------------------------------------------------
  client = connect(ldapsUrl());
  const wrong = await bind(client, dn, PASSWORD + "-not");
  await unbind(client);
  check(product ? "PRODUCT: a wrong password is refused 49 " +
                  "(invalidCredentials)"
                : "development: a wrong password is still accepted",
        function () {
    if (product) {
      assert.ok(!wrong.ok && wrong.code === 49,
        "a wrong password answered " + wrong.code + " " + wrong.message);
    } else {
      assert.ok(wrong.ok, "development mode refuses no bind; this one " +
                "answered " + wrong.code + " " + wrong.message);
    }
  });

  client = connect(ldapsUrl());
  const anonymous = await bind(client, "", "");
  // Asked on the SAME connection: whatever the bind answered, an anonymous
  // connection must not be able to read the directory in product mode.
  const afterAnonymous = await search(client, dn,
    { scope: "base", filter: "(objectClass=*)" });
  await unbind(client);
  if (product) {
    check("PRODUCT: after an anonymous bind, a search on that connection is " +
          "refused 50", function () {
      assert.ok(!afterAnonymous.ok && afterAnonymous.code === 50,
        "a search after an anonymous bind answered " + afterAnonymous.code +
        " " + afterAnonymous.message);
    });
  }
  check(product ? "PRODUCT: an anonymous bind is refused 48 " +
                  "(inappropriateAuthentication)"
                : "development: an anonymous bind is accepted", function () {
    if (product) {
      assert.ok(!anonymous.ok && anonymous.code === 48,
        "an anonymous bind answered " + anonymous.code + " " +
        anonymous.message);
    } else {
      assert.ok(anonymous.ok, "it answered " + anonymous.code + " " +
                anonymous.message);
    }
  });

  client = connect(ldapsUrl());
  const unbound = await search(client, dn, { scope: "base",
                                             filter: "(objectClass=*)" });
  const rootDse = await search(client, "", { scope: "base",
                                             filter: "(objectClass=*)" });
  await unbind(client);
  check(product ? "PRODUCT: a search on an unbound connection is refused " +
                  "50 (insufficientAccessRights)"
                : "development: an unbound connection may search",
        function () {
    if (product) {
      assert.ok(!unbound.ok && unbound.code === 50,
        "an unbound search answered " + unbound.code + " " + unbound.message);
    } else {
      assert.ok(unbound.ok && unbound.entries.length === 1,
        "it answered " + unbound.code + " " + unbound.message);
    }
  });
  check("and the root DSE answers an unbound connection in every mode",
        function () {
    assert.ok(rootDse.ok && rootDse.entries.length === 1,
      "the root DSE answered " + rootDse.code + " " + rootDse.message);
  });

  // --- 4. the same bind on the PLAIN listener ----------------------------
  client = connect(ldapUrl());
  const plain = await bind(client, dn, PASSWORD);
  await unbind(client);
  check(product ? "PRODUCT: the same bind on the plain listener is refused " +
                  "13 (confidentialityRequired) — LDAPS is the door"
                : "development: the same bind on the plain listener is " +
                  "accepted", function () {
    if (product) {
      assert.ok(!plain.ok && plain.code === 13,
        "a simple bind on " + ldapUrl() + " answered " + plain.code + " " +
        plain.message);
    } else {
      assert.ok(plain.ok, "it answered " + plain.code + " " + plain.message);
    }
  });

  // A FLOOR on the count: a section that stops running must fail the job.
  assert.ok(checks >= (product ? 11 : 9),
    "only " + checks + " checks ran; a section stopped running.");
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                  "ignored; kept for a uniform CLI across the suite"));
program.parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
