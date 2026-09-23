"use strict";
//
// File: sts_kerberos_rc4.js
//
// ---------------------------------------------------------------------------
// RC4-HMAC AND DIGEST MD5 ARE DEVELOPMENT'S (#182, 2026-09-23).
//
// RFC 8429 deprecates rc4-hmac (enctype 23), and RFC 7616 keeps MD5 in HTTP
// Digest for backward compatibility only. Product honoured both: the
// default `krb5.enctypes` gave every krbtgt, service and person an RC4 key,
// and `scim.digestMd5` was on by default. Both are now #104's machinery —
// `usesBrokenAlgorithms()` in `common/mode.js`, the `onlyWhile` marker (on
// the ELEMENT `23` of the csv row, `onlyWhileValues`), refused on write
// (STS-CORE-0103) and ignored where read (STS-CORE-0106). This job drives
// both over the wire, against the service's own KDC on TCP 88, in whatever
// mode the service was started in, and in two throwaway realms (one each
// way) for what a realm can carry:
//
//   1. AS EXCHANGES offering only 23: product refuses the bare AS-REQ
//      KDC_ERR_ETYPE_NOSUPP naming product mode; development issues a TGT
//      whose enc-part is sealed with RC4. Offering 23 then 18, product
//      answers with 18 and development honours the client's order with 23.
//      An AES-only exchange gets a TGT in both.
//   2. TGS EXCHANGES for the acceptor's service principal: offering only 23
//      is KDC_ERR_ETYPE_NOSUPP in product and a ticket in development; an
//      AES request whose Authenticator carries an RC4 SUBKEY is refused in
//      product and answered under that subkey in development.
//   3. THE ACCEPTOR: an AP-REQ at `/authn/spnego` whose initiator subkey is
//      RC4 is refused in product (401, KDC_ERR_ETYPE_NOSUPP in the reject
//      token) and accepted in development.
//   4. FAST ARMOR with an RC4 subkey: refused in product before any armor
//      key is made; accepted as armor in development.
//   5. THE PERSON'S KEYTAB from `reset-person-keytab`: no RC4 key in
//      product; an RC4 key beside the AES ones in development.
//   6. MIT `kinit` with `permitted_enctypes = rc4-hmac`, wherever MIT
//      Kerberos is installed: refused in product, a TGT in development.
//   7. THE SETTINGS, in the two realms: `krb5.enctypes` naming 23 and
//      `scim.digestMd5` on are refused in the product realm and accepted in
//      the development one; `/admin-api/mode` lists both, with 23 dropped from
//      the value in force in product.
//   8. SCIM DIGEST: the development realm offers no MD5 by default and
//      refuses an MD5 credential; with `scim.digestMd5` on it offers MD5 and
//      accepts a correct MD5 credential. The product realm offers no Digest
//      at all.
//
// WHAT IT CHANGES ON THE SERVICE: one person, created here (its password is
// reset by section 5), and two realms it leaves standing
// (`leave-test-created-realms`).
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const childProcess = require("child_process");
const nodeCrypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");
const registry = require("./sts_applications.js");
const wire = require("./krb5_wire.js");
const { declineToRun } = require("./expectation.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads,
  // for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_kerberos_rc4",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";

const USER = names.usernameFor("krb5-rc4");
const PASSWORD = "Krb5-Rc4-Passw0rd!-" + String(Date.now()).slice(-6);
const RESET_PASSWORD = "Krb5-Rc4-Reset-Passw0rd!-" +
                       String(Date.now()).slice(-6);
const STAMP = names.runStamp();
const DEV = ("rc4md5-d-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const PROD = ("rc4md5-p-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const RC4 = 23;
const AES256 = 18;

// How long a product person's keys may take to reach the node that answers
// (sts_kerberos_spnego.js's KEYS_WAIT_MS, for its reason).
const KEYS_WAIT_MS = 20000;

const K = { product: false, realm: "", kdcHost: "", kdcPort: 88,
            servicePrincipal: "", password: "", spnegoOn: true };

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function call(method, url, body, headers) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call(). HTTP " + r.status);
  return { status: r.status, json: json, text: text, headers: r.headers };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function realmBase(id) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + id;
}

// The KRB-ERROR of an exchange's first or second round trip.
function refusal(result) {
  log.debug("Entering refusal().");
  log.debug("Leaving refusal().");
  return (result.second && result.second.error) ||
         (result.first && result.first.error) || null;
}

// An AS exchange for the person, retried through product mode's window (the
// keys reaching the node that answers) — and only while the refusal says the
// keys are not there yet.
async function asForThePerson(opts) {
  log.debug("Entering asForThePerson().");
  const tcp = wire.tcpTransport(K.kdcHost, K.kdcPort);
  const options = Object.assign({ password: K.password }, opts || {});
  const started = Date.now();
  let result = await wire.asExchange(tcp, K.realm, USER, options);
  const waiting = function (r) {
    log.debug("Entering waiting().");
    const e = refusal(r);
    const again = !!(K.product && !r.tgt && e &&
                     /no Kerberos keys yet|sign in once|nobody by that name/i
                       .test(e.eText) && Date.now() - started < KEYS_WAIT_MS);
    log.debug("Leaving waiting(). " + again);
    return again;
  };
  while (waiting(result)) {
    await pause(500);
    result = await wire.asExchange(tcp, K.realm, USER, options);
  }
  log.debug("Leaving asForThePerson().");
  return result;
}

// ---------------------------------------------------------------------------
// 0. THE SERVICE, THE PERSON AND THE TWO REALMS.
// ---------------------------------------------------------------------------
async function learnTheService() {
  log.debug("Entering learnTheService().");
  K.product = await facts.isProduct(api);
  K.realm = String(process.env.KRB5_REALM ||
                   await facts.setting(api, "krb5.realm") || "");
  K.kdcHost = process.env.STS_KDC_HOST || new URL(base).hostname;
  K.kdcPort = Number(process.env.STS_KDC_PORT ||
                     await facts.setting(api, "krb5.kdcPort") || 88);
  K.servicePrincipal = String(
    await facts.setting(api, "krb5.servicePrincipal") || "");
  const spnegoOn = await facts.setting(api, "krb5.spnegoAuthentication");
  K.spnegoOn = spnegoOn !== false && String(spnegoOn) !== "false";
  K.password = K.product ? PASSWORD :
    String(await facts.setting(api, "krb5.userPassword") || "password!");
  const enabled = await facts.setting(api, "krb5.enabled");
  log.info("mode " + (K.product ? "product" : "development") + ", realm " +
           K.realm + ", KDC " + K.kdcHost + ":" + K.kdcPort);
  check("the service has Kerberos on and names a realm and a service " +
        "principal", function () {
    assert.ok(enabled === true || String(enabled) === "true",
              "krb5.enabled is " + JSON.stringify(enabled));
    assert.ok(K.realm, "krb5.realm is empty");
    assert.ok(K.servicePrincipal.indexOf("/") > 0,
              "krb5.servicePrincipal is " +
              JSON.stringify(K.servicePrincipal));
  });
  await registry.ensurePerson(base, USER, PASSWORD);
  await ok(api + "/realms/create",
           { id: PROD, domain: PROD + ".example.net", name: "#182 product",
             overrides: { "global.mode": "product" } },
           "created the product realm");
  await ok(api + "/realms/create",
           { id: DEV, domain: DEV + ".example.net", name: "#182 development",
             overrides: { "global.mode": "development" } },
           "created the development realm");
  log.debug("Leaving learnTheService().");
}

// ---------------------------------------------------------------------------
// 1. THE AS EXCHANGE.
// ---------------------------------------------------------------------------
async function asExchanges() {
  log.debug("Entering asExchanges().");
  log.info("=== 1. AS exchanges offering rc4-hmac ===");
  const aes = await asForThePerson({ etypes: [AES256] });
  check("an AS exchange offering only aes256 gets a TGT for " + USER,
        function () {
    assert.ok(aes.tgt, "no TGT: " + JSON.stringify(refusal(aes)));
    assert.strictEqual(aes.tgt.replyEtype, AES256, "the reply's enctype");
  });
  const only = await asForThePerson({ etypes: [RC4] });
  if (K.product) {
    check("PRODUCT: the bare AS-REQ offering only rc4-hmac is refused " +
          "KDC_ERR_ETYPE_NOSUPP, naming product mode, with no TGT",
          function () {
      assert.ok(!only.tgt, "a TGT was issued over rc4-hmac");
      assert.ok(only.first && only.first.error, JSON.stringify(only.first));
      assert.strictEqual(only.first.error.code, 14,
                         only.first.error.toString());
      assert.ok(/product mode/.test(only.first.error.eText) &&
                /RFC 8429/.test(only.first.error.eText),
                only.first.error.eText);
    });
  } else {
    check("DEVELOPMENT: offering only rc4-hmac gets a TGT whose enc-part is " +
          "sealed with the RC4 key", function () {
      assert.ok(only.tgt, "no TGT: " + JSON.stringify(refusal(only)));
      assert.strictEqual(only.info.etype, RC4, "ETYPE-INFO2's enctype");
      assert.strictEqual(only.tgt.replyEtype, RC4, "the reply's enctype");
    });
  }
  const both = await asForThePerson({ etypes: [RC4, AES256] });
  check((K.product ? "PRODUCT" : "DEVELOPMENT") + ": offering rc4-hmac " +
        "first and aes256 second, the exchange uses " +
        (K.product ? "aes256 — RC4 is not offered at all"
                   : "rc4-hmac, the client's first choice"), function () {
    assert.ok(both.tgt, "no TGT: " + JSON.stringify(refusal(both)));
    assert.strictEqual(both.info.etype, K.product ? AES256 : RC4,
                       "ETYPE-INFO2 / the chosen enctype");
    assert.strictEqual(both.tgt.replyEtype, K.product ? AES256 : RC4);
  });
  log.debug("Leaving asExchanges().");
  return aes.tgt;
}

// ---------------------------------------------------------------------------
// 2. THE TGS EXCHANGE, for the acceptor's service principal.
// ---------------------------------------------------------------------------
async function tgsExchanges(tgt) {
  log.debug("Entering tgsExchanges().");
  log.info("=== 2. TGS exchanges for " + K.servicePrincipal + " ===");
  const tcp = wire.tcpTransport(K.kdcHost, K.kdcPort);
  const sname = { type: wire.msgs.NAME_TYPE.SRV_HST,
                  name: K.servicePrincipal.split("/") };
  const aes = await wire.tgsExchange(tcp, tgt, sname);
  check("an AES TGS-REQ gets a ticket for " + K.servicePrincipal,
        function () {
    assert.ok(aes.ok, "refused: " + (aes.error && aes.error.toString()));
  });
  const only = await wire.tgsExchange(tcp, tgt, sname, null,
                                      { etypes: [RC4] });
  const subkeyed = await wire.tgsExchange(tcp, tgt, sname, null,
                                          { subkeyEtype: RC4 });
  if (K.product) {
    check("PRODUCT: a TGS-REQ offering only rc4-hmac is refused " +
          "KDC_ERR_ETYPE_NOSUPP, naming product mode", function () {
      assert.ok(!only.ok, "a ticket was issued over rc4-hmac");
      assert.strictEqual(only.error.code, 14, only.error.toString());
      assert.ok(/product mode/.test(only.error.eText), only.error.eText);
    });
    check("PRODUCT: an AES TGS-REQ whose Authenticator carries an rc4-hmac " +
          "subkey is refused KDC_ERR_ETYPE_NOSUPP", function () {
      assert.ok(!subkeyed.ok, "a reply was sealed under an RC4 subkey");
      assert.strictEqual(subkeyed.error.code, 14, subkeyed.error.toString());
      assert.ok(/subkey/.test(subkeyed.error.eText), subkeyed.error.eText);
    });
  } else {
    check("DEVELOPMENT: a TGS-REQ offering only rc4-hmac gets a ticket",
          function () {
      assert.ok(only.ok, "refused: " + (only.error && only.error.toString()));
      assert.strictEqual(only.etype, RC4, "the ticket's session key");
    });
    check("DEVELOPMENT: an rc4-hmac Authenticator subkey is used — the " +
          "reply opens under it at key usage 9", function () {
      assert.ok(subkeyed.ok, "refused: " +
                (subkeyed.error && subkeyed.error.toString()));
    });
  }
  log.debug("Leaving tgsExchanges().");
  return aes;
}

// ---------------------------------------------------------------------------
// 3. THE ACCEPTOR, at the SPNEGO sign-in door.
// ---------------------------------------------------------------------------
async function theAcceptor(ticket) {
  log.debug("Entering theAcceptor().");
  log.info("=== 3. an AP-REQ with an rc4-hmac initiator subkey ===");
  if (!K.spnegoOn) {
    log.info("  krb5.spnegoAuthentication is off here; section skipped.");
    log.debug("Leaving theAcceptor(). Skipped.");
    return;
  }
  const built = await wire.apRequest(ticket, { subkeyEtype: RC4 });
  const token = await wire.negTokenInit(built, {});
  const r = await fetch(base + "/authn/spnego", { redirect: "manual",
    headers: { Authorization: "Negotiate " +
                              Buffer.from(token).toString("base64") } });
  const body = await r.text();
  const header = r.headers.get("www-authenticate") || "";
  if (K.product) {
    const reply = await wire.readNegotiate(header, ticket, built);
    check("PRODUCT: the acceptor refuses an rc4-hmac initiator subkey — " +
          "401, KDC_ERR_ETYPE_NOSUPP in the reject token", function () {
      assert.strictEqual(r.status, 401, body.slice(0, 300));
      assert.ok(reply && reply.error, "no KRB-ERROR in the reject token: " +
                header.slice(0, 200));
      assert.strictEqual(reply.error.code, 14, reply.error.toString());
    });
  } else {
    check("DEVELOPMENT: the acceptor accepts an rc4-hmac initiator subkey " +
          "— 200", function () {
      assert.strictEqual(r.status, 200, body.slice(0, 300));
    });
  }
  log.debug("Leaving theAcceptor().");
}

// ---------------------------------------------------------------------------
// 4. FAST ARMOR with an rc4-hmac subkey.
// ---------------------------------------------------------------------------
async function fastArmor(tgt) {
  log.debug("Entering fastArmor().");
  log.info("=== 4. FAST armor with an rc4-hmac subkey ===");
  const tcp = wire.tcpTransport(K.kdcHost, K.kdcPort);
  const none = async function () {
    log.debug("Entering none().");
    log.debug("Leaving none().");
    return [];
  };
  const rc4 = await wire.fastAsExchange(tcp, K.realm, USER, tgt, none,
                                        { subkeyEtype: RC4 });
  if (K.product) {
    check("PRODUCT: FAST armor whose subkey is rc4-hmac is refused " +
          "KDC_ERR_ETYPE_NOSUPP before any armor key is made (unarmored)",
          function () {
      assert.ok(!rc4.ok, "an AS-REP came back");
      assert.strictEqual(rc4.armored, false, "the refusal was armored");
      assert.strictEqual(rc4.code, 14, rc4.code + " " + rc4.eText);
      assert.ok(/armor subkey/.test(rc4.eText), rc4.eText);
    });
  } else {
    check("DEVELOPMENT: FAST armor with an rc4-hmac subkey is accepted — " +
          "the answer is armored under it", function () {
      assert.strictEqual(rc4.armored, true,
                         "not armored: " + rc4.code + " " + rc4.eText);
    });
  }
  log.debug("Leaving fastArmor().");
}

// ---------------------------------------------------------------------------
// 5. THE PERSON'S KEYTAB.
// ---------------------------------------------------------------------------
async function theKeytab() {
  log.debug("Entering theKeytab().");
  log.info("=== 5. the person's keytab ===");
  const r = await call("POST", api + "/kerberos/principals/" +
                                     "reset-person-keytab",
                       { username: USER, password: RESET_PASSWORD });
  check("reset-person-keytab answers a keytab", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(r.json && r.json.keytab, r.text.slice(0, 300));
  });
  const etypes = wire.readKeytab(Buffer.from(r.json.keytab, "base64"))
    .map(function (one) {
      return one.etype;
    });
  check((K.product ? "PRODUCT: the keytab holds no rc4-hmac key"
                   : "DEVELOPMENT: the keytab holds an rc4-hmac key") +
        " beside aes256 (" + etypes.join(",") + ")", function () {
    assert.ok(etypes.indexOf(AES256) >= 0, etypes.join(","));
    assert.strictEqual(etypes.indexOf(RC4) >= 0, !K.product,
                       etypes.join(","));
  });
  if (K.product) {
    K.password = RESET_PASSWORD;
  }
  log.debug("Leaving theKeytab().");
}

// ---------------------------------------------------------------------------
// 6. MIT KINIT RESTRICTED TO RC4.
// ---------------------------------------------------------------------------
function hasMit() {
  log.debug("Entering hasMit().");
  const r = childProcess.spawnSync("sh", ["-c", "command -v kinit"],
                                   { encoding: "utf8" });
  log.debug("Leaving hasMit().");
  return r.status === 0 && /kinit/.test(r.stdout || "");
}

async function mitKinit() {
  log.debug("Entering mitKinit().");
  log.info("=== 6. MIT kinit with permitted_enctypes = rc4-hmac ===");
  if (!hasMit() || process.env.STS_KRB5_MIT === "off") {
    log.info("  MIT Kerberos (kinit) is not installed here, so this section " +
             "is SKIPPED; section 1 drove the same exchange with this job's " +
             "own client.");
    log.debug("Leaving mitKinit(). Skipped.");
    return;
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "krb5-rc4-"));
  try {
    const conf = path.join(dir, "krb5.conf");
    fs.writeFileSync(conf, "[libdefaults]\n default_realm = " + K.realm +
      "\n dns_lookup_kdc = false\n dns_lookup_realm = false\n" +
      " udp_preference_limit = 1\n rdns = false\n" +
      " allow_weak_crypto = true\n allow_rc4 = true\n" +
      " permitted_enctypes = rc4-hmac\n default_tkt_enctypes = rc4-hmac\n" +
      " default_tgs_enctypes = rc4-hmac\n\n[realms]\n " + K.realm +
      " = {\n  kdc = " + K.kdcHost + ":" + K.kdcPort + "\n }\n");
    const env = Object.assign({}, process.env, {
      KRB5_CONFIG: conf, KRB5CCNAME: "FILE:" + path.join(dir, "cc"),
      KRB5_TRACE: path.join(dir, "trace") });
    const started = Date.now();
    let run = null;
    for (;;) {
      run = childProcess.spawnSync("kinit", [USER + "@" + K.realm], {
        env: env, input: K.password + "\n", encoding: "utf8",
        timeout: 60000 });
      const out = String(run.stdout || "") + String(run.stderr || "");
      if (run.status === 0 || !K.product ||
          !/not found in Kerberos database|keys yet/i.test(out) ||
          Date.now() - started > KEYS_WAIT_MS) {
        break;
      }
      await pause(500);
    }
    const out = String(run.stdout || "") + String(run.stderr || "");
    if (K.product) {
      check("PRODUCT: MIT kinit restricted to rc4-hmac is refused — the KDC " +
            "has no support for that encryption type", function () {
        assert.notStrictEqual(run.status, 0, out);
        assert.ok(/encryption type|enctype/i.test(out), out);
      });
    } else {
      check("DEVELOPMENT: MIT kinit restricted to rc4-hmac gets a TGT",
            function () {
        assert.strictEqual(run.status, 0, out);
      });
    }
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // A temporary directory left behind is not what this job tests.
      log.debug("Caught in mitKinit(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving mitKinit().");
}

// ---------------------------------------------------------------------------
// 7. THE SETTINGS, in the two realms.
// ---------------------------------------------------------------------------
function rowOf(report, key) {
  log.debug("Entering rowOf(). " + key);
  log.debug("Leaving rowOf().");
  return ((report && report.developmentOnlySettings) || []).filter(
    function (row) {
      return row.key === key;
    })[0] || null;
}

async function theSettings() {
  log.debug("Entering theSettings().");
  log.info("=== 7. krb5.enctypes and scim.digestMd5 in each realm ===");
  const enc = await call("POST", api + "/realms/set",
                         { id: PROD, key: "krb5.enctypes", value: "18,23" });
  check("product realm: realms/set krb5.enctypes=18,23 is refused, naming " +
        "product mode", function () {
    assert.strictEqual(enc.status, 400, enc.text.slice(0, 300));
    assert.ok(/product mode/.test(enc.text) &&
              enc.text.indexOf("krb5.enctypes") >= 0, enc.text.slice(0, 300));
  });
  await ok(api + "/realms/set", { id: PROD, key: "krb5.enctypes",
                                  value: "18,20" },
           "product realm: krb5.enctypes=18,20 (no RC4)");
  check("product realm: krb5.enctypes=18,20 is accepted", function () {
    assert.ok(true);
  });
  await ok(api + "/realms/set", { id: DEV, key: "krb5.enctypes",
                                  value: "18,23" },
           "development realm: krb5.enctypes=18,23");
  check("development realm: krb5.enctypes=18,23 is accepted", function () {
    assert.ok(true);
  });
  const md5 = await call("POST", realmBase(PROD) + "/admin-api/config/set",
                         { key: "scim.digestMd5", value: true });
  check("product realm: config/set scim.digestMd5=true is refused, naming " +
        "product mode", function () {
    assert.strictEqual(md5.status, 400, md5.text.slice(0, 300));
    assert.ok(/product mode/.test(md5.text), md5.text.slice(0, 300));
  });
  const prodMode = await call("GET", realmBase(PROD) + "/admin-api/mode");
  const devMode = await call("GET", realmBase(DEV) + "/admin-api/mode");
  check("/admin-api/mode: krb5.enctypes and scim.digestMd5 are listed as " +
        "development-only in both realms", function () {
    [prodMode, devMode].forEach(function (r) {
      assert.strictEqual(r.status, 200, r.text.slice(0, 200));
      assert.ok(rowOf(r.json, "krb5.enctypes"), "no krb5.enctypes row");
      assert.ok(rowOf(r.json, "scim.digestMd5"), "no scim.digestMd5 row");
    });
    assert.ok((prodMode.json.requirements || []).some(function (row) {
      return row.id === "kerberos-deprecated-enctypes";
    }), "no kerberos-deprecated-enctypes requirement");
  });
  const devRow = rowOf(devMode.json, "krb5.enctypes");
  check("development realm: 23 is in force (" +
        JSON.stringify(devRow.inForce) + ")", function () {
    assert.ok(devRow.inForce.indexOf("23") >= 0 && !devRow.ignored,
              JSON.stringify(devRow));
  });
  // Switched to product with 23 STILL stored: read without it.
  await ok(api + "/realms/set", { id: DEV, key: "global.mode",
                                  value: "product" },
           "switched the development realm to product");
  const switched = await call("GET", realmBase(DEV) + "/admin-api/mode");
  const row = rowOf(switched.json, "krb5.enctypes");
  check("switched to product with 18,23 still stored, /admin-api/mode " +
        "lists krb5.enctypes as IGNORED and 18 alone in force", function () {
    assert.ok(row && row.ignored === true, JSON.stringify(row));
    assert.deepStrictEqual(row.inForce, ["18"], JSON.stringify(row));
  });
  await ok(api + "/realms/set", { id: DEV, key: "global.mode",
                                  value: "development" },
           "switched it back to development");
  log.debug("Leaving theSettings().");
}

// ---------------------------------------------------------------------------
// 8. SCIM DIGEST, in the two realms.
// ---------------------------------------------------------------------------
function md5(text) {
  log.debug("Entering md5().");
  log.debug("Leaving md5().");
  return nodeCrypto.createHash("md5").update(text, "utf8").digest("hex");
}

// Every `Digest` challenge a 401 carries, with its parameters.
function digestChallenges(res) {
  log.debug("Entering digestChallenges().");
  const lines = [];
  res.headers.forEach(function (value, name) {
    if (name.toLowerCase() === "www-authenticate") {
      lines.push(value);
    }
  });
  const out = [];
  lines.join(", ").split(/(?=\bDigest\s)/).forEach(function (piece) {
    if (!/^Digest\s/.test(piece)) {
      return;
    }
    const params = {};
    const re = /(\w+)=(?:"([^"]*)"|([^\s,]+))/g;
    let m;
    while ((m = re.exec(piece)) !== null) {
      params[m[1].toLowerCase()] = m[2] !== undefined ? m[2] : m[3];
    }
    out.push(params);
  });
  log.debug("Leaving digestChallenges(). " + out.length);
  return out;
}

async function scimGet(realm, authorization) {
  log.debug("Entering scimGet().");
  const headers = { Accept: "application/scim+json" };
  if (authorization) {
    headers.Authorization = authorization;
  }
  // No bearer token rides along: the suite's attach-admin-token preload adds
  // one only to /admin-api.
  const r = await fetch(realmBase(realm) + "/scim/v2/Users?count=1",
                        { headers: headers, redirect: "manual" });
  const text = await r.text();
  log.debug("Leaving scimGet(). HTTP " + r.status);
  return { status: r.status, text: text, headers: r.headers };
}

// An RFC 7616 MD5 credential answering `challenge` for GET `uri`.
function md5Credential(challenge, uri, password) {
  log.debug("Entering md5Credential().");
  const user = "rc4md5-scim";
  const cnonce = nodeCrypto.randomBytes(8).toString("hex");
  const nc = "00000001";
  const ha1 = md5(user + ":" + challenge.realm + ":" + password);
  const ha2 = md5("GET:" + uri);
  const response = md5(ha1 + ":" + challenge.nonce + ":" + nc + ":" +
                       cnonce + ":auth:" + ha2);
  log.debug("Leaving md5Credential().");
  return "Digest username=\"" + user + "\", realm=\"" + challenge.realm +
    "\", nonce=\"" + challenge.nonce + "\", uri=\"" + uri +
    "\", algorithm=MD5, qop=auth, nc=" + nc + ", cnonce=\"" + cnonce +
    "\", response=\"" + response + "\"" +
    (challenge.opaque ? ", opaque=\"" + challenge.opaque + "\"" : "");
}

async function scimDigest() {
  log.debug("Entering scimDigest().");
  log.info("=== 8. SCIM HTTP Digest and MD5 ===");
  const uri = "/realm/" + DEV + "/scim/v2/Users?count=1";
  const password = String(await facts.setting(realmBase(DEV) + "/admin-api",
                                              "scim.digestPassword") ||
                          "password!");
  const off = await scimGet(DEV);
  const offered = digestChallenges(off);
  check("development realm, scim.digestMd5 at its default (off): Digest is " +
        "offered with SHA-256 and SHA-512-256 and without MD5", function () {
    assert.strictEqual(off.status, 401, off.text.slice(0, 200));
    const algs = offered.map(function (c) {
      return c.algorithm;
    });
    assert.ok(algs.indexOf("SHA-256") >= 0, algs.join(","));
    assert.ok(algs.indexOf("MD5") < 0, algs.join(","));
  });
  const refusedMd5 = await scimGet(DEV, md5Credential(offered[0], uri,
                                                      password));
  check("development realm, MD5 off: a correct MD5 credential is refused, " +
        "401, naming scim.digestMd5", function () {
    assert.strictEqual(refusedMd5.status, 401, refusedMd5.text.slice(0, 200));
    assert.ok(/scim\.digestMd5/.test(refusedMd5.text),
              refusedMd5.text.slice(0, 300));
  });
  await ok(realmBase(DEV) + "/admin-api/config/set",
           { key: "scim.digestMd5", value: true },
           "development realm: scim.digestMd5=true");
  const on = await scimGet(DEV);
  const md5Challenge = digestChallenges(on).filter(function (c) {
    return c.algorithm === "MD5";
  })[0];
  check("development realm, scim.digestMd5 on: MD5 is offered, last",
        function () {
    assert.ok(md5Challenge, JSON.stringify(digestChallenges(on)));
  });
  const accepted = await scimGet(DEV, md5Credential(md5Challenge, uri,
                                                    password));
  check("development realm, MD5 on: a correct MD5 credential is accepted, " +
        "200", function () {
    assert.strictEqual(accepted.status, 200, accepted.text.slice(0, 300));
  });
  await call("POST", realmBase(DEV) + "/admin-api/config/reset",
             { key: "scim.digestMd5" });
  const prod = await scimGet(PROD);
  check("product realm: no Digest challenge at all", function () {
    assert.strictEqual(prod.status, 401, prod.text.slice(0, 200));
    assert.strictEqual(digestChallenges(prod).length, 0,
                       JSON.stringify(digestChallenges(prod)));
  });
  const prodMd5 = await scimGet(PROD, md5Credential(
    { realm: "SCIM", nonce: "n" }, "/realm/" + PROD + "/scim/v2/Users?count=1",
    password));
  check("product realm: an MD5 Digest credential is refused, 401, Digest " +
        "not offered in product mode", function () {
    assert.strictEqual(prodMd5.status, 401, prodMd5.text.slice(0, 200));
    assert.ok(/not offered in product mode/.test(prodMd5.text),
              prodMd5.text.slice(0, 300));
  });
  log.debug("Leaving scimDigest().");
}

async function test() {
  log.debug("Entering test().");
  if (String(process.env.STS_TEST_UNPUBLISHED || "").split(",")
        .indexOf("kerberos") >= 0) {
    declineToRun(log, "this environment does not publish the KDC's TCP 88 " +
                      "(STS_TEST_UNPUBLISHED names kerberos).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("Driving rc4-hmac and Digest MD5 at " + base);
  await learnTheService();
  const tgt = await asExchanges();
  const ticket = await tgsExchanges(tgt);
  await theAcceptor(ticket);
  await fastArmor(tgt);
  await theKeytab();
  await mitKinit();
  await theSettings();
  await scimDigest();
  const floor = 22;
  assert.ok(checks >= floor, "only " + checks + " checks ran (floor " +
            floor + "); a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_rc4")
  .description("#182: rc4-hmac in krb5.enctypes and MD5 in SCIM Digest are " +
    "development's — refused over TCP 88, at the acceptor, in FAST armor, " +
    "in a keytab and by MIT kinit in product; refused on write and ignored " +
    "on read there.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
