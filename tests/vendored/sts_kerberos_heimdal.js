"use strict";
//
// File: sts_kerberos_heimdal.js
//
// ---------------------------------------------------------------------------
// HEIMDAL'S CLIENT TOOLS BESIDE MIT'S (#205, 2026-09-26).
//
// Every other Kerberos interoperability check here drives MIT krb5's client.
// Heimdal is the other independent implementation — the one in macOS and in
// Samba — and it differs from MIT where it matters: it puts FAST in every
// TGS-REQ with hide-client-names set, prefers the SHA-2 AES enctypes, reads
// RFC 6806's enc-pa-rep, and implements neither RFC 6560 OTP nor MS-KKDCP.
// This job runs the existing sts_kerberos_* scenarios with Heimdal's own
// kinit, klist, kgetcred, `heimtools kvno`, ktutil and gss-token, and with a
// curl built against Heimdal's GSSAPI (tests/kerberos-interop/
// build-heimdal.sh), against the service's KDC on TCP 88, in whatever mode
// the service was started in:
//
//   1. AS EXCHANGES PER REALM: `kinit` for a person in the default trust
//      realm, and for one in a throwaway development realm whose KDC answers
//      on the same port, routed by its Kerberos realm name (#33); `klist -v`
//      reads each TGT, with pre-authent and RFC 6806's enc-pa-rep.
//   2. TGS EXCHANGES: `kgetcred` and `heimtools kvno` for a service principal
//      in each realm — FAST-armored by Heimdal, with hide-client-names.
//   3. KEYTABS: a service principal's keytab from create-service and a
//      person's from reset-person-keytab, each read by `ktutil list` and
//      signed in with by `kinit -k -t`.
//   4. FAST (#173): `kinit --fast-armor-cache` with the host's armor TGT
//      for a person with no second factor; and for a person a second factor
//      is required of, the password alone refused in product both unarmored
//      and inside FAST — Heimdal has no OTP client, so that is as far as it
//      can go (EXCEPTIONS).
//   5. RC4 BY MODE (#182): `kinit -e arcfour-hmac-md5` refused in product,
//      a ticket with an RC4 session key in development.
//   6. SPNEGO at /authn/spnego: `curl --negotiate` through Heimdal's GSSAPI,
//      and a `gss-token` token sent by this job — each a 200 naming the
//      person, and a session.
//   7. MS-KKDCP: not driven; Heimdal's client has no MS-KKDCP transport
//      (EXCEPTIONS).
//
// WHAT FAILS THIS JOB: any check below, and any line on a Heimdal tool's
// output that is not what it prints on success or a message this job
// accepts by name (ACCEPTED_LINES).
//
// WHAT IT CHANGES ON THE SERVICE: three people, a service principal in the
// default realm, and one realm it leaves standing
// (`leave-test-created-realms`).
//
// OWNED HERE (local: true). tests/CLAUDE.md, *The Kerberos interoperability
// harnesses*, is the provenance.
// ---------------------------------------------------------------------------

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");
const registry = require("./sts_applications.js");
const { declineToRun } = require("./expectation.js");

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
var log = bunyan.createLogger({ name: "sts_kerberos_heimdal",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";

const HEIMDAL = process.env.STS_HEIMDAL_DIR || "/opt/heimdal";
const BIN = path.join(HEIMDAL, "bin");

const USER = names.usernameFor("krb5-heimdal");
const MFA_USER = names.usernameFor("krb5-heimdal-mfa");
const KEYTAB_USER = names.usernameFor("krb5-heimdal-keytab");
const STAMP = String(Date.now()).slice(-6);
const PASSWORD = "Krb5-Heimdal-Passw0rd!-" + STAMP;
const RESET_PASSWORD = "Krb5-Heimdal-Reset-Passw0rd!-" + STAMP;
const TAG = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(0, 10);
const RID = "heimdal-" + TAG;
const RDOMAIN = RID + ".example.net";
const RREALM = RDOMAIN.toUpperCase();

// How long a product person's keys may take to reach the node that answers
// (sts_kerberos_spnego.js's KEYS_WAIT_MS, for its reason).
const KEYS_WAIT_MS = 20000;

// What Heimdal prints that this job accepts, by name. Anything else on a
// tool's output fails the step it came from.
const ACCEPTED_LINES = [
  // Heimdal's own notice when the enctype asked for is rc4-hmac: section 5
  // asks for exactly that, in development, on purpose.
  /^Encryption type arcfour-hmac-md5\(23\) used for authentication is weak and will be deprecated$/
];

// What #205 asks for that Heimdal cannot do, recorded on the ticket.
const EXCEPTIONS = {
  otp: "Heimdal's client implements no RFC 6560 OTP pre-authentication " +
       "(its kinit has no OTP prompt; MIT's does, and " +
       "sts_kerberos_fast_otp.js drives it), so the second half of #173 — " +
       "password and authenticator code in one FAST exchange — cannot be " +
       "driven with Heimdal; the refusal of the password alone is",
  kkdcp: "Heimdal's client implements no MS-KKDCP transport: its `http` " +
         "KDC transport is a GET of the base64 request, not [MS-KKDCP]'s " +
         "POST of a KDC-PROXY-MESSAGE (lib/krb5/krbhst.c defines " +
         "KD_SRV_KKDCP and nothing uses it); MS-KKDCP is driven by " +
         "sts_kerberos_spnego.js and sts_kerberos_krbtgt_rotation.js"
};

const K = { product: false, realm: "", kdcHost: "", kdcPort: 88,
            servicePrincipal: "", password: "", devPassword: "", host: "" };

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

async function call(method, url, body) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: { "Content-Type": "application/json" },
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

// ---------------------------------------------------------------------------
// HEIMDAL, from a krb5.conf and a credential cache of this run's own. Every
// command is run asynchronously (enroll_clients_kit.js's lesson: a
// synchronous spawn blocks the loop while the service closes keep-alives).
// ---------------------------------------------------------------------------
const H = { dir: "", conf: "", n: 0 };

function writeConf(extra) {
  log.debug("Entering writeConf().");
  const kdc = "tcp/" + K.kdcHost + ":" + K.kdcPort;
  fs.writeFileSync(H.conf, "[libdefaults]\n default_realm = " + K.realm +
    "\n dns_lookup_kdc = false\n dns_lookup_realm = false\n rdns = false\n" +
    (extra || "") + "\n[realms]\n " + K.realm + " = {\n  kdc = " + kdc +
    "\n }\n " + RREALM + " = {\n  kdc = " + kdc + "\n }\n" +
    "[domain_realm]\n " + K.host + " = " + K.realm + "\n");
  log.debug("Leaving writeConf().");
}

function run(tool, args, opts) {
  log.debug("Entering run(). " + tool + " " + args.join(" "));
  const options = opts || {};
  return new Promise(function (resolve, reject) {
    H.n += 1;
    const child = childProcess.spawn(path.join(BIN, tool), args, {
      env: Object.assign({}, process.env, {
        KRB5_CONFIG: H.conf,
        KRB5CCNAME: options.cache || "FILE:" + path.join(H.dir, "cc")
      }, options.env || {}) });
    let out = "";
    const timer = setTimeout(function () {
      child.kill("SIGKILL");
    }, 60000);
    child.stdout.on("data", function (b) {
      out += b.toString();
    });
    child.stderr.on("data", function (b) {
      out += b.toString();
    });
    child.on("error", function (e) {
      clearTimeout(timer);
      reject(new Error(tool + " could not be run: " + e.message));
    });
    child.on("close", function (code) {
      clearTimeout(timer);
      log.debug("Leaving run(). " + tool + " exit " + code);
      resolve({ status: code, out: out });
    });
    child.stdin.end(options.input || "");
  });
}

// A successful command's output may carry nothing this job has not accepted
// by name.
function quiet(result, what, expected) {
  log.debug("Entering quiet().");
  const stray = result.out.split("\n").map(function (line) {
    return line.trim();
  }).filter(function (line) {
    return line && !(expected || []).some(function (re) {
      return re.test(line);
    }) && !ACCEPTED_LINES.some(function (re) {
      return re.test(line);
    });
  });
  assert.deepStrictEqual(stray, [], what + " printed more than it should: " +
                         result.out.slice(0, 600));
  log.debug("Leaving quiet().");
}

// kinit with a password on stdin, retried through product mode's window
// (the person's keys reaching the node that answers).
async function kinitPassword(who, password, extra, cache) {
  log.debug("Entering kinitPassword(). " + who);
  const started = Date.now();
  for (;;) {
    const r = await run("kinit", ["--password-file=STDIN"]
                        .concat(extra || []).concat([who]),
                        { input: password + "\n", cache: cache });
    if (r.status === 0 || !K.product ||
        !/not found in Kerberos database|keys yet|sign in once/i
          .test(r.out) || Date.now() - started > KEYS_WAIT_MS) {
      log.debug("Leaving kinitPassword(). exit " + r.status);
      return r;
    }
    await pause(500);
  }
}

async function klistOf(cache) {
  log.debug("Entering klistOf().");
  const r = await run("klist", ["-v"], { cache: cache });
  assert.strictEqual(r.status, 0, "klist -v: " + r.out.slice(0, 400));
  log.debug("Leaving klistOf().");
  return r.out;
}

function cacheIn(name) {
  log.debug("Entering cacheIn().");
  log.debug("Leaving cacheIn().");
  return "FILE:" + path.join(H.dir, name);
}

// ---------------------------------------------------------------------------
// 0. THE SERVICE, THE PEOPLE AND THE REALM.
// ---------------------------------------------------------------------------
async function learnTheService() {
  log.debug("Entering learnTheService().");
  K.product = await facts.isProduct(api);
  K.realm = String(process.env.KRB5_REALM ||
                   await facts.setting(api, "krb5.realm") || "");
  K.host = new URL(base).hostname;
  K.kdcHost = process.env.STS_KDC_HOST || K.host;
  K.kdcPort = Number(process.env.STS_KDC_PORT ||
                     await facts.setting(api, "krb5.kdcPort") || 88);
  K.servicePrincipal = String(
    await facts.setting(api, "krb5.servicePrincipal") || "");
  K.devPassword = String(await facts.setting(api, "krb5.userPassword") ||
                         "password!");
  K.password = K.product ? PASSWORD : K.devPassword;
  log.info("mode " + (K.product ? "product" : "development") + ", realm " +
           K.realm + ", KDC " + K.kdcHost + ":" + K.kdcPort + ", " +
           fs.readFileSync(path.join(HEIMDAL, "HEIMDAL_COMMIT"), "utf8")
             .trim().slice(0, 12) + " Heimdal");
  await registry.ensurePerson(base, USER, PASSWORD);
  await registry.ensurePerson(base, MFA_USER, PASSWORD);
  await registry.ensurePerson(base, KEYTAB_USER, PASSWORD);
  await ok(api + "/users/require-mfa", { user: MFA_USER },
           "a second factor is required of " + MFA_USER);
  await ok(api + "/realms/create",
           { id: RID, domain: RDOMAIN, name: "#205 Heimdal",
             overrides: { "krb5.enabled": true, "krb5.realm": RREALM,
                          "global.mode": "development" } },
           "created the development realm " + RID);
  log.debug("Leaving learnTheService().");
}

// ---------------------------------------------------------------------------
// 1. AS EXCHANGES PER REALM.
// ---------------------------------------------------------------------------
async function asPerRealm() {
  log.debug("Entering asPerRealm().");
  log.info("=== 1. kinit per realm ===");
  const r = await kinitPassword(USER + "@" + K.realm, K.password);
  check("kinit " + USER + "@" + K.realm + " gets a TGT, and says nothing " +
        "else", function () {
    assert.strictEqual(r.status, 0, r.out);
    quiet(r, "kinit");
  });
  const listed = await klistOf();
  check("klist -v: the TGT is krbtgt/" + K.realm + ", pre-authent, and " +
        "carries enc-pa-rep (RFC 6806 section 11)", function () {
    assert.ok(listed.indexOf("Server: krbtgt/" + K.realm + "@" + K.realm) !==
              -1, listed);
    assert.ok(/Ticket flags:.*enc-pa-rep/.test(listed) &&
              /Ticket flags:.*pre-authent/.test(listed), listed);
  });
  const other = await kinitPassword("heimdal-" + STAMP + "@" + RREALM,
                                    K.devPassword, [], cacheIn("cc-realm"));
  check("kinit in the development realm " + RREALM + " on the same port, " +
        "routed by its name", function () {
    assert.strictEqual(other.status, 0, other.out);
    quiet(other, "kinit (" + RREALM + ")");
  });
  const otherListed = await klistOf(cacheIn("cc-realm"));
  check("and its TGT is krbtgt/" + RREALM, function () {
    assert.ok(otherListed.indexOf("Server: krbtgt/" + RREALM + "@" +
                                  RREALM) !== -1, otherListed);
  });
  log.debug("Leaving asPerRealm().");
}

// ---------------------------------------------------------------------------
// 2. TGS EXCHANGES — FAST-armored by Heimdal, with hide-client-names.
// ---------------------------------------------------------------------------
async function tgsPerRealm() {
  log.debug("Entering tgsPerRealm().");
  log.info("=== 2. kgetcred and kvno ===");
  const spn = K.servicePrincipal + "@" + K.realm;
  const got = await run("kgetcred", [spn]);
  check("kgetcred " + spn + " (Heimdal armors the TGS-REQ with FAST and " +
        "hide-client-names)", function () {
    assert.strictEqual(got.status, 0, got.out);
    quiet(got, "kgetcred");
  });
  const kvno = await run("heimtools", ["kvno", "-S", spn]);
  check("heimtools kvno -S " + spn, function () {
    assert.strictEqual(kvno.status, 0, kvno.out);
    quiet(kvno, "kvno", [/kvno = \d+$/]);
  });
  const listed = await klistOf();
  check("klist -v lists the service ticket beside the TGT", function () {
    assert.ok(listed.indexOf("Server: " + spn) !== -1, listed);
  });
  const rspn = "host/heimdal." + RDOMAIN + "@" + RREALM;
  const other = await run("kgetcred", [rspn], { cache: cacheIn("cc-realm") });
  check("kgetcred " + rspn + " in the development realm", function () {
    assert.strictEqual(other.status, 0, other.out);
    quiet(other, "kgetcred (" + RREALM + ")");
  });
  log.debug("Leaving tgsPerRealm().");
}

// ---------------------------------------------------------------------------
// 3. KEYTABS.
// ---------------------------------------------------------------------------
async function keytabs() {
  log.debug("Entering keytabs().");
  log.info("=== 3. keytabs, read by ktutil and used by kinit -k ===");
  const host = "host/heimdal-" + STAMP + "." + K.realm.toLowerCase();
  const made = await ok(api + "/kerberos/principals/create-service",
                        { spn: host }, "created " + host);
  // THE KEYTAB, WRITTEN AT RUN TIME into this run's temporary directory and
  // removed with it: the service's answer to this run's create-service,
  // never a file in the repository.
  const file = path.join(H.dir, "host.keytab");
  fs.writeFileSync(file, Buffer.from(made.keytab, "base64"),
                   { mode: 0o600 });
  const listed = await run("ktutil", ["-k", "FILE:" + file, "list"]);
  check("ktutil list reads the service keytab and names " + host,
        function () {
    assert.strictEqual(listed.status, 0, listed.out);
    assert.ok(listed.out.indexOf(host + "@" + K.realm) !== -1, listed.out);
  });
  const armor = await run("kinit", ["-k", "-t", "FILE:" + file,
                                    host + "@" + K.realm],
                          { cache: cacheIn("armor") });
  check("kinit -k -t signs the host in with its keytab — the FAST armor " +
        "TGT of section 4", function () {
    assert.strictEqual(armor.status, 0, armor.out);
    quiet(armor, "kinit -k");
  });
  const person = await ok(api + "/kerberos/principals/reset-person-keytab",
                          { username: KEYTAB_USER, password: RESET_PASSWORD },
                          "reset " + KEYTAB_USER + "'s password and took a " +
                          "keytab");
  const pfile = path.join(H.dir, "person.keytab");
  fs.writeFileSync(pfile, Buffer.from(person.keytab, "base64"),
                   { mode: 0o600 });
  const started = Date.now();
  let signed;
  for (;;) {
    signed = await run("kinit", ["-k", "-t", "FILE:" + pfile,
                                 KEYTAB_USER + "@" + K.realm],
                       { cache: cacheIn("person") });
    if (signed.status === 0 || !K.product ||
        Date.now() - started > KEYS_WAIT_MS) {
      break;
    }
    await pause(500);
  }
  check("kinit -k -t signs " + KEYTAB_USER + " in with the keytab " +
        "reset-person-keytab handed over", function () {
    assert.strictEqual(signed.status, 0, signed.out);
    quiet(signed, "kinit -k (person)");
  });
  log.debug("Leaving keytabs().");
  return cacheIn("armor");
}

// ---------------------------------------------------------------------------
// 4. FAST (#173).
// ---------------------------------------------------------------------------
async function fast(armorCache) {
  log.debug("Entering fast().");
  log.info("=== 4. FAST with the host's armor TGT ===");
  const armored = await kinitPassword(USER + "@" + K.realm, K.password,
    ["--fast-armor-cache=" + armorCache], cacheIn("fast"));
  check("kinit --fast-armor-cache gets " + USER + " a TGT through FAST " +
        "(the encrypted challenge, the strengthened reply key)", function () {
    assert.strictEqual(armored.status, 0, armored.out);
    quiet(armored, "kinit --fast-armor-cache");
  });
  const plain = await kinitPassword(MFA_USER + "@" + K.realm, K.password,
                                    [], cacheIn("mfa"));
  const inFast = await kinitPassword(MFA_USER + "@" + K.realm, K.password,
    ["--fast-armor-cache=" + armorCache], cacheIn("mfa-fast"));
  if (K.product) {
    check("PRODUCT: " + MFA_USER + ", of whom a second factor is required, " +
          "is refused on the password alone — unarmored and inside FAST " +
          "(KDC_ERR_POLICY)", function () {
      assert.notStrictEqual(plain.status, 0, plain.out);
      assert.notStrictEqual(inFast.status, 0, inFast.out);
      assert.ok(/password alone|policy/i.test(plain.out + inFast.out),
                plain.out + inFast.out);
    });
  } else {
    check("DEVELOPMENT: the password alone is a ticket for " + MFA_USER +
          ", as every password is", function () {
      assert.strictEqual(plain.status, 0, plain.out);
      assert.strictEqual(inFast.status, 0, inFast.out);
    });
  }
  log.info("  [exception] OTP: " + EXCEPTIONS.otp + ".");
  log.debug("Leaving fast().");
}

// ---------------------------------------------------------------------------
// 5. RC4 BY MODE (#182).
// ---------------------------------------------------------------------------
async function rc4() {
  log.debug("Entering rc4().");
  log.info("=== 5. kinit -e arcfour-hmac-md5 ===");
  writeConf(" allow_weak_crypto = true\n");
  try {
    const r = await kinitPassword(USER + "@" + K.realm, K.password,
      ["-e", "arcfour-hmac-md5"], cacheIn("rc4"));
    if (K.product) {
      // The KDC answers KDC_ERR_ETYPE_NOSUPP naming product mode
      // (STS-KRB-0156; sts_kerberos_rc4.js reads the e-text). Heimdal's
      // client reports an ETYPE_NOSUPP that carries no padata with the
      // sentence it uses for a PREAUTH_REQUIRED without any
      // (lib/krb5/init_creds_pw.c), so that sentence is accepted by name.
      check("PRODUCT: kinit restricted to rc4-hmac is refused — the KDC " +
            "has no support for that encryption type", function () {
        assert.notStrictEqual(r.status, 0, r.out);
        assert.ok(/encryption type|enctype|etype|Preauth required but no preauth options sent by KDC/i
          .test(r.out), r.out);
      });
    } else {
      check("DEVELOPMENT: kinit restricted to rc4-hmac gets a TGT",
            function () {
        assert.strictEqual(r.status, 0, r.out);
        quiet(r, "kinit -e arcfour-hmac-md5");
      });
      const listed = await klistOf(cacheIn("rc4"));
      check("DEVELOPMENT: its session key is rc4-hmac and the ticket is " +
            "still sealed with the krbtgt's strongest key", function () {
        assert.ok(/Ticket session etype: arcfour-hmac-md5/.test(listed),
                  listed);
        assert.ok(/Ticket etype: aes256-cts-hmac-sha1-96/.test(listed),
                  listed);
      });
    }
  } finally {
    writeConf("");
  }
  log.debug("Leaving rc4().");
}

// ---------------------------------------------------------------------------
// 6. SPNEGO AT /authn/spnego.
// ---------------------------------------------------------------------------
function signedIn(status, body, what) {
  log.debug("Entering signedIn().");
  assert.strictEqual(status, 200, what + " answered " + status + ": " +
                     String(body).replace(/<[^>]+>/g, " ")
                       .replace(/\s+/g, " ").slice(0, 400));
  assert.ok(String(body).indexOf("<strong>" + USER + "</strong>") !== -1,
            what + ": the page does not name " + USER);
  log.debug("Leaving signedIn().");
}

async function spnego() {
  log.debug("Entering spnego().");
  log.info("=== 6. SPNEGO with Heimdal's GSSAPI ===");
  // The name Heimdal's GSSAPI derives from the URL, HTTP/<host>. A
  // development KDC makes it on first sight for a host it is willing to be;
  // a product one makes nothing on demand, so it is keyed here as an
  // administrator would, and the acceptor opens it with the stored key.
  const spn = "HTTP/" + K.host;
  if (K.product) {
    await ok(api + "/kerberos/principals/create-service", { spn: spn },
             "keyed " + spn + " for the acceptor");
  }
  const url = base + "/authn/spnego";
  const cafile = process.env.NODE_EXTRA_CA_CERTS || "";
  const bodyFile = path.join(H.dir, "spnego.html");
  const curl = await run("curl", ["-sS", "--negotiate", "-u", ":"]
    .concat(cafile ? ["--cacert", cafile] : [])
    .concat(["-o", bodyFile, "-w", "%{http_code}", url]));
  const body = fs.existsSync(bodyFile) ? fs.readFileSync(bodyFile, "utf8")
                                       : "";
  check("curl --negotiate (Heimdal GSSAPI) signs " + USER + " in at " +
        "/authn/spnego", function () {
    assert.strictEqual(curl.status, 0, curl.out);
    signedIn(Number(curl.out.trim().slice(-3)), body, "curl --negotiate");
  });
  const token = await run("gss-token", ["-N", "HTTP@" + K.host]);
  check("gss-token -N HTTP@" + K.host + " makes an initial context token",
        function () {
    assert.strictEqual(token.status, 0, token.out);
    assert.ok(/^Negotiate [A-Za-z0-9+/=]+$/.test(token.out.trim()),
              token.out.slice(0, 200));
  });
  const sent = await fetch(url, { headers: {
    Authorization: token.out.trim() }, redirect: "manual" });
  const sentBody = await sent.text();
  check("that token at /authn/spnego is a 200 naming " + USER + " and a " +
        "session cookie", function () {
    signedIn(sent.status, sentBody, "the gss-token token");
    assert.ok(/sts_session=/.test(String(sent.headers.get("set-cookie"))),
              "no session cookie");
  });
  log.debug("Leaving spnego().");
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
  assert.ok(fs.existsSync(path.join(BIN, "kinit")), "Heimdal is not " +
            "installed at " + HEIMDAL + " (tests/Dockerfile builds it; " +
            "STS_HEIMDAL_DIR names another)");
  H.dir = fs.mkdtempSync(path.join(os.tmpdir(), "krb5-heimdal-"));
  H.conf = path.join(H.dir, "krb5.conf");
  try {
    await learnTheService();
    writeConf("");
    await asPerRealm();
    await tgsPerRealm();
    const armorCache = await keytabs();
    await fast(armorCache);
    await rc4();
    await spnego();
    log.info("=== 7. MS-KKDCP ===");
    log.info("  [exception] " + EXCEPTIONS.kkdcp + ".");
  } finally {
    try {
      fs.rmSync(H.dir, { recursive: true, force: true });
    } catch (e) {
      // A temporary directory left behind is not what this job tests.
      log.debug("Caught in test(): " + ((e && e.message) || e));
    }
  }
  const floor = 16;
  assert.ok(checks >= floor, "only " + checks + " checks ran (floor " +
            floor + "); a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_heimdal")
  .description("#205: Heimdal's kinit, klist, kgetcred, kvno, ktutil, " +
    "gss-token and a Heimdal-GSSAPI curl against the service's KDC — AS " +
    "and TGS per realm, keytabs, FAST, RC4 by mode and SPNEGO.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
