"use strict";
//
// File: conformance_suite.js
//
// ---------------------------------------------------------------------------
// WHAT EVERY DRIVER OF THE OPENID FOUNDATION'S CONFORMANCE SUITE SHARES (#187,
// 2026-09-24). `sts_fapi_conformance.js` (#176) was the first driver and
// carries its own copy of the suite's API client, which is left as it is so
// the FAPI plans' behaviour does not move; the drivers #187 added — OpenID
// Connect, Shared Signals, OpenID Federation, OpenID4VCI, OpenID4VP and
// Identity Assurance — share this file instead. It is a HELPER, listed in
// MANIFEST.js's LOCAL_HELPERS, and owns no plan.
//
// What it adds over the FAPI driver's copy is the WARNING ledger: a module
// that ends WARNING carries one or more log entries whose `src` names the
// suite's condition. #187's rule is that every warning is either fixed in the
// service or recorded with its reason, so each driver passes a table of
// KNOWN warnings (condition -> reason) and a warning from any other condition
// fails the job exactly as a FAILED module does. A reason is a sentence a
// reviewer can check, and the same sentence is in oauth-oidc/CLAUDE.md 3bg.
//
// OWNED HERE (local: true): nothing in the parent project uses it.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const https = require("https");
const nodeCrypto = require("crypto");
const os = require("os");
const bunyan = require("bunyan");

const log = bunyan.createLogger({ name: "conformance_suite",
                                  level: process.env.LOG_LEVEL || "info" });

// Where the suite answers, as a job reaches it — and the base the suite
// believes it has, which its redirect URIs are built on.
const SUITE = String(process.env.CONFORMANCE_SUITE_URL ||
                     "https://localhost.emobix.co.uk:8443/")
  .replace(/\/?$/, "/");
// Where the suite reaches a JOB, for an address the job serves itself (the
// CIBA approver, the SSF push receiver's trigger).
const SELF_HOST = process.env.CONFORMANCE_CALLBACK_HOST || os.hostname();
// How long one module may run.
const MODULE_SECONDS = Number(process.env.CONFORMANCE_MODULE_SECONDS) || 300;

// The discovery document's members the suite's schema does not know, named
// as its warning asks — `oauth-oidc/CLAUDE.md` 3bg says why each is there.
const EXTENSION_METADATA = [
  "crypto_metadata_uri", "verified_claims_supported",
  "native_sso_supported",
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer_supported",
  "urn:ietf:params:oauth:client-assertion-type:saml2-bearer_supported",
  "assertion_signing_alg_values_supported",
  "assertion_encryption_alg_values_supported",
  "assertion_encryption_enc_values_supported",
  // draft-ietf-oauth-attestation-based-client-auth-11 section 15.2 registers
  // it (#229); the suite's RFC 8414 schema (v5.3.1) predates it, and knows
  // the other three members that section registers.
  "client_attestation_pop_methods_supported"];

function waitMs(ms) {
  log.debug("Entering waitMs().");
  log.debug("Leaving waitMs().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// A request to THIS service, through `fetch`, verified against the stack's
// trust as in every other job.
async function send(url, options) {
  log.debug("Entering send(). " + url);
  let r = await fetch(url, Object.assign({ redirect: "manual" },
                                         options || {}));
  // A PLAN RUN OUTLIVES ITS /admin-api TOKEN. The runner hands each job a
  // token good for an hour, and the OpenID Connect plans take longer: a
  // management call that is refused 401 mints a fresh one through the
  // preload's refresh() and is made again, once.
  if (r.status === 401 && /\/admin-api(\/|$)/.test(String(url)) &&
      globalThis.stsAdminApiToken &&
      typeof globalThis.stsAdminApiToken.refresh === "function") {
    log.info("The /admin-api token was refused; minting a fresh one.");
    await globalThis.stsAdminApiToken.refresh();
    r = await fetch(url, Object.assign({ redirect: "manual" },
                                       options || {}));
  }
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). " + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// An EC P-256 (or RSA) key pair as the suite wants it: a JWK Set with the
// PRIVATE key (the suite signs with it) and the public one this service
// registers. Made here, at run time — no key material in git.
function keyPair(kid, alg) {
  log.debug("Entering keyPair().");
  const rsa = alg && /^(RS|PS)/.test(alg);
  const pair = rsa
    ? nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
    : nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pub = pair.publicKey.export({ format: "jwk" });
  const priv = pair.privateKey.export({ format: "jwk" });
  [pub, priv].forEach(function (jwk) {
    jwk.kid = kid;
    jwk.use = "sig";
    jwk.alg = alg || "ES256";
  });
  log.debug("Leaving keyPair().");
  return { publicJwks: { keys: [pub] }, privateJwks: { keys: [priv] } };
}

// A TLS client certificate for a registered client, from the realm's own CA,
// as the PEMs the suite wants — the FAPI driver's clientCertificate().
async function clientCertificate(api, clientId) {
  log.debug("Entering clientCertificate(). " + clientId);
  const password = nodeCrypto.randomBytes(18).toString("base64url");
  const r = await ok(api + "/applications/issue-tls-client-certificate",
                     { application: clientId, password: password,
                       keyAlg: "ec-p256", label: "conformance" },
                     "issued a client certificate");
  const key = nodeCrypto.createPrivateKey({ key: r.files.key.text,
                                           format: "pem",
                                           passphrase: password })
    .export({ format: "pem", type: "pkcs8" });
  log.debug("Leaving clientCertificate().");
  return { cert: r.certificate.certificatePem, key: String(key),
           ca: (r.certificate.chainPem || []).join("\n"),
           subjectDn: r.certificate.subject || "" };
}

// ---------------------------------------------------------------------------
// THE SUITE'S API, VERIFIED (#187). The FAPI driver could not anchor the
// certificate the suite's image shipped; conformance-tls now mints one for
// the suite's own name, so these calls verify it. A run without that file
// (a suite started by hand from its own compose file) falls back to the FAPI
// driver's unverified agent and says so.
// ---------------------------------------------------------------------------
let suiteCa = null;
try {
  suiteCa = fs.readFileSync(process.env.CONFORMANCE_SUITE_CA_FILE ||
                            "/run/sts-test/conformance/server.crt", "utf8");
} catch (e) {
  log.debug("Caught reading the suite's certificate: " +
            ((e && e.message) || e));
  log.warn("The conformance suite's certificate is not in the shared " +
           "directory, so its API is called without verifying it.");
  suiteCa = null;
}
const SUITE_AGENT = new https.Agent(suiteCa
  ? { ca: suiteCa, keepAlive: true }
  : { rejectUnauthorized: false, keepAlive: true });

function suite(method, path, body) {
  log.debug("Entering suite(). " + method + " " + path);
  const payload = body ? JSON.stringify(body) : "";
  return new Promise(function (resolve, reject) {
    const req = https.request(new URL(SUITE + path), {
      method: method, agent: SUITE_AGENT,
      headers: body ? { "Content-Type": "application/json",
                        "Content-Length": Buffer.byteLength(payload) } : {}
    }, function (res) {
      let raw = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        raw += chunk;
      });
      res.on("end", function () {
        let parsed = null;
        try {
          parsed = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in suite(): " + ((e && e.message) || e));
          // Not JSON; the caller reads `raw`.
          parsed = null;
        }
        log.debug("Leaving suite(). " + res.statusCode);
        resolve({ status: res.statusCode, body: parsed, raw: raw });
      });
    });
    req.on("error", function (e) {
      log.debug("Leaving suite(). " + ((e && e.message) || e));
      reject(e);
    });
    req.end(payload);
  });
}

async function waitForSuite() {
  log.debug("Entering waitForSuite().");
  for (let i = 0; i < 120; i++) {
    try {
      const r = await suite("GET", "api/plan?length=1");
      if (r.status === 200) {
        log.debug("Leaving waitForSuite(). Up.");
        return;
      }
    } catch (e) {
      log.debug("Caught in waitForSuite(): " + ((e && e.message) || e));
    }
    await waitMs(5000);
  }
  log.debug("Leaving waitForSuite(). Never up.");
  throw new Error("the conformance suite at " + SUITE + " never answered");
}

// One module: created in the plan, then waited on until it finishes. A
// module left WAITING past MODULE_SECONDS is stopped and counted as the
// failure it is. Answers its FAILURE and WARNING log entries as well.
// `onWaiting(id, info)`, when given, is awaited on each poll that finds the
// module WAITING (or CONFIGURED and not started) — for a module that waits
// on this service's OPERATOR (a credential offer to be sent, a transaction
// code to be typed, the OP's keys to be rotated), which the driver plays.
async function runModule(planId, module, onWaiting) {
  log.debug("Entering runModule(). " + module.testModule);
  const q = "test=" + encodeURIComponent(module.testModule) + "&plan=" +
            encodeURIComponent(planId) +
            (module.variant ? "&variant=" +
             encodeURIComponent(JSON.stringify(module.variant)) : "");
  const created = await suite("POST", "api/runner?" + q);
  assert.ok(created.status === 201 || created.status === 200,
            "creating " + module.testModule + ": " + created.raw.slice(0, 300));
  const id = created.body.id;
  let info = null;
  const deadline = Date.now() + MODULE_SECONDS * 1000;
  while (true) {
    info = (await suite("GET", "api/info/" + id)).body || {};
    if (info.status === "FINISHED" || info.status === "INTERRUPTED") {
      break;
    }
    // On EVERY poll while it waits, not once per transition: a module can
    // go from waiting on one thing (an offer) to waiting on the next (its
    // transaction code) between two polls. The operator knows what it has
    // already done.
    // And while it is CONFIGURED and not started: a module that waits for
    // the operator to do something BEFORE it is started (the OP key
    // rotation module) is started by that operator.
    if (onWaiting && (info.status === "WAITING" ||
                      info.status === "CONFIGURED")) {
      try {
        await onWaiting(id, info);
      } catch (e) {
        // Reported, and the module is left to time out or fail on its own:
        // the suite's log is the record of what it was not sent.
        log.warn("The operator step for " + module.testModule +
                 " failed: " + ((e && e.message) || e));
      }
    }
    if (Date.now() > deadline) {
      await suite("DELETE", "api/runner/" + id);
      info = Object.assign({}, info, { status: "TIMED OUT" });
      break;
    }
    await waitMs(2000);
  }
  const logs = (await suite("GET", "api/log/" + id)).body || [];
  const entries = function (result) {
    return logs.filter(function (entry) {
      return entry.result === result;
    }).map(function (entry) {
      return { src: String(entry.src || ""), msg: String(entry.msg || "") };
    });
  };
  log.debug("Leaving runModule(). " + info.result);
  return { module: module.testModule, id: id, status: info.status,
           result: info.result || "", failures: entries("FAILURE"),
           warnings: entries("WARNING") };
}

// What a running module has EXPOSED — the endpoints it waits on — from the
// runner's own view of it (`GET /api/runner/{id}`).
async function exposed(id) {
  log.debug("Entering exposed(). " + id);
  const r = await suite("GET", "api/runner/" + id);
  log.debug("Leaving exposed(). " + r.status);
  return (r.body && r.body.exposed) || {};
}

// A whole plan: created with its configuration, every module run in turn.
async function runPlan(planName, variant, configuration, label, onWaiting) {
  log.debug("Entering runPlan(). " + planName);
  const created = await suite("POST", "api/plan?planName=" +
    encodeURIComponent(planName) +
    (variant ? "&variant=" + encodeURIComponent(JSON.stringify(variant))
             : ""),
    configuration);
  assert.ok(created.status === 201 || created.status === 200,
            "creating " + planName + ": " + created.raw.slice(0, 400));
  const results = [];
  const modules = created.body.modules || [];
  for (let i = 0; i < modules.length; i++) {
    const got = await runModule(created.body.id, modules[i], onWaiting);
    log.info("  " + label + " " + got.module + ": " +
             (got.result || got.status) +
             (got.failures.length ? " — " + got.failures[0].src + ": " +
                                    got.failures[0].msg : ""));
    results.push(got);
  }
  log.debug("Leaving runPlan(). " + results.length);
  return { planId: created.body.id, results: results };
}

// ---------------------------------------------------------------------------
// A THROWAWAY REALM (left behind, as every job here leaves its realms), its
// settings, and a person with a password the scripted browser signs in as.
// ---------------------------------------------------------------------------
async function makeRealm(root, id, label, settings) {
  log.debug("Entering makeRealm(). " + id);
  await ok(root + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: label }, "created the realm " + id);
  const api = root + "/realm/" + id + "/admin-api";
  for (let i = 0; i < (settings || []).length; i++) {
    await ok(api + "/config/set", { key: settings[i][0],
                                    value: settings[i][1] },
             "set " + settings[i][0] + " in " + id);
  }
  log.debug("Leaving makeRealm().");
  return { id: id, base: root + "/realm/" + id, api: api };
}

async function makePerson(api, username, password, extra) {
  log.debug("Entering makePerson(). " + username);
  await ok(api + "/users/create", { username: username, invent: false,
    credential: "password", password: password,
    attributes: Object.assign({ cn: "Conformance " + username,
                                givenName: "Conformance", sn: username,
                                mail: username + "@conformance.test" },
                              extra || {}) },
    "created " + username);
  log.debug("Leaving makePerson().");
}

// The suite's listener certificate, as conformance-tls minted it into the
// directory the service reads CA files from (#171's shared directory): what
// the service sends the suite — a Logout Token, a pushed Security Event
// Token — and what it fetches there go with verification ON, against the
// name the suite answers to. Answers the path, which the realm settings name.
function suiteCaFile() {
  log.debug("Entering suiteCaFile().");
  const file = process.env.CONFORMANCE_SUITE_CA_FILE ||
               "/run/sts-test/conformance/server.crt";
  assert.ok(fs.existsSync(file), "the conformance suite's certificate is " +
            "not at " + file + " (conformance-tls in " +
            "docker-compose-run-tests.yml makes it)");
  log.debug("Leaving suiteCaFile(). " + file);
  return file;
}

// An EC P-256 key and a self-signed certificate for it, made HERE at run
// time with this repository's own encoder (`common/vendored/x509.js`, which
// the tests image carries): the private JWK with an `x5c`, for a key the
// suite signs with — a credential issuer's, a key attester's — and the PEM
// the realm is told to trust. No key material in git.
async function selfSignedKey(label) {
  log.debug("Entering selfSignedKey(). " + label);
  const repo = require("path").join(__dirname, "..", "..");
  const x509 = require(require("path").join(repo, "common", "vendored",
                                            "x509"));
  const keyMaterial = require(require("path").join(repo, "common",
                                                   "vendored",
                                                   "key_material"));
  const pair = await keyMaterial.generateKeyPair("ec-p256");
  const issued = await x509.issueCertificate({
    subject: [{ name: "CN", value: label },
              { name: "O", value: "iya-sts conformance" }],
    subjectPublicKey: pair.publicPem,
    issuerPrivateKey: pair.privatePem,
    signatureAlg: "sha256-ecdsa",
    serial: nodeCrypto.randomBytes(8).toString("hex"),
    notBefore: new Date(Date.now() - 60000).toISOString(),
    notAfter: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ["digitalSignature"] },
      subjectKeyIdentifier: { present: true }
    }
  });
  const jwk = nodeCrypto.createPrivateKey(pair.privatePem)
    .export({ format: "jwk" });
  jwk.kid = label.replace(/[^A-Za-z0-9_-]/g, "-");
  jwk.alg = "ES256";
  jwk.use = "sig";
  jwk.x5c = [issued.pem.replace(/-----[^-]+-----|\s+/g, "")];
  log.debug("Leaving selfSignedKey().");
  return { jwk: jwk, pem: issued.pem };
}

// A certificate authority and a leaf it issued, both made here at run time
// (no key material in git) — for a key the suite presents with an x5c chain
// that must NOT be self-signed: HAIP 1.0 section 4.4.1's client attester
// (#229). The leaf's private JWK carries `x5c: [leaf]` alone, the CA being
// the trust anchor the realm is configured with (`caPem`), never in x5c.
async function caAndLeaf(label) {
  log.debug("Entering caAndLeaf(). " + label);
  const repo = require("path").join(__dirname, "..", "..");
  const x509 = require(require("path").join(repo, "common", "vendored",
                                            "x509"));
  const keyMaterial = require(require("path").join(repo, "common",
                                                   "vendored",
                                                   "key_material"));
  const now = Date.now();
  const caPair = await keyMaterial.generateKeyPair("ec-p256");
  const ca = await x509.issueCertificate({
    subject: [{ name: "CN", value: label + " CA" },
              { name: "O", value: "iya-sts conformance" }],
    subjectPublicKey: caPair.publicPem,
    issuerPrivateKey: caPair.privatePem,
    signatureAlg: "sha256-ecdsa",
    serial: nodeCrypto.randomBytes(8).toString("hex"),
    notBefore: new Date(now - 60000).toISOString(),
    notAfter: new Date(now + 7 * 24 * 3600 * 1000).toISOString(),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: 0 },
      keyUsage: { present: true, critical: true,
                  usages: ["keyCertSign", "cRLSign"] },
      subjectKeyIdentifier: { present: true }
    }
  });
  const leafPair = await keyMaterial.generateKeyPair("ec-p256");
  const leaf = await x509.issueCertificate({
    subject: [{ name: "CN", value: label },
              { name: "O", value: "iya-sts conformance" }],
    subjectPublicKey: leafPair.publicPem,
    issuer: { certificatePem: ca.pem, privateKeyPem: caPair.privatePem,
              keyAlg: "ec-p256" },
    signatureAlg: "sha256-ecdsa",
    serial: nodeCrypto.randomBytes(8).toString("hex"),
    notBefore: new Date(now - 60000).toISOString(),
    notAfter: new Date(now + 7 * 24 * 3600 * 1000).toISOString(),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ["digitalSignature"] },
      subjectKeyIdentifier: { present: true },
      authorityKeyIdentifier: { present: true }
    }
  });
  const jwk = nodeCrypto.createPrivateKey(leafPair.privatePem)
    .export({ format: "jwk" });
  jwk.kid = label.replace(/[^A-Za-z0-9_-]/g, "-");
  jwk.alg = "ES256";
  jwk.use = "sig";
  jwk.x5c = [leaf.pem.replace(/-----[^-]+-----|\s+/g, "")];
  log.debug("Leaving caAndLeaf().");
  return { jwk: jwk, leafPem: leaf.pem, caPem: ca.pem };
}

// ---------------------------------------------------------------------------
// THE LEDGER. `expected` is `<label>/<module>` -> reason (a FAILED module
// that is argued), `knownWarnings` is `<condition>` -> reason (a WARNING the
// service keeps, and why), and `knownFailures` is `<condition>` (or, for one
// plan only, `<label>/*/<condition>`, and for one module only,
// `<label>/<module>/<condition>`) -> reason: a
// FAILURE from that condition alone is argued, and a module that fails on it
// AND on anything else is still a failure — which is why it is keyed by the
// suite's condition and not by the module, so one argued difference cannot
// hide the next. Answers the counts and the unexplained lines.
// ---------------------------------------------------------------------------
function judge(label, ran, expected, knownWarnings, knownFailures) {
  log.debug("Entering judge(). " + label);
  const counts = {};
  const unexplained = [];
  const warned = {};
  const failureKnown = knownFailures || {};
  ran.results.forEach(function (r) {
    const k = r.result || r.status;
    counts[k] = (counts[k] || 0) + 1;
    // FINISHED, or INTERRUPTED by a stop-on-failure condition that is itself
    // known: a module the suite ends at its first failure is judged by that
    // failure, which is all it ran.
    const onlyKnown = (r.status === "FINISHED" ||
                       r.status === "INTERRUPTED") &&
      r.failures.length > 0 &&
      r.failures.every(function (f) {
        return !!(failureKnown[f.src] ||
                  failureKnown[label + "/*/" + f.src] ||
                  failureKnown[label + "/" + r.module + "/" + f.src]);
      });
    const moduleArgued = expected[label + "/" + r.module] ||
                         expected["*/" + r.module];
    const argued = moduleArgued || onlyKnown;
    if ((r.result === "FAILED" || r.status !== "FINISHED") && !argued) {
      unexplained.push(label + "/" + r.module + " (" + k + "): " +
        r.failures.slice(0, 3).map(function (f) {
          return f.src + ": " + f.msg;
        }).join(" | "));
    }
    r.warnings.forEach(function (w) {
      // A known warning is a reason (any message from that condition), or
      // { why, msg: RegExp } when only some of the condition's messages are
      // argued and another would be a new finding.
      const known = knownWarnings[w.src];
      const covered = !!known && (typeof known === "string" ||
                                  known.msg.test(String(w.msg || "")));
      if (!covered && !moduleArgued) {
        const key = w.src + ": " + w.msg.slice(0, 200);
        warned[key] = (warned[key] || []).concat([r.module]);
      }
    });
  });
  Object.keys(warned).forEach(function (key) {
    unexplained.push(label + " WARNING " + key + " (in " +
                     warned[key].slice(0, 3).join(", ") +
                     (warned[key].length > 3 ? ", ..." : "") + ")");
  });
  log.debug("Leaving judge(). " + unexplained.length);
  return { counts: counts, unexplained: unexplained };
}

// The plans a run names (`CONFORMANCE_PLANS`, a comma list of keys), or all.
function selected(key) {
  log.debug("Entering selected(). " + key);
  const only = String(process.env.CONFORMANCE_PLANS || "").split(",")
    .map(function (s) {
      return s.trim();
    }).filter(Boolean);
  log.debug("Leaving selected().");
  return !only.length || only.indexOf(key) >= 0 ||
         only.some(function (o) {
           return o.slice(-1) === "*" && key.indexOf(o.slice(0, -1)) === 0;
         });
}

module.exports = {
  SUITE: SUITE,
  SELF_HOST: SELF_HOST,
  EXTENSION_METADATA: EXTENSION_METADATA,
  waitMs: waitMs,
  send: send,
  ok: ok,
  keyPair: keyPair,
  clientCertificate: clientCertificate,
  suite: suite,
  waitForSuite: waitForSuite,
  runModule: runModule,
  exposed: exposed,
  runPlan: runPlan,
  judge: judge,
  selected: selected,
  caAndLeaf: caAndLeaf,
  makeRealm: makeRealm,
  makePerson: makePerson,
  suiteCaFile: suiteCaFile,
  selfSignedKey: selfSignedKey
};
