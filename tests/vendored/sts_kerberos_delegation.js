// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_kerberos_delegation.js
//
// ---------------------------------------------------------------------------
// KERBEROS DELEGATION OVER THE WIRE, DECIDED BY THE ONE DELEGATION POLICY
// (iya-sts #186, 2026-10-03).
//
// S4U2Self is an impersonation by the service of itself, S4U2Proxy a
// delegation by the front end to the back end, and both are decided by the
// issuance policy from the common controls on the directory's entries —
// the rules WS-Trust and the RFC 8693 token exchange are decided by. This
// job builds its OWN services and people through /admin-api, so it runs in
// either mode (the KDC refuses in both): four service principals made with
// `create-service` (their keytabs are how this job holds their keys), their
// delegation set on their application entries, a person, and a protected
// person (set-not-delegated, keyed with `reset-person-keytab`). Then, over
// TCP 88, with this suite's own client (`krb5_wire.js`):
//
//   1. S4U2Self: forwardable for a service allowing impersonation, not for
//      one that does not, not for the protected person; PA-S4U-X509-USER by
//      name, answered in the reply, and refused with a bad checksum.
//   2. S4U2Proxy: classic to the back end the front end names, refused to
//      one it does not; resource-based with PA-PAC-OPTIONS, refused without;
//      non-forwardable evidence refused; the forwardable flag set on its own
//      evidence by the requester (CVE-2020-17049) refused; evidence forged
//      with the requester's key refused; the protected person refused over
//      resource-based delegation, whose S4U2Self ticket is not forwardable
//      ([MS-SFU] 3.2.5.2.3, #492).
//   3. The protected person's TGT is not forwardable and cannot be
//      forwarded; krb5TrustedForDelegation puts ok-as-delegate on a
//      service's tickets and nothing else does.
//   4. An edit to an entry changes the next answer; the acts are on
//      GET /admin-api/delegation, refusals included.
//
// OWNED HERE (local: true): the policy is this repository's own.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const facts = require("./service_facts.js");
const wire = require("./krb5_wire.js");

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
var log = bunyan.createLogger({ name: "sts_kerberos_delegation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";
const msgs = wire.msgs;
const SUFFIX = crypto.randomBytes(3).toString("hex");
const host = function (role) {
  log.debug("Entering host().");
  log.debug("Leaving host().");
  return "kd-" + role + "-" + SUFFIX + ".example.com";
};
const ROLES = ["front", "back", "rbcd", "notrusted", "trusted"];
const PERSON = usernameFor("kd-person");
const PROTECTED = usernameFor("kd-protected");
const PASSWORD = "Kd!" + crypto.randomBytes(12).toString("base64url") + "9z";
// The keytab reset SETS a password, and the realm's password policy refuses
// one the account has just had — so it is a second one.
const KEYTAB_PASSWORD = "Kt!" + crypto.randomBytes(12).toString("base64url") +
                        "8y";
const KEYS_WAIT_MS = 20000;
const K = { product: false, realm: "", kdcHost: "", kdcPort: 88,
            transport: null };

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

async function call(method, where, body) {
  log.debug("Entering call(). " + method + " " + where);
  const r = await fetch(api + where, { method: method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — the raw text says more than a parse failure.
    parsed = raw;
  }
  log.debug("Leaving call(). HTTP " + r.status);
  return { status: r.status, body: parsed, text: raw };
}

async function ok(where, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", where, body);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
            what + ": " + r.status + " " + String(r.text).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function idOf(role) {
  log.debug("Entering idOf().");
  log.debug("Leaving idOf().");
  return "HTTP/" + host(role) + "@" + K.realm;
}

function sname(role) {
  log.debug("Entering sname().");
  log.debug("Leaving sname().");
  return { type: 3, name: ["HTTP", host(role)] };
}

function keysOf(keytabB64) {
  log.debug("Entering keysOf().");
  const keys = {};
  wire.readKeytab(Buffer.from(String(keytabB64), "base64"))
    .forEach(function (one) {
      keys[one.etype] = one.key;
    });
  log.debug("Leaving keysOf().");
  return keys;
}

// A TGT with keys, retried through product mode's window — the KDC reads a
// stored key once the change has reached it.
async function tgtWith(name, keys) {
  log.debug("Entering tgtWith(). " + name);
  const started = Date.now();
  let got = await wire.asExchange(K.transport, K.realm, name, { keys: keys });
  while (!got.tgt && Date.now() - started < KEYS_WAIT_MS) {
    await pause(500);
    got = await wire.asExchange(K.transport, K.realm, name, { keys: keys });
  }
  assert.ok(got.tgt, "a TGT for " + name + ": " +
            JSON.stringify(got.second || got.first));
  log.debug("Leaving tgtWith().");
  return got.tgt;
}

function s4u2self(tgt, user) {
  log.debug("Entering s4u2self(). " + user);
  log.debug("Leaving s4u2self().");
  return wire.tgsExchange(K.transport, tgt, tgt.client, K.realm, {
    padata: async function () {
      return [await wire.paForUser(tgt, user, K.realm)];
    }
  });
}

function s4u2proxy(tgt, evidence, role, rbcd) {
  log.debug("Entering s4u2proxy(). " + role);
  log.debug("Leaving s4u2proxy().");
  return wire.tgsExchange(K.transport, tgt, sname(role), K.realm, {
    kdcOptions: [msgs.KDC_OPTION.CNAME_IN_ADDL_TKT],
    additionalTickets: [evidence],
    padata: rbcd ? [wire.paPacOptionsRbcd()] : []
  });
}

function forwardable(r) {
  log.debug("Entering forwardable().");
  log.debug("Leaving forwardable().");
  return !!r.ok && r.flagNames.indexOf("forwardable") >= 0;
}

function refusedWith(r, code) {
  log.debug("Entering refusedWith().");
  assert.ok(!r.ok, "expected a refusal, got a ticket");
  assert.strictEqual(r.error.code, code, String(r.error));
  log.debug("Leaving refusedWith().");
}

// Opens an evidence ticket with the key its service holds, changes it, and
// seals it again — what a front end can do to its own evidence.
async function resealed(ticket, keys, change) {
  log.debug("Entering resealed().");
  const kcrypto = wire.kcrypto;
  const profile = kcrypto.etypeById(ticket.encPart.etype);
  const key = keys[ticket.encPart.etype];
  assert.ok(key, "the keytab has a key of the evidence's enctype");
  const part = msgs.readEncTicketPart(await profile.decrypt(key,
    kcrypto.KEY_USAGE.KDC_REP_TICKET, ticket.encPart.cipher));
  change(part);
  const cipher = await profile.encrypt(key, kcrypto.KEY_USAGE.KDC_REP_TICKET,
                                       msgs.encEncTicketPart(part));
  // WITHOUT `raw`: the codec sends a parsed ticket's original bytes when it
  // has them, which would be the ticket before the change.
  const out = Object.assign({}, ticket, {
    encPart: Object.assign({}, ticket.encPart, { cipher: cipher }) });
  delete out.raw;
  log.debug("Leaving resealed().");
  return out;
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== set-up: four services, their delegation, two people ===");
  const keys = {};
  for (const role of ROLES) {
    const made = await call("POST", "/kerberos/principals/create-service",
                            { spn: "HTTP/" + host(role) });
    assert.ok(made.status === 200 && made.body.keytab, "create-service " +
              role + ": " + String(made.text).slice(0, 300));
    keys[role] = keysOf(made.body.keytab);
  }
  const set = async function (role, attribute, mode, value) {
    log.debug("Entering set().");
    await ok("/applications/" + mode, { application: idOf(role),
             attribute: attribute, value: value },
             mode + " " + attribute + " on " + role);
    log.debug("Leaving set().");
  };
  await set("front", "appAllowedToDelegateTo", "add", idOf("back"));
  await set("front", "appDelegationSemantics", "add", "delegation");
  await set("front", "appDelegationSemantics", "add", "impersonation");
  await set("notrusted", "appAllowedToDelegateTo", "add", idOf("back"));
  await set("rbcd", "appAllowedToActOnBehalfOf", "add", idOf("front"));
  await set("trusted", "krb5TrustedForDelegation", "set", "TRUE");
  for (const who of [PERSON, PROTECTED]) {
    await ok("/users/create", { username: who, invent: false,
                                credential: "password", password: PASSWORD,
                                attributes: { cn: who, sn: who } },
             "created " + who);
  }
  await ok("/users/set-not-delegated", { user: PROTECTED, value: true },
           "set stsNotDelegated on " + PROTECTED);
  const protectedKeytab = await call("POST",
    "/kerberos/principals/reset-person-keytab",
    { username: PROTECTED, password: KEYTAB_PASSWORD });
  assert.ok(protectedKeytab.status === 200 && protectedKeytab.body.keytab,
            "a keytab for the protected person: " +
            String(protectedKeytab.text).slice(0, 300));
  const personKeytab = await call("POST",
    "/kerberos/principals/reset-person-keytab",
    { username: PERSON, password: KEYTAB_PASSWORD });
  assert.ok(personKeytab.status === 200 && personKeytab.body.keytab,
            "a keytab for the person: " +
            String(personKeytab.text).slice(0, 300));
  const tgts = {
    front: await tgtWith("HTTP/" + host("front"), keys.front),
    notrusted: await tgtWith("HTTP/" + host("notrusted"), keys.notrusted),
    person: await tgtWith(PERSON, keysOf(personKeytab.body.keytab)),
    protected: await tgtWith(PROTECTED, keysOf(protectedKeytab.body.keytab))
  };
  log.debug("Leaving setUp().");
  return { keys: keys, tgts: tgts };
}

async function selfSection(w) {
  log.debug("Entering selfSection().");
  log.info("=== 1. S4U2Self ===");
  let r = await s4u2self(w.tgts.front, PERSON);
  check("1a. by a service allowing impersonation: FORWARDABLE", function () {
    assert.ok(forwardable(r), JSON.stringify(r.ok ? r.flagNames
                                                  : String(r.error)));
  });
  const evidence = r.ticket;
  r = await s4u2self(w.tgts.notrusted, PERSON);
  check("1b. by one that does not: issued, NOT forwardable", function () {
    assert.ok(r.ok && !forwardable(r), String(r.error || r.flagNames));
  });
  const weak = r.ticket;
  r = await s4u2self(w.tgts.front, PROTECTED);
  check("1c. for the protected person: issued, NOT forwardable", function () {
    assert.ok(r.ok && !forwardable(r), String(r.error || r.flagNames));
  });
  const protectedEvidence = r.ticket;
  r = await wire.tgsExchange(K.transport, w.tgts.front, w.tgts.front.client,
    K.realm, { padata: async function (nonce) {
      return [await wire.paS4uX509User(w.tgts.front,
        { nonce: nonce, realm: K.realm, name: PERSON })];
    } });
  check("1d. PA-S4U-X509-USER by name: a forwardable ticket, and the reply " +
        "carries PA-S4U-X509-USER back", function () {
    assert.ok(forwardable(r), String(r.error || r.flagNames));
    assert.ok(r.replyPadata.some(function (pa) {
      return pa.type === msgs.PA_TYPE.S4U_X509_USER;
    }), JSON.stringify(r.replyPadata.map(function (pa) {
      return pa.type;
    })));
  });
  r = await wire.tgsExchange(K.transport, w.tgts.front, w.tgts.front.client,
    K.realm, { padata: async function (nonce) {
      return [await wire.paS4uX509User(w.tgts.front,
        { nonce: nonce, realm: K.realm, name: PERSON }, true)];
    } });
  check("1e. and with a checksum that does not verify: KRB_AP_ERR_MODIFIED",
        function () {
          refusedWith(r, 41);
        });
  log.debug("Leaving selfSection().");
  return { evidence: evidence, weak: weak,
           protectedEvidence: protectedEvidence };
}

async function proxySection(w, ev) {
  log.debug("Entering proxySection().");
  log.info("=== 2. S4U2Proxy ===");
  let r = await s4u2proxy(w.tgts.front, ev.evidence, "back");
  check("2a. classic: the front end's appAllowedToDelegateTo names the back " +
        "end — a ticket to it as the person", function () {
    assert.ok(r.ok, String(r.error || ""));
    assert.strictEqual(r.client.name.join("/"), PERSON);
  });
  r = await s4u2proxy(w.tgts.front, ev.evidence, "trusted");
  check("2b. to a back end nothing names: KDC_ERR_BADOPTION, naming the " +
        "entries' attributes", function () {
    refusedWith(r, 13);
    assert.ok(/appAllowedToDelegateTo/.test(r.error.eText), r.error.eText);
  });
  r = await s4u2proxy(w.tgts.front, ev.evidence, "rbcd", true);
  check("2c. resource-based with PA-PAC-OPTIONS", function () {
    assert.ok(r.ok, String(r.error || ""));
  });
  r = await s4u2proxy(w.tgts.front, ev.evidence, "rbcd", false);
  check("2d. and without it: KDC_ERR_BADOPTION", function () {
    refusedWith(r, 13);
  });
  r = await s4u2proxy(w.tgts.notrusted, ev.weak, "back");
  check("2e. classic with evidence that is not forwardable: " +
        "KDC_ERR_BADOPTION", function () {
    refusedWith(r, 13);
    assert.ok(/not forwardable/.test(r.error.eText), r.error.eText);
  });
  const flipped = await resealed(ev.weak, w.keys.notrusted, function (part) {
    if (part.flags.indexOf(msgs.TICKET_FLAG.FORWARDABLE) < 0) {
      part.flags.push(msgs.TICKET_FLAG.FORWARDABLE);
    }
  });
  r = await s4u2proxy(w.tgts.notrusted, flipped, "back");
  check("2f. evidence whose forwardable flag the requester set itself " +
        "(CVE-2020-17049): KRB_AP_ERR_MODIFIED", function () {
    refusedWith(r, 41);
  });
  const forged = await resealed(ev.evidence, w.keys.front, function (part) {
    part.cname = { type: 1, name: [PROTECTED] };
    part.authorizationData = null;
  });
  r = await s4u2proxy(w.tgts.front, forged, "back");
  check("2g. evidence FORGED with the front end's own key: " +
        "KRB_AP_ERR_MODIFIED", function () {
    refusedWith(r, 41);
  });
  r = await s4u2proxy(w.tgts.front, ev.protectedEvidence, "rbcd", true);
  check("2h. the protected person over resource-based delegation: their " +
        "S4U2Self ticket is not forwardable, which [MS-SFU] 3.2.5.2.3 " +
        "refuses — KDC_ERR_BADOPTION (#492)", function () {
    refusedWith(r, 13);
    assert.ok(/3\.2\.5\.2\.3/.test(r.error.eText), r.error.eText);
  });
  log.debug("Leaving proxySection().");
}

async function forwardedSection(w) {
  log.debug("Entering forwardedSection().");
  log.info("=== 3. forwarded TGTs and ok-as-delegate ===");
  check("3a. the protected person's TGT is not forwardable; the person's is",
        function () {
          assert.ok(w.tgts.person.flagNames.indexOf("forwardable") >= 0);
          assert.ok(w.tgts.protected.flagNames.indexOf("forwardable") < 0,
                    w.tgts.protected.flagNames.join());
        });
  const krbtgt = { type: 2, name: ["krbtgt", K.realm] };
  let r = await wire.tgsExchange(K.transport, w.tgts.protected, krbtgt,
    K.realm, { kdcOptions: [msgs.KDC_OPTION.FORWARDED] });
  check("3b. and cannot be forwarded", function () {
    refusedWith(r, 13);
  });
  r = await wire.tgsExchange(K.transport, w.tgts.person, sname("trusted"),
                             K.realm);
  check("3c. krb5TrustedForDelegation puts ok-as-delegate on a service's " +
        "tickets", function () {
    assert.ok(r.ok && r.flagNames.indexOf("ok-as-delegate") >= 0,
              String(r.error || r.flagNames));
  });
  r = await wire.tgsExchange(K.transport, w.tgts.person, sname("back"),
                             K.realm);
  check("3d. and a service without it gets none", function () {
    assert.ok(r.ok && r.flagNames.indexOf("ok-as-delegate") < 0,
              String(r.error || r.flagNames));
  });
  log.debug("Leaving forwardedSection().");
}

async function entriesSection(w, ev) {
  log.debug("Entering entriesSection().");
  log.info("=== 4. the entries are the truth, and the acts are recorded ===");
  await ok("/applications/remove", { application: idOf("front"),
           attribute: "appAllowedToDelegateTo", value: idOf("back") },
           "removed the front end's rule");
  let r = await s4u2proxy(w.tgts.front, ev.evidence, "back");
  check("4a. the edit changes the next answer: classic is refused",
        function () {
          refusedWith(r, 13);
        });
  await ok("/applications/add", { application: idOf("front"),
           attribute: "appAllowedToDelegateTo", value: idOf("back") },
           "restored the front end's rule");
  r = await s4u2proxy(w.tgts.front, ev.evidence, "back");
  check("4b. and restoring it allows it again", function () {
    assert.ok(r.ok, String(r.error || ""));
  });
  // Each kind asked for by its own filter: the list is PAGED, newest first,
  // and a page of one kind would hide the others.
  const kinds = [["krb5-s4u2proxy-classic", "issued"],
                 ["krb5-s4u2proxy-classic", "refused"],
                 ["krb5-s4u2self", "issued"]];
  const found = [];
  for (const kind of kinds) {
    const acts = await call("GET", "/delegation?type=" + kind[0] +
                            "&outcome=" + kind[1]);
    found.push({ kind: kind.join(" "), status: acts.status,
                 count: ((acts.body && acts.body.acts) || []).length });
  }
  check("4c. the acts, refusals included, are on GET /admin-api/delegation",
        function () {
          assert.ok(found.every(function (one) {
            return one.status === 200 && one.count > 0;
          }), JSON.stringify(found));
        });
  log.debug("Leaving entriesSection().");
}

async function test() {
  log.debug("Entering test().");
  K.product = await facts.isProduct(api);
  K.realm = String(process.env.KRB5_REALM ||
                   await facts.setting(api, "krb5.realm") || "");
  K.kdcHost = process.env.STS_KDC_HOST || new URL(base).hostname;
  K.kdcPort = Number(process.env.STS_KDC_PORT ||
                     await facts.setting(api, "krb5.kdcPort") || 88);
  K.transport = wire.tcpTransport(K.kdcHost, K.kdcPort);
  log.info("mode " + (K.product ? "product" : "development") + ", realm " +
           K.realm + ", KDC " + K.kdcHost + ":" + K.kdcPort);
  const w = await setUp();
  const ev = await selfSection(w);
  await proxySection(w, ev);
  await forwardedSection(w);
  await entriesSection(w, ev);
  assert.ok(checks >= 20, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_delegation")
  .description("Kerberos S4U2Self, S4U2Proxy, forwarded TGTs and " +
    "PA-S4U-X509-USER over TCP 88, decided by the one delegation policy " +
    "over the directory's entries.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
