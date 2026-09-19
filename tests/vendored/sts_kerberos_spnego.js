"use strict";
//
// File: sts_kerberos_spnego.js
//
// ---------------------------------------------------------------------------
// KERBEROS V5 AND SPNEGO OVER THE NETWORK, AT THE ADDRESS THE SERVICE IS
// REACHED AT (2026-09-18).
//
// Until this file one Kerberos sign-in touched a deployed service from
// outside: an AS exchange over MS-KKDCP inside `sts_global_logout.js`, which
// asks only "was a TGT issued". Everything else about this directory's
// Kerberos — the raw socket on 88, the TGS, the acceptor, SPNEGO — was tested
// IN PROCESS (`tests/kerberos_*.js`, `tests/spnego_identity.js`) or by the
// parent project against a local stack. None of that can see what a
// deployment adds between a client and the KDC: a load balancer passing TCP 88
// through with a PROXY protocol v2 header, three nodes that must agree about
// one principal database and one replay cache, a Kerberos realm and service
// principal that are not the development defaults, and keys derived from a
// person's own password (kerberos/CLAUDE.md, *STORED LONG-TERM KEYS*). So this
// job is a Kerberos CLIENT pointed at the service's public address, and it
// does what a workstation does, in order:
//
//   1. AS EXCHANGE OVER RAW TCP (RFC 4120 section 7.2.2's four-byte framing)
//      for a person created beforehand with a password: the bare AS-REQ is
//      refused KDC_ERR_PREAUTH_REQUIRED with a method list that names
//      PA-ENC-TIMESTAMP (the 2026-08-27 fix, kerberos/CLAUDE.md) and an
//      ETYPE-INFO2 whose salt is the realm's convention; the PA-ENC-TIMESTAMP
//      one gets a TGT whose enc-part OPENS under the key derived from the
//      person's password — the client's proof the KDC holds the same key.
//   2. TGS EXCHANGE for the acceptor's service principal — read from the
//      `X-Krb5-Service-Principal` header the SPNEGO door volunteers and held
//      to `krb5.servicePrincipal` — giving a service ticket.
//   3. SPNEGO SIGN-IN at `GET /authn/spnego`: a NegTokenInit around a GSS
//      AP-REQ, with a mechListMIC, answered 200 with a session cookie, a
//      bare NegTokenResp (accept-completed) and an AP-REP whose ctime/cusec
//      echo proves the acceptor held the service key (mutual authentication).
//      The session is then found on `/admin-api/sessions` under the cookie's
//      own id, marked SPNEGO, with `amr` read off the ticket's pre-authent
//      flag.
//   4. THE SAME AS EXCHANGE OVER MS-KKDCP (`POST /KdcProxy`), agreeing with
//      TCP 88 on everything a client can see — the method list, the salt, the
//      ticket flags — and a TGT from one door spent at the other.
//
// AND THE NEGATIVES, WHICH ARE HALF OF IT ON PURPOSE. A KDC that issues a
// ticket to the right password looks finished and is worth little; what makes
// it worth anything is what it refuses, and saying which refusal it was:
//
//   * a wrong password: KDC_ERR_PREAUTH_FAILED (24), over both transports;
//   * an unknown principal: KDC_ERR_C_PRINCIPAL_UNKNOWN (6) — in development
//     a name `krb5.unknownUsers` keeps unknown (the KDC invents any other),
//     in product a name nobody provisioned;
//   * a realm name the KDC does not serve: KDC_ERR_WRONG_REALM (68), over
//     both transports;
//   * a service ticket for a principal that does not exist:
//     KDC_ERR_S_PRINCIPAL_UNKNOWN (7) — and, by mode, a host inside
//     `krb5.serviceDomains`: invented on first sight in development, refused
//     in product, which creates nothing on demand;
//   * at the acceptor: the SAME Authenticator presented twice is
//     KRB_AP_ERR_REPEAT (34) and mints no session — across three nodes that
//     is the cluster claim (`kerberos.replay-cache`), since a load balancer
//     sends the second request wherever it likes — while a FRESH
//     Authenticator on the same ticket is accepted again, which is what shows
//     the refusal was about the replay and not the ticket; a TGT presented
//     as a service ticket is KRB_AP_ERR_NOT_US (35); an Authenticator with
//     one flipped byte is KRB_AP_ERR_BAD_INTEGRITY (31); one an hour off the
//     clock is KRB_AP_ERR_SKEW (37);
//   * at the HTTP layer: the first request is a bare `Negotiate` challenge
//     with no token (RFC 4559 section 4), a token that is not SPNEGO and a
//     scheme that is not Negotiate are both 401, and none of these mints a
//     session.
//
// ---------------------------------------------------------------------------
// WHAT IT CHANGES ON THE SERVICE: ONE PERSON, AND NOTHING ELSE.
//
// The person is created through `/admin-api` with a password of their own
// (`registry.ensurePerson()`), which in product mode is what derives their
// Kerberos keys. No setting is read-and-changed, no check is loosened: the job
// reads `GET /admin-api/config` for the realm, the KDC's port, the service
// principal and whether the SPNEGO door is open. **If
// `krb5.spnegoAuthentication` is off, the job does NOT turn it on**: it
// asserts the documented refusal instead — 403 naming the setting, with a
// valid ticket, and no session.
//
// WHERE IT DIALS. The KDC's host is the service URL's host and its port is
// `krb5.kdcPort`, which is right for the compose network (`sts:88`) and for a
// load balancer that publishes 88 as 88. `STS_KDC_HOST` / `STS_KDC_PORT`
// override both, for a stack whose published address differs from its own
// idea of it. UDP is not driven: RFC 4120 lets a client use either, the
// deployment this was written against does not publish UDP 88, and the TCP
// path carries every assertion a UDP one could.
//
// BY MODE, AND WHY. Development keys every user from ONE shared password
// (`krb5.userPassword`) and creates any name on first sight; product keys a
// person from their own password and creates nobody. So the password the AS
// exchange presents, the unknown name it asks for, and the on-demand service
// case are branched on `global.mode`; everything else is asserted the same in
// both.
//
// THE CLIENT is `krb5_wire.js` beside this file (a local helper): the
// service's vendored codec for the wire format, and the assembly — key
// usages, checksums, the GSS 0x8003 field, the SPNEGO wrapping — written out
// there rather than borrowed from the KDC or acceptor it is testing.
//
// OWNED HERE (local: true): it drives this repository's own sockets and
// sign-in door, against the address the service is published at.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const facts = require("./service_facts.js");
const registry = require("./sts_applications.js");
const wire = require("./krb5_wire.js");

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
var log = bunyan.createLogger({ name: "sts_kerberos_spnego",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const apiBase = base + "/admin-api";

// The person, generated per run so a leftover row on /admin/users or in the
// principal table names this file. The password is long and mixed because a
// product-mode password policy applies to it like any other.
const USER = usernameFor("krb5-spnego");
const PERSON_PASSWORD = "Krb5-Spnego-Passw0rd!-" +
                        String(Date.now()).slice(-6);

// What the service says it is, filled by learnTheService().
const K = {
  product: false,
  realm: "",
  domain: "",
  kdcHost: "",
  kdcPort: 88,
  servicePrincipal: "",
  password: "",
  unknownUser: "",
  spnegoOn: true
};

// The HTTP path of the sign-in door (authn/authn.ts's SPNEGO_PATH).
const SPNEGO_PATH = "/authn/spnego";

// How long a PRODUCT-mode person's keys may take to appear after the password
// is set. The derivation is queued behind the act
// (kerberos/krb5_person_keys.ts, *THE WINDOW*) — tens of milliseconds on one
// node — and with three nodes the entry the keys are written to also has to
// reach the node the load balancer picked. Measured well under a second;
// twenty is a hung derivation.
const KEYS_WAIT_MS = 20000;

// What TCP 88's ETYPE-INFO2 said, for section 4 to compare MS-KKDCP with.
let tcpInfo = null;

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

// The session cookie a response set, or "" — the value before the first `.`
// is the session's id (the part after it is the rotating handle's MAC), which
// is what /admin-api/sessions lists as `sessionId`.
function sessionCookieOf(res) {
  log.debug("Entering sessionCookieOf().");
  const lines = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  const line = lines.filter(function (one) {
    return /^sts_session=[^;]+/.test(one);
  })[0] || "";
  log.debug("Leaving sessionCookieOf().");
  return (/^sts_session=([^;]*)/.exec(line) || [])[1] || "";
}

// One GET of the sign-in door, with an optional Authorization header, read
// once. `redirect: "manual"` because a pending record would send an accepted
// sign-in onwards with a 303 — none is carried here, so none is expected, and
// following one would hide it.
async function door(authorization) {
  log.debug("Entering door().");
  const headers = {};
  if (authorization) {
    headers.Authorization = authorization;
  }
  const r = await fetch(base + SPNEGO_PATH, { headers: headers,
                                              redirect: "manual" });
  const body = await r.text();
  log.debug("Leaving door(). HTTP " + r.status);
  return { status: r.status, body: body, res: r,
           wwwAuthenticate: r.headers.get("www-authenticate") || "",
           spn: r.headers.get("x-krb5-service-principal") || "",
           cookie: sessionCookieOf(r) };
}

async function negotiateWith(token) {
  log.debug("Entering negotiateWith().");
  log.debug("Leaving negotiateWith().");
  return door("Negotiate " + Buffer.from(token).toString("base64"));
}

// The page body without markup, for assertion messages.
function text(body) {
  log.debug("Entering text().");
  log.debug("Leaving text().");
  return String(body || "").replace(/<style[\s\S]*?<\/style>/g, " ")
    .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 500);
}

// Assert a KRB-ERROR with one of `codes`, from an exchange result or from
// what the acceptor's reject token carried.
function refusedWith(error, codes, what) {
  log.debug("Entering refusedWith().");
  assert.ok(error, what + ": expected a KRB-ERROR " + codes.join(" or ") +
            " and there was none");
  assert.ok(codes.indexOf(error.code) !== -1,
            what + ": expected KRB-ERROR " + codes.join(" or ") + ", got " +
            error.toString());
  log.debug("Leaving refusedWith().");
}

// ---------------------------------------------------------------------------
// WHAT THE SERVICE IS, asked rather than assumed (service_facts.js).
// ---------------------------------------------------------------------------
async function learnTheService() {
  log.debug("Entering learnTheService().");
  K.product = await facts.isProduct(apiBase);
  K.realm = String(process.env.KRB5_REALM ||
                   await facts.setting(apiBase, "krb5.realm") || "");
  K.domain = K.realm.toLowerCase();
  K.kdcHost = process.env.STS_KDC_HOST || new URL(base).hostname;
  K.kdcPort = Number(process.env.STS_KDC_PORT ||
                     await facts.setting(apiBase, "krb5.kdcPort") || 88);
  K.servicePrincipal = String(
    await facts.setting(apiBase, "krb5.servicePrincipal") || "");
  const enabled = await facts.setting(apiBase, "krb5.enabled");
  const spnegoOn = await facts.setting(apiBase, "krb5.spnegoAuthentication");
  K.spnegoOn = spnegoOn !== false && String(spnegoOn) !== "false";
  if (K.product) {
    // A person's keys are derived from THEIR password (krb5_person_keys.ts).
    K.password = PERSON_PASSWORD;
    // Nobody is created on demand, so any name nobody provisioned is unknown.
    // Kept inside the username rules and marked as this job's.
    K.unknownUser = usernameFor("krb5-nobody");
  } else {
    // One password for every user account (kerberos/CLAUDE.md, *Kerberos is
    // the exception*), and a name the KDC keeps unknown on purpose — any
    // other it would create on first sight.
    K.password = String(await facts.setting(apiBase, "krb5.userPassword") ||
                        "password!");
    const reserved = await facts.setting(apiBase, "krb5.unknownUsers");
    K.unknownUser = String((Array.isArray(reserved) ? reserved
      : String(reserved || "nosuchuser").split(","))[0] || "nosuchuser")
      .trim();
  }
  log.info("mode " + (K.product ? "product" : "development") + ", realm " +
           K.realm + ", KDC " + K.kdcHost + ":" + K.kdcPort + ", service " +
           K.servicePrincipal + ", SPNEGO sign-in " +
           (K.spnegoOn ? "on" : "OFF"));
  check("the service has Kerberos on and names a realm", function () {
    assert.ok(enabled === true || String(enabled) === "true",
              "krb5.enabled is " + JSON.stringify(enabled) + " on " + base +
              "; this job cannot exercise a KDC that is switched off, and " +
              "will not switch it on");
    assert.ok(/^[A-Z0-9.-]+$/.test(K.realm),
              "krb5.realm is " + JSON.stringify(K.realm));
    assert.ok(K.servicePrincipal.indexOf("/") > 0,
              "krb5.servicePrincipal is " +
              JSON.stringify(K.servicePrincipal));
  });
  log.debug("Leaving learnTheService().");
}

// ---------------------------------------------------------------------------
// THE AS EXCHANGE FOR THE PERSON, waiting out product mode's derivation
// window (and, on a cluster, the entry reaching the node that answers). Only
// the refusals that window produces are retried — the "sign in once" e-text,
// or a node that has not seen the entry yet — so a wrong key is still
// reported at once.
// ---------------------------------------------------------------------------
async function asForThePerson(transport) {
  log.debug("Entering asForThePerson(). " + transport.label);
  const started = Date.now();
  let result = await wire.asExchange(transport, K.realm, USER,
                                     { password: K.password });
  const waiting = function (r) {
    log.debug("Entering waiting().");
    const e = (r.second && r.second.error) || (r.first && r.first.error);
    const again = !!(K.product && !r.tgt && e &&
                     /no Kerberos keys yet|sign in once|nobody by that name/i
                       .test(e.eText) && Date.now() - started < KEYS_WAIT_MS);
    log.debug("Leaving waiting(). " + again);
    return again;
  };
  while (waiting(result)) {
    await pause(500);
    result = await wire.asExchange(transport, K.realm, USER,
                                   { password: K.password });
  }
  if (Date.now() - started > 600) {
    log.info("  the KDC keyed " + USER + " after " +
             (Date.now() - started) + "ms");
  }
  log.debug("Leaving asForThePerson().");
  return result;
}

// Everything section 1 asserts about an AS exchange, for either transport.
function assertAsExchange(result, label) {
  log.debug("Entering assertAsExchange(). " + label);
  check(label + ": the bare AS-REQ is refused KDC_ERR_PREAUTH_REQUIRED, and " +
        "the method list names PA-ENC-TIMESTAMP and ETYPE-INFO2",
        function () {
          refusedWith(result.first && result.first.error, [25],
                      label + ": the first, unauthenticated AS-REQ for " +
                      USER + "@" + K.realm);
          assert.ok(result.offered.indexOf(wire.msgs.PA_TYPE.ENC_TIMESTAMP) !==
                    -1,
                    label + ": PA-ENC-TIMESTAMP (2) must be OFFERED in the " +
                    "METHOD-DATA, or no MIT-derived client can get a ticket " +
                    "(kerberos/CLAUDE.md). Offered: " + result.offered);
          assert.ok(result.offered.indexOf(wire.msgs.PA_TYPE.ETYPE_INFO2) !==
                    -1, label + ": and an ETYPE-INFO2. Offered: " +
                    result.offered);
        });
  check(label + ": the ETYPE-INFO2 names an AES type and the realm's salt " +
        "(REALM + name)", function () {
          assert.ok(result.info, label + ": no ETYPE-INFO2 entry for " +
                    wire.ETYPES.join("/"));
          assert.strictEqual(result.info.salt, K.realm + USER,
                             label + ": the salt");
        });
  check(label + ": the PA-ENC-TIMESTAMP AS-REQ gets a TGT whose enc-part " +
        "opens under the key derived from the person's password",
        function () {
          assert.ok(result.tgt, label + ": no TGT for " + USER + "@" +
                    K.realm + ": " +
                    (result.second && result.second.error
                       ? result.second.error.toString()
                       : JSON.stringify(result.first)));
          assert.ok(result.tgt.nonceEchoed,
                    label + ": the enc-part must echo the request's nonce");
        });
  check(label + ": the TGT is krbtgt/" + K.realm + " for " + USER +
        ", flagged initial and pre-authent", function () {
          assert.deepStrictEqual(result.tgt.sname.name,
                                 ["krbtgt", K.realm], label);
          assert.strictEqual(result.tgt.srealm, K.realm, label);
          assert.strictEqual(result.tgt.realm, K.realm, label);
          assert.deepStrictEqual(result.tgt.client.name, [USER], label);
          assert.ok(result.tgt.flagNames.indexOf("initial") !== -1 &&
                    result.tgt.flagNames.indexOf("pre-authent") !== -1,
                    label + ": flags " + result.tgt.flagNames.join(","));
        });
  log.debug("Leaving assertAsExchange().");
}

// ---------------------------------------------------------------------------
// 1. THE AS EXCHANGE OVER RAW TCP, and the KDC's refusals.
// ---------------------------------------------------------------------------
async function asOverTcp(tcp) {
  log.debug("Entering asOverTcp().");
  log.info("=== 1. the AS exchange over " + tcp.label + " ===");
  const result = await asForThePerson(tcp);
  assertAsExchange(result, "TCP");
  // Kept for section 4, which holds MS-KKDCP to what TCP 88 said.
  tcpInfo = result.info;

  const wrong = await wire.asExchange(tcp, K.realm, USER,
                                      { password: K.password + "-wrong" });
  check("TCP: a wrong password is KDC_ERR_PREAUTH_FAILED and no TGT",
        function () {
          assert.ok(!wrong.tgt, "a TGT was issued for a wrong password");
          refusedWith(wrong.second && wrong.second.error, [24],
                      "the AS-REQ with a timestamp under the wrong key");
        });

  const unknown = await wire.asExchange(tcp, K.realm, K.unknownUser,
                                        { password: K.password });
  check("TCP: an unknown principal (" + K.unknownUser + ") is " +
        "KDC_ERR_C_PRINCIPAL_UNKNOWN, before any pre-authentication",
        function () {
          assert.ok(!unknown.tgt, "a TGT was issued for " + K.unknownUser);
          refusedWith(unknown.first && unknown.first.error, [6],
                      "the AS-REQ for " + K.unknownUser + "@" + K.realm);
        });

  const foreign = "NOT-SERVED-" + String(Date.now()).slice(-6) + ".INVALID";
  const wrongRealm = await wire.asExchange(tcp, foreign, USER,
                                           { password: K.password });
  check("TCP: a realm the KDC does not serve (" + foreign + ") is " +
        "KDC_ERR_WRONG_REALM, naming the realm it does", function () {
          assert.ok(!wrongRealm.tgt, "a TGT was issued in " + foreign);
          refusedWith(wrongRealm.first && wrongRealm.first.error, [68],
                      "the AS-REQ in " + foreign);
          assert.strictEqual(wrongRealm.first.error.realm, K.realm,
                             "the KRB-ERROR's realm is the KDC's own");
        });
  log.debug("Leaving asOverTcp().");
  return result.tgt;
}

// ---------------------------------------------------------------------------
// 2. THE TGS EXCHANGE for the acceptor's service principal.
// ---------------------------------------------------------------------------
async function tgsOverTcp(tcp, tgt, spnHeader) {
  log.debug("Entering tgsOverTcp().");
  log.info("=== 2. the TGS exchange over " + tcp.label + " ===");
  const spn = spnHeader.replace(/@[^@]*$/, "");
  const sname = { type: wire.msgs.NAME_TYPE.SRV_HST, name: spn.split("/") };
  const ticket = await wire.tgsExchange(tcp, tgt, sname);
  check("TCP: a TGS-REQ for " + spn + " with the TGT gets a service ticket " +
        "for that principal", function () {
          assert.ok(ticket.ok, "the TGS-REQ for " + spn + " was refused: " +
                    (ticket.error ? ticket.error.toString() : "?"));
          assert.strictEqual(ticket.kind, "TGS-REP", "the reply kind");
          assert.deepStrictEqual(ticket.sname.name, spn.split("/"),
                                 "the ticket's sname");
          assert.strictEqual(ticket.srealm, K.realm, "the ticket's srealm");
          assert.deepStrictEqual(ticket.client.name, [USER],
                                 "the ticket's client");
          assert.ok(ticket.nonceEchoed, "the enc-part echoes the nonce");
        });
  check("TCP: the service ticket carries pre-authent from the TGT and is " +
        "not initial", function () {
          assert.ok(ticket.flagNames.indexOf("pre-authent") !== -1 &&
                    ticket.flagNames.indexOf("initial") === -1,
                    "flags " + ticket.flagNames.join(","));
        });

  const nowhere = await wire.tgsExchange(tcp, tgt, {
    type: wire.msgs.NAME_TYPE.SRV_HST,
    name: ["HTTP", "no-such-host-" + String(Date.now()).slice(-6) +
                   ".invalid"] });
  check("TCP: a ticket for a service principal that does not exist is " +
        "KDC_ERR_S_PRINCIPAL_UNKNOWN", function () {
          assert.ok(!nowhere.ok, "a ticket was issued for a host in .invalid");
          refusedWith(nowhere.error, [7], "the TGS-REQ for .invalid");
        });

  // A host INSIDE the realm's own domain, which `krb5.serviceDomains` lists:
  // the development KDC creates a service for it on first sight (it is both
  // the KDC and the acceptor, so the key is not unknown to anybody), and a
  // product KDC creates nothing on demand (kerberos/CLAUDE.md, *PRODUCT
  // MODE*).
  const inDomain = "HTTP/krb5-spnego-" + String(Date.now()).slice(-6) + "." +
                   K.domain;
  const onDemand = await wire.tgsExchange(tcp, tgt, {
    type: wire.msgs.NAME_TYPE.SRV_HST, name: inDomain.split("/") });
  if (K.product) {
    check("TCP (product): " + inDomain + " is NOT created on demand — " +
          "KDC_ERR_S_PRINCIPAL_UNKNOWN", function () {
            assert.ok(!onDemand.ok, "a product KDC issued a ticket for an " +
                      "unprovisioned " + inDomain);
            refusedWith(onDemand.error, [7], "the TGS-REQ for " + inDomain);
          });
  } else {
    check("TCP (development): " + inDomain + " is created on first sight " +
          "and ticketed", function () {
            assert.ok(onDemand.ok, "the development KDC refused " + inDomain +
                      ": " + (onDemand.error ? onDemand.error.toString() :
                              "?"));
          });
  }
  log.debug("Leaving tgsOverTcp().");
  return ticket;
}

// ---------------------------------------------------------------------------
// 3. THE SPNEGO SIGN-IN.
// ---------------------------------------------------------------------------

// The session this job's cookie names, as /admin-api/sessions lists it, and
// the TGT rows the AS exchanges left. Read until both are there: with several
// nodes the listing is assembled from shared state that may trail the answer
// that created it by a moment.
async function sessionsOf(sessionId) {
  log.debug("Entering sessionsOf().");
  const started = Date.now();
  let found = { session: null, tgts: [] };
  for (;;) {
    const r = await fetch(apiBase + "/sessions?per=500&q=" +
                          encodeURIComponent(USER),
                          { headers: { Accept: "application/json" } });
    const body = await r.json();
    const rows = body.sessions || [];
    found = {
      session: rows.filter(function (row) {
        return row.family === "session" && row.sessionId === sessionId;
      })[0] || null,
      tgts: rows.filter(function (row) {
        return row.family === "krb5" &&
               String(row.username) === USER + "@" + K.realm;
      })
    };
    if ((found.session && found.tgts.length) ||
        Date.now() - started > 15000) {
      break;
    }
    await pause(500);
  }
  log.debug("Leaving sessionsOf().");
  return found;
}

async function spnegoSignIn(tgt, ticket) {
  log.debug("Entering spnegoSignIn().");
  log.info("=== 3. SPNEGO sign-in at " + base + SPNEGO_PATH + " ===");

  const built = await wire.apRequest(ticket);
  const token = await wire.negTokenInit(built, { mic: true });
  const first = await negotiateWith(token);
  check("the NegTokenInit (Kerberos first, with a mechListMIC) is " +
        "accepted: 200 and a session cookie", function () {
          assert.strictEqual(first.status, 200,
                             "GET " + SPNEGO_PATH + " with a valid ticket " +
                             "answered " + first.status + ": " +
                             text(first.body));
          assert.ok(first.cookie, "no sts_session cookie was set");
          assert.ok(first.body.indexOf("<strong>" + USER + "</strong>") !==
                    -1, "the page must name " + USER + ": " +
                    text(first.body));
        });
  const reply = await wire.readNegotiate(first.wwwAuthenticate, ticket, built);
  check("the 200 carries a bare NegTokenResp, accept-completed, selecting " +
        "Kerberos", function () {
          assert.ok(reply, "no Negotiate token on the 200 — the mutual half " +
                    "of the exchange travels in that header");
          assert.strictEqual(reply.first, 0xa1,
                             "a reply token is a BARE NegTokenResp (RFC " +
                             "4178 section 4.2), not an InitialContextToken");
          assert.strictEqual(reply.negStateName, "accept-completed");
          assert.strictEqual(reply.supportedMech,
                             wire.spnego.KRB5_MECH_OID);
        });
  check("its AP-REP echoes the Authenticator's ctime and cusec under the " +
        "ticket's session key — mutual authentication", function () {
          assert.ok(reply.apRep, "the responseToken is not an AP-REP" +
                    (reply.error ? ": " + reply.error.toString() : ""));
          assert.ok(reply.apRep.ctimeEchoed && reply.apRep.cusecEchoed,
                    "the echo does not match what was sent");
          assert.ok(reply.apRep.acceptorSubkey,
                    "and the acceptor offers a subkey");
        });

  const sessionId = first.cookie.split(".")[0];
  const listed = await sessionsOf(sessionId);
  check("the session is on /admin-api/sessions under the cookie's id: " +
        USER + ", SPNEGO, amr pwd from the ticket's pre-authent flag",
        function () {
          assert.ok(listed.session, "no browser session " + sessionId +
                    " for " + USER);
          assert.strictEqual(listed.session.username, USER);
          assert.ok(/SPNEGO/.test(String(listed.session.protocol)),
                    "protocol " + listed.session.protocol);
          assert.deepStrictEqual(listed.session.amr, ["pwd"],
                                 "amr " + JSON.stringify(listed.session.amr));
        });
  check("and the KDC's TGTs for " + USER + "@" + K.realm + " are listed too",
        function () {
          assert.ok(listed.tgts.length >= 1, "no krb5 row for " + USER + "@" +
                    K.realm);
        });

  // THE SAME TOKEN AGAIN — byte for byte, so the same Authenticator. With
  // several nodes the load balancer may well deliver it to one that did not
  // see the first, which is exactly the case the cluster claim exists for.
  const replay = await negotiateWith(token);
  const replayed = await wire.readNegotiate(replay.wwwAuthenticate, ticket,
                                            built);
  check("the same Authenticator a second time is KRB_AP_ERR_REPEAT, 401, " +
        "and mints no session", function () {
          assert.strictEqual(replay.status, 401,
                             "a replayed AP-REQ answered " + replay.status +
                             ": " + text(replay.body));
          assert.ok(!replay.cookie, "a replay set a session cookie");
          assert.ok(replayed && replayed.negStateName === "reject",
                    "the reply must be a SPNEGO reject");
          refusedWith(replayed.error, [34], "the replay");
        });

  const fresh = await wire.apRequest(ticket);
  const again = await negotiateWith(await wire.negTokenInit(fresh, {}));
  check("a FRESH Authenticator on the same ticket is accepted — the " +
        "refusal was the replay, not the ticket", function () {
          assert.strictEqual(again.status, 200,
                             "a fresh AP-REQ answered " + again.status + ": " +
                             text(again.body));
          assert.ok(again.cookie, "and sets a session cookie");
        });

  const asTgt = await wire.apRequest(tgt);
  const notUs = await negotiateWith(await wire.negTokenInit(asTgt, {}));
  const notUsReply = await wire.readNegotiate(notUs.wwwAuthenticate, tgt,
                                              asTgt);
  check("a TGT presented as a service ticket is KRB_AP_ERR_NOT_US, 401, no " +
        "session", function () {
          assert.strictEqual(notUs.status, 401, text(notUs.body));
          assert.ok(!notUs.cookie, "a TGT set a session cookie");
          refusedWith(notUsReply && notUsReply.error, [35],
                      "the TGT at the acceptor");
        });

  const corrupt = await wire.apRequest(ticket, { corrupt: true });
  const bad = await negotiateWith(await wire.negTokenInit(corrupt, {}));
  const badReply = await wire.readNegotiate(bad.wwwAuthenticate, ticket,
                                            corrupt);
  check("an Authenticator with one flipped byte is " +
        "KRB_AP_ERR_BAD_INTEGRITY, 401, no session", function () {
          assert.strictEqual(bad.status, 401, text(bad.body));
          assert.ok(!bad.cookie, "a corrupt Authenticator set a cookie");
          refusedWith(badReply && badReply.error, [31],
                      "the corrupt Authenticator");
        });

  const skewed = await wire.apRequest(ticket, { ctimeOffsetMs: -3600000 });
  const late = await negotiateWith(await wire.negTokenInit(skewed, {}));
  const lateReply = await wire.readNegotiate(late.wwwAuthenticate, ticket,
                                             skewed);
  check("an Authenticator an hour off the clock is KRB_AP_ERR_SKEW, 401, no " +
        "session", function () {
          assert.strictEqual(late.status, 401, text(late.body));
          assert.ok(!late.cookie, "a skewed Authenticator set a cookie");
          refusedWith(lateReply && lateReply.error, [37],
                      "the skewed Authenticator");
        });
  log.debug("Leaving spnegoSignIn().");
}

// The HTTP-level refusals, which need no ticket at all.
async function spnegoRefusals() {
  log.debug("Entering spnegoRefusals().");
  const garbage = await door("Negotiate " +
    Buffer.from("this is not a SPNEGO token").toString("base64"));
  check("a Negotiate token that is not SPNEGO is 401 and mints no session",
        function () {
          assert.strictEqual(garbage.status, 401, text(garbage.body));
          assert.ok(!garbage.cookie, "a garbage token set a session cookie");
          assert.ok(/^Negotiate\b/i.test(garbage.wwwAuthenticate),
                    "and it is still a Negotiate challenge: " +
                    garbage.wwwAuthenticate);
        });
  const basic = await door("Basic " +
    Buffer.from(USER + ":" + K.password).toString("base64"));
  check("a scheme that is not Negotiate (Basic, with the right password) is " +
        "401 and mints no session", function () {
          assert.strictEqual(basic.status, 401, text(basic.body));
          assert.ok(!basic.cookie, "Basic set a session cookie at the " +
                    "Kerberos door");
        });
  log.debug("Leaving spnegoRefusals().");
}

// With `krb5.spnegoAuthentication` off: the documented refusal, asserted with
// a VALID ticket so it is the setting that refuses and nothing else.
async function spnegoSwitchedOff(ticket) {
  log.debug("Entering spnegoSwitchedOff().");
  log.info("=== 3. SPNEGO sign-in is OFF on this service; asserting the " +
           "refusal (the job does not turn it on) ===");
  const built = await wire.apRequest(ticket);
  const r = await negotiateWith(await wire.negTokenInit(built, {}));
  check("with krb5.spnegoAuthentication off, a valid ticket is 403 naming " +
        "the setting, and mints no session", function () {
          assert.strictEqual(r.status, 403, text(r.body));
          assert.ok(/krb5\.spnegoAuthentication/.test(r.body),
                    "the refusal must name the setting: " + text(r.body));
          assert.ok(!r.cookie, "a session cookie was set anyway");
        });
  log.debug("Leaving spnegoSwitchedOff().");
}

// ---------------------------------------------------------------------------
// 4. THE SAME KDC OVER MS-KKDCP.
// ---------------------------------------------------------------------------
async function asOverProxy(tcp, tcpTgt, spn) {
  log.debug("Entering asOverProxy().");
  const proxy = wire.proxyTransport(base);
  log.info("=== 4. the AS exchange over " + proxy.label + " ===");
  const result = await asForThePerson(proxy);
  assertAsExchange(result, "MS-KKDCP");
  check("MS-KKDCP agrees with TCP: the same etype and salt, the same TGT " +
        "flags", function () {
          assert.deepStrictEqual(result.info, tcpInfo,
                                 "the ETYPE-INFO2 entry (etype, salt, " +
                                 "s2kparams)");
          assert.strictEqual(result.tgt.replyEtype, tcpTgt.replyEtype,
                             "the AS-REP enc-part etype");
          assert.deepStrictEqual(result.tgt.flagNames.slice().sort(),
                                 tcpTgt.flagNames.slice().sort(),
                                 "the TGT flags");
        });

  const wrong = await wire.asExchange(proxy, K.realm, USER,
                                      { password: K.password + "-wrong" });
  check("MS-KKDCP: a wrong password is KDC_ERR_PREAUTH_FAILED, as over TCP",
        function () {
          assert.ok(!wrong.tgt, "a TGT was issued for a wrong password");
          refusedWith(wrong.second && wrong.second.error, [24],
                      "the wrong password over MS-KKDCP");
        });
  const foreign = "NOT-SERVED-" + String(Date.now()).slice(-5) + ".INVALID";
  const wrongRealm = await wire.asExchange(proxy, foreign, USER,
                                           { password: K.password });
  check("MS-KKDCP: a realm the KDC does not serve is KDC_ERR_WRONG_REALM, " +
        "as over TCP", function () {
          refusedWith(wrongRealm.first && wrongRealm.first.error, [68],
                      "the AS-REQ in " + foreign + " over MS-KKDCP");
        });

  // ONE KDC BEHIND TWO DOORS: a TGT the proxy issued, spent on the socket.
  const tcpTicket = await wire.tgsExchange(tcp, result.tgt, {
    type: wire.msgs.NAME_TYPE.SRV_HST, name: spn.split("/") });
  check("a TGT issued over MS-KKDCP gets a service ticket over TCP 88",
        function () {
          assert.ok(tcpTicket.ok, "the TCP TGS-REQ with the proxy's TGT " +
                    "was refused: " +
                    (tcpTicket.error ? tcpTicket.error.toString() : "?"));
        });
  log.debug("Leaving asOverProxy().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving Kerberos and SPNEGO at " + base);
  await learnTheService();

  log.info("=== 0. the person, created with a password of their own ===");
  await registry.ensurePerson(base, USER, PERSON_PASSWORD);
  log.info("  created " + USER);

  // The bare challenge first: it needs no ticket, and it is where this
  // service volunteers the SPN the acceptor holds a key for — which the TGS
  // exchange below asks for (kerberos/spnego_exchange.js, volunteerTheSpn()).
  const bare = await door(null);
  if (K.spnegoOn) {
    check("the first GET of " + SPNEGO_PATH + " is 401 with the bare word " +
          "Negotiate and no token (RFC 4559 section 4), and no session",
          function () {
            assert.strictEqual(bare.status, 401, text(bare.body));
            assert.strictEqual(bare.wwwAuthenticate.trim(), "Negotiate",
                               "the first challenge carries no token");
            assert.ok(!bare.cookie, "a bare GET set a session cookie");
          });
    check("the challenge volunteers the SPN krb5.servicePrincipal names, " +
          "in this realm", function () {
            assert.strictEqual(bare.spn, K.servicePrincipal + "@" + K.realm,
                               "X-Krb5-Service-Principal");
          });
  }
  const spn = (bare.spn || K.servicePrincipal + "@" + K.realm)
    .replace(/@[^@]*$/, "");

  const tcp = wire.tcpTransport(K.kdcHost, K.kdcPort);
  const tgt = await asOverTcp(tcp);
  const ticket = await tgsOverTcp(tcp, tgt, spn);
  if (K.spnegoOn) {
    await spnegoSignIn(tgt, ticket);
    await spnegoRefusals();
  } else {
    await spnegoSwitchedOff(ticket);
  }
  await asOverProxy(tcp, tgt, spn);

  // A FLOOR, so a section that silently stopped being called fails the job
  // rather than passing it with fewer assertions.
  const floor = K.spnegoOn ? 34 : 21;
  assert.ok(checks >= floor, "only " + checks + " checks ran (floor " +
            floor + "); a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_spnego")
  .description("Kerberos v5 over TCP 88 and MS-KKDCP, the TGS exchange and " +
    "the SPNEGO sign-in at /authn/spnego, against the service's published " +
    "address — with the KDC's and the acceptor's refusals.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
