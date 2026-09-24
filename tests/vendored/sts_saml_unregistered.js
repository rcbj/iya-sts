// ===========================================================================
// WHAT A SAML SERVICE PROVIDER NOBODY REGISTERED CAN CAUSE, OVER HTTP (#112).
//
// Until #112 two things answered for any name at all. `/saml2/metadata/{sp}`
// and `/saml11/metadata/{rp}` minted a signed document for whatever segment
// they were asked for, in product mode too. And with `saml2.mdqBaseUrl` set,
// an anonymous AuthnRequest from an unknown entityID started a Metadata Query
// lookup whose answer created the application entry, signed or not.
// `tests/saml_metadata_lifecycle.js` holds every case in process, the
// product-mode answers that verify against a realm trust anchor included.
// This job drives the running service, in TWO REALMS OF ITS OWN — one in each
// mode, whatever mode the process is in — and asserts what a stranger and an
// operator can see:
//
//   1. PER-PROVIDER PATHS. In the product realm `/saml2/metadata|sso|slo/{x}`,
//      `POST /saml2/ars/{x}`, `/saml11/metadata|sso/{x}` and
//      `POST /saml11/responder/{x}` answer 404, text/plain, no-store, for a
//      name nobody registered; a registered service provider's and relying
//      party's documents are 200; asking registers nothing. In the
//      development realm the documents are minted for any name, as always.
//   2. A REQUEST-STARTED LOOKUP. This job serves an MDQ responder of its own,
//      and both realms point `saml2.mdqBaseUrl` at it. In the development
//      realm an anonymous AuthnRequest from an unknown entityID makes the
//      service ask the responder and the entity is registered. In the product
//      realm, which has no trust anchor, the responder is NEVER asked, no
//      application exists afterwards, and `GET /admin-api/saml2` lists the
//      entityID in `mdqRefused`. (The positive product case needs the
//      service to dial this job, which product mode refuses as an internal
//      address — so it is held in process.)
//   3. AN OPERATOR'S IMPORT in the product realm with no trust anchor is
//      refused, and nothing is fetched.
//
// Every realm and application is CREATED by this run and left standing
// (tests/CLAUDE.md, *No job removes a realm*).
//
// THE LISTENER runs in this job on OUTBOUND_TEST_HOST, or GNAP_PUSH_HOST —
// the name the service reaches this runner by.
//
// OWNED HERE (local: true).
// ===========================================================================

"use strict";

const assert = require("assert");
const http = require("http");
const zlib = require("zlib");
const { Command, Option } = require("commander");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_saml_unregistered",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = names.runStamp();
const DEV = ("sud-" + STAMP).replace(/[^a-z0-9-]/g, "").slice(0, 30);
const PROD = ("sup-" + STAMP).replace(/[^a-z0-9-]/g, "").slice(0, 30);
const HOST = process.env.OUTBOUND_TEST_HOST || process.env.GNAP_PUSH_HOST ||
             "localhost";
const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";

let checks = 0;
const failures = [];

async function check(what, fn) {
  log.debug("Entering check(). " + what);
  try {
    await fn();
    checks += 1;
    log.info("  ✓ " + what);
  } catch (e) {
    log.debug("Caught in check(): " + ((e && e.message) || e));
    failures.push(what + " — " + ((e && e.message) || e));
    log.error("  ✗ " + what + "  — " + ((e && e.message) || e));
  }
  log.debug("Leaving check().");
}

function must(condition, message) {
  log.debug("Entering must().");
  if (!condition) {
    log.debug("Leaving must(). Refused.");
    throw new Error("SETUP: " + message);
  }
  log.debug("Leaving must().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function realmBase(realm) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + realm;
}

function nameFor(label) {
  log.debug("Entering nameFor().");
  log.debug("Leaving nameFor().");
  return "https://" + label + "-" + STAMP + ".unregistered.test/saml";
}

// The management API in the realm named; the run's token is attached by
// tests/tools/attach-admin-token.js.
async function api(realm, method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = { method: method, redirect: "manual", headers: {} };
  if (payload !== undefined) {
    options.headers["content-type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const prefix = realm ? realmBase(realm) : base;
  const r = await fetch(prefix + "/admin-api" + path, options);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
    // Not JSON; `text` carries the answer into every message quoting it.
    body = null;
  }
  log.debug("Leaving api(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

// A request with no cookie, no token and no certificate: a stranger's.
async function anonymous(method, url, body) {
  log.debug("Entering anonymous(). " + method + " " + url);
  const r = await fetch(url, {
    method: method, redirect: "manual",
    headers: body === undefined ? {} : { "content-type": "text/xml" },
    body: body });
  const text = r.status >= 300 && r.status < 400 ? "" : await r.text();
  log.debug("Leaving anonymous(). " + r.status);
  return { status: r.status, text: text,
           type: r.headers.get("content-type") || "",
           cache: r.headers.get("cache-control") || "" };
}

async function setting(realm, key, value) {
  log.debug("Entering setting(). " + key);
  const r = await api(realm, "POST", "/config/set",
                      { key: key, value: value });
  must(r.status === 200 && r.body && r.body.ok !== false,
       "setting " + key + " in " + realm + " answered " + r.status + " " +
       r.text.slice(0, 300));
  log.debug("Leaving setting().");
}

async function createApplication(realm, identifier, protocols) {
  log.debug("Entering createApplication(). " + identifier);
  const r = await api(realm, "POST", "/applications/create",
    { identifier: identifier, name: "unregistered " + identifier,
      protocols: protocols, fields: { samlEntityId: [identifier] } });
  must(r.status === 200 && r.body && r.body.ok,
       "creating the application " + identifier + " answered " + r.status +
       " " + r.text.slice(0, 300));
  log.debug("Leaving createApplication().");
}

async function isRegistered(realm, entityId) {
  log.debug("Entering isRegistered().");
  const r = await api(realm, "GET", "/saml2?sp=" +
                                    encodeURIComponent(entityId));
  must(r.status === 200 && r.body, "GET /admin-api/saml2?sp= answered " +
                                   r.status);
  log.debug("Leaving isRegistered(). " + r.body.found);
  return r.body.found === true;
}

function entityDescriptor(entityId) {
  log.debug("Entering entityDescriptor().");
  log.debug("Leaving entityDescriptor().");
  return '<md:EntityDescriptor xmlns:md="' + NS_MD + '" entityID="' +
    entityId + '"><md:SPSSODescriptor protocolSupportEnumeration="' +
    NS_SAMLP + '"><md:AssertionConsumerService Binding="' +
    'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="' +
    'https://acs.unregistered.test/acs" index="0"/></md:SPSSODescriptor>' +
    '</md:EntityDescriptor>';
}

// AN MDQ RESPONDER OF THIS JOB'S OWN: `/mdq/entities/<entityID>` answers the
// unsigned descriptor of whatever it is asked for, and counts the asks.
async function responder() {
  log.debug("Entering responder().");
  const seen = [];
  const server = http.createServer(function (req, res) {
    const path = decodeURIComponent(String(req.url).split("?")[0]);
    seen.push(path);
    const m = /^\/mdq\/entities\/(.+)$/.exec(path);
    if (!m) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("no");
      return;
    }
    res.writeHead(200, { "content-type": "application/samlmetadata+xml" });
    res.end(entityDescriptor(m[1]));
  });
  await new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", resolve);
  });
  const url = "http://" + (HOST.indexOf(":") >= 0 ? "[" + HOST + "]" : HOST) +
              ":" + server.address().port + "/mdq/";
  log.debug("Leaving responder(). " + url);
  return {
    server: server, url: url,
    asked: function (entityId) {
      log.debug("Entering asked().");
      log.debug("Leaving asked().");
      return seen.filter(function (p) {
        return p === "/mdq/entities/" + entityId;
      }).length;
    }
  };
}

function authnRequestUrl(realm, issuer) {
  log.debug("Entering authnRequestUrl().");
  const xml = '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="_' + STAMP.replace(/[^a-z0-9]/gi, "") +
    Date.now() + '" Version="2.0" IssueInstant="' +
    new Date().toISOString() + '"><saml:Issuer>' + issuer +
    '</saml:Issuer></samlp:AuthnRequest>';
  const encoded = zlib.deflateRawSync(Buffer.from(xml, "utf8"))
    .toString("base64");
  log.debug("Leaving authnRequestUrl().");
  return realmBase(realm) + "/saml2/sso?SAMLRequest=" +
         encodeURIComponent(encoded);
}

async function setUp(mdq) {
  log.debug("Entering setUp().");
  for (const row of [[PROD, "product"], [DEV, "development"]]) {
    const made = await api(null, "POST", "/realms/create",
      { id: row[0], domain: row[0] + ".example.net",
        name: "unregistered SAML (" + row[1] + ")",
        overrides: { "global.mode": row[1] } });
    must(made.status === 200 ||
         /already/i.test(JSON.stringify(made.body || made.text)),
         "creating the realm " + row[0] + " answered " + made.status + " " +
         made.text.slice(0, 300));
    await setting(row[0], "saml2.mdqBaseUrl", mdq.url);
    await setting(row[0], "federation.outbound", true);
  }
  // Plain http is a development-only allowance (#171); it is what lets the
  // development realm reach this job's responder at all.
  await setting(DEV, "federation.outboundAllowHttp", true);
  log.debug("Leaving setUp().");
}

// ---------------------------------------------------------------------------
// 1. THE PER-PROVIDER PATHS.
// ---------------------------------------------------------------------------
async function perProviderPaths() {
  log.debug("Entering perProviderPaths().");
  log.info("=== 1. per-provider paths for a name nobody registered ===");
  const sp = nameFor("registered-sp");
  const rp = nameFor("registered-rp");
  for (const realm of [PROD, DEV]) {
    await createApplication(realm, sp, ["saml2"]);
    await createApplication(realm, rp, ["saml11"]);
  }
  const stranger = nameFor("stranger");
  const seg = encodeURIComponent(stranger);
  const paths = [
    ["GET", "/saml2/metadata/" + seg], ["GET", "/saml2/sso/" + seg],
    ["GET", "/saml2/slo/" + seg], ["POST", "/saml2/ars/" + seg],
    ["GET", "/saml11/metadata/" + seg], ["GET", "/saml11/sso/" + seg],
    ["POST", "/saml11/responder/" + seg]];
  for (const row of paths) {
    const r = await anonymous(row[0], realmBase(PROD) + row[1],
                              row[0] === "POST" ? "<x/>" : undefined);
    await check("PRODUCT: " + row[0] + " " + row[1].split("/").slice(0, 3)
                  .join("/") + "/{unregistered} is 404, text/plain, " +
                "no-store", async function () {
      assert.strictEqual(r.status, 404, r.status + " " + r.text.slice(0, 200));
      assert.ok(/text\/plain/.test(r.type), r.type);
      assert.ok(/no-store/.test(r.cache), r.cache);
      assert.ok(!/Cannot (GET|POST)/.test(r.text),
                "Express's own 404 body: the route was not reached");
    });
  }
  await check("PRODUCT: asking registered nothing", async function () {
    assert.strictEqual(await isRegistered(PROD, stranger), false);
  });
  for (const realm of [PROD, DEV]) {
    const mode = realm === PROD ? "PRODUCT" : "DEVELOPMENT";
    const mine = await anonymous("GET", realmBase(realm) +
                                 "/saml2/metadata/" + encodeURIComponent(sp));
    await check(mode + ": a registered service provider's SAML 2.0 " +
                "document is 200", async function () {
      assert.strictEqual(mine.status, 200, mine.text.slice(0, 200));
      assert.ok(/EntityDescriptor/.test(mine.text), mine.text.slice(0, 200));
    });
    const ours11 = await anonymous("GET", realmBase(realm) +
                                   "/saml11/metadata/" +
                                   encodeURIComponent(rp));
    await check(mode + ": a registered relying party's SAML 1.1 document " +
                "is 200", async function () {
      assert.strictEqual(ours11.status, 200, ours11.text.slice(0, 200));
    });
  }
  const devStranger = nameFor("dev-stranger");
  const minted = await anonymous("GET", realmBase(DEV) + "/saml2/metadata/" +
                                 encodeURIComponent(devStranger));
  const minted11 = await anonymous("GET", realmBase(DEV) +
                                   "/saml11/metadata/" +
                                   encodeURIComponent(devStranger));
  await check("DEVELOPMENT: both documents are minted for a name nobody " +
              "registered, as always", async function () {
    assert.strictEqual(minted.status, 200, minted.text.slice(0, 200));
    assert.ok(/EntityDescriptor/.test(minted.text), minted.text.slice(0, 200));
    assert.strictEqual(minted11.status, 200, minted11.text.slice(0, 200));
  });
  log.debug("Leaving perProviderPaths().");
}

// ---------------------------------------------------------------------------
// 2. A LOOKUP AN ANONYMOUS REQUEST STARTS.
// ---------------------------------------------------------------------------
async function requestStartedLookup(mdq) {
  log.debug("Entering requestStartedLookup().");
  log.info("=== 2. a Metadata Query lookup an AuthnRequest starts ===");
  const devName = nameFor("dev-lookup");
  const devAnswer = await anonymous("GET", authnRequestUrl(DEV, devName));
  let registered = false;
  for (let i = 0; i < 40 && !registered; i++) {
    await sleep(250);
    registered = await isRegistered(DEV, devName);
  }
  await check("DEVELOPMENT: the request is answered, the responder is " +
              "asked, and the entity is registered", async function () {
    assert.ok(devAnswer.status === 303 || devAnswer.status === 302,
              "answered " + devAnswer.status + " " +
              devAnswer.text.slice(0, 200));
    assert.strictEqual(mdq.asked(devName), 1);
    assert.ok(registered, "no application after ten seconds");
  });

  const prodName = nameFor("prod-lookup");
  const prodAnswer = await anonymous("GET", authnRequestUrl(PROD, prodName));
  await sleep(1500);
  await check("PRODUCT, no trust anchor: the unsigned request is refused " +
              "and the responder is NEVER asked", async function () {
    assert.strictEqual(prodAnswer.status, 403,
                       prodAnswer.text.slice(0, 200));
    assert.strictEqual(mdq.asked(prodName), 0);
  });
  await check("PRODUCT: no application exists for it afterwards",
              async function () {
    assert.strictEqual(await isRegistered(PROD, prodName), false);
  });
  const view = await api(PROD, "GET", "/saml2");
  await check("PRODUCT: GET /admin-api/saml2 lists it in mdqRefused, with " +
              "its own pager", async function () {
    assert.ok(view.body && Array.isArray(view.body.mdqRefused),
              view.text.slice(0, 300));
    assert.ok(view.body.mdqRefusedPaging, "no mdqRefusedPaging");
    const row = view.body.mdqRefused.filter(function (one) {
      return one.entityId === prodName;
    })[0];
    assert.ok(row, JSON.stringify(view.body.mdqRefused).slice(0, 400));
    assert.strictEqual(row.errorCode, "STS-SAML-0080");
  });
  log.debug("Leaving requestStartedLookup().");
}

// ---------------------------------------------------------------------------
// 3. AN OPERATOR'S IMPORT.
// ---------------------------------------------------------------------------
async function operatorImport(mdq) {
  log.debug("Entering operatorImport().");
  log.info("=== 3. an operator's MDQ import with no trust anchor ===");
  const name = nameFor("operator");
  const r = await api(PROD, "POST", "/saml2/mdq-import", { sp: name });
  await sleep(500);
  await check("PRODUCT: POST /admin-api/saml2/mdq-import with no trust " +
              "anchor is refused, and nothing is fetched or created",
              async function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/trust anchor/.test(r.text), r.text.slice(0, 300));
    assert.ok(/mdqImportWithoutAnchors/.test(r.text), r.text.slice(0, 300));
    assert.strictEqual(mdq.asked(name), 0);
    assert.strictEqual(await isRegistered(PROD, name), false);
  });
  log.debug("Leaving operatorImport().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the unregistered-SAML-provider checks against " + base +
           "; this job's MDQ responder is on " + HOST);
  const mdq = await responder();
  try {
    await setUp(mdq);
    await perProviderPaths();
    await requestStartedLookup(mdq);
    await operatorImport(mdq);
  } finally {
    mdq.server.close();
  }
  log.info("The realms " + PROD + " and " + DEV + " are left standing " +
           "(tests/CLAUDE.md, *No job removes a realm*).");
  if (failures.length) {
    log.error(checks + " check(s) passed, " + failures.length + " FAILED:");
    failures.forEach(function (f) {
      log.error("  ✗ " + f);
    });
    log.debug("Leaving test(). Failed.");
    return 1;
  }
  // A FLOOR ON THE COUNT: a section that stops being called takes its
  // assertions with it and the run would still say "passed".
  assert.ok(checks >= 17, "only " + checks + " checks ran; a section " +
                          "stopped being called");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
  return 0;
}

const program = new Command();
program
  .name("sts_saml_unregistered")
  .description("What a SAML service provider nobody registered can cause " +
      "(#112), in a product realm and a development realm of one service: " +
      "the per-provider paths of both profiles, a Metadata Query lookup an " +
      "anonymous AuthnRequest starts against this job's own responder, and " +
      "an operator's import with no trust anchor.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().then(function (code) {
  process.exit(code);
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
