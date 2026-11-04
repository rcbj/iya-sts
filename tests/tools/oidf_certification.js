#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: oidf_certification.js
//
// ---------------------------------------------------------------------------
// THE OPENID FOUNDATION'S HOSTED SUITE, FOR CERTIFICATION (#1293). The test
// runs an OpenID Provider certification is submitted from have to be made
// on www.certification.openid.net against a deployment the suite can reach,
// and `sts_oidcc_conformance.js` runs the same plans only against a suite
// of our own. This drives the hosted one through its API, with the same
// helper (`tests/protocol/conformance_suite.js`) and the same person
// (`tests/protocol/conformance_browser.js`, headless Chrome on this machine).
//
//   1. ONE CERTIFICATION REALM on the target, made once and kept (a
//      certification is of a deployment, and the plans are re-run against
//      the same issuer until each is clean): open registration, post-quantum
//      signing OFF (the suite cannot parse kty AKP, and a package full of
//      warnings for it is a worse submission than a classical one), product
//      mode unless --development, and the two settings the local job turns
//      off for the suite's own reasons (`oauth2.codeReplayIdempotent`,
//      `oauth2.requestUriFragmentCheck`; the job's header says why).
//   2. A FRESH PERSON per run, with a password made here.
//   3. Each selected certification plan, ONE AT A TIME and under ONE alias:
//      the suite's redirect URI is built on the alias, and two plans running
//      under the same alias at once interfere with each other.
//   4. A REPORT, NOT A VERDICT. The local job judges against our ledger;
//      certification judges the module result, and any FAILED or
//      INTERRUPTED module rules a profile out. So every module that did not
//      PASS is listed with its first message, and the plan's URL is printed
//      to read it in the suite.
//   5. NOTHING IS PUBLISHED. Publishing a plan and building its certification
//      package carry the signed Certification of Conformance and are done by
//      a person in the suite's UI.
//
// THE TOKENS ARE PASSED IN, NEVER WRITTEN DOWN. The suite's API token is
// --token-file or CONFORMANCE_SUITE_TOKEN; the target's management API secret
// is --admin-secret-file or STS_ADMIN_API_CLIENT_SECRET.
//
// Run it from the repository root, with the tests' dependencies:
//
//   node tests/tools/oidf_certification.js \
//     --token-file ~/oidf-token --admin-secret-file ~/testidp-admin-secret
//
// --list shows the plans; --plans narrows them (a trailing `*` is a prefix);
// --create-only creates the plans in the suite and runs nothing, so they can
// be run by hand there.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const nodeCrypto = require("crypto");
const path = require("path");
const { Command, Option } = require("commander");

const program = new Command()
  .description("Run the OpenID Provider certification plans on the " +
               "OpenID Foundation's hosted conformance suite (#1293).")
  .addOption(new Option("--target <url>", "the deployment under test")
    .default("https://test-idp.iyasec.io"))
  .addOption(new Option("--suite <url>", "the hosted suite")
    .default("https://www.certification.openid.net/"))
  .addOption(new Option("--token-file <file>", "a file holding the " +
    "suite's API token (or CONFORMANCE_SUITE_TOKEN)"))
  .addOption(new Option("--admin-secret-file <file>", "a file holding the " +
    "target's sts-api-client secret (or STS_ADMIN_API_CLIENT_SECRET)"))
  .addOption(new Option("--realm <id>", "the certification realm")
    .default("oidf-cert"))
  .addOption(new Option("--domain <domain>", "the realm's DNS domain, " +
    "when it is created").default("oidf-cert.iyasec.io"))
  .addOption(new Option("--alias <alias>", "the suite alias; part of " +
    "every redirect URI").default("iya-sts"))
  .addOption(new Option("--plans <keys>", "comma list of plan keys " +
    "(a trailing * is a prefix); default every plan --list marks default"))
  .addOption(new Option("--logout-response-types <types>", "comma list; " +
    "a logout profile is submitted once per response type the OP supports")
    .default("code,id_token,id_token token,code id_token,code token," +
             "code id_token token"))
  .addOption(new Option("--development", "leave the realm in the " +
    "deployment's mode instead of product"))
  .addOption(new Option("--create-only", "create the plans, run nothing"))
  .addOption(new Option("--out <file>", "where the JSON report goes")
    .default("oidf-certification-" +
             new Date().toISOString().replace(/[:.]/g, "-") + ".json"))
  .addOption(new Option("--list", "list the plans and stop"))
  .parse(process.argv);
const opts = program.opts();

// What the helpers read at require time, set before they are required.
// No Entering/Leaving pair: it runs before the logger exists, which is made
// after these values are in the environment (`common/config_file.js`'s
// reason).
function readSecret(file, variable) {
  if (file) {
    return fs.readFileSync(file, "utf8").trim();
  }
  return String(process.env[variable] || "").trim();
}

const target = String(opts.target).replace(/\/+$/, "");
const suiteToken = readSecret(opts.tokenFile, "CONFORMANCE_SUITE_TOKEN");
const adminSecret = readSecret(opts.adminSecretFile,
                               "STS_ADMIN_API_CLIENT_SECRET");
process.env.CONFORMANCE_SUITE_URL = String(opts.suite).replace(/\/?$/, "/");
process.env.CONFORMANCE_SUITE_TOKEN = suiteToken;
process.env.STS_ADMIN_API_CLIENT_SECRET = adminSecret;
process.env.WSTRUST_STS_URL = target;
process.env.STS_TEST_SERVICE_URL = target;
// One hosted module can wait on a person for a while; the suite's own
// timeout is longer than the local job's five minutes.
process.env.CONFORMANCE_MODULE_SECONDS =
  process.env.CONFORMANCE_MODULE_SECONDS || "600";

const bunyan = require("bunyan");
const log = bunyan.createLogger({ name: "oidf_certification",
                                  level: process.env.LOG_LEVEL || "info" });

// A browser user agent the risk policy does not refuse in product mode — one
// of the two preloads the runner gives every job. The other,
// attach-admin-token.js, is required in main() AFTER the token is minted: it
// installs its hooks only when STS_ADMIN_API_TOKEN is set as it loads (the
// runner mints before it starts a job), so required here it attached
// nothing and every /admin-api call answered 401 (2026-11-03).
require("./browser-user-agent.js");
const PROTOCOL = path.join(__dirname, "..", "protocol");
const oidf = require(path.join(PROTOCOL, "conformance_suite.js"));
const conformanceBrowser = require(path.join(PROTOCOL,
                                             "conformance_browser.js"));
const minter = require("./admin-api-token.js");

const DYNAMIC = { server_metadata: "discovery",
                  client_registration: "dynamic_client" };
const STATIC = { server_metadata: "discovery",
                 client_registration: "static_client" };

// ---------------------------------------------------------------------------
// THE CERTIFICATION PLANS, and the profile each is submitted as (the column
// label of the certification table, which the Certification of Conformance
// names). `byResponseType` plans are made once per --logout-response-types.
// `default: false` plans run only when named: Session Management, because
// the suite's HtmlUnit browser cannot load the OP iframe (the local job's
// EXPECTED entry, `oauth-oidc/CLAUDE.md` 3bp), so it cannot pass there.
// ---------------------------------------------------------------------------
const PLANS = [
  { key: "basic", profile: "Basic OP",
    name: "oidcc-basic-certification-test-plan", variant: DYNAMIC },
  { key: "basic-static", profile: "Basic OP (static client)",
    name: "oidcc-basic-certification-test-plan", variant: STATIC,
    static: "client_secret_basic", responseTypes: ["code"] },
  { key: "implicit", profile: "Implicit OP",
    name: "oidcc-implicit-certification-test-plan", variant: DYNAMIC },
  { key: "hybrid", profile: "Hybrid OP",
    name: "oidcc-hybrid-certification-test-plan", variant: DYNAMIC },
  { key: "config", profile: "Config OP",
    name: "oidcc-config-certification-test-plan", variant: null },
  { key: "dynamic", profile: "Dynamic OP",
    name: "oidcc-dynamic-certification-test-plan",
    variant: { response_type: "code" } },
  { key: "formpost-basic", profile: "Form Post OP (Basic)",
    name: "oidcc-formpost-basic-certification-test-plan", variant: DYNAMIC },
  { key: "formpost-implicit", profile: "Form Post OP (Implicit)",
    name: "oidcc-formpost-implicit-certification-test-plan",
    variant: DYNAMIC },
  { key: "formpost-hybrid", profile: "Form Post OP (Hybrid)",
    name: "oidcc-formpost-hybrid-certification-test-plan",
    variant: DYNAMIC },
  { key: "3rdparty", profile: "3rd Party-Init OP",
    name: "oidcc-3rdparty-init-login-certification-test-plan",
    variant: { response_type: "code" } },
  { key: "logout-rp", profile: "RP-Initiated OP",
    name: "oidcc-rp-initiated-logout-certification-test-plan",
    byResponseType: true },
  { key: "logout-front", profile: "Front-Channel OP",
    name: "oidcc-frontchannel-rp-initiated-logout-certification-test-plan",
    byResponseType: true },
  { key: "logout-back", profile: "Back-Channel OP",
    name: "oidcc-backchannel-rp-initiated-logout-certification-test-plan",
    byResponseType: true },
  { key: "session", profile: "Session OP", default: false,
    name: "oidcc-session-management-certification-test-plan",
    byResponseType: true }
];

// The plans with the logout ones made once per response type, each keyed
// `<key>:<response type>` (spaces as `+`).
function expanded() {
  log.debug("Entering expanded().");
  const types = String(opts.logoutResponseTypes).split(",")
    .map(function (t) {
      return t.trim();
    }).filter(Boolean);
  const out = [];
  PLANS.forEach(function (plan) {
    if (!plan.byResponseType) {
      out.push(plan);
      return;
    }
    types.forEach(function (type) {
      out.push(Object.assign({}, plan, {
        key: plan.key + ":" + type.replace(/ /g, "+"),
        group: plan.key,
        variant: { response_type: type,
                   client_registration: "dynamic_client" } }));
    });
  });
  log.debug("Leaving expanded(). " + out.length);
  return out;
}

function wanted(plan) {
  log.debug("Entering wanted(). " + plan.key);
  if (!opts.plans) {
    log.debug("Leaving wanted(). Default.");
    return plan.default !== false;
  }
  const keys = String(opts.plans).split(",").map(function (s) {
    return s.trim();
  }).filter(Boolean);
  const hit = keys.some(function (k) {
    return k === plan.key || k === plan.group ||
           (k.slice(-1) === "*" && plan.key.indexOf(k.slice(0, -1)) === 0);
  });
  log.debug("Leaving wanted(). " + hit);
  return hit;
}

// ---------------------------------------------------------------------------
// THE REALM, kept across runs: created when it is not there, its settings
// put again every run (each is idempotent).
// ---------------------------------------------------------------------------
async function ensureRealm() {
  log.debug("Entering ensureRealm().");
  const base = target + "/realm/" + opts.realm;
  const api = base + "/admin-api";
  const there = await oidf.send(base + "/.well-known/openid-configuration");
  if (there.status !== 200) {
    await oidf.ok(target + "/admin-api/realms/create", { id: opts.realm,
      domain: opts.domain, name: "OpenID certification" },
      "created the realm " + opts.realm);
    log.info("Created the realm " + opts.realm + ".");
  } else {
    log.info("The realm " + opts.realm + " is there; using it.");
  }
  const settings = [["oauth2.openRegistration", true],
                    ["oauth2.codeReplayIdempotent", false],
                    ["oauth2.requestUriFragmentCheck", false],
                    oidf.CLASSICAL_SETTING,
                    // A RUN IS HUNDREDS OF SIGN-INS BY ONE NEW PERSON FROM ONE
                    // ADDRESS, which the risk model rightly finds unusual: its
                    // user term put them at 3.0-3.6 against MEDIUM's default
                    // 3.00 (risk.mediumScorePercent), and a MEDIUM sign-in in
                    // product is asked for a second factor this person does
                    // not have (STS-RISK-0017/0018), so oidcc-scope-profile
                    // hung on 2026-11-03. Raised for THIS realm only, below
                    // HIGH (1000), so risk is still scored and enforced; the
                    // setting's own description says to tune it per realm.
                    ["risk.mediumScorePercent", 800],
                    // THE TOKEN RESPONSE TYPES (#1295, #1296). Product mode
                    // refuses them (RFC 9700 section 2.1.2); the Implicit,
                    // Hybrid and Dynamic OP profiles need them. The realm
                    // waives the section, and lets a client registering
                    // itself enable all four for itself, which is how the
                    // suite's clients arrive. A production realm leaves
                    // both off; each application then needs an
                    // administrator or its owner to enable a type.
                    ["oauth2.allowImplicitTokenResponses", true],
                    ["oauth2.dynamicRegistrationTokenResponseTypes",
                     "token,id_token token,code token,code id_token token"]];
  if (!opts.development) {
    settings.push(["global.mode", "product"]);
  }
  if (expanded().some(function (plan) {
    return plan.group === "session" && wanted(plan);
  })) {
    settings.push(["oauth2.sessionManagement", true]);
  }
  for (let i = 0; i < settings.length; i++) {
    await oidf.ok(api + "/config/set", { key: settings[i][0],
                                         value: settings[i][1] },
                  "set " + settings[i][0]);
  }
  log.debug("Leaving ensureRealm().");
  return { base: base, api: api };
}

// The three clients a static plan names, registered here with the suite's
// redirect URI for the alias: two client_secret_basic, one
// client_secret_post (the certification instructions' three).
async function staticClients(plan, base) {
  log.debug("Entering staticClients(). " + plan.key);
  const redirect = oidf.SUITE + "test/a/" + opts.alias + "/callback";
  const methods = [plan.static, plan.static, "client_secret_post"];
  const clients = [];
  for (let n = 1; n <= methods.length; n++) {
    const registered = await oidf.send(base + "/oauth2/register", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: [redirect],
        token_endpoint_auth_method: methods[n - 1],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: plan.responseTypes,
        scope: "openid profile email address phone offline_access",
        client_name: "OpenID certification " + plan.key + " " + n }) });
    assert.strictEqual(registered.status, 201, plan.key + " client " + n +
                       ": " + registered.raw.slice(0, 400));
    clients.push({ client_id: registered.body.client_id,
                   client_secret: registered.body.client_secret,
                   scope: "openid profile email" });
  }
  log.debug("Leaving staticClients().");
  return clients;
}

async function configurationFor(plan, realm) {
  log.debug("Entering configurationFor(). " + plan.key);
  const configuration = {
    alias: opts.alias,
    description: "iya-sts " + plan.profile + " (" + plan.key + ")",
    server: { discoveryUrl: realm.base + "/.well-known/openid-configuration",
              allow_unexpected_metadata_fields: oidf.EXTENSION_METADATA }
  };
  if (plan.static) {
    const clients = await staticClients(plan, realm.base);
    configuration.client = clients[0];
    configuration.client2 = clients[1];
    configuration.client_secret_post = clients[2];
  } else {
    const tag = plan.key.replace(/[^A-Za-z0-9]/g, "-");
    configuration.client = { client_name: "OpenID certification " +
      plan.key + " 1", jwks: oidf.keyPair("cert-" + tag + "-1").privateJwks };
    configuration.client2 = { client_name: "OpenID certification " +
      plan.key + " 2", jwks: oidf.keyPair("cert-" + tag + "-2").privateJwks };
  }
  log.debug("Leaving configurationFor().");
  return configuration;
}

// Every module that did not PASS, with its first failure or warning — what
// the certification rule reads.
function summarise(plan, ran) {
  log.debug("Entering summarise(). " + plan.key);
  const counts = {};
  const notPassed = [];
  ran.results.forEach(function (r) {
    const result = r.result || r.status;
    counts[result] = (counts[result] || 0) + 1;
    if (result !== "PASSED") {
      const first = r.failures[0] || r.warnings[0] || null;
      notPassed.push({ module: r.module, result: result,
                       status: r.status, id: r.id,
                       first: first ? first.src + ": " + first.msg : "" });
    }
  });
  const blocked = notPassed.some(function (m) {
    return m.result === "FAILED" || m.status === "INTERRUPTED" ||
           m.status === "TIMED OUT";
  });
  log.debug("Leaving summarise().");
  return { key: plan.key, profile: plan.profile, plan: plan.name,
           variant: plan.variant, planId: ran.planId,
           url: oidf.SUITE + "plan-detail.html?plan=" + ran.planId,
           counts: counts, certifiable: !blocked, notPassed: notPassed };
}

async function runOne(plan, realm, someone) {
  log.debug("Entering runOne(). " + plan.key);
  const configuration = await configurationFor(plan, realm);
  log.info("=== " + plan.profile + ": " + plan.name + " " +
           JSON.stringify(plan.variant) + " ===");
  if (opts.createOnly) {
    const created = await oidf.suite("POST", "api/plan?planName=" +
      encodeURIComponent(plan.name) + (plan.variant
        ? "&variant=" + encodeURIComponent(JSON.stringify(plan.variant))
        : ""), configuration);
    assert.ok(created.status === 201 || created.status === 200,
              "creating " + plan.name + ": " + created.raw.slice(0, 400));
    log.debug("Leaving runOne(). Created.");
    return { key: plan.key, profile: plan.profile, plan: plan.name,
             variant: plan.variant, planId: created.body.id,
             url: oidf.SUITE + "plan-detail.html?plan=" + created.body.id,
             created: true };
  }
  const operator = oidf.keyRotationOperator(realm.api);
  const ran = await oidf.runPlan(plan.name, plan.variant, configuration,
                                 plan.key, async function (id, info) {
                                   log.debug("Entering the plan's people.");
                                   await operator(id, info);
                                   await someone.visit(id, info);
                                   log.debug("Leaving the plan's people.");
                                 });
  const summary = summarise(plan, ran);
  log.info("  " + plan.key + ": " + JSON.stringify(summary.counts) +
           (summary.certifiable ? "" : "  NOT CERTIFIABLE") +
           "\n  " + summary.url);
  log.debug("Leaving runOne().");
  return summary;
}

// THE PERSON'S AUTHENTICATOR APP (#1293, rcbj's choice over switching risk
// off): enrolled the way the person would enrol it, through the portal's
// account API (`/portal/mfa` start, then confirm with a code), so a sign-in
// the risk model sends to a step-up is answered by conformance_browser.js
// at /authn/totp. Risk stays scored and enforced in the realm.
async function enrolTotp(base, username, password) {
  log.debug("Entering enrolTotp().");
  const portal = require(path.join(PROTOCOL, "portal_signin.js"));
  const c = await portal.signInToThePortal(base, username, null,
                                           { password: password });
  assert.ok(c && c.token, "the test person could not sign in to the " +
            "portal to enrol an authenticator");
  await c.act("/portal/mfa", { action: "start" });
  const page = await c.page("/portal/mfa");
  const secret = String((page.json && page.json.setup &&
                         page.json.setup.grouped) || "").replace(/\s+/g, "");
  assert.ok(secret, "no shared secret on /portal/mfa: " +
            String(page.text).slice(0, 300));
  const step = Math.floor(Date.now() / 30000);
  const done = await c.act("/portal/mfa", { action: "confirm",
    code: conformanceBrowser.totpAt(secret, step) });
  assert.ok(done && done.status === 200, "confirming the authenticator " +
            "answered " + (done && done.status));
  conformanceBrowser.usedTotpStep(step);
  log.info("Enrolled an authenticator app for " + username + ".");
  log.debug("Leaving enrolTotp().");
  return secret;
}

async function main() {
  log.debug("Entering main().");
  const plans = expanded().filter(wanted);
  if (opts.list) {
    expanded().forEach(function (plan) {
      process.stdout.write((wanted(plan) ? "* " : "  ") + plan.key +
                           "  " + plan.profile + "  " + plan.name + "\n");
    });
    log.debug("Leaving main(). Listed.");
    return 0;
  }
  assert.ok(suiteToken, "no suite API token: --token-file or " +
            "CONFORMANCE_SUITE_TOKEN");
  assert.ok(adminSecret, "no management API secret for " + target +
            ": --admin-secret-file or STS_ADMIN_API_CLIENT_SECRET");
  assert.ok(plans.length, "no plan matches --plans " + opts.plans);
  process.env.STS_ADMIN_API_TOKEN = await minter.tokenFor(target);
  require("./attach-admin-token.js");
  await oidf.waitForSuite();
  const realm = await ensureRealm();
  const username = "oidf-cert-" +
    nodeCrypto.randomBytes(3).toString("hex");
  const password = "Cert-" + nodeCrypto.randomBytes(12).toString("base64url");
  // EVERY CLAIM OF THE `profile`, `phone` AND `address` SCOPES (OIDC Core
  // 5.4), so each has a value in the entry: the suite's
  // VerifyScopesReturnedInUserInfoClaims and ...InAuthorizationEndpoint-
  // IdToken want all of them whatever claims_supported says, and product mode
  // invents nothing. The profile attributes are sts_oidcc_conformance.js's
  // (#1292, which mapped the last five); the phone and address ones are
  // this tool's. INVENTED values: 555-01xx is reserved for fiction, the
  // street does not exist, and conformance.example is a reserved name.
  const site = "https://conformance.example/~" + username;
  await oidf.makePerson(realm.api, username, password, {
    middleName: "Middle", displayName: "Conf",
    labeledURI: site,
    profileUrl: site + "/profile",
    pictureUrl: site + "/photo.jpg",
    schacGender: "9", schacDateOfBirth: "19800131",
    timeZone: "Europe/Stockholm", preferredLanguage: "en-GB",
    telephoneNumber: "+1 512 555 0142",
    street: "1 Conformance Way",
    l: "Austin",
    st: "TX",
    postalCode: "78701"
  });
  const totpSecret = await enrolTotp(realm.base, username, password);
  const someone = conformanceBrowser.person({
    suite: oidf.suite, suiteBase: oidf.SUITE, serviceBase: realm.base,
    username: username, password: password, totpSecret: totpSecret,
    actions: {
      "oidcc-prompt-login": "photograph",
      "oidcc-max-age-1": "photograph",
      "oidcc-registration-logo-uri": "photograph-only",
      "oidcc-registration-policy-uri": "photograph-only",
      "oidcc-registration-tos-uri": "photograph-only"
    }
  });
  log.info(plans.length + " plan(s) against " + realm.base + " as " +
           username + ", alias " + opts.alias + ".");
  const report = { target: realm.base, suite: oidf.SUITE,
                   alias: opts.alias, started: new Date().toISOString(),
                   plans: [] };
  for (let i = 0; i < plans.length; i++) {
    try {
      report.plans.push(await runOne(plans[i], realm, someone));
    } catch (e) {
      // One plan that cannot be made is reported with the rest.
      log.error("Caught in main(): " + plans[i].key + ": " +
                ((e && e.message) || e));
      report.plans.push({ key: plans[i].key, profile: plans[i].profile,
                          error: String((e && e.message) || e) });
    }
    fs.writeFileSync(opts.out, JSON.stringify(report, null, 2) + "\n");
  }
  await conformanceBrowser.quit();
  report.finished = new Date().toISOString();
  fs.writeFileSync(opts.out, JSON.stringify(report, null, 2) + "\n");
  process.stdout.write("\n");
  report.plans.forEach(function (p) {
    const verdict = p.error ? "ERROR " + p.error
      : p.created ? "created"
      : p.certifiable ? "certifiable" : "NOT certifiable";
    process.stdout.write(p.key + "  " + verdict + "  " + (p.url || "") +
                         "\n");
    (p.notPassed || []).forEach(function (m) {
      process.stdout.write("    " + m.result + "  " + m.module +
                           (m.first ? "  " + m.first : "") + "\n");
    });
  });
  process.stdout.write("\nReport: " + path.resolve(opts.out) + "\n");
  const bad = report.plans.some(function (p) {
    return p.error || p.certifiable === false;
  });
  log.debug("Leaving main(). " + (bad ? 1 : 0));
  return bad ? 1 : 0;
}

main().then(function (code) {
  process.exit(code);
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(2);
});
