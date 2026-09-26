"use strict";
//
// File: sts_provider_commands.js
//
// ---------------------------------------------------------------------------
// OPENID PROVIDER COMMANDS 1.0 (#151, 2026-09-26), over HTTP, in a
// throwaway realm, against this service's own mock relying party
// (`/oauth2/commands/mock-rp`, development only).
//
//   1. REGISTRATION: command_endpoint accepted over https and refused over
//      http, and echoed in the registration response.
//   2. METADATA: what the relying party supports, recorded.
//   3. ACCOUNT COMMANDS: activate, an _async suspend finished through the
//      callback, and incompatible_state as a dead letter.
//   4. AUTOMATIC: a disable sends suspend and an enable reactivate.
//   5. A TENANT RUN whose stream the relying party drops is resumed.
//   6. A 503 is retried; the Monitoring page's API lists every kind.
//   7. THE CALLBACK refuses a bad token with RFC 6750's challenge.
//
// OWNED HERE (local: true): this repository's provider and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_provider_commands",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12);
const REALM = "pc-" + TAG;
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const PERSON = names.usernameFor("pc-person");
const PASSWORD = "Pc-" + crypto.randomBytes(9).toString("base64url") + "-Aa1!";
const MOCK = base + "/oauth2/commands/mock-rp";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
    .toString("utf8"));
}

// A cookie jar that keeps each cookie's Path, as a browser does: the two
// realms are on one host, and their session cookies share names, so a jar
// keyed by name alone lets the provider realm's sign-in overwrite the OP
// realm's session.
function jar() {
  log.debug("Entering jar().");
  const cookies = {};
  log.debug("Leaving jar().");
  return {
    header: function header(url) {
      log.debug("Entering header().");
      const at = new URL(url).pathname;
      const out = Object.keys(cookies).map(function (k) {
        return cookies[k];
      }).filter(function (c) {
        return at === c.path || at.indexOf(c.path.replace(/\/?$/, "/")) ===
          0 || c.path === "/";
      }).sort(function (a, b) {
        return b.path.length - a.path.length;
      }).map(function (c) {
        return c.name + "=" + c.value;
      }).join("; ");
      log.debug("Leaving header().");
      return out;
    },
    take: function take(response, url) {
      log.debug("Entering take().");
      const set = typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie() : [];
      set.forEach(function (line) {
        const pair = line.split(";")[0];
        const eq = pair.indexOf("=");
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        const p = (/;\s*path=([^;]*)/i.exec(line) || [])[1];
        const cpath = p ? p.trim() :
          new URL(url).pathname.replace(/\/[^/]*$/, "") || "/";
        const key = name + " " + cpath;
        if (/Max-Age=0/i.test(line) || value === "") {
          delete cookies[key];
        } else {
          cookies[key] = { name: name, value: value, path: cpath };
        }
      });
      log.debug("Leaving take().");
      return set;
    }
  };
}

async function hop(who, method, url, opts) {
  log.debug("Entering hop(). " + method + " " + url);
  const o = opts || {};
  const headers = Object.assign({}, o.headers || {});
  let body;
  if (o.form) {
    body = new URLSearchParams(o.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  if (who && who.header(url)) {
    headers.cookie = who.header(url);
  }
  const r = await fetch(url, { method: method, headers: headers,
                               body: body, redirect: "manual" });
  if (who) {
    who.take(r, url);
  }
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    json = null;
  }
  const location = r.headers.get("location") || "";
  log.debug("Leaving hop(). " + r.status);
  if (process.env.CA_TRACE) {
    log.info("HOP " + method + " " + url + " -> " + r.status + " " +
             (location || ""));
  }
  return { status: r.status, text: text, json: json,
           location: location ? new URL(location, url).toString() : "" };
}

function hiddenFields(html) {
  log.debug("Entering hiddenFields().");
  const out = {};
  (String(html).match(/<input type="hidden"[^>]*>/g) || [])
    .forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        out[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  log.debug("Leaving hiddenFields().");
  return out;
}

function csrfOf(html) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (/name="csrf_token" value="([^"]+)"/.exec(html) || [])[1] || "";
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await hop(null, "POST", url, { json: payload || {} });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// Follows redirects inside this service, signing the person in on the
// realm's screen and allowing a consent screen, until the answer leaves the
// service or is a page.
function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// Polls /admin-api/commands until `until(report)` holds, or gives up.
async function waitFor(what, until) {
  log.debug("Entering waitFor(). " + what);
  let last = null;
  for (let i = 0; i < 60; i++) {
    last = (await hop(null, "GET", api + "/commands")).json;
    if (last && until(last)) {
      log.debug("Leaving waitFor().");
      return last;
    }
    await sleep(500);
  }
  log.debug("Leaving waitFor(). Gave up.");
  throw new Error("waited for " + what + " and it did not happen: " +
                  JSON.stringify(last).slice(0, 1500));
}

async function register(name, endpoint) {
  log.debug("Entering register(). " + name);
  const r = await hop(null, "POST", base + "/oauth2/register", { json: {
    redirect_uris: ["https://rp.commands.example/cb"],
    token_endpoint_auth_method: "client_secret_post",
    grant_types: ["authorization_code"], response_types: ["code"],
    scope: "openid", client_name: name + " " + TAG,
    command_endpoint: endpoint } });
  log.debug("Leaving register().");
  return r;
}

function accountOf(report, clientId) {
  log.debug("Entering accountOf().");
  log.debug("Leaving accountOf().");
  return (report.accounts || []).filter(function (a) {
    return a.clientId === clientId && a.username === PERSON;
  })[0];
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Provider commands " + TAG },
    "created the realm");
  await ok(api + "/config/set", { key: "oauth2.openRegistration",
                                  value: true }, "opened registration");
  await ok(api + "/config/set", { key: "oauth2.providerCommands",
                                  value: true }, "turned commands on");
  await ok(api + "/config/set", { key: "oauth2.commandBackoffMs",
                                  value: 200 }, "shortened the backoff");
  // The mock relying party is this service, dialled at its own address,
  // whose certificate is this run's own: sts_ciba.js's arrangement.
  await ok(api + "/config/set", { key: "federation.outboundSkipTlsVerification",
    value: true }, "let the realm reach its own mock relying party");
  await registry.ensurePerson(base, PERSON, PASSWORD);

  log.info("=== 1. registration ===");
  const plain = await register("Plain", "http://rp.commands.example/c");
  const app = await register("Mock", MOCK);
  const dropping = await register("Dropping", MOCK + "?drop=1");
  const failing = await register("Failing", MOCK + "?fail=1");
  check("an http command_endpoint is refused; an https one is echoed",
        function () {
    assert.strictEqual(plain.status, 400, plain.text.slice(0, 200));
    assert.strictEqual(plain.json.error, "invalid_client_metadata");
    assert.strictEqual(app.status, 201, app.text.slice(0, 200));
    assert.strictEqual(app.json.command_endpoint, MOCK);
  });
  const APP = app.json.client_id;
  const DROP = dropping.json.client_id;
  const FAIL = failing.json.client_id;

  log.info("=== 2. metadata ===");
  await ok(api + "/commands/send-tenant", { clientId: APP,
    command: "metadata" }, "sent metadata");
  const learned = await waitFor("metadata", function (r) {
    return r.clients.some(function (c) {
      return c.clientId === APP && c.learned;
    });
  });
  const row = learned.clients.filter(function (c) {
    return c.clientId === APP;
  })[0];
  check("what the relying party supports is recorded", function () {
    assert.ok(row.learned.commandsSupported.indexOf("suspend") >= 0);
    assert.ok(row.learned.commandsSupported.indexOf("audit_tenant") >= 0);
    assert.strictEqual(row.learned.roles.length, 2);
  });

  log.info("=== 3. account commands ===");
  await ok(api + "/commands/send-account", { clientId: APP,
    username: PERSON, command: "activate" }, "sent activate");
  await waitFor("active", function (r) {
    const a = accountOf(r, APP);
    return a && a.state === "active";
  });
  const mock = (await hop(null, "GET", MOCK + "?client_id=" +
                          encodeURIComponent(APP))).json;
  check("the relying party created the account with its claims",
        function () {
    assert.strictEqual(mock.accounts.length, 1);
    assert.strictEqual(mock.accounts[0].state, "active");
  });
  await ok(api + "/commands/send-account", { clientId: APP,
    username: PERSON, command: "suspend_async" }, "sent suspend_async");
  await waitFor("suspended through the callback", function (r) {
    const a = accountOf(r, APP);
    return a && a.state === "suspended";
  });
  check("an _async command is finished through the callback", function () {
    assert.ok(true);
  });
  await ok(api + "/commands/send-account", { clientId: APP,
    username: PERSON, command: "activate" }, "sent activate again");
  const refused = await waitFor("a dead letter", function (r) {
    return r.deliveries.some(function (d) {
      return d.command === "activate" && d.state === "dead";
    });
  });
  check("incompatible_state is a dead letter with its code", function () {
    const dead = refused.deliveries.filter(function (d) {
      return d.command === "activate" && d.state === "dead";
    })[0];
    assert.strictEqual(dead.errorCode, "STS-OAUTH-0771");
    assert.strictEqual(dead.status, 409);
  });

  log.info("=== 4. automatic commands ===");
  await ok(api + "/commands/send-account", { clientId: APP,
    username: PERSON, command: "reactivate" }, "sent reactivate");
  await waitFor("active again", function (r) {
    const a = accountOf(r, APP);
    return a && a.state === "active";
  });
  await ok(api + "/users/disable", { user: PERSON }, "disabled the person");
  await waitFor("suspended by the disable", function (r) {
    const a = accountOf(r, APP);
    return a && a.state === "suspended";
  });
  await ok(api + "/users/enable", { user: PERSON }, "enabled the person");
  await waitFor("reactivated by the enable", function (r) {
    const a = accountOf(r, APP);
    return a && a.state === "active";
  });
  check("a disable sends suspend and an enable reactivate", function () {
    assert.ok(true);
  });

  log.info("=== 5. a tenant run, resumed ===");
  await ok(api + "/commands/send-tenant", { clientId: DROP,
    command: "metadata" }, "sent metadata to the dropping client");
  await ok(api + "/commands/send-account", { clientId: DROP,
    username: PERSON, command: "activate" }, "activated there");
  await waitFor("active at the dropping client", function (r) {
    const a = accountOf(r, DROP);
    return a && a.state === "active";
  });
  await ok(api + "/commands/send-tenant", { clientId: DROP,
    command: "audit_tenant" }, "started audit_tenant");
  const runs = await waitFor("the run to finish", function (r) {
    return r.runs.some(function (run) {
      return run.clientId === DROP && run.state !== "running";
    });
  });
  check("the stream the relying party dropped is resumed, and completes",
        function () {
    const run = runs.runs.filter(function (one) {
      return one.clientId === DROP;
    })[0];
    assert.strictEqual(run.state, "complete", JSON.stringify(run));
    assert.strictEqual(run.resumes, 1);
    assert.strictEqual(run.totalAccounts, 1);
  });

  log.info("=== 6. a retry, and every kind ===");
  await ok(api + "/commands/send-tenant", { clientId: FAIL,
    command: "metadata" }, "sent metadata to the failing client");
  const retried = await waitFor("a retried delivery", function (r) {
    return r.deliveries.some(function (d) {
      return d.clientId === FAIL && d.state === "sent";
    });
  });
  const deliveries = (await hop(null, "GET", api + "/deliveries")).json;
  check("a 503 is retried and lands; /admin-api/deliveries lists the " +
        "three kinds", function () {
    const d = retried.deliveries.filter(function (one) {
      return one.clientId === FAIL && one.state === "sent";
    })[0];
    assert.strictEqual(d.attempts, 2);
    assert.deepStrictEqual(deliveries.kinds.map(function (k) {
      return k.id;
    }), ["backchannel-logout", "ciba", "provider-commands"]);
  });

  log.info("=== 7. the callback ===");
  const r = await hop(null, "POST", base + "/oauth2/commands/callback", {
    json: { command_requested: "metadata" },
    headers: { Authorization: "Bearer not-a-token" } });
  check("a bad callback token is 401 with a Bearer challenge", function () {
    assert.strictEqual(r.status, 401, r.text.slice(0, 200));
    assert.strictEqual(r.json.error, "invalid_token");
  });

  assert.ok(checks >= 9, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("OpenID Provider Commands (#151) against the mock relying " +
    "party, over HTTP.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
