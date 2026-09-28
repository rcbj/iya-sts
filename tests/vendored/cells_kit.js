// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: cells_kit.js
//
// ===========================================================================
// WHAT THE `sts_cells_*.js` JOBS SHARE (#98, 2026-09-28). Not a job.
//
// The `cells` mode (tests/tools/modes.sh, tests/docker-compose-run-tests-
// cells.yml) runs two cells of one service, and hands the runner each cell by
// name — STS_TEST_CELL_A_URL and STS_TEST_CELL_B_URL — which is a TEST-ONLY
// resolver override (#98 section 9): nothing outside a test ever addresses a
// cell. Every other mode sets neither, and each job declines to run there
// (expectation.js's declineToRun), naming the variable.
//
// What is here:
//
//   * THE MANAGEMENT API AT EITHER CELL, each with a token minted AT THAT
//     CELL for the service's one `/admin-api` audience — the public name,
//     which is cell A's URL here, because both cells issue under it
//     (STS-CELL-0005). The Authorization header is set explicitly, so the
//     runner's preload (tools/attach-admin-token.js), which attaches cell A's
//     token only where a request carries none, never decides which token a
//     cell is shown.
//   * A BROWSER: a cookie jar and a fetch that never follows a redirect, so
//     each hop of a flow — and each cookie it sets, the `sts_cell` pin
//     included — is the job's to read and assert.
//   * A JWT CHECKED AGAINST A JWKS with node's own crypto, so "the tokens
//     verify against cell A's key set" is a verification here rather than
//     the service agreeing with itself.
//   * Waiting for the global tier: a realm or a setting written at one cell
//     reaches the other through the global change log, after its pull. A
//     read that must see it polls within a bound, and the bound is the
//     assertion.
//
// Node built-ins, bunyan, and tests/tools/admin-api-token.js for the mint.
// Nothing from the service.
// ===========================================================================
"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const path = require("path");
const log = require("bunyan").createLogger({ name: "cells_kit",
  level: process.env.LOG_LEVEL || "info" });

// The service's one public name: where every token is audienced, and the
// cell the runner drives as `sts` in every mode.
const PUBLIC_ENV = "STS_TEST_CELL_A_URL";

/**
 * The two cells this stack runs, from the environment the `cells` mode's
 * layer gives the runner.
 *
 * @returns `{ a, b, ids: { a, b }, jurisdictions: { a, b } }`, or null when
 *   this is not the `cells` mode
 */
function cellsFromEnv() {
  log.debug("Entering cellsFromEnv().");
  const a = String(process.env.STS_TEST_CELL_A_URL || "").replace(/\/+$/, "");
  const b = String(process.env.STS_TEST_CELL_B_URL || "").replace(/\/+$/, "");
  if (!a || !b) {
    log.debug("Leaving cellsFromEnv(). Not the cells mode.");
    return null;
  }
  // `cella:us,cellb:ca`, cell A first.
  const listed = String(process.env.STS_TEST_CELLS || "cella:us,cellb:ca")
    .split(",").map(function (one) {
      const parts = one.trim().split(":");
      return { id: parts[0] || "", jurisdiction: parts[1] || "" };
    });
  assert.strictEqual(listed.length, 2,
    "STS_TEST_CELLS names " + listed.length + " cell(s); this suite drives " +
    "two: " + process.env.STS_TEST_CELLS);
  log.debug("Leaving cellsFromEnv().");
  return {
    a: a, b: b,
    ids: { a: listed[0].id, b: listed[1].id },
    jurisdictions: { a: listed[0].jurisdiction, b: listed[1].jurisdiction }
  };
}

// The minted token per cell URL, for this process.
const tokens = {};

/**
 * An `/admin-api` access token minted AT one cell, audienced to the
 * service's one management API.
 *
 * @param cellUrl - the cell's URL
 * @returns a promise of the access token
 */
async function tokenAt(cellUrl) {
  log.debug("Entering tokenAt(). " + cellUrl);
  if (tokens[cellUrl]) {
    log.debug("Leaving tokenAt(). Cached.");
    return tokens[cellUrl];
  }
  const minter = require(path.join(__dirname, "..", "tools",
                                   "admin-api-token.js"));
  const secret = process.env.ADMIN_API_CLIENT_SECRET ||
                 process.env.STS_ADMIN_API_CLIENT_SECRET || "";
  assert.ok(secret, "ADMIN_API_CLIENT_SECRET is not in this job's " +
    "environment, so no /admin-api token can be minted at " + cellUrl +
    ". The launcher pins it for the run (run-tests.sh).");
  const audience = String(process.env[PUBLIC_ENV] || cellUrl)
    .replace(/\/+$/, "") + "/admin-api";
  tokens[cellUrl] = await minter.mint(cellUrl, secret,
                                      { audience: audience });
  log.debug("Leaving tokenAt().");
  return tokens[cellUrl];
}

/**
 * One management API call at one cell, with that cell's own token.
 *
 * @param cellUrl - the cell's URL (a realm prefix may follow it)
 * @param method - GET or POST
 * @param apiPath - the path under `/admin-api`, query included
 * @param body - the JSON body of a POST
 * @param opts - `{ tokenFrom }`: the cell whose token to present (default
 *   the cell called), for a request that crosses to another cell
 * @returns a promise of `{ status, body, raw }`
 */
async function api(cellUrl, method, apiPath, body, opts) {
  log.debug("Entering api(). " + method + " " + apiPath);
  const origin = new URL(cellUrl).origin;
  const token = await tokenAt((opts && opts.tokenFrom) || origin);
  const headers = { Accept: "application/json",
                    Authorization: "Bearer " + token };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const r = await fetch(String(cellUrl).replace(/\/+$/, "") + "/admin-api" +
                        apiPath, {
    method: method, headers: headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const raw = await r.text();
  let parsed = null;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    // Not JSON: a text refusal from the edge, or an HTML page. The caller
    // asserts on the status and reads `raw`.
    log.debug("Caught in api(): " + ((e && e.message) || e));
    parsed = null;
  }
  log.debug("Leaving api(). " + r.status);
  return { status: r.status, body: parsed, raw: raw };
}

/**
 * Polls until `probe()` answers something truthy, or the bound passes.
 *
 * @param what - what is waited for, for the failure
 * @param boundMs - the bound
 * @param probe - an async function; truthy ends the wait
 * @returns a promise of the probe's last answer
 */
async function until(what, boundMs, probe) {
  log.debug("Entering until(). " + what);
  const began = Date.now();
  let last = null;
  let lastError = null;
  while (Date.now() - began < boundMs) {
    try {
      last = await probe();
      lastError = null;
    } catch (e) {
      // A probe may throw while the other cell has not caught up (a realm it
      // does not know yet answers 404); the bound decides, and the last
      // error is in the failure.
      log.debug("Caught in until(): " + ((e && e.message) || e));
      lastError = e;
      last = null;
    }
    if (last) {
      log.info("  (" + what + " after " + (Date.now() - began) + " ms)");
      log.debug("Leaving until().");
      return last;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
  }
  log.debug("Leaving until(). Timed out.");
  throw new Error("not within " + boundMs + " ms: " + what +
                  (lastError ? " (last error: " + lastError.message + ")"
                             : ""));
}

// ---------------------------------------------------------------------------
// A BROWSER: cookies by name, every redirect the job's.
// ---------------------------------------------------------------------------
/**
 * A cookie jar for one origin's worth of cookies — every cell answers on the
 * service's one name, so one jar is the browser's.
 */
class Jar {
  /**
   * An empty jar.
   */
  constructor() {
    log.debug("Entering Jar.constructor().");
    this.cookies = {};
    log.debug("Leaving Jar.constructor().");
  }

  /**
   * Takes every Set-Cookie of a response.
   *
   * @param response - a fetch Response
   * @returns the names set (a deleted cookie included)
   */
  take(response) {
    log.debug("Entering Jar.take().");
    const self = this;
    const lines = typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [String(response.headers.get("set-cookie") || "")].filter(Boolean);
    const names = [];
    lines.forEach(function (line) {
      const first = String(line).split(";")[0];
      const at = first.indexOf("=");
      if (at <= 0) {
        return;
      }
      const name = first.slice(0, at).trim();
      const value = first.slice(at + 1).trim();
      names.push(name);
      if (!value || /;\s*max-age=0(\s*;|\s*$)/i.test(line)) {
        delete self.cookies[name];
      } else {
        self.cookies[name] = value;
      }
    });
    log.debug("Leaving Jar.take(). " + names.join(","));
    return names;
  }

  /**
   * One cookie's value.
   *
   * @param name - its name
   * @returns the value, or ''
   */
  get(name) {
    log.debug("Entering Jar.get(). " + name);
    log.debug("Leaving Jar.get().");
    return this.cookies[name] || "";
  }

  /**
   * A copy of the jar without one cookie, for asking what a request is
   * answered with when it does not carry it.
   *
   * @param name - the cookie left out
   * @returns a new jar
   */
  without(name) {
    log.debug("Entering Jar.without(). " + name);
    const out = new Jar();
    Object.assign(out.cookies, this.cookies);
    delete out.cookies[name];
    log.debug("Leaving Jar.without().");
    return out;
  }

  /**
   * The Cookie header.
   *
   * @returns every cookie, as a browser sends them
   */
  header() {
    log.debug("Entering Jar.header().");
    const self = this;
    log.debug("Leaving Jar.header().");
    return Object.keys(this.cookies).map(function (name) {
      return name + "=" + self.cookies[name];
    }).join("; ");
  }
}

/**
 * One request the way a browser makes it, redirects NOT followed.
 *
 * @param jar - the browser's cookies, updated from the answer
 * @param url - the URL
 * @param opts - `{ method, form }`: a POST of an urlencoded form
 * @returns a promise of `{ status, location, text, set }`, where `set` is
 *   the cookie names the answer set
 */
async function browse(jar, url, opts) {
  log.debug("Entering browse(). " + url);
  const options = opts || {};
  const headers = { Accept: "text/html,application/json" };
  const cookie = jar.header();
  if (cookie) {
    headers.Cookie = cookie;
  }
  let body;
  if (options.form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(options.form).toString();
  }
  const r = await fetch(url, { method: options.method ||
                                       (options.form ? "POST" : "GET"),
                               headers: headers, body: body,
                               redirect: "manual" });
  const set = jar.take(r);
  const text = await r.text();
  const location = r.headers.get("location") || "";
  log.debug("Leaving browse(). " + r.status);
  return { status: r.status,
           location: location ? new URL(location, url).toString() : "",
           text: text, set: set };
}

/**
 * The hidden sign-in fields of a sign-in screen.
 *
 * @param page - the screen's HTML
 * @returns `{ authnId, csrf }`
 */
function signInFields(page) {
  log.debug("Entering signInFields().");
  const authnId = (String(page).match(/name="authn_id" value="([^"]+)"/) ||
                   [])[1] || "";
  const csrf = (String(page).match(/name="csrf_token" value="([^"]+)"/) ||
                [])[1] || "";
  log.debug("Leaving signInFields().");
  return { authnId: authnId, csrf: csrf };
}

/**
 * Follows a browser flow on the service's origin — every redirect, and a
 * consent screen answered Allow — until it leaves for the client's redirect
 * URI or stops on a page.
 *
 * @param jar - the browser's cookies
 * @param url - where the flow is now
 * @param clientRedirect - the client's redirect URI
 * @returns a promise of `{ code, state, hops, stopped }`: the code and state
 *   the client was sent, every hop (`{ url, status, location, set }`), and
 *   the last answer when the flow stopped anywhere else
 */
async function drive(jar, url, clientRedirect) {
  log.debug("Entering drive().");
  const hops = [];
  let at = url;
  for (let i = 0; i < 12; i++) {
    const r = await browse(jar, at);
    hops.push({ url: at, status: r.status, location: r.location,
                set: r.set });
    if (r.status >= 300 && r.status < 400 && r.location) {
      if (r.location.indexOf(clientRedirect) === 0) {
        const back = new URL(r.location);
        log.debug("Leaving drive(). Sent to the client.");
        return { code: back.searchParams.get("code") || "",
                 state: back.searchParams.get("state") || "",
                 error: back.searchParams.get("error") || "",
                 hops: hops, stopped: null };
      }
      at = r.location;
      continue;
    }
    const consentId = (String(r.text).match(
      /name="consent_id" value="([^"]+)"/) || [])[1];
    if (r.status === 200 && consentId) {
      const shown = new URL(at);
      const answered = await browse(jar, shown.origin + shown.pathname,
        { form: { consent_id: consentId, action: "allow" } });
      hops.push({ url: shown.origin + shown.pathname,
                  status: answered.status, location: answered.location,
                  set: answered.set });
      if (answered.location) {
        at = answered.location;
        continue;
      }
      log.debug("Leaving drive(). The consent answer did not redirect.");
      return { code: "", state: "", error: "", hops: hops,
               stopped: answered };
    }
    log.debug("Leaving drive(). Stopped on a page.");
    return { code: "", state: "", error: "", hops: hops, stopped: r };
  }
  log.debug("Leaving drive(). Too many hops.");
  return { code: "", state: "", error: "", hops: hops,
           stopped: { status: 0, text: "more than twelve hops" } };
}

/**
 * The text of a page, tags stripped, for a failure message.
 *
 * @param html - the page
 * @returns at most 300 characters of its text
 */
function said(html) {
  log.debug("Entering said().");
  log.debug("Leaving said().");
  return String(html || "").replace(/<(style|script)[^>]*>[\s\S]*?<\/\1>/gi,
                                    " ")
    .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 400);
}

// ---------------------------------------------------------------------------
// FIXTURES.
// ---------------------------------------------------------------------------
/**
 * A PKCE pair.
 *
 * @returns `{ verifier, challenge }`
 */
function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const challenge = nodeCrypto.createHash("sha256").update(verifier)
    .digest("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier, challenge: challenge };
}

/**
 * A public OAuth client (PKCE, no secret) registered through cell A — the
 * applications register is the global tier's, so both cells hold it once
 * cell B's follower has pulled it.
 *
 * @param realmBase - cell A's URL, realm prefix included
 * @param clientId - the client id
 * @param redirectUri - its one redirect URI
 * @returns a promise settled when it is registered
 */
async function publicClient(realmBase, clientId, redirectUri) {
  log.debug("Entering publicClient(). " + clientId);
  const created = await api(realmBase, "POST", "/applications/create", {
    identifier: clientId, name: clientId, protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: clientId, oauthRedirectUri: [redirectUri],
              oauthTokenEndpointAuthMethod: "none",
              oauthGrantType: ["authorization_code", "refresh_token"],
              oauthScope: ["openid", "profile"] }
  });
  assert.ok(created.status === 200 ||
            /already in this registry/i.test(created.raw),
    "registering the client " + clientId + " answered " + created.status +
    ": " + created.raw.slice(0, 300));
  log.debug("Leaving publicClient().");
}

/**
 * A person with a password, created at one cell through `/admin-api`.
 *
 * @param base - the cell's URL, realm prefix included
 * @param username - the login name
 * @param password - the password
 * @param homeCell - the cell to home them in, or '' for the default
 * @returns a promise of the call's `{ status, body, raw }`
 */
async function createPerson(base, username, password, homeCell) {
  log.debug("Entering createPerson(). " + username);
  const body = {
    username: username, invent: false, credential: "password",
    password: password,
    attributes: { cn: "Cells " + username, givenName: "Cells",
                  sn: username, displayName: "Cells " + username,
                  mail: username + "@cells.example.test" }
  };
  if (homeCell) {
    body.homeCell = homeCell;
  }
  const out = await api(base, "POST", "/users/create", body);
  log.debug("Leaving createPerson(). " + out.status);
  return out;
}

/**
 * How many people the routing index holds per cell in one realm, as a cell
 * reports it (`store.peoplePerCell`, `[{ realm, cell, people }]`).
 *
 * @param realmBase - a cell's URL, realm prefix included
 * @param realmId - the realm
 * @returns a promise of `{ <cell>: <people> }`
 */
async function peopleIn(realmBase, realmId) {
  log.debug("Entering peopleIn().");
  const view = await api(realmBase, "GET", "/cells");
  assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
  const out = {};
  ((view.body.store && view.body.store.peoplePerCell) || [])
    .forEach(function (row) {
      if (String(row.realm || "") === realmId) {
        out[row.cell] = (out[row.cell] || 0) + Number(row.people || 0);
      }
    });
  log.debug("Leaving peopleIn(). " + JSON.stringify(out));
  return out;
}

/**
 * Waits until the routing index holds at least `n` people of a realm in a
 * cell. A person is claimed in the index when their home cell's store is
 * flushed (persistence/CLAUDE.md, *Tiers*) — a moment after the creation
 * answers — and a sign-in elsewhere before then finds nobody to send home.
 *
 * @param realmBase - a cell's URL, realm prefix included
 * @param realmId - the realm
 * @param cellId - the cell
 * @param n - how many
 * @returns a promise settled when they are there
 */
async function homed(realmBase, realmId, cellId, n) {
  log.debug("Entering homed().");
  await until(n + " person(s) of " + realmId + " homed in " + cellId +
              " in the routing index", 30000, async function () {
                const now = await peopleIn(realmBase, realmId);
                return (now[cellId] || 0) >= n;
              });
  log.debug("Leaving homed().");
}

/**
 * A throwaway trust realm, created at cell A (realms are the global tier's)
 * and waited for at cell B.
 *
 * @param cells - `cellsFromEnv()`
 * @param id - the realm id
 * @returns a promise of `{ a, b }`, each cell's URL under the realm prefix
 */
async function throwawayRealm(cells, id) {
  log.debug("Entering throwawayRealm(). " + id);
  const made = await api(cells.a, "POST", "/realms/create", {
    id: id, domain: id + ".example.net", name: "Cells " + id });
  assert.ok(made.status === 200 && made.body && made.body.ok !== false,
    "creating the realm " + id + " at cell A answered " + made.status +
    ": " + made.raw.slice(0, 300));
  const out = { a: cells.a + "/realm/" + id, b: cells.b + "/realm/" + id };
  await until("cell B knows the realm " + id, 60000, async function () {
    const seen = await api(out.b, "GET", "/cells");
    return seen.status === 200;
  });
  log.debug("Leaving throwawayRealm().");
  return out;
}

/**
 * Sets one setting of a realm (or the default realm) at cell A.
 *
 * @param realmBase - cell A's URL, realm prefix included
 * @param key - the setting
 * @param value - its value
 * @returns a promise settled when it is written
 */
async function setSetting(realmBase, key, value) {
  log.debug("Entering setSetting(). " + key);
  const set = await api(realmBase, "POST", "/config/set",
                        { key: key, value: value });
  assert.ok(set.status === 200 && set.body && set.body.ok !== false,
    "setting " + key + " answered " + set.status + ": " +
    set.raw.slice(0, 300));
  log.debug("Leaving setSetting().");
}

/**
 * One setting's effective value at a cell.
 *
 * @param base - the cell's URL, realm prefix included
 * @param key - the setting
 * @returns a promise of its value
 */
async function settingAt(base, key) {
  log.debug("Entering settingAt(). " + key);
  const got = await api(base, "GET", "/config");
  let found;
  ((got.body && got.body.groups) || []).forEach(function (group) {
    (group.settings || []).forEach(function (row) {
      if (row.key === key) {
        found = row.value;
      }
    });
  });
  log.debug("Leaving settingAt().");
  return found;
}

// ---------------------------------------------------------------------------
// A JWT CHECKED AGAINST A JWKS.
// ---------------------------------------------------------------------------
/**
 * Verifies a compact JWS against a key set with node's crypto.
 *
 * @param jwt - the token
 * @param jwks - `{ keys: [...] }`
 * @returns the payload
 * @throws when no key in the set verifies it
 */
function verifyJwt(jwt, jwks) {
  log.debug("Entering verifyJwt().");
  const parts = String(jwt).split(".");
  assert.strictEqual(parts.length, 3, "not a compact JWS: " +
    String(jwt).slice(0, 40));
  const header = JSON.parse(Buffer.from(parts[0], "base64url")
    .toString("utf8"));
  const input = Buffer.from(parts[0] + "." + parts[1], "ascii");
  const signature = Buffer.from(parts[2], "base64url");
  const alg = String(header.alg || "");
  const candidates = (jwks.keys || []).filter(function (k) {
    return !header.kid || k.kid === header.kid;
  });
  assert.ok(candidates.length, "the key set has no key " + header.kid +
    " (alg " + alg + "); it holds " + (jwks.keys || []).map(function (k) {
      return k.kid;
    }).join(", "));
  const hash = { 256: "sha256", 384: "sha384", 512: "sha512" }[
    alg.slice(2)] || null;
  const verified = candidates.some(function (jwk) {
    let key;
    try {
      key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
    } catch (e) {
      // A key type node cannot load (a post-quantum one) is not this token's
      // key; the next candidate is tried.
      log.debug("Caught in verifyJwt(): " + ((e && e.message) || e));
      return false;
    }
    if (/^RS/.test(alg)) {
      return nodeCrypto.verify(hash, input, key, signature);
    }
    if (/^PS/.test(alg)) {
      return nodeCrypto.verify(hash, input, {
        key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST }, signature);
    }
    if (/^ES/.test(alg)) {
      return nodeCrypto.verify(hash, input, { key: key,
                                              dsaEncoding: "ieee-p1363" },
                               signature);
    }
    if (alg === "EdDSA" || alg === "Ed25519") {
      return nodeCrypto.verify(null, input, key, signature);
    }
    return false;
  });
  assert.ok(verified, "no key " + (header.kid || "") + " in the key set " +
    "verifies this " + alg + " token");
  log.debug("Leaving verifyJwt().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

/**
 * A realm's key set, read at a cell through its discovery document.
 *
 * @param realmBase - the cell's URL, realm prefix included
 * @returns a promise of the JWKS
 */
async function jwksAt(realmBase) {
  log.debug("Entering jwksAt().");
  const d = await fetch(realmBase +
                        "/.well-known/openid-configuration");
  assert.strictEqual(d.status, 200, "discovery answered " + d.status);
  const doc = await d.json();
  // The jwks_uri names the public name; it is read at the cell asked, so
  // the key set is that cell's answer.
  const u = new URL(doc.jwks_uri);
  const r = await fetch(new URL(realmBase).origin + u.pathname);
  assert.strictEqual(r.status, 200, "the key set answered " + r.status);
  log.debug("Leaving jwksAt().");
  return r.json();
}

module.exports = {
  cellsFromEnv: cellsFromEnv,
  tokenAt: tokenAt,
  api: api,
  until: until,
  Jar: Jar,
  browse: browse,
  signInFields: signInFields,
  drive: drive,
  said: said,
  pkce: pkce,
  publicClient: publicClient,
  createPerson: createPerson,
  throwawayRealm: throwawayRealm,
  peopleIn: peopleIn,
  homed: homed,
  setSetting: setSetting,
  settingAt: settingAt,
  verifyJwt: verifyJwt,
  jwksAt: jwksAt
};
