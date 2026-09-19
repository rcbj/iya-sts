"use strict";
//
// File: gnap_flow.js
//
// ---------------------------------------------------------------------------
// WHAT THE GNAP JOBS SHARE BESIDES THE CLIENT: A THROWAWAY REALM, A PERSON WITH
// A REAL PASSWORD, A COOKIE-JAR BROWSER, AND THE REDIRECT GRANT DANCE.
//
// `gnap_client.js` is the independent client instance; this is the RESOURCE
// OWNER and the harness around both. It was the top third of
// `sts_gnap_core.js` until a second and third GNAP job needed the same sign-in
// and approval, and three copies of a function that reads a CSRF token out of a
// page are three places for a markup change to be half-fixed.
//
// Every refusal is read as its GNAP ERROR CODE (RFC 9635 section 3.6), never by
// its status alone, and every response a refusal arrives in must be `no-store`.
//
// It is a LOCAL HELPER (tests/vendored/MANIFEST.js), owned here. Its only
// requires are `assert`, node's crypto and `gnap_client.js`.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const gnap = require("./gnap_client.js");

// `options`: { base, realm, password, log }. Answers the harness bound to them.
function harness(options) {
  const base = options.base;
  const REALM = options.realm;
  const PASSWORD = options.password;
  const log = options.log;
  const api = base + "/admin-api";
  const realmBase = base + "/realm/" + REALM;
  const realmApi = realmBase + "/admin-api";
  const GRANT = realmBase + "/gnap";
  const FINISH = "https://client.gnap.test/callback";
  const DEMO = "urn:mock-sts:gnap:demo";
  const self = { base: base, api: api, realm: REALM, realmBase: realmBase,
                 realmApi: realmApi,
                 GRANT: GRANT, FINISH: FINISH, DEMO: DEMO, RS: realmBase +
                     "/gnap/rs/resource",
                 checks: 0 };

  // THE REGISTRAR gnap_client.js asks before a key's first request
  // (2026-09-18): the key goes onto an application entry, in the realm the
  // request is addressed to, as `gnapKey` — which is how a request by value is
  // matched to its entry. One entry per key, named after its thumbprint-free
  // kid, created once.
  // One spelling of a key object — a JSON string or an object — so a key the
  // job registered and the key a client presents compare equal.
  function canonicalKey(key) {
    log.debug("Entering canonicalKey().");
    let value = key;
    if (typeof value === "string") {
      try {
        value = JSON.parse(value);
      } catch (e) {
        log.debug("Caught in canonicalKey(): " + ((e && e.message) || e));
        // Not JSON: compared as the string it is.
        log.debug("Leaving canonicalKey().");
        return value;
      }
    }
    const jwk = (value && value.jwk) || {};
    log.debug("Leaving canonicalKey().");
    return JSON.stringify([value && value.proof, jwk.kty, jwk.crv, jwk.x,
                           jwk.y, jwk.n, jwk.e, value && value.cert]);
  }

  const registered = new Set();
  // Keys a JOB registered itself, through /applications/create with a
  // gnapKey (self.apiPost notes them): those entries carry the identifier,
  // kind and finish URI the job asserts on, so the registrar must not file
  // the same key a second time under another name.
  const jobKeys = new Set();
  self.noteJobKey = function (body) {
    log.debug("Entering noteJobKey().");
    const key = body && body.fields && body.fields.gnapKey;
    if (key) {
      jobKeys.add(canonicalKey(key));
    }
    log.debug("Leaving noteJobKey().");
  };
  gnap.setRegistrar(async function (client, url, keyObject) {
    log.debug("Entering the GNAP registrar.");
    if (jobKeys.has(canonicalKey(keyObject))) {
      log.debug("Leaving the GNAP registrar. The job registered this key.");
      return;
    }
    const m = /\/realm\/([^/]+)\//.exec(new URL(url).pathname);
    const where = m ? base + "/realm/" + m[1] + "/admin-api" : api;
    const kid = (client.key && client.key.kid) ||
                nodeCrypto.randomBytes(6).toString("hex");
    const identifier = "gnap-key-" + kid;
    if (registered.has(where + " " + identifier)) {
      log.debug("Leaving the GNAP registrar. Already registered.");
      return;
    }
    await self.ok(where + "/applications/create", {
      identifier: identifier, name: "GNAP job key " + kid,
      protocols: ["gnap"],
      fields: { gnapKey: JSON.stringify(keyObject), gnapFinishUri: FINISH }
    }, "provisioned the GNAP key " + kid);
    registered.add(where + " " + identifier);
    log.debug("Leaving the GNAP registrar.");
  });

  self.check = function (what, fn) {
    log.debug("Entering check().");
    fn();
    self.checks += 1;
    log.info("  [ok] " + what);
    log.debug("Leaving check().");
  };

  self.apiPost = async function (url, body) {
    log.debug("Entering apiPost().");
    if (/\/applications\/create$/.test(url)) {
      self.noteJobKey(body);
    }
    const r = await fetch(url,
                          { method: "POST",
                                 headers:
                                   { "Content-Type": "application/json" },
                                 body: JSON.stringify(body) });
    const raw = await r.text();
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      log.debug("Caught in apiPost(): " + ((e && e.message) || e));
      // Not JSON: an HTML error page. `raw` carries it into the message.
      parsed = raw;
    }
    log.debug("Leaving apiPost().");
    return { status: r.status, body: parsed, raw: raw };
  };

  self.apiGet = async function (url) {
    log.debug("Entering apiGet().");
    const r = await fetch(url);
    const raw = await r.text();
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      log.debug("Caught in apiGet(): " + ((e && e.message) || e));
      // Not JSON; the caller asserts on `raw`.
      parsed = raw;
    }
    log.debug("Leaving apiGet().");
    return { status: r.status, body: parsed, raw: raw };
  };

  self.ok = async function (url, body, what) {
    log.debug("Entering ok().");
    const r = await self.apiPost(url, body);
    assert.ok(r.status === 200 && r.body && r.body.ok !== false,
      what + ": " + url + " answered " + r.status + " " +
      String(r.raw).slice(0, 400));
    log.debug("Leaving ok().");
    return r.body;
  };

  self.setting = async function (key, value) {
    log.debug("Entering setting().");
    await self.ok(realmApi + "/config/set", { key: key, value: String(value) },
                  "set " + key);
    log.debug("Leaving setting().");
  };

  // A refusal read as the GNAP error CODE (section 3.6).
  self.refused = function (r, code, what) {
    log.debug("Entering refused().");
    const error = r.json && r.json.error;
    const got = error && typeof error === "object" ? error.code : error;
    assert.strictEqual(got, code, what + " should be refused " + code + "; " +
        "it answered " + r.status +
                       " " + String(r.text).slice(0, 400));
    assert.ok(r.headers["cache-control"] === "no-store", what + ": section 3 " +
        "requires no-store");
    log.debug("Leaving refused().");
    return r.json;
  };

  self.absolute = function (location) {
    log.debug("Entering absolute().");
    log.debug("Leaving absolute().");
    return /^https?:\/\//i.test(String(location || "")) ? String(location)
                                                         : base +
                                                             String(
                                                                 location ||
                                                                     "");
  };

  // A BROWSER: manual redirects and a cookie jar kept BY NAME, so every
  // assertion is about which page came back.
  self.browser = function () {
    log.debug("Entering browser().");
    const b = {
      jar: {},
      async go(method, url, form) {
        log.debug("Entering go().");
        const headers = {};
        const cookie = Object.keys(b.jar)
                             .map(function (k) { return k + "=" + b.jar[k]; })
                             .join("; ");
        if (cookie) {
          headers.cookie = cookie;
        }
        let body;
        if (form) {
          headers["Content-Type"] = "application/x-www-form-urlencoded";
          body = typeof form === "string" ? form :
                 new URLSearchParams(form).toString();
        }
        const r = await fetch(self.absolute(url),
                              { method: method, redirect: "manual",
                                                    headers: headers,
                                                    body: body });
        (r.headers.getSetCookie ? r.headers.getSetCookie() : []).forEach(
            function (one) {
          const pair = String(one).split(";")[0];
          const name = pair.split("=")[0];
          b.jar[name] = pair.slice(name.length + 1);
        });
        log.debug("Leaving go().");
        return { status: r.status, location: r.headers.get("location") || "",
                 text: await r.text() };
      }
    };
    log.debug("Leaving browser().");
    return b;
  };

  self.csrfOf = function (text) {
    log.debug("Entering csrfOf().");
    log.debug("Leaving csrfOf().");
    return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
            [])[1] || "";
  };

  // From an interaction start URI, through sign-in, to the approval page.
  self.reachApproval = async function (b, startUrl, who) {
    log.debug("Entering reachApproval().");
    let r = await b.go("GET", startUrl);
    assert.ok(r.status === 303 && /\/gnap\/approve\//.test(r.location),
      "an interaction start URI forwards to the approval page; got " +
      r.status + " " + r.location +
      " " + r.text.slice(0, 200));
    const approve = r.location;
    r = await b.go("GET", approve);
    if (r.status === 303 && /\/authn\/login\?authn=/.test(r.location)) {
      r = await b.go("GET", r.location);
      const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) ||
                       [])[1];
      assert.ok(authnId,
                "the sign-in screen carries an authn_id: " +
                r.text.slice(0, 300));
      r = await b.go("POST", "/realm/" + REALM + "/authn/login",
                     { authn_id: authnId, username: who, password: PASSWORD,
                       action: "login",
                       csrf_token: self.csrfOf(r.text) });
      assert.ok(r.status === 303,
                "the sign-in redirects back; got " + r.status + " " +
                r.text.slice(0, 300));
      r = await b.go("GET", r.location);
    }
    log.debug("Leaving reachApproval().");
    return { approve: approve, page: r };
  };

  // Tick every right and answer. An approval REMEMBERED from an earlier grant
  // (the consent register) skips the page and goes straight to the finish.
  self.answer = async function (b, approval, action, untick) {
    log.debug("Entering answer().");
    const page = approval.page;
    if (action === "allow" &&
        ((page.status === 303 && /hash=/.test(page.location)) ||
                               (page.status === 200 &&
                                /You approved the request/.test(page.text)))) {
      log.debug("Leaving answer().");
      return page;
    }
    assert.ok(page.status === 200 && /Allow access\?/.test(page.text),
      "the approval page is drawn; got " + page.status + " " +
      page.text.slice(0, 300));
    const rights = [];
    const re = /name="right" value="([^"]+)"/g;
    let m;
    while ((m = re.exec(page.text))) {
      if (!untick || untick.indexOf(m[1]) < 0) {
        rights.push("right=" + encodeURIComponent(m[1]));
      }
    }
    let form = "action=" + action + "&csrf_token=" +
               encodeURIComponent(self.csrfOf(page.text)) +
      (rights.length ? "&" + rights.join("&") : "");
    if (/name="subject" value="yes"/.test(page.text)) {
      form += "&subject=yes";
    }
    log.debug("Leaving answer().");
    return b.go("POST", approval.approve, form);
  };

  self.finishParams = function (location, response) {
    log.debug("Entering finishParams().");
    assert.ok(/^https?:\/\//.test(String(location || "")),
      "the approval should redirect to the client's finish URI; got " +
      (response ? response.status + " " + String(response.text).slice(0, 600) :
       String(location)));
    const u = new URL(location);
    log.debug("Leaving finishParams().");
    return { hash: u.searchParams.get("hash"),
             ref: u.searchParams.get("interact_ref") };
  };

  self.readAccess = function (action) {
    log.debug("Entering readAccess().");
    log.debug("Leaving readAccess().");
    return [{ type: DEMO, actions: [action || "read", "write"] }];
  };

  // A grant request from `client` with the usual interaction.
  self.grantBody = function (client, extra, displayName) {
    log.debug("Entering grantBody().");
    log.debug("Leaving grantBody().");
    return Object.assign({
      access_token: { access: self.readAccess() },
      client: { key: client.keyObject(),
                display: { name: displayName || "GNAP " +
          "job",
                                                    uri: "https://client.gnap.test/" } },
      interact: { start: ["redirect"],
                  finish: { method: "redirect", uri: FINISH, nonce: "n-" +
                  nodeCrypto.randomBytes(8).toString("hex") } }
    }, extra || {});
  };

  // The whole redirect / redirect-finish dance, returning the released
  // response.
  self.redirectGrant = async function (client, who, extra, opts) {
    log.debug("Entering redirectGrant().");
    const body = self.grantBody(client, extra);
    const url = (opts && opts.grant) || GRANT;
    let r = await client.send("POST", url, { json: body });
    assert.strictEqual(r.status, 200,
                       "the grant request is accepted: " +
                       r.text.slice(0, 400));
    const pending = r.json;
    const b = (opts && opts.browser) || self.browser();
    const approval = await self.reachApproval(b, pending.interact.redirect,
                                              who);
    r = await self.answer(b, approval, "allow");
    const finished = self.finishParams(r.location, r);
    const expected = gnap.interactionHash(body.interact.finish.nonce,
                                          pending.interact.finish,
                                          finished.ref, url);
    assert.strictEqual(finished.hash, expected, "the interaction hash " +
                                                "(section 4.2.3) verifies");
    r = await client.send("POST", pending.continue.uri,
                          { token: pending.continue.access_token.value,
                                                          json: {
                                                            interact_ref:
                                                              finished.ref } });
    assert.strictEqual(r.status, 200,
                       "the continuation releases the grant: " +
                       r.text.slice(0, 400));
    log.debug("Leaving redirectGrant().");
    return { pending: pending, released: r.json, browser: b, body: body,
             interactRef: finished.ref };
  };

  self.ensurePerson = async function (who) {
    log.debug("Entering ensurePerson().");
    const r = await self.apiPost(realmApi + "/users/create", {
      username: who, invent: false, credential: "password", password: PASSWORD,
      attributes: { cn: "GNAP " + who, sn: who, givenName: "GNAP",
                    displayName: "GNAP " + who,
                    mail: who + "@gnap.test" } });
    assert.ok(r.status === 200 && r.body.ok,
              "created " + who + ": " + r.raw.slice(0, 300));
    log.debug("Leaving ensurePerson().");
  };

  // A PERSON'S SUBJECT, as every token issued to them carries it
  // (2026-09-14): `urn:uuid:<entryUUID>`, read off `GET /admin-api/users` in
  // this realm. It is not derivable from the name any more, so a job asserting
  // `sub` asks the service rather than building the string.
  self.subjectOf = async function (who) {
    log.debug("Entering subjectOf().");
    const r = await self.apiGet(realmApi + "/users?user=" +
                                encodeURIComponent(who));
    const subject = r.body && typeof r.body === "object" ? r.body.subject : "";
    assert.ok(/^urn:uuid:[0-9a-f-]{36}$/.test(String(subject || "")),
              "the subject of " + who + " from /admin-api/users: " +
              String(r.raw).slice(0, 200));
    log.debug("Leaving subjectOf().");
    return subject;
  };

  self.createRealm = async function (name) {
    log.debug("Entering createRealm().");
    await self.ok(api + "/realms/create", { id: REALM,
                                            domain: REALM + ".example.net",
                                            name: name },
                  "created " +
        "the realm");
    log.debug("Leaving createRealm().");
  };

  return self;
}

module.exports = { harness: harness };
