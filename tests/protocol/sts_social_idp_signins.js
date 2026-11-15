// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_social_idp_signins.js
//
// ===========================================================================
// ONE SIGN-IN THROUGH EACH NAMED SOCIAL PROVIDER'S DUMMY, OVER THE WIRE
// (#1689; #444 D12, phase 7).
//
// `tests/social_idp_signins.js` runs the stack and the companion's
// `social_idps.js` in one child. Here the dummies are served by THIS
// process — `companion/social_idps.js` itself, its public URL the address
// the service dials (OUTBOUND_TEST_HOST) — and the service is a running
// one, in a development realm with `federation.outboundAllowHttp`,
// `federation.consumerProviders` and `federation.atprotoPlcDirectory` (the
// dummies' Bluesky directory) set on the realm. For each named provider, in
// catalogue order:
//
//   * the relationship is created from the profile through
//     `/admin-api/federation/create` (`provider`), pointed at the dummy with
//     the fields `relationshipFields()` names, and enabled last;
//   * a whole sign-in is walked — the service's redirects, the dummy's
//     auto-posted forms — and the namespaced entry
//     (`<relationship>~<subject>`) exists;
//   * its name, given name, surname and address are the dummy account's, and
//     the address verified exactly when the dummy says so.
//
// The catalogue comparison of the in-process file (the dummies are the
// named providers, in order; the two generic profiles stay out) is read
// here from what the API's create accepts: every dummy's id creates a
// relationship, and the two generic profiles are not dummies. `GET /social`
// (the dummies' own index) is the companion's page, not the service's, and
// is not asked.
//
// The browser reaches the dummies on this host's loopback; the service
// reaches them at OUTBOUND_TEST_HOST.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const http = require("http");
const path = require("path");
const K = require("./oauth_wire_kit.js").kit("sts_social_idp_signins");

const log = K.log;
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const { SocialIdps } = require(path.join(REPO, "companion",
                                         "social_idps.js"));
let SP = null;

function htmlText(value) {
  log.debug("Entering htmlText().");
  log.debug("Leaving htmlText().");
  return String(value).replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

function postedForm(html) {
  log.debug("Entering postedForm().");
  const form = /<form method="post" action="([^"]*)">/.exec(html);
  if (!form) {
    log.debug("Leaving postedForm(). None.");
    return null;
  }
  const fields = {};
  const input = /<input type="hidden" name="([^"]*)" value="([^"]*)">/g;
  let one = input.exec(html);
  while (one) {
    fields[htmlText(one[1])] = htmlText(one[2]);
    one = input.exec(html);
  }
  log.debug("Leaving postedForm().");
  return { action: htmlText(form[1]), fields: fields };
}

// THE BROWSER: cookies for the service only, the dummy's pages fetched on
// the loopback, its auto-posted forms posted.
async function signIn(rel) {
  log.debug("Entering signIn(). " + rel);
  const b = K.browser();
  const toLoop = function (u) {
    log.debug("Entering toLoop().");
    log.debug("Leaving toLoop().");
    return String(u).replace("//" + K.HOST + ":", "//127.0.0.1:");
  };
  let at = K.rb(SP) + "/federation/login/" + rel;
  let r = await b.go(at);
  for (let hop = 0; hop < 16; hop += 1) {
    if (r.status >= 300 && r.status < 400 && r.location) {
      at = new URL(r.location, at).toString();
      const remote = at.indexOf(K.base) !== 0;
      r = remote ? await K.send(toLoop(at)) : await b.go(at);
      continue;
    }
    const remoteNow = at.indexOf(K.base) !== 0;
    if (remoteNow && r.text.indexOf("<form method=\"post\" action=") >= 0) {
      const form = postedForm(r.text);
      if (form) {
        at = new URL(form.action, at).toString();
        const remote = at.indexOf(K.base) !== 0;
        r = remote ? await K.send(toLoop(at), { form: form.fields })
                   : await b.go(at, { form: form.fields });
        continue;
      }
    }
    break;
  }
  log.debug("Leaving signIn(). " + r.status);
  return { r: r, at: at };
}

async function entry(name) {
  log.debug("Entering entry(). " + name);
  const r = await K.send(K.rb(SP) + "/admin-api/users?user=" +
                         encodeURIComponent(name));
  const ldap = (r.json && r.json.ldap) || {};
  log.debug("Leaving entry().");
  return { found: !!ldap.found, attrs: (ldap.entry || {}).attributes || {} };
}

function first(e, name) {
  log.debug("Entering first(). " + name);
  const v = e.attrs[name];
  log.debug("Leaving first().");
  return v === undefined ? undefined : [].concat(v)[0];
}

async function oneProvider(social, id) {
  log.debug("Entering oneProvider(). " + id);
  const rel = "soc-" + id;
  const made = await K.send(K.rb(SP) + "/admin-api/federation/create",
                            { json: { id: rel, provider: id } });
  K.check(id + ": the relationship is created from the profile",
          function () {
            assert.strictEqual(made.status, 200, made.text.slice(0, 300));
          });
  const fields = social.relationshipFields(id);
  const bad = [];
  for (const one of fields) {
    const r = await K.send(K.rb(SP) + "/admin-api/federation/set",
      { json: { id: rel, field: one.field, value: one.value } });
    if (r.status !== 200) {
      bad.push(one.field + ": " + r.text.slice(0, 200));
    }
  }
  const on = await K.send(K.rb(SP) + "/admin-api/federation/enable",
                          { json: { id: rel } });
  K.check(id + ": pointed at the dummy and enabled last", function () {
    assert.strictEqual(bad.length, 0, bad.join(" | "));
    assert.strictEqual(on.status, 200, on.text.slice(0, 300));
  });
  const got = await signIn(rel);
  const account = SocialIdps.account(id);
  const name = rel + "~" + String(account.subject);
  let e = await entry(name);
  if (!e.found) {
    // A subject the namespacing rewrites (a URL, a DID): the created entry
    // is the one whose link names the subject.
    const listed = await K.send(K.rb(SP) + "/admin-api/federation?" +
                                "relationship=" + encodeURIComponent(rel));
    const holder = ((listed.json || {}).links || []).map(function (l) {
      return l.user || l.uid || l.username || "";
    }).filter(Boolean)[0];
    if (holder) {
      e = await entry(holder);
    }
  }
  K.check(id + ": signs in " + account.subject, function () {
    assert.strictEqual(got.r.status, 200, got.at + " " + K.shown(got.r));
    assert.ok(e.found, "no entry for " + account.subject);
  });
  const expect = account.expect || {};
  for (const [field, want] of [["cn", expect.cn],
                               ["givenName", expect.givenName],
                               ["sn", expect.sn], ["mail", expect.mail]]) {
    if (want !== undefined) {
      K.check(id + ": the " + field + " is " + want, function () {
        assert.strictEqual(first(e, field), want,
                           JSON.stringify(e.attrs).slice(0, 400));
      });
    }
  }
  if (expect.mail !== undefined) {
    const verified = first(e, "stsMailVerified");
    K.check(id + ": the address is " + (expect.verified ? "" : "not ") +
            "verified", function () {
      if (expect.verified) {
        assert.strictEqual(verified, expect.mail);
      } else {
        assert.strictEqual(verified, undefined);
      }
    });
  }
  log.debug("Leaving oneProvider().");
}

async function test() {
  log.debug("Entering test().");
  const social = new SocialIdps({ publicUrl: "http://127.0.0.1" });
  const server = http.createServer(function (req, res) {
    social.handle(req, res);
  });
  await new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", resolve);
  });
  social.setPublicUrl("http://" + K.HOST + ":" + server.address().port);
  try {
    SP = await K.realm("soc", "development", {
      "federation.outboundAllowHttp": "true",
      "federation.consumerProviders": "true",
      "federation.atprotoPlcDirectory": social.blueskyDirectory() });
    const ids = SocialIdps.ids();
    K.check("the dummies are the named providers, and the two generic " +
            "profiles are not among them", function () {
      assert.ok(ids.length >= 30, String(ids.length));
      assert.ok(ids.indexOf("generic-oidc") < 0 &&
                ids.indexOf("generic-oauth2") < 0);
    });
    const failures = [];
    for (const id of ids) {
      try {
        await oneProvider(social, id);
      } catch (e) {
        log.debug("Caught in test(): " + ((e && e.message) || e));
        // One provider's failure is recorded and the loop continues, so a
        // broken dummy does not hide the others; the run fails below.
        failures.push(id + ": " + ((e && e.message) || e).slice(0, 300));
        log.error(id + " failed: " + ((e && e.message) || e).slice(0, 600));
      }
    }
    assert.strictEqual(failures.length, 0, failures.join("\n"));
  } finally {
    server.close();
  }
  log.debug("Leaving test().");
}

K.main(test, 100);
