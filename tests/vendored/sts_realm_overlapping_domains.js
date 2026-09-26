"use strict";
//
// File: sts_realm_overlapping_domains.js
//
// ---------------------------------------------------------------------------
// THREE TRUST REALMS WHOSE DOMAINS OVERLAP (#85, 2026-09-26).
//
// dev.iyasec.io, test.iyasec.io and prod.iyasec.io share every `dc=` RDN but
// the first one — `dc=dev,dc=iyasec,dc=io` beside `dc=test,dc=iyasec,dc=io` —
// which is exactly the shape a directory that decided a realm by SUFFIX, or a
// lookup that walked up to a shared `dc=iyasec,dc=io`, would get wrong. Each
// realm is a tree of its own (`common/realms.js`, the domain's note; rcbj's
// decision of 2026-09-18 that nesting and siblings under one parent are
// allowed), and this job asks whether that is still true over the wire:
//
//   0. The three realms, named and domained dev.iyasec.io, test.iyasec.io and
//      prod.iyasec.io. A realm id cannot hold a dot, so the ids are
//      dev-iyasec-io and so on.
//   1. An APPLICATION in each: its entry's DN ends in its own realm's base DN.
//   2. A PERSON in each: likewise, and their subject is theirs.
//   3. Each person signs in by the OIDC AUTHORIZATION CODE FLOW at their own
//      realm: the ID Token's issuer is that realm, its `sub` the subject the
//      realm's directory holds, and its key is in that realm's JWKS and in
//      neither of the others'. Their access token is good at their realm's
//      UserInfo and refused at the other two.
//   4. NOBODY SEES ANYBODY ELSE'S: each realm, and the default realm, is
//      asked for every other realm's person — by name, by their exact DN and
//      by their subject — and for every other realm's application, by
//      identifier and in its list, and knows none of them. The DN is the
//      sharp one: `uid=x,ou=people,dc=test,dc=iyasec,dc=io` handed to the dev
//      realm is a place in a tree that realm does not hold.
//   5. ONE NAME, THREE TREES: the same username created in all three is three
//      entries whose DNs differ only in the realm's `dc=` RDNs, three
//      subjects, and — in a realm in product mode, where passwords are
//      checked — another realm's password signs nobody in there while the
//      realm's own does.
//
// **THE REALMS ARE LEFT STANDING, AND A KEPT STACK REUSES THEM.** No job here
// removes a realm (tests/CLAUDE.md), and a realm's domain is unique and fixed
// at creation, so the second run against a stack that outlives the run —
// testidp — would be refused its domains. A realm already holding one of the
// three domains is used as it is; everything created INSIDE it carries this
// run's stamp, so the run still starts from nothing of its own.
//
// OWNED HERE (local: true): this repository's realms, directory,
// authorization server and management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
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
var log = bunyan.createLogger({ name: "sts_realm_overlapping_domains",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REDIRECT = "https://rp.overlap.example.test/cb";
const SCOPES = ["openid", "profile", "email"];
// ONE NAME IN ALL THREE REALMS (section 5).
const SHARED = names.usernameFor("overlap-shared");

// The three realms, filled in as the job goes: `id` is the realm that holds
// the domain (this run's or an earlier one's), `base` its URL prefix.
const REALMS = ["dev", "test", "prod"].map(function (label) {
  const domain = label + ".iyasec.io";
  return {
    label: label,
    domain: domain,
    id: domain.replace(/\./g, "-"),
    baseDn: domain.split(".").map(function (part) {
      return "dc=" + part;
    }).join(","),
    user: names.usernameFor("overlap-" + label),
    // Random per process: a kept stack (testidp) must not hold an account
    // whose password is published in this file. See console_signin.js.
    password: "Overlap-" + nodeCrypto.randomBytes(12).toString("base64url") +
              "-Aa1!",
    sharedPassword: "Overlap-shared-" +
                    nodeCrypto.randomBytes(12).toString("base64url") + "-Aa1!",
    client: { client_id: "overlap-" + label + "-" + STAMP,
              client_secret: nodeCrypto.randomBytes(24).toString("base64url") }
  };
});

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — an HTML page or an empty body; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
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

async function get(url, what) {
  log.debug("Entering get().");
  const r = await send(url, { headers: { Accept: "application/json" } });
  assert.ok(r.status === 200 && r.body,
    "GET " + url + " (" + what + ") answered " + r.status + " " +
    String(r.raw).slice(0, 300));
  log.debug("Leaving get().");
  return r.body;
}

function apiOf(realm) {
  log.debug("Entering apiOf().");
  log.debug("Leaving apiOf().");
  return (realm ? realm.base : base) + "/admin-api";
}

function whoOf(realm) {
  log.debug("Entering whoOf().");
  log.debug("Leaving whoOf().");
  return realm ? "the " + realm.domain + " realm" : "the default realm";
}

// One person as a realm's management API answers them: `known` and, when
// known, the entry's DN and the subject every token carries.
async function personAt(realm, key) {
  log.debug("Entering personAt(). " + key);
  const body = await get(apiOf(realm) + "/users?user=" +
                         encodeURIComponent(key), "a person");
  const ldap = body.ldap || {};
  log.debug("Leaving personAt(). known=" + body.known);
  return { known: body.known === true && ldap.found !== false,
           dn: String(ldap.dn || ""), subject: String(body.subject || ""),
           body: body };
}

async function applicationAt(realm, identifier) {
  log.debug("Entering applicationAt(). " + identifier);
  const body = await get(apiOf(realm) + "/applications?application=" +
                         encodeURIComponent(identifier), "an application");
  log.debug("Leaving applicationAt(). found=" + body.found);
  return { found: body.found === true, dn: String(body.dn || ""),
           body: body };
}

function endsWithBase(dn, realm) {
  log.debug("Entering endsWithBase().");
  const tail = "," + realm.baseDn;
  log.debug("Leaving endsWithBase().");
  return dn.toLowerCase().slice(-tail.length) === tail.toLowerCase();
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const parts = String(jwt || "").split(".");
  assert.strictEqual(parts.length, 3, "not a compact JWS: " +
                     String(jwt).slice(0, 80));
  log.debug("Leaving claimsOf().");
  return { header: JSON.parse(Buffer.from(parts[0], "base64url").toString()),
           payload: JSON.parse(Buffer.from(parts[1], "base64url").toString()) };
}

// A JWK's key material, as one comparable string: what makes two keys the
// same key whatever `kid` either realm gave it.
function materialOf(jwk) {
  log.debug("Entering materialOf().");
  const k = jwk || {};
  log.debug("Leaving materialOf().");
  return [k.kty, k.crv, k.n, k.e, k.x, k.y, k.pub].join("|");
}

// ---------------------------------------------------------------------------
// THE REALM, CREATED OR FOUND. See the header for why an existing holder of
// the domain is reused rather than refused.
// ---------------------------------------------------------------------------
async function ensureRealm(realm) {
  log.debug("Entering ensureRealm(). " + realm.domain);
  const listed = await get(base + "/admin-api/realms", "the realms");
  const all = listed.realms || [];
  const holder = all.filter(function (one) {
    return one && String(one.domain || "").toLowerCase() === realm.domain;
  })[0];
  if (holder) {
    realm.id = holder.id;
    log.info("  " + realm.domain + " is already the realm \"" + holder.id +
             "\" (an earlier run's); it is used as it is.");
  } else {
    const clash = all.filter(function (one) {
      return one && one.id === realm.id;
    })[0];
    assert.ok(!clash, "a realm called " + realm.id + " already exists " +
      "with the domain " + (clash && clash.domain) + ", not " + realm.domain +
      "; a domain is fixed at creation, so this job cannot use it.");
    await ok(base + "/admin-api/realms/create", {
      id: realm.id, name: realm.domain, domain: realm.domain,
      description: "Issue #85: one of three realms whose domains share " +
                   "dc=iyasec,dc=io. Left standing by " +
                   "sts_realm_overlapping_domains.js." },
      "created the " + realm.domain + " realm");
  }
  realm.base = base + "/realm/" + realm.id;
  log.debug("Leaving ensureRealm(). " + realm.id);
}

function applicationSpec(realm) {
  log.debug("Entering applicationSpec().");
  log.debug("Leaving applicationSpec().");
  return { identifier: realm.client.client_id, kind: "oauth2-client",
           name: "Overlap " + realm.domain, protocols: ["oauth2", "oidc"],
           fields: { oauthClientId: [realm.client.client_id],
                     oauthClientSecret: realm.client.client_secret,
                     oauthRedirectUri: [REDIRECT],
                     oauthGrantType: ["authorization_code"],
                     oauthAllowedScope: SCOPES,
                     oauthTokenEndpointAuthMethod: "client_secret_basic" } };
}

function personSpec(realm, username, password) {
  log.debug("Entering personSpec().");
  log.debug("Leaving personSpec().");
  return { username: username, invent: false, credential: "password",
           password: password,
           attributes: { cn: "Overlap " + username, givenName: "Overlap",
                         sn: username, displayName: "Overlap " + username,
                         mail: username + "@" + realm.domain } };
}

// The code flow, the way a browser walks it, then the token request with
// the client's secret. Answers the token response.
async function signIn(realm, username, password) {
  log.debug("Entering signIn(). " + username + " at " + realm.domain);
  const got = await registry.authorizationCode(realm.base, {
    clientId: realm.client.client_id, redirectUri: REDIRECT,
    username: username, password: password, scope: SCOPES.join(" ") });
  const r = await send(realm.base + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: "Basic " + Buffer.from(
                 encodeURIComponent(realm.client.client_id) + ":" +
                 encodeURIComponent(realm.client.client_secret))
                 .toString("base64") },
    body: new URLSearchParams({ grant_type: "authorization_code",
      code: got.code, redirect_uri: REDIRECT,
      code_verifier: got.verifier }).toString() });
  assert.strictEqual(r.status, 200, "the token request at " + realm.domain +
                     ": " + r.raw.slice(0, 400));
  log.debug("Leaving signIn().");
  return r.body;
}

// Whether a sign-in with this password is refused at the screen. Walks the
// authorization request and the screen only: a sign-in that works answers a
// redirect back to the authorization endpoint, and anything else — the
// screen drawn again with its refusal — is the refusal asked about.
async function signInRefused(realm, username, password) {
  log.debug("Entering signInRefused(). " + username + " at " + realm.domain);
  const pair = registry.pkce();
  const url = realm.base + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: realm.client.client_id,
    redirect_uri: REDIRECT, scope: "openid", state: "overlap",
    code_challenge: pair.challenge,
    code_challenge_method: pair.method }).toString();
  const first = await fetch(url, { redirect: "manual" });
  const screenAt = new URL(first.headers.get("location") || "", realm.base);
  assert.ok(/\/authn\/login$/.test(screenAt.pathname),
    "the authorization request at " + realm.domain + " should reach the " +
    "sign-in screen; it answered " + first.status + " " + screenAt);
  const page = await (await fetch(screenAt, { redirect: "manual" })).text();
  const authnId = (page.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  const csrf = (page.match(/name="csrf_token" value="([^"]+)"/) || [])[1] ||
               "";
  assert.ok(authnId, "the sign-in screen carries no authn_id.");
  const posted = await fetch(screenAt.origin + screenAt.pathname, {
    method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ authn_id: authnId, username: username,
                                password: password, action: "login",
                                csrf_token: csrf }).toString() });
  const back = posted.headers.get("location") || "";
  const refused = !(posted.status >= 300 && posted.status < 400 &&
                    /\/oauth2\/authorize/.test(back));
  log.debug("Leaving signInRefused(). " + refused + " (" + posted.status +
            ")");
  return refused;
}

async function test() {
  log.debug("Entering test().");
  log.info("Three realms with overlapping domains at " + base);

  log.info("=== 0. the realms ===");
  for (const realm of REALMS) {
    await ensureRealm(realm);
  }
  const listed = (await get(base + "/admin-api/realms", "the realms"))
    .realms || [];
  check("dev.iyasec.io, test.iyasec.io and prod.iyasec.io are three realms, " +
        "each holding its own domain", function () {
    REALMS.forEach(function (realm) {
      const row = listed.filter(function (one) {
        return one && one.id === realm.id;
      })[0];
      assert.ok(row, realm.id + " is not listed");
      assert.strictEqual(String(row.domain).toLowerCase(), realm.domain);
    });
    assert.strictEqual(new Set(REALMS.map(function (r) {
      return r.id;
    })).size, 3);
  });

  log.info("=== 1. an application in each ===");
  for (const realm of REALMS) {
    await ok(apiOf(realm) + "/applications/create", applicationSpec(realm),
             "registered " + realm.client.client_id + " in " + realm.domain);
    realm.app = await applicationAt(realm, realm.client.client_id);
  }
  check("each application's entry is under its own realm's dc= RDNs",
        function () {
    REALMS.forEach(function (realm) {
      assert.ok(realm.app.found, realm.client.client_id + " not found in " +
                realm.domain + ": " + JSON.stringify(realm.app.body)
                  .slice(0, 200));
      assert.ok(endsWithBase(realm.app.dn, realm),
                realm.app.dn + " is not under " + realm.baseDn);
    });
  });

  log.info("=== 2. a person in each ===");
  for (const realm of REALMS) {
    await ok(apiOf(realm) + "/users/create",
             personSpec(realm, realm.user, realm.password),
             "created " + realm.user + " in " + realm.domain);
    realm.person = await personAt(realm, realm.user);
  }
  check("each person's entry is under its own realm's dc= RDNs, with a " +
        "subject", function () {
    REALMS.forEach(function (realm) {
      assert.ok(realm.person.known, realm.user + " unknown in " +
                realm.domain + ": " + JSON.stringify(realm.person.body)
                  .slice(0, 200));
      assert.ok(endsWithBase(realm.person.dn, realm),
                realm.person.dn + " is not under " + realm.baseDn);
      assert.ok(/^urn:uuid:/i.test(realm.person.subject),
                "subject: " + realm.person.subject);
    });
  });

  log.info("=== 3. each signs in by the authorization code flow ===");
  const jwks = {};
  for (const realm of REALMS) {
    const doc = await get(realm.base + "/.well-known/openid-configuration",
                          "discovery");
    realm.issuer = doc.issuer;
    realm.userinfo = doc.userinfo_endpoint;
    jwks[realm.id] = (await get(doc.jwks_uri, "the JWKS")).keys || [];
    realm.tokens = await signIn(realm, realm.user, realm.password);
    realm.idToken = claimsOf(realm.tokens.id_token);
  }
  check("each realm's discovery document names that realm as the issuer",
        function () {
    REALMS.forEach(function (realm) {
      assert.strictEqual(realm.issuer, realm.base);
    });
  });
  check("each ID Token is issued by its realm, to its client, about the " +
        "subject its realm's directory holds", function () {
    REALMS.forEach(function (realm) {
      const p = realm.idToken.payload;
      assert.strictEqual(p.iss, realm.base);
      assert.ok([].concat(p.aud).indexOf(realm.client.client_id) >= 0,
                "aud " + JSON.stringify(p.aud));
      assert.strictEqual(p.sub, realm.person.subject);
    });
    assert.strictEqual(new Set(REALMS.map(function (r) {
      return r.idToken.payload.sub;
    })).size, 3, "two realms' people share a subject");
  });
  check("each ID Token's key is in its own realm's JWKS and in neither " +
        "other realm's", function () {
    REALMS.forEach(function (realm) {
      const kid = realm.idToken.header.kid;
      const own = jwks[realm.id].filter(function (k) {
        return k.kid === kid;
      })[0];
      assert.ok(own, "kid " + kid + " is not in " + realm.domain +
                     "'s JWKS");
      REALMS.forEach(function (other) {
        if (other === realm) {
          return;
        }
        const held = jwks[other.id].map(materialOf);
        assert.ok(held.indexOf(materialOf(own)) < 0, realm.domain +
                  "'s signing key is also published by " + other.domain);
      });
    });
  });
  for (const realm of REALMS) {
    realm.userinfoAt = {};
    for (const other of REALMS) {
      realm.userinfoAt[other.id] = await send(other.userinfo, {
        headers: { Authorization: "Bearer " + realm.tokens.access_token } });
    }
  }
  check("each access token is good at its own realm's UserInfo and refused " +
        "at the other two", function () {
    REALMS.forEach(function (realm) {
      REALMS.forEach(function (other) {
        const r = realm.userinfoAt[other.id];
        if (other === realm) {
          assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
          assert.strictEqual(r.body.sub, realm.person.subject);
        } else {
          assert.strictEqual(r.status, 401, realm.domain + "'s token at " +
                             other.domain + ": " + r.status + " " +
                             r.raw.slice(0, 200));
        }
      });
    });
  });

  log.info("=== 4. nobody sees anybody else's ===");
  // Every realm, and the default realm, asked about every other realm's
  // person and application.
  const askers = REALMS.concat([null]);
  const seen = [];
  for (const asker of askers) {
    for (const owner of REALMS) {
      if (owner === asker) {
        continue;
      }
      for (const key of [owner.user, owner.person.dn, owner.person.subject]) {
        const r = await personAt(asker, key);
        seen.push({ what: whoOf(asker) + " asked for " + owner.domain +
                          "'s person as " + key, leaked: r.known });
      }
      const app = await applicationAt(asker, owner.client.client_id);
      seen.push({ what: whoOf(asker) + " asked for " + owner.domain +
                        "'s application", leaked: app.found });
      const people = await get(apiOf(asker) + "/users?q=" +
                               encodeURIComponent(owner.user), "the list");
      seen.push({ what: whoOf(asker) + "'s people list searched for " +
                        owner.user,
                  leaked: JSON.stringify(people.users || [])
                    .indexOf(owner.user) >= 0 });
      const apps = await get(apiOf(asker) + "/applications?q=" +
                             encodeURIComponent(owner.client.client_id),
                             "the list");
      seen.push({ what: whoOf(asker) + "'s application list searched for " +
                        owner.client.client_id,
                  leaked: JSON.stringify(apps.applications || [])
                    .indexOf(owner.client.client_id) >= 0 });
    }
  }
  check("no realm, and not the default realm, knows another realm's person " +
        "by name, DN or subject, or its application (" + seen.length +
        " questions)", function () {
    const leaks = seen.filter(function (one) {
      return one.leaked;
    }).map(function (one) {
      return one.what;
    });
    assert.deepStrictEqual(leaks, []);
  });
  // The control for the DN and subject questions above: the same keys at
  // home find the person, so "unknown" was an answer about the realm.
  const home = [];
  for (const realm of REALMS) {
    home.push(await personAt(realm, realm.person.dn));
    home.push(await personAt(realm, realm.person.subject));
  }
  check("and each realm finds its own person by that DN and that subject",
        function () {
    home.forEach(function (one) {
      assert.ok(one.known, JSON.stringify(one.body).slice(0, 200));
    });
  });

  log.info("=== 5. one name, three trees ===");
  for (const realm of REALMS) {
    await ok(apiOf(realm) + "/users/create",
             personSpec(realm, SHARED, realm.sharedPassword),
             "created " + SHARED + " in " + realm.domain);
    realm.shared = await personAt(realm, SHARED);
  }
  check(SHARED + " is three entries whose DNs differ only in the realm's " +
        "dc= RDNs, with three subjects", function () {
    const stems = REALMS.map(function (realm) {
      assert.ok(realm.shared.known, SHARED + " unknown in " + realm.domain);
      assert.ok(endsWithBase(realm.shared.dn, realm), realm.shared.dn);
      return realm.shared.dn.slice(0, realm.shared.dn.length -
                                      realm.baseDn.length).toLowerCase();
    });
    assert.strictEqual(new Set(stems).size, 1, JSON.stringify(stems));
    assert.strictEqual(new Set(REALMS.map(function (realm) {
      return realm.shared.subject;
    })).size, 3);
  });
  // THE REALM'S MODE, NOT THE PROCESS'S: a password is checked by the realm
  // the sign-in is at, and a realm may be in product mode in a development
  // process (and a kept realm may have been switched since it was made).
  const crossed = [];
  for (const realm of REALMS) {
    if (!(await registry.isProduct(realm.base))) {
      log.info("  " + realm.domain + " is in development mode, which checks " +
               "no password, so another realm's password is not asked " +
               "about there.");
      continue;
    }
    const other = REALMS[(REALMS.indexOf(realm) + 1) % REALMS.length];
    crossed.push({ at: realm.domain, with: other.domain,
                   refused: await signInRefused(realm, SHARED,
                                                other.sharedPassword),
                   own: await signInRefused(realm, SHARED,
                                            realm.sharedPassword) });
  }
  if (crossed.length) {
    check("in product mode, " + SHARED + "'s password in one realm signs " +
          "nobody in at another, and their own there does (" +
          crossed.length + " realm(s))", function () {
      crossed.forEach(function (one) {
        assert.ok(one.refused, "at " + one.at + " with " + one.with +
                               "'s password");
        assert.ok(!one.own, "at " + one.at + " with its own password");
      });
    });
  }

  assert.ok(checks >= 10, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_realm_overlapping_domains")
  .description("Three trust realms with overlapping domains (#85).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
