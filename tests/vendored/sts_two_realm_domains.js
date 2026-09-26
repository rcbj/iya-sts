"use strict";
//
// File: sts_two_realm_domains.js
//
// ---------------------------------------------------------------------------
// TWO TRUST REALMS WITH TWO DIFFERENT DOMAINS, AND WHERE EVERY OBJECT LANDS
// (#87, 2026-09-26).
//
// `sts_realm_overlapping_domains.js` (#85) is about three trees that share
// every `dc=` RDN but the first. This is the other case: two realms whose
// domains share NOTHING and are not even the same depth —
// `alpha-<stamp>.com` (two labels) and `beta-<stamp>.corp.net` (three) — so a
// base DN built from anything but the realm's own domain, or cut to a fixed
// number of labels, is wrong for at least one of them.
//
//   0. The two realms; each directory's base DN is the RFC 2247 mapping of
//      its domain, the base entry exists, and `ou=users`, `ou=applications`
//      and `ou=groups` sit directly beneath it.
//   1. An APPLICATION in each, at exactly
//      `cn=<identifier>,ou=applications,<base>`.
//   2. A PERSON in each, at exactly `uid=<username>,ou=users,<base>`, the
//      realm's users container naming the same place, a subject.
//   3. A GROUP in each, at exactly `cn=<name>,ou=groups,<base>`, whose
//      `member` names the person's exact DN in the same realm.
//   4. Each person signs in by the OIDC AUTHORIZATION CODE FLOW at their own
//      realm: the ID Token's issuer is that realm, its `sub` is
//      `urn:uuid:<the entryUUID on the person's entry>`, UserInfo agrees, and
//      the access token is refused at the other realm's UserInfo.
//   5. THE WHOLE TREE of each realm, every page: every entry under the
//      realm's base and none under the other's; every DN-valued attribute
//      value (a `member`, a `seeAlso`, anything naming a `dc=`) pointing
//      inside the realm; and the entries this run created are exactly the
//      three expected DNs — none of the other realm's, nothing elsewhere.
//   6. Neither realm knows the other's person (by name, DN or subject),
//      application or group.
//
// Every domain, realm and name carries this run's stamp, so a kept stack
// takes a second run without meeting the first. The realms are left
// standing, as every realm a job makes is (tests/CLAUDE.md).
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
var log = bunyan.createLogger({ name: "sts_two_realm_domains",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REDIRECT = "https://rp.two-realms.example.test/cb";
const SCOPES = ["openid", "profile", "email"];
const PAGE_SIZE = 200;

const REALMS = [
  { label: "a", domain: "alpha-" + STAMP + ".com" },
  { label: "b", domain: "beta-" + STAMP + ".corp.net" }
].map(function (realm) {
  realm.id = ("two-" + realm.label + "-" + STAMP).slice(0, 31);
  realm.base = base + "/realm/" + realm.id;
  realm.baseDn = realm.domain.split(".").map(function (part) {
    return "dc=" + part;
  }).join(",");
  realm.user = names.usernameFor("two-realm-" + realm.label);
  realm.group = names.usernameFor("two-realm-group-" + realm.label);
  // Random per process: a kept stack (testidp) must not hold an account
  // whose password is published in this file. See console_signin.js.
  realm.password = "TwoRealm-" +
    nodeCrypto.randomBytes(12).toString("base64url") + "-Aa1!";
  realm.client = {
    client_id: names.usernameFor("two-realm-app-" + realm.label),
    client_secret: nodeCrypto.randomBytes(24).toString("base64url") };
  realm.expected = {
    user: "uid=" + realm.user + ",ou=users," + realm.baseDn,
    application: "cn=" + realm.client.client_id + ",ou=applications," +
                 realm.baseDn,
    group: "cn=" + realm.group + ",ou=groups," + realm.baseDn
  };
  return realm;
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

function same(a, b) {
  log.debug("Entering same().");
  log.debug("Leaving same().");
  return String(a || "").toLowerCase() === String(b || "").toLowerCase();
}

function under(dn, baseDn) {
  log.debug("Entering under().");
  const d = String(dn || "").toLowerCase();
  const b = String(baseDn).toLowerCase();
  log.debug("Leaving under().");
  return d === b || d.slice(-(b.length + 1)) === "," + b;
}

// Every entry in a realm's directory, walking the pager to its end: a claim
// about what a tree holds is a claim about the whole list (tests/CLAUDE.md,
// *Assert against the whole list*). `q` narrows it the way the API does.
async function directoryOf(realm, q) {
  log.debug("Entering directoryOf(). " + realm.id);
  const entries = [];
  let page = 1;
  let first = null;
  for (;;) {
    const body = await get(realm.base + "/admin-api/ldap/directory?per=" +
      PAGE_SIZE + "&page=" + page + (q ? "&q=" + encodeURIComponent(q) : ""),
      "the directory");
    first = first || body;
    (body.entries || []).forEach(function (entry) {
      entries.push(entry);
    });
    if (!body.pages || page >= body.pages) {
      break;
    }
    page += 1;
  }
  log.debug("Leaving directoryOf(). " + entries.length + " entries.");
  return { baseDn: String(first.baseDn || ""), count: first.count,
           entries: entries };
}

async function personAt(realm, key) {
  log.debug("Entering personAt(). " + key);
  const body = await get(realm.base + "/admin-api/users?user=" +
                         encodeURIComponent(key), "a person");
  const ldap = body.ldap || {};
  log.debug("Leaving personAt(). known=" + body.known);
  return { known: body.known === true && ldap.found !== false,
           dn: String(ldap.dn || ""), usersDn: String(ldap.usersDn || ""),
           subject: String(body.subject || ""), entry: ldap.entry || {},
           body: body };
}

async function applicationAt(realm, identifier) {
  log.debug("Entering applicationAt(). " + identifier);
  const body = await get(realm.base + "/admin-api/applications?application=" +
                         encodeURIComponent(identifier), "an application");
  log.debug("Leaving applicationAt(). found=" + body.found);
  return { found: body.found === true, dn: String(body.dn || ""),
           body: body };
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const parts = String(jwt || "").split(".");
  assert.strictEqual(parts.length, 3, "not a compact JWS: " +
                     String(jwt).slice(0, 80));
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString());
}

function applicationSpec(realm) {
  log.debug("Entering applicationSpec().");
  log.debug("Leaving applicationSpec().");
  return { identifier: realm.client.client_id, kind: "oauth2-client",
           name: "Two realms " + realm.domain,
           protocols: ["oauth2", "oidc"],
           fields: { oauthClientId: [realm.client.client_id],
                     oauthClientSecret: realm.client.client_secret,
                     oauthRedirectUri: [REDIRECT],
                     oauthGrantType: ["authorization_code"],
                     oauthAllowedScope: SCOPES,
                     oauthTokenEndpointAuthMethod: "client_secret_basic" } };
}

// The code flow the way a browser walks it, then the token request with the
// client's secret. Answers the token response.
async function signIn(realm) {
  log.debug("Entering signIn(). " + realm.user);
  const got = await registry.authorizationCode(realm.base, {
    clientId: realm.client.client_id, redirectUri: REDIRECT,
    username: realm.user, password: realm.password,
    scope: SCOPES.join(" ") });
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

// Every attribute value on an entry that names a place in a directory — a
// `member`, a `seeAlso`, a `manager` — read as "anything carrying a dc= RDN",
// with the entry's own `entryDN` left out (it is the entry's DN again).
function dnValuesOf(entry) {
  log.debug("Entering dnValuesOf().");
  const out = [];
  Object.keys(entry.attributes || {}).forEach(function (name) {
    if (name.toLowerCase() === "entrydn") {
      return;
    }
    [].concat(entry.attributes[name]).forEach(function (value) {
      if (/(^|,)\s*dc=/i.test(String(value))) {
        out.push({ attribute: name, value: String(value) });
      }
    });
  });
  log.debug("Leaving dnValuesOf().");
  return out;
}

async function test() {
  log.debug("Entering test().");
  log.info("Two realms with two different domains at " + base);
  const [A, B] = REALMS;

  log.info("=== 0. the realms and their trees ===");
  for (const realm of REALMS) {
    await ok(base + "/admin-api/realms/create", {
      id: realm.id, name: realm.domain, domain: realm.domain,
      description: "Issue #87: one of two realms with different domains. " +
                   "Left standing by sts_two_realm_domains.js." },
      "created the " + realm.domain + " realm");
    realm.tree = await directoryOf(realm);
  }
  check(A.domain + " and " + B.domain + " are two realms, each directory " +
        "rooted at its domain's RFC 2247 base DN", function () {
    REALMS.forEach(function (realm) {
      assert.ok(same(realm.tree.baseDn, realm.baseDn),
                realm.domain + "'s base is " + realm.tree.baseDn);
    });
    assert.ok(!under(A.baseDn, B.baseDn) && !under(B.baseDn, A.baseDn));
  });
  check("each base entry exists, with ou=users, ou=applications and " +
        "ou=groups directly beneath it", function () {
    REALMS.forEach(function (realm) {
      const dns = realm.tree.entries.map(function (e) {
        return e.dn.toLowerCase();
      });
      [realm.baseDn, "ou=users," + realm.baseDn,
       "ou=applications," + realm.baseDn, "ou=groups," + realm.baseDn]
        .forEach(function (dn) {
          assert.ok(dns.indexOf(dn.toLowerCase()) >= 0,
                    dn + " is not in " + realm.domain + "'s directory");
        });
    });
  });

  log.info("=== 1. an application in each ===");
  for (const realm of REALMS) {
    await ok(realm.base + "/admin-api/applications/create",
             applicationSpec(realm),
             "registered " + realm.client.client_id);
    realm.app = await applicationAt(realm, realm.client.client_id);
  }
  check("each application is at cn=<identifier>,ou=applications,<its " +
        "realm's base>", function () {
    REALMS.forEach(function (realm) {
      assert.ok(realm.app.found, JSON.stringify(realm.app.body)
        .slice(0, 200));
      assert.ok(same(realm.app.dn, realm.expected.application),
                realm.app.dn + " is not " + realm.expected.application);
    });
  });

  log.info("=== 2. a person in each ===");
  for (const realm of REALMS) {
    await ok(realm.base + "/admin-api/users/create", {
      username: realm.user, invent: false, credential: "password",
      password: realm.password,
      attributes: { cn: "Two realms " + realm.user, givenName: "Two",
                    sn: realm.user, displayName: "Two realms " + realm.user,
                    mail: realm.user + "@" + realm.domain } },
      "created " + realm.user);
    realm.person = await personAt(realm, realm.user);
  }
  check("each person is at uid=<username>,ou=users,<its realm's base>, the " +
        "realm's users container, with an entryUUID", function () {
    REALMS.forEach(function (realm) {
      const p = realm.person;
      assert.ok(p.known, JSON.stringify(p.body).slice(0, 200));
      assert.ok(same(p.dn, realm.expected.user),
                p.dn + " is not " + realm.expected.user);
      assert.ok(same(p.usersDn, "ou=users," + realm.baseDn),
                "users container " + p.usersDn);
      realm.entryUuid = String([].concat(
        (p.entry.attributes || {}).entryUUID || [])[0] || "");
      assert.ok(/^[0-9a-f-]{36}$/i.test(realm.entryUuid),
                "entryUUID " + realm.entryUuid);
      assert.ok(same(p.subject, "urn:uuid:" + realm.entryUuid),
                "subject " + p.subject);
    });
  });

  log.info("=== 3. a group in each, holding the person ===");
  for (const realm of REALMS) {
    const made = await ok(realm.base + "/admin-api/groups/create",
      { group: realm.group,
        note: "Created by sts_two_realm_domains.js, run " + STAMP + "." },
      "created the group " + realm.group);
    realm.groupDn = String(made.dn || "");
    await ok(realm.base + "/admin-api/groups/add-member",
             { group: realm.groupDn, member: realm.person.dn },
             "added " + realm.user + " to " + realm.group);
  }

  log.info("=== 4. each signs in by the authorization code flow ===");
  for (const realm of REALMS) {
    const doc = await get(realm.base + "/.well-known/openid-configuration",
                          "discovery");
    realm.userinfo = doc.userinfo_endpoint;
    realm.tokens = await signIn(realm);
    realm.claims = claimsOf(realm.tokens.id_token);
  }
  check("each ID Token is issued by its realm to its client, about " +
        "urn:uuid:<the entryUUID on the person's entry>", function () {
    REALMS.forEach(function (realm) {
      const c = realm.claims;
      assert.strictEqual(c.iss, realm.base);
      assert.ok([].concat(c.aud).indexOf(realm.client.client_id) >= 0,
                "aud " + JSON.stringify(c.aud));
      assert.strictEqual(c.sub, "urn:uuid:" + realm.entryUuid);
    });
  });
  for (const realm of REALMS) {
    realm.userinfoAt = {};
    for (const other of REALMS) {
      realm.userinfoAt[other.id] = await send(other.userinfo, {
        headers: { Authorization: "Bearer " + realm.tokens.access_token } });
    }
  }
  check("UserInfo at the person's own realm names the same subject and the " +
        "address in its domain, and the other realm refuses the token",
        function () {
    REALMS.forEach(function (realm) {
      REALMS.forEach(function (other) {
        const r = realm.userinfoAt[other.id];
        if (other === realm) {
          assert.strictEqual(r.status, 200, r.raw.slice(0, 200));
          assert.strictEqual(r.body.sub, realm.claims.sub);
          assert.strictEqual(r.body.email, realm.user + "@" + realm.domain);
        } else {
          assert.strictEqual(r.status, 401, realm.domain + "'s token at " +
                             other.domain + ": " + r.status);
        }
      });
    });
  });

  log.info("=== 5. every object in each tree ===");
  for (const realm of REALMS) {
    realm.tree = await directoryOf(realm);
  }
  check("the group is at cn=<name>,ou=groups,<its realm's base> and its " +
        "member is the person's exact DN", function () {
    REALMS.forEach(function (realm) {
      assert.ok(same(realm.groupDn, realm.expected.group),
                realm.groupDn + " is not " + realm.expected.group);
      const entry = realm.tree.entries.filter(function (e) {
        return same(e.dn, realm.expected.group);
      })[0];
      assert.ok(entry, realm.expected.group + " is not in the directory");
      const members = [].concat((entry.attributes || {}).member || []);
      assert.ok(members.some(function (m) {
        return same(m, realm.expected.user);
      }), "member " + JSON.stringify(members));
    });
  });
  check("every entry in each realm's directory is under that realm's base " +
        "and none under the other's (" + A.tree.entries.length + " + " +
        B.tree.entries.length + " entries)", function () {
    REALMS.forEach(function (realm) {
      const other = realm === A ? B : A;
      const stray = realm.tree.entries.filter(function (e) {
        return !under(e.dn, realm.baseDn) || under(e.dn, other.baseDn);
      }).map(function (e) {
        return e.dn;
      });
      assert.deepStrictEqual(stray, [], realm.domain);
      assert.strictEqual(realm.tree.entries.length, realm.tree.count,
                         "the pager walked " + realm.tree.entries.length +
                         " of " + realm.tree.count);
    });
  });
  check("every DN-valued attribute value in each realm points inside that " +
        "realm", function () {
    REALMS.forEach(function (realm) {
      const outside = [];
      realm.tree.entries.forEach(function (entry) {
        dnValuesOf(entry).forEach(function (one) {
          if (!under(one.value, realm.baseDn)) {
            outside.push(entry.dn + " " + one.attribute + ": " + one.value);
          }
        });
      });
      assert.deepStrictEqual(outside, [], realm.domain);
    });
  });
  check("the entries this run made in each realm are exactly its person, " +
        "application and group, at the DNs expected", function () {
    REALMS.forEach(function (realm) {
      // By the first RDN's VALUE, not by `q`: the stamp is in the realm's
      // domain as well, so a search for it matches every DN in the tree.
      const found = realm.tree.entries.filter(function (e) {
        const value = String(e.dn).split(",")[0].split("=").slice(1).join("=");
        return value.indexOf("two-realm-") === 0 &&
               value.indexOf(STAMP) >= 0;
      }).map(function (e) {
        return e.dn.toLowerCase();
      }).sort();
      const wanted = [realm.expected.user, realm.expected.application,
                      realm.expected.group].map(function (dn) {
        return dn.toLowerCase();
      }).sort();
      assert.deepStrictEqual(found, wanted, realm.domain);
    });
  });

  log.info("=== 6. neither realm knows the other's ===");
  const leaks = [];
  for (const realm of REALMS) {
    const other = realm === A ? B : A;
    for (const key of [other.user, other.person.dn, other.claims.sub]) {
      if ((await personAt(realm, key)).known) {
        leaks.push(realm.domain + " knows " + other.domain + "'s person as " +
                   key);
      }
    }
    if ((await applicationAt(realm, other.client.client_id)).found) {
      leaks.push(realm.domain + " knows " + other.domain + "'s application");
    }
    const byGroup = await directoryOf(realm, other.group);
    if (byGroup.entries.length) {
      leaks.push(realm.domain + " holds " + byGroup.entries.map(function (e) {
        return e.dn;
      }).join(", ") + " for " + other.domain + "'s group");
    }
  }
  check("neither realm knows the other's person by name, DN or subject, its " +
        "application, or its group", function () {
    assert.deepStrictEqual(leaks, []);
  });

  assert.ok(checks >= 11, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_two_realm_domains")
  .description("Two trust realms with two different domains (#87).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
