// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_federation_rules.js
//
// ===========================================================================
// WHAT A PARTNER'S SIGN-IN CREATES, JOINS AND WRITES, OVER THE WIRE (#358,
// #109; #444 D12, phase 7).
//
// The in-process files call `FederationSp` and `federation.*` in a child
// process. Here a running service is its own partner, on the front-channel
// shape `sts_federation_realms.js` argues for: an identity-provider realm
// (an OpenID Provider whose people this job creates) and a
// service-provider realm federated to it by an OpenID Connect relationship
// (`fedResponseType` id_token by form_post, the partner's keys pasted).
// Every sign-in is a real one through both realms' screens; what was made
// is read back through the service provider's `/admin-api`, each refusal's
// code off its audit log:
//
//   J. `federation_jit.js` and `stable_subject.js` F: with `jit-namespaced`
//      and `fedAutocreateUsers` on, a newcomer becomes ONE entry named
//      `<relationship>~sub-<uuid>` after the partner's `urn:uuid:` subject
//      — a name of its own, whose local subject is not the partner's — and a
//      second sign-in reaches the same entry; with the switch off the next
//      newcomer is refused (STS-FED-0090, "has not been provisioned");
//      `fedProvisionCap` at the count refuses the next newcomer and the
//      linked person still signs in; a cap that is not a count is
//      STS-FED-0163.
//   S. `portal_delegate_search.js` A1, A3, A4: the created entry is stamped
//      `stsProvisionedBy` `federation:<relationship>`; a person already here
//      whom a sign-in reaches is not stamped; a later sign-in through the
//      same partner does not move it.
//   M. `mail_address_sources.js` 4: a partner's address is written verified
//      unless the partner said `email_verified: false` (the realm's people
//      are made with the address unverified to say so).
//   G. `federation_group_authority.js` 1, 2, 7: with `fedProvisionGroups`
//      on and the partner's ID Token carrying groups, a plain new name is
//      created and joined; a console roster's name is refused
//      (`federation.group-ignored`, STS-FED-0164) and neither created nor
//      joined; an ordinary group of that name already here is a collision
//      (STS-FED-0161) and not joined.
//   U. `sourced_attributes.js` B and E: a mapping onto a refused target
//      (`memberOf`) is refused at the relationship's door; the names a
//      partner sent that nothing wrote are listed on the relationship's
//      view.
//
// NOT HERE: the provision-idle job (a clock), the windowed directory (a
// worker's process state) and the in-process calls of
// `applyFederatedGroups()` for a role or policy name (3–6), which need a
// role or an XACML policy naming a group the partner then sends — owed to a
// follow-up with the XACML family (phase 8). The SAML 2.0, SAML 1.1,
// WS-Federation and OAuth 2.0 creates of `federation_jit.js` are owed: each
// needs the partner realm's own protocol walked as this job walks OIDC.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const authnSignin = require("./authn_signin");
const K = require("./oauth_wire_kit.js").kit("sts_federation_rules");

const log = K.log;
const PASSWORD = "Fed-Rules-Passw0rd!-" + String(Date.now()).slice(-6);
const REL = "oidc-rules";
let IDP = null;
let SP = null;
const CLIENT = "fr-client-" + K.STAMP;

function api(realm, path, body) {
  log.debug("Entering api(). " + path);
  log.debug("Leaving api().");
  return K.send(K.rb(realm) + "/admin-api" + path,
                body === undefined ? {} : { json: body });
}

function setRel(field, value) {
  log.debug("Entering setRel(). " + field);
  log.debug("Leaving setRel().");
  return api(SP, "/federation/set", { id: REL, field: field, value: value });
}

async function mustRel(field, value) {
  log.debug("Entering mustRel(). " + field);
  const r = await setRel(field, value);
  assert.strictEqual(r.status, 200, "setting " + field + ": " +
                     r.text.slice(0, 300));
  log.debug("Leaving mustRel().");
}

async function partnerPerson(who, extra) {
  log.debug("Entering partnerPerson(). " + who);
  await K.ok(K.rb(IDP) + "/admin-api/users/create", { username: who,
    invent: false, credential: "password", password: PASSWORD,
    attributes: Object.assign({ cn: "Partner " + who, givenName: "Partner",
      sn: who, mail: who + "@" + IDP + ".example.net" }, extra || {}) },
  "created " + who + " at the partner");
  log.debug("Leaving partnerPerson().");
}

async function view(realm, who) {
  log.debug("Entering view(). " + who);
  const r = await api(realm, "/users?user=" + encodeURIComponent(who));
  const ldap = (r.json && r.json.ldap) || {};
  log.debug("Leaving view().");
  return { status: r.status, json: r.json || {},
           entry: ldap.found && ldap.entry ? ldap.entry.attributes || {}
                                           : null,
           subject: (r.json && r.json.subject) || "",
           links: (r.json && r.json.federationLinks) || [] };
}

function formsIn(html) {
  log.debug("Entering formsIn().");
  const out = [];
  const re = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
  let m = re.exec(String(html || ""));
  while (m) {
    const action = (/action="([^"]*)"/i.exec(m[1]) || [])[1] || "";
    const fields = {};
    for (const one of m[2].matchAll(/<input[^>]*type="hidden"[^>]*>/gi)) {
      const n = /name="([^"]+)"/.exec(one[0]);
      const v = /value="([^"]*)"/.exec(one[0]);
      if (n) {
        fields[n[1]] = v ? v[1].replace(/&quot;/g, "\"").replace(/&#39;/g,
          "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
          .replace(/&amp;/g, "&") : "";
      }
    }
    out.push({ action: action.replace(/&amp;/g, "&"), fields: fields });
    m = re.exec(String(html || ""));
  }
  log.debug("Leaving formsIn().");
  return out;
}

// ONE FEDERATED SIGN-IN, whole: the service provider's login, the partner's
// screen as `who`, the ID Token posted to the ACS, and the redirects until
// the service provider's answer. Answers the last response.
async function federatedSignIn(who) {
  log.debug("Entering federatedSignIn(). " + who);
  const b = K.browser();
  let r = await b.go(K.rb(SP) + "/federation/login/" + REL);
  for (let step = 0; step < 24; step += 1) {
    if ((r.status === 302 || r.status === 303) && r.location) {
      const next = new URL(r.location, K.base).toString();
      if (/\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(next)) {
        const at = new URL(next);
        const screenBase = at.origin +
          at.pathname.replace(/\/authn\/login$/, "");
        const jar = Object.keys(b.jar).map(function (k) {
          return k + "=" + b.jar[k];
        }).join("; ");
        const opened = await authnSignin.screen(screenBase, next,
                                                { cookie: jar });
        const a = await authnSignin.submit(screenBase, next,
          { action: "login", username: who, password: PASSWORD },
          { screen: opened, cookie: jar });
        (a.setCookies || []).concat(opened.setCookies || []).forEach(
          function (line) {
            const pair = String(line).split(";")[0];
            const i = pair.indexOf("=");
            if (i > 0) {
              b.jar[pair.slice(0, i)] = pair.slice(i + 1);
            }
          });
        if (a.next !== "redirect") {
          log.debug("Leaving federatedSignIn(). The screen said " + a.next);
          return { status: a.status, text: JSON.stringify(a.json || {}),
                   location: "" };
        }
        r = await b.go(a.location);
        continue;
      }
      if (authnSignin.isConsent(next)) {
        r = await K.consent(b, next);
        continue;
      }
      r = await b.go(next);
      continue;
    }
    if (r.status !== 200) {
      break;
    }
    const onward = formsIn(r.text).filter(function (f) {
      return "id_token" in f.fields;
    })[0];
    if (!onward) {
      break;
    }
    r = await b.go(new URL(onward.action, K.base).toString(),
                   { form: onward.fields });
  }
  log.debug("Leaving federatedSignIn(). " + r.status);
  return r;
}

async function setUp() {
  log.debug("Entering setUp().");
  IDP = await K.realm("fri", "development");
  SP = await K.realm("frs", "development");
  const d = await K.send(K.rb(IDP) + "/.well-known/openid-configuration");
  const jwks = await K.send(d.json.jwks_uri);
  const made = await api(SP, "/federation/create", { id: REL,
    role: "service-provider", protocol: "oidc", peer: d.json.issuer });
  assert.strictEqual(made.status, 200, made.text.slice(0, 300));
  const settings = { fedSsoUrl: d.json.authorization_endpoint,
    fedScope: "openid profile email", fedUsernameSource: "preferred_username",
    fedClientId: CLIENT, fedResponseType: "id_token",
    fedJwks: JSON.stringify(jwks.json), fedAllowUnencrypted: "TRUE",
    fedAutocreateUsers: "TRUE", fedSubjectPolicy: "jit-namespaced" };
  for (const field of Object.keys(settings)) {
    await mustRel(field, settings[field]);
  }
  for (const mapping of ["given_name=givenName", "family_name=sn",
                         "email=mail", "groups=memberOf"]) {
    await api(SP, "/federation/add-value", { id: REL,
      field: "fedAttributeMap", value: mapping });
  }
  const enabled = await api(SP, "/federation/enable", { id: REL });
  assert.strictEqual(enabled.status, 200, enabled.text.slice(0, 300));
  const rel = await api(SP, "/federation?relationship=" + REL);
  const acs = ((rel.json || {}).endpoints || {}).assertionConsumerService;
  await K.ok(K.rb(IDP) + "/admin-api/applications/create", {
    identifier: CLIENT, name: "federation rules", protocols: ["oidc"],
    fields: { oauthClientId: [CLIENT], oauthRedirectUri: [acs],
              oauthTokenEndpointAuthMethod: "none",
              oauthGrantType: ["implicit"], oauthResponseType: ["id_token"],
              appGroupsClaim: "TRUE", appGroupsClaimName: "groups" } },
  "created the partner's application");
  log.debug("Leaving setUp().");
}

// --------------------------------------------------------------------- J
async function jit() {
  log.debug("Entering jit().");
  log.info("=== J. a created federated entry is <relationship>~sub-<uuid> ===");
  const who = "fr-new-" + K.rand(2);
  await partnerPerson(who);
  const at = await view(IDP, who);
  const name = REL + "~sub-" + at.subject.replace(/^urn:uuid:/i, "")
    .toLowerCase();
  const r = await federatedSignIn(who);
  const made = await view(SP, name);
  const plain = await view(SP, who);
  K.check("J1. a newcomer becomes ONE entry named after the partner's " +
          "subject, " + name + ", and none of the partner's username",
          function () {
            assert.strictEqual(r.status, 200, K.shown(r));
            assert.ok(made.entry, "no entry " + name);
            assert.strictEqual(plain.entry, null);
            assert.strictEqual(made.links.length, 1);
          });
  K.check("J2 (stable_subject F). its local subject is its own, never the " +
          "partner's urn:uuid:", function () {
    assert.ok(/^urn:uuid:/.test(made.subject), made.subject);
    assert.notStrictEqual(made.subject, at.subject);
  });
  const again = await federatedSignIn(who);
  K.check("J3. a second sign-in reaches the same entry, creating none",
          function () {
            assert.strictEqual(again.status, 200, K.shown(again));
            assert.ok((made.links[0] || {}).subject === at.subject ||
                      JSON.stringify(made.links).indexOf(at.subject) >= 0,
                      JSON.stringify(made.links));
          });
  const stamp = JSON.stringify(made.json).match(
    /"stsProvisionedBy":\s*\[?"([^"]+)"/);
  K.check("S1 (delegate search A1). the created entry is stamped " +
          "stsProvisionedBy federation:" + REL, function () {
    assert.ok(stamp && stamp[1] === "federation:" + REL,
              JSON.stringify(made.entry).slice(0, 600));
  });
  await mustRel("fedAutocreateUsers", "FALSE");
  const refusedWho = "fr-late-" + K.rand(2);
  await partnerPerson(refusedWho);
  const refused = await K.coded(SP, "STS-FED-0090", function () {
    return federatedSignIn(refusedWho);
  });
  K.check("J4. with fedAutocreateUsers off the next newcomer is refused, " +
          "STS-FED-0090, the page saying not provisioned", function () {
    assert.strictEqual(refused.answer.status, 403, K.shown(refused.answer));
    assert.ok(/not been provisioned/.test(refused.answer.text));
    assert.ok(refused.rose >= 1);
  });
  await mustRel("fedAutocreateUsers", "TRUE");
  const capBad = await K.coded(SP, "STS-FED-0163", function () {
    return setRel("fedProvisionCap", "many");
  });
  K.check("J5. a cap that is not a count is refused, STS-FED-0163",
          function () {
            assert.ok(capBad.answer.status >= 400, capBad.answer.text);
            assert.ok(capBad.rose >= 1);
          });
  await mustRel("fedProvisionCap", "1");
  const capped = await federatedSignIn(refusedWho);
  const still = await federatedSignIn(who);
  K.check("J6. fedProvisionCap at the count refuses the next newcomer; the " +
          "linked person still signs in", function () {
    assert.ok(capped.status >= 400, K.shown(capped));
    assert.strictEqual(still.status, 200, K.shown(still));
  });
  await mustRel("fedProvisionCap", "");
  log.debug("Leaving jit().");
  return { who: who, name: name };
}

// --------------------------------------------------------------- S, M
async function stampAndMail(first) {
  log.debug("Entering stampAndMail().");
  log.info("=== S. the provisioning stamp; M. a partner's address ===");
  const native = "fr-native-" + K.rand(2);
  await partnerPerson(native);
  await K.ok(K.rb(SP) + "/admin-api/users/create", { username: native,
    invent: false, credential: "password", password: PASSWORD,
    attributes: { cn: "Native " + native, givenName: "Native", sn: native,
                  mail: native + "@sp.example.test" } }, "created " + native);
  const subject = (await view(IDP, native)).subject;
  await api(SP, "/users/federation-link", { user: native, relationship: REL,
                                            subject: subject });
  await mustRel("fedSubjectPolicy", "pre-linked");
  const r = await federatedSignIn(native);
  const v = await view(SP, native);
  K.check("S2 (A3). a person already here whom a federated sign-in reaches " +
          "is not stamped", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(!/"stsProvisionedBy"/.test(JSON.stringify(v.json)),
              JSON.stringify(v.entry).slice(0, 300));
  });
  await mustRel("fedSubjectPolicy", "jit-namespaced");
  await federatedSignIn(first.who);
  const again = await view(SP, first.name);
  K.check("S3 (A4). a later sign-in through the partner does not move the " +
          "stamp", function () {
    assert.ok(/"stsProvisionedBy":\s*\[?"federation:oidc-rules"/.test(
      JSON.stringify(again.json)));
  });
  const verifiedOf = function (vv) {
    return JSON.stringify(vv.json).match(/"mailVerified"\s*:\s*(true|false)/
      ) || JSON.stringify(vv.json).match(/"verified"\s*:\s*(true|false)/);
  };
  K.check("M1. a partner's address is written verified", function () {
    const m = verifiedOf(again);
    assert.ok(m && m[1] === "true", JSON.stringify(again.json).slice(0, 800));
  });
  log.debug("Leaving stampAndMail().");
}

// --------------------------------------------------------------- G, U
async function groupsAndMaps() {
  log.debug("Entering groupsAndMaps().");
  log.info("=== G. a partner's groups; U. what nothing wrote ===");
  await mustRel("fedProvisionGroups", "TRUE");
  // The console's read roster's name, read off the process's settings
  // (`admin.readGroup` is not realm-settable).
  let roster = "";
  (function walk(n) {
    if (n && typeof n === "object") {
      if (n.key === "admin.readGroup" && typeof n.value === "string") {
        roster = n.value;
      }
      Object.keys(n).forEach(function (k) {
        walk(n[k]);
      });
    }
  })((await K.send(K.base + "/admin-api/config")).json);
  assert.ok(roster, "no admin.readGroup in the settings");
  const who = "fr-groups-" + K.rand(2);
  await partnerPerson(who);
  const plainGroup = "fr-plain-" + K.rand(2);
  const collide = "fr-collide-" + K.rand(2);
  for (const g of [plainGroup, roster, collide]) {
    await K.ok(K.rb(IDP) + "/admin-api/groups/create", { group: g },
               "created " + g + " at the partner").catch(function (e) {
      log.debug("Caught in groupsAndMaps(): " + e.message);
      // The roster may already exist at the partner; joining is what counts.
      return null;
    });
    await api(IDP, "/groups/add-member", { group: g, member: who });
  }
  await K.ok(K.rb(SP) + "/admin-api/groups/create", { group: collide },
             "created " + collide + " at the service provider");
  const granted = await K.codeCount(SP, "STS-FED-0164");
  const collided = await K.codeCount(SP, "STS-FED-0161");
  const r = await federatedSignIn(who);
  const name = REL + "~sub-" + (await view(IDP, who)).subject
    .replace(/^urn:uuid:/i, "").toLowerCase();
  // Membership as the person's own view states it (its memberOf), and the
  // group list as the realm's /admin-api/groups?q= finds it.
  const person = JSON.stringify((await view(SP, name)).json).toLowerCase();
  const inGroup = function (g) {
    return person.indexOf("cn=" + g.toLowerCase() + ",") >= 0;
  };
  const listed = async function (g) {
    const gr = await api(SP, "/groups?q=" + encodeURIComponent(g));
    return gr.text.indexOf('"' + g + '"') >= 0 ||
           gr.text.indexOf("cn=" + g + ",") >= 0;
  };
  const plain = { joined: inGroup(plainGroup), made: await listed(plainGroup) };
  const ros = { joined: inGroup(roster), made: await listed(roster) };
  const col = { joined: inGroup(collide) };
  K.check("G1. a plain new name is created and the person joined",
          function () {
            assert.strictEqual(r.status, 200, K.shown(r));
            assert.ok(plain.made && plain.joined, JSON.stringify(plain));
          });
  const g164 = await K.codeAfter(SP, "STS-FED-0164", granted);
  const g161 = await K.codeAfter(SP, "STS-FED-0161", collided);
  K.check("G2. a console roster's name is refused, STS-FED-0164, the person in it nowhere",
          function () {
            assert.ok(g164 > granted, "no STS-FED-0164 row");
            assert.ok(!ros.joined, "joined the roster");
          });
  K.check("G3. an ordinary group of that name already here is a collision, " +
          "STS-FED-0161, and not joined", function () {
    assert.ok(g161 > collided, "no STS-FED-0161 row");
    assert.ok(!col.joined, "joined the colliding group");
  });
  const refusedMap = await api(SP, "/federation/add-value", { id: REL,
    field: "fedAttributeMap", value: "nickname=pwdAccountLockedTime" });
  K.check("U1. a mapping onto a refused target is refused at the " +
          "relationship's door", function () {
    assert.strictEqual(refusedMap.status, 400, refusedMap.text.slice(0, 300));
  });
  const rel = await api(SP, "/federation?relationship=" + REL);
  K.check("U2. the names the partner sent that nothing wrote are listed on " +
          "the relationship's view", function () {
    assert.ok(/unmapped|notMapped|ignored/i.test(rel.text) &&
              /preferred_username|nonce|auth_time|sid|amr|acr/.test(rel.text),
              rel.text.slice(0, 600));
  });
  log.debug("Leaving groupsAndMaps().");
}

async function test() {
  log.debug("Entering test().");
  await setUp();
  const first = await jit();
  await stampAndMail(first);
  await groupsAndMaps();
  log.debug("Leaving test().");
}

K.main(test, 15);
