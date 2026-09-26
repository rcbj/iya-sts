// ===========================================================================
// KEYCLOAK AS A SAML 2.0 BROKERING SERVICE PROVIDER (#192).
//
// Keycloak already runs in the parent project's stack, but only as an OpenID
// provider FOR the debugger. Here it is a fourth independent SAML stack: a
// Keycloak realm with a SAML IDENTITY PROVIDER (its broker) pointed at this
// service, which exercises what Keycloak is strictest about — signature
// placement, NameID formats, WantAssertionsSigned and WantAuthnRequestsSigned,
// encrypted assertions, and back-channel Single Logout. Keycloak's official
// image runs as a second container (tests/saml-peers/keycloak), configured
// ENTIRELY through its admin REST API by this job — no exported realm file,
// so no key in git — against two throwaway realms of this service,
// development and product:
//
//   * a Keycloak realm per realm of this service, its SAML identity provider
//     imported from the per-SP metadata this service publishes (Keycloak's
//     own import-config), signatures validated and assertions required
//     signed AND encrypted, AuthnRequests signed; attribute mappers for mail,
//     givenName and sn under their X.500/LDAP names;
//   * this service registers Keycloak's broker by CONSUMING its SP
//     descriptor (#37);
//   * a sign-in through Keycloak (kc_idp_hint) on the HTTP-Redirect and on
//     the HTTP-POST binding for the AuthnRequest, with the brokered user
//     checked: linked to this service, with its attributes;
//   * NameIDPolicy in four formats;
//   * Single Logout: BACK-CHANNEL (Keycloak's admin logout of the user makes
//     Keycloak POST a LogoutRequest to this service server to server, which
//     must end this service's session though no browser is there), then
//     front-channel from Keycloak, and identity-provider-initiated from this
//     service.
//
// A SCENARIO PASSES WHEN Keycloak ends where it should AND its server log
// gained no WARN or ERROR while it ran.
//
// `local: true`, `samlPeer: 'keycloak'` (tests/vendored/MANIFEST.js).
// ===========================================================================

"use strict";

const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const kitFactory = require("./saml_peer_kit.js");

const kit = kitFactory.create("sts_saml_interop_keycloak");
const log = kit.log;

const KC = String(process.env.SAML_PEER_KEYCLOAK_URL || "")
  .replace(/\/+$/, "");
const STAMP = names.runStamp();
const PASSWORD = "Kc-Passw0rd!-" + String(Date.now()).slice(-6);
const ALIAS = "sts";
const CLIENT = "interop";
// Where the OpenID client Keycloak signs its users in to "returns": never
// dialled — the walk stops before it.
const DONE = "http://done.invalid/cb";
const LOGS = ["keycloak.log"];
const NAMEID = {
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  email: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  unspecified: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
};

function isProblem(line) {
  log.debug("Entering isProblem().");
  log.debug("Leaving isProblem().");
  return /\s(WARN|ERROR|FATAL)\s/.test(line);
}

// THE ONE WARNING THE HARNESS CAUSES, set aside by name: Keycloak warns on
// every cookie it sets over plain HTTP, and the peers speak plain HTTP on the
// suite's private bridge (tests/CLAUDE.md, *The SAML peers*). It is about the
// peer's own front door, never about a message this service sent.
const HARNESS = [/DefaultCookieProvider\].*Non-secure context detected/];

// ---------------------------------------------------------------------------
// KEYCLOAK'S ADMIN API
// ---------------------------------------------------------------------------
let adminToken = "";

async function adminLogin() {
  log.debug("Entering adminLogin().");
  const creds = JSON.parse(fs.readFileSync(path.join(kit.logDir("keycloak"),
                                                     "admin.json"), "utf8"));
  const r = await fetch(KC + "/realms/master/protocol/openid-connect/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password",
                                client_id: "admin-cli",
                                username: creds.username,
                                password: creds.password }).toString() });
  const body = kit.jsonOf(await r.text());
  kit.must(r.status === 200 && body && body.access_token,
           "Keycloak's admin token answered " + r.status);
  adminToken = body.access_token;
  log.debug("Leaving adminLogin().");
}

async function kc(method, p, payload, raw) {
  log.debug("Entering kc(). " + method + " " + p);
  const headers = { authorization: "Bearer " + adminToken };
  let body;
  if (raw) {
    body = raw;
  } else if (payload !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(payload);
  }
  const r = await fetch(KC + "/admin" + p, { method: method,
                                              headers: headers, body: body });
  const text = await r.text();
  log.debug("Leaving kc(). " + r.status);
  return { status: r.status, text: text, body: kit.jsonOf(text),
           location: r.headers.get("location") || "" };
}

async function waitForKeycloak() {
  log.debug("Entering waitForKeycloak().");
  // HAND OVER THE ANCHOR, which is what the peer waits for before it starts
  // (tests/saml-peers/keycloak/entrypoint.sh).
  const anchorFile = path.join(kit.logDir("keycloak"), "sts-ca.pem");
  if (!fs.existsSync(anchorFile)) {
    fs.writeFileSync(anchorFile, await kit.stsAnchor());
  }
  const deadline = Date.now() + 240000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(KC + "/realms/master");
      if (r.status === 200) {
        log.debug("Leaving waitForKeycloak(). Up.");
        return;
      }
    } catch (e) {
      log.debug("Caught in waitForKeycloak(): " + ((e && e.message) || e));
      // Still starting: the JVM takes a while.
    }
    await kit.sleep(2000);
  }
  kit.must(false, "Keycloak did not come up at " + KC + " in four minutes");
}

// ---------------------------------------------------------------------------
// ONE REALM OF THIS SERVICE, AND ITS KEYCLOAK REALM
// ---------------------------------------------------------------------------
async function makeWorld(realmMode) {
  log.debug("Entering makeWorld(). " + realmMode);
  const tag = realmMode === "product" ? "p" : "d";
  const realm = ("kc" + tag + "-" + STAMP).replace(/[^a-z0-9-]/g, "")
    .slice(0, 30);
  const rb = kit.realmBase(realm);
  const w = { mode: realmMode, realm: realm, rb: rb, kcRealm: realm,
              person: names.usernameFor("kc" + tag) };
  await kit.ensureRealm(realm, realmMode, {
    "saml2.entityId": rb + "/saml2/idp"
  });
  await kit.createPerson(realm, w.person, PASSWORD);

  const made = await kc("POST", "/realms", { realm: w.kcRealm,
                                             enabled: true });
  kit.must(made.status === 201 || made.status === 409, "creating the " +
           "Keycloak realm answered " + made.status + " " + made.text);
  // THE SP's ENTITYID is Keycloak's default for a broker: the realm's URL.
  w.sp = KC + "/realms/" + w.kcRealm;
  // Registered first, so the per-SP identity provider document exists for
  // Keycloak to import; then consumed once Keycloak's broker exists.
  await kit.createApplication(realm, w.sp, ["saml2"], {});
  const m2 = await fetch(rb + "/saml2/metadata/" + encodeURIComponent(w.sp));
  w.idpMetadata = await m2.text();
  kit.must(m2.status === 200, "the identity provider metadata answered " +
           m2.status);
  w.idp = (/entityID="([^"]+)"/.exec(w.idpMetadata) || [])[1];

  const form = new FormData();
  form.append("providerId", "saml");
  form.append("file", new Blob([w.idpMetadata], { type: "text/xml" }),
              "idp.xml");
  const imported = await kc("POST", "/realms/" + w.kcRealm +
                            "/identity-provider/import-config", undefined,
                            form);
  kit.must(imported.status === 200 && imported.body, "Keycloak's " +
           "import-config answered " + imported.status + " " +
           imported.text.slice(0, 400));
  w.idpConfig = Object.assign({}, imported.body, {
    entityId: w.sp,
    validateSignature: "true",
    wantAuthnRequestsSigned: "true",
    signatureAlgorithm: "RSA_SHA256",
    wantAssertionsSigned: "true",
    wantAssertionsEncrypted: "true",
    postBindingResponse: "true",
    postBindingAuthnRequest: "false",
    postBindingLogout: "false",
    backchannelSupported: "true",
    principalType: "SUBJECT",
    nameIDPolicyFormat: NAMEID.unspecified,
    syncMode: "FORCE"
  });
  const idp = await kc("POST", "/realms/" + w.kcRealm +
                       "/identity-provider/instances", {
    alias: ALIAS, providerId: "saml", enabled: true, trustEmail: true,
    config: w.idpConfig });
  kit.must(idp.status === 201 || idp.status === 409, "creating Keycloak's " +
           "SAML identity provider answered " + idp.status + " " + idp.text);
  for (const [attr, user] of [
    ["urn:oid:0.9.2342.19200300.100.1.3", "email"],
    ["urn:oid:2.5.4.42", "firstName"],
    ["urn:oid:2.5.4.4", "lastName"]]) {
    await kc("POST", "/realms/" + w.kcRealm + "/identity-provider/" +
             "instances/" + ALIAS + "/mappers", {
      name: user, identityProviderAlias: ALIAS,
      identityProviderMapper: "saml-user-attribute-idp-mapper",
      config: { syncMode: "INHERIT", "attribute.name": attr,
                "user.attribute": user } });
  }
  await kc("POST", "/realms/" + w.kcRealm + "/clients", {
    clientId: CLIENT, publicClient: true, standardFlowEnabled: true,
    redirectUris: [DONE, "http://done.invalid/*"],
    attributes: { "post.logout.redirect.uris": "http://done.invalid/*" } });

  const d = await fetch(KC + "/realms/" + w.kcRealm + "/broker/" + ALIAS +
                        "/endpoint/descriptor");
  w.spMetadata = await d.text();
  kit.must(d.status === 200 && /EntityDescriptor/.test(w.spMetadata),
           "Keycloak's SP descriptor answered " + d.status);
  await kit.consumeMetadata(realm, w.sp, w.spMetadata);
  log.info("realm " + realm + " (" + realmMode + "): Keycloak broker " +
           w.sp + " ↔ identity provider " + w.idp);
  log.debug("Leaving makeWorld().");
  return w;
}

// Keycloak's SP descriptor declares the ONE NameID format its identity
// provider asks for, so a change of format is consumed again: this service
// answers a NameIDPolicy only in a format the metadata declares (#37).
async function reconsume(w) {
  log.debug("Entering reconsume().");
  const d = await fetch(KC + "/realms/" + w.kcRealm + "/broker/" + ALIAS +
                        "/endpoint/descriptor");
  await kit.consumeMetadata(w.realm, w.sp, await d.text());
  log.debug("Leaving reconsume().");
}

async function setIdp(w, changes) {
  log.debug("Entering setIdp().");
  Object.assign(w.idpConfig, changes);
  const r = await kc("PUT", "/realms/" + w.kcRealm + "/identity-provider/" +
                     "instances/" + ALIAS, {
    alias: ALIAS, providerId: "saml", enabled: true, trustEmail: true,
    config: w.idpConfig });
  kit.must(r.status === 204, "updating the identity provider answered " +
           r.status + " " + r.text);
  log.debug("Leaving setIdp().");
}

async function scenario(w, what, fn, allowed) {
  log.debug("Entering scenario(). " + what);
  log.info("=== " + w.mode + ": " + what + " ===");
  const watch = kit.logWatch("keycloak", LOGS, isProblem);
  await fn();
  await kit.sleep(500);
  watch.since().forEach(function (l) {
    log.debug("keycloak log: " + l);
  });
  await kit.check(w.mode + ": " + what + " — Keycloak logged no warning " +
                  "or error", async function () {
    const bad = watch.problems(HARNESS.concat(allowed || []));
    kit.assert(!bad.length, bad.length + " line(s):\n    " +
               bad.join("\n    "));
  });
  log.debug("Leaving scenario().");
}

function authUrl(w) {
  log.debug("Entering authUrl().");
  log.debug("Leaving authUrl().");
  return KC + "/realms/" + w.kcRealm + "/protocol/openid-connect/auth?" +
    new URLSearchParams({ client_id: CLIENT, response_type: "code",
                          scope: "openid", redirect_uri: DONE,
                          state: "s-" + STAMP, nonce: "n-" + STAMP,
                          kc_idp_hint: ALIAS }).toString();
}

// Keycloak's own pages a sign-in may meet: the first-broker-login review of
// the profile it built from the assertion. Answered with what it holds.
async function keycloakPage(r, forms) {
  log.debug("Entering keycloakPage().");
  if (new URL(r.url).origin !== new URL(KC).origin) {
    log.debug("Leaving keycloakPage(). Not Keycloak's.");
    return null;
  }
  const profile = forms.find(function (f) {
    return /login-actions/.test(f.action) && "email" in f.fields;
  });
  if (profile) {
    log.debug("Leaving keycloakPage(). The profile review.");
    return { url: profile.action, fields: profile.fields };
  }
  const logout = forms.find(function (f) {
    return /logout/.test(f.action);
  });
  if (logout) {
    log.debug("Leaving keycloakPage(). The logout confirmation.");
    return { url: logout.action, fields: Object.assign({}, logout.fields,
                                                       { confirmLogout: "" }) };
  }
  log.debug("Leaving keycloakPage().");
  return null;
}

async function signIn(w, b, username) {
  log.debug("Entering signIn().");
  const walked = await kit.walk(b, authUrl(w), {
    username: username === undefined ? w.person : username,
    password: PASSWORD, onPage: keycloakPage,
    stopBefore: function (u) {
      return u.indexOf("http://done.invalid") === 0;
    } });
  log.debug("Leaving signIn().");
  return walked;
}

async function brokeredUser(w) {
  log.debug("Entering brokeredUser().");
  const users = await kc("GET", "/realms/" + w.kcRealm + "/users?" +
                         "briefRepresentation=false&max=50");
  const list = (users.body || []).filter(function (u) {
    return !/^service-account/.test(u.username);
  });
  for (const u of list) {
    const fed = await kc("GET", "/realms/" + w.kcRealm + "/users/" + u.id +
                         "/federated-identity");
    const link = (fed.body || []).find(function (f) {
      return f.identityProvider === ALIAS;
    });
    if (link) {
      u.link = link;
    }
  }
  log.debug("Leaving brokeredUser().");
  return list.filter(function (u) {
    return u.link;
  });
}

// ===========================================================================
// SIGN-IN
// ===========================================================================
async function signIns(w) {
  log.debug("Entering signIns().");
  for (const c of [
    { what: "a brokered sign-in, AuthnRequest on HTTP-Redirect",
      post: "false" },
    { what: "a brokered sign-in, AuthnRequest on HTTP-POST", post: "true" }
  ]) {
    await scenario(w, c.what, async function () {
      await setIdp(w, { postBindingAuthnRequest: c.post,
                        nameIDPolicyFormat: NAMEID.unspecified });
      const b = kit.browser();
      const walked = await signIn(w, b);
      const users = await brokeredUser(w);
      const me = users.find(function (u) {
        return u.link.userId === w.person || u.link.userName === w.person;
      });
      await kit.check(w.mode + ": " + c.what + " — Keycloak issued its " +
                      "code, and the brokered user carries this service's " +
                      "attributes", async function () {
        kit.assert(walked.next && /[?&]code=/.test(walked.next),
                   "Keycloak did not complete the sign-in: " +
                   kit.describeWalk(walked));
        kit.assert(me, "no Keycloak user is linked to " + w.person + ": " +
                   JSON.stringify(users.map(function (u) {
                     return u.link;
                   })));
        kit.assert(/@/.test(me.email || ""), "no email mapped: " +
                   JSON.stringify(me));
        // The person's sn: the directory's in product, the invented persona
        // fact in development (saml/person_attributes.ts).
        kit.assert(me.lastName === (w.mode === "product" ? w.person
                                                          : "Mock"),
                   "sn was not mapped to lastName: " + JSON.stringify(me));
      });
      await kit.check(w.mode + ": " + c.what + " — the AuthnRequest was " +
                      "signed, and the Response's assertion encrypted",
                      async function () {
        const req = walked.captured.find(function (m) {
          return m.field === "SAMLRequest";
        });
        const resp = walked.captured.find(function (m) {
          return m.field === "SAMLResponse";
        });
        kit.assert(req && (req.signed || /Signature/.test(req.xml)),
                   "the AuthnRequest was not signed");
        kit.assert(resp && /EncryptedAssertion/.test(resp.xml),
                   "the assertion was not encrypted");
      });
    });
  }
  log.debug("Leaving signIns().");
}

async function nameIdFormats(w) {
  log.debug("Entering nameIdFormats().");
  for (const [label, format] of Object.entries(NAMEID)) {
    await scenario(w, "NameIDPolicy " + label, async function () {
      // Only a persistent or unspecified NameID is the username here: for
      // the other two Keycloak takes the username from the uid attribute,
      // so the brokered user stays the one already linked.
      const byAttribute = label === "transient" || label === "email";
      await setIdp(w, { nameIDPolicyFormat: format,
                        postBindingAuthnRequest: "false",
                        principalType: byAttribute ? "ATTRIBUTE" : "SUBJECT",
                        principalAttribute: byAttribute
                          ? "urn:oid:0.9.2342.19200300.100.1.1" : "" });
      await reconsume(w);
      const walked = await signIn(w, kit.browser());
      await kit.check(w.mode + ": NameIDPolicy " + label + " — Keycloak " +
                      "completed the sign-in, and the NameID is in that " +
                      "format", async function () {
        kit.assert(walked.next && /[?&]code=/.test(walked.next),
                   "Keycloak did not complete the sign-in: " +
                   kit.describeWalk(walked));
        const resp = walked.captured.find(function (m) {
          return m.field === "SAMLRequest";
        });
        kit.assert(resp && resp.xml.indexOf(format) >= 0, "the " +
                   "AuthnRequest's NameIDPolicy is not " + format);
      });
    });
  }
  await setIdp(w, { nameIDPolicyFormat: NAMEID.unspecified,
                    principalType: "SUBJECT", principalAttribute: "" });
  await reconsume(w);
  log.debug("Leaving nameIdFormats().");
}

// ===========================================================================
// SINGLE LOGOUT
// ===========================================================================
async function serviceHasSession(w, b) {
  log.debug("Entering serviceHasSession().");
  const walked = await signIn(w, b, "");
  const onScreen = kit.formsIn(walked.last.body).some(function (f) {
    return "authn_id" in f.fields;
  });
  log.debug("Leaving serviceHasSession(). " + !onScreen);
  return !onScreen;
}

async function singleLogout(w) {
  log.debug("Entering singleLogout().");
  await scenario(w, "back-channel Single Logout from Keycloak",
                 async function () {
    await setIdp(w, { backchannelSupported: "true" });
    const b = kit.browser();
    await signIn(w, b);
    const users = await brokeredUser(w);
    const me = users.find(function (u) {
      return u.link.userName === w.person || u.link.userId === w.person;
    });
    const out = me ? await kc("POST", "/realms/" + w.kcRealm + "/users/" +
                              me.id + "/logout") : { status: 0 };
    await kit.sleep(1000);
    // Keycloak's session is gone by the admin act; the question is whether
    // THIS SERVICE's is, which only the back-channel LogoutRequest ended.
    b.forget(KC);
    const still = await serviceHasSession(w, b);
    await kit.check(w.mode + ": back-channel logout — Keycloak's " +
                    "server-to-server LogoutRequest ended this service's " +
                    "session", async function () {
      kit.assert(me, "no brokered user");
      kit.assert(out.status === 204, "Keycloak's admin logout answered " +
                 out.status);
      kit.assert(!still, "a new sign-in through Keycloak was answered " +
                 "without this service's sign-in screen: the session " +
                 "survived the back-channel LogoutRequest");
    });
  });

  await scenario(w, "front-channel Single Logout from Keycloak",
                 async function () {
    await setIdp(w, { backchannelSupported: "false" });
    const b = kit.browser();
    const walked = await signIn(w, b);
    const code = walked.next ? new URL(walked.next).searchParams.get("code")
                             : "";
    const tokens = await fetch(KC + "/realms/" + w.kcRealm +
                               "/protocol/openid-connect/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code",
                                  client_id: CLIENT, code: code,
                                  redirect_uri: DONE }).toString() });
    const idToken = (kit.jsonOf(await tokens.text()) || {}).id_token || "";
    const out = await kit.walk(b, KC + "/realms/" + w.kcRealm +
                               "/protocol/openid-connect/logout?" +
                               new URLSearchParams({
                                 id_token_hint: idToken,
                                 post_logout_redirect_uri:
                                   "http://done.invalid/out" }).toString(), {
      onPage: keycloakPage,
      stopBefore: function (u) {
        return u.indexOf("http://done.invalid") === 0;
      } });
    b.forget(KC);
    const still = await serviceHasSession(w, b);
    await kit.check(w.mode + ": front-channel logout — Keycloak sent a " +
                    "LogoutRequest through the browser, this service " +
                    "answered Success and its session ended",
                    async function () {
      const resp = out.captured.find(function (m) {
        return m.field === "SAMLResponse" && /LogoutResponse/.test(m.xml);
      });
      kit.assert(resp && /status:Success/.test(resp.xml),
                 "no Success LogoutResponse: " + kit.describeWalk(out));
      kit.assert(!still, "this service still holds a session");
    });
  });

  await scenario(w, "identity-provider-initiated Single Logout",
                 async function () {
    const b = kit.browser();
    await signIn(w, b);
    const page = await b.hop(w.rb + "/saml2/slo");
    const link = (/<a href="([^"]*SAMLRequest=[^"]*)"/.exec(page.body) ||
                  [])[1];
    const walked = link ? await kit.walk(b, kit.htmlDecode(link), {
      onPage: keycloakPage }) : null;
    const again = await signIn(w, b, "");
    await kit.check(w.mode + ": identity-provider-initiated logout — " +
                    "Keycloak ended its session and answered Success",
                    async function () {
      kit.assert(link, "the logout page names no LogoutRequest");
      const resp = walked.captured.find(function (m) {
        return m.field === "SAMLResponse" && /LogoutResponse/.test(m.xml);
      });
      kit.assert(resp && /status:Success"/.test(resp.xml),
                 "no Success LogoutResponse: " + kit.describeWalk(walked));
      kit.assert(!(again.next && /[?&]code=/.test(again.next)),
                 "Keycloak still signed the browser in without a sign-in");
    });
  });
  log.debug("Leaving singleLogout().");
}

async function test() {
  log.debug("Entering test().");
  kit.must(KC, "SAML_PEER_KEYCLOAK_URL is not set: this job drives a " +
           "Keycloak container the launcher starts under the saml-peers " +
           "compose profile (tests/CLAUDE.md, *The SAML peers*)");
  kit.must(kit.logDirReadable("keycloak"), "the Keycloak peer's log " +
           "directory " + kit.logDir("keycloak") + " is not readable here");
  await waitForKeycloak();
  await adminLogin();
  const only = String(process.env.SAML_PEER_SECTIONS || "").split(",")
    .filter(Boolean);
  const run = function (name) {
    log.debug("Entering run(). " + name);
    log.debug("Leaving run().");
    return !only.length || only.indexOf(name) >= 0;
  };
  for (const realmMode of ["development", "product"]) {
    await adminLogin();
    const w = await makeWorld(realmMode);
    if (run("signin")) {
      await signIns(w);
    }
    if (run("nameid")) {
      await nameIdFormats(w);
    }
    if (run("slo")) {
      await singleLogout(w);
    }
  }
  log.debug("Leaving test().");
  return kit.finish(only.length ? 1 : 30);
}

const program = new Command();
program
  .name("sts_saml_interop_keycloak")
  .description("Keycloak as a SAML 2.0 brokering SP against this service " +
      "(#192), in a development and a product realm, configured through " +
      "its admin API, with its server log as the error-and-warning source.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(kit.base()))
  .parse(process.argv);
kit.setBase(program.opts().url);

test().then(function (code) {
  process.exit(code);
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
