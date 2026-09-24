// ===========================================================================
// THE SHIBBOLETH SERVICE PROVIDER 3 AGAINST BOTH SAML IDENTITY PROVIDERS
// (#189).
//
// There is no maintained SAML conformance tool — Kantara's interoperability
// programme ended and `saml2test` was archived in 2014 — so an independent
// reference implementation is the strongest check there is, and Shibboleth's
// SP is the reference one, and the only mainstream SP that still speaks SAML
// 1.1's Browser/POST and Browser/Artifact. It runs as a second container
// (tests/saml-peers/shibboleth: shibd and Apache with mod_shib, from the
// Consortium's own packages) and this job drives it, over HTTP, as a browser
// would, against TWO throwaway realms of this service — one in development
// mode and one in product mode:
//
//   * the SP is registered by CONSUMING its own metadata (#37), and it trusts
//     the identity provider through the metadata this service publishes for
//     it — both profiles' documents, as they are, handed to the peer's
//     control server with the service's TLS anchor for the back channel;
//   * SAML 2.0, SP-initiated: the AuthnRequest on HTTP-Redirect and on
//     HTTP-POST, the Response on HTTP-POST, POST-SimpleSign and
//     HTTP-Artifact (resolved by the SP over SOAP), every assertion
//     encrypted to the key the SP's metadata publishes;
//   * SAML 2.0, identity-provider-initiated: an unsolicited Response on
//     HTTP-POST and on HTTP-Artifact;
//   * SAML 1.1: Browser/POST and Browser/Artifact, through the SP's Shib1
//     session initiator;
//   * the attribute query, SAML 2.0 and SAML 1.1, asked by the SP's own
//     AttributeResolver handler for the NameID the sign-in gave it;
//   * Single Logout both ways: the SP's LogoutRequest to this service, and
//     this service's identity-provider-initiated logout reaching the SP.
//
// A SCENARIO PASSES WHEN the SP ends with a session whose attributes and
// identity provider are the ones this service sent — read from the peer's
// protected page — AND Shibboleth's own log gained no WARN, ERROR, CRIT or
// FATAL line while it ran. Shibboleth's log is the error-and-warning source
// the ticket names; the lines each scenario gained are in this job's output.
//
// `local: true`, `samlPeer: 'shibboleth'` (tests/vendored/MANIFEST.js): the
// runner skips it, saying why, where the launcher brought up no peer.
// ===========================================================================

"use strict";

const { Command, Option } = require("commander");
const names = require("./random_username.js");
const kitFactory = require("./saml_peer_kit.js");

const kit = kitFactory.create("sts_saml_interop_shibboleth");
const log = kit.log;

const PEER = String(process.env.SAML_PEER_SHIBBOLETH_URL || "")
  .replace(/\/+$/, "");
const STAMP = names.runStamp();
const PASSWORD = "Shib-Passw0rd!-" + String(Date.now()).slice(-6);
const NS = {
  saml1p: "urn:oasis:names:tc:SAML:1.1:protocol",
  saml2p: "urn:oasis:names:tc:SAML:2.0:protocol"
};
// The SP's ACS indexes, in the order its <SSO>SAML2 SAML1</SSO> publishes
// them (protocols.xml): SAML 2.0 POST, POST-SimpleSign, Artifact, ECP, then
// SAML 1.1 POST and Artifact.
const ACS = { post: 1, simpleSign: 2, artifact: 3, saml11post: 5,
              saml11artifact: 6 };

// A line Shibboleth writes at WARN or above.
function isProblem(line) {
  log.debug("Entering isProblem().");
  log.debug("Leaving isProblem().");
  return /\s(WARN|ERROR|CRIT|FATAL)\s/.test(line) ||
         /\[(warn|error|crit|alert|emerg)\]/.test(line) ||
         /:(warn|error|crit|alert|emerg)\]/.test(line);
}

const LOGS = ["shibd.log", "native.log", "apache_error.log"];

// THE ONE WARNING SET ASIDE BY NAME: the Shibboleth SP 3.6 announces, at
// WARN, on every use of SAML 1.1, that the next major version removes it.
// It is about the SP's own roadmap, never about a message this service sent,
// and SAML 1.1 is what #189 asks this harness to exercise.
const HARNESS = [/Shibboleth\.DEPRECATION .*(SAML 1\.1|SAML1|Shib1)/];

async function control(pathname, payload) {
  log.debug("Entering control(). " + pathname);
  const u = new URL(PEER);
  const r = await fetch(u.protocol + "//" + u.hostname + ":9090" + pathname, {
    method: payload ? "POST" : "GET",
    headers: payload ? { "content-type": "application/json" } : {},
    body: payload ? JSON.stringify(payload) : undefined });
  const text = await r.text();
  log.debug("Leaving control(). " + r.status);
  return { status: r.status, text: text, body: kit.jsonOf(text) };
}

// ---------------------------------------------------------------------------
// ONE REALM: the person, the SP registered from its metadata, and the SP
// configured with this realm's two identity provider documents.
// ---------------------------------------------------------------------------
async function makeWorld(realmMode) {
  log.debug("Entering makeWorld(). " + realmMode);
  const tag = realmMode === "product" ? "p" : "d";
  const realm = ("sh" + tag + "-" + STAMP).replace(/[^a-z0-9-]/g, "")
    .slice(0, 30);
  const rb = kit.realmBase(realm);
  const w = { mode: realmMode, realm: realm, rb: rb,
              person: names.usernameFor("shib" + tag) };
  // saml11.doNotCacheCondition OFF: the Shibboleth SP's stock
  // security-policy.xml refuses a DoNotCacheCondition (#189; the setting's
  // own description says so).
  await kit.ensureRealm(realm, realmMode, {
    "saml2.entityId": rb + "/saml2/idp",
    "saml11.providerId": rb + "/saml11/idp",
    "saml11.doNotCacheCondition": false
  });
  await kit.createPerson(realm, w.person, PASSWORD);

  const md = await fetch(PEER + "/Shibboleth.sso/Metadata");
  w.spMetadata = await md.text();
  kit.must(md.status === 200 && /EntityDescriptor/.test(w.spMetadata),
           "the SP's metadata answered " + md.status);
  w.sp = (/entityID="([^"]+)"/.exec(w.spMetadata) || [])[1];
  kit.must(w.sp, "the SP's metadata names no entityID");
  await kit.createApplication(realm, w.sp, ["saml2", "saml11"], {});
  w.consumed = await kit.consumeMetadata(realm, w.sp, w.spMetadata);

  const enc = encodeURIComponent(w.sp);
  const m2 = await fetch(rb + "/saml2/metadata/" + enc);
  w.idp2Metadata = await m2.text();
  kit.must(m2.status === 200, "the SAML 2.0 identity provider metadata " +
           "for the SP answered " + m2.status + " " +
           kit.squash(w.idp2Metadata));
  const m11 = await fetch(rb + "/saml11/metadata/" + enc);
  w.idp11Metadata = await m11.text();
  kit.must(m11.status === 200, "the SAML 1.1 metadata for the SP answered " +
           m11.status + " " + kit.squash(w.idp11Metadata));
  w.idp2 = (/entityID="([^"]+)"/.exec(w.idp2Metadata) || [])[1];
  w.idp11 = (/entityID="([^"]+)"/.exec(w.idp11Metadata) || [])[1];

  const configured = await control("/configure", { files: {
    "idp-saml2.xml": w.idp2Metadata,
    "idp-saml11.xml": w.idp11Metadata,
    "sts-ca.pem": await kit.stsAnchor() } });
  kit.must(configured.status === 200 && configured.body &&
           configured.body.ok, "the Shibboleth peer would not take the " +
           "identity provider's metadata: " + configured.text.slice(0, 600));
  log.info("realm " + realm + " (" + realmMode + "): SP " + w.sp +
           "; identity providers " + w.idp2 + " and " + w.idp11);
  log.debug("Leaving makeWorld().");
  return w;
}

// The SP's protected page, as JSON: what mod_shib put in the environment.
async function sessionAt(b) {
  log.debug("Entering sessionAt().");
  const r = await b.hop(PEER + "/peer/env");
  log.debug("Leaving sessionAt(). " + r.status);
  return r.status === 200 ? kit.jsonOf(r.body) : null;
}

// Runs `fn` as one scenario: the checks it makes, then that Shibboleth's own
// log gained no warning or error while it ran.
async function scenario(w, what, fn, allowed) {
  log.debug("Entering scenario(). " + what);
  log.info("=== " + w.mode + ": " + what + " ===");
  const watch = kit.logWatch("shibboleth", LOGS, isProblem);
  await fn();
  await kit.sleep(300);
  const lines = watch.since();
  lines.forEach(function (l) {
    log.debug("shibboleth log: " + l);
  });
  await kit.check(w.mode + ": " + what + " — Shibboleth logged no warning " +
                  "or error", async function () {
    const bad = watch.problems(HARNESS.concat(allowed || []));
    kit.assert(!bad.length, bad.length + " line(s):\n    " +
               bad.join("\n    "));
  });
  log.debug("Leaving scenario().");
}

// Whether THIS SERVICE still holds a session for the browser: an SP-initiated
// sign-in is started and walked with no credentials — a live session answers
// it without the sign-in screen, an ended one stops on the screen.
async function serviceHasSession(w, b) {
  log.debug("Entering serviceHasSession().");
  const walked = await kit.walk(b, login({ entityID: w.idp2 }), {
    stopAt: function (url) {
      return url.indexOf(PEER + "/peer/env") === 0;
    } });
  const onScreen = kit.formsIn(walked.last.body).some(function (f) {
    return "authn_id" in f.fields;
  });
  log.debug("Leaving serviceHasSession(). " + !onScreen);
  return !onScreen;
}

async function signIn(w, b, loginUrl) {
  log.debug("Entering signIn(). " + loginUrl);
  const walked = await kit.walk(b, loginUrl, {
    username: w.person, password: PASSWORD,
    stopAt: function (url) {
      return url.indexOf(PEER + "/peer/env") === 0;
    } });
  log.debug("Leaving signIn().");
  return walked;
}

function expectSession(w, walked, env, idp, extra) {
  log.debug("Entering expectSession().");
  kit.assert(env, "no session at the SP; the browser went " +
             kit.describeWalk(walked));
  kit.assert(env.Shib_Identity_Provider === idp,
             "Shib_Identity_Provider is " + env.Shib_Identity_Provider +
             ", not " + idp + "; the session holds " + JSON.stringify(env));
  kit.assert(env.uid === w.person, "uid is " + env.uid + ", not " + w.person +
             "; the session holds " + JSON.stringify(env));
  kit.assert(/@/.test(String(env.mail || "")), "no mail attribute: " +
             JSON.stringify(env));
  if (extra) {
    extra(env);
  }
  log.debug("Leaving expectSession().");
}

function login(query) {
  log.debug("Entering login().");
  log.debug("Leaving login().");
  return PEER + "/Shibboleth.sso/" +
    (query.post ? "LoginPost" : (query.shib1 ? "LoginShib1" : "Login")) +
    "?target=" + encodeURIComponent(PEER + "/peer/env") +
    "&entityID=" + encodeURIComponent(query.entityID) +
    (query.acsIndex ? "&acsIndex=" + query.acsIndex : "");
}

// ===========================================================================
// SAML 2.0, SP-INITIATED
// ===========================================================================
async function saml2SpInitiated(w) {
  log.debug("Entering saml2SpInitiated().");
  const cases = [
    { what: "SAML 2.0 SP-initiated, AuthnRequest on HTTP-Redirect, " +
            "Response on HTTP-POST", q: { acsIndex: ACS.post },
      binding: "post" },
    { what: "SAML 2.0 SP-initiated, AuthnRequest on HTTP-POST, Response on " +
            "HTTP-POST", q: { post: true, acsIndex: ACS.post },
      binding: "post" },
    { what: "SAML 2.0 SP-initiated, Response on HTTP-POST-SimpleSign",
      q: { acsIndex: ACS.simpleSign }, binding: "simplesign" },
    { what: "SAML 2.0 SP-initiated, Response on HTTP-Artifact",
      q: { acsIndex: ACS.artifact }, binding: "artifact" }
  ];
  for (const c of cases) {
    await scenario(w, c.what, async function () {
      const b = kit.browser();
      const walked = await signIn(w, b, login(Object.assign(
        { entityID: w.idp2 }, c.q)));
      const env = await sessionAt(b);
      await kit.check(w.mode + ": " + c.what + " — the SP holds a session " +
                      "with this service's attributes", async function () {
        expectSession(w, walked, env, w.idp2);
      });
      await kit.check(w.mode + ": " + c.what + " — the AuthnRequest was " +
                      "signed, and the Response went on the binding asked " +
                      "for", async function () {
        const req = walked.captured.find(function (m) {
          return m.field === "SAMLRequest";
        });
        kit.assert(req, "no AuthnRequest was captured: " +
                   kit.describeWalk(walked));
        kit.assert(req.signed || /<ds:Signature|<Signature/.test(req.xml),
                   "the AuthnRequest was not signed");
        const resp = walked.captured.find(function (m) {
          return m.field === "SAMLResponse" || m.field === "SAMLart";
        });
        kit.assert(resp, "no Response or artifact was captured: " +
                   kit.describeWalk(walked));
        const got = resp.binding === "artifact" ? "artifact" : resp.binding;
        kit.assert(got === c.binding, "the Response came on " + got +
                   ", not " + c.binding);
        if (resp.xml) {
          kit.assert(/EncryptedAssertion/.test(resp.xml),
                     "the assertion was not encrypted to the SP's key");
        }
      });
    });
  }
  log.debug("Leaving saml2SpInitiated().");
}

// ===========================================================================
// SAML 2.0, IDENTITY-PROVIDER-INITIATED
// ===========================================================================
async function saml2Unsolicited(w) {
  log.debug("Entering saml2Unsolicited().");
  for (const c of [
    { what: "SAML 2.0 identity-provider-initiated, Response on HTTP-POST",
      shire: "/Shibboleth.sso/SAML2/POST", field: "SAMLResponse" },
    { what: "SAML 2.0 identity-provider-initiated, Response on " +
            "HTTP-Artifact", shire: "/Shibboleth.sso/SAML2/Artifact",
      field: "SAMLart" }
  ]) {
    await scenario(w, c.what, async function () {
      const b = kit.browser();
      const url = w.rb + "/saml2/unsolicited/" + encodeURIComponent(w.sp) +
        "?shire=" + encodeURIComponent(PEER + c.shire) + "&target=" +
        encodeURIComponent(PEER + "/peer/env");
      const walked = await signIn(w, b, url);
      const env = await sessionAt(b);
      await kit.check(w.mode + ": " + c.what + " — the SP accepted the " +
                      "unsolicited Response", async function () {
        expectSession(w, walked, env, w.idp2);
        const got = walked.captured.find(function (m) {
          return m.field === c.field;
        });
        kit.assert(got, "no " + c.field + " reached the SP: " +
                   kit.describeWalk(walked));
        if (got.xml) {
          kit.assert(!/InResponseTo=/.test(got.xml.split(">")[0]),
                     "the unsolicited Response carries InResponseTo");
        }
      });
    });
  }
  log.debug("Leaving saml2Unsolicited().");
}

// ===========================================================================
// SAML 1.1
// ===========================================================================
async function saml11(w) {
  log.debug("Entering saml11().");
  const cases = [
    { what: "SAML 1.1 Browser/POST", acsIndex: ACS.saml11post,
      field: "SAMLResponse" },
    { what: "SAML 1.1 Browser/Artifact", acsIndex: ACS.saml11artifact,
      field: "SAMLart" }
  ];
  for (const c of cases) {
    await scenario(w, c.what, async function () {
      const b = kit.browser();
      const walked = await signIn(w, b, login({ entityID: w.idp11,
                                                acsIndex: c.acsIndex,
                                                shib1: true }));
      const env = await sessionAt(b);
      await kit.check(w.mode + ": " + c.what + " — the SP holds a session " +
                      "with this service's attributes", async function () {
        expectSession(w, walked, env, w.idp11);
      });
      await kit.check(w.mode + ": " + c.what + " — the profile the SP's " +
                      "shire asked for was used", async function () {
        const got = walked.captured.find(function (m) {
          return m.field === c.field;
        });
        kit.assert(got, "no " + c.field + " reached the SP: " +
                   kit.describeWalk(walked));
      });
    });
  }
  log.debug("Leaving saml11().");
}

// ===========================================================================
// THE ATTRIBUTE QUERY
// ===========================================================================
async function attributeQuery(w) {
  log.debug("Entering attributeQuery().");
  for (const c of [
    { what: "SAML 2.0 attribute query", idp: w.idp2, protocol: NS.saml2p },
    { what: "SAML 1.1 attribute query", idp: w.idp11, protocol: NS.saml1p }
  ]) {
    await scenario(w, c.what, async function () {
      const b = kit.browser();
      const walked = await signIn(w, b, login({
        entityID: c.idp, shib1: c.protocol === NS.saml1p }));
      const env = await sessionAt(b);
      const nameId = (env && env.REMOTE_USER) || "";
      const url = PEER + "/Shibboleth.sso/AttrQuery?entityID=" +
        encodeURIComponent(c.idp) + "&nameId=" +
        encodeURIComponent(w.person) + "&protocol=" +
        encodeURIComponent(c.protocol) + "&format=" +
        encodeURIComponent("urn:oasis:names:tc:SAML:1.1:nameid-format:" +
                           "unspecified");
      const r = await b.hop(url);
      log.info(c.what + " answered " + r.status + ": " +
               kit.squash(r.body).slice(0, 300) + " (session NameID " +
               nameId + ", walk " + walked.trail.length + " hops)");
      await kit.check(w.mode + ": " + c.what + " — the SP resolved this " +
                      "service's attributes for the person", async function () {
        kit.assert(r.status === 200, "the SP's AttrQuery handler answered " +
                   r.status + " " + kit.squash(r.body));
        kit.assert(r.body.indexOf(w.person) >= 0, "the answer does not " +
                   "carry the person's uid: " + kit.squash(r.body));
      });
    });
  }
  log.debug("Leaving attributeQuery().");
}

// ===========================================================================
// SINGLE LOGOUT
// ===========================================================================
async function singleLogout(w) {
  log.debug("Entering singleLogout().");
  await scenario(w, "SAML 2.0 Single Logout, SP-initiated", async function () {
    const b = kit.browser();
    await signIn(w, b, login({ entityID: w.idp2 }));
    const before = await sessionAt(b);
    const walked = await kit.walk(b, PEER + "/Shibboleth.sso/Logout?return=" +
                                  encodeURIComponent(PEER + "/done"), {
      stopAt: function (url) {
        return url.indexOf(PEER + "/done") === 0;
      } });
    const after = await sessionAt(b);
    const stillSignedIn = await serviceHasSession(w, b);
    await kit.check(w.mode + ": SP-initiated logout — a LogoutRequest went " +
                    "to this service and its LogoutResponse came back",
                    async function () {
      kit.assert(before, "there was no SP session to end");
      const req = walked.captured.find(function (m) {
        return m.field === "SAMLRequest" && /LogoutRequest/.test(m.xml);
      });
      const resp = walked.captured.find(function (m) {
        return m.field === "SAMLResponse" && /LogoutResponse/.test(m.xml);
      });
      kit.assert(req, "no LogoutRequest: " + kit.describeWalk(walked));
      kit.assert(resp, "no LogoutResponse: " + kit.describeWalk(walked));
      kit.assert(/status:Success/.test(resp.xml), "the LogoutResponse " +
                 "status is not Success: " + resp.xml.slice(0, 600));
      kit.assert(!after, "the SP still holds a session: " +
                 JSON.stringify(after));
    });
    await kit.check(w.mode + ": SP-initiated logout — the session at this " +
                    "service ended too", async function () {
      kit.assert(!stillSignedIn, "a new sign-in at the SP was answered " +
                 "without the sign-in screen: this service still has a " +
                 "session for the browser");
    });
  });

  await scenario(w, "SAML 2.0 Single Logout, identity-provider-initiated",
                 async function () {
    const b = kit.browser();
    await signIn(w, b, login({ entityID: w.idp2 }));
    const before = await sessionAt(b);
    const page = await b.hop(w.rb + "/saml2/slo");
    const link = (/<a href="([^"]*SAMLRequest=[^"]*)"/.exec(page.body) ||
                  [])[1];
    let walked = null;
    if (link) {
      walked = await kit.walk(b, kit.htmlDecode(link), {});
    }
    const after = await sessionAt(b);
    await kit.check(w.mode + ": identity-provider-initiated logout — the " +
                    "SP accepted this service's LogoutRequest and answered",
                    async function () {
      kit.assert(before, "there was no SP session to end");
      kit.assert(link, "the logout page names no LogoutRequest for the SP: " +
                 kit.squash(page.body));
      const resp = walked.captured.find(function (m) {
        return m.field === "SAMLResponse" && /LogoutResponse/.test(m.xml);
      });
      kit.assert(resp, "the SP sent no LogoutResponse: " +
                 kit.describeWalk(walked));
      kit.assert(/status:Success"/.test(resp.xml) &&
                 !/PartialLogout/.test(resp.xml),
                 "the SP's LogoutResponse is not a full Success: " +
                 resp.xml.slice(0, 800));
      kit.assert(!after, "the SP still holds a session: " +
                 JSON.stringify(after));
    });
    await kit.check(w.mode + ": identity-provider-initiated logout — the " +
                    "session at this service ended", async function () {
      kit.assert(!(await serviceHasSession(w, b)), "a new sign-in at the " +
                 "SP was answered without the sign-in screen");
    });
  });
  log.debug("Leaving singleLogout().");
}

async function test() {
  log.debug("Entering test().");
  kit.must(PEER, "SAML_PEER_SHIBBOLETH_URL is not set: this job drives a " +
           "Shibboleth SP container the launcher starts under the " +
           "saml-peers compose profile (tests/CLAUDE.md, *The SAML peers*)");
  kit.must(kit.logDirReadable("shibboleth"), "the Shibboleth peer's log " +
           "directory " + kit.logDir("shibboleth") + " is not readable here; " +
           "it is the harness's error-and-warning source");
  const health = await control("/health");
  kit.must(health.status === 200, "the Shibboleth peer is not up: " +
           health.text.slice(0, 300));
  const only = String(process.env.SAML_PEER_SECTIONS || "").split(",")
    .filter(Boolean);
  const run = function (name) {
    log.debug("Entering run(). " + name);
    log.debug("Leaving run().");
    return !only.length || only.indexOf(name) >= 0;
  };
  for (const realmMode of ["development", "product"]) {
    const w = await makeWorld(realmMode);
    if (run("saml2")) {
      await saml2SpInitiated(w);
    }
    if (run("unsolicited")) {
      await saml2Unsolicited(w);
    }
    if (run("saml11")) {
      await saml11(w);
    }
    if (run("query")) {
      await attributeQuery(w);
    }
    if (run("slo")) {
      await singleLogout(w);
    }
  }
  log.debug("Leaving test().");
  return kit.finish(only.length ? 1 : 40);
}

const program = new Command();
program
  .name("sts_saml_interop_shibboleth")
  .description("The Shibboleth SP 3 against this service's SAML 2.0 and " +
      "SAML 1.1 identity providers (#189), in a development and a product " +
      "realm, with Shibboleth's own log as the error-and-warning source.")
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
