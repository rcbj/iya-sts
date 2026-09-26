// ===========================================================================
// SIMPLESAMLPHP AS A SAML 2.0 SERVICE PROVIDER AGAINST THIS SERVICE (#191).
//
// SimpleSAMLphp is the most widely deployed PHP SAML stack and a different
// implementation lineage from Shibboleth, Keycloak and pysaml2 — the case
// this repository argues again and again: a round trip between two copies of
// one understanding interoperates with nobody. Its official release runs as a
// second container (tests/saml-peers/simplesamlphp) with a `saml:SP` auth
// source, and this job drives it over HTTP, as a browser would, against two
// throwaway realms of this service — one in development mode, one in product
// mode:
//
//   * each SP is registered by CONSUMING its own metadata (#37), and trusts
//     the identity provider through the per-SP metadata this service
//     publishes, read by SimpleSAMLphp's own SAMLParser and schema
//     validation (its METADATA VALIDATOR: /peer/configure.php answers what
//     it said, and a problem fails the realm);
//   * SP-initiated SSO: the AuthnRequest on HTTP-Redirect (SimpleSAMLphp's
//     choice) and on HTTP-POST (configured to use only that binding), the
//     Response on HTTP-POST, the assertion encrypted to the SP's key — which
//     it insists on. NOT HTTP-Artifact: a SimpleSAMLphp SP
//     cannot ask for it (authsources.php in its peer directory says why);
//   * ForceAuthn, IsPassive with and without a session, and NameIDPolicy
//     asking for persistent, transient and emailAddress;
//   * identity-provider-initiated SSO, an unsolicited Response;
//   * Single Logout both ways.
//
// A SCENARIO PASSES WHEN the SP ends where it should — a session with this
// service's attributes, or the status an error case asks for — AND
// SimpleSAMLphp's own log (with `debug.validatexml` on, so it schema-checks
// everything it receives) gained no WARNING or worse, nor Apache's error log
// an error, while it ran.
//
// `local: true`, `samlPeer: 'simplesamlphp'` (tests/vendored/MANIFEST.js).
// ===========================================================================

"use strict";

const { Command, Option } = require("commander");
const names = require("./random_username.js");
const kitFactory = require("./saml_peer_kit.js");

const kit = kitFactory.create("sts_saml_interop_simplesamlphp");
const log = kit.log;

const PEER = String(process.env.SAML_PEER_SSP_URL || "").replace(/\/+$/, "");
const STAMP = names.runStamp();
const PASSWORD = "Ssp-Passw0rd!-" + String(Date.now()).slice(-6);
const SOURCES = ["sp"];
const LOGS = ["simplesamlphp.log", "apache_error.log"];
const NAMEID = {
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  email: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
};
const UID_NAMES = ["urn:oid:0.9.2342.19200300.100.1.1", "uid"];

// A line SimpleSAMLphp writes at WARNING or worse, or Apache at warn or worse.
function isProblem(line) {
  log.debug("Entering isProblem().");
  log.debug("Leaving isProblem().");
  return /\s(WARNING|ERR|ERROR|CRITICAL|ALERT|EMERG)\s/.test(line) ||
         /:(warn|error|crit|alert|emerg)\]/.test(line);
}

// ---------------------------------------------------------------------------
// ONE REALM, its person, both SPs registered from their metadata, and the
// peer configured with the identity provider metadata published for each.
// SimpleSAMLphp holds several identity providers at once, so both SPs' are
// handed over together.
// ---------------------------------------------------------------------------
async function makeWorld(realmMode) {
  log.debug("Entering makeWorld(). " + realmMode);
  const tag = realmMode === "product" ? "p" : "d";
  const realm = ("ss" + tag + "-" + STAMP).replace(/[^a-z0-9-]/g, "")
    .slice(0, 30);
  const rb = kit.realmBase(realm);
  const w = { mode: realmMode, realm: realm, rb: rb, sp: {},
              person: names.usernameFor("ssp" + tag) };
  await kit.ensureRealm(realm, realmMode, {
    "saml2.entityId": rb + "/saml2/idp"
  });
  await kit.createPerson(realm, w.person, PASSWORD);
  const idpDocs = [];
  for (const source of SOURCES) {
    const md = await fetch(PEER + "/simplesaml/module.php/saml/sp/metadata/" +
                           source);
    const xml = await md.text();
    kit.must(md.status === 200 && /EntityDescriptor/.test(xml),
             "the " + source + " SP's metadata answered " + md.status);
    const entityId = (/entityID="([^"]+)"/.exec(xml) || [])[1];
    await kit.createApplication(realm, entityId, ["saml2"], {});
    await kit.consumeMetadata(realm, entityId, xml);
    const m2 = await fetch(rb + "/saml2/metadata/" +
                           encodeURIComponent(entityId));
    const idpXml = await m2.text();
    kit.must(m2.status === 200, "the identity provider metadata for " +
             entityId + " answered " + m2.status);
    w.sp[source] = { entityId: entityId,
                     idp: (/entityID="([^"]+)"/.exec(idpXml) || [])[1] };
    idpDocs.push(idpXml);
    w.idpXml = idpXml;
  }
  for (const [i, doc] of idpDocs.entries()) {
    const r = await fetch(PEER + "/peer/configure.php", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ idpMetadata: doc, append: i > 0 }) });
    const body = kit.jsonOf(await r.text());
    await kit.check(realmMode + ": SimpleSAMLphp's metadata validator " +
                    "accepts the identity provider metadata published for " +
                    (body && body.entities ? body.entities.join(", ") : "?"),
                    async function () {
      kit.assert(r.status === 200 && body && body.ok,
                 "configure answered " + r.status + " " +
                 JSON.stringify(body));
    });
  }
  log.info("realm " + realm + " (" + realmMode + "): " +
           JSON.stringify(w.sp));
  log.debug("Leaving makeWorld().");
  return w;
}

async function sessionAt(b, source) {
  log.debug("Entering sessionAt(). " + source);
  const r = await b.hop(PEER + "/peer/env.php?as=" + source);
  log.debug("Leaving sessionAt(). " + r.status);
  return r.status === 200 ? kit.jsonOf(r.body) : null;
}

function loginUrl(w, source, extra) {
  log.debug("Entering loginUrl().");
  log.debug("Leaving loginUrl().");
  return PEER + "/peer/login.php?as=" + source + "&idp=" +
    encodeURIComponent(w.sp[source].idp) + (extra || "");
}

async function scenario(w, what, fn, allowed) {
  log.debug("Entering scenario(). " + what);
  log.info("=== " + w.mode + ": " + what + " ===");
  const watch = kit.logWatch("simplesamlphp", LOGS, isProblem);
  await fn();
  await kit.sleep(300);
  watch.since().forEach(function (l) {
    log.debug("simplesamlphp log: " + l);
  });
  await kit.check(w.mode + ": " + what + " — SimpleSAMLphp logged no " +
                  "warning or error", async function () {
    const bad = watch.problems(allowed);
    kit.assert(!bad.length, bad.length + " line(s):\n    " +
               bad.join("\n    "));
  });
  log.debug("Leaving scenario().");
}

function walkIn(w, b, url, opts) {
  log.debug("Entering walkIn().");
  log.debug("Leaving walkIn().");
  return kit.walk(b, url, Object.assign({
    username: w.person, password: PASSWORD,
    stopAt: function (u) {
      return u.indexOf(PEER + "/peer/env.php") === 0;
    } }, opts || {}));
}

function uidOf(env) {
  log.debug("Entering uidOf().");
  const attrs = (env && env.attributes) || {};
  const name = UID_NAMES.find(function (n) {
    return Array.isArray(attrs[n]) && attrs[n].length;
  });
  log.debug("Leaving uidOf().");
  return name ? attrs[name][0] : "";
}

function expectSession(w, source, walked, env) {
  log.debug("Entering expectSession().");
  kit.assert(env && env.authenticated, "no session at the SP; the browser " +
             "went " + kit.describeWalk(walked));
  kit.assert(env.idp === w.sp[source].idp, "the session's identity " +
             "provider is " + env.idp + ", not " + w.sp[source].idp);
  kit.assert(uidOf(env) === w.person, "no uid of " + w.person + " among " +
             "the attributes: " + JSON.stringify(env.attributes));
  kit.assert(env.attributes["urn:oid:0.9.2342.19200300.100.1.3"],
             "no mail attribute under its X.500/LDAP name: " +
             JSON.stringify(env.attributes));
  log.debug("Leaving expectSession().");
}

// ===========================================================================
// SP-INITIATED SSO, BOTH RESPONSE BINDINGS
// ===========================================================================
async function spInitiated(w) {
  log.debug("Entering spInitiated().");
  // NO ARTIFACT CASE: SimpleSAMLphp cannot ask for one — see
  // tests/saml-peers/simplesamlphp/authsources.php and #191.
  for (const c of [
    { source: "sp", what: "SP-initiated SSO, Response on HTTP-POST",
      field: "SAMLResponse" }
  ]) {
    await scenario(w, c.what, async function () {
      const b = kit.browser();
      const walked = await walkIn(w, b, loginUrl(w, c.source));
      const env = await sessionAt(b, c.source);
      await kit.check(w.mode + ": " + c.what + " — the SP holds a session " +
                      "with this service's attributes", async function () {
        expectSession(w, c.source, walked, env);
      });
      await kit.check(w.mode + ": " + c.what + " — the Response came on " +
                      "the binding the SP asked for, the assertion " +
                      "encrypted", async function () {
        const got = walked.captured.find(function (m) {
          return m.field === c.field;
        });
        kit.assert(got, "no " + c.field + " reached the SP: " +
                   kit.describeWalk(walked));
        if (got.xml) {
          kit.assert(/EncryptedAssertion/.test(got.xml), "the assertion " +
                     "was not encrypted");
        }
      });
    });
  }
  // THE AuthnRequest ON HTTP-POST: SimpleSAMLphp configured to use only the
  // identity provider's POST SingleSignOnService (it prefers Redirect).
  await scenario(w, "SP-initiated SSO, AuthnRequest on HTTP-POST",
                 async function () {
    const onlyPost = await fetch(PEER + "/peer/configure.php", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ idpMetadata: w.idpXml,
        ssoBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" }) });
    const b = kit.browser();
    const walked = await walkIn(w, b, loginUrl(w, "sp"));
    const env = await sessionAt(b, "sp");
    await fetch(PEER + "/peer/configure.php", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ idpMetadata: w.idpXml }) });
    await kit.check(w.mode + ": the AuthnRequest went on HTTP-POST, signed, " +
                    "and the SP holds a session", async function () {
      kit.assert(onlyPost.status === 200, "configure answered " +
                 onlyPost.status);
      const req = walked.captured.find(function (m) {
        return m.field === "SAMLRequest";
      });
      kit.assert(req && req.binding === "post" &&
                 /<ds:Signature/.test(req.xml),
                 "no signed POST-binding AuthnRequest: " +
                 kit.describeWalk(walked));
      expectSession(w, "sp", walked, env);
    });
  });
  log.debug("Leaving spInitiated().");
}

// ===========================================================================
// ForceAuthn, IsPassive, NameIDPolicy
// ===========================================================================
async function requestOptions(w) {
  log.debug("Entering requestOptions().");
  await scenario(w, "IsPassive with no session answers NoPassive",
                 async function () {
    const b = kit.browser();
    const walked = await walkIn(w, b, loginUrl(w, "sp", "&isPassive=1"), {
      username: "" });
    await kit.check(w.mode + ": IsPassive with no session — the Response " +
                    "says NoPassive and no sign-in screen was shown",
                    async function () {
      const resp = walked.captured.find(function (m) {
        return m.field === "SAMLResponse";
      });
      kit.assert(resp && /status:NoPassive/.test(resp.xml),
                 "no NoPassive Response: " + kit.describeWalk(walked));
      kit.assert(!walked.trail.some(function (t) {
        return /\/authn\/login/.test(t);
      }), "the sign-in screen was shown");
    });
  }, [/NoPassive/, /Unhandled exception/, /Error report with id/,
      /\[[0-9a-f]+\] (Backtrace|\d+ |Caused by)/]);

  await scenario(w, "IsPassive with a session, and ForceAuthn",
                 async function () {
    const b = kit.browser();
    await walkIn(w, b, loginUrl(w, "sp"));
    const passive = await walkIn(w, b, loginUrl(w, "sp", "&isPassive=1"), {
      username: "" });
    const forced = await walkIn(w, b, loginUrl(w, "sp", "&forceAuthn=1"));
    await kit.check(w.mode + ": IsPassive with a session is answered " +
                    "without the sign-in screen", async function () {
      kit.assert(!passive.trail.some(function (t) {
        return /\/authn\/login/.test(t);
      }), "the sign-in screen was shown: " + kit.describeWalk(passive));
      kit.assert(await sessionAt(b, "sp"), "no SP session");
    });
    await kit.check(w.mode + ": ForceAuthn shows the sign-in screen again " +
                    "though a session exists", async function () {
      kit.assert(forced.trail.some(function (t) {
        return /\/authn\/login/.test(t);
      }), "the sign-in screen was not shown: " + kit.describeWalk(forced));
      kit.assert(await sessionAt(b, "sp"), "no SP session afterwards");
    });
  });

  for (const [label, format] of Object.entries(NAMEID)) {
    await scenario(w, "NameIDPolicy " + label, async function () {
      const b = kit.browser();
      const walked = await walkIn(w, b, loginUrl(w, "sp", "&nameIdFormat=" +
                                                 encodeURIComponent(format)));
      const env = await sessionAt(b, "sp");
      await kit.check(w.mode + ": NameIDPolicy " + label + " — the NameID " +
                      "is in that format", async function () {
        expectSession(w, "sp", walked, env);
        kit.assert(env.nameIdFormat === format, "the NameID format is " +
                   env.nameIdFormat);
        if (label === "transient") {
          kit.assert(env.nameId !== w.person, "a transient NameID is the " +
                     "username");
        }
      });
    });
  }
  log.debug("Leaving requestOptions().");
}

// ===========================================================================
// IDENTITY-PROVIDER-INITIATED SSO
// ===========================================================================
async function idpInitiated(w) {
  log.debug("Entering idpInitiated().");
  await scenario(w, "identity-provider-initiated SSO", async function () {
    const b = kit.browser();
    const acs = PEER + "/simplesaml/module.php/saml/sp/saml2-acs.php/sp";
    const url = w.rb + "/saml2/unsolicited/" +
      encodeURIComponent(w.sp.sp.entityId) + "?shire=" +
      encodeURIComponent(acs) + "&target=" +
      encodeURIComponent(PEER + "/peer/env.php?as=sp");
    const walked = await walkIn(w, b, url);
    const env = await sessionAt(b, "sp");
    await kit.check(w.mode + ": identity-provider-initiated SSO — the SP " +
                    "accepted the unsolicited Response", async function () {
      expectSession(w, "sp", walked, env);
      const resp = walked.captured.find(function (m) {
        return m.field === "SAMLResponse";
      });
      kit.assert(resp && !/InResponseTo=/.test(resp.xml.split(">")[0]),
                 "the Response carries an InResponseTo or was not sent");
    });
  });
  log.debug("Leaving idpInitiated().");
}

// ===========================================================================
// SINGLE LOGOUT
// ===========================================================================
async function serviceHasSession(w, b) {
  log.debug("Entering serviceHasSession().");
  const walked = await kit.walk(b, loginUrl(w, "sp"), {
    stopAt: function (u) {
      return u.indexOf(PEER + "/peer/env.php") === 0;
    } });
  const onScreen = kit.formsIn(walked.last.body).some(function (f) {
    return "authn_id" in f.fields;
  });
  log.debug("Leaving serviceHasSession(). " + !onScreen);
  return !onScreen;
}

async function singleLogout(w) {
  log.debug("Entering singleLogout().");
  await scenario(w, "Single Logout, SP-initiated", async function () {
    const b = kit.browser();
    await walkIn(w, b, loginUrl(w, "sp"));
    const before = await sessionAt(b, "sp");
    const walked = await kit.walk(b, PEER + "/peer/logout.php?as=sp&return=" +
                                  encodeURIComponent(PEER + "/peer/env.php" +
                                                     "?as=sp&after=1"), {
      stopAt: function (u) {
        return /after=1/.test(u);
      } });
    const after = await sessionAt(b, "sp");
    await kit.check(w.mode + ": SP-initiated logout — both sessions ended",
                    async function () {
      kit.assert(before, "there was no SP session to end");
      const resp = walked.captured.find(function (m) {
        return m.field === "SAMLResponse" && /LogoutResponse/.test(m.xml);
      });
      kit.assert(resp && /status:Success/.test(resp.xml),
                 "no successful LogoutResponse: " + kit.describeWalk(walked));
      kit.assert(!after, "the SP still holds a session");
      kit.assert(!(await serviceHasSession(w, b)), "this service still " +
                 "holds a session");
    });
  });

  await scenario(w, "Single Logout, identity-provider-initiated",
                 async function () {
    const b = kit.browser();
    await walkIn(w, b, loginUrl(w, "sp"));
    const before = await sessionAt(b, "sp");
    const page = await b.hop(w.rb + "/saml2/slo");
    const link = (/<a href="([^"]*SAMLRequest=[^"]*)"/.exec(page.body) ||
                  [])[1];
    const walked = link ? await kit.walk(b, kit.htmlDecode(link), {}) : null;
    const after = await sessionAt(b, "sp");
    await kit.check(w.mode + ": identity-provider-initiated logout — the " +
                    "SP ended its session and answered Success",
                    async function () {
      kit.assert(before, "there was no SP session to end");
      kit.assert(link, "the logout page names no LogoutRequest: " +
                 kit.squash(page.body));
      const resp = walked.captured.find(function (m) {
        return m.field === "SAMLResponse" && /LogoutResponse/.test(m.xml);
      });
      kit.assert(resp && /status:Success"/.test(resp.xml),
                 "the SP's LogoutResponse is not Success: " +
                 kit.describeWalk(walked));
      kit.assert(!after, "the SP still holds a session");
    });
  });
  log.debug("Leaving singleLogout().");
}

async function test() {
  log.debug("Entering test().");
  kit.must(PEER, "SAML_PEER_SSP_URL is not set: this job drives a " +
           "SimpleSAMLphp container the launcher starts under the " +
           "saml-peers compose profile (tests/CLAUDE.md, *The SAML peers*)");
  kit.must(kit.logDirReadable("simplesamlphp"), "the SimpleSAMLphp peer's " +
           "log directory " + kit.logDir("simplesamlphp") + " is not " +
           "readable here; it is the harness's error-and-warning source");
  const only = String(process.env.SAML_PEER_SECTIONS || "").split(",")
    .filter(Boolean);
  const run = function (name) {
    log.debug("Entering run(). " + name);
    log.debug("Leaving run().");
    return !only.length || only.indexOf(name) >= 0;
  };
  for (const realmMode of ["development", "product"]) {
    const w = await makeWorld(realmMode);
    if (run("sso")) {
      await spInitiated(w);
    }
    if (run("options")) {
      await requestOptions(w);
    }
    if (run("idp")) {
      await idpInitiated(w);
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
  .name("sts_saml_interop_simplesamlphp")
  .description("SimpleSAMLphp as a SAML 2.0 SP against this service " +
      "(#191), in a development and a product realm, with its own log and " +
      "metadata validator as the error-and-warning sources.")
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
