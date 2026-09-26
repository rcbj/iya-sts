// ===========================================================================
// PYSAML2 AS A SCRIPTED SAML 2.0 SERVICE PROVIDER, NEGATIVE CASES INCLUDED
// (#190).
//
// pysaml2 (IdentityPython, Apache-2.0, maintained) is a complete SAML 2.0
// implementation that can be SCRIPTED, which a browser SP cannot be: it can
// send exactly the malformed, replayed, wrongly signed and wrongly addressed
// messages the refusals in saml/ exist for, and it validates what comes back
// with its own parser — signatures, conditions, audience, InResponseTo and
// SubjectConfirmationData. It runs as a second container
// (tests/saml-peers/pysaml2, `peer.py` over Saml2Client) and this job drives
// it against two throwaway realms, development and product:
//
//   * the SP is registered by CONSUMING its metadata (#37) and trusts the
//     per-SP identity provider metadata this service publishes;
//   * every binding: the AuthnRequest on HTTP-Redirect and on HTTP-POST, the
//     Response on HTTP-POST and on HTTP-Artifact (resolved by pysaml2 over
//     SOAP, with a signed ArtifactResolve);
//   * signed and UNSIGNED AuthnRequests: refused in both modes while the
//     SP's metadata says AuthnRequestsSigned="true", and — with that
//     metadata consumed saying "false" — decided by
//     `saml2.requireSignedAuthnRequests` off, on and auto;
//   * ForceAuthn, IsPassive (with and without a session), NameIDPolicy in
//     four formats, and identity-provider-initiated SSO;
//   * Single Logout both ways;
//   * THE NEGATIVE SET — a bad signature, a wrong Destination, a stale
//     IssueInstant and a replayed request ID — each of which must be
//     REFUSED: no assertion may reach the SP.
//
// A SCENARIO PASSES WHEN pysaml2 accepted (or, for a negative, never
// received) what it should, AND its own log gained no WARNING or worse while
// it ran — except the lines a scenario expects, which it names.
//
// ECP is not claimed by this service (PAOS is refused by name,
// saml/CLAUDE.md), so it is not exercised; #190 records that.
//
// `local: true`, `samlPeer: 'pysaml2'` (tests/vendored/MANIFEST.js).
// ===========================================================================

"use strict";

const { Command, Option } = require("commander");
const names = require("./random_username.js");
const kitFactory = require("./saml_peer_kit.js");

const kit = kitFactory.create("sts_saml_interop_pysaml2");
const log = kit.log;

const PEER = String(process.env.SAML_PEER_PYSAML2_URL || "")
  .replace(/\/+$/, "");
const STAMP = names.runStamp();
const PASSWORD = "Py-Passw0rd!-" + String(Date.now()).slice(-6);
const LOGS = ["pysaml2.log"];
const NAMEID = {
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  transient: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  email: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  unspecified: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
};

function isProblem(line) {
  log.debug("Entering isProblem().");
  log.debug("Leaving isProblem().");
  return /\s(WARNING|ERROR|CRITICAL)\s/.test(line);
}

async function peer(method, p, payload) {
  log.debug("Entering peer(). " + method + " " + p);
  const r = await fetch(PEER + p, {
    method: method,
    headers: payload ? { "content-type": "application/json" } : {},
    body: payload ? JSON.stringify(payload) : undefined });
  const text = await r.text();
  log.debug("Leaving peer(). " + r.status);
  return { status: r.status, text: text, body: kit.jsonOf(text) };
}

async function makeWorld(realmMode) {
  log.debug("Entering makeWorld(). " + realmMode);
  const tag = realmMode === "product" ? "p" : "d";
  const realm = ("py" + tag + "-" + STAMP).replace(/[^a-z0-9-]/g, "")
    .slice(0, 30);
  const rb = kit.realmBase(realm);
  const w = { mode: realmMode, realm: realm, rb: rb,
              person: names.usernameFor("py" + tag) };
  await kit.ensureRealm(realm, realmMode, {
    "saml2.entityId": rb + "/saml2/idp"
  });
  await kit.createPerson(realm, w.person, PASSWORD);
  const md = await peer("GET", "/metadata");
  w.sp = (/entityID="([^"]+)"/.exec(md.text) || [])[1];
  kit.must(md.status === 200 && w.sp, "the pysaml2 SP's metadata answered " +
           md.status);
  await kit.createApplication(realm, w.sp, ["saml2"], {});
  w.spMetadata = md.text;
  await kit.consumeMetadata(realm, w.sp, md.text);
  const m2 = await fetch(rb + "/saml2/metadata/" + encodeURIComponent(w.sp));
  const idpXml = await m2.text();
  kit.must(m2.status === 200, "the identity provider metadata answered " +
           m2.status);
  // THE ANCHOR STILL GOES WITH IT (#248). The metadata now publishes the
  // back channel's TLS certificate, but pysaml2's SOAP client verifies the
  // server with `requests` against a CA bundle (`ca_certs`) and reads no
  // metadata key for TLS, so for pysaml2 metadata cannot suffice.
  const configured = await peer("POST", "/configure", {
    idpMetadata: idpXml, caPem: await kit.stsAnchor() });
  kit.must(configured.status === 200 && configured.body &&
           configured.body.ok, "the pysaml2 peer would not take the " +
           "metadata: " + configured.text.slice(0, 400));
  w.idp = configured.body.idp;
  log.info("realm " + realm + " (" + realmMode + "): SP " + w.sp +
           ", identity provider " + w.idp);
  log.debug("Leaving makeWorld().");
  return w;
}

async function scenario(w, what, fn, allowed) {
  log.debug("Entering scenario(). " + what);
  log.info("=== " + w.mode + ": " + what + " ===");
  const watch = kit.logWatch("pysaml2", LOGS, isProblem);
  await fn();
  await kit.sleep(200);
  watch.since().forEach(function (l) {
    log.debug("pysaml2 log: " + l);
  });
  await kit.check(w.mode + ": " + what + " — pysaml2 logged no warning or " +
                  "error" + (allowed ? " but the expected one(s)" : ""),
                  async function () {
    const bad = watch.problems(allowed);
    kit.assert(!bad.length, bad.length + " line(s):\n    " +
               bad.join("\n    "));
  });
  log.debug("Leaving scenario().");
}

// One sign-in through the peer: /login with `query`, walked to the peer's
// answer (/acs) or wherever it stops, then the peer's own verdict.
async function signIn(w, b, query, opts) {
  log.debug("Entering signIn(). " + query);
  const walked = await kit.walk(b, PEER + "/login?" + query, Object.assign({
    username: w.person, password: PASSWORD,
    stopAt: function (u, r) {
      return u.indexOf(PEER + "/acs") === 0 && r.status !== 302;
    } }, opts || {}));
  const last = await peer("GET", "/last");
  log.debug("Leaving signIn().");
  return { walked: walked, outcome: last.body || {} };
}

function uidOf(outcome) {
  log.debug("Entering uidOf().");
  const a = outcome.attributes || {};
  log.debug("Leaving uidOf().");
  return ((a.uid || a["urn:oid:0.9.2342.19200300.100.1.1"] || [])[0]) || "";
}

function expectAccepted(w, s) {
  log.debug("Entering expectAccepted().");
  kit.assert(s.outcome.ok, "pysaml2 did not accept a Response: " +
             JSON.stringify(s.outcome).slice(0, 600) + "; the browser went " +
             kit.describeWalk(s.walked));
  kit.assert(s.outcome.issuer === w.idp, "the issuer is " + s.outcome.issuer);
  kit.assert(uidOf(s.outcome) === w.person, "the uid is not " + w.person +
             ": " + JSON.stringify(s.outcome.attributes));
  log.debug("Leaving expectAccepted().");
}

// A refusal: the service answered with a page of its own (4xx) or a Response
// whose status is not Success — and no assertion reached pysaml2.
function expectRefused(s) {
  log.debug("Entering expectRefused().");
  const resp = s.walked.captured.find(function (m) {
    return m.field === "SAMLResponse";
  });
  const status = s.walked.last ? s.walked.last.status : 0;
  kit.assert(!s.outcome.ok, "pysaml2 ACCEPTED an assertion: " +
             JSON.stringify(s.outcome).slice(0, 400));
  kit.assert((status >= 400 && status < 500 && !resp) ||
             (resp && !/StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"\/>/.test(resp.xml)),
             "the service did not refuse: " + kit.describeWalk(s.walked));
  log.debug("Leaving expectRefused().");
}

// ===========================================================================
// POSITIVE
// ===========================================================================
async function bindings(w) {
  log.debug("Entering bindings().");
  for (const c of [
    { what: "AuthnRequest on HTTP-Redirect, Response on HTTP-POST",
      q: "binding=redirect&response=post", how: "post" },
    { what: "AuthnRequest on HTTP-POST, Response on HTTP-POST",
      q: "binding=post&response=post", how: "post" },
    { what: "AuthnRequest on HTTP-Redirect, Response on HTTP-Artifact",
      q: "binding=redirect&response=artifact", how: "artifact" },
    { what: "AuthnRequest on HTTP-POST, Response on HTTP-Artifact",
      q: "binding=post&response=artifact", how: "artifact" }
  ]) {
    await scenario(w, c.what, async function () {
      const s = await signIn(w, kit.browser(), c.q);
      await kit.check(w.mode + ": " + c.what + " — pysaml2 accepted the " +
                      "Response, encrypted to its key", async function () {
        expectAccepted(w, s);
        kit.assert(s.outcome.how === c.how, "it came by " + s.outcome.how);
        // What travelled: the POSTed Response is in the walk; an artifact's
        // is not, and pysaml2 decrypted it or it would not have accepted it.
        const posted = s.walked.captured.find(function (m) {
          return m.field === "SAMLResponse";
        });
        kit.assert(!posted || /EncryptedAssertion/.test(posted.xml),
                   "the assertion was not encrypted");
      });
    });
  }
  log.debug("Leaving bindings().");
}

// An UNSIGNED AuthnRequest is refused in BOTH modes here, and that is the
// stronger check: pysaml2's metadata says AuthnRequestsSigned="true", which
// puts this service provider in the product column of
// `saml2.requireSignedAuthnRequests` whatever the realm's mode
// (saml/CLAUDE.md, *A service provider's signature*).
async function signing(w) {
  log.debug("Entering signing().");
  await scenario(w, "an UNSIGNED AuthnRequest from an SP whose metadata " +
                 "says it signs is refused", async function () {
    const s = await signIn(w, kit.browser(),
                           "binding=redirect&response=post&unsigned=1");
    await kit.check(w.mode + ": an unsigned AuthnRequest is refused (the " +
                    "SP's metadata says AuthnRequestsSigned)",
                    async function () {
      expectRefused(s);
    });
  });

  // AND AGAINST THE SETTING ITSELF: the same SP's metadata consumed with
  // AuthnRequestsSigned="false" — an operator's upload of what it says of
  // itself — so `saml2.requireSignedAuthnRequests` alone decides. `auto` is
  // on in product and off in development.
  const unsignedMetadata = w.spMetadata.replace(
    /AuthnRequestsSigned="true"/, 'AuthnRequestsSigned="false"');
  await kit.consumeMetadata(w.realm, w.sp, unsignedMetadata);
  for (const [value, refused] of [
    ["off", false], ["on", true],
    ["auto", w.mode === "product"]]) {
    await scenario(w, "saml2.requireSignedAuthnRequests=" + value + ": an " +
                   "unsigned AuthnRequest is " +
                   (refused ? "refused" : "accepted"), async function () {
      await kit.setting(w.realm, "saml2.requireSignedAuthnRequests", value);
      const s = await signIn(w, kit.browser(),
                             "binding=redirect&response=post&unsigned=1");
      await kit.check(w.mode + ": saml2.requireSignedAuthnRequests=" + value +
                      " — an unsigned AuthnRequest is " +
                      (refused ? "refused" : "accepted"), async function () {
        if (refused) {
          expectRefused(s);
        } else {
          expectAccepted(w, s);
        }
      });
    });
  }
  await kit.setting(w.realm, "saml2.requireSignedAuthnRequests", "auto");
  await kit.consumeMetadata(w.realm, w.sp, w.spMetadata);
  log.debug("Leaving signing().");
}

async function options(w) {
  log.debug("Entering options().");
  await scenario(w, "IsPassive with no session", async function () {
    const s = await signIn(w, kit.browser(),
                           "binding=redirect&response=post&isPassive=1",
                           { username: "" });
    await kit.check(w.mode + ": IsPassive with no session — a NoPassive " +
                    "Response and no sign-in screen", async function () {
      const resp = s.walked.captured.find(function (m) {
        return m.field === "SAMLResponse";
      });
      kit.assert(resp && /status:NoPassive/.test(resp.xml), "no NoPassive " +
                 "Response: " + kit.describeWalk(s.walked));
      kit.assert(!s.walked.trail.some(function (t) {
        return /\/authn\/login/.test(t);
      }), "the sign-in screen was shown");
      kit.assert(!s.outcome.ok, "pysaml2 accepted an assertion");
    });
  }, [/REFUSED \(post\): StatusNoPassive/, /SAML status error/]);

  await scenario(w, "IsPassive and ForceAuthn with a session",
                 async function () {
    const b = kit.browser();
    await signIn(w, b, "binding=redirect&response=post");
    const passive = await signIn(w, b, "binding=redirect&response=post&" +
                                 "isPassive=1", { username: "" });
    const forced = await signIn(w, b, "binding=redirect&response=post&" +
                                "forceAuthn=1");
    await kit.check(w.mode + ": IsPassive with a session is answered " +
                    "without the sign-in screen", async function () {
      expectAccepted(w, passive);
      kit.assert(!passive.walked.trail.some(function (t) {
        return /\/authn\/login/.test(t);
      }), "the sign-in screen was shown");
    });
    await kit.check(w.mode + ": ForceAuthn shows the sign-in screen again",
                    async function () {
      expectAccepted(w, forced);
      kit.assert(forced.walked.trail.some(function (t) {
        return /\/authn\/login/.test(t);
      }), "the sign-in screen was not shown");
    });
  });

  for (const [label, format] of Object.entries(NAMEID)) {
    await scenario(w, "NameIDPolicy " + label, async function () {
      const s = await signIn(w, kit.browser(), "binding=redirect&" +
                             "response=post&nameIdFormat=" +
                             encodeURIComponent(format));
      await kit.check(w.mode + ": NameIDPolicy " + label + " — the NameID " +
                      "is in that format", async function () {
        expectAccepted(w, s);
        kit.assert(s.outcome.nameIdFormat === format, "the format is " +
                   s.outcome.nameIdFormat);
      });
    });
  }
  log.debug("Leaving options().");
}

async function unsolicited(w) {
  log.debug("Entering unsolicited().");
  await scenario(w, "identity-provider-initiated SSO", async function () {
    const b = kit.browser();
    await peer("GET", "/reset");
    const url = w.rb + "/saml2/unsolicited/" + encodeURIComponent(w.sp) +
      "?shire=" + encodeURIComponent(PEER + "/acs");
    const walked = await kit.walk(b, url, {
      username: w.person, password: PASSWORD,
      stopAt: function (u, r) {
        return u.indexOf(PEER + "/acs") === 0 && r.status !== 302;
      } });
    const last = (await peer("GET", "/last")).body || {};
    await kit.check(w.mode + ": identity-provider-initiated SSO — pysaml2 " +
                    "accepted an unsolicited Response", async function () {
      expectAccepted(w, { walked: walked, outcome: last });
      kit.assert(!last.inResponseTo, "it carries InResponseTo " +
                 last.inResponseTo);
    });
  });
  log.debug("Leaving unsolicited().");
}

async function singleLogout(w) {
  log.debug("Entering singleLogout().");
  await scenario(w, "Single Logout, SP-initiated", async function () {
    const b = kit.browser();
    await signIn(w, b, "binding=redirect&response=post");
    const walked = await kit.walk(b, PEER + "/logout", {
      stopAt: function (u, r) {
        return u.indexOf(PEER + "/slo") === 0 && r.status !== 302;
      } });
    const last = (await peer("GET", "/last")).body || {};
    const again = await signIn(w, b, "binding=redirect&response=post",
                               { username: "" });
    await kit.check(w.mode + ": SP-initiated logout — pysaml2 received a " +
                    "Success LogoutResponse and this service's session " +
                    "ended", async function () {
      kit.assert(last.how === "logout-response" && last.ok,
                 "pysaml2's verdict: " + JSON.stringify(last) + "; " +
                 kit.describeWalk(walked));
      kit.assert(again.walked.trail.some(function (t) {
        return /\/authn\/login/.test(t);
      }), "a new sign-in was answered without the sign-in screen");
    });
  });

  await scenario(w, "Single Logout, identity-provider-initiated",
                 async function () {
    const b = kit.browser();
    await signIn(w, b, "binding=redirect&response=post");
    const page = await b.hop(w.rb + "/saml2/slo");
    const link = (/<a href="([^"]*SAMLRequest=[^"]*)"/.exec(page.body) ||
                  [])[1];
    let walked = null;
    if (link) {
      walked = await kit.walk(b, kit.htmlDecode(link), {});
    }
    const resp = walked && walked.captured.find(function (m) {
      return m.field === "SAMLResponse" && /LogoutResponse/.test(m.xml);
    });
    await kit.check(w.mode + ": identity-provider-initiated logout — " +
                    "pysaml2 ended its session and answered Success",
                    async function () {
      kit.assert(link, "the logout page names no LogoutRequest");
      kit.assert(resp && /status:Success"/.test(resp.xml),
                 "no Success LogoutResponse: " +
                 (walked ? kit.describeWalk(walked) : ""));
    });
  });
  log.debug("Leaving singleLogout().");
}

// ===========================================================================
// NEGATIVE
// ===========================================================================
async function negatives(w) {
  log.debug("Entering negatives().");
  for (const c of [
    { fault: "badsig", what: "an AuthnRequest whose signature does not " +
      "cover what arrived (the XML changed after signing)" },
    { fault: "destination", what: "an AuthnRequest whose Destination is " +
      "another identity provider's" },
    { fault: "stale", what: "an AuthnRequest issued an hour ago" }
  ]) {
    await scenario(w, "REFUSED: " + c.what, async function () {
      const s = await signIn(w, kit.browser(), "binding=redirect&" +
                             "response=post&fault=" + c.fault);
      await kit.check(w.mode + ": " + c.what + " is refused",
                      async function () {
        expectRefused(s);
      });
    });
  }
  await scenario(w, "REFUSED: a replayed AuthnRequest (an ID already " +
                 "answered)", async function () {
    const b = kit.browser();
    const first = await signIn(w, b, "binding=redirect&response=post");
    const again = await signIn(w, kit.browser(), "binding=redirect&" +
                               "response=post&fault=replay");
    await kit.check(w.mode + ": a replayed AuthnRequest is refused",
                    async function () {
      expectAccepted(w, first);
      expectRefused(again);
    });
  }, [/Response REFUSED/]);
  log.debug("Leaving negatives().");
}

async function test() {
  log.debug("Entering test().");
  kit.must(PEER, "SAML_PEER_PYSAML2_URL is not set: this job drives a " +
           "pysaml2 container the launcher starts under the saml-peers " +
           "compose profile (tests/CLAUDE.md, *The SAML peers*)");
  kit.must(kit.logDirReadable("pysaml2"), "the pysaml2 peer's log " +
           "directory " + kit.logDir("pysaml2") + " is not readable here");
  const only = String(process.env.SAML_PEER_SECTIONS || "").split(",")
    .filter(Boolean);
  const run = function (name) {
    log.debug("Entering run(). " + name);
    log.debug("Leaving run().");
    return !only.length || only.indexOf(name) >= 0;
  };
  for (const realmMode of ["development", "product"]) {
    const w = await makeWorld(realmMode);
    if (run("bindings")) {
      await bindings(w);
    }
    if (run("signing")) {
      await signing(w);
    }
    if (run("options")) {
      await options(w);
    }
    if (run("idp")) {
      await unsolicited(w);
    }
    if (run("slo")) {
      await singleLogout(w);
    }
    if (run("negatives")) {
      await negatives(w);
    }
  }
  log.debug("Leaving test().");
  return kit.finish(only.length ? 1 : 60);
}

const program = new Command();
program
  .name("sts_saml_interop_pysaml2")
  .description("pysaml2 as a scripted SAML 2.0 SP against this service " +
      "(#190), negative cases included, in a development and a product " +
      "realm, with pysaml2's own log as the error-and-warning source.")
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
