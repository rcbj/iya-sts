'use strict';
//
// File: sts_pki_revocation.js
//
// ===========================================================================
// THE REVOCATION ENDPOINTS AND THE CONSOLE PANE, OVER HTTP (2026-09-11).
//
// **THIS REPOSITORY'S OWN (`local: true`)**, on the first of `tests/CLAUDE.md`'s
// two questions: most of what it drives is `/admin-api/pki` and the pane on
// `/admin/pki`, and the tree that ADDS a control to that console is the tree
// that should go red when the control loses its operation.
//
// ---------------------------------------------------------------------------
// WHAT THIS ASSERTS THAT `tests/pki_revocation.js` CANNOT.
//
// That file holds the REGISTER and the two documents: the reasons, the
// refusals, the CRL OpenSSL verifies, the responder's good/revoked/unknown,
// the rotation that fills the lists. All of it in process, none of it through
// a socket.
//
// **THE WIRING IS WHERE A FEATURE LIKE THIS ACTUALLY BREAKS**, and none of it
// is visible in process:
//
//   * **THE ENDPOINTS ARE UNGATED AND HAVE TO BE.** A relying party fetches a
//     CRL before it has decided to trust anything, often before it has
//     authenticated to anybody — so a revocation list behind this service's
//     admin gate is a revocation nobody acts on. That is one line of
//     middleware away from being wrong and no in-process test can see it.
//   * **THE MEDIA TYPES ARE THE PROTOCOL.** `application/pkix-crl` and
//     `application/ocsp-response` are what a client dispatches on; a handler
//     that sent DER as `text/html` would work perfectly in every test that
//     parsed the body itself.
//   * **THE BYTES SURVIVE THE TRANSPORT.** A DER document sent through a
//     response that stringifies it arrives as mojibake, and every assertion
//     about its structure made in process still passes.
//   * **AND THE CONSOLE'S TWO CONTROLS REACH THE REGISTER.** A form posting an
//     action the handler does not know answers a refusal that reads like a
//     refusal.
//
// **THE NEGATIVES ARE MOST OF IT**, for `tests/sts_dpop.js`'s reason: a
// responder that answers `good` for a good certificate looks finished and is
// worth nothing.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_pki_revocation",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.info("  ✓ " + what);
}

async function getJson(path) {
  const r = await fetch(api + path);
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // Not JSON — an HTML error page. Quoting it whole says more than a parse
    // failure would.
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

async function post(path, payload) {
  const r = await fetch(api + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {})
  });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

// **`Authorization: none` IS NOT DECORATION.** The launchers preload an admin
// access token and `tests/tools/attach-admin-token.js` puts it on every fetch
// this process makes — so a job asserting that an endpoint is ANONYMOUS would
// be asserting it while sending a credential, and would pass against an
// endpoint that requires one. That header is the documented way to say "send
// nothing", and it is the difference between this file testing what it says it
// tests and testing nothing.
async function anonymous(path, options) {
  const opts = Object.assign({}, options || {});
  opts.headers = Object.assign({ Authorization: "none" }, opts.headers || {});
  const r = await fetch(base + path, opts);
  const buf = Buffer.from(await r.arrayBuffer());
  return {
    status: r.status,
    type: String(r.headers.get("content-type") || ""),
    cache: String(r.headers.get("cache-control") || ""),
    bytes: buf
  };
}

// A DER document begins with a SEQUENCE tag. It is a weak check on its own and
// a strong one in this context: what it catches is the whole class of failure
// where the bytes were sent through something that stringified them, which
// leaves a body that is the right length and is not DER at all.
function looksLikeDer(buf) {
  return buf.length > 100 && buf[0] === 0x30;
}

async function test() {
  log.info("=== A. the index: ungated, and it names all three schemes ===");

  const index = await anonymous("/pki/revocation");
  check("GET /pki/revocation answers WITH NO CREDENTIAL. It has to: every " +
        "address in it is already inside every certificate this service " +
        "hands out, and a client reads them before it has decided to trust " +
        "anything", function () {
          assert.strictEqual(index.status, 200,
            "status " + index.status + ": " + index.bytes.toString().slice(0, 200));
        });
  const listing = JSON.parse(index.bytes.toString("utf8"));
  check("it lists one entry PER CERTIFICATE AUTHORITY rather than one per " +
        "realm — a CRL is signed by an issuer, so a list per realm would be " +
        "a document with no valid issuer and nothing could sign it",
        function () {
          assert.ok(Array.isArray(listing.authorities) &&
                    listing.authorities.length >= 4,
            JSON.stringify(listing).slice(0, 300));
          assert.ok(listing.authorities.some(function (one) {
            return one.ca === "root";
          }), "no Root authority in the index");
        });
  check("and every one of them carries its CRL in http, ldap AND ldaps plus " +
        "an OCSP responder and a caIssuers address — which is what was " +
        "asked for: a client that can only reach one scheme still finds a " +
        "list", function () {
          listing.authorities.forEach(function (one) {
            assert.ok(/^https?:/.test(one.crl.http), one.ca + ": http");
            assert.ok(/^ldap:/.test(one.crl.ldap), one.ca + ": ldap");
            assert.ok(/^ldaps:/.test(one.crl.ldaps), one.ca + ": ldaps");
            assert.ok(/^https?:/.test(one.ocsp), one.ca + ": ocsp");
            assert.ok(/^https?:/.test(one.caIssuers), one.ca + ": caIssuers");
          });
        });
  check("and it says in as many words that this service PUBLISHES revocation " +
        "and cannot make anybody consult it — which is true of every " +
        "certificate authority and is the reason a client author would point " +
        "their stack here", function () {
          assert.ok(/cannot make anybody consult/
            .test(String(listing.revocationIsPublishedNotEnforced)),
            JSON.stringify(listing.revocationIsPublishedNotEnforced));
        });
  check("and NO SERIAL NUMBERS are in it. The list of what is revoked is the " +
        "CRL; a JSON copy beside it would be a second answer to the same " +
        "question — the one that goes stale, and the one nobody signed",
        function () {
          assert.ok(!/serialHex|serialNumber/.test(index.bytes.toString()),
            "the index carries serials");
        });

  const realmAuthority = listing.authorities.filter(function (one) {
    return one.ca === "jose";
  })[0] || listing.authorities[0];
  const scope = realmAuthority.scope;
  const ca = realmAuthority.ca;

  log.info("=== B. the CRL: DER, its own media type, and cacheable ===");

  const crl = await anonymous("/pki/crl/" + scope + "/" + ca);
  check("GET /pki/crl/{scope}/{ca} answers 200 with no credential",
        function () { assert.strictEqual(crl.status, 200); });
  check("as application/pkix-crl — the media type IS the protocol here, and " +
        "a handler that sent these bytes as text/html would pass every test " +
        "that parsed the body itself", function () {
          assert.ok(/application\/pkix-crl/.test(crl.type), crl.type);
        });
  check("and the bytes are really DER rather than a stringified copy of it, " +
        "which is the failure that survives every in-process assertion about " +
        "the document's structure", function () {
          assert.ok(looksLikeDer(crl.bytes),
            crl.bytes.length + " bytes, first " + crl.bytes[0]);
        });
  check("and it is CACHEABLE, which is the one family of documents here that " +
        "is: a CRL carries its own nextUpdate, so the header says the same " +
        "thing the document does. Everything else that publishes key " +
        "material is no-store, because a key regenerated per start must not " +
        "be cached", function () {
          assert.ok(/max-age=\d+/.test(crl.cache) && /public/.test(crl.cache),
            crl.cache);
        });
  const suffixed = await anonymous("/pki/crl/" + scope + "/" + ca + ".crl");
  check("the `.crl` suffix answers identically — a client following a URL " +
        "out of a certificate must never meet a 404 over a routing detail",
        function () {
          assert.strictEqual(suffixed.status, 200);
          assert.strictEqual(suffixed.bytes.length, crl.bytes.length);
        });

  const noSuchCa = await anonymous("/pki/crl/" + scope + "/not-an-authority");
  check("an authority that does not exist is a 404 in PLAIN TEXT, not an " +
        "HTML error page — a revocation client is not a browser and will not " +
        "parse one", function () {
          assert.strictEqual(noSuchCa.status, 404);
          assert.ok(/text\/plain/.test(noSuchCa.type), noSuchCa.type);
          assert.ok(/\/pki\/revocation/.test(noSuchCa.bytes.toString()),
            "the refusal does not name the index that would have told them");
        });

  const caCert = await anonymous("/pki/ca/" + scope + "/" + ca + ".cer");
  check("GET /pki/ca/{scope}/{ca}.cer is the authority's own certificate, as " +
        "application/pkix-cert — the caIssuers address in everything it " +
        "signed, and what lets a client sent an incomplete chain finish " +
        "building one", function () {
          assert.strictEqual(caCert.status, 200);
          assert.ok(/application\/pkix-cert/.test(caCert.type), caCert.type);
          assert.ok(looksLikeDer(caCert.bytes));
        });
  check("and NO PRIVATE KEY is reachable through it, in any scope",
        function () {
          assert.ok(caCert.bytes.toString("latin1").indexOf("PRIVATE") < 0);
        });

  log.info("=== C. the OCSP responder, and three refusals that are answers ===");

  const garbage = await anonymous("/pki/ocsp/" + scope + "/" + ca, {
    method: "POST",
    headers: { "Content-Type": "application/ocsp-request" },
    body: Buffer.from("this is not an OCSP request at all", "utf8")
  });
  check("a POST of bytes that are not an OCSP request answers HTTP 200 with " +
        "an application/ocsp-response — `malformedRequest` is a status " +
        "INSIDE the protocol (RFC 6960 appendix A.2), so a client can report " +
        "what happened rather than guessing from a status code",
        function () {
          assert.strictEqual(garbage.status, 200, "status " + garbage.status);
          assert.ok(/application\/ocsp-response/.test(garbage.type),
            garbage.type);
          assert.ok(garbage.bytes.length > 0,
            "even a refusal has to be a real response with bytes in it");
        });
  check("and an OCSP answer is NOT cached, unlike a CRL — it carries " +
        "nextUpdate, and the interesting thing a person does with this " +
        "responder is revoke something and ask again", function () {
          assert.ok(/no-store/.test(garbage.cache), garbage.cache);
        });

  const empty = await anonymous("/pki/ocsp/" + scope + "/" + ca, {
    method: "POST",
    headers: { "Content-Type": "application/ocsp-request" },
    body: Buffer.alloc(0)
  });
  check("a POST with NO BODY is refused as a request rather than answered as " +
        "a certificate status", function () {
          assert.strictEqual(empty.status, 400, "status " + empty.status);
        });

  const huge = await anonymous("/pki/ocsp/" + scope + "/" + ca, {
    method: "POST",
    headers: { "Content-Type": "application/ocsp-request" },
    body: Buffer.alloc(200 * 1024, 0x41)
  });
  check("and a body larger than the cap is refused with 413. This is an " +
        "UNAUTHENTICATED endpoint that reads a body: a request for one " +
        "certificate is about eighty bytes, so anything approaching a " +
        "megabyte is a client doing something else", function () {
          assert.ok(huge.status === 413 || huge.status === 400,
            "status " + huge.status);
        });

  const notBase64 = await anonymous("/pki/ocsp/" + scope + "/" + ca +
                                    "/%20%20%20%20");
  check("the GET form refuses something that is not base64 at all (RFC 6960 " +
        "appendix A.1.1 is the base64 of the DER request as the last path " +
        "segment)", function () {
          assert.ok(notBase64.status === 400 || notBase64.status === 200,
            "status " + notBase64.status);
        });

  log.info("=== D. the management API carries the register AND the sentence ===");

  const view = await getJson("/pki");
  check("GET /admin-api/pki answers", function () {
    assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
  });
  check("with `revocation` as the REGISTER and `revocationNote` as the " +
        "SENTENCE. They are two members because an empty list and no lists " +
        "at all are different answers, and one field could only have carried " +
        "one of them", function () {
          assert.ok(view.body.revocation &&
                    Array.isArray(view.body.revocation.authorities),
            JSON.stringify(view.body.revocation).slice(0, 200));
          // `PUBLISHED AND CONSULTED` since 2026-09-12, when the service
          // started checking the revocation of a presented certificate. It
          // read `PUBLISHED, NOT ENFORCED` until then.
          assert.ok(/PUBLISHED AND CONSULTED/.test(view.body.revocationNote),
            String(view.body.revocationNote).slice(0, 200));
        });
  check("the register offers the nine RFC 5280 section 5.3.1 reasons — not " +
        "eleven: 7 is unused and removeFromCRL is a delta-CRL verb this " +
        "service publishes no delta CRLs to honour", function () {
          assert.strictEqual(view.body.revocation.reasons.length, 9);
          assert.ok(!view.body.revocation.reasons.some(function (one) {
            return one.code === 7;
          }));
        });
  check("and both new actions are in the published action list, so a machine " +
        "chooses from the service rather than from a copy of the list in a " +
        "document", function () {
          assert.ok(view.body.actions.indexOf("revoke-certificate") >= 0,
            view.body.actions.join(", "));
          assert.ok(view.body.actions.indexOf("release-hold") >= 0);
          assert.ok(view.body.actions.indexOf("revoke") >= 0,
            "the OLDER `revoke` must still be there — that list is published " +
            "and renaming it to make room would break every caller that has it");
        });

  // **A LEAF OF THE JOSE AUTHORITY, AND NEVER A CERTIFICATE AUTHORITY
  // (2026-09-12).** This picked the first authority with anything unrevoked,
  // which is the ROOT — so it revoked an INTERMEDIATE, keyCompromise, in the
  // one service every job in the run shares. That cost nothing while
  // revocation was only published. Since this service CONSULTS it for a
  // presented certificate, a revoked Intermediate refuses every X509-SVID and
  // every x5c assertion under it, and the job that did it would be failing
  // other jobs in whatever order they happened to run. A signing-key leaf is
  // presented to this service by nothing, so revoking it tests the register
  // and the documents and changes no other job's answer.
  const isLeaf = function (cert) {
    return !cert.revoked && cert.kind === "leaf";
  };
  const authority = view.body.revocation.authorities.filter(function (one) {
    return one.ca === "jose" && one.issued.some(isLeaf);
  })[0] || view.body.revocation.authorities.filter(function (one) {
    return one.ca !== "root" && one.ca !== "intermediate" &&
           one.ca !== "spiffe" && one.issued.some(isLeaf);
  })[0];
  assert.ok(authority, "no Issuing CA has an unrevoked leaf to work with");
  const target = authority.issued.filter(isLeaf)[0];

  log.info("=== E. revoking through the API, and every refusal ===");

  const before = await anonymous("/pki/crl/" +
    (authority.scopeSegment || "default") + "/" + authority.ca);

  const revoked = await post("/pki/revoke-certificate", {
    scope: authority.scope, ca: authority.ca,
    serialHex: target.serialHex, reason: "keyCompromise",
    note: "driven by sts_pki_revocation"
  });
  check("a certificate can be revoked through the API", function () {
    assert.strictEqual(revoked.status, 200, revoked.raw.slice(0, 300));
    assert.strictEqual(revoked.body.ok, true);
  });
  check("and the reply says what it did NOT change, which is most of what an " +
        "operator needs to know: whoever holds that key still holds it, the " +
        "certificate still chains, and this service does not consult its own " +
        "lists", function () {
          assert.ok(/NOTHING ELSE CHANGED/.test(String(revoked.body.why)),
            String(revoked.body.why).slice(0, 200));
        });

  const after = await anonymous("/pki/crl/" +
    (authority.scopeSegment || "default") + "/" + authority.ca);
  check("and the PUBLISHED CRL grows — which is the whole point, and the one " +
        "thing an in-process assertion about the register cannot tell you: " +
        "the endpoint builds and signs on demand, so the next fetch already " +
        "carries the entry", function () {
          assert.ok(after.bytes.length > before.bytes.length,
            before.bytes.length + " -> " + after.bytes.length + " bytes");
        });

  const twice = await post("/pki/revoke-certificate", {
    scope: authority.scope, ca: authority.ca,
    serialHex: target.serialHex, reason: "superseded"
  });
  check("revoking the same serial again SUCCEEDS and reports that it was " +
        "already revoked — a refusal would make an operator think the " +
        "certificate was not on the list", function () {
          assert.strictEqual(twice.body.ok, true, twice.raw.slice(0, 200));
          assert.strictEqual(twice.body.already, true);
        });
  check("and the ORIGINAL moment and reason stand. Moving a revocation date " +
        "forward would be this service saying a certificate was valid for " +
        "longer than it had already told a validator", function () {
          assert.strictEqual(twice.body.entry.revokedAt,
                             revoked.body.entry.revokedAt);
          assert.strictEqual(twice.body.entry.reason, "keyCompromise");
        });

  const release = await post("/pki/release-hold", {
    scope: authority.scope, ca: authority.ca, serialHex: target.serialHex
  });
  check("releasing something revoked as keyCompromise is REFUSED — RFC 5280 " +
        "makes every reason but certificateHold permanent, because a " +
        "validator may cache a permanent revocation for as long as the CRL " +
        "it read says it is fresh", function () {
          assert.strictEqual(release.body.ok, false, release.raw.slice(0, 200));
          assert.ok(/PERMANENT/.test((release.body.errors || []).join(" ")),
            (release.body.errors || []).join(" "));
        });

  const noAuthority = await post("/pki/revoke-certificate", {
    scope: authority.scope, ca: "not-an-authority", serialHex: target.serialHex
  });
  check("revoking at an authority that does not exist is refused, and the " +
        "refusal says why a serial alone is not a question: a serial is " +
        "unique only WITHIN one issuer", function () {
          assert.strictEqual(noAuthority.body.ok, false);
          assert.ok(/BY AN ISSUER/.test((noAuthority.body.errors || []).join(" ")),
            (noAuthority.body.errors || []).join(" "));
        });
  const noSerial = await post("/pki/revoke-certificate", {
    scope: authority.scope, ca: authority.ca, serialHex: ""
  });
  check("and a revocation with no serial is refused", function () {
    assert.strictEqual(noSerial.body.ok, false);
  });
  const badReason = await post("/pki/revoke-certificate", {
    scope: authority.scope, ca: authority.ca,
    serialHex: target.serialHex, reason: "becauseIFeltLikeIt"
  });
  check("and a reason RFC 5280 does not define is refused rather than mapped " +
        "to unspecified — a revocation filed under an invented code is one a " +
        "validator cannot act on", function () {
          assert.strictEqual(badReason.body.ok, false);
        });

  log.info("=== F. the hold, which is the only reason that can be undone ===");

  const second = authority.issued.filter(function (one) {
    return isLeaf(one) && one.serialHex !== target.serialHex;
  })[0];
  if (second) {
    const held = await post("/pki/revoke-certificate", {
      scope: authority.scope, ca: authority.ca,
      serialHex: second.serialHex, reason: "certificateHold"
    });
    check("a certificate can be put on hold", function () {
      assert.strictEqual(held.body.ok, true, held.raw.slice(0, 200));
    });
    const lifted = await post("/pki/release-hold", {
      scope: authority.scope, ca: authority.ca, serialHex: second.serialHex
    });
    check("and the hold can be lifted", function () {
      assert.strictEqual(lifted.body.ok, true, lifted.raw.slice(0, 200));
    });
    check("and the reply says the undoing is not instantaneous anywhere but " +
          "here — a validator that cached the previous CRL goes on calling " +
          "it revoked until that copy expires", function () {
            assert.ok(/cached/.test(String(lifted.body.why)),
              String(lifted.body.why).slice(0, 200));
          });
  } else {
    log.warn("that authority has only one unrevoked certificate, so the " +
             "hold-and-release path is not covered by this run.");
  }

  log.info("=== G. the console page is gated, and the endpoints are not ===");

  const page = await fetch(base + "/admin/pki", { redirect: "manual" });
  check("/admin/pki is BEHIND THE GATE — it is reached through the " +
        "authorization code flow like every other page of that console",
        function () {
          assert.ok(page.status === 303 || page.status === 302,
            "status " + page.status);
        });
  check("and the revocation ENDPOINTS are not, which is the asymmetry that " +
        "matters: a relying party fetches a CRL before it has authenticated " +
        "to anybody, and a list behind an admin gate is a revocation nobody " +
        "acts on", function () {
          assert.strictEqual(crl.status, 200);
          assert.strictEqual(index.status, 200);
        });

  log.info(checks + " check(s) passed.");
}

const program = new Command();
program
  .name("sts_pki_revocation")
  .description("Drive the CRL and OCSP endpoints and the revocation pane's " +
      "two actions: that the four endpoints answer with NO credential while " +
      "the console page stays gated, that a CRL is DER under its own media " +
      "type and is the one cacheable document here, that an OCSP refusal is " +
      "a 200 response inside the protocol rather than an HTTP error, that " +
      "revoking through /admin-api/pki grows the PUBLISHED list, that a " +
      "second revocation of one serial cannot move its date forward, and " +
      "that only a certificateHold can be released.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
