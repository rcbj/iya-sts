// ===========================================================================
// EVERY XML DOCUMENT THIS SERVICE EMITS IN FOUR FAMILIES, AGAINST THE
// PUBLISHED SCHEMAS (#188).
//
// OASIS publishes the XML Schemas for SAML 2.0 and SAML 1.1, WS-Trust (from
// the 2004/04 and 2005/02 member submissions through 1.3 and 1.4),
// WS-Security and WS-Federation 1.2, and the W3C the XML Signature, XML
// Encryption, SOAP 1.2 and WS-Addressing schemas beneath them. They are the
// one OFFICIAL machine check of those documents there is — OASIS publishes
// conformance requirements and no tool — and until this job nothing here
// validated a single emitted message against them.
//
// ---------------------------------------------------------------------------
// HOW
//
// The schemas are FETCHED when the tests image is built, each pinned by its
// sha256 (tests/xml-schemas/SCHEMAS, tests/tools/fetch-xml-schemas.sh), and
// this job validates with libxml2's own `xmllint --nonet` against
// tests/xml-schemas/all.xsd — one schema importing every published one —
// through the catalogue beside it. Nothing is fetched while the suite runs.
//
// A document is VALID here when all three hold, and each is a check:
//
//   1. xmllint says it validates, with no error and no warning about the
//      DOCUMENT (the schema set's own "Skipping import" notes are about the
//      schemas, identical for every document, and are set aside by name);
//   2. every namespace an element or attribute of it uses is one all.xsd
//      imports (`covered()`) — because the containers of these formats hold
//      their content through wildcards with processContents="lax", which
//      validate an element strictly when its namespace is loaded and SKIP it
//      silently when it is not; and
//   3. every element's local name is declared somewhere in the schema of its
//      namespace (`declared()`) — the same hole one level down: a lax
//      wildcard skips an element its namespace does not declare, so a
//      misspelled element inside a RequestedSecurityToken would pass (1).
//
// ---------------------------------------------------------------------------
// WHAT IS EMITTED, AND BY WHOM — in TWO throwaway realms, one in development
// mode and one in product mode (a realm's `global.mode` is its own), because
// the documents differ between them: product refuses what development
// answers, and a refusal is a document too.
//
//   SAML 2.0    the identity provider's metadata, unscoped and per service
//               provider; the Response on HTTP-POST, HTTP-Redirect,
//               POST-SimpleSign and HTTP-Artifact, signed, and with an
//               EncryptedAssertion to a service provider that registered an
//               encryption certificate; the ArtifactResponse over SOAP; an
//               error Response (IsPassive with no session); the
//               LogoutResponse to a service provider's LogoutRequest and the
//               LogoutRequests of identity-provider-initiated logout. The
//               service providers are THIS FILE — requests signed with a key
//               made for the run.
//   SAML 1.1    the metadata; the Browser/POST Response; the SOAP responder's
//               answer to an artifact, an AssertionIDReference, an
//               AttributeQuery and an AuthenticationQuery (the
//               attribute-authority answers; refusals in product), and its
//               refusals.
//   WS-Trust    Issue, Renew, Validate and Cancel in the 2004/04, 2005/02 and
//               1.3 namespaces over SOAP 1.1 and 1.2, a SAML 2.0 assertion and
//               a JWT, an encrypted assertion, 1.4's ActAs and OnBehalfOf,
//               and the SOAP faults.
//   WS-Fed      the federation metadata and the sign-in response, SAML 1.1 and
//               SAML 2.0 tokens in 2005/02 and 1.3 wrappers.
//   federation  a third realm federating to the first: its SAML 2.0 and
//               WS-Federation relationship metadata, its outbound
//               AuthnRequest on HTTP-Redirect and HTTP-POST, and its outbound
//               LogoutRequest when the person signs out.
//
// Every document is validated whether or not it is the one a check expected,
// and a scenario that yields NO document fails: a flow that silently stopped
// producing its message would otherwise take its coverage with it.
//
// `local: true`: this repository's own documents, and a new document type is
// owed a scenario here in the change that adds it.
// ===========================================================================

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const nodeCrypto = require("crypto");
const { spawnSync } = require("child_process");
const { Command, Option } = require("commander");
const { DOMParser } = require("@xmldom/xmldom");
const { SignedXml } = require("xml-crypto");
const forge = require("node-forge");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_xml_schema_validation",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// Where tests/tools/fetch-xml-schemas.sh put the schemas. The tests image
// builds them into /opt/xml-schemas; a hand run points this at its own copy.
const SCHEMA_DIR = process.env.STS_XML_SCHEMA_DIR || "/opt/xml-schemas";

const STAMP = names.runStamp();
const PASSWORD = "Schema-Passw0rd!-" + String(Date.now()).slice(-6);
const NS = {
  saml: "urn:oasis:names:tc:SAML:2.0:assertion",
  samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
  saml1: "urn:oasis:names:tc:SAML:1.0:assertion",
  samlp1: "urn:oasis:names:tc:SAML:1.0:protocol",
  soap11: "http://schemas.xmlsoap.org/soap/envelope/",
  soap12: "http://www.w3.org/2003/05/soap-envelope",
  wsse: "http://docs.oasis-open.org/wss/2004/01/" +
        "oasis-200401-wss-wssecurity-secext-1.0.xsd",
  wsp: "http://schemas.xmlsoap.org/ws/2004/09/policy",
  wsa: "http://www.w3.org/2005/08/addressing",
  wst13: "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
  wst14: "http://docs.oasis-open.org/ws-sx/ws-trust/200802",
  wst0502: "http://schemas.xmlsoap.org/ws/2005/02/trust",
  wst0404: "http://schemas.xmlsoap.org/ws/2004/04/trust"
};
const BINDING = {
  post: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
  redirect: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
  artifact: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
  simpleSign: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
};
const SIG_ALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

let checks = 0;
const failures = [];
// Every document validated, for the summary: what, where from, verdict.
const validated = [];

// ---------------------------------------------------------------------------
// ONE CHECK. A failure is recorded and the run carries on; setup that later
// sections depend on uses `must()` instead, which throws.
// ---------------------------------------------------------------------------
async function check(what, fn) {
  log.debug("Entering check(). " + what);
  try {
    await fn();
    checks += 1;
    log.info("  ✓ " + what);
  } catch (e) {
    log.debug("Caught in check(): " + ((e && e.message) || e));
    failures.push(what + " — " + ((e && e.message) || e));
    log.error("  ✗ " + what + "  — " + ((e && e.message) || e));
  }
  log.debug("Leaving check().");
}

function must(condition, message) {
  log.debug("Entering must().");
  if (!condition) {
    log.debug("Leaving must(). Refused.");
    throw new Error("SETUP: " + message);
  }
  log.debug("Leaving must().");
}

function squash(text) {
  log.debug("Entering squash().");
  log.debug("Leaving squash().");
  return String(text || "").replace(/<style[\s\S]*?<\/style>/g, " ")
    .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 300);
}

function htmlDecode(text) {
  log.debug("Entering htmlDecode().");
  log.debug("Leaving htmlDecode().");
  return String(text || "").replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function realmBase(realm) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + realm;
}

// ===========================================================================
// THE VALIDATOR
// ===========================================================================

// What all.xsd imports, and every element name each of those namespaces
// declares — read once from the fetched files themselves, so the two
// coverage checks can never disagree with the schema xmllint compiled.
let schemaIndex = null;

function schemaIndexOf() {
  log.debug("Entering schemaIndexOf().");
  if (schemaIndex) {
    log.debug("Leaving schemaIndexOf(). Cached.");
    return schemaIndex;
  }
  const XS = "http://www.w3.org/2001/XMLSchema";
  const parse = function (file) {
    log.debug("Entering parse(). " + file);
    // The DOCTYPE (xmldsig-core-schema.xsd has one naming XMLSchema.dtd)
    // and the XML declaration are dropped: xmldom reads neither, and a
    // declaration after a byte-order mark is a fatal error to it.
    const text = fs.readFileSync(path.resolve(SCHEMA_DIR, file), "utf8")
      .replace(/^\uFEFF/, "").replace(/^\s*<\?xml[^>]*\?>/, "")
      .replace(/<!DOCTYPE[\s\S]*?\]>/, "").replace(/<!DOCTYPE[^>]*>/, "");
    log.debug("Leaving parse().");
    return new DOMParser().parseFromString(text, "text/xml");
  };
  const driver = parse(driverPath);
  const imports = Array.from(driver.getElementsByTagNameNS(XS, "import"));
  const declaredIn = {};
  const seenFiles = {};
  // Every file a namespace's schema is made of: the one all.xsd names and
  // whatever it xs:includes. None of the published set uses xs:include
  // today; reading it anyway costs nothing and keeps the index honest if a
  // file is ever added that does.
  const collect = function (ns, file) {
    log.debug("Entering collect(). " + file);
    if (seenFiles[file]) {
      log.debug("Leaving collect(). Seen.");
      return;
    }
    seenFiles[file] = true;
    const doc = parse(file);
    const names = declaredIn[ns] || (declaredIn[ns] = {});
    Array.from(doc.getElementsByTagNameNS(XS, "element")).forEach(
      function (el) {
        if (el.getAttribute("name")) {
          names[el.getAttribute("name")] = true;
        }
      });
    Array.from(doc.getElementsByTagNameNS(XS, "include")).forEach(
      function (inc) {
        collect(ns, inc.getAttribute("schemaLocation"));
      });
    log.debug("Leaving collect().");
  };
  imports.forEach(function (imp) {
    collect(imp.getAttribute("namespace"), imp.getAttribute("schemaLocation"));
  });
  schemaIndex = { namespaces: Object.keys(declaredIn), declaredIn: declaredIn };
  log.debug("Leaving schemaIndexOf(). " + schemaIndex.namespaces.length +
            " namespaces.");
  return schemaIndex;
}

// Namespaces a document may use without a schema: the namespace declarations
// themselves, the xml: prefix's (xml.xsd is imported anyway), and
// XMLSchema-instance, whose four attributes every validator knows natively.
const EXEMPT_NAMESPACES = ["http://www.w3.org/2000/xmlns/",
                           "http://www.w3.org/2001/XMLSchema-instance"];

// Checks 2 and 3 of the header. Answers a list of problems, empty when none.
function coverageProblems(xml) {
  log.debug("Entering coverageProblems().");
  const index = schemaIndexOf();
  const problems = [];
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  // No Entering/Leaving pair in walk(): it is called once for every node of
  // every document, and the pair would drown the log.
  const walk = function (node) {
    if (node.nodeType !== 1) {
      return;
    }
    const ns = node.namespaceURI || "";
    // AN UNQUALIFIED ELEMENT is a LOCAL declaration of its parent's type —
    // SOAP 1.1's faultcode and faultstring are the ones emitted here — so it
    // is looked for in the parent's namespace.
    const parentNs = (node.parentNode && node.parentNode.namespaceURI) || "";
    if (!ns && index.declaredIn[parentNs] &&
        index.declaredIn[parentNs][node.localName]) {
      Array.from(node.childNodes || []).forEach(walk);
      return;
    }
    if (index.namespaces.indexOf(ns) < 0) {
      problems.push("element {" + ns + "}" + node.localName + " is in a " +
                    "namespace no published schema loaded here covers");
    } else if (!index.declaredIn[ns][node.localName]) {
      problems.push("element {" + ns + "}" + node.localName + " is declared " +
                    "nowhere in that namespace's schema");
    }
    Array.from(node.attributes || []).forEach(function (a) {
      const ans = a.namespaceURI || "";
      if (ans && EXEMPT_NAMESPACES.indexOf(ans) < 0 &&
          index.namespaces.indexOf(ans) < 0) {
        problems.push("attribute {" + ans + "}" + a.localName + " on " +
                      node.localName + " is in a namespace no published " +
                      "schema loaded here covers");
      }
    });
    Array.from(node.childNodes || []).forEach(walk);
  };
  walk(doc.documentElement);
  log.debug("Leaving coverageProblems(). " + problems.length);
  return Array.from(new Set(problems));
}

let docCounter = 0;
const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "sts-xsd-"));

// ---------------------------------------------------------------------------
// THE DRIVER THIS RUN VALIDATES WITH: all.xsd, with its schemaLocations made
// absolute, plus ONE schema that is not a published standard's — this
// service's own `urn:iya:sts:crypto-metadata:1`, served at
// /crypto/metadata.xsd. The SAML 2.0 metadata carries an element of that
// namespace in its md:Extensions (#42), which the metadata schema admits
// through a lax wildcard; loading the service's own schema for it is what
// makes that element CHECKED rather than skipped. It is read from the
// service under test, so it is the schema that service stands behind.
// ---------------------------------------------------------------------------
let driverPath = "";

async function prepareDriver() {
  log.debug("Entering prepareDriver().");
  const own = await fetch(base + "/crypto/metadata.xsd");
  const ownText = await own.text();
  must(own.status === 200 && /targetNamespace="urn:iya:sts:crypto-metadata:1"/
         .test(ownText),
       "GET /crypto/metadata.xsd answered " + own.status);
  fs.writeFileSync(path.join(workDir, "crypto-metadata.xsd"), ownText);
  const driver = fs.readFileSync(path.join(SCHEMA_DIR, "all.xsd"), "utf8")
    .replace(/schemaLocation="([^"]+)"/g, function (all, file) {
      return "schemaLocation=\"" + path.join(SCHEMA_DIR, file) + "\"";
    })
    .replace("</xs:schema>",
             "  <xs:import namespace=\"urn:iya:sts:crypto-metadata:1\"\n" +
             "             schemaLocation=\"" +
             path.join(workDir, "crypto-metadata.xsd") + "\"/>\n" +
             "</xs:schema>");
  driverPath = path.join(workDir, "all.xsd");
  fs.writeFileSync(driverPath, driver);
  log.debug("Leaving prepareDriver().");
}

// xmllint, against all.xsd, with nothing fetched. Answers { ok, errors }.
function xmllint(xml) {
  log.debug("Entering xmllint().");
  docCounter += 1;
  const file = path.join(workDir, "doc-" + docCounter + ".xml");
  fs.writeFileSync(file, xml);
  const run = spawnSync("xmllint",
    ["--nonet", "--noout", "--schema", driverPath, file],
    { encoding: "utf8",
      env: Object.assign({}, process.env,
                         { XML_CATALOG_FILES: path.join(SCHEMA_DIR,
                                                        "catalog.xml") }) });
  if (run.error) {
    log.debug("Leaving xmllint(). It did not run.");
    throw new Error("xmllint did not run (" + run.error.message + "). It " +
                    "is libxml2-utils, installed in tests/Dockerfile.");
  }
  // THE SCHEMA SET'S OWN NOTES, identical for every document: all.xsd
  // imports each namespace first, so every published file's own import of
  // it is skipped, and libxml2 says so. Anything else — an error or a
  // warning about the document — is kept.
  const lines = String(run.stderr || "").split("\n").filter(function (l) {
    return l.trim() && !/Skipping import of schema located at/.test(l) &&
           l.trim() !== file + " validates" &&
           l.trim() !== file + " fails to validate";
  }).map(function (l) {
    return l.split(file).join("doc");
  });
  const ok = run.status === 0 && lines.length === 0;
  log.debug("Leaving xmllint(). ok=" + ok);
  return { ok: ok, errors: lines, status: run.status };
}

// Validate one emitted document: a check of its own, named for what it is
// and where it came from.
async function validate(what, xml, from) {
  log.debug("Entering validate(). " + what);
  await check("schema-valid: " + what + (from ? "  [" + from + "]" : ""),
              async function () {
    if (!xml || !/</.test(xml)) {
      throw new Error("no document was captured");
    }
    const lint = xmllint(xml);
    const coverage = coverageProblems(xml);
    validated.push({ what: what, from: from || "",
                     ok: lint.ok && coverage.length === 0 });
    if (!lint.ok || coverage.length) {
      throw new Error(lint.errors.concat(coverage).join(" | ").slice(0, 2000) +
                      "\n      DOCUMENT: " + xml.slice(0, 1500));
    }
  });
  log.debug("Leaving validate().");
}

// ===========================================================================
// THE BROWSER, AND THE MESSAGES IT CARRIES
// ===========================================================================

function jar() {
  log.debug("Entering jar().");
  const store = {};
  log.debug("Leaving jar().");
  return {
    header: function () {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(store).map(function (k) {
        return k + "=" + store[k];
      }).join("; ");
    },
    take: function (res) {
      log.debug("Entering take().");
      (res.headers.getSetCookie ? res.headers.getSetCookie() : []).forEach(
        function (line) {
          const pair = line.split(";")[0];
          const i = pair.indexOf("=");
          store[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
        });
      log.debug("Leaving take().");
    },
    has: function () {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return Object.keys(store).length > 0;
    }
  };
}

// One request, one body read, redirects NOT followed.
async function hop(cookies, url, options) {
  log.debug("Entering hop(). " + ((options && options.method) || "GET") +
            " " + url);
  const o = Object.assign({ redirect: "manual", headers: {} }, options || {});
  o.headers = Object.assign({}, o.headers);
  if (cookies && cookies.has()) {
    o.headers.cookie = cookies.header();
  }
  const r = await fetch(url, o);
  if (cookies) {
    cookies.take(r);
  }
  const body = r.status >= 300 && r.status < 400 ? "" : await r.text();
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, headers: r.headers, body: body, url: url,
           location: r.headers.get("location") || "" };
}

function postForm(cookies, url, fields) {
  log.debug("Entering postForm(). " + url);
  log.debug("Leaving postForm().");
  return hop(cookies, url, {
    method: "POST", body: new URLSearchParams(fields).toString(),
    headers: { "content-type": "application/x-www-form-urlencoded" } });
}

// Every form on a page, with its action and its hidden fields decoded.
function formsIn(html) {
  log.debug("Entering formsIn().");
  const out = [];
  const re = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
  let m = re.exec(String(html || ""));
  while (m) {
    const action = htmlDecode((/action="([^"]*)"/i.exec(m[1]) || [])[1] || "");
    const method = ((/method="([^"]*)"/i.exec(m[1]) || [])[1] || "get")
      .toLowerCase();
    const fields = {};
    [...m[2].matchAll(/<input[^>]*type="hidden"[^>]*>/gi)].forEach(
      function (one) {
        const n = /name="([^"]+)"/.exec(one[0]);
        const v = /value="([^"]*)"/.exec(one[0]);
        if (n) {
          fields[htmlDecode(n[1])] = v ? htmlDecode(v[1]) : "";
        }
      });
    out.push({ action: action, method: method, fields: fields });
    m = re.exec(String(html || ""));
  }
  log.debug("Leaving formsIn(). " + out.length);
  return out;
}

// A SAML message as it travels: DEFLATE and base64 on the Redirect binding,
// base64 alone on POST and POST-SimpleSign.
function decodeRedirect(value) {
  log.debug("Entering decodeRedirect().");
  log.debug("Leaving decodeRedirect().");
  return zlib.inflateRawSync(Buffer.from(String(value), "base64"))
    .toString("utf8");
}

function decodePost(value) {
  log.debug("Entering decodePost().");
  log.debug("Leaving decodePost().");
  return Buffer.from(String(value), "base64").toString("utf8");
}

// Every SAML or WS-Federation message a hop CARRIES, in the form it was
// emitted: a Location's query, or a page's forms. `from` names the
// service's URL that emitted it.
function messagesIn(r) {
  log.debug("Entering messagesIn().");
  const out = [];
  const from = new URL(r.url).pathname;
  if (r.location) {
    const u = new URL(r.location, r.url);
    for (const field of ["SAMLRequest", "SAMLResponse"]) {
      const v = u.searchParams.get(field);
      if (v) {
        out.push({ field: field, binding: "redirect", xml: decodeRedirect(v),
                   from: from, to: u.origin + u.pathname,
                   signed: !!u.searchParams.get("Signature") });
      }
    }
    if (u.searchParams.get("SAMLart")) {
      out.push({ field: "SAMLart", binding: "artifact",
                 artifact: u.searchParams.get("SAMLart"), from: from,
                 to: u.origin + u.pathname });
    }
  }
  if (r.body) {
    formsIn(r.body).forEach(function (f) {
      for (const field of ["SAMLRequest", "SAMLResponse"]) {
        if (f.fields[field]) {
          out.push({ field: field,
                     binding: f.fields.SigAlg ? "simplesign" : "post",
                     xml: decodePost(f.fields[field]), from: from,
                     to: f.action });
        }
      }
      if (f.fields.wresult) {
        out.push({ field: "wresult", binding: "post", xml: f.fields.wresult,
                   from: from, to: f.action });
      }
    });
  }
  log.debug("Leaving messagesIn(). " + out.length);
  return out;
}

// ---------------------------------------------------------------------------
// A BROWSER THAT STOPS AT THE SERVICE'S EDGE. Follows redirects and forms,
// answers the sign-in and consent screens, records every message a hop
// carries — and stops at the first hop addressed to another origin (a
// service provider this file only pretends to be) or matching `stopAt`,
// returning that hop UNSENT with everything captured on the way.
// ---------------------------------------------------------------------------
async function browse(cookies, startUrl, username, stopAt) {
  log.debug("Entering browse(). " + startUrl);
  const captured = [];
  const origin = new URL(base).origin;
  const stops = function (url) {
    log.debug("Entering stops().");
    log.debug("Leaving stops().");
    return new URL(url).origin !== origin || (stopAt && stopAt(url));
  };
  let r = await hop(cookies, startUrl);
  const trail = [];
  for (let step = 0; step < 30; step += 1) {
    trail.push(r.status + " " + r.url);
    messagesIn(r).forEach(function (m) {
      captured.push(m);
    });
    if (r.status >= 300 && r.status < 400 && r.location) {
      const next = new URL(r.location, r.url).toString();
      if (stops(next)) {
        log.debug("Leaving browse(). A redirect out.");
        return { captured: captured, last: r, stop: { method: "GET",
                 url: next }, trail: trail };
      }
      r = await hop(cookies, next);
      continue;
    }
    if (r.status !== 200) {
      break;
    }
    const forms = formsIn(r.body);
    const signIn = forms.find(function (f) {
      return "authn_id" in f.fields;
    });
    const consent = forms.find(function (f) {
      return /consent/.test(f.action) || "consent_id" in f.fields;
    });
    const onward = forms.find(function (f) {
      return f.method === "post" &&
             ("SAMLResponse" in f.fields || "SAMLRequest" in f.fields ||
              "wresult" in f.fields);
    });
    if (signIn) {
      const to = new URL(signIn.action || r.url, r.url).toString();
      r = await postForm(cookies, to, Object.assign({}, signIn.fields, {
        username: username, password: PASSWORD, action: "login" }));
      continue;
    }
    if (consent) {
      const to = new URL(consent.action || r.url, r.url).toString();
      r = await postForm(cookies, to, Object.assign({}, consent.fields, {
        action: "allow", decision: "allow" }));
      continue;
    }
    if (onward) {
      const to = new URL(onward.action, r.url).toString();
      if (stops(to)) {
        log.debug("Leaving browse(). A form out.");
        return { captured: captured, last: r, stop: { method: "POST",
                 url: to, fields: onward.fields }, trail: trail };
      }
      r = await postForm(cookies, to, onward.fields);
      continue;
    }
    break;
  }
  log.debug("Leaving browse(). It stopped inside the service.");
  return { captured: captured, last: r, stop: null, trail: trail };
}

// ===========================================================================
// THE MANAGEMENT API, AND THE WORLD
// ===========================================================================

async function api(realm, method, p, payload) {
  log.debug("Entering api(). " + method + " " + p);
  const options = { method: method, redirect: "manual", headers: {} };
  if (payload !== undefined) {
    options.headers["content-type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const prefix = realm ? realmBase(realm) : base;
  const r = await fetch(prefix + "/admin-api" + p, options);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
    // Not JSON; `text` carries the answer into every message that quotes it.
    body = null;
  }
  log.debug("Leaving api(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

async function ensureRealm(id, mode) {
  log.debug("Entering ensureRealm(). " + id + " " + mode);
  const made = await api(null, "POST", "/realms/create",
                         { id: id, domain: id + ".example.net",
                           name: "#188 " + mode,
                           overrides: { "global.mode": mode } });
  must(made.status === 200 ||
       /already/i.test(JSON.stringify(made.body || made.text)),
       "creating the realm " + id + " answered " + made.status + " " +
       made.text.slice(0, 300));
  log.debug("Leaving ensureRealm().");
}

async function createPerson(realm, username) {
  log.debug("Entering createPerson(). " + realm + " " + username);
  const r = await api(realm, "POST", "/users/create", {
    username: username, invent: false,
    attributes: { cn: "Schema " + username, givenName: "Schema",
                  sn: username, displayName: "Schema " + username,
                  mail: username + "@" + realm + ".example.net" },
    credential: "password", password: PASSWORD });
  must(r.status === 200 && r.body && r.body.ok,
       "creating " + username + " in " + realm + " answered " + r.status +
       " " + r.text.slice(0, 300));
  log.debug("Leaving createPerson().");
}

async function createApplication(realm, identifier, protocols, fields) {
  log.debug("Entering createApplication(). " + identifier);
  const r = await api(realm, "POST", "/applications/create",
    { identifier: identifier, name: "schema " + identifier,
      protocols: protocols, fields: fields });
  must(r.status === 200 && r.body && r.body.ok,
       "creating the application " + identifier + " in " + realm +
       " answered " + r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving createApplication().");
}

// ---------------------------------------------------------------------------
// THIS FILE'S OWN KEYS: a signing pair its service providers, relying parties
// and WS-Trust requesters sign with, and an encryption certificate the
// service encrypts assertions to. Made per run; nothing here is committed.
// ---------------------------------------------------------------------------
function selfSignedPair(cn) {
  log.debug("Entering selfSignedPair(). " + cn);
  const pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privateKeyPem = pair.privateKey.export({ type: "pkcs8",
                                                 format: "pem" });
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(
    pair.publicKey.export({ type: "spki", format: "pem" }));
  cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 24 * 3600 * 1000);
  const subject = [{ name: "commonName", value: cn }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.sign(forge.pki.privateKeyFromPem(privateKeyPem),
            forge.md.sha256.create());
  const certPem = forge.pki.certificateToPem(cert);
  log.debug("Leaving selfSignedPair().");
  return { privateKeyPem: privateKeyPem, certPem: certPem,
           certB64: certPem.replace(/-----[^-]+-----|\s+/g, "") };
}

const SIGNER = selfSignedPair("xsd-" + STAMP + ".example.com");
const ENCRYPTER = selfSignedPair("xsd-enc-" + STAMP + ".example.com");

// An enveloped signature on a protocol message, placed where the schema
// wants it: after Issuer in SAML 2.0, first in a SAML 1.1 Request.
function signEnveloped(xml, rootLocalName, idAttribute, after) {
  log.debug("Entering signEnveloped(). " + rootLocalName);
  const where = "//*[local-name(.)='" + rootLocalName + "']";
  const sig = new SignedXml({
    privateKey: SIGNER.privateKeyPem, idAttribute: idAttribute,
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    signatureAlgorithm: SIG_ALG
  });
  sig.addReference({
    xpath: where,
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                 "http://www.w3.org/2001/10/xml-exc-c14n#"],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256"
  });
  const location = after
    ? { reference: "//*[local-name(.)='" + rootLocalName +
                   "']/*[local-name(.)='" + after + "']", action: "after" }
    : { reference: where, action: "prepend" };
  sig.computeSignature(xml, { location: location });
  log.debug("Leaving signEnveloped().");
  return sig.getSignedXml();
}

// The Redirect binding's signature over the query string (saml-bindings-2.0
// section 3.4.4.1).
function redirectQuery(field, xml, relayState) {
  log.debug("Entering redirectQuery(). " + field);
  let q = field + "=" + encodeURIComponent(
    zlib.deflateRawSync(Buffer.from(xml, "utf8")).toString("base64"));
  if (relayState) {
    q += "&RelayState=" + encodeURIComponent(relayState);
  }
  q += "&SigAlg=" + encodeURIComponent(SIG_ALG);
  const signature = nodeCrypto.sign("RSA-SHA256", Buffer.from(q, "utf8"),
                                    SIGNER.privateKeyPem).toString("base64");
  log.debug("Leaving redirectQuery().");
  return q + "&Signature=" + encodeURIComponent(signature);
}

function samlId() {
  log.debug("Entering samlId().");
  log.debug("Leaving samlId().");
  return "_" + nodeCrypto.randomBytes(16).toString("hex");
}

// ===========================================================================
// THE REALMS
// ===========================================================================

// One world per mode: a realm, a person, and the parties this file plays.
async function makeWorld(mode) {
  log.debug("Entering makeWorld(). " + mode);
  const tag = mode === "product" ? "p" : "d";
  const realm = "xsd" + tag + "-" + STAMP;
  await ensureRealm(realm, mode);
  const w = {
    mode: mode, realm: realm, rb: realmBase(realm),
    person: names.usernameFor("xsd" + tag),
    other: names.usernameFor("xsd" + tag + "o"),
    sp: "https://sp-" + tag + "-" + STAMP + ".example.com/saml",
    spEnc: "https://spenc-" + tag + "-" + STAMP + ".example.com/saml",
    rp11: "https://rp11-" + tag + "-" + STAMP + ".example.com/shibboleth",
    wsRp: "https://wsrp-" + tag + "-" + STAMP + ".example.com/",
    requester: "xsd-req-" + tag + "-" + STAMP
  };
  w.acs = w.sp.replace(/\/saml$/, "/acs");
  w.slo = w.sp.replace(/\/saml$/, "/slo");
  w.acsEnc = w.spEnc.replace(/\/saml$/, "/acs");
  w.acs11 = w.rp11.replace(/\/shibboleth$/, "/SAML/POST");
  w.wsReply = w.wsRp + "signin";
  await createPerson(realm, w.person);
  await createPerson(realm, w.other);
  // The WS-Trust requester of 1.4's ActAs and 1.3's OnBehalfOf: an
  // application (only an application may delegate, #108) holding a
  // password, so its UsernameToken verifies in product, and trusted to act
  // for others.
  await createPerson(realm, w.requester);
  const signing = [SIGNER.certPem];
  await createApplication(realm, w.sp, ["saml2"], {
    samlEntityId: [w.sp], samlAssertionConsumerService: [w.acs],
    samlSingleLogoutService: [w.slo], samlSigningCertificate: signing });
  await createApplication(realm, w.spEnc, ["saml2"], {
    samlEntityId: [w.spEnc], samlAssertionConsumerService: [w.acsEnc],
    samlSigningCertificate: signing,
    samlEncryptionCertificate: ENCRYPTER.certPem,
    saml2EncryptAssertion: "TRUE", saml2EncryptLogoutNameId: "TRUE" });
  await createApplication(realm, w.rp11, ["saml11"], {
    samlEntityId: [w.rp11], samlAssertionConsumerService: [w.acs11],
    samlSigningCertificate: signing });
  await createApplication(realm, w.wsRp, ["wsfed", "wstrust"], {
    wsfedRealm: [w.wsRp], wsfedReplyUrl: [w.wsReply],
    wstrustAppliesTo: [w.wsRp] });
  await createApplication(realm, w.requester, ["wstrust"], {
    appTrustedToImpersonate: "TRUE", appAllowedToDelegateTo: [w.wsRp] });
  log.debug("Leaving makeWorld().");
  return w;
}

// ===========================================================================
// 1. METADATA
// ===========================================================================
async function metadata(w) {
  log.debug("Entering metadata().");
  log.info("=== " + w.mode + ": the published metadata ===");
  const docs = [
    ["SAML 2.0 identity provider metadata", "/saml2/metadata"],
    ["SAML 2.0 identity provider metadata for one service provider",
     "/saml2/metadata/" + encodeURIComponent(w.sp)],
    ["SAML 1.1 metadata", "/saml11/metadata"],
    ["SAML 1.1 metadata for one relying party",
     "/saml11/metadata/" + encodeURIComponent(w.rp11)],
    ["WS-Federation federation metadata",
     "/FederationMetadata/2007-06/FederationMetadata.xml"]
  ];
  for (const [what, p] of docs) {
    const r = await hop(null, w.rb + p);
    await validate(w.mode + " " + what + " (HTTP " + r.status + ")",
                   r.status === 200 ? r.body : "", p);
  }
  log.debug("Leaving metadata().");
}

// ===========================================================================
// 2. SAML 2.0 WEB BROWSER SSO
// ===========================================================================

function authnRequest(w, spEntityId, acsUrl, protocolBinding, extra) {
  log.debug("Entering authnRequest().");
  const id = samlId();
  const xml = "<samlp:AuthnRequest xmlns:samlp=\"" + NS.samlp + "\" " +
    "xmlns:saml=\"" + NS.saml + "\" ID=\"" + id + "\" Version=\"2.0\" " +
    "IssueInstant=\"" + new Date().toISOString() + "\" Destination=\"" +
    w.rb + "/saml2/sso\" AssertionConsumerServiceURL=\"" + acsUrl + "\" " +
    "ProtocolBinding=\"" + protocolBinding + "\"" + ((extra && extra.attrs) ||
    "") + "><saml:Issuer>" + spEntityId + "</saml:Issuer>" +
    ((extra && extra.inner) || "") + "</samlp:AuthnRequest>";
  log.debug("Leaving authnRequest().");
  return { id: id, xml: xml };
}

// One sign-in at the identity provider: the AuthnRequest on the Redirect
// binding, signed, asking for the Response on `protocolBinding`.
async function ssoRound(w, cookies, spEntityId, acsUrl, protocolBinding,
                        extra) {
  log.debug("Entering ssoRound(). " + protocolBinding);
  const req = authnRequest(w, spEntityId, acsUrl, protocolBinding, extra);
  const url = w.rb + "/saml2/sso?" + redirectQuery("SAMLRequest", req.xml,
                                                   "rs-" + STAMP);
  const walked = await browse(cookies, url, w.person);
  log.debug("Leaving ssoRound(). " + walked.captured.length + " captured.");
  return walked;
}

async function capturedOne(what, walked, field, binding) {
  log.debug("Entering capturedOne(). " + what);
  const found = walked.captured.filter(function (m) {
    return m.field === field && (!binding || m.binding === binding);
  });
  if (!found.length) {
    await check(what + " was emitted", async function () {
      throw new Error("no " + field + " on the " + (binding || "any") +
                      " binding; the browser went " +
                      walked.trail.join(" → ") + " — " +
                      squash(walked.last && walked.last.body));
    });
  }
  log.debug("Leaving capturedOne(). " + found.length);
  return found;
}

async function saml2(w) {
  log.debug("Entering saml2().");
  log.info("=== " + w.mode + ": SAML 2.0 Web Browser SSO ===");
  const cookies = jar();

  // AN ERROR RESPONSE FIRST, while there is no session: IsPassive.
  const passive = await ssoRound(w, cookies, w.sp, w.acs, BINDING.post,
                                 { attrs: " IsPassive=\"true\"" });
  for (const m of await capturedOne("the IsPassive error Response",
                                    passive, "SAMLResponse")) {
    await validate(w.mode + " SAML 2.0 error Response (IsPassive, no " +
                   "session) on " + m.binding, m.xml, m.from);
  }

  const rounds = [
    ["HTTP-POST", BINDING.post, "post"],
    ["HTTP-Redirect", BINDING.redirect, "redirect"],
    ["POST-SimpleSign", BINDING.simpleSign, "simplesign"]
  ];
  for (const [label, binding, carried] of rounds) {
    const walked = await ssoRound(w, cookies, w.sp, w.acs, binding);
    for (const m of await capturedOne("the Response on " + label, walked,
                                      "SAMLResponse", carried)) {
      await validate(w.mode + " SAML 2.0 Response on " + label, m.xml,
                     m.from);
    }
  }

  // THE ENCRYPTED ASSERTION, to the service provider that registered an
  // encryption certificate.
  const enc = await ssoRound(w, cookies, w.spEnc, w.acsEnc, BINDING.post);
  for (const m of await capturedOne("the Response with an " +
                                    "EncryptedAssertion", enc,
                                    "SAMLResponse", "post")) {
    await check(w.mode + " the Response to the encrypting service provider " +
                "carries an EncryptedAssertion", async function () {
      if (!/EncryptedAssertion/.test(m.xml)) {
        throw new Error("no EncryptedAssertion: " + m.xml.slice(0, 400));
      }
    });
    await validate(w.mode + " SAML 2.0 Response with an EncryptedAssertion",
                   m.xml, m.from);
  }

  // THE ARTIFACT, and the ArtifactResponse the service provider fetches.
  const art = await ssoRound(w, cookies, w.sp, w.acs, BINDING.artifact);
  for (const m of await capturedOne("the artifact", art, "SAMLart")) {
    const resolveId = samlId();
    const resolve = signEnveloped(
      "<samlp:ArtifactResolve xmlns:samlp=\"" + NS.samlp + "\" " +
      "xmlns:saml=\"" + NS.saml + "\" ID=\"" + resolveId + "\" " +
      "Version=\"2.0\" IssueInstant=\"" + new Date().toISOString() + "\" " +
      "Destination=\"" + w.rb + "/saml2/ars\"><saml:Issuer>" + w.sp +
      "</saml:Issuer><samlp:Artifact>" + m.artifact + "</samlp:Artifact>" +
      "</samlp:ArtifactResolve>", "ArtifactResolve", "ID", "Issuer");
    const r = await hop(null, w.rb + "/saml2/ars", {
      method: "POST",
      body: "<soap:Envelope xmlns:soap=\"" + NS.soap11 + "\"><soap:Body>" +
            resolve + "</soap:Body></soap:Envelope>",
      headers: { "content-type": "text/xml; charset=utf-8",
                 soapaction: "\"\"" } });
    await check(w.mode + " the ArtifactResponse carries the Response",
                async function () {
      if (!/ArtifactResponse[\s\S]*:Response/.test(r.body)) {
        throw new Error("HTTP " + r.status + " " + r.body.slice(0, 600));
      }
    });
    await validate(w.mode + " SAML 2.0 ArtifactResponse over SOAP (HTTP " +
                   r.status + ")", r.body, "/saml2/ars");
  }

  // IDENTITY-PROVIDER-INITIATED SSO (#189): the unsolicited Response.
  const unsolicited = await browse(cookies, w.rb + "/saml2/unsolicited?" +
    "providerId=" + encodeURIComponent(w.sp) + "&shire=" +
    encodeURIComponent(w.acs) + "&target=uns-" + STAMP, w.person);
  for (const m of await capturedOne("the unsolicited Response", unsolicited,
                                    "SAMLResponse", "post")) {
    await validate(w.mode + " SAML 2.0 unsolicited Response " +
                   "(identity-provider-initiated)", m.xml, m.from);
  }

  // THE ATTRIBUTE AUTHORITY (#189): a signed AttributeQuery about the person
  // this session signed in to w.sp, and the Response over SOAP.
  const query = signEnveloped(
    "<samlp:AttributeQuery xmlns:samlp=\"" + NS.samlp + "\" " +
    "xmlns:saml=\"" + NS.saml + "\" ID=\"" + samlId() + "\" " +
    "Version=\"2.0\" IssueInstant=\"" + new Date().toISOString() + "\" " +
    "Destination=\"" + w.rb + "/saml2/aa\"><saml:Issuer>" + w.sp +
    "</saml:Issuer><saml:Subject><saml:NameID>" + w.person +
    "</saml:NameID></saml:Subject></samlp:AttributeQuery>",
    "AttributeQuery", "ID", "Issuer");
  const aa = await hop(null, w.rb + "/saml2/aa", {
    method: "POST",
    body: "<soap:Envelope xmlns:soap=\"" + NS.soap11 + "\"><soap:Body>" +
          query + "</soap:Body></soap:Envelope>",
    headers: { "content-type": "text/xml; charset=utf-8",
               soapaction: "\"\"" } });
  await check(w.mode + " the attribute authority answers Success",
              async function () {
    if (!/status:Success/.test(aa.body)) {
      throw new Error("HTTP " + aa.status + " " + aa.body.slice(0, 600));
    }
  });
  await validate(w.mode + " SAML 2.0 attribute query Response over SOAP " +
                 "(HTTP " + aa.status + ")", aa.body, "/saml2/aa");

  // SERVICE-PROVIDER-INITIATED LOGOUT: the LogoutResponse.
  const logoutId = samlId();
  const logout = "<samlp:LogoutRequest xmlns:samlp=\"" + NS.samlp + "\" " +
    "xmlns:saml=\"" + NS.saml + "\" ID=\"" + logoutId + "\" Version=\"2.0\" " +
    "IssueInstant=\"" + new Date().toISOString() + "\" Destination=\"" +
    w.rb + "/saml2/slo\"><saml:Issuer>" + w.sp + "</saml:Issuer>" +
    "<saml:NameID>" + w.person + "</saml:NameID></samlp:LogoutRequest>";
  const slo = await browse(cookies, w.rb + "/saml2/slo?" +
                           redirectQuery("SAMLRequest", logout, "slo-" +
                                         STAMP), w.person);
  for (const m of await capturedOne("the LogoutResponse", slo,
                                    "SAMLResponse")) {
    await validate(w.mode + " SAML 2.0 LogoutResponse on " + m.binding, m.xml,
                   m.from);
  }

  // IDENTITY-PROVIDER-INITIATED LOGOUT: a new session signed in to both
  // service providers, then ended at /saml2/slo, which draws a LogoutRequest
  // for each.
  const idpCookies = jar();
  await ssoRound(w, idpCookies, w.sp, w.acs, BINDING.post);
  await ssoRound(w, idpCookies, w.spEnc, w.acsEnc, BINDING.post);
  const page = await hop(idpCookies, w.rb + "/saml2/slo");
  const links = [...page.body.matchAll(/href="([^"]*SAMLRequest=[^"]*)"/g)]
    .map(function (x) {
      return htmlDecode(x[1]);
    });
  await check(w.mode + " identity-provider-initiated logout names a " +
              "LogoutRequest per service provider", async function () {
    if (links.length < 2) {
      throw new Error(links.length + " link(s): " + squash(page.body));
    }
  });
  let sawEncryptedId = false;
  for (const link of links) {
    const u = new URL(link, page.url);
    const xml = decodeRedirect(u.searchParams.get("SAMLRequest"));
    sawEncryptedId = sawEncryptedId || /EncryptedID/.test(xml);
    await validate(w.mode + " SAML 2.0 LogoutRequest (identity-provider-" +
                   "initiated) to " + u.origin, xml, "/saml2/slo");
  }
  await check(w.mode + " the LogoutRequest to the encrypting service " +
              "provider carries an EncryptedID", async function () {
    if (!sawEncryptedId) {
      throw new Error("no LogoutRequest carried one");
    }
  });

  // AN UNSATISFIABLE NameIDPolicy: the error Response
  // InvalidNameIDPolicy, on a session that exists.
  const policy = await ssoRound(w, cookies, w.sp, w.acs, BINDING.post, {
    inner: "<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:2.0:" +
           "nameid-format:kerberos\" AllowCreate=\"false\"/>" });
  for (const m of await capturedOne("the InvalidNameIDPolicy Response",
                                    policy, "SAMLResponse")) {
    await validate(w.mode + " SAML 2.0 error Response (an unsatisfiable " +
                   "NameIDPolicy) on " + m.binding, m.xml, m.from);
  }

  // THE MOCK SERVICE PROVIDER's AuthnRequests (/saml2/sp, non-spec, but a
  // document this service emits): one per response binding it offers.
  const mock = await hop(null, w.rb + "/saml2/sp");
  const requests = [...mock.body.matchAll(/href="([^"]*SAMLRequest=[^"]*)"/g)]
    .map(function (x) {
      return htmlDecode(x[1]);
    });
  await check(w.mode + " the mock service provider offers its " +
              "AuthnRequests", async function () {
    if (requests.length < 3) {
      throw new Error(requests.length + " — " + squash(mock.body));
    }
  });
  for (const link of requests) {
    const u = new URL(link, mock.url);
    const xml = decodeRedirect(u.searchParams.get("SAMLRequest"));
    await validate(w.mode + " SAML 2.0 AuthnRequest from the mock service " +
                   "provider (" + ((/ProtocolBinding="[^"]*:([^:"]+)"/
                     .exec(xml) || [])[1] || "?") + ")", xml, "/saml2/sp");
  }
  log.debug("Leaving saml2().");
}

// ===========================================================================
// 3. SAML 1.1
// ===========================================================================
function saml11Request(inner) {
  log.debug("Entering saml11Request().");
  const xml = "<samlp:Request xmlns:samlp=\"" + NS.samlp1 + "\" " +
    "xmlns:saml=\"" + NS.saml1 + "\" RequestID=\"" + samlId() + "\" " +
    "MajorVersion=\"1\" MinorVersion=\"1\" IssueInstant=\"" +
    new Date().toISOString() + "\">" + inner + "</samlp:Request>";
  log.debug("Leaving saml11Request().");
  return "<soap:Envelope xmlns:soap=\"" + NS.soap11 + "\"><soap:Body>" +
    signEnveloped(xml, "Request", "RequestID") +
    "</soap:Body></soap:Envelope>";
}

async function responder11(w, what, body) {
  log.debug("Entering responder11(). " + what);
  const r = await hop(null, w.rb + "/saml11/responder", {
    method: "POST", body: body,
    headers: { "content-type": "text/xml; charset=utf-8",
               soapaction: "\"\"" } });
  await validate(w.mode + " SAML 1.1 responder: " + what + " (HTTP " +
                 r.status + ")", r.body, "/saml11/responder");
  log.debug("Leaving responder11().");
  return r;
}

async function saml11(w) {
  log.debug("Entering saml11().");
  log.info("=== " + w.mode + ": SAML 1.1 ===");
  const cookies = jar();
  const start = function (profile) {
    log.debug("Entering start().");
    log.debug("Leaving start().");
    return w.rb + "/saml11/sso?" + new URLSearchParams({
      providerId: w.rp11, shire: w.acs11, TARGET: w.acs11 + "?t=1",
      profile: profile }).toString();
  };
  const post = await browse(cookies, start("post"), w.person);
  let assertionId = "";
  for (const m of await capturedOne("the Browser/POST Response", post,
                                    "SAMLResponse", "post")) {
    assertionId = (/AssertionID="([^"]+)"/.exec(m.xml) || [])[1] ||
                  assertionId;
    await validate(w.mode + " SAML 1.1 Browser/POST Response", m.xml, m.from);
  }
  const art = await browse(cookies, start("artifact"), w.person);
  for (const m of await capturedOne("the Browser/Artifact artifact", art,
                                    "SAMLart")) {
    await responder11(w, "the artifact's Response",
                      saml11Request("<samlp:AssertionArtifact>" + m.artifact +
                                    "</samlp:AssertionArtifact>"));
  }
  await responder11(w, "an AssertionIDReference",
                    saml11Request("<saml:AssertionIDReference>" +
                                  (assertionId || "_none") +
                                  "</saml:AssertionIDReference>"));
  await responder11(w, "an AttributeQuery (the attribute authority)",
                    saml11Request("<samlp:AttributeQuery Resource=\"" +
                                  w.rp11 + "\"><saml:Subject>" +
                                  "<saml:NameIdentifier>" + w.person +
                                  "</saml:NameIdentifier></saml:Subject>" +
                                  "</samlp:AttributeQuery>"));
  await responder11(w, "an AuthenticationQuery",
                    saml11Request("<samlp:AuthenticationQuery>" +
                                  "<saml:Subject><saml:NameIdentifier>" +
                                  w.person + "</saml:NameIdentifier>" +
                                  "</saml:Subject>" +
                                  "</samlp:AuthenticationQuery>"));
  await responder11(w, "a refused AuthorizationDecisionQuery",
                    saml11Request("<samlp:AuthorizationDecisionQuery " +
                                  "Resource=\"" + w.rp11 + "\">" +
                                  "<saml:Subject><saml:NameIdentifier>" +
                                  w.person + "</saml:NameIdentifier>" +
                                  "</saml:Subject><saml:Action>read" +
                                  "</saml:Action>" +
                                  "</samlp:AuthorizationDecisionQuery>"));
  await responder11(w, "a body that is not XML", "<not xml <<<");
  log.debug("Leaving saml11().");
}

// ===========================================================================
// 4. WS-TRUST
// ===========================================================================
function rst(o) {
  log.debug("Entering rst().");
  const soapNs = o.soap === "1.1" ? NS.soap11 : NS.soap12;
  const ns = o.trustNs;
  const security = o.username
    ? "<wsse:Security xmlns:wsse=\"" + NS.wsse + "\"><wsse:UsernameToken>" +
      "<wsse:Username>" + o.username + "</wsse:Username><wsse:Password>" +
      o.password + "</wsse:Password></wsse:UsernameToken>" +
      // The certificate `?encrypt=1` encrypts to: the endpoint takes the
      // first X509Certificate in the request (a WS-Security signature's
      // KeyInfo in a real client).
      (o.recipientCertB64 ? "<ds:X509Data xmlns:ds=\"http://www.w3.org/" +
        "2000/09/xmldsig#\"><ds:X509Certificate>" + o.recipientCertB64 +
        "</ds:X509Certificate></ds:X509Data>" : "") + "</wsse:Security>"
    : "";
  const body = "<wst:RequestSecurityToken xmlns:wst=\"" + ns + "\">" +
    (o.tokenType ? "<wst:TokenType>" + o.tokenType + "</wst:TokenType>" : "") +
    "<wst:RequestType>" + ns + "/" + o.op + "</wst:RequestType>" +
    (o.appliesTo ? "<wsp:AppliesTo xmlns:wsp=\"" + NS.wsp + "\">" +
      "<wsa:EndpointReference xmlns:wsa=\"" + NS.wsa + "\"><wsa:Address>" +
      o.appliesTo + "</wsa:Address></wsa:EndpointReference>" +
      "</wsp:AppliesTo>" : "") + (o.inner || "") +
    "</wst:RequestSecurityToken>";
  log.debug("Leaving rst().");
  return "<s:Envelope xmlns:s=\"" + soapNs + "\"><s:Header>" + security +
    "</s:Header><s:Body>" + body + "</s:Body></s:Envelope>";
}

async function sts(w, what, o, query) {
  log.debug("Entering sts(). " + what);
  const r = await hop(null, w.rb + "/sts" + (query || ""), {
    method: "POST", body: rst(o),
    headers: { "content-type": o.soap === "1.1" ? "text/xml; charset=utf-8"
                                                : "application/soap+xml" } });
  await validate(w.mode + " WS-Trust " + what + " (HTTP " + r.status + ")",
                 r.body, "/sts");
  log.debug("Leaving sts().");
  return r;
}

async function wsTrust(w) {
  log.debug("Entering wsTrust().");
  log.info("=== " + w.mode + ": WS-Trust ===");
  const versions = [["2004/04", NS.wst0404], ["2005/02", NS.wst0502],
                    ["1.3", NS.wst13]];
  let issued = "";
  for (const [label, ns] of versions) {
    for (const soap of ["1.1", "1.2"]) {
      for (const op of ["Issue", "Renew", "Validate", "Cancel"]) {
        for (const tokenType of ["", "urn:ietf:params:oauth:token-type:jwt"]) {
          if (tokenType && (op === "Validate" || op === "Cancel")) {
            continue;
          }
          const target = op === "Issue" ? "" : op + "Target";
          const r = await sts(w, label + " " + op + " over SOAP " + soap +
                              (tokenType ? " (JWT)" : " (SAML 2.0)"), {
            trustNs: ns, soap: soap, op: op, tokenType: tokenType,
            username: w.person, password: PASSWORD, appliesTo: w.wsRp,
            inner: target ? "<wst:" + target + ">" + (issued || "<x/>") +
                            "</wst:" + target + ">" : "" });
          if (op === "Issue" && !tokenType && !issued) {
            issued = (/<saml:Assertion[\s\S]*<\/saml:Assertion>/
              .exec(r.body) || [])[0] || "";
          }
        }
      }
    }
  }
  // A Validate with nothing to validate: wst:Status invalid.
  await sts(w, "1.3 Validate with no token (status invalid)", {
    trustNs: NS.wst13, soap: "1.2", op: "Validate", username: w.person,
    password: PASSWORD, inner: "<wst:ValidateTarget/>" });
  // An assertion encrypted to the relying party's registered certificate —
  // `?encrypt=1`, the non-spec control this endpoint has for it.
  const enc = await sts(w, "1.3 Issue, encrypted to the AppliesTo", {
    trustNs: NS.wst13, soap: "1.2", op: "Issue", username: w.person,
    password: PASSWORD, appliesTo: w.wsRp,
    recipientCertB64: ENCRYPTER.certB64 }, "?encrypt=1");
  await check(w.mode + " the encrypted Issue carries an EncryptedAssertion",
              async function () {
    if (!/EncryptedAssertion/.test(enc.body)) {
      throw new Error("HTTP " + enc.status + " " + enc.body.slice(0, 400));
    }
  });
  // 1.4's ActAs and 1.3's OnBehalfOf, from the application trusted to.
  await sts(w, "1.4 ActAs", {
    trustNs: NS.wst13, soap: "1.2", op: "Issue", username: w.requester,
    password: PASSWORD, appliesTo: w.wsRp,
    inner: "<wst14:ActAs xmlns:wst14=\"" + NS.wst14 + "\">" + issued +
           "</wst14:ActAs>" });
  await sts(w, "1.3 OnBehalfOf", {
    trustNs: NS.wst13, soap: "1.1", op: "Issue", username: w.requester,
    password: PASSWORD, appliesTo: w.wsRp,
    inner: "<wst:OnBehalfOf>" + issued + "</wst:OnBehalfOf>" });
  // A PERSON asking to act for somebody: refused in product with WS-Trust
  // 1.4 section 11's wst:RequestFailed as the faultcode (SOAP 1.1) and the
  // Subcode (SOAP 1.2); recorded and issued in development.
  for (const soap of ["1.1", "1.2"]) {
    await sts(w, "OnBehalfOf by a person (SOAP " + soap + ")", {
      trustNs: NS.wst13, soap: soap, op: "Issue", username: w.other,
      password: PASSWORD, appliesTo: w.wsRp,
      inner: "<wst:OnBehalfOf>" + issued + "</wst:OnBehalfOf>" });
  }
  // The faults.
  await sts(w, "fault: a wrong password over SOAP 1.1", {
    trustNs: NS.wst13, soap: "1.1", op: "Issue", username: w.person,
    password: "invalid" });
  await sts(w, "fault: a wrong password over SOAP 1.2", {
    trustNs: NS.wst13, soap: "1.2", op: "Issue", username: w.person,
    password: "invalid" });
  for (const soap of ["1.1", "1.2"]) {
    const r = await hop(null, w.rb + "/sts", {
      method: "POST", body: "<a><b></a>",
      headers: { "content-type": soap === "1.1" ? "text/xml"
                                                : "application/soap+xml" } });
    await validate(w.mode + " WS-Trust fault: a body that is not XML, SOAP " +
                   soap + " (HTTP " + r.status + ")", r.body, "/sts");
  }
  log.debug("Leaving wsTrust().");
}

// ===========================================================================
// 5. WS-FEDERATION
// ===========================================================================
async function wsFederation(w) {
  log.debug("Entering wsFederation().");
  log.info("=== " + w.mode + ": WS-Federation ===");
  const cookies = jar();
  // The default token is SAML 1.1 (what AD FS sends a passive relying
  // party); `tokenType=saml2` is the endpoint's non-spec switch.
  const cases = [["SAML 1.1, WS-Trust 2005/02", {}, NS.saml1],
                 ["SAML 1.1, WS-Trust 1.3", { trust: "1.3" }, NS.saml1],
                 ["SAML 2.0, WS-Trust 2005/02", { tokenType: "saml2" },
                  NS.saml],
                 ["SAML 2.0, WS-Trust 1.3", { tokenType: "saml2",
                                              trust: "1.3" }, NS.saml]];
  for (const [label, extra, tokenNs] of cases) {
    const url = w.rb + "/wsfed?" + new URLSearchParams(Object.assign({
      wa: "wsignin1.0", wtrealm: w.wsRp, wreply: w.wsReply,
      wctx: "ctx-" + STAMP }, extra)).toString();
    const walked = await browse(cookies, url, w.person);
    for (const m of await capturedOne("the sign-in response (" + label + ")",
                                      walked, "wresult")) {
      await check(w.mode + " the " + label + " sign-in response carries " +
                  "that token", async function () {
        if (m.xml.indexOf("Assertion xmlns:saml=\"" + tokenNs + "\"") < 0 &&
            m.xml.indexOf("=\"" + tokenNs + "\"") < 0) {
          throw new Error(m.xml.slice(0, 500));
        }
      });
      await validate(w.mode + " WS-Federation sign-in response wresult (" +
                     label + ")", m.xml, m.from);
    }
  }
  log.debug("Leaving wsFederation().");
}

// ===========================================================================
// 6. THE federation/ MODULE: a third realm, the SERVICE PROVIDER, federating
// to the development realm's identity provider.
// ===========================================================================
async function federation(idp) {
  log.debug("Entering federation().");
  log.info("=== the federation module's outbound documents ===");
  const sp = "xsdf-" + STAMP;
  await ensureRealm(sp, "development");
  await createPerson(sp, idp.person);
  const setRel = async function (id, field, value) {
    log.debug("Entering setRel(). " + id + " " + field);
    const set = await api(sp, "POST", "/federation/set",
                          { id: id, field: field, value: value });
    must(set.status === 200 && set.body && set.body.ok, "setting " + field +
         " on " + id + " answered " + set.status + " " + set.text.slice(0,
                                                                        300));
    log.debug("Leaving setRel().");
  };
  const rels = [["xsd-post", "HTTP-POST"], ["xsd-redirect", "HTTP-Redirect"]];
  for (const [id, binding] of rels) {
    const made = await api(sp, "POST", "/federation/create",
      { id: id, role: "service-provider", protocol: "saml2" });
    must(made.status === 200 && made.body && made.body.ok, "creating " + id +
         " answered " + made.status + " " + made.text.slice(0, 300));
    const view = (await api(sp, "GET", "/federation?relationship=" + id))
      .body || {};
    const endpoints = view.endpoints || {};
    const ours = await hop(null, new URL(endpoints.metadata, base).toString());
    await validate("federation SAML 2.0 relationship metadata (" + binding +
                   ")", ours.body, "/federation/metadata/" + id);
    const entityId = (/entityID="([^"]+)"/.exec(ours.body) || [])[1] || "";
    const signing = ((/<md:KeyDescriptor use="signing">[\s\S]*?X509Certificate>([^<]+)</
      .exec(ours.body) || [])[1] || "").replace(/\s+/g, "");
    must(entityId && signing && endpoints.singleLogout, "the relationship " +
         "publishes no entityID, signing certificate or singleLogout: " +
         JSON.stringify(endpoints));
    await createApplication(idp.realm, entityId, ["saml2"], {
      samlEntityId: [entityId],
      samlAssertionConsumerService: [endpoints.assertionConsumerService],
      samlSingleLogoutService: [endpoints.singleLogout],
      samlSigningCertificate: ["-----BEGIN CERTIFICATE-----\n" +
        (signing.match(/.{1,64}/g) || []).join("\n") +
        "\n-----END CERTIFICATE-----\n"] });
    // The identity provider's document FOR this service provider: the
    // entityID it will issue under, and its endpoints.
    const idpMeta = await hop(null, idp.rb + "/saml2/metadata/" +
                                    encodeURIComponent(entityId));
    const idpEntity = (/entityID="([^"]+)"/.exec(idpMeta.body) || [])[1] ||
                      "";
    const idpCert = ((/<md:KeyDescriptor[^>]*use="signing"[\s\S]*?X509Certificate>([^<]+)</
      .exec(idpMeta.body) || [])[1] || "").replace(/\s+/g, "");
    const idpSso = (new RegExp("SingleSignOnService[^>]*Binding=\"" +
      (binding === "HTTP-POST" ? BINDING.post : BINDING.redirect)
        .replace(/[.:]/g, "\\$&") + "\"[^>]*Location=\"([^\"]+)\"")
      .exec(idpMeta.body) || [])[1] || "";
    const idpSlo = (/SingleLogoutService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"[^>]*Location="([^"]+)"/
      .exec(idpMeta.body) || [])[1] || "";
    must(idpEntity && idpCert && idpSso && idpSlo, "the identity " +
         "provider's metadata lacks something: " + idpMeta.body.slice(0, 300));
    for (const [field, value] of [["fedPeer", idpEntity],
                                  ["fedSsoUrl", idpSso],
                                  ["fedSigningCertificate", idpCert],
                                  ["fedBinding", binding],
                                  ["fedSignRequest", "TRUE"],
                                  ["fedSloUrl", idpSlo],
                                  ["fedAllowUnencrypted", "TRUE"]]) {
      await setRel(id, field, value);
    }
    const on = await api(sp, "POST", "/federation/enable", { id: id });
    must(on.status === 200 && on.body && on.body.ok, "enabling " + id +
         " answered " + on.status + " " + on.text.slice(0, 300));
    const linked = await api(sp, "POST", "/users/federation-link",
                             { user: idp.person, relationship: id,
                               subject: idp.person });
    must(linked.status === 200, "linking answered " + linked.status + " " +
         linked.text.slice(0, 300));

    const cookies = jar();
    const walked = await browse(cookies, realmBase(sp) +
                                "/federation/login/" + id, idp.person,
                                function (url) {
                                  return /\/federation\/acs\//.test(url);
                                });
    for (const m of await capturedOne("the outbound AuthnRequest (" + binding +
                                      ")", walked, "SAMLRequest")) {
      await validate("federation outbound AuthnRequest on " + m.binding +
                     " (" + binding + ")", m.xml, m.from);
    }
    for (const m of walked.captured.filter(function (x) {
      return x.field === "SAMLResponse";
    })) {
      await validate("SAML 2.0 Response to a federation partner on " +
                     m.binding, m.xml, m.from);
    }
    if (!walked.stop) {
      continue;
    }
    const back = walked.stop.method === "POST"
      ? await postForm(cookies, walked.stop.url, walked.stop.fields)
      : await hop(cookies, walked.stop.url);
    await check("federation " + binding + ": the partner's answer signed " +
                "the person in", async function () {
      if (!(back.status >= 200 && back.status < 400)) {
        throw new Error("HTTP " + back.status + " " + squash(back.body));
      }
    });
    // THE OUTBOUND LogoutRequest: signing out at the service provider realm
    // offers the partner one, and the partner's LogoutResponse comes back.
    const bye = await postForm(cookies, realmBase(sp) + "/logout",
                               { scope: "global" });
    const toPartner = [...String(bye.body).matchAll(/href="([^"]+)"/g)]
      .map(function (x) {
        return htmlDecode(x[1]);
      }).filter(function (u) {
        return u.indexOf(idpSlo + "?") === 0;
      })[0] || "";
    await check("federation " + binding + ": signing out offers the partner " +
                "a LogoutRequest", async function () {
      if (!toPartner) {
        throw new Error("HTTP " + bye.status + " " + squash(bye.body));
      }
    });
    if (toPartner) {
      const u = new URL(toPartner);
      await validate("federation outbound LogoutRequest on redirect (" +
                     binding + ")",
                     decodeRedirect(u.searchParams.get("SAMLRequest")),
                     "/logout");
      const atPartner = await hop(jar(), toPartner);
      for (const m of await capturedOne("the partner's LogoutResponse",
                                        { captured: messagesIn(atPartner),
                                          trail: [atPartner.status + " " +
                                                  atPartner.url],
                                          last: atPartner },
                                        "SAMLResponse")) {
        await validate("SAML 2.0 LogoutResponse to a federation partner on " +
                       m.binding, m.xml, m.from);
      }
    }
  }
  // A SAML 1.1 relationship publishes metadata too.
  const s11 = await api(sp, "POST", "/federation/create",
    { id: "xsd-saml11", role: "service-provider", protocol: "saml11",
      peer: "urn:xsd:saml11-partner:" + STAMP });
  must(s11.status === 200 && s11.body && s11.body.ok, "creating the SAML " +
       "1.1 relationship answered " + s11.status + " " +
       s11.text.slice(0, 300));
  const s11Meta = await hop(null, realmBase(sp) +
                                  "/federation/metadata/xsd-saml11");
  await validate("federation SAML 1.1 relationship metadata", s11Meta.body,
                 "/federation/metadata/xsd-saml11");
  // A WS-Federation relationship publishes metadata too.
  const ws = await api(sp, "POST", "/federation/create",
    { id: "xsd-wsfed", role: "service-provider", protocol: "wsfed",
      peer: "urn:xsd:wsfed-partner:" + STAMP });
  must(ws.status === 200 && ws.body && ws.body.ok, "creating the " +
       "WS-Federation relationship answered " + ws.status + " " +
       ws.text.slice(0, 300));
  const wsMeta = await hop(null, realmBase(sp) +
                                 "/federation/metadata/xsd-wsfed");
  await validate("federation WS-Federation relationship metadata",
                 wsMeta.body, "/federation/metadata/xsd-wsfed");
  log.debug("Leaving federation().");
}

// ===========================================================================
async function selfTest() {
  log.debug("Entering selfTest().");
  log.info("=== the validator itself ===");
  // A validator that accepts everything passes any suite made only of valid
  // documents. Each of these must be REFUSED, and each for its own check.
  await check("a SAML 2.0 Response missing its required Version is " +
              "refused by xmllint", async function () {
    const r = xmllint("<samlp:Response xmlns:samlp=\"" + NS.samlp + "\" " +
                      "ID=\"_1\" IssueInstant=\"2026-01-01T00:00:00Z\">" +
                      "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:" +
                      "names:tc:SAML:2.0:status:Success\"/></samlp:Status>" +
                      "</samlp:Response>");
    if (r.ok || !/Version/.test(r.errors.join(" "))) {
      throw new Error("accepted, or refused for another reason: " +
                      r.errors.join(" | "));
    }
  });
  await check("the same Response with Version is accepted (the control)",
              async function () {
    const r = xmllint("<samlp:Response xmlns:samlp=\"" + NS.samlp + "\" " +
                      "ID=\"_1\" Version=\"2.0\" IssueInstant=\"2026-01-01T" +
                      "00:00:00Z\"><samlp:Status><samlp:StatusCode Value=\"" +
                      "urn:oasis:names:tc:SAML:2.0:status:Success\"/>" +
                      "</samlp:Status></samlp:Response>");
    if (!r.ok) {
      throw new Error(r.errors.join(" | "));
    }
  });
  await check("an element in a namespace nothing covers is refused, " +
              "though lax content would let xmllint pass it",
              async function () {
    const doc = "<s:Envelope xmlns:s=\"" + NS.soap11 + "\"><s:Body>" +
                "<x:Unknown xmlns:x=\"urn:nobody\"/></s:Body></s:Envelope>";
    if (!xmllint(doc).ok) {
      throw new Error("xmllint refused it, so this is not the lax case");
    }
    if (!coverageProblems(doc).length) {
      throw new Error("coverage found nothing");
    }
  });
  await check("a misspelled element in a covered namespace is refused, " +
              "though lax content would let xmllint pass it",
              async function () {
    const doc = "<s:Envelope xmlns:s=\"" + NS.soap11 + "\"><s:Body>" +
                "<wst:RequestSecurityTokenResponse xmlns:wst=\"" + NS.wst13 +
                "\"><wst:RequestedSecurityTokn/>" +
                "</wst:RequestSecurityTokenResponse></s:Body></s:Envelope>";
    if (!xmllint(doc).ok) {
      throw new Error("xmllint refused it, so this is not the lax case");
    }
    if (!coverageProblems(doc).length) {
      throw new Error("coverage found nothing");
    }
  });
  log.debug("Leaving selfTest().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Validating what " + base + " emits against the schemas in " +
           SCHEMA_DIR);
  must(fs.existsSync(path.join(SCHEMA_DIR, "all.xsd")),
       "no schemas at " + SCHEMA_DIR + ". The tests image builds them " +
       "(tests/Dockerfile); for a hand run, `tests/tools/fetch-xml-" +
       "schemas.sh <dir>` and STS_XML_SCHEMA_DIR=<dir>.");
  await prepareDriver();
  await selfTest();
  const dev = await makeWorld("development");
  const prod = await makeWorld("product");
  for (const w of [dev, prod]) {
    await metadata(w);
    await saml2(w);
    await saml11(w);
    await wsTrust(w);
    await wsFederation(w);
  }
  await federation(dev);
  log.info("The realms " + dev.realm + ", " + prod.realm + " and xsdf-" +
           STAMP + " are left standing (tests/CLAUDE.md, *No job removes a " +
           "realm*).");
  const bad = validated.filter(function (v) {
    return !v.ok;
  });
  log.info(validated.length + " documents validated, " + bad.length +
           " invalid.");
  if (failures.length) {
    log.error(checks + " check(s) passed, " + failures.length + " FAILED:");
    failures.forEach(function (f) {
      log.error("  ✗ " + f.split("\n")[0]);
    });
    log.debug("Leaving test(). Failed.");
    return 1;
  }
  // A FLOOR ON THE COUNT: a section that stops being called takes its
  // documents with it and the run would still say "passed".
  assert(validated.length >= 120, "only " + validated.length + " documents " +
         "were validated, so a SECTION STOPPED BEING CALLED.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
  return 0;
}

function assert(condition, message) {
  log.debug("Entering assert().");
  if (!condition) {
    log.debug("Leaving assert(). Refused.");
    throw new Error(message);
  }
  log.debug("Leaving assert().");
}

const program = new Command();
program
  .name("sts_xml_schema_validation")
  .description("Every SAML 2.0, SAML 1.1, WS-Trust and WS-Federation " +
      "document this service emits, in a development and a product realm, " +
      "validated against the published OASIS and W3C XML Schemas (#188).")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().then(function (code) {
  process.exit(code);
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
