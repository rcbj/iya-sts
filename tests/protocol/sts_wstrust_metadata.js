// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_metadata.js
//
// ===========================================================================
// THE WS-TRUST METADATA, AS A CLIENT READS IT (#958; #444 D12, phase 7).
//
// `tests/wstrust_metadata.js` builds the documents from the model with the
// flags it chooses. Here they are fetched from a running service, in a
// development and a product realm of the job's own, with the flags set
// through the realm's settings:
//
//   V. GET /sts/metadata is WSDL 1.1 (application/wsdl+xml, no-store): a
//      port type per trust version, oldest first, each with the operations
//      its version defines (May 2004 has no Cancel), each operation reading
//      its version's RST and answering its RSTR (an RSTRC for a 1.3/1.4
//      Issue), WS-Trust's input action and the output action an RSTR
//      carries; eight ports at the realm's /sts; a schema per trust
//      namespace; the capability document and WS-MEX named, optionally.
//   C. GET /sts/metadata/capabilities (#958's extension): every credential
//      in the order the endpoint reads them, every issued type, every pair
//      written out; Kerberos unsupported while `wstrust.issueKerberos` is
//      off and conditional (transport, target) once on; a disabled
//      credential unsupported for every output, naming its setting; the
//      empty credential only in development; validated by xmllint against
//      the schema the service publishes beside it.
//   M. POST /sts/mex: a WS-Transfer Get in SOAP 1.2 and WS-Addressing 1.0
//      (three sections, GetResponse, RelatesTo), a GetMetadata in SOAP 1.1
//      and 2004/08 addressing narrowed by Dialect, an unknown dialect an
//      empty Metadata, and the two faults (STS-WSTRUST-0072 a Client fault
//      at 400, 0073 a Sender fault), the codes on the audit log and never
//      in the answer.
//   W. the WSDL validates with `xmllint --nonet` against the published
//      schemas (tests/tools/fetch-xml-schemas.sh's directory,
//      STS_XML_SCHEMA_DIR, as `sts_xml_schema_validation.js` reads it).
//   F. the WSDL is formatted: one element a line, each two spaces deeper
//      than its parent; so is the WSDL inside a WS-MEX answer.
//
// NOT HERE: the model's own tables and the escaping of an issuer name no
// request can set (the in-process file's builders) are (d).
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const childProcess = require("child_process");
const { DOMParser } = require("@xmldom/xmldom");
const K = require("./oauth_wire_kit.js").kit("sts_wstrust_metadata");

const log = K.log;
const WSDL = "http://schemas.xmlsoap.org/wsdl/";
const WSAM = "http://www.w3.org/2007/05/addressing/metadata";
const MEX = "http://schemas.xmlsoap.org/ws/2004/09/mex";
const CAP = "urn:iya-sts:metadata:token-capabilities:1";
const SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP12 = "http://www.w3.org/2003/05/soap-envelope";
const WSA10 = "http://www.w3.org/2005/08/addressing";
const WSA04 = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
const T2004 = "http://schemas.xmlsoap.org/ws/2004/04/trust";
const T2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust";
const T13 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
const T14 = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";
const SCHEMA_DIR = process.env.STS_XML_SCHEMA_DIR || "/opt/xml-schemas";

function xmllint(xml, schemaFile) {
  log.debug("Entering xmllint().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sts-wsmd-"));
  try {
    const doc = path.join(dir, "doc.xml");
    fs.writeFileSync(doc, xml);
    const args = ["--noout", "--nonet"];
    if (schemaFile) {
      args.push("--schema", schemaFile);
    }
    args.push(doc);
    const run = childProcess.spawnSync("xmllint", args,
      { encoding: "utf8", env: Object.assign({}, process.env,
        { XML_CATALOG_FILES: path.join(SCHEMA_DIR, "catalog.xml") }) });
    log.debug("Leaving xmllint(). " + run.status);
    return { ok: run.status === 0,
             errors: String(run.stderr || (run.error && run.error.message) ||
                            "") };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function parse(xml) {
  log.debug("Entering parse().");
  log.debug("Leaving parse().");
  return new DOMParser().parseFromString(xml, "application/xml");
}

function elements(root, ns, name) {
  log.debug("Entering elements().");
  const out = [];
  const all = root.getElementsByTagNameNS(ns, name);
  for (let i = 0; i < all.length; i += 1) {
    out.push(all[i]);
  }
  log.debug("Leaving elements().");
  return out;
}

function envelope(soapNs, wsaNs, action, body, messageId) {
  log.debug("Entering envelope().");
  log.debug("Leaving envelope().");
  return '<s:Envelope xmlns:s="' + soapNs + '" xmlns:a="' + wsaNs +
    '"><s:Header>' + (action ? "<a:Action>" + action + "</a:Action>" : "") +
    (messageId ? "<a:MessageID>" + messageId + "</a:MessageID>" : "") +
    "</s:Header><s:Body>" + (body || "") + "</s:Body></s:Envelope>";
}

// ----------------------------------------------------------------- V, W, F
async function wsdl(id, label) {
  log.debug("Entering wsdl(). " + label);
  const rb = K.rb(id);
  const r = await K.send(rb + "/sts/metadata");
  K.check("V0 (" + label + "). GET /sts/metadata is WSDL, no-store",
          function () {
            assert.strictEqual(r.status, 200);
            assert.ok(/^application\/wsdl\+xml/.test(
              r.headers.get("content-type")), r.headers.get("content-type"));
            assert.ok(/no-store/.test(r.headers.get("cache-control")));
          });
  const xml = r.text;
  const root = parse(xml).documentElement;
  const want = {
    TrustMay2004: { ns: T2004, cancel: false, collection: false },
    TrustFeb2005: { ns: T2005, cancel: true, collection: false },
    Trust13: { ns: T13, cancel: true, collection: true },
    Trust14: { ns: T13, cancel: true, collection: true }
  };
  const messages = {};
  elements(root, WSDL, "message").forEach(function (one) {
    const part = elements(one, WSDL, "part")[0];
    const qname = String(part.getAttribute("element"));
    messages[one.getAttribute("name")] = {
      ns: root.lookupNamespaceURI(qname.split(":")[0]),
      local: qname.split(":")[1] };
  });
  const portTypes = elements(root, WSDL, "portType");
  K.check("V1 (" + label + "). one port type per trust version, oldest " +
          "first", function () {
    assert.strictEqual(portTypes.map(function (one) {
      return one.getAttribute("name");
    }).join(" "), "TrustMay2004 TrustFeb2005 Trust13 Trust14");
  });
  for (const portType of portTypes) {
    const name = portType.getAttribute("name");
    const v = want[name];
    const ops = elements(portType, WSDL, "operation");
    K.check("V2 (" + label + "). " + name + " has the operations its " +
            "version defines; each reads its version's RST and answers its " +
            "RSTR, with WS-Trust's actions", function () {
      assert.strictEqual(ops.map(function (one) {
        return one.getAttribute("name");
      }).join(" "), v.cancel ? "Issue Renew Validate Cancel"
                             : "Issue Renew Validate");
      for (const op of ops) {
        const opName = op.getAttribute("name");
        const input = elements(op, WSDL, "input")[0];
        const output = elements(op, WSDL, "output")[0];
        const inMsg = messages[String(input.getAttribute("message"))
          .split(":")[1]];
        const outMsg = messages[String(output.getAttribute("message"))
          .split(":")[1]];
        assert.ok(inMsg && inMsg.ns === v.ns &&
                  inMsg.local === "RequestSecurityToken",
                  opName + " " + JSON.stringify(inMsg));
        const outLocal = opName === "Issue" && v.collection
          ? "RequestSecurityTokenResponseCollection"
          : "RequestSecurityTokenResponse";
        assert.ok(outMsg && outMsg.ns === v.ns && outMsg.local === outLocal,
                  opName + " " + JSON.stringify(outMsg));
        assert.strictEqual(input.getAttributeNS(WSAM, "Action"),
                           v.ns + "/RST/" + opName);
        const outAction = v.collection
          ? (opName === "Issue" ? v.ns + "/RSTRC/IssueFinal"
                                : v.ns + "/RSTR/" + opName + "Final")
          : v.ns + "/RSTR/" + opName;
        assert.strictEqual(output.getAttributeNS(WSAM, "Action"),
                           outAction, name + " " + opName);
      }
    });
  }
  const ports = elements(root, WSDL, "port");
  K.check("V3 (" + label + "). eight ports, each version over SOAP 1.1 " +
          "and 1.2, every one at the realm's /sts", function () {
    assert.strictEqual(ports.length, 8);
    for (const port of ports) {
      const address = port.getElementsByTagNameNS("*", "address")[0];
      assert.strictEqual(address.getAttribute("location"), rb + "/sts");
    }
  });
  const schemas = elements(root, "http://www.w3.org/2001/XMLSchema",
                           "schema").map(function (one) {
    return one.getAttribute("targetNamespace");
  });
  K.check("V4 (" + label + "). a schema per trust namespace (1.4's for " +
          "ActAs), and the capability document and WS-MEX named " +
          "optionally", function () {
    for (const ns of [T2004, T2005, T13, T14]) {
      assert.ok(schemas.indexOf(ns) >= 0, ns + " in " + schemas.join(" "));
    }
    assert.ok(xml.indexOf('location="' + rb + '/sts/metadata/capabilities"')
              >= 0);
    assert.ok(xml.indexOf('metadataExchange="' + rb + '/sts/mex"') >= 0);
    assert.ok(xml.indexOf('wsdl:required="false"') >= 0);
  });
  const lint = xmllint(xml, path.join(SCHEMA_DIR, "all.xsd"));
  K.check("W (" + label + "). the WSDL validates against the published " +
          "schemas (" + SCHEMA_DIR + ")", function () {
    assert.ok(fs.existsSync(path.join(SCHEMA_DIR, "all.xsd")),
              "no published schemas in " + SCHEMA_DIR +
              " (tests/tools/fetch-xml-schemas.sh <dir>)");
    assert.ok(lint.ok, lint.errors.slice(0, 600));
  });
  formatted(xml, label);
  log.debug("Leaving wsdl().");
}

function formatted(xml, label) {
  log.debug("Entering formatted().");
  const lines = xml.replace(/\n$/, "").split("\n");
  K.check("F1/F2 (" + label + "). the WSDL is on many lines, no line " +
          "opening more than one element", function () {
    assert.ok(lines.length > 200, lines.length + " lines");
    const two = lines.filter(function (line) {
      return (line.match(/<[A-Za-z]/g) || []).length > 1;
    });
    assert.strictEqual(two.length, 0, two[0]);
  });
  let depth = 0;
  const misplaced = [];
  for (const line of lines) {
    const body = line.trim();
    if (/^<\//.test(body)) {
      depth -= 1;
    }
    if (!/^<\?/.test(body) && line.length - body.length !== 2 * depth) {
      misplaced.push(line.slice(0, 80));
    }
    if (/^<[A-Za-z]/.test(body) && !/\/>$/.test(body) &&
        !/<\/[^>]+>$/.test(body)) {
      depth += 1;
    }
  }
  K.check("F3 (" + label + "). each element is two spaces deeper than its " +
          "parent", function () {
    assert.ok(misplaced.length === 0 && depth === 0,
              misplaced[0] || ("ended at depth " + depth));
  });
  log.debug("Leaving formatted().");
}

// --------------------------------------------------------------------- C
function capabilityModel(xml) {
  log.debug("Entering capabilityModel().");
  const root = parse(xml).documentElement;
  const ids = function (name) {
    return elements(root, CAP, name).map(function (one) {
      return one.getAttribute("id");
    });
  };
  const pairs = elements(root, CAP, "Combination").map(function (one) {
    return { input: one.getAttribute("input"),
             output: one.getAttribute("output"),
             support: one.getAttribute("support"),
             conditions: elements(one, CAP, "Condition").map(function (c) {
               return { kind: c.getAttribute("kind"),
                        setting: c.getAttribute("setting") };
             }) };
  });
  const inputs = {};
  elements(root, CAP, "InputToken").forEach(function (one) {
    inputs[one.getAttribute("id")] = one.getAttribute("enabled");
  });
  log.debug("Leaving capabilityModel().");
  return { inputs: ids("InputToken"), outputs: ids("OutputToken"),
           enabled: inputs, pairs: pairs,
           pair: function (i, o) {
             return pairs.filter(function (one) {
               return one.input === i && one.output === o;
             })[0];
           } };
}

async function capabilities(D, P) {
  log.debug("Entering capabilities().");
  log.info("=== C. the token capability document ===");
  const fetchModel = async function (id) {
    const r = await K.send(K.rb(id) + "/sts/metadata/capabilities");
    assert.strictEqual(r.status, 200, r.text.slice(0, 200));
    return { r: r, m: capabilityModel(r.text) };
  };
  const xsd = await K.send(K.rb(D) + "/sts/metadata/capabilities.xsd");
  const schemaFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(),
                                                        "sts-cap-")), "c.xsd");
  fs.writeFileSync(schemaFile, xsd.text);
  let got = await fetchModel(D);
  let m = got.m;
  K.check("C1. every credential in the order the endpoint reads them, " +
          "every issued type, every pair written out", function () {
    assert.strictEqual(m.inputs.join(" "), "x509-signature username-token " +
                       "saml2 saml11 jwt kerberos tls-client-certificate none");
    assert.strictEqual(m.outputs.join(" "), "saml2 saml11 jwt kerberos");
    assert.strictEqual(m.pairs.length, m.inputs.length * 4);
  });
  K.check("C2. every credential to SAML 2.0, SAML 1.1 and a JWT is " +
          "supported; Kerberos unsupported while issueKerberos is off",
          function () {
            for (const o of ["saml2", "saml11", "jwt"]) {
              for (const i of m.inputs) {
                assert.strictEqual(m.pair(i, o).support, "supported",
                                   i + " -> " + o);
              }
            }
            assert.strictEqual(m.pair("username-token", "kerberos").support,
                               "unsupported");
          });
  const lint = xmllint(got.r.text, schemaFile);
  K.check("C3. the document validates against the schema published " +
          "beside it", function () {
    assert.strictEqual(xsd.status, 200);
    assert.ok(lint.ok, lint.errors.slice(0, 500));
  });
  await K.set(D, "wstrust.issueKerberos", true);
  await K.set(D, "wstrust.acceptKerberos", false);
  await K.set(D, "wstrust.acceptClientCertificate", false);
  got = await fetchModel(D);
  m = got.m;
  K.check("C4. once issued, Kerberos is conditional on the transport and " +
          "a Kerberos target", function () {
    const k = m.pair("jwt", "kerberos");
    assert.strictEqual(k.support, "conditional", JSON.stringify(k));
    assert.strictEqual(k.conditions.map(function (one) {
      return one.kind;
    }).join(" "), "transport target");
  });
  K.check("C5. a disabled credential is unsupported for every output, " +
          "and names the setting that disables it", function () {
    for (const i of ["kerberos", "tls-client-certificate"]) {
      for (const o of m.outputs) {
        assert.strictEqual(m.pair(i, o).support, "unsupported", i + o);
      }
    }
    assert.strictEqual(m.pair("kerberos", "saml2").conditions[0].setting,
                       "wstrust.acceptKerberos");
  });
  const lintOn = xmllint(got.r.text, schemaFile);
  K.check("C6. the document with Kerberos issued validates too",
          function () {
            assert.ok(lintOn.ok, lintOn.errors.slice(0, 500));
          });
  for (const key of ["wstrust.issueKerberos", "wstrust.acceptKerberos",
                     "wstrust.acceptClientCertificate"]) {
    await K.unset(D, key);
  }
  const prod = (await fetchModel(P)).m;
  K.check("C7. the empty credential only in development: product " +
          "supports nothing from it", function () {
    for (const o of prod.outputs) {
      assert.strictEqual(prod.pair("none", o).support, "unsupported",
                         "none -> " + o);
    }
    assert.strictEqual(m.pair("none", "saml2").support === "unsupported",
                       false, "development lost the empty credential");
  });
  const wsdlText = (await K.send(K.rb(D) + "/sts/metadata")).text;
  K.check("C8. the WSDL names the capability document's address the " +
          "route answers", function () {
    assert.ok(wsdlText.indexOf(K.rb(D) + "/sts/metadata/capabilities") > 0);
  });
  log.debug("Leaving capabilities().");
}

// --------------------------------------------------------------------- M
async function mex(D) {
  log.debug("Entering mex().");
  log.info("=== M. WS-MetadataExchange ===");
  const at = K.rb(D) + "/sts/mex";
  const post = function (body, soap11) {
    return K.send(at, { method: "POST", raw: body, headers: {
      "Content-Type": soap11 ? "text/xml; charset=utf-8"
                             : "application/soap+xml" } });
  };
  const sectionsOf = function (body) {
    return elements(parse(body).documentElement, MEX, "MetadataSection")
      .map(function (one) {
        return one.getAttribute("Dialect");
      });
  };
  const get = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get";
  const getMetadata = MEX + "/GetMetadata/Request";
  const all = await post(envelope(SOAP12, WSA10, get, "", "urn:uuid:1"));
  K.check("M1. a WS-Transfer Get in SOAP 1.2 is answered in SOAP 1.2, " +
          "GetResponse, RelatesTo, the request's addressing", function () {
    assert.strictEqual(all.status, 200, all.text.slice(0, 300));
    assert.ok(/^application\/soap\+xml/.test(all.headers.get(
      "content-type")));
    assert.ok(all.text.indexOf('xmlns:soap="' + SOAP12 + '"') >= 0);
    assert.ok(all.text.indexOf("/transfer/GetResponse</wsa:Action>") > 0);
    assert.ok(all.text.indexOf("<wsa:RelatesTo>urn:uuid:1</wsa:RelatesTo>") >
              0);
    assert.ok(all.text.indexOf('xmlns:wsa="' + WSA10 + '"') > 0);
  });
  K.check("M2. three sections: the WSDL, the capabilities and their " +
          "schema; the WSDL in it indented", function () {
    assert.strictEqual(sectionsOf(all.text).join(" "), WSDL + " " + CAP +
                       " http://www.w3.org/2001/XMLSchema");
    assert.ok(all.text.indexOf("\n  <wsdl:types>") > 0 ||
              /\n\s+<wsdl:types>/.test(all.text), "the WSDL is not indented");
  });
  const narrowed = await post(envelope(SOAP11, WSA04, getMetadata,
    '<m:GetMetadata xmlns:m="' + MEX + '"><m:Dialect>' + WSDL +
    "</m:Dialect></m:GetMetadata>"), true);
  K.check("M3. a GetMetadata in SOAP 1.1 and 2004/08 addressing is " +
          "answered so, narrowed by its Dialect to the WSDL", function () {
    assert.strictEqual(narrowed.status, 200, narrowed.text.slice(0, 300));
    assert.ok(/^text\/xml/.test(narrowed.headers.get("content-type")));
    assert.ok(narrowed.text.indexOf('xmlns:wsa="' + WSA04 + '"') > 0);
    assert.ok(narrowed.text.indexOf("/GetMetadata/Response</wsa:Action>") >
              0);
    assert.strictEqual(sectionsOf(narrowed.text).join(" "), WSDL);
  });
  const none = await post(envelope(SOAP11, WSA10, getMetadata,
    '<m:GetMetadata xmlns:m="' + MEX + '"><m:Dialect>urn:nothing' +
    "</m:Dialect></m:GetMetadata>"), true);
  K.check("M4. an unknown dialect is an empty Metadata, not a fault",
          function () {
            assert.strictEqual(none.status, 200);
            assert.strictEqual(sectionsOf(none.text).length, 0);
          });
  const notSoap = await K.coded(D, "STS-WSTRUST-0072", function () {
    return post("<x/>", true);
  });
  K.check("M5. a body that is not SOAP is a Client fault at 400, recorded " +
          "STS-WSTRUST-0072, the code not sent", function () {
    assert.strictEqual(notSoap.answer.status, 400);
    assert.ok(/soap:Client/.test(notSoap.answer.text));
    assert.ok(!/STS-/.test(notSoap.answer.text));
    assert.ok(notSoap.rose >= 1);
  });
  const other = await K.coded(D, "STS-WSTRUST-0073", function () {
    return post(envelope(SOAP12, WSA10, "urn:something-else", ""));
  });
  K.check("M6. another action is a Sender fault in SOAP 1.2, the fault " +
          "action, recorded STS-WSTRUST-0073", function () {
    assert.strictEqual(other.answer.status, 500);
    assert.ok(/soap:Sender/.test(other.answer.text));
    assert.ok(/\/fault<\/wsa:Action>/.test(other.answer.text));
    assert.ok(!/STS-/.test(other.answer.text));
    assert.ok(other.rose >= 1);
  });
  log.debug("Leaving mex().");
}

async function test() {
  log.debug("Entering test().");
  const D = await K.realm("wm-d", "development");
  const P = await K.realm("wm-p", "product");
  await wsdl(D, "development");
  await wsdl(P, "product");
  await capabilities(D, P);
  await mex(D);
  log.debug("Leaving test().");
}

K.main(test, 30);
