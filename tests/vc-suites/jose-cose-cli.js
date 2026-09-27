"use strict";
//
// File: tests/vc-suites/jose-cose-cli.js
//
// ---------------------------------------------------------------------------
// THIS SERVICE AS A W3C VC-JOSE-COSE TEST SUITE IMPLEMENTATION (#198).
//
// The suite runs an implementation as a command line (its README, "Docker
// Integration"):
//
//   <issue|verify> --input <file> --key <file> --feature <feature>
//                  [--sd '<json array of paths>'] --output <file>
//
// and reads back `{ "result": "success" | "failure" | "indeterminate" |
// "error", "data": "<secured value>" }` from the output file. This CLI is
// that, over the service's VC-API adapter (oid4vc/vc_api.ts) in the realm
// VC_API_REALM_BASE names, with the access token VC_API_TOKEN carries:
//
//   issue    POST /vc-api/issuers/<issuer>/credentials/issue, or
//            /vc-api/holders/<holder>/presentations/prove — `jose-p256`,
//            `sd-jwt-p256` or `cose-p256` by the feature. THE SERVICE SIGNS
//            WITH ITS OWN KEY AND AS ITSELF: the suite's key file carries a
//            PRIVATE key, and this service never takes one over HTTP, so the
//            document's `issuer` (or `holder`) is set to the service's own
//            did:key before it is sent, and the suite's key is not read. The
//            suite checks only the result of an issuance.
//   verify   POST /vc-api/credentials/verify or /presentations/verify, the
//            secured value wrapped as the VC Data Model's enveloped object
//            (a data: URL), and the key file's PUBLIC key named as the
//            verification method — its `secretKeyJwk` is never sent.
//
// "success" is a 2xx from the service; "failure" is the service refusing
// (a 4xx, or a verification answering verified: false); "error" is
// anything else — the service unreachable, an answer that is not JSON.
// ---------------------------------------------------------------------------

const fs = require("fs");
const https = require("https");
const http = require("http");
const bunyan = require("bunyan");

const log = bunyan.createLogger({ name: "jose-cose-cli",
                                  level: process.env.LOG_LEVEL || "info",
                                  stream: process.stderr });

const V2 = "https://www.w3.org/ns/credentials/v2";
const MECHANISM = {
  credential_jose: { name: "jose-p256", kind: "vc", type: "vc+jwt" },
  credential_sdjwt: { name: "sd-jwt-p256", kind: "vc", type: "vc+sd-jwt" },
  credential_cose: { name: "cose-p256", kind: "vc", type: "vc+cose" },
  presentation_jose: { name: "jose-p256", kind: "vp", type: "vp+jwt" },
  presentation_sdjwt: { name: "sd-jwt-p256", kind: "vp", type: "vp+sd-jwt" },
  presentation_cose: { name: "cose-p256", kind: "vp", type: "vp+cose" }
};

// The container paths the suite names, mapped onto its own tests/ tree.
function hostPath(p) {
  log.debug("Entering hostPath().");
  const dir = process.env.VC_JOSE_COSE_SUITE_DIR || process.cwd();
  log.debug("Leaving hostPath().");
  return String(p).replace(/^\/tests\//, dir.replace(/\/+$/, "") +
                           "/tests/");
}

function parseArgs(argv) {
  log.debug("Entering parseArgs().");
  const out = { fn: argv[0] };
  for (let i = 1; i < argv.length; i++) {
    const name = String(argv[i]).replace(/^--/, "");
    out[name] = argv[i + 1];
    i += 1;
  }
  log.debug("Leaving parseArgs().");
  return out;
}

function request(method, url, body) {
  log.debug("Entering request(). " + method + " " + url);
  log.debug("Leaving request().");
  return new Promise(function (resolve, reject) {
    const u = new URL(url);
    const mod = u.protocol === "http:" ? http : https;
    const payload = body === undefined ? null : JSON.stringify(body);
    const headers = { Accept: "application/json",
                      Authorization: "Bearer " + process.env.VC_API_TOKEN };
    if (payload !== null) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }
    const r = mod.request({ hostname: u.hostname, port: u.port,
                            path: u.pathname + u.search, method: method,
                            headers: headers }, function (res) {
      let text = "";
      res.on("data", function (c) {
        text += c;
      });
      res.on("end", function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in request(): " + ((e && e.message) || e));
          json = null;
        }
        resolve({ status: res.statusCode, json: json, text: text });
      });
    });
    r.on("error", reject);
    if (payload !== null) {
      r.write(payload);
    }
    r.end();
  });
}

// The service's own identifier for a mechanism, from its issuer list.
async function ownId(base, name) {
  log.debug("Entering ownId(). " + name);
  const r = await request("GET", base + "/vc-api/issuers");
  const row = (((r.json || {}).issuers) || []).filter(function (one) {
    return one.name === name;
  })[0];
  if (!row) {
    log.debug("Leaving ownId(). None.");
    throw new Error("the service offers no issuer " + name + " (" +
                    r.status + ")");
  }
  log.debug("Leaving ownId().");
  return row.id;
}

// The secured value inside an envelope's data: URL.
function unwrap(envelope) {
  log.debug("Entering unwrap().");
  const m = /^data:([^,;]*)(;base64)?,(.*)$/s.exec(String(envelope &&
                                                           envelope.id));
  log.debug("Leaving unwrap().");
  return m ? m[3] : "";
}

async function issue(args, mech, base) {
  log.debug("Entering issue().");
  const doc = JSON.parse(fs.readFileSync(hostPath(args.input), "utf8"));
  const id = await ownId(base, mech.name);
  const options = {};
  if (args.sd) {
    options.disclosurePaths = JSON.parse(args.sd);
  }
  let r;
  if (mech.kind === "vc") {
    if (doc.issuer && typeof doc.issuer === "object") {
      doc.issuer.id = id;
    } else {
      doc.issuer = id;
    }
    r = await request("POST", base + "/vc-api/issuers/" + mech.name +
                      "/credentials/issue", { credential: doc,
                                              options: options });
  } else {
    if (doc.holder !== undefined) {
      doc.holder = id;
    }
    r = await request("POST", base + "/vc-api/holders/" + mech.name +
                      "/presentations/prove", { presentation: doc,
                                                options: options });
  }
  const secured = r.json && (r.json.verifiableCredential ||
                             r.json.verifiablePresentation);
  log.info("issue " + mech.type + ": " + r.status + " " +
           (r.status >= 300 ? r.text.slice(0, 400) : ""));
  log.debug("Leaving issue().");
  if (r.status >= 200 && r.status < 300 && secured) {
    return { result: "success", data: unwrap(secured) };
  }
  return { result: r.status >= 400 && r.status < 500 ? "failure" : "error",
           data: "" };
}

async function verify(args, mech, base) {
  log.debug("Entering verify().");
  const raw = fs.readFileSync(hostPath(args.input), "utf8").trim();
  const key = JSON.parse(fs.readFileSync(hostPath(args.key), "utf8"));
  const options = { verificationMethod: { id: key.id, type: key.type,
    controller: key.controller, publicKeyJwk: key.publicKeyJwk } };
  let document;
  if (/\.json$/.test(String(args.input))) {
    // An unsecured document: sent as it is, which the verifier refuses.
    document = JSON.parse(raw);
  } else {
    const cose = /cose$/.test(mech.type);
    document = { "@context": V2,
                 type: mech.kind === "vc" ? "EnvelopedVerifiableCredential"
                                          : "EnvelopedVerifiablePresentation",
                 id: "data:application/" + mech.type +
                     (cose ? ";base64," : ",") + raw };
  }
  const r = mech.kind === "vc"
    ? await request("POST", base + "/vc-api/credentials/verify",
                    { verifiableCredential: document, options: options })
    : await request("POST", base + "/vc-api/presentations/verify",
                    { verifiablePresentation: document, options: options });
  log.info("verify " + mech.type + ": " + r.status + " " +
           JSON.stringify((r.json && r.json.errors) || []).slice(0, 600));
  log.debug("Leaving verify().");
  if (r.status === 200 && r.json && r.json.verified === true) {
    return { result: "success", data: raw };
  }
  return { result: r.status === 400 || (r.json && r.json.verified === false)
    ? "failure" : "error", data: raw };
}

async function main() {
  log.debug("Entering main().");
  const args = parseArgs(process.argv.slice(2));
  const mech = MECHANISM[args.feature];
  const base = String(process.env.VC_API_REALM_BASE || "").replace(/\/+$/,
                                                                    "");
  let out;
  try {
    if (!mech || !base || !args.output) {
      throw new Error("usage: issue|verify --input --key --feature " +
                      "[--sd] --output, with VC_API_REALM_BASE set");
    }
    out = args.fn === "issue" ? await issue(args, mech, base)
                              : await verify(args, mech, base);
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.error(e.stack || e.message);
    out = { result: "error", data: "" };
  }
  if (args.output) {
    fs.writeFileSync(hostPath(args.output), JSON.stringify(out));
  }
  log.debug("Leaving main().");
}

main();
