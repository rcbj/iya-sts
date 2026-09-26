"use strict";
//
// File: tests/vc-suites/offline-contexts.cjs
//
// ---------------------------------------------------------------------------
// THE W3C VC SUITES' JSON-LD CONTEXTS, ANSWERED FROM THIS REPOSITORY'S
// COPIES RATHER THAN FETCHED (#194-#197). A mocha --require hook.
//
// The Data Integrity suites' document loaders fetch any `https:` context
// they hold no static copy of from the web — the VC 2.0 and examples
// contexts among them — at TEST time, so a run depended on w3.org being
// reachable from the runner, and a context changed upstream between two runs
// would change what was signed. This wraps `globalThis.fetch` (what their
// HTTP client, ky, calls) so that the context URLs this service itself holds
// (oid4vc/vc_jsonld.ts: byte-for-byte copies, each held to its SHA-256 by
// tests/vc_jsonld.js) are answered from those files. Every other request —
// the service's own endpoints above all — goes through untouched; an
// external URL that is NOT one of them is logged, so a new dependency on the
// network is seen rather than silently tolerated.
//
// It changes no assertion: the suite reads the same bytes it would have
// fetched.
// ---------------------------------------------------------------------------

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..", "..");
const OWN = path.join(ROOT, "oid4vc", "contexts");
const VENDORED = path.join(ROOT, "common", "vendored", "contexts");

const FILES = {
  "https://www.w3.org/ns/credentials/v2": [VENDORED, "credentials_v2.json"],
  "https://www.w3.org/2018/credentials/v1": [VENDORED,
                                             "credentials_v1.json"],
  "https://www.w3.org/ns/credentials/examples/v2": [OWN,
    "credentials_examples_v2.json"],
  "https://w3id.org/security/data-integrity/v1": [OWN,
                                                  "data_integrity_v1.json"],
  "https://w3id.org/security/data-integrity/v2": [OWN,
                                                  "data_integrity_v2.json"],
  "https://w3id.org/security/multikey/v1": [OWN, "multikey_v1.json"],
  "https://www.w3.org/ns/did/v1": [OWN, "did_v1.json"],
  "https://www.w3.org/ns/cid/v1": [OWN, "cid_v1.json"],
  "https://w3id.org/security/v1": [OWN, "security_v1.json"],
  "https://w3id.org/security/v2": [OWN, "security_v2.json"],
  "https://w3id.org/security/suites/ed25519-2020/v1": [OWN,
                                                       "ed25519_2020_v1.json"],
  "https://w3id.org/security/suites/jws-2020/v1": [OWN, "jws_2020_v1.json"],
  "https://w3id.org/vc/status-list/2021/v1": [OWN, "status_list_2021_v1.json"],
  "https://w3id.org/citizenship/v4rc1": [OWN, "citizenship_v4rc1.json"]
};

// Called for every request the suite makes, so no Entering/Leaving pair — the
// hot-path exception, stated as the style requires; and this runs inside the
// third-party suite's own process, where no logger of this service exists.
const original = globalThis.fetch;
const own = String(process.env.VC_API_REALM_BASE || "");

function offlineFetch(input, init) {
  const url = typeof input === "string" ? input
    : (input && (input.url || String(input))) || "";
  const key = url.replace(/#.*$/, "");
  const where = FILES[key];
  if (where) {
    const body = fs.readFileSync(path.join(where[0], where[1]));
    return Promise.resolve(new Response(body, { status: 200,
      headers: { "Content-Type": "application/ld+json" } }));
  }
  if (/^https?:/.test(url) && (!own || url.indexOf(new URL(own).origin) !== 0)) {
    process.stderr.write("offline-contexts: fetching " + url +
                         " from the network\n");
  }
  return original(input, init);
}

globalThis.fetch = offlineFetch;
