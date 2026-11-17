// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// File: bbs_w3c.js
//
// ---------------------------------------------------------------------------
// A SECOND OPINION ON A bbs-2023 CREDENTIAL, FOR THE PROTOCOL JOBS (#1878).
//
// Since 1.1.0 an ldp_vc this service issues carries a W3C Data Integrity BBS
// Cryptosuites v1.0 base proof. A base proof is the holder's to derive from
// and never a verifier's to check, so "does the credential verify" means: a
// holder derives a proof from it and a verifier accepts that. Both are done
// here by Digital Bazaar's @digitalbazaar/bbs-2023-cryptosuite — the version
// w3c/vc-di-bbs-test-suite's lockfile pins, installed in the tests image under
// /opt/vc-suites by tests/vc-suites/fetch-suites.sh — so a job checks the
// issuer with an implementation this repository did not write.
//
// The issuer's key is the Multikey its credential's verificationMethod
// dereferences to (the job fetches it); its controller document is the
// issuer's DID document where there is one, and otherwise one this helper
// states, naming that key as an assertion method — the job's trust in the
// issuer it is testing. Contexts come from the service's own copies: the
// loader fetches nothing.
// ---------------------------------------------------------------------------
"use strict";

const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");
const { createRequire } = require("module");
const paths = require("./module_paths.js");

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "bbs_w3c",
    level: process.env.LOG_LEVEL || "info" });

const SUITE = path.join(process.env.STS_VC_SUITES_DIR || "/opt/vc-suites",
                        "vc-di-bbs-test-suite");

// The service's context files, by URL: the three the issuer signs against
// and the four a Multikey and a controller document are read with.
function contexts() {
  log.debug("Entering contexts().");
  const bbs = paths.mockStsModule("bbs2023.js");
  if (!bbs) {
    log.debug("Leaving contexts(). No service tree.");
    throw new Error("bbs_w3c.js: the service's common/crypto_impl/" +
                    "bbs2023.js was not found, so neither were its contexts.");
  }
  const own = path.join(path.dirname(bbs), "contexts");
  const oid4vc = path.join(path.dirname(bbs), "..", "..", "oid4vc",
                           "contexts");
  const read = function (dir, file) {
    return JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
  };
  const out = {
    "https://www.w3.org/ns/credentials/v2": read(own, "credentials_v2.json"),
    "https://www.w3.org/2018/credentials/v1": read(own,
                                                   "credentials_v1.json"),
    "https://iyasec.io/contexts/identity/v1": read(own,
                                                   "iya_identity_v1.json"),
    "https://w3id.org/security/multikey/v1": read(oid4vc,
                                                  "multikey_v1.json"),
    "https://www.w3.org/ns/cid/v1": read(oid4vc, "cid_v1.json"),
    "https://www.w3.org/ns/did/v1": read(oid4vc, "did_v1.json"),
    "https://w3id.org/security/data-integrity/v2": read(oid4vc,
      "data_integrity_v2.json"),
    "https://w3id.org/security/suites/jws-2020/v1": read(oid4vc,
      "jws_2020_v1.json")
  };
  log.debug("Leaving contexts().");
  return out;
}

async function library() {
  log.debug("Entering library().");
  const nm = path.join(SUITE, "node_modules");
  if (!fs.existsSync(path.join(nm, "@digitalbazaar",
                               "bbs-2023-cryptosuite"))) {
    log.debug("Leaving library(). Not installed.");
    throw new Error("bbs_w3c.js: @digitalbazaar/bbs-2023-cryptosuite is " +
                    "not installed under " + SUITE + " (the tests image's " +
                    "vc-suites stage, tests/vc-suites/fetch-suites.sh).");
  }
  const req = createRequire(path.join(nm, "index.js"));
  const esm = function (name) {
    return import(pathToFileURL(path.join(nm, name, "lib",
                                          "index.js")).href);
  };
  const out = {
    jsigs: req("jsonld-signatures"),
    di: await esm("@digitalbazaar/data-integrity"),
    bbs: await esm("@digitalbazaar/bbs-2023-cryptosuite")
  };
  log.debug("Leaving library().");
  return out;
}

// Derives a proof from `credential` (revealing `selectivePointers`, the
// subject by default, under `presentationHeader`) and verifies it, both with
// Digital Bazaar's library. `keyDoc` is the Multikey the verification method
// dereferenced to; `controllerDoc`, the issuer's DID document if it has one.
// Answers `{ verified, derived, errors }`.
async function deriveAndVerify(credential, keyDoc, opts) {
  log.debug("Entering deriveAndVerify().");
  const o = opts || {};
  const lib = await library();
  const held = contexts();
  const method = String(credential.proof.verificationMethod);
  // Only what a Multikey is: the key endpoint's own members (`state`,
  // `cryptosuite`) are no term of the Multikey context.
  const vm = { "@context": "https://w3id.org/security/multikey/v1",
               id: method, type: "Multikey", controller: keyDoc.controller,
               publicKeyMultibase: keyDoc.publicKeyMultibase };
  const controller = o.controllerDoc || {
    "@context": "https://www.w3.org/ns/cid/v1",
    id: vm.controller, assertionMethod: [vm] };
  const documentLoader = async function (url) {
    if (held[url]) {
      return { contextUrl: null, documentUrl: url, document: held[url] };
    }
    if (url === method ||
        (url.split("#")[0] === controller.id && url !== controller.id)) {
      return { contextUrl: null, documentUrl: url, document: vm };
    }
    if (url === controller.id) {
      return { contextUrl: null, documentUrl: url, document: controller };
    }
    throw new Error("bbs_w3c.js: the loader holds no " + url);
  };
  const purpose = new lib.jsigs.purposes.AssertionProofPurpose();
  const derived = await lib.jsigs.derive(credential, {
    suite: new lib.di.DataIntegrityProof({
      cryptosuite: lib.bbs.createDiscloseCryptosuite({
        selectivePointers: o.selectivePointers || ["/credentialSubject/id"],
        presentationHeader: o.presentationHeader }) }),
    purpose: purpose, documentLoader: documentLoader });
  const result = await lib.jsigs.verify(derived, {
    suite: new lib.di.DataIntegrityProof({
      cryptosuite: lib.bbs.createVerifyCryptosuite() }),
    purpose: purpose, documentLoader: documentLoader });
  const errors = ((result.error || {}).errors || [result.error])
    .filter(Boolean).map(function (e) { return e.message || String(e); });
  log.debug("Leaving deriveAndVerify(). " + result.verified);
  return { verified: !!result.verified, derived: derived, errors: errors };
}

module.exports = { deriveAndVerify: deriveAndVerify, contexts: contexts };
