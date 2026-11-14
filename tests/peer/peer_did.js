// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/peer/peer_did.js
//
// ===========================================================================
// A did:web HOST (#693, 2026-11-03): the https origin a person's `did:web`
// document is published on, which no job had. `oid4vc/siop.ts` fetches a
// did:web document to enrol it by proof and to sign in with it, and a
// did:web must be https (`Siop.didWebUrl()`), so until this role the fetch
// was driven only in process with a stubbed `fetchDocument`.
//
// The JOB is the person and holds the private key; the peer holds only the
// DOCUMENT the job hands it, and serves it as did:web's resolution says:
//
//   did:web:<host>%3A<port>:t:<tenant>:did:<name>
//     → https://<host>:<port>/t/<tenant>/did/<name>/did.json
//
//   * `PUT /t/{tenant}/did/{name}/did.json` — the job publishes (or
//     REPLACES, which is how a job rotates the key under a pinned
//     enrolment) the document. Its `id` must be the DID this path resolves
//     from, with the host the request named, so a job cannot publish a
//     document a resolver would refuse for its id without being told.
//   * `GET /t/{tenant}/did/{name}/did.json` — what the service fetches,
//     over the peer's TLS listener, whose CA a realm trusts through
//     `federation.outboundCaFile`. Every fetch is RECORDED (role `did`,
//     `name`, `tls`, `found`), so a job asserts how many times the service
//     dialled and when — the one fetch per enrolment, and none for a token
//     whose other checks failed.
//   * `DELETE /t/{tenant}/did/{name}/did.json` — the document is withdrawn,
//     and a fetch answers 404: a document that cannot be fetched.
//
// Nothing here is a key: the document carries public keys only, and a
// `d` member anywhere in it is refused.
// ===========================================================================

const util = require("./peer_util.js");

const log = util.logger("peer_did");

// A tenant holds at most this many documents; the oldest goes first.
const MAX_DOCUMENTS = 50;

// The path segment a document is published under.
const NAME = /^[A-Za-z0-9._-]{1,60}$/;

function configure(tenant) {
  log.debug("Entering configure().");
  tenant.did = tenant.did || { documents: new Map() };
  log.debug("Leaving configure().");
}

// The DID a document published at `name` resolves from, for a peer whose
// TLS address is `host` (name and port).
function didFor(host, tenantId, name) {
  log.debug("Entering didFor().");
  log.debug("Leaving didFor().");
  return "did:web:" + encodeURIComponent(host) + ":t:" + tenantId +
    ":did:" + name;
}

// Whether a value carries a private key member anywhere.
function holdsPrivateKey(value) {
  log.debug("Entering holdsPrivateKey().");
  if (!value || typeof value !== "object") {
    log.debug("Leaving holdsPrivateKey(). Not an object.");
    return false;
  }
  if (Array.isArray(value)) {
    const found = value.some(holdsPrivateKey);
    log.debug("Leaving holdsPrivateKey(). " + found);
    return found;
  }
  const found = Object.prototype.hasOwnProperty.call(value, "d") ||
    Object.keys(value).some(function (key) {
      return holdsPrivateKey(value[key]);
    });
  log.debug("Leaving holdsPrivateKey(). " + found);
  return found;
}

// PUT, GET or DELETE /t/{tenant}/did/{name}/did.json. `secureHost` is the
// host and port of the peer's TLS address, which is what a DID names.
function document(tenant, request, name, secureHost) {
  log.debug("Entering document(). " + request.method + " " + name);
  configure(tenant);
  if (!NAME.test(name)) {
    log.debug("Leaving document(). Bad name.");
    return { status: 400, body: { ok: false, error: "a document name is 1 " +
                                  "to 60 of A-Z a-z 0-9 . _ -" } };
  }
  const docs = tenant.did.documents;
  if (request.method === "GET") {
    const held = docs.get(name);
    tenant.record("did", { ok: !!held, name: name, tls: !!request.tls,
                           found: !!held, why: held ? "" : "no document " +
                           "is published as " + name });
    if (!held) {
      log.debug("Leaving document(). Not published.");
      return { status: 404, body: { ok: false, error: "no document " +
                                    name } };
    }
    log.debug("Leaving document(). Served.");
    return { status: 200, body: JSON.stringify(held),
             headers: { "Content-Type": "application/did+json" } };
  }
  if (request.method === "DELETE") {
    const had = docs.delete(name);
    log.debug("Leaving document(). Withdrawn: " + had);
    return { status: had ? 200 : 404, body: { ok: had } };
  }
  if (request.method !== "PUT") {
    log.debug("Leaving document(). Method.");
    return { status: 405, body: { ok: false, error: "PUT, GET or DELETE" } };
  }
  let doc;
  try {
    doc = JSON.parse(request.body.toString("utf8") || "null");
  } catch (e) {
    log.debug("Caught in document(): " + ((e && e.message) || e));
    // Said to the job, which sent it.
    log.debug("Leaving document(). Bad JSON.");
    return { status: 400, body: { ok: false, error: "the body is not " +
                                  "JSON: " + e.message } };
  }
  const wanted = didFor(secureHost, tenant.id, name);
  if (!doc || typeof doc !== "object" || Array.isArray(doc) ||
      doc.id !== wanted) {
    log.debug("Leaving document(). Wrong id.");
    return { status: 400, body: { ok: false, error: "the document's id " +
      "must be " + wanted + ", the DID this path resolves from" } };
  }
  if (holdsPrivateKey(doc)) {
    log.debug("Leaving document(). A private key.");
    return { status: 400, body: { ok: false, error: "the document carries " +
                                  "a private key member (d)" } };
  }
  if (!docs.has(name) && docs.size >= MAX_DOCUMENTS) {
    docs.delete(docs.keys().next().value);
  }
  const replaced = docs.has(name);
  docs.set(name, doc);
  log.info("peer: " + tenant.id + " did " + (replaced ? "replaced " :
           "published ") + name);
  log.debug("Leaving document().");
  return { status: 200, body: { ok: true, did: wanted,
                                replaced: replaced } };
}

module.exports = { configure: configure, document: document,
                   didFor: didFor };
