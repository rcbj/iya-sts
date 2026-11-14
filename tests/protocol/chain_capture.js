// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: chain_capture.js
//
// ---------------------------------------------------------------------------
// AN OPTIONAL RECORD OF WHAT EACH CHAIN JOB WAS ISSUED, LAYER BY LAYER. rcbj
// wants a spreadsheet of the token, assertion or ticket issued at each layer
// of the four-tier chain (bob -> webapp1 -> apigw1 -> esb1 -> sp1), for each
// protocol and use case. The chain kits (`token_exchange_chain_kit.js`,
// `wstrust_chain_kit.js`, `kerberos_chain_kit.js`, and the GNAP kit built
// with the same shape) call this module where a hop's artifact arrives, and
// this module writes it down.
//
// OFF UNLESS ASKED. Only when STS_CHAIN_CAPTURE names a directory does a job
// write `<job name>.json` there (the job name is the script's basename). With
// the variable unset every function below returns at once and nothing is
// written, so a job runs exactly as it did. AND IT NEVER FAILS A JOB: every
// public function catches what it throws, logs it and carries on — a capture
// is a by-product of a run, never a reason for one to go red.
//
// THE FILE:
//
//   { protocol, useCase: "impersonation" | "delegation", service, mode,
//     job, capturedAt, layers: [ { hop, requester, target, mechanism, kind,
//     format, value, header, claims, actChain, notes }, ... ] }
//
// It is REWRITTEN WHOLE after every layer, synchronously, so a job that dies
// half-way leaves the layers it got, and a job that passes leaves them all.
//
// `actChain` is ALWAYS OLDEST FIRST, whatever the protocol's own order:
// RFC 8693's `act` nests the current actor outermost, a SAML Delegation
// Restriction lists delegates least to most recent, and S4UTransitedServices
// oldest first. One order makes the spreadsheet's column read one way.
//
// WHAT IS NEVER WRITTEN: a private key, a client secret, a password, a keytab
// or a session key. The kits never hand one over; `scrub()` below is the
// second line, dropping any member whose NAME says it is one, and a JWK's
// private members wherever a JWK appears.
//
// OWNED HERE (a LOCAL helper, tests/vendored/MANIFEST.js).
// ---------------------------------------------------------------------------

const fs = require("fs");
const path = require("path");

var bunyan = require("bunyan");
var log = bunyan.createLogger({
  name: "chain_capture",
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).LOG_LEVEL || "info";
    } catch (e) {
      // A hand run without CONFIG_FILE still loads; the level falls back.
      return "info";
    }
  })()
});

// The one record this process is building. A job is one process, so one
// record is one file.
const record = {
  protocol: "",
  useCase: "",
  service: "",
  mode: "",
  job: "",
  capturedAt: "",
  layers: []
};

// Members dropped by name, at any depth.
const SECRET_NAME = /secret|password|passwd|keytab|private|session_?key|^key$/i;
// A JWK's private members; dropped only from an object with a `kty`.
const JWK_PRIVATE = ["d", "p", "q", "dp", "dq", "qi", "k", "priv", "seed"];

function directory() {
  log.debug("Entering directory().");
  const out = String(process.env.STS_CHAIN_CAPTURE || "").trim();
  log.debug("Leaving directory().");
  return out;
}

function enabled() {
  log.debug("Entering enabled().");
  log.debug("Leaving enabled().");
  return directory() !== "";
}

function jobName() {
  log.debug("Entering jobName().");
  const script = process.argv[1] || "chain";
  log.debug("Leaving jobName().");
  return path.basename(script, path.extname(script));
}

// A copy that JSON can hold: bytes as base64, a BigInt as a string, and
// every secret-named member, and a JWK's private members, left out.
function scrub(value, depth) {
  log.debug("Entering scrub().");
  const level = depth || 0;
  if (level > 40) {
    log.debug("Leaving scrub(). Too deep.");
    return "(nested too deeply to record)";
  }
  if (value === null || value === undefined) {
    log.debug("Leaving scrub().");
    return value === undefined ? null : value;
  }
  if (typeof value === "bigint") {
    log.debug("Leaving scrub().");
    return value.toString();
  }
  if (value instanceof Uint8Array) {
    log.debug("Leaving scrub().");
    return Buffer.from(value).toString("base64");
  }
  if (value instanceof Date) {
    log.debug("Leaving scrub().");
    return isNaN(value.getTime()) ? String(value) : value.toISOString();
  }
  if (Array.isArray(value)) {
    log.debug("Leaving scrub().");
    return value.map(function (one) {
      return scrub(one, level + 1);
    });
  }
  if (typeof value === "object") {
    const jwk = typeof value.kty === "string";
    const out = {};
    Object.keys(value).forEach(function (name) {
      if (SECRET_NAME.test(name) ||
          (jwk && JWK_PRIVATE.indexOf(name) >= 0)) {
        return;
      }
      if (typeof value[name] === "function") {
        return;
      }
      out[name] = scrub(value[name], level + 1);
    });
    log.debug("Leaving scrub().");
    return out;
  }
  log.debug("Leaving scrub().");
  return value;
}

function write() {
  log.debug("Entering write().");
  const dir = directory();
  if (!dir) {
    log.debug("Leaving write(). Not capturing.");
    return;
  }
  try {
    fs.mkdirSync(dir, { recursive: true });
    record.job = record.job || jobName();
    record.capturedAt = new Date().toISOString();
    const file = path.join(dir, record.job + ".json");
    fs.writeFileSync(file + ".tmp", JSON.stringify(record, null, 2) + "\n");
    fs.renameSync(file + ".tmp", file);
  } catch (e) {
    log.debug("Caught in write(): " + ((e && e.message) || e));
    // A capture that cannot be written is reported and the job goes on.
    log.warn("[capture] could not write the capture file: " +
             ((e && e.message) || e));
  }
  log.debug("Leaving write().");
}

// The record's own fields: protocol, useCase, service, mode. Called by a kit
// as it learns each one; a later call overwrites an earlier one.
function set(fields) {
  log.debug("Entering set().");
  if (!enabled()) {
    log.debug("Leaving set(). Not capturing.");
    return;
  }
  try {
    ["protocol", "useCase", "service", "mode"].forEach(function (name) {
      if (fields && fields[name] !== undefined && fields[name] !== null &&
          fields[name] !== "") {
        record[name] = String(fields[name]);
      }
    });
    write();
  } catch (e) {
    log.debug("Caught in set(): " + ((e && e.message) || e));
  }
  log.debug("Leaving set().");
}

// One layer, in the order the chain produced it. Every field the file names
// is present on every layer, null where there is nothing to say.
function layer(fields) {
  log.debug("Entering layer(). " + ((fields && fields.hop) || ""));
  if (!enabled()) {
    log.debug("Leaving layer(). Not capturing.");
    return;
  }
  try {
    const f = fields || {};
    record.layers.push({
      hop: f.hop || null,
      requester: f.requester || null,
      target: f.target || null,
      mechanism: f.mechanism || null,
      kind: f.kind || null,
      format: f.format || null,
      value: f.value === undefined ? null : f.value,
      header: scrub(f.header === undefined ? null : f.header),
      claims: scrub(f.claims === undefined ? null : f.claims),
      actChain: scrub(Array.isArray(f.actChain) ? f.actChain : []),
      notes: f.notes || null
    });
    log.info("[capture] layer " + record.layers.length + ": " + f.hop +
             ", " + f.kind + " (" + f.mechanism + ")");
    write();
  } catch (e) {
    log.debug("Caught in layer(): " + ((e && e.message) || e));
    log.warn("[capture] could not record a layer: " +
             ((e && e.message) || e));
  }
  log.debug("Leaving layer().");
}

// "bob→webapp1".
function hop(from, to) {
  log.debug("Entering hop().");
  log.debug("Leaving hop().");
  return String(from) + "→" + String(to);
}

// A compact JWS read without verifying it: { header, claims }. A JWE (five
// parts) gives its protected header and no claims, which only its recipient
// could read. Anything else gives nulls.
function jwt(token) {
  log.debug("Entering jwt().");
  const parts = String(token || "").split(".");
  const out = { header: null, claims: null, encrypted: parts.length === 5 };
  try {
    if (parts.length === 3 || parts.length === 5) {
      out.header = JSON.parse(Buffer.from(parts[0], "base64url")
        .toString("utf8"));
    }
    if (parts.length === 3) {
      out.claims = JSON.parse(Buffer.from(parts[1], "base64url")
        .toString("utf8"));
    }
  } catch (e) {
    log.debug("Caught in jwt(): " + ((e && e.message) || e));
    // Not a JWT after all: the layer is recorded with its raw value.
  }
  log.debug("Leaving jwt().");
  return out;
}

// RFC 8693's nested `act`, oldest actor first: each entry its `sub` (with
// `@iss` only where the issuer differs from the token's own).
function actChain(act, tokenIssuer) {
  log.debug("Entering actChain().");
  const newestFirst = [];
  let at = act;
  while (at && typeof at === "object" && newestFirst.length < 64) {
    newestFirst.push(at.sub + (at.iss && tokenIssuer && at.iss !== tokenIssuer
      ? "@" + at.iss : ""));
    at = at.act;
  }
  log.debug("Leaving actChain().");
  return newestFirst.reverse();
}

// The kind of a JWT from its header: "access token (at+jwt)" for RFC 9068's
// type, "JWT (<typ>)" for any other declared type, "JWT" for none.
function jwtKind(header, fallback) {
  log.debug("Entering jwtKind().");
  const typ = String((header && header.typ) || "");
  if (/^(application\/)?at\+jwt$/i.test(typ)) {
    log.debug("Leaving jwtKind(). RFC 9068.");
    return "access token (at+jwt)";
  }
  log.debug("Leaving jwtKind().");
  return fallback ||
    (typ && !/^jwt$/i.test(typ) ? "JWT (" + typ + ")" : "JWT");
}

module.exports = {
  enabled: enabled,
  set: set,
  layer: layer,
  hop: hop,
  jwt: jwt,
  jwtKind: jwtKind,
  actChain: actChain,
  scrub: scrub
};
