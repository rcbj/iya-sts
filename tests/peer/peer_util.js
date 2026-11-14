// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/peer/peer_util.js
//
// ===========================================================================
// WHAT EVERY ROLE OF THE TEST PEER SHARES (#586): the logger, base64url and
// digests, reading a request body, answering JSON, a parsed XML document
// with the lookups SAML needs, and the one outbound HTTP request the peer
// makes to the service.
//
// **THE OUTBOUND REQUEST VERIFIES THE SERVICE'S CERTIFICATE, AGAINST THE
// ANCHORS THE JOB HANDED OVER.** The peer is an outside party: it trusts the
// service the way a relying party would, through the anchors its operator
// configured — here the PEM a job puts on the tenant (`serviceCaPem`), the
// service Root and the main port's certificate. There is no "skip
// verification" switch, on purpose: a peer that dialled anything would
// prove nothing about the TLS the service presents.
//
// Node built-ins and bunyan only.
// ===========================================================================

const http = require("http");
const https = require("https");
const nodeCrypto = require("crypto");
const bunyan = require("bunyan");

// One logger per module, at LOG_LEVEL — the level the rest of the suite
// reads.
function logger(name) {
  const log = bunyan.createLogger({ name: name,
                                    level: process.env.LOG_LEVEL || "info" });
  log.debug("Entering logger(). " + name);
  log.debug("Leaving logger().");
  return log;
}

const log = logger("peer_util");

function b64u(bytes) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(bytes).toString("base64url");
}

function sha(name, bytes) {
  log.debug("Entering sha().");
  log.debug("Leaving sha().");
  return nodeCrypto.createHash(name).update(bytes).digest();
}

// A request body, whole, as bytes. Capped: nothing a protocol here sends
// is near a megabyte, and the peer must not be the thing a runaway client
// fills.
function readBody(req) {
  log.debug("Entering readBody().");
  log.debug("Leaving readBody().");
  return new Promise(function (resolve, reject) {
    const chunks = [];
    let size = 0;
    req.on("data", function (chunk) {
      size += chunk.length;
      if (size > 4 * 1024 * 1024) {
        reject(new Error("the request body is over 4 MiB"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", function () {
      resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

// `application/x-www-form-urlencoded` bytes as an object of strings.
function formOf(bytes) {
  log.debug("Entering formOf().");
  const out = {};
  new URLSearchParams(Buffer.from(bytes || "").toString("utf8")).forEach(
    function (value, key) {
      out[key] = value;
    });
  log.debug("Leaving formOf().");
  return out;
}

// An answer. Every answer is `no-store`: what the peer says changes with
// every request, and a cached readback is a wrong one.
function send(res, status, body, headers) {
  log.debug("Entering send(). " + status);
  const h = Object.assign({ "Cache-Control": "no-store" }, headers || {});
  let payload = "";
  if (body !== undefined && body !== null) {
    if (typeof body === "string" || Buffer.isBuffer(body)) {
      payload = body;
    } else {
      payload = JSON.stringify(body, null, 2);
      h["Content-Type"] = h["Content-Type"] || "application/json";
    }
  }
  res.writeHead(status, h);
  res.end(payload);
  log.debug("Leaving send().");
}

// The anchors a tenant was configured with, as the array https wants.
function anchorsOf(pem) {
  log.debug("Entering anchorsOf().");
  const found = String(pem || "").match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  log.debug("Leaving anchorsOf(). " + found.length);
  return found;
}

// ONE OUTBOUND REQUEST, to the service. `options`: { headers, body (a
// Buffer or string), ca (PEM text), timeoutMs }. No redirect is followed: a
// protocol message the service answers with a redirect is the answer.
function outbound(method, url, options) {
  log.debug("Entering outbound(). " + method + " " + url);
  const opts = options || {};
  log.debug("Leaving outbound().");
  return new Promise(function (resolve, reject) {
    const u = new URL(url);
    const body = opts.body === undefined || opts.body === null
      ? null : Buffer.from(opts.body);
    const headers = Object.assign({}, opts.headers || {});
    if (body) {
      headers["Content-Length"] = String(body.length);
    }
    const lib = u.protocol === "https:" ? https : http;
    const requestOptions = { method: method, hostname: u.hostname,
                             port: u.port, path: u.pathname + u.search,
                             headers: headers,
                             timeout: opts.timeoutMs || 20000 };
    if (u.protocol === "https:") {
      const ca = anchorsOf(opts.ca);
      if (ca.length) {
        requestOptions.ca = ca;
      }
      requestOptions.agent = false;
    }
    const req = lib.request(requestOptions, function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("end", function () {
        const text = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = text ? JSON.parse(text) : null;
        } catch (e) {
          log.debug("Caught in outbound(): " + ((e && e.message) || e));
          // Not JSON: an XML document or a page; `text` carries it.
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text: text,
                  json: json });
      });
    });
    req.on("timeout", function () {
      req.destroy(new Error("no answer from " + url + " in " +
                            (opts.timeoutMs || 20000) + " ms"));
    });
    req.on("error", reject);
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

// ---------------------------------------------------------------------------
// XML. A document parsed by xmldom, and the lookups by LOCAL NAME the SAML
// roles need — namespaces are compared where they decide something, and
// found by local name where they do not.
// ---------------------------------------------------------------------------
function parseXml(text) {
  log.debug("Entering parseXml().");
  const { DOMParser } = require("@xmldom/xmldom");
  const doc = new DOMParser().parseFromString(String(text), "text/xml");
  log.debug("Leaving parseXml().");
  return doc;
}

// Every element in `root`'s subtree with this local name, in document order.
function allByLocal(root, name) {
  log.debug("Entering allByLocal(). " + name);
  const out = [];
  const els = root ? root.getElementsByTagNameNS("*", name) : null;
  for (let i = 0; els && i < els.length; i++) {
    out.push(els[i]);
  }
  log.debug("Leaving allByLocal(). " + out.length);
  return out;
}

function firstByLocal(root, name) {
  log.debug("Entering firstByLocal(). " + name);
  log.debug("Leaving firstByLocal().");
  return allByLocal(root, name)[0] || null;
}

// A DIRECT child by local name: a Response's own Signature and its
// assertion's are both `Signature`, and only the direct child answers which
// element a signature is on.
function childByLocal(el, name) {
  log.debug("Entering childByLocal(). " + name);
  for (let i = 0; el && i < el.childNodes.length; i++) {
    const child = el.childNodes[i];
    if (child.nodeType === 1 && child.localName === name) {
      log.debug("Leaving childByLocal(). Found.");
      return child;
    }
  }
  log.debug("Leaving childByLocal(). None.");
  return null;
}

function textOf(el) {
  log.debug("Entering textOf().");
  log.debug("Leaving textOf().");
  return el ? String(el.textContent || "").trim() : "";
}

// A base64 DER certificate as PEM.
function pemOf(b64) {
  log.debug("Entering pemOf().");
  const clean = String(b64 || "").replace(/\s+/g, "");
  log.debug("Leaving pemOf().");
  return "-----BEGIN CERTIFICATE-----\n" +
    (clean.match(/.{1,64}/g) || []).join("\n") +
    "\n-----END CERTIFICATE-----\n";
}

// Every distinct X509Certificate a metadata document publishes, as PEM.
function certificatesIn(xml) {
  log.debug("Entering certificatesIn().");
  const seen = {};
  allByLocal(parseXml(xml).documentElement, "X509Certificate")
    .forEach(function (el) {
      const b64 = textOf(el).replace(/\s+/g, "");
      if (b64) {
        seen[b64] = true;
      }
    });
  const out = Object.keys(seen).map(pemOf);
  log.debug("Leaving certificatesIn(). " + out.length);
  return out;
}

module.exports = {
  logger: logger,
  b64u: b64u,
  sha: sha,
  readBody: readBody,
  formOf: formOf,
  send: send,
  anchorsOf: anchorsOf,
  outbound: outbound,
  parseXml: parseXml,
  allByLocal: allByLocal,
  firstByLocal: firstByLocal,
  childByLocal: childByLocal,
  textOf: textOf,
  pemOf: pemOf,
  certificatesIn: certificatesIn
};
