// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: ssf_roles.js
//
// A client_credentials token is issued ssf.read or ssf.manage only when the
// application is a member of SSF_READ or SSF_MANAGE. These jobs used to be
// issued the scopes because the client declared them. mapApplication() adds
// the application to the roles the requested scope names, and treats "already
// holds" as success so a token helper can call it on every mint.
// A scope that names neither posts nothing. An omitted scope maps both.
// A LOCAL HELPER (MANIFEST.js's LOCAL_HELPERS).

const bunyan = require("bunyan");
const log = bunyan.createLogger({ name: "ssf_roles",
                                  level: process.env.LOG_LEVEL || "info" });

const ROLES = { "ssf.read": "SSF_READ", "ssf.manage": "SSF_MANAGE" };

function rolesFor(scopes) {
  log.debug("Entering rolesFor().");
  if (scopes == null) {
    log.debug("Leaving rolesFor(). Both.");
    return ["SSF_READ", "SSF_MANAGE"];
  }
  const names = [];
  String(scopes).split(/\s+/).filter(Boolean).forEach(function (one) {
    const role = ROLES[one];
    if (role && names.indexOf(role) < 0) {
      names.push(role);
    }
  });
  log.debug("Leaving rolesFor(). " + names.join(" "));
  return names;
}

function answerText(r) {
  log.debug("Entering answerText().");
  const text = r && (r.text || r.raw);
  log.debug("Leaving answerText().");
  return String(text || JSON.stringify((r && (r.json || r.body)) || ""));
}

function succeeded(r) {
  log.debug("Entering succeeded().");
  if (/already holds/.test(answerText(r))) {
    log.debug("Leaving succeeded(). Already a member.");
    return true;
  }
  const body = (r && (r.json || r.body)) || {};
  const ok = !!(r && r.status === 200 && body.ok !== false);
  log.debug("Leaving succeeded(). " + ok);
  return ok;
}

// post(url, body) answers { status, text|raw, json|body }.
async function mapApplication(post, apiBase, clientId, scopes) {
  log.debug("Entering mapApplication(). " + clientId);
  const roles = rolesFor(scopes);
  const base = String(apiBase || "").replace(/\/+$/, "");
  for (let i = 0; i < roles.length; i++) {
    const role = roles[i];
    const r = await post(base + "/roles/add-member", {
      role: role, kind: "application", member: clientId });
    if (!succeeded(r)) {
      log.debug("Leaving mapApplication(). Refused.");
      throw new Error("mapping " + clientId + " onto " + role + " failed: " +
                      (r && r.status) + " " + answerText(r).slice(0, 400));
    }
  }
  log.debug("Leaving mapApplication(). " + roles.length + " role(s).");
}

function sendPost(send) {
  log.debug("Entering sendPost().");
  log.debug("Leaving sendPost().");
  return async function (url, body) {
    log.debug("Entering sendPost.post().");
    const r = await send(url, { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body) });
    log.debug("Leaving sendPost.post().");
    return { status: r.status, text: r.raw || r.text, json: r.body || r.json };
  };
}

function callPost(call) {
  log.debug("Entering callPost().");
  log.debug("Leaving callPost().");
  return async function (url, body) {
    log.debug("Entering callPost.post().");
    const r = await call("POST", url, body);
    log.debug("Leaving callPost.post().");
    return r;
  };
}

function hopPost(hop) {
  log.debug("Entering hopPost().");
  log.debug("Leaving hopPost().");
  return async function (url, body) {
    log.debug("Entering hopPost.post().");
    const r = await hop("POST", url, body);
    log.debug("Leaving hopPost.post().");
    return r;
  };
}

function hopOptsPost(hop) {
  log.debug("Entering hopOptsPost().");
  log.debug("Leaving hopOptsPost().");
  return async function (url, body) {
    log.debug("Entering hopOptsPost.post().");
    const r = await hop(null, "POST", url, { json: body });
    log.debug("Leaving hopOptsPost.post().");
    return r;
  };
}

function jsonPost(fn) {
  log.debug("Entering jsonPost().");
  log.debug("Leaving jsonPost().");
  return async function (url, body) {
    log.debug("Entering jsonPost.post().");
    const r = await fn(url, body);
    log.debug("Leaving jsonPost.post().");
    return { status: r.status, text: r.raw || r.text, json: r.body || r.json };
  };
}

module.exports = {
  mapApplication: mapApplication,
  rolesFor: rolesFor,
  sendPost: sendPost,
  callPost: callPost,
  hopPost: hopPost,
  hopOptsPost: hopOptsPost,
  jsonPost: jsonPost
};
