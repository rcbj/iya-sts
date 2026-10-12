// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: companion/companion_util.js
//
// ===========================================================================
// WHAT EVERY DEMONSTRATION IN THE COMPANION SHARES (#594): the logger, a
// request body, cookies, the one page layout and its policy, and the answers
// a handler sends.
//
// **THE PAGES ARE DRAWN HERE, ON THE SERVER, AND CARRY NO SCRIPT.** The
// companion is not the service, so the service's static-surface rule (root
// CLAUDE.md, *Pages with a script*) does not bind it, and nothing a person
// does here needs one: a link is a link, a form posts, a QR code is an SVG
// drawn on the server, and the one page that waits for a wallet waits with a
// `<meta>` refresh. So the policy is `default-src 'none'` with the stylesheet
// at `/companion.css` and `frame-ancestors 'none'` — no `script-src` at all,
// which `default-src 'none'` makes `'none'`.
//
// **NO `form-action`.** The verifier's start posts here and is answered with
// a 303 to the wallet, which may be another origin or an `openid4vp://`
// address; Chrome holds a redirect after a submission to `form-action`, so a
// `form-action 'self'` would block the very hand-over the page exists for.
// `default-src` does not cover `form-action`, so leaving it out allows that
// redirect and nothing else.
//
// Node built-ins and bunyan only.
// ===========================================================================

const bunyan = require("bunyan");

// One logger per module, at COMPANION_LOG_LEVEL (LOG_LEVEL as the suite's
// tools read it, then info).
function logger(name) {
  const log = bunyan.createLogger({ name: name,
    level: process.env.COMPANION_LOG_LEVEL || process.env.LOG_LEVEL ||
           "info" });
  log.debug("Entering logger(). " + name);
  log.debug("Leaving logger().");
  return log;
}

const log = logger("companion_util");

const POLICY = "default-src 'none'; style-src 'self'; img-src 'self' data:; " +
               "frame-ancestors 'none'; base-uri 'none'";

// The one stylesheet, served at /companion.css. A string here rather than a
// file beside the module so the image is the JavaScript and nothing else.
const CSS = [
  "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;",
  "margin:0;background:#f4f5f7;color:#1d2330}",
  "main{max-width:44rem;margin:2rem auto;padding:0 1rem}",
  ".card{background:#fff;border:1px solid #d8dbe2;border-radius:8px;",
  "padding:1.5rem 1.75rem;margin-bottom:1.25rem}",
  "h1{font-size:1.5rem;margin:0 0 .5rem}h2{font-size:1.1rem;margin:1.25rem 0 ",
  ".5rem}",
  ".sub{color:#5a6275;margin:.25rem 0 1rem}",
  ".err{color:#9b1c1c;background:#fdecec;border-radius:6px;padding:.75rem}",
  ".ok{color:#185c37;background:#e6f4ec;border-radius:6px;padding:.75rem}",
  ".qr svg{width:16rem;height:16rem;display:block;margin:1rem 0}",
  "code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;",
  "font-size:.85rem;word-break:break-all}",
  "a.button,button{display:inline-block;background:#2754c5;color:#fff;",
  "border:0;border-radius:6px;padding:.5rem 1rem;text-decoration:none;",
  "font-size:1rem;cursor:pointer;margin:.25rem .25rem .25rem 0}",
  "table{border-collapse:collapse;width:100%}",
  "td,th{text-align:left;border-bottom:1px solid #eceef2;padding:.35rem}",
  "label{display:block;margin:.5rem 0 .25rem}",
  "select{font-size:1rem;padding:.25rem}",
  "footer{color:#5a6275;font-size:.85rem;margin-top:1rem}"
].join("");

/**
 * Escapes text for HTML, in an element or in a double-quoted attribute.
 *
 * @param {*} value - the text
 * @returns {string} the escaped text
 */
function esc(value) {
  log.debug("Entering esc().");
  log.debug("Leaving esc().");
  return String(value === undefined || value === null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/**
 * A whole document: the title, the body, and an optional refresh.
 *
 * @param {string} title - the document's title, as text
 * @param {string} body - the body, as markup the caller escaped
 * @param {object} [opts] - `refresh` (seconds), `refreshUrl`
 * @returns {string} the document
 */
function page(title, body, opts) {
  log.debug("Entering page(). " + title);
  const o = opts || {};
  const refresh = o.refresh
    ? "<meta http-equiv=\"refresh\" content=\"" + Number(o.refresh) +
      (o.refreshUrl ? ";url=" + esc(o.refreshUrl) : "") + "\">"
    : "";
  const html = "<!doctype html><html lang=\"en\"><head>" +
    "<meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    refresh + "<title>" + esc(title) + "</title>" +
    "<link rel=\"stylesheet\" href=\"/companion.css\"></head><body><main>" +
    body + "<footer>The iya-sts development companion. A demonstration " +
    "that uses the service as any wallet's issuer and verifier would; " +
    "nothing here is part of the service.</footer></main></body></html>";
  log.debug("Leaving page().");
  return html;
}

/**
 * Sends a document with the companion's policy.
 *
 * @param {object} res - the response
 * @param {number} status - the status
 * @param {string} html - the document
 */
function sendHtml(res, status, html) {
  log.debug("Entering sendHtml(). " + status);
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": POLICY,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    // same-origin, not no-referrer: under no-referrer a browser sends a
    // form's Origin as "null", and the start's Origin check then refuses
    // the companion's own form (found driving the pages in Chrome). Nothing
    // leaves for another site either way.
    "Referrer-Policy": "same-origin"
  });
  res.end(html);
  log.debug("Leaving sendHtml().");
}

/**
 * Sends JSON.
 *
 * @param {object} res - the response
 * @param {number} status - the status
 * @param {*} body - the value
 */
function sendJson(res, status, body) {
  log.debug("Entering sendJson(). " + status);
  res.writeHead(status, { "Content-Type": "application/json",
                          "Cache-Control": "no-store",
                          "X-Content-Type-Options": "nosniff" });
  res.end(JSON.stringify(body));
  log.debug("Leaving sendJson().");
}

/**
 * Sends a redirect: 303, so a POST becomes a GET.
 *
 * @param {object} res - the response
 * @param {string} location - where to
 */
function redirect(res, location) {
  log.debug("Entering redirect().");
  res.writeHead(303, { Location: location, "Cache-Control": "no-store",
                       "Content-Security-Policy": POLICY });
  res.end();
  log.debug("Leaving redirect().");
}

/**
 * A refusal or a failure, as a page.
 *
 * @param {object} res - the response
 * @param {number} status - the status
 * @param {string} title - what failed
 * @param {string} why - the reason, as text
 */
function sendError(res, status, title, why) {
  log.debug("Entering sendError(). " + status);
  sendHtml(res, status, page(title, "<div class=\"card\"><h1>" + esc(title) +
    "</h1><p class=\"err\">" + esc(why) + "</p><p><a href=\"/\">Back to " +
    "the start</a></p></div>"));
  log.debug("Leaving sendError().");
}

/**
 * A request body, whole, capped at 64 KiB: nothing a form here sends is
 * near it.
 *
 * @param {object} req - the request
 * @returns {Promise<Buffer>} the bytes
 */
function readBody(req) {
  log.debug("Entering readBody().");
  log.debug("Leaving readBody().");
  return new Promise(function (resolve, reject) {
    const chunks = [];
    let size = 0;
    req.on("data", function (chunk) {
      size += chunk.length;
      if (size > 64 * 1024) {
        reject(new Error("the request body is over 64 KiB"));
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

/**
 * `application/x-www-form-urlencoded` bytes as an object of strings.
 *
 * @param {Buffer} bytes - the body
 * @returns {object} name to value, the first of each
 */
function formOf(bytes) {
  log.debug("Entering formOf().");
  const out = {};
  new URLSearchParams(bytes.toString("utf8")).forEach(function (value, name) {
    if (!(name in out)) {
      out[name] = value;
    }
  });
  log.debug("Leaving formOf().");
  return out;
}

/**
 * The request's cookies.
 *
 * @param {object} req - the request
 * @returns {object} name to value
 */
function cookiesOf(req) {
  log.debug("Entering cookiesOf().");
  const out = {};
  String(req.headers.cookie || "").split(";").forEach(function (pair) {
    const at = pair.indexOf("=");
    if (at > 0) {
      out[pair.slice(0, at).trim()] = pair.slice(at + 1).trim();
    }
  });
  log.debug("Leaving cookiesOf().");
  return out;
}

module.exports = {
  logger: logger,
  esc: esc,
  page: page,
  sendHtml: sendHtml,
  sendJson: sendJson,
  redirect: redirect,
  sendError: sendError,
  readBody: readBody,
  formOf: formOf,
  cookiesOf: cookiesOf,
  CSS: CSS,
  POLICY: POLICY
};
