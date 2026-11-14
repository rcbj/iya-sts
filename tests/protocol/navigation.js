// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: navigation.js
//
// ---------------------------------------------------------------------------
// A GET AS A BROWSER'S TOP-LEVEL NAVIGATION SENDS IT. Node's `fetch` sends
// `Sec-Fetch-Mode: cors` on every request and will not let a caller change
// it, and since #1443 (ASVS 5.0.0 3.5.3) `/oauth2/logout` asks rather than
// signs out when a GET says it is not a navigation. A job standing in for a
// browser that follows an RP-Initiated Logout link sends what a browser
// sends: `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`.
//
// The answer has the parts of a fetch Response the jobs read: `status`,
// `headers.get()`, `headers.getSetCookie()` and `text()`. Redirects are not
// followed, as `redirect: "manual"` does not follow them.
// ---------------------------------------------------------------------------

const http = require("http");
const https = require("https");
const log = require("bunyan").createLogger({ name: "navigation",
  level: process.env.LOG_LEVEL || "info" });

/**
 * Asks for a page as a top-level navigation.
 *
 * @param {string} url - the absolute address
 * @param {object} [headers] - more request headers (a cookie, say)
 * @returns {Promise<object>} `{ status, headers, text() }`
 */
function navigate(url, headers) {
  log.debug("Entering navigate(). " + url);
  const target = new URL(String(url));
  const transport = target.protocol === "https:" ? https : http;
  const sent = Object.assign({ "sec-fetch-mode": "navigate",
                               "sec-fetch-dest": "document",
                               accept: "text/html" }, headers || {});
  log.debug("Leaving navigate().");
  return new Promise(function (resolve, reject) {
    const request = transport.request(target, { method: "GET",
                                                headers: sent },
      function (res) {
        const chunks = [];
        res.on("data", function (chunk) {
          chunks.push(chunk);
        });
        res.on("end", function () {
          const body = Buffer.concat(chunks).toString("utf8");
          const raw = res.headers;
          resolve({
            status: res.statusCode,
            headers: {
              get: function (name) {
                const value = raw[String(name).toLowerCase()];
                return value === undefined ? null
                  : (Array.isArray(value) ? value.join(", ") : String(value));
              },
              getSetCookie: function () {
                return (raw["set-cookie"] || []).slice();
              }
            },
            text: function () {
              return Promise.resolve(body);
            }
          });
        });
      });
    request.on("error", function (e) {
      log.debug("Caught in navigate(): " + ((e && e.message) || e));
      reject(e);
    });
    request.end();
  });
}

module.exports = { navigate: navigate };
