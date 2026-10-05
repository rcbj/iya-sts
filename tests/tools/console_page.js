// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/console_page.js
//
// ---------------------------------------------------------------------------
// DRAWING A CONSOLE PAGE IN PROCESS, AS THE STATIC CONSOLE DRAWS IT (#446).
//
// Until the cutover an in-process test drew a console page by calling its
// route's handler and reading the HTML it sent. The console has no such
// routes now: a page is its `/admin-api` operation's answer drawn by its
// renderer (`admin-ui/web_pages.ts`) in the browser. So this does exactly
// that in node — the operation's handler is called directly, past the API's
// token gate (an in-process test asks the service itself, as the route
// handler did past the console's gate), and the answer is drawn with
// `WebPages.render()` as a reader holding Admin Write sees it.
//
// `draw(path, query)` answers `{ status, json, html }`: `json` is the
// operation's answer — what `?format=json` used to be — and `html` the page's
// body. `act(operation, body)` calls a POST operation the same way.
//
// A tool of the in-process half: it is required inside a test's own process
// (or child) from the service's root, and it asserts nothing.
// ---------------------------------------------------------------------------

/**
 * Makes the drawer for one service tree.
 *
 * @param root - the service's root directory, as the test requires it from
 * @returns `draw(path, query)` and `act(operation, body, query)`
 */
function consolePage(root) {
  const adminApi = require(root + '/mgmt-api/admin_api');
  const WebPages = require(root + '/admin-ui/web_pages');
  const WebKit = require(root + '/admin-ui/web_kit');

  const call = function (method, operation, query, body) {
    return new Promise(function (resolve, reject) {
      const entry = adminApi.ROUTES.filter(function (one) {
        if (one.method !== method || typeof one.handler !== 'function') {
          return false;
        }
        if (one.path === operation) {
          return true;
        }
        return !!one.route && one.actions && one.actions.some(function (a) {
          return one.route.replace(':action', a.action) === operation;
        });
      })[0];
      if (!entry) {
        reject(new Error('no ' + method + ' operation at ' + operation));
        return;
      }
      const params = {};
      if (entry.route) {
        params.action = operation.split('/').pop();
      }
      const text = body === undefined ? '' : JSON.stringify(body);
      const headers = { host: 'sts.example', accept: 'application/json',
                        'content-type': 'application/json' };
      const req = {
        method: method, query: query || {}, headers: headers, body: text,
        params: params, protocol: 'https', secure: true,
        hostname: 'sts.example', path: operation, url: operation,
        originalUrl: operation, socket: { encrypted: true }, connection: {},
        get: function (name) {
          return headers[String(name).toLowerCase()];
        }
      };
      const sent = { status: 200, headers: {} };
      const res = {
        locals: {}, statusCode: 200,
        status: function (code) {
          this.statusCode = code;
          return this;
        },
        type: function (value) {
          sent.headers['content-type'] = value;
          return this;
        },
        set: function (name, value) {
          sent.headers[String(name).toLowerCase()] = value;
          return this;
        },
        setHeader: function (name, value) {
          sent.headers[String(name).toLowerCase()] = value;
          return this;
        },
        json: function (value) {
          resolve({ status: this.statusCode, json: value, text: '',
                    headers: sent.headers });
          return this;
        },
        send: function (value) {
          let json = null;
          try {
            json = typeof value === 'string' ? JSON.parse(value) : value;
          } catch (e) {
            // Not JSON (a document, a drawing): answered as its text.
            json = null;
          }
          resolve({ status: this.statusCode, json: json,
                    text: typeof value === 'string' ? value : '',
                    headers: sent.headers });
          return this;
        },
        end: function () {
          resolve({ status: this.statusCode, json: null, text: '',
                    headers: sent.headers });
          return this;
        }
      };
      Promise.resolve().then(function () {
        return entry.handler(req, res);
      }).catch(reject);
    });
  };

  return {
    /**
     * Draws a console page from its operation's answer.
     *
     * @param path - the console path, `/admin/caches`
     * @param query - the page's query, its own names
     * @returns `status`, `json` (the answer) and `html` (the body), or
     *   rejects for a path that is no console page
     */
    draw: async function (path, query) {
      const page = WebPages.PAGES.filter(function (one) {
        return one.path === path;
      })[0];
      if (!page) {
        throw new Error(path + ' is not a console page');
      }
      const q = Object.assign({}, query || {});
      delete q.format;
      const answer = await call('GET', page.operation,
                                WebPages.operationQuery(page.path, q));
      const html = answer.status === 200 && answer.json
        ? WebPages.render(page.path, JSON.parse(JSON.stringify(answer.json)),
                          WebKit.context(q, true))
        : '';
      return { status: answer.status, json: answer.json, html: html };
    },
    /**
     * Calls a POST operation, as a form of the console is sent.
     *
     * @param operation - the operation's path, `/admin-api/mail/send-test`
     * @param body - the form's fields
     * @returns `status`, `json` and `text`
     */
    act: function (operation, body) {
      return call('POST', operation, {}, body || {});
    },
    /**
     * Calls a GET operation with a query.
     *
     * @param operation - the operation's path
     * @param query - its query
     * @returns `status`, `json`, `text` and `headers`
     */
    get: function (operation, query) {
      return call('GET', operation, query || {});
    }
  };
}

module.exports = { consolePage: consolePage };
