// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_account_api.ts
//
// ---------------------------------------------------------------------------
// `/admin/account-api`: THE ACCOUNT API'S OPENAPI DOCUMENT, READ IN THE
// CONSOLE (#568).
//
// The user portal became a static application on #568 and `/account-api` is
// its only door. This page draws that API's OpenAPI 3.1 document — the one
// `/account-api/openapi.json` publishes, answered here by `GET
// /admin-api/account-api` for the realm the console is in — as a reference:
// every operation by tag, the portal page or form it is the door of, who may
// call it, its parameters, its request body and its answers, with the
// document itself to download.
//
// **IT CALLS NOTHING**, which is the difference from the management API's
// explorer beside it: every operation of the account API acts on the
// SIGNED-IN PERSON's own account and takes their DPoP-bound token carrying
// `account:manage`, which the console's token is not and must not be.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

// The order a reader expects the methods in, and their badge colours (the
// explorer's).
const METHODS = ['get', 'post', 'put', 'patch', 'delete'];
const ACCESS = {
  person: 'a person\'s token (DPoP, account:manage)',
  link: 'no token — spends the single-use link it carries',
  public: 'no token'
};

/**
 * The console's Account API page. A static utility class.
 */
class AccountApiPage {
  /**
   * The document's prose as HTML: escaped, with `code` spans and paragraph
   * breaks kept.
   *
   * @param text - the description
   * @returns the HTML
   */
  static prose(text: string): string {
    return String(text || '').split(/\n\n+/).map(function (para) {
      return '<p class="note">' + kit.esc(para)
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>') + '</p>';
    }).join('');
  }

  /**
   * A JSON Schema, pretty-printed.
   *
   * @param schema - the schema
   * @returns the HTML
   */
  static schema(schema: Json): string {
    return '<pre class="code">' + kit.esc(JSON.stringify(schema, null, 2)) +
      '</pre>';
  }

  /**
   * One operation: its row and its details.
   *
   * @param method - the HTTP method, lower case
   * @param path - the path
   * @param op - the OpenAPI operation
   * @returns the HTML
   */
  static operation(method: string, path: string, op: Json): string {
    const params: Json[] = op.parameters || [];
    const body = op.requestBody && op.requestBody.content &&
      op.requestBody.content['application/json'];
    const access = String(op['x-access'] || 'person');
    return '<details class="op"><summary><code class="m m-' + method + '">' +
      method.toUpperCase() + '</code> <code>' + kit.esc(path) + '</code> ' +
      kit.esc(op.summary || '') + '</summary>' +
      '<table><tr><th>Operation</th><td><code>' +
      kit.esc(op.operationId || '') + '</code></td></tr>' +
      '<tr><th>Who may call it</th><td>' +
      kit.esc(ACCESS[access] || access) + '</td></tr>' +
      (op['x-mirrors'] ? '<tr><th>The portal\'s</th><td><code>' +
        kit.esc(op['x-mirrors']) + '</code></td></tr>' : '') +
      '</table>' + AccountApiPage.prose(op.description) +
      (params.length
        ? '<h4>Parameters</h4><table><tr><th>Name</th><th>In</th>' +
          '<th>Required</th><th>Schema</th></tr>' +
          params.map(function (p: Json): string {
            return '<tr><td><code>' + kit.esc(p.name) + '</code></td><td>' +
              kit.esc(p.in) + '</td><td>' + (p.required ? 'yes' : 'no') +
              '</td><td><code>' + kit.esc(JSON.stringify(p.schema || {})) +
              '</code>' + (p.description ? '<br>' + kit.esc(p.description)
                                          : '') + '</td></tr>';
          }).join('') + '</table>' : '') +
      (body ? '<h4>Request body (application/json)</h4>' +
              AccountApiPage.schema(body.schema) : '') +
      '<h4>Answers</h4><ul>' +
      Object.keys(op.responses || {}).map(function (status) {
        return '<li><code>' + kit.esc(status) + '</code> ' +
          kit.esc((op.responses[status] || {}).description || '') + '</li>';
      }).join('') + '</ul></details>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /admin-api/account-api`'s answer
   * @returns the HTML
   */
  static render(view: Json): string {
    const doc = (view && view.document) || {};
    const info = doc.info || {};
    const byTag: Json = {};
    const order: string[] = (doc.tags || []).map(function (tag: Json) {
      return String(tag.name);
    });
    Object.keys(doc.paths || {}).forEach(function (path) {
      const item = doc.paths[path];
      METHODS.forEach(function (method) {
        const op = item[method];
        if (!op) {
          return;
        }
        const tag = String((op.tags || ['Other'])[0]);
        if (order.indexOf(tag) < 0) {
          order.push(tag);
        }
        (byTag[tag] = byTag[tag] || []).push(
          AccountApiPage.operation(method, path, op));
      });
    });
    // THE DOCUMENT'S LINK IS A PLAIN LINE, not `kit.note()`'s, which folds
    // a long note away — and this one is what the page is for.
    return '<div class="card">' +
      AccountApiPage.prose(info.description || '') +
      '<p><strong>' + kit.esc(info.title || '') + '</strong> ' +
        kit.esc(info.version || '') + ' — ' + kit.esc(view.paths) +
        ' paths, ' + kit.esc(view.operations) + ' operations, at <code>' +
        kit.esc(((doc.servers || [])[0] || {}).url || '') +
        '</code>. The document: <a href="' + kit.esc(view.url) +
        '" target="_blank" rel="noopener">' + kit.esc(view.url) +
        '</a>. Nothing on this page calls the API: every operation acts on ' +
        'the signed-in person\'s own account, with their token.</p>' +
      '</div>' +
      order.filter(function (tag) {
        return byTag[tag];
      }).map(function (tag) {
        return '<div class="card"><h2>' + kit.esc(tag) + '</h2>' +
          byTag[tag].join('') + '</div>';
      }).join('');
  }
}

export = AccountApiPage;
