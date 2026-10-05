// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_forms.ts
//
// ---------------------------------------------------------------------------
// WHICH /admin-api OPERATION A CONSOLE FORM IS (#446, 2026-10-05).
//
// The console's forms post to its own pages — `POST /admin/users` with a
// hidden `action` — and the server-rendered console answered them there. The
// static console cannot: it has no server of its own, only `/admin-api`. So
// a submitted form has to be sent to the operation that IS that control, and
// the table that says which is not written here. It is read off the index
// `GET /admin-api` answers (`operations`), where every operation names the
// console control it mirrors — the declaration rule 7 already requires of
// each one. An action route (`/admin-api/users/:action`) is listed once per
// action, its path ending in the action's name.
//
// So a form resolves to the POST operation that mirrors its page and whose
// last path segment is its `action`, or — for a form with no `action` field,
// which is a page whose one form is one act — the one POST operation that
// mirrors its page, or the action its page is named after. Anything else is null, and the runtime refuses the form
// rather than guessing: a form sent to the wrong operation is a change made
// that nobody asked for.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

type Json = any;

/**
 * Resolves a console form to the `/admin-api` operation it mirrors.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class WebForms {
  // `mirrors` is prose for a reader as well as a key for this: one control
  // (`POST /admin/users`), two (`POST /admin/users and POST
  // /admin/users/new`) or a list (`POST /a, POST /b and POST /c`). Every
  // console path named after a POST is taken.
  /**
   * Lists the console paths a `mirrors` declaration names for POST.
   *
   * @param mirrors - the operation's `mirrors`
   * @returns the console paths, `/admin/...`
   */
  static mirroredPosts(mirrors: string): string[] {
    const out = [];
    const re = /POST (\/admin[^\s,;)]*)/g;
    let m = re.exec(String(mirrors || ''));
    while (m) {
      const path = m[1].replace(/[.:]+$/, '');
      if (out.indexOf(path) < 0) {
        out.push(path);
      }
      m = re.exec(String(mirrors || ''));
    }
    return out;
  }

  // Keyed `<console path> <action>`, and `<console path>` alone for the
  // page whose form carries no action — kept only when exactly one POST
  // operation mirrors that page, since otherwise there is no one answer.
  // A key two operations claim is recorded as ambiguous (null) rather than
  // won by whichever came first.
  /**
   * Builds the table of console forms to operations from the API's index.
   *
   * @param operations - `GET /admin-api`'s `operations`
   * @returns the table: key to the operation's path, or null where two
   *   operations claim one key
   */
  static table(operations: Json[]): Json {
    const table = {};
    const bare = {};
    const put = function (key, path) {
      if (Object.prototype.hasOwnProperty.call(table, key) &&
          table[key] !== path) {
        table[key] = null;
        return;
      }
      table[key] = path;
    };
    (operations || []).forEach(function (op) {
      if (op.method !== 'POST') {
        return;
      }
      const action = String(op.path).split('/').pop();
      WebForms.mirroredPosts(op.mirrors).forEach(function (page) {
        put(page + ' ' + action, op.path);
        bare[page] = (bare[page] || []).concat([op.path]);
      });
    });
    Object.keys(bare).forEach(function (page) {
      if (bare[page].length === 1) {
        put(page, bare[page][0]);
      }
    });
    return table;
  }

  /**
   * Resolves one form.
   *
   * @param table - `table()`'s answer
   * @param page - the console path the form posts to, with no realm prefix
   * @param action - the form's `action` field, or '' when it has none
   * @returns the operation's path, or null when no one operation is it
   */
  static resolve(table: Json, page: string, action: string): string | null {
    const has = function (key) {
      return Object.prototype.hasOwnProperty.call(table, key) && table[key]
        ? table[key] : null;
    };
    if (action) {
      return has(page + ' ' + action);
    }
    // A form with no `action` field whose page is named after its act —
    // `POST /admin/keys/export` — is that action of the operation that
    // mirrors it, when the page alone is shared by several.
    return has(page) || has(page + ' ' + String(page).split('/').pop());
  }
}

export = WebForms;
