// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_explorer.ts
//
// ---------------------------------------------------------------------------
// THE API EXPLORER, DRAWN FROM ITS VIEW ALONE (#446, step 5).
//
// Draws `/admin/api-explorer` from the answer of `GET /admin-api/api-explorer`
// for the static console. The server-rendered page embedded an access token
// minted for the console session in `data-token`, and the explorer's script
// sent it as a Bearer token. The static console has no session to mint for
// and a token issued to it is DPoP-bound, so nothing is embedded: the page
// carries `data-console-fetch`, and `admin_api_explorer.js` sends every call
// — the document included — through `window.stsConsoleFetch`, which the
// runtime (`web_runtime.ts`) answers with its own token and a proof by its
// own key. That is the ticket's "the API explorer works while
// `oauth2.accessTokenRequireDpop` is on, because it uses the console's DPoP
// key".
//
// A script in markup drawn by `innerHTML` does not run, so the page names
// its script in `data-script` and the runtime loads it after drawing.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * Draws the API explorer from its answer.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ExplorerPage {
  /**
   * The explorer's stylesheet, one string — also the server-rendered
   * explorer's (`mgmt-api/admin_api_docs.ts` reads it from here).
   */
  static readonly STYLE = [
  'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;',
  'background:#f4f4f7;margin:0;padding:2rem 1rem;color:#222;line-height:1.45}',
  '#app{max-width:76rem;margin:0 auto}',
  '.head{background:#fff;border:1px solid #d5d5dd;border-radius:10px;',
  'padding:22px 26px;margin:0 0 18px;box-shadow:0 6px 24px rgba(0,0,0,.08)}',
  'h1{font-size:1.35em;margin:0 0 6px;color:#12107c}',
  'h2{font-size:1.05em;margin:0 0 4px;color:#12107c}',
  '.meta{margin:0 0 10px;font-size:.82em;color:#666}',
  '.meta span,.meta a{margin-right:1em}',
  '.meta a{color:#12107c}',
  '.lede{font-size:.86em;color:#444;margin:.5em 0}',
  '.filter{margin:0 0 14px}',
  '.filter label{font-size:.78em;font-weight:600;color:#555;margin-right:.5em}',
  '.filter input{width:22rem;max-width:100%}',
  '.tag{background:#fff;border:1px solid #d5d5dd;border-radius:10px;',
  'padding:16px 20px;margin:0 0 14px;box-shadow:0 6px 24px rgba(0,0,0,.06)}',
  '.tagnote{font-size:.8em;color:#666;margin:0 0 10px}',
  '.op{border-top:1px solid #eee}',
  '.ophead{display:flex;gap:.7em;align-items:baseline;width:100%;',
  'text-align:left;background:none;border:0;padding:9px 2px;cursor:pointer;',
  'font:inherit}',
  '.ophead:hover{background:#fafafc}',
  '.method{font-size:.72em;font-weight:700;letter-spacing:.04em;',
  'border-radius:4px;padding:2px 7px;color:#fff;flex:none;min-width:3.4rem;',
  'text-align:center}',
  '.m-get{background:#0b6b4f}.m-post{background:#b06000}',
  '.path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;',
  'font-size:.84em;flex:none}',
  '.summary{font-size:.8em;color:#666}',
  '.opbody{padding:4px 2px 18px 4.4rem}',
  '.prose{font-size:.82em;color:#444;margin:.4em 0}',
  '.hint{font-size:.76em;color:#777;margin:.2em 0 0;flex-basis:100%}',
  '.form{margin:.8em 0 .4em}',
  '.field{display:flex;flex-wrap:wrap;gap:.6em;align-items:center;',
  'margin:.5em 0}',
  '.field label{font-size:.78em;font-weight:600;color:#555;min-width:9rem}',
  '.field.wide{display:block}',
  'input[type=text],textarea{box-sizing:border-box;padding:6px 8px;',
  'border:1px solid #bbb;border-radius:5px;font-size:.85em;',
  'font-family:inherit}',
  'input[type=text]{min-width:16rem}',
  'textarea{width:100%;font-size:.8em;',
  'font-family:ui-monospace,SFMono-Regular,Menlo,monospace}',
  '.controls{margin:.6em 0}',
  'button.run{padding:6px 14px;border-radius:5px;border:1px solid #12107c;',
  'background:#12107c;color:#fff;font-size:.82em;cursor:pointer}',
  '.curl,.body{background:#f4f4f8;border:1px solid #e2e2ea;border-radius:5px;',
  'padding:8px 10px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;',
  'font-size:.76em;white-space:pre-wrap;word-break:break-word;margin:.5em 0}',
  '.curl{color:#555}',
  '.resulthead{display:flex;gap:.8em;align-items:baseline;margin:.6em 0 0}',
  '.status{font-weight:700;font-size:.82em}',
  '.status.ok{color:#0b6b4f}.status.bad{color:#b00020}',
  '.status.err{color:#b00020}',
  '.ms{font-size:.76em;color:#777}',
  '.pending{font-size:.8em;color:#777;margin:.6em 0}',
  '.warn{background:#fff8e1;border:1px solid #ffe082;padding:9px 12px;',
  'border-radius:5px;font-size:.82em;margin:0 0 16px}',
  'code{font-size:.9em;',
  'font-family:ui-monospace,SFMono-Regular,Menlo,monospace;',
  'background:#f4f4f8;padding:.1rem .25rem;border-radius:3px}'
].join('');

  /**
   * Draws `/admin/api-explorer` from its answer: the explorer's stylesheet,
   * the element its script reads, and the script named for the runtime.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/api-explorer`
   * @returns the body as HTML
   */
  static body(ctx: Json, json: Json): string {
    const spec = String(json.realmPrefix || '') + json.api + '/openapi.json';
    return '<style>' +
      ExplorerPage.STYLE.replace(/(^|})body\{[^}]*\}/g, '$1') + '</style>' +
      '<p class="lede">Every operation this service\'s management API ' +
      'offers, read from the same OpenAPI document the API publishes, with ' +
      'a form that calls it. Calls are made with this console\'s own ' +
      'access token, issued to <strong>' + kit.esc(json.who || 'you') +
      '</strong> and bound to this browser\'s key, carrying <code>' +
      kit.esc(json.scope || '(no scope)') + '</code> — the scopes your ' +
      'console roles grant and no others, so an operation you may not ' +
      'perform is refused here exactly as it would be anywhere else.</p>' +
      '<div id="app" data-spec="' + kit.esc(spec) + '" ' +
      'data-version="' + kit.esc(json.version || '') + '" ' +
      'data-realm-prefix="' + kit.esc(json.realmPrefix || '') + '" ' +
      'data-token="" data-console-fetch="1" ' +
      'data-script="' + kit.esc(json.script) + '">' +
      '<p class="lede">Reading <code>' + kit.esc(spec) + '</code>&hellip;' +
      '</p></div>';
  }
}

export = ExplorerPage;
