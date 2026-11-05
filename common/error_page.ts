// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: error_page.ts
//
// ---------------------------------------------------------------------------
// ONE ERROR PAGE, FOR EVERY SERVER-DRAWN BROWSER FLOW THAT ENDS IN AN ERROR
// (#1326, rcbj's decision, 2026-11-05).
//
// The OAuth 2.0 and OpenID Connect error pages had grown one at a time, and an
// OpenID Foundation reviewer walking through them saw the differences: some
// put the client, the redirect_uri and the state in large type under the
// error, some put a paragraph of RFC 9700 there, some ended with nowhere to
// go, and every one was English whatever language the person had chosen.
// rcbj's design, which this file is the one copy of:
//
//   1. THE ERROR FIRST, in the yellow box every page already had: the
//      protocol's error code (a value, shown as sent) and a sentence saying
//      what was wrong, in the page's language. Whatever a specification — or
//      a certification reviewer's prompt — needs a person to see stays here,
//      where nobody has to look for it.
//   2. WHAT THE PERSON CAN DO, where the page has an action (the RFC 9700
//      interstitial's link to the client, for one).
//   3. THE BACKGROUND, collapsed: why the page was shown rather than the
//      browser being sent somewhere, with the section it rests on. A
//      `<details>`, which needs no script — these pages run none.
//   4. A NOTE TO CLOSE THE TAB AND START AGAIN, and a link to the realm's
//      user portal: no error page ends with nowhere to go.
//   5. DIAGNOSTICS, in a box of their own at the bottom and in small type:
//      the time, the INCIDENT ID — the `seq` of the audit row this request is
//      recorded as (`audit.reserveIncident()`), so one number finds it on
//      /admin/audit — and whatever the caller knows (the application, the
//      redirect_uri, the state, the nonce, who is signed in, the
//      error_description an application would receive).
//
// **EVERY WORD FOLLOWS THE LANGUAGE CHOSEN**, from `errorPages` (this frame)
// and the caller's own namespace (its messages), with the standard language
// chooser at the top. This reverses, for these pages, the earlier rule that
// "a refusal stays English" (#539). What is NOT translated is data: a
// protocol value (an `error`, an `error_description`, a URI, a state) is shown
// exactly as it was sent or would be, because a person reporting it has to
// be able to quote it.
//
// It draws markup and sends it; it decides nothing. Callers build the
// translated message, background and diagnostics, and pass them in.
// ---------------------------------------------------------------------------

import Html = require('./html');
import PageLocale = require('./page_locale');
import realms = require('./realms');
import audit = require('./audit');
import helpers = require('./helpers');

const log = helpers.log;

type Translator = ReturnType<typeof PageLocale.forPage>;

// One row of the diagnostics box: a translated label and a value shown as
// data (escaped, in a monospace face). An empty value leaves the row out.
interface DiagnosticRow {
  label: string;
  value: unknown;
}

interface ErrorPageSpec {
  // The page's translator, and the language chooser drawn with it ('' for
  // none — every caller here passes one).
  t: Translator;
  chooser: string;
  status: number;
  // The heading, translated (plain text).
  title: string;
  // The protocol's error code, shown in bold as a value, or ''.
  error?: string;
  // The sentence in the box, translated HTML.
  message: string;
  // HTML drawn right below the box: an action, or a sentence that must stay
  // visible (a sign-out that did nothing says so here).
  after?: string;
  // The background, translated HTML, drawn collapsed; '' for none.
  background?: string;
  // The caller's own diagnostics, below the time and the incident ID.
  diagnostics?: DiagnosticRow[];
  // Anything for the document's head (a refresh).
  extraHead?: string;
}

// The page's style: the yellow box the earlier pages used, the collapsed
// background in the console's `details.prose` manner, and the diagnostics in
// a quieter box of their own.
const CSS =
  'body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;' +
  'margin:2rem auto;max-width:46rem;padding:0 1rem;line-height:1.5;' +
  'color:#222;background:#fff}' +
  'h1{font-size:1.5rem;margin:.4rem 0 1rem}' +
  'code{font-family:ui-monospace,Menlo,monospace;font-size:.85rem;' +
  'background:#f4f4f8;padding:.1rem .25rem;border-radius:3px;' +
  'word-break:break-all}' +
  '.warn{background:#fff8e1;border:1px solid #ffe082;padding:.7rem .9rem;' +
  'border-radius:4px;margin:1rem 0}' +
  '.warn .error{display:block;font-weight:600;margin-bottom:.2rem}' +
  'details.prose{margin:1rem 0;color:#444}' +
  'details.prose>summary{cursor:pointer;color:#1f4fa3}' +
  'details.prose>summary:hover{color:#2c5cc5}' +
  'details.prose>div{margin:.5rem 0 0 1rem;font-size:.92rem}' +
  '';

// THE ENDING EVERY ERROR PAGE SHARES — the start-over note, the portal link,
// the diagnostics — as CSS of its own, for a page that draws its own body
// and borrows only the ending (the sign-out page whose return was refused).
const FOOTER_CSS =
  '.next{margin:1.2rem 0}' +
  '.next a.portal{display:inline-block;margin-top:.5rem;padding:.35rem .8rem;' +
  'border:1px solid #1f4fa3;border-radius:4px;color:#1f4fa3;' +
  'text-decoration:none}' +
  '.next a.portal:hover{background:#eef3fc}' +
  'button.as-link{background:none;border:0;padding:0;font:inherit;' +
  'color:#00e;color:LinkText;text-decoration:underline;cursor:pointer}' +
  'section.diagnostics{margin:2rem 0 1rem;padding:.6rem .9rem;' +
  'border:1px solid #ddd;border-radius:4px;background:#fafafa;' +
  'font-size:.82rem;color:#555}' +
  'section.diagnostics h2{font-size:.85rem;margin:0 0 .4rem;' +
  'text-transform:uppercase;letter-spacing:.04em;color:#666}' +
  'section.diagnostics dl{display:grid;grid-template-columns:max-content 1fr;' +
  'gap:.15rem .9rem;margin:0}' +
  'section.diagnostics dt{color:#666}section.diagnostics dd{margin:0;' +
  'min-width:0}section.diagnostics dd code{font-size:.8rem}';

const PAGE_CSS = CSS + FOOTER_CSS +
  '.sub{color:#666;font-size:.92rem}' +
  'details.language-row{float:right;margin:0 0 .5rem 1rem}';

/**
 * Draws and sends the shared error page (#1326): the error, the background
 * collapsed, a start-over note with a link to the portal, and the diagnostics
 * with the audit row's incident ID, all in the page's language.
 *
 * A static utility class; it holds no state.
 */
class ErrorPage {
  /**
   * The ending's CSS, for a page that borrows only `footer()`.
   */
  static readonly FOOTER_CSS = FOOTER_CSS;

  /**
   * The ending every error page shares: the start-over note, the link to
   * the realm's user portal, and the diagnostics with the time and the
   * incident ID first.
   *
   * @param t - the page's translator
   * @param diagnostics - the caller's rows
   * @param incident - the incident ID, or 0 for none
   * @param now - the time to print
   * @returns the HTML
   */
  static footer(t: Translator, diagnostics: DiagnosticRow[],
                incident: number, now: Date): string {
    log.debug("Entering ErrorPage.footer().");
    const first: DiagnosticRow[] = [
      { label: t.text('errorPages.time'), value: now.toISOString() },
      { label: t.text('errorPages.incident'),
        value: incident ? String(incident) : t.text('errorPages.noIncident') }
    ];
    const rows: DiagnosticRow[] = first.concat(diagnostics || []);
    const portal = realms.currentPrefix() + '/portal';
    const out = '<div class="next"><p>' + t.html('errorPages.startOver') +
      '</p><a class="portal" href="' + Html.esc(portal) + '">' +
      t.html('errorPages.portal') + '</a></div>' +
      '<section class="diagnostics" aria-labelledby="diagnostics-heading">' +
      '<h2 id="diagnostics-heading">' + t.html('errorPages.diagnostics') +
      '</h2><dl>' +
      rows.filter(function (row: DiagnosticRow): boolean {
        return row.value !== undefined && row.value !== null &&
               String(row.value) !== '';
      }).map(function (row: DiagnosticRow): string {
        return '<dt>' + Html.esc(row.label) + '</dt><dd><code>' +
               Html.esc(String(row.value)) + '</code></dd>';
      }).join('') +
      '</dl></section>';
    log.debug("Leaving ErrorPage.footer().");
    return out;
  }

  /**
   * The first of `candidates` the page's catalogs hold, drawn with `params`
   * (#1327). A family's sentence is looked up BY ERROR CODE — a key test E
   * cannot see in the source, since it is built from the code — so every
   * caller hands a chain that ends in a general sentence, and a missing key
   * never draws its own name.
   *
   * @param t - the page's translator
   * @param candidates - keys, most specific first; '' entries are skipped
   * @param params - the values a sentence may name
   * @returns the sentence as HTML, or '' where none of them exists
   */
  static sentence(t: Translator, candidates: string[],
                  params?: Record<string, unknown>): string {
    log.debug("Entering ErrorPage.sentence().");
    for (let i = 0; i < candidates.length; i++) {
      const key = candidates[i];
      if (key && t.has(key)) {
        log.debug("Leaving ErrorPage.sentence(). " + key);
        return t.html(key, params || {});
      }
    }
    log.debug("Leaving ErrorPage.sentence(). None.");
    return '';
  }

  /**
   * The language chooser's return path for an error page: the request
   * itself where asking again is harmless (a GET, which these pages answer
   * only ever by refusing again), the realm's front door otherwise.
   *
   * @param req - the request the page answers
   * @returns a local path
   */
  static returnPath(req: any): string {
    log.debug("Entering ErrorPage.returnPath().");
    const method = String((req && req.method) || 'GET').toUpperCase();
    const url = String((req && req.originalUrl) || '');
    const out = method === 'GET' && url.charAt(0) === '/' &&
      url.charAt(1) !== '/' ? url : realms.currentPrefix() + '/';
    log.debug("Leaving ErrorPage.returnPath().");
    return out;
  }

  /**
   * The language chooser for an error page.
   *
   * @param t - the page's translator
   * @param req - the request the page answers
   * @returns the chooser's HTML
   */
  static chooser(t: Translator, req: any): string {
    log.debug("Entering ErrorPage.chooser().");
    const out = PageLocale.chooser(t, realms.currentPrefix(),
                                   ErrorPage.returnPath(req));
    log.debug("Leaving ErrorPage.chooser().");
    return out;
  }

  /**
   * The whole document.
   *
   * @param spec - what to draw
   * @param incident - the incident ID, or 0 for none
   * @param now - the time to print
   * @returns the HTML document
   */
  static document(spec: ErrorPageSpec, incident: number, now: Date): string {
    log.debug("Entering ErrorPage.document().");
    const t = spec.t;
    const out = '<!doctype html><html' + PageLocale.htmlAttributes(t) +
      '><head><meta charset="utf-8"><meta name="viewport" ' +
      'content="width=device-width, initial-scale=1">' +
      (spec.extraHead || '') + '<title>' + Html.esc(spec.title) +
      '</title><style>' + PAGE_CSS + PageLocale.ROW_CSS +
      '</style></head><body>' +
      (spec.chooser || '') +
      '<h1>' + Html.esc(spec.title) + '</h1>' +
      '<div class="warn" role="alert">' +
      (spec.error ? '<span class="error">' + Html.esc(spec.error) +
                    '</span>' : '') +
      spec.message + '</div>' +
      (spec.after || '') +
      (spec.background
        ? '<details class="prose"><summary>' +
          t.html('errorPages.background') + '</summary><div>' +
          spec.background + '</div></details>'
        : '') +
      ErrorPage.footer(t, spec.diagnostics || [], incident, now) +
      '</body></html>';
    log.debug("Leaving ErrorPage.document().");
    return out;
  }

  /**
   * Reserves the incident ID, draws the page and sends it — in that order and
   * in one synchronous run, which `audit.reserveIncident()` requires.
   *
   * @param res - the response
   * @param spec - what to draw
   */
  static send(res: any, spec: ErrorPageSpec): void {
    log.debug("Entering ErrorPage.send(). " + spec.status);
    const incident = audit.reserveIncident(res);
    const html = ErrorPage.document(spec, incident, new Date());
    // error-code: none — every caller marks its own condition before this
    res.status(spec.status).type('text/html')
       .set('Cache-Control', 'no-store').send(html);
    log.debug("Leaving ErrorPage.send().");
  }
}

export = ErrorPage;
