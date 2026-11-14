// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: page_footer.ts
//
// ---------------------------------------------------------------------------
// THE FOOTER AS THE SERVER DRAWS IT (rcbj, 2026-11-14).
//
// `common/web_footer.ts` is the markup and the stylesheet; this is the
// server's half: the version and the build line from `common/version.js` —
// the one source every surface that draws a version reads
// (`tests/version.js`) — the current year, and the page's translator. Two
// callers draw with it:
//
//   * `common/shell_document.ts`, for EVERY static surface's shell: the
//     console, the portal, the reports application, the front door, the
//     sign-in screens and their steps, consent, the sign-out, GNAP's
//     interaction pages, the federation pages and the protocol families'
//     description pages. Each runtime draws it again from the facts the
//     shell's footer carries (`WebFooter.drawnIn()`).
//   * `common/error_page.ts`, the server-drawn error page, which runs no
//     script and carries it as markup.
//
// WHAT HAS NO FOOTER, AND WHY. A specification's endpoint is never converted
// (the root CLAUDE.md), and its documents are not this service's pages to
// furnish: the auto-POST forms (WS-Federation's sign-in response,
// `response_mode=form_post`, the SAML 2.0 HTTP POST binding and SAML 1.1's
// Browser/POST profile), the OP iframe at `/oauth2/check_session` (framed by
// a relying party, its one inline script admitted by hash), the federation
// fragment page, and the RFC 4559 exchange's own responses at
// `/authn/spnego` (`kerberos/spnego_authn.ts` turns its footer off). None
// of the first five is drawn through either caller above, so none has one;
// the last is a shell, and says so. Machine answers (JSON, XML, a JWT) are
// not pages. The embedded debugger (`debugger/`) is on a listener and an
// origin of its own with pages of its own, and the companion is not part
// of the service.
//
// A LIBRARY (rule 3): `helpers`, `version` and `page_locale`, which are
// leaves here; it registers nothing.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import version = require('./version');
import PageLocale = require('./page_locale');
import WebFooter = require('./web_footer');

const { log } = helpers;

type Json = any;

/**
 * The server's half of the footer. A static utility class; it holds no
 * state.
 */
class PageFooter {
  /**
   * The facts the footer draws: the version and its build line, as
   * `common/version.js` reads them, and the year.
   *
   * @param now - optional; the time, now when left out
   * @returns `{ version, buildInfo, year }`
   */
  static facts(now?: Date): { version: string, buildInfo: string,
                              year: string } {
    log.debug("Entering PageFooter.facts().");
    const v = version.load();
    const out = { version: String(v.version || ''),
                  buildInfo: String(version.buildInfo(v) || ''),
                  year: String((now || new Date()).getUTCFullYear()) };
    log.debug("Leaving PageFooter.facts(). " + out.version);
    return out;
  }

  /**
   * The footer's markup, in the page's language.
   *
   * @param t - optional; the page's translator, the ambient request's when
   *   left out
   * @returns the `<footer>` element
   */
  static html(t?: Json): string {
    log.debug("Entering PageFooter.html().");
    let translator = t || null;
    if (!translator) {
      try {
        translator = PageLocale.forPage();
      } catch (e) {
        // A language that cannot be worked out draws the footer in English,
        // which `WebFooter.word()` falls back to; a footer must not cost a
        // page.
        log.debug("Caught in PageFooter.html(): " +
                  ((e && (e as Error).message) || e));
        translator = null;
      }
    }
    const out = WebFooter.html(translator, PageFooter.facts());
    log.debug("Leaving PageFooter.html().");
    return out;
  }
}

export = PageFooter;
