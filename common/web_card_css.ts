// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_card_css.ts
//
// ---------------------------------------------------------------------------
// THE CARD: THE STYLESHEET A PERSON MEETS THIS SERVICE IN (#570, 2026-10-12).
//
// The sign-in screen, the federation chooser, the consent screen, GNAP's
// interaction, the wallet and SPNEGO sign-ins and the emailed-code pages are
// all drawn as one card on a grey page, with `authn/authn.ts`'s stylesheet
// inline in each (`authn.CARD_CSS`, which the others import rather than
// copy). The static public surfaces of #569 are drawn with the same card,
// as a stylesheet a shell links to (`/web/card.css`,
// `common/public_assets.ts`): moving the text here, to a `web_` module, is
// what lets the server pages and the static ones carry ONE copy, and lets a
// surface's renderer name the classes the card defines with nothing to keep
// in step. The two strings are byte for byte what `authn.ts` declared; that
// file's comment above them says why the chooser's rules are a constant of
// their own.
//
// A `web_` MODULE, on `admin-ui/web_kit.ts`'s terms: it requires nothing and
// logs nothing.
// ---------------------------------------------------------------------------

/**
 * The card's stylesheets. A static utility class of constants.
 */
class WebCardCss {
  /**
   * The language chooser's stylesheet (#539), small and to one side: a page's
   * first business is its own form. A constant of its own because the second
   * factor pages carry stylesheets of their own, and each appends this one —
   * their `button{width:100%}` and `input{width:100%}` would otherwise stretch
   * the chooser across the card.
   */
  static readonly CHOOSER_CSS =
    'form.language-chooser{float:right;font-size:.75em;margin:0 0 6px 8px}for' +
    'm.language-chooser select,form.language-chooser button{width:auto;displa' +
    'y:inline;padding:2px 6px;margin:0;font-size:1em}form.language-chooser la' +
    'bel{display:inline;margin:0 4px 0 0}';

  /**
   * What the sign-in surface's steps draw beyond the screen (#572, #573):
   * the notice a resend leaves, the warning of a set of recovery codes
   * running low, the set-up step's headings, a code's wide field, the ways
   * round a factor, the technical fold (the QR code's rule is the
   * wallet's, #574). They were in each step page's own stylesheet while the
   * server drew the steps.
   */
  static readonly STEP_CSS =
    '.ok{background:#eef7ee;border:1px solid #cfe6cf;color:#1d5c1d;padding:' +
    '8px 10px;border-radius:5px;font-size:.85em;margin-bottom:12px}.warn{bac' +
    'kground:#fff8e6;border:1px solid #f0dca8;color:#7a5a00;padding:8px 10px' +
    ';border-radius:5px;font-size:.85em;margin-bottom:12px}.card h2{font-siz' +
    'e:1em;margin:18px 0 6px}input.code{font-size:1.4em;letter-spacing:.35em' +
    ';text-align:center;font-family:ui-monospace,SFMono-Regular,Menlo,monosp' +
    'ace}.links div{margin:6px 0;font-size:.85em}details summary{cursor:poin' +
    'ter;color:#12107c}';

  /**
   * The console's prose fold (`WebKit.note()`, rcbj 2026-10-12): the
   * sign-in screen's explanations — the federation, Kerberos and wallet
   * blurbs and the notes at its foot — are each a `<p class="note">` or,
   * longer than a line, a `<details class="note fold">` whose summary is
   * the first sentence. The palette is the text's own (a fold reads as the
   * sentence it summarises), the marker the console's triangles.
   */
  static readonly FOLD_CSS =
    'p.note{margin:2px 0}.fed p.note,.fed details.note{font-size:.78em;color' +
    ':#666;margin:0 0 8px}details.fold{margin:2px 0}details.fold>summary{curs' +
    'or:pointer;color:inherit;list-style:none;display:flex;gap:.45em;align-i' +
    'tems:baseline}details.fold>summary::-webkit-details-marker{display:none' +
    '}details.fold>summary::before{content:"\\25b8";flex:none;font-size:.9e' +
    'm}details.fold[open]>summary::before{content:"\\25be"}details.fold>sum' +
    'mary:focus-visible{outline:2px solid #555;outline-offset:2px}.foldbody{m' +
    'argin:.3em 0 0 1.05em}';

  /**
   * The WIDE card (#575): the SPNEGO sign-in's pages carry tables — the
   * service principal, the ticket's flags, the acceptor's checks — that do
   * not fit the 380-pixel card, so `.card.wide` lifts the width and every
   * rule below is scoped to it, leaving every other page of the card as it
   * was. The values are `kerberos/spnego.js`'s page shell's, where these
   * pages were drawn until #575.
   */
  static readonly WIDE_CSS =
    '.card.wide{width:auto;max-width:52rem;margin:2rem;line-height:1.45}.wid' +
    'e h2{font-size:1em;margin:1.4em 0 .4em}.wide table{border-collapse:coll' +
    'apse;width:100%;margin:.5rem 0 1rem;font-size:.85em}.wide th,.wide td{b' +
    'order:1px solid #ddd;padding:.35rem .55rem;text-align:left;vertical-ali' +
    'gn:top}.wide th{background:#f0f0f5}.wide .pass{color:#0b6b4f;font-weigh' +
    't:600;white-space:nowrap}.wide .fail{color:#b00020;font-weight:600;whit' +
    'e-space:nowrap}.wide .ok{background:#e8f5e9;border:1px solid #a5d6a7;pa' +
    'dding:8px 10px;border-radius:5px;font-size:.9em;margin-bottom:12px}.wid' +
    'e code{font-size:.85em;background:#f4f4f8;padding:.1rem .25rem;border-r' +
    'adius:3px;word-break:break-all}.wide a{color:#12107c}';

  /**
   * The CONSENT SCREEN's card (#576): the rules `oauth-oidc/consent_screen.ts`
   * appended to the card while it drew the page, scoped to `.card.consent` so
   * no other page of the card changes — a wider card for the scope rows,
   * each scope and authorization detail in a box of its own, a detail's
   * members as a grid, a detail's limits (#432 phase 5), and the fold of
   * what was already agreed.
   */
  static readonly CONSENT_CSS =
    '.card.consent{width:460px}.consent div.limits{margin:6px 0 0;font-size:' +
    '.9em}.consent div.limits div{margin:3px 0}.consent p.app{font-size:.9em' +
    ';margin:0 0 14px}.consent ul.scopes{list-style:none;padding:0;margin:0 ' +
    '0 8px}.consent ul.scopes li{padding:8px 10px;margin:6px 0;border:1px so' +
    'lid #e3e3ea;border-radius:6px;background:#fafafd;font-size:.85em}.conse' +
    'nt ul.scopes li span{display:block;color:#666;font-size:.9em;margin-top' +
    ':3px}.consent ul.scopes li dl{margin:6px 0 0;display:grid;grid-template' +
    '-columns:auto 1fr;gap:2px 8px}.consent ul.scopes li dt{color:#555}.cons' +
    'ent ul.scopes li dd{margin:0;overflow-wrap:anywhere}.consent details{ma' +
    'rgin:10px 0 0;font-size:.8em;color:#555}';

  /**
   * GNAP's interaction pages (#578), which carried these in a `<style>` of
   * their own (`gnap_interact.ts`'s `PAGE_CSS`) until they became a static
   * surface: the wider card, the client's line and logo, the rights as a
   * list of boxes, a right's limits under it, and the user code's field.
   * Every rule is scoped to `.gnap`, the class the surface's card carries,
   * so no other page of the card changes.
   */
  static readonly GNAP_CSS =
    '.card.gnap{width:520px}.gnap p.app{font-size:.9em;margin:0 0 14px}.gna' +
    'p ul.rights{list-style:none;padding:0;margin:0 0 8px}.gnap ul.rights l' +
    'i{padding:8px 10px;margin:6px 0;border:1px solid #e3e3ea;border-radius' +
    ':6px;background:#fafafd;font-size:.85em}.gnap ul.rights li label{displ' +
    'ay:flex;gap:8px;align-items:flex-start}.gnap ul.rights li span{display' +
    ':block;color:#666;font-size:.9em;margin-top:3px}.gnap img.logo{max-wid' +
    'th:48px;max-height:48px;float:right;margin:0 0 6px 8px}.gnap input.cod' +
    'e{font-size:1.4em;letter-spacing:.2em;text-transform:uppercase;width:1' +
    '00%;text-align:left}.gnap div.limits{margin:6px 0 0 24px;font-size:.9e' +
    'm}.gnap div.limits div{margin:3px 0}.gnap div.limits input{font-size:.' +
    '95em}';

  /**
   * The protocol families' description pages (#584): `/saml2`, `/saml11`,
   * `/xacml`, `/ssf`, `/scim` and `/spiffe`, each a long page of tables
   * that the server drew in a stylesheet of its own until then — a wider
   * card, a note, the lists, a third-level heading. Scoped to `.describe`,
   * the class the surface's card carries, so no other page of the card
   * changes.
   */
  static readonly DESCRIBE_CSS =
    '.card.wide.describe{max-width:60rem}.describe .note{color:#666}.descr' +
    'ibe ul{margin:.3em 0;padding-left:1.2em}.describe li{margin:.2em 0}.d' +
    'escribe h3{font-size:.95em;margin:1.2em 0 .3em}.describe p{line-heigh' +
    't:1.5}.describe .row a{text-decoration:none}';

  /**
   * The DIAGNOSTIC pages (#583): the TLS pages and the SPNEGO demonstration
   * pages, which carried these in the `<style>` of their own server-drawn
   * shells (`tls_server.js`'s `pageShell()`, `spnego.js`'s `page()`) until
   * they became static surfaces — a verdict's band, the truststore's PEM
   * box, a list's indent — scoped to `.diag`, the class their card carries,
   * and the TLS page's wider card to `.tls`, so no other page changes.
   */
  static readonly DIAG_CSS =
    '.card.tls{max-width:60rem}.diag p.verdict{background:#f0f0f8;border-l' +
    'eft:4px solid #12107c;padding:.6rem .8rem;margin:.6rem 0}.diag textar' +
    'ea{width:100%;box-sizing:border-box;font-family:ui-monospace,monospac' +
    'e;font-size:.8em}.diag ul{margin:.3em 0;padding-left:1.2em}.diag li{m' +
    'argin:.2em 0}';

  /**
   * The stylesheet of the sign-in screen and the federation chooser, shared
   * with the consent screen; the wide card's rules after the chooser's.
   */
  static readonly CARD_CSS =
    'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;bac' +
    'kground:#f4f4f7;margin:0;display:flex;align-items:center;justify-content' +
    ':center;min-height:100vh;color:#222}.card{background:#fff;border:1px sol' +
    'id #d5d5dd;border-radius:10px;padding:28px 32px;width:380px;box-shadow:0' +
    ' 6px 24px rgba(0,0,0,.08)}h1{font-size:1.25em;margin:0 0 4px}p.sub{color' +
    ':#666;font-size:.85em;margin:0 0 18px}label{display:block;font-size:.85e' +
    'm;font-weight:600;margin:12px 0 4px}input[type=text],input[type=password' +
    ']{width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid #bb' +
    'b;border-radius:5px;font-size:1em}.row{display:flex;gap:10px;margin-top:' +
    '20px}button{flex:1;padding:9px 12px;border-radius:5px;border:1px solid #' +
    '12107c;background:#12107c;color:#fff;font-size:.95em;cursor:pointer}butt' +
    'on.secondary{background:#fff;color:#12107c}.err{background:#fdecea;borde' +
    'r:1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;fon' +
    't-size:.85em;margin-bottom:12px}.meta{margin-top:20px;padding-top:14px;b' +
    'order-top:1px solid #eee;font-size:.75em;color:#777;word-break:break-all' +
    '}.meta div{margin:2px 0}code{font-family:ui-monospace,SFMono-Regular,Men' +
    'lo,monospace}.fed{margin-top:18px;padding-top:14px;border-top:1px solid ' +
    '#eee}.fed p{font-size:.78em;color:#666;margin:0 0 8px}a.fedbtn{display:b' +
    'lock;text-align:center;padding:9px 12px;margin:6px 0;border-radius:5px;b' +
    'order:1px solid #12107c;color:#12107c;background:#fff;text-decoration:no' +
    'ne;font-size:.9em}a.fedbtn span{display:block;font-size:.75em;color:#777' +
    '}' +
    // THE WALLET SIGN-IN'S PAGES (#574), which carried these in a `<style>`
    // of their own until they became routes of the sign-in surface: the QR
    // code, the presentation's checks, and the Digital Credentials API
    // button, which is a button and looks like the link beside it.
    '.qr{display:block;margin:12px auto;text-align:center}.checks{font-size:' +
    '.8em;margin:8px 0;padding-left:18px}.checks .bad{color:#b00020}button.f' +
    'edbtn{display:block;width:100%;margin:6px 0}button.fedbtn span{display:' +
    'block;font-size:.75em}' +
    WebCardCss.CHOOSER_CSS + WebCardCss.STEP_CSS + WebCardCss.FOLD_CSS +
    // The steps' rules BEFORE the wide card's, which win where both speak.
    WebCardCss.WIDE_CSS + WebCardCss.CONSENT_CSS +
    // GNAP's (#578): scoped to its own card, and after the steps'
    // code field, which its own replaces.
    WebCardCss.GNAP_CSS +
    // The description pages' last (#584), scoped to their own card.
    WebCardCss.DESCRIBE_CSS +
    // The diagnostic pages' last (#583), scoped to `.diag` and `.tls`.
    WebCardCss.DIAG_CSS;
}

export = WebCardCss;
