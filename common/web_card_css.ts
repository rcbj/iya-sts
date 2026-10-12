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
    WebCardCss.CHOOSER_CSS + WebCardCss.WIDE_CSS;
}

export = WebCardCss;
