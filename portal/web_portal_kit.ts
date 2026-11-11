// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_portal_kit.ts
//
// ---------------------------------------------------------------------------
// THE USER PORTAL'S RENDERING KIT (#568): what every page of the portal is
// drawn with in the browser — escaping, the icons, the stylesheet and the
// page list. The portal became a static application over `/account-api` on
// #568, on the admin console's pattern (#446), and these are the pieces of
// `portal.ts` its renderers need, MOVED here rather than copied, so the
// server and the browser cannot hold two page lists.
//
// THE TABLE IS THE PAGE LIST AND THERE IS NO SECOND COPY. The frame
// (`web_portal_shell.ts`) draws the column from it and titles the page from
// it, and `portal.ts`'s `paths()` reports it to `sts_metadata.ts` — so a
// page added here appears in the column, in the browser tab and in the
// endpoint list, and one removed leaves none of the three behind. Its keys
// name the `portal` catalog's entries (#539); the English beside them is the
// catalog's English.
//
// A `web_` MODULE, on `admin-ui/web_kit.ts`'s terms: it requires only
// `common/web_nav_sections.ts` (the navigation's rules, shared with the
// console since #1229), logs nothing, and is bundled for a browser by
// `build-typescript.sh`. The
// server reads `NAV` and `STYLE` from it — the console's `web_database.ts`
// arrangement — and never the other way round.
// ---------------------------------------------------------------------------

import WebNavSections = require('../common/web_nav_sections');
import WebLocale = require('../common/web_locale');

type Json = any;

/**
 * The portal's base path.
 */
const BASE = '/portal';

const SVG_OPEN = '<svg class="ico" width="22" height="22" ' +
  'viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" ' +
  'aria-hidden="true" focusable="false">';
const PORTAL_ICONS = {
  passkey: SVG_OPEN + '<circle cx="8" cy="7.5" r="3.5"/>' +
    '<path d="M2 20c0-3.6 2.7-6 6-6 1.5 0 2.9.5 4 1.4"/>' +
    '<circle cx="17.5" cy="11" r="2.5"/><path d="M17.5 13.5V21"/>' +
    '<path d="M17.5 17.5h2M17.5 20h1.5"/></svg>',
  devices: SVG_OPEN + '<rect x="2" y="5" width="13" height="9" rx="1"/>' +
    '<path d="M1 17.5h15"/><rect x="17.5" y="8" width="5" height="11" ' +
    'rx="1"/><path d="M19.5 16.5h1"/></svg>',
  securityKey: SVG_OPEN + '<rect x="8" y="2" width="8" height="13" ' +
    'rx="2"/><circle cx="12" cy="8" r="1.8"/><path d="M9.5 15v6h5v-6"/>' +
    '<path d="M11 18h2"/></svg>'
};

// The stylesheet as written, in the portal's own palette; `PortalKit.STYLE`
// is what is served, every colour a realm may set read through a custom
// property (`themed()`, #717).
// WHAT WAS A `style=""` (2026-11-10). The portal's policy is `style-src
// 'self'` with no 'unsafe-inline', so a style attribute in the markup is not
// applied; these classes carry what the attributes did. A sign-in's level is
// a chip in the level's colours (`web_sign_ins.ts`), and a one-button form
// sits inline beside the text it acts on.
const NO_INLINE_STYLE =
  '.inline-form{display:inline}' +
  '.level{padding:2px 8px;border-radius:10px;font-weight:600}' +
  '.level-LOW{background:#e6f4ea;color:#137333}' +
  '.level-MEDIUM{background:#fef7e0;color:#b06000}' +
  '.level-HIGH{background:#fce8e6;color:#a50e0e}' +
  '.level-UNSCORED{background:#f1f3f4;color:#3c4043}';

const STYLE_AS_WRITTEN =
  'body{font-family:system-ui,-apple-system,"Segoe ' +
  'UI",Arial,sans-serif;background:#f4f4f7;margin:0;padding:2rem ' +
  '1rem;color:#222;line-height:1.5}.wrap{max-width:720px;margin:0 ' +
  'auto}.card{background:#fff;border:1px solid ' +
  '#d5d5dd;border-radius:10px;padding:24px ' +
  '28px;margin-bottom:18px;box-shadow:0 2px 10px ' +
  'rgba(0,0,0,.04)}h1{font-size:1.4em;margin:0 0 ' +
  '4px}h2{font-size:1.05em;margin:0 0 12px}' +
  // The language chooser, a collapsed row in the header (#1289).
  WebLocale.ROW_CSS +
  // The heading and its one control on the same line. `align-items:start` and
  // not `center`: the button is a small box beside a large heading and centring
  // it drags it down past the heading's baseline. The form's margin is reset
  // because `button` carries a top margin of its own for the stacked forms
  // below, which is right there and wrong here.
  '.menuphoto{width:24px;height:24px;border-radius:50%;object-fit:cover;' +
  'vertical-align:middle;margin-right:6px}.photoshown{width:128px;' +
  'height:128px;border-radius:50%;object-fit:cover;display:block;' +
  'margin:8px 0}' +
  '.pagehead{display:flex;gap:12px;align-items:start;' +
  'justify-content:space-between;flex-wrap:wrap}.pagehead ' +
  'h1{margin:0}.pagehead form{margin:0}.pagehead .acts{display:flex;' +
  'gap:8px;align-items:start;flex-wrap:wrap}.pagehead ' +
  'button{margin-top:0}' +
  // THE OPEN CHOOSER STAYS IN THE HEADER'S ROW, not dropped below it: the
  // shared row's drop-down sat over the Switch user button, so here the
  // form is in the flow beside its summary, its label inline and its
  // controls the header's size, and Refresh, Sign out and Switch user move
  // left to make room. `.acts` wraps, so a narrow window puts the chooser
  // on a line of its own rather than off the edge.
  '.pagehead details.language-row[open]{display:flex;align-items:center;' +
  'gap:6px}.pagehead details.language-row form.language-chooser{' +
  'position:static;border:0;padding:0;box-shadow:none;background:none}' +
  '.pagehead form.language-chooser label{display:inline;margin:0}' +
  '.pagehead form.language-chooser select{padding:6px 8px}' +
  '.pagehead form.language-chooser button{padding:7px 12px}' +
  // THE ACCOUNT MENU (#561), drawn only with several accounts on: a
  // `<details>` beside Sign out whose panel drops below it, its buttons
  // reading as links.
  '.usermenu{position:relative}.usermenu>summary{cursor:pointer;' +
  'list-style:none;border:1px solid #c9c9d2;border-radius:6px;padding:7px ' +
  '12px;background:#fff;color:#333;font-size:.9em}.usermenu>summary::-' +
  'webkit-details-marker{display:none}.usermenupanel{position:absolute;' +
  'right:0;top:calc(100% + 6px);z-index:30;min-width:14rem;background:' +
  '#fff;border:1px solid #d5d5dd;border-radius:8px;box-shadow:0 8px 28px ' +
  'rgba(0,0,0,.14);padding:6px}.usermenupanel button.linklike{display:' +
  'block;width:100%;margin:0;text-align:left;background:none;color:' +
  '#2c5cc5;padding:6px 8px}.usermenupanel button.linklike:hover{' +
  'background:#eef2fb}.usermenupanel button span{color:#777;font-size:' +
  '.9em}' +
  // What the Switch user group says rather than offers (#751): there is no
  // other account yet, and the one this tab leaves stays signed in.
  '.usermenupanel p.usermenunote{margin:4px 8px;color:#666;font-size:' +
  '.8em}' +
  'p.sub{color:#666;font-size:.9em;margin:0 0 ' +
  '18px}label{display:block;font-size:.85em;font-weight:600;margin:12px 0 ' +
  '4px}input[type=text],input[type=password]{width:100%;padding:9px ' +
  '10px;border:1px solid #c9c9d2;border-radius:6px;font-size:1em;' +
  'box-sizing:border-box}button{margin-top:14px;padding:9px 16px;border:0;' +
  'border-radius:6px;background:#2c5cc5;color:#fff;font-size:.95em;' +
  // The two buttons NOT in the accent keep white text whatever the realm's
  // accent asks of the others (#717): written `#ffffff` so `themed()`,
  // which turns every `color:#fff` into the text on the accent, leaves
  // them alone. They render as they always did.
  'cursor:pointer}button.danger{background:#b00020;color:#ffffff}' +
  'button.secondary{background:#5a5a68;color:#ffffff}' +
  'table{border-collapse:collapse;' +
  'width:100%;font-size:.9em}th,td{text-align:left;padding:7px ' +
  '10px;border-bottom:1px solid #e6e6ec}th{color:#555;font-weight:600;' +
  'width:34%}.err{background:#fdecef;border:1px solid ' +
  '#f5c2cb;color:#8a1027;padding:10px 12px;border-radius:6px;' +
  'margin-bottom:14px;font-size:.9em}.ok{background:#eaf6ec;border:1px solid ' +
  '#bfe3c6;color:#1d5b2a;padding:10px 12px;border-radius:6px;' +
  'margin-bottom:14px;font-size:.9em}.note{color:#555;font-size:.85em;' +
  'margin:10px 0 0}code{background:#f0f0f5;padding:1px ' +
  '5px;border-radius:4px;font-size:.9em}' +
  // A LONG VALUE IN A TABLE CELL BREAKS ANYWHERE (2026-10-20, rcbj on 8081):
  // an identifier has no spaces, so a did:jwk — two hundred characters of
  // base64url — set the table's minimum width and pushed it far past its
  // card on /portal/self-issued. `anywhere` (not `break-word`) is what lets
  // the table's automatic layout shrink the column to fit.
  'td code{overflow-wrap:anywhere}' +
  // ...EXCEPT A VALUE DRAWN ON ONE LINE (2026-10-20, rcbj on
  // /portal/self-issued: "a single line", the whole value in a tooltip). A
  // block of its own width, cut with an ellipsis, so the column is that
  // wide whatever the value; its `title` carries the rest. Narrower on a
  // phone, where seven columns have less than half the room.
  'td .oneline{display:inline-block;max-width:13em;overflow:hidden;' +
  'text-overflow:ellipsis;white-space:nowrap;overflow-wrap:normal;' +
  'vertical-align:bottom;cursor:help}' +
  'td .oneline.location{max-width:10em}' +
  '@media (max-width:40rem){td .oneline{max-width:8em}' +
  'td .oneline.location{max-width:7em}}' +
  // The last resort for a heading-row table too wide for its card on a
  // narrow screen: it scrolls inside the card rather than past it.
  '.scrollx{overflow-x:auto;max-width:100%}' +
  // THE LINK TO A DID'S DOCUMENT, one short line under the subject.
  'td .didlink{font-size:.85em;margin-top:2px;white-space:nowrap}' +
  // ONE DID'S DOCUMENT (/portal/self-issued/did): the DID breaks anywhere,
  // and the JSON keeps its indentation but wraps a long line inside the
  // card — a did:jwk's `x` is one base64url line — rather than running out.
  '.didpage code{overflow-wrap:anywhere}' +
  'pre.diddoc{white-space:pre-wrap;overflow-wrap:anywhere;' +
  'overflow-x:auto;max-width:100%;background:#f6f6fa;border:1px solid ' +
  '#e6e6ec;border-radius:6px;padding:10px 12px;font-size:.85em;margin:0}' +
  // THE RECOVERY CODE LIST (2026-09-10). Two columns where there is room and
  // one where there is not, because the list is read off a phone as often as
  // off a laptop — and a ten-character code that wraps mid-string is one
  // somebody transcribes wrongly. `.spent` is struck through AND dimmed: the
  // strike alone is invisible to a reader who cannot see it, and the word
  // `used` beside it in the markup is what actually carries the meaning.
  // ---------------------------------------------------------------------
  // THE DIRECTORY ENTRY TABLE (2026-09-11). `.attr` is the LDAP name and the
  // RFC under each value — small, grey and always drawn rather than hidden in
  // a tooltip, because the whole reason somebody reads this page on a MOCK is
  // to find out what the attribute is called before they go and write it over
  // LDAP. A `title` carries the same thing for a pointer; neither is the only
  // copy, because a title is invisible on a phone.
  // SCOPED, and that is not fussiness. A bare `h3` rule here would restyle
  // `/portal/mfa`'s two headings as well — *Or type it in* and *Then prove it
  // works* — which is a change to a page this feature has nothing to do with,
  // made by a stylesheet shared between them.
  '.dirhead{margin-top:24px;padding-top:18px;border-top:1px solid #e6e6ec;' +
  'font-size:.95em;margin-bottom:8px}' +
  'h3.dirclass{font-size:.95em;margin:18px 0 8px}' +
  '.attr{color:#8a8a97;font-size:.78em;margin-top:2px}' +
  '.attr code{background:none;padding:0;color:#6a6a77}' +
  '.unset{color:#9a9aa6;font-style:italic}' +
  '.set{color:#1d5b2a;font-weight:600}' +
  '.must{background:#eef1fb;color:#2c5cc5;font-size:.7em;font-weight:600;' +
  'padding:1px 5px;border-radius:3px;vertical-align:middle;margin-left:4px}' +
  'ul.vals{list-style:none;margin:0;padding:0}ul.vals li{margin:0 0 2px}' +
  // The fold. `<details>` is MARKUP — see directoryBlock()'s header — so this
  // page keeps `script-src 'none'` and still collapses fifty rows.
  'details{margin:6px 0 0}' +
  'details summary{cursor:pointer;color:#2c5cc5;font-size:.85em;' +
  'padding:4px 0}' +
  'details table{margin-top:4px}' +
  // A FOLDED BLOCK OF TEXT (#1289): its bold lead (or title) as the summary,
  // read as the start of the text rather than as a link, and the rest under
  // it, indented to the disclosure mark.
  'details.prose{margin:8px 0 0}details.prose>summary{color:#333;' +
  'font-size:.88em;font-weight:600}details.prose>summary:hover{color:#2c5cc5}' +
  '.prose-body{margin:2px 0 0 1.1em}.prose-body p:first-child{margin-top:0}' +
  // THE PASSKEY LIST (#470): one row per passkey, an icon, a body that
  // wraps, and the actions at the end; the two calls to action side by side.
  'svg.ico{vertical-align:-5px;margin-right:6px;color:#2c5cc5}' +
  'button svg.ico{color:#fff;vertical-align:-6px}' +
  'h2.pkgroup{margin:22px 0 4px}' +
  'ul.pk{list-style:none;margin:0;padding:0}' +
  'ul.pk>li{display:flex;gap:10px;align-items:flex-start;padding:12px 0;' +
  'border-bottom:1px solid #e6e6ec}' +
  'ul.pk .body{flex:1;min-width:0}ul.pk .name{font-weight:600}' +
  'ul.pk .meta{color:#666;font-size:.85em}' +
  'ul.pk .acts form{margin:0}ul.pk .acts button{margin-top:0;' +
  'padding:6px 12px}' +
  '.ctas{display:flex;gap:10px;flex-wrap:wrap}' +
  // THE PEM BLOCK (2026-09-12). A private key is eighteen lines of base64 that
  // must be copied WHOLE and must not be re-wrapped by the browser: a PEM with
  // a line break inserted where the sender did not put one is a PEM openssl
  // refuses, and somebody debugging that spends the afternoon on the wrong
  // problem. So it scrolls sideways rather than wrapping, and `user-select:all`
  // makes one click select the lot — the block is there to be taken away.
  'pre.pem{background:#f7f7fb;border:1px solid #d5d5dd;border-radius:6px;' +
  'padding:12px 14px;margin:12px 0 0;font-size:.78em;line-height:1.45;' +
  'overflow-x:auto;white-space:pre;user-select:all}' +
  'ul.codes{list-style:none;margin:14px 0 0;padding:0;display:grid;' +
  'grid-template-columns:repeat(auto-fill,minmax(11rem,1fr));gap:8px}' +
  'ul.codes li{margin:0}' +
  'ul.codes code{display:inline-block;font-size:1.05em;letter-spacing:.06em;' +
  'padding:6px 9px}' +
  'ul.codes code.spent{text-decoration:line-through;color:#8a8a97;' +
  'background:#f6f6f9}' +
  // -------------------------------------------------------------------------
  // THE TWO-COLUMN SHELL AND ITS NAVIGATION (2026-09-06). Its own rules and
  // its own palette: the console's sidebar is #12107c and forty pages long,
  // this one is the portal's blue and has eight, and the two files sharing a
  // stylesheet is the thing this application deliberately does not do.
  //
  // `.side` is STICKY and has no `overflow-y` of its own, which is the one
  // difference from the console's worth stating rather than leaving as a
  // divergence somebody 'fixes'. That console scrolls its own nav because the
  // list is longer than a screen; eight items are not, and a scroll container
  // here would only ever be a box that never scrolls — and would bring the
  // `autofocus` trick that console needs to scroll the list back to the
  // current page. There is no `autofocus` in this application at all.
  // -------------------------------------------------------------------------
  '.wrap.wide{max-width:1040px}' +
  '.shell{display:flex;flex-wrap:wrap;align-items:flex-start;gap:18px}' +
  '.side{flex:0 0 13rem;position:sticky;top:1rem}' +
  '.side .card{padding:16px 14px;margin-bottom:0}' +
  '.main{flex:1 1 28rem;min-width:0}' +
  '.doclink{margin:0 0 12px;font-size:.92em}' +
  'nav ul{list-style:none;margin:0;padding:0}' +
  // THE SECTIONS ARE THE CONSOLE'S SINCE #1229: a `<summary>` heading that
  // opens and closes its section, one open at a time, and the rule down the
  // left marking the section the current page is in, open or closed, so a
  // reader who arrived on a deep link can see where they are without opening
  // every section. The rules are `common/web_nav_sections.ts`'s, which argues
  // them, in the portal's blue; the card's left padding is 14px.
  WebNavSections.css('#2c5cc5', '#6a6a78', 14) +
  'nav a,nav .here{display:block;padding:4px 7px;' +
  'border-radius:5px;text-decoration:none;color:#2c5cc5;font-size:.9em}nav ' +
  'a:hover{background:#eef2fb}nav .here{font-weight:700;color:#fff;' +
  'background:#2c5cc5}.who{color:#666;font-size:.85em;margin:3px 0 0}' +
  // A HEADER TABLE RATHER THAN A LABEL COLUMN. `th` above is 34% wide because
  // every table in this application until now was two columns of name and
  // value; the applications list is four columns with a heading ROW, where a
  // third of the width for the first cell is simply wrong.
  '.grid th{width:auto;color:#555}' +
  '.grid td strong{display:block}' +
  // SECURITY ACTIVITY'S PAYLOADS SCROLL IN THEIR OWN BOX. A signal's
  // payload is whatever its transmitter sent and can be any size, and a
  // table cell grows to fit its content, so one long line of JSON pushed the
  // whole table past the card's edge. With a FIXED layout the columns keep
  // the card's width, the two narrow ones wrap a long event type URI, and
  // the payload scrolls inside a box of bounded size, sideways and down.
  'table.grid.signals{table-layout:fixed}' +
  'table.grid.signals th:nth-child(1){width:11em}' +
  'table.grid.signals th:nth-child(2){width:30%}' +
  'table.grid.signals td{overflow-wrap:anywhere;vertical-align:top}' +
  'pre.signal-payload{overflow:auto;max-width:100%;max-height:24rem;' +
  'white-space:pre;overflow-wrap:normal;background:#f7f7fb;' +
  'border:1px solid #d5d5dd;border-radius:6px;padding:8px 10px;' +
  'margin:6px 0;font-size:.85em}' +
  // THE APPLICATION'S NAME WHEN THERE IS SOMEWHERE TO GO, and when there is
  // not. The grey is the whole of what tells a reader the difference at a
  // glance, so it is a real colour change rather than the link colour with the
  // underline removed — which reads as a link that has been visited.
  '.grid td strong .home{color:#2c5cc5}' +
  '.grid td strong .unlinked{color:#8a8a96;cursor:help}' +
  '.grid td strong a.launch{font-size:.85em;font-weight:normal;' +
  'margin-left:.5em}' +
  // A BLOCK, because two of them follow the application's name in one cell —
  // the identifier and the description — and inline they run together into
  // one line that reads as a single fact.
  '.ident{display:block;color:#666;font-size:.85em}.tag{display:inline-block;' +
  'background:#eef2fb;border:1px solid ' +
  '#d3ddf4;color:#26417d;border-radius:4px;padding:0 6px;margin:0 4px 3px ' +
  '0;font-size:.8em}.pagenav{margin:14px 0 0;font-size:.85em}.pagenav ' +
  'a,.pagenav span{display:inline-block;padding:3px 9px;border:1px solid ' +
  '#d5d5dd;border-radius:5px;margin-right:6px;text-decoration:none;' +
  'color:#2c5cc5;background:#fff}.pagenav .here{background:#2c5cc5;' +
  'border-color:#2c5cc5;color:#fff;font-weight:700}.pagenav ' +
  '.off{color:#9a9aa6;background:#f4f4f7}' +
  // One column on a narrow screen, and the sections laid out across the top
  // rather than stacked: four headings down the page before any content would
  // be a phone showing nothing but navigation.
  '@media (max-width:52rem){.side{position:static;flex:1 1 100%}' +
  WebNavSections.narrowCss('#2c5cc5', '10rem') + '}' +
  // The version line at the foot of every page. Quiet and small: it is
  // provenance rather than content, and this is the surface a person visits to
  // change their own password, not one they came to read a build number off.
  '.ver{color:#9a9aa6;font-size:.78em;text-align:center;margin:16px 0 0}' +
  // THE TLS CLIENT CERTIFICATE CARD (2026-09-13). A select for the key
  // algorithm and the revocation reason, drawn like the text inputs above it;
  // download LINKS that look like buttons, because a `data:` link with
  // `download` is how a file leaves a page with no script on it; and the
  // install steps, one browser per fold.
  'select{padding:8px;border:1px solid #c7c7d1;border-radius:6px;' +
  'font:inherit;background:#fff;max-width:100%}' +
  'a.dl{display:inline-block;background:#2c5cc5;color:#fff;' +
  'text-decoration:none;border-radius:6px;padding:9px 14px;' +
  'margin:6px 8px 0 0;font-size:.9em}a.dl.secondary{background:#5a5a68;' +
  'color:#ffffff}' +
  // WHAT A GENERATE JUST ANSWERED, ONCE (#671): the certificate's row with
  // its two downloads, tinted and outlined, and what to do with them in a
  // block under the table, set apart from the card around it — the one thing
  // on the page that will not come back is the thing that shows.
  '.fresh{border:2px solid #2c5cc5;background:#f3f6fd;border-radius:8px;' +
  'padding:4px 14px 12px;margin:8px 0 14px}.fresh h3{margin-top:10px}' +
  'tr.fresh-row>td,tr.fresh-row>th{background:#f3f6fd;border-top:2px solid ' +
  '#2c5cc5;border-bottom:2px solid #2c5cc5}.dl-row{display:flex;' +
  'flex-wrap:wrap;gap:6px;margin:0 0 6px}.dl-row a.dl{margin:0}' +
  // /portal/wallet's offer (#589): the Transaction Code a person reads off
  // the screen into a wallet, large and spaced, and the offer URI, which
  // breaks anywhere rather than running off the card.
  '.txcode{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;' +
  'font-size:2em;letter-spacing:.28em;font-weight:700;color:#12107c;' +
  'background:#f0f0fa;border-radius:8px;padding:10px 6px;margin:6px 0;' +
  'text-align:center}.offer-uri{word-break:break-all;font-family:' +
  'ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.75em;' +
  'color:#555;background:#fafafa;border:1px solid #eee;border-radius:6px;' +
  'padding:8px}' +
  'ol.steps{margin:6px 0 0 1.2em;padding:0;font-size:.9em}' +
  'ol.steps li{margin:0 0 4px}' +
  '.state-valid{color:#1b7a3a;font-weight:600}' +
  '.state-revoked,.state-superseded{color:#b00020;font-weight:600}' +
  '.state-expired{color:#8a8a96;font-weight:600}' +
  '.ver code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}';

const NAV = [
  // `key` names the section in the `portal` catalog (#539): its title and
  // `what` are `portal.section.<key>.title` and `.what`; a page's label and
  // heading are `portal.nav.<slug>.label` and `.heading`, its slug read from
  // the path (`navSlug()`). The English here is the catalog's English.
  { key: 'account', title: 'Your account',
    what: 'What this identity provider knows about you, and where you can ' +
          'use it.',
    items: [
      { path: BASE, label: 'Overview', heading: 'Your account' },
      { path: BASE + '/applications', label: 'Applications',
        heading: 'Applications you can sign in to' },
      // SECURITY ACTIVITY (2026-09-10). Under *Your account* rather than under
      // *How I sign in*, and the two headings are the argument: that section
      // holds the CREDENTIALS on this person's entry, one page each, and every
      // page in it is a control. This is not a control and not about a
      // credential — it is what this identity provider has SAID about them,
      // to this portal, over the Shared Signals Framework. A reader arrives at
      // it asking what happened rather than asking to change something.
      { path: BASE + '/signals', label: 'Security activity',
        heading: 'Your security activity' },
      // RECENT SIGN-INS (#62 P6, 2026-09-22), beside Security activity and
      // for its reason: not a control over a credential, but what this
      // service made of the person's sign-ins — with the one control that
      // belongs there, saying whether each was them. Drawn by
      // `portal_sign_ins.ts`.
      { path: BASE + '/sign-ins', label: 'Recent sign-ins',
        heading: 'Your recent sign-ins' },
      // CONSENTS (#172, 2026-09-23), under *Your account* for Security
      // activity's reason: not a credential, but what this person has let
      // each application ask for — with the one control that belongs there,
      // taking it back. Drawn by `portal_consents.ts`.
      { path: BASE + '/consents', label: 'Consents',
        heading: 'What you have agreed applications may do' },
      // GNAP GRANTS (#432 phase 7, 2026-10-03), beside Consents and for its
      // reason: what this person has let applications do, with the one
      // control that belongs there, revoking it. A page of its own rather
      // than a section of Consents — `portal_gnap.ts`'s header argues it.
      { path: BASE + '/gnap', label: 'GNAP grants',
        heading: 'Access you have given through GNAP' },
      // EMAIL (#63, 2026-09-22): the address this service writes to, whether
      // it is verified, which messages may be declined, and what was sent.
      // Under *Your account* for Security activity's reason — it is what this
      // service SAYS to the person, not a credential. Drawn by
      // `portal_mail.ts`.
      { path: BASE + '/email', label: 'Email',
        heading: 'Your email address and messages' },
      // SIGN-IN NAMES (#644). Under *Your account* beside Email: another
      // name for the same person, not a credential. Drawn by
      // `portal_pseudonyms.ts`. The verification link is a page for
      // nobody and is not in this column.
      { path: BASE + '/pseudonyms', label: 'Sign-in names',
        heading: 'Names you can sign in with' }
    ] },
  // RESOURCES I OWN (#604, rcbj): what the owner fields on roles, groups,
  // service accounts and applications name this person — or a group they are
  // in — as answering for. Read-only; drawn by `web_owned.ts` from
  // `portal_owned.ts`'s four operations.
  { key: 'owned', title: 'Resources I own',
    what: 'The roles, groups, service accounts and applications that name ' +
          'you, or a group you are in, as an owner.',
    items: [
      { path: BASE + '/owned/roles', label: 'Roles',
        heading: 'Roles you own' },
      { path: BASE + '/owned/groups', label: 'Groups',
        heading: 'Groups you own' },
      { path: BASE + '/owned/service-accounts', label: 'Service accounts',
        heading: 'Service accounts you own' },
      { path: BASE + '/owned/applications', label: 'Applications',
        heading: 'Applications you own' }
    ] },
  // SHARING (#1168, rcbj's decision 7): User-Managed Access 2.0 — what the
  // person shares, as a policy they write, and what others share with
  // them. A section of its own rather than under *Your account*, because
  // its first page is a CONTROL over somebody else's access, which no page
  // there is. Drawn by `web_shared.ts` from `portal_shared.ts`.
  { key: 'sharing', title: 'Sharing',
    what: 'What you share with other people through User-Managed Access, ' +
          'and what they share with you.',
    items: [
      { path: BASE + '/shared', label: 'What I share',
        heading: 'What you share' },
      { path: BASE + '/shared-with-me', label: 'Shared with me',
        heading: 'What others share with you' }
    ] },
  { key: 'signIn', title: 'How I sign in',
    what: 'The credentials on your own entry, one page each.',
    items: [
      { path: BASE + '/password', label: 'Password',
        heading: 'Change your password' },
      // PASSKEYS (#470): the one heading the passkey guidelines put over
      // every kind, security keys included; the path is unchanged.
      { path: BASE + '/keys', label: 'Passkeys',
        heading: 'Passkeys' },
      // THE AUTHENTICATOR APP (2026-09-10). Its own page beside the keys
      // rather than a card on that one, for the reason this column exists at
      // all: the enrolment is a QR code, a transcribable secret, a code field
      // and three paragraphs about which app to use, and putting it under a
      // list of security keys would bury the control somebody came for below a
      // page about something else.
      { path: BASE + '/mfa', label: 'Authenticator app',
        heading: 'Your authenticator app' },
      // THE SIGNING KEY (2026-09-12), and this section rather than *Your
      // account* — which is the console's filing rule read for this column:
      // where a page goes is decided by the question it answers. This
      // section's own description is *the credentials on your own entry, one
      // page each*, and an RFC 7523 key pair is exactly that: seven
      // attributes on this person's entry that obtain a token as them.
      //
      // **THE ARGUMENT FOR PUTTING IT UNDER *Your account* WAS CONSIDERED AND
      // REFUSED**: it runs that this key never signs anybody IN — there is no
      // browser session at the end of it, so it is not "how you sign in". True,
      // and it is an argument about the section's TITLE rather than about what
      // the section holds. A person looking for the thing they can change
      // about how this service lets something act as them will look in the
      // list of credentials, and moving the heading's meaning to fit one page
      // would misfile the other three.
      { path: BASE + '/signing-key', label: 'Signing keys',
        heading: 'Your signing keys' },
      // CERTIFICATE ENROLLMENT (2026-09-13), in this section for the signing
      // keys' reason: an ACME account binding key and a SCEP challenge
      // password are credentials on this person's own entry, and so are the
      // certificates they obtain. Drawn by `portal_certificates.ts`.
      { path: BASE + '/certificates', label: 'Certificates',
        heading: 'Your certificates' },
      // APP PASSWORDS (#101, 2026-09-22), in this section for the signing
      // keys' reason: a credential on this person's own entry. The doors
      // that take only a password refuse a second-factor person's own
      // password in product mode, and this is what they use there. Drawn by
      // `portal_app_passwords.ts`.
      { path: BASE + '/app-passwords', label: 'App passwords',
        heading: 'Your app passwords' },
      // KERBEROS (#59, 2026-09-22), in this section for the signing keys'
      // reason: the principal is this person's own entry, and a keytab is a
      // credential derived from their own password. Drawn by
      // `portal_kerberos.ts`.
      { path: BASE + '/kerberos', label: 'Kerberos',
        heading: 'Your Kerberos principal and keytab' },
      // WHO MAY ACT FOR YOU (#108, 2026-09-23), in this section for the
      // signing keys' reason: `stsMayAct` is on this person's own entry, and
      // it is what their access tokens' `may_act` claim says. Drawn by
      // `portal_delegate.ts`.
      { path: BASE + '/delegate', label: 'Who may act for you',
        heading: 'Who may act for you' },
      // SELF-ISSUED IDs (#129, 2026-09-23), in this section for the signing
      // keys' reason: the wallet keys enrolled on this person's own entry,
      // each of which signs them in by SIOPv2. Drawn by
      // `portal_self_issued.ts`.
      { path: BASE + '/self-issued', label: 'Self-issued IDs',
        heading: 'Your self-issued IDs' },
      // ADD A CREDENTIAL TO YOUR WALLET (#589, 2026-10-12), beside the
      // wallet keys above and in this section for the signing keys' reason:
      // what it hands over is a credential about this person, made on their
      // own sign-in, for their own wallet. Drawn by `portal_wallet.ts`.
      { path: BASE + '/wallet', label: 'Add to your wallet',
        heading: 'Add a credential to your wallet' },
      // DEVICES (#130, 2026-09-23), in this section for the signing keys'
      // reason: each device holds a credential — a Native SSO secret — that
      // signs this person's apps in. Drawn by `portal_devices.ts`.
      { path: BASE + '/devices', label: 'Devices',
        heading: 'Your devices' },
      // SIGN-IN REQUESTS (#131, 2026-09-23), in this section for the signing
      // keys' reason: an approval here signs this person in to an
      // application elsewhere (OpenID Connect CIBA), and the user code is a
      // credential on their own entry. Drawn by `portal_ciba.ts`.
      { path: BASE + '/ciba', label: 'Sign-in requests',
        heading: 'Sign-in requests' },
      // ACCESS REQUESTS (#1180), beside Sign-in requests and for its
      // reason: an approval here gives access elsewhere — though to
      // somebody else, as the approver an AuthZEN access request's policy
      // named, never as its subject. Drawn by `portal_access_requests.ts`.
      { path: BASE + '/access-requests', label: 'Access requests',
        heading: 'Access requests waiting for you' },
      // SIGN IN A DEVICE (#150, 2026-09-26), for CIBA's reason: the code a
      // television or a command line shows is typed here, and an approval
      // signs this person in on it (RFC 8628). Drawn by `portal_device.ts`.
      { path: BASE + '/device', label: 'Sign in a device',
        heading: 'Sign in a device' },
      // CONNECTED CLAIM SOURCES (#147, 2026-09-24), in this section for the
      // same reason: a link hands this service a token at another provider
      // that vouches for this person. Drawn by `portal_claim_sources.ts`.
      { path: BASE + '/claim-sources', label: 'Claim sources',
        heading: 'Connected claim sources' },
      // CONNECTED ACCOUNTS (#565), in this section for the claim sources'
      // reason: a connection lets a consumer provider vouch for this person
      // at sign-in. Drawn by `portal_connected_accounts.ts`.
      { path: BASE + '/connected-accounts', label: 'Connected accounts',
        heading: 'Connected accounts' }
    ] }
];


/**
 * The portal's rendering kit. A static utility class; it holds no state.
 */
class PortalKit {
  /**
   * The portal's base path.
   */
  static readonly BASE = BASE;
  /**
   * The navigation column: the sections, each with its pages.
   */
  static readonly NAV = NAV;
  /**
   * A REALM'S SIGN-IN APPEARANCE IN THE PORTAL (#717, rcbj's D4): the
   * brand header the runtime draws above the page (`WebSurface.brandHeader()`
   * from the shell's `<html>` facts, `web_portal_runtime.ts`'s `put()`), and
   * what the realm's colours do to the tints `themed()` cannot name. Every
   * rule but the header's is under `html[data-sts-layout]`, which a shell
   * carries only for a realm whose appearance differs from the service's, so
   * nowhere else does any of it apply; the `:where()` keeps each at the
   * specificity of the rule it overrides, so a more specific rule of the
   * portal's (`.attr code`) still wins.
   *
   *   * THE LAYOUTS: centered is the header above the page, in the middle.
   *     banner AND split are a band in the accent colour across the top: the
   *     portal already has a column of its own beside its cards, and a
   *     panel beside that would leave a phone's width for three columns, so
   *     the split panel is drawn as the band here (`portal/CLAUDE.md`).
   *   * THE TINTS — a hover, a tag, a just-generated row, a code's ground —
   *     were pale blues and greys written for a white card. For a realm
   *     they are mixed from its accent or text and its card
   *     (`color-mix()`), so a dark card keeps them dark; a browser without
   *     `color-mix()` keeps the literal, which is the old look.
   */
  static readonly BRAND_CSS =
    '.sts-brand{display:flex;align-items:center;justify-content:center;' +
    'gap:12px;max-width:1040px;margin:0 auto 18px;' +
    'color:var(--sts-text,#222)}img.sts-brand-logo{display:block;' +
    'max-width:240px;max-height:56px}a.sts-brand-link{display:block;' +
    'line-height:0}.sts-brand-name{font-weight:600;font-size:1.15em;' +
    'overflow-wrap:anywhere}' +
    'html[data-sts-layout=banner] .sts-brand,' +
    'html[data-sts-layout=split] .sts-brand{justify-content:flex-start;' +
    'max-width:none;margin:-2rem -1rem 24px;padding:12px 24px;' +
    'background:var(--sts-accent,#2c5cc5);' +
    'color:var(--sts-on-accent,#fff)}' +
    ':where(html[data-sts-layout]) code{background:color-mix(in srgb,' +
    'var(--sts-text,#222) 7%,var(--sts-card,#fff))}' +
    ':where(html[data-sts-layout]) :is(pre.pem,pre.diddoc,' +
    'pre.signal-payload,.offer-uri){background:color-mix(in srgb,' +
    'var(--sts-text,#222) 4%,var(--sts-card,#fff));' +
    'color:var(--sts-text,#222)}' +
    ':where(html[data-sts-layout]) nav a:hover,' +
    ':where(html[data-sts-layout]) .usermenupanel button.linklike:hover{' +
    'background:color-mix(in srgb,var(--sts-accent,#2c5cc5) 12%,' +
    'var(--sts-card,#fff))}' +
    ':where(html[data-sts-layout]) .tag,:where(html[data-sts-layout]) ' +
    '.must{background:color-mix(in srgb,var(--sts-accent,#2c5cc5) 12%,' +
    'var(--sts-card,#fff));border-color:color-mix(in srgb,' +
    'var(--sts-accent,#2c5cc5) 30%,var(--sts-card,#fff));' +
    'color:var(--sts-text,#222)}' +
    ':where(html[data-sts-layout]) .fresh,' +
    ':where(html[data-sts-layout]) tr.fresh-row>td,' +
    ':where(html[data-sts-layout]) tr.fresh-row>th,' +
    ':where(html[data-sts-layout]) .txcode{background:color-mix(in srgb,' +
    'var(--sts-accent,#2c5cc5) 8%,var(--sts-card,#fff))}';

  /**
   * The portal's stylesheet with every colour a realm may set read through
   * the custom property `/web/theme.css` sets (#717, `common/branding.ts`),
   * each falling back to the literal it replaces — so with no theme linked
   * (every realm that set nothing) the portal is drawn exactly as before.
   * `web_card_css.ts`'s `themed()` is the card's; this is the portal's,
   * because its palette is its own (the portal's blue, `#2c5cc5`, is its
   * accent's fallback). The semantic colours — an error's red, a success's
   * green — and the mid greys stay literal: they mean the same on any card.
   * The order matters: the accent first, then the text on it.
   *
   * @param css - the stylesheet as written
   * @returns the same rules, each themable colour a custom property
   */
  static themed(css: string): string {
    return css
      .replace(/#2c5cc5/g, 'var(--sts-accent,#2c5cc5)')
      .replace(/#12107c/g, 'var(--sts-accent,#12107c)')
      // White text is only ever on the accent here; the two buttons that
      // are not in the accent write theirs `#ffffff`, which this skips.
      .replace(/color:#fff(?=[;}])/g, 'color:var(--sts-on-accent,#fff)')
      .replace('sans-serif;background:#f4f4f7;',
               'sans-serif;background:var(--sts-page,#f4f4f7);')
      .replace(/background:#fff(?=[;}])/g, 'background:var(--sts-card,#fff)')
      .replace(/color:#(222|333)(?=[;}])/g, 'color:var(--sts-text,#$1)')
      .replace(/color:#666(?=[;}])/g, 'color:var(--sts-muted,#666)')
      .replace(/color:#555(?=[;}])/g, 'color:var(--sts-dim,#555)')
      .replace(/color:#777(?=[;}])/g, 'color:var(--sts-faint,#777)')
      .replace(/solid #(d5d5dd|c9c9d2|c7c7d1|c9cad6)(?=[;}])/g,
               'solid var(--sts-border,#$1)')
      .replace(/solid #(e6e6ec|eee)(?=[;}])/g, 'solid var(--sts-rule,#$1)');
  }

  /**
   * The stylesheet, one string, served as `/portal/portal.css`: the rules
   * as written, themed, and the realm's brand rules last (#717).
   */
  static readonly STYLE = PortalKit.themed(STYLE_AS_WRITTEN) +
    NO_INLINE_STYLE + PortalKit.BRAND_CSS;
  /**
   * The icons a page draws, by name.
   */
  static readonly ICONS = PORTAL_ICONS;

  /**
   * Escapes text for HTML.
   *
   * @param value - anything
   * @returns the escaped text
   */
  static esc(value: unknown): string {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * Every page in the column, in order.
   *
   * @returns the pages
   */
  static navPages(): Json[] {
    return NAV.reduce(function (all: Json[], section: Json): Json[] {
      return all.concat(section.items);
    }, []);
  }

  /**
   * The catalog slug of a portal page: its path after `/portal`, with `/`
   * as `.`, and `overview` for `/portal` itself.
   *
   * @param path - the page's path
   * @returns the slug
   */
  static navSlug(path: string): string {
    const rest = String(path || '').slice(BASE.length).replace(/^\/+/, '');
    return rest ? rest.replace(/\//g, '.') : 'overview';
  }

  /**
   * A query string from an object, empty values left out.
   *
   * @param params - the parameters
   * @returns `?a=1&b=2`, or ''
   */
  static queryOf(params: Json): string {
    const keep: Json = {};
    Object.keys(params || {}).forEach(function (name) {
      const value = params[name];
      if (value !== undefined && value !== null && value !== '') {
        keep[name] = String(value);
      }
    });
    const qs = new URLSearchParams(keep).toString();
    return qs ? '?' + qs : '';
  }

  // ONE PAGER FOR A PAGED LIST (#313's sweep). The portal's earlier lists
  // each drew their own Previous / Page n of m / Next on `?page=` alone;
  // this is the same control for a list whose answer carries `paging`
  // (`page`, `pages`) and which moves on a parameter of its own. Every
  // other parameter the reader is carrying rides along, except the two a
  // callback or a form brought back (`notice`, `problem`), which belong to
  // the moment they were said and not to the list. Nothing is drawn when
  // the list fits on one page, unless the page asks for it `always`.
  /**
   * The Previous / Page n of m / Next control under a paged list.
   *
   * @param path - the page's path
   * @param query - the page's own query parameters
   * @param paging - the list's `paging` from its answer
   * @param param - the query parameter the list moves on
   * @param t - the translator
   * @param always - true draws it for one page too
   * @returns the HTML, '' for one page unless `always`
   */
  static pageNav(path: string, query: Json, paging: Json, param: string,
                 t: Json, always?: boolean): string {
    const at = Number(paging && paging.page) || 1;
    const pages = Number(paging && paging.pages) || 1;
    if (pages <= 1 && always !== true) {
      return '';
    }
    const carried: Json = {};
    Object.keys(query || {}).forEach(function (name) {
      if (name !== 'notice' && name !== 'problem' && name !== 'done') {
        carried[name] = query[name];
      }
    });
    const href = function (page: number): string {
      const move: Json = Object.assign({}, carried);
      move[param] = page > 1 ? String(page) : '';
      return PortalKit.esc(path + PortalKit.queryOf(move));
    };
    return '<p class="pagenav" id="pager-' + PortalKit.esc(param) + '">' +
      (at > 1
        ? '<a href="' + href(at - 1) + '">' +
          t.html('portal.paging.previous') + '</a>'
        : '<span class="off">' + t.html('portal.paging.previous') +
          '</span>') +
      '<span class="here">' + t.html('portal.paging.page',
        { at: at, pages: pages }) + '</span>' +
      (at < pages
        ? '<a href="' + href(at + 1) + '">' +
          t.html('portal.paging.next') + '</a>'
        : '<span class="off">' + t.html('portal.paging.next') + '</span>') +
      '</p>';
  }
}

export = PortalKit;
