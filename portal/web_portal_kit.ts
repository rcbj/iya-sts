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
// A `web_` MODULE, on `admin-ui/web_kit.ts`'s terms: it requires nothing,
// logs nothing, and is bundled for a browser by `build-typescript.sh`. The
// server reads `NAV` and `STYLE` from it — the console's `web_database.ts`
// arrangement — and never the other way round.
// ---------------------------------------------------------------------------

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

const STYLE =
  'body{font-family:system-ui,-apple-system,"Segoe ' +
  'UI",Arial,sans-serif;background:#f4f4f7;margin:0;padding:2rem ' +
  '1rem;color:#222;line-height:1.5}.wrap{max-width:720px;margin:0 ' +
  'auto}.card{background:#fff;border:1px solid ' +
  '#d5d5dd;border-radius:10px;padding:24px ' +
  '28px;margin-bottom:18px;box-shadow:0 2px 10px ' +
  'rgba(0,0,0,.04)}h1{font-size:1.4em;margin:0 0 ' +
  '4px}h2{font-size:1.05em;margin:0 0 12px}' +
  // The heading and its one control on the same line. `align-items:start` and
  // not `center`: the button is a small box beside a large heading and centring
  // it drags it down past the heading's baseline. The form's margin is reset
  // because `button` carries a top margin of its own for the stacked forms
  // below, which is right there and wrong here.
  '.pagehead{display:flex;gap:12px;align-items:start;' +
  'justify-content:space-between;flex-wrap:wrap}.pagehead ' +
  'h1{margin:0}.pagehead form{margin:0}.pagehead .acts{display:flex;' +
  'gap:8px;align-items:start}.pagehead ' +
  'button{margin-top:0}' +
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
  'p.sub{color:#666;font-size:.9em;margin:0 0 ' +
  '18px}label{display:block;font-size:.85em;font-weight:600;margin:12px 0 ' +
  '4px}input[type=text],input[type=password]{width:100%;padding:9px ' +
  '10px;border:1px solid #c9c9d2;border-radius:6px;font-size:1em;' +
  'box-sizing:border-box}button{margin-top:14px;padding:9px 16px;border:0;' +
  'border-radius:6px;background:#2c5cc5;color:#fff;font-size:.95em;' +
  'cursor:pointer}button.danger{background:#b00020}' +
  'button.secondary{background:#5a5a68}table{border-collapse:collapse;' +
  'width:100%;font-size:.9em}th,td{text-align:left;padding:7px ' +
  '10px;border-bottom:1px solid #e6e6ec}th{color:#555;font-weight:600;' +
  'width:34%}.err{background:#fdecef;border:1px solid ' +
  '#f5c2cb;color:#8a1027;padding:10px 12px;border-radius:6px;' +
  'margin-bottom:14px;font-size:.9em}.ok{background:#eaf6ec;border:1px solid ' +
  '#bfe3c6;color:#1d5b2a;padding:10px 12px;border-radius:6px;' +
  'margin-bottom:14px;font-size:.9em}.note{color:#555;font-size:.85em;' +
  'margin:10px 0 0}code{background:#f0f0f5;padding:1px ' +
  '5px;border-radius:4px;font-size:.9em}' +
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
  'nav ul{list-style:none;margin:0;padding:0}' +
  '.navsec{margin:0 0 14px}.navsec:last-child{margin-bottom:0}' +
  '.navhead{margin:0 0 5px;font-size:.7em;text-transform:uppercase;' +
  'letter-spacing:.06em;color:#6a6a78;font-weight:700}' +
  // The rule down the left marking the section the current page is in, so a
  // reader who arrived on a deep link can see where they are without reading
  // every label. Same device as the console's, one colour over.
  '.navsec.open{border-left:3px solid ' +
  '#2c5cc5;margin-left:-14px;padding-left:11px}.navsec.open ' +
  '.navhead{color:#2c5cc5}nav a,nav .here{display:block;padding:4px 7px;' +
  'border-radius:5px;text-decoration:none;color:#2c5cc5;font-size:.9em}nav ' +
  'a:hover{background:#eef2fb}nav .here{font-weight:700;color:#fff;' +
  'background:#2c5cc5}.who{color:#666;font-size:.85em;margin:3px 0 0}' +
  // A HEADER TABLE RATHER THAN A LABEL COLUMN. `th` above is 34% wide because
  // every table in this application until now was two columns of name and
  // value; the applications list is four columns with a heading ROW, where a
  // third of the width for the first cell is simply wrong.
  '.grid th{width:auto;color:#555}' +
  '.grid td strong{display:block}' +
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
  '.navsec{display:inline-block;vertical-align:top;min-width:10rem;' +
  'margin-right:1.2em}' +
  '.navsec.open{margin-left:0;padding-left:0;border-left:0;' +
  'border-top:3px solid #2c5cc5;padding-top:6px}}' +
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
  'margin:6px 8px 0 0;font-size:.9em}a.dl.secondary{background:#5a5a68}' +
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
        heading: 'Your email address and messages' }
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
   * The stylesheet, one string, served as `/portal/portal.css`.
   */
  static readonly STYLE = STYLE;
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
